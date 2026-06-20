#Requires -Version 5.1
<#
.SYNOPSIS
    Hidden Protocol Systems — Windows Server Security Audit Framework
    
.DESCRIPTION
    Comprehensive Windows Server security audit tool with TUI interface.
    Covers AD policies, Group Policies, user enumeration, installed software,
    network state, IOC detection, and full system configuration baseline.
    Outputs a unified Markdown report.

.AUTHOR
    Jamie Eastridge — CISO / Principal
    Hidden Protocol Systems (Hidden Protocol LLC)
    jamie@hiddenprotocol.com

.VERSION
    2.0.0

.NOTES
    Run as Administrator. Domain-joined hosts will yield richer AD/GPO output.
    Designed for Windows Server 2016/2019/2022.
#>

Set-StrictMode -Version Latest
# Keep SilentlyContinue as default so native cmdlet errors don't spam
# the console — Invoke-Safe catches everything that matters explicitly.
$ErrorActionPreference = 'SilentlyContinue'

# ─────────────────────────────────────────────────────────────────────────────
#  GLOBALS
# ─────────────────────────────────────────────────────────────────────────────
$Script:VERSION        = "3.0.0"
$Script:BUILD_DATE     = "2026-06-20"
$Script:AUTHOR         = "Jamie Eastridge // Hidden Protocol Systems"
$Script:REPORT_PATH    = ""
$Script:FINDINGS       = [System.Collections.Generic.List[string]]::new()
$Script:IOC_HITS       = [System.Collections.Generic.List[string]]::new()
$Script:ERRORS_LOG     = [System.Collections.Generic.List[string]]::new()
$Script:SELECTED_MODS  = [System.Collections.Generic.List[string]]::new()
$Script:SERVER_ROLES   = [System.Collections.Generic.List[string]]::new()
$Script:START_TIME     = Get-Date
# Live running counters — displayed after every module
$Script:CNT_PASS       = 0
$Script:CNT_WARN       = 0
$Script:CNT_CRIT       = 0
$Script:CNT_IOC        = 0
$Script:CNT_ERR        = 0
$Script:CYAN           = [ConsoleColor]::Cyan
$Script:GREEN          = [ConsoleColor]::Green
$Script:YELLOW         = [ConsoleColor]::Yellow
$Script:RED            = [ConsoleColor]::Red
$Script:WHITE          = [ConsoleColor]::White
$Script:GRAY           = [ConsoleColor]::DarkGray
$Script:MAGENTA        = [ConsoleColor]::Magenta

# ─────────────────────────────────────────────────────────────────────────────
#  TUI RENDERING HELPERS  (v3 — live scrolling output engine)
# ─────────────────────────────────────────────────────────────────────────────
function Write-HPS-Banner {
    Clear-Host
    $banner = @"

  ██╗  ██╗██████╗ ███████╗
  ██║  ██║██╔══██╗██╔════╝
  ███████║██████╔╝███████╗
  ██╔══██║██╔═══╝ ╚════██║
  ██║  ██║██║     ███████║
  ╚═╝  ╚═╝╚═╝     ╚══════╝  HIDDEN PROTOCOL SYSTEMS
"@
    Write-Host $banner -ForegroundColor Cyan
    Write-Host "  ─────────────────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
    Write-Host "  [ WINDOWS SERVER SECURITY AUDIT FRAMEWORK ]  " -NoNewline -ForegroundColor DarkGray
    Write-Host "v$($Script:VERSION)" -ForegroundColor Cyan
    Write-Host "  [ Jamie Eastridge — CISO / Principal, Hidden Protocol Systems ]" -ForegroundColor DarkGray
    Write-Host "  [ Signal over noise. ]" -ForegroundColor DarkGray
    Write-Host "  ─────────────────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
    Write-Host ""
}

function Write-Box {
    param([string]$Title, [ConsoleColor]$Color = [ConsoleColor]::Cyan)
    $pad = [math]::Max(0, 73 - $Title.Length - 4)
    Write-Host ""
    Write-Host "  ┌─[ " -NoNewline -ForegroundColor $Color
    Write-Host $Title   -NoNewline -ForegroundColor White
    Write-Host " ]$('─' * $pad)┐" -ForegroundColor $Color
}

function Write-BoxEnd {
    param([ConsoleColor]$Color = [ConsoleColor]::Cyan)
    Write-Host "  └$('─' * 75)┘" -ForegroundColor $Color
    Write-Host ""
}

# Sub-section divider inside a module — lightweight visual separator
function Write-Divider {
    param([string]$Label = "", [ConsoleColor]$Color = [ConsoleColor]::DarkGray)
    if ($Label) {
        $pad = [math]::Max(0, 58 - $Label.Length)
        Write-Host "  ┄┄[ " -NoNewline -ForegroundColor $Color
        Write-Host $Label    -NoNewline -ForegroundColor DarkCyan
        Write-Host " ]$('┄' * $pad)" -ForegroundColor $Color
    } else {
        Write-Host "  $('┄' * 72)" -ForegroundColor $Color
    }
}

# Timestamped operation status line
function Write-Status {
    param(
        [string]$Label,
        [string]$Status = "RUN",
        [ConsoleColor]$StatusColor = [ConsoleColor]::Cyan
    )
    $ts = (Get-Date).ToString("HH:mm:ss")
    Write-Host "  " -NoNewline
    Write-Host "[" -NoNewline -ForegroundColor DarkGray
    Write-Host $ts  -NoNewline -ForegroundColor DarkGray
    Write-Host "][" -NoNewline -ForegroundColor DarkGray
    Write-Host $Status.PadRight(4) -NoNewline -ForegroundColor $StatusColor
    Write-Host "] " -NoNewline -ForegroundColor DarkGray
    Write-Host $Label -ForegroundColor White
}

# Inline key/value data line — real-time data scrolling during scan
function Write-DataLine {
    param(
        [string]$Key,
        [string]$Value,
        [ConsoleColor]$ValColor = [ConsoleColor]::White
    )
    Write-Host "       " -NoNewline
    Write-Host ($Key.PadRight(30)) -NoNewline -ForegroundColor DarkGray
    Write-Host $Value -ForegroundColor $ValColor
}

# The main finding printer — rich live output + counter tracking + report log
function Write-Finding {
    param(
        [string]$Message,
        [ValidateSet('INFO','WARN','CRIT','PASS','IOC','ERR')]
        [string]$Severity = 'INFO',
        [string]$Detail = ""
    )

    # Severity config: colour, gutter glyph, badge
    $cfg = @{
        INFO = @{ C=[ConsoleColor]::Cyan;    G='  ·  '; B='INFO' }
        WARN = @{ C=[ConsoleColor]::Yellow;  G='  ▶  '; B='WARN' }
        CRIT = @{ C=[ConsoleColor]::Red;     G='  ▣  '; B='CRIT' }
        PASS = @{ C=[ConsoleColor]::Green;   G='  ✓  '; B='PASS' }
        IOC  = @{ C=[ConsoleColor]::Magenta; G='  ⚡ '; B='IOC ' }
        ERR  = @{ C=[ConsoleColor]::DarkGray;G='  ?  '; B='ERR ' }
    }
    $c = $cfg[$Severity]

    # Gutter + badge
    Write-Host $c.G -NoNewline -ForegroundColor $c.C
    Write-Host "[$($c.B)] " -NoNewline -ForegroundColor $c.C
    Write-Host $Message -ForegroundColor White

    # Optional detail line indented below
    if ($Detail) {
        Write-Host "            " -NoNewline
        Write-Host $Detail -ForegroundColor DarkGray
    }

    # Update live counters
    switch ($Severity) {
        'PASS' { $Script:CNT_PASS++ }
        'WARN' { $Script:CNT_WARN++ }
        'CRIT' { $Script:CNT_CRIT++ }
        'IOC'  { $Script:CNT_IOC++;  $Script:IOC_HITS.Add("[$Severity] $Message") | Out-Null }
        'ERR'  { $Script:CNT_ERR++;  $Script:ERRORS_LOG.Add("[$Severity] $Message") | Out-Null }
    }

    # Persist to report
    $entry = "[$Severity] $Message$(if($Detail){" — $Detail"})"
    $Script:FINDINGS.Add($entry) | Out-Null
    if ($Severity -in @('IOC','CRIT') -and -not $Script:IOC_HITS.Contains($entry)) {
        $Script:IOC_HITS.Add($entry) | Out-Null
    }
}

# Running totals bar — printed at the end of each module so the operator
# can see the cumulative score without waiting for the final report
function Write-LiveStats {
    Write-Host ""
    Write-Host "  ┌─[ RUNNING TOTALS ]───────────────────────────────────────────────────┐" -ForegroundColor DarkGray
    Write-Host "  │  " -NoNewline -ForegroundColor DarkGray
    Write-Host "PASS $($Script:CNT_PASS.ToString().PadRight(5))" -NoNewline -ForegroundColor Green
    Write-Host "  WARN $($Script:CNT_WARN.ToString().PadRight(5))" -NoNewline -ForegroundColor Yellow
    Write-Host "  CRIT $($Script:CNT_CRIT.ToString().PadRight(5))" -NoNewline -ForegroundColor Red
    Write-Host "  IOC  $($Script:CNT_IOC.ToString().PadRight(5))"  -NoNewline -ForegroundColor Magenta
    Write-Host "  ERR  $($Script:CNT_ERR.ToString().PadRight(5))"  -NoNewline -ForegroundColor DarkGray
    Write-Host "  │" -ForegroundColor DarkGray
    Write-Host "  └───────────────────────────────────────────────────────────────────────┘" -ForegroundColor DarkGray
    Write-Host ""
}

# Safe execution wrapper — catches ALL exceptions from a named block and
# logs them as ERR findings so the script ALWAYS continues even if a
# cmdlet doesn't exist, a module is missing, or access is denied.
function Invoke-Safe {
    param(
        [string]$Name,
        [scriptblock]$Block
    )
    try {
        & $Block
    } catch {
        $msg = "[$Name] $($_.Exception.Message) (line $($_.InvocationInfo.ScriptLineNumber))"
        Write-Finding $msg ERR
    }
}

function Write-MDSection {
    param([string]$Text)
    $Script:FINDINGS.Add($Text) | Out-Null
}

function Write-ProgressBar {
    param([int]$Current, [int]$Total, [string]$Label = "")
    if ($Total -le 0) { return }
    $pct    = [math]::Min(100, [math]::Round(($Current / $Total) * 100))
    $filled = [math]::Round($pct / 2)
    $empty  = 50 - $filled
    $bar    = ('█' * $filled) + ('░' * $empty)
    Write-Host "`r  [$bar] " -NoNewline -ForegroundColor Cyan
    Write-Host "$pct% " -NoNewline -ForegroundColor White
    Write-Host $Label   -NoNewline -ForegroundColor DarkGray
    if ($Current -ge $Total) { Write-Host "" }
}

# ─────────────────────────────────────────────────────────────────────────────
#  SERVER ROLE SELECTOR
# ─────────────────────────────────────────────────────────────────────────────
function Show-ServerRoleMenu {
    Clear-Host
    Write-HPS-Banner
    Write-Box "STEP 1 OF 2 — SERVER ROLE IDENTIFICATION" Magenta

    $roles = @(
        @{ Key='1';  Name='Domain Controller / Active Directory';  Tag='DC';      Icon='🏛️';  Desc='Adds: AD replication health, FSMO, Sysvol, Netlogon, DC-specific GPO checks' }
        @{ Key='2';  Name='Citrix Virtual Apps & Desktops (CVAD)'; Tag='CITRIX';  Icon='🖥️';  Desc='Adds: Citrix service health, session limits, profile config, ICA security' }
        @{ Key='3';  Name='Hyper-V Host';                          Tag='HYPERV';  Icon='⚙️';  Desc='Adds: VM inventory, virtual switch config, snapshot state, integration services' }
        @{ Key='4';  Name='Microsoft SQL Server';                  Tag='SQL';     Icon='🗄️';  Desc='Adds: SQL instances, logins, SA account, linked servers, xp_cmdshell, encryption' }
        @{ Key='5';  Name='SaaS / Web Application Server (IIS)';   Tag='IIS';     Icon='🌐';  Desc='Adds: IIS sites, app pools, SSL bindings, anonymous auth, request filtering' }
        @{ Key='6';  Name='File Server / DFS';                     Tag='FILESVR'; Icon='📁';  Desc='Adds: DFS namespace/replication, share ACLs, quota state, open files' }
        @{ Key='7';  Name='Certificate Authority (PKI/ADCS)';      Tag='PKI';     Icon='🔐';  Desc='Adds: CA config, issued certs, template ACLs, AIA/CDP paths, expiring certs' }
        @{ Key='8';  Name='Remote Desktop Services (RDSH/RDG)';    Tag='RDS';     Icon='🖱️';  Desc='Adds: RDS licensing, session host config, RDG health, per-user settings' }
        @{ Key='9';  Name='WSUS / Update Services';                Tag='WSUS';    Icon='🔄';  Desc='Adds: WSUS sync status, approval rules, downstream servers, declined updates' }
        @{ Key='0';  Name='Exchange / Mail Server';                 Tag='EXCHANGE';Icon='📧';  Desc='Adds: Exchange health, connectors, relay config, mailbox audit, TLS settings' }
        @{ Key='S';  Name='STANDALONE / General Purpose Server';   Tag='STANDALONE';Icon='🖧'; Desc='No role-specific modules — baseline, network, users, and hardening only' }
    )

    foreach ($r in $roles) {
        $keyColor = switch ($r.Key) {
            'S'     { [ConsoleColor]::Yellow }
            default { [ConsoleColor]::Magenta }
        }
        Write-Host "  │" -ForegroundColor DarkGray
        Write-Host "  │  [$($r.Key)] " -NoNewline -ForegroundColor $keyColor
        Write-Host "$($r.Icon)  $($r.Name)" -ForegroundColor White
        Write-Host "  │      " -NoNewline -ForegroundColor DarkGray
        Write-Host $r.Desc -ForegroundColor DarkGray
    }

    Write-Host "  │" -ForegroundColor DarkGray
    Write-Host "  │  " -NoNewline -ForegroundColor DarkGray
    Write-Host "Select one or more roles (e.g. 13 for DC+Hyper-V, S for standalone):" -ForegroundColor DarkGray
    Write-Host "  │  " -NoNewline -ForegroundColor DarkGray
    Write-Host "Role selection unlocks additional targeted checks in the audit report." -ForegroundColor DarkGray
    Write-Host "  └" + ('─' * 75) + "┘" -ForegroundColor Magenta
    Write-Host ""
    Write-Host "  hps> " -NoNewline -ForegroundColor Magenta
    $raw = (Read-Host).ToUpper()

    $Script:SERVER_ROLES.Clear()
    if ($raw -match 'S') {
        $Script:SERVER_ROLES.Add('STANDALONE') | Out-Null
    } else {
        $map = @{
            '1'='DC'; '2'='CITRIX'; '3'='HYPERV'; '4'='SQL';
            '5'='IIS'; '6'='FILESVR'; '7'='PKI'; '8'='RDS';
            '9'='WSUS'; '0'='EXCHANGE'
        }
        foreach ($ch in $raw.ToCharArray()) {
            $key = [string]$ch
            if ($map.ContainsKey($key) -and -not $Script:SERVER_ROLES.Contains($map[$key])) {
                $Script:SERVER_ROLES.Add($map[$key]) | Out-Null
            }
        }
    }

    if ($Script:SERVER_ROLES.Count -eq 0) {
        Write-Host "  [!] No role selected. Treating as Standalone." -ForegroundColor Yellow
        Start-Sleep -Milliseconds 800
        $Script:SERVER_ROLES.Add('STANDALONE') | Out-Null
    }
}

# ─────────────────────────────────────────────────────────────────────────────
#  MENU SYSTEM
# ─────────────────────────────────────────────────────────────────────────────
function Show-MainMenu {
    Clear-Host
    Write-HPS-Banner

    # Show selected roles as context
    Write-Host "  Selected Role(s): " -NoNewline -ForegroundColor DarkGray
    Write-Host ($Script:SERVER_ROLES -join ' + ') -ForegroundColor Magenta
    Write-Host ""

    Write-Box "STEP 2 OF 2 — AUDIT MODULE SELECTOR" Cyan

    $modules = @(
        @{ Key='1'; Name='System Baseline & Hardware Inventory';     Tag='SYSBASE'  }
        @{ Key='2'; Name='User & Account Security Audit';             Tag='USERS'    }
        @{ Key='3'; Name='Active Directory Policy Audit';             Tag='ADPOL'    }
        @{ Key='4'; Name='Group Policy Object (GPO) Audit';           Tag='GPOL'     }
        @{ Key='5'; Name='Network Configuration & Netstat';           Tag='NETSTAT'  }
        @{ Key='6'; Name='Installed Software & Patch Inventory';      Tag='SOFTWARE' }
        @{ Key='7'; Name='Services, Scheduled Tasks & Autoruns';      Tag='PERSIST'  }
        @{ Key='8'; Name='Windows Firewall & Security Policy';        Tag='FIREWALL' }
        @{ Key='9'; Name='Event Log & Audit Policy Review';           Tag='EVTLOG'   }
        @{ Key='0'; Name='IOC Detection & Threat Hunt';               Tag='IOC'      }
        @{ Key='A'; Name='RUN ALL MODULES (Full Spectrum Audit)';     Tag='ALL'      }
    )

    foreach ($m in $modules) {
        $keyColor = if ($m.Key -eq 'A') { [ConsoleColor]::Magenta } else { [ConsoleColor]::Cyan }
        Write-Host "  │ " -NoNewline -ForegroundColor DarkGray
        Write-Host " [$($m.Key)] " -NoNewline -ForegroundColor $keyColor
        Write-Host $m.Name -ForegroundColor White
    }

    Write-Host "  │" -ForegroundColor DarkGray
    Write-Host "  │  " -NoNewline -ForegroundColor DarkGray
    Write-Host "Select modules (e.g. 135 for System+Users+Network, A for all):" -ForegroundColor DarkGray
    Write-Host "  └" + ('─' * 75) + "┘" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  hps> " -NoNewline -ForegroundColor Cyan
    $raw = (Read-Host).ToUpper()

    $Script:SELECTED_MODS.Clear()
    if ($raw -match 'A') {
        $Script:SELECTED_MODS.AddRange([string[]]@('SYSBASE','USERS','ADPOL','GPOL','NETSTAT','SOFTWARE','PERSIST','FIREWALL','EVTLOG','IOC'))
    } else {
        $map = @{
            '1'='SYSBASE'; '2'='USERS'; '3'='ADPOL'; '4'='GPOL';
            '5'='NETSTAT'; '6'='SOFTWARE'; '7'='PERSIST'; '8'='FIREWALL';
            '9'='EVTLOG'; '0'='IOC'
        }
        foreach ($ch in $raw.ToCharArray()) {
            $key = [string]$ch
            if ($map.ContainsKey($key)) {
                if (-not $Script:SELECTED_MODS.Contains($map[$key])) {
                    $Script:SELECTED_MODS.Add($map[$key]) | Out-Null
                }
            }
        }
    }

    if ($Script:SELECTED_MODS.Count -eq 0) {
        Write-Host "  [!] No valid modules selected. Defaulting to full audit." -ForegroundColor Yellow
        Start-Sleep -Seconds 1
        $Script:SELECTED_MODS.AddRange([string[]]@('SYSBASE','USERS','ADPOL','GPOL','NETSTAT','SOFTWARE','PERSIST','FIREWALL','EVTLOG','IOC'))
    }

    # Report path
    $hostname = $env:COMPUTERNAME
    $ts       = (Get-Date).ToString("yyyyMMdd-HHmmss")
    $defaultReport = "$env:USERPROFILE\Desktop\HPS-AUDIT-$hostname-$ts.md"
    Write-Host ""
    Write-Host "  Output report path [ENTER = $defaultReport]:" -ForegroundColor DarkGray
    Write-Host "  hps> " -NoNewline -ForegroundColor Cyan
    $rp = Read-Host
    $Script:REPORT_PATH = if ([string]::IsNullOrWhiteSpace($rp)) { $defaultReport } else { $rp }
}

# ─────────────────────────────────────────────────────────────────────────────
#  REPORT HELPERS
# ─────────────────────────────────────────────────────────────────────────────
function Add-MD {
    param([string]$Line = "")
    $Script:FINDINGS.Add($Line) | Out-Null
}

function Add-MDTable {
    param(
        [string[]]$Headers,
        [object[]]$Rows
    )
    Add-MD ("| " + ($Headers -join " | ") + " |")
    Add-MD ("|" + (($Headers | ForEach-Object { " --- |" }) -join "") )
    foreach ($row in $Rows) {
        if ($row -is [System.Collections.IDictionary]) {
            $cells = $Headers | ForEach-Object { if ($null -ne $row[$_]) { [string]$row[$_] } else { '' } }
        } elseif ($row -is [PSCustomObject]) {
            $cells = $Headers | ForEach-Object { if ($null -ne $row.$_) { [string]$row.$_ } else { '' } }
        } else {
            $cells = @([string]$row)
        }
        Add-MD ("| " + ($cells -join " | ") + " |")
    }
    Add-MD ""
}

# ─────────────────────────────────────────────────────────────────────────────
#  HELPER — ELEVATE CHECK
# ─────────────────────────────────────────────────────────────────────────────
function Test-AdminPrivilege {
    $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $pr = [System.Security.Principal.WindowsPrincipal]$id
    return $pr.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

# ─────────────────────────────────────────────────────────────────────────────
#  MODULE 1: SYSTEM BASELINE
# ─────────────────────────────────────────────────────────────────────────────
function Invoke-SysBaselineAudit {
    Write-Box "MODULE 1 — SYSTEM BASELINE & HARDWARE" Cyan
    Add-MD ""
    Add-MD "---"
    Add-MD "## 1. System Baseline & Hardware Inventory"
    Add-MD ""

    # OS Info
    Write-Status "Collecting OS information"
    $os  = Get-CimInstance Win32_OperatingSystem
    $cs  = Get-CimInstance Win32_ComputerSystem
    $bios= Get-CimInstance Win32_BIOS
    $cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
    $tpm = Get-CimInstance -Namespace root\cimv2\security\microsofttpm -Class Win32_Tpm

    Add-MD "### 1.1 OS Details"
    Add-MD ""
    Add-MDTable -Headers @('Property','Value') -Rows @(
        @{ Property='Hostname';            Value=$env:COMPUTERNAME }
        @{ Property='OS Name';             Value=$os.Caption }
        @{ Property='OS Version';          Value=$os.Version }
        @{ Property='Build Number';        Value=$os.BuildNumber }
        @{ Property='Architecture';        Value=$os.OSArchitecture }
        @{ Property='Install Date';        Value=$os.InstallDate }
        @{ Property='Last Boot';           Value=$os.LastBootUpTime }
        @{ Property='Uptime';             Value=((Get-Date) - $os.LastBootUpTime).ToString('d\d\ h\h\ m\m') }
        @{ Property='System Drive Free';   Value="{0:N1} GB" -f ($os.FreePhysicalMemory/1MB) }
        @{ Property='Total RAM';           Value="{0:N1} GB" -f ($cs.TotalPhysicalMemory/1GB) }
        @{ Property='Manufacturer';        Value=$cs.Manufacturer }
        @{ Property='Model';               Value=$cs.Model }
        @{ Property='Domain/Workgroup';    Value=if ($cs.PartOfDomain) {"$($cs.Domain) [DOMAIN]"} else {"$($cs.Workgroup) [WORKGROUP]"} }
        @{ Property='BIOS Version';        Value=$bios.SMBIOSBIOSVersion }
        @{ Property='BIOS Date';           Value=$bios.ReleaseDate }
        @{ Property='Serial Number';       Value=$bios.SerialNumber }
        @{ Property='CPU';                 Value=$cpu.Name }
        @{ Property='CPU Cores';           Value="$($cpu.NumberOfCores) cores / $($cpu.NumberOfLogicalProcessors) logical" }
        @{ Property='TPM Present';         Value=if($tpm) { "Yes — Version: $($tpm.SpecVersion)" } else { "Not detected" } }
    )

    # Secure Boot
    Write-Status "Checking Secure Boot"
    $sb = Confirm-SecureBootUEFI
    if ($sb) {
        Write-Finding "Secure Boot is ENABLED" PASS
        Add-MD "- **Secure Boot:** ✅ Enabled"
    } else {
        Write-Finding "Secure Boot is DISABLED — system may boot unauthorized code" CRIT
        Add-MD "- **Secure Boot:** ❌ Disabled"
    }

    # Windows license
    Write-Status "Checking Windows activation"
    $lic = Get-CimInstance SoftwareLicensingProduct | Where-Object { $_.Name -match 'Windows' -and $_.LicenseStatus -eq 1 } | Select-Object -First 1
    if ($lic) {
        Write-Finding "Windows is activated (licensed)" PASS
        Add-MD "- **Activation:** ✅ Activated"
    } else {
        Write-Finding "Windows may not be properly activated" WARN
        Add-MD "- **Activation:** ⚠️ Unlicensed/Unconfirmed"
    }

    # Virtualization
    $hvPresent = (Get-CimInstance Win32_ComputerSystem).HypervisorPresent
    if ($hvPresent) {
        Write-Finding "Running inside a Hypervisor / VM" INFO
        Add-MD "- **Environment:** 🖥️ Virtualized (Hypervisor detected)"
    } else {
        Add-MD "- **Environment:** 🖥️ Bare metal (no Hypervisor detected)"
    }

    # Drives
    Write-Status "Enumerating disk volumes"
    Add-MD ""
    Add-MD "### 1.2 Disk Volumes"
    Add-MD ""
    $disks = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Used -ne $null }
    $diskRows = $disks | ForEach-Object {
        $total = $_.Used + $_.Free
        $pct   = if ($total -gt 0) { [math]::Round(($_.Used / $total) * 100, 1) } else { 0 }
        @{
            Drive   = $_.Name
            Total   = "{0:N1} GB" -f ($total / 1GB)
            Used    = "{0:N1} GB ({1}%)" -f ($_.Used/1GB, $pct)
            Free    = "{0:N1} GB" -f ($_.Free / 1GB)
            Root    = $_.Root
        }
    }
    Add-MDTable -Headers @('Drive','Total','Used','Free','Root') -Rows $diskRows

    if ($diskRows | Where-Object { [float]($_.Free -replace ' GB','') -lt 5 }) {
        Write-Finding "One or more volumes has < 5 GB free" WARN
    }

    # Hotfixes / patches
    Write-Status "Enumerating installed hotfixes"
    Add-MD "### 1.3 Recent Hotfixes (Last 60 Days)"
    Add-MD ""
    $cutoff = (Get-Date).AddDays(-60)
    $hf = Get-HotFix | Where-Object { $_.InstalledOn -gt $cutoff } | Sort-Object InstalledOn -Descending
    if ($hf) {
        Add-MDTable -Headers @('HotFix ID','Description','Installed On','Installed By') -Rows (
            $hf | ForEach-Object { @{ 'HotFix ID'=$_.HotFixID; Description=$_.Description; 'Installed On'=$_.InstalledOn; 'Installed By'=$_.InstalledBy } }
        )
    } else {
        Write-Finding "No hotfixes applied in last 60 days — patching may be overdue" CRIT
        Add-MD "> ❌ **No hotfixes found in last 60 days — verify patching cadence**"
        Add-MD ""
    }

    # Last full patch
    $allHF = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1
    if ($allHF) {
        $daysSince = ((Get-Date) - $allHF.InstalledOn).Days
        if ($daysSince -gt 60) {
            Write-Finding "Last patch applied $daysSince days ago ($($allHF.HotFixID)) — OVERDUE" CRIT
        } elseif ($daysSince -gt 30) {
            Write-Finding "Last patch applied $daysSince days ago ($($allHF.HotFixID)) — approaching overdue" WARN
        } else {
            Write-Finding "Last patch: $($allHF.HotFixID) ($daysSince days ago)" PASS
        }
    }

    Write-BoxEnd
}

# ─────────────────────────────────────────────────────────────────────────────
#  MODULE 2: USER & ACCOUNT AUDIT
# ─────────────────────────────────────────────────────────────────────────────
function Invoke-UserAudit {
    Write-Box "MODULE 2 — USER & ACCOUNT SECURITY" Cyan
    Add-MD ""
    Add-MD "---"
    Add-MD "## 2. User & Account Security Audit"
    Add-MD ""

    # Local users
    Write-Status "Enumerating local users"
    Add-MD "### 2.1 Local User Accounts"
    Add-MD ""
    $users = Get-LocalUser
    $userRows = $users | ForEach-Object {
        $acct = $_
        $grps = (Get-LocalGroup | Where-Object { 
            (Get-LocalGroupMember -Group $_.Name -ErrorAction SilentlyContinue) | 
            Where-Object { $_.Name -match [regex]::Escape($acct.Name) }
        }).Name -join ', '
        
        @{
            Name         = $acct.Name
            Enabled      = if($acct.Enabled) {'✅'} else {'❌'}
            'Password Required' = if($acct.PasswordRequired) {'Yes'} else {'⚠️ No'}
            'Password Expires' = if($acct.PasswordExpires) {$acct.PasswordExpires.ToString('yyyy-MM-dd')} else {'Never ⚠️'}
            'Last Logon' = if($acct.LastLogon) {$acct.LastLogon.ToString('yyyy-MM-dd HH:mm')} else {'Never'}
            Groups       = if($grps) {$grps} else {'(none)'}
            SID          = $acct.SID.Value
        }
    }
    Add-MDTable -Headers @('Name','Enabled','Password Required','Password Expires','Last Logon','Groups') -Rows $userRows

    # Checks
    $users | Where-Object { $_.Enabled -and -not $_.PasswordRequired } | ForEach-Object {
        Write-Finding "Account '$($_.Name)' is enabled with no password required" CRIT
    }
    $users | Where-Object { $_.Enabled -and $_.PasswordExpires -eq $null } | ForEach-Object {
        Write-Finding "Account '$($_.Name)' has a non-expiring password" WARN
    }
    $adminAccount = $users | Where-Object { $_.SID.Value -match '-500$' }
    if ($adminAccount -and $adminAccount.Enabled) {
        Write-Finding "Built-in Administrator account (RID-500) is ENABLED" WARN
    } else {
        Write-Finding "Built-in Administrator account (RID-500) is disabled" PASS
    }
    if ($users | Where-Object { $_.Name -eq 'Guest' -and $_.Enabled }) {
        Write-Finding "Guest account is ENABLED" CRIT
    } else {
        Write-Finding "Guest account is disabled" PASS
    }

    # Local groups
    Write-Status "Enumerating local groups and members"
    Add-MD "### 2.2 Local Groups & Membership"
    Add-MD ""
    $sensitiveGroups = @('Administrators','Remote Desktop Users','Remote Management Users','Backup Operators','Power Users','Network Configuration Operators')
    foreach ($grp in $sensitiveGroups) {
        $members = Get-LocalGroupMember -Group $grp -ErrorAction SilentlyContinue
        if ($members) {
            Add-MD "#### $grp"
            Add-MDTable -Headers @('Name','Object Class','PrincipalSource') -Rows (
                $members | ForEach-Object { @{ Name=$_.Name; 'Object Class'=$_.ObjectClass; PrincipalSource=$_.PrincipalSource } }
            )
            $adminCount = ($members | Where-Object { $_.ObjectClass -eq 'User' }).Count
            if ($grp -eq 'Administrators' -and $adminCount -gt 3) {
                Write-Finding "Administrators group has $adminCount local user members — review for least privilege" WARN
            }
        }
    }

    # Password policy
    Write-Status "Checking local password policy"
    Add-MD "### 2.3 Local Password Policy"
    Add-MD ""
    $pwPol = net accounts 2>&1
    Add-MD "``````"
    $pwPol | ForEach-Object { Add-MD $_ }
    Add-MD "``````"
    Add-MD ""

    # Locked / disabled accounts with recent activity
    Write-Status "Checking for stale enabled accounts"
    $stale = $users | Where-Object { 
        $_.Enabled -and 
        $_.LastLogon -and 
        $_.LastLogon -lt (Get-Date).AddDays(-90) 
    }
    if ($stale) {
        Add-MD "### 2.4 Stale Active Accounts (No Logon > 90 Days)"
        Add-MD ""
        Add-MDTable -Headers @('Name','Last Logon','Days Since Logon') -Rows (
            $stale | ForEach-Object { 
                @{ 
                    Name='Last Logon'=$_.LastLogon.ToString('yyyy-MM-dd')
                    'Days Since Logon'=((Get-Date) - $_.LastLogon).Days
                }
            }
        )
        foreach ($s in $stale) {
            Write-Finding "Stale enabled account: '$($s.Name)' — last logon $([math]::Round(((Get-Date)-$s.LastLogon).Days)) days ago" WARN
        }
    }

    # Logon sessions
    Write-Status "Enumerating active logon sessions"
    Add-MD "### 2.5 Active Logon Sessions"
    Add-MD ""
    $sessions = query session 2>&1
    Add-MD "``````"
    $sessions | ForEach-Object { Add-MD $_ }
    Add-MD "``````"
    Add-MD ""

    Write-BoxEnd
}

# ─────────────────────────────────────────────────────────────────────────────
#  MODULE 3: ACTIVE DIRECTORY POLICY AUDIT
# ─────────────────────────────────────────────────────────────────────────────
function Invoke-ADPolicyAudit {
    Write-Box "MODULE 3 — ACTIVE DIRECTORY POLICY AUDIT" Yellow

    Add-MD ""
    Add-MD "---"
    Add-MD "## 3. Active Directory Policy Audit"
    Add-MD ""

    $adAvailable = $false
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        $domain = Get-ADDomain -ErrorAction Stop
        $adAvailable = $true
    } catch {
        Write-Finding "ActiveDirectory module not available or host is not domain-joined — limited AD audit" WARN
        Add-MD "> ⚠️ **AD module unavailable. Host may not be domain-joined or RSAT is missing.**"
        Add-MD ""
    }

    if ($adAvailable) {
        Write-Status "Pulling AD domain information"
        Add-MD "### 3.1 Domain Information"
        Add-MD ""
        Add-MDTable -Headers @('Property','Value') -Rows @(
            @{ Property='Domain Name';        Value=$domain.Name }
            @{ Property='DNS Root';           Value=$domain.DNSRoot }
            @{ Property='NetBIOS Name';       Value=$domain.NetBIOSName }
            @{ Property='Forest Name';        Value=$domain.Forest }
            @{ Property='Domain Mode';        Value=$domain.DomainMode }
            @{ Property='PDC Emulator';       Value=$domain.PDCEmulator }
            @{ Property='RID Master';         Value=$domain.RIDMaster }
            @{ Property='Infrastructure Master'; Value=$domain.InfrastructureMaster }
        )

        # Domain controllers
        Write-Status "Enumerating Domain Controllers"
        Add-MD "### 3.2 Domain Controllers"
        Add-MD ""
        $dcs = Get-ADDomainController -Filter * -ErrorAction SilentlyContinue
        if ($dcs) {
            Add-MDTable -Headers @('Name','Site','OS','IsGC','IsRODC','IPv4') -Rows (
                $dcs | ForEach-Object { @{
                    Name=$_.HostName; Site=$_.Site; OS=$_.OperatingSystem
                    IsGC=if($_.IsGlobalCatalog){'Yes'}else{'No'}
                    IsRODC=if($_.IsReadOnly){'Yes'}else{'No'}
                    IPv4=$_.IPv4Address
                }}
            )
            $rodcs = $dcs | Where-Object { $_.IsReadOnly }
            if ($rodcs) { Write-Finding "RODC(s) present: $($rodcs.HostName -join ', ')" INFO }
        }

        # Default Domain Password Policy
        Write-Status "Reading default domain password policy"
        Add-MD "### 3.3 Default Domain Password Policy"
        Add-MD ""
        $pp = Get-ADDefaultDomainPasswordPolicy -ErrorAction SilentlyContinue
        if ($pp) {
            Add-MDTable -Headers @('Policy Setting','Value','Recommendation','Status') -Rows @(
                @{ 'Policy Setting'='Min Password Length';   Value=$pp.MinPasswordLength;       Recommendation='≥ 14'; Status=if($pp.MinPasswordLength -ge 14){'✅ Pass'}elseif($pp.MinPasswordLength -ge 8){'⚠️ Marginal'}else{'❌ Fail'} }
                @{ 'Policy Setting'='Password History';      Value=$pp.PasswordHistoryCount;     Recommendation='≥ 24'; Status=if($pp.PasswordHistoryCount -ge 24){'✅ Pass'}else{'⚠️ Review'} }
                @{ 'Policy Setting'='Max Password Age';      Value=$pp.MaxPasswordAge;           Recommendation='≤ 365d'; Status='ℹ️ See Policy' }
                @{ 'Policy Setting'='Min Password Age';      Value=$pp.MinPasswordAge;           Recommendation='≥ 1d'; Status=if($pp.MinPasswordAge.TotalDays -ge 1){'✅ Pass'}else{'⚠️ Review'} }
                @{ 'Policy Setting'='Complexity Enabled';    Value=$pp.ComplexityEnabled;        Recommendation='True'; Status=if($pp.ComplexityEnabled){'✅ Pass'}else{'❌ Fail'} }
                @{ 'Policy Setting'='Reversible Encryption'; Value=$pp.ReversibleEncryptionEnabled; Recommendation='False'; Status=if(-not $pp.ReversibleEncryptionEnabled){'✅ Pass'}else{'❌ CRITICAL'} }
                @{ 'Policy Setting'='Account Lockout Threshold'; Value=$pp.LockoutThreshold;    Recommendation='≤ 10'; Status=if($pp.LockoutThreshold -gt 0 -and $pp.LockoutThreshold -le 10){'✅ Pass'}elseif($pp.LockoutThreshold -eq 0){'❌ No Lockout'}else{'⚠️ Review'} }
                @{ 'Policy Setting'='Lockout Duration';      Value=$pp.LockoutDuration;          Recommendation='≥ 30m'; Status='ℹ️ See Policy' }
            )
            if ($pp.ReversibleEncryptionEnabled) { Write-Finding "Reversible encryption is ENABLED — passwords stored in plaintext-equivalent form" CRIT }
            if ($pp.LockoutThreshold -eq 0)       { Write-Finding "Account lockout threshold is 0 — no lockout policy (brute-force risk)" CRIT }
            if ($pp.MinPasswordLength -lt 8)      { Write-Finding "Minimum password length < 8 characters" CRIT }
            if ($pp.ComplexityEnabled -eq $false) { Write-Finding "Password complexity is DISABLED" WARN }
        }

        # Fine-grained password policies
        Write-Status "Checking for fine-grained password policies (PSO)"
        $fgpp = Get-ADFineGrainedPasswordPolicy -Filter * -ErrorAction SilentlyContinue
        if ($fgpp) {
            Add-MD "### 3.4 Fine-Grained Password Policies (PSOs)"
            Add-MD ""
            Add-MDTable -Headers @('Name','Precedence','Min Length','Lockout Threshold','Applies To') -Rows (
                $fgpp | ForEach-Object { @{
                    Name=$_.Name; Precedence=$_.Precedence; 'Min Length'=$_.MinPasswordLength
                    'Lockout Threshold'=$_.LockoutThreshold
                    'Applies To'=($_.AppliesTo -join ', ')
                }}
            )
        }

        # Privileged accounts
        Write-Status "Auditing privileged AD accounts"
        Add-MD "### 3.5 Privileged Account Audit"
        Add-MD ""
        $privGroups = @('Domain Admins','Enterprise Admins','Schema Admins','Administrators','Group Policy Creator Owners')
        foreach ($pg in $privGroups) {
            $members = Get-ADGroupMember -Identity $pg -Recursive -ErrorAction SilentlyContinue
            if ($members) {
                Add-MD "#### $pg ($($members.Count) members)"
                Add-MDTable -Headers @('Name','SAMAccountName','ObjectClass','Enabled') -Rows (
                    $members | ForEach-Object {
                        $usr = $null
                        if ($_.objectClass -eq 'user') { $usr = Get-ADUser $_ -Properties Enabled -ErrorAction SilentlyContinue }
                        @{
                            Name=$_.Name; SAMAccountName=$_.SamAccountName
                            ObjectClass=$_.objectClass
                            Enabled=if($usr){if($usr.Enabled){'✅'}else{'❌ Disabled'}}else{'(group)'}
                        }
                    }
                )
                if ($members.Count -gt 5 -and $pg -in @('Domain Admins','Enterprise Admins','Schema Admins')) {
                    Write-Finding "$pg has $($members.Count) members — review for least privilege" WARN
                }
            }
        }

        # Privileged users with no MFA / Kerberos indicators
        Write-Status "Checking for Kerberos delegation settings"
        Add-MD "### 3.6 Kerberos Delegation (Risk Accounts)"
        Add-MD ""
        $unconstrained = Get-ADComputer -Filter { TrustedForDelegation -eq $true } -Properties TrustedForDelegation -ErrorAction SilentlyContinue
        if ($unconstrained) {
            Add-MDTable -Headers @('Name','DN') -Rows ($unconstrained | ForEach-Object { @{ Name=$_.Name; DN=$_.DistinguishedName } })
            foreach ($uc in $unconstrained) {
                Write-Finding "Computer '$($uc.Name)' has UNCONSTRAINED Kerberos delegation enabled" CRIT
            }
        } else {
            Write-Finding "No computers with unconstrained Kerberos delegation found" PASS
        }

        $unconstrainedUsers = Get-ADUser -Filter { TrustedForDelegation -eq $true } -Properties TrustedForDelegation -ErrorAction SilentlyContinue
        if ($unconstrainedUsers) {
            foreach ($u in $unconstrainedUsers) {
                Write-Finding "User '$($u.SamAccountName)' has unconstrained delegation — potential for privilege escalation" CRIT
            }
        }

        # AS-REP Roasting candidates
        Write-Status "Checking for AS-REP Roasting candidates"
        $asrep = Get-ADUser -Filter { DoesNotRequirePreAuth -eq $true } -Properties DoesNotRequirePreAuth -ErrorAction SilentlyContinue
        if ($asrep) {
            Add-MD "### 3.7 AS-REP Roasting Candidates (Pre-Auth Disabled)"
            Add-MD ""
            Add-MDTable -Headers @('SAMAccountName','DistinguishedName') -Rows (
                $asrep | ForEach-Object { @{ SAMAccountName=$_.SamAccountName; DistinguishedName=$_.DistinguishedName } }
            )
            foreach ($a in $asrep) {
                Write-Finding "AS-REP Roasting: '$($a.SamAccountName)' does not require Kerberos pre-auth" CRIT
            }
        } else {
            Write-Finding "No AS-REP Roasting candidates found (Kerberos pre-auth required on all users)" PASS
        }

        # SPN / Kerberoasting candidates
        Write-Status "Checking for Kerberoasting candidates (SPNs on user accounts)"
        $spnUsers = Get-ADUser -Filter { ServicePrincipalNames -ne '' } -Properties ServicePrincipalNames -ErrorAction SilentlyContinue
        if ($spnUsers) {
            Add-MD "### 3.8 Kerberoasting Candidates (User Accounts with SPNs)"
            Add-MD ""
            Add-MDTable -Headers @('SAMAccountName','SPNs') -Rows (
                $spnUsers | ForEach-Object { @{
                    SAMAccountName=$_.SamAccountName
                    SPNs=($_.ServicePrincipalNames -join '; ')
                }}
            )
            foreach ($s in $spnUsers) {
                Write-Finding "Kerberoasting risk: user '$($s.SamAccountName)' has SPN(s) set — hash extractable" WARN
            }
        } else {
            Write-Finding "No user accounts with SPNs found (Kerberoasting not directly applicable)" PASS
        }

        # AdminSDHolder protected accounts
        Write-Status "Enumerating AdminSDHolder-protected accounts"
        $adminSD = Get-ADUser -LDAPFilter '(adminCount=1)' -Properties adminCount -ErrorAction SilentlyContinue
        if ($adminSD) {
            Add-MD "### 3.9 AdminSDHolder Protected Accounts (adminCount=1)"
            Add-MD ""
            Add-MDTable -Headers @('SAMAccountName','Distinguished Name') -Rows (
                $adminSD | ForEach-Object { @{ SAMAccountName=$_.SamAccountName; 'Distinguished Name'=$_.DistinguishedName } }
            )
            Write-Finding "$($adminSD.Count) accounts with adminCount=1 — verify all are intentional" INFO
        }

        # LAPS
        Write-Status "Checking for LAPS deployment"
        $lapsAttr = Get-ADObject -SearchBase (Get-ADRootDSE).SchemaNamingContext -LDAPFilter '(lDAPDisplayName=ms-Mcs-AdmPwd)' -ErrorAction SilentlyContinue
        if ($lapsAttr) {
            Write-Finding "LAPS schema attributes detected — verify LAPS is deployed to all computers" PASS
            Add-MD "### 3.10 LAPS: ✅ Schema attributes present"
        } else {
            Write-Finding "LAPS schema attributes NOT found — local admin passwords not managed by LAPS" WARN
            Add-MD "### 3.10 LAPS: ❌ Not deployed (schema attributes missing)"
        }
        Add-MD ""
    }

    Write-BoxEnd
}

# ─────────────────────────────────────────────────────────────────────────────
#  MODULE 4: GROUP POLICY AUDIT
# ─────────────────────────────────────────────────────────────────────────────
function Invoke-GPOAudit {
    Write-Box "MODULE 4 — GROUP POLICY OBJECTS" Yellow
    Add-MD ""
    Add-MD "---"
    Add-MD "## 4. Group Policy Object (GPO) Audit"
    Add-MD ""

    # Resultant Set of Policy (local)
    Write-Status "Running gpresult for effective policy (this may take a moment)"
    Add-MD "### 4.1 Effective Policy (gpresult /r)"
    Add-MD ""
    $gpResult = gpresult /r 2>&1
    Add-MD "``````"
    $gpResult | ForEach-Object { Add-MD $_ }
    Add-MD "``````"
    Add-MD ""

    # GPO list via AD
    $adAvailable = $false
    try {
        Import-Module GroupPolicy -ErrorAction Stop
        $adAvailable = $true
    } catch {
        Write-Finding "GroupPolicy module not available — cannot enumerate AD GPOs" WARN
        Add-MD "> ⚠️ GroupPolicy RSAT module not available."
    }

    if ($adAvailable) {
        Write-Status "Enumerating all Group Policy Objects"
        $gpos = Get-GPO -All -ErrorAction SilentlyContinue
        if ($gpos) {
            Add-MD "### 4.2 All GPOs in Domain"
            Add-MD ""
            Add-MDTable -Headers @('Name','Status','Created','Modified','ID') -Rows (
                $gpos | ForEach-Object { @{
                    Name=$_.DisplayName; Status=$_.GpoStatus
                    Created=$_.CreationTime.ToString('yyyy-MM-dd')
                    Modified=$_.ModificationTime.ToString('yyyy-MM-dd')
                    ID=$_.Id
                }}
            )

            $disabled = $gpos | Where-Object { $_.GpoStatus -eq 'AllSettingsDisabled' }
            foreach ($d in $disabled) {
                Write-Finding "GPO '$($d.DisplayName)' is fully disabled — review if intentional" WARN
            }

            # GPO links
            Write-Status "Checking GPO links and inheritance"
            Add-MD "### 4.3 Default Domain Policy Settings (Security)"
            Add-MD ""
            $ddp = Get-GPO -Name 'Default Domain Policy' -ErrorAction SilentlyContinue
            if ($ddp) {
                $rpt = Get-GPOReport -Guid $ddp.Id -ReportType XML -ErrorAction SilentlyContinue
                if ($rpt) {
                    [xml]$xml = $rpt
                    Add-MD "GPO Name: **$($ddp.DisplayName)**"
                    Add-MD ""
                    Add-MD "Full GPO report available via: ``Get-GPOReport -Name 'Default Domain Policy' -ReportType HTML -Path output.html``"
                    Add-MD ""
                }
            }

            # Unlinked GPOs
            Write-Status "Detecting unlinked GPOs"
            Add-MD "### 4.4 Unlinked GPOs"
            Add-MD ""
            $unlinked = @()
            foreach ($gpo in $gpos) {
                $report = [xml](Get-GPOReport -Guid $gpo.Id -ReportType XML -ErrorAction SilentlyContinue)
                if ($report -and $report.GPO.LinksTo -eq $null) {
                    $unlinked += $gpo
                }
            }
            if ($unlinked) {
                Add-MDTable -Headers @('Name','ID','Modified') -Rows (
                    $unlinked | ForEach-Object { @{
                        Name=$_.DisplayName; ID=$_.Id
                        Modified=$_.ModificationTime.ToString('yyyy-MM-dd')
                    }}
                )
                foreach ($u in $unlinked) {
                    Write-Finding "Unlinked GPO: '$($u.DisplayName)' — no scope; review for orphan cleanup" INFO
                }
            } else {
                Write-Finding "All GPOs appear to be linked" PASS
            }
        }
    }

    # Local security policy
    Write-Status "Dumping local security policy (secedit)"
    Add-MD "### 4.5 Local Security Policy (secedit export)"
    Add-MD ""
    $secTmp = "$env:TEMP\hps_secedit_$(Get-Date -Format 'yyyyMMddHHmmss').inf"
    secedit /export /cfg $secTmp /quiet 2>&1 | Out-Null
    if (Test-Path $secTmp) {
        $secContent = Get-Content $secTmp
        Add-MD "``````ini"
        $secContent | ForEach-Object { Add-MD $_ }
        Add-MD "``````"
        Remove-Item $secTmp -Force
    }
    Add-MD ""

    Write-BoxEnd
}

# ─────────────────────────────────────────────────────────────────────────────
#  MODULE 5: NETWORK — FULL DEEP DIVE
# ─────────────────────────────────────────────────────────────────────────────
function Invoke-NetworkAudit {
    Write-Box "MODULE 5 — NETWORK: FULL DEEP DIVE" Cyan
    Add-MD ""; Add-MD "---"; Add-MD "## 5. Network Configuration — Full Deep Dive"; Add-MD ""

    # ── 5.1 ADAPTER INVENTORY ────────────────────────────────────────────────
    Invoke-Safe "Adapter Inventory" {
        Write-Status "Enumerating all network adapters"
        Write-Divider "ADAPTERS"
        Add-MD "### 5.1 Network Adapter Inventory"; Add-MD ""
        $adapters = Get-NetAdapter -ErrorAction SilentlyContinue
        $rows = $adapters | ForEach-Object {
            $col = if ($_.Status -eq 'Up') { [ConsoleColor]::Green } elseif ($_.Status -eq 'Disconnected') { [ConsoleColor]::DarkGray } else { [ConsoleColor]::Yellow }
            Write-DataLine $_.Name "$($_.Status) | $($_.LinkSpeed) | MAC: $($_.MacAddress)" $col
            @{ Name=$_.Name; Description=$_.InterfaceDescription; Status=$_.Status; Speed=$_.LinkSpeed; MAC=$_.MacAddress; Index=$_.ifIndex }
        }
        Add-MDTable -Headers @('Name','Description','Status','Speed','MAC','Index') -Rows $rows
        $adapters | Where-Object { $_.Status -eq 'Up' -and $_.Virtual } | ForEach-Object {
            Write-Finding "Virtual adapter active: '$($_.Name)' — verify expected purpose" INFO
        }
    }

    # ── 5.2 IP CONFIGURATION ─────────────────────────────────────────────────
    Invoke-Safe "IP Configuration" {
        Write-Status "Collecting full IP configuration per interface"
        Write-Divider "IP CONFIG"
        Add-MD "### 5.2 IP Address Configuration"; Add-MD ""
        $cfgs = Get-NetIPConfiguration -Detailed -ErrorAction SilentlyContinue
        foreach ($ifc in $cfgs) {
            if (-not $ifc.IPv4Address -and -not $ifc.IPv6Address) { continue }
            Add-MD "#### Interface: $($ifc.InterfaceAlias)"
            $rows = @(
                @{ Property='Index';        Value=$ifc.InterfaceIndex }
                @{ Property='Description';  Value=$ifc.InterfaceDescription }
                @{ Property='IPv4 Address'; Value=if ($ifc.IPv4Address) { ($ifc.IPv4Address.IPAddress -join ', ') } else { 'None' } }
                @{ Property='Prefix Length';Value=if ($ifc.IPv4Address) { ($ifc.IPv4Address.PrefixLength -join ', ') } else { 'None' } }
                @{ Property='Default GW';   Value=if ($ifc.IPv4DefaultGateway) { $ifc.IPv4DefaultGateway.NextHop } else { 'None' } }
                @{ Property='DNS Servers';  Value=($ifc.DNSServer.ServerAddresses -join ', ') }
                @{ Property='IPv6 Address'; Value=if ($ifc.IPv6Address) { ($ifc.IPv6Address.IPAddress -join ', ') } else { 'None' } }
            )
            $rows | ForEach-Object { Write-DataLine $_.Property $_.Value }
            Add-MDTable -Headers @('Property','Value') -Rows $rows
        }
        # APIPA detection
        $apipa = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -match '^169\.254\.' }
        if ($apipa) {
            foreach ($a in $apipa) { Write-Finding "APIPA on '$($a.InterfaceAlias)': $($a.IPAddress) — DHCP failure or no network" WARN }
        } else { Write-Finding "No APIPA addresses — DHCP appears healthy" PASS }
    }

    # ── 5.3 ipconfig /all ────────────────────────────────────────────────────
    Invoke-Safe "ipconfig /all" {
        Write-Status "Capturing ipconfig /all"
        Write-Divider "IPCONFIG /ALL"
        Add-MD "### 5.3 ipconfig /all"; Add-MD '```'
        ipconfig /all 2>&1 | ForEach-Object { Add-MD $_; Write-DataLine "" $_ }
        Add-MD '```'; Add-MD ""
    }

    # ── 5.4 DNS CONFIG & RESOLUTION ──────────────────────────────────────────
    Invoke-Safe "DNS Audit" {
        Write-Status "Auditing DNS client configuration and resolution"
        Write-Divider "DNS"
        Add-MD "### 5.4 DNS Client Configuration"; Add-MD ""
        $dnsClients = Get-DnsClientServerAddress -ErrorAction SilentlyContinue | Where-Object { $_.ServerAddresses }
        if ($dnsClients) {
            Add-MDTable -Headers @('Interface','Family','DNS Servers') -Rows (
                $dnsClients | ForEach-Object {
                    Write-DataLine $_.InterfaceAlias ($_.ServerAddresses -join ', ')
                    @{ Interface=$_.InterfaceAlias; Family=$_.AddressFamily; 'DNS Servers'=($_.ServerAddresses -join ', ') }
                }
            )
        }
        # Live resolution tests
        @('www.google.com','cloudflare.com') | ForEach-Object {
            $r = Resolve-DnsName $_ -ErrorAction SilentlyContinue
            if ($r) { Write-Finding "External DNS OK: $_ -> $($r[0].IPAddress)" PASS }
            else     { Write-Finding "External DNS FAILED: $_" WARN }
        }
        # DNS client cache sample
        Add-MD "### 5.4.1 DNS Client Cache (first 25 entries)"; Add-MD ""
        $cache = Get-DnsClientCache -ErrorAction SilentlyContinue | Select-Object -First 25
        if ($cache) {
            Add-MDTable -Headers @('Entry','Type','Data','TTL') -Rows (
                $cache | ForEach-Object { @{ Entry=$_.Entry; Type=$_.Type; Data=$_.Data; TTL=$_.TimeToLive } }
            )
        }
        Add-MD ""
    }

    # ── 5.5 ROUTING TABLE ────────────────────────────────────────────────────
    Invoke-Safe "Routing Table" {
        Write-Status "Capturing full routing table"
        Write-Divider "ROUTING"
        Add-MD "### 5.5 Routing Table (route print)"; Add-MD '```'
        route print 2>&1 | ForEach-Object { Add-MD $_ }
        Add-MD '```'; Add-MD ""
        # Structured routes via PowerShell
        $routes = Get-NetRoute -ErrorAction SilentlyContinue | Where-Object { $_.RouteMetric -lt 256 } | Select-Object -First 40
        if ($routes) {
            Add-MD "### 5.5.1 Active Routes (Get-NetRoute)"; Add-MD ""
            Add-MDTable -Headers @('Destination','NextHop','Interface','Metric') -Rows (
                $routes | ForEach-Object { @{ Destination=$_.DestinationPrefix; NextHop=$_.NextHop; Interface=$_.InterfaceAlias; Metric=$_.RouteMetric } }
            )
        }
        Add-MD ""
    }

    # ── 5.6 NETSTAT FULL ─────────────────────────────────────────────────────
    Invoke-Safe "Netstat Full" {
        Write-Status "Running netstat -anob — all connections with process mapping"
        Write-Divider "NETSTAT -ANOB"
        Add-MD "### 5.6 netstat -anob (All Connections)"; Add-MD '```'
        netstat -anob 2>&1 | ForEach-Object { Add-MD $_ }
        Add-MD '```'; Add-MD ""
        # Protocol statistics
        Write-Status "Capturing netstat -s protocol statistics"
        Add-MD "### 5.6.1 Protocol Statistics (netstat -s)"; Add-MD '```'
        netstat -s 2>&1 | ForEach-Object { Add-MD $_ }
        Add-MD '```'; Add-MD ""
    }

    # ── 5.7 LISTENING PORTS — CLASSIFIED ─────────────────────────────────────
    Invoke-Safe "Listening Ports" {
        Write-Status "Parsing and classifying all TCP/UDP listeners"
        Write-Divider "LISTENERS"
        $knownPorts = @{
            21='FTP';22='SSH';23='TELNET';25='SMTP';53='DNS';80='HTTP';88='Kerberos'
            110='POP3';135='RPC';139='NetBIOS';143='IMAP';389='LDAP';443='HTTPS'
            445='SMB';464='Kerberos-chpw';587='SMTP-Submit';636='LDAPS';993='IMAPS'
            995='POP3S';1433='SQL';1434='SQL-Browser';1494='Citrix-ICA';2598='Citrix-CGP'
            3268='GC-LDAP';3269='GC-LDAPS';3389='RDP';4022='SQL-SvcBroker'
            5985='WinRM-HTTP';5986='WinRM-HTTPS';8080='HTTP-Alt';8443='HTTPS-Alt'
        }
        $riskyPorts = @(21,23,110,143,514,1434,4444,6667,31337,9001,8888,4045)

        Add-MD "### 5.7 Listening Ports — Classified"; Add-MD ""
        $listening = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Sort-Object LocalPort
        $rows = $listening | ForEach-Object {
            $proc = try { (Get-Process -Id $_.OwningProcess -EA Stop).Name } catch { 'system' }
            $svc  = if ($knownPorts.ContainsKey($_.LocalPort)) { $knownPorts[$_.LocalPort] } else { 'Unknown' }
            $flag = if ($_.LocalPort -in $riskyPorts) { 'RISKY' } elseif ($svc -eq 'Unknown') { 'Review' } else { 'OK' }
            $col  = switch ($flag) { 'RISKY' { [ConsoleColor]::Red } 'Review' { [ConsoleColor]::Yellow } default { [ConsoleColor]::DarkGray } }
            Write-DataLine "TCP/$($_.LocalPort)" "$svc | $proc | $flag" $col
            if ($_.LocalPort -in $riskyPorts)                                { Write-Finding "Risky port open: TCP/$($_.LocalPort) ($svc) — $proc PID:$($_.OwningProcess)" CRIT }
            elseif ($svc -eq 'Unknown' -and $_.LocalPort -lt 49152)         { Write-Finding "Unknown service TCP/$($_.LocalPort) — $proc PID:$($_.OwningProcess)" WARN }
            @{ 'Local Address'="$($_.LocalAddress):$($_.LocalPort)"; Service=$svc; PID=$_.OwningProcess; Process=$proc; Flag=$flag }
        }
        Add-MDTable -Headers @('Local Address','Service','PID','Process','Flag') -Rows $rows

        # Specific high-risk checks
        if ($listening | Where-Object { $_.LocalPort -eq 23 }) { Write-Finding "TELNET (23) is listening — plaintext credential exposure" CRIT }
        if ($listening | Where-Object { $_.LocalPort -eq 21 }) { Write-Finding "FTP (21) is listening — unencrypted transfers" WARN }

        # UDP listeners
        Add-MD "### 5.7.1 UDP Endpoints (sample)"; Add-MD ""
        $udp = Get-NetUDPEndpoint -ErrorAction SilentlyContinue | Sort-Object LocalPort | Select-Object -First 30
        if ($udp) {
            Add-MDTable -Headers @('Local Address','Port','PID') -Rows (
                $udp | ForEach-Object { @{ 'Local Address'=$_.LocalAddress; Port=$_.LocalPort; PID=$_.OwningProcess } }
            )
        }
        Add-MD ""
    }

    # ── 5.8 ESTABLISHED CONNECTIONS ──────────────────────────────────────────
    Invoke-Safe "Established Connections" {
        Write-Status "Analysing all established TCP connections"
        Write-Divider "ESTABLISHED"
        Add-MD "### 5.8 Established Connections"; Add-MD ""
        $allEst = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue
        # External
        $extEst = $allEst | Where-Object {
            $_.RemoteAddress -notmatch '^(127\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|::1|^0\.)'
        }
        Add-MD "#### External Connections"
        if ($extEst) {
            $extRows = $extEst | ForEach-Object {
                $proc = try { (Get-Process -Id $_.OwningProcess -EA Stop).Name } catch { 'unknown' }
                Write-DataLine "$proc -> $($_.RemoteAddress)" ":$($_.RemotePort)" [ConsoleColor]::Yellow
                @{ 'Remote IP'=$_.RemoteAddress; 'Remote Port'=$_.RemotePort; 'Local Port'=$_.LocalPort; PID=$_.OwningProcess; Process=$proc }
            }
            Add-MDTable -Headers @('Remote IP','Remote Port','Local Port','PID','Process') -Rows $extRows
        } else {
            Write-Finding "No established external connections at scan time" PASS
            Add-MD "*None at scan time.*"
        }
        # Internal summary by process
        $intEst = $allEst | Where-Object { $_ -notin $extEst }
        Add-MD ""; Add-MD "#### Internal Connection Summary ($($intEst.Count) connections)"
        $grp = $intEst | Group-Object { try{(Get-Process -Id $_.OwningProcess -EA Stop).Name}catch{'unknown'} } | Sort-Object Count -Descending
        if ($grp) {
            Add-MDTable -Headers @('Process','Count') -Rows ($grp | ForEach-Object { @{ Process=$_.Name; Count=$_.Count } })
        }
        Add-MD ""
    }

    # ── 5.9 CONNECTION STATE SUMMARY ─────────────────────────────────────────
    Invoke-Safe "Connection States" {
        Write-Status "Checking for TIME_WAIT / CLOSE_WAIT accumulation"
        Write-Divider "CONN STATES"
        Add-MD "### 5.9 TCP Connection State Summary"; Add-MD ""
        $states = Get-NetTCPConnection -ErrorAction SilentlyContinue | Group-Object State | Sort-Object Count -Descending
        $rows = $states | ForEach-Object { Write-DataLine $_.Name $_.Count; @{ State=$_.Name; Count=$_.Count } }
        Add-MDTable -Headers @('State','Count') -Rows $rows
        $cw = ($states | Where-Object { $_.Name -eq 'CloseWait' }).Count
        if ($cw -and $cw -gt 50) { Write-Finding "$cw CLOSE_WAIT connections — possible app leak or stale sessions" WARN }
        else { Write-Finding "Connection state distribution looks normal" PASS }
        Add-MD ""
    }

    # ── 5.10 ARP TABLE ───────────────────────────────────────────────────────
    Invoke-Safe "ARP Cache" {
        Write-Status "Capturing ARP cache and checking for duplicate MACs (ARP spoofing)"
        Write-Divider "ARP"
        Add-MD "### 5.10 ARP Cache"; Add-MD '```'
        $arpOut = arp -a 2>&1
        $arpOut | ForEach-Object { Add-MD $_ }
        Add-MD '```'; Add-MD ""
        # Duplicate MAC detection
        $macs = $arpOut | ForEach-Object {
            if ($_ -match '((?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2})') { $Matches[1] }
        } | Where-Object { $_ }
        $dups = $macs | Group-Object | Where-Object { $_.Count -gt 1 }
        if ($dups) {
            foreach ($d in $dups) { Write-Finding "DUPLICATE MAC in ARP: $($d.Name) — possible ARP spoofing/poisoning" IOC }
        } else { Write-Finding "No duplicate MACs in ARP cache" PASS }
    }

    # ── 5.11 HOSTS FILE ──────────────────────────────────────────────────────
    Invoke-Safe "Hosts File" {
        Write-Status "Reading and analysing hosts file for hijack entries"
        Write-Divider "HOSTS FILE"
        Add-MD "### 5.11 Hosts File"; Add-MD '```'
        $hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
        if (Test-Path $hostsPath) {
            $lines = Get-Content $hostsPath
            $lines | ForEach-Object { Add-MD $_ }
            Add-MD '```'; Add-MD ""
            $active = $lines | Where-Object { $_ -notmatch '^\s*#' -and $_ -match '\S' }
            foreach ($h in $active) {
                Write-DataLine "hosts entry" $h [ConsoleColor]::Yellow
                if ($h -match 'google|microsoft|windows|update|antivirus|defender|wpad') {
                    Write-Finding "SUSPICIOUS hosts redirect: $h — possible malware hijack" IOC
                } else { Write-Finding "Hosts file entry: $h" INFO }
            }
            if (-not $active) { Write-Finding "Hosts file is default — no custom entries" PASS }
        }
    }

    # ── 5.12 WIFI PROFILES ───────────────────────────────────────────────────
    Invoke-Safe "WiFi Profiles" {
        Write-Status "Enumerating stored WiFi profiles"
        Write-Divider "WIFI"
        Add-MD "### 5.12 Stored WiFi Profiles"; Add-MD ""
        $wifi = netsh wlan show profiles 2>&1
        if ($wifi -notmatch 'There is no wireless interface') {
            Add-MD '```'; $wifi | ForEach-Object { Add-MD $_ }; Add-MD '```'; Add-MD ""
            $wifi | Where-Object { $_ -match 'All User Profile' } | ForEach-Object {
                $pn = ($_ -replace '.*:\s*','').Trim()
                Write-DataLine "WiFi Profile" $pn [ConsoleColor]::Yellow
                Write-Finding "Stored WiFi profile on server: '$pn' — verify this is intentional" WARN
            }
        } else { Write-Finding "No wireless interfaces — expected on a server" PASS; Add-MD "*No wireless interfaces.*"; Add-MD "" }
    }

    # ── 5.13 SMB SHARES + ACLs ───────────────────────────────────────────────
    Invoke-Safe "SMB Shares" {
        Write-Status "Enumerating SMB shares with ACLs"
        Write-Divider "SMB SHARES"
        Add-MD "### 5.13 SMB Share Inventory & ACLs"; Add-MD ""
        $shares = Get-SmbShare -ErrorAction SilentlyContinue
        foreach ($sh in $shares) {
            $isAdmin = $sh.Name -match '^\w+\$$'
            $col     = if (-not $isAdmin) { [ConsoleColor]::Yellow } else { [ConsoleColor]::DarkGray }
            Write-DataLine $sh.Name $sh.Path $col
            Add-MD "#### $($sh.Name) $(if($isAdmin){'[admin$]'}) — $($sh.Path)"
            $acl = Get-SmbShareAccess -Name $sh.Name -ErrorAction SilentlyContinue
            if ($acl) {
                Add-MDTable -Headers @('Account','Access','Right') -Rows (
                    $acl | ForEach-Object { @{ Account=$_.AccountName; Access=$_.AccessControlType; Right=$_.AccessRight } }
                )
                $acl | Where-Object { $_.AccountName -match 'Everyone' -and $_.AccessRight -ne 'Read' } | ForEach-Object {
                    Write-Finding "Share '$($sh.Name)' grants $($_.AccessRight) to Everyone" CRIT
                }
            }
            if (-not $sh.EncryptData -and -not $isAdmin) { Write-Finding "Share '$($sh.Name)' has no SMB encryption" WARN }
        }
        Add-MD ""
    }

    # ── 5.14 SMB SERVER CONFIG ────────────────────────────────────────────────
    Invoke-Safe "SMB Config" {
        Write-Status "Auditing SMB server security config"
        Write-Divider "SMB CONFIG"
        Add-MD "### 5.14 SMB Server Security Configuration"; Add-MD ""
        $cfg = Get-SmbServerConfiguration -ErrorAction SilentlyContinue
        if ($cfg) {
            Add-MDTable -Headers @('Setting','Value','Status') -Rows @(
                @{ Setting='SMBv1 Enabled';          Value=$cfg.EnableSMB1Protocol;       Status=if(-not $cfg.EnableSMB1Protocol){'OK'}else{'CRITICAL — EternalBlue risk'} }
                @{ Setting='SMBv2 Enabled';          Value=$cfg.EnableSMB2Protocol;       Status=if($cfg.EnableSMB2Protocol){'OK'}else{'WARNING'} }
                @{ Setting='Signing Required';        Value=$cfg.RequireSecuritySignature; Status=if($cfg.RequireSecuritySignature){'OK'}else{'WARNING — relay risk'} }
                @{ Setting='Encrypt Data';            Value=$cfg.EncryptData;              Status=if($cfg.EncryptData){'OK'}else{'Consider enabling'} }
                @{ Setting='Null Session Pipes';      Value=($cfg.NullSessionPipes -join ','); Status=if(-not $cfg.NullSessionPipes){'OK'}else{'Review'} }
            )
            if ($cfg.EnableSMB1Protocol)            { Write-Finding "SMBv1 is ENABLED — EternalBlue/WannaCry attack surface" CRIT }
            else                                     { Write-Finding "SMBv1 is disabled" PASS }
            if (-not $cfg.RequireSecuritySignature) { Write-Finding "SMB signing not required — NTLM relay attacks possible" WARN }
            else                                     { Write-Finding "SMB signing required" PASS }
        }
        Add-MD ""
    }

    # ── 5.15 OPEN FILES ──────────────────────────────────────────────────────
    Invoke-Safe "Open Files" {
        Write-Status "Checking currently open network files"
        Write-Divider "OPEN FILES"
        Add-MD "### 5.15 Currently Open Network Files"; Add-MD ""
        $openFiles = Get-SmbOpenFile -ErrorAction SilentlyContinue
        if ($openFiles) {
            Write-DataLine "Open files" $openFiles.Count
            Add-MDTable -Headers @('FileId','Path','Client','SessionId') -Rows (
                $openFiles | Select-Object -First 50 | ForEach-Object {
                    @{ FileId=$_.FileId; Path=$_.Path; Client=$_.ClientComputerName; SessionId=$_.SessionId }
                }
            )
        } else { Write-Finding "No open network files at scan time" PASS; Add-MD "*None.*" }
        Add-MD ""
    }

    # ── 5.16 PROXY & WINSOCK ─────────────────────────────────────────────────
    Invoke-Safe "Proxy and WinSock" {
        Write-Status "Checking proxy settings and WinSock catalog"
        Write-Divider "PROXY / WINSOCK"
        Add-MD "### 5.16 Proxy Settings"; Add-MD '```'
        netsh winhttp show proxy 2>&1 | ForEach-Object { Add-MD $_ }
        Add-MD '```'; Add-MD ""
        $regProxy = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction SilentlyContinue
        if ($regProxy.ProxyEnable -eq 1) {
            Write-Finding "System proxy ENABLED: $($regProxy.ProxyServer)" WARN
            Add-MD "- **IE/System Proxy:** $($regProxy.ProxyServer)"
        } else { Write-Finding "No system proxy configured" PASS }
        # WinSock LSP check
        Add-MD "### 5.16.1 WinSock LSP Catalog (first 30 lines)"; Add-MD '```'
        $wsc = netsh winsock show catalog 2>&1
        $wsc | Select-Object -First 30 | ForEach-Object { Add-MD $_ }
        Add-MD '```'; Add-MD ""
        if ($wsc -match 'unknown|inject|spy') { Write-Finding "Suspicious string in WinSock catalog — possible LSP injection" IOC }
        else { Write-Finding "WinSock catalog appears normal" PASS }
    }

    # ── 5.17 NETWORK HARDENING REGISTRY ──────────────────────────────────────
    Invoke-Safe "Network Hardening" {
        Write-Status "Checking TCP/IP stack hardening registry values"
        Write-Divider "HARDENING"
        Add-MD "### 5.17 Network Stack Hardening Checks"; Add-MD ""
        $checks = @(
            @{ Key='HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'; Name='EnableICMPRedirect';           Safe=0; Desc='ICMP Redirect Disabled' }
            @{ Key='HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'; Name='DisableIPSourceRouting';       Safe=2; Desc='IP Source Routing Disabled' }
            @{ Key='HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'; Name='SynAttackProtect';             Safe=1; Desc='SYN Flood Protection' }
            @{ Key='HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'; Name='TcpMaxConnectResponseRetransmissions'; Safe=2; Desc='SYN Retransmission Limit' }
            @{ Key='HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters';Name='DisableIPSourceRouting';       Safe=2; Desc='IPv6 Source Routing Disabled' }
            @{ Key='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa';               Name='RestrictAnonymous';            Safe=1; Desc='Anon Enum Restricted' }
            @{ Key='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa';               Name='RestrictAnonymousSAM';         Safe=1; Desc='Anon SAM Enum Restricted' }
            @{ Key='HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters'; Name='NodeType';                    Safe=2; Desc='NetBIOS Node Type (P-node)' }
        )
        $rows = $checks | ForEach-Object {
            $chk = $_
            $cur = try { (Get-ItemProperty $chk.Key -EA Stop).$($chk.Name) } catch { $null }
            $ok  = $cur -eq $chk.Safe
            $disp= if ($null -eq $cur) { 'Not Set' } else { [string]$cur }
            $col = if ($ok) { [ConsoleColor]::Green } else { [ConsoleColor]::Yellow }
            Write-DataLine $chk.Desc "$disp (want: $($chk.Safe))" $col
            if (-not $ok) { Write-Finding "$($chk.Desc) — current: $disp, recommended: $($chk.Safe)" WARN }
            else          { Write-Finding "$($chk.Desc) — OK" PASS }
            @{ Check=$chk.Desc; Current=$disp; Recommended=$chk.Safe; Status=if($ok){'OK'}else{'Review'} }
        }
        Add-MDTable -Headers @('Check','Current','Recommended','Status') -Rows $rows
        Add-MD ""
    }

    # ── 5.18 WMI ADAPTER DETAIL ──────────────────────────────────────────────
    Invoke-Safe "WMI Adapter Detail" {
        Write-Status "Pulling WMI network adapter configuration (DHCP, WINS etc.)"
        Write-Divider "WMI ADAPTERS"
        Add-MD "### 5.18 WMI Network Adapter Detail (IP-Enabled)"; Add-MD ""
        $wmiAdapters = Get-CimInstance Win32_NetworkAdapterConfiguration -ErrorAction SilentlyContinue | Where-Object { $_.IPEnabled }
        $rows = $wmiAdapters | ForEach-Object {
            Write-DataLine $_.Description "$($_.IPAddress -join ', ') | DHCP:$($_.DHCPEnabled)"
            if ($_.WINSPrimaryServer) { Write-Finding "WINS configured: $($_.WINSPrimaryServer) — legacy NetBIOS name resolution active" INFO }
            @{
                Description=$_.Description; 'IP'=($_.IPAddress -join ', ')
                'Subnet'=($_.IPSubnet -join ', '); 'GW'=($_.DefaultIPGateway -join ', ')
                'DHCP'=$_.DHCPEnabled; 'DHCP Server'=$_.DHCPServer
                'WINS Pri'=$_.WINSPrimaryServer; 'MAC'=$_.MACAddress
            }
        }
        Add-MDTable -Headers @('Description','IP','Subnet','GW','DHCP','DHCP Server','WINS Pri','MAC') -Rows $rows
        Add-MD ""
    }

    # ── 5.19 NETWORK SUMMARY SCORECARD ───────────────────────────────────────
    Invoke-Safe "Network Summary" {
        Write-Status "Building network summary scorecard"
        Write-Divider "NET SUMMARY"
        $listenCount = (Get-NetTCPConnection -State Listen      -EA SilentlyContinue).Count
        $estCount    = (Get-NetTCPConnection -State Established -EA SilentlyContinue).Count
        $extCount    = (Get-NetTCPConnection -State Established -EA SilentlyContinue | Where-Object {
            $_.RemoteAddress -notmatch '^(127\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|::1)'
        }).Count
        Write-DataLine "TCP Listening Ports"      $listenCount
        Write-DataLine "Total Established"         $estCount
        Write-DataLine "External Established"      $extCount
        Add-MD "### 5.19 Network Summary"; Add-MD ""
        Add-MDTable -Headers @('Metric','Value') -Rows @(
            @{ Metric='TCP Listening Ports';     Value=$listenCount }
            @{ Metric='Established Connections'; Value=$estCount }
            @{ Metric='External Connections';    Value=$extCount }
        )
        Add-MD ""
    }

    Write-LiveStats
    Write-BoxEnd
}

# ─────────────────────────────────────────────────────────────────────────────
#  MODULE 6: SOFTWARE & PATCH INVENTORY
# ─────────────────────────────────────────────────────────────────────────────
function Invoke-SoftwareAudit {
    Write-Box "MODULE 6 — INSTALLED SOFTWARE & PATCH INVENTORY" Cyan
    Add-MD ""
    Add-MD "---"
    Add-MD "## 6. Installed Software & Patch Inventory"
    Add-MD ""

    Write-Status "Enumerating installed software (registry)"
    $regPaths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )

    $software = $regPaths | ForEach-Object {
        Get-ItemProperty $_ -ErrorAction SilentlyContinue
    } | Where-Object { $_.DisplayName } | Sort-Object DisplayName

    Add-MD "### 6.1 Installed Applications"
    Add-MD ""
    Add-MD "Total applications found: **$($software.Count)**"
    Add-MD ""
    Add-MDTable -Headers @('Name','Version','Publisher','Install Date') -Rows (
        $software | ForEach-Object { @{
            Name=$_.DisplayName
            Version=if($_.DisplayVersion){$_.DisplayVersion}else{'N/A'}
            Publisher=if($_.Publisher){$_.Publisher}else{'Unknown'}
            'Install Date'=if($_.InstallDate){$_.InstallDate}else{'Unknown'}
        }}
    )

    # Flag risky/interesting software
    $flagPatterns = @(
        'TeamViewer','AnyDesk','Ammyy','LogMeIn','RemotePC',
        'Wireshark','Nmap','NetScan','Advanced IP Scanner',
        'Process Hacker','HxD','OllyDbg','x64dbg',
        'Python','Ruby','Perl','PowerShell 7',
        '7-Zip','WinRAR','WinZip',
        'PuTTY','WinSCP','FileZilla',
        'Tor Browser','VPN','OpenVPN','Mullvad','ProtonVPN'
    )

    Add-MD "### 6.2 Flagged Software (Remote Access / Dev Tools / Privacy Tools)"
    Add-MD ""
    $flagged = $software | Where-Object { $name = $_.DisplayName; $flagPatterns | Where-Object { $name -match $_ } }
    if ($flagged) {
        Add-MDTable -Headers @('Name','Version','Publisher') -Rows (
            $flagged | ForEach-Object { @{ Name=$_.DisplayName; Version=$_.DisplayVersion; Publisher=$_.Publisher } }
        )
        foreach ($f in $flagged) {
            Write-Finding "Notable software: $($f.DisplayName) $($f.DisplayVersion) — verify authorization" WARN
        }
    } else {
        Write-Finding "No flagged software categories detected" PASS
        Add-MD "*No flagged software found.*"
    }
    Add-MD ""

    # Windows roles / features
    Write-Status "Enumerating Windows Roles and Features"
    Add-MD "### 6.3 Installed Windows Roles & Features"
    Add-MD ""
    $features = Get-WindowsFeature | Where-Object { $_.Installed } -ErrorAction SilentlyContinue
    if ($features) {
        Add-MDTable -Headers @('Name','Display Name','Feature Type') -Rows (
            $features | ForEach-Object { @{ Name=$_.Name; 'Display Name'=$_.DisplayName; 'Feature Type'=$_.FeatureType } }
        )
        # Warn on unnecessary features
        $riskyFeatures = @('Telnet-Client','TFTP-Client','SMB1Protocol','FTP-Server','Web-DAV-Publishing','Windows-Server-Backup')
        foreach ($rf in $riskyFeatures) {
            $found = $features | Where-Object { $_.Name -eq $rf }
            if ($found) {
                Write-Finding "Potentially unnecessary feature installed: $rf" WARN
            }
        }
    }
    Add-MD ""

    Write-BoxEnd
}

# ─────────────────────────────────────────────────────────────────────────────
#  MODULE 7: SERVICES, TASKS & AUTORUNS
# ─────────────────────────────────────────────────────────────────────────────
function Invoke-PersistenceAudit {
    Write-Box "MODULE 7 — SERVICES, SCHEDULED TASKS & AUTORUNS" Cyan
    Add-MD ""
    Add-MD "---"
    Add-MD "## 7. Services, Scheduled Tasks & Autoruns"
    Add-MD ""

    # Services
    Write-Status "Enumerating running services"
    Add-MD "### 7.1 Running Services"
    Add-MD ""
    $services = Get-Service | Where-Object { $_.Status -eq 'Running' } | Sort-Object Name
    Add-MDTable -Headers @('Name','Display Name','Start Type','Status','Path') -Rows (
        $services | ForEach-Object {
            $svc = $_
            $wmi = Get-CimInstance Win32_Service -Filter "Name='$($svc.Name)'" -ErrorAction SilentlyContinue
            @{
                Name=$svc.Name; 'Display Name'=$svc.DisplayName
                'Start Type'=$svc.StartType; Status=$svc.Status
                Path=if($wmi){$wmi.PathName}else{'N/A'}
            }
        }
    )

    # Services with non-standard paths
    Write-Status "Checking service executable paths"
    $svcWithPaths = Get-CimInstance Win32_Service | Where-Object { $_.PathName -and $_.State -eq 'Running' }
    $suspiciousSvcPaths = $svcWithPaths | Where-Object { 
        $p = $_.PathName.Trim('"').Split(' ')[0]
        $p -and -not ($p -match '^(C:\\Windows\\|C:\\Program Files\\|C:\\Program Files \(x86\)\\)') 
    }
    if ($suspiciousSvcPaths) {
        Add-MD "### 7.2 Services with Non-Standard Executable Paths"
        Add-MD ""
        Add-MDTable -Headers @('Name','Path','Account') -Rows (
            $suspiciousSvcPaths | ForEach-Object { @{ Name=$_.Name; Path=$_.PathName; Account=$_.StartName } }
        )
        foreach ($s in $suspiciousSvcPaths) {
            Write-Finding "Service '$($s.Name)' runs from non-standard path: $($s.PathName)" WARN
        }
    } else {
        Write-Finding "All running services use standard executable paths" PASS
    }

    # Scheduled tasks
    Write-Status "Enumerating scheduled tasks"
    Add-MD "### 7.3 Non-Microsoft Scheduled Tasks"
    Add-MD ""
    $tasks = Get-ScheduledTask | Where-Object { 
        $_.TaskPath -notmatch '\\Microsoft\\' -and $_.State -ne 'Disabled'
    }
    if ($tasks) {
        Add-MDTable -Headers @('Name','Path','State','Run As','Action') -Rows (
            $tasks | ForEach-Object {
                $action = ($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join '; '
                @{
                    Name=$_.TaskName; Path=$_.TaskPath; State=$_.State
                    'Run As'=$_.Principal.UserId; Action=$action
                }
            }
        )
        foreach ($t in $tasks) {
            if ($t.Principal.RunLevel -eq 'Highest' -or $t.Principal.UserId -match 'SYSTEM|Administrator') {
                Write-Finding "High-privilege scheduled task: '$($t.TaskName)' runs as $($t.Principal.UserId)" WARN
            }
        }
    } else {
        Write-Finding "No non-Microsoft enabled scheduled tasks found" PASS
    }

    # Registry autoruns
    Write-Status "Checking registry Run keys (autoruns)"
    Add-MD "### 7.4 Registry Autoruns (Run Keys)"
    Add-MD ""
    $runKeys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'
    )
    $autoruns = @()
    foreach ($key in $runKeys) {
        if (Test-Path $key) {
            Get-ItemProperty $key -ErrorAction SilentlyContinue | 
            Get-Member -MemberType NoteProperty | 
            Where-Object { $_.Name -notmatch '^PS' } | 
            ForEach-Object {
                $val = (Get-ItemProperty $key).$($_.Name)
                $autoruns += @{ Key=$key; Name=$_.Name; Value=$val }
            }
        }
    }

    if ($autoruns) {
        Add-MDTable -Headers @('Key','Name','Value') -Rows $autoruns
        foreach ($ar in $autoruns) {
            if ($ar.Value -match '%TEMP%|%APPDATA%|\\Temp\\|\\AppData\\|\.vbs|\.bat|\.cmd|\.ps1|powershell|wscript|cscript') {
                Write-Finding "Suspicious autorun: '$($ar.Name)' = $($ar.Value)" CRIT
            } else {
                Write-Finding "Autorun entry: '$($ar.Name)' = $($ar.Value)" INFO
            }
        }
    } else {
        Write-Finding "No autorun entries found in standard Run keys" PASS
    }

    # WMI subscriptions
    Write-Status "Checking WMI event subscriptions (common persistence mechanism)"
    Add-MD "### 7.5 WMI Event Subscriptions"
    Add-MD ""
    $wmiFilters      = Get-WMIObject -Namespace root\subscription -Class __EventFilter -ErrorAction SilentlyContinue
    $wmiConsumers    = Get-WMIObject -Namespace root\subscription -Class __EventConsumer -ErrorAction SilentlyContinue
    $wmiBindings     = Get-WMIObject -Namespace root\subscription -Class __FilterToConsumerBinding -ErrorAction SilentlyContinue

    if ($wmiFilters -or $wmiConsumers) {
        Write-Finding "WMI event subscriptions detected — POSSIBLE PERSISTENCE MECHANISM" CRIT
        Add-MD "#### WMI Filters"
        $wmiFilters | ForEach-Object { Add-MD "- **$($_.Name)**: $($_.Query)" }
        Add-MD ""
        Add-MD "#### WMI Consumers"
        $wmiConsumers | ForEach-Object { Add-MD "- **$($_.Name)**" }
        Add-MD ""
    } else {
        Write-Finding "No WMI event subscriptions found" PASS
        Add-MD "*No WMI subscriptions detected.*"
    }
    Add-MD ""

    Write-BoxEnd
}

# ─────────────────────────────────────────────────────────────────────────────
#  MODULE 8: FIREWALL & SECURITY POLICY
# ─────────────────────────────────────────────────────────────────────────────
function Invoke-FirewallAudit {
    Write-Box "MODULE 8 — WINDOWS FIREWALL & SECURITY POLICY" Cyan
    Add-MD ""
    Add-MD "---"
    Add-MD "## 8. Windows Firewall & Security Policy"
    Add-MD ""

    # Firewall profiles
    Write-Status "Checking Windows Firewall profiles"
    Add-MD "### 8.1 Firewall Profile Status"
    Add-MD ""
    $profiles = Get-NetFirewallProfile
    Add-MDTable -Headers @('Profile','Enabled','DefaultInboundAction','DefaultOutboundAction','NotifyOnListen') -Rows (
        $profiles | ForEach-Object { @{
            Profile=$_.Name
            Enabled=if($_.Enabled){'✅ Yes'}else{'❌ NO'}
            DefaultInboundAction=$_.DefaultInboundAction
            DefaultOutboundAction=$_.DefaultOutboundAction
            NotifyOnListen=$_.NotifyOnListen
        }}
    )
    $disabled = $profiles | Where-Object { -not $_.Enabled }
    foreach ($d in $disabled) {
        Write-Finding "Windows Firewall '$($d.Name)' profile is DISABLED" CRIT
    }
    $profiles | Where-Object { $_.Enabled } | ForEach-Object {
        Write-Finding "Firewall '$($_.Name)' profile is enabled (Inbound: $($_.DefaultInboundAction))" PASS
    }

    # Inbound rules — enabled, allow
    Write-Status "Enumerating enabled inbound ALLOW firewall rules"
    Add-MD "### 8.2 Enabled Inbound ALLOW Rules"
    Add-MD ""
    $inboundAllows = Get-NetFirewallRule | Where-Object { 
        $_.Enabled -eq 'True' -and 
        $_.Direction -eq 'Inbound' -and 
        $_.Action -eq 'Allow' 
    }
    $inboundRows = $inboundAllows | ForEach-Object {
        $rule = $_
        $portFilter = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $rule -ErrorAction SilentlyContinue
        @{
            Name=$rule.DisplayName
            Profile=($rule.Profile -join ',')
            Protocol=if($portFilter){$portFilter.Protocol}else{'Any'}
            Port=if($portFilter){$portFilter.LocalPort}else{'Any'}
            RemoteAddress=(Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $rule -ErrorAction SilentlyContinue).RemoteAddress
        }
    }
    Add-MDTable -Headers @('Name','Profile','Protocol','Port','RemoteAddress') -Rows $inboundRows

    $broadRules = $inboundAllows | Where-Object {
        $af = Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $_ -ErrorAction SilentlyContinue
        $af.RemoteAddress -eq 'Any'
    }
    foreach ($br in $broadRules) {
        Write-Finding "Broad inbound ALLOW rule (Any source): '$($br.DisplayName)'" WARN
    }

    # RDP check
    Write-Status "Checking RDP configuration"
    Add-MD "### 8.3 Remote Desktop (RDP) Configuration"
    Add-MD ""
    $rdpEnabled = (Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -ErrorAction SilentlyContinue).fDenyTSConnections
    if ($rdpEnabled -eq 0) {
        Write-Finding "RDP is ENABLED — verify access is restricted to authorized IPs" WARN
        Add-MD "- **RDP Status:** ⚠️ Enabled"
    } else {
        Write-Finding "RDP is disabled" PASS
        Add-MD "- **RDP Status:** ✅ Disabled"
    }

    $nla = (Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'UserAuthentication' -ErrorAction SilentlyContinue).UserAuthentication
    if ($nla -eq 1) {
        Write-Finding "Network Level Authentication (NLA) for RDP is ENABLED" PASS
        Add-MD "- **NLA:** ✅ Enabled"
    } else {
        Write-Finding "NLA for RDP is DISABLED — credentials exposed pre-auth" CRIT
        Add-MD "- **NLA:** ❌ Disabled"
    }
    Add-MD ""

    # SMB config
    Write-Status "Checking SMB security configuration"
    Add-MD "### 8.4 SMB Security Configuration"
    Add-MD ""
    $smb1 = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue
    if ($smb1 -and $smb1.State -eq 'Enabled') {
        Write-Finding "SMBv1 is ENABLED — EternalBlue / WannaCry attack surface" CRIT
        Add-MD "- **SMBv1:** ❌ Enabled (CRITICAL — disable immediately)"
    } else {
        Write-Finding "SMBv1 is disabled" PASS
        Add-MD "- **SMBv1:** ✅ Disabled"
    }

    $smbConf = Get-SmbServerConfiguration -ErrorAction SilentlyContinue
    if ($smbConf) {
        Add-MDTable -Headers @('Setting','Value','Status') -Rows @(
            @{ Setting='SMBv1 Enabled';          Value=$smbConf.EnableSMB1Protocol; Status=if(-not $smbConf.EnableSMB1Protocol){'✅'}else{'❌'} }
            @{ Setting='SMBv2 Enabled';          Value=$smbConf.EnableSMB2Protocol; Status=if($smbConf.EnableSMB2Protocol){'✅'}else{'⚠️'} }
            @{ Setting='Signing Required';        Value=$smbConf.RequireSecuritySignature; Status=if($smbConf.RequireSecuritySignature){'✅'}else{'⚠️'} }
            @{ Setting='Encrypt Data';            Value=$smbConf.EncryptData; Status=if($smbConf.EncryptData){'✅'}else{'⚠️'} }
            @{ Setting='Null Session Pipes';      Value=($smbConf.NullSessionPipes -join ', '); Status=if(-not $smbConf.NullSessionPipes){'✅'}else{'⚠️'} }
        )
        if (-not $smbConf.RequireSecuritySignature) { Write-Finding "SMB signing is not required — relay attacks possible" WARN }
    }

    Write-BoxEnd
}

# ─────────────────────────────────────────────────────────────────────────────
#  MODULE 9: EVENT LOG & AUDIT POLICY
# ─────────────────────────────────────────────────────────────────────────────
function Invoke-EventLogAudit {
    Write-Box "MODULE 9 — EVENT LOG & AUDIT POLICY REVIEW" Cyan
    Add-MD ""
    Add-MD "---"
    Add-MD "## 9. Event Log & Audit Policy Review"
    Add-MD ""

    # Audit policy
    Write-Status "Dumping audit policy (auditpol)"
    Add-MD "### 9.1 Audit Policy Configuration"
    Add-MD ""
    $auditPol = auditpol /get /category:* 2>&1
    Add-MD "``````"
    $auditPol | ForEach-Object { Add-MD $_ }
    Add-MD "``````"
    Add-MD ""

    # Key audit categories check
    $criticalCategories = @(
        'Logon', 'Account Logon', 'Account Management', 'Policy Change',
        'Privilege Use', 'Object Access', 'System'
    )
    foreach ($cat in $criticalCategories) {
        $line = $auditPol | Where-Object { $_ -match $cat }
        if ($line -match 'No Auditing') {
            Write-Finding "Audit category '$cat' has 'No Auditing' — blind spot in event log" CRIT
        } elseif ($line) {
            Write-Finding "Audit category '$cat' is configured" PASS
        }
    }

    # Event log sizes
    Write-Status "Checking event log sizes and retention"
    Add-MD "### 9.2 Event Log Configuration"
    Add-MD ""
    $logs = @('Security','System','Application')
    $logRows = $logs | ForEach-Object {
        $log = Get-WinEvent -ListLog $_ -ErrorAction SilentlyContinue
        if ($log) {
            @{
                Name=$log.LogName
                'Max Size (MB)'=[math]::Round($log.MaximumSizeInBytes/1MB, 0)
                'Current Size (MB)'=[math]::Round($log.FileSize/1MB, 2)
                'Record Count'=$log.RecordCount
                'Retention'=$log.LogMode
                'Is Enabled'=if($log.IsEnabled){'✅'}else{'❌'}
            }
        }
    }
    Add-MDTable -Headers @('Name','Max Size (MB)','Current Size (MB)','Record Count','Retention','Is Enabled') -Rows $logRows

    foreach ($lr in $logRows) {
        if ([int]($lr['Max Size (MB)']) -lt 128) {
            Write-Finding "Event log '$($lr.Name)' max size is only $($lr['Max Size (MB)']) MB — increase for forensic retention" WARN
        }
    }

    # Recent security events — failed logons
    Write-Status "Pulling recent failed logon events (4625)"
    Add-MD "### 9.3 Recent Failed Logon Events (Last 24h, Event ID 4625)"
    Add-MD ""
    $failedLogons = Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4625; StartTime=(Get-Date).AddHours(-24) } -ErrorAction SilentlyContinue | Select-Object -First 50
    if ($failedLogons) {
        Add-MDTable -Headers @('Time','Account','Failure Reason','Source IP','Logon Type') -Rows (
            $failedLogons | ForEach-Object {
                $evt = [xml]$_.ToXml()
                $data = $evt.Event.EventData.Data
                $account = ($data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
                $reason  = ($data | Where-Object { $_.Name -eq 'FailureReason' }).'#text'
                $ip      = ($data | Where-Object { $_.Name -eq 'IpAddress' }).'#text'
                $logonT  = ($data | Where-Object { $_.Name -eq 'LogonType' }).'#text'
                @{ Time=$_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'); Account=$account; 'Failure Reason'=$reason; 'Source IP'=$ip; 'Logon Type'=$logonT }
            }
        )
        Write-Finding "$($failedLogons.Count) failed logons in last 24 hours — review for brute-force activity" WARN
    } else {
        Write-Finding "No failed logon events in last 24 hours" PASS
        Add-MD "*No failed logon events in last 24 hours.*"
    }
    Add-MD ""

    # Recent account lockouts
    Write-Status "Checking for account lockouts (4740)"
    Add-MD "### 9.4 Account Lockout Events (Last 24h, Event ID 4740)"
    Add-MD ""
    $lockouts = Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4740; StartTime=(Get-Date).AddHours(-24) } -ErrorAction SilentlyContinue | Select-Object -First 20
    if ($lockouts) {
        Add-MDTable -Headers @('Time','Locked Account','Caller Computer') -Rows (
            $lockouts | ForEach-Object {
                $evt  = [xml]$_.ToXml()
                $data = $evt.Event.EventData.Data
                $acct = ($data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
                $cmp  = ($data | Where-Object { $_.Name -eq 'TargetDomainName' }).'#text'
                @{ Time=$_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'); 'Locked Account'=$acct; 'Caller Computer'=$cmp }
            }
        )
        Write-Finding "$($lockouts.Count) account lockout events in last 24 hours" WARN
    } else {
        Write-Finding "No account lockout events in last 24 hours" PASS
        Add-MD "*No lockout events.*"
    }
    Add-MD ""

    # Cleared event logs
    Write-Status "Checking for log clearing events (1102, 104)"
    $logCleared = Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=1102 } -ErrorAction SilentlyContinue | Select-Object -First 10
    $logCleared += Get-WinEvent -FilterHashtable @{ LogName='System'; Id=104 } -ErrorAction SilentlyContinue | Select-Object -First 10
    if ($logCleared) {
        Add-MD "### 9.5 Event Log Clearing Events Detected ⚠️"
        Add-MD ""
        Add-MDTable -Headers @('Time','Log','Message') -Rows (
            $logCleared | ForEach-Object { @{ Time=$_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'); Log=$_.LogName; Message=$_.Message.Substring(0,[Math]::Min(200,$_.Message.Length)) } }
        )
        foreach ($lc in $logCleared) {
            Write-Finding "EVENT LOG CLEARED at $($lc.TimeCreated) — potential evidence tampering" CRIT
        }
    } else {
        Write-Finding "No event log clearing events detected" PASS
    }
    Add-MD ""

    Write-BoxEnd
}

# ─────────────────────────────────────────────────────────────────────────────
#  MODULE 10: IOC DETECTION & THREAT HUNT
# ─────────────────────────────────────────────────────────────────────────────
function Invoke-IOCHunt {
    Write-Box "MODULE 10 — IOC DETECTION & THREAT HUNT" Magenta
    Add-MD ""
    Add-MD "---"
    Add-MD "## 10. IOC Detection & Threat Hunt"
    Add-MD ""

    # Suspicious processes
    Write-Status "Hunting suspicious process names"
    Add-MD "### 10.1 Running Process Inventory & Suspicious Process Hunt"
    Add-MD ""
    $allProcs = Get-Process | Sort-Object Name
    Add-MDTable -Headers @('PID','Name','CPU (s)','Memory (MB)','Path') -Rows (
        $allProcs | ForEach-Object {
            @{
                PID=$_.Id; Name=$_.Name
                'CPU (s)'=[math]::Round($_.CPU, 2)
                'Memory (MB)'=[math]::Round($_.WorkingSet/1MB, 1)
                Path=if($_.Path){$_.Path}else{'(system/protected)'}
            }
        }
    )

    $suspiciousProcs = @(
        'mimikatz','mimi','wce','fgdump','pwdump',
        'psexec','psexesvc','remcos','njrat','asyncrat',
        'cobaltstrike','beacon','empire','metasploit','meterpreter',
        'nc','ncat','netcat','nbtscan','masscan','zmap',
        'procdump','dumpert','nanodump',
        'mshta','wscript','cscript','regsvr32','rundll32',
        'certutil','bitsadmin','schtasks','at\.exe'
    )

    $foundSuspicious = $allProcs | Where-Object {
        $n = $_.Name.ToLower()
        $suspiciousProcs | Where-Object { $n -match $_ }
    }

    if ($foundSuspicious) {
        foreach ($sp in $foundSuspicious) {
            Write-Finding "SUSPICIOUS PROCESS: $($sp.Name) (PID $($sp.Id)) — Path: $($sp.Path)" IOC
        }
    } else {
        Write-Finding "No known malicious process names detected" PASS
    }

    # Processes running from unusual locations
    Write-Status "Checking process executable paths for anomalies"
    Add-MD "### 10.2 Processes from Unusual Paths"
    Add-MD ""
    $unusualProcs = $allProcs | Where-Object {
        $p = $_.Path
        $p -and (
            $p -match '\\Temp\\|\\AppData\\|\\ProgramData\\|\\Downloads\\|\\Desktop\\' -or
            ($p -notmatch '^C:\\Windows\\' -and $p -notmatch '^C:\\Program Files' -and $p -notmatch '^C:\\Program Files \(x86\)' -and $p -notmatch 'System32')
        )
    }
    if ($unusualProcs) {
        Add-MDTable -Headers @('PID','Name','Path') -Rows (
            $unusualProcs | ForEach-Object { @{ PID=$_.Id; Name=$_.Name; Path=$_.Path } }
        )
        foreach ($up in $unusualProcs) {
            Write-Finding "Process '$($up.Name)' (PID $($up.Id)) executing from unusual path: $($up.Path)" IOC
        }
    } else {
        Write-Finding "No processes found executing from unusual filesystem paths" PASS
        Add-MD "*No unusual path processes.*"
    }
    Add-MD ""

    # LOLBins usage check (Living Off the Land Binaries)
    Write-Status "Checking for LOLBin activity in recent events"
    Add-MD "### 10.3 Living Off the Land Binary (LOLBin) Activity"
    Add-MD ""
    $lolbins = @('mshta.exe','wscript.exe','cscript.exe','certutil.exe','bitsadmin.exe',
                  'regsvr32.exe','msiexec.exe','installutil.exe','rundll32.exe',
                  'forfiles.exe','pcalua.exe','regasm.exe','regsvcs.exe')

    $lolbinEvents = Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4688; StartTime=(Get-Date).AddDays(-7) } -ErrorAction SilentlyContinue | Where-Object {
        $msg = $_.Message
        $lolbins | Where-Object { $msg -match $_ }
    } | Select-Object -First 30

    if ($lolbinEvents) {
        Add-MDTable -Headers @('Time','Process') -Rows (
            $lolbinEvents | ForEach-Object {
                @{ Time=$_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'); Process=$_.Message.Substring(0,[Math]::Min(300,$_.Message.Length)) }
            }
        )
        foreach ($lb in $lolbinEvents) {
            Write-Finding "LOLBin execution detected in event log — review: $($lb.TimeCreated)" IOC
        }
    } else {
        Write-Finding "No LOLBin execution events found in security log (7 days)" PASS
        Add-MD "*No LOLBin events found (note: process auditing may be required for full coverage).*"
    }
    Add-MD ""

    # Temp / staging directories
    Write-Status "Scanning temp/staging directories for executables"
    Add-MD "### 10.4 Executables in Temp/Download Directories"
    Add-MD ""
    $scanPaths = @(
        "$env:TEMP", "$env:WINDIR\Temp", "$env:SYSTEMROOT\System32\Temp",
        "$env:USERPROFILE\Downloads", "$env:PUBLIC\Downloads"
    )
    $suspiciousFiles = @()
    foreach ($sp in $scanPaths) {
        if (Test-Path $sp) {
            $files = Get-ChildItem -Path $sp -Include '*.exe','*.dll','*.bat','*.cmd','*.ps1','*.vbs','*.js','*.hta' -Recurse -ErrorAction SilentlyContinue | Select-Object -First 50
            $suspiciousFiles += $files
        }
    }

    if ($suspiciousFiles) {
        Add-MDTable -Headers @('Path','Size (KB)','Created','Modified') -Rows (
            $suspiciousFiles | ForEach-Object { @{
                Path=$_.FullName
                'Size (KB)'=[math]::Round($_.Length/1KB, 1)
                Created=$_.CreationTime.ToString('yyyy-MM-dd HH:mm')
                Modified=$_.LastWriteTime.ToString('yyyy-MM-dd HH:mm')
            }}
        )
        foreach ($sf in $suspiciousFiles) {
            Write-Finding "Executable in temp/staging: $($sf.FullName)" IOC
        }
    } else {
        Write-Finding "No executables found in temp/staging directories" PASS
        Add-MD "*No suspicious executables in temp paths.*"
    }
    Add-MD ""

    # PowerShell transcript / logging check
    Write-Status "Checking PowerShell logging configuration"
    Add-MD "### 10.5 PowerShell Security Logging"
    Add-MD ""
    $psLogging    = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -ErrorAction SilentlyContinue
    $psTranscript = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' -ErrorAction SilentlyContinue
    $psModuleLog  = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' -ErrorAction SilentlyContinue

    Add-MDTable -Headers @('Setting','Value','Status') -Rows @(
        @{ Setting='Script Block Logging'; Value=if($psLogging.EnableScriptBlockLogging -eq 1){'Enabled'}else{'Disabled'}; Status=if($psLogging.EnableScriptBlockLogging -eq 1){'✅'}else{'⚠️'} }
        @{ Setting='Transcription';        Value=if($psTranscript.EnableTranscripting -eq 1){"Enabled → $($psTranscript.OutputDirectory)"}else{'Disabled'}; Status=if($psTranscript.EnableTranscripting -eq 1){'✅'}else{'⚠️'} }
        @{ Setting='Module Logging';       Value=if($psModuleLog.EnableModuleLogging -eq 1){'Enabled'}else{'Disabled'}; Status=if($psModuleLog.EnableModuleLogging -eq 1){'✅'}else{'⚠️'} }
    )

    if ($psLogging.EnableScriptBlockLogging -ne 1) { Write-Finding "PowerShell Script Block Logging is DISABLED — PS activity may be invisible" CRIT }
    if ($psTranscript.EnableTranscripting -ne 1)   { Write-Finding "PowerShell Transcription logging is DISABLED" WARN }
    if ($psModuleLog.EnableModuleLogging -ne 1)    { Write-Finding "PowerShell Module Logging is DISABLED" WARN }

    Add-MD ""

    # AMSI bypass check
    Write-Status "Checking for AMSI bypass indicators in registry"
    Add-MD "### 10.6 AMSI Bypass Indicators"
    Add-MD ""
    $amsiPath = 'HKLM:\SOFTWARE\Microsoft\Windows Script\Settings'
    $amsi = Get-ItemProperty $amsiPath -ErrorAction SilentlyContinue
    if ($amsi -and $amsi.AmsiEnable -eq 0) {
        Write-Finding "AMSI appears to be DISABLED via registry — possible bypass in place" IOC
        Add-MD "- ❌ **AMSI Disabled via registry**"
    } else {
        Write-Finding "AMSI registry indicator appears normal" PASS
        Add-MD "- ✅ AMSI registry indicator normal"
    }
    Add-MD ""

    # Defender / AV status
    Write-Status "Checking Windows Defender status"
    Add-MD "### 10.7 Windows Defender / AV Status"
    Add-MD ""
    $mpStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
    if ($mpStatus) {
        Add-MDTable -Headers @('Setting','Value','Status') -Rows @(
            @{ Setting='Antivirus Enabled';        Value=$mpStatus.AntivirusEnabled;       Status=if($mpStatus.AntivirusEnabled){'✅'}else{'❌'} }
            @{ Setting='Real-time Protection';     Value=$mpStatus.RealTimeProtectionEnabled; Status=if($mpStatus.RealTimeProtectionEnabled){'✅'}else{'❌'} }
            @{ Setting='Antispyware Enabled';      Value=$mpStatus.AntispywareEnabled;     Status=if($mpStatus.AntispywareEnabled){'✅'}else{'❌'} }
            @{ Setting='Behavior Monitor Enabled'; Value=$mpStatus.BehaviorMonitorEnabled;  Status=if($mpStatus.BehaviorMonitorEnabled){'✅'}else{'❌'} }
            @{ Setting='IOAV Protection Enabled';  Value=$mpStatus.IoavProtectionEnabled;  Status=if($mpStatus.IoavProtectionEnabled){'✅'}else{'❌'} }
            @{ Setting='Signature Version';        Value=$mpStatus.AntivirusSignatureVersion; Status='ℹ️' }
            @{ Setting='Last Signature Update';    Value=$mpStatus.AntivirusSignatureLastUpdated; Status=if(((Get-Date)-$mpStatus.AntivirusSignatureLastUpdated).TotalDays -gt 7){'⚠️ Stale'}else{'✅'} }
            @{ Setting='Quick Scan Age (Days)';    Value=$mpStatus.QuickScanAge; Status=if($mpStatus.QuickScanAge -gt 7){'⚠️'}else{'✅'} }
        )
        if (-not $mpStatus.AntivirusEnabled)          { Write-Finding "Windows Defender Antivirus is DISABLED" CRIT }
        if (-not $mpStatus.RealTimeProtectionEnabled) { Write-Finding "Windows Defender Real-time Protection is DISABLED" CRIT }
        $sigAge = ((Get-Date) - $mpStatus.AntivirusSignatureLastUpdated).TotalDays
        if ($sigAge -gt 7) { Write-Finding "Defender signatures are $([math]::Round($sigAge,0)) days old — update immediately" WARN }
    } else {
        Write-Finding "Windows Defender status unavailable — third-party AV or management policy may apply" WARN
        Add-MD "> ⚠️ Windows Defender status unavailable. Verify third-party AV is active."
    }
    Add-MD ""

    # Credential Guard / Device Guard
    Write-Status "Checking Credential Guard and Device Guard"
    Add-MD "### 10.8 Credential Guard & Device Guard"
    Add-MD ""
    $cg = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue
    if ($cg) {
        Add-MDTable -Headers @('Feature','Status') -Rows @(
            @{ Feature='Virtual Based Security'; Status=switch($cg.VirtualizationBasedSecurityStatus){1{'Enabled (not running)'} 2{'✅ Running'} default{'❌ Not enabled'}} }
            @{ Feature='Credential Guard';       Status=switch($cg.SecurityServicesRunning -contains 1){$true{'✅ Running'} $false{'❌ Not running'}} }
            @{ Feature='HVCI';                   Status=switch($cg.SecurityServicesRunning -contains 2){$true{'✅ Running'} $false{'❌ Not running'}} }
        )
        if ($cg.VirtualizationBasedSecurityStatus -ne 2) { Write-Finding "Virtualization Based Security (VBS) is not running — Credential Guard inactive" WARN }
    } else {
        Write-Finding "Device Guard CIM class unavailable — VBS/Credential Guard status unknown" WARN
        Add-MD "> ⚠️ Device Guard WMI class unavailable on this system."
    }
    Add-MD ""

    Write-BoxEnd
}

# ─────────────────────────────────────────────────────────────────────────────
#  REPORT GENERATION
# ─────────────────────────────────────────────────────────────────────────────
function New-AuditReport {
    $hostname  = $env:COMPUTERNAME
    $scanTime  = $Script:START_TIME.ToString("yyyy-MM-dd HH:mm:ss")
    $elapsed   = [math]::Round(((Get-Date) - $Script:START_TIME).TotalSeconds, 0)

    $header = @"
# HPS Windows Server Security Audit Report

---

> **Hidden Protocol Systems**
> *Signal over noise.*
>
> **Author:** Jamie Eastridge — CISO / Principal
> **Organization:** Hidden Protocol Systems (Hidden Protocol LLC)
> **Contact:** jamie@hiddenprotocol.com
> **Tool Version:** $($Script:VERSION) (Build: $($Script:BUILD_DATE))

---

## Audit Summary

| Field | Value |
| --- | --- |
| **Hostname** | $hostname |
| **Scan Initiated** | $scanTime |
| **Scan Duration** | ${elapsed} seconds |
| **Modules Run** | $($Script:SELECTED_MODS -join ', ') |
| **Server Role(s)** | $($Script:SERVER_ROLES -join ', ') |
| **Total Findings** | $($Script:FINDINGS.Count) |
| **PASS** | ✅ $($Script:CNT_PASS) |
| **WARN** | ⚠️ $($Script:CNT_WARN) |
| **CRITICAL** | ❌ $($Script:CNT_CRIT) |
| **IOC / Threat** | ⚡ $($Script:CNT_IOC) |
| **Errors (skipped checks)** | ⚫ $($Script:CNT_ERR) |

---

## CRITICAL & IOC Findings Summary

"@

    $iocSection = ""
    if ($Script:IOC_HITS.Count -gt 0) {
        $iocSection += "The following findings require **immediate action**:`n`n"
        foreach ($hit in $Script:IOC_HITS) {
            $iocSection += "- $hit`n"
        }
    } else {
        $iocSection = "> ✅ No critical IOC findings detected during this scan."
    }

    $footer = @"

---

## Disclaimer

This report was generated by the Hidden Protocol Systems Windows Server Security Audit Framework.
All findings should be validated by a qualified security professional before remediation actions are taken.
This report is confidential and intended for authorized personnel only.

**Generated by:** HPS Windows Security Audit Framework v$($Script:VERSION)
**Author:** Jamie Eastridge // Hidden Protocol Systems
**Website:** hiddenprotocol.com

---
*End of Report*
"@

    $iocSection = if ($Script:IOC_HITS.Count -gt 0) {
        "The following findings require **immediate action**:`n`n" + ($Script:IOC_HITS | ForEach-Object { "- $_" } | Out-String)
    } else { "> ✅ No critical or IOC findings during this scan." }

    $errSection = ""
    if ($Script:ERRORS_LOG.Count -gt 0) {
        $errSection  = "`n`n---`n`n## Script Errors (checks that were skipped)`n`n"
        $errSection += "These checks failed and were skipped — the audit continued.`n`n"
        $errSection += ($Script:ERRORS_LOG | ForEach-Object { "- $_" } | Out-String)
    }

    $fullReport = $header + "`n" + $iocSection + "`n`n---`n`n" + ($Script:FINDINGS -join "`n") + $errSection + "`n`n" + $footer

    try {
        $dir = Split-Path $Script:REPORT_PATH -Parent
        if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        $fullReport | Out-File -FilePath $Script:REPORT_PATH -Encoding UTF8 -Force
        Write-Finding "Report written: $($Script:REPORT_PATH)" PASS
    } catch {
        # Fallback — write to TEMP if Desktop write fails
        $fallback = "$env:TEMP\HPS-AUDIT-FALLBACK-$(Get-Date -Format 'yyyyMMddHHmmss').md"
        $fullReport | Out-File -FilePath $fallback -Encoding UTF8 -Force
        Write-Finding "Could not write to target path — report saved to fallback: $fallback" WARN
        $Script:REPORT_PATH = $fallback
    }
}


# ─────────────────────────────────────────────────────────────────────────────
#  ROLE MODULE: DOMAIN CONTROLLER / ACTIVE DIRECTORY
# ─────────────────────────────────────────────────────────────────────────────
function Invoke-RoleAudit-DC {
    Write-Box "ROLE AUDIT — DOMAIN CONTROLLER" Magenta
    Add-MD ""
    Add-MD "---"
    Add-MD "## R1. Domain Controller — Role-Specific Audit"
    Add-MD ""

    # FSMO roles
    Write-Status "Checking FSMO role holders"
    Add-MD "### R1.1 FSMO Role Holders"
    Add-MD ""
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        $domain  = Get-ADDomain
        $forest  = Get-ADForest
        Add-MDTable -Headers @('FSMO Role','Holder') -Rows @(
            @{ 'FSMO Role'='PDC Emulator';          Holder=$domain.PDCEmulator }
            @{ 'FSMO Role'='RID Master';             Holder=$domain.RIDMaster }
            @{ 'FSMO Role'='Infrastructure Master';  Holder=$domain.InfrastructureMaster }
            @{ 'FSMO Role'='Schema Master';          Holder=$forest.SchemaMaster }
            @{ 'FSMO Role'='Domain Naming Master';   Holder=$forest.DomainNamingMaster }
        )
        # Warn if all FSMO on one DC
        $fsmoHolders = @($domain.PDCEmulator,$domain.RIDMaster,$domain.InfrastructureMaster,$forest.SchemaMaster,$forest.DomainNamingMaster) | Sort-Object -Unique
        if ($fsmoHolders.Count -eq 1) {
            Write-Finding "All 5 FSMO roles held by a single DC ($($fsmoHolders[0])) — single point of failure" WARN
        } else {
            Write-Finding "FSMO roles distributed across $($fsmoHolders.Count) DC(s)" PASS
        }
    } catch {
        Write-Finding "AD module unavailable — skipping FSMO check" WARN
        Add-MD "> ⚠️ AD module not available on this host."
    }

    # Replication health
    Write-Status "Checking AD replication status (repadmin)"
    Add-MD "### R1.2 AD Replication Status"
    Add-MD ""
    $repl = repadmin /replsummary 2>&1
    Add-MD "``````"
    $repl | ForEach-Object { Add-MD $_ }
    Add-MD "``````"
    Add-MD ""
    $replErrors = $repl | Where-Object { $_ -match 'fail|error|unable' }
    if ($replErrors) {
        foreach ($re in $replErrors) { Write-Finding "Replication issue detected: $re" CRIT }
    } else {
        Write-Finding "No obvious replication failures detected in repadmin output" PASS
    }

    # Replication failures detail
    $replFail = repadmin /showrepl * /errorsonly 2>&1
    if ($replFail -match 'error|fail') {
        Add-MD "### R1.3 Replication Errors Detail"
        Add-MD ""
        Add-MD "``````"
        $replFail | ForEach-Object { Add-MD $_ }
        Add-MD "``````"
        Add-MD ""
        Write-Finding "Replication errors found — review immediately" CRIT
    }

    # Sysvol / Netlogon share check
    Write-Status "Verifying SYSVOL and NETLOGON shares"
    Add-MD "### R1.4 SYSVOL & NETLOGON Share Availability"
    Add-MD ""
    $sysvolShare   = Get-SmbShare -Name 'SYSVOL'   -ErrorAction SilentlyContinue
    $netlogonShare = Get-SmbShare -Name 'NETLOGON' -ErrorAction SilentlyContinue
    if ($sysvolShare)   { Write-Finding "SYSVOL share is present and accessible"   PASS; Add-MD "- **SYSVOL:** ✅ Present — Path: $($sysvolShare.Path)" }
    else                { Write-Finding "SYSVOL share NOT FOUND — DC may be degraded" CRIT; Add-MD "- **SYSVOL:** ❌ Not found" }
    if ($netlogonShare) { Write-Finding "NETLOGON share is present and accessible" PASS; Add-MD "- **NETLOGON:** ✅ Present — Path: $($netlogonShare.Path)" }
    else                { Write-Finding "NETLOGON share NOT FOUND — authentication issues likely" CRIT; Add-MD "- **NETLOGON:** ❌ Not found" }
    Add-MD ""

    # DFSR / FRS status
    Write-Status "Checking DFSR / FRS service state"
    Add-MD "### R1.5 SYSVOL Replication Service"
    Add-MD ""
    $dfsr = Get-Service 'DFSR' -ErrorAction SilentlyContinue
    $ntfrs = Get-Service 'NtFrs' -ErrorAction SilentlyContinue
    if ($dfsr) {
        if ($dfsr.Status -eq 'Running') { Write-Finding "DFSR service is Running (modern SYSVOL replication)" PASS; Add-MD "- **DFSR:** ✅ Running" }
        else { Write-Finding "DFSR service is $($dfsr.Status) — SYSVOL replication may be broken" CRIT; Add-MD "- **DFSR:** ❌ $($dfsr.Status)" }
    }
    if ($ntfrs -and $ntfrs.Status -eq 'Running') {
        Write-Finding "Legacy FRS (NtFrs) service is running — SYSVOL migration to DFSR recommended" WARN
        Add-MD "- **FRS (Legacy):** ⚠️ Running — migrate to DFSR"
    }
    Add-MD ""

    # DNS service
    Write-Status "Checking DNS Server service"
    $dns = Get-Service 'DNS' -ErrorAction SilentlyContinue
    if ($dns -and $dns.Status -eq 'Running') {
        Write-Finding "DNS Server service is Running" PASS
        Add-MD "- **DNS Server:** ✅ Running"
    } elseif ($dns) {
        Write-Finding "DNS Server service is $($dns.Status) — check if DNS is on a separate server" WARN
        Add-MD "- **DNS Server:** ⚠️ $($dns.Status)"
    }

    # Kerberos ticket policy
    Write-Status "Checking Kerberos ticket policy"
    Add-MD "### R1.6 Kerberos Ticket Policy"
    Add-MD ""
    $kpol = net accounts /domain 2>&1
    Add-MD "``````"
    $kpol | ForEach-Object { Add-MD $_ }
    Add-MD "``````"
    Add-MD ""

    # Domain tombstone lifetime
    Write-Status "Checking tombstone lifetime"
    try {
        $configNC = (Get-ADRootDSE).configurationNamingContext
        $tombstone = (Get-ADObject "CN=Directory Service,CN=Windows NT,CN=Services,$configNC" -Properties tombstoneLifetime).tombstoneLifetime
        if ($tombstone -lt 180) {
            Write-Finding "Tombstone lifetime is $tombstone days (recommended ≥ 180)" WARN
            Add-MD "- **Tombstone Lifetime:** ⚠️ ${tombstone} days"
        } else {
            Write-Finding "Tombstone lifetime: $tombstone days" PASS
            Add-MD "- **Tombstone Lifetime:** ✅ ${tombstone} days"
        }
    } catch {
        Add-MD "- **Tombstone Lifetime:** ⚠️ Could not retrieve"
    }
    Add-MD ""

    Write-BoxEnd
}

# ─────────────────────────────────────────────────────────────────────────────
#  ROLE MODULE: CITRIX VIRTUAL APPS & DESKTOPS
# ─────────────────────────────────────────────────────────────────────────────
function Invoke-RoleAudit-Citrix {
    Write-Box "ROLE AUDIT — CITRIX VIRTUAL APPS & DESKTOPS" Magenta
    Add-MD ""
    Add-MD "---"
    Add-MD "## R2. Citrix — Role-Specific Audit"
    Add-MD ""

    # Citrix services
    Write-Status "Enumerating Citrix services"
    Add-MD "### R2.1 Citrix Service Health"
    Add-MD ""
    $citrixServices = Get-Service | Where-Object { $_.Name -match '^Citrix|^Brok|^Xte|^picaSvc|^IMAService|^cdf' } | Sort-Object Name
    if ($citrixServices) {
        Add-MDTable -Headers @('Service Name','Display Name','Status','Start Type') -Rows (
            $citrixServices | ForEach-Object { @{ 'Service Name'=$_.Name; 'Display Name'=$_.DisplayName; Status=if($_.Status -eq 'Running'){'✅ Running'}else{"❌ $($_.Status)"}; 'Start Type'=$_.StartType } }
        )
        $stoppedCitrix = $citrixServices | Where-Object { $_.Status -ne 'Running' -and $_.StartType -ne 'Disabled' }
        foreach ($sc in $stoppedCitrix) {
            Write-Finding "Citrix service '$($sc.DisplayName)' is not running (StartType: $($sc.StartType))" CRIT
        }
    } else {
        Write-Finding "No Citrix services detected — verify role assignment is correct" WARN
        Add-MD "> ⚠️ No Citrix services found. Confirm this is a CVAD component."
    }
    Add-MD ""

    # ICA/HDX listener ports
    Write-Status "Checking ICA listener port (2598/1494)"
    Add-MD "### R2.2 ICA / HDX Port Listener"
    Add-MD ""
    $icaPort  = Get-NetTCPConnection -LocalPort 1494 -State Listen -ErrorAction SilentlyContinue
    $cgpPort  = Get-NetTCPConnection -LocalPort 2598 -State Listen -ErrorAction SilentlyContinue
    $ssltcp   = Get-NetTCPConnection -LocalPort 443  -State Listen -ErrorAction SilentlyContinue
    if ($icaPort)  { Write-Finding "ICA listener active on port 1494" PASS;  Add-MD "- **ICA (1494):** ✅ Listening" }
    else           { Write-Finding "ICA port 1494 not listening — sessions may be broken" WARN; Add-MD "- **ICA (1494):** ⚠️ Not detected" }
    if ($cgpPort)  { Write-Finding "CGP/Session Reliability listener active on port 2598" PASS; Add-MD "- **CGP (2598):** ✅ Listening" }
    else           { Write-Finding "CGP port 2598 not listening — Session Reliability may be off" WARN; Add-MD "- **CGP (2598):** ⚠️ Not detected" }
    if ($ssltcp)   { Add-MD "- **SSL/TLS (443):** ✅ Listening (HDX over HTTPS / Secure ICA)" }
    Add-MD ""

    # Citrix session audit
    Write-Status "Checking active Citrix/RDS sessions"
    Add-MD "### R2.3 Active Session Inventory"
    Add-MD ""
    $sessions = query session 2>&1
    Add-MD "``````"
    $sessions | ForEach-Object { Add-MD $_ }
    Add-MD "``````"
    Add-MD ""

    # Session limit policy check
    Write-Status "Checking session time limit policies"
    Add-MD "### R2.4 Session Time Limit Policy (Registry)"
    Add-MD ""
    $sessionLimits = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -ErrorAction SilentlyContinue
    if ($sessionLimits) {
        Add-MDTable -Headers @('Policy','Value (ms)') -Rows @(
            @{ Policy='Max Idle Time';         'Value (ms)'=if($sessionLimits.MaxIdleTime){$sessionLimits.MaxIdleTime}else{'Not Set'} }
            @{ Policy='Max Disconnection Time';'Value (ms)'=if($sessionLimits.MaxDisconnectionTime){$sessionLimits.MaxDisconnectionTime}else{'Not Set'} }
            @{ Policy='Max Connection Time';   'Value (ms)'=if($sessionLimits.MaxConnectionTime){$sessionLimits.MaxConnectionTime}else{'Not Set'} }
            @{ Policy='Reset Broken';          'Value (ms)'=if($sessionLimits.fResetBroken){$sessionLimits.fResetBroken}else{'Not Set'} }
        )
        if (-not $sessionLimits.MaxIdleTime) { Write-Finding "No idle session timeout configured — sessions may persist indefinitely" WARN }
    } else {
        Write-Finding "No Terminal Services session limit policies found — configure idle/disconnect timeouts" WARN
        Add-MD "> ⚠️ Session time limit policies not configured."
    }
    Add-MD ""

    # Citrix-related event log scan
    Write-Status "Scanning for Citrix errors in event logs (last 24h)"
    Add-MD "### R2.5 Citrix Event Log Errors (Last 24h)"
    Add-MD ""
    $citrixEvents = Get-WinEvent -FilterHashtable @{ LogName='Application'; StartTime=(Get-Date).AddHours(-24) } -ErrorAction SilentlyContinue |
        Where-Object { $_.ProviderName -match 'Citrix|XenDesktop|XenApp|Broker' -and $_.Level -le 3 } |
        Select-Object -First 25
    if ($citrixEvents) {
        Add-MDTable -Headers @('Time','Level','Source','Message') -Rows (
            $citrixEvents | ForEach-Object { @{
                Time=$_.TimeCreated.ToString('yyyy-MM-dd HH:mm')
                Level=switch($_.Level){1{'Critical'}2{'Error'}3{'Warning'}default{'Info'}}
                Source=$_.ProviderName
                Message=$_.Message.Substring(0,[Math]::Min(200,$_.Message.Length))
            }}
        )
        $citrixCrit = $citrixEvents | Where-Object { $_.Level -le 2 }
        if ($citrixCrit) { Write-Finding "$($citrixCrit.Count) Citrix critical/error events in last 24h" CRIT }
    } else {
        Write-Finding "No Citrix error events in application log (last 24h)" PASS
        Add-MD "*No Citrix error events found.*"
    }
    Add-MD ""

    # Citrix receiver / workspace app on server (flagging risk)
    $citrixRcvr = Get-ItemProperty 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -match 'Citrix Workspace|Citrix Receiver' }
    if ($citrixRcvr) {
        Write-Finding "Citrix Workspace App / Receiver installed on server — review if this is a session host or management station" INFO
        Add-MD "- **Citrix Workspace App:** Installed — $($citrixRcvr.DisplayName) $($citrixRcvr.DisplayVersion)"
    }

    Write-BoxEnd
}

# ─────────────────────────────────────────────────────────────────────────────
#  ROLE MODULE: HYPER-V HOST
# ─────────────────────────────────────────────────────────────────────────────
function Invoke-RoleAudit-HyperV {
    Write-Box "ROLE AUDIT — HYPER-V HOST" Magenta
    Add-MD ""
    Add-MD "---"
    Add-MD "## R3. Hyper-V — Role-Specific Audit"
    Add-MD ""

    Write-Status "Checking Hyper-V feature and service state"
    $hvFeature = Get-WindowsFeature -Name 'Hyper-V' -ErrorAction SilentlyContinue
    if ($hvFeature -and $hvFeature.Installed) {
        Write-Finding "Hyper-V role is installed" PASS
        Add-MD "- **Hyper-V Role:** ✅ Installed"
    } else {
        Write-Finding "Hyper-V role not detected — verify role assignment" WARN
        Add-MD "- **Hyper-V Role:** ⚠️ Not detected"
    }
    $vmms = Get-Service 'vmms' -ErrorAction SilentlyContinue
    if ($vmms -and $vmms.Status -eq 'Running') {
        Write-Finding "Virtual Machine Management Service (VMMS) is Running" PASS
        Add-MD "- **VMMS Service:** ✅ Running"
    } else {
        Write-Finding "VMMS service is not running — Hyper-V management unavailable" CRIT
        Add-MD "- **VMMS Service:** ❌ Not running"
    }
    Add-MD ""

    # VM inventory
    Write-Status "Enumerating virtual machines"
    Add-MD "### R3.1 Virtual Machine Inventory"
    Add-MD ""
    $vms = Get-VM -ErrorAction SilentlyContinue
    if ($vms) {
        Add-MDTable -Headers @('Name','State','CPU Usage (%)','Mem Assigned (GB)','Uptime','Generation','Checkpoints') -Rows (
            $vms | ForEach-Object { @{
                Name=$_.Name; State=$_.State
                'CPU Usage (%)'=$_.CPUUsage
                'Mem Assigned (GB)'=[math]::Round($_.MemoryAssigned/1GB,1)
                Uptime=if($_.Uptime.TotalSeconds -gt 0){$_.Uptime.ToString('d\d\ h\h')}else{'Offline'}
                Generation=$_.Generation
                Checkpoints=(Get-VMCheckpoint -VMName $_.Name -ErrorAction SilentlyContinue).Count
            }}
        )
        $vmOff = $vms | Where-Object { $_.State -eq 'Off' }
        if ($vmOff) { Write-Finding "$($vmOff.Count) VMs are powered off — verify intentional" INFO }
        $vmCheckpoints = $vms | Where-Object { (Get-VMCheckpoint -VMName $_.Name -ErrorAction SilentlyContinue).Count -gt 0 }
        foreach ($vc in $vmCheckpoints) {
            Write-Finding "VM '$($vc.Name)' has active checkpoints — production checkpoints increase storage risk" WARN
        }
    } else {
        Write-Finding "No VMs found or Hyper-V module unavailable" WARN
        Add-MD "*No VMs enumerated.*"
    }
    Add-MD ""

    # Virtual switches
    Write-Status "Enumerating virtual switches"
    Add-MD "### R3.2 Virtual Switch Configuration"
    Add-MD ""
    $switches = Get-VMSwitch -ErrorAction SilentlyContinue
    if ($switches) {
        Add-MDTable -Headers @('Name','Type','NetAdapterName','Notes') -Rows (
            $switches | ForEach-Object { @{
                Name=$_.Name; Type=$_.SwitchType; NetAdapterName=if($_.NetAdapterInterfaceDescription){$_.NetAdapterInterfaceDescription}else{'N/A (Internal/Private)'}
                Notes=if($_.SwitchType -eq 'External'){'⚠️ Bridged to physical network'}elseif($_.SwitchType -eq 'Private'){'✅ Isolated'}else{'ℹ️ Internal only'}
            }}
        )
        $externalSwitches = $switches | Where-Object { $_.SwitchType -eq 'External' }
        foreach ($es in $externalSwitches) {
            Write-Finding "External vSwitch '$($es.Name)' bridges VMs to physical network — verify VLAN isolation" INFO
        }
    }
    Add-MD ""

    # Integration services
    Write-Status "Checking VM integration services versions"
    Add-MD "### R3.3 Integration Services Status"
    Add-MD ""
    if ($vms) {
        $isRows = $vms | ForEach-Object {
            $vm = $_
            $is = Get-VMIntegrationService -VMName $vm.Name -ErrorAction SilentlyContinue
            $enabled  = ($is | Where-Object { $_.Enabled }).Name -join ', '
            $disabled = ($is | Where-Object { -not $_.Enabled }).Name -join ', '
            @{
                VM=$vm.Name
                'Enabled Services'=if($enabled){$enabled}else{'None'}
                'Disabled Services'=if($disabled){"⚠️ $disabled"}else{'✅ None'}
            }
        }
        Add-MDTable -Headers @('VM','Enabled Services','Disabled Services') -Rows $isRows
    }
    Add-MD ""

    # Hyper-V host security settings
    Write-Status "Checking Hyper-V security settings"
    Add-MD "### R3.4 Hyper-V Host Security Settings"
    Add-MD ""
    $hvHostSec = Get-VMHost -ErrorAction SilentlyContinue
    if ($hvHostSec) {
        Add-MDTable -Headers @('Setting','Value') -Rows @(
            @{ Setting='Enabled for Enhanced Session Mode'; Value=if($hvHostSec.EnableEnhancedSessionMode){'✅ Yes'}else{'No'} }
            @{ Setting='VM Default Path';                   Value=$hvHostSec.VirtualMachinePath }
            @{ Setting='VHD Default Path';                  Value=$hvHostSec.VirtualHardDiskPath }
            @{ Setting='MacAddress Range';                  Value="$($hvHostSec.MacAddressMinimum) — $($hvHostSec.MacAddressMaximum)" }
        )
    }
    Add-MD ""

    Write-BoxEnd
}

# ─────────────────────────────────────────────────────────────────────────────
#  ROLE MODULE: SQL SERVER
# ─────────────────────────────────────────────────────────────────────────────
function Invoke-RoleAudit-SQL {
    Write-Box "ROLE AUDIT — MICROSOFT SQL SERVER" Magenta
    Add-MD ""
    Add-MD "---"
    Add-MD "## R4. SQL Server — Role-Specific Audit"
    Add-MD ""

    # SQL services
    Write-Status "Enumerating SQL Server services"
    Add-MD "### R4.1 SQL Server Services"
    Add-MD ""
    $sqlSvcs = Get-Service | Where-Object { $_.Name -match '^MSSQL|^SQLAgent|^SQLBrowser|^SSAS|^SSRS|^SSIS|^MsDts' } | Sort-Object Name
    if ($sqlSvcs) {
        Add-MDTable -Headers @('Service','Display Name','Status','Start Type') -Rows (
            $sqlSvcs | ForEach-Object { @{
                Service=$_.Name; 'Display Name'=$_.DisplayName
                Status=if($_.Status -eq 'Running'){'✅ Running'}else{"❌ $($_.Status)"}
                'Start Type'=$_.StartType
            }}
        )
        $sqlBrowser = $sqlSvcs | Where-Object { $_.Name -eq 'SQLBrowser' -and $_.Status -eq 'Running' }
        if ($sqlBrowser) { Write-Finding "SQL Browser service is running — exposes SQL instance discovery on UDP 1434" WARN }
        $stoppedSQL = $sqlSvcs | Where-Object { $_.Status -ne 'Running' -and $_.StartType -eq 'Automatic' }
        foreach ($ss in $stoppedSQL) { Write-Finding "SQL service '$($ss.DisplayName)' is set to Automatic but not Running" CRIT }
    } else {
        Write-Finding "No SQL Server services found — verify role assignment" WARN
        Add-MD "> ⚠️ No SQL Server services detected."
    }
    Add-MD ""

    # SQL instances via registry
    Write-Status "Detecting SQL Server instances"
    Add-MD "### R4.2 SQL Instance Detection"
    Add-MD ""
    $sqlInstances = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server' -ErrorAction SilentlyContinue).InstalledInstances
    if ($sqlInstances) {
        Add-MDTable -Headers @('Instance Name') -Rows ($sqlInstances | ForEach-Object { @{ 'Instance Name'=$_ } })
        foreach ($inst in $sqlInstances) {
            Write-Finding "SQL instance detected: $inst" INFO
        }
    } else {
        Add-MD "*No SQL instances found via registry.*"
    }
    Add-MD ""

    # SQL network listeners
    Write-Status "Checking SQL port listeners"
    Add-MD "### R4.3 SQL Network Listeners"
    Add-MD ""
    $sqlPorts = Get-NetTCPConnection -State Listen | Where-Object { $_.LocalPort -in @(1433,1434,4022,5022) }
    if ($sqlPorts) {
        Add-MDTable -Headers @('Port','Description','PID','Process') -Rows (
            $sqlPorts | ForEach-Object {
                $proc = try { (Get-Process -Id $_.OwningProcess -EA Stop).Name } catch { 'unknown' }
                $desc = switch ($_.LocalPort) {
                    1433 { 'SQL Default Instance' }
                    1434 { 'SQL Browser / DAC' }
                    4022 { 'SQL Service Broker' }
                    5022 { 'SQL AG Mirroring Endpoint' }
                    default { 'SQL Related' }
                }
                @{ Port=$_.LocalPort; Description=$desc; PID=$_.OwningProcess; Process=$proc }
            }
        )
        if ($sqlPorts | Where-Object { $_.LocalPort -eq 1433 }) {
            Write-Finding "SQL Server listening on default port 1433 — consider non-default port + firewall restriction" WARN
        }
    }
    Add-MD ""

    # SQL Server account check (service account)
    Write-Status "Checking SQL service account context"
    Add-MD "### R4.4 SQL Service Account Security"
    Add-MD ""
    $sqlServiceAccts = Get-CimInstance Win32_Service | Where-Object { $_.Name -match '^MSSQL' -and $_.StartName }
    foreach ($svc in $sqlServiceAccts) {
        $acct = $svc.StartName
        if ($acct -match 'LocalSystem|NT AUTHORITY\\SYSTEM') {
            Write-Finding "SQL service '$($svc.Name)' running as $acct — over-privileged, use a dedicated service account or MSA" CRIT
            Add-MD "- **$($svc.Name):** ❌ Running as $acct (over-privileged)"
        } elseif ($acct -match 'NT Service\\') {
            Write-Finding "SQL service '$($svc.Name)' running as virtual account $acct" PASS
            Add-MD "- **$($svc.Name):** ✅ Virtual account ($acct)"
        } else {
            Write-Finding "SQL service '$($svc.Name)' running as $acct — verify this is a least-privilege dedicated account" INFO
            Add-MD "- **$($svc.Name):** ℹ️ Account: $acct"
        }
    }
    Add-MD ""

    # SQL error log location
    Write-Status "Locating SQL Server error log path"
    Add-MD "### R4.5 SQL Error Log Location"
    Add-MD ""
    $sqlLogKey = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\*\Setup' -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($sqlLogKey -and $sqlLogKey.SQLPath) {
        Add-MD "- **SQL Install Path:** $($sqlLogKey.SQLPath)"
        Add-MD "- **SQL Data Path:** $($sqlLogKey.SQLDataRoot)"
    }
    Add-MD ""

    # SQL audit note
    Add-MD "### R4.6 SQL Security — Manual Steps Required"
    Add-MD ""
    Add-MD "> ⚠️ **The following SQL security checks require SSMS or sqlcmd access and cannot be automated without credentials:**"
    Add-MD ""
    Add-MD "- [ ] Verify SA account is DISABLED or renamed"
    Add-MD "- [ ] Audit SQL logins — confirm no unnecessary sysadmin members"
    Add-MD "- [ ] Check `xp_cmdshell` is DISABLED (``EXEC sp_configure 'xp_cmdshell'``)"
    Add-MD "- [ ] Verify SQL Audit / C2 audit mode is configured"
    Add-MD "- [ ] Confirm TDE (Transparent Data Encryption) on sensitive databases"
    Add-MD "- [ ] Review linked server configurations for unnecessary trust"
    Add-MD "- [ ] Check CLR integration is disabled if not required"
    Add-MD "- [ ] Verify backup encryption is configured"
    Add-MD "- [ ] Confirm database mail is disabled if not required (exposes SMTP relay)"
    Add-MD ""

    Write-BoxEnd
}

# ─────────────────────────────────────────────────────────────────────────────
#  ROLE MODULE: IIS / WEB APPLICATION SERVER
# ─────────────────────────────────────────────────────────────────────────────
function Invoke-RoleAudit-IIS {
    Write-Box "ROLE AUDIT — IIS / WEB APPLICATION SERVER" Magenta
    Add-MD ""
    Add-MD "---"
    Add-MD "## R5. IIS / SaaS Web Server — Role-Specific Audit"
    Add-MD ""

    Write-Status "Checking IIS service state"
    $w3svc = Get-Service 'W3SVC' -ErrorAction SilentlyContinue
    $was   = Get-Service 'WAS'   -ErrorAction SilentlyContinue
    if ($w3svc -and $w3svc.Status -eq 'Running') { Write-Finding "IIS W3SVC is Running" PASS; Add-MD "- **W3SVC:** ✅ Running" }
    else { Write-Finding "IIS W3SVC is not running" CRIT; Add-MD "- **W3SVC:** ❌ Not running" }
    if ($was -and $was.Status -eq 'Running') { Add-MD "- **WAS (Process Activation):** ✅ Running" }
    Add-MD ""

    # Import WebAdmin
    $webAdmin = $false
    try { Import-Module WebAdministration -ErrorAction Stop; $webAdmin = $true } catch {}

    if ($webAdmin) {
        # Sites
        Write-Status "Enumerating IIS sites"
        Add-MD "### R5.1 IIS Sites"
        Add-MD ""
        $sites = Get-Website -ErrorAction SilentlyContinue
        if ($sites) {
            Add-MDTable -Headers @('Name','State','Physical Path','Bindings') -Rows (
                $sites | ForEach-Object {
                    $bindings = ($_.Bindings.Collection | ForEach-Object { "$($_.Protocol)://$($_.BindingInformation)" }) -join ', '
                    @{ Name=$_.Name; State=if($_.State -eq 'Started'){'✅ Started'}else{"❌ $($_.State)"}; 'Physical Path'=$_.PhysicalPath; Bindings=$bindings }
                }
            )
        }
        Add-MD ""

        # App pools
        Write-Status "Enumerating application pools"
        Add-MD "### R5.2 Application Pools"
        Add-MD ""
        $pools = Get-WebConfiguration '/system.applicationHost/applicationPools/add' -ErrorAction SilentlyContinue
        if ($pools) {
            Add-MDTable -Headers @('Name','State','Identity','Pipeline Mode','.NET Version') -Rows (
                $pools | ForEach-Object { @{
                    Name=$_.Name
                    State=if($_.State -eq 'Started'){'✅ Started'}else{"❌ $($_.State)"}
                    Identity=$_.processModel.userName
                    'Pipeline Mode'=$_.managedPipelineMode
                    '.NET Version'=$_.managedRuntimeVersion
                }}
            )
            $poolsAsSystem = $pools | Where-Object { $_.processModel.userName -match 'LocalSystem' }
            foreach ($ps in $poolsAsSystem) { Write-Finding "App pool '$($ps.Name)' runs as LocalSystem — over-privileged" CRIT }
        }
        Add-MD ""

        # SSL bindings
        Write-Status "Checking SSL/TLS bindings"
        Add-MD "### R5.3 SSL/TLS Bindings"
        Add-MD ""
        $sslBindings = Get-Item 'IIS:\SslBindings\*' -ErrorAction SilentlyContinue
        if ($sslBindings) {
            $sslRows = $sslBindings | ForEach-Object {
                $cert = try { Get-Item "Cert:\LocalMachine\$($_.Store)\$($_.Thumbprint)" -ErrorAction Stop } catch { $null }
                @{
                    Binding="$($_.Host):$($_.Port)"
                    Thumbprint=$_.Thumbprint
                    Subject=if($cert){$cert.Subject}else{'(cert not found)'}
                    Expiry=if($cert){$cert.NotAfter.ToString('yyyy-MM-dd')}else{'Unknown'}
                    'Days Left'=if($cert){[math]::Round(($cert.NotAfter - (Get-Date)).TotalDays)}else{'N/A'}
                }
            }
            Add-MDTable -Headers @('Binding','Subject','Expiry','Days Left') -Rows $sslRows
            foreach ($sl in $sslRows) {
                $days = $sl['Days Left']
                if ($days -ne 'N/A' -and [int]$days -lt 30) {
                    Write-Finding "SSL cert for $($sl.Binding) expires in $days days" CRIT
                } elseif ($days -ne 'N/A' -and [int]$days -lt 90) {
                    Write-Finding "SSL cert for $($sl.Binding) expires in $days days — plan renewal" WARN
                }
            }
        } else {
            Write-Finding "No SSL bindings found — sites may be serving over HTTP only" WARN
        }
        Add-MD ""

        # Anonymous auth check
        Write-Status "Checking for anonymous authentication on sites"
        Add-MD "### R5.4 Anonymous Authentication Status"
        Add-MD ""
        foreach ($site in $sites) {
            $anon = Get-WebConfigurationProperty -Filter '/system.webServer/security/authentication/anonymousAuthentication' -Name 'enabled' -PSPath "IIS:\Sites\$($site.Name)" -ErrorAction SilentlyContinue
            if ($anon.Value -eq $true) {
                Write-Finding "Anonymous authentication ENABLED on site: '$($site.Name)'" WARN
                Add-MD "- **$($site.Name):** ⚠️ Anonymous Auth Enabled"
            } else {
                Write-Finding "Anonymous auth disabled on '$($site.Name)'" PASS
                Add-MD "- **$($site.Name):** ✅ Anonymous Auth Disabled"
            }
        }
        Add-MD ""

        # Request filtering / directory browsing
        Write-Status "Checking directory browsing and request filtering"
        Add-MD "### R5.5 Directory Browsing"
        Add-MD ""
        foreach ($site in $sites) {
            $dirBrowse = Get-WebConfigurationProperty -Filter '/system.webServer/directoryBrowse' -Name 'enabled' -PSPath "IIS:\Sites\$($site.Name)" -ErrorAction SilentlyContinue
            if ($dirBrowse.Value -eq $true) {
                Write-Finding "Directory browsing ENABLED on '$($site.Name)' — information disclosure risk" CRIT
                Add-MD "- **$($site.Name):** ❌ Directory Browsing Enabled"
            } else {
                Add-MD "- **$($site.Name):** ✅ Directory Browsing Disabled"
            }
        }
        Add-MD ""
    } else {
        Write-Finding "WebAdministration module unavailable — IIS detailed checks skipped" WARN
        Add-MD "> ⚠️ WebAdministration module not available. Install RSAT/IIS management tools."
    }

    Write-BoxEnd
}

# ─────────────────────────────────────────────────────────────────────────────
#  ROLE MODULE: FILE SERVER / DFS
# ─────────────────────────────────────────────────────────────────────────────
function Invoke-RoleAudit-FileServer {
    Write-Box "ROLE AUDIT — FILE SERVER / DFS" Magenta
    Add-MD ""
    Add-MD "---"
    Add-MD "## R6. File Server / DFS — Role-Specific Audit"
    Add-MD ""

    # All SMB shares with ACLs
    Write-Status "Enumerating all SMB shares and permissions"
    Add-MD "### R6.1 All SMB Shares & Access Control"
    Add-MD ""
    $shares = Get-SmbShare -ErrorAction SilentlyContinue
    foreach ($share in $shares) {
        Add-MD "#### Share: $($share.Name)"
        Add-MDTable -Headers @('Property','Value') -Rows @(
            @{ Property='Path';           Value=$share.Path }
            @{ Property='Description';    Value=$share.Description }
            @{ Property='Concurrent Users';Value=$share.ConcurrentUserLimit }
            @{ Property='Encrypt Data';   Value=if($share.EncryptData){'✅ Yes'}else{'⚠️ No'} }
            @{ Property='Cache Mode';     Value=$share.CachingMode }
        )
        $acl = Get-SmbShareAccess -Name $share.Name -ErrorAction SilentlyContinue
        if ($acl) {
            Add-MDTable -Headers @('Account','Access Control','Access Right') -Rows (
                $acl | ForEach-Object { @{ Account=$_.AccountName; 'Access Control'=$_.AccessControlType; 'Access Right'=$_.AccessRight } }
            )
            $everyoneACE = $acl | Where-Object { $_.AccountName -match 'Everyone|EVERYONE' -and $_.AccessRight -ne 'Read' }
            if ($everyoneACE) { Write-Finding "Share '$($share.Name)' grants '$($everyoneACE.AccessRight)' to Everyone — excessive permissions" CRIT }
        }
        if (-not $share.EncryptData) { Write-Finding "Share '$($share.Name)' does not enforce SMB encryption" WARN }
    }
    Add-MD ""

    # Open files
    Write-Status "Checking open files on shares"
    Add-MD "### R6.2 Currently Open Files"
    Add-MD ""
    $openFiles = Get-SmbOpenFile -ErrorAction SilentlyContinue
    if ($openFiles) {
        Add-MDTable -Headers @('File ID','Path','Client','Session ID') -Rows (
            $openFiles | Select-Object -First 50 | ForEach-Object { @{
                'File ID'=$_.FileId; Path=$_.Path
                Client=$_.ClientComputerName; 'Session ID'=$_.SessionId
            }}
        )
        Add-MD ""
        Write-Finding "$($openFiles.Count) files currently open across shares" INFO
    } else {
        Add-MD "*No open files at time of scan.*"
    }
    Add-MD ""

    # DFS
    Write-Status "Checking DFS Namespace and Replication"
    Add-MD "### R6.3 DFS Namespace Configuration"
    Add-MD ""
    $dfsn = Get-DfsnRoot -ErrorAction SilentlyContinue
    if ($dfsn) {
        Add-MDTable -Headers @('Path','Type','State','Description') -Rows (
            $dfsn | ForEach-Object { @{ Path=$_.Path; Type=$_.Type; State=$_.State; Description=$_.Description } }
        )
        $disabledDFS = $dfsn | Where-Object { $_.State -ne 'Online' }
        foreach ($d in $disabledDFS) { Write-Finding "DFS namespace '$($d.Path)' is not Online — state: $($d.State)" WARN }
    } else {
        Write-Finding "No DFS Namespaces found or DFS role not installed" INFO
        Add-MD "*No DFS Namespaces detected.*"
    }
    Add-MD ""

    # DFS Replication
    $dfsr = Get-DfsrGroupMembership -ErrorAction SilentlyContinue
    if ($dfsr) {
        Add-MD "### R6.4 DFS Replication Group Membership"
        Add-MD ""
        Add-MDTable -Headers @('Group','Folder','Volume','Enabled','State') -Rows (
            $dfsr | ForEach-Object { @{
                Group=$_.GroupName; Folder=$_.FolderName
                Volume=$_.VolumeName; Enabled=$_.Enabled; State=$_.State
            }}
        )
        $dfsBroken = $dfsr | Where-Object { $_.State -ne 'Normal' -and $_.State -ne 'Initialized' }
        foreach ($db in $dfsBroken) { Write-Finding "DFS-R '$($db.GroupName)\$($db.FolderName)' replication state: $($db.State)" WARN }
    }
    Add-MD ""

    # Quota
    Write-Status "Checking FSRM quotas"
    Add-MD "### R6.5 FSRM Quota Status"
    Add-MD ""
    $quotas = Get-FsrmQuota -ErrorAction SilentlyContinue
    if ($quotas) {
        Add-MDTable -Headers @('Path','Limit (GB)','Used (GB)','% Used','Status') -Rows (
            $quotas | ForEach-Object { @{
                Path=$_.Path
                'Limit (GB)'=[math]::Round($_.Size/1GB,1)
                'Used (GB)'=[math]::Round($_.Usage/1GB,1)
                '% Used'=[math]::Round(($_.Usage/$_.Size)*100,1)
                Status=$_.QuotaFlags
            }}
        )
        $overQuota = $quotas | Where-Object { $_.Usage -ge $_.Size }
        foreach ($oq in $overQuota) { Write-Finding "Quota exceeded on $($oq.Path)" CRIT }
    } else {
        Write-Finding "No FSRM quotas configured — consider configuring storage quotas" INFO
        Add-MD "*No FSRM quotas found.*"
    }
    Add-MD ""

    Write-BoxEnd
}

# ─────────────────────────────────────────────────────────────────────────────
#  ROLE MODULE: PKI / CERTIFICATE AUTHORITY
# ─────────────────────────────────────────────────────────────────────────────
function Invoke-RoleAudit-PKI {
    Write-Box "ROLE AUDIT — CERTIFICATE AUTHORITY (ADCS/PKI)" Magenta
    Add-MD ""
    Add-MD "---"
    Add-MD "## R7. PKI / Certificate Authority — Role-Specific Audit"
    Add-MD ""

    # CA service
    Write-Status "Checking Certificate Services"
    $certSvc = Get-Service 'CertSvc' -ErrorAction SilentlyContinue
    if ($certSvc -and $certSvc.Status -eq 'Running') {
        Write-Finding "Active Directory Certificate Services (CertSvc) is Running" PASS
        Add-MD "- **CertSvc:** ✅ Running"
    } else {
        Write-Finding "CertSvc not running or not installed" WARN
        Add-MD "- **CertSvc:** ⚠️ Not running — verify CA role"
    }
    Add-MD ""

    # CA config
    Write-Status "Reading CA configuration"
    Add-MD "### R7.1 CA Configuration"
    Add-MD ""
    $caConfig = certutil -getconfig 2>&1
    Add-MD "``````"
    $caConfig | ForEach-Object { Add-MD $_ }
    Add-MD "``````"
    Add-MD ""

    # CA registry config
    $caRegPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration'
    $caReg = Get-ChildItem $caRegPath -ErrorAction SilentlyContinue
    if ($caReg) {
        $caName = $caReg[0].PSChildName
        $caProps = Get-ItemProperty "$caRegPath\$caName" -ErrorAction SilentlyContinue
        if ($caProps) {
            Add-MDTable -Headers @('Property','Value') -Rows @(
                @{ Property='CA Name';           Value=$caName }
                @{ Property='CA Type';           Value=switch($caProps.CAType){0{'Enterprise Root CA'}1{'Enterprise Subordinate CA'}3{'Standalone Root CA'}4{'Standalone Subordinate CA'}default{"Unknown ($($caProps.CAType))"}} }
                @{ Property='CRL Period';        Value="$($caProps.CRLPeriodUnits) $($caProps.CRLPeriod)" }
                @{ Property='CRL Delta Period';  Value="$($caProps.CRLDeltaPeriodUnits) $($caProps.CRLDeltaPeriod)" }
                @{ Property='Validity Period';   Value="$($caProps.ValidityPeriodUnits) $($caProps.ValidityPeriod)" }
                @{ Property='Audit Filter';      Value=$caProps.AuditFilter }
            )

            if ($caProps.AuditFilter -lt 127) {
                Write-Finding "CA Audit Filter ($($caProps.AuditFilter)) does not capture all events — recommended value: 127" WARN
            } else {
                Write-Finding "CA audit logging configured for all event categories" PASS
            }
        }
    }
    Add-MD ""

    # Expiring certificates
    Write-Status "Checking for certificates expiring within 90 days"
    Add-MD "### R7.2 Certificates Expiring Within 90 Days"
    Add-MD ""
    $expiring = Get-ChildItem 'Cert:\LocalMachine\My' | Where-Object { 
        $_.NotAfter -lt (Get-Date).AddDays(90) -and $_.NotAfter -gt (Get-Date)
    }
    $expired = Get-ChildItem 'Cert:\LocalMachine\My' | Where-Object { $_.NotAfter -lt (Get-Date) }

    if ($expiring) {
        Add-MDTable -Headers @('Subject','Thumbprint','Expiry','Days Left','Issuer') -Rows (
            $expiring | ForEach-Object { @{
                Subject=$_.Subject; Thumbprint=$_.Thumbprint.Substring(0,16)+'...'
                Expiry=$_.NotAfter.ToString('yyyy-MM-dd')
                'Days Left'=[math]::Round(($_.NotAfter-(Get-Date)).TotalDays)
                Issuer=$_.Issuer
            }}
        )
        foreach ($ec in $expiring) {
            $days = [math]::Round(($ec.NotAfter - (Get-Date)).TotalDays)
            Write-Finding "Certificate expiring in $days days: $($ec.Subject)" $(if($days -lt 30){'CRIT'}else{'WARN'})
        }
    } else {
        Write-Finding "No certificates in LocalMachine\My expiring within 90 days" PASS
        Add-MD "*No near-expiry certificates.*"
    }

    if ($expired) {
        Add-MD ""
        Add-MD "### R7.3 Expired Certificates Still in Store"
        Add-MD ""
        Add-MDTable -Headers @('Subject','Expired','Issuer') -Rows (
            $expired | ForEach-Object { @{ Subject=$_.Subject; Expired=$_.NotAfter.ToString('yyyy-MM-dd'); Issuer=$_.Issuer } }
        )
        foreach ($ex in $expired) { Write-Finding "EXPIRED certificate still in store: $($ex.Subject) (expired $($ex.NotAfter.ToString('yyyy-MM-dd')))" CRIT }
    }
    Add-MD ""

    # CRL check
    Write-Status "Checking CRL validity"
    Add-MD "### R7.4 CRL Status"
    Add-MD ""
    $crlCheck = certutil -CRL 2>&1
    Add-MD "``````"
    $crlCheck | Select-Object -First 30 | ForEach-Object { Add-MD $_ }
    Add-MD "``````"
    Add-MD ""

    Write-BoxEnd
}

# ─────────────────────────────────────────────────────────────────────────────
#  ROLE MODULE: REMOTE DESKTOP SERVICES
# ─────────────────────────────────────────────────────────────────────────────
function Invoke-RoleAudit-RDS {
    Write-Box "ROLE AUDIT — REMOTE DESKTOP SERVICES" Magenta
    Add-MD ""
    Add-MD "---"
    Add-MD "## R8. Remote Desktop Services — Role-Specific Audit"
    Add-MD ""

    # RDS services
    Write-Status "Checking RDS services"
    Add-MD "### R8.1 RDS Service Health"
    Add-MD ""
    $rdsSvcs = @('TermService','SessionEnv','UmRdpService','RpcSs','RDSessMgr','TscPubRPC','TlntSvr') | ForEach-Object {
        Get-Service $_ -ErrorAction SilentlyContinue
    } | Where-Object { $_ }
    if ($rdsSvcs) {
        Add-MDTable -Headers @('Service','Display Name','Status','Start Type') -Rows (
            $rdsSvcs | ForEach-Object { @{
                Service=$_.Name; 'Display Name'=$_.DisplayName
                Status=if($_.Status -eq 'Running'){'✅ Running'}else{"⚠️ $($_.Status)"}
                'Start Type'=$_.StartType
            }}
        )
    }
    Add-MD ""

    # Licensing
    Write-Status "Checking RDS licensing mode"
    Add-MD "### R8.2 RDS Licensing Configuration"
    Add-MD ""
    $licMode = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -ErrorAction SilentlyContinue).LicensingMode
    $licServer = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -ErrorAction SilentlyContinue).LicenseServers
    $licModeStr = switch ($licMode) {
        2 { 'Per Device' }
        4 { 'Per User' }
        $null { 'Not configured (grace period / unlicensed)' }
        default { "Unknown ($licMode)" }
    }
    Add-MDTable -Headers @('Setting','Value','Status') -Rows @(
        @{ Setting='Licensing Mode';   Value=$licModeStr;  Status=if($licMode){'✅'}else{'⚠️ Grace/Unlicensed'} }
        @{ Setting='License Server';  Value=if($licServer){$licServer}else{'Not configured'}; Status=if($licServer){'✅'}else{'⚠️'} }
    )
    if (-not $licMode)   { Write-Finding "RDS licensing mode not configured — server may be in grace period" CRIT }
    if (-not $licServer) { Write-Finding "No RDS license server configured" WARN }
    Add-MD ""

    # Session security
    Write-Status "Checking RDS session security settings"
    Add-MD "### R8.3 RDS Session Security Settings"
    Add-MD ""
    $rdsPol = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -ErrorAction SilentlyContinue
    Add-MDTable -Headers @('Setting','Value','Recommendation','Status') -Rows @(
        @{ Setting='Security Layer';          Value=switch($rdsPol.SecurityLayer){0{'RDP Security'}1{'Negotiate'}2{'SSL/TLS'}$null{'Not Set'}default{$rdsPol.SecurityLayer}}
           Recommendation='SSL (2)';          Status=if($rdsPol.SecurityLayer -eq 2){'✅'}else{'⚠️'} }
        @{ Setting='Encryption Level';        Value=switch($rdsPol.MinEncryptionLevel){1{'Low'}2{'Client Compatible'}3{'High'}4{'FIPS'}$null{'Not Set'}default{$rdsPol.MinEncryptionLevel}}
           Recommendation='High (3) or FIPS'; Status=if($rdsPol.MinEncryptionLevel -ge 3){'✅'}elseif($rdsPol.MinEncryptionLevel){'⚠️'}else{'⚠️ Not Set'} }
        @{ Setting='NLA Required';            Value=if($rdsPol.UserAuthentication -eq 1){'Yes'}else{'No / Not Set'}
           Recommendation='Yes (1)';          Status=if($rdsPol.UserAuthentication -eq 1){'✅'}else{'❌'} }
        @{ Setting='Clipboard Redirection Disabled'; Value=if($rdsPol.fDisableClip -eq 1){'Yes'}else{'No'}
           Recommendation='Yes (security baseline)'; Status=if($rdsPol.fDisableClip -eq 1){'✅'}else{'ℹ️ Evaluate'} }
        @{ Setting='Drive Redirection Disabled';     Value=if($rdsPol.fDisableCdm -eq 1){'Yes'}else{'No'}
           Recommendation='Yes (security baseline)'; Status=if($rdsPol.fDisableCdm -eq 1){'✅'}else{'ℹ️ Evaluate'} }
    )
    if ($rdsPol.UserAuthentication -ne 1) { Write-Finding "NLA not enforced for RDS sessions — pre-auth credential exposure" CRIT }
    if ($rdsPol.SecurityLayer -ne 2)      { Write-Finding "RDS Security Layer is not SSL/TLS — consider enforcing SSL (layer 2)" WARN }
    Add-MD ""

    # Active sessions
    Write-Status "Querying active RDS sessions"
    Add-MD "### R8.4 Active RDS Sessions"
    Add-MD ""
    $sessions = query session 2>&1
    Add-MD "``````"
    $sessions | ForEach-Object { Add-MD $_ }
    Add-MD "``````"
    Add-MD ""

    Write-BoxEnd
}

# ─────────────────────────────────────────────────────────────────────────────
#  ROLE MODULE: WSUS
# ─────────────────────────────────────────────────────────────────────────────
function Invoke-RoleAudit-WSUS {
    Write-Box "ROLE AUDIT — WSUS / WINDOWS SERVER UPDATE SERVICES" Magenta
    Add-MD ""
    Add-MD "---"
    Add-MD "## R9. WSUS — Role-Specific Audit"
    Add-MD ""

    # WSUS service
    Write-Status "Checking WSUS services"
    $wsusSvcs = @('WsusService','UpdateServices-Db','wuauserv') | ForEach-Object {
        Get-Service $_ -ErrorAction SilentlyContinue
    } | Where-Object { $_ }
    Add-MD "### R9.1 WSUS Service State"
    Add-MD ""
    if ($wsusSvcs) {
        Add-MDTable -Headers @('Service','Status','Start Type') -Rows (
            $wsusSvcs | ForEach-Object { @{
                Service=$_.DisplayName
                Status=if($_.Status -eq 'Running'){'✅ Running'}else{"❌ $($_.Status)"}
                'Start Type'=$_.StartType
            }}
        )
    }
    Add-MD ""

    # WSUS API
    Write-Status "Connecting to WSUS API"
    Add-MD "### R9.2 WSUS Server Status"
    Add-MD ""
    try {
        [reflection.assembly]::LoadWithPartialName('Microsoft.UpdateServices.Administration') | Out-Null
        $wsus = [Microsoft.UpdateServices.Administration.AdminProxy]::GetUpdateServer('localhost',$false,8530)
        if ($wsus) {
            $status = $wsus.GetStatus()
            Add-MDTable -Headers @('Property','Value') -Rows @(
                @{ Property='WSUS Version';          Value=$wsus.Version }
                @{ Property='Server Name';            Value=$wsus.ServerName }
                @{ Property='Total Computers';        Value=$status.ComputerTargetCount }
                @{ Property='Updates Needed';         Value=$status.UpdatesWithInstallableUpdatesCount }
                @{ Property='Failed Updates';         Value=$status.ComputersWithUpdateErrorsCount }
                @{ Property='Last Sync Time';         Value=$wsus.GetSubscription().LastSynchronizationTime }
                @{ Property='Sync Status';            Value=$wsus.GetSubscription().LastSynchronizationResult }
            )
            if ($status.ComputersWithUpdateErrorsCount -gt 0) {
                Write-Finding "$($status.ComputersWithUpdateErrorsCount) computers have update errors in WSUS" WARN
            }
        }
    } catch {
        Write-Finding "Could not connect to WSUS API — checking registry config instead" WARN
        $wsusReg = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Update Services\Server\Setup' -ErrorAction SilentlyContinue
        if ($wsusReg) {
            Add-MDTable -Headers @('Property','Value') -Rows @(
                @{ Property='WSUS Install Path';  Value=$wsusReg.TargetDir }
                @{ Property='Port';              Value=$wsusReg.PortNumber }
                @{ Property='SSL Enabled';       Value=if($wsusReg.UseSSL){'Yes'}else{'⚠️ No'} }
            )
            if (-not $wsusReg.UseSSL) { Write-Finding "WSUS is not configured with SSL — update communications unencrypted" WARN }
        } else {
            Add-MD "> ⚠️ WSUS does not appear to be installed on this server."
        }
    }
    Add-MD ""

    # Client WSUS config
    Write-Status "Checking Windows Update / WSUS client configuration"
    Add-MD "### R9.3 Windows Update Client Settings"
    Add-MD ""
    $wuReg = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -ErrorAction SilentlyContinue
    $wuAU  = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -ErrorAction SilentlyContinue
    if ($wuReg -or $wuAU) {
        Add-MDTable -Headers @('Setting','Value') -Rows @(
            @{ Setting='WSUS Server';         Value=if($wuReg.WUServer){$wuReg.WUServer}else{'(direct to Microsoft)'} }
            @{ Setting='Status Server';       Value=if($wuReg.WUStatusServer){$wuReg.WUStatusServer}else{'Not set'} }
            @{ Setting='Target Group';        Value=if($wuReg.TargetGroup){$wuReg.TargetGroup}else{'Not set'} }
            @{ Setting='Auto Update';         Value=if($wuAU.NoAutoUpdate -eq 1){'Disabled'}else{'Enabled'} }
            @{ Setting='Scheduled Install Day';Value=if($wuAU.ScheduledInstallDay){$wuAU.ScheduledInstallDay}else{'Not set'} }
            @{ Setting='Elevate Non-Admins';  Value=if($wuAU.ElevateNonAdmins){'Yes'}else{'No'} }
        )
    } else {
        Write-Finding "No WSUS client GPO settings found — server may be pulling from Windows Update directly" WARN
        Add-MD "> ⚠️ No WSUS client policies detected."
    }
    Add-MD ""

    Write-BoxEnd
}

# ─────────────────────────────────────────────────────────────────────────────
#  ROLE MODULE: EXCHANGE / MAIL SERVER
# ─────────────────────────────────────────────────────────────────────────────
function Invoke-RoleAudit-Exchange {
    Write-Box "ROLE AUDIT — EXCHANGE / MAIL SERVER" Magenta
    Add-MD ""
    Add-MD "---"
    Add-MD "## R10. Exchange — Role-Specific Audit"
    Add-MD ""

    # Exchange services
    Write-Status "Checking Exchange services"
    Add-MD "### R10.1 Exchange Service Health"
    Add-MD ""
    $exSvcs = Get-Service | Where-Object { $_.Name -match '^MSExchange' } | Sort-Object Name
    if ($exSvcs) {
        Add-MDTable -Headers @('Service','Display Name','Status','Start Type') -Rows (
            $exSvcs | ForEach-Object { @{
                Service=$_.Name; 'Display Name'=$_.DisplayName
                Status=if($_.Status -eq 'Running'){'✅ Running'}else{"❌ $($_.Status)"}
                'Start Type'=$_.StartType
            }}
        )
        $stoppedEx = $exSvcs | Where-Object { $_.Status -ne 'Running' -and $_.StartType -eq 'Automatic' }
        foreach ($se in $stoppedEx) { Write-Finding "Exchange service '$($se.DisplayName)' is Automatic but not running" CRIT }
    } else {
        Write-Finding "No Exchange services detected — verify role" WARN
        Add-MD "> ⚠️ No Exchange services found."
    }
    Add-MD ""

    # Exchange Shell
    $exShell = $false
    try {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn -ErrorAction Stop
        $exShell = $true
    } catch {
        # Try module
        $exModule = Get-Module -Name ExchangeOnlineManagement -ListAvailable -ErrorAction SilentlyContinue
        if (-not $exModule) {
            Write-Finding "Exchange Management Shell/SnapIn not available — Exchange-specific cmdlets unavailable" WARN
            Add-MD "> ⚠️ Exchange Management Shell not available. Run from Exchange server or EMS."
        }
    }

    if ($exShell) {
        # Server version
        Write-Status "Getting Exchange server version"
        Add-MD "### R10.2 Exchange Server Configuration"
        Add-MD ""
        $exServer = Get-ExchangeServer -ErrorAction SilentlyContinue
        if ($exServer) {
            Add-MDTable -Headers @('Name','Role','Version','Edition','Is Hub') -Rows (
                $exServer | ForEach-Object { @{
                    Name=$_.Name; Role=($_.ServerRole -join ','); Version=$_.AdminDisplayVersion
                    Edition=$_.Edition; 'Is Hub'=$_.IsHubTransportServer
                }}
            )
        }
        Add-MD ""

        # Receive connectors
        Write-Status "Checking receive connectors for open relay"
        Add-MD "### R10.3 Receive Connectors (Open Relay Check)"
        Add-MD ""
        $rcvConn = Get-ReceiveConnector -ErrorAction SilentlyContinue
        if ($rcvConn) {
            Add-MDTable -Headers @('Name','Bindings','RemoteIP','Auth','Permission Groups') -Rows (
                $rcvConn | ForEach-Object { @{
                    Name=$_.Name
                    Bindings=($_.Bindings -join ', ')
                    RemoteIP=($_.RemoteIPRanges -join ', ')
                    Auth=($_.AuthMechanism -join ', ')
                    'Permission Groups'=($_.PermissionGroups -join ', ')
                }}
            )
            $openRelay = $rcvConn | Where-Object { 
                ($_.RemoteIPRanges -join '') -match '0\.0\.0\.0-255\.255\.255\.255|\{-\}' -and
                $_.PermissionGroups -match 'Anonymous'
            }
            foreach ($or in $openRelay) {
                Write-Finding "Potential OPEN RELAY: connector '$($or.Name)' allows anonymous from any IP" CRIT
            }
        }
        Add-MD ""

        # Transport rules
        Write-Status "Checking transport rules"
        Add-MD "### R10.4 Mail Flow / Transport Rules"
        Add-MD ""
        $transRules = Get-TransportRule -ErrorAction SilentlyContinue
        if ($transRules) {
            Add-MDTable -Headers @('Name','State','Priority','Description') -Rows (
                $transRules | ForEach-Object { @{
                    Name=$_.Name; State=$_.State; Priority=$_.Priority
                    Description=$_.Description
                }}
            )
        } else {
            Add-MD "*No transport rules configured.*"
        }
        Add-MD ""

        # TLS settings
        Write-Status "Checking Exchange TLS configuration"
        Add-MD "### R10.5 TLS / Certificate Configuration"
        Add-MD ""
        $exCerts = Get-ExchangeCertificate -ErrorAction SilentlyContinue
        if ($exCerts) {
            Add-MDTable -Headers @('Thumbprint','Subject','Services','Expiry','Days Left','Self-Signed') -Rows (
                $exCerts | ForEach-Object { @{
                    Thumbprint=$_.Thumbprint.Substring(0,16)+'...'
                    Subject=$_.Subject
                    Services=($_.Services -join ',')
                    Expiry=$_.NotAfter.ToString('yyyy-MM-dd')
                    'Days Left'=[math]::Round(($_.NotAfter-(Get-Date)).TotalDays)
                    'Self-Signed'=if($_.IsSelfSigned){'⚠️ Yes'}else{'✅ No'}
                }}
            )
            foreach ($cert in $exCerts) {
                $days = [math]::Round(($cert.NotAfter-(Get-Date)).TotalDays)
                if ($days -lt 30)  { Write-Finding "Exchange cert expiring in $days days: $($cert.Subject)" CRIT }
                elseif ($days -lt 90) { Write-Finding "Exchange cert expiring in $days days: $($cert.Subject)" WARN }
                if ($cert.IsSelfSigned) { Write-Finding "Exchange cert is SELF-SIGNED: $($cert.Subject) — replace with CA-issued cert" WARN }
            }
        }
        Add-MD ""
    } else {
        # Fallback — check SMTP ports
        Add-MD "### R10.2 SMTP Port Listener Status (Fallback)"
        Add-MD ""
        $smtpPorts = Get-NetTCPConnection -State Listen | Where-Object { $_.LocalPort -in @(25,465,587,993,995,143,110) }
        if ($smtpPorts) {
            Add-MDTable -Headers @('Port','Protocol Meaning') -Rows (
                $smtpPorts | ForEach-Object {
                    $proto = switch ($_.LocalPort) { 25{'SMTP'}465{'SMTPS (legacy)'}587{'SMTP Submission'}993{'IMAPS'}995{'POP3S'}143{'IMAP'}110{'POP3'}default{'Unknown'} }
                    @{ Port=$_.LocalPort; 'Protocol Meaning'=$proto }
                }
            )
        } else {
            Add-MD "*No SMTP/mail ports detected listening.*"
        }
        Add-MD ""
        Add-MD "### R10.3 Manual Exchange Security Checklist"
        Add-MD ""
        Add-MD "- [ ] Verify no anonymous relay configured on receive connectors"
        Add-MD "- [ ] Confirm TLS enforced on send/receive connectors"
        Add-MD "- [ ] Check Exchange Emergency Mitigation Service (EMS) is enabled"
        Add-MD "- [ ] Verify Mailbox Audit Logging is enabled for all mailboxes"
        Add-MD "- [ ] Check OWA/ECP virtual directories — disable if not required"
        Add-MD "- [ ] Review Exchange certificate expiration"
        Add-MD "- [ ] Confirm EWS is locked down if not required externally"
        Add-MD ""
    }

    Write-BoxEnd
}

# ─────────────────────────────────────────────────────────────────────────────
#  ROLE MODULE DISPATCHER
# ─────────────────────────────────────────────────────────────────────────────
function Invoke-RoleAudits {
    if ($Script:SERVER_ROLES -contains 'STANDALONE') {
        Write-Status "Standalone server — role-specific modules skipped" INFO
        Add-MD ""
        Add-MD "---"
        Add-MD "## Role Audit: Standalone Server"
        Add-MD ""
        Add-MD "> ℹ️ Standalone role selected. No role-specific modules were executed."
        Add-MD ""
        return
    }

    Add-MD ""
    Add-MD "---"
    Add-MD "# ROLE-SPECIFIC AUDIT SECTIONS"
    Add-MD ""
    Add-MD "Roles identified: **$($Script:SERVER_ROLES -join ', ')**"
    Add-MD ""

    foreach ($role in $Script:SERVER_ROLES) {
        switch ($role) {
            'DC'        { Invoke-RoleAudit-DC }
            'CITRIX'    { Invoke-RoleAudit-Citrix }
            'HYPERV'    { Invoke-RoleAudit-HyperV }
            'SQL'       { Invoke-RoleAudit-SQL }
            'IIS'       { Invoke-RoleAudit-IIS }
            'FILESVR'   { Invoke-RoleAudit-FileServer }
            'PKI'       { Invoke-RoleAudit-PKI }
            'RDS'       { Invoke-RoleAudit-RDS }
            'WSUS'      { Invoke-RoleAudit-WSUS }
            'EXCHANGE'  { Invoke-RoleAudit-Exchange }
        }
    }
}

# ─────────────────────────────────────────────────────────────────────────────
#  COMPLETION SCREEN
# ─────────────────────────────────────────────────────────────────────────────
function Show-Completion {
    $elapsed = [math]::Round(((Get-Date) - $Script:START_TIME).TotalSeconds, 0)

    Write-Host ""
    Write-Host "  ╔══════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "  ║                                                                          ║" -ForegroundColor Cyan
    Write-Host "  ║   A U D I T   C O M P L E T E                                           ║" -ForegroundColor Cyan
    Write-Host "  ║                                                                          ║" -ForegroundColor Cyan
    Write-Host "  ║   Duration:   " -NoNewline -ForegroundColor Cyan
    Write-Host ("{0,-57}" -f "${elapsed}s")                -NoNewline -ForegroundColor White;   Write-Host "║" -ForegroundColor Cyan
    Write-Host "  ║   Report:     " -NoNewline -ForegroundColor Cyan
    Write-Host ("{0,-57}" -f $Script:REPORT_PATH)          -NoNewline -ForegroundColor Yellow;  Write-Host "║" -ForegroundColor Cyan
    Write-Host "  ║                                                                          ║" -ForegroundColor Cyan
    Write-Host "  ║   PASS        " -NoNewline -ForegroundColor Cyan
    Write-Host ("{0,-57}" -f "✓  $($Script:CNT_PASS)")    -NoNewline -ForegroundColor Green;   Write-Host "║" -ForegroundColor Cyan
    Write-Host "  ║   WARN        " -NoNewline -ForegroundColor Cyan
    Write-Host ("{0,-57}" -f "!  $($Script:CNT_WARN)")    -NoNewline -ForegroundColor Yellow;  Write-Host "║" -ForegroundColor Cyan
    Write-Host "  ║   CRITICAL    " -NoNewline -ForegroundColor Cyan
    Write-Host ("{0,-57}" -f "X  $($Script:CNT_CRIT)")    -NoNewline -ForegroundColor Red;     Write-Host "║" -ForegroundColor Cyan
    Write-Host "  ║   IOC / THREAT" -NoNewline -ForegroundColor Cyan
    Write-Host ("{0,-57}" -f "!  $($Script:CNT_IOC)")     -NoNewline -ForegroundColor Magenta; Write-Host "║" -ForegroundColor Cyan
    Write-Host "  ║   ERRORS      " -NoNewline -ForegroundColor Cyan
    Write-Host ("{0,-57}" -f "?  $($Script:CNT_ERR)")     -NoNewline -ForegroundColor DarkGray;Write-Host "║" -ForegroundColor Cyan
    Write-Host "  ║                                                                          ║" -ForegroundColor Cyan
    Write-Host "  ║   Hidden Protocol Systems — Signal over noise.                           ║" -ForegroundColor DarkGray
    Write-Host "  ║   Jamie Eastridge // CISO / Principal // jamie@hiddenprotocol.com        ║" -ForegroundColor DarkGray
    Write-Host "  ╚══════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
}

# ─────────────────────────────────────────────────────────────────────────────
#  MAIN ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────
function Main {
    # Elevation check
    if (-not (Test-AdminPrivilege)) {
        Write-Host ""
        Write-Host "  [!] This script requires elevation. Please run as Administrator." -ForegroundColor Red
        Write-Host ""
        exit 1
    }

    # Step 1: Server role identification
    Show-ServerRoleMenu

    # Step 2: Audit module selection
    Show-MainMenu

    # Confirm and go
    Clear-Host
    Write-HPS-Banner
    Write-Host "  Server Role(s):   " -NoNewline -ForegroundColor DarkGray
    Write-Host ($Script:SERVER_ROLES -join ' + ') -ForegroundColor Magenta
    Write-Host "  Modules selected: " -NoNewline -ForegroundColor DarkGray
    Write-Host ($Script:SELECTED_MODS -join ' → ') -ForegroundColor Cyan
    Write-Host "  Output: " -NoNewline -ForegroundColor DarkGray
    Write-Host $Script:REPORT_PATH -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  Starting in 2s... " -NoNewline -ForegroundColor DarkGray
    Start-Sleep -Seconds 1; Write-Host "1... " -NoNewline -ForegroundColor DarkGray
    Start-Sleep -Seconds 1; Write-Host "GO" -ForegroundColor Cyan
    Write-Host ""

    # Dispatch core modules
    $total   = $Script:SELECTED_MODS.Count
    $current = 0

    foreach ($mod in $Script:SELECTED_MODS) {
        $current++
        Write-ProgressBar -Current $current -Total $total -Label "[$mod]"
        Start-Sleep -Milliseconds 200

        switch ($mod) {
            'SYSBASE'  { Invoke-SysBaselineAudit }
            'USERS'    { Invoke-UserAudit }
            'ADPOL'    { Invoke-ADPolicyAudit }
            'GPOL'     { Invoke-GPOAudit }
            'NETSTAT'  { Invoke-NetworkAudit }
            'SOFTWARE' { Invoke-SoftwareAudit }
            'PERSIST'  { Invoke-PersistenceAudit }
            'FIREWALL' { Invoke-FirewallAudit }
            'EVTLOG'   { Invoke-EventLogAudit }
            'IOC'      { Invoke-IOCHunt }
        }
    }

    # Dispatch role-specific modules
    Write-Host ""
    Write-LiveStats
    Write-Status "Running role-specific modules: $($Script:SERVER_ROLES -join ', ')" INFO
    Invoke-RoleAudits

    # Final stats before writing
    Write-LiveStats
    Write-Status "Writing unified Markdown report..." INFO
    New-AuditReport

    # Done
    Show-Completion
}

# LAUNCH
Main
