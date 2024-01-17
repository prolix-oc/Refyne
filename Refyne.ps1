# https://admx.help/
# https://learn.microsoft.com/en-us/windows-hardware/test/?view=windows-11


# -----------------------------------------------------------------
# Enforce Administrator Privileges
# -----------------------------------------------------------------

if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process -verb RunAs powershell.exe -ArgumentList "-NoExit", "-ExecutionPolicy Bypass", "-Command", "$($PSCommandPath)";
    exit;
}

# -----------------------------------------------------------------
# Global Variables
# -----------------------------------------------------------------

# Error Handling
$ErrorCount = 0
$FailedCommands = @()

# Script Variables
$CurrentVersion = "0.0.9-beta"

# Acceptance Variables
$AcceptW10Risk = $false
$AcceptMemRisk = $false
$AcceptTweaksRisk = $false

# Shell Variables
$TerminalWindowWidth = 0
$TerminalWindowWidth = [int][System.Math]::Round($Host.UI.RawUI.WindowSize.Width / 2, [System.MidpointRounding]::AwayFromZero)

# System Version
$OSVersion = ((Get-CimInstance -ClassName Win32_OperatingSystem).Caption) -replace "Microsoft ", ""
$WindowsVersion = if ($OSVersion -like "*Windows 11*") { 11 } elseif ($OSVersion -like "*Windows 10*") { 10 } else { 0 }

# GPU
$AMDRegistryPath = "HKLM:\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}"
$NVIDIARegistryPath = "HKLM\System\ControlSet001\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}"
$Card = ""
$Cpu = ""

# Memory
$TotalMemory = (Get-CimInstance Win32_PhysicalMemory | Measure-Object -Property capacity -Sum).sum / 1gb

# Logging and Backup Paths
$TimeStamp = Get-Date -Format "yyyyMMdd_HHmmss"
$LogFilePath = "C:\Refyne\logfile-$($TimeStamp).txt"
$RegistryBackupPath = "C:\Refyne\resources\regedits.bak"
$BCDBackupPath = "C:\Refyne\resources\backup.bcd"

# Timer
$StopWatch = [System.Diagnostics.Stopwatch]::StartNew()

# -----------------------------------------------------------------
# Enums
# -----------------------------------------------------------------

enum Severity {
    Warn
    Fatal
    Success
    Info
}

enum Stage {
    Recovery
    BCD
    Memory
    Registry
    GPU
    Network
    Interrupts
    Tweak
    Windows10
    Final
}

# -----------------------------------------------------------------
# Helper Functions
# -----------------------------------------------------------------

Function Convert-RegistryPath {

    [CmdLetBinding()]
    Param(
        [Parameter(ValueFromPipeline = $true, Mandatory = $true)]
        [Alias("FullName")]
        [string]$path,
        $Encoding = "utf8"
    )

    Begin {
    }
    Process {
        $grabString = $path.ToString()
        switch -Wildcard ($grabString) {
            'HKEY_LOCAL_MACHINE*' { $grabString -replace ("HKEY_LOCAL_MACHINE\\", "HKLM:\") }
            'HKEY_CURRENT_USER*' { $grabString -replace ("HKEY_CURRENT_USER\\", "HKCU:\") }
            'HKEY_CLASSES_ROOT*' { $grabString -replace ("HKEY_CLASSES_ROOT\\", "HKCR:\") }
            'HKEY_CURRENT_CONFIG*' { $grabString -replace ("HKEY_CURRENT_CONFIG\\", "HKCC:\") }
            'HKEY_USERS*' { $grabString -replace ("HKEY_USERS\\", "HKU:\") }
        }
    }
}

function Get-ComputerHardwareSpecification {
    [CmdletBinding()]
    PARAM (
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0)]
        [string[]]$ComputerName = $env:COMPUTERNAME,
        [System.Management.Automation.PSCredential]$Credential = [System.Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        foreach ($Computer in $ComputerName) {
            $ErrorActionPreference = 'Stop'
            try {
                $CPU = Get-CimInstance -ClassName win32_processor
                $PhyMemory = Get-CimInstance -ClassName win32_physicalmemory
                $ECC = (Get-WMIObject -Class "Win32_PhysicalMemoryArray").MemoryErrorCorrection
                $ECCType = Switch ($ECC) {
                    0 { "Reserved" }
                    1 { "Other" }
                    2 { "Unknown" }
                    3 { "None" }
                    4 { "Parity" }
                    5 { "Single-bit ECC" }
                    6 { "Multi-bit ECC" }
                    7 { "CRC" }
                    8 { "ECC & parity" }
                    9 { "ECC & CRC" }
                    10 { "ECC, parity & CRC" }
                    11 { "Reserved" }
                    12 { "RDRAM ECC" }
                    13 { "Reserved" }
                    14 { "Reserved" }
                    15 { "Reserved" }
                }
                $colSlots = Get-WmiObject -Class "win32_PhysicalMemoryArray" -namespace "root\CIMV2" -computerName $env:COMPUTERNAME
                $TotalDIMMSlots = ($colSlots | Measure-Object -Property MemoryDevices -Sum).Sum
                $qwMemorySize = (Get-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0*" -Name HardwareInformation.qwMemorySize -ErrorAction SilentlyContinue)."HardwareInformation.qwMemorySize"
                $GpuName = (Get-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0*" -Name DriverDesc -ErrorAction SilentlyContinue)."DriverDesc"
                $script:Card = $GpuName
                $GpuDriver = (Get-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0*" -Name DriverDate -ErrorAction SilentlyContinue)."DriverDate"
                $VRAM = [math]::round($qwMemorySize / 1GB)
                $CleanCPUName = ($CPU | Select-Object -Property Name -First 1).Name -replace '\(R\)', ''
                $CleanCPUName = $CleanCPUName -replace '\(TM\)', '' 
                $CPU = $CleanCPUName
                $SysProperties = [ordered]@{
                    "Refyne Version"       = $CurrentVersion
                    "CPU"                  = $CleanCPUName
                    "Current clock speed"  = "$(($CPU | Select-Object -Property CurrentClockSpeed -First 1).CurrentClockSpeed) MHz"
                    "Max clock speed"      = "$(($CPU | Select-Object -Property MaxClockSpeed -First 1).MaxClockSpeed) MHz"
                    "Physical sockets"     = $CPU.SocketDesignation.Count
                    "Physical cores"       = [int]($CPU | Measure-Object -Property NumberofCores -Sum).Sum 
                    "Virtual cores"        = [int]($CPU | Measure-Object -Property NumberOfLogicalProcessors -Sum).Sum
                    "Hyper-Threading (HT)" = ($CPU | Measure-Object -Property NumberOfLogicalProcessors -Sum).Sum -gt ($CPU | Measure-Object -Property NumberofCores -Sum).Sum 
                    "System Memory"        = "$TotalMemory GB"
                    "Memory layout"        = "$TotalDIMMSlots-DIMM"
                    "Memory speed"         = "$(($PhyMemory)[0].Speed) MT/s"
                    "GPU"                  = $GpuName
                    "Video RAM"            = "$VRAM GB"
                    "GPU Driver Date"      = $GpuDriver
                    "ECC Memory"           = $ECCType
                }
                return $SysProperties
            }
            catch {
                $ErrorActionPreference = 'Continue'
                Write-ColorOutput -InputObject "Could not pull statistics."
            }
        }
    }
}
Function Write-ColorOutput {
    [CmdletBinding()]
    PARAM (
        [Parameter(ValueFromPipeline = $true)]
        [psobject[]]$InputObject,

        [Parameter()]
        [ValidateSet('Black', 'Blue', 'Cyan', 'DarkBlue', 'DarkCyan',
            'DarkGray', 'DarkGreen', 'DarkMagenta', 'DarkRed', 'DarkYellow',
            'Gray', 'Green', 'Magenta', 'Red', 'White', 'Yellow')]      
        [string]$ForegroundColor = [System.Console]::ForegroundColor,

        [Parameter()]
        [ValidateSet('Black', 'Blue', 'Cyan', 'DarkBlue', 'DarkCyan',
            'DarkGray', 'DarkGreen', 'DarkMagenta', 'DarkRed', 'DarkYellow',
            'Gray', 'Green', 'Magenta', 'Red', 'White', 'Yellow')]    
        [string]$BackgroundColor = [System.Console]::BackgroundColor,

        [Parameter()]
        [int]$HorizontalPad = 0,

        [Parameter()]
        [int]$VerticalPad = 0,

        [Parameter()]
        [switch]$NoEnumerate
    )

    BEGIN {
        $ResetColorCheck = [bool]([System.Console] | Get-Member -Static -MemberType Method -Name ResetColor)
        If (-Not $ResetColorCheck) {
            $DefaultConsoleForegroundColor = [System.Console]::ForegroundColor
            $DefaultConsoleBackgroundColor = [System.Console]::BackgroundColor
        }
    }

    PROCESS {
        Foreach ($Object in $InputObject) {
            [System.Console]::ForegroundColor = $ForeGroundColor
            [System.Console]::BackgroundColor = $BackGroundColor

            If ($HorizontalPad -gt 0) {
                $Object = $Object.PadLeft($Object.Length + $HorizontalPad)
                $Object = $Object.PadRight($Object.Length + $HorizontalPad)
            }
            If ($VerticalPad -gt 0) {
                $BlankLine = ' ' * $Object.Length
                1..$VerticalPad | ForEach-Object {
                    Microsoft.PowerShell.Utility\Write-Output -InputObject $BlankLine
                }
            }

            If ($PSBoundParameters.ContainsKey('NoEnumerate')) {
                Microsoft.PowerShell.Utility\Write-Output -InputObject $Object -NoEnumerate
            }
            Else {
                Microsoft.PowerShell.Utility\Write-Output -InputObject $Object
            }

            If ($VerticalPad -gt 0) {
                1..$VerticalPad | ForEach-Object {
                    Microsoft.PowerShell.Utility\Write-Output -InputObject $BlankLine
                }
            }
        }
    }

    END {
        If ($ResetColorCheck) {
            [System.Console]::ResetColor()
        }
        Else {
            [System.Console]::ForegroundColor = $DefaultConsoleForegroundColor
            [System.Console]::BackgroundColor = $DefaultConsoleBackgroundColor
        }
    }
}

function Show-Disclosure {
    [CmdletBinding()]
    PARAM (
        [Parameter(ValueFromPipeline = $true)]
        [string[]]$InputObject,
        [Severity]$severity,
        [Stage]$scope,
        [string]$prompt
    )

    BEGIN {
        switch ($severity) {
            Warn { Write-ColorOutput -InputObject "[WARNING]" -ForegroundColor Yellow -HorizontalPad ($TerminalWindowWidth - [Math]::Floor($discheader.Length))  -VerticalPad 2 }
            Fatal { Write-ColorOutput -InputObject "[FATAL ERROR]" -ForegroundColor Red -HorizontalPad ($TerminalWindowWidth - [Math]::Floor($discheader.Length)) -VerticalPad 2 }
            Success { Write-ColorOutput -InputObject "[SUCCESS]" -ForegroundColor Green -HorizontalPad ($TerminalWindowWidth - [Math]::Floor($discheader.Length)) -VerticalPad 2 }
            Info { Write-ColorOutput -InputObject "[INFO]" -ForegroundColor Gray -HorizontalPad ($TerminalWindowWidth - [Math]::Floor($discheader.Length)) -VerticalPad 2 }
            Default { Write-ColorOutput -ForegroundColor White -HorizontalPad ($TerminalWindowWidth - [Math]::Floor($discheader.Length)) -VerticalPad 2 }
        }
    }

    PROCESS {
        foreach ($line in $InputObject) {
            Write-ColorOutput -InputObject $line -ForegroundColor White
        }
    }

    END {
        [Console]::SetCursorPosition(0, $Host.UI.RawUI.WindowSize.Height - 1)
        $Choice = Read-Host "$prompt"
        Get-UserIntent -UserInput $Choice $scope
    }
}

function Show-DisclosureError {
    [CmdletBinding()]
    PARAM (
        [Parameter(Mandatory = $true)]
        [Stage]$target
    )
    
    BEGIN {
        $headertext = "$($script:ErrorCount) ISSUE(S) OCCURED"
    }

    PROCESS {
        Write-ColorOutput -InputObject $headertext -ForegroundColor Red -HorizontalPad ($TerminalWindowWidth - [Math]::Floor($discheader.Length / 2)) -VerticalPad 2
        Write-ColorOutput -InputObject "Looks like one or more commands failed to run on this system. They are as follows:`n" -ForegroundColor White -VerticalPad 3
        ForEach-Object ($FailedCommands) {
            Write-ColorOutput -InputObject "- $($_)" -ForegroundColor White
        }
        Write-ColorOutput -InputObject "`nIf this is acceptable, and you'd like to proceed: you can. However, it is likely safer to stop this script and ask for assistance in fixing the issue." -ForegroundColor White
    }

    END {
        [Console]::SetCursorPosition(0, $Host.UI.RawUI.WindowSize.Height - 1)
        $Choice = Read-Host "Type [a] to continue or [x] to exit script"
        Get-UserIntent -UserInput $Choice -Stage $target
    }
}

function Show-Prompt {
    [CmdletBinding()]
    PARAM (
        [Parameter(Mandatory = $false)]
        [string]$prompt = "Enter your choice"
    )

    BEGIN {
        [Console]::SetCursorPosition(0, $Host.UI.RawUI.WindowSize.Height - 1)
    }

    PROCESS {
        $Choice = Read-Host $prompt
        return $Choice
    }
}

function Write-StatusLine {
    [CmdletBinding()]
    PARAM (
        [Parameter(Mandatory = $true)]
        [Severity]$severity,
        [Parameter(Mandatory = $true)]
        [string]$content
    )

    PROCESS {
        switch ($severity) {
            Warn { Write-ColorOutput -InputObject "[WARNING] $content" -ForegroundColor Yellow }
            Fatal { Write-ColorOutput -InputObject "[FATAL ERROR] $content" -ForegroundColor Red }
            Success { Write-ColorOutput -InputObject "[SUCCESS] $content" -ForegroundColor Green }
            Info { Write-ColorOutput -InputObject "[INFO] $content" -ForegroundColor Gray }
            Default { Write-ColorOutput -ForegroundColor White }
        }
    }
}

function Write-Windows10Warning {
    [CmdletBinding()]
    PARAM ( ) # No parameters

    BEGIN {
        Clear-Host
        $lines = @(
            "These tweaks are not certified to run on Windows 10 at this time, but may still work.",
            "`nDESPITE `"still working`", they do have the possibility of adversely affecting your system in a negative way.",
            "If you choose to run Refyne on this Windows 10 machine regardless, you are assuming any liability for a damaged system or unbootable environment.",
            "This message isn't meant to fearmonger, but it is an inevitable reality when it comes to doing things you possibly shouldn't.",
            "`nIf you want a better chance of Refyne working properly, then I'd recommend upgrading to Windows 11 (namely the Pro for Workstations variant) and starting there.",
            "`If you choose to use the tweak anyways, and accept in the next prompt: no support will be provided. You are in uncharted territory.",
            "`nGeneral support and information for this page can be found in Prolix OCs Discord [https://discord.gg/ffW3vCpGud] under the support channel, but only provided you have done your due diligence and have tried to prevent or fix any issues as a result of your usage."
        )
    }

    PROCESS {
        Show-Disclosure $lines Warn Windows10 "Type [Y]es to agree or [N]o to close"
    }
}

function Write-LegacyWindowsWarning () {
    [CmdletBinding()]
    PARAM ( 
        [Parameter()]
        [string]$OSVersion
    ) # No parameters

    BEGIN {
        Clear-Host
    }

    PROCESS {
        Write-ColorOutput -InputObject  "You're running an unsupported Windows version! $OSVersion is not supported by Refyne!" -ForegroundColor Red -HorizontalPad $($TerminalWindowWidth) 
    }
}

function Write-RisksWarning {
    [CmdletBinding()]
    PARAM ( ) # No parameters

    BEGIN {
        $lines = @( 
            "By agreeing to the next prompt, you are doing so according to the following terms:`n",
            "- You are assuming all risks for any potential corruption or instability of your system",
            "- You are receiving no warranty from Prolix OCs, implied or otherwise, for this freely distributed script.",
            "- You understand the risks that modifying Windows can bring, and will utilize the created restore point to revert these changes.",
            "- You are not entitled to on-demand 24/7 support, and such entitlement displayed in my social channels will result in removal of your presence.",
            "- One-on-one support requested of me after running this script will be billable at your expense.",
            "`nGeneral support and information for this page can be found in Prolix OCs Discord [https://discord.gg/ffW3vCpGud] under the support channel, but only provided you have done your due diligence and have tried to prevent or fix any issues as a result of your usage."
        )

        Clear-Host
    }

    PROCESS {
        Show-Disclosure $lines Warn Tweak "Type [Y]es to agree or [N]o to close"
    }
}

function Get-UserIntent {
    PARAM (
        [Parameter(Mandatory = $true)]
        [ValidateSet('y', 'n', 'x', 'a', 'r')]
        [string]$UserInput,
        [Parameter(Mandatory = $true)]
        [Stage]$ScriptStage
    )
    BEGIN {

    }
    PROCESS {
        switch -regex ($UserInput.ToLower()) {
            'y' { 
                switch ($ScriptStage) {
                    ([Stage]::Windows10) {
                        $script:AcceptW10Risk = $true
                        $script:AcceptTweaksRisk = $true
                        Clear-Host
                        Set-EnableSystemRecovery
                    }
                    ([Stage]::Memory) {
                        $script:AcceptMemRisk = $true
                        Clear-Host
                        Set-BCDTweaksMem
                    }
                    ([Stage]::Tweak) {
                        $script:AcceptTweaksRisk = $true
                        Clear-Host
                        Set-EnableSystemRecovery
                    }
                }
            }
            'n' {
                exit
            }
            'x' {
                exit
            }
            'a' {
                switch ($stage) {
                    ([Stage]::Recovery) { Set-BCDTweaks }
                    ([Stage]::BCD) { Set-Tweaks }
                    ([Stage]::Memory) {  }
                    ([Stage]::Registry) {  }
                    ([Stage]::GPU) {  }
                    ([Stage]::Network) {  }
                    ([Stage]::Interrupts) {  }
                }
            }
            'r' {
                Restart-Computer -Force
            }        
            Default {
                Write-StatusLine Fatal "Invalid input detected, closing for your own safety."
                exit
            }
        }
    }
}

function Read-CommandStatus {
    PARAM (
        [Parameter(Mandatory = $true)]
        [string]$command,
        [Parameter(Mandatory = $true)]
        [string]$type
    )

    PROCESS {
        $ProgressPreference = 'SilentlyContinue'
        Write-LogEntry "Command run: $command"
        $null = Invoke-Expression $command 
    }

    END {
        if ($?) {
            Write-StatusLine Success "Was able to $($type) for this system!"
        }
        else {
            Write-StatusLine Fatal "Failed to perform $($type) for this system!"
            $ErrorCount += 1
            $FailedCommands += $type
        }
    }
}

# -----------------------------------------------------------------
# Main Functions
# -----------------------------------------------------------------

function Undo-SystemChanges {
    [CmdletBinding()]
    PARAM (
    )

    BEGIN {
        if (Test-Path $RegistryBackupPath) {
            Write-StatusLine Info "Found registry backup, reverting to stock settings..."
            $RegBack = (Get-Content -Path $RegistryBackupPath)
        }
        else {
            Write-StatusLine Fatal "No registry backup found, cannot revert to stock settings..."
            exit
        }
    }

    PROCESS {
        for ($i = 0; $i -lt $RegBack.Length; $i++) {
            $PathKeyArr = $(RegBack[$i]).Split(";")
            if (-NOT ($param[2] -eq 'Binary')) {
                Write-RegistryKey "$($PathKeyArr[0])" "$($PathKeyArr[1])" "$($PathKeyArr[2])" "$($PathKeyArr[3])"
                Write-StatusLine info "Reset value for $($PathKeyArr[1]) to default settings."
            }
            else {
                Write-BinaryRegistry "$($PathKeyArr[0])" "$($PathKeyArr[1])" "$($PathKeyArr[3])"
                Write-StatusLine info "Reset value for $($PathKeyArr[1]) to default settings."
            }
            $cmdstring = 'bcdedit /import "{0}"' -f $bcdfilepath
            Read-CommandStatus $cmdstring "restoring default BCD storage device."
        }
    }

    END {
        Write-EndMenuStart
    }
}
function Write-LogEntry {
    [CmdletBinding()]
    PARAM (
        [Parameter(Mandatory = $true)]
        [string]$body
    )

    BEGIN {
        $bodytimestamp = "[$([int]$StopWatch.Elapsed.TotalSeconds)s] $($body)"
    }

    PROCESS {
        Write-Output -InputObject "$bodytimestamp" >> $LogFilePath
    }
}

function Backup-BCDStorage {
    [CmdletBinding()]
    PARAM (
    )

    BEGIN {
        
    }

    PROCESS {
        if (-NOT (Test-Path $BCDBackupPath)) {
            $cmdstring = 'bcdedit /export "{0}"' -f $BCDBackupPath
            Read-CommandStatus $cmdstring "backing up BCD storage device."
        }
        else {
            Write-StatusLine Info "Already have a backup saved, moving on..."
        }
    }
}
function Backup-RegistryPathKey {
    [CmdletBinding()]
    PARAM (
        [Parameter(Mandatory = $true)]
        [string]$regpath,
        [Parameter(Mandatory = $true)]
        [string]$regkey,
        [Parameter(Mandatory = $true)]
        [string]$proptype
    )

    BEGIN {
        
    }

    PROCESS {
        if (-NOT (Test-Path $RegistryBackupPath)) {
            $Value = (Get-ItemProperty -Path "$regpath" -Name "$regkey" | Select-Object -First 1).$regkey
            Write-Output -InputObject "$($regpath);$($regkey);$($proptype);$($Value)" >> $RegistryBackupPath
            Write-StatusLine Info "Backing up default value for $regkey..."
        }
        else {
            Write-StatusLine Info "Already captured registry backup, moving on..."
        }
    }
}

function Write-RegistryKey {
    [CmdletBinding()]
    PARAM (
        [Parameter(Mandatory = $true)]
        [string]$regpath,
        [Parameter(Mandatory = $true)]
        [string]$regkey,
        [Parameter(Mandatory = $true)]
        [string]$proptype,
        [Parameter(Mandatory = $true)]
        [string]$regvalue
    )

    BEGIN {
        if (-NOT (Test-Path $regpath)) {
            Write-StatusLine Info "Registry key for $regkey does not exist, creating..."
            Write-LogEntry "Registry path created: `"$regpath`" for key `"$regkey`""
            $cmdstring = 'New-Item -LiteralPath "{0}"' -f $regpath
            Read-CommandStatus $cmdstring "create registry key for $regkey"
        }
        else {
            Backup-RegistryPathKey $regpath $regkey $proptype
        }
    }

    PROCESS {
        Write-LogEntry "Registry path modified: `"$regpath`" for key `"$regkey`" with value `"$regvalue`" using datatype $proptype"
        $cmdstring = 'New-ItemProperty -LiteralPath "{0}" -Name "{1}" -Value {2} -PropertyType {3} -Force' -f $regpath, $regkey, $regvalue, $proptype
        Read-CommandStatus $cmdstring "set $regkey"
    }
}
function Write-BinaryRegistry {
    [CmdletBinding()]
    PARAM (
        [Parameter(Mandatory = $true)]
        [string]$regpath,
        [Parameter(Mandatory = $true)]
        [string]$regkey,
        [Parameter(Mandatory = $true)]
        [byte[]]$regvalue
    )
    BEGIN {
        Backup-RegistryPathKey $regpath $regkey "Binary"
    }
    PROCESS {
        Write-LogEntry "Registry path modified: `"$regpath`" for key `"$regkey`" with value `"$regvalue`" using datatype Binary"
        New-ItemProperty -LiteralPath $regpath -Name $regkey -Value $regvalue -PropertyType Binary -Force
    }
}
function Remove-RegistryKey {  
    [CmdletBinding()]
    PARAM ( 
        [Parameter(Mandatory = $true)]
        [string]$regpath,
        [Parameter(Mandatory = $true)]
        [bool]$haskey,
        [Parameter(Mandatory = $true)]
        [string]$regkey,
        [Parameter(Mandatory = $true)]
        [string]$step
    )

    BEGIN {

    }

    PROCESS {
        if ($haskey -eq 0) {
            if (Test-Path $regpath) { Write-StatusLine Info "previously removed $step, skipping..." } else {
                Backup-RegistryPathKey $regpath "NA" "DELETE"
                Write-LogEntry "Registry path removed: $regpath"
                $cmdstring = 'Remove-Item -LiteralPath "{0}"' -f $regpath
                Read-CommandStatus $cmdstring "remove $step"
            }
        }
        else {
            if (Test-Path $regpath) { Write-StatusLine Info "previously removed $step, skipping..." } else {
                Backup-RegistryPathKey $regpath $regkey "$(Get-ItemProperty -Path `"$regpath`" -Name `"$regkey`" | Select-Object -First 1).$regkey"
                $cmdstring = 'Remove-ItemProperty -LiteralPath "{0}" -Name {1}' -f $regpath, $regkey
                Write-LogEntry "Registry path removed: `"$regpath`" with key: `"$regkey`""
                Read-CommandStatus $cmdstring "remove $regkey"
            }
        }
    }
}

function Set-EnableSystemRecovery {
    [CmdletBinding()]
    PARAM ( ) # No parameters 
    
    BEGIN {
        $script:ErrorCount = 0
        Write-StatusLine Info "Enabling System Restore and setting point creation frequency..."
    }
    
    PROCESS {
        Write-RegistryKey "HKLM:\Software\Microsoft\Windows` NT\CurrentVersion\SystemRestore" "SystemRestorePointCreationFrequency" "DWord" "0"
        $targets = ""
        $fsdrives = Get-PSDrive -PSProvider FileSystem 
        foreach($drive in $fsdrives) {
            if ($drive -eq $testarray[-1]) {
                $targets += "$($drive.Root)"
                Write-StatusLine Info "Enabled restore point creation for $($drive.Root)"
            } else {
                $targets += "'$($drive.Root)', "
                Write-StatusLine Info "Enabled restore point creation for $($drive.Root)"
            }
        }
        Read-CommandStatus "Enable-ComputerRestore -Drive $($targets)" "enabled restore for all system drives"
        Write-StatusLine Info "Making a restore point for this system..."
        Read-CommandStatus "Checkpoint-Computer -Description 'RefyneTweaks'" "created a restore point pre-Refyne"
    }

    END {
        if ($script:ErrorCount -lt 1) {
            Clear-Host
            Set-BCDTweaks
        }
        else {
            Clear-Host
            Show-DisclosureError Recovery
        }
    }
}

function Set-BCDTweaks {
    [CmdletBinding()]
    PARAM ( ) # No parameters 
    
    BEGIN {
        $script:ErrorCount = 0
        Write-StatusLine Info "back up Boot Configuration Device"
        Backup-BCDStorage
    }

    PROCESS {
        Write-StatusLine Info "Applying tweaks to Boot Configuration Device..."
        Read-CommandStatus 'bcdedit /set useplatformtick yes' "enable usage of platform ticks"
        Read-CommandStatus 'bcdedit /set disabledynamictick yes' "disable dynamic platform ticks"
        Read-CommandStatus 'bcdedit /set useplatformclock no' "disable use of platform clock-source"
        Read-CommandStatus 'bcdedit /set usefirmwarepcisettings no' "disable BIOS PCI device mapping"
        Read-CommandStatus 'bcdedit /set usephysicaldestination no' "disable physical APIC device mapping"
        Read-CommandStatus 'bcdedit /set MSI Default' "defaulte all devices to Messaged-signal Interrutps"
        Read-CommandStatus 'bcdedit /set configaccesspolicy Default' "defaulte memory mapping policy"
        Read-CommandStatus 'bcdedit /set x2apicpolicy Enable' "enable modern APIC policy"
        Read-CommandStatus 'bcdedit /set vm Yes' "disable virtualization"
        Read-CommandStatus 'bcdedit /set vsmlaunchtype Off' "disable Virtual Secure Mode" 
        Read-CommandStatus 'bcdedit /deletevalue uselegacyapicmode' "disable legacy APIC methods" 
        Read-CommandStatus 'bcdedit /set tscsyncpolicy Enhanced' "set TSC sync policy" 
        Read-CommandStatus 'bcdedit /set linearaddress57 OptOut' "disable 57-bit linear addressing" 
        Read-CommandStatus 'bcdedit /set increaseuserva 268435328' "set virtual memory allocation" 
        Read-CommandStatus 'bcdedit /set nx OptIn' "enable NX bit" 
        Read-CommandStatus 'bcdedit /set hypervisorlaunchtype off' "Disable Hypervisor" 
        Read-CommandStatus 'bcdedit /set isolatedcontext No' 'disable Hypervisor jailed memory context'
    }
    
    END {
        if ($script:ErrorCount -lt 1) {
            Clear-Host
            Set-Tweaks
        }
        else {
            Clear-Host
            Show-DisclosureError BCD
        } 
    }
}

function Set-Tweaks {
    [CmdletBinding()]
    PARAM ( ) # No parameters

    BEGIN {
        $osMemory = (Get-WmiObject -Class win32_operatingsystem | Select-Object -Property TotalVisibleMemorySize).TotalVisibleMemorySize + 1024000
    }

    PROCESS {
        Write-StatusLine Info "Initializing the component cleanup task... you have an hour to deinitalize this task before it runs."
        Read-CommandStatus "schtasks.exe /Run /TN '\Microsoft\Windows\Servicing\StartComponentCleanup'" "Started component cleanup task." # https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/clean-up-the-winsxs-folder?view=windows-11

        Write-StatusLine Info "Modifying your pagefile settings..."
        Read-CommandStatus 'Start-Process -FilePath "cmd" -ArgumentList "/c wmic computersystem where name=`"$env:COMPUTERNAME`" set AutomaticManagedPagefile=False" -Wait' "Disable automatic pagefile management"
        Read-CommandStatus 'Start-Process -FilePath "cmd" -ArgumentList "/c wmic pagefileset where name="C" "\pagefile.sys" set InitialSize=12000,MaximumSize=16000" -Wait' "Set pagefile size to 12-16GB"

        Write-StatusLine Info "Applying tweaks to registry..."
        Write-RegistryKey "HKLM:\System\ControlSet001\Control\PriorityControl" "Win32PrioritySeparation" "DWord" "42"
        Write-RegistryKey "HKLM:\System\ControlSet001\Control\PriorityControl" "EnableVirtualizationBasedSecurity" "DWord" "0"
        Write-RegistryKey "HKLM:\System\CurrentControlSet\Services\mouclass\Parameters" "TreatAbsolutePointerAsAbsolute" "DWord" "1"
        Write-RegistryKey "HKLM:\System\CurrentControlSet\Services\mouhid\Parameters" "TreatAbsoluteAsRelative" "DWord" "0"
        Write-RegistryKey "HKLM:\System\CurrentControlSet\Services\kbdclass\Parameters" "Status" "DWord" "0"
        Write-RegistryKey "HKLM:\System\CurrentControlSet\Services\lfsvc\Service\Configuration" "Status" "DWord" "0"
        Write-RegistryKey "HKLM:\System\CurrentControlSet\Services\GpuEnergyDrv" "Start" "DWord" "2"
        Write-RegistryKey "HKLM:\System\CurrentControlSet\Services\GpuEnergyDr" "Start" "DWord" "2"
        Write-RegistryKey "HKLM:\System\CurrentControlSet\Control" "SvcHostSplitThresholdInKB" "DWord" "$($osMemory)"
        Write-RegistryKey "HKLM:\System\CurrentControlSet\Control\Session Manager\kernel" "GlobalTimerResolutionRequests" "DWord" "1"
        Write-RegistryKey "HKLM:\System\CurrentControlSet\Control\Session Manager\Memory Management" "LargeSystemCache" "DWord" "1"
        Write-RegistryKey "HKLM:\System\CurrentControlSet\Control\Session Manager\Power" "HiberbootEnabled" "DWord" "0"
        Write-RegistryKey "HKLM:\System\CurrentControlSet\Control\Session Manager" "HeapDeCommitFreeBlockThreshold" "DWord" "262144"
        Write-RegistryKey "HKLM:\System\CurrentControlSet\Control\FileSystem\" "LongPathsEnabled" "DWord" "0"
        Write-RegistryKey "HKLM:\System\CurrentControlSet\Control\GraphicsDrivers\Scheduler" "EnablePreemption" "DWord" "1"
        Write-RegistryKey "HKLM:\System\CurrentControlSet\Control\GraphicsDrivers" "PlatformSupportMiracast" "DWord" "0"
        Write-RegistryKey "HKLM:\System\CurrentControlSet\Control\Power\PowerThrottling" "PowerThrottlingOff" "DWord" "00000001"
        Write-RegistryKey "HKLM:\System\CurrentControlSet\Control\CrashControl" "DisplayParameters" "DWord" "1"
        Write-RegistryKey "HKLM:\Software\Policies\Microsoft\Windows\AppCompat" "AITEnable" "DWord" "0"
        Write-RegistryKey "HKLM:\System\CurrentControlSet\Control\GraphicsDrivers" "DpiMapIommuContiguous" "DWord" "1"
        Write-RegistryKey "HKLM:\System\CurrentControlSet\Control\Session Manager\Memory Management" "DisablePagingExecutive " "DWord" "1"
        Write-RegistryKey "HKLM:\System\CurrentControlSet\Control\Session Manager\Memory Management" "LargeSystemCache " "DWord" "1"
        Write-RegistryKey "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" "Value" "String" "Deny"
        Write-RegistryKey "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\DataCollection" "AllowTelemetry" "DWord" "0"
        Write-RegistryKey "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "ContentDeliveryAllowed" "DWord" "0"
        Write-RegistryKey "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "OemPreInstalledAppsEnabled" "DWord" "0"
        Write-RegistryKey "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "PreInstalledAppsEnabled" "DWord" "0"
        Write-RegistryKey "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "PreInstalledAppsEverEnabled" "DWord" "0"
        Write-RegistryKey "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SilentInstalledAppsEnabled" "DWord" "0"
        Write-RegistryKey "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SubscribedContent-338387Enabled" "DWord" "0"
        Write-RegistryKey "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SubscribedContent-338388Enabled" "DWord" "0"
        Write-RegistryKey "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SubscribedContent-338389Enabled" "DWord" "0"
        Write-RegistryKey "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SubscribedContent-353698Enabled" "DWord" "0"
        Write-RegistryKey "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SystemPaneSuggestionsEnabled" "DWord" "0"
        Write-RegistryKey "HKLM:\Software\Policies\Microsoft\Windows\System" "EnableActivityFeed" "DWord" "0"
        Write-RegistryKey "HKLM:\Software\Policies\Microsoft\Windows\System" "PublishUserActivities" "DWord" "0"
        Write-RegistryKey "HKLM:\Software\Policies\Microsoft\Windows\System" "UploadUserActivities" "DWord" "0"
        Write-RegistryKey "HKLM:\Software\Policies\Microsoft\Windows\DataCollection" "AllowTelemetry" "DWord" "0"
        Write-RegistryKey "HKLM:\Software\Policies\Microsoft\Windows\CloudContent" "DisableSoftLanding" "DWord" "1"
        Write-RegistryKey "HKLM:\Software\Microsoft\Windows\CurrentVersion\Reliability" "TimeStampInterval " "DWord" "0"
        Write-RegistryKey "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" "SensorPermissionState" "DWord" "0"
        Write-RegistryKey "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe\PerfOptions" "CpuPriorityClass" "DWord" "4"
        Write-RegistryKey "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe\PerfOptions" "IoPriority" "DWord" "3"
        Write-RegistryKey "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" "NoLazyMode" "DWord" "1"
        Write-RegistryKey "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" "AlwaysOn" "DWord" "1"
        Write-RegistryKey "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" "SystemResponsiveness" "DWord" "0"
        Write-RegistryKey "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" "Scheduling Category" "String" "High"
        Write-RegistryKey "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" "GPU Priority" "DWord" "8"
        Write-RegistryKey "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" "Priority" "DWord" "6"
        Write-RegistryKey "HKLM:\Software\Microsoft\FTH" "Enabled" "DWord" "0"
        Write-RegistryKey "HKLM:\SOFTWARE\Policies\Microsoft\FVE" "DisableExternalDMAUnderLock" "DWord" "0"
        Write-RegistryKey "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" "EnableVirtualizationBasedSecurity" "DWord" "0"
        Write-RegistryKey "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" "HVCIMATRequired" "DWord" "0"
        Write-RegistryKey "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer" "Max Cached Icons" "String" "4096"
        Write-RegistryKey "HKLM:\Software\Microsoft\Windows\Dwm\" "OverlayTestMode" "DWord" "5"
        Write-RegistryKey "HKLM:\System\Maps" "AutoUpdateEnabled" "DWord" "0"
        Write-RegistryKey "HKCU:\Software\Microsoft\GameBar" "AllowAutoGameMode" "DWord" "1"
        Write-RegistryKey "HKCU:\Software\Microsoft\GameBar" "AutoGameModeEnabled" "DWord" "1"
        Remove-RegistryKey "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace_41040327\{e88865ea-0e1c-4e20-9aa6-edcd0212c87c}" $false "" "Removed Gallery shortcut from explorer"
        Read-CommandStatus "fsutil behavior set disable8dot3 1" "disabled 8.3 legacy file system"
        Read-CommandStatus "fsutil behavior set disabledeletenotify 0" "forced TRIM enabled"
        Read-CommandStatus "fsutil behavior set quotanotify 5400" "raised quota timer for quota violation notifications"
        Read-CommandStatus "fsutil behavior set mftzone 2" "doubled master file table size"
        Read-CommandStatus "fsutil behavior set encryptpagingfile 0" "disabled encrypted pagefile"
        Read-CommandStatus "fsutil behavior set memoryusage 2" "increased pagefile size limit"
        Read-CommandStatus "fsutil behavior set disablelastaccess 1" "disabled last accessed timestamp logging"
        Read-CommandStatus "fsutil behavior set disablecompression 1" "disabled system drive compression"
    }

    END {
        if ($script:ErrorCount -lt 1) {
            Clear-Host
            Read-GPUManual
        }
        else {
            Clear-Host
            Show-DisclosureError Registry
        }
    }
}

function Read-GPUManual {
    PARAM ()
    BEGIN {
        Write-StatusLine Info "Determining GPU optimizations to apply..."
    }

    PROCESS {
        switch -regex ($script:Card.ToLower()) {
            'nvidia' {             
                Clear-Host
                Set-RegistryTweaksNVIDIA 
            }
            'amd' {
                Clear-Host 
                Set-RegistryTweaksAMD 
            }
            Default: { 
                Clear-Host
                Set-RegistryTweaksInterrupts 
            }
        }
    }
}

function Set-RegistryTweaksNVIDIA {
    [CmdletBinding()]
    PARAM ( ) # No parameters

    BEGIN {
        Write-StatusLine Info "Applying NVIDIA-focused driver tweaks to registry..."
        $NVIDIARegistryPath = (reg query "HKLM\System\ControlSet001\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /t REG_SZ /s /e /f "NVIDIA" | findstr "HKEY" | Select-Object -First 1)
    }

    PROCESS {
        foreach ($regline in $NVIDIARegistryPath) {
            $line = Convert-RegistryPath $regline
            Write-RegistryKey "$($line)" "PowerMizerEnable" "DWord" "1"
            Write-RegistryKey "$($line)" "PowerMizerLevel" "DWord" "1"
            Write-RegistryKey "$($line)" "PowerMizerLevelAC" "DWord" "1"
            Write-RegistryKey "$($line)" "PerfLevelSrc" "DWord" "8738"
            Write-RegistryKey "$($line)" "PreferSystemMemoryContiguous" "DWord" "1"
            Write-RegistryKey "HKLM:\Software\NVIDIA Corporation\NvControlPanel2\Client" "PerfLevelSrc" "DWord" "8738"
            Write-RegistryKey "HKLM:\Software\NVIDIA Corporation\Global\FTS" "PerfLevelSrc" "DWord" "8738"
            Write-RegistryKey "HKLM:\System\CurrentControlSet\Services\nvlddmkm\Global\NVTweak" "PerfLevelSrc" "DWord" "8738"
            Write-RegistryKey "HKLM:\System\CurrentControlSet\Services\nvlddmkm\FTS" "PerfLevelSrc" "DWord" "8738"
            Write-RegistryKey "HKLM:\SYSTEM\CurrentControlSet\Services\nvlddmkm\" "PerfLevelSrc" "DWord" "8738"
            Remove-RegistryKey "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" $true "NvBackend" "remove NVIDIA backend services"
            Read-CommandStatus "schtasks /change /disable /tn `"NvTmRep_CrashReport2_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}`"" "disable crash reporting instance two"
            Read-CommandStatus "schtasks /change /disable /tn `"NvTmRep_CrashReport3_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}`"" "disable crash reporting instance three"
            Read-CommandStatus "schtasks /change /disable /tn `"NvTmRep_CrashReport1_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}`"" "disable crash reporting instance one"
            Read-CommandStatus "schtasks /change /disable /tn `"NvTmRep_CrashReport4_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}`"" "disable crash reporting instance four"
        }
    }

    END {
        if ($script:ErrorCount -lt 1) {
            Clear-Host
            Set-RegistryTweaksInterrupts
        }
        else {
            Clear-Host
            Show-DisclosureError Registry
        }
    }
}

function Set-RegistryTweaksAMD {
    [CmdletBinding()]
    PARAM ( ) # No parameters

    BEGIN {
        Write-StatusLine Info "Applying AMD-focused driver tweaks to registry..."
        $AMDRegistryPath = (reg query "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /s /v "DriverDesc" | findstr "HKEY AMD ATI Radeon" | Select-Object -First 1)        
    }

    PROCESS {
        if ($Card.Contains('Series')) { 
            Clear-Host
            Write-StatusLine info "No applicable tweaks available for pre-Navi/Crimson-based Radeon cards, moving on..."
            Start-Sleep -Seconds 2
            Set-RegistryTweaksInterrupts
        } else {
            foreach ($regline in $AMDRegistryPath) {
                $line = Convert-RegistryPath $regline
                Write-RegistryKey "$($line)" "3to2Pulldown_NA" "DWord" "0"
                Write-RegistryKey "$($line)" "Adaptive De-interlacing" "DWord" "1"
                Write-RegistryKey "$($line)" "AllowRSOverlay" "String" "false"
                Write-RegistryKey "$($line)" "AllowSkins" "String" "false"
                Write-RegistryKey "$($line)" "AllowSnapshot" "DWord" "0"
                Write-RegistryKey "$($line)" "AllowSubscription" "DWord" "0"
                Write-RegistryKey "$($line)" "AutoColorDepthReduction_NA" "DWord" "0"
                Write-RegistryKey "$($line)" "DisableSAMUPowerGating" "DWord" "1"
                Write-RegistryKey "$($line)" "DisableUVDPowerGatingDynamic" "DWord" "1"
                Write-RegistryKey "$($line)" "DisableVCEPowerGating" "DWord" "1"
                Write-RegistryKey "$($line)" "EnableAspmL0s" "DWord" "0"
                Write-RegistryKey "$($line)" "EnableAspmL1" "DWord" "0"
                Write-RegistryKey "$($line)" "EnableUlps" "DWord" "0"
                Write-RegistryKey "$($line)" "KMD_DeLagEnabled" "DWord" "1"
                Write-RegistryKey "$($line)" "EnableUlps_NA" "String" "0"
                Write-RegistryKey "$($line)" "KMD_FRTEnabled" "Dword" "0"
                Write-RegistryKey "$($line)" "DisableDMACopy" "DWord" "1"
                Write-RegistryKey "$($line)" "DisableBlockWrite" "DWord" "0"
                Write-RegistryKey "$($line)" "StutterMode" "DWord" "0"
                Write-RegistryKey "$($line)" "EnableUlps" "DWord" "0"
                Write-RegistryKey "$($line)" "PP_SclkDeepSleepDisable" "DWord" "1"
                Write-RegistryKey "$($line)" "PP_ThermalAutoThrottlingEnable" "DWord" "0"
                Write-RegistryKey "$($line)" "DisableDrmdmaPowerGating" "DWord" "1"
                Write-RegistryKey "$($line)" "KMD_EnableComputePreemption" "DWord" "0"
                Write-RegistryKey "$($line)\UMD" "Main3D_DEF" "String" "1"
                Write-BinaryRegistry "$($line)\UMD" "Main3D" ([byte[]](0x32, 0x00))
                Write-BinaryRegistry "$($line)\UMD" "ShaderCache" ([byte[]](0x32, 0x00))
                Write-BinaryRegistry "$($line)\UMD" "Tessellation_OPTION" ([byte[]](0x32, 0x00))
                Write-BinaryRegistry "$($line)\UMD" "Tessellation" ([byte[]](0x31, 0x00))
                Write-BinaryRegistry "$($line)\UMD" "VSyncControl" ([byte[]](0x30, 0x00))
                Write-BinaryRegistry "$($line)\UMD" "TFQ" ([byte[]](0x32, 0x00))
                Write-RegistryKey "$($line)\UMD" "3D_Refresh_Rate_Override_DEF" "DWord" "0"
            }
        }
        
    }

    END {
        if ($script:ErrorCount -lt 1) {
            Clear-Host
            Set-RegistryTweaksInterrupts
        }
        else {
            Clear-Host
            Show-DisclosureError Registry
        }
    }
}

function Set-RegistryTweaksInterrupts {
    [CmdletBinding()]
    PARAM ( ) # No parameters

    BEGIN {
        Write-StatusLine Info "Applying interrupt tweaks to registry..."
        $gpureg = (wmic path Win32_VideoController get PNPDeviceID | findstr /l "PCI\VEN_")
        $netreg = (wmic path Win32_NetworkAdapter get PNPDeviceID | findstr /L "VEN_")
        $usbpwr = (wmic path Win32_USBController get PNPDeviceID | findstr /l "PCI\VEN_")
        $storreg = (reg query "HKLM\SYSTEM\CurrentControlSet\Enum" /s /f "StorPort" | findstr "StorPort")
        $usbpwralt = (wmic PATH Win32_PnPEntity GET DeviceID | findstr "USB\VID_")
    }

    PROCESS {
        foreach ($line in $gpureg) {
            $lineclean = $line.Trim()
            Write-RegistryKey "HKLM:\System\CurrentControlSet\Enum\$($lineclean)\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties" "MSISupported" "DWord" "1"
            Remove-RegistryKey "HKLM:\System\CurrentControlSet\Enum\$($lineclean)\Device` Parameters\Interrupt` Management\Affinity Policy" $true "DevicePriority" "removed device priority flag"
            Write-RegistryKey "HKLM:\System\CurrentControlSet\Enum\$($lineclean)\Device Parameters\Interrupt Management\Affinity Policy" "DevicePolicy" "DWord" "4"
            Write-BinaryRegistry "HKLM:\System\CurrentControlSet\Enum\$($lineclean)\Device Parameters\Interrupt Management\Affinity Policy" "AssignmentSetOverride" ([byte[]](0xc0))

        }
        foreach ($line in $netreg) {
            $lineclean = $line.Trim()
            Write-RegistryKey "HKLM:\System\CurrentControlSet\Enum\$($lineclean)\Device` Parameters\Interrupt Management\MessageSignaledInterruptProperties" "MSISupported" "DWord" "1"
            Remove-RegistryKey "HKLM:\System\CurrentControlSet\Enum\$($lineclean)\Device` Parameters\Interrupt` Management\Affinity Policy" $true "DevicePriority" "removed device priority flag"
            Write-RegistryKey "HKLM:\System\CurrentControlSet\Enum\$($lineclean)\Device` Parameters\Interrupt Management\Affinity Policy" "DevicePolicy" "DWord" "4"
            Write-BinaryRegistry "HKLM:\System\CurrentControlSet\Enum\$($lineclean)\Device` Parameters\Interrupt Management\Affinity Policy" "AssignmentSetOverride" ([byte[]](0x30))
        }
        foreach ($line in $usbpwr) {
            $lineclean = $line.Trim()
            Write-RegistryKey "HKLM:\System\CurrentControlSet\Enum\$($lineclean)\Device` Parameters\Interrupt Management\MessageSignaledInterruptProperties" "MSISupported" "DWord" "1"
            Remove-RegistryKey "HKLM:\System\CurrentControlSet\Enum\$($lineclean)\Device` Parameters\Interrupt` Management\Affinity` Policy" $true "DevicePriority" "removed device priority flag"
            Write-RegistryKey "HKLM:\System\CurrentControlSet\Enum\$($lineclean)\Device` Parameters\Interrupt Management\Affinity Policy" "DevicePolicy" "DWord" "4"
            Write-BinaryRegistry "HKLM:\System\CurrentControlSet\Enum\$($lineclean)\Device` Parameters\Interrupt Management\Affinity Policy" "AssignmentSetOverride" ([byte[]](0xc0))
        }
        foreach ($regline in $storreg) {
            $line = Convert-RegistryPath $regline
            Write-RegistryKey "$($line)" "EnableIdlePowerManagement" "DWord" "0"
        }
        foreach ($line in $usbpwralt) {
            $lineclean = $line.Trim()
            Write-RegistryKey "HKLM:\System\CurrentControlSet\Enum\$($lineclean)\Device` Parameters" "EnhancedPowerManagementEnabled" "DWord" "0"
            Write-RegistryKey "HKLM:\System\CurrentControlSet\Enum\$($lineclean)\Device` Parameters" "AllowIdleIrpInD3" "DWord" "0"
            Write-RegistryKey "HKLM:\System\CurrentControlSet\Enum\$($lineclean)\Device` Parameters" "EnableSelectiveSuspend" "DWord" "0"
            Write-RegistryKey "HKLM:\System\CurrentControlSet\Enum\$($lineclean)\Device` Parameters" "DeviceSelectiveSuspended" "DWord" "0"
            Write-RegistryKey "HKLM:\System\CurrentControlSet\Enum\$($lineclean)\Device` Parameters" "SelectiveSuspendEnabled" "DWord" "0"
            Write-RegistryKey "HKLM:\System\CurrentControlSet\Enum\$($lineclean)\Device` Parameters" "SelectiveSuspendOn" "DWord" "0"
            Write-RegistryKey "HKLM:\System\CurrentControlSet\Enum\$($lineclean)\Device` Parameters" "D3ColdSupported" "DWord" "0"
        }
    }

    END {
        if ($script:ErrorCount -lt 1) {
            Clear-Host
            Set-NetworkTweaks
        }
        else {
            Clear-Host
            Show-DisclosureError Registry
        }
    }
}

function Set-NetworkTweaks {
    [CmdletBinding()]
    PARAM ( ) # No parameters

    BEGIN {
        Write-StatusLine Info "Applying interrupt tweaks to registry..."
        $nics4 = (reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /f "1" /d /s | findstr HKEY_)
        $nics6 = (reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces" /f "1" /d /s | findstr HKEY_)
        $adapterName = (Get-NetAdapter | Where-Object { $_.Status -eq 'Up' }).Name
    }

    PROCESS {
        foreach ($regline in $nics4) {
            $line = Convert-RegistryPath $regline
            Write-RegistryKey "$($line)" "TCPNoDelay" "DWord" "1"
            Write-RegistryKey "$($line)" "TcpAckFrequency" "DWord" "1"
            Write-RegistryKey "$($line)" "TcpDelAckTicks" "DWord" "0"
            Write-RegistryKey "$($line)" "TcpInitialRTT" "DWord" "300"
            Write-RegistryKey "$($line)" "TcpMaxDupAcks" "DWord" "2" # https://techcommunity.microsoft.com/t5/networking-blog/algorithmic-improvements-boost-tcp-performance-on-the-internet/ba-p/2347061
            Write-RegistryKey "$($line)" "SynAttackProtect" "DWord" "1" # TCP Hardening -> https://admx.help/?Category=security-compliance-toolkit&Policy=Microsoft.Policies.MSS::Pol_MSS_SynAttackProtect
            Write-RegistryKey "$($line)" "TCPMaxConnectResponseRetransmissions" "DWord" "2" # TCP Hardening -> https://admx.help/?Category=security-compliance-toolkit&Policy=Microsoft.Policies.MSS::Pol_MSS_TcpMaxConnectResponseRetransmissions
            Write-RegistryKey "$($line)" "TcpMaxDataRetransmissions" "DWord" "3" # TCP Hardening -> https://admx.help/?Category=security-compliance-toolkit&Policy=Microsoft.Policies.MSS::Pol_MSS_TcpMaxDataRetransmissions
            Write-RegistryKey "$($line)" "TcpMaxHalfOpen" "DWord" "100" # TCP Hardening
            Write-RegistryKey "$($line)" "TcpMaxHalfOpenRetried" "DWord" "80" # TCP Hardening
            Write-RegistryKey "$($line)" "TcpMaxPortsExhausted" "DWord" "5" # TCP Hardening
            Write-RegistryKey "$($line)" "EnableDeadGWDetect" "DWord" "0" # TCP Hardening -> https://admx.help/?Category=security-compliance-toolkit&Policy=Microsoft.Policies.MSS::Pol_MSS_EnableDeadGWDetect
            Write-RegistryKey "$($line)" "DisableIPSourceRouting" "DWord" "1" # TCP Hardening -> https://admx.help/?Category=security-compliance-toolkit&Policy=Microsoft.Policies.MSS::Pol_MSS_DisableIPSourceRouting
        }

        foreach ($regline in $nics6) {
            $line = Convert-RegistryPath $regline
            Write-RegistryKey "$($line)" "TCPNoDelay" "DWord" "1"
            Write-RegistryKey "$($line)" "TcpAckFrequency" "DWord" "1"
            Write-RegistryKey "$($line)" "TcpDelAckTicks" "DWord" "0"
            Write-RegistryKey "$($line)" "TcpInitialRTT" "DWord" "300"
            Write-RegistryKey "$($line)" "TcpMaxDupAcks" "DWord" "2" # https://techcommunity.microsoft.com/t5/networking-blog/algorithmic-improvements-boost-tcp-performance-on-the-internet/ba-p/2347061
            Write-RegistryKey "$($line)" "SynAttackProtect" "DWord" "1" # TCP Hardening -> https://admx.help/?Category=security-compliance-toolkit&Policy=Microsoft.Policies.MSS::Pol_MSS_SynAttackProtect
            Write-RegistryKey "$($line)" "TCPMaxConnectResponseRetransmissions" "DWord" "2" # TCP Hardening -> https://admx.help/?Category=security-compliance-toolkit&Policy=Microsoft.Policies.MSS::Pol_MSS_TcpMaxConnectResponseRetransmissions
            Write-RegistryKey "$($line)" "TcpMaxDataRetransmissions" "DWord" "3" # TCP Hardening -> https://admx.help/?Category=security-compliance-toolkit&Policy=Microsoft.Policies.MSS::Pol_MSS_TcpMaxDataRetransmissions
            Write-RegistryKey "$($line)" "TcpMaxHalfOpen" "DWord" "100" # TCP Hardening
            Write-RegistryKey "$($line)" "TcpMaxHalfOpenRetried" "DWord" "80" # TCP Hardening
            Write-RegistryKey "$($line)" "TcpMaxPortsExhausted" "DWord" "5" # TCP Hardening
            Write-RegistryKey "$($line)" "EnableDeadGWDetect" "DWord" "0" # TCP Hardening -> https://admx.help/?Category=security-compliance-toolkit&Policy=Microsoft.Policies.MSS::Pol_MSS_EnableDeadGWDetect
            Write-RegistryKey "$($line)" "DisableIPSourceRouting" "DWord" "1" # TCP Hardening -> https://admx.help/?Category=security-compliance-toolkit&Policy=Microsoft.Policies.MSS::Pol_MSS_DisableIPSourceRouting      
        }

        if ($WindowsVersion -eq 11) {
            Read-CommandStatus "netsh int tcp set supplemental Template=Internet CongestionProvider=bbr2" "Enabled BBRv2 for general traffic"
            Read-CommandStatus "netsh int tcp set supplemental Template=Datacenter CongestionProvider=bbr2" "Enabled BBRv2 for datacenter traffic"
            Read-CommandStatus "netsh int tcp set supplemental Template=Compat CongestionProvider=bbr2" "Enabled BBRv2 for compatibility traffic"
            Read-CommandStatus "netsh int tcp set supplemental Template=DatacenterCustom CongestionProvider=bbr2" "Enabled BBRv2 for custom datacenter traffic"
            Read-CommandStatus "netsh int tcp set supplemental Template=InternetCustom CongestionProvider=bbr2" "Enabled BBRv2 for custom general traffic"
        }
        else {
            Read-CommandStatus "netsh int tcp set supplemental Template=Internet CongestionProvider=NewReno" "Enabled New-Reno for general traffic"
            Read-CommandStatus "netsh int tcp set supplemental Template=Datacenter CongestionProvider=NewReno" "Enabled New-Reno for datacenter traffic"
            Read-CommandStatus "netsh int tcp set supplemental Template=Compat CongestionProvider=NewReno" "Enabled New-Reno for compatibility traffic"
            Read-CommandStatus "netsh int tcp set supplemental Template=DatacenterCustom CongestionProvider=NewReno" "Enabled New-Reno for custom datacenter traffic"
            Read-CommandStatus "netsh int tcp set supplemental Template=InternetCustom CongestionProvider=NewReno" "Enabled New-Reno for custom general traffic"
        }
        Set-DnsClientServerAddress -InterfaceAlias $adapterName -ServerAddresses ("1.1.1.1", "1.0.0.1")
        Set-DnsClientServerAddress -InterfaceAlias $adapterName -ServerAddresses ("2606:4700:4700::1111", "2606:4700:4700::1001")
    }

    END {
        if ($script:ErrorCount -lt 1) {
            $script:stopwatch.Elapsed.TotalSeconds
            Write-LogEntry "Total time for script execution: $([int]$StopWatch.Elapsed.TotalSeconds) seconds"
            Write-EndMenuStart
        }
        else {
            Clear-Host
            Show-DisclosureError Registry
        }
    }
}

function Optimize-PowerShell {
    [CmdletBinding()]
    PARAM ( ) # No parameters

    BEGIN {
        Write-StatusLine Info "Optimizing PowerShell..."
    }

    PROCESS {
        Read-CommandStatus { Start-Process -FilePath "powershell" -ArgumentList '-Command', "Invoke-RestMethod 'https://github.com/luke-beep/ps-optimize-assemblies/raw/main/optimize-assemblies.ps1' | Invoke-Expression" -Verb RunAs -Wait } "optimize PowerShell assemblies"    
    }
}

function Write-MainMenuStart {
    [CmdletBinding()]
    PARAM ( ) # No parameters

    BEGIN {
        New-Item $LogFilePath -ItemType File -Force
        if (-NOT (Test-Path $RegistryBackupPath)) {
            New-Item -Path $RegistryBackupPath -ItemType File -Force
        }
        Write-LogEntry "Starting Refyne..."
        Clear-Host
        $host.ui.RawUI.WindowTitle = "Refyne $($CurrentVersion)"
        Write-ColorOutput -InputObject "Thank you for trusting Prolix OCs with your PC! <3" -ForegroundColor Green
        Write-ColorOutput -InputObject "Join the Discord [https://discord.gg/ffW3vCpGud] for any help." -ForegroundColor Gray 
    }

    PROCESS {
        $specs = Get-ComputerHardwareSpecification | Format-Table -AutoSize -Property Name, Value
        $specs >> $LogFilePath
        $specs
        if ($WindowsVersion -eq 11) {
            Write-ColorOutput -InputObject  "You're currently running $($OSVersion)! Nice, let's get started." -ForegroundColor Green
            Write-ColorOutput -InputObject "`nOptions:`n" -ForegroundColor DarkGray
            if (Test-Path $RegistryBackupPath -PathType Leaf) { Write-ColorOutput -InputObject "[1] Run Refyne                      [5] Revert Changes" -ForegroundColor Gray } else { Write-ColorOutput -InputObject "[1] Run Refyne" -ForegroundColor Gray }
            Write-ColorOutput -InputObject "[2] Generate System Report" -ForegroundColor Gray
            Write-ColorOutput -InputObject "[3] Optimize PowerShell" -ForegroundColor Gray
            Write-ColorOutput -InputObject "[4] Activate Windows" -ForegroundColor Gray

            $Choice = Show-Prompt "Enter number choice here"
            if ($Choice -eq "1") {
                Clear-Host
                Write-RisksWarning
            }
            elseif ($Choice -eq "2") {
                Clear-Host
                Write-LogEntry "Running a system report via Luke-Beep's System Report Generator."
                Read-CommandStatus { Start-Process -FilePath "powershell" -ArgumentList '-Command', "Invoke-RestMethod 'https://raw.githubusercontent.com/luke-beep/GSR/main/GenerateSystemReport.ps1' | Invoke-Expression" -Verb RunAs -Wait } "generate a system report"            
            }
            elseif ($Choice -eq "3") {
                Clear-Host
                Optimize-PowerShell
            }
            elseif ($Choice -eq "4") {
                Clear-Host
                Read-CommandStatus "irm https://massgrave.dev/get | iex" "activate Windows using MAS (https://github.com/massgravel/Microsoft-Activation-Scripts) <3"
            }
            elseif ($Choice -eq "5") {
                Clear-Host
                Undo-SystemChanges
                Start-Sleep -Seconds 2
                exit
            }
        }
        elseif ($WindowsVersion -eq 10) {
            Clear-Host
            Write-Windows10Warning
        }
        else {
            Clear-Host
            Write-LegacyWindowsWarning $OSVersion
        }
    }
}

function Write-EndMenuStart {
    [CmdletBinding()]
    PARAM ( ) # No parameters
    BEGIN {
        $lines = @(
            "You're all wrapped up! The latest and greatest in optimizations has been applied to your machine. Keep in mind of the following things before you go:`n",
            "- Keep an eye on your performance and notate if anything has degraded in usability or overall performance.",
            "- Taking note on any issues and submitting feedback is crucial to the development of this script.",
            "- Utilizing Process Lasso is highly recommended to keep your system running at peak performance.",
            "- This script is free to use and distribute, but support is helpful!",
            "- You can drop by my [https://twitch.tv/prolix_gg] or come say hello on [https://tiktok.com/@prolix_oc].",
            "- You are not entitled to on-demand 24/7 support, and such entitlement displayed in my social channels will result in removal of your presence.",
            "- One-on-one support requested of me after running this script will be billable at your expense.",
            "`nGeneral support, updates and information for this tweak can be found in Prolix OC's Discord [https://discord.gg/ffW3vCpGud], hope to see you there!"
        )
        Clear-Host
    }
    PROCESS {
        Show-Disclosure $lines Success Final "Type [R] to reboot now or [N] to exit without restart [NOT RECOMMENDED]"
    } 

}

Write-MainMenuStart
