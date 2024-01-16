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

[int]$ErrorCount = 0
$FailedCommands = @()
$CurrentVersion = "0.0.5-beta"
[bool]$AcceptW10Risk = $false
[bool]$AcceptMemRisk = $false
[bool]$AcceptTweaksRisk = $false
[int]$TerminalWindowWidth = 0
$TerminalWindowWidth = [int][System.Math]::Round($Host.UI.RawUI.WindowSize.Width / 2, [System.MidpointRounding]::AwayFromZero)
$Card = ""
[string]$OSVersion = ((Get-CimInstance -ClassName Win32_OperatingSystem).Caption) -replace "Microsoft ", ""
$AmdRegPath = "HKLM:\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}"
$NvRegPath = "HKLM\System\ControlSet001\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}"
# -----------------------------------------------------------------
# Enums
# -----------------------------------------------------------------

enum Severity {
    Warn
    Fatal
    Success
    Info
}

# enum Stage {
#     Windows10
#     Memory
#     Tweak
#     Recovery
#     Bcd
#     Registry
# }

# -----------------------------------------------------------------
# Helper Functions
# -----------------------------------------------------------------

Function Convert-RegistryPath {

    [CmdLetBinding()]
    Param(
        [Parameter(ValueFromPipeline=$true, Mandatory=$true)]
        [Alias("FullName")]
        [string]$path,
        $Encoding = "utf8"
    )

    Begin {
    }
    Process {
        $grabString = $path.ToString()
        switch -Wildcard ($grabString) {
        'HKEY_LOCAL_MACHINE*' { $grabString -replace("HKEY_LOCAL_MACHINE\\", "HKLM:\") }
        'HKEY_CURRENT_USER*' { $grabString -replace("HKEY_CURRENT_USER\\", "HKCU:\") }
        'HKEY_CLASSES_ROOT*' { $grabString -replace("HKEY_CLASSES_ROOT\\", "HKCR:\") }
        'HKEY_CURRENT_CONFIG*' { $grabString -replace("HKEY_CURRENT_CONFIG\\", "HKCC:\") }
        'HKEY_USERS*' { $grabString -replace("HKEY_USERS\\", "HKU:\") }
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
                $qwMemorySize = (Get-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0*" -Name HardwareInformation.qwMemorySize -ErrorAction SilentlyContinue)."HardwareInformation.qwMemorySize"
                $GpuName = (Get-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0*" -Name DriverDesc -ErrorAction SilentlyContinue)."DriverDesc"
                $script:Card = $GpuName
                $GpuDriver = (Get-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0*" -Name DriverDate -ErrorAction SilentlyContinue)."DriverDate"
                $VRAM = [math]::round($qwMemorySize / 1GB)
                $CleanCPUName = ($CPU | Select-Object -Property Name -First 1).Name -replace '\(R\)',''
                $CleanCPUName = $CleanCPUName -replace '\(TM\)',''
                $SysProperties = [ordered]@{
                    "CPU"                               = $CleanCPUName
                    "Current clock speed"               = "$(($CPU | Select-Object -Property CurrentClockSpeed -First 1).CurrentClockSpeed) MHz"
                    "Max clock speed"                   = "$(($CPU | Select-Object -Property MaxClockSpeed -First 1).MaxClockSpeed) MHz"
                    "Physical sockets"        = $CPU.SocketDesignation.Count
                    "Physical cores"          = [int]($CPU | Measure-Object -Property NumberofCores -Sum).Sum 
                    "Virtual cores"           = [int]($CPU | Measure-Object -Property NumberOfLogicalProcessors -Sum).Sum
                    "Hyper-Threading (HT)"              = ($CPU | Measure-Object -Property NumberOfLogicalProcessors -Sum).Sum -gt ($CPU | Measure-Object -Property NumberofCores -Sum).Sum 
                    "System Memory"                     = "$(($PhyMemory | Measure-Object -Property FormFactor -Sum).Sum) GB"
                    "Memory layout"                     = "$(($PhyMemory | Measure-Object -Property FormFactor -Sum).Count)-DIMM"
                    "Memory speed"                      = "$(($PhyMemory)[0].Speed) MT/s"
                    "GPU"                               = $GpuName
                    "Video RAM"                         = "$VRAM GB"
                    "GPU Driver Date"                   = $GpuDriver
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
        [string]$scope,
        [string]$prompt
    )

    BEGIN {
        switch ($severity) {
            Warn { Write-ColorOutput -InputObject "[WARNING]" -ForegroundColor Yellow -HorizontalPad ($TerminalWindowWidth - [Math]::Floor($discheader.Length / 2))  -VerticalPad 2 }
            Fatal { Write-ColorOutput -InputObject "[FATAL ERROR]" -ForegroundColor Red -HorizontalPad ($TerminalWindowWidth - [Math]::Floor($discheader.Length / 2)) -VerticalPad 2 }
            Success { Write-ColorOutput -InputObject "[SUCCESS]" -ForegroundColor Green -HorizontalPad ($TerminalWindowWidth - [Math]::Floor($discheader.Length / 2)) -VerticalPad 2 }
            Info { Write-ColorOutput -InputObject "[INFO]" -ForegroundColor Gray -HorizontalPad ($TerminalWindowWidth - [Math]::Floor($discheader.Length / 2)) -VerticalPad 2 }
            Default { Write-ColorOutput -ForegroundColor White -HorizontalPad ($TerminalWindowWidth - [Math]::Floor($discheader.Length / 2)) -VerticalPad 2 }
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
        Get-UserIntent $Choice $scope
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

function Show-Prompt () {
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
            Warn { Write-ColorOutput -InputObject "[WARNING] $content" -ForegroundColor Yellow}
            Fatal { Write-ColorOutput -InputObject "[FATAL ERROR] $content" -ForegroundColor Red}
            Success { Write-ColorOutput -InputObject "[SUCCESS] $content" -ForegroundColor Green}
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
    }

    PROCESS {
        Write-ColorOutput -InputObject  "`nYou're currently running $($OSVersion). Be aware of a few things:`n"-ForegroundColor Yellow -HorizontalPad ($TerminalWindowWidth)
        Write-ColorOutput -InputObject  "- $($OSVersion) is not officially supported by my script, but the optimizations have a chance to still work.`n- By choosing to run this script anyways, you assume all risks to YOUR system's integrity.`n- By agreeing to the prompt, you are rescinding your chance for support by not running the proper script designed for your OS.`n- If you need a script designed for Windows 10, join Prolix's Discord [https://discord.gg/ffW3vCpGud] and keep an eye out for the release." -ForegroundColor Gray
        $Choice = Show-Prompt "`nType [Y/y]es to accept and proceed, or [N/n]o to exit"
    }

    END {
        Get-UserIntent $Choice "W10" 
    }
}

function Write-LegacyWindowsWarning () {
    [CmdletBinding()]
    PARAM ( ) # No parameters

    BEGIN {
        Clear-Host
    }

    PROCESS {
        Write-ColorOutput -InputObject  "You're running an unsupported Windows version!" -ForegroundColor Red -HorizontalPad $($TerminalWindowWidth) 
    }
}

function Write-MemTweakWarning {
    [CmdletBinding()]
    PARAM ( ) # No parameters

    BEGIN {
        Clear-Host
        $lines = @(
            "There is a tweak I include in this pack that can adversely affect systems with memory stability issues!",
            "`nIf you have ever had the following:",
            "- Bluescreens involving DPC_WATCHDOG_TIMEOUT, IRQL_NOT_LESS_OR_EQUAL, or WHEA_UNCORRECTABLE_ERROR",
            "- Issues presenting as slow cold boots, multiple restarts when attempting to boot, or `"Overclocking failed`" messages.",
            "- Frequent file system corruption or even loss of data.",
            "`n`nI cannot advise you put this particular tweak on your system if you are unsure your RAM overclock or XMP/DOCP profile is `"NASA Stable`", or if any of the mentioned issues occur with your PC.",
            "`nIf you choose to use the tweak anyways, and accept in the next prompt: no support will be provided until we can verify your RAM is stable, whether that requires de-tuning your RAM OC, changing XMP/DOCP profiles, or reverting to stock configuration.",
            "`nGeneral support and information for this page can be found in Prolix OCs Discord [https://discord.gg/ffW3vCpGud], but only provided you have done your due diligence and have tried to prevent or fix any issues as a result of your usage."
        )
    }

    PROCESS {
        Show-Disclosure $lines Warn "MEM" "Type [Y]es to agree or [N]o to close"
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
            "`nGeneral support and information for this page can be found in Prolix OCs Discord [https://discord.gg/ffW3vCpGud], but only provided you have done your due diligence and have tried to prevent or fix any issues as a result of your usage."
        )

        Clear-Host
    }

    PROCESS {
        Show-Disclosure $lines Warn "TWEAK" "Type [Y]es to agree or [N]o to close"
    }
}

function Get-UserIntent {
    PARAM (
        [Parameter(Mandatory = $true)]
        [ValidateSet('y', 'n', 'x', 'a', 'r')]
        [string]$UserInput,
        [Parameter(Mandatory = $true)]
        [string]$Stage
    )
    BEGIN {

    }
    PROCESS {
        switch -regex ($UserInput.ToLower()) {
            'y' { 
                switch ($stage) {
                    'W10' {
                        $script:AcceptW10Risk = $true
                        $script:AcceptTweaksRisk = $true
                        Clear-Host
                        Set-EnableSystemRecovery
                    }
                    'MEM' {
                        $script:AcceptMemRisk = $true
                        Clear-Host
                        Set-BCDTweaksMem                
                    }
                    'TWEAK' {
                        $script:AcceptTweaksRisk = $true
                        Clear-Host
                        Set-EnableSystemRecovery                
                    }
                    Default: {}
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
                    "rec" { Set-BCDTweaks }
                    "bcd" { Write-MemTweakWarning }
                    "mem" { Set-RegistryTweaks }
                    "reg" {  }
                    "gpu"{  }
                    "net" {  }
                    "inter" {  }
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
            $cmdstring = 'New-Item -Path ''{0}''' -f $regpath
            Read-CommandStatus $cmdstring "create registry key for $regkey"
        }
    }

    PROCESS {
        $cmdstring = 'New-ItemProperty -Path ''{0}'' -Name ''{1}'' -Value {2} -PropertyType {3} -Force' -f $regpath, $regkey, $regvalue, $proptype
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
    }
    PROCESS {
        $cmdstring = New-ItemProperty -LiteralPath $regpath -Name $regkey -Value $regvalue -PropertyType Binary -Force
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

    PROCESS {
        if ($haskey -eq 0) {
            if (Test-Path $regpath) { Write-StatusLine Info "Seems we've already $step, skipping..." } else {
                $cmdstring = 'Remove-Item -LiteralPath "{0}"' -f $regpath
                Read-CommandStatus $cmdstring "remove $step"
            }
        }
        else {
            if (Test-Path $regpath) { Write-StatusLine Info "Seems we've already $step, skipping..." } else {
                $cmdstring = 'Remove-ItemProperty -LiteralPath {0} -Name {1}' -f $regpath, $regkey
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
        Read-CommandStatus "Enable-ComputerRestore -Drive 'C:\', 'D:\', 'E:\', 'F:\', 'G:\'" "Pre-Optimization Restore Point."
        Write-StatusLine "info" "Making a restore point for this system..."
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
        Write-StatusLine Info "Applying tweaks to Boot Configuration Device..."
    }

    PROCESS {
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
    }
    
    END {
        if ($script:ErrorCount -lt 1) {
            Clear-Host
            Write-MemTweakWarning
        }
        else {
            Clear-Host
            Show-DisclosureError Bcd
        } 
    }
}

function Set-BCDTweaksMem {
    [CmdletBinding()]
    PARAM ( ) # No parameters

    BEGIN {
        Write-StatusLine Info "Applying tweaks to Boot Configuration Device involving memory..."
    }

    PROCESS {
        Read-CommandStatus 'bcdedit /set firstmegabytepolicy UseAll' "Set command address buffer range"
        Read-CommandStatus 'bcdedit /set avoidlowmemory 0x8000000' "set uncontiguous memory address range"
        Read-CommandStatus 'bcdedit /set nolowmem Yes' "disable low-memory condition checks"
        Read-CommandStatus 'bcdedit /set allowedinmemorysettings 0x0' "disable SGX in-memory context"
        Read-CommandStatus 'bcdedit /set isolatedcontext No' 'disable kernel memory checks (mitigations)'
    }

    END {
        if ($script:ErrorCount -lt 1) {
            Clear-Host
            Set-RegistryTweaks
        }
        else {
            Clear-Host
            Show-DisclosureError Memory
        }
    }
}

function Set-RegistryTweaks {
    [CmdletBinding()]
    PARAM ( ) # No parameters

    BEGIN {
        Write-StatusLine Info "Applying tweaks to registry..."
        $osMemory = (Get-WmiObject -Class win32_operatingsystem | Select-Object -Property TotalVisibleMemorySize).TotalVisibleMemorySize + 1024000
    }

    PROCESS {
        Write-RegistryKey "HKLM:\System\ControlSet001\Control\PriorityControl" "Win32PrioritySeparation" "DWord" "42"
        Write-RegistryKey "HKLM:\System\ControlSet001\Control\PriorityControl" "EnableVirtualizationBasedSecurity" "DWord" "0"
        Write-RegistryKey "HKLM:\System\CurrentControlSet\Services\mouclass\Parameters" "TreatAbsolutePointerAsAbsolute" "DWord" "1"
        Write-RegistryKey "HKLM:\System\CurrentControlSet\Services\mouhid\Parameters" "TreatAbsoluteAsRelative" "DWord" "0"
        Write-RegistryKey "HKLM:\System\CurrentControlSet\Services\kbdclass\Parameters" "Status" "DWord" "0"
        Write-RegistryKey "HKLM:\System\CurrentControlSet\Services\lfsvc\Service\Configuration" "Status" "DWord" "0"
        Write-RegistryKey "HKLM:\System\CurrentControlSet\Services\GpuEnergyDrv" "Start" "DWord" "2"
        Write-RegistryKey "HKLM:\System\CurrentControlSet\Services\GpuEnergyDr" "Start" "DWord" "2"
        Write-RegistryKey "HKLM:\System\CurrentControlSet\Control" "SvcHostSplitThresholdInKB" "DWord" "$($osMemory)"
        Write-RegistryKey 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel' "GlobalTimerResolutionRequests" "DWord" "1"
        Write-RegistryKey 'HKLM:\System\CurrentControlSet\Control\Session Manager\Memory Management' "LargeSystemCache" "DWord" "1"
        Write-RegistryKey 'HKLM:\System\CurrentControlSet\Control\Session Manager\Power' "HiberbootEnabled" "DWord" "0"
        Write-RegistryKey 'HKLM:\System\CurrentControlSet\Control\Session Manager' "HeapDeCommitFreeBlockThreshold" "DWord" "262144"
        Write-RegistryKey "HKLM:\System\CurrentControlSet\Control\FileSystem" "LongPathsEnabled" "DWord" "0"
        Write-RegistryKey "HKLM:\System\CurrentControlSet\Control\GraphicsDrivers\Scheduler" "EnablePreemption" "DWord" "1"
        Write-RegistryKey "HKLM:\System\CurrentControlSet\Control\GraphicsDrivers" "PlatFORmSupportMiracast" "DWord" "0"
        Write-RegistryKey "HKLM:\System\CurrentControlSet\Control\Power\PowerThrottling" "PowerThrottlingOff" "DWord" "00000001"
        Write-RegistryKey "HKLM:\System\CurrentControlSet\Control\CrashControl" "DisplayParameters" "DWord" "1"
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
        Write-RegistryKey "HKLM:\Software\Microsoft\Windows` NT\CurrentVersion\Sensor\Overrides\{{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" "SensorPermissionState" "DWord" "0"
        Write-RegistryKey "HKLM:\Software\Microsoft\Windows` NT\CurrentVersion\Image` File` Execution` Options\csrss.exe\PerfOptions" "CpuPriorityClass" "DWord" "4"
        Write-RegistryKey "HKLM:\Software\Microsoft\Windows` NT\CurrentVersion\Image` File` Execution` Options\csrss.exe\PerfOptions" "IoPriority" "DWord" "3"
        Write-RegistryKey "HKLM:\Software\Microsoft\Windows` NT\CurrentVersion\Multimedia\SystemProfile" "NoLazyMode" "DWord" "1"
        Write-RegistryKey "HKLM:\Software\Microsoft\Windows` NT\CurrentVersion\Multimedia\SystemProfile" "AlwaysOn" "DWord" "1"
        Write-RegistryKey "HKLM:\Software\Microsoft\Windows` NT\CurrentVersion\Multimedia\SystemProfile" "SystemResponsiveness" "DWord" "0"
        Write-RegistryKey "HKLM:\Software\Microsoft\Windows` NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" "Scheduling Category" "String" "High"
        Write-RegistryKey "HKLM:\Software\Microsoft\Windows` NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" "GPU Priority" "DWord" "8"
        Write-RegistryKey "HKLM:\Software\Microsoft\Windows` NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" "Priority" "DWord" "6"
        Write-RegistryKey "HKLM:\Software\Microsoft\FTH" "Enabled" "DWord" "0"
        Write-RegistryKey "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer" "Max` Cached` Icons" "String" "4096"
        Write-RegistryKey "HKLM:\Software\Microsoft\Windows\Dwm" "OverlayTestMode" "DWord" "5"
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
            Read-GPUManu
        }
        else {
            Clear-Host
            Show-DisclosureError Registry
        }
    }
}

function Read-GPUManu {
    PARAM ()
    BEGIN {
        Write-StatusLine Info "Determining GPU optimizations to apply..."
    }

    PROCESS {
        switch -regex ($script:Card.ToLower()) {
            'nvidia' {             
                Set-RegistryTweaksNvidia }
            'amd' { 
                Set-RegistryTweaksAmd }
            Default: { Set-RegistryTweaksInterrupts }
        }
    }
}

#to be filled by Luke
function Set-RegistryTweaksNvidia {
    [CmdletBinding()]
    PARAM ( ) # No parameters

    BEGIN {
        Write-StatusLine Info "Applying NVIDIA-focused driver tweaks to registry..."
        $NvRegPath = (reg query "HKLM\System\ControlSet001\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /t REG_SZ /s /e /f "NVIDIA" | findstr "HKEY" | Select-Object -First 1)
    }

    PROCESS {
        foreach($regline in $NvRegPath) {
            $line = Convert-RegistryPath $regline
            Write-RegistryKey "$($line)" "PowerMizerEnable" "DWord" "1"
            Write-RegistryKey "$($line)" "PowerMizerLevel" "DWord" "1"
            Write-RegistryKey "$($line)" "PowerMizerLevelAC" "DWord" "1"
            Write-RegistryKey "$($line)" "PerfLevelSrc" "DWord" "8738"
            Write-RegistryKey "HKLM:\Software\NVIDIA` Corporation\NvControlPanel2\Client" "PerfLevelSrc" "DWord" "8738"
            Write-RegistryKey "HKLM:\Software\NVIDIA` Corporation\Global\FTS" "PerfLevelSrc" "DWord" "8738"
            Write-RegistryKey "HKLM:\Software\NVIDIA` Corporation\Global\FTS" "PerfLevelSrc" "DWord" "8738"
            Write-RegistryKey "HKLM:\Software\NVIDIA` Corporation\Global\FTS" "PerfLevelSrc" "DWord" "8738"
            Write-RegistryKey "HKLM:\System\CurrentControlSet\Services\nvlddmkm\Global\NVTweak" "PerfLevelSrc" "DWord" "8738"
            Write-RegistryKey "HKLM:\System\CurrentControlSet\Services\nvlddmkm\FTS" "PerfLevelSrc" "DWord" "8738"
            Write-RegistryKey "HKLM:\SYSTEM\CurrentControlSet\Services\nvlddmkm" "PerfLevelSrc" "DWord" "8738"
            Write-RegistryKey "HKLM:\SYSTEM\CurrentControlSet\Services\nvlddmkm" "PerfLevelSrc" "DWord" "8738"
            Write-RegistryKey "HKLM:\SYSTEM\CurrentControlSet\Services\nvlddmkm" "PerfLevelSrc" "DWord" "8738"
            Write-RegistryKey "HKLM:\SYSTEM\CurrentControlSet\Services\nvlddmkm" "PerfLevelSrc" "DWord" "8738"
            Write-RegistryKey "HKLM:\SYSTEM\CurrentControlSet\Services\nvlddmkm" "PerfLevelSrc" "DWord" "8738"
            Remove-RegistryKey "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" $true "NvBackend" "remove NVIDIA backend services"
            Read-CommandStatus "schtasks /change /disable /tn `"NvTmRep_CrashReport1_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}`"" "disable crash reporting instance one"
            Read-CommandStatus "schtasks /change /disable /tn `"NvTmRep_CrashReport2_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}`"" "disable crash reporting instance two"
            Read-CommandStatus "schtasks /change /disable /tn `"NvTmRep_CrashReport3_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}`"" "disable crash reporting instance three"
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

function Set-RegistryTweaksAmd {
    [CmdletBinding()]
    PARAM ( ) # No parameters

    BEGIN {
        Write-StatusLine Info "Applying AMD-focused driver tweaks to registry..."
        $AmdRegPath = (reg query "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /s /v "DriverDesc" | findstr "HKEY AMD ATI Radeon" | Select-Object -First 1)        
    }

    PROCESS {
        foreach ($regline in $AmdRegPath) {
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
            Write-BinaryRegistry "$($line)\UMD" "Main3D" ([byte[]](0x32,0x00))
            Write-BinaryRegistry "$($line)\UMD" "ShaderCache" ([byte[]](0x32,0x00))
            Write-BinaryRegistry "$($line)\UMD" "Tessellation_OPTION" ([byte[]](0x32,0x00))
            Write-BinaryRegistry "$($line)\UMD" "Tessellation" ([byte[]](0x31,0x00))
            Write-BinaryRegistry "$($line)\UMD" "VSyncControl" ([byte[]](0x30,0x00))
            Write-BinaryRegistry "$($line)\UMD" "TFQ" ([byte[]](0x32,0x00))
            Write-RegistryKey "$($line)\UMD" "3D_Refresh_Rate_Override_DEF" "DWord" "0"
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
            Write-RegistryKey "HKLM:\System\CurrentControlSet\Enum\$($lineclean)\Device` Parameters\Interrupt` Management\MessageSignaledInterruptProperties" "MSISupported" "DWord" "1"
            Remove-RegistryKey "HKLM:\System\CurrentControlSet\Enum\$($lineclean)\Device` Parameters\Interrupt` Management\Affinity Policy" $true "DevicePriority" "removed device priority flag"
            Write-RegistryKey "HKLM:\System\CurrentControlSet\Enum\$($lineclean)\Device` Parameters\Interrupt` Management\Affinity Policy" "DevicePolicy" "DWord" "4"
            Write-BinaryRegistry "HKLM:\System\CurrentControlSet\Enum\$($lineclean)\Device` Parameters\Interrupt` Management\Affinity Policy" "AssignmentSetOverride" ([byte[]](0xc0))

        }
        foreach ($line in $netreg) {
            $lineclean = $line.Trim()
            Write-RegistryKey "HKLM:\System\CurrentControlSet\Enum\$($lineclean)\Device` Parameters\Interrupt` Management\MessageSignaledInterruptProperties" "MSISupported" "DWord" "1"
            Remove-RegistryKey "HKLM:\System\CurrentControlSet\Enum\$($lineclean)\Device` Parameters\Interrupt` Management\Affinity` Policy" $true "DevicePriority" "removed device priority flag"
            Write-RegistryKey "HKLM:\System\CurrentControlSet\Enum\$($lineclean)\Device` Parameters\Interrupt` Management\Affinity` Policy" "DevicePolicy" "DWord" "4"
            Write-BinaryRegistry "HKLM:\System\CurrentControlSet\Enum\$($lineclean)\Device` Parameters\Interrupt` Management\Affinity` Policy" "AssignmentSetOverride" ([byte[]](0x30))
        }
        foreach ($line in $usbpwr) {
            $lineclean = $line.Trim()
            Write-RegistryKey "HKLM:\System\CurrentControlSet\Enum\$($lineclean)\Device` Parameters\Interrupt` Management\MessageSignaledInterruptProperties" "MSISupported" "DWord" "1"
            Remove-RegistryKey "HKLM:\System\CurrentControlSet\Enum\$($lineclean)\Device` Parameters\Interrupt` Management\Affinity` Policy" $true "DevicePriority" "removed device priority flag"
            Write-RegistryKey "HKLM:\System\CurrentControlSet\Enum\$($lineclean)\Device` Parameters\Interrupt` Management\Affinity` Policy" "DevicePolicy" "DWord" "4"
            Write-BinaryRegistry "HKLM:\System\CurrentControlSet\Enum\$($lineclean)\Device` Parameters\Interrupt` Management\Affinity` Policy" "AssignmentSetOverride" ([byte[]](0xc0))
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
        $nics = (reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /f "1" /d /s | findstr HKEY_)
    }

    PROCESS {
        foreach ($regline in $nics) {
            $line = Convert-RegistryPath $regline
            Write-RegistryKey "$($line)" "TCPNoDelay" "DWord" "1"
            Write-RegistryKey "$($line)" "TcpAckFrequency" "DWord" "1"
            Write-RegistryKey "$($line)" "TcpDelAckTicks" "DWord" "0"
        }
        Read-CommandStatus "netsh int tcp set supplemental Template=Internet CongestionProvider=bbr2" "enabled BBRv2 for general traffic"
        Read-CommandStatus "netsh int tcp set supplemental Template=Datacenter CongestionProvider=bbr2" "enabled BBRv2 for datacenter traffic"
        Read-CommandStatus "netsh int tcp set supplemental Template=Compat CongestionProvider=bbr2" "enabled BBRv2 for compatibility traffic"
        Read-CommandStatus "netsh int tcp set supplemental Template=DatacenterCustom CongestionProvider=bbr2" "enabled BBRv2 for custom datacenter traffic"
        Read-CommandStatus "netsh int tcp set supplemental Template=InternetCustom CongestionProvider=bbr2" "enabled BBRv2 for custom general traffic"

    }

    END {
        if ($script:ErrorCount -lt 1) {
            Write-EndMenuStart
        }
        else {
            Clear-Host
            Show-DisclosureError Registry
        }
    }
}

function Write-MainMenuStart {
    [CmdletBinding()]
    PARAM ( ) # No parameters

    BEGIN {
        Clear-Host
        Write-ColorOutput -InputObject "Thank you for trusting Prolix OCs with your PC! <3" -ForegroundColor Green
        Write-ColorOutput -InputObject "Join the Discord [https://discord.gg/ffW3vCpGud] for any help.`n" -ForegroundColor Gray 
    }

    PROCESS {
        Get-ComputerHardwareSpecification | Format-Table -AutoSize -Property Name, Value

        if ($OSVersion -like "*Windows 11*") {
            Write-ColorOutput -InputObject  "You're currently running $($OSVersion)! Nice, let's get started." -ForegroundColor Green
            Write-ColorOutput -InputObject "`nOptions:" -ForegroundColor DarkGray
            Write-ColorOutput -InputObject "`n[1] Run Prolix Tweaks`n" -ForegroundColor Gray

            $Choice = Show-Prompt "Enter number choice here"
            if ($Choice -eq "1") {
                Clear-Host
                Write-RisksWarning
            }
        }
        elseif ($OSVersion -like "*Windows 10*") {
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
        $host.ui.RawUI.WindowTitle = "Refyne $($CurrentVersion)"
        $lines = @(
            "You're all wrapped up! The latest and greatest in optimizations has been applied to your machine. Keep in mind of the following things before you go:`n",
            "- Keep an eye on your performance and notate if anything has degraded in usability or overall performance.",
            "- Taking note on any issues and submitting feedback is crucial to the development of this script.",
            "- This script is free to use and distribute, but support is helpful!",
            "- You can drop by my [https://twitch.tv/prolix_gg] or come say hello on [https://tiktok.com/@prolix_oc].",
            "- You are not entitled to on-demand 24/7 support, and such entitlement displayed in my social channels will result in removal of your presence.",
            "- One-on-one support requested of me after running this script will be billable at your expense.",
            "`nGeneral support, updates and information for this tweak can be found in Prolix OC's Discord [https://discord.gg/ffW3vCpGud], hope to see you there!"
        )
        Clear-Host
    }
    PROCESS {
        Show-Disclosure -InputObject $lines -Severity Success -Scope "END" -Prompt "Type [R] to reboot now or [N] to exit without restart [NOT RECOMMENDED]"
    }
}
Write-MainMenuStart