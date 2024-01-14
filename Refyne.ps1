# -----------------------------------------------------------------
# Enforce Administrator Privileges
# -----------------------------------------------------------------

if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process -verb RunAs wt.exe -ArgumentList "PowerShell.exe", "-NoExit", "-ExecutionPolicy Bypass", "-Command", "$($PSCommandPath)";
    exit;
}

# -----------------------------------------------------------------
# Global Variables
# -----------------------------------------------------------------

[int]$ErrorCount = 0
$FailedCommands = @()

[bool]$AcceptW10Risk = $false
[bool]$AcceptMemRisk = $false
[bool]$AcceptTweaksRisk = $false
[int]$TerminalWindowWidth = 0
$TerminalWindowWidth = [int][System.Math]::Round($Host.UI.RawUI.WindowSize.Width / 2, [System.MidpointRounding]::AwayFromZero)

[string]$OSVersion = ((Get-CimInstance -ClassName Win32_OperatingSystem).Caption) -replace "Microsoft ", ""

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
    Windows10
    Memory
    Tweak
    Recovery
    Bcd
    Registry
}

# -----------------------------------------------------------------
# Helper Functions
# -----------------------------------------------------------------

function New-ResilientCimSession {
    [CmdletBinding()]
    PARAM (
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,
        [ValidateSet('Wsman', 'Dcom')]
        [string]$Protocol = 'Wsman',
        [System.Management.Automation.PSCredential]$Credential = [System.Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $ErrorActionPreference = 'Stop'
        Write-ColorOutput -InputObject "Warming up hardware statistics, sit tight for a few seconds :)" 
    }

    PROCESS {
        function Test-CimSession {
            PARAM (
                [string]$ComputerName,
                [string]$Protocol
            )
            $CimSessionOption = New-CimSessionOption -Protocol $Protocol
            try {
                Write-Verbose -Message  "Attempting to establish CimSession to $ComputerName using protocol $Protocol."
                if ($null -eq $Credential.Username) {
                    $CimSession = New-CimSession -ComputerName $ComputerName -SessionOption $CimSessionOption
                    Write-Verbose -Message "Successfully established CimSession $($CimSession.Name) to $ComputerName using protocol $Protocol."
                    $CimSession
                }
                else {
                    $CimSession = New-CimSession -ComputerName $ComputerName -SessionOption $CimSessionOption -Credential $Credential
                    Write-Verbose -Message "Successfully established CimSession $($CimSession.Name) to $ComputerName using protocol $Protocol."
                    $CimSession
                }
            }
            catch {
                Write-Verbose -Message  "Unable to establish CimSession to $ComputerName using protocol $Protocol."
            }
        }
        
        $CimSession = Test-CimSession -ComputerName $ComputerName -Protocol $Protocol
        if ($CimSession) {
            $CimSession
        }
        else {
            if ($Protocol -eq 'Wsman') {
                $Protocol = 'Dcom'
            }
            else {
                $Protocol = 'Wsman'
            }
            $CimSession = Test-CimSession -ComputerName $ComputerName -Protocol $Protocol
            if ($CimSession) {
                $CimSession
            }
            else {
                Write-Error -Message "Unable to establish CimSession with any protocols."
            }
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
                $GpuDriver = (Get-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0*" -Name DriverDate -ErrorAction SilentlyContinue)."DriverDate"
                $VRAM = [math]::round($qwMemorySize / 1GB)
                $SysProperties = [ordered]@{
                    "CPU"                               = ($CPU | Select-Object -Property Name -First 1).Name
                    "Current clock speed"               = ($CPU | Select-Object -Property CurrentClockSpeed -First 1).CurrentClockSpeed
                    "Max clock speed"                   = ($CPU | Select-Object -Property MaxClockSpeed -First 1).MaxClockSpeed
                    "Number of physical sockets"        = $CPU.SocketDesignation.Count
                    "Number of physical cores"          = ($CPU | Measure-Object -Property NumberofCores -Sum).Sum 
                    "Number of virtual cores"           = ($CPU | Measure-Object -Property NumberOfLogicalProcessors -Sum).Sum
                    "Hyper-Threading (HT) Status"       = ($CPU | Measure-Object -Property NumberOfLogicalProcessors -Sum).Sum -gt ($CPU | Measure-Object -Property NumberofCores -Sum).Sum 
                    "Total amount of memory (GB)"       = ($PhyMemory | Measure-Object -Property FormFactor -Sum).Sum
                    "Memory layout"                     = ($PhyMemory | Measure-Object -Property FormFactor -Sum).Count
                    "Memory speed (Mbps/MT/s)"          = ($PhyMemory)[0].Speed
                    "VRAM"                              = $VRAM
                    "GPU"                               = $GpuName
                    "Graphics Driver Installation Date" = $GpuDriver
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
        [Console]::SetCursorPosition(0, $Host.UI.RawUI.BufferSize.Height - 1)
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
        [Console]::SetCursorPosition(0, $Host.UI.RawUI.BufferSize.Height - 1)
        $Choice = Read-Host "Type [a] to continue or [x] to exit script"
        Get-UserIntent $Choice $target
    }
}

function Show-Prompt () {
    [CmdletBinding()]
    PARAM (
        [Parameter(Mandatory = $false)]
        [string]$prompt = "Enter your choice"
    )

    BEGIN {
        [Console]::SetCursorPosition(0, $Host.UI.RawUI.BufferSize.Height - 1)
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
            Warn { Write-ColorOutput -InputObject "[WARNING]" -ForegroundColor Yellow -HorizontalPad ($TerminalWindowWidth - [Math]::Floor($discheader.Length / 2))  -VerticalPad 2 }
            Fatal { Write-ColorOutput -InputObject "[FATAL ERROR]" -ForegroundColor Red -HorizontalPad ($TerminalWindowWidth - [Math]::Floor($discheader.Length / 2)) -VerticalPad 2 }
            Success { Write-ColorOutput -InputObject "[SUCCESS]" -ForegroundColor Green -HorizontalPad ($TerminalWindowWidth - [Math]::Floor($discheader.Length / 2)) -VerticalPad 2 }
            Info { Write-ColorOutput -InputObject "[INFO]" -ForegroundColor Gray -HorizontalPad ($TerminalWindowWidth - [Math]::Floor($discheader.Length / 2)) -VerticalPad 2 }
            Default { Write-ColorOutput -ForegroundColor White -HorizontalPad ($TerminalWindowWidth - [Math]::Floor($discheader.Length / 2)) -VerticalPad 2 }
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
            "General support and information for this page can be found in Prolix OCs Discord [https://discord.gg/ffW3vCpGud], but only provided you have done your due diligence and have tried to prevent or fix any issues as a result of your usage."
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
        [string]$input,
        [Parameter(Mandatory = $true)]
        [Stage]$stage
    )

    PROCESS {
        switch -regex ($input.ToLower()) {
            'y' { 
                switch ($stage) {
                    Windows10 {
                        $script:AcceptW10Risk = $true
                        $script:AcceptTweaksRisk = $true
                        Clear-Host
                        Set-EnableSystemRecovery
                    }
                    Memory {
                        $script:AcceptMemRisk = $true
                        Clear-Host
                        Set-BCDTweaksMem                
                    }
                    Tweak {
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
                    Recovery {
                        Set-BCDTweaks
                    }
                    Bcd {
                        Write-MemTweakWarning             
                    }
                    Memory {
                        Set-RegistryTweaks              
                    }
                    Registry {
                        # Do nothing
                    }
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
        Invoke-Expression $command
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
            Read-CommandStatus $cmdstring "create registry key for $regkey" "reg"
        }
        else {
            Write-StatusLine Info "Registry key for $regkey already exists, skipping..."
        }
    }

    PROCESS {
        $cmdstring = 'New-ItemProperty -Path ''{0}'' -Name ''{1}'' -Value ''{2}'' -PropertyType {3} -Force' -f $regpath, $regkey, $regvalue, $proptype
        Read-CommandStatus $cmdstring "set $regkey" "reg"
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
            if (-NOT (Test-Path $regpath)) { Write-StatusLine Info "Seems we've already $step, skipping..." } else {
                $cmdstring = 'Remove-Item -LiteralPath "{0}"' -f $regpath
                Read-CommandStatus $cmdstring "remove $step" "reg" 
            }
        }
        else {
            if (-NOT (Test-Path $regpath)) { Write-StatusLine Info "Seems we've already $step, skipping..." } else {
                $cmdstring = 'Remove-ItemProperty -LiteralPath {0} -Name {1}' -f $regpath, $regkey
                Read-CommandStatus $cmdstring "remove $regkey" "reg"
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
        Read-CommandStatus "Enable-ComputerRestore -Drive 'C:\', 'D:\', 'E:\', 'F:\', 'G:\'" "Pre-Optimization Restore Point." "recovery"
    }

    END {
        if ($script:ErrorCount -lt 1) {
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
        Read-CommandStatus 'bcdedit /set useplatformtick yes' "enable usage of platform ticks" "Boot Configuration Data Store optimizations"
        Read-CommandStatus 'bcdedit /set disabledynamictick yes' "disable dynamic platform ticks" "Boot Configuration Data Store optimizations"
        Read-CommandStatus 'bcdedit /set useplatformclock no' "disable use of platform clock-source" "Boot Configuration Data Store optimizations"
        Read-CommandStatus 'bcdedit /set usefirmwarepcisettings no' "disable BIOS PCI device mapping" "Boot Configuration Data Store optimizations"
        Read-CommandStatus 'bcdedit /set usephysicaldestination no' "disable physical APIC device mapping" "Boot Configuration Data Store optimizations"
        Read-CommandStatus 'bcdedit /set MSI Default' "defaulte all devices to Messaged-signal Interrutps" "Boot Configuration Data Store optimizations"
        Read-CommandStatus 'bcdedit /set configaccesspolicy Default' "defaulte memory mapping policy" "Boot Configuration Data Store optimizations"
        Read-CommandStatus 'bcdedit /set x2apicpolicy Enable' "enable modern APIC policy" "Boot Configuration Data Store optimizations"
        Read-CommandStatus 'bcdedit /set vm Yes' "disable virtualization" "Boot Configuration Data Store optimizations"
        Read-CommandStatus 'bcdedit /set vsmlaunchtype Off' "disable Virtual Secure Mode" "Boot Configuration Data Store optimizations"
        Read-CommandStatus 'bcdedit /deletevalue uselegacyapicmode' "disable legacy APIC methods" "Boot Configuration Data Store optimizations"
        Read-CommandStatus 'bcdedit /set tscsyncpolicy Enhanced' "set TSC sync policy" "Boot Configuration Data Store optimizations"
        Read-CommandStatus 'bcdedit /set linearaddress57 OptOut' "disable 57-bit linear addressing" "Boot Configuration Data Store optimizations"
        Read-CommandStatus 'bcdedit /set increaseuserva 268435328' "set virtual memory allocation" "Boot Configuration Data Store optimizations"
        Read-CommandStatus 'bcdedit /set nx OptIn' "enable NX bit" "Boot Configuration Data Store optimizations"
        Read-CommandStatus 'bcdedit /set hypervisorlaunchtype off' "Disable Hypervisor" "Boot Configuration Data Store optimizations"
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
        Read-CommandStatus 'bcdedit /set firstmegabytepolicy UseAll' "Set command address buffer range" "Boot Configuration Data Store"
        Read-CommandStatus 'bcdedit /set avoidlowmemory 0x8000000' "set uncontiguous memory address range" "Boot Configuration Data Store"
        Read-CommandStatus 'bcdedit /set nolowmem Yes' "disable low-memory condition checks" "Boot Configuration Data Store"
        Read-CommandStatus 'bcdedit /set allowedinmemorysettings 0x0' "disable SGX in-memory context" "Boot Configuration Data Store"
        Read-CommandStatus 'bcdedit /set isolatedcontext No' 'disable kernel memory checks (mitigations)' "Boot Configuration Data Store"
    }

    END {
        if ($script:ErrorCount -lt 1) {
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
        Write-RegistryKey "HKLM:\System\ControlSet001\Control\DeviceGuard" "MouseDataQueueSize" "DWord" "20"
        Write-RegistryKey "HKLM:\System\CurrentControlSet\Services\mouclass\Parameters" "TreatAbsolutePointerAsAbsolute" "DWord" "1"
        Write-RegistryKey "HKLM:\System\CurrentControlSet\Services\mouhid\Parameters" "TreatAbsoluteAsRelative" "DWord" "0"
        Write-RegistryKey "HKLM:\System\CurrentControlSet\Services\mouhid\Parameters" "KeyboardDataQueueSize" "DWord" "20"
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
        Write-ColorOutput -InputObject "Thank you for trusting Prolix OCs with your PC! <3" -ForegroundColor Green -BackgroundColor Black
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
        $lines = @(
            "You're all wrapped up! The latest and greatest in optimizations has been applied to your machine. Keep in mind of the following things before you go:",
            "- Keep an eye on your performance and notate if anything has degraded in usability or overall performance.",
            "- Taking note on any issues and submitting feedback is crucial to the development of this script.",
            "- This script is free to use and distribute, but support is helpful!",
            "- You can drop by my [https://twitch.tv/prolix_gg] or come say hello on [https://tiktok.com/@prolix_oc].",
            "- You are not entitled to on-demand 24/7 support, and such entitlement displayed in my social channels will result in removal of your presence.",
            "- One-on-one support requested of me after running this script will be billable at your expense.",
            "General support, updates and information for this tweak can be found in Prolix OC's Discord [https://discord.gg/ffW3vCpGud], hope to see you there!"
        )

        Clear-Host
    }

    PROCESS {
        Show-Disclosure -InputObject $lines -Severity Success -Scope "END" -Prompt "Type [R] to reboot now or [N] to exit without restart [NOT RECOMMENDED]"
    }
}

Write-MainMenuStart