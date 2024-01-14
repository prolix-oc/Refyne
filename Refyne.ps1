# Ensure we are in a privileged shell first, before carrying on, with a preference to Windows Terminal.

if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process -verb RunAs wt.exe -ArgumentList "PowerShell.exe", "-NoExit", "-ExecutionPolicy Bypass", "-Command", "$($PSCommandPath)";
    exit;
}

# Helper functions

function New-ResilientCimSession {
    param (
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,
        [ValidateSet('Wsman', 'Dcom')]
        [string]$Protocol = 'Wsman',
        [System.Management.Automation.PSCredential]$Credential = [System.Management.Automation.PSCredential]::Empty
    )

    begin {
        $ErrorActionPreference = 'Stop'
        Write-ColorOutput -InputObject "Warming up hardware statistics, sit tight for a few seconds :)" 
        function Test-CimSession {
            param (
                [string]$ComputerName,
                [string]$Protocol
            )
            $CimSessionOption = New-CimSessionOption -Protocol $Protocol
            try {
                Write-Verbose -Message  "Attempting to establish CimSession to $ComputerName using protocol $Protocol."
                if ($Credential.Username -eq $null) {
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
    }
    process {

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
    end {}
}

function Get-ComputerHardwareSpecification {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0)]
        [string[]]$ComputerName = $env:COMPUTERNAME,
        [System.Management.Automation.PSCredential]$Credential = [System.Management.Automation.PSCredential]::Empty
    )
    begin {        
    }
    process {
        foreach ($Computer in $ComputerName) {
            $ErrorActionPreference = 'Stop'
            # Establishing CIM Session
            try {
                $CPU = Get-CimInstance -ClassName win32_processor
                $PhyMemory = Get-CimInstance -ClassName win32_physicalmemory
                $qwMemorySize = (Get-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0*" -Name HardwareInformation.qwMemorySize -ErrorAction SilentlyContinue)."HardwareInformation.qwMemorySize"
                $GpuName = (Get-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0*" -Name DriverDesc -ErrorAction SilentlyContinue)."DriverDesc"
                $GpuDriver = (Get-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0*" -Name DriverDate -ErrorAction SilentlyContinue)."DriverDate"
                $VRAM = [math]::round($qwMemorySize/1GB)
                # Building object properties
                $SysProperties = [ordered]@{
                    CpuName           = ($CPU | Select-Object -Property Name -First 1).Name
                    CurrentClockSpeed = ($CPU | Select-Object -Property CurrentClockSpeed -First 1).CurrentClockSpeed
                    MaxClockSpeed     = ($CPU | Select-Object -Property MaxClockSpeed -First 1).MaxClockSpeed
                    NumberofSockets   = $CPU.SocketDesignation.Count
                    NumberofCores     = ($CPU | Measure-Object -Property NumberofCores -Sum).Sum 
                    LogicalProcessors = ($CPU | Measure-Object -Property NumberOfLogicalProcessors -Sum).Sum
                    HyperThreading    = ($CPU | Measure-Object -Property NumberOfLogicalProcessors -Sum).Sum -gt ($CPU | Measure-Object -Property NumberofCores -Sum).Sum 
                    TotalMem          = ($PhyMemory | Measure-Object -Property FormFactor -Sum).Sum
                    MemTopo           = ($PhyMemory | Measure-Object -Property FormFactor -Sum).Count
                    Speed             = ($PhyMemory)[0].Speed
                    DgpuVram          = $VRAM
                    DgpuName          = $GpuName
                    DgpuDate          = $GpuDriver
                }
                return $SysProperties
                Remove-CimSession
            }
            catch {
                $ErrorActionPreference = 'Continue'
                Write-ColorOutput -InputObject "error Could not pull statistics for local PC."
                Start-Sleep -Milliseconds 1000
            }
        }
    }
    end {
    }
}
Function Write-ColorOutput {

    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline=$true)]
        [psobject[]]$InputObject,

        [Parameter()]
        [ValidateSet('Black','Blue','Cyan','DarkBlue','DarkCyan',
                    'DarkGray','DarkGreen','DarkMagenta','DarkRed','DarkYellow',
                    'Gray','Green','Magenta','Red','White','Yellow')]      
        [string]$ForegroundColor = [System.Console]::ForegroundColor,

        [Parameter()]
        [ValidateSet('Black','Blue','Cyan','DarkBlue','DarkCyan',
                    'DarkGray','DarkGreen','DarkMagenta','DarkRed','DarkYellow',
                    'Gray','Green','Magenta','Red','White','Yellow')]    
        [string]$BackgroundColor = [System.Console]::BackgroundColor,

        [Parameter()]
        [int]$HorizontalPad = 0,

        [Parameter()]
        [int]$VerticalPad = 0,

        [Parameter()]
        [switch]$NoEnumerate
    )

    Begin {
        $ResetColorCheck = [bool]([System.Console] | Get-Member -Static -MemberType Method -Name ResetColor)
        If (-Not $ResetColorCheck) {
            $DefaultConsoleForegroundColor = [System.Console]::ForegroundColor
            $DefaultConsoleBackgroundColor = [System.Console]::BackgroundColor
        }
    }

    Process {
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
            } Else {
                Microsoft.PowerShell.Utility\Write-Output -InputObject $Object
            }

            If ($VerticalPad -gt 0) {
                1..$VerticalPad | ForEach-Object {
                    Microsoft.PowerShell.Utility\Write-Output -InputObject $BlankLine
                }
            }
        }
    }

    End {
        If ($ResetColorCheck) {
            [System.Console]::ResetColor()
        } Else {
            [System.Console]::ForegroundColor = $DefaultConsoleForegroundColor
            [System.Console]::BackgroundColor = $DefaultConsoleBackgroundColor
        }
    }
}

function New-Hyperlink {
    [Alias("Url")]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string]$Uri,
        [ValidateNotNullOrEmpty()]
        [Parameter(ValueFromRemainingArguments)]
        [String]$InputObject = $Uri
    )
    $8 = [char]27 + "]8;;"
    "$8{0}`a{1}$8`a" -f $Uri, $InputObject
}

function Show-Disclosure ($discheader, $discbody, $disclist, $discsupp, $severity, $scope, $prompttext) {
    switch ($severity) {
        "warn" { Write-ColorOutput -InputObject "$($discheader)" -ForegroundColor Yellow -HorizontalPad ($TerminalWindowWidth - [Math]::Floor($discheader.Length / 2))  -VerticalPad 2}
        "fatal" { Write-ColorOutput -InputObject "$($discheader)" -ForegroundColor Red -HorizontalPad ($TerminalWindowWidth - [Math]::Floor($discheader.Length / 2)) -VerticalPad 2}
        "success" { Write-ColorOutput -InputObject "$($discheader)" -ForegroundColor Green -HorizontalPad ($TerminalWindowWidth - [Math]::Floor($discheader.Length / 2)) -VerticalPad 2}
        Default { Write-ColorOutput -InputObject "$($discheader)" -ForegroundColor White -HorizontalPad ($TerminalWindowWidth - [Math]::Floor($discheader.Length / 2)) -VerticalPad 2}
    }
    Write-ColorOutput -InputObject "$($discbody)" -ForegroundColor White
    Write-ColorOutput -InputObject "$($disclist)" -ForegroundColor White
    Write-ColorOutput -InputObject "$($discsupp)" -ForegroundColor White
    [Console]::SetCursorPosition(0,$Host.UI.RawUI.BufferSize.Height - 1)
    $Choice = Read-Host "$prompttext"
    Get-UserIntent $Choice $scope
}

$[int]$ErrorCount = 0
$FailedCommands = @()

function Show-DisclosureError ($target) {
    $headertext = "!!! $($script:ErrorCount) ISSUE(S) OCCURED !!!"
    Write-ColorOutput -InputObject $headertext -ForegroundColor Red -HorizontalPad ($TerminalWindowWidth - [Math]::Floor($discheader.Length / 2)) -VerticalPad 2
    Write-ColorOutput -InputObject "Looks like one or more commands failed to run on this system. They are as follows:`n" -ForegroundColor White -VerticalPad 3
    ForEach-Object ($FailedCommands) {
        Write-ColorOutput -InputObject "- $($_)" -ForegroundColor White
    }
    Write-ColorOutput -InputObject "`nIf this is acceptable, and you'd like to proceed: you can. However, it is likely safer to stop this script and ask for assistance in fixing the issue." -ForegroundColor White
    [Console]::SetCursorPosition(0,$Host.UI.RawUI.BufferSize.Height - 1)
    $Choice = Read-Host "Type [a] to continue or [x] to exit script"
    Get-UserIntent $Choice $target
}

function Show-Prompt () {
    [Console]::SetCursorPosition(0,$Host.UI.RawUI.BufferSize.Height - 1)
    $Choice = Read-Host "Enter an option number"
    return $Choice
}

function Write-StatusLine ($stat, $content) {
    switch -regex ($stat) {
        "error" { Write-ColorOutput -InputObject  "[ERR] $($content)" -ForegroundColor Red }
        'warning' { Write-ColorOutput -InputObject  "[WARN] $($content)" -ForegroundColor Yellow }
        'success' { Write-ColorOutput -InputObject  "[OK] $($content)" -ForegroundColor Green }
        'info' { Write-ColorOutput -InputObject  "[INFO] $($content)" -ForegroundColor White }
        Default {}
    } 
}

#Data parser functions

[bool]$AcceptW10Risk = $false
[bool]$AcceptMemRisk = $false
[bool]$AcceptTweaksRisk = $false
[int]$TerminalWindowWidth = 0
$TerminalWindowWidth = [int][System.Math]::Round($Host.UI.RawUI.WindowSize.Width / 2,[System.MidpointRounding]::AwayFromZero)


function Write-Windows10Warning {
    Clear-Host
    Write-ColorOutput -InputObject  "`n!!! You're currently running $($OSVersion). Be aware of a few things: !!!`n"-ForegroundColor Yellow -HorizontalPad ($TerminalWindowWidth)
    Write-ColorOutput -InputObject  "- $($OSVersion) is not officially supported by my script, but the optimizations have a chance to still work.`n- By choosing to run this script anyways, you assume all risks to YOUR system's integrity.`n- By agreeing to the prompt, you are rescinding your chance for support by not running the proper script designed for your OS.`n- If you need a script designed for Windows 10, join Prolix's Discord [$(New-Hyperlink 'https://discord.gg/ffW3vCpGud')] and keep an eye out for the release." -ForegroundColor Gray
    $Choice = Show-Prompt "`nType [Y/y]es to accept and proceed, or [N/n]o to exit"
    Get-UserIntent $Choice "W10" 
}

function Write-LegacyWindowsWarning ($osVer) {
    Clear-Host
    Write-ColorOutput -InputObject  "You're running an unsupported Windows version!" -ForegroundColor Red -HorizontalPad $($TerminalWindowWidth)    
}

function Write-MemTweakWarning {
    Show-Disclosure "!!! READ THIS FIRST !!!" "There is a tweak I include in this pack that can adversely affect systems with memory stability issues!" "`nIf you have ever had the following:`n- Bluescreens involving DPC_WATCHDOG_TIMEOUT, IRQL_NOT_LESS_OR_EQUAL, or WHEA_UNCORRECTABLE_ERROR`n- Issues presenting as slow cold boots, multiple restarts when attempting to boot, or `"Overclocking failed`" messages.`n- Frequent file system corruption or even loss of data.`n`nI cannot advise you put this particular tweak on your system if you are unsure your RAM overclock or XMP/DOCP profile is `"NASA Stable`", or if any of the mentioned issues occur with your PC.`n`nIf you choose to use the tweak anyways, and accept in the next prompt: no support will be provided until we can verify your RAM is stable, whether that requires de-tuning your RAM OC, changing XMP/DOCP profiles, or reverting to stock configuration." "`nGeneral support and information for this page can be found in Prolix OCs Discord [$(New-Hyperlink 'https://discord.gg/ffW3vCpGud')], but only provided you have done your due diligence and have tried to prevent or fix any issues as a result of your usage." "warn" "MEM" "Type [Y]es to agree or [N]o to close"
}

function Write-RisksWarning {
    Show-Disclosure "!!! ONE MORE THING !!!" "By agreeing to the next prompt, you are doing so to the following terms:" "`n- You are assuming all risks for any potential corruption or instability of your system`n- You are receiving no warranty from Prolix OCs, implied or otherwise, for this freely distributed script.`n- You understand the risks that modifying Windows can bring, and will utilize the created restore point to revert these changes.`n- You are not entitled to on-demand 24/7 support, and such entitlement displayed in my social channels will result in removal of your presence.`n- One-on-one support requested of me after running this script will be billable at your expense." "`nGeneral support and information for this page can be found in Prolix OCs Discord [$(New-Hyperlink 'https://discord.gg/ffW3vCpGud')], but only provided you have done your due diligence and have tried to prevent or fix any issues as a result of your usage." "warn" "TWEAK" "Type [Y]es to agree or [N]o to close"
}

function Get-UserIntent($userInp, $stage) {
    switch -regex ($userInp) {
        'y' { 
            if ($stage -eq "W10") {
                $script:AcceptW10Risk=$true
                $script:AcceptTweaksRisk=$true
                Clear-Host
                Set-EnableSystemRecovery
            }
            if ($stage -eq "MEM") {
                $script:AcceptMemRisk=$true
                Clear-Host
                Set-BCDTweaksMem
            }
            if ($stage -eq "TWEAK") {
                $script:AcceptTweaksRisk=$true
                Clear-Host
                Set-EnableSystemRecovery
            }
        }
        'n' {
            exit
        }
        'x' {
            exit
        }
        'a' {
            if ($stage -eq "recovery") {
                Set-BCDTweaks
            }
            if ($stage -eq "bcd") {
                Write-MemTweakWarning
            }
            if ($stage -eq "mem") {
                Set-RegistryTweaks
            }
            if ($stage -eq "reg") {
            }
        }
        'r' {
            Restart-Computer -Force
        }        
        Default {
            Write-StatusLine "error" "Invalid input detected, closing for your own safety."
            exit
        }
    }
}

function Read-CommandStatus ($command, $type, $section) {
    $cmd = (Invoke-Expression $command)
    if($?)
    {
        Write-StatusLine "success" "Was able to $($type) for this system!"
    }
    else
    {
        Write-StatusLine "error" "Failed to $($type) for this system!"
        $ErrorCount += 1
        $FailedCommands += $type
    }
}

#Runner functions

function Write-RegistryKey($regpath, $regkey, $proptype, $regvalue) {
    if (-NOT (Test-Path $regpath)) {
        Write-StatusLine "info" "Registry key for $regkey does not exist, creating..."
        $cmdstring = 'New-Item -Path ''{0}''' -f $regpath
        Read-CommandStatus $cmdstring "create registry key for $regkey" "reg"
    }
    $cmdstring = 'New-ItemProperty -Path ''{0}'' -Name ''{1}'' -Value ''{2}'' -PropertyType {3} -Force' -f $regpath, $regkey, $regvalue, $proptype
    Read-CommandStatus $cmdstring "set $regkey" "reg"
}
function Remove-RegistryKey($regpath, [bool]$haskey, $regkey, $step) {  
    if ($haskey -eq 0) {
        if (-NOT (Test-Path $regpath)) { Write-StatusLine "info" "Seems we've already $step, skipping..." } else {
            $cmdstring = 'Remove-Item -LiteralPath "{0}"' -f $regpath
            Read-CommandStatus $cmdstring "remove $step" "reg" 
        }
    } else {
        if (-NOT (Test-Path $regpath)) { Write-StatusLine "info" "Seems we've already $step, skipping..." } else {
            $cmdstring = 'Remove-ItemProperty -LiteralPath {0} -Name {1}' -f $regpath, $regkey
            Read-CommandStatus $cmdstring "remove $regkey" "reg"
        }
    }
}

function Set-EnableSystemRecovery {
    $script:ErrorCount = 0
    Write-StatusLine "info" "Enabling System Restore and setting point creation frequency..."
    Write-RegistryKey "HKLM:\Software\Microsoft\Windows` NT\CurrentVersion\SystemRestore" "SystemRestorePointCreationFrequency" "DWord" "0"
    Read-CommandStatus "Enable-ComputerRestore -Drive 'C:\', 'D:\', 'E:\', 'F:\', 'G:\'" "enable System Restore point creation" "recovery"
    # Read-CommandStatus "Checkpoint-Computer -Description 'Prolix Optimizations'" "create a good restore point" "recovery"

    if ($script:ErrorCount -lt 1) {
        Set-BCDTweaks
    } else {
        Clear-Host
        Show-DisclosureError "recovery"
    }
}

function Set-BCDTweaks {
    $script:ErrorCount = 0
    Write-StatusLine "info" "Applying tweaks to Boot Configuration Device..."
    Read-CommandStatus 'bcdedit /set useplatformtick yes' "enable usage of platform ticks" "bcd"
    Read-CommandStatus 'bcdedit /set disabledynamictick yes' "disable dynamic platform ticks" "bcd"
    Read-CommandStatus 'bcdedit /set useplatformclock no' "disable use of platform clock-source" "bcd"
    Read-CommandStatus 'bcdedit /set usefirmwarepcisettings no' "disable BIOS PCI device mapping" "bcd"
    Read-CommandStatus 'bcdedit /set usephysicaldestination no' "disable physical APIC device mapping" "bcd"
    Read-CommandStatus 'bcdedit /set MSI Default' "defaulte all devices to Messaged-signal Interrutps" "bcd"
    Read-CommandStatus 'bcdedit /set configaccesspolicy Default' "defaulte memory mapping policy" "bcd"
    Read-CommandStatus 'bcdedit /set x2apicpolicy Enable' "enable modern APIC policy" "bcd"
    Read-CommandStatus 'bcdedit /set vm Yes' "disable virtualization" "bcd"
    Read-CommandStatus 'bcdedit /set vsmlaunchtype Off' "disable Virtual Secure Mode" "bcd"
    Read-CommandStatus 'bcdedit /deletevalue uselegacyapicmode' "disable legacy APIC methods" "bcd"
    Read-CommandStatus 'bcdedit /set tscsyncpolicy Enhanced' "set TSC sync policy" "bcd"
    Read-CommandStatus 'bcdedit /set linearaddress57 OptOut' "disable 57-bit linear addressing"
    Read-CommandStatus 'bcdedit /set increaseuserva 268435328' "set virtual memory allocation"

    if ($script:ErrorCount -lt 1) {
        Start-Sleep 1
        Clear-Host
        Write-MemTweakWarning
    } else {
        Clear-Host
        Show-DisclosureError "bcd"
    }
}

function Set-BCDTweaksMem {
    Write-StatusLine "info" "Applying tweaks to Boot Configuration Device involving memory..."
    Read-CommandStatus 'bcdedit /set firstmegabytepolicy UseAll' "set command address buffer range" "bcd"
    Read-CommandStatus 'bcdedit /set avoidlowmemory 0x8000000' "set uncontiguous memory address range" "bcd"
    Read-CommandStatus 'bcdedit /set nolowmem Yes' "disable low-memory condition checks" "bcd"
    Read-CommandStatus 'bcdedit /set allowedinmemorysettings 0x0' "disable SGX in-memory context"
    Read-CommandStatus 'bcdedit /set isolatedcontext No' 'disable kernel memory checks (mitigations)'
    if ($script:ErrorCount -lt 1) {
        Start-Sleep 1
        Set-RegistryTweaks
    } else {
        Clear-Host
        Show-DisclosureError "mem"
    }
}

function Set-RegistryTweaks {
    Write-StatusLine "info" "Applying tweaks to registry..."
    $osMemory = (Get-WmiObject -Class win32_operatingsystem | Select-Object -Property TotalVisibleMemorySize).TotalVisibleMemorySize + 1024000
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
    Remove-RegistryKey "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace_41040327\{e88865ea-0e1c-4e20-9aa6-edcd0212c87c}" $false "" "removed Gallery shortcut"

    if ($script:ErrorCount -lt 1) {
        Start-Sleep 1
        Write-EndMenuStart
    } else {
        Clear-Host
        Show-DisclosureError "reg"
    }
}
#Main Application

function Write-MainMenuStart {
    Clear-Host
    Write-ColorOutput -InputObject "Warming up hardware statistics, sit tight for a few seconds :)"
    $hwinfo = (Get-ComputerHardwareSpecification)
    Clear-Host
    Write-ColorOutput -InputObject "Thank you for trusting Prolix OCs with your PC! <3" -ForegroundColor Green -BackgroundColor Black
    Write-ColorOutput -InputObject "Join the Discord [$(New-Hyperlink 'https://discord.gg/ffW3vCpGud')] for any help, or to show your support!" -ForegroundColor Gray 
    Write-Output -InputObject "`n"
    Write-ColorOutput -InputObject "CPU: $($hwinfo['CpuName'])`nCores/Threads: $($hwinfo['NumberOfCores'])c/$($hwinfo['LogicalProcessors'])t`nMemory Configuration: $($hwinfo['MemTopo'])x$($hwinfo['TotalMem']/$hwinfo['MemTopo'])GB ($($hwinfo['TotalMem'])GB Total)`nMemory Speed: $($hwinfo['Speed']) MT/s`nGPU: $($hwinfo['DgpuName']) ($($hwinfo['DgpuVram'])GB)`nDriver Date: $($hwinfo['DgpuDate'])`n" -ForegroundColor Gray
    [string]$OSVersion = (Get-WmiObject Win32_OperatingSystem).caption
    $OSVersion = $OSVersion -replace "Microsoft ", ""
    if ($OSVersion.Contains("11 ")) {
        Write-ColorOutput -InputObject  "You're currently running $($OSVersion)! Nice, let's get started." -ForegroundColor Green
        Write-ColorOutput -InputObject "`nOptions:" -ForegroundColor DarkGray
        Write-ColorOutput -InputObject "`n[1] Run Prolix Tweaks`n" -ForegroundColor Gray
        $Choice = Show-Prompt "Enter number choice here"
        if ($Choice -eq "1") {
            Clear-Host
            Write-RisksWarning
        }
    } elseif ($OSVersion.Contains("10 ")) {
        Clear-Host
        Write-Windows10Warning
    } else {
        Clear-Host
        Write-LegacyWindowsWarning $OSVersion
    }
}

function Write-EndMenuStart {
    Clear-Host
    Show-Disclosure "!!! DONE !!!" "You're all wrapped up! The latest and greatest in optimizations has been applied to your machine. Keep in mind of the following things before you go:" "`n- Keep an eye on your performance and notate if anything has degraded in usability or overall performance. Taking note of this behavior and submitting feedback is crucial.`n- If you have any further questions, just remember: don't ask to ask. When you join my Discord, please lay out any questions or concerns as soon as you join.`nThis script is free to use and distribute, but support is helpful! You can drop by my [$(New-Hyperlink 'https://twitch.tv/prolix_gg' 'Twitch')] or come say hello on [$(New-Hyperlink 'https://tiktok.com/@prolix_oc' 'TikTok')].`n- You are not entitled to on-demand 24/7 support, and such entitlement displayed in my social channels will result in removal of your presence.`n- One-on-one support requested of me after running this script will be billable at your expense." "`nGeneral support, updates and information for this tweak can be found in Prolix OC's Discord [$(New-Hyperlink 'https://discord.gg/ffW3vCpGud')], Hope to see you there!" "success" "END" "Type [R] to reboot now or [N] to exit without restart [NOT RECOMMENDED]"
}

Write-MainMenuStart