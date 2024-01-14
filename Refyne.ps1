if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process -verb RunAs wt.exe -ArgumentList "PowerShell.exe", "-NoExit", "-ExecutionPolicy Bypass", "-Command", "$($PSCommandPath)";
    exit;
}

# ------------------------------
# Script Variables
# ------------------------------

# Risks
[bool]$AcceptW10Risk = $false
[bool]$AcceptMemRisk = $false
[bool]$AcceptTweaksRisk = $false

# Terminal
[int]$TerminalWindowWidth = [int][System.Math]::Round($Host.UI.RawUI.WindowSize.Width / 2.5, [System.MidpointRounding]::AwayFromZero)

# OS
[string]$OSVersion = ((Get-CimInstance -ClassName Win32_OperatingSystem).caption).Replace("Microsoft ", "")
[string]$KernelVersion = (Get-CimInstance -ClassName Win32_OperatingSystem).Version

# Environment
$SystemDrive = $env:SystemDrive
$UserName = $env:UserName
$ComputerName = $env:ComputerName
$UserDomain = $env:UserDomain
$UserProfile = $env:UserProfile
$HomeDrive = $env:HomeDrive
$HomePath = $env:HomePath
$Path = $env:Path

# ------------------------------
# Misc Functions
# ------------------------------

function Write-TimestampedInformation {
    PARAM (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [string]$Output
    )
  
    PROCESS {
        TRAP {
            Write-ErrorEvent $_.Exception.Message
            continue
        }
        Write-Host ("[{0}] {1}" -f (Get-Date), $Output)
    }
}
  
function Write-TimestampedWarning {
    PARAM (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [string]$WarningMessage
    )
  
    PROCESS {
        TRAP {
            Write-ErrorEvent $_.Exception.Message
            continue
        }
        Write-Warning ("[{0}] {1}" -f (Get-Date), $WarningMessage)
    }
}
  
function Write-TimestampedError {
    PARAM (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [string]$ErrorMessage
    )
  
    PROCESS {
        TRAP {
            Write-ErrorEvent $_.Exception.Message
            continue
        }
        Write-Error ("[{0}] {1}" -f (Get-Date), $ErrorMessage)
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

# ------------------------------
# Helper Functions
# ------------------------------

function Show-Prompt ($message = "What would you like to do?") {
    [Console]::SetCursorPosition(0, $Host.UI.RawUI.BufferSize.Height - 1)
    $Choice = Read-Host $message
    return $Choice
}

function Show-Disclosure ($discheader, $discbody, $disclist, $discsupp, $severity, $scope) {
    Clear-Host

    switch ($severity) {
        "warn" { Write-ColorOutput -InputObject "$($discheader)" -ForegroundColor Yellow -HorizontalPad $($TerminalWindowWidth) -VerticalPad 2 }
        "fatal" { Write-ColorOutput -InputObject "$($discheader)" -ForegroundColor Red -HorizontalPad $($TerminalWindowWidth) -VerticalPad 2 }
        "success" { Write-ColorOutput -InputObject "$($discheader)" -ForegroundColor Green -HorizontalPad $($TerminalWindowWidth) -VerticalPad 2 }
        Default { Write-ColorOutput -InputObject "$($discheader)" -ForegroundColor White -HorizontalPad $($TerminalWindowWidth) -VerticalPad 2 }
    }
    Write-ColorOutput -InputObject "$($discbody)" -ForegroundColor White
    Write-ColorOutput -InputObject "$($disclist)" -ForegroundColor White
    Write-ColorOutput -InputObject "$($discsupp)" -ForegroundColor White
    $Choice = Show-Prompt "Type Y/y to agree and proceed or N/n to exit"
    Get-UserIntent($Choice, $scope)
}

function Write-StatusLine ($stat, $content) {
    switch ($stat) {
        { $_ -match "error" } { Write-ColorOutput -InputObject  "[ERROR] "+ $content +"" -ForegroundColor Red -HorizontalPad $($TerminalWindowWidth) }
        { $_ -match "warning" } { Write-ColorOutput -InputObject  "[WARNING] "+ $content +"" -ForegroundColor Yellow -HorizontalPad $($TerminalWindowWidth) }
        { $_ -match "success" } { Write-ColorOutput -InputObject  "[SUCCESS] "+ $content +"" -ForegroundColor Green -HorizontalPad $($TerminalWindowWidth) }
        { $_ -match "info" } { Write-ColorOutput -InputObject  "[INFO] "+ $content +"" -ForegroundColor White -HorizontalPad $($TerminalWindowWidth) }
        Default {}
    } 
}

function Write-Windows10Warning {
    Write-ColorOutput -InputObject  "`nYou're currently running $($OSVersion). Be aware of a few things:`n"-ForegroundColor Yellow -HorizontalPad $($TerminalWindowWidth)
    Write-ColorOutput -InputObject  "- $($OSVersion) is not officially supported by my script, but the optimizations have a chance to still work.`n- By choosing to run this script anyways, you assume all risks to YOUR system's integrity.`n- By agreeing to the prompt, you are rescinding your chance for support by not running the proper script designed for your OS.`n- If you need a script designed for Windows 10, join Prolix's Discord [$(New-Hyperlink 'https://discord.gg/ffW3vCpGud')] and keep an eye out for the release." -ForegroundColor Gray
    $Choice = Show-Prompt "`nType Y/y to agree and proceed or N/n to exit"
    if ($Choice -eq "Y") {
        Get-UserIntent($Choice, "W10")
    }
    else {
        exit
    }
}

function Write-LegacyWindowsWarning {
    Write-ColorOutput -InputObject  "You're running an unsupported Windows version." -ForegroundColor Red -HorizontalPad $($TerminalWindowWidth)  
    Write-ColorOutput -InputObject  "This script is designed for Windows 11, and will most likely not work on your system. Exiting..." -ForegroundColor Gray
    exit  
}

function Write-MemTweakWarning {
    Show-Disclosure "[WARNING]" "There is a tweak I include in this pack that can adversely affect systems with memory stability issues!" "`nIf you have ever had the following:`n- Bluescreens involving DPC_WATCHDOG_TIMEOUT, IRQL_NOT_LESS_OR_EQUAL, or WHEA_UNCORRECTABLE_ERROR`n- Issues presenting as slow cold boots, multiple restarts when attempting to boot, or `"Overclocking failed`" messages.`n- Frequent file system corruption or even loss of data.`n`nI cannot advise you put this particular tweak on your system if you are unsure your RAM overclock or XMP/DOCP profile is `"NASA Stable`", or if any of the mentioned issues occur with your PC.`nIf you choose to use the tweak anyways, and accept in the next prompt: no support will be provided until we can verify your RAM is stable, whether that requires de-tuning your RAM OC, changing XMP/DOCP profiles, or reverting to stock configuration." "`nGeneral support and information for this page can be found in Prolix OCs Discord [$(New-Hyperlink 'https://discord.gg/ffW3vCpGud')], but only provided you have done your due diligence and have tried to prevent or fix any issues as a result of your usage." "warn" "MEM"
}

function Write-RisksWarning {
    Show-Disclosure "[WARNING]" "By agreeing to the next prompt, you are doing so to the following terms:" "`n- You are assuming all risks for any potential corruption or instability of your system`n- You are receiving no warranty from Prolix OCs, implied or otherwise, for this freely distributed script.`n- You understand the risks that modifying Windows can bring, and will utilize the created restore point to revert these changes.`n- You are not entitled to on-demand 24/7 support, and such entitlement displayed in my social channels will result in removal of your presence.`n- One-on-one support requested of me after running this script will be billable at your expense." "`nGeneral support and information for this page can be found in Prolix OCs Discord [$(New-Hyperlink 'https://discord.gg/ffW3vCpGud')], but only provided you have done your due diligence and have tried to prevent or fix any issues as a result of your usage." "warn" "TWEAK"
}

function Set-Risk($stage) {
    if ($stage -eq "W10") {
        $script:AcceptW10Risk = $true
        $script:AcceptTweaksRisk = $true
    }
    if ($stage -eq "MEM") {
        $script:AcceptMemRisk = $true
    }
    if ($stage -eq "TWEAK") {
        $script:AcceptTweaksRisk = $true
        Clear-Host
        Set-EnableSystemRecovery
    }
}

function Get-UserIntent($userInp, $stage) {
    $userInp = $userInp.ToUpper()
    switch ($userInp) {
        'Y' { 
            Set-Risk $stage
        }
        'N' {
            exit
        }
        Default {
            exit
        }
    }
}

# ------------------------------
# Tweaks
# ------------------------------
function Write-RegistryKey($regpath, $regkey, $regvalue, $proptype) {
    if (-NOT (Test-Path $regpath)) {
        New-Item -Path $regpath -Force | *>$null
    }  

    New-ItemProperty -Path $regpath -Name $regkey -Value $regvalue -PropertyType $proptype -Force *>$null
}

function Write-BCDCommand($bcdkey, $bcdbvalue) {
    Invoke-Command -ComputerName $comp -Credential $cred -ScriptBlock { 
        $ "bcdedit /set $(bcdkey) $(bcdvalue)" *>$null
    }
}

function Set-EnableSystemRecovery {
    Write-ColorOutput -InputObject "Enabling restore points and shortening frequency..."

    $ "dism /online /enable-feature /featurename:MicrosoftWindowsWMICore /NoRestart >nul" *>$null

    Write-RegistryKey("HKLM\Software\Microsoft\Windows NT\CurrentVersion\SystemRestore", "SystemRestorePointCreationFrequency", "0", "DWORD") *>$null

    Enable-ComputerRestore -Drive 'C:\', 'D:\', 'E:\', 'F:\', 'G:\' *>$null

    Checkpoint-Computer -Description 'Prolix Optimizations' *>$null
}

function Select-Optimization {
    Write-ColorOutput -InputObject "`nOptions:`n" -ForegroundColor DarkGray
        
    Write-ColorOutput -InputObject "[0] Exit" -ForegroundColor Gray
    Write-ColorOutput -InputObject "[1] Run Prolix Tweaks" -ForegroundColor Gray

    $Choice = Show-Prompt
    if ($Choice -eq "1") { 
        Write-RisksWarning
    }
}

# ------------------------------
# Main
# ------------------------------

TRAP {
    Write-TimestampedError $_.Exception.Message
    continue
}

function Main {
    Clear-Host

    Write-ColorOutput -InputObject "Thank you for trusting Prolix OCs with your PC! <3" -ForegroundColor Green -BackgroundColor Black
    Write-ColorOutput -InputObject "Join the Discord [$(New-Hyperlink 'https://discord.gg/ffW3vCpGud')] for any help, or to show your support!`n" -ForegroundColor Gray

    if ($OSVersion -like "*Windows 11*") {
        Write-ColorOutput -InputObject  "You're currently running $($OSVersion)! Nice, let's get started." -ForegroundColor Green
        Select-Optimization
    }
    elseif ($OSVersion -like "*Windows 10*") {
        Clear-Host 
        Write-Windows10Warning
    }
    else {
        Clear-Host 
        Write-LegacyWindowsWarning
    }
}
Main