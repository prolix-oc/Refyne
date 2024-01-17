# <p align="center"> Refyne Main Execution Flow </p>

> [!NOTE]
> This is a control flow diagram of the main execution flow of the script. It is not a flowchart of the entire script. It is a high-level overview of the entire script. It does include all functions, variables, and enums used in the script.

```mermaid
flowchart TD
    subgraph Main
    direction LR
        A[Start] --> |Get-ComputerHardwareSpecification| B(Operating System Version)
        B --> C(Windows 11)
        B --> D(Windows 10)
        B --> F(Other)
        C -- Yes --> G(Windows 11 Warning)
        C -- No --> Exit
        D -- Yes --> H(Windows 10 Warning)
        D -- No --> Exit
        F --> Func(Legacy Warning) --> Exit
        G -- Yes --> Accepted(Selection)
        G -- No --> Exit
        H -- Yes --> Accepted
        H -- No --> Exit
    end

    subgraph Choices
    direction LR
        Accepted -- Accept --> Accepted-Stage
        Accepted -- No --> Exit
        Accepted -- Exit --> Exit
        Accepted -- Continue --> Continue-Stage
        Accepted -- Reboot --> Rebooted
    end

    subgraph Execution
    direction LR
        Accepted-Stage[Accepted] -- Windows 10 --> Set-EnableSystemRecovery
        Accepted-Stage -- Memory --> Set-BCDTweaksMem
        Accepted-Stage -- Tweak --> Set-EnableSystemRecovery
        Continue-Stage[Continued] -- Recovery --> Backup-BCDStorage --> Set-BCDTweaks
        Continue-Stage -- Boot Configuration Data --> Write-MemTweakWarning
        Continue-Stage -- Memory --> Set-Tweaks
    end

    subgraph Error-Handling[Error Handling]
    direction LR
        Show-DisclosureError[Disclosure Errors] --> FailedCommands(Failed Commands)
        Show-DisclosureError --> C1(Error Count)
    end

    subgraph Enums
    direction LR
        Severity --> Warn
        Severity --> Fatal
        Severity --> Success
        Severity --> Info
    end

    subgraph Variables
    direction LR
        v1(ErrorCount)
        v2(FailedCommands)
        v3(CurrentVersion)
        v4(AcceptW10Risk)
        v5(AcceptMemRisk)
        v6(AcceptTweaksRisk)
        v7(TerminalWindowWidth)
        v8(Card)
        v9(OSVersion)
        v10(WindowsVersion)
        v11(AmdRegPath)
        v12(NvRegPath)
        v13(TotalMemory)
        v14(timestamp)
        v15(logfilepath)
        v16(regfilepath)
        v17(bcdfilepath)
        v18(stopwatch)
    end

    subgraph Functions
    direction LR

        f1[Backup-BCDStorage]
        f1[Backup-RegistryPathKey]
        f1[Convert-RegistryPath]
        f2[Get-ComputerHardwareSpecification]
        f3[Write-ColorOutput]
        f4[Show-Disclosure]
        f5[Show-DisclosureError]
        f6[Show-Prompt]
        f7[Write-StatusLine]
        f8[Write-Windows10Warning]
        f9[Write-LegacyWindowsWarning]
        f10[Write-MemTweakWarning]
        f11[Write-RisksWarning]
        f12[Get-UserIntent]
        f13[Read-CommandStatus]
        f14[Write-LogEntry]
        f15[Backup-BCDStorage]
        f16[Backup-RegistryPathKey]
        f14[Write-RegistryKey]
        f15[Write-BinaryRegistry]
        f16[Set-EnableSystemRecovery]
        f17[Set-BCDTweaks]
        f18[Set-BCDTweaksMem]
        f19[Set-Tweaks]
        f20[Read-GPUManu]
        f21[Set-RegistryTweaksNvidia]
        f22[Set-RegistryTweaksAmd]
        f23[Set-RegistryTweaksInterrupts]
        f24[Set-NetworkTweaks]
        f25[Optimize-PowerShell]
        f26[Write-MainMenuStart]
        f27[Write-EndMenuStart]
        f28[Undo-SystemChanges]
    end

    Main-->Error-Handling
    Execution-->Error-Handling
    Choices-->Error-Handling
```
```

---

**<div align="center" id="footer">© 2024 Refyne. All rights reserved. <div>**
<br>
<div align="right"><a href="#">(Back to top)</a></div>
