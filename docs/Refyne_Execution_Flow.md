# <p align="center"> Refyne Main Execution Flow </p>

> [!NOTE]
> This is a control flow diagram of the main execution flow of the script. It is not a flowchart of the entire script. It is a high-level overview of the entire script. It does include all functions, variables, and enums used in the script.

```mermaid
flowchart TD
    subgraph Main
    direction BT
        A[Start] --> |Get-ComputerHardwareSpecification| B[Operating System Version]
        B --> C[Windows 11]
        B --> D[Windows 10]
        B --> F[Other]

        C -- 1 --> G[Windows 11 Warning]
        C -- 2 --> GSR[GSR]
        C -- 3 --> fnc[Optimize PowerShell]
        C -- 4 --> fnd[Windows Activation]
        C -- 5 --> fk[Undo Changes]
        
        D --> H[Windows 10 Warning]

        F --> Func[Legacy Warning] --> Exit

        G -- Yes --> Accepted[Selection]
        G -- No --> Exit

        H -- Yes --> Accepted
        H -- No --> Exit

        Accepted --> Execution
    end

    subgraph Execution
    direction LR
        MA[Set-EnableSystemRecovery]
        MB[Set-BCDTweaksMem]
        MC[Set-BCDTweaks]
        MD[Write-MemTweakWarning]
        ME[Set-Tweaks]
    end

    subgraph Backup
    direction LR
        BA[Backup-RegistryPathKey]
        BB[Backup-BCDStorage]
        BC[Undo-SystemChanges]
    end

    subgraph Error-Handling[Error Handling]
    direction LR
        Show-DisclosureError[Disclosure Errors] --> FailedCommands[Failed Commands]
        Show-DisclosureError --> C1[Error Count]
    end

    subgraph Enums
    direction LR
        Severity --> Warn
        Severity --> Fatal
        Severity --> Success
        Severity --> Info

        Stage --> Recovery
        Stage --> BCD
        Stage --> Memory
        Stage --> Registry
        Stage --> GPU
        Stage --> Network
        Stage --> Interrupts
        Stage --> Tweak
        Stage --> Windows10
        Stage --> Final
    end

    subgraph Variables
    direction LR
        v1[ErrorCount]
        v2[FailedCommands]
        v3[CurrentVersion]
        v4[AcceptW10Risk]
        v5[AcceptMemRisk]
        v6[AcceptTweaksRisk]
        v7[TerminalWindowWidth]
        v8[OSVersion]
        v9[WindowsVersion]
        v10[AMDRegistryPath]
        v11[NVIDIARegistryPath]
        v12[Card]
        v13[TotalMemory]
        v14[TimeStamp]
        v15[LogFilePath]
        v16[RegistryBackupPath]
        v17[BCDBackupPath]
        v18[StopWatch]
    end

    subgraph Functions
    direction LR
        f1[Convert-RegistryPath]
        f1[Get-ComputerHardwareSpecification]
        f1[Write-ColorOutput]
        f2[Show-Disclosure]
        f3[Show-DisclosureError]
        f4[Show-Prompt]
        f5[Write-StatusLine]
        f6[Write-Windows10Warning]
        f7[Write-LegacyWindowsWarning]
        f8[Write-MemTweakWarning]
        f9[Write-RisksWarning]
        f10[Get-UserIntent]
        f11[Read-CommandStatus]
        f12[Undo-SystemChanges]
        f13[Write-LogEntry]
        f14[Backup-BCDStorage]
        f15[Backup-RegistryPathKey]
        f14[Write-RegistryKey]
        f15[Write-BinaryRegistry]
        f17[Remove-RegistryKey]
        f16[Set-EnableSystemRecovery]
        f17[Set-BCDTweaks]
        f18[Set-BCDTweaksMem]
        f19[Set-Tweaks]
        f20[Read-GPUManual]
        f21[Set-RegistryTweaksNVIDIA]
        f22[Set-RegistryTweaksAMD]
        f23[Set-RegistryTweaksInterrupts]
        f24[Set-NetworkTweaks]
        f25[Optimize-PowerShell]
        f26[Write-MainMenuStart]
        f27[Write-EndMenuStart]
    end

    Main-->Error-Handling
    Execution-->Error-Handling
    Execution --> Backup
    Backup --> Error-Handling
```

---

**<div align="center" id="footer">© 2024 Refyne. All rights reserved. <div>**
<br>

<div align="right"><a href="#">(Back to top)</a></div>
