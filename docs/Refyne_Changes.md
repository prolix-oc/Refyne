# What does this script change?

## Registry

### System Recovery

| Path                                                             | Value                               | Type  | Data |
| ---------------------------------------------------------------- | ----------------------------------- | ----- | ---- |
| HKLM:\Software\Microsoft\Windows NT\CurrentVersion\SystemRestore | SystemRestorePointCreationFrequency | DWord | 0    |

### System

| Path                                                                                                                       | Value                             | Type   | Data     |
| -------------------------------------------------------------------------------------------------------------------------- | --------------------------------- | ------ | -------- |
| HKLM:\System\ControlSet001\Control\PriorityControl                                                                         | Win32PrioritySeparation           | DWord  | 42       |
| HKLM:\System\ControlSet001\Control\PriorityControl                                                                         | EnableVirtualizationBasedSecurity | DWord  | 0        |
| HKLM:\System\CurrentControlSet\Services\mouclass\Parameters                                                                | TreatAbsolutePointerAsAbsolute    | DWord  | 1        |
| HKLM:\System\CurrentControlSet\Services\mouhid\Parameters                                                                  | TreatAbsoluteAsRelative           | DWord  | 0        |
| HKLM:\System\CurrentControlSet\Services\kbdclass\Parameters                                                                | Status                            | DWord  | 0        |
| HKLM:\System\CurrentControlSet\Services\lfsvc\Service\Configuration                                                        | Status                            | DWord  | 0        |
| HKLM:\System\CurrentControlSet\Services\GpuEnergyDrv                                                                       | Start                             | DWord  | 2        |
| HKLM:\System\CurrentControlSet\Services\GpuEnergyDr                                                                        | Start                             | DWord  | 2        |
| HKLM:\System\CurrentControlSet\Control                                                                                     | SvcHostSplitThresholdInKB         | DWord  | Memory   |
| HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel                                                              | GlobalTimerResolutionRequests     | DWord  | 1        |
| HKLM:\System\CurrentControlSet\Control\Session Manager\Memory Management                                                   | LargeSystemCache                  | DWord  | 1        |
| HKLM:\System\CurrentControlSet\Control\Session Manager\Power                                                               | HiberbootEnabled                  | DWord  | 0        |
| HKLM:\System\CurrentControlSet\Control\Session Manager                                                                     | HeapDeCommitFreeBlockThreshold    | DWord  | 262144   |
| HKLM:\System\CurrentControlSet\Control\FileSystem                                                                          | LongPathsEnabled                  | DWord  | 0        |
| HKLM:\System\CurrentControlSet\Control\GraphicsDrivers\Scheduler                                                           | EnablePreemption                  | DWord  | 1        |
| HKLM:\System\CurrentControlSet\Control\GraphicsDrivers                                                                     | PlatFORmSupportMiracast           | DWord  | 0        |
| HKLM:\System\CurrentControlSet\Control\Power\PowerThrottling                                                               | PowerThrottlingOff                | DWord  | 00000001 |
| HKLM:\System\CurrentControlSet\Control\CrashControl                                                                        | DisplayParameters                 | DWord  | 1        |
| HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat                                                                        | AITEnable                         | DWord  | 0        |
| HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers                                                                     | DpiMapIommuContiguous             | DWord  | 1        |
| HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management                                                   | DisablePagingExecutive            | DWord  | 1        |
| HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management                                                   | LargeSystemCache                  | DWord  | 1        |
| HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location                              | Value                             | String | Deny     |
| HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\DataCollection                                                    | AllowTelemetry                    | DWord  | 0        |
| HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager                                                     | ContentDeliveryAllowed            | DWord  | 0        |
| HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager                                                     | OemPreInstalledAppsEnabled        | DWord  | 0        |
| HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager                                                     | PreInstalledAppsEnabled           | DWord  | 0        |
| HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager                                                     | PreInstalledAppsEverEnabled       | DWord  | 0        |
| HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager                                                     | SilentInstalledAppsEnabled        | DWord  | 0        |
| HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager                                                     | SubscribedContent-338387Enabled   | DWord  | 0        |
| HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager                                                     | SubscribedContent-338388Enabled   | DWord  | 0        |
| HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager                                                     | SubscribedContent-338389Enabled   | DWord  | 0        |
| HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager                                                     | SubscribedContent-353698Enabled   | DWord  | 0        |
| HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager                                                     | SystemPaneSuggestionsEnabled      | DWord  | 0        |
| HKLM:\Software\Policies\Microsoft\Windows\System                                                                           | EnableActivityFeed                | DWord  | 0        |
| HKLM:\Software\Policies\Microsoft\Windows\System                                                                           | PublishUserActivities             | DWord  | 0        |
| HKLM:\Software\Policies\Microsoft\Windows\System                                                                           | UploadUserActivities              | DWord  | 0        |
| HKLM:\Software\Policies\Microsoft\Windows\DataCollection                                                                   | AllowTelemetry                    | DWord  | 0        |
| HKLM:\Software\Policies\Microsoft\Windows\CloudContent                                                                     | DisableSoftLanding                | DWord  | 1        |
| HKLM:\Software\Microsoft\Windows\CurrentVersion\Reliability                                                                | TimeStampInterval                 | DWord  | 0        |
| HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}                 | SensorPermissionState             | DWord  | 0        |
| HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe\PerfOptions                      | CpuPriorityClass                  | DWord  | 4        |
| HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe\PerfOptions                      | IoPriority                        | DWord  | 3        |
| HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile                                                | NoLazyMode                        | DWord  | 1        |
| HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile                                                | AlwaysOn                          | DWord  | 1        |
| HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile                                                | SystemResponsiveness              | DWord  | 0        |
| HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games                                    | Scheduling Category               | String | High     |
| HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games                                    | GPU Priority                      | DWord  | 8        |
| HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games                                    | Priority                          | DWord  | 6        |
| HKLM:\Software\Microsoft\FTH                                                                                               | Enabled                           | DWord  | 0        |
| HKLM:\SOFTWARE\Policies\Microsoft\FVE                                                                                      | DisableExternalDMAUnderLock       | DWord  | 0        |
| HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard                                                                      | EnableVirtualizationBasedSecurity | DWord  | 0        |
| HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard                                                                      | HVCIMATRequired                   | DWord  | 0        |
| HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer                                                                   | Max Cached Icons                  | String | 4096     |
| HKLM:\Software\Microsoft\Windows\Dwm                                                                                       | OverlayTestMode                   | DWord  | 5        |
| HKLM:\System\Maps                                                                                                          | AutoUpdateEnabled                 | DWord  | 0        |
| HKCU:\Software\Microsoft\GameBar                                                                                           | AllowAutoGameMode                 | DWord  | 1        |
| HKCU:\Software\Microsoft\GameBar                                                                                           | AutoGameModeEnabled               | DWord  | 1        |
| HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace_41040327\{e88865ea-0e1c-4e20-9aa6-edcd0212c87c} |                                   |        |          |

### NVIDIA

| Path                                                                            | Value             | Type  | Data |
| ------------------------------------------------------------------------------- | ----------------- | ----- | ---- |
| HKLM:\System\ControlSet001\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318} | PowerMizerEnable  | DWord | 1    |
| HKLM:\System\ControlSet001\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318} | PowerMizerLevel   | DWord | 1    |
| HKLM:\System\ControlSet001\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318} | PowerMizerLevelAC | DWord | 1    |
| HKLM:\System\ControlSet001\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318} | PerfLevelSrc      | DWord | 8738 |
| HKLM:\Software\NVIDIA Corporation\NvControlPanel2\Client                        | PerfLevelSrc      | DWord | 8738 |
| HKLM:\Software\NVIDIA Corporation\Global\FTS                                    | PerfLevelSrc      | DWord | 8738 |
| HKLM:\System\CurrentControlSet\Services\nvlddmkm\Global\NVTweak                 | PerfLevelSrc      | DWord | 8738 |
| HKLM:\System\CurrentControlSet\Services\nvlddmkm\FTS                            | PerfLevelSrc      | DWord | 8738 |
| HKLM:\SYSTEM\CurrentControlSet\Services\nvlddmkm                                | PerfLevelSrc      | DWord | 8738 |
| HKLM:\Software\Microsoft\Windows\CurrentVersion\Run                             | NvBackend         |       |      |

### AMD

| Path                                                                                   | Value                          | Type   | Data  |
| -------------------------------------------------------------------------------------- | ------------------------------ | ------ | ----- |
| HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}     | 3to2Pulldown_NA                | DWord  | 0     |
| HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}     | Adaptive De-interlacing        | DWord  | 1     |
| HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}     | AllowRSOverlay                 | String | false |
| HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}     | AllowSkins                     | String | false |
| HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}     | AllowSnapshot                  | DWord  | 0     |
| HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}     | AllowSubscription              | DWord  | 0     |
| HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}     | AutoColorDepthReduction_NA     | DWord  | 0     |
| HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}     | DisableSAMUPowerGating         | DWord  | 1     |
| HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}     | DisableUVDPowerGatingDynamic   | DWord  | 1     |
| HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}     | DisableVCEPowerGating          | DWord  | 1     |
| HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}     | EnableAspmL0s                  | DWord  | 0     |
| HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}     | EnableAspmL1                   | DWord  | 0     |
| HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}     | EnableUlps                     | DWord  | 0     |
| HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}     | KMD_DeLagEnabled               | DWord  | 1     |
| HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}     | EnableUlps_NA                  | String | 0     |
| HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}     | KMD_FRTEnabled                 | Dword  | 0     |
| HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}     | DisableDMACopy                 | DWord  | 1     |
| HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}     | DisableBlockWrite              | DWord  | 0     |
| HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}     | StutterMode                    | DWord  | 0     |
| HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}     | EnableUlps                     | DWord  | 0     |
| HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}     | PP_SclkDeepSleepDisable        | DWord  | 1     |
| HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}     | PP_ThermalAutoThrottlingEnable | DWord  | 0     |
| HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}     | DisableDrmdmaPowerGating       | DWord  | 1     |
| HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\UMD | Main3D_DEF                     | String | 1     |
| HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\UMD | Main3D                         | Binary | 32 00 |
| HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\UMD | ShaderCache                    | Binary | 32 00 |
| HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\UMD | Tessellation_OPTION            | Binary | 32 00 |
| HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\UMD | Tessellation                   | Binary | 31 00 |
| HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\UMD | VSyncControl                   | Binary | 30 00 |
| HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\UMD | TFQ                            | Binary | 32 00 |
| HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\UMD | 3D_Refresh_Rate_Override_DEF   | DWord  | 0     |

### Interrupts

| Path                                                                                                                         | Value                          | Type   | Data |
| ---------------------------------------------------------------------------------------------------------------------------- | ------------------------------ | ------ | ---- |
| HKLM:\System\CurrentControlSet\Enum\GPU\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties            | MSISupported                   | DWord  | 1    |
| HKLM:\System\CurrentControlSet\Enum\GPU\Device Parameters\Interrupt Management\Affinity Policy                               | DevicePriority                 |        |      |
| HKLM:\System\CurrentControlSet\Enum\GPU\Device Parameters\Interrupt Management\Affinity Policy                               | DevicePolicy                   | DWord  | 4    |
| HKLM:\System\CurrentControlSet\Enum\GPU\Device Parameters\Interrupt Management\Affinity Policy                               | AssignmentSetOverride          | Binary | C0   |
| HKLM:\System\CurrentControlSet\Enum\NetworkAdapter\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties | MSISupported                   | DWord  | 1    |
| HKLM:\System\CurrentControlSet\Enum\NetworkAdapter\Device Parameters\Interrupt Management\Affinity Policy                    | DevicePriority                 |        |      |
| HKLM:\System\CurrentControlSet\Enum\NetworkAdapter\Device Parameters\Interrupt Management\Affinity Policy                    | DevicePolicy                   | DWord  | 4    |
| HKLM:\System\CurrentControlSet\Enum\NetworkAdapter\Device Parameters\Interrupt Management\Affinity Policy                    | AssignmentSetOverride          | Binary | 30   |
| HKLM:\System\CurrentControlSet\Enum\USB\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties            | MSISupported                   | DWord  | 1    |
| HKLM:\System\CurrentControlSet\Enum\USB\Device Parameters\Interrupt Management\Affinity Policy                               | DevicePriority                 |        |      |
| HKLM:\System\CurrentControlSet\Enum\USB\Device Parameters\Interrupt Management\Affinity Policy                               | DevicePolicy                   | DWord  | 4    |
| HKLM:\System\CurrentControlSet\Enum\USB\Device Parameters\Interrupt Management\Affinity Policy                               | AssignmentSetOverride          | Binary | C0   |
| HKLM:\System\CurrentControlSet\Enum\StorPort                                                                                 | EnableIdlePowerManagement      | DWord  | 0    |
| HKLM:\System\CurrentControlSet\Enum\USB\Device                                                                               | EnhancedPowerManagementEnabled | DWord  | 0    |
| HKLM:\System\CurrentControlSet\Enum\USB\Device                                                                               | AllowIdleIrpInD3               | DWord  | 0    |
| HKLM:\System\CurrentControlSet\Enum\USB\Device                                                                               | EnableSelectiveSuspend         | DWord  | 0    |
| HKLM:\System\CurrentControlSet\Enum\USB\Device                                                                               | DeviceSelectiveSuspended       | DWord  | 0    |
| HKLM:\System\CurrentControlSet\Enum\USB\Device                                                                               | SelectiveSuspendEnabled        | DWord  | 0    |
| HKLM:\System\CurrentControlSet\Enum\USB\Device                                                                               | SelectiveSuspendOn             | DWord  | 0    |
| HKLM:\System\CurrentControlSet\Enum\USB\Device                                                                               | D3ColdSupported                | DWord  | 0    |

### Network

| Path                                                      | Value                                | Type  | Data |
| --------------------------------------------------------- | ------------------------------------ | ----- | ---- |
| HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters  | TCPNoDelay                           | DWord | 1    |
| HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters  | TcpAckFrequency                      | DWord | 1    |
| HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters  | TcpDelAckTicks                       | DWord | 0    |
| HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters  | TcpInitialRTT                        | DWord | 300  |
| HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters  | TcpMaxDupAcks                        | DWord | 2    |
| HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters  | SynAttackProtect                     | DWord | 1    |
| HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters  | TCPMaxConnectResponseRetransmissions | DWord | 2    |
| HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters  | TcpMaxDataRetransmissions            | DWord | 3    |
| HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters  | TcpMaxHalfOpen                       | DWord | 100  |
| HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters  | TcpMaxHalfOpenRetried                | DWord | 80   |
| HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters  | TcpMaxPortsExhausted                 | DWord | 5    |
| HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters  | EnableDeadGWDetect                   | DWord | 0    |
| HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters  | DisableIPSourceRouting               | DWord | 1    |
| HKLM:\System\CurrentControlSet\Services\Tcpip6\Parameters | TCPNoDelay                           | DWord | 1    |
| HKLM:\System\CurrentControlSet\Services\Tcpip6\Parameters | TcpAckFrequency                      | DWord | 1    |
| HKLM:\System\CurrentControlSet\Services\Tcpip6\Parameters | TcpDelAckTicks                       | DWord | 0    |
| HKLM:\System\CurrentControlSet\Services\Tcpip6\Parameters | TcpInitialRTT                        | DWord | 300  |
| HKLM:\System\CurrentControlSet\Services\Tcpip6\Parameters | TcpMaxDupAcks                        | DWord | 2    |
| HKLM:\System\CurrentControlSet\Services\Tcpip6\Parameters | SynAttackProtect                     | DWord | 1    |
| HKLM:\System\CurrentControlSet\Services\Tcpip6\Parameters | TCPMaxConnectResponseRetransmissions | DWord | 2    |
| HKLM:\System\CurrentControlSet\Services\Tcpip6\Parameters | TcpMaxDataRetransmissions            | DWord | 3    |
| HKLM:\System\CurrentControlSet\Services\Tcpip6\Parameters | TcpMaxHalfOpen                       | DWord | 100  |
| HKLM:\System\CurrentControlSet\Services\Tcpip6\Parameters | TcpMaxHalfOpenRetried                | DWord | 80   |
| HKLM:\System\CurrentControlSet\Services\Tcpip6\Parameters | TcpMaxPortsExhausted                 | DWord | 5    |
| HKLM:\System\CurrentControlSet\Services\Tcpip6\Parameters | EnableDeadGWDetect                   | DWord | 0    |
| HKLM:\System\CurrentControlSet\Services\Tcpip6\Parameters | DisableIPSourceRouting               | DWord | 1    |

## Commands

### System Recovery

```powershell
Enable-ComputerRestore -Drive 'C:\', 'D:\', 'E:\', 'F:\', 'G:\'
Checkpoint-Computer -Description 'RefyneTweaks'
```

### System

```powershell
schtasks.exe /Run /TN '\Microsoft\Windows\Servicing\StartComponentCleanup'
Start-Process -FilePath "cmd" -ArgumentList "/c wmic computersystem where name="$env:COMPUTERNAME" set AutomaticManagedPagefile=False" -Wait
Start-Process -FilePath "cmd" -ArgumentList "/c wmic pagefileset where name="C:\\pagefile.sys" set InitialSize=12000,MaximumSize=16000" -Wait
fsutil behavior set disable8dot3 1
fsutil behavior set disabledeletenotify 0
fsutil behavior set quotanotify 5400
fsutil behavior set mftzone 2
fsutil behavior set encryptpagingfile 0
fsutil behavior set memoryusage 2
fsutil behavior set disablelastaccess 1
fsutil behavior set disablecompression 1
```

### NVIDIA

```powershell
schtasks /change /disable /tn "NvTmRep_CrashReport2_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}"
schtasks /change /disable /tn "NvTmRep_CrashReport3_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}"
schtasks /change /disable /tn "NvTmRep_CrashReport1_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}"
schtasks /change /disable /tn "NvTmRep_CrashReport4_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}"
```

### Network

```powershell
netsh int tcp set supplemental Template=Internet CongestionProvider=bbr2
netsh int tcp set supplemental Template=Datacenter CongestionProvider=bbr2
netsh int tcp set supplemental Template=Compat CongestionProvider=bbr2
netsh int tcp set supplemental Template=DatacenterCustom CongestionProvider=bbr2
netsh int tcp set supplemental Template=InternetCustom CongestionProvider=bbr2
```

> Windows 11

```powershell
netsh int tcp set supplemental Template=Internet CongestionProvider=NewReno
netsh int tcp set supplemental Template=Datacenter CongestionProvider=NewReno
netsh int tcp set supplemental Template=Compat CongestionProvider=NewReno
netsh int tcp set supplemental Template=DatacenterCustom CongestionProvider=NewReno
netsh int tcp set supplemental Template=InternetCustom CongestionProvider=NewReno
```

> Windows 10

```powershell
Set-DnsClientServerAddress -InterfaceAlias $adapterName -ServerAddresses ("1.1.1.1", "1.0.0.1")
Set-DnsClientServerAddress -InterfaceAlias $adapterName -ServerAddresses ("2606:4700:4700::1111", "2606:4700:4700::1001")
```

### BCD for Memory

```powershell
bcdedit /set firstmegabytepolicy UseAll
bcdedit /set avoidlowmemory 0x8000000
bcdedit /set nolowmem Yes
bcdedit /set allowedinmemorysettings 0x0
bcdedit /set isolatedcontext No
bcdedit /set useplatformclock Yes
```

### BCD

```powershell
bcdedit /set useplatformtick yes
bcdedit /set disabledynamictick yes
bcdedit /set useplatformclock no
bcdedit /set usefirmwarepcisettings no
bcdedit /set usephysicaldestination no
bcdedit /set MSI Default
bcdedit /set configaccesspolicy Default
bcdedit /set x2apicpolicy Enable
bcdedit /set vm Yes
bcdedit /set vsmlaunchtype Off
bcdedit /deletevalue uselegacyapicmode
bcdedit /set tscsyncpolicy Enhanced
bcdedit /set linearaddress57 OptOut
bcdedit /set increaseuserva 268435328
bcdedit /set nx OptIn
bcdedit /set hypervisorlaunchtype off
```

### Misc

```powershell
Invoke-RestMethod 'https://github.com/luke-beep/ps-optimize-assemblies/raw/main/optimize-assemblies.ps1' | Invoke-Expression
Invoke-RestMethod 'https://raw.githubusercontent.com/luke-beep/GSR/main/GenerateSystemReport.ps1' | Invoke-Expression
irm https://massgrave.dev/get | iex
```

### Global Variables

```powershell
$TerminalWindowWidth = [int][System.Math]::Round($Host.UI.RawUI.WindowSize.Width / 2, [System.MidpointRounding]::AwayFromZero)
[string]$OSVersion = ((Get-CimInstance -ClassName Win32_OperatingSystem).Caption) -replace "Microsoft ", ""
[int]$WindowsVersion = if ($OSVersion -like "*Windows 11*") { 11 } elseif ($OSVersion -like "*Windows 10*") { 10 } else { 0 }
$AmdRegPath = "HKLM:\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}"
$NvRegPath = "HKLM\System\ControlSet001\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}"
$TotalMemory = (Get-CimInstance Win32_PhysicalMemory | Measure-Object -Property capacity -Sum).sum / 1gb
```

--- 

**<div align="center" id="footer">© 2024 Refyne. All rights reserved. <div>**
<br>
<div align="right"><a href="#">(Back to top)</a></div>
