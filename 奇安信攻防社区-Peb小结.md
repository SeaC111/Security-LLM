0x00 前言
=======

每个进程都会有自己独立的4GB的内存空间

0x01 本质
=======

当进程中的线程执行代码时，能访问的内容，是由进程决定的

任何进程，在0环都会有一个结构体，EPROCESS

`OpenProcess()`函数的本质：是拿到0环结构体`EPROCESS`的句柄

0x02 配置符号路径
===========

使用Windbg，正确配置符号路径

参考：<https://docs.microsoft.com/zh-cn/windows/win32/dxtecharts/debugging-with-symbols?redirectedfrom=MSDN>

path变量
------

Windbg访问符号须要两个文件(SYMSRV.DLL 和 SYMSTORE.EXE)

因此 添加上面这两个文件存在的目录 到path环境变量

我使用的是微软商店安装的Windbg Preview，它的默认路径

```php
C:\Program Files (x86)\Windows Kits\10\Debuggers\x64
```

`_NT_SYMBOL_PATH`变量
-------------------

在创建一个变量

```php
变量名:_NT_SYMBOL_PATH
变量值:SRVc:\localsymbolshttp://msdl.microsoft.com/download/symbols
```

![image-20220422230859372](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-bb99f539ef2bef47eb0b1c4d2293579e46885749.png)

0x03 进程结构体(EPROCESS)
====================

整体结构
----

采用附加进程的方式去Windbg

打开notepad.exe，在Windbg中

```php
File -> Attach to a Process -> notepad.exe
```

![image-20220425005215611](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-664b113a18d0b347c2010d5b8c897a1a53f20b32.png)

![image-20220425005230090](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-a44dd332ad780b33d1d7ac1a15057386c7b7d941.png)

查看EPROCESS结构体

```php
dt nt!_eprocess
```

```php
0:010&gt; dt nt!_eprocess
ntdll!_EPROCESS
   +0x000 Pcb              : _KPROCESS
   +0x438 ProcessLock      : _EX_PUSH_LOCK
   +0x440 UniqueProcessId  : Ptr64 Void
   +0x448 ActiveProcessLinks : _LIST_ENTRY
   +0x458 RundownProtect   : _EX_RUNDOWN_REF
   +0x460 Flags2           : Uint4B
   +0x460 JobNotReallyActive : Pos 0, 1 Bit
   +0x460 AccountingFolded : Pos 1, 1 Bit
   +0x460 NewProcessReported : Pos 2, 1 Bit
   +0x460 ExitProcessReported : Pos 3, 1 Bit
   +0x460 ReportCommitChanges : Pos 4, 1 Bit
   +0x460 LastReportMemory : Pos 5, 1 Bit
   +0x460 ForceWakeCharge  : Pos 6, 1 Bit
   +0x460 CrossSessionCreate : Pos 7, 1 Bit
   +0x460 NeedsHandleRundown : Pos 8, 1 Bit
   +0x460 RefTraceEnabled  : Pos 9, 1 Bit
   +0x460 PicoCreated      : Pos 10, 1 Bit
   +0x460 EmptyJobEvaluated : Pos 11, 1 Bit
   +0x460 DefaultPagePriority : Pos 12, 3 Bits
   +0x460 PrimaryTokenFrozen : Pos 15, 1 Bit
   +0x460 ProcessVerifierTarget : Pos 16, 1 Bit
   +0x460 RestrictSetThreadContext : Pos 17, 1 Bit
   +0x460 AffinityPermanent : Pos 18, 1 Bit
   +0x460 AffinityUpdateEnable : Pos 19, 1 Bit
   +0x460 PropagateNode    : Pos 20, 1 Bit
   +0x460 ExplicitAffinity : Pos 21, 1 Bit
   +0x460 ProcessExecutionState : Pos 22, 2 Bits
   +0x460 EnableReadVmLogging : Pos 24, 1 Bit
   +0x460 EnableWriteVmLogging : Pos 25, 1 Bit
   +0x460 FatalAccessTerminationRequested : Pos 26, 1 Bit
   +0x460 DisableSystemAllowedCpuSet : Pos 27, 1 Bit
   +0x460 ProcessStateChangeRequest : Pos 28, 2 Bits
   +0x460 ProcessStateChangeInProgress : Pos 30, 1 Bit
   +0x460 InPrivate        : Pos 31, 1 Bit
   +0x464 Flags            : Uint4B
   +0x464 CreateReported   : Pos 0, 1 Bit
   +0x464 NoDebugInherit   : Pos 1, 1 Bit
   +0x464 ProcessExiting   : Pos 2, 1 Bit
   +0x464 ProcessDelete    : Pos 3, 1 Bit
   +0x464 ManageExecutableMemoryWrites : Pos 4, 1 Bit
   +0x464 VmDeleted        : Pos 5, 1 Bit
   +0x464 OutswapEnabled   : Pos 6, 1 Bit
   +0x464 Outswapped       : Pos 7, 1 Bit
   +0x464 FailFastOnCommitFail : Pos 8, 1 Bit
   +0x464 Wow64VaSpace4Gb  : Pos 9, 1 Bit
   +0x464 AddressSpaceInitialized : Pos 10, 2 Bits
   +0x464 SetTimerResolution : Pos 12, 1 Bit
   +0x464 BreakOnTermination : Pos 13, 1 Bit
   +0x464 DeprioritizeViews : Pos 14, 1 Bit
   +0x464 WriteWatch       : Pos 15, 1 Bit
   +0x464 ProcessInSession : Pos 16, 1 Bit
   +0x464 OverrideAddressSpace : Pos 17, 1 Bit
   +0x464 HasAddressSpace  : Pos 18, 1 Bit
   +0x464 LaunchPrefetched : Pos 19, 1 Bit
   +0x464 Background       : Pos 20, 1 Bit
   +0x464 VmTopDown        : Pos 21, 1 Bit
   +0x464 ImageNotifyDone  : Pos 22, 1 Bit
   +0x464 PdeUpdateNeeded  : Pos 23, 1 Bit
   +0x464 VdmAllowed       : Pos 24, 1 Bit
   +0x464 ProcessRundown   : Pos 25, 1 Bit
   +0x464 ProcessInserted  : Pos 26, 1 Bit
   +0x464 DefaultIoPriority : Pos 27, 3 Bits
   +0x464 ProcessSelfDelete : Pos 30, 1 Bit
   +0x464 SetTimerResolutionLink : Pos 31, 1 Bit
   +0x468 CreateTime       : _LARGE_INTEGER
   +0x470 ProcessQuotaUsage : [2] Uint8B
   +0x480 ProcessQuotaPeak : [2] Uint8B
   +0x490 PeakVirtualSize  : Uint8B
   +0x498 VirtualSize      : Uint8B
   +0x4a0 SessionProcessLinks : _LIST_ENTRY
   +0x4b0 ExceptionPortData : Ptr64 Void
   +0x4b0 ExceptionPortValue : Uint8B
   +0x4b0 ExceptionPortState : Pos 0, 3 Bits
   +0x4b8 Token            : _EX_FAST_REF
   +0x4c0 MmReserved       : Uint8B
   +0x4c8 AddressCreationLock : _EX_PUSH_LOCK
   +0x4d0 PageTableCommitmentLock : _EX_PUSH_LOCK
   +0x4d8 RotateInProgress : Ptr64 _ETHREAD
   +0x4e0 ForkInProgress   : Ptr64 _ETHREAD
   +0x4e8 CommitChargeJob  : Ptr64 _EJOB
   +0x4f0 CloneRoot        : _RTL_AVL_TREE
   +0x4f8 NumberOfPrivatePages : Uint8B
   +0x500 NumberOfLockedPages : Uint8B
   +0x508 Win32Process     : Ptr64 Void
   +0x510 Job              : Ptr64 _EJOB
   +0x518 SectionObject    : Ptr64 Void
   +0x520 SectionBaseAddress : Ptr64 Void
   +0x528 Cookie           : Uint4B
   +0x530 WorkingSetWatch  : Ptr64 _PAGEFAULT_HISTORY
   +0x538 Win32WindowStation : Ptr64 Void
   +0x540 InheritedFromUniqueProcessId : Ptr64 Void
   +0x548 OwnerProcessId   : Uint8B
   +0x550 Peb              : Ptr64 _PEB
   +0x558 Session          : Ptr64 _MM_SESSION_SPACE
   +0x560 Spare1           : Ptr64 Void
   +0x568 QuotaBlock       : Ptr64 _EPROCESS_QUOTA_BLOCK
   +0x570 ObjectTable      : Ptr64 _HANDLE_TABLE
   +0x578 DebugPort        : Ptr64 Void
   +0x580 WoW64Process     : Ptr64 _EWOW64PROCESS
   +0x588 DeviceMap        : Ptr64 Void
   +0x590 EtwDataSource    : Ptr64 Void
   +0x598 PageDirectoryPte : Uint8B
   +0x5a0 ImageFilePointer : Ptr64 _FILE_OBJECT
   +0x5a8 ImageFileName    : [15] UChar
   +0x5b7 PriorityClass    : UChar
   +0x5b8 SecurityPort     : Ptr64 Void
   +0x5c0 SeAuditProcessCreationInfo : _SE_AUDIT_PROCESS_CREATION_INFO
   +0x5c8 JobLinks         : _LIST_ENTRY
   +0x5d8 HighestUserAddress : Ptr64 Void
   +0x5e0 ThreadListHead   : _LIST_ENTRY
   +0x5f0 ActiveThreads    : Uint4B
   +0x5f4 ImagePathHash    : Uint4B
   +0x5f8 DefaultHardErrorProcessing : Uint4B
   +0x5fc LastThreadExitStatus : Int4B
   +0x600 PrefetchTrace    : _EX_FAST_REF
   +0x608 LockedPagesList  : Ptr64 Void
   +0x610 ReadOperationCount : _LARGE_INTEGER
   +0x618 WriteOperationCount : _LARGE_INTEGER
   +0x620 OtherOperationCount : _LARGE_INTEGER
   +0x628 ReadTransferCount : _LARGE_INTEGER
   +0x630 WriteTransferCount : _LARGE_INTEGER
   +0x638 OtherTransferCount : _LARGE_INTEGER
   +0x640 CommitChargeLimit : Uint8B
   +0x648 CommitCharge     : Uint8B
   +0x650 CommitChargePeak : Uint8B
   +0x680 Vm               : _MMSUPPORT_FULL
   +0x7c0 MmProcessLinks   : _LIST_ENTRY
   +0x7d0 ModifiedPageCount : Uint4B
   +0x7d4 ExitStatus       : Int4B
   +0x7d8 VadRoot          : _RTL_AVL_TREE
   +0x7e0 VadHint          : Ptr64 Void
   +0x7e8 VadCount         : Uint8B
   +0x7f0 VadPhysicalPages : Uint8B
   +0x7f8 VadPhysicalPagesLimit : Uint8B
   +0x800 AlpcContext      : _ALPC_PROCESS_CONTEXT
   +0x820 TimerResolutionLink : _LIST_ENTRY
   +0x830 TimerResolutionStackRecord : Ptr64 _PO_DIAG_STACK_RECORD
   +0x838 RequestedTimerResolution : Uint4B
   +0x83c SmallestTimerResolution : Uint4B
   +0x840 ExitTime         : _LARGE_INTEGER
   +0x848 InvertedFunctionTable : Ptr64 _INVERTED_FUNCTION_TABLE
   +0x850 InvertedFunctionTableLock : _EX_PUSH_LOCK
   +0x858 ActiveThreadsHighWatermark : Uint4B
   +0x85c LargePrivateVadCount : Uint4B
   +0x860 ThreadListLock   : _EX_PUSH_LOCK
   +0x868 WnfContext       : Ptr64 Void
   +0x870 ServerSilo       : Ptr64 _EJOB
   +0x878 SignatureLevel   : UChar
   +0x879 SectionSignatureLevel : UChar
   +0x87a Protection       : _PS_PROTECTION
   +0x87b HangCount        : Pos 0, 3 Bits
   +0x87b GhostCount       : Pos 3, 3 Bits
   +0x87b PrefilterException : Pos 6, 1 Bit
   +0x87c Flags3           : Uint4B
   +0x87c Minimal          : Pos 0, 1 Bit
   +0x87c ReplacingPageRoot : Pos 1, 1 Bit
   +0x87c Crashed          : Pos 2, 1 Bit
   +0x87c JobVadsAreTracked : Pos 3, 1 Bit
   +0x87c VadTrackingDisabled : Pos 4, 1 Bit
   +0x87c AuxiliaryProcess : Pos 5, 1 Bit
   +0x87c SubsystemProcess : Pos 6, 1 Bit
   +0x87c IndirectCpuSets  : Pos 7, 1 Bit
   +0x87c RelinquishedCommit : Pos 8, 1 Bit
   +0x87c HighGraphicsPriority : Pos 9, 1 Bit
   +0x87c CommitFailLogged : Pos 10, 1 Bit
   +0x87c ReserveFailLogged : Pos 11, 1 Bit
   +0x87c SystemProcess    : Pos 12, 1 Bit
   +0x87c HideImageBaseAddresses : Pos 13, 1 Bit
   +0x87c AddressPolicyFrozen : Pos 14, 1 Bit
   +0x87c ProcessFirstResume : Pos 15, 1 Bit
   +0x87c ForegroundExternal : Pos 16, 1 Bit
   +0x87c ForegroundSystem : Pos 17, 1 Bit
   +0x87c HighMemoryPriority : Pos 18, 1 Bit
   +0x87c EnableProcessSuspendResumeLogging : Pos 19, 1 Bit
   +0x87c EnableThreadSuspendResumeLogging : Pos 20, 1 Bit
   +0x87c SecurityDomainChanged : Pos 21, 1 Bit
   +0x87c SecurityFreezeComplete : Pos 22, 1 Bit
   +0x87c VmProcessorHost  : Pos 23, 1 Bit
   +0x87c VmProcessorHostTransition : Pos 24, 1 Bit
   +0x87c AltSyscall       : Pos 25, 1 Bit
   +0x87c TimerResolutionIgnore : Pos 26, 1 Bit
   +0x87c DisallowUserTerminate : Pos 27, 1 Bit
   +0x880 DeviceAsid       : Int4B
   +0x888 SvmData          : Ptr64 Void
   +0x890 SvmProcessLock   : _EX_PUSH_LOCK
   +0x898 SvmLock          : Uint8B
   +0x8a0 SvmProcessDeviceListHead : _LIST_ENTRY
   +0x8b0 LastFreezeInterruptTime : Uint8B
   +0x8b8 DiskCounters     : Ptr64 _PROCESS_DISK_COUNTERS
   +0x8c0 PicoContext      : Ptr64 Void
   +0x8c8 EnclaveTable     : Ptr64 Void
   +0x8d0 EnclaveNumber    : Uint8B
   +0x8d8 EnclaveLock      : _EX_PUSH_LOCK
   +0x8e0 HighPriorityFaultsAllowed : Uint4B
   +0x8e8 EnergyContext    : Ptr64 _PO_PROCESS_ENERGY_CONTEXT
   +0x8f0 VmContext        : Ptr64 Void
   +0x8f8 SequenceNumber   : Uint8B
   +0x900 CreateInterruptTime : Uint8B
   +0x908 CreateUnbiasedInterruptTime : Uint8B
   +0x910 TotalUnbiasedFrozenTime : Uint8B
   +0x918 LastAppStateUpdateTime : Uint8B
   +0x920 LastAppStateUptime : Pos 0, 61 Bits
   +0x920 LastAppState     : Pos 61, 3 Bits
   +0x928 SharedCommitCharge : Uint8B
   +0x930 SharedCommitLock : _EX_PUSH_LOCK
   +0x938 SharedCommitLinks : _LIST_ENTRY
   +0x948 AllowedCpuSets   : Uint8B
   +0x950 DefaultCpuSets   : Uint8B
   +0x948 AllowedCpuSetsIndirect : Ptr64 Uint8B
   +0x950 DefaultCpuSetsIndirect : Ptr64 Uint8B
   +0x958 DiskIoAttribution : Ptr64 Void
   +0x960 DxgProcess       : Ptr64 Void
   +0x968 Win32KFilterSet  : Uint4B
   +0x970 ProcessTimerDelay : _PS_INTERLOCKED_TIMER_DELAY_VALUES
   +0x978 KTimerSets       : Uint4B
   +0x97c KTimer2Sets      : Uint4B
   +0x980 ThreadTimerSets  : Uint4B
   +0x988 VirtualTimerListLock : Uint8B
   +0x990 VirtualTimerListHead : _LIST_ENTRY
   +0x9a0 WakeChannel      : _WNF_STATE_NAME
   +0x9a0 WakeInfo         : _PS_PROCESS_WAKE_INFORMATION
   +0x9d0 MitigationFlags  : Uint4B
   +0x9d0 MitigationFlagsValues : 
   +0x9d4 MitigationFlags2 : Uint4B
   +0x9d4 MitigationFlags2Values : 
   +0x9d8 PartitionObject  : Ptr64 Void
   +0x9e0 SecurityDomain   : Uint8B
   +0x9e8 ParentSecurityDomain : Uint8B
   +0x9f0 CoverageSamplerContext : Ptr64 Void
   +0x9f8 MmHotPatchContext : Ptr64 Void
   +0xa00 DynamicEHContinuationTargetsTree : _RTL_AVL_TREE
   +0xa08 DynamicEHContinuationTargetsLock : _EX_PUSH_LOCK
   +0xa10 DynamicEnforcedCetCompatibleRanges : _PS_DYNAMIC_ENFORCED_ADDRESS_RANGES
   +0xa20 DisabledComponentFlags : Uint4B
   +0xa28 PathRedirectionHashes : Ptr64 Uint4B
```

![image-20220425005321756](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-e4de460f92619870ddbe848ec1842a6556140d43.png)

KPROCESS(主要成员)
--------------

它是进程结构体EPROCESS的主要成员，它是一个结构体，进一步查看

```php
0:010&gt; dt nt!_KPROCESS
ntdll!_KPROCESS
   +0x000 Header           : _DISPATCHER_HEADER
   +0x018 ProfileListHead  : _LIST_ENTRY
   +0x028 DirectoryTableBase : Uint8B
   +0x030 ThreadListHead   : _LIST_ENTRY
   +0x040 ProcessLock      : Uint4B
   +0x044 ProcessTimerDelay : Uint4B
   +0x048 DeepFreezeStartTime : Uint8B
   +0x050 Affinity         : _KAFFINITY_EX
   +0x0f8 AffinityPadding  : [12] Uint8B
   +0x158 ReadyListHead    : _LIST_ENTRY
   +0x168 SwapListEntry    : _SINGLE_LIST_ENTRY
   +0x170 ActiveProcessors : _KAFFINITY_EX
   +0x218 ActiveProcessorsPadding : [12] Uint8B
   +0x278 AutoAlignment    : Pos 0, 1 Bit
   +0x278 DisableBoost     : Pos 1, 1 Bit
   +0x278 DisableQuantum   : Pos 2, 1 Bit
   +0x278 DeepFreeze       : Pos 3, 1 Bit
   +0x278 TimerVirtualization : Pos 4, 1 Bit
   +0x278 CheckStackExtents : Pos 5, 1 Bit
   +0x278 CacheIsolationEnabled : Pos 6, 1 Bit
   +0x278 PpmPolicy        : Pos 7, 3 Bits
   +0x278 VaSpaceDeleted   : Pos 10, 1 Bit
   +0x278 ReservedFlags    : Pos 11, 21 Bits
   +0x278 ProcessFlags     : Int4B
   +0x27c ActiveGroupsMask : Uint4B
   +0x280 BasePriority     : Char
   +0x281 QuantumReset     : Char
   +0x282 Visited          : Char
   +0x283 Flags            : _KEXECUTE_OPTIONS
   +0x284 ThreadSeed       : [20] Uint2B
   +0x2ac ThreadSeedPadding : [12] Uint2B
   +0x2c4 IdealProcessor   : [20] Uint2B
   +0x2ec IdealProcessorPadding : [12] Uint2B
   +0x304 IdealNode        : [20] Uint2B
   +0x32c IdealNodePadding : [12] Uint2B
   +0x344 IdealGlobalNode  : Uint2B
   +0x346 Spare1           : Uint2B
   +0x348 StackCount       : _KSTACK_COUNT
   +0x350 ProcessListEntry : _LIST_ENTRY
   +0x360 CycleTime        : Uint8B
   +0x368 ContextSwitches  : Uint8B
   +0x370 SchedulingGroup  : Ptr64 _KSCHEDULING_GROUP
   +0x378 FreezeCount      : Uint4B
   +0x37c KernelTime       : Uint4B
   +0x380 UserTime         : Uint4B
   +0x384 ReadyTime        : Uint4B
   +0x388 UserDirectoryTableBase : Uint8B
   +0x390 AddressPolicy    : UChar
   +0x391 Spare2           : [71] UChar
   +0x3d8 InstrumentationCallback : Ptr64 Void
   +0x3e0 SecureState      : 
   +0x3e8 KernelWaitTime   : Uint8B
   +0x3f0 UserWaitTime     : Uint8B
   +0x3f8 EndPadding       : [8] Uint8B
```

![image-20220425005400712](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-03a5471e0a5903afd57ae4ccd5c60dda78cccb9b.png)

继续看参数

继续看参数

1、

```php
   +0x000 Header           : _DISPATCHER_HEADER
```

只要我们的结构体中包含`_DISPATCHER_HEADER`，就可以成为被等待对象

2、

```php
   +0x028 DirectoryTableBase : Uint8B
```

它是页目录表的基址，也就是cr3

1个内核，只有一个cr3，但是可以跑10个进程：

10个进程，每个进程保存自己的进程结构体`EPROCESS`

每个进程都保存着自己的cr3：`+0x018 DirectoryTableBase : [2] Uint4B`

A进程执行的时候，就把它A进程的cr3放到内核中的cr3寄存器中

B进程执行的时候，就把它B进程的cr3放到内核中的cr3寄存器中

A进程：x、y、z三个线程，三个线程使用同一个cr3，就是进程A的cr3

B进程：m、n两个线程，两个线程使用同一个cr3，就是进程B的cr3

线程切换，cr3可能并不会切换，比如x切换到y，因为他们都使用进程A的cr3

进程切换，比如x切换到m，x使用进程A的cr3，m使用进程B的cr3，所以需要切换cr3

两个进程之间的线程切换，cr3才会切换

3、

```php
   +0x37c KernelTime       : Uint4B
   +0x380 UserTime         : Uint4B
```

统计信息 记录了一个进程在内核模式/用户模式下所花的时间

4、

```php
   +0x050 Affinity         : _KAFFINITY_EX
```

规定进程里面的所有线程能在哪个CPU上跑

看哪一位为1，倒着走，分别是0号CPU、1号CPU、2号CPU、3号CPU...

如果值为1，转换成二进制`00000001`，那这个进程的所以线程只能在0号CPU上跑(00000001)---&gt;看哪一位为1  
如果值为3，转换成二进制`000000011`，那这个进程的所以线程能在0、1号CPU上跑(000000011)  
如果值为4，转换成二进制`000000100`，那这个进程的所以线程能在2号CPU上跑(000000100)  
如果值为5，转换成二进制`000000101`，那这个进程的所以线程能在0，2号CPU上跑(000000101)  
4个字节共32位 所以最多32核 Windows64位 就64核  
如果只有一个CPU 把这个设置为4 那么这个进程就死了

5、

```php
   +0x280 BasePriority     : Char
```

基础优先级或最低优先级 该进程中的所有线程最起码的优先级.

其他成员
----

1、

```php
   +0x440 UniqueProcessId  : Ptr64 Void
```

进程的编号 任务管理器中的PID

当我们把它改成0使用时，程序依然可以跑，但是某些API可能不能用了

2、

```php
   +0x448 ActiveProcessLinks : _LIST_ENTRY
```

双向链表 所有的活动进程都连接在一起，构成了一个链表`PsActiveProcessHead`指向全局链表头

它可以看到当前操作系统中，所有正在运行的进程

3、

```php
   +0x468 CreateTime       : _LARGE_INTEGER
```

进程的创建时间

4、

```php
   +0x840 ExitTime         : _LARGE_INTEGER
```

进程的退出时间

5、

```php
   +0x470 ProcessQuotaUsage : [2] Uint8B
   +0x480 ProcessQuotaPeak : [2] Uint8B
```

物理页相关的统计信息

6、

```php
   +0x4b0 ExceptionPortData : Ptr64 Void
   +0x4b0 ExceptionPortValue : Uint8B
   +0x4b0 ExceptionPortState : Pos 0, 3 Bits
   +0x578 DebugPort        : Ptr64 Void
```

调试相关

7、

```php
   +0x490 PeakVirtualSize  : Uint8B
   +0x498 VirtualSize      : Uint8B
   +0x648 CommitCharge     : Uint8B
```

虚拟内存相关的统计信息

8、

```php
   +0x570 ObjectTable      : Ptr64 _HANDLE_TABLE
```

句柄表

9、

```php
   +0x5a8 ImageFileName    : [15] UChar
```

进程镜像文件名 最多16个字节

10、

```php
   +0x5f0 ActiveThreads    : Uint4B
```

活动线程的数量

11、

```php
   +0x7d8 VadRoot          : _RTL_AVL_TREE
```

标识0-2G哪些地址没占用了

PEB
---

```php
   +0x550 Peb              : Ptr64 _PEB
```

### 前言

PEB，它是进程环境块是一个从内核分配给每个进程的用户模式结构，存放进程信息，每个进程都有自己的PEB信息。位于用户地址空间

PEB的位置取决于进程是在32位还是64位地址空间中运行

在32位进程中，可以在FS寄存器上找到具有48字节偏移量的PEB

在64位进程中，可以将其PEB定位在偏移的GS寄存器上

从Windows 2000以来，它就一直存在于 Windows 中，并且从那以后通过更新版本的 Windows 对其进行了改进

### 实操

#### 伪装CommandLine

##### 手工实现

通常的恶意进程往往特征会比较明显，我们可以伪造PEB进程环境块来伪装自己，让自己的特征不那么明显，从而增加一点存活率

查看进程的PEB内容

```php
0:010&gt; r $PEB
$peb=000000792ea25000
```

```php
0:010&gt; dt _PEB @$PEB
ntdll!_PEB
   +0x000 InheritedAddressSpace : 0 ''
   +0x001 ReadImageFileExecOptions : 0 ''
   +0x002 BeingDebugged    : 0x1 ''
   +0x003 BitField         : 0x84 ''
   +0x003 ImageUsesLargePages : 0y0
   +0x003 IsProtectedProcess : 0y0
   +0x003 IsImageDynamicallyRelocated : 0y1
   +0x003 SkipPatchingUser32Forwarders : 0y0
   +0x003 IsPackagedProcess : 0y0
   +0x003 IsAppContainer   : 0y0
   +0x003 IsProtectedProcessLight : 0y0
   +0x003 IsLongPathAwareProcess : 0y1
   +0x004 Padding0         : [4]  ""
   +0x008 Mutant           : 0xffffffff`ffffffff Void
   +0x010 ImageBaseAddress : 0x00007ff6`a4710000 Void
   +0x018 Ldr              : 0x00007ffd`2b0ba4c0 _PEB_LDR_DATA
   +0x020 ProcessParameters : 0x000001ce`40ff3390 _RTL_USER_PROCESS_PARAMETERS
   +0x028 SubSystemData    : 0x00007ffd`1f3391d0 Void
   +0x030 ProcessHeap      : 0x000001ce`40ff0000 Void
   +0x038 FastPebLock      : 0x00007ffd`2b0ba0e0 _RTL_CRITICAL_SECTION
   +0x040 AtlThunkSListPtr : (null) 
   +0x048 IFEOKey          : (null) 
   +0x050 CrossProcessFlags : 1
   +0x050 ProcessInJob     : 0y1
   +0x050 ProcessInitializing : 0y0
   +0x050 ProcessUsingVEH  : 0y0
   +0x050 ProcessUsingVCH  : 0y0
   +0x050 ProcessUsingFTH  : 0y0
   +0x050 ProcessPreviouslyThrottled : 0y0
   +0x050 ProcessCurrentlyThrottled : 0y0
   +0x050 ProcessImagesHotPatched : 0y0
   +0x050 ReservedBits0    : 0y000000000000000000000000 (0)
   +0x054 Padding1         : [4]  ""
   +0x058 KernelCallbackTable : 0x00007ffd`2a911070 Void
   +0x058 UserSharedInfoPtr : 0x00007ffd`2a911070 Void
   +0x060 SystemReserved   : 0
   +0x064 AtlThunkSListPtr32 : 0
   +0x068 ApiSetMap        : 0x000001ce`40f80000 Void
   +0x070 TlsExpansionCounter : 0
   +0x074 Padding2         : [4]  ""
   +0x078 TlsBitmap        : 0x00007ffd`2b0ba440 Void
   +0x080 TlsBitmapBits    : [2] 0xffffffff
   +0x088 ReadOnlySharedMemoryBase : 0x00007df4`81fe0000 Void
   +0x090 SharedData       : (null) 
   +0x098 ReadOnlyStaticServerData : 0x00007df4`81fe0750  -&gt; (null) 
   +0x0a0 AnsiCodePageData : 0x00007df5`84120000 Void
   +0x0a8 OemCodePageData  : 0x00007df5`84120000 Void
   +0x0b0 UnicodeCaseTableData : 0x00007df5`84150028 Void
   +0x0b8 NumberOfProcessors : 0xc
   +0x0bc NtGlobalFlag     : 0
   +0x0c0 CriticalSectionTimeout : _LARGE_INTEGER 0xffffe86d`079b8000
   +0x0c8 HeapSegmentReserve : 0x100000
   +0x0d0 HeapSegmentCommit : 0x2000
   +0x0d8 HeapDeCommitTotalFreeThreshold : 0x10000
   +0x0e0 HeapDeCommitFreeBlockThreshold : 0x1000
   +0x0e8 NumberOfHeaps    : 4
   +0x0ec MaximumNumberOfHeaps : 0x10
   +0x0f0 ProcessHeaps     : 0x00007ffd`2b0b8d40  -&gt; 0x000001ce`40ff0000 Void
   +0x0f8 GdiSharedHandleTable : 0x000001ce`41430000 Void
   +0x100 ProcessStarterHelper : (null) 
   +0x108 GdiDCAttributeList : 0x14
   +0x10c Padding3         : [4]  ""
   +0x110 LoaderLock       : 0x00007ffd`2b0b44f8 _RTL_CRITICAL_SECTION
   +0x118 OSMajorVersion   : 0xa
   +0x11c OSMinorVersion   : 0
   +0x120 OSBuildNumber    : 0x4a64
   +0x122 OSCSDVersion     : 0
   +0x124 OSPlatformId     : 2
   +0x128 ImageSubsystem   : 2
   +0x12c ImageSubsystemMajorVersion : 0xa
   +0x130 ImageSubsystemMinorVersion : 0
   +0x134 Padding4         : [4]  ""
   +0x138 ActiveProcessAffinityMask : 0xfff
   +0x140 GdiHandleBuffer  : [60] 0
   +0x230 PostProcessInitRoutine : (null) 
   +0x238 TlsExpansionBitmap : 0x00007ffd`2b0ba420 Void
   +0x240 TlsExpansionBitmapBits : [32] 1
   +0x2c0 SessionId        : 2
   +0x2c4 Padding5         : [4]  ""
   +0x2c8 AppCompatFlags   : _ULARGE_INTEGER 0x0
   +0x2d0 AppCompatFlagsUser : _ULARGE_INTEGER 0x0
   +0x2d8 pShimData        : 0x000001ce`40fc0000 Void
   +0x2e0 AppCompatInfo    : (null) 
   +0x2e8 CSDVersion       : _UNICODE_STRING ""
   +0x2f8 ActivationContextData : 0x000001ce`40fb0000 _ACTIVATION_CONTEXT_DATA
   +0x300 ProcessAssemblyStorageMap : 0x000001ce`40ffc1c0 _ASSEMBLY_STORAGE_MAP
   +0x308 SystemDefaultActivationContextData : 0x000001ce`40fa0000 _ACTIVATION_CONTEXT_DATA
   +0x310 SystemAssemblyStorageMap : (null) 
   +0x318 MinimumStackCommit : 0
   +0x320 SparePointers    : [4] (null) 
   +0x340 SpareUlongs      : [5] 0
   +0x358 WerRegistrationData : 0x000001ce`42e80000 Void
   +0x360 WerShipAssertPtr : (null) 
   +0x368 pUnused          : (null) 
   +0x370 pImageHeaderHash : (null) 
   +0x378 TracingFlags     : 0
   +0x378 HeapTracingEnabled : 0y0
   +0x378 CritSecTracingEnabled : 0y0
   +0x378 LibLoaderTracingEnabled : 0y0
   +0x378 SpareTracingBits : 0y00000000000000000000000000000 (0)
   +0x37c Padding6         : [4]  ""
   +0x380 CsrServerReadOnlySharedMemoryBase : 0x00007df4`89e00000
   +0x388 TppWorkerpListLock : 0
   +0x390 TppWorkerpList   : _LIST_ENTRY [ 0x00000079`2e94f7b0 - 0x00000079`2edff7b0 ]
   +0x3a0 WaitOnAddressHashTable : [128] (null) 
   +0x7a0 TelemetryCoverageHeader : (null) 
   +0x7a8 CloudFileFlags   : 0xe0
   +0x7ac CloudFileDiagFlags : 0
   +0x7b0 PlaceholderCompatibilityMode : 2 ''
   +0x7b1 PlaceholderCompatibilityModeReserved : [7]  ""
   +0x7b8 LeapSecondData   : 0x00007df5`84110000 _LEAP_SECOND_DATA
   +0x7c0 LeapSecondFlags  : 0
   +0x7c0 SixtySecondEnabled : 0y0
   +0x7c0 Reserved         : 0y0000000000000000000000000000000 (0)
   +0x7c4 NtGlobalFlag2    : 0
```

![image-20220425005535477](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-44888ab907a16a2acf256f6e04bc6d66e2a73386.png)

在`0x00007ff7`b98c0000`处为：ImageBaseAddress

```php
   +0x010 ImageBaseAddress : 0x00007ff6`a4710000 Void
```

查看其内容

```php
db 0x00007ff6`a4710000 L300
```

```php
0:010&gt; db 0x00007ff6`a4710000 L300
00007ff6`a4710000  4d 5a 90 00 03 00 00 00-04 00 00 00 ff ff 00 00  MZ..............
00007ff6`a4710010  b8 00 00 00 00 00 00 00-40 00 00 00 00 00 00 00  ........@.......
00007ff6`a4710020  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
00007ff6`a4710030  00 00 00 00 00 00 00 00-00 00 00 00 f8 00 00 00  ................
00007ff6`a4710040  0e 1f ba 0e 00 b4 09 cd-21 b8 01 4c cd 21 54 68  ........!..L.!Th
00007ff6`a4710050  69 73 20 70 72 6f 67 72-61 6d 20 63 61 6e 6e 6f  is program canno
00007ff6`a4710060  74 20 62 65 20 72 75 6e-20 69 6e 20 44 4f 53 20  t be run in DOS 
00007ff6`a4710070  6d 6f 64 65 2e 0d 0d 0a-24 00 00 00 00 00 00 00  mode....$.......
00007ff6`a4710080  65 39 d7 77 21 58 b9 24-21 58 b9 24 21 58 b9 24  e9.w!X.$!X.$!X.$
00007ff6`a4710090  28 20 2a 24 11 58 b9 24-35 33 bd 25 2b 58 b9 24  ( *$.X.$53.%+X.$
00007ff6`a47100a0  35 33 ba 25 22 58 b9 24-35 33 b8 25 28 58 b9 24  53.%"X.$53.%(X.$
00007ff6`a47100b0  21 58 b8 24 09 5d b9 24-35 33 b1 25 3f 58 b9 24  !X.$.].$53.%?X.$
00007ff6`a47100c0  35 33 bc 25 3e 58 b9 24-35 33 44 24 20 58 b9 24  53.%&gt;X.$53D$ X.$
00007ff6`a47100d0  35 33 46 24 20 58 b9 24-35 33 bb 25 20 58 b9 24  53F$ X.$53.% X.$
00007ff6`a47100e0  52 69 63 68 21 58 b9 24-00 00 00 00 00 00 00 00  Rich!X.$........
00007ff6`a47100f0  00 00 00 00 00 00 00 00-50 45 00 00 64 86 07 00  ........PE..d...
00007ff6`a4710100  d3 ae 78 41 00 00 00 00-00 00 00 00 f0 00 22 00  ..xA..........".
00007ff6`a4710110  0b 02 0e 14 00 4a 02 00-00 e0 00 00 00 00 00 00  .....J..........
00007ff6`a4710120  50 40 02 00 00 10 00 00-00 00 71 a4 f6 7f 00 00  P@........q.....
00007ff6`a4710130  00 10 00 00 00 02 00 00-0a 00 00 00 0a 00 00 00  ................
00007ff6`a4710140  0a 00 00 00 00 00 00 00-00 80 03 00 00 04 00 00  ................
00007ff6`a4710150  81 7b 03 00 02 00 60 c1-00 00 08 00 00 00 00 00  .{....`.........
00007ff6`a4710160  00 10 01 00 00 00 00 00-00 00 10 00 00 00 00 00  ................
00007ff6`a4710170  00 10 00 00 00 00 00 00-00 00 00 00 10 00 00 00  ................
00007ff6`a4710180  00 00 00 00 00 00 00 00-a8 d0 02 00 44 02 00 00  ............D...
00007ff6`a4710190  00 60 03 00 d8 0b 00 00-00 30 03 00 ec 10 00 00  .`.......0......
00007ff6`a47101a0  00 00 00 00 00 00 00 00-00 70 03 00 d4 02 00 00  .........p......
00007ff6`a47101b0  20 ac 02 00 54 00 00 00-00 00 00 00 00 00 00 00   ...T...........
00007ff6`a47101c0  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
00007ff6`a47101d0  d0 66 02 00 18 01 00 00-00 00 00 00 00 00 00 00  .f..............
00007ff6`a47101e0  e8 67 02 00 00 09 00 00-c0 c9 02 00 e0 00 00 00  .g..............
00007ff6`a47101f0  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
00007ff6`a4710200  2e 74 65 78 74 00 00 00-0f 49 02 00 00 10 00 00  .text....I......
00007ff6`a4710210  00 4a 02 00 00 04 00 00-00 00 00 00 00 00 00 00  .J..............
00007ff6`a4710220  00 00 00 00 20 00 00 60-2e 72 64 61 74 61 00 00  .... ..`.rdata..
00007ff6`a4710230  68 92 00 00 00 60 02 00-00 94 00 00 00 4e 02 00  h....`.......N..
00007ff6`a4710240  00 00 00 00 00 00 00 00-00 00 00 00 40 00 00 40  ............@..@
00007ff6`a4710250  2e 64 61 74 61 00 00 00-38 27 00 00 00 00 03 00  .data...8'......
00007ff6`a4710260  00 0e 00 00 00 e2 02 00-00 00 00 00 00 00 00 00  ................
00007ff6`a4710270  00 00 00 00 40 00 00 c0-2e 70 64 61 74 61 00 00  ....@....pdata..
00007ff6`a4710280  ec 10 00 00 00 30 03 00-00 12 00 00 00 f0 02 00  .....0..........
00007ff6`a4710290  00 00 00 00 00 00 00 00-00 00 00 00 40 00 00 40  ............@..@
00007ff6`a47102a0  2e 64 69 64 61 74 00 00-78 01 00 00 00 50 03 00  .didat..x....P..
00007ff6`a47102b0  00 02 00 00 00 02 03 00-00 00 00 00 00 00 00 00  ................
00007ff6`a47102c0  00 00 00 00 40 00 00 c0-2e 72 73 72 63 00 00 00  ....@....rsrc...
00007ff6`a47102d0  d8 0b 00 00 00 60 03 00-00 0c 00 00 00 04 03 00  .....`..........
00007ff6`a47102e0  00 00 00 00 00 00 00 00-00 00 00 00 40 00 00 40  ............@..@
00007ff6`a47102f0  2e 72 65 6c 6f 63 00 00-d4 02 00 00 00 70 03 00  .reloc.......p..
```

![image-20220425005707088](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-f4577e7c2db4cac226452d4b76b9a07b8e711be6.png)

更改这个进程的命令行参数，用到的是ProcessParameters

我们可以看到它的结构体为：`_RTL_USER_PROCESS_PARAMETERS`

```php
   +0x020 ProcessParameters : 0x000001ce`40ff3390 _RTL_USER_PROCESS_PARAMETERS
```

```php
0:011&gt; dt _PEB @$PEB ProcessP*
ntdll!_PEB
   +0x020 ProcessParameters : 0x000001ce`40ff3390 _RTL_USER_PROCESS_PARAMETERS
   +0x050 ProcessPreviouslyThrottled : 0y0
```

查看其内容

```php
0:010&gt; dt _RTL_USER_PROCESS_PARAMETERS 0x000001ce`40ff3390
ntdll!_RTL_USER_PROCESS_PARAMETERS
   +0x000 MaximumLength    : 0x78a
   +0x004 Length           : 0x78a
   +0x008 Flags            : 0x6001
   +0x00c DebugFlags       : 0
   +0x010 ConsoleHandle    : (null) 
   +0x018 ConsoleFlags     : 0
   +0x020 StandardInput    : (null) 
   +0x028 StandardOutput   : 0x00000000`00010001 Void
   +0x030 StandardError    : (null) 
   +0x038 CurrentDirectory : _CURDIR
   +0x050 DllPath          : _UNICODE_STRING ""
   +0x060 ImagePathName    : _UNICODE_STRING "C:\WINDOWS\system32\notepad.exe"
   +0x070 CommandLine      : _UNICODE_STRING ""C:\WINDOWS\system32\notepad.exe" "
   +0x080 Environment      : 0x000001ce`40ff0fe0 Void
   +0x088 StartingX        : 0
   +0x08c StartingY        : 0
   +0x090 CountX           : 0
   +0x094 CountY           : 0
   +0x098 CountCharsX      : 0
   +0x09c CountCharsY      : 0
   +0x0a0 FillAttribute    : 0
   +0x0a4 WindowFlags      : 0xc01
   +0x0a8 ShowWindowFlags  : 1
   +0x0b0 WindowTitle      : _UNICODE_STRING "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Accessories\Notepad.lnk"
   +0x0c0 DesktopInfo      : _UNICODE_STRING "Winsta0\Default"
   +0x0d0 ShellInfo        : _UNICODE_STRING ""
   +0x0e0 RuntimeData      : _UNICODE_STRING ""
   +0x0f0 CurrentDirectores : [32] _RTL_DRIVE_LETTER_CURDIR
   +0x3f0 EnvironmentSize  : 0x23a4
   +0x3f8 EnvironmentVersion : 3
   +0x400 PackageDependencyData : (null) 
   +0x408 ProcessGroupId   : 0x6dc8
   +0x40c LoaderThreads    : 0
   +0x410 RedirectionDllName : _UNICODE_STRING ""
   +0x420 HeapPartitionName : _UNICODE_STRING ""
   +0x430 DefaultThreadpoolCpuSetMasks : (null) 
   +0x438 DefaultThreadpoolCpuSetMaskCount : 0
   +0x43c DefaultThreadpoolThreadMaximum : 0
```

![image-20220425005831056](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-36fb9f24e61f234652318db42d7006ac678a1743.png)

其中的Commandline就是我们需要更改的项，其为一个`_UNICODE_STRING`结构

```php
   +0x070 CommandLine      : _UNICODE_STRING ""C:\WINDOWS\system32\notepad.exe" "
```

进一步查看它的结构，地址+偏移即可

可以看到在 0x00000204`dfc73958 处就是我们需要更改的内容

```php
0:010&gt; dt _UNICODE_STRING 0x000001ce`40ff3390+0x070
ntdll!_UNICODE_STRING
 ""C:\WINDOWS\system32\notepad.exe" "
   +0x000 Length           : 0x44
   +0x002 MaximumLength    : 0x46
   +0x008 Buffer           : 0x000001ce`40ff3a18  ""C:\WINDOWS\system32\notepad.exe" "
```

![image-20220425005928670](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-2824225ec25ef8420e42ed6a604bf6382bf9a3a6.png)

使用db也可以看到

```php
0:010&gt; db 0x000001ce`40ff3a18
000001ce`40ff3a18  22 00 43 00 3a 00 5c 00-57 00 49 00 4e 00 44 00  ".C.:.\.W.I.N.D.
000001ce`40ff3a28  4f 00 57 00 53 00 5c 00-73 00 79 00 73 00 74 00  O.W.S.\.s.y.s.t.
000001ce`40ff3a38  65 00 6d 00 33 00 32 00-5c 00 6e 00 6f 00 74 00  e.m.3.2.\.n.o.t.
000001ce`40ff3a48  65 00 70 00 61 00 64 00-2e 00 65 00 78 00 65 00  e.p.a.d...e.x.e.
000001ce`40ff3a58  22 00 20 00 00 00 43 00-3a 00 5c 00 50 00 72 00  ". ...C.:.\.P.r.
000001ce`40ff3a68  6f 00 67 00 72 00 61 00-6d 00 44 00 61 00 74 00  o.g.r.a.m.D.a.t.
000001ce`40ff3a78  61 00 5c 00 4d 00 69 00-63 00 72 00 6f 00 73 00  a.\.M.i.c.r.o.s.
000001ce`40ff3a88  6f 00 66 00 74 00 5c 00-57 00 69 00 6e 00 64 00  o.f.t.\.W.i.n.d.
```

![image-20220425010004402](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-7eed64b71918897363d49909222c217bc17959e5.png)

使用ProcessHacker，查看notepad.exe进程

下载地址：<https://processhacker.sourceforge.io/downloads.php>

![image-20220425010114500](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-9bff4a80791492fbf963b23d2b867e3c193786bd.png)

将其指向的字符串进行修改

```php
eu 0x000001ce`40ff3a18 "C:\\Windows\\System32\\matrix.exe"
```

进行查看

```php
0:010&gt; dt _UNICODE_STRING 0x000001ce`40ff3390+0x070
ntdll!_UNICODE_STRING
 "C:\Windows\System32\matrix.exexe" "
   +0x000 Length           : 0x44
   +0x002 MaximumLength    : 0x46
   +0x008 Buffer           : 0x000001ce`40ff3a18  "C:\Windows\System32\matrix.exexe" "
```

![image-20220425010308245](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-51a8a1737732c65ae54e89f205c0acf2a3b6ef90.png)

重启使用ProcessHacker，查看notepad.exe进程

成功修改

![image-20220425010452379](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-1c48bed11f13fad6792756e9e3e4c44351e68618.png)

##### 代码实现

使用`NtQueryInformationProcess` API函数

参考：<https://docs.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess>

(我这里在啰嗦一下)

作用：查看进程的信息

结构定义：

```php
__kernel_entry NTSTATUS NtQueryInformationProcess(
  [in]            HANDLE           ProcessHandle,              
  [in]            PROCESSINFOCLASS ProcessInformationClass,    
  [out]           PVOID            ProcessInformation,         
  [in]            ULONG            ProcessInformationLength,
  [out, optional] PULONG           ReturnLength
);
```

注：该函数并没有被微软公开，它在Ntdll.dll 里导出的，所以要想调用此函数，得用LoadLibrary和GetProcAddress来加载  
用的时候要`#include`头文件  
参数介绍：

```php
[in] ProcessHandle:要检索其信息的进程的句柄
[in] ProcessInformationClass:要检索的进程信息的类型，它是一个 PROCESSINFOCLASS 的枚举类型，可以取值:
ProcessBasicInformation         0
ProcessDebugPort                7
ProcessWow64Information         26
ProcessImageFileName            27
ProcessBreakOnTermination       29

[out] ProcessInformation:要存放查询结果的缓冲区，这个结构要根据第二个参数取值来决定
ProcessInformationLength:缓冲区大小
ReturnLength:实际返回的写入缓冲区的字节数
```

继续看一下`ProcessBasicInformation`这个结构，**该结构体的第二个参数是指向PEB的指针**

官方定义如下：

```php
typedef struct _PROCESS_BASIC_INFORMATION {
    PVOID Reserved1;
    PPEB PebBaseAddress;
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID Reserved3;
} PROCESS_BASIC_INFORMATION;
```

注：修改字符串的同时最好也要修改该结构体的Lenght的成员，使用修改指针的方式实现

代码示例

```php
#include 
#include 
#include 
#include 

// 定义函数指针
typedef DWORD(*pNtQueryInformationProcess)(
    _In_      HANDLE           ProcessHandle,
    _In_      PROCESSINFOCLASS ProcessInformationClass,
    _Out_     PVOID            ProcessInformation,
    _In_      ULONG            ProcessInformationLength,
    _Out_opt_ PULONG           ReturnLength
);

int main()
{
    HANDLE hProcess = 0;
    ULONG length = 0;
    HMODULE hModule;
    PROCESS_BASIC_INFORMATION ProcessInformation;
    pNtQueryInformationProcess NtQueryInformationProcess;
    wchar_t CommandLine[] = L"C:\\Windows\\system32\\notepad.exe";

    hModule = LoadLibraryA("Ntdll.dll");

    // 返回值是当前进程的伪句柄
    // 此句柄具有对进程对象的 PROCESS_ALL_ACCESS 访问权限
    // 当不再需要伪句柄时，不需要关闭它
    hProcess = GetCurrentProcess();

    // 获取ntdll.dll中 NtQueryInformationProcess 函数的地址
    NtQueryInformationProcess = (pNtQueryInformationProcess)GetProcAddress(hModule, "NtQueryInformationProcess");

    // 获取PEB
    NtQueryInformationProcess(hProcess, ProcessBasicInformation, &amp;ProcessInformation, sizeof(ProcessInformation), &amp;length);

    ProcessInformation.PebBaseAddress-&gt;ProcessParameters-&gt;CommandLine.Length = sizeof(CommandLine);
    ProcessInformation.PebBaseAddress-&gt;ProcessParameters-&gt;CommandLine.Buffer = (PWSTR)&amp;CommandLine;

    getchar();
    return 0;
}
```

![image-20220425011005770](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-77c44918f25c192d19605b379d4558355367160b.png)

#### 查看调用的dll

操作系统会在ring3维护一个结构体PEB(进程环境块)

x86环境下，段寄存器`FS:[00]`在三环时始终指向TEB(线程环境块)，TEB偏移0x30则指向该进程的PEB

x64环境下，段寄存器`GS:[00]`在三环时始终指向TEB(线程环境块)，TEB偏移0x60则指向该进程的PEB

通常我们可以使用内联汇编的方式获取PEB位于内存的虚拟地址

```php
mov eax, fs: [0x30] ;x86

mov eax, gs: [0x60] ;x64
```

通过Windbg定位TEB-&gt;PEB

```php
0:010&gt; r $TEB
$teb=000000792ea3c000
```

```php
0:010&gt; dt _TEB @$TEB
ntdll!_TEB
   +0x000 NtTib            : _NT_TIB
   +0x038 EnvironmentPointer : (null) 
   +0x040 ClientId         : _CLIENT_ID
   +0x050 ActiveRpcHandle  : (null) 
   +0x058 ThreadLocalStoragePointer : (null) 
   +0x060 ProcessEnvironmentBlock : 0x00000079`2ea25000 _PEB
   +0x068 LastErrorValue   : 0
   +0x06c CountOfOwnedCriticalSections : 0
   +0x070 CsrClientThread  : (null) 
   +0x078 Win32ThreadInfo  : (null) 
   +0x080 User32Reserved   : [26] 0
   +0x0e8 UserReserved     : [5] 0
   +0x100 WOW32Reserved    : (null) 
   +0x108 CurrentLocale    : 0x804
   +0x10c FpSoftwareStatusRegister : 0
   +0x110 ReservedForDebuggerInstrumentation : [16] (null) 
   +0x190 SystemReserved1  : [30] (null) 
   +0x280 PlaceholderCompatibilityMode : 0 ''
   +0x281 PlaceholderHydrationAlwaysExplicit : 0 ''
   +0x282 PlaceholderReserved : [10]  ""
   +0x28c ProxiedProcessId : 0
   +0x290 _ActivationStack : _ACTIVATION_CONTEXT_STACK
   +0x2b8 WorkingOnBehalfTicket : [8]  ""
   +0x2c0 ExceptionCode    : 0n0
   +0x2c4 Padding0         : [4]  ""
   +0x2c8 ActivationContextStackPointer : 0x00000079`2ea3c290 _ACTIVATION_CONTEXT_STACK
   +0x2d0 InstrumentationCallbackSp : 0
   +0x2d8 InstrumentationCallbackPreviousPc : 0
   +0x2e0 InstrumentationCallbackPreviousSp : 0
   +0x2e8 TxFsContext      : 0xfffe
   +0x2ec InstrumentationCallbackDisabled : 0 ''
   +0x2ed UnalignedLoadStoreExceptions : 0 ''
   +0x2ee Padding1         : [2]  ""
   +0x2f0 GdiTebBatch      : _GDI_TEB_BATCH
   +0x7d8 RealClientId     : _CLIENT_ID
   +0x7e8 GdiCachedProcessHandle : (null) 
   +0x7f0 GdiClientPID     : 0
   +0x7f4 GdiClientTID     : 0
   +0x7f8 GdiThreadLocalInfo : (null) 
   +0x800 Win32ClientInfo  : [62] 0
   +0x9f0 glDispatchTable  : [233] (null) 
   +0x1138 glReserved1      : [29] 0
   +0x1220 glReserved2      : (null) 
   +0x1228 glSectionInfo    : (null) 
   +0x1230 glSection        : (null) 
   +0x1238 glTable          : (null) 
   +0x1240 glCurrentRC      : (null) 
   +0x1248 glContext        : (null) 
   +0x1250 LastStatusValue  : 0
   +0x1254 Padding2         : [4]  ""
   +0x1258 StaticUnicodeString : _UNICODE_STRING ""
   +0x1268 StaticUnicodeBuffer : [261]  ""
   +0x1472 Padding3         : [6]  ""
   +0x1478 DeallocationStack : 0x00000079`2ef80000 Void
   +0x1480 TlsSlots         : [64] (null) 
   +0x1680 TlsLinks         : _LIST_ENTRY [ 0x00000000`00000000 - 0x00000000`00000000 ]
   +0x1690 Vdm              : (null) 
   +0x1698 ReservedForNtRpc : (null) 
   +0x16a0 DbgSsReserved    : [2] (null) 
   +0x16b0 HardErrorMode    : 0
   +0x16b4 Padding4         : [4]  ""
   +0x16b8 Instrumentation  : [11] (null) 
   +0x1710 ActivityId       : _GUID {00000000-0000-0000-0000-000000000000}
   +0x1720 SubProcessTag    : (null) 
   +0x1728 PerflibData      : (null) 
   +0x1730 EtwTraceData     : (null) 
   +0x1738 WinSockData      : (null) 
   +0x1740 GdiBatchCount    : 0
   +0x1744 CurrentIdealProcessor : _PROCESSOR_NUMBER
   +0x1744 IdealProcessorValue : 0
   +0x1744 ReservedPad0     : 0 ''
   +0x1745 ReservedPad1     : 0 ''
   +0x1746 ReservedPad2     : 0 ''
   +0x1747 IdealProcessor   : 0 ''
   +0x1748 GuaranteedStackBytes : 0
   +0x174c Padding5         : [4]  ""
   +0x1750 ReservedForPerf  : (null) 
   +0x1758 ReservedForOle   : (null) 
   +0x1760 WaitingOnLoaderLock : 0
   +0x1764 Padding6         : [4]  ""
   +0x1768 SavedPriorityState : (null) 
   +0x1770 ReservedForCodeCoverage : 0
   +0x1778 ThreadPoolData   : (null) 
   +0x1780 TlsExpansionSlots : (null) 
   +0x1788 DeallocationBStore : (null) 
   +0x1790 BStoreLimit      : (null) 
   +0x1798 MuiGeneration    : 0
   +0x179c IsImpersonating  : 0
   +0x17a0 NlsCache         : (null) 
   +0x17a8 pShimData        : (null) 
   +0x17b0 HeapData         : 0
   +0x17b4 Padding7         : [4]  ""
   +0x17b8 CurrentTransactionHandle : (null) 
   +0x17c0 ActiveFrame      : (null) 
   +0x17c8 FlsData          : (null) 
   +0x17d0 PreferredLanguages : (null) 
   +0x17d8 UserPrefLanguages : (null) 
   +0x17e0 MergedPrefLanguages : (null) 
   +0x17e8 MuiImpersonation : 0
   +0x17ec CrossTebFlags    : 0
   +0x17ec SpareCrossTebBits : 0y0000000000000000 (0)
   +0x17ee SameTebFlags     : 8
   +0x17ee SafeThunkCall    : 0y0
   +0x17ee InDebugPrint     : 0y0
   +0x17ee HasFiberData     : 0y0
   +0x17ee SkipThreadAttach : 0y1
   +0x17ee WerInShipAssertCode : 0y0
   +0x17ee RanProcessInit   : 0y0
   +0x17ee ClonedThread     : 0y0
   +0x17ee SuppressDebugMsg : 0y0
   +0x17ee DisableUserStackWalk : 0y0
   +0x17ee RtlExceptionAttached : 0y0
   +0x17ee InitialThread    : 0y0
   +0x17ee SessionAware     : 0y0
   +0x17ee LoadOwner        : 0y0
   +0x17ee LoaderWorker     : 0y0
   +0x17ee SkipLoaderInit   : 0y0
   +0x17ee SpareSameTebBits : 0y0
   +0x17f0 TxnScopeEnterCallback : (null) 
   +0x17f8 TxnScopeExitCallback : (null) 
   +0x1800 TxnScopeContext  : (null) 
   +0x1808 LockCount        : 0
   +0x180c WowTebOffset     : 0n0
   +0x1810 ResourceRetValue : (null) 
   +0x1818 ReservedForWdf   : (null) 
   +0x1820 ReservedForCrt   : 0
   +0x1828 EffectiveContainerId : _GUID {00000000-0000-0000-0000-000000000000}
```

PEB在

```php
   +0x060 ProcessEnvironmentBlock : 0x00000079`2ea25000 _PEB
```

在PEB偏移`0x018`位置存在着三条模块链表

```php
   +0x018 Ldr              : 0x00007ffd`2b0ba4c0 _PEB_LDR_DATA
```

使用汇编获取

```php
mov eax, [eax + 0x018]; x64

mov eax, [eax + 0x0c] ;x86
```

根据链表含义分别是 模块加载顺序、模块初始化顺序、模块内存顺序

```php
0:010&gt; dt _PEB_LDR_DATA 0x00007ffd`2b0ba4c0
ntdll!_PEB_LDR_DATA
   +0x000 Length           : 0x58
   +0x004 Initialized      : 0x1 ''
   +0x008 SsHandle         : (null) 
   +0x010 InLoadOrderModuleList : _LIST_ENTRY [ 0x000001ce`40ff3dc0 - 0x000001ce`410232d0 ]
   +0x020 InMemoryOrderModuleList : _LIST_ENTRY [ 0x000001ce`40ff3dd0 - 0x000001ce`410232e0 ]
   +0x030 InInitializationOrderModuleList : _LIST_ENTRY [ 0x000001ce`40ff3c50 - 0x000001ce`410232f0 ]
   +0x040 EntryInProgress  : (null) 
   +0x048 ShutdownInProgress : 0 ''
   +0x050 ShutdownThreadId : (null) 
```

这三个双向链表`LIST_ENTRY`，链表的每一个都是指向`_LDR_DATA_TABLE_ENTRY`结构的指针

它们分别代表**模块加载顺序，模块在内存中的加载顺序、模块初始化装载的顺序**

`_PEB_LDR_DATA`的定义如下

```php
typedef struct _PEB_LDR_DATA {
    ULONG Length;
    ULONG Initialized;
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;
```

`_LDR_DATA_TABLE_ENTRY`的定义如下

```php
typedef struct _LDR_DATA_TABLE_ENTRY {
    PVOID Reserved1[2];
    LIST_ENTRY InMemoryOrderLinks;
    PVOID Reserved2[2];
    PVOID DllBase; // 模块基地址
    PVOID EntryPoint;
    PVOID Reserved3;
    UNICODE_STRING FullDllName;// 模块名称
    BYTE Reserved4[8];
    PVOID Reserved5[3];
    union {
        ULONG CheckSum;
        PVOID Reserved6;
    };
    ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;
```

我们用到的是其中的`InMemoryOrderModuleList` ，它在`_LIST_ENTRY`与`_LDR_DATA_TABLE_ENTRY`之中

```php
0:010&gt; dt _LIST_ENTRY 0x000001ce`40ff3dd0
ntdll!_LIST_ENTRY
 [ 0x000001ce`40ff3c40 - 0x00007ffd`2b0ba4e0 ]
   +0x000 Flink            : 0x000001ce`40ff3c40 _LIST_ENTRY [ 0x000001ce`40ff4290 - 0x000001ce`40ff3dd0 ]
   +0x008 Blink            : 0x00007ffd`2b0ba4e0 _LIST_ENTRY [ 0x000001ce`40ff3dd0 - 0x000001ce`410232e0 ]
```

```php
0:010&gt; dt _LDR_DATA_TABLE_ENTRY 0x000001ce`40ff3dd0
ntdll!_LDR_DATA_TABLE_ENTRY
   +0x000 InLoadOrderLinks : _LIST_ENTRY [ 0x000001ce`40ff3c40 - 0x00007ffd`2b0ba4e0 ]
   +0x010 InMemoryOrderLinks : _LIST_ENTRY [ 0x00000000`00000000 - 0x00000000`00000000 ]
   +0x020 InInitializationOrderLinks : _LIST_ENTRY [ 0x00007ff6`a4710000 - 0x00007ff6`a4734050 ]
   +0x030 DllBase          : 0x00000000`00038000 Void
   +0x038 EntryPoint       : 0x00000000`0040003e Void
   +0x040 SizeOfImage      : 0x40ff39d8
   +0x048 FullDllName      : _UNICODE_STRING "notepad.exe"
   +0x058 BaseDllName      : _UNICODE_STRING "雰䄀ǎ"
   +0x068 FlagGroup        : [4]  "???"
   +0x068 Flags            : 0x2b0ba190
   +0x068 PackagedBinary   : 0y0
   +0x068 MarkedForRemoval : 0y0
   +0x068 ImageDll         : 0y0
   +0x068 LoadNotificationsSent : 0y0
   +0x068 TelemetryEntryProcessed : 0y1
   +0x068 ProcessStaticImport : 0y0
   +0x068 InLegacyLists    : 0y0
   +0x068 InIndexes        : 0y1
   +0x068 ShimDll          : 0y1
   +0x068 InExceptionTable : 0y0
   +0x068 ReservedFlags1   : 0y00
   +0x068 LoadInProgress   : 0y0
   +0x068 LoadConfigProcessed : 0y1
   +0x068 EntryProcessed   : 0y0
   +0x068 ProtectDelayLoad : 0y1
   +0x068 ReservedFlags3   : 0y11
   +0x068 DontCallForThreads : 0y0
   +0x068 ProcessAttachCalled : 0y1
   +0x068 ProcessAttachFailed : 0y0
   +0x068 CorDeferredValidate : 0y0
   +0x068 CorImage         : 0y0
   +0x068 DontRelocate     : 0y0
   +0x068 CorILOnly        : 0y1
   +0x068 ChpeImage        : 0y1
   +0x068 ReservedFlags5   : 0y10
   +0x068 Redirected       : 0y0
   +0x068 ReservedFlags6   : 0y01
   +0x068 CompatDatabaseProcessed : 0y0
   +0x06c ObsoleteLoadCount : 0x7ffd
   +0x06e TlsIndex         : 0
   +0x070 HashLinks        : _LIST_ENTRY [ 0x00000000`4178aed3 - 0x00000000`00000000 ]
   +0x080 TimeDateStamp    : 0
   +0x088 EntryPointActivationContext : 0x000001ce`40ff3ef0 _ACTIVATION_CONTEXT
   +0x090 Lock             : 0x000001ce`40ff3ef0 Void
   +0x098 DdagNode         : 0x000001ce`40ff3ef0 _LDR_DDAG_NODE
   +0x0a0 NodeModuleLink   : _LIST_ENTRY [ 0x00000000`00000000 - 0x00000000`00000000 ]
   +0x0b0 LoadContext      : 0x00007ffd`2b06c3a4 _LDRP_LOAD_CONTEXT
   +0x0b8 ParentDllBase    : (null) 
   +0x0c0 SwitchBackContext : (null) 
   +0x0c8 BaseAddressIndexNode : _RTL_BALANCED_NODE
   +0x0e0 MappingInfoIndexNode : _RTL_BALANCED_NODE
   +0x0f8 OriginalBase     : 0x00000004`4c900b25
   +0x100 LoadTime         : _LARGE_INTEGER 0x00000002`00000000
   +0x108 BaseNameHashValue : 0
   +0x10c LoadReason       : 0 ( LoadReasonStaticDependency )
   +0x110 ImplicitPathOptions : 0
   +0x114 ReferenceCount   : 0
   +0x118 DependentLoadFlags : 0xe93fdc0b
   +0x11c SigningLevel     : 0xf ''
```

![image-20220425012124256](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-faecd6a1f40598c616533fa2dd94924a7885eb70.png)

因为它是一个内存区域我们可以用循环的方式来遍历它

```php
!list -x "dt _LDR_DATA_TABLE_ENTRY" 0x000001ce`40ff3dd0
```

注：这里我就不贴输出了

![image-20220425012323850](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-c2698cfca914971d3483de75550eb84d69a15fe6.png)

跟进其结构，实现模块断链隐藏dll也是没问题的

使用`!dlls`也可以达到同样的效果

注：这里我就不贴输出了

![image-20220425012251199](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-2295418b52cf7b343ab965336835d14dcd82c872.png)

### 获取PEB

PEB结构非常复杂

贴一下大佬们整理好的头文件，方便相关结构体调用

<http://bytepointer.com/resources/tebpeb32.htm>

<http://bytepointer.com/resources/tebpeb64.htm>

#### NtQueryInformationProcess

NtQueryInformationProcess 的第二个参数可以是一个PROCESS\_BASIC\_INFORMATION的结构体

该结构体的第二个参数是指向PEB的指针，所以我们可以使用该方法来获取PEB的内容

#### 汇编调用

对于获取PEB来说32位与64位并不相同，分别存放在fs与gs寄存器中

x64汇编：

```php
GetPEBAsm64 proc 
    push rbx 
    xor rbx,rbx 
    xor rax,rax 
    mov rbx, qword ptr gs:[00000060h] 
    mov rax, rbx 
    pop rbx 
    ret 
GetPEBAsm64 endp
```

x86汇编(采用内联汇编)：

```php
__asm
{
    mov eax, dword ptr fs : [00000030h] 
    mov peb, eax 
}
```

因为VStudio默认支持x86汇编，这里来演示x64如何内联汇编查找PEB，这里的代码直接选择获取其参数：

```php
.code 

ProcParam PROC 

    mov rax, gs:[30h] ; TEB from gs in 64 bit only 
    mov rax, [rax+60h] ; PEB 
    mov rax, [rax+20h] ; RTL_USER_PROCESS_PARAMETERS 
    ret 

ProcParam ENDP 

end
```

原结构

```php
typedef struct _RTL_USER_PROCESS_PARAMETERS 
{ 
    DWORD MaximumLength; //0x00 
    DWORD Length; //0x04 
    DWORD Flags; //0x08 
    DWORD DebugFlags; //0x0C 
    void* ConsoleHandle; //0x10 
    DWORD ConsoleFlags; //0x14 
    HANDLE StdInputHandle; //0x18 
    HANDLE StdOutputHandle; //0x1C 
    HANDLE StdErrorHandle; //0x20 
    UNICODE_STRING CurrentDirectoryPath; //0x24 
    HANDLE CurrentDirectoryHandle; //0x2C 
    UNICODE_STRING DllPath; //0x30 
    UNICODE_STRING ImagePathName; //0x38 
    UNICODE_STRING CommandLine; //0x40 
    void* Environment; //0x48 
    DWORD StartingPositionLeft; //0x4C 
    DWORD StartingPositionTop; //0x50 
    DWORD Width; //0x54 
    DWORD Height; //0x58 
    DWORD CharWidth; //0x5C 
    DWORD CharHeight; //0x60 
    DWORD ConsoleTextAttributes; //0x64 
    DWORD WindowFlags; //0x68 
    DWORD ShowWindowFlags; //0x6C 
    UNICODE_STRING WindowTitle; //0x70UNICODE_STRING DesktopName; //0x78 
    UNICODE_STRING ShellInfo; //0x80 
    UNICODE_STRING RuntimeData; //0x88 
    RTL_DRIVE_LETTER_CURDIR DLCurrentDirectory[0x20]; //0x90 
} RTL_USER_PROCESS_PARAMETERS;
```

定义主程序，根据原结构可以做自己需要的修改

```php
#include 
#include 

typedef struct _UNICODE_STRING {
    unsigned short Length;
    unsigned short MaximumLength;
    wchar_t* Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _CURDIR {
    UNICODE_STRING DosPath; void* Handle;
} CURDIR, * PCURDIR;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
    unsigned int MaximumLength;
    unsigned int Length;
    unsigned int Flags;
    unsigned int DebugFlags;
    void* ConsoleHandle;
    unsigned int ConsoleFlags;
    void* StandardInput;
    void* StandardOutput;
    void* StandardError;
    CURDIR CurrentDirectory;
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

PRTL_USER_PROCESS_PARAMETERS ProcParam(void);

int main(void)
{
    wprintf(L"%s\n", ProcParam()-&gt;CurrentDirectory.DosPath.Buffer);
}
```

添加汇编文件

![image-20220425014511669](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-0e532028f4ec80edc384170880b0e1ebf85b3392.png)

配置汇编文件

![image-20220426110215760](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-632fd424c5f0d087b2f87844ebe84f501c9b2e52.png)

生成依赖项中勾选asm

![image-20220425020314456](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-e53118d6e73d40b5eca52aea1bab1cde1ae0cb0f.png)

![image-20220426120917762](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-8b44d76680d2d2a29c0c63809831036bab1c7b07.png)

#### 内部函数

像 `__readfsbyte` 、 `__readfsdword` 这类双下划线开头的都是内部函数，与正常函数的区别在于，这些函数直接存在于编译器中，在编译器编译的时候，会将它们直接替换成对应的指令集

32位：`__readfsbyte、__readfsdword、__readfsqword、__readfsword`

从相对于 FS 段开头的偏移量指定的位置读取内存

```C
unsigned char __readfsbyte(
   unsigned long Offset
);
unsigned short __readfsword(
   unsigned long Offset
);
unsigned long __readfsdword(
   unsigned long Offset
);
unsigned __int64 __readfsqword(
   unsigned long Offset
);
```

64位：`__readgsbyte、__readgsdword、__readgsqword、__readgsword`

从相对于 GS 段开头的偏移量指定的位置读取内存。

```C
unsigned char __readgsbyte(
   unsigned long Offset
);
unsigned short __readgsword(
   unsigned long Offset
);
unsigned long __readgsdword(
   unsigned long Offset
);
unsigned __int64 __readgsqword(
   unsigned long Offset
);
```

代码示例

```php
int main(VOID) {
 PPEB Peb = (PPEB)__readfsdword(0x30); //32bit process
 PPEB Peb = (PPEB)__readgsqword(0x60); //64bit process
 return ERROR_SUCCESS;
}
```

整体代码

```php
#include  
#include  
#include  

typedef struct _UNICODE_STRING { 
    USHORT Length; 
    USHORT MaximumLength; 
    PWSTR Buffer; 
} UNICODE_STRING, * PUNICODE_STRING; 

typedef struct _PEB_LDR_DATA { 
    BYTE Reserved1[8]; 
    PVOID Reserved2[3]; 
    LIST_ENTRY InMemoryOrderModuleList; 
} PEB_LDR_DATA, * PPEB_LDR_DATA; 

typedef struct _RTL_USER_PROCESS_PARAMETERS { 
    BYTE Reserved1[16]; 
    PVOID Reserved2[10]; 
    UNICODE_STRING ImagePathName; 
    UNICODE_STRING CommandLine; 
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS; 

typedef struct _PEB { 
    BYTE Reserved1[2]; 
    BYTE BeingDebugged; 
    BYTE Reserved2[1]; 
    PVOID Reserved3[2]; 
    PPEB_LDR_DATA Ldr; 
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters; 
    PVOID Reserved4[3]; 
    PVOID AtlThunkSListPtr; 
    PVOID Reserved5; 
    ULONG Reserved6;
    PVOID Reserved7; 
    ULONG Reserved8; 
    ULONG AtlThunkSListPtr32; 
    PVOID Reserved9[45]; 
    BYTE Reserved10[96]; 
    BYTE Reserved11[128]; 
    PVOID Reserved12[1]; 
    ULONG SessionId; 
} PEB, * PPEB; 

#ifndef _WIN64 
PPEB pPeb = (PPEB)__readfsdword(0x30); 
#else 
PPEB pPeb = (PPEB)__readgsqword(0x60); 
#endif // _WIN64 

int main(void) 
{ 
    wprintf(L"%s\n", pPeb-&gt;ProcessParameters-&gt;ImagePathName.Buffer); 
}
```

![image-20220426130133282](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-66359a8787fd84b5b770c6eb17aab73475a6799d.png)