用 Yara 对红队工具 "打标"（三）——免杀类规则提取
=============================

前言:
---

该系列文章是对 [红队知识仓库 ](https://github.com/Threekiii/Awesome-Redteam) 这个高赞项目中所提到的红队工具进行 "打标"的知识分享。前面已经整理了 [用Yara 对红队工具 "打标"](https://forum.butian.net/share/1913) 和 [用 Yara 对红队工具 "打标"（二） ](https://forum.butian.net/share/1954)，前两篇文章都是对普通工具类进行单体识别，现在开始对免杀类工具的落地文件进行特征提取。

都说攻和防是一体的，知道别人怎么防才知道怎么绕过，怎么更好地攻。等知道了被提取的点，便知道怎么去修饰对应代码来避免被特征匹配，希望这篇文章能对你有用。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-4d21343fd28709a6c0776af08584ce612a3d267b.png)

回顾混淆类特征提取：
----------

混淆类和免杀类大方向上是一样的，都是分析提取被 “处理过” 的文件的特征，我们可以根据混淆脚本的源代码来查看它用什么进行混淆，然后再把范围收缩到其它正常情况下不会出现的特征中，这样对应的识别规则就产生了。

### PHPFuck：

前面提到过 PHPFuck 混淆是使用 7 个不同的字符来编写和执行 php，原理就是这7个字符的异或和加运算来产生其它的字符。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-0dd2e9f58495223c3a505ab16e1a0e1aa8057967.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-79f52f46a1f668ae7bc245298c2ccce375cca149.png)

然后为了排除大型的乱码的字节可能包含这四个字符的情况，我们还要根据位置或数量上的特征再把范围收缩化，于是就写成的规则如下：

```c
rule PHPFuck
{
    meta:
        decription = "phpfuck only uses 7 characters to write, so use these 7 characters as metadata."
    strings:
        $s1 = "[].[]"
        $s2 = "[]^[]"
        $s3 = "[]^[[]]"
        $s4 = "[][[]]"
    condition:
        all of ($s*) and for any of them:(# &gt; 10)

}
```

### JSFuck:

与 PHPFuck 相似:

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-531b000af8e493e1d0e9e785ab173774a74c8430.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-f251cc1d2d6f7a31c4a245c962ae290b43839c02.png)  
同样的根据位置或数量上的特征再把范围收缩化：

```c
rule JSFuck
{
    meta:
        decription = "jsfuck only uses 6 different characters, so just include the metadata of these characters directly."
    strings:
        //$s = "[][[]]"
        //$s = "[+!+[]]+[+[]]"
        $s1 = "[]+[]"
        $s2 = "![]"
        $s3 = "+!+[]"

    condition:
        all of ($s*) and for any of them:(# &gt;10)
}
```

免杀类工具特征提取：
----------

由混淆类工具特征提取引过来，我们来看免杀类工具特征提取。这里我提取的只有 bypassAV、GolangBypassAV、shellcodeloader 这三个，因为它们都是开源项目，有源码可以对应，比较适合我这种菜鸡，剩余的不是在线类就是文档类。特别的，“掩日” 这个工具它的源码和发布版本对应不上，这个后面会提到。

### bypassAV：

项目介绍：条件触发式远控 VT 5/70 免杀国内杀软及defender、卡巴斯基等主流杀软

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-d2456923f85dcf87e9eda64745886b7236954638.png)

#### 源码分析：

##### 主代码分析：

该项目从 README.MD 中可以看到其使用方式如下。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-37201b283d2427bec0c0155c7565fb93298ca13a.png)

源码也不算多，也就三个脚本，在自己简单学了GO语言的基础语法后遍也能看懂，搭配使用方式介绍便能分出各自的功能。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-3def1459a0c38a111fff82b65d6eeacdd5ee2a46.png)

主要的脚本是 go\_shellcode\_encode.py 和 main.go，其中 go\_shellcode\_encode.py 只是将 playload 简单的 base64 加密后替换字符，那么有加密就有解密，有字符替换就一定会有替换回来，那这些逆向操作不用说都知道是在 main.go 中了。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-79e79b97d0dc270822fa88bc0cdf0ceaaff23ff9.png)

在 main.go 中可以看到变量区先是加载特定的 kernel32.dll 基址，然后再动态获取其内存申请和内存复制函数 VirtualAlloc 、RtlMoveMemory。其免杀的原理就是动态加载函数的调用以及内存中简单的自定义的变形小算法解密

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-b2e2cc533ecbb4b92b7d80ea6314c53d4b5f00f1.png)

主代码中就是该项目提到的条件触发式了，在[条件触发式远控 – pureqh](https://pureqh.top/?p=5412)中有很好的诠释，目的是为了躲避沙盒的部分机制：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-3fec6826fac60c32d7ff5cc178af4485ce610b02.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-79355d7fe59dc7600f381a5f44d85dbfb8bd127a.png)

##### 辅助脚本——变量名随机生成：

作者写了一个随机生成 go 脚本的生成器，主要是变量名随机生成而已。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-b379aa09a2cb978ca4ed7dbf0a77212fc9b6108b.png)

举例生成的随机变量名脚本如下，其它是不变的：  
![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-5699a7c396de9c8b167fa5b699e73ea76013c083.png)

### 免杀特征提取：

#### 静态的 YARA 和 PE文件结构：

首先得知道 yara 是静态匹配的，它是基于文本或二进制模式创建恶意样本的描述规则，也就是说我们要么提取文本，要么提取字节码。（当然我们也可以使用 cuckoo 模块导入 Cuckoo 沙箱生成的行为信息进行行为匹配，但是这里不涉及~）

所有的你能提取的特征最原始的模样应该是从字节码编辑器中能直接看到的：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-34dc5ac4348886a7c7d9db809537b5f30eef917c.png)

**那顺着思路来，一个由代码编译而成的 exe 可执行文件在二进制字节码和源码之间是否可以对应起来呢？**

这就需要了解 PE 的文件结构了，PE 格式文件可以大体分成两个部分，PE 文件头部和 PE 文件身体。PE 文件头部最为重要，它索引整个文件，并且其中的节表项定义了 PE 文件身体的具体内容。

（下面的图都出自《WINDOWS PE 权威指南》）

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-b1f022f7aa102a001359588349e5263b299796c2.png)

PE 头由系统编译而成，其中的字段值都在编译时都计算并填充好了，主要是一些索引类的信息标识，统领整个文件，但和我们要对应的源码相关度不大。而节表项及其节内容则定义了与源代码相关的具体组织形式，这正是我们想要的。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-0e3befc4fd434eabcae714002a70495689ae7eb1.png)

PE 结构中有一个数据结构称为数据目录，其中记录了所有可能的数据类型。在编译器和链接器把源代码组织成 PE 可执行文件的过程中，就会根据这些数据类型把源代码拆分成各个对应的部分放在不同的节区中。（包括导出表、导入表、资源表、异常表、属性证书表、重定位表、调试数据、Architecture、Global Ptr、线程局部存储、加载配置表、绑定导入表、IAT、和延迟导入表和 CLR 运行时头部）

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-d0f1b5c4834faf294c9fe13a2fe679f62aca4869.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-1a3241ce90081dac13f357bb3266a08487791fd3.png)  
这些是情有可原的，因为无论是结构化程序设计，还是面向对象程序设计，都提倡程序与数据的独立性。因此，程序中的代码和数据通常是分开存放的。最平常的有 .text 节通常对应代码段，.rdata 节通常对应常量段(也是导入表部分)，.data 通常对应变量段，.reloc 段对应重定位表等等。

所以代码中我们看到的直接写出来的 <http://192.168.150.131> 这个数据因为没有变量载体，所以我们可以直接归为常量段的 .rdata 部分。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-2f7abdc9cb7276f3c3c25146d8c62296b79cf9c8.png)

#### 用代码还是数据做规则？

前面讲解了 PE 文件结构后，我们知道源代码的各个部分会被拆分放到各个不同的节表段中，那么是用代码做规则还是用数据做规则？其实两个可以一起用，但我的思路是用代码，因为我看这几个免杀都没有多少常量数据可以用，而且这些常量的特征值也太笼统了，普通的程序都可以拥有。

那么我们继续往下走，一个项目有众多的代码，最终写入到落地文件的是那些代码？

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-9f3c5ef3dc0858180b055a45a00d69c880fab24a.png)

根据使用说明我们可以知道是 main.go 这个程序，其中主要的参数 trimpath 是去除部分编译机器信息，这些信息主要是字符串信息，并不影响我们 .text 段的特征提取。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-a3694c19418e335eb694bf30af9a064ea66b502e.png)

那么代码中那些可以被用来作为特征呢？看来看去也就只有自定义解密这一部分了，其它的动态解密，vbs 条件式触发，其实正常程序中不少也有，所以本着减少误报的风险还是提取这一段即可。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-6c71a9109960107f019c678a66b5fe25e2e58514.png)

#### 机器码也是字节码：

我们生成一个免杀程序扔如 IDA 中，定位到对应的函数处，因为没有加混淆，所以也比较轻松能找到。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-0797c3eeaded7f4eb976adce649c4ade90b21bb7.png)

前面说过了，提取的特征最原始的模样应该是从字节码编辑器中能直接看到的，所以上面 F5 反编译的伪代码是没法做规则的，所以我们得从反汇编出发。.text 段因为是代码段，所以其中对应的文件字节码也是反编译出来的机器码，而机器码又和汇编语言相对应，所以我们就可以用热键 shift+e 提取出该函数段的机器码。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-5296d2c30fd8d18d7a3454ecdbb718dfb069eba4.png)

&gt; 49 3B 66 10 0F 86 85 01 00 00 48 83 EC 60 48 89 6C 24 58 48 8D 6C 24 58 48 89 44 24 68 48 8D 0D 75 1B 06 00 BF 01 00 00 00 48 8D 35 7E 1B 06 00 49 89 F8 49 C7 C1 FF FF FF FF E8 61 DA E6 FF 48 8D 0D 52 1B 06 00 BF 01 00 00 00 48 8D 35 5E 1B 06 00 49 89 F8 49 C7 C1 FF FF FF FF 0F 1F 40 00 E8 3B DA E6 FF 48 8D 0D 41 1B 06 00 BF 01 00 00 00 48 8D 35 2D 1B 06 00 49 89 F8 49 C7 C1 FF FF FF FF E8 19 DA E6 FF 48 8D 0D 10 1B 06 00 BF 01 00 00 00 48 8D 35 1C 1B 06 00 49 89 F8 49 C7 C1 FF FF FF FF E8 F7 D9 E6 FF 48 8B 15 E0 89 24 00 48 89 D9 48 89 C3 48 89 D0 E8 82 81 E6 FF 48 89 44 24 48 48 89 5C 24 38 48 8D 05 51 CB 01 00 E8 6C A3 DE FF 48 8B 54 24 38 48 89 50 08 48 C7 40 10 00 30 00 00 48 C7 40 18 40 00 00 00 4C 8B 15 84 8B 24 00 48 89 C3 B9 04 00 00 00 48 89 CF 4C 89 D0 E8 39 FE E6 FF 48 8B 54 24 38 48 85 D2 76 73 48 89 44 24 40 48 8B 4C 24 48 48 89 4C 24 50 48 8D 05 19 C9 01 00 E8 14 A3 DE FF 48 8B 4C 24 40 48 89 08 48 8B 54 24 50 48 89 50 08 48 8B 54 24 38 48 89 50 10 48 8B 15 23 8B 24 00 48 89 C3 BF 03 00 00 00 48 89 D0 48 89 F9 0F 1F 44 00 00 E8 DB FD E6 FF 48 8B 44 24 40 31 DB 48 89 D9 48 89 CF 48 89 CE E8 C6 DD E3 FF 48 8B 6C 24 58 48 83 C4 60 C3

#### 汇编中的变与不变：

上面提取的机器码是不可行的，也就只能标识这一个程序而已，我们要创建一个通用的规则，那么就需要知道汇编层面中的变与不变的地方。

- 寄存器操作数和立即数是不变的：

对于那些直接在寄存器中操作数值以及直接赋值的没有载体的常量这种，就是不变的，无论编译多少次它都是这样的。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-e6a95a5eaab024a54e6df022cda8e124001d21a7.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-cbdbdb082649b494e307afb0c80a3ceec9d7b88f.png)

- 传入的参数和局部变量的引用是不变的：

因为它们都是相对于 esp|rsp 的位置，我们提取的是整个函数，哪怕是函数中的一部分，由于堆栈需要平衡，所以它们始终不会改变。  
![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-13d26e893d715f51b99140ca03d98e5ecf331f10.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-3e6970373266a30c606bc2bb0ee8f21073db838c.png)

- 内存操作数都是可变的：

内存操作数是引用数据在内存位置，在 IDA 的反汇编窗口中通常以 ASCII 的 asc 前缀加其内存偏移来作为那些识别不出原标识符的变量名，如：lea rsi, asc\_684EF0 。能识别出的变量名则会赋予一个大致的名称，如：lea rsi, a1\_9 。

（特别要注意的是偏移是基于内存的偏移，所以在文件字节码中要进行 FOA——&gt;VA 的转换，拿着内存偏移在文件字节码中是定位不到数据的）

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-1e634eaeb368e542d7a1f975718fc398fb5c83d6.png)

为什么说内存操作数是可变的呢？比如上图数据在常量 .rdata 段中，前面该项目的介绍中说过其编译方式是 go build -trimpath -ldflags="-w -s -H=windowsgui"，其中 trimpath 参数是去除部分编译机器信息，这些信息主要是字符串信息，也是常量信息，它应该会影响常量 .rdata 段。多了这些常量那原来代码中预定义常量的位置可能就移动了，所以这些是可变的。

- 函数调用地址是可变的：

反汇编中的 CALL 指令都是段间调用，是相对偏移。这里我猜测还是编译方式影响了 .text 段的各函数位置， go build -trimpath -ldflags="-w -s -H=windowsgui" 中的 -ldflags 参数 “是在每次 go 工具链接调用时传递的参数” ，这里应该会影响 .text 段各函数的位置布局，所以它也是可变的。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-a9050e1efb3e3699f6c901293faa31a9c88fa870.png)

### 最终 yara 规则：

把前面提到的不变的部分的机器码照搬，可变部分的机器码用 yara 的十六进制通配符 ?? 占位，最终得到如下的 yara 规则。

```php
rule BypessAV{
    meta:
    reference = "https://github.com/Threekiii/Awesome-Redteam"

    strings:
/*
ÿ Go build ID:

func build(ddm string){
    str1 :=strings.Replace(ddm, "#", "A", -1 )
    str2 :=strings.Replace(str1, "!", "H", -1 )
    str3 :=strings.Replace(str2, "@", "1", -1 )
    str4 :=strings.Replace(str3, ")", "T", -1 )
    sDec,_ := base64.StdEncoding.DecodeString(str4) 
    addr, _, _ := VirtualAlloc.Call(0, uintptr(len(sDec)), 0x1000|0x2000, 0x40)
    _, _, _ = RtlMoveMemory.Call(addr, (uintptr)(unsafe.Pointer(&amp;sDec[0])), uintptr(len(sDec)))
    syscall.Syscall(addr, 0, 0, 0, 0)

}

*/
    $x1 = {49 3B 66 10 0F 86 85 01 00 00 48 83 EC 60 48 89 6C 24 58 48 8D 6C 24 58 48 89 44 24 68 48 8D 0D ?? ?? ?? 00 BF 01 00 00 00 48 8D 35 ?? ?? ?? 00 49 89 F8 49 C7 C1 FF FF FF FF E8 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? 00 BF 01 00 00 00 48 8D 35 ?? ?? ?? 00 49 89 F8 49 C7 C1 FF FF FF FF 0F 1F 40 00 E8 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? 00 BF 01 00 00 00 48 8D 35 ?? ?? ?? 00 49 89 F8 49 C7 C1 FF FF FF FF E8 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? 00 BF 01 00 00 00 48 8D 35 ?? ?? ?? 00 49 89 F8 49 C7 C1 FF FF FF FF E8 ?? ?? ?? ?? 48 8B 15 ?? ?? ?? 00 48 89 D9 48 89 C3 48 89 D0 E8 ?? ?? ?? ?? 48 89 44 24 48 48 89 5C 24 38 48 8D 05 ?? ?? ?? 00 E8 ?? ?? ?? ?? 48 8B 54 24 38 48 89 50 08 48 C7 40 10 00 30 00 00 48 C7 40 18 40 00 00 00 4C 8B 15 ?? ?? ?? 00 48 89 C3 B9 04 00 00 00 48 89 CF 4C 89 D0 E8 ?? ?? ?? ?? 48 8B 54 24 38 48 85 D2 76 73 48 89 44 24 40 48 8B 4C 24 48 48 89 4C 24 50 48 8D 05 ?? ?? ?? 00 E8 ?? ?? ?? ?? 48 8B 4C 24 40 48 89 08 48 8B 54 24 50 48 89 50 08 48 8B 54 24 38 48 89 50 10 48 8B 15 ?? ?? ?? 00 48 89 C3 BF 03 00 00 00 48 89 D0 48 89 F9 0F 1F 44 00 00 E8 ?? ?? ?? ?? 48 8B 44 24 40 31 DB 48 89 D9 48 89 CF 48 89 CE E8 ?? ?? ?? ?? 48 8B 6C 24 58 48 83 C4 60 C3}

    $x2 = {FF 20 47 6F 20 62 75 69 6C 64 20 49 44 3A}

    condition:
    uint16be(0) == 0x4D5A and all of them
}
```

本地测试的几个样本全部命中，并且没有误报

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-fb04a34de28766f3193b92840f528efb3395e88c.png)

### 怎么绕过该规则的检测？

出于避免误报和误杀的目的，其实做检测规则的限制很多，提取面要是太窄，那就会提高误报的几率。

比如我就提取下面这一段比较：

```go
    str1 :=strings.Replace(ddm, "#", "A", -1 )
    str2 :=strings.Replace(str1, "!", "H", -1 )
    str3 :=strings.Replace(str2, "@", "1", -1 )
    str4 :=strings.Replace(str3, ")", "T", -1 )
```

谁知道会不会有那个正常软件碰巧用了这个规则呢，不就几个正常的替换吗？如果误报了过多正常的软件，那么可能就会被投诉甚至是不信任，所带来的负面影响我觉得高于你规则本身的漏报。

所以我选择提取这一整个函数出来:

```go
func build(ddm string){
    str1 :=strings.Replace(ddm, "#", "A", -1 )
    str2 :=strings.Replace(str1, "!", "H", -1 )
    str3 :=strings.Replace(str2, "@", "1", -1 )
    str4 :=strings.Replace(str3, ")", "T", -1 )
    sDec,_ := base64.StdEncoding.DecodeString(str4) 
    addr, _, _ := VirtualAlloc.Call(0, uintptr(len(sDec)), 0x1000|0x2000, 0x40)
    _, _, _ = RtlMoveMemory.Call(addr, (uintptr)(unsafe.Pointer(&amp;sDec[0])), uintptr(len(sDec)))
    syscall.Syscall(addr, 0, 0, 0, 0)

}
```

前面说过攻和防是一体的，知道别人怎么防才知道怎么绕过，现在知道了提取的点，便知道怎么去修饰对应代码来避免被特征匹配。

比如你随便加一点无关代码：

```go
func build(ddm string){
    str1 :=strings.Replace(ddm, "#", "A", -1 )
    str2 :=strings.Replace(str1, "!", "H", -1 )
    str3 :=strings.Replace(str2, "@", "1", -1 )
    str4 :=strings.Replace(str3, ")", "T", -1 )
    fmt.Println("666")
    fmt.Println("666")
    fmt.Println("666")
    sDec,_ := base64.StdEncoding.DecodeString(str4) 
    addr, _, _ := VirtualAlloc.Call(0, uintptr(len(sDec)), 0x1000|0x2000, 0x40)
    _, _, _ = RtlMoveMemory.Call(addr, (uintptr)(unsafe.Pointer(&amp;sDec[0])), uintptr(len(sDec)))
    syscall.Syscall(addr, 0, 0, 0, 0)

}
```

比如你把函数拆分出来：

```go
func build1(ddm string){
    str1 :=strings.Replace(ddm, "#", "A", -1 )
    str2 :=strings.Replace(str1, "!", "H", -1 )
    str3 :=strings.Replace(str2, "@", "1", -1 )
    str4 :=strings.Replace(str3, ")", "T", -1 )
    return str4
}

func build2(ddm2 string){
    sDec,_ := base64.StdEncoding.DecodeString(ddm2) 
    addr, _, _ := VirtualAlloc.Call(0, uintptr(len(sDec)), 0x1000|0x2000, 0x40)
    _, _, _ = RtlMoveMemory.Call(addr, (uintptr)(unsafe.Pointer(&amp;sDec[0])), uintptr(len(sDec)))
    syscall.Syscall(addr, 0, 0, 0, 0)
    }
```

上面提到的方法等等都可以绕过我做的这个规则，但是原作者给的那个变量名随机生成辅助脚本，我是真不知道有什么用。至少对我这个规则是没用的，因为我是基于二进制代码的，而汇编层面的参数传递，变量等，不是寄存器就是堆栈或者内存偏移量，哪里有什么变量名在里面。可能有别的杀软用了字符串做规则来提取吧，不过变量名也不应该存在啊，想不通~~

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-b6d4df99d43470447ce82ffa73467e169ccac2f3.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-32faeab70a9d068eccc7a363fcbc111b8b4c7b39.png)

### 最后：

自己提取过规则才发现诸多限制，真的是随随便便就能绕过，又不能写得太通泛，不然就把正常的代码也杀掉了，这也许是免杀代码层出不穷的原因吧。当然大环境中的杀软还是有诸多手段的，特征代码法、校验和法、行为监测法、软件模拟法、启发式扫描等等，上面仅表示我粗浅的见解，如有错误还请指正！

PS：

本来是想写完 bypassAV、GolangBypassAV、shellcodeloader 这三个工具的提取思路的，但是因为篇幅还是比较长的，最近（懒得写了）太忙了，就先写最简单的 bypassAV 吧。以后（有空的话）过段时间再把剩下两个工具的提取思路也整理出来吧，其实提取的手法也差不多，就是源码审计和提取点不一样，后会有期！