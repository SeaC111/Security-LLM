0x00 前言:
========

在前面 [用Yara 对红队工具 "打标"](https://forum.butian.net/share/1913) 文章中提到过我们的目的是对 [红队知识仓库 ](https://github.com/Threekiii/Awesome-Redteam) 这个 1.5k 的项目中所提到的红队工具进行 "打标" ，用于在内网中对目标主机进行扫描时根据匹配的红队工具来判断主机的大致用途以及加强信息收集。

因为 YARA 本身是用于识别和分类恶意软件样本的工具，所以想要把它应用在工具识别方面就需要 "另类" 的思维和处理方式。前文中陆陆续续提出了用 YARA 对批量红队工具 "打标" 过程中三种制定方案以及 yaGen 工具的使用，并学习了如何编写合理有效的 Yara 规则。

但是该红队知识仓库中的红队工具实在太多了，除去在线工具外 github 上项目也有将近 200 个。由于不同类型的工具在大小、主体、特征、文件量等等方面都有很大的不同，所以原来的三个方案很快就不够用也不适用了。如果硬套原来三个方案的话就会出现规则难以维护，误报后难以修正，无法匹配其它版本等一系列问题，所以我们需要继续思考，不能在一个大锅饭中吃到底。

0x01 回顾前面提出的三种方案
================

**方案一：直接用 010 Editor 进行字节码比较，提取出不同版本中相同的字节码部分**

*适用情况：*

1：单一或少量的文件，并且大小不应超过 10MB，否则 010 Editor 要加载很长时间。

2：无法直接运行的，比如插件这些，或运行后没有特征。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-db9d61fa9d9ebaa70a6abfee681409d37cdc7a4c.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-f26ff90316825cb72a752c9562f9b8d75a52dafe.png)

**方案二：寻找检测面并搭配 yaGen 工具自动生成规则**

*适用情况：*

无论是单一的的文件还是大中型项目中都适用，但是尽量少用！因为其自动生成的规则需要手动剔除一些实际上不成语意的字符串，有时候这成了一项很繁琐的工作。

最最重要的是难以维护！因为它挑选出来的字符串其实没有那么大的典型性，但是它通过像 ( uint16(0) == 0x5a4d and filesize &lt; 800KB and ( 5 of them ) ) or ( all of them ) 这样的限制条件让规则变得有用起来。

这更像是从把各个地方的字符串汇聚起来，所以当规则产生误报的时候，你只能去从原规则上去不断修改，以让它更通用一点或者更严格一点。但是你无法从 "检测面" 本身去寻找问题，因为你根本不知道 yarGen 是在哪个角落提取出来的规则！

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-c19337004f92672fa5a7dcbcc4b9c264bfc00554.png)

**方案三：从资源入手**

*适用情况：*

如果项目的主要可执行文件有资源节 .reloc ，或直接用 Resource Hacker 能提取出东西，那就可以直接使用。特别是对于有图标资源的，它最大的特点就是够典型且通用，不同版本之间图标通常是不会变的。所以只要有资源内嵌在可执行文件中，就可以直接入手。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-c599e7670f2fa7ae5b949ac08ecba93e7fc0210b.png)

0x02 继续思考——细分应用场景：
==================

我们要尝试寻找一个通用的特征，它应该要在同一个工具的不同版本中都始终存在或尽可能存在。这种特征应该是典型的，它不应该是从某个细枝末节中你自己认为是的特征，它应该是一种公认的特征，使它能在转接给下一个人的时候别人能认同你的规则并迅速定位到你提取规则的点来优化和跟进。

1：从命令行界面中寻找特征点：
---------------

对于没有 UI 的命令行程序和脚本代码，给人最先和最直观的印象就是其启动界面中的艺术字 "logo" 和说明，所以我们要好好利用这个特征。

### 艺术字 "logo" 入手：

对于命令行的程序，通常会有其自己的艺术字 "logo"，这种就属于一脉相承并公认典型的特征，不管它作为一个单独的可执行文件还是多文件中 "检测面"，它都适合做标签！

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-7332586afd8621b26b72c68ac9e8c8c54bef8a80.png)

因为放在 github 上的项目几乎都是开源的，所以就能在源代码中提取字符串出来，这样会更精确。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-5592528ca6b573f9f02264286db1c77974fed6b6.png)

值得注意的是像这种艺术字体涉及了很多传统的转义序列以及正则表达式，这些在 YARA 中也同样存在。特别的，在之前的 YARA 版本中，使用 PCRE 和 RE2 等外部库来执行正则表达式匹配。但从 2.0 版之后，YARA 使用自己的正则表达式引擎。这个新引擎实现了 PCRE 中的大多数功能，除了其中一些功能，如捕获组、POSIX 字符类（\[\[:isalpha:\]\]、\[\[:isdigit:\]\] 等）和反向引用。

最最最关键的是 YARA 没有 python 的那种原始字符串标记表示法 "r"，所以就造成了很大的困扰，总不可能对每一个特殊字符都用反斜杠转义，所以我想到了用等价的字节码来表示它。而且对于很多的已编译好的项目，可执行文件才是主体，所以选择字节码具有更好的通用性。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-6e28d7e2f6b3ad36c895c11c8ed554b5b2a9bddf.png)

编写 YARA 规则如下，把 logo 作为注释显得直观：

```c
rule identYwaf {
   meta:
      decryption = "I picked the icons part of this command line interface, I think they are generic and unique."
      hash1 = "cf37c9d7ed9129679fc125d2ab5d2d5953aa333c0a9a894f6b33eab6543320d6"
   strings:
/*
                                   ` __ __ `
 ____  ___      ___  ____   ______ `|  T  T` __    __   ____  _____ 
l    j|   \    /  _]|    \ |      T`|  |  |`|  T__T  T /    T|   __|
 |  T |    \  /  [_ |  _  Yl_j  l_j`|  ~  |`|  |  |  |Y  o  ||  l_
 |  | |  D  YY    _]|  |  |  |  |  `|___  |`|  |  |  ||     ||   _|
 j  l |     ||   [_ |  |  |  |  |  `|     !` \      / |  |  ||  ] 
|____jl_____jl_____jl__j__j  l__j  `l____/ `  \_/\_/  l__j__jl__j 
*/
      $x1 = {0A 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 60 20 5F 5F 20 5F 5F 20 60 0A 20 5F 5F 5F 5F 20 20 5F 5F 5F 20 20 20 20 20 20 5F 5F 5F 20 20 5F 5F 5F 5F 20 20 20 5F 5F 5F 5F 5F 5F 20 60 7C 20 20 54 20 20 54 60 20 5F 5F 20 20 20 20 5F 5F 20 20 20 5F 5F 5F 5F 20 20 5F 5F 5F 5F 5F 20 0A 6C 20 20 20 20 6A 7C 20 20 20 5C 20 20 20 20 2F 20 20 5F 5D 7C 20 20 20 20 5C 20 7C 20 20 20 20 20 20 54 60 7C 20 20 7C 20 20 7C 60 7C 20 20 54 5F 5F 54 20 20 54 20 2F 20 20 20 20 54 7C 20 20 20 5F 5F 7C 0A 20 7C 20 20 54 20 7C 20 20 20 20 5C 20 20 2F 20 20 5B 5F 20 7C 20 20 5F 20 20 59 6C 5F 6A 20 20 6C 5F 6A 60 7C 20 20 7E 20 20 7C 60 7C 20 20 7C 20 20 7C 20 20 7C 59 20 20 6F 20 20 7C 7C 20 20 6C 5F 0A 20 7C 20 20 7C 20 7C 20 20 44 20 20 59 59 20 20 20 20 5F 5D 7C 20 20 7C 20 20 7C 20 20 7C 20 20 7C 20 20 60 7C 5F 5F 5F 20 20 7C 60 7C 20 20 7C 20 20 7C 20 20 7C 7C 20 20 20 20 20 7C 7C 20 20 20 5F 7C 0A 20 6A 20 20 6C 20 7C 20 20 20 20 20 7C 7C 20 20 20 5B 5F 20 7C 20 20 7C 20 20 7C 20 20 7C 20 20 7C 20 20 60 7C 20 20 20 20 20 21 60 20 5C 20 20 20 20 20 20 2F 20 7C 20 20 7C 20 20 7C 7C 20 20 5D 20 0A 7C 5F 5F 5F 5F 6A 6C 5F 5F 5F 5F 5F 6A 6C 5F 5F 5F 5F 5F 6A 6C 5F 5F 6A 5F 5F 6A 20 20 6C 5F 5F 6A 20 20 60 6C 5F 5F 5F 5F 2F 20 60 20 20 5C 5F 2F 5C 5F 2F 20 20 6C 5F 5F 6A 5F 5F 6A 6C 5F 5F 6A 20 20}

   condition:
      uint16(0) == 0x2123 and filesize < 80KB and $x1
}

```

### 参数说明入手：

同样的，命令行起始界面中参数说明也是通用且独特的，很多项目也许会在后面添加或更改功能，到时我们在修改或直接在条件上给一个数量容错即可。

参数说明出现在艺术字 "logo" 下面，直观性虽不如 "logo"，但是典型性两者是差不多的。有一些项目会存在没有艺术字 "logo" ，但是他们基本都会有说明界面。所以在命令行程序中没有艺术字 "logo" 的情况下，我们也可以把说明提取出来作为规则。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-f4c70a637ed37d615840e81fad6f3303c8ace770.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-26debf99b9aed8cbcf8f105cefd42d14cf8fc785.png)

但是对于有 release 版的项目，大家基本都只会下载编译好的可执行文件，所以我们不能从代码入手，得从字节码入手：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-3bf7fec14b2daac6bf7f77a7254fa534985fffb3.png)

为了寻找大块连续的，和参数说明相关的内容区，我尝试扔入 IDA 中查看 string 窗口：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-36fde0dcb8eac67432277873a0cf1ad530684e3e.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-6a77631d8a224abc2384a730e892e054983ac6d7.png)

尝试编写规则如下：

```c
rule gobuster{
   meta:
      decription = "I picked out the instructions for using the command line interface, I think they are generic and unique"
   strings:
//Usage:{{if .Runnable}}\n  {{.UseLine}}{{end}}{{if .HasAvailableSubCommands}}\n  {{.CommandPath}} [command]{{end}}{{if gt (len .Aliases) 0}}\n\nAliases:\n  {{.NameAndAliases}}{{end}}{{if .HasExample}}\n\nExamples:\n{{.Example}}{{end}}{{if .HasAvailableSubCommands}}\n\nAvailable Commands:{{range .Commands}}{{if (or .IsAvailableCommand (eq .Name \"help\"))}}\n  {{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}{{end}}{{if .HasAvailableLocalFlags}}\n\nFlags:\n{{.LocalFlags.FlagUsages | trimTrailingWhitespaces}}{{end}}{{if .HasAvailableInheritedFlags}}\n\nGlobal Flags:\n{{.InheritedFlags.FlagUsages | trimTrailingWhitespaces}}{{end}}{{if .HasHelpSubCommands}}\n\nAdditional help topics:{{range .Commands}}{{if .IsAdditionalHelpTopicCommand}}\n  {{rpad .CommandPath .CommandPathPadding}} {{.Short}}{{end}}{{end}}{{end}}{{if .HasAvailableSubCommands}}\n\nUse \"{{.CommandPath}} [command] --help\" for more information about a command.{{end}}\n

      $x1 = {55 73 61 67 65 3A 7B 7B 69 66 20 2E 52 75 6E 6E 61 62 6C 65 7D 7D 0A 20 20 7B 7B 2E 55 73 65 4C 69 6E 65 7D 7D 7B 7B 65 6E 64 7D 7D 7B 7B 69 66 20 2E 48 61 73 41 76 61 69 6C 61 62 6C 65 53 75 62 43 6F 6D 6D 61 6E 64 73 7D 7D 0A 20 20 7B 7B 2E 43 6F 6D 6D 61 6E 64 50 61 74 68 7D 7D 20 5B 63 6F 6D 6D 61 6E 64 5D 7B 7B 65 6E 64 7D 7D 7B 7B 69 66 20 67 74 20 28 6C 65 6E 20 2E 41 6C 69 61 73 65 73 29 20 30 7D 7D 0A 0A 41 6C 69 61 73 65 73 3A 0A 20 20 7B 7B 2E 4E 61 6D 65 41 6E 64 41 6C 69 61 73 65 73 7D 7D 7B 7B 65 6E 64 7D 7D 7B 7B 69 66 20 2E 48 61 73 45 78 61 6D 70 6C 65 7D 7D 0A 0A 45 78 61 6D 70 6C 65 73 3A 0A 7B 7B 2E 45 78 61 6D 70 6C 65 7D 7D 7B 7B 65 6E 64 7D 7D 7B 7B 69 66 20 2E 48 61 73 41 76 61 69 6C 61 62 6C 65 53 75 62 43 6F 6D 6D 61 6E 64 73 7D 7D 0A 0A 41 76 61 69 6C 61 62 6C 65 20 43 6F 6D 6D 61 6E 64 73 3A 7B 7B 72 61 6E 67 65 20 2E 43 6F 6D 6D 61 6E 64 73 7D 7D 7B 7B 69 66 20 28 6F 72 20 2E 49 73 41 76 61 69 6C 61 62 6C 65 43 6F 6D 6D 61 6E 64 20 28 65 71 20 2E 4E 61 6D 65 20 22 68 65 6C 70 22 29 29 7D 7D 0A 20 20 7B 7B 72 70 61 64 20 2E 4E 61 6D 65 20 2E 4E 61 6D 65 50 61 64 64 69 6E 67 20 7D 7D 20 7B 7B 2E 53 68 6F 72 74 7D 7D 7B 7B 65 6E 64 7D 7D 7B 7B 65 6E 64 7D 7D 7B 7B 65 6E 64 7D 7D 7B 7B 69 66 20 2E 48 61 73 41 76 61 69 6C 61 62 6C 65 4C 6F 63 61 6C 46 6C 61 67 73 7D 7D 0A 0A 46 6C 61 67 73 3A 0A 7B 7B 2E 4C 6F 63 61 6C 46 6C 61 67 73 2E 46 6C 61 67 55 73 61 67 65 73 20 7C 20 74 72 69 6D 54 72 61 69 6C 69 6E 67 57 68 69 74 65 73 70 61 63 65 73 7D 7D 7B 7B 65 6E 64 7D 7D 7B 7B 69 66 20 2E 48 61 73 41 76 61 69 6C 61 62 6C 65 49 6E 68 65 72 69 74 65 64 46 6C 61 67 73 7D 7D 0A 0A 47 6C 6F 62 61 6C 20 46 6C 61 67 73 3A 0A 7B 7B 2E 49 6E 68 65 72 69 74 65 64 46 6C 61 67 73 2E 46 6C 61 67 55 73 61 67 65 73 20 7C 20 74 72 69 6D 54 72 61 69 6C 69 6E 67 57 68 69 74 65 73 70 61 63 65 73 7D 7D 7B 7B 65 6E 64 7D 7D 7B 7B 69 66 20 2E 48 61 73 48 65 6C 70 53 75 62 43 6F 6D 6D 61 6E 64 73 7D 7D 0A 0A 41 64 64 69 74 69 6F 6E 61 6C 20 68 65 6C 70 20 74 6F 70 69 63 73 3A 7B 7B 72 61 6E 67 65 20 2E 43 6F 6D 6D 61 6E 64 73 7D 7D 7B 7B 69 66 20 2E 49 73 41 64 64 69 74 69 6F 6E 61 6C 48 65 6C 70 54 6F 70 69 63 43 6F 6D 6D 61 6E 64 7D 7D 0A 20 20 7B 7B 72 70 61 64 20 2E 43 6F 6D 6D 61 6E 64 50 61 74 68 20 2E 43 6F 6D 6D 61 6E 64 50 61 74 68 50 61 64 64 69 6E 67 7D 7D 20 7B 7B 2E 53 68 6F 72 74 7D 7D 7B 7B 65 6E 64 7D 7D 7B 7B 65 6E 64 7D 7D 7B 7B 65 6E 64 7D 7D 7B 7B 69 66 20 2E 48 61 73 41 76 61 69 6C 61 62 6C 65 53 75 62 43 6F 6D 6D 61 6E 64 73 7D 7D 0A 0A 55 73 65 20 22 7B 7B 2E 43 6F 6D 6D 61 6E 64 50 61 74 68 7D 7D 20 5B 63 6F 6D 6D 61 6E 64 5D 20 2D 2D 68 65 6C 70 22 20 66 6F 72 20 6D 6F 72 65 20 69 6E 66 6F 72 6D 61 74 69 6F 6E 20 61 62 6F 75 74 20 61 20 63 6F 6D 6D 61 6E 64 2E 7B 7B 65 6E 64 7D 7D 0A}

   condition:
      ( uint16(0) == 0xfacf or uint16(0) == 0x457f or uint16(0) == 0x5a4d or uint16(0) == 0xface) and filesize < 10MB and $x1
}

```

但是在大范围测试的时候发现误报率很高，所以这应该是一种前端说明的框架：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-cfd379412feb77af6b937245aea4dcf53f654f93.png)

但是同 IDA 中看到的一样，很多参数其实是填充进去的，比如 help for gobuster 就不能找到完整的例子，我尝试提取上面那个 "AvailableCommands" 的命令说明，因为那里有完整的字节码对应，但是很快我发现自己忽略了一个问题，那就是 3.01 版本和 3.10 版本的命令行界面是不同的！

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-79b286c2dcd3169fa47ad055fbd8d32bd2a25123.png)

第一部分参数说明有个别单词不同，下面那部分说明有增加，这就是典型的功能新增了，那还是挑选下面参数说明的最小子集吧，把那些要填充的分开来写并设置对应权重就好啦。

最终规则如下：

```php
rule gobuster{
   meta:
      decription = "I picked out the instructions for using the command line interface, I think they are generic and unique"
   strings:
/*
Flags:
  -h, --help              help for gobuster
  -z, --noprogress        Don't display progress
  -o, --output string     Output file to write results to (defaults to stdout)
  -q, --quiet             Don't print the banner and other noise
  -t, --threads int       Number of concurrent threads (default 10)
  -v, --verbose           Verbose output (errors)
  -w, --wordlist string   Path to the wordlist
*/

      $s1 = "help for" 
      $x1 = "gobuster" 
      $s2 = "Don't display progress" 
      $s3 = "Output file to write results to (defaults to stdout)" 
      $s4 = "Don't print the banner and other noise" 
      $s5 = "Number of concurrent threads" 
      $s6 = "Verbose output (errors)"
      $s7 = "Path to the wordlist"

   condition:
      ( uint16(0) == 0xfacf or uint16(0) == 0x457f or uint16(0) == 0x5a4d or uint16(0) == 0xface) and filesize < 10MB and $x1 and 6 of ($s*)
}
```

2：在文件集中找 "商标"
-------------

对于大中型文件集中，简单挑选检测面后用 yarGen 一把梭在前面已经说过问题了。那如何在大量文件中寻找其独有且典型的特征？商标给了我灵感，就像老干妈的商标是陶华碧这个人物，腾讯商标是企鹅一样，我们也可以找文件集中的 "商标"，这种商标以图片为准，因为其更具有直观性。

### 商标可直接获取类型：

在一些文件集中，图标并没有嵌入在可执行文件中，其属于引用方式展现，就像 MD 图片本身或者 HTML , JS 代码这些。在文件集中不用一个个翻看文件找图片，我们在下载项目后直接在父目录中搜索 ico，jpg，png图标即可：  
![image.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-2267087c3a225769428292cfbf2c24147efc4646.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-7bb5dc4a7790cea208d6ffcc679cc86eb2fe8b9a.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-aa577ae7e3bf9a063b184e27695b6d34b9ece402.png)

编写规则如下：

```C
rule SwitchyOmega
{
    meta:
        description = "I chose the program-specific icon as the detection object"
    strings:
        $s1 = {A5 72 36 48 5D F1 33 D4 76 4E DC 65 44 DE 00 9E 06 4A 02 E6 BD 0C 7A 48 B3 7A B0 EF A9 C8 2F 05 05 D8 19 1B DD B0 10 2A 79 07 F4 65 C0 0D 08 5E A9 B4 88 7C 54 3A 3D D3 FE C3 B3 D5 0B 81 03 D4 1D 19 AF 31 8E E9 54 D8 56 20 78 25 E5 AC C9 EA}
    condition:
        uint16be(0) == 0x8950 and filesize < 5KB and $s1

}
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-aabd8e56462f1e56b7aa1d3de2f1f4bff899d1cb.png)

### 商标需要剥离类型：

这种和方案三中的资源提取图标类似，但是又有点不同。YAKIT 就是这样一种类型，它本来是大型文件集，但是有最终编译好的文件安装包存在。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-cf91282c0dbb732fc847465f75af846d1c401038.png)

下载了最终编译文件后可以看到，除了 windows 系统平台的文件外，其它系统平台都没有图标显现。所以我把其源码也下载了下来，在父目录中搜索图片类型。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-592be322d05c86f2d46f1fb9be1e22742777e2df.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-643ce32e20c755f35b6b4a45120c2b3831f8ad18.png)

陆陆续续试了几个图标发现都不行，一下子把我搞懵了，但是在 linux 上运行又有图标啊

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-a1ade16ca17568ebf869ae9614e4fdf5d8dca5cb.png)

思考了一下，肯定是嵌进去了的，但是其它平台文件格式没学过，想着如何分离，想起 CTF 杂项时用过 formost 分离工具，分离出来即可：

（附上一个可在 windows 上用的 foremost [jin-stuff/foremost](https://github.com/jin-stuff/foremost)）

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-7a99538f20bd4cca47e2032520ef67ec9fdf408b.png)

三个可执行文件都提取出来放在一起作为特征，挨个提取部分即可：  
![image.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-414d6d8c1d1f65c8fb8d69537fe56543aae41d8e.png)

写 yara 规则时可以加多点限制条件，比如不同的类型对应不同的图标这样：

```c
rule yakit
{
    meta:
        decription = "I selected the icon resource of this program. This program is packaged by upx. Even if it is unpacked, the icon still exists.But different systems I found have different icons"
    strings:
        $x1 = {DA ED 9D 7B B4 14 D5 9D EF 3F F5 E8 C3 E3 80 88 E0 03 11 51 D0 88 0A 8A 88 F2 50 C0}
        $x2 = {27 E8 DC 43 7B CE EE EC 74 BF F7 A7 DE EB 9E B3 67 76 67 0F 4C AA 70 6F 75 CD 4E BF EE D7 EF FB}
        $x3 = {DC 44 38 DE 48 3B DC 45 38 DB 44 37 DB 44 38 DE 47 3B DC 46 37 DB 46 38 DC 45 38 DC 45 38 DC 45}
        $x4 = {FA DD 7F DF 7D 6F A3 0D 4D C0 48 D7 D2 39 8E BA 0E 6C DA E0 94 53 4E}
    condition:
        (uint16be(0) == 0x78DA and $x3 and $x4) or (uint16be(0) == 0x7F45 and $x2)or (uint16be(0) == 0x4D5A and $x1) and filesize > 60MB and filesize < 200MB
}
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-128a02f31e7954a001d47a648eec1ea26a82c290.png)

3：从文件注释入手：
----------

官方注释是一种比较典型且一脉相承的提取点，毕竟谁没事会动一个方便自己理解的官方注释呢？

### 配置文件注释：

配置文件是大型项目的基本要素，在一些图标，艺术字 logo，参数说明等都无法完整映射全部版本的时候，可以考虑从配置文件下手。基于大部分配置文件都会在使用时或多或少被修改参数值，所以我们直接提取基本不被修改的官方注释来做特征。

最典型的一个就是 frp 了，它有 "商标" ，但是似乎只在源码的 web 文件夹中（我没用过不知道啊~-~），启动界面中也没有艺术字 "logo" 和参数说明。最关键的是它分客户端和服务端，和 Cobalt Strike 一样：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-15be255004df55649bc76a26085b90d07ccea2cd.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-058eca69a0c8cd014150d67bb45b66b4b35622f4.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-5c7dffe4a5fa5601ad6c7741c9101e38333b47f8.png)  
这就造成一个困扰，怎么提取规则把客户端和服务端都检测到呢，那就是寻找两边具有很大相似性的文件。那就是他们的配置文件，可以在其开头提取它们之间相同的说明注释：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-afcd6dc9fd5e8da44ac8d57af1088c8ffdeff4c2.png)

编写规则如下：

```c
rule frp
{
    meta:
        description = "I picked the opening comments from the essential configuration file frps_full.ini, I think they are common across different versions of frp"
    strings:
/*
# [common] is integral section
[common]
# A literal address or host name for IPv6 must be enclosed
# in square brackets, as in "[::1]:80", "[ipv6-host]:http" or "[ipv6-host%zone]:80"
# For single "server_addr" field, no need square brackets, like "server_addr = ::".

# For single "bind_addr" field, no need square brackets, like "bind_addr = ::".
*/

        $x1 = {23 20 5B 63 6F 6D 6D 6F 6E 5D 20 69 73 20 69 6E 74 65 67 72 61 6C 20 73 65 63 74 69 6F 6E}
        $x2 = {23 20 41 20 6C 69 74 65 72 61 6C 20 61 64 64 72 65 73 73 20 6F 72 20 68 6F 73 74 20 6E 61 6D 65 20 66 6F 72 20 49 50 76 36 20 6D 75 73 74 20 62 65 20 65 6E 63 6C 6F 73 65 64}
        $x3 = {23 20 69 6E 20 73 71 75 61 72 65 20 62 72 61 63 6B 65 74 73 2C 20 61 73 20 69 6E 20 22 5B 3A 3A 31 5D 3A 38 30 22 2C 20 22 5B 69 70 76 36 2D 68 6F 73 74 5D 3A 68 74 74 70 22 20 6F 72 20 22 5B 69 70 76 36 2D 68 6F 73 74 25 7A 6F 6E 65 5D 3A 38 30 22}

        $c1 ={23 20 46 6F 72 20 73 69 6E 67 6C 65 20 22 73 65 72 76 65 72 5F 61 64 64 72 22 20 66 69 65 6C 64 2C 20 6E 6F 20 6E 65 65 64 20 73 71 75 61 72 65 20 62 72 61 63 6B 65 74 73 2C 20 6C 69 6B 65 20 22 73 65 72 76 65 72 5F 61 64 64 72 20 3D 20 3A 3A 22 2E}
        $s1 = {23 20 46 6F 72 20 73 69 6E 67 6C 65 20 22 62 69 6E 64 5F 61 64 64 72 22 20 66 69 65 6C 64 2C 20 6E 6F 20 6E 65 65 64 20 73 71 75 61 72 65 20 62 72 61 63 6B 65 74 73 2C 20 6C 69 6B 65 20 22 62 69 6E 64 5F 61 64 64 72 20 3D 20 3A 3A 22 2E}
    condition:
        uint16be(0) == 0x2320 and filesize < 1MB and all of ($x*) and ($c1 or $s1)

}
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-cbd5f5d4b454e9b95124ca46ea43037dcc93e40d.png)

### 主代码文件注释：

对于要想直接根据主运行文件是否存在来检测的话就可以从其注释下手，对于主运行文件很多项目作者都会在其开头摆放版权声明和一些项目信息，其中不乏有十分典型的项目 URL、作者 email、作者名等等。而且由于其大块存在并位置明显，所以也能被他人认可。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-6fa9cabab9975bfc7994fefe7d262a63b93a5220.png)

直接提取规则如下：

```c
rule dirsearch 
{
   meta:
      description = "The program has neither a command line icon nor a command line description, so only features in the main code can be selected as rules"
      hash1 = "076ea463a7dca58dd90673b1a4c1128a1fc22ad1a487cf5108fd89885ca7250c"
   strings:
    $x1 = "#  This program is free software; you can redistribute it and/or modify" fullword ascii
    $x2 = "#  it under the terms of the GNU General Public License as published by" fullword ascii
    $x3 = "#  the Free Software Foundation; either version 2 of the License, or" fullword ascii
    $x4 = "#  (at your option) any later version." fullword ascii
    $x5 = "#  This program is distributed in the hope that it will be useful," fullword ascii
    $x6 = "#  but WITHOUT ANY WARRANTY; without even the implied warranty of" fullword ascii
    $x7 = "#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the" fullword ascii
    $x8 = "#  GNU General Public License for more details." fullword ascii
    $x9 = "#  You should have received a copy of the GNU General Public License" fullword ascii
    $x10 = "#  along with this program; if not, write to the Free Software" fullword ascii
    $x11 = "#  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston," fullword ascii
    $x12 = "#  MA 02110-1301, USA." fullword ascii
    $x13 = "#  Author: Mauro Soria" fullword ascii
   condition:
      uint16(0) == 0x2123 and filesize < 4MB and all of them
}

```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-6e2b6cdd351201d4d377fb6f9f5af8b6c40dc2db.png)

4：简单杂烩
------

### 直接用项目 url：

有时候其它方案都不灵或者直接想走简单路线的，可以直接使用项目 url 做规则。项目文件中也许行为上会引用自己在 github 上的代码文件，也许只是简单的注释介绍，当然大多数是编译成可执行文件时把 github 路径也包含进去了，所以使用项目 url 有时会有意想不到的收获。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-16bdeaae034063af20df41257ec4d0112d8b174c.png)

尝试编写规则如下，可执行文件类型限制要加上：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-2aefcf89ffb5830c55a5948c277dea48c9ebe7cb.png)

0x03 部分混淆类：
===========

混淆类这些不是要中标项目本身，而是要检测出其衍生的混淆过的代码，所以都要一对一深入理解后来写的。通过查看文档说明和源码是用什么来作为替代的，又是怎么组合和运算的，基本元素有那几个。我们通常以基本元素来做规则，因为万变不离其宗！

PHPFuck：
--------

PHPFuck 在项目介绍中说是仅使用 7 个不同的字符来编写和执行 php，原理就是这7个字符的异或和加运算来产生其它的字符。  
![image.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-ffeb257660312f51cdbc3553aa23241f8d799b7f.png)

尝试在其 web 端界面中寻找其基本单元：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-2226a9e8780e4afeeb59ec0339a663cdba75ffc6.png)

尝试书写规则如下：

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
        all of ($s*)

}
```

但是不太行，因为规则肉眼可见的简单，在一些大型的乱码的字节中包含这四个也许是很正常的事，所以我们多加一些限制条件，比如数量上的。  
![image.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-2a21251308bb062e2dde7e08ec1d87e84404b6df.png)

所以最终编写规则如下：（不加文件类型限制是因为和php特性有关，具体自己查哈~）

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
        all of ($s*) and for any of them:(# > 10)

}
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-beac25622469eb0a7742362a616d0f430f57009f.png)

JSFuck：
-------

与 PHPFuck 相似，说明如下：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-c1ec9ef58c70859d9ed559f6542700c91794b155.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-10996348011ae5e890ad8288b84ddb8da41106e7.png)

那么同样的把握数量上的关系，编写规则如下：

```C
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
        all of ($s*) and for any of them:(# >10)
}
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-66525339a3abd4d4bab8eeee48959dbeed138f2c.png)

0x04 YARA 进阶——编写高性能的规则
======================

从 [Nextron](https://www.nextron-systems.com/) 公司博客站上 [How to Write Simple but Sound Yara Rules – Part 2](https://www.nextron-systems.com/2015/10/17/how-to-write-simple-but-sound-yara-rules-part-2/)) 中提到了作者在多年编写 YARA 中对性能的关注和研究，参考其内容可以学到不同匹配规则对 CPU 占用的差异，以此来编写出更高性能的检测规则。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-f8e2adb031ef4bea7bb9ef7de89c5d30802df22f.png)

YARA 扫描过程：
----------

YARA 扫描前会把字符串拆分成原子，然后在生成前缀数（Aho-Corasick 自动机）在各个文件中进行匹配，接着把匹配原子的部分移交到字节码引擎进行完整性查询，最后在完成所有模式匹配后将验证条件是否符合

**以下面的规则为例：**

```C
rule example_php_webshell_rule
{
    meta:
        description = "Just an example php webshell rule"
    strings:
        $x = "<?php"
        $s1   = "GET"
        $s2   = "POST"
        $a = /assert[\t ]{0,100}/
    condition:
        filesize < 20KB and $x and $a and any of ( $s* ) 
}
```

**1：编译规则：**  
编译上面的规则时，YARA 可能会选择以下 4 个原子以非常巧妙地选择它们以避免太多匹配。

```php
<?ph
GET
POST
sser（出自 assert）
```

**2：Aho-Corasick 自动机**  
YARA 将在每个文件中查找上面定义的 4 个原子，其前缀树称为 Aho-Corasick 自动机，任何匹配都会移交给字节码引擎。

**3：字节码引擎**  
如果在上面匹配sser，YARA 将检查它是否以 an 为前缀 a 并以 t 继续，是的话它将继续使用正则表达式 \[\\t \]{0,100} 来继续往下搜索 。通过这种方法可以避免对整个文件使用缓慢的正则表达式引擎，而只是选择某些部分进行仔细查看。

**4：条件**  
完成所有模式匹配后，将检查条件是否满足。

YARA 中的原子：
----------

YARA 从字符串中提取 4 个字节的短子字符串，这些子字符串称为“原子”。这些原子可以从实在的字符串中的任何位置提取，而不是从正则表达式的未确定值中提取，并且 YARA 在扫描文件时搜索这些原子，如果找到其中一个原子，则继续验证字符串是否实际匹配。

举例规则1：

```c
/abc.*cde/
```

可能的原子是abc 或 cde， abc 原子当前是首选的，因为它们具有相同的质量，并且是两者中的第一个。

举例规则2：

```c
/(one|two)three/
```

可能的原子是 one、two、thre 和 hree，我们可以单独搜索 thre（或 hree），或者同时搜索 one 和two。 thre 是首选，因为它们更独特。

举例规则3：

```c
{ 00 00 00 00 [1-4] 01 02 03 04 }
```

YARA 使用 `01 02 03 04`，因为`00 00 00 00`太常见了

举例规则4：

```c
{ 01 02 [1-4] 01 02 03 04 }
```

01 02 03 04 是首选因为它更长，所以更难匹配

举例规则5：

```c
{00 00 00 00 [1-2] FF FF [1-2] 00 00 00 00}
{AB  [1-2] 03 21 [1-2] 01 02}
/a.*b/
/a(c|d)/
```

上面的是坏字符串，因为它们包含太短或太常见的原子：

举例规则6：

```c
/\w.*\d/
/[0-9]+\n/
```

上面是更坏的字符串，因为它们根本不包含任何原子的字符串。这种正则表达式不包含任何可用作原子的固定子字符串，因此必须在文件的每个偏移量处对其进行评估以查看它是否与那里匹配。

提高检测性能：
-------

**1：避免迭代次数过多的 for循环，特别是循环内的语句过于复杂，例如：**

```c
strings:
    $a = {00 00}
condition:
    (for all i in (1..#a) : (@a[i] < 10000)) or (for all i in (1..filesize) : ($a at i))
```

第一个是上述规则中 $a 太常见了，所以 #a 可能太高，可以被评估数千次。第二个是迭代次数取决于文件大小，文件大小也可能非常高：

**2：自定义 magic 模块：**

使用 yara 自带的 “magic” 模块会减慢扫描速，但可以提供完全匹配。

**自定义的：**

```c
rule gif_1 {
  condition:
    (uint32be(0) == 0x47494638 and uint16be(4) == 0x3961) or
    (uint32be(0) == 0x47494638 and uint16be(4) == 0x3761)
}
```

**使用自带的：**

```c
import "magic"
rule gif_2 {
  condition:
    magic.mime_type() == "image/gif"
}
```

**3：不要使字符串太短**

避免定义太短的字符串。任何少于 4 个字节的字符串都可能出现在很多文件中，或者作为异或文件中的统一内容出现。

高效率的字符串：
--------

尽可能完整地描述字符串定义，避免使用 “nocase” 属性，因为将生成指数级的原子。在没有修饰符的情况下，默认情况下假定为 “ascii”，下面是可能的组合：

**产生少量原子的规则：**

```c
$s1 = "cmd.exe"            // (ascii only)
$s2 = "cmd.exe" ascii          // (ascii only, same as $s1)
$s3 = "cmd.exe" wide           // (UTF-16 only)
$s4 = "cmd.exe" ascii wide     // (both ascii and UTF-16) two atoms will be generated 
$s5 = { 63 6d 64 2e 65 78 65 } // ascii char code in hex
```

**产生指数级原子的规则：**

```c
$s5 = "cmd.exe" nocase      (all different cases, e.g. "Cmd.", "cMd.", "cmD." ..)
```

**如果只需要一个或两个字母的不同大小写，则应该写成如下正则表达式:**

```c
$re = /[Pp]assword/
```

**避免使用交替的字符串，因为这些字符串会产生可以减慢扫描速度的短原子，应该编写单独的字符串：**

```c
/*
$re = /(a|b)cde/
$hex = {C7 C3 00 (31 | 33)}
*/
$re1 = /acde/
$re2 = /bcde/
$hex1 = {C7 C3 00 31}
$hex2 = {C7 C3 00 33}
```

正则表达式的优化：
---------

正则表达式求值本质上比纯字符串匹配要慢，并且会消耗大量内存，尽量用带有跳转和通配符的十六进制字符串来代替正则表达式。

如果非要使用正则表达式，应该避免使用贪婪 . *和不确定的量词 .*?。而是使用确切的数字，例如 .{1,30}，不要忘记设上限。

对应规则举例：

```c
$re1 = /Tom.{0,2}/      // will find Tomxx in "Tomxx"
$re2 = /.{0,2}Tom/      // will find Tom, xTom, xxTom in "xxTom"
```

**寻找最小子集：**

举例在电子邮件地址的正则表达式，当 \[-a-z0-9.\_%+\] 与量词一起使用时，YARA 会多次匹配一个地址。这时应该找到一个相当小的地址子集，为分析提供足够的信息。

好的规则：

```c
/[-a-z0-9._%+]@[-a-z0-9.]{2,10}\.[a-z]{2,4}/
OR
/@[-a-z0-9.]{2,10}\.[a-z]{2,4}/ 
```

差的规则：

```c
/[-a-z0-9._%+]*@[-a-z0-9.]{2,10}\.[a-z]{2,4}/
/[-a-z0-9._%+]+@[-a-z0-9.]{2,10}\.[a-z]{2,4}/
/[-a-z0-9._%+]{x,y}@[-a-z0-9.]{2,10}\.[a-z]{2,4}/
```

条件和短路评估：
--------

这就跟 &amp;&amp; （逻辑与）运算符一样，把最有可能为 “假” 的元素放在首位。从左到右评估条件，引擎越早识别出不满足规则，它就越早可以跳过当前规则并评估下一个规则。

这种排序条件语句的方式所带来的速度提高取决于处理每个语句所需的 CPU 周期的差异。如果所有语句的成本或多或少都相同，则重新排序语句不会导致明显的改进。如果其中一个语句可以非常快速地处理，则建议将其放在首位，以便在第一个语句为 FALSE 的情况下跳过昂贵的语句评估。

规则举例1：慢速的

```c
EXPENSIVE and CHEAP
math.entropy(0, filesize) > 7.0 and uint16(0) == 0x5A4D
```

规则举例2：快速地

```c
CHEAP and EXPENSIVE
uint16(0) == 0x5A4D and math.entropy(0, filesize) > 7.0
```

0x05 调整后的已整理规则
==============

```c
rule yakit
{
    meta:
        decription = "I selected the icon resource of this program. This program is packaged by upx. Even if it is unpacked, the icon still exists.But different systems I found have different icons"
    strings:
        $x1 = {DA ED 9D 7B B4 14 D5 9D EF 3F F5 E8 C3 E3 80 88 E0 03 11 51 D0 88 0A 8A 88 F2 50 C0}
        $x2 = {27 E8 DC 43 7B CE EE EC 74 BF F7 A7 DE EB 9E B3 67 76 67 0F 4C AA 70 6F 75 CD 4E BF EE D7 EF FB}
                $x3 = {DC 44 38 DE 48 3B DC 45 38 DB 44 37 DB 44 38 DE 47 3B DC 46 37 DB 46 38 DC 45 38 DC 45 38 DC 45}
        $x4 = {FA DD 7F DF 7D 6F A3 0D 4D C0 48 D7 D2 39 8E BA 0E 6C DA E0 94 53 4E}
    condition:
        (uint16be(0) == 0x78DA and $x3 and $x4) or (uint16be(0) == 0x7F45 and $x2)or (uint16be(0) == 0x4D5A and $x1) and filesize > 60MB and filesize < 200MB
}

rule Wappalyzer
{
    meta:
        description = "I chose the program-specific icon as the detection object"
    strings:
        $s1 = {00 00 07 47 49 44 41 54 78 9C ED 9B 5F 6C 5B D5 1D C7 BF E7 5E BB 71 E3 44 B9 94 04 87 A6 C1 66 6E 57 26 4D 26 D2 34 A5 AB 44 14 D8 6C 02 12 13 66 14 54 A9 55 D3 97 AD 40 A4 3A 59 BB D7 24 CF
DD 16 57 DA 60 DA 1E 5A D6 BD 40 55 6E BB BE}
    condition:
        uint16be(0) == 0x8950 and filesize < 5KB and $s1

}

rule hydra {
   meta:
      description = "I picked the program's icon"
   strings:
      $s1 = {40 9F 40 08 13 13 13 1B 0C 0E 05 6C 1F 25 03 B3 2F 3C 01 E4 39 47 00 FF 41 51 00 FF 44 53 00 FF 40 4F 00 FF 36 43 00 FF 2A 35 01 ED 1A 21 03 B7 09 0C 05 6D 14 14 14 19}
      $s2 = {17 17 17 FE 02 02 02 FF 02 02 02 FF 02 02 02 FF 02 02 02 FF 02 02 02 FF 02 02 02 FF 02 02 02 FF 34 34 34 FF FE FE FE FF FE FE FE FF FE FE FE FF FE FE FE FF FE FE FE FF FE FE FE FF FE FE FE FF FE FE FE FF FE FE FE FF FE FE FE FF FE FE FE FF FE FE FE FF FE FE FE FF FE FE FE FF FE FE FE FF FE FE FE FF FE FE FE FF FE FE FE FF FE FE FE FF FE FE FE FF FE FE FE FF FE FE FE FF FE FE FE FF FE FE FE FF FE FE FE FF FE FE FE FF FE FE FE FF FE FE FE FF FE FE FE FF FE FE FE FF FE FE FE FF FE FE FE FF FE FE FE FF FE FE FE FF FE FE FE FF FE FE FE FF FE FE FE FF FE FE FE FF FE FE FE FF FE FE FE FF FE FE FE FF FE FE FE FF FE FE FE FF FE FE FE FF FE FE FE FF FE FE FE FF FE FE FE FF FE FE FE FF FE FE FE FF FE FE FE FF FE FE FE FF FE FE FE FF FE FE FE FF FE FE FE FF FE FE FE FF FE FE FE FF FE FE FE FF FE FE FE FF FE FE FE FF FE FE FE FF FE FE FE FF FE FE FE FF FE FE FE FF FE FE FE FF FE FE FE FF FE FE FE FF FE FE FE FF FE FE FE FF FE FE FE FF FE FE FE FF FE FE FE FF FE FE FE FF FE FE FE FF FE FE FE FF FE FE FE FF FE FE FE FF FE FE FE FF FE FE FE FF FE FE FE FF FE FE FE FF FE FE FE FF FE FE FE FF FE FE FE FF FE FE FE FF FE FE FE FF FE FE FE FF FE FE FE FF}
   condition:
      any of them
}

rule RouteVulScan {
   meta:
    description = "Choose commonalities from multiple versions"
   strings:
    $s1 = {00 00 00 62 75 72 70 2F 56 69 65 77 24 54 61 62 6C 65 2E 63 6C 61 73 73 85 52 4D 6F D3 40 10 7D EB 38 71 9D 98 34 2D 0D 50 D2 96 06 92 92 A4 A1 2E DF 12 45 BD 44 80 82 0C 1C 8A 72 C8 CD 71 57 CE 56 C6 46 8E 43}
   condition:
        ( uint16(0) == 0x4B50 and filesize > 30MB) and $s1
}

rule SwitchyOmega
{
    meta:
        description = "I chose the program-specific icon as the detection object"
    strings:
        $s1 = {A5 72 36 48 5D F1 33 D4 76 4E DC 65 44 DE 00 9E 06 4A 02 E6 BD 0C 7A 48 B3 7A B0 EF A9 C8 2F 05 05 D8 19 1B DD B0 10 2A 79 07 F4 65 C0 0D 08 5E A9 B4 88 7C 54 3A 3D D3 FE C3 B3 D5 0B 81 03 D4
1D 19 AF 31 8E E9 54 D8 56 20 78 25 E5 AC C9 EA}
    condition:
        uint16be(0) == 0x8950 and filesize < 5KB and $s1

}

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
        all of ($s*) and for any of them:(# > 10)

}

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
        all of ($s*) and for any of them:(# >10)
}

rule PEID
{
    meta:
        decription = "I selected the icon resource of this program. This program is packaged by upx. Even if it is unpacked, the icon still exists."
        md5 = "ef2327b387b8e22b186cf935913b05d5"

    strings:
        $s0 = {0B BB 3C 88 88 08 00 55 55 59 B3 33 80 FB BB 30 0D BB BB 33 3D C9 F0 55 55 55 B3 33 C0 03 BB BF 09 BB BB 3E BB BB D0 55 55 55 3D D3 30 8D BB BD 02 BB BB D0 9B BB B2 55 55 55 D3 D3 30 8E 3B B3 88 3B B3 30 8B BB BC 05 45 55 93 DD 3F 5F 33 33 25 DB 33 38 83 BB BD 55 55 54 23 D3 3C 2C 33 33 C5 CB BB BE 93 BB 3D 85 45 45 4B BB BB BB BB BB E2 2B BB BB BB B3 B3 55 45 44 4C EE EE EE DE DE 
F4 44 CD EE EE EE E9 54 44 44 44 44 47 77 71 71 71 77 77 77 77 77 44 44 44 44 44 74 74 77 AA AA AA AA A7 A7 77 77 77 44 44 44 74 74 74 77 7A A6 AA 6A 6A A7 A7 7A 77 74 44 44 44 44 44 45 44 44 44 44 44 44 44 44 44 44 }

    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and filesize < 1MB and $s0
}

rule LSTAR
{
    meta:
        description = "I choose the version screenshot in the project's readme.md as the identification"
    strings:
        $s1 = {00 00 09 FB 69 43 43 50 49 43 43 20 50 72 6F 66 69 6C 65 00 00 48 89 95 96 77 54 53 D9 16 C6 CF BD E9 0D 08 09 11 90 12 6A E8 55 20 80 D4 D0}
    condition:
        uint16be(0) == 0x8950 and filesize < 100KB and $s1

}

rule Log4j2Scan {
   meta:
    description = "I Choose commonalities from multiple versions"
   strings:
    $s1 = {32 00 63 6F 6D 2F 61 6C 69 62 61 62 61 2F 66 61 73 74 6A 73 6F 6E 2F 4A 53 4F 4E 50 61 74 68 24 46 6C 6F 6F 72 53 65 67 6D 65 6E 74 2E 63 6C 61 73 73 50 4B 01 02 14 00 14 00 08 08 08 00 72 07 B7 54 00 00 00 00 02 00 00 00 00 00 00 00 1B 00 00 00 00 00 00 00 00 00 00 00 00 00}
   condition:
        ( uint16(0) == 0x4B50 and filesize > 3MB) and $s1
}

rule ksubdomain {
   meta:
      decryption = "I picked the icons part of this command line interface, I think they are generic and unique."

   strings:
/*
db 0Ah
db ' _  __   _____       _         _                       _',0Ah
db '| |/ /  / ____|     | |       | |                     (_)',0Ah
db '| ',27h,' /  | (___  _   _| |__   __| | ___  _ __ ___   __ _ _ _ __',0Ah
db '|  <    \___ \| | | | ',27h,'_ \ / _| |/ _ \| ',27h,'_   _ \ / _  | | ',27h,'_ \',0Ah
db '| . \   ____) | |_| | |_) | (_| | (_) | | | | | | (_| | | | | |',0Ah
db '|_|\_\ |_____/ \__,_|_.__/ \__,_|\___/|_| |_| |_|\__,_|_|_| |_|',0Ah
*/
      $x1 = {0A 20 5F 20 20 5F 5F 20 20 20 5F 5F 5F 5F 5F 20 20 20 20 20 20 20 5F 20 20 20 20 20 20 20 20 20 5F 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 5F 0A 7C 20 7C 2F 20 2F 20 20 2F 20 5F 5F 5F 5F 7C 20 20 20 20 20 7C 20 7C 20 20 20 20 20 20 20 7C 20 7C 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 28 5F 29 0A 7C 20 27 20 2F 20 20 7C 20 28 5F 5F 5F 20 20 5F 20 20 20 5F 7C 20 7C 5F 5F 20 20 20 5F 5F 7C 20 7C 20 5F 5F 5F 20 20 5F 20 5F 5F 20 5F 5F 5F 20 20 20 5F 5F 20 5F 20 5F 20 5F 20 5F 5F 0A 7C 20 20 3C 20 20 20 20 5C 5F 5F 5F 20 5C 7C 20 7C 20 7C 20 7C 20 27 5F 20 5C 20 2F 20 5F 7C 20 7C 2F 20 5F 20 5C 7C 20 27 5F 20 20 20 5F 20 5C 20 2F 20 5F 20 20 7C 20 7C 20 27 5F 20 5C 0A 7C 20 2E 20 5C 20 20 20 5F 5F 5F 5F 29 20 7C 20 7C 5F 7C 20 7C 20 7C 5F 29 20 7C 20 28 5F 7C 20 7C 20 28 5F 29 20 7C 20 7C 20 7C 20 7C 20 7C 20 7C 20 28 5F 7C 20 7C 20 7C 20 7C 20 7C 20 7C 0A 7C 5F 7C 5C 5F 5C 20 7C 5F 5F 5F 5F 5F 2F 20 5C 5F 5F 2C 5F 7C 5F 2E 5F 5F 2F 20 5C 5F 5F 2C 5F 7C 5C 5F 5F 5F 2F 7C 5F 7C 20 7C 5F 7C 20 7C 5F 7C 5C 5F 5F 2C 5F 7C 5F 7C 5F 7C 20 7C 5F 7C 0A 0A}

   condition:
      (uint16(0) == 0x5A4D or uint32(0) == 0x464C457F or uint32(0) == 0xFEEDFACF) and filesize < 30MB and $x1
}

rule john {
   meta:
      description = "This is a set of projects, with too many subtools, so I chose one sentence that I thought was sufficient to identify the project, and it would normally not be intentionally altered"
   strings:
      $s1 = "Please install json / simplejson module which is currently not installed." fullword ascii
   condition:
      $s1
}

rule IoT_vunlhub {
   meta:
      hash1 = "7698b65c4c4ca086aca26dfd3a6ac5b92f9db4ac2093dd93ce3facb3e3131eba"
      hash2 = "1cb47eb8f8f4b5005775097e20ab607a35228ce92e06e7fe9fefad0a40b8b9f1"
      hash3 = "0019cd8982f2e842ab4303ae4dbf3bb58433cee81b6925e3a12d9955b81e8229"
      hash4 = "0d1c1d89e3aef9d7ae098fcce4e3727b3a4cc51d7aa08bbf8acb77a70da30917"
   strings:
      $s1 = "virtual char* process_stratum_target::pid_to_exec_file(int)" fullword ascii
      $s2 = "lwp_info* linux_process_target::filter_event(int, int)" fullword ascii
      $s3 = "thread_info* find_thread_in_random(Func) [with Func = linux_process_target::wait_for_event_filtered(ptid_t, ptid_t, int*, int)::" ascii
      $s4 = "thread_info* find_thread_in_random(Func) [with Func = linux_process_target::wait_for_event_filtered(ptid_t, ptid_t, int*, int)::" ascii
      $s5 = "void linux_process_target::complete_ongoing_step_over()" fullword ascii
      $s6 = "process %d is a zombie - the process has already terminated" fullword ascii
      $s7 = "virtual int process_stratum_target::read_loadmap(const char*, CORE_ADDR, unsigned char*, unsigned int)" fullword ascii
      $s8 = "virtual int process_stratum_target::get_tls_address(thread_info*, CORE_ADDR, CORE_ADDR, CORE_ADDR*)" fullword ascii
      $s9 = "virtual int process_stratum_target::qxfer_siginfo(const char*, unsigned char*, const unsigned char*, CORE_ADDR, int)" fullword ascii
      $s10 = "virtual int process_stratum_target::qxfer_libraries_svr4(const char*, unsigned char*, const unsigned char*, CORE_ADDR, int)" fullword ascii
      $s11 = "void linux_process_target::resume_one_lwp_throw(lwp_info*, int, int, siginfo_t*)" fullword ascii
      $s12 = "virtual int process_stratum_target::qxfer_osdata(const char*, unsigned char*, const unsigned char*, CORE_ADDR, int)" fullword ascii
      $s13 = "void linux_process_target::wait_for_sigstop()" fullword ascii
      $s14 = "virtual int process_stratum_target::get_tib_address(ptid_t, CORE_ADDR*)" fullword ascii
      $s15 = "22process_stratum_target" fullword ascii
      $s16 = "virtual int linux_process_target::attach(long unsigned int)" fullword ascii
      $s17 = "virtual void linux_process_target::low_delete_thread(arch_lwp_info*)" fullword ascii
      $s18 = "void linux_process_target::unstop_all_lwps(int, lwp_info*)" fullword ascii
      $s19 = "bool linux_process_target::maybe_move_out_of_jump_pad(lwp_info*, int*)" fullword ascii
      $s20 = "bool linux_process_target::stuck_in_jump_pad(thread_info*)" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 1MB and 8 of them 
}

rule identYwaf {
   meta:
      decryption = "I picked the icons part of this command line interface, I think they are generic and unique."
      hash1 = "cf37c9d7ed9129679fc125d2ab5d2d5953aa333c0a9a894f6b33eab6543320d6"
   strings:
/*
                                   ` __ __ `
 ____  ___      ___  ____   ______ `|  T  T` __    __   ____  _____ 
l    j|   \    /  _]|    \ |      T`|  |  |`|  T__T  T /    T|   __|
 |  T |    \  /  [_ |  _  Yl_j  l_j`|  ~  |`|  |  |  |Y  o  ||  l_
 |  | |  D  YY    _]|  |  |  |  |  `|___  |`|  |  |  ||     ||   _|
 j  l |     ||   [_ |  |  |  |  |  `|     !` \      / |  |  ||  ] 
|____jl_____jl_____jl__j__j  l__j  `l____/ `  \_/\_/  l__j__jl__j 
*/
      $x1 = {0A 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 60 20 5F 5F 20 5F 5F 20 60 0A 20 5F 5F 5F 5F 20 20 5F 5F 5F 20 20 20 20 20 20 5F 5F 5F 20 20 5F 5F 5F 5F 20 20 20 5F 5F 5F 5F 5F 5F 20 60 7C 20 20 54 20 20 54 60 20 5F 5F 20 20 20 20 5F 5F 20 20 20 5F 5F 5F 5F 20 20 5F 5F 5F 5F 5F 20 0A 6C 20 20 20 20 6A 7C 20 20 20 5C 20 20 20 20 2F 20 20 5F 5D 7C 20 20 20 20 5C 20 7C 20 20 20 20 20 20 54 60 7C 20 20 7C 20 20 7C 60 7C
20 20 54 5F 5F 54 20 20 54 20 2F 20 20 20 20 54 7C 20 20 20 5F 5F 7C 0A 20 7C 20 20 54 20 7C 20 20 20 20 5C 20 20 2F 20 20 5B 5F 20 7C 20 20 5F 20 20 59 6C 5F 6A 20 20 6C 5F 6A 60 7C 20 20 7E 20 20 7C 60 7C 20 20 7C 20 20 7C 20 20 7C 59 20 20 6F 20 20 7C 7C 20 20 6C 5F 0A 20 7C 20 20 7C 20 7C 20 20 44 20 20 59 59 20 20 20 20 5F 5D 7C 20 20 7C 20 20 7C 20 20 7C 20 20 7C 20 20 60 7C 5F 5F 5F 20 20 7C 60 7C 20 20 7C 20 20 7C 20 20 7C 7C 20 20 20 20 20 7C 7C 20 20 20 5F 7C 0A 20 6A 20 20 6C 20 7C 20 20 20 20 20 7C 7C 20 20 20 5B 5F 20 7C 20 20 7C 20 20 7C 20 20 7C 20 20 7C 20 20 60 7C 20 20 20 20 20 21 60 20 5C 20 20 20 20 20 20 2F 20 7C 20 20 7C 20 20 7C 7C 20 20 5D 20 0A 7C 5F 5F 5F 5F 6A 6C 5F 5F 5F 5F 5F 6A 6C 5F 5F 5F 5F 5F 6A 6C 5F 5F 6A 5F 5F 6A 20 20 6C 5F 5F 6A 20 20 60 6C 5F 5F 5F 5F 2F 20 60 20 20 5C 5F 2F 5C 5F 2F 20 20 6C 5F 5F 6A 5F 5F 6A 6C 5F 5F 6A 20 20}

   condition:
      uint16(0) == 0x2123 and filesize < 80KB and all of them
}

rule hping
{
    meta:
        descript = "I picked the program's icon as the test object"
    strings:
        $s1 = {86 86 86 86 86 86 86 82 34 53 17 59 86 86 86 9B 76 99 4C 76 7E 86 86 48 22 3D 90 85 01 86 86 32 2B 37 2D 10 43 86 86 04 3F 55 8D 1D 0D 86 86 2E A4 1E 4A 14 28 86 9F 15 54 25 8C 40 96 86 86 2E
A4 74 4D 14 5A 86 42 26 97 86 6A 9A 96 86 86 2E A4 88 5B 69 94 86 70 7A A3 21 83 78 96 86 86 58 56 2F 52 5C 29 57 4B 98 6E 8B 50 66 06 86 86 86 49 86 63 9D 8E 87 08 5D A0 1C 79 03 0B 86 86 6B 47 1A 18 7F 91 7D 6D 30 95 1B 75 4F 84 86 86 2A 67 7B 0F 62 33 7D 38 5E 07 73 71 72 20 86 86 7C 16 7B 5F 80 31 45 27 0A 61 3A 60 68 20 86 86 7C 16 9C 0E 64 31 45 46 6F 02 44 35 68 20 86 86 7C 16 39 81 00 77 7D 1F 4E 19 0C 12 68 20 86 86 7C 16 2C 6C 8F 13 89 A2 A1 93 41 9E 05 3E 86 86 7C 65 51 86 86 86 86 86 86 86 86 92 24 3B 86 86 11 36 3C 86 86 86 86 86 86 86 86 8A 09 23 86}
    condition:
    (uint32be(0) ==0x00000100 or uint32be(0) ==0xFFD8FFE0) and filesize < 1MB and $s1
}

rule HFish
{
    meta:
        descript = "I chose the program-specific icon as the detection object"

    strings:
        $x1 = {F2 FF F2 F2 F2 FF F2 F2 F2 FF F2 F2 F2 FF DB DB F1 FF 7C 7C EC FF 5A 5A EB FF 36 36 E9 FF 36 36
E9 FF 36 36 E9 FF 36 36 E9 FF 36 36 E9 FF 36 36 E9 FF 36 36 E9 FF 36 36 E9 FF 36 36 E9 FF 36 36 E9 FF 36 36 E9 FF 36 36 E9 FF 36 36 E9 FF 36 36 E9 FF 36 36 E9 FF 36 36 E9 FF 36 36 E9 FF 36 36 E9 FF 36 36 E9 FF 36 36 E9 FF 36 36 E9 FF 36 36 E9 FF 36 36 E9 FF 36 36 E9 FF 36 36 E9 FF 36 36}    

    condition:
        uint32(0) == 0x00000100 and filesize < 1MB and $x1
}

rule HaE {
   meta:
    description = "Choose commonalities from multiple versions"
   strings:
    $s1 = {03 00 00 AA 06 00 00 33 00 00 00 62 75 72 70 2F 75 69 2F 4A 54 61 62 62 65 64 50 61 6E 65 43 6C 6F 73 65 42 75 74 74 6F 6E 24 43 6C 6F 73 65 42 75 74 74 6F 6E 54 61 62 2E 63 6C 61 73 73 9D 55}
   condition:
        ( uint16(0) == 0x4B50 and filesize < 2MB) and $s1
}

rule hack_browser {
   meta:
      description = "This part is generated by yaraGen"
      hash1 = "ef9281e777f8083738653683137fffd0d06f2f8f63b19e1424957a9148e7c463"
      hash2 = "b16672f3fa38fbdde1207883fbc7774746141ff824f11ef22fb563da846bdef8"
      hash3 = "35dcf6a2ef444708fbc21764be7498eb37b2abc3a44e973585123460b8f1c5cd"
      hash4 = "49e62206353bb7f248734f2aad56c31b87a2f4f8e705e2c5730af743dc1515a4"
      hash5 = "089791d205039a61089efb21ce82d8546107bd2a66b8901bceedd72de46a9835"
      hash6 = "9ae7cd82ce55a9059368c404e376eb4110a6b0c30ac9e670bdd045470daba59e"
   strings:
      $x1 = "github.com/gookit/slog.SugaredLogger.PushProcessor" fullword ascii
      $x2 = "github.com/gookit/slog.(*Logger).PushProcessor" fullword ascii
      $x3 = "github.com/gookit/slog.(*Logger).SetProcessors" fullword ascii
      $x4 = "github.com/gookit/slog.(*SugaredLogger).AddProcessors" fullword ascii
      $x5 = "github.com/gookit/slog.SugaredLogger.AddProcessors" fullword ascii
      $x6 = "github.com/gookit/slog.SugaredLogger.AddProcessor" fullword ascii
      $x7 = "github.com/gookit/slog.(*Logger).AddProcessor" fullword ascii
      $x8 = "github.com/gookit/slog.(*Logger).ResetProcessors" fullword ascii
      $x9 = "github.com/gookit/slog.(*SugaredLogger).SetProcessors" fullword ascii
      $x10 = "github.com/gookit/slog.(*SugaredLogger).AddProcessor" fullword ascii
      $x11 = "github.com/gookit/slog.SugaredLogger.ResetProcessors" fullword ascii
      $x12 = "github.com/gookit/slog.(*SugaredLogger).PushProcessor" fullword ascii
      $x13 = "github.com/gookit/slog.(*Logger).AddProcessors" fullword ascii
      $x14 = "github.com/gookit/slog.(*SugaredLogger).ResetProcessors" fullword ascii
      $x15 = "github.com/gookit/slog.SugaredLogger.SetProcessors" fullword ascii
      $s16 = "github.com/gookit/slog.SugaredLogger.Error" fullword ascii
      $s17 = "github.com/gookit/slog.(*Logger).Error" fullword ascii
      $s18 = "github.com/gookit/slog.(*Logger).Errorf" fullword ascii
      $s19 = "github.com/gookit/slog.SugaredLogger.Errorf" fullword ascii
      $s20 = "*template.ExecError" fullword ascii
   condition:
      ( ( uint16(0) == 0x457f or uint16(0) == 0xfacf or uint16(0) == 0x5a4d ) and filesize < 10MB and ( 1 of ($x*) and all of them )) or ( all of them )
}

rule Hack_Bar
{
    meta:
        description = "I chose the program-specific icon as the detection object"
    strings:
        $s1 = {00 00 03 E0 49 44 41 54 78 9C ED DD BF 8B 1C 65 1C 80 F1 67 37 39 B8 FC 02 D1 4B 8A 88 76 16}
    condition:
        uint16be(0) == 0x8950 and filesize < 5KB and $s1

}

rule Gopherus
{
    meta:
        decription = "I picked the icons part of this command line interface, I think they are generic and unique."
    strings:
/*
  ________              .__
 /  _____/  ____ ______ |  |__   ___________ __ __  ______
/   \  ___ /  _ \\\\____ \|  |  \_/ __ \_  __ \  |  \/  ___/
\    \_\  (  <_> )  |_> >   Y  \  ___/|  | \/  |  /\___ \\
 \______  /\____/|   __/|___|  /\___  >__|  |____//____  >
        \/       |__|        \/     \/                 \/
*/

        $x1 = {0A 0A 20 20 5F 5F 5F 5F 5F 5F 5F 5F 20 20 20 20 20 20 20 20 20 20 20 20 20 20 2E 5F 5F 0A 20 2F 20 20 5F 5F 5F 5F 5F 2F 20 20 5F 5F 5F 5F 20 5F 5F 5F 5F 5F 5F 20 7C 20 20 7C 5F 5F 20 20 20 5F 5F 5F 5F 5F 5F 5F 5F 5F 5F 5F 20 5F 5F 20 5F 5F 20 20 5F 5F 5F 5F 5F 5F 0A 2F 20 20 20 5C 20 20 5F 5F 5F 20 2F 20 20 5F 20 5C 5C 5C 5C 5F 5F 5F 5F 20 5C 7C 20 20 7C 20 20 5C 5F 2F 20 5F 5F 20 5C 5F 20 20 5F 5F 20 5C 20 20 7C 20 20 5C 2F 20 20 5F 5F 5F 2F 0A 5C 20 20 20 20 5C 5F 5C 20 20 28 20 20 3C 5F 3E 20 29 20 20 7C 5F 3E 20 3E 20 20 20 59 20 20 5C 20 20 5F 5F 5F 2F 7C 20 20 7C 20 5C 2F 20 20 7C 20 20 2F 5C 5F 5F 5F 20 5C 5C 0A 20 5C 5F 5F 5F 5F 5F 5F 20 20 2F 5C 5F 5F 5F 5F 2F 7C 20 20 20 5F 5F 2F 7C 5F 5F 5F 7C 20 20 2F 5C 5F 5F 5F 20 20 3E 5F 5F 7C 20 20 7C 5F 5F 5F 5F 2F 2F 5F 5F 5F 5F 20 20 3E 0A 20 20 20 20 20 20 20 20 5C 2F 20 20 20 20 20 20 20 7C 5F 5F 7C 20 20 20 20 20 20 20 20 5C 2F 20 20 20 20 20 5C 2F 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 5C 2F 0A}       
    condition:
        filesize < 1MB and $x1
}

rule gobuster{
   meta:
      decription = "I picked out the instructions for using the command line interface, I think they are generic and unique"
   strings:
/*
Flags:
  -h, --help              help for gobuster
  -z, --noprogress        Don't display progress
  -o, --output string     Output file to write results to (defaults to stdout)
  -q, --quiet             Don't print the banner and other noise
  -t, --threads int       Number of concurrent threads (default 10)
  -v, --verbose           Verbose output (errors)
  -w, --wordlist string   Path to the wordlist
*/

      $s1 = "help for" 
      $x1 = "gobuster" 
      $s2 = "Don't display progress" 
      $s3 = "Output file to write results to (defaults to stdout)" 
      $s4 = "Don't print the banner and other noise" 
      $s5 = "Number of concurrent threads" 
      $s6 = "Verbose output (errors)"
      $s7 = "Path to the wordlist"

   condition:
      ( uint16(0) == 0xfacf or uint16(0) == 0x457f or uint16(0) == 0x5a4d or uint16(0) == 0xface) and filesize < 10MB and $x1 and 6 of ($s*)
}

rule fscan {
   strings:
      $s1 = "yrstuv" fullword ascii
      $s2 = "NOPQRSy" fullword ascii
      $s3 = "<klmno" fullword ascii
      $s4 = "<./012" fullword ascii
      $s5 = "-./012y" fullword ascii
      $s6 = "234567<" fullword ascii
      $s7 = "<DEFGH" fullword ascii
      $s8 = "y#$%&'" fullword ascii
      $s9 = "yGHIJK" fullword ascii
      $s10 = "<cdefg" fullword ascii
      $s11 = "<ijklm" fullword ascii
      $s12 = "s).7'>" fullword ascii
      $s13 = "<KLMNO" fullword ascii
      $s14 = "y/0123" fullword ascii
      $s15 = "#$%&'(y" fullword ascii

//The following is a separate fscan_arm

      $a1 = "$Id: UPX 3.96 Copyright (C) 1996-2020 the UPX Team. All Rights Reserved. $" fullword ascii
      $a2 = "NTLMv2" fullword ascii
      $a3 = "lAnXuQmq" fullword ascii
      $a4 = "nvQdg!#" fullword ascii
      $a5 = "hpKD5J;ke" fullword ascii
      $a6 = "M_DTYwA9DS" fullword ascii
      $a7 = "7`JdPhL-S&" fullword ascii
      $a8 = "3mMTX!H" fullword ascii
      $a9 = "Keyurlfrphp" fullword ascii
      $a10 = "\\u0be?." fullword ascii
      $a11 = "\\i8.LJ" fullword ascii
      $a12 = "& m>l4L" fullword ascii
      $a13 = "Br(29$B" fullword ascii
      $a14 = "81 Uy82" fullword ascii
      $a15 = "l:6&F!" fullword ascii
      $a16 = "/73 Ay74" fullword ascii
      $a17 = "4O617)" fullword ascii
      $a18 = "2SUuSU" fullword ascii
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x457f or uint16(0) == 0xfacf ) and filesize < 8MB and ( 6 of ($s*)) or 8 of ($a*)) or ( all of ($s*) or all of ($a*) )
}

rule FindSomething
{
    meta:
        description = "I chose the program-specific icon as the detection object"
    strings:
        $s1 = {00 00 20 00 49 44 41 54 78 9C EC 7D 59 77 1C 37 92 35 50 FB BE 72 91 2C C9 9E EE F6 9C 7E 99 33 6F F3 07 E6 CF 4F BF 4D 8F E7 6B B7 3D 92 B5}
    condition:
        uint16be(0) == 0x8950 and filesize < 200KB and $s1

}

rule ExeinfoPe {
   meta:
      decription = "I selected the icon resource of this program. This program is packaged by upx. Even if it is unpacked, the icon still exists."
      hash1 = "7ffcbdedd2fef54b22840be62e0658d2bf203096f33dd9a95bcbb1698d324f42"
   strings:
      $s1 = {3D 32 3D 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 45 3D 2F 36 32 32 }
   condition:
      uint16(0) == 0x5a4d and filesize < 2MB and $s1
}

rule Erebus
{
    meta:
        description = "I choose the version screenshot in the project's readme.md as the identification"
    strings:
        $s1 = {00 00 20 00 49 44 41 54 78 01 ED 9D 0B 7C 54 D5 BD EF 7F 3B 09 06 79 19 40 AB 55 81 20 26 AD 88 DA 6A C5 07 41 93 A6 49 13 9E 0A EA B9 F5 09}
    condition:
        uint16be(0) == 0x8950 and filesize < 30KB and $s1

}

rule ENScan_GO {
   meta:
      description = "The program's command line icon is UTF-8 gesh and I couldn't find its icon there, so I picked the documentation that appeared with the icon on the start screen."
   strings:
/*
%sBuilt At: %s\nGo Version: %s\nAuthor: %s\nBuild SHA: %s\nVersion: %s\n\n"
\t\thttps://github.com/wgpsec/ENScan\n\n
工具仅用于信息收集，请勿用于非法用途\n
开发人员不承担任何责任，也不对任何滥用或损坏负责.\n
*/
      $x1 = {25 73 42 75 69 6C 74 20 41 74 3A 20 25 73 0A 47 6F 20 56 65 72 73 69 6F 6E 3A 20 25 73 0A 41 75 74 68 6F 72 3A 20 25 73 0A 42 75 69 6C 64 20 53 48 41 3A 20 25 73 0A 56 65 72 73 69 6F 6E 3A 20 25 73 0A 0A}
      $x2 = {09 09 68 74 74 70 73 3A 2F 2F 67 69 74 68 75 62 2E 63 6F 6D 2F 77 67 70 73 65 63 2F 45 4E 53 63 61 6E 0A 0A}
      $x3 = {E5 B7 A5 E5 85 B7 E4 BB 85 E7 94 A8 E4 BA 8E E4 BF A1 E6 81 AF E6 94 B6 E9 9B 86 EF BC 8C E8 AF B7 E5 8B BF E7 94 A8 E4 BA 8E E9 9D 9E E6 B3 95 E7 94 A8 E9 80 94 0A}
      $x4 = {E5 BC 80 E5 8F 91 E4 BA BA E5 91 98 E4 B8 8D E6 89 BF E6 8B 85 E4 BB BB E4 BD 95 E8 B4 A3 E4 BB BB EF BC 8C E4 B9 9F E4 B8 8D E5 AF B9 E4 BB BB E4 BD 95 E6 BB A5 E7 94 A8 E6 88 96 E6 8D 9F E5 9D 8F E8 B4 9F E8 B4 A3 2E 0A}
   condition:
      filesize < 30MB and all of them
}

rule ElevateKit {
   meta:
      hash1 = "905b9b288810220aa92e78d3d6fee94b5e4b6a2bfdd3879f994b0e369f16140d"
   strings:
      $x1 = "# generate our shellcode. Use 'thread' exit option as this DLL implementation migrates into winlogon.exe" fullword ascii
      $x2 = "# https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/windows/local/cve_2020_0796_smbghost.rb" fullword ascii
      $x3 = "bdllspawn!($1, getFileProper(script_resource(\"modules\"), \"cve-2016-0051.x86.dll\"), $stager, \"ms16-016\", 5000);" fullword ascii
      $x4 = "bdllspawn!($1, getFileProper(script_resource(\"modules\"), \"CVE-2020-0796.x64.dll\"), $stager, \"cve-2020-0796\", 5000);" fullword ascii
      $x5 = "beacon_elevator_register(\"uac-wscript\", \"Bypass UAC with wscript.exe\", &wscript_elevator);" fullword ascii
      $x6 = "bpowerpick!($1, \"Invoke-EnvBypass -Command \\\" $+ $payload_oneliner $+ \\\"\", $exploit_oneliner);" fullword ascii
      $x7 = "# Integrate wscript.exe Bypass UAC attack" fullword ascii
      $s8 = "$handle = openf(getFileProper(script_resource(\"modules\"), \"Invoke-EventVwrBypass.ps1\"));" fullword ascii
      $s9 = "bpowerpick!($1, \"Invoke-WScriptBypassUAC -payload \\\" $+ $2 $+ \\\"\", $oneliner);" fullword ascii
      $s10 = "$handle = openf(getFileProper(script_resource(\"modules\"), \"Invoke-WScriptBypassUAC.ps1\"));" fullword ascii
      $s11 = "beacon_elevator_register(\"uac-schtasks\", \"Bypass UAC with schtasks.exe (via SilentCleanup)\", &schtasks_elevator);" fullword ascii
      $s12 = "$handle = openf(getFileProper(script_resource(\"modules\"), \"Invoke-EnvBypass.ps1\"));" fullword ascii
      $s13 = "# https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/windows/local/ms15_051_client_copy_image.rb" fullword ascii
      $s14 = "# https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/windows/local/ms14_058_track_popup_menu.rb" fullword ascii
      $s15 = "# Integrate schtasks.exe (via SilentCleanup) Bypass UAC attack" fullword ascii
      $s16 = "# https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/windows/local/ms16_016_webdav.rb" fullword ascii
      $s17 = "# Integrate schtasks.exe (via SilentCleanup) Bypass UAC attack as an exploit!" fullword ascii
      $s18 = "# export our payload as a PowerShell script" fullword ascii
      $s19 = "# spawn a Beacon post-ex job with the exploit DLL" fullword ascii
      $s20 = "bpowerpick!($1, \"Invoke-EnvBypass -Command \\\" $+ $command $+ \\\"\", $oneliner);" fullword ascii
   condition:
      uint16(0) == 0x0a23 and filesize < 30KB and 1 of ($x*) and 4 of them
}

rule EHole {
   meta:
      description = "this has upx shell"
      hash1 = "8cf2c2f45ed34b2489b6f7c4cd6b7c24721011a8df756948e455d498bef000e2"
   strings:
      $s1 = "\"keyword\": [\"Airflow - Login\"]" fullword ascii
      $s2 = "    \"keyword\": [\"TamronOS\",\"loginbox\",\"tamronos.com\"]" fullword ascii
      $s3 = "    \"keyword\": [\"ER6300G2\",\"h3c.com\",\"login\"]" fullword ascii
      $s4 = "    \"keyword\": [\"ER3100\",\"h3c.com\",\"login\"]" fullword ascii
      $s5 = "\"keyword\": [\"/seeyon/USER-DATA/IMAGES/LOGIN/login.gif\"]" fullword ascii
      $s6 = "\"keyword\": [\"css/R1Login.css\", \"share.ti_username\",\"login_logo\"]" fullword ascii
      $s7 = "\",\"resources/commonImage/favicon.ico\",\"login/createQRCode.do\"]" fullword ascii
      $s8 = "\"keyword\": [\"LanProxy\",\"password\",\"lanproxy-config\"]" fullword ascii
      $s9 = "\"keyword\": [\"/console/framework/skins/wlsconsole/images/login_WebLogic_branding.png\"]" fullword ascii
      $s10 = "\"keyword\": [\"/por/login_psw.csp\"]" fullword ascii
      $s11 = "    \"keyword\": [\"Jhsoft.Web.login\",\"PassWord.aspx\"]" fullword ascii
      $s12 = "\"keyword\": [\"resources/image/logo_header.png\",\"360\",\"" fullword ascii
      $s13 = "\"cms\": \"Palo Alto Login Portal\"," fullword ascii
      $s14 = "\"keyword\": [\"Citrix Access Gateway\",\"login\"]" fullword ascii
      $s15 = "\"cms\": \"Ubiquiti Login Portals\"," fullword ascii
      $s16 = "\"keyword\": [\"Grafana\",\"login\",\"grafana-app\"]" fullword ascii
      $s17 = "\"keyword\": [\"/wnm/ssl/web/frame/login.html\"]" fullword ascii
      $s18 = "\",\"login\",\"useusbkey\"]" fullword ascii
      $s19 = "\"keyword\": [\"loginPageSP/loginPrivacy.js\"]" fullword ascii
      $s20 = "\"keyword\": [\"IBOS\",\"login-panel\",\"loginsubmit\"]" fullword ascii
   condition:
      uint16(0) == 0x0d7b and filesize < 200KB and 8 of them
}

rule EditThisCookie
{
    meta:
        description = "I chose the program-specific icon as the detection object"
    strings:
        $s1 = {00 00 0A 39 49 44 41 54 58 85 C5 97 7D 8C 5D C7 59 C6 7F 33 E7 EB DE 7B EE D7 DE FD F6 7E D8 5E DB B1 B7 8E B1 42 4B 02 11 B4 4A 09 A5 44 A1 B4 20 45 01 52 D8 08 AA 40 A1 50 15 15 50 40 08}
    condition:
        uint16be(0) == 0x8950 and filesize < 5KB and $s1

}

rule DruidCrack {
   meta:
      hash1 = "8a1dc161533e12b2ee830cae0dce6b76b63e286df05b4e2637d69ca1b02136da"
   strings:
      $s1 = "com/alibaba/druid/proxy/jdbc/StatementExecuteType.class" fullword ascii
      $s2 = "com/alibaba/druid/proxy/jdbc/StatementExecuteType.classPK" fullword ascii
      $s3 = "com/alibaba/druid/support/spring/stat/annotation/StatAnnotationBeanPostProcessor.class" fullword ascii
      $s4 = "com/alibaba/druid/support/spring/stat/annotation/StatAnnotationBeanPostProcessor.classPK" fullword ascii
      $s5 = "com/alibaba/druid/support/ibatis/SqlMapExecutorWrapper.classPK" fullword ascii
      $s6 = "com/alibaba/druid/support/ibatis/SqlMapExecutorWrapper.class" fullword ascii
      $s7 = "com/alibaba/druid/sql/dialect/mysql/ast/statement/MySqlExecuteStatement.classPK" fullword ascii
      $s8 = "com/alibaba/druid/sql/dialect/mysql/ast/statement/MySqlExecuteStatement.class" fullword ascii
      $s9 = "com/alibaba/druid/sql/dialect/mysql/ast/statement/MySqlExecuteForAdsStatement.class" fullword ascii
      $s10 = "com/alibaba/druid/mock/handler/MockExecuteHandler.classPK" fullword ascii
      $s11 = "com/alibaba/druid/sql/dialect/mysql/ast/statement/MySqlExecuteForAdsStatement.classPK" fullword ascii
      $s12 = "com/alibaba/druid/sql/dialect/oracle/ast/stmt/OracleExecuteImmediateStatement.classPK" fullword ascii
      $s13 = "com/alibaba/druid/sql/dialect/oracle/ast/stmt/OracleExecuteImmediateStatement.class" fullword ascii
      $s14 = "com/alibaba/druid/mock/handler/MySqlMockExecuteHandlerImpl.classPK" fullword ascii
      $s15 = "com/alibaba/druid/mock/handler/MySqlMockExecuteHandlerImpl.class" fullword ascii
      $s16 = "com/alibaba/druid/mock/handler/MockExecuteHandler.classu" fullword ascii
   condition:
      uint16(0) == 0x4b50 and filesize < 4MB and 8 of them
}

rule Disable_JavaScript
{
    meta:
        description = "I chose the program-specific icon as the detection object"
    strings:
        $s1 = {00 00 10 41 49 44 41 54 78 9C ED 9D 4B 6C 5C D7 79 C7 FF E7 DC C7 DC D1 90 9C 21 44 91 26 44 89 74 13 A4 4D 55 88 DC D4 76 02 44 24 A0 2A 69}
    condition:
        uint16be(0) == 0x8950 and filesize < 10KB and $s1

}

rule dirsearch 
{
   meta:
      description = "The program has neither a command line icon nor a command line description, so only features in the main code can be selected as rules"
      hash1 = "076ea463a7dca58dd90673b1a4c1128a1fc22ad1a487cf5108fd89885ca7250c"
   strings:
    $x1 = "#  This program is free software; you can redistribute it and/or modify" fullword ascii
    $x2 = "#  it under the terms of the GNU General Public License as published by" fullword ascii
    $x3 = "#  the Free Software Foundation; either version 2 of the License, or" fullword ascii
    $x4 = "#  (at your option) any later version." fullword ascii
    $x5 = "#  This program is distributed in the hope that it will be useful," fullword ascii
    $x6 = "#  but WITHOUT ANY WARRANTY; without even the implied warranty of" fullword ascii
    $x7 = "#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the" fullword ascii
    $x8 = "#  GNU General Public License for more details." fullword ascii
    $x9 = "#  You should have received a copy of the GNU General Public License" fullword ascii
    $x10 = "#  along with this program; if not, write to the Free Software" fullword ascii
    $x11 = "#  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston," fullword ascii
    $x12 = "#  MA 02110-1301, USA." fullword ascii
    $x13 = "#  Author: Mauro Soria" fullword ascii
   condition:
      uint16(0) == 0x2123 and filesize < 4MB and all of them
}

rule dirmap {
   meta:
      description = "I picked the icons part of this command line interface, I think they are generic and unique."
   strings:
/*
                     #####  # #####  #    #   ##   #####
                     #    # # #    # ##  ##  #  #  #    #
                     #    # # #    # # ## # #    # #    #
                     #    # # #####  #    # ###### #####
                     #    # # #   #  #    # #    # #
                     #####  # #    # #    # #    # #   v1.0
*/
      $x1 = {0A 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 23 23 23 23 23 20 20 23 20 23 23 23 23 23 20 20 23 20 20 20 20 23 20 20 20 23 23 20 20 20 23 23 23 23 23 0A 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 23 20 20 20 20 23 20 23 20 23 20 20 20 20 23 20 23 23 20 20 23 23 20 20 23 20 20 23 20 20 23 20 20 20 20 23 0A 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 23 20 20 20 20 23 20 23 20 23 20 20 20 20 23 20 23 20 23 23 20 23 20
23 20 20 20 20 23 20 23 20 20 20 20 23 0A 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 23 20 20 20 20 23 20 23 20 23 23 23 23 23 20 20 23 20 20 20 20 23 20 23 23 23 23 23 23 20 23 23 23 23 23 0A 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 23 20 20 20 20 23 20 23 20 23 20 20 20 23 20 20 23 20 20 20 20 23 20 23 20 20 20 20 23 20 23 0A 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 23 23 23 23 23 20 20 23 20 23 20 20 20 20 23 20 23 20 20 20 20 23 20 23 20 20 20 20 23 20 23 20 20 20 76 31 2E 30 0A}
   condition:
      uint16(0) == 0x2123 and filesize < 21KB and $x1
}

rule CrackMinApp {
   meta:
      description = "This is the bytecode of the extracted icon resource"
      hash = "e88edcd093e89d3fbd8771abf64c0bf33565b781"
   strings:
      $s1 = {6B 38 FF F3 6A 38 FF F3 6B 37 FF F3 6B 38 FF F3 6B 38 FF F3 6B 38 FF F3 6B 38 FF F2 6A 38 FF A0 52 3A FF 65 42 3D FF 64 42 3D FF 65 42 3D FF 65 42 3D FF 65 42 3D FF 65 42 3D FF 65 42 3D FF 64 42 3D FF 65 42 3D FF 65 42 3D FF 65 42 3D FF 65 42 3D FF A0 53 3A FF F2 6A 37 FF F3 6B 38 FF F3 6B 38 FF F3 6B 37 FF F3 6B 38 FF F3 6B 38 FF F3 6B 37 FF F3 6B 38 }
   condition:
      uint16(0) == 0x5A4D and filesize < 1MB and $s1
}

rule arjun {
   meta:
      decription = "I picked the icons part of this command line interface, I think they are generic and unique."
      hash1 = "f138f0c4f6edb53a8a2868f9ee4a8fdf088b2d19aedb101b695a7722d23791db"
   strings:
/*
%s    _
   /_| _ '
  (  |/ /(//) v%s
      _/      %s
*/
      $x1 = {25 73 20 20 20 20 5F 0A 20 20 20 2F 5F 7C 20 5F 20 27 0A 20 20 28 20 20 7C 2F 20 2F 28 2F 2F 29 20 76 25 73 0A 20 20 20 20 20 20 5F 2F 20 20 20 20 20 20 25 73 0A}
   condition:
      uint16(0) == 0x2123 and filesize < 20KB and $x1
}

rule AppInfoScanner {
   meta:
      description = "I picked out the instructions for using the command line interface, I think they are generic and unique"
      hash1 = "596b2c070eaf18a13f581981e1bd03f49984e8c1be7dfa422d7d80b9335282f8"
   strings:
/*
Commands:
  android  Get the key information of Android system.
  ios      Get the key information of iOS system.
  web      Get the key information of Web system.
*/
      $x1 = "Get the key information of Android system." fullword ascii
      $x2 = "Get the key information of iOS system."
      $x3 = "Get the key information of Web system."
   condition:
      uint16(0) == 0x2123 and filesize < 10KB and all of them
}
```

0x05 总结：
========

规则不是一次性的，所以它应该要可被理解和接受的，这样在别人维护和更新时才能有迹可循。追踪病毒家族组织也是一样的，需要不断对比前后的变化提取出尽可能持久的规则，有时还需梳理出其的演变进阶过程，所以一种好的规则尤其重要！

0x06 参考链接：
==========

[PE module — yara 4.2.0 documentation](https://yara.readthedocs.io/en/v4.2.3/)  
[Threekiii/Awesome-Redteam: 一个红队知识仓库 (github.com)](https://github.com/Threekiii/Awesome-Redteam#%E5%86%85%E7%BD%91%E7%A9%BF%E9%80%8F)  
[Neo23x0/yarGen: yarGen is a generator for YARA rules (github.com)](https://github.com/Neo23x0/yarGen)  
[Neo23x0/yarAnalyzer: Yara Rule Analyzer and Statistics (github.com)](https://github.com/Neo23x0/yarAnalyzer)  
[Neo23x0/YARA-Performance-Guidelines：关于如何编写快速且内存友好的 YARA 规则的指南 (github.com)](https://github.com/Neo23x0/YARA-Performance-Guidelines/#atoms)  
[How to Write Simple but Sound Yara Rules - Nextron Systems (nextron-systems.com)](https://www.nextron-systems.com/2015/02/16/write-simple-sound-yara-rules/)  
[How to Write Simple but Sound Yara Rules - Part 2 - Nextron Systems (nextron-systems.com)](https://www.nextron-systems.com/2015/10/17/how-to-write-simple-but-sound-yara-rules-part-2/)

[如何编写简单但合理的 Yara 规则 - 第 3 部分 - Nextron Systems (nextron-systems.com)](https://www.nextron-systems.com/2016/04/15/how-to-write-simple-but-sound-yara-rules-part-3/)