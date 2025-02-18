### **前言**

最近在渗透测试的时候，在后台发现一个打包功能点，可以对文件进行解析，并生成html文档。

![1.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-7b118fdea8ec0f128296428222e6d95a07e3f49e.png)

发现文档是rdoc生成的，搜索发现rdoc是ruby中的一个文档生成器，并且rdoc低于3.0.1版本存在命令注入漏洞的，利用[CVE-2021-31799](https://nvd.nist.gov/vuln/detail/CVE-2021-31799)成功getshell，顺便本地搭建了一个环境来分析一下。

### **漏洞描述**

- 漏洞类型

命令注入

- 影响版本

RDoc 3.11 - 6.3.0

- 漏洞等级

高

- CVE编号

[CVE-2021-31799](https://nvd.nist.gov/vuln/detail/CVE-2021-31799)

### **组件介绍**

RDoc是Ruby程序的文档生成器。它可以解析Ruby源代码并生成HTML文档。它可以通过包含在Ruby发行版中的命令行工具使用，也可以通过作为一个Gem包进行安装。RDoc支持文本格式的注释和Ruby源代码中的一些标记来指示要如何渲染注释。它还可以生成相应的RDoc文件，使您可以浏览整个库。

### **Rdoc的安装**

`gem install rdoc -v 6.3.0`

### **漏洞分析**

- 漏洞详情

RDoc用来调用Kernel#open来打开一个本地文件。如果一个Ruby项目有一个文件，其名称以|开头，以tag结尾，那么管道字符后面的命令就会被执行。

- 漏洞分析

首先，漏洞详情说的是open函数，在ruby中，open函数是可以直接执行命令的，在清风月郎居师傅的[博客文章](https://niubl.com/2021/05/04/research-on-ruby-command-injection-vulnerability/)中介绍

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-2ce4a4ccc96363c02515dd90e3273f23a84af7ae.png)

官方文档给出一个示例代码，可以通过管道符号执行系统命令

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-82858bb9fb62d866c64ef58c66210aa3fc6b09ec.png)

查看rdoc修复代码，漏洞函数是在产生漏洞的代码在lib/rdoc/rdoc.rb的remove\_unparseable方法，使用了open函数接收外部参数。

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-58b22cccb8939b9bcac4aea22613c7af0071e13e.png)

```ruby
  def remove\_unparseable files

    files.reject do |file, \*|

      file =~ /\\.(?:class|eps|erb|scpt\\.txt|svg|ttf|yml)$/i or

        (file =~ /tags$/i and

         **open(file, 'rb')** { |io|

           io.read(100) =~ /\\A(\\f\\n\[^,\]+,\\d+$|!\_TAG\_)/

         })

    end

  end
```

把rdoc 的6.3.0源码下载到本地进行调试。  
[Release v6.3.0 · ruby/rdoc · GitHub](https://github.com/ruby/rdoc/releases/tag/v6.3.0)  
在本地目录中提前新建好一个文件，命令为  
`touch '| touch evil.txt && echo tags'`

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-c9fc03ff814e8b3def31dcab4d8b5325d918a420.png)

下面开始分析该漏洞过程。  
先在编辑器中给该方法打上断点

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-a0e6dd7b98833cddfe29c6d205a7c7b368cdff52.png)

IDE的运行配置，设置好工作目录和rdoc文件位置  
![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-9a40bf0169225c77792c2cca97e9072fb3161c01.png)

点击debug，在该方法前面暂停下来。

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-d688d06d93b7ec56f12a622121106ecca9e614ae.png)

给该方法传入了一个hash，hash中的key为目录中的文件名称。

`{"| touch evil.txt && echo tags"=>2023-04-18 07:38:21.544248155 +0000}`

通过reject方法把key值取出来，**| touch evil.txt &amp;&amp; echo tags** ，赋予file变量。

把file变量进行两次判断，用or连接。

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-ad8a6b2a21a1ba5e8f6a6607fb6ccae53c4f488d.png)

- 第一个匹配  
    `file =~ /\\.(?:class|eps|erb|scpt\\.txt|svg|ttf|yml)$/i`  
    用于检查文件名是否符合一些特定的扩展名，即class、eps、erb、scpt.txt、svg、ttf、yml，不区分大小写，这个匹配肯定是不符合的，但是这里用的是or，ruby进入下一个判断。
- 第二个匹配

```ruby
(file =~ /tags$/i and  
 open(file, 'rb') { |io|  
   io.read(100) =~ /\\A(\\f\\n\[^,\]+,\\d+$|!\_TAG\_)/  
 })
```

先对file变量进行匹配，现在file变量的值是  
`| touch evil.txt && echo tags`  
符合括号中代码的第一个匹配规则，匹配判断结尾是否有tags字符串，返回真

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-b82e826a67bf9141c5a0f05d1b532e22c7bc5947.png)

然后and进行下一个判断，open函数执行变成了下面这串代码

**open("| touch evil.txt &amp;&amp; echo tags",’rb’)**

然后把结果保存到io变量中，通过read方法读取io中的值，进行匹配

`io.read(100) =~ /\\A(\\f\\n\[^,\]+,\\d+$|!\_TAG\_)/`

等方法执行完毕，就执行了`touch evil.txt`命令，成功在目录中新建了evil.txt文件。

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-f22fa88587f6c8d3a570ff4dc52cb7422361e0ab.png)

还可以通过"|$(id)-tags" 这样的输入，执行命令。

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-d5eda069cef8678c1018a9f40c4783b917c3ac13.png)

### **修复过程**

官方把open函数更换成了File.open函数

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-1ef27942eeb1c1f7f3fa31cf070e701f3d08f89f.png)

### **修复措施**

升级到rdoc6.3.1版本

### **参考链接**

- <https://blog.vackbot.com/archives/ruby-an-quan-man-tan>
- <https://niubl.com/2021/05/04/research-on-ruby-command-injection-vulnerability/>