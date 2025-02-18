CraftCMS在4.4.14版本中存在服务器端模板注入的漏洞，经过身份验证的攻击者可以绕过路径过滤设置模板目录，将任意文件上传至Twig模板目录中，从而导致模板注入进而造成远程代码执行。

0x01 环境搭建
=========

这里使用craft cms 4.4.14版本，首先从github的Releases中下对应版本的压缩包解压，也可以通过composer或ddev进行安装，需要这里需要linux系统，并且php版本需要高于8.0，中间件为apache，因为程序安装完后会自动生成apache的伪静态配置文件，少一部配置过程。

```php
composer create -y --no-scripts craftcms/craft=4.4.14
```

然后执行`php craft setup`进行设置安装

![image-20230907141916580](https://shs3.b.qianxin.com/butian_public/f528407ba04a13ab76bab6c8f173f296f614cc1bfde24.jpg)

设置数据库相关信息和管理员密码后会自动导入数据库进行安装，安装成功后访问如下即可

![image-20230907113620674](https://shs3.b.qianxin.com/butian_public/f193008714469be62022063d05863f27570d3b59befee.jpg)

0x02 漏洞复现及分析
============

- 1. 设置Filesystem

首先进入后台，点击Settings设置Filesystem

> Filesystem将资产管理（组织、权限和内容）与实际存储和服务文件的细节分离。

这里Name和Handle可以随便填，Base Path需要填写模板文件的路径，当我们直接填写模板文件的绝对路径时

![image-20230907152102498](https://shs3.b.qianxin.com/butian_public/f90583311b2d5a1e2b9b79deebb595dfe2d4f7b7f4846.jpg)

在保存时会提示`Local volumes cannot be located within system directories.`提示本地卷不能位于系统目录中。在之前的版本中，我们可以可以填写模板文件的路径，但是在之后的版本中进行修复，增加了`validatePath`方法对输入的路径进行检测

![image-20230907114840910](https://shs3.b.qianxin.com/butian_public/f8683183550066f00955a4665928a06743e255a6823fb.jpg)

![image-20230907114854192](https://shs3.b.qianxin.com/butian_public/f398470952b7f3efe17f9a2a970cdba9afc4b7087ebb7.jpg)

在`validatePath`方法中，会分别获取需要验证的路径和系统路径进行一一对比，

如果为系统路径则报错`Local volumes cannot be located within system directories.`提示本地卷不能位于系统目录中，在SystemPaths中正好有模板目录的路径，所以这里会被拦截

![image-20230907154950484](https://shs3.b.qianxin.com/butian_public/f747432ff6c81039fdda6f9f36526f9438a586f09f5e6.jpg)

但是这里可以通过`file`协议来进行绕过，但是这里**仅支持linux系统**，因为在windows下路径的风格时采用反斜杠"\\"，所以程序会将输入的内容进行替换

![image-20230907154402829](https://shs3.b.qianxin.com/butian_public/f5478358eb51e6f84736e53193a4e80348a9363feac46.jpg)

所以使用`file://`也会被替换成`file:\\`导致不会进入第二个红框里进行跳出，最后进入第三个红框中将所以路径用操作系统对应的分隔符进行拼接，最后形成

```php
file:\C:\CraftCMS-4.4.14\templates
```

而在linux中则会在第二个判断协议中直接跳出判断，可以正常设置。所以这里只有linux才能复现成功。

![image-20230907154850487](https://shs3.b.qianxin.com/butian_public/f8491424e7690ede4d10476cba5aedb8f5947cbb433aa.jpg)

- 2. 设置Asset

接下来就是创建资产，点击Settings设置Asset，新增一个Volumes（卷）

> Craft 允许您像条目和其他内容类型一样管理媒体和文档文件（“Asset”）。Asset可以存在于任何地方——Web 服务器上的目录，或 Amazon S3 等远程存储服务。
> 
> 资产被组织成**卷**，每个卷都位于文件系统之上，并具有自己的权限和内容选项。卷是从**Settings** → **Assets**配置的。

这里的Name和Handle可以随便填，Filesystem选择我们刚刚新建好的，然后点击右上角的保存

![image-20230907162017888](https://shs3.b.qianxin.com/butian_public/f963894b9842b160eb7978e38ada2343e661d12dad91c.jpg)

- 3. 上传模板文件

接下里就可以在模板目录里上传模板文件了，该cms使用的是Twig模板进行渲染的，所以这里我们可以使用Twig模板引擎注入进行RCE，

关于Twig模板注入已经有师傅在社区中研究过了，具体可以移步至 [Twig 模板引擎注入详解](https://forum.butian.net/share/2242)学习

所以构造以下payload

```php
{{123*123}}
{{['whoami']|map('system')|join}}
{{['id']|map('system')|join}}
```

这里简单说一下它和flask中的jinja2模板引擎差不多，都是使用一对大括号包裹语法。由于craft cms使用的twig模板引擎的版本是3.x，所以可以使用map过滤器进行构造payload，在模板中会被编译为如下图，第二行的代码手下按会经过`twig_array_map`然后执行`twig_join_filter`：

![image-20230908112313933](https://shs3.b.qianxin.com/butian_public/f452385d90851c4329f8fd0c382e35db3e426018f2c3e.jpg)

查看map过滤器的源码：

![image-20230908111901556](https://shs3.b.qianxin.com/butian_public/f464921fc468f041d02ae4cd74fd6700045d2f70ff11f.jpg)

这里`$r[$k] = $arrow($v, $k)`，只要控制传过来的两个参数`$arrow`和`$array`就可以实现函数调用

由于map过滤器返回的是一个array类型，所以还需要用`join`将其转传承string才能正常显示。

![image-20230908112729791](https://shs3.b.qianxin.com/butian_public/f115353ea0ffab5f559581da06a7616471799098efca1.jpg)

将该内容保存为`poc.txt`，然后在Assets中上传文件

![image-20230907172347183](https://shs3.b.qianxin.com/butian_public/f8745408c2bd5ed44c86e50ff478e5afa2036c8b0f963.jpg)

这里上传文件时，会首先对前面设置的Filesystem中的路径进行创建，

![image-20230907174019881](https://shs3.b.qianxin.com/butian_public/f8717159cca6d35092bf553d2022881e16cf3da5ad1d2.jpg)

这里使用的是`mkdir`方法，通过查看官方文档查看`file://`和`mkdir`

![image-20230907173608186](https://shs3.b.qianxin.com/butian_public/f332565e401f8af1a8f58633f9d152ecc071e6939d45c.jpg)

![image-20230907173846702](https://shs3.b.qianxin.com/butian_public/f52797477d97e6a2107d242e3766854d65136551469fb.jpg)

- 4. 设置路由

在Settings然后点击New route新建一个路由，URI设置`test`（当然也可以设置为`*`），Template设置poc.txt

![image-20230907172608116](https://shs3.b.qianxin.com/butian_public/f2627713077f5368707dadad1ce00e2c45f766765cd01.jpg)

最后访问设置的路由即可实现rce

![image-20230907172642016](https://shs3.b.qianxin.com/butian_public/f37487633fdef868372ada5bc167e7f544260c34d559f.jpg)

0x03 修复方式
=========

官方已经发布了修复方式

![image-20230907172831401](https://shs3.b.qianxin.com/butian_public/f204573cb62395346ce301e1f7d6d8b8a4ef76f3837c6.jpg)

对输入的路径移除最左边的`file://`