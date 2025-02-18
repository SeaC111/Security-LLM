0x00 什么是VBA stomping？
=====================

VBA stomping 是指破坏 Microsoft Office 文档中的 VBA 源代码，只在文档文件中留下称为 p-code 的宏代码的编译版本。攻击者可以通过良性代码或随机字节，覆盖VBA源代码位置，同时通过保留先前编译的恶意p-code，隐藏恶意VBA代码。

0x01 实现方式
=========

实现VBA stomping有两种方式，一种是手动修改，一种是通过工具Evil Clippy。

手动修改
----

- 测试所需环境
    
    
    - Windows 10
    - Office2016
    - 解压缩软件
    - 十六进制编辑器

### 创建宏

新建Excel文件，创建宏，可以通过点击视图--&gt;宏--&gt;查看宏--&gt;输入宏名，创建

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-5930b8e68d8b44e75e71131069e13fbefbfd3e09.png)

也可以通过文件--&gt;选项--&gt;自定义功能区--&gt;勾选开发工具--确定

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-00530610fd050b45bf78bbe175c7c66efa12de35.png)

然后点击开发工具--&gt;Visual Basic创建宏

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-35a1237597c44d6aed381cddb72e97c80027af45.png)

### 编辑宏代码

这里我双击的Sheet1，然后编辑宏代码，实现弹窗显示ABC

```vb
Sub test()
MsgBox "ABC"
End Sub
```

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-8f0b8584816ce76ebeb25b71662be15eb2bcd79c.png)

代码编辑完成后，然后保存，这个时候如果提示“无法在未启用宏的工作簿中保存以下功能”

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-1d867b7dbc2bbada33b19f1dc11df0bd01d2dd44.png)

点击否，会弹出另存文件的框，将保存类型选择为“Excel启用宏的工作簿”，点击保存即可

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-d0aff941aaa03d3f75f212708b178ab8e391b52d.png)

运行宏代码，测试下

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-89d717fd82fd3760e7cc82b065f6ea753f818716.png)

### VBA stomping

选中刚创建的Excel文件，右键选择压缩软件，将该文件解压缩

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-0b371dd626c056e79d5008f20df2ef0d90e20a2b.png)

打开开解压缩后的文件夹，找到xl文件下的vbaProject.bin。

PS：这个vbaProject.bin是默认文件名，但是可以重命名。

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-ea08e04b261e83ee254cd7308e250c4630f6d09d.png)

将文件用十六进制编辑器打开，找到源代码。

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-a6fd2fe98238e64763f2c864c79b3b577e015a50.png)

将ABC改成XYZ并保存。**注意**：修改代码的时候，点击需修改的内容，比如A，然后输入新的内容就行，会自动覆盖掉ABC

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-8e500b9ea1da26cb3986a7739ca9a686a779cde5.png)

然后选中我们的Excel文件，右键选择压缩软件，打开压缩包

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-b16f2fd00ad9e749b3a906fd58fb0c89feed6e2d.png)

进入xl文件夹，用修改后的vbaProject.bin将文件进行替换

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-583db96c0c291b413148bbb9832a074beb8a160d.png)

替换完成后，打开Excel文件，显示“宏已被禁用，启动内容”，**注意**：这个时候先别点启用内容，先去看看宏代码

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-e522f8a17b370e3d92c3faa76d8ae7ebb95d86f5.png)

点击开发工具--&gt;Visual Basic，可以看到原来的`MsgBox "ABC"`变成了`MsgBox "XYZ"`

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-bf937ddef86f608bb600355187b0cd052be6fabe.png)

这个时候我们再启用宏，运行宏代码，结果弹出来的是ABC

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-f2d9401fcb7939406a5d0e2f0b95e27a97d7b3f6.png)

再打开宏代码进行查看，又变成了`MsgBox "ABC"`

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-c84973ddcd26a7e5fe6b2fa93c184690cac62b21.png)

### 为什么会这样？

这是因为存储在文档中的 p-code就是实际执行的代码，只要它与系统上当前的 VBA 版本兼容。而宏编辑器在未启用内容前显示的是解压缩的VBA源代码，在启用内容后，显示的不是解压缩的 VBA 源代码，而是反编译的p-code。

有一个需要注意的点：**只能使用用于创建文档的相同 VBA 版本来执行 VBA Stomping 的恶意文档。**

因为在不同版本的 Word（使用不同的 VBA 版本）中打开文档， p-code将无法重用，所以会强制将 VBA 源代码解压缩并重新编译为p-code。可以理解为：你将原有的vbaProject.bin文件中的`MsgBox "ABC"`修改成`MsgBox "XYZ"`并替换后，此时你VBA的源代码是`MsgBox "XYZ"`，p-code是编译后的`MsgBox "ABC"`。但用不同版本的VBA打开，就会将VBA 源代码解压缩并重新编译为p-code，所以会将你VBA的源代码中`MsgBox "XYZ"`重新编译成p-code，那么你再启动宏，运行的是p-code，也就是重新编译后的`MsgBox "XYZ"`。

因此，攻击者生成恶意文档之前，会对目标进行侦察，来确定要使用的适当 Office 版本或通过生成具有多个 Office 版本的恶意文档并将它们喷洒到目标来解决此限制。

Evil Clippy
-----------

### 下载工具

下载链接：

> [EvilClippy](https://github.com/outflanknl/EvilClippy)

### 生成可执行文件

下载后解压缩，使用VS打开该文件夹

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-798e7645d5893acdcf155b1c82fe971475e4ab9b.png)

使用VS打开文件夹后，选中并右键--&gt;在终端中打开，打开开发者窗口

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-2289dd22356b4e85ada83089600bbffe79b57f27.png)

在开发者窗口中输入命令，生成可执行文件

```powershell
csc /reference:OpenMcdf.dll,System.IO.Compression.FileSystem.dll /out:EvilClippy.exe *.cs
```

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-81a2ce30470c0b4a360fe87d1cb571322fbda31d.png)

在窗口中输入`.\EvilClippy -h`，就可以查看参数信息

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-d6a1ad28ea1d107045b2a7d572edebc5c4cd6c76.png)

### VBA stomping

创建一个xlsm文件(也就是上述提到的，启动宏的工作簿)，写上宏代码`MsgBox "ABC"`；接着创建一个vba文件，写上宏代码`MsgBox "XYZ"`

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-824dd4bd2bf128aba08d1607204826010738233c.png)

在开发者窗口中使用工具EvilClippy.exe执行命令，将会生成VBA stomping后的1\_EvilClippy.xlsm文件

PS：以下命令根据自己的文件路径来，比如EvilClippy.exe在test文件夹的上级目录，所以我这里写成`..\EvilClippy`

```powershell
. ..\EvilClippy -s abc.vba 1.xlsm
```

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-dfddd13f6efae46c10cc4f81ee55515302e5e075.png)

打开生成的1\_EvilClippy.xlsm文件，同样的先不要启用内容

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-9bee02414c784a39db47898fdd23a7b06910e4e7.png)

查看宏代码，显示的是`MsgBox "XYZ"`

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-36cc5ee50999dabd4f418d2f8b1e784cb6a1abea.png)

然后我们再运行宏看看，发现弹出的却是ABC

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-b42b715c0bb173596db6243b551165ce74026c2a.png)

此时再查看宏代码，也变成了`MsgBox "ABC"`

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-b77c116f87dd02b24d30f5a10137223816a5f5fb.png)

0x02 总结
=======

攻击者可以使用这种方法用良性代码或随机代码，隐藏恶意的源代码。通过VBA stomping，当你查看宏代码，发现没有恶意代码而启动宏的时候，就会运行攻击者恶意的源代码了。