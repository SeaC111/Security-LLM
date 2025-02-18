C#根据登录文件制作解密工具
==============

前言
--

当我们在渗透时，经常会遇到这样一种情况，就是wenshell后进行数据库查询账号密码时，只能够获取加密后的密码信息，而这个密码对我们后续渗透至关重要，通过各种手段尝试解密都无效，此时我们要获取到明文密码，可以根据网站登录文件中的代码查看该加密算法是否可逆，如果可逆根据登录文件中的代码来制作解密工具，获取我们所需要的明文密码。

工具
--

**Visual Studio 2017**  
[https://blog.csdn.net/weixin\_42614447/article/details/86598286](https://blog.csdn.net/weixin_42614447/article/details/86598286)  
**ILSpy**  
链接：<https://pan.baidu.com/s/1cvruIlquMAorE9Rt5vk94A>  
提取码：874t

对登录文件处理与分析
----------

获取到数据库服务器权限时，通过查询用户的账号密码，获取到密文，此时分析该密文，通过网上的各种资料并不能破解，接下来该怎么办？由于这里主要讲制作解密工具，所以如何获取到权限就不谈了。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-84ad36f191605b9efb72c0d2a449951132c352a7.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-84ad36f191605b9efb72c0d2a449951132c352a7.png)  
账号和密文

```php
admin AE5F6187F32825CA
cc123 B97C57DB005F954242450A255217DA9F
```

通过msf反弹的会话，查看网站的登录代码，分析这个网站得知是使用asp.net开发的，并且是由C#实现的伪静态。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-5a12fbc953980183ed6cf57dcb95dd860a623437.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-5a12fbc953980183ed6cf57dcb95dd860a623437.png)  
查找并下载登录文件后，使用ILSpy对App\_Web\_login.aspx.fdf7a39c.dll文件进行反编译  
**App\_Web\_login.aspx.fdf7a39c.dll下载：**  
链接：<https://pan.baidu.com/s/1JVmK2UxVn9uVploGLjnFow>  
提取码：t2vi  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-be254e24c394d2dd613cd3f96f2f83eb3dfd783a.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-be254e24c394d2dd613cd3f96f2f83eb3dfd783a.png)

寻找加密函数

[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-b744e7d47c9a0b731e53d82e7820cca6ddf3e029.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-b744e7d47c9a0b731e53d82e7820cca6ddf3e029.png)

找到加密的文件的同时发现解密文件，此时就要感觉很欣慰，说明该密文是可以解密的，在加密文件中通过一个类实现加密方法，并且结合上图可知skey传入的值为yx139222，skey的值至关重要，它相当于秘钥。

[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-13d4b1d4d9d25160e3e64e9300046a945518358d.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-13d4b1d4d9d25160e3e64e9300046a945518358d.png)

加密方法代码：

```csharp
// StringClass
public static string Encrypt(string pToEncrypt, string sKey)
{
    DESCryptoServiceProvider dESCryptoServiceProvider = new DESCryptoServiceProvider();
    byte[] bytes = Encoding.Default.GetBytes(pToEncrypt);
    dESCryptoServiceProvider.Key = Encoding.ASCII.GetBytes(sKey);
    dESCryptoServiceProvider.IV = Encoding.ASCII.GetBytes(sKey);
    MemoryStream memoryStream = new MemoryStream();
    CryptoStream cryptoStream = new CryptoStream(memoryStream, dESCryptoServiceProvider.CreateEncryptor(), CryptoStreamMode.Write);
    cryptoStream.Write(bytes, 0, bytes.Length);
    cryptoStream.FlushFinalBlock();
    StringBuilder stringBuilder = new StringBuilder();
    byte[] array = memoryStream.ToArray();
    for (int i = 0; i < array.Length; i++)
    {
        byte b = array[i];
        stringBuilder.AppendFormat("{0:X2}", b);
    }
    stringBuilder.ToString();
    return stringBuilder.ToString();
}

```

解密文件也是通过一个类实现解密方法  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-d0d4a5c2cefe266e085ae5f396197993ee9c6cd0.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-d0d4a5c2cefe266e085ae5f396197993ee9c6cd0.png)

解密方法代码：

```csharp
// StringClass
public static string Decrypt(string pToDecrypt, string sKey)//将密文与skey的值进行配合解密
{
    DESCryptoServiceProvider dESCryptoServiceProvider = new DESCryptoServiceProvider();
    byte[] array = new byte[pToDecrypt.Length / 2];
    for (int i = 0; i < pToDecrypt.Length / 2; i++)
    {
        int num = Convert.ToInt32(pToDecrypt.Substring(i * 2, 2), 16);
        array[i] = (byte)num;
    }
    dESCryptoServiceProvider.Key = Encoding.ASCII.GetBytes(sKey);
    dESCryptoServiceProvider.IV = Encoding.ASCII.GetBytes(sKey);
    MemoryStream memoryStream = new MemoryStream();
    CryptoStream cryptoStream = new CryptoStream(memoryStream, dESCryptoServiceProvider.CreateDecryptor(), CryptoStreamMode.Write);
    cryptoStream.Write(array, 0, array.Length);
    cryptoStream.FlushFinalBlock();
    new StringBuilder();
    return Encoding.Default.GetString(memoryStream.ToArray());
}

```

制作解密工具
------

使用Visual Studio 2017  
新建一个项目，这里要注意使用.NET F ramework 4.5框架  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-0aca3f7d6e5dec2cc7a5fa884317027580c63d86.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-0aca3f7d6e5dec2cc7a5fa884317027580c63d86.png)

先看一下我们制作的工具大致框架：

[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-e74282ddc5afdadc90c45c973eb2b9582747a032.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-e74282ddc5afdadc90c45c973eb2b9582747a032.png)

添加框架

[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-99bee19bfc54eea2b7217eeed8b2a52dd55e2214.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-99bee19bfc54eea2b7217eeed8b2a52dd55e2214.png)

修改框架文本中的内容，文本内容根据需要进行填写

[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-b90eb24e424f14f34b460c33f1247640397cf1a0.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-b90eb24e424f14f34b460c33f1247640397cf1a0.png)

添加文本框

[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-583c166142a5edc726088155ff46a9b64b09e7b9.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-583c166142a5edc726088155ff46a9b64b09e7b9.png)

添加标签

[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-ec266debd7108d529ecff830cf9c91e094b35887.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-ec266debd7108d529ecff830cf9c91e094b35887.png)

添加解密按钮

[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-b2dce347366cf77ac8fa7c90b21c44adf56aec24.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-b2dce347366cf77ac8fa7c90b21c44adf56aec24.png)

双击解密按钮，会自动跳转到按钮的代码文件，将解密类放置对应位置后，发现有函数缺少using指令或程序集引用，此时有点不知所措，不要急百度一波，发现该工具可以添加指定的using指令或程序集。

[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-c4063ca68d603a51343b0a6d64494691648ad6d6.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-c4063ca68d603a51343b0a6d64494691648ad6d6.png)

于是添加using指令或程序集引用，右键点击该函数，点击快速操作和重构

[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-eca7b1afb3c99e0afe3d95a9e6eec3efa0f75b2a.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-eca7b1afb3c99e0afe3d95a9e6eec3efa0f75b2a.png)

选择对应的using指令

[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-d9f7fadda447a693587bee64b564d3a779f07dcd.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-d9f7fadda447a693587bee64b564d3a779f07dcd.png)

MemoryStream函数也需要添加using指令

[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-fbfe95d98121e9aea4872d9e0e5deb74cc4eece1.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-fbfe95d98121e9aea4872d9e0e5deb74cc4eece1.png)

在解密按钮功能函数中进行修改，以获取密文和key来传给解密方法

[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-741c89f4f6ac5f7ee61c7f736904658d328c29ec.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-741c89f4f6ac5f7ee61c7f736904658d328c29ec.png)  
解密按钮的代码如下：

```csharp
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace WindowsFormsApp3
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
        }
        public static string Decrypt(string pToDecrypt, string sKey)  //实现解密方法
        {
            DESCryptoServiceProvider dESCryptoServiceProvider = new DESCryptoServiceProvider();
            byte[] array = new byte[pToDecrypt.Length / 2];
            for (int i = 0; i < pToDecrypt.Length / 2; i++)
            {
                int num = Convert.ToInt32(pToDecrypt.Substring(i * 2, 2), 16);
                array[i] = (byte)num;
            }
            dESCryptoServiceProvider.Key = Encoding.ASCII.GetBytes(sKey);
            dESCryptoServiceProvider.IV = Encoding.ASCII.GetBytes(sKey);
            MemoryStream memoryStream = new MemoryStream();
            CryptoStream cryptoStream = new CryptoStream(memoryStream, dESCryptoServiceProvider.CreateDecryptor(), CryptoStreamMode.Write);
            cryptoStream.Write(array, 0, array.Length);
            cryptoStream.FlushFinalBlock();
            new StringBuilder();
            return Encoding.Default.GetString(memoryStream.ToArray());
        }

        private void Form1_Load(o bject sender, EventArgs e)
        {

        }

        private void button1_Click(o bject sender, EventArgs e)
        {
            string passwd = textBox1.Text.Trim();//获取输入的passwd
            string key = textBox2.Text.Trim();//获取输入的key
            textBox3.Text = Decrypt(passwd, key);//调用Decrypt解密方法，并传入passwd、key参数的值
        }
    }
}

```

解密
--

启动并运行  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-a4714bd10e037d1f990bfd8eb885aba42f43ccca.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-a4714bd10e037d1f990bfd8eb885aba42f43ccca.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-1810bacc086500ab77c8984a1e0aaf66f2637feb.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-1810bacc086500ab77c8984a1e0aaf66f2637feb.png)

总结
--

在制作解密工具时一定要分析该解密方法是由什么语言编写的，然后选择特定语言制作解密工具，在解密方法中我们可能不能完全理解它到底是由什么算法编写，因为有可能是多种算法结合在一起，但不要急，发现没有，在这个案例中，我们对解密方法并没有做过多的分析，因为解密方法往往是一个整体，只要我们能够将代码放到指定位置，传入的参数正确，并且准确调用解密方法就可以，解密工具就很容易编写出来。