0x0前言
=====

朋友遇到一个站点，存在整站源码泄露，但是无法继续深入。再继续尝试突破现有情况中获取到了新的知识以及体验了有趣的过程，于是记录下过程

0x1简记
=====

首先简单看了一下泄露的整站源码，发现是ASP.NET的源码，有ashx,cs,dll等后缀，由于从没接触过，于是查看了些资料学习了下.Net，发现aspx属于是前台文件，aspx.cs是属于后台文件，是C#代码，可以通过C#写很多模块功能并且编译成dll，然后提供给aspx.cs调用

0x2突破
=====

学习完上述简单理论后，简单看了下目录结构，发现是DtCms，并且再App\_Data中找到了数据库文件DtCmsdb.mdb  
通过利用本地Office全家桶中的Microsoft Office Access打开

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-984f911903364b23870f0e44d43bd6a54c43e356.jpg)

发现了后台管理员的账号密码，但是UserPwd的值是加密的，并且不是md5，于是暂且放弃了解密获取明文密码的思路，简单梳理下如何进一步突破

简单梳理：由于泄露获取到了源码，发现是DTCMS，找了下历史漏洞，发现有后台的，但是没有前台的，sql注入的口子也不对，数据库表中的AddTime也是2011年，直接相差了11年，且网页上的建站公司也是个人公司。猜测是根据Dtcms的核心功能源码改的一个站点，还是想从源码代审入手

其实上面的思考还是挺正常的，但是想着想着发现，既然有源码，那我不就可以跟踪登录口获取密码然后加密存入数据库的流程，密码的加密方式肯定在该流程中。找到密码的加密方式就可以写对应的解密脚本

于是在`/Admin/login.aspx.cs`中找到了对于后台登录密码的校验流程

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-d401679f49765c769ae86355aac3ecc1a75a0ab0.jpg)

首先简单判断账号密码是否为空，否则通过获取Session的值判断是否已登录，如果不为空，且未登录，则通过chkAdminLogin函数判断该用户对应的密码是否正确

这里的bll含义是`DtCms.BLL.Administrator bll = new DtCms.BLL.Administrator();`

在bin目录中找到DtCms.BLL.dll，但是看不到源码

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-d18eef1d06db07e62b696d64bb77d574ea987319.jpg)

于是Github搜索是否开源，找到了该Dll的源码 <https://github.com/tengge1/DTcms/tree/master/DTcms.BLL>

但是全局搜索字符串chkAdminLogin，没有任何一处匹配，且在`/DTcms.Web/admin/login.aspx.cs`中的校验密码的方式也不相同，到这里就断了，无法跟到chkAdminLogin函数，可能用的DTcms源码版本都不一样

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-d1e6a2bbef4106ea1f3b632860a0a497a7434695.jpg)

于是再次回到上述源码，尝试直接搜索DESEncrypt关键词来找加密的源码，在`/DTcms.Common/DESEncrypt.cs`中找到DES加密解密的类，尝试在此基础上增加一个Main函数来编译解密该密码，代码如下

```c#
using System;
using System.Security.Cryptography;
using System.Text;

namespace DTcms.Common
{
    /// <summary>
    /// DES加密/解密类。
    /// </summary>
    public class DESEncrypt
    {

        #region ========加密========

        /// <summary>
        /// 加密
        /// </summary>
        /// <param name="Text"></param>
        /// <returns></returns>
        public static string Encrypt(string Text)
        {
            return Encrypt(Text, "DTcms");
        }
        /// <summary> 
        /// 加密数据 
        /// </summary> 
        /// <param name="Text"></param> 
        /// <param name="sKey"></param> 
        /// <returns></returns> 
        public static string Encrypt(string Text, string sKey)
        {
            DESCryptoServiceProvider des = new DESCryptoServiceProvider();
            byte[] inputByteArray;
            inputByteArray = Encoding.Default.GetBytes(Text);
            des.Key = ASCIIEncoding.ASCII.GetBytes(System.Web.Security.FormsAuthentication.HashPasswordForStoringInConfigFile(sKey, "md5").Substring(0, 8));
            des.IV = ASCIIEncoding.ASCII.GetBytes(System.Web.Security.FormsAuthentication.HashPasswordForStoringInConfigFile(sKey, "md5").Substring(0, 8));
            System.IO.MemoryStream ms = new System.IO.MemoryStream();
            CryptoStream cs = new CryptoStream(ms, des.CreateEncryptor(), CryptoStreamMode.Write);
            cs.Write(inputByteArray, 0, inputByteArray.Length);
            cs.FlushFinalBlock();
            StringBuilder ret = new StringBuilder();
            foreach (byte b in ms.ToArray())
            {
                ret.AppendFormat("{0:X2}", b);
            }
            return ret.ToString();
        }

        #endregion

        #region ========解密========

        /// <summary>
        /// 解密
        /// </summary>
        /// <param name="Text"></param>
        /// <returns></returns>
        public static string Decrypt(string Text)
        {
            return Decrypt(Text, "DTcms");
        }
        /// <summary> 
        /// 解密数据 
        /// </summary> 
        /// <param name="Text"></param> 
        /// <param name="sKey"></param> 
        /// <returns></returns> 
        public static string Decrypt(string Text, string sKey)
        {
            DESCryptoServiceProvider des = new DESCryptoServiceProvider();
            int len;
            len = Text.Length / 2;
            byte[] inputByteArray = new byte[len];
            int x, i;
            for (x = 0; x < len; x++)
            {
                i = Convert.ToInt32(Text.Substring(x * 2, 2), 16);
                inputByteArray[x] = (byte)i;
            }
            des.Key = ASCIIEncoding.ASCII.GetBytes(System.Web.Security.FormsAuthentication.HashPasswordForStoringInConfigFile(sKey, "md5").Substring(0, 8));
            des.IV = ASCIIEncoding.ASCII.GetBytes(System.Web.Security.FormsAuthentication.HashPasswordForStoringInConfigFile(sKey, "md5").Substring(0, 8));
            System.IO.MemoryStream ms = new System.IO.MemoryStream();
            CryptoStream cs = new CryptoStream(ms, des.CreateDecryptor(), CryptoStreamMode.Write);
            cs.Write(inputByteArray, 0, inputByteArray.Length);
            cs.FlushFinalBlock();
            return Encoding.Default.GetString(ms.ToArray());
        }
            static void Main(string[] args)
        {
            /* 我的第一个 C# 程序 */
            Console.WriteLine(Decrypt("42xxxxxxx"));
            Console.ReadKey();
        }

        #endregion

    }
}
```

利用自带的C#编译器`C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe`编译即可，然后运行exe

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-2780079888cb2537910e219945a33345f771ac2c.jpg)

发现直接解密失败了，不过转念一想也正常，要么是版本不一样，解密的方式都变了，要么是魔改的Dtcms，核心功能源码也修改了，于是找到了好几个Github的Dtcms源码中的Des解密函数，运行都无法处理该串数据，到这里就很懵了，不知道该怎么办

最后在Google乱七八糟搜索dll的时候发现可以反编译C#封装的dll从而获取到C#源代码，找到的某个开源工具[ILSPY](https://github.com/icsharpcode/ILSpy)

通过该工具直接反编译源代码中的`/bin/DTcms.Common.dll`

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-94cda75d69c6257bf6f5edda6ac5c37d441ad469.jpg)

发现sKey(Salt)是DtCms而不是DTcms，由于.net版本不同，重载的Decrypt函数看上去不同，但是函数基本使用的大同小异，没什么变化，只需要修改上述代码中的DTcms为DtCms即可解密

修改sKey后再次编译运行

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-c9a7d1ac9a505d5b73138db2fc165ecb74206a8c.jpg)

成功解密管理员后台密码，进入后台发现有文件上传类型限制和SQL注入过滤

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-bd50f17824c150978078de87cc0a10b6a28feff3.png)

于是文件上传类型添加aspx，ashx，然后上传相应的冰蝎马，直连即可

此次渗透主要记录从无头苍蝇到崎岖的明文密码解密，过程中也学到了一些.Net，反编译等知识，虽然过程比较简短，但是发现以及突破的流程还是比较有意思的。