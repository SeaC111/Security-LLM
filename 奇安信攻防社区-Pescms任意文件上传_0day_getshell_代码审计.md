Pescms任意文件上传代码审计  
工具  
Seay源代码审计系统  
pescmsteam-v2.3.3  
phpstudy

漏洞挖掘及审计  
使用phpstudy搭建好系统后发现可以修改上传的图片及文件后缀，添加php后缀进行上传  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-54a7c5dfeda95b7ce2566723471735e74bb8d990.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-54a7c5dfeda95b7ce2566723471735e74bb8d990.png)  
查看修改后的后缀如何保存。可以看到将输入的数据并未作过滤操作就写入数据库。造成后缀名的绕过。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-adcd3026fc0f55b465cb022e6fb56aa3cb78cc7c.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-adcd3026fc0f55b465cb022e6fb56aa3cb78cc7c.png)  
此时寻找到文件上传的方法，此时upload类继承了controller类，跟踪到该类。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-835b81760a7046a1ed2a2ff4cc4160be56fca31d.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-835b81760a7046a1ed2a2ff4cc4160be56fca31d.png)  
查看该类的函数可以得到一个数组config，该数组存储了数据库中获取的可上传的文件的后缀名等信息。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-cf22ad5ec24d9ee2ef2da3b6ebf74eeb0a8d8afd.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-cf22ad5ec24d9ee2ef2da3b6ebf74eeb0a8d8afd.png)  
继续向上寻找具体的处理方法。可以看到在这里首先包含了Uploader.php文件。查看上传配置中的config数组中的允许上传字段即是从数据库中读取的自己写入的字段。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-ba3e29d124fe4d49ef20612a85a0a141dca5198f.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-ba3e29d124fe4d49ef20612a85a0a141dca5198f.png)  
打开上一步包含的文件uploader.php，查看具体的文件上传方法  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-083c23894bad76a7559757abdbac72b7d7126eeb.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-083c23894bad76a7559757abdbac72b7d7126eeb.png)  
检查文件名后缀是否满足要求，  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-5e1b22c582f4867e5d19ab2ead933c6398c72c8e.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-5e1b22c582f4867e5d19ab2ead933c6398c72c8e.png)  
当后缀满足要求时继续执行，这里的config\[“allowFiles”\]为我们第一步写入的后缀名。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-72589634571e7433405a508db8ef909603ca9f4f.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-72589634571e7433405a508db8ef909603ca9f4f.png)  
继续执行该上传方法，当上传的文件为图片时使用gd库过滤掉图片马，否则直接上传。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-305651040288f426f3893342dada239cb85a3eb8.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-305651040288f426f3893342dada239cb85a3eb8.png)

实际操作getshell  
在编辑时选择附件上传，如下为上传数据包，成功上传并返回shell的路径。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-e548785a15f94ecf7f4f6330097a920dfd5c019c.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-e548785a15f94ecf7f4f6330097a920dfd5c019c.png)  
使用工具进行连接，成功getshell  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-b0710bf12e96f09ff6ee39bd27f5893e717c4ae3.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-b0710bf12e96f09ff6ee39bd27f5893e717c4ae3.png)

操作过程中的坑点  
在修改后缀处能够修改图片的上传后缀以及文件的的上传后缀，但是上传图片shell并不能成功getshell

在上传图片时成功修改图片的后缀为php，也能成功返回路径，但是在连接时总是无法连接成功，通过代码审计的过程发现主要是在针对图片上传时使用了GD库进行了过滤  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-a6037c54130fb50e03e3a31e8ab3c88f4f28415d.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-a6037c54130fb50e03e3a31e8ab3c88f4f28415d.png)