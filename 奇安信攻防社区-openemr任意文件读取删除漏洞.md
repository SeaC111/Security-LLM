前言
--

OpenEMR 是最受欢迎的开源电子健康记录和医疗实践管理解决方案。

5.0.1版本后台存在任意文件读取和删除漏洞。

审计过程
----

通过全局搜索容易出现问题的函数，发现`readfile()`函数，通过一个一个跟，最终锁定如下文件。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-ca40edcd89f96c98e040af606f0af5859e561d1a.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-ca40edcd89f96c98e040af606f0af5859e561d1a.png)

通过进一步跟踪，寻找参数`$finalZip`来源，发现有两个赋值的地方。通过分析，第一处（48行）赋值限制条件太多，跟进第二处（63行）赋值，要想代码执行63行，就需要43行处为`False`。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-facbcd2379ef11e17998df46592e756a8a950df1.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-facbcd2379ef11e17998df46592e756a8a950df1.png)

所以，只需要变量`$fileName`中不包含`,`即可。进一步跟进，发现变量`$fileName`来自`GET`方法`fileName`参数。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-92bf1809b72a5e52200ed3fdd3a581a9102fad9a.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-92bf1809b72a5e52200ed3fdd3a581a9102fad9a.png)

还有一个变量，`$qrda_file_path`,看一下来源  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-83e05e59af88d8fe92358f060c025b7a09470292.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-83e05e59af88d8fe92358f060c025b7a09470292.png)  
继续跟进变量`$GLOBALS['OE_SITE_DIR']`。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-24a7c5151d50c912dd2f6fa1749333ec127ddad3.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-24a7c5151d50c912dd2f6fa1749333ec127ddad3.png)  
跟进变量`$GLOBALS['OE_SITES_BASE']`。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-a16eb6f2eafdf58d3e263b9ff85ee0d85180c595.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-a16eb6f2eafdf58d3e263b9ff85ee0d85180c595.png)  
那么，现在参数`$finalZip`就很容易构造了。如果要查看根目录任意文件，只需要`../../../../`4层即可

不过需要注意，查看文件后，会删除查看的文件。  
同时，这个页面需要登陆后才能访问。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-cd3ba11fd78de564999f230e2f595e4b49684617.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-cd3ba11fd78de564999f230e2f595e4b49684617.png)  
比如查看根目录的`version.php`文件,构造路径`/custom/ajax_download.php?fileName=../../../../version.php`即可。

复现过程
----

下载地址： [https://www.open-emr.org/wiki/index.php?title=OpenEMR\_Downloads&amp;amp;oldid=27661](https://www.open-emr.org/wiki/index.php?title=OpenEMR_Downloads&amp;oldid=27661)

环境安装好之后，来到登录页面。  
`http://127.0.0.1/interface/login/login.php?site=default`

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-1a16d6b1daf5d5e5a530ce1db7419c7483ebde2d.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-1a16d6b1daf5d5e5a530ce1db7419c7483ebde2d.png)

然后打开Burp代理工具，设置代理。然后在浏览器登陆。

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-5af1882583de78a9a8d1816b86b21837ab7814c0.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-5af1882583de78a9a8d1816b86b21837ab7814c0.png)

选择一个登录后的数据包，发送到burp的重放模块  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-b7533d6f31bedfa5140985c7fc5c7e54c62f9a42.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-b7533d6f31bedfa5140985c7fc5c7e54c62f9a42.png)

修改方法为`GET`，修改路径为`/custom/ajax_download.php?fileName=../../../../version.php`，查看根目录下的version.php文件的源码  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-7c6badfaaa7e8b20cbd63460d7a817e0edbcf4c5.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-7c6badfaaa7e8b20cbd63460d7a817e0edbcf4c5.png)

`version.php`文件内容：  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-80ad2ed4510cea9af8bfec68cdb99ebebda03dfa.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-80ad2ed4510cea9af8bfec68cdb99ebebda03dfa.png)

同时，这个文件也被自动删除了。