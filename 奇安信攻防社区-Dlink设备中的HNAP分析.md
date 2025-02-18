最近在学习设备中的认证绕过漏洞，发现HNAP这个协议，思科太难搞了，刚好Dlink设备存在几个相关的漏洞，顺便就学习了。

> D-Link DIR-882、DIR-878 和 DIR-867路由器

固件下载地址：<https://tsd.dlink.com.tw>  
下载了DIR-878 v1.10设备的固件，这里有些版本的DLink固件要加密，但是我下载的时候并没有说这个是加密的，所以就不演示固件界面了，实际上，DIR设备的解密也非常简单，可看以下连接。  
<https://yjy123123.github.io/2021/05/28/D-Link-%E8%B7%AF%E7%94%B1%E5%99%A8%E5%9B%BA%E4%BB%B6%E8%A7%A3%E5%AF%86/>  
思路就是利用有解密模块的未加密固件进行解密。

0x01 CVE-2020-8864漏洞分析
======================

系统在处理HNAP登录请求时，处理password存在固定缺席导致的未授权登录，攻击者可以利用此漏洞进行RCE。

1.1 HNAP协议
----------

该协议过时，不用过多的理解，稍微了解就行了。  
[HNAP相关漏洞和基本资料](https://research.qianxin.com/archives/599)  
[请求详情](https://github.com/bikerp/dsp-w215-hnap/wiki/Authentication-process)

第一步：发送登录请求，然后等回显。  
请求的数据包格式如下：

```c
Headers:
"Content-Type": "text/xml; charset=utf-8"
"SOAPAction": "http://purenetworks.com/HNAP1/Login"

<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <Login xmlns="http://purenetworks.com/HNAP1/">
      <Action>request</Action>
      <Username>admin</Username>
      <LoginPassword/>
      <Captcha/>
    </Login>
  </soap:Body>
</soap:Envelope>
```

有SOAPAction头部，xml中有username。  
响应数据

```c
<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <LoginResponse xmlns="http://purenetworks.com/HNAP1/">
      <LoginResult>OK</LoginResult>
      <Challenge>........</Challenge>
      <Cookie>........</Cookie>
      <PublicKey>........</PublicKey>
    </LoginResponse>
  </soap:Body>
</soap:Envelope>
```

返回challenge，cookie和public。其中cookie被用来作为http请求的cookie头，其他两个被用来加密password，作为http头中的HNAP\_AUTH认证。

```xml
Headers:
"Content-Type": "text/xml; charset=utf-8"
"SOAPAction": "http://purenetworks.com/HNAP1/Login"
"HNAP_AUTH": "........"
"Cookie": "uid=........"

<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <Login xmlns="http://purenetworks.com/HNAP1/">
      <Action>login</Action>
      <Username>admin</Username>
      <LoginPassword>........</LoginPassword>
      <Captcha/>
    </Login>
  </soap:Body>
</soap:Envelope>
```

```xml
<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <LoginResponse xmlns="http://purenetworks.com/HNAP1/">
      <LoginResult>success</LoginResult>
    </LoginResponse>
  </soap:Body>
</soap:Envelope>
```

1.2 漏洞分析
--------

可以通过grep定位关键字符串，找到漏洞程序为/bin/prog.cgi，在其中的sub\_42141C，为关键的登录逻辑判断。

从未知的角度来看，我需要分析HNAP处理流程，自然还是从字符串下手，可以搜索`LoginPassword`之类的字符串。注意**搜索的一定是response包里面的内容**。  
也可以搜到 bin/prog.cgi 和 bin/prog-cgi，逆向程序的时候，交叉应用，也很方便的找到了处理函数。  
sub\_424090函数中，明显是response包生成的过程

![Pasted image 20220810162902.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-cd521b42bfb5daa15e0b62b7b0d660b2dc5f882d.png)

返回上一级函数可能就是处理的流程。最终找到websSecurityHandler函数，该函数是整个HNAP认证的开始，其调用的sub\_423DF4函数是主要的认证函数。

![Pasted image 20220810164723.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-36286c702aa1089ec31e2110e8d8ab06a4fc9b3d.png)  
sub\_42141C函数中是漏洞出现的位置，进入login的逻辑之后，在其中发现一处关键比较点，如下：

![Pasted image 20220811080830.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-c1234ab717b4f6d849d632151eefebca86896889.png)

使用nvram获取了登录状态，使用strncmp比较了密码，这里有个重要的漏洞pattern，  
`strncmp(x, y, strlen(y))`，strlen遇到00截断，而其中的y代表输入的passwd，如果输入的是\\x00，那么比较的就是前0位，即一位也不比较，这将strncmp返回0，所以这里就存在了非预期的登录成功。

> CGI调试的时候，可以使用sh脚本，首先设置好环境变量，然后再去qemu开启调试比较合适。

0x02 CVE-2020-8863 漏洞分析
=======================

和8864是同样的设备，发生在request中，

![Pasted image 20220811082746.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-0f9d264d28dc8dc84624405e57c4e317c2179e49.png)

进入之后，逻辑比较清晰，和上面那个漏洞一样。  
![Pasted image 20220811102251.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-dd01a5eaa7e73b6030258833f0024e3d45ac86b2.png)  
一个关键的比较是，privatelogin这个节点里面，前八个字节如果是Username，那么就把传入的username当作是passwd，而else分支中，则是nvram函数从http\_passwd中取出passwd。  
继续看，似乎passwd被用来加密，最终结果传递到了a4。

![Pasted image 20220811103141.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-0137b80bd43f0279939dfb4c223b7ac69b2d0b30.png)

继续跟踪这个变量。

![Pasted image 20220811104934.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-a2dead69987f7ec908012bec301ad87549ddff14.png)

在pub\_key未初始化的时候，初始化v24，然后传给pub\_key，且**预言家说，要看一下a4这个参数，函数的第四个参数** 第四个参数最终传入sub\_41EA9C(a1, (int)v23);函数，函数中，把这个参数也就是v23，指针赋给了a1+212。最后在`sub_424090(a1, 0);`函数中，注意到生成的challenge之类的。

![Pasted image 20220811104202.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-f29dd482a5351979592b63c4f3919c4bcfc75b8f.png)  
来自于上面几个变量，进去看，发现大都一致。

![Pasted image 20220811104248.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-04ae25c0186d4661fee8773e587824e8ab1a847b.png)  
只是strcmp比较不同，这里专门看了public\_key的，如果i\[8\]一样，那么返回i\[9\]。  
综上，总结出，最后的challenge，cookie，public\_key分别是 `sub_41F430`函数的第345个参数。

所以说，正常来看，public\_key由http\_psswd生成，但是控制这个private\_login则可以自己生成，那么用户完全可以自己构造响应数据包，响应认证，即可完成登录。

感觉这个漏洞像个预留的后门，不像是代码上的失误。以上几个漏洞呢，也是了解到了strncmp函数存在的某些bug，测试了strcmp，不可以输入\\x00字符，所以应该是不存在类似bug的。  
疑惑的还是第二个漏洞，private-login明显是添加上去的，普遍性不高吧，（还是感觉这样的洞有点离谱。

此外该设备还存在许多命令注入的漏洞，但不是学习的重点，稍微了解了一下就没有继续分析了。