### 一、前言

 随着移动端使用的越来越广泛，针对安全测试的工作也是由之前的以web为主到目前大量的移动端的安全测试工作。那么针对Android端的安全测试一些测试人员都是有自己的一些思路和规范流程，这里也是结合平时工作将自己在做Android端的一些测试思路以及工具环境进行了梳理。  
 针对Android端的安全测试个人一般从两大方面进行，第一就是自动化检测，会使用到一些框架及平台，包括drozer、Mobsf等平台，对apk的一些信息和风险问题进行自动识别发现，针对发现的问题进行验证和测试。第二就是手动测试，包括本地敏感数据的检测、apk的反编译以及重编译、frida hook以及抓包改包等操作进行测试。当然这一块测试还需要我们对反编译后的一些代码进行分析，以及动态调试过程中对一些arm汇编代码熟练掌握。  
 本次主要介绍一下Android测试过程中的本地敏感数据检测、apk反编译和重编译、Drozer、Mobsf、frida hook以及Fiddler抓包工具等一系列环境的安装和对应的一些测试思路。

### 二、测试思路及环境搭建

#### 1、本地敏感数据检测

 Android APP本地存储方式四种，分别为：文件存储数据、SQLite数据库存储数据、使用ContentProvider存储数据、使用SharedPreferences存储数据。App会将一些私有的数据存储再本地，私有目录通常位于“／data／data／应用名称／”。从安全的角度出发，对本地信息存储进行安全测试需要安装对应的环境和工具。  
Android SDK 指的是Android专属的软件开发工具包，其中包括adb以及ddms等一些列调试工具，可以用于安全测试过程中针对app的调试检测。官网：[https://www.androiddevtools.cn/，下载SDK](https://www.androiddevtools.cn/%EF%BC%8C%E4%B8%8B%E8%BD%BDSDK) Tools，并下载platform-tools和tools的文件复制到sdk目录下，并配置全局环境变量。  
![![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-47eacb5a1ef64d11d3d5615e08e7b6397caa6522.png)](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-0b0acb7ff4da1a34ccde640bb9b3b5c041646ffc.png)  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-bd5e050ca22d43e86f176fa1308c34c4add97931.png)  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-aa58b495652d876a101f54d211fc7e5ce37a79b7.png)  
执行adb和ddms能够打开环境则安装完成。  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-1345147be15005f384fa3c3f8fce3fe8ea6c0e85.png)  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-1bf461b84b02c05ed5aeb46f9531493ea7243242.png)  
至此，对应sdk的环境安装和配置完成。

##### 1）Xml等文件敏感信息查看

 打开ddms，同时打开运行app的安卓模拟器或者真机，选择Device下的File Explore，  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-85fb2a00948e103668f17a9b6e16ab7dad13637b.png)  
选择data/data/app包名目录下  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-635a7ecea8b760c044069e50d62281aa7ce36a64.png)  
选择需要查看的配置文件进行导出查看  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-2025b1ab52e606771930d9410f3ec63bbf4147a9.png)  
导出后可以利用sublime等应用程序进行查看是否存在敏感信息的存放。  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-d7cfe94b7d56bbbd7037e6f2979c548f821985b2.png)

##### 2）SQLite数据库存储敏感数据查看

 在该app包目录下找到database目录，找到程序运行生成的\*.db文件进行导出。  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-56e3c83981ca9f6118e9ccbf9e9c34e29dbb4c1a.png)  
将导出的db文件利用Sqlite进行数据查看  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-916491cd46822b990181ca80ca55197722755a75.png)

##### 3）SharedPreferences存储敏感数据查看

 SharedPreferences通常用来存储应用的配置信息，保存方式基于XML文件存储的key-value键值对数据，一般作为数据存储的一种补充。存储路径为：/data/data/&lt;package name&gt;/shared\_prefs目录下。  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-8c21bb45b251c75cc495e65df528830f6f4e5113.png)  
利用sublime打开查看  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-33888d2aa2fb4f877af86bfcfabd6da892508321.png)  
以上便是文件存储数据、SQLite数据库存储数据、使用SharedPreferences存储数据三种本地存储数据的查看测试方法，至于使用ContentProvider存储数据将在后边利用drozer工具进行测试。

##### 4）数字签名检测

 数字签名用来防止要保护的内容被篡改，用的是非对称加密算法，通过签名信息可以确定APP和其开发者的关系，检测签名的字段是否正确标示客户端程序的来源和发布者身份。所用到的工具是jarsigner.jar，jdk的安装目录下的bin目录中便有。  
进入jdk目录，打开cmd窗体：  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-2a4b0c1bfa1f287d46ab88ec2acf4ce8e8ca3704.png)  
执行一下检测命令进行检测  
jarsigner.exe -verify -verbose –certs apk路径  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-3a832ad3bdf9a481200dcf7a4022f64a50ac0461.png)  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-542ad9330b011a14a7e5b2f6f9dd24a8ae6ec33c.png)

#### 2、APK反编译和重编译检测

 Apk安装包在反编译之后可以进行一些资源以及代码的查看分析和修改，修改完成重编译签名之后可以安装使用修改后的app程序。APK的反编译分别有apktool、dex2jar以及jd-gui等工具。

##### 1）apktool进行反编译和重编译

 Apktool可以对app资源文件获取，提取出图片文件和布局文件进行使用查看。下载地址：<https://bitbucket.org/iBotPeaches/apktool/downloads/>  
反编译：  
java -jar apktool\_2.5.0.jar d -f apk apk名称 -o 反编译后的文件名  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-aa8a55ba0b54e4c82ebe51d6096b418f29c55a65.png)  
重编译  
java -jar apktool.jar b -f 需重编译的文件夹名称 -o apk名称  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-e5518983d81405a8aa58cb821b9aa567f9535c0d.png)  
Apk反编译过程中如果有资源文件提示错误找不到等信息，或者混淆问题，在反编译时可以尝试使用–only-main-classes和-r参数。  
Apk重编译完成想要正常使用或者安装运行，则必须对该apk进行签名。可以使用SignApk，工具下载地址：[https://github.com/techexpertize/SignApk，并使用以下命令进行签名](https://github.com/techexpertize/SignApk%EF%BC%8C%E5%B9%B6%E4%BD%BF%E7%94%A8%E4%BB%A5%E4%B8%8B%E5%91%BD%E4%BB%A4%E8%BF%9B%E8%A1%8C%E7%AD%BE%E5%90%8D)  
java -jar signapk.jar certificate.pem key.pk8 待签名apk 签名后输出apk  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-9f81129ed7ea5b35a78825f77a98b3db95e6d5ce.png)  
当然如果想利用工具直接进行反编译和重编译，可以使用AndroidKiller，工具可以配置不同版本的apktool以及签名文件供安全人员进行自动化编译。  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-c965727929a27818d176f725d5e1d1f54e43d7a9.png)

##### 2）dex反编译

 d2j-dex2jar将APK反编译成Java源码（classes.dex转化成jar文件）工具下载地址：<https://sourceforge.net/p/dex2jar>  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-1acbdd5061c960c6e840965cd373c060ac76632c.png)  
将apk文件后缀修改为.zip，并进行解压  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-566ddd6ed5b448b01954a06c000d60b033220b12.png)  
进入文件夹可以看到classes.dex  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-1afd799e6bfef6ba0a12d647d13cddd7b04a4396.png)  
利用反编译命令如下：  
d2j-dex2jar.bat classes.dex  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-ab9e993e0532eade8f61d2f7c41c3ec7311efd78.png)  
可以看到成功反编译成.jar后缀文件  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-c88d2339d68368f83ff3a613c909d02ef475c483.png)  
如果是多个dex文件时则需要使用dex2.1 ，命令如下：  
d2j-dex2jar.bat apk文件  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-8a2ece05076828a9b4827a8e260233fb4220a752.png)  
成功反编译成.jar后缀文件。  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-3bce709f024d8e4e8a82667a06e0f6978af23839.png)

##### 3）jd\_gui查看.jar文件

 将.jar文件拖入jd\_gui中便可以查看java代码，进行逻辑关系的分析。  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-db42d43cbf7afbea90e8cd82acfe290be9a467c8.png)  
当然，利用androidKiller反编译后可以直接查看java代码  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-f4b44add1d9010d9e4b3a9acb2527e44928efcf4.png)  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-bfd1e4a5aaf3b3e0b6ce3ef1eb908e24e0b026ef.png)  
同时，在反编译完成后也可以进行一些敏感关键词的搜索，包括一些手机号、pass、user等需要的字段。  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-52fb48f5144dbe1b66f1ccb328d142da5cabc21c.png)

#### 3、Drozer安全测试框架

 Drozer是MWR Labs开发的一款Android安全测试框架。利用该测试框架可以测试app四大组件安全。下载地址：<https://github.com/FSecureLABS/drozer/releases>  
运行Drozer需要java环境、python27环境，因此需要提前安装需要的环境。本地PC端安装完成后需要下载apk文件在android端也进行安装。  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-0282243894fbda64e953946dd618510fbc9c1a7e.png)  
完成安装后利用adb命令查看连接的andorid终端  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-eab8e9c93e03aedbfa71f021ce2ab3e3abe2ea50.png)  
利用命令进行端口转发：adb forward tcp:31415 tcp:31415，同时利用命令启动drozer：drozer console connect  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-eed169c12eff5419861df4d721ee762feb7cd69a.png)  
在android端启动drozer终端  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-f586f347015e2300ca41a9272f9fcf3ca0a1921a.png)  
都启动之后运行以下命令可以查看android终端上所有的app包  
run app.package.list  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-d3d0bd1276193e53d3d0c1e20a7009cd48eb06ee.png)  
利用以下命令可以查看需要测试app的包名  
run app.package.list -f app名称  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-a1dd13bc09adf5a74202eee9fb3b6ca03e23ecaf.png)  
也可以在androidkiller中直接查看app包名  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-2a01504712916449d33ed495d502af92c26a8ae8.png)  
利用以下查看可导出的组件  
run app.package.attacksurface app包名  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-66b81fe0c0e6051447f3fdfdcf32202f0e2f69a5.png)

##### 1）Activity组件安全检测

 利用以下命令查看activity组件  
run app.activity.info -a app包名  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-4306b92ddbc0654812341ef7a249c1016bee7aa1.png)  
如果是一些第三方的或者其他组件可以使用drozer中的activity调用模块尝试启动查看是否可以获取一些敏感数据等，这边以MainActivity进行演示，命令如下  
run app.activity.start --component app包名 调用的activity  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-442357d860344532812162b9c4a4ba22477780ba.png)  
成功启动该activity  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-f9fd9c9b29c49278f8d5809f1b6437b8c9d993c8.png)

##### 2）Broadcast Receiver组件安全

 利用以下命令进行查看，存在可导出的Receiver组件，可以导致Receiver被劫持、绕过、本地认证，造成拒绝服务，导致程序崩溃等。  
run app.broadcast.info -a app包名  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-fe40b548cdc5a272dd3b56448baa5d2fbabdf636.png)

##### 3）ContentProvider组件安全检测

 在前面的本地存储数据中介绍ContentProvider存储数据便是其中的一种方法，因此需要针对性的检测，利用以下命令进行检测。  
run scanner.provider.finduris -a app包名  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-79e828e739d9b89d5b18da960328d45f80c5310c.png)  
如果存在可访问的content,可能导致应用数据的泄露。利用以下命令可以检测是否存在sql注入：  
run scanner.provider.injection -a \[包名\]  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-43aecb8503e81ede259c5830dae8c6d6d4d36727.png)  
利用以下命令可以检测是否存在遍历文件的漏洞  
run scanner.provider.traversal -a \[包名\]  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-79f122f25c0ce6022c47be15143da8b580d67729.png)

##### 4）Service组件安全检测

 利用以下命令进行检测：  
run app.service.info -a app包名  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-c9108ebfd18db0d8d47e884687075c37720cc31f.png)  
如果存在可以导出的service。可能被恶意应用提供获取重要信息。

#### 4、Mobsf

 MobSF(Mobile-Security-Framework)是一种开源自动化的移动应用程序（Android / iOS / Windows）安全测试框架，能够执行静态，动态和恶意软件分析。它可用于Android/iOS和Windows移动应用程序的有效和快速安全分析，并支持二进制文件分析。辅助安全人员进行安全测试以及分析。针对MobSF在kali linux的安装进行介绍  
系统更新  
apt-get update  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-cd99c5887bc869b1349b7e920008c4ce4f86fdb4.png)  
安装https协议、CA证书  
apt-get install -y apt-transport-https ca-certificates  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-0c87f70210c1a78f9a5f7a0213b23485a3c47bee.png)  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-c545dbfc295ddf3b01d03c9e6fdf50f549735229.png)  
安装dirmngr  
apt-get install dirmngr  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-8cef2703e613791b250027f2f923bbb56928e8de.png)  
添加GPG密钥并添加更新源  
curl -fsSL <https://mirrors.tuna.tsinghua.edu.cn/docker-ce/linux/debian/gpg> | sudo apt-key add -  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-1f812681dc1366c99b914d90c1d52842c71d05f1.png)  
echo 'deb <https://mirrors.tuna.tsinghua.edu.cn/docker-ce/linux/debian/> buster stable' | sudo tee /etc/apt/sources.list.d/docker.list  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-21b23a10e19dcc30affdc76cb661acb0612b504e.png)  
系统更新  
apt-get update  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-5142658912a9e3295c51d10f6a0dcf0026e90d47.png)  
安装docker  
apt install docker-ce  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-f6f545568ffad5b08d28b8fc90869e8a440cd9ea.png)  
启动docker服务器  
service docker start  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-e7d9f07f56317cd251661223876c0525dc060fc5.png)  
安装compose  
apt install docker-compose  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-8410d5d6b465bfbf0a4fbd69bd845ec00e3e102a.png)  
docker快速进行安装  
docker pull opensecurity/mobile-security-framework-mobsf  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-027612ec484a454ac12e822aeb577ba183d89021.png)  
执行启动命令  
docker run -it -p 8008:8000 opensecurity/mobile-security-framework-mobsf:latest  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-d0afbafc3cea2c4149d721a6c3c19fc65e7a1bfd.png)  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-57955859dac9b8243e703ab5d3f799507112036c.png)  
本地浏览器访问8008端口，  
<http://localhost:8008/>  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-90728cfdc04b0401e76e748c0f3bd8733e960cfc.png)  
可以上传apk文件进行检测，检测完成后便可以查看结果。  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-3761dee45b6ccb6a4c4780ed2a00525c4903b5ef.png)  
 MobSF不仅支持静态分析，还支持Android应用动态分析，可以动态调试正在运行的应用。如果需要动态分析，请不要在Docker或虚拟机中部署MobSF，另外需要下载安装Genymotion模拟器。

#### 5、Frida Hook

 frida是一款基于python + javascript 的hook框架，可运行android、ios、linux、windows等各平台，主要使用动态二进制插桩技术。本次主要介绍在kali linux进行安装。  
在针对android app的测试过程中，需要对一些输出的数据进行加密方式的分析或者修改邓操作，如果通过动态调试可能需要绕过反调试检测等一系列操作，是比较麻烦的，因此通过hook进行查看和修改相对就比较简单方便。  
pip命令安装frida  
pip install frida  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-374a3b283535173fb1ec86def9f6869d32d81a80.png)  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-65d6d5998a2b1d457c276f26ac4e2c7a8c454c1c.png)  
查看frida版本  
frida --version  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-e356aa60547a8b54b9d11862a69211d9e7928f32.png)  
访问github下载对应版本的server文件，选择android环境下的进行下载。  
<https://github.com/frida/frida/releases>  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-c62314af19a9137b29caf1392d64652e594748b0.png)  
利用adb命令将对应版本的frida文件push到android中的/data/local/tmp/目录下  
adb push /root/Desktop/frida-server-15.1.14-android-arm /data/local/tmp/frida-server  
利用adb命令进入android命令行切换为root账号  
adb shell  
su root  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-d9b3ac8b48749a5825e1c5aef7f6b74c45c55b22.png)  
进入/data/local/tmp/目录  
cd /data/local/tmp  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-0ff445adeb30b0b8e7a4d7886e8d38c2ebb138b7.png)  
修改权限为777  
chmod 777 frida-server  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-9f8685fcb68f6241bca30a8e49891bfbc6e5b26e.png)  
转发android TCP端口到本地：  
adb forward tcp:27042 tcp:27042  
adb forward tcp:27043 tcp:27043  
运行push商量的frida文件  
./frida-server  
在kali linux下运行该命令进行查看，出现android手机的进程列表说明搭建成功。接下来就可以分析app代码并编写hook脚本进行测试了。  
frida-ps -U  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-2c2feca14762cff2a647eb987d0fa5d3eb2b6199.png)

#### 6、Fiddler

 Fiddler是位于客户端和服务器端之间的代理。它能够记录客户端和服务器之间的所有 请求，可以针对特定的请求，分析请求数据、设置断点、调试web应用、修改请求的数据，甚至可以修改服务器返回的数据，功能非常强大。工具下载地址：<https://www.telerik.com/download/fiddler>。  
下载安装完成后点击Tools菜单下的Options菜单，进入弹出的配置界面，选择HTTPS下的Actions进行证书的导出。  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-3d981aa7191f77f5a021f01f6e8576fb9580b57a.png)  
导出之后上传到android终端，通过设置-安全-从SD卡安装证书进行证书的安装，可以分别选择VPN和应用以及WLAN都安装  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-03b6b17b65b37b231389c449db6c26113d6a539f.png)  
安装完成之后可以查看监听端口，并在android中设置代理进行抓包。  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-b02228e2f35a34bc821edd078ed4a371cb77a45e.png)  
当然也可以为他设置代理和burpsuite进行联动。  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-83df52712ea0f813c2f87aa064fe0dfa4898958d.png)  
 剩下的就是一些功能和api的测试了，当然大家也可以直接使用burpsuite进行抓包测试。

### 三、总结

 以上就是本次针对Android安全测试过程中需要到的一些工具环境的安装和测试思路，当然Android安全测试过程中还涉及很多的知识点和内容，每一块都需要不断的练习和实操，如果对Android攻防感兴趣的可以深入研究。