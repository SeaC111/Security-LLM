0x00 前景
=======

 由于马上开始护网了,公司想要在护网前对公司员工进行钓鱼意识培训,所以要我搞一下钓鱼,好久没搞了,还是在网上找了下资料,本次使用ewomail和gophish联动,最后总算还是完成了任务,下面我对本次钓鱼实战进行下详细步骤复盘,以后要搞也方便,希望和师傅们多交流交流,有啥更好的方法可以给我留言,当然还是那句话,该篇文章只做学习交流使用,犯罪等一切行为与本文作者无关。

0x01 域名购买
=========

1.本次演练由于是内部演练,未申请国外的域名,使用的是国内腾讯云的域名,注册购买也很简单,购买后进入我的域名进行解析,下一节配置邮箱的时候对着我的配置配就行了。

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-3109dfe49a4890e42179a65fc64abd254224acdd.png)

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-0b36293b0087d14bbe6e1f4d6bfd7d1b10b14420.png)

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-0b2188acdf55f8d100e3923404d00b25ec3ccdb2.png)

0X02 ewomail安装
==============

1.关闭selinux

 vi /etc/sysconfig/selinux

SELINUX\\=enforcing 改为 SELINUX\\=disabled

2.使用git进行安装

这里我们的vps是国外的,所有安装域名后面加空格加en，例如 sh ./start.sh ewomail.cn en,注意ewomail.cn替换为我们注册的邮件域名。

 yum -y install git

cd /root

git clone <https://github.com/gyxuehu/EwoMail.git>

cd /root/EwoMail/install

需要输入一个邮箱域名，不需要前缀，列如下面的ewomail.cn，域名后面要加空格加en

sh ./start.sh ewomail.cn en

3.访问地址

邮箱管理后台,默认口令admin,ewomail123!

 <http://IP:8010>

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-b327b03d293d436bd86394b7bf3dae06d761c2c0.png)

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-2ecfa6bd7bd2c524697f7cc631984545476b647b.png)

web邮件系统

 <http://IP:8000>

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-d795170c8e1167ffb49c49d3256951168a38957a.png)

4.配置邮箱

1.在购买的dns解析处配置,这里用腾讯云的配置,配置dkim值(DKIM是电子邮件验证标准，域名密钥识别邮件标准，主要是用来防止被判定为垃圾邮件)需要到服务器使用命令

 amavisd -c /etc/amavisd/amavisd.conf showkeys

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-360bf199657b05ae85e38b783d1b8bb4156195f5.png)

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-c38727c9f8986018cbb1af56b25a19045c877f39.png)

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-7e0f590ed724d53604d03526f5b015e02a8357ee.png)

2.安装完成后邮箱系统配置如下马赛克的地方为你的域名。

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-c1126537c4e56207304d87a38eda1b02d56263c4.png)

2.修改/etc/hostsname的配置文件,把主机改为mail.xxx,/etc/hosts里配置 127.0.0.1 mail.xxx smtp.xxx imap.xxx 这里的xxx为你的域名,设置完后重启生效。

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-881840c67a6fd2b02d27f117dcccd931fa727c26.png)

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-8073a11e35bcb9bfe3620fcdea208f7676a60662.png)

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-e6521e4adfca25df41d9aaf9c73bfc9eb8e78555.png)

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-5f5dbb11c3c125c4b9756431af1c26d875fe225a.png)

5.添加邮箱用户,添加完毕可以点击右上角的web邮件系统,如果域名配置正确,这里地址应该变为域名:8000。  
![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-7258f79b51c6d46922c2309e23f114164474b414.png)

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-4bba0bb131d715ae5fd2d69fbc5b87772d754398.png)

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-2e084524eb99d78e8c84fcf07a13f99acd1d7882.png)

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-0b73e76dc954585c538695e37d26676bfd808ea2.png)

0x03 gophish配置
==============

1.安装gophish

这里采用docker快捷安装

 docker pull gophish/gophish

docker run -it -d --rm --name gophish -p 3333:3333 -p 8003:80 -p 8004:8080 gophish/gophish

docker logs gophish(查看安装日志中的登录密码)

2.配置gophish

1.访问地址,登录账号admin,密码为日志中的密码gophish

 <https://VPS:3333>

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-12543aeddcd59ecbe7995b7e41df27910c02e828.png)

2.依次配置gophish的各个模块.如下:

1.设置Sending ProfileS,这里是添加发送邮箱服务器的地方,from:填写你刚才ewomail添加的邮箱账号,host:填写你注册域名:25,username:也是填写ewomail添加的邮箱账号,密码;填写添加邮箱账号是设置的密码,保存即可。

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-590c5c4f745df31c0c672377201d5b9c0d72cd3a.png)

2.设置Landing Pages.该页面为用于钓鱼的页面

1.这里系统自带的importsite可以直接输入要copy的网站地址,但是这种方法我尝试了一些网站,有许多网站都不能完美copy,这里我介绍一种方法,使用火狐带的插件,save page可以完美把网页给copy下来,然后把copy下的页面源码贴在HTML的位置就行了,这里我随便找个后台演示下。

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-a88142d54a6e242c2c6a67874df8e3e9c514545f.png)

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-5540b98f1086c833ddcaf18cdf842f735fac249f.png)

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-a9febe30e5ab6709f16ffc3d3e84132147c31910.png)

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-ff7ad3a5d7462940f3761ea4b7fef9bbdfbae634.png)

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-da4fdc08cd40b7011f1724a5b5daf1ec579fecf1.png)

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-9f6446dc18ac1dc032cf149461d4ce97113c03c0.png)

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-dbd2366fec6a86cae82c6a1ef6b8f31da9f9ce71.png)  
3.配置Email Templates

这里使用import Email导入已经写好的.eml后缀的邮件原文,可以先配置好钓鱼邮件内容,然后自己测试发送下,到收件人那里获取邮件原文导入即可。

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-340b5bd56385fe2b7e4bf54f1a593ed26069193e.png)

这里以qq邮箱为例,我们找到一封QQ邮件,在下图所示位置,打开邮件原文,复制里面的内容导入即可。

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-66d9be4fc80d15d3ed0bf40b92289dbd3d18579e.png)

注意勾选Change Links to Point这个选项,后面我们针对邮件模板里的a href="xxxxxx"可以将xxxx替换为{{.URL}},这样邮件里面的钓鱼链接就会被系统自动替代了。

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-1b908dc81d76115fbb48156a1c572244f9a93161.png)

4.配置用户和组

这里主要是配置要发送的人,可以使用csv导入,如果是xlxs文件是不行的需要进行转换,只有要使用excel自带的另存为csv带逗号格式的就行了。

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-280cd2dd022b8d032643148bb6ad88dd733e539f.png)

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-f699f830b6c291c85899f2e8da71329d7b2da76d.png)

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-0e3d3d294746d5c7286777a70bb77f4e61f417ed.png)

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-44e76a8197bd74ac0bfe60f25af775b8d662c0e8.png)

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-2a88c4f213cf529d9635457e9906b19d4ed946c8.png)

5.这里配置Campains,这个模块主要就是拿来钓鱼了,依次勾选上诉这里我们配置好的选项就好了,ULR要设置为hppt://(这里可以为域名或者vps的Ip,具体看需求):8003,配置好就可以愉快钓鱼了。

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-48a83981acd08ab789f9b559276e3da3c7fb33c6.png)

0x04 钓鱼结果展示
===========

1.这里点击图中所示可以看到钓鱼详情,值得一提的是我是前一天发的,第二天发现只有9个人点击,但是其中5个人都上当提交了数据,虽然可以交差,但是总感觉哪里不对,为啥点击的这么少,最后才发现我那邮箱服务器一个时间内发送邮件数量太多会导致很多邮件被退回。。。,所以如果要发送大量邮件,服务器配置不行话,建议定个时间分组发送了。

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-6e3db44d62b53b7e5cdf6f68e903a2d3574a6423.png)

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-9a90cff7ef764b4379d60147b5d1fc685ab7dcc2.png)

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-a0c2a262c7b4813c9a8f823efe7924535aa22986.png)

设置下分组再发有调了几个,哈哈,等今晚在看估计更多了,交差溜了。

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-145eba101f7a9a90429e3c6bb7e80bfcdd168447.png)