0x01 固件模拟
=========

下载wayos相关固件：<http://www.wayos.com/products/WAM9900siWANquanqianzhaodedaiw.html>

尝试使用FirmAE进行固件模拟;

![image-20221013214834502.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-826058f690d14fdc38c968287d1af6a7bd39f3ab.png)  
访问192.168.1.1，80端口，可以进入到wayos路由器的用户登录界面。

![image-20221013215112590.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-ee5a2ed81d07a1a065f774ae41b99efb86d4dce9.png)

以默认账户口令root admin可以登录到用户管理界面;

![image-20221013215435537.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-47856b2051aa8fd950bba9187c87b9f89af76b06.png)

0x02 固件解包获取文件系统
===============

`binwalk -Me WAN\_9900-21.10.09V.trx`

![image-20221103101948455.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-14979b15a6b0824fe75a487acc3b69e398e91267.png)

0x03 mqtt协议telnet账户泄露漏洞
=======================

rcS是linux启动配置脚本文件，在会linux启动后执行。查看他的rcS文件发现会自启动telnet，固件模拟之后对端口进行扫描发现确实开启了telnet服务。

![image-20221103103222727.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-119de7cf6876271244536207666c54cae9a043ff.png)

![image-20221103103650911.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-fbdd63eed29ba34a2956dc98833ead90cd3d0d4a.png)

利用grep命令搜索字符串:WayOS和login，然后取并集，发现这两个词同时出现在mqtt\_ai这个文件中，然后对这个文件进行逆向分析。

![image-20221103105718126.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-29cf082a3fc63f1681968481b8a726069dd65f14.png)  
采用string字符串定位login，然后交叉引用跳转到相关的函数进行分析。

![image-20221103110522626.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-e0c18b2b126eb3ab92d6b6fad5a3c873847d5806.png)

这里是MIPS架构的文件，我的IDA逆向F5反编译的时候发生问题，这里尝试使用Ghidra进行反编译，找到上述定位到的函数mqtt\_ai\_sw\_telnet\_login。

```js

undefined4 mqtt\_ai\_sw\_telnet\_login(int param\_1,int param\_2)  
{  
  ssize\_t sVar2;  
  int iVar3;  
  size\_t sVar4;  
  uint uVar5;  
  int iVar6;  
  char \*pcVar7;  
  char local\_2028 \[4096\];  
  char acStack4136 \[4096\];  
  char cVar1;  
​  
  memset(acStack4136,0,0x1000);  
  iVar6 = 0;  
  memset(local\_2028,0,0x1000);  
  do {  
    while( true ) {       #双层循环，外层循环为死循环  
      memset(local\_2028,0,0x1000);  
      sVar2 = recv(param\_1,local\_2028,0x1000,0);    
      if (sVar2 < 1) {        #recv失败检查，local\_2028为缓冲区  
        return 0xffffffff;  
      }  
      for (pcVar7 = local\_2028;   #字符处理  
          ((cVar1 = \*pcVar7, cVar1 == '\\r' || (cVar1 == '\\n')) || (cVar1 == ' '));  
          pcVar7 = pcVar7 + 1) {  
      }  
      iVar3 = strncmp(pcVar7,"User Name:",10);  
      if (iVar3 != 0) break;    #检查是否为User Name，如果是推出内部循环  
      if (3 < iVar6) {      #iVar为尝试次数，3次失败后return 0xfffffff  
        puts("login failed");  
        return 0xffffffff;  
      }  
      sVar4 = snprintf(acStack4136,0x1000,"root\\n");  将acStack4136赋值为root  
      if (0xfff < sVar4) {  
        sVar4 = 0xfff;      
      }  
      send(param\_1,acStack4136,sVar4,0); #send发送root  
      sVar4 = snprintf(acStack4136,0x1000,"admin\\n");  将acStack4136赋值为admin  
      if (0xfff < sVar4) {  
        sVar4 = 0xfff;  
      }  
      send(param\_1,acStack4136,sVar4,0);           #send发送admin  
      sVar4 = snprintf(acStack4136,0x1000,"enable\\n");  
      if (0xfff < sVar4) {  
        sVar4 = 0xfff;  
      }     
      send(param\_1,acStack4136,sVar4,0);    #send发送enable  
      pcVar7 = "configure\\n";  
LAB\_0044c564:  
      iVar6 = iVar6 + 1;     #验证次数加一  
      uVar5 = snprintf(acStack4136,0x1000,pcVar7);  
      sVar4 = 0xfff;  
      if (uVar5 < 0x1000) {  
        sVar4 = uVar5;  
      }  
      send(param\_1,acStack4136,sVar4,0);      #send发送configure，而且这一步pcVar7改变，就不会再被进入其他strcmp验证  
    }  #内层循环结束  
    iVar3 = strncmp(pcVar7,"Login:",6);  #匹配关键指纹login：，进入login的验证模式  
    if (iVar3 == 0) {  
      if (3 < iVar6) goto LAB\_0044c7bc;    
      sVar4 = snprintf(acStack4136,0x1000,"root\\n");  
      if (0xfff < sVar4) {  
        sVar4 = 0xfff;           
      }  
      send(param\_1,acStack4136,sVar4,0);   #send发送root  
      pcVar7 = "admin\\n";  
      goto LAB\_0044c564;        #send发送admin,尝试次数加一,再去发送configure  
    }  
    iVar3 = strncmp(pcVar7,"Username:",9);    #再次匹配Username:  
    if (iVar3 == 0) {  
      if (3 < iVar6) {  
LAB\_0044c7bc:  
        puts("login failed");  
        return 0xffffffff;  
      }  
      sVar4 = snprintf(acStack4136,0x1000,"admin\\n");  
      if (0xfff < sVar4) {  
        sVar4 = 0xfff;  
      }  
      send(param\_1,acStack4136,sVar4,0);  
      iVar6 = iVar6 + 1;  
      uVar5 = snprintf(acStack4136,0x1000,"admin\\n");  
      sVar4 = 0xfff;  
      if (uVar5 < 0x1000) {  
        sVar4 = uVar5;  
      }  
      send(param\_1,acStack4136,sVar4,0);  
      \*(undefined \*)(param\_2 + 0x31) = 2;  
    }  
    else {                                      #针对于configure处理                
      if (\*(char \*)(param\_2 + 0x31) == '\\x02') {  
        sVar4 = strlen(pcVar7);  
        iVar3 = strncmp(pcVar7 + (sVar4 - 2),"# ",2);  
        if (iVar3 == 0) {  
          return 0;  
        }  
      }  
      else {  
        sVar4 = strlen(pcVar7);  
      }  
      iVar3 = strncmp(pcVar7 + (sVar4 - 10),"(config)# ",10);  
      if (iVar3 == 0) {  
        \*(undefined \*)(param\_2 + 0x31) = 0;  
        return 0;  
      }  
      pcVar7 = strstr(pcVar7,"WayOS#");  
      if (pcVar7 != (char \*)0x0) {  
        \*(undefined \*)(param\_2 + 0x31) = 1;  
        return 0;  
      }  
    }  
  } while( true );  
}
```

首先理解wayos中telnetd的登录验证流程，telnetd文件是一个链接到busybox的链接文件，逆向分析busybox的telnetd的登录过程。

![image-20221107155427102.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-3961f9ce55230c88e5cd8732d814281c54c1893d.png)

利用Ghidra逆向分析busybox，在string窗口中过滤login、login incorrect等关键词，然后通过交叉引用可以快速的定位到目标位置。

这里首先是通过login函数打印登录时的提示指纹login:，然后通过终端获取到输入的命令，进行基础的处理与检查，如果正常流程则进入到nvram函数。

![image-20221107155533694.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-cd9e9c0e229c4cb20ec8854d94231b37ae9ef5d8.png)

![image-20221107160448970.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-5b7774b1d46ff901491b0224454512eec7c10ff8.png)

获取解析之后所作的事情为利用nvram命令获取nvram信息，其中nvram get http\_username获取用户名，然后与输入相匹配。

![image-20221107161821830.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-2101e29511c7b2e788285ee7a054eb438ab1603b.png)

如果用户名输入失败（ivar22==0）则直接到exit，正确则提示输入password，然后这里有time函数和random函数提供了一个校验码，

![image-20221107162110888.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-4b05c6e785c0f726a622c8b5a8b9ed1e63ca96ce.png)

password可以通过一个循环实现，此循环最多循环三遍。

![image-20221107162215473.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-41f40a4b17f132ea374b42276561d05b58c74603.png)

这里有一个关键跳转，这里uVar16与password相关，uvar24为校验码。

![image-20221107162758611.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-f93efb4a06f8165a5380be318b8fb450d8a0dd0e.png)

根据以上分析，telnet的登录机制应该是没有问题，此漏洞的问题在于talnet服务mqtt协议的自动登录机制，在接受到对应的username或者password提示之后，会自行发送用户和密码，这里泄露了telnet的用户和口令。

利用mqtt\_ai文件中mqtt\_ai\_sw\_telnet\_login函数中的可以账户和口令可以进行telnet的登录获取shell。

0x04 httpd命令注入漏洞
================

将文件系统中的httpd可执行程序进行逆向分析，首先对于system函数进行Ghidra逆向分析，在Function栏里面过滤出system函数，找到函数的位置后点击交叉引用，得到所有调用system函数的位置，如下图所示。

![image-20221107194934625.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-856cced0345a7ff7a5d0b0db6c82221f0286b35c.png)

从中找出其中system执行的命令中含有可控数据流的部分，然后反向追溯，查看其是否对数据流进行了过滤等防护。

通过逐个调用点反汇编，发现如下可疑的system函数的参数数据流可控。

![image-20221107195550060.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-b631d0cbb223074e29e975383105b74bf1485160.png)

![image-20221107195702082.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-a3e37c003f5bdabb3d6d9c3ff5562273dd836be3.png)

![image-20221107200642523.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-a86934c01996f48d13f5c2d4acfbe1c8fa4d815f.png)

首先分析第一个，从用户输入获取usb\_username和use\_husername没有进行完全过滤，拼接的命令直接作为system()参数执行，引发命令注入。根据其关键词usb\_username和usb\_hosorname可以推断出其是有关于usb的，并且可能和用户有关。

从网页上找到对应可能有关的功能，先熟悉该防火墙的功能。可以发现其对于usb储存具有安全功能，而且其中具有一个共享服务，共享服务就有可能和用户相关系。

![image-20221107230918493.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-1769903c4928a34eafa79a41398599c969c865f1.png)

浏览器F12查看器network，设置usb共享服务之后有这样一个请求与上述的分析相类似。

![image-20221107231548691.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-403cf4e6a9c740d14e61c8b74d86966ed63eb339.png)

利用burpsuit进行测试，漏洞点如下所示，可以利用;进行原来的用户名与嵌入的命令分割，同时利用``(单引号，键盘的左上角)将需要嵌入的命令包含，这样system执行命令时会首先执行引号内的命令，然后将结果与echo命令的内容相结合，然后通过echo执行输出。

`sprintf(acStack304,"echo \\"%s = %s\\" >> /etc/smbusers","smbadmin",uVar7); system(acStack304);`

这里首先需要对于嵌入的命令进行url编码。

![image-20221107234203314.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-23dd579dcf56f47274342fa2f15b42a6b67e39c8.png)

然后利用burpsuit抓包，抓取到如下数据包，然后将hname部分字段替换后发送：

![image-20221107234412634.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-dde7bc3fd99d8ecf31b4ed1937ef2b9f4a9740e9.png)

查看tmp文件夹，发现新建了一个1.txt文件，同样可以执行其他命令，比如反弹shell、写马、泄露文件等等。

![image-20221107234535849.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-40aabe27e31b2ab6f959775a7272e60fa9d0b4b4.png)

另外的两个可疑漏洞点指定了数据流必须是%d为数字型，而且该数字是上面的函数根据nvram\_get（xxx）获取对应进程信息，难以有效控制，所以难以利用。

0x05 CSRF漏洞
===========

继续在httpd文件逆向中字符串窗口筛选usb，发现有如下一些功能，尤其是usb.upload.htm文件可以在免登录的情况下访问，输入文件后进行删除功能。

![image-20221108105021787.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-31e77fdc433ddde4e6633e5c4715e856d156a881.png)  
输入需要删除的文件之后发现其在没有登录的情况下权限不够

![image-20221108105235119.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-b55ecd99755ea88a8b92bbf6e52e6b3d0c4bd4eb.png)

![image-20221108105434718.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-46c6702394e2a8031bd99673cd53d41b9411f316.png)

然后会自动跳转到，需要usb\_share账户的认证登录。这个服务需要在配置端的usb储存共享服务中开启。

![image-20221108105547360.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-a89fa2ba4c874fc2bfb7f45eb586e5e5cfb2678c.png)

登录后再次访问到usb\_upload.htm文件，发现其报文cookie中没有tocken防护，也没有reference，而且再次点击删除提示文件不存在，说明执行了删除操作，则应该具有csrf漏洞。

![image-20221108110020510.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-bf4a429afa78a2773553a1785315abb40d2de8ed.png)

抓包删除功能的请求，利用burpsuit进行csrf的poc的生成（需要pro版本的burpsuit）。然后使用usr\_share用户登录后的状态下打开poc文件，则执行文件删除功能。

![image-20221108112129443.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-f69fbe04b27f6e198c68dbd3a47e96322615c44d.png)

文件上传功能相似：

![image-20221108112055103.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-ba9d7cb29483bcdc618739b44d13771c68b81d6a.png)