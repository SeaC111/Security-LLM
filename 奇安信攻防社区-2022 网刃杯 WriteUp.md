0x01 Re
=======

freestyle
---------

签到题，

![f3250a37261b0acdeb7139d3a8ec33d.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-635659beec1556225fcb8b3c2f6f1be1bb161b71.png)

![a60b06730a4015087b45e634bce4b3c.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-92bbcc6f32c4cfab4095543535cc1f5024961404.png)

![5268e9a9b01481fd8b48b60b13cbda9.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-8f3470d90e034910e38e6e1aaac2b187d310bf4a.png)

解出来两个方程式，第一个为3327、第二个为105

flag{31a364d51abd0c8304106c16779d83b1}

Re\_function
------------

有两个文件，一个是32为exe，另一个是64为的elf文件

exe文件直接看c伪代码没看懂感觉好乱看不懂，我还是直接看汇编吧，相对之下比较友好哈哈哈。

然后经过一整调试发现，是将我们输入的奇数位与0x37异或然后得到了一串字符

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-54fa81341975ca7f6fd2c77441fff83164ebcb4f.png)

然后看elf文件

是一个base64算法，是经过了魔改的，敲，只换了字符串表然后解接就好了

```php
# coding:utf-8

#s = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
#s = "vwxrstuopq34567ABCDEFGHIJyz012PQRSTKLMNOZabcdUVWXYefghijklmn89+/"
s = "FeVYKw6a0lDIOsnZQ5EAf2MvjS1GUiLWPTtH4JqRgu3dbC8hrcNo9/mxzpXBky7+"

def My_base64_encode(inputs):
    # 将字符串转化为2进制
    bin_str = []
    for i in inputs:
        x = str(bin(ord(i))).replace('0b', '')
        bin_str.append('{:0>8}'.format(x))
    #print(bin_str)
    # 输出的字符串
    outputs = ""
    # 不够三倍数，需补齐的次数
    nums = 0
    while bin_str:
        #每次取三个字符的二进制
        temp_list = bin_str[:3]
        if(len(temp_list) != 3):
            nums = 3 - len(temp_list)
            while len(temp_list) < 3:
                temp_list += ['0' * 8]
        temp_str = "".join(temp_list)
        #print(temp_str)
        # 将三个8字节的二进制转换为4个十进制
        temp_str_list = []
        for i in range(0,4):
            temp_str_list.append(int(temp_str[i*6:(i+1)*6],2))
        #print(temp_str_list)
        if nums:
            temp_str_list = temp_str_list[0:4 - nums]

        for i in temp_str_list:
            outputs += s[i]
        bin_str = bin_str[3:]
    outputs += nums * '='
    print("Encrypted String:\n%s "%outputs)

def My_base64_decode(inputs):
    # 将字符串转化为2进制
    bin_str = []
    for i in inputs:
        if i != '=':
            x = str(bin(s.index(i))).replace('0b', '')
            bin_str.append('{:0>6}'.format(x))
    #print(bin_str)
    # 输出的字符串
    outputs = ""
    nums = inputs.count('=')
    while bin_str:
        temp_list = bin_str[:4]
        temp_str = "".join(temp_list)
        #print(temp_str)
        # 补足8位字节
        if(len(temp_str) % 8 != 0):
            temp_str = temp_str[0:-1 * nums * 2]
        # 将四个6字节的二进制转换为三个字符
        for i in range(0,int(len(temp_str) / 8)):
            outputs += chr(int(temp_str[i*8:(i+1)*8],2))
        bin_str = bin_str[4:]   
    print("Decrypted String:\n%s "%outputs)

print()
print("     *************************************")
print("     *    (1)encode         (2)decode    *") 
print("     *************************************")
print()

num = input("Please select the operation you want to perform:\n")
if(num == "1"):
    input_str = input("Please enter a string that needs to be encrypted: \n")
    My_base64_encode(input_str)
else:
    input_str = input("Please enter a string that needs to be decrypted: \n")
    My_base64_decode(input_str)
```

出了

flag{we1come\_t0\_wrb}

ez\_algorithm
-------------

是个比较复杂的，但是是可以爆破的，每一位都和动调时的相同，这样就爆出了，算是个非预期吧

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-3d7a0c6f593095e38b97421eff4fbe8837562ca0.png)

这是调整之后的

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-3e21ccb3405709c64bab2b9fdc9b26e0ceb84115.png)

我们发现与加密后的密文相比第一个字母相同，所以就是w

一次类推爆破出

flag{w3Lc0mE\_t0\_3NcrYPti0N:}

0x02 MISC
=========

玩坏的winxp
--------

火眼仿真，在桌面文件夹取消隐藏，能出来一个图

![image-20220424160152443](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-da1b33ca3a472c296ed97ed37e6346e8c5b6a094.png)

![image-20220424160239701](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-37976eaf738d64e57d735630c28bd439dc2afb40.png)

binwalk，出来一个假flag图，再binwalk，出来加密压缩包

![image-20220424160308107](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-8c03af22e13ebdfc79f32631b88f110f58126604.png)

压缩包注释有提示

![image-20220424160330399](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-0783727617515381103e7782e78bd9bb3c0d586f.png)

需要社工，打开取证大师，在浏览器记录发现qq号

![image-20220424160455717](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-9ea7d8167b808ed11912ba459fa7f4f4645b73b0.png)

![image-20220424160556541](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-5dd772f81b5ef3ce705bf4ffa9aee3592ab762c4.png)

![image-20220424160610740](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-51eca406d6319c7ada886d0e5e13aa9f4dd52740.png)

解压压缩包，得到flag

![image-20220424160640462](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-9b9ef11f9d54fa2983e071bcaecee2a35992dc4e.png)

0x03 ICS
========

easyiec
-------

一翻就翻到了

![image-20220424192418622](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-a59f23e7462e1684e4c500aecc4b1b1f092c3d0a.png)

Carefulguy
----------

66 f的16进制

![image-20220424191931279](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-e8a2115bc917a25c8dd8a164744890bf6ddb3672.png)

往后翻翻，拼起来

![image-20220424192036730](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-e727790cbcd61c4453f154414ca06bde5a886076.png)

ncsubj
------

找到三段疑似Base64字符串

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-a58ee9e8ac9437f30dd56d27ffeabb9efdfdf93c.png)  
拼起来

`anx1fG58Z3xufGF8cHxmfGh8b3x3fHJ8cHxnfA==`

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-2bc0b7714030e3be916bc588556d8ce92b3149d8.png)  
还有一层

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-da18819256f421313513af46222f2651d1400268.png)

喜欢移动的黑客
-------

![image-20220424155014478](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-49006b5d35801e0d89331e2384e3361e3da3aefc.png)

问转速，参考这个：[https://blog.csdn.net/qq\_43264813/article/details/120262405?spm=1001.2014.3001.5501](https://blog.csdn.net/qq_43264813/article/details/120262405?spm=1001.2014.3001.5501)

在modbus协议中搜UINT16

搜到9933，对应的是26cd

![image-20220424155226918](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-27825c0ca75680f1c243f470d9cd00ed744ff801.png)

还没到10000，往前找找，找到一个DATA：2766，对应是10086，所以确定是这个，但是68456和68158里都是10086，不确定是哪个

![image-20220424155407186](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-9240d3140b7893b48263b1832497fe536dd391b4.png)

所以列了一下，16进制和10进制挨个试，最后好像有个‘+’，记不清了

![image-20220424155319789](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-c150ac32caf530eb5954ba833bb9e786247c966a.png)

xyp07
-----

这题是复现的，无语了，真就找flag大赛

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-b15b045a97ebbe88454f6310bbe962ab3168ac1c.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-3988d143a3dee4f7e15194145f8ba6b3a81557f4.png)

0x04 Web
========

sign in
-------

进入后可以看到源码

&lt;?php  
 highlight\_file(\_\_FILE\_\_);  
 $ch \\= curl\_init();  
 curl\_setopt($ch, CURLOPT\_URL, $\_GET\['url'\]);  
 curl\_setopt($ch, CURLOPT\_HEADER, 0);  
 curl\_exec($ch);  
 curl\_close($ch);  
?&gt;

显然 SSRF，可以读文件

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-221944298beea39a3c587de27c4995268764b429.png)

在 /etc/hosts 中发现内网 ip

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-b3a9612e056bd0735d7f4fbb21ee1ef6b51b94d5.png)

尝试用 dict 爆破端口，发现只开启了 80 端口，只好去爆破内网网段，在 172.73.26.100 处发现存活主机

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-a8cf134179c65d952d4a78d24b6b382bdb223943.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-bb457cb341e05d9b6013945d0fbda4a423148bfa.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-819f801a65486b1335e21e7bbb32cda9a4172acf.png)

接下来就是一系列的套娃，GET，POST，加 XFF 头，加 Referer 头即可

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-3fbf4346fd668b12ff0b309257e186de1b8440a8.png)

签到

upload
------

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-4de91538654cae721da1b5967d486d727b0e6a2c.png)

在题目描述中可以获得提示，在测试后可以发现存在报错注入

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-19145f1e0836f8cbb8bd8d49ed60903e0f796c66.png)

为 10.0.38-MariaDB 数据库与 ubuntu 系统，中间遇到了一些问题，会对`.`进行识别，导致我们不能读取表名，盲猜一手 flag

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-2ec66612026b3007253edff7cb19e10876cb2d38.png)

`flag{5937a0b90b5966939cccd369291c68aa}`

不够长，MID截取不了

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-dfbfee30ff81dbfdab219abb23272f99ff7fe55c.png)

ez-java
-------

进入后为如下页面

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-9439b722520b54bf0fe9772c7b4fe51773077d1c.png)

存在 /download 路由，推测存在任意文件下载

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-f05f1ed3d837ab404d4716d1bec074e45f2cd6b3.png)

读取到 web.xml ，发现 /test388 路由，尝试读取对应的包

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-8b4fa86acf113579bdb53d91e072adf0c8ec20ac.png)

反编译后可以看到

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-0e14d4a12a2720fd2f64f18516bfc08c116b8520.png)

猜测存在 SpEL 注入，不过存在黑名单

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-67e4d9c6e2d03f52405a036ce67c424399f8496c.png)

在网上找一下绕过的姿势

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-e325bffaa768b0b61d99e07ae8d668efe089d5c1.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-20f9d06a52767b5105384c2e0b1673ceea91bf90.png)

```php
{new java.util.Scanner(new ProcessBuilder("ls","/").start().getInputStream(), "GBK").useDelimiter("whoami").next()}
```

0x05 参考文章
=========

<https://www.cnblogs.com/bitterz/archive/2021/08/30/15206255.html#spel%E5%8F%98%E5%BD%A2%E5%92%8Cbypass%E7%9A%84tips>

ezjs
----

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-46881563c128f11d77287832ecf90f1eb62b40cc.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-d0e8f2c383e6685239d442ba621ea0dfb4566b0f.png)

原型链污染后利用 wget 读 flag