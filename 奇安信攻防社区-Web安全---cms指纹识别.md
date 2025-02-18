**一、前言**  
CMS指纹识别：指纹识别是将识别对象的指纹进行分类对比从而进行判别，就像是人的指纹一样，不会出现一模一样的指纹，从而通过每个对象的不同特征来识别对象的归属。这里的指纹识别是指网站CMS指纹识别，在渗透测试过程我们会遇到各种各样的CMS建站，我们需要判断目标网站使用的到底是哪一个CMS。判别方法就是看应用程序的文件中出现的特征码，这个特征码就可以快速识别出到底是哪一个CMS，再将判别出来的CMS进行漏洞查找利用。  
**二、CMS指纹识别思路**  
可以对CMS指纹的各个识别工具进行使用，区别各个指纹识别的不同与特点  
（一）可以使用CMS指纹识别工具来进行客户端的识别，常用的工具有Test404轻量CMS之别识别工具、plecost、cmscan、御剑WEB指纹识别工具、BlindElephant、FingerPrint、gwhatweb、TideFinger、Wappalyzer、指纹特征识别beta2-b0y等  
（二）手工进行识别，可以对网站的显示信息进行分析，如技术支持显示、Powered by xxx，或者是网站的后台登录界面也有建站cms的特征码。以及网站的路径信息，不同的cms建站有不同的网站路径名，可以根据其中特有的路径名进行区分，还可以利用robots.txt文件来匹配不同的cms。  
（三）在线cms指纹识别平台检测，如http://whatweb.bugscaner.com/look/、<http://www.yunsee.cn/finger.html>  
**三、脚本类的指纹识别工具进行利用**  
**（一）根据关键字、网页显示的特征码识别cms类型**  
脚本代码如下：  
利用过程：  
request建立连接---获取网页内容---利用正则表达式匹配关键字---识别CMS类型

```python
import requests
import re
header={
'Accept-Language':'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
'User-Agent':'xxxxxx',
'Accept-Encoding':'gzip, deflate, br'
}
url=(&amp;amp;amp;quot;http://www.xxx.com&amp;amp;amp;quot;)
res=requests.get(url, header)
text=res.text
pattern=re.compile('Powered by &amp;amp;amp;lt;.*?&amp;amp;amp;gt;(.*?)&amp;amp;amp;lt;\/.*?&amp;amp;amp;gt;.*?',re.S)
flag=re.findall(pattern,text)
if flag!=[]:
print(&amp;amp;amp;quot;识别成功:&amp;amp;amp;quot;,end=&amp;amp;amp;quot;&amp;amp;amp;quot;)
print(flag)
else:
print(&amp;amp;amp;quot;识别失败&amp;amp;amp;quot;)
```

**Phpwind cms指纹识别**  
[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-42fca1ba0373af57e04b8400ba867332b20506ee.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-42fca1ba0373af57e04b8400ba867332b20506ee.png)  
**织梦 cms指纹识别**  
[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-1eb8b897d44eba7751c6337409ce07dd2cc1e591.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-1eb8b897d44eba7751c6337409ce07dd2cc1e591.png)  
**Discuz cms指纹识别**  
[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-104cb388066d726072e1b50bfdf88e080de011e8.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-104cb388066d726072e1b50bfdf88e080de011e8.png)  
在互联网上，还有一种显示建站厂商的特征码方式，就是技术支持：XXX  
这种方式和前面介绍的Power by xxx的方式是一样的，都是反映该网站建站以及维护的cms厂商信息。  
**技术支持：本成网络**  
脚本代码如下：  
利用过程：  
request建立连接---获取网页内容---利用正则表达式匹配关键字---识别CMS类型

```python
import requests
import re
header={
'Accept-Language':'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
'User-Agent':'xxxxxx',
'Accept-Encoding':'gzip, deflate, br'
}
url=(&amp;amp;amp;quot;http://xxx.com&amp;amp;amp;quot;)
res=requests.get(url, header)
text=res.text
pattern=re.compile('技术支持:.*?&amp;amp;amp;lt;.*?&amp;amp;amp;gt;(.*?)&amp;amp;amp;lt;\/.*?&amp;amp;amp;gt;.*?',re.S)
flag=re.findall(pattern,text)
if flag!=[]:
print(&amp;amp;amp;quot;识别成功:&amp;amp;amp;quot;,end=&amp;amp;amp;quot;&amp;amp;amp;quot;)
print(flag)
else:
print(&amp;amp;amp;quot;识别失败&amp;amp;amp;quot;)
```

运行效果图如下：  
[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-b4786d1a8b992a47afbfea2a5d2bdf2df7a60716.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-b4786d1a8b992a47afbfea2a5d2bdf2df7a60716.png)  
**（二）根据cms的路径信息识别cms类型**  
脚本代码如下：  
利用过程：  
request建立连接---枚举网站路径---返回状态码---识别CMS类型

```python
import requests
import re
url = 'http://www.xxx.com'
with open(&amp;amp;amp;quot;web.txt&amp;amp;amp;quot;,&amp;amp;amp;quot;r&amp;amp;amp;quot;) as web:
webs=web.readlines()
w=open('write.txt','w+')
for web in webs:
web=web.strip()
pattern=re.compile('(.*?)------.*?',re.S)
flag=re.findall(pattern,web)
u = url+flag[0]
r = requests.get(u)
status_code=r.status_code
if status_code==200:
print(&amp;amp;amp;quot;识别成功:&amp;amp;amp;quot;,flag[1])
print(&amp;amp;amp;quot;url为:&amp;amp;amp;quot;+u+' '+&amp;amp;amp;quot;状态为:%d&amp;amp;amp;quot;%status_code)
w.write(&amp;amp;amp;quot;识别成功:&amp;amp;amp;quot;+flag[1]+&amp;amp;amp;quot;url为:&amp;amp;amp;quot;+u+' '+&amp;amp;amp;quot;状态为:%d&amp;amp;amp;quot;%r.status_code+&amp;amp;amp;quot;\n&amp;amp;amp;quot;)
```

**phpwind cms指纹识别**  
[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-385bb4f4a1d77302d58e1948a49ccc939991b63f.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-385bb4f4a1d77302d58e1948a49ccc939991b63f.png)  
将脚本运行的结果保存在write.txt文本下，方便用户查看  
[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-280102ff85e458e1aaa57d04c431292f13ce9c0f.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-280102ff85e458e1aaa57d04c431292f13ce9c0f.png)  
**四、客户端类的指纹识别工具进行利用**  
**（一）御剑WEB指纹识别工具**  
工具介绍：  
该工具利用的原理类似于上述的python脚本，通过枚爆破识别cms的路径和特征码  
[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-c37f02b3914e415cb77306d263fc36beebf6b019.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-c37f02b3914e415cb77306d263fc36beebf6b019.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-cf1b98b24e826c429aa90f1043237e24317398a8.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-cf1b98b24e826c429aa90f1043237e24317398a8.png)  
使用中可以单一添加，也可以导入文本（存放多个网站的文本），然后进行扫描  
[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-1c69f0238553b5f2e5e0b7c880def10cf358b136.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-1c69f0238553b5f2e5e0b7c880def10cf358b136.png)  
这里以i春秋论坛为例子，御剑WEB指纹识别工具会通过应用指纹（网页特征）和判定文件（路径信息）来识别各个不同的cms类型  
[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-e9d7780858199900ddf8cd0d869b9700f8295353.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-e9d7780858199900ddf8cd0d869b9700f8295353.png)  
最终结果为无法判定，现实中在建站的初期，如果网站管理员想要避免自己的网站被黑客前期信息收集的话，可以修改网页的特征信息  
（1）修改网页展示信息（网页模板、技术支持、关键字、版本信息、后台登录模块信息等）  
（2）修改网页路径信息（/robots、/admin等）  
（3）修改网页信息可以个性化一点，修改网页路径信息可以通过拼音缩写或者个性化方式来隐藏建站厂商的通用路径名，例如/admin修改为/a8min  
[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-39ca8b3b85a57f6639940159abd7b19042241732.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-39ca8b3b85a57f6639940159abd7b19042241732.png)  
识别成功的案例如下  
现实中如果是大型的互联网企业，网站中常常会部署一些安全设备，比如WAF（WEB Application Firewall），流量探针等，如果某个用户ip在一个很短的时间段发送了多个请求url，这就明显是有人利用工具在爆破，这个时候网站可能就会做一些保护措施，例如常见的封IP等  
[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-8e71f2b9fab579f7dd004fd0d0edb45ef0e7f1ca.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-8e71f2b9fab579f7dd004fd0d0edb45ef0e7f1ca.png)  
**（二）指纹特征识别beta2-b0y**  
工具介绍：  
通过识别/robots.txt路径下的内容，如果出现Disallow://wp-includes/，则判定cms为wordpress，以此类推来匹配robots路径下的内容  
[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-000be781c33ec675e45474453ff42b061bf77f8f.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-000be781c33ec675e45474453ff42b061bf77f8f.png)  
识别成功案例  
[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-d49351faec1aeaac8546b2a99027b7d2a75c7ed9.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-d49351faec1aeaac8546b2a99027b7d2a75c7ed9.png)  
如下该工具的配置，可以导入特征文件，也可以导出特征文件，从而增加工具可识别的范围  
[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-4a8cd76d030c4b5f5938515a274f9310b5f17eac.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-4a8cd76d030c4b5f5938515a274f9310b5f17eac.png)  
**五、在线cms指纹识别平台**  
平台网址为：[http://whatweb.bugscaner.com/look/，通过域名或者ip地址进行查询](http://whatweb.bugscaner.com/look/%EF%BC%8C%E9%80%9A%E8%BF%87%E5%9F%9F%E5%90%8D%E6%88%96%E8%80%85ip%E5%9C%B0%E5%9D%80%E8%BF%9B%E8%A1%8C%E6%9F%A5%E8%AF%A2)。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-d3e695c007c27c661b799ee188e4c5a80ca1d808.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-d3e695c007c27c661b799ee188e4c5a80ca1d808.png)

**六、后记**  
CMS指纹识别技术在实际的渗透测试中处于信息收集的模块，如果在前期的信息收集中能够收集到一个网站的建站cms，就能够利用该cms 的版本漏洞，以及在开源的cms中可以利用代码审计来寻找网站漏洞。平时挖掘通用漏洞中，寻找相同建站cms也是一个比较麻烦的过程，用户可以利用上述的方式来寻找该网站是否属于自己想寻找的cms建站厂商。