从脱壳到无视抓包限制破解某壁纸APP注册登录协议和会员
---------------------------

### 此款 App 监测 VPN 抓包

这是一款手机壁纸 App。

最初是想通过单纯的通过 VPN 抓包，利用 HttpCanary 工具，实现找到图片的链接然后下载，只要传输中不是加密的，那么这种方法一定可行。

因为 VPN 是常用的办公工具，并且如今代理 wifi 大多数 APP 都会进行监测，代理 VPN 是目前流行的最好抓包办法。

然而，此款 App 监测了 VPN ，如果手机挂着 VPN，此款 App 是不走流量的，刷新时就会一直显示正在加载。抓不到任何的数据包。

![1.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-5853b488e0afc6a2663e81a10155b41ff33d200c.png)

### hook 框架进行抓包

既然通过常规抓包方式抓不到。那么尝试 hook 框架进行抓包。

首先就要确定这个 App 使用了哪个网络框架进行收发包，安卓常用的网络框架有 HttpURLConnection，OKhttp3，Retrofit。

先动态搜索 HttpURLConnection ，发现使用了这个框架。

![2.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-d116b2dc34d6a075a2670e8f857777d5a20b727c.png)

再动态搜索 OKHttp ，发现也使用了 okhttp3 这个框架。

![3.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-28e7d05d9894614033b0ed9939c35ee9142542aa.png)

既然两个都使用了，动态分析结束再静态分析看看，两个结合逆向分析，效果会好些。

但是当把 Apk 文件拖入到 Jadx 中发现是加壳的。

于是使用 frida-dexdump 进行脱壳。

![4.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-f32a792cd2c0491f8dda96da2d617a1d77d0efa8.png)

从脱壳后的文件可知，确实使用了 okhttp3。

![5.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-e6848ff601960916ec498688bfc45686ecaf9ed3.png)

常用对 OKhttp3 hook 的框架是 OkHttpLogger-Frida。

首选将 OkHttpLogger-Frida 项目的 okhttpfind.dex 拷贝到 /data/local/tmp 目录下，并赋予 777 权限。

![6.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-7c9a51cd41a4d6b7bb1a9383e08bd7d85dfd4aa6.png)

然后 frida Spawned 模式下进行 hook ，首先执行 find() 命令，查看是否使用了混淆。

经过查找发现没有混淆。

![7.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-2b729254fc7791735a1358848bcf02d399728acf.png)

然后将查找到的结果，复制到 okhttp\_poker.js 中。

![8.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-10fe8c8e0367ddff818acd51403309b072c36093.png)

当网络执行时，使用 hold() 命令，就可以进行抓包了。并且界面非常的简洁。

### 实现脱机注册和登录

在注册页面进行注册的内容是：账号 qqqqwwww 密码 123456789 email <a@qq.com> 。

通过 hook 抓包可拿到所有信息，注册失败时，它会提示 success:0 ，此用户名已被注册。

![9.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-ec148d21af2f26bfa036b47a44cd5ae5adb0d07a.png)

再次注册，在注册页面进行注册的内容是：账号 qqqqwwwwa 密码 123456789 email <a@qq.com> 。

同样也可通过 hook 抓包拿到所有信息，这次注册成功，它会提示 success:1，注册成功。

![10.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-e8f3e14310b759c4b74667f79de720fe64fcb4fb.png)

通过上面两张图得知，此 App 只限制了常规的抓包方式，而对于 hook 抓包是不能免疫的，并且是完全的明文传输。

将上面的过程，用代码实现，就可实现脱机注册。

```python
import requests  
import json  
​  
headers = {  
    'user-agent': 'Mozilla/5.0 (Linux; Android 8.1.0; Nexus 6P Build/OPM7.181205.001; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/61.0.3163.98 Mobile Safari/537.36 uni-app Html5Plus/1.0 (Immersed/24.0)'  
}  
​  
​  
def register(username, passwd, email):  
    url = 'https://x.xxxxxxxx.xxx/wp-admin/admin-ajax.php?action=ajaxregister2'  
​  
    params = {'username': username,  
              'passwd': passwd,  
              'email': email  
              }  
​  
    response = requests.get(url=url, params=params, headers=headers, verify=False)  
    result = response.content  
​  
    json_obj = json.loads(result)  
    print(json_obj)  
    print(json_obj['message'])
```

注册完毕后，还剩下登录，原理相同。

用注册成功的账号进行登录，在登录的时候进行 hook 抓包，抓到的包如下：

![11.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-5a54b2513817cc74d251579a65e4c2b6ced1df7b.png)

同样将上面的过程，用代码实现，就可实现脱机登录。

```python
import requests  
import json  
​  
headers = {  
    'user-agent': 'Mozilla/5.0 (Linux; Android 8.1.0; Nexus 6P Build/OPM7.181205.001; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/61.0.3163.98 Mobile Safari/537.36 uni-app Html5Plus/1.0 (Immersed/24.0)'  
}  
​  
​  
def login(username, passwd):  
    url = 'https://x.xxxxxxxx.xxx/wp-admin/admin-ajax.php?action=ajaxlogin2'  
​  
    params = {'username': username,  
              'passwd': passwd  
              }  
​  
    response = requests.get(url=url, params=params, headers=headers, verify=False)  
    result = response.content  
​  
    json_obj = json.loads(result)  
    print(json_obj)  
​
```

这就造成了很严重的问题，例如脱机注册，写一个循环就可进行批量注册，会对服务器的压力和判断软件的使用情况，造成艰难的影响。

脱机登录，就会造成，对已有用户的暴利破解，只要时间足够，一定就会获取到他人的账号和密码，并完成登录。

### 绕过会员限制，实现非会员下载会员壁纸

非会员进入 vip 栏如下图，就是看到的壁纸都是带手机框框的，如果下载下来肯定也是带手机框框的，显然无法使用。

![12.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-3b5d81bf90ba5ff525f018e9aa022c46d38e22be.png)

所以这就面对了两种方式破解实现，非会员下载会员壁纸。

第一种方式，就是想办法成为会员。

通过抓包可以看到，当登录成功后，App 就会每隔 2-3 秒请求一次下面的内容

![13.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-97a7f7b1058d18a725830a02e819d382ad48514a.png)

通过返回的内容，可以看出，返回的内容就是用户的全部信息。

boolean 项都是 true，也就是说这里面肯定有一项为 false 代表的是会员，这难点就很大了，第一要找到哪个字段代表的是 vip，第二这个是服务器端返回的结果，客户端无法操作。所以先放弃第一种，

第二种方式，不成为会员，但找到会员的图片。

非会员的图片已经看到了，就是带有手机框框的。

会员的图片用脑袋也可以想到，那就是去除手机框框的，开发中不可能当用户充值会员后，可以去除手机框框。

真相肯定就是：带有手机框框的壁纸，和不带有手机框框的壁纸肯定各有一份。

只需找到真正的 url 就找到了胜利。

还是通过抓包，定位到请求 vip 栏的网址。

发现请求后仍是一堆 json 字符串，这堆字符串中就有三种权限的网址，分别是非vip，vip，使用者。

![14.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-9e9a1faa98c5ca4de9bae3d3c3555f12b091d2a0.png)

以其中一张图为例，非 vip 看见的图片就是：

![15.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-929d12b3d7bbcd098693a01abda35794e2dc7f2f.png)

以其中一张图为例，vip 看见的图片就是：

![16.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-e67d34624298bb14d69dcb9ed1302648b54c13b4.png)  
也就是仅仅通过 hook 方式的抓包，再结合一些奇思妙想，就可实现越权的降为打击。