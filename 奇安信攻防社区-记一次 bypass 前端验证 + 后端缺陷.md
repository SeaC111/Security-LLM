### 0x00 故事的开始

有人找到我,搞攻防请求支援,当然这种请求那当然要逝世呀

### 0x01 开始渗透

发了一堆站,有ip有域名

我搞了一晚上啥都没发现,本来想挖挖越权啥的

早上起来用jsFinder扫描,说不定有什么接口泄露呢

结果还真扫到了一堆,一看就看到了一些不得了的东西

![](https://shs3.b.qianxin.com/butian_public/f5ccd9977a5ff93a3ceed7303c7ad840d.jpg)

getAllUsers,deleteuser等  
尝试访问一个接口发现报错  
![](https://shs3.b.qianxin.com/butian_public/f827054bbb51d06b0a8de1ce148bed7c9.jpg)

有可能是未授权!,赶紧构造一下参数

分析js后需要两个参数

![](https://shs3.b.qianxin.com/butian_public/fa027cd9e966233cf428f9a0c76ee999e.jpg)

随便构造了一下出现了所有人的信息但是密码全部md5加密了,尝试解密了一下解不出来,size表示显示的字节

![](https://shs3.b.qianxin.com/butian_public/f2fea8273446b105abf835829c109707a.jpg)

接下来要想办法进入后台进行更多的操作,因为构造参数什么的太麻烦了,他的大部分参数都rsa加密过

![](https://shs3.b.qianxin.com/butian_public/f61b37b0acf3423f6b29364d5183d25e3.jpg)

尝试修改过登入的返回包也没用

![](https://shs3.b.qianxin.com/butian_public/f06da5e5fc1297dbac4f0efb70ea4ddb8.jpg)

改为0表示成功

![image-20210604174516077](https://shs3.b.qianxin.com/butian_public/fcc2bac4f82f0107478b1cf0c016bd8fe.jpg)

发现并没有用

![image-20210604174618827](https://shs3.b.qianxin.com/butian_public/fa6055eb09a28d650a48a0f18577d098d.jpg)

如果换做以前的我,我会放弃,但是！我遇到了龙哥(前端代码审计的神)

### 0x02开始反转

![image-20210604174901464](https://shs3.b.qianxin.com/butian_public/f47a1ef53b37eb4ac9ae55f3f8bf09810.jpg)

![image-20210604175102543](https://shs3.b.qianxin.com/butian_public/fc055e6447d8b1e6d313822e6e77dea06.jpg)

找到了js判断是否登入后台的地方

```js
while (1)
    switch (e.prev = e.next) {
        case 0:
            if (T.a.start(),
                document.title = j(t.m eta.title),
                i = O bject(P[&quot;a&quot;])(), !i) {
                e.next = 9;
                sessionStorage.setItem(&quot;user&quot;, JSON.stringify({ &quot;userRole&quot;: &quot;admin&quot; }))
                break
            }
            if (&quot;/login&quot; !== t.path) {
                e.next = 9;
                break
            }
            o({
                    path: &quot;/&quot;
                }),
                T.a.done(),
                e.next = 28;
            break;
        case 9:
            if (r = p[&quot;a&quot;].getters.name, !r) {
                e.next = 15;
                break
            }
            s = JSON.parse(sessionStorage.getItem(&quot;user&quot;)),
                &quot;admin&quot; == s.userRole &amp;&amp; &quot;/bg_userManage&quot; !== t.path ? (O bject(a[&quot;Message&quot;])({
                        message: &quot;只有用户管理的权限&quot;,
                        type: &quot;warning&quot;,
                        duration: 5e3
                    }),
                    o({
                        path: &quot;/bg_userManage&quot;
                    }),
                    T.a.done()) : &quot;audit&quot; == s.userRole &amp;&amp; &quot;/bg_logManage&quot; !== t.path ? (O bject(a[&quot;Message&quot;])({
                        message: &quot;只有日志管理的权限&quot;,
                        type: &quot;warning&quot;,
                        duration: 5e3
                    }),
                    o({
                        path: &quot;/bg_logManage&quot;
                    }),
                    T.a.done()) : &quot;user&quot; != s.userRole || &quot;/bg_logManage&quot; !== t.path &amp;&amp; &quot;/bg_userManage&quot; !== t.path ? (o(),
                    T.a.done()) : (o({
                        path: &quot;/404&quot;
                    }),
                    T.a.done()),
                e.next = 28;
            break;
        case 15:
            return e.prev = 15,
                e.next = 18,
                p[&quot;a&quot;].dispatch(&quot;user/getInfo&quot;);
        case 18:
            o(),
                e.next = 28;
            break;
        case 21:
            return e.prev = 21,
                e.t0 = e[&quot;catch&quot;](15),
                e.next = 25,
                p[&quot;a&quot;].dispatch(&quot;user/resetToken&quot;);
        case 25:
            a[&quot;Message&quot;].error(e.t0 || &quot;Has Error&quot;),
                o(&quot;/login?redirect=&quot;.concat(t.path)),
                T.a.done();
        case 28:
            e.next = 31;
            break;
        case 30:
            -1 !== z.indexOf(t.path) ? (T.a.done(),
                o()) : (-1 !== n.path.indexOf(&quot;/non_visitor&quot;) ? o(&quot;/dashboard&quot;) : o(n.path),
                p[&quot;a&quot;].commit(&quot;user/SET_LOGINWINDOWSTATE&quot;),
                T.a.done());
        case 31:
        case &quot;end&quot;:
            return e.stop()
    }

```

使用f12断点进行Dbug调试

![image-20210604175501133](https://shs3.b.qianxin.com/butian_public/f942c0485be488acb7cfdd12db8e240d1.jpg)

发现是走到了0

![image-20210604175537414](https://shs3.b.qianxin.com/butian_public/f2e1a0069b91f5c9f947bf41bc1d45f61.jpg)

然后赋值了30,因为是while (1)所以跳到了30后面就直接结束了

![image-20210604175647519](https://shs3.b.qianxin.com/butian_public/f37aecb69544fe379e22591ca86c109bc.jpg)

注意到了9,感觉就是后台页面,我们只需要想办法进到9里面就可以了

![image-20210604175807700](https://shs3.b.qianxin.com/butian_public/fa15cd9492e7894f152d3c9dba887f6d4.jpg)

尝试重新调试

只需要在他赋值30的完事后在重新赋值覆盖掉他的值

![image-20210604175943529](https://shs3.b.qianxin.com/butian_public/f6e43b16610a43b558f8a8f8afbb00090.jpg)

然后不就会跳转到9了?

确实,成功跳到了9

![image-20210604180037854](https://shs3.b.qianxin.com/butian_public/fed9d06a60ab6f98ab09ee3d90229af37.jpg)

第一个if没有进,不管他看下面的s.userRole,而s又等于JSON.parse(sessionStorage.getItem("user"))

![image-20210604180348622](https://shs3.b.qianxin.com/butian_public/f403d5abf746ab93dd4ab86828fcf1271.jpg)

直接在这个地方赋值s.userRole="admin"发现报错,请求了龙哥

### 0x03白热化阶段

![image-20210604180522104](https://shs3.b.qianxin.com/butian_public/f4751f2b8b687d311b0121aa963cf4116.jpg)

![image-20210604180545776](https://shs3.b.qianxin.com/butian_public/f89172ae67452b6b42b760044a25a759a.jpg)

![image-20210604180635111](https://shs3.b.qianxin.com/butian_public/f3eb9ea87550c4c56b3ac8b9560a8f499.jpg)

```js
sessionStorage.setItem(&quot;user&quot;,JSON.stringify({&quot;userRole&quot;:&quot;admin&quot;}))
```

他这里先构造一个userRole=admin的json然后在进行写入本地的sessionStorage?

前面搞定了只需要把path路径改为bg\_userManage就可以查看了

![image-20210604181200037](https://shs3.b.qianxin.com/butian_public/f12f6de304ce7d588f72c9aa463a5a11f.jpg)

成功进来了这个判断:

![image-20210604181409145](https://shs3.b.qianxin.com/butian_public/f558a8410005642cc0d45a885ff84f55f.jpg)

查看后台:

![](https://shs3.b.qianxin.com/butian_public/f2c998612ec22a2abb85796661abda6ba.jpg)

尝试添加一个账号

![image-20210604181657503](https://shs3.b.qianxin.com/butian_public/f56be07092ce838e9f24f77635964c8f8.jpg)

果然,rsa加密了,如果我不进后台,拿头给他构造

![image-20210604181820472](https://shs3.b.qianxin.com/butian_public/f4a8b385c6b919fec86761d3d6d230a5e.jpg)

登入就完事了

![image-20210604182027341](https://shs3.b.qianxin.com/butian_public/f471d2e1c3569fb247a474397a0dd921a.jpg)

第一次登入需要修改密码:

![image-20210604182104210](https://shs3.b.qianxin.com/butian_public/f9b936e7dce3544f1fe66dcc123517072.jpg)

尝试直接修改别的用户的密码:

![image-20210604182155268](https://shs3.b.qianxin.com/butian_public/f2e6bc5663c660cf75ab54f8f2193d1a1.jpg)

结果真的可以修改

登入后的页面就不展示了,全是水印根本码不过来

### 0x04推荐

推荐浏览器插件reres

可以把网站的js下载到本地进行本地加载(实现修改js的目的,省的dbug修改)

![image-20210604182851612](https://shs3.b.qianxin.com/butian_public/f767f6949d1f78f418f52549de6b4e3ec.jpg)

可以直接在0的地方修改

![image-20210604182948940](https://shs3.b.qianxin.com/butian_public/fb161307964a9f0ed6bc0fb9922740b7e.jpg)

就不用每一次dbug了

### 0x05结尾

以后渗透要多看看js,接口什么,实现真正的从0到1

![image-20210604183205324](https://shs3.b.qianxin.com/butian_public/f0008810950bff35f443f46353e44f781.jpg)