前言
==

某次企业SRC的一次实战。其中通过信息收集发现了一个站点，这里为内部系统，访问的时候居然直接一片空白，是空白页面。难道空白页面就没有漏洞吗？我就偏偏不信这个邪，上手就是干！

过程
==

<a>https://x,x.com/</a>  
打开页面啥也没有，一片空白:  
![image.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-9e18868f4deac235815e855067853150b44aa67c.png)

其中这里按下键盘中的F12，通过审计js后，发现接口：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-860a5d6923f2b3874e741668fa082e5247546ca8.png)

其中的一个接口/api/plugin/directory/getLastUsedDirId拼接后，如下提示：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-f3d889da33d83212d44444003f915d28adb62052.png)

其中响应包中响应的“插件分类不能为空”让我百思不得其解，不知道是缺了什么参数。那么这里就再回到js中看看吧，果然，给我发现了端倪：  
这里再查看js，发现其中给出提示，原来是header要加如下字段：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-84d7c25891d5a1212e5c0abb03955d814fe998c9.png)

那么我加了其中一个字段category，发现成功，但是却又报了非法用户登录。那么这里就必须需要Authorization认证字段了：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-0ac19db5897ac11f1d34ec773afca08e6bd9c90b.png)

因此这里就又碰到了一个棘手的问题，Authorization认证字段这个一般都是成功登录系统后才会赋予给用户的一个值，而这个地方连页面都是空白的，那么这里到底去哪里寻找Authorization认证字段的值呢？

这里贯彻着遇事不决看js的思想，继续来审计js，终于发现了解决方法：  
其中在js中发现了login接口。这里存在该逻辑漏洞：id:t.id||"1234",name:t.name||"1234",organizationCode:t.organizationCode||-1。这里用了||或，那么言下之意就是如果不知道id、name和organizationCode的话，就可以直接id参数和name参数都填1234，organizationCode填-1

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-91f0038868843c21dfa94ce4004a139fd232845f.png)

login接口，这里真成功了，其中获取到data

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-f437984ff06653785b30cc07cad71aa6b1dcb270.png)

那么这里猜测data的值即为那个Authorization认证字段的值，这里填入：

发现成功调用接口：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-2b183549f7bc9c8ce3113556a799188beb6667bb.png)

那么这里其中的接口就都可以成功调用了：

像这里的获取内部数据等等

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-1da25297b64687a211c41241790c65a19797ee25.png)

这里最关键的一个接口来了：  
这里通过js审计到查看oss配置信息的接口：  
![image.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-0daa6175fc7f39ac159e8466d594718404ea7ebe.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-3ee593012c54271227cb3639078e9da2c5cb2b0f.png)

这里因为是阿里云的，所以这里直接使用oss browser来进行利用，利用成功：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-95e12befec279411a48e73e59ea985ea60c1c32c.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-fd260f6425981eb7daf805f3fc2538f98215fc92.png)

这些直接可以下载到后端的源码：

其中反编译出来直接为后端源码，泄露许多严重敏感信息

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-cc18a41f3b1fb3859deb56dd79c6c1d5833f6b0a.png)

后端的配置信息：

其中还有数据库密码等等敏感信息

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-ebc591e7e5d02da90c6e2b777da69cd681fd8144.png)

反编译出来的后端源码：  
![image.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-ca155fb43d6e785c0d2b38bcc471a63b8fd1cc48.png)

最后的最后，当然也是给了严重的漏洞等级，舒服了！