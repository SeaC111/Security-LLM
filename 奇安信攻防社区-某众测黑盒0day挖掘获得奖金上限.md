刚开学没多久在宿舍隔离上网课，无聊看漏洞众测平台发布了新项目（好好学习，好好听课，不要逛SRC）

![attach-14df3f269ab5a1a80e1ec8f1ebc0df71206c3599.jpg](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-1d56a8c7cf34a1d68a2b68f42212fdc5d0349e6a.jpg)

最高奖金一千块。然后成功报名并通过审核占到茅坑（占着茅坑不拉屎）  
![image-20221114222234298.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-6f8ef03ffeca15b22eecf6d70c18d4d1cf9701d3.png)

使用奇安信的资产收集平台直接找到用户服务系统。  
访问地址：<http://user.xxx.cc/newlogin>  
![image-20221114222919191.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-c33548cc11d7b94223145321ef66062cc5d00185.png)

然后拿自己手机号码注册个账号登录进去。因为是众测，贵公司也关了好多功能不给用，所以注册的账号进去只是个空壳，并没有什么功能点。  
![image-20221114223117908.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-7695b6659d8313f9e9fc4aded20f96d4130b83aa.png)

然后点击右上角的应用中心会跳过这个系统进入下一个子站。然后使用F12大法开始审计JS，看看JS文件里有没有开发遗留的账号和链接接口。

最终在一处文件中发现一处接口：  
[https://xxx.xxx.cn/xxxx/web/singlelogin.aspx?AuthType=UserMap&amp;AppCode=BI&amp;UserCode](https://xxx.xxx.cn/xxxx/web/singlelogin.aspx?AuthType=UserMap&AppCode=BI&UserCode)=

![image-20221114223727713.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-533a4af040d4e15cb97e6319a826f63bcbf3c92a.png)

访问接口：[https://xxx.xxx.cn/xxxx/web/singlelogin.aspx?AuthType=UserMap&amp;AppCode=BI&amp;UserCode=](https://xxx.xxx.cn/xxxx/web/singlelogin.aspx?AuthType=UserMap&AppCode=BI&UserCode=)

页面提示无法获取到UserCode参数：

![image-20221114224239357.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-f0c212b2ace42e8cf2df52cd1b42870031f25bef.png)

根据UserCode参数里面的User，猜测是关联用户名，于是加个admin尝试：[https://xxx.xxx.cn/xxxx/web/singlelogin.aspx?AuthType=UserMap&amp;AppCode=BI&amp;UserCode=admin](https://xxx.xxx.cn/xxxx/web/singlelogin.aspx?AuthType=UserMap&AppCode=BI&UserCode=admin)  
提示该用户没有关联GS用户，验证了我们的猜测。

![image-20221114224545387.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-91cdeb6eeb845ed31f96b51b5a05f00bd9858338.png)

然后抓包遍历用户名，发现有几个302重定向跳转了：

![image-20221114224749782.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-d6282c22c97087e1b102cd283f37954490214e58.png)

然后在UserCode参数后面加上遍历出来的用户名。（这里不使用真实用户名）

wsh  
wshwsh  
wshwshwsh  
wshwshwshwsh

选取其中一个去访问：[https://xxx.xxx.cn/xxxxx/web/singlelogin.aspx?AuthType=UserMap&amp;AppCode=BI&amp;UserCode=wsh](https://xxx.xxx.cn/xxxxx/web/singlelogin.aspx?AuthType=UserMap&AppCode=BI&UserCode=wsh)

然后302跳转进入到核心系统：<https://xxxxx.xxxx.cn/xxxxx/web/gsprtf/main.aspx>?

![image-20221114225037858.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-ae87bfd34d27789e10f2c68c64bfc60f0d64d713.png)

然后进入应用里面查看，全是合同等敏感数据，还可对其增删改查。

![image-20221114225554900.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-7939fa2b00f3b572ed0012dffbf63f08ebb89455.png)

看到了我最喜欢的报账功能：

![image-20221114225740678.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-7cceb763917e11468356afe86aa2576d5fe9c88a.png)

里面的功能模块还有很多可以测。但是因为系统比较敏感，就不做多余的测试（其实是奖金池奖金不多了）。然后提交漏洞获取赏金，点到为止。

最后去fofa指纹识别一下，发现是一个通用漏洞（意外收获），但是使用的资产不是特别多：

![image-20221114230629233.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-6984e517d5448a73d755d864d0e5c178ad791e1f.png)

随便找一个站测试：

![image-20221114231317853.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-8b6422800a687a8974567dcef595214b2443b71f.png)

贴上跟前面一个系统一样的接口：[https://xx.xxx.com.cn/xxxxx/web/singlelogin.aspx?AuthType=UserMap&amp;AppCode=BI&amp;UserCode=](https://xx.xxx.com.cn/xxxxx/web/singlelogin.aspx?AuthType=UserMap&AppCode=BI&UserCode=)

得到一样的结果。证明了通用性。

![image-20221114231411322.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-d96dd2878ff333e0dc71f1be67682f580219c34c.png)