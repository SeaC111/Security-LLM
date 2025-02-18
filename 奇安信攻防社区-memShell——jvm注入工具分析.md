前提简要
----

#### Tomcat中Filter简要

Filter 程序是一个实现了 Filter 接口的 Java 类，与 Servlet 程序相似，它由 Servlet容器进行调用和执行。这个 Servlet 过滤器就是我们的 filter，当在 web.xml 中注册了一个 Filter 来对某个 Servlet 程序进行拦截处理时，这个Filter 就成了 Tomcat 与该 Servlet 程序的通信线路上的一道关卡，该 Filter 可以对Servlet 容器发送给 Servlet 程序的请求和 Servlet 程序回送给 Servlet 容器的响应进行拦截，可以决定是否将请求继续传递给 Servlet 程序，以及对请求和相应信息是否进行修改。

工具利用效果
------

来自冰蝎作者键盘下的demo工具：<https://github.com/rebeyond/memShell>  
利用效果如下图：

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-940ee7785be2011554c6fc32f21f6ef4d562fa63.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-940ee7785be2011554c6fc32f21f6ef4d562fa63.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-e5a8f9403f25e35051856c67056a584267bc237e.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-e5a8f9403f25e35051856c67056a584267bc237e.png)

Debug环境搭建
---------

首先启动tomcat，搭建可实现jvm注入的环境

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-5f0a9ec7b6d2c2735785dbd042d8cac9763642a5.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-5f0a9ec7b6d2c2735785dbd042d8cac9763642a5.png)

在idea配置被动监听debug端口，再debug启动项目

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-a91c6f357c372c89b21af5933216c24b8b1b8daa.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-a91c6f357c372c89b21af5933216c24b8b1b8daa.png)

运行inject.jar包时采用主动debug方式连接本地的idea中的源代码项目

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-8ad041b23876bee864518d2b1a9aae1f9a1bdfcc.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-8ad041b23876bee864518d2b1a9aae1f9a1bdfcc.png)

工具分析
----

首先就是需要键入获取密码以提高木马在用户界面具有较好的交互式

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-54909823b8d28ab98aeecf043595d38bcf2f3d2d.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-54909823b8d28ab98aeecf043595d38bcf2f3d2d.png)

然后获取当前目录找到同目录下的agent.jar

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-8f1d129a6eb2f18b9784dcaec52a6969e0fd20f3.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-8f1d129a6eb2f18b9784dcaec52a6969e0fd20f3.png)

接下来就是寻找`catalina`即tomcat的jvm进程，然后将agent.jar注入进去。现在先通过`VirtualMachine.list()`遍历所有jvm中的进程，可以看到`vmlist`中存在PID为9404的`org.apache.catalina.startup.Bootstrap start`的服务进程

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-f986a2ae88cf2cf9142da50f04d974930fe82803.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-f986a2ae88cf2cf9142da50f04d974930fe82803.png)

接着通过`VirtualMachine.attach(vmd)`获取`catalina`进程的`VirtaulMachine`实例，再通过简单的判断确认，利用`loadAgent()`方法用于加载agent.jar，以对catalina进程完成注入agent.jar。

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-27f7cfb8061fd539e1476f6b53ef5b7656adcb7f.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-27f7cfb8061fd539e1476f6b53ef5b7656adcb7f.png)

由于agent.jar跟命令行中执行的inject.jar不是一块的，所以暂时无法继续debug跟踪，以上仅对如何寻找tomcat进程对其实现注入做了分析，最后一步将手把手对agent.jar做源代码的分析。

当debug断掉之后，可以看到tomcat启动命令行中出现`Agent Main Done`的字眼，所以可以看出jvm进程中必定走到了源代码的Agent类中的`agentmain()`方法

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-67c099881b065af5d7a0cc269624bf8952897603.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-67c099881b065af5d7a0cc269624bf8952897603.png)

从classname中指定的类`org.apache.catalina.core.ApplicationFilterChain`即tomcat的调用过滤器链，可以看出，这agent应该是个动态注册filter型内存马，`getallloadedclasses()`将返回 jvm 当前已加载的所有类，找到指定`ApplicationFilterChain`类则利用`retransformClasses()`方法重新加载，最后`initload()`以提供内存马功能点的正常使用

#### Tips：

关于tomcat如何处理filter可参考：<https://www.136.la/jingpin/show-35570.html>  
关于该工具的功能点分析可参考：[https://blog.csdn.net/weixin\_39541600/article/details/110078172](https://blog.csdn.net/weixin_39541600/article/details/110078172)