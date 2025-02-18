一 概述
----

> “ Lookups provide a way to add values to the Log4j configuration at arbitrary places. They are a particular type of Plugin that implements the StrLookup interface. ”

以上內容复制于log4j2的官方文档lookup - Office Site。其清晰地说明了lookup的主要功能就是提供另外一種方式以添加某些特殊的值到日志中，以最大化松散耦合地提供可配置属性供使用者以约定的格式进行调用。

二. 配置示例
-------

以下列举了两個主要使用的位置；當然不仅仅如此，log4j2允许你在任何需要的地方使用约定格式来获取环境中的指定配置信息。

```php
<properties>
   <!-- 之后我們就可以以 ${logPath}來引用该属性值  -->
  <property name="logPath">${sys:catalina.home}/xmlogs</property>
</properties>

<!-- 这里的${hostName} 是由log4j2默认提供的, 其值为程序所在的服务器的主机名 -->
<!-- 至於${thread:threadName}, 將是本次我們所提供一個自定义lookup示例 -->
<PatternLayout pattern="[${hostName}];[${thread:threadName}];[%X{user}];[$${ctx:user}];[$${date:YYYY-MM/dd}]" />
关于log4j2的详细使用说明，请参看官网开发文档。
```

三. 分析
-----

我们分析一下lookup机制，都会在什么地方级别的日志中出现。首先我们要了解一点日志等级，在log4j2中， 共有8个级别，按照从低到高为：ALL &lt; TRACE &lt; DEBUG &lt; INFO &lt; WARN &lt; ERROR &lt; FATAL &lt; OFF。

- All:最低等级的，用于打开所有日志记录.
- Trace:是追踪，就是程序推进一下.
- Debug:指出细粒度信息事件对调试应用程序是非常有帮助的.
- Info:消息在粗粒度级别上突出强调应用程序的运行过程.
- Warn:输出警告及warn以下级别的日志.
- Error:输出错误信息日志.
- Fatal:输出每个严重的错误事件将会导致应用程序的退出的日志.
- All:最低等级的，用于打开所有日志记录.
- Trace:是追踪，就是程序推进一下.
- Debug:指出细粒度信息事件对调试应用程序是非常有帮助的.
- Info:消息在粗粒度级别上突出强调应用程序的运行过程.
- Warn:输出警告及warn以下级别的日志.
- Error:输出错误信息日志.
- Fatal:输出每个严重的错误事件将会导致应用程序的退出的日志.

程序会打印高于或等于所设置级别的日志，设置的日志等级越高，打印出来的日志就越少 。

详细代码可以看这里![图片](https://shs3.b.qianxin.com/butian_public/f194135e3ad1a3da842979f939a8266699c86af910d33.jpg)

也就是说，在不管什么级别的日志下都可以出发lookup。但是为什么有些级别的日志下却不可以触发呢？那是因为你的日志级别设置的太高，导致log4j根本就没打印日志内容。

在`org.apache.logging.log4j.core.pattern.MessagePatternConverter#format`中，会按字符检测每条日志，一旦发现某条日志中包含`$ {`，则触发替换机制，也就是将表达式内的内容替换成真实的内容，其中`config.getStrSubstitutor().replace(event, value)`执行下一步替换操作，关键代码如图![图片](https://shs3.b.qianxin.com/butian_public/f89576864fb18e94383a948201d19f0e2b3888d2c5942.jpg)

`org.apache.logging.log4j.core.lookup.StrSubstitutor#substitute(org.apache.logging.log4j.core.LogEvent, java.lang.StringBuilder, int, int, java.util.List<java.lang.String>)`中，其实就是一个简单的字符串提取，然后找到lookup的内容并替换。函数的文档如下![图片](https://shs3.b.qianxin.com/butian_public/f6802583a46557b51b659b5a691982f78320c810cb3a5.jpg)

![图片](https://shs3.b.qianxin.com/butian_public/f819180ee976d33f160541ce2c76c07de5693edfd39a2.jpg)

没啥说的，一个简单的字符串查找函数，学过数据结构的都会，不详细介绍了。

在函数的这个地方，执行变量解析，如图

![图片](https://shs3.b.qianxin.com/butian_public/f826798d54f40089a0a71e72de006ed2a9c0705fda97b.jpg)

在这个函数，执行查找，也就是根据变量的协议，关键代码+文档如图![图片](https://shs3.b.qianxin.com/butian_public/f825873b50dce986e99774304f9eb00fa9ec0c818ab73.jpg)

剩下就是一个简单的字符串查找函数，从字符串中提取类似于url的结构去解析，关键代码如下

![图片](https://shs3.b.qianxin.com/butian_public/f8261002f82875bb999bd230133e2b2c278785d53d9cc.jpg)

值得注意的是，log4j2支持很多协议，例如通过ldap查找变量，通过docker查找变量，详细参考这里https://www.docs4dev.com/docs/zh/log4j2/2.x/all/manual-lookups.html

代码结构如图

![图片](https://shs3.b.qianxin.com/butian_public/f906493d89c5f818422918ecb561b51576d7bc48aa4d4.jpg)

由以上类层次结构图可以看出

1. log4j2提供不下十种获取所运行环境配置信息的方式，基本能滿足实际运行环境中获取各类配置信息的需求。
2. 我們在自定义lookup時，可以根據自身需求自由选择继承自StrLookup，AbstractLookup，AbstractConfigurationAwareLookup等等來簡化我們的代碼。以上默认提供的各类lookup，其取值來源看官可以通过下面给出的引用链接中的第二個進行详细的了解，我就不再在这里赘述一遍了。

接下來我們來探索一些稍微深入的內容，以及一些細節性的內容。

1. 作爲lookup對外門面的Interpolator是通過 log4j2中負責解析節點的PropertiesPlugin類來併入執行流程中的。具體源碼可以參見PropertiesPlugin.configureSubstitutor方法。其中注意的是，我們在中提供的属性是以default的优先级提供給外界的。
2. 作为lookup对外门面的Interpolator，在其构造函数中载入了所有category值为StrLookup.CATEGORY的plugin【即包括log4j2內置的(“org.apache.logging.log4j.core” package下的），也包括用戶自定義的（log4j2.xml文件中的 Configuration.packages 属性值指示的package下的）】。
3. Interpolator可以单独使用，但某些值可能取不到。
4. 获取MDC中的內容，log4j2提供了兩种方式：$${ctx:user}或%X{user}。