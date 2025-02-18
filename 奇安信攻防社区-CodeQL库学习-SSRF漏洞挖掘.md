### 规则分析

SSRF的常见代码表现形式：（HTTP SSRF）

```go
URL url = new URL(imageUrl);
HttpURLConnection connection = (HttpURLConnection) url.openConnection(); --> sink
connection.setRequestMethod("GET");

return connection.getResponseMessage();
```

sink函数中并没有外部参数，检测sink需要和前面的代码联系，需要判断URL 对象在构造时是否外部可控。

因此分析ql库中对SSRF漏洞是如何检测的：

Config路径：ql/java/ql/lib/semmle/code/java/security/RequestForgeryConfig.qll

#### isSource

```go
source instanceof RemoteFlowSource and
// Exclude results of remote HTTP requests: fetching something else based on that result
// is no worse than following a redirect returned by the remote server, and typically
// we're requesting a resource via https which we trust to only send us to safe URLs.
not source.asExpr().(MethodAccess).getCallee() instanceof URLConnectionGetInputStreamMethod
```

source使用了常见的RemoteFlowSource，覆盖常见的远程请求，同时作为Method的source调用中，不能包含URLConnectionGetInputStreamMethod类型的调用

```go
/** The method `java.net.URLConnection::getInputStream`. */
class URLConnectionGetInputStreamMethod extends Method {
  URLConnectionGetInputStreamMethod() {
    this.getDeclaringType() instanceof TypeUrlConnection and
    this.hasName("getInputStream") and
    this.hasNoParameters()
  }
}
```

即如下的Source：

```go
java.net.URLConnection.getInputStream()
```

这种不认为是SSRF的Source，可能是因为连接的数据是否可控不能确定

#### isSink

```go
override predicate isSink(DataFlow::Node sink) { sink instanceof RequestForgerySink }

abstract class RequestForgerySink extends DataFlow::Node { }

private class UrlOpenSinkAsRequestForgerySink extends RequestForgerySink {
  UrlOpenSinkAsRequestForgerySink() { sinkNode(this, "open-url") }
}

predicate sinkNode(Node node, string kind) {
  exists(InterpretNode n | isSinkNode(n, kind) and n.asNode() = node)
}

```

其中使用到了ExternalFlow.ql中的sinkNode谓词，该库中表示，该库为内部使用API，处理csv格式的数据，sinkNode(Node node, string kind)属于一个接口，从Node中找符合sinkModelCsv或者SinkModelCsv子类的Node数据，其中最后一个参数用于标识Sink的类型，每一列参数的含义在ExternalFlow.ql中有详细讲解，这里简单介绍几个常用的参数，在RequestForgeryConfig中使用的是sinkNode(this, "open-url")

1. package 包名
2. 类名
3. 是否跳转到子类
4. 方法名
5. 签名列，限制选择方法名
6. ext 不太懂
7. input 输入的位置
8. kind 当前sink的类型

就是匹配所有open-url类型的数据类型。

sinkModelCsv谓词数据如下：

```go
private predicate sinkModelCsv(string row) {
  row =
    [
      // Open URL
      "java.net;URL;false;openConnection;;;Argument[-1];open-url",
      "java.net;URL;false;openStream;;;Argument[-1];open-url",
      "java.net.http;HttpRequest;false;newBuilder;;;Argument[0];open-url",
      "java.net.http;HttpRequest$Builder;false;uri;;;Argument[0];open-url",
      "java.net;URLClassLoader;false;URLClassLoader;(URL[]);;Argument[0];open-url",
      "java.net;URLClassLoader;false;URLClassLoader;(URL[],ClassLoader);;Argument[0];open-url",
      "java.net;URLClassLoader;false;URLClassLoader;(URL[],ClassLoader,URLStreamHandlerFactory);;Argument[0];open-url",
      "java.net;URLClassLoader;false;URLClassLoader;(String,URL[],ClassLoader);;Argument[1];open-url",
      "java.net;URLClassLoader;false;URLClassLoader;(String,URL[],ClassLoader,URLStreamHandlerFactory);;Argument[1];open-url",
      "java.net;URLClassLoader;false;newInstance;;;Argument[0];open-url",
      // Bean validation
      "javax.validation;ConstraintValidatorContext;true;buildConstraintViolationWithTemplate;;;Argument[0];bean-validation",
      // Set hostname
      "javax.net.ssl;HttpsURLConnection;true;setDefaultHostnameVerifier;;;Argument[0];set-hostname-verifier",
      "javax.net.ssl;HttpsURLConnection;true;setHostnameVerifier;;;Argument[0];set-hostname-verifier"
    ]
}
```

其他还有很多SinkModelCsv的子类，包含了一些第三方库的sink函数。

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-e200b781edd1ea9751ae8dcb5509b3bcf43f9771.png)

#### isAdditionalTaintStep

前面提到，SSRF漏洞不同于JNDI注入或者SQL注入，它的sink检测需要联系sink之前的代码，判断sink的Method调用方是否外部可控。ql库中通过实现isAdditionalTaintStep(DataFlow::Node pred, DataFlow::Node succ)方法进行功能的实现。该谓词的作用是将两个原本不相连的Node强行连在一起

```go
override predicate isAdditionalTaintStep(DataFlow::Node pred, DataFlow::Node succ) {
  any(RequestForgeryAdditionalTaintStep r).propagatesTaint(pred, succ)
}

private class DefaultRequestForgeryAdditionalTaintStep extends RequestForgeryAdditionalTaintStep {
  override predicate propagatesTaint(DataFlow::Node pred, DataFlow::Node succ) {
    // propagate to a URI when its host is assigned to
    exists(UriCreation c | c.getHostArg() = pred.asExpr() | succ.asExpr() = c)
    or
    // propagate to a URL when its host is assigned to
    exists(UrlConstructorCall c | c.getHostArg() = pred.asExpr() | succ.asExpr() = c)
  }
}

```

这里相对有点抽象，举个例子去进行理解

```go
    @RequestMapping(value = "/one")
    public String One(@RequestParam(value = "url") String imageUrl) {
        try {
            URL url = new URL(imageUrl);
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("GET");
            return connection.getResponseMessage();
        } catch (IOException var3) {
            System.out.println(var3);
            return "Hello";
        }
    }
```

此处按照正常的逻辑，

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-ce161d7990db4dfc39412e7580e2cf796bf034cb.png)

由于url不被认为是污点，因此没有继续向后寻找，isAdditionalTaintStep的作用是：当存在`URL url = new URL(imageURL)`，且`imageURL`为污点时，认为 `url`也是污点。

接着分析它是如何实现的，在函数中，pred代表的是污点，在SSRF中就是用户指定的URL字符串，succ则是代表类似URL(url)这种方法调用或者是对象的实例化。实现中的意思为，**succ是一个UriCreation 调用或者一个UriConstructorCall调用，它的getHostArg方法返回的表达式等于污点node**。其中UriCreation和UriConstructorCall的定义都在Networking.ql中，不做过多的分析。总的来说，它们匹配new URL()、URI.create()，并且其中url地址对应的参数需要是外部可控。满足上述条件的，我们认为它也是一个污点。从而成功的把url→new URL(url)链接起来。

#### isSanitizer

```go
override predicate isSanitizer(DataFlow::Node node) { node instanceof RequestForgerySanitizer }

private class PrimitiveSanitizer extends RequestForgerySanitizer {
  PrimitiveSanitizer() {
    this.getType() instanceof PrimitiveType or
    this.getType() instanceof BoxedType or
    this.getType() instanceof NumberType
  }

private class HostnameSantizer extends RequestForgerySanitizer {
  HostnameSantizer() { this.asExpr() = any(HostnameSanitizingPrefix hsp).getAnAppendedExpression() }
}

```

该方法用于净化污点，去除一些误报。PrimitiveSanitizer 是常见的方法，不匹配基础类型、数字类型的节点。重点是第二个HostnameSantizer，HostnameSanitizingPrefix继承自InterestingPrefix，该类在Stringprefixes.qll中，该文件的注释中讲解了该类的作用，简单来说就是可以定义一个字符串前缀，并提供一个getAnAppendedExpression函数，用来匹配任意该前缀+ 污点字符串的节点，简单演示如下，其中suffix标识会被匹配到的节点

```go
 * "foo:" + suffix1
 * "barfoo:" + suffix2
 * stringBuilder.append("foo:").append(suffix3);
 * String.format("%sfoo:%s", notSuffix, suffix4);
```

HostnameSanitizingPrefix 用一个正则定义前缀

```go
HostnameSanitizingPrefix() {
  exists(
    this.getStringValue()
        .regexpFind(".*([?#]|[^?#:/\\\\][/\\\\]).*|[/\\\\][^/\\\\].*|^/$", 0, offset)
  )
}
```

该正则匹配字符串中`？`、`#`等符号之后的部分，用来解决如下情况的误报：

```go
URL url = new URL("http://127.0.0.1?x="+imageUrl);

```

此时，imageUrl无法指定目标访问任意的地址，也就不算是SSRF漏洞。

### 规则实战

使用microserviceseclab进行测试，该项目中的SSRFController.java包含了常见的5种SSRF漏洞。首先直接运行该检测QL，可以发现3处漏洞

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-cb31b8ef61a576687e45965485792d3c3bc25963.png)

漏洞代码如下:

```go
@RequestMapping(value = "/one")
public String One(@RequestParam(value = "url") String imageUrl) {
    try {
        URL url = new URL(imageUrl);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("GET");
        return connection.getResponseMessage();
    } catch (IOException var3) {
        System.out.println(var3);
        return "Hello";
    }
}

@RequestMapping(value = "/four")
public String Four(@RequestParam(value = "url") String imageUrl) {
    try {
        DefaultHttpClient client = new DefaultHttpClient();
        HttpGet get = new HttpGet(imageUrl);
        HttpResponse response = client.execute(get);
        return response.toString();
    } catch (IOException var1) {
        System.out.println(var1);
        return "Hello";
    }
}

@RequestMapping(value = "five")
public String Five(@RequestParam(value = "url") String imageUrl) {
    try {
        URL url = new URL(imageUrl);
        InputStream inputStream = url.openStream();
        return String.valueOf(inputStream.read());
    } catch (IOException var1) {
        System.out.println(var1);
        return "Hello";
    }
}
```

由于该项目使用了Spring-boot框架， 因此Source都是@RequestParam注解的参数。

在被成功检测的漏洞中，1和5分别使用了url.openConnection和url.openStream，被sinkModelCsv中的如下规则所匹配

\\root\\codeQL\\databases\\micro-service-seclab-database\\src.zip\\root\\codeQL\\micro\_service\_seclab\\src\\main\\java\\com\\l4yn3\\microserviceseclab\\controller\\SSRFController.java

```go
"java.net;URL;false;openConnection;;;Argument[-1];open-url"
"java.net;URL;false;openStream;;;Argument[-1];open-url"
```

4中使用了第三方的HTTP请求库，同样可以在ApacheHttp.qll中的ApacheHttpOpenUrlSink找到对应的sink定义

```go
"org.apache.http.client.methods;HttpGet;false;HttpGet;;;Argument[0];open-url"

```

2和3 没有被检测到，因此接下来分析其原因。

```go
@RequestMapping(value = "/two")
public String Two(@RequestParam(value = "url") String imageUrl) {
    try {
        URL url = new URL(imageUrl);
        HttpResponse response = Request.Get(String.valueOf(url)).execute().returnResponse();
        return response.toString();
    } catch (IOException var1) {
        System.out.println(var1);
        return "Hello";
    }
}

@RequestMapping(value = "/three")
public String Three(@RequestParam(value = "url") String imageUrl) {
    try {
        URL url = new URL(imageUrl);
        OkHttpClient client = new OkHttpClient();
        com.squareup.okhttp.Request request = new com.squareup.okhttp.Request.Builder().get().url(url).build();
        Call call = client.newCall(request);
        Response response = call.execute();
        return response.toString();
    } catch (IOException var1) {
        System.out.println(var1);
        return "Hello";
    }
}
```

#### 漏报1

该漏洞的触发流程如下：

imageUrl→url = new URL(imageUrl)→String.valueOf(url)→Request.Get(String.valueOf(url))

首先可以发现，在现有的规则中，没有 org.apache.http.client.fluent.Request.Get()这个sink。因此我们在Apachehttp.qll中的ApacheHttpOpenUrlSink加入如下行，

```go
//my
"org.apache.http.client.fluent;Request;false;Get;;;Argument[0];open-url",
```

接着重新运行漏洞查询ql，会发现还是无法检测到该链。原因是什么呢？第一反应是规则是否写的有问题，直接在RequestForgerySink使用Quick Evalutation

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-b8ba86e01c65e70818ad6e3c469bb5441bc45867.png)

会发现该sink点被成功找到了

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-7666d2f3ee5e63c45c911f4a84881fa0c33ab633.png)

既然sink点没有问题，那没有扫出来就说明是路径的问题。我们再观察漏洞触发点，会发现，从url到Requests.get()中，存在一个String.valueOf(url)方法，正常情况下程序不会觉得String.valueOf方法返回的仍然是污点。因此我们需要修改Config中的isAdditionalTaintStep方法，将java.net.URL和String.valueOf(url)绑定。为了不影响原有代码，新创建一个ql文件，写如下内容

```go

import java
import semmle.code.java.security.RequestForgeryConfig
import DataFlow::PathGraph
import semmle.code.java.dataflow.ExternalFlow

class MySinkModelCsv extends SinkModelCsv {
    override predicate row(string row) {
      row =
        [
            "org.apache.http.client.fluent;Request;false;Get;;;Argument[0];open-url",

        ]
    }
}

class TypeStringLib extends RefType {
  TypeStringLib() { this.hasQualifiedName("java.lang", "String") }
}

class StringValue extends MethodAccess {
    StringValue(){
      this.getCallee().getDeclaringType() instanceof TypeStringLib and
      this.getCallee().hasName("valueOf")
    }
}

private class MyRequestForgeryAdditionalTaintStep extends RequestForgeryAdditionalTaintStep {
    override predicate propagatesTaint(DataFlow::Node pred, DataFlow::Node succ) {
      // propagate to a URI when its host is assigned to
      exists(UriCreation c | c.getHostArg() = pred.asExpr() | succ.asExpr() = c)
      or
      // propagate to a URL when its host is assigned to
      exists(UrlConstructorCall c | c.getHostArg() = pred.asExpr() | succ.asExpr() = c)
      or 
      //处理String.valueOf(URL)
      exists(StringValue c | c.getArgument(0) = pred.asExpr() | succ.asExpr() = c)
    }
  }

class MyRequestForgeryConfiguration extends RequestForgeryConfiguration {
    MyRequestForgeryConfiguration() { this = "Server-Side Request Forgery" }

    override predicate isAdditionalTaintStep(DataFlow::Node pred, DataFlow::Node succ) {
      any(RequestForgeryAdditionalTaintStep r).propagatesTaint(pred, succ)
    }

}
from DataFlow::PathNode source, DataFlow::PathNode sink, MyRequestForgeryConfiguration conf
where conf.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Potential server-side request forgery due to $@.",
  source.getNode(), "a user-provided value"

```

关键代码

```go
//处理String.valueOf(URL)
exists(StringValue c | c.getArgument(0) = pred.asExpr() | succ.asExpr() = c)
```

此时成功检测到该漏洞

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-52183844492dc332c5c516460d1db9c224bd9964.png)

#### 漏报2

漏洞代码如下：

```go
@RequestMapping(value = "/three")
public String Three(@RequestParam(value = "url") String imageUrl) {
    try {
        URL url = new URL(imageUrl);
        OkHttpClient client = new OkHttpClient();
        com.squareup.okhttp.Request request = new com.squareup.okhttp.Request.Builder().get().url(url).build();
        Call call = client.newCall(request);
        Response response = call.execute();
        return response.toString();
    } catch (IOException var1) {
        System.out.println(var1);
        return "Hello";
    }
}
```

这种方式使用了Okhttp发起HTTP请求，okhttp是链式调用，常见的请求代码写法如下：

```go
new com.squareup.okhttp.Request.Builder().xxx.xxx.xxx.url(url).xxx.build()
```

这种请求相对更复杂，不适合使用之前的csv格式写漏洞检测规则， 因此需要自行构造规则。

漏洞的构造中我认为有两个关键的定位锚点，一个是url(url)，一个是build()，url()确定是否引入污点，build()确定sink的位置。结合这两者，进行检测ql的构造。

首先观察这种结构的语法树

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-2eb32a857ba3b11af8456fca17540cef21076c9f.png)

这种链式结构调用在语法树中是包含的关系，当获取到最外层的MethodAccess时，可以使用getAChildExpr()方法返回其子语句，使用getAChildExpr+()可以递归返回全部子语句。结合前面说到的两个关键定位锚点，进行如下代码构造

```go
MethodAccess url(MethodAccess ma,DataFlow::Node node){
    exists( MethodAccess mc | mc = ma.getAChildExpr()| if mc.getCallee().hasName("url") and mc.getArgument(0) = node.asExpr() then result = mc else result = url(mc,node)
    )
}

MethodAccess m(DataFlow::Node node){
    exists(
        MethodAccess ma | ma.getCallee().hasName("build") and ma.getCallee().getDeclaringType().hasName("Builder") |result = url(ma,node)
    )
}
```

m方法用来寻找Builder.build()方法，找到之后，调用第一个url方法，并将污点node和找到的MethodAccess作为参数传递进函数。url方法对传入的MethodAccess调用getAChildExpr进行递归检查，查找是否存在url方法的调用，并且污点node是url方法的参数。写好这两个方法后，重写五点分析Configuration中的isSink方法， 在原有的基础上增加对这个m方法的检查，完整代码如下：

```go
class MyRequestForgeryConfiguration extends RequestForgeryConfiguration {
    MyRequestForgeryConfiguration() { this = "Server-Side Request Forgery" }

    override predicate isSink(DataFlow::Node sink) { 
        sink instanceof RequestForgerySink or  
        //sink = URL对象
        exists (m(sink))
    }

    override predicate isAdditionalTaintStep(DataFlow::Node pred, DataFlow::Node succ) {
      any(RequestForgeryAdditionalTaintStep r).propagatesTaint(pred, succ)
    }

}
```

重新执行ql，成功检测到所有种类的SSRF漏洞

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-157e405b415b69c5807270e0c68401fa17fba34f.png)