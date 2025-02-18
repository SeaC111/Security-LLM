0x00 关于Apache CXF
=================

 Apache CXF 是 Apache 软件基金会下的一个开源项目，用于构建 Web Services 的应用程序。CXF 支持多种标准 Web Services 规范，如 JAX-RS 和 JAX-WS，并提供了基于这些规范的高效实现。

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-401719a160335ae18f11e58304c7a6b58347d3da.png)

 而cxf-spring-boot-starter-jaxrs 是 CXF 在 Spring Boot 中支持 JAX-RS 的 starter 包。它为您提供了构建 RESTful 服务所需的依赖和配置，并且与 Spring Boot 自动配置相集成，使得开发者可以更轻松地创建和部署 CXF JAX-RS 服务。

0x01 JAX-RS服务请求解析过程
===================

 以cxf-spring-boot-starter-jaxrs-3.4.1为例，查看CXF构建的JAX-RS服务具体请求解析过程：

 在处理HTTP请求期间，CXF会依次调用一系列消息拦截器，这些拦截器可以对请求或响应进行各种操作，例如添加、修改或删除头部信息、转换消息格式等。

1.1 解析过程
--------

 `org.apache.cxf.jaxrs.interceptor.JAXRSInInterceptor`是Apache CXF框架中的一个拦截器，它用于在JAX-RS服务请求之前拦截HTTP请求，并将其转换为CXF消息对象。其核心方法为`processRequest()`。查看具体的实现：

 首先会获取请求预处理器RequestPreprocessor，对请求进行预处理，这里会对message中的一些属性key进行赋值处理：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-14bafdc7559852ed837cbf251e9e6e25cfcfa41d.png)

 然后获取类似请求方法、请求真实路径等信息：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-7e43c7cc3010ff3072ef0891fe3f483a1997bed0.png)

 获取完相应的信息以后，会进行资源的匹配。在Apache CXF中，`JAXRSUtils`是一个重要的工具类，它主要用于处理与JAX-RS相关的功能。根据请求path定位和调用相应的资源类或方法可以简单的分为这三个过程：

- 首先根据message调用`JAXRSUtils.getRootResources`获取所有的RootResources
- 然后根据原始路径rawPath调用`JAXRSUtils.selectResourceClass`选择RootResources中特定资源
- 定位到特定资源后再调用`JAXRSUtils.findTargetMethod()`获取对应的资源方法

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-b89915a16dd86e68e93a158eb31dcef9bc558621.png)

 如果matchedResources为null，会设置对应的response内容，并设置404状态码，抛出toNotFoundException异常，说明没有找到对应的资源类：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-cfcad62dde7a379a89d03949daf8b1e811e2ef3d.png)

 否则会调用调用`JAXRSUtils.findTargetMethod()`获取对应的资源方法。

 其中会对存储了已匹配资源及其对应值的映射matchedResources遍历`matchedResources.entrySet()`中的每个实体，提取出`ClassResourceInfo`对象（资源）和与之关联的`MultivaluedMap`（值）：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-e493d78ded24252a2220462c43944459d4e4acbd.png)

 然后会遍历`resource.getMethodDispatcher().getOperationResourceInfos()`（资源相关的所有方法信息），首先会提取出当前的`URITemplate`，并与当前方法的路径进行匹配：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-18a32e145a4a57fa5a7ea95ef7adb49534df538a.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-f3ce8ee6643bb9f4c2d3b314608a8adfa1a86c4d.png)

 这里看一下`uriTemplate.match()`的具体实现，同样的，对于每个路由规则，会判断请求路径是否与该规则匹配。主要是调用java.util.regex.Pattern#matcher方法进行匹配的：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-d8ed0848ac6f4421bbb55f754232a23b33e4d7ac.png)

 如果第一次匹配失败的话，会判断是否是因为`;`影响，通过获取PathSegment进行重组后进行二次匹配：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-009f62f85197ae39e0ceb606911f29887540d1c6.png)

 可以看到Apache CXF会对请求Path中的`;`进行处理：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-bb03bcdc000f018fc1bc6bc21a452fe3b254c4a9.png)

 如果不为null并且成功匹配，会获取`FINAL_MATCH_GROUP`的值，并根据该值确定是否为最终路径（`finalPath`）。如果当前方法是子资源定位器（SubResourceLocator），将其添加到candidateList（候选列表）中。 如果是最终路径，将其添加到finalPathSubresources（一个存储了子资源定位器的链表）中。如果已匹配到最终路径，会进一步检查HTTP方法、请求类型和接受的内容类型等条件。最终会根据匹配的结果返回设置不同的状态码，然后在response返回对应的响应结果：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-a73b4a1fafda9d5a0a9c156760aa8ff0b4e4cd56.png)

1.2 关键属性
--------

 在整个解析过程中，存在一些关键属性，看看具体是怎么生成&amp;处理的。

1.2.1 org.apache.cxf.transport.endpoint.address
-----------------------------------------------

 前面分析中会获取Endpoint Address（用于标识该端点提供的Web服务）。

 `getEndpointAddress`方法首先获取当前消息对象所对应的目标对象（Destination），然后判断目标对象是否是AbstractHTTPDestination类型。如果是，则表示当前消息对象与HTTP传输相关，需要根据当前的HTTP请求上下文信息来确定服务端点地址，这里是通过关键属性`org.apache.cxf.transport.endpoint.address`来获取的：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-c5631c03020107e2af2a74022ffcfe1005671194.png)

 看下`org.apache.cxf.transport.endpoint.address`的封装过程：

 `org.apache.cxf.transport.servlet.ServletController`是Apache CXF框架中的一个重要组件，用于处理基于Servlet容器的HTTP传输方式的请求。它是CXF的Servlet控制器，负责将HTTP请求转发到CXF框架中的适当位置进行处理。该过程主要是在invoke方法完成的。

 而这个过程中会调用`updateDestination`方法用于更新服务端点地址信息。其会根据当前的HTTP请求上下文信息，将服务端点地址与Servlet容器的基本URL进行拼接，以便确定要调用的服务实现类：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-b3896a4520897d46531058a1310f80cfcd247aa6.png)

 查看该方法的具体实现，首先从当前请求方法中获取BaseURL，然后调用`updateDestination`重载的方法：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-634e2e2e9206dc9333b5d63ce88f7a556579d392.png)

 在`updateDestination`重载的方法里可以看到这里对request请求上下文进行了一定的封装，包括关键属性`org.apache.cxf.transport.endpoint.address`，这里主要是将base以及ad合并并设置对应属性的值:

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-4f42e1f8fbec3b0674d8891a6f642aca1d7cdce4.png)

 查看base以及ad的解析逻辑，首先是base，是调用org.apache.cxf.transport.servlet.ServletController#getBaseURL方法进行处理的：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-8d7aabac62e78f6595b46017f2679a806a51b0fd.png)

 如果forcedBaseAddress不为空，返回对应的值，否则调用BaseUrlHelper.getBaseURL方法进行处理，首先通过getRequestURL方法获取reqPrefix，然后通过getPathInfo获取路径信息：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-27a2b282cdf339d5337a5204a9c70091e3992ca2.png)

 如果pathInfo不是`/`或者reqPrefix包含`;`会进行额外的处理，否则直接返回前面getRequestURL方法获取到的reqPrefix。

 首先根据reqPrefix创建URI对象，然后进行字符串的拼接（主要是获取协议以及主机名），然后调用`request.getContextPath`获取请求的Context-path，最后通过`request.getServletPath`方法获取HTTP请求的Servlet路径，此时新的reqPrefix组装完成：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-c9a10cdbaef31547980587368597b25029022fef.png)

 最后是ad的处理逻辑，主要是从EndpointInfo的address属性获取，获取不到的话会设置为`/`：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-ad2d0925c3f17923c28c5163f9e2b049b28c6b54.png)

### 1.2.2 path\_to\_match\_slash

 前面提到了Apache CXF在解析时，会结合JAXRSUtils.selectResourceClass()方法检索rawPath找到对应的资源，所以所以有必要看看rawPath具体是怎么生成的：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-778eb5f346aed47e7c57ade65e1871da34d09a33.png)

 根据对应的方法，可以看到其是从Message的`path_to_match_slash`属性获取的：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-9a39f4f2ca0ad7e00c324990fb02fc7469f0f9e8.png)

 所以实际上需要查看Message的`path_to_match_slash`属性是如何被赋值的。在processRequest方法中，会有预处理请求的过程：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-955bc330bd10474faab3be4a22d1ed91b55c3d08.png)

 在preprocess方法中，会对类似受支持的客户端类型进行处理，最终返回通过`new UriInfoImpl(m, (MultivaluedMap)null)`创建的`UriInfoImpl`对象的路径：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-0f257927c7ec57ea33715f8d530c05f578090a8d.png)

 doGetPath方法实际上调用的是`httpUtils.getPathToMatch()`：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-784bf7905b09d8ad946c6fbd934e763cc15fc398.png)

 因为此时`path_to_match_slash`对应的值为null，所以会走到如下逻辑，而不是直接返回对应的值：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-f01c9ded230158588c7017a304523d38132dd003.png)

 首先会尝试从getProtocolHeader()方法中获取请求地址。如果未找到，则默认为根路径`/`。这里实际上是直接从message的`org.apache.cxf.request.uri`键获取的：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-1157439c6d64083d2a74531c995517dcbc2d14c8.png)

 然后根据`?`处理参数部分，然后getBaseAddres()方法获取基本路径。在getBaseAddres()方法中，会先调用getEndpointAddress()方法对message进行处理：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-c31512841cd50b03910b4d5acecd5e65d9d4cba8.png)

 在getEndpointAddress()方法中，首先从message中获取目标地址的`Destination`对象。如果该对象不为空，则继续执行后面的步骤；否则，代码使用`Message.ENDPOINT_ADDRESS`键从消息上下文中获取服务端点地址，并返回该地址。

 如果`Destination`不为null且对象是`AbstractHTTPDestination`实例，则代码通过该对象获取服务端点信息`EndpointInfo`。并尝试从HTTP请求中获取属性`org.apache.cxf.transport.endpoint.address`的值，以覆盖服务端点地址。如果请求对象不为空且属性存在，则将属性值作为服务端点地址；否则，使用`EndpointInfo`中的地址作为服务端点地址：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-a25480c0256521c337825dea0646784b00f1220c.png)

 获取到endpointAddress后，会结合`java.net``.URI`对象进行处理，主要是获取协议以及真实的path，处理后如果path为null，则返回`/`,此时baseAddress处理完成，会调用getPathToMatch进行处理：

- 首先用`indexOf()`方法找到`address`在`path`中第一次出现的位置
- 若ind为-1，且address与path的末尾添加斜杠后的值一致的话，将path的末尾添加斜杠并将ind设置为0
- 若ind为0，使用`substring()`方法截取`path`字符串，从地址部分的长度开始，得到处理后的路径部分
- 最后判断`addSlash`参数的值是否为`true`，并检查处理后的路径部分是否以斜杠开头，否则在处理后的路径前追加`/`:

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-841500592f093fdc7acc85f1de2c49833bacea1f.png)

 处理完后将pathToMatch的值赋予给message中的path\_to\_match\_slash键对应的值。综上，path\_to\_match\_slash键值与request请求中org.apache.cxf.transport.endpoint.address的值有很大的关系。

1.3 关于目录穿越符
-----------

 在cxf-spring-boot-starter-jaxrs中，会引入spring-boot-starter-web依赖，从而引入spring-boot-starter-tomcat，也就是说默认是使用tomcat作为中间件进行解析的。

 跟Jersey类似，**Apache CXF正常情况下也是不会对路径穿越符../进行额外的处理的**。

 例如如下的Resource Class:

```Java
@GET
@Path("/manage")
public Response manage() {
    return Response.ok().entity("admin page").build();
}
```

 尝试以`/admin/info/../manage`访问会返回404，找不到对应的资源：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-b27515a636b4ff6133c5e213baab2bc1477b97dd.png)

 当使用默认的tomcat中间件进行解析时，假设当前Resource Class如下：

 定义的路由`@Path("/{path : .*}")`中的正则为`.*`,表示匹配任意字符。

```Java
@GET
@Path("/{path : .*}")
public Response getUser(@PathParam("path") String path) throws IOException {
    return Response.ok().entity(path).build();
}
```

 正常情况下应该跟Jersey一样，访问`/..`也是能匹配到该资源的，但是实际上访问会返回404:

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-a3531d6b7c93d77fc5c4957c2ecc78604459e05e.png)

 看下具体的原因，根据前面的分析，Apache CXF在解析时，会结合JAXRSUtils.selectResourceClass()方法检索rawPath找到对应的资源。主要跟`path_to_match_slash`和`org.apache.cxf.transport.endpoint.address`这两个属性有关。看看当请求`/admin/..`时具体的属性是如何赋值的。

 首先是`org.apache.cxf.transport.endpoint.address`，其值是由base跟ad组成的，首先是base，其是在getBaseURL方法处理的：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-bbf3626d4a7cc60647cc54a3ad0870f366773d3c.png)

 因为通过request.getPathInfo()获取pathInfo时是会对请求的path进行规范化处理的，所以`/admin/..`会变成`/`，那么此时不会重组reqPrefix，直接返回原始的内容：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-8715cce6bc3cccbc239c157a91e69773d4d21241.png)

 加上ad的值为`/`，此时request上下文中`org.apache.cxf.transport.endpoint.address`对应的值为`http://127.0.0.1:8080/admin/../`

 然后是`path_to_match_slash`,会在第一次调用`httpUtils.getPathToMatch()`时进行设置。

 首先从从message的`org.apache.cxf.request.uri`键获取requestAddress为`/admin/..`：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-2342d9895dd35454f397fee4076640ec621fba7d.png)

 然后获取baseAddress，根据前面的分析，这里会从`org.apache.cxf.transport.endpoint.address`键中获取对应的值，然后进行额外的处理，处理后返回内容为`/admin/../`：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-6c029ced868ec2cc306372694ac63b08cad04b1c.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-76a576b19307570f9a365e7772b36f98bfd580b6.png)

 此时会调用getPathToMatch进行二次处理，因为requestAddress结尾追加`/`后与baseAddress相等，当ind=0时经过切割后，返回的值为`/`：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-8b5b6b11e5fe9422a0042bbce27eb2637b3eab16.png)

 所以当Apache CXF在尝试获取rawPath时，得到的是`/`:

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-ce96a168fbc409cde23d7efb567c903b2995e5d3.png)

 此时在查找对应的ResourceClass时会返回null从而无法继续匹配资源，最终返回404。

 那么是不是说当前场景下类似`@Path("/{path : .*}")`就没办法获取到`/..`呢？问题主要在`org.apache.cxf.transport.endpoint.address`里，request.getPathInfo()获取pathInfo时是会对请求的path进行规范化处理的，所以`/admin/..`会变成`/`，那么此时不会重组reqPrefix，直接返回原始的内容：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-9771e3b21537425dec428c2b79e7efe588d24efd.png)

 同样是上面的解析过程，当请求`/admin/info/..`时，此时pathInfo经过规范化处理后为`/admin/`，此时会对preqPrefix进行重组：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-e49a899070ad50b20fe9cd3808b38d0aac65018c.png)

 加上ad的值为`/`，此时request上下文中`org.apache.cxf.transport.endpoint.address`对应的值为`http://127.0.0.1:8080/`。

 既然这里存在差异，当在getPathToMatch方法处理时，baseAddress为`/`,requestAddress为`/admin/info/..`:

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-4791b907ef4076734de29e2c7dff449544dd3112.png)

 经过处理后，最后返回的值为`/admin/info/..`，也就是说rawPath的值也是一致的，那么此时查询ResourceClass是可以匹配到对应的资源的，所以可以成功访问资源：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-ff8b05b1909e888394821ff980ee08b9acf2de2e.png)

0x02 潜在的风险
==========

 通过上面对Apache cxf请求解析过程的分析，结合现有的一些漏洞场景，列举下其中潜在的安全风险。

2.1 权限绕过
--------

### 2.1.1 获取请求Path未规范化处理

 `ContainerRequestContext`表示当前请求的上下文信息，包括请求头、URI、HTTP 方法、实体等信息。一般情况下会结合`ContainerRequestFilter`进行使用。同样的Apache CXF也支持对应的实现。

 在基于`ContainerRequestFilter`实现的权限Filter中，某些时候可能会有基于URI白名单的方式对特定的请求进行放行。跟Servlet中的request.getRequestURI()方法一样，当获取请求Path的方法不规范时，可能会存在绕过权限Filter的风险。

 看看获取请求Path的方法主要有哪些，效果是什么。

 `javax.ws.rs.core.UriInfo`提供了有关当前请求URI的各种信息。可以通过ContainerRequestContext的getUriInfo方法进行获取：

```Java
UriInfo uriInfo = requestContext.getUriInfo();
```

 获取到UriInfo后，可以调用其方法来获取请求Path信息。

 以请求http://127.0.0.1:8080/api/manage;bypass/ 为例，查看各个方法的返回值：

| 方法名 | 功能 | 返回值 |
|---|---|---|
| getAbsolutePath() | 获取请求的绝对路径 | <http://localhost:8080/admin/manage;bypass/> |
| getPath() | 获取请求的路径部分 | api/manage;bypass/ |
| getRequestUri() | 返回一个URI对象，表示客户端发出请求的完整请求URI | <http://localhost:8080/admin/manage;bypass/> |
| getPathSegments() | 返回一个List对象，其中包含路径中每个段的字符串值 | \[admin, manage;bypass, \] |

 可以看到获取到的返回值均未进行标准化处理。如果只是简单的使用startwith或者contiain方法进行白名单/黑名单的鉴权处理的话，在某种情况下是存在绕过的可能的。

 除了UriInfo以外，使用`requestContext.getUriInfo().getRequestUri()`方法来获取访问请求的URI后，可以调用相应方法来获取各种URI组件的信息，包括请求的path，同样以以请求http://127.0.0.1:8080/api/manage;bypass/为例，查看各个方法的返回值，同样的均未进行标准化处理：

| 方法名 | 功能 | 返回值 |
|---|---|---|
| getPath() | 返回请求URI的路径部分，并解析任何转义字符（如URL编码的斜杠） | /api/manage;bypass/ |
| getRawPath() | 返回请求URI的路径部分，但不进行解码或规范化 | /api/manage;bypass/ |

 其次，`requestContext.getUriInfo().getRequestUri().compareTo()`方法用于比较两个URI，这个方法返回一个整数值，表示两个URI的排序顺序。如果两个URI相等，则返回0；如果第一个URI小于第二个URI，则返回负数；否则，返回正数。但是该方法比较`http://127.0.0.1:8080/api/manage;bypass/`和`http://localhost:8080/admin/manage;bypass/`同样会认为不是一个URI。

### 2.1.2 以`/`结尾的Bypass

 例如如下的例子，正常来说访问`/manage`会匹配到manage方法然后进行相应的处理：

```Java
@GET
@Path("/manage")
public Response manage() {
    return Response.ok().entity("admin page").build();
}
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-94e90dfe6b9722b39bd05583d24cc5dcc572580a.png)

 根据前面的分析，Apache CXF主要的路径匹配是在org.apache.cxf.jaxrs.model.URITemplate#match方法进行处理的，对于每个路由规则，会判断请求路径是否与该规则匹配。主要是调用java.util.regex.Pattern#matcher方法进行匹配的：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-14315b80c90540a5887044fe3ec4028be8807523.png)

 其中请求的path是可以以`/`结尾的：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-cb36a348998dc13a29159b5e52cb894e97380b65.png)

 同样的，跟Spring/Jersey类似，Apache CXF在解析时如果请求路径有尾部斜杠也能成功匹配（类似Spring里TrailingSlashMatch的作用）:

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-8aa0b2f69740a6200868cb50f5ff967573e21fcf.png)

 那么在使用filter或者某些权限控制框架进行鉴权处理的的时候需要额外注意，避免绕过的风险。

### 2.1.3 解析差异绕过

 以shiro为例，对应的权限控制如下，`/admin`目录下的所有接口都需要经过安全认证才能访问：

```Java
@Bean
ShiroFilterFactoryBean shiroFilterFactoryBean(){
    ShiroFilterFactoryBean bean = new ShiroFilterFactoryBean();
    bean.setSecurityManager(securityManager());
    bean.setLoginUrl("/login");
    bean.setSuccessUrl("/index");
    bean.setUnauthorizedUrl("/unauthorizedurl");
    Map map = new LinkedHashMap&lt;&gt;();
    map.put("/doLogin/", "anon");
    map.put("/admin/**", "authc");
    bean.setFilterChainDefinitionMap(map);
    return  bean;
}
```

 假设对应的请求资源如下：

```Java
@GET
@Path("/{path : .*}")
public Response getUser(@PathParam("path") @Encoded String path) throws IOException {
    return Response.ok().entity(path).build();
}
```

 正常情况下，在缺少安全认证的情况下访问/admin/page，会返回302状态码重定向到login页面：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-8e83dd2ef2f4acbe817a8786d62d7262b2ee441e.png)

 利用shiro会解析`..`而Apache CXF不会的差异，因为可以这里路由匹配的正则表达式为`.*`表示匹配任意字符，那么理论上请求`/admin/..`即可绕过对应的限制。

 可以看到绕过了shiro的权限控制，但是没办法访问相应的资源：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-a2dcd3e1b364949d11d5d295edce4387cb23787b.png)

 根据前面的分析主要是处理`org.apache.cxf.transport.endpoint.address`时，request.getPathInfo()进行了规范化处理。实际上只需以`/admin/../info`访问即可绕过并访问对应的资源了：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-9cf6debbd0e95ea6a144b3e1f979e3f026a74a37.png)

2.2 任意文件下载
----------

 在Apache CXF中，同样可以通过在 `@Path` 注解中使用 `{variable:regexp}` 的形式，来指定请求路径中的变量名和对应的正则表达式，例如如下的例子：

 通过`@PathParam` 注解从请求路径中提取和获取指定的参数值，并将其作为方法的参数path进行传递：

```Java
@GET
@Path("/download/{path : .*}")
public Response fileDownload(@PathParam("path") @Encoded String path) throws IOException {
    File file = new File(resource + path);
    FileInputStream fileInputStream = new FileInputStream(file);
    InputStream fis = new BufferedInputStream(fileInputStream);
    byte[] buffer = new byte[fis.available()];
    fis.read(buffer);
    fis.close();
    return Response.ok().entity(buffer).build();
}
```

 因为前面定义的路由`@Path("/{path : .*}")`中的正则为`.*`,表示匹配任意字符。因为Jersey不会对`../`进行额外的处理，所以是否能获取用户输入的多个路径穿越符`../`主要还是受中间件的影响。

 因为在Tomcat的场景下（cxf-spring-boot-starter-jaxrs默认是使用Tomcat进行处理的），此时漏洞利用需要考虑请求URI的目录层级以及`/../`个数限制的关系。

 这里以jetty为例，具体解析过程可以参考之前的分析：

 只需要以`..//..`的形式进行访问即可达到利用的效果：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-455b6dd73136bc22194be4ea019fc36ec8edc9f9.png)

 同理，对于非正则的情况，Jersey默认是会对url编码进行解码的（使用`@Encoded`注解可以防止Jersey对URI进行解码），也就是说可以以`%2f`的方式获取到路径穿越需要的元素，剩下的就是中间件解析的问题了，例如tomcat默认会对%2f进行拦截，这样请求是不可行的：

```Java
@GET
@Path("/download/{path}")
public Response fileDownload(@PathParam("path")String path) throws IOException {
    File file = new File("/tmp" + path);
    FileInputStream fileInputStream = new FileInputStream(file);
    InputStream fis = new BufferedInputStream(fileInputStream);
    byte[] buffer = new byte[fis.available()];
    fis.read(buffer);
    fis.close();
    return Response.ok().entity(buffer).build();
}
```

 同样的如果是Jetty环境下，只需要将`/`url编码,然后以`..//..`的形式进行访问即可：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-01d410b62ff84118f6817707552926989be0978b.png)

2.3 线程安全问题
----------

 Apache CXF并不直接提供 Controller 的概念。通常情况下，Apache CXF中的资源类（Resource Class）可以看做是类似于 Spring 中的 Controller 的实现方式。

 默认情况下，资源类也是单例的（Singleton）。也就是说，在应用程序初始化时，Apache CXF会创建每个资源类的一个实例，并由框架维护其生命周期，以供后续请求使用。而在单例模式中，由于多个线程共享同一个对象实例，因此存在线程安全问题。

 下面证明Apache CXF 的Resource Class是单例的：

 1.首先创建一个简单的 Resource Class：

```Java
@Path("/admin")
public class ApiController {

    private int count = 0;

    @GET
    @Path("/count")
    public Response getCount() {
        count++;
        return Response.ok().entity("count:"+count).build();
    }
}
```

 2.启动应用程序，并使用浏览器或其他客户端工具访问该接口`http://127.0.0.1:8080/api/admin/count`：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-2659e13dbb9a77ff8a2edb168379af99c235bb46.png)

 3.多次访问该接口，并观察返回结果：

```Plain
count=1
count=2
count=3
...
```

 从输出结果可以看出，在多次访问同一个接口时，每次都会增加 count 的值，说明不同的请求实际上都在使用同一个 Resource Class 实例。