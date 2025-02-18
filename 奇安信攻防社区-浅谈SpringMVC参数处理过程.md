0x00 前言
=======

 传统的 Java Web 项目，通常会通过 HttpServletRequest 来获取请求相关的参数。

```Java
request.getParameter("param")
```

 而Spring MVC 简化了请求参数的获取方式，直接将请求参数定义为Controller方法参数即可。当Controller方法被 Spring MVC 调用时，Spring MVC 会根据请求上下文信息解析出给定类型的方法参数值，并自动进行类型转换和参数校验。

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-46528fffad09a3bead3fd884269bd0ce98d16ada.png)

 下面看看SpringMVC是如何接收并处理请求有关的参数的。

0x01 请求参数解析过程
=============

 以5.3.26版本为例，查看具体的解析过程。

 当Spring MVC接收到请求时，Servlet容器会调用DispatcherServlet的service方法（方法的实现在其父类FrameworkServlet中定义），首先会获取request请求的类型，除了PATCH方法以外都会通过HttpServlet的service方法进行处理：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-47e1df5ed14fbea07496841d89abdefbbe25fdb7.png)

 实际上根据不同的请求方法，会调用processRequest方法进行处理，例如GET请求会调用doGet方法：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-87b35b975cbb9c812d8f54f03a2983aedb2e3e78.png)

 在执行doService方法后，继而调用doDispatch方法处理，首先会对multipart请求进行处理，然后获取对应的mappedHandler，其实就是获取到url 和 Handler 映射关系，然后就可以根据请求的uri来找到对应的Controller和method，处理和响应请求：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-c96ed9717f8bfcee74d25744bd9786d392e25644.png)

 然后会获取适合处理当前请求的HandlerAdapter，并通过调用handle()方法处理请求：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-0703e29e2c67c93a0ce8741bb36368e20ca07051.png)

 实际上调用的是handleInternal方法进行处理：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-f288e9f50aa3c0bc6d0187b7ca9b8c9c22817426.png)

 首先会对请求进行检查，确保请求的有效性，然后判断是否需要在会话级别进行同步，如果需要，获取当前请求的`HttpSession`，并根据会话获取一个互斥对象，对该对象进行同步：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-5345d2a87b59637da549220396b9cc71e9a79552.png)

 否则调用invokeHandlerMethod()方法，传递HttpServletRequest、HttpServletResponse和HandlerMethod对象，执行实际的请求处理逻辑，并返回一个ModelAndView对象：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-711d3013206a05c5c7e835f732376b34f19578a3.png)

 首先创建ServletWebRequest对象，将HttpServletRequest和HttpServletResponse封装起来，以便后续处理：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-3a5da10784f4fd2252df9fd89657727609858640.png)

 根据处理器方法获取DataBinderFactory和ModelFactory，然后创建ServletInvocableHandlerMethod对象，用于执行处理器方法的调用和处理：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-8a1c1360c3d799d7de46d8eed3ee308fa6b4907c.png)

 经过一系列的初始化还有处理后会执行处理器方法并处理结果：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-6518c7d435edb8a6ff306b2eed7cc34e6fa2890a.png)

 这里会调用invokeForRequest()方法对请求进行处理：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-9fea5cec4ec4c865a6911db0c1c740c786d8aa15.png)

 在invokeForRequest方法中，会调用 `getMethodArgumentValues()` 方法获取方法的参数值。这些参数值会根据请求的特定上下文和配置进行解析：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-c9617d8108795d4ed1ac8463371c33719b151b39.png)

 首先调用 getMethodParameters() 方法获取参数列表，如果参数列表为空，表示没有参数，直接返回空数组：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-8a705b0ba934205ca750621623e6a865647293e0.png)

 然后遍历参数列表，依次处理每个参数，调用 findProvidedArgument() 方法查找是否有在 providedArgs 中提供的参数值，如果有则将其赋给 args\[i\]：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-a6d78dcdc5770760f2eb0bc83a81a092089324be.png)

 否则需要使用参数解析器进行解析，首先检查是否有合适的参数解析器支持当前参数，如果不支持则抛出异常：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-9571ba345fd5cc12b431c227b73c7c9b5f2dc5fa.png)

 这里实际调用了getArgumentResolver进行处理：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-abb763c370671e9fa45b94299c02410307b7a713.png)

 在getArgumentResolver中，首先，检查缓存中是否已经存在适用于给定参数的解析器。如果存在，则直接返回缓存中的解析器。如果缓存中不存在适用的解析器，则遍历已配置的解析器列表。对于每个解析器，它会调用supportsParameter方法来判断是否支持给定的参数类型。如果找到了支持的解析器，则将其缓存，并返回该解析器：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-a90619a3ea9c506b55612ed7fc6cb511f87f1797.png)

 得到解析器后就可以调用参数解析器的 resolveArgument() 方法解析参数的值：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-63a0aee0435b25f109b94d45373d74fcc5b6060d.png)

 首先调用 getArgumentResolver() 方法获取与方法参数类型相对应的参数解析器。 如果解析器为 null，表示不支持当前参数类型，抛出异常并指明不支持的参数类型，如果解析器存在，则调用解析器的 `resolveArgument()` 方法来解析参数的值：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-61ca16da64c51772bd6cd2adf690dece500ca2e0.png)

 以解析带有命名值注解（如 `@RequestParam`）的方法参数的方法为例，首先会获取方法参数上的命名值注解的相关信息，例如参数名称、默认值等，然后获取对应注解中定义的参数名称，并根据需要解析其中的表达式和占位符，然后通过解析后的参数名称，在请求中查找对应的参数值，如果找不到则抛出异常，因为因为参数不能为空：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-6f400cfda6a32d574d0c443d43eea51eeebdc89e.png)

 否则将解析后的参数名传递给 resolveName() 方法，从请求中获取参数值：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-e300af7133c32030bd073ee8b0632c3c8bd7e2fc.png)

 解析得到的参数值将被用作方法参数的实际值，并在后续处理中进行转换、绑定和验证。

 以上是请求参数解析的大概过程。实际上主要是通过 HandlerMethodArgumentResolver 接口解析Controller的参数。根据前面的分析，会在getArgumentResolver方法中遍历已配置的解析器列表，并找到合适的解析器，大概有28个解析器：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-79ff8b399325f88530aad4b8f80669c320f2234e.png)

0x02 解析器解析过程
============

 根据前面的分析，在getArgumentResolver中，如果缓存中不存在适用的解析器，则遍历已配置的解析器列表。对于每个解析器，它会调用supportsParameter方法来判断是否支持给定的参数类型。如果找到了支持的解析器，则将其缓存，并返回该解析器。也就是说可以**通过解析器的supportsParameter方法查看当前解析器解析的参数类型**。

 举个例子，以下是RequestParamMapMethodArgumentResolver的supportsParameter方法：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-5723c8d64c5da2f8f36d15db349d65f6bcd990c8.png)

 从supportsParameter可以看到，使用@RequestParam注解标注且为Map类型的参数均会被该解析器解析，举例说明：

```Java
@RequestParam Map param
```

 下面以最常见的`param=value`为例，查看具体的解析过程。主要是通过RequestParamMethodArgumentResolver的supportsParameter方法进行解析的：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-b2f9fba1b5d3954c7063fe4f110562cf9b171b99.png)

 从supportsParameter可以看到，满足下列条件的都可能被RequestParamMethodArgumentResolver解析：

- @RequestParam注解标注且非Map类型

 举例说明：

```Java
@RequestParam("param") String param
@RequestParam String param
```

- 未经过@RequestPart注解标注
- Multipart参数（包括Part、Part\[\]、List、List、MultipartFile\[\]等）

 举例说明：

```Java
MultipartFile file
```

- 基本类型及包装类型（包括Enum、CharSequence、Number、Date、Temporal、URI、URL、Locale、Class类型）

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-1992a03e70fe814e1c1e7c155b1dd442a8fdf419.png)

 举例说明：

```Java
String param
```

- 可选请求参数

 举例说明：

```Java
@RequestParam("password") Optional password
@RequestParam(required = false) String param
```

 然后是具体的解析逻辑，主要是在resolveName方法进行解析，首先，通过 `request.getNativeRequest(HttpServletRequest.class)` 获取到 `HttpServletRequest` 对象，以便后续处理：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-df3e7971bfa3e881fbdaec3d96fcc6b4562a034a.png)

 然后是对multipart请求的处理：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-ba6b6c5f80d2b352c85218dbe8be74b60a79e796.png)

 简单的跟进可以看到这里主要是调用对应上传解析类进行处理文件上传相关的参数：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-22c58e77acecd4a7cd735b815cb0704feb6f2342.png)

 如果不存在文件参数，则通过request.getParameterValues(name) 获取普通的请求参数值。如果存在请求参数，则返回单个参数值或参数值数组：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-3ed528734d1f39db981fc09036167487fb6f5e23.png)

 这里有个有趣的trick，HTTP参数污染漏洞（HTTP Parameter Pollution）简称HPP，由于HTTP协议允许同名参数的存在，同时，后台处理机制对同名参数的处理方式不当，造成“参数污染”。攻击者可以利用此漏洞对网站业务造成攻击，甚至结合其他漏洞，获取服务器数据或获取服务器最高权限。例如tomcat对同样名称的参数出现多次的情况会取第一个参数。

 而对于Spring来说，当处理`@RequestParam("param") String param`时，若请求`param=1&amp;param=2`时，根据前面的分析，主要会进行如下处理，首先通过request.getParameterValues(name) 获取普通的请求参数值。如果存在请求参数，则根据实际情况返回单个参数值或参数值数组：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-388d0d721303f77b0f892eefe6a35bcf386745c2.png)

 当请求`param=1&amp;param=2`时，会以数组的形式返回1,2：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-9e5addea4ead3619b5fa92e7f275f7694160f38b.png)

 利用该特性，在某种程度上可能可以绕过类似WAF这类的安全防护软件。

 举个例子：

 一般情况下，对于SQL注入的拦截思路通常包括检测和过滤可能包含恶意SQL代码的输入。其中，检测闭合的括号前后内容是一种常见的策略。

 正常情况下，sortType是用于OrderBy查询的参数，存在SQL注入的风险：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-a0cb2ea032a77bcdb34279a1e54601cf5283cae3.png)

 查询1/0时返回500，说明`division by zero`异常被触发：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-3adf527d88aa585942106ed895a0f3a670aff676.png)

 通过盲注尝试进一步利用，对应的payload：`1/(case+when+ascii(substr(user,1,1))=112+then+1+else+0+end)`，通过枚举对应用户名的ascii码触发`division by zero`异常进行利用，这里类似substr()函数基本上是会被waf/filter拦截掉的。

 根据前面的分析，因为resolveName方法返回的arg类型是Object，可以适应各种不同类型的结果。这使得方法可以在不同的上下文中使用，无需限定具体的返回类型：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-3b16c84de9a637ad5fefc275d9dbfd9b6098cea2.png)

 那么此时就可以利用RequestParamMethodArgumentResolver的解析方式通过`,`对payload进行拆分。

 当枚举当前数据库用户的第一位字符ascii为111时，返回0，触发`division by zero`异常：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-2fe810dbacd8383c66b44ac60e764181e63ded66.png)

 当枚举当前数据库用户的第一位字符ascii为112时，正常返回，说明当前数据库用户的第一位字符为p:

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-8a9f48b729fc79d91cfb6181a342a1b8636c31a8.png)

 整个过程对substr()进行了一定的拆分，在某些情况下利用该思路可能可以绕过一些安全防护。

 除此之外，还有还多不同类型的解析器，例如PathVariableMethodArgumentResolver和PathVariableMapMethodArgumentResolver用于解析@PathVariable注解，RequestPartMethodArgumentResolver用于解析@RequestPart注解等等。就不一一赘述了。