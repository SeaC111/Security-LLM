0x00 前言
=======

 SpringMVC的参数解析器，也就是`HandlerMethodArgumentResolver`接口，是SpringMVC框架中用于将HTTP请求中的数据解析并绑定到控制器方法参数的关键组件。其提供了多种内置的`HandlerMethodArgumentResolver`实现，用于处理不同类型的请求参数。

 常见的例如`PathVariableMethodArgumentResolver`：用于解析`@PathVariable`注解的参数。

 具体的分析可见https://forum.butian.net/share/2372 。

0x01 常见解析器及解析场景
===============

 由于每个解析器的解析逻辑都不一致，在某种程度上可能可以绕过类似WAF这类的安全防护软件。尤其是前面提到的HPP参数污染的例子，下面简单看看常见的解析器以及对应的解析场景。

1.1 RequestParamMethodArgumentResolver
--------------------------------------

 在org.springframework.web.method.annotation.RequestParamMethodArgumentResolver#supportsParameter方法可以看到具体支持的参数类型：

- 如果有 `@RequestParam` 注解的话，分两种情况
    
    
    - 参数类型如果是 Map，则 `@RequestParam` 注解必须配置 name 属性，否则不支持；
    - 若参数类型不是 Map，则直接返回 true。
- 参数如果含有 `@RequestPart` 注解，则不支持。
- 检查下是不是文件上传请求，是的话返回 true 。

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/07/attach-5846f30276d4dcd407d1988fc6f6db807b60d786.png)

 最后若上面的条件均不满足，则使用默认的解决方案，判断是不是简单类型。

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/07/attach-6b5ba55ede6eeb482788ba4901b88baf95179171.png)

 在 resolveName 方法中会解析出参数的具体值，对于非multipart请求，会调用WebRequest#getParameterValues方法获取对应的内容，如果对应的内容列表长度为1，则返回paramValues\[0\]，否则返回对应的参数值数组paramValues:

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/07/attach-99c788ed3ebc0e746def53101da43b5b62010b5d.png)

1.2 RequestParamMapMethodArgumentResolver
-----------------------------------------

 org.springframework.web.method.annotation.RequestParamMapMethodArgumentResolver#supportsParameter方法中可以看到：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/07/attach-13e74b3de53f9cdf3a8ad25791b041597d3471d8.png)

 主要是解析 `@RequestParam` 注解的参数类型是 Map，且该注解没有有 name 值的情况，类似这类的场景

```Java
@RequestMapping(value = "/demo",method = RequestMethod.POST)
public String demo(@RequestParam Map<String, String> allRequestParams){
   ......
}
```

 在 resolveName 方法中会解析出参数的具体值，对于非multipart请求，会调用WebRequest#getParameterMap方法获取对应的内容，在封装对应的结果时，默认会取values第一个值：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/07/attach-8a11519725bac4bbb153b8307384519368f635d0.png)

1.3 ServletRequestMethodArgumentResolver
----------------------------------------

 主要是用于处理 WebRequest、ServletRequest、MultipartRequest、HttpSession、Principal、InputStream、Reader、HttpMethod等类型的参数：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/07/attach-1ffea33f0ad7002f96b997018c4308ad0003aa80.png)

1.4 ModelAttributeMethodProcessor
---------------------------------

 主要是处理使用了 `@ModelAttribute` 注解以及非简单类型的参数：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/07/attach-bf4da21394ec9f733f19eb2e86b6aac954c5dd9a.png)

 org.springframework.web.util.WebUtils#getParametersStartingWith方法进行相关参数内容的封装，同样的通过ServletRequest#getParameterValues方法对应参数的值，如果length&gt;1则获取对应的参数值数组所有内容，否则设置对应的值为values\[0\]：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/07/attach-9bad765654183a3d2a2e3db3f68915e58ef5ba1c.png)

1.5 其他
------

 除此以外，还有很多其他的解析器，例如用于解析path路径参数、JSON解析的，就不一一列举了：

- **PathVariableMethodArgumentResolver**
- **PathVariableMapMethodArgumentResolver**
- **RequestPartMethodArgumentResolver**
- **RequestHeaderMapMethodArgumentResolver**
- **RequestResponseBodyMethodProcessor**
- ......

0x02 HandlerMethodArgumentResolver自定义解析器
========================================

 在 Spring MVC 的控制器（Controller）中，方法参数通常由 Spring 容器自动解析。然而，在某些情况下，开发者可能需要自定义解析逻辑，以满足特定的需求。例如在参数注入之前，可能需要进行安全性检查或验证。最常见的例如

获取当前登陆人的基本信息进行对应的权限封装。再比如需要调整（兼容）数据结构。

 自定义解析器主要通过实现HandlerMethodArgumentResolver接口，将方法参数解析为来自给定请求的参数值：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/07/attach-24ec3993b235cf03c26b052cf8a654b3fc85bfef.png)

 主要涉及如下两个函数：

- **supportsParameter用于判断是否支持给定的方法参数**

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/07/attach-63795eb48153561ad8efce404bbfecb39a0c0e02.png)

- **resolveArgument用于将方法参数解析为来自给定请求的参数值**

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/07/attach-fbbb7161a97f670823b67c3e7e20c42a582d90f3.png)

 最后在配置中加入相应的resolver的配置即可，以Springboot为例：

```Java
@Configuration
public class WebMvcConfig extends WebMvcConfigurerAdapter {
    @Autowired
    private LoginUserHandlerMethodArgumentResolver loginUserHandlerMethodArgumentResolver;

    @Override
    public void addArgumentResolvers(List<HandlerMethodArgumentResolver> argumentResolvers) {
        argumentResolvers.add(loginUserHandlerMethodArgumentResolver);
    }
}
```

0x03 常见风险
=========

 在实际代码审计时，自定义的参数解析逻辑很容易因为解析差异的问题，导致类似HPP的问题。

 HTTP参数污染漏洞（HTTP Parameter Pollution）简称HPP，由于HTTP协议允许同名参数的存在，同时，后台处理机制对同名参数的处理方式不当，造成“参数污染”。攻击者可以利用此漏洞对网站业务造成攻击，甚至结合其他漏洞，获取服务器数据或获取服务器最高权限。例如tomcat对同样名称的参数出现多次的情况会取第一个参数。

 下面是一个具体的例子：

 对于特定注解的情况，在resolveArgument方法中，会通过webRequest来获取当前请求的所有参数内容，如果是sort或者order参数，则进行SQL注入检查，如果不是特定内容输入的话，则抛出对应的异常，否则完成参数对应的封装：

```Java
@Override
public Object resolveArgument(MethodParameter parameter, ModelAndViewContainer mavContainer, NativeWebRequest webRequest, WebDataBinderFactory binderFactory) throws Exception {
    Object obj = BeanUtils.instantiate(parameter.getParameterType());
    BeanWrapper wrapper = PropertyAccessorFactory.forBeanPropertyAccess(obj);
    Iterator<String> paramNames = webRequest.getParameterNames();
    while (paramNames.hasNext()) {
        String paramName = paramNames.next();
        Object o = webRequest.getParameter(paramName);
        if ("sort".equalsIgnoreCase(paramName) || "order".equalsIgnoreCase(paramName)) {
            if (o != null && !o.toString().matches("^[a-zA-Z0-9_-]*$")) {
                throw new Exception(
                        "Invalid value for parameter '" + paramName + "': " + o,
                        new IllegalArgumentException("Potential SQL injection detected.")
                );
            }
        }
        try {
            wrapper.setPropertyValue(paramName, o);
        } catch (BeansException e) {

        }
    }
    return obj;
}
```

 参数值的获取是通过`Object o = webRequest.getParameter(paramName);`进行处理的，这里会从paramHashValues获取对应参数名的内容，如果对应的values长度不为null，则取得第一个值：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/07/attach-784e891cc23e23fc941e408d72e3184115ac6a1a.png)

 而tomcat在进行参数解析时，是通过addParameter方法进行处理的，这里对于类似param=1&amp;param=2的情况，会通过ArrayList来管理对应的值，最终会以\[1,2\]的形式进行处理：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/07/attach-285c6e86744b3f0133822e708791032ab997c3cd.png)

 也就是说，类似param=1&amp;param=2，在上面自定义的resolver最终会获取到param=1的内容。这跟RequestParamMethodArgumentResolver还有ModelAttributeMethodProcessor最终以\[1,2\]形式处理是不同的。

 拦截器Interceptor一般会用于一些通用的权限校验处理。在实际场景中，经常会通过拦截器获取当前用户请求参数值，然后进行对应的权限校验。例如下面的例子：

```Java
@Override
public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
    //.....
    Map<String, Object> paramMap = Maps.newHashMap();
    if ("GET".equalsIgnoreCase(request.getMethod())) {
         String param = request.getQueryString();
         if (StringUtils.isNotBlank(param)) {
             String[] strs = param.split("&");
             for(String str:strs){
                 if (s.split("=").length == 2) {
                    String key = s.split("=")[0];
                    String value = s.split("=")[1];
                    paramMap.put(key,value);
                 }
             }
         }
    }
    //.....
    //对获取到的paramMap进行二次处理，检查关键参数的权限是否合理
    //......
}
```

 主要的逻辑是通过&amp;以及=进行切割，获取对应的参数内容封装到HashMap中，然后对特定的参数进行权限校验。因为`HashMap` 不允许有两个相同的键。如果尝试将具有相同键的值添加到 `HashMap` 中，那么新值将会替换掉原有键对应的旧值。对于类似param=1&amp;param=2的情况，这里实际封装的是param=2。

 因为intercepotr的执行逻辑要在参数Resolver解析之前，那么对于上述场景，会存在解析差异的问题。只需要利用HPP，即可达到绕过对应的权限校验，造成对应的业务风险。类似RequestParamMapMethodArgumentResolver也会有类似的问题，在实际代码审计过程中可以额外关注。

 除此以外，自定义参数解析器具还可能会做一些归一化的处理，例如驼峰法和\_的转换等（类似https://github.com/LoverITer/easyboot-cli/blob/7500cd98f35a5b85df7fe847d2cb01a748630985/easyboot-web/src/main/java/top/easyboot/titan/config/UnderlineToCamelArgumentResolver.java#L63 ）。在特定场景中可能同样可以绕过对应的安全检查，在审计时可以额外关注。