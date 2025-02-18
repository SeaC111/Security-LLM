这两天社区里有一位师傅分享了他对JiraCVE-2020-36239的[分析](https://forum.butian.net/share/653)，内容写的很详细。于是我跟着他的教程进行了复现，在对RMI进行探测时，师傅说使用了RmiTaste进行检测，没有收到结果。同时我在另一篇分析CVE-2020-36239的文章中看到作者说他用RmiTaste检测时遇到了些问题，简单的patch后，RmiTaste变得可以使用，并且利用RmiTaste完成了后续的攻击。因此我对这个工具的使用产生了兴趣，因此搭建了一个Jira的环境，并进行了复现，中间产生了一些意料之外的问题，比较有意思，因此写下此文记录一下学到的知识，以及遇到的和解决的问题。

### 源码分析

RmiTaste可以帮助广大安全研究专家通过调用ysoserial实用工具所提供的远程方法来检测、枚举、交互和攻击RMI服务。除此之外，它还允许我们使用特定的参数来调用远程方法。

运行RmiTaste，可以看到它存在四种指令

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-2c6581ffadfe48db74938e83fdeb81ba8879aa38.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-2c6581ffadfe48db74938e83fdeb81ba8879aa38.png)

1. 连接。检测到目标服务是否联通
2. 枚举。枚举目标主机中的服务
3. 攻击。使用ysoserial中的序列化链攻击目标主机
4. 调用。调用远程目标服务上的特殊方法。

它的四种指令，在代码里对应的是Commands四个类。它们都继承自BasicCommand

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-0e6b916cce507c269d568c2eb7743780fc9d6974.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-0e6b916cce507c269d568c2eb7743780fc9d6974.png)

这里顺带说一下RmiTaste的目录结构。

- helpers目录主要是一些IO读写类、命令行参数解析类
    
    [![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-82108d782b24c1ddc7518d1a33a9953c8b6ba7dd.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-82108d782b24c1ddc7518d1a33a9953c8b6ba7dd.png)
- rmitaste目录是主要的代码，下面包含三个目录以及一个入口文件
    
    
    - commands  
        四种命令的实现类
    - rmi  
        和远程主机交互时的连接、处理类
    - utils  
        日志相关的工具类

在命令行输入命令，以及其需要的参数，就会调用相应命令类的call函数

1.ConnectionCommand执行的命令是

```Java
Enumerate.connect(this.target, this.port);

```

这里的Enumerate是这个工具处理远程操作的一个总的处理类，它的connect方法，本质上调用的是

```Java
Registry reg = LocateRegistry.getRegistry(host, port);
```

2.EnumerateCommand是最主要的一个类，它和后面的两个命令类都会调用如下的命令

```Java
Enumerate enumerate = new Enumerate(this.target, this.port);
enumerate.enumerate();
RmiRegistry rmiRegistry = enumerate.getRegistry();
```

其中最主要的就是enumerate.enumerate();，这个函数负责连接目标、获取对象名称和相应的类以及绑定。

```Java
public void enumerate() throws Throwable{
    // Connect
    this.registry = Enumerate.connect(this.registry);
    // Get object names and corresponding classes
    this.registry.loadObjects();
    // Get references to objects
    this.registry.loadObjectRef();
}

```

第一步connect会生成一个和远程建立了连接的Registry对象，重点是第二步的loadObjects()，它首先会调用registry的list方法，获取目标主机的RMI服务名列表。接着遍历服务名调用lookup方法，这里的lookup方法，不再是RegistryImpl\_Stub原生的lookup方法，最主要的区别是，原生的lookup方法，在向目标主机发送了我们期望的服务名后，会直接调用readObject方法，序列化远程主机传过来的对象。但是这样做的前提是我们的classpath中存在目标主机传回来的对象的class文件，否则就会报错。

举个例子

```Java
public static void main(String[] args) throws Exception {
    String host = "127.0.0.1";
    int port =40001;
    Registry registry = LocateRegistry.getRegistry(host, port);
    for (String name :registry.list()){
        System.out.println(name);
    }
   Remote r=  registry.lookup(registry.list()[0]);

}
```

使用如上代码去请求jira的远程服务，可以看到在lookup时出错了

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-7eb51b0614be26eb471beec9e71df9530d0fe212.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-7eb51b0614be26eb471beec9e71df9530d0fe212.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-5272f139b9519fbab9854374bdc6f348c4324481.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-5272f139b9519fbab9854374bdc6f348c4324481.png)

根本原因在于，原生反序列化中会调用Class.forName去获取类，并生成对象。RmiTaste的处理方法是首先通过反射获取输入流里的byte流，然后使用RmiObjectParser去解析并生成对象。RmiObjectParser的解析流程和ObjectInputStream中的解析流程保持一致，但是避免使用class.forName等需要目标类在classpath中的操作，而是将class名作为一个RmiObjectClass对象的属性进行保存，并把所有获取到的类保存到RmiObject对象的classes属性中

```Java
public RmiObject(String nameL){
    name = nameL;
    classes = new HashMap<String, RmiObjectClass>();
    isJMX = false;
    isDynamicStub = true;
}

public RmiObjectClass(String nameL, boolean isInterface){
    name = nameL;
    methods = new HashMap<String, RmiObjectMethod>();
    reference = null;
    simpleClassLoader = new SimpleClassLoader();
    this.isInterface = isInterface;
    this.isRemote = false;
}
```

RmiTaste用这样的方式代替了原生的readObject。

接着是第三步loadObjectRef();这里主要是遍历获取到的RmiObject列表，执行真正的RegistryImpl\_Stub.lookup方法，以获取远程对象。

至此，和远程服务的交互结束，接下来就是收集到信息的展示。在处理完远程流之后，就会调用RmiObject的toString方法对服务名和类、方法等进行输出，如果在前面第三步中成功获取到了远程对象，那么此处就会打印Method信息，否则，只会打印服务名和绑定的类名

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-8f61b8151be40e3f383e04c18785a7cd56f7db6d.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-8f61b8151be40e3f383e04c18785a7cd56f7db6d.png)

如果想要读到完整信息，还是需要将目标类也加入classpath中。

3.AttackCommand是攻击模块，在攻击前同样使用如下代码进行信息收集

```Java
Enumerate enumerate = new Enumerate(this.target, this.port);
enumerate.enumerate();
RmiRegistry rmiRegistry = enumerate.getRegistry();
```

该模块存在许多参数，允许调用目标单个方法、或者从文件中读多个方法、或者批量执行目标绑定类的方法，以及执行ysoserial中所有的payload、或者指定payload，最终调用反射进行远程调用，同时把恶意代码作为参数传入远程调用中。

```Java
Attack attack = new Attack(rmiRegistry, payloadGenerator);
attack.attackRegistry(methodsList);
RemoteRef.invoke()
```

4.CallCommand相当于一个工具命令，封装了一些远程调用的方法，通过传入参数进行远程调用。

```Java
Attack attack = new Attack(rmiRegistry);
Object result = attack.invokeMethod(elements.get(2), elements.get(3), elements.get(4), params);
```

### 实战运用

在对Jira的40001端口探测的使用中出现了两个Bug，都是出现在RmiObjectParser的解析过程中，由于这里模拟的是原生的对java字节码的处理，原作者可能考虑的情况不够完全，所以出现了一些问题。在Debug的同时，也学习了很多java字节码相关的知识，因此记录一下。

1. Class Desc有一个classAnnotations的属性，在解析目标Class的Desc的时候，程序总是走到TC\_STRING的处理流程，然后在获取UTF-String的时候出错，其获取UTF-String的代码如下

```Java
private String getUtfShort(){
    int len = this.getShort();
    byte[] bytes = this.getBytes(len);
    return new String(bytes);
}

private Short getShort(){
    Short r = (short) (((this.getByte() << 8) & 0xFF00 ) | (this.getByte() &0xFF));
    return r;
}

```

每次在解析classAnnotations时，len总会为负数，这个len会用于生成一个new byte\[num\]数组，由于长度不能为负，程序就会报错。

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-714960294c436960160579f9eb27ccb5dd271b61.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-714960294c436960160579f9eb27ccb5dd271b61.png)

为了解决这个bug，我进行了抓包，

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-822bea790f7397324aad6ddaa2fee7b89efd6d89.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-822bea790f7397324aad6ddaa2fee7b89efd6d89.png)

这样的数据看不直观，将返回的数据，从aced开始，复制一部分序列化数据，使用SerializationDumper进行分析，SerializationDumper是一个分析序列化数据流的工具。

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-f24273f0a6cbe442d5c08b7a72e6872b9c9f2fe8.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-f24273f0a6cbe442d5c08b7a72e6872b9c9f2fe8.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-52236b4f70c7c415b35d322a06f5dfe70ca19957.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-52236b4f70c7c415b35d322a06f5dfe70ca19957.png)

可以看到，SerializationDumper分析出来的classAnnotation中，第一个byte为0x74，对应TC\_STRING，然后两个byte标识String的长度，这里的长度为0x99cf，转换为int为39375。但是在RmiTaste的代码中，这里获取String长度使用的是short，这本身也没有错，因为两byte的数字就应该对应short，但是short类型，最大为32767，因此更大的数就会变为负数，导致了bug的产生。这里修复的方法就是新写一个getBigShort函数，直接将两byte的数据转换为int类型

```Java
private Integer getBigShort(){
    Integer r = (Integer) (((this.getByte() << 8) & 0xFF00 ) | (this.getByte() &0xFF));
    return r;
}
```

2. 第二个遇到的问题和国外的那篇jira分析文章的作者遇到的问题相同

```Java
private void parseClassAnnotation(){
        // Skip annotation element
        Byte b = 0x00;
        while (true){
            b = this.getByte();
            if(b == TC_ENDBLOCKDATA){
                break;
            }
            else if(b == TC_REFERENCE){
                this.getInteger();
            }
            else if(b == TC_STRING){
                this.getUtfShort();
            }
        }
    }
```

在`parseClassAnnotation`函数中，如果程序读完了Annotation那么它还会继续循环，因为它使用的是while(true)循环，但是如果此时数据已经读完了，getByte就会返回-1，当然正常情况下b应该会返回TC\_ENDBLOCKDATA从而结束循环，但是如第一个bug所示，当Annotation特别大时，更容易会出现问题。

```Java
private Byte getByte(){
    if(this.index < this.streamSize){
        Byte b = this.stream.get(this.index);
        this.index++;
        return b;
    }
    this.logger.severe("No more bytes to read. Limit has been reached!");
    return -1;
}
```

如果你足够清醒，你会意识到`classAnnotations`表示和类相关的`Annotation`的描述信息，它在这个工具中后续的流程中其实起不了什么作用，因此如果只是为了让工具正常运行，其实不需要对这个Annotation的读取太过关心，只需要处理好异常就可以了。

因此这里debug的方法也很简单，在parseClassAnnotation的循环中，如果getByte返回了-1，那么直接退出循环即可，而不是继续在循环里读数据。

### 总结

对这个工具进行分析和使用的起因是社区师傅的一篇Jira漏洞的分析文章。接着就面临了贴近实战的Rmi探测到攻击的实践，在实践的同时遇到了一些现象和问题，通过阅读源码和动态调试去解释现象，解决问题，最后就有了这篇源码浅析以及bug记录的文章。文章中可能存在一些不严谨的地方，希望大家一起讨论一起学习一起进步。

### 参考

[奇安信攻防社区-CVE-2020-36239 - Jira 多款产品RCE漏洞分析 (butian.net)](https://forum.butian.net/share/653)

[Developing an exploit for the Jira Data Center Ehcache RCE (CVE-2020-36239) | dozer.nz](https://dozer.nz/posts/CVE-2020-36239-POC-dev)