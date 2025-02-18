该文章首发于跳跳糖：<https://tttang.com/archive/1334/>

本文略有删改

0x01 背景
-------

之前在先知社区写过相关的文章：<https://xz.aliyun.com/t/10433>

文章过于粗糙，一些基础原理和细节问题没有谈明白

所以再写一篇文章做更完善的分析

0x02 数据流分析
----------

静态分析理论中的数据流分析，通过算法得到**Basic Block**进而建立**Control Flow Graph**后，根据传递函数迭代生成每个**Basic Block**的**in/out**集直到不再变化后得到一个保守的分析结果

不同于标准的数据流分析，笔者这里是一种**简单的方式**

先带大家从一个**简单的SQL注入例子**的字节码来分析`JVM Stack Frame`中`Operand Stack`和`Local Variables`的变化

### 状态分析

给出一个最简单的SQL注入例子

```java
public List<User> selectUser(String name) {
    String sql = "select * from t_user where name=\"" + name + "\"";
    List<User> users = jdbcTemplate.query(sql, new BeanPropertyRowMapper(User.class));
    return users;
}
```

简单分析上面的代码可以得出结论：`name`参数存在了字符串拼接操作，并且拼接后的字符串被设置为`jdbcTemplate.query`方法的第一个参数执行了该方法

如果`name`参数是可控的用户输入变量，那么就可以成功触发SQL注入漏洞

假设现在我们确认了`name`是可控输入（如何将在后文中详细解释）应该如何分析呢

首先来看`String sql = ...`这句话的字节码

```java
    NEW java/lang/StringBuilder
    DUP
    INVOKESPECIAL java/lang/StringBuilder.<init> ()V
    LDC "select * from t_user where name=\""
    INVOKEVIRTUAL java/lang/StringBuilder.append (Ljava/lang/String;)Ljava/lang/StringBuilder;
    ALOAD 1
    INVOKEVIRTUAL java/lang/StringBuilder.append (Ljava/lang/String;)Ljava/lang/StringBuilder;
    LDC "\""
    INVOKEVIRTUAL java/lang/StringBuilder.append (Ljava/lang/String;)Ljava/lang/StringBuilder;
    INVOKEVIRTUAL java/lang/StringBuilder.toString ()Ljava/lang/String;
    ASTORE 2
```

第一行`NEW java/lang/StringBuilder`实际在JVM中的过程如下

代码中没有`StringBuilder`为什么字节码中有呢？

因为在JVM中字符串相加其实会被转为`StringBuilder.append`操作

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-ccd0c2869fc7eb854c302ac6d1e2b95dcd8ad6c0.png)

第二句`DUP`会将`Operand Stack`栈顶元素复制一份，变成下图这样（为什么要复制见下文）

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-a99cd5f4bf049cbdbd672cacf71df6a9772d2c35.png)

下一句`INVOKESPECIAL java/lang/StringBuilder.<init> ()V`真正地实例化对象

虽然并没有传参数，但非STATIC方法的调用第0个参数实际上是this对象，也就是这里的`Object Ref`

在JVM中方法调用的过程如图：从`Local Varaibles`中取值放入`OperandStack`作为方法参数，调用方法时弹出。调用方法结束后，如果方法有返回值会讲返回值压入`OperandStack`

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-c84af7804cafaced304752633a41deb77e356c0d.png)

回到刚才的实例化`StringBuilder`字节码，这里会弹出栈顶的一个`Object Ref`，由于初始化方法没有返回值，所以并没有压入的返回值。但是此时栈顶存在的另一个`Object Ref`指向被实例化的对象，所以不再是空指针，当然这里不是我们需要关注的地方

所以这一步调用结束后，状态应该和第一步`NEW`相同

再看下一句`LDC "select * from t_user where name=\""`

这句的效果是直接将字符串常量压栈，如下图

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-b4372bb1dedf3de57cecc544b80297fad5b4ab5b.png)

其实这一句LDC的作用是为了下一句的`append`方法调用

`INVOKEVIRTUAL java/lang/StringBuilder.append (Ljava/lang/String;)Ljava/lang/StringBuilder;`

注意到方法非STATIC且有一个参数，所以会弹出栈顶两个元素

`append`方法执行完后会有一个返回值，压栈

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-7fba66ced8221af4a8e1fe9eb4aaff4023dc10d8.png)

上一步压栈的返回值其实还是`StringBuilder`对象，如果要下一次`append`那么就需要再找一个字符串

看到下一步是`ALOAD 1`操作，这条指令的作用是取`Local Variables`第2个元素压栈

注意到上面一些列图中的`Local Variables`一直都有两个元素（为了防止干扰所以没有标明是什么）

非STATIC方法的`Local Variables`的第1个元素一定是this对象，而传入的参数依次往后排

所以`ALOAD 1`在JVM中执行的过程应该如下

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-903fa236eb1befe15e76890532be57b4d118d959.png)

后续三步的过程同上

第一个`INVOKEVIRTUAL`作用是`append`了可控变量`name`，返回值压栈

`LDC`是SQL语句的结尾，再次`append`完返回值压栈

```java
    INVOKEVIRTUAL java/lang/StringBuilder.append (Ljava/lang/String;)Ljava/lang/StringBuilder;
    LDC "\""
    INVOKEVIRTUAL java/lang/StringBuilder.append (Ljava/lang/String;)Ljava/lang/StringBuilder;
```

执行完这两步后状态如下（注意`Local Variables`中的变量被`ALOAD`完不变）

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-d317a2b32903461d497e66e64d8b8e5c0dcbfc27.png)

结尾的两步其实也简单，注意到`toString`方法没有参数，返回一个String

所以会弹栈再压栈，下一步的`ASTORE 2`作用是保存到局部变量表第3位

```java
    INVOKEVIRTUAL java/lang/StringBuilder.toString ()Ljava/lang/String;
    ASTORE 2
```

以上过程图示

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-2d904ab477b231e9445269f499e34c66c32f645a.png)

注意以上的过程只是第一句`String sql = ...`的字节码分析

第二步`List<User> users = jdbcTemplate.query(...);`的字节码如下

```java
    ALOAD 0
    GETFIELD org/sec/cidemo/dao/impl/SQLIDaoImpl.jdbcTemplate : Lorg/springframework/jdbc/core/JdbcTemplate;
    ALOAD 2
    NEW org/springframework/jdbc/core/BeanPropertyRowMapper
    DUP
    LDC Lorg/sec/cidemo/model/User;.class
    INVOKESPECIAL org/springframework/jdbc/core/BeanPropertyRowMapper.<init> (Ljava/lang/Class;)V
    INVOKEVIRTUAL org/springframework/jdbc/core/JdbcTemplate.query (Ljava/lang/String;Lorg/springframework/jdbc/core/RowMapper;)Ljava/util/List;
    ASTORE 3
```

首先来看前两步，局部变量表第1位的this压栈，然后`GETFIELD`

这个指令的作用是取栈顶对象中的某个属性，然后压栈

再取局部变量表第3位的`sql`压栈

之后`NEW BeanPropertyRowMapper`不仔细分析了，读者可以自行分析

直到关键方法`INVOKEVIRTUAL JdbcTemplate.query`之前的过程图示如下

（其中`BPW`是`BeanPropertyRowMapper`对象）

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-48478a1ee10042bba2eb93d5475cffdcf82a126f.png)

上图最右侧的`OperandStack`状态正是调用关键方法之前的状态

```java
INVOKEVIRTUAL org/springframework/jdbc/core/JdbcTemplate.query (Ljava/lang/String;Lorg/springframework/jdbc/core/RowMapper;)Ljava/util/List;
```

该方法需要两个参数，由于非STATIC需要加上方法本身的this参数，也就是总共需要三个参数

入参的顺序是从右到左，依次弹出栈中的三个元素作为参数，然后执行该方法

没有必要做后续的分析了，这一步已经可以确认SQL注入漏洞了

### 分析思路

借用上文一张图

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-903fa236eb1befe15e76890532be57b4d118d959.png)

JVM在进入该方法时候，会在局部变量表里面初始化参数，第1位this，方法参数依次往后排

由于我们假设了`name`参数是可控的参数，可以给它一个颜色表明它存在问题

所以上文拼接字符串的部分可以表示如下

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-a8682d372874280726f589e116bbe4e1a8ed53bf.png)

字符串被拼接后保存到局部变量表

后续的`jdbcTemplate.query`调用又会取出来，作为参数传入

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-641595e7209537016a40cf78fc16339918bee377.png)

所以如果一开始的`name`是红色且最后数据库操作的参数中包含了红色，说明存在漏洞

### 代码实现

那么如何实现呢？

造个`Operand Stack`和`Local Variables`

其中的泛型T可以理解为上文的红色

```java
public class OperandStack<T> {
    private final LinkedList<Set<T>> stack;
    // pop push methods
}
```

```java
public class LocalVariables<T> {
    private final ArrayList<Set<T>> array;
    // set get method
}
```

在进入方法的时候初始化这两个数据结构

```java
public void visitCode() {
    super.visitCode();
    localVariables.clear();
    operandStack.clear();

    if ((this.access & Opcodes.ACC_STATIC) == 0) {
        localVariables.add(new HashSet<>());
    }
    for (Type argType : Type.getArgumentTypes(desc)) {
        for (int i = 0; i < argType.getSize(); i++) {
            localVariables.add(new HashSet<>());
        }
    }
}
```

模拟JVM的操作

以下是节选自`CoreMethodAdapter`的部分代码，其中`visitInsn`方法是遇到无操作数的指令情况

实际上这个模拟很复杂，需要处理各种指令的情况，比如`GOTO`等指令需要复制状态，处理起来很麻烦

```java
@Override
public void visitInsn(int opcode) {
    switch (opcode) {
        case Opcodes.NOP:
            break;
        case Opcodes.LCONST_0:
        case Opcodes.LCONST_1:
        case Opcodes.DCONST_0:
        case Opcodes.DCONST_1:
            operandStack.push();
            operandStack.push();
            break;
        case Opcodes.IALOAD:
        case Opcodes.FALOAD:
        case Opcodes.AALOAD:
        case Opcodes.BALOAD:
        case Opcodes.CALOAD:
        case Opcodes.SALOAD:
            operandStack.pop();
            operandStack.pop();
            operandStack.push();
            break;
        case Opcodes.LALOAD:
        case Opcodes.DALOAD:
            operandStack.pop();
            operandStack.pop();
            operandStack.push();
            operandStack.push();
            break;
            ....
    }
}
```

关于该类完整代码参考：

<https://github.com/EmYiQing/CodeInspector/blob/master/src/main/java/org/sec/core/CoreMethodAdapter.java>

当我们给两大数据结构中的元素设置内容时，其实就相当于上文的红色

遇到JVM指令后，模拟做出**相同**的push/pop等操作，**一般情况**下这个红色就会传递下去

如果出现类似RETURN的操作，红色不会传递下去，那么我们判断下是否符合指定的条件，然后手动传递下去即可

实际上这一步实现起来不是那么简单，会遇到很多意外的情况

0x03 方法调用图
----------

回到一开始的地方：当时说我们**认为name参数是可控参数**

为什么能这么认为，如何判断是否真正可控？

还是从实际的例子入手，一个最简单的`SpringMVC`入口，经过`Service`层到达`Dao`层完成数据库操作

```java
@RequestMapping("/select")
@ResponseBody
public List<User> select(@RequestParam("name") String name){
    return sqliService.selectUser(name);
}

@Override
public List<User> selectUser(String name) {
    return sqliDao.selectUser(name);
}

@Override
public List<User> selectUser(String name) {
    String sql = "select * from t_user where name=\"" + name + "\"";
    List<User> users = jdbcTemplate.query(sql, new BeanPropertyRowMapper(User.class));
    return users;
}
```

可以使用ASM技术分析**所有的**字节码

这里的所有指的是目标jar包中源代码，依赖库以及JDK中的字节码

然后`visit`所有的`method`（可以理解为遍历所有class文件的方法）

分析即可得到当前整个运行环境中，存在的每个方法中有那些方法调用

直接这样说也许显得空白，下面用一个简单的例子解释：**每个方法中有那些方法调用**是什么意思

```java
public class Demo{
    int demo(int a){
        int b = A.test1(a);
        int c = new A().test2(a);
    }
}
```

那么它存在这样的调用（数字表示参数索引）

```java
Demo.demo(1)->A.test1(0)
Demo.demo(1)->A.test2(1)
```

由于`test1`方法是静态方法，而`demo`和`test2`方法不是。需要考虑到正常情况下方法参数索引0为`this`

而`caller`参数`a`的索引为1，`target`参数索引在静态情况下为0，正常情况下为1

这是一处简单的方法，经过测试运行环境实际上会有几万到几百万个方法，需要做的事情是分析所有方法

思路有了，接下来写代码

遍历到的每个方法在进入方法时设置上当前的参数索引（visitCode是ASM定义观察方法过程中的第一步）

```java
@Override
public void visitCode() {
    super.visitCode();
    int localIndex = 0;
    int argIndex = 0;
    if ((this.access & Opcodes.ACC_STATIC) == 0) {
        localVariables.set(localIndex, "arg" + argIndex);
        localIndex += 1;
        argIndex += 1;
    }
    for (Type argType : Type.getArgumentTypes(desc)) {
        localVariables.set(localIndex, "arg" + argIndex);
        localIndex += argType.getSize();
        argIndex += 1;
    }
}
```

在当前方法内遇到方法调用时，会执行`visitMethodInsn`方法

```java
@Override
public void visitMethodInsn(int opcode, String owner, String name, String desc, boolean itf) {
    Type[] argTypes = Type.getArgumentTypes(desc);
    // 这里主要目的是判断是否STATIC决定第0位参数是否为this
    if (opcode != Opcodes.INVOKESTATIC) {
        Type[] extendedArgTypes = new Type[argTypes.length + 1];
        System.arraycopy(argTypes, 0, extendedArgTypes, 1, argTypes.length);
        extendedArgTypes[0] = Type.getObjectType(owner);
        argTypes = extendedArgTypes;
    }
    switch (opcode) {
        case Opcodes.INVOKESTATIC:
        case Opcodes.INVOKEVIRTUAL:
        case Opcodes.INVOKESPECIAL:
        case Opcodes.INVOKEINTERFACE:
            int stackIndex = 0;
            // 遍历调用方法的所有参数
            for (int i = 0; i < argTypes.length; i++) {
                // 这个argIndex是目标方法的参数索引
                int argIndex = argTypes.length - 1 - i;
                Type type = argTypes[argIndex];
                // 从Operand Stack中取出当前参数对应的值
                Set<String> taint = operandStack.get(stackIndex);
                if (taint.size() > 0) {
                    for (String argSrc : taint) {
                        // 由于这个值是visitCode时初始化的
                        // 所以会是arg1这样的格式需要切割
                        srcArgIndex = Integer.parseInt(argSrc.substring(3));
                        // 构造当前的CallGraph并保存结果
                        discoveredCalls.add(new CallGraph(
                            new MethodReference.Handle(
                                new ClassReference.Handle(this.owner), this.name, this.desc),
                            new MethodReference.Handle(
                                new ClassReference.Handle(owner), name, desc),
                            srcArgIndex,
                            argIndex));
                    }
                }
                stackIndex += type.getSize();
            }
            break;
        default:
            throw new IllegalStateException("unsupported opcode: " + opcode);
    }
    super.visitMethodInsn(opcode, owner, name, desc, itf);
}
```

通过以上的代码，筛选后可以得到下面的结果

```text
caller:Controller.select(1)
target:Service.selectUser(1)

caller:Service.selectUser(1)
target:Dao.selectUser(1)
```

这时候如果将第一步的`name`变成红色，通过模拟JVM两大数据结构之间的交互，让这个红色在**方法调用间**逐渐传递

从Controller层传递到最后Dao层调用数据库操作的地方，这里就贯通了整个流程

为了方便理解，再画一张图表示

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-09e42bf7e72a74b20b829ee9945c176a1982de17.png)

其中`start`是前端传入的可控参数，在`Local Variables`中将它染红，`select(name)`方法调用前压栈，调用后弹出

这时候红色消失了，如何确保传递呢？

通过上文分析得到的`CallGraph`结果，查到`Controller.select(1)->Service.selectUser(1)`发现`name`参数传入了`selectUser`方法中，也就是上图最左边栈顶的红色

于是手动给`Service Local Variables`中**对应的参数索引位置**设置颜色，为了区分选择了蓝色

Service层两大数据结构模拟过程同上，到达Dao层。通过`CallGraph`查到了这样的结果：`Service.selectUser(1)->Dao.selectUser(1)`认为第1个参数`name`可以继续传递

而Dao层的操作相比前两层来看复杂了很多，这里正是本文一开始分析的**数据流分析**

一开始假设`Dao.selectUser(name)`的name参数是可控输入，直接染红。假设在这里就可以去掉了

最终到达`jdbcTemplate.query(sql,...)`处

经过上文**数据流分析**，发现了拼接sql语句并执行的操作，也就是SQL注入漏洞

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-641595e7209537016a40cf78fc16339918bee377.png)

0x04 返回值分析
----------

对漏洞而言，仅仅确定漏洞可以触发其实是不足的，更需要想办法做到**回显**

类似普通的漏洞分析，可以看到上文已经做到了漏洞触发的分析，如果遇到反射XSS这种需要判断回显的怎么办

给出一个简单的反射XSS例子

Controller

```java
@RequestMapping("/reflection")
@ResponseBody
public String reflection(@RequestParam("data") String message) {
    return xssService.reflection(message);
}
```

Service

```java
@Override
public String reflection(String message) {
    if (!message.equals("test")) {
        return message;
    }
    return "error";
}
```

简单地分析可以发现如果`message`参数不是`test`那么就会原样输出给前端，造成反射XSS

上文的红色原理可以用在这里

单独分析Service层方法，如果入参染成红色，返回时`ALOAD 1`会把入参压栈，因此返回值也变成了红色

```java
    ALOAD 1
    LDC "test"
    INVOKEVIRTUAL java/lang/String.equals (Ljava/lang/Object;)Z
    ...
    ALOAD 1
    ARETURN
```

图片表示过程如下：

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-543ad6f1b508be9011b81f06e88abbbcfe607ae7.png)

再分析Controller层，由于我们已知Service层的方法返回值有可能和入参一致，所以调用`Service.select`方法得到返回值可以设为红色，进而可以初步推断出反射XSS

（这里为了简化分析，所以暂不考虑其他的操作，比如字符串是否被实体化编码等）

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-e6007d30e7717fc2aa18fb8a1467fd2e5e33d0f0.png)

### 逆拓扑排序

涉及到另外一个问题，应该从哪个方法优先分析？

答案：应该从最底层的调用开始分析

假如有如下的调用链：`A.B.C.D.E`单一的线性调用，可以直接从E开始

如果不是线性的，应该如何处理呢？

参考`GadgetInspector`中的逆拓扑排序

关于逆拓扑排序，参考**Longofo**师傅的文章，对图片做了一些优化和精简

这是一个方法调用关系：

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-eb55e0e40dcfdffcd0ad664c891d6b1034101ad3.png)

在排序中的stack和visited和sorted过程如下：

只要有子方法，就一个个地入栈

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-e7053c567fd9cf5314ac183a1c86f41aea2e97a4.png)

到达method7发现没有子方法，那么弹出并加入visited和sorted

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-98458ab9304504154cc0ae6757b9319db8674c02.png)

回溯上一层，method3还有一个method8子方法，压栈

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-e8f6b41795cdd1e0d80f7458aedf9c66c1eeb539.png)

method8没有子方法，回溯上一层method3也没有，都弹出并进入右侧

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-b83ea176797b655321186b1fdeef629f3cfe8dd6.png)

到达method6，有子方法，压栈，找到method6下的method1，压栈，注意这里是Set结构不重复，所以压了等于没压

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-94d3ab374755e9ff95b6eb6a545f0136ea44f83a.png)

回溯后method6和method2都没有子方法了，弹出并进入右边

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-8cc05c09c6ecd611831fc5dc602d91d567769b5d.png)

往后执行遇到method1的两个子方法method3和method4，由于method3已在visited，直接return，把method4压栈。然后method4没有子方法弹栈，最后剩下的method1也没有子方法，弹栈

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-f1877cc8eea02f5568a5d7707f503a262e7d015f.png)

最终得到的排序结果就是7836241，达到了最末端在最开始的效果

0x05 总结
-------

代码地址：<https://github.com/EmYiQing/CodeInspector>