一、Dalvik字节码
===========

**为逆向破解做准备!**  
Dalvik就是smali代码一种编写形式，那么在Java代码里面不能去修改某个逻辑，那么把java代码编译成smali代码，就是把dex文件转换为smali文件，也就说java和smali进行了一个翻译，那么记住Dalvik里面的smali是可以修改的，java代码是修改不了的，那么我们想要去破解也就是把Java改成smali，用smali去修改之后在回编译回去同时java逻辑也发生的改变!就是这个尝试破解的思路!

1、Dalvik寄存器
-----------

32位，支持所有类型,&lt;=32的一个寄存器，如果寄存器里面的东西超过32位怎么办?使用32位两个相邻的寄存器就是64位，所以64位就是两个相邻的寄存器!

2、寄存器的命名法
---------

V命名法

局部变量寄存器：v0-vn

参数寄存器：vn-vn+m

P命名法

参数寄存器：p0-pn

3、第一步分析
-------

V命名法分析~ 这是smali代码，我们来分析一下

![image-20210803155939098](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-60e1a826265cb4020575e9433b0a5aedc3605783.png)

这个demo里面有一个gethelloworld一个方法，括号里面传的是参数，java/lang/string就是参数，“;”符号是隔开两个参数，所以这里面是两个参数一个是java/lang/string和I，返回值类型就是string!

regsize表示寄存器有5个，此时看到的是调用方法，五个vO~v4，第一个红框调用了一个方法把V2、v3存了进去，返回了一个v2，回头看知道这里传入的参数类型是两个需要用到的参数类型就是两个，此时定义了v2和v3是变量寄存器返回了v2，vO和v4做一个参数寄存器返回了v0，那么v3是什么?v3在这里已经开始被v2返回掉了。

invoke-virtual是调用一个虚方法一个直接方法的意思。

4、第二步分析
-------

P命名法分析~

![image-20210803160828502](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-f3e839cc7d1ad9e9dfd4a5aec5453ffab881ba4f.png)同样是gethelloworld参数java/lang/string和l，红框第一个在  
java/lang/stringbuilder类里面调用了一个append的方法拼接传来string，然后返回了一个java/lang/stringbuilder类型，此时传入的java/lang/string是谁?

是PO，把PO传了进去，PO前面看是参数，这里就是把PO作为参数传了进去调用了v1，就是在V1里面传入了个P0，然后在返回一个javalangstring，最后返回了个V1，V1本来是存在的但他传入了个PO，但是他还是V1，返回了move o bject对象!所以他返回了个v1。所以v0作为参数寄存器!

第二个红框中，为什么只有p1没有p2呢? p1这时候作为一个参数继续传给v0，继续最终返回v0，所以这样就可以理解了p0和p1为参数寄存器。

这里两个步骤是简单了解字母意思...了解后我们在了解语法!面熟悉即可!

5、dex 文件反汇编工具
-------------

接下来熟悉反汇编工具dex!

1\) .java编译成.class在编译成.dex，最后反编译得到samli文件:

```php
.java - .class - .dex - smali
```

2\) dx.jar: .class打包.dex

```php
dx--dex --output=Decrypt.dex com/yijinda/ demo/Decrypt.class
```

使用dex将指定目录下的class打包成dex!

3)Baksmali.jar: .dex反编译成smali

```php
java -jar baksmali.jar -o smali_out/ classes.dex
```

这里了解下怎么编译的，在安卓模块这是系统自动去完成的!

4\) Samli.jar : .smali打包成.dex

```php
java -jar smali.jar smali_out/ -o classes.dex
```

第三个第四个称为反编译和回编译!

6、Dalvik字节码类型
-------------

![image-20210803163512445](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-f08e4224a678be253d368130da2a16e095d3a953.png)

Java 的八大类型, byte的b用B来表示，回到前面图中可以看到l就是这里的int表示，所以参数传入的类型是int类型的!都是首字母表示!为什么是红色字体?因为除了这几个红色字体不是首字母表示，其他都是首字母表示的!记住就可以了!  
以上图就是smali中的转换!

7、字段
----

Lpackage/name/o bjectName;-&gt;FieldName:Ljava/lang/String;

字段格式:类型(包名+类名) -&gt; 字段名称:字段类型  
解释:  
一个完整的类里面有方法、变量，字段表示的是变量，是成员变量的意思。

Lpackage/name/o bjectName就是包名+类名。

FieldName:Ljava/lang/String;就是字段的名称或者变量的类型。

前面都是描述变量而存在的!

```php
Package com.shi.demo
Class dome{
    String FieldName;
}
```

8、方法
----

Lpackage/name/o bjectName;-&gt;MethodName (lII)Z

(I)Z:这部分表示的是方法的签名信息

```php
Package com.shi.demo
class dome {
    String FieldName;
    Public boolen MethodName(int1,int2,int3){};
}
```

二、Dalvik指令集
===========

1、熟悉Dalvik指令
------------

**基础字节码-名称后缀/字节码后缀 目的寄存器 源寄存**

1)名称后缀是wide，表示数据宽度为64位

2)字节码后缀是from16，表示源寄存器为16位

3\) move-wide/from16 vAA， vBBBB

这里AA是目的寄存器没表示出来，这里为什么是四个B呢，因为一个字母是4位，4个B就表示源寄存器为16位。

**解释︰**

move为基础字节码，即opcode。

wide为名称后缀标识指令操作的数据宽度为64位。

from16为字节码后缀，标识源为一个16位的寄存器引用变量vAA为目的寄存器，它始终在源的前面，取值范围为v~V255。

vBBBB为源寄存器，取值范围为v0~v65535

Dalvik指令集中大多数指令用到了寄存器作为目的操作数或源操作数，其中A/B/C/D/E/F/G/H代表一个4位的数值，AA/BB/.../HH代表一个8位的数值，AAAA/BBBB/.../HHHH代表一个16位的数值。

2、十三种Dalvik指令使用
---------------

### 1、空操作指令 nop

空操作指令的助记符为nop。它的值为00，通常nop指令被用来作对齐代码之用，无实际操作!!

### 2、数据操作指令 move

1\) Move vA,vB ：将vB寄存器的值赋给vA寄存器，源寄存器与目的寄存器都为4位。

2\) Move/form16 vAA,vBBBB ：将vBBBB寄存器的值赋给vAA寄存器，源寄存器为16位，目的寄存器为8位。

3\) "move-wide vA,vB" ：将vB寄存器的值赋给vA寄存器，为4位的寄存器赋值。源寄存器与目的寄存器都为4位。

4\) "move-o bject vA,vB" ： o bject是对象的意思，出现这个词即为对象。那这里就是为对象赋值。源寄存器与目的寄存器都为4位。就是vBo bject给vAo bject!

5\) "move-o bject/from16 vAA,vBBBB" ：为对象赋值。源寄存器为16位，目的寄存器为8位!

6\) "move-o bject/16 vAA, v BBBB" ：为对象赋值。源寄存器与目的寄存器都为16位。在后缀标明16，就是16位!

7\) "move-result vAA" ：将上一个invoke类型指令操作的单字**非对象结果**赋给vAA寄存器，就是说不是对象的结果赋值给vAA寄存器，**就是用vAA去接收前面的返回值**，一个方法有返回值的时候会出现!

8\) "move-result-wide vAA" ：将上一个invoke类型指令操作的双字**非对象结果**赋给vAA寄存器。

9\) "move-result-o bject vAA" ：将上一个 invoke类型指令操作的**对象结果**赋给vAA寄存器。

10\) "move-exception vAA"：保有运行时发生的异常到vAA寄存器。就是异常状态下存入的!

分析了那麽多，总结起来move指令有三种作用

```php
1、进行赋值操作
2、move-result 接受方法返回值操作
3、处理异常操作
```

### 3、反馈指令 return（重点）

1\) "return-void" ：表示函数从一个void方法返回，返回值为空。

2\) "return vAA" ：表示函数返回一个32位非对象类型的值,返回值寄存器为8位的寄存器vAA

3\) "return-wide vAA":表示函数返回一个64位非对象类型的值，返回值为8位的寄存器对vAA。

4\) "return-o bject vAA"︰这里面出现了o bject，表示函数返回一个对象类型的值。返回值为8位的寄存器vAA。

### 4、数据定义指令 const（重点）

需要修改逻辑需要学会

![image-20210803232837482](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-84e6938e86622806f72bc7445310e87cee94894e.png)

1\) "const/4 vA,#+B" ：将数值符号扩展为32位后赋给寄存器vA。

2\) "const/16 vAA，#+BBBB" ：将数据符号扩展为32位后赋给寄存器vA。

3\) "const vAA，#+BBBBBBBB" ：将数值赋给寄存器vAA。

4\) "const/high16 vAA，#+BBBB0000" ：将数值右边零扩展为32位后赋给寄存器vAA。

5\) "const-string vAA,string@BBBB” ：通过字符串索引构造一个字符串并赋给寄存器vAA。

6\) "const-string/jumbo vAA,string@BBBBBBBB" ：通过字符串索引(较大)构造一个字符串并赋给寄存器vAA。

7\) "const-class vAA,type@BBBB" ：通过类型索引获取一个类引用并赋给寄存器vAA。

8\) "const-class/jumbo vAAAA,type@BBBBBBBB" ：通过给定的类型索引获取一个类引用并赋给寄存器vAAAA。

(这条指令占用两个字节,值为0xooff(Android4.0中新增的指令))。

![image-20210803233654086](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-fc5bea8555f62cd77fa5d5fcc813652c2f2d9dd9.png)

官方解释图

```php
https://blog.csdn.net/u010164190/article/d etails/52089794
```

只需要知道看到const是在操作什么指令即可

### 5、实列操作指令 instance

1\) "check-cast vAA,type@BBBB": check-cast vO

将vAA寄存器中的对象引用转换成指定的类型。如果失败会报出Class CastException异常。  
如果类型B指定的是基本类型，对于非基本类型的A来说，运行时始终会失败。  
2\) "instance-of vA,vB,":  
判断vB寄存器中的对象引用是否可以转换成指定的类型。如果可以vA寄存器赋值为1，否则vA寄存器赋值为0。  
3\) "new-instance vAA, type@BBBB":  
构造一个指定类型对象的新实例，并将对象引用赋值给vAA寄存器。类型符type指定的类型不能是数组类。

### 6、数组操作类型 array

数组操作包括获取数组长度，新建数组，数组赋值，数组元素取值与赋值等操作。

1\) "array-length vA， vB":

获取给定vB寄存器中数组的长度并将值赋给vA寄存器。数组长度指的是数组的条目个数。

2\) "new-array vA,vB,type@ccCC":

构造指定类型(type@ccCC)与大小(vB)的数组，并将值赋给vA寄存器。

**1和2记住即可，后面遇到比较少的我没列出!!**

### 7、异常指令 throw

“throw vAA"

抛出vAA寄存器中指定类型的异常

### 8、跳转指令goto、switch 、if (重点)

**重点中的重点!!!破解必会!! !**

跳转指令用于从当前地址跳转到指定的偏移处。

**Dalvik指令集中有三种跳转指令:**

(1) goto:无条件跳转

(2) switch:分支跳转

(3) packed-switch:有规律跳转(4) sparse-switch:无规律跳转

(4) sparse-switch：无规律跳转

(5) if : 条件跳转（重点)

```php
if-eq：等于/if-ne：不等于
if-lt：小于/if-le：小于等于
if-gt：大于/if-ge：大于等于
if-eqz：等于0/
```

### 9、比较指令cmpg、cmpl

比较指令用于对两个寄存器的值（浮点型或长整型)进行比较。

大于⑴/等于(0)/小于(-1) =&gt; cmpg、cmp  
大于(-1)/等于(0)小于⑴=&gt; cmpl  
**1)例如:cmp-long vAA,vBB, vCcC**  
比较两个长整型数。如果vBB寄存器大于vCC寄存器，则结果为1，相等则结果为0，小则结果为-1。  
这里是和  
**2)例如:cmpl-float vAA, vBB, vCC**  
比较两个**单精度浮点数**。如果vBB寄存器大于vCC寄存器，结果为-1，相等则结果为0，小于的话结果为1。

### 10、字段操作指令 iget、iput 、sget、sput

字段是成员变量  
**1)普通字段=&gt; iget读/ iput 写**

iget读是从后往前走  
iput写是从前往后走  
**2)静态字段=&gt;sget读/ sput 写**

### 11、方法调用 invoke-\*（重点）

根据方法类型不同，共有5条方法调用指令∶  
1\) invoke-virtual：调用实例的虚方法（普通方法)

2\) invoke-super：调用实例的父类/基类方法

3\) invoke-direct ：调用实例的直接方法

4\) invoke-static：调用实例的静态方法

5)invoke-interface：调用实例的接口方法

### 12、数据转换指令 opcode（了解）

数据转换指令用于将一种类型的数值转换成另一种类型。  
**例：“opcode vA, vB"**

vB寄存器存放需要转换的数据，转换后的结果保存在vA寄存器中。

neg-数据类型=&gt;求补

not-数据类型=&gt;求反

数据类型1-to-数据类型2=&gt;将数据类型1转换为数据类型2。

### 13、数据运算指令（了解）

add/sub/mul/div/rem

加/减/乘/除/模

and/or/xor

与/或/异或

shl/shr/ushr

有符号左移/有符号右移/无符号右移

三、Android 破解小游戏
===============

1、使用雷电模拟器运行小游戏
--------------

![image-20210803224618494](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-e3c6a9c19f7faa8ba3d1366ce81e1ec646e99488.png)

2、jadx-gui-1.2.0反编译为java
------------------------

将APK丢入工具

![image-20210803224833866](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-83573c198b87d8d75a8d724c7ad480b93e496ea2.png)

点击放大镜，然后进行查询：支付

![image-20210803224922534](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-f0b42d8c8f99984006e7582d674b4515c298f594.png)

双击进入支付成功哪里，看一下java代码

![image-20210803225024933](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-929408cbb10f5790a2e9f7e2e10077aac3daf98e.png)

关注支付取消，因为我们不支付，会提示支付取消。

我们发现支付成功调用zombie.BuySccess()方法，支付失败和支付取消都是调用 zombie.BuyFailed();

![image-20210803225231585](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-03c55ece42b13e52628156e64c8904a08a635e15.png)

按住CTRL+鼠标右键点击选中：zombie查看

![image-20210803230030332](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-f27500ab165e94ae7da8c17166cae802506470cc.png)

他这里目前无法分析逻辑，因为用的是别的代码去制造的逻辑，那么我们可以直接从代码入手。

**思路：**

把支付取消调用的zombie.BuyFailed()方法修改为支付成功调用的zombie.BuySccess()方法

3、AndroidKiller修改smali代码
------------------------

因为无法直接修改java代码，这里我们要上AndroidKiller工具了

使用androidKiller工具打开贪吃蛇的apk包

![image-20210803231024230](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-94d4cef32508ec7b3b4924b6166abc63fd859314.png)

查询支付取消，注意：需要将文本转换为Unicode

![image-20210803231218705](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-5d604ca112ff8f5c153e92832e671247c6f49f1a.png)

分析smali代码，我们看到第一个标红的地方调用.show()方法；第二个标红的地方L在smali中表示java代码，com/qy/zombie/zombie对用java代码中zombie类；第三行标红为支付取消调用的BuyFailed()方法。

![image-20210803231345440](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-7a48d034504f269019485f207a6d242adeabcb94.png)

我们查一下支付成功，发现调用的是BuySccess()方法

![image-20210803231827867](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-6e1a306006e62af66cd97eaa38624dc890f3f4c9.png)

那我们将支付取消的BuyFailed()替换为支付成功的BuySccess()方法，编译一下

![image-20210803232148712](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-00b6d5fdfd59436f9e7b3bbd96fab1ca30b185d0.png)

4、雷电模拟器测试
---------

安装回编译之后的APK包，测试

这里有很多 可以自己玩一玩

**请注意：这里使用的技术仅用于学习知识目的，如果列出的技术用于其他任何目标，我概不负责。**

四、总结
====

本章我们熟悉了Dalvik寄存器与指令集，分析了smali代码，运用解析了jadx-gui与AndroidKiller工具成功破解贪吃蛇小游戏，为下一步安卓逆向做准备。