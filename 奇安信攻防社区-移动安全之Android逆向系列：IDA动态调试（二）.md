一、传参分析
------

### 1、载入so文件

操作步骤同**IDA动态调试（一）**中的普通调试，参考该文章进行操作即可

### 2、寄存器介绍

传参操作涉及到寄存器，先简要介绍下各个寄存器

```php
R0-R3       参数寄存器
R4-R6, R8, R10-R11  普通的通用寄存器
R7          栈帧指针
R9          操作系统保留
R12:IP      指令指针寄存器
R13:SP      栈顶指针
R14:LR      函数返回地址
R15:PC      指向当前指令地址
```

### 3、参数个数

#### 1）动态代码中查看

首先我们要知道如何传参个数？分为以下两种情况：

1. 参数少于等于4个时，使用R0、R1、R2、R3四个参数寄存器，并且下一个寄存器用于地址存放  
    比如`BL R2`指令，这里的R2存放了地址，那么参数传递就是用了R0、R1两个寄存器。如果要使用4个参数进行传递，就会依次使用R0、R1、R2、R3寄存器，使用R4存放跳转的地址
2. 参数多于5个时，前四个参数通过R0、R1、R2、R3参数寄存器传递，剩下的参数通过压栈的方式传递。

**实例：**

在该程序中的`BLX R3`指令处中下断点，并F9执行到该处，R3寄存器存放了地址，那么该函数参数只能在R0、R1、R2三个寄存器中。也就是Rn编号小于4时，其对应使用的参数寄存器为n。F7单步执行后，可以看到栈地址未发生变动，可以验证参数小于4时只会使用到R0、R1、R2、R3参数寄存器。

![4K1p5D.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-b78f3976a56e06b69a2a62f937f8d03c48333ff5.png)

#### 2）静态代码中查看

这部分比较简单，主要是通过F5查看函数伪代码，其中的参数会标出来（不过这部分是可变的）

![4Klvb6.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-bc69781bfc43e26e1ef71ad316b239304f816c70.png)

### 4、查看堆栈信息

开启`Stack pointer`有助于快速识别栈中数据，开启步骤如下。可以看到在主窗口中多了一列信息，用于显示每一行指令对应的栈偏移信息，也就是**相对栈底指针的偏移**

![4KlXK1.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-caa162052eeef65e008312e95c02c386aac6423c.png)

### 5、IDA中参数的修改

#### 1）静态代码中修改参数类型声明

按F5反编译查看静态代码后，选中参数，按y可以修改参数的类型声明

![4KljDx.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-491c15710b6be436aa023cb03d9b6d1cd8f92b6a.png)

#### 2）动态代码中修改寄存器值

有两种方式进行修改寄存器值：

1. 直接双击进行修改
2. 选中一个寄存器的值，右键选择`Modify value`进行修改

![4K1SUO.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-bb6c5e824166f604dd34d5e394f12cb3ea3054e3.png)

两种方式的修改界面一致：

![4KlzVK.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-9bedd8317cc2661bcd55bec46a34ae777101f4a5.png)

参考：[ARM函数调用传参规则](https://juejin.cn/post/6882941595893792781)

二、函数修改
------

### 1、Hex View中修改指令

> 如果我们想在动态调试中修改一个指令进行测试，那么如何进行修改指令呢？
> 
> 我们可以在Hex View窗口中以指令的16进制格式进行修改
> 
> 指令对应的16进制格式的有关概念会在之后的文章中更新介绍~！

先设置**同步PC选定**，设置好后我们在代码段中选定一个值，在hex-view中就会显示该指令对应的16进制代码。在Hex窗口中右键选择`Synchronize with`下的`IDA View-PC`选项

![4K1eVf.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-dafd7e466edc3e15727d38cd0652afb357e21486.png)

接着随便选定一行指令，如下面这行，就会在Hex窗口中显示对应的十六进制格式。

![4K1ma8.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-0f4a51dc9eb41a795b97c670d80b87f690974822.png)

在Hex窗口中选定该值，按F2开始编辑修改，编辑修改完成后再次按F2进行保存，发现指令已被修改。

![4K1nIS.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-6c907292be3fab85bb98c412973e37f268396586.png)

**小技巧：**

设置在主窗口中的每一行指令显示对应的16进制格式，设置好后，可以看到多了一列信息，这部分就是该行指令对应的16进制格式机器码。

![4K1KPg.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-666a7e611584c1d1027c2e58c177fd6292fa69ad.png)

### 2、修改当前指令PC

> 用于调试测试

我们可以通过修改PC值来跳转到我们想要的地址中

我们当前位置为0xF3B0003C，打算直接执行0xF3B00044地址的指令`STR LR, [SP, #var_4]`，那我们在寄存器窗口双击PC值，将原先的0xF3B0003C修改为0xF3B00044，确定后可以看到当前指令变成了`STR LR, [SP, #var_4]`，直接跳转成功

![4K18rq.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-3aadb7c8ccdd0969f4a9e137cd05baa0311abc36.png)

三、标志位详解
-------

### 1、CPSR程序状态寄存器

CPSR（程序状态寄存器），包含条件码标志、中断禁止位、当前处理器模式以及其他状态和控制信息，其大小为4字节，基本结构如下，

![4K1Ert.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-27ac6ce47d4245d1518beaa1421f8f20c4061fdf.png)

高四位依次是NZCV，分别含义为：

- N（Negative）：两个带符号数进行运算时，N=1表示运算的结果为负数；N=0表示运算的结果为正数或零
- Z（Zero）：Z=1表示运算的结果为零，Z=0表示运算的结果非零
- C（Carry）：运算结果产生了进位（无符号数溢出），C=1，否则C=0
- V（Overflow）：V=1表示符号位溢出

对于剩余部分的含义，现阶段部分了解即可

- T（State bit）：处理器的运行状态，T=1表示目标代码解释为Thumb代码，T=0表示目标代码解释为ARM代码。该信号反映在外部引脚TBIT上

### 2、结合条件码

上一篇文章中介绍了条件码，其中每个条件助记符实际上都是有其对应的标志，比如EQ条件码对应的标志为Z=1，其他的参照下面的表格即可

![4ea8Re.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-fcb0c6e1f858966d8bf8c5e4e8b133b9f5e496fc.png)