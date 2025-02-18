一、ARM指令集介绍
----------

**ARM**架构是一个精简指令集（RISC）处理器架构家族，其广泛地使用在许多嵌入式系统设计（绝大部分安卓手机都是基于ARM）。ARM架构的指令为定长32位（Thumb指令集支持变长的指令集，提供对32位和16位指令集的支持）

### 1、ARM指令格式介绍

ARM指令基本格式：

```php
<opcode>{<cond>}{S}  <Rd>,<Rn>{,<opcode2}

opcode      指令助记符,如LDR, STR等
cond        执行条件,如EQ, NE等
S           是否影响CPSR寄存器的值,书写时影响CPSR,否则不影响
Rd          目标寄存器
Rn          第一个操作数的寄存器
opcode2     第二个操作数
```

- 中括号`<>`内的项是必须的
- 大括号`{}`内的项是可选的

### 2、条件码

条件码对应于ARM指令格式中的执行条件cond

![4ea8Re.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-d420f8b27eac5ea48b50dfe1a6765105764f6622.png)

二、ARM寻址方式
---------

### 1、寄存器寻址

操作数的值在寄存器中，指令执行时直接取出寄存器值操作。

```php
MOV R2, R1
```

### 2、立即寻址

立即寻址指令中的操作码字段后面的地址码部分就是操作数本身

```php
MOV R0, #0XFF00
```

### 3、寄存器偏移寻址

将第二个寄存器的值进行移位操作后赋予第一个寄存器中

```php
MOV R0, R1 LSL #3
```

将R1寄存器中的值左移3位放置到R0寄存器中。

移位操作之前介绍

### 4、寄存器间接寻址

间接寻址的地址存在第二个寄存器指定地址的存储单元中，使用`[]`表示其中的值作为地址进行寻址。

```php
LDR R1, [R2]
```

读取R2寄存器中的地址对应的存储单元中的值至R1寄存器中

三、常见ARM指令简介
-----------

> 这里使用之前编译的so文件反编译学习ARM指令

先使用IDA随便打开个so文件，如下

![4AzF5q.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-0d8b323a21d4ab2a7a3d5f9188b781d03025e875.png)

### 1、跳转指令

#### 1）B

B（Branch）为直接跳转指令

```php
B 0x11223344
B R3
```

跳转到0x11223344地址/R3处

#### 2）BL

带链接的跳转，即跳转前会将下一条指令的地址拷贝到LR寄存器中，保存好后才会执行跳转，便于找到返回地址。

```php
F3B00058 BL R3
F3B0005C CMP    R0, #0
```

跳转后可以看到LR中的值为F3B0005C

#### 3）BX

带状态切换的跳转，若跳转地址的位\[0\]为1，将标志T置为1，目标代码解释为Thumb代码；若跳转地址的位\[0\]为0，将标志位置为0，目标代码解释为ARM代码。

**小拓展：**Thumb 指令可以看作是 ARM 指令压缩形式的子集,是针对代码密度的问题而提出的

```php
BX  R3
```

跳转到R3中的地址处

#### 4）BLX

带状态切换和带链接的跳转

### 2、存储器访问指令

#### 1）LDR和STR

对存储器的访问需要通过加载和存储指令实现（LDR、STR），详细可分为字/半字，有符号/无符号等操作。

LDR：从内存单元中加载数据到寄存器（从右到左）

```php
LDR R8,[R9,#4]
```

加载R9+0x4（作为地址）所指向的内容存入R8中

STR：将寄存器中的数据存储到所指向的存储单元中（也就是左边的值放到右边）

```php
STR R8,[R9,#4]
```

存储R9+0x4所指向的内容存储至R8中

**实例：**

```php
LDR     R3, [R0,#0x4C]
将R0+0x4指向的内存单元内容读取到R3寄存器中
```

![4AzSKg.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-597d47b3ac039c787b86b2deee4fa49b67b12776.png)

#### 2）LDM和STM

批量加载/存储指令用于在一组寄存器和一块连续的内存单元之间的数据传输。主要作用为现场保护、数据传送。其中，后缀！表示最后

LDM：将存储器的数据加载到一个寄存器列表

```php
LDM R0!, {R1-R3}
```

将R0指向的存储单元的数据依次加载到R1,R2,R3寄存器

STM：将一个寄存器列表的数据存储到指定的存储器

```php
STM R0!, {R1-R3}
```

将R1-R3的数据存储到R0指向的地址上

**实例：**

```php
STMFD       SP!, {R3,LR}
STM加上FD表示堆栈操作，保护现场，将R3和LR寄存器的值保存到堆栈内，并更新SP值
```

![4AzprQ.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-32fcd086119b963de508f3400f1c63caddef0972.png)

#### 3）SWP

SWP指令用于将一个内存单元中的值读取到寄存器中，同时将另一个寄存器中的值写入该内存单元中。可以用于信号量的操作

```php
SWP R1, R2 [R0]
```

读取R0指向的内容到R1中，并将R2的内容写入到该内存单元中

### 3、数据传送指令

#### 1）MOV

MOV为数据传送指令，用于传输数据

```php
MOV R0, R1
```

将R1中的数值传送至R0寄存器

**实例：**

```php
MOV R1, R4
MOV R0, #9

```

![4AzPVs.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-42849b1a54cfbe18ed821d0a8e7dc862a0d8479f.png)

### 4、逻辑运算指令

#### 1）ADD、SUB

ADD、SUB等的逻辑运算指令用于寄存器中值的运算，举一反三即可

```php
ADD R1, R2, R3
SUB R1, R2, R3

```

将R2和R3的值相加存至R1中

#### 2）AND、ORR

```php
AND R1, R2, R3
ORR R1, R2, R3

```

将R2和R3进行按位与/或操作，结果保存至R1中

### 5、比较指令

#### 1）CMP

CMP为比较指令，通过减法操作，再根据结果修改标志位，一般修改CF、OF、SF、ZF，尤其是Z标志位。

```php
CMP R1, R2

```

R1的值减去R2的值，得到相应标志位的改变

**实例：**

```php
CMP R7, #6
将R7中的值和6进行比较，若相等ZF置为1，不相等ZF置为0
结合下面的BNE指令分析，当R7不等于6时进行跳转，即ZF值为0时跳转。

```

![4Az9bj.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-bd986cc8bad83a3c0008c78a76edbdbafc60f08c.png)

#### 2）TST

TST位测试指令，将两值按位作逻辑与操作，根据结果得新的标志位信息，用于后续的条件判断

```php
TST R1, #0X01
TST R2, #0x0F

```

判断R1寄存器中的最低位是否为和0x01相等，判断R2寄存器中的低4位是否和0x0F相等。TST指令一般和EQ、NE等条件码配合使用，**当所有测试位均为0时，EQ有效**，只要有一个测试不为0，则NE有效

**实例：**

```php
TST R3, #4
BNE loc_17B4
测试R3中的值和4进行按位与操作，如果结果不等于0（表示R3值不为4），执行BNE指令。

```

![4Azian.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-5fdcb08f3be9a82390399a881a07dd51f67a293a.png)

### 6、移位指令

#### 1）逻辑移位LSL、LSR

LSL是逻辑左移，低位补0

LSR是逻辑右移，高位补0

#### 2）算术移位ASL、ASR

ASL算术左移和LSL类似，主要是ASR有点细微区别

ASR算术右移中保持符号位不变，正数的话最高位补0，负数最高位补1

四、IDA动态分析源码
-----------

> 这部分承接上篇文章的第六部分，前边介绍了ARM汇编，稍微懂得了一些常见简单的ARM汇编指令

### 1、IDA动态调试载入so文件

这部分可以参考上篇文章中的普通调试部分，按照其中的步骤可以找到so文件中的JNI\_OnLoad函数

### 2、逐行汇编指令详解

在第一行下了断点后（F2），直接步进到此处（F9），左边蓝色的PC标志表示当前指令位于此。

![4AzUqH.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-77540e79698d7f51064402bd5359445a332f2a44.png)

#### 1）第一行汇编指令

第一行汇编代码如下，含义为将R0值指向的内存单元的值存入R3中，我们注意图中寄存器信息页面的两个框，分别是R0和R3。

```php
LDR R3, [R0]

```

先查看R0所指向内存单元的值，值为0xF4DB3D20（ARM使用小端序法进行存储数据）

![4AzNse.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-10ab6a349b27db10e333cf9444b7943c9258688d.png)

那么根据上面的分析，这条汇编指令执行完成后R3的值变为0XF4DB3D20

小技巧：点击PC的小箭头可以返回到指令位置

单击F7单步执行，可以看到和我们的分析完全一致

![4Az3Px.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-403739d690529e7e6b8257130a2765e7c3c64cda.png)

#### 2）第二行汇编指令

第二行指令为`MOV R2, #4`，意思是将立即数4赋予到R2中。

F7单步执行完该MOV指令后R2中的值将会被覆盖为4

![4Az8G6.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-274f6b2a971f343f8d5a0b35c665ed76d45a7a08.png)

#### 3）第三行汇编指令

第三行指令为`STR LR, [SP, #VAR_4]!`，表示将LR中的值存储至内存单元某处。

这里的`#VAR_4`是一个变量，指令上面有给出是-4。SP寄存器保存栈顶指针，所以本指令的内存单元为**SP值减4**的位置，也就是栈顶指针减4的位置。并且最后的`!`表示SP值加上偏移量值后会写回到SP寄存器中，我们先查看执行前的各值。

![4AzGRK.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-3dddf963be58e52318cc802993cd5a8de6479f31.png)

F7单步执行后为

![4AzJxO.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-fb144b4d727773ec086912981fadea8001ea1e65.png)

**拓展：**可以查看hex信息窗口，在栈地址中选定栈顶地址，右键`Follow in hex dump`可以跳转到指定地址的hex页面， 也可以查看到该值

![4AztMD.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-b355ce9e5d320f015e463ab07dd02404ab7a56d2.png)

#### 4）第四行汇编指令

第四行指令为`SUB SP, SP, #0xC`，意思就是将SP值减4写到SP中（注意这里是直接SP的值，而不是SP值指向的值）

这里SP的值为0xFF952CAC减去0xC就是0xFF952CA0，F7单步执行看看

![4AzbyF.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-0d289af6099032b9482c640f073674af9067fe46.png)

#### 5）第五行汇编指令

第五行指令为`ADD R1, SP, R2`，含义是将SP和R2的值相加写到R1中，（没有加中括号`[]`都是指寄存器中的值），SP值为0xFF952CA0，R2值为4，相加为0xFF952CA4，F7单步执行：

![4AzIJ0.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-821316bc5410f3ca6b97a8a8b8a53d0895c30435.png)

#### 6）第六行汇编指令

第六行指令为`LDR R3, [R3, #0x18]`，将R3值加上0x18值作为地址指向的值写到R3中。R3值为0xF4DB3D20，加上0x18得到0xF4DB3D38，可以查看到该内存单元的值为0xF470111

![4Az5iq.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-8fe8ad963742d422172e25c1765c710be1b912ac.png)

直接F7单步执行

![4AzoWV.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-b555ea02fb7a7f43a164225fe18b26bb2b94c3d2.png)

#### 7）第七行汇编指令

第七行指令为`MOVT R2, #1`，MOV后面加了T表示只操作高16位，即将1赋值到R2的高16位。这里的R2值为0x00000004，操作后应该为0x00010004，F7单步执行

![4AzTzT.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-88168cbea6efa936cf9efbc48b752bddeaa3a149.png)

#### 8）第八行汇编指令

第八行指令为`BLX R3`，是一个带状态切换和带链接的跳转，跳转到R3中保存的地址中，即`0XF4A70111`。

执行前的信息：

```php
R3: 0XF4A70111  跳转的地址
0xF3B00058      下一个指令的地址(之后会保存至LR寄存器中)
T:0             标志位

```

![4AzHQU.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-15d8d285eb2ecfef680ec48314ec730dea28c376.png)

F7单步执行后，可以看到跳转到了指定地址并且LR寄存器中保存了相应的返回地址，标志位T置为1表示目标代码解释为Thumb代码。

![4ESkeH.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-ab55262a4e689ac56f5b533218c3e08aeb92cf33.png)

**小技巧：**

1. 按`ESC`回到跳转前的指令处（这里的回指的是视角的回去，但是指令执行顺序是不会回去的）
2. 找到当前执行指令的位置，按PC寄存器旁边的箭头即可跳转找到
3. 按F4代码运行到当前光标处

将光标移到函数的末尾，按F4后代码直接跳转到此处

![4ESiOe.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-8b976969b0e718aa9cde40c3d687e566ec01ab81.png)

接着按F7跳出该函数，回到原先指令的下一条指令的地址处

![4ESPyD.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-39d0d6a0b24260a7439eec3842b1cb69f9c58a44.png)

#### 9）第九行汇编指令

第九行指令为`CMP R0, #0`，将R0的值和0做减法比较，根据结果修改标志寄存器中的标志位（一般看Z标志位），R0值0和立即数0相等，Z标志位置为1

![4ESAwd.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-050c181eb9f9e0fd8233859f25595615e6d64dbf.png)

#### 10）第十行汇编指令

第十行指令为`BNE loc_F3B000B4`，根据状态位进行跳转，BNE看Z标志位，Z=1跳转，Z=0不跳转。

![4ESETA.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-4eb17578efe33df012a054f6124850db73449c7b.png)

五、总结
----

对于刚入门安卓逆向，能看懂一些常见的、简单的ARM汇编就是我们的目标，不用追求理解ARM汇编指令中的所有内容。不同学习阶段有不同的任务，之后深入学习下去遇到不会的ARM汇编指令再查就是了。所以，对于一段ARM汇编程序代码，能看懂大部分即可。