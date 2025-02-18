0x0前言
=====

千呼万唤始出来，嗨咻咻，笔者VMre系列的第二篇文章来喽。

这篇文章主要讨论利用anger工具符号执行秒解vm类re题目，以及一道更为复杂的逆向分析带vm虚拟机保护程序的题目。

0x1angr符号执行一把梭
==============

符号执行
----

简单的来说，符号执行就是在运行程序时，用符号来替代真实值。符号执行有什么好处呢？当使用真实值执行程序时，我们能遍历的程序路径只有一条，而使用符号执行，由于符号的灵活性（可变）我们就可以利用这一特性，尽可能地将程序的每一条路径遍历，这样的话，必定存在至少一条能够输出正确结果的分支。每一条分支的结果都可以表示为一个离散关系式，离散关系式的话我们使用约束求解引擎即可分析出正确结果。

angr
----

> Angr是一个利用python开发的二进制程序分析框架，我们可以利用这个工具尝试对一些CTF题目进行符号执行来找到正确的解答，即flag。当然，要注意的是符号执行的路径选择问题到现在依旧是一个很大的问题，换句话说也就是当我们的程序存在循环时，因为符号执行会尽量遍历所有的路径，所以每次循环之后会形成至少两个分支，当循环的次数足够多时，就会造成路径爆炸，整个机器的内存会被耗尽。

环境搭建
----

可以使用docker

```php
docker pull angr/angr
docker run -it -v /mnt/hgfs/share:/mnt/ angr/angr
#/mnt/hgfs/share 目录是我题目所在的目录，直接挂载在docker里的/tmp目录
```

当然也可以直接使用pycharm即可

```php
pip install angr
```

如何使用angr对REVERSE类题目进行分析求解
-------------------------

### 创建angr工程

我们在得到一个程序时，首先需要对此程序创建一个Angr工程。

```php
p=angr.Project('program')
```

我们可以通过Angr工程来获取程序的信息，比如程序名p.filename等等。然后需要将这个程序运行起来，并且处理程序的一些输入，接下来我们需要构造一个Angr中的符号来当做程序的输入。

### 命令行参数（可选）

当我们需要使用命令行参数时，我们需要在py程序中添加如下语句

```php
import claripy 
```

claripy的`BVS`函数可以创建一个指定长度的抽象数据，`BVS`函数要求两个参数，\*\*\*个参数为变量名，第二个参数为变量长度。

```php
argv = [p.filename,]  
arg = claripy.BVS(‘arg1′, 8)
argv.append(arg1) 
```

这样，我们就创建好了一个命令行参数，我们现在可以将程序运行到程序入口处，并获得当前的一个状态。

```php
state = p.factory.entry_state(args=argv) 
```

`P.factory`是工厂函数的一个集合，在这里面可以调用各种各样的函数来进行符号执行，其中`entry_state()`函数接收一个list作为程序的命令行参数并且返回程序入口的状态

### Angr中程序的几种状态

我们在之前提到了获取程序入口点的状态，状态在Angr中表示着程序符号执行后的几种结果，在Angr中，当获取到程序入口点的状态后，我们需要使用Angr的`Simgr`模拟器来进行符号执行。

```php
qaq = p.factory.simgr(state) 
```

该语句表示从程序入口点创建一个模拟器来进行符号执行。那么angr寻找路径时，程序到底有多少种状态呢？

```php
step()表示向下执行一个block(42bytes)，step()函数产生active状态，表示该分支在执行中;
run()表示运行到结束，run()函数产生deadended状态，表示分支结束;
explore()产生found状态，表示探索的结果;
并且explore()可以对地址进行限制以减少符号执行遍历的路径（俗称剪枝）。例如
sm.explore(find=0x400676,avoid=[0x40073d])
```

### 标准输入输出

当程序需要从标准输入处读取数据时，需要使用read\_from()函数，特别要注意的是，这个函数位于状态（state）中，并且我们可以对输入进行一些约束来剪枝

**标准输入**例如：

```php
for _ in xrange(5):   
    f = state.posix.files[0].read_from(1) 
```

剪枝例如(限制k在100以内的条件)：

```php
for _ in xrange(5):   
    f = state.posix.files[0].read_from(1)
      state.se.add(k<100) 
```

当符号执行遍历玩路径后，会产生大量的状态，我们则需要从这些状态中找出我们所需要的一条路径。那么怎么获取符号执行的输出呢？

首先我们可以获取当前状态程序的输出：

```php
print sm.found.posix.dumps(1) 
```

其次我们可以获取命令行参数的输出：

```php
print sm.found.solver.eval(arg1,cast_to = str) 
```

当然也可以获取标准输出：

```php
inp = sm.found.posix.files[0].all_bytes()   
print sm.found.solver.eval(inp,cast_to = str)z  #利用约束求解引擎求解输入
```

初涉angr--\[Whale CTF\] defcamp\_r100
-----------------------------------

这道题目本身非常非常简单，就是要求输入一个password 然后check一下是否正确。其实反编译大法之后写逆向脚本一下就出来了。

check函数

```c
signed __int64 __fastcall sub_4006FD(__int64 a1)
{
  signed int i; // [sp+14h] [bp-24h]@1
  const char *v3; // [sp+18h] [bp-20h]@1
  const char *v4; // [sp+20h] [bp-18h]@1
  const char *v5; // [sp+28h] [bp-10h]@1

  v3 = "Dufhbmf"; 
  v4 = "pG`imos";
  v5 = "ewUglpt";
  for ( i = 0; i <= 11; ++i )
  {
    if ( (&v3)[8 * (i % 3)][2 * (i / 3)] - *(_BYTE *)(i + a1) != 1 )
      return 1LL;
  }
  return 0LL;
}
```

main函数

```c
__int64 __fastcall main(int a1, char **a2, char **a3)
{
  __int64 result; // rax
  char s[264]; // [rsp+0h] [rbp-110h] BYREF
  unsigned __int64 v5; // [rsp+108h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  printf("Enter the password: ");
  if ( !fgets(s, 255, stdin) )
    return 0LL;
  if ( (unsigned int)sub_4006FD(s) )
  {
    puts("Incorrect password!");
    result = 1LL;
  }
  else
  {
    puts("Nice!");
    result = 0LL;
  }
  return result;
}
```

但是这道题目我们不采用常规的做法，毕竟做题的目的是为了学习angr不是么~

angr解题的话采取寻找find\_addr和avoid\_addr，再过滤出满足条件的path就可以了。

### 寻找find\_addr 和avoid\_addr

很多angr相关的文章中没有说明find和avoid具体是什么。可能是大佬节省笔墨吧，这里我为小白们发声一下`find`是想要程序执行的分支，`avoid`是不希望程序执行的分支。find\_addr则是想要程序执行的分支的开头地址，avoid\_addr则是不想要程序执行分支的开头地址。

![image-20220216052142521](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-5e1dc1077ccd1ca18a69706e988b9c279ce76cfa.png)

ida中使用距离视图查看程序结构，1分支是我们想执行的，2 分支是我们不想执行的。空格跳到文本页面查看地址

![image-20220216052313449](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-127cfdc3553230968fc3b9716cdbf1cf27069c31.png)

```python
import angr # 导入angr库
p=angr.Project('./r100',auto_load_libs=False) # 加载程序
state=p.factory.entry_state() # 创建一个状态,默认为程序的入口地址
simgr=p.factory.simgr(state) # 创建一个模拟器用来模拟程序执行,遍历所有路径
simgr.explore(find=0x400844,avoid=0x400855)
flag=simgr.found[0].posix.dumps(0)
print (flag)
```

得到密码为Code\_Talkers

![image-20220216060629505](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-6bdf215ea3d0ad9515837eb34caffe51d6af187e.png)

再探2020网鼎杯青龙组re\_signal
----------------------

这题根本不需要符号执行的什么高端操作，直接就是粗暴的一~把~梭

```python
import angr
p=angr.Project('./signal.exe')
state =p.factory.entry_state() #新建对象
simgr =p.factory.simgr(state) #simgr，angr 的主要入口
simgr.explore(find=0x004017A5,avoid=0x004016E6)
flag =simgr.found[0].posix.dumps(0)[:15]
print(flag)
```

![image-20220216055134015](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-8610a8b33bc93b31259d0e38538ae14e74c7cd7c.png)

本篇文章关于`angr`的部分到此结束，当然`angr`的玩法不止于此，以后再慢慢探索吧。附一张dalao总结的`angr+ctf`玩法

![image-20220216060947347](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-e97c03d8c78b59d39a3b6e3ac91b7d09f404f382.png)

图源链接：<https://blog.csdn.net/lhk124/article/details/110225169?spm=1001.2014.3001.5502>

作者：酸酸菜鱼

0x2回归vm逆向分析—\[UNCTF2019\]easyvm
===============================

研究了这么久的angr了，vm虚拟机保护类题目的常规解法怕是要忘了。做道题复习一下~

运行一下程序发现是匹配字符串。查一下壳发现是64位程序。ida打开后反编译main函数

```c
__int64 __fastcall main(int a1, char **a2, char **a3)
{
  unsigned int (__fastcall ***v3)(_QWORD, void *, void *, char *); // rbx
  char s[96]; // [rsp+10h] [rbp-80h] BYREF
  int v6; // [rsp+70h] [rbp-20h]
  unsigned __int64 v7; // [rsp+78h] [rbp-18h]

  v7 = __readfsqword(0x28u);
  memset(s, 0, sizeof(s));
  v6 = 0;
  v3 = (unsigned int (__fastcall ***)(_QWORD, void *, void *, char *))operator new(0x28uLL);
  sub_400C1E(v3, a2);
  puts("please input your flag:");
  scanf("%s", s);
  if ( strlen(s) != 32 )
  {
    puts("The length of flag is wrong!");
    puts("Please try it again!");
  }
  if ( (**v3)(v3, &unk_602080, &unk_6020A0, s) )
  {
    puts("Congratulations!");
    printf("The flag is UNCTF{%s}", s);
  }
  return 1LL;
}
```

寻找flag的关键逻辑代码是判断s长度是否为32位，如果是，则调用 **v3函数指针所对应的函数，参数分别是v3, &amp;unk\_602080, &amp;unk\_6020A0, &amp;s**。

接下来分析初始化v3的重要函数 sub\_400C1E(v3, a2);发现一个特殊值off\_4010A8 双击跟进

```发现一个特殊值off4010A8
__int64 __fastcall sub_400C1E(__int64 a1)
{
  __int64 result; // rax

  *(_QWORD *)a1 = off_4010A8;
  *(_QWORD *)(a1 + 8) = 0LL;
  *(_BYTE *)(a1 + 16) = 0;
  *(_BYTE *)(a1 + 17) = 0;
  *(_BYTE *)(a1 + 18) = 0;
  *(_DWORD *)(a1 + 20) = 0;
  *(_QWORD *)(a1 + 24) = 0LL;
  result = a1;
  *(_QWORD *)(a1 + 32) = 0LL;
  return result;
}
```

![image-20220216153457181](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-5f5a526429e0921ed0cf574cd47ce471ef5984fe.png)

结合函数400C1E分析，我们发现都是一些函数的偏移量。所以这里也可以知道。v3调用的就是sub\_400806这个函数。接下来分析400806这个函数，我们看到了熟悉的case结构，虚拟机re嘛。

```c
__int64 __fastcall sub_400806(__int64 offset, __int64 constvalue, __int64 checknum, __int64 inputnum)
{
  *(_QWORD *)(offset + 8) = constvalue + 9;
  *(_QWORD *)(offset + 24) = checknum;
  *(_QWORD *)(offset + 32) = inputnum;
  while ( 2 )
  {
    switch ( **(_BYTE **)(offset + 8) )
    {
      case 0xA0:
        (*(void (__fastcall **)(__int64))(*(_QWORD *)offset + 8LL))(offset);
        continue;
      case 0xA1:
        (*(void (__fastcall **)(__int64))(*(_QWORD *)offset + 16LL))(offset);
        continue;
      case 0xA2:
        (*(void (__fastcall **)(__int64))(*(_QWORD *)offset + 24LL))(offset);
        *(_QWORD *)(offset + 8) += 11LL;
        continue;
      case 0xA3:
        (*(void (__fastcall **)(__int64))(*(_QWORD *)offset + 32LL))(offset);
        *(_QWORD *)(offset + 8) += 2LL;
        continue;
      case 0xA4:
        (*(void (__fastcall **)(__int64))(*(_QWORD *)offset + 40LL))(offset);
        *(_QWORD *)(offset + 8) += 7LL;
        continue;
      case 0xA5:
        (*(void (__fastcall **)(__int64))(*(_QWORD *)offset + 48LL))(offset);
        ++*(_QWORD *)(offset + 8);
        continue;
      case 0xA6:
        (*(void (__fastcall **)(__int64))(*(_QWORD *)offset + 56LL))(offset);
        *(_QWORD *)(offset + 8) -= 2LL;
        continue;
      case 0xA7:
        (*(void (__fastcall **)(__int64))(*(_QWORD *)offset + 64LL))(offset);
        *(_QWORD *)(offset + 8) += 7LL;
        continue;
      case 0xA8:
        (*(void (__fastcall **)(__int64))(*(_QWORD *)offset + 72LL))(offset);
        continue;
      case 0xA9:
        (*(void (__fastcall **)(__int64))(*(_QWORD *)offset + 80LL))(offset);
        *(_QWORD *)(offset + 8) -= 6LL;
        continue;
      case 0xAA:
        (*(void (__fastcall **)(__int64))(*(_QWORD *)offset + 88LL))(offset);
        continue;
      case 0xAB:
        (*(void (__fastcall **)(__int64))(*(_QWORD *)offset + 96LL))(offset);
        *(_QWORD *)(offset + 8) -= 4LL;
        continue;
      case 0xAC:
        (*(void (__fastcall **)(__int64))(*(_QWORD *)offset + 104LL))(offset);
        continue;
      case 0xAD:
        (*(void (__fastcall **)(__int64))(*(_QWORD *)offset + 112LL))(offset);
        *(_QWORD *)(offset + 8) += 2LL;
        continue;
      case 0xAE:
        if ( *(_DWORD *)(offset + 20) )
          return 0LL;
        *(_QWORD *)(offset + 8) -= 12LL;
        continue;
      case 0xAF:

        if ( *(_DWORD *)(offset + 20) != 1 )
        {
          *(_QWORD *)(offset + 8) -= 6LL;
          continue;
        }
        return 1LL;
      default:
        puts("cmd execute error");
        return 0LL;
    }
  }
}
```

随便找一个case分析，例如case 0xa9.发现执行offset+80函数指针对应的函数，参数为offset，之后(offset+8)-6，也就是下一个循环将执行0xA3的内容。那就很明白了吗，**每一个字符对应一个函数执行，执行完会按照一定规则跳转到特定字符对应函数执行，直到执行**0xaf（其if判定条件为！=）

依次类推。可以按照这个规则先推到处程序执行switch的顺序  
**0xA9u 0xA3u 0xA5u 0xA6u 0xA4u 0xABu 0xA7u 0xAEu 0xA2u 0xADu 0xAFu**

```php
0XA9(){
    *(_BYTE *)(offset + 16)=*(_BYTE *)(inputnum + *(unsigned __int8 *)(offset + 18))
}

0XA3(){
     *(_BYTE *)(offset + 16) -= *(_BYTE *)(offset + 18)
}

0XA5(){
    *(_BYTE *)(offset + 17) ^= *(_BYTE *)(offset + 16)
}

0XA6(){
    *(_BYTE *)(offset + 16) = 0xCD
}

0XA4(){
    *(_BYTE *)(offset + 16) ^= *(_BYTE *)(offset + 17)
}

0XAB(){
    if ( *(_BYTE *)(offset + 16) == *(_BYTE *)(*(_QWORD *)(offset + 24) + *(unsigned __int8 *)(offset + 18)) )
        *(_DWORD *)(offset + 20) = 0
    else if ( *(_BYTE *)(offset + 16) >= *(_BYTE *)(*(_QWORD *)(offset + 24) + *(unsigned __int8 *)(offset + 18)) )
        *(_DWORD *)(offset + 20) = 1
    else
        *(_DWORD *)(offset + 20) = -1
}

0XA7(){
     *(_BYTE *)(offset + 17) = *(_BYTE *)(offset + 16);
}

0XAE(){
    if ( *(_DWORD *)(offset + 20) )
        return 0
    else
        goto A2()
}

0XA2(){
    ++*(_BYTE *)(offset + 18)
}

0XAD(){
    if ( *(_BYTE *)(offset + 18) > 31u )
         *(_DWORD *)(offset + 20) = 1
    else
        *(_DWORD *)(offset + 20) = 0
}

0XAF(){
    if ( *(_DWORD *)(offset + 20) != 1 )
        goto A9()
    else
        return 1
}
```

该虚拟机的逻辑就是从头开始取字符串的字符（假设i=0），之后减去i，然后与0xCD异或，之后这个对这个值进行判断是否的等于i（这里我们是想要他等于i的）,然后该值自增，i++，当循环到最后一个字符时，如果能够循环31次，那么就可以返回1，也就是我们想要的值。了解了通篇的逻辑，写代码很简单

```python
num='F4 0A F7 64 99 78 9E 7D EA 7B 9E 7B 9F 7E EB 71 E8 00 E8 07 98 19 F4 25 F3 21 A4 2F F4 2F A6 7C'
checknum=list(num.split(' '))
for i in range(len(checknum)):
    checknum[i]=int(str(checknum[i]),16)
flag=""
for i in range(31,-1,-1):
    temp=checknum[i]
    temp^=0xcd
    if i==0:
        count=0
    else:
        count=checknum[i-1] #这种处理是由于我们移植必有正解情况
        temp^=count
        temp+=i
    flag+=chr(temp)
print(flag[::-1])
```

得到flag（ps：这题是可以用angr一把梭的，angr牛b！）

![image-20220216163350665](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-716d56ec77f297ddc1004224200b1235f1d21527.png)

0x3后记
=====

本篇文章主要讨论了vm虚拟机逆向中angr符号执行的妙用，以及更加复杂的vm逆向题目的分析，本篇文章为系列文章的第二篇，下一篇将会研究存在栈结构的虚拟机保护re,敬请期待

0x4参考文章
=======

<https://xz.aliyun.com/t/3990#toc-3>

<https://netsecurity.51cto.com/article/554933.html>

[https://blog.csdn.net/Breeze\_CAT/article/details/106139253?spm=1001.2101.3001.6661.1&amp;utm\_medium=distribute.pc\_relevant\_t0.none-task-blog-2%7Edefault%7EBlogCommendFromBaidu%7ERate-1.queryctrv4&amp;depth\_1-utm\_source=distribute.pc\_relevant\_t0.none-task-blog-2%7Edefault%7EBlogCommendFromBaidu%7ERate-1.queryctrv4&amp;utm\_relevant\_index=1](https://blog.csdn.net/Breeze_CAT/article/details/106139253?spm=1001.2101.3001.6661.1&utm_medium=distribute.pc_relevant_t0.none-task-blog-2~default~BlogCommendFromBaidu~Rate-1.queryctrv4&depth_1-utm_source=distribute.pc_relevant_t0.none-task-blog-2~default~BlogCommendFromBaidu~Rate-1.queryctrv4&utm_relevant_index=1)

<https://blog.csdn.net/lhk124/article/details/110225169?spm=1001.2014.3001.5502>

[https://blog.csdn.net/weixin\_43884935/article/details/104870414](https://blog.csdn.net/weixin_43884935/article/details/104870414)

<https://www.dazhuanlan.com/wsd/topics/1663690>