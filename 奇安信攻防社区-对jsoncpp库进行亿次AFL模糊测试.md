0x01 关于AFL
==========

（一） **模糊测试fuzzing与AFL**
-----------------------

模糊测试（Fuzzing），是一种通过向目标系统提供非预期的输入并监视异常结果来发现软件漏洞的方法。它是一种挖掘软件安全漏洞、检测软件健壮性的黑盒测试，它通过向软件输入非法的字段，观测被测试软件是否异常而实现。

模糊测试（Fuzzing）不需要过多的人为参与，也不像动态分析那样要求分析人员有丰富的知识。在模糊测试中，用随机数据攻击一个程序，然后等着观察哪里遭到了破坏。模糊测试的技巧在于，它是不符合常规逻辑的：自动模糊测试不去猜测哪个数据会导致破坏，将尽可能多的杂乱数据投入程序中。从而发现哪些输入能够使程序发生异常，进而分析可能存在的漏洞。当前比较成功的Fuzzer（执行模糊测试的程序）有AFL、libFuzzer、OSS-Fuzz等。

AFL（American Fuzzy Lop）是由安全研究员Michal Zalewski开发的一款基于覆盖引导（Coverage-guided）的模糊测试工具，它通过记录输入样本的代码覆盖率，从而调整输入样本以提高覆盖率，增加发现漏洞的概率。

AFL工作流程大致如下：

·从源码编译程序时进行插桩，以记录代码覆盖率（Code Coverage）；

·选择一些输入文件，作为初始测试集加入输入队列（queue）；

·将队列中的文件按一定的策略进行“突变”；

·如果经过变异文件更新了覆盖范围，则将其保留添加到队列中;

·上述过程会一直循环进行，期间触发了crash的文件会被记录下来。

![wps1.jpg](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-6ea362b73a31fc594e7f5c31607fc176e563c8dd.jpg)

（二） **AFL插桩**
-------------

有源码时则在编译时对源码进行插桩，常规模式为在汇编语言上进行插桩，LLVM模式在LLVM编译器的中间代码中进行插桩，可以提高性能。

无源码时使用动态qume模式进行插桩。

（三） **AFL结果分析**
---------------

在输出目录中创建了三个子目录并实时更新

queue/:每个独特的执行路径的测试用例，加上用户给出的所有开始文件。crashes/:导致被测试程序接收致命信号的唯一测试用例,这些条目按接收到的信号分组。hangs/ 导致被测试程序超时的唯一测试用例。在某些东西被归类为挂起之前的默认时间限制大于1秒和-t参数的值。

\\1) Process timing 指示了Fuzzer测试的时间消耗

process timing 指示了Fuzzer测试的时间消耗。run time: 运行总时间。last new path: path(触发新执行的测试用例的缩写)，上次执行测试用例的时间,长时间未变化说明有程序有问题，过于简单无分支或内存太小会收到一个红色警告。

last uniq crash: 上次崩溃的时间。last uniq hang: 上次挂起的时间。

\\2) Overall results 汇总了fuzzer测试的执行结果。

cycle done: 表明fuzzer的轮数。品红色处于 the first pass，如果有新发现，颜色会变成黄色，所有子过程完成后将会变成蓝色，最后变成绿色的话表明已经长时间没有新的动作了，此时也提示我们应该手动ctrl-c去关闭fuzzing。

total paths: 目前为止执行的测试用例。uniq crashes: 目前为止发现的崩溃。uniq hang: 目前为止发现的挂起。

\\3) Cycle progress 展示了当前队列中fuzzer 执行了多少。

ow processing: 当前测试用例的进程的ID 因为fuzzer是开启另一个进程进行测试的 结果写回共享内存中。paths timed out: 根据超时决定是否放弃。

\\4) Map coverage

map density：多少个分支元组,命中，与位图的容量成比例.号码在左边描述当前输入;右边的是整体的值是输入语料库。count coverage：另一行处理元组命中次数的可变性二进制文件。

\\5) Stage progress 进一步展示了fuzzer的执行过程细节。

now trying: 指明当前所用的变异输入的方法，包括确定性的比特位翻转、确定性的算术运算、确定性的值覆盖、确定性的字典注入、固定长度的堆叠随机扭曲等方式。

stage execs: 当前阶段的进度指示。total execs: 全局的进度指示。exec speed: 执行速度但是基准测试应该理想地超过500次执行/秒。

\\6) Findings in depth 应该是种子变异产生的信息

favored paths: 基于最小化算法产生新的更好的路径。new edges on: 基于更好路径产生的新边。total crashes: 基于更好路径产生的崩溃。total tmouts: 基于更好路径产生的超时 包括所有超时的超时 即使这些超时不足以分类到hangs。

\\7) Fuzzing strategy yields 进一步展示了AFL所做的工作，在更有效路径上得到的结果比例，针对的应该是上文的 stage progress的now trying一栏的参数。

\\8) Path geometry 汇总了路径测试的相关信息。

levels: 表示测试等级。pending: 表示还没有经过fuzzing的输入数量。pend fav: 表明fuzzer感兴趣的输入数量。own finds: 表示在fuzzing过程中新找到的，或者是并行测试从另一个实例导入的。imported: n/a表明不可用，即没有导入。stability: 表明相同输入是否产生了相同的行为，一般结果都是100%。

0x02 **AFL编译测试步骤**
==================

（一） **AFL与jsoncpp\_master的编译使用**
--------------------------------

安装AFL后将文件afl-clang和afl-clang++复制到系统路径/usr/bin/，供后续jsoncpp插桩编译前export指定终端编译器使用。

![wps2.jpg](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-95a26bfa67a9e2bdb4b08d4fa143d6ee0f842164.jpg)

jsoncpp是一个开源C++库,提供对JSON字符串序列化/反序列化的功能。 jsoncpp主要包含三种类型的C++类 - value、reader、writer。value表示json对象和数组。reader用于反序列化json字符串。writer用于序列化json字符串。

Jsoncpp是一个开源的C++库，正常的编译过程无法生成有效的可执行文件，但是可以通过cmake编译生成链接库文件libjsoncpp.a，将该链接库文件与其他需要引用的头文件添加到系统文件夹中以方便调用。

![wps3.jpg](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-bf39581fa61dc723e8120370fdc1d6ddfd5d7d27.jpg)

需要编写main程序调用jsoncpp库以实现有输入的可执行程序，为了对jsoncpp库进行AFL的模糊测试，需要对jsoncpp库的编译过程进行afl插桩，调用AFL的afl-g++/afl-gcc代替g++/gcc编译器进行编译并插桩。

![wps4.jpg](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-0396aeeb0657fb9c742f7a5253ca398127fbfeb0.jpg)

![wps5.jpg](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-4761c36dba8969839d641b7c7916de9e21f5bb9b.jpg)

将编译生成的jsoncpp.a文件拖入ida中查看插桩效果，基本块都插入了一可以看到afl在代码段进行了插桩，主要是 \_\_afl\_maybe\_log 函数，用来探测、反馈程序此时的状态。

![wps6.jpg](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-55564508ec0883bd4c93aa7a9a9971b2ce797c99.jpg)

编写具有自定义输入的文件调用库文件，由于已经对于我们想要测试的主体jsoncpp库进行了插桩编译，此main调用程序利用gcc/g++进行正常的编译即可。

![wps7.jpg](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-6bef60cb90c2b30df221c64ed546efa226be3ca4.jpg)

Main文件中的思路框架为，创建一个Value结构体，然后利于Reader解析json文件并输出，利用FastWrite写入并保存json文件，借此以测试其Value、reader、write功能：

![wps8.jpg](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-2d1715a2e79da8bcf9507839244cd6adb82e506b.jpg)

（二） **测试用例处理**
--------------

[JSON](https://baike.baidu.com/item/JSON)([JavaScript](https://baike.baidu.com/item/JavaScript) Object Notation, JS 对象简谱) 是一种轻量级的数据交换格式。它基于 [ECMAScript](https://baike.baidu.com/item/ECMAScript) (欧洲计算机协会制定的js规范)的一个子集，采用完全独立于编程语言的文本格式来存储和表示数据。简洁和清晰的层次结构使得 JSON 成为理想的数据交换语言。 易于人阅读和编写，同时也易于机器解析和生成，并有效地提升网络传输效率。

首先从网站下载json文件作为测试用例，然后进行fuzzing，这里提示说有太多的文件，可以使用afl-cmin或者afl-tmin进行修剪。

![wps9.jpg](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-ac1c4e49a1f647ab4f8177a9de9cd3598f9bbdbb.jpg)

afl-cmin的作用为移除执行相同代码的测试用例，afl-cmin的核心思想是：尝试找到与语料库全集具有相同覆盖范围的最小子集。 操作进行时，每次用一个文件跟之前的比较，如果能达到上一个的效果，就替换掉上一个文件。整体的大小得到了改善，接下来还要对每个文件进行更细化的处理。afl-tmin为减少单个输入文件的大小，afl-tmin有两种工作模式，instrumented mode和crash mode。默认的工作方式是instrumented mode。命令语句分别为：

```js

afl-cmin -i fuzz\_in -o fuzz\_in\_cmin ./afl\_test  
​  
afl-tmin -i testcase -o fuzz\_in\_tmin/testcase\_tmin ./afl\_test
```

如果指定了参数-x，就会调用crash mode模式，会把导致程序非正常退出的文件直接剔除。

由于我所找的测试json文件为省区地图数据，数据结构大致相同，所以在cmin剪枝后仅仅剩下了一个文件，如有需要还可以利用tmin再次缩减。

![wps10.jpg](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-ad1a07de0863f9a740d8a6e441abf0553e06072a.jpg)

（三） **Fuzzing**
---------------

### 1．字典

afl-fuzz变异引擎针对紧凑型数据格式，即图像，多媒体，压缩数据，正则表达式语法或shell脚本进行了优化。为了避免构建语法感知工具的麻烦，afl-fuzz提供了一种使用语言关键字，magic header或其他与目标数据类型相关联的特殊表示的可选字典为模糊过程提供种子的方法 - 并且使用它来重建底层语法。

要使用这个功能，首先需要创建在dictionaries/README.dictionaries中讨论的两种格式之一的字典；然后在命令行中使用-x选项将fuzzer指向它。（在该目录的子目录下已经提供了几个常用字典）。

如果没有办法提供更多结构化的底层语法的描述，但是fuzzer可能会根据单独的插桩反馈来找出其中的一些。即使当没有给出明确的字典时，afl-fuzz将通过在确定性字节翻转期间非常仔细地观察插桩来尝试提取输入语料库中的现有语法表示（token-表示，记号）。 这适用于一些类型的解析器和语法，但不像-x模式那么好。

针对于我本次的实验的实验对象是jsoncpp，输入文件为json文件，恰好AFL中自带了json的字典文件json.dict，可以供我直接使用。

![wps11.jpg](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-8089822194f21486325bac30a5fdf2b793f60640.jpg)

可以使用语句进行字典模块的调用：

```js
 afl-fuzz -x json.dict -m none -i ./input -o ./out ./xxx @@
```

### 2．多核并行测试

每一个afl-fuzz进程都需要占用一个内核。这意味着在多核系统中，为了充分利用硬件资源，并行化是必须的。并行fuzzing模式提供了一个为AFL接口与其他模糊器，符号执行或者concolic混合符号执行引擎等连接的简单方法。

首先建立一个空的输出文件夹，这个文件夹可以被多个afl-fuzz程序所共享，

```js
Run the first one ("master", -M) like this:  
    $ ./afl-fuzz -i testcase\_dir -o sync\_dir -M fuzzer01 \[...other stuff...\]  
    ...and then, start up secondary (-S) instances like this:  
    $ ./afl-fuzz -i testcase\_dir -o sync\_dir -S fuzzer02 \[...other stuff...\]  
    $ ./afl-fuzz -i testcase\_dir -o sync\_dir -S fuzzer03 \[...other stuff...\]
```

-M和-S模式的区别在于，主实例仍然将执行确定性检查；而次实例将直接进行随机调整。如果根本不想做确定性模糊，可以使用-s运行所有实例。

每个实例还将定期为其他fuzzing发现的任何测试用例重新扫描目录，当它们被认为足够有趣时，将将它们合并到自己的fuzzing中。

结合字典测试其命令为：

```js
$ ./afl-fuzz  -x json.dict -m none -i testcase\_dir -o sync\_dir -M fuzzer01 \[...other stuff...\]  
​  
$ ./afl-fuzz  -x json.dict -m none -i testcase\_dir -o sync\_dir -S fuzzer02 \[...other stuff...\]  
​  
$ ./afl-fuzz  -x json.dict -m none -i testcase\_dir -o sync\_dir -S fuzzer03 \[...other stuff...\]
```

### 3．内存错误检查工具（ASAN）

ASAN(Address Sanitizer)是linux下的内存检测工具，早先是LLVM中的特性，后来被加入GCC 4.9，现被clang和gcc支持，用于运行的时候对内存进行检测，以达到发现内存漏洞的效果。

例如越界读等内存访问错误不一定会造成程序的崩溃，所以在没有开启ASAN的情况下，许多内存漏洞都无法被AFL给发现。在开启ASAN后，afl插桩则会在目标代码的关键位置添加检查代码，例如：malloc(),free()等，一旦发现了内存访问错误，便可以SIGABRT中止程序。

ASAN是GCC支持的一个性能，所以，在使用ALF对软件进行编译之前，只需要设置环境变量即可，指令如下：

![wps12.jpg](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-9676ad6012f876267ca18b8ba3c076591d77849f.jpg)

然后按照之前编译的方式进行编译，然后查看是否成功开启ASAN，方式为查看其编译后的文件是否存在插桩关键字。

![wps13.jpg](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-6b590682d50fcc01885e9d775ea801c5c6521817.jpg)

ASAN开启后的fuzzing会消耗更多的内存，这是需要注意的因素，对于32位的程序，基本上800MB即可；但64为程序大概需要20TB。所以，使用ASAN的时建议添加CFLAGS=-m32来限制编译目标为32位或者alf-fuzz的时候通过选项-m来指定使用的内存上限。

### 4．持久模式

在AFL的默认模式下，每当AFL运行程序时，它都会使用系统调用fork()来创建一个新的子进程。但是，由于这个系统调用的开销非常大，从而会严重拖慢整个模糊测试过程。当使用持久模式时，Fuzzer会重复使用同一个进程。这样做的唯一的要求是，在每次循环运行时都要擦除所有变量和缓冲区。

安装llvm和clang，然后会有 afl-clang-fast 和 afl-clang-fast++ 两个命令，用这两个命令来编译目标应用。即可使用持久模式。

```js
• \*export LLVM\_CONFIG=/usr/bin/llvm-config-\*\*6.0设置环境变量。\*
```

就可以调用afl-clang-fast和 afl-clang-fast++ 两个命令进行编译。

![wps14.jpg](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-51705baa8ed82f8285858c23fa1b22366a0ca893.jpg)

### 5．综合测试

综合上述功能进行测试，首先通过引入环境变量设置ASAN和afl-clang编译器，对库文件进行编译，将该文件移动到系统文件夹，然后写main程序调用该库，再利用g++进行编译获得可执行程序。

![wps15.jpg](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-6e3f19f0ba59203654a17306e8934186ef3de1cb.jpg)

![wps16.jpg](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-96cce97eceb69127275ed1552dd09f81264be4ae.jpg)

然后设置使用json.dict字典，同时调用多核进行afl的并行测试。所选用的测试用例为精简化处理后的测试用例。

（四） **关于havoc的资料理解**
--------------------

在查找相关的资料的时候，对于havoc的编译策略，AFL的做法，是将一系列变异随机组合到一起来看，能否基于字符的“重要程度”有倾向地havoc，去提高路径覆盖率。

一般来说，文件可以分为“元数据”和“数据”两部分。例如，ELF文件中，program header, section header等属于“元数据”，而具体的指令就属于“数据”。文件解析工具会首先读取“元数据”，获取所需的flag, offset, length等，然后再根据这些信息，去读取和处理“数据”。于是，从我们的直觉和经验来讲，相比对“数据”的变异，变异“元数据”往往更容易引起新路径，从而也是性价比更高的方式。一个极端的例子就是，如果我们有一张json文件，那么即使把所有的{xx:yy}中的xx和yy全部变异掉，得到的也只是一张看上去完全不同的文件，从代码执行路径的角度来看并没有什么不同。于是，在havoc阶段，如果我们能提高“元数据”被变异的概率，那么新路径的发现概率，应该也会提高。

随着对文件的不断变异，最初的“元数据”仍然是“元数据”的概率，也在逐渐减小。那么当这个概率降到一定程度时，最初的”元数据“信息已经不够准确，不再具有参考价值。此时，我们可以更新”元数据“信息，再指导之后的变异；我们最终使用的是另一种更省事的方法，即直接恢复到原始havoc的方式，进行无指导的随机选取。

有了改进的基本思路。但是，如何判断一个文件中，哪些bytes是”元数据“，哪些bytes是”数据“，就是另一个关键问题了，而且这个问题需要利用数学上的一些知识去解决。

0x03 **crash**分析
================

重新以-g模式编译main测试文件，并且对crash得到的poc进行复现测试，结果如下：

查看其poc数据：

![wps17.jpg](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-8c3535a61b46dfdbf1f43d0bf4818adda42545eb.jpg)

![wps18.jpg](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-29774fc0f87a75cc343303908d313221ebb136c5.jpg)

运行测试结果：

多个文件都报这个同样同位置的错误，栈溢出造成的程序崩溃，说明爆出来的crash并不是unique，是存在重复的。

![wps19.jpg](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-ccc4e05c9ce8d39e93b2f88aed71a7c14f87241b.jpg)

0x04 **结果**
===========

在综合测试中我利用了四个核进行并行测试，共计完成测试1亿余次。运行总时间约24小时，每个进程fuzzer的轮数约为平均90轮。Totalpath约为3000左右。map density约为2% / 4%。count coverage约为5bits/tuple。 5) Stage progress 进一步展示了fuzzer的执行过程细节。Cpu的利用率约为150%，平均每个进程发现20个unique crash。

![wps20.jpg](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-fb570e11adb008e78d0c55bdb6113c9f44419ae9.jpg)

![wps21.jpg](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-39185733dd240fd2cc6693d53df3c22746405c53.jpg)

![wps22.jpg](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-f1cfc77681dcfbc483e0329c17e5bc34ad065b30.jpg)

![wps23.jpg](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-b93b22fbf083cac2def6b81ed2e553fd1ad7d5d4.jpg)

对测试数据进行可视化展示（部分数据）：

![wps24.jpg](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-270cdccfc164a5490d2dcda1d5aad5dc756906b8.jpg)

0x05 **问题与解决**
==============

**1.** ***\*关于M主进程测试速度明显慢于S副进程的问题。\****
---------------------------------------

在实验的过程中，我发现在M主进程里面运行的速度比较慢，而其他的几个副进程运行速度比较快，我认为这是主进程在变异策略方面对测试用例进行了更多的变异，所有的变异类型都有所展现，而副进程仅仅运行最后两种编译策略，这个从ui的fuzzing stratragy yield的数据展示中可以看出来。

**2.** ***\*关于crash重复的问题\****
-----------------------------

经过前十几个crash文件的验证，发现重复性特别高，虽然crash文件内容不一样，但是触发的漏洞位置和类型一模一样，虽然AFL将这些poc定义为unique，但是这种crash其实并不unique，而且很多crash并不能触发真正的漏洞，是假crash。

**3.** ***\*关于havoc改进中元数据的区分\****
---------------------------------

对于这个想法在元数据与基础数据的自动区分这个关键问题上还没有很好的想法，不是很好解决。

**4.** ***\*关于测试速度的问题\****
--------------------------

我的测试用例的速度大致为400/sec，整体速度偏慢，我认为这有两个方面的原因，一个是我所测试的程序为一个json的解析、生成库，为了提高代码覆盖率，我在编写测试程序main时同时引用了库中value、read、write三个功能，造成了测试的代价增大；另一个原因是我的测试用例偏大，cmin处理后没有进行tmin处理，造成了速度的降低。