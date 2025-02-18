参考
==

[https://xz.aliyun.com/t/12967?time\_\_1311=mqmhqIx%2BODkKDsD7G30%3D3DtQp%2BnYFeD&amp;alichlgref=https%3A%2F%2Fwww.google.com.hk%2F#toc-4](https://xz.aliyun.com/t/12967?time__1311=mqmhqIx%2BODkKDsD7G30=3DtQp%2BnYFeD&amp;alichlgref=https://www.google.com.hk/#toc-4)  
[https://xz.aliyun.com/t/12994?time\_\_1311=mqmhqIhiGKBKDsD7GG7Cbi%3DQDtkInuGD&amp;alichlgref=https%3A%2F%2Fxz.aliyun.com%2Ftab%2F1%3Fpage%3D3#toc-0](https://xz.aliyun.com/t/12994?time__1311=mqmhqIhiGKBKDsD7GG7Cbi=QDtkInuGD&amp;alichlgref=https://xz.aliyun.com/tab/1?page=3#toc-0)

异常处理顺序
======

异常处理顺序：throw -&gt;try中的catch  
throw 函数会从当前函数找，然后往上找上个调用当前函数的函数，查看是否有函数有合适的catch处理模块，当前函数没有合适的catch处理模块就会把当前函数的栈帧给清除掉恢复到调用当前函数的函数，依次这样，知道找到合适的catch处理模块，然后再该模块下继续往后执行

eh\_frame段的作用
=============

```cpp
#include 

void funcB() {
    throw std::runtime_error("Error in function B");
}

void funcA() {
    try {
        funcB();
    } catch (const std::exception&amp; e) {
        std::cout &lt;&lt; "Caught in A: " &lt;&lt; e.what() &lt;&lt; std::endl;
    }
}

int main() {
    try {
        funcA();
    } catch (...) {
        std::cout &lt;&lt; "Caught in main" &lt;&lt; std::endl;
    }
    return 0;
}
```

在这个例子中，`funcB`抛出了一个异常，`funcA`尝试捕获这个异常并处理它。如果`funcA`没有捕获到，异常会继续向上传递到`main`函数。

### 编译过程中的`.eh_frame`生成

当你编译这个程序时（比如使用`g++`编译器），编译器会生成额外的数据结构来支持异常处理流程，这些数据就储存在`.eh_frame`节中。`.eh_frame`包含了一系列被称为“异常表条目”（exception table entries）的信息，每个条目对应于可能抛出异常的函数（在这个例子中主要是`funcB`和含有try-catch块的函数）。

对于上面的代码，`.eh_frame`会记录下如下的关键信息：

- **函数入口点**：每个函数开始执行的位置。
- **着陆垫（Landing Pad）**：异常发生后，控制流应该跳转到哪里去继续执行，通常是异常处理代码的起点。
- **调用帧信息**：如何恢复调用者的状态，包括如何调整堆栈指针、恢复寄存器等，以便正确地从异常发生点恢复到异常处理代码或继续执行。
- **异常过滤信息**：在某些高级用法中，还可以指定哪些类型的异常应该被哪个`catch`块处理。

### 运行时异常处理

当程序运行并且`funcB`抛出异常时，运行时系统会：

1. 查找最近的未处理异常的`catch`块。
2. 使用`.eh_frame`中的信息，计算出如何从当前执行点跳转到对应的`catch`块（即`funcA`中的catch或者如果没有被捕获则到`main`中的catch）。
3. 执行必要的堆栈展开操作，恢复调用者的状态，保证异常处理代码能够在一个正确的上下文中执行。

堆栈展开
====

当运行时系统（如C++运行时库或操作系统的一部分）遇到一个未处理的异常时，它需要确定如何从当前执行点回退到能够妥善处理这个异常的代码位置，这一过程就叫做堆栈展开（stack unwinding）。堆栈展开涉及以下几个关键步骤：

1. **识别异常处理程序**：首先，系统需要知道应该去哪里寻找处理当前异常的代码。`.eh_frame`段包含了一个描述程序调用堆栈的结构化信息，使得运行时系统能够根据当前的调用序列找到最近的合适的`catch`块。
2. **恢复调用者状态**：在异常抛出点和异常处理器之间，可能有多个函数调用层次。堆栈展开的过程中，系统会逆序遍历这些调用层级，对每个调用帧（stack frame）执行必要的清理操作，比如：
    
    
    - 释放局部变量占用的堆栈空间。
    - 调用局部对象的析构函数，以确保资源被正确释放。
    - 重置CPU寄存器到调用该函数前的状态，以便正确返回到调用者上下文。
3. **控制流转移**：完成堆栈上各帧的清理后，运行时系统使用`.eh_frame`中记录的指令或地址信息，跳转到异常处理器（也就是`catch`块）开始执行。这个跳转确保了异常被正确处理，同时保持了程序状态的一致性和完整性。

简而言之，执行“必要的堆栈展开操作”意味着在异常传播路径上，系统要清理已不再需要的函数调用记录，恢复调用者环境，并最终将控制权传递给适当的异常处理逻辑，所有这些操作都是依据`.eh_frame`段提供的指令和数据来精确执行的。

简单劫持
====

```cpp
#include 
#include 
#include 

class x {
    public:
    char buf[0x10];
    x(void) {
        printf("x:x() called\n");
    }
    ~x(void) {
        printf("x:~x() called\n");
    }
};

void test() {
    x a;
    int cnt = 0x100;
    size_t len = read(0,a.buf,cnt);
    if(len &gt; 0x10) {
        throw "Buffer overflow";
    }
}

int main()
{
    try {
        test();
        throw 1;
    }
    catch(int x) {
        printf("Int: %d\n", x);
    }
    catch(const char* s) {
        printf("String: %s\n", s);
    }
    return 0;
}
```

rbp
---

throw函数最后会析构当前函数的变量，如果当前函数有合适的catch处理那么会进行catch处理，否则进行堆栈展开并跳转上一个函数的catch部分

假设溢出到test函数的rbp位置的值  
![图片.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-62dee89e105037430bfaa39c1af30c0753635e03.png)

\_\_cxa\_throw内最终执行到\_Unwind\_Resume后会将rbp置换到原来保存的rbp值也就是test函数的上一个函数的rbp值  
![图片.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-79a7c2d384f7eac57beaa202b090462472998307.png)

跳转到main的异常处理catch后继续往后正常执行leave ret此时会将rsp变成rbp的值然后pop rbp然后ret，也就是ret会跳转到rbp+8的值的位置  
![图片.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-330a7581bfa96fcd9c963d0069023d219c2065bc.png)

ret
---

覆盖rbp和ret，这里注意rbp值要能够访问到，不然也会出错。

从抛出异常到开始执行 catch，包含两个过程：1. 从抛出异常的函数开始，对调用链上的函数逐个往前查找；2.如果没有找到 catch则把程序 abort，否则则记下 存在catch位置，再重新回到抛异常的函数开始清理调用链上的各个函数内部的局部变量并回溯，直到到达所在catch为止。

注意对调用链上的函数逐个往前找时查找位置和当前函数的返回地址有关，原来的返回地址是在try里面，下面正好有对应的catch

将返回地址设置为  
![图片.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-d3917760fecd72de9336e994cc896869fce5a4b0.png)

最后依然成功到达了main的catch处理部分  
![图片.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-77107cd1d433b9a5bca83c3e316e856cd501d86c.png)

如果在catch中呢  
![图片.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-7b599ed2c1ba163bffc6fb5a5677413266a6a6cb.png)

停到0x401276发现不可  
![图片.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-a99aa23f947a38052137c9bbe0541522071cc323.png)

0x0000000000401280试试，也不可  
![图片.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-26e44fc14fdc42fd4f25f098590b495c8836eac7.png)

try catch中间这坨0x0000000000401262试试，\_Unwind\_RaiseException没有调到退出地方，好像可

![图片.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-b9a8f2a61f267a2952a43192f7d01c1f59c7035e.png)

\_Unwind\_Resume正常到main的catch处理部分，那可以

![图片.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-4f437081583744e2be93ea0ac506c1de6280f046.png)  
所以篡改返回地址大概就try部分和try和catch中间那坨可以正常到达返回地址所在的函数的catch部分

- 而且\_Unwind\_RaiseException承担根据返回地址搜寻是否有合适catch的作用，没有最后会跳转到abort那部分
- 当\_Unwind\_RaiseException寻找到有合适的才会析构当前函数对象然后进入\_Unwind\_Resume，最后跳到对应catch处理部分

chop
====

[https://download.vusec.net/papers/chop\_ndss23.pdf](https://download.vusec.net/papers/chop_ndss23.pdf)

```cpp
静态编译
g++ -no-pie -g  -static llk.c -o llk
```

```cpp
#include 
#include 
#include 

class x {
    public:
    char buf[0x10];
    x(void) {
        printf("x:x() called\n");
    }
    ~x(void) {
        printf("x:~x() called\n");
    }
};

void backdoor()
{
    system("/bin/sh");
}

void test() {
    x a;
    int cnt = 0x100;
    size_t len = read(0,a.buf,cnt);
    if(len &gt; 0x10) {
        throw "Buffer overflow";
    }
}

int main()
{
    try {
        test();
        throw 1;
    }
    catch(int x) {
        printf("Int: %d\n", x);
    }
    catch(const char* s) {
        printf("String: %s\n", s);
    }
    return 0;
}
```

当程序抛出一个异常，而该异常没有被适当的catch块捕获时，控制权会转交给\_\_cxa\_call\_unexpected函数

```cpp
在ubuntu22.04上为__cxa_call_unexpected() ==&gt; __cxa_call_unexpected.cold() ==&gt;  (), 大略代码如下：

void __cxa_call_unexpected (void *exc_obj_in) {
 try { /* ... */ }
 catch (...) {
    __cxa_call_unexpected_cold(a1)
 }
}

void _cxa_call_unexpected_cold(void *a1) {
    void (*v2)(void); // r12
    void *retaddr; // [rsp+0h] [rbp+0h] BYREF
    /*...*/
    if (!check_exception_spec(&amp;retaddr, ...)) {
        if (check_exception_spec(&amp;retaddr, ... )) {
          /*...*/
          _cxa_throw();
        }
        __terminate(v2);
    }
}

void __terminate (void (*handler)()) throw () {
 /* ... */
 handler();
 std::abort();
}
```

![图片.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-0861330c356ef47eb2e87883eeb5d76738942617.png)

需要控制局部变量进入\_cxa\_call\_unexpected\_cold()中\_\_terminate的分支，防止中途再次抛出异常或是直接crash掉进程，terminate执行的函数指针是寄存器r12的值

利用到.eh\_frame上的信息将栈上数据与寄存器做以联系，从而控制寄存器

`readelf` 是一个在类Unix系统上用于显示ELF格式可执行文件、目标文件、共享库等内部结构的工具。它是GNU Binary Utilities（binutils）套件的一部分。当你在命令行中使用 `readelf` 加上不同的选项和文件名，可以获取关于该文件的详细信息。

命令 `readelf -wF file` 的意义分解如下：

- `readelf`: 这是命令本身，用于读取和解析ELF（Executable and Linkable Format，可执行与可链接格式）文件。
- `-w`: 这个选项告诉 `readelf` 显示DWARF调试信息。DWARF是一种常用的调试文件格式，它包含了源代码级别的调试信息，如变量名、函数名、行号信息等，使得调试器能够提供源代码级的调试体验。
- `-F`: 当与 `-w` 一起使用时，这个选项会让 `readelf` 显示DWARF信息中的框架信息（Frame Information）。框架信息对于理解函数调用堆栈、局部变量布局以及异常处理非常重要。
- `file`: 这里替换为你要分析的具体文件名。它应该是你想要查看其DWARF调试信息中框架部分的 ELF 格式文件，比如一个可执行文件或者库。

`readelf -wF file` 命令的作用是展示指定ELF文件中的DWARF调试信息的框架部分

![图片.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-b18be52155e3e6b80470b5ef2d0e4ab2acf54930.png)

### 1. 异常发生时的堆栈保存

当程序中抛出一个异常时，首先异常处理机制会保存当前的执行上下文，包括程序计数器（PC）、栈指针（SP）以及其他寄存器的状态。这是通过硬件和操作系统共同完成的，确保了在异常处理完成后能够回到异常发生前的执行状态。

### 2. 查找`.eh_frame`信息

接着，异常处理机制会根据当前的PC（程序计数器）在`.eh_frame`节中查找对应的FDE（Frame Description Entry）。`.eh_frame`是ELF文件格式的一部分，存储了异常处理所需的信息，包括函数的堆栈帧布局和异常处理流程。

### 3. 解析FDE并恢复CFA

找到匹配的FDE后，异常处理机制会解析CFA（Canonical Frame Address）和各个寄存器的偏移量信息。CFA是理解当前堆栈帧布局的关键，它通常是指向当前栈帧底部的某个参考点，比如栈指针减去一定偏移量。通过FDE中描述的规则，异常处理程序知道如何从CFA计算得到各个寄存器的值。

### 4. 恢复寄存器

根据FDE中的规则，异常处理机制会从当前的堆栈中恢复寄存器的值。例如，如果规则指出`rbp`寄存器的值在CFA之下16字节处，异常处理程序就会从当前栈顶指针减去16字节的位置读取`rbp`的值并将其恢复到寄存器中。这个过程会重复进行，直到所有需要恢复的寄存器都按照规则恢复完毕。

### 5. 堆栈展开

在寄存器恢复之后，异常处理机制还需要进行堆栈展开，即逐步弹出函数调用栈中的帧，直到找到能够处理当前异常的catch块。这个过程同样依赖于`.eh_frame`中的信息，通过迭代地应用FDE中的规则来逐步恢复调用链上各函数的堆栈状态。

### 6. 转向异常处理逻辑

最后，当异常被正确地传递给一个catch块时，控制权会转移给catch块中的代码，程序可以从异常发生点之后继续执行，此时寄存器和堆栈已经恢复到一个已知的、安全的状态。