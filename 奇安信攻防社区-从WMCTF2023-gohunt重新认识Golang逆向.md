前言
==

9.3记，马上就WMCTF2024了，去年这个时候WMCTF2023已经结束了，当时还没有正式入门网安，眨眼就是一年哩。正巧借这个时机复现以下去年的题目，查缺补漏。关于Golang逆向，一直都不太会啊。滴本文重点不在该题上。

gohunt
======

题目是用tinygo编译的，tinygo是一个轻量级的Go语言编译器，主要体现在它生成的代码体积非常小。同样的一个base58编码实现的go程序，正常go build后的体积在2000kb，经过tinygo build的体积仅为500kb。

![image-20240903154325502](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-27509c981e461addc637d8afec0693211c39283a.png)

程序打开main\_main函数足有三千行，某种程度上还是经过优化的...字符串经过了base64编码。

![image-20240903155824269](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-cb23a48b1e3367bdb1378f32099f9ee933283468.png)

第一处字符串加密这里，程序输出Please enter a flag：

![image-20240903160000036](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-4b05e963136c35ddcc2e6ec50c109e32d658ffba.png)

第二处这里xxtea加密的key 动态调试可以得到：FMT2ZCEHS6pcfD2R，测试数据111111，写一个Go程序，使用go get指令导入github的xxtea包。

```go
 package main  
 ​  
 import (  
     "encoding/hex"  
     "fmt"  
 ​  
     "github.com/xxtea/xxtea-go/xxtea"  
 )  
 ​  
 func main() {  
     key := "FMT2ZCEHS6pcfD2R"  
     plaintext := "111111"  
     encryptedData := xxtea.Encrypt([]byte(plaintext), []byte(key))  
     encryptedHex := hex.EncodeToString(encryptedData)  
     fmt.Println("加密后的数据:", encryptedHex)  
 }
```

![image-20240904093539167](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-f85d0b02df9fe0451e461e95cb71f8b41606052e.png)

![image-20240903160149280](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-6c84b76890683dba2b7114669eb902b453ac6fc5.png)

第三处是异或的key：NPWrpd1CEJH2QcJ3，写个python脚本验证一下，明文是上面xxtea后的值。

![image-20240904094811344](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-c26f2422427e05ae48e4ea9273feaeee1e6b3242.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-51b004d08eec04cda18ea55f869af2bf35c86612.png)

最后进行了一次base58编码，该码表可以通过ShiftF12查看字符串发现。base58编码不使用I、l、O、Q和+、-，算是一个比较明显的特点了。

密文从flag.jpg得到，使用QR Research：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-a8466af896a8f4acfda3431cd3cac3e441457482.png)

CyberChef：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-05df6e507a5ea12702ce860049a8f743feedb7d5.png)

```go
 package main  
 ​  
 import (  
     "fmt"  
 ​  
     "github.com/xxtea/xxtea-go/xxtea"  
 )  
 ​  
 func main() {  
     // 定义密钥  
     key := []byte("FMT2ZCEHS6pcfD2R")  
 ​  
     // 提供的字节数组  
     ptr := []byte{0xdb, 0x27, 0xee, 0xea, 0x98, 0xb6, 0xa7, 0x4f, 0x5e, 0xa6, 0x8e, 0xb2, 0xa7, 0x63, 0x00, 0x6b, 0x50, 0xf6, 0xdd, 0xc3, 0x2b, 0x26, 0x49, 0xf0, 0xbb, 0xfe, 0x01, 0x40, 0x80, 0xa7, 0x70, 0xf6, 0x79, 0xb0, 0xcd, 0x8d, 0x20, 0x06, 0xfd, 0x4f, 0xd5, 0x48, 0x26, 0x2e}  
 ​  
     // 提供的密钥  
     keyBytes := []byte("NPWrpd1CEJH2QcJ3")  
 ​  
     // XOR 操作  
     var f []byte  
     for i := 0; i &lt; len(ptr); i++ {  
         f = append(f, ptr[i]^keyBytes[i%16])  
     }  
 ​  
     // 使用 XXTEA 解密  
     decryptData := xxtea.Decrypt(f, key)  
 ​  
     // 输出解密后的数据  
     fmt.Println("解密后的数据:", string(decryptData))  
 }
```

hou言
====

解出来了就感觉挺简单的，无非就是一个xxtea+xor+base58，动调就出key。但我道行太浅，程序如果跟着走，在xxtea之后还会对测试数据进行一次逆序，之后还有近俩百行的代码不知道在干什么（调试的时候又不敢随便跳过，只能慢慢看有没有用），在base58编码之后，也进行了一次逆序（都没用），此后还有俩千行的代码。。。后面了解到都是生成二维码的操作。

初探Golang逆向
==========

从题目开始思考，为什么Go语言编译之后代码量和函数量会激增。

0x1.Go编译过程
----------

Golang自带自定义编译工具链（解析器、编译器、汇编器、链接器），全部都由Go语言编译。

Go编译器在逻辑上可以分为四个阶段，或用前端和后端表示前俩个阶段和后俩个阶段。

![image-20240904153457389](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-60feb88edbfc867c9046c9f27ff0f222f0cce29e.png)

### 解析（词法和语法分析）

编译器首先逐行读取源代码，将源码转换为词法单元（标记Token），如关键字、标识符、运算符、常量、分隔符等。这些标记是编译器处理代码的基本单位。

利用[该代码](https://gist.github.com/blanchonvincent/1f1cb850a436ffbb81df14eb586f52df)可以查看go源代码的Token序列。该代码由go编译器的`src/cmd/compile/internal/scanner`实现。

示例：

```go
 package main  
 ​  
 import (  
     "fmt"  
 )  
 ​  
 func main() {  
     a := 1  
     b := 2  
     add(a, b)  
 }  
 ​  
 func add(a, b int) {  
     fmt.Println(a + b)  
 }
```

![image-20240905095036846](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-0faa8b000d6ab4cfe1e2ac86c1cfe2f22985f2f5.png)

Go编译器内置的词法分析器`src/cmd/compile/internal/syntax`会将这些词法单元传递给语法分析器，语法分析器根据语法规则，将标记组合成具有层次结构的抽象语法树（AST）。AST是程序代码的树状结构表示，展示了各个表达式和语句之间的关系。

AST中每一个节点都表示源代码中的一个元素，每一颗子树都表示一个语法元素。以表达式`2*3+7`为例，语法分析器会生成如下图所示的抽象语法树：

![image-20240905100619539](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-0a32027cb7f715b16041b67a35726436715eccc2.png)

每个语法树都是对应源文件的精确表示，其中的节点对应源文件的各种元素，例如表达式、声和语句。语法树还包括用于错误报告和创建调试信息的位置信息。

### 类型检查和AST转换

编译器会对AST进行类型检查。第一步是名称解析和类型解析，确定哪个对象属于哪个标识符，以及每个表达式的类型。类型检查包括某种额外检查，例如“已声明但未使用”，以及确定函数是否终止。

AST上还会进行某些转换。一些节点会根据类型信息进行细化，例如字符串加法会从算术加法节点类型中分离出来。其它一些示例包括死代码消除、函数调用内联和逃逸分析。

编译器会在这一阶段进行垃圾回收（GC）的准备，首先是对每一个动态分配的对象插入额外的信息，进行标记和跟踪。分析程序中的变量、指针以及对象引用的关系，确保GC能够识别哪些对象是存活的，哪些对象是垃圾。（在此也会生成元数据，帮助GC区分堆、栈上的引用关系。）  
GC还需要知道程序在运行时堆栈的布局结构，以便遍历栈中存储的指针和对象引用。（插入与栈帧布局和内存分配位置相关的信息）。

### SSA生成

SSA（静态单赋值）是中间代码的特性，如果中间代码具有SSA的特性，那么每个变量只会被赋值一次。用下面代码举例：

```go
 x := 1  
 x := 2  
 y := x
```

经过分析，上面代码的`x := 1`不会有任何作用，下面是具有SSA特性的中间代码：

```go
x_1 := 1
x_2 := 2
y_1 := x_2
```

这会，从看上去，就可以知道`y_1`和`x_1`是没有任何关系的。所以在机器码生成的时候就可以省去`x := 1`的赋值，从而减少需要执行的指令优化这段代码。

编译器将源文件转换为AST并对它进行类型检查和转换后，就认为当前文件中的代码不存在语法错误和类型错误了，这时，编译器将输入的抽象语法树转换成具有SSA特性的中间代码。

在AST到SSA的转换过程中，会进行一些通用优化和简化过程，确保代码可以在各种架构上高效运行。  
例如，`copy`内置命令被内存移动取代，`range`范围循环被重写为`for`循环。  
然后，编译器在SSA阶段会应用一系列与具体硬件架构无关的优化规则和传递。这些传递和规则与任何单一计算机架构无关，因此可以在所有`GOARCH`变体上运行。这些传递包括消除死代码、删除不需要的nil检查以及删除未使用的分支。通用重写规则主要涉及表达式，例如用常量值替换某些表达式，以及优化乘法和浮点运算。

编译器除了实现Go的垃圾回收系统，还有一个Go语言的重要特点-并发模型。在此阶段，Go编译器会将`goroutines`的调度机制以及`channel`通信机制转换为更底层的实现。

### 生成机器码

Go编译过程的最后一个阶段就是根据SSA中间代码生成机器码，这一阶段，编译器将经过优化的SSA表示转换为目标机器（x86、ARM）的低级汇编代码或机器码。即将高层次的操作转换为低级指令集（降级操作）。在该阶段还会处理一些低级优化，例如减少内存访问、减少分支跳转、调用约定等细节。

此步骤中完成的其他重要工作包括堆栈框架布局（将堆栈偏移量分配给局部变量）和指针活跃度分析（计算每个 GC 安全点上哪些堆栈指针处于活跃状态）。

在 SSA 生成阶段结束时，Go函数已转换为一系列`obj.Prog`指令。这些指令被传递给汇编器，汇编器将它们转换为机器代码并写出最终的目标文件。目标文件还将包含反射数据、导出数据和调试信息。

### 小结

GO编译器在解析阶段时会为接口匹配、类型断言等功能生成相应的元数据和代码结构，AST还包含用于错误报告和创建调试信息的位置信息。到了第二阶段进行类型检查时会插入对应的检查代码和垃圾回收的相关代码。从AST转换到SSA，GO编译器实现了整个垃圾回收系统和并发模型。最后生成机器码时也会附带许多数据和调试信息。

这里实际上对应了Go编译工具链的几个过程，解析阶段由GO解析器完成；编译器负责将AST转换为SSA；汇编器将SSA转换为机器指令，输出目标文件`.o`。最后一个阶段其实还有链接器，它将编译生成的多个目标文件以及依赖的库文件（静态库和运行时库）整合成一个可执行文件。Go默认采用静态链接方式，这意味着它会讲所有依赖库和运行时（runtime）代码正在在一起。（C/C++通常采用动态链接库，只包含程序代码）

上述种种Go编译过程的操作，使得Go编译后的二进制文件很大且复杂。

0x2 复杂的数据类型
-----------

### 字符串String

Go的字符串类型不是传统C语言中以`0x00`结尾的字符数组。它被表示为一个包含**起始地址**和**长度**的结构：

- `StartAddress`：字符串数据在内存中的起始地址，指向第一个字符。
- `Length`：字符串的长度，表示字符串的字节数。

所以，当一个`string`类型作为参数传递给函数时，实际上是传递俩个值。在汇编层面，函数需要接收俩个参数，而不是一个指向字符串的指针。

如下：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-15897d705f563a4c7b69bba821cb900240c66661.png)

### 切片slice

`slice`是一个数组的某个部分的引用。在内存中，它是一个包含三个域的结构体；指向slice中的第一个元素的指针，slice的长度以及slice的容量。在Go的运行时库中可以看到它的实现（`$GOROOT/src/pkg/runtime/runtime.h`):

```go
struct    Slice
{    // must not move anything
    byte*    array;        // actual data
    uintgo    len;        // number of elements
    uintgo    cap;        // allocated number of elements
};
```

同上，在汇编中，Go函数接收一个silce，实际上是接收了三个参数。如下：

```go
package main

import "fmt"

func main() {
    var nums []int = []int{1, 2, 3, 4, 5}
    fmt.Println(nums)
}
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-79952c1b8455edb48775f4fa6d1a76c4d04640db.png)

### 映射map

Go的map实现是在底层是用哈希表实现的，可以在`$GOROOT/src/pkg/runtime/hashmap.goc`找到它的实现。

```go
type hmap struct {
    count     int
    flags     uint8
    B         uint8    
    noverflow uint16
    hash0     uint32

    buckets    unsafe.Pointer
    oldbuckets unsafe.Pointer
    nevacuate  uintptr

    extra *mapextra
}

type mapextra struct {
    overflow    *[]*bmap
    oldoverflow *[]*bmap
    nextOverflow *bmap
}
```

关键字段：

- count：表示当前`map`中存储的元素数量
- buckets：指向`map`的桶数组，每个桶存储多个键值对
- oldbuckets：扩容时的旧桶数组，用于迁移数据。
- extra：用于处理溢出桶的扩展字段，防止哈希冲突过多时导致性能下降。

每个 `map` 由多个桶（bucket）组成。桶是 `map` 中实际存储键值对的地方。每个桶可以存储多个键值对。

```go
type bmap struct {
    tophash [8]uint8  // 哈希值的高 8 位，用于快速比较和查找
    keys    [8]key    // 存储的键
    values  [8]value  // 存储的值
    overflow *bmap    // 指向溢出桶的指针，处理冲突时用
}
```

当插入一个键值对时，Go 语言会使用哈希函数计算键的哈希值，并根据哈希值将键值对分配到相应的桶中。哈希值的高 8 位存储在 `tophash` 字段中，以便在查找时进行快速比较。

哈希冲突发生时，Go 采用了链式溢出桶的方式进行处理。每个桶中有一个 `overflow` 字段，用来指向溢出桶。当某个桶中的 8 个位置被占满时，多余的键值对会被存储到溢出桶中。

溢出桶和原桶通过 `overflow` 指针相连，形成一个链表。当在一个桶中找不到对应的键时，Go 会依次访问桶的 `overflow` 链表，直到找到键或者到达链表的末尾。

当 `map` 中的桶被过度使用或元素过多时，Go 会自动对 `map` 进行扩容。扩容会创建一个新的、更大的桶数组，并将旧桶中的数据迁移到新的桶中。扩容的触发条件通常是 `map` 的负载因子（即元素数量与桶数量的比值）超过某个阈值。

扩容时，Go 使用渐进式迁移机制，逐步将旧桶中的数据迁移到新桶中，以避免在扩容期间阻塞程序。

在汇编层面，当传递 `map` 类型时，实际上传递的是一个指针，该指针指向 `hmap` 结构体。然后，`hmap` 中的 `buckets` 指针指向桶数组，桶数组存储着具体的键值对。

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-5faace1ac08ba27dd951341b4875a53d79e7db81.png)

`runtime_mapaccess2_faststr`是 Go 运行时的一个函数，用于高效地访问 `map` 中的元素。它接收 `map` 的类型、键等参数，并返回指向 `map` 元素的指针。

`v20`是指向`map`中元素的指针。这个指针实际上指向了`hmap`结构体。`v26`获取`map`中的实际数据，经过`runtime_convT64`进行类型转换，传递给`fmt_Fprintf`函数。

后言
==

初探，后续继续深入。

参考
==

<https://www.anquanke.com/post/id/218377#h2-4>  
<https://tiancaiamao.gitbooks.io/go-internals/content/zh/02.4.html>  
<https://draveness.me/golang/docs/part2-foundation/ch03-datastructure/golang-string/>