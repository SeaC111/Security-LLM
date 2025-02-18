源码分析关注两个方面，第一个方面关注afl-gcc的插桩方式，第二个方面关注afl-fuzz模式，和变异模式。

为了方便下面的分析，需要先了解一点知识，首先看一下AFL的makefile

```c
afl-gcc: afl-gcc.c $(COMM_HDR) | test_x86
    $(CC) $(CFLAGS) $@.c -o $@ $(LDFLAGS)
    set -e; for i in afl-g++ afl-clang afl-clang++; do ln -sf afl-gcc $$i; done

afl-as: afl-as.c afl-as.h $(COMM_HDR) | test_x86
    $(CC) $(CFLAGS) $@.c -o $@ $(LDFLAGS)
    ln -sf afl-as as
```

可以知道afl-g++等都是指向afl-gcc的，且都是由afl-gcc.c编译出来的。

此外afl-fuzz有三种模式

- 普通模式 汇编层面插桩，一般用gcc和clang
- llvm模式，编译层面为程序插桩，适用于clang，一般使用afl-clang-fast编译
- qemu模式，通过修改qemu的代码，在模拟程序运行的时候，记录程序路径起到类似于插桩的效果。  
    这次分析afl-fuzz.c只涉及到第一个模式llvm模式和qemu的源码后续再看

afl-gcc
=======

选择先看gcc的源码，因为就300+很好看，核心函数只有三个`find_as`，`edit_params`，`main`，前面的学习中可以知道afl-gcc本质上就是在系统的gcc编译器的上层添加了一个wrapper，具体分析如下：

find\_as函数
----------

函数原型`static void find_as(u8* argv0)`，这个函数使用来寻找`afl-as`的位置，下面看代码。

```c
static void find_as(u8* argv0) {

  u8 *afl_path = getenv("AFL_PATH");
  u8 *slash, *tmp;
  if (afl_path) {
    tmp = alloc_printf("%s/as", afl_path);
    if (!access(tmp, X_OK)) {//如果存在该文件
      as_path = afl_path;
      ck_free(tmp);
      return;
    }
    ck_free(tmp);
  }
  slash = strrchr(argv0, '/');//查找是否存在/
  if (slash) {
    u8 *dir;
    *slash = 0;
    dir = ck_strdup(argv0);//去除空格
    *slash = '/';
    tmp = alloc_printf("%s/afl-as", dir);
    if (!access(tmp, X_OK)) {
      as_path = dir;
      ck_free(tmp);
      return;
    }
    ck_free(tmp);
    ck_free(dir);
  }
  if (!access(AFL_PATH "/as", X_OK)) {
    as_path = AFL_PATH;
    return;
  }
  FATAL("Unable to find AFL wrapper binary for 'as'. Please set AFL_PATH");
}
```

- 首先查找`AFL_PATH`环境变量，如果存在该环境变量则赋值给afl-path，然后查找`afl_path/as`是否可以访问，如果可以访问把afl-path赋值给as\_path。
- 如果不存在环境AFL\_PATH，则查找第一个参数的最后一个字符是不是/，如果是则去掉这个字符，把身下的作为dir，例如`/home/tamako/afl-gcc`后面是否存在/，检查完毕之后，检测`dir/afl-as`是否可以访问，如果可以访问，则设置为as\_path
- 以上都不行，则FATAL抛出错误

通过环境变量和参数来查找`as`的位置，环境变量的优先级高于参数，找到`as`位置之后，将值传递给`as_path`。

edit\_params
------------

对于该函数，有一条注释

> Copy argv to cc\_params, making the necessary edits

看注释可以知道，该函数是把参数复制到cc\_params，然后做一些必要的编辑。  
函数比较长，就不贴了，下面说一下该函数的主要流程。

- 首先ck\_alloc函数申请了一大片空间给cc\_params
- 接下来查找第一个参数的最后一个字符，如果不是 / 那么将参数一赋值给name，如果是 / 那么将 / 后面的东西（可执行文件名字）赋值给name
- 将name的前9个字符和`afl-clang`进行比较 
    - 如果name是afl-clang，那么设置`clang_mode=1`然后设置`CLANG_ENV_VAR`环境变量为1，然后比较name和`afl-clang++`
        - 接下来又是一个if判断，该判断中设置了cc\_params\[0\]，通过前面的比较，可以得出编译需要的是gcc还是g++
        - 然后获得环境变量中的`AFL_GXX或者AFL_CC`，如果没有设置环境变量，那么就赋值为clang或者clang++
    - 如果名字不是`afl-clang`，那么就和afl-gcc以及afl-g++，gcj比较。

```c
  while (--argc) {
    u8* cur = *(++argv);

    if (!strncmp(cur, "-B", 2)) {

      if (!be_quiet) WARNF("-B is already set, overriding");

      if (!cur[2] && argc > 1) { argc--; argv++; }
      continue;

    }

    if (!strcmp(cur, "-integrated-as")) continue;

    if (!strcmp(cur, "-pipe")) continue;

#if defined(__FreeBSD__) && defined(__x86_64__)
    if (!strcmp(cur, "-m32")) m32_set = 1;
#endif

    if (!strcmp(cur, "-fsanitize=address") ||
        !strcmp(cur, "-fsanitize=memory")) asan_set = 1;

    if (strstr(cur, "FORTIFY_SOURCE")) fortify_set = 1;

    cc_params[cc_par_cnt++] = cur;

  }
```

处理完编译器之后，继续处理参数，参数大部分都是continue，后面少数几个选项，设置了几个标志位。

- 如果存在`-fsanitize=address`或者`-fsanitize=memory`，就设置asan\_set为1;
- 如果存在`FORTIFY_SOURCE`，则设置fortify\_set为1
- `cc_params[cc_par_cnt++] = cur`; 其中的cc\_par\_cnt应该是作为index出现
- 后面依旧是设置参数 
    - 首先是设置-B和前面在find\_as中计算出来的as\_path，`-B as_path`
    - 如果设置了clang\_mode 那么添加 `-no-integrated-as` 参数。
    - 接下来检查`AFL_HARDEN`，如果设置了该环境变量则添加`-fstack-protector-all`（我也不知道开这个保护有什么用） 
        - 同时检查`fortify_set`，设置`-D_FORTIFY_SOURCE=2`参数。  
            sanitizer
- 检查asan是否被设置为1，如果为1，则设置AFL\_USE\_ASAN为1
- asan不为1，检查环境变量AFL\_USE\_ASAN，如果存在，则设置后续参数为`-U_FORTIFY_SOURCE -fsanitize=address`
- AFL\_USE\_MSAN如果被设置，则参数为`-U_FORTIFY_SOURCE -fsanitize=memory`  
    但是MASN和ASAN不能被同时使用，否则会抛出异常。
- 检查**&lt;font color="#ff0000"&gt;AFL\_DONT\_OPTIMIZE&lt;/font&gt;**环境变量有没有被设置，如果没有被设置，则添加参数`-g -O3 -funroll-loops -D__AFL_COMPILER=1 -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION=1`(x86和freebsd下面，如果开了clang mode和m32则没有-g参数)
- 若设置了**&lt;font color="#ff0000"&gt;AFL\_NO\_BUILTIN&lt;/font&gt;**环境变量，则添加`-fno-builtin-strcmp`等参数
- 最后执行`cc_params[cc_par_cnt] = NULL;`，作为参数的截止符

该函数主要是添加了一个-B参数，该参数指定了劫持的as的路径，即不使用原本的as汇编，而使用afl-as汇编，同时，该函数对ASAN，clang mode等设置了flag，且将环境编译的`GXX GCC`都做了设置。

main函数
------

main函数总结起来就只有三行

```c
  find_as(argv[0]);
  edit_params(argc, argv);
  execvp(cc_params[0], (char**)cc_params);
```

结合起来看，首先找到`afl-as`的路径，然后重新编辑一些参数，最后执行改变参数之后的程序，从意义上看只是对as的路径进行了劫持和修改，可以打印一下其中的参数。

```c
  find_as(argv[0]);
  for (int i = 0; i < argc; i++) {
      printf("\targ%d: %s\n",i,argv[i]);
  }
  edit_params(argc, argv);
  printf("\n");
  for (int i = 0; i < 15; i++) {
    printf("\targ%d: %s\n",i,cc_params[i]);
  }
```

```shell
afl-cc 2.57b by <lcamtuf@google.com>
    arg0: /home/tamako/Desktop/FUZZ/AFL_debug/AFLcpp/afl-gcc
    arg1: -g
    arg2: -o
    arg3: fuzz1_png
    arg4: test.c

    arg0: gcc
    arg1: -g
    arg2: -o
    arg3: fuzz1_png
    arg4: test.c
    arg5: -B
    arg6: /home/tamako/Desktop/FUZZ/AFL_debug/AFLcpp
    arg7: -g
    arg8: -O3
    arg9: -funroll-loops
    arg10: -D__AFL_COMPILER=1
    arg11: -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION=1
    arg12: (null)
    arg13: (null)
    arg14: (null)
afl-as 2.57b by <lcamtuf@google.com>
```

关于其中一些细节的理解可以看下面，首先我们观察一下gcc的具体操作，虽然我们平时对编译链接那一套比较熟悉了，但是使用`--verbose`参数可以得到gcc编译的详细全过程。

```shell
$ gcc --verbose test.c -o test
..............
 /usr/lib/gcc/x86_64-linux-gnu/9/cc1 -quiet -v -imultiarch x86_64-linux-gnu test.c -quiet -dumpbase test.c -mtune=generic -march=x86-64 -auxbase test -version -fasynchronous-unwind-tables -fstack-protector-strong -Wformat -Wformat-security -fstack-clash-protection -fcf-protection -o /tmp/cc7SDSlv.s
............
 as -v --64 -o /tmp/cc1aWLRu.o /tmp/cc7SDSlv.s
GNU assembler version 2.34 (x86_64-linux-gnu) using BFD version (GNU Binutils for Ubuntu) 2.34
...........
 /usr/lib/gcc/x86_64-linux-gnu/9/collect2 -plugin /usr/lib/gcc/x86_64-linux-gnu/9/liblto_plugin.so -plugin-opt=/usr/lib/gcc/x86_64-linux-gnu/9/lto-wrapper -plugin-opt=-fresolution=/tmp/ccx9lNVu.res -plugin-opt=-pass-through=-lgcc -plugin-opt=-pass-through=-lgcc_s -plugin-opt=-pass-through=-lc -plugin-opt=-pass-through=-lgcc -plugin-opt=-pass-through=-lgcc_s --build-id --eh-frame-hdr -m elf_x86_64 --hash-style=gnu --as-needed -dynamic-linker /lib64/ld-linux-x86-64.so.2 -pie -z now -z relro -o test /usr/lib/gcc/x86_64-linux-gnu/9/../../../x86_64-linux-gnu/Scrt1.o /usr/lib/gcc/x86_64-linux-gnu/9/../../../x86_64-linux-gnu/crti.o /usr/lib/gcc/x86_64-linux-gnu/9/crtbeginS.o -L/usr/lib/gcc/x86_64-linux-gnu/9 -L/usr/lib/gcc/x86_64-linux-gnu/9/../../../x86_64-linux-gnu -L/usr/lib/gcc/x86_64-linux-gnu/9/../../../../lib -L/lib/x86_64-linux-gnu -L/lib/../lib -L/usr/lib/x86_64-linux-gnu -L/usr/lib/../lib -L/usr/lib/gcc/x86_64-linux-gnu/9/../../.. /tmp/cc1aWLRu.o -lgcc --push-state --as-needed -lgcc_s --pop-state -lc -lgcc --push-state --as-needed -lgcc_s --pop-state /usr/lib/gcc/x86_64-linux-gnu/9/crtendS.o /usr/lib/gcc/x86_64-linux-gnu/9/../../../x86_64-linux-gnu/crtn.o
```

从上面简单节选出来的内容可以看到，首先调用的是cc1编译生成`/tmp/cc7SDSlv.s`，然后使用as进行汇编，把cc7SDSlv.s转化为`/tmp/cc1aWLRu.o`，最后生成可执行文件。

在以上的afl-gcc的代码里面只看到了wrapper部分，实际上的调用却没体现出来，（其实仔细看可以知道就是-B一个参数指定了找到的`afl-as路径`实际上也可以打印一下具体的过程。

```shell
 /home/tamako/Desktop/FUZZ/AFL_debug/AFLcpp/as -v --64 -o /tmp/ccn9gj4T.o /tmp/cc6rIr4V.s
```

可以发现汇编的代码变成了如上代码，所以afl-gcc在编译的时候没问题，植入的插桩代码实在汇编的时候植入的，下面分析一下afl-as源码。

afl-as
======

edit\_params函数
--------------

和afl-gcc中的类似，也是编辑传递给`as`的参数。其中涉及到一些对MAC OS系统的处理，都定义在了`__APPLE`宏中，后续短时间内不会涉及到APPLE的系统，所以分析的时候绕过该类，把握大体的插桩即可。

开篇的注释介绍了函数的主要内容

> / *Examine and modify parameters to pass to 'as'. Note that the file name is always the last parameter passed by GCC, so we exploit this property to keep the code simple.* /

修改as的参数，file name 一般都是gcc传递过来的最后一个参数，抓住这个要点可以让代码变得简洁。

- 从环境变量中获得需要汇编的`.s`文件的目录，`TMPDIR TMP TEMP`环境变量都没有设置的话，就设置该目录为`/tmp`（默认为tmp）
- 同样的，获得`AFL_AS`的值（afl-as的路径），如果没有则设置为`as`
- 遍历所有的参数，根据-m64和-m32设置`use_64bit`为1或者0
- 其余的参数简单的复制到`as_params`即可
- `input_file = argv[argc - 1];`最后一个参数赋值给input\_file 
    - 如果是--version，那么设置just\_version标志位，设置modified\_file为input file，然后跳到结尾
    - 如果不是--version，那么一般就是目标文件（具体可以在上文gcc细节中看到），检查完毕对应临时文件夹，然后进行重命名

```c
modified_file = alloc_printf("%s/.afl-%u-%u.s", tmp_dir, getpid(), (u32)time(NULL));
```

设置文件名字为`tmp_dir/.afl-pid-time.s`这样的类型  
结尾

- 设置`as_params[as_par_cnt++] = modified_file`
- `as_params[as_par_cnt] = NULL;`

对原来的参数做了一些修改的工作，找到原来生成的需要被汇编的文件，一般来说经过gcc之后该文件为`/tmp/随机数.s`，modify一个新的文件`tmp_dir/.afl-pid-time.s`这个文件在后面的函数中被用来存放插桩后的代码，除此之外该函数还设置了一些标志位，属于一些细节，屏蔽即可。

add\_instrumentation函数
----------------------

> / *Process input file, generate modified\_file. Insert instrumentation in all the appropriate places.* /

处理程序的输入文件，生成modified\_file，在适当的位置插入instrument。

生成的modified\_file即为插桩后的文件，instrumentation即为插桩代码。

- 如果input\_file不为空，那么打开input\_file，文件描述符为`inf`，如果为空则设置为stdin，inf为FILE\* 类型指针。
- 然后打开modified\_file对应的临时文件，并获取其句柄outfd，再根据句柄通过fdopen函数拿到FILE\* 指针outf
- 接下来通过while循环和getline函数，把input\_file的内容转存到line内，一次读出8192。  
    **接下来就是函数最重要的部分**，while循环内是插桩的一些限制条件，通过一些判断，从而断定在哪些地方插桩，哪些地方应该插桩。

### 应该在哪里插桩

可以看到while循环内的几段注释

> / *In some cases, we want to defer writing the instrumentation trampoline  
> until after all the labels, macros, comments, etc. If we're in this  
> mode, and if the line starts with a tab followed by a character, dump  
> the trampoline now.* /

我们在一些情况下插桩：  
此外，如果当前这一行由指标符`\t`开始并且在制表符后面紧紧跟着一个字母，则插入trampoline（trampoline即理解为插桩）

后来再继续看，下面有一段别的注释引起了我的注意

```php
 /* If we're in the right mood for instrumenting, check for function 
    names or conditional labels. This is a bit messy, but in essence, 
    we want to catch:

      ^main:      - function entry point (always instrumented)
      ^.L0:       - GCC branch label
      ^.LBB0_0:   - clang branch label (but only in clang mode)
      ^\tjnz foo  - conditional branches

    ...but not:

      ^# BB#0:    - clang comments
      ^ # BB#0:   - ditto
      ^.Ltmp0:    - clang non-branch labels
      ^.LC0       - GCC non-branch labels
      ^.LBB0_0:   - ditto (when in GCC mode)
      ^\tjmp foo  - non-conditional jumps

    Additionally, clang and GCC on MacOS X follow a different convention
    with no leading dots on labels, hence the weird maze of #ifdefs
    later on.
     */
```

这里更加明确的提出了哪些“标签”，编译之后的branch label和有条件跳转都要插桩，后面还有一些不插桩的情况。

### 一些头文件中的代码

trampoline\_fmt\_64这个字符串和trampoline\_fmt\_32都存在于afl-as.h中。

```c
static const u8* trampoline_fmt_64 =

  "\n"
  "/* --- AFL TRAMPOLINE (64-BIT) --- */\n"
  "\n"
  ".align 4\n"
  "\n"
  "leaq -(128+24)(%%rsp), %%rsp\n"
  "movq %%rdx,  0(%%rsp)\n"
  "movq %%rcx,  8(%%rsp)\n"
  "movq %%rax, 16(%%rsp)\n"
  "movq $0x%08x, %%rcx\n"
  "call __afl_maybe_log\n"
  "movq 16(%%rsp), %%rax\n"
  "movq  8(%%rsp), %%rcx\n"
  "movq  0(%%rsp), %%rdx\n"
  "leaq (128+24)(%%rsp), %%rsp\n"
  "\n"
  "/* --- END --- */\n"
  "\n";
```

32和64意思差不多，都是一段类似的汇编代码，以64为例分析，按照fprintf的格式，在后面的R函数执行完毕之后，会将随机值格式化输入到上面的这一段字符串中，可以观察到目标代码：`"movq $0x%08x, %%rcx\n"`，可以确定是被传入了`rcx`寄存器，再回头看这段汇编本身，意思是，保存各个寄存器的值，然后赋予`rcx`一个随机数，最后调用`__afl_maybe_log`函数，`__afl_maybe_log`函数的实现也在同一个头文件中，存在于变量`main_payload_64`中，代码如下：其实现和fuzz的forkserver机制有关系。

#### forkserver 相关

AFL提供了两种fuzzer与被fuzz程序通信的方式：

- execv  
    在fuzzer中，每次fuzz都调用execv来运行目标程序进行fuzz。然后等待程序执行结束，获得其执行路径和退出状态。

使用这种方法效率低下。如果目标程序是动态链接的，使用这种方法，每次execv执行程序都会进行内存分配，动态库的链接等过程，无疑是非常耗费时间的。因此AFL默认不会使用这种模式，除非使用特殊选项(AFL\_NO\_FORKSRV,dumb\_mode1)。

- forkserver  
    fuzzer和forkserver使用两个管道通信，一个`控制管道`(forkserver读，fuzzer写)，一个`数据管道`(fuzzer读，forkserver写)

fuzzer会在初始阶段调用一次execve()，运行一次目标程序，这个运行的程序被称为forkserver，forkserver会运行到插入的桩处（main函数开始的时候是第一个桩），然后就会执行到afl\_maybe\_log中，执行的具体如下分析

```c
  "__afl_maybe_log:\n"
  "\n"
#if defined(__OpenBSD__)  || (defined(__FreeBSD__) && (__FreeBSD__ < 9))
  "  .byte 0x9f /* lahf */\n"
#else
  "  lahf\n"
#endif /* ^__OpenBSD__, etc */
  "  seto  %al\n"
  "\n"
  "  /* Check if SHM region is already mapped. */\n"
  "\n"
  "  movq  __afl_area_ptr(%rip), %rdx\n"
  "  testq %rdx, %rdx\n"
  "  je    __afl_setup\n"
  "\n"
  "__afl_store:\n"
  "\n"
  "  /* Calculate and store hit for the code location specified in rcx. */\n"
  "\n"
#ifndef COVERAGE_ONLY
  "  xorq __afl_prev_loc(%rip), %rcx\n" // 两次异或是因为，__afl_prev_loc保存上一个branch的编号，
  "  xorq %rcx, __afl_prev_loc(%rip)\n" // 执行到这里之后需要更新为这一个branch的编号
  "  shrq $1, __afl_prev_loc(%rip)\n" // 当前branch的编号右移一位，然后存储在afl_prev_loc中，右移是为了减少冲突，
#endif /* ^!COVERAGE_ONLY */
  "\n"
#ifdef SKIP_COUNTS
  "  orb  $1, (%rdx, %rcx, 1)\n"
#else
  "  incb (%rdx, %rcx, 1)\n" // 实现了 share_memory[rcx^afl_prev_loc]++的操作
#endif /* ^SKIP_COUNTS */
  "\n"
  "__afl_return:\n"
  "\n"
  "  addb $127, %al\n"
#if defined(__OpenBSD__)  || (defined(__FreeBSD__) && (__FreeBSD__ < 9))
  "  .byte 0x9e /* sahf */\n"
#else
  "  sahf\n"
#endif /* ^__OpenBSD__, etc */
  "  ret\n"
  "\n"
  ".align 8\n"
  "\n"
```

- 通过全局变量`__afl_area_ptr`检查是否已经初始化（共享内存是否设置） 
    - 如果没有则je 跳转到\_\_afl\_setup函数
    - 如果已经初始化则执行\_\_afl\_store  
        由`__afl_store`函数注释可知：该函数被用来计算并存储rcx指定代码的执行概率。  
        所以这一部分代码应该是计算rcx标记的代码块的执行次数，后期会被用来计算代码覆盖率。

`__afl_prev_loc`存储前一块代码块的RCX编号，和这一块异或之后保存在RCX中，然后再次和RCX异或，保存在\_\_afl\_prev\_loc中，这是为了将当前块的编号保存到全局变量中，异或之后得到的路径理论上来说是唯一的，但是实际上不一定唯一，为了避免冲突将最后得到的值还右移了一位，最后一个incb指令实现了`hare_memory[rcx^afl_prev_loc]++的操作`，将共享内存对应位置的count加一。

`addb $127, %al`恢复溢出寄存器标识位（前面如果被置位的话，这里加`127`会溢出，实现置位），`sahf`指令恢复其余的标志位寄存器，恢复现场，`__afl_maybe_log`结束，分支记录完成，返回到正常的程序执行。

`__afl_setup`函数负责初始化，初始化的流程也相对简单，只是代码比较长。  
汇编代码的设计没啥好分析的，总结了一下大概就是以下伪代码。

```c
__afl_setup:
    if(__afl_setup_failure) return __afl_return
    if(__afl_global_area_ptr) return __afl_store
    else __afl_setup_first

__afl_setup_first
    save all the regs(include xmm0)
    AFL_SHM_ENV = getenv(AFL_SHM_ENV)
    a = atoi(AFL_SHM_ENV)
    addr = shmat(a, 0, 0)
    __afl_arena_ptr = addr
    __afl_global_area_ptr@GOTPCREL = addr
    __afl_forkserver
```

需要注意的地方只有后续的forkserver函数和shmat函数，shmat函数是用来允许本进程访问一块共享内存的函数，一般和shmget函数一起使用。

> void \*shmat（int shmid，const void \*shmaddr,int shmflg）;  
> 它需要如下3个参数：  
> 第一个是参数是 shmid 是shmget 返回的标识符，  
> 第二个参数 三种情况  
> 1.如果shmaddr 是NULL，系统将自动选择一个合适的地址！  
> 2.如果shmaddr 不是NULL 并且没有指定SHM\_RND，则此段连接到addr所指定的地址上.  
> 3.如果shmaddr非0 并且指定了SHM\_RND 则此段连接到shmaddr -（shmaddr mod SHMLAB)所表示的地址上。这里解释一下SHM\_RND命令，它的意思是取整，而SHMLAB的意思是低边界地址的倍数，它总是2的乘方，该算式是将地址向下取最近一个SHMLAB的倍数。 除非只计划在一种硬件上运行应用程序(在现在是不太可能的)，否则不用指定共享段所连接到的地址。所以一般指定shmaddr为0，以便由内核选择地址。  
> 第三个参数如果在flag中指定了SHM\_RDONLY位，则以只读方式连接此段，否则以读写的方式连接此段。  
> shmat返回值是该段所连接的实际地址，如果出错返回 -1.

函数调用中，只有第一个参数指定了，剩下两个参数都是0，则这里是系统自动分配一块合适的共享内存地址。

为了弄清楚这个共享内存是在哪里初始化的，追溯环境变量`AFL_SHM_ENV`，发现该变量实际上来自`SHM_ENV_VAR`，这一环境变量的产生在afl-fuzz.c中的`setup_shm`函数。

由shmget通过其机制返回了一块共享内存的id，而shmat的第一个参数就是这个id。  
可以看到初始化其实很简单，就是分配一块共享空间即可。

后面的afl\_forkserver主要函数如下：

- 首先通过write发送4字节数据给fuzzer，告诉fuzzer我准备好了
- 然后进入loop循环，循环会阻塞在read函数，接受fuzzer的4字节信号
- fork函数fork出来一个子进程，然后父进程发送子进程的进程号给fuzzer，然后等子进程结束
- 子进程`In child process: close fds, resume execution`，然后返回之前保存的寄存器（上下文），之后跳到afl\_store记录覆盖率然后继续执行代码，这里体现的就是forkserver的精髓，fuzzer只要记录子进程的进程号，然后每次插桩的时候可以出一个新的进程执行，而不用重新execve一遍。

#### fuzzer 相关

fuzzer那边的forkserver初始化在`afl-fuzz.c中的init_forkserver`函数中，该函数由`calibrate_case`函数调用，当`forksrv_pid`没有值的时候，说明`forkserver`尚未初始化，调用`init_forkserver`。

```c
  if (dumb_mode != 1 && !no_forkserver && !forksrv_pid)
    init_forkserver(argv);
```

init\_forkserver函数执行操作如下：

- pipe创建了两个管道`ctl_pipe和st_pipe`，且通过fork，创建了一个子进程
- 子进程通过setrlimit函数，设置了子进程的一些资源，并且将子进程的标准输入，输出，错误流全部关闭，输入改为了文件输入。
- 同时`setsid`解放子进程，让其成为一个独立的进程，不受父进程影响，接着子进程使用cttl\_pipe的输出端和st\_pipe的输入端，然后调用execve执行目标程序
- 父进程使用ctl\_pipe的输入端和st\_pipe的输出端，通过read函数读取st\_pipe管道的数据，直到接受4个字节的数据，返回forkserver创建成功，然后退出函数。  
    在子进程执行的时候调用了`execve`，因为该函数不会返回，后面加上`*(u32*)trace_bits = EXEC_FAIL_SIG;`语句，就知道如果执行了该语句，那么execve执行就失败了，就意味着forkserver创建失败。

综上分析，afl-fuzz执行到init\_forkserver函数的时候，创建了fuzzer（自己）和forkserver（子进程），forkserver会继续执行目标程序，然后在第一个插桩的位置，进入`__afl_forkserver`，初始化forkserver，然后返回信息给父进程，此时fuzzer接收到创建成功的消息，init\_forkserver触发return，继续执行别的代码，而forkserver再次调用fork，执行目标进程。

在后续的`桩`中，因为已经初始化，所以只需要往共享内存中记录代码覆盖率即可。

最终形成的forkserver如下：  
![](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-d2a01303a8dd1f2f02a6a8f760ba3a093ef85563.png)

### while循环内的处理

```c
if (!pass_thru && !skip_intel && !skip_app && !skip_csect && instr_ok && instrument_next && line[0] == '\t' && isalpha(line[1])) {
    fprintf(outf, use_64bit ? trampoline_fmt_64 : trampoline_fmt_32, R(MAP_SIZE));

    instrument_next = 0;
    ins_lines++;
```

while中的第一个if条件，满足该条件则进行插桩，插桩的具体操作是fprintf把trampoline代码读入 outf，然后ins\_line插桩计数器加一，trampoline就是插桩插入的语句，涉及到forkserver机制，后面再分析。

pass\_thru标志实在edit\_param中设置的，具体作用不知，设置的条件是`tmp_dir为/tmp`。

- 实际上只需要注意到instr\_ok标志位即可，该标志位用来表示当前section是否为text段，因为AFL只需要在text段插桩，instr\_ok为1则表示为text段，bss等其他段则用instr\_ok=0表示 
    - `\t.text`表示代码段，类似的，可以表示别的段
    - 通过检查line中的内容可以得到以下处理过程 
        - 如果不是clangmode 且 instr\_ok=1 且line为`\t.p2align!\n` 其中感叹号用来代指数字，那么设置skip\_next\_label为1，该标签被用来处理`OpenBSD`系统上的跳转表而设置的标志位
        - 如果`\t.text | section\t.text | section\t__TEXT,__text`是这一行的开头，那么设置instr\_ok为1，即标记为代码段
        - 如果`\t.section\t | \t.section | \t.bss | \t.data`开头则标记instr\_ok为0
    - 完成以上的判断，则返回到getline读取下一行
- 设置完毕标志位之后，后面可以看到在代码段中的什么位置插桩，前面有注释提到了，但是除了第一段if判断插桩之外，后面还有一处判断插桩。

```c
if (line[0] == '\t') {
  if (line[1] == 'j' && line[2] != 'm' && R(100) < inst_ratio) {
    fprintf(outf, use_64bit ? trampoline_fmt_64 : trampoline_fmt_32, R(MAP_SIZE));
    ins_lines++;
  }
  continue;
}
```

遇上跳转语句且不是无条件跳转，则进行插桩，同时`instrument_next`表示下一条语句需要插桩。

- main\_payload添加到末尾  
    `fputs(use_64bit ? main_payload_64 : main_payload_32, outf);`
- 最后关闭相应的句柄，结束插桩

总结起来，似乎只有instr\_ok比较有用，主要是在跳转指令的后面插桩。  
具体的可以看sakura师傅对该部分的总结，其中还有些地方我的理解不够深入。  
<https://eternalsakura13.com/2020/08/23/afl/#more>

该函数插桩似乎只是在modified\_file文件插入了一些代码，但是没有和原本的汇编联系起来（尽管是按照原来的汇编做的插桩，但是没有插在原来的汇编中）

通过反编译查看插桩效果来看，确实在每一个标签的位置，之前都插入了指定的汇编代码。然后汇过去再看代码，看到了期望的代码：  
`fputs(line, outf);`，每次插桩后都有该语句（除了跳转插桩），该语句把正常的汇编和插桩代码一起写入了新文件。

main
----

- 从`AFL_INST_RATIO`环境变量中获得inst\_ratio\_str的值
- 设置srandom的随机种子为`rand_seed = tv.tv_sec ^ tv.tv_usec ^ getpid();`
- 设置AS\_LOOP\_ENV\_VAR为1
- edit\_params函数
- 判断环境变量AFL\_USE\_ASAN和AFL\_USE\_MASN是否为空，只要其中一种不为空，则设置sanitizer为1，且将inst\_ratio除以，因为带ASAN编译的话，没有办法识别出来一些特别的ASAN分支，所以在插桩上会多很多开销，则暴力将插桩概率除以3
- 子进程执行 `execvp(as_params[0], (char**)as_params);`
- unlink(modified\_file)