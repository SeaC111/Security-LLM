本次研究的固件是[tplink archer c7 V5.80](https://www.tp-link.com/us/support/download/archer-c7/#Firmware)。

tplink archer c7的lua版本是5.1.4，下载对应版本[lua源码](https://www.lua.org/ftp/lua-5.1.4.tar.gz)。

lua加载执行chunk流程
--------------

main函数中，首先`lua_open`打开文件，调用`luaL_dofile`。`luaL_dofile`是一个宏实际调用`luaL_loadfile`和`lua_pcall`。

```c
#define luaL_dofile(L, fn) \
    (luaL_loadfile(L, fn) || lua_pcall(L, 0, LUA_MULTRET, 0))

int main(void)
{
 lua_State *L=lua_open();
 lua_register(L,"print",print);
 if (luaL_dofile(L,NULL)!=0) fprintf(stderr,"%s\n",lua_tostring(L,-1));
 lua_close(L);
 return 0;
}
```

#### luaL\_loadfile

从调试时的调用栈可以看到，`luaL_loadfile`最终调用`f_parser`。

`f_parser`中，首先读取第一个字节，判断是不是0x1B，是则认为是lua字节码文件，调用`luaU_undump`，否则解析lua源码。

```c
static void f_parser (lua_State *L, void *ud) {
  int i;
  Proto *tf;
  Closure *cl;
  struct SParser *p = cast(struct SParser *, ud);
  // 预读入第一个字符
  int c = luaZ_lookahead(p->z);
  luaC_checkGC(L);
  // 根据之前预读的数据来决定下面的分析采用哪个函数
  tf = ((c == LUA_SIGNATURE[0]) ? luaU_undump : luaY_parser)(L, p->z,
                                                             &p->buff, p->name);
  cl = luaF_newLclosure(L, tf->nups, hvalue(gt(L)));
  cl->l.p = tf;
  for (i = 0; i < tf->nups; i++)  /* initialize eventual upvalues */
    cl->l.upvals[i] = luaF_newupval(L);
  setclvalue(L, L->top, cl);
  incr_top(L);
}
```

`luaU_undump`，`LoadHeader`获取文件头，`LoadFunction`获取函数体。

```c
Proto* luaU_undump (lua_State* L, ZIO* Z, Mbuffer* buff, const char* name)
{
 LoadState S;
 if (*name=='@' || *name=='=')
  S.name=name+1;
 else if (*name==LUA_SIGNATURE[0])
  S.name="binary string";
 else
  S.name=name;
 S.L=L;
 S.Z=Z;
 S.b=buff;
 LoadHeader(&S); // 文件头
 return LoadFunction(&S,luaS_newliteral(L,"=?")); //函数体
}
```

#### LoadHeader

文件头格式如下，这里只介绍后续会用到的字段。

第一个字段是luac文件的magic number，用于标识luac文件。

`version`字段表示lua版本，这里使用的是lua5.1，所以值是0x51。

`format`字段为0表示是官方定义的文件格式，不为0则为其他格式。但是实际上有些luac文件即使修改了官方的格式，该字段还是为0。

`endian`表示字节序。

`size_size_t`字段表示size\_t类型所占的字节数。32位为4，64位为8。

`size_lua_Number`表示`lua_Number`类型的数据大小。lua中的number使用浮点数表示，float为32位，double为64位。

```c
typedef struct {
    char signature[4];   // #define LUA_SIGNATURE   "\033Lua"
    uchar version;      // 0x51,0x52，0x53
    uchar format;
    uchar endian;
    uchar size_int;
    uchar size_size_t;
    uchar size_Instruction;
    uchar size_lua_Number;
    uchar lua_num_valid;
    uchar luac_tail[0x6];
} GlobalHeader;
```

使用101 editor模板可以很清楚地看到header结构的各个字段。

![image-20240821111556927.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-673bc506b9f10f5802b6ec2a6d377dbc6d91c859.png)

#### LoadFunction

`LoadFunction`首先初始化Proto结构体（存放函数原型的数据结构），之后是加载`protoheader`、`code`、`constants`和`debug`部分。

`protoheader`包含source（函数名或文件名）、linedefined（源码第一行行号）、lastlinedefined（源码最后一行行号）、is\_vararg（是否可变参数）等字段，描述函数相关信息。

```c
static Proto* LoadFunction(LoadState* S, TString* p)
{
 Proto* f;
 if (++S->L->nCcalls > LUAI_MAXCCALLS) error(S,"code too deep");
 f=luaF_newproto(S->L);
 setptvalue2s(S->L,S->L->top,f); incr_top(S->L);
 f->source=LoadString(S); if (f->source==NULL) f->source=p; // protoheader
 f->linedefined=LoadInt(S);
 f->lastlinedefined=LoadInt(S);
 f->nups=LoadByte(S);
 f->numparams=LoadByte(S);
 f->is_vararg=LoadByte(S);
 f->maxstacksize=LoadByte(S);
 LoadCode(S,f);         // code
 LoadConstants(S,f);    // constants
 LoadDebug(S,f);        // debug
 IF (!luaG_checkcode(f), "bad code");
 S->L->top--;
 S->L->nCcalls--;
 return f;
}
```

#### LoadCode

`LoadCode`获取指令个数n，之后获取n条指令，每个指令是32位。

```c
static void LoadCode(LoadState* S, Proto* f)
{
 int n=LoadInt(S);
 f->code=luaM_newvector(S->L,n,Instruction);
 f->sizecode=n;
 LoadVector(S,f->code,n,sizeof(Instruction));
}
```

#### LoadConstants

`LoadConstants`获取常量，同样先获取常量个数，再根据常量类型分别设置常量数据。

常量类型分为LUA\_TNIL（空）、LUA\_TBOOLEAN（布尔）、LUA\_TNUMBER（数字）、LUA\_TSTRING（字符串），其中数字使用浮点数表示。

之后获取该函数中的函数原型个数，嵌套调用`LoadFunction`。一个luac文件可以认为是一整个最大的proto，文件中定义的每个函数是最大proto的子函数。通过这种方式就把所有的function都加载进来。（这应该就是luadec的反编译结果中第一个函数是所有函数的定义的原因）

```c
static void LoadConstants(LoadState* S, Proto* f)
{
 int i,n;
 n=LoadInt(S);
 f->k=luaM_newvector(S->L,n,TValue);
 f->sizek=n;
 for (i=0; i<n; i++) setnilvalue(&f->k[i]);
 for (i=0; i<n; i++)
 {
  TValue* o=&f->k[i];
  int t=LoadChar(S);
  switch (t)
  {
   case LUA_TNIL:
    setnilvalue(o);
    break;
   case LUA_TBOOLEAN:
    setbvalue(o,LoadChar(S)!=0);
    break;
   case LUA_TNUMBER:
    setnvalue(o,LoadNumber(S));
    break;
   case LUA_TSTRING:
    setsvalue2n(S->L,o,LoadString(S));
    break;
   default:
    error(S,"bad constant");
    break;
  }
 }
 n=LoadInt(S);
 f->p=luaM_newvector(S->L,n,Proto*);
 f->sizep=n;
 for (i=0; i<n; i++) f->p[i]=NULL;
 for (i=0; i<n; i++) f->p[i]=LoadFunction(S,f->source);
}
```

#### LoadDebug

获取行号信息，局部变量，和upvalue。当函数A中包含子函数B，并且函数B访问了函数A的参数或局部变量时，就会产生upvalue。实际iot固件中大多upvalue是函数访问全局变量时产生的。

```c
static void LoadDebug(LoadState* S, Proto* f)
{
 int i,n;
 n=LoadInt(S);
 f->lineinfo=luaM_newvector(S->L,n,int);
 f->sizelineinfo=n;
 LoadVector(S,f->lineinfo,n,sizeof(int));
 n=LoadInt(S);
 f->locvars=luaM_newvector(S->L,n,LocVar);
 f->sizelocvars=n;
 for (i=0; i<n; i++) f->locvars[i].varname=NULL;
 for (i=0; i<n; i++)
 {
  f->locvars[i].varname=LoadString(S);
  f->locvars[i].startpc=LoadInt(S);
  f->locvars[i].endpc=LoadInt(S);
 }
 n=LoadInt(S);
 f->upvalues=luaM_newvector(S->L,n,TString*);
 f->sizeupvalues=n;
 for (i=0; i<n; i++) f->upvalues[i]=NULL;
 for (i=0; i<n; i++) f->upvalues[i]=LoadString(S);
}
```

总之，整个luac文件可分为`header`和`function`两部分，`function`又分为`protoheader`，`code`，`constants`，`subproto`，`debug`部分。

首先加载解析`protoheader`部分，之后`LoadFunction`解析`proto`部分。

`LoadFunction`中，解析`protoheader`（函数头），`code`（代码），`subproto`（子函数），`debug`（行号信息、局部变量、upvalue）部分。

`subproto`中，同样按照`LoadFunction`流程解析。通过层层嵌套的方式，整个luac解析完成。

![image-20240822155546582.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-600a61c91379f6baa04112c7c96dcc5fd49e5977.png)

#### lua\_pcall

加载完luac文件后，调用`docall`执行指令，最终调用`luaV_execute`执行，根据不同opcode执行对应操作。

```c
void luaV_execute (lua_State *L, int nexeccalls) {
  ...
    switch (GET_OPCODE(i)) {
      case OP_MOVE: {
        setobjs2s(L, ra, RB(i));
        continue;
      }
      case OP_LOADK: {
        setobj2s(L, ra, KBx(i));
        continue;
      }
      case OP_LOADBOOL: {
        setbvalue(ra, GETARG_B(i));
        if (GETARG_C(i)) pc++;  /* skip next instruction (if C) */
        continue;
      }
      case OP_LOADNIL: {
        TValue *rb = RB(i);
        do {
          setnilvalue(rb--);
        } while (rb >= ra);
        continue;
      }
...
```

对比官方和tplink lua的不同
------------------

在了解了标准的luac的加载执行流程后，为了还原tplink luac，我们需要对比tplink luac的加载执行过程和标准的luac不同的地方。

下面列出一些可能的不同点。

1.header中的magic number、format。

例如小米luac的magic number不是`\x1BLua`而是`\x1BFate/Z`

![image-20240826154653091.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-17ff2497229823468c2026f022215110ac5b250e.png)

2.一些结构体中各个字段的顺序。

例如修改`protoheader`中的`source`、`linedefined`、`lastlinedefined`等字段顺序，导致标准反编译器无法识别luac的格式

3.contants和opcode可能修改ENUM的值，或者添加原本没有的类型。

例如`LUA_T`开头的宏是从0开始，有的lua不是从0开始而是从3开始。

```c
#define LUA_TNIL        0
#define LUA_TBOOLEAN        1
#define LUA_TLIGHTUSERDATA  2
#define LUA_TNUMBER     3
#define LUA_TSTRING     4
#define LUA_TTABLE      5
#define LUA_TFUNCTION       6
#define LUA_TUSERDATA       7
#define LUA_TTHREAD     8
```

4.打乱opcode原本的顺序

5.自定义contants类型格式

#### tplink lua的不同

在不断逆向分析以及调试验证后，发现tplink的lua做出了以下修改（逻辑在liblua.so.5.1.4）：

1.修改opcode

对比`luaV_execute`中的opcode的值和执行的操作，发现相同的opcode值执行的操作不同，所以需要一一对比opcode对应的代码，并还原成原本对应的opcode。

![image-20240826162541826.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-b9f788464cf51a21fd7bf1b7e6eda7d9648b0e7c.png)

还原后的opcode如下：

```c
// official
typedef enum {
OP_MOVE, OP_LOADK, OP_LOADBOOL, OP_LOADNIL, OP_GETUPVAL,
OP_GETGLOBAL, OP_GETTABLE, OP_SETGLOBAL, OP_SETUPVAL, OP_SETTABLE, 
OP_NEWTABLE, OP_SELF, OP_ADD, OP_SUB, OP_MUL, OP_DIV, OP_MOD, 
OP_POW, OP_UNM, OP_NOT, OP_LEN, OP_CONCAT, OP_JMP, OP_EQ, OP_LT, 
OP_LE, OP_TEST, OP_TESTSET, OP_CALL, OP_TAILCALL, OP_RETURN, 
OP_FORLOOP, OP_FORPREP, OP_TFORLOOP, OP_SETLIST, OP_CLOSE, 
OP_CLOSURE, OP_VARARG
} OpCode;

// tplink
typedef enum {
OP_GETTABLE, OP_GETGLOBAL, OP_SETGLOBAL, OP_SETUPVAL, OP_SETTABLE, 
OP_NEWTABLE, OP_SELF, OP_LOADNIL, OP_LOADK, OP_LOADBOOL, OP_GETUPVAL, OP_LT, OP_LE, OP_EQ, OP_DIV, OP_MUL, OP_SUB, OP_ADD, 
OP_MOD, OP_POW, OP_UNM, OP_NOT, OP_LEN, OP_CONCAT, OP_JMP, OP_TEST, 
OP_TESTSET, OP_MOVE, OP_FORLOOP, OP_FORPREP, OP_TFORLOOP, 
OP_SETLIST, OP_CLOSE, OP_CLOSURE, OP_RETURN, OP_TAILCALL, OP_VARARG
} OpCode;

```

这里有一个技巧，ida中搜索luaP\_opnames字符串可以看到每种指令的字符串，对比官方和tplink的lua可以很清楚地得到映射关系，还原时可以少花点时间。但是这个方法不一定有效，有些lua即使修改了代码中的opcode也不会修改luaP\_opnames数组，所以最准确的方法还是像上面一样逐一比较二者之间的代码。

![image-20240826162449244.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-702ce39fa6f021e840b29b6c5e70df19441f98dd.png)

2.添加int类型

在`LoadConstants`中，tplink的lua多了一个constant类型9，这里将其命名为`LUA_TINT`。该类型在`LoadConstants`里的代码逻辑是加载4字节数据直接赋值给`TValue`，对比case 3也就是`LUA_TNUMBER`类型，`LUA_TNUMBER`是加载8字节数据直接赋值给`TValue`，因此可以推测`LUA_TINT`是一个类似于`LUA_TNUMBER`的类型，推测是int类型。

![image-20240826162303954.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-1e2a7e4f7c25f910d45fdc7295e83567729ea419.png)

还原实现
----

这里主要参考github上一位师傅的脚本：[https://github.com/zh-explorer/mi\_lua/](https://github.com/zh-explorer/mi_lua/)。

相关脚本已上传至[github](https://github.com/no1rr/luaAnalyzer)。

脚本的做法是解析tplink的luac文件并转换成中间数据，再把中间数据转换成标准格式的luac。

#### lua\_ori.py

lua\_ori中，使用construct的Struct定义好标准的luac文件的格式。

例如，luac文件由`header`和一整个大的`proto`组成，而`header`又有`signature`，`version`，`format`等字段。所以我们需要使用`Struct`定义一个`Luac`结构包含`global_head`和`top_proto`，其中`global_head`具体由`GlobalHead`定义。`GlobalHead`中，`signature`是一个固定字符串，`version`是一个字节长度的数据表示lua版本，必须是5.1、5.2、5.3版本中的一个。`size_int`表示int的长度，是一个8位数据。以此类推。

```python
Luac = Struct(
    "global_head" / GlobalHead, # 
    "top_proto" / Proto
)

Version = Enum(Byte, lua51=0x51, lua52=0x52, lua53=0x53) # 5.1、5.2、5.3版本
GlobalHead = Struct(
    "signature" / Const(b"\x1bLua"), #字符串常量
    "version" / Version,
    "format" / Format,
    "endian" / Endian,
    "size_int" / Int8ul,
    "size_size_t" / Int8ul,
    "size_instruction" / Int8ul,
    "size_lua_number" / Int8ul,
    "lua_num_valid" / Byte,
)

```

定义好luac的格式后，先调用`GlobalHead.parse`解析`luac`的`header`部分，之后`lua_type_define`根据解析结果设置`size_int`、`size_size_`t等字段，最后`Luac.parse`解析整个`luac`文件。因为luac的`proto`部分需要使用到`size_int`、`size_size_t`等字段来确定数字长度大小端等问题，所以需要先解析一遍`header`。

```python
header = GlobalHead.parse(data)
lua_type_define(header)
h = Luac.parse(data)
```

#### lua\_tplink.py

lua\_tplink则是针对tplink luac文件格式的解析，脚本针对tplink做出的魔改使用Adapter类来解析修改后的格式。

1.还原opcode

添加`InstructionAdapter`用于转换标准的opcode和tplink的opcode。

`_encode`函数在中间数据转换到tplink格式时用到，`_decode`反之。

```python
OpCodeMap = [6, 5, 7, 8, 9, 10, 11, 3, 1, 2, 4, 24, 25, 23, 15, 14, 13, 12, 16, 17, 18, 19, 20, 21, 22, 26, 27, 0, 31, 32, 33, 34, 35, 36, 28, 30, 29, 37]

class InstructionAdapter(Adapter):
    def _encode(self, obj, context, path):
        obj.opcode = OpCode.parse(integer2bits(OpCodeMap.index(int(obj.opcode)), 6))
        return obj

    def _decode(self, obj, context, path):
        obj.opcode = OpCode.parse(integer2bits(OpCodeMap[int(obj.opcode)], 6))
        return obj
```

2.添加tplink独有的常量类型，因为正常lua没有该类型，而且该独有类型实际上也是数字，所以遇到`LUA_TINT`类型时可以直接转换成`LUA_TNUMBER`类型（\\x03）。

```python
LuaDatatype = Enum(Byte,
                   LUA_TNIL=0,
                   LUA_TBOOLEAN=1,
                   LUA_TLIGHTUSERDATA=2,
                   LUA_TNUMBER=3,
                   LUA_TSTRING=4,
                   LUA_TTABLE=5,
                   LUA_TFUNCTION=6,
                   LUA_TUSERDATA=7,
                   LUA_TTHREAD=8,
                   LUA_TPLINKDATA=9)

class LuaDatatypeAdapter(Adapter):
    def _decode(self, obj, context, path):
        if obj == 9:
            logging.warning("translate may not success")
        return LuaDatatype.parse(bytes([obj]))

    def _encode(self, obj, context, path):
        return bytes([int(obj)])

class ConstantAdapter(Adapter):
    def _decode(self, obj, context, path):
        if int(obj.data_type) == 9:
            obj.data_type = LuaDatatype.parse(b'\x03')
            obj.data = float(obj.data)
        return obj

    def _encode(self, obj, context, path):
        return obj

```

#### main.py

首先lua\_tplink加载解析tplink的luac文件。

之后确定要转换的luac的global\_head中`size_int`、`size_size_t`、`size_lua_number`、`size_instruction`的大小。

tplink archer c7 是MIPS架构，32位，小端，根据luac的header相应字段的定义，lua\_type\_set的参数是4, 4, 8, 4。

`lua_ori.Luac.build`将中间数据转换成标准格式的luac文件。

```python
if lua_type == TPLINK_LUA:
        header = lua_tplink.GlobalHead.parse(data)
        lua_tplink.lua_type_define(header)
        h = lua_tplink.Luac.parse(data)
    else:
        pass 

    if args.decode:
        print(h)
    else:
        if lua_type == TPLINK_LUA:
            # 32bit  
            lua_ori.lua_type_set(4, 4, 8, 4)
            h.global_head = lua_ori.GlobalHead.parse(
                bytes([0x1B, 0x4C, 0x75, 0x61, 0x51, 0x00, 0x01, 0x04, 0x04, 0x04, 0x08, 0x00]))
            d = lua_ori.Luac.build(h)
            with open(outfile_path, 'wb') as fp:
                fp.write(d)
```

在还原成正确的官方格式后，再使用标准的luadec或unluac还原。这里笔者使用unluac来还原。效果如下

![image-20240826113414489.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-c38b5cab902c019361be030316f7b9bed0712c9d.png)

这时还原的结果已经是能看的状态的了，如果想要更进一步可以借助大模型来辅助还原。

![image-20240826113235004.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-de5e3e07a1d3b9ec92c2900ed650e2d4e395bd47.png)

这时的结果已经很接近源码，交给[静态分析工具](https://poc.qianxin.com/tools)分析也能够识别出语法。

总结
--

总而言之，还原luac基本思路就是找出luac文件在加载解析执行时官方的格式流程和魔改之间的不同，之后编写工具还原成标准格式的luac，在使用标准的反编译工具还原。

还原luac还有一种思路是针对特定格式的luac编写专门的反编译器，而不是通过转换格式标准的反编译器能够识别，[luadec-tplink](https://github.com/superkhung/luadec-tplink)就是这样做的。

参考
--

[https://github.com/zh-explorer/mi\_lua/](https://github.com/zh-explorer/mi_lua/)