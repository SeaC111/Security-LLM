quickjs reverse
===============

> quickjs是一个体积小，速度快的js编译/解释引擎，可以通过qjsc将js文件编译为.c文件，其中嵌入了字节码供虚拟机执行。

[quickjs](https://bellard.org/quickjs/)官网下载选定版本进行编译。

刨根问底
----

对于quickjs的一些结构和具体函数调用的实现可以参考 [文章链接](https://ming1016.github.io/2021/02/21/deeply-analyse-quickjs/#%E8%A7%A3%E9%87%8A%E6%89%A7%E8%A1%8C-JS-EvalFunctionInternal)，本文部分图片引自网络如有侵权请联系撤回。

![](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-23adc2c4e7d4ccc19ff742cbd6448defd6cb17e3.png)

`quickjs`中最上层的两个程序分别为`qjs`和`qjsc`，而`qjscalc`则是一个js的计算器。

其函数调用链

> main-&gt;eval\_file-&gt;eval\_buf-&gt;JS\_EvalFunction-&gt;JS\_EvalFunctionInternal-&gt;JS\_CallFree-&gt;JS\_CallInternal

| name | function |
|---|---|
| qjs | js解释器，可以直接执行js代码 |
| qjsc | 编译器，可以将js文件编译成c文件，通过内部虚拟机和字节码执行。 |

> qjsc的虚拟机是基于栈的，并且其opcode定义在quickjs-opcode.h中。

编译好后，目录下会有一个hello.c的测试用例，其编译过程可以在makefile中找到,修改后如下。

```makefile
HELLO_SRCS=hello.js
HELLO_OPTS=-fno-string-normalize -fno-map -fno-promise -fno-typedarray \
           -fno-typedarray -fno-regexp -fno-json -fno-eval -fno-proxy \
           -fno-date -fno-module-loader
ifdef CONFIG_BIGNUM
HELLO_OPTS+=-fno-bigint
endif

Lu1u.c: $(HELLO_SRCS)
    ./qjsc -e $(HELLO_OPTS) -o $@ $(HELLO_SRCS)
```

通过向`hello.js`中写入js代码，之后运行`make -f mkf1`，同目录下生成`Lu1u.c`文件，内容如下。

> -e 是输出 .c文件，否则直接编译成可执行文件。

```c
/* File generated automatically by the QuickJS compiler. */

#include "quickjs-libc.h"

const uint32_t qjsc_hello_size = 78;

const uint8_t qjsc_hello[78] = {
 0x02, 0x04, 0x0e, 0x63, 0x6f, 0x6e, 0x73, 0x6f,
 0x6c, 0x65, 0x06, 0x6c, 0x6f, 0x67, 0x16, 0x4c,
 0x75, 0x31, 0x75, 0x31, 0x75, 0x31, 0x75, 0x31,
 0x75, 0x21, 0x10, 0x68, 0x65, 0x6c, 0x6c, 0x6f,
 0x2e, 0x6a, 0x73, 0x0e, 0x00, 0x06, 0x00, 0xa0,
 0x01, 0x00, 0x01, 0x00, 0x03, 0x00, 0x00, 0x14,
 0x01, 0xa2, 0x01, 0x00, 0x00, 0x00, 0x38, 0xe1,
 0x00, 0x00, 0x00, 0x42, 0xe2, 0x00, 0x00, 0x00,
 0x04, 0xe3, 0x00, 0x00, 0x00, 0x24, 0x01, 0x00,
 0xcd, 0x28, 0xc8, 0x03, 0x01, 0x00
};

static JSContext *JS_NewCustomContext(JSRuntime *rt)
{
  JSContext *ctx = JS_NewContextRaw(rt);
  if (!ctx)
    return NULL;
  JS_AddIntrinsicBaseObjects(ctx);
  JS_AddIntrinsicBigInt(ctx);
  return ctx;
}

int main(int argc, char **argv)
{
  JSRuntime *rt;            //js运行时
  JSContext *ctx;           //上下文
  rt = JS_NewRuntime();
  js_std_set_worker_new_context_func(JS_NewCustomContext);
  js_std_init_handlers(rt);
  ctx = JS_NewCustomContext(rt);
  js_std_add_helpers(ctx, argc, argv);
  js_std_eval_binary(ctx, qjsc_hello, qjsc_hello_size, 0);
  js_std_loop(ctx);
  JS_FreeContext(ctx);
  JS_FreeRuntime(rt);
  return 0;
}
```

`qjsc_hello`中存放的是对应字节码的机器码，通过内部的虚拟机执行，首先程序会创建上下文和运行时，并且通过`js_std_eval_binary`来执行字节码，对应传入的参数为上下文、字节码和字节码长度等。

拿到了`qjsc`编译出的`.c`文件，我们可以通过`gcc`完成后续的编译,需要外部链接一些库，可以直接写到一个makefile文档里。

```makefile
gcc Lu1u.c libquickjs.a -lm -ldl -lpthread -o test
```

此时我们已知qjsc的字节码会写入到c程序中，这为我们逆向指明了思路，即还原字节码甚至做到反编译。

在`quickjs.c`的源码中可以发现，有关dump bytecode的相关宏定义已经被注释掉，并且内部有`js_dump_function_bytecode`函数实现。

![image-20220905205529406](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-7a5fe23ab996b27689043643897ec0a3a3d95af1.png)

所以我们需要在函数加载的合适位置，插入`dump`函数以便得到可读的字节码，并且需要将相关宏定义注释掉(取消code的注释即可)，可知他在`js_create_function`时调用过dump函数。

![image-20220905210206426](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-a295a21bab37ef87190dad03e3d84c7d3e5caa52.png)

修改后重新编译quickjs项目，再次编译发现在第一步将js转成c代码的时候输出了字节码，而常规逆向中我们只能拿到字节码，所以需要让其在执行`.c`文件中的某一个函数中插入`js_dump_function_bytecode`函数。

![image-20220905211233413](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-2bbea5a81efa534bb21632d13cbb456df897a5c0.png)

patch`quickjs.c`文件，找到他读取函数`bytecode`的函数。

![image-20220905222933401](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-1c9f002b4ab23400daafc0402a26b15602b264b1.png)

在break前插入`dump`调用，但是缺少`JSFunctionBytecode`的变量，所以可以跟进`JS_ReadFunctionTag`函数，在其return前调用即可。

```c
//patch1
#define DUMP_BYTECODE  (1)
//patch2
#if DUMP_BYTECODE 
js_dump_function_bytecode(ctx, b);  
#endif
```

`out`

patch后重新编译出可执行文件并运行，可见输出了易读的字节码。

![image-20220905225037342](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-b8701ae3480f3fd8e9f9daf69fd81d4f5930fe3e.png)

利刃出鞘
----

### Read and Reverse

#### get cf

通过IDA字符串中的`quickjs.c`和一些`js_xxx`函数可以确定是`quickjs`编译出的可执行。

![image-20220905230321233](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-c7488db4c773411537b911c739a8566cc23698b4.png)

提取出4513长度的机器码，替换掉自己编译出的`.c`文件中的`qjsc_hello`,并修改其长度。

```makefile
gcc Lu1u.c libquickjs.a -lm -ldl -lpthread -o test
```

编译并运行test，并将结果输出到out.txt文件，`test > out.txt`。

![image-20220905231011662](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-05815be56211caa76078a0b4275b1d2b8aa38dbf.png)

一共有12个函数，不过其中有些解密的函数是不必分析的，因为patch`quickjs.c`时只dump了bytecode，所以字节码会更整齐一些。

> Next, let's we reverse it.

根据函数调用链main-&gt;eval\_file-&gt;eval\_buf-&gt;JS\_EvalFunction-&gt;JS\_EvalFunctionInternal-&gt;JS\_CallFree-&gt;JS\_CallInternal，故入口为function\\&lt;eval&gt;。

该虚拟机是基于栈的，参数是v命名法，所以要了解调用栈的机制，详细opcode参考[`quickjs-opcode.h`](https://github.com/bellard/quickjs/blob/master/quickjs-opcode.h)。

#### `function<eval>`

![image-20220905231707984](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-5fc11dda4d8818cb880dc3a22cca237fd24e9cd9.png)

首先开辟了一些变量，array用于生成数组，顺序即从左向右入的栈。

```python
data3=  [5911837666743816200  ,
        5133585975960501272  ,
        9082418069800623372  ,
        9154480062992383756  ,
        6848599583376686600  ,
        147787617043219975   ,
        6140429622497212985  ,
        2526269866358605591  ,
        4552892036882908959  ,
        4543304157965338119  ,
        4620825451554930944  ,
        8808899373961281307  ,
        5924901230665995531  ,
        8808899373961281307  ,
        8662527953563041043 ]
data4=[2101524238053948931,9154814254531429383,8941618984500083987]
data5=[0]*12
```

之后开始调用函数处理数据，从初始化可知a是我们的输入，而b则是加密用的key。

> 根据keystr的字符串也可以让我们提前猜测encode64是换表的base64加密。

![image-20220905233528115](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-3139a267af6a372c7e10ced597ee7007fe9bc3e2.png)

![image-20220905233438579](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-9ac888683b0b12881217fed10965aae2e1d6d11d.png)

call指令后面跟参数个数，call method则是调用对象中的方法，get是获取参数入栈，push是直接压入栈，而put则是将栈中的数据存放至某个变量。

> 对于js的一条指令，从左向右将需要的元素入栈，如上则是依次压入myenc、encode64、enc1和参数a b。

之后将数据copy到data2中，该块为一个循环语句，`to_prokey2`和`put_array_el`实现了data2\[i\]=的功能, `lt`和`goto`组合实现条件跳转。

![image-20220905234116248](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-a8b4fb79e77da70bd1b9252396385d896f3b734b.png)

之后`function<eval>`的逻辑解读同上，python实现如下。

```python
data3=  [5911837666743816200  ,
        5133585975960501272  ,
        9082418069800623372  ,
        9154480062992383756  ,
        6848599583376686600  ,
        147787617043219975   ,
        6140429622497212985  ,
        2526269866358605591  ,
        4552892036882908959  ,
        4543304157965338119  ,
        4620825451554930944  ,
        8808899373961281307  ,
        5924901230665995531  ,
        8808899373961281307  ,
        8662527953563041043 ]
data4=[2101524238053948931,9154814254531429383,8941618984500083987]
data5=[0]*12

index = 0
index1 = 0
i=0
def func5(s):
    pass
def func6(x):
    pass

keystr="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/="
k="welcometoycb2022"

data2=myenc.encode64(enc1(input,k))  # 魔改xxtea + 换表base64

for i in range(len(data2)):          # 异或
    data2[i]^=data2[(i+2)%len(data2)]

for i in range(0,len(data2),8):      #转换
     if i%32 !=8:
         arg=[]
         for j in range(8):
              arg.append(data2[i+j])
         data5[index]=func5(arg)
     else:
         data5[index]=data4[index1]
         index1+=1
     index+=1
z=0
for i in range(3):
    if func6(i):
        z+=1
if(z==3):
    print('suc')
else:
    print('nono')
```

解下来主要分析重要的加密函数。

#### `encode64`

在初始化阶段可知，encode64函数对应第一个function\\&lt;null&gt;。

```js
re.js:143: function: <null>
  args: input
  locals:
    0: var output
    1: var chr1
    2: var chr2
    3: var chr3
    4: var enc1
    5: var enc2
    6: var enc3
    7: var enc4
    8: var i
```

![image-20220905235526239](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-28cf5b555a2aff5e11846a21a30e0736e33de93e.png)

可知是经典base64的位运算，并且之后的输出位置没有变，单纯是换表。

#### `enc1`

通过参数的命名大致便确定为魔改的`tea`加密。

![image-20220905235700416](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-7cd1e36e06b3680428cc2fa9fdea158f5a5ffb6e.png)

`xxtea`的数据初始化

![image-20220906000321296](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-e84ea66f1df13e5f2963257828b7926607b63766.png)

`xxtea`可见魔改了delta和位运算的参数。

![image-20220906001155386](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-0af4a120796473355c371193d24f57f06744cd84.png)

`delta`为289739796,位运算参数为6、3、4、5。

#### `func6`

func6为check函数，其将输入的参数4个8byte一组x、y、z、w进行逻辑运算并于data5中的数据比对，并且根据main函数中的逻辑没组第二个数据即y需要等于data4中的数据，一共3组。

> 因为约束求解可能会出现多解的问题，故出题人添加data4进行约束，保证解为正确的flag。

![image-20220906001721806](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-85fd0ce6388b334b2ecc8c344c2b54c2dd636e18.png)

![image-20220906001703578](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-d957da79911264253dd465740f8bdd51de949848.png)

> 注意入栈是元素从左向右入，例如get x再get y not and 则是对y取~ 并且与x与 ，即x&amp;(~y) 。

更多细节不再展开，把握规律后阅读十分简单。

### get flag

首先我们需要通过z3约束求解方程，之后需要将得到的结果转为func5之前的存放方式，并依次进行异或、换表base64以及魔改的xxtea。

`step1`

```python
from z3 import *
"""
a=((~x)&z)
b = w ^ (((~y)&x) | ((~y)&z) | (x&y)| ((~x)&z))
c = (((~(x|y)) | ((~x & y) | (x & y))) & z) | ((~y & z) & x)
d =  (~y&x) | (x&y) | (~x&z) | (~y&z)
e = (y&z)|(x&y)|(~x&z)
"""
ans=[]
data3= [5911837666743816200  ,
        5133585975960501272  ,
        9082418069800623372  ,
        9154480062992383756  ,
        6848599583376686600  ,
        147787617043219975   ,
        6140429622497212985  ,
        2526269866358605591  ,
        4552892036882908959  ,
        4543304157965338119  ,
        4620825451554930944  ,
        8808899373961281307  ,
        5924901230665995531  ,
        8808899373961281307  ,
        8662527953563041043 ]
data4=[2101524238053948931,9154814254531429383,8941618984500083987]
index=0
for i in range(3):
        x=BitVec('x',65)
        y=BitVec('y',65)
        z=BitVec('z',65)
        w=BitVec('w',65)
        s=Solver()
        s.add((~x)&z==data3[5*i])
        s.add(w ^ (((~y)&x) | ((~y)&z) | (x&y)| ((~x)&z))==data3[5*i+1])
        s.add((((~(x|y)) | ((~x & y) | (x & y))) & z) | ((~y & z) & x)==data3[5*i+2])
        s.add((~y&x) | (x&y) | (~x&z) | (~y&z)==data3[5*i+3])
        s.add((y&z)|(x&y)|(~x&z) ==data3[5*i+4])
        s.add(y==data4[index])
        index+=1
        print(s.check())
        m=s.model()
        ans.append(m[x].as_long())
        ans.append(m[y].as_long())
        ans.append(m[z].as_long())
        ans.append(m[w].as_long())
#get ans
print(ans)
def tobyte1(x):
        h=hex(x)[2:].zfill(16)
        hi=int('0x'+h[:8],16)
        lo=int('0x'+h[8:],16)
        b2=int.to_bytes(hi,4,'little')
        b1=int.to_bytes(lo,4,'little')
        return b1 + b2
res=b''
for i in ans:
   if i!=0:
      res+=tobyte1(i)
res = list(res)
l=len(res)
ms=[BitVec('ms%d'%i,8) for i in range(l)]
sk=[]
for i in range(len(ms)):
        sk.append(ms[i])
for i in range(len(ms)):          # 异或
    ms[i]^=ms[(i+2)%len(ms)]
s=Solver()
for i in range(len(ms)):
        s.add(ms[i]==res[i])
print(s.check())
ss=''
mm=s.model()
for i in range(len(ms)):
        ss+=chr(mm[sk[i]].as_long())
print(ss)
#mZi5mwyYytzJnJGWmJaWowrLy2m1nZLLyta5mZLInti0nZa5mJzMnJaWntHIowuXm2vLmJfMywjJn2y1nMeXzG==
```

`step2`

变表base64

![image-20220904105129729](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-4ea62de6112166c4780725865753fa64d3b55e08.png)

`step3`

魔改xxtea

```python
from ctypes import c_uint32
DELTA = 289739796
from Crypto.Util.number import *
def decrypt(v, n, k):
    rounds = 6 + int(52 / n)
    sum = c_uint32(rounds * DELTA)
    y = v[0].value
    while rounds > 0:
        e = (sum.value >> 2) & 3
        p = n - 1
        while p > 0:
            z = v[p - 1].value
            v[p].value -= (((z >> 6 ^ y << 3) + (y >> 4 ^ z << 5)) ^ ((sum.value ^ y) + (k[(p & 3) ^ e] ^ z)))
            y = v[p].value
            p -= 1
        z = v[n - 1].value
        v[0].value -= (((z >> 6 ^ y << 3) + (y >> 4 ^ z << 5)) ^ ((sum.value ^ y) + (k[(p & 3) ^ e] ^ z)))
        y = v[0].value
        sum.value -= DELTA
        rounds -= 1

s=bytes.fromhex('3291f2a6c6802009decc579ea0939b52470926f60058b9e13ee21fabc7f56a1f')
vv=[]

for i in range(0,len(s)//4):
    num=0
    for j in range(4):
        num|=s[4*i+j]<<(8*j)
    vv.append(c_uint32(num))
k=[]
kk=b'welcometoycb2022'
for i in range(0,len(kk)//4):
    num=0
    for j in range(4):
        num|=kk[4*i+j]<<(8*j)
    k.append((num))

decrypt(vv,len(vv),k)
ans=b''
for i in range(len(vv)):
    ans+=int.to_bytes(vv[i].value,4,'little')
print(ans)
#9JIOSTywl3n3VzpanY93l9sZGtK1YrVr
```

总结
--

本题通过泄露的字符串确定位quickjs逆向，但逆向过程仍然具有一定的困难，版本为最新版，网上资料指出的patch并不明确且会编译出错，只能思考新的patch点。即便是拿到字节码后逆向仍是一件痛苦的事情，例如func6中冗余的逻辑运算，令人头晕目眩的端序转换等。对于字节码逆向的题目，只要把握其指令格式，花费一定的时间一般都会得到解决，虽然过程很枯燥，但是去拼一血、抢时间的过程却十分的令人兴奋。

> 遗憾的不该是我们，致敬每一位死磕字节码，与各种算法做斗争的逆向战士们！。

参考:

<https://bbs.pediy.com/thread-258985.htm>

<https://ming1016.github.io/2021/02/21/deeply-analyse-quickjs/#%E8%A7%A3%E9%87%8A%E6%89%A7%E8%A1%8C-JS-EvalFunctionInternal>