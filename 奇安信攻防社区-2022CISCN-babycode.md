0x01 babycode
=============

mruby字节码逆向题目，需要找到对应版本的源码编译出解释器，进而打印出字节码信息，并借此逆向程序逻辑。

题目附件是`babycode.mrb`,根据题目名搜索可知`.mrb`后缀文件为mruby编译出的字节码程序。

> mruby是一个Ruby语言的轻量级实现,可以将ruby源码便以为中间代码，之后有基于寄存器的虚拟机解释运行。

通过010editor加载文件，查看文件头`RITE0300`,对照知这是mruby最新版编译出的字节码文件。

| magic number | mruby version |
|---|---|
| RITE0006 | mruby v2.1.0 |
| RITE0200 | mruby v3.0.0 |
| RITE0300 | mruby v3.1.0 |

随着版本号的增高，模数中的数值也在增大，发布版本不多，可以下载编译出字节码文件对照。

![image-20220602204653972](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-d2c32a448f81499e0f8867d6ef7c7cb50e579b49.png)

确定好mruby的版本之后，去[mruby](https://mruby.org/)官网下载对应源码进行编译，rake编译完成后bin目录下可见如下系列的工具。

![image-20220602210910785](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-0ac0b7251f4022d7abc5be2682c1195d998d19a3.png)

| tool |  |
|---|---|
| mruby | 解释器，解释执行字节码文件，可打印字节码信息 |
| mirb | 用于评估ruby代码 |
| mrbc | 编译器，将源程序编译为字节码 |

`.mrb`文件可由`mruby`解释器或`mrb_load_irep_file()`函数执行，-b参数是表示该文件是字节码文件，-v参数可以打印出字节码信息。

所以用mrbuy程序拿到可读的字节码信息。

![image-20220602211952915](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-fbba243dbb752de3abc859aee418c20988e02e71.png)

之后就是漫长的人脑反编译过程，在[mruby/include/mruby/ops.h](https://github.com/mruby/mruby/blob/master/include/mruby/ops.h)文件中有对mruby字节码的注解。

![image-20220602212824572](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-620117bc8d275feb085bf17b456cbea4560fafc0.png)

翻译开始前最好先仔细观察指令格式，并且对于有疑问的opcode要搜索对照或自己写测试代码解释为字节码查看，这个过程一定要沉住气，以减少不必要的错误。

**观察字节码格式，发现其分块比较明显，irep 后面跟一个地址则是函数地址，之后则是关于函数所用的寄存器信息和指令长度等，其在打印字节码时按源码位置从上到下翻译，但是类和函数的只展示声明，主体放到后面，主要是函数的调用信息。**

```ruby
irep 0x56268619b4b0 nregs=5 nlocals=2 pools=1 syms=5 reps=2 ilen=55
local variable names:
  R1:p
      000 LOADNIL       R2                            #R2=nil
      002 LOADNIL       R3                            #R3=nil
      004 CLASS         R2      :Crypt
      007 EXEC          R2      I(0:0x56268619b580)
      010 TCLASS        R2
      012 METHOD        R3      I(1:0x56268619bd80)
      015 DEF           R2      :check
      018 SSEND         R2      :gets   n=0 (0x00)    #R2=gets()
      022 SEND          R2      :chomp  n=0 (0x00)    #R2=R2.chomp
      026 MOVE          R1      R2              ; R1:p
      029 MOVE          R3      R1              ; R1:p
      032 SSEND         R2      :check  n=1 (0x01)
      036 JMPNOT        R2      050
      040 STRING        R3      L(0)    ; yes         #if(R2==TRUE) PUTS('yes') 
      043 SSEND         R2      :puts   n=1 (0x01) 
      047 JMP           052 
      050 LOADNIL       R2
      052 RETURN        R2
      054 STOP                                        # exit VM
```

**其中定义类的模块、定义函数和函数调用模块如下**

```ruby
    004 CLASS         R2      :Crypt
    007 EXEC          R2      I(0:0x56268619b580)

    #这块指令定义了一个Crypt类，且主体代码在地址 0x56268619b580

    010 TCLASS        R2
    012 METHOD        R3      I(1:0x56268619bd80)
    015 DEF           R2      :check

    #这类模块定义了一个名为check的函数，且主体在地址 0x56268619bd80

    018 SSEND         R2      :gets   n=0 (0x00)    #R2=gets()
    022 SEND          R2      :chomp  n=0 (0x00)    #R2=R2.chomp

    #SEND和SSEND系列主要用于函数调用，其中SSEND是直接调用，而SEND是内置函数  
    # “:” 后面为函数名 n=0表示用到R2后连续0个寄存器
    #如果n=x 这表明函数调用时需要用到额外x个R2之后的寄存器 如R2、R3、R4...注意是连续的

    029 MOVE          R3      R1              ; R1:p
    032 SSEND         R2      :check  n=1 (0x01)
    #上例则是n=1 SSEND 调用需要用到R2和R3  即 R2=check(R3)  而R3又是p即我们的输入 R2为函数的返回值

```

分析知我们的输入传入check函数，如果返回真则输出yes，故主要加密逻辑在check函数中。跟随check函数声明时的地址到函数主体，字节码如下。

![image-20220602213844980](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-ec632bd5a348a11d4e057a2fb0ba6c024f571277.png)

可见在定义局部变量时格式如下

```ruby
local variable names:
  R1:p
  R2:&           #参数和局部变量的分界线 即R1是参数 R3-R7为局部变量
  R3:i
  R4:lst_ch
  R5:c
  R6:k
  R7:cipher_text
```

之后根据opcode解析指令，首先是赋值

```ruby
     004 LOADI_0       R3                      ; R3:i           #i=0
     006 LOADI_0       R4                      ; R4:lst_ch  #lst_ch=0
     #OPCODE(LOADI_1,    B)         R[a] = mrb_int(1)
     #此类loadi_0 加载立即数进寄存器 立即数为"_"的数值
```

循环体结构

```ruby
      008 MOVE          R8      R3              ; R3:i
      011 MOVE          R9      R1              ; R1:p
      014 SEND          R9      :length n=0 (0x00)           # R9=R9.length
      018 LT            R8      R9                           # R8=i<R9
      020 JMPNOT        R8      086                          # if(!R8) jmp 到 086的地址
      024 MOVE          R8      R1              ; R1:p
      027 MOVE          R9      R3              ; R3:i
      030 GETIDX        R8      R9                           #R8=R8[R9] 即取出 R8=p[i]
      032 SEND          R8      :ord    n=0 (0x00)           #R8=ord(p[i])
      036 MOVE          R5      R8              ; R5:c
      039 MOVE          R8      R5              ; R5:c       #c=R8
      042 MOVE          R9      R4              ; R4:lst_ch
      045 SEND          R8      :^      n=1 (0x01)           #R8=R8^R9  R8=p[i]^lst_h
      049 MOVE          R9      R3              ; R3:i       
      052 ADDI          R9      1                            #R9=i+1
      055 SEND          R8      :^      n=1 (0x01)           #R8^=(i+1)  
      059 SEND          R8      :chr    n=0 (0x00)           #R8=chr(R8)
      063 MOVE          R9      R1              ; R1:p
      066 MOVE          R10     R3              ; R3:i
      069 MOVE          R11     R8
      072 SETIDX        R9      R10     R11                  #p[i]=R8
      074 MOVE          R8      R5              ; R5:c
      077 MOVE          R4      R8              ; R4:lst_ch  #lst_ch=c
      080 ADDI          R3      1               ; R3:i       #i+=1
      083 JMP           008
```

之后是调用加密类的函数进行加密

```ruby
      089 GETCONST      R8      Crypt
      092 GETMCNST      R8      R8::CIPHER
      095 MOVE          R9      R1              ; R1:p
      098 MOVE          R10     R6              ; R6:k
      101 SEND          R8      :encrypt        n=2 (0x02)  #R8 = Crypt::CIPHER.encrypt(p,k)
      105 MOVE          R7      R8              ; R7:cipher_text
      108 MOVE          R8      R7              ; R7:cipher_text
      111 STRING        R9      L(1)    ; f469358b7f165145116e127ad6105917bce5225d6d62a714c390c5ed93b22d8b6b102a8813488fdb
      114 EQ            R8      R9        #if R8==R9
      116 JMPNOT        R8      124
      120 LOADT         R8
      122 RETURN        R8                #R8=true
      124 LOADF         R8                  
      126 RETURN        R8        #R9=fale

```

上述函数翻译后以python呈现如下

```python
def check(p):
    lst_ch=0
    for i in range(len(p)):
        c=ord(p[i])
        p[i]=ord(p[i])^lst_ch
        p[i]^=(i+1)
        lst_ch=c
    enc=encrypt(p)
    if enc=='f469358b7f165145116e127ad6105917bce5225d6d62a714c390c5ed93b22d8b6b102a8813488fdb':
        return True
    else:
        return False
```

查看Crypto类相关函数定义

```ruby
irep 0x56268619b580 nregs=3 nlocals=1 pools=0 syms=1 reps=1 ilen=12
      000 LOADNIL       R1
      002 LOADNIL       R2
      004 CLASS         R1      :CIPHER #定义了一个子类 CIPHER
      007 EXEC          R1      I(0:0x56268619b650) 
      010 RETURN        R1

```

转到CIPHER子类的定义

```ruby
irep 0x56268619b650 nregs=3 nlocals=1 pools=0 syms=6 reps=4 ilen=55
      000 LOADI32       R1      305419896            #R1=305419896
      006 SETCONST      XX      R1                   #XX=305419896
      009 LOADI         R1      16
      012 SETCONST      YY      R1                   #YY=16
      015 LOADSELF      R1

      017 SCLASS                R1     
      019 METHOD        R2      I(0:0x56268619b790)
      022 DEF           R1      :encrypt             #encrypt

      025 TCLASS        R1
      027 METHOD        R2      I(1:0x56268619b830)
      030 DEF           R1      :encrypt             #私有的encrypt函数
      033 SSEND         R1      :private        n=0 (0x00)

      037 TCLASS        R1
      039 METHOD        R2      I(2:0x56268619bb50)
      042 DEF           R1      :to_key              #to_key函数

      045 TCLASS        R1
      047 METHOD        R2      I(3:0x56268619bc20)
      050 DEF           R1      :enc_one             #enc_one函数
      053 RETURN        R1
```

> 其中SCLASS singleton\_class
> 
> Singleton 是一种确保类只能有一个对象的设计模式。可以简单理解为该函数内可以创建本类的对象，完成一些私有函数的调用。

根据类的定义，Crypt::CIPHER.encrypt调用的是public的encrypt函数，故转到其定义。

```ruby
irep 0x56268619b790 nregs=9 nlocals=5 pools=0 syms=3 reps=0 ilen=29
local variable names:
  R1:t
  R2:p
  R3:&
  R4:cip
      000 ENTER         2:0:0:0:0:0:0 (0x80000)
      004 GETCONST      R5      CIPHER
      007 SEND          R5      :new    n=0 (0x00)        
      011 MOVE          R4      R5              ; R4:cip     #cip=CIPHER.new()
      014 MOVE          R5      R4              ; R4:cip
      017 MOVE          R6      R1              ; R1:t
      020 MOVE          R7      R2              ; R2:p
      023 SEND          R5      :encrypt        n=2 (0x02)   #r5=cip.encrypt(t,p) 私有函数
#这里参数容易混淆 t和p是传入的p(输入)和k调用encrypt
```

前面的工作主要是通过公有函数encrypt接口使用`singleton_class`来创建一个CIPHER对象，进而调用私有的encrypt函数。

```ruby
irep 0x56268619b830 nregs=16 nlocals=11 pools=1 syms=8 reps=1 ilen=346
local variable names:
  R1:t
  R2:p
  R3:&
  R4:key
  R5:c
  R6:n
  R7:num1
  R8:num2
  R9:enum1
  R10:enum2
      000 ENTER         2:0:0:0:0:0:0 (0x80000)
      004 MOVE          R12     R2              ; R2:p
      007 SSEND         R11     :to_key n=1 (0x01)
      011 MOVE          R4      R11             ; R4:key   #key=to_key(p)
      014 ARRAY         R5      R5      0       ; R5:c     #c=[]
      017 LOADI_0       R6                      ; R6:n     #n=0
      019 MOVE          R11     R6              ; R6:n
      022 MOVE          R12     R1              ; R1:t      
      025 SEND          R12     :length n=0 (0x00)         #R12=t.length()
      029 LT            R11     R12                        # if(n<t.length())
      031 JMPNOT        R11     327
      035 MOVE          R11     R1              ; R1:t
      038 MOVE          R12     R6              ; R6:n
      041 GETIDX        R11     R12                         #R11=t[n]
      043 SEND          R11     :ord    n=0 (0x00)
      047 SEND          R11     :to_i   n=0 (0x00)          #R11=ord(R11).to_i
      051 LOADI         R12     24
      054 SEND          R11     :<<     n=1 (0x01)          #R11=R11<<24
      058 MOVE          R7      R11             ; R7:num1
      061 MOVE          R11     R7              ; R7:num1
      064 MOVE          R12     R1              ; R1:t
      067 MOVE          R13     R6              ; R6:n
      070 ADDI          R13     1
      073 GETIDX        R12     R13
      075 SEND          R12     :ord    n=0 (0x00)
      079 SEND          R12     :to_i   n=0 (0x00)
      083 LOADI         R13     16
      086 SEND          R12     :<<     n=1 (0x01)
      090 ADD           R11     R12
      092 MOVE          R7      R11             ; R7:num1
      095 MOVE          R11     R7              ; R7:num1
      098 MOVE          R12     R1              ; R1:t
      101 MOVE          R13     R6              ; R6:n
      104 ADDI          R13     2
      107 GETIDX        R12     R13
      109 SEND          R12     :ord    n=0 (0x00)
      113 SEND          R12     :to_i   n=0 (0x00)
      117 LOADI         R13     8
      120 SEND          R12     :<<     n=1 (0x01)
      124 ADD           R11     R12
      126 MOVE          R7      R11             ; R7:num1
      129 MOVE          R11     R7              ; R7:num1
      132 MOVE          R12     R1              ; R1:t
      135 MOVE          R13     R6              ; R6:n
      138 ADDI          R13     3
      141 GETIDX        R12     R13
      143 SEND          R12     :ord    n=0 (0x00)
      147 SEND          R12     :to_i   n=0 (0x00)
      151 ADD           R11     R12
      153 MOVE          R7      R11             ; R7:num1   #num1=(t[n]<<24)|(t[n+1]<<16)|(t[n+2]<<8)|t[n+3]
      156 MOVE          R11     R1              ; R1:t
      159 MOVE          R12     R6              ; R6:n
      162 ADDI          R12     4
      165 GETIDX        R11     R12
      167 SEND          R11     :ord    n=0 (0x00)
      171 SEND          R11     :to_i   n=0 (0x00)
      175 LOADI         R12     24
      178 SEND          R11     :<<     n=1 (0x01)
      182 MOVE          R8      R11             ; R8:num2
      185 MOVE          R11     R8              ; R8:num2
      188 MOVE          R12     R1              ; R1:t
      191 MOVE          R13     R6              ; R6:n
      194 ADDI          R13     5
      197 GETIDX        R12     R13
      199 SEND          R12     :ord    n=0 (0x00)
      203 SEND          R12     :to_i   n=0 (0x00)
      207 LOADI         R13     16
      210 SEND          R12     :<<     n=1 (0x01)
      214 ADD           R11     R12
      216 MOVE          R8      R11             ; R8:num2
      219 MOVE          R11     R8              ; R8:num2
      222 MOVE          R12     R1              ; R1:t
      225 MOVE          R13     R6              ; R6:n
      228 ADDI          R13     6
      231 GETIDX        R12     R13
      233 SEND          R12     :ord    n=0 (0x00)
      237 SEND          R12     :to_i   n=0 (0x00)
      241 LOADI         R13     8
      244 SEND          R12     :<<     n=1 (0x01)
      248 ADD           R11     R12
      250 MOVE          R8      R11             ; R8:num2
      253 MOVE          R11     R8              ; R8:num2
      256 MOVE          R12     R1              ; R1:t
      259 MOVE          R13     R6              ; R6:n
      262 ADDI          R13     7
      265 GETIDX        R12     R13
      267 SEND          R12     :ord    n=0 (0x00)
      271 SEND          R12     :to_i   n=0 (0x00)
      275 ADD           R11     R12
      277 MOVE          R8      R11             ; R8:num2    #num2=(t[n+4]<<24)|(t[n+5]<<16)|(t[n+6]<<8)|t[n+7]
      280 MOVE          R12     R7              ; R7:num1
      283 MOVE          R13     R8              ; R8:num2
      286 MOVE          R14     R4              ; R4:key
      289 SSEND         R11     :enc_one        n=3 (0x03)   #R11=enc_one(num1,num2,key)
      293 AREF          R9      R11     0       ; R9:enum1   #enum1=R11[0]
      297 AREF          R10     R11     1       ; R10:enum2  #enum1=R11[1]
      301 MOVE          R11     R5              ; R5:c
      304 MOVE          R12     R9              ; R9:enum1   # << 在ruby对于数组运算类似append
      307 SEND          R11     :<<     n=1 (0x01)           #c.append(enum1)
      311 MOVE          R11     R5              ; R5:c
      314 MOVE          R12     R10             ; R10:enum2  
      317 SEND          R11     :<<     n=1 (0x01)
      321 ADDI          R6      8               ; R6:n       #c.append(enum2)
      324 JMP           019
      327 MOVE          R11     R5              ; R5:c
      330 BLOCK         R12     I(0:0x56268619ba80)
      333 SENDB         R11     :collect        n=0 (0x00)   #迭代数组 进行sprintf(" %.8x ")
      337 STRING        R12     L(0)    ; 
      340 SEND          R11     :join   n=1 (0x01)           #R11.join把密文连起来
      344 RETURN        R11

irep 0x56268619ba80 nregs=7 nlocals=3 pools=1 syms=1 reps=0 ilen=16
local variable names:
  R1:x
  R2:&
      000 ENTER         1:0:0:0:0:0:0 (0x40000)
      004 STRING        R4      L(0)    ; %.8x 
      007 MOVE          R5      R1              ; R1:x
      010 SSEND         R3      :sprintf        n=2 (0x02)  
      014 RETURN        R3

```

这步函数的主要操作是将输入4个一组大端序转int，之后两个一组num1和num2和key调用enc\_one函数。key有字符串unpack得到其中L表示将4个char转为一个无符号的长整型。

```ruby
 #函数调用方式,循环迭代
      330 BLOCK         R12     I(0:0x56268619ba80)       #指明代码块
      333 SENDB         R11     :collect        n=0 (0x00)    #调用
 #test
      num=5
      num.times {|i| print i," "}
      005 BLOCK         R3      I(0:0x55741d0c6c80)           #对应{}内的代码
      008 SENDB         R2      :times  n=0 (0x00)
#跳转到一个代码块迭代执行 可以通过GETUPVAR获取函数的局部变量
```

enc\_one函数如下

```ruby
irep 0x56268619bc20 nregs=11 nlocals=8 pools=0 syms=2 reps=1 ilen=42
local variable names:
  R1:num1
  R2:num2
  R3:key
  R4:&
  R5:y
  R6:z
  R7:s
      000 ENTER         3:0:0:0:0:0:0 (0xc0000)
      004 MOVE          R8      R1              ; R1:num1
      007 MOVE          R9      R2              ; R2:num2
      010 LOADI_0       R10
      012 MOVE          R5      R8              ; R5:y          #y=num1
      015 MOVE          R6      R9              ; R6:z          #z=num2
      018 MOVE          R7      R10             ; R7:s          #s=0
      021 GETCONST      R8      YY                              #R8=16
      024 BLOCK         R9      I(0:0x56268619bcf0)
      027 SENDB         R8      :times  n=0 (0x00)              #times(16) 即循环16次执行  0x56268619bcf0处的代码
      031 MOVE          R8      R5              ; R5:y
      034 MOVE          R9      R6              ; R6:z
      037 ARRAY         R8      R8      2
      040 RETURN        R8

irep 0x56268619bcf0 nregs=10 nlocals=3 pools=1 syms=5 reps=0 ilen=186
local variable names:
  R1:i
  R2:&
      000 ENTER         1:0:0:0:0:0:0 (0x40000)    
      004 GETUPVAR      R3      5       0             #获取局部变量 R3=R5:y
      008 GETUPVAR      R4      6       0             #R4=R6:z
      012 LOADI_3       R5                            #R5=3
      014 SEND          R4      :<<     n=1 (0x01)    #R4=z<<3
      018 GETUPVAR      R5      6       0
      022 LOADI_5       R6
      024 SEND          R5      :>>     n=1 (0x01)    #R5=z>>5
      028 SEND          R4      :^      n=1 (0x01)    #R4=(z<<3)^(z>>5)
      032 GETUPVAR      R5      6       0
      036 ADD           R4      R5                    #R4=((z<<3)^(z>>5))+z
      038 GETUPVAR      R5      7       0             #R5=s
      042 GETUPVAR      R6      3       0             #R6=key
      046 GETUPVAR      R7      7       0         #R7=s
      050 LOADI         R8      11
      053 SEND          R7      :>>     n=1 (0x01)    #R7=s>>11
      057 ADDI          R7      1                     #R7=(s>>11)+1
      060 LOADI_3       R8                              
      062 SEND          R7      :&      n=1 (0x01)    #R7=((s>>11)+1)&3 
      066 GETIDX        R6      R7                    #R6=key[((s>>11)+1)&3]
      068 ADD           R5      R6                    #R5=s+key[((s>>11)+1)&3]
      070 SEND          R4      :^      n=1 (0x01)    #R4=(((z<<3)^(z>>5))+z)^(s+key[((s>>11)+1)&3])
      074 ADD           R3      R4                    #y+=(((z<<3)^(z>>5))+z)^(s+key[((s>>11)+1)&3])
      076 SETUPVAR      R3      5       0             
      080 LOADL         R4      L(0)    ; 4294967295  #hex()=0xffffffff
      083 SEND          R3      :&      n=1 (0x01)
      087 SETUPVAR      R3      5       0             #y = y&0xffffffff

      091 GETUPVAR      R3      7       0
      095 GETCONST      R4      XX
      098 ADD           R3      R4
      100 SETUPVAR      R3      7       0             #s+=XX

      104 GETUPVAR      R3      6       0             #R3=z
      108 GETUPVAR      R4      5       0             #R4=y
      112 LOADI_3       R5
      114 SEND          R4      :<<     n=1 (0x01)  
      118 GETUPVAR      R5      5       0
      122 LOADI_5       R6
      124 SEND          R5      :>>     n=1 (0x01)
      128 SEND          R4      :^      n=1 (0x01)
      132 GETUPVAR      R5      5       0
      136 ADD           R4      R5                   #((y<<3)^(y>>5)+y)
      138 GETUPVAR      R5      7       0
      142 GETUPVAR      R6      3       0
      146 GETUPVAR      R7      7       0
      150 ADDI          R7      1
      153 LOADI_3       R8
      155 SEND          R7      :&      n=1 (0x01)   
      159 GETIDX        R6      R7                   #R6=key[(s+1)&3]
      161 ADD           R5      R6
      163 SEND          R4      :^      n=1 (0x01)   
      167 ADD           R3      R4                  
      169 SETUPVAR      R3      6       0            #z+=((y<<3)^(y>>5)+y)^(s+key[(s+1)&3])
      173 LOADL         R4      L(0)    ; 4294967295 #z&=0xffffffff
      176 SEND          R3      :&      n=1 (0x01)
      180 SETUPVAR      R3      6       0

      184 RETURN        R3
```

上述操作实现了一个魔改的Tea系列加密，以C的形式给出如下。

```c
#define ut32 unsigned int
#define delta 305419896
void encrypt(ut32* src, ut32* k) {
    ut32 sum = 0;
    ut32 y = src[0];
    ut32 z = src[1];
    for (int i = 0; i < 16; i++) {
        y += (((z << 3) ^ (z >> 5)) + z) ^ (sum + k[((sum >> 11) + 1) & 3]);
        sum += delta;
        z += (((y << 3) ^ (y >> 5)) + y) ^ (sum + k[(sum & 3)]);
    }
    src[0] = y;
    src[1] = z;
}
```

综上，对输入先进行异或之后是魔改的Tea，把密文的16进制拼起来比对，解密脚本如下。

```python
from Crypto.Util.number import *
s='f469358b7f165145116e127ad6105917bce5225d6d62a714c390c5ed93b22d8b6b102a8813488fdb'
c=[]
for i in range(0,len(s),8): #8各一组4字节
    c.append(int(s[i:i+8],16))
print(c)
"""
[4100535691, 2132169029, 292426362, 3591395607, 3169133149, 1835181844, 3281044973, 2477927819, 1796221576, 323522523]
"""
k='aaaassssddddffff'
key=[]
for i in range(0,len(k),4):
    key.append(bytes_to_long(k[i:i+4].encode()))
print(key)
"""
[1633771873, 1936946035, 1684300900, 1717986918]
"""
```

解密tea

```c
#include<iostream>
#define ut32 unsigned int
#define delta 305419896
void decrypt(ut32* enc, ut32* k) {
    ut32 sum = delta * 16;
    ut32 y = enc[0];
    ut32 z = enc[1];
    for (int i = 0; i < 16; i++) {
        z -= (((y << 3) ^ (y >> 5)) + y) ^ (sum + k[(sum + 1) & 3]);
        sum -= delta;
        y -= (((z << 3) ^ (z >> 5)) + z) ^ (sum + k[((sum >> 11) + 1) & 3]);
    }
    enc[0] = y;
    enc[1] = z;
}
int main() {
    ut32 enc[10] = { 4100535691, 2132169029, 292426362, 3591395607, 3169133149, 1835181844, 3281044973, 2477927819, 1796221576, 323522523 };
    ut32 k[4] = { 1633771873, 1936946035, 1684300900, 1717986918 };
    for (int i = 0; i < 10; i += 2)
        decrypt(enc + i, k);
    for (int i = 0; i < 10; i++)
        printf("%08x", enc[i]);
    return 0;
}
//67080e02194b500d5c585f0b5e40461511470a08154211560d47491e04031d262771217626242765
```

解密异或

```python
c=bytes.fromhex('67080e02194b500d5c585f0b5e40461511470a08154211560d47491e04031d262771217626242765')
c=list(c)
c[0]^=1
for i in range(1,len(c)):
    c[i]^=(i+1)
    c[i]^=c[i-1]
print(bytes(c))
#flag{6ad1c70c-daa4-11ec-9d64-0242ac1200}
```

0x02 总结
=======

mruby字节码整体上比较可读，并且其基于寄存器的结构让传参并不是太复杂。不过要想快速恢复程序逻辑还要熟悉字节码的指令格式以及创建函数、对象和函数调用等模块的结构。

0x03 参考
=======

<https://www.anquanke.com/post/id/253572>