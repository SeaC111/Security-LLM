研究过网络编程的都知道那两个老毛病：数据粘包和数据不完整。为了解决这个问题神仙们设计了特定的数据结构进行传输和解析，这就是传输协议了(我自己的理解)。

HTTP 1 协议
=========

这里不再赘述，参考：<https://www.bilibili.com/read/cv5832775>

缺点是: 每次请求响应后都会断开连接，反复地进行 TCP 三次握手，四次挥手， 服务器无法主动推送。

HTTP 2 协议
=========

HTTP 2 支持了长链接，采用了二进制分帧的推送方式，在不改变 HTTP 的语义、方法、状态码、URL以及首部字段的情况下，在应用层（HTTP）和传输层（TCP）之间增加一个二进制分帧层，改进传输性能，实现低延迟高吞吐量.

基础知识
====

在深入了解 HTTP 2 之前， 需要知道点基础知识。

1 个字节 `byte` 等于 8 个比特 `bit` , 也就是 `0000 0000` (中间的空格是为了好计算而加的), **一个字节的数据最大是 127**，

怎么得来的？下面举个例子：**二进制转十进制**, 看如下表格. 八位 `bit` 对应 `2^0 - 2^7` (2的0次方到2的6次方), 当全为 `1` 时, 为 总合为 `127`，不是 8 个`bit`吗，少了一位呀。

### 原码

**因为最高位是符号位**，0表示正数，1表示负数，其余位表示数值的大小。所以一个字节最大存储为 `127`，这就是**原码**

[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-f0f94899de026f65b848ee6c7f0e692b5bdf273c.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-f0f94899de026f65b848ee6c7f0e692b5bdf273c.png)

### 反码

**正数的反码与其原码相同**；**负数的反码是对其原码逐位取反**，但**符号位除外**。如 `-127` 二进制 `1111 1111` 。反码是 `1000 0000`

### 补码

正数的补码与其原码相同；**负数的补码**是在其**反码的末位加1**。如 `-127` 二进制 `1111 1111` 。补码(反码+1)是 `1000 0001` ，**在计算机系统中，数值一律用补码来表示和存储**

### 接下来常用的 &amp; 0xFF

在 `socket` 通信中基于长度的成帧方法中经常见到, `websocket` 协议就是一个。`HTTP 2` 中也会用到. 最主要的作用是 **保证补码的一致性**，上面说了 **在计算机系统中，数值一律用补码来表示和存储，所以保证补码的一致性是非常重要的事情**。

`&` 是 **与运算**，只有都是 1 的情况下结果才是 1，其余情况为0，如下

```php
值一 : 110 1001
值二 : 101 1010
结果 : 100 1000
```

`0xFF` 0x 代表16进制数, `0xFF` 的二进制是 `1111 1111` 所以进行与运算就是本身

```php
值一 : 0110 1001
值二 : 1111 1111
结果 : 0110 1001
```

什么情况下会不同呢，参照网上给出的例子: <https://blog.csdn.net/i6223671/article/d> etails/88924481

```java
public static void main(String[] args) {
    byte b = -127;          // 1000 0001  : 127 二进制 1111 1111 取反 1000 0000 然后加 1 补码结果: 1000 0001

    int a =  b;             // byte 转 int, 补码会变成 32 位，往高位补，
                            // 补 1             : 1111 1111 1111 1111 1111 1111 1000 0001
                            // 最高位符号位不变取反后: 1000 0000 0000 0000 0000 0000 0111 1110
                            // 最高位符号位不变补码 :  1000 0000 0000 0000 0000 0000 0111 1111

    System.out.println(a);  // 输出结果 -127

    a =  b & 0xFF;          // & 0xFF 结果 : 1000 0001
                            // 实际上缺省了0(因为是int): 0000 0000 0000 0000 0000 0000 1000 0001
                            // 此时就是 128 + 1 = 129, 最高位符号位是 0 是正数

    System.out.println(a);  // 输出结果 129
}
```

虽然最终十进制的结果是 129；但因为**计算机中存储的是补码，所以我们只需要保证补码一致就好**

下面是类型长度参照表, 为什么上面的例子中 `byte` 转 `int` 补码为什么会变成32位, 因为`int`对应的大小是 `4 byte` 所以是 `(4 * 8 bit = 32 bit)` 自然 `byte` 转 `int` 时候需要向高位补到`32位bit`

[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-ecb0460c3386f239bcc63e3482620927514f445f.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-ecb0460c3386f239bcc63e3482620927514f445f.png)  
如果理解了前面的知识，就可以算出`int` 最大存储值是 `2147483647 (2^31-1)` 别忘了最高位是符号位所以是 `2 的 31 次方 - 1`;

`0xFF` 还有一个作用是**只保留低八位**，如果进行 `& 0xFF` 运算, `9 - 16 bit` 的值就被刷掉了。最后的结果只保留了低8位

```php
24676 : 0110 0000 0110 0100
0xFF  : 0000 0000 1111 1111
result: 0000 0000 0110 0100
```

### 移位运算符 "&gt;&gt;" 与 "&lt;&lt;"

这也会是常用到的，简单的说位移运算符就是 **移位用的**，看下面例子

```java
int a = 1;            // 0000 0001
int b = a << 1;         // 0000 0010
System.out.println(b);  // 2
int c = b >> 1;      // 0000 0001
System.out.println(b);  // 1
```

**会在什么地方用呢 ?** 想一下我们有一个非常大的数字需要传输比如 `201314`; 一个字节最大表示 `127`，需要存储的话那一个字节是不够的. 怎么办呢？

```java
// 10进制: 201314
// 2 进制: 11 0001 0010 0110 0010
```

我们将他分别存储到3个`byte`里，要用的时候拼接起来

```php
a = 0000 0011
b = 0001 0010
c = 0110 0010
```

先来看一个例子, 最后的结果是 `98`;

```java
byte a = (byte) 201314;
System.out.println(a);  //98
```

怎么来的呢 ? 我们知道`1byte = 8bit` `1byte`他只能存储 `8bit` , 先看一下 `98` 的 2进制，有没有很熟悉，是不是就是 `201314` 最低那 8 位的二进制， 为什么? 因为前面的知识: `int(32bit) -> byte(8 bit)`, 所以只保留了最低的 8 位

```php
10进制: 98
2 进制: 0110 0010

201314 二进制:0000 0011 0001 0010 0110 0010
98     二进制:0000 0000 0000 0000 0110 0010
```

那怎么存储 `9 - 16 bit` 呢，这个时候**位移运算符**就上场了. 我们只需要用位移运算符往右移8位，那么最低的8位就是 `9 - 16 bit`了， 如下的结果是 18, 二进制就是 `201314` 的 `9 - 16 bit` 的二进制 `0001 0010`，

```java
byte a = (byte) (201314 >> 8);
System.out.println(a);  // 18
// 18 二进制: 0001 0010
```

以此类推 `17 - 24 bit` 就是 `(byte) (201314 >> 16)`

### 或运算符 |

那怎么把分离存储的数据合并起来呢 ??, 这里就需要用到**或运算符 |**，或运算符的作用: 如果相对应位都是 0，则结果为 0，否则为 1， 如下

```php
A     = 0011 1100
B     = 0000 1101
A | B = 0011 1101
```

上面的例子看不出怎么合并. 那这样呢？ 是不是就叠加起来了

```php
A     = 0011 1100 0000 0000
B     = 0000 0000 0000 1101
A | B = 0011 1100 0000 1101
```

### 总结

经过上面的学习，我写了一个 Demo, 存储一个 `201314`, 那下面的 3 个字节能存储多大的数呢`2 的 23 (3 * 8) 次方 减 1` 记作 `2^23-1`, 所以是 `8388607`，

```java
public class Demo1 {
    public static byte[] body = new byte[3];

    public static long get() {
        // 0xFFL 多了个 L, 这里的L是用来说明跟在其前面的是什么类型的数据
        return ((((long) body[0]) & 0xFFL) << 16)
                | ((((long) body[1]) & 0xFFL) << 8)
                | (((long) body[2]) & 0xFFL);
    }

    public static void set(long num) {
        body[0] = (byte) (num >> 16);
        body[1] = (byte) (num >> 8);
        body[2] = (byte) (num);
    }

    public static void main(String[] args) {
        set(201314L);
        System.out.println(get());
    }
}
```

HTTP 2 数据帧
==========

附官方文档: \[<https://httpwg.org/specs/rfc7540.html#F> rameHeader\](<https://httpwg.org/specs/rfc7540.html#F> rameHeader)

HTTP2 通信的最小单位，所有帧都共享一个8字节的首部，其中包含帧的长度、类型、标志、还有保留位，并且至少有标识出当前帧所属的流的标识符，帧承载着特定类型的数据，如HTTP首部、负荷、等等。

下面是帧结构，从灰色第一行看起，`+0..7` 表示 8 个比特 `bit` 一个字节 `byte`，前三个字节(`+0..23` 共 24 `bit`)表示整个数据帧的数据长度。`+24..31` 8 `bit` 表示类型, 以此类推，

[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-bb07bcffcbed14cca0501b0269e2143bba42028e.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-bb07bcffcbed14cca0501b0269e2143bba42028e.png)

**Length**: 24 位比特表示的帧有效载荷的长度。通常不能大于 `2^14 (16,384)`， 你可以通过设置 `SETTINGS_MAX_F rame_SIZE` 来发送更大的值

`SETTINGS_MAX_F rame_SIZE`设置中通告的最大大小的限制。可以设置 `2^14 (16,384)` 和 `2^24 -1 (16,777,215)` 之间的任何值。

**Type**: 8位比特表示帧的类型， 帧类型决定了帧的格式和语义。实现必须忽略并丢弃任何类型未知的帧。

**Flags**: 为特定于帧类型的布尔标志保留的 8 位比特。标志被分配特定于指示的帧类型的语义。对于特定帧类型没有定义语义的标志必须被忽略并且在发送时必须保持未设置 (0x0)。

**R**: 保留的 1 位比特字段。该位的语义未定义，并且该位在发送时必须保持未设置 (0x0)，在接收时必须被忽略。

**Stream Identifier**: **流** 标识， 31 位比特的流标识符。值 0x0 保留用于与整个连接相关联的帧，而不是单个流

流标识有点难理解，先来了解一下**流：**存在于连接中的一个虚拟通道。流可以承载双向消息，每个流都有一个唯一的整数ID。如请求时携带的标识，响应时带上我就知道是回复该请求的了(我自己的理解)，或者响应时带上表示，分帧的时候标识是同一个数据包。

**F rame Payload**: 有效负载，就是实际的数据了。

借鉴学习 HTTP 2 实战
==============

这里演示实现简单的字符串通讯(我的封装技术很烂仅供参考)，简化了一下数据帧，如下，这样结构的数据帧已经够解决数据粘包和数据不完整了

[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-367a70f5511f474ee9ec366a406398bbdafebdd7.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-367a70f5511f474ee9ec366a406398bbdafebdd7.png)

F rame 帧定义抽象类
-------------

```java
package com.johnson.demo;

public abstract class F rame {
    // 帧长度大小
    public static final int HEADER_LENGTH_SIZE = 3;

    // 帧类型大小
    public static final int HEADER_TYPE_SIZE = 1;

    // 头部总大小
    public static final int HEADER_SIZE = HEADER_LENGTH_SIZE + HEADER_TYPE_SIZE;

    // 数据包最大长度
    public static final int MAX_CAPACITY = (int) Math.pow(2, HEADER_LENGTH_SIZE * 8) - 1;

    // 字符串类型标识
    public static final byte TYPE_STRING_F rame = 11;
}
```

Receive 接收处理
------------

```java
package com.johnson.demo;

import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;
import java.net.SocketException;

public class Receive {
    protected static byte[] header = new byte[F rame.HEADER_SIZE];

    public final int length;
    public final int type;
    public final byte[] body;

    public Receive(int length, int type, byte[] body) {
        this.length = length;
        if (length > F rame.MAX_CAPACITY || length < 0) {
            throw new RuntimeException("The Body length of a single 
            should be between 0 and " + F rame.MAX_CAPACITY);
        }

        this.type = type;

        this.body = body;
    }

    public static Receive handler(InputStream inputStream) throws IOException {

        int headerReadCount = inputStream.read(header);
        if (headerReadCount < F rame.HEADER_SIZE) {
            throw new SocketException("Packet exception, Bad request.");
        }

        int length = getLength(header);
        if (length > F rame.MAX_CAPACITY || length < 0) {
            throw new RuntimeException("The Body length of a single F rame should be between 0 and " + F rame.MAX_CAPACITY);
        }

        int type = getType(header);

        byte[] body = new byte[length];

        int bodyReadCount = inputStream.read(body);
        if (bodyReadCount != length) {
            throw new RuntimeException("The Body length " + length + ", But get not.");
        }

        inputStream.close();
        return new Receive(length, type, body);
    }

    public static int getType(byte[] header) {
        return header[3];
    }

    public static int getLength(byte[] header) {
        return ((header[0] & 0xFF) << 16 | (header[1] & 0xFF) << 8 | header[2] & 0XFF);
    }
}
```

Sender 发送处理
-----------

```java
package com.johnson.demo;

public class Sender {
    protected final byte[] header = new byte[F rame.HEADER_SIZE];
    protected final byte[] packet;

    public final byte[] payload;
    public final int length;

    public Sender(byte type, String data) {
        payload = data.getBytes();
        length = payload.length;
        if (length > F rame.MAX_CAPACITY || length < 0) {
            throw new RuntimeException("The Body length of a single F rame should be between 0 and " + F rame.MAX_CAPACITY);
        }

        header[1] = (byte) (payload.length >> 16);
        header[1] = (byte) (payload.length >> 8);
        header[2] = (byte) payload.length;

        header[3] = type;

        packet = new byte[length + F rame.HEADER_SIZE];
        System.arraycopy(header, 0, packet, 0, F rame.HEADER_SIZE);
        System.arraycopy(payload, 0, packet, F rame.HEADER_SIZE, length);
    }

    public byte[] getPacket() {
        return packet;
    }
}
```

Demo1 Server 端
--------------

```java
package com.johnson.demo;

import java.io.IOException;
import java.io.InputStream;
import java.net.ServerSocket;
import java.net.Socket;

public class Demo1 {
    public static void main(String[] args) {
        try {
            ServerSocket serverSocket = new ServerSocket(8848);
            Socket accept = serverSocket.accept();
            InputStream inputStream = accept.getInputStream();

            Receive receive = Receive.handler(inputStream);

            if (receive.type != F rame.TYPE_STRING_F rame) {
                throw new RuntimeException("The packet was discarded due to an abnormal packet type");
            }

            System.out.println(new String(receive.body));

            inputStream.close();
            accept.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
```

Demo2 Client 端

```java
package com.johnson.demo;

import java.io.IOException;
import java.io.OutputStream;
import java.net.Socket;

public class Demo2 {
    public static void main(String[] args) {
        try {
            Socket socket = new Socket("127.0.0.1", 8848);

            Sender hello_client = new Sender(F rame.TYPE_STRING_F rame, "Hello World");

            OutputStream outputStream = socket.getOutputStream();
            outputStream.write(hello_client.getPacket());
            outputStream.close();
            socket.close();
        } catch (IOException e) {
            e.printStackTrace();
        }

    }
}
```