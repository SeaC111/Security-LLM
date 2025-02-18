某游戏盒App的So层逆向
-------------

### 抓包

进入 App 的登录界面，输入账号：15026818188，密码：123456789。

![1.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-670f6123b91fd705dc262eb0b64181c23605c718.png)

然后点击登录后，进行抓包。

![2.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-53ad17a3a88228672c1401a6f4a816d82e3e0cb2.png)

对抓到的包进行请求参数的预览，发现只有 sign 和 password 是加密的。下面就对这两个请求头的值进行逆向分析。

### Java层协议逆向

对于字符串的加密，尝试使用 objection hook java.lang.String.getBytes 方法。

android hooking watch class\_method java.lang.String.getBytes --dump-args --dump-backtrace --dump-return

将 windows 的命令行窗口放置最大，hook 到的结果都要在 50 页以上，是不可能找得到的关键方法的。

在尝试使用，静态分析工具 GDAE 搜索 "sign" 试试。

![3.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-95ea97664b6c9dc8c696df41074587a65c39f4b6.png)

再搜索 "password" 试试。

![4.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-7e187850a61a77e6dfba19dfd883e60046b3eeec.png)

buildRequestParams 方法虽然名字是相同的，但是在不同的类下。

在 sign 的搜索结果中，随意点开一个 buildRequestParams 方法。

![5.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-119b01e339185fdcaa3cec76fc06f5114c925bee.png)

在 password 的搜索结果中，随意点开一个 buildRequestParams 方法。

![6.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-c6837b22a2e296137ec1ac26a10df275d2326a13.png)

通过上面的两个搜索结果可以看到，最终的值都是通过 AppNativeHelper 类调用静态方法得到的。

AppNativeHelper 类如下：

![7.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-606e41e4b218b66ad89013bd52aecafdce586ae4.png)

这个类的功能，通过上述代码可知，是加载了 libNativeHelper.so ，然后调用了里面的 native 方法。

### So层关键函数定位

虽然通过 Java 层分析没有找到 Java 层关键的发包函数，但是可以完全确定，sign 和 password 的值是 So 层函数产生的。

于是关键点还是要放在 So 层的分析。

既然是 So 层产生的，那么 sign 和 password 的值很有可能是由 jstring 类型返回的，那么就会调用 NewStringUTF 函数。

NewStringUTF 函数，是 env 调用的，是 jni 函数。

jni 函数放在了 libart.so 中，所以要先遍历 libart.so 中的函数，找打 NewStringUTF 函数的地址，在进行 hook 。

NewStringUTF 函数有两个参数，第 2 个参数是想要的数据。

![8.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-f40f6c75e98293d99a188c48f36c5afc77101709.png)

编写 frida 代码：

```js
var artSym = Module.enumerateSymbols("libart.so");
var NewStringUTFAddr = null;
for (var i = 0; i < artSym.length; i++) {
    if (artSym[i].name.indexOf("CheckJNI") == -1 && artSym[i].name.indexOf("NewStringUTF") != -1) {
        console.log(JSON.stringify(artSym[i]));
        NewStringUTFAddr = artSym[i].address;
    }
}

if (NewStringUTFAddr != null) {
    Interceptor.attach(NewStringUTFAddr, {
        onEnter: function (args) {
            console.log(Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n') + '\n');
            console.log(args[1].readCString());
        },
        onLeave: function (retval) {
        }
    });
}
```

hook 上之后，重新进行登录提交并抓包。

![9.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-3f459472a222d62426b5e31c4a9d2a2dd2693f0c.png)

对抓到包的值在 hook 到的结果中进行搜索。

password 的返回值在 libNativeHelper.so 中，偏移量是 0x5ba5。

![10.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-cc04a69eb9b4e320232f43271e63dabac35c5862.png)

sign 的返回值在 libNativeHelper.so 中，偏移量是 0x4eef。

![11.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-6e74a3967bbb3e4d710314fbf20b1c8d1f04b273.png)

### So层sign逆向

既然得到 sign 的返回值的地址，就对其进行逆向分析。

在 IDA 中打开 libNativeHelper.so ，跳转到地址 0x4eef。

反编译的结果如下：

```c
jstring __fastcall sub_4DF0(JNIEnv *env, int a2, const char *a3)
{
  void *v5; // r9
  const char *v6; // r5
  size_t v7; // r4
  size_t v8; // r0
  char *v9; // r0
  char *v10; // r10
  size_t v11; // r0
  size_t v12; // r0
  int v13; // r11
  char v15[16]; // [sp+8h] [bp-B0h] BYREF
  char v16[88]; // [sp+18h] [bp-A0h] BYREF
  char v17[40]; // [sp+70h] [bp-48h] BYREF

  v5 = (void *)a2;
  if ( a2 )
    v6 = (*env)->GetStringUTFChars(env, a2, 0);
  else
    v6 = (const char *)&unk_13A59;
  v7 = strlen(v6);
  v8 = strlen(a3);
  v9 = (char *)calloc(v8 + v7 + 2, 1u);
  if ( v9 )
  {
    v10 = v9;
    v11 = strlen(v6);
    strncpy(v10, v6, v11 + 1);
    if ( a3 )
      strcat(v10, a3);
    memset(v17, 0, 0x21u);
    memset(v16, 0, sizeof(v16));
    sub_4538(v16);
    v12 = strlen(v10);
    sub_4564(v16, v10, v12);
    v13 = 0;
    memset(v15, 0, sizeof(v15));
    sub_4D1C((int)v15, (int)v16);
    while ( v13 != 16 )
      sprintf(v17, "%s%02x", v17, (unsigned __int8)v15[v13++]);
    free(v10);
    if ( v5 )
      (*env)->ReleaseStringUTFChars(env, v5, v6);
    return (*env)->NewStringUTF(env, v17);
  }
  return v5;
}
```

v17 肯定是 sign 值了，往前捋。

前面调用了 sprintf(v17, "%s%02x", v17, (unsigned \_\_int8)v15\[v13++\])，所以 v17 是 v15给的。

v15 又在 sub\_4D1C(v15, v16) 函数中。

对 sub\_4D1C 函数进行 hook。并抓包。

```js
let nativeHelperAddr = Module.findBaseAddress("libNativeHelper.so")
let sub4d1dddr = nativeHelperAddr.add(0x4d1d)
console.log(sub4d1dddr)
Interceptor.attach(sub4d1dddr, {
    onEnter: function (args) {
        this.args0 = args[0]
        this.args1 = args[1]

        console.log("onEnter args0 => ", hexdump(args[0]))
        console.log("onEnter args1 => ", hexdump(args[1]))

    }, onLeave: function (retval) {
        console.log("onLeave args0 => ", hexdump(this.args0))
        console.log("onLeave args1 => ", hexdump(this.args1))
        console.log("retval => ", hexdump(retval))
    }
})
```

hook 到的结果：

```php
0xac8d9d1d
onEnter args0 =>             0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
ff8825e0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
ff8825f0  51 f9 b0 b2 d6 f9 a1 45 aa 6d 84 63 89 1e 4e e1  Q......E.m.c..N.
ff882600  f0 02 00 00 00 00 00 00 32 76 78 23 73 66 2a 5e  ........2vx#sf*^
ff882610  46 6c 6b 6c 53 44 2a 39 73 64 66 28 6d 24 26 71  FlklSD*9sdf(m$&q
ff882620  77 25 64 37 70 6f 4a 68 56 33 77 71 6d 54 44 4f  w%d7poJhV3wqmTDO
ff882630  39 74 4d 6e 63 56 48 67 67 3d 3d 31 35 30 32 36  9tMncVHgg==15026
ff882640  38 31 38 31 38 38 65 66 00 00 00 00 00 00 00 00  818188ef........
ff882650  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
ff882660  00 00 00 00 00 00 00 00 00 26 88 ff c0 26 88 ff  .........&...&..
ff882670  da 4e 76 d8 c0 26 88 ff 00 de a4 e7 c0 27 88 ff  .Nv..&.......'..
ff882680  44 27 88 ff 6f 00 00 00 40 91 a8 e7 e8 14 c1 b5  D'..o...@.......
ff882690  a8 26 88 ff f7 75 8e ac 00 00 00 00 94 2f f1 b6  .&...u......./..
ff8826a0  02 00 00 00 00 de a4 e7 bc f0 9b bd 2b a2 4c bd  ............+.L.
ff8826b0  94 2f f1 b6 94 5a 88 ff 02 00 00 00 98 58 ee 12  ./...Z.......X..
ff8826c0  48 94 80 13 07 00 00 00 0c 27 88 ff 93 4f 99 71  H........'...O.q
ff8826d0  b0 91 80 13 00 00 00 00 00 00 00 00 00 00 00 00  ................
onEnter args1 =>             0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
ff8825f0  51 f9 b0 b2 d6 f9 a1 45 aa 6d 84 63 89 1e 4e e1  Q......E.m.c..N.
ff882600  f0 02 00 00 00 00 00 00 32 76 78 23 73 66 2a 5e  ........2vx#sf*^
ff882610  46 6c 6b 6c 53 44 2a 39 73 64 66 28 6d 24 26 71  FlklSD*9sdf(m$&q
ff882620  77 25 64 37 70 6f 4a 68 56 33 77 71 6d 54 44 4f  w%d7poJhV3wqmTDO
ff882630  39 74 4d 6e 63 56 48 67 67 3d 3d 31 35 30 32 36  9tMncVHgg==15026
ff882640  38 31 38 31 38 38 65 66 00 00 00 00 00 00 00 00  818188ef........
ff882650  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
ff882660  00 00 00 00 00 00 00 00 00 26 88 ff c0 26 88 ff  .........&...&..
ff882670  da 4e 76 d8 c0 26 88 ff 00 de a4 e7 c0 27 88 ff  .Nv..&.......'..
ff882680  44 27 88 ff 6f 00 00 00 40 91 a8 e7 e8 14 c1 b5  D'..o...@.......
ff882690  a8 26 88 ff f7 75 8e ac 00 00 00 00 94 2f f1 b6  .&...u......./..
ff8826a0  02 00 00 00 00 de a4 e7 bc f0 9b bd 2b a2 4c bd  ............+.L.
ff8826b0  94 2f f1 b6 94 5a 88 ff 02 00 00 00 98 58 ee 12  ./...Z.......X..
ff8826c0  48 94 80 13 07 00 00 00 0c 27 88 ff 93 4f 99 71  H........'...O.q
ff8826d0  b0 91 80 13 00 00 00 00 00 00 00 00 00 00 00 00  ................
ff8826e0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
onLeave args0 =>             0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
ff8825e0  e2 73 11 3e 68 12 69 93 bc 4c 49 4a 51 86 00 b6  .s.>h.i..LIJQ...
ff8825f0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
ff882600  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
ff882610  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
ff882620  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
ff882630  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
ff882640  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
ff882650  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
ff882660  00 00 00 00 00 00 00 00 00 26 88 ff c0 26 88 ff  .........&...&..
ff882670  da 4e 76 d8 c0 26 88 ff 00 de a4 e7 c0 27 88 ff  .Nv..&.......'..
ff882680  44 27 88 ff 6f 00 00 00 40 91 a8 e7 e8 14 c1 b5  D'..o...@.......
ff882690  a8 26 88 ff f7 75 8e ac 00 00 00 00 94 2f f1 b6  .&...u......./..
ff8826a0  02 00 00 00 00 de a4 e7 bc f0 9b bd 2b a2 4c bd  ............+.L.
ff8826b0  94 2f f1 b6 94 5a 88 ff 02 00 00 00 98 58 ee 12  ./...Z.......X..
ff8826c0  48 94 80 13 07 00 00 00 0c 27 88 ff 93 4f 99 71  H........'...O.q
ff8826d0  b0 91 80 13 00 00 00 00 00 00 00 00 00 00 00 00  ................
onLeave args1 =>             0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
ff8825f0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
ff882600  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
ff882610  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
ff882620  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
ff882630  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
ff882640  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
ff882650  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
ff882660  00 00 00 00 00 00 00 00 00 26 88 ff c0 26 88 ff  .........&...&..
ff882670  da 4e 76 d8 c0 26 88 ff 00 de a4 e7 c0 27 88 ff  .Nv..&.......'..
ff882680  44 27 88 ff 6f 00 00 00 40 91 a8 e7 e8 14 c1 b5  D'..o...@.......
ff882690  a8 26 88 ff f7 75 8e ac 00 00 00 00 94 2f f1 b6  .&...u......./..
ff8826a0  02 00 00 00 00 de a4 e7 bc f0 9b bd 2b a2 4c bd  ............+.L.
ff8826b0  94 2f f1 b6 94 5a 88 ff 02 00 00 00 98 58 ee 12  ./...Z.......X..
ff8826c0  48 94 80 13 07 00 00 00 0c 27 88 ff 93 4f 99 71  H........'...O.q
ff8826d0  b0 91 80 13 00 00 00 00 00 00 00 00 00 00 00 00  ................
ff8826e0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
retval =>             0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
ff882648  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
ff882658  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
ff882668  00 26 88 ff c0 26 88 ff da 4e 76 d8 c0 26 88 ff  .&...&...Nv..&..
ff882678  00 de a4 e7 c0 27 88 ff 44 27 88 ff 6f 00 00 00  .....'..D'..o...
ff882688  40 91 a8 e7 e8 14 c1 b5 a8 26 88 ff f7 75 8e ac  @........&...u..
ff882698  00 00 00 00 94 2f f1 b6 02 00 00 00 00 de a4 e7  ...../..........
ff8826a8  bc f0 9b bd 2b a2 4c bd 94 2f f1 b6 94 5a 88 ff  ....+.L../...Z..
ff8826b8  02 00 00 00 98 58 ee 12 48 94 80 13 07 00 00 00  .....X..H.......
ff8826c8  0c 27 88 ff 93 4f 99 71 b0 91 80 13 00 00 00 00  .'...O.q........
ff8826d8  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
ff8826e8  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
ff8826f8  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
ff882708  00 00 00 00 00 00 00 00 00 00 00 00 02 00 00 00  ................
ff882718  00 de a4 e7 bc f0 9b bd 00 00 00 00 c0 27 88 ff  .............'..
ff882728  44 27 88 ff c7 eb a4 e3 00 00 00 00 48 94 80 13  D'..........H...
ff882738  88 27 88 ff 48 27 88 ff 0c 00 00 00 01 00 00 00  .'..H'..........
```

本次抓包的结果：

![12.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-c542ab259aa98c6e4be7f6d6c739f9e6c7ec3525.png)

从结果可以看到

进入函数前，v15 什么都没有，v16 看不懂。

函数结束后，v15 被附上了值，通过和抓包的结果比对，就是 sign 的值；v16 被清空，推测 v16 可能是一些初始值。

继续往上看反汇编代码，点开 sub\_4538(v16)。

发现里面的值是标准的，MD5 初始化常量。所以 v16 就是做初始化用的。

![13.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-1fbdc39ae83d3844c66db5abe136774c021813e7.png)

在往下看，sub\_4564(v16, v10, v12) 。

v12 = strlen(v10) ， v12 是 v10 的长度。

strcat(v10, a3) ，v10 是和 a3 连接起来的，a3 又是传进来的数据。那么 v10 大概率就是明文了。

所以 MD5 的关键运算是在 sub\_4564 中。

进入 sub\_4564 中，进入后继续跟进函数。发现里面是标准的 MD5 参与运算的 K 值。

![14.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-aba1bcd75d7e7fe123fad006674b77ed499d16da.png)

hook sub\_4564 函数，并抓包。目的有两个，第一个是验证刚才的推论，第二是看一下明文是怎样构造的。

```js
let nativeHelperAddr = Module.findBaseAddress("libNativeHelper.so")
let sub4565dddr = nativeHelperAddr.add(0x4565)
console.log(sub4565dddr)
Interceptor.attach(sub4565dddr, {
    onEnter: function (args) {
        this.args0 = args[0]
        this.args1 = args[1]
        this.args2 = args[2]

        console.log("onEnter args0 => ", hexdump(args[0]))
        console.log("onEnter args1 => ", hexdump(args[1]))
        console.log("onEnter args2 => ", args[2].toInt32())

    }, onLeave: function (retval) {
        console.log("onLeave args0 => ", hexdump(this.args0))
        console.log("onLeave args1 => ", hexdump(this.args1))
        console.log("onLeave args2 => ", this.args2.toInt32())
    }
})
```

hook 到的结果：

```php
0xac8d9565
onEnter args0 =>             0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
ff8825f0  01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10  .#Eg........vT2.
ff882600  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
ff882610  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
ff882620  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
ff882630  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
ff882640  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
ff882650  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
ff882660  00 00 00 00 00 00 00 00 00 26 88 ff c0 26 88 ff  .........&...&..
ff882670  da 4e 76 d8 c0 26 88 ff 00 de a4 e7 c0 27 88 ff  .Nv..&.......'..
ff882680  44 27 88 ff 6f 00 00 00 40 91 a8 e7 00 cc b0 b5  D'..o...@.......
ff882690  a8 26 88 ff f7 75 8e ac 00 00 00 00 94 2f f1 b6  .&...u......./..
ff8826a0  02 00 00 00 00 de a4 e7 bc f0 9b bd 2b a2 4c bd  ............+.L.
ff8826b0  94 2f f1 b6 94 5a 88 ff 02 00 00 00 a0 56 a6 13  ./...Z.......V..
ff8826c0  90 f9 3e 14 07 00 00 00 0c 27 88 ff 93 4f 99 71  ..>......'...O.q
ff8826d0  f8 f6 3e 14 00 00 00 00 00 00 00 00 00 00 00 00  ..>.............
ff8826e0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
onEnter args1 =>             0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
dc4a4200  31 36 39 30 33 34 33 30 35 35 30 63 34 34 33 35  16903430550c4435
dc4a4210  65 38 62 38 63 61 61 31 35 34 31 79 74 48 4a 68  e8b8caa1541ytHJh
dc4a4220  56 33 77 71 6d 54 44 4f 39 74 4d 6e 63 56 48 67  V3wqmTDO9tMncVHg
dc4a4230  67 3d 3d 31 35 30 32 36 38 31 38 31 38 38 65 66  g==15026818188ef
dc4a4240  32 76 78 23 73 66 2a 5e 46 6c 6b 6c 53 44 2a 39  2vx#sf*^FlklSD*9
dc4a4250  73 64 66 28 6d 24 26 71 77 25 64 37 70 6f 00 00  sdf(m$&qw%d7po..
dc4a4260  84 53 92 e5 09 00 00 00 00 00 00 00 72 00 00 00  .S..........r...
dc4a4270  00 00 00 00 c0 c4 4c dc d0 c4 4c dc d0 c4 4c dc  ......L...L...L.
dc4a4280  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
dc4a4290  00 00 80 3f 00 00 00 00 80 08 01 00 80 4a 44 dc  ...?.........JD.
dc4a42a0  c0 42 4a dc 08 00 00 00 00 00 00 00 00 00 00 00  .BJ.............
dc4a42b0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
dc4a42c0  00 00 04 80 00 00 00 80 00 00 00 00 00 00 00 00  ................
dc4a42d0  00 00 00 00 00 00 00 80 00 00 00 00 00 00 00 00  ................
dc4a42e0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
dc4a42f0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
onEnter args2 =>  94
onLeave args0 =>             0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
ff8825f0  00 ba 0f 2e 03 b5 d5 ec 06 6c 64 64 4a 2a 7d 00  .........lddJ*}.
ff882600  f0 02 00 00 00 00 00 00 32 76 78 23 73 66 2a 5e  ........2vx#sf*^
ff882610  46 6c 6b 6c 53 44 2a 39 73 64 66 28 6d 24 26 71  FlklSD*9sdf(m$&q
ff882620  77 25 64 37 70 6f 4a 68 56 33 77 71 6d 54 44 4f  w%d7poJhV3wqmTDO
ff882630  39 74 4d 6e 63 56 48 67 67 3d 3d 31 35 30 32 36  9tMncVHgg==15026
ff882640  38 31 38 31 38 38 65 66 00 00 00 00 00 00 00 00  818188ef........
ff882650  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
ff882660  00 00 00 00 00 00 00 00 00 26 88 ff c0 26 88 ff  .........&...&..
ff882670  da 4e 76 d8 c0 26 88 ff 00 de a4 e7 c0 27 88 ff  .Nv..&.......'..
ff882680  44 27 88 ff 6f 00 00 00 40 91 a8 e7 00 cc b0 b5  D'..o...@.......
ff882690  a8 26 88 ff f7 75 8e ac 00 00 00 00 94 2f f1 b6  .&...u......./..
ff8826a0  02 00 00 00 00 de a4 e7 bc f0 9b bd 2b a2 4c bd  ............+.L.
ff8826b0  94 2f f1 b6 94 5a 88 ff 02 00 00 00 a0 56 a6 13  ./...Z.......V..
ff8826c0  90 f9 3e 14 07 00 00 00 0c 27 88 ff 93 4f 99 71  ..>......'...O.q
ff8826d0  f8 f6 3e 14 00 00 00 00 00 00 00 00 00 00 00 00  ..>.............
ff8826e0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
onLeave args1 =>             0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
dc4a4200  31 36 39 30 33 34 33 30 35 35 30 63 34 34 33 35  16903430550c4435
dc4a4210  65 38 62 38 63 61 61 31 35 34 31 79 74 48 4a 68  e8b8caa1541ytHJh
dc4a4220  56 33 77 71 6d 54 44 4f 39 74 4d 6e 63 56 48 67  V3wqmTDO9tMncVHg
dc4a4230  67 3d 3d 31 35 30 32 36 38 31 38 31 38 38 65 66  g==15026818188ef
dc4a4240  32 76 78 23 73 66 2a 5e 46 6c 6b 6c 53 44 2a 39  2vx#sf*^FlklSD*9
dc4a4250  73 64 66 28 6d 24 26 71 77 25 64 37 70 6f 00 00  sdf(m$&qw%d7po..
dc4a4260  84 53 92 e5 09 00 00 00 00 00 00 00 72 00 00 00  .S..........r...
dc4a4270  00 00 00 00 c0 c4 4c dc d0 c4 4c dc d0 c4 4c dc  ......L...L...L.
dc4a4280  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
dc4a4290  00 00 80 3f 00 00 00 00 80 08 01 00 80 4a 44 dc  ...?.........JD.
dc4a42a0  c0 42 4a dc 08 00 00 00 00 00 00 00 00 00 00 00  .BJ.............
dc4a42b0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
dc4a42c0  00 00 04 80 00 00 00 80 00 00 00 00 00 00 00 00  ................
dc4a42d0  00 00 00 00 00 00 00 80 00 00 00 00 00 00 00 00  ................
dc4a42e0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
dc4a42f0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
onLeave args2 =>  94
```

本次抓包的结果：

![15.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-177109483084fccf9190f8fa396d6d34ca4da5ff.png)

通过抓包和 hook 到的结果可知。

明文就是由：dateline(时间戳) + deviceIdentifier(设备标识符) + info("1") + password("输入的密码加密后的值") + 输入的手机号 + ef2vx#sf*^FlklSD*9sdf(m$&amp;qw%d7po。

后面这串字符串乱乱的，但是是固定的。通过静态分析，是在 Java 层写死的。

![16.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-2bf297620afe5af4d0c091dce74700be826da572.png)

sign 就是上面构成的字符串取 md5。

![17.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-a3b716c904271fb95e31b84018fd5b6b949e2226.png)

sign 值的分析完毕，接下来分析 pasword。

### So层password逆向

password 返回值也被找到了。

在 IDA 中打开 libNativeHelper.so ，跳转到地址 0x5ba5。

反编译的结果如下：

```c
jstring __fastcall sub_5AEC(JNIEnv *env, int a2, char *a3)
{
  const char *v5; // r0
  char *v6; // r5
  signed int v7; // r0
  unsigned int v8; // r4
  int v9; // r6
  int v10; // r10
  char *v11; // r0
  char *v12; // r11
  void *v13; // r0
  size_t v14; // r1
  void *v15; // r4
  char *password; // r8
  jstring v17; // r4

  if ( a2 )
  {
    v5 = (const char *)sub_5E60(env, a2, "utf-8");
    if ( v5 )
    {
      v6 = (char *)v5;
      v7 = strlen(v5);
      v8 = (v7 + ((unsigned int)(v7 >> 31) >> 29)) & 0xFFFFFFF8;
      v9 = v7 % 8;
      if ( !(v7 % 8) )
        v8 = v7;
      v10 = v8 + 8;
      v11 = (char *)calloc(v8 + 8, 1u);
      if ( v11 )
      {
        v12 = v11;
        memset(v11, (unsigned __int8)(8 - v9), v8 + 8);
        qmemcpy(v12, v6, strlen(v6));
        v13 = calloc(v8 + 9, 1u);
        v14 = v8 + 9;
        v15 = v13;
        memset(v13, 0, v14);
        if ( v15 )
        {
          sub_5BCC((int)v12, (int)v15, v10, a3, 1);
          password = (char *)sub_209C(v15, v10);
          free(v15);
          free(v12);
          free(v6);
          if ( password )
          {
            v17 = (*env)->NewStringUTF(env, password);
            free(password);
            return v17;
          }
        }
      }
      else
      {
        free(v6);
      }
    }
  }
  return 0;
}
```

网上捋，password = (char \*)sub\_209C(v15, v10)。

点进去 sub\_209C 函数。

```c
char *__fastcall sub_209C(int a1, int a2, _DWORD *a3)
{
  int v4; // r8
  char *result; // r0
  unsigned __int8 *v6; // r3
  int v7; // r12
  unsigned int v8; // r4
  unsigned int v9; // r6
  unsigned int v10; // r5
  char *v11; // r1
  unsigned int v12; // r6
  int v13; // r5
  unsigned int v14; // r3
  char v15; // r2

  if ( a2 + 2 <= -1 )
  {
    result = 0;
    if ( a3 )
      *a3 = 0;
  }
  else
  {
    v4 = a2;
    result = (char *)malloc(4 * ((a2 + 2) / 3u) + 1);
    v6 = (unsigned __int8 *)(a1 + 1);
    v7 = 0;
    while ( 1 )
    {
      v11 = &result[v7];
      if ( v4 < 3 )
        break;
      v8 = *(v6 - 1);
      v7 += 4;
      v4 -= 3;
      *v11 = aAbcdefghijklmn[v8 >> 2];
      v9 = *v6;
      v11[1] = aAbcdefghijklmn[(v9 >> 4) | (16 * (v8 & 3))];
      v10 = v6[1];
      v6 += 3;
      LOBYTE(v9) = aAbcdefghijklmn[(v10 >> 6) | (4 * (v9 & 0xF))];
      v11[3] = aAbcdefghijklmn[v10 & 0x3F];
      v11[2] = v9;
    }
    if ( v4 )
    {
      v12 = *(v6 - 1);
      *v11 = aAbcdefghijklmn[v12 >> 2];
      v13 = (16 * v12) & 0x30;
      if ( v4 < 2 )
      {
        v11[1] = aAbcdefghijklmn[v13];
        v15 = 61;
      }
      else
      {
        v14 = *v6;
        v15 = aAbcdefghijklmn[4 * (v14 & 0xF)];
        v11[1] = aAbcdefghijklmn[v13 | (v14 >> 4)];
      }
      v11[2] = v15;
      v11[3] = 61;
      v11 += 4;
    }
    *v11 = 0;
  }
  return result;
}
```

点进去发现有一堆，abcd 这样的字符串。转换成汇编代码进行查看。

发现是 ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/ 。

![18.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-889a45ff193e1e06e5c7881ecba83cdce0ef0ca3.png)

所以判断 sub\_209C 函数，实现的很可能就是 base64 编码。

v10 前面有一个 v10 = v8 + 8。所以 v10 是长度，v15 就是明文。

hook 一下，并进行抓包。

```js
let nativeHelperAddr = Module.findBaseAddress("libNativeHelper.so")
let sub209ddddr = nativeHelperAddr.add(0x209d)
console.log(sub209ddddr)
Interceptor.attach(sub209ddddr, {
    onEnter: function (args) {
        this.args0 = args[0]
        this.args1 = args[1]

        console.log("onEnter args0 => ", hexdump(args[0]))
        console.log("onEnter args1 => ", args[1].toInt32())

    }, onLeave: function (retval) {
        console.log("onLeave args0 => ", hexdump(this.args0))
        console.log("onLeave args1 => ", this.args1.toInt32())
        console.log("retval => ", hexdump(retval))
    }
})
```

hook 到的结果：

```php
0xac8d709d
onEnter args0 =>             0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
ab7f6ce0  ca d1 c9 85 5d f0 aa 64 c3 3b db 4c 9d c5 47 82  ....]..d.;.L..G.
ab7f6cf0  00 00 00 00 00 00 00 00 b0 23 46 dc 18 7a 7f ab  .........#F..z..
ab7f6d00  a8 7a 7f ab 01 00 00 00 c0 ce df c3 4c d5 5d bf  .z..........L.].
ab7f6d10  c0 f6 52 ba df 3b 6b fe 10 82 2b cf 80 79 75 ba  ..R..;k...+..yu.
ab7f6d20  a8 79 75 ba c0 79 75 ba 84 79 17 e5 00 00 00 00  .yu..yu..y......
ab7f6d30  08 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
ab7f6d40  28 61 7f ab 25 b5 10 2a e4 b0 5d bf e0 6c 7e ab  (a..%..*..]..l~.
ab7f6d50  f0 6c 7e ab 00 6d 7e ab c4 79 17 e5 05 00 00 00  .l~..m~..y......
ab7f6d60  08 00 00 00 00 00 00 00 00 00 00 00 14 67 ca bb  .............g..
ab7f6d70  08 51 7f ab 88 70 7f ab f0 78 a0 e7 01 00 00 00  .Q...p...x......
ab7f6d80  80 af d9 c3 30 92 f0 b6 f3 04 35 3f f3 04 35 3f  ....0.....5?..5?
ab7f6d90  f3 04 35 3f f3 04 35 3f 54 bb 08 ba 80 4f e3 bb  ..5?..5?T....O..
ab7f6da0  c0 16 46 dc d2 a5 8a 03 c4 b1 5d bf 80 34 cc b5  ..F.......]..4..
ab7f6db0  88 34 cc b5 90 34 cc b5 a4 79 17 e5 00 00 00 00  .4...4...y......
ab7f6dc0  08 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
ab7f6dd0  00 00 00 00 00 00 00 00 18 6e 7f ab 01 00 00 00  .........n......
onEnter args1 =>  16
onLeave args0 =>             0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
ab7f6ce0  ca d1 c9 85 5d f0 aa 64 c3 3b db 4c 9d c5 47 82  ....]..d.;.L..G.
ab7f6cf0  00 00 00 00 00 00 00 00 b0 23 46 dc 18 7a 7f ab  .........#F..z..
ab7f6d00  a8 7a 7f ab 01 00 00 00 c0 ce df c3 4c d5 5d bf  .z..........L.].
ab7f6d10  c0 f6 52 ba df 3b 6b fe 10 82 2b cf 80 79 75 ba  ..R..;k...+..yu.
ab7f6d20  a8 79 75 ba c0 79 75 ba 84 79 17 e5 00 00 00 00  .yu..yu..y......
ab7f6d30  08 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
ab7f6d40  28 61 7f ab 25 b5 10 2a e4 b0 5d bf e0 6c 7e ab  (a..%..*..]..l~.
ab7f6d50  f0 6c 7e ab 00 6d 7e ab c4 79 17 e5 05 00 00 00  .l~..m~..y......
ab7f6d60  08 00 00 00 00 00 00 00 00 00 00 00 14 67 ca bb  .............g..
ab7f6d70  08 51 7f ab 88 70 7f ab f0 78 a0 e7 01 00 00 00  .Q...p...x......
ab7f6d80  80 af d9 c3 30 92 f0 b6 f3 04 35 3f f3 04 35 3f  ....0.....5?..5?
ab7f6d90  f3 04 35 3f f3 04 35 3f 54 bb 08 ba 80 4f e3 bb  ..5?..5?T....O..
ab7f6da0  c0 16 46 dc d2 a5 8a 03 c4 b1 5d bf 80 34 cc b5  ..F.......]..4..
ab7f6db0  88 34 cc b5 90 34 cc b5 a4 79 17 e5 00 00 00 00  .4...4...y......
ab7f6dc0  08 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
ab7f6dd0  00 00 00 00 00 00 00 00 18 6e 7f ab 01 00 00 00  .........n......
onLeave args1 =>  16
retval =>             0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
ba7535c0  79 74 48 4a 68 56 33 77 71 6d 54 44 4f 39 74 4d  ytHJhV3wqmTDO9tM
ba7535d0  6e 63 56 48 67 67 3d 3d 00 2e 70 6c 75 67 69 00  ncVHgg==..plugi.
ba7535e0  01 00 00 00 53 00 00 00 00 00 04 00 00 00 00 00  ....S...........
ba7535f0  00 00 28 b7 00 00 00 00 00 00 00 00 00 00 00 00  ..(.............
ba753600  49 4e 54 45 47 45 52 00 34 00 33 00 39 00 39 00  INTEGER.4.3.9.9.
ba753610  2e 00 61 00 6e 00 61 00 6c 00 79 00 00 00 00 00  ..a.n.a.l.y.....
ba753620  6c 61 72 67 65 20 6f 62 6a 65 63 74 20 73 70 61  large object spa
ba753630  63 65 20 61 6c 6c 6f 63 61 74 69 6f 6e 00 00 00  ce allocation...
ba753640  49 4e 54 45 47 45 52 00 63 6f 6e 74 65 6e 74 2e  INTEGER.content.
ba753650  53 68 61 72 65 64 50 72 65 66 65 72 65 6e 63 00  SharedPreferenc.
ba753660  cc e0 da e3 b9 23 a2 e3 0d 00 54 68 00 00 00 00  .....#....Th....
ba753670  00 00 00 00 00 00 00 00 00 69 6e 74 65 72 6e 00  .........intern.
ba753680  01 00 00 00 0c 00 00 00 a0 35 75 ba 00 73 70 61  .........5u..spa
ba753690  46 72 61 6d 65 4c 61 79 6f 75 74 00 6e 00 40 07  FrameLayout.n.@.
ba7536a0  01 00 00 00 0f 00 00 00 6f 6e 61 6c 46 69 74 73  ........onalFits
ba7536b0  52 65 6c 61 74 69 76 65 4c 61 79 6f 75 74 00 00  RelativeLayout..
```

本次抓到的包：

![19.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-0766195b3dd4c99695c44edb75913257839c035a.png)

返回的结果就是抓包中的密码。但是 v15 是还看不懂的。

v15 的 16 进制数据是：cad1c9855df0aa64c33bdb4c9dc54782。

想到很多加密方式，就是对加密后的结果进行 base64编码。

对其进行 16 进制解码，在 base64 编码，就是 password 的值。

![20.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-965146044d87a16486e79b11e51dfc5bfb6a70d6.png)

所以目光聚焦在 v15 的身上。

在网上捋，sub\_5BCC((int)v12, (int)v15, v10, a3, 1)。

hook sub\_5BCC 函数。

```js
let nativeHelperAddr = Module.findBaseAddress("libNativeHelper.so")
let sub5bcdaddr = nativeHelperAddr.add(0x5bcd)
console.log(sub5bcdaddr)
Interceptor.attach(sub5bcdaddr, {
    onEnter: function (args) {
        this.args0 = args[0]
        this.args1 = args[1]
        this.args2 = args[2]
        this.args3 = args[3]

        console.log("onEnter args0 => ", hexdump(args[0]))
        console.log("onEnter args1 => ", hexdump(args[1]))
        console.log("onEnter args2 => ", args[2].toInt32())
        console.log("onEnter args3 => ", hexdump(args[3]))
    }, onLeave: function (retval) {
        console.log("onLeave args0 => ", hexdump(this.args0))
        console.log("onLeave args1 => ", hexdump(this.args1))
        console.log("onLeave args2 => ", this.args2.toInt32())
        console.log("onEnter args3 => ", hexdump(this.args3))
    }
})
```

hook 到的结果。

```php
0xac8dabcd
onEnter args0 =>             0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
ba290f20  31 32 33 34 35 36 37 38 39 07 07 07 07 07 07 07  123456789.......
ba290f30  31 32 33 34 35 36 37 38 39 00 a2 e7 55 11 00 00  123456789...U...
ba290f40  00 00 50 41 00 00 50 41 00 00 50 41 00 00 50 41  ..PA..PA..PA..PA
ba290f50  a0 38 3d dc 2f 04 00 00 a0 38 3d dc 82 01 00 00  .8=./....8=.....
ba290f60  6c 04 00 00 6c 04 00 00 6c 04 00 00 6c 04 00 00  l...l...l...l...
ba290f70  a0 38 3d dc 2f 04 00 00 a0 38 3d dc 82 01 00 00  .8=./....8=.....
ba290f80  d0 ce 4c dc 51 04 45 7a 60 41 d2 b5 00 00 50 41  ..L.Q.Ez`A....PA
ba290f90  00 00 50 41 00 00 50 41 00 00 50 41 00 00 b0 41  ..PA..PA..PA...A
ba290fa0  a0 38 3d dc 2f 04 00 00 a0 38 3d dc 82 01 00 00  .8=./....8=.....
ba290fb0  6c 04 00 00 6c 04 00 00 6c 04 00 00 19 00 00 00  l...l...l.......
ba290fc0  c0 0e 29 ba 50 d0 17 8b 50 42 d2 b5 00 00 b0 41  ..).P...PB.....A
ba290fd0  a0 38 3d dc 2f 04 00 00 a0 38 3d dc 82 01 00 00  .8=./....8=.....
ba290fe0  a0 38 3d dc 2f 04 00 00 a0 38 3d dc 82 01 00 00  .8=./....8=.....
ba290ff0  d0 9b 1a d2 ab 01 0d 7f ab 01 0d 7f 40 62 9a b5  ............@b..
ba291000  f0 ea e6 70 0b 00 00 00 44 eb e6 70 0c 00 00 00  ...p....D..p....
ba291010  b4 fd 4a b7 0d 00 00 00 9c ea e6 70 24 00 00 00  ..J........p$...
onEnter args1 =>             0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
aabc6740  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
aabc6750  00 00 00 00 00 00 00 00 a4 79 17 e5 00 00 00 00  .........y......
aabc6760  08 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
aabc6770  84 79 17 e5 00 00 00 00 08 00 00 00 00 00 00 00  .y..............
aabc6780  00 00 00 00 00 00 00 00 c4 79 17 e5 06 00 00 00  .........y......
aabc6790  08 00 00 00 80 84 1e 00 00 00 00 00 00 00 00 00  ................
aabc67a0  c4 79 17 e5 06 00 00 00 08 00 00 00 00 00 00 00  .y..............
aabc67b0  00 00 00 00 54 fb 39 ba a4 79 17 e5 00 00 00 00  ....T.9..y......
aabc67c0  08 00 00 00 00 00 00 00 00 00 00 00 94 fb 39 ba  ..............9.
aabc67d0  84 79 17 e5 00 00 00 00 08 00 00 00 00 00 00 00  .y..............
aabc67e0  00 00 00 00 00 00 00 00 c4 79 17 e5 06 00 00 00  .........y......
aabc67f0  08 00 00 00 80 84 1e 00 00 00 00 00 94 fc 39 ba  ..............9.
aabc6800  c4 79 17 e5 06 00 00 00 08 00 00 00 00 00 00 00  .y..............
aabc6810  00 00 00 00 d4 fc 39 ba a4 79 17 e5 00 00 00 00  ......9..y......
aabc6820  08 00 00 00 00 00 00 00 00 00 00 00 14 fd 39 ba  ..............9.
aabc6830  84 79 17 e5 00 00 00 00 08 00 00 00 00 00 00 00  .y..............
onEnter args2 =>  16
onEnter args3 =>             0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
ba290ee0  75 21 7e 23 37 40 77 30 00 00 00 00 00 00 00 00  u!~#7@w0........
ba290ef0  00 00 50 41 00 00 50 41 00 00 b0 41 00 00 00 00  ..PA..PA...A....
ba290f00  6c 04 00 00 6c 04 00 00 18 00 00 00 00 00 00 00  l...l...........
ba290f10  c0 71 c6 b5 c2 ec ce a7 40 3e d2 b5 03 00 00 00  .q......@>......
ba290f20  31 32 33 34 35 36 37 38 39 07 07 07 07 07 07 07  123456789.......
ba290f30  31 32 33 34 35 36 37 38 39 00 a2 e7 55 11 00 00  123456789...U...
ba290f40  00 00 50 41 00 00 50 41 00 00 50 41 00 00 50 41  ..PA..PA..PA..PA
ba290f50  a0 38 3d dc 2f 04 00 00 a0 38 3d dc 82 01 00 00  .8=./....8=.....
ba290f60  6c 04 00 00 6c 04 00 00 6c 04 00 00 6c 04 00 00  l...l...l...l...
ba290f70  a0 38 3d dc 2f 04 00 00 a0 38 3d dc 82 01 00 00  .8=./....8=.....
ba290f80  d0 ce 4c dc 51 04 45 7a 60 41 d2 b5 00 00 50 41  ..L.Q.Ez`A....PA
ba290f90  00 00 50 41 00 00 50 41 00 00 50 41 00 00 b0 41  ..PA..PA..PA...A
ba290fa0  a0 38 3d dc 2f 04 00 00 a0 38 3d dc 82 01 00 00  .8=./....8=.....
ba290fb0  6c 04 00 00 6c 04 00 00 6c 04 00 00 19 00 00 00  l...l...l.......
ba290fc0  c0 0e 29 ba 50 d0 17 8b 50 42 d2 b5 00 00 b0 41  ..).P...PB.....A
ba290fd0  a0 38 3d dc 2f 04 00 00 a0 38 3d dc 82 01 00 00  .8=./....8=.....
onLeave args0 =>             0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
ba290f20  31 32 33 34 35 36 37 38 39 07 07 07 07 07 07 07  123456789.......
ba290f30  31 32 33 34 35 36 37 38 39 00 a2 e7 55 11 00 00  123456789...U...
ba290f40  00 00 50 41 00 00 50 41 00 00 50 41 00 00 50 41  ..PA..PA..PA..PA
ba290f50  a0 38 3d dc 2f 04 00 00 a0 38 3d dc 82 01 00 00  .8=./....8=.....
ba290f60  6c 04 00 00 6c 04 00 00 6c 04 00 00 6c 04 00 00  l...l...l...l...
ba290f70  a0 38 3d dc 2f 04 00 00 a0 38 3d dc 82 01 00 00  .8=./....8=.....
ba290f80  d0 ce 4c dc 51 04 45 7a 60 41 d2 b5 00 00 50 41  ..L.Q.Ez`A....PA
ba290f90  00 00 50 41 00 00 50 41 00 00 50 41 00 00 b0 41  ..PA..PA..PA...A
ba290fa0  a0 38 3d dc 2f 04 00 00 a0 38 3d dc 82 01 00 00  .8=./....8=.....
ba290fb0  6c 04 00 00 6c 04 00 00 6c 04 00 00 19 00 00 00  l...l...l.......
ba290fc0  c0 0e 29 ba 50 d0 17 8b 50 42 d2 b5 00 00 b0 41  ..).P...PB.....A
ba290fd0  a0 38 3d dc 2f 04 00 00 a0 38 3d dc 82 01 00 00  .8=./....8=.....
ba290fe0  a0 38 3d dc 2f 04 00 00 a0 38 3d dc 82 01 00 00  .8=./....8=.....
ba290ff0  d0 9b 1a d2 ab 01 0d 7f ab 01 0d 7f 40 62 9a b5  ............@b..
ba291000  f0 ea e6 70 0b 00 00 00 44 eb e6 70 0c 00 00 00  ...p....D..p....
ba291010  b4 fd 4a b7 0d 00 00 00 9c ea e6 70 24 00 00 00  ..J........p$...
onLeave args1 =>             0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
aabc6740  ca d1 c9 85 5d f0 aa 64 c3 3b db 4c 9d c5 47 82  ....]..d.;.L..G.
aabc6750  00 00 00 00 00 00 00 00 a4 79 17 e5 00 00 00 00  .........y......
aabc6760  08 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
aabc6770  84 79 17 e5 00 00 00 00 08 00 00 00 00 00 00 00  .y..............
aabc6780  00 00 00 00 00 00 00 00 c4 79 17 e5 06 00 00 00  .........y......
aabc6790  08 00 00 00 80 84 1e 00 00 00 00 00 00 00 00 00  ................
aabc67a0  c4 79 17 e5 06 00 00 00 08 00 00 00 00 00 00 00  .y..............
aabc67b0  00 00 00 00 54 fb 39 ba a4 79 17 e5 00 00 00 00  ....T.9..y......
aabc67c0  08 00 00 00 00 00 00 00 00 00 00 00 94 fb 39 ba  ..............9.
aabc67d0  84 79 17 e5 00 00 00 00 08 00 00 00 00 00 00 00  .y..............
aabc67e0  00 00 00 00 00 00 00 00 c4 79 17 e5 06 00 00 00  .........y......
aabc67f0  08 00 00 00 80 84 1e 00 00 00 00 00 94 fc 39 ba  ..............9.
aabc6800  c4 79 17 e5 06 00 00 00 08 00 00 00 00 00 00 00  .y..............
aabc6810  00 00 00 00 d4 fc 39 ba a4 79 17 e5 00 00 00 00  ......9..y......
aabc6820  08 00 00 00 00 00 00 00 00 00 00 00 14 fd 39 ba  ..............9.
aabc6830  84 79 17 e5 00 00 00 00 08 00 00 00 00 00 00 00  .y..............
onLeave args2 =>  16
onEnter args3 =>             0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
ba290ee0  75 21 7e 23 37 40 77 30 00 00 00 00 00 00 00 00  u!~#7@w0........
ba290ef0  00 00 50 41 00 00 50 41 00 00 b0 41 00 00 00 00  ..PA..PA...A....
ba290f00  6c 04 00 00 6c 04 00 00 18 00 00 00 00 00 00 00  l...l...........
ba290f10  c0 71 c6 b5 c2 ec ce a7 40 3e d2 b5 03 00 00 00  .q......@>......
ba290f20  31 32 33 34 35 36 37 38 39 07 07 07 07 07 07 07  123456789.......
ba290f30  31 32 33 34 35 36 37 38 39 00 a2 e7 55 11 00 00  123456789...U...
ba290f40  00 00 50 41 00 00 50 41 00 00 50 41 00 00 50 41  ..PA..PA..PA..PA
ba290f50  a0 38 3d dc 2f 04 00 00 a0 38 3d dc 82 01 00 00  .8=./....8=.....
ba290f60  6c 04 00 00 6c 04 00 00 6c 04 00 00 6c 04 00 00  l...l...l...l...
ba290f70  a0 38 3d dc 2f 04 00 00 a0 38 3d dc 82 01 00 00  .8=./....8=.....
ba290f80  d0 ce 4c dc 51 04 45 7a 60 41 d2 b5 00 00 50 41  ..L.Q.Ez`A....PA
ba290f90  00 00 50 41 00 00 50 41 00 00 50 41 00 00 b0 41  ..PA..PA..PA...A
ba290fa0  a0 38 3d dc 2f 04 00 00 a0 38 3d dc 82 01 00 00  .8=./....8=.....
ba290fb0  6c 04 00 00 6c 04 00 00 6c 04 00 00 19 00 00 00  l...l...l.......
ba290fc0  c0 0e 29 ba 50 d0 17 8b 50 42 d2 b5 00 00 b0 41  ..).P...PB.....A
ba290fd0  a0 38 3d dc 2f 04 00 00 a0 38 3d dc 82 01 00 00  .8=./....8=.....
```

很明显的是第一个参数，在内存中是： 31 32 33 34 35 36 37 38 39 07 07 07 07 07 07 07

第一个参数是 123456789 也就是输入的密码。在内存中应该是 3132333435363739 。

通过观察可知，12345678 正好是 8 个，第 9 个是多出来的一个，于是后面填 7 个 7 。这是明显的 DES 填充。

如果前面是 6 个，8 个 8 个一分组后面就会填写 02 02 。

openssl 中 des cbc 的调用方式如下。

```c
DES_ncbc_encrypt(input_data, output_data, data_len, &schedule, &iv, DES_DECRYPT);
```

有 iv 的是 cbc 模式，没有的是 ecb 模式。

所以点进去 sub\_5BCC 函数。

v9 正好是 iv 的位置，并且正好 8 个字节，符合 des 中 iv 长度的规定。

```c
int __fastcall sub_5BCC(int a1, int a2, int a3, char *s, int a5)
{
  _DWORD v9[2]; // [sp+8h] [bp-B0h] BYREF
  char v10[128]; // [sp+10h] [bp-A8h] BYREF
  int v11[3]; // [sp+90h] [bp-28h] BYREF
  int v12; // [sp+9Ch] [bp-1Ch]

  qmemcpy(v11, s, strlen(s));
  sub_2284(v11, (int)v10);
  v9[0] = 0x78563412;
  v9[1] = 0xEFCDAB90;
  ((void (__fastcall *)(int, int, int, char *, _DWORD *, int))sub_42F4)(a1, a2, a3, v10, v9, a5);
  return _stack_chk_guard - v12;
}
```

那么可以得出，这是一个 *DES*/*CBC*/PKCS7Padding 加密。字符串形式秘钥是 u!~#7@w0，16进制 iv 是 1234567890abcdef。

验证猜想：

![21.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-36f2d4ae000b34e79e30a0a89176d86d8e45c9b2.png)

这样 password 值的逆向也分析完毕。

### 总结语

分析 So 层的加密是很困难的，因为 C/C++ 和 Java 加密不同的点在于，C/C++ 没有一个标准的加密库，也就无法 hook 通杀。并且 C/C++ 的汇编代码比 smali 代码难看很多，反汇编的还原度更差十万八千里。

所以分析 So 层的加密，一定要对常见加密方式有很全的了解，例如本文就是靠 MD5 的常量值，初始化值，80 的填充，DES 的填充方式，逆向出来算法。

除了对加密算法了解外，逆向 So 层还要靠较多的体力劳动，要一遍又一遍的对怀疑的函数进行 hook ，然后观察进入函数的参数和离开函数参数的值。