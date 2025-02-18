过某TV App Root检测及协议分析
--------------------

### 过 root 检测

打开这款 TV App ，如果手机已 root ，那么在进入 App 正式页面之前，会先提示 "当前设备可能处于root环境，继续运行应用将有风险"。

![1.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-63051bf3babb1850f470c3c5a731d523b6f0e22c.png)

所以要在逆向协议之前，先过掉 root 检测。

逆向的时候，要以正向开发的角度去思考问题，才能快速定位重要代码块。

这段提示，看起来像是一个 Toast。那么就去 hook Toast.show 方法，并且打印参数、返回值和调用栈。

由于考虑 Toast.show 方法执行早的原因，采用 objection -s 参数进行 hook。

objection -g com.xxxx.xxxxxxx.xxx.xxxxxx explore -s "android hooking watch class\_method android.widget.Toast.show --dump-args --dump-backtrace --dump-return"

当弹出"当前设备可能处于root环境，继续运行应用将有风险"时，成功 hook 到。

![2.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-b12d2010cddf22fdf3259156ac5abcf3f8db4fb3.png)

通过观察方法调用栈，最上面是 Toast.show 下面三个方法都是 showToast 所以目光定位到 WelcomeActivity$2$1.run 方法。

将 Apk 拖入到 Jadx 中进行反编译，并找到 WelcomeActivity$2$1.run 方法。

![3.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-d9102ec501403024981d9b4d3260aaadbfb95af8.png)

run 方法里面主要调用了 SystemUtils.checkSuFile() 和 SystemUtils.checkRootFile() 两个方法。下面逐一进行分析。

SystemUtils.checkSuFile() 方法，就是调用了 which su 命令，如果存在 su 命令，就会打印 su 命令的路径，那就证明存在 root。

![4.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-28280e5f1c63c1e07d8ad3340bdfb0904e32a9ed.png)

SystemUtils.checkRootFile() 方法，通过判断是否有字符串数组中的路径存在，如果有，那就证明存在 root。

![5.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-9eeef7438c1ca31c79b2c3e527900c006953be68.png)

所以，想过掉 root 检测，就要 hook 这两个方法，让 checkSuFile() 方法返回 false ，让 checkRootFile() 方法返回 null。

编写过 root 检测的 frida 代码：

```js
Java.perform(function () {
    let SystemUtils = Java.use("com.xxxx.xxxxxxx.xxxxxxx.xxxx.system.SystemUtils");
    SystemUtils["checkSuFile"].implementation = function () {
        console.log(`SystemUtils.checkSuFile is called`);
        return false;
    };

    SystemUtils["checkRootFile"].implementation = function () {
        console.log(`SystemUtils.checkRootFile is called`);
        return null;
    };
});
```

此时 root 检测就会失效。

![6.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-d8e82adcbc04374e93d56976bb2d8117f1c0090a.png)

### 抓包

在登录界面，输入账号 15026818188 ，密码 123456789。

![7.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-8ed2efea5f1c13688b75e447958425241fc4f24d.png)

抓到包的请求头部分如下：

![8.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-f6146e0f131e1e0bd958b20b2f72a365d64343ba.png)

X-API-VERSION 是 App 的版本，X-API-TIMESTAMP 是时间戳。

所以有分析必要的就是 X-API-KEY 和 X-API-SIGNATURE，经过多次测试 X-API-KEY 也是写死的，那么只分析 X-API-SIGNATURE 即可。

### Java层协议分析

既然是加密，很有可能就会对即将要加密的数据转为 bytes，所以先对 java.lang.String.getBytes 方法进行 hook 并打调用栈。

再点击登录后，调用 java.lang.String.getBytes 方法很多次，所以不太便于逆向分析。

最终结合方法里最好要有 X-API-SIGNATURE 字符串字样，才定位到下面的调用栈。

![9.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-b633ed76fb88e6cb4960ed1cbdf6b6a96c9b1be6.png)

在 Jadx 中找到 com.xxxx.xxxxxxx.xxxxxxx.util.Util.getRequestHeader 方法。

发现这里面根本就没有方法体，而是一堆不知所云的描述。

![10.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-fe14b825cbbb223f734884bad4b798040511d263.png)

最终，用了 3 款反编译工具，才将这段代码补齐！

在 GDAE 中可以找到方法体。

str = Base64.encode(str1.getBytes()); 是 str1 调用的 getBytes 方法。

继续往上找。

关于 str1 的生成重要代码如下：

String versionName = Util.getVersionName(instance); String randomData = SecurityUtil.getRandomData(6);

objArray1\[i\] = versionName; objArray1\[1\] = randomData;

Class uClass = Class.forName("com.xxxx.xxxxxxx.jni.Utils");

Method declaredMeth = uClass.getDeclaredMethod("signature", uClassArray);

str1 = declaredMeth.invoke(uClass.newInstance(), objArray1);

这是一段反射代码，组合成 Java 代码就是 com.xxxx.xxxxxxx.jni.Utils.signature(objArray1)。

![11.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-925dfd9f53f891c3dcadd1ae0b01290fde63fe57.png)

所以接下来，要找到 com.xxxx.xxxxxxx.jni.Utils.signature 方法。

这个方法在 Jeb 中可以找得到。

一个方法体，需要三个反编译工具才可补全，可见多准备几样工具还是非常有必要的。

![12.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-0e60dd86fe98502439e731c208d174930b217da5.png)

signature 方法是 native 方法，尝试进行 hook。

frida hook 代码如下：

```js
Java.perform(function () {
    let SystemUtils = Java.use("com.xxxx.xxxxxxx.jni.Utils");
    SystemUtils["signature"].implementation = function (str, str2) {
        console.log(`signature is called: str=${str}, str2=${str2}`);
        let result = this["signature"](str, str2);
        console.log(`signature result=${result}`);
        return result;
    }
})
```

点击登录后获取到的：

signature is called: str=4.0.0, str2=1689690618994is9eCh signature result=6554fde5134c30ea26a1aed8599bc5556652dc6b

因为 str2 是时间戳，为了不影响 So 层的分析，所以写一个 signature 方法的主动调用。

frida 主动调用如下：

```js
function callSignature() {
    Java.perform(function () {
        let SystemUtils = Java.use("com.xxxx.xxxxxxx.jni.Utils");
        let str = "4.0.0";
        let str2 = "1689690618994is9eCh";
        let utils = SystemUtils.$new();
        let result = utils.signature(str, str2);
        console.log("result =>", result);
    })
}
```

进入 frida 后，执行 callSignature() 就会进行主动调用。

### So层协议分析

接下来分析 So 层。

找到 signature 函数，因为是静态注册，所以很好找到，并对其进行反编译。

由于对开发的了解，对参数类型和参数名进行修改。

反编译后的代码如下：

```c
int __fastcall signature(JNIEnv *env, jstring versionName, jstring randomData)
{
  const char *v5; // r7
  const char *v6; // r0
  const char *v7; // r8
  size_t v8; // r11
  size_t v9; // r11
  void *v10; // r0
  char *v11; // r6
  int v12; // r5
  void *p; // [sp+1Ch] [bp-2Ch] BYREF

  p = 0;
  if ( !is_initialised )
    exit(1);
  v5 = (*env)->GetStringUTFChars(env, versionName, 0);
  v6 = (*env)->GetStringUTFChars(env, randomData, 0);
  v7 = v6;
  if ( v5 )
  {
    if ( v6 && (v8 = strlen(v5), v9 = v8 + strlen(v7), v10 = malloc(v9 + 80), (v11 = (char *)v10) != 0) )
    {
      memset(v10, 0, v9 + 80);
      snprintf(
        v11,
        v9 + 80,
        "%s&%s&%s&%s",
        "877a9ba7a98f75b90a9d49f53f15a858",
        "NjhhMDRiODE3N2JkYzllNWUxNmE4OWU2Nzc3YTdiNjY=",
        v5,
        v7);
      sha1_encode(v11, v9 + 79, &p);
      if ( p )
        v12 = ((int (__fastcall *)(JNIEnv *))(*env)->NewStringUTF)(env);
      else
        v12 = 0;
    }
    else
    {
      v12 = 0;
      v11 = 0;
    }
    (*env)->ReleaseStringUTFChars(env, versionName, v5);
  }
  else
  {
    v12 = 0;
    v11 = 0;
  }
  if ( v7 )
    (*env)->ReleaseStringUTFChars(env, randomData, v7);
  if ( v11 )
    free(v11);
  if ( p )
    free(p);
  return v12;
}
```

首先参数 jstring 类型转换为 const char\* 类型。

versionName 给了 v5，参数 randomData 给了 v7。

然后又经历了一个 snprintf( v11,v9 + 80,"%s&amp;%s&amp;%s&amp;%s","877a9ba7a98f75b90a9d49f53f15a858","NjhhMDRiODE3N2JkYzllNWUxNmE4OWU2Nzc3YTdiNjY=",v5,v7); 函数。

snprintf 函数执行后，v11 存放的值就是 877a9ba7a98f75b90a9d49f53f15a858&amp;NjhhMDRiODE3N2JkYzllNWUxNmE4OWU2Nzc3YTdiNjY=&amp; 传进来的versionName参数&amp;传进来的randomData参数。

最后又经历了 sha1\_encode(v11, v9 + 79, &amp;p); 函数。v11 就是明文，v9 是长度，那么 &amp;p 就是存放的加密结果。

点进去 sha1\_encode 函数。

```c
int __fastcall sha1_encode(void *a1, int a2, char **a3)
{
  int result; // r0
  char *v6; // r0
  char *v7; // r6
  int i; // r4
  int v9; // r3
  _BYTE v10[96]; // [sp+0h] [bp-98h] BYREF
  char v11[20]; // [sp+60h] [bp-38h] BYREF

  memset(v10, 0, sizeof(v10));
  if ( !a3 )
    return -1;
  memset(v11, 0, sizeof(v11));
  SHA1_Init(v10);
  SHA1_Update((int)v10, a1);
  SHA1_Final(v11, v10);
  OPENSSL_cleanse(v10, 96);
  v6 = (char *)malloc(0x29u);
  v7 = v6;
  if ( !v6 )
    return -1;
  memset(v6, 0, 0x29u);
  for ( i = 0; i != 20; ++i )
  {
    v9 = (unsigned __int8)v11[i];
    sprintf(v7, "%s%02x", v7, v9);
  }
  result = 0;
  *a3 = v7;
  return result;
}
```

v7 是加密后的结果，给了 \*a3，a3 是 char\*\* 类型，所以 v7 就是 char\* 类型。

这是一个二级指针去数据的问题，&amp;p 是 char\*\* 类型，要想读出其中的数据就要，先读出 char\*\* 里面的地址，然后再从这个地址拿数据。

所以编写 frida 代码要先将 args\[2\] 的地址保存起来，然后先读出指针，再读数据。

```js
let sha1_encodeAddr = Module.findExportByName("libm2o_jni.so", "sha1_encode")
console.log(sha1_encodeAddr)
Interceptor.attach(sha1_encodeAddr, {
    onEnter: function (args) {
        console.log("onEnter args0 => ", args[0].readCString())
        console.log("onEnter args1 => ", args[1].toInt32())
        this.args2 = args[2]

    }, onLeave: function (retval) {
        let args2Pointer = this.args2.readPointer()
        console.log("onLeave args2 => ", args2Pointer.readCString())
    }
})
```

hook 到的结果与推断的一致

参数是 str=4.0.0, str2=1689690618994is9eCh，和 877a9ba7a98f75b90a9d49f53f15a858 和 NjhhMDRiODE3N2JkYzllNWUxNmE4OWU2Nzc3YTdiNjY= 用 &amp; 拼接起来。

![13.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-f7629275f8ea53c222182a30d09e9dc513146199.png)

最后取 SHA1。

![14.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-5f04baf6d00a15eda9f389d9ed2aaa9598274585.png)

到此协议分析就结束了。

### 总结语

本文首先定位到检测 root 的代码，通过 frida hook修改返回值，过掉 root 检测。

然后抓包找到要逆向的协议部分，通过动静态结合的方式（objecton、frida hook java、frida 主动调用，ida 静态分析，frida hook so）还原了登录协议。

期间遇见的问题有反射部分代码找不到，反射代码的还原，以及 So 层算法的分析，和二级指针的数据读取也都解决成功。