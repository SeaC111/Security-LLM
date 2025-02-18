以攻促防-Android安全开发
----------------

### AES加密Demo

要讲 Android 安全开发，那就先要有一个案例，案例是一个 AES 加密的 Demo。

加密部分通过 C++ 代码实现，调用算法部分通过 Java 代码实现。

项目架构如图：

![1.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-35572e5d104413bcbce729e9e8df520e831595dc.png)

加密算法 Java 层的定义在 bm 包下的 Aes 类中。

```java
package com.bmstd.aesencryption.bm;

public class Aes {
    static {
        System.loadLibrary("native-lib");
    }

    public static native String encryption(String plainText);
    public static native String decryption(String encryptText);
}
```

调用加密算法在 Java 层的 MainActivity 类。

```php
package com.bmstd.aesencryption;

import androidx.appcompat.app.AppCompatActivity;

import android.os.Bundle;
import android.util.Log;

import com.bmstd.aesencryption.bm.Aes;
import com.bmstd.aesencryption.bm.Confuse;

public class MainActivity extends AppCompatActivity {

    static {
        System.loadLibrary("native-lib");
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        String text = "bmstdAEStest";
        String textEnc = Aes.encryption(text);
        String textDec = Aes.decryption(textEnc);

        Log.d("bmstdAes", "text: " + text);
        Log.d("bmstdAes", "textAESEnc : " + textEnc);
        Log.d("bmstdAes", "textAESDec : " + textDec);

        String Confusetest = Confuse.test;
        Log.d("bmstdAes", "Confusetest : " + Confusetest);
    }
}
```

Confuse 类没有实际用处，只是作为测试使用。

```java
package com.bmstd.aesencryption.bm;

public class Confuse {
    public static String test = "bmstd";
}
```

被调用算法端 So 层 native-lib.cpp 代码

```c++
#include <jni.h>
#include <string>
#include <iostream>
#include "utils/AES.h"
#include "utils/encryption.h"
#include <typeinfo>

extern "C"
JNIEXPORT jstring JNICALL
Java_com_bmstd_aesencryption_bm_Aes_encryption(JNIEnv *env, jclass thiz, jstring plain_text) {
    const char *c_data = env->GetStringUTFChars(plain_text, 0);
    string encrypt_data = encryptByAES(c_data);
    return env->NewStringUTF(encrypt_data.c_str());
}

extern "C"
JNIEXPORT jstring JNICALL
Java_com_bmstd_aesencryption_bm_Aes_decryption(JNIEnv *env, jclass thiz, jstring encrypt_text) {
    const char *c_data = env->GetStringUTFChars(encrypt_text, 0);
    string decrypt_data = decryptByAES(c_data);
    return env->NewStringUTF(decrypt_data.c_str());
}
```

通过上面代码可知，主要是通过 encryptByAES 函数实现的加密，decryptByAES 函数实现的解密。

两个函数的实现都在 encryption.cpp 中，并且将 key 和 iv 直接写在了代码中。

```php
#include "encryption.h"
#include "AES.h"
#include "Base64.h"
#include <iostream>
using namespace std;
/**
 * cbc方式加密
 * @param data
 * @param secretKey
 * @param iv
 * @return
 */

const char* secretKey = "bmstd-aes-key666";
const char* iv = "bmstd-aes-iv1234";
int iMode = 1;

string encryptByAES(const char * data) {
    string data_str(data);
    size_t length = data_str.length();
    int block_num = length / BLOCK_SIZE + 1;
    //明文
    char* szDataIn = new char[block_num * BLOCK_SIZE + 1];
    memset(szDataIn, 0x00, block_num * BLOCK_SIZE + 1);
    strcpy(szDataIn, data_str.c_str());

    //进行PKCS7Padding填充。
    int k = length % BLOCK_SIZE;
    int j = length / BLOCK_SIZE;
    int padding = BLOCK_SIZE - k;
    for (int i = 0; i < padding; i++)
    {
        szDataIn[j * BLOCK_SIZE + k + i] = padding;
    }
    szDataIn[block_num * BLOCK_SIZE] = '\0';

    //加密后的密文
    char* szDataOut = new char[block_num * BLOCK_SIZE + 1];
    memset(szDataOut, 0, block_num * BLOCK_SIZE + 1);

    //进行进行AES的CBC模式加密
    AES aes;
    aes.MakeKey(secretKey, iv, 16, 16);
    aes.Encrypt(szDataIn, szDataOut, block_num * BLOCK_SIZE, iMode);
    string str = base64_encode((unsigned char*)szDataOut,
                               block_num * BLOCK_SIZE);
    delete[] szDataIn;
    delete[] szDataOut;
    return str;
}

/**
 * cbc方式解密
 * @param data
 * @param secretKey
 * @param iv
 * @return
 */
string decryptByAES(const char * data) {
    string data_str(data);
    string strData = base64_decode(data_str);
    size_t length = strData.length();
    //密文
    char* szDataIn = new char[length + 1];
    memcpy(szDataIn, strData.c_str(), length + 1);
    //明文
    char* szDataOut = new char[length + 1];
    memcpy(szDataOut, strData.c_str(), length + 1);

    //进行AES的CBC模式解密
    AES aes;
    aes.MakeKey(secretKey, iv, 16, 16);
    aes.Decrypt(szDataIn, szDataOut, length, iMode);

    //去PKCS7Padding填充
    if (0x00 < szDataOut[length - 1] <= 0x16)
    {
        int tmp = szDataOut[length - 1];
        for (int i = length - 1; i >= length - tmp; i--)
        {
            if (szDataOut[i] != tmp)
            {
                memset(szDataOut, 0, length);
                cout << "去填充失败！解密出错！！" << endl;
                break;
            }
            else
                szDataOut[i] = 0;
        }
    }
    string strDest(szDataOut);
    delete[] szDataIn;
    delete[] szDataOut;
    return strDest;

}
```

其余的一些代码过于长和复杂，但也只是为了完成 AES 加密的计算，所以这里不在列出。

将上面的工程，生成 APK ，执行后就可以看到对 bmstdAEStest 字符串加密和解密的结果了。

![2.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-7e0794e53bc8c2bd778f0020c8cfa59a72b68534.png)

通过在线 AES 加密的网站，输入密码和偏移量后得出的结果与编写代码得出的结果是完全一致的，证明对 AES 加解密的实现是完全没有问题的。

![3.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-b543bef85fa5da756200aac2263c2bcc67b26ca5.png)

### 静态分析Java和So

下面对上面工程生成的 APK 文件进行静态分析。

将 APK 文件 拖入 jadx 中进行 Java 层的反编译。

可以看到由于 Java 层没加任何的保护，所以直接反编译就可以看到要加密的字符串。

而且 Aes 类很明显，见名知意就知道和 AES 加密有关。

再加上代码量不多，看起代码会很轻松的就完成逆向的工作。

![4.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-c3f7831d4366b4d6a3df585ebbe032dc7894e7e1.png)

下面再对 APK 的 so 层进行逆向分析。

提取 libnative-lib.so 再拖入到 IDA 中进行反编译。

可以看到很明显的，调用 encryption 函数后又调用了 encryptByAES，而且看名字一看就知道是加密 AES 的函数。

![5.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-4b3dcfc0bce1a872be80fb80ff2d193e45c8d529.png)

继续跟进，进入 encryptByAES 函数，然后在 AES::MakeKey 函数这里调用了 secretKey\[0\] 和 iv。

![6.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-768ec58e855c85ee55d887a18520408887a78bee.png)

点进去就可以看到正确的 key 和 iv 了。

![7.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-727e1ff2e8a1cc1a65bf6e43fe9fa90e78de03b1.png)

通过上面如此简单的分析，就捋清了加密的调用关系，加密函数，和 Key iv，整个 App 已经没有秘密可言了。

所以，实现功能只是 Android 功能开发的结束，而却是安全问题的刚刚开始。

下面将从 6 个方面对 Java 层和 So 层进行一个安全的提升。

### Java层类名混淆

通过上面的分析可以知道，bm 下的 AES 类，一看就知道是做什么的了。而开发者还不得不起一个，一看就知道是做什么的类名，因为见名知意这种命名手段有助于项目的开发。

所以只能在生成 APK 的过程中将类名混淆。

因为开启混淆会使编译时间变长，所以 debug 模式下不开启。需要做的是：

将 release 下 minifyEnabled 的值改为 true，打开混淆；

```groovy
buildTypes {
    release {
        minifyEnabled true // 混淆
        zipAlignEnabled true // Zipalign优化
        shrinkResources true  // 移除无用的resource文件
        proguardFiles getDefaultProguardFile('proguard-android.txt'), 'proguard-rules.pro'  // 加载默认混淆配置文件
    }
}
```

混淆会用无意义的短变量去重命名类、变量、方法，但是对于外部的一些引用是通过名字找到对应的方法和类。混淆过后通过原来的名字去找混淆后的名字，是找不到对应方法和类，就会出异常报错。所以有些情况是不能进行混淆的。

所以在 Android 项目中用到 Jni，当用了 proguard 后，发现 native 方法找不到很多变量，原来是 proguard 不会对含有 native 方法的类进行类名混淆，现实中也只有少量的 native 加载，只用 C++/C 开发的项目少之又少，所以这里把 Aes 类重命名为 A 类。

在 app 目录下创建 proguard-android.txt 文件。

然后根据混淆规则配置 proguard-android.txt 文件。

```properties
# 设置混淆的压缩比率 0 ~ 7
-optimizationpasses 5
# 混淆时不使用大小写混合，混淆后的类名为小写
-dontusemixedcaseclassnames
# 指定不去忽略非公共库的类
-dontskipnonpubliclibraryclasses
# 指定不去忽略非公共库的成员
-dontskipnonpubliclibraryclassmembers
# 混淆时不做预校验
-dontpreverify
# 混淆时不记录日志
-verbose
# 代码优化
-dontshrink
# 不优化输入的类文件
-dontoptimize
# 保留注解不混淆
-keepattributes *Annotation*,InnerClasses
# 避免混淆泛型
-keepattributes Signature
# 保留代码行号，方便异常信息的追踪
-keepattributes SourceFile,LineNumberTable
# 混淆采用的算法
-optimizations !code/simplification/cast,!field/*,!class/merging/*

# dump.txt文件列出apk包内所有class的内部结构
-dump class_files.txt
# seeds.txt文件列出未混淆的类和成员
-printseeds seeds.txt
# usage.txt文件列出从apk中删除的代码
-printusage unused.txt
# mapping.txt文件列出混淆前后的映射
-printmapping mapping.txt

# 不需混淆的Android类
-keep public class * extends android.app.Fragment
-keep public class * extends android.app.Activity
-keep public class * extends android.app.Application
-keep public class * extends android.app.Service
-keep public class * extends android.content.BroadcastReceiver
-keep public class * extends android.preference.Preference
-keep public class * extends android.content.ContentProvider
-keep public class * extends android.support.v4.**
-keep public class * extends android.support.annotation.**
-keep public class * extends android.support.v7.**
-keep public class * extends android.app.backup.BackupAgentHelper
-keep public class * extends android.preference.Preference
-keep public class * extends android.view.View
-keep public class com.android.vending.licensing.ILicensingService
-keep class android.support.** {*;}

# support-v4包
-dontwarn android.support.v4.**
-keep class android.support.v4.app.** { *; }
-keep interface android.support.v4.app.** { *; }
-keep class android.support.v4.** { *; }

# support-v7包
-dontwarn android.support.v7.**
-keep class android.support.v7.internal.** { *; }
-keep interface android.support.v7.internal.** { *; }
-keep class android.support.v7.** { *; }
```

此时再用 jadx 进行反编译，类名就变成了 a，b，c，d 大大增加了对代码记忆难度。

![8.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-04f062e2992d35c96a822a4877472caaa77f8b97.png)

### Java层生成垃圾代码

虽然对代码的记忆难度增加了，可代码的数量还是太少了，如果能增加些代码和方法，让逆向分析难度再加大就更好了。

在根目录的 build.gradle 中添加：

```groovy
buildscript {
    dependencies {
        classpath "cn.hx.plugin:android-junk-code:1.0.2"
    }
}
```

app 目录的 build.gradle 模块中添加：

```groovy
apply plugin: 'com.android.application'
apply plugin: 'android-junk-code'

android {
    //xxx
}

android.applicationVariants.all { variant ->
    switch (variant.name) {
        case "debug":
        case "release":
            androidJunkCode.configMap.put(variant.name, {
                packageBase = "com.bmstd.aesencryption"  //生成java类根包名
                packageCount = 30 //生成包数量
                activityCountPerPackage = 3 //每个包下生成Activity类数量
                otherCountPerPackage = 50  //每个包下生成其它类的数量
                methodCountPerClass = 20  //每个类下生成方法数量
                resPrefix = "junk_"  //生成的layout、drawable、string等资源名前缀
                drawableCount = 300  //生成drawable资源数量
                stringCount = 300  //生成string数量
            })
            break
    }
}
```

此时在拖入 jadx 中进行反编译，就会发现多出超级多的包和类以及方法和变量。

![9.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-25bedd6c89347da9d124766a612b9372f5a7000a.png)

这种垃圾代码的数量，将会严重打击逆向分析者的信心，并且会对精确的找出想要的那部分代码，增加了很大的难度。

### Java层代码混淆

接下来就是对 Java 层的代码部分进行混淆。

根目录 Gradle 文件加入

```groovy
buildscript {
    repositories {
        ...
        // 加入仓库
        maven { url 'https://jitpack.io' }
    }
    dependencies {
        ...
        classpath "com.github.CodingGay:BlackObfuscator-ASPlugin:3.7"
    }
}
```

app模块加入plugin

```groovy
apply plugin: 'com.android.application'
// 加入
apply plugin: 'top.niunaijun.blackobfuscator'
```

或者

```groovy
plugins {
    id 'com.android.application'
    // 加入
    id 'top.niunaijun.blackobfuscator'
}
```

添加混淆配置

```groovy
android {
    ...

    defaultConfig {
       ...
    }
}

// 加入混淆配置
BlackObfuscator {
    // 是否启用
    enabled true
    // 混淆深度
    depth 2
    // 需要混淆的包或者类(匹配前面一段)
    obfClass = ["com.bmstd.aesencryption"]
    // blackClass中的包或者类不会进行混淆(匹配前面一段)
    blackClass = ["com.bmstd.aesencryption.MainActivity"]
}

dependencies {
    ...
}
```

此时 Aes 类的代码就变成了如下，增加了花指令，一些列判断等无用的代码，并且字符串处增加了各种奇怪的字符，难以复制。

![10.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-f45e1a84bd54818c255fefcf4f72792b187f0998.png)

Java 层类名混淆，代码混淆并且生成很多垃圾代码，这三种防护设置完毕，足以让 Java 层有了“护城河”。

### So层保护秘钥

通过上面对 So 的分析，可以直接拿到 Key 和 iv 。

对 Key 和 iv 一定要加以保护，因为只要拿到了 Key 和 iv 就拿到了破解的关键。

所以对写死的 Key 和 iv 是不可取的。

常用的方法是将 Key 和 iv 通过 get方法获取。get 方法里面可通过一些数学计算，计算出 Key 和 iv、 或者使用一些编码解码。

最基本的也可使用 switch case 来完成。

```c++
#include "encryption.h"
#include "AES.h"
#include "Base64.h"
#include <iostream>

using namespace std;
/**
 * cbc方式加密
 * @param data
 * @param secretKey
 * @param iv
 * @return
 */

// key: bmstd-aes-key666
static const char *getKey() {
    const int len = 16;
    char *src = static_cast<char *>(malloc(len + 1));

    for (int i = 0; i < len; ++i) {
        switch (i) {
            case 0:
                src[i] = 'b';
                break;
            case 1:
                src[i] = 'm';
                break;
            case 2:
                src[i] = 's';
                break;
            case 3:
                src[i] = 't';
                break;
            case 4:
                src[i] = 'd';
                break;
            case 5:
                src[i] = '-';
                break;
            case 6:
                src[i] = 'a';
                break;
            case 7:
                src[i] = 'e';
                break;
            case 8:
                src[i] = 's';
                break;
            case 9:
                src[i] = '-';
                break;
            case 10:
                src[i] = 'k';
                break;
            case 11:
                src[i] = 'e';
                break;
            case 12:
                src[i] = 'y';
                break;
            case 13:
                src[i] = '6';
                break;
            case 14:
                src[i] = '6';
                break;
            case 15:
                src[i] = '6';
                break;
        }
    }
    src[len] = '\0';
    return src;
}

// iv: bmstd-aes-iv1234
static const char *getIV() {
    const int len = 16;
    char *src = static_cast<char *>(malloc(len + 1));

    for (int i = 0; i < len; ++i) {
        switch (i) {
            case 0:
                src[i] = 'b';
                break;
            case 1:
                src[i] = 'm';
                break;
            case 2:
                src[i] = 's';
                break;
            case 3:
                src[i] = 't';
                break;
            case 4:
                src[i] = 'd';
                break;
            case 5:
                src[i] = '-';
                break;
            case 6:
                src[i] = 'a';
                break;
            case 7:
                src[i] = 'e';
                break;
            case 8:
                src[i] = 's';
                break;
            case 9:
                src[i] = '-';
                break;
            case 10:
                src[i] = 'i';
                break;
            case 11:
                src[i] = 'v';
                break;
            case 12:
                src[i] = '1';
                break;
            case 13:
                src[i] = '2';
                break;
            case 14:
                src[i] = '3';
                break;
            case 15:
                src[i] = '4';
                break;
        }
    }
    src[len] = '\0';
    return src;
}

int iMode = 1;

string encryptByAES(const char *data) {
    const char *AES_KEY = getKey();
    const char *AES_IV = getIV();

    ...

    //进行进行AES的CBC模式加密
    AES aes;
    aes.MakeKey(AES_KEY, AES_IV, 16, 16);
    ...
}

string decryptByAES(const char *data) {
    const char *AES_KEY = getKey();
    const char *AES_IV = getIV();
    ...

    //进行AES的CBC模式解密
    AES aes;
    aes.MakeKey(AES_KEY, AES_IV, 16, 16);
    aes.Decrypt(szDataIn, szDataOut, length, iMode);
    ...
```

用 IDA 分析，Key 和 iv 就变成了 for 循环和 switch case 的判断。

![11.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-c431f78e22105d3a0c737e831dc2b845ce2bb5c6.png)

原本的 Key 和 iv 这些关键数据，就显得很不清晰。

### So层代码混淆

c++ 代码的混淆就用 #define 来做，常见的是 0o 或者 1l 混淆。这里以 1l 来举例。

AES.h代码增加 #define 部分

```c++
#ifndef _AES_H
#define _AES_H
#include <exception>
#include <cstring>
#include <string>
#define BLOCK_SIZE 16
#define decryptByAES               ll11l1l1ll
#define encryptByAES               ll11lll11l
#define MakeKey                    ll11lll1l1
#define Decrypt                    ll11l1l1l1
#define Encrypt                    ll11l1l11l
#define getKey                     lll1l1l1l1
#define getIV                      ll11l1llll
#define AES                        ll1ll1l1ll
using namespace std;

class AES
{
    ......
}
```

此时进入加密函数的代码就被混淆了

![12.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-bdb20d6c380b61ab682f1016ad0662f6a744135c.png)

点进 ll11lll11l 函数进行跟踪。

发现加载 Key 和 iv 的函数更是混淆的非常让人眩晕。

![13.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-53b970db18d8d497dde835faaf0d088ebe64e641.png)

### So层花指令

花指令是由设计者特别构思，希望使反汇编的时候出错，让破解者无法清楚正确地反汇编程序的内容，迷失方向。

这里使用的花指令库是 junk.h

```c++
//
// Created by ting on 2019-09-17.
//

#ifndef _JUNK_H_
#define _JUNK_H_

#define JUNK_CODE        //是否插入垃圾代码的开关
#ifdef JUNK_CODE

#define junk_fun0                 li11li1o0
#define junk_fun1                 li11li1o1
#define junk_fun2                 li11li1o2
#define junk_fun3                 li11li1o3

static inline int junk_fun0(void) {
    volatile int i = 138, j = 1949;

    if ((i++) % 2 > 0) j *= i;
    if (j < 0) i *= 2;
    else return 0;

    i = 1;
    while (i++ < 2) {
        j /= i;
        j++;
        i++;
    }
    return i;
}

static inline int junk_fun1(void) {
    volatile int i = 21, j = 75;

    if ((i--) % 3 > 0) j *= i;
    if (j > 1) i *= 3;
    else return 1;

    i = 1;
    while (i++ < 3) {
        j /= i;
        j--;
        i++;
    }
    return j;
}

static inline int junk_fun2(void) {
    volatile int i = 56, j = 17;

    if ((i--) % 5 > 0) j *= i;
    if (j > 2) i *= 5;
    else return 0;

    i = 1;
    while (i++ < 5) {
        j *= i;
        j += 3;
        i += 3;
    }
    return i;
}

static inline int junk_fun3(void) {
    volatile int i = 1909, j = 131;

    if ((i--) % 7 > 0) j *= i;
    if (j > 3) i *= 7;
    else return 1;

    i = 1;
    while (i++ < 7) {
        j /= i;
        j -= 5;
        i += 5;
    }
    return i;
}

#define _JUNK_FUN_0 {if(junk_fun2())junk_fun1();if(junk_fun0()) junk_fun3();if(junk_fun1()) junk_fun2();if(junk_fun3()) junk_fun1(); \
                       if(junk_fun1())junk_fun0();if(junk_fun2()) junk_fun3();if(junk_fun3()) junk_fun1();if(junk_fun1()) junk_fun0();}
#define _JUNK_FUN_1 {if(junk_fun3())junk_fun1();if(junk_fun1()) junk_fun2();if(junk_fun2()) junk_fun0();if(junk_fun0()) junk_fun1(); \
                       if(junk_fun2())junk_fun1();if(junk_fun0()) junk_fun3();if(junk_fun1()) junk_fun2();if(junk_fun3()) junk_fun1();}
#define _JUNK_FUN_2 {if(junk_fun1())junk_fun0();if(junk_fun2()) junk_fun3();if(junk_fun3()) junk_fun1();if(junk_fun1()) junk_fun0(); \
                       if(junk_fun0())junk_fun2();if(junk_fun3()) junk_fun0();if(junk_fun0()) junk_fun3();if(junk_fun2()) junk_fun3();}
#define _JUNK_FUN_3 {if(junk_fun0())junk_fun2();if(junk_fun3()) junk_fun0();if(junk_fun0()) junk_fun3();if(junk_fun2()) junk_fun3(); \
                       if(junk_fun3())junk_fun1();if(junk_fun1()) junk_fun2();if(junk_fun2()) junk_fun0();if(junk_fun0()) junk_fun1();}

#else

#define _JUNK_FUN_0 {}
#define _JUNK_FUN_1 {}
#define _JUNK_FUN_2 {}
#define _JUNK_FUN_3 {}

#endif
#endif
```

然后在重要数据或逻辑附近，这里选择 getKey 函数，插入一定量的花指令。

```c++
#include "encryption.h"
#include "AES.h"
#include "Base64.h"
#include <iostream>
#include "junk.h"

using namespace std;
/**
 * cbc方式加密
 * @param data
 * @param secretKey
 * @param iv
 * @return
 */

// key: bmstd-aes-key666
static const char *getKey() {
    const int len = 16;
    char *src = static_cast<char *>(malloc(len + 1));

    for (int i = 0; i < len; ++i) {
        switch (i) {
            case 0:
                src[i] = 'b';
                _JUNK_FUN_0
                break;
            case 1:
                src[i] = 'm';
                break;
            case 2:
                src[i] = 's';
                break;
            case 3:
                src[i] = 't';
                _JUNK_FUN_1
                break;
            case 4:
                src[i] = 'd';
                break;
            case 5:
                src[i] = '-';
                break;
            case 6:
                src[i] = 'a';
                _JUNK_FUN_3
                break;
            ...
```

此时在 switch 的基础上又增加了特别多 if 等逻辑判断。花指令将严重影响分析逻辑的完整性和顺畅性。

![14.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-7e8f6349a10321ee3368eb904f9bad6cced08fef.png)

总结语
---

以上对一个简单的 AES 加密 Demo 进行了 Java 类名混淆，Java 层生成垃圾代码及代码混淆。对 C 层的秘钥进行了保护，及代码混淆，并增加了花指令。

最后的结果可以看到，当时简单的 App 代码已经变的面目全非了，极大的增加了逆向分析者的难度。可以说，安全开发横跨一条河的难度，就是逆向工作者横跨一条江的难度，以攻促防，是安全的充分必要条件。