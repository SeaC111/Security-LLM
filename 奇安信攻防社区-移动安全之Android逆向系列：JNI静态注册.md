一、JNI使用简述
---------

本节以安卓逆向的角度介绍JNI入门使用，主要涉及到JNI的使用书写步骤，最后再通过NDK静态注册上传至手机上测试。主要步骤如下：

1. 编写带有native声明的方法的Java类，这里的native声明为本地方法且不要实现，其中的参数和方法体留在后面实现
2. 使用javah命令生成.h头文件，该.h头文件相当于在Java层中的接口，里面存在的方法在编写C/C++中实现。
3. C/C++中编写本地方法及.h头文件中存在的方法
4. 生成动态库.so文件，之后运行即可

二、使用JNI-书写步骤介绍及简单Toast弹窗
------------------------

### 1、Eclipse创建Android工程

#### 1）创建Android工程

![4SYlO1.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-9f92156c92c1fe6d212d64ba2c8b128fa1a0856f.png)

#### 2）项目设置

![4SY8w6.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-0b73d1e4e4002091f97f0534c048ef9ad10712f8.png)

#### 3）编写MainActivity.java

在`MainActivity.java`文件中编写一个`Getstring()`方法，并在`onCreate()`方法中添加Toast弹窗显示，便于测试

![4SYQyR.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-a34a1a7b77cad3d64d3b7888e61716c3ea78bc4b.png)

前面把程序放到Jadx工具里面进行反编译处理后，发现很多使用native修饰的方法，这些方法的特点是不可见性，即在jadx反编译时看不到其逻辑代码，只能看到一个空的方法名，而且使用native修饰的方法具体实现在java层是看不到的。这时就需要ndk开发的知识，在.so程序找到其对应的.so文件，然后去.so里面分析它的一个逻辑。

这里已经定义了一个被native修饰的方法，那么修饰这个方法就要做一些操作，在java层用Toast弹窗展示出来

```java
package com.example.anquantest;

import android.os.Bundle;
import android.app.Activity;
import android.widget.Toast;

public class MainActivity extends Activity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        Toast.makeText(this, Getstring(), 1).show();    //Toast弹窗
    }

    public native CharSequence Getstring();

}
```

#### 4）设置编码格式

![4SY3ex.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-784a7fbb6c1190a41e0eedeb71c4a2d81bc9fd33.png)

### 2、javah生成JNI样式的标头文件

> 这部分是基于MainActivity.java文件中的类，通过javah命令生成JNI样式的头部文件。

#### 1）前往文件目录下

该项目的资源src目录位置

```php
cd D:\EveryCode\Eclipse\data\anquantest\src
```

#### 2）javah命令生成JNI头文件

```php
javah -jni 包名＋类
javah -jni com.example.anquantest.MainActivity
```

![4SYhXn.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-d7a32a3815d25420a33d90cbbdb6ec745099ec2f.png)

可以在src目录下看到生成了一个`com_example_anquantest_MainActivity.h`文件

### 3、分析javah生成的.h文件

> 这部分简单介绍及分析了通过javah生成的.h头文件的内容

.h文件内容如下

![4SY5mq.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-a878a866de3145775de46f47b662c588f8d58c2d.png)

第一行代码引入jni头文件，也就是之前介绍的jin文件

```php
#include <jni.h>
```

预处理功能中的**条件编译**，根据是否已经定义了一个变量来进行分支选择，用于**防止重名和重复导入**。

```php
#ifndef
#endif
```

`jobject`类型的方法

```php
JNIEXPORT jobject JNICALL Java_com_example_anquantest_MainActivity_Getstring
  (JNIEnv *, jobject);
```

### 4、ndk编译前准备

> 这部分是编写三个文件，用于NDK编译.so文件，分别是JNI\_anquan.c、Application.mk、Android.mk文件。

#### 1）主目录下创建jni文件夹，并将.h文件移入其中

改为`JNI_anquan.h`并移动到jni文件夹中

![4SYWlj.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-8870dc62cdbd78133c4977a6448afff259275cf2.png)

#### 2）创建JNI\_anquan.c文件

![4SYf6s.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-a4f4f724f61e68755d00e0ad95b203c53d28c680.png)

```c
#include "JNI_anquan.h"

JNIEXPORT jobject JNICALL Java_com_example_anquantest_MainActivity_Getstring
  (JNIEnv *env, jobject obj){

    jstring str = (*env)->NewStringUTF(env, "testtest");

    return str;
}
```

首先是引入头文件`JNI_anquan.h`，接下来的`.._Getstring(){}`方法是在`JNI_anquan.h`中获取（使用javah生成的文件），添加两个参数env和obj，在方法体中添加`NewSreingUTF()`方法定义jstring类型的变量str，接收字符串testtest，最后将该字符串传回。

#### 3）创建Android.mk文件

```php
LOCAL_PATH          := $(call my-dir)
include $(CLEAR_VARS)
LOCAL_MODULE        := JNI_anquan
LOCAL_SRC_FILES     := JNI_anquan.c
LOCAL_ARM_MODE      := arm
LOCAL_LDLIBS        := -llog  
include $(BUILD_SHARED_LIBRARY)
```

![4SYRpQ.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-56f4c8e28e8508d49404303582f4835f19b3b187.png)

#### 4）创建Application.mk文件

```php
APP_ABI := armeabi-v7a
```

![4SYsTf.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-1c09e2a6c2da85b402601d51b00b99336020ab90.png)

### 5、生成.so文件

在cmd命令行中输入命令进行编译

```php
ndk-build
```

![4SYr0P.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-7f9d02eb9234983e6e03e2e55be7b416553ce098.png)

### 6、调用载入so库并连接手机测试

在`MainActivity.java`文件中添加代码至MainActivity类中，达到调用so库的作用

```java
    static{
         System.loadLibrary("JNI_anquan");
    }
```

![4SY6k8.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-a70e044103616ad089310348cef7916699fb6016.png)

```java
package com.example.anquantest;

import android.os.Bundle;
import android.app.Activity;
import android.widget.Toast;

public class MainActivity extends Activity {

    static{
         System.loadLibrary("JNI_anquan");
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        Toast.makeText(this, Getstring(), Toast.LENGTH_SHORT).show();
    }

    public native CharSequence Getstring();

}
```

保存后，连接手机测试

![4SYctS.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-0e5be3d6093fadb09b4e1a110c3b2a8b67ea5ac0.png)

可以在手机上看到

![4SYgfg.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-c70ecdacb8d4b254ff48fabf3bcb684f9c6d94ed.png)

小结：

```php
JNI：返回值类型 方法名称 参数类型
jobject (*CallObjectMethod)(JNIEnv*, jobject, jmethodID, ...);

C层：返回值 参数 方法体
JNIEXPORT jobject JNICALL Java_com_example_anquantest_MainActivity_Getstring
  (JNIEnv *, jobject){

  }
NewStringUTF
```

三、使用JNI-调用普通和静态变量
-----------------

### 1、编写MainActivity.java

```java
package com.example.anquantest;

import android.os.Bundle;
import android.app.Activity;
import android.widget.Toast;

public class MainActivity extends Activity {

    public String car1 = "yeah yeah !!!!";
    public static String car2 = "static static static static";

    static{
         System.loadLibrary("JNI_anquan");
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        Toast.makeText(this, Getstring(), Toast.LENGTH_SHORT).show();

        Toast.makeText(this, Getstr(), Toast.LENGTH_SHORT).show();
        Toast.makeText(this, GetStatic_str(), Toast.LENGTH_SHORT).show();
    }

    public native CharSequence Getstring();

    public native CharSequence Getstr();
    public native CharSequence GetStatic_str();

}
```

### 2、通过javah命令生成MainActivity.h文件

```php
javah -jni com.example.anquantest.MainActivity
```

![4StZnI.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-d63b27375d25209a89e522725e6b7f0f4eeda696.png)

将其改名为`JNI_anquan.h`并移动到jni目录下

### 3、编写JNI\_anquan.c文件

在之前的基础上需要新加两个函数方法，分别是`Getstr()`方法体和`Getstatic_str()`方法体，下面先详细介绍编写`Getstr()`方法体，后面的`Getstatic_str()`方法体类似。

#### 1）编写Getstatic\_str()方法体

##### 0x01 GetObjectField方法

首先**获取普通字段**方法需要用到JNI接口中的`Getobjectfield`方法

```c
jobject     (*GetObjectField)(JNIEnv*, jobject, jfieldID);
注：返回值-方法名称-参数类型
```

![4StuAf.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-dbf77da114b18094cc80ca102605317115076859.png)

添加了GetObjectField方法后，**发现jfieldID未知，需要通过其他方法获取**

那么jfieldID值需要如何获取呢？在`jni.h`中提供了GetFieldID方法获取jfieldID值

![4StKN8.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-6612cc7fa28deb421431ef9d1ee5d4938e0c85d5.png)

##### 0x02 GetFieldID方法

`GetFieldID`方法用于**获取jfieldID**

```php
jfieldID    (*GetFieldID)(JNIEnv*, jclass, const char*, const char*);

第一个参数：JNI接口对象       env
第二个参数：Java类对象        jclass
第三个参数：Java中的变量名     car1
第四个参数：Java变量签名      Ljava/lang/String;  (变量返回值类型,注意有分号)

```

![4StmHP.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-7f2696a92c409298d91ae5bc5955e30cbe8042a2.png)

添加了GetFieldID方法后，发现还有个jclass参数未知，也是需要其他方法来获取。

同样我们可以在`jni.h`中找到FindClass方法来得到jclass参数的值

![4SteBt.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-785d6db175b7ed339a13f52c82be814b22784410.png)

> 这里`Ljava/lang/String`后面需要加上一个分号`;`

##### 0x03 FindClass方法

`FindClass`方法用于**获取jclass值**

```php
jclass      (*FindClass)(JNIEnv*, const char*);

第一个参数：JNI接口对象       env
第二个参数：Java类的完整路径   com/example/anquantest/MainActivity
这里的完整路径是包名＋类名，将点换成斜杆

```

![4StyuR.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-175f7717f822582570e5f80b6eaedf3e3ff752ff.png)

完整代码如下

![4St0CF.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-c18244a57cf0ae2aecdbb845a658afc058e5146c.png)

##### 0x04 完整方法体

```c
JNIEXPORT jobject JNICALL Java_com_example_anquantest_MainActivity_Getstr
  (JNIEnv *env, jobject obj){

    jclass _jclass = (*env)->FindClass(env, "com/example/anquantest/MainActivity");

    jfieldID _jfieldID = (*env)->GetFieldID(env, _jclass, "car1", "Ljava/lang/String;");

    jobject str1 = (*env)->GetObjectField(env, obj, _jfieldID);

    return str1;
}

```

#### 2）编写Getstatic\_str()方法体

类似`Getstr()`方法，`Getstatic_str()`方法内容构造类似

##### 0x01 GetStaticObjectField方法

```php
jobject     (*GetStaticObjectField)(JNIEnv*, jclass, jfieldID);

```

参数中的`jclass`和`jfieldID`未知，可以通过上述方法获取，代码类似，这里就不展开

![4StDgJ.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-b46745289a65850f654c93f2203798625b4db7a3.png)

##### 0x02 GetStaticFieldID方法

```php
jfieldID    (*GetStaticFieldID)(JNIEnv*, jclass, const char*,const char*);

```

![4StB34.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-108ec1d4d5b2143e689349fac163beeb58bc0fd2.png)

##### 0x03 完整方法体

```c
JNIEXPORT jobject JNICALL Java_com_example_anquantest_MainActivity_GetStatic
  (JNIEnv *env, jobject obj){
    jclass _jclass = (*env)->FindClass(env, "com/example/anquantest/MainActivity");

    jfieldID _jfieldID = (*env)->GetStaticFieldID(env, _jclass, "car2", "Ljava/lang/String;");

    jobject str2 = (*env)->GetStaticObjectField(env, _jclass, _jfieldID);

    return str2;
}

```

#### 3）JNI\_anquan.c完整版

```c
#include "JNI_anquan.h"

JNIEXPORT jobject JNICALL Java_com_example_anquantest_MainActivity_Getstring
  (JNIEnv *env, jobject obj){

    jstring str = (*env)->NewStringUTF(env, "testtest");

    return str;
}

// 获取Java层普通变量
JNIEXPORT jobject JNICALL Java_com_example_anquantest_MainActivity_Getstr
  (JNIEnv *env, jobject obj){

    // FindClass方法返回jclass，第二个参数是包名+类名以斜杆隔开
    jclass _jclass = (*env)->FindClass(env, "com/example/anquantest/MainActivity");

    // GetFieldID方法获取jfieldID，第三个参数是变量名
    // 第四个参数是变量签名，也就是变量的类型，L表示类类型，后面加上分号; !!!~~~
    jfieldID _jfieldID = (*env)->GetFieldID(env, _jclass, "car1", "Ljava/lang/String;");

    // GetObjectField获取变量值，其中未知的参数通过上面的方法均可找到
    jobject str1 = (*env)->GetObjectField(env, obj, _jfieldID);

    // 返回获取到的变量值
    return str1;
}

JNIEXPORT jobject JNICALL Java_com_example_anquantest_MainActivity_GetStatic
  (JNIEnv *env, jobject obj){
    jclass _jclass = (*env)->FindClass(env, "com/example/anquantest/MainActivity");

    jfieldID _jfieldID = (*env)->GetStaticFieldID(env, _jclass, "car2", "Ljava/lang/String;");

    jobject str2 = (*env)->GetStaticObjectField(env, _jclass, _jfieldID);

    return str2;
}

```

![4Strv9.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-ab5c3e6447acfe6f207a4d043c0be3aeeec05298.png)

### 4、创建Android.mk文件

```php
LOCAL_PATH          := $(call my-dir)
include $(CLEAR_VARS)
LOCAL_MODULE        := JNI_anquan
LOCAL_SRC_FILES     := JNI_anquan.c
LOCAL_ARM_MODE      := arm
LOCAL_LDLIBS        := -llog  
include $(BUILD_SHARED_LIBRARY)
```

### 5、Application.mk文件

```php
APP_ABI := armeabi-v7a

```

### 6、生成.so文件

```php
ndk-build

```

![4Std4U.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-d59d568a6354fbc8a12b2685b9a79e0d61db0fc6.png)

### 7、连接手机测试

![4pohy4.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-c95ba9715fd0c611f33ea59ed8d98d9991b728e0.png)

![4poflF.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-e795851b9b2a0aa4c5444ebed01196d11b35cf9f.png)