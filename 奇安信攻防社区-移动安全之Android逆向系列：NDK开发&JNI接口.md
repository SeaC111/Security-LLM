> 本篇文章是Android逆向系列的第五篇，开始介绍学习NDK的开发及JNI接口。本文先介绍使用NDK套件编译出一个基于ARM平台的程序，并在手机上测试运行，接着介绍引入JNI，先简单入门熟悉下JNI头文件中的内容，包括定义的一些基本类型和本地接口结构体。

一、简介
----

本节介绍使用NDK工具编译一个运行于arm上的可执行程序，上传至手机上并测试运行。

开始之前，首先要了解架构平台，arm架构非常适用于移动平台，所以安卓手机基本上都是arm架构，除此Linux系统上使用的通常是x86\_64架构，那么在Linux上编译出的可执行文件就无法直接在手机上运行，这就造就了架构平台的不一样，编译出的可执行程序不能通用。所以需要交叉编译器，用于在本平台上编译出基于其他平台的程序，本节所使用的NDK工具就可以视为一款交叉编译器，在Windows上编译出基于ARM架构的可执行程序。

二、NDK工具安装
---------

### 1、Android NDK安装

Android NDK（Native Development Kit）原生开发工具，用于编译生成so文件、可执行文件。（适用于ARM架构）

下载地址：<https://developer.android.com/ndk/downloads>

参考：[NDK 使用入门](https://developer.android.com/ndk/guides?hl=zh-cn)

**1）下载解压至C盘**

![h1OgZd.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-34ff682c92b24dca8b5cfb5db3956a64657e7d82.png)

**2）配置环境变量**

```php
C:\android-ndk-r10e
```

![h1O6qH.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-fd4c2f9db2359f7876634c2439bab498f6670847.png)

**3）构建build**

![h1O2dA.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-18e4e489a76ab52b10d7da8c9d1cc294dd8397d6.png)

三、源文件及配置文件
----------

### 1、编写.c源文件

编写文件`anquan.c`，内容如下，测试输出test

```c
#include <stdio.h>

int main (){
    printf("test");
    printf("\n");
    return 0;
}
```

### 2、.mk文件简介

`.mk`文件是makefile文件，定义了一系列的规则来指定文件那部分需要编译及如何编译。

`Android.mk`文件描述要编译某个具体的模块，所需要的一些资源，包括要编译的源码、要链接的库等。

`Application.mk`文件用来描述你的应用程序需要哪些模块，以及这些模块所要具有的一些特性。

### 3、编写Android.mk文件

```mk
LOCAL_PATH := $(call my-dir) 
include $(CLEAR_VARS)
LOCAL_ARM_MODE := arm  
LOCAL_MODULE := anquan 
LOCAL_SRC_FILES := anquan.c 
LOCAL_CFLAGS += -pie -fPIE
LOCAL_LDFLAGS += -pie -fPIE
include $(BUILD_EXECUTABLE) 
```

内容解释：

1. `LOCAL_PATH := $(call my-dir)` ：返回Android.mk文件的路径（jni目录路径），my-dir是由编译系统提供的一个宏
2. `include $(CLEAR_VARS)`：CLEAR-VARS变量由编译系统提供，定时清理LOCAL开头的文件，但不会清理LOCAL\_PATH字段，清理的目的是因为以LOCAL开头的变量是全局的，清理后避免影响。
3. `LOCAL_ARM_MODE := arm` ：指定编译后的指令集，arm指令集中的每个指令有4个字节
4. `LOCAL_MODULE := anquan`：定义的模块文件（编译后的名字）
5. `LOCAL_SRC_FILES := anquan.c` ：同目录下的源文件
6. `LOCAL_CFLAGS += -pie -fPIE`  
    `LOCAL_LDFLAGS += -pie -fPIE`：指定源文件基于PIE安全机制来编译
7. `include $(BUILD_EXECUTABLE)` ：指定编译文件的类型，EXECUTABLE可执行文件，SHARED\_LIBRARY共享库文件.so文件

### 4、编写Application.mk文件

```mk
APP_ABI := x86 armeabi-v7a
```

`APP_ABI`：指明编译与调试的CPU架构，v7a是第七代及以上的ARM处理器。

四、ndk编译可执行程序
------------

### 1、在jni目录下创建上述三个文件

三个文件内容在第三部分中已经描述了，可以回去看看

![4StO58.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-192ab77d4244da32879ab4eea67d3ad81c57bb47.png)

### 2、使用ndk工具进行编译

进入到jni目录下，使用命令`ndk-build`进行编译

![4St7DI.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-56aba48760483e9921ea92c62a5fc35fff3d01af.png)

可以在上一级目录下看到三个文件夹，其中编译出的**可执行文件**位于`libs\armeabi-v7a`下

五、在手机上执行文件
----------

### 1、usb连接调试

插入usb线后，可以通过命令`adb devices`进行查看连接的设备

![4StqVP.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-b578070a313c3ecde94e5ca1c3351accfd6b4fd6.png)

### 2、将编译后的程序移到手机上

```php
adb push D:\EveryCode\AndroidLearning\libs\armeabi-v7a\anquan /data/local/tmp
```

![4StLUf.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-c8d4be0eec5b02265d6127e203e6fd987932744e.png)

### 3、adb工具进入手机内部

```php
adb shell
su
cd /data/local/tmp
```

### 4、执行该文件

```php
chmod 777 anquan
./anquan
```

![4StHbt.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-458322ccc89d9438dc1c63509e0827feddb21e88.png)

六、JNI入门介绍
---------

### 1、JNI概述

JNI接口是一大堆**函数的接口API**

在Java和C中起到桥梁的作用

### 2、JNI作用

通过JNI接口**实现Java层与Native层相互调用**，在使用Jadx等反编译软件时就只能显示出方法名而无法显示方法体内容，具体的在更底层。

方便Java层调用C++的优秀资源库，也方便交叉开发

七、JNI头文件
--------

### 1、基本类型的定义

这部分使用typedef关键字定义了jbyte、jchar、jint等一系列变量

![4SNCbq.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-7434e2c2fdbca2ef2e5e273bda776b644f095b24.png)

### 2、本地接口结构体的定义

这里给出了一堆调用Java的方法

![4SN9rn.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-90bd8d00844cdb78443e81a78cdfd1c5a3ae0d30.png)

主要有get、set、call三种，下面简单介绍下

#### 1）Call开头的方法

如下图，简单了解第一行的`CallobjectMethod()`方法

jobject：表示返回值

JNIEnv\*：参数之一，本地调用的一个接口，提供了大量的JNI接口函数调用。（默认传入）

jobject：参数之一（默认传入）

jmethodID：参数之一，该方法需要一个方法ID，即Java层方法的ID，这里可以通过另一个方法GetMethodid来获取ID值

![4SNiV0.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-f2e6f6edd894d2a2dc8efd49b3ccb19ca8636942.png)

#### 2）Get开头的方法

GetFieldID方法用于获取FieldID值，返回值为jfieldID

JNIEnv\*：默认参数之一

jclass：参数之一，由findclass方法获取

两个const char\*：分别是Java层方法名称和函数签名（返回值+参数）

![4SNpKs.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-52f9df984b9cce5ee54776578747f8ff55fc6da9.png)

#### 3）Set开头的方法

设置各种字段，返回值为空void

![4Stzvj.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-bd70a9c776afdbdbbc8f404cc5892fac568d8292.png)

### 3、Java参数类型与Native参数类型

上面简单介绍了JNI头文件中部分调用Java层的方法，其中的参数大致相同但还是有区别，这里详细解释下：

Java层中的八种基本类型，在JNI中对应的是类型前加上j即可

Java层中的object（类、接口等），在JNI中对应于jobject

Java层中基本数据类型的数组，在JNI中对用jarray类型

可参考下图，基本数据类型对比图

![4SNexJ.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-2844d5104960152d591c7733512f965a8f59ad0d.png)

引用数据类型图

![4SNnM9.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-6f2d2b0b227e094bdc03a27d0ad26f6f94ecb2db.png)