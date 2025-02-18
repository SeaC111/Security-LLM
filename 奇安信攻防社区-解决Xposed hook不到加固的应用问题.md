解决Xposed hook不到加固的应用问题
----------------------

#### 应用被加固 Xposed 是 hook 不到的

测试的是一个不良 App，名字是 移动TV。

要用 Xposed hook 的类是 com.cz.babySister.activity.MainActivity。

首先用 objection search 一下这个类，看是否存在。

```php
objection -g com.cz.babySister explore
android hooking search classes com.cz.babySister.activity.MainActivity
```

![1.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-0e29cbb93a33af5e27dead3f86c2c33f6d087c5b.png)

通过从内存里面查找，发现 com.cz.babySister.activity.MainActivity 类是的的确确存在的。

那么既然这个类存在，用 Xposed hook 应该就可以 hook 的到。

编写 Xposed hook 代码：

```java
package com.bmstd.xposed1;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

public class HookTest implements IXposedHookLoadPackage {

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam loadPackageParam) throws Throwable {
        if (loadPackageParam.packageName.equals("com.cz.babySister")) {
            Class<?> aClass = XposedHelpers.findClass("com.cz.babySister.activity.MainActivity", loadPackageParam.classLoader);
            XposedBridge.hookAllMethods(aClass, "onCreate", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    super.beforeHookedMethod(param);
                    XposedBridge.log("MainActivity onCreate called");
                }
            });
        }
    }
}
```

发现会一直触发 java.lang.ClassNotFoundException 类找不到的异常。

![2.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-d29cc5eacd22f51ff0edfd24a86a6c225cf608ee.png)

将 App 进行静态分析，拖入 GDA 中，发现这是一个加了壳的 App ，进行了腾讯加固。

![3.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-10ca4f5f0fb541c7762ab2982347a28fd038f326.png)

所以，由于 Xposed 是系统级别 hook 框架，Xposed 注入的时机是很早的，而壳程序总是又较 App 应用程序最先执行的，所以 Xposed hook 默认使用的是壳的 ClassLoader 而不是应用本身的 ClassLoader，所以是不可能 hook 到应用内部的代码的。

这就将问题转换为，如何转换 ClassLoader。

#### 基本原理

要使用 Xposed hook 加固的应用分为三步

1. 是拿到加载应用本身 dex 的 ClassLoader
2. 是通过这个 ClassLoader 去找到被加固的类
3. 是通过这个类去 hook 需要 hook 的方法

#### 从多dex hook不到的问题角度去解决 Xposed hook 不到加固的应用

现在很多的 app 都有多个 dex 文件，因为谷歌规定单个 dex 文件中的方法不能超过 65536 个。

如果代码太多的话必须拆分 dex。如果用 Xposed 去 hook 非默认 dex 文件的类就会发生 ClassNotFoundError。

要解决这个问题，需要拿到对应 dex 文件的上下文环境。

android 在加载 dex 文件后会创建一个 Application 类，然后会调用 attach 方法，attach 方法的参数就是上下文 context。

![4.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-8333483110134382280f2bf13c175daf587ba5e2.png)

而且 attach 方法是 final 方法，不会因为被覆盖而 hook 不到，拿到这个 context 就可以获取对应的 classloader，然后可以顺利 hook 到需要的类。

根据上面的思路，编写代码：

```java
package com.bmstd.xposed1;

import android.app.Application;
import android.content.Context;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

public class HookTest implements IXposedHookLoadPackage {

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam loadPackageParam) throws Throwable {
        if (loadPackageParam.packageName.equals("com.cz.babySister")) {
            // 解决多dex文件hook不到问题
            XposedHelpers.findAndHookMethod(Application.class, "attach", Context.class,
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                            super.beforeHookedMethod(param);
                            // 获取上下文
                            Context context = (Context) param.args[0];
                            XposedBridge.log("context => " + context);
                            // 类加载器
                            ClassLoader classLoader = context.getClassLoader();
                            XposedBridge.log("classLoader => " + classLoader);

                            // 替换类加载器进行 hook 对应的方法
                            Class<?> aClass = XposedHelpers.findClass("com.cz.babySister.activity.MainActivity", classLoader);
                            XposedBridge.hookAllMethods(aClass, "onCreate", new XC_MethodHook() {
                                @Override
                                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                                    super.beforeHookedMethod(param);
                                    XposedBridge.log("MainActivity onCreate called");
                                }
                            });
                        }
                    });
        }
    }
}
```

执行代码后，可以看到首先进入了壳的 context ，然后获取到了壳的 ClassLoader。

![5.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-1e30bed6235b7f4a6d71a707a925221b8f851ba8.png)

等正式进入 App 后，android 会重新加载 App 本身 dex 文件，会创建一个 Application 类，然后会调用 attach 方法，attach 方法的参数就是上下文 context。通过这个 context 获取到的就是 App 本身的 ClassLoader 了。

在通过这个 ClassLoader 找到要 hook 的类，执行后的结果就是成功 hook 到类中的方法。

![6.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-f41ea8174a6c8241770bcdcf339789a2d0a51e94.png)

#### 从动态加载dex hook不到的问题角度去解决 Xposed hook 不到加固的应用

从上面的理论分析得知，重点问题还是在 ClassLoader 的切换。

所以直接使用 java.lang.ClassLoader.loadClass(java.lang.String) 这个方法。

这个方法的功能是：加载具有指定二进制名称的类，成功，然后一个类的对象。

![7.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-9d478cc98af8e15f459a3ee63417d0ad6ca39e33.png)

根据上面的思路，编写代码：

```java
package com.bmstd.xposed1;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

public class HookTest implements IXposedHookLoadPackage {
    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam loadPackageParam) throws Throwable {
        if (loadPackageParam.packageName.equals("com.cz.babySister")) {
            XposedBridge.log("has hooked!");
            // 解决动态加载dex文件hook不到问题
            XposedHelpers.findAndHookMethod(ClassLoader.class,
                    "loadClass",
                    String.class,
                    new XC_MethodHook() {
                        @Override
                        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                            super.afterHookedMethod(param);
                            // 打印当前已经加载的类
                            XposedBridge.log("clazz => " + param.getResult());
                            Class<?> clazz = (Class<?>) param.getResult();
                            if (clazz != null && clazz.getName().equals("com.cz.babySister.activity.MainActivity")) {
                                XposedBridge.hookAllMethods(clazz, "onCreate", new XC_MethodHook() {
                                    @Override
                                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                                        super.beforeHookedMethod(param);
                                        XposedBridge.log("MainActivity onCreate called");
                                    }
                                });
                            }
                        }
                    });
        }
    }
}
```

执行代码后，首先找到了壳的类。

![8.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-a71ffb6df77339a6ee157916e4a01cc21d33b338.png)

然后陆续找到了所有类，并成功进行预想中的 hook 。

![9.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-0e22e412077aecd57c0d78b9a4c84bf9497afe40.png)

#### 从应用加载角度解决 Xposed hook 不到加固的应用

App 是通过 Zygote 进程孵化的，通过 ActivityThread.main() 进入 App 。

performLaunchActivity() 函数用于响应 Activity 的操作。

并且 ActivityThread 类中还存在 Application 类型的 mInitialApplication。

![10.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-5ec7ddcb006749de4221a1780729ea2b72e8c038.png)

mInitialApplication 可以获得当前的 ClassLoader。

根据上面的思路，编写代码：

```java
package com.bmstd.xposed1;

import android.app.Application;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

public class HookTest implements IXposedHookLoadPackage {
    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam loadPackageParam) throws Throwable {
        if (loadPackageParam.packageName.equals("com.cz.babySister")) {
            Class ActivityThread = XposedHelpers.findClass("android.app.ActivityThread", loadPackageParam.classLoader);
            XposedBridge.hookAllMethods(ActivityThread, "performLaunchActivity", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    Application mInitialApplication = (Application) XposedHelpers.getObjectField(param.thisObject, "mInitialApplication");
                    ClassLoader finalClassloader = mInitialApplication.getClassLoader();
                    XposedBridge.log("found classload is => " + finalClassloader.toString());
                    Class<?> MainActivity = XposedHelpers.findClass("com.cz.babySister.activity.MainActivity", finalClassloader);
                    XposedBridge.hookAllMethods(MainActivity, "onCreate", new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                            super.beforeHookedMethod(param);
                            XposedBridge.log("MainActivity onCreate called");
                        }
                    });
                }
            });
        }
    }
}
```

再次成功完成 hook 。

![11.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-645e45127a39cb81179cd01d256603b0cfd6ad46.png)