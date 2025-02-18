XposedApi详解到RPC的使用
------------------

### XposedApi详解

要想学习 Xposed Api 一定要借助官方文档。

官方 Api 文档网址：<https://api.xposed.info/reference/packages.html>

下面介绍在开发 Xposed 插件中最常使用的几种方式

#### 在介绍之前，要先创建一个测试 App

测试 App 共两个类，一个是 MainActivity 类，一个是 Dog 类。

MainActivity 类代码：

```java
package com.bmstd.hookdog;

import androidx.appcompat.app.AppCompatActivity;

import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.Toast;

public class MainActivity extends AppCompatActivity implements View.OnClickListener {
    Button bt_hookNormalMethod;
    Button bt_hookConstructMethod;
    Button bt_hookEat;
    Button bt_hookOverloadEat;
    Button bt_hookInner;
    Dog dog;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        bt_hookNormalMethod = findViewById(R.id.bt_hookNormalMethod);
        bt_hookConstructMethod = findViewById(R.id.bt_hookConstructMethod);
        bt_hookEat = findViewById(R.id.bt_hookEat);
        bt_hookOverloadEat = findViewById(R.id.bt_hookOverloadEat);
        bt_hookInner = findViewById(R.id.bt_hookInner);

        bt_hookNormalMethod.setOnClickListener(this);
        bt_hookConstructMethod.setOnClickListener(this);
        bt_hookEat.setOnClickListener(this);
        bt_hookOverloadEat.setOnClickListener(this);

        bt_hookInner.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                Toast.makeText(MainActivity.this, "内部类被调用", Toast.LENGTH_LONG).show();
            }
        });

    }

    @Override
    public void onClick(View v) {
        switch (v.getId()) {
            case R.id.bt_hookNormalMethod:
                dog = new Dog("辛巴", 14);
                int countSum = dog.count(100, 200);
                Toast.makeText(this, "得到的结果是：" + countSum, Toast.LENGTH_LONG).show();
                break;
            case R.id.bt_hookConstructMethod:
                dog = new Dog("靓仔", 15);
                String dogString = dog.toString();
                Toast.makeText(this, dogString, Toast.LENGTH_LONG).show();
                break;
            case R.id.bt_hookEat:
                dog = new Dog("公爵", 13);
                String eatResult = dog.eat("猪肉");
                Toast.makeText(this, eatResult, Toast.LENGTH_LONG).show();
                break;
            case R.id.bt_hookOverloadEat:
                dog = new Dog("哈利", 11);
                String eatOverLoadResult = dog.eat("狗粮", 50);
                Toast.makeText(this, eatOverLoadResult, Toast.LENGTH_LONG).show();
                break;
        }
    }
}
```

Dog 类代码：

```java
package com.bmstd.hookdog;

class Dog {
    String name;
    private int age;
    static String type = "狗类";

    public Dog(String name, int age) {
        this.name = name;
        this.age = age;
    }

    public static String work(String w) {
        return w;
    }

    public static String work(String w, int h) {
        String str = "狗正在" + w + "已工作" + h + "小时";
        return str;
    }

    int count(int num1, int num2) {
        int sum = 0;
        sum = num1 + num2;
        return sum;
    }

    public String eat(String foodName) {
        return "我爱吃" + foodName;
    }

    public String eat(String foodName, int amount) {
        return "我爱吃" + foodName + ",一次吃" + amount + "克";
    }

    private int sub(int num) {
        int subResult = num - 1;
        return subResult;
    }

    @Override
    public String toString() {
        return "Dog{" +
                "name='" + name + '\'' +
                ", age=" + age + '\'' +
                ", type=" + type + '\'' +
                '}';
    }
}
```

#### hook 构造方法

hook 构造方式使用 api，XposedHelpers.findAndHookConstructor。

hook 构造方法与 hook 普通方法类似，只是不用写方法名而已，因为构造方法的方法名就是类名。

这里 hook Dog 类的构造函数

```java
public Dog(String name, int age) {
    this.name = name;
    this.age = age;
}
```

编写代码：

```java
package com.bmstd.xposed1;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

public class HookTest implements IXposedHookLoadPackage {
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam loadPackageParam) throws Throwable {
        if (loadPackageParam.packageName.equals("com.bmstd.hookdog")) {
            Class clazz = loadPackageParam.classLoader.loadClass("com.bmstd.hookdog.Dog");

            XposedHelpers.findAndHookConstructor(clazz, String.class, int.class, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    param.args[0] = "逆刃";
                    param.args[1] = 8;
                }
            });
        }
    }
}
```

正常情况下，点击 Hook 构造方法按钮，会走下面代码的分支

```java
case R.id.bt_hookConstructMethod:
    dog = new Dog("靓仔", 15);
    String dogString = dog.toString();
    Toast.makeText(this, dogString, Toast.LENGTH_LONG).show();
    break;
```

然后由于 hook 住了构造方法，并修改了里面的参数，所以输出结果就不是 靓仔，15 ，而是 逆刃，8。

![1.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-1e05535ab1fafe7c03b04f7c3111fede4375aca6.png)

#### 获取和修改静态字段

获取静态字段，方法如下图

![2.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-4ef1162fe441fad0f375ff0854a5c4e209c15b0a.png)

这里以获取 Dog 类的静态属性 type 为例

```java
static String type = "狗类";
```

编写代码：

```java
package com.bmstd.xposed1;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

public class HookTest implements IXposedHookLoadPackage {
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam loadPackageParam) throws Throwable {
        if (loadPackageParam.packageName.equals("com.bmstd.hookdog")) {
            Class clazz = loadPackageParam.classLoader.loadClass("com.bmstd.hookdog.Dog");

            Object type = XposedHelpers.getStaticObjectField(clazz, "type");
            XposedBridge.log("获取类属性 type => " + type + "");
        }
    }
}
```

成功获取到类属性

![3.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-69bda6d91acd03c6934e1dc2ce82de5dc0e86ca7.png)

修改静态字段，与获取静态字段相似，只不过方法由 get 变为 set

修改静态字段，方法如下图

![4.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-6490f49e44a3f3a1e410a22a9c03fc002e501d01.png)

这里以修改 Dog 类的静态属性 type 为例

编写代码：

```java
package com.bmstd.xposed1;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

public class HookTest implements IXposedHookLoadPackage {
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam loadPackageParam) throws Throwable {
        if (loadPackageParam.packageName.equals("com.bmstd.hookdog")) {
            Class clazz = loadPackageParam.classLoader.loadClass("com.bmstd.hookdog.Dog");

            XposedHelpers.setStaticObjectField(clazz, "type", "猫类");
        }
    }
}
```

此时点击 HOOK 构造方法，弹出的就不是狗类，而是猫类

![5.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-1cee5d8089582b5a7d7c98525e268128ee0eda6f.png)

#### 调用静态方法

调用静态方法，使用的方法如下图

![6.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-da238612e298176e789c95fe9adfe1458d69bb14.png)

这里举的例子，都调用 work 方法

可以看到 work 方法有重载，有两个 work 方法

```java
public static String work(String w) {
    return w;
}

public static String work(String w, int h) {
    String str = "狗正在" + w + "已工作" + h + "小时";
    return str;
}
```

只需要在调用时，按参数的类型，严谨填入即可，无需考虑重载，想调用哪个就按哪个的参数类型进行填写。

分别调用上面两个 work 方法，代码如下：

```java
package com.bmstd.xposed1;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

public class HookTest implements IXposedHookLoadPackage {
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam loadPackageParam) throws Throwable {
        if (loadPackageParam.packageName.equals("com.bmstd.hookdog")) {
            Class clazz = loadPackageParam.classLoader.loadClass("com.bmstd.hookdog.Dog");

            Object work = XposedHelpers.callStaticMethod(clazz, "work", "狗正在看家");
            XposedBridge.log("调用静态方法 work => " + work);

            Object workOverload = XposedHelpers.callStaticMethod(clazz, "work", "狗正在玩耍", 50);
            XposedBridge.log("调用静态方法 work => " + workOverload);
        }
    }
}
```

可以看到 work 的两个重载方法都可成功调用

![7.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-8340cec23dba32f356f634e8f9e0376ee324c600.png)

#### 获取和修改动态字段

动态字段就是要有对象，而不能靠类直接进行调用。

所以首先要解决的第一个难点就是，获取对象！

获取对象的方式有两种

第一种方式就是使用 XposedHelpers.newInstance ，new 一个对象出来

第二种方式就是在 hook 方法时，使用 param.thisObject 获取对象

获取动态字段和获取静态字段方式的差异性只是少了 static

获取调用 eat 方法对象的 name，和 age 字段。编写代码：

```java
package com.bmstd.xposed1;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

public class HookTest implements IXposedHookLoadPackage {
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam loadPackageParam) throws Throwable {
        if (loadPackageParam.packageName.equals("com.bmstd.hookdog")) {
            Class clazz = loadPackageParam.classLoader.loadClass("com.bmstd.hookdog.Dog");

            XposedHelpers.findAndHookMethod(clazz, "eat", String.class, int.class, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    Object name = XposedHelpers.getObjectField(param.thisObject, "name");
                    int age = XposedHelpers.getIntField(param.thisObject, "age");

                    XposedBridge.log("获取实例属性 name => " + name);
                    XposedBridge.log("获取实例属性 age => " + age);
                }
            });
        }
    }
}
```

从上面的开发可知，调用的是下面的分支

```java
case R.id.bt_hookOverloadEat:
    dog = new Dog("哈利", 11);
    String eatOverLoadResult = dog.eat("狗粮", 50);
    Toast.makeText(this, eatOverLoadResult, Toast.LENGTH_LONG).show();
    break;
```

所以获取到的 name 是哈利，age 是 11

![8.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-cfa2b5aa747115346d321f3ff4e21c2c09b49cc1.png)

修改动态字段，就是将 set 变为 get

修改调用 eat 方法对象的 name，和 age 字段。

```java
package com.bmstd.xposed1;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

public class HookTest implements IXposedHookLoadPackage {
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam loadPackageParam) throws Throwable {
        if (loadPackageParam.packageName.equals("com.bmstd.hookdog")) {
            Class clazz = loadPackageParam.classLoader.loadClass("com.bmstd.hookdog.Dog");

            XposedHelpers.findAndHookMethod(clazz, "eat", String.class, int.class, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    XposedHelpers.setObjectField(param.thisObject, "name", "多多");
                    XposedHelpers.setIntField(param.thisObject, "age", 6);
                }
            });
        }
    }
}
```

通过 objection 搜索对象获取到 name 已经变成了多多，age 变成了 6。

![9.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-40a6a098afd8d1b4242944d01facbbe5012e4ea4.png)

#### 调用普通方法

调用普通方法，使用的方法如下图

![10.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-0e2aac3cbf9751e6d82bfcb2f0e47a7adc62bc9e.png)

首选运用是通过 new 对象，来调用 count 方法

```java
Object dog = XposedHelpers.newInstance(clazz, "哈里", 12);
Object count = XposedHelpers.callMethod(dog, "count", 22, 11);
XposedBridge.log("调用普通方法 work => " + count);
```

调用普通方法成功，得到的结果是

![11.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-a9cd3d41b459bb7a5d311ad750a636759a145485.png)

运行第二种方法，通过 hook 然后使用 param.thisObject 获取对象，进行调用

```java
package com.bmstd.xposed1;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

public class HookTest implements IXposedHookLoadPackage {
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam loadPackageParam) throws Throwable {
        if (loadPackageParam.packageName.equals("com.bmstd.hookdog")) {
            Class clazz = loadPackageParam.classLoader.loadClass("com.bmstd.hookdog.Dog");

            XposedHelpers.findAndHookMethod(clazz, "eat", String.class, int.class, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    Object count = XposedHelpers.callMethod(param.thisObject, "count", 66, 55);
                    XposedBridge.log("调用普通方法 work => " + count);
                }
            });
        }
    }
}
```

同样调用普通方法也可成功，得到的结果是

![12.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-b65dc82c0ab2f655ded5ad2bad6d2b9d77416ab2.png)

### Xposed结合NanoHttpd使用RPC

Xposed 本身是不支持 RPC 的，但 Xposed 的优点是，可以在代码中嵌入任意 Java 代码，与Android本身开发无差别。、

所以可以在 Xposed 中结合 NanoHttpd 完成 RPC。

首先在 Android Studio 工程中的 build.grade 中引入依赖

```xml
implementation 'org.nanohttpd:nanohttpd:2.3.1'
```

![13.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-11f5cff574ec1ebf1a54e3377c8c9994842612f0.png)

然后就可以使用 NanoHttpd 了。

Xposed 结合 NanoHttp 使用 RPC 原理如下图所示：

![14.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-3af112dd648dacd5d22f6ad90ed54d825136032a.png)

编写 RPC 代码，可以调用静态方法 work 和普通方法 eat

```java
package com.bmstd.xposed1;

import java.io.IOException;
import java.util.Map;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;
import fi.iki.elonen.NanoHTTPD;

public class HookTest implements IXposedHookLoadPackage {
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam loadPackageParam) throws Throwable {
        // 判断包名
        if (loadPackageParam.packageName.equals("com.bmstd.hookdog")) {
            // 寻找类
            Class clazz = loadPackageParam.classLoader.loadClass("com.bmstd.hookdog.Dog");
            class App extends NanoHTTPD {
                String msg = "";

                // 这里的写法是不变的，变的只是端口
                public App() throws IOException {
                    super(8899); // 定义端口
                    start(NanoHTTPD.SOCKET_READ_TIMEOUT, true); // 启动 NanoHTTPD
                    XposedBridge.log("\nRunning! Point your browsers to http://localhost:8899/ \n");
                }

                // serve 就是处理请求和返回的地方，主要的逻辑就在 serve 里面写
                @Override
                public Response serve(IHTTPSession session) {
                    // 获取参数，但是这里只能获取 get 参数
                    Map<String, String> parameters = session.getParms();
                    // 如果参数的键有 work，就调用静态方法 work
                    if (parameters.containsKey("work")) {
                        String work = parameters.get("work");
                        msg = (String) XposedHelpers.callStaticMethod(clazz, "work", work);
                    }

                    // 如果参数的键有 foodName 和 amount，就调用普通方法 eat 
                    if (parameters.containsKey("foodName") && parameters.containsKey("amount")) {
                        Object dog = XposedHelpers.newInstance(clazz, "哈里", 12);
                        String foodName = parameters.get("foodName");
                        String amount = parameters.get("amount");
                        int i = Integer.parseInt(amount);

                        msg = (String) XposedHelpers.callMethod(dog, "eat", foodName, i);
                    }

                    // 将结果返回页面
                    return newFixedLengthResponse(Response.Status.OK, NanoHTTPD.MIME_PLAINTEXT, msg);
                }
            }

            new App();
        }
    }
}
```

由于 NanoHttpd 一定使用的是网络，所以被 hook 的 App 必须拥有网络权限，这点很重要，否则就会启动网络异常，报错误。

一定要在被 hook 的 App 中增加网络权限。这里就要在 com.bmstd.hookdog 设置网络权限。

![15.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-9fe954abfa434f3b3969a99f01ffe7acbe500139.png)

此时通过网站就可以调用 Xposed 的主动调用了。

调用普通方法 eat 效果。

![16.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-c9128820453f9c201c34a144c8ed1c07d387ec30.png)

调用静态方法 work 效果。

![17.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-aa15cf45793db3dae07ff8e094488f1b9419a4d5.png)

这样就可以既隐藏代码细节，使用者又方便。

### 总结语

本文共详解并举例了： hook构造方法；获取和修改静态字段；调用静态方法；获取和修改动态字段；调用普通方法。并最后让 Xposed 结合 NanoHttpd 弥补了 Xposed 不能 RPC 的功能。