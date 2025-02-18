0x01 查找dll文件。
=============

```php
using System.Reflection;
Assembly.Load()
Assembly.LoadFrom()
Assembly.LoadFile()
```

Load需要把dll放到程序当前路径加载，也可以读取字符串形式。LoadFrom需要写全路径，如果test1.dll引用了test2.dll，同时也会加载test2.dll进来。LoadFile不会加载test2.dll。

```php
Assembly assembly1 = Assembly.Load("DllTest");
Assembly assembly2 = Assembly.LoadFile(@"C:\Users\Administrator\Desktop\c#\learn\reflection2\DllTest\bin\Release\DllTest.dll");
Assembly assembly3 = Assembly.LoadFrom(@"C:\Users\Administrator\Desktop\c#\learn\reflection2\DllTest\bin\Release\DllTest.dll");
Assembly assembly4 = Assembly.LoadFrom("DllTest.dll");
```

0x02 调用构造函数
===========

首先写一个DllTest.dll

```php
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace DllTest
{
    public class Class1
    {
        public Class1()
        {
            Console.WriteLine("no params");
        }

        public Class1(string name)
        {
            Console.WriteLine($"have params value is {name}");
        }
    }
}
```

前面我们已经加载了dll文件，但是可能会存在多个类，所以我们要获取指定类型。

```php
Type type = assembly.GetType("DllTest.Class1");
```

然后动态的实例化对象

```php
Object obj = Activator.CreateInstance(type);
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-ba875927c666ed1f1840f56c9a98bb5f81a492df.png)

调用参数构造方法

```php
Object obj = Activator.CreateInstance(type,new Object[] {"test"});
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-44e73e875d78b014b2902afd171fa70823c601f3.png)

如何调用私有的构造函数

```php
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace DllTest
{
    public class Class1
    {
        private Class1()
        {
            Console.WriteLine("no params");
        }

        public Class1(string name)
        {
            Console.WriteLine($"have params value is {name}");
        }
    }
}
```

在CreateInstance方法第二个参数设置为true即可

```php
Assembly assembly = Assembly.LoadFrom("DllTest.dll");
Type type = assembly.GetType("DllTest.Class1");
Object obj = Activator.CreateInstance(type,true);
```

0x03 查找所有类，构造方法和参数
==================

很多时候我们得到一个dll文件但是不知道里面存在哪些类  
我们在DllTest.dll再创建一个类。

```php
Assembly assembly = Assembly.LoadFrom("DllTest.dll");
foreach(var all_type in assembly.GetTypes())
{
    Console.WriteLine(all_type.Name);
}
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-8d8ab3644b079bb62221b9941236e3539c1acc85.png)

当我们获取到类后，再获取所有的构造方法

```php
Type type = assembly.GetType("DllTest.Class1");
foreach(var all_cons in type.GetConstructors())
{
    Console.WriteLine(all_cons);
}
```

如果我们要获取构造方法里面的参数

```php
Assembly assembly = Assembly.LoadFrom("DllTest.dll");
foreach(var all_type in assembly.GetTypes())
{
    Console.WriteLine("类:"+all_type.Name);
}
Type type = assembly.GetType("DllTest.Class1");
foreach(var all_cons in type.GetConstructors())
{
    Console.WriteLine("构造方法:"+all_cons);
    foreach(var param in all_cons.GetParameters())
    {
        Console.WriteLine("所有参数:"+param.Name);
    }
}
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-8b8da996f5c1cf8ebecf59a9d903481f4d68629d.png)

但是这里可以看到private没有显示出来，我们加参数即可。

```php
static void Main(string[] args)
{
    Assembly assembly = Assembly.LoadFrom("DllTest.dll");
    foreach(var all_type in assembly.GetTypes())
    {
        Console.WriteLine("类:"+all_type.Name);
    }
    Type type = assembly.GetType("DllTest.Class1");
    foreach(var all_cons in type.GetConstructors(BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic))
    {
        Console.WriteLine("构造方法:"+all_cons);
        foreach(var param in all_cons.GetParameters())
        {
            Console.WriteLine("所有参数:"+param.Name);
        }
    }
}
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-b06b94b0909551af19826201e07681007117b375.png)

0x04 调用方法
=========

在DllTest添加一个普通方法和一个私有方法

```php
public void TestMethod()
{
    Console.WriteLine("TestMethod");
}
```

先获取所有方法

```php
var methods = type.GetMethods(BindingFlags.Instance|BindingFlags.Public|BindingFlags.NonPublic);
foreach(var method in methods)
{
    Console.WriteLine(method);
    Console.WriteLine(method.Attributes);
}
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-c712e04b6c1839a2511e452449a77c81880bdf80.png)

可以看到TetMethod方法为public，TestMethod2方法为private。

调用TestMethod方法，就算我们知道这个方法里面没有参数但是还是要new一个空数组，如果有参数写进去即可。

```php
var method = type.GetMethod("TestMethod");
method.Invoke(obj,new object[] {});
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-c10090239dc38def4c9d1bb95927d223e23d5e63.png)

调用TestMethod2方法。

```php
var method = type.GetMethod("TestMethod2",BindingFlags.Public|BindingFlags.NonPublic|BindingFlags.Instance);
method.Invoke(obj,new object[] {});
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-75903a00101a56356b1e2101f1b7655f57707abb.png)

0x05 调用泛型方法
===========

先在DllTest添加两个泛型方法

```php
public void Test<T>()
{
    Console.WriteLine("Test");
}

public void Test2<T>(string name)
{
    Console.WriteLine($"name is:{name}");
}
```

```php
var method = type.GetMethod("Test"); //获取方法
var genericMethod = method.MakeGenericMethod(new Type[] {typeof(int)}); //指定泛型参数类型(前面的T)
genericMethod.Invoke(obj, new object[] { });
```

有参数

```php
var method = type.GetMethod("Test2");
var genericMethod = method.MakeGenericMethod(new Type[] {typeof(string)});
genericMethod.Invoke(obj, new object[] {"jjjj"});
```

0x06 操作属性
=========

DllTest创建一个Pro类

```php
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace DllTest
{
    public class Pro
    {
        public string name { get; set; }
        public int num { get; set; }
    }
}

```

先获取所有属性

```php
Assembly assembly = Assembly.LoadFrom("DllTest.dll");
Type type = assembly.GetType("DllTest.Pro");
object obj = Activator.CreateInstance(type);
foreach(var property in type.GetProperties())
{
    Console.WriteLine(property.Name);
}
```

设置属性和获取属性

```php
Assembly assembly = Assembly.LoadFrom("DllTest.dll");
Type type = assembly.GetType("DllTest.Pro");
object obj = Activator.CreateInstance(type);
foreach(var property in type.GetProperties())
{
    //Console.WriteLine(property.Name);
    if (property.Name.Equals("name"))
    {
        property.SetValue(obj, "zhangsan");
    }else if (property.Name.Equals("num"))
    {
        property.SetValue(obj, 123123);
    }

    Console.WriteLine(property.GetValue(obj));
}
```

0x07 利用
=======

DllTest添加TestCalc类

```php
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;

namespace DllTest
{
    public class TestCalc
    {
        public static void Start()
        {
            Process p = new Process();
            p.StartInfo.FileName = "c:\\windows\\system32\\calc.exe";
            p.Start();
        }
    }
}
```

```php
using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text;

namespace reflection2
{
    internal class Program
    {
        static void Main(string[] args)
        {
            Assembly assembly = Assembly.LoadFrom("DllTest.dll");
            Type type = assembly.GetType("DllTest.TestCalc");
            var method = type.GetMethod("Start");
            method.Invoke(type,null);
        }
    }
}
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-e40d17197ff961aedfa8767452b01a921ba36d4a.png)

前面我们说了`Assembly.Load()`可以从string类型加载程序集。  
新建testcalc项目

```php
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;

namespace testcalc
{
    internal class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("test");
        }
    }
    public class Strat
    {
        public static void run()
        {
                Process p = new Process();
                p.StartInfo.FileName = "c:\\windows\\system32\\calc.exe";
                p.Start();
        }
    }
}
```

然后使用`File.ReadAllBytes`讲testcalc.exe转换为string类型

```php
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace readCalc
{
    internal class Program
    {
        static void Main(string[] args)
        {
            byte[] buffer = File.ReadAllBytes("testcalc.exe");
            string base64str = Convert.ToBase64String(buffer);
            Console.WriteLine(base64str);
        }
    }
}
```

结果

```php
TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4gRE9TIG1vZGUuDQ0KJAAAAAAAAABQRQAATAEDAI+UC8QAAAAAAAAAAOAAIgALATAAAAgAAAAIAAAAAAAAsicAAAAgAAAAQAAAAABAAAAgAAAAAgAABAAAAAAAAAAEAAAAAAAAAACAAAAAAgAAAAAAAAMAQIUAABAAABAAAAAAEAAAEAAAAAAAABAAAAAAAAAAAAAAAF4nAABPAAAAAEAAALwFAAAAAAAAAAAAAAAAAAAAAAAAAGAAAAwAAACwJgAAOAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAAACAAAAAAAAAAAAAAACCAAAEgAAAAAAAAAAAAAAC50ZXh0AAAAuAcAAAAgAAAACAAAAAIAAAAAAAAAAAAAAAAAACAAAGAucnNyYwAAALwFAAAAQAAAAAYAAAAKAAAAAAAAAAAAAAAAAABAAABALnJlbG9jAAAMAAAAAGAAAAACAAAAEAAAAAAAAAAAAAAAAAAAQAAAQgAAAAAAAAAAAAAAAAAAAACSJwAAAAAAAEgAAAACAAUAjCAAACQGAAABAAAAAQAABgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAC5yAQAAcCgOAAAKKh4CKA8AAAoqcnMQAAAKJW8RAAAKcgsAAHBvEgAACm8TAAAKJioeAigPAAAKKgAAAEJTSkIBAAEAAAAAAAwAAAB2Mi4wLjUwNzI3AAAAAAUAbAAAABwCAAAjfgAAiAIAAGQCAAAjU3RyaW5ncwAAAADsBAAASAAAACNVUwA0BQAAEAAAACNHVUlEAAAARAUAAOAAAAAjQmxvYgAAAAAAAAACAAABRxUAAAkAAAAA+gEzABYAAAEAAAASAAAAAwAAAAQAAAABAAAAEwAAAA0AAAABAAAAAgAAAAAAhwEBAAAAAAAGAPwAFQIGAGkBFQIGAEkA4wEPADUCAAAGAHEAqAEGAN8AqAEGAMAAqAEGAFABqAEGABwBqAEGADUBqAEGAIgAqAEGAF0A9gEGADsA9gEGAKMAqAEGAFcCnAEGABwAnAEKAEkC4wEKAMwB4wEAAAAAAQAAAAAAAQABAAAAEACUARMAPQABAAEAAQAQAFECEwA9AAEAAwBQIAAAAACRAKMBMQABAFwgAAAAAIYY3QEGAAIAZCAAAAAAlgC6ATcAAgCBIAAAAACGGN0BBgACAAAAAQBEAgkA3QEBABEA3QEGABkA3QEKACkA3QEQADEA3QEQADkA3QEQAEEA3QEQAEkA3QEQAFEA3QEQAFkA3QEQAGEA3QEVAGkA3QEQAHEA3QEQAIEAMQAaAHkA3QEGAIkA3QEGAIkAvgEfAJEAJAAQAIkAXgIkAC4ACwA7AC4AEwBEAC4AGwBjAC4AIwBsAC4AKwB6AC4AMwB6AC4AOwCAAC4AQwBsAC4ASwCKAC4AUwB6AC4AWwB6AC4AYwCmAC4AawDQAASAAAABAAAAAAAAAAAAAAAAABMAAAACAAAAAAAAAAAAAAAoAAoAAAAAAAIAAAAAAAAAAAAAACgAnAEAAAAAAAAAAAA8TW9kdWxlPgBtc2NvcmxpYgB0ZXN0Y2FsYwBDb25zb2xlAHNldF9GaWxlTmFtZQBXcml0ZUxpbmUAR3VpZEF0dHJpYnV0ZQBEZWJ1Z2dhYmxlQXR0cmlidXRlAENvbVZpc2libGVBdHRyaWJ1dGUAQXNzZW1ibHlUaXRsZUF0dHJpYnV0ZQBBc3NlbWJseVRyYWRlbWFya0F0dHJpYnV0ZQBBc3NlbWJseUZpbGVWZXJzaW9uQXR0cmlidXRlAEFzc2VtYmx5Q29uZmlndXJhdGlvbkF0dHJpYnV0ZQBBc3NlbWJseURlc2NyaXB0aW9uQXR0cmlidXRlAENvbXBpbGF0aW9uUmVsYXhhdGlvbnNBdHRyaWJ1dGUAQXNzZW1ibHlQcm9kdWN0QXR0cmlidXRlAEFzc2VtYmx5Q29weXJpZ2h0QXR0cmlidXRlAEFzc2VtYmx5Q29tcGFueUF0dHJpYnV0ZQBSdW50aW1lQ29tcGF0aWJpbGl0eUF0dHJpYnV0ZQB0ZXN0Y2FsYy5leGUAUHJvZ3JhbQBTeXN0ZW0ATWFpbgBTeXN0ZW0uUmVmbGVjdGlvbgBydW4AZ2V0X1N0YXJ0SW5mbwBQcm9jZXNzU3RhcnRJbmZvAC5jdG9yAFN5c3RlbS5EaWFnbm9zdGlj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
```

然后再使用`Assembly.Load`加载string反射调用Strat类的run方法

```php
using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text;

namespace Loader
{
    internal class Program
    {
        static void Main(string[] args)
        {
            string base64str = "TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4gRE9TIG1vZGUuDQ0KJAAAAAAAAABQRQAATAEDAI+UC8QAAAAAAAAAAOAAIgALATAAAAgAAAAIAAAAAAAAsicAAAAgAAAAQAAAAABAAAAgAAAAAgAABAAAAAAAAAAEAAAAAAAAAACAAAAAAgAAAAAAAAMAQIUAABAAABAAAAAAEAAAEAAAAAAAABAAAAAAAAAAAAAAAF4nAABPAAAAAEAAALwFAAAAAAAAAAAAAAAAAAAAAAAAAGAAAAwAAACwJgAAOAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAAACAAAAAAAAAAAAAAACCAAAEgAAAAAAAAAAAAAAC50ZXh0AAAAuAcAAAAgAAAACAAAAAIAAAAAAAAAAAAAAAAAACAAAGAucnNyYwAAALwFAAAAQAAAAAYAAAAKAAAAAAAAAAAAAAAAAABAAABALnJlbG9jAAAMAAAAAGAAAAACAAAAEAAAAAAAAAAAAAAAAAAAQAAAQgAAAAAAAAAAAAAAAAAAAACSJwAAAAAAAEgAAAACAAUAjCAAACQGAAABAAAAAQAABgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAC5yAQAAcCgOAAAKKh4CKA8AAAoqcnMQAAAKJW8RAAAKcgsAAHBvEgAACm8TAAAKJioeAigPAAAKKgAAAEJTSkIBAAEAAAAAAAwAAAB2Mi4wLjUwNzI3AAAAAAUAbAAAABwCAAAjfgAAiAIAAGQCAAAjU3RyaW5ncwAAAADsBAAASAAAACNVUwA0BQAAEAAAACNHVUlEAAAARAUAAOAAAAAjQmxvYgAAAAAAAAACAAABRxUAAAkAAAAA+gEzABYAAAEAAAASAAAAAwAAAAQAAAABAAAAEwAAAA0AAAABAAAAAgAAAAAAhwEBAAAAAAAGAPwAFQIGAGkBFQIGAEkA4wEPADUCAAAGAHEAqAEGAN8AqAEGAMAAqAEGAFABqAEGABwBqAEGADUBqAEGAIgAqAEGAF0A9gEGADsA9gEGAKMAqAEGAFcCnAEGABwAnAEKAEkC4wEKAMwB4wEAAAAAAQAAAAAAAQABAAAAEACUARMAPQABAAEAAQAQAFECEwA9AAEAAwBQIAAAAACRAKMBMQABAFwgAAAAAIYY3QEGAAIAZCAAAAAAlgC6ATcAAgCBIAAAAACGGN0BBgACAAAAAQBEAgkA3QEBABEA3QEGABkA3QEKACkA3QEQADEA3QEQADkA3QEQAEEA3QEQAEkA3QEQAFEA3QEQAFkA3QEQAGEA3QEVAGkA3QEQAHEA3QEQAIEAMQAaAHkA3QEGAIkA3QEGAIkAvgEfAJEAJAAQAIkAXgIkAC4ACwA7AC4AEwBEAC4AGwBjAC4AIwBsAC4AKwB6AC4AMwB6AC4AOwCAAC4AQwBsAC4ASwCKAC4AUwB6AC4AWwB6AC4AYwCmAC4AawDQAASAAAABAAAAAAAAAAAAAAAAABMAAAACAAAAAAAAAAAAAAAoAAoAAAAAAAIAAAAAAAAAAAAAACgAnAEAAAAAAAAAAAA8TW9kdWxlPgBtc2NvcmxpYgB0ZXN0Y2FsYwBDb25zb2xlAHNldF9GaWxlTmFtZQBXcml0ZUxpbmUAR3VpZEF0dHJpYnV0ZQBEZWJ1Z2dhYmxlQXR0cmlidXRlAENvbVZpc2libGVBdHRyaWJ1dGUAQXNzZW1ibHlUaXRsZUF0dHJpYnV0ZQBBc3NlbWJseVRyYWRlbWFya0F0dHJpYnV0ZQBBc3NlbWJseUZpbGVWZXJzaW9uQXR0cmlidXRlAEFzc2VtYmx5Q29uZmlndXJhdGlvbkF0dHJpYnV0ZQBBc3NlbWJseURlc2NyaXB0aW9uQXR0cmlidXRlAENvbXBpbGF0aW9uUmVsYXhhdGlvbnNBdHRyaWJ1dGUAQXNzZW1ibHlQcm9kdWN0QXR0cmlidXRlAEFzc2VtYmx5Q29weXJpZ2h0QXR0cmlidXRlAEFzc2VtYmx5Q29tcGFueUF0dHJpYnV0ZQBSdW50aW1lQ29tcGF0aWJpbGl0eUF0dHJpYnV0ZQB0ZXN0Y2FsYy5leGUAUHJvZ3JhbQBTeXN0ZW0ATWFpbgBTeXN0ZW0uUmVmbGVjdGlvbgBydW4AZ2V0X1N0YXJ0SW5mbwBQcm9jZXNzU3RhcnRJbmZvAC5jdG9yAFN5c3RlbS5EaWFnbm9zdGlj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";
            byte[] buffer = Convert.FromBase64String(base64str);
            Assembly assembly = Assembly.Load(buffer);
            Type type = assembly.GetType("testcalc.Strat");
            MethodInfo method = type.GetMethod("run");
            Object obj = assembly.CreateInstance(method.Name);
            method.Invoke(obj, new object[] { });
        }
    }
}
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-57b42285d4d7b4299e14c8576c4f6208df47b1e2.png)