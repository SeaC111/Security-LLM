0x01 dcsync简介
=============

dcsync基本的原理我就不讲了，网上挺多相关教程。  
其实只需要两条acl即可

```php
复制目录更改
复制目录更改全部
```

或者拥有一条

```php
完全控制权限
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-7143040c543614d1c283953c1bee88946f8da165.png)

0x02 连接ldap
===========

上篇文章讲到本地添加用户使用到的DirectoryServices.dll。这里也需要引用，windows本机自带了该dll，可以自行everything查找下。  
首先我们通过最简单粗暴的方法来获取`args`。

```php
if(args.Length == 7)
            {
                if (args[0] == "-d" && args[2] == "-u" && args[4] == "-p" && args[6] == "--list")
                {
                    domain = "LDAP://"+args[1]; username = args[3]; password = args[5];
                }
            }
```

我们常规的ldap查询例如ldapsearch

```php
ldapsearch -x -H ldap://192.168.11.16:389 -D "CN=hack,CN=Users,DC=redteam,DC=local" -w test123.. -b "DC=redteam,DC=local"
```

我们可以得知url前面需要`ldap://`，例如`http://www.baidu.com`

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-e3ac820e627562dd53bebbfc784cf3d25ea9d6b0.png)

这里通过`ldap_conn`来进行ldap的连接，我们来编写`ldap_conn`方法。  
DirectoryEntry类可封装 Active Directory 域服务层次结构中的节点或对象。

```php
string url = "LDAP://192.168.11.16/";
string username = "hack";
string password = "test123..";
DirectoryEntry coon = new DirectoryEntry(url,username, password);
```

我们使用了conn来获取节点列表，所以还需要一个来添加搜索条件。这里如下操作：

```php
DirectorySearcher search = new DirectorySearcher(coon);
```

关于`DirectoryEntry`和`DirectorySearcher`，please F1。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-2e720726fb2c5a26ebcfd63ad5e17f3eb20ccdd8.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-187a29b342307da33549b4fc90c9ff955a63a49d.png)

0x03 查询acl
==========

因为我们知道dcsync具有的acl是对根节点的。所以我们要选择查询哪里的acl，就要选择为他的path。例如我当前的测试环境为

```php
LDAP://192.168.111.16/DC=redteam,DC=local
```

每个环境结果不一样所以我们要先查询这个”后缀“。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-e82932e590490b7cff80c12dad7eb34c17423985.png)

看到属性为`distinguishedName`的值就存储了该结果，先定义一个方法为`GetdistinguishedName()`。

```php
public static string GetdistinguishedName()
{

    string Domain_DNS_Name = "";
    search.Filter = "(&(objectClass=domainDNS))";
    foreach (SearchResult r in search.FindAll())
    {
        string domainDNS_Name = "";
        domainDNS_Name = r.Properties["distinguishedName"][0].ToString();
        Domain_DNS_Name = domainDNS_Name;
    }
    return Domain_DNS_Name;
}
```

DirectorySearcher类存在一个Filter属性，该属性为搜索条件，`FindAll()`方法返回一个集合。  
得到该”后缀“，设置跟路径为

```php
string dcsync_user_path = domain + "/" + distinguishendName;
```

`DirectoryEntry.ObjectSecurity` 属性表示了该目录的安全说明符可以调用`GetAccessRules()`方法来返回一个集合，通过  
`foreach (ActiveDirectoryAccessRule rule in rules)`再调用`ToString()`方法来转换为字符串。  
复制目录更改和复制目录更改全部的guid分别为

```php
1131f6aa-9c07-11d1-f79f-00c04fc2dcd2
1131f6ad-9c07-11d1-f79f-00c04fc2dcd2
```

所以当acl为完全控制，或者同时满足上两条acl的即拥有dcsync权限。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-0e02f0327e299c95260d00f7380c8bbccda97fa2.png)

但是我们在域外有时候现实的不是用户名，而是用户的sid，所以我们再来编写`SidToUser()`方法。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-ce04991e47d8652e80b0aaea2fa0018c89d53c21.png)

在ldap数据库中可以通过如下方法来寻找一个用户

```php
LDAP://192.168.111.16/<SID=用户sid>
```

该sid可能代表了一个组或者一个用户或者某个机器用户。

```php
public static string SidToUser(string sid,string domain)
{
    try
    {
        string url = domain + "/<SID=" + sid + ">";
        coon.Path = url;
        search.Filter = "(&(objectClass=user)(objectCategory=person))";
        foreach (SearchResult r in search.FindAll())
        {
            string users = "";
            users = r.Properties["name"][0].ToString();
            if (users != "")
            {
                return users;
            }
        }
        search.Filter = "(&(objectClass=group))";
        foreach (SearchResult r in search.FindAll())
        {
            string groups = "";
            groups = r.Properties["name"][0].ToString();
            if (groups != "")
            {
                return groups;
            }
        }
        search.Filter = "(&(objectClass=computer))";
        foreach (SearchResult r in search.FindAll())
        {
            string computers = "";
            computers = r.Properties["name"][0].ToString();
            if (computers != "")
            {
                return computers;
            }
        }
    }
    catch
    {
    }
    return "error";
}
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-b5c3244bae74fc5c2be5d555be1d000242268781.png)

这里为什么会出现error。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-54e963392e3baa6966eed446d75cad55ce8cfa1b.png)

在域内以前存在过的用户(现在已经删除)，这里还是会显示他的sid，但是当带入ldap查询的时候是没有name等其他属性的所以会报错也就走到了我们的`return "error"`。所以我们判断如果为error就不打印。在判断是否拥有完全控制权限是完全可以通过打印的方式来输出，但是如何获取同时拥有两条acl的结果呢。这里我做出两个list，lista和listb，把拥有完全控制权限的添加到两个list中，然后两条acl分别添加到a和b，最后取a和b的交集。

这里为了方便直接通过`rule`来转换sid，写个`dcsync_return_username`方法

```php
public static string dcsync_return_username(ActiveDirectoryAccessRule rule,string domain)
{
    string username = "";
    string user_name = rule.IdentityReference.Value;
    if (user_name.Contains('-'))
    {
        username = SidToUser(user_name,domain);
    }
    else
    {
        username = user_name;
    }

    //如果用户被删除了，guid还是可以获取，但是sid转换为username的时候就会识别不出来，就会error，这里判断如果是识别失败返回的null的话就直接break
    if (username == "error")
    {
        return null;
    }
    return username;
}
```

所以同时满足两条acl的情况如下

```php
string user_name = "";
string guids = rule.ObjectType.ToString();
//string guids_extend = rule.InheritedObjectType.ToString();
switch (guids)
{
    case "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2":
        user_name = dcsync_return_username(rule,domain);
        if (user_name == null)
        {
            continue;
        }
        ACE_Changes.Add(user_name);
        break;
    case "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2":
        user_name = dcsync_return_username(rule,domain);
        if (user_name == null)
        {
            continue;
        }
        ACE_Changes_All.Add(user_name);
        break;
}
switch (guids_extend)
{
    case "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2":
        user_name = dcsync_return_username(rule,domain);
        if (user_name == null)
        {
            continue;
        }
        ACE_Changes.Add(user_name);
        break;
    case "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2":
        user_name = dcsync_return_username(rule,domain);
        if (user_name == null)
        {
            continue;
        }
        ACE_Changes_All.Add(user_name);
        break;
}
```

最后取出交集

```php
IEnumerable<string> dcsync_users1 = ACE_Changes.Intersect(ACE_Changes_All);
foreach (string dcsync_users in dcsync_users1)
{
    Console.WriteLine(dcsync_users);
}
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-42415d1454c8b9a6888d1dac3c414cfee4e8a826.png)