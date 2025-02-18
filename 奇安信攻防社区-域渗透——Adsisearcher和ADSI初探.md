Adsisearcher是什么？
================

很多情况下对于枚举AD对象大部分都是使用的PV(Powerview),但在每个Windows下都存在一个"内置"的Adsisearcher，注意内置，这意味着Adsisearcher自然存在于 Windows 环境中，无论它是什么，它都能够枚举 Active Directory。  
Adsisearcher是所谓的类型加速器，指向.NET类，通常指向==DirectoryServices.DirectorySearcher==类，除了Adsisearcher类型加速器，我们还会经常使用另一个类型加速器,即ADSI（指向==DirectoryServices.DirectoryEntry==），更多的类型加速器指向类请[参考](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_type_accelerators?view=powershell-7.1)  
Adsisearcher和ADSI（PowerShell不区分大小写）允许我们使用LDAP查询系统管理员常用的AD DS，这使它成为枚举AD环境的一个相当合适的操作。

ADSI 和 Adsisearcher有什么区别？
=========================

正如前面提到的，ADSI，Adsisearcher它们都是类型加速器，因此指向不同的类。我们可以使用Adsisearcher返回域中对象对应的 LDAP 查询以及该对象的一些信息，并获得域中的一般“lay of the land”。我们将使用ADSI查询更多详细信息使用来自Adsisearcher的LDAP查询的特定对象。  
下一步我们先使用两个命令

```powershell
$ExecutionContext.SessionState.LanguageMode  
# 默认模式是FullLanguage允许执行任何命令

Get-Host | select version
# 查看powershell版本
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-1eeae4fb729f9e775e3d8a666ea6b4345027f54e.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-1eeae4fb729f9e775e3d8a666ea6b4345027f54e.png)

使用 Adsisearcher 进行搜索
====================

首先，我们必须创建一个Adsisearcher对象,并验证它是否与 DirectorySearcher 类相同  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-3bf2dc35d866c289e15d58d1eeaca04a10cbdf83.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-3bf2dc35d866c289e15d58d1eeaca04a10cbdf83.png)  
可以看到类型一致，现在我们为Adsisearcher创建了对象，让我们看看我们得到了哪些信息  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-b4778ebd7cddc9a8441777b02773713a99509493.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-b4778ebd7cddc9a8441777b02773713a99509493.png)

在这些属性中，我们将主要关注`Filter`和`PropertiesToLoad`以及`SearchRoot`这三个属性，更多的可以阅读有关更多[属性的详解](https://docs.microsoft.com/en-us/dotnet/api/system.directoryservices.directorysearcher?view=net-5.0)  
`Filter`将允许我们使用[LDAP 过滤语法](https://docs.microsoft.com/en-us/windows/win32/adsi/search-filter-syntax)设置过滤器。`SearchRoot`可用于返回根域和查询基本信息，例如子域以及某些其他属性。我们将从Adsisearcher对象中使用的最后一个属性是`PropertiesToLoad`，它允许通过提供仅返回指定属性的选项来更精细地控制输出,如果为空，则返回所有属性。我们这里将重点关注`filter`属性。

SearchRoot
----------

`SearchRoot`属性可用于查询有关根域的数据，并告诉我们从何处开始搜索。从这个属性中，我们可以查询到根域的子对象、DC名称等信息，我们可以使用如下命令

```powershell
$test.SearchRoot
# 查询域名称、路径

$test.SearchRoot.dc
# 查询dc域

$test.SearchRoot.Children | select -first 10
# 查询前10个域成员
```

LDAP 筛选：Filter
--------------

我们可以使用`Filter`（Powershell不区分大小写，`filter`也可以做到这一点）来搜索域中具有特定属性的对象，例如`objectclass`并用`admincount`获取域中对象的信息。在实际处理`filter`属性之前要注意的一件事是有两种返回搜索结果的方法：返回搜索的第一个实例 ( `FindOne()`)，或返回搜索的每个实例`FindAll()`。这里的解决方法是使用`select`，它是 PowerShell `Select-String`cmdlet的别名。因此我们可以使用`objectclass`属性根据对象类过滤出域对象。我们可以使用如下命令

```powershell
$test.Filter = "(|objectclass=user)(objectclass=group))"
# 过滤对象属性为用户和组

$test.FindAll()
# 返回过滤
```

使用`admincount`属性将返回具有`admincount`过滤器中指定值的所有对象

```powershell
$test.Filter = "(admincount=1)"
# 过滤admincount为1

$test.FindAll()
# 返回过滤
```

PropertyToLoad
--------------

```powershell
$test.PropertyToLoad.Add("cn")
# 添加cn值

$test.PropertyToLoad.Add("admincount")
# 添加admincount值

$test.Filter = "(objectclass=user)"

$test.FindAll()
```

使用`PropertyToLoad`属性，我们可以通过告诉Adsiseacher我们不仅要返回过滤出`user`值的对象，而且只返回那些结果对象的`admincount`和`cn`值来进一步细化我们的搜索。

至此我们对Adsiseacher有了一个基本的了解，下面我们来看下ADSI。

ADSI
====

ADSI如前文所述，是一个类型加速器且指向`DirectoryEntry`属于`DirectoryServices`命名空间的类，ADSI 还用于指代管理员使用的 COM 对象集合集，用于与域环境中的任务交互并自动执行任务。更多信息请点击[此处](https://docs.microsoft.com/en-us/windows/win32/adsi/active-directory-service-interfaces-adsi)  
此类允许我们进行 LDAP 查询并检索有关域的更具体的数据。我们可以使用上文定义的==$test==来获取与特定用户对应的 LDAP 查询。  
我们可以创建一个指向用户的 ADSI 对象`abcd`,我们可以通过搜索用户的规范名称并返回`Path`属性来做到这一步。

```powershell
$test = new-object adsisearcher
# 创建adsisearcher对象

$test.Filter = "(cn=abcd)"
# 过滤值

($test.FindAll()).Path
# 返回路径

$ADSI = [ADSI]($test.FindAll()).Path

$ADSI
# 返回ADSI查询结果
```

更多的，我们可以只查看具体某一值，例如

```powershell
$ADSI.cn
$ADSI.memberOf
$ADSI.objectCategory
$ADSI.objectClass
$ADSI.Parent
```

使用ADSI和Adsisearcher进行域枚举
========================

成员信息收集
------

假如当前有一个域ceshi，并且执行完命令

```powershell
whoami /groups | findstr ceshi
```

发现有一个成员admintest,那么我们可以使用Adsisearcher挖掘这个成员的信息，我们可以这样

```shell
$test.Filter = "(cn=admintest)"

$test.FindAll()

($test.FindAll()).Properties
```

上面的方法可以快速返回此成员的信息，同时拼接其他值，我们可以快速获得某一信息。

通用域枚举
-----

### 快速列举其他的组和用户

```powershell
$test.Filter = "(&(objectclass=user)(givenname=*))"
$test.Filter = "(&(samaccounttype=268435456))"
```

### 列举SqlServer 服务器

```powershell
$test.Filter = "(&(cn=MSSQL*))"
```

### 查询密码信息

```powershell
$ADSI = [ADSI]"LDAP://DC=ceshi,DC=local"
$ADSI | Format-List *pwd*,*lockout*
```

### 参考资料

<https://devblogs.microsoft.com/scripting/use-the-powershell-adsisearcher-type-accelerator-to-search-active-directory/>  
<https://www.alkanesolutions.co.uk/2021/03/03/search-active-directory-using-adsisearcher-filters/>