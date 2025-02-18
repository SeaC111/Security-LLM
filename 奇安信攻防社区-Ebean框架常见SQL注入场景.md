0x01 关于Ebean
============

 Ebean ORM框架，可以说几乎支持所有的JPA的功能同时也兼顾了Mybatis的灵活性，并且还有一些较实用的增加功能。同时兼容多种数据库，可以很方便的实现对应的sql操作，在一定程度上对SQL注入也有一定的防护。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-1b5a060bb355b0b80a453e399d17fde45509418b.png)

1.1 Ebean基本使用方法
---------------

### 1.1.1 实体类继承Model类，自带增删改方法

 例如新增记录：

```Java
Author author = new Author(null, "Lorin", "Lorin");
author.save();
```

### 1.1.2 Ebean/EbeanServer&amp;DB/database

 可以使用Ebean或 EbeanServer 来创建和执行查询。高版本已经弃用，会迁移到io.ebean.Database/io.bean.DB:

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-a7bb2d79c9e23bfc1540b949445f6f8b2fa4a466.png)

### 1.1.3 Q实体增强类

 Ebean可以对对应的entity生成出”Q实体类“，比如Author就会生成出QAuthor类，相比于普通实体类，QAuthor类的功能更强大，而且相比于普通实体类，QAuthor类的增删改有返回值，可以用来判断操作是否成功，普通实体类的增删改没有返回值。

 例如查询id=1的内容：

```Java
QAuthor().id.eq(1).findOne();
```

1.2 常见参数绑定方式
------------

### 1.2.1 ?和:param

 跟其他框架类似，均支持?和:param的方式进行参数绑定。

 类似SqlQuery可以直接执行自定义SQL，可以通过setParameter()方法进行参数绑定（多参数时可以使用setParameters()方法）。

```java
Ebean.createSqlQuery(sql).setParameter(1,name).findList();
```

 查看具体的SQL日志，name参数已经进行预编译处理：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-026ce8cf7e9750b4412146cebe97895d0b4c5ef4.png)

 使用:param同理。

### 1.2.2 表达式自身处理

 Ebean提供的表达式已经进行了相应的预编译处理，使用也比较方便，例如这里的eq，查询对应name的用户信息：

```java
server.find(Content.class).where().eq("name",sort).findList();
```

 查看对应的日志已经进行了参数绑定：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-29f675943549d249ef471eaff22a83a59a7c8c67.png)

0x02 常见SQL注入场景
==============

2.1 OrderBy排序
-------------

 因为OrderBy场景下是没办法进行预编译处理的，跟所有常见的orm框架一样，如果没有做相应的处理的话是存在SQL注入风险的。

 常见的接口有：

- io.ebean.OrderBy
    
    
    - Query asc(String propertyName)
    - Query desc(String propertyName)
- io.ebean.Query
    
    
    - Query order(String var1);
- io.ebean.ExpressionList;
    
    
    - Query orderBy(String var1);

 举个例子，例如下面的SQL，通过用户传入的sort参数进行排序，因为是直接SQL拼接的，会存在SQL注入风险：

```Java
server.find(Content.class).order(sort).findList();
```

 这里尝试报错注入，成功获取到数据库用户SA（数据库是H2 database）

![1280X1280 (1).PNG](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-73041d2192b4cdb24e5060bdbbb97158cb9b8a04.png)

2.2 执行任意 SQL、函数和存储过程
--------------------

 在查询where子句中经常需要包含执行任意SQL、函数和存储过程的需求。因为这里存在大量的自定义sql场景，如果直接拼接的话会存在SQL注入的风险，所以在审计时可以重点关注，下面列举一些常见的function：

- Raw expressions  
     Raw表达式允许在查询的where子句中使用对应数据库的函数或表达式。例如： ```java
    .raw("add_days(orderDate, 10) &lt; ?", someDate)
    ```
    
     这里使用?进行预编译处理了，如果直接进行SQL拼接的话会存在注入风险。

 rawOrEmpty()同理。

2.3 执行自定义SQL
------------

 由于实际业务比较复杂，常规的function并不能很好的完成业务需要，同样的Ebean也提供了很多自定义SQL的方法：

### 2.3.1 获取java.sql.Connection对象执行原始SQL

 java.sql.Connection对象可以从事务中返回，此时就可以直接调用对应的方法执行任意的sql，同样的如果使用不当存在sql拼接的话也会存在SQL注入的风险：

```Java
try (Transaction transaction = server.beginTransaction()) {

    Connection connection = transaction.getConnection();
    // use raw JDBC
    Statement stmt = connection .prepareStatement(sql);
    ......
    transaction.commit();
} catch (SQLException throwables) {
    throwables.printStackTrace();
}
```

### 2.3.2 Ebean常见API

通过下面的api可以直接生成对应的sql进行执行，如果相关的参数没有经过过滤或者类似?和:param预编译处理，**直接进行拼接**的话，是存在SQL注入风险的。

- createSqlQuery(String sql)
- sqlQuery(String var1);
- sqlUpdate(String var1);
- createCallableSql(String var1);
- createSqlUpdate(String sql)
- findNative(Class\\ var1,String var2)
- ......

 例如如下例子,这里通过?进行预编译处理，然后再通过setParameter进行赋值，避免了SQL注入的风险：

```java
String sql= "select id,name f rom customer where name like ?";
Customer customer = DB.findNative(Customer.class, sql)
    .setParameter("Jo%")
    .findOne();
```

 如果直接使用字符串拼接的话（尤其是类似orderby排序、动态表名等场景），如果没有经过相关的过滤，会存在SQL注入的风险，在审计时可以重点关注下。

### 2.3.2 RawSqlBuilder

 一般来说可以通过RawSql显式指定要执行的SQL语句，并将列显式映射到对应的属性。但是使用不当也会出现SQL注入的风险。

 例如如下例子，通过用户输入的query进行sql拼接，会存在sql注入的风险：

```java
public static List search(String query) {
    List matches = new ArrayList();
    try {

        String sql =    "SELECT  v.id, c.company, c.postcode \n" +
                        "F ROM    venue v \n" +
                        "JOIN    contact c ON (c.id = v.id) \n" +
                        "WHERE   REPLACE(c.postcode, ' ', '') LIKE '%" + q + "%' \n" +
                        "    OR  c.company LIKE '%" + query + "%'";

        RawSql rawSql = RawSqlBuilder.unparsed(sql)
            .columnMapping("v.id", "id")
            .columnMapping("c.company", "contact.company")
            .columnMapping("c.postcode", "contact.postcode")
            .create();

        Query eQ = Ebean.find(Venue.class);

        eQ.setRawSql(rawSql);

        matches = eQ.findList();
    }
    catch (Exception e) {
        Utils.eHandler("Venue.search(" + query + ")", e);
    }
    finally {
        return matches;
    }
}
```

 正确的做饭还是需要通过?或者param:进行预编译处理，然后再通过setParameter进行赋值。

2.4 动态列名
--------

 在列名查询时，可能会需要用到相关的sql函数，例如将数据库表中的姓和名拼接起来,Ebean中对应的select表达式是满足这个需求的。

 举个例子，这里直接从用户传递的参数传入column进行查询，但是实际上存在sql拼接是有SQL注入风险的：

```Java
Content.find.query().select(sort).findSingleAttributeList();
```

 这里尝试报错注入，成功获取到数据库用户SA（数据库是H2 database）：  
![1280X1280.PNG](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-6688a371ccf40b523699552eb99aa1e701ed35b4.png)

0x03 其他
=======

 上述场景中绝大部分是因为方法使用不当导致注入，可以通过param:或者?进行预编译的方式来避免，类似Orderby排序、动态拼接的场景，可以参考如下方法进行安全加固：

1. **在代码层使用白名单验证方式，如设置表名白名单，如果输入不再白名单范围内则设置为一个默认值如user；**
2. **在代码层使用间接引用方式，如限制用户输入只能为数字1、2,当输入1时映射到user，为2时映射到product，其他情况均映射到一个默认值例如product；**
3. **使用sdk对用户输入进行安全检查。**

0x04 参考资料
=========

<https://ebean.io/docs/>