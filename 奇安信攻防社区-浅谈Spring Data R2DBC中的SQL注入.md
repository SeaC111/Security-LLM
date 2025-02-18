0x00 关于Spring Data R2DBC
========================

 Spring Data R2DBC 是 Spring Framework 的一部分，它提供了一种简化和抽象化与关系型数据库进行交互的方式。它是基于响应式编程模型的数据库访问框架，旨在与 R2DBC（Reactive Relational Database Connectivity）兼容。

 Spring Data R2DBC目前支持以下数据库：

- H2 (io.r2dbc:r2dbc-h2)
- MariaDB (org.mariadb:r2dbc-mariadb)
- Microsoft SQL Server (io.r2dbc:r2dbc-mssql)
- MySQL (dev.miku:r2dbc-mysql)
- jasync-sql MySQL (com.github.jasync-sql:jasync-r2dbc-mysql)
- Postgres (io.r2dbc:r2dbc-postgresql)
- Oracle (com.oracle.database.r2dbc:oracle-r2dbc)

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-be8ad7bc26f50b3898ef2e6d3b59be7dc1c99e8f.png)

0x01 常见交互方式
===========

 Spring Data R2DBC 中主要提供了以下几种常见的数据库交互方式。

1.1 DatabaseClient
------------------

 DatabaseClient是 Spring Data R2DBC 提供的一个API，用于执行数据库操作。可以执行原始的 SQL 查询、插入、更新和删除操作，并支持异步和反应式的方式。（**可以通过使用 execute() 方法执行原生的 SQL 语句，可以执行复杂的查询或执行数据库特定的操作**）

 例如下面的例子：

 通过预编译的方式查询传入的id：

```Java
@Override
public Mono<UserEntity> findById(final UUID id) {
    return databaseClient.execute("SELECT * FROM app.user WHERE id = :id")
            .bind("id", id)
            .map(this::convert)
            .one()
            .switchIfEmpty(Mono.error(new NotFoundException("User id \"" + id.toString() + "\"not found")));
}
```

1.2 R2dbcEntityTemplate
-----------------------

 R2dbcEntityTemplate 与传统的 JdbcTemplate 类似，但针对 R2DBC 进行了优化和扩展。它的设计目标是通过简单且直观的 API 提供对数据库的访问，并提供异步和反应式的支持。其中提供了一些便利的方法，如根据条件查询、分页查询、排序等。（内部实际上是使用 `DatabaseClient` 进行处理的）

 举个例子：

 Controller定义如下，这里实现的是一个排序的功能：

```Java
@GetMapping("/slice")
public Flux<ProvinceEntity> findAllAsSlice(String sort,int page,int size) {
    final Pageable pageable = SliceRequest.of(
            page,
            size,
            Sort.by(Sort.Order.by(sort).with(Sort.Direction.ASC))
    );
    return provinceRepository.findAllAsSlice(Query.empty(), pageable);
}
```

 主要service实现在provinceRepository的findAllAsSlice方法，这里使用了Spring Data R2DBC中的R2dbcEntityTemplate来查询数据库中的数据：

```Java
@Override
public Flux<ProvinceEntity> findAllAsSlice(final Query query, final Pageable pageable) {
    final Query q = query
            .offset(pageable.getOffset())
            .limit(pageable.getPageSize())
            .sort(pageable.getSort());
    return r2dbcEntityTemplate.select(ProvinceEntity.class).matching(q).all();
}
```

 **PS：高版本的 Spring Data R2DBC 中，R2dbcEntityTemplate类已被移除。从 Spring Data R2DBC 1.2 版本开始，官方不再推荐使用 R2dbcEntityTemplate。**

1.3 R2DBC Repository
--------------------

 Spring-data-r2dbc也实现了spring data repository的反应式API。主要是以下几个：

- **ReactiveCrudRepository**

 ReactiveCrudRepository 是 Spring Data R2DBC 的基础接口，提供了常见的增删改查操作，包括保存实体、更新实体、删除实体和查询实体等。它定义了一组基本的 CRUD 操作方法，可以根据实体的类型进行操作。

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-91ce884da549c070bfc9bd3410400e3d8072a5d7.png)

- **ReactiveSortingRepository**

 ReactiveSortingRepository 继承自 ReactiveCrudRepository，除了提供了基本的 CRUD 操作外，还额外支持了排序功能。其扩展了 ReactiveCrudRepository，使得在进行查询操作时可以更方便地指定排序条件。

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-b7874bbe6ff51881bbec62e1df1d0443036a3fbc.png)

- **R2dbcRepository**

 跟前面两者类似，其继承自ReactiveSortingRepository，继承了其定义的常用的CRUD操作方法，如保存、更新、删除和查询实体等还有排序等方法：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-9b74b18c7197c65fbe642458209c52d9a4a86166.png)

 下面看一个实际的例子：

 定义UserRepository接口继承ReactiveSortingRepository，包含了基本的CRUD操作方法。

```Java
public interface UserRepository extends ReactiveSortingRepository<UserEntity, UUID> {

}
```

 此时在Controller进行相关的调用即可，例如通过主键进行查询：

```Java
@GetMapping("/{id}")
public Mono<UserEntity> findById(@PathVariable("id") final UUID id) {
    return userRepository.findById(id)
            .switchIfEmpty(Mono.error(new NotFoundException("User id \"" + id.toString() + "\"not found")));
}
```

 具体效果：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-f6cdc12aa473bf7ea4bae8eec90428fdbde5d768.png)

 除此之外，Repository还支持基于方法名的查询，通过方法名的约定即可根据属性名自动生成查询。

 举个例子：

 findByUsername方法会自动生成根据username属性查询单个UserEntity实体的查询：

```Java
public interface UserRepository extends ReactiveSortingRepository<UserEntity, UUID> {

    Mono<UserEntity> findByUsername(String username);
}
```

 具体效果：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-377be741398441f2d41a3d244470e14ac97f2f59.png)

 用法也比较灵活，例如还可以可以使用关键字进行排序，就不一一介绍了。

```Java
public interface UserRepository extends R2dbcRepository<User, Long> {
    Flux<User> findByAgeGreaterThanOrderByLastNameDesc(int age);
}
```

1.4 @Query自定义查询
---------------

 除了前面介绍的以外，还可以通过在方法上使用`@Query`注解，可以定义自定义的SQL查询，提供灵活的查询能力。看一个实际的例子：

 以模糊查询为例，在查询语句中使用了占位符`:keyword`来表示模糊查询的关键字。通过在查询方法中传递关键字参数，例如`findByKeyword("John")`，将会执行类似于`SELECT * FROM app.user WHERE username LIKE '%John%'`的查询，返回满足模糊查询条件的结果集：

```Java
public interface UserRepository extends ReactiveSortingRepository<UserEntity, UUID> {
    @Query("SELECT * FROM app.user WHERE username LIKE '%' || :keyword || '%'")
    Flux<UserEntity> findByKeyword(String keyword);
}
```

 在Controller调用具体的方法即可模糊查询username：

```Java
@GetMapping("/findByKeyWord/{keyword}")
public Flux<UserEntity> findByKeyWord(@PathVariable("keyword") final String keyword) {
    return userRepository.findByKeyword(keyword)
            .switchIfEmpty(Mono.error(new NotFoundException("User not found")));
}
```

 具体效果：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-e7e5ad4f90091ef84d6d9c202a487444ba83400d.png)

0x02 常见SQL注入场景
==============

 上述交互方式中，在大部分场景已经进行了预编译处理，但是对于很多特殊的情况还可能存在SQL注入的风险，下面列举一些场景的场景：

2.1 Order by排序
--------------

 在Spring Data R2DBC中，一般会通过org.springframework.data.domain.Sort来定义排序规则。其提供了多种创建排序规则的方法，包括按照单个属性升序或降序排序，以及按照多个属性的组合排序。可以将 Sort对象传递给查询方法，以在查询结果中应用所需的排序。例如ReactiveSortingRepository中也是通过Sort对象来实现排序的：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-771dab0f403895d4f7d0c99b213b53500753951d.png)

 而org.springframework.data.domain.Sort的构造方法是私有的：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-fa45f146e3057ef9ebd8e6870e3dd787c8fb300d.png)

 所以一般情况下会通过`Sort.by()`的方式进行调用，例如下面的例子：

```Java
Sort sort = Sort.by(Sort.Direction.ASC, "propertyName");
Sort sort = Sort.by("propertyName").ascending();
```

 在Sort对象中，决定升序降序的字段是enum类型的，所以**一般情况下SQL注入主要存在排序的字段名处**：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-3a16a7019088c82c0eab6093c2097ad6e218d730.png)

 PS：org.springframework.data.domain.Pageable 是 Spring Data 提供的一个用于进行分页查询的接口。它用于表示分页的相关信息，包括页码、每页的数据量以及排序规则。其也是通过操作Sort对象进行排序的：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-a31d32103f1f317b4b0109bd0df404cf974f9c21.png)

### 2.1.1 已有的安全措施

 当使用Repository时，可以通过传入一个Sort对象来指定排序规则，例如下面的例子：

```Java
public interface UserRepository extends ReactiveSortingRepository<UserEntity, UUID> {
    Mono<UserEntity> findByUsername(String username, Sort sort);
}
```

 然后在Controller里封装Sort对象即可完成基于字段名的排序：

```Java
@GetMapping("/findByUserName")
public Mono<UserEntity> findByUsername(@RequestParam("username") final String username,@RequestParam("fieldName") final String fieldName) {
    Sort sort = Sort.by(fieldName);
    return userRepository.findByUsername(username,sort)
            .switchIfEmpty(Mono.error(new NotFoundException("UserName\"" + username + "\"not found")));
}
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-4a9b40020b390c1dffc24edffdd86b61eecf5ca1.png)

 而当使用实体不存在的字段尝试封装Sort对象进行处理时，在解析时会抛出对应的异常：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-bafe8685a3400a2ae2259c33a3b3d64e353944b4.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-7a4c63d1c9f0a0c81dd3cbbbe4592b84ee349d27.png)

 R2dbcQueryCreator Spring Data R2DBC 内部使用的组件，开发者可以通过使用 Spring Data R2DBC 提供的高级抽象接口（如 ReactiveCrudRepository 和 R2dbcRepository）或自定义的查询方法，间接地利用 R2dbcQueryCreator 来执行数据库查询操作。

 R2dbcQueryCreator主要负责以下任务：

- 解析方法上的查询注解，如@Query注解，获取查询语句和参数绑定信息。
- 解析方法参数，根据参数的类型和注解等信息，将参数值与查询语句进行绑定。
- 构建一个SelectSpec对象，设置查询语句、参数绑定和返回类型等信息，用于执行数据库查询操作。

 其中select 方法的作用是构建一个 SelectSpec 对象，该对象代表了一个可以执行的查询操作。如果是排序的话，会调用getSort方法进行进一步的处理：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-8ca802e9a95a788892461c3a6d123a7c65d3ba9e.png)

 查看getSort方法的具体实现：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-04c1e7922cb3c2a2ffe1c455d62994564566f08d.png)

 在org.springframework.data.mapping.PersistentEntity#getRequiredPersistentProperty方法中，会校验排序的字段所属关系，如果获取不到该字段的话会抛出异常，类似白名单的作用，从一定程度上防止了SQL注入的产生：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-8702a61b14e842913792376deecc22396a462668.png)

### 2.1.2 SQL注入案例

 除去上述的场景，某些情况下还是会存在SQL注入风险的，这些方法是预定义的方法，它们通过内部实现来处理排序逻辑，而不是通过 `R2dbcQueryCreator` 来解析和执行查询，具体的判断逻辑在org.springframework.data.repository.core.support.QueryExecutorMethodInterceptor#hasQueryFor方法：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-37e6888f3094b6cbcb918162a9355340b42bc57a.png)

 this.queries中存储的都是自定义的查询方法：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-6068029e7bf217b0134c432c7fa4f21a87b490ac.png)

 以ReactiveSortingRepository的findAll查询为例，其是预定义而非用户自己定义的：

```Java
public interface UserRepository extends ReactiveSortingRepository<UserEntity, UUID> {

}
```

```Java
@GetMapping("/findAll")
public Flux<UserEntity> findAllBySort(@RequestParam("sortType") final String sortType) {
    Sort sort = Sort.by(sortType).ascending();
    return userRepository.findAll(sort);
}
```

 正常情况下以id查询返回正常：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-7a5bab1a38c758a6171b7b685093f42f77aa0636.png)

 以1/0进行排序返回异常：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-10a6d5cddb6cd357e00bae223df94bb83abfb396.png)

 查看对应的报错可以看到1/0执行成功，证明SQL注入存在：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-6f36a86764102983edda4ab4a2369c6d25eceede.png)

 同理，使用r2dbcEntityTemplate也存在类似的问题：

```Java
@Override
public Flux<ProvinceEntity> findAllAsSlice(final Query query, final Pageable pageable) {
    final Query q = query
            .offset(pageable.getOffset())
            .limit(pageable.getPageSize())
            .sort(pageable.getSort());
    return r2dbcEntityTemplate.select(ProvinceEntity.class).matching(q).all();
}
```

### 2.1.3 其他

 此外，对于3.1.1版本，还提供了SqlSort对象（Sort.Order的一个子类，用于SQL排序的扩展）进行对应安全检查：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-c48d92498357ba9cfb0761c81fd3c9d52b003822.png)

 查看具体的validate方法，可以看到限制了排序字段只能包含数字、字母、'.'、'\_'和''字符，否则会抛出异常：

```Java
/**
     * Validates a {@link org.springframework.data.domain.Sort.Order}, to be either safe for use in SQL or to be
     * explicitely marked unsafe.
     * 
     * @param order the {@link org.springframework.data.domain.Sort.Order} to validate. Must not be null.
     */
    public static void validate(Sort.Order order) {

        String property = order.getProperty();
        boolean isMarkedUnsafe = order instanceof SqlSort.SqlOrder ro && ro.isUnsafe();
        if (isMarkedUnsafe) {
            return;
        }

        if (!predicate.test(property)) {
            throw new IllegalArgumentException(
                    "order fields that are not marked as unsafe must only consist of digits, letter, '.', '_', and '\'. If you want to sort by arbitrary expressions please use RelationalSort.unsafe. Note that such expressions become part of SQL statements and therefore need to be sanatized to prevent SQL injection attacks.");
        }
    }
```

 具体的issue:<https://github.com/spring-projects/spring-data-relational/issues/1507>

2.2 DatabaseClient动态拼接sql语句
---------------------------

 前面提到，在DatabaseClient中，可以通过**使用 execute() 方法执行原生的 SQL 语句**，可以执行复杂的查询或执行数据库特定的操作）。那么此时如果使用不当，会存在SQL注入的风险。

### 2.2.1 预编译方式

 一般情况下可以通过预编译的方式防止SQL注入，DatabaseClient同样提供了自己的方式来处理预编译的语句。主要是以下两种方式：

- 基于命名的占位符

 :id 表示一个具有特定名称的参数。可以在 SQL 查询语句中使用 :id 来表示占位符的名称。通过 bind("id", value) 方法将具体的参数值绑定到 :id 占位符上：

```Java
@Override
public Mono<ProvinceEntity> findById(UUID id) {
    return databaseClient.execute("SELECT app.province.* FROM app.province WHERE id = :id")
            .bind("id", id)
            .map(this::convert)
            .one()
            .switchIfEmpty(Mono.error(new NotFoundException("Province id \"" + id.toString() + "\"not found")));
}
```

- 基于位置的占位符

 $1 表示第一个参数。可以在 SQL 查询语句中使用 $1 来表示占位符的位置。通过 bind("$1", value) 方法将具体的参数值绑定到 $1 占位符上：

```Java
@Override
public Mono<ProvinceEntity> findById(UUID id) {
    return databaseClient.execute("SELECT app.province.* FROM app.province WHERE id = $1")
            .bind("$1", id)
            .map(this::convert)
            .one()
            .switchIfEmpty(Mono.error(new NotFoundException("Province id \"" + id.toString() + "\"not found")));
}
```

 通过上述的两种方式能在DatabaseClient实现预编译处理，并将具体的参数值安全地绑定到 SQL 查询语句中，避免了 SQL 注入的风险。

### 2.2.2 SQL注入案例

 而动态 SQL 查询由于其灵活性和可变性，往往无法在编译时确定完整的 SQL 查询语句和参数。例如Orderby排序、动态表名等。此时需要额外对相应的参数进行额外的安全检查，避免SQL注入风险。

 以Orderby排序为例，对应的SQL调用如下,这里sort是直接进行SQL拼接的，同时没有经过任何的安全检查，若用户可控的话会存在SQL注入的风险：

```Java
@Override
public Flux<ProvinceEntity> findAll(String sort) {
    return databaseClient.execute("SELECT app.province.* FROM app.province Order by "+sort).map(this::convert).all();
}
```

 假设数据库是Postgresql，以1/1排序时正常返回：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-04bbbc2cc70bb49e730282d2998ea61e4c22a104.png)

 以1/0排序时触发异常，返回500状态码，证明SQL注入存在：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-f173eed2c1cadc6c3c758e04148ef8e00c18a478.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-91da786cabc6f4a9d93a0b4bb0ada73eaf2b3ea8.png)

 正确的做法应该是，如果在动态 SQL 查询中，若无法使用参数化查询或预编译处理来保护查询的安全性，应该在拼接 SQL 之前，对输入的参数进行验证和过滤，确保只允许合法的值。可以使用正则表达式、白名单或其他验证机制来检查输入数据的合法性。

0x03 其他
=======

 前面提到Spring Data R2DBC存在@Query注解，实际上还支持SpEL表达式。但是在解析时传入的位置并不是expression，而是content。所以不存在类似CVE-2022-22980 Spring Data MongoDB SpEL 表达式注入的风险。