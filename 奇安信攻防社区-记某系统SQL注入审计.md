记某系统SQL注入审计
===========

0x00 简介
-------

在复现jeecg历史漏洞时发现了一基于jeecg框架仓库系统，故在此记录一下审计过程。

0x01 路由
-------

查看`src/main/webapp/WEB-INF/web.xml`文件看到提供了三种路由形式`.do`、`.action`和`/rest/`  
![](https://shs3.b.qianxin.com/butian_public/f40972930bfbd7fb03dc0397ebe0373d76b0941db9125.jpg)

0x02 鉴权
-------

### Filter

这里没有用于权限认证Filter  
![](https://shs3.b.qianxin.com/butian_public/f293377ebb915dbb85dac1be5297b4a7090af09df0fcb.jpg)

### Interceptors

查看`/src/main/resources/spring-mvc.xml`  
![](https://shs3.b.qianxin.com/butian_public/f6870161fd6acf8cf98c970bbc55074ba6b31d7fe3fbe.jpg)  
可以看到定义了四个interceptor

#### 1. EncodingInterceptor

主要是设置请求包和响应包的编码格式  
![](https://shs3.b.qianxin.com/butian_public/f829686736ca5e4d6defa31580859bc6c1fd94022d9bf.jpg)

#### 2. SignInterceptor

跟进方法，发现注释掉了原有处理流程直接返回`true`  
![](https://shs3.b.qianxin.com/butian_public/f99373511825ca0fe7d94f4e977ede9118f55939fbdf6.jpg)

#### 3. AuthInterceptor

该拦截器的mapping为`/**`,即处理所有请求，根进到具体实现  
![](https://shs3.b.qianxin.com/butian_public/f76225358cae756bbf8b4a413a3efd05bebf6212265e1.jpg)

#### 4. WmsApiInterceptor

该拦截器的mapping也为`/**`，查看具体实现  
![](https://shs3.b.qianxin.com/butian_public/f2851405f70d561f0833fe42f9ab9e1e9f622a67631cf.jpg)

0x03 权限绕过
---------

我们通过上述分析，发现处理鉴权操作的仅是`AuthInterceptor`和`WmsApiInterceptor`两个类。  
**首先我们来分析`AuthInterceptor`类**：  
在`spring-mvc.xml`中，对`AuthInterceptor`类的`excludeUrls`和`excludeContainUrls`两个成员变量做了初始化：  
![](https://shs3.b.qianxin.com/butian_public/f1834123fc410add3ba513ceb5215c285ae933175da7b.jpg)  
我们来到`AuthInterceptor`类鉴权方法`preHandle`的具体实现：  
![](https://shs3.b.qianxin.com/butian_public/f74511779d7710be4a5a41c8b47e769453c09eb66d113.jpg)  
可以看到当url中包含`rest/`或者`excludeUrls`和`excludeContainUrls`数组里的字符串时直接返回true放行请求。  
正常访问后台接口返回302：  
![](https://shs3.b.qianxin.com/butian_public/f170526362a053e659a2c531f90978b60522b2b6912f3.jpg)  
我们可以用`rest/`和`wmOmNoticeHController.do`来bypass：  
![](https://shs3.b.qianxin.com/butian_public/f2079535c9ce7c38f59258b7150e6eff73aa6653abfc1.jpg)  
![](https://shs3.b.qianxin.com/butian_public/f69952365083a476bace8e4b8b27a1b5611137f741140.jpg)

**`WmsApiInterceptor`类**：  
跟进到`prehandle`方法实现：  
![](https://shs3.b.qianxin.com/butian_public/f72329593e61298f68f2853131dbf07315b008b8d1039.jpg)  
当请求url在containUrls列表中时进入if处理逻辑：  
1.获取header中`Authorization`的值  
2.利用`jwtUtils`解析`Authorization`  
3.当解析后的值等于`wmsAccount`时放行  
而`JwtUtils`硬编码了jwt密钥  
![](https://shs3.b.qianxin.com/butian_public/f1347103e853bd013bf64c7ed92a7a2312da1d5fbc5a2.jpg)  
我们可以利用密钥自己构造`Authorization`为`wmsAccount`来bypass，这里就不赘述了。

0x04 SQL注入
----------

根据README和pom.xml发现其是使用`Hibernat`框架进行sql。我们可以通过搜索Hql相关查询语法，如:`session.createQuery`,`Restrictions.sqlRestriction`等关键字，或是对有关数据查询等功能点抓包找到接口具体实现跟进。  
这里我们通过关键字搜索到了HQL实现类`src/main/java/xx/xx/xx/extend/hqlsearch/HqlGenerateUtil`,其中`installHql`方法调用了`Restrictions.sqlRestriction()`进行查询。  
![](https://shs3.b.qianxin.com/butian_public/f9377574d768d0dfe7982ce9729f61f00f05a413ebbe4.jpg)  
方法主要获取`sqlbuilder`参数的值（数据结构为json）进行sql查询。搜索其用例发现在用户查询功能处调用了其方法  
![](https://shs3.b.qianxin.com/butian_public/f9752514f7b62f72a0d55186eaae0de6276661f486029.jpg)  
于是我们对其功能点进行抓包  
![](https://shs3.b.qianxin.com/butian_public/f64361285ac54efb6b37c488b234feda5aea38e1e534b.jpg)  
发现传参中存在`sqlbuilder`,不过前端代码`sqlbuilder`被隐藏掉了。  
![](https://shs3.b.qianxin.com/butian_public/f4156906a6d9f1048eb1f0deefce16442c0e1a4d7fc08.jpg)  
于是我们再看`HqlGenerateUtil:installHql()`的实现，其中获取到`sqlbuilder`的值后通过`JSONHelper:toList()`转化成`QueryCondition`类型对象存入列表中。而`QueryCondition`类有如下成员变量：  
![](https://shs3.b.qianxin.com/butian_public/f7677097de721cd7fdf40bcdc6cebec45c3d1607708db.jpg)  
随后通过getSql()方法将遍历list和searchObj两对象的成员变量拼接成最终查询的SQL字符串。下面是getSsql方法的实现。  
![](https://shs3.b.qianxin.com/butian_public/f1430650f6b1936d015edb2a5ffbd530d43f7f7c79ca8.jpg)  
当执行到`sb.append(tab+c)`时会调用`QueryCondition`类的`toString`方法：  
![](https://shs3.b.qianxin.com/butian_public/f61287163537b8b10f1f4389e47976bc077496ec581e3.jpg)  
可以看到其对QueryCondition的成员变量进行拼接最后根据this.type的值确定this.value的拼接方式。  
于是我们构造payload为

```php
sqlbuilder=[{"field":"createName","type":"string","condition":"is not null and user() like '%25r%25' and '1' like ","value":"%251%25","relation":"and"}]
```

最终的SQL字符串为

```php
 1=1 and create_name is not null and user() like '%r%' and '1' like  '%1%'
```

![](https://shs3.b.qianxin.com/butian_public/f480166878fb40487d5c8e22bfa1c61c4cd186f3fa252.jpg)  
最后配合前面的权限绕过可达到未授权SQL注入  
![](https://shs3.b.qianxin.com/butian_public/f27588432694fc2798a98146b6feb8b14cac4807c949e.jpg)

![bp3.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-7b43e3f5daa68da2f41ae22d74bcd1326b0461f5.png)