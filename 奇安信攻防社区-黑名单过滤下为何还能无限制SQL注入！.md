0x01 前言
-------

这周看到了某公众号发的springboot+vue实现的一个后台管理系统。阅读量还挺高的，就下了一下源码翻一翻，发现里边漏洞还挺多的。尤其是SQL方面，作者虽然做了过滤但还是因为配置不当的导致SQL注入。

![1](https://shs3.b.qianxin.com/attack_forum/2024/04/attach-0e5e370a893a525e8194fc2d758e7b086adef6f5.png)

后边经过作者的同意，然后把本次代码审计的思路放出来和大家分享一下

![2](https://shs3.b.qianxin.com/attack_forum/2024/04/attach-9bd2afdfc8d204a25c264497b0c59b234515e6ad.png)

0x02 SQL注入
----------

mybatis-plus对绝大部分场景进行了预编译处理。但是类似动态表名、orderby这种需要拼接的场景配置不当还是会存在漏洞。本次就是记录一下在代码审计中遇到的一个奇怪的SQL注入，在对请求参数进行黑名单过滤十分严格的情况，代码逻辑不当导致SQL注入！

### 分页SQL注入分析

翻了一下pom.xml文件，发现该项目持久层使用的是Mybatis-puls框架！

![image-20240403021320315](https://shs3.b.qianxin.com/attack_forum/2024/04/attach-3ec16f686e19c50c3aed3322c7f04e03fe7ea1e1.png)

我对mybatis-plus的理解就是封装了一些sql以减少代码量，其对绝大部分场景进行了预编译处理。但是类似动态表名、orderby这种需要拼接的场景配置不当还是会存在漏洞。

在翻工具类时发现该项目有对sql注入进行过滤

![image-20240403025212716](https://shs3.b.qianxin.com/attack_forum/2024/04/attach-36e3b6fba42eb82a140b77741523187049cd8331.png)

那就跟进去看看在哪里做了过滤，只在`com.utils.Query#Query`中有4处调用

![image-20240411115923581](https://shs3.b.qianxin.com/attack_forum/2024/04/attach-0903ffbf5f94ee48b9e32c3c59da6937f35783e9.png)

跟进`com.utils.Query#Query`看看，发现**该类具有两个重载的构造方法**，接收的参数类型不同

- **JQPageInfo**：封装了分页参数的实体类
- **Map&lt;String, Object&gt; params**：集合类型的params参数

![image-20240411120600013](https://shs3.b.qianxin.com/attack_forum/2024/04/attach-bc247895058bcbcfea74900714b96db15c3ee30c.png)

但其对sql注入的防御逻辑都相同，都是对sidx和order参数进行处理后，然后封装成Page对象

![image-20240411121107373](https://shs3.b.qianxin.com/attack_forum/2024/04/attach-04ddc9a0714ff7579d6865a241f575a45c43e199.png)

![image-20240411121146368](https://shs3.b.qianxin.com/attack_forum/2024/04/attach-09faa249a96a894a46edd9b93c0043fa5d5c01d4.png)

源码：

```java
package com.utils;

import java.util.LinkedHashMap;
import java.util.Map;

import org.apache.commons.lang3.StringUtils;

import com.baomidou.mybatisplus.plugins.Page;

/**
 * 查询参数
 */
public class Query<T> extends LinkedHashMap<String, Object> {
    private static final long serialVersionUID = 1L;
    /**
     * mybatis-plus分页参数
     */
    private Page<T> page;
    /**
     * 当前页码
     */
    private int currPage = 1;
    /**
     * 每页条数
     */
    private int limit = 10;

    public Query(JQPageInfo pageInfo) {
        //分页参数
        if(pageInfo.getPage()!= null){
            currPage = pageInfo.getPage();
        }
        if(pageInfo.getLimit()!= null){
            limit = pageInfo.getLimit();
        }

        //防止SQL注入（因为sidx、order是通过拼接SQL实现排序的，会有SQL注入风险）
        String sidx = SQLFilter.sqlInject(pageInfo.getSidx());
        String order = SQLFilter.sqlInject(pageInfo.getOrder());

        //mybatis-plus分页
        this.page = new Page<>(currPage, limit);

        //排序
        if(StringUtils.isNotBlank(sidx) && StringUtils.isNotBlank(order)){
            this.page.setOrderByField(sidx);
            this.page.setAsc("ASC".equalsIgnoreCase(order));
        }
    }

    public Query(Map<String, Object> params){
        this.putAll(params);

        //分页参数
        if(params.get("page") != null){
            currPage = Integer.parseInt((String)params.get("page"));
        }
        if(params.get("limit") != null){
            limit = Integer.parseInt((String)params.get("limit"));
        }

        this.put("offset", (currPage - 1) * limit);
        this.put("page", currPage);
        this.put("limit", limit);

        //防止SQL注入（因为sidx、order是通过拼接SQL实现排序的，会有SQL注入风险）
        String sidx = SQLFilter.sqlInject((String)params.get("sidx"));
        String order = SQLFilter.sqlInject((String)params.get("order"));
        this.put("sidx", sidx);
        this.put("order", order);

        //mybatis-plus分页
        this.page = new Page<>(currPage, limit);

        //排序
        if(StringUtils.isNotBlank(sidx) && StringUtils.isNotBlank(order)){
            this.page.setOrderByField(sidx);
            this.page.setAsc("ASC".equalsIgnoreCase(order));
        }

    }

    public Page<T> getPage() {
        return page;
    }

    public int getCurrPage() {
        return currPage;
    }

    public int getLimit() {
        return limit;
    }
}

```

很完美的防御、不过这里就有点奇怪了，翻了几个sql的xml文件，发现都没有使用到这个`page`对象

![image-20240411121930477](https://shs3.b.qianxin.com/attack_forum/2024/04/attach-1754874526eae6ebf856fadfcaea5d725808c48a.png)

那我们从页面中随机找一个带分页的查询请求分析一下，例如：

```php
/jixiaokaohe/page?page=1&limit=10&sort=id
```

跟进到他的controller-&gt;`com.controller.JixiaokaoheController#page`

调用的是`jixiaokaoheService.queryPage`来进行的查询，使用`MPUtil.sort`来自定义了一个`wrapper`

![image-20240403032355989](https://shs3.b.qianxin.com/attack_forum/2024/04/attach-0cb0b94aebcf94e084a0fa7226a79ef606392740.png)

继续跟进到`com.service.impl.JixiaokaoheServiceImpl#queryPage`

可以看到这块使用了sql过滤的`com.utils.Query#Query(java.util.Map<java.lang.String,java.lang.Object>)`

![image-20240403032630418](https://shs3.b.qianxin.com/attack_forum/2024/04/attach-60e3aaab1e8e2298a8bcb71efb8291dbeadd5378.png)

继续向下跟

![image-20240403033241569](https://shs3.b.qianxin.com/attack_forum/2024/04/attach-feab81eded99648a88a1d9441f9636f2b1f787cd.png)

![image-20240403033302136](https://shs3.b.qianxin.com/attack_forum/2024/04/attach-ae243f349b68d1f1b686b03c70369048362f709b.png)

可以看到最终sql的实现使用的是开头说的自定义的`wrapper`来构建查询条件。

![image-20240403033810081](https://shs3.b.qianxin.com/attack_forum/2024/04/attach-18859e800509145cc0b01a4f7df1075cb4a12989.png)

跟进去看看-&gt;`com.utils.MPUtil#sort`

发现在这块对`sort`参数直接使用了拼接而且没有进行过滤

![image-20240403033917326](https://shs3.b.qianxin.com/attack_forum/2024/04/attach-d65afa11acac07217a766aa6d8f7d3b3f3e1765f.png)

打个poc试一下吧！

```php
page=1&limit=10&sort=id+and+updatexml(1,concat(0x7e,database()),0)#
```

![image-20240403034431648](https://shs3.b.qianxin.com/attack_forum/2024/04/attach-c2ace7485898ef14dac13bb3806ddf0cd7f58b96.png)

### 其他SQL注入分析

从Mybatis-puls的简介中可以看到：**Mybatis-Plus是一个Mybatis（opens new window）的增强工具，在Mybatis的基础上只做增强不做改变，为简化开发。**因此mybatis中实现sql的方式在Mybatis-puls同样适用。

`#{}`预处理、`${}`拼接就不用多说了。直接实现sql的xml搜索`${`

![image-20240403040500351](https://shs3.b.qianxin.com/attack_forum/2024/04/attach-e4fcc43894f16f19287dc08ee39c4234454a99c8.png)

可以发现多出使用拼接，那直接选择一个分析一下

![image-20240404211942229](https://shs3.b.qianxin.com/attack_forum/2024/04/attach-4e172dad4506fc7ffb8836fed3021416ccf6553b.png)

一路向上跟进  
`com.service.impl.CommonServiceImpl#remindCount`

![image-20240404212053916](https://shs3.b.qianxin.com/attack_forum/2024/04/attach-74fed281e8c9932ea338b26081d04dbd1d4ff879.png)

最终跟到`com.controller.CommonController#remindCount`，发现全程也无过滤

![image-20240404212127974](https://shs3.b.qianxin.com/attack_forum/2024/04/attach-18222ea664e37973824a09b9edea1a605d8fa6d7.png)

根据接口，构造，打个poc

```php
users union select group_concat(SCHEMA_NAME) from information_schema.SCHEMATA
```

![image-20240404211110262](https://shs3.b.qianxin.com/attack_forum/2024/04/attach-7765ca1537bf6085a47fe41097f3ac5ecf3a5846.png)

### SQL注入总结

在对动态表名、orderby这种需要拼接的场景下，在代码实现时一定要仔细！总体来说mybatispuls框架中SQL注入漏洞挖掘相较于mybatis中更为困难，需要我们更加有耐心！

0x03 任意用户密码重置
-------------

这是在无意间发现的一个功能，感觉是作者设计的一个功能。但我没太看懂作者的意图，重置密码的接口可以不进行权限认证就使用！

`@IgnoreAuth`这个注解的作用是不进行权限认证，之后就是通过用户名来查询用户，然后修改用户的密码为`123456`

![image-20240404232632119](https://shs3.b.qianxin.com/attack_forum/2024/04/attach-7cf2f6a7bec9da3a954dfcec705011671c3239f2.png)

```php
GET /springboot57n6g/users/resetPass?username=admin HTTP/1.1
Host: localhost:8081
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36
Accept: application/json, text/plain, */*
sec-ch-ua: "Chromium";v="122", "Not(A:Brand";v="24", "Google Chrome";v="122"
sec-ch-ua-platform: "Windows"
sec-ch-ua-mobile: ?0
Accept-Encoding: gzip, deflate, br
Sec-Fetch-Site: same-origin
Sec-Fetch-Dest: empty
Referer: http://localhost:8081/
Sec-Fetch-Mode: cors
Accept-Language: zh-CN,zh;q=0.9
```

![image-20240404233310202](https://shs3.b.qianxin.com/attack_forum/2024/04/attach-6079c0b5a461019c22219710ada4a906535b3b07.png)

0x04 任意文件上传
-----------

![image-20240405012738083](https://shs3.b.qianxin.com/attack_forum/2024/04/attach-607340d7c49aa46f4c1efe93691b0366d11fe005.png)

### 分析

在`com.controller.FileController#upload`中实现的文件上传功能，通过最后一个点来获取上传文件后缀，在结合时间生成心的文件名，但未对文件进行过滤。导致任意文件上传

![image-20240405012907744](https://shs3.b.qianxin.com/attack_forum/2024/04/attach-dd4cefbb224ea3ead9f9ae9d8ed150a3ebcf3162.png)

0x05 任意文件下载
-----------

![image-20240405012147812](https://shs3.b.qianxin.com/attack_forum/2024/04/attach-586aec266639dc1acbf84ae08b269adde3010506.png)

### 分析

在`com.controller.FileController#download`中实现的文件下载功能，但是在94行文件路径是由拼接而得：`静态目录/upload/filename`

由于filename我们可控。并且也无过滤，导致目录穿越下载任意文件

![image-20240405012326337](https://shs3.b.qianxin.com/attack_forum/2024/04/attach-8055e0d02d53e4e58c38cb0504957ff7b3c1df3a.png)

0x06 总结
-------

开发注重功能的同时也应该考虑到一些安全问题。就像重置密码那个问题，作者就没有思考到安全问题。