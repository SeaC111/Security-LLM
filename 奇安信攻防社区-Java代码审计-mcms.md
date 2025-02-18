环境搭建：
-----

首先配置数据库用户名和密码  
![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1683079863516-416a2532-d99c-4f17-b68d-8c016d3cf895.png)  
然后进行环境搭建，访问首页。  
![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1683079874365-f826a020-7fdd-4b2d-a1fb-a8b46986dbc1.png)  
使用默认密码，成功登录。  
![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1683080007192-2a02b84b-1010-46ed-88be-35c5efbe1ec9.png)

代码审计：
-----

1.xss漏洞
-------

根据漏洞点，我们定位到 net.mingsoft.basic.filter.XssHttpServletRequestWrapper这部分源码中  
然后直接去看源码。  
net/mingsoft/basic/filter/XssHttpServletRequestWrapper.java

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1683081007162-beadb2c0-ff09-4fbd-ad9b-e874e57ad2ea.png)  
发现其直接使用throw抛出异常，并直接进行拼接。  
![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1683004544076-e35610ec-8857-4cb0-bb97-c3276f116ba2.png)

然后直接输出。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1683004519530-a1a601fa-c73e-455f-a615-b0bca8742f8b.png)

### 漏洞复现：

进入前台地址。  
![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1683080480362-b9124a16-8783-4f4d-8a51-891a9fefc3f5.png)  
构造xss的payload，成功实现弹框。  
![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1683080507084-fe0b6cf0-6ea8-436a-8f60-3435392ba7be.png)

2.SQL注入
-------

全局搜索关键字 ${

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1683004935437-5c9d2030-a419-4e44-a02c-47948c5fb290.png)  
发现有几处存在关键字。  
进入ICategoryDao.xml![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1683005035204-c6951212-d99d-4d78-be59-24bb2c6547d7.png)

跟进include中的sqlWhere函数。

在这里我们需要注意：

- ${item.field}被直接拼接在SQL语句中
- ${item.field}，item是collection="sqlWhereList"的别名，也就是${sqlWhereList.field}
- 传递的参数sqlWhereList，需要构造的是其中的field

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1683005138024-72d63a30-69ca-427b-bb25-618003ad0708.png)

然后接着去找接口及其实现过程，然后回到ICategoryDao.xml，找"query"对应的接口。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1683006557402-dd599df8-80ce-49b4-87b6-4ecc6f2cf2e0.png)

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1683006600830-b0b46a26-4509-4aeb-993e-33f3680d8531.png)

然后发现query的类有三个，但只有一个接收传参

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1683006835234-2d1d6da6-1d8c-46bb-9d7d-00294f661e5f.png)

然后获得地址。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1683006881009-d24093e6-fadf-485c-b0a2-25a2a2ba6fd3.png)

找到了query，然后去找它的参数sqlWhereList。  
![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1683006965519-e59930f7-91ca-46f5-b633-9a61a7a6d589.png)

子类没有发现，就去看父类BaseEntity，在父类中找到sqlWhereList和SQLwhere。  
...  
public abstract class BaseEntity implements Serializable{  
/\*\*  
\* 自定义SQL where条件，需要配合对应dao.xml使用  
\*/  
@JsonIgnore  
@XmlTransient  
@TableField(exist = false)  
protected String sqlWhere;

```php
@JsonIgnore
@XmlTransient
public String getSqlWhere() {
    return sqlWhere;
}
public void setSqlWhere(String sqlWhere) {
    this.sqlWhere = sqlWhere;
}

@JsonIgnore
@XmlTransient
public List getSqlWhereList() {
    if(StringUtils.isNotBlank(sqlWhere)){
        try {
            return JSONObject.parseArray(sqlWhere,Map.class);
        }catch (Exception e){
            e.printStackTrace();
        }
    }
    return Collections.EMPTY\_LIST;
}
...
```

}

### 漏洞复现：

进入公司管理-文章管理处。  
![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1683082292587-ecfa022e-51a8-4b65-8d6f-889d3f4e833b.png)  
使用burpsuite抓包，然后输入SQL注入的paylaod去触发报错注入。  
![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1683082281300-a7479950-1bbb-441c-92af-ba83120bb82c.png)

3.文件上传
------

定位到接口为，/ms/file/uploadTemplate.do  
![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1683084673249-a6d796a9-bf4d-4a63-9e9c-3e2126dcfdce.png)

然后使用Burp进行抓包。  
![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1683084663693-9ad2ca1d-93e3-48ee-93bb-40ab3390102c.png)  
在正常上传压缩文件之后直接进行解压，没有对其进行检测，直接传入文件中。  
![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1683084646152-04cca3c0-7e35-4f00-b153-1f96aa0ea9ae.png)

成功上传1.jsp文件。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1683085052024-73bf3271-c3b4-4bbd-a177-edcee88470ef.png)

4、SSTI：Freemarker模板注入
---------------------

源码位置net\\mingsoft\\base\\util\\FtlUtil.java

发现其访问指定路由后，会调用generate()生成主页

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1683086339402-9d10ce83-e7e4-41fd-a2fe-032f2028051b.png)

其中主要是对map进行一些初始化操作，并通过rendering()进行渲染

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1683086448706-c8e24aef-98a0-4abc-be80-21230637773b.png)

最后调用process()进行渲染，造成代码执行

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1683086546077-fae685b2-4a33-4ab5-b9ea-518f4d82d779.png)

### 漏洞复现：

```php
进入首页文件，然后修改index.html
```

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1683085267640-2af60972-2b2f-4002-bdc7-05a43b0f4516.png)  
加入SSTI的payload  
![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1683085310896-eca1c689-0b3c-4918-a0d8-40bd41c19c24.png)  
然后生生成主页，成功弹出计算器。  
![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1683085300009-dd9d2e06-3225-48f5-b4b7-46ed5d6edfc4.png)

5.FastJson反序列化漏洞
----------------

发现其在代码中，存在fastjson组件。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1683086728097-26dc8619-926b-46fa-85f5-e5ccf065e0be.png)
----------------------------------------------------------------------------------------------------------

其版本为1.2.8，无法进行执行命令。  
![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1683086908731-b98dbb3b-79d7-4598-a061-950f19df7453.png)

### 漏洞复现：

使用burp进行抓包，然后设置dnslog  
![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1683087108628-cbb22db1-7a65-404d-b61c-b3f91266df8e.png)  
然后使用burp去触发，成功收到监听。  
![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1683087073891-574cac38-3138-4ad3-b382-6d0b1ffa9031.png)

6.SQL注入2
--------

全局搜索${}，发现query方法中，categoryId参数存在SQL注入

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1683087267991-5480479d-95e3-4079-b7f9-bccfd497360d.png)

根据namespace可知该语句的映射接口类ContentDao

在IContentDao中并没有发现query方法，但他继承了IBaseDao，而query就在其中，然后去看他父类文件。  
![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1683087445311-1f33ebf4-c4c9-4f41-a03b-617e43251835.png)

它的业务层对应接口类为:IContentBiz ，而实现类是ContentBizImpl而其中子类没有调用该方法，所以向上找他的父类BaseBizImpl

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1683087477097-4bedd933-6909-4d43-b7bd-5a427852606e.png)

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1683087543940-37f06e66-4fa9-4ccd-a7be-9f524c8d180d.png)

找到了控制层ContentAction，该层的接口为/cms/content

在该类的list方法中，会调用contentBiz属性的query方法参数为content  
未对用户输入的参数进行过滤，另外该CMS全局也没有针对SQL注入的过滤，所以只需要传入categoryId参数，将查询语句闭合即可导致SQL注入

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1683087646148-c395e145-5039-40d9-a08b-056f4fa892e4.png)

### 漏洞复现：

使用post方式进行传参。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1683088003547-66960c6e-6a34-4a0d-97e8-cbc518aef906.png)  
可以使用hackbar或者bp进行漏洞利用。  
![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1683087992477-eb91b77b-6df2-4f4b-92d1-6c8be727809a.png)

7.任意文件删除
--------

在TemplateAction接口中，发现其通过fileName可以指定目录删除。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1683088938198-a027d37c-c221-4d40-b6a3-164aba29c883.png)  
并且未对文件上传对…/进行限制，我们可以通过…/进行任意目录删除  
![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1683089086305-9a7af762-7ab5-45d9-9545-b0db0612e943.png)

### 漏洞复现：

我们使用hackbar，删除我们上传的1.jsp，成功删除。  
![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1683088333315-bc96cbc1-2dea-4b30-b812-db35c7803077.png)

8.shiro反序列化
-----------

在登录框发现存在记住密码的功能。  
![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1683090269674-b0621dd0-85d6-4cf6-9a4c-ab90c88abffa.png)  
然后对其进行测试，发现其存在shio的特征。  
![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1683090257599-8ed6130c-a976-4363-9483-2c3d8ca52085.png)  
全局搜索shiro，发现其存在shiro组件。  
![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1683090205186-ff6ec917-22f7-472d-9244-7b6cccf37d76.png)  
发现源码中写入了key。  
![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1683090116652-44134fdb-b478-4a38-9c9f-6b6a608fe40a.png)  
然后我们使用工具进行测试。  
![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1683090096992-99dbf7c8-0d2b-41f1-9c2c-6f3130c7bb07.png)  
发现我们可以通过源码中的key和爆破出的利用链，成功命令执行。  
![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1683090285259-bd03b024-1d04-4e4d-a18b-19f911bc6dc3.png)  
然后写入内存马，成功可以getshell。  
![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1683090342987-b9c03307-2483-4a0c-ba83-1e2b422796a7.png)

9、文件上传2
-------

定位到源码为:net.mingsoft.basic.action.TemplateAction#writeFileContent

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1683091233150-fb3efec1-7566-4eb0-8cfd-03f7a164b350.png)  
发现其使用filename来获取为文件。  
![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1683091258442-dfd716ac-55ec-47c6-b794-fdef189c6618.png)  
然后接着进入模板管理、然后点击编辑。  
![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1683090591749-fcde5aa9-834f-40a0-8f95-f8e13d964d7d.png)  
发现存在一个上传点，  
![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1683090837651-da20410b-d405-4b87-bea2-03ba2862a385.png)  
然后上传测试文件，发现可以成功进行上传。  
![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1683090823051-00a47e88-1ced-46c8-8458-19f9978d287f.png)

10、文件上传3
--------

这个漏洞和上面的那个漏洞一样，只不过是另一个方法upload。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1683091575717-368d0179-05fd-4a9c-8ba2-f9b9f805c07d.png)

发现其存在非法路径过滤函数 checkUploadPath，  
然后查看checkUploadPath函数，其只对 ../进行了校验，通过绝对路径仍然可以绕过。  
![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1683091613849-262d0238-40d2-4d39-966c-e0953ca6e56a.png)  
对文件的上传是利用了upload方法  
![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1683091643229-b8acb9d9-1e61-4a21-b822-7ed99b1a3e81.png)  
在测试过程中出现了文件，响应码为400.  
![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1683091482989-afe20d3e-a56a-447e-bddc-04571d6b7461.png)  
**REF**  
[https://baijiahao.baidu.com/s?id=1745383988318751780&amp;wfr=spider&amp;for=pc](https://baijiahao.baidu.com/s?id=1745383988318751780&wfr=spider&for=pc)  
<https://www.freebuf.com/articles/web/360757.html>