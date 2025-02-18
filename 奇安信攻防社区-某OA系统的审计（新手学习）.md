某OA系统的审计（新手学习）
==============

一次偶然机会，找人要了套源码，是Stuts2和spring框架混用的系统，比较简单适合入门学习

0x01 SQL注入
----------

该项目是基于mvc框架开发的，与数据库交互的代码在`DAO`目录下，在core/base/dao中存在IBaseDao类属于该项目的数据库操作的基类

![image-20230907155510687](https://shs3.b.qianxin.com/butian_public/f271933ad05004c4c82cdae66b4f99f444183120c5c1f.jpg)

根据其定义的函数名，都能看出是传入SQL语句进行查询，我们找的他的实现类

![image-20230907155538251](https://shs3.b.qianxin.com/butian_public/f155370a892ae9c5734da083f3943e0925b7827a92f24.jpg)

可以看到其方法实现也是传入SQL语句字符串直接它通过hibernateTemplate API直接进行查询。其实现SQL查询的方法也有很多。![image-20230907155622721](https://shs3.b.qianxin.com/butian_public/f19395832984531b164ba16c5bd494027599c0ed399d2.jpg)

同时我们发现该baseDao类有七百多个继承者

​ ![image-20230907151141401](https://shs3.b.qianxin.com/butian_public/f13077735edac9153ccc378e7cc34ed1f5ff1af527fa6.jpg)

跟进去发现基本都继承了BaseDao的方法，并没有进行重载，于是我们全局搜索相关危险方法，这里以sqlFind方法为例

![image-20230907160033608](https://shs3.b.qianxin.com/butian_public/f95905820b32906436e29dc059e78b5ba65828c467ad0.jpg)

发现在构造SQL语句是用了?占位符，这样的语法是无法进行注入的，于是我们寻找直接拼接参数到SQL语句字符串中的方法

![image-20230907161017336](https://shs3.b.qianxin.com/butian_public/f7798551d31edde46638725ba515fcedad06362902931.jpg)

根据sqlFind方法的重装情况，当参数`param`为空则不会进行占位符参数绑定，于是我们可以缩小搜索范围

向下翻找就找到在`BaseDataService`类中`listBaseDataByFlowId`方法，存在直接拼接参数构造SQL语句的情况，

![image-20230907161616783](https://shs3.b.qianxin.com/butian_public/f801226fa6b0dc4a77e142018746134a85f47e68bc450.jpg)

这里直接将`flowId`等参数拼接到语句中调用`sqlFind`方法进行数据库查询，我们向上找是哪个controller调用该危险方法

最终定位在`BaseDataController`中的`listBaseDataByFlowId`方法中

![image-20230907161958425](https://shs3.b.qianxin.com/butian_public/f660671a2f6ef2503536f399d25648b37995ea9133500.jpg)

这里直接将请求中type和flowId传入service层进行查询，我们构造该接口的请求

![image-20230907162240488](https://shs3.b.qianxin.com/butian_public/f5552903270c3ca5a5aacb607b79a99a8779d6884f9cd.jpg)

提示我们没有登录，应该是spring进行了拦截处理

0x02 权限绕过
---------

我们查看spring配置文件，找的拦截器的实现类

![image-20230907162648937](https://shs3.b.qianxin.com/butian_public/f188938f0d9db3dbca3294c4de7ccda49ad2c365dbf7c.jpg)

可以看到该项目有个全局拦截器`PermissionInterceptor`，我们跟进到里面，根据spring拦截器实现原理直接来到`prehandle`方法，主要处理逻辑如下

![image-20230907163033544](https://shs3.b.qianxin.com/butian_public/f449878aa82242c9deca8272c05c3137cf4a87f44144e.jpg)

该拦截器定义了两个成员数组`UN_LOGIN_EXPOSE_CONTROLLERS`和`UN_LOGIN_EXPOSE_SERVLET_PATH`，当我们请求的控制器或者接口url在这两个数组中是会放行我们的请求，也就是定义了白名单请求，很遗憾我们的`listBaseDataByFlowId`方法的请求不在白名单中，会进入if判断。

首先判断session中是否有登录凭证（显然没有），如果没有会获取请求中jwt参数的值进行JSON Web Token的认证，检查token的有效性。

看到jwt 认证，很快就想到会不会硬编码jwt 密钥，因为在初期翻配置文件中没看到有jwt 密钥的定义

于是我们跟进到`jwtCheck`方法，果然验证了我们的猜想

![image-20230907164822180](https://shs3.b.qianxin.com/butian_public/f3549129e969c3625da8700f01eb37d490e03bc63662c.jpg)

于是我们根据密钥生成token

![image-20230907164928048](https://shs3.b.qianxin.com/butian_public/f12170818f6cfe646b2dfb998c8fd238c3b9d6c7e1e52.jpg)

带着jwt token访问目标接口，发现不在提示未登录

![image-20230907165131183](https://shs3.b.qianxin.com/butian_public/f8295281d9ad19991421d21c6f6faee640a05edcf9beb.jpg)

根据配置文件该系统是属于了sql server数据库，于是构造语句

```php
flowId = 1'+(case when (1=1) then '' else char(1/0) end)+'
```

当为正是，正常返回

![image-20230907173029086](https://shs3.b.qianxin.com/butian_public/f12471661233e95e3e2ac47336cc992b90d9a3baf1b40.jpg)

为假是进行char(1/0)构造报错会返回500

![image-20230907173101190](https://shs3.b.qianxin.com/butian_public/f6784281bb84fab1ea7e3707de403cc849db96e429678.jpg)

证明存在SQL注入

0x03 总结
-------

1、mvc框架中service层一般是负责sql语句的封装，dao层一般负责与数据库交互，所以我们可以在dao层中找直接执行sql语句的方法，在service层调用可疑查询方法处查看sql语句构造情况，找的可能存在sql注入的点，向上找的controller层的具体调用接口

2、主要还是看鉴权，通过配置文件找的鉴权类，如使用了request.getRequestUri等危险方法来获取请求url做判断时很容易就被bypass，或是看jwt等第三方鉴权组件硬编码的问题

0x04 另外发现
---------

### 1、未授权文件上传

在鉴权文件中存在白名单controller类和接口数组`UN_LOGIN_EXPOSE_CONTROLLERS`和`UN_LOGIN_EXPOSE_SERVLET_PATH`，我们关注一下

![image-20230913181059687](https://shs3.b.qianxin.com/butian_public/f6874980dfb8737f407cb5474e190726b3c60ee661898.jpg)

翻找未授权类时在appCallController中，有文件操作的方法

```java
@RequestMapping({"uploadFile"})
    @ResponseBody
    @Transactional(
        readOnly = false
    )
    public String uploadFile(@RequestParam(value = "file",required = false) MultipartFile file) {
        try {
            String id = UUIDUtils.getuid();
            String extension = StringUtils.getFilenameExtension(file.getOriginalFilename());
            if (StringUtils.hasText(extension)) {
                extension = "." + extension;
            }

            String fileUrl = "../xxx_Ueditor_File/app/files/" + id + extension;
            String savePath = getCurRequest().getSession().getServletContext().getRealPath(fileUrl);
            File saveFile = new File(savePath);
            if (!saveFile.exists()) {
                saveFile.mkdirs();
            }

            file.transferTo(saveFile);
            APPFiles af = new APPFiles();
            af.setFileLength(file.getSize());
            af.setId(id);
            af.setFilePath(saveFile.getAbsolutePath());
            af.setFileName(file.getOriginalFilename());
            af.setTime(new Date());
            af.setFileType(file.getContentType());
            af.setMsgId("");
            af.setType(2);
            this.dao.save(af);
            return id;
        } catch (Exception var8) {
            var8.printStackTrace();
            return "";
        }
    }
```

该方法是获取随机数id，然后取到表单上传中的文件名后缀名，然后将其保存在`/xxx_Ueditor_File/app/files/`目录中，最后讲随机数id返回给前端，因为未对文件后缀名做限制导致可以上传jsp文件

构造请求上传

![image-20230914170411814](https://shs3.b.qianxin.com/butian_public/f686991682ca36d4e81fe896120badcbc89d76b6171db.jpg)

![image-20230914170500004](https://shs3.b.qianxin.com/butian_public/f1644951e70941d2c2b491599749e937ed897939d1a41.jpg)

成功上传文件

### 2、未授权SQL注入

该项目除了用到spring框架外还用到了st2框架，在`struts.xml`查看配置信息，这里也定义了拦截器

![image-20230914171023854](https://shs3.b.qianxin.com/butian_public/f699751aed858acf2c58aa1cc1df3fd0a1a708cc2435e.jpg)

具体实现逻辑在doIntercept()方法中

![image-20230914171257111](https://shs3.b.qianxin.com/butian_public/f46442157022d5b9537b79a8dafd737182f561c18987c.jpg)

可以看到这里也是定义白名单方法名和类名

```java
private Set<String> UN_LOGIN_EXPOSE_METHODS = new HashSet<String>() {
        {
            this.add("saveStaffInfo");
            this.add("updateStaffInfo");
            this.add("listRegionTree");
            this.add("CostCloudProject");
            ...
            this.add("handle");
            this.add("listProjAuditQGC");
            this.add("getlistProjAuditDataQGC");
        }
    };
    private static List<Class<?>> TEMP_USER_EXPOSE_ACTIONS = new ArrayList<Class<?>>() {
        {
            this.add(IndexAction.class);
            ...
        }
    };
    private static List<String> TEMP_USER_EXPOSE_METHODS = new ArrayList<String>() {
        {
            this.add("showPhoto");
            this.add("download");
        }
    };
```

看到白名单方法中有些get操作的函数，如`getlistProjAuditDataQGC`看名称是获取list数据，跟进其中

![image-20230914172238302](https://shs3.b.qianxin.com/butian_public/f846762c51c2978e9993f76e82389a4a577d5dcdc3c6f.jpg)

可以看到调用`findByBusinessByQueryQGC`方法进行查询，来到`findByBusinessByQueryQGC`方法实现，可以看到其是获取请求中的特定参数，并将其直接拼接在sql变量中

![image-20230914172639900](https://shs3.b.qianxin.com/butian_public/f4420913c4baebc9fb0702d36ac35c31f3540865e4418.jpg)

最后调用`sqlFindPage`拼接sql变量执行

![image-20230914172738295](https://shs3.b.qianxin.com/butian_public/f370241ccfbd1162f5f06d7cae813c16323de646444a0.jpg)

![image-20230914172926441](https://shs3.b.qianxin.com/butian_public/f7365160c2e437522e5e255393b19b3db209f1943ebfa.jpg)

此处也是存在SQL注入

![image-20230914173102686](https://shs3.b.qianxin.com/butian_public/f5539871758408d8e4722640e6fd74d0aed8d31adc95b.jpg)