最近爆出了一个metersphere的高危漏洞，一方面是对该漏洞的应急响应，另一方面对这个项目的历史漏洞也进行了一些了解和学习，因此写下此文对该项目安全相关的框架，以及几个比较严重的漏洞的原理、利用及修复方法进行分析。

0x0项目背景
-------

MeterSphere 是一站式开源持续测试平台，涵盖测试跟踪、接口测试、性能测试、 团队协作等功能，兼容 JMeter 等开源标准，有效助力开发和测试团队充分利用云弹性进行高度可扩展的自动化测试，加速高质量的软件交付，推动中国测试行业整体效率的提升。

该项目没有类似于Apache那种专用的安全漏洞提交邮箱，因此该项目的安全漏洞一般是由漏洞发现者在GitHu提交Issue，缺点是漏洞的细节会被公开。

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-4290217aa6b1f0899ec346d4b776ccc6aac96f02.png)

### 认证方式

该项目基于Springboot+shiro进行路由和权限控制。metersphere项目使用shiro框架进行权限控制。相关的权限配置在`io.metersphere.config.ShiroConfig`和`io.metersphere.commons.utils.ShiroUtils`中。

```Java
//io.metersphere.config.ShiroConfig
@Bean
public ShiroFilterFactoryBean getShiroFilterFactoryBean(DefaultWebSecurityManager sessionManager) {
    ShiroFilterFactoryBean shiroFilterFactoryBean = new ShiroFilterFactoryBean();
    shiroFilterFactoryBean.setLoginUrl("/login");
    shiroFilterFactoryBean.setSecurityManager(sessionManager);
    shiroFilterFactoryBean.setUnauthorizedUrl("/403");
    shiroFilterFactoryBean.setSuccessUrl("/");

    shiroFilterFactoryBean.getFilters().put("apikey", new ApiKeyFilter());
    shiroFilterFactoryBean.getFilters().put("csrf", new CsrfFilter());
    Map<String, String> filterChainDefinitionMap = shiroFilterFactoryBean.getFilterChainDefinitionMap();

    ShiroUtils.loadBaseFilterChain(filterChainDefinitionMap);

    ShiroUtils.ignoreCsrfFilter(filterChainDefinitionMap);

    filterChainDefinitionMap.put("/**", "apikey, csrf, authc");
    return shiroFilterFactoryBean;
}
```

在shiroConfig中配置了默认所有路由都需要经过apikey、csrf、authc三个过滤器，其中authc就代表所有路径都需要认证。

在ShiroUtils中，对不需要认证的路径及一些特殊的路径进行了认证配置。

```Java
public static void loadBaseFilterChain(Map<String, String> filterChainDefinitionMap){

    filterChainDefinitionMap.put("/resource/**", "anon");
    filterChainDefinitionMap.put("/*.worker.js", "anon");
    filterChainDefinitionMap.put("/login", "anon");
    filterChainDefinitionMap.put("/signin", "anon");
    filterChainDefinitionMap.put("/ldap/signin", "anon");
    filterChainDefinitionMap.put("/ldap/open", "anon");
    filterChainDefinitionMap.put("/signout", "anon");
    filterChainDefinitionMap.put("/isLogin", "anon");
    filterChainDefinitionMap.put("/css/**", "anon");
    filterChainDefinitionMap.put("/js/**", "anon");
    filterChainDefinitionMap.put("/img/**", "anon");
    filterChainDefinitionMap.put("/fonts/**", "anon");
    filterChainDefinitionMap.put("/display/info", "anon");
    filterChainDefinitionMap.put("/favicon.ico", "anon");
    filterChainDefinitionMap.put("/display/file/**", "anon");
    filterChainDefinitionMap.put("/jmeter/download/**", "anon");
    filterChainDefinitionMap.put("/jmeter/ping", "anon");
    filterChainDefinitionMap.put("/jmeter/ready/**", "anon");
    filterChainDefinitionMap.put("/authsource/list/allenable", "anon");
    filterChainDefinitionMap.put("/sso/signin", "anon");
    filterChainDefinitionMap.put("/sso/callback", "anon");
    filterChainDefinitionMap.put("/license/valid", "anon");
    filterChainDefinitionMap.put("/api/jmeter/download", "anon");
    filterChainDefinitionMap.put("/api/jmeter/download/files", "anon");
    filterChainDefinitionMap.put("/api/jmeter/download/jar", "anon");
    filterChainDefinitionMap.put("/api/jmeter/download/plug/jar", "anon");

    // for swagger
    filterChainDefinitionMap.put("/swagger-ui.html", "anon");
    filterChainDefinitionMap.put("/swagger-ui/**", "anon");
    filterChainDefinitionMap.put("/v3/api-docs/**", "anon");

    filterChainDefinitionMap.put("/403", "anon");
    filterChainDefinitionMap.put("/anonymous/**", "anon");

    //分享相关接口
    filterChainDefinitionMap.put("/share/info/generateShareInfoWithExpired", "anon");
    filterChainDefinitionMap.put("/share/info/selectApiInfoByParam", "anon");
    filterChainDefinitionMap.put("/share/get/**", "anon");
    filterChainDefinitionMap.put("/share/info", "apikey, csrf, authc"); // 需要认证
    filterChainDefinitionMap.put("/document/**", "anon");
    filterChainDefinitionMap.put("/share/**", "anon");
    filterChainDefinitionMap.put("/sharePlanReport", "anon");

    filterChainDefinitionMap.put("/system/theme", "anon");
    filterChainDefinitionMap.put("/system/save/baseurl/**", "anon");
    filterChainDefinitionMap.put("/system/timeout", "anon");

    filterChainDefinitionMap.put("/v1/catalog/**", "anon");
    filterChainDefinitionMap.put("/v1/agent/**", "anon");
    filterChainDefinitionMap.put("/v1/health/**", "anon");
    //mock接口
    filterChainDefinitionMap.put("/mock/**", "anon");
    filterChainDefinitionMap.put("/ws/**", "anon");

    filterChainDefinitionMap.put("/plugin/**", "anon");

}
```

0x1历史漏洞
-------

### CVE-2021-45789

#### 漏洞原理

这是一个任意文件上传漏洞，影响1.15.4及之前的版本，经过授权的攻击者可以利用下载功能读取目标主机上的任意文件。漏洞issue链接：<https://github.com/metersphere/metersphere/issues/8652>

issue中提到了漏洞的关键函数

```Java
public byte[] loadFileAsBytes(FileOperationRequest fileOperationRequest) {
    File file = new File(FileUtils.BODY_FILE_DIR + "/" + fileOperationRequest.getId() + "_" + fileOperationRequest.getName());
    try (FileInputStream fis = new FileInputStream(file);
         ByteArrayOutputStream bos = new ByteArrayOutputStream(1000);) {
        byte[] b = new byte[1000];
        int n;
        while ((n = fis.read(b)) != -1) {
            bos.write(b, 0, n);
        }
        return bos.toByteArray();
    } catch (Exception ex) {
        LogUtil.error(ex);
    }
    return null;
}
```

可以看到函数从fileOperationRequest中读取id和name并拼接进File对象，未进行任何的过滤就进行了文件读取。往前回溯，看哪里引用了这个函数，并关注fileOperationRequest变量是否用户可控。很快可以在`io.metersphere.api.controller.ApiAutomationController`中找到download函数，对该方法进行了调用。

```Java
@PostMapping("/file/download")
public ResponseEntity<byte[]> download(@RequestBody FileOperationRequest fileOperationRequest) {
    byte[] bytes = apiAutomationService.loadFileAsBytes(fileOperationRequest);
    return ResponseEntity.ok()
            .contentType(MediaType.parseMediaType("application/octet-stream"))
            .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + fileOperationRequest.getName() + "\"")
            .body(bytes);
}
```

metersphere后端基于springboot开发，这个函数对应的就是/api/automation/file/download路由，并且fileOperationRequest直接来源于用户输入，同时有RequestBody注解，可以使用json或者xml格式的HTTP请求体进行数据的输入。

因此可以构建如下payload读取/etc/passwd文件

```Java
POST /api/automation/file/download HTTP/1.1
Host: host.com
Cookie: COOKIE
Content-Type: application/json

{"id":"","name":"../../../etc/passwd"}
```

这里的/api/automation路径属于需要认证的路径，因此该漏洞利用需要授权。

#### 修复补丁

GitHub 补丁commit：<https://github.com/metersphere/metersphere/commit/18c62d91f8e0ad5b1f5730a757c5a195eb0f0723>

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-18c4b2df749d86e54ed650ac863634ac952be0c3.png)

在读取文件函数中增加了过滤，不允许`/`出现。

### CVE-2021-45790

#### 漏洞原理

这是一个任意文件上传漏洞，影响v.1.15.4及以前的版本，无需授权的攻击者可以利用该漏洞上传任意文件，并且可能造成任意命令执行。漏洞issue链接：<https://github.com/metersphere/metersphere/issues/8653>

漏洞作者同样贴出了触发漏洞的关键代码，在io.metersphere.service.ResourceService中：

```Java
public void mdUpload(MdUploadRequest request, MultipartFile file) {
    FileUtils.uploadFile(file, FileUtils.MD_IMAGE_DIR, request.getId() + "_" + request.getFileName());
}
```

这个函数从名字来看，功能可能是上传markdown文件，但是可以看见，该函数中并未对文件的后缀有任何的限制，再看FileUtils.uploadFile函数

```Java
public static String uploadFile(MultipartFile uploadFile, String path, String name) {
    if (uploadFile == null) {
        return null;
    }
    File testDir = new File(path);
    if (!testDir.exists()) {
        testDir.mkdirs();
    }
    String filePath = testDir + "/" + name;
    File file = new File(filePath);
    try (InputStream in = uploadFile.getInputStream(); OutputStream out = new FileOutputStream(file)) {
        file.createNewFile();
        FileUtil.copyStream(in, out);
    } catch (IOException e) {
        LogUtil.error(e.getMessage(), e);
        MSException.throwException(Translator.get("upload_fail"));
    }
    return filePath;
}
```

同样没有做任何过滤。接着向前回溯，看哪里调用了`mdUpload`函数，同样很快就可以找到io.metersphere.controller.ResourceController中的调用

```Java
@Resource
ResourceService resourceService;
@PostMapping(value = "/md/upload", consumes = {"multipart/form-data"})
public void upload(@RequestPart(value = "request") MdUploadRequest request, @RequestPart(value = "file", required = false) MultipartFile file) {
    resourceService.mdUpload(request, file);
}

```

同样是未做任何过滤，直接就进行了函数调用。并且该函数属于`/resource`路由，该路由属于可以匿名访问的路由。

因此可以使用如下格式的payload上传文件：

```Java
POST /resource/md/upload HTTP/1.1
Host: host.com
Content-Type: multipart/form-data;boundary=xxx

--xxx
Content-Disposition: form-data;name="file"; fileName="test"
Content-Type: image/jpeg

123
--xxx
Content-Disposition: form-data;name="request"; fileName="xxx"
Content-Type: application/json

{"id":"../","fileName":"../../tmp/test"}
--xxx--

```

#### 修复补丁

漏洞的issue中提的补丁，修改了允许匿名访问的路由限制，匿名用户无法再使用该功能。

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-f54b813a556ed2a9cd6adeac2d7c28d8d6cc9613.png)

### 远程代码执行漏洞

#### 漏洞原理

这个漏洞是安全厂商提交给官方的漏洞，看不到漏洞细节，但是可以在GitHub找到相对应的commit记录。公开的漏洞信息是该漏洞是一个未授权的远程代码执行漏洞，影响v1.16.3及以前的版本，在GitHub的release中可以看到v1.16.4只有一个fix，看起来像是专门为修复这个漏洞升级的版本。

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-f9c848555574079a9d163d0f8464a8410406990a.png)

commit标题为

```Java
fix(测试计划): 修复自定义插件安全漏洞及用例模块匹配问题

```

对应着两处代码修改。跟修复漏洞相关的无疑是这一处。

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-0910f09fcc0380a64309b4f00fae9dcde2b67eae.png)

补丁中删除了/plugin/路径的匿名访问。因此漏洞分析着重看这一部分路由的代码逻辑。直接在代码种全局搜索/plugin，很快可以定位到io.metersphere.controller.PluginController，该类处理/plugin路由。其中包含了5种方法，方法不多因此依次分析。

```JavaScript
    @PostMapping("/add")
    public String create(@RequestPart(value = "file", required = false) MultipartFile file) {
        if (file == null) {
            MSException.throwException("上传文件/执行入口为空");
        }
        return pluginService.editPlugin(file);
    }

    @GetMapping("/list")
    public List<PluginDTO> list(String name) {
        return pluginService.list(name);
    }

    @GetMapping("/get/{id}")
    public Plugin get(@PathVariable String id) {
        return pluginService.get(id);
    }

    @GetMapping("/delete/{id}")
    public String delete(@PathVariable String id) {
        return pluginService.delete(id);
    }

    @PostMapping(value = "/customMethod")
    public Object customMethod(@RequestBody PluginRequest request) {
        return pluginService.customMethod(request);
    }
```

第一个add方法， 可以看到上传了一个文件，并调用pluginService的editPlugin方法，跟进这个方法。

```JavaScript
public String editPlugin(MultipartFile file) {
    String id = UUID.randomUUID().toString();
    String path = FileUtils.create(id, file);
    if (StringUtils.isNotEmpty(path)) {
        List<PluginResourceDTO> resources = this.getMethod(path, file.getOriginalFilename());
        if (CollectionUtils.isNotEmpty(resources)) {
            for (PluginResourceDTO resource : resources) {
                PluginExample example = new PluginExample();
                example.createCriteria().andPluginIdEqualTo(resource.getPluginId());
                List<Plugin> plugins = pluginMapper.selectByExample(example);
                if (CollectionUtils.isNotEmpty(plugins)) {
                    String delPath = plugins.get(0).getSourcePath();
                    // this.closeJar(delPath);
                    FileUtils.deleteFile(delPath);
                    pluginMapper.deleteByExample(example);
                }
                this.create(resource, path, file.getOriginalFilename());
            }
        }
    }
    return null;
}
```

首先会随机生成一个文件名，并调用FileUtils.create方法创建这个文件。

```JavaScript
    private List<PluginResourceDTO> getMethod(String path, String fileName) {
        List<PluginResourceDTO> resources = new LinkedList<>();
        this.loadJar(path);
        List<Class<?>> classes = CommonUtil.getSubClass(fileName);
        try {
            for (Class<?> aClass : classes) {
                Object instance = aClass.newInstance();
                Object pluginObj = aClass.getDeclaredMethod("init").invoke(instance);
                if (pluginObj != null) {
                    PluginResourceDTO pluginResourceDTO = new PluginResourceDTO();
                    BeanUtils.copyBean(pluginResourceDTO, (PluginResource) pluginObj);
                    pluginResourceDTO.setEntry(aClass.getName());
                    resources.add(pluginResourceDTO);
                }
            }
        } catch (Exception e) {
            LogUtil.error("初始化脚本异常：" + e.getMessage());
            MSException.throwException("调用插件初始化脚本失败");
        }
        return resources;
    }
```

这里会调用LoadJar方法

```JavaScript
    private void loadJar(String jarPath) {
        File jarFile = new File(jarPath);
        // 从URLClassLoader类中获取类所在文件夹的方法，jar也可以认为是一个文件夹
        Method method = null;
        try {
            method = URLClassLoader.class.getDeclaredMethod("addURL", URL.class);
        } catch (NoSuchMethodException | SecurityException e1) {
            e1.printStackTrace();
        }
        // 获取方法的访问权限以便写回
        try {
            method.setAccessible(true);
            // 获取系统类加载器
            URLClassLoader classLoader = (URLClassLoader) ClassLoader.getSystemClassLoader();

            URL url = jarFile.toURI().toURL();
            //URLClassLoader classLoader = new URLClassLoader(new URL[]{url});

            method.invoke(classLoader, url);
        } catch (Exception e) {
            LogUtil.error(e);
        }
    }
```

这个方法执行URLClassloader.addURL(jarPath)方法，相当于把我们传入的文件路径加入了classpath列表。完成后回到上个方法，继续往下走，会调用CommonUtil.getSubClass(fileName);

```JavaScript
    public static List<Class<?>> getSubClass(String fileName) {
        List<Class<?>> classes = new LinkedList<>();
        try {
            if (StringUtil.isNotEmpty(fileName) && fileName.endsWith(".jar")) {
                fileName = fileName.substring(0, fileName.length() - 4);
            }
            LogUtil.info("获取到文件路径：" + fileName);
            Resource resource = new ClassPathResource(fileName);
            Properties inPro = PropertiesLoaderUtils.loadProperties(resource);
            if (inPro != null) {
                LogUtil.info("开始读取文件内容进行反射处理");
                Set<String> entryObj = inPro.stringPropertyNames();
                if (entryObj != null) {
                    for (String entry : entryObj) {

                        Class<?> clazz = Class.forName(entry);
                        classes.add(clazz);

                    }
                }
            }
        } catch (Exception e) {
            MSException.throwException("解析插件失败，未找到入口配置");
        }
        return classes;
    }

```

这里会将我们传入的jar包中PropertiesLoaderUtils.loadProperties能找到的属性类都调用Class.forName加入到内存中。

到这里，漏洞的第一步也就很清晰了，我们可以上传一个恶意的jar包，其中包含了我们传入的恶意class文件，并且在jar包中的属性配置中，设置为我们传入的类的名字。从而服务端就会加载我们传入的恶意类到内存。接下俩需要找一个会实例化我们传入类的地方。也就是漏洞执行的第二步。

哪里会实例化呢？我们回到io.metersphere.controller.PluginController类中，对其中的方法进行分析，很快可以发现最后一个路径，/customMethod，存在对应的调用。

该方法调用的是pluginService.customMethod方法

```JavaScript
public Object customMethod(PluginRequest request) {
    try {
        Class<?> clazz = Class.forName(request.getEntry());
        Object instance = clazz.newInstance();
        Object pluginObj = clazz.getDeclaredMethod("customMethod", String.class).invoke(instance, request.getRequest());
        return pluginObj;
    } catch (Exception ex) {
        LogUtil.error("加载自定义方法失败：" + ex.getMessage());
    }
    return null;
}
```

这个方法，会实例化我们传入的任意类，并调用该类的customMethod方法，因此整条链就连起来了。

#### 修复补丁

官方使用的修复方法是将存在漏洞的路径增加权限控制。但是存在权限的用户还是可以利用该功能远程命令执行。这里我不太明白，官方这里的修复行为应该意为许可后台用户是有控制主机的权限，但是同时又在之前的版本中修复了多个后台漏洞，并给了CVE编号。