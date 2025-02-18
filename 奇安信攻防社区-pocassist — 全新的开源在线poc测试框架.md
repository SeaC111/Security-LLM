[pocassist](https://github.com/jweny/pocassist) 是一个 Go (Golang) 编写的全新的开源漏洞测试框架，实现对poc的在线编辑、管理、测试。

如果你不想撸代码，又想实现poc的逻辑，又想在线对靶机快速测试，那就使用pocassist吧。

项目地址：<https://github.com/jweny/pocassist>

0x01 特性
-------

### 规则体系

- pocassist借鉴了xray优秀的规则体系。通过基于CEL表达式定义poc规则。
- 完全兼容xray现有规则。
- 不仅仅是xray。pocassist除了支持定义目录级漏洞poc，还支持服务器级漏洞、参数级漏洞、url级漏洞以及对页面内容检测，如果以上还不满足你的需求，还支持加载自定义脚本。

### 性能

高并发：支持批量运行poc，通过使用 `ants`实例化协程池，复用 goroutine ，节省资源，提升性能。

### 资源

小内存占用：使用内存复用机制。每个poc / 请求 / 响应 均使用`sync.Pool` 来缓存对象，减轻GC消耗。

### 易用

pocassist 为单二进制文件，无依赖，也无需安装，下载后直接使用。

0x02 Demo
---------

![登录页](https://shs3.b.qianxin.com/butian_public/f2483161ff57b942da271a96f78d404fd864742a6d150.jpg)

### poc管理

![poc](https://shs3.b.qianxin.com/butian_public/f9796628849e46470a5b859947f70062c27db64578dd0.jpg)

poc在线编辑

![poc编辑](https://shs3.b.qianxin.com/butian_public/f7666241168c43b501f72b4d559c07ee7d20b1c0286c5.jpg)

poc在线运行

![poc运行结果](https://shs3.b.qianxin.com/butian_public/f208799c322b22d164f36bd4f196ed9d9970dc039df9d.jpg)

### 漏洞管理

每个poc可以关联配套的漏洞描述。

![漏洞描述](https://shs3.b.qianxin.com/butian_public/f652867eeb3cde46cc97deda079d8a9104f1fa0a3a98e.jpg)

![漏洞描述详情](https://shs3.b.qianxin.com/butian_public/f467817d36bbf4c25c7aaf408c17446a301fbcebf5afc.jpg)

0x03 快速开始
---------

### 下载

直接下载相应系统构建的二进制文件即可，下载时选择最新的版本。

下载地址：<https://github.com/jweny/pocassist/releases/>

### 运行

pocassist分为两种模式：

- web：提供web页面进行在线poc编辑和测试
- cli：提供批量扫描功能

![image-20210523182641503](https://shs3.b.qianxin.com/butian_public/f79516482e88ed9764ed8376c49261a2ecc740eb07343.jpg)

如使用默认配置，可直接运行二进制文件。这里以pocassist\_darwin\_amd64为例：

`./pocassist_darwin_amd64 -h`

#### 全局参数

pocassist 的全局参数是启动的基础参数，webserver 和 cli 都将继承全局参数。

![image-20210521114002361](https://shs3.b.qianxin.com/butian_public/f3287332d76d810660f5f065d34e1a6b3443634536fa3.jpg)

```php
-h, --help            显示此帮助消息并退出
-b, --database              选择后端的数据库类型，目前支持sqlite和mysql，默认sqlite
-d, --debug           是否启用debug模式，debug模式将输出程序运行过程中的更多细节，默认false
-v, --version         显示版本并退出
```

#### web端

pocassist的server模块是整个项目的核心，通过web实现在线poc编辑。

![image-20210523183024140](https://shs3.b.qianxin.com/butian_public/f97407512a73bf6ca3a2f68445d3a8aa7855f8ce857e5.jpg)

```php
-h, --help            显示此帮助消息并退出
-p, --port                      server的启动端口，默认1231
```

运行web端，默认1231端口。：

`./pocassist_darwin_amd64 server`

自定义端口，如8888：

`./pocassist_darwin_amd64 server -p 8888`

默认账号密码：`admin/admin2`

#### cli

pocassist的cli模块主要是实现批量扫描功能：提供批量加载目标、批量加载poc进行检测。

`/pocassist_darwin_amd64 cli -h`

![image-20210521120042659](https://shs3.b.qianxin.com/butian_public/f67303060d1631381eb6dc304c79bcce95d04b982b2bc.jpg)

```php
-h, --help            显示此帮助消息并退出
# 加载目标
-u, --url                           单个url (e.g. -u https://github.com)
-f, --urlFile               选择一个目标列表文件,每个url必须用行来区分 (e.g. -f "/home/user/list.txt")
-r, --urlRaw                    从一个请求报文文件中加载单个测试目标
# 加载poc
-l, --loadPoc               poc插件加载模式
-o, --condition             poc插件加载条件
```

注意：

poc插件有以下四种加载模式（`loadPoc`的值）：

- single：加载单个插件
- multi：加载多个插件，多个插件用逗号隔开
- all：加载所有插件
- affects：加载某一类插件。

`condition`是与`loadPoc`配套使用的，关系如下：

- 加载模式为`single`时：`condition`为poc\_id，如 `poc-db-001`
- 加载模式为`multi`时：`condition`为多个poc\_id，用逗号隔开。如 `poc-db-001,poc-db-002`
- 加载模式为`all`时：无需指定condition`。
- 加载模式为`affects`时：`condition`为数据库中plugins表的affects字段的值，也就是前端的`规则类型`。如只加载目录级漏洞的poc可指定为"directory"。目前有以下值：
    
    directory / text / url / server / script / appendparam / replaceparam

0x04 个性化配置
----------

下载的release中，会包含一个`config.yaml`文件。该文件中的配置项将直接运行pocassist在运行时的状态。

注意：

- 在修改某项配置时，请务必理解该项的含义后再修改，否则可能会导致非预期的情况发生。
- 当前pocassist正在快速迭代，不保证配置文件向后兼容。请保证使用相同版本release中pocassist二进制和配置文件。

### server运行配置

pocassist的webserver使用gin开发。在配置文件中可以使用以下配置修改gin的启动模式：

```php
serverConfig:
    # 配置jwt秘钥
  jwt_secret: "pocassist"
  # gin的运行模式 "release" 或者 "debug"
  run_mode: "release"                               
  # 运行日志的文件名，日志将保存在二进制所在目录
  log_name : "debug.log"                            
```

### HTTP配置

对于 web 扫描来说，http 协议的交互是整个过程检测过程的核心。

因此这里的配置将影响到pocassist在poc运行时进行 http 发包时的行为。

```php
httpConfig:
  # 扫描时使用的代理：格式为 IP:PORT，example: 如 burpsuite，可填写 127.0.0.1:8080
  proxy: ""
  # 读取 http 响应超时时间，不建议设置太小，否则可能影响到盲注的判断
  http_timeout: 10
  # 建立 tcp 连接的超时时间
  dail_timeout: 5
  # udp 超时时间
  udp_timeout: 5
  # 每秒最大请求数
  max_qps: 100
  # 单个请求最大允许的跳转次数
  max_redirect: 5
  headers:
    # 默认 UA
    user_agent: "Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0"
```

注意：

- 使用代理：配置该项后漏洞扫描发送请求时将使用代理发送。目前pocassist仅支持http代理，因此配置代理时仅提供`IP:PORT`即可。
- 每秒最大请求数：默认100，这里限制发包速度。通常是为了防止被ban才会将该值调的小一些。

### 数据库配置

pocassist支持sqlite和mysql两种数据库类型。

```php
dbConfig:
  # sqlite配置：sqlite数据库文件的路径
  sqlite : "pocassist.db"
  # mysql配置
  mysql:
    host: "127.0.0.1"
    password: ""
    port: "3306"
    user: "root"
    database: "pocassist"
    # 数据库连接超时时间
    timeout: "3s"
```

### 并发配置

pocassist 基于 Go 编写。通过使用 `ants`实例化协程池，复用 goroutine ，节省资源，提升性能。所以，这里的并发也基本指代的是同时在进行漏洞扫描的 Goroutine 的数量。

通俗来讲就是同时运行的插件数量。假设一个请求在整个扫描流程中需要被 100 个插件扫描且每个插件的执行时间为1秒钟， 倘若我们设置了并发为 50，那么只需要 2s 就能执行完所有的插件；如果设置并发为 20，那么就需要 5s 才能执行完所有插件。

```php
pluginsConfig:
  # 并发量:同时运行的插件数量
  parallel: 8
```

### 反连平台

反连平台常用于解决没有回显的漏洞探测的情况，最常见的应该属于 ssrf 和 存储型xss。

目前pocassist支持的反连平台为[ceye.io](http://ceye.io/)，配置ceye的`api_key`和`domain`即可。

```php
# 反连平台配置: 目前使用 ceye.io
reverse:
  api_key: ""
  domain: ""
```

0x05 poc编辑手册
------------

![image-20210521170258960](https://shs3.b.qianxin.com/butian_public/f57873364bfa384a0e4a3b74e3a82d3866d652e673c3d.jpg)

poc编辑主要分为两大块：

### 规则内容

熟悉xray规则的师傅，看到“规则内容” 这部分就很熟悉了。pocassist借鉴了xray优秀的规则体系，将xray规则中的所有的变量、方法全部实现注入到cel环境中，也就是说pocassist完全兼容xray所有规则。

因此该模块的编写可以参考xray规则的[编辑手册](https://docs.xray.cool/#/guide/poc)。

注意：

- 无论是哪种`规则类型`，`请求路径 path` 字段均必须以`/`开头。
- 如果定义了多个`请求头 headers`，填写完之后必须先点击一下保存请求头按钮，否则不会保存请求头。

### 规则类型

pocassist poc 运行时发起的请求由 原始请求 + 规则内容 共同决定。

这部分最关键的就是`规则类型`。规则类型的不同，检测过程中的最终请求uri 和 参数是完全不同的。

pocassist定义了以下几种类型。

#### 1. directory

目录型扫描。检测目标为目录，请求头使用规则定义。

poc运行时发起的请求路径为`原始请求路径 + "/" + 规则中定义的path`。请求头使用规则定义。

例如：

输入目标为 `https://jweny.top/aaa/bbb/` ，规则中定义的path为 `/user/zs.php?do=save`，poc运行时的请求路径为`https://jweny.top/aaa/bbb/user/zs.php?do=save`

#### 2. text

页面内容检测。检测目标为原始请求的响应，因此直接使用原始请求请求头。

poc运行时发起的请求直接为原始请求。

也就是说该类型的poc只需要定义cel表达式。（其他字段即使填写也会被忽略）

#### 3.url

url级漏洞检测。检测路径为原始请求的uri，除了路径外，均使用规则定义。

poc运行时发起的请求路径为原始请求的路径，请求头、请求方法、post body等均使用规则定义。

#### 4. server

server级漏洞检测。检测路径为原始请求的`server:port`+规则中定义的path，其他均使用规则定义。

poc运行时发起的请求路径为`server:port`+规则path，请求头、请求方法、post body等均使用规则定义。

例如：

输入目标为 `https://jweny.top/aaa/bbb.cc.php` ，规则中定义的path为 `/user/zs.php?do=save`，poc运行时的请求路径为`https://jweny.top/user/zs.php?do=save`

#### 5. script

脚本检测。脚本检测目前只支持开发者模式，也就是说直接使用release二进制是无法加载到引擎中的。（该缺陷正在紧急修复）。

脚本检测的poc只需要在前端配置`漏洞编号、规则类型、是否启用、漏洞描述、规则内容中的名称`即可，没有配置的话，脚本不会加载到引擎中。

![image-20210521182719146](https://shs3.b.qianxin.com/butian_public/f2553533bf9df993e9958040dad602906bb0b460f509d.jpg)

前端配置完基础信息，可以在scripts目录下编写go脚本。源码中已提供两个demo，一个是检测memcached未授权，一个是检测tomcat弱口令。

```php
func MemcachedUnauthority(args *ScriptScanArgs) (*util.ScanResult, error) {
    addr := args.Host + ":11211"
    payload := []byte("stats\n")
    resp, err := util.TcpSend(addr, payload)
    if err != nil {
        return nil, err
    }
    if bytes.Contains(resp, []byte("STAT pid")) {
        return util.VulnerableTcpOrUdpResult(addr, "",
            []string{string(payload)},
            []string{string(resp)},
        ),nil
    }
    return &util.InVulnerableResult, nil
}

func init() {
    ScriptRegister("poc-go-memcached-unauth", MemcachedUnauthority)
}
```

说明：

- 脚本的入参必须为`*ScriptScanArgs`，返回值必须为`(*util.ScanResult, error)`。
- 脚本中必须定义`init`方法用来注册脚本，`ScriptRegister`方法的第一个值为`前端配置的规则内容中的名称`，第二个为要运行的方法名。
- 脚本编写完之后重新编译pocassist。`go build -o pocassist`

#### 6. appendparam

参数级漏洞检测。

目前仅解析了`query string`和`post body` 中的参数（json解析已在计划中）。

参数级漏洞检测只需要在前端配置payload列表（目前前端未显示，下一版修复）。

appendparam为依次在每个参数值后面拼接payload。

例如，检测sql注入时，可定义payload为`'` / `%2527` 等，原始请求为`?aaa=bbb`，那么poc运行时会依次发两个请求，`?aaa=bbb'`和`?aaa=bbb%2327`

#### 7. replaceparam

参数级漏洞检测。

目前仅解析了`query string`和`post body` 中的参数（json解析已在计划中）。

参数级漏洞检测只需要在前端配置payload列表（目前前端未显示，下一版修复）。

replaceparam为依次直接使用payload替换原始参数值。

例如，检测ssrf时，可定义payload定义为反连平台的domain，原始请求为`?aaa=bbb`，那么poc运行时发起的请求为`?aaa=你的reverseDomain'`

0x06 常见问题
---------

1. config.yaml 加载失败：config.yaml要与pocassist二进制文件放置于同一目录中。
2. 使用mysql时，数据库初始化失败：如果后端使用mysql数据库，一定先创建数据库，导入数据，并将数据库信息更新至config.yaml后，再运行pocassist。
3. 目前前端有一个小bug，首次登陆成功之后，跳转至/vul时会显示空，需要强制刷新下。
4. `go get ./... connection error`
    
    启用goproxy（请参阅此[文章](https://madneal.com/post/gproxy/)以进行golang升级）：
    
    ```php
    go env -w GOPROXY=https://goproxy.cn,direct
    go env -w GO111MODULE=on
    ```
5. 如果使用前后端分离部署的师傅可自行打包前端。
    
    <https://github.com/jweny/pocassistweb>

0x07 todo
---------

- 收集师傅们在使用过程中遇到的问题
- 目前cli端的批量快扫功能为临时方案，后续所有批量快扫功能web端都将支持。
- 发现潜在bug
- json参数解析
- 修复前端bug 
    - 初次加载时要强制刷新
    - 参数级扫描：payload列表前端未提供在线编辑

0x08 免责声明
---------

未经授权，使用pocassist攻击目标是非法的。pocassist仅用于安全测试目的。

为避免被恶意使用，本项目所有收录的poc均为漏洞的理论判断，不存在漏洞利用过程，不会对目标发起真实攻击和漏洞利用。

0x09 参考项目
---------

- <https://github.com/chaitin/xray/tree/master/pocs>
- <https://phith0n.github.io/xray-poc-generation/>
- <https://github.com/jjf012/gopoc>
- <https://codelabs.developers.google.com/codelabs/cel-go#0>