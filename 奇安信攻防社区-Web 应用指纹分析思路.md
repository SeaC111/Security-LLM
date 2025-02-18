0x01 写在前面
---------

Web 指纹识别虽然已经是老生常谈的话题，但其在漏洞挖掘 / 漏洞治理的过程中仍然有着举足轻重的作用：

- 红军：资产建模、漏洞应急时风险的快速收敛
- 蓝军：信息收集、漏洞挖掘过程中的针对组件漏洞的精准
- 空间测绘
- ...

实际落地时，无论甲方场景还是乙方场景，基本都是构建指纹体系，通过对指纹库的持续运营实现。指纹库通常由【Web 组件】 + 【识别该组件的规则】组成，识别过程通过解析流量，查找匹配的规则，输出指纹。本文中将着重分析下指纹识别体系建设的一些维度和实现思路。

大纲：  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-d66637c058edebcec191cbcab70135ba73340c55.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-d66637c058edebcec191cbcab70135ba73340c55.png)

0x02 识别模式
---------

### 主动识别

主动识别逻辑比较简单。主动访问特定的 URL ，从响应中提取特征信息，从而判定是否为某个 Web 组件。

例如：识别`OFBiz`，可主动访问`/myportal/control/main`，检查 Cookie 和响应 body 是否包括 `OFBiz` /`ofbiz` 等字样。

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-c624e3a5809d67a576f378327dc3af573896e088.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-c624e3a5809d67a576f378327dc3af573896e088.png)

### 被动识别

被动接收所有流量，也就是说并不会额外发送请求。每条响应再去逐一匹配指纹库的每条规则。

请求数据源可来源于：

- 爬虫：基于 `Chrome` 的爬虫，为了应对 js 动态页面
- 浏览器代理插件
- 对于甲方场景，可直接识别流量镜像

这里有几个场景急需解决：

1. 减少发包次数：消息队列记录已发的包。
2. 流量去重：被动识别的匹配次数是 `响应数 * 规则数`。为了降低轮训匹配的大量消耗，可以对爬虫 / 镜像中的流量进行去重，可大幅度减少要检测的响应数。对于相似流量比对，可参考[腾讯src的策略](https://www.secrss.com/articles/34442)。
3. 资源调度：请求、去重、识别各模块使用消息队列通信，便于水平扩展。

0x03 指纹特征维度
-----------

获取响应后可通过以下维度进行特征匹配。多个维度可以同时设定特征规则，最后通过加权计算后，输出指纹识别结果。

### 1.分析HTTP响应头

根据响应头中的信息进行匹配。重点关注 HTTP 的以下响应头，如：

- `Server`
- `X-Powered-by`
- `Set-Cookie`
- 其他可能带有明显特征的头，例如`WWW-Authenticate`

### 2.分析HTML

分析

1. 特殊文本。响应的HTML中有明显的关键字。例如： `Powered By XXX`
2. CSS 类选择器。例如： `<body class="ke-content">`
3. Meta 标签。例如： `<meta name="version" content="neblog-1.0">`
4. script标签。一般检测bootstrap、jQuery等前端框架。例如：`<script src="http://example.com/js/bootstrap.min.js"></script>`
5. 其他特殊字段

### 3.分析URL特征

1. 特有的目录结构特征。例如 `wordpress` 默认带有 `readme.html` ，以及 `wp-admin`、`wp-content/uploads` 等目录；`weblogic` 可能使用 `wls-wsat` 目录
2. 错误页面。识别已有的错误页面响应，或主动构造错误页面，根据报错信息来判断。例如`Apache` 默认的404页面、`Tomcat` 的报错页面、`Mysql` 默认SQL错误信息
3. `robots.txt`。例如 `Discuz` 的默认 `robots.txt`
4. 带有明显特征文件的 `Hash`（通常计算 `MD5` ）。例如：通用的特征文件，如 `favicon.ico`、`css`、`logo.ico`、`js`等文件一般不会修改；其他带有明显特征的文件。例如 `Dedecms` 的 `/img/buttom_logo.gif`

### 4.主机端口特征

1. 默认端口。例如1443、306、27017
2. 端口交互特征。例如获取banner
3. 借助 nmap 操作系统指纹
4. SSL 证书信息

0x04 一些想法
---------

指纹识别看似简单的领域，其实深入研究后还是有很多值得钻研的点的，例如：

- 未知指纹的自动特征提取
- 流量建模提取共性
- 不同维度的权重
- 指纹字典的加载权重：历史记录命中率高的先加载
- 提升性能：任务动态调度、及时中断、异常处理等

如果有师傅有任何问题，或者想参与到指纹识别模块的开发中来，欢迎与我联系。