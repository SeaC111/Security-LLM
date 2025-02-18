如何打造好用的ModSecurity系列 Part 2
===========================

前言
--

在第一部分[Part 1](https://forum.butian.net/share/258)简单介绍了如何安装并使用ModSecurity，第二部分将重点讲述其优秀的规则体系是怎么实现的，用户在使用的时候应该如何利用好这些机制。

三、引擎规则体系
--------

### 3.1 规则引擎配置

规则引擎的配置文件位于modsecurity.conf文件中，主要控制waf引擎的行为，下面介绍一些重要的参数，在使用过程中，可以根据业务情况，自己进行查看设置。

1. SecRuleEngine：On/Off/Detection Only分别代表开启或关闭waf，和只检测但不进行任何阻断操作
2. SecRequestBodyAccess：是否允许waf检测request body，一般都会打开
3. request body格式解析：目前modsecurity额外支持xml、json、multipart的解析
    
    Content-Type为`(?:application(?:/soap\+|/)|text/)xml`的使用xml解析引擎，`application/json`的使用json解析引擎
    
    并设置了`REQBODY_ERROR`参数用于在解析request body过程中出现错误的记录，对于multipart格式，专门设置了`MULTIPART_STRICT_ERROR`参数，并根据错误类型进行严格的记录
    
    ```json
    PE %{REQBODY_PROCESSOR_ERROR}, \
    BQ %{MULTIPART_BOUNDARY_QUOTED}, \
    BW %{MULTIPART_BOUNDARY_WHITESPACE}, \
    DB %{MULTIPART_DATA_BEFORE}, \
    DA %{MULTIPART_DATA_AFTER}, \
    HF %{MULTIPART_HEADER_FOLDING}, \
    LF %{MULTIPART_LF_LINE}, \
    SM %{MULTIPART_MISSING_SEMICOLON}, \
    IQ %{MULTIPART_INVALID_QUOTING}, \
    IP %{MULTIPART_INVALID_PART}, \
    IH %{MULTIPART_INVALID_HEADER_FOLDING}, \
    FL %{MULTIPART_FILE_LIMIT_EXCEEDED}
    ```
    
    modsecurity对于multipart解析进行了严格的格式校验，也就是说一般的绕过waf的方式，可能会因为格式校验不通过而失败，具体在multipart解析层面对waf的绕过可以参考[从RFC看如何绕过waf文件上传表单](https://www.anquanke.com/post/id/241265)，简单测试一下在boundary处的绕过waf的小trick
    
    [![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-26e88863220731dc83327c27179877aae5cd346d.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-26e88863220731dc83327c27179877aae5cd346d.png)
    
    直接400了，查看nginx日志能看到详细信息
    
    [![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-eaccfd2e9a3a91cac2391d02501e559b96a32a59.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-eaccfd2e9a3a91cac2391d02501e559b96a32a59.png)  
    `BQ MULTIPART_BOUNDARY_QUOTED`为1，格式校验失败，当然这种严格的格式校验有误报的可能性，但也相对来说增加了绕过waf的难度。
4. SecResponseBodyAccess：是否允许waf检测响应包response body
5. SecDebugLogLevel：调试日志级别，不建议设置太高，增加性能消耗
    
    [![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-4fc49ac492707704ade162bb86e093778c4f97c6.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-4fc49ac492707704ade162bb86e093778c4f97c6.png)
6. SecAuditEngine/SecAuditLogRelevantStatus 仅为状态代码与提供的正则表达式匹配的事务配置审计日志记录。默认将记录所有 5xx 和 4xx 级别的状态代码，404 除外。
7. SecAuditLogParts： 每个事务中记录到审计日志中的部分，默认ABIJDEFHZ，具体取值可参考
    
    ```json
    A：审计日志头（必须配置）
    B：请求头
    C：请求体（仅在请求体存在并且ModSecurity配置为拦截它时才存在。 这需要将SecRequestBodyAccess设置为On）
    D：该值是为中间响应头保留，尚未有任何实际作用
    E：中间响应体（仅当ModSecurity配置为拦截响应体并且审计日志引擎配置为记录时才存在。 拦截响应体需要将SecResponseBodyAccess设置为On）。 除非ModSecurity拦截中间响应体，否则中间响应体与实际响应体相同，在这种情况下，实际响应体将包含错误消息（Apache默认错误消息或ErrorDocument页面））
    F：最终响应头（不包括日期和服务器标题，Apache始终在内容交付的后期阶段添加）
    G：该值是为实际响应体保留，尚未有任何实际作用
    H：审计日志追踪内容；
    I：该部分是C的替代品。除了使用multipart/form-data编码，否则它在所有情况下记录的数据与C相同。 在这种情况下，它将记录一个假应用程序/ x-www-form-urlencoded正文，其中包含有关参数的信息，但不包含有关文件的信息。 如果您不想在审核日志中存储（通常很大）的文件，使用I比使用C更方便。
    J：该部分包含有关使用multipart/form-data编码上传的文件的信息。
    K：该部分包含了本次访问中所匹配到的所有规则（按每行一个进行记录）。规则是完全合格的，因此将显示继承的操作和默认操作符。V2.5.0以上支持。
    Z：结尾分界线，表示本次日志记录完毕（必须配置）
    ```

### 3.2 规则体系解析

#### 3.2.1 ModSecurity事务生命周期

每个事务在modsecurity需要经历5个阶段，在每个阶段可能需要解析等操作，然后调用相应阶段的规则进行匹配，对应规则中的`phase`

[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-ef3f2c9d55201e5aca90060ab949bc707b6d32a1.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-ef3f2c9d55201e5aca90060ab949bc707b6d32a1.png)

阶段一：request headers请求头，这是modsecurity最先接触到的数据，需要验证请求头相关的规则，并根据请求头来判断如何解析request body

阶段二：request body请求体，此阶段需要根据请求头正确解析body数据，并验证request body相关的规则

阶段三：response headers响应头，在获取到响应头之后，验证response header相关的规则

阶段四：response body响应体，正确解析响应体数据之后，验证response body相关的规则

阶段五：logging日志记录，日志记录阶段是一定存在的，用于记录事务信息，包括命中规则信息，处理方式等。

#### 3.2.2 ModSecurity全局规则配置级别

modsecurity根据规则可能存在的误报情况，设置了规则的级别，称之为PL(paranoia level)，共有4个级别，分别为1/2/3/4，级别越高，漏报越少，误报越多。用户可以根据实际业务情况适当调整，默认设置PL=1，可以在crs-setup.conf中设置

```php
SecAction \
  "id:900000,\
   phase:1,\
   nolog,\
   pass,\
   t:none,\
   setvar:tx.paranoia_level=1"
```

其规则的分级方式也很特别，是通过在规则文件中的位置进行的分级，下面简化下分级规则设置方法

- 级别规则设置方法：skipAfter和SecMarker
    
    skipAfter：条件达成，跳到下个标记点
    
    SecMarker：规则标记点
- 规则结构

```yaml
SecRule TX:EXECUTING_PARANOIA_LEVEL "@lt 1" "id:920011,phase:1,pass,nolog,skipAfter:END-REQUEST-920-PROTOCOL-ENFORCEMENT"   # PL<1，跳到SecMarker，全部规则无法应用

#一级规则

SecRule TX:EXECUTING_PARANOIA_LEVEL "@lt 2" "id:920013,phase:1,pass,nolog,skipAfter:END-REQUEST-920-PROTOCOL-ENFORCEMENT"   # PL<2，跳到SecMarker，二级、三级、四级规则无法应用

#二级规则

SecRule TX:EXECUTING_PARANOIA_LEVEL "@lt 3" "id:920015,phase:1,pass,nolog,skipAfter:END-REQUEST-920-PROTOCOL-ENFORCEMENT"   # PL<3，跳到到SecMarker，三级、四级规则无法应用

#三级规则

SecRule TX:EXECUTING_PARANOIA_LEVEL "@lt 4" "id:920017,phase:1,pass,nolog,skipAfter:END-REQUEST-920-PROTOCOL-ENFORCEMENT"   # PL<4，跳到SecMarker，四级规则无法应用

#四级规则

SecMarker "END-REQUEST-920-PROTOCOL-ENFORCEMENT"
```

所以使用skipAfter和SecMarker，并在每个conf文件中按照级别确定好规则的位置，就可以实现规则分级。

这里的规则分级不仅给每个规则通过位置进行级别的设置，crs还给每个级别的规则进行了字符的限制，用于防御未知的攻击，这部分内容将在后续规则详细解析中介绍。

测试一下，将PL设置为1，然后发送攻击请求，此攻击请求只能命中PL2级别（以932200为例）的规则，但是无法命中PL1规则，此规则为了防护`;cat$u+/etc$u/passwd`的命令注入

```json
# 二级命令注入绕过方式，误报比较高。含有$a 或 \a 或 *a/通配符，并且含有/和\s
SecRule REQUEST_COOKIES|!REQUEST_COOKIES:/__utm/|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/* "@rx (?:[*?`\\'][^/\n]+/|\$[({\[#a-zA-Z0-9]|/[^/]+?[*?`\\'])" \
    "id:932200,\
    phase:2,\
    block,\
    capture,\
    t:none,t:lowercase,t:urlDecodeUni,\
    msg:'RCE Bypass Technique',\
    logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',\
    tag:'application-multi',\
    tag:'language-multi',\
    tag:'platform-multi',\
    tag:'attack-rce',\
    tag:'paranoia-level/2',\
    tag:'OWASP_CRS',\
    tag:'capec/1000/152/248/88',\
    tag:'PCI/6.5.2',\
    ver:'OWASP_CRS/3.4.0-dev',\
    severity:'CRITICAL',\
    chain"
    SecRule MATCHED_VAR "@rx /" "t:none,t:urlDecodeUni,chain"
        SecRule MATCHED_VAR "@rx \s" "t:none,t:urlDecodeUni,\
            setvar:'tx.lfi_score=+%{tx.critical_anomaly_score}',\
            setvar:'tx.anomaly_score_pl2=+%{tx.critical_anomaly_score}'"
```

发送攻击请求，返回200

[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-08588c99a7332970a5bae6e888eb97afdeb4bfa9.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-08588c99a7332970a5bae6e888eb97afdeb4bfa9.png)

切换为PL=2，在进行测试，直接返回403

[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-2ef552849e0edaeae1d2e53b9b0edb43905182ed.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-2ef552849e0edaeae1d2e53b9b0edb43905182ed.png)

#### 3.2.3 ModSecurity检测模式

检测模式的配置在crs-setup.conf中，具体通过`SecDefaultAction`来进行配置

1. Self-contained mode：自主机制
    
    ```php
    SecDefaultAction "phase:1,log,auditlog,deny,status:403"
    SecDefaultAction "phase:2,log,auditlog,deny,status:403"
    ```
    
    这种机制是非常传统的简单的方式，只要命中其中一条规则，就直接进行拦截，返回403，也可以设置其他动作，各规则之间没有任何联系，当然可以通过规则链的写法进行弥补规则之间的联系，这种优点明显，学习和使用难度很小，理解简单，并且在性能上很优秀，命中规则直接拦截，不需要后续的处理。但是对于目前庞大的规则体系里，使用这种模式肯定是要删除掉大量规则的，比如一些根据rfc进行校验的规则，简单举个例子，将模式设置为自主模式，并且直接403拦截
    
    [![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-6b805da34f051831e77ce43046b7ff8014a15adf.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-6b805da34f051831e77ce43046b7ff8014a15adf.png)
    
    此请求会被直接403拦截，原因不过是请求得Host是一个ip地址而不是一个域名！所以对于一些本来只需要警告或者提醒的规则，使用自主模式，会造成误报，并且很多规则没法使用。
    
    [![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-1e597ad8ea956d66349a64b81686b78b40e286ca.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-1e597ad8ea956d66349a64b81686b78b40e286ca.png)
    
    
    2. Anomaly Scoring mode：评分机制，默认机制
    
    ```php
    SecDefaultAction "phase:1,log,auditlog,pass"
    SecDefaultAction "phase:2,log,auditlog,pass"
    ```
    
    这种评分机制作为默认机制，是crs体系优点之一，顾名思义，评分机制就是给每个规则赋予一个权重分数，当命中规则的权重分数增加到设定的拦截阈值时，进行拦截。使各条规则之间通过变量的方式进行联系，从而计算总体权重分。对于危险性或者说攻击性不足的规则给予小权重，对于确认很大可能为攻击的规则给与大权重，然后可以根据业务情况来设定拦截阈值，从而在误报和漏报之间寻找平衡，优点十分明显。但是这也增加了使用者的学习难度，加大了性能的消耗，再确认拦截之前需要去匹配大量的规则，并且需要设置变量并进行变量的计算，对性能是一种考验。
    
    crs对于判断不同类型规则的权重分数，有多种类型，并且可以根据各类型进行权重分的积累并设置对应阈值（901中可以看到）：
    
    ```json
    SecAction \
       "id:901200,\
       phase:1,\
       pass,\
       t:none,\
       nolog,\
       ver:'OWASP_CRS/3.4.0-dev',\
       setvar:'tx.anomaly_score=0',\
       setvar:'tx.anomaly_score_pl1=0',\
       setvar:'tx.anomaly_score_pl2=0',\
       setvar:'tx.anomaly_score_pl3=0',\
       setvar:'tx.anomaly_score_pl4=0',\
       setvar:'tx.sql_injection_score=0',\
       setvar:'tx.xss_score=0',\
       setvar:'tx.rfi_score=0',\
       setvar:'tx.lfi_score=0',\
       setvar:'tx.rce_score=0',\
       setvar:'tx.php_injection_score=0',\
       setvar:'tx.http_violation_score=0',\
       setvar:'tx.session_fixation_score=0',\
       setvar:'tx.inbound_anomaly_score=0',\
       setvar:'tx.outbound_anomaly_score=0',\
       setvar:'tx.outbound_anomaly_score_pl1=0',\
       setvar:'tx.outbound_anomaly_score_pl2=0',\
       setvar:'tx.outbound_anomaly_score_pl3=0',\
       setvar:'tx.outbound_anomaly_score_pl4=0',\
       setvar:'tx.sql_error_match=0'"
    ```
    
    901200是初始化权重分数用的，下面简单介绍几种权重的使用方式，在阈值判断中，默认使用949中的`anomaly_score`作为总分和阈值进行比较，达到阈值就进行拦截，其他权重分的计算目前只是在日志中记录，利于后续分析与调试。
    
    ##### 全局级别分类（severity）：
    
    将所有规则分为四类，分别为critical\_anomaly\_score/error\_anomaly\_score/warning\_anomaly\_score/notice\_anomaly\_score，对应严重，错误，警告，提醒四类，权重由高到低，默认其权重分数在crs-setup.conf中配置，分数对应为5/4/3/2
    
    ```json
    SecAction \
    "id:900100,\
     phase:1,\
     nolog,\
     pass,\
     t:none,\
     setvar:tx.critical_anomaly_score=5,\
     setvar:tx.error_anomaly_score=4,\
     setvar:tx.warning_anomaly_score=3,\
     setvar:tx.notice_anomaly_score=2"
    ```
    
    将modsecurity设置为评分机制，测试一下评分机制效果
    
    [![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-952fb8fd230618f4095fb3c2443bb9bb566f46c1.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-952fb8fd230618f4095fb3c2443bb9bb566f46c1.png)
    
    此请求和上面类似，并且设置Accept为空，用来积累权重分，我们看下详细日志
    
    [![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-e8a12be8c680db5bf54382a1f08da119bdfb1f3a.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-e8a12be8c680db5bf54382a1f08da119bdfb1f3a.png)
    
    很明显Accept为空是notice，权重为2，Host为ip地址权重为3，总分在`949-BLOCKING-EVALUATION`规则中被命中，因为总分为5，判断为critical严重级别直接进行拦截。
    
    继续查看`949-BLOCKING-EVALUATION`d中的949110规则
    
    ```json
    SecRule TX:ANOMALY_SCORE "@ge %{tx.inbound_anomaly_score_threshold}" \
       "id:949110,\
       phase:2,\
       deny,\
       t:none,\
       msg:'Inbound Anomaly Score Exceeded (Total Score: %{TX.ANOMALY_SCORE})',\
       tag:'application-multi',\
       tag:'language-multi',\
       tag:'platform-multi',\
       tag:'attack-generic',\
       ver:'OWASP_CRS/3.4.0-dev',\
       severity:'CRITICAL',\
       setvar:'tx.inbound_anomaly_score=%{tx.anomaly_score}'"
    ```
    
    此规则就是来验证总分是否不小于`tx.inbound_anomaly_score_threshold`阈值的，此参数可以在crs-setup.conf中设置，也可以在901规则文件中配置
    
    ```json
    # Default Inbound Anomaly Threshold Level (rule 900110 in setup.conf)
    SecRule &TX:inbound_anomaly_score_threshold "@eq 0" \
       "id:901100,\
       phase:1,\
       pass,\
       nolog,\
       ver:'OWASP_CRS/3.4.0-dev',\
       setvar:'tx.inbound_anomaly_score_threshold=5'"
    ```
    
    用户可以自定义这些权重分数和阈值来寻找平衡，个人认为应该将critical和notice/warning的权重分数拉大一些，其实在真实环境中，会出现各种奇怪的情况，但是这些都是正常得请求，如果简单的一个notice和warning规则就直接进行拦截，肯定会出现误报情况，所以应该将确认为攻击的规则权重直接设置为阈值，并将notice/warning规则权重减小，并多维度进行分析请求响应，如出现不明显攻击特征或者可能存在误报的数据，再进行拦截，而不是轻易拦截notice/warning积累的一些格式校验未通过的数据。
    
    ##### 漏洞类型分类：
    
    通过规则防护漏洞类型来进行分类，每一种漏洞类型的全部规则，都共享一个其相对应的权重分变量，如xss类型的规则都共享`tx.xss_score`变量，命中一个xss规则，`tx.xss_score`就会相应增加，增加的权重分数由此规则的级别而定也就是上文提到的全局规则的类型，严重，错误，警告，提醒四类
    
    ```json
    SecRule REQUEST_COOKIES|!REQUEST_COOKIES:/__utm/|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/* "@pm document.cookie document.write .parentnode .innerhtml window.location -moz-binding <!-- <![cdata[" \
       "id:941180,\
       phase:2,\
       block,\
       capture,\
       t:none,t:utf8toUnicode,t:urlDecodeUni,t:htmlEntityDecode,t:jsDecode,t:cssDecode,t:removeNulls,\
       msg:'Node-Validator Blacklist Keywords',\
       logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',\
       tag:'application-multi',\
       tag:'language-multi',\
       tag:'platform-multi',\
       tag:'attack-xss',\
       tag:'paranoia-level/1',\
       tag:'OWASP_CRS',\
       tag:'capec/1000/152/242',\
       ctl:auditLogParts=+E,\
       ver:'OWASP_CRS/3.4.0-dev',\
       severity:'CRITICAL',\
       setvar:'tx.xss_score=+%{tx.critical_anomaly_score}',\
       setvar:'tx.anomaly_score_pl1=+%{tx.critical_anomaly_score}'"
    ```
    
    上面这个规则就是，命中后，xss\_score增加critical\_anomaly\_score。简单测试一个利用多种漏洞攻击的请求
    
    [![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-6f111194d4cc8c25a82e7f77aee7289697ac1a9d.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-6f111194d4cc8c25a82e7f77aee7289697ac1a9d.png)
    
    查看日志，可以看到每种漏洞类型的积累分数
    
    [![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-a42c88db0b928c02adc61d110e33d9f321d555bf.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-a42c88db0b928c02adc61d110e33d9f321d555bf.png)
    
    ##### PL级别分类：
    
    上文提到modsecurity对规则进行了分级，为了后续能够分析每种级别的规则在waf上的效果，评分机制对每一个级别的规则，也进行了权重分的计算，每个级别对应的权重分变量为tx.anomaly\_score\_pl1/2/3/4,上文中的规则`setvar:'tx.anomaly_score_pl1=+%{tx.critical_anomaly_score}`就是在命中此PL1规则后，anomaly\_score\_pl1权重分增加此规则的全局分类权重分critical\_anomaly\_score。
    
    我们以上文规则分级中的测试为例，modsecurity设置使用PL2，发送会命中PL1、PL2规则的请求
    
    [![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-99a0c8f2185af0ddf1becf4374847ea9075d5d79.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-99a0c8f2185af0ddf1becf4374847ea9075d5d79.png)
    
    查看日志，可以看到PL各级别的总分
    
    [![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-0fd33656cef811c1e1ec78237e78c6102fb691ee.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-0fd33656cef811c1e1ec78237e78c6102fb691ee.png)
    
    这种类型的权重分总和，默认情况下并没有设置阈值进行拦截，如果业务需要，可以对每一个权重分总和设置阈值，从而当某一分类规则命中权重到达阈值就直接进行拦截，下面为PL级别分数到达10，进行拦截的规则示例
    
    ```json
    SecRule TX:ANOMALY_SCORE_PL1 "@ge 10" \
       "id:949999,\
       phase:2,\
       deny,\
       t:none,\
       msg:'anomaly score pl1 Exceeded (Total Score: %{TX:ANOMALY_SCORE_PL1})',\
       tag:'application-multi',\
       tag:'language-multi',\
       tag:'platform-multi',\
       tag:'attack-generic',\
       ver:'OWASP_CRS/3.4.0-dev',\
       severity:'CRITICAL'"
    ```

小结
--

本部分介绍了ModSecurity的规则分级机制，和规则评分机制，并分析了其实现的方式，由于篇幅有限，将在第三部分具体介绍ModSecurity如何处理可能存在攻击行为的数据，各种类型漏洞的利用请求是如何拦截的，和现规则体系下存在的问题，以及如何改善这些问题。

参考资料
----

<http://www.modsecurity.cn/>

<https://github.com/SpiderLabs/ModSecurity/wiki/>

<https://www.cnblogs.com/wuweidong/p/8535048.html>

<https://www.cnblogs.com/Hi-blog/p/ModSecurity-Transaction-Lifecycle.html>