四、 规则解析
-------

Version: OWASP\_CRS/4.0-dev

原版文档：<https://github.com/SpiderLabs/ModSecurity/wiki/> x版本没有:)

中文参考：<http://www.modsecurity.cn/chm/>

### 4.1 规则参数解析

通用格式

SecRule VARIABLES OPERATOR \[TRANSFORMATION\_FUNCTIONS, ACTIONS\]

接下来将选取重要的参数进行介绍

#### 4.1.1 变量

##### 4.1.1.1 Request variables

ARGS 请求参数，类型read-only collection  
ARGS\_COMBINED\_SIZE 请求参数的总大小  
ARGS\_NAMES 请求参数的名字， 类型read-only collection  
ARGS\_GET 查询字符串参数，类型read-only collection  
ARGS\_GET\_NAMES 查询字符串参数,类型read-only collection  
ARGS\_POST 请求体参数，类型read-only collection  
ARGS\_POST\_NAMES 请求体参数的名字，类型read-only collection  
FILES 上传文件域，类型read-only collection  
FILES\_COMBINED\_SIZE 上传文件大小  
FILES\_NAMES 上传文件表单文件域参数的名字，类型read-only collection  
FILES\_SIZES 上传文件的大小，类型read-only collection  
FILES\_TMPNAMES 文件临时名字，类型read-only collection  
PATH\_INFO URI path  
QUERY\_STRING 查询字符串  
REQUESET\_BASENAME URI basename，同时支持/与\\这两种文件分隔符  
REQUEST\_BODY 请求体，默认处理application/x-www-form-urlencoded 请求  
REQUEST\_COOKIES cookie参数  
REQUEST\_COOKIES\_NAMES cookie参数的名字，类型read-only collection  
REQUEST\_FILENAME URI filename/path  
REQUEST\_HEADERS 请求头，类型read-only collection  
REQUEST\_HEADERS\_NAMES 请求头参数的名字， 类型read-only collection  
REQUEST\_LINE 请求行  
REQUEST\_METHOD 请求方法  
REQUEST\_PROTOCOL 请求协议  
REQUEST\_URI 请求URI,但不包括hostname  
REQUEST\_URI\_RAW 请求URI,包括hostname

##### 4.1.1.2 Server variables

AUTH\_TYPE 认证类型，代理模式下非本地认证，需要指定Authorization头  
REMOTE\_ADDR 远程地址， 访问者ip  
REMOTE\_HOST 远程host，访问者hostname，当HostnameLookUps开启时，为dns解析的域名，否则为ip地址  
REMOTE\_PORT 远程端口，访问者端口  
REMOTE\_USER 访问者用户名  
SERVER\_ADDR 服务端地址  
SERVER\_NAME 服务端hostname，取值Host请求头  
SERVER\_PORT 服务端端口  
SCRIPT\_BASENAME 脚本basename, 代理模式不可用  
SCRIPT\_FILENAME 脚本 filename，代理模式不可用  
SCRIPT\_GID 脚本group ID，代理模式不可用  
SCRIPT\_GROUPNAME 脚本 group name，代理模式不可用  
SCRIPT\_MODE 脚本权限 ，代理模式不可用  
SCRIPT\_UID 脚本 user ID，代理模式不可用  
SCRIPT\_USERNAME 脚本 user name，代理模式不可用

##### 4.1.1.3 Response variables

RESPONSE\_BODY 响应体  
RESPONSE\_CONTENT\_LENGTH 响应实体长度，单位bytes  
RESPONSE\_CONTENT\_TYPE 响应实体类型，仅仅在phase3可用  
RESPONSE\_HEADERS 响应头，类型read-only collection  
在内嵌模式中，像那种会优先将数据发送给客户端的响应头是不可获得的，例如Server,Date,Connection,Content-Type  
在代理模式中，阶段5可用  
RESPONSE\_HEADERS\_NAMES 响应头参数的名字，类型read-only collection  
在内嵌模式中，像那种会优先将数据发送给客户端的响应头是不可获得的，例如Server,Date,Connection,Content-Type  
在代理模式中，阶段5可用  
RESPONSE\_PROTOCOL 响应协议  
RESPONSE\_STATUS 响应码，仅代理模式可用

##### 4.1.1.4 Parsing flags

MULTIPART\_BOUNDARY\_QUOTED multipart 解析错误：boudnary中有引号  
MULTIPART\_BOUNDARY\_WHITESPACE multipart 解析错误：boudnary中有空格  
MULTIPART\_CRLF\_LF\_LINES multipart 解析错误：混合使用\\r\\n 与\\n作为分界线， 当允许使用混合粉各符时设置为1  
MULTIPART\_DATA\_BEFORE multipart 解析错误：第一个boudnary前有数据  
MULTIPART\_DATA\_AFTER multipart 解析错误：最后一个boudnary后有数据  
MUTLIPART\_HEADER\_FOLDING multipart 解析错误：boudnary中  
MULTIPART\_LF\_LINE multipart 解析错误：使用\\n作为分界线  
MULTIPART\_SEMICOLON\_MISSIONG multipart 解析错误：缺少分号  
MULTIPART\_STRICT\_ERROR 当以下值为1时，该值为1;  
REQBODY\_PROCESSOR\_ERROR  
MULTIPART\_BOUNDARY\_QUOTED  
MULTIPART\_BOUNDARY\_WHITESPACE  
MULTIPART\_DATA\_BEFORE  
MULTIPART\_DATA\_AFTER  
MULTIPART\_HEADER\_FOLDING  
MULTIPART\_LF\_LINE 使用换行做分界线  
MULTPART\_SEMICOLON\_MISSING 分号缺失  
MULTPART\_INVALID\_QUOTING 无效引号  
MULTIPART\_INVALID\_QUOTING multipart 解析错误： 无效引号  
MULTIPART\_UNMATCHED\_BOUDDARY multipart 解析错误：不合规范的boudnary，容易漏报  
REQBODY\_PROCESSOR 处理request解析，内置的解析功能包括URLENCODED, MULTIPART, XML  
REQBODY\_PROCESSOR\_ERROR request解析错误标记，1表示错误，0表示ok  
REQBODY\_PROCESSOR\_ERROR\_MSG request解析错误信息  
URLENCODED\_ERROR 当解析application/x-www-form-urlencoded格式的请求体出错时值为1

#### 4.1.2 操作符

beginsWith  
contains  
containsWord  
endsWith  
rx Regular pattern match 正则  
pm 特征字符串的匹配， 大小不敏感，基于Aho-Corasick匹配算法  
pmFromFile 从文件读取匹配特征字符串 ，Parallel matching, with arguments from a file  
streq String equal to  
within Within  
eq 相等  
ge 大于等于  
gt 大于  
le 小于等于  
lt 小于  
validateByteRange  
validateDTD XML相关  
validateSchema XML相关  
validateUrlEncoding  
validateUtf8Encoding  
geoLookup Determines the physical location of an IP address  
inspectFile 使用外部脚本处理  
rbl 去RBL REAL-TIME BLANKHOLE LISTS反垃圾邮件黑名单里查找ipv4地，或hostname  
verifyCC Checks if the parameter is a valid credit card number

#### 4.1.3 转换函数

base64Decode  
base64Encode  
compressWhitespace  
cssDecode  
escapeSeqDecode   
hexDecode  
hexEncode  
htmlEntityDecode  
jsDecode  
length  
lowercase  
md5  
normalizePath 移除掉多个斜杠  
normalizePathWin 移除掉多个斜杠,但首先会将\\转化成/  
parityEven7bit  
parityOdd7bit  
parityZero7bit  
removeNulls 删除空字节  
removeWhiteSpace 删除空格字符  
replaceComments 将注释语句/*...*/转换为空格  
replaceNulls 将NULL字节转换为空格  
urlDecode  
urlDecodeUni  
urlEncode  
sha1  
trimLeft 移除左边的空格  
trimeRight 移除右边的空格  
trim 移除左右两端的空格

#### 4.1.4 动作

allow  
2.5版本之前是只影响当前阶段  
2.5版本之后，如果单独使用，除了log阶段，其他阶段都停止处理，如果和参数phase一起使用，allow将停止当前阶段的处理，其他阶段不受影响  
block 相当于占位符，会被上下文的SecDefaultAction 指令中的动作取代  
deny 使用错误页面block 当前事务,Block transaction with an error page  
drop 断开网络连接  
pass 继续执行下一个规则  
proxy 代理请求到后端web server  
redirect 重定向请求到其他web server  
chain 相当于多个规则的and操作  
skip 跳过指定的规则,值为跳过的规则个数，不能跳过同一个规则链中的规则  
skipAfter 调转到指定的规则  
id 设置规则ID  
phase 指明处理阶段  
msg  
rev 设置版本号  
severity 设置rule的严重级别，最好用文本来指定，v2.5.0版本已弃用  
capture 将捕获结果存入ＴＸ变量，可以存储１０个变量，ｔｘ变量集合的下标为０－９  
deprecatevar 设置指定时间内递减数字型变量  
expirevar 设置指定时间内移除过期的变量  
initcol 创建持久性collections，通常在阶段１中设置  
setenv 设置环境变量  
setvar 设置变量  
setuid 设置当前事务的user ID  
setsid 设置当前事务的session ID  
auditlog 将当前事务记录到审计log中  
log Log error message; implies auditlog  
logdata Log supplied data as part of error message  
noauditlog Do not log current transaction to audit log  
nolog Do not log error message; implies noauditlog

### 4.2 具体规则解析

规则具体的全局配置在crs-setup.conf中

#### 901

*901-INITIALIZATION* 初始化变量定义

#### 903

一些应用漏洞防护规则

9001：DRUPAL

9002：WOEDPRESS

9003：NEXTCLOUD

9004：DOKUWIKI

9005：CPANEL

9006：XENFORO

9007：PHPBB

9008：PHPMYADMIN

#### 905

*905-COMMON-EXCEPTIONS* 常见的两种请求情况Apache SSL pinger和Apache internal dummy connection，关闭ruleEngine和auditEngine

#### 910

*910-IP-REPUTATION* IP信誉库，可以直接连接第三方IP信誉库

#### 911

*911-METHOD-ENFORCEMENT* PL1-允许请求方法

#### 912

*912-DOS-PROTECTION* DOS防护

- PL0
    
    912100/912110：如果没有这是dos防护参数，就直接跳过dos防护规则
- PL1
    
    912150：记录非静态文件访问次数
    
    912160/912161：请求数超过用户设置，就进行记录，一种从0-1，一种从1-2，不会超过2
    
    912170：当超过次数为2时，认定为潜在的dos攻击
- PL2
    
    912171：同912170，次数为1时，就认定为潜在的dos攻击

#### 913

*913-SCANNER-DETECTION* 扫描器检测

都为PL1规则，通过关键字进行检测，关键字列表见data文件

#### 920

*920-PROTOCOL-ENFORCEMENT* 协议强制规则

根据RFC对http协议的规范编写的规则，包括编码、request\_header、ascii字符范围、请求参数最大长度等限制，多为NOTICE/WARNING level

还有一些对uri限制的规则，如文件扩展名

- PL0
    
    
    1. 920100：request\_header(eg.`POST /index.html HTTP/1.1`)验证
- PL1
    
    
    1. 920120：文件名和文件参数名验证，没看懂
    2. 920160：Content-Length取值非数字
    3. 920170：非GET/HEAD方法，Content-Length不能取0或者无值
    4. 920172：GET/HEAD方法，不能含有Transfer-Encoding
    5. 920180：非HTTP/2协议，post方法，CL TE不能同时不存在
    6. 920181：CL TE不能同时存在
    7. 920190：HTTP request\_header:Range，范围必须从小到大
    8. 920210：Connection不能取两个值
    9. 920220/920240：验证url编码准确性
    10. 920250：验证utf8编码准确性
    11. 920260：宽字节编码
    12. *920270*：
        
        全局设置规则应用的级别paranoia level，可在crs-setup.conf中设置
        
        ```yaml
        SecAction \
         "id:900000,\
         phase:1,\
         nolog,\
         pass,\
         t:none,\
         setvar:tx.paranoia_level=1"
        ```
        
        920270中解释了，每个级别中限制通行的ByteRange
        
        ```yaml
        # -=[ Targets and ASCII Ranges ]=-
        #
        # 920270: PL1 : REQUEST_URI, REQUEST_HEADERS, ARGS and ARGS_NAMES
        #       ASCII 1-255 : Full ASCII range without null character
        #
        # 920271: PL2 : REQUEST_URI, REQUEST_HEADERS, ARGS and ARGS_NAMES
        #       ASCII 9,10,13,32-126,128-255 : Full visible ASCII range, tab, newline
        #
        # 920272: PL3 : REQUEST_URI, REQUEST_HEADERS, ARGS, ARGS_NAMES and REQUEST_BODY
        #       ASCII 32-36,38-126 : Visible lower ASCII range without percent symbol
        #
        # 920273: PL4 : ARGS, ARGS_NAMES and REQUEST_BODY
        #       ASCII 38,44-46,48-58,61,65-90,95,97-122
        #       A-Z a-z 0-9 = - _ . , : &amp;
        #
        # 920274: PL4 : REQUEST_HEADERS without User-Agent, Referer, Cookie
        #               and Structured Header booleans
        #       ASCII 32,34,38,42-59,61,65-90,95,97-122
        #       A-Z a-z 0-9 = - _ . , : &amp; " * + / SPACE
        ```
        
        PL取值越大，其可通行的字符范围越小，而且由于字符范围越小，也会应用更多的规则。很多规则会因为PL级别很小，导致会被忽略，不进行匹配拦截
        
        
        13. 920280：不允许Host字段不存在
        14. 920290：不允许Host取值为空
        15. 920310：非OPTIONS方法，非特定一些UA，不允许Accept取值为空
        16. 920311：不允许非OPTIONS方法，Accept取值为空，并不存在UA
        17. 920330：不允许UA取值为空
        18. 920340：CL取值大于0，必须存在Content-Type
        19. 920350：Host非域名
        20. 920380：最大请求参数数量限制
        21. 920360：请求参数名的长度
        22. 920370：请求参数值长度
        23. 920390：请求参数总长度
        24. 920400：最大上传文件大小
        25. 920410：总上传文件大小
        26. 920470/920420/920480：Content-Type限制
        27. 920430：请求http协议限制
        28. 920440：url文件扩展名限制
        29. 920500：url文件名称限制，eg:`index.php~`
        30. 920450：请求头限制
- PL2
    
    
    1. 920200/920201：Range头取值个数限制
    2. 920230：url多次编码检测
    3. 920271：可用字符限制规则，同920270
    4. 920230：UA存在
    5. 920121：上传文件名不能含有\['\\";=\]
    6. 920341：Content-Length不等于0时，必须存在Content-Type
- PL3
    
    
    1. 920272：可用字符规则，同920270
    2. 920300：非Option方法，除特定UA，Accept必须存在
    3. 920490：针对x-up-devcap-post-charset头的规则，[blog](https://soroush.secproject.com/blog/2019/05/x-up-devcap-post-charset-header-in-aspnet-to-bypass-wafs-again/)
    4. 920510：Cache-Control白名单
- PL4
    
    
    1. 920202：同920200
    2. 920273/920274/920275：可用字符限制规则，同920270
    3. 920460：防御类似`arg=cat+/e\tc/pa\ssw\d`，误报率不用说，很高

#### 921

*921-PROTOCAL-ATTACK* 防御协议攻击的规则

- PL1
    
    
    1. 921110：HTTP走私，请求方法关键字
    2. 921120：HTTP响应拆分攻击，\[\\r\\n\]和常见header
    3. 921130：response头http/，和常用xss标签\\&lt;html&gt;\\&lt;meta&gt;
    4. 921140：request\_header中含有\[\\r\\n\]
    5. 921150：参数名中含有\[\\r\\n\]
    6. 921160：参数中含有\[\\r\\n\]和常见request\_header
    7. 921190：请求中文件名不能含有\[\\r\\n\]，类似uri
    8. 921200：LDAP注入规则，必须要有)闭合括号才能匹配中，eg.`)(!)`
- PL2
    
    921151：GET参数值中含有\[\\r\\n\]
- PL3
    
    921170/921180：HTTP参数污染漏洞规则，先将每一个参数名都匹配出来，并以paramcounter\_为前缀增加变量进行计数，最后如果相同参数名含有两个值或以上就拦截

#### 930

*930-APPLICATION-ATTACK-LFI* 本地文件包含漏洞规则

- PL1 
    1. 930050：Google OAuth2 callback 检测
    2. 930100：url编码过的payloads eg.`urlencode(/../)`
    3. 930110：普通../和/.. ..\\和..
    4. 930120/930121/930130：一些常见的本地文件列表关键字，具体内容见data数据

#### 931

*931-APPLICATION-ATTACK-RFI* 远程文件包含漏洞规则

- PL1 
    1. 931100：file/ftps/[https://协议加数字ip形式](https://xn--ip-cr5cyzs52ajsfuqam10bn17f)
    2. 931110：文件包含的参数名如include
    3. 931120：file/ftps/<a>https://协议，误报很高</a>
- PL2 
    1. 931130：出现file://类似关键字就直接拦截，且包含host地址，与请求host不同，误报高

#### 932

APPLICATION-ATTACK-RCE 远程代码执行(代码注入)

- PL1 
    1. 932100：regexp-932100.txt中各种uninx命令的拦截
    2. 932110：windows命令拦截
    3. 932120：powershell命令
    4. 932130：unix命令表达式bypass拦截，缺少$\\w+，变量未定义默认为空，可以绕过 ;cat$a+/etc&amp;b/passed$c/
    5. 932180：配置文件上传导致的RCE
- PL2 
    1. 932200：二级命令注入绕过方式，误报比较高。含有$a 或 \\a 或 \*a/通配符，并且含有/和\\s
    2. 932210：sqlite cli命令注入拦截规则，不错，二级规则，但是误报率不会大
- PL3 
    1. 932106：增加的命令拦截
    2. 932190：通配符命令增加规则

#### 933

933-APPLICATION-ATTACK-PHP php攻击防护，可根据后端应用类型开启

#### 934

934-APPLICATION-ATTACK-NODEJS nodejs攻击防护，可根据后端应用类型开启

#### 943

- PL1 
    1. 943100：会话固定攻击 [Session-Fixation](http://projects.webappsec.org/Session-Fixation)
    2. 943110：参数名中含有session设置的关键词，并且referer和请求host不一致，感觉误报很多
    3. 943120：参数名中含有session关键词，且没有referer，误报超高应该

#### 944

944-APPLICATION-ATTACK-JAVA java攻击防护，可根据后端应用类型开启

#### 95x

950-954 DATA-LEAKAGES 数据泄露规则，主要返回包中含有相关关键字

#### 955

955-WEB-SHELLS webshell规则，主要是国外常见webshell规则，国内没啥用

### 4.3 一个绕过案例

先看一个简单的规则

```json
SecRule REQUEST_URI|ARGS|REQUEST_HEADERS|!REQUEST_HEADERS:Referer|XML:/* "@rx (?:(?:^|[\\/])\.\.[\\/]|[\\/]\.\.(?:[\\/]|$))" \
    "id:930110,\
    phase:2,\
    block,\
    capture,\
    t:none,t:utf8toUnicode,t:urlDecodeUni,t:removeNulls,t:cmdLine,\
    msg:'Path Traversal Attack (/../)',\
    logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',\
    tag:'application-multi',\
    tag:'language-multi',\
    tag:'platform-multi',\
    tag:'attack-lfi',\
    tag:'paranoia-level/1',\
    tag:'OWASP_CRS',\
    tag:'capec/1000/255/153/126',\
    ver:'OWASP_CRS/3.4.0-dev',\
    severity:'CRITICAL',\
    multiMatch,\
    setvar:'tx.anomaly_score_pl1=+%{tx.critical_anomaly_score}',\
    setvar:'tx.lfi_score=+%{tx.critical_anomaly_score}'"
```

需要关注的就是，待检测数据在匹配规则之前，会进行数据的转换，由t这个动作完成，后面跟的就是需要什么转换函数来进行转化，上文已经列举了相关的函数。这些函数可以从代码中看到

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-94b14a2594a2df0f3ade0e0d06c1b9a535d47d22.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-94b14a2594a2df0f3ade0e0d06c1b9a535d47d22.png)

测试时，我发现这个防止本地文件包含的规则经过cmlLine函数的转换，接着查看其转化代码

```cpp
std::string CmdLine::evaluate(const std::string &amp;value,
    Transaction *transaction) {
    std::string ret;
    int space = 0;

    for (auto&amp; a : value) {
        switch (a) {
            /* remove some characters */
            case '"':
            case '\'':
            case '\\':
            case '^':
                break;

            /* replace some characters to space (only one) */
            case ' ':
            case ',':
            case ';':
            case '\t':
            case '\r':
            case '\n':
                if (space == 0) {
                    ret.append(" ");
                    space++;
                }
                break;

            /* remove space before / or ( */
            case '/':
            case '(':
                if (space) {
                    ret.pop_back();
                }
                space = 0;
                ret.append(&amp;a, 1);
                break;

            /* copy normal characters */
            default :
                char b = std::tolower(a);
                ret.append(&amp;b, 1);
                space = 0;
                break;
        }
    }

    return ret;
}
```

很明显主要是删除一些命令注入bypass的关键字符如`"'\^`，并将一些字符转换成空格，但是930110这个规则主要防御的就是`/../`或者`\..\`类似的攻击，这就导致`\`会被删除。

然后我搭建了Apache/2.4.29+CRSv3.4/dev+PL1的环境进行测试payload: `..\secret`

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-835923c638f3d276dcaebc5b47c4f4d19697427a.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-835923c638f3d276dcaebc5b47c4f4d19697427a.png)

结果不出所料，直接绕过了modsecurity最新规则，接着我直接提了[issue](https://github.com/coreruleset/coreruleset/issues/2140)给CRS，一开始他们不确定这是个绕过，最后又承认是`False Negative`

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-1e1ba011c8ac850dc59f83da3d82a51d9967cab1.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-1e1ba011c8ac850dc59f83da3d82a51d9967cab1.png)

之后就没再关注这个东西，最近发现事情远没有这么简单，如果只是简单的删除掉规则中的cmdLine转换函数并不能解决掉这个漏报，修改规则并测试

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-f55f665c4a5c5a6b904c7686caaeee84f74dc8d1.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-f55f665c4a5c5a6b904c7686caaeee84f74dc8d1.png)

发现还是未拦截，根据issue中的回复来看，参考此前的一个[ SpiderLabs/ModSecurity#2148](https://github.com/SpiderLabs/ModSecurity/issues/2148)，简单来说就是双斜杠`\\`在经过Apache解析时，会转化成一个`\`最终正则变为了`(?:^|[\/])\.\.(?:[\/]|$)`，所以无法匹配`..\`

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-e406a89ec043e488ed1e9efb539f88c869e192df.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-e406a89ec043e488ed1e9efb539f88c869e192df.png)

接着我也测试了将规则改为`(?:^|[\\\\/])\.\.(?:[\\\\/]|$)`，确实能够准确拦截，可是在没有删除cmdLine函数转换的情况下也拦截了

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-49fc491d7a9fbbc7410874e88d37ad1aa9ffd483.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-49fc491d7a9fbbc7410874e88d37ad1aa9ffd483.png)

可是这并没有解决我一开始的问题，确实拦截了，但即使正则在解析之后是准确的，而`..\secret`经过处理`\`应该被删除才对。

接着为了测试是否cmdLine函数起作用[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-ff85c56bc9963c38e79eb3c667e10e0212d97a3b.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-ff85c56bc9963c38e79eb3c667e10e0212d97a3b.png)

`.."/a`直接拦截，说明cmdLine没有问题，接着测试`.".\a`时

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-b0c3e2d943b787ee1497afd7585bfe022fbb37ec.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-b0c3e2d943b787ee1497afd7585bfe022fbb37ec.png)

目前也没发现具体原因是什么导致的，当然从结果上来说，不影响具体waf的拦截情况。

参考资料
----

<http://www.modsecurity.cn/>

<https://github.com/SpiderLabs/ModSecurity/wiki/>

<https://www.cnblogs.com/wuweidong/p/8535048.html>

<https://www.cnblogs.com/Hi-blog/p/ModSecurity-Transaction-Lifecycle.html>

<https://www.shuzhiduo.com/A/QV5ZZV1y5y/>