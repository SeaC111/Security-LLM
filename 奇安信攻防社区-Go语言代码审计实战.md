本文主要是实战go语言编写的两个小程序的漏洞挖掘。

0x01程序一: PPGo
=============

github地址 [https://github.com/george518/PPGo\_Job](https://github.com/george518/PPGo_Job)

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-4ed50e0d4c1ea41acd0aca6f1a0fec9ee7a1ec6e.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-4ed50e0d4c1ea41acd0aca6f1a0fec9ee7a1ec6e.jpg)

从这里直接下载就行了。  
进入文件夹，设置好数据库(创建数据库，导入`ppgo_job2.sql`)和配置文件(`conf/app.conf`)  
运行 `./run.sh start|stop`

成功后

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-af91199458a15d9a6f478a0d5ecf382155e86e5b.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-af91199458a15d9a6f478a0d5ecf382155e86e5b.jpg)

表示成功。

#### 开始挖：

先看登录代码

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-33e263afcdd554fa6828bda8da845691521b6f53.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-33e263afcdd554fa6828bda8da845691521b6f53.jpg)

登录代码没有发现什么问题。简单的比较从数据库取的账号密码匹配。  
成功后设置auth响应。

先登录成功抓一个包：

```php
POST /login_in HTTP/1.1
Host: maoge:8080
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:94.0) Gecko/20100101 Firefox/94.0
Accept: application/json, text/javascript, */*; q=0.01
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Content-Length: 30
Origin: http://maoge:8080
Connection: close
Referer: http://maoge:8080/
Cookie: Hm_lvt_8acef669ea66f479854ecd328d1f348f=1616241442,1618728317; Hm_lvt_1cd9bcbaae133f03a6eb19da6579aaba=1616723765,1616858080,1616942607; USER_ID_ANONYMOUS=b3acc94ef8cb416eae4a54f0208b0b87; MAIN_NAV_ACTIVE_TAB_INDEX=1; DETECTED_VERSION=2.3.0; ANALYSIS_PROJECT_ID=; PAGINATION_PAGE_SIZE=10; DATA_FILTER_SEARCH=other; sc=M38BEbHqxH5aXtFqEGynxePWh8EuUDGoiEhTw164lDN2Qxdr3XpWXAflnqESg3nn; Hm_lvt_1d2d61263f13e4b288c8da19ad3ff56d=1629280468; uid=MTYzMzk0NzkzOQ==|1633947939543498000|db23261bcc5dff7017756ad873f755dab61521e3; token=Mg==|1633947939543553000|b7794845537943b17f13c40ac378589fb2c15d38; beegosessionID=ffb9e2b7bfff94a8ddecc8dbf1768171

username=admin&amp;password=123456
```

返回内容

```php
``HTTP/1.1 200 OK
Content-Length: 46
Content-Type: application/json; charset=utf-8
Server: beegoServer:1.11.1
Set-Cookie: auth=1|c2ef80548b36081206a40745cffbca88; Expires=Thu, 02 Dec 2021 05:12:52 UTC; Max-Age=604800; Path=/
Date: Thu, 25 Nov 2021 05:12:52 GMT
Connection: close

{
  "message": "登录成功",
  "status": 0
}
```

返回了一个`set cookie`应该就是后面的鉴权凭证。

尝试渗透这个页面，页面内有服务器的账号密码，比较有价值。

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-107260c595917ab2b4e817291149009b09de28e2.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-107260c595917ab2b4e817291149009b09de28e2.jpg)

```php
GET /server/edit?id=5 HTTP/1.1
Host: maoge:8080
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:94.0) Gecko/20100101 Firefox/94.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Connection: close
Referer: http://maoge:8080/home
Cookie: auth=1|c2ef80548b36081206a40745cffbca88
Upgrade-Insecure-Requests: 1
```

这里直接走到鉴权的代码，架构采用的是beego，通常直接找到prepare，相当于AOP，里面就是鉴权的代码

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-50d4905b9cb4aa09ee4ef552e44d0a1070928549.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-50d4905b9cb4aa09ee4ef552e44d0a1070928549.jpg)

进入auth方法。

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-2ddc88ba24e47b28ab754a09eefc839991a4f479.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-2ddc88ba24e47b28ab754a09eefc839991a4f479.jpg)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-5350e568f13f5c96c2f0c5f3d15c8ce737528631.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-5350e568f13f5c96c2f0c5f3d15c8ce737528631.jpg)

会对`auth=1|c2ef80548b36081206a40745cffbca88` 进行分隔。  
1为 userid ``，`c2ef80548b36081206a40745cffbca88`鉴权字段。

跟如`auth`

1. 最开始，self.userId 赋值为 0；
2. 然后将auth里面的id传给变量 userId =1；
3. 进入if userId&gt;0 ; 获取用户信息根据 id。并且进行鉴权如果成功了设置self.userId 的值为1。

继续往下走

4. 判断url是否在`allowUrl`和`noAuth`。如果都不在则无权限。明显我们的不满足。
5. 如果self.userId=0 且 `actionName` 和 `controllerName` 满足条件则未授权。否者在鉴权成功。明显我们 self.userId&gt;0 则成功。  
    看下如何绕过。  
    如果我们把 userid 设置为 &gt;0 甚至一个不存在的值并且比如 userid 设置为5。

试着走一下

1. userId&gt;0 满足走if语句
2. 获取到 user 的信息为 nil
3. 明显的我们的url不满足 `allowUrl` 和 `noAuth` 的 if 。
4. 走到下面的if 我们的 self.userId&gt;0 不满足，则直接跳过，绕过鉴权。

所以我们只需要将 userid 改为 &gt;1 即可。

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-734be7d869b1b43304ca1fc0f46011c97710f25d.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-734be7d869b1b43304ca1fc0f46011c97710f25d.jpg)

0x02程序二
=======

程序二是一个文档管理工具。  
文档搭建好以后进入登录页面。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-1f063055ffc049f7b0351e55f670a5ac61825e0c.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-1f063055ffc049f7b0351e55f670a5ac61825e0c.jpg)  
先看登录账号是否存在问题 。

```go
    if c.Ctx.Input.IsPost() {
        account := c.GetString("account")
        password := c.GetString("password")
        captcha := c.GetString("code")
        isRemember := c.GetString("is_remember")

        // 如果开启了验证码
        if v, ok := c.Option["ENABLED_CAPTCHA"]; ok && strings.EqualFold(v, "true") {
            v, ok := c.GetSession(conf.CaptchaSessionName).(string)
            if !ok || !strings.EqualFold(v, captcha) {
                c.JsonResult(6001, i18n.Tr(c.Lang, "message.captcha_wrong"))
            }
        }

        if account == "" || password == "" {
            c.JsonResult(6002, i18n.Tr(c.Lang, "message.account_or_password_empty"))
        }

        member, err := models.NewMember().Login(account, password)
        if err == nil {
            member.LastLoginTime = time.Now()
            _ = member.Update("last_login_time")

            c.SetMember(*member)

            if strings.EqualFold(isRemember, "yes") {
                remember.MemberId = member.MemberId
                remember.Account = member.Account
                remember.Time = time.Now()
                v, err := utils.Encode(remember)
                if err == nil {
                    c.SetSecureCookie(conf.GetAppKey(), "login", v, time.Now().Add(time.Hour*24*30).Unix())
                }
            }

```

进入验证代码

```go
func PasswordVerify(hashing string, pass string) (bool, error) {
    data := trimSaltHash(hashing)

    interation, _ := strconv.ParseInt(data["interation_string"], 10, 64)

    has, err := hash(pass, data["salt_secret"], data["salt"], int64(interation))
    if err != nil {
        return false, err
    }

    if (data["salt_secret"] + delmiter + data["interation_string"] + delmiter + has + delmiter + data["salt"]) == hashing {
        return true, nil
    } else {
        return false, nil
    }

}
```

没有看出来什么问题。获取密码并且加密与之对比。  
如果登录成功了 那么设置sessionId。如果设置了remember参数，那么在cookie里面设置login参数。

```go
func (c *BaseController) SetMember(member models.Member) {
    if member.MemberId <= 0 {
        c.DelSession(conf.LoginSessionName)
        c.DelSession("uid")
        c.DestroySession()
    } else {
        c.SetSession(conf.LoginSessionName, member)
        c.SetSession("uid", member.MemberId)
    }
}
```

进入到校验session的位置 采用的是beego框架，也直接进入Prepare进去。

```go
if member, ok := c.GetSession(conf.LoginSessionName).(models.Member); ok && member.MemberId > 0 {
        c.Member = &member
        c.Data["Member"] = c.Member
    } else {
        var remember CookieRemember
         //如果Cookie中存在登录信息，从cookie中获取用户信息
        if cookie, ok := c.GetSecureCookie(conf.GetAppKey(), "login"); ok {
            if err := utils.Decode(cookie, &remember); err == nil {
                if member, err := models.NewMember().Find(remember.MemberId); err == nil {
                    c.Member = member
                    c.Data["Member"] = member
                    c.SetMember(*member)
                }
            }
        }
    }
```

如果session不正确那么走CookieRemember的分支，那么就从GetSecureCookie里面获取login的信息。那么先看看SecureCooki是如何设置的。  
这个方法来自于beego的里面的设置cookie的方法，加密方式很简单。但是加入了随机时间戳。我们再来设置的密钥。

```go
func (ctx *Context) SetSecureCookie(Secret, name, value string, others ...interface{}) {
    vs := base64.URLEncoding.EncodeToString([]byte(value))
    timestamp := strconv.FormatInt(time.Now().UnixNano(), 10)
    h := hmac.New(sha256.New, []byte(Secret))
    fmt.Fprintf(h, "%s%s", vs, timestamp)
    sig := fmt.Sprintf("%02x", h.Sum(nil))
    cookie := strings.Join([]string{vs, timestamp, sig}, "|")
    ctx.Output.Cookie(name, cookie, others...)
}

app_key 为Secret ,mindoc。
func GetAppKey() string {
return web.AppConfig.DefaultString("app_key", "mindoc")
}

```

也就是说我们直接使用就可以构造出login,cookie。感觉很像shiro的RememberMe。

```go
SetSecureCookie("mindoc", "login", v, time.Now().Add(time.Hour*24*30).Unix())
```

然后我们直接在cookie里面加入login字段，既可绕过权限，成功进入后台。

0x03 总结
=======

总的来说，go语言是一门相对简单的语言相比其他语言而言。go语言的框架有非常多并且很精巧，不过轮子都差不多，知一通百。