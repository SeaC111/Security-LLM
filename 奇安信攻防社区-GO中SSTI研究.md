0x0前言
-----

在ByteCTF2021与SCTF2021中，我们都可以看到GO语言下的SSTI的身影，借此机会深入学习一下GO语言下的SSTI，在ByteCTF的WP文档中有相应的链接来介绍GO语言下的SSTI利用方法的研究。

<https://www.onsecurity.io/blog/go-ssti-method-research/>

<https://blog.takemyhand.xyz/2020/05/ssti-breaking-gos-template-engine-to.html>

<https://tyskill.github.io/posts/gossti/>

本文也主要参考自上面的几篇文章。

0x1漏洞介绍
-------

和其他像Python、PHP环境下的模板注入一样，Go语言下的模板注入也是因为未使用 Go 中渲染模板的预期方式来利用，用户传入的数据直接传递到了能够被模板执行的位置，导致了一系列的安全问题。

### GO 语言下

GO 语言是一个正在兴起的编程语言，正在我们的视野范围内迅速崛起。

GO语言提供了两个模板包，一个是 [html/template 模块](https://pkg.go.dev/html/template)，另一个是 [text/template 模块](https://pkg.go.dev/text/template)，两个模块都可以在它的官网文档中找到。

这两个模板有很大的不同，例如，在 text/template 中，您可以使用`call`值直接调用任何公共函数，但是在 html/template 中则不是这种情况,text/template 包对 XSS 或任何类型的 HTML 编码没有任何保护，第二个包 html/template 增加了 HTML 编码等安全保护。

0x2利用方法
-------

我们编写如下代码来进行测试，代码中引入了`text/template`，会导致SSTI漏洞出现

```go
package main

import (
    "fmt"
    "net/http"
    "strings"
    "text/template"
)

type User struct {
    Id     int
    Name   string
    Passwd string
}

func StringTplExam(w http.ResponseWriter, r *http.Request) {
    user := &User{1, "admin", "123456"}
    r.ParseForm()
    arg := strings.Join(r.PostForm["name"], "")
    tpl1 := fmt.Sprintf(`<h1>Hi, ` + arg + `</h1> Your name is ` + arg + `!`)
    html, err := template.New("login").Parse(tpl1)
    html = template.Must(html, err)
    html.Execute(w, user)
}

func main() {
    server := http.Server{
        Addr: "127.0.0.1:8080",
    }
    http.HandleFunc("/login", StringTplExam)
    server.ListenAndServe()
}

```

### 环境搭建

#### GO环境

推荐Go官网安装，也可以在[Go中文网](https://studygolang.com/dl)下载。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-25f6261173c57bcdbbb09b6492f602eb9b4194de.png)

VSCode yyds

### 漏洞测试

#### 信息泄露

进入login路由，会发现这样的一个页面

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-c74496a49121ef2761ee658e0ea278982a47e001.png)

但是由于我们的源码中：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-3acff7ffec3ddc959aee1ea339af91d314db8260.png)

使用了 模板`&User` 因此`{{.Passwd}}`模板使用 user 的 Passwd 属性，就会导致密码的泄露

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-41c2b3406d4f0ef6f6885a7fd5ffa368b4135f12.png)

模板User的定义

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-c69c9453a997aad0f56cf00f29423b6a660d1ae9.png)

我们还可以直接利用`{{ . }}` 这种形式来返回全部的模板中的内容，在我们的例子中是 user 结构。这可以被认为是其他模板引擎中的 {{ self }} 的等价物。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-b757c35996efb16ad6fca9340c17ae707a97b8ba.png)

tyskill师傅还给出了一个防御方法，tql

```go
func StringTpl2Exam(w http.ResponseWriter, r *http.Request) {
    user := &User{1, "tyskill", "tyskill"}
    r.ParseForm()
    arg := strings.Join(r.PostForm["name"], "")
    tpl := `<h1>Hi, {{ .arg }}</h1><br>Your name is {{ .Name }}`
    data := map[string]string{
        "arg":  arg,
        "Name": user.Name,
    }
    html := template.Must(template.New("login").Parse(tpl))
    html.Execute(w, data)
}
```

#### 实现 RCE

Go语言中的SSTI可以和Python中的SSTI一样，进行方法的调用，在特定情况下，我们可以进行恶意的func调用，实现RCE

比如，我们在代码中引入`"os/exec"`并添加如下func

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-55e41b4e8823a1c282c9c8e772a89360e0b8c0c6.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-a1b5ce4f5602ff3833a8d77c27fbf9e2b4bdf19e.png)

我们就可以实现恶意的命令执行了

本质上这其实是一种代码审计发现不安全的方法定义的过程，在另一个例子中可以体现

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-2fc181b4899ba733328145177ba42e8e74baa4dd.png)

这里就是在审计的过程中发现了一个可以进行任意文件读取的方法，并且存在模板注入的点，导致了文件信息的泄露，我们简化一下，引入`"io/ioutil"`包

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-af77350568d31ab3e62db010651bab7d3c283490.png)

接下来就用和上面一样的调用方式就可以进行文件读取了

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-c9ee689919c1f91a6c42a470e854bdf3c631ba47.png)

还可以进行`{{printf "%s"}}`格式的输出

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-4eebd03a22305164c22571f9fa4d4bd7cf9d6065.png)

还有一些其他可以用于输出的payload： `{{html "ssti"}}`, `{{js "ssti"}}` 实现的也是如上效果，实际上直接`{{"ssti"}}`也可以... 我们后面的XSS就是这样进行的

#### XSS

我们可以利用这里的模板实现 XSS

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-e1ecd231136955ed8d017d9ce86a68e03886e88b.png)

这样不可以，这样只是单纯的输出，因为没有默认编码的行为，XSS不会实现，但是GO允许我们对模板进行定义，这样就出现了编码行为：

**`{{define "T1"}}ONE{{end}}{{template "T1"}}`**

即**`{{define "T1"}}<script>alert(1)</script>{{end}} {{template "T1"}}`**

{template "name"}} 执行名为name的模板，提供给模板的参数为nil，如模板不存在输出为""  
{{define "name"}模板内容{{end}}}定义一个名为name的模板

这里实际上就是一个我们进行模板的定义，并输出的过程，这样我们就可以顺利的实现XSS了

但是这种方法我目前还没有成功实践，页面无法接收这样格式的请求，以上内容来自<https://blog.takemyhand.xyz/2020/05/ssti-breaking-gos-template-engine-to.html>的分享。

0x3总结
-----

模板注入作为一种攻击方式绝不是简单的flask，对各种语言的模板使用与规则进行研究面，对各种模板进行研究，都是必要的。