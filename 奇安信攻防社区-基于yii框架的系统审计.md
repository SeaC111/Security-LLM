基于yii框架的系统审计
============

前言
--

某次审计基于YII框架二开的系统

YII框架基础
-------

### Yii控制器

#### 创建控制器

在yii\\web\\Application网页应用中，控制器应继承yii\\web\\Controller 或它的子类。 同理在yii\\console\\Application控制台应用中，控制器继承yii\\console\\Controller 或它的子类。 如下代码定义一个 `site` 控制器:

```php
namespace app\controllers;

use yii\web\Controller;

class SiteController extends Controller
{
}
```

#### 控制器ID

通常情况下，控制器用来处理请求有关的资源类型，因此控制器ID通常为和资源有关的名词。 例如使用`article`作为处理文章的控制器ID。

控制器ID应仅包含英文小写字母、数字、下划线、中横杠和正斜杠， 例如 `article` 和 `post-comment` 是真是的控制器ID，`article?`, `PostComment`, `admin\post`不是控制器ID。

控制器Id可包含子目录前缀，例如 `admin/article` 代表 yii\\base\\Application::controllerNamespace控制器命名空间下 `admin`子目录中 `article` 控制器。 子目录前缀可为英文大小写字母、数字、下划线、正斜杠，其中正斜杠用来区分多级子目录(如`panels/admin`)。

#### 控制器类命名

控制器ID遵循以下规则衍生控制器类名：

- 将用正斜杠区分的每个单词第一个字母转为大写。注意如果控制器ID包含正斜杠，只将最后的正斜杠后的部分第一个字母转为大写；
- 去掉中横杠，将正斜杠替换为反斜杠;
- 增加`Controller`后缀;
- 在前面增加yii\\base\\Application::controllerNamespace控制器命名空间.

下面为一些示例，假设yii\\base\\Application::controllerNamespace控制器命名空间为 `app\controllers`:

- `article` 对应 `app\controllers\ArticleController`;
- `post-comment` 对应 `app\controllers\PostCommentController`;
- `admin/post-comment` 对应 `app\controllers\admin\PostCommentController`;
- `adminPanels/post-comment` 对应 `app\controllers\adminPanels\PostCommentController`

### 路由

终端用户通过所谓的*路由*寻找到操作，路由是包含以下部分的字符串：

- 模型ID: 仅存在于控制器属于非应用的模块;
- 控制器ID: 同应用（或同模块如果为模块下的控制器）下唯一标识控制器的字符串;
- 操作ID: 同控制器下唯一标识操作的字符串。

路由使用如下格式:

```php
ControllerID/ActionID
```

如果属于模块下的控制器，使用如下格式：

```php
ModuleID/ControllerID/ActionID
```

如果用户的请求地址为 `http://hostname/index.php?r=site/index`, 会执行`site` 控制器的`index` 操作。

### 自实现路由

在本系统中，除了controller目录下创建控制器外，还有在plugins目录中也存在。并且在`core/application.php`中通过重写`runAction`方法使之可运行插件`plugins`下的代码

具体实现如下：

```php
public function runAction($route, $params = [])
    {
        bcscale(2);//配置BC函数小数精度

        $route = ltrim($route, '/');
        $pattern = '/^plugin\/.*/';
        preg_match($pattern, $route, $matches);
        if ($matches) {
            $originRoute = $matches[0];
            $originRouteArray = mb_split('/', $originRoute);

            $pluginId = !empty($originRouteArray[1]) ? $originRouteArray[1] : null;
            if (!$pluginId) {
                throw new NotFoundHttpException();
            }
            if (!$this->plugin->getInstalledPlugin($pluginId)) {
                throw new NotFoundHttpException();
            }
            $controllerId = 'index';
            $controllerClass = "app\\plugins\\{$pluginId}\\controllers\\IndexController";
            $actionId = 'index';
            $appendNamespace = '';
            for ($i = 2; $i < count($originRouteArray); $i++) {
                $controllerId = !empty($originRouteArray[$i]) ? $originRouteArray[$i] : 'index';
                $controllerName = preg_replace_callback('/\-./', function ($e) {
                    return ucfirst(trim($e[0], '-'));
                }, $controllerId);
                $controllerName = ucfirst($controllerName);
                $controllerName .= 'Controller';
                $controllerClass = "app\\plugins\\{$pluginId}\\controllers\\{$appendNamespace}{$controllerName}";
                $actionId = !empty($originRouteArray[$i + 1]) ? $originRouteArray[$i + 1] : 'index';
                if (class_exists($controllerClass)) {
                    break;
                }
                $appendNamespace .= $originRouteArray[$i] . '\\';
            }

            try {
                /** @var Controller $controller */
                $controller = \Yii::createObject($controllerClass, [$controllerId, $this]);
                $module = new Module($pluginId, $this);
                $controller->module = $module;
                $this->controller = $controller;
                \Yii::$app->plugin->setCurrentPlugin(\Yii::$app->plugin->getPlugin($pluginId));
                return $controller->runAction($actionId, $params);
            } catch (\ReflectionException $e) {
                throw new NotFoundHttpException(\Yii::t('yii', 'Page not found.'), 0, $e);
            }
        }
        return parent::runAction($route, $params);
    }
```

主要处理逻辑是

1. 首先匹配$route中是否以`/plugin/`开头
2. 将$route以`/`进行分割定位具体的controllerID和ActionID
3. 调用$controller-&gt;runAction()来执行该控制器文件的文件的$actionId -&gt; action方法

比如请求URL如下

```php
index.php?r=plugin/booking/api/index/index -> web/app/plugins/booking/contorllers/api/IndexController.php::actionIndex()
```

难点解决
----

我们发现在此系统中有上千个controller.php文件，要是一个个审计其工作量是巨大。在控制器多而杂的情况下，想要快速的过一遍然后找到没有鉴权的方法/控制器进行快速审计，我们可以根据URI对应控制器的特征:

```php
index.php?r=plugin/booking/api/index/index -> web/app/plugins/booking/contorllers/api/IndexController.php::actionIndex()
index.php?r=admin/api/v1/user/get-user -> /web/app/Api/Controllers/v1/UserController.php::actionGetUser()
```

这里特征就很明显了：以`"/"`对参数r的值进行分割的话，`/web/app/`下的文件夹构成了第一部分，而在对应文件夹下的`controllers目录`下的文件夹及`xxController.php`文件名前半部分（即此处的xx）构成了第二、三...部分，最后一部分是由公开方法名`（去除Action）`构成。

并且我们知道无论是文件夹还是文件的名字都要变成小写，且有两个及以上连续的单词构建的文件夹、文件、方法都需要转为小写，且使用"-"符号来连接。

基于如上结果，在Mac下，我首先会通过如下命令，将所有的控制器文件路径获取，保存在url.txt中：

```bash
tree -f -i | grep "Controller.php" > url.txt
```

Windowx下使用如下命令（来自ChatGPT）：

```bash
tree /f /a | findstr /i "Controller.php" > url.txt
```

接着写了一个简单的Python脚本遵循控制器对应URI的逻辑

```python
import os
import re

def getFileNamePath(path):
    controlFilePath = []
    files = os.listdir(path)  # 获取当前目录的所有文件及文件夹
    for file in files:
        try:
            file_path = os.path.join(path, file)  # 获取绝对路径
            if os.path.isdir(file_path):  # 判断是否是文件夹
                getFileNamePath(file_path)  # 如果是文件夹，就递归调用自己
            else:
                if 'Controller' in os.path.splitext(file_path)[0]:  # 查找后缀为.md的文件
                    cur_path = os.path.dirname(os.path.realpath(file_path))  # 查找文件的绝对路径
                    controlFilePath.append((cur_path + '\\' + file))
        except:
            continue  # 可能会报错，所以用了try-except,如果要求比较严格，不需要报错，就删除异常处理，自己调试
    with open("./url.txt", "a+") as k:
        for y in controlFilePath:
            k.write(y + "\n")

def getUri():

    pattern = r"public function action(.*?)\(\)"
    with open("./url.txt") as f:
        for i in f.readlines():
            x = i.replace("\n", "").replace("\\", "/")
            with open(x, encoding='gb18030', errors='ignore') as v:
                matches = re.findall(pattern, v.read())
                for c in matches:
                    c = "-".join(re.findall('[A-Za-z][a-z]*', c)).lower()
                    y = x.replace("/controllers", "").replace("Controller.php", "") + "/" + c
                    if "plugin" not in y:
                        y = y.lower()
                    print(y)
                    with open("./res.txt", "a+") as k:
                        k.write(y + "\n")

if __name__ == '__main__':
    path = ""
    getFileNamePath(path)
    getUri()
```

处理路径、提取公开方法、拼接，形成一个字典res.txt

![image-20230803163416679](https://shs3.b.qianxin.com/butian_public/f5768175040081cbeee6ed83788122eaf2e0f7437ef7c.jpg)

再代入到参数r中进行枚举，结合HaE的特征匹配

![image-20230804112821151](https://shs3.b.qianxin.com/butian_public/f451455b86bc6e9d5eaa986ee4fa755439d19b14e0c37.jpg)

### 漏洞发现

发现了一些mysql报错信息

在三个`Goods`相关的请求中都是报错提示数据表缺少列名

![image-20230808162753801](https://shs3.b.qianxin.com/butian_public/f572213d90cceb817009c85c8c82bcbcbf68f52834cf0.jpg)

在具体的模型中，可传入page，type和cat\_id三个参数

![image-20230808162909421](https://shs3.b.qianxin.com/butian_public/f7621424b60eccd942da2f4b308a1a217ca6938878b20.jpg)

而且rules中规定了三个都是interger类似，无法注入

最后的希望来到了booking相关的请求

![image-20230804112920696](https://shs3.b.qianxin.com/butian_public/f1430843cbdafc0e65e1a10e9ea17026901dfd8e1f6f0.jpg)

结合白盒对特定controller进行审计，根据路由特征找到响应的controller，这里路由为`plugin/xxx/api/Booking/store-list`对应`plugins/xxx/controllers/api`目录下的`BookingController.php`中的`actionStoreList()`方法

![image-20230804113506484](https://shs3.b.qianxin.com/butian_public/f98148173f65666c0a12372e5bf399a3a5266843bea4e.jpg)

首先创建了`BookingForm`类，利用`\Yii::$app->request->get()`获取get请求中的参数赋值给`$form->attributes`变量

![image-20230804114531262](https://shs3.b.qianxin.com/butian_public/f603796563335290b65637df87978b73008c78ff2d03f.jpg)

![image-20230804114646477](https://shs3.b.qianxin.com/butian_public/f9298024014c2f9e2bb49a92c41ec01827dea9473f1e8.jpg)

可以看到`BookingForm`类是继承自`\yii\base\Model`类

> 模型是 [MVC](http://en.wikipedia.org/wiki/Model%E2%80%93view%E2%80%93controller) 模式中的一部分， 是代表业务数据、规则和逻辑的对象。
> 
> 可通过继承 yii\\base\\Model 或它的子类定义模型类，基类yii\\base\\Model支持许多实用的特性：
> 
> - [属性](http://www.yiichina.com/doc/guide/2.0/structure-models#attributes): 代表可像普通类属性或数组一样被访问的业务数据;
> - [属性标签](http://www.yiichina.com/doc/guide/2.0/structure-models#attribute-labels): 指定属性显示出来的标签;
> - [块赋值](http://www.yiichina.com/doc/guide/2.0/structure-models#massive-assignment): 支持一步给许多属性赋值;
> - [验证规则](http://www.yiichina.com/doc/guide/2.0/structure-models#validation-rules): 确保输入数据符合所申明的验证规则;
> - [数据导出](http://www.yiichina.com/doc/guide/2.0/structure-models#data-exporting): 允许模型数据导出为自定义格式的数组。

默认情况下模型类直接从yii\\base\\Model继承，所有 *non-static public非静态公有* 成员变量都是属性。`BookingForm`模型类有四个属性`$goods_id`, `$keyword`, `$longitude` and `$latitude`， `BookingForm` 模型用来代表从HTML表单获取的输入数据。

同时定义了属性输入验证：

```php
public function rules()
    {
        return [
            [['goods_id'], 'integer'],
            [['longitude', 'latitude'], 'trim'],
            [['keyword'], 'string']
        ];
    }
```

其中`goods_id`和`keyword`变量规定类型为整数和字符串，`longitude`和`latitude`变量会去除前后空格即执行trim()函数

在`BookingController.php`中的`actionStoreList()`方法中利用块赋值对`BookingForm`模型类进行赋值

```php
$form->attributes = \Yii::$app->request->get();
```

即我们构造请求

```http
GET /web/index.php?r=plugin/xxx/api/Booking/store-list&longitude=1&latitude=1&keyword=1&goods_id=1 HTTP/1.1
```

即可完成对`BookingForm`模型类属性赋值

![image-20230804123853486](https://shs3.b.qianxin.com/butian_public/f520467247ee0b41a0680d478f88fae19d13884db1b3b.jpg)

随后调用`BookingForm::store()`方法，我们跟进到`BookingForm::store()`：

```php
public function store()
    {
        try {
            if (!$this->validate()) {
                return $this->getErrorResponse();
            }
            $store = BookingStore::find()->alias('b')->where([
                'b.mall_id' => \Yii::$app->mall->id,
                'b.goods_id' => $this->goods_id,
                'b.is_delete' => 0,
                's.is_delete' => 0,
            ])->joinWith(['store s'])
                ->select(['*', "(st_distance(point(longitude, latitude), point($this->longitude, $this->latitude)) * 111195) as distance"])
                ->keyword($this->keyword, ['like', 's.name', $this->keyword])
                ->page($pagination)
                ->orderBy('distance ASC')
                ->asArray()
                ->all();
            $store = array_map(function ($item) {
                $info = $item['store'];

                if ($info['longitude']
                    && $info['latitude']
                    && $this->longitude
                    && $this->latitude) {
                    $distance = get_distance($item['store']['longitude'], $item['store']['latitude'], $this->longitude, $this->latitude);
                    if ($distance > 1000) {
                        $info['distance'] = number_format($distance / 1000, 2) . 'km';
                    } else {
                        $info['distance'] = number_format($distance, 0) . 'm';
                    }
                } else {
                    $info['distance'] = '-m';
                }
                return $info;
            }, $store);
            return [
                'code' => ApiCode::CODE_SUCCESS,
                'data' => [
                    'list' => $store,
                ]
            ];
        } catch (\Exception $e) {
            return [
                'code' => ApiCode::CODE_ERROR,
                'msg' => $e->getMessage(),
            ];
        }
    }
```

这里`BookingStore`类继承自`\yii\db\ActiveRecord`，在Yii框架中主要是进行sql查询，其类名`BookingStore`表示数据库中的`booking_store`表

> [Active Record](https://zh.wikipedia.org/wiki/%E4%B8%BB%E5%8A%A8%E8%AE%B0%E5%BD%95) 提供了一个面向对象的接口， 用以访问和操作数据库中的数据。Active Record 类与数据库表关联， Active Record 实例对应于该表的一行， Active Record 实例的*属性*表示该行中特定列的值。 您可以访问 Active Record 属性并调用 Active Record 方法来访问和操作存储在数据库表中的数据， 而不用编写原始 SQL 语句。

在代码中可以看到首先是根据模型属性构造sql查询，并将结果进行遍历赋值给给新的`$store`，最后输出返回response

![image-20230804125516220](https://shs3.b.qianxin.com/butian_public/f439921d9e81fcdb45dba5619c0219f40a41fc8a83120.jpg)

根据定义的属性输入验证，`$keyword`, `$longitude` and `$latitude`可以是字符串类型，极有可以存在注入，根据查询方法：

```php
->select(['*', "(st_distance(point(longitude, latitude), point($this->longitude, $this->latitude)) * 111195) as distance"])
->keyword($this->keyword, ['like', 's.name', $this->keyword])
```

`$longitude` and `$latitude`是在select方法中，`$keyword`在keyword方法中，而keyword()方法其实是实现了`\yii\db\Query::andWhere`方法：

```php
public function keyword($keyword, $condition)
    {
        if ($keyword) {
            $this->andWhere($condition);
        }
        return $this;
    }
```

在yii中属于附件条件

![image-20230804141231688](https://shs3.b.qianxin.com/butian_public/f91202468b376effca0692055b72f5bcc9364bc7e35e0.jpg)

其应该是形成

```sql
AND (`s.name` LIKE '%$keyword%')
```

当我们构造`keyword=%'''%`，按理应该会闭合模糊查询的%'，即

```sql
AND (`s.name` LIKE '%%'''%%')
```

因为'单引号溢出而报错，但是请求却是正常的

![image-20230804145521998](https://shs3.b.qianxin.com/butian_public/f2043117a8903284066361445ae4352a044bec6db4c13.jpg)

而我们对`longitude` 和`latitude`进行单引号测试，发现成功报错

![image-20230804145752718](https://shs3.b.qianxin.com/butian_public/f5545407b66cb8bbf2e69df86a1d117eb8c9bb220322f.jpg)

利用报错语法成功注入

![image-20230804145941771](https://shs3.b.qianxin.com/butian_public/f536372d7e219fcd9473b2ae4e951f4df6d39cc55f7d1.jpg)

那么问题来了，为什么select()方法可以，而andWhere()方法却不可以

原来在构造查询语句时以占位符的方式创建预处理语句，即

```php
AND (`s.name` LIKE :keyword, $keyword)
```

但在`buildSelect()`方法中传入的参数直接拼接，即：

```php
select(['*', "(st_distance(point(longitude, latitude), point($this->longitude, $this->latitude)) * 111195) as distance"])
=>
SELECT *,(st_distance(point(longitude, latitude), point($this->longitude, $this->latitude)) * 111195) as distance
```

![image-20230804152601145](https://shs3.b.qianxin.com/butian_public/f637420fda5fc646e853d7d9afc5dd1dde126d93f2989.jpg)

后续在进行参数绑定，执行`bindParam`是会对`$keyword`参数中特殊字符做转义，导致无法逃逸

![image-20230804150053280](https://shs3.b.qianxin.com/butian_public/f672536c884a607a8c6a4b76d471f5211bcfd6dfba452.jpg)

在select操作中，传入的变量$this-&gt;longitude和$this-&gt;latitude直接作为字符串传入到select() ，最终导致$this-&gt;longitude和$this-&gt;latitude存在SQL注入

### 总结

做PHP审计的时候经常会遇到MVC框架的程序，在控制器多而杂的情况下，想要快速的过一遍然后找到没有鉴权的方法/控制器进行快速审计，我们可以根据URI对应控制器的特征，利用脚本构造出所有的接口url，进行批量遍历找到可能存在漏洞的未授权接口，实现快速审计。