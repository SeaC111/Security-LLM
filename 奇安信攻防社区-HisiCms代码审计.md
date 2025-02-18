### Cms安装处Getshell

我们首先看cms安装代码，比较容易出现问题的一般是执行安装时获取数据库信息环节

```php
  private function step4()
    {
        if ($this->request->isPost()) {

            if (!is_writable($this->root_path.'config/database.php')) {
                return $this->error('[config/database.php]无读写权限！');
            }

            $data = $this->request->post();
            $data['type'] = 'mysql';
            $rule = [
                'hostname|服务器地址' => 'require',
                'hostport|数据库端口' => 'require|number',
                'database|数据库名称' => 'require',
                'username|数据库账号' => 'require',
                'prefix|数据库前缀' => 'require|regex:^[a-z0-9]{1,20}[_]{1}',
                'cover|覆盖数据库' => 'require|in:0,1',
            ];

            $validate = $this->validate($data, $rule);

```

第9行获取了POST()数据，我们看下具体

```php
 public function post($name = '', $default = null, $filter = '')
    {
        if (empty($this->post)) {
        $this->post = !empty($_POST) ? $_POST : $this->getInputData($this->input);
        }
        return $this->input($this->post, $name, $default, $filter);
    }

```

判断是否为空，然后利用三元运算符返回了POST()的的值。目前到这里是没有做过滤的我们继续往下看

```php
              $validate = $this->validate($data, $rule);

    if (true !== $validate) {
        return $this->error($validate);
    }
    $cover = $data['cover'];
    unset($data['cover']);
    $config = include $this->root_path.'config/database.php';

    foreach ($data as $k => $v) {

        if (array_key_exists($k, $config) === false) {
            return $this->error('参数'.$k.'不存在！');
        }

    }
    // 不存在的数据库会导致连接失败
    $database = $data['database'];
    unset($data['database']);
    // 创建数据库连接
    $db_connect = Db::connect($data);
```

在最后一行，142行，没有对`$data`进行处理，然后写入了database.php  
于是  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-05dbe6deb60f901a86b10fc659bc87d3b58d097f.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-05dbe6deb60f901a86b10fc659bc87d3b58d097f.png)  
查看配置文件  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-20d7e9c913c17d04badc13b6b8077608c03025c3.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-20d7e9c913c17d04badc13b6b8077608c03025c3.png)

### 任意文件上传漏洞

有时候黑盒比白盒效率高一些  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-f4d0f9709181a8d65effa2a091d4204e71002c81.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-f4d0f9709181a8d65effa2a091d4204e71002c81.png)  
我们看下源码

```php
    public function index($group = 'base')
    {
        if ($this->request->isPost()) {
            $webPath = './';
            $data = $this->request->post();
            $types = $data['type'];

            if (isset($data['id'])) {
                $ids = $data['id'];
            } else {
                $ids = $data['id'] = '';
            }
```

`$data = $this->request->post();` 获取了post的数据  
`$types = $data['type'];`post数据中的`$data['type']`赋值给了$types  
`$ids = $data['id'];` post数据中的`$data['id']`复制给了$ids  
这时候配置文件的相关信息都在`$ids`数组中。继续看下面源码

```php
// 系统模块配置保存

    if (!$types) return false;
    $adminPath = config('sys.admin_path');
    foreach ($types as $k => $v) {

        if ($v == 'switch' &amp;&amp; !isset($ids[$k])) {
            ConfigModel::where('name', $k)->update(['value' => 0]);
            continue;
        }

        if ($v == 'checkbox') {
            if (isset($ids[$k])) {
                $ids[$k] = implode(',', $ids[$k]);

            } else {
                $ids[$k] = '';
            }
        }
        // 修改后台管理目录
        var_dump($k == 'admin_path');
        if ($k == 'admin_path' &amp;&amp; $ids[$k] != config('sys.admin_path')) {
            if (is_file($webPath.config('sys.admin_path')) &amp;&amp; is_writable($webPath.config('sys.admin_path'))) {
                @rename($webPath.config('sys.admin_path'), $webPath.$ids[$k]);
                if (!is_file($webPath.$ids[$k])) {
                    $ids[$k] = config('sys.admin_path');
                }

                $adminPath = $ids[$k];
            }
        }
        ConfigModel::where('name', $k)->update(['value' => $ids[$k]]);

    }

```

注意在5行，利用遍历对$type进行处理，我们可以看下$k的值是什么  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-09a18fb38a1b77f9ff5007c14fa0b37efa5df551.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-09a18fb38a1b77f9ff5007c14fa0b37efa5df551.png)  
很明显是上传配置的信息，这里注意是没有"admin\_path"的,所以5行的处理是无法进行的  
而`$ids[$k]`则是  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-0c83c34a2f5747bbba1f9656ff3f6c26a638c063.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-0c83c34a2f5747bbba1f9656ff3f6c26a638c063.png)  
是我们输入的配置 数据，接下来只需要关注`$ids[$k]`有没有过滤就好了  
上面很明显没有对此进行过滤处理，  
于是  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-43511bf2d1d27c1a9de6dc4ada6034cfea75fd68.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-43511bf2d1d27c1a9de6dc4ada6034cfea75fd68.png)  
我们看下上传方法是怎么进行的

```php
    public function upload($from = 'input', $group = 'sys', $water = '', $thumb = '', $thumb_type = '', $input = 'file')
    {
        return json(AnnexModel::upload($from, $group, $water, $thumb, $thumb_type, $input));
    }
```

跟进看下

```php

        } else if ($file->checkExt(config('upload.upload_file_ext'))) {

            $type = 'file';
            if (config('upload.upload_file_size') > 0 &amp;&amp; !$file->checkSize(config('upload.upload_file_size')*1024)) {
                return self::result('上传的文件大小超过系统限制['.config('upload.upload_file_size').'KB]！', $from);
            }

```

这里是和上面写入的配置文件进行比较  
然后尝试上传，还附赠了一个目录跨越漏洞  
(因为这里的路由是伪静态，所以需要将group变为传统的`xxx?group=/../`)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-d63a531163a798f657883edd116a692bc480aab5.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-d63a531163a798f657883edd116a692bc480aab5.png)