狂雨小说内容管理系统（简称KYXSCMS）提供一个轻量级小说网站解决方案，基于ThinkPHP5.1+MySQL的技术开发。  
KYXSCMS,灵活，方便，人性化设计简单易用是最大的特色，是快速架设小说类网站首选，只需5分钟即可建立一个海量小说的行业网站，批量采集目标网站数据或使用数据联盟，即可自动采集获取大量数据。内置标签模版，即使不懂代码的前端开发者也可以快速建立一个漂亮的小说网站。

0x0环境
=====

windows  
phpstudy php7.3.4  
phpstorm

0x1安装
=====

首先要配置一下伪静态，一开始我没有配置所以跳到detect.html显示404，后来按照官网上的配置显示 No input file specified，百度才知道index.php后少了一个问号

```php
<IfModule mod_rewrite.c>
  Options +FollowSymlinks -Multiviews
  RewriteEngine On

  RewriteCond %{REQUEST_FILENAME} !-d
  RewriteCond %{REQUEST_FILENAME} !-f
  RewriteRule ^(.*)$ index.php?/$1 [QSA,PT,L]
</IfModule>
```

先创建好数据库，我的数据库名字叫kycms

0x2目录结构
=======

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-c4d26c817157d6a3e132c0866d607e797fcf1238.png)  
addon：插件，主要是邮箱的一个插件  
application：包括后台、接口、安装、用户等代码  
config：配置代码，数据库、缓存等  
extend：基础类代码  
public：前端  
route：路由  
runtime：缓存  
template：模板  
thinkphp：thinkphp的模板  
uploads：上传文件的设置

漏洞是在后台，利用条件比较苛刻

0x3任意文件写入
=========

在后台系统扩展--模板管理--index.html处后端源码在：admin/controller/Template.php处  
![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-f6c69827a93a5b14505ac67aac815102045dad1b.png)  
模板文件的内容是由edit方法传入的data值决定的

```php
public function edit(){
    $Template=model('template');
    $data=$this->request->post();
    if($this->request->isPost()){
        $res = $Template->edit($data);
        if($res  !== false){
            return $this->success('模版文件修改成功！',url('index'));
        } else {
            $this->error($Template->getError());
        }
    }else{
        $path=urldecode($this->request->param('path'));
        $info=$Template->file_info($path);
        $this->assign('path',$path);
        $this->assign('content',$info);
        $this->assign('meta_title','修改模版文件');
        return $this->fetch();
    }
}
```

追中edit()方法，含有edit方法的控制器很多，看含有template路径的/admin/model/Template.php

```php
public function edit($data){
    return File::put($data['path'],$data['content']);
}
```

继续看put方法，使用file\_put\_contents()方法将content写入指定路径

```php
static public function put($filename,$content,$type=''){
    $dir   =  dirname($filename);
    if(!is_dir($dir))
        mkdir($dir,0755,true);
    if(false === file_put_contents($filename,$content)){
        throw new \think\Exception('文件写入错误:'.$filename);
    }else{
        self::$contents[$filename]=$content;
        return true;
    }
}
```

这样就能直接写到根目录的index.php，也可以写到index.html包含的header.html等  
![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-35b425bbd564f0fdd6a2b0339665e5bdf9904eec.jpg)

0x4文件上传
=======

上传网站logo  
![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-e993349aafe88676e028ad4e4452e5d867f47b3d.jpg)

```php
查看文件上传中关于图片的方法
public function pic(){
    $file = $this->request->file('file');
    $info = $file->validate(['ext'=>'jpg,jpeg,png,gif,webp,bmp','type'=>'image/jpeg,image/png,image/gif,image/webp,image/bmp'])->move(config('web.upload_path').$this->request->param('path'));
    if($info){
        $this->success('上传成功！','',['path'=>substr(config('web.upload_path'),1).$this->request->param('path').'/'.str_replace('\\','/',$info->getSaveName())]);
    }else{
        $this->error($file->getError());
    }
}
```

跟进validate方法，没什么东西

```php
public function validate($rule = [])
{
    $this->validate = $rule;

    return $this;
}
```

只要文件类型和后缀是图片格式就行就可绕过前半部分的过滤，还有后面的

```php
$info = $file->validate(['ext'=>'jpg,jpeg,png,gif,webp,bmp','type'=>'image/jpeg,image/png,image/gif,image/webp,image/bmp'])->move(config('web.upload_path').$this->request->param('path'));
```

里面的

```php
->move(config('web.upload_path').$this->request->param('path'));
```

跟进move方法

```php
public function move($path, $savename = true, $replace = true, $autoAppendExt = true)
{
    // 文件上传失败，捕获错误代码
    if (!empty($this->info['error'])) {
        $this->error($this->info['error']);
        return false;
    }

    // 检测合法性
    if (!$this->isValid()) {
        $this->error = 'upload illegal files';
        return false;
    }

    // 验证上传
    if (!$this->check()) {
        return false;
    }

    $path = rtrim($path, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR;
    // 文件保存命名规则
    $saveName = $this->buildSaveName($savename, $autoAppendExt);
    $filename = $path . $saveName;

    // 检测目录
    if (false === $this->checkPath(dirname($filename))) {
        return false;
    }

    /* 不覆盖同名文件 */
    if (!$replace && is_file($filename)) {
        $this->error = ['has the same filename: {:filename}', ['filename' => $filename]];
        return false;
    }

    /* 移动文件 */
    if ($this->isTest) {
        rename($this->filename, $filename);
    } elseif (!move_uploaded_file($this->filename, $filename)) {
        $this->error = 'upload write error';
        return false;
    }

    // 返回 File对象实例
    $file = new self($filename);
    $file->setSaveName($saveName);
    $file->setUploadInfo($this->info);

    return $file;
}
```

一个一个跟进方法，首先检测文件合法性的isValid()

```php
public function isValid()
{
    if ($this->isTest) {
        return is_file($this->filename);
    }

    return is_uploaded_file($this->filename);
}
```

isTest方法中默认是false，那么就进入下面的return，值为true，接下来看check()方法

```php
public function check($rule = [])
{
    $rule = $rule ?: $this->validate;

    if ((isset($rule['size']) && !$this->checkSize($rule['size']))
        || (isset($rule['type']) && !$this->checkMime($rule['type']))
        || (isset($rule['ext']) && !$this->checkExt($rule['ext']))
        || !$this->checkImg()) {
        return false;
    }

    return true;
}
```

检查后缀，如果没有在extension中就会抛出异常

```php
public function checkExt($ext)
{
    if (is_string($ext)) {
        $ext = explode(',', $ext);
    }

    $extension = strtolower(pathinfo($this->getInfo('name'), PATHINFO_EXTENSION));

    if (!in_array($extension, $ext)) {
        $this->error = 'extensions to upload is not allowed';
        return false;
    }

    return true;
}
```

检查文件类型

```php
public function checkMime($mime)
{
    if (is_string($mime)) {
        $mime = explode(',', $mime);
    }

    if (!in_array(strtolower($this->getMime()), $mime)) {
        $this->error = 'mimetype to upload is not allowed';
        return false;
    }

    return true;
}
```

跟进getMime方法，

```php
public function getMime()
{
    $finfo = finfo_open(FILEINFO_MIME_TYPE);

    return finfo_file($finfo, $this->filename);
}
```

fino\_open配合finfo\_file将会回文件类型  
<https://cloud.tencent.com/developer/section/1340584>  
检查文件大小、类型和后缀使用GIF89a+shell或者图片马配合上面的文件包含

0x5任意文件删除
=========

/controller/Template.php

```php
public function del(){
    $id = array_unique((array)$this->request->param('id'));
    if ( empty($id) ) {
        $this->error('请选择要操作的数据!');
    }
    $Template=model('template');
    $res = $Template->del($id);
    if($res  !== false){
        $this->success('删除成功');
    } else {
        $this->error($Template->getError());
    }
}
```

array\_unique()：该方法移除数组中重复的值，先将值作为字符串进行排序，对每个值保留第一个遇到的键名，然后忽略所有后面的键名。  
而且id的值是可控的，然后看del方法

```php
public function del($id){
    $map = ['id' => $id];
    $name = Template::where($map)->column('name');
    foreach ($name as $value) {
        del_dir_file('./'.config('web.default_tpl').DIRECTORY_SEPARATOR.$value,true);
    }
    $result = Template::where($map)->delete();
    if(false === $result){
        $this->error=Template::getError();
        return false;
    }else{
        return $result;
    }
}
```

通过查询id所在的列，获取name值，然后删除，跟进del\_dir\_file()方法，该方法接收path的传参，并且第二个参数为true，所以只能删除目录

```php
/**
 * 删除目录及目录下所有文件或删除指定文件
 * @param str $path   待删除目录路径
 * @param int $delDir 是否删除目录，1或true删除目录，0或false则只删除文件保留目录（包含子目录）
 * @return bool 返回删除状态
 */
function del_dir_file($path, $delDir = FALSE) {
    if(is_dir($path)){
        $handle = opendir($path);
        if ($handle) {
            while (false !== ( $item = readdir($handle) )) {
                if ($item != "." && $item != "..")
                    is_dir("$path/$item") ? del_dir_file("$path/$item", $delDir) : unlink("$path/$item");
            }
            closedir($handle);
            if ($delDir)
                return rmdir($path);
        }else {
            if (file_exists($path)) {
                return unlink($path);
            } else {
                return FALSE;
            }
        }
    }
}
```

首先判断path是否正确，然后读取内容，并返回下个文件名直到为空，然后删除文件，可以配合目录穿越实现任意文件夹的删除  
根目录新建一个zy文件夹  
调用/admin/tool/sqlexecute.html  
post:  
sql=insert into {pre}template values('3','../../zy/','2','1','2','2','0','2','0')  
查看下数据库的内容  
![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-bde89bd24454ea4565cf059521bfeeba885bb0a5.jpg)  
然后访问/admin/template/del?id=3即可删除文件

0x6任意文件清空
=========

/admin/Tool.php的sitemap\_progress()

```php
  public function sitemap_progress($page=1){
   $content='';
   $page_num=$this->request->param('page_num');
      $page_no=$this->request->param('page_no');
      $type=$this->request->param('type');
      $filename='sitemap';
      $map = ['status'=>1];
      $novel=Db::name('novel')->field('id,update_time')->where($map)->order('update_time desc')->limit($page_num);
      if($page_no){
       $filename.='_'.$page;
       $data=$novel->page($page);
       $count=Db::name('novel')->where($map)->count('id');
       $page_count=ceil($count/$page_num);
      }else{
       $page_count=1;
      }
      $data=$novel->select();
      foreach ($data as $k=>$v){
   if($type=='xml'){
      $content.='<url>'.PHP_EOL.'<loc>'.url("home/novel/index",["id"=>$v["id"]],true,true).'</loc>'.PHP_EOL.'<mobile:mobile type="pc,mobile" />'.PHP_EOL.'<priority>0.8</priority>'.PHP_EOL.'<lastmod>'.time_format($v["update_time"],'Y-m-d').'</lastmod>'.PHP_EOL.'<changefreq>daily</changefreq>'.PHP_EOL.'</url>';
       }else{
           $content.=url("home/novel/index",["id"=>$v["id"]],true,true).PHP_EOL;
       }
}
      if($type=='xml'){
       $xml='<?xml version="1.0" encoding="UTF-8"?>'.PHP_EOL.'<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9" xmlns:mobile="http://www.baidu.com/schemas/sitemap-mobile/1/">'.PHP_EOL;
   $xml.=$content.PHP_EOL.'</urlset>';
   $content=$xml;
      }
      $url=$this->request->domain().'/runtime/'.'repaste/'.$filename.'.'.$type;
      $filename=Env::get('runtime_path').'repaste'.DIRECTORY_SEPARATOR.$filename.'.'.$type;
      $content=File::put($filename,$content);
      if($page_count<=$page){
          return $this->success('生成完成',url('sitemap_progress',['page_no'=>$page_no,'page'=>$page,'page_num'=>$page_num,'type'=>$type,]),['complete'=>true,'page_count'=>$page_count,'page'=>$page,'filename'=>$url]);
      }else{
          return $this->success('生成进度',url('sitemap_progress',['page_no'=>$page_no,'page'=>$page+1,'page_num'=>$page_num,'type'=>$type,]),['complete'=>false,'page_count'=>$page_count,'page'=>$page+1,'filename'=>$url]);
      }
  }
```

content为空，则进入put方法就可以写空内容进文件，也就是清空文件