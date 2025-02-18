最近根据 `phpggc`学习了一下 `zendframework`的反序列化链，在这里跟大家分享一下

目录
--

- ZendFramework FD1
- ZendFramework RCE1
- ZendFramework RCE2

由于这里分享的三条链都是用的同一个测试环境，因此在这里统一说一下测试版本与环境

测试版本
----

`ZendFramework 1.12.20`  
`php5.6`

环境搭建
----

```php
https://framework.zend.com/downloads/archives
```

```php
zf.bat create project zendApplication
```

在 `php.ini` 中添加 `include_path` `Zend`  
然后搞一个入口点 `zendApplication/application/controllers/IndexController.php`

```php
<?php

class IndexController extends Zend_Controller_Action
{

    public function init()
    {
        unserialize(base64_decode($_POST['a']));
        /* Initialize action controller here */
    }

    public function indexAction()
    {
        // action body
    }

}
```

ZendFramework FD1
-----------------

### 文件删除调用链

```php
library/Zend/Http/Response/Stream.php::__destruct()
```

### 细节分析

入口点选择 `library/Zend/Http/Response/Stream.php` 的 `__destruct`，明显全部可控，直接可以删除

```php
public function __destruct()
{
    if(is_resource($this->stream)) {
        fclose($this->stream);
        $this->stream = null;
    }
    if($this->_cleanup) {
        @unlink($this->stream_name);
    }
}
```

ZendFramework RCE1
------------------

### 命令执行调用链

```php
library/Zend/Filter/PregReplace.php::filter($value)
library/Zend/Layout.php::render($name = null)
library/Zend/Log/Writer/Mail.php::shutdown()
library/Zend/Log.php::__destruct()
```

### 细节分析

入口点在 `library/Zend/Log.php` 的 `__destruct`

```php
public function __destruct()
{
    /** @var Zend_Log_Writer_Abstract $writer */
    foreach($this->_writers as $writer) {
        $writer->shutdown();
    }
}
```

这里的 `$this->_writers` 可控，因此可以进入任意类的 `shutdown` 方法，可以全局搜索

找到一处，位于 `library/Zend/Log/Writer/Mail.php`

```php
public function shutdown()
{
    // If there are events to mail, use them as message body.  Otherwise,
    // there is no mail to be sent.
    if (empty($this->_eventsToMail)) {
        return;
    }

    if ($this->_subjectPrependText !== null) {
        // Tack on the summary of entries per-priority to the subject
        // line and set it on the Zend_Mail object.
        $numEntries = $this->_getFormattedNumEntriesPerPriority();
        $this->_mail->setSubject(
            "{$this->_subjectPrependText} ({$numEntries})");
    }

    // Always provide events to mail as plaintext.
    $this->_mail->setBodyText(implode('', $this->_eventsToMail));

    // If a Zend_Layout instance is being used, set its "events"
    // value to the lines formatted for use with the layout.
    if ($this->_layout) {
        // Set the required "messages" value for the layout.  Here we
        // are assuming that the layout is for use with HTML.
        $this->_layout->events =
            implode('', $this->_layoutEventsToMail);

        // If an exception occurs during rendering, convert it to a notice
        // so we can avoid an exception thrown without a stack frame.
        try {
            $this->_mail->setBodyHtml($this->_layout->render());
        } catch (Exception $e) {
            trigger_error(
                "exception occurred when rendering layout; " .
                    "unable to set html body for message; " .
                    "message = {$e->getMessage()}; " .
                    "code = {$e->getCode()}; " .
                    "exception class = " . get_class($e),
                E_USER_NOTICE);
        }
    }

    // Finally, send the mail.  If an exception occurs, convert it into a
    // warning-level message so we can avoid an exception thrown without a
    // stack frame.
    try {
        $this->_mail->send();
    } catch (Exception $e) {
        trigger_error(
            "unable to send log entries via email; " .
                "message = {$e->getMessage()}; " .
                "code = {$e->getCode()}; " .
                    "exception class = " . get_class($e),
            E_USER_WARNING);
    }
}
```

前面都可控，通过设置变量避免一些不必要的麻烦

```php
$this->_eventsToMail = "aa";  //绕过是否为空的判断
$this->_subjectPrependText = "null"; //绕过是否为控的判断
```

然后来到这里

```php
$this->_mail->setBodyText(implode('', $this->_eventsToMail));
```

这里需要通过，我们可以按照 `$this->_mail` 的定义来

```php
$this->_mail = new Zend_Mail();
```

这样就可以直接通过，继续向下走，对于 `$this->_layout` ，我们也可以按照他的定义来

```php
$this->_layout = new Zend_Layout();
```

顺利进入 `$this->_layout->render()`

```php
public function render($name = null)
{
    if (null === $name) {
        $name = $this->getLayout();
    }

    if ($this->inflectorEnabled() && (null !== ($inflector = $this->getInflector())))
    {
        $name = $this->_inflector->filter(array('script' => $name));
    }

    $view = $this->getView();

    if (null !== ($path = $this->getViewScriptPath())) {
        if (method_exists($view, 'addScriptPath')) {
            $view->addScriptPath($path);
        } else {
            $view->setScriptPath($path);
        }
    } elseif (null !== ($path = $this->getViewBasePath())) {
        $view->addBasePath($path, $this->_viewBasePrefix);
    }

    return $view->render($name);
}
```

我们需要跟进 `$this->_inflector->filter(array('script' => $name));` ，因此需要满足条件，我们来看 `$this->inflectorEnabled()`

```php
public function inflectorEnabled()
{
    return $this->_inflectorEnabled;
}
```

可控，直接设为 `true` 即可，然后来到 `$inflector = $this->getInflector()`

```php
public function getInflector()
{
    if (null === $this->_inflector) {
        require_once 'Zend/Filter/Inflector.php';
        $inflector = new Zend_Filter_Inflector();
        $inflector->setTargetReference($this->_inflectorTarget)
                  ->addRules(array(':script' => array('Word_CamelCaseToDash', 'StringToLower')))
                  ->setStaticRuleReference('suffix', $this->_viewSuffix);
        $this->setInflector($inflector);
    }

    return $this->_inflector;
}
```

也就是 `$this->_inflector` 不为空即可，接下来就可以进入任意类的 `filter` 方法，我们选择 `library/Zend/Filter/PregReplace.php`

```php
public function filter($value)
{
    if ($this->_matchPattern == null) {
        require_once 'Zend/Filter/Exception.php';
        throw new Zend_Filter_Exception(get_class($this) . ' does not have a valid MatchPattern set.');
    }

    return preg_replace($this->_matchPattern, $this->_replacement, $value);
}
```

这是一个前两个参数都可控的 `preg_replace` ，我们只要第一个参数匹配所有，然后使用 `/e` 模式即可执行第二个参数

ZendFramework RCE2
------------------

### 命令执行调用链

```php
library/Zend/Cache/Frontend/Function.php::call($callback, array $parameters = array(), $tags = array(), $specificLifetime = false, $priority = 8)
library/Zend/Form/Decorator/Form.php::render($content)
library/Zend/Form/Element.php::render(Zend_View_Interface $view = null)
library/Zend/Form/Element.php::__toString()
library/Zend/Http/Response/Stream.php::__destruct()
```

### 细节分析

这条链子的入口是 `__toString()` ，由于我太菜，没法直接触发他，所以找了一个先触发 `__destruct` ，再触发 `__toString` 的地方，比如说 `library/Zend/Http/Response/Stream.php` 的 `__destruct()`

```php
public function __destruct()
{
    if(is_resource($this->stream)) {
        fclose($this->stream);
        $this->stream = null;
    }
    if($this->_cleanup) {
        @unlink($this->stream_name);
    }
}
```

`$this->_cleanup` 可控，可以进入 `if` 中，`unlink` 的参数会被当成字符串，因此可以触发 `__toString` 方法

`PHPGGC` 中入口点在 `library/Zend/Form/Element.php` 的 `__toString()`

```php
public function __toString()
{
    try {
        $return = $this->render();
        return $return;
    } catch (Exception $e) {
        trigger_error($e->getMessage(), E_USER_WARNING);
        return '';
    }
}
```

跟进 `$this->render()`

```php
public function render(Zend_View_Interface $view = null)
{
    if ($this->_isPartialRendering) {
        return '';
    }

    if (null !== $view) {
        $this->setView($view);
    }

    $content = '';
    foreach ($this->getDecorators() as $decorator) {
        $decorator->setElement($this);
        $content = $decorator->render($content);
    }
    return $content;
}
```

`$this->_isPartialRendering` 可控，可以跳过，我们没有传值进来，所以 `$view` 为 `null` ，直接可以来到 `foreach`

跟进 `$this->getDecorators()`

```php
public function getDecorators()
{
    foreach ($this->_decorators as $key => $value) {
        if (is_array($value)) {
            $this->_loadDecorator($value, $key);
        }
    }
    return $this->_decorators;
}
```

`$this->_decorators` 可控，所以可以令其值 `$value` 不为数组，即可跳过 `if` 中的代码，可以避免不必要的麻烦，直接返回我们可控的数据

回到上一步，`$decorator` 既要有 `setElement` 方法，又要有 `render` 方法，我们先全局搜索 `setElement` 方法，`idea` 正则搜索

```php
 setElement\(
```

发现只有一个 `interface` 和实现了这个 `interface` 的抽象类 `Zend_Form_Decorator_Abstract` 存在该方法，于是我们需要找一个继承了这个抽象类的类，依旧是全局搜索，给一个搜索的正则（写的很烂）

```php
extends Zend_Form_Decorator_Abstract((.|\s)*)render\(
```

这样可以搜索既继承了该类，又存在 `render` 方法的类

最后确定使用 `library/Zend/Form/Decorator/Form.php` 中的类，跟进 `setElement` ，会跳到父类 `Zend_Form_Decorator_Abstract`

```php
public function setElement($element)
{
    if ((!$element instanceof Zend_Form_Element)
        && (!$element instanceof Zend_Form)
        && (!$element instanceof Zend_Form_DisplayGroup))
    {
        require_once 'Zend/Form/Decorator/Exception.php';
        throw new Zend_Form_Decorator_Exception('Invalid element type passed to decorator');
    }

    $this->_element = $element;
    return $this;
}
```

`$element` 也就是上面的 `$this` 是 `Zend_Form_Element` 的实例化对象，因此 `if` 条件不满足，跳出来进行赋值 `$this->_element = $element` ，最后返回

然后跟进 `$decorator->render($content)`

```php
public function render($content)
{
    $form    = $this->getElement();
    $view    = $form->getView();
    if (null === $view) {
        return $content;
    }

    $helper        = $this->getHelper();
    $attribs       = $this->getOptions();
    $name          = $form->getFullyQualifiedName();
    $attribs['id'] = $form->getId();
    return $view->$helper($name, $attribs, $content);
}
```

看到他的最后一句，这样的构造很容易让我们进入任意类的任意方法，实现我们想要的命令执行，好了，来分析分析，分为六个值（实际上是五个）

##### $form

跟进第一句的 `$this->getElement()`

```php
public function getElement()
{
    return $this->_element;
}
```

看到 `$this->_element` ，可能会以为是可控的，实际上不是，在上面的 `setElement` 方法中，他已经被赋值为 `Zend_Form_Element` 的实例化对象，然后赋值给上一步的 `$form`

##### $view

接下来跟进 `$form->getView()` ，就是上述类的 `getView` 方法

```php
public function getView()
{
    if (null === $this->_view) {
        require_once 'Zend/Controller/Action/HelperBroker.php';
        $viewRenderer = Zend_Controller_Action_HelperBroker::getStaticHelper('viewRenderer');
        $this->setView($viewRenderer->view);
    }
    return $this->_view;
}
```

`$this->_view` 是可控的，不为空就直接返回，那我们就直接返回

##### $helper

来到下面一句，跟进 `$this->getHelper()`

```php
public function getHelper()
{
    if (null !== ($helper = $this->getOption('helper'))) {
        $this->setHelper($helper);
        $this->removeOption('helper');
    }
    return $this->_helper;
}
```

跟进 `$this->getOption('helper')`

```php
public function getOption($key)
{
    $key = (string) $key;
    if (isset($this->_options[$key])) {
        return $this->_options[$key];
    }

    return null;
}
```

就是存在 `$this->_options[$key]` 就返回他，不存在就返回 `null` ，这是我们可控的，那必然可以返回

然后跟进 `$this->setHelper($helper)`

```php
public function setHelper($helper)
{
    $this->_helper = (string) $helper;
    return $this;
}
```

这里就是直接设置 `$this->_helper` ，然后 `removeOption` ，顾名思义，就是删除

之后就可以返回可控的 `$this->_helper`

##### $attribs

继续分析上面的 `$this->getOptions()`

```php
public function getOptions()
{
    if (null !== ($element = $this->getElement())) {
        if ($element instanceof Zend_Form) {
            $element->getAction();
            $method = $element->getMethod();
            if ($method == Zend_Form::METHOD_POST) {
                $this->setOption('enctype', 'application/x-www-form-urlencoded');
            }
            foreach ($element->getAttribs() as $key => $value) {
                $this->setOption($key, $value);
            }
        } elseif ($element instanceof Zend_Form_DisplayGroup) {
            foreach ($element->getAttribs() as $key => $value) {
                $this->setOption($key, $value);
            }
        }
    }

    if (isset($this->_options['method'])) {
        $this->_options['method'] = strtolower($this->_options['method']);
    }

    return $this->_options;
}
```

`$this->getElement()` 我们讲过了，返回值是 `Zend_Form_Element` 的实例化对象，因此不满足里面的任一条件，直接跳出

下面使用 `strtolower` 处理 `$this->_options['method']` 后返回，返回值是我们可控的 `$this->_options`

把最后三句拿下来继续分析

```php
    $name          = $form->getFullyQualifiedName();
    $attribs['id'] = $form->getId();
    return $view->$helper($name, $attribs, $content);
```

##### $name

`$form` 之前讲过了，赋值为类 `Zend_Form_Element` 的实例，跟进 `$form->getFullyQualifiedName();`

```php
public function getFullyQualifiedName()
{
   $name = $this->getName();

   if (null !== ($belongsTo = $this->getBelongsTo())) {
       $name = $belongsTo . '[' . $name . ']';
   }

   if ($this->isArray()) {
       $name .= '[]';
   }

   return $name;
}
```

跟进 `$this->getName()`

```php
public function getName()
{
    return $this->_name;
}
```

直接返回了可控值，继续跟进 `$this->getBelongsTo()`

```php
public function getBelongsTo()
{
    return $this->_belongsTo;
}
```

也是可控值，这里我们返回 `null` 就可以跳过 `if` 语句，接下来进入 `$this->isArray()`

```php
public function isArray()
{
    return $this->_isArray;
}
```

返回的也是可控值，这里返回 `false` 跳过 `if` 语句，最后返回的是 `$name` ，也就是完全可控的值

##### $attribs\['id'\]

分析 `$form->getId()`

```php
public function getId()
{
    if (isset($this->id)) {
        return $this->id;
    }
```

`$this->id` 可控，如果存在，就直接返回了

因此，这里五个变量，都是可控的

```php
$view->$helper($name, $attribs, $content);
```

此时，我们可以进入任意类的任意方法，并且所有参数都可控

这里我们使用 `PHPGGC` 中使用的 `library/Zend/Cache/Frontend/Function.php` 文件中的类 `Zend_Cache_Frontend_Function`，以及他的 `call` 方法

来到 `call` 方法，这里只贴出我们用到的部分

```php
public function call($callback, array $parameters = array(), $tags = array(), $specificLifetime = false, $priority = 8)
{
    if (!is_callable($callback, true, $name)) {
        Zend_Cache::throwException('Invalid callback');
    }

    $cacheBool1 = $this->_specificOptions['cache_by_default'];
    $cacheBool2 = in_array($name, $this->_specificOptions['cached_functions']);
    $cacheBool3 = in_array($name, $this->_specificOptions['non_cached_functions']);
    $cache = (($cacheBool1 || $cacheBool2) && (!$cacheBool3));
    if (!$cache) {
        // Caching of this callback is disabled
        return call_user_func_array($callback, $parameters);
    }
```

`call` 方法前面三个参数是我们可控的，注意这一句

```php
call_user_func_array($callback, $parameters);
```

这里的两个参数刚好都是我们可控的，于是我们可以执行任意命令，但是需要满足条件 `!$cache` ，`$cache` 的值由 `(($cacheBool1 || $cacheBool2) && (!$cacheBool3))` ，`$this->_specificOptions` 数组是我们可控的，所以也可以比较简单的绕过。  
​

总结
--

就不放`POC`了，毕竟 `phpggc`上都有了。写到这里已经快1点了，就先停了，感觉人要噶了。后面还有两条链子有空再继续。  
​