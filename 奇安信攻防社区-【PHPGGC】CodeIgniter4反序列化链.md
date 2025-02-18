前言
--

目前正在学习 `PHP` 反序列化，因此想顺着反序列化工具 `PHPGGC` 跟一下其中的链，巩固学习。本文是对 `CodeIgniter4` 反序列化的分析，有不对的地方，还请大佬们斧正。

目录
--

- `CodeIgniter4 RCE1`
- `CodeIgniter4 RCE2`
- `CodeIgniter4 FD1`

CodeIgniter4 RCE1
-----------------

### 环境搭建

可以从这里获取环境 [传送门](https://github.com/N0puple/php-unserialize-lib/tree/main/CodeIgniter4/CodeIgniter4%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E9%93%BE%20RCE1)

执行如下命令启动一个 `CodeIgniter4.0.0-rc.4` 的环境：

```php
docker-compose up -d
```

访问 <http://x.x.x.x/> ，看到 `hello world` 既搭建成功

漏洞测试代码如下，在环境中都准备好了，可以直接用

```php
<?php namespace App\Controllers;

class Home extends BaseController
{
    public function index()
    {
        if(isset($_POST['a']))
        {
            unserialize(base64_decode($_POST['a']));
        }
        else
        {
            return "hello world";
        }
        #return view('welcome_message');
    }
}
```

### 命令执行调用链

```php
system/Validation/Validation.php::processRules
system/Validation/Validation.php::run
system/Model.php::validate
system/Model.php::trigger
system/Model.php::delete
system/Session/Handlers/MemcachedHandler.php::close
system/Cache/Handlers/RedisHandler.php::__destruct
```

### 细节分析

`CodeIgniter` 的 `__destruct` 或者 `__wakeup` 这种常用的入口点极少，这次搜索只搜索到了三个 `__destruct` ，其中一个可用

```php
system/Cache/Handlers/RedisHandler.php
```

```php
public function __destruct()
{
    if ($this->redis)
    {
        $this->redis->close();
    }
}
```

这里我们就可以调用任意类的 `close` 方法，然后全局搜索可用的 `close`

```php
system/Session/Handlers/MemcachedHandler.php
```

```php
public function close(): bool
{
    if (isset($this->memcached))
    {
        isset($this->lockKey) && $this->memcached->delete($this->lockKey);

        if (! $this->memcached->quit())
        {
            return false;
        }

        $this->memcached = null;

        return true;
    }

    return false;
}
```

这时可以调用任意类的 `delete` 方法，并且参数可控，全局搜索 `delete`

我们跟进 `system/Model.php` 的 `delete` 方法

```php
public function delete($id = null, bool $purge = false)
{
    if (! empty($id) && is_numeric($id))
    {
        $id = [$id];
    }

    $builder = $this->builder();
    if (! empty($id))
    {
        $builder = $builder->whereIn($this->primaryKey, $id);
    }

    $this->trigger('beforeDelete', ['id' => $id, 'purge' => $purge]);

    if ($this->useSoftDeletes && ! $purge)
    {
        if (empty($builder->getCompiledQBWhere()))
        {
            if (CI_DEBUG)
            {
                throw new DatabaseException('Deletes are not allowed unless they contain a "where" or "like" clause.');
            }
            return false;
        }
        $set[$this->deletedField] = $this->setDate();

        if ($this->useTimestamps && ! empty($this->updatedField))
        {
            $set[$this->updatedField] = $this->setDate();
        }

        $result = $builder->update($set);
    }
    else
    {
        $result = $builder->delete();
    }

    $this->trigger('afterDelete', ['id' => $id, 'purge' => $purge, 'result' => $result, 'data' => null]);

    return $result;
}
```

`$id` 是我们可控的，只要设置 `$id` 为字符串，那么就不会变成数组（变成数组在后面会麻烦一点），我们可以来到

```php
$builder = $this->builder();
if (! empty($id))
{
    $builder = $builder->whereIn($this->primaryKey, $id);
}
```

这里需要顺利通过，`$this->primaryKey` 与 `$id` 都是可控的，我们进入 `$this->builder();`

```php
protected function builder(string $table = null)
{
    if ($this->builder instanceof BaseBuilder)
    {
        return $this->builder;
    }

    if (empty($this->primaryKey))
    {
        throw ModelException::forNoPrimaryKey(get_class($this));
    }

    $table = empty($table) ? $this->table : $table;
    if (! $this->db instanceof BaseConnection)
    {
        $this->db = Database::connect($this->DBGroup);
    }

    $this->builder = $this->db->table($table);

    return $this->builder;
}
```

其实下面的代码不用关注，我们只要满足 `$this->builder instanceof BaseBuilder` 即可成功返回，而这个 `$builder` 又需要存在 `whereIn` 方法，我们全局搜索这个方法，只发现一处位于 `system/Database/BaseBuilder.php` 的 `BaseBuilder` 类中，因此我们可以直接 `new` 一个 `BaseBuilder` 或者他的子类

我们跟进这个 `whereIn` 方法

```php
public function whereIn(string $key = null, $values = null, bool $escape = null)
{
    return $this->_whereIn($key, $values, false, 'AND ', $escape);
}
```

继续跟进 `$this->_whereIn`

```php
protected function _whereIn(string $key = null, $values = null, bool $not = false, string $type = 'AND ', bool $escape = null, string $clause = 'QBWhere')
{
    if ($key === null || $values === null || (! is_array($values) && ! ($values instanceof Closure)))
    {
        return $this;
    }

    is_bool($escape) || $escape = $this->db->protectIdentifiers;

    $ok = $key;
```

这里表示，只要满足上面三个条件之一，就可以成功返回，而 `$key` 是可控的，控制 `$this->primaryKey` 为 `null` 就可以顺利返回

接下来我们就进入 `trigger` 方法

```php
$this->trigger('beforeDelete', ['id' => $id, 'purge' => $purge]);
```

```php
protected function trigger(string $event, array $eventData)
{
    // Ensure it's a valid event
    if (! isset($this->{$event}) || empty($this->{$event}))
    {
        return $eventData;
    }

    foreach ($this->{$event} as $callback)
    {
        if (! method_exists($this, $callback))
        {
            throw DataException::forInvalidMethodTriggered($callback);
        }

        $eventData = $this->{$callback}($eventData);
    }

    return $eventData;
}
```

这里几乎都是可控的，我们可以通过下面这一句进入 `Model` 类的任意一个方法，并且参数部分可控

```php
$eventData = $this->{$callback}($eventData);
```

这里我们选择 validate 方法

```php
public function validate($data): bool
{
    if ($this->skipValidation === true || empty($this->validationRules) || empty($data))
    {
        return true;
    }

    // Query Builder works with objects as well as arrays,
    // but validation requires array, so cast away.
    if (is_object($data))
    {
        $data = (array) $data;
    }

    $rules = $this->validationRules;

    // ValidationRules can be either a string, which is the group name,
    // or an array of rules.
    if (is_string($rules))
    {
        $rules = $this->validation->loadRuleGroup($rules);
    }

    $rules = $this->cleanValidationRules
        ? $this->cleanValidationRules($rules, $data)
        : $rules;

    // If no data existed that needs validation
    // our job is done here.
    if (empty($rules))
    {
        return true;
    }

    // Replace any placeholders (i.e. {id}) in the rules with
    // the value found in $data, if exists.
    $rules = $this->fillPlaceholders($rules, $data);

    $this->validation->setRules($rules, $this->validationMessages);
    $valid = $this->validation->run($data, null, $this->DBGroup);

    return (bool) $valid;
}
```

从第一句开始看起，`$this->skipValidation` 可控，可以跳过，`$this->validationRules` 可控，因此 `$rules` 可控，不是字符串就能跳过下面那句，一直来到最后两句

```php
$this->validation->setRules($rules, $this->validationMessages);
$valid = $this->validation->run($data, null, $this->DBGroup);
```

这里的 `$this->validation` 我们设置成 `system/Validation/Validation.php` 中类 `Validation` 的实例化对象，因为只有他是拥有 `setRules` 方法的

来看 `setRules` 方法，比较简单，作用就是设置 `$rules`

```php
public function setRules(array $rules, array $errors = []): ValidationInterface
{
    $this->customErrors = $errors;

    foreach ($rules as $field => &$rule)
    {
        if (is_array($rule))
        {
            if (array_key_exists('errors', $rule))
            {
                $this->customErrors[$field] = $rule['errors'];
                unset($rule['errors']);
            }
        }
    }

    $this->rules = $rules;

    return $this;
}
```

这里需要注意的是 `$this->rules` 是由参数传进来的，也就是上面的 `getValidationRules` 方法中的 `$this->validationRules` ，因此要注意 `$rules` 的值由 `Model` 类来设置，而不是 `Validation` 类

来到 `run` 方法

```php
public function run(array $data = null, string $group = null, string $db_group = null): bool
{
    $data = $data ?? $this->data;

    // i.e. is_unique
    $data['DBGroup'] = $db_group;

    $this->loadRuleSets();

    $this->loadRuleGroup($group);

    // If no rules exist, we return false to ensure
    // the developer didn't forget to set the rules.
    if (empty($this->rules))
    {
        return false;
    }

    // Need this for searching arrays in validation.
    helper('array');

    // Run through each rule. If we have any field set for
    // this rule, then we need to run them through!
    foreach ($this->rules as $rField => $rSetup)
    {
        // Blast $rSetup apart, unless it's already an array.
        $rules = $rSetup['rules'] ?? $rSetup;

        if (is_string($rules))
        {
            $rules = $this->splitRules($rules);
        }

        $value = dot_array_search($rField, $data);

        $this->processRules($rField, $rSetup['label'] ?? $rField, $value ?? null, $rules, $data);
    }

    return ! empty($this->getErrors()) ? false : true;
}
```

接下来进入这两个方法，我们注意 `$this->loadRuleSets();`

```php
$this->loadRuleSets();
$this->loadRuleGroup($group);
```

```php
protected function loadRuleSets()
{
    if (empty($this->ruleSetFiles))
    {
        throw ValidationException::forNoRuleSets();
    }

    foreach ($this->ruleSetFiles as $file)
    {
        $this->ruleSetInstances[] = new $file();
    }
}
```

这里主要是需要注意，要找一个构造函数不需要传入参数的类，比如 `Config\Database`

`loadRuleGroup` 方法比较简单，可以直接返回，继续往下走，进入 `for` 循环

我们的 `$rules` 不为字符串，就可以直接来到 `dot_array_search($rField, $data);`

```php
function dot_array_search(string $index, array $array)
{
    $segments = explode('.', rtrim(rtrim($index, '* '), '.'));
    return _array_search_dot($segments, $array);
}
```

`explode` 以点分割后跟进 `_array_search_dot`

```php
function _array_search_dot(array $indexes, array $array)
{
    // Grab the current index
    $currentIndex = $indexes
        ? array_shift($indexes)
        : null;

    if (empty($currentIndex) || (! isset($array[$currentIndex]) && $currentIndex !== '*'))
    {
        return null;
    }

    // Handle Wildcard (*)
    if ($currentIndex === '*')
    {
        ...
    }

    if (empty($indexes))
    {
        return $array[$currentIndex];
    }

    // Do we need to recursively search this value?
    if (is_array($array[$currentIndex]) && $array[$currentIndex])
    {
        return _array_search_dot($indexes, $array[$currentIndex]);
    }

    // Otherwise we've found our match!
    return $array[$currentIndex];
}
```

这里从 `$indexes` 中取出一个值，需要在 `$array` 中存在以这个值为键的值，不然就会返回 `null` ，接下来 `$indexes` 中没有值就返回，有就继续该操作

由于参数可控，所以返回的值我们是可控的，我们继续进入

```php
$this->processRules($rField, $rSetup['label'] ?? $rField, $value ?? null, $rules, $data);
```

这里的参数，全部都是可控的

```php
protected function processRules(string $field, string $label = null, $value, $rules = null, array $data): bool
{
    // If the if_exist rule is defined...
    if (in_array('if_exist', $rules))
    {
        ......
    }

    if (in_array('permit_empty', $rules))
    {
        ......
    }

    foreach ($rules as $rule)
    {
        $callable = is_callable($rule);
        $passed   = false;

        // Rules can contain parameters: max_length[5]
        $param = false;
        if (! $callable && preg_match('/(.*?)\[(.*)\]/', $rule, $match))
        {
            $rule  = $match[1];
            $param = $match[2];
        }

        // Placeholder for custom errors from the rules.
        $error = null;

        // If it's a callable, call and and get out of here.
        if ($callable)
        {
            $passed = $param === false ? $rule($value) : $rule($value, $param, $data);
        }
        else
        {
            ......
        }

        ......
    }

    return true;
}
```

注意到这个方法中存在 `$rule($value)` ，很明显是可以执行命令的，只要我们可以让参数可控就可以了

我们不进入 `if` 语句，直接来到 `foreach` ，使得 `$rules` 中有一个值是可回调的，这样就可以进入

```php
$passed = $param === false ? $rule($value) : $rule($value, $param, $data);
```

`$rule` 与 `$value` 可控，因此可以命令执行

CodeIgniter4 RCE2
-----------------

### 环境搭建

环境搭建部分同上，环境可以从这里获取 [传送门](https://github.com/N0puple/php-unserialize-lib/tree/main/CodeIgniter4/CodeIgniter4%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E9%93%BE%20RCE2)

执行如下命令启动一个 `CodeIgniter4.0.4` 的环境：

```php
docker-compose up -d
```

### 命令执行调用链

```php
system/Validation/Validation.php::processRules
system/Validation/Validation.php::run
system/Model.php::validate
system/Model.php::trigger
system/Model.php::delete
system/Session/Handlers/MemcachedHandler.php::close
system/Cache/Handlers/RedisHandler.php::__destruct
```

### 细节分析

从上面的命令执行调用链来看，这条链与 `RCE1` 这条链是一样的，从其影响范围来看也是无缝衔接，因此这两条链实际上属于同一条，只不过各版本之间存在着细微的差别，这条链就不过于详细地讲了，主要看存在差别的位置。

前面是一样的，同一个 `__destruct` 调用 `close` 后调用 `delete` 方法

这时可以调用任意类的 `delete` 方法，并且参数可控，全局搜索 `delete`

我们跟进 `system/Model.php` 的 `delete` 方法

```php
public function delete($id = null, bool $purge = false)
{
    if (! empty($id) && (is_numeric($id) || is_string($id)))
    {
        $id = [$id];
    }

    $builder = $this->builder();
    if (! empty($id))
    {
        $builder = $builder->whereIn($this->primaryKey, $id);
    }

    $this->trigger('beforeDelete', ['id' => $id, 'purge' => $purge]);

    if ($this->useSoftDeletes && ! $purge)
    {
        if (empty($builder->getCompiledQBWhere()))
        {
            if (CI_DEBUG)
            {
                throw new DatabaseException('Deletes are not allowed unless they contain a "where" or "like" clause.');
            }
            // @codeCoverageIgnoreStart
            return false;
            // @codeCoverageIgnoreEnd
        }
        $set[$this->deletedField] = $this->setDate();

        if ($this->useTimestamps && ! empty($this->updatedField))
        {
            $set[$this->updatedField] = $this->setDate();
        }

        $result = $builder->update($set);
    }
    else
    {
        $result = $builder->delete();
    }

    $this->trigger('afterDelete', ['id' => $id, 'purge' => $purge, 'result' => $result, 'data' => null]);

    return $result;
}
```

`$id` 是我们可控的，这里与之前有一点点不同，最后得到的 `$id` 必然是一个数组（这里很重要），我们可以来到

```php
$builder = $this->builder();
if (! empty($id))
{
    $builder = $builder->whereIn($this->primaryKey, $id);
}
```

这里需要顺利通过，`$this->primaryKey` 与 `$id` 都是可控的，我们进入 `$this->builder();`

```php
protected function builder(string $table = null)
{
    if ($this->builder instanceof BaseBuilder)
    {
        return $this->builder;
    }

    if (empty($this->primaryKey))
    {
        throw ModelException::forNoPrimaryKey(get_class($this));
    }

    $table = empty($table) ? $this->table : $table;
    if (! $this->db instanceof BaseConnection)
    {
        $this->db = Database::connect($this->DBGroup);
    }

    $this->builder = $this->db->table($table);

    return $this->builder;
}
```

其实下面的代码不用关注，我们只要满足 `$this->builder instanceof BaseBuilder` 即可成功返回，而这个 `$builder` 又需要存在 `whereIn` 方法，我们全局搜索这个方法，只发现一处位于 `system/Database/BaseBuilder.php` 的 `BaseBuilder` 类中，因此我们可以直接 `new` 一个 `BaseBuilder` 或者他的子类

接下来我们就进入 `trigger` 方法

```php
$this->trigger('beforeDelete', ['id' => $id, 'purge' => $purge]);
```

```php
protected function trigger(string $event, array $eventData)
{
    $allowed                  = $this->tempAllowCallbacks;
    $this->tempAllowCallbacks = $this->allowCallbacks;

    if (! $allowed)
    {
        return $eventData;
    }

    // Ensure it's a valid event
    if (! isset($this->{$event}) || empty($this->{$event}))
    {
        return $eventData;
    }

    foreach ($this->{$event} as $callback)
    {
        if (! method_exists($this, $callback))
        {
            throw DataException::forInvalidMethodTriggered($callback);
        }

        $eventData = $this->{$callback}($eventData);
    }

    return $eventData;
}
```

这里几乎都是可控的，我们可以通过下面这一句进入 `Model` 类的任意一个方法，并且参数部分可控

```php
$eventData = $this->{$callback}($eventData);
```

这里我们选择 validate 方法

```php
public function validate($data): bool
{
    $rules = $this->getValidationRules();

    if ($this->skipValidation === true || empty($rules) || empty($data))
    {
        return true;
    }

    // Query Builder works with objects as well as arrays,
    // but validation requires array, so cast away.
    if (is_object($data))
    {
        $data = (array) $data;
    }

    // ValidationRules can be either a string, which is the group name,
    // or an array of rules.
    if (is_string($rules))
    {
        $rules = $this->validation->loadRuleGroup($rules);
    }

    $rules = $this->cleanValidationRules
        ? $this->cleanValidationRules($rules, $data)
        : $rules;

    // If no data existed that needs validation
    // our job is done here.
    if (empty($rules))
    {
        return true;
    }

    $this->validation->setRules($rules, $this->validationMessages);
    $valid = $this->validation->run($data, null, $this->DBGroup);

    return (bool) $valid;
}
```

从第一句开始看起，跟进 `$this->getValidationRules()`

```php
public function getValidationRules(array $options = []): array
{
    $rules = $this->validationRules;

    // ValidationRules can be either a string, which is the group name,
    // or an array of rules.
    if (is_string($rules))
    {
        $rules = $this->validation->loadRuleGroup($rules);
    }

    if (isset($options['except']))
    {
        $rules = array_diff_key($rules, array_flip($options['except']));
    }
    elseif (isset($options['only']))
    {
        $rules = array_intersect_key($rules, array_flip($options['only']));
    }

    return $rules;
}
```

`$this->validationRules` 可控，`$rules` 是字符串类型的时候，我们需要进入 `$this->validation->loadRuleGroup($rules)` ，并且需要成功返回，因此我们使 `$rules` 不为字符串类型，可以让他是一个数组类型

继续上面的 `validate` 方法，`$this->skipValidation` 可控，`$data` 就是之前的 `$eventData` 数组，然后又是一次 `loadRuleGroup` ，但这里我们又可以直接跳过

继续下去，`$this->cleanValidationRules` 可控，将其设置成 `false` ，就可以直接来到最后两句

```php
$this->validation->setRules($rules, $this->validationMessages);
$valid = $this->validation->run($data, null, $this->DBGroup);
```

这里的 `$this->validation` 我们设置成 `system/Validation/Validation.php` 中类 `Validation` 的实例化对象，因为只有他是拥有 `setRules` 方法的

来看 `setRules` 方法，比较简单，作用就是设置 `$rules`

```php
public function setRules(array $rules, array $errors = []): ValidationInterface
{
    $this->customErrors = $errors;

    foreach ($rules as $field => &$rule)
    {
        if (is_array($rule))
        {
            if (array_key_exists('errors', $rule))
            {
                $this->customErrors[$field] = $rule['errors'];
                unset($rule['errors']);
            }
        }
    }

    $this->rules = $rules;

    return $this;
}
```

这里需要注意的是 `$this->rules` 是由参数传进来的，也就是上面的 `getValidationRules` 方法中的 `$this->validationRules` ，因此要注意 `$rules` 的值由 `Model` 类来设置，而不是 `Validation` 类

来到 `run` 方法

```php
public function run(array $data = null, string $group = null, string $db_group = null): bool
{
    $data = $data ?? $this->data;

    $data['DBGroup'] = $db_group;

    $this->loadRuleSets();

    $this->loadRuleGroup($group);

    if (empty($this->rules))
    {
        return false;
    }

    $this->rules = $this->fillPlaceholders($this->rules, $data);

    helper('array');

    foreach ($this->rules as $rField => $rSetup)
    {
        $rules = $rSetup['rules'] ?? $rSetup;

        if (is_string($rules))
        {
            $rules = $this->splitRules($rules);
        }

        $value          = dot_array_search($rField, $data);
        $fieldNameToken = explode('.', $rField);

        if (is_array($value) && end($fieldNameToken) === '*')
        {
            foreach ($value as $val)
            {
                $this->processRules($rField, $rSetup['label'] ?? $rField, $val ?? null, $rules, $data);
            }
        }
        else
        {
            $this->processRules($rField, $rSetup['label'] ?? $rField, $value ?? null, $rules, $data);
        }
    }

    return ! empty($this->getErrors()) ? false : true;
}
```

接下来进入这两个方法，我们注意 `$this->loadRuleSets();`

```php
$this->loadRuleSets();
$this->loadRuleGroup($group);
```

```php
protected function loadRuleSets()
{
    if (empty($this->ruleSetFiles))
    {
        throw ValidationException::forNoRuleSets();
    }

    foreach ($this->ruleSetFiles as $file)
    {
        $this->ruleSetInstances[] = new $file();
    }
}
```

这里主要是需要注意，要找一个构造函数不需要传入参数的类，比如 `Config\Database`

`loadRuleGroup` 方法比较简单，可以直接返回

接下来来到 `$this->rules = $this->fillPlaceholders($this->rules, $data);` ，这里是一个替换的函数，但我们的参数都是可控的 ，对我们不造成影响，继续往下走，进入 `for` 循环

我们的 `$rules` 不为字符串，就可以绕过这里，然后来到 `dot_array_search($rField, $data);`

```php
function dot_array_search(string $index, array $array)
{
    $segments = explode('.', rtrim(rtrim($index, '* '), '.'));
    return _array_search_dot($segments, $array);
}
```

`explode` 以点分割后跟进 `_array_search_dot`

```php
function _array_search_dot(array $indexes, array $array)
{
    // Grab the current index
    $currentIndex = $indexes
        ? array_shift($indexes)
        : null;

    if ((empty($currentIndex)  && intval($currentIndex) !== 0) || (! isset($array[$currentIndex]) && $currentIndex !== '*'))
    {
        return null;
    }

    // Handle Wildcard (*)
    if ($currentIndex === '*')
    {
       ......
    }
    if (empty($indexes))
    {
        return $array[$currentIndex];
    }

    if (is_array($array[$currentIndex]) && $array[$currentIndex])
    {
        return _array_search_dot($indexes, $array[$currentIndex]);
    }

    // Otherwise we've found our match!
    return $array[$currentIndex];
}
```

这里从 `$indexes` 中取出一个值，需要在 `$array` 中存在以这个值为键的值，不然就会返回 `null` ，接下来 `$indexes` 中没有值就返回，有就继续该操作

由于参数可控，所以返回的值我们是可控的，使其不为数组，那我们就进入

```php
$this->processRules($rField, $rSetup['label'] ?? $rField, $value ?? null, $rules, $data);
```

这里的参数，全部都是可控的

```php
protected function processRules(string $field, string $label = null, $value, $rules = null, array $data): bool
{
    // If the if_exist rule is defined...
    if (in_array('if_exist', $rules))
    {
        ......
    }

    if (in_array('permit_empty', $rules))
    {
        ......
    }

    foreach ($rules as $rule)
    {
        $callable = is_callable($rule);
        $passed   = false;

        // Rules can contain parameters: max_length[5]
        $param = false;
        if (! $callable && preg_match('/(.*?)\[(.*)\]/', $rule, $match))
        {
            $rule  = $match[1];
            $param = $match[2];
        }

        // Placeholder for custom errors from the rules.
        $error = null;

        // If it's a callable, call and and get out of here.
        if ($callable)
        {
            $passed = $param === false ? $rule($value) : $rule($value, $param, $data);
        }
        else
        {
            ......
        }

        ......
    }

    return true;
}
```

注意到这个方法中存在 `$rule($value)` ，很明显是可以执行命令的，只要我们可以让参数可控就可以了

我们不进入 `if` 语句，直接来到 `foreach` ，使得 `$rules` 中有一个值是可回调的，这样就可以进入

```php
$passed = $param === false ? $rule($value) : $rule($value, $param, $data);
```

`$rule` 与 `$value` 可控，因此可以命令执行

CodeIgniter4 FD1
----------------

### 环境搭建

此环境可用 `CodeIgniter4 RCE2` 的，一摸一样

### 文件删除调用链

```php
system/Cache/Handlers/FileHandler.php::delete
system/Session/Handlers/MemcachedHandler.php::close
system/Cache/Handlers/RedisHandler.php::__destruct
```

### 细节分析

入口还是与上面一样

```php
system/Cache/Handlers/RedisHandler.php
public function __destruct()
{
    if ($this->redis)
    {
        $this->redis->close();
    }
}
```

这里我们就可以调用任意类的 `close` 方法，然后全局搜索可用的 `close`

```php
system/Session/Handlers/MemcachedHandler.php
public function close(): bool
{
    if (isset($this->memcached))
    {
        isset($this->lockKey) && $this->memcached->delete($this->lockKey);

        if (! $this->memcached->quit())
        {
            return false;
        }
        $this->memcached = null;
        return true;
    }
    return false;
}
```

这时可以调用任意类的 `delete` 方法，并且参数可控，全局搜索 `delete`

我们跟进 `system/Cache/Handlers/FileHandler.php` 的 `delete` 方法

```php
public function delete(string $key)
{
    $key = $this->prefix . $key;
    return is_file($this->path . $key) && unlink($this->path . $key);
}
```

这里就很明显了，全部都是我们可控的内容

总结
--

反序列化链还是得自己动手才行，有很多的坑点，这里前两个 `RCE` 其实就是同一个链，只是在不同的版本中，有些细微的差别，第三条的删除链并不在 `PHPGGC` 的列表中，在复现前两条的过程中发现了就写了出来。写的时候有点头昏脑涨，有错误的地方还请大佬们斧正。

文中涉及的环境以及我复现时写的 `poc` 都在这里 [传送门](https://github.com/N0puple/php-unserialize-lib/tree/main/CodeIgniter4)