一、源码地址以及版本  
<http://down.chinaz.com/soft/39353.htm>  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-9ef768f7f177010c4c8f97bdde23bf5a5bf9dae1.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-9ef768f7f177010c4c8f97bdde23bf5a5bf9dae1.png)

二、审计工具  
Seay源代码审计系统,phpstrom2020.1.3  
三、审计步骤  
1.利用Seay自动审计功能观察到到一处可能存在任意文件上传漏洞  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-d156345dbd42a3cface1160af5ff2cdfcace2e0a.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-d156345dbd42a3cface1160af5ff2cdfcace2e0a.png)  
2.跟进FIle.php代码进行分析,发现在一个move方法里,大致分析下代码，传入参数为一个移动路径,然后验证文件后缀,check()函数验证用户是否登录,验证是否存在同名文件，检查目录是否可写，然后返回FILE对象实例,包括它的路径以及上传对象本身。

```php
public function move($path, $savename = true, $replace = true)
{
    // 文件上传失败，捕获错误代码
    if (!empty($this-&amp;amp;amp;amp;gt;info['error'])) {
        $this-&amp;amp;amp;amp;gt;error($this-&amp;amp;amp;amp;gt;info['error']);
        return false;
    }
    // 检测合法性
    if (!$this-&amp;amp;amp;amp;gt;isValid()) {
        $this-&amp;amp;amp;amp;gt;error = 'upload illegal files';
        return false;
    }

    // 验证上传
    if (!$this-&amp;amp;amp;amp;gt;check()) {
        return false;
    }

    $path = rtrim($path, DS) . DS;
    // 文件保存命名规则
    $saveName = $this-&amp;amp;amp;amp;gt;buildSaveName($savename);
    $filename = $path . $saveName;

    // 检测目录
    if (false === $this-&amp;amp;amp;amp;gt;checkPath(dirname($filename))) {
        return false;
    }

    // 不覆盖同名文件
    if (!$replace &amp;amp;amp;amp;amp;&amp;amp;amp;amp;amp; is_file($filename)) {
        $this-&amp;amp;amp;amp;gt;error = ['has the same filename: {:filename}', ['filename' =&amp;amp;amp;amp;gt; $filename]];
        return false;
    }

    /* 移动文件 */
    if ($this-&amp;amp;amp;amp;gt;isTest) {
        rename($this-&amp;amp;amp;amp;gt;filename, $filename);
    } elseif (!move_uploaded_file($this-&amp;amp;amp;amp;gt;filename, $filename)) {
        $this-&amp;amp;amp;amp;gt;error = 'upload write error';
        return false;
    }

    // 返回 File 对象实例
    $file = new self($filename);
    $file-&amp;amp;amp;amp;gt;setSaveName($saveName)-&amp;amp;amp;amp;gt;setUploadInfo($this-&amp;amp;amp;amp;gt;info);

    return $file;
}
```

3.跟进move方法，找到了index.php下有很多方法里使用了该方法，于是逐一定位，发现在pluginlist()处为压缩文件上传以及解压，且方法大致为上传一个压缩文件，放入move方法中获取需要移动到哪个目录，然后进行解压缩到该目录，通过正则匹配压缩内容进行获取插件作者，内容之类的信息返回前端。其中对解压缩的目录访问权限并未设置，可以直接访问，对压缩文件内容也未判断，也就是说可以直接上传带有任意文件的压缩文件，进行上传解压缩，且可以访问。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-45c031873d4ec782b7aa0d3aa99e2408fd17b9ef.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-45c031873d4ec782b7aa0d3aa99e2408fd17b9ef.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-5570e53550764c2be8de12d244d479f9fcc37807.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-5570e53550764c2be8de12d244d479f9fcc37807.png)  
4.在该插件功能处，发现下方还存在插件删除功能，且未对删除路径参数做任何过滤，可以实现任意文件删除。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-798ae8ac6f30706a28bf717193361cfe74fdeec8.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-798ae8ac6f30706a28bf717193361cfe74fdeec8.png)  
四、漏洞复现

1.任意文件上传复现(需要管理员有插件上传功能模块)  
1.上传一个test.zip的压缩包，其中test文件夹里有一个phpinfo.php的文件。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-4ff870a5c40c1fbf4e7731681651262fa2e5f874.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-4ff870a5c40c1fbf4e7731681651262fa2e5f874.png)  
2.直接访问网站根目录+plugins/压缩文件夹名字(test)/压缩文件内容(phpinfo.php)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-401d027e3ad8ec10013519a8aa42d774518b9b38.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-401d027e3ad8ec10013519a8aa42d774518b9b38.png)  
2.任意文件删除复现  
1.点击删除抓包。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-bd1bbf98adca0a5fda806f7c32e285325c6673cc.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-bd1bbf98adca0a5fda806f7c32e285325c6673cc.png)  
2.在网站根目录下创建一个testdel的测试文件。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-9ee4291555d4c5c81bb89fea0739ab0a6b184a3a.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-9ee4291555d4c5c81bb89fea0739ab0a6b184a3a.png)  
3.修改plugin的文件路径为../testdel,点击放包,成功删除。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-460b97bf96295447fe506c27807bfbec2409c450.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-460b97bf96295447fe506c27807bfbec2409c450.png)  
4.testdel文件已经删除。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-e40efa0875cf28e21d02adb16f95a698f24246c2.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-e40efa0875cf28e21d02adb16f95a698f24246c2.png)