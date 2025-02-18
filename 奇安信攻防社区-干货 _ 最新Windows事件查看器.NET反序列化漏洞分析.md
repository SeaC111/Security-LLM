0x01 漏洞背景
=========

4月26日@Orange Tsai 在Twitter上发表一个有关Windows事件查看器的反序列化漏洞，可以用来绕过Windows Defender或者ByPass UAC等其它攻击场景，Orange视频里也给出了攻击载荷 DataSet

> ysoserial.exe -o raw -f BinaryFormatter -g DataSet -c calc &gt; %LOCALAPPDATA%\\Microsoft\\Eventv~1\\RecentViews

![图片](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-1cc7286b267692f1059b63bc0ddd623be4070a77.640%3Fwx_fmt%3Dpng%26amp%3Bwxfrom%3D5%26amp%3Bwx_lazy%3D1%26amp%3Bwx_co%3D1)

0x02 漏洞复现
=========

@Orange Tsai 给出的ysoserial DataSet载荷用到的是BinaryFormatter反序列化，有关.NET反序列化漏洞参考：[这个系列文章](https://mp.weixin.qq.com/s/9_YaDdOOPZCYfb3NOIlg6A)，因为笔者使用DataSet载荷复现未成功，所以替换用TypeConfuseDelegate作为攻击载荷，%LOCALAPPDATA% 等同于 C:\\Users\\用户名\\AppData\\Local 目录，Eventv~1 代表目录名前6个字符 Eventv开头的第1个目录，其实可指定为本地的 Event Viewer文件夹，文件名一定得是固定的RecentViews，至于为什么可以看后续的原理分析，ysoserial 生成攻击载荷命令如下，有个小小的建议：可以先打开一次事件查看器，便于操作系统创建EventViewer目录，否则执行ysoserial命令会抛出 "系统找不到路径"错误

> ysoserial.exe -o raw -f BinaryFormatter -g TypeConfuseDelegate -c calc &gt; %LOCALAPPDATA%\\Microsoft\\Eventv~1\\RecentViews

打开Windows事件查看器或者输入如下所示的命令行均可触发漏洞

> cmd/c eventvwr.msc  
> cmd/c eventvwr.exe

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-5a86e5a7787ff75454a73b38e7b768d804476089.png)

0x03 调用链分析
==========

打开事件查看器Windows系统会启动mmc.exe去关联eventvwr.msc，进中mmc.exe右击 ”属性“ -&gt; .NET程序集 如下图所示

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-352f4b34e58f2e8106ddcf076a13a526c46635ef.png)  
反编译EventViewer.dll，笔者从EventViewer事件查看器核心代码入手，至于它继承的父类FormView及基类View不再跟进，EventViewerHomePage类是主入口，实现基类View里的虚方法OnInitialize，

![图片](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-87921c9035ae6bcbb3973c9825598a88a5d40bc1.640%3Fwx_fmt%3Dpng%26amp%3Bwxfrom%3D5%26amp%3Bwx_lazy%3D1%26amp%3Bwx_co%3D1)

接着对EventHomeControl类做了初始化， UpdateUIDelegate(this.UpdateUI) 表示 EventHomeControl 读取数据并加载数据到可视化UI界面

```php
public EventHomeControl()
{
    this.InitializeComponent();
    UIControlProcessing.SetControlSystemFont(this);
    UIControlProcessing.SetControlTitleFont(this.eventViewerLabel, this.Font);
    this.updateUI = new EventHomeControl.UpdateUIDelegate(this.UpdateUI);
    this.enableControl = new EventHomeControl.EnableControlDelegate(this.EnableControl);
}
```

this.UpdateUI方法对可视化操作选项做了多重判断，有更新事件列表、有更新日志摘要、有更新事件列表当前对应的进程信息、还有我们重点关注的case 1 更新最近访问浏览的信息，进入UpdateRecentViewsUI 条件分支  
![图片](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-65d0bd82593a9076a653fd1dacddf458703f1b6b.640%3Fwx_fmt%3Dpng%26amp%3Bwxfrom%3D5%26amp%3Bwx_lazy%3D1%26amp%3Bwx_co%3D1)

UpdateRecentViewsUI方法调用了UpdateRecentViewsListViewUI，并且将属性 RecentViewsDataArrayList的值传递给此方法，如下图

![图片](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-263c9db3328ebb69bf676515777d1ade5b0ca37b.640%3Fwx_fmt%3Dpng%26amp%3Bwxfrom%3D5%26amp%3Bwx_lazy%3D1%26amp%3Bwx_co%3D1)

RecentViewsDataArrayList属于EventsNode类的成员，数据来源自LoadDataForRecentView执行后的结果，这里是将EventsNode.recentViewsDataArrayList的值赋给了RecentViewsDataArrayList属性，代码如下

```php
internal ArrayList RecentViewsDataArrayList
{
    get
  {
      this.LoadDataForRecentViews();
      return EventsNode.recentViewsDataArrayList;
  }
}
```

LoadDataForRecentView方法再调用LoadMostRecentViewsDataFromFile，

![图片](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-ff15d05d5bcff7173bbc91676330207063ad630e.640%3Fwx_fmt%3Dpng%26amp%3Bwxfrom%3D5%26amp%3Bwx_lazy%3D1%26amp%3Bwx_co%3D1)

读取 EventsNode.recentViewsFile 流后用 Deserialize(fileStream) 去反序列化，再将集合赋给 recentViewsDataArrayList，这样正常情况RecentViewsDataArrayList就获取到了最近浏览的数据。代码如下

```php
private void LoadMostRecentViewsDataFromFile()
{
   try
  {
  if (!string.IsNullOrEmpty(EventsNode.recentViewsFile) && File.Exists(EventsNode.recentViewsFile))
    {
    FileStream fileStream = new FileStream(EventsNode.recentViewsFile, FileMode.Open);
    object syncRoot = EventsNode.recentViewsDataArrayList.SyncRoot;
    lock (syncRoot)
    {
    EventsNode.recentViewsDataArrayList = (ArrayList)new BinaryFormatter().Deserialize(fileStream);
    }
    fileStream.Close();
  }
}catch (FileNotFoundException){}
}
```

再来细看下EventsNode.recentViewsFile，整个定义在EventsNode类构造方法里分了3步，笔者个人觉得判断逻辑有些罗里吧嗦的

![图片](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-c6164a42733cfd52b50918945fdeca9ab23954c3.640%3Fwx_fmt%3Dpng%26amp%3Bwxfrom%3D5%26amp%3Bwx_lazy%3D1%26amp%3Bwx_co%3D1)

第1步
---

Environment.SpecialFolder.CommonApplicationData 在Windows系统里表示 "C:\\Users\\用户名\\AppData\\Roaming"，StandardStringValues类自定义多个静态变量，如MicrosoftFolderName代表"Microsoft", LIN\_EventViewer 代表 " Event Viewer "；

第2步
---

用 CommonApplicationData 替代 LocalApplicationData，LocalApplicationData代表 " C:\\Users\\用户名\\AppData\\Local "；

第3步
---

将前两步和“RecentViews”串起来，最终得到 recentViewsFile = ”C:\\Users\\用户名\\AppData\\Local\\Microsoft\\Event Viewer\\RecentViews“，所以笔者在上小节复现的时候提到RecentViews文件名是固定的不能改。

![图片](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-76c8b4d5670977c1c26467de5bfeecf89bde3bc6.640%3Fwx_fmt%3Dpng%26amp%3Bwxfrom%3D5%26amp%3Bwx_lazy%3D1%26amp%3Bwx_co%3D1)

如上图 ysoserial 生成攻击载荷写入到 \\Microsoft\\Event Viewer\\RecentViews，打开事件查看器即可触发漏洞。

0x04 结语
=======

最后回顾总结下漏洞的主体调用链

> View -&gt; FormView -&gt; EventViewerHomePage -&gt; EventHomeControl -&gt; UpdateUIDelegate(委托) -&gt; UpdateUI -&gt; UpdateRecentViewsUI -&gt; UpdateRecentViewsListViewUI -&gt; RecentViewsDataArrayList -&gt; LoadDataForRecentView -&gt; LoadMostRecentViewsDataFromFile -&gt; BinaryFormatter().Deserialize

关于.NET反序列化漏洞可以在GitHub上找到相关解读[文章](https://github.com/Ivan1ee/NET-Deserialize)参考学习或关注公众号[dotNet安全矩阵](https://mp.weixin.qq.com/s/A7Z720lavhNSjlNNc3nzng)