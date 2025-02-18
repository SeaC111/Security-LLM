漏洞修复说明：  
此类相关漏洞源码已修复，可在官网查看https://www.inxedu.com/

**反射型xss**
==========

自行搭建系统后发现一处反射型xss，如图  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-b31783a572da2293cea0b95930a839b57cc61311.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-b31783a572da2293cea0b95930a839b57cc61311.png)  
数据包  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-1c0c63d53dfa853f1a9e02af7ba9182202b8d129.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-1c0c63d53dfa853f1a9e02af7ba9182202b8d129.png)  
涉及到已知参数有queryCourse.courseName，路径为/front/showcoulist  
从而定位CourseController.java  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-0c79264db64caf003af559056b7d72637c7be7e3.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-0c79264db64caf003af559056b7d72637c7be7e3.png)  
可以看到搜索课程列表中，以集合形式传递，以此向上的方法中追踪到courseService中，这里定义了一些查询课程的接口  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-34becec2d9f9078d18859a22304b38c786855485.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-34becec2d9f9078d18859a22304b38c786855485.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-dffcb149d31f02ecb1ed047499f6b2fbd5f05413.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-dffcb149d31f02ecb1ed047499f6b2fbd5f05413.png)  
再根据查询相关的接口在定义接口的实现类里查询具体实现的方法，49行，在CourseMapper中进行数据库查询，直接返回一个集合  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-c2d47c34f0ea57a99ed0489fde1d7026ec3babfb.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-c2d47c34f0ea57a99ed0489fde1d7026ec3babfb.png)  
这里是CourseMapper中对应查询queryCourseList的sql语句  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-ace15650dbe43e47bc30eb41e04f631d7260327f.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-ace15650dbe43e47bc30eb41e04f631d7260327f.png)  
然后直接将内容返回到前台的页面上，其实${queryCourse.courseName}是一个EL表达式，代表queryCourse这个实体类下面courseName的值，就是我们查询课程的内容  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-f98f08285c95602a1e57847db165d1ccd97f21c4.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-f98f08285c95602a1e57847db165d1ccd97f21c4.png)

**存储型xss**
==========

这里先看结果  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-967a74ff8d89649fd00e31096688f323a1fb2be0.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-967a74ff8d89649fd00e31096688f323a1fb2be0.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-e966dede0eead59956f9206f692a2aecf3c4da1f.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-e966dede0eead59956f9206f692a2aecf3c4da1f.png)  
漏洞参数为article.title  
漏洞url：/admin/article/updatearticle  
根据漏洞地址可以找到AdminArtcleController.java  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-f8a4d94aa30f2923dc5cd6a4b9935ecce6762147.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-f8a4d94aa30f2923dc5cd6a4b9935ecce6762147.png)  
new了一个对象 ，获取到参数修改数据库数据，存储到数据库中，再返回到原来的页面中  
做了一个判断如果为null就跳转默认地址  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-2a7f6ae159a73710b34803cddbe3549caa2547d1.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-2a7f6ae159a73710b34803cddbe3549caa2547d1.png)  
直接将内容返回到前台的页面上，${article.title}是EL表达式,  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-ed2f77894aeee96a1ee990dec4dace0e324716f9.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-ed2f77894aeee96a1ee990dec4dace0e324716f9.png)  
在AdminArtcleController.java控制层涉及到的方法，（存储的过程）  
ArticleService.java 和ArticleDao.java代码是一样的，其中定义了一些修改的方法，从而被AdminArtcleController.java调用  
这里定义了UpdateArticle方法和updateArticleContent方法  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-3534828192ac1f9b6a1ba0104a193b60c3434022.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-3534828192ac1f9b6a1ba0104a193b60c3434022.png)  
ArticleDaoImpl.java  
实现类是实现ArticleDao.java层中UpdateArticle和updateArticleContent方法的接口  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-832140fe5d244377eab3e518191ed28a01aa84d9.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-832140fe5d244377eab3e518191ed28a01aa84d9.png)  
ArticleDao层负责和数据库进行交互，  
这里可以看ArticleMapper.xml去执行更新的sql语句  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-9345831696d6a5696c8bbf972f3361557610e12e.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-9345831696d6a5696c8bbf972f3361557610e12e.png)  
Article定义字段，封装好为实体类，可以直接调用，故在整个存储的过程中没有任何的过滤  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-d105209fd007c268cb73eaa23c40855271df7dc5.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-d105209fd007c268cb73eaa23c40855271df7dc5.png)