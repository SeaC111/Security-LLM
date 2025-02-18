简介
--

GitHub： <https://github.com/BloodHoundAD/SharpHound>

SharpHound是BloodHound的官方数据收集工具。上面写着 在C#中，并使用本机Windows API函数和LDAP命名空间函数 从域控制器和加入域的Windows系统收集数据。

官方使用文档：<https://bloodhound.readthedocs.io/en/latest/data-collection/sharphound.html#>

文档中有详细使用说明，这里就不过多赘述。

功能分析
----

### 入口函数

先看一下入口函数都做了什么

Program.cs line 341 - 424

```php
 它使用 CommandLineParser 库来解析命令行参数，然后根据这些参数执行各种操作。  
 ​  
 options.WithParsedAsync 方法用于异步执行将解析的选项作为参数的函数。 BasicLogger 类用于创建记录器对象，该对象用于记录整个程序中的各种消息。  
 ​  
 Flags 类包含一组布尔标志，用于控制程序行为的各个方面，例如是否排除域控制器、是否禁用 Kerberos 签名以及是否收集所有属性。  
 ​  
 LDAPConfig 类用于存储与 LDAP 相关的配置选项，例如要连接的 LDAP 服务器、要使用的端口和身份验证类型。  
 ​  
 BaseContext 类用于存储程序的上下文信息，例如记录器对象、LDAP 配置对象以及各种标志和选项。  
 ​  
 该程序使用由 SharpLinks 类表示的链接链来执行各种操作，例如测试 LDAP 连接、获取用于枚举的域以及启动基本收集任务。该程序还包括各种选项，例如循环持续时间、循环间隔和搜索基础。  
 ​  
 CancellationTokenSource 类用于提供一种机制，用于在收到控制台中断信号时取消程序执行。
```

### SharpLinks链接链

整个的数据收集逻辑在这个链中，继续跟进`SharpLinks`类

Program.cs Line 433 - 453

```php
 SharpLinks 类是 Links 抽象类的一个实现，带有一个类型参数 IContext，它表示在枚举过程中使用的上下文对象。 Links 类提供命令链模式以按特定顺序执行一系列任务。  
 ​  
 SharpLinks 类专门包含 SharpHound 枚举工具的命令链的实现细节。  
     它包括初始化上下文对象、  
     测试与域控制器的连接、  
     设置会话用户名、  
     初始化公共库、  
     获取用于枚举的域、  
     启动基础收集任务、  
     等待基础运行完成、  
     启动循环计时器的方法，  
     开始循环，  
     等待循环完成，  
     保存缓存文件，  
     并完成链。  
 ​  
 SharpLinks 类中的每个方法都会修改 IContext 对象并返回修改后的对象以用作链中下一个方法的输入。 Links 类允许针对不同的工具或用例轻松修改和扩展命令链模式。
```

### 启动基础收集任务

下边重点关注基础信息收集的过程，也就是`StartBaseCollectionTask`。

```php
 //5. Start the collection  
 var task \= new CollectionTask(context);  
 context.CollectionTask \= task.StartCollection();
```

#### LDAP

LDAP（Lightweight Directory Access Protocol）是一种用于访问和维护分布式目录服务信息的协议。在Active Directory（AD）域中，LDAP是用于管理和查询AD域中存储的对象的主要协议之一。

AD域中的LDAP是通过TCP/IP协议进行通信的，使用389端口进行非加密连接和636端口进行加密连接。LDAP可以用来查询和修改AD域中的用户、计算机、组、权限等对象的属性和信息。例如，可以使用LDAP查询所有属于某个部门的用户，或者修改某个用户的密码。

LDAP在AD域中扮演着重要的角色，它是许多管理和安全工具的基础，例如LDAP浏览器、身份验证工具、组策略管理器等。对于AD域管理员来说，了解LDAP协议以及如何使用LDAP工具是非常重要的。

#### CollectionTask-生产者

创建三个通道对象，并将它们分别赋值给 *ldapChannel、*compStatusChannel 和 \_outputChannel 字段。通道对象用于在生产者和消费者之间异步传递数据。

根据 context 中的 Flags 属性，创建不同类型的生产者对象，并将其赋值给 \_producer 字段。生产者对象用于从不同来源获取数据并发送到通道中。

- StealthProducer：生成隐式 LDAP 目标
- ComputerFileProducer：从选项中指定的文本文件中获取计算机名称，并尝试将它们解析为 LDAP 对象。将相应的 LDAP 对象推送到队列。
- LdapProducer：使用指定的 LDAP 过滤器和属性从 LDAP 获取数据，并将其推送到队列。

创建两个输出相关的对象，并将它们分别赋值给 \_compStatusWriter 和 \_outputWriter 字段。输出相关的对象用于从通道中接收数据并写入到文件中。

这里主要看一下`LdapProducer`，一般情况下会通过这种方式。

LdapProducer.Produce()

这是一个异步方法，它覆盖了基类中的方法。在执行此方法时，它将创建一个用于取消操作的令牌。

 var cancellationToken \\= Context.CancellationTokenSource.Token;

然后它会使用CreateLDAPData()方法创建一个LDAP数据对象。

 var ldapData \\= CreateLDAPData();

接下来，它会迭代遍历传入的Context.Domains列表，针对每个域名执行LDAP查询，并将结果写入到一个数据通道中。查询时，它将使用LDAPUtils.QueryLDAP()方法，传递所需的参数。在处理搜索结果时，它会检查DistinguishedName属性是否包含特定的字符串并过滤掉一些结果，然后将剩余结果写入到数据通道中。

```php
 foreach (var domain in Context.Domains)  
 {  
     Context.Logger.LogInformation("Beginning LDAP search for {Domain}", domain);  
     //Do a basic  LDAP search and grab results  
     foreach (var searchResult in Context.LDAPUtils.QueryLDAP(ldapData.Filter.GetFilter(), SearchScope.Subtree,  
                  ldapData.Props.Distinct().ToArray(), cancellationToken, domain,  
                  adsPath: Context.SearchBase,  
                  includeAcl: (Context.ResolvedCollectionMethods & ResolvedCollectionMethod.ACL) != 0))  
     {  
         var l = searchResult.DistinguishedName.ToLower();  
         if (l.Contains("cn=domainupdates,cn=system"))  
             continue;  
         if (l.Contains("cn=policies,cn=system") && (l.StartsWith("cn=user") || l.StartsWith("cn=machine")))  
             continue;  
 ​  
         await Channel.Writer.WriteAsync(searchResult, cancellationToken);  
         Context.Logger.LogTrace("Producer wrote {DistinguishedName} to channel", searchResult.DistinguishedName);  
     }  
 }
```

值得注意的是，在写入数据到通道时，它还会记录日志以便后续跟踪和调试。此外，在查询LDAP时，它还会检查传入的Context.ResolvedCollectionMethods参数，以决定是否在查询结果中包含ACL（访问控制列表）信息。

总之，这段代码的主要作用是从多个域中执行LDAP查询，并将结果写入到一个数据通道中，以便后续处理。

具体查询的什么数据？

BaseProducer.CreateLDAPData()

它首先创建一个LDAPFilter对象（要查询的项）和一个空的LDAPData对象。还有一个List&lt;String&gt;字符串数组props（查询的范围）。

 var query \\= new LDAPFilter();  
 var props \\= new List&lt;string&gt;();  
 var data \\= new LDAPData();

然后根据Context.ResolvedCollectionMethods的值来决定添加哪些属性和过滤条件到LDAPFilter对象中。

如果ObjectProps（为LastLogon或PwdLastSet等属性执行对象属性收集）或ACL（执行ACL的收集）设置了，进行如下收集，根据启动程序时候的参数设置，决定添加的项。

```php
 if ((methods & ResolvedCollectionMethod.ObjectProps) != 0 || (methods & ResolvedCollectionMethod.ACL) != 0)  
 {  
     query \= query.AddComputers().AddContainers().AddUsers().AddGroups().AddDomains().AddOUs().AddGPOs();  
     props.AddRange(CommonProperties.ObjectPropsProps);  
 ​  
     if ((methods & ResolvedCollectionMethod.Container) != 0)  
         props.AddRange(CommonProperties.ContainerProps);  
 ​  
     if ((methods & ResolvedCollectionMethod.Group) != 0)  
     {  
         props.AddRange(CommonProperties.GroupResolutionProps);  
         query \= query.AddPrimaryGroups();  
     }  
 ​  
     if ((methods & ResolvedCollectionMethod.ACL) != 0) props.AddRange(CommonProperties.ACLProps);  
 ​  
     if ((methods & ResolvedCollectionMethod.LocalAdmin) != 0 ||  
         (methods & ResolvedCollectionMethod.DCOM) != 0 ||  
         (methods & ResolvedCollectionMethod.PSRemote) != 0 ||  
         (methods & ResolvedCollectionMethod.RDP) != 0 ||  
         (methods & ResolvedCollectionMethod.LoggedOn) != 0 ||  
         (methods & ResolvedCollectionMethod.Session) != 0 ||  
         (methods & ResolvedCollectionMethod.ObjectProps) != 0)  
         props.AddRange(CommonProperties.ComputerMethodProps);  
 ​  
     if ((methods & ResolvedCollectionMethod.Trusts) != 0) props.AddRange(CommonProperties.DomainTrustProps);  
 ​  
     if ((methods & ResolvedCollectionMethod.GPOLocalGroup) != 0)  
         props.AddRange(CommonProperties.GPOLocalGroupProps);  
 ​  
     if ((methods & ResolvedCollectionMethod.SPNTargets) != 0)  
         props.AddRange(CommonProperties.SPNTargetProps);  
 }
```

对应的命令行参数如下：

```php
 CollectionMethod \- 要使用的集合方法。此参数接受以逗号分隔的值列表。具有以下默认值（Default: Default）：  
 ​  
     Default \- 执行组成员身份收集、域信任收集、本地管理收集和会话收集  
     Group\- 执行组成员身份集合  
     LocalGroup \- 执行本地管理员集合  
     RDP \- 执行远程桌面用户集合  
     DCOM \- 执行分布式COM用户集合  
     GPOLocalGroup \- 使用组策略对象执行本地管理员收集  
     Session\- 执行会话收集  
     ObjectProps \- 为LastLogon或PwdLastSet等属性执行对象属性收集  
     ComputerOnly \- 执行本地管理员，RDP，DCOM和会话集合  
     LoggedOn \- 执行特权会话收集（需要目标系统上的管理员权限）  
     Trusts  \- 执行域信任枚举  
     ACL \- 执行ACL的收集  
     Container \- 执行容器的收集  
     DcOnly \- 仅使用LDAP执行收集。包括Group，Trusts，ACL，ObjectProps，Container和GPOLocalGroup。  
     All\- 执行除GPOLocalGroup和LoggedOn之外的所有收集方法
```

最后，将LDAPFilter和属性列表赋值给LDAPData对象并返回它。

#### StartCollection-消费者

`StartCollection`是一种异步方法，用来启动LDAP的收集任务。它在完成时返回一个字符串。

该方法首先根据`_context.Threads`变量的值创建一些消费者任务。这些消费者任务使用`LDAPConsumer.ConsumeSearchResults`方法使用来自 LDAP 的搜索结果，并将结果写入`_outputChannel`通道。使用`Add`方法将任务添加到名为`_taskPool`的任务池中。

接下来，使用`_outputWriter`对象启动收集结果处理任务，使用`StartWriter`方法启动，将输出写入到一个zip压缩的文件，并使用`StartStatusOutput`方法启动收集任务结果输出计时。

使用`_compStatusWriter`对象启动计算机状态收集任务，使用`StartWriter`方法启动。

然后，使用`_producer.Produce`方法启动生产者任务。该任务执行 LDAP 相关信息搜索操作。

生产者任务完成后，使用`_ldapChannel`通道的编写器上的`Complete`方法关闭 LDAP 通道。然后该方法使用`Task.WhenAll`方法等待`_taskPool`中的所有消费者任务完成。

消费者任务完成后，该方法使用通道编写器上的`WriteAsync`方法将一些额外数据写入`_outputChannel`通道。然后使用`Complete`方法关闭通道编写器。如果`_compStatusWriter`对象不为空，则对`_compStatusChannel`通道执行类似的操作。

最后，该方法使用`await`关键字等待输出任务完成，并将生成的 zip 文件作为字符串返回。

LDAPConsumer.ConsumeSearchResults()

以上下文信息对象、日志对象为参数，创建对象进程对象。

 var processor \\= new ObjectProcessors(context, log);

从inputChannel对象的Reader属性中创建一个异步可枚举对象，用于读取通道中的所有数据。该对象可以使用await foreach语句来异步遍历通道中的数据。

 await foreach (var item in inputChannel.Reader.ReadAllAsync())

创建单个结果的解析BloodHound信息的对象res

 var res \\= item.ResolveBloodHoundInfo();

然后把单个结果和解析对象放到processor.ProcessObject中，按照解析模板，解析收集的数据。最后返回的是以下类型之一的对象。

 var processed = await processor.ProcessObject(item, res, computerStatusChannel);

数据主要分为如下几类：

用户（User）、计算机（Computer）、组（Group）、组策略（GPO）、域（Domain）、组织单位（OU）、容器（Container）

```php
 case Label.User:  
     return await ProcessUserObject(entry, resolvedSearchResult);  
 case Label.Computer:  
     return await ProcessComputerObject(entry, resolvedSearchResult, compStatusChannel);  
 case Label.Group:  
     return ProcessGroupObject(entry, resolvedSearchResult);  
 case Label.GPO:  
     return ProcessGPOObject(entry, resolvedSearchResult);  
 case Label.Domain:  
     return await ProcessDomainObject(entry, resolvedSearchResult);  
 case Label.OU:  
     return await ProcessOUObject(entry, resolvedSearchResult);  
 case Label.Container:  
     return ProcessContainerObject(entry, resolvedSearchResult);
```

下面拿用户举例：

ProcessUserObject()

先新建一个用户类对象ret

 var ret \\= new User  
 {  
 ObjectIdentifier \\= resolvedSearchResult.ObjectId  
 };

接着添加用户对象的成员

```php
 ret.Properties.Add("domain", resolvedSearchResult.Domain);  
 ret.Properties.Add("name", resolvedSearchResult.DisplayName);  
 ret.Properties.Add("distinguishedname", entry.DistinguishedName.ToUpper());  
 ret.Properties.Add("domainsid", resolvedSearchResult.DomainSid);  
 ret.Properties.Add("highvalue", false);  
 ret.Properties.Add("samaccountname", entry.GetProperty(LDAPProperties.SAMAccountName));
```

然后根据命令行参数，添加对应的成员。

```php
 if ((\_methods & ResolvedCollectionMethod.ACL) != 0)  
 {  
     var aces \= \_aclProcessor.ProcessACL(resolvedSearchResult, entry);  
     var gmsa \= entry.GetByteProperty(LDAPProperties.GroupMSAMembership);  
     ret.Aces \= aces.Concat(\_aclProcessor.ProcessGMSAReaders(gmsa, resolvedSearchResult.Domain)).ToArray();  
     ret.IsACLProtected \= \_aclProcessor.IsACLProtected(entry);  
 }  
 ······略
```

最后，异步把解析后的对象写入到输出管道，之后就是保存了。

 await outputChannel.Writer.WriteAsync(processed);

### 启动循环

先从指定的循环中删除非计算机收集方法，赋值给`context.ResolvedCollectionMethods`。

接着把`context`当作参数，传递给`LoopManager`类，并新建对象为`manager`，然后启动循环控制器。

把循环控制器运行的结果传递给`context.CollectionTask`。

循环逻辑:按照指定的时间间隔、次数，循环运行基础收集任务。把结果放入`_filenames`列表

```php
 var task = new CollectionTask(\_context).StartCollection();  
 ​  
 var filename = await task;  
 \_filenames.Add(filename);
```

之后再把结果写入缓存流

```php
 foreach (var entry in \_filenames.Where(x \=> !string.IsNullOrEmpty(x)))  
 {  
     var fi \= new FileInfo(entry);  
     var zipEntry \= new ZipEntry(fi.Name) { DateTime \= fi.LastWriteTime, Size \= fi.Length };  
     zipStream.PutNextEntry(zipEntry);  
 ​  
     var buffer \= new byte\[4096\];  
     using (var fileStream \= File.OpenRead(entry))  
     {  
         StreamUtils.Copy(fileStream, zipStream, buffer);  
     }
```

### 保存缓存文件

代码通过 Cache.GetCacheInstance() 方法获取缓存实例，然后使用 JsonConvert.SerializeObject 将缓存对象序列化为字符串。

```php
 var cache \= Cache.GetCacheInstance();  
 var serialized \= JsonConvert.SerializeObject(cache);
```

接下来，代码通过 context.GetCachePath() 方法获取缓存文件的路径，使用 StreamWriter 将序列化后的缓存字符串写入文件中。最后返回当前的上下文 context。

```php
 using var stream \=  
     new StreamWriter(context.GetCachePath());  
 stream.Write(serialized);
```

在保存缓存文件之前，代码通过 context.Logger.LogInformation 方法记录了保存缓存时的统计信息，包括缓存的状态。

总结
--

这个工具主要利用LDAP对域内信息进行收集，采用多线程和异步技术，过程中可能会产生大量流量。实战中很少采用，比较适合内部安全评估使用。