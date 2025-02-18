描述
--

<https://github.com/fox-it/aclpwn.py>

Aclpwn.py 是一种与 BloodHound 交互以识别和利用基于 ACL 的特权升级路径的工具。它需要一个起点和终点，并将使用 Neo4j 寻路算法找到最有效的基于 ACL 的权限升级路径。

功能分析
----

### 整体流程

程序的入口在aclpwn目录下的`__init__.py`文件中的`main()`函数。

![image-20230408202100265.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-427e62ff79f83d0335155e68f6f499ed9b5cd78a.png)

程序开始使用Python标准库中的argparse模块，解析命令行参数。

创建ArgumentParser对象，并设置相关的参数说明和默认值。使用parse\_args()方法解析命令行参数，并将结果存储在args变量中。将args变量转换为字典形式，并将其存储在argsdict变量中，以便后续使用。

```php
 parser \= argparse.ArgumentParser(description\='Exploit ACL escalation paths via BloodHound')  
 parser.\_optionals.title \= "Main options"  
 parser.\_positionals.title \= "Required options"  
 ​  
 #Main parameters  
 maingroup \= parser.add\_argument\_group("aclpwn options")  
 maingroup.add\_argument("-f","--from", type\=str, metavar\='SOURCE', help\="Source object to start the path (usually a user). Example: user@domain.local")  
 ······略  
 validtypes \= \['User', 'Group', 'Domain', 'Computer'\]  
 args \= parser.parse\_args()  
 \# Since we deal with some reserved keywords, we use a dictionary too  
 argsdict \= vars(args)
```

添加不同的命令行选项：

- -f, --from: 指定起始对象（通常为用户），格式为user@domain.local。
- -ft, --from-type: 指定起始对象的类型，可选值为User/Group/Domain/Computer，默认为User。
- -t, --to: 指定目标对象（通常为组/域），格式为computer.domain.local或domain.local。
- -tt, --to-type: 指定目标对象的类型，可选值为User/Group/Domain/Computer，默认为Domain。
- -d, --domain: 指定操作的域，如果未指定，则需要在from和to参数中指定完整的对象名称。
- -a, --algorithm: 指定路径查找算法，可选值为shortestonly/dijkstra/dijkstra-cypher/allsimple，默认为dijkstra。
- -r, --restore: 恢复aclpwn存储的更改（备份文件）。
- \--database: 指定Neo4j数据库的主机地址，默认为localhost。
- -du, --database-user: 指定Neo4j数据库的用户名，默认为neo4j。
- -dp, --database-password: 指定Neo4j数据库的密码。
- \--no-prepare: 当使用Dijkstra算法时，不执行数据库准备操作。
- -s, --server: 指定用于攻击的服务器地址。
- -u, --user: 指定用于攻击的用户名。
- -p, --password: 指定用于攻击的密码或Hash值。
- -sp, --source-password: 指定源用户的密码或Hash值。
- -dry, --dry-run: 仅显示将要执行的攻击操作，不实际执行。

接着，55-91行对参数进行检查和处理：

- 检查恢复操作的备份文件路径是否存在，如果存在，则进行恢复操作并结束程序。
- 检查传入的 --from-type 和 --to-type 是否是有效的类型，如果不是则结束程序。
- 如果未指定数据库密码，则从BloodHound配置文件中获取密码。
- 如果`dry_run`参数未指定，则检查 --domain 和 --server 是否指定了有效值，以及是否已提供源用户的密码。
- 根据传入的参数，构造完整的起始对象和目标对象名称，并将其附加到args字典中。

接着初始化数据库连接

```php
 database.init\_driver(args.database, args.database\_user, args.database\_password)
```

接着进行路径查找，如果Dijkstra参数设定了，则使用Dijkstra算法路径查找。其中根据输入参数的不同，分别采用 REST API 或 Cypher 查询来进行 Dijkstra 算法路径查找。在使用 REST API 查询时，首先需要获取节点的 ID，然后使用 dijkstra\_find() 函数来进行查找。查询结果将经过校验，去除不支持的操作后输出可行的路径供选择。

![image-20230408204850675.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-cdfe797fa839fb113dc18156c0e10fefe2475996.png)

如果使用的是除了dijkstra和dijkstra-cypher之外的算法，会调用get\_path函数，从源对象到目标对象获取路径信息。

![image-20230408205453720.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-50ea2598480fd7143e97261004fafc2d94b3bc56.png)

通过循环处理所有找到的路径，测试每个路径上是否存在不受支持的操作，并打印出路径成本。

![image-20230408205549622.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-b500ffaebb8a3f7748dd6560e16a3d5c55c8e8d1.png)

找到最便捷的路径，并存储它的数据以供后续使用。如果没有找到路径，将打印错误消息。如果找到了多条路径，则允许用户选择使用哪条路径。如果只找到了一条路径，则直接使用该路径。

![image-20230408205757698.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-67bd06170fff5cff036ce04cf6ed8467c282c171.png)

最后使用了 exploitpath 变量中的路径，使用 exploitation.walk\_path 函数进行路径的遍历，并尝试利用此路径进行攻击，获取了攻击后的操作队列和状态信息。

```php
 exploitdata \= exploitation.walk\_path(exploitpath, args, None, args.dry\_run)  
 task\_queue, state \= exploitdata
```

然后根据是否使用了 --dry-run 参数进行实际的操作或者只是模拟操作，并在运行操作过程中记录操作的执行情况，最后如果操作成功，就输出一条消息表明操作已经完成，并且保存操作的恢复数据。

```php
 exploitation.run\_tasks(task\_queue, args.dry\_run)  
 state.save\_restore\_data()
```

### 主要模块

#### utils模块

utils库主要用于提供通用的实用函数，帮助其他部分更轻松地处理数据。

`getnodemap(nodes):`将节点列表转换为一个以id为键、以节点对象为值的映射字典。 `print_path(record):`打印查询Neo4j数据库时返回的path对象，格式为“（start\_node\_name）-\[relationship\_type\]-&gt;（end\_node\_name）”。 `build_path(record):`将查询Neo4j数据库时返回的path对象构建成一个元组列表，元组中第一个元素为relationship对象，第二个元素为end node对象。 `build_rest_path(nodes, rels):`将REST API返回的节点列表和关系列表构建成一个元组列表，元组中第一个元素为relationship对象，第二个元素为end node对象。 `print_rest_path(nodes, rels):`打印REST API返回的节点列表和关系列表，格式为“（start\_node\_name）-\[relationship\_type\]-&gt;（end\_node\_name）”。 `get_modify_length(record):`返回一个查询Neo4j数据库时返回的path对象中，具有“isacl”属性的节点数量。 `append_domain(name, otype, domain):`将指定类型的名称添加到指定的域名后面，如果该名称已经包含域名，则返回该名称。 `prompt_path(pathlen):`用于提示用户选择一个路径。 `domain2ldap(domain):`将域名转换为LDAP格式。 `ldap2domain(ldap):`将LDAP格式的域名转换为正常格式的域名。 `get_sam_name(fullname):`从BloodHound格式的名称中获取SAM名称（用户、组、计算机）。 `get_domain(fullname):`从BloodHound格式的名称中获取域名（用户、组、计算机）。

这个库比较基础，不进行深入分析。

#### database模块

这个库主要用来连接Neo4j数据库的，实现了初始化连接、关闭连接、预处理数据等操作。其中还有一个detect\_db\_config()函数用于检测Bloodhound配置文件，因此可以在不同的操作系统下连接到不同的数据库。

这个库同样比较基础，不进行深入分析。

#### pathfinding模块

这个库用来查找Neo4j图数据库中两个节点之间的最短路径。它提供了两个函数：dijkstra\_find()和dijkstra\_find\_cypher()，它们使用不同的方法来查找路径。其中，dijkstra\_find()使用REST API，

![image-20230408234916841.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-3cebee4595991aeb917bcf5670b95f40bd5037f3.png)

而dijkstra\_find\_cypher()使用Cypher查询语言。

![image-20230408234946763.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-d3bc27700eba2db772835a2a742d21fa332cf180.png)

它还提供了一些其他的查询方法，例如get\_path()，可以查询所有的最短路径或所有简单路径。

![image-20230408235008060.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-3220925c84ed10485f5ea0c417ff8e3fc867344a.png)

resolve\_dijkstra\_path()函数用于解析Dijkstra算法的结果。

**Dijkstra算法：** Dijkstra算法来寻找最短路径，该算法基于贪心策略和动态规划思想。它使用了成本映射（即costmap），其中关系类型的成本用于确定路径的总成本。Dijkstra算法使用BFS（广度优先搜索）来查找最短路径，首先将起始节点添加到队列中，然后将其弹出并检查其所有出边。如果边指向未访问的节点，则将其添加到队列中，并更新到该节点的距离。此过程将一直持续，直到队列为空或找到目标节点。

![image-20230408235130826.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-51b42401477b353a251696ba32c47ac0f19da899.png)

resolve\_rest\_path()函数用于解析REST API返回的路径。

![image-20230408235148344.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-b5442ba1280be6758fc5412038fa04bb91e27ade.png)

### 对域的ACL渗透测试的核心模块exploitation模块

#### ACL策略检测

这个模块是对域的ACL进行安全行测试的核心部分。

100-349行是实现LDAP（轻量目录访问协议）连接并操作Active Directory（AD）的Python代码。LDAP是一种轻量级的目录访问协议，用于在分布式环境中查找和验证用户信息。Active Directory是一种用于管理计算机网络上的用户、计算机、组织等对象的目录服务。

这些操作通常用于在Windows Active Directory环境中进行提权。其中涉及了对安全描述符（Security Descriptor）的修改，以及对LDAP目录树中对象（如用户、组）的添加、修改和查询。通过这些操作，攻击者可以获取到更高的权限，例如域管理员权限，甚至是企业管理员权限，从而控制整个AD域。

主要包括如下函数：

- get\_domain：从给定的用户名中提取域名。
- get\_object\_info：通过LDAP查询给定SAM账户名对应的DN和SID。
- get\_sam\_name：从给定DN中提取SAM账户名。
- security\_descriptor\_control：创建一个包含给定SD flags的LDAP控件对象。
- create\_object\_ace：创建一个给定的SID、权限和属性的LDAP访问控制项。
- add\_addmember\_privs：给定用户账户添加“写入成员”权限以将其添加到组中。
- write\_owner：将组的所有权更改为给定的用户。
- rebind\_ldap：使用给定的用户凭证重新连接到LDAP服务器。
- connect\_ldap：使用给定的用户凭证连接到LDAP服务器。
- perform\_rebind：在执行某些操作之前或之后，重新连接LDAP服务器或将连接切换到不同的用户。

#### 路径测试

351-382行这段代码定义了一个函数test\_path，其作用是检查传入的路径是否包含了不支持的操作。该函数遍历了路径中的每一个关系，如果发现关系类型不被支持，则输出错误信息并返回False，否则返回True。

具体来说，对于关系类型为MemberOf的关系，函数直接跳过。对于关系类型为AddMember的关系，如果其终点是Group类型的节点，则也直接跳过，否则输出错误信息并返回False。对于关系类型为DCSync和GetChangesAll的关系，函数同样直接跳过。对于关系类型为WriteDacl、GenericAll、GenericWrite和Owns的关系，如果其终点是Group类型或Domain类型的节点，则也直接跳过，否则输出错误信息并返回False。对于关系类型为WriteOwner的关系，如果其终点是Group类型或Domain类型的节点，则也直接跳过，否则输出错误信息并返回False。对于所有其他类型的关系，函数同样输出错误信息并返回False。

#### 执行路径操作

这个函数的作用是执行操作路径中定义的操作。操作路径指定了在哪些节点执行哪些操作。该函数根据节点上的标签和操作类型，将每个操作分配给相应的函数，并将操作作为任务添加到任务队列中，最后在状态中记录对目录对象所做的更改。如果dry\_run设置为True，则不执行任何更改操作。

总结
--

这个程序是一个用于自动化执行某些恶意操作的Python脚本。它通过在Windows Active Directory中执行一系列特权升级操作来获取域管理员权限。它的工作原理是使用BloodHound生成的关系路径（即在域内访问某些对象需要执行的一系列操作）来自动化执行特权升级操作。