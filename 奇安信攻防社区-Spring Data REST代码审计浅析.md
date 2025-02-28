0x00 前言
=======

 Springboot + Spring MVC大大简化了Web应用的RESTful开发，而Spring Data REST更简单。Spring Data REST是建立在Data Repository之上的，它能直接把resository以HATEOAS风格暴露成Web服务，而不需要再手写Controller层。客户端可以轻松查询并调用存储库本身暴露出来的接口。

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/02/attach-79411a0c38de21aa84dd130270c00c7293def5e1.png)

0x01 请求路径组成
===========

 首先是Spring Data REST的根URL属性basePath。

 默认情况下，Spring Data REST 在根 URI`/`处提供 REST 资源。可以通过`spring.data.rest.basePath` 属性进行修改该属性用于设置仓库资源路径的基本路径。

通过使用如下配置，所有的路由都会以 `/api` 为基础构建，包括仓库路径、实体资源路径、查询路径等：

```Java
spring.data.rest.basePath=/api
```

 当然也可以通过通过注册RepositoryRestConfigurer（或扩展RepositoryRestConfigurerAdapter(高版本已经弃用)）来自定义配置，例如下面的例子：

```Java
@Configuration
class CustomRestMvcConfiguration {

  @Bean
  public RepositoryRestConfigurer repositoryRestConfigurer() {

    return new RepositoryRestConfigurerAdapter() {

      @Override
      public void configureRepositoryRestConfiguration(RepositoryRestConfiguration config) {
        configuration.setBasePath("/api")
      }
    };
  }
}
```

 然后就是Sping Data REST生成的rest接口，在进行路由处理时会使用**DelegatingHandlerMapping，然后委托给RepositoryRestHandlerMapping和BasePathAwareHandlerMapping处理。**

 主要是处理@RepositoryRestController和@BasePathAwareController对应的类：

- @RepositoryRestController
    
    
    - RepositoryController
    - RepositoryEntityController
    - RepositoryPropertyReferenceController
    - RepositorySearchController
- @BasePathAwareController
    
    
    - ProfileController
    - AlpsController
    - HalExplorer

 以下面的例子为例，生成的rest接口都会由上面几个Controller进行处理，简单看看Spring Data REST的路径组成：

```Java
@RepositoryRestResource(path = "tenantPath")
public interface TenantRepository extends CrudRepository<Tenant, Long> {
    Page<Tenant> findAllByNameContaining(String name, Pageable page);

    Page<Tenant> findAllByIdCardContaining(String idCard, Pageable page);

    @RestResource(path = "mobile",rel = "mobile")
    Tenant findFirstByMobile(String mobile);

    @RestResource(exported = false)
    Tenant findFirstByIdCard(String idCard);

}
```

- **仓库路径（Repository Path）**：
    
    
    - 仓库路径是仓库资源路径的子路径，表示单个仓库的根路径。
    - 例如，如果有一个名为 `TenantRepository` 的仓库，其路径可能为 `/tenants`（默认情况下）或根据@RepositoryRestResource注解的配置路径为`tenantPath`
- **实体资源路径（Entity Resource Path）**：
    
    
    - 实体资源路径是仓库路径的子路径，表示具体实体资源的路径。
    - 例如，`Tenant` 实体的路径可能是 `/tenants/1`
- **查询路径（Search Path）**：
    
    
    - 用于执行仓库中定义的查询。
    - 例如，`findAllByNameContaining` 查询的路径可能是 `/tenants/search/findAllByNameContaining` ,也可以通过注解@RestResource进行定义。
- **关系路径（Association Path）**：
    
    
    - 用于导航到实体之间的关系。
    - 例如，如果 `Tenant` 与 `Address` 有关联关系，可能存在 `/tenants/1/address` 的关系路径。
- **Profile 路径**：
    
    
    - `/profile` 用于查看服务器支持的功能和约束信息。
    - 例如，`/profile` 提供有关 Spring Data REST 服务器配置和功能的元信息。

0x02 请求解析过程
===========

 Spring Data REST本身是一个Spring MVC的应用。以spring-data-rest-webmvc-3.7.18以及下面的Repository为例：

```Java
@RepositoryRestResource(path = "tenantPath")
public interface TenantRepository extends CrudRepository<Tenant, Long> {

    Page<Tenant> findAllByIdCardContaining(String idCard, Pageable page)

}
```

 当请求/tenantPath/search/findAllByIdCardContaining时，查看具体的请求解析过程：

 当接收到请求后，跟SpringWeb类似，Servlet容器会调用DispatcherServlet的service方法（方法的实现在其父类FrameworkServlet中定义）：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/02/attach-f86091a6aa0d1d66c56ada89ef421c0828c18dfc.png)

 前面的流程跟SpringWeb类似，经过一系列处理后，会在getHandler方法中，按顺序循环调用HandlerMapping的getHandler方法：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/02/attach-e05f2ea8ed9fd39e37c04716e65b13dc0d84ab8c.png)

 这里不再使用RequestMappingHandlerMapping，会使用**DelegatingHandlerMapping，然后委托给RepositoryRestHandlerMapping和BasePathAwareHandlerMapping处理**：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/02/attach-98fcf3d9e8f9bddb408a98a986541e948ff3b5db.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/02/attach-e350ca3bf89336e12f58779735f97e0ba8d39d68.png)

 以RepositoryRestHandlerMapping为例，从org.springframework.data.rest.webmvc.RepositoryRestHandlerMapping#isHandlerInternal方法可以知道，主要是处理RepositoryRestController注解类：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/02/attach-0d41e3c4438abd1fc76ebd38ee4ce3cffe07e48b.png)

 首先在RepositoryRestHandlerMapping#getHandler方法中通过getHandlerInternal获取handler构建HandlerExecutionChain并返回：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/02/attach-50ca054226acef47bdd120a9691c9c9f725b8fb9.png)

 getHandlerInternal方法会调用org.springframework.web.servlet.handler.AbstractHandlerMethodMapping#getHandlerInternal从request对象中获取请求的path并根据path找到handlerMethod：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/02/attach-0eb701b852fe6b9c98a1c999c57380aa65881e22.png)

 这里跟SpringWeb类似，在initLookupPath方法中，主要用于初始化请求映射的路径，这里会根据是否使用PathPattern解析器来调用**UrlPathHelper**类进行不同程度路径的处理（具体可以参考https://forum.butian.net/share/2214） ：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/02/attach-12fceebb89da7578cacb5038c265c0286dee61a1.png)

 获取到路径后，调用RepositoryRestHandlerMapping#lookupHandlerMethod方法，首先调用父类org.springframework.data.rest.webmvc.BasePathAwareHandlerMapping#lookupHandlerMethod方法进行处理：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/02/attach-740fb0feae4e83c816287cacf249edbe5252e736.png)

 在BasePathAwareHandlerMapping#lookupHandlerMethod方法中，首先从请求头中获取`Accept`的值:

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/02/attach-e7782e9bd9579a0143476c46976a18e11466c7ae.png)

 对获取到的值进行处理，将配置中设置的默认媒体类型加入媒体类型列表中，然后调用父类的RequestMappingHandlerMapping#lookupHandlerMethod方法进行进一步处理，跟SpringWeb类似，首先直接根据路径获取对应的Mapping，获取不到的话调用addMatchingMappings遍历所有的ReuqestMappingInfo对象并进行匹配：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/02/attach-e6e061a653a8b49597161549b0bb09f36e5949c9.png)

 例如当前的ReuqestMappingInfo对象如下：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/02/attach-fe81d05b579828bc0cbfcfd5a79db7362c2778fc.png)

 在addMatchingMappings方法中，遍历识别到的ReuqestMappingInfo对象并进行匹配，跟SpringWeb类似，在getMatchingCondition中会根据不同版本调用不同的解析模式来匹配，高版本会使用PathPattern来进行URL匹配（**不同版本会有差异，在 2.6之前，默认使用的是AntPathMatcher**进行的字符串模式匹配）：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/02/attach-68ed369ff1bea5149fd37d475428b194cf936937.png)

 在获取到对应的handlerMethod后，回到RepositoryRestHandlerMapping#lookupHandlerMethod的逻辑，如果反悔的handlerMethod为null则直接返回，否则进一步调用BaseUril#getRepositoryLookupPath方法获取repositoryLookupPath：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/02/attach-f56729f74b76de220287837bac277cb9613dffab.png)

 getRepositoryLookupPath具体实现如下，这里主要是对baseUri进行处理，以得到最终的仓库查找路径，例如如果配置了`spring.data.rest.base-path=api`那么会剔除掉路径里的`/api`，这里还进行了一些额外的处理：

- 将重复的斜杠（//）替换为单个斜杠（/）
- 去除路径末尾的斜杠

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/02/attach-a4cc6ee48794f80dcc020267c7d547ab30a8886e.png)

 然后会调用getRepositoryBasePath方法：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/02/attach-cc4ca9eb08f47f8f237eff04d8c03d78efc57222.png)

 根据 repositoryLookupPath是否以`/`来获取第二个目录斜杠的索引，这是因为，如果 repositoryLookupPath以斜杠开头，第一个斜杠是路径的一部分，应该从第二个斜杠处分割，这个方法用于根据仓库查找路径提取仓库的基本路径，以便确定请求中要访问的具体仓库：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/02/attach-75a11ec46a0b7d43549dfdffd8d48591bd1f9750.png)

 在获取到RepositoryBasePath后，调用org.springframework.data.rest.core.mapping.PersistentEntitiesResourceMappings#exportsTopLevelResourceFor方法,判断与metadata的path是否匹配：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/02/attach-367ff9addf2599daec3dcab67efae24765ecc97a.png)

 这里首先使用 Pattern.quote 对匹配的字符串进行转义，然后通过正则进行匹配：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/02/attach-91254971f86fdcdbea6ed1ffe98986b669140199.png)

 若匹配失败则返回null，否则继续调用exposeEffectiveLookupPathKey方法进行处理：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/02/attach-75c3aeb24a6b6c95174f17e62dc4831f8da10469.png)

 在exposeEffectiveLookupPathKey方法中，在获取到对应的Pattern后，例如`/api/{repository}/search/{search}`,会把`/{repository}`替换成前面获取到的repositoryBasePath，然后创建路径模式解析器PathPattern，并将其设置到请求属性中，以便后续处理中使用：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/02/attach-10aa1ae5e626efdbc0abcd5ba78a33126cde96cc.png)

 在获取到url 和 Handler 映射关系后，就可以根据请求的uri来找到对应的Controller和method，处理和响应请求。这里一般处理的是RepositoryRestController注解类。

 上述案例最终映射到的org.springframework.data.rest.webmvc.RepositorySearchController#executeSearch：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/02/attach-42333572d8e618a028b7b34a6f13346065bff42d.png)

 首先会调用checkExecutability处理，实际上就是匹配调用的方法，例如案例中的是findAllByIdCardContaining：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/02/attach-2aa07b94da500bc0f74446a48ca0d79bb2dedbde.png)

 这里首先会获取所有的SearchResourceMappings：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/02/attach-a7757c5459654433efbdfe52b0788d88756c4ef7.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/02/attach-c6922fb972cfac72e6be0b359fd3ca7c351070f7.png)

 在获取时会对@RestResource注解进行处理，这里可以自定义访问的path：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/02/attach-94921ba06a2fa61ec29ae7e79ee188e7de47f8fc.png)

 若当前的resourceMappings都是非暴露的，则会抛出异常，否则继续调用searchMapping.getMappedMethod进行匹配：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/02/attach-d1ed899769818883bc99ee0af75705385a8607a3.png)

 在匹配前会先将对应的path封装在org.springframework.data.rest.core.Path对象中，这里cleanUp默认是true：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/02/attach-fe2224454d076e4bfbdd1f0a6fb9f8daa31b9d5e.png)

 在cleanUp方法中，会对对输入的路径字符串进行清理和规范化处理：

- 使用 `path.trim().replaceAll(" ", "")` 去除路径两端的空格，并将路径中的空格替换为空字符串。
- 截取路径，并在需要时添加斜杠

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/02/attach-47a3f7be3d46b4279c5d52833ca5e4bf91bcb40f.png)

 然后进行匹配，匹配到对应的Method后进行返回。回到Controller的逻辑调用executeQueryMethod方法进行处理，获取对应Repository方法操作的结果：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/02/attach-24a30dbb123a870d31ba9b8f2d85faea2f491b28.png)

 获取到result后，这里重新获取所有的SearchResourceMappings，然后调用getExportedMethodMappingForPath进行处理，这里会重新对当前path进行匹配，检查对应的mapping是否暴露且对应的path是否匹配，匹配的方式跟之前一样，也是通过正则表达式对 Pattern.quote 转义后的字符串进行匹配：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/02/attach-7eb9bc2965e78b41a93469df084b8c3339fbd6ac.png)

 最后获取对应的返回值，完成对应的响应。以上是Spring Data REST简单的search请求解析过程。大致可以总结为，通过请求的path，找到对应的Repository定义，然后通过Repository定义，使用对应的RepositoryInvoker并执行对应的方法。

2.1 与SpringWeb的区别
-----------------

 整体的调用过程与SpringWeb类似，都会通过DispatchServlet统一处理。但是不再使用RequestMappingHandlerMapping，会使用**DelegatingHandlerMapping，然后委托给RepositoryRestHandlerMapping和BasePathAwareHandlerMapping处理。**

 路径处理模式也是类似的，同样的会在initLookupPath方法中初始化请求映射的路径，并且根据是否使用PathPattern解析器来调用**UrlPathHelper**类进行不同程度路径的处理：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/02/attach-16f0414861990fa8742cfe1e93064cd04dcfb631.png)

 也就是说，类似SpringWeb中的一些变形后的URL，在Spring Data REST同样可以处理。但是实际上还是会有一些区别。以上述分析的`/{repository}/search/{search}`请求过程为例。

 在SpringWeb中，是可以对请求路径进行URL编码并且均可以正常解析的。但是对于类似Spring Data REST中的`/{repository}/search/{search}`接口，`{repository}`并不能进行URL编码处理：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/02/attach-8796c4da3bd38a2002046e4d676749b0e3a36efc.png)

 根据前面的分析，在获取到RepositoryBasePath后，调用org.springframework.data.rest.core.mapping.PersistentEntitiesResourceMappings#exportsTopLevelResourceFor方法,判断与metadata的path是否匹配：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/02/attach-9306c3d44907fbd2c3f35582ba3e304fca232326.png)

 这里首先使用 Pattern.quote 对匹配的字符串进行转义，然后通过正则进行匹配：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/02/attach-361b00e97ce4c4ef4358cef71e1aa2fccf0d2951.png)

 这里并不会进行URL解码处理，所以返回404 status。

 同理，类似`/{repository}/{id}`的访问也没办法解析编码后的`{repository}`：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/02/attach-f746701dd0180b30db754e712f2f9cf816e710bc.png)

 可以看到返回了404 status：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/02/attach-f5ad899f6b6ca1253f2d5d8b83d3cc3b8e1cb30b.png)

 但是类似尾部额外的`/`,getRepositoryLookupPath时会进行额外的剔除，所以跟SpringWeb一样，在匹配时也会支持尾部额外的`/`，同样可以正常解析。

0x03 潜在的安全风险
============

3.1 ALPS 文档信息泄漏
---------------

 ALPS 是一种描述RESTful服务中资源和操作的元数据格式。在SpringDataRest中主要是为每个导出的存储库提供一个ALPS文档。它包含有关RESTful转换以及每个存储库的属性的信息（例如服务支持的资源、属性、关系以及相关操作的 ALPS 元数据）。

 `org.springframework.data.rest.webmvc.alps.AlpsController` 是 Spring Data REST 中负责处理 Application-Level Profile Semantics (ALPS) 的Controller类：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/02/attach-32e623a4dee44d46b0037897a3a1fdfb56a83dff.png)

 通过访问 `/profile` 路径，`AlpsController` 会提供 ALPS 文档，例如下面的例子：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/02/attach-35d082e8ef92489979f5a8dd1dc06b50d3bcb02a.png)

 其中具体的文档包含了关于支持的资源、属性、关系和操作的信息：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/02/attach-9fb21b41490f7d4bd9fa0d50669fb6f86518a54c.png)

 在某些情况下可能存在信息泄露的风险。

### 3.1.1 禁用Alps

 可以看到，是否启用Alps主要是通过org.springframework.data.rest.core.config.MetadataConfiguration的alpsEnabled属性来控制的：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/02/attach-2aba5f4b2c523a6a71a409a434150e19c88076bb.png)

 默认情况下alpsEnabled的值为true:

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/02/attach-a3f0c9389d9cf93f7435cb1597b3d23a9b76f231.png)

 可以通过注册RepositoryRestConfigurer（或扩展RepositoryRestConfigurerAdapter(高版本已经弃用)）来自定义配置，例如下面的例子：

```Java
@Configuration
public class CustomRestMvcConfiguration {

    @Bean
    public RepositoryRestConfigurer repositoryRestConfigurer() {

        return new RepositoryRestConfigurerAdapter() {
            @Override
            public void configureRepositoryRestConfiguration(RepositoryRestConfiguration config) {
                MetadataConfiguration metadataConfiguration = config.getMetadataConfiguration();
                metadataConfiguration.setAlpsEnabled(false);
            }
        };
    }
}
```

 高版本通过直接实现RepositoryRestConfigurer来自定义配置：

```Java
@Configuration
public class CustomRestMvcConfiguration {

    @Bean
    public RepositoryRestConfigurer repositoryRestConfigurer() {

        return new RepositoryRestConfigurer() {
            @Override
            public void configureRepositoryRestConfiguration(RepositoryRestConfiguration config, CorsRegistry cors) {
                MetadataConfiguration metadataConfiguration = config.getMetadataConfiguration();
                metadataConfiguration.setAlpsEnabled(false);
            }
        };
    }
}
```

 同样是上面的例子，通过对应的配置设置alpsEnabled的值为false后，尝试访问相关的ALPS 文档会返回404：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/02/attach-5a3bcacb36074ae6abf4344d879d2e3732d40063.png)

3.2 暴露的端点
---------

 在Spring Data REST中可以通过如下方式将exported属性设置为false来实现接口及接口中的所有方法不对外暴露，从而限制访问。一般情况下为了防止HTTP用户调用CrudRepository的删除方法，会覆盖所有这些删除方法，并将对应的注释添加到覆盖方法中。

- 在接口级别增加@RepositoryRestResource(exported = false)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/02/attach-7ab649de20ca7c127495466c9d40c0947423b4da.png)

- 在指定的方法使用@RestResource(exported = false)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/02/attach-32c26e5390e028be8d8ac56c46618062a96fbc1b.png)

 此外，还可以通过SpringSecurity对相关的请求路径进行防护。网上很多的案例都是使用AntPathRequestMatcher基于Ant风格模式进行匹配的。实际上这里会存在解析差异的问题。实际上应该使用MvcRequestMatcher，在匹配时会更严谨。

 如果通过自定义filter基于请求Path进行权限控制的话，这里跟SpringWeb是类似的，同样也存在解析差异导致的绕过风险。在审计过程中需要额外注意。

### 3.2.1 获取请求路径的方式

 之前简单分析了SpringWeb中获取当前请求路径的方式，具体可以参考https://forum.butian.net/share/2606。

 HandlerMapping 是 Spring Framework 中用于处理请求映射的核心接口之一。它定义了一种策略，用于确定请求应该由哪个处理器（Handler）来处理。HandlerMapping 接口提供了一组方法，用于获取与请求相关的处理器。BEST\_MATCHING\_PATTERN\_ATTRIBUTE属性在处理请求时，Spring会尝试找到最适合处理请求的Controller。该属性存储了在这个过程中找到的最佳匹配的Controller。

 在Spring Data Rest中也存在类似的属性`RepositoryRestHandlerMapping.`*`BEST_MATCHING_PATTERN_ATTRIBUTE`*。但是通过类似`request.getAttribute(RepositoryRestHandlerMapping.`*`BEST_MATCHING_PATTERN_ATTRIBUTE`*`);`获取的path某些时候并不能满足对应的鉴权需求。例如请求RepositoryEntityController时获取到的路径为`/{repository}/{id}`。缺少了具体的仓库路径Repository Path。

 根据前面的分析，可以通过`EFFECTIVE_REPOSITORY_RESOURCE_LOOKUP_PATH`属性获取包含仓库路径Repository Path的请求path：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/02/attach-1a4ba22fdc3156b161b695183c074dbff36490be.png)

 在exposeEffectiveLookupPathKey方法中，在获取到对应的Pattern后，例如`/api/{repository}/search/{search}`,会把`/{repository}`替换成前面获取到的repositoryBasePath：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/02/attach-c5d7ce59920cde186a2d880eb06eee5776dea56a.png)

 也就是说，可以通过下面的方法来获取包含仓库路径Repository Path的请求path：

```Java
PathPattern pathPattern = (PathPattern) request.getAttribute("org.springframework.data.rest.webmvc.RepositoryRestHandlerMapping.EFFECTIVE_REPOSITORY_RESOURCE_LOOKUP_PATH");
String requestPath = pathPattern.getPatternString();
```

 以RepositorySearchController调用为例，尝试调用前面的findFirstByMobile方法，此时获取到的请求路径为`/tenantPath/search/{search}`。

3.3 敏感数据暴露
----------

 默认情况下，Spring Data REST 可能会暴露实体类的所有字段，包括敏感信息。

- 避免在响应中暴露敏感信息。
- 使用投影来控制响应中返回的数据。

 具体使用可以参考https://docs.spring.io/spring-data/rest/docs/current-SNAPSHOT/reference/html/#projections-excerpts

3.4 Denial of Service
---------------------

 Spring Data REST是建立在Data Repository之上的，可能通过执行大量数据查询来导致服务器负载过高，引发拒绝服务攻击。对于查询类的接口，需要限制查询端点的返回结果数量，并配置合适的分页和排序。

3.5 其他
------

 除此之外，本身的sql注入问题在审计时也是需要关注的。