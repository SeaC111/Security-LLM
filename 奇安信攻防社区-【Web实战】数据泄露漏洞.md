API安全
=====

随着移动互联网的快速发展和物联网设备的普及，API在应用开发中扮演着越来越关键的角色。几乎所有的APP、web网站、小程序、微服务都依赖API进行数据调用，因此与API相关的数据泄露事件也逐渐增多。Facebook 、Twitter、Amazon、美团等公司均发生过由于API未鉴权、鉴权不严格或其它漏洞而发生大量数据泄露事件。

**API安全**指的是确保应用程序接口的安全性，以防止未经授权的访问、数据泄露、篡改或其他恶意攻击。

API架构
-----

**API**，即应用程序接口，是应用程序之间通信的关键协议。它们定义了如何请求和响应资源或服务，使不同的应用程序可以集成和互操作。API接口通常包括请求方法（如GET、POST、PUT、DELETE等）、请求头、请求体、响应状态码、响应头和响应体等部分。这些元素共同构成了应用程序之间的信息交流方式。

以下是一些常见的API架构和规范：

### SOAP

SOAP在过去被广泛用于Web服务，它是基于XML 格式的，现在也有使用但不多，因为SOAP消息基于XML格式，这使得它的消息相对繁琐和冗长。XML消息包含大量的标记和元数据，这使得消息传输的数据量相对较大。但SOAP集成了WS-Security安全规范，可以使用令牌、签名和加密的方式来实现身份认证和数据安全传输。

下面是SOAP消息的基本结构：

```php
<?xml version="1.0"?>
<soap:Envelope
xmlns:soap="http://www.w3.org/2001/12/soap-envelope"
soap:encodingStyle="http://www.w3.org/2001/12/soap-encoding">

<soap:Header>
...
</soap:Header>

<soap:Body>
...
  <soap:Fault>
  ...
  </soap:Fault>
</soap:Body>

</soap:Envelope>
```

### REST

REST是一种基于HTTP协议的架构风格，它使用HTTP的GET、POST、PUT、DELETE等方法来执行对资源的操作。RESTful API使用简单的URL和HTTP方法来表示资源，并通常使用JSON来进行数据交互。现在大部分Web服务和移动应用程序均使用REST API。

REST API本身不提供安全保护能力，所以需要使用Authorization头或Token参数来确保只有授权的用户能够访问受保护的资源。有时，API会要求数据传输进行签名以确保数据的完整性和真实性，通常使用数字签名或哈希算法来实现。

REST API存在一个非常典型的缺陷，存在响应过度问题，客户端仅需要部分信息，API也会返回完整的资源信息。这可能会导致数据冗余和信息泄露，以及带宽浪费。

```php
GET /article/1315742
```

### GraphQL

GraphQL是一种查询语言和运行时环境，用于从API中获取精确的数据。它允许客户端以自定义方式请求所需的数据，而不是像传统的RESTful API那样提供固定的端点。GraphQL通常使用HTTP作为传输协议。

在GraphQL中，客户端可以编写一个查询，指定所需的数据字段和关联数据，而服务器将根据查询来提供相应的数据。这使得客户端能够更加灵活地获取所需的数据，而无需多次请求不同的端点。这种能力使得GraphQL在移动应用和前端开发中非常受欢迎，因为它允许客户端精确控制数据的获取，减少了不必要的数据传输，从而提高了性能。

虽然GraphQL的这种特性非常有用，但也需要开发人员和API提供者注意安全性。由于客户端可以自由选择所需的数据，必须实施合适的鉴权和权限控制，以确保敏感数据不被未经授权的用户访问。这也是GraphQL API设计中的一个关键考虑因素。

```php
常见的GraphQL路径如下：

/graphql
/graphiql
/v1/graphql
/v2/graphql
/v3/graphql
/v1/graphiql
/v2/graphiql
/v3/graphiql
/api/graphql
/api/graphiql
/graphql/api
/graphql/console
/console
/playground
/gql
/query
/graphql-devtools
/graphql-explorer
/graphql-playground
/graphql.php
/index.php?graphql
......
```

基本结构

```php
POST /graphql

{
"query":"query{user(id:1){id name}}"
}
```

GitHub使用了GraphQL做为API架构

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-b6177a8ad1bbd6405dae911ab87877b21c562ab6.png)

不同的API架构在不同的应用场景和需求下发挥各自的优势。

REST通常被选用来构建简单的、无状态的API，特别适合用于大多数Web服务。REST的无状态性质使其成为轻量级的选择，能够应对高并发和分布式系统的需求。

SOAP通常被用于对安全性要求较高的企业级应用程序。SOAP提供了强大的功能和安全性，支持高级的消息传递、事务管理和安全协议。由于其复杂性，SOAP通常用于复杂的集成和通信场景，如金融服务和医疗保健领域。

GraphQL则适用于需要高度定制数据查询的场景。它允许客户端应用程序根据其具体需求定义数据查询，避免了过度或不足的数据传输。GraphQL的灵活性和强大的查询语言使其成为构建应对复杂数据需求的现代应用的理想选择。

因此，根据项目需求和安全级别，可以选择适合的API架构，以最好地满足业务需求和性能要求。

服务架构
----

### 前后端分离

作为当今广受欢迎的软件开发方法之一，将前端和后端的开发过程分隔开，使各自团队能够独立开展工作，从而极大地提升了开发效率和灵活性。前后端开发人员按照API接口文档，其中包括URL接口、数据参数、以及数据类型等具体信息，进行各自的独立开发。数据交互通常采用标准化的JSON格式，确保数据的一致性和可理解性。这种方法的优势在于，它有效地降低了前后端协作的复杂性。

**JSON**，全称JavaScript对象表示法，是一种通用的数据交换格式，可以轻松在不同的系统和语言之间传递数据。JSON的灵活性和可读性使其成为API通信中常用的数据格式。通过API接口和JSON数据的结合使用，可以实现跨平台、跨语言的应用程序之间的数据交换和通信。

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-499ef5d32ede807cb2d9a805bf0694ccfe4f0219.png)

### 第三方API

是由外部组织或服务提供的API，允许应用程序与外部服务或数据源进行交互,如高德地图API、企查查API、第三方支付API。

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-bd78ea3439d63fa494e79bd105940b0481ecc4f8.png)

### 微服务

是一种开发软件的架构模式和组织方法，将一个大型应用程序拆分为小的、相对独立的服务单元，这些服务单元可以独立部署、扩展和维护。API（Application Programming Interface）是这些服务之间通信的关键方式之一，它们允许不同的微服务之间互相交互和协作。

在微服务架构中，随着服务的增多和复杂性的提高，API的数量也会快速增加。为了更好地管理和控制这些API，大型企业通常会选择使用API网关作为管理和安全的中心点。API网关提供了统一的接口，允许客户端与后端服务系统之间的交互得以规范化和简化。 与之而来的便是安全问题，API网关的安全十分重要。

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-0859f08beedafb2d66b9294e32f014bfa45d6157.png)

API安全涉及范围十分广泛，身份验证、授权、数据加密和防止恶意请求等，企业对于API安全的重视程度尚且不足，往往在设计阶段未充分考虑安全性，并且不了解系统存在使用了哪些API，导致存在大量未知僵尸API、未知影子API、未经鉴权API和安全漏洞，使得这些API成为攻击入口。在本文中，我们主要探讨API漏洞导致数据泄露的部分。

安全策略
----

### 认证机制

API 认证是确保 API 安全的核心。它用于验证请求的来源和合法性。常见的认证机制包括：

#### Token

##### 基于令牌（Token）的认证：

这是一种常见的认证方式，其中请求者提供一个令牌，通常是访问令牌或身份验证令牌，来验证其身份。这可以确保请求者是经过身份验证的合法用户或应用程序。

```php
1、用户登录请求：
  ○ 客户端发送登录请求，传递用户名和密码。
2、用户身份验证：
  ○ 服务端接收登录请求后，对用户提供的用户名和密码进行验证。
  ○ 若验证失败，服务端返回错误响应，指示登录未成功。
  ○ 若验证通过，服务端继续下一步操作。
3、令牌生成和存储：
  ○ 在用户身份验证通过后，服务端生成一个随机且不重复的令牌（通常是字符串或哈希值），这个令牌将用于后续的请求身份验证。
  ○ 生成的令牌将存储在持久性存储中，可以选择存储在Redis、数据库或其他适当的位置。
  ○ 服务端将令牌与用户信息相关联，通常存储在一个键值对存储中（比如，Redis的key-value存储），这个存储的键通常为令牌，值包含用户信息。
4、设置令牌过期时间：
  ○ 为了确保安全性和有效性，服务端为生成的令牌设置一个过期时间。过期时间可以在生成令牌时定义，通常以秒为单位。
5、返回令牌给客户端：
  ○ 服务端将生成的令牌返回给客户端，以便后续的API请求使用。通常，令牌包含在HTTP响应的头部或作为响应正文的一部分。
6、使用令牌进行请求：
  ○ 客户端在后续的API请求中需要在请求头或参数中携带这个令牌。
7、令牌有效性校验：
  ○ 服务端拦截API请求，校验请求中的令牌。
  ○ 服务端检查令牌是否存在、是否过期，以及是否与存储的用户信息匹配。
8、提取用户信息：
  ○ 如果令牌有效，服务端从令牌中提取用户信息，供后续的业务逻辑使用。
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-61e7426a833ccb8ac5309a54cd3b89c098311e68.png)

##### 签名（Sign）机制

但仅用Token认证则存在中间人攻击的安全隐患，这时就需要引入签名（Sign）机制，用于确保数据完整性和防止中间人攻击。

以下是使用签名来防止传入参数被篡改的具体步骤：

```php
1、约定加密算法：客户端和服务端首先需要约定使用的加密算法，例如MD5加密、SHA1加密，或者可以根据需求选择其他更安全的算法。这一步确保双方使用相同的算法进行签名。

2、参数排序和拼接：客户端在发起请求时，将所有非空参数按照升序或降序的规则进行排序，然后将它们拼接在一起。这样确保了参数的一致性，无论谁生成签名都得到相同的结果。

3、生成签名：客户端使用约定的加密算法对拼接后的参数进行加密，生成一个签名（Sign）。这个签名是请求的一部分，将与其他参数一起传递给服务端。

4、服务端验证：服务端接收请求后，会对接收到的非空参数按照相同的规则进行排序和拼接。然后，服务端使用相同的加密算法生成一个本地签名。

5、比较签名：服务端的本地签名与客户端传递的签名进行比较。如果两者一致，说明请求未被篡改，服务端予以放行并提供相应的数据。如果签名不一致，服务端拒绝请求，因为数据可能已被篡改。
```

这个签名机制有效地防止了中间人攻击，因为中间人无法生成有效的签名，除非它们知道加密算法和密钥。这种方法还适用于防止不信任的第三方调用接口，因为只有知道签名算法和密钥的合法客户端才能够成功生成有效的签名。

##### 时间戳（timestamp）机制

但仅仅使用签名机制还会出现暴力破解和Ddos问题，为了解决这些问题就需要引入时间戳机制timestamp

```php
1、客户端生成时间戳：客户端在发起请求时生成一个时间戳，通常以秒为单位。时间戳应该与客户端和服务器的系统时间同步，以确保准确性。

2、将时间戳包含在请求中：客户端将生成的时间戳包含在请求参数中，与其他参数一起进行签名。这样，服务器将能够验证请求的时间戳。
    sign值 = 非空参数按照相同的规则进行排序和拼接+token+timestamp。

3、服务器验证时间戳：服务器在接收请求后，首先验证时间戳的有效性。它可以检查时间戳是否在合理的时间范围内，例如，不接受太早或太迟的请求。如果时间戳无效，服务器可以拒绝请求。

4、设置时间戳过期时间：为了防止重放攻击，服务器可以设置时间戳的过期时间。一旦时间戳过期，服务器将不再接受请求，即使时间戳本身是有效的。

5、使用合适的时钟同步：确保客户端和服务器的系统时钟同步是至关重要的，以避免时间戳验证出现误差。使用网络时间协议（NTP）等工具可确保时钟同步。
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-a5830dd9b0f3c9d72c7f43976f404b208795a575.png)

#### OAuth 2.0

OAuth（开放授权）是一种开放标准和协议，用于第三方应用程序访问用户资源时进行授权，但无需分享用户的凭证，保护了用户的凭证。OAuth的设计目标是允许用户授权应用程序代表他们来执行特定操作，同时也提供了对应用程序访问资源的精确控制。

OAuth 2.0 是OAuth协议的一个广泛采用的版本，它定义了一种标准的授权流程，被用于许多在线服务和应用程序中，如第三方微信登录、支付宝登录等等。

OAuth 2.0 的授权过程包括以下步骤：

```php
1. 客户端向授权服务器请求授权，资源所有者登录并同意授权。
2. 授权服务器颁发访问令牌给客户端。
3. 客户端使用访问令牌来请求访问资源服务器上的资源。
4. 资源服务器验证访问令牌，如果有效，则允许客户端访问资源。
```

OAuth 2.0 支持不同的授权流程，包括授权码授权、密码授权、客户端凭据授权等，可以根据应用程序的需求选择最适合的授权流程。这使得应用程序能够获得对用户资源的有限、受控制的访问权限，同时不需要用户共享他们的用户名和密码。OAuth在互联网上的广泛采用，保护了用户数据的隐私和安全。

#### AccessKey&amp;SecretKey

在开发者接口的安全设计中，Access Key 和 Secret Key 是一种常见的身份验证机制，通常用于确保只有合法的开发者可以访问和使用API。这是一种基于密钥的身份验证方式，其中：

```php
Access Key（访问密钥）是开发者的唯一标识，类似于用户名。
Secret Key（密钥）是与Access Key相关联的密钥，用于签名请求以进行身份验证。
```

开发者在访问API时需要使用Access Key和Secret Key来通过特定的身份认证接口获取Token。

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-e483494df5ef37e5fef155c824300adfd10d1b37.png)

### 授权机制：访问控制

访问控制机制用于限制 API 的访问权限，确保 API 的数据仅被授权的用户或应用程序访问。常见的授权机制包括：

```php
1、基于角色的访问控制（RBAC）： RBAC 是一种访问控制模型，其中权限与角色相关联。用户分配到特定角色，而角色有特定权限。这使得管理和控制权限变得更加可管理。

2、基于属性的访问控制（ABAC）： ABAC 是一种更动态的授权模型，它使用属性来控制对资源的访问。这可以根据用户的属性、上下文或其他因素动态决定访问权限。
```

RBAC和ABAC可以通过不同的技术和底层组件来实现。在实际应用中，RBAC和ABAC通常依赖于数据库、身份验证和授权模块、访问控制列表、策略引擎以及上下文和属性管理模块，以维护和执行权限策略。

```php
1、用户表（User Table）：通常，API身份认证和授权的起点是用户信息。用户表存储了用户的基本信息，如用户名、密码（经过哈希处理的）、电子邮件地址等。这些信息用于验证用户身份。授权管理也可能与用户表相关，包括用户角色和权限字段。

2、角色表（Role Table）：在许多身份认证和授权方案中，角色起到了关键作用。角色表存储了可分配给用户的不同角色，例如管理员、普通用户、编辑等。每个角色通常与权限相关联，允许或限制用户执行特定操作。

3、权限表（Permission Table）：权限表包含了应用程序中的各种权限定义。这些权限可以是对资源（如文件、页面、API端点等）的访问权限，或者是执行特定操作（如创建、读取、更新、删除）的权限。权限表通常与角色表关联，以定义哪些角色具有哪些权限。

4、用户-角色关系表（User-Role Relationship Table）：这是连接用户和角色的中间表。它将用户ID与角色ID关联起来，允许为用户分配一个或多个角色。

5、角色-权限关系表（Role-Permission Relationship Table）：类似于用户-角色关系表，这个表将角色ID与权限ID相关联，确定了每个角色具有哪些权限。

6、令牌表（Token Table）：用于存储身份验证过程中生成的令牌信息。令牌可以是访问令牌（Access Token）或刷新令牌（Refresh Token）。这些令牌在身份验证后用于访问受保护的资源或生成新的访问令牌。

7、日志表（Log Table）：用于跟踪用户的身份认证和授权操作。这对于审计和安全监控至关重要，以便追踪谁何时访问了什么资源。
```

底层原理包括根据用户提供的凭证（如用户名和密码）进行身份验证，根据角色和权限关系确定用户的授权，生成并管理访问令牌，以及记录相关操作的日志。这些数据表之间的关联和逻辑是构建API身份认证和授权的关键。

基于Java过滤器实现API操作权限控制是一种常见的做法。

```php
import javax.servlet.*;
import javax.servlet.annotation.WebFilter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@WebFilter("/api/*") // 拦截以/api/开头的URL
public class ApiAuthorizationFilter implements Filter {
    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        // 过滤器初始化操作
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;

        // 这里可以进行权限验证逻辑
        if (userHasPermission(httpRequest)) {
            // 用户有权限，继续请求链
            chain.doFilter(request, response);
        } else {
            // 用户无权限，返回错误响应
            httpResponse.setStatus(HttpServletResponse.SC_FORBIDDEN);
        }
    }

    @Override
    public void destroy() {
        // 过滤器销毁操作
    }

    private boolean userHasPermission(HttpServletRequest request) {
        // 实现权限验证逻辑，例如验证用户是否有访问API的权限
        // 返回true表示有权限，返回false表示无权限
        // 你需要根据你的应用逻辑来实现此方法
        return true; // 示例中始终返回true
    }
}
```

Shiro和Spring Security均是基于过滤器设计出来的框架

```php
1、Shiro
Shiro被认为是非常容易入手的安全框架，有很好的文档和示例。它的配置通常较为简单，新手可以迅速上手。允许以不同的粒度管理安全性，可以进行细粒度的控制，也可以根据需要进行简化。

2、Spring Security
Spring Security提供了强大的认证、授权和安全管理功能。它支持各种认证机制和权限控制，同时还提供了对Oauth和OpenID等标准的支持。在细粒度的权限控制方面非常强大，可以根据角色和权限进行非常精确的控制。但Spring Security太过复杂。
```

### 加密机制

API 数据的加密用于保护数据在传输和存储过程中的安全性。常见的加密机制包括：

```php
1、HTTPS 协议： 使用加密的传输层安全性来保护数据在传输过程中不被窃取或篡改。这是通过使用 TLS/SSL 证书来实现的。

2、TLS 协议： 运行在应用层之上的安全传输协议，提供端到端的数据加密。TLS 可以用于保护数据在传输层和应用层之间的传输。
```

这些机制的组合可以确保 API 的安全性和数据完整性。同时，它们可以根据应用程序的具体需求进行调整和配置，以满足不同的安全标准和法规要求。

API接口泄露+未授权访问
-------------

API由于鉴权机制存在问题或权限控制的细粒度不够导致，存在未授权访问漏洞泄露敏感数据，配合以下漏洞可获取API接口。获取到API接口后，通过调试对API进行未授权访问测试，有些接口可以直接获取敏感信息，有些可以通过多个接口组合获取信息，对于接口返回的URL信息也不要忽略，需要耐心进行测试。

### Druid泄露

Druid是一种数据库查询和数据分析引擎，未授权访问或者弱口令漏洞，可导致网站接口泄露。

从URL监控和JSON API功能均能看到大量的接口信息，从请求时间和次数可判断数据量的大小和使用频率，进而进行未授权访问尝试。

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-380b87f998707438855798b32067541d50af091f.png)

### Actuator信息泄露

Spring Boot Actuator模块提供了许多有用的功能，如健康检查、审计、指标收集和HTTP跟踪，以帮助监控和管理Spring Boot应用程序。然而，如果不正确使用和配置Actuator，可能会引发严重的安全隐患，特别是外部人员非授权访问Actuator端点的情况。httptrace端点提供了HTTP请求-响应交换的详细信息，包括请求头、响应头和请求体。logfile端点提供对应用程序日志文件内容的访问。metrics端点提供了应用程序指标的访问，包括性能、资源利用率等。这些均有可能泄露应用程序的API接口信息。

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-f3052ee7c8a715b5c29fd56523d33f26f640c656.png)

### SVN泄露

当使用Subversion（SVN）版本控制系统管理本地代码库时，每个受版本控制的文件夹中都会自动生成一个名为.svn的隐藏文件夹。这个.svn文件夹包含了与Subversion版本控制相关的元数据信息，利用工具可下载源代码：<https://github.com/admintony/svnExploit>

（这里拿一个SVN文件泄露实例进行说明，其实其它的文件泄露也会可能造成数据泄露，如代码文件的直接泄露，日志文件泄露等等）

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-59e172e80dbcca4fbbf32702d05044ff86a026c8.png)

源代码中泄露了接口信息

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-a94d3cdf0f922eb1f2704a3982efcd889d55ef8a.png)

### 接口手册泄露

#### swagger

Swagger是一个用于构建、文档化和测试REST Web服务的工具集。Swagger UI：Swagger UI是一个交互式的Web界面，用于可视化地浏览、测试和调试REST API。它生成一个用户友好的API文档，允许开发人员轻松地了解API的端点、请求参数和响应数据，并在浏览器中执行API请求。若存在Swagger UI未授权访问，攻击者可直接查看Swagger接口文档，进行接口测试，通过回显获取系统大量的敏感信息。

利用Swagger UI的测试功能，能够直接进行测试。存在必须参数时，也可以输入任意字符进行测试，系统可能存在逻辑漏洞。

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-36c119a6de5c22b886868ea35bcaf837309a380e.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-6595c1012133f3e6dcfe83048c7e9683515153e5.png)

当遇见不存在try it out测试功能时，或者仅可访问json文件，可以使用第三方接口工具进行测试

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-56ad11268f803692b0f959c7feda6b548881f2f4.png)

<https://app.apifox.com> ，选择导入数据，使用URL方式导入

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-46ef031f65293a7c874c2fb31421282446f7caa3.png)

即可进行测试

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-911a67749f40b3e2feda879f843c3a937b9450a8.png)

#### 其它接口泄露

除了swagger外，部分网站可能存在其它接口文件泄露，实际情况实际利用。

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-66f980e9bc3180352716eaa5bc102d0dee2f7822.png)

### webpack

Webpack是一个常用的JavaScript模块打包工具，用于将多个JavaScript文件、样式表和其他资源打包成单个或多个文件，以提高前端应用的性能和加载速度。Source Map是一种用于调试的工具，它将编译后的JavaScript代码映射回原始的源代码，以便开发人员可以在浏览器中进行调试。但如果不小心在生产环境中启用了Source Map，攻击者可能会利用它来获取源代码，进一步利用。

可参考文章：发现Webpack中泄露的api：<https://xz.aliyun.com/t/9453>

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-8b7b38e0358a0cf0c89287c71487865b43abc3e1.png)

可利用SourceDetector 谷歌插件，项目地址：[https://github.com/SunHuawei/SourceDetector使用插件可自动化判断网站是否存在](https://github.com/SunHuawei/SourceDetector%E4%BD%BF%E7%94%A8%E6%8F%92%E4%BB%B6%E5%8F%AF%E8%87%AA%E5%8A%A8%E5%8C%96%E5%88%A4%E6%96%AD%E7%BD%91%E7%AB%99%E6%98%AF%E5%90%A6%E5%AD%98%E5%9C%A8) js.map 文件，并能直接下载源码：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-ece3676c81ccc32e8e39f317cc13fde457d2b64c.png)

也可直接使用Packer-Fuzzer：[https://github.com/rtcatc/Packer-Fuzzer，能够直接对Webpack的网站进行测试](https://github.com/rtcatc/Packer-Fuzzer%EF%BC%8C%E8%83%BD%E5%A4%9F%E7%9B%B4%E6%8E%A5%E5%AF%B9Webpack%E7%9A%84%E7%BD%91%E7%AB%99%E8%BF%9B%E8%A1%8C%E6%B5%8B%E8%AF%95)。

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-2fc4381345008460c201bbf78f00928f6b75a8f8.png)

案例1:

发现由Webpack打包的网站，然后直接查看原码，发现存在着直接获取系统所有api列表的API

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-9a7429c36c02d218889d37b94389d25eeb4ccbf1.png)

注意1:根目录api，直接访问lyapi.json是没有任何返回的  
注意2:api站点（8070端口）和网站地址（8071）是不一样的  
![image.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-d00e29ddc5f23ec339085a5cbde5eeb6e9504dcf.png)

![](https://shs3.b.qianxin.com/attack_forum/attach-3dea37cad4e202ecad55f.png)

利用第三方api管理平台进行测试

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-20ab0548e15d839909a537ef9c1b34a40a8360d7.png)

将服务的前置URL改为测试网站的URL

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-705d8956fb4e2c5ec34df9fdbbd2ff1246201a3e.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-13f82aa91b235f69fba1f3d9fa23f5f3bca91ff5.png)

GraphQL 内省查询
------------

内省查询允许客户端查询GraphQL服务器上的架构信息，包括可用的查询、类型、字段等，以便客户端可以自动构建查询。这个功能本身是为了提高客户端的开发效率，但如果不加以控制，可能会导致接口信息泄露。GraphQL内省查询通常使用双下划线（\_\_）前缀来标识一部分特殊的查询，用于获取架构信息，如：\_\_Schema, \_\_Type, \_\_TypeKind, \_\_Field, \_\_InputValue, \_\_EnumValue, \_\_Directive等，

官方文档：<https://graphql.org/learn/introspection/>

利用\_\_schema字段查询实例

```php
{"query":"\n    query IntrospectionQuery {\r\n      __schema {\r\n        queryType { name }\r\n        mutationType { name }\r\n        subscriptionType { name }\r\n        types {\r\n          ...FullType\r\n        }\r\n        directives {\r\n          name\r\n          description\r\n          locations\r\n          args {\r\n            ...InputValue\r\n          }\r\n        }\r\n      }\r\n    }\r\n\r\n    fragment FullType on __Type {\r\n      kind\r\n      name\r\n      description\r\n      fields(includeDeprecated: true) {\r\n        name\r\n        description\r\n        args {\r\n          ...InputValue\r\n        }\r\n        type {\r\n          ...TypeRef\r\n        }\r\n        isDeprecated\r\n        deprecationReason\r\n      }\r\n      inputFields {\r\n        ...InputValue\r\n      }\r\n      interfaces {\r\n        ...TypeRef\r\n      }\r\n      enumValues(includeDeprecated: true) {\r\n        name\r\n        description\r\n        isDeprecated\r\n        deprecationReason\r\n      }\r\n      possibleTypes {\r\n        ...TypeRef\r\n      }\r\n    }\r\n\r\n    fragment InputValue on __InputValue {\r\n      name\r\n      description\r\n      type { ...TypeRef }\r\n      defaultValue\r\n    }\r\n\r\n    fragment TypeRef on __Type {\r\n      kind\r\n      name\r\n      ofType {\r\n        kind\r\n        name\r\n        ofType {\r\n          kind\r\n          name\r\n          ofType {\r\n            kind\r\n            name\r\n            ofType {\r\n              kind\r\n              name\r\n              ofType {\r\n                kind\r\n                name\r\n                ofType {\r\n                  kind\r\n                  name\r\n                  ofType {\r\n                    kind\r\n                    name\r\n                  }\r\n                }\r\n              }\r\n            }\r\n          }\r\n        }\r\n      }\r\n    }\r\n  ","variables":null}
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-78d53dfc468bb9aede3d3c6a68437731cc8ad261.png)

使用graphql-voyager可以对数据进行解析展示：<https://graphql-kit.com/graphql-voyager/>

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-f03655004e09957d39a8bed46d1b72100d3aca60.png)

某真实案例通过GraphQL 内省查询，导致全部接口泄露，通过对接口进行调试，发现未授权访问获取大量敏感信息，并有接口可修改身份信息造成任意用户登录。

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-a607b774bcd1e7862d0291c9b4c729ea3be03615.png)

逻辑漏洞
----

### 第三方API

未正确使用第三方API，请求参数写在代码中，访问目标接口即可直接访问第三方API获取信息

```php
api_url = "https://api.example.com/data"
params = {
    'param1': 'value1',
    'param2': 'value2'
}

response = requests.get(api_url, params=params)
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-d5977d09665cc0439e5efe9606cf2e52f37eea6c.png)

### 参数遍历

案例1、参数未加密或者加密失效，导致可以对接口参数进行遍历获取大量敏感信息

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-00582a5e0ca8c890ac726b041efa22f418d87d77.png)  
案例2、其中一个API接口可遍历返回sign值

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-c4f7cbb86264a2f5936726e1cf1cda5374f46667.png)

利用sign值在另一个接口可获取敏感信息

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-cf359fa92f9d9b10b3e95184eae168c779a36385.png)  
案例3:paypal

1个价值10500刀的洞

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-e5c977dfb16cf5bd28e99ee11b10fcec8ae211a6.png)

使用者在正常访问子账号功能时（[https://www.paypal.com/businessmanage/users/1657893467745278998），会产生1个PUT请求](https://www.paypal.com/businessmanage/users/1657893467745278998%EF%BC%89%EF%BC%8C%E4%BC%9A%E4%BA%A7%E7%94%9F1%E4%B8%AAPUT%E8%AF%B7%E6%B1%82)

```php
PUT /businessmanage/users/api/v1/users? HTTP/1.1
Host: www.paypal.com

[{"id":"1657893467745278998","accessPoint":{"privileges":[    "MANUAL_REFERENCE_TXN","VIEW_CUSTOMERS","SEND_MONEY"],    "id":"5994224506","accounts":["attacker@mail.com"]    },"roleID":0,"roleName":"CUSTOM",    "privilegeChanged":true,"privilegeSecondaryName":"A1"  }]
```

其中id1657893467745278998表示为企业账号A，id5994224506表示为企业自账号A1

其中A账号是可以爆破的，A1账号也是可以爆破的，通过爆破其它公司B的账号，再爆破下属子账号B1，即可进行越权修改密码，转账等敏感操作

### 认证失效

上传接口使用loadToken()方法直接获取Token，查看loadToken()方法，获取API路径

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-16414516e47a33d30d4de11568e8f3b08c9aec7a.png)

直接访问API可直接生成Token

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-23d734c0977c919bd4797b0d44907510b0c80dfb.png)

利用token访问其它需要鉴权接口，即可获取大量敏感信息

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-2e118b2a29ece15ccf4edfebc3f2871cdf2db67b.png)

### 越权

利用系统注册功能进入系统后台，找到如下接口

```php
/getCenterInfo?memberId=MzIwMjIwOANxMDAx&roleTypeId=32&roleId=5
```

可以看到memberId为base64编码，解码后可以遍历爆破越权获取其它用户的敏感信息，并且直接将password进行返回

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-eb3550eb5c2131ec87cb45dab944c36e2c43c192.png)

爆破未找到管理员账号，将memberId制空，roleTypeId和roleId值为1

```php
/getCenterInfo?memberId=&roleTypeId=1&roleId=1
```

直接返回管理员账号

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-49d8b516c0f09f519cd3d7c02e8e11c4f1a5a42b.png)

以管理员身份登录，即可看到千万级别的敏感信息，以“黄”模糊搜索为例，发现139211条记录

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-54b6c4217795efa5033e2ee40a002eb4f450f4c6.png)

### 接口易猜解

访问个人中心，可获取全部用户的ID

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-b70146baedd426acaf7e51eb63969d4487464cdb.png)  
存在API通过ID获取手机号码，并且可以越权获取任意ID的手机号

```php
/ABC/GetStaffMobile?st_id=
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-60554733125fa0fd9935eac6b5b3e569f2655e27.png)

对API进行fuzz猜解，找到了名为SetStaffMobile接口，再对参数进行fuzz，找到了手机号的参数mobile，允许未经授权的用户可更改任意用户的手机号，然后根据手机号验证码登录系统后台，本质上是个未授权访问漏洞，但由于接口的易被猜解所以放在这一单元。后面反馈给研发后，经查证为已知漏洞，API已被废弃，但接口未下架仍然运行在程序上。

```php
/ABC/SetStaffMobile?st_id=&mobile=
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-83e705c9cad154b9c613eab08cd3ff2b76a6aa57.png)

### 硬编码

如果访问接口的User-Agent设置为"Nacos-Server"，则请求将不会经过认证和授权检查，因此导致了Nacos的未授权访问。

这个问题的根本原因在于开发者将User-Agent设置直接硬编码为"Nacos-Server"，用于处理服务端对服务端的请求，因为攻击者可以伪造请求，将User-Agent设置为"Nacos-Server"，绕过认证授权，从而访问未经授权的资源。

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-1830659825961e392d54867c371a526cd7297e3c.png)

过量的数据暴露
-------

在安全规范欠缺和安全需求不明确的情况下，开放者有时为了方便，在设计过程中忽视后端服务器返回数据的筛选策略，直接返回数据对象的所有字段，然后在前端控制显示，即使在前端显示正常，但当攻击者抓包时就会发现其它数据。在实战环境中，此类漏洞出现频率最高，大部分接口会将诸如手机号之类的敏感信息返回，更有甚者直接将账号密码返回。

实战中使用burp + logger++（<https://github.com/nccgroup/LoggerPlusPlus>）  
尽可能的点击网站的全部功能点，确保触发所有的接口流量，然后通过自定义正则即可发现接口的泄露的敏感信息。

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-1558253dd294f768be0e0197ff796fc183ec56c7.png)

案例1、前端页面仅有姓名、企业、性别、类型、参加工作时间5个字段

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-2c8efb1749f212fd8ab9789afbcba901457edf49.png)

但API接口将数据对象所有字段均返回，造成数据泄露

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-7c6ce1423c2923cea957dab3f189835561e3e316.png)

案例2、前端页面仅有5个字段，后端数据全部返回

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-8a4614f4b3eddaa0552aee2fa616ff63cd0c2591.png)

案例3、边缘功能处，选择指导老师，模糊搜索可出现姓名、学号、学院

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-476a0e52b504af4b3202554f96011b337a818f02.png)

但后端数据返回了大量敏感信息

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-af31e9ec461810d524d860b165892c4d05946034.png)

案例4:接口返回过多数据包含用户名，通过收集用户名，爆破密码，登录系统后台，利用身份认证获取未加密敏感信息

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-d32ba81e144806ff8107109c67bb2cdbd5b7b04d.png)

敏感信息未加密或加密失效
------------

数据安全是近两年比较火的话题，有些强监管的单位需要将系统中的敏感数据进行脱敏，开放商选用的数据脱敏方案可能并不完全有效，就导致了漏洞的产生，如常用功能处脱敏部分功能处未脱敏，加密方式失效，前端加密等等

### 前端加密

可以看到敏感进行了脱敏处理

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-fc3dd7c5e2242f36311eadb5753907a872df0b0f.png)

但仅在前端进行了脱敏，后端数据仍为明文

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-987c9f6ed571b090b225529c6ea89ee1c000d6a5.png)

### 部分功能未加密

案例1、前后端均加密时，使用文件导出功能也会存在未加密情况

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-39e5cfd62f6042837cb8d866562769c2704edd5e.png)  
案例2、常用的主要功能页面进行加密

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-2b83d536518269fc191734222f9053edb7f8ebde.png)

边缘功能未加密

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-6bc48678711c9154b2f4cb735ee44ee4a8d4a571.png)

接口参数"mobile"加密 "mob"未加密

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-a439074c8eed5f5ee3841dd5ffc345f14199ed9b.png)

### 加密方式失效

系统对身份证号的出生日期进行了加密

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-6e8bb2efe4a528f6530fda0701c38b095cc50858.png)

但出生日期字段是明文的

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-83bdbbe312c7544c08d79624ff01d5b0816ea282.png)

其它漏洞造成数据泄露
==========

Google黑客语法
----------

这里可以使用常用的谷歌高级语法："敏感信息" filetype：进行搜索

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-8dc0859d350efcaf9d705809d26da6ef27e1840b.png)

在遇到参数较短时，可以对参数进行爆破

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-c7a3704d18e4211e4c7ece50a8ba2d166426dc76.png)

文件泄露敏感信息导致数据泄露
--------------

案例1、JS文件泄露token

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-8194389a16bb32d85e9448418c661bddfeb0e831.png)

案例2、JS文件泄露账号密码

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-2c2bf2b1a5fc2638a34ddea478cd93a022131544.png)

案例3、JS文件泄露OSS存储桶密钥

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-602790e29743cba6c808369cbd45f96310ac0fbd.png)

案例4、备份文件泄露AKSK

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-02c61e7c990e9c983d2e94ef24209584409d016b.png)

案例5、JS文件泄露AKSK

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-c08c130ac26b0ebf880653ff87168ebd3305fc20.png)

开发工程文件泄露导致数据泄露
--------------

如gitlab漏洞、备份文件泄露、存储管理平台（harbor、Nacos）的漏洞均可能导致项目工程文件泄露。

**敏感配置信息泄露**：开发工程文件中可能包含数据库连接字符串、API密钥、密码等敏感信息，泄露这些信息可能导致数据库或云服务的未经授权访问。

案例1:Sonatype Nexus是一个广泛用于构建和管理软件仓库的工具。如果 Nexus 仓库的浏览权限过于宽松，未经授权的用户可以访问仓库并查看其中的内容，包括源代码等。

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-c9320f23eaae673cfb539a9600ce5b6253bb6706.png)

下载jar包，查看配置文件

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-cd02b1b1822891fec99f833006c908f43c09d0fd.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-5cf4a8e4d053960c0baf0a378e7031cc7a42b4a0.png)

案例2：Harbor仓库任意下载镜像文件

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-02ac8c65fa0f131dae691f82f39019c75844260b.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-39325eea3d6d572dc1b21df201793bdb2addee72.png)

jar包反编译获取配置文件

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-082fbe2e8b0448189226da7d176aac49dfdeb3f4.png)

其它
--

GitHub泄露、MinIO、OSS、Nacos、ES、heapdump等均可能导致数据泄露这里不再赘述。