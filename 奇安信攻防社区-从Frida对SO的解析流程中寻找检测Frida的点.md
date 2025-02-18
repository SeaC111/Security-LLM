0x01 frida寻找符号地址
================

frida hook Native 的基础就是如何寻找到符号在内存中的地址，在frida中就仅仅是一句话 findExportByName或者通过枚举符号遍历，今天我们就一起看一看他是如何实现的。

寻找模块基址
------

首先就要找到他是哪里实现的，frida源码这么大而我们之前有没有阅读ts的经验，所以选择了直接grep寻找函数名称的方法，在frida目录输入下面命令

```bash
grep -rl findExportByName
```

发现了如下文件中有我们要的函数名称

```java
frida-core/tests/test-host-session.vala//使用findExportByName
frida-core/src/darwin/agent/xpcproxy.js//使用findExportByName
frida-core/src/darwin/agent/launchd.js//使用findExportByName
frida-gum/tests/gumjs/script.c//使用findExportByName
frida-gum/bindings/gumjs/runtime/core.js//定义其他函数
frida-gum/bindings/gumjs/gumv8module.cpp//函数的定义
frida-gum/bindings/gumjs/gumquickmodule.c//函数定义
```

在这之中我们发现了2个文件中都有findExportByName的实现，那么如何分辨呢，我们选择了加一条日志重新编译来看一看到底是哪一个

```c
//frida-gum/bindings/gumjs/gumv8module.cpp
GUMJS_DEFINE_FUNCTION (gumjs_module_find_export_by_name)
{
    __android_log_print(6,"r0ysue","i am from v8")
......

}
// frida-gum/bindings/gumjs/gumquickmodule.c
GUMJS_DEFINE_FUNCTION (gumjs_module_find_export_by_name)
{

  __android_log_print(6,"r0ysue","i am from qucik");
 .......
}
```

![1.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-4004f0036812eddb127276ddaafeb4d3e42afab4.png)

可以看到是quick中的代码，那么我们只要阅读这当中的代码即可，首先进入了gum\_module\_find\_export\_by\_name函数中，地址就是它的返回值，

```c
// frida-gum/bindings/gumjs/gumquickmodule.c
GUMJS_DEFINE_FUNCTION (gumjs_module_find_export_by_name)
{
...
  address = gum_module_find_export_by_name (module_name, symbol_name);//得到返回值
...
}
// frida-gum/gum/backend-linux/gumprocess-linux.c
GumAddress
gum_module_find_export_by_name (const gchar * module_name,
                                const gchar * symbol_name)
{
  GumAddress result;
  void * module;
#ifdef HAVE_ANDROID//这一段主要判断是否是低版本dlopen之类的特殊函数，由于我们是高版本android而且在分析通用符号寻找所以不管
  if (gum_android_get_linker_flavor () == GUM_ANDROID_LINKER_NATIVE &&
      gum_android_try_resolve_magic_export (module_name, symbol_name, &result))
    return result;
#endif
  if (module_name != NULL)
  {
    module = gum_module_get_handle (module_name);/获得模块基址
    if (module == NULL)
      return 0;
  }
  else
  {
    module = RTLD_DEFAULT;
  }
  result = GUM_ADDRESS (gum_module_get_symbol (module, symbol_name));//寻找符号地址
  if (module != RTLD_DEFAULT)
    dlclose (module);
  return result;
}

```

接着跟进gum\_module\_get\_handle继续分析如何得到的模块地址，这里它分了2种形式，正如我们之前写的文章，高版本的android不能打开系统白名单之外的so所以上面是修改的dlopen，下面是linux的dlopen

```c
gum_module_get_handle (const gchar * module_name)
{
#ifdef HAVE_ANDROID
  if (gum_android_get_linker_flavor () == GUM_ANDROID_LINKER_NATIVE)
    return gum_android_get_module_handle (module_name);//无限制的dlopen
#endif
  return dlopen (module_name, RTLD_LAZY | RTLD_NOLOAD);//普通的dlopen
}
```

寻找linker相关的信息
-------------

普通的dlopen之前的文章领着大家看过这里就只分析无限制的dlopen是如何实现的了，跟进gum\_android\_get\_module\_handle，这里有2个函数一个是gum\_enumerate\_soinfo，一个是gum\_store\_module\_handle\_if\_name\_matches，我们分开看，先看一个他是如何枚举soinfo的，跟进去发现gum\_linker\_api\_get函数来获得linker中的api，跟进去看看如何实现的，这里首先获得了linker的首地址如下，最终到了gum\_try\_parse\_linker\_proc\_maps\_line函数中，这个函数就是遍历了maps来获得linker（目前好像只有这一种获得linker首地址的方法），虽然这种方法很准确但是frida太谨慎了，又校验了魔术字段，又校验了只读权限，所以这是一个antifrida的关键点

```c
void *
gum_android_get_module_handle (const gchar * name)
{
  GumGetModuleHandleContext ctx;
  ctx.name = name;
  ctx.module = NULL;
  gum_enumerate_soinfo (
      (GumFoundSoinfoFunc)  gum_store_module_handle_if_name_matches, &ctx);//赋值ctx的module
  return ctx.module;
}

static void
gum_enumerate_soinfo (GumFoundSoinfoFunc func,
                      gpointer user_data)
{

  api = gum_linker_api_get ();//获得linker中的函数地址
  .......
}
static GumLinkerApi *
gum_linker_api_get (void)
{
 .....

  g_once (&once, (GThreadFunc) gum_linker_api_try_init, NULL);//用宏定义调用gum_linker_api_try_init函数
.......
}
static GumLinkerApi *
gum_linker_api_try_init (void)
{
....
  linker = gum_android_open_linker_module ();//找到linker
  ....
}
GumElfModule *
gum_android_open_linker_module (void)
{
  const GumModuleDetails * linker;
  linker = gum_android_get_linker_module_details ();
  return gum_elf_module_new_from_memory (linker->path,
      linker->range->base_address);//构造结构体无具体逻辑
}
const GumModuleDetails *
gum_android_get_linker_module_details (void)
{
  static GOnce once = G_ONCE_INIT;

  g_once (&once, (GThreadFunc) gum_try_init_linker_details, NULL);//找到linker的首地址

  if (once.retval == NULL)//抛出异常在第二篇里面就用到了这里，通过主动抛出这个异常的方式来antifrida
  {
    g_critical ("Unable to locate the Android linker; please file a bug");
    g_abort ();
  }

  return once.retval;
}

static const GumModuleDetails *
gum_try_init_linker_details (void)
{
  const GumModuleDetails * result = NULL;
  gchar * linker_path;
  GRegex * linker_path_pattern;
  gchar * maps, ** lines;
  gint num_lines, vdso_index, i;
  linker_path = gum_find_linker_path ();//得到linker的路径包括安卓10之上或者低版本android
  linker_path_pattern = gum_find_linker_path_pattern ();
  g_file_get_contents ("/proc/self/maps", &maps, NULL, NULL);//通过glibc的库函数打开maps
  lines = g_strsplit (maps, "\n", 0);
  num_lines = g_strv_length (lines);

  vdso_index = -1;
  for (i = 0; i != num_lines; i++)
  {
    const gchar * line = lines[i];

    if (g_str_has_suffix (line, " [vdso]"))
    //这里有一个分叉，目的就是我们可以通过安卓源码得知linker的内存排布在[vdso]之后，所以我们可以以[vdso]为基准向上下遍历maps快速的寻找linker地址
    {
      vdso_index = i;
      break;
    }
  }
  if (vdso_index == -1)
    goto no_vdso;

  for (i = vdso_index + 1; i != num_lines; i++)
  {
    if (gum_try_parse_linker_proc_maps_line (lines[i], linker_path,
        linker_path_pattern, &gum_dl_module, &gum_dl_range))
        //遍历maps寻找linker在内存中的地址，这里逻辑很简单里面就一个魔术字段的判断，找到了linker的首地址和我们之前写的遍历maps寻找linker差不多，这里可以用来检测frida
    {
      result = &gum_dl_module;
      goto beach;
    }
  }

  for (i = vdso_index - 1; i >= 0; i--)
  {
    if (gum_try_parse_linker_proc_maps_line (lines[i], linker_path,
        linker_path_pattern, &gum_dl_module, &gum_dl_range))
    {
      result = &gum_dl_module;
      goto beach;
    }
  }

  goto beach;

no_vdso://没有vdso就从头开始一个一个的判断
  for (i = num_lines - 1; i >= 0; i--)
  {
    if (gum_try_parse_linker_proc_maps_line (lines[i], linker_path,
        linker_path_pattern, &gum_dl_module, &gum_dl_range))
    {
      result = &gum_dl_module;
      goto beach;
    }
  }

.......
}

static gboolean
gum_try_parse_linker_proc_maps_line (const gchar * line,
                                     const gchar * linker_path,
                                     const GRegex * linker_path_pattern,
                                     GumModuleDetails * module,
                                     GumMemoryRange * range)
{
  GumAddress start, end;
  gchar perms[5] = { 0, };
  gchar path[PATH_MAX];
  gint n;
  const guint8 elf_magic[] = { 0x7f, 'E', 'L', 'F' };//elf魔术字段头4个字节

  n = sscanf (line,
      "%" G_GINT64_MODIFIER "x-%" G_GINT64_MODIFIER "x "
      "%4c "
      "%*x %*s %*d "
      "%s",
      &start, &end,
      perms,
      path);//字符串扫描
  if (n != 4)
    return FALSE;

  if (!g_regex_match (linker_path_pattern, path, 0, NULL))//路径匹配
    return FALSE;

  if (perms[0] != 'r')//可读匹配，不可读就没办法看下面的魔术字段
    return FALSE;

  if (memcmp (GSIZE_TO_POINTER (start), elf_magic, sizeof (elf_magic)) != 0)//判断魔术字段，通过这个可以antifrida，因为魔术字段在运行过程中没啥太大作用，这是一个点
    return FALSE;

  module->name = strrchr (linker_path, '/') + 1;//下面就是保存下来
  module->range = range;
  module->path = linker_path;

  range->base_address = start;
  range->size = end - start;

  return TRUE;
}

```

之后我们一起看一看，他是如何寻找linker中函数的地址，也就是如何初始化的api，可以看到和我们之前的方法差不多都是从节头表索引，也只有遍历节头表这一种方式能够得到linker中的dlopen这种符号了因为linker没有导出符号，最终到了gum\_store\_linker\_symbol\_if\_needed函数中，保存需要的符号类似do\_dlopen等,经此之后我们就有了直接从maps中得到的linker中的do\_dlopen和do\_dlsym等,保存到了api中

```c
//接上文gum_linker_api_try_init的下半段逻辑
static GumLinkerApi *
gum_linker_api_try_init (void)
{
.....
  api_level = gum_android_get_api_level ();//得到手机的安卓版本
gum_elf_module_enumerate_symbols (linker,
      (GumElfFoundSymbolFunc) gum_store_linker_symbol_if_needed, &pending);//将linker中的符号提取出来包括do_dlopen,do_dlsym等
.....
}
void
gum_elf_module_enumerate_symbols (GumElfModule * self,
                                  GumElfFoundSymbolFunc func,
                                  gpointer user_data)
{
  gum_elf_module_enumerate_symbols_in_section (self, SHT_SYMTAB, func,
      user_data);
}
static void
gum_elf_module_enumerate_symbols_in_section (GumElfModule * self,
                                             GumElfSectionHeaderType section,
                                             GumElfFoundSymbolFunc func,
                                             gpointer user_data)
{
......
  if (!gum_elf_module_find_section_header_by_type (self, section, &scn, &shdr))//寻找linker节头之前解析elf都讲过就不带着大家看了，从节头表中寻找类型为2的节，我们是通过name判断的他这种更巧妙
.......

  for (symbol_index = 0;
      symbol_index != symbol_count && carry_on;
      symbol_index++)
  {//遍历节符号表中所有的符号，如果是我们需要的就保存下来
    ......

    carry_on = func (&details, user_data);//执行上面的gum_store_linker_symbol_if_needed函数，遍历所有的符号表，如果有我们需要的符号就保留下来
  }
}

static gboolean
gum_store_linker_symbol_if_needed (const GumElfSymbolDetails * details,
                                   guint * pending)
{//这里列出了不同版本的dlopen的符号名称，遍历前面的节头表即可通过字符串匹配得到
  /* Restricted dlopen() implemented in API level >= 26 (Android >= 8.0). */
  GUM_TRY_ASSIGN (dlopen, "__dl___loader_dlopen");       /* >= 28 */
  GUM_TRY_ASSIGN (dlsym, "__dl___loader_dlvsym");        /* >= 28 */
  GUM_TRY_ASSIGN (dlopen, "__dl__Z8__dlopenPKciPKv");    /* >= 26 */
  GUM_TRY_ASSIGN (dlsym, "__dl__Z8__dlvsymPvPKcS1_PKv"); /* >= 26 */
  /* Namespaces implemented in API level >= 24 (Android >= 7.0). */
  GUM_TRY_ASSIGN_OPTIONAL (do_dlopen,
      "__dl__Z9do_dlopenPKciPK17android_dlextinfoPv");
  GUM_TRY_ASSIGN_OPTIONAL (do_dlsym, "__dl__Z8do_dlsymPvPKcS1_S_PS_");

  GUM_TRY_ASSIGN (dl_mutex, "__dl__ZL10g_dl_mutex"); /* >= 21 */
  GUM_TRY_ASSIGN (dl_mutex, "__dl__ZL8gDlMutex");    /*  < 21 */
  GUM_TRY_ASSIGN (solist_get_head, "__dl__Z15solist_get_headv"); /* >= 26 */
  GUM_TRY_ASSIGN_OPTIONAL (solist, "__dl__ZL6solist");           /* >= 21 */
  GUM_TRY_ASSIGN_OPTIONAL (libdl_info, "__dl_libdl_info");       /*  < 21 */
  GUM_TRY_ASSIGN (solist_get_somain, "__dl__Z17solist_get_somainv"); /* >= 26 */
  GUM_TRY_ASSIGN_OPTIONAL (somain, "__dl__ZL6somain");               /* "any" */

  GUM_TRY_ASSIGN (soinfo_get_path, "__dl__ZNK6soinfo12get_realpathEv");

beach:
  return *pending != 0;
}

```

处理我们要寻找的符号
----------

那么这里我们就可以通过linker中的soinfo链表来遍历所有的soinfo，然后再通过**dl**Z17solist\_get\_somainv函数来匹配so的名字，最后通过我们之前得到的dlopen函数调用来，得到该so的handle

```c
//继续接上文gum_enumerate_soinfo函数
static void
gum_enumerate_soinfo (GumFoundSoinfoFunc func,
                      gpointer user_data)
{

    ......
 somain = api->solist_get_somain ();//得到somain指针，这里又是另一个anti的点，就是可以清空somain因为他没判断是否为空
  gum_init_soinfo_details (&details, somain, api, &ranges);//将它初始化到detail中
  carry_on = func (&details, user_data);//通过调用gum_store_module_handle_if_name_matches匹配路径
  for (si = api->solist_get_head (); carry_on && si != NULL; si = next)//通过链表遍历所有的soinfo指针，当carry_on为false或者链表后没有元素的时候退出循环
  {
     carry_on = func (&details, user_data);//使用gum_store_module_handle_if_name_matches函数判断，如果路径一致就返回false
     ....

}
.....
}

static gboolean
gum_store_module_handle_if_name_matches (const GumSoinfoDetails * details,
                                         GumGetModuleHandleContext * ctx)
{
  GumLinkerApi * api = details->api;

  if (gum_linux_module_path_matches (details->path, ctx->name))//通过名字匹配，就是上面的通过链表索引出来的soinfo文件名是否一样
  {
    GumSoinfoBody * sb = details->body;
    int flags = RTLD_LAZY;
    void * caller_addr = GSIZE_TO_POINTER (sb->base);//dlopen的第三个参数，只有成功找到了do_dlopen的第三个参数才能成功的找到符号

    if (gum_android_is_vdso_module_name (details->path))
      return FALSE;

    if ((sb->flags & GUM_SOINFO_NEW_FORMAT) != 0)
    {
      GumSoinfo * parent;

      parent = (sb->parents.head != NULL)
          ? sb->parents.head->element
          : NULL;//通过指针找到该so的爸爸的首地址
      if (parent != NULL)
      {
        caller_addr = GSIZE_TO_POINTER (gum_soinfo_get_body (parent)->base);
      }

      if (sb->version >= 1)
      {
        flags = sb->rtld_flags;
      }
    }

    if (gum_android_get_api_level () >= 21)
    {
      flags |= RTLD_NOLOAD;
    }

    if (api->dlopen != NULL)
    {
      /* API level >= 26 (Android >= 8.0) */
      ctx->module = api->dlopen (details->path, flags, caller_addr);//调用我们之前得到的dlopen来获得该so的handle
    }
    else if (api->do_dlopen != NULL)
    {
      /* API level >= 24 (Android >= 7.0) */
      ctx->module = api->do_dlopen (details->path, flags, NULL, caller_addr);
    }
    else
    {
      ctx->module = dlopen (details->path, flags);
    }

    return FALSE;
  }

  return TRUE;
}

```

至此我们解析完了frida构造没有限制的dlopen的过程，那么接下来就看看他是如何找到dlsym的

```c
//接上文gum_module_find_export_by_name
GumAddress
gum_module_find_export_by_name (const gchar * module_name,
                                const gchar * symbol_name)
{

....
  result = GUM_ADDRESS (gum_module_get_symbol (module, symbol_name));
....
}
static void *
gum_module_get_symbol (void * module,
                       const gchar * symbol)
{
  GumGenericDlsymImpl dlsym_impl = dlsym;
#ifdef HAVE_ANDROID
  if (gum_android_get_linker_flavor () == GUM_ANDROID_LINKER_NATIVE)
    gum_android_find_unrestricted_dlsym (&dlsym_impl);//和上面一样构造没限制的dlsym
#endif
  return dlsym_impl (module, symbol);
}

gboolean
gum_android_find_unrestricted_dlsym (GumGenericDlsymImpl * generic_dlsym)
{
  if (!gum_android_find_unrestricted_linker_api (NULL))//初始化我们的api
    return FALSE;
  *generic_dlsym = gum_call_inner_dlsym;//最终赋值
  return TRUE;
}
static void *
gum_call_inner_dlsym (void * handle,
                      const char * symbol)
{
  return gum_dl_api.dlsym (handle, symbol, NULL, gum_dl_api.trusted_caller);//在&gum_dl_api函数中完成api的初始化，在高版本中也就是__dl___loader_dlvsym
}

```

到此为止我们就分析完了，frida是如何找到高版本的dlopen和dlsym，其实就是从节头表找到几个函数的地址，期间还意外的发现了anti frida的方法（其实具体逻辑不在这里，因为即使dlopen为空也能正常找到符号地址，但是attach需要验头，下文再说）

0x02 于frida缺陷的反frida
====================

frida发展了这么久，发展出了2种anti方式，一种是以字符串为基准的旧检测方式，一种是以frida代码为基准的各种各样的崩溃基址，旧方案现在很多地方还在使用，但是旧方案的绕过方式就太多了，比如hook fgets函数，甚至出现了hluda这种傻瓜式的绕过方式，所以有必要开发新的anti方式，这就是这篇文章的主旨希望能找到一个新的，难以被发现的antifrida的方式

旧方案之`maps`检测法
-------------

在字符串的检测方案中，大部分用的都是这种，但是这种也很容易被感知，它的代码结构如下,主要就是检测maps文件种是否有frida-agent字符串，当然这种取自maps的方式太容易被感知了，随便hook一下就知道我们遍历了maps，所以有以下的改进版本，通过遍历链表的方式来获得so的名称，查看是否有frida字样的so。

```c
void anti3(){
while (1) {
    sleep(1);
    char line[1024];

    FILE *fp = fopen("/proc/self/maps", "r");
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "frida-agent")) {
            __android_log_print(6, "r0ysue", "i find frida from anti3");
        }
    }
}
}
```

改进

```c
 void fridafind(){
    char line[1024];
    int *start;
    int *end;
    int n=1;
    int m=1;
    int *start1;
    FILE *fp=fopen("/proc/self/maps","r");
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "linker64") ) {
            __android_log_print(6,"r0ysue","%s", line);
            if(n==1){
                start = reinterpret_cast<int *>(strtoul(strtok(line, "-"), NULL, 16));
                end = reinterpret_cast<int *>(strtoul(strtok(NULL, " "), NULL, 16));

            }
            else{
                strtok(line, "-");
                end = reinterpret_cast<int *>(strtoul(strtok(NULL, " "), NULL, 16));
            }
            n++;

        }
        if (strstr(line, "libopenjdkjvm.so") ) {
            __android_log_print(6,"r0ysue","%s", line);
            if(m==1){
                start1 = reinterpret_cast<int *>(strtoul(strtok(line, "-"), NULL, 16));

            }
            m++;
        }

    }//获得liner首地址
int dlopenoff=findsym("/system/bin/linker64","__dl__Z8__dlopenPKciPKv");
    int headeroff=findsym("/system/bin/linker64","_dl__ZL6solist");//得到soinfo链表的头部
    long header= *(long *) ((char *) start + headeroff);
    for ( _QWORD *result = (_QWORD *)header; result; result = (_QWORD *)result[5] )//遍历所有的soinfo对象{
     if(strstr((const char*)*(_QWORD *)((__int64)result + 408),"frida"))
        __android_log_print(6,"r0ysue","%s",*(_QWORD *)((__int64)result + 408));//得到so的name

    }

}
```

这种还有一个版本，就是检查/data/local/tmp目录下面有没有frida依赖so所组成的文件夹，就是说frida-server在启动的时候会将依赖的so放在  
/data/local/tmp这个文件夹下面，所以我们可以扫描有没有这个文件夹，类似与下面这样的代码，当然上面提到的两种方法都能被简单的绕过，比如典型了hluda，就可以轻松的绕过，或者直接hook strstr函数也能发现校验的关键点，就不是很好，所以其实也可以改成逐比特用等号对比，当然也是很好绕过就对了

```c
void anti4(){
    int a=   access("/data/local/tmp/re.frida.server",0);
    if(a ==0)
    __android_log_print(6,"r0ysue","i find frida from anti4");

}
```

当然这里还有一些原理性的检测方法，比如和xposed一样检测ArtMethod的AccessFlags值来判断一个确定为Java的函数是否变成了Native函数，这个和java hook的原理有关,这个是frida绕不开的，就是想hookjava函数就一定要将java函数改成native函数，但是这种方式如果不 hook java函数直接搞Native层就拉了，所以这种方案也不太行。

```c
//  jclass myclass=env->FindClass("com/roysue/myanti/MainActivity");
// jmethodID mymethod=env->GetMethodID(myclass,"encr", "()I");
// a1=mymethod
void anti7(__int64 a1){
    while (1) {
        sleep(1);

        __android_log_print(6,"r0ysue","i find frida %x", (~*(_DWORD *)(a1 + 4) & 0x80000) );

        if((~*(_DWORD *)(a1 + 4) & 0x80000) !=0)
            __android_log_print(6,"r0ysue","i find frida %x", (~*(_DWORD *)(a1 + 4) & 0x80000) );
    }

}
```

当然后来又有大佬搞出了一个方案,见贴`https://bbs.pediy.com/thread-268586.htm`,这种方式提供了一个新思路，就是从frida的变化入手，例如检测frida的inline hook，这种方法就相当的好用了，因为frida作者也说了异常处理有一个bug必须要hook PrettyMethod函数，所以这种script boy就是无论如何都绕不开的

```c
function fixupArtQuickDeliverExceptionBug (api) {                                                            // frida源码
  const prettyMethod = api['art::ArtMethod::PrettyMethod'];
  if (prettyMethod === undefined) {
    return;
  }
  /*
   * There is a bug in art::Thread::QuickDeliverException() where it assumes
   * there is a Java stack frame present on the art::Thread's stack. This is
   * not the case if a native thread calls a throwing method like FindClass().
   *
   * We work around this bug here by detecting when method->PrettyMethod()
   * happens with method == nullptr.
   */
  Interceptor.attach(prettyMethod.impl, artController.hooks.ArtMethod.prettyMethod);
  Interceptor.flush();
}
```

所以说这种的anti 代码就如下,这种就靠谱多了，但是有可能会误杀，现在很多inline hook 都会采用x16跳转这种形式

```c

// as=findsym("/system/lib64/libart.so","_ZN3art9ArtMethod12PrettyMethodEb");
void anti6(long * as){
        while (1) {
            pthread_mutex_lock(&mutex);
//            __android_log_print(6, "r0ysue", "i find frida 1 %p",*as);
//                long long as = *(long long *) reinterpret_cast<long>(libnative[n]);
                if (*as == 0xd61f020058000050) {
                    __android_log_print(6, "r0ysue", "i find frida from anti6 ");
                }
sleep(2);
            pthread_mutex_unlock(&mutex);
            }
        }
```

所以说旧方式都是形式上的anti frida，都是可见的，都是在frida对系统的更改，那么新方式就是从frida的bug出发，要寻找frida在做寻找符号过程中容易发出异常的点，来主动抛出这些异常。

新方案之attach流程中寻找anti点
--------------------

在上篇文章中我们发现了frida调用了一个函数`gum_android_open_linker_module`来获取linker的地址，但是有一个缺陷，导致我们可以根据这一点反制frida，接下来我们就来一起看一下这个问题。

首先写一个简单的demo，逻辑很简单就是在主函数里面加一个anti7函数，从maps里面遍历linker64，然后把它开头的魔术字随便段改一个，比如我们这里就是将0x7f改成了0，最后看一下结果

```c
//libnative-lib.so
void anti7(){
    char line[1024];
    int *start;
    int *end;
    int n=1;
    FILE *fp=fopen("/proc/self/maps","r");
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "linker64") ) {
            __android_log_print(6,"r0ysue","%s", line);
            if(n==1){
                start = reinterpret_cast<int *>(strtoul(strtok(line, "-"), NULL, 16));
                end = reinterpret_cast<int *>(strtoul(strtok(NULL, " "), NULL, 16));
            }
            else{
                strtok(line, "-");
                end = reinterpret_cast<int *>(strtoul(strtok(NULL, " "), NULL, 16));
            }
            n++;
        }
    }
long* sr= reinterpret_cast<long *>(start);
    mprotect(start,PAGE_SIZE,PROT_WRITE|PROT_READ|PROT_EXEC);
    *sr=*sr^0x7f;
    __android_log_print(6, "r0ysue", "i find frida %p",*sr);
    void* tt=dlopen("libc.so",RTLD_NOW);
    void* ts=dlsym(tt,"strstr");
    __android_log_print(6,"r0ysue","%p",ts);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_roysue_anti_MainActivity_stringFromJNI(
        JNIEnv* env,
        jobject /* this */) {
    std::string hello = "Hello from C++";
anti7();
    return env->NewStringUTF(hello.c_str());
}
```

![2.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-20cbf329c330bdd1f40ed653e2486b1ae139ed8b.png)

可以看到以attach的方式启动，可以成功的使我们的frida崩溃掉，我们来一起看一下他为什么会有这种结果。

可以直接从frida-core/src/linux/frida-helper-backend-glue.c目录下的\_frida\_linux\_helper\_backend\_do\_inject函数入手（还是c代码比较易读其他语言不太易读），发现这里面调用了frida\_resolve\_linker\_address函数来获得dlclose函数，我们跟进去看一下

```c
void
_frida_linux_helper_backend_do_inject (FridaLinuxHelperBackend * self, guint pid, const gchar * path, const gchar * entrypoint, const gchar * data, const gchar * temp_path, guint id, GError ** error)
{
    .....
#elif defined (HAVE_ANDROID)
  params.dlopen_impl = frida_resolve_android_dlopen (pid);
  params.dlclose_impl = frida_resolve_linker_address (pid, dlclose);//从linker里面搜索dlclose
  params.dlsym_impl = frida_resolve_linker_address (pid, dlsym);//从linker里面搜索dlsym
....
}

```

有两个frida\_resolve\_linker\_address函数我们只需要看这个ANDROID就好了，它之中调用了gum\_android\_get\_linker\_module\_details函数来获得linker地址

```c
#ifdef HAVE_ANDROID
static GumAddress
frida_resolve_linker_address (pid_t pid, gpointer func)
{
......
  else
    local_base = gum_android_get_linker_module_details ()->range->base_address;//使用获得linker的地址
.....

  return remote_address;
}
```

接着就跳到了gum\_android\_get\_linker\_module\_details函数，又回到了上篇文章的那里

```c
// frida-gum/gum/backend-linux/gumandroid.c
const GumModuleDetails *
gum_android_get_linker_module_details (void)
{
  static GOnce once = G_ONCE_INIT;
  g_once (&once, (GThreadFunc) gum_try_init_linker_details, NULL);
  if (once.retval == NULL)
  {
    g_critical ("Unable to locate the Android linker; please file a bug");
    g_abort ();
  }
  return once.retval;
}
```

调用了gum\_try\_parse\_linker\_proc\_maps\_line，来寻找maps当中的linker

```c
static const GumModuleDetails *
gum_try_init_linker_details (void)
{
no_vdso:
  for (i = num_lines - 1; i >= 0; i--)
  {
    if (gum_try_parse_linker_proc_maps_line (lines[i], linker_path,
        linker_path_pattern, &gum_dl_module, &gum_dl_range))
    {
      result = &gum_dl_module;
      goto beach;
    }
  }

  return result;
}
```

最终到了我们的判断函数gum\_try\_parse\_linker\_proc\_maps\_line，这里面最大的问题就是验证了elf头部信息这个根本不会被用到的东西，那么只要我们更改掉maps里面的elf头那么frida就找不到linker的地址了，那么frida就自然崩掉了，会抛出异常`Unable to locate the Android linker; please file a bug`

```c
static gboolean
gum_try_parse_linker_proc_maps_line (const gchar * line,
                                     const gchar * linker_path,
                                     const GRegex * linker_path_pattern,
                                     GumModuleDetails * module,
                                     GumMemoryRange * range)
{
    .....
  const guint8 elf_magic[] = { 0x7f, 'E', 'L', 'F' };
  if (memcmp (GSIZE_TO_POINTER (start), elf_magic, sizeof (elf_magic)) != 0)//判断开头魔术字段是否是elf的魔术字段
    return FALSE;
    ....
  return TRUE;
}
```

新方案之findsymbol流程中寻找anti点
------------------------

承接上文的`findsymbol`,这里其实存在一个巨大的`bug`，就是`somain`的获取他没有判断是否为空我们跟下去看一下，跟踪到最后发现它没有判断是否为空就直接取值了，就会造成地址不对这种情况，下面我们试一下。

```c
static void
gum_enumerate_soinfo (GumFoundSoinfoFunc func,
                      gpointer user_data)
{

    ......
    //得到主进程的soinfo指针
 somain = api->solist_get_somain ();
  gum_init_soinfo_details (&details, somain, api, &ranges);//将它初始化到detail中
.....
}

static void
gum_init_soinfo_details (GumSoinfoDetails * details,
                         GumSoinfo * si,
                         GumLinkerApi * api,
                         GHashTable ** ranges)
{
  details->path = gum_resolve_soinfo_path (si, api, ranges);
  details->si = si;
  //跟入这里
  details->body = gum_soinfo_get_body (si);
  details->api = api;
}

static GumSoinfoBody *
gum_soinfo_get_body (GumSoinfo * self)
{
  guint api_level = gum_android_get_api_level ();
  if (api_level >= 26)
  //这里没有做判断直接就取值了，十分的不科学，所以我们可以将somain改为空对普通使用也没啥影响,下面也一样
    return &self->modern.body;
  else if (api_level >= 23)
    return &self->legacy23.body;
  else
    return &self->legacy.legacy23.body;
}

```

写一个简单的demo,搞到app里面,这里写在了init段中就是，让他人不管是spawn或者attch都不能寻找符号。

```c
void anti7(){
    char line[1024];
    int *start;
    int *end;
    int n=1;
    FILE *fp=fopen("/proc/self/maps","r");
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "linker64") ) {
            __android_log_print(6,"r0ysue","%s", line);
            if(n==1){
                start = reinterpret_cast<int *>(strtoul(strtok(line, "-"), NULL, 16));
                end = reinterpret_cast<int *>(strtoul(strtok(NULL, " "), NULL, 16));

            }
            else{
                strtok(line, "-");
                end = reinterpret_cast<int *>(strtoul(strtok(NULL, " "), NULL, 16));
            }
            n++;

        }

    }
long* sr= reinterpret_cast<long *>(start);

    mprotect(start,PAGE_SIZE,PROT_WRITE|PROT_READ|PROT_EXEC);
    long off=findsym("/system/bin/linker64","__dl__ZL6somain");
    __android_log_print(6,"r0ysue","xxxxxxxx %p",off);
    long* somain= reinterpret_cast<long*>((char *) sr + off);

    *somain=0;
    void* sb=dlopen("libc.so",RTLD_NOW);
    void* ddd=dlsym(sb,"strstr");
    void* tt=dlopen("libc.so",RTLD_NOW);
    void* ts=dlsym(tt,"strstr");
    __android_log_print(6,"r0ysue","%p",ts);
}

extern "C" void _init(void){
    anti7();

}
```

用下面的frida脚本试一下，最后果然崩溃了。

```js
function main(){
    var dlopen = Module.findExportByName(null, "android_dlopen_ext");

    Interceptor.attach(dlopen, {
        onEnter: function (arg) {
        var name=ptr(arg[0]).readCString();

        if(name.indexOf("libnative-lib.so")>=0){
               console.log(name)
        this.name=name;
        }

        }, onLeave: function (ret) {

            if(this.name!=undefined){

               var  libcrackme=Module.findBaseAddress("libnative-lib.so");

                console.log(libcrackme);

            }

        }

    })

}
setImmediate(main);
```

![3.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-1be4f46112a6510a1feb0f37a2fe712c9f021f70.png)

0x03 总结
=======

`anti-frida`与绕过`frida`的手段都在一直的进步，比如早期提出的so特征antifrida的方式就被hluda完美的绕过了，导致很长一段时间内frida畅通无阻；后来的从大致的原理出发的ptrace与hook特征，也有一定的局限性就是太容易被感知到了，比如双进程互相ptrace判断，这样ps就能知道手法。

最好的方式还是从源码出发，直接以找bug的心态阅读frida源码，当然前文介绍的这种方式也有一定的局限性，就是如果以spawn的方式启动frida，此时so代码是没法影响到`frida-server`的，所以spwan去hook系统的so是确实anti不到，算是一个小的遗憾吧，但是只要我们的app启动frida就没法完成hook包括java hook，总之说了这么多，脚本小子总会被掣肘，想愉快的逆向，最好是能自己开发一个主动调用兼hook框架。