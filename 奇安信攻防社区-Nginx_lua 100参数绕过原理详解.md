一、环境搭建  
Nginx\_lua 安装

<https://github.com/openresty/lua-nginx-module#installation>

```asp
wget 'https://openresty.org/download/nginx-1.19.3.tar.gz'
 tar -xzvf nginx-1.19.3.tar.gz
 cd nginx-1.19.3/

 # tell nginx's build system where to find LuaJIT 2.0:
 export LUAJIT_LIB=/path/to/luajit/lib
 export LUAJIT_INC=/path/to/luajit/include/luajit-2.0

 # tell nginx's build system where to find LuaJIT 2.1:
 export LUAJIT_LIB=/path/to/luajit/lib
 export LUAJIT_INC=/path/to/luajit/include/luajit-2.1

 # Here we assume Nginx is to be installed under /opt/nginx/.
 ./configure --prefix=/opt/nginx \
         --with-ld-opt=&quot;-Wl,-rpath,/path/to/luajit/lib&quot; \
         --add-module=/path/to/ngx_devel_kit \
         --add-module=/path/to/lua-nginx-module

 # Note that you may also want to add `./configure` options which are used in your
 # current nginx build.
 # You can get usually those options using command nginx -V

 # you can change the parallism number 2 below to fit the number of spare CPU cores in your
 # machine.
 make -j2
 make install
```

安装完之后可以在nginx.conf 写入配置。可以动态在Nginx 层面进行过滤和调度

这里使用一个很简单的方式来展示绕过的原理

```asp
location = /api2 {
        content_by_lua_block {
            tmp=''
            for i,v in pairs(ngx.req.get_uri_args()) do
              if type(i)=='string' then 
                tmp=tmp..i..' '
              end
            end
            ngx.header.content_type = &quot;application/json;&quot;
            ngx.status = 200
            ngx.say(tmp)
            ngx.exit(200)
        }
    }
```

这里是意思是访问/api2 然后返回get的所有参数。默认他是接受100个参数。当超过100个参数的时候会默认不会记录。这样达成了一个绕过的一个方式。演示如下：

首先先发送两个id 过去试试

那么试试id1-&gt;id100

```asp
a=''
for i in range(1,102):
   a=a+'id'+str(i)+'=11&amp;'
print(a)
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/04/attach-5c8f2554645809c4c18a9f9ceb87becb1aadf31a.png)](https://shs3.b.qianxin.com/attack_forum/2021/04/attach-5c8f2554645809c4c18a9f9ceb87becb1aadf31a.png)

```asp
GET /api2?id1=11&amp;id2=11&amp;id3=11&amp;id4=11&amp;id5=11&amp;id6=11&amp;id7=11&amp;id8=11&amp;id9=11&amp;id10=11&amp;id11=11&amp;id12=11&amp;id13=11&amp;id14=11&amp;id15=11&amp;id16=11&amp;id17=11&amp;id18=11&amp;id19=11&amp;id20=11&amp;id21=11&amp;id22=11&amp;id23=11&amp;id24=11&amp;id25=11&amp;id26=11&amp;id27=11&amp;id28=11&amp;id29=11&amp;id30=11&amp;id31=11&amp;id32=11&amp;id33=11&amp;id34=11&amp;id35=11&amp;id36=11&amp;id37=11&amp;id38=11&amp;id39=11&amp;id40=11&amp;id41=11&amp;id42=11&amp;id43=11&amp;id44=11&amp;id45=11&amp;id46=11&amp;id47=11&amp;id48=11&amp;id49=11&amp;id50=11&amp;id51=11&amp;id52=11&amp;id53=11&amp;id54=11&amp;id55=11&amp;id56=11&amp;id57=11&amp;id58=11&amp;id59=11&amp;id60=11&amp;id61=11&amp;id62=11&amp;id63=11&amp;id64=11&amp;id65=11&amp;id66=11&amp;id67=11&amp;id68=11&amp;id69=11&amp;id70=11&amp;id71=11&amp;id72=11&amp;id73=11&amp;id74=11&amp;id75=11&amp;id76=11&amp;id77=11&amp;id78=11&amp;id79=11&amp;id80=11&amp;id81=11&amp;id82=11&amp;id83=11&amp;id84=11&amp;id85=11&amp;id86=11&amp;id87=11&amp;id88=11&amp;id89=11&amp;id90=11&amp;id91=11&amp;id92=11&amp;id93=11&amp;id94=11&amp;id95=11&amp;id96=11&amp;id97=11&amp;id98=11&amp;id99=11&amp;id100=11&amp;id101=11 HTTP/1.1
Host: 192.168.1.70
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.190 Safari/537.36
Connection: close
```

返回从1-100

```asp
id76 id74 id64 id62 id60 id61 id5 id73 id71 id14 id91 id15 id20 id22 id12 id66 id13 id32 id10 id31 id33 id11 id92 id21 id84 id93 id85 id67 id30 id83 id58 id3 id88 id59 id98 id68 id69 id81 id48 id49 id8 id9 id25 id24 id26 id16 id79 id17 id36 id35 id18 id89 id99 id29 id28 id100 id97 id96 id95 id94 id6 id38 id90 id87 id39 id86 id19 id82 id80 id42 id56 id78 id52 id77 id75 id57 id44 id53 id7 id54 id72 id50 id1 id46 id55 id70 id51 id65 id23 id2 id40 id37 id4 id43 id47 id27 id41 id45 id34 id63

```

但是没有id101 那么这个id101 哪里去了呢？

那么看看ngx.req.get\_uri\_args() 这个函数是怎么实现的

二、源码解析  
参考文章:  
<https://blog.csdn.net/liujiyong7/article/details/37692027>

src/ngx\_http\_lua\_module.c为模块主入口文件

注册函数的写法有统一的格式：

```asp
static int
ngx_http_lua_ngx_req_get_method(lua_State *L)
{
    int                      n;
    ngx_http_request_t      *r;
    n = lua_gettop(L);
    if (n != 0) {
        return luaL_error(L, &quot;only one argument expected but got %d&quot;, n);
    }
    r = ngx_http_lua_get_req(L);//从lua全局变量得到request结构体指针，见4.2.2
    if (r == NULL) {
        return luaL_error(L, &quot;request object not found&quot;);
    }
    ngx_http_lua_check_fake_request(L, r);//检查r合法性

    lua_pushlstring(L, (char *) r-&gt;method_name.data, r-&gt;method_name.len);//将method压栈
    return 1;
}
```

注册get\_uri\_args 在

所有的nginx api for lua注册在lua-nginx-module/src/ngx\_http\_lua\_util.c:ngx\_http\_lua\_inject\_ngx\_api 函数中

与request有关的注册在lua-nginx-module/src/ngx\_http\_lua\_util.c: ngx\_http\_lua\_inject\_req\_api 函数中

ngx\_http\_lua\_inject\_ngx\_api 函数

```asp
static void
ngx_http_lua_inject_ngx_api(lua_State *L, ngx_http_lua_main_conf_t *lmcf,
    ngx_log_t *log)
{
    lua_createtable(L, 0 /* narr */, 113 /* nrec */);    /* ngx.* */

    lua_pushcfunction(L, ngx_http_lua_get_raw_phase_context);
    lua_setfield(L, -2, &quot;_phase_ctx&quot;);

    ngx_http_lua_inject_arg_api(L);

    ngx_http_lua_inject_http_consts(L);
    ngx_http_lua_inject_core_consts(L);

    ngx_http_lua_inject_log_api(L);
    ngx_http_lua_inject_output_api(L);
    ngx_http_lua_inject_string_api(L);
    ngx_http_lua_inject_control_api(log, L);
    ngx_http_lua_inject_subrequest_api(L);
    ngx_http_lua_inject_sleep_api(L);

    ngx_http_lua_inject_req_api(log, L);
    ngx_http_lua_inject_resp_header_api(L);
    ngx_http_lua_create_headers_metatable(log, L);
    ngx_http_lua_inject_shdict_api(lmcf, L);
    ngx_http_lua_inject_socket_tcp_api(log, L);
    ngx_http_lua_inject_socket_udp_api(log, L);
    ngx_http_lua_inject_uthread_api(log, L);
    ngx_http_lua_inject_timer_api(L);
    ngx_http_lua_inject_config_api(L);

    lua_getglobal(L, &quot;package&quot;); /* ngx package */
    lua_getfield(L, -1, &quot;loaded&quot;); /* ngx package loaded */
    lua_pushvalue(L, -3); /* ngx package loaded ngx */
    lua_setfield(L, -2, &quot;ngx&quot;); /* ngx package loaded */
    lua_pop(L, 2);

    lua_setglobal(L, &quot;ngx&quot;);

    ngx_http_lua_inject_coroutine_api(log, L);
}
```

ngx\_http\_lua\_inject\_req\_api 函数

```asp
void
ngx_http_lua_inject_req_api(ngx_log_t *log, lua_State *L)
{
    /* ngx.req table */

    lua_createtable(L, 0 /* narr */, 23 /* nrec */);    /* .req */

    ngx_http_lua_inject_req_header_api(L);
    ngx_http_lua_inject_req_uri_api(log, L);
    ngx_http_lua_inject_req_args_api(L);
    ngx_http_lua_inject_req_body_api(L);
    ngx_http_lua_inject_req_socket_api(L);
    ngx_http_lua_inject_req_misc_api(L);

    lua_setfield(L, -2, &quot;req&quot;);
}
```

看着应该是ngx\_http\_lua\_inject\_req\_uri\_api 和 ngx\_http\_lua\_inject\_req\_args\_api 比较像 跟踪一下这两个函数

ngx\_http\_lua\_inject\_req\_uri\_api

```actionscript
void
ngx_http_lua_inject_req_uri_api(ngx_log_t *log, lua_State *L)
{
    lua_pushcfunction(L, ngx_http_lua_ngx_req_set_uri);
    lua_setfield(L, -2, &quot;set_uri&quot;);
}
```

ngx\_http\_lua\_inject\_req\_args\_api

```actionscript
ngx_http_lua_inject_req_args_api(lua_State *L)
{
    lua_pushcfunction(L, ngx_http_lua_ngx_req_set_uri_args);
    lua_setfield(L, -2, &quot;set_uri_args&quot;);

    lua_pushcfunction(L, ngx_http_lua_ngx_req_get_post_args);
    lua_setfield(L, -2, &quot;get_post_args&quot;);
}}
```

这里只有set\_uri\_args 和get\_post\_args 并没有找到get\_uri\_args

这里陷入了深深的沉思

全局搜索下只有ngx\_http\_lua\_ffi\_req\_get\_uri\_args 这一个函数是相关的 。

这个函数在src/ngx\_http\_lua\_args.c

三、查看get\_post\_args 这个函数过程  
首先看一下get\_post\_args 这个一个过程吧

注册为get\_post\_args 那么nginx内部的调用方式为ngx.req.get\_post\_args

```actionscript
lua_pushcfunction(L, ngx_http_lua_ngx_req_get_post_args);
lua_setfield(L, -2, &quot;get_post_args&quot;);
```

ngx\_http\_lua\_ngx\_req\_get\_post\_args 函数体

```actionscript
static int
ngx_http_lua_ngx_req_get_post_args(lua_State *L)
{
    ngx_http_request_t          *r;
    u_char                      *buf;
    int                          retval;
    size_t                       len;
    ngx_chain_t                 *cl;
    u_char                      *p;
    u_char                      *last;
    int                          n;
    int                          max;

    n = lua_gettop(L);

    if (n != 0 &amp;&amp; n != 1) {
        return luaL_error(L, &quot;expecting 0 or 1 arguments but seen %d&quot;, n);
    }

    if (n == 1) {
        max = luaL_checkinteger(L, 1);
        lua_pop(L, 1);

    } else {
        max = NGX_HTTP_LUA_MAX_ARGS;
    }

    r = ngx_http_lua_get_req(L);
    if (r == NULL) {
        return luaL_error(L, &quot;no request object found&quot;);
    }

    ngx_http_lua_check_fake_request(L, r);

    if (r-&gt;discard_body) {
        lua_createtable(L, 0, 0);
        return 1;
    }

    if (r-&gt;request_body == NULL) {
        return luaL_error(L, &quot;no request body found; &quot;
                          &quot;maybe you should turn on lua_need_request_body?&quot;);
    }

    if (r-&gt;request_body-&gt;temp_file) {
        lua_pushnil(L);
        lua_pushliteral(L, &quot;request body in temp file not supported&quot;);
        return 2;
    }

    if (r-&gt;request_body-&gt;bufs == NULL) {
        lua_createtable(L, 0, 0);
        return 1;
    }

    /* we copy r-&gt;request_body-&gt;bufs over to buf to simplify
     * unescaping query arg keys and values */

    len = 0;
    for (cl = r-&gt;request_body-&gt;bufs; cl; cl = cl-&gt;next) {
        len += cl-&gt;buf-&gt;last - cl-&gt;buf-&gt;pos;
    }

    dd(&quot;post body length: %d&quot;, (int) len);

    if (len == 0) {
        lua_createtable(L, 0, 0);
        return 1;
    }

    buf = ngx_palloc(r-&gt;pool, len);
    if (buf == NULL) {
        return luaL_error(L, &quot;no memory&quot;);
    }

    lua_createtable(L, 0, 4);

    p = buf;
    for (cl = r-&gt;request_body-&gt;bufs; cl; cl = cl-&gt;next) {
        p = ngx_copy(p, cl-&gt;buf-&gt;pos, cl-&gt;buf-&gt;last - cl-&gt;buf-&gt;pos);
    }

    dd(&quot;post body: %.*s&quot;, (int) len, buf);

    last = buf + len;

    retval = ngx_http_lua_parse_args(L, buf, last, max);

    ngx_pfree(r-&gt;pool, buf);

    return retval;
}
```

上述的关键的在于

max = NGX\_HTTP\_LUA\_MAX\_ARGS;

找到定义的NGX\_HTTP\_LUA\_MAX\_ARGS 默认为100

```actionscript
ifndef NGX_HTTP_LUA_MAX_ARGS
    define NGX_HTTP_LUA_MAX_ARGS 100
endif
```

然后走到了ngx\_http\_lua\_parse\_args 这个函数

```actionscript
int
ngx_http_lua_parse_args(lua_State *L, u_char *buf, u_char *last, int max)
{
    u_char                      *p, *q;
    u_char                      *src, *dst;
    unsigned                     parsing_value;
    size_t                       len;
    int                          count = 0;
    int                          top;

    top = lua_gettop(L);

    p = buf;

    parsing_value = 0;
    q = p;

    while (p != last) {
        if (*p == '=' &amp;&amp; ! parsing_value) {
            /* key data is between p and q */

            src = q; dst = q;

            ngx_http_lua_unescape_uri(&amp;dst, &amp;src, p - q,
                                      NGX_UNESCAPE_URI_COMPONENT);

            dd(&quot;pushing key %.*s&quot;, (int) (dst - q), q);

            /* push the key */
            lua_pushlstring(L, (char *) q, dst - q);

            /* skip the current '=' char */
            p++;

            q = p;
            parsing_value = 1;

        } else if (*p == '&amp;') {
            /* reached the end of a key or a value, just save it */
            src = q; dst = q;

            ngx_http_lua_unescape_uri(&amp;dst, &amp;src, p - q,
                                      NGX_UNESCAPE_URI_COMPONENT);

            dd(&quot;pushing key or value %.*s&quot;, (int) (dst - q), q);

            /* push the value or key */
            lua_pushlstring(L, (char *) q, dst - q);

            /* skip the current '&amp;' char */
            p++;

            q = p;

            if (parsing_value) {
                /* end of the current pair's value */
                parsing_value = 0;

            } else {
                /* the current parsing pair takes no value,
                 * just push the value &quot;true&quot; */
                dd(&quot;pushing boolean true&quot;);

                lua_pushboolean(L, 1);
            }

            (void) lua_tolstring(L, -2, &amp;len);

            if (len == 0) {
                /* ignore empty string key pairs */
                dd(&quot;popping key and value...&quot;);
                lua_pop(L, 2);

            } else {
                dd(&quot;setting table...&quot;);
                ngx_http_lua_set_multi_value_table(L, top);
            }

            if (max &gt; 0 &amp;&amp; ++count == max) {
                lua_pushliteral(L, &quot;truncated&quot;);

                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ngx_cycle-&gt;log, 0,
                               &quot;lua hit query args limit %d&quot;, max);
                return 2;
            }

        } else {
            p++;
        }
    }

    if (p != q || parsing_value) {
        src = q; dst = q;

        ngx_http_lua_unescape_uri(&amp;dst, &amp;src, p - q,
                                  NGX_UNESCAPE_URI_COMPONENT);

        dd(&quot;pushing key or value %.*s&quot;, (int) (dst - q), q);

        lua_pushlstring(L, (char *) q, dst - q);

        if (!parsing_value) {
            dd(&quot;pushing boolean true...&quot;);
            lua_pushboolean(L, 1);
        }

        (void) lua_tolstring(L, -2, &amp;len);

        if (len == 0) {
            /* ignore empty string key pairs */
            dd(&quot;popping key and value...&quot;);
            lua_pop(L, 2);

        } else {
            dd(&quot;setting table...&quot;);
            ngx_http_lua_set_multi_value_table(L, top);
        }
    }

    dd(&quot;gettop: %d&quot;, lua_gettop(L));
    dd(&quot;type: %s&quot;, lua_typename(L, lua_type(L, 1)));

    if (lua_gettop(L) != top) {
        return luaL_error(L, &quot;internal error: stack in bad state&quot;);
    }

    return 1;
}
```

如上代码。读取等于号之前的作为key 然后&amp; 之前的作为value 。然后进行保存到内存中然后进行判断是否大于等于max

获取key

```actionscript
src = q; dst = q;

            ngx_http_lua_unescape_uri(&amp;dst, &amp;src, p - q,
                                      NGX_UNESCAPE_URI_COMPONENT);

            dd(&quot;pushing key %.*s&quot;, (int) (dst - q), q);

            /* push the key */
            lua_pushlstring(L, (char *) q, dst - q);

            /* skip the current '=' char */
            p++;

            q = p;
            parsing_value = 1;
```

value

```actionscript
src = q; dst = q;

    ngx_http_lua_unescape_uri(&amp;dst, &amp;src, p - q,
                              NGX_UNESCAPE_URI_COMPONENT);

    dd(&quot;pushing key or value %.*s&quot;, (int) (dst - q), q);

    /* push the value or key */
    lua_pushlstring(L, (char *) q, dst - q);
```

判断长度是否等于max

```actionscript
if (max &gt; 0 &amp;&amp; ++count == max) {
                lua_pushliteral(L, &quot;truncated&quot;);

                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ngx_cycle-&gt;log, 0,
                               &quot;lua hit query args limit %d&quot;, max);
                return 2;
            }
```

但是现在还有一个疑问就是get\_uri\_args 这个怎么获取的呢？ 如上是获取了get\_post\_args

四、get\_uri\_args  
参考大量的代码发现。他这个是内置的一个格式ngx\_http\_lua\_ffi 开头。我也没有找到他内部怎么注册流程。

例如：

ngx\_http\_lua\_ffi\_encode\_base64

ngx\_http\_lua\_ffi\_unescape\_uri

ngx\_http\_lua\_ffi\_time

暂时没有找到他的内部注册的逻辑。这里先不做讨论了。如果有大佬可以指出哪里是注册流程话记得艾特一下我

ngx\_http\_lua\_ffi\_req\_get\_uri\_args 代码如下

```actionscript
int
ngx_http_lua_ffi_req_get_uri_args(ngx_http_request_t *r, u_char *buf,
    ngx_http_lua_ffi_table_elt_t *out, int count)
{
    int                          i, parsing_value = 0;
    u_char                      *last, *p, *q;
    u_char                      *src, *dst;

    if (count &lt;= 0) {
        return NGX_OK;
    }

    ngx_memcpy(buf, r-&gt;args.data, r-&gt;args.len);

    i = 0;
    last = buf + r-&gt;args.len;
    p = buf;
    q = p;

    while (p != last) {
        if (*p == '=' &amp;&amp; !parsing_value) {
            /* key data is between p and q */

            src = q; dst = q;

            ngx_http_lua_unescape_uri(&amp;dst, &amp;src, p - q,
                                      NGX_UNESCAPE_URI_COMPONENT);

            dd(&quot;saving key %.*s&quot;, (int) (dst - q), q);

            out[i].key.data = q;
            out[i].key.len = (int) (dst - q);

            /* skip the current '=' char */
            p++;

            q = p;
            parsing_value = 1;

        } else if (*p == '&amp;') {
            /* reached the end of a key or a value, just save it */
            src = q; dst = q;

            ngx_http_lua_unescape_uri(&amp;dst, &amp;src, p - q,
                                      NGX_UNESCAPE_URI_COMPONENT);

            dd(&quot;pushing key or value %.*s&quot;, (int) (dst - q), q);

            if (parsing_value) {
                /* end of the current pair's value */
                parsing_value = 0;

                if (out[i].key.len) {
                    out[i].value.data = q;
                    out[i].value.len = (int) (dst - q);
                    i++;
                }

            } else {
                /* the current parsing pair takes no value,
                 * just push the value &quot;true&quot; */
                dd(&quot;pushing boolean true&quot;);

                if (dst - q) {
                    out[i].key.data = q;
                    out[i].key.len = (int) (dst - q);
                    out[i].value.len = -1;
                    i++;
                }
            }

            if (i == count) {
                return i;
            }

            /* skip the current '&amp;' char */
            p++;

            q = p;

        } else {
            p++;
        }
    }

    if (p != q || parsing_value) {
        src = q; dst = q;

        ngx_http_lua_unescape_uri(&amp;dst, &amp;src, p - q,
                                  NGX_UNESCAPE_URI_COMPONENT);

        dd(&quot;pushing key or value %.*s&quot;, (int) (dst - q), q);

        if (parsing_value) {
            if (out[i].key.len) {
                out[i].value.data = q;
                out[i].value.len = (int) (dst - q);
                i++;
            }

        } else {
            if (dst - q) {
                out[i].key.data = q;
                out[i].key.len = (int) (dst - q);
                out[i].value.len = (int) -1;
                i++;
            }
        }
    }

    return i;
}
```

首先呢。他这个也是获取一个key 和一个value 的过程。然后判断一下是否是i==count

i 这个地方是一个整数。每次设置好值之后i++

这里画了一个图  
[![](https://shs3.b.qianxin.com/attack_forum/2021/04/attach-4fd8bd706bda4f5046963fcab5f5ca8f0e885094.png)](https://shs3.b.qianxin.com/attack_forum/2021/04/attach-4fd8bd706bda4f5046963fcab5f5ca8f0e885094.png)

文章来源于自己博客，博客地址https://www.o2oxy.cn/3303.html