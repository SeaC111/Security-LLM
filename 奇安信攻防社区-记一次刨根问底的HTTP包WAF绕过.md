![1](https://shs3.b.qianxin.com/butian_public/f7d28ccc9e8e997f37c6302e45e841637.jpg)

```php
POST /sql/post.php HTTP/1.1
Host: 192.168.1.72
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://192.168.1.76
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.190 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://192.168.1.76/sql.html
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close
Content-Type: multipart/form-data; boundary=--------1721837650
Content-Length: 156

----------1721837650
Content-Disposition: form-data; name="name\"; filename=";name='username'"
Content-Type: image/jpeg

admin
----------1721837650--

```

首先他是一个from-data的参数传递。并不上文件上传。因为\\ 把双引号给注释起来了。然后name=”name; filename=”;

然后另外一个是name=’username’

猜测。两个只会选择最后一个进行参数传递。

一、Fastcgi 了解

<https://segmentfault.com/a/1190000016901718>

然后两台机器 WEB 192.168.1.72 PHP 192.168.1.70

PHP 服务器开启php-fpm 端口

![](https://shs3.b.qianxin.com/butian_public/fc7a65159079a62a01c55fa0f7ecee65a.jpg)

WEB服务器通过192.168.1.70:9000 去连接PHP

![](https://shs3.b.qianxin.com/butian_public/f8cb495b2745b7ad186b5ebcf8ba741a5.jpg)

然后进行抓包。 PHP 服务器抓WEB服务器发过来的包

`tcpdump  src host  192.168.1.72 -w qq.cap`

看看FastCgi 具体的一个from-data 的内容

![](https://shs3.b.qianxin.com/butian_public/f74d70bd227bb5ce1fa28d16de8484a06.jpg)

```php
.........................&SCRIPT_FILENAME/www/wwwroot/192.168.1.72/sql/post.php..QUERY_STRING..REQUEST_METHODPOST.0CONTENT_TYPEmultipart/form-data; boundary=--------1721837650..CONTENT_LENGTH156.
SCRIPT_NAME/sql/post.php.
REQUEST_URI/sql/post.php.
DOCUMENT_URI/sql/post.php
.DOCUMENT_ROOT/www/wwwroot/192.168.1.72..SERVER_PROTOCOLHTTP/1.1..REQUEST_SCHEMEhttp..GATEWAY_INTERFACECGI/1.1..SERVER_SOFTWAREnginx/1.18.0..REMOTE_ADDR192.168.1.75..REMOTE_PORT59676..SERVER_ADDR192.168.1.72..SERVER_PORT80..SERVER_NAME192.168.1.72..REDIRECT_STATUS200.&SCRIPT_FILENAME/www/wwwroot/192.168.1.72/sql/post.php.
SCRIPT_NAME/sql/post.php    .PATH_INFO  .HTTP_HOST192.168.1.72. HTTP_CACHE_CONTROLmax-age=0..HTTP_UPGRADE_INSECURE_REQUESTS1..HTTP_ORIGINhttp://192.168.1.76.sHTTP_USER_AGENTMozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.190 Safari/537.36.....HTTP_ACCEPTtext/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9..HTTP_REFERERhttp://192.168.1.76/sql.html.
HTTP_ACCEPT_ENCODINGgzip, deflate..HTTP_ACCEPT_LANGUAGEzh-CN,zh;q=0.9..HTTP_CONNECTIONclose.0HTTP_CONTENT_TYPEmultipart/form-data; boundary=--------1721837650..HTTP_CONTENT_LENGTH156.....................
----------1721837650
Content-Disposition: form-data; name="name\"; filename=";name='username'"
Content-Type: image/jpeg

admin
----------1721837650--............

```

看到流量包的时候，感觉之前的东西是错了。前期和Yukion 师傅一直感觉是Nginx 做了处理，现在才明白其实最终是PHP进行了处理

Params 数据包参数整理:

| key len | val len | key | val |  |
|---|---|---|---|---|
| 10 | 4 | PRODUCTION | true |  |
| 15 | 38 | SCRIPT\_FILENAME | /home/xiaoju/webroot/default/index.php |  |
| 12 | 0 | QUERY\_STRING |  |  |
| 14 | 3 | REQUEST\_METHOD | GET |  |
| 12 | 0 | CONTENT\_TYPE |  |  |
| 14 | 0 | CONTENT\_LENGTH |  |  |
| 11 | 10 | SCRIPT\_NAME | /index.php |  |
| 11 | 1 | REQUEST\_URI | / |  |
| 12 | 10 | DOCUMENT\_URI | /index.php |  |
| 13 | 28 | DOCUMENT\_ROOT | /home/xiaoju/webroot/default |  |
| 15 | 8 | SERVER\_PROTOCOL | HTTP/1.1 |  |
| 17 | 7 | GATEWAY\_INTERFACE | CGI/1.1 |  |
| 15 | 11 | SERVER\_SOFTWARE | nginx/1.6.2 |  |
| 11 | 9 | REMOTE\_ADDR | 127.0.0.1 |  |
| 11 | 5 | REMOTE\_PORT | 42282 |  |
| 11 | 9 | SERVER\_ADDR | 127.0.0.1 |  |
| 11 | 4 | SERVER\_PORT | 8100 |  |
| 11 | 0 | SERVER\_NAME |  |  |
| 15 | 3 | REDIRECT\_STATUS | 200 |  |
| 15 | 11 | HTTP\_USER\_AGENT | curl/7.29.0 |  |
| 9 | 14 | HTTP\_HOST | localhost:8100 |  |
| 11 | 3 | HTTP\_ACCEPT | */* |  |

对于Fastcgi 协议。前面的文章介绍的很全了。

那么fastcgi 传递到PHP中PHP 是怎么处理的

参考文章：<https://segmentfault.com/a/1190000016868502>

从该文件中得到了具体的答案：

```php
对于multipart/form-data，post_handler是rfc1867_post_handler。
由于它的代码过长，这里不再贴代码了。由于在body信息读取阶段，
钩子的post_reader是空，
所以rfc1867_post_handler会一边做FCGI_STDIN数据包的读取，
一边做解析存储工作，
最终将数据包中的key-value对存储到PG(http_globals)[0]中。
另外，该函数还会对上传的文件进行处理，有兴趣的同学可以读下这个函数。
```

打开github

[https://github.com/php/php-src/search?q=ALLOC\_HASHTABLE](https://github.com/php/php-src/search?q=ALLOC_HASHTABLE)

搜索rfc1867\_post\_handler

![](https://shs3.b.qianxin.com/butian_public/f507f86ad8368b63fd78ef2f15820c126.jpg)  
找到具体的函数实现方法

```php
SAPI_API SAPI_POST_HANDLER_FUNC(rfc1867_post_handler) /* {{{ */
{
    char *boundary, *s = NULL, *boundary_end = NULL, *start_arr = NULL, *array_index = NULL;
    char *lbuf = NULL, *abuf = NULL;
    zend_string *temp_filename = NULL;
    int boundary_len = 0, cancel_upload = 0, is_arr_upload = 0;
    size_t array_len = 0;
    int64_t total_bytes = 0, max_file_size = 0;
    int skip_upload = 0, anonindex = 0, is_anonymous;
    HashTable *uploaded_files = NULL;
    multipart_buffer *mbuff;
    zval *array_ptr = (zval *) arg;
    int fd = -1;
    zend_llist header;
    void *event_extra_data = NULL;
    unsigned int llen = 0;
    int upload_cnt = INI_INT("max_file_uploads");
    const zend_encoding *internal_encoding = zend_multibyte_get_internal_encoding();
    php_rfc1867_getword_t getword;
    php_rfc1867_getword_conf_t getword_conf;
    php_rfc1867_basename_t _basename;
    zend_long count = 0;

    if (php_rfc1867_encoding_translation() && internal_encoding) {
        getword = php_rfc1867_getword;
        getword_conf = php_rfc1867_getword_conf;
        _basename = php_rfc1867_basename;
    } else {
        getword = php_ap_getword;
        getword_conf = php_ap_getword_conf;
        _basename = php_ap_basename;
    }

    if (SG(post_max_size) > 0 && SG(request_info).content_length > SG(post_max_size)) {
        sapi_module.sapi_error(E_WARNING, "POST Content-Length of " ZEND_LONG_FMT " bytes exceeds the limit of " ZEND_LONG_FMT " bytes", SG(request_info).content_length, SG(post_max_size));
        return;
    }

    /* Get the boundary */
    boundary = strstr(content_type_dup, "boundary");
    if (!boundary) {
        int content_type_len = (int)strlen(content_type_dup);
        char *content_type_lcase = estrndup(content_type_dup, content_type_len);

        php_strtolower(content_type_lcase, content_type_len);
        boundary = strstr(content_type_lcase, "boundary");
        if (boundary) {
            boundary = content_type_dup + (boundary - content_type_lcase);
        }
        efree(content_type_lcase);
    }

    if (!boundary || !(boundary = strchr(boundary, '='))) {
        sapi_module.sapi_error(E_WARNING, "Missing boundary in multipart/form-data POST data");
        return;
    }

    boundary++;
    boundary_len = (int)strlen(boundary);

    if (boundary[0] == '"') {
        boundary++;
        boundary_end = strchr(boundary, '"');
        if (!boundary_end) {
            sapi_module.sapi_error(E_WARNING, "Invalid boundary in multipart/form-data POST data");
            return;
        }
    } else {
        /* search for the end of the boundary */
        boundary_end = strpbrk(boundary, ",;");
    }
    if (boundary_end) {
        boundary_end[0] = '\0';
        boundary_len = boundary_end-boundary;
    }

    /* Initialize the buffer */
    if (!(mbuff = multipart_buffer_new(boundary, boundary_len))) {
        sapi_module.sapi_error(E_WARNING, "Unable to initialize the input buffer");
        return;
    }

    /* Initialize $_FILES[] */
    zend_hash_init(&PG(rfc1867_protected_variables), 8, NULL, NULL, 0);

    ALLOC_HASHTABLE(uploaded_files);
    zend_hash_init(uploaded_files, 8, NULL, free_filename, 0);
    SG(rfc1867_uploaded_files) = uploaded_files;

    if (Z_TYPE(PG(http_globals)[TRACK_VARS_FILES]) != IS_ARRAY) {
        /* php_auto_globals_create_files() might have already done that */
        array_init(&PG(http_globals)[TRACK_VARS_FILES]);
    }

    zend_llist_init(&header, sizeof(mime_header_entry), (llist_dtor_func_t) php_free_hdr_entry, 0);

    if (php_rfc1867_callback != NULL) {
        multipart_event_start event_start;

        event_start.content_length = SG(request_info).content_length;
        if (php_rfc1867_callback(MULTIPART_EVENT_START, &event_start, &event_extra_data) == FAILURE) {
            goto fileupload_done;
        }
    }

    while (!multipart_buffer_eof(mbuff))
    {
        char buff[FILLUNIT];
        char *cd = NULL, *param = NULL, *filename = NULL, *tmp = NULL;
        size_t blen = 0, wlen = 0;
        zend_off_t offset;

        zend_llist_clean(&header);

        if (!multipart_buffer_headers(mbuff, &header)) {
            goto fileupload_done;
        }

        if ((cd = php_mime_get_hdr_value(header, "Content-Disposition"))) {
            char *pair = NULL;
            int end = 0;

            while (isspace(*cd)) {
                ++cd;
            }

            while (*cd && (pair = getword(mbuff->input_encoding, &cd, ';')))
            {
                char *key = NULL, *word = pair;

                while (isspace(*cd)) {
                    ++cd;
                }

                if (strchr(pair, '=')) {
                    key = getword(mbuff->input_encoding, &pair, '=');

                    if (!strcasecmp(key, "name")) {
                        if (param) {
                            efree(param);
                        }
                        param = getword_conf(mbuff->input_encoding, pair);
                        if (mbuff->input_encoding && internal_encoding) {
                            unsigned char *new_param;
                            size_t new_param_len;
                            if ((size_t)-1 != zend_multibyte_encoding_converter(&new_param, &new_param_len, (unsigned char *)param, strlen(param), internal_encoding, mbuff->input_encoding)) {
                                efree(param);
                                param = (char *)new_param;
                            }
                        }
                    } else if (!strcasecmp(key, "filename")) {
                        if (filename) {
                            efree(filename);
                        }
                        filename = getword_conf(mbuff->input_encoding, pair);
                        if (mbuff->input_encoding && internal_encoding) {
                            unsigned char *new_filename;
                            size_t new_filename_len;
                            if ((size_t)-1 != zend_multibyte_encoding_converter(&new_filename, &new_filename_len, (unsigned char *)filename, strlen(filename), internal_encoding, mbuff->input_encoding)) {
                                efree(filename);
                                filename = (char *)new_filename;
                            }
                        }
                    }
                }
                if (key) {
                    efree(key);
                }
                efree(word);
            }

            /* Normal form variable, safe to read all data into memory */
            if (!filename && param) {
                size_t value_len;
                char *value = multipart_buffer_read_body(mbuff, &value_len);
                size_t new_val_len; /* Dummy variable */

                if (!value) {
                    value = estrdup("");
                    value_len = 0;
                }

                if (mbuff->input_encoding && internal_encoding) {
                    unsigned char *new_value;
                    size_t new_value_len;
                    if ((size_t)-1 != zend_multibyte_encoding_converter(&new_value, &new_value_len, (unsigned char *)value, value_len, internal_encoding, mbuff->input_encoding)) {
                        efree(value);
                        value = (char *)new_value;
                        value_len = new_value_len;
                    }
                }

                if (++count <= PG(max_input_vars) && sapi_module.input_filter(PARSE_POST, param, &value, value_len, &new_val_len)) {
                    if (php_rfc1867_callback != NULL) {
                        multipart_event_formdata event_formdata;
                        size_t newlength = new_val_len;

                        event_formdata.post_bytes_processed = SG(read_post_bytes);
                        event_formdata.name = param;
                        event_formdata.value = &value;
                        event_formdata.length = new_val_len;
                        event_formdata.newlength = &newlength;
                        if (php_rfc1867_callback(MULTIPART_EVENT_FORMDATA, &event_formdata, &event_extra_data) == FAILURE) {
                            efree(param);
                            efree(value);
                            continue;
                        }
                        new_val_len = newlength;
                    }
                    safe_php_register_variable(param, value, new_val_len, array_ptr, 0);
                } else {
                    if (count == PG(max_input_vars) + 1) {
                        php_error_docref(NULL, E_WARNING, "Input variables exceeded " ZEND_LONG_FMT ". To increase the limit change max_input_vars in php.ini.", PG(max_input_vars));
                    }

                    if (php_rfc1867_callback != NULL) {
                        multipart_event_formdata event_formdata;

                        event_formdata.post_bytes_processed = SG(read_post_bytes);
                        event_formdata.name = param;
                        event_formdata.value = &value;
                        event_formdata.length = value_len;
                        event_formdata.newlength = NULL;
                        php_rfc1867_callback(MULTIPART_EVENT_FORMDATA, &event_formdata, &event_extra_data);
                    }
                }

                if (!strcasecmp(param, "MAX_FILE_SIZE")) {
                    max_file_size = strtoll(value, NULL, 10);
                }

                efree(param);
                efree(value);
                continue;
            }

            /* If file_uploads=off, skip the file part */
            if (!PG(file_uploads)) {
                skip_upload = 1;
            } else if (upload_cnt <= 0) {
                skip_upload = 1;
                sapi_module.sapi_error(E_WARNING, "Maximum number of allowable file uploads has been exceeded");
            }

            /* Return with an error if the posted data is garbled */
            if (!param && !filename) {
                sapi_module.sapi_error(E_WARNING, "File Upload Mime headers garbled");
                goto fileupload_done;
            }

            if (!param) {
                is_anonymous = 1;
                param = emalloc(MAX_SIZE_ANONNAME);
                snprintf(param, MAX_SIZE_ANONNAME, "%u", anonindex++);
            } else {
                is_anonymous = 0;
            }

            /* New Rule: never repair potential malicious user input */
            if (!skip_upload) {
                long c = 0;
                tmp = param;

                while (*tmp) {
                    if (*tmp == '[') {
                        c++;
                    } else if (*tmp == ']') {
                        c--;
                        if (tmp[1] && tmp[1] != '[') {
                            skip_upload = 1;
                            break;
                        }
                    }
                    if (c < 0) {
                        skip_upload = 1;
                        break;
                    }
                    tmp++;
                }
                /* Brackets should always be closed */
                if(c != 0) {
                    skip_upload = 1;
                }
            }

            total_bytes = cancel_upload = 0;
            temp_filename = NULL;
            fd = -1;

            if (!skip_upload && php_rfc1867_callback != NULL) {
                multipart_event_file_start event_file_start;

                event_file_start.post_bytes_processed = SG(read_post_bytes);
                event_file_start.name = param;
                event_file_start.filename = &filename;
                if (php_rfc1867_callback(MULTIPART_EVENT_FILE_START, &event_file_start, &event_extra_data) == FAILURE) {
                    temp_filename = NULL;
                    efree(param);
                    efree(filename);
                    continue;
                }
            }

            if (skip_upload) {
                efree(param);
                efree(filename);
                continue;
            }

            if (filename[0] == '\0') {
#if DEBUG_FILE_UPLOAD
                sapi_module.sapi_error(E_NOTICE, "No file uploaded");
#endif
                cancel_upload = UPLOAD_ERROR_D;
            }

            offset = 0;
            end = 0;

            if (!cancel_upload) {
                /* only bother to open temp file if we have data */
                blen = multipart_buffer_read(mbuff, buff, sizeof(buff), &end);
#if DEBUG_FILE_UPLOAD
                if (blen > 0) {
#else
                /* in non-debug mode we have no problem with 0-length files */
                {
#endif
                    fd = php_open_temporary_fd_ex(PG(upload_tmp_dir), "php", &temp_filename, PHP_TMP_FILE_OPEN_BASEDIR_CHECK_ON_FALLBACK);
                    upload_cnt--;
                    if (fd == -1) {
                        sapi_module.sapi_error(E_WARNING, "File upload error - unable to create a temporary file");
                        cancel_upload = UPLOAD_ERROR_E;
                    }
                }
            }

            while (!cancel_upload && (blen > 0))
            {
                if (php_rfc1867_callback != NULL) {
                    multipart_event_file_data event_file_data;

                    event_file_data.post_bytes_processed = SG(read_post_bytes);
                    event_file_data.offset = offset;
                    event_file_data.data = buff;
                    event_file_data.length = blen;
                    event_file_data.newlength = &blen;
                    if (php_rfc1867_callback(MULTIPART_EVENT_FILE_DATA, &event_file_data, &event_extra_data) == FAILURE) {
                        cancel_upload = UPLOAD_ERROR_X;
                        continue;
                    }
                }

                if (PG(upload_max_filesize) > 0 && (zend_long)(total_bytes+blen) > PG(upload_max_filesize)) {
#if DEBUG_FILE_UPLOAD
                    sapi_module.sapi_error(E_NOTICE, "upload_max_filesize of " ZEND_LONG_FMT " bytes exceeded - file [%s=%s] not saved", PG(upload_max_filesize), param, filename);
#endif
                    cancel_upload = UPLOAD_ERROR_A;
                } else if (max_file_size && ((zend_long)(total_bytes+blen) > max_file_size)) {
#if DEBUG_FILE_UPLOAD
                    sapi_module.sapi_error(E_NOTICE, "MAX_FILE_SIZE of %" PRId64 " bytes exceeded - file [%s=%s] not saved", max_file_size, param, filename);
#endif
                    cancel_upload = UPLOAD_ERROR_B;
                } else if (blen > 0) {
#ifdef PHP_WIN32
                    wlen = write(fd, buff, (unsigned int)blen);
#else
                    wlen = write(fd, buff, blen);
#endif

                    if (wlen == (size_t)-1) {
                        /* write failed */
#if DEBUG_FILE_UPLOAD
                        sapi_module.sapi_error(E_NOTICE, "write() failed - %s", strerror(errno));
#endif
                        cancel_upload = UPLOAD_ERROR_F;
                    } else if (wlen < blen) {
#if DEBUG_FILE_UPLOAD
                        sapi_module.sapi_error(E_NOTICE, "Only %zd bytes were written, expected to write %zd", wlen, blen);
#endif
                        cancel_upload = UPLOAD_ERROR_F;
                    } else {
                        total_bytes += wlen;
                    }
                    offset += wlen;
                }

                /* read data for next iteration */
                blen = multipart_buffer_read(mbuff, buff, sizeof(buff), &end);
            }

            if (fd != -1) { /* may not be initialized if file could not be created */
                close(fd);
            }

            if (!cancel_upload && !end) {
#if DEBUG_FILE_UPLOAD
                sapi_module.sapi_error(E_NOTICE, "Missing mime boundary at the end of the data for file %s", filename[0] != '\0' ? filename : "");
#endif
                cancel_upload = UPLOAD_ERROR_C;
            }
#if DEBUG_FILE_UPLOAD
            if (filename[0] != '\0' && total_bytes == 0 && !cancel_upload) {
                sapi_module.sapi_error(E_WARNING, "Uploaded file size 0 - file [%s=%s] not saved", param, filename);
                cancel_upload = 5;
            }
#endif
            if (php_rfc1867_callback != NULL) {
                multipart_event_file_end event_file_end;

                event_file_end.post_bytes_processed = SG(read_post_bytes);
                event_file_end.temp_filename = temp_filename ? ZSTR_VAL(temp_filename) : NULL;
                event_file_end.cancel_upload = cancel_upload;
                if (php_rfc1867_callback(MULTIPART_EVENT_FILE_END, &event_file_end, &event_extra_data) == FAILURE) {
                    cancel_upload = UPLOAD_ERROR_X;
                }
            }

            if (cancel_upload) {
                if (temp_filename) {
                    if (cancel_upload != UPLOAD_ERROR_E) { /* file creation failed */
                        unlink(ZSTR_VAL(temp_filename));
                    }
                    zend_string_release_ex(temp_filename, 0);
                }
                temp_filename = NULL;
            } else {
                zend_hash_add_ptr(SG(rfc1867_uploaded_files), temp_filename, temp_filename);
            }

            /* is_arr_upload is true when name of file upload field
             * ends in [.*]
             * start_arr is set to point to 1st [ */
            is_arr_upload = (start_arr = strchr(param,'[')) && (param[strlen(param)-1] == ']');

            if (is_arr_upload) {
                array_len = strlen(start_arr);
                if (array_index) {
                    efree(array_index);
                }
                array_index = estrndup(start_arr + 1, array_len - 2);
            }

            /* Add $foo_name */
            if (llen < strlen(param) + MAX_SIZE_OF_INDEX + 1) {
                llen = (int)strlen(param);
                lbuf = (char *) safe_erealloc(lbuf, llen, 1, MAX_SIZE_OF_INDEX + 1);
                llen += MAX_SIZE_OF_INDEX + 1;
            }

            if (is_arr_upload) {
                if (abuf) efree(abuf);
                abuf = estrndup(param, strlen(param)-array_len);
                snprintf(lbuf, llen, "%s_name[%s]", abuf, array_index);
            } else {
                snprintf(lbuf, llen, "%s_name", param);
            }

            /* Pursuant to RFC 7578, strip any path components in the
             * user-supplied file name:
             *  > If a "filename" parameter is supplied ... do not use
             *  > directory path information that may be present."
             */
            s = _basename(internal_encoding, filename);
            if (!s) {
                s = filename;
            }

            if (!is_anonymous) {
                safe_php_register_variable(lbuf, s, strlen(s), NULL, 0);
            }

            /* Add $foo[name] */
            if (is_arr_upload) {
                snprintf(lbuf, llen, "%s[name][%s]", abuf, array_index);
            } else {
                snprintf(lbuf, llen, "%s[name]", param);
            }
            register_http_post_files_variable(lbuf, s, &PG(http_globals)[TRACK_VARS_FILES], 0);
            efree(filename);
            s = NULL;

            /* Possible Content-Type: */
            if (cancel_upload || !(cd = php_mime_get_hdr_value(header, "Content-Type"))) {
                cd = "";
            } else {
                /* fix for Opera 6.01 */
                s = strchr(cd, ';');
                if (s != NULL) {
                    *s = '\0';
                }
            }

            /* Add $foo_type */
            if (is_arr_upload) {
                snprintf(lbuf, llen, "%s_type[%s]", abuf, array_index);
            } else {
                snprintf(lbuf, llen, "%s_type", param);
            }
            if (!is_anonymous) {
                safe_php_register_variable(lbuf, cd, strlen(cd), NULL, 0);
            }

            /* Add $foo[type] */
            if (is_arr_upload) {
                snprintf(lbuf, llen, "%s[type][%s]", abuf, array_index);
            } else {
                snprintf(lbuf, llen, "%s[type]", param);
            }
            register_http_post_files_variable(lbuf, cd, &PG(http_globals)[TRACK_VARS_FILES], 0);

            /* Restore Content-Type Header */
            if (s != NULL) {
                *s = ';';
            }
            s = "";

            {
                /* store temp_filename as-is (in case upload_tmp_dir
                 * contains escapable characters. escape only the variable name.) */
                zval zfilename;

                /* Initialize variables */
                add_protected_variable(param);

                /* if param is of form xxx[.*] this will cut it to xxx */
                if (!is_anonymous) {
                    if (temp_filename) {
                        ZVAL_STR_COPY(&zfilename, temp_filename);
                    } else {
                        ZVAL_EMPTY_STRING(&zfilename);
                    }
                    safe_php_register_variable_ex(param, &zfilename, NULL, 1);
                }

                /* Add $foo[tmp_name] */
                if (is_arr_upload) {
                    snprintf(lbuf, llen, "%s[tmp_name][%s]", abuf, array_index);
                } else {
                    snprintf(lbuf, llen, "%s[tmp_name]", param);
                }
                add_protected_variable(lbuf);
                if (temp_filename) {
                    ZVAL_STR_COPY(&zfilename, temp_filename);
                } else {
                    ZVAL_EMPTY_STRING(&zfilename);
                }
                register_http_post_files_variable_ex(lbuf, &zfilename, &PG(http_globals)[TRACK_VARS_FILES], 1);
            }

            {
                zval file_size, error_type;
                int size_overflow = 0;
                char file_size_buf[65];

                ZVAL_LONG(&error_type, cancel_upload);

                /* Add $foo[error] */
                if (cancel_upload) {
                    ZVAL_LONG(&file_size, 0);
                } else {
                    if (total_bytes > ZEND_LONG_MAX) {
#ifdef PHP_WIN32
                        if (_i64toa_s(total_bytes, file_size_buf, 65, 10)) {
                            file_size_buf[0] = '0';
                            file_size_buf[1] = '\0';
                        }
#else
                        {
                            int __len = snprintf(file_size_buf, 65, "%" PRId64, total_bytes);
                            file_size_buf[__len] = '\0';
                        }
#endif
                        size_overflow = 1;

                    } else {
                        ZVAL_LONG(&file_size, total_bytes);
                    }
                }

                if (is_arr_upload) {
                    snprintf(lbuf, llen, "%s[error][%s]", abuf, array_index);
                } else {
                    snprintf(lbuf, llen, "%s[error]", param);
                }
                register_http_post_files_variable_ex(lbuf, &error_type, &PG(http_globals)[TRACK_VARS_FILES], 0);

                /* Add $foo_size */
                if (is_arr_upload) {
                    snprintf(lbuf, llen, "%s_size[%s]", abuf, array_index);
                } else {
                    snprintf(lbuf, llen, "%s_size", param);
                }
                if (!is_anonymous) {
                    if (size_overflow) {
                        ZVAL_STRING(&file_size, file_size_buf);
                    }
                    safe_php_register_variable_ex(lbuf, &file_size, NULL, size_overflow);
                }

                /* Add $foo[size] */
                if (is_arr_upload) {
                    snprintf(lbuf, llen, "%s[size][%s]", abuf, array_index);
                } else {
                    snprintf(lbuf, llen, "%s[size]", param);
                }
                if (size_overflow) {
                    ZVAL_STRING(&file_size, file_size_buf);
                }
                register_http_post_files_variable_ex(lbuf, &file_size, &PG(http_globals)[TRACK_VARS_FILES], size_overflow);
            }
            efree(param);
        }
    }

fileupload_done:
    if (php_rfc1867_callback != NULL) {
        multipart_event_end event_end;

        event_end.post_bytes_processed = SG(read_post_bytes);
        php_rfc1867_callback(MULTIPART_EVENT_END, &event_end, &event_extra_data);
    }

    if (lbuf) efree(lbuf);
    if (abuf) efree(abuf);
    if (array_index) efree(array_index);
    zend_hash_destroy(&PG(rfc1867_protected_variables));
    zend_llist_destroy(&header);
    if (mbuff->boundary_next) efree(mbuff->boundary_next);
    if (mbuff->boundary) efree(mbuff->boundary);
    if (mbuff->buffer) efree(mbuff->buffer);
    if (mbuff) efree(mbuff);
}
/* }}} */
```

代码的逻辑首先是获取boundary

然后进入!multipart\_buffer\_eof(mbuff) 循环

解析头multipart\_buffer\_headers

```c++
    if ((cd = php_mime_get_hdr_value(header, "Content-Disposition"))) {
            char *pair = NULL;
            int end = 0;

            while (isspace(*cd)) {
                ++cd;
            }

            // 最终调用的是php_ap_getword 函数 
            while (*cd && (pair = getword(mbuff->input_encoding, &cd, ';')))
            {
                // pair =
                char *key = NULL, *word = pair;

                while (isspace(*cd)) {
                    ++cd;
                }

                if (strchr(pair, '=')) {
                    key = getword(mbuff->input_encoding, &pair, '=');

                    if (!strcasecmp(key, "name")) {
                        if (param) {
                            efree(param);
                        }
                        param = getword_conf(mbuff->input_encoding, pair);
                        if (mbuff->input_encoding && internal_encoding) {
                            unsigned char *new_param;
                            size_t new_param_len;
                            if ((size_t)-1 != zend_multibyte_encoding_converter(&new_param, &new_param_len, (unsigned char *)param, strlen(param), internal_encoding, mbuff->input_encoding)) {
                                efree(param);
                                param = (char *)new_param;
                            }
                        }
                    } else if (!strcasecmp(key, "filename")) {
                        if (filename) {
                            efree(filename);
                        }
                        filename = getword_conf(mbuff->input_encoding, pair);
                        if (mbuff->input_encoding && internal_encoding) {
                            unsigned char *new_filename;
                            size_t new_filename_len;
                            if ((size_t)-1 != zend_multibyte_encoding_converter(&new_filename, &new_filename_len, (unsigned char *)filename, strlen(filename), internal_encoding, mbuff->input_encoding)) {
                                efree(filename);
                                filename = (char *)new_filename;
                            }
                        }
                    }
                }
                if (key) {
                    efree(key);
                }
                efree(word);
            }
```

关键点在于getword。追踪一下getword 函数

```php
    php_rfc1867_getword_t getword;
    php_rfc1867_getword_conf_t getword_conf;
    php_rfc1867_basename_t _basename;
    zend_long count = 0;

    if (php_rfc1867_encoding_translation() && internal_encoding) {
        getword = php_rfc1867_getword;
        getword_conf = php_rfc1867_getword_conf;
        _basename = php_rfc1867_basename;
    } else {
        getword = php_ap_getword;
        getword_conf = php_ap_getword_conf;
        _basename = php_ap_basename;
    }
```

最终最终到php\_ap\_getword

```php
static char *php_ap_getword(const zend_encoding *encoding, char **line, char stop)
{
    char *pos = *line, quote;
    char *res;

    while (*pos && *pos != stop) {
        if ((quote = *pos) == '"' || quote == '\'') {
            ++pos;
            while (*pos && *pos != quote) {
                if (*pos == '\\' && pos[1] && pos[1] == quote) {
                    pos += 2;
                } else {
                    ++pos;
                }
            }
            if (*pos) {
                ++pos;
            }
        } else ++pos;
    }
    if (*pos == '\0') {
        res = estrdup(*line);
        *line += strlen(*line);
        return res;
    }

    res = estrndup(*line, pos - *line);

    while (*pos == stop) {
        ++pos;
    }

    *line = pos;
    return res;
}
```

发现这里是跳过了。\\ 那么就从最开始的如下

`Content-Disposition: form-data; name="name\"; filename=";name='username'"`

获取到了Content-Disposition 之后的数据。然后以; 结尾的数据取出来。然后再通过name filename 这样的key进行存入到结构体中。

当\\ 出现之后。

那么name 获取的value 的值为

name=”name\\”; filename=”;

name=’username’

最终PHP 获取得到的为$\_POST 中的数据值 username=&gt;admin

如果哪里写的不对。请斧正

文章首发在自己博客，原文地址为：<https://www.o2oxy.cn/3239.html>