![darkangel.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-c6410dbea045e708c42aac9ce7552bcccbf32570.png)

- - - - - -

DarkAngel 是一款全自动白帽漏洞扫描器，从hackerone、bugcrowd资产监听到漏洞报告生成、企业微信通知。

DarkAngel 下载地址：[github.com/Bywalks/DarkAngel](https://github.com/Bywalks/DarkAngel)

当前已支持的功能：

- hackerone资产监听；
- bugcrowd资产监听；
- 自定义资产添加；
- 子域名扫描；
- 网站指纹识别；
- 漏洞扫描；
- 漏洞报告自动生成；
- 企业微信通知扫描结果；
- 前端显示扫描结果；

自动生成漏洞报告
--------

自动生成漏洞报告 - MarkDown格式 - 存放地址/root/darkangel/vulscan/results/report

![report.jpg](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-9b33151d69e4926bfbcbdb8eff5a4c4b9c78bf8a.jpg)

支持自添加漏洞报告模板，目前已添加漏洞报告模板如下，漏洞名配置为nuclei模板文件名即可

![report_template1.jpg](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-60f1a67680adb245dea798c015cb07188a479776.jpg)

自定义漏洞报告模板格式

![report_template2.jpg](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-d1f8da21c0d28c855e1128608b09d73a16caec9a.jpg)

企业微信通知
------

可先查看如何获取配置：[企业微信开发接口文档](https://developer.work.weixin.qq.com/document/path/90487)

获取参数后，在/root/darkangel/vconfig/config.ini中配置参数，即可启用企业微信通知

微信通知 - 漏洞结果

![result_vx2.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-e7c5764d69192cf4de7ac203bebc7361938d228e.png)

微信通知 - 扫描进程

![result_vx1.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-ba9475603a4372889d550955629af04bf89bc8c8.png)

安装
--

整体项目架构ES+Kibana+扫描器，所以安装需要三个部分

ES镜像：

```php
拉取ES镜像
docker pull bywalkss/darkangel:es7.9.3

部署ES镜像
docker run -e ES_JAVA_OPTS="-Xms1024m -Xms1024m" -d -p 9200:9200 -p 9300:9300 --name elasticsearch elasticsearch:7.9.3

查看日志
docker logs -f elasticsearch

出现问题，执行命令
sysctl -w vm.max_map_count=262144

重启docker
docker start elasticsearch
```

Kibana镜像：

```php
拉取Kibana镜像
docker pull bywalkss/darkangel:kibana7.9.3

部署Kibana镜像（修改一下es-ip）
docker run --name kibana -e ELASTICSEARCH_URL=http://es-ip:9200 -p 5601:5601 -d docker.io/bywalkss/darkangel:kibana7.9.3

查看日志
docker logs -f elasticsearch

出现问题，执行命令
sysctl -w vm.max_map_count=262144

重启docker
docker start elasticsearch
```

扫描器镜像：

```php
拉取扫描器镜像
docker pull bywalkss/darkangel:v2

部署扫描器
docker run -it -d -v /root/darkangel:/root/darkangel --name darkangel bywalkss/darkangel:v2

进入扫描器docker
docker exec -it /bin/bash docker_id

复制源代码
cp -r /root/DarkAngel/* /root/darkangel/
```

docker容器内挂载目录无权限  
运行容器时：--privileged=true

用法
--

```php
usage:  [-h] [--scan-new-domain]
        [--add-domain-and-scan ADD_DOMAIN_AND_SCAN [ADD_DOMAIN_AND_SCAN ...]]
        [--offer-bounty {yes,no}] [--nuclei-file-scan]
        [--nuclei-file-scan-by-new-temp NUCLEI_FILE_SCAN_BY_NEW_TEMP]
        [--nuclei-file-scan-by-new-add-temp NUCLEI_FILE_SCAN_BY_NEW_ADD_TEMP]
        [--nuclei-file-scan-by-temp-name NUCLEI_FILE_SCAN_BY_TEMP_NAME]
        [--nuclei-file-polling-scan] [--delete]

DarkAngel is a white hat scanner. Every user makes the Internet more secure.

--------------------------------------------------------------------------------

optional arguments:
  -h, --help            show this help message and exit
  --scan-new-domain     scan new domain from h1 and bc
  --add-domain-and-scan ADD_DOMAIN_AND_SCAN [ADD_DOMAIN_AND_SCAN ...]
                        scan new domain from h1 and bc
  --offer-bounty {yes,no}
                        set add domain is bounty or no bounty
  --nuclei-file-scan    scan new domain from h1 and bc
  --nuclei-file-scan-by-new-temp NUCLEI_FILE_SCAN_BY_NEW_TEMP
                        use new template scan five file by nuclei
  --nuclei-file-scan-by-new-add-temp NUCLEI_FILE_SCAN_BY_NEW_ADD_TEMP
                        add new template scan five file by nuclei
  --nuclei-file-scan-by-temp-name NUCLEI_FILE_SCAN_BY_TEMP_NAME
                        use template scan five file by nuclei
  --nuclei-file-polling-scan
                        five file polling scan by nuclei
```

### --scan-new-domain

`$ python3 darkangel.py --scan-new-domain`

- 监听hackerone和bugcrowd域名并进行扫描（第一次使用时会把hackerone和bugcrowd域名全部添加进去，资产过多的情况下做好准备，扫描时间很长）

![scan-new-domain.jpg](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-872a79e7bfdd76388bbae6ec18a62b6fe460d966.jpg)

### --add-domain-and-scan

`$ python3 darkangel.py --add-domain-and-scan program-file-name1 program-file-name2 --offer-bounty yes/no`

- 自定义添加扫描域名，并对这些域名进行漏洞扫描
- 文件名为厂商名称，文件内存放需扫描域名
- 需提供--offer-bounty参数，设置域名是否提供赏金

![add_domain_and_scan1.jpg](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-8d6205fdd1f4ceb8633c0befd5d105508a7e6887.jpg)

![add_domain_and_scan2.jpg](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-43e9c2fea1aa1f74932337652e12a2dc14f9d988.jpg)

扫描结束后，会把子域名结果存在在/root/darkangel/vulscan/results/urls目录，按照是否提供赏金分别存放在，bounty\_temp\_urls\_output.txt、nobounty\_temp\_urls\_output.txt文件内

### --nuclei-file-scan

`$ python3 darkangel.py --nuclei-file-scan`

- 用nuclei扫描20个url文件

![nuclei-file-scan2.jpg](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-516291f167f78083577cc63e6bb82f538016196d.jpg)

url列表存放位置

![nuclei-file-scan1.jpg](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-cf695dff460effa9cddf86a0a5a6e9bd3295cd63.jpg)

### --nuclei-file-polling-scan

`$ python3 darkangel.py --nuclei-file-polling-scan`

- 轮询用nuclei扫描20个url文件，可把该进程放在后台，轮询扫描，监听是否url列表是否存在新漏洞出现

### --nuclei-file-scan-by-new-temp

`$ python3 darkangel.py --nuclei-file-scan-by-new-temp nuclei-template-version`

- 监听nuclei-template更新，当更新时，对url列表进行扫描

当前nuclei-template版本为9.3.1

![nuclei_file_scan_by_new_temp1.jpg](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-b5d46c8c71fc09a8539abc8c65d091fac6b133ca.jpg)

执行命令，监听9.3.2版本更新

![nuclei_file_scan_by_new_temp2.jpg](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-a650eda4d69a53979a4847173bdac6b1f3465a30.jpg)

企业微信通知

![nuclei_file_scan_by_new_temp3.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-fd915b226db5db53418c55f3d596af727d1c72bc.png)

url列表存放位置

![nuclei-file-scan1.jpg](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-6c56eaf52c0da369cd8a992d63833e2d925cb144.jpg)

### --nuclei-file-scan-by-new-add-temp

`$ python3 darkangel.py --nuclei-file-scan-by-new-add-temp nuclei-template-id`

- 监听nuclei单template更新，当更新时，用该template对url列表进行扫描，这里是打了个时间差，某些时候先提交tempalte，验证后才会加入nuclei模板，在还未加入时，我们已经监听并进行扫描，扫描后id会自动增加，监听并进行扫描

查看nuclei单template的id，这里为6296

![nuclei_file_scan_by_new_add_temp1.jpg](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-1fee556e18c010eba615e12153d4023739739e4e.jpg)

执行命令，对该template进行扫描

![nuclei_file_scan_by_new_add_temp2.jpg](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-46d929e6cc9b356716660c64b3f8f4ef1d4a37b7.jpg)

url列表存放位置

![nuclei-file-scan1.jpg](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-421c908f4333ae8f89f6b78fbc7cb8c6133052a7.jpg)

### --nuclei-file-scan-by-temp-name

`$ python3 darkangel.py --nuclei-file-scan-by-temp-name nuclei-template-name`

- 用单template对url列表进行扫描

![nuclei_file_scan_by_temp.jpg](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-6eae38021c27aac9952022dd1babbbce51bb1adc.jpg)

结果显示
----

前端 - 扫描厂商

![result_kibana_program.jpg](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-7031496494ad242056e53c30cc0e1d95d50fb7b0.jpg)

前端 - 扫描域名

![result_kibana_domain.jpg](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-d869cd61ce7bc35257f0e599f1512821c8dfe642.jpg)

前端 - 扫描结果

![result_kibana_vuln.jpg](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-d7b5d38fe649748b3e1439e516e4e171ea29d3bf.jpg)

微信通知 - 扫描进程

![result_vx1.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-6c12636dccb32c241bcca14ed28c07ec9b232cb2.png)

微信通知 - 漏洞结果

![result_vx2.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-62f1debaf776fc1664b9f260ae330a3b103cbec9.png)

注意事项
----

- 本工具仅用于合法合规用途，严禁用于违法违规用途。