0x00 前言：
========

在cs上线后，需要查询当前主机是否存在安全软件，虽然有在线等方式可以查询，但是还是一键梭比较方便。

cs自己造轮子，从编写exe到编写cs插件

0x01：实现
=======

c#编写可执行文件
---------

实现方法：args参数接收输入字符，通过判断输入参数调用哪个函数

```php
   class Program
    {
        static void Main(string[] args)
        {

            System.Console.WriteLine("");
            System.Console.WriteLine("Author: 西米");
            System.Console.WriteLine("Github: https://gitee.com/git63/cobalt-strike-plug-in-unit.git");
            System.Console.WriteLine("");

            if (args.Length != 1)
            {

                System.Console.WriteLine("ximi_cs -autoSafety");

            }
            if (args.Length == 1 && (args[0] == "-autoSafety"))
            {
                Console.WriteLine("");
                Console.WriteLine("---------------------安全软件进程识别----------------------");
                Console.WriteLine("");
                av_nameCheck();
            }
            Console.ReadKey();
        }

        //安全进程识别
        private static void av_nameCheck()
        {
            av_name pavname = new av_name();
            Dictionary<string, string> av_dicnName2 = pavname.dicavname();

            Process[] procs = Process.GetProcesses(Environment.MachineName);

            Console.WriteLine("=====================存在安全进程====（Security software processes exist）=================");
            for (int i = 0; i < procs.Length; i++)
            {
                string processname = procs[i].ProcessName;
                foreach (var key in av_dicnName2.Keys)
                {                  
                    if (processname.Equals(key))
                    {
                        Console.WriteLine(key + ":" + av_dicnName2[key]);
                    }
                }
            }
            Console.WriteLine("=====================END=====================");

        }
    }
```

cs插件编写
------

- 直接用cna脚本当中的[bshell](https://www.cobaltstrike.com/aggressor-script/functions.html#bshell)、[bpowerpick](https://www.cobaltstrike.com/aggressor-script/functions.html#bpowerpick)等函数，直接执行命令行指令
- 将功能写成Reflective dll的形式，用[bdllspawn](https://www.cobaltstrike.com/aggressor-script/functions.html#bdllspawn)加载
- 将功能写成普通dll的形式，用[bdllinject](https://www.cobaltstrike.com/aggressor-script/functions.html#bdllinject)或者[bdllload](https://www.cobaltstrike.com/aggressor-script/functions.html#bdllload)加载
- 将功能用.NET写，然后用[bexecute\_assembly](https://www.cobaltstrike.com/aggressor-script/functions.html#bexecute_assembly)将其在内存当中执行
- 将功能直接写成exe的格式，然后用[bupload](https://www.cobaltstrike.com/aggressor-script/functions.html#bupload)上传用[bexecute](https://www.cobaltstrike.com/aggressor-script/functions.html#bexecute)执行
- 

1、main.can文件是目录结构

2、信息收集.can是调用安全进程识别的

[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-8c80b1b6b3deed9c603adc89fc9385d692712fbf.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-8c80b1b6b3deed9c603adc89fc9385d692712fbf.png)

0x03效果图：
========

系统因为，中文有点乱码的bug  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-c2cde82b983a7b5a153082c07960ea18b7f214bf.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-c2cde82b983a7b5a153082c07960ea18b7f214bf.png)

目前支持的：
------

```php
//进程名称   名称
            av_dicnName.Add("ZhuDongFangYu", "360主动防御");
            av_dicnName.Add("360tray", "360安全卫士");
            av_dicnName.Add("360sd", "360杀毒");
            av_dicnName.Add("a2guard", "a-squared杀毒");
            av_dicnName.Add("ad-watch", "Lavasoft杀毒");
            av_dicnName.Add("cleaner8", "The Cleaner杀毒");
            av_dicnName.Add("vba32lder", "vb32杀毒");
            av_dicnName.Add("MongoosaGUI", "Mongoosa杀毒");
            av_dicnName.Add("CorantiControlCenter32", "Coranti2012杀毒");
            av_dicnName.Add("F-PROT", "F-PROT杀毒");
            av_dicnName.Add("CMCTrayIcon", "CMC杀毒");
            av_dicnName.Add("K7TSecurity", "K7杀毒");
            av_dicnName.Add("UnThreat", "UnThreat杀毒");
            av_dicnName.Add("CKSoftShiedAntivirus4", "Shield Antivirus杀毒");
            av_dicnName.Add("AVWatchService", "VIRUSfighter杀毒");
            av_dicnName.Add("ArcaTasksService", "ArcaVir杀毒");
            av_dicnName.Add("iptray", "Immunet杀毒");
            av_dicnName.Add("PSafeSysTray", "PSafe杀毒");
            av_dicnName.Add("nspupsvc", "nProtect杀毒");
            av_dicnName.Add("SpywareTerminatorShield", "SpywareTerminator杀毒");
            av_dicnName.Add("BKavService", "Bkav杀毒");
            av_dicnName.Add("MsMpEng", "Microsoft Security Essentials");
            av_dicnName.Add("SBAMSvc", "VIPRE");
            av_dicnName.Add("ccSvcHst", "Norton杀毒");
            av_dicnName.Add("QQ", "QQ");
            av_dicnName.Add("f-secure", "冰岛");
            av_dicnName.Add("avp", "卡巴斯基");
            av_dicnName.Add("KvMonXP", "江民杀毒");
            av_dicnName.Add("RavMonD", "瑞星杀毒");
            av_dicnName.Add("Mcshield", "麦咖啡");
            av_dicnName.Add("egui", "NOD32");
            av_dicnName.Add("kxetray", "金山毒霸");
            av_dicnName.Add("knsdtray", "可牛杀毒");
            av_dicnName.Add("TMBMSRV", "趋势杀毒");
            av_dicnName.Add("avcenter", "Avira(小红伞)");
            av_dicnName.Add("ashDisp", "Avast网络安全");
            av_dicnName.Add("rtvscan", "诺顿杀毒");
            av_dicnName.Add("ksafe", "金山卫士");
            av_dicnName.Add("QQPCRTP", "QQ电脑管家");
            av_dicnName.Add("Miner", "流量矿石");
            av_dicnName.Add("AYAgent.aye", "韩国胶囊");
            av_dicnName.Add("patray", "安博士");
            av_dicnName.Add("V3Svc", "安博士V3");
            av_dicnName.Add("avgwdsvc", "AVG杀毒");
            av_dicnName.Add("ccSetMgr", "赛门铁克");
            av_dicnName.Add("QUHLPSVC", "QUICK HEAL杀毒");
            av_dicnName.Add("mssecess", "微软杀毒");
            av_dicnName.Add("SavProgress", "Sophos杀毒");
            av_dicnName.Add("fsavgui", "F-Secure杀毒");
            av_dicnName.Add("vsserv", "比特梵德");
            av_dicnName.Add("remupd", "熊猫卫士");
            av_dicnName.Add("FortiTray", "飞塔");
            av_dicnName.Add("safedog", "安全狗");
            av_dicnName.Add("parmor", "木马克星");
            av_dicnName.Add("beikesan", "贝壳云安全");
            av_dicnName.Add("KSWebShield", "金山网盾");
            av_dicnName.Add("TrojanHunter", "木马猎手");
            av_dicnName.Add("GG", "巨盾网游安全盾");
            av_dicnName.Add("adam", "绿鹰安全精灵");
            av_dicnName.Add("AST", "超级巡警");
            av_dicnName.Add("ananwidget", "墨者安全专家");
            av_dicnName.Add("AVK", "GData");
            av_dicnName.Add("ccapp", "Symantec Norton");
            av_dicnName.Add("avg", "AVG Anti-Virus");
            av_dicnName.Add("spidernt", "Dr.web");
            av_dicnName.Add("avgaurd", "Avira Antivir");     
            av_dicnName.Add("vsmon", "ZoneAlarm");
            av_dicnName.Add("avpe", "Kaspersky");
            av_dicnName.Add("cpf", "Comodo");
            av_dicnName.Add("outpost", "Outpost Firewall");
            av_dicnName.Add("rfwmain", "瑞星防火墙");
            av_dicnName.Add("kpfwtray", "金山网镖");
            av_dicnName.Add("FYFireWall", "风云防火墙");
            av_dicnName.Add("MPMon", "微点主动防御");
            av_dicnName.Add("pfw", "天网防火墙");
            av_dicnName.Add("S", "在抓鸡");
            av_dicnName.Add("1433", "在扫1433");
            av_dicnName.Add("DUB", "在爆破");
            av_dicnName.Add("ServUDaemon", "发现S-U");
            av_dicnName.Add("BaiduSdSvc", "百度杀软");
            av_dicnName.Add("SafeDogGuardCenter", "安全狗");
            av_dicnName.Add("safedogupdatecenter", "安全狗");
            av_dicnName.Add("safedogguardcenter", "安全狗");
            av_dicnName.Add("SafeDogSiteIIS", "安全狗");
            av_dicnName.Add("SafeDogTray", "安全狗");
            av_dicnName.Add("SafeDogServerUI", "安全狗");
            av_dicnName.Add("D_Safe_Manage", "D盾");
            av_dicnName.Add("d_manage", "D盾");
            av_dicnName.Add("yunsuo_agent_service", "云锁");
            av_dicnName.Add("yunsuo_agent_daemon", "云锁");
            av_dicnName.Add("HwsPanel", "护卫神·入侵防护系统（状态托盘）");
            av_dicnName.Add("hws_ui", "护卫神·入侵防护系统 - www.huweishen.com");
            av_dicnName.Add("hws", "护卫神·入侵防护系统 服务处理程序");
            av_dicnName.Add("hwsd", "护卫神·入侵防护系统 监控组件");
            av_dicnName.Add("hipstray", "火绒");
            av_dicnName.Add("wsctrl", "火绒");
            av_dicnName.Add("usysdiag", "火绒");
```

插件下载地址：
=======

<https://gitee.com/git63/cobalt-strike-plug-in-unit.git>