标准控件
====

前言
--

Windows标准控件,标准控件总是可用的

具体有
---

```php
Static          
Group Box           
Button          
Check Box           
Radio Button            
Edit            
ComboBox            
ListBox
```

通用控件
====

前言
--

Windows通用控件,代码包含在`Comctrl32.dll`

具体有
---

```php
Animation       
ComboBoxEx      
Date_and_Time_Picker        
Drag_List_Box       
Flat_Scroll_Bar         
Header      
HotKey      
ImageList       
IPAddress       
List_View       
Month_Calendar      
Pager       
Progress_Bar        
Property_Sheets         
Rebar       
Status Bars         
SysLink         
Tab         
Toolbar         
ToolTip         
Trackbar        
TreeView        
Up_and_Down
```

使用
--

画两个通用控件，进行简单排版

![image-20220305195104512](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-069b9e36c86ec1c2389d2e0fa29db962bcfe0261.png)

修改ID

```php
IDC_LIST_PROCESS
IDC_LIST_MOUDLE
```

修改输出为报表形式

![image-20220305195211216](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-0dc368a60ba2ee49393621b56b7f67818e5a9192.png)

代码中，还需要添加代码，进行加载DLL

```php
#include <commctrl.h>
#pragma comment(lib,"comctl32.lib")
```

通用控件在使用前，需要通过INITCOMMONCONTROLSEX进行初始化

只要在您的程序中的任意地方引用了该函数就、会使得WINDOWS的程序加载器PE Loader加载该库

```php
INITCOMMONCONTROLSEX icex;
icex.dwSize = sizeof(INITCOMMONCONTROLSEX);     
icex.dwICC = ICC_WIN95_CLASSES;     
InitCommonControlsEx(&icex);
```

我们可以去MSDN看一下`INITCOMMONCONTROLSEX`这个函数

![image-20220305195836505](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-850beec1ee862c5619748a512f779ea3f88bb65c.png)

```php
typedef struct tagINITCOMMONCONTROLSEX {
    DWORD dwSize; //当前结构的大小
    DWORD dwICC; //通用控件名
} INITCOMMONCONTROLSEX, *LPINITCOMMONCONTROLSEX;
```

![image-20220305200045070](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-73c688e18cbc8694b626652b97e6f76ae8b70c38.png)

![image-20220305200141364](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-7f41b2150e93784f53471f06f485589f34a33d72.png)

初始化列名信息

```php
//设置ProcessListView风格
VOID InitProcessListView(HWND hDlg)
{
    LV_COLUMN lv;
    HWND hListProcess;

    //初始化
    memset(&lv,0,sizeof(LV_COLUMN));
    //获取IDC_LIST_PROCESS句柄
    hListProcess = GetDlgItem(hDlg,IDC_LIST_PROCESS);
    //设置整行选中
    SendMessage(hListProcess,LVM_SETEXTENDEDLISTVIEWSTYLE,LVS_EX_FULLROWSELECT,LVS_EX_FULLROWSELECT);

    //第一列
    lv.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
    lv.pszText = TEXT("进程"); //列标题
    lv.cx = 150; //列宽
    lv.iSubItem = 0; //表示第1列
    //ListView_InsertColumn(hListProcess, 0, &lv);
    SendMessage(hListProcess,LVM_INSERTCOLUMN,0,(DWORD)&lv);

    //第二列
    lv.pszText = TEXT("PID");
    lv.cx = 90;
    lv.iSubItem = 1; //表示第2列
    //ListView_InsertColumn(hListProcess, 1, &lv);
    SendMessage(hListProcess,LVM_INSERTCOLUMN,1,(DWORD)&lv);

    //第三列
    lv.pszText = TEXT("镜像基址");
    lv.cx = 90;
    lv.iSubItem = 2; //表示第3列
    ListView_InsertColumn(hListProcess, 2, &lv);

    //第四列
    lv.pszText = TEXT("镜像大小");
    lv.cx = 90;
    lv.iSubItem = 3;
    ListView_InsertColumn(hListProcess, 3, &lv);
}

消息:
//主窗口初始化
case WM_INITDIALOG:
    {
        InitProcessListView(hDlg);
    }
```

![image-20220305202040656](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-2edbb4468f67554eb6f19609a70608a15c4b8a6a.png)

向进程窗口中新增数据

```php
//向进程窗口中新增数据函数
VOID EnumProcess(HWND hListProcess)
{
    //描述成员和元素
    LV_ITEM vitem;

    //初始化
    memset(&vitem,0,sizeof(LV_ITEM));
    vitem.mask = LVIF_TEXT; //存储的是文本

    vitem.pszText = "csrss.exe"; //第一个成员
    vitem.iItem = 0; //第1行
    vitem.iSubItem = 0; //第1列
    //ListView_InsertItem(hListProcess, &vitem); ListView_InsertItem是一个宏 == SendMessage
    //只有第一列是:LVM_INSERTITEM，后面的都是LVM_SETITEM
    SendMessage(hListProcess, LVM_INSERTITEM,0,(DWORD)&vitem);

    vitem.pszText = TEXT("448");
    vitem.iItem = 0;
    vitem.iSubItem = 1;
    ListView_SetItem(hListProcess, &vitem);

    vitem.pszText = TEXT("56590000");
    vitem.iItem = 0;
    vitem.iSubItem = 2;
    ListView_SetItem(hListProcess, &vitem);

    vitem.pszText = TEXT("000F0000");
    vitem.iItem = 0;
    vitem.iSubItem = 3;
    ListView_SetItem(hListProcess, &vitem);

    vitem.pszText = TEXT("winlogon.exe");
    vitem.iItem = 1;
    vitem.iSubItem = 0;
    //ListView_InsertItem(hListProcess, &vitem);
    SendMessage(hListProcess, LVM_INSERTITEM,0,(DWORD)&vitem);

    vitem.pszText = TEXT("456");
    vitem.iSubItem = 1;
    ListView_SetItem(hListProcess, &vitem);

    vitem.pszText = TEXT("10000000");
    vitem.iSubItem = 2;
    ListView_SetItem(hListProcess, &vitem);

    vitem.pszText = TEXT("000045800");
    vitem.iSubItem = 3;
    ListView_SetItem(hListProcess, &vitem);
}
```

![image-20220305201957799](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-51b76b6ca69e10474349f4bf58852a7a788f327d.png)

```php
//设置ModulesListView风格
VOID InitModulesListView(HWND hwndDlg)
{
    LV_COLUMN lv;
    HWND hListModules;

    //初始化
    memset(&lv, 0, sizeof(LV_COLUMN));

    //获取IDC_LIST_MODULE句柄
    hListModules = GetDlgItem(hwndDlg, IDC_LIST_MODULE);

    //设置整行选中
    SendMessage(hListModules,LVM_SETEXTENDEDLISTVIEWSTYLE, LVS_EX_FULLROWSELECT,LVS_EX_FULLROWSELECT);

    //第一列
    lv.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
    lv.pszText = TEXT("模块名称");  //列标题
    lv.cx = 200;                //列宽
    lv.iSubItem = 0;
    // ListView_InsertColumn(hListModules, 0, &lv);

    SendMessage(hListModules,LVM_INSERTCOLUMN,0,(DWORD)&lv);

    //第二列
    lv.pszText = TEXT("模块位置");
    lv.cx = 200;
    lv.iSubItem = 1;
    // ListView_InsertColumn(hListModules, 1, &lv);

    SendMessage(hListModules,LVM_INSERTCOLUMN,1,(DWORD)&lv);
}

消息:
//主窗口初始化
case WM_INITDIALOG:
    {
        InitProcessListView(hDlg);
        InitModulesListView(hDlg);
    }
```

向模块新增数据

```php
//向模块新增数据
VOID EnumModules(HWND hListProcess, WPARAM wParam, LPARAM lParam)
{
    DWORD dwRowId;
    TCHAR szPid[0x20];
    LV_ITEM lv;

    //初始化
    memset(&lv, 0, sizeof(LV_ITEM));
    memset(szPid, 0, 0x20);

    //获取选择行
    //点第一行:dwRowId == 0
    //点第二行:dwRowId == 1
    dwRowId = SendMessage(hListProcess, LVM_GETNEXTITEM, -1, LVNI_SELECTED);
    if (dwRowId == -1)
    {
        MessageBox(NULL, TEXT("请选择进程"), TEXT("出错咯"), MB_OK);
        return;
    }
    //想要遍历进程的模块，要拿到进程的PID
    //获取PID
    lv.iSubItem = 1;                    //要获取的列
    lv.pszText = szPid;                 //指定存储查询结果的缓冲区
    lv.cchTextMax = 0x20;               //指定缓冲区大小
    SendMessage(hListProcess, LVM_GETITEMTEXT, dwRowId, (DWORD)&lv);

    MessageBox(NULL, szPid, TEXT("PID"), MB_OK);
}
```

`WM_NOTIFY`&amp;子控件
===================

前言
--

该消息类型与`WM_COMMAND`类型相似，都是由子窗口向父窗口发送的消息

`WM_NOTIFY`可以包含比`WM_COMMAND`更丰富的信息

Windows通用组件中有很多消息，都是通过WM\_NOTIFY来描述的

参数解析
----

![image-20220305233221565](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-9467a34173b320ace713e591f5f9c52de36e8d9d.png)

```php
WM_NOTIFY 
    idCtrl = (int) wParam; 
    pnmh = (LPNMHDR) lParam;
```

参数解析

wParam：控件ID  
lParam：指向一个结构

```php
typedef struct tagNMHDR {
    HWND hwndFrom; //发送通知消息的控制窗口句柄
    UINT idFrom;   //发送通知消息的控制ID值
    UINT code;     //通知码，如LVM_SELCHANGED，左键，右键  
} NMHDR;
```

![image-20220305233314329](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-458c60c7b0e7762c4a0f462bc215bd601c1c93ab.png)

这个结构体能满足一般的要求，但能描述的信息还是有限的

解决方案：对每种不同用途的通知消息都定义另一种结构来表示

针对lParam指向的结构，还有类似的结构，类似继承的思想

```php
typedef struct tagNMLVCACHEHINT {           
    NMHDR   hdr;
    int     iFrom;
    int     iTo;    
} NMLVCACHEHINT, *PNMLVCACHEHINT;       

typedef struct tagLVDISPINFO {
    NMHDR hdr;  
    LVITEM item;        
} NMLVDISPINFO, FAR *LPNMLVDISPINFO;

typedef struct _NMLVFINDITEM {  
    NMHDR hdr;
    int iStart;
    LVFINDINFO lvfi;
} NMLVFINDITEM, *PNMLVFINDITEM;
```

总结
--

通用控件发送消息，都是使用`WM_NOTIFY`消息类型

消息调用
----

```php
case WM_NOTIFY:
        {
            NMHDR* pNMHDR = (NMHDR*)lParam;
            if (wParam == IDC_LIST_PROCESS && pNMHDR->code == NM_CLICK)
            {
                EnumModules(GetDlgItem(hDlg, IDC_LIST_PROCESS), wParam, lParam);
            }
            break;
        }
```

代码示例
----

```php
// test2.cpp : Defines the entry point for the application.
//

#include "stdafx.h"
#include "resource.h"
#include <commctrl.h>

#pragma comment(lib,"comctl32.lib")

//向列表中新增数据函数
VOID EnumProcess(HWND hListProcess)
{
    LV_ITEM vitem;

    //初始化
    memset(&vitem,0,sizeof(LV_ITEM));
    vitem.mask = LVIF_TEXT;

    vitem.pszText = "csrss.exe";
    vitem.iItem = 0;
    vitem.iSubItem = 0;
    //ListView_InsertItem(hListProcess, &vitem);
    SendMessage(hListProcess, LVM_INSERTITEM,0,(DWORD)&vitem);

    vitem.pszText = TEXT("448");
    vitem.iItem = 0;
    vitem.iSubItem = 1;
    ListView_SetItem(hListProcess, &vitem);

    vitem.pszText = TEXT("56590000");
    vitem.iItem = 0;
    vitem.iSubItem = 2;
    ListView_SetItem(hListProcess, &vitem);

    vitem.pszText = TEXT("000F0000");
    vitem.iItem = 0;
    vitem.iSubItem = 3;
    ListView_SetItem(hListProcess, &vitem);

    vitem.pszText = TEXT("winlogon.exe");
    vitem.iItem = 1;
    vitem.iSubItem = 0;
    //ListView_InsertItem(hListProcess, &vitem);
    SendMessage(hListProcess, LVM_INSERTITEM,0,(DWORD)&vitem);

    vitem.pszText = TEXT("456");
    vitem.iSubItem = 1;
    ListView_SetItem(hListProcess, &vitem);

    vitem.pszText = TEXT("10000000");
    vitem.iSubItem = 2;
    ListView_SetItem(hListProcess, &vitem);

    vitem.pszText = TEXT("000045800");
    vitem.iSubItem = 3;
    ListView_SetItem(hListProcess, &vitem);
}

//设置ProcessListView风格
VOID InitProcessListView(HWND hDlg)
{
    LV_COLUMN lv;
    HWND hListProcess;

    //初始化
    memset(&lv,0,sizeof(LV_COLUMN));
    //获取IDC_LIST_PROCESS句柄
    hListProcess = GetDlgItem(hDlg,IDC_LIST_PROCESS);
    //设置整行选中
    SendMessage(hListProcess,LVM_SETEXTENDEDLISTVIEWSTYLE,LVS_EX_FULLROWSELECT,LVS_EX_FULLROWSELECT);

    //第一列
    lv.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
    lv.pszText = TEXT("进程");                //列标题
    lv.cx = 150;                                //列宽
    lv.iSubItem = 0;
    //ListView_InsertColumn(hListProcess, 0, &lv);
    SendMessage(hListProcess,LVM_INSERTCOLUMN,0,(DWORD)&lv);
    //第二列
    lv.pszText = TEXT("PID");
    lv.cx = 90;
    lv.iSubItem = 1;
    //ListView_InsertColumn(hListProcess, 1, &lv);
    SendMessage(hListProcess,LVM_INSERTCOLUMN,1,(DWORD)&lv);
    //第三列
    lv.pszText = TEXT("镜像基址");
    lv.cx = 90;
    lv.iSubItem = 2;
    ListView_InsertColumn(hListProcess, 2, &lv);
    //第四列
    lv.pszText = TEXT("镜像大小");
    lv.cx = 90;
    lv.iSubItem = 3;
    ListView_InsertColumn(hListProcess, 3, &lv);

    EnumProcess(hListProcess);
}

//向模块新增数据
VOID EnumModules(HWND hListProcess, WPARAM wParam, LPARAM lParam)
{
    DWORD dwRowId;
    TCHAR szPid[0x20];
    LV_ITEM lv;

    //初始化
    memset(&lv, 0, sizeof(LV_ITEM));
    memset(szPid, 0, 0x20);

    //获取选择行
    //点第一行:dwRowId == 0
    //点第二行:dwRowId == 1
    dwRowId = SendMessage(hListProcess, LVM_GETNEXTITEM, -1, LVNI_SELECTED);
    if (dwRowId == -1)
    {
        MessageBox(NULL, TEXT("请选择进程"), TEXT("出错咯"), MB_OK);
        return;
    }

    //想要遍历进程的模块，要拿到进程的PID
    //获取PID
    lv.iSubItem = 1;                    //要获取的列
    lv.pszText = szPid;                 //指定存储查询结果的缓冲区
    lv.cchTextMax = 0x20;               //指定缓冲区大小
    SendMessage(hListProcess, LVM_GETITEMTEXT, dwRowId, (DWORD)&lv);

    MessageBox(NULL, szPid, TEXT("PID"), MB_OK);
}

//设置ModulesListView风格
VOID InitModulesListView(HWND hDlg)
{
    LV_COLUMN lv;
    HWND hListModules;

    //初始化
    memset(&lv, 0, sizeof(LV_COLUMN));

    //获取IDC_LIST_MODULE句柄
    //GetDlgItem:父窗口的句柄，子窗口的序号
    hListModules = GetDlgItem(hDlg, IDC_LIST_MOUDLE);

    //设置整行选中
    SendMessage(hListModules,LVM_SETEXTENDEDLISTVIEWSTYLE, LVS_EX_FULLROWSELECT,LVS_EX_FULLROWSELECT);

    //第一列
    lv.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM; //列类型
    lv.pszText = TEXT("模块名称"); //列标题
    lv.cx = 200; //列宽
    lv.iSubItem = 0; //第1列
    // ListView_InsertColumn(hListModules, 0, &lv);
    SendMessage(hListModules,LVM_INSERTCOLUMN,0,(DWORD)&lv); //新增列

    //第二列
    lv.pszText = TEXT("模块位置");
    lv.cx = 200;
    lv.iSubItem = 1; //第2列
    // ListView_InsertColumn(hListModules, 1, &lv);

    SendMessage(hListModules,LVM_INSERTCOLUMN,1,(DWORD)&lv);
}

//消息处理函数
BOOL CALLBACK DialogProc(                                   
                         HWND hDlg,  // handle to dialog box            
                         UINT uMsg,     // message          
                         WPARAM wParam, // first message parameter          
                         LPARAM lParam  // second message parameter         
                         )          
{
    switch(uMsg)                                
    {

    //关闭窗口
    case WM_CLOSE:
        {
            EndDialog(hDlg, 0);
            break;
        }
    //主窗口初始化
    case WM_INITDIALOG:
        {
            //设置ProcessListView风格
            InitProcessListView(hDlg);
            //设置ModulesListView风格
            InitModulesListView(hDlg);
        }

    //通用控件向父窗口发送消息
    case WM_NOTIFY:
        {
            NMHDR* pNMHDR = (NMHDR*)lParam;
            if (wParam == IDC_LIST_PROCESS && pNMHDR->code == NM_CLICK)
            {
                EnumModules(GetDlgItem(hDlg, IDC_LIST_PROCESS), wParam, lParam);
            }
            break;
        }
    case  WM_COMMAND :                              

        switch (LOWORD (wParam))                            
        {                           
        case   IDC_BUTTON_PE:                       

            return TRUE;                        

        case   IDC_BUTTON_ABOUT:
            {
                return TRUE;

            }

        case IDC_BUTTON_LOGOUT:
            {
                EndDialog(hDlg, 0);
                return TRUE;
            }
        }

        break ;                         
    }                                   

    return FALSE ;                                  
}                                   

int APIENTRY WinMain(HINSTANCE hInstance,
                     HINSTANCE hPrevInstance,
                     LPSTR     lpCmdLine,
                     int       nCmdShow)
{
    INITCOMMONCONTROLSEX icex;
    icex.dwSize = sizeof(INITCOMMONCONTROLSEX);     
    icex.dwICC = ICC_WIN95_CLASSES;     
    InitCommonControlsEx(&icex);

    // TODO: Place code here.
    DialogBox(hInstance, MAKEINTRESOURCE(IDD_DIALOG_MAIN), NULL, DialogProc);

    return 0;
}
```

![image-20220305235641199](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-5c090e92e4d25412cc211b69a928f8b0c5217013.png)

![image-20220305235659365](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-65d717b518393a8dc6cb019a518f1749b524c0df.png)

![image-20220305235709543](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-83b437185db01b0f680f54b0b1ecda3c4d234796.png)

```php
// test2.cpp : Defines the entry point for the application.
//

#include "stdafx.h"
#include "resource.h"
#include <commctrl.h>

#pragma comment(lib,"comctl32.lib")

//设置ProcessListView风格
VOID InitProcessListView(HWND hDlg)
{
    LV_COLUMN lv;
    HWND hListProcess;

    //初始化
    memset(&lv,0,sizeof(LV_COLUMN));
    //获取IDC_LIST_PROCESS句柄
    hListProcess = GetDlgItem(hDlg,IDC_LIST_PROCESS);
    //设置整行选中
    SendMessage(hListProcess,LVM_SETEXTENDEDLISTVIEWSTYLE,LVS_EX_FULLROWSELECT,LVS_EX_FULLROWSELECT);

    //第一列
    lv.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
    lv.pszText = TEXT("进程");                //列标题
    lv.cx = 150;                                //列宽
    lv.iSubItem = 0;
    //ListView_InsertColumn(hListProcess, 0, &lv);
    SendMessage(hListProcess,LVM_INSERTCOLUMN,0,(DWORD)&lv);
    //第二列
    lv.pszText = TEXT("PID");
    lv.cx = 90;
    lv.iSubItem = 1;
    //ListView_InsertColumn(hListProcess, 1, &lv);
    SendMessage(hListProcess,LVM_INSERTCOLUMN,1,(DWORD)&lv);
    //第三列
    lv.pszText = TEXT("镜像基址");
    lv.cx = 90;
    lv.iSubItem = 2;
    ListView_InsertColumn(hListProcess, 2, &lv);
    //第四列
    lv.pszText = TEXT("镜像大小");
    lv.cx = 90;
    lv.iSubItem = 3;
    ListView_InsertColumn(hListProcess, 3, &lv);

    // 遍历进程列表
    InitListContentProcess(hwndList);
}

// 遍历进程列表
void InitListContentProcess(hwndList)
{
    // 1. 取得所有进程
    // 2. 获取进程信息(进程名称, 主模块ImageBase, 主模块ImageSize, 主模块EOP)
    // 3. 填充列表数据

    //// 1. 获取所有进程ID
    //DWORD processIds[1024] = { 0 };
    //DWORD dwNumberOfIds = 0;
    //if (GetAllProcessId(processIds, sizeof(processIds), &dwNumberOfIds) == FALSE)
    //{
    //    MessageBox(g_hwndMain, TEXT("获取进程列表!"), TEXT("WARRING"), MB_OK);
    //    return;
    //}

    HANDLE lpSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (lpSnapshot == INVALID_HANDLE_VALUE)
    {
        MessageBox(g_hwndMain, TEXT("创建快照失败"), TEXT("ERROR"), MB_OK);
        return;
    }

    PROCESSENTRY32 p32;
    p32.dwSize = sizeof(p32);
    BOOL pr = Process32First(lpSnapshot, &p32);
    // 遍历所有进程

    for (int row = 0; pr; row++)
    {
        // 进程ID
        DWORD dwPid = p32.th32ProcessID;
        // 进程名
        LPTSTR name = p32.szExeFile;
        // 主模块信息
        MODULEINFO mi = { 0 };
        BOOL miResult = FALSE;
        miResult = GetMainModuleInfo(dwPid, &mi);

        LV_ITEM vitem = { 0 };
        vitem.mask = LVIF_TEXT;
        vitem.iItem = row;

        // 第一列(进程名)
        vitem.pszText = name;
        vitem.iSubItem = 0;
        ListView_InsertItem(hwndList, &vitem);

        // 第二列(PID)
        TCHAR buffer[16];
        wsprintf(buffer, TEXT("%d"), dwPid);
        vitem.pszText = buffer;
        vitem.iSubItem = 1;
        ListView_SetItem(hwndList, &vitem);

        if (miResult)
        {
            // 第三列(主模块基地址)
            wsprintf(buffer, TEXT("%p"), mi.lpBaseOfDll);
            vitem.pszText = buffer;
            vitem.iSubItem = 2;
            ListView_SetItem(hwndList, &vitem);

            // 第四列(镜像大小)
            wsprintf(buffer, TEXT("%p"), mi.SizeOfImage);
            vitem.pszText = buffer;
            vitem.iSubItem = 3;
            ListView_SetItem(hwndList, &vitem);
        }

        pr = Process32Next(lpSnapshot, &p32);
    }

}

//设置ModulesListView风格
VOID InitModulesListView(HWND hDlg)
{
    LV_COLUMN lv;
    HWND hListModules;

    //初始化
    memset(&lv, 0, sizeof(LV_COLUMN));

    //获取IDC_LIST_MODULE句柄
    //GetDlgItem:父窗口的句柄，子窗口的序号
    hListModules = GetDlgItem(hDlg, IDC_LIST_MOUDLE);

    //设置整行选中
    SendMessage(hListModules,LVM_SETEXTENDEDLISTVIEWSTYLE, LVS_EX_FULLROWSELECT,LVS_EX_FULLROWSELECT);

    //第一列
    lv.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM; //列类型
    lv.pszText = TEXT("模块名称"); //列标题
    lv.cx = 200; //列宽
    lv.iSubItem = 0; //第1列
    // ListView_InsertColumn(hListModules, 0, &lv);
    SendMessage(hListModules,LVM_INSERTCOLUMN,0,(DWORD)&lv); //新增列

    //第二列
    lv.pszText = TEXT("模块位置");
    lv.cx = 200;
    lv.iSubItem = 1; //第2列
    // ListView_InsertColumn(hListModules, 1, &lv);

    SendMessage(hListModules,LVM_INSERTCOLUMN,1,(DWORD)&lv);
}

//消息处理函数
BOOL CALLBACK DialogProc(                                   
                         HWND hDlg,  // handle to dialog box            
                         UINT uMsg,     // message          
                         WPARAM wParam, // first message parameter          
                         LPARAM lParam  // second message parameter         
                         )          
{
    OPENFILENAME = stOpenFile;

    switch(uMsg)                                
    {

    //关闭窗口
    case WM_CLOSE:
        {
            EndDialog(hDlg, 0);
            break;
        }
    //主窗口初始化
    case WM_INITDIALOG:
        {
            //设置ProcessListView风格
            InitProcessListView(hDlg);
            //设置ModulesListView风格
            InitModulesListView(hDlg);
        }

    //通用控件向父窗口发送消息
    case WM_NOTIFY:
        {
            NMHDR* pNMHDR = (NMHDR*)lParam;
            if (wParam == IDC_LIST_PROCESS && pNMHDR->code == NM_CLICK)
            {
                EnumModules(GetDlgItem(hDlg, IDC_LIST_PROCESS), wParam, lParam);
            }
            break;
        }
    case  WM_COMMAND :                              

        switch (LOWORD (wParam))                            
        {                       
        case   IDC_BUTTON_ABOUT:
            {
                return TRUE;

            }

        case IDC_BUTTON_LOGOUT:
            {
                EndDialog(hDlg, 0);
                return TRUE;
            }

        //文件选择消息
        case IDC_BUTTON_OPEN:
            {
                TCHAR strPeFileExt[128] = TEXT("PE File(*.exe,*.dll,*.sys)\0*.exe;*.dll*;.sys\0") \
                    TEXT("All File(*.*)\0*.*\0\0");
                TCHAR strFileName[256];

                meset(strFileName, 0, 256);
                meset(&stOpenFile, 0, sizeof(OPENFILENAME));

                stOpenFile.lStructSize = sizeof(OPENFILENAME); //当前结构体大小
                stOpenFile.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
                stOpenFile.hwndOwner = hDlg;
                stOpenFile.lpstrFilter = strPeFileExt; //过滤器，只有符合过滤名的，才会显示出来
                stOpenFile.lpstrFile = strFileName;
                stOpenFile.nMaxFile = MAX_PATH;

                if (GetOpenFileName(&st) == FALSE)
                {
                    SetStaticMessage(TEXT("未选择文件!"));
                    return;
                }

                //PVOID g_pFileBuffer = NULL;
                //DWORD g_dwFileSize = 0;
                if (ReadPeFile(strFileName, &g_pFileBuffer, &g_dwFileSize) == FALSE)
                {
                    SetStaticMessage(TEXT("加载PE文件失败!"));
                    return;
                }

                TCHAR buf[1024];
                wsprintf(buf, TEXT("已打开文件 %s"), strFileName);
                SetStaticMessage(buf);

                DialogBox(g_hInstance, MAKEINTRESOURCE(IDD_DIALOG_PE), g_hwndMain, DialogPeProc);
            }
            }
        }

        break ;                         
    }                                   

    return FALSE ;                                  
}                                   

int APIENTRY WinMain(HINSTANCE hInstance,
                     HINSTANCE hPrevInstance,
                     LPSTR     lpCmdLine,
                     int       nCmdShow)
{
    INITCOMMONCONTROLSEX icex;
    icex.dwSize = sizeof(INITCOMMONCONTROLSEX);     
    icex.dwICC = ICC_WIN95_CLASSES;     
    InitCommonControlsEx(&icex);

    // TODO: Place code here.
    DialogBox(hInstance, MAKEINTRESOURCE(IDD_DIALOG_MAIN), NULL, DialogProc);

    return 0;
}
```

进程
==

前言
--

一个进程中，至少有一个线程

线程
==

前言
--

表示当前进程中包含了多少线程

线程句柄与线程ID:

线程是由Windows内核负责创建与管理的，句柄相当于一个令牌，有了这个令牌就可以使用线程对象.

线程ID是身份证，唯一的，系统进行线程调度的时候要使用的.

创建线程
----

注：等待系统分配CPU才可以跑起来

```php
HANDLE CreateThread(                
  LPSECURITY_ATTRIBUTES lpThreadAttributes, // 安全属性 通常为NULL             
  SIZE_T dwStackSize,                       // 参数用于设定线程可以将多少地址空间用于它自己的堆栈                
                                            // 每个线程拥有它自己的堆栈
  LPTHREAD_START_ROUTINE lpStartAddress,    // 参数用于指明执行的线程函数的地址             
  LPVOID lpParameter,                       // 线程函数的参数              
                                            // 在线程启动执行时将该参数传递给线程函数
                                            // 既可以是数字，也可以是指向包含其他信息的一个数据结构的指针
  DWORD dwCreationFlags,                    // 0:创建完毕立即调度  CREATE_SUSPENDED:创建后挂起               
  LPDWORD lpThreadId                        // 线程ID(out类型参数)                
);// 返回值：线程句柄

//::的意思是定义为全局函数
HANDLE hThread = ::CreateThread(NULL, 0, ThreadProc, NULL, 0, NULL);            

//关闭句柄:线程还在，只是表示系统分配的编号没了       
::CloseHandle(hThread);
```

代码示例
----

```php
// test00.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <Windows.h>

//线程函数
DWORD WINAPI ThreadProc1(LPVOID lpParameter)
{
    for (int i = 0;i < 1000; i++)
    {
        Sleep(1000);
        printf("%d*************************\n",i);
    }
    return 0;
}

//线程函数
DWORD WINAPI ThreadProc2(LPVOID lpParameter)
{
    for (int i = 0;i < 1000; i++)
    {
        Sleep(1000);
        printf("%d*************************\n",i);
    }
    return 0;
}

void Test1()
{
    //::的意思是定义为全局函数
    HANDLE hThread = ::CreateThread(NULL, 0, ThreadProc1, NULL, 0,  NULL);

    //线程还在，只是表示系统分配的编号没了
    ::CloseHandle(hThread);
}

void Test2()
{
    HANDLE hThread = ::CreateThread(NULL, 0, ThreadProc2, NULL, 0,  NULL);
    ::CloseHandle(hThread);
}

int main(int argc, char* argv[])
{
    Test1();
    Test2();
    for (int i = 0;i < 1000; i++)
    {
        Sleep(1000); //休息一秒
        printf("%d*************************\n",i);
    }

    return 0;
}
```

线程数
---

以任务管理器为例

![image-20220306154608832](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-2474145592babb5b4718216140408c3c12f7ad94.png)

![image-20220306154635695](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-22a39244529de06e6d8291a3b9b9c68e1aca79f4.png)

![image-20220306154703197](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-ceead8f1cb5d55f4bbf82e72499a128a5dfc6eee.png)

线程函数&amp;传递变量
-------------

### 全局变量

#### 代码示例

```php
#include "stdafx.h"
#include <windows.h>

//线程函数，就是线程数据 thread data
DWORD WINAPI ThreadProc1(LPVOID lpParameter)
{
    int* p = (int*)lpParameter;
    for (int i = 0;i < 1000; i++)
    {
        Sleep(1000);
        printf("**********************%d***\n", *p);
    }
    return 0;
}

//全局变量
int x = 6;
void Test1()
{
    HANDLE hThread = ::CreateThread(NULL, 0, ThreadProc1, (void* )&x, 0,  NULL);
    ::CloseHandle(hThread);
}

int main(int argc, char* argv[])
{
    Test1();
    for (int i = 0;i < 1000; i++)
    {
        Sleep(1000);
        printf("*************************\n");
    }

    return 0;
}
```

![image-20220306212932275](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-9d84d5c9f00787cf9499227d0925d268b16ca1fc.png)

![image-20220306213435117](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-c3c0b40add426e23ad4fc13b4306c0d6bd5ce682.png)

### 线程参数

#### 代码示例

```php
#include "stdafx.h"
#include <windows.h>

//线程函数，就是线程数据 thread data
DWORD WINAPI ThreadProc2(LPVOID lpParameter)
{
    int p = (int)lpParameter;
    for (int i = 0;i < 1000; i++)
    {
        Sleep(1000);
        printf("%d*************************\n",p);
    }
    return 0;
}

void Test2()
{   
    //局部变量，做线程参数
    int x = 6;
    HANDLE hThread = ::CreateThread(NULL, 0, ThreadProc2, (void* )x, 0,  NULL);
    ::CloseHandle(hThread);
}

int main(int argc, char* argv[])
{
    Test2();
    for (int i = 0;i < 1000; i++)
    {
        Sleep(1000);
        printf("*************************\n",i);
    }

    return 0;
}
```

![image-20220306212812469](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-27a9268d64f82219ffa7e8e07739bfbef65cc155.png)

![image-20220306213526522](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-205b8f4472a431bb13a5d994431747fad30d7e35.png)

### 总结

线程在代码写完，编译链接完成，正常执行应用程序，期间正常加载至操作系统，形成进程，不做创建线程的操作

默认就是只有一个主线程在工作

若增加线程，那么就相当于同一个事情在同一时间，多个人在一起做

实操
--

当我们是单线程程序时，点击开始，占了主线程，界面的消息没有cpu去处理

```php
#include "stdafx.h"
#include "resource.h"

HWND hEdit;
int dwNum = 1000;

//线程函数
DWORD WINAPI ThreadProc(LPVOID lpParameter)
{
    int* p = (int*)lpParameter;
    // 获取文本框内容
    TCHAR szBuffer[10];
    memset(szBuffer, 0, 10);
    GetWindowText(hEdit, szBuffer, 10);

    // 转成整数
    DWORD dwTimer;
    sscanf(szBuffer, "%d", &dwTimer);

    while(dwTimer > 0)
    {
        // 转成字符串
        memset(szBuffer, 0, 10);
        Sleep(1000);
        sprintf(szBuffer, "%d", --dwTimer);

        // 写回去
        SetWindowText(hEdit, szBuffer);
    }

    return 0;
}

BOOL CALLBACK MainDlgProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    BOOL bRet = FALSE;

    switch (uMsg)
    {
    case WM_CLOSE:
        {
            EndDialog(hDlg, 0);
            break;
        }

    case WM_INITDIALOG:
        {
            //得到文本框编号
            hEdit= GetDlgItem(hDlg, IDC_EDIT);

            //文本框赋值
            SetWindowText(hEdit,"1000");
            break;
        }

    case WM_COMMAND:
        switch (LOWORD (wParam))
        {
        case IDC_BUTTON:
            {
                //创建线程
                //HANDLE hThread = ::CreateThread(NULL, 0, ThreadProc, NULL, 0,  NULL);
                HANDLE hThread = ::CreateThread(NULL, 0, ThreadProc, (void*)&dwNum, 0,  NULL);
                ::CloseHandle(hThread);
                return TRUE;
            }
        }
        break;
    }
    return bRet;
}

int APIENTRY WinMain(HINSTANCE hInstance,
                     HINSTANCE hPrevInstance,
                     LPSTR     lpCmdLine,
                     int       nCmdShow)
{
    // TODO: Place code here.

    DialogBox(hInstance, MAKEINTRESOURCE(IDD_DIALOG_MAIN), NULL, MainDlgProc);

    return 0;
}
```

线程控制
====

挂起线程
----

注：当我们挂起线程时，操作系统是不会给它分CPU时间的

```php
 ::SuspendThread(hThread);
```

恢复线程
----

注：Windows操作系统不是一个实时操作系统，在我们恢复线程的时候，看调度程序什么时候给它分CPU

```php
::ResumeThread(hThread);
```

终止线程
----

### 方式一

它是放到线程函数中的，可以使用一个全局变量去判断

```php
::ExitThread(DWORD dwExitCode);

DWORD x = 0;
if(x == 1)
{
    ::ExitThread(1);
}
```

dwExitCode：它是退出码，会在Output进行输出，`code 1`

正常线程执行完毕，`return 0`

线程是终止的，`::ExitThread(1);`

特点：会把当前线程的堆栈处理掉，同步调用

**同步调用**：在同一个线程中，下面的代码是一定不会去执行，返回即代表线程已经结束了

### 方式二

```php
线程函数返回
```

表示线程正常结束

特点：资源都是自己去释放

### 方式三

它是放到Button中的

这种方式是我们告诉操作系统，我们要结束这个线程

```php
::TerminateThread(hThread,2);
```

特点：堆栈并不会被清理，异步调用(需要一个函数去判断线程是否被关闭了)

**异步调用**：在起一个线程，去关闭当前线程，两者在不同线程

它做的只是：告诉操作系统一声，把这个线程关闭，并不会去管操作系统是否已经关闭

所以，引出了，等待操作系统关闭线程的函数`WaitForSingleObject`

```php
::WaitForSingleObject(hThread,INFINITE);
```

获取结束码
-----

使用`GetExitCodeThread`函数

```php
BOOL GetExitCodeThread(
  HANDLE hThread,
  LPDWORD lpExitCode    
);
```

参数解析

```php
hThread:要结束的线程句柄
dwExitCode:指定线程的退出代码。可以通过GetExitCodeThread来查看一个线程的退出代码
```

代码示例
----

```php
// jiayou.cpp : Defines the entry point for the application.
//

#include "stdafx.h"
#include "resource.h"

int dwNum = 1000;

HWND hEdit;
HANDLE hThread;
//线程函数
DWORD WINAPI ThreadProc(LPVOID lpParameter)
{
    int* p = (int*)lpParameter;
    // 获取文本框内容
    TCHAR szBuffer[10];
    memset(szBuffer, 0, 10);
    GetWindowText(hEdit, szBuffer, 10);

    // 转成整数
    DWORD dwTimer;
    sscanf(szBuffer, "%d", &dwTimer);

    while(dwTimer > 0)
    {
        // 转成字符串
        memset(szBuffer, 0, 10);
        Sleep(1000);
        sprintf(szBuffer, "%d", --dwTimer);

        // 写回去
        SetWindowText(hEdit, szBuffer);
    }

    return 0;
}

BOOL CALLBACK MainDlgProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    BOOL bRet = FALSE;

    switch (uMsg)
    {
    case WM_CLOSE:
        {
            EndDialog(hDlg, 0);
            break;
        }

    case WM_INITDIALOG:
        {
            //得到文本框编号
            hEdit= GetDlgItem(hDlg, IDC_EDIT);

            //文本框赋值
            SetWindowText(hEdit,"1000");
            break;
        }

    case WM_COMMAND:
        switch (LOWORD (wParam))
        {
        case IDC_BUTTON_1:
            {
                //创建线程
                HANDLE hThread = ::CreateThread(NULL, 0, ThreadProc, NULL, 0,  NULL);
                //hThread = ::CreateThread(NULL, 0, ThreadProc, (void*)&dwNum, 0,  NULL);
                ::CloseHandle(hThread);
                return TRUE;
            }

        case IDC_BUTTON_2:
            {
                //挂起线程
                ::SuspendThread(hThread);
                return TRUE;
            }
        case IDC_BUTTON_3:
            {
                //恢复线程
                ::ResumeThread(hThread);
                return TRUE;
            }

        case IDC_BUTTON_4:
            {   
                //终止线程
                ::TerminateThread(hThread,2);
                ::WaitForSingleObject(hThread,INFINITE);
                return TRUE;
            }
        }
        break;
    }
    return bRet;
}

int APIENTRY WinMain(HINSTANCE hInstance,
                     HINSTANCE hPrevInstance,
                     LPSTR     lpCmdLine,
                     int       nCmdShow)
{
    // TODO: Place code here.
    DialogBox(hInstance, MAKEINTRESOURCE(IDD_DIALOG_MAIN), NULL, MainDlgProc);
    return 0;
}

```

线程CONTEXT对象
===========

前言
--

每个线程在执行的时候，操作系统会给他分一个CPU时间片(20毫秒)

但时间到了，但是它的线程没有跑完，要切到另外一个线程了，那么各种寄存器的值是怎么保存的呢？

切回来之后，从哪个地址开始执行呢？各种寄存器的值又是如何恢复的呢？

解决
--

CONTEXT：包含了所有的寄存器

该结构包含了特定处理器的寄存器数据

```php
typedef struct _CONTEXT {                           

    //                          
    // The flags values within this flag control the contents of                            
    // a CONTEXT record.                            
    //                          
    // If the context record is used as an input parameter, then                            
    // for each portion of the context record controlled by a flag                          
    // whose value is set, it is assumed that that portion of the                           
    // context record contains valid context. If the context record                         
    // is being used to modify a threads context, then only that                            
    // portion of the threads context will be modified.                         
    //                          
    // If the context record is used as an IN OUT parameter to capture                          
    // the context of a thread, then only those portions of the thread's                            
    // context corresponding to set flags will be returned.                         
    //                          
    // The context record is never used as an OUT only parameter.                           
    //                          

    //要获取的寄存器类型
    DWORD ContextFlags;                         

    //                          
    // This section is specified/returned if CONTEXT_DEBUG_REGISTERS is                         
    // set in ContextFlags.  Note that CONTEXT_DEBUG_REGISTERS is NOT                           
    // included in CONTEXT_FULL.                            
    //                          

    //Debug(调试)寄存器
    DWORD   Dr0;                            
    DWORD   Dr1;                            
    DWORD   Dr2;                            
    DWORD   Dr3;                            
    DWORD   Dr6;                            
    DWORD   Dr7;                            

    //                          
    // This section is specified/returned if the                            
    // ContextFlags word contians the flag CONTEXT_FLOATING_POINT.                          
    //                          

    //浮点寄存器
    FLOATING_SAVE_AREA FloatSave;                           

    //                          
    // This section is specified/returned if the                            
    // ContextFlags word contians the flag CONTEXT_SEGMENTS.                            
    //                          

    //段寄存器
    DWORD   SegGs;                          
    DWORD   SegFs;                          
    DWORD   SegEs;                          
    DWORD   SegDs;                          

    //                          
    // This section is specified/returned if the                            
    // ContextFlags word contians the flag CONTEXT_INTEGER.                         
    //                          

    DWORD   Edi;                            
    DWORD   Esi;                            
    DWORD   Ebx;                            
    DWORD   Edx;                            
    DWORD   Ecx;                            
    DWORD   Eax;                            

    //                          
    // This section is specified/returned if the                            
    // ContextFlags word contians the flag CONTEXT_CONTROL.                         
    //                          

    //段寄存器
    DWORD   Ebp;                            
    DWORD   Eip;                            
    DWORD   SegCs;              // MUST BE SANITIZED                            
    DWORD   EFlags;             // MUST BE SANITIZED                            
    DWORD   Esp;                            
    DWORD   SegSs;                          

    //                          
    // This section is specified/returned if the ContextFlags word                          
    // contains the flag CONTEXT_EXTENDED_REGISTERS.                            
    // The format and contexts are processor specific                           
    //                          

    BYTE    ExtendedRegisters[MAXIMUM_SUPPORTED_EXTENSION];                         

} CONTEXT;
```

获取线程CONTEXT结构
-------------

```php
//挂起线程                  
SuspendThread(线程句柄);
CONTEXT context

//设置要获取的类型
context.ContextFlags = CONTEXT_CONTROL;

//获取
BOOL ok = ::GetThreadContext(hThread,&context);

//设置(自己切换线程)
context.Eip = 0x401000;

//写回去
SetThreadContext(hThread,&context);

//恢复线程
::ResumeThread(hThread);
```

代码示例
----

```php
// jiayou.cpp : Defines the entry point for the application.
//

#include "stdafx.h"
#include "resource.h"

int dwNum = 1000;

HWND hEdit;
HANDLE hThread;
//线程函数
DWORD WINAPI ThreadProc(LPVOID lpParameter)
{
    int* p = (int*)lpParameter;
    // 获取文本框内容
    TCHAR szBuffer[10];
    memset(szBuffer, 0, 10);
    GetWindowText(hEdit, szBuffer, 10);

    // 转成整数
    DWORD dwTimer;
    sscanf(szBuffer, "%d", &dwTimer);

    while(dwTimer > 0)
    {
        // 转成字符串
        memset(szBuffer, 0, 10);
        Sleep(1000);
        sprintf(szBuffer, "%d", --dwTimer);

        // 写回去
        SetWindowText(hEdit, szBuffer);
    }

    return 0;
}

BOOL CALLBACK MainDlgProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    BOOL bRet = FALSE;

    switch (uMsg)
    {
    case WM_CLOSE:
        {
            EndDialog(hDlg, 0);
            break;
        }

    case WM_INITDIALOG:
        {
            //得到文本框编号
            hEdit= GetDlgItem(hDlg, IDC_EDIT);

            //文本框赋值
            SetWindowText(hEdit,"1000");
            break;
        }

    case WM_COMMAND:
        switch (LOWORD (wParam))
        {
        case IDC_BUTTON_1:
            {
                //创建线程
                HANDLE hThread = ::CreateThread(NULL, 0, ThreadProc, NULL, 0,  NULL);
                //hThread = ::CreateThread(NULL, 0, ThreadProc, (void*)&dwNum, 0,  NULL);
                ::CloseHandle(hThread);
                return TRUE;
            }

        case IDC_BUTTON_2:
            {
                //挂起线程
                ::SuspendThread(hThread);

                CONTEXT context
                //设置要获取的类型
                context.ContextFlags = CONTEXT_CONTROL;
                //获取
                BOOL ok = ::GetThreadContext(hThread,&context);
                //设置(想当于自己手动切换线程)
                context.Eip = 0x401000;
                //写回去
                SetThreadContext(hThread,&context);
                //恢复线程
                ::ResumeThread(hThread);

                return TRUE;
            }
        case IDC_BUTTON_3:
            {
                //恢复线程
                ::ResumeThread(hThread);
                return TRUE;
            }

        case IDC_BUTTON_4:
            {   
                //终止线程
                ::TerminateThread(hThread,2);
                ::WaitForSingleObject(hThread,INFINITE);
                return TRUE;
            }
        }
        break;
    }
    return bRet;
}

int APIENTRY WinMain(HINSTANCE hInstance,
                     HINSTANCE hPrevInstance,
                     LPSTR     lpCmdLine,
                     int       nCmdShow)
{
    // TODO: Place code here.
    DialogBox(hInstance, MAKEINTRESOURCE(IDD_DIALOG_MAIN), NULL, MainDlgProc);
    return 0;
}
```

多线程&amp;全局变量
============

前言
--

两个线程会互相抢占

代码示例
----

它是有问题的

```php
HWND hEdit ;                    
DWORD WINAPI ThreadProc1(LPVOID lpParameter)                    
{                   
    TCHAR szBuffer[10];             
    DWORD dwIndex = 0;              
    DWORD dwCount;              

    while(dwIndex<10)               
    {               
        GetWindowText(hEdit,szBuffer,10);           
        sscanf( szBuffer, "%d", &dwCount );         
        dwCount++;          
        memset(szBuffer,0,10);          
        sprintf(szBuffer,"%d",dwCount);         
        SetWindowText(hEdit,szBuffer);          
        dwIndex++;          
    }               

    return 0;               
}                   
DWORD WINAPI ThreadProc2(LPVOID lpParameter)                    
{                   
    TCHAR szBuffer[10];             
    DWORD dwIndex = 0;              
    DWORD dwCount;              

    while(dwIndex<10)               
    {               
        GetWindowText(hEdit,szBuffer,10);           
        sscanf( szBuffer, "%d", &dwCount );         
        dwCount++;          
        memset(szBuffer,0,10);          
        sprintf(szBuffer,"%d",dwCount);         
        SetWindowText(hEdit,szBuffer);          
        dwIndex++;          
    }               

    return 0;               
}                   

BOOL CALLBACK MainDlgProc(HWND hDlg,UINT uMsg,WPARAM wParam,LPARAM lParam)                  
{                   
    BOOL bRet = FALSE;              

    switch(uMsg)                
    {               
    case WM_CLOSE:              
        {           
            EndDialog(hDlg,0);      
            break;      
        }           
    case WM_INITDIALOG:             
        {           
            hEdit = GetDlgItem(hDlg,IDC_EDIT1);     
            SetWindowText(hEdit,"0");       

            break;      
        }           
    case WM_COMMAND:                

        switch (LOWORD (wParam))            
        {           
        case IDC_BUTTON_T1:         
            {       
                HANDLE hThread1 = ::CreateThread(NULL, 0, ThreadProc1,  
                    NULL, 0, NULL);

                ::CloseHandle(hThread1);    
                return TRUE;    
            }       
        case IDC_BUTTON_T2:         
            {       
                HANDLE hThread2 = ::CreateThread(NULL, 0, ThreadProc2,  
                    NULL, 0, NULL);

                ::CloseHandle(hThread2);    
                return TRUE;    
            }       
        }           
        break ;         
    }               

    return bRet;                
}                   

int APIENTRY WinMain(HINSTANCE hInstance,                   
                     HINSTANCE hPrevInstance,                   
                     LPSTR     lpCmdLine,                   
                     int       nCmdShow)                    
{                   
    // TODO: Place code here.               

    DialogBox(hInstance,MAKEINTRESOURCE(IDD_DIALOG_MAIN),NULL,MainDlgProc);             

    return 0;               
}
```

总结
==

进程就是4GB空间，线程就是EIP

线程安全
====

本质
--

每个线程都会有自己的堆栈，参数，局部变量都会压到堆栈中

但是，全局变量是在全局区

线程安全的本质是：多个线程操作了同一块`"资源"`

临界区
===

前言
--

进行线程调度

示意图
---

![image-20220308165925495](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-afcbcdc0db9b409f52f697d78e75584b9d06eab1.png)

创建CRITICAL\_SECTION：
--------------------

```php
//创建令牌，一个全局的结构体
CRITICAL_SECTION cs;
```

```php
typedef struct _RTL_CRITICAL_SECTION {      
    PRTL_CRITICAL_SECTION_DEBUG DebugInfo;      
    LONG LockCount;     
    LONG RecursionCount;        
    HANDLE OwningThread;            
    HANDLE LockSemaphore;       
    DWORD SpinCount;        
} RTL_CRITICAL_SECTION, *PRTL_CRITICAL_SECTION;
```

参数解析：

```php
LockCount:      
它被初始化为数值 -1     
此数值等于或大于 0 时，表示此临界区被占用
LockCount = 0 表示有1个线程等待获得临界区
LockCount = 1 表示有2个线程等待获得临界区
LockCount = 2 表示有3个线程等待获得临界区

等待获得临界区的线程数:LockCount - (RecursionCount -1)     

RecursionCount:     
此字段包含所有者线程已经获得该临界区的次数       

OwningThread:       
此字段包含当前占用此临界区的线程的线程标识符      
此线程 ID 与GetCurrentThreadId 所返回的 ID 相同
```

初始化
---

```php
//初始化令牌
InitializeCriticalSection(&cs);
```

函数中使用
-----

```php
DWORD WINAPI 线程A(PVOID pvParam) 
{     
      //获取令牌
      EnterCriticalSection(&cs);            

      //对全局遍历X的操作   

      //释放令牌
      LeaveCriticalSection(&cs);

   return(0);               
}               

DWORD WINAPI 线程B(PVOID pvParam)                 
{               
      EnterCriticalSection(&g_cs);              

      //对全局遍历X的操作               

      LeaveCriticalSection(&g_cs);              
   return(0);               
}
```

删除CRITICAL\_SECTION
-------------------

注：当线程不再试图访问共享资源时

```php
//销毁令牌
VOID DeleteCriticalSection(PCRITICAL_SECTION pcs);
```

实例一
---

多线程程序，应该将获取令牌和释放令牌放到循环里，只有涉及到全局变量，才会放到临界区

![image-20220308183812726](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-55caaa9479324284a3a5da8536fc767f7d58e798.png)

实例二
---

多线程程序，没有实现多线程，应该把全局变量放到临界区中

![image-20220308183536243](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-4dcc77c902788886df9e19b2aa51141d3d758e79.png)

实例三
---

多线程程序，下面的线程没有拿到令牌，就闯进去了

![image-20220308183619437](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-2daecb204846981c7f3b1d5b46d61d2236c06879.png)

实例四
---

分析这个程序：

```php
全局变量X
全局变量Y
全局变量Z

线程1
DWORD WINAPI ThreadFunc(PVOID pvParam) 
{
   EnterCriticalSection(&g_cs);
   使用X
   使用Y
   LeaveCriticalSection(&g_cs);
   return(0);
}

线程2
DWORD WINAPI ThreadFunc(PVOID pvParam) 
{
   EnterCriticalSection(&g_cs);
   使用X
   使用Z
   LeaveCriticalSection(&g_cs);
   return(0);
}

线程3
DWORD WINAPI ThreadFunc(PVOID pvParam) 
{
   EnterCriticalSection(&g_cs);
   使用Y
   使用X
   LeaveCriticalSection(&g_cs);
   return(0);
}
```

这个程序的问题在于：浪费时间

解决方案：针对每一个全局变量，我们要单独去把它放到临界区

```php
CRITICAL_SECTION g_csX; 
CRITICAL_SECTION g_csY; 
CRITICAL_SECTION g_csZ; 

线程1
DWORD WINAPI ThreadFunc(PVOID pvParam) 
{
   EnterCriticalSection(&g_csX);
   使用X
   LeaveCriticalSection(&g_csX);
   EnterCriticalSection(&g_csY);
   使用Y
   LeaveCriticalSection(&g_csY);

   return(0);
}

线程2
DWORD WINAPI ThreadFunc(PVOID pvParam) 
{
   EnterCriticalSection(&g_csX);
   使用X
   LeaveCriticalSection(&g_csX);
   EnterCriticalSection(&g_csZ);
   使用Z
   LeaveCriticalSection(&g_csZ);

   return(0);
}

线程3
DWORD WINAPI ThreadFunc(PVOID pvParam) 
{
   EnterCriticalSection(&g_csX);
   使用X
   LeaveCriticalSection(&g_csX);
   return(0);
}
```

总结
--

多个线程不访问全局变量，或者对全局变量是只读的操作，是不需要去管的

多个线程，对全局变量`修改`的地方，都要单独放到临界区里

死锁
==

示意图
---

一个多线程程序，看CPU切换的时机

```php
线程A:                     线程B:

拿A的令牌                  拿B的令牌
   1、CPU时间片到了           2、CPU时间片到了
    拿B的令牌                    拿A的令牌

    还B的令牌                    还A的令牌

还A的令牌                  还B的令牌
```

总结
--

避免死锁：

1、每个线程函数中，获取令牌的顺序一致

2、尽量不要嵌套，拿一个还一个

WaitForSingleObject
===================

前言
--

它是一个等待函数，当我们调用它的时候，操作系统处于阻塞状态(一直在循环等着)

结构
--

```php
DWORD WaitForSingleObject(
  HANDLE hHandle,        // 内核对象的句柄
  DWORD dwMilliseconds  
);
```

参数说明
----

```php
hHandle:内核对象的句柄，不同的内核对象，处理方式不同

dwMilliseconds:等待时间，单位是毫秒  INFINITE(-1)一直等待

往下执行的两种情况:  
1、等待对象变为已通知
2、超时
至于是哪一种情况，可以通过返回值的宏去判断

返回值:                            
WAIT_OBJECT_0(0)        等待对象变为已通知       

WAIT_TIMEOUT(0x102)     超时
```

功能说明
----

等待函数可使线程自愿进入等待状态，直到一个特定的内核对象变为已通知状态为止

特别说明
----

```php
1、内核对象中的每种对象都可以说是处于已通知或未通知的状态之中

2、这种状态的切换是由Microsoft为每个对象建立的一套规则来决定的

3、当线程正在运行的时候，线程内核对象处于未通知状态

4、当线程终止运行的时候，它就变为已通知状态

5、在内核中就是个BOOL值，运行时FALSE 结束TRUE
```

代码示例
----

```php
#include "stdafx.h"
#include <windows.h>

DWORD WINAPI ThreadProc1(LPVOID lpParameter)                    
{                   
    for(int i=0;i<5;i++)                
    {               
        printf("+++++++++\n");          
        Sleep(1000);            
    }               
    return 0;               
}                   

int main(int argc, char* argv[])                    
{                   

    //创建一个新的线程              
    HANDLE hThread1 = ::CreateThread(NULL, 0, ThreadProc1,              
        NULL, 0, NULL);         

    //等待函数
    DWORD dwCode = ::WaitForSingleObject(hThread1, INFINITE);               

    MessageBox(0,0,0,0);                

    return 0;               
}
```

可以通过看dwCode判断等待函数是如何结束的

可以看到它是正常结束的

![image-20220309120743206](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-c009a5141854a195ffa2796cc8f1b449a7544100.png)

超时结束的

![image-20220309120844122](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-33a5996c3f7263936b2cdb52c9e7b0a477a9b654.png)

CloseHandle
===========

注意
--

这个函数是用来关闭关闭内核对象

内核对象是操作系统替我们创建的，保存在高2G的内存中

内核对象总结：**线程、互斥体**

1、当我们程序执行完后，我们没有主动关闭内核对象(CloseHandle)，但是操作系统会替我们关闭内核对象

2、当我们程序正在运行时，我们没有主动关闭内核对象(CloseHandle)，会有内核对象泄露的风险

WaitForMultipleObjects
======================

前言
--

它也是一个等待函数，等待多个线程，使用数组保存多个内核对象

结构
--

```php
DWORD WaitForMultipleObjects(
  DWORD nCount,         
  CONST HANDLE *lpHandles,
  BOOL bWaitAll,
  DWORD dwMilliseconds
);
```

参数解析
----

```php
nCount:要查看内核对象的数量                           

lpHandles:内核对象数组                            

bWaitAll:等待类型
TRUE:等待所有线程变为已通知
FALSE:只要有一个线程变为已通知                          

dwMilliseconds:超时时间(INFINITE一直等待)

返回值:

bWaitAll:TRUE时，返回WAIT_OBJECT_0(0)代码所有内核对象都变成已通知                         

bWaitAll:FALSE时，返回最先变成已通知的内核对象在数组中的索引
第一个线程变成已通知，返回0
第二个线程变成已通知，返回1

WAIT_TIMEOUT(0x102)，超时
```

功能说明
----

同时查看若干个内核对象的已通知状态

代码示例
----

```php
#include "stdafx.h"
#include <windows.h>

DWORD WINAPI ThreadProc1(LPVOID lpParameter)                            
{                           
    for(int i=0;i<5;i++)                        
    {                       
        printf("+++++++++\n");                  
        Sleep(1000);                    
    }                       
    return 0;                       
}                           

DWORD WINAPI ThreadProc2(LPVOID lpParameter)                            
{                           
    for(int i=0;i<3;i++)                        
    {                       
        printf("---------\n");                  
        Sleep(1000);                    
    }                       

    return 0;                       
}                           

int main(int argc, char* argv[])                            
{                           

    HANDLE hArray[2];                       

    //创建第一个线程                       
    hArray[0] = ::CreateThread(NULL, 0, ThreadProc1,                        
        NULL, 0, NULL);                 

    //创建第二个线程                       
    hArray[1] = ::CreateThread(NULL, 0, ThreadProc2,                        
        NULL, 0, NULL);                 

    //等待多个函数
    DWORD dwCode = ::WaitForMultipleObjects(2, hArray,FALSE,INFINITE);                      

    MessageBox(0,0,0,0);                        

    return 0;                       
}
```

![image-20220309122826869](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-b4c12e2086febd23fcd380d53104d2cf29d8084b.png)

互斥体
===

创建互斥体
-----

使用`CreateMutex`

查看MSDN

![image-20220309145914535](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-68f0c6ab38b691e84b4340e2cb6357afa840d802.png)

![image-20220309145932546](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-067127940395accf9a2d233806fe924adc2e71e7.png)

```php
HANDLE CreateMutex(
  LPSECURITY_ATTRIBUTES lpMutexAttributes,  // 权限控制，一般传NULL即可
  BOOL bInitialOwner,                       // initial owner
  LPCTSTR lpName                            // 互斥体的名字
);
```

注：有权限控制的对象即为内核对象

打开互斥体
-----

在B进程中，得到A进程创建的互斥体

使用`OpenMutex`函数

![image-20220309151111326](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-0310994d2d73af010dc57471a6b31eec5fd39ba9.png)

```php
HANDLE OpenMutex(
  DWORD dwDesiredAccess,  // 权限控制
  BOOL bInheritHandle,    // 是否被继承
  LPCTSTR lpName          // 互斥体的名字
);
```

进入&amp;退出互斥体
------------

进入：

```php
WaitForSingleObject(g_hMutex,INFINITE); 
```

离开：

```php
ReleaseMutex(g_hMutex);
```

特点
--

互斥体可以，跨进程的，对两个进程的线程，进行互斥控制

互斥体&amp;临界区
-----------

1、临界区只能用于单个进程间的线程控制

2、互斥体可以设定等待超时，但临界区不能

3、线程意外终结时，互斥体可以避免无限等待

4、互斥体效率没有临界区高，因为它跨进程了

内核对象
====

前言
--

常见的内核对象有：进程、线程、文件、文件映射、事件、互斥体等等

一旦创建，即是在高2G的内存

示意图
---

![image-20220309160246994](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-555b9194c3f16fe3d887cdc5d12ed97586b29aef.png)

内核对象的创建
-------

```php
//事件内核对象
HANDLE g_hEvent = CreateEvent(NULL, TRUE, FALSE, "XYZ");

//互斥体内核对象
HANDLE g_hMutex = CreateMutex(NULL,FALSE, "XYZ");
```

我们可以这么理解：

`g_hMutex`它是一个指针的指针，它这个值很小，是操作系统给的编号

为了安全考虑，避免非法的手段修改内核对象

内核对象的获取
-------

```php
HANDLE OpenEvent(                       
  DWORD dwDesiredAccess,  // access             
  BOOL bInheritHandle,    // inheritance option             
  LPCTSTR lpName          // object name                        
);

HANDLE g_hEvent = OpenEvent(EVENT_ALL_ACCESS, FALSE, "XYZ");

HANDLE g_hMutex = OpenMutex(MUTEX_ALL_ACCESS,FALSE, "XYZ");
```

内核对象的销毁
-------

注意：`CloseHandle`函数其实它是关闭句柄，内核对象的销毁其实未必

```php
BOOL CloseHandle(HANDLE hobj);

(1)、当没有其他程序引用时，系统会销毁内核对象(使用数量)

(2)、内核对象的生命周期，可能比创建它的对象要长
```

内核对象的生命周期
---------

内核对象在创建出来之前，在高2G会有一个结构体

结构体中有一个成员，它是计数器，初始是0

```php
HANDLE g_hEvent = CreateEvent(NULL, TRUE, FALSE, "XYZ"); //计数器+1
```

```php
HANDLE g_hEvent = OpenEvent(EVENT_ALL_ACCESS, FALSE, "XYZ"); //计数器+1
```

然后我们调用`CloseHandle`函数，关闭互斥体的句柄

计数器(2)-1=1，所以当前的内核对象并不会被销毁

内核对象的生命周期比创建内核的程序，时间要长

事件对象
====

事件对象的创建
-------

```php
HANDLE CreateEvent(             
  LPSECURITY_ATTRIBUTES lpEventAttributes, // 安全属性 NULL时为系统默认               
  BOOL bManualReset,                       
  //TRUE:通过调用ResetEvent将事件对象标记为未通知
  //FALSE:调用它的时候，自动变成未通知状态
  //简单理解:是否自动复位
  BOOL bInitialState,                      // TRUE:已通知状态  FALSE:未通知状态       
  LPCTSTR lpName                           // 对象名称，跨进程时使用它的对象，否则写NULL
);
```

事件对象的控制
-------

```php
BOOL SetEvent(HANDLE hEvent);   //将对象设置为已通知
```

关闭事件对象句柄
--------

```php
CloseHandle(); //关闭句柄
```

代码示例
----

```php
// test6.cpp : Defines the entry point for the application.
//

#include "stdafx.h"
#include "resource.h"

HANDLE g_hEvent;        

HWND hEdit1;        
HWND hEdit2;        
HWND hEdit3;        
HWND hEdit4;        
HANDLE hThread1;        
HANDLE hThread2;        
HANDLE hThread3;        
HANDLE hThread4;

DWORD WINAPI ThreadProc2(LPVOID lpParameter)                
{               
    TCHAR szBuffer[10] = {0};           

    //当事件变成已通知时             
    WaitForSingleObject(g_hEvent, INFINITE);            

    //读取内容          
    GetWindowText(hEdit1,szBuffer,10);          

    SetWindowText(hEdit2,szBuffer);         

    return 0;           
}               
DWORD WINAPI ThreadProc3(LPVOID lpParameter)                
{               
    TCHAR szBuffer[10] = {0};           

    //当事件变成已通知时             
    WaitForSingleObject(g_hEvent, INFINITE);            

    //读取内容          
    GetWindowText(hEdit1,szBuffer,10);          

    SetWindowText(hEdit3,szBuffer);         

    return 0;           
}               
DWORD WINAPI ThreadProc4(LPVOID lpParameter)                
{               
    TCHAR szBuffer[10] = {0};           

    //当事件变成已通知时             
    WaitForSingleObject(g_hEvent, INFINITE);            

    //读取内容          
    GetWindowText(hEdit1,szBuffer,10);          

    SetWindowText(hEdit4,szBuffer);         

    return 0;           
}

DWORD WINAPI ThreadProc1(LPVOID lpParameter)                
{               
    //创建事件          
    //默认安全属性  手动设置未通知状态(TRUE)  初始状态未通知 没有名字             
    g_hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);            

    HANDLE hThread[3];

    //创建3个线程            
    hThread[0] = ::CreateThread(NULL, 0, ThreadProc2, NULL, 0, NULL);       
    hThread[1] = ::CreateThread(NULL, 0, ThreadProc3, NULL, 0, NULL);       
    hThread[2] = ::CreateThread(NULL, 0, ThreadProc4, NULL, 0, NULL);       

    //设置文本框的值           
    SetWindowText(hEdit1,"1000");           

    //设置事件为已通知
    //三个线程全处于可调度状态
    SetEvent(g_hEvent);         

    //等待线程结束 销毁内核对象         
    WaitForMultipleObjects(3, hThread, TRUE, INFINITE);             
    CloseHandle(hThread[0]);            
    CloseHandle(hThread[1]);            
    CloseHandle(hThread[2]);            
    CloseHandle(g_hEvent);              

    return 0;           
}               

//消息处理函数
BOOL CALLBACK DialogProc(                                   
                         HWND hDlg,  // handle to dialog box            
                         UINT uMsg,     // message          
                         WPARAM wParam, // first message parameter          
                         LPARAM lParam  // second message parameter         
                         )          
{   
    switch(uMsg)                                
    {                               
    case  WM_INITDIALOG :                               

        hEdit1 = GetDlgItem(hDlg,IDC_EDIT1);
        hEdit2 = GetDlgItem(hDlg,IDC_EDIT2);
        hEdit3 = GetDlgItem(hDlg,IDC_EDIT3);
        hEdit4 = GetDlgItem(hDlg,IDC_EDIT4);

        //设置文本框的值           
        SetWindowText(hEdit1,"0");
        SetWindowText(hEdit2,"0");
        SetWindowText(hEdit3,"0");
        SetWindowText(hEdit4,"0");                          

        break;                          

    case  WM_COMMAND :                              

        switch (LOWORD (wParam))                            
        {                           
        case    IDC_BUTTON_BEGIN:                       
            {
                ::CreateThread(NULL, 0, ThreadProc1, NULL, 0, NULL);
                return TRUE;
            }               

        }                       
        break ;                         
    }                                   

    return FALSE ;                                  
}                                   

int APIENTRY WinMain(HINSTANCE hInstance,
                     HINSTANCE hPrevInstance,
                     LPSTR     lpCmdLine,
                     int       nCmdShow)
{
    DialogBox(hInstance, MAKEINTRESOURCE(IDD_DIALOG_MAIN), NULL, DialogProc);

    return 0;
}
```

我们发现三个线程都执行了

![image-20220309220605828](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-9dc4cecb4a748cf94e7e512a5bfc18ac76e717a4.png)

原因在于我们创建事件的第二个参数

```php
g_hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
```

```php
TRUE:通过调用ResetEvent将事件对象标记为未通知
```

而当我们`SetEvent(g_hEvent);`，三个线程全处于可调度状态

在每个线程执行过程中，我们并没有手动将它改回未通知状态

第二个线程执行，它还是已通知状态

第三个线程执行，它还是已通知状态

所以三个线程都执行了

我们创建事件的第二个参数改为FALSE时

```php
g_hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
```

```php
FALSE:调用它的时候，自动变成未通知状态
```

所以只要有一个线程执行了，它就变成未通知状态了

线程是由操作系统去调度的，所以会执行一个线程，其他两个线程都在阻塞

![image-20220309220521684](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-f8f4a18baa6c03aea251b6730bb9d7ec2214fd34.png)

我们若是想实现一个一个去调度

首先创建事件的第二个参数改成FALSE

然后在每个线程调度完成之后，把它的状态改为已通知即可

```php
SetEvent(g_hEvent);
```

总结
--

```php
线程同步:线程的先后顺序(类比生产者线程和消费者线程)
事件对象

线程互斥:多个线程对同一个资源进行访问的时候，我们要保证某一个时刻，只能有一个线程对资源进行操作
临界区(一个进程)、互斥体(内核对象-->性能较差，因为它要先进到r0、可跨进程)、事件对象
```

线程同步
====

前言
--

可以用一个全局变量去控制线程同步，但是效率很低

事件&amp;线程同步
-----------

### 前言

事件可以做一些简单的线程同步

主要是利用创建事件时的，第二个和第三个参数

### 代码示例

```php
HANDLE g_hSet, g_hClear;        
int g_Max = 10;     
int g_Number = 0;       

//生产者线程函数       
DWORD WINAPI ThreadProduct(LPVOID pM)       
{       
    for (int i = 0; i < g_Max; i++)     
    {       
        WaitForSingleObject(g_hSet, INFINITE);          
        g_Number = 1; 
        DWORD id = GetCurrentThreadId();
        printf("生产者%d将数据%d放入缓冲区\n",id, g_Number); 

        Sleep(1000);
        //修改消费者为已通知状态
        SetEvent(g_hClear);         
    }       
    return 0;       
}       
//消费者线程函数       
DWORD WINAPI ThreadConsumer(LPVOID pM)          
{       
    for (int i = 0; i < g_Max; i++)     
    {       
        WaitForSingleObject(g_hClear, INFINITE);        
        g_Number = 0; 
        DWORD id = GetCurrentThreadId();
        printf("----消费者%d将数据%d放入缓冲区\n",id, g_Number); 

        Sleep(1000);
        //修改生产者为已通知状态
        SetEvent(g_hSet);           
    }       
    return 0;       
}       

int main(int argc, char* argv[])        
{       

    HANDLE hThread[2];      

    //第二个参数(FALSE):调用完它的时候，自动变成未通知状态，不抢占CPU
    //第三个参数(FALSE):创建事件即为已通知状态，所以生产者事件肯定先执行
    g_hSet = CreateEvent(NULL, FALSE, TRUE, NULL);

    //第三个参数:创建事件为未通知状态，所以消费者事件肯定后执行
    g_hClear = CreateEvent(NULL, FALSE, FALSE, NULL);       

    hThread[0] = ::CreateThread(NULL, 0, ThreadProduct, NULL, 0, NULL);         
    hThread[1] = ::CreateThread(NULL, 0, ThreadConsumer, NULL, 0, NULL);    

    WaitForMultipleObjects(2, hThread, TRUE, INFINITE);         
    CloseHandle(hThread[0]);        
    CloseHandle(hThread[1]);        

    //销毁    
    CloseHandle(g_hSet);    
    CloseHandle(g_hClear);          

    return 0;   
}
```

编译时，有一个bug

```php
LIBCD.lib(wincrt0.obj) : error LNK2001: unresolved external symbol _WinMain@16
Debug/memset.exe : fatal error LNK1120: 1 unresolved externals
Error executing link.exe.
```

Project-&gt;Settings-&gt;Link-&gt;Project Options下

将`/subsystem:windows`修改为`/subsystem:console`

```php
kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:console /incremental:yes /pdb:"Debug/m.pdb" /debug /machine:I386 /out:"Debug/m.exe" /pdbtype:sept 
```

![image-20220310103204584](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-fae75b0c3e484d26383777f3bbcaff6b3657ecad.png)

重新编译即可

![image-20220310103250775](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-82c8242bb9fa6a622d07e7f9276b8fdb4779edfd.png)

### 特点

当A线程处于未通知状态时，操作系统不会给你分CPU时间，不会浪费资源，效率较高

信号量
===

前言
--

它也是内核对象，要去控制想有几个线程，就有几个线程在跑

创建信号量
-----

使用`CreateSemaphore`函数

```php
HANDLE CreateSemaphore(     

  LPSECURITY_ATTRIBUTES lpSemaphoreAttributes,      

  LONG lInitialCount,       

  LONG lMaximumCount,       

  LPCTSTR lpName        

);
```

参数解析：

```php
第一个参数表示安全控制，一般直接传入NULL

第二个参数表示初始资源数量。0时不发送信号

第三个参数表示最大并发数量。lInitialCount<=lMaximumCount

第四个参数表示信号量的名称，可以跨进程获取，传入NULL表示匿名信号量
```

打开信号量
-----

在B进程中，得到A进程创建的信号量

使用`OpenSemaphore`函数

```php
HANDLE OpenSemaphore(       

  DWORD dwDesiredAccess,        

  BOOL bInheritHandle,      

  LPCTSTR lpName        

);
```

参数解析：

```php
第一个参数表示访问权限，对一般传入SEMAPHORE_ALL_ACCESS。详细解释可以查看MSDN文档    

第二个参数表示信号量句柄继承性，一般传入FALSE即可     

第三个参数表示名称，不同进程中的各线程可以通过名称来确保它们访问同一个信号量
```

递增信号量&amp;当前资源计数
----------------

调用它可以让当前的资源数+1

使用`ReleaseSemaphore`函数

```php
BOOL ReleaseSemaphore(      

  HANDLE hSemaphore,        

  LONG lReleaseCount,       

  LPLONG lpPreviousCount        

);
```

参数解析：

```php
第一个参数是信号量的句柄

第二个参数表示增加个数，必须大于0且不超过最大资源数量 

第三个参数返回当前资源数量的原始值，设为NULL表示不需要传出     

注:没有一个函数可以用来查询信标的当前资源数量的值
```

代码示例
----

```php
#include "stdafx.h"
#include "resource.h"
#include <stdio.h>

HINSTANCE hAppinstance;

HANDLE hSemaphore;
HANDLE hThread[3];

HWND hEditSet;
HWND hEdit1;
HWND hEdit2;
HWND hEdit3;

// 因为有3个线程函数，所以定义一个长度为3的窗口句柄数组
//用数组去封装
HWND hArray[3];

DWORD WINAPI ThreadProc1(LPVOID lpParameter)
{
    TCHAR szBuffer[10];
    DWORD dwTimmer=0;
    WaitForSingleObject(hSemaphore, INFINITE);

    //接收传进来的值，强转一下
    DWORD dwIndex = (DWORD)lpParameter;
    while(dwTimmer<100)
    {
        Sleep(100);
        memset(szBuffer, 0, 10);
        GetWindowText(hArray[dwIndex], szBuffer, 10);
        sscanf( szBuffer, "%d", &dwTimmer );
        dwTimmer++;
        memset(szBuffer,0,10);
        sprintf(szBuffer,"%d",dwTimmer);
        SetWindowText(hArray[dwIndex],szBuffer);
    }
    ReleaseSemaphore(hSemaphore, 1, NULL); // 设置当前的信号量
    return 0;
}

DWORD WINAPI ThreadBegin(LPVOID lpParameter)
{
    TCHAR szBuffer[10];
    DWORD dwMoney=0;

    //创建信号量
    //初始是0，创建之后不发送信号量
    //最多可以有3个线程同时跑
    //第二个参数<=第三个参数
    hSemaphore = CreateSemaphore(NULL, 0, 3, NULL);

    //使用一份相同的代码创建3个线程，下面的第四个参数代表传递的是数组的下标
    //传参的时候要进行强转
    hThread[0] = ::CreateThread(NULL, 0, ThreadProc1, (void*)0, 0, NULL);
    hThread[1] = ::CreateThread(NULL, 0, ThreadProc1, (void*)1, 0, NULL);
    hThread[2] = ::CreateThread(NULL, 0, ThreadProc1, (void*)2, 0, NULL);

    //开始准备红包
    while(dwMoney<1000)
    {
        //Sleep(50);
        memset(szBuffer, 0, 10);
        GetWindowText(hEditSet, szBuffer, 10);
        sscanf( szBuffer, "%d", &dwMoney );
        dwMoney++;
        memset(szBuffer, 0, 10);
        sprintf(szBuffer, "%d", dwMoney);
        SetWindowText(hEditSet, szBuffer);
    }

    //开始发信号量
    //3:允许有3个线程同时跑
    ReleaseSemaphore(hSemaphore, 3, NULL);

    ::WaitForMultipleObjects(3, hThread, TRUE, INFINITE);

    //关闭三个线程
    CloseHandle(hThread[0]);            
    CloseHandle(hThread[1]);            
    CloseHandle(hThread[2]);

    //关闭信号量
    ::CloseHandle(hSemaphore);

    return 0;
}

BOOL CALLBACK MainDlgProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    BOOL bRet = FALSE;

    switch(uMsg)
    {
    case WM_CLOSE:
        {
            EndDialog(hDlg, 0);
            break;
        }
    case WM_INITDIALOG:
        {
            hEditSet = GetDlgItem(hDlg, IDC_EDIT1);
            hEdit1 = GetDlgItem(hDlg, IDC_EDIT2);
            hEdit2 = GetDlgItem(hDlg, IDC_EDIT3);
            hEdit3 = GetDlgItem(hDlg, IDC_EDIT4);

            SetWindowText(hEditSet, "0");
            SetWindowText(hEdit1, "0");
            SetWindowText(hEdit2, "0");
            SetWindowText(hEdit3, "0");

            hArray[0] = hEdit2;
            hArray[1] = hEdit3;
            hArray[2] = hEdit4;
            break;
        }
    case WM_COMMAND:
        {
            switch (LOWORD (wParam))
            {
            case IDC_BUTTON_BEGIN:
                {
                    CreateThread(NULL, 0, ThreadBegin, NULL, 0, NULL);

                    return TRUE;
                }
            }
            break;
        }
        break;
    }

    return bRet;
}

int APIENTRY WinMain(HINSTANCE hInstance,
                     HINSTANCE hPrevInstance,
                     LPSTR     lpCmdLine,
                     int       nCmdShow)
{
    hAppinstance = hInstance;
    DialogBox(hInstance, MAKEINTRESOURCE(IDD_DIALOG_MAIN), NULL, MainDlgProc);

    return 0;
}
```

![image-20220310110229595](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-4f24ba56c0344ffc4496266f2bd44028dffdebcb.png)

总结
==

线程互斥
----

### 前言

当多个线程访问同一个全局变量，或者同一个资源(比如打印机)的时候，需要进行线程间的互斥操作，来保证访问的安全性.

### 临界区&amp;互斥体

#### 各自特点

```php
临界区:
初始化:Initialize-CriticalSection          
进入互斥区域:Enter-CriticalSection            
离开互斥区域:Leave-CriticalSection            
销毁:DeleteCriticalSection

互斥体:
初始化:CreateMutex     
进入互斥区域:WaitForSingleObject          
离开互斥区域:ReleaseMutex         
销毁:CloseHandle
```

#### 区别

1、临界区只能用于进程内的线程互斥，性能较好

2、互斥体属于内核对象，可以用于进程间的线程互斥，性能较差.

3、线程意外终究时，互斥体可以正常执行，因为它是内核对象，内核可以检测到当前线程已经结束了

线程同步
----

### 前言

当有多个线程同时执行时，可能需要线程按照一定的顺序执行

### 事件&amp;信号量

#### 各自特点

```php
事件:

创建               使事件进入触发状态      使事件进入未触发状态              销毁

CreateEvent         SetEvent              ResetEvent            CloseHandle

信号量:                                

创建                      递减计数                    递增计数                    销毁

CreateSemaphore     WaitForSingleObject         ReleaseSemaphore            CloseHandle
```

#### 区别

```php
1、都是内核对象，使用完毕后应该关闭句柄

2、信号量可以用于相当复杂的线程同步控制
```

进程
==

进程的创建步骤
-------

步骤一：

当系统启动后，创建一个进程，`Explorer.exe` --&gt;是桌面进程

步骤二：

当用户双击某一个EXE时，Explorer 进程使用CreateProcess函数创建被双击的EXE进程

简单来说：我们在桌面上双击创建的进程都是Explorer进程的子进程

使用`XueTr.exe`

我们可以找到

```php
explore.exe 进程ID:1548 父进程ID:1484
```

注：它的父进程，创建完`explore.exe`后就被终结了

父进程挂了，子进程依然可以执行

![image-20220310160611596](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-f8463ff8ff2bacb96ecb3e3d38ba8ee928649e8b.png)

当我们在桌面启动一个exe

可以看到它的父进程ID就是`explore.exe`

![image-20220310160904028](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-3c1017359d77ec72f0de66f874c5cbccd2f2f3c9.png)

进程的创建过程
-------

### 一、创建内核对象

注：句柄表是为了保证内核对象的安全

![image-20220310162519457](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-5bedb1edc06e964337e91fae8cef423035df3ccc.png)

### 二、分配4GB的虚拟空间(Win2位)

![image-20220310162921177](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-17e93b7643137ba29a26f94377f7cb3b562701cc.png)

### 三、创建进程的主线程

当进程的空间创建完毕，EXE与导入表中的DLL都正确加载完毕后，会创建一个线程

当线程得到CPU的时候，程序就正开始指向了，EIP的初始值设定为：ImageBase+OEP

```php
HANDLE CreateThread(                                    
   PSECURITY_ATTRIBUTES psa,                                    
   DWORD cbStack,                                   
   PTHREAD_START_ROUTINE pfnStartAddr,                                  
   PVOID pvParam,                                   
   DWORD fdwCreate,                                 
   PDWORD pdwThreadID); 
```

当进程创建成功后，会将进程句柄、主线程句柄、进程ID以及主线程ID存储在CreateProcess的最后一个 OUT 参数

```php
typedef struct _PROCESS_INFORMATION                                 
{                                   
   HANDLE hProcess;             //进程句柄                  
   HANDLE hThread;              //主线程句柄                 
   DWORD dwProcessId;           //进程ID                  
   DWORD dwThreadId;            //线程ID                  
} PROCESS_INFORMATION;
```

### 参数解析

我们要得到的是：创建新进程的句柄、ID，主线程的句柄

```php
BOOL CreateProcess(                 
   PCTSTR pszApplicationName, //应用程序名(常量字符串)                    
   PTSTR pszCommandLine, //控制行参数                    
   PSECURITY_ATTRIBUTES psaProcess,                 
   PSECURITY_ATTRIBUTES psaThread,                  
   BOOL bInheritHandles, //是否允许当前进程继承父进程中，允许被继承的句柄              
   DWORD fdwCreate,                 
   PVOID pvEnvironment,                 
   PCTSTR pszCurDir,                    
   PSTARTUPINFO psiStartInfo, //out类型参数，应用程序的状态             
   PPROCESS_INFORMATION ppiProcInfo //out类型参数，这个结构体是用来接收进程句柄、主线程句柄、进程ID、线程ID
);
```

`PSTARTUPINFO psiStartInfo`参数的结构体

我们只需要给第一个参数赋值即可

```php
typedef struct _STARTUPINFO
{           
   DWORD cb; //当前结构体的大小     
   PSTR lpReserved;         
   PSTR lpDesktop;          
   PSTR lpTitle;            
   DWORD dwX;           
   DWORD dwY;           
   DWORD dwXSize;           
   DWORD dwYSize;           
   DWORD dwXCountChars;         
   DWORD dwYCountChars;         
   DWORD dwFillAttribute;           
   DWORD dwFlags;           
   WORD wShowWindow;            
   WORD cbReserved2;            
   PBYTE lpReserved2;           
   HANDLE hStdInput;            
   HANDLE hStdOutput;           
   HANDLE hStdError;            
} STARTUPINFO, *LPSTARTUPINFO;
```

`PPROCESS_INFORMATION ppiProcInfo`参数的结构体

```php
typedef struct _PROCESS_INFORMATION         
{                   
   HANDLE hProcess;             //进程句柄
   HANDLE hThread;              //主线程句柄
   DWORD dwProcessId;           //进程ID
   DWORD dwThreadId;            //线程ID
} PROCESS_INFORMATION;
```

可以有三种方式去传递

第一种方式：

使用第一个参数

特点：需要绝对路径

```php
TCHAR szApplicationName[] =TEXT("c://program files//internet explorer//iexplore.exe");              

BOOL res = CreateProcess(               
    szApplicationName,          
    NULL,           
    NULL,           
    NULL,           
    FALSE,          
    CREATE_NEW_CONSOLE,             
    NULL,           
    NULL, &si, &pi);
```

第二种方式

使用第二个参数

特点：

1、可以直接传入参数，前提是exe可以接收这个参数

2、可以写相对路径`iexplore`，但是它是不安全的，它会默认给加上一个`.exe`--&gt;`iexplore.exe`

查找顺序：当前程序的目录--&gt;系统环境变量--&gt;操作系统目录

都没有找见的话，创建失败

```php
TCHAR szCmdline[] =TEXT("c://program files//internet explorer//iexplore.exe http://www.baidu.com");         

BOOL res = CreateProcess(               
    NULL,           
    szCmdline,          
    NULL,           
    NULL,           
    FALSE,          
    CREATE_NEW_CONSOLE,             
    NULL,           
    NULL, &si, &pi);
```

第三种方式：

组合使用

注意：第二个参数进行传参，记得有一个空格

```php
TCHAR szCmdline[] =TEXT(" http://www.baidu.com");               

BOOL res = CreateProcess(               
    TEXT("c://program files//internet explorer//iexplore.exe"),             
    szCmdline,          
    NULL,           
    NULL,           
    FALSE,          
    CREATE_NEW_CONSOLE,             
    NULL,           
    NULL, &si, &pi);
```

句柄&amp;ID
---------

1、都是系统分配的一个编号，句柄是`客户程序`使用、ID主要是`系统调度`时使用

2、调用CloseHandle关闭进程或者线程句柄的时候，只是让内核计数器减少一个，并不是终止进程或者线程

**进程或线程将继续运行，直到它自己终止运行**

3、进程ID和线程ID并非是永久性控制

进程ID与线程ID是不可能相同。但不要通过进程或者线程的ID来操作进程或者线程，因为，这个编号是会重复使用的，也就是说，当你通过ID=100这个编号去访问一个进程的时候，它已经结束了，而且系统将这个编号赋给了另外一个进程或者线程

程序挂了之后，编号会重复使用

进程的终止
-----

### 整个过程

```php
1、进程中剩余的所有线程全部终止运行

2、进程指定的所有用户对象均被释放(应用层)，所有内核对象均被关闭(内核层)

3、进程内核对象的状态未通知-->已通知的状态

4、进程内核对象的使用计数递减1
```

### 三种方式

```php
1、VOID　ExitProcess(UINT fuExitCode)                                 //进程自己调用

2、BOOL TerminateProcess(HANDLE hProcess, UINT fuExitCode);          //终止其他进程

3、ExitThread                                                        //终止进程中的所有线程，进程也会终止
```

### 退出码

用来获取进程是如何退出的

```php
BOOL GetExitCodeProcess(HANDLE hProcess,PDWORD pdwExitCode);
```

句柄的继承
=====

前言
--

可以实现，不同的进程拥有相同的内核对象

代码示例
----

进程A的代码

```php
// test1.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <windows.h>

int main(int argc, char* argv[])
{
    char szBuffer[256] = {0};                           
    char szHandle[8] = {0};

    //若要创建能继承的句柄，父进程必须指定一个SECURITY_ATTRIBUTES(安全属性)结构并对它进行初始化
    SECURITY_ATTRIBUTES sa;

    sa.nLength = sizeof(sa); //结构体大小                    
    sa.lpSecurityDescriptor = NULL; //默认安全属性                    
    sa.bInheritHandle = TRUE; //是否可以继承

    //创建一个可以被继承的内核对象
    //注意第一个参数是:安全属性
    //我们手动创建一个安全属性的结构体
    //当我们填NULL:表示系统默认，句柄表中填的就是0，不能继承    
    HANDLE g_hEvent = CreateEvent(&sa, TRUE, FALSE, NULL);

    //转换成字符串，作为命令行参数
    sprintf(szHandle,"%x",g_hEvent);                            
    sprintf(szBuffer,"C:/test2.exe %s",szHandle);                           

    //定义创建进程需要用的结构体                         
    STARTUPINFO si = {0};                               
    PROCESS_INFORMATION pi;                         
    si.cb = sizeof(si);

    //创建子进程，注意第5个参数:设置子进程可以进程父进程中句柄表为1复制到子进程句柄表
    BOOL res = CreateProcess(                   
        NULL,                   
        szBuffer,                   
        NULL,                   
        NULL,                   
        TRUE, //TRUE的时候，说明当前进程可以继承父进程的句柄表，复制父进程中句柄表为1复制到当前进程句柄表
        CREATE_NEW_CONSOLE,
        NULL,       
        NULL, &si, &pi);

    //设置事件为已通知                          
    SetEvent(g_hEvent);                         

    //关闭句柄，内核对象并不会被销毁                           
    CloseHandle(g_hEvent);
    return 0;
}
```

进程B的代码

注：将进程B的代码编译链接生成的exe文件为test2.exe

将其复制到目录：`C:/test2.exe`

```php
// test2.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <windows.h>

int main(int argc, char* argv[])
{
    char szBuffer[256] = {0};

    //argv[0]:当前内存的地址
    //argv[1]:传入的命令行参数
    memcpy(szBuffer,argv[1],8);                         

    DWORD dwHandle = 0;                         

    //字符串转成DWORD
    sscanf(szBuffer,"%x",&dwHandle);                            

    printf("%s\n",argv[0]);                         

    printf("%x\n",dwHandle);                            

    //重新转成句柄
    //编号拿过来之后，重新转型就可以用了，因为它已经继承过来了，句柄表中是有的
    HANDLE g_hEvent = (HANDLE)dwHandle;                     

    printf("开始等待.....\n");                  
    //当事件变成已通知时                             
    WaitForSingleObject(g_hEvent, INFINITE);                            

    DWORD dwCode = GetLastError();                          

    printf("等到消息.....%x\n",dwCode);                         

    getchar();
    return 0;
}
```

断点调试
----

现在子进程已经创建了

![image-20220311093746470](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-eaf9e9b81a793c63de65729f28fcadfbea476810.png)

断到这里了

![image-20220311093811141](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-dfa8bf5159d2372da744adad6a4319cc9655ef5d.png)

F10单步将事件设为已通知

可以看到成功继承

![image-20220311093906283](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-bae0a96d000f6743106b1c8d24c75c942bdeb45f.png)

![image-20220311093925239](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-e780cc56355680e922bc18e45ea8d79c4fe2568b.png)

挂起&amp;创建进程
===========

前言
--

空间分了，但是内容还没有给

参数分析
----

注意第三、第四个参数

```php
BOOL CreateProcess(
  LPCTSTR lpApplicationName,                 //应用程序名(常量字符串)
  LPTSTR lpCommandLine,                      //控制行参数
  LPSECURITY_ATTRIBUTES lpProcessAttributes, //当前进程的子进程是否可以继承刚刚创建的这个进程的进程句柄
  LPSECURITY_ATTRIBUTES lpThreadAttributes,  //当前进程的子进程是否可以继承刚刚创建的这个进程的线程的句柄
  BOOL bInheritHandles,                      //是否允许当前进程继承父进程中，允许被继承的句柄
  DWORD dwCreationFlags,                     // creation flags
  LPVOID lpEnvironment,                     
  //传入CREATE_NEW_CONSOLE:表示子进程和父进程都有自己独立的控制台
  //传入NULL:子进程将自己输出的信息打印到父进程

  LPCTSTR lpCurrentDirectory,         
  //进程的当前目录，当创建子进程时，传入NULL，则子进程获取当前目录将获取父进程的目录
  LPSTARTUPINFO lpStartupInfo,               //out类型参数，应用程序的状态
  LPPROCESS_INFORMATION lpProcessInformation //out类型参数，这个结构体是用来接收进程句柄、主线程句柄、进程ID、线程ID
);
```

代码示例
----

单进程代码示例

```php
// test2.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <windows.h>

int main(int argc, char* argv[])
{
    STARTUPINFO ie_si = {0};                        
    PROCESS_INFORMATION ie_pi;                      
    ie_si.cb = sizeof(ie_si);

    TCHAR szBuffer[256] = "C:\\notepad.exe";
    //挂起进程
    CreateProcess(                      
        NULL,
        szBuffer,
        NULL,
        NULL,
        FALSE,
        CREATE_NEW_CONSOLE,
        NULL,
        NULL,
        &ie_si,
        &ie_pi
        );          

    //恢复执行
    ResumeThread(ie_pi.hThread);
    return 0;
}
```

![image-20220311115941018](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-5aa2dee606db6334e8941b5981b936d2d0b96829.png)

两个进程联动示例

进程A的代码

```php
// test1.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <windows.h>

int main(int argc, char* argv[])
{
    char szBuffer[256] = {0};                           
    char szHandle[8] = {0};                         

    SECURITY_ATTRIBUTES ie_sa_p;                            
    ie_sa_p.nLength = sizeof(ie_sa_p);                          
    ie_sa_p.lpSecurityDescriptor = NULL;                            
    ie_sa_p.bInheritHandle = TRUE;                          

    SECURITY_ATTRIBUTES ie_sa_t;                            
    ie_sa_t.nLength = sizeof(ie_sa_t);                          
    ie_sa_t.lpSecurityDescriptor = NULL;                            
    ie_sa_t.bInheritHandle = TRUE;                          
    //创建一个可以被继承的内核对象,此处是个进程                         
    STARTUPINFO ie_si = {0};                            
    PROCESS_INFORMATION ie_pi;                          
    ie_si.cb = sizeof(ie_si);                           

    TCHAR szCmdline[] =TEXT("c://program files//internet explorer//iexplore.exe");

    //创建一个进程
    //看第三个参数和第四个参数
    /*
    句柄表中:
        X   进程内核对象  1
        Y   线程内核对象  1
   */
    CreateProcess(                          
        NULL,                       
        szCmdline,                      
        &ie_sa_p, //设置进程可被继承的安全属性 ie_sa_p.bInheritHandle = TRUE;                
        &ie_sa_t, //设置线程可被继承的安全属性 ie_sa_t.bInheritHandle = TRUE;                        
        TRUE,                       
        CREATE_NEW_CONSOLE,                         
        NULL,                       
        NULL, &ie_si, &ie_pi);                      

    //进程句柄、线程句柄，命令行参数传进来                            
    sprintf(szHandle,"%x %x",ie_pi.hProcess,ie_pi.hThread);                         
    sprintf(szBuffer,"C:/z2.exe %s",szHandle);                          

    //定义创建进程需要用的结构体                         
    STARTUPINFO si = {0};                               
    PROCESS_INFORMATION pi;                         
    si.cb = sizeof(si);                         

    //创建子进程
    //注意第5个参数:说明当前进程可以继承父进程的句柄表，复制父进程中句柄表为1复制到当前进程句柄表
    BOOL res = CreateProcess(                           
        NULL,                       
        szBuffer,                       
        NULL,                       
        NULL,                       
        TRUE,                       
        CREATE_NEW_CONSOLE,                         
        NULL,                       
        NULL, &si, &pi);                        

    return 0;
}
```

进程B的代码

```php
// test2.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <windows.h>

int main(int argc, char* argv[])
{
    //进程句柄
    DWORD dwProcessHandle = -1;

    //线程句柄
    DWORD dwThreadHandle = -1;
    char szBuffer[256] = {0};

    //argv[0]:当前内存的地址
    //argv[1]:传入的命令行参数
    //继承过来的进程ID给dwProcessHandle
    memcpy(szBuffer,argv[1],8);                     
    sscanf(szBuffer,"%x",&dwProcessHandle);                     

    //继承过来的线程ID给dwThreadHandle
    memset(szBuffer,0,256);                     
    memcpy(szBuffer,argv[2],8);                     
    sscanf(szBuffer,"%x",&dwThreadHandle);

    printf("获取IE进程、主线程句柄\n");                       
    Sleep(10000);                       
    //挂起主线程                     
    printf("挂起主线程\n");                      
    ::SuspendThread((HANDLE)dwThreadHandle);                        

    Sleep(10000);                       

    //恢复主线程                     
    ::ResumeThread((HANDLE)dwThreadHandle);                     
    printf("恢复主线程\n");                      

    Sleep(10000);                       

    //关闭浏览器ID进程                     
    ::TerminateProcess((HANDLE)dwProcessHandle,1);                      
    ::WaitForSingleObject((HANDLE)dwProcessHandle, INFINITE);                       

    printf("ID进程已经关闭.....\n");                      

    return 0;
}
```

总结
--

进行应用：

1、挂起的方式创建进程，获取进程的ImageBase和AddressOfEntryPoint

```php
// test2.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <windows.h>

int main(int argc, char* argv[])
{
    STARTUPINFO ie_si = {0};                            
    PROCESS_INFORMATION ie_pi;                          
    ie_si.cb = sizeof(ie_si);                           

    //以挂起的方式创建进程                            
    TCHAR szBuffer[256] = "C:\\notepad.exe";                            
    CreateProcess(                          
        NULL,                    // name of executable module                       
        szBuffer,                // command line string                     
        NULL,                    // SD  
        NULL,                    // SD              
        FALSE,                   // handle inheritance option                       
        CREATE_SUSPENDED,        // creation flags                      
        NULL,                    // new environment block                       
        NULL,                    // current directory name                      
        &ie_si,                  // startup information                     
        &ie_pi                   // process information                     
        );

    CONTEXT contx;

    //获取其他所有的寄存器
    contx.ContextFlags = CONTEXT_FULL;              

    //获取主线程的上下文对象，首先要知道主线程的句柄
    GetThreadContext(ie_pi.hThread, &contx);                            

    //获取入口点                         
    DWORD dwEntryPoint = contx.Eax;                         

    //获取ImageBase
    //contx.Ebx+8，是一个地址，它里面存储的值才是ImageBase
    //注:这个地址它是notepad.exe的地址，不是我们程序本身的地址
    char* baseAddress = (CHAR *) contx.Ebx+8;                           

    memset(szBuffer,0,256);                         

    //读其他进程的ImageBase
    ReadProcessMemory(ie_pi.hProcess,baseAddress,szBuffer,4,NULL);                          

    ResumeThread(ie_pi.hThread);                            

    return 0;
}
```

2、修改外壳程序的内容，注意要修改程序的ImageBase和入口点

3、将恶意程序拉伸，替换外壳程序

4、恢复执行