起因
==

有一天打开 github 的 explore页面，发现推送了一个 [sboot\_stm32](https://github.com/dmitrystu/sboot_stm32) 的项目，之前也一直对USB协议栈的实现感兴趣，于是就分析了一下，分析完 `sboot_stm32` 后，然后花了 2 天在 [google](https://www.google.com/search?q=USB+Device+Stack+github&sxsrf=ALeKk017s3KYyzHJmygebf2l7FtwPM6xFg%3A1623324126270&ei=3vXBYJiBEJPTmAWmhaWAAw&oq=USB+Device+Stack+github&gs_lcp=Cgdnd3Mtd2l6EANQ1ghY1ghg0wloAHACeACAAQCIAQCSAQCYAQCgAQGqAQdnd3Mtd2l6wAEB&sclient=gws-wiz&ved=0ahUKEwiY6JrP-YzxAhWTKaYKHaZCCTAQ4dUDCA4&uact=5) 上找了一些类似的嵌入式USB协议栈的源码进行了分析。

下面对分析的一些思路和发现进行分享，发现的都是一些内存越界、溢出相关的漏洞，具体数目如下：

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-f70480634fab543a5a1e2dc79701a5e7b99169b1.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-f70480634fab543a5a1e2dc79701a5e7b99169b1.jpg)

不过大部分开发者还没回复，最终可能会有偏差.

漏洞挖掘
====

sboot\_stm32
------------

issue 地址

```php
https://github.com/dmitrystu/sboot_stm32/issues/35
```

`sboot_stm32` 是基于 `libusb_stm32` 开发的 usb 协议栈的上层应用，类似于 HTTP 和 TCP 之间的关系。我们首先来看一下 `libusb_stm32` 对 usb 协议数据的处理。

首先我们要明确 USB 本身就是一个收发USB数据的外设，那么在代码中处理USB数据包的逻辑肯定是：

1. 控制USB外设，从总线收包
2. 调用处理函数对数据包进行解析、处理

为了快速定位数据处理函数，我们可以从协议规范入手，对于 USB 协议而言，通信的第一步是传输 USB control request，所以可以根据文件名、数据结构的定义和协议规范中对 USB control request 的数据结构进行对比就可以找到协议栈中的数据处理函数，最后再依次回溯，可以找到最上层的收包函数。

在 `libusb_stm32` 中描述 USB control request 数据包的结构体定义如下

```php
/**\brief Represents generic USB control request.*/
typedef struct {
    uint8_t     bmRequestType;  /**<\brief This bitmapped field identifies the characteristics of
                                 * the specific request.*/
    uint8_t     bRequest;       /**<\brief This field specifies the particular request.*/
    uint16_t    wValue;         /**<\brief It is used to pass a parameter to the device, specific to
                                 * the request.*/
    uint16_t    wIndex;         /**<\brief It is used to pass a parameter to the device, specific to
                                 * the request.*/
    uint16_t    wLength;        /**<\brief This field specifies the length of the data transferred
                                 * during the second phase of the control transfer.*/
    uint8_t     data[];         /**<\brief Data payload.*/
} usbd_ctlreq;
```

处理 control request 的函数为 usbd\_process\_ep0 .

```php
static void usbd_process_ep0 (usbd_device *dev, uint8_t event, uint8_t ep) {
    switch (event) {
    case usbd_evt_epsetup:
        /* force switch to setup state */
        dev->status.control_state = usbd_ctl_idle;
        dev->complete_callback = 0;
    case usbd_evt_eprx:
        usbd_process_eprx(dev, ep);
        break;
    case usbd_evt_eptx:
        usbd_process_eptx(dev, ep);
        break;
    default:
        break;
    }
}
```

在 USB 设备中，端点（endpoint）是主机和设备之间进行通讯的基本单元，USB 设备间的通信实际是就是端点之间的通信，所以在USB代码中带 `endpoint/ep` 的函数比较有可能会数据收发有关。

`usbd_process_ep0` 就是用于处理 0 号端点的数据交互，实际数据处理位于 `usbd_process_eprx` .

```php
static void usbd_process_eprx(usbd_device *dev, uint8_t ep) {
    uint16_t _t;
    usbd_ctlreq *const req = dev->status.data_buf;

    ......................
    ......................
    // 驱动 USB外设收包
    _t = dev->driver->ep_read(ep, dev->status.data_buf, dev->status.data_count);

    // 处理收到的数据包
    switch (usbd_process_request(dev, req)) {
```

函数首先通过 ep\_read 收取数据包，然后调用 usbd\_process\_request 进行解析，usbd\_process\_request里面就会根据数据包的内容进入具体的分支去解析。

```php
static usbd_respond usbd_process_request(usbd_device *dev, usbd_ctlreq *req) {
    if (dev->control_callback) {
        usbd_respond r = dev->control_callback(dev, req, &(dev->complete_callback));
        if (r != usbd_fail) return r;
    }
    switch (req->bmRequestType & (USB_REQ_TYPE | USB_REQ_RECIPIENT)) {
    case USB_REQ_STANDARD | USB_REQ_DEVICE:
        return usbd_process_devrq(dev, req);
    case USB_REQ_STANDARD | USB_REQ_INTERFACE:
        return usbd_process_intrq(dev, req);
    case USB_REQ_STANDARD | USB_REQ_ENDPOINT:
        return usbd_process_eptrq(dev, req);
    default:
        break;
    }
    return usbd_fail;
}
```

如果用户设置了 `control_callback` ，就会先调用 `control_callback` 去解析数据，否则就进入标准的USB协议解析流程。

`sboot_stm32` 里面的两个漏洞就位于自己实现的 `control_callback` 函数中

```php
inline static void usbd_reg_control(usbd_device *dev, usbd_ctl_callback callback) {
    dev->control_callback = callback;
}
usbd_reg_control(&dfu, dfu_control);
```

下面分析一下 `dfu_control` 函数，关键代码如下

```php
static usbd_respond dfu_control (usbd_device *dev, usbd_ctlreq *req, usbd_rqc_callback *callback) {

    if ((req->bmRequestType & (USB_REQ_TYPE | USB_REQ_RECIPIENT)) == (USB_REQ_CLASS | USB_REQ_INTERFACE)) {
        switch (req->bRequest) {

        case USB_DFU_DNLOAD:
            return dfu_dnload(req->data, req->wLength);
        case USB_DFU_UPLOAD:
            return dfu_upload(dev, req->wLength);
        case USB_DFU_GETSTATUS:
            return dfu_getstatus(req->data);
        case USB_DFU_CLRSTATUS:
            return dfu_clrstatus();
        case USB_DFU_GETSTATE:
            return dfu_getstate(req->data);
        case USB_DFU_ABORT:
            return dfu_abort();
        default:
            return dfu_err_badreq();
        }
    }
    return usbd_fail;
}
```

函数入参中 `req` 是直接从 `USB` 总线上接收的，可以认为是有害的数据，函数根据 bmRequestType 和 bRequest 来决定下一步的处理。

漏洞位于下面两个 case:

```php
        case USB_DFU_DNLOAD:
            return dfu_dnload(req->data, req->wLength);
        case USB_DFU_UPLOAD:
            return dfu_upload(dev, req->wLength);
```

问题的根因都一样，如果 **req-&gt;wLength 过大**，就会导致溢出。

tinyusb
-------

issue 地址

```php
https://github.com/hathach/tinyusb/issues/880
```

tinyusb 处理USB数据包的入口函数为 tuh\_task，关键代码如下

```php
void tuh_task(void)
{
  while (1)
  {
    if ( !osal_queue_receive(_usbd_q, &event) ) return;

    switch (event.event_id)
    {
      case DCD_EVENT_SETUP_RECEIVED:
        // Process control request
        if ( !process_control_request(event.rhport, &event.setup_received) )
        {
      break;

      case HCD_EVENT_XFER_COMPLETE:
      {
        usbh_device_t* dev = &_usbh_devices[event.dev_addr];
        uint8_t const ep_addr = event.xfer_complete.ep_addr;
        uint8_t const epnum   = tu_edpt_number(ep_addr);
        uint8_t const ep_dir  = tu_edpt_dir(ep_addr);

        if ( 0 == epnum )
        {
          usbh_control_xfer_cb(event.dev_addr, ep_addr, event.xfer_complete.result, event.xfer_complete.len);
        }else
        {
          uint8_t drv_id = dev->ep2drv[epnum][ep_dir];
          usbh_class_drivers[drv_id].xfer_cb(event.dev_addr, ep_addr, event.xfer_complete.result, event.xfer_complete.len);
        }
      }
      break;

```

其实主要就是根据收到的事件类型来调用特定函数对端点的数据进行解析：

1. process\_control\_request： 处理 setup 数据包
2. usbh\_control\_xfer\_cb： 处理 0 号端点的数据
3. usbh\_class\_drivers\[drv\_id\].xfer\_cb： 处理其他端点的数据
    
    process\_control\_request 的关键代码如下

```php
static bool process_control_request(uint8_t rhport, tusb_control_request_t const * p_request)
{

  switch ( p_request->bmRequestType_bit.recipient )
  {
    case TUSB_REQ_RCPT_DEVICE:
      if ( TUSB_REQ_TYPE_CLASS == p_request->bmRequestType_bit.type )
      {

        usbd_class_driver_t const * driver = get_driver(_usbd_dev.itf2drv[itf]);

        // forward to class driver: "non-STD request to Interface"
        return invoke_class_control(rhport, driver, p_request);
      }
     case ...................
       ................
       ................
```

这里就是常规的利用 switch 根据请求的类型进行相应的处理，其中 invoke\_class\_control 用于调用其他代码注册的处理函数，对数据包进行处理

```php
static bool invoke_class_control(uint8_t rhport, usbd_class_driver_t const * driver, tusb_control_request_t const * request)
{
  return driver->control_xfer_cb(rhport, CONTROL_STAGE_SETUP, request);
}
```

可以看到实际是调用 `control_xfer_cb` 回调函数进行解析，于是我们搜索 `.control_xfer_cb` 就可以找到所有注册的 control 请求的处理函数，比如

```php
  {
    DRIVER_NAME("CDC")
    .init             = cdcd_init,
    .reset            = cdcd_reset,
    .open             = cdcd_open,
    .control_xfer_cb  = cdcd_control_xfer_cb,
    .xfer_cb          = cdcd_xfer_cb,
    .sof              = NULL
  },
```

### dfu\_moded\_control\_xfer\_cb 越界访问

```php
bool dfu_moded_control_xfer_cb(uint8_t rhport, uint8_t stage, tusb_control_request_t const * request)
{
  switch (request->bRequest)
  {

    case DFU_REQUEST_DETACH:
    case DFU_REQUEST_UPLOAD:
    case DFU_REQUEST_GETSTATUS:
    case DFU_REQUEST_CLRSTATUS:
    case DFU_REQUEST_GETSTATE:
    case DFU_REQUEST_ABORT:
    {
      if(stage == CONTROL_STAGE_SETUP)
      {
        return dfu_state_machine(rhport, request);
      }
    }
```

其中 request 从 usb 总线直接收上来，从该函数开始一个一个处理函数进行分析，就可以发现一些问题，比如 dfu\_req\_dnload\_setup

```php
static void dfu_req_dnload_setup(uint8_t rhport, tusb_control_request_t const * request)
{
  tud_control_xfer(rhport, request, _dfu_state_ctx.transfer_buf, request->wLength);
}
```

如果 `request->wLength` 比较大，就会导致越界读。

### netd\_xfer\_cb 整数溢出导致堆溢出漏洞

函数代码如下

```php
bool netd_xfer_cb(uint8_t rhport, uint8_t ep_addr, xfer_result_t result, uint32_t xferred_bytes)
{
  /* new packet received */
  if ( ep_addr == _netd_itf.ep_out )
  {
    handle_incoming_packet(xferred_bytes);
  }
```

问题出在 handle\_incoming\_packet 函数

```php
static void handle_incoming_packet(uint32_t len)
{
  uint8_t *pnt = received;
  uint32_t size = 0;

  if (_netd_itf.ecm_mode)
  {
    size = len;
  }
  else
  {
    rndis_data_packet_t *r = (rndis_data_packet_t *) ((void*) pnt);
    if (len >= sizeof(rndis_data_packet_t))
      if ( (r->MessageType == REMOTE_NDIS_PACKET_MSG) && (r->MessageLength <= len))
        if ( (r->DataOffset + offsetof(rndis_data_packet_t, DataOffset) + r->DataLength) <= len)
        {
          pnt = &received[r->DataOffset + offsetof(rndis_data_packet_t, DataOffset)];
          size = r->DataLength;
        }
  }

  if (!tud_network_recv_cb(pnt, size))
  {
```

`r->DataLength` 和 `r->DataOffset` 的类型都是`uint32_t` ，且都是从 USB 总线上接收。

当`r->DataLength=0xFFFFFFFF` 且 `r->DataOffset` 是一个比较小的值, 就会导致整数溢出，从而通过下面的检查.

```php
if ( (r->DataOffset + offsetof(rndis_data_packet_t, DataOffset) + r->DataLength) <= len)
```

然后在 `tud_network_recv_cb` 时就会越界。

lufa
----

issue 链接

```php
https://github.com/abcminiuser/lufa/issues/172
```

### 定位数据入口

结合代码文件名、函数中使用到的结构体、以及USB的规范，可以快速定位到处理控制传输的代码

```php
void USB_Device_ProcessControlRequest(void)
{
    USB_ControlRequest.bmRequestType = Endpoint_Read_8();
    USB_ControlRequest.bRequest      = Endpoint_Read_8();
    USB_ControlRequest.wValue        = Endpoint_Read_16_LE();
    USB_ControlRequest.wIndex        = Endpoint_Read_16_LE();
    USB_ControlRequest.wLength       = Endpoint_Read_16_LE();

    EVENT_USB_Device_ControlRequest();
    .................
    .................

    if (Endpoint_IsSETUPReceived())
    {
        uint8_t bmRequestType = USB_ControlRequest.bmRequestType;

        switch (USB_ControlRequest.bRequest)
        {
            case ....
            ......
```

lufa的代码中会使用封装好的 `Endpoint_Read_xx` 从端点中获取数据，函数开头首先获取了 USB\_ControlRequest 的各个字段，然后根据 `USB_ControlRequest.bRequest` 进行相应的处理。

对于源码审计而言，找到入口后跟数据流即可，简单跟踪了USB\_Device\_ProcessControlRequest里面的分支，没有发现什么问题，其实在 device 侧的 控制传输 的处理逻辑都相对比较简单，一般不容易出现问题，在device 侧更容易出现问题的是那些USB应用层的协议，比如 CDC、RNDIS等。

于是又翻了翻代码的目录，发现一些路径下存在一些USB应用层协议的实现，比如

```php
E:\data\USB_VULN\lufa-master\Demos\Device\ClassDriver
λ ls
AudioInput/   DualVirtualSerial/  KeyboardMouse/             MassStorageKeyboard/  VirtualSerial/
AudioOutput/  GenericHID/         KeyboardMouseMultiReport/  MIDI/                 VirtualSerialMassStorage/
CCID/         Joystick/           makefile                   Mouse/                VirtualSerialMouse/
DualMIDI/     Keyboard/           MassStorage/               RNDISEthernet/
```

或者我们可以通过全局搜索 `Endpoint_Read_` 来找到代码中会处理 USB 数据的位置，进而找到审计的入口。

代码思维导图

![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-323668689f0b5ed8242c042b908ceca075a048b7.png)

下面直接介绍几个典型的漏洞

### RNDISEthernet 控制请求处理溢出

在 USB\_Device\_ProcessControlRequest 里面，会先调用 EVENT\_USB\_Device\_ControlRequest 对数据进行处理，用户可以自己实现 EVENT\_USB\_Device\_ControlRequest 来实现自定义的控制传输

```php
void USB_Device_ProcessControlRequest(void)
{
    .........
    EVENT_USB_Device_ControlRequest(); // 调用回调函数进行处理
```

RNDISEthernet 实现的 `EVENT_USB_Device_ControlRequest` 如下

```php
void EVENT_USB_Device_ControlRequest(void)
{
    CheckIfMSCompatibilityDes criptorRequest();

    switch (USB_ControlRequest.bRequest)
    {
        case RNDIS_REQ_SendEncapsulatedCommand:
            if (USB_ControlRequest.bmRequestType == (REQDIR_HOSTTODEVICE | REQTYPE_CLASS | REQREC_INTERFACE))
            {
                Endpoint_ClearSETUP();

                /* Read in the RNDIS message into the message buffer */
                Endpoint_Read_Control_Stream_LE(RNDISMessageBuffer, USB_ControlRequest.wLength);
```

漏洞在于没有检查 `USB_ControlRequest.wLength` ，如果 `USB_ControlRequest.wLength` 大于 `RNDISMessageBuffer` 的大小就会导致全局变量的溢出。

### CCID\_Task 栈溢出漏洞

根据函数名可以大概猜测，CCID\_Task 应该是负责处理 CCID 协议数据的应用

```php
void CCID_Task(void)
{
    Endpoint_SelectEndpoint(CCID_OUT_EPADDR);

    uint8_t RequestBuffer[CCID_EPSIZE - sizeof(USB_CCID_BulkMessage_Header_t)];
    uint8_t ResponseBuffer[CCID_EPSIZE];
    Aborted = false;
    AbortedSeq = -1;

    if (Endpoint_IsOUTReceived())
    {
        USB_CCID_BulkMessage_Header_t CCIDHeader;
        CCIDHeader.MessageType = Endpoint_Read_8();
        CCIDHeader.Length      = Endpoint_Read_32_LE();
        CCIDHeader.Slot        = Endpoint_Read_8();
        CCIDHeader.Seq         = Endpoint_Read_8();

        switch (CCIDHeader.MessageType)
        {
            ........
            ........
```

函数首先切换端点，用于后续的数据传输，然后调用 Endpoint\_Read 从端点中获取 CCIDHeader， 最后根据 CCIDHeader.MessageType 来决定处理的方式，漏洞位于处理 CCID\_PC\_to\_RDR\_XfrBlock 请求时

```php
            case CCID_PC_to_RDR_XfrBlock:
            {
                uint8_t  Bwi            = Endpoint_Read_8();
                uint16_t LevelParameter = Endpoint_Read_16_LE();

                Endpoint_Read_Stream_LE(RequestBuffer, CCIDHeader.Length * sizeof(uint8_t), NULL);
```

这里直接使用 `CCIDHeader.Length` 来读取数据到 RequestBuffer 中， RequestBuffer是一个栈数组，大小为 64 字节，只要 **CCIDHeader.Length 大于 64** 就会栈溢出。

### IP\_ProcessIPPacket 越界访问

RNDIS 设备通过 USB 读取到以太报文后会调用 Ethernet\_ProcessPacket 对报文进行解析

```php
RNDIS_Device_ReadPacket(&Ethernet_RNDIS_Interface, &F rameIN.F rameData, &F rameIN.F rameLength);
Ethernet_ProcessPacket(&F rameIN, &F rameOUT);
```

最终会进入 IP\_ProcessIPPacket 解析 IP 数据包，关键代码如下：

```php
int16_t IP_ProcessIPPacket(Ethernet_F rame_Info_t* const F rameIN,
                           void* InDataStart,
                           void* OutDataStart)
{

    IP_Header_t* IPHeaderIN  = (IP_Header_t*)InDataStart;
    uint16_t HeaderLengthBytes = (IPHeaderIN->HeaderLength * sizeof(uint32_t));

    switch (IPHeaderIN->Protocol)
    {
        case PROTOCOL_ICMP:
            RetSize = ICMP_ProcessICMPPacket(F rameIN,
                                             &((uint8_t*)InDataStart)[HeaderLengthBytes],
                                             &((uint8_t*)OutDataStart)[sizeof(IP_Header_t)]);
            break;
```

问题在于**没有校验 IPHeaderIN-&gt;HeaderLength**， 从而会在后面使用 HeaderLengthBytes 时导致越界。

TeenyUSB
--------

issue 链接

```php
https://github.com/xtoolbox/TeenyUSB/issues/18
```

### 定位数据入口

TeenyUSB 代码逻辑还是比较清晰的，`USB_LP_CAN_RX0_IRQHandler` 为 USB 中断的处理函数

```php
void USB_LP_CAN_RX0_IRQHandler(void)
{
    while ((wIstr = GetUSB(drv)->ISTR) & USB_ISTR_CTR)
    {
        GetUSB(drv)->ISTR = (uint16_t)(USB_CLR_CTR);
        tusb_ep_handler(drv, wIstr & USB_ISTR_EP_ID);  // 处理端点的数据
    }
```

如果 USB 相关的中断就会进入 tusb\_ep\_handler 进行处理，关键代码如下

```php
void tusb_ep_handler(tusb_device_driver_t *drv, uint8_t EPn)
{
    uint16_t EP = PCD_GET_ENDPOINT(GetUSB(drv), EPn);
    if (EP & USB_EP_CTR_RX)
    {
        if (EPn == 0)
        {
            if (EP & USB_EP_SETUP)
            {
                // Handle setup packet
                uint8_t temp[8];
                tusb_read_ep0(drv, temp);
                tusb_device_ep_xfer_done(drv, EPn, temp, 8, 1);
            }
            else
            {
                // Handle ep 0 data packet
                tusb_recv_data(drv, EPn);
            }
        }
        else
        {
            tusb_recv_data(drv, EPn);
        }
    }
```

主要就是根据触发中断的端点号、数据传输类型调用相应的函数进行解析：

1. tusb\_device\_ep\_xfer\_done：处理 setup 请求
2. tusb\_recv\_data： 处理端点的数据请求，包括 ep0.

下面看 tusb\_recv\_data 的实现，关键的代码如下：

```php
// called by the ep data interrupt handler when got data
void tusb_recv_data(tusb_device_driver_t *drv, uint8_t EPn)
{
    tusb_ep_data *ep = &drv->Ep[EPn];
    uint16_t EP = PCD_GET_ENDPOINT(GetUSB(drv), EPn);
    ...............
    ...............
    if (ep->rx_buf && pma)
    {
        uint32_t len = tusb_pma_rx(drv, pma, ep->rx_buf + ep->rx_count);
        pma->cnt = 0;
        ep->rx_count += len;

        // 判断数据包是否以及传输完毕
        if (len != GetOutMaxPacket(drv, EPn) || ep->rx_count >= ep->rx_size)
        {
            if (tusb_device_ep_xfer_done(drv, EPn, ep->rx_buf, ep->rx_count, 0) == 0)
            {
                ep->rx_count = 0;
            }
            else
            {
                // of rx done not return success, change rx_count to rx_size, this will block
                // the data recieve
                ep->rx_count = ep->rx_size;
            }
        }
    }
```

`tusb_recv_data` 会接收端点的数据包，同时也会处理**分包传输**的场景，数据包传输完毕后进入 `tusb_device_ep_xfer_done` 对数据进行解析。

```php
int tusb_device_ep_xfer_done(tusb_device_driver_t *drv, uint8_t EPn, const void *data, int len, uint8_t isSetup)
{
    tusb_device_t *dev = (tusb_device_t *)tusb_dev_drv_get_context(drv);
    if (dev)
    {
        if (EPn == 0x00)
        {
            if (isSetup)
            {
                // endpoint 0, setup data out
                memcpy(&dev->setup, data, len);
                tusb_setup_handler(dev);
            }else if (dev->ep0_rx_done)
            {
                dev->ep0_rx_done(dev, data, len);
                dev->ep0_rx_done = NULL;
            }
        }
        else if (EPn & 0x80)
        {
            tusb_on_tx_done(dev, EPn & 0x7f, data, len);
        }
        else
        {
            return tusb_on_rx_done(dev, EPn, data, len);
        }
    }
```

主要就是根据端点的信息决定下一步的解析方式：

1. tusb\_setup\_handler：处理 setup 请求
2. ep0\_rx\_done： 处理从 ep0 收到的数据
3. tusb\_on\_rx\_done： 解析其他端点收到的数据，实际调用 backend-&gt;device\_recv\_done 函数进行解析。

tusb\_setup\_handler 代码如下

```php
void tusb_setup_handler(tusb_device_t *dev)
{
    tusb_setup_packet *setup_req = &dev->setup;
    // we pass all request to tusb_class_request, not only class request
    if (tusb_class_request(dev, setup_req))
    {
        return;
    }
    if ((setup_req->bmRequestType & USB_REQ_TYPE_MASK) == USB_REQ_TYPE_VENDOR)
    {
        if (tusb_vendor_request(dev, setup_req))
        {
            return;
        }
    }
    else if ((setup_req->bmRequestType & USB_REQ_TYPE_MASK) == USB_REQ_TYPE_STANDARD)
    {
        if (!tusb_standard_request(dev, setup_req))
        {
```

首先会通过 tusb\_class\_request 调用其他应用注册的回调函数对数据进行解析

```php
int tusb_class_request(tusb_device_t* dev, tusb_setup_packet* setup_req)
{
    tusb_device_config_t* dev_config = dev->user_data;
    if(dev_config && 
      (setup_req->bmRequestType & USB_REQ_RECIPIENT_MASK) == USB_REQ_RECIPIENT_INTERFACE ){
        uint16_t iInterfce = setup_req->wIndex;
        if(iInterfce<dev_config->if_count){
            tusb_device_interface_t* itf = dev_config->interfaces[iInterfce];
            if(itf && itf->backend && itf->backend->device_request){
                return itf->backend->device_request(itf, setup_req);
            }
        }
    }
    // the setup packet will be processed in Teeny USB stack
    return 0;
}
```

比如

```php
const tusb_device_backend_t cdc_device_backend = {
    .device_init = (int(*)(tusb_device_interface_t*))tusb_cdc_device_init,
    .device_request = (int(*)(tusb_device_interface_t*, tusb_setup_packet*))tusb_cdc_device_request,
    .device_send_done = (int(*)(tusb_device_interface_t*, uint8_t, const void*, int))tusb_cdc_device_send_done,
    .device_recv_done = (int(*)(tusb_device_interface_t*, uint8_t, const void*, int))tusb_cdc_device_recv_done,
};
```

其中 `device_recv_done` 在 `tusb_on_rx_done` 中被调用。

至此我们弄清楚了程序的收包逻辑，所以程序中解析数据的入口有以下几种：

1. `tusb_setup_handler` 解析标准的 `setup` 请求
2. `tusb_device_backend_t` 结构体中注册的 `device_request` 和 `device_recv_done`.
3. `dev->ep0_rx_done` 回调函数

代码思维导图

![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-6d03fe89c82cc60921a5200a4aeeb7072bf882f1.png)

下面介绍几个典型漏洞

### tusb\_rndis\_device\_request 溢出漏洞

关键代码如下

```php
static int tusb_rndis_device_request(tusb_rndis_device_t* cdc, tusb_setup_packet* setup_req)
{
    ...................
    ...................
    }else if(setup_req->bRequest == CDC_SEND_ENCAPSULATED_COMMAND){
        dev->ep0_rx_done = rndis_dataout_request;
        tusb_set_recv_buffer(dev, 0, cdc->encapsulated_buffer, setup_req->wLength);
        tusb_set_rx_valid(dev, 0);
        return 1;
    }
```

入参 setup\_req 是从 USB 总线中收上来的，问题在于**没有校验 setup\_req-&gt;wLength** ，直接通过 `tusb_set_recv_buffer` 让 USB 外设往 `cdc->encapsulated_buffer` 收数据，如果 wLength 过大，就会导致 `encapsulated_buffer` 溢出。

### msc\_scsi\_write\_10 越界读

msc 的收包和处理函数为 msc\_data\_out

```php
static void msc_data_out(tusb_msc_device_t* msc)
{
  switch(msc->state.stage){
    case MSC_STAGE_CMD:
      if(msc->state.cbw.signature != MSC_CBW_SIGNATURE || msc->state.data_out_length != BOT_CBW_LENGTH){
        // Got an error command
        msc_scsi_sense(msc, msc->state.cbw.lun, SCSI_SENSE_ILLEGAL_REQUEST, INVALID_CDB, 0);
        msc_bot_abort(msc);
        return;
      }
      msc->state.csw.signature = MSC_CSW_SIGNATURE;
      msc->state.csw.tag = msc->state.cbw.tag;
      msc->state.csw.data_residue = msc->state.cbw.total_bytes;
      handle_msc_scsi_command(msc);
      break;
    case MSC_STAGE_DATA:
      handle_msc_scsi_command(msc);
      break;
    default:
      msc->state.stage = MSC_STAGE_CMD;
      msc_prepare_rx(msc, &msc->state.cbw, BOT_CBW_LENGTH);
      break;
  }
}
```

这个函数会被循环调用，函数的大概逻辑是 首先 `msc_prepare_rx` 往 `msc->state.cbw` 里面收数据，然后解析 `msc->state.cbw` 里面的数据进行后续的处理，整个状态机通过 `msc->state.stage` 控制。

漏洞点

```php
static int msc_scsi_write_10(tusb_msc_device_t* msc)
{
  tusb_msc_cbw_t * cbw = &msc->state.cbw;
  tusb_msc_csw_t       * csw = &msc->state.csw;
  scsi_read_10_cmd_t* cmd = (scsi_read_10_cmd_t*)cbw->command;
    ......
    ......
    uint32_t block_addr = GET_BE32(cmd->logical_block_addr);
    uint32_t block_size = cbw->total_bytes/ GET_BE16(cmd->transfer_length);
    int length = msc->state.data_out_length;
    uint16_t block_count = length/block_size;

    if(msc->block_write){
      // TODO: support data buffer length less than the block size
      int xferred_length = cbw->total_bytes - csw->data_residue;

      // vuln !!! 
      length = msc->block_write(msc, cbw->lun, msc->state.data_buffer, block_addr + xferred_length/block_size, block_count);
```

问题在于没有检查 `block_count` ，导致 write 的时候会越界。

USBDevice
---------

issue 链接

```php
https://github.com/IntergatedCircuits/USBDevice/issues/28
```

### 定位数据入口

USBDevice 的收包的入口函数为 USB\_vDevIRQHandler ，关键代码如下

```php
void USB_vDevIRQHandler(USB_HandleType * pxUSB)
{
    uint32_t ulGINT = pxUSB->Inst->GINTSTS.w & pxUSB->Inst->GINTMSK.w;

        // 从USB外设接收数据
        ......................
        ......................

        /* OUT endpoint interrupts */
        if ((ulGINT & USB_OTG_GINTSTS_OEPINT) != 0)
        {
            uint8_t ucEpNum;

            /* Handle individual endpoint interrupts */
            for (ucEpNum = 0; xDAINT.b.OEPINT != 0; ucEpNum++, xDAINT.b.OEPINT >>= 1)
            {
                if ((xDAINT.b.OEPINT & 1) != 0)
                {
                    // 处理 out 端点接收到数据
                    USB_prvOutEpEventHandler(pxUSB, ucEpNum);
                }
            }
        }
```

函数首先从USB外设接收数据，数据接收完后调用 `USB_prvOutEpEventHandler` 对收到的数据进行处理

```php
static void USB_prvOutEpEventHandler(USB_HandleType * pxUSB, uint8_t ucEpNum)
{
    if ((ulEpFlags & USB_OTG_DOEPINT_STUP) != 0)
    {
        /* Process SETUP Packet */
        USB_vSetupCallback(pxUSB);
    }
    else if ((ulEpFlags & USB_OTG_DOEPINT_XFRC) != 0)
    {

        if ((ucEpNum > 0) || (pxEP->Transfer.Progress == pxEP->Transfer.Length))
        {
            /* 处理 data 包 */
            USB_vDataOutCallback(pxUSB, pxEP);
        }
```

主要就是根据硬件上报的状态决定是 setup 包还是 data 包的处理。

1. USB\_vSetupCallback： 处理 setup 包
2. USB\_vDataOutCallback： 处理 data 包

`USB_vSetupCallback` 实际为 `USBD_SetupCallback` 函数

```php
void USBD_SetupCallback(USBD_HandleType *dev)
{
    USBD_ReturnType retval = USBD_E_INVALID;

    dev->EP.OUT[0].State = USB_EP_STATE_SETUP;

    /* Route the request to the recipient */
    switch (dev->Setup.RequestType.Recipient)
    {
        case USB_REQ_RECIPIENT_DEVICE:
            retval = USBD_DevRequest(dev);
            break;

        case USB_REQ_RECIPIENT_INTERFACE:
            retval = USBD_IfRequest(dev);
            break;

        case USB_REQ_RECIPIENT_ENDPOINT:
            retval = USBD_EpRequest(dev);
            break;

        default:
            break;
    }
```

代码流程非常清晰，就是根据 `RequestType` 来分发请求，这里需要注意的是 `USBD_IfRequest` 里面会调用 `Class->SetupStage` 来对请求进行处理，USB应用可以自己实现相应的回调函数

```php
static inline USBD_ReturnType USBD_IfClass_SetupStage(
        USBD_IfHandleType *itf)
{
    if (itf->Class->SetupStage == NULL)
    {   return USBD_E_INVALID; }
    else
    {   return itf->Class->SetupStage(itf); }
}
```

因此 `SetupStage` 回调函数也是一个处理数据的点。

处理 data 包实际进入 `USBD_EpOutCallback`

```php
void USBD_EpOutCallback(USBD_HandleType *dev, USBD_EpHandleType *ep)
{
    ep->State = USB_EP_STATE_IDLE;

    if (ep == &dev->EP.OUT[0])
    {
        USBD_CtrlOutCallback(dev);
    }
    else
    {
        USBD_IfClass_OutData(dev->IF[ep->IfNum], ep);
    }
}
```

函数根据端点的类型，来决定调用对应的回调函数

![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-51019b6aaae32da64119da24ac091c1ff9fe87ea.png)

一个注册回调函数的示例如下：

```php
/* NCM interface class callbacks structure */
static const USBD_ClassType ncm_cbks = {
    .GetDes criptor  = (USBD_IfDescCbkType)  ncm_getDesc,
    .GetString      = (USBD_IfStrCbkType)   ncm_getString,
    .Init           = (USBD_IfCbkType)      ncm_init,
    .Deinit         = (USBD_IfCbkType)      ncm_deinit,
    .SetupStage     = (USBD_IfSetupCbkType) ncm_setupStage,
    .DataStage      = (USBD_IfCbkType)      ncm_dataStage,
    .OutData        = (USBD_IfEpCbkType)    ncm_outData,
    .InData         = (USBD_IfEpCbkType)    ncm_inData,
};
```

代码的思维导图

![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-80b04e45cf5f765a0f3777ea9b41ffcb3bd7ec6f.png)

下面介绍几个典型漏洞

### USBD\_CtrlReceiveData 溢出漏洞

函数的定义如下

```php
USBD_ReturnType USBD_CtrlReceiveData(USBD_HandleType *dev, void *data)
{
    USBD_ReturnType retval = USBD_E_ERROR;

    /* Sanity check */
    if (dev->EP.OUT[0].State == USB_EP_STATE_SETUP)
    {
        uint16_t len = dev->Setup.Length;

        dev->EP.OUT[0].State = USB_EP_STATE_DATA;
        USBD_PD_EpReceive(dev, 0x00, (uint8_t*)data, len);

        retval = USBD_E_OK;
    }
    return retval;
}
```

函数入参中的 data 用于存放从端点读取的数据，函数内部会调用 USBD\_PD\_EpReceive 从端点接收数据，接收的长度为 `dev->Setup.Length`， 但是由于 `dev->Setup.Length` 是直接从 `USB` 总线中接收的，所以如果上层没有校验就会导致溢出。

示例

```php
static USBD_ReturnType cdc_setupStage(USBD_CDC_IfHandleType *itf)
{
    USBD_ReturnType retval = USBD_E_INVALID;
    USBD_HandleType *dev = itf->Base.Device;

    switch (dev->Setup.RequestType.Type)
    {
        case USB_REQ_TYPE_CLASS:
        {
            switch (dev->Setup.Request)
            {
                case CDC_REQ_SET_LINE_CODING:
                    cdc_deinit(itf);

                    retval = USBD_CtrlReceiveData(dev, &itf->LineCoding);  // 没有检查 dev->Setup.Length
```

### dfu\_upload 溢出漏洞

调用路径

```php
dfu_setupStage -> dfu_upload
```

漏洞代码

```php
static USBD_ReturnType dfu_upload(USBD_DFU_IfHandleType *itf)
{
    USBD_ReturnType retval = USBD_E_INVALID;
    USBD_HandleType *dev = itf->Base.Device;

    if ((dev->Setup.Length > 0) && (DFU_APP(itf)->Read != NULL))
    {
        uint8_t *data = dev->CtrlData;
        itf->BlockNum = dev->Setup.Value;

        else if (itf->BlockNum > 1)
        {
            itf->DevStatus.State = DFU_STATE_UPLOAD_IDLE;

            DFU_APP(itf)->Read(
                    DFUSE_GETADDRESS(itf, &dfu_desc),
                    data,
                    dev->Setup.Length);
```

问题在于没有检查 `dev->Setup.Length`， 导致 `DFU_APP(itf)->Read` 时会溢出。

rt-thread USB 协议栈
-----------------

issue 链接

```php
https://github.com/RT-Thread/rt-thread/issues/4776
```

### 定位数据入口

#### device侧协议栈

在 RT-Thread 中，USB协议栈作为一个 task 运行， 其入口函数为 rt\_usbd\_thread\_entry

```php
    /* init usb device thread */
    rt_thread_init(&usb_thread,
                   "usbd",
                   rt_usbd_thread_entry, RT_NULL,
                   usb_thread_stack, RT_USBD_THREAD_STACK_SZ,
                   RT_USBD_THREAD_PRIO, 20);
```

函数的关键代码如下

```php
static void rt_usbd_thread_entry(void* parameter)
{
    while(1)
    {
        if(rt_mq_recv(&usb_mq, &msg, sizeof(struct udev_msg),
                    RT_WAITING_FOREVER) != RT_EOK )
            continue;

        switch (msg.type)
        {

        case USB_MSG_DATA_NOTIFY:
            _data_notify(device, &msg.content.ep_msg);
            break;
        case USB_MSG_SETUP_NOTIFY:
            _setup_request(device, &msg.content.setup);
            break;
        case USB_MSG_EP0_OUT:
            _ep0_out_notify(device, &msg.content.ep_msg);
            break;
        ..................
        ..................

        }
    }
}
```

主要就是事件驱动，然后根据事件的类型来进行相应的处理

1. \_setup\_request： 处理 setup 数据
2. \_ep0\_out\_notify：处理 ep0 的 data 包
3. \_data\_notify： 处理其他端点的 data 包

相关的代码逻辑如下

![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-c1c5464e0ad37b537ccda25c2b4fb18cf662ab45.png)

其中比较重要的时图中标黄的部分，这些涉及到回调函数的调用，以 `_function_request` 为例

```php
static rt_err_t _function_request(udevice_t device, ureq_t setup)
{

    switch(setup->request_type & USB_REQ_TYPE_RECIPIENT_MASK)
    {
    case USB_REQ_TYPE_INTERFACE:
        intf = rt_usbd_find_interface(device, setup->wIndex & 0xFF, &func);
        .............
        .............
        intf->handler(func, setup);
```

参数中的 `setup` 是从 `USB` 总线上收到的数据包，然后根据 `setup->wIndex` 找到 `intf` ， 最后调用 `intf->handler` 完成数据的解析。

这里是调用点，用户可以 `rt_usbd_interface_new` 注册一个 `interface` 和相应的回调函数。

```php
rt_usbd_interface_new(device, _interface_as_handler);
```

下面再看一下 \_data\_notify 处理 USB 分包的逻辑， USB 的数据传输和以太网的数据传输比较类似，也有类似 MTU的概念，USB 一次传输的最大长度一般为 64 或者 128，当需要传输的数据大于最大传输长度时就需要进行分包传输，所以对于 USB 协议栈来说需要对分包的情况进行处理。

```php
static rt_err_t _data_notify(udevice_t device, struct ep_msg* ep_msg)
{

    {
        size = ep_msg->size;

        ep->request.remain_size -= size;
        ep->request.buffer += size;

        if(ep->request.req_type == UIO_REQUEST_READ_BEST)
        {
            EP_HANDLER(ep, func, size);
        }
        else if(ep->request.remain_size == 0)
        {
            EP_HANDLER(ep, func, ep->request.size);
        }
        else
        {
            dcd_ep_read_prepare(device->dcd, EP_ADDRESS(ep), ep->request.buffer, ep->request.remain_size > EP_MAXPACKET(ep) ? EP_MAXPACKET(ep) : ep->request.remain_size);
        }
    }

    return RT_EOK;
}
```

每当usb设备的OUT端点接收完一个数据包，就会进入 `_data_notify`，这里面会根据收到数据包的长度对 ep-&gt;request.remain\_size 进行修改，当 `ep->request.remain_size` 为 0 就表示数据包接收完毕。

当 `remain_size` 大于最大包长度时就会涉及到分包传输，这时如果 `req_type == UIO_REQUEST_READ_BEST`，就表示分包的处理由应用程序自己实现，协议栈每收到一个包就调用回调函数让应用程序去处理。

否则的话就由协议栈处理分包，当数据包接收完毕之后在调用回调函数，应用程序处理分包的场景示例：

```php
if(ecm_eth_dev->func->device->state == USB_STATE_CONFIGURED)
{
    ecm_eth_dev->rx_size = 0;
    ecm_eth_dev->rx_offset = 0;
    ecm_eth_dev->eps.ep_out->request.buffer = ecm_eth_dev->eps.ep_out->buffer;
    ecm_eth_dev->eps.ep_out->request.size = EP_MAXPACKET(ecm_eth_dev->eps.ep_out);
    ecm_eth_dev->eps.ep_out->request.req_type = UIO_REQUEST_READ_BEST;
    rt_usbd_io_request(ecm_eth_dev->func->device, ecm_eth_dev->eps.ep_out, &ecm_eth_dev->eps.ep_out->request);
}
```

经过对数据流的梳理，可以知道涉及到数据处理的函数如下：

1. `_setup_request`： 处理 setup 请求
2. 通过 `rt_usbd_ep0_read` 注册的 ep0 收包结束函数 `ep0->rx_indicate`
3. 通过 `rt_usbd_interface_new` 注册的 interface 数据处理函数
4. 通过 `rt_usbd_endpoint_new` 注册的端点数据处理函数

代码导图

![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-012205921a29748ee459fc0c77bab18376ec4319.png)

#### host 侧协议栈

当有USB 设备插上时会进入 `rt_usbh_attatch_instance` ，主要是获取一些 USB 设备的基本信息，比如设备类型、支持功能等。

host 侧主要是通过封装的 pipe 来完成和 USB 设备的通信

```php
    /* alloc true address ep0 pipe*/
    rt_usb_hcd_alloc_pipe(device->hcd, &device->pipe_ep0_out, device, &ep0_out_desc);
    rt_usb_hcd_alloc_pipe(device->hcd, &device->pipe_ep0_in, device, &ep0_in_desc);
```

以 `rt_usbh_get_des criptor` 为例看一下 host 收包的方式

```php
rt_err_t rt_usbh_get_descriptor(uinst_t device, rt_uint8_t type, void* buffer,
    int nbytes)
{
    struct urequest setup;
    int timeout = USB_TIMEOUT_BASIC;

    RT_ASSERT(device != RT_NULL);

    setup.request_type = USB_REQ_TYPE_DIR_IN | USB_REQ_TYPE_STANDARD |
        USB_REQ_TYPE_DEVICE;
    setup.bRequest = USB_REQ_GET_DESCRIPTOR;
    setup.wIndex = 0;
    setup.wLength = nbytes;
    setup.wValue = type << 8;

    if(rt_usb_hcd_setup_xfer(device->hcd, device->pipe_ep0_out, &setup, timeout) == 8)
    {
        if(rt_usb_hcd_pipe_xfer(device->hcd, device->pipe_ep0_in, buffer, nbytes, timeout) == nbytes)
        {
            if(rt_usb_hcd_pipe_xfer(device->hcd, device->pipe_ep0_out, RT_NULL, 0, timeout) == 0)
            {
                return RT_EOK;
            }
        }
    }
    return RT_ERROR;
}
```

首先发送 `setup` 请求通知 usb device 发送 `des criptor` 给 `host` ， 然后用 `rt_usb_hcd_pipe_xfer` 接收数据，该函数内部会处理分包的情况。

下面介绍几个典型的漏洞

### ecm模块 \_ep\_out\_handler 溢出漏洞

`rt_usbd_function_ecm_create` 中会注册 `out` 端点的回调函数

```php

    /* create a bulk in and a bulk out endpoint */
    data_desc = (ucdc_data_desc_t)data_setting->desc;
    eps->ep_out = rt_usbd_endpoint_new(&data_desc->ep_out_desc, _ep_out_handler);
    eps->ep_in = rt_usbd_endpoint_new(&data_desc->ep_in_desc, _ep_in_handler);
```

然后在 `_function_enable` 里面会调用 rt\_usbd\_io\_request 准备后续收包，`req_type` 为 `UIO_REQUEST_READ_BEST` ，表示USB的分包由 ecm 模块自己处理。

```php
static rt_err_t _function_enable(ufunction_t func)
{
    cdc_eps_t eps;
    rt_ecm_eth_t ecm_device = (rt_ecm_eth_t)func->user_data;

    eps = (cdc_eps_t)&ecm_device->eps;
    eps->ep_out->buffer = ecm_device->rx_pool;

    eps->ep_out->request.buffer = (void *)eps->ep_out->buffer;
    eps->ep_out->request.size = EP_MAXPACKET(eps->ep_out);
    eps->ep_out->request.req_type = UIO_REQUEST_READ_BEST;
    rt_usbd_io_request(func->device, eps->ep_out, &eps->ep_out->request);
    return RT_EOK;
}
```

下面看看 `_ep_out_handler` 的代码

```php
static rt_err_t _ep_out_handler(ufunction_t func, rt_size_t size)
{
    rt_ecm_eth_t ecm_device = (rt_ecm_eth_t)func->user_data;
    rt_memcpy((void *)(ecm_device->rx_buffer + ecm_device->rx_offset),ecm_device->rx_pool,size);
    ecm_device->rx_offset += size;
    if(size < EP_MAXPACKET(ecm_device->eps.ep_out))
    {
        ecm_device->rx_size = ecm_device->rx_offset;
        ecm_device->rx_offset = 0;
        eth_device_ready(&ecm_device->parent);

    }else
    {
        ecm_device->eps.ep_out->request.buffer = ecm_device->eps.ep_out->buffer;
        ecm_device->eps.ep_out->request.size = EP_MAXPACKET(ecm_device->eps.ep_out);
        ecm_device->eps.ep_out->request.req_type = UIO_REQUEST_READ_BEST;
        rt_usbd_io_request(ecm_device->func->device, ecm_device->eps.ep_out, &ecm_device->eps.ep_out->request);
    }

    return RT_EOK;
}
```

首先将收到的数据拷贝到 `ecm_device->rx_buffer` ，然后把收到数据包的 `size` 和 `EP_MAXPACKET`进行比较，不相等就表示收包结束，否则再次请求收包。

漏洞在于没有校验 `ecm_device->rx_offset` 是否会越界，如果恶意的 USB 设备不断发送 `size ==  EP_MAXPACKET` 的数据包就会导致溢出。

### rt\_usbh\_attatch\_instance 堆溢出漏洞

相关代码如下

```php
    /* get device descriptor head */
    ret = rt_usbh_get_descriptor(device, USB_DESC_TYPE_DEVICE, (void*)dev_desc, 8);

    /* get full device descriptor again */
    ret = rt_usbh_get_descriptor(device, USB_DESC_TYPE_DEVICE, (void*)dev_desc, dev_desc->bLength);
```

1. 首先通过 `rt_usbh_get_des criptor` 获取 usb 设备的`des criptor`， 保存到 `dev_desc`.
2. 然后再次使用 `rt_usbh_get_des criptor` 往往 `dev_desc` 里面写数据，长度为 `dev_desc->bLength` 。

问题在于如果 `dev_desc->bLength` 过大，就会溢出 `dev_desc`.

总结
==

漏洞大部分出现在基于USB协议栈的上层应用，比如 dfu、RNDIS 等，而且尽管 setup 请求只有简单的8个字节，但是对 setup 请求中的 size 字段解析也出现了很多的问题。

大部分漏洞都是由于解析变长数据结构时导致的，这也是解析二进制数据格式时经常出现漏洞的地方。

文中涉及的漏洞，基本用 libfuzzer 适配一下都能发现，主要是识别出数据的入口。

由于漏洞成因都不复杂，感觉用黑盒fuzz工具也能快速发现。