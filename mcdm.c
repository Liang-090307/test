#include <windows.h>
#include <stdio.h>
#include <ShellAPI.h>

// 检查当前进程是否以管理员权限运行
BOOL IsRunAsAdmin() {
    BOOL isAdmin = FALSE;
    PSID adminGroupSid = NULL;

    // 创建管理员组的 SID
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    if (!AllocateAndInitializeSid(
        &NtAuthority, 2,
        SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0,
        &adminGroupSid)) {
        return FALSE;
    }

    // 检查当前进程是否属于管理员组
    if (!CheckTokenMembership(NULL, adminGroupSid, &isAdmin)) {
        isAdmin = FALSE;
    }

    FreeSid(adminGroupSid);
    return isAdmin;
}

// 重新以管理员权限运行程序
BOOL RestartAsAdmin() {
    WCHAR szPath[MAX_PATH];
    if (GetModuleFileNameW(NULL, szPath, ARRAYSIZE(szPath))) {
        SHELLEXECUTEINFOW sei = { sizeof(sei) };
        sei.lpVerb = L"runas"; // 请求管理员权限
        sei.lpFile = szPath;   // 当前程序路径
        sei.nShow = SW_NORMAL;

        if (!ShellExecuteExW(&sei)) {
            DWORD dwError = GetLastError();
            if (dwError == ERROR_CANCELLED) {
                // 用户拒绝了 UAC 提权请求
                printf("权限错误\n需要管理员权限才能继续\n\n");
            }
            return FALSE;
        }
        return TRUE; // 提权成功，原进程可退出
    }
    return FALSE;
}

int dir_exists(const char *path) {
    DWORD attrib = GetFileAttributesA(path);
    return (attrib != INVALID_FILE_ATTRIBUTES && 
           (attrib & FILE_ATTRIBUTE_DIRECTORY));
}

void ExecutePowerShellCommand(const char *command) {
    SECURITY_ATTRIBUTES sa = {sizeof(SECURITY_ATTRIBUTES), NULL, TRUE};
    HANDLE hReadPipe, hWritePipe;
    CHAR buffer[4096];
    DWORD bytesRead;

    // 创建匿名管道用于读取输出
    CreatePipe(&hReadPipe, &hWritePipe, &sa, 0);

    // 配置进程启动信息
    STARTUPINFO si = {sizeof(STARTUPINFO)};
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.hStdOutput = hWritePipe;
    si.wShowWindow = SW_HIDE; // 隐藏窗口

    PROCESS_INFORMATION pi;
    char cmdLine[1024];
    
    // 构建完整的PowerShell命令
    snprintf(cmdLine, sizeof(cmdLine), "powershell -Command \"%s\"", command);

    // 创建进程
    if (CreateProcess(
        NULL,           // 不直接指定程序路径
        cmdLine,        // 命令行参数
        NULL,           // 进程安全属性
        NULL,           // 线程安全属性
        TRUE,           // 继承句柄
        0,              // 无标志
        NULL,           // 使用父进程环境
        NULL,           // 使用父进程目录
        &si,            // 启动信息
        &pi             // 进程信息
    )) {
        // 关闭写入端管道
        CloseHandle(hWritePipe);

        // 读取输出
        while (ReadFile(hReadPipe, buffer, sizeof(buffer) - 1, &bytesRead, NULL) && bytesRead > 0) {
            buffer[bytesRead] = '\0';
            printf("%s", buffer);
        }

        // 清理资源
        CloseHandle(hReadPipe);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    } else {
        printf("创建进程失败！错误码: %d\n", GetLastError());
    }
}

int main()
{
    if (!IsRunAsAdmin())
    {
        if (RestartAsAdmin())
        {
            // 提权成功，退出当前非管理员进程
            return 0;
        }
        // 提权失败，处理错误
        return 1;
    }
    // 以管理员权限运行后续代码
    printf("正在下载Java\n\n");
    ExecutePowerShellCommand("wget -Uri \"https://download.oracle.com/java/24/latest/jdk-24_windows-x64_bin.exe\" -UseBasicParsing -o \"java.exe\"");
    printf("正在下载hmcl\n\n");
    ExecutePowerShellCommand("wget -Uri \"http://mirrors.cloud.tencent.com/nexus/repository/maven-public/org/glavo/hmcl/hmcl-dev/3.6.12.276/hmcl-dev-3.6.12.276.exe\" -UseBasicParsing -o \"hmcl.exe\"");
    printf("接下来将安装Java,请在弹出的窗口中保持默认,一直下一步\n\n");
    system("java.exe");
    printf("下面将检测目录(D:\\Game)是否存在\n你的游戏将保存在这里\n\n");
    const char *dir_path = "D:\\Game"; // 反斜杠需转义
    if (dir_exists(dir_path))
    {
        printf("目录存在\n");
    }
    else
    {
        printf("目录不存在\n");
        printf("将创建目录\n");
        CreateDirectoryA(dir_path,NULL);
    }
    system("copy hmcl.exe D:\\Game");
    ExecutePowerShellCommand("$WshShell=New-Object -ComObject WScript.Shell; $Shortcut=$WshShell.CreateShortcut(\"$env:USERPROFILE\\Desktop\\hmcl.lnk\"); $Shortcut.TargetPath='D:\\Game\\hmcl.exe'; $Shortcut.Save()");
    system("del java.exe");
    system("del hmcl.exe");
    system("pause");
    return 0;
}
