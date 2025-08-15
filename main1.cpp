#include <windows.h>
#include <commdlg.h>
#include <tchar.h>
#include <stdio.h>

// 颜色和常量定义
#define IDD_MAIN_DIALOG 101
#define IDI_ICON1 102
#define BTN_SET_ID 1001
#define BTN_REMOVE_ID 1002
#define BTN_BROWSE_ID 1003
#define EDIT_PATH_ID 1004
#define LBL_RESULT_ID 1005

// 全局变量
HWND hEditPath, hLblResult;
HINSTANCE hInst;

// 函数声明
BOOL IsAdmin();
BOOL RunAsAdmin();
void ShowPermissionError(LPCTSTR msg);
BOOL CheckProtectedHidden(LPCTSTR filePath, BOOL* isSet, LPTSTR errMsg, DWORD errMsgSize);
BOOL SetProtectedHidden(LPCTSTR filePath, LPTSTR resultMsg, DWORD msgSize);
BOOL RemoveProtectedHidden(LPCTSTR filePath, LPTSTR resultMsg, DWORD msgSize);
INT_PTR CALLBACK MainDialogProc(HWND hDlg, UINT msg, WPARAM wParam, LPARAM lParam);
void UpdateResultText(LPCTSTR text);
void BrowseFile(HWND hDlg);

// 检查是否以管理员权限运行
BOOL IsAdmin() {
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    PSID pAdministratorsGroup;
    if (!AllocateAndInitializeSid(
        &NtAuthority,
        2,
        SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0,
        &pAdministratorsGroup
    )) {
        return FALSE;
    }

    BOOL isAdmin;
    CheckTokenMembership(NULL, pAdministratorsGroup, &isAdmin);
    FreeSid(pAdministratorsGroup);
    return isAdmin;
}

// 以管理员权限重启程序
BOOL RunAsAdmin() {
    TCHAR szPath[MAX_PATH];
    if (!GetModuleFileName(NULL, szPath, MAX_PATH)) {
        return FALSE;
    }

    SHELLEXECUTEINFO sei = { sizeof(sei) };
    sei.lpVerb = _T("runas");
    sei.lpFile = szPath;
    sei.hwnd = NULL;
    sei.nShow = SW_NORMAL;

    return ShellExecuteEx(&sei) ? TRUE : FALSE;
}

// 显示权限错误提示
void ShowPermissionError(LPCTSTR msg) {
    TCHAR fullMsg[512];
    _stprintf_s(fullMsg, sizeof(fullMsg) / sizeof(TCHAR),
        _T("%s\n\n请尝试：\n1. 右键程序选择「以管理员身份运行」\n2. 确认当前用户有管理员权限"), msg);
    MessageBox(NULL, fullMsg, _T("权限错误"), MB_ICONERROR | MB_OK);
}

// 检查文件是否具有系统+隐藏属性
BOOL CheckProtectedHidden(LPCTSTR filePath, BOOL* isSet, LPTSTR errMsg, DWORD errMsgSize) {
    DWORD attrs = GetFileAttributes(filePath);
    if (attrs == INVALID_FILE_ATTRIBUTES) {
        DWORD err = GetLastError();
        FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL, err, 0, errMsg, errMsgSize, NULL);
        return FALSE;
    }

    *isSet = ((attrs & FILE_ATTRIBUTE_SYSTEM) && (attrs & FILE_ATTRIBUTE_HIDDEN)) ? TRUE : FALSE;
    return TRUE;
}

// 设置文件系统+隐藏属性
BOOL SetProtectedHidden(LPCTSTR filePath, LPTSTR resultMsg, DWORD msgSize) {
    BOOL isSet;
    TCHAR errMsg[256] = { 0 };

    if (!CheckProtectedHidden(filePath, &isSet, errMsg, sizeof(errMsg) / sizeof(TCHAR))) {
        _stprintf_s(resultMsg, msgSize, _T("文件属性获取失败：%s"), errMsg);
        return FALSE;
    }

    if (isSet) {
        _tcscpy_s(resultMsg, msgSize, _T("文件已包含系统保护+隐藏属性，无需重复设置"));
        return FALSE;
    }

    DWORD attrs = GetFileAttributes(filePath);
    if (!SetFileAttributes(filePath, attrs | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN)) {
        DWORD err = GetLastError();
        FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL, err, 0, errMsg, sizeof(errMsg) / sizeof(TCHAR), NULL);
        _stprintf_s(resultMsg, msgSize, _T("设置失败：%s (0x%08X)"), errMsg, err);
        return FALSE;
    }

    _tcscpy_s(resultMsg, msgSize, _T("系统保护+隐藏属性设置成功 ✅"));
    return TRUE;
}

// 移除文件系统+隐藏属性
BOOL RemoveProtectedHidden(LPCTSTR filePath, LPTSTR resultMsg, DWORD msgSize) {
    BOOL isSet;
    TCHAR errMsg[256] = { 0 };

    if (!CheckProtectedHidden(filePath, &isSet, errMsg, sizeof(errMsg) / sizeof(TCHAR))) {
        _stprintf_s(resultMsg, msgSize, _T("文件属性获取失败：%s"), errMsg);
        return FALSE;
    }

    if (!isSet) {
        _tcscpy_s(resultMsg, msgSize, _T("文件未包含系统保护+隐藏属性，无需移除"));
        return FALSE;
    }

    DWORD attrs = GetFileAttributes(filePath);
    if (!SetFileAttributes(filePath, attrs & ~(FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN))) {
        DWORD err = GetLastError();
        FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL, err, 0, errMsg, sizeof(errMsg) / sizeof(TCHAR), NULL);
        _stprintf_s(resultMsg, msgSize, _T("移除失败：%s (0x%08X)"), errMsg, err);
        return FALSE;
    }

    _tcscpy_s(resultMsg, msgSize, _T("系统保护+隐藏属性移除成功 ✅"));
    return TRUE;
}

// 更新结果显示文本
void UpdateResultText(LPCTSTR text) {
    SetWindowText(hLblResult, text);
}

// 浏览文件选择
void BrowseFile(HWND hDlg) {
    OPENFILENAME ofn = { sizeof(ofn) };
    TCHAR filePath[MAX_PATH] = { 0 };

    ofn.hwndOwner = hDlg;
    ofn.lpstrFile = filePath;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrFilter = _T("所有文件 (*.*)\0*.*\0");
    ofn.lpstrTitle = _T("选择要处理的文件");
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;

    if (GetOpenFileName(&ofn)) {
        SetWindowText(hEditPath, filePath);
    }
}

// 主窗口消息处理
INT_PTR CALLBACK MainDialogProc(HWND hDlg, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_INITDIALOG: {
        // 初始化控件
        hEditPath = GetDlgItem(hDlg, EDIT_PATH_ID);
        hLblResult = GetDlgItem(hDlg, LBL_RESULT_ID);

        // 设置窗口图标
        HICON hIcon = LoadIcon(hInst, MAKEINTRESOURCE(IDI_ICON1));
        if (hIcon)
        {
            SendMessage(hDlg, WM_SETICON, ICON_SMALL, (LPARAM)hIcon);
            SendMessage(hDlg, WM_SETICON, ICON_BIG, (LPARAM)hIcon);
        }

        // 显示当前权限状态
        if (IsAdmin()) {
            UpdateResultText(_T("已准备就绪 | 当前权限：管理员模式 🔑（功能正常）"));
        }
        else {
            UpdateResultText(_T("已准备就绪 | 当前权限：普通模式 ⚠️（请获取管理员权限）"));
        }
        return TRUE;
    }

    case WM_COMMAND: {
        switch (LOWORD(wParam)) {
        case BTN_BROWSE_ID:
            BrowseFile(hDlg);
            return TRUE;

        case BTN_SET_ID: {
            // 检查权限
            if (!IsAdmin()) {
                UpdateResultText(_T("❌ 权限不足：无法执行此操作"));
                ShowPermissionError(_T("设置文件属性需要管理员权限"));
                return TRUE;
            }

            // 获取文件路径
            TCHAR filePath[MAX_PATH];
            GetWindowText(hEditPath, filePath, MAX_PATH);
            if (_tcslen(filePath) == 0 || GetFileAttributes(filePath) == INVALID_FILE_ATTRIBUTES) {
                UpdateResultText(_T("❌ 错误：文件路径无效或文件不存在"));
                return TRUE;
            }

            // 执行设置操作
            TCHAR resultMsg[512];
            SetProtectedHidden(filePath, resultMsg, sizeof(resultMsg) / sizeof(TCHAR));
            UpdateResultText(resultMsg);
            return TRUE;
        }

        case BTN_REMOVE_ID: {
            // 检查权限
            if (!IsAdmin()) {
                UpdateResultText(_T("❌ 权限不足：无法执行此操作"));
                ShowPermissionError(_T("移除文件属性需要管理员权限"));
                return TRUE;
            }

            // 获取文件路径
            TCHAR filePath[MAX_PATH];
            GetWindowText(hEditPath, filePath, MAX_PATH);
            if (_tcslen(filePath) == 0 || GetFileAttributes(filePath) == INVALID_FILE_ATTRIBUTES) {
                UpdateResultText(_T("❌ 错误：文件路径无效或文件不存在"));
                return TRUE;
            }

            // 执行移除操作
            TCHAR resultMsg[512];
            RemoveProtectedHidden(filePath, resultMsg, sizeof(resultMsg) / sizeof(TCHAR));
            UpdateResultText(resultMsg);
            return TRUE;
        }

        case IDOK:
        case IDCANCEL:
            EndDialog(hDlg, 0);
            return TRUE;
        }
        break;
    }

    case WM_CLOSE:
        EndDialog(hDlg, 0);
        return TRUE;
    }
    return FALSE;
}

// 程序入口
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    hInst = hInstance;

    // 启动时检查权限
    if (!IsAdmin()) {
        int ret = MessageBox(NULL,
            _T("本工具需要管理员权限才能正常工作，是否立即获取权限？"),
            _T("权限不足"),
            MB_YESNO | MB_ICONWARNING
        );

        if (ret == IDYES) {
            if (!RunAsAdmin()) {
                ShowPermissionError(_T("获取管理员权限失败"));
                return 1;
            }
            return 0; // 新进程启动后退出当前进程
        }
        else {
            ShowPermissionError(_T("您选择了继续使用普通模式，部分功能将不可用"));
        }
    }

    // 创建主窗口
    DialogBox(hInstance, MAKEINTRESOURCE(IDD_MAIN_DIALOG), NULL, MainDialogProc);
    return 0;
}
