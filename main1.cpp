#include <windows.h>
#include <commdlg.h>
#include <tchar.h>
#include <stdio.h>
#include <wincrypt.h>
#include <aclapi.h>
#include <winnls.h>

#define IDD_MAIN_DIALOG 101
#define IDI_ICON1 102
#define BTN_SET_ID 1001
#define BTN_REMOVE_ID 1002
#define BTN_BROWSE_ID 1003
#define EDIT_PATH_ID 1004
#define LBL_RESULT_ID 1005

HWND hEditPath, hLblResult;
HINSTANCE hInst;

BOOL IsAdmin();
BOOL RunAsAdmin();
void ShowPermissionError(LPCTSTR msg);
BOOL CheckProtectedHidden(LPCTSTR filePath, BOOL* isSet, LPTSTR errMsg, DWORD errMsgSize);
BOOL SetProtectedHidden(LPCTSTR filePath, LPTSTR resultMsg, DWORD msgSize);
BOOL RemoveProtectedHidden(LPCTSTR filePath, LPTSTR resultMsg, DWORD msgSize);
INT_PTR CALLBACK MainDialogProc(HWND hDlg, UINT msg, WPARAM wParam, LPARAM lParam);
void UpdateResultText(LPCTSTR text);
void BrowseFile(HWND hDlg);
BOOL GetHistoryFilePath(LPTSTR path, DWORD size);
BOOL AddToHistory(LPCTSTR filePath);
BOOL RemoveFromHistory(LPCTSTR filePath);
BOOL CleanupHistory();
BOOL LoadRecentHistory(LPTSTR historyText, DWORD textSize, int maxEntries);
int WideCharToUtf8(LPCWSTR wideStr, char* utf8Str, int utf8Size);
int Utf8ToWideChar(LPCSTR utf8Str, WCHAR* wideStr, int wideSize);
BOOL ValidateFilePath(LPCTSTR filePath, LPTSTR normalizedPath, DWORD pathSize, LPTSTR errMsg, DWORD errMsgSize);
BOOL IsSymlink(LPCTSTR filePath);
BOOL ProtectHistoryFile(LPCTSTR filePath);
BOOL EncryptString(LPCWSTR plainText, LPBYTE* encryptedData, DWORD* dataSize);
BOOL DecryptString(LPBYTE encryptedData, DWORD dataSize, LPWSTR* plainText);

int WideCharToUtf8(LPCWSTR wideStr, char* utf8Str, int utf8Size) {
    if (!wideStr || !utf8Str || utf8Size <= 0) return 0;
    int len = WideCharToMultiByte(CP_UTF8, 0, wideStr, -1, NULL, 0, NULL, NULL);
    if (len == 0 || len > utf8Size) return 0;
    return WideCharToMultiByte(CP_UTF8, 0, wideStr, -1, utf8Str, len, NULL, NULL);
}

int Utf8ToWideChar(LPCSTR utf8Str, WCHAR* wideStr, int wideSize) {
    if (!utf8Str || !wideStr || wideSize <= 0) return 0;
    int len = MultiByteToWideChar(CP_UTF8, 0, utf8Str, -1, NULL, 0);
    if (len == 0 || len > wideSize) return 0;
    return MultiByteToWideChar(CP_UTF8, 0, utf8Str, -1, wideStr, len);
}

BOOL IsSymlink(LPCTSTR filePath) {
    DWORD attrs = GetFileAttributes(filePath);
    if (attrs == INVALID_FILE_ATTRIBUTES) {
        return FALSE;
    }
    return (attrs & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
}

BOOL EncryptString(LPCWSTR plainText, LPBYTE* encryptedData, DWORD* dataSize) {
    if (!plainText || !encryptedData || !dataSize) return FALSE;

    DWORD plainTextSize = (lstrlenW(plainText) + 1) * sizeof(WCHAR);
    *dataSize = 0;

    DATA_BLOB inputBlob;
    inputBlob.cbData = plainTextSize;
    inputBlob.pbData = (BYTE*)plainText;

    DATA_BLOB outputBlob = { 0 };
    if (!CryptProtectData(
        &inputBlob,
        NULL,
        NULL,
        NULL,
        NULL,
        CRYPTPROTECT_LOCAL_MACHINE,
        &outputBlob
    )) {
        return FALSE;
    }

    *encryptedData = (LPBYTE)LocalAlloc(LPTR, outputBlob.cbData);
    if (!*encryptedData) {
        LocalFree(outputBlob.pbData);
        return FALSE;
    }

    CopyMemory(*encryptedData, outputBlob.pbData, outputBlob.cbData);
    *dataSize = outputBlob.cbData;
    LocalFree(outputBlob.pbData);
    return TRUE;
}

BOOL DecryptString(LPBYTE encryptedData, DWORD dataSize, LPWSTR* plainText) {
    if (!encryptedData || dataSize == 0 || !plainText) return FALSE;

    DATA_BLOB inputBlob = { dataSize, encryptedData };
    DATA_BLOB outputBlob = { 0 };

    if (!CryptUnprotectData(
        &inputBlob,
        NULL,
        NULL,
        NULL,
        NULL,
        CRYPTPROTECT_LOCAL_MACHINE,
        &outputBlob
    )) {
        return FALSE;
    }

    *plainText = (LPWSTR)LocalAlloc(LPTR, outputBlob.cbData);
    if (!*plainText) {
        LocalFree(outputBlob.pbData);
        return FALSE;
    }

    CopyMemory(*plainText, outputBlob.pbData, outputBlob.cbData);
    LocalFree(outputBlob.pbData);
    return TRUE;
}

BOOL ProtectHistoryFile(LPCTSTR filePath) {
    if (!filePath) return FALSE;

    DWORD result = SetNamedSecurityInfo(
        (LPTSTR)filePath,
        SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION,
        NULL,
        NULL,
        NULL,
        NULL
    );

    if (result != ERROR_SUCCESS) return FALSE;

    PSECURITY_DESCRIPTOR pSD = NULL;
    result = GetNamedSecurityInfo(
        (LPTSTR)filePath,
        SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION,
        NULL,
        NULL,
        NULL,
        NULL,
        &pSD
    );

    if (result != ERROR_SUCCESS) return FALSE;

    EXPLICIT_ACCESS ea;
    ZeroMemory(&ea, sizeof(EXPLICIT_ACCESS));
    ea.grfAccessPermissions = GENERIC_READ | GENERIC_WRITE | DELETE;
    ea.grfAccessMode = SET_ACCESS;
    ea.grfInheritance = NO_INHERITANCE;
    ea.Trustee.TrusteeForm = TRUSTEE_IS_NAME;
    ea.Trustee.TrusteeType = TRUSTEE_IS_USER;
    ea.Trustee.ptstrName = (LPTSTR)_T("SYSTEM");

    PACL pNewDACL = NULL;
    result = SetEntriesInAcl(1, &ea, NULL, &pNewDACL);
    if (result != ERROR_SUCCESS) {
        LocalFree(pSD);
        return FALSE;
    }

    result = SetNamedSecurityInfo(
        (LPTSTR)filePath,
        SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION,
        NULL,
        NULL,
        pNewDACL,
        NULL
    );

    LocalFree(pSD);
    LocalFree(pNewDACL);
    return (result == ERROR_SUCCESS);
}

BOOL NormalizePathForValidation(LPCTSTR inputPath, LPTSTR outputPath, DWORD outputSize) {
    if (!inputPath || !outputPath || outputSize == 0) return FALSE;

    size_t len = _tcslen(inputPath);
    if (len == 0 || len >= outputSize) return FALSE;

    _tcscpy_s(outputPath, outputSize, inputPath);

    for (int i = 0; outputPath[i] != '\0'; i++) {
        if (outputPath[i] == 0xFF0E) {
            outputPath[i] = '.';
        } else if (outputPath[i] == 0xFF0F) {
            outputPath[i] = '/';
        } else if (outputPath[i] == 0x202E) {
            outputPath[i] = '\0';
            break;
        }
    }

    TCHAR tempPath[MAX_PATH] = { 0 };
    int normLen = NormalizeString((NORM_FORM)0x0001, outputPath, -1, tempPath, MAX_PATH);
    if (normLen > 0 && normLen < MAX_PATH) {
        _tcscpy_s(outputPath, outputSize, tempPath);
    }

    return TRUE;
}

BOOL IsUNCPath(LPCTSTR path) {
    if (!path) return FALSE;
    if (_tcslen(path) < 2) return FALSE;
    return (path[0] == _T('\\') && path[1] == _T('\\'));
}

BOOL HasPathTraversal(LPCTSTR path) {
    if (!path) return FALSE;

    TCHAR checkPath[MAX_PATH] = { 0 };
    if (!NormalizePathForValidation(path, checkPath, MAX_PATH)) {
        return TRUE;
    }

    if (_tcsstr(checkPath, _T("..")) != NULL) {
        return TRUE;
    }

    return FALSE;
}

BOOL ValidateFilePath(LPCTSTR filePath, LPTSTR normalizedPath, DWORD pathSize, LPTSTR errMsg, DWORD errMsgSize) {
    if (!filePath || !normalizedPath || !errMsg) {
        _tcscpy_s(errMsg, errMsgSize, _T("无效参数"));
        return FALSE;
    }

    if (_tcslen(filePath) == 0) {
        _tcscpy_s(errMsg, errMsgSize, _T("文件路径不能为空"));
        return FALSE;
    }

    if (_tcslen(filePath) >= MAX_PATH) {
        _tcscpy_s(errMsg, errMsgSize, _T("文件路径过长"));
        return FALSE;
    }

    if (IsUNCPath(filePath)) {
        _tcscpy_s(errMsg, errMsgSize, _T("不支持UNC路径"));
        return FALSE;
    }

    if (HasPathTraversal(filePath)) {
        _tcscpy_s(errMsg, errMsgSize, _T("文件路径包含非法字符"));
        return FALSE;
    }

    DWORD attrs = GetFileAttributes(filePath);
    if (attrs == INVALID_FILE_ATTRIBUTES) {
        _tcscpy_s(errMsg, errMsgSize, _T("文件路径无效或文件不存在"));
        return FALSE;
    }

    if ((attrs & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
        _tcscpy_s(errMsg, errMsgSize, _T("不支持符号链接操作"));
        return FALSE;
    }

    if (!GetFullPathName(filePath, pathSize, normalizedPath, NULL)) {
        _tcscpy_s(errMsg, errMsgSize, _T("路径规范化失败"));
        return FALSE;
    }

    if (HasPathTraversal(normalizedPath)) {
        _tcscpy_s(errMsg, errMsgSize, _T("文件路径包含非法字符（路径遍历）"));
        return FALSE;
    }

    return TRUE;
}

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

    HANDLE hFile = CreateFile(
        filePath,
        FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS,
        NULL
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL, err, 0, errMsg, sizeof(errMsg) / sizeof(TCHAR), NULL);
        _stprintf_s(resultMsg, msgSize, _T("打开文件失败：%s (0x%08X)"), errMsg, err);
        return FALSE;
    }

    BY_HANDLE_FILE_INFORMATION fileInfo;
    if (!GetFileInformationByHandle(hFile, &fileInfo)) {
        DWORD err = GetLastError();
        FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL, err, 0, errMsg, sizeof(errMsg) / sizeof(TCHAR), NULL);
        _stprintf_s(resultMsg, msgSize, _T("获取文件信息失败：%s (0x%08X)"), errMsg, err);
        CloseHandle(hFile);
        return FALSE;
    }

    if ((fileInfo.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
        _tcscpy_s(resultMsg, msgSize, _T("不支持符号链接操作"));
        CloseHandle(hFile);
        return FALSE;
    }

    isSet = ((fileInfo.dwFileAttributes & FILE_ATTRIBUTE_SYSTEM) && 
              (fileInfo.dwFileAttributes & FILE_ATTRIBUTE_HIDDEN)) ? TRUE : FALSE;

    if (isSet) {
        _tcscpy_s(resultMsg, msgSize, _T("文件已包含系统保护+隐藏属性，无需重复设置"));
        CloseHandle(hFile);
        return FALSE;
    }

    if (!SetFileAttributes(filePath, fileInfo.dwFileAttributes | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN)) {
        DWORD err = GetLastError();
        FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL, err, 0, errMsg, sizeof(errMsg) / sizeof(TCHAR), NULL);
        _stprintf_s(resultMsg, msgSize, _T("设置失败：%s (0x%08X)"), errMsg, err);
        CloseHandle(hFile);
        return FALSE;
    }

    CloseHandle(hFile);

    _tcscpy_s(resultMsg, msgSize, _T("系统保护+隐藏属性设置成功 ✅"));
    AddToHistory(filePath);
    return TRUE;
}

// 移除文件系统+隐藏属性
BOOL RemoveProtectedHidden(LPCTSTR filePath, LPTSTR resultMsg, DWORD msgSize) {
    BOOL isSet;
    TCHAR errMsg[256] = { 0 };

    HANDLE hFile = CreateFile(
        filePath,
        FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS,
        NULL
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL, err, 0, errMsg, sizeof(errMsg) / sizeof(TCHAR), NULL);
        _stprintf_s(resultMsg, msgSize, _T("打开文件失败：%s (0x%08X)"), errMsg, err);
        return FALSE;
    }

    BY_HANDLE_FILE_INFORMATION fileInfo;
    if (!GetFileInformationByHandle(hFile, &fileInfo)) {
        DWORD err = GetLastError();
        FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL, err, 0, errMsg, sizeof(errMsg) / sizeof(TCHAR), NULL);
        _stprintf_s(resultMsg, msgSize, _T("获取文件信息失败：%s (0x%08X)"), errMsg, err);
        CloseHandle(hFile);
        return FALSE;
    }

    if ((fileInfo.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
        _tcscpy_s(resultMsg, msgSize, _T("不支持符号链接操作"));
        CloseHandle(hFile);
        return FALSE;
    }

    isSet = ((fileInfo.dwFileAttributes & FILE_ATTRIBUTE_SYSTEM) && 
              (fileInfo.dwFileAttributes & FILE_ATTRIBUTE_HIDDEN)) ? TRUE : FALSE;

    if (!isSet) {
        _tcscpy_s(resultMsg, msgSize, _T("文件未包含系统保护+隐藏属性，无需移除"));
        CloseHandle(hFile);
        return FALSE;
    }

    if (!SetFileAttributes(filePath, fileInfo.dwFileAttributes & ~(FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN))) {
        DWORD err = GetLastError();
        FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL, err, 0, errMsg, sizeof(errMsg) / sizeof(TCHAR), NULL);
        _stprintf_s(resultMsg, msgSize, _T("移除失败：%s (0x%08X)"), errMsg, err);
        CloseHandle(hFile);
        return FALSE;
    }

    CloseHandle(hFile);

    _tcscpy_s(resultMsg, msgSize, _T("系统保护+隐藏属性移除成功 ✅"));
    RemoveFromHistory(filePath);
    return TRUE;
}

// 获取历史文件路径（程序目录下的 history.txt）
BOOL GetHistoryFilePath(LPTSTR path, DWORD size) {
    if (!GetModuleFileName(NULL, path, size)) {
        return FALSE;
    }
    LPTSTR lastSlash = _tcsrchr(path, _T('\\'));
    if (lastSlash) {
        *(lastSlash + 1) = _T('\0');
        _tcscat_s(path, size, _T("history.txt"));
        return TRUE;
    }
    return FALSE;
}

BOOL AddToHistory(LPCTSTR filePath) {
    TCHAR historyPathW[MAX_PATH];
    if (!GetHistoryFilePath(historyPathW, MAX_PATH)) {
        return FALSE;
    }

    char historyPath[MAX_PATH * 4] = { 0 };
    WideCharToUtf8(historyPathW, historyPath, sizeof(historyPath));

    char existingContent[MAX_PATH * 200] = { 0 };
    FILE* f = NULL;
    errno_t err = fopen_s(&f, historyPath, "rb");
    if (!err && f) {
        size_t bytesRead = fread(existingContent, 1, sizeof(existingContent) - 1, f);
        existingContent[bytesRead] = '\0';
        fclose(f);
    }

    char filePathUtf8[MAX_PATH * 4] = { 0 };
    int utf8Len = WideCharToUtf8(filePath, filePathUtf8, sizeof(filePathUtf8));
    if (utf8Len == 0) {
        return FALSE;
    }

    char newContent[MAX_PATH * 200] = { 0 };
    int resultLen = sprintf_s(newContent, sizeof(newContent), "%s\n%s", filePathUtf8, existingContent);
    if (resultLen < 0 || resultLen >= (int)sizeof(newContent)) {
        return FALSE;
    }

    err = fopen_s(&f, historyPath, "wb");
    if (err || !f) {
        return FALSE;
    }
    fwrite(newContent, 1, strlen(newContent), f);
    fclose(f);

    SetFileAttributes(historyPathW, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
    ProtectHistoryFile(historyPathW);
    return TRUE;
}

BOOL RemoveFromHistory(LPCTSTR filePath) {
    TCHAR historyPathW[MAX_PATH];
    if (!GetHistoryFilePath(historyPathW, MAX_PATH)) {
        return FALSE;
    }

    char historyPath[MAX_PATH * 4] = { 0 };
    WideCharToUtf8(historyPathW, historyPath, sizeof(historyPath));

    char filePathUtf8[MAX_PATH * 4] = { 0 };
    int utf8Len = WideCharToUtf8(filePath, filePathUtf8, sizeof(filePathUtf8));
    if (utf8Len == 0) {
        return FALSE;
    }

    FILE* f = NULL;
    errno_t err = fopen_s(&f, historyPath, "rb");
    if (err || !f) {
        return FALSE;
    }

    char line[MAX_PATH * 4] = { 0 };
    char newContent[MAX_PATH * 200] = { 0 };
    BOOL firstLine = TRUE;
    size_t newContentLen = 0;

    while (fgets(line, sizeof(line), f)) {
        char* newline = strrchr(line, '\n');
        if (newline) *newline = '\0';

        if (strcmp(line, filePathUtf8) == 0) {
            ZeroMemory(line, sizeof(line));
            continue;
        }

        size_t lineLen = strlen(line);
        if (lineLen == 0) {
            ZeroMemory(line, sizeof(line));
            continue;
        }

        size_t requiredLen = newContentLen + lineLen + 2;
        if (requiredLen >= sizeof(newContent)) {
            fclose(f);
            return FALSE;
        }

        if (!firstLine) {
            newContent[newContentLen++] = '\n';
        }
        memcpy_s(newContent + newContentLen, sizeof(newContent) - newContentLen, line, lineLen);
        newContentLen += lineLen;
        newContent[newContentLen] = '\0';
        firstLine = FALSE;
        ZeroMemory(line, sizeof(line));
    }
    fclose(f);

    err = fopen_s(&f, historyPath, "wb");
    if (err || !f) {
        return FALSE;
    }
    if (newContentLen > 0) {
        fwrite(newContent, 1, newContentLen, f);
    }
    fclose(f);

    ProtectHistoryFile(historyPathW);
    return TRUE;
}

BOOL CleanupHistory() {
    TCHAR historyPathW[MAX_PATH];
    if (!GetHistoryFilePath(historyPathW, MAX_PATH)) {
        return FALSE;
    }

    char historyPath[MAX_PATH * 4] = { 0 };
    WideCharToUtf8(historyPathW, historyPath, sizeof(historyPath));

    FILE* f = NULL;
    errno_t err = fopen_s(&f, historyPath, "rb");
    if (err || !f) {
        return FALSE;
    }

    char line[MAX_PATH * 4] = { 0 };
    char validContent[MAX_PATH * 200] = { 0 };
    BOOL firstLine = TRUE;
    size_t validContentLen = 0;

    while (fgets(line, sizeof(line), f)) {
        char* newline = strrchr(line, '\n');
        if (newline) *newline = '\0';

        size_t lineLen = strlen(line);
        if (lineLen == 0) {
            ZeroMemory(line, sizeof(line));
            continue;
        }

        TCHAR widePath[MAX_PATH] = { 0 };
        if (!Utf8ToWideChar(line, widePath, MAX_PATH)) {
            ZeroMemory(line, sizeof(line));
            continue;
        }

        BOOL isHidden;
        TCHAR errMsg[256] = { 0 };
        if (!CheckProtectedHidden(widePath, &isHidden, errMsg, sizeof(errMsg) / sizeof(TCHAR))) {
            ZeroMemory(line, sizeof(line));
            ZeroMemory(widePath, sizeof(widePath));
            continue;
        }

        if (!isHidden) {
            ZeroMemory(line, sizeof(line));
            ZeroMemory(widePath, sizeof(widePath));
            continue;
        }

        size_t requiredLen = validContentLen + lineLen + 2;
        if (requiredLen >= sizeof(validContent)) {
            fclose(f);
            return FALSE;
        }

        if (!firstLine) {
            validContent[validContentLen++] = '\n';
        }
        memcpy_s(validContent + validContentLen, sizeof(validContent) - validContentLen, line, lineLen);
        validContentLen += lineLen;
        validContent[validContentLen] = '\0';
        firstLine = FALSE;
        ZeroMemory(line, sizeof(line));
        ZeroMemory(widePath, sizeof(widePath));
    }
    fclose(f);

    err = fopen_s(&f, historyPath, "wb");
    if (err || !f) {
        return FALSE;
    }
    if (validContentLen > 0) {
        fwrite(validContent, 1, validContentLen, f);
    }
    fclose(f);

    ProtectHistoryFile(historyPathW);
    return TRUE;
}

BOOL LoadRecentHistory(LPTSTR historyText, DWORD textSize, int maxEntries) {
    if (!historyText || textSize == 0 || maxEntries <= 0) {
        return FALSE;
    }

    TCHAR historyPathW[MAX_PATH] = { 0 };
    if (!GetHistoryFilePath(historyPathW, MAX_PATH)) {
        return FALSE;
    }

    char historyPath[MAX_PATH * 4] = { 0 };
    WideCharToUtf8(historyPathW, historyPath, sizeof(historyPath));

    FILE* f = NULL;
    errno_t err = fopen_s(&f, historyPath, "rb");
    if (err || !f) {
        return FALSE;
    }

    char line[MAX_PATH * 4] = { 0 };
    TCHAR result[MAX_PATH * 200] = { 0 };
    BOOL firstLine = TRUE;
    int count = 0;
    size_t resultLen = 0;

    while (fgets(line, sizeof(line), f) && count < maxEntries) {
        char* newline = strrchr(line, '\n');
        if (newline) *newline = '\0';

        size_t lineLen = strlen(line);
        if (lineLen == 0) {
            ZeroMemory(line, sizeof(line));
            continue;
        }

        TCHAR wideLine[MAX_PATH] = { 0 };
        if (!Utf8ToWideChar(line, wideLine, MAX_PATH)) {
            ZeroMemory(line, sizeof(line));
            continue;
        }

        size_t wideLen = _tcslen(wideLine);
        size_t requiredLen = resultLen + wideLen + 2;
        if (requiredLen >= sizeof(result) / sizeof(TCHAR)) {
            fclose(f);
            return FALSE;
        }

        if (!firstLine) {
            result[resultLen++] = '\n';
        }
        memcpy_s(result + resultLen, (sizeof(result) / sizeof(TCHAR)) - resultLen, wideLine, wideLen * sizeof(TCHAR));
        resultLen += wideLen;
        result[resultLen] = '\0';
        firstLine = FALSE;
        count++;
        ZeroMemory(line, sizeof(line));
        ZeroMemory(wideLine, sizeof(wideLine));
    }
    fclose(f);

    if (resultLen == 0) {
        _tcscpy_s(historyText, textSize, _T("暂无历史记录"));
        return TRUE;
    }

    if (resultLen >= textSize) {
        return FALSE;
    }
    _tcscpy_s(historyText, textSize, result);
    return TRUE;
}

// 更新结果显示文本
void UpdateResultText(LPCTSTR text) {
    SetWindowText(hLblResult, text);
}

// 浏览文件选择
void BrowseFile(HWND hDlg) {
    CleanupHistory();

    TCHAR historyText[2048];
    if (LoadRecentHistory(historyText, sizeof(historyText) / sizeof(TCHAR), 5)) {
        TCHAR displayText[2048];
        _stprintf_s(displayText, sizeof(displayText) / sizeof(TCHAR), _T("最近隐藏记录（最多5条）：\n%s"), historyText);
        UpdateResultText(displayText);
    }

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
            if (!IsAdmin()) {
                UpdateResultText(_T("❌ 权限不足：无法执行此操作"));
                ShowPermissionError(_T("设置文件属性需要管理员权限"));
                return TRUE;
            }

            TCHAR filePath[MAX_PATH];
            GetWindowText(hEditPath, filePath, MAX_PATH);

            TCHAR normalizedPath[MAX_PATH] = { 0 };
            TCHAR errMsg[256] = { 0 };

            if (!ValidateFilePath(filePath, normalizedPath, MAX_PATH, errMsg, sizeof(errMsg) / sizeof(TCHAR))) {
                TCHAR resultMsg[512];
                _stprintf_s(resultMsg, sizeof(resultMsg) / sizeof(TCHAR), _T("❌ 错误：%s"), errMsg);
                UpdateResultText(resultMsg);
                return TRUE;
            }

            TCHAR resultMsgSet[512];
            SetProtectedHidden(normalizedPath, resultMsgSet, sizeof(resultMsgSet) / sizeof(TCHAR));
            UpdateResultText(resultMsgSet);
            return TRUE;
        }

        case BTN_REMOVE_ID: {
            if (!IsAdmin()) {
                UpdateResultText(_T("❌ 权限不足：无法执行此操作"));
                ShowPermissionError(_T("移除文件属性需要管理员权限"));
                return TRUE;
            }

            TCHAR filePath[MAX_PATH];
            GetWindowText(hEditPath, filePath, MAX_PATH);

            TCHAR normalizedPath[MAX_PATH] = { 0 };
            TCHAR errMsg[256] = { 0 };

            if (!ValidateFilePath(filePath, normalizedPath, MAX_PATH, errMsg, sizeof(errMsg) / sizeof(TCHAR))) {
                TCHAR resultMsg[512];
                _stprintf_s(resultMsg, sizeof(resultMsg) / sizeof(TCHAR), _T("❌ 错误：%s"), errMsg);
                UpdateResultText(resultMsg);
                return TRUE;
            }

            TCHAR resultMsgRemove[512];
            RemoveProtectedHidden(normalizedPath, resultMsgRemove, sizeof(resultMsgRemove) / sizeof(TCHAR));
            UpdateResultText(resultMsgRemove);
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
