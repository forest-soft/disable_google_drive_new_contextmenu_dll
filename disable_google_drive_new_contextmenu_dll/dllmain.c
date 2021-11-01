#include "pch.h"
#include <stdio.h>
#include <strsafe.h>
#include <time.h>
#include <windows.h>
#include <winreg.h>
#include <tlhelp32.h>
#include <Dbghelp.h>
#pragma comment(lib, "Dbghelp")

// 「command」のリダイレクト先のキー名
#define REDIRECT_NEW_CONTEXT_MENU_KEY L"command_xxx"

// リダイレクトさせるレジストリキーのリスト
unsigned char target_registry_key_list[3][1000] = {
    {"SOFTWARE\\Classes\\.gdoc\\ShellNew"},
    {"SOFTWARE\\Classes\\.gsheet\\ShellNew"},
    {"SOFTWARE\\Classes\\.gslides\\ShellNew"},
};

// レジストリキーのハンドルからパスを求めた際のパス(「\REGISTRY\USER\XXX\.gdoc\ShellNew」というパスになる)
unsigned char target_real_registry_key_list[3][1000];

BOOL output_log = FALSE;
char log_path[1000];

void debugLog(char* str, ...);
void getRegistryPath(HKEY hkey, int path_size, unsigned char* path);
void hookIAT(char* module_name, void* old_function, void* new_function);

FARPROC original_RegQueryValueExW;
LSTATUS hook_RegQueryValueExW(HKEY hkey, LPCWSTR name, LPDWORD reserved, LPDWORD type, LPBYTE data, LPDWORD count);

FARPROC original_RegSetValueExW;
LSTATUS hook_RegSetValueExW(HKEY hkey, LPCWSTR name, DWORD reserved, DWORD type, const BYTE* data, DWORD count);

typedef struct _KEY_NAME_INFORMATION {
    ULONG NameLength;
    WCHAR Name[1];
} KEY_NAME_INFORMATION, * PKEY_NAME_INFORMATION;
FARPROC NtQueryKey;

#define STATUS_BUFFER_TOO_SMALL          (0xC0000023L)
#define STATUS_SUCCESS                   (0x00000000L)

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    char path[1000];
    GetModuleFileName(hinstDLL, path, 1000);
    // debugLog("DLLパス：%s", path);

    char* p = strrchr(path, '\\');
    strncpy_s(log_path, sizeof(log_path), path, p - path);
    sprintf_s(log_path, sizeof(log_path), "%s\\log.txt", log_path);
    // debugLog("DLLディレクトリ：%s", log_path);

    LoadLibrary("ntdll.dll");
    NtQueryKey = GetProcAddress(GetModuleHandle("ntdll.dll"), "NtQueryKey");

    HMODULE advapi32 = GetModuleHandle("ADVAPI32.dll");
    original_RegQueryValueExW = GetProcAddress(advapi32, "RegQueryValueExW");
    original_RegSetValueExW = GetProcAddress(advapi32, "RegSetValueExW");

    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
        hookIAT("ADVAPI32.dll", original_RegQueryValueExW, hook_RegQueryValueExW);
        hookIAT("ADVAPI32.dll", original_RegSetValueExW, hook_RegSetValueExW);
        break;
    case DLL_PROCESS_DETACH:
        hookIAT("ADVAPI32.dll", hook_RegQueryValueExW, original_RegQueryValueExW);
        hookIAT("ADVAPI32.dll", hook_RegSetValueExW, original_RegSetValueExW);
        break;
    }

    // リダイレクト対象のレジストリキーの実際のパスを調べる。
    // また、新規作成コンテキストメニューを表示するための「command」キーを削除する。
    for (int i = 0; i < sizeof(target_registry_key_list) / sizeof(target_registry_key_list[0]); i++)
    {
        HKEY key_handle;
        RegOpenKeyEx(HKEY_CURRENT_USER, target_registry_key_list[i], 0, KEY_SET_VALUE, &key_handle);
        if (key_handle != NULL)
        {
            getRegistryPath(key_handle, sizeof(target_real_registry_key_list[i]), target_real_registry_key_list[i]);

            RegDeleteValue(key_handle, "command");

            RegCloseKey(key_handle);
        }
    }

    return TRUE;
}

void debugLog(char* str, ...)
{
    if (!output_log)
    {
        return;
    }

    FILE* fp;
    fopen_s(&fp, log_path, "a");
    if (fp != NULL)
    {
        time_t now = time(NULL);
        struct tm tm;
        localtime_s(&tm, &now);
        char time_str[256];
        strftime(time_str, sizeof(time_str), "%Y/%m/%d %H:%M:%S", &tm);
        fprintf(fp, "[%s] ", time_str);

        va_list args;
        va_start(args, str);
        vfprintf(fp, str, args);
        va_end(args);
        fprintf(fp, "\n");

        fclose(fp);
    }
}

void hookIAT(char* module_name, void* old_function, void* new_function)
{
    HANDLE snapshot_handle = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
    if (snapshot_handle == INVALID_HANDLE_VALUE)
    {
        return;
    }

    MODULEENTRY32 entry;
    entry.dwSize = sizeof(MODULEENTRY32);
    if (!Module32First(snapshot_handle, &entry))
    {
        return;
    }

    do
    {
        // モジュール(DLL)のリストを取得する。
        ULONG directory_entry_size;
        PIMAGE_IMPORT_DESCRIPTOR directry_entry;
        directry_entry = (PIMAGE_IMPORT_DESCRIPTOR)ImageDirectoryEntryToData(entry.hModule, TRUE, IMAGE_DIRECTORY_ENTRY_IMPORT, &directory_entry_size);
        if (directry_entry == NULL)
        {
            return;
        }

        // モジュールのリストからHookしたいDLLを探し出す。
        while (directry_entry->Name != 0)
        {
            char* name = (char*)entry.hModule + directry_entry->Name;
            if (strcmp(name, module_name) == 0) {
                break;
            }
            directry_entry++;
        }

        if (directry_entry->Name == 0)
        {
            return;
        }

        // 関数を置き換える。
        PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((char*)entry.hModule + directry_entry->FirstThunk);
        while (thunk->u1.Function) {
            if (IMAGE_SNAP_BY_ORDINAL(thunk->u1.Ordinal))
            {
                continue;
            }

            PROC* paddr = (PROC*)&thunk->u1.Function;
            if (*paddr == old_function) {
                DWORD old_protect;
                VirtualProtect(paddr, sizeof(paddr), PAGE_EXECUTE_READWRITE, &old_protect);
                *paddr = new_function;
                VirtualProtect(paddr, sizeof(paddr), old_protect, &old_protect);

                break;
            }

            thunk++;
        }

    } while (Module32Next(snapshot_handle, &entry));

    CloseHandle(snapshot_handle);
}

void getRegistryPath(HKEY hkey, int path_size, unsigned char* path)
{
    if (!NtQueryKey) {
        return "";
    }

    DWORD size = 0;
    DWORD result = 0;

    result = NtQueryKey(hkey, 3, 0, 0, &size);
    if (result != STATUS_BUFFER_TOO_SMALL) {
        debugLog("バッファが無い");
        return "";
    }

    PKEY_NAME_INFORMATION Info;
    Info = (PKEY_NAME_INFORMATION)_alloca(size);

    result = NtQueryKey(hkey, 3, Info, (ULONG)size, &size);
    if (result != STATUS_SUCCESS) {
        debugLog("パス取得失敗");
        return "";
    }

    size = size / sizeof(wchar_t) - 2;

    unsigned char value[1000];

    int value_counter = 0;

    for (int i = 0; i < size && value_counter < 1000 - 2; i++)
    {
        if (*(Info->Name + i) == '\0') {
            continue;
        }
        value[value_counter] = *(Info->Name + i);
        value_counter++;
    }
    value[value_counter] = '\0';

    strcpy_s(path, path_size, value);
}

LSTATUS hook_RegQueryValueExW(HKEY hkey, LPCWSTR name, LPDWORD reserved, LPDWORD type, LPBYTE data, LPDWORD count)
{
    unsigned char read_path[1000];
    getRegistryPath(hkey, sizeof(read_path), read_path);

    if (wcslen(name) != 0)
    {
        debugLog("読み込みパス:%s\\%ls", read_path, name);
    }
    else
    {
        debugLog("読み込みパス:%s", read_path);
    }

    // リダイレクト対象のキーへの読み込みであれば、リダイレクトさせる。
    for (int i = 0; i < sizeof(target_real_registry_key_list) / sizeof(target_real_registry_key_list[0]); i++) {
        if (target_real_registry_key_list[i] == NULL) {
            continue;
        }

        if (strcmp(read_path, target_real_registry_key_list[i]) == 0 && wcscmp(name, L"command") == 0)
        {
            debugLog("読み込みリダイレクト！");
            name = REDIRECT_NEW_CONTEXT_MENU_KEY;
        }
    }

    return original_RegQueryValueExW(hkey, name, reserved, type, data, count);
}


LSTATUS hook_RegSetValueExW(HKEY hkey, LPCWSTR name, DWORD reserved, DWORD type, const BYTE* data, DWORD count)
{
    unsigned char write_path[1000];
    getRegistryPath(hkey, sizeof(write_path), write_path);

    if (wcslen(name) != 0)
    {
        debugLog("書き込みパス:%s\\%ls", write_path, name);
    }
    else
    {
        debugLog("書き込みパス:%s", write_path);
    }

    // リダイレクト対象のキーへの書き込みであれば、リダイレクトさせる。
    for (int i = 0; i < sizeof(target_real_registry_key_list) / sizeof(target_real_registry_key_list[0]); i++) {
        if (target_real_registry_key_list[i] == NULL) {
            continue;
        }

        if (strcmp(write_path, target_real_registry_key_list[i]) == 0 && wcscmp(name, L"command") == 0)
        {
            debugLog("書き込みリダイレクト！");
            name = REDIRECT_NEW_CONTEXT_MENU_KEY;
        }
    }

    return original_RegSetValueExW(hkey, name, reserved, type, data, count);
}



