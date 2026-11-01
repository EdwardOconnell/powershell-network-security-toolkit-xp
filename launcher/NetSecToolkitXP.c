/*
 * NetSecToolkitXP.exe - launcher for the NetSecToolkitXP PowerShell module.
 * Copyright (c) 2026 Edward O'Connell III. MIT License (see LICENSE).
 *
 * Double-click it to open the toolkit menu (Start-NetSecToolkitXP), or run
 * it from a command prompt with a command to run that instead, e.g.
 *     NetSecToolkitXP.exe Invoke-XPSecurityCheck -ActiveScan
 *
 * It finds the NetSecToolkitXP folder next to the .exe, checks that
 * Windows PowerShell 2.0 is installed, and starts powershell.exe with
 * -ExecutionPolicy Bypass for that one process, so nobody has to change
 * the execution policy or know Import-Module.
 *
 * Written for Windows XP SP3 (32-bit): plain Win32 API, no C runtime, so it
 * only imports functions that exist in XP's kernel32.dll and user32.dll.
 * Build: see build.sh (mingw-w64, i686).
 */
#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0501
#include <windows.h>

#define TITLE L"NetSecToolkitXP"
#define CMD_MAX 8192

static wchar_t g_exe[MAX_PATH];
static wchar_t g_dir[MAX_PATH];
static wchar_t g_psd1[MAX_PATH + 64];
static wchar_t g_ps[MAX_PATH];
static wchar_t g_msg[2048];
static wchar_t g_cmd[CMD_MAX];

/* No C runtime: the compiler may still emit calls to memset for zeroing. */
void *memset(void *dst, int c, unsigned int n)
{
    unsigned char *p = (unsigned char *)dst;
    while (n--) *p++ = (unsigned char)c;
    return dst;
}

static void Fail(const wchar_t *text)
{
    MessageBoxW(NULL, text, TITLE, MB_OK | MB_ICONERROR);
    ExitProcess(1);
}

static int FileExists(const wchar_t *path)
{
    DWORD a = GetFileAttributesW(path);
    return (a != INVALID_FILE_ATTRIBUTES) && !(a & FILE_ATTRIBUTE_DIRECTORY);
}

/* Appends src to dst (capacity cap, in characters). Returns 0 if it would overflow. */
static int Append(wchar_t *dst, int cap, const wchar_t *src)
{
    int used = lstrlenW(dst);
    int add = lstrlenW(src);
    if (used + add + 1 > cap) return 0;
    lstrcpyW(dst + used, src);
    return 1;
}

/* Appends src inside a PowerShell single-quoted string: ' becomes ''. */
static int AppendPsQuoted(wchar_t *dst, int cap, const wchar_t *src)
{
    int used = lstrlenW(dst);
    if (used + 2 > cap) return 0;
    dst[used++] = L'\'';
    for (; *src; src++) {
        if (*src == L'\'') {
            if (used + 3 > cap) return 0;
            dst[used++] = L'\'';
        } else if (used + 2 > cap) {
            return 0;
        }
        dst[used++] = *src;
    }
    if (used + 2 > cap) return 0;
    dst[used++] = L'\'';
    dst[used] = 0;
    return 1;
}

/* The command line after the program name (quoted or not). */
static const wchar_t *ArgsAfterProgram(const wchar_t *cmd)
{
    if (*cmd == L'"') {
        cmd++;
        while (*cmd && *cmd != L'"') cmd++;
        if (*cmd) cmd++;
    } else {
        while (*cmd && *cmd != L' ' && *cmd != L'\t') cmd++;
    }
    while (*cmd == L' ' || *cmd == L'\t') cmd++;
    return cmd;
}

/* The console's Ctrl+C belongs to PowerShell; the launcher just waits. */
static BOOL WINAPI IgnoreCtrl(DWORD type)
{
    (void)type;
    return TRUE;
}

void __stdcall Start(void)
{
    int i, last = -1;
    const wchar_t *args;
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    DWORD code = 1;
    DWORD n = GetModuleFileNameW(NULL, g_exe, MAX_PATH);

    if (n == 0 || n >= MAX_PATH) Fail(L"Could not tell which folder NetSecToolkitXP.exe is in.");
    lstrcpyW(g_dir, g_exe);
    for (i = 0; g_dir[i]; i++) if (g_dir[i] == L'\\') last = i;
    if (last < 0) Fail(L"Could not tell which folder NetSecToolkitXP.exe is in.");
    g_dir[last] = 0;

    lstrcpyW(g_psd1, g_dir);
    if (!Append(g_psd1, MAX_PATH + 64, L"\\NetSecToolkitXP\\NetSecToolkitXP.psd1") || !FileExists(g_psd1)) {
        g_msg[0] = 0;
        Append(g_msg, 2048, L"The NetSecToolkitXP folder was not found next to this program.\n\n"
                            L"Keep NetSecToolkitXP.exe and the NetSecToolkitXP folder together, "
                            L"as they came in the zip. Expected:\n\n");
        Append(g_msg, 2048, g_psd1);
        Fail(g_msg);
    }

    if (!ExpandEnvironmentStringsW(L"%SystemRoot%\\system32\\WindowsPowerShell\\v1.0\\powershell.exe", g_ps, MAX_PATH)
        || !FileExists(g_ps)) {
        Fail(L"Windows PowerShell 2.0 is not installed.\n\n"
             L"Install the Windows Management Framework Core for Windows XP (KB968930). "
             L"It needs .NET Framework 2.0 SP1 or later (3.5 SP1 covers it). "
             L"Then run NetSecToolkitXP.exe again.");
    }

    /* "powershell.exe" -NoLogo -NoProfile -ExecutionPolicy Bypass -Command
       "& { Import-Module '<psd1>' -Force; <args or Start-NetSecToolkitXP> }" */
    args = ArgsAfterProgram(GetCommandLineW());
    g_cmd[0] = 0;
    if (!Append(g_cmd, CMD_MAX, L"\"") || !Append(g_cmd, CMD_MAX, g_ps) ||
        !Append(g_cmd, CMD_MAX, L"\" -NoLogo -NoProfile -ExecutionPolicy Bypass -Command \"& { Import-Module ") ||
        !AppendPsQuoted(g_cmd, CMD_MAX, g_psd1) ||
        !Append(g_cmd, CMD_MAX, L" -Force; ") ||
        !Append(g_cmd, CMD_MAX, *args ? args : L"Start-NetSecToolkitXP") ||
        !Append(g_cmd, CMD_MAX, L" }\"")) {
        Fail(L"The command line is too long.");
    }

    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    memset(&pi, 0, sizeof(pi));
    SetConsoleTitleW(TITLE);
    SetConsoleCtrlHandler(IgnoreCtrl, TRUE);

    if (!CreateProcessW(g_ps, g_cmd, NULL, NULL, FALSE, 0, NULL, g_dir, &si, &pi)) {
        Fail(L"Could not start Windows PowerShell (powershell.exe).");
    }
    WaitForSingleObject(pi.hProcess, INFINITE);
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    ExitProcess(code);
}
