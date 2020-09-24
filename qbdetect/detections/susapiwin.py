'''
    __G__ = "(G)bd249ce4"
    detector -> detect -> susp
    You can add more DETECTIONS
'''

from re import I, findall
from re import compile as rcompile
from analyzer.logger.logger import verbose

DETECTIONS = {"APIs":rcompile(r"(accept|AddCredentials|AdjustTokenPrivileges|AttachThreadInput|bind|BitBlt|CertDeleteCertificateFromStore|CertOpenSystemStore|CheckRemoteDebuggerPresent|CloseHandle|closesocket|connect|ConnectNamedPipe|ControlService|CopyFile|CreateDirectory|CreateFile|CreateFileMapping|CreateMutex|CreateProcess|CreateRemoteThread|CreateService|CreateThread|CreateToolhelp32Snapshot|CryptAcquireContext|CryptEncrypt|DeleteFile|DeviceIoControl|DisconnectNamedPipe|DNSQuery|EnableExecuteProtectionSupport|EnumProcesses|EnumProcessModules|ExitProcess|ExitThread|FindFirstFile|FindNextFile|FindResource|FindWindow|FltRegisterFilter|FtpGetFile|FtpOpenFile|FtpPutFile|GetAdaptersInfo|GetAsyncKeyState|GetCommandLine|GetComputerName|GetCurrentProcess|GetDC|GetDriveType|GetFileAttributes|GetFileSize|GetForegroundWindow|GetHostByAddr|GetHostByName|GetHostName|GetKeyState|GetModuleFileName|GetModuleHandle|GetProcAddress|GetStartupInfo|GetSystemDefaultLangId|GetSystemDirectory|GetTempFileName|GetTempPath|GetThreadContext|GetTickCount|GetUpdateRect|GetUpdateRgn|GetUrlCacheEntryInfo|GetUserName|GetVersionEx|GetWindowsDirectory|GetWindowThreadProcessId|HttpQueryInfo|HttpSendRequest|IcmpSendEcho|inet_addr|InternetCloseHandle|InternetConnect|InternetCrackUrl|InternetGetConnectedState|InternetOpen|InternetOpenUrl|InternetQueryDataAvailable|InternetQueryOption|InternetReadFile|InternetWriteFile|IsBadReadPtr|IsBadWritePtr|IsDebuggerPresent|IsNTAdmin|IsWoW64Process|LdrLoadDll|listen|LoadLibrary|LoadResource|LockResource|LsaEnumerateLogonSessions|MapViewOfFile|MapVirtualKey|Module32First/Module32Next|NetScheduleJobAdd|NetShareEnum|NtQueryDirectoryFile|NtQueryInformationProcess|NtSetInformationProcess|OpenFileMapping|OpenMutex|OpenProcess|OutputDebugString|PeekNamedPipe|Process32First|Process32Next|QueueUserAPC|ReadFile|ReadProcessMemory|recv|RegCloseKey|RegCreateKey|RegDeleteKey|RegDeleteValue|RegEnumKey|RegisterHotKey|RegOpenKey|ResumeThread|RtlCreateRegistryKey|RtlWriteRegistryValue|SamIConnect|SamIGetPrivateData|SamQueryInformationUse|send|sendto|SetFilePointer|SetFileTime|SetKeyboardState|SetThreadContext|SetWindowsHook|SetWindowsHookEx|SfcTerminateWatcherThread|ShellExecute|Sleep|socket|StartService|StartServiceCtrlDispatcher|SuspendThread|System|TerminateProcess|Thread32First|Thread32Next|Toolhelp32ReadProcessMemory|UnhandledExceptionFilter|URLDownload|URLDownloadToFile|VirtualAlloc|VirtualAllocEx|VirtualFree|VirtualProtect|VirtualProtectEx|WideCharToMultiByte|WinExec|WriteFile|WriteProcessMemory|WSASend|WSASocket|WSAStartup|ZwQueryInformation)", I)}

@verbose(True, verbose_output=False, timeout=None, _str="Finding suspicious functions")
def startanalyzing(data):
    '''
    start extracting susp patterns
    '''
    for detectonroot in DETECTIONS:
        temp_list = []
        temp_var = findall(DETECTIONS[detectonroot], data["StringsRAW"]["wordsstripped"])
        if len(temp_var) > 0:
            for _ in temp_var:
                temp_list.append(_)
        for temp_var in set(temp_list):
            data["QBDETECT"]["Detection"].append({"Count":temp_list.count(temp_var), "Offset":"Unavailable", "Rule":"API Alert", "Match":temp_var, "Parsed":None})
