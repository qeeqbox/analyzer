__G__ = "(G)bd249ce4"

from analyzer.logger.logger import verbose, verbose_flag, verbose_timeout
from re import I, compile, findall

detections = {"APIs" :compile(r"(accept|AddCredentials|AdjustTokenPrivileges|AttachThreadInput|bind|BitBlt|CertDeleteCertificateFromStore|CertOpenSystemStore|CheckRemoteDebuggerPresent|CloseHandle|closesocket|connect|ConnectNamedPipe|ControlService|CopyFile|CreateDirectory|CreateFile|CreateFileMapping|CreateMutex|CreateProcess|CreateRemoteThread|CreateService|CreateThread|CreateToolhelp32Snapshot|CryptAcquireContext|CryptEncrypt|DeleteFile|DeviceIoControl|DisconnectNamedPipe|DNSQuery|EnableExecuteProtectionSupport|EnumProcesses|EnumProcessModules|ExitProcess|ExitThread|FindFirstFile|FindNextFile|FindResource|FindWindow|FltRegisterFilter|FtpGetFile|FtpOpenFile|FtpPutFile|GetAdaptersInfo|GetAsyncKeyState|GetCommandLine|GetComputerName|GetCurrentProcess|GetDC|GetDriveType|GetFileAttributes|GetFileSize|GetForegroundWindow|GetHostByAddr|GetHostByName|GetHostName|GetKeyState|GetModuleFileName|GetModuleHandle|GetProcAddress|GetStartupInfo|GetSystemDefaultLangId|GetSystemDirectory|GetTempFileName|GetTempPath|GetThreadContext|GetTickCount|GetUpdateRect|GetUpdateRgn|GetUrlCacheEntryInfo|GetUserName|GetVersionEx|GetWindowsDirectory|GetWindowThreadProcessId|HttpQueryInfo|HttpSendRequest|IcmpSendEcho|inet_addr|InternetCloseHandle|InternetConnect|InternetCrackUrl|InternetGetConnectedState|InternetOpen|InternetOpenUrl|InternetQueryDataAvailable|InternetQueryOption|InternetReadFile|InternetWriteFile|IsBadReadPtr|IsBadWritePtr|IsDebuggerPresent|IsNTAdmin|IsWoW64Process|LdrLoadDll|listen|LoadLibrary|LoadResource|LockResource|LsaEnumerateLogonSessions|MapViewOfFile|MapVirtualKey|Module32First/Module32Next|NetScheduleJobAdd|NetShareEnum|NtQueryDirectoryFile|NtQueryInformationProcess|NtSetInformationProcess|OpenFileMapping|OpenMutex|OpenProcess|OutputDebugString|PeekNamedPipe|Process32First|Process32Next|QueueUserAPC|ReadFile|ReadProcessMemory|recv|RegCloseKey|RegCreateKey|RegDeleteKey|RegDeleteValue|RegEnumKey|RegisterHotKey|RegOpenKey|ResumeThread|RtlCreateRegistryKey|RtlWriteRegistryValue|SamIConnect|SamIGetPrivateData|SamQueryInformationUse|send|sendto|SetFilePointer|SetFileTime|SetKeyboardState|SetThreadContext|SetWindowsHook|SetWindowsHookEx|SfcTerminateWatcherThread|ShellExecute|Sleep|socket|StartService|StartServiceCtrlDispatcher|SuspendThread|System|TerminateProcess|Thread32First|Thread32Next|Toolhelp32ReadProcessMemory|UnhandledExceptionFilter|URLDownload|URLDownloadToFile|VirtualAlloc|VirtualAllocEx|VirtualFree|VirtualProtect|VirtualProtectEx|WideCharToMultiByte|WinExec|WriteFile|WriteProcessMemory|WSASend|WSASocket|WSAStartup|ZwQueryInformation)", I)}

@verbose(True, verbose_flag, verbose_timeout, "Finding suspicious functions")
def startanalyzing(data):
	for detectonroot in detections:
		_List = []
		x = findall(detections[detectonroot], data["StringsRAW"]["wordsstripped"])
		if len(x) > 0:
			for _ in x:
				_List.append(_)
		for x in set(_List):
			data["QBDETECT"]["Detection"].append({"Count":_List.count(x), "Offset":"Unavailable", "Rule":"API Alert", "Match":x, "Parsed":None})