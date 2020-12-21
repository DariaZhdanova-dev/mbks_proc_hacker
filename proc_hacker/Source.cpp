#define _WIN32_WINNT 0x0A00
#define PRINT_PERM(name) \
		if (perms & name) \
		{ \
			jsonFile << #name " "; \
			perms &= ~name; \
			good = 1; \
		}

#include <iostream>
#include "jsonxx/jsonxx.h"
#include "jsonxx/jsonxx.cc"
#include <windows.h>
#include <sddl.h>
#include <tlhelp32.h>
#include <Psapi.h>
#include <tchar.h>
#include <wchar.h>
#include <strsafe.h>
#include <winbase.h>
#include <winnt.h>
#include <vector>
#include <atlstr.h>
#include <strsafe.h>
#include <processthreadsapi.h>
#include <aclapi.h>
#include <comdef.h>
#include <winver.h>
#include <cstring>
#include <filesystem>
#include <fstream>
TCHAR dll[10000] = { 0 };
using namespace std;
using namespace jsonxx;
#define BUFSIZE 4096 
jsonxx::Object jsonObj;
jsonxx::Object jsonObj2;
jsonxx::Array _Masks;
jsonxx::Array _newLpNames;
jsonxx::Array _rights;
HANDLE g_hInputFile = NULL;
jsonxx::Array dllArr;
ofstream jsonFile;
struct StructProcParam
{
	LPSTR UserName; 
	PTOKEN_USER pUser; //Указывает структуру SID_AND_ATTRIBUTES, представляющую пользователя, связанного с маркером доступа
	DWORD uSize = 0;
	SID_NAME_USE SidType; //Тип перечисления SID_NAME_USE содержит значения, определяющие тип идентификатора безопасности (SID)
	TCHAR lpName[256];
	TCHAR lpDomain[256];
	PROCESS_MITIGATION_DEP_POLICY dep;
	PROCESS_MITIGATION_ASLR_POLICY aslr;
	PSECURITY_DESCRIPTOR pSD;
	PSID pSID;
	PACL pacl, pdacl;
	LPWSTR SIDParam;
	PROCESS_MEMORY_COUNTERS procMem;
	BOOL is = FALSE;
	TCHAR ProcPath[256] = { 0 };
	TCHAR buffer[256] = { 0 };
	TCHAR NameFile[256] = { 0 };
	DWORD sizeName;
}Proc;
void ErrorExit(const wchar_t* lpszFunction)
{
	LPVOID lpMsgBuf;
	LPVOID lpDisplayBuf;
	DWORD dw = GetLastError();
	FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, dw, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPTSTR)&lpMsgBuf, 0, NULL);
	lpDisplayBuf = (LPVOID)LocalAlloc(LMEM_ZEROINIT, (lstrlen((LPCTSTR)lpMsgBuf) + lstrlen((LPCTSTR)lpszFunction) + 40) * sizeof(TCHAR));
	StringCchPrintf((LPTSTR)lpDisplayBuf, LocalSize(lpDisplayBuf) / sizeof(TCHAR), TEXT("%s failed with error %d: %s"), lpszFunction, dw, lpMsgBuf);
	MessageBox(NULL, (LPCTSTR)lpDisplayBuf, TEXT("Error"), MB_OK);
	LocalFree(lpMsgBuf);
	LocalFree(lpDisplayBuf);
	ExitProcess(dw);
}
BOOL SetPrivilege(HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege)
{
	TOKEN_PRIVILEGES tp;
	LUID luid;
	if (!LookupPrivilegeValue(NULL, // lookup privilege on local system
		lpszPrivilege,   // privilege to lookup 
		&luid))        // receives LUID of privilege
	{
		return 0;
	}
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	if (bEnablePrivilege)
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	else
		tp.Privileges[0].Attributes = 0;
	if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL))
	{
		return FALSE;
	}
	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
	{
		return FALSE;
	}
	return TRUE;
}
int get_integrity_level(HANDLE hProcess_i)
{
	HANDLE hProcessToken = NULL;
	DWORD dwIntegrityLevel;
	DWORD dwLengthNeeded;
	if (!OpenProcessToken(hProcess_i, TOKEN_QUERY, &hProcessToken) || !hProcessToken)
	{
		jsonObj << "Integrity level" << "Undected";
		return 0;
	}
	GetTokenInformation(hProcessToken, TokenIntegrityLevel, NULL, 0, &dwLengthNeeded);
	if (GetLastError() == ERROR_INSUFFICIENT_BUFFER)
	{
		PTOKEN_MANDATORY_LABEL pTIL = reinterpret_cast<PTOKEN_MANDATORY_LABEL>(new BYTE[dwLengthNeeded]);
		if (GetTokenInformation(hProcessToken, TokenIntegrityLevel, pTIL, dwLengthNeeded, &dwLengthNeeded))
		{
			dwIntegrityLevel = *GetSidSubAuthority(pTIL->Label.Sid, (DWORD)(UCHAR)(*GetSidSubAuthorityCount(pTIL->Label.Sid) - 1));
			if (dwIntegrityLevel == SECURITY_MANDATORY_UNTRUSTED_RID)
			{
				jsonObj << "Integrity level" << "UNTRUSTED";
				return 0;
			}
			else if (dwIntegrityLevel == SECURITY_MANDATORY_LOW_RID)
			{
				jsonObj << "Integrity level" << "LOW";
				return 1;
			}
			else if (dwIntegrityLevel >= SECURITY_MANDATORY_MEDIUM_RID && dwIntegrityLevel < SECURITY_MANDATORY_HIGH_RID)
			{
				jsonObj << "Integrity level" << "MEDIUM";
				//cout << jsonObj.json() << endl;
				return 2;
			}
			else if (dwIntegrityLevel >= SECURITY_MANDATORY_HIGH_RID && dwIntegrityLevel < SECURITY_MANDATORY_SYSTEM_RID)
			{
				jsonObj << "Integrity level" << "HIGH";
				return 3;
			}
			else if (dwIntegrityLevel >= SECURITY_MANDATORY_SYSTEM_RID && dwIntegrityLevel < SECURITY_MANDATORY_PROTECTED_PROCESS_RID)
			{
				jsonObj << "Integrity level" << "SYSTEM";
				return 4;
			}
			else if (dwIntegrityLevel == SECURITY_MANDATORY_PROTECTED_PROCESS_RID)
			{
				jsonObj << "Integrity level" << "PROTECTED";
				return 5;
			}
		}
	}
	return -1;
}
DWORD pid_from_name(const wchar_t* proc_name)
{
	PROCESSENTRY32 pe32;
	size_t length = wcslen(proc_name);
	HANDLE CONST hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (INVALID_HANDLE_VALUE == hSnapshot)
	{
		return 0;
	}
	pe32.dwSize = sizeof(PROCESSENTRY32);
	Process32First(hSnapshot, &pe32); //получаем процесс
	do
	{
		if (wcsncmp(pe32.szExeFile, proc_name, length) == 0)
		{
			if (length == wcslen(pe32.szExeFile))
				return pe32.th32ProcessID;
		}
	} while (Process32Next(hSnapshot, &pe32));
	return 0;
}
bool change_integrity_level(HANDLE proc, const TCHAR* asking_level)
{
	int answer;
	int ask = 0;
	bool set_token_info = false;
	HANDLE hProcessToken = NULL;
	DWORD dwreturnLength;
	if (!proc)
	{
		return false;
	}
	answer = get_integrity_level(proc);
	PSID sid;
	LPCWSTR sidStr;
	if (answer == 0)
	{
		return false;
	}
	if (_tccmp(asking_level, L"Untrusted") == 0)
	{
		ask = 0;
		sidStr = L"S-1-16-0";
	}
	else if (_tccmp(asking_level, L"Low") == 0)
	{
		ask = 1;
		sidStr = L"S-1-16-4096";
	}
	else if (_tccmp(asking_level, L"Medium") == 0)
	{
		ask = 2;
		sidStr = L"S-1-16-8192";
	}
	else if (_tccmp(asking_level, L"High") == 0)
	{
		ask = 3;
		sidStr = L"S-1-16-12288";
	}
	else if (_tccmp(asking_level, L"System") == 0)
	{
		ask = 4;
		sidStr = L"S-1-16-16384";
	}
	else if (_tccmp(asking_level, L"Protected") == 0)
	{
		return false;
	}
	else
	{
		return false;
	}
	if (ask == answer)
	{
		return true;
	}
	if (ask > answer)
	{
		return false;
	}
	ConvertStringSidToSid(sidStr, &sid);
	if (!OpenProcessToken(proc, TOKEN_QUERY | TOKEN_ADJUST_DEFAULT, &hProcessToken) || !hProcessToken)
	{
		return false;
	}
	GetTokenInformation(hProcessToken, TokenIntegrityLevel, NULL, 0, &dwreturnLength);
	if (GetLastError() == ERROR_INSUFFICIENT_BUFFER)
	{
		PTOKEN_MANDATORY_LABEL mandatoryLabel = reinterpret_cast<PTOKEN_MANDATORY_LABEL>(new BYTE[dwreturnLength]);
		GetTokenInformation(hProcessToken, TokenIntegrityLevel, mandatoryLabel, dwreturnLength, &dwreturnLength);
		mandatoryLabel->Label.Attributes = SE_GROUP_INTEGRITY;
		mandatoryLabel->Label.Sid = sid;
		if (!SetTokenInformation(hProcessToken, TokenIntegrityLevel, mandatoryLabel, dwreturnLength))
		{
			return false;
		}
		get_integrity_level(proc);
	}
	return true;
}
int printFileDescriptions(const wchar_t* filename)
{
	HRESULT hr;
	char buf[MAX_PATH];
	int dwLen = GetFileVersionInfoSize(filename, NULL);
	if (!dwLen)
	{
		jsonObj << "Description" << "no information";
		return false;
	}
	auto* sKey = new BYTE[dwLen];
	unique_ptr<BYTE[]> skey_automatic_cleanup(sKey);
	if (!GetFileVersionInfo(filename, NULL, dwLen, sKey))
	{
		jsonObj << "Description" << "no information";
		return false;
	}
	struct LANGANDCODEPAGE
	{
		WORD wLanguage;
		WORD wCodePage;
	} *lpTranslate;
	UINT cbTranslate = 0;
	if (!VerQueryValue(sKey, L"\\VarFileInfo\\Translation", (LPVOID*)&lpTranslate, &cbTranslate))
	{
		jsonObj << "Description" << "no information";
		return false;
	}
	for (unsigned int i = 0; i < (cbTranslate / sizeof(LANGANDCODEPAGE)); i++)
	{
		wchar_t fileDescriptionKey[256];
		wchar_t* fileDescription = NULL;
		UINT fileDescriptionSize;
		hr = StringCchPrintf(fileDescriptionKey, 50, TEXT("\\StringFileInfo\\%04x%04x\\FileDescription"), lpTranslate[i].wLanguage, lpTranslate[i].wCodePage);
		if (FAILED(hr))
		{
				jsonObj << "Description" << "no information";
				return false;
		}
		if (VerQueryValue(sKey, fileDescriptionKey, (LPVOID*)&fileDescription, &fileDescriptionSize))
		{
			size_t len = wcslen(fileDescription);
			int size_needed = WideCharToMultiByte(CP_ACP, 0, &fileDescription[0],len, NULL, 0, NULL, NULL);
			WideCharToMultiByte(CP_ACP, 0, &fileDescription[0],len, &buf[0], size_needed, NULL, NULL);
			buf[len] = '\0';
			for (int i = 0; i < len; i++)
			{
				if ((unsigned char)buf[i] >= 192 && (unsigned char)buf[i] <= 255)
				{
					jsonObj << "Description" << "no information";
					return false;
				}
			}
			jsonObj << "Description:" << buf;
			return true;
		}
	}
	return TRUE;
}
int PrintModuleList(DWORD CONST dwProcessId)
{
	MODULEENTRY32 meModuleEntry;
	int res = 0;
	TCHAR buffer[256] = { 0 };
	CStringA dll;
	HANDLE CONST hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwProcessId);
	if (INVALID_HANDLE_VALUE == hSnapshot)
	{
		return res;
	}
	meModuleEntry.dwSize = sizeof(MODULEENTRY32);
	Module32First(hSnapshot, &meModuleEntry);
	int i = 0;
	do {
		wsprintf(buffer, L"%s", meModuleEntry.szModule);
 		if (wcsstr(buffer, TEXT("mscore.dll")) != 0 || wcsstr(buffer, TEXT("shcore.dll")) != 0)
		{
			res = 1;
		}
		i++;
		wsprintf(buffer, L"%s", meModuleEntry.szModule);
		dll+=buffer;
		dll+= TEXT(" ");
		memset(buffer, 0, sizeof(buffer));
	} while (Module32Next(hSnapshot, &meModuleEntry));
	const size_t newsizea = (dll.GetLength() + 1);
	char nstringa [100000];
	strcpy_s(nstringa, newsizea, dll);
	jsonObj << "Libraries" << nstringa;
	return res;
}
bool IsWow64(HANDLE hProcess, BOOL& isWow64)
{
	typedef BOOL(WINAPI* LPFN_ISWOW64PROCESS) (HANDLE, PBOOL);
	LPFN_ISWOW64PROCESS fnIsWow64Process;
	fnIsWow64Process = (LPFN_ISWOW64PROCESS)GetProcAddress(GetModuleHandle(TEXT("kernel32")), "IsWow64Process");
	bool res = fnIsWow64Process != NULL && fnIsWow64Process(hProcess, &isWow64);
	return res;
}
//void check_aslr_dep(HANDLE process)
//{
//	PROCESS_MITIGATION_DEP_POLICY DEPStruct;
//	PROCESS_MITIGATION_ASLR_POLICY ASLRStruct;
//	if (!GetProcessMitigationPolicy(process, ProcessDEPPolicy, (PVOID)&DEPStruct, sizeof(_PROCESS_MITIGATION_DEP_POLICY)))
//	{
//		jsonObj << "DEP" << "Undetected";
//	}
//	if (!DEPStruct.Enable)
//	{
//		jsonObj << "DEP" << std::string("-");
//	}
//	else
//	{
//		jsonObj << "DEP" << std::string("+");
//	}
//	if (!GetProcessMitigationPolicy(process, ProcessASLRPolicy, (PVOID)&ASLRStruct, sizeof(_PROCESS_MITIGATION_ASLR_POLICY)))
//	{
//		jsonObj << "ASLR" << "Undetected";
//	}
//	if (!ASLRStruct.EnableBottomUpRandomization)
//	{
//		jsonObj << "ASLR" << std::string("-");
//	}
//	else
//	{
//		jsonObj << "ASLR" << std::string("+");
//	}
//}
void get_process_privileges(HANDLE process)
{
	HANDLE hProcessToken = NULL;
	DWORD dwLengthNeeded;
	DWORD dwPrivilegeNameSize;
	LPWSTR* ucPrivilegeName;//переделать на динамику
	if (!OpenProcessToken(process, TOKEN_QUERY, &hProcessToken) || !hProcessToken)
	{
		jsonObj << "Privileges" << "Undetected";
		return;
	}
	GetTokenInformation(hProcessToken, TokenPrivileges, NULL, 0, &dwLengthNeeded);
	if (GetLastError() == ERROR_INSUFFICIENT_BUFFER)
	{
		PTOKEN_PRIVILEGES tkp = reinterpret_cast<PTOKEN_PRIVILEGES>(new BYTE[dwLengthNeeded]);
		if (GetTokenInformation(hProcessToken, TokenPrivileges, tkp, dwLengthNeeded, &dwLengthNeeded))
		{
			if (tkp->PrivilegeCount == 0)
			{
				jsonObj << "Privileges" << "No Privileges";
				return;
			}
			CStringA priv;
			for (int i = 0; i < tkp->PrivilegeCount; i++)
			{
				dwPrivilegeNameSize = sizeof ucPrivilegeName;
				LookupPrivilegeName(NULL, &tkp->Privileges[i].Luid, NULL, &dwPrivilegeNameSize);
				LPWSTR szName = new TCHAR[dwPrivilegeNameSize + 1];
				LookupPrivilegeName(NULL, &tkp->Privileges[i].Luid, szName, &dwPrivilegeNameSize);
				if ((tkp->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED_BY_DEFAULT) == SE_PRIVILEGE_ENABLED_BY_DEFAULT)
				{
					priv += szName;
					priv += TEXT(" 1 ");
				}
				else if ((tkp->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED) == SE_PRIVILEGE_ENABLED)
				{
					priv += szName;
					priv += TEXT(" 2 ");
				}
				else if ((tkp->Privileges[i].Attributes & SE_PRIVILEGE_REMOVED) == SE_PRIVILEGE_REMOVED)
				{
					priv += szName;
					priv += TEXT(" 3 ");
				}
				else if ((tkp->Privileges[i].Attributes & SE_PRIVILEGE_USED_FOR_ACCESS) == SE_PRIVILEGE_USED_FOR_ACCESS)
				{
					priv += szName;
					priv += TEXT(" 4 ");
				}
				else
				{
					priv += szName;
					priv += TEXT(" 0 ");
				}
				delete[] szName;
			}
			const size_t newsizea = (priv.GetLength() + 1);
			char nstringa[100000];
			strcpy_s(nstringa, newsizea, priv);
			jsonObj << "Privileges" << nstringa;
			//
		}
	}
}
void ExtractProcessOwner(HANDLE hProcess_i)
{
	HANDLE hProcessToken = NULL;
	char buf[MAX_PATH];
	if (!OpenProcessToken(hProcess_i, TOKEN_QUERY, &hProcessToken) || !hProcessToken)//все проблемы в токенах
	{
		jsonObj << "Domain" << "Undetected";
		jsonObj << "User name" << "Undetected";
	}
	DWORD dwProcessTokenInfoAllocSize = 0;
	GetTokenInformation(hProcessToken, TokenUser, NULL, 0, &dwProcessTokenInfoAllocSize);
	if (GetLastError() == ERROR_INSUFFICIENT_BUFFER)
	{
		PTOKEN_USER pUserToken = reinterpret_cast<PTOKEN_USER>(new BYTE[dwProcessTokenInfoAllocSize]);
		if (pUserToken != NULL)
		{
			if (GetTokenInformation(hProcessToken, TokenUser, pUserToken, dwProcessTokenInfoAllocSize, &dwProcessTokenInfoAllocSize))
			{
				PSID_NAME_USE eUse = new SID_NAME_USE;
				LPWSTR AcctName;
				DWORD dwAcctName = 0;
				LPWSTR DomainName;
				DWORD dwDomainName = 0;
				BOOL bRtnBool = LookupAccountSid(NULL, pUserToken->User.Sid, NULL, &dwAcctName, NULL, &dwDomainName, eUse);
				AcctName = new TCHAR[dwAcctName + 1];
				DomainName = new TCHAR[dwDomainName + 1];
				bRtnBool = LookupAccountSid(NULL, pUserToken->User.Sid, AcctName, &dwAcctName, DomainName, &dwDomainName, eUse);                 // SID type
				if (bRtnBool == FALSE)
				{
					DWORD dwErrorCode = 0;
					dwErrorCode = GetLastError();
					if (dwErrorCode == ERROR_NONE_MAPPED)
					{
						jsonObj << "Domain" << "Undetected";
						jsonObj << "User name" << "Undetected";
					}
					else
					{
						jsonObj << "Domain" << "Undetected";
						jsonObj << "User name" << "Undetected";
					}
					return;

				}
				else if (bRtnBool == TRUE)
				{
					int size_needed = WideCharToMultiByte(CP_UTF8, 0, &DomainName[0], wcslen(DomainName), NULL, 0, NULL, NULL);
					WideCharToMultiByte(CP_UTF8, 0, &DomainName[0], wcslen(DomainName), &buf[0], size_needed, NULL, NULL);
					buf[size_needed] = '\0';
					jsonObj << "Domain" << buf;
					size_needed = WideCharToMultiByte(CP_ACP, 0, &AcctName[0], wcslen(AcctName), NULL, 0, NULL, NULL);
					WideCharToMultiByte(CP_ACP, 0, &AcctName[0], wcslen(AcctName), &buf[0], size_needed, NULL, NULL);
					buf[size_needed] = '\0';
					if (strcmp(buf, "Администратор") == 0)
					{
						jsonObj << "User name" << "Administrator";
						return;
					}
					if (strcmp(buf, "СИСТЕМА") == 0)
					{
						jsonObj << "User name" << "System";
						return;
					}
					if ((unsigned char)buf[0] >= 192 && (unsigned char)buf[0] <= 255)
					{
						jsonObj << "User name" << "User";
						return;
					}
					jsonObj << "User name" << buf;
					return;
					//cout << jsonObj.json() << endl;
				}
			}
		}
	}
	CloseHandle(hProcessToken);
}
void get_process_time(HANDLE proc)
{
	TCHAR buf[200];
	char help[200];
	FILETIME ft[4];
	SYSTEMTIME systemTime;
	if (!GetProcessTimes(proc, &ft[0], &ft[1], &ft[2], &ft[3]))
	{
		jsonObj << "Time" << "Undetected";
		return;
	}
	FileTimeToSystemTime(&ft[0], &systemTime);
	wsprintf(buf, L"%02d-%02d-%d %02d:%02d:%02d",systemTime.wDay, systemTime.wMonth, systemTime.wYear,systemTime.wHour, systemTime.wMinute, systemTime.wSecond);
	int size_needed = WideCharToMultiByte(CP_UTF8, 0, &buf[0], wcslen(buf), NULL, 0, NULL, NULL);
	WideCharToMultiByte(CP_UTF8, 0, &buf[0], wcslen(buf), &help[0], size_needed, NULL, NULL);
	help[size_needed] = '\0';
	jsonObj << "Time" << help;
}
void PrintProcessList()
{
	jsonFile.open("proccess.json");
	PROCESSENTRY32 peProcessEntry;
	char buf[MAX_PATH];
	HANDLE Handle1;
	HANDLE Handle;
	BOOL isWow64 = false;
	BOOL resultKnown;
	CString Owner_process_name;
	LPWSTR Owner_process_sid = new TCHAR[MAX_SID_SIZE];
	LPWSTR privileges = new TCHAR[500];
	HANDLE CONST hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	bool first_rec = true;
	if (INVALID_HANDLE_VALUE == hSnapshot)
	{
		return;
	}
	peProcessEntry.dwSize = sizeof(PROCESSENTRY32);
	Process32First(hSnapshot, &peProcessEntry); //получаем процесс

	jsonFile << "{\"params\":[";
	do {
		Handle1 = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, peProcessEntry.th32ProcessID);
		wsprintf(Proc.buffer, L"%s", peProcessEntry.szExeFile);
		int size_needed = WideCharToMultiByte(CP_UTF8, 0, &Proc.buffer[0], wcslen(peProcessEntry.szExeFile), NULL, 0, NULL, NULL);
		WideCharToMultiByte(CP_UTF8, 0, &Proc.buffer[0], wcslen(peProcessEntry.szExeFile), &buf[0], size_needed, NULL, NULL);
		buf[size_needed] = '\0';
		jsonObj << "Process name" << buf; //Имя exe файла
		memset(Proc.buffer, 0, sizeof(Proc.buffer));
		memset(buf, 0, sizeof(buf));
		_itoa_s(peProcessEntry.th32ProcessID, buf, 10);
		jsonObj << "PID" << buf; //PID
		memset(Proc.buffer, 0, sizeof(Proc.buffer));
		if (Handle1 != NULL)
		{
			GetModuleFileNameEx(Handle1, NULL, Proc.ProcPath, sizeof(Proc.ProcPath)); //Функция GetModuleFileName извлекает полный путь доступа к файлу, содержащему указанный модуль, которым владеет текущий процесс
			size_needed = WideCharToMultiByte(CP_UTF8, 0, &Proc.ProcPath[0], wcslen(Proc.ProcPath), NULL, 0, NULL, NULL);
			WideCharToMultiByte(CP_UTF8, 0, &Proc.ProcPath[0], wcslen(Proc.ProcPath), &buf[0], size_needed, NULL, NULL);
			buf[size_needed] = '\0';
			jsonObj << "FilePath" << buf; //Путь к исполняемому файлу процесса
		}
		else
		{
			jsonObj << "FilePath" << "Undetected";
		}
		printFileDescriptions(Proc.ProcPath);
		memset(Proc.buffer, 0, sizeof(Proc.buffer));
		memset(buf, 0, sizeof(buf));
		_itoa_s(peProcessEntry.th32ParentProcessID, buf, 10);
		jsonObj << "PPID" << buf; //PID
		Handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, peProcessEntry.th32ParentProcessID);
		if (Handle != NULL)
		{
			GetModuleFileNameEx(Handle, NULL, Proc.ProcPath, sizeof(Proc.ProcPath)); //Функция GetModuleFileName извлекает полный путь доступа к файлу, содержащему указанный модуль, которым владеет текущий процесс
			size_needed = WideCharToMultiByte(CP_UTF8, 0, &Proc.ProcPath[0], wcslen(Proc.ProcPath), NULL, 0, NULL, NULL);
			WideCharToMultiByte(CP_UTF8, 0, &Proc.ProcPath[0], wcslen(Proc.ProcPath), &buf[0], size_needed, NULL, NULL);
			buf[size_needed] = '\0';
			jsonObj << "ParentPath" <<buf; //Путь к исполняемому файлу процесса
		}
		else
		{
			jsonObj << "ParentPath" << "Undetected";
		}
		ULONG Error = GetSecurityInfo(Handle1,SE_FILE_OBJECT,OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,&Proc.pSID,NULL,&Proc.pdacl,&Proc.pacl,&Proc.pSD);
		if (Error != ERROR_SUCCESS)
		{
			jsonObj << "SID" << "Undetected"; //SID
		}
		else
		{
			ConvertSidToStringSid(Proc.pSID, &Proc.SIDParam);
			size_needed = WideCharToMultiByte(CP_UTF8, 0, &Proc.SIDParam[0], wcslen(Proc.SIDParam), NULL, 0, NULL, NULL);
			WideCharToMultiByte(CP_UTF8, 0, &Proc.SIDParam[0], wcslen(Proc.SIDParam), &buf[0], size_needed, NULL, NULL);
			buf[size_needed] = '\0';
			jsonObj << "SID" << buf; 
		}
		GetProcessMemoryInfo(Handle1, &Proc.procMem, sizeof(Proc.procMem)); //Извлекает информацию об использовании памяти указанного процесса
		wsprintf(Proc.buffer, L"%d", Proc.procMem.WorkingSetSize);
		size_needed = WideCharToMultiByte(CP_UTF8, 0, &Proc.buffer[0], wcslen(Proc.buffer), NULL, 0, NULL, NULL);
		WideCharToMultiByte(CP_UTF8, 0, &Proc.buffer[0], wcslen(Proc.buffer), &buf[0], size_needed, NULL, NULL);
		buf[size_needed] = '\0';
		jsonObj << "Memory" << buf; //Память
		memset(Proc.buffer, 0, sizeof(Proc.buffer));
		wsprintf(Proc.buffer, L"%d", peProcessEntry.pcPriClassBase);
		size_needed = WideCharToMultiByte(CP_UTF8, 0, &Proc.buffer[0], wcslen(Proc.buffer), NULL, 0, NULL, NULL);
		WideCharToMultiByte(CP_UTF8, 0, &Proc.buffer[0], wcslen(Proc.buffer), &buf[0], size_needed, NULL, NULL);
		buf[size_needed] = '\0';
		jsonObj << "Priority" << buf; //Приоритет
		memset(Proc.buffer, 0, sizeof(Proc.buffer));
		resultKnown = IsWow64(Handle1, isWow64);
		if (resultKnown == false)
			jsonObj << "System type" << "Uknown";
		else
			jsonObj << "System type" << (isWow64 ? "32-bit" : "64-bit");
		//check_aslr_dep(Handle1);
		ExtractProcessOwner(Handle1);
		get_integrity_level(Handle1);
		get_process_privileges(Handle1);
		get_process_time(Handle1);
		//	token_handle = NULL;
		if (PrintModuleList(peProcessEntry.th32ProcessID))
		{
			jsonObj << "Native code" << "+"; //Является код нативным (машинным) или нет
		}
		else
		{
			jsonObj << "Native code" << "-"; //Является код нативным (машинным) или нет
		}
		if (!first_rec) 
		{
			jsonFile << ",";
		}
		first_rec = false;
		jsonFile << jsonObj;
		jsonObj.reset();
		Proc = {};
		//CloseHandle(Handle);
	//	CloseHandle(Handle1);
	} while (Process32Next(hSnapshot, &peProcessEntry));
	jsonFile << "]}";
	jsonFile.close();
	CloseHandle(hSnapshot);
	
}
void find_file_owner_name(LPCWSTR name)
{
	DWORD dwRtnCode = 0;
	PSID pSidOwner = NULL;
	BOOL bRtnBool = TRUE;
	LPTSTR AcctName = NULL;
	LPTSTR DomainName = NULL;
	DWORD dwAcctName = 1, dwDomainName = 1;
	SID_NAME_USE eUse = SidTypeUnknown;
	PSECURITY_DESCRIPTOR pSD = NULL;
	char buf[MAX_PATH];
	dwRtnCode = GetNamedSecurityInfo(name, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION, &pSidOwner, NULL, NULL, NULL, &pSD);
	if (dwRtnCode != ERROR_SUCCESS)
	{
		jsonFile << "\"Owner\": \"" << "\"Undetected\"";
		return;
	}
	bRtnBool = LookupAccountSid(NULL, pSidOwner, NULL, &dwAcctName, NULL, &dwDomainName, &eUse);
	AcctName = new TCHAR[dwAcctName + 1];
	DomainName = new TCHAR[dwDomainName + 1];
	bRtnBool = LookupAccountSid(NULL, pSidOwner, AcctName, &dwAcctName, DomainName, &dwDomainName, &eUse);                 // SID type
	if (bRtnBool == FALSE)
	{
			jsonFile << "\"Owner\": \"" << "\"Undetected\"";
			return;
	}
	if (bRtnBool == TRUE)
	{
		int size_needed = WideCharToMultiByte(CP_ACP, 0, &AcctName[0], wcslen(AcctName), NULL, 0, NULL, NULL);
		WideCharToMultiByte(CP_ACP, 0, &AcctName[0], wcslen(AcctName), &buf[0], size_needed, NULL, NULL);
		buf[size_needed] = '\0';
		if ((unsigned char)buf[0] >= 192 && (unsigned char)buf[0] <= 255)
		{
			if (strcmp(buf, "Администраторы")==0 || strcmp(buf, "Администратор") == 0)
			jsonFile << "\"Owner\": \"" << "Administrator" << "\", ";
			else
				jsonFile << "\"Owner\": \"" << "User" << "\", ";
			return;
		}
		jsonFile << "\"Owner\": \"" << buf << "\", ";
		return;
	}
	delete[] AcctName;
	delete[] DomainName;
}
bool deleteace(LPTSTR name, LPTSTR user, bool mode)
{
	HANDLE hToken;
	DWORD dwReturn = 0;
	PSID pSidOwner = NULL;
	PSECURITY_DESCRIPTOR pSD = NULL;
	PACL ppAcl;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
		return FALSE;
	SetPrivilege(hToken, L"SeSecurityPrivilege", 1);
	dwReturn = GetNamedSecurityInfo(name, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, &ppAcl, NULL, &pSD);
	ACL_SIZE_INFORMATION buf;
	GetAclInformation(ppAcl, &buf, sizeof(ACL_SIZE_INFORMATION), AclSizeInformation);
	LPVOID pTempAce;
	SID_NAME_USE snuSIDNameUse;
	TCHAR szUser[MAX_PATH] = { 0 };
	DWORD dwUserNameLength = MAX_PATH;
	TCHAR szDomain[MAX_PATH] = { 0 };
	DWORD dwDomainNameLength = MAX_PATH;
	ACCESS_ALLOWED_ACE* ACE;
	DWORD Result;
	PSID pSid;
	bool cont = false;
	int size_needed = 0;
	for (DWORD dwIndex = 0; dwIndex < buf.AceCount; dwIndex++)
	{
		pTempAce = nullptr;
		Result = GetAce(ppAcl, dwIndex, &pTempAce);
		if (Result)
		{
			ACE = (ACCESS_ALLOWED_ACE*)pTempAce;
			pSid = (PSID)(&(ACE->SidStart));
			if (LookupAccountSid(NULL, pSid, szUser, &dwUserNameLength, szDomain, &dwDomainNameLength, &snuSIDNameUse) != 0)
			{
				if (wcscmp(user, szUser) == 0 && ((mode == 1 && ACE->Header.AceType == ACCESS_ALLOWED_ACE_TYPE) || (mode == 0 && ACE->Header.AceType == ACCESS_DENIED_ACE_TYPE)))
				{
					if (DeleteAce(ppAcl, dwIndex) == 0)
					{
						ErrorExit(L"DeleteAce");
					}
					else
					{
						Result = SetNamedSecurityInfo(name, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, ppAcl, NULL);
						if (Result != ERROR_SUCCESS)
						{
							ErrorExit(L"SetNamedSecurityInfo");
						}
					}

				}
			}

		}
		SetPrivilege(hToken, L"SeSecurityPrivilege", 0);
	}
}
DWORD AddAceToObjectsSecurityDescriptor(LPTSTR pszObjName, LPTSTR pszTrustee, DWORD dwAccessRights, ACCESS_MODE AccessMode, DWORD dwInheritance)
{
	DWORD dwRes = 0;
	PACL pOldDACL = NULL, pNewDACL = NULL, pSuperNew = NULL;
	PSECURITY_DESCRIPTOR pSD = NULL;
	EXPLICIT_ACCESS ea;
	PEXPLICIT_ACCESS entryList;
	ULONG entryCount;
	bool nice = false;
	if (NULL == pszObjName)
		return ERROR_INVALID_PARAMETER;
	dwRes = GetNamedSecurityInfo(pszObjName, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, &pOldDACL, NULL, &pSD);
	if (ERROR_SUCCESS != dwRes)
	{
		if (pSD != NULL)
			LocalFree((HLOCAL)pSD);
		if (pNewDACL != NULL)
			LocalFree((HLOCAL)pNewDACL);
		return 0;
	}
	ZeroMemory(&ea, sizeof(EXPLICIT_ACCESS));
	ea.grfAccessPermissions = dwAccessRights;
	ea.grfAccessMode = AccessMode;
	ea.grfInheritance = dwInheritance;
	ea.Trustee.TrusteeForm = TRUSTEE_IS_NAME;
	ea.Trustee.TrusteeType = TRUSTEE_IS_USER;
	ea.Trustee.ptstrName = pszTrustee;
	int access = 0;
	if (AccessMode == SET_ACCESS)
		access = 1;
	if (GetExplicitEntriesFromAcl(pOldDACL, &entryCount, &entryList) !=ERROR_SUCCESS)
	return 0;
	if (entryCount != 0)
	{
		if (AccessMode == SET_ACCESS)
		{
			nice = true;
			dwRes = SetEntriesInAcl(1, &ea, NULL, &pNewDACL);
				dwRes = SetEntriesInAcl(entryCount, entryList, pNewDACL, &pSuperNew);
			
		}
		else
			dwRes = SetEntriesInAcl(1, &ea, pOldDACL, &pNewDACL);
	}
	else
		dwRes = SetEntriesInAcl(1, &ea, pOldDACL, &pNewDACL);
	if (ERROR_SUCCESS != dwRes)
	{
		if (pSD != NULL)
			LocalFree((HLOCAL)pSD);
		if (pNewDACL != NULL)
			LocalFree((HLOCAL)pNewDACL);
		return 0;
	}
	if (!nice)
	{
		dwRes = SetNamedSecurityInfo(pszObjName, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, pNewDACL, NULL);

	}
	else
	{
		dwRes = SetNamedSecurityInfo(pszObjName, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, pSuperNew, NULL);

	}
	if (ERROR_SUCCESS != dwRes)
	{
		if (pSD != NULL)
			LocalFree((HLOCAL)pSD);
		if (pNewDACL != NULL)
			LocalFree((HLOCAL)pNewDACL);
		return 0;
	}
	
	//
	return dwRes;
}
int change_owner(char* filename, char* username)
{
	int length = strlen(filename);
	setlocale(LC_ALL, "СP866");
	char cmd[BUFSIZE] = { 0 };
	strncat_s(cmd, "icacls ", strlen("icacls "));
	strncat_s(cmd, filename, length);
	strncat_s(cmd, " /setowner ", 11);
	length = strlen(username);
	strncat_s(cmd, username, length);
	char buf[BUFSIZE] = { 0 };
	FILE* fp;
	if ((fp = _popen(cmd, "r")) == NULL)
	{
		//printf("Error opening pipe!\n");
		return -1;
	}
	while (fgets(buf, BUFSIZE, fp) != NULL)
	{
		OemToCharA(buf, buf);
		//printf("ВЫВОД: %s", buf);
	}
	if (_pclose(fp))
	{
		//printf("Command not found or exited with error status\n");
		return -1;
	}
	if (strncmp(buf, "Успешно обработано 1 файлов; не удалось обработать 0 файлов", BUFSIZE))
		return 1;
	return 0;
}
bool read_acl(LPCWSTR name, bool mode) // change reading
{
	HANDLE hToken;
	DWORD dwReturn = 0;
	PSID pSidOwner = NULL;
	DWORD err;
	PSID trusteeSid;
	EXPLICIT_ACCESS* pEntry;
	PEXPLICIT_ACCESS entryList;
	ULONG entryCount;
	PSECURITY_DESCRIPTOR pSD = NULL;
	PACL ppAcl;
	char namebuf[1024];
	char domainbuf[1024];
	SID_NAME_USE nametype;
	DWORD namelen = sizeof(namebuf);
	DWORD domainlen = sizeof(domainbuf);
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
		return FALSE;
	SetPrivilege(hToken, L"SeSecurityPrivilege", 1);
	if (mode)
		dwReturn = GetNamedSecurityInfo(name, SE_FILE_OBJECT, SACL_SECURITY_INFORMATION, NULL, NULL, NULL, &ppAcl, &pSD);
	else
		dwReturn = GetNamedSecurityInfo(name, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, &ppAcl, NULL, &pSD);
	if (dwReturn != ERROR_SUCCESS || ppAcl == 0)
	{
		jsonFile << "\"DACL entry 0\": " << "\"Undefined\"}";
		return 0;
	}
	err = GetExplicitEntriesFromAcl(ppAcl, &entryCount, &entryList);
	if (ERROR_SUCCESS != err) 
	{
		jsonFile << "\"DACL entry 0\": " << "\"Undefined\"}";
		return 0;
	}
	if (entryCount == 0)
	{
		jsonFile << "\"DACL entry 0" << "\": \"";
		jsonFile << "\"";
	}
	int counter = 0;
	for (int i = 0; i < entryCount; i++)
	{
		pEntry = &(entryList[i]);
		DWORD perms = pEntry->grfAccessPermissions;
		bool good = 0;
		jsonFile << "\"DACL entry " << (unsigned long)counter <<"\": \"";
		jsonFile << "Permission: ";
		PRINT_PERM(DELETE);
		PRINT_PERM(READ_CONTROL);
		PRINT_PERM(WRITE_DAC);
		PRINT_PERM(WRITE_OWNER);
		PRINT_PERM(MAXIMUM_ALLOWED);
		PRINT_PERM(GENERIC_ALL);
		PRINT_PERM(GENERIC_EXECUTE);
		PRINT_PERM(GENERIC_WRITE);
		PRINT_PERM(GENERIC_READ);
		PRINT_PERM(SYNCHRONIZE);
		if (!good)
			jsonFile << "0 ";
		good = 0;
		perms = pEntry->grfInheritance;
		jsonFile << "Inheritance: ";
		PRINT_PERM(CONTAINER_INHERIT_ACE);
		PRINT_PERM(INHERIT_NO_PROPAGATE);
		PRINT_PERM(INHERIT_ONLY);
		PRINT_PERM(INHERIT_ONLY_ACE);
		PRINT_PERM(NO_INHERITANCE);
		PRINT_PERM(NO_PROPAGATE_INHERIT_ACE);
		PRINT_PERM(OBJECT_INHERIT_ACE);
		PRINT_PERM(SUB_CONTAINERS_AND_OBJECTS_INHERIT);
		PRINT_PERM(SUB_CONTAINERS_ONLY_INHERIT);
		PRINT_PERM(SUB_OBJECTS_ONLY_INHERIT);
		if (!good)
			jsonFile << "0 ";
		jsonFile << "Access_mode: ";
		switch (pEntry->grfAccessMode)
		{
		case NOT_USED_ACCESS:
			jsonFile << "NOT_USED_ACCESS ";
			break;
		case GRANT_ACCESS:
			jsonFile << "GRANT_ACCESS ";
			break;
		case DENY_ACCESS:
			jsonFile << "DENY_ACCESS ";
			break;
		case REVOKE_ACCESS:
			jsonFile << "REVOKE_ACCESS ";
			break;
		case SET_AUDIT_SUCCESS:
			jsonFile << "SET_AUDIT_SUCCESS ";
			break;
		case SET_AUDIT_FAILURE:
			jsonFile << "SET_AUDIT_FAILURE ";
			break;
		default:
			jsonFile << "Unknown ";

		}
		jsonFile << "Trustee: ";
		switch (pEntry->Trustee.TrusteeForm)
		{
		case TRUSTEE_IS_SID:
		
			trusteeSid = (PSID)(pEntry->Trustee.ptstrName);
			namelen = sizeof(namebuf);
			domainlen = sizeof(domainbuf);
			(LookupAccountSidA(NULL, trusteeSid, namebuf, &namelen,
				domainbuf, &domainlen, &nametype));
			if (strcmp(namebuf, "Администраторы") == 0 || strcmp(namebuf, "Администратор") == 0)
				jsonFile << "Administrator"<< " ";
			else if (strcmp(namebuf, "Пользователь") == 0 || strcmp(namebuf, "Пользователи") == 0)
				jsonFile << "Users" << " ";
			else if (strcmp(namebuf, "ВСЕ ОГРАНИЧЕННЫЕ ПАКЕТЫ ПРИЛОЖЕНИЙ") == 0)
				jsonFile << "ALL_RESTRICTED_APPLICATION_PACKAGES" << " ";
			else if (strcmp(namebuf, "ВСЕ ПАКЕТЫ ПРИЛОЖЕНИЙ")== 0)
				jsonFile << "ALL_APPLICATION_PACKAGES" << " ";
			else if (strcmp(namebuf, "СИСТЕМА") == 0)
				jsonFile << "System" << " ";
			else if ((unsigned char)namebuf[0] >= 192 && (unsigned char)namebuf[0] <= 255)
			{
				jsonFile << "Untranslatable" << " ";
			}
			else
				jsonFile  << namebuf << " ";
			break;
		case TRUSTEE_IS_NAME:
			jsonFile << "Name ";
			break;
		case TRUSTEE_BAD_FORM:
			jsonFile << "Bad form ";
			break;
		case TRUSTEE_IS_OBJECTS_AND_SID:
			jsonFile << "Objects and SID ";
			break;
		case TRUSTEE_IS_OBJECTS_AND_NAME:
			jsonFile << "Objects and name ";
			break;
		default:
			jsonFile << "Unknown form ";
			break;
		}
		jsonFile << "\"";
		if (i != entryCount - 1)
			jsonFile << ", ";
		counter++;
	}
	jsonFile << "}";
	SetPrivilege(hToken, L"SeSecurityPrivilege", 0);
	return 1;
}
int GetFileIntegrityLevel(LPCWSTR FileName)
{
	DWORD integrityLevel = SECURITY_MANDATORY_MEDIUM_RID;
	PSECURITY_DESCRIPTOR pSD = new SECURITY_DESCRIPTOR;
	PACL acl = new ACL;
	if (ERROR_SUCCESS == GetNamedSecurityInfo(FileName, SE_FILE_OBJECT, LABEL_SECURITY_INFORMATION, 0, 0, 0, &acl, &pSD))
	{
		if (0 != acl && 0 < acl->AceCount)
		{
			SYSTEM_MANDATORY_LABEL_ACE* ace = 0;
			if (GetAce(acl, 0, reinterpret_cast<void**>(&ace)))
			{
				SID* sid = reinterpret_cast<SID*>(&ace->SidStart);
				integrityLevel = sid->SubAuthority[0];
			}
		}
	}
	jsonFile << "{";
	if (integrityLevel == 0x0000)
	{
		jsonFile << "\"Integrity\": " << "\"SECURITY_MANDATORY_UNTRUSTED_RID\"";
		return 0;
	}
	else if (integrityLevel == 0x1000)
	{
		jsonFile <<  "\"Integrity\": " << "\"SECURITY_MANDATORY_LOW_RID\"";
		return 1;
	}
	else if (integrityLevel == 0x2000)
	{
		jsonFile <<  "\"Integrity\": " << "\"SECURITY_MANDATORY_MEDIUM_RID\"";
		return 2;
	}
	else if (integrityLevel == 0x3000)
	{
		jsonFile << "\"Integrity\": " << "\"SECURITY_MANDATORY_HIGH_RID\"";
		return 3;
	}
	else if (integrityLevel == 0x4000)
	{
		jsonFile <<  "\"Integrity\": " << "\"SECURITY_MANDATORY_SYSTEM_RID\"";
		return 4;
	}
	else
	{
		jsonFile << "\"Integrity\": " << "\"Undetected\"";
		return -1;
	}
		
}
bool SetFileIntegrityLevel(int level, LPCWSTR FileName)
{
	LPCWSTR INTEGRITY_SDDL_SACL_W = 0;
	if (level == 0)
		INTEGRITY_SDDL_SACL_W = L"S:(ML;;NR;;;LW)";
	else if (level == 1)
		INTEGRITY_SDDL_SACL_W = L"S:(ML;;NR;;;ME)";
	else if (level == 2)
		INTEGRITY_SDDL_SACL_W = L"S:(ML;;NR;;;HI)";
	DWORD dwErr = ERROR_SUCCESS;
	PSECURITY_DESCRIPTOR pSD = NULL;
	PACL pSacl = NULL;
	BOOL fSaclPresent = FALSE;
	BOOL fSaclDefaulted = FALSE;
	if (ConvertStringSecurityDescriptorToSecurityDescriptor(INTEGRITY_SDDL_SACL_W, SDDL_REVISION_1, &pSD, NULL))
	{
		if (GetSecurityDescriptorSacl(pSD, &fSaclPresent, &pSacl, &fSaclDefaulted))
		{
			dwErr = SetNamedSecurityInfoW((LPWSTR)FileName, SE_FILE_OBJECT, LABEL_SECURITY_INFORMATION, NULL, NULL, NULL, pSacl);
			if (dwErr == ERROR_SUCCESS)
			{
				return true;
			}
		}
		LocalFree(pSD);
		return false;
	}
	return false;
}

int main(int argc, char** argv)
{
	setlocale(LC_ALL, "Russian");
	HANDLE handle1;
	HANDLE hToken;
	if (argc ==1)
	{
		PrintProcessList();
	}
	else
	{
		if (strcmp(argv[1], "procint") == 0)
		{
			int pid = atoi(argv[2]);
			size_t size = strlen(argv[3]) + 1;
			wchar_t* portName = new wchar_t[size];
			size_t outSize;
			mbstowcs_s(&outSize, portName, size, argv[3], size - 1);
			handle1 = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
			change_integrity_level(handle1, portName);
			jsonObj.reset();
			PrintProcessList();
		}
		else if (strcmp(argv[1], "setpriv") == 0)
		{
			int pid = atoi(argv[2]);
			size_t size = strlen(argv[3]) + 1;
			wchar_t* portName = new wchar_t[size];
			size_t outSize;
			mbstowcs_s(&outSize, portName, size, argv[3], size - 1);
			handle1 = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
			if (!OpenProcessToken(handle1, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
				return FALSE;
			SetPrivilege(hToken, portName, 1);
			jsonObj.reset();
			PrintProcessList();
		}
		else if (strcmp(argv[1], "resetpriv") == 0)
		{
			int pid = atoi(argv[2]);
			size_t size = strlen(argv[3]) + 1;
			wchar_t* portName = new wchar_t[size];
			size_t outSize;
			mbstowcs_s(&outSize, portName, size, argv[3], size - 1);
			handle1 = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
			SetPrivilege(handle1, portName, 0);
			jsonObj.reset();
			PrintProcessList();
		}
		else if (strcmp(argv[1], "fileinfo") == 0)
		{
			size_t size = strlen(argv[2]) + 1;
			wchar_t* portName = new wchar_t[size];
			size_t outSize;
			jsonFile.open("file.json");
			mbstowcs_s(&outSize, portName, size, argv[2], size - 1);
			GetFileIntegrityLevel(portName);
			jsonFile << ", ";
			find_file_owner_name(portName);
			read_acl(portName, 0);
			jsonFile.close();
			jsonObj2.reset();
		}
		else if (strcmp(argv[1], "changeint") == 0)
		{
			size_t size = strlen(argv[2]) + 1;
			wchar_t* portName = new wchar_t[size];
			size_t outSize;
			jsonFile.open("file.json");
			mbstowcs_s(&outSize, portName, size, argv[2], size - 1);
			int level = atoi(argv[3]);
			SetFileIntegrityLevel(level, portName);
			GetFileIntegrityLevel(portName);
			jsonFile << ", ";
			find_file_owner_name(portName);
			read_acl(portName, 0);
			jsonFile.close();
			jsonObj2.reset();
		}
		else if (strcmp(argv[1], "changeowner") == 0)
		{
			size_t size = strlen(argv[2]) + 1;
			wchar_t* portName = new wchar_t[size];
			size_t outSize;
			mbstowcs_s(&outSize, portName, size, argv[2], size - 1);
			jsonFile.open("file.json");
			change_owner(argv[2], argv[3]);
			GetFileIntegrityLevel(portName);
			jsonFile << ", ";
			find_file_owner_name(portName);
			read_acl(portName, 0);
			jsonFile.close();
			jsonObj2.reset();
		}
		else if (strcmp(argv[1], "deleteace") == 0)
		{
			size_t size = strlen(argv[2]) + 1;
			wchar_t* portName = new wchar_t[size];
			size_t outSize;
			mbstowcs_s(&outSize, portName, size, argv[2], size - 1);
			size = strlen(argv[3]) + 1;
			wchar_t* name = new wchar_t[size];
			mbstowcs_s(&outSize, name, size, argv[3], size - 1);
			bool mode = atoi(argv[4]);
			deleteace(portName, name, mode);
			deleteace(portName, name, mode);
			jsonFile.open("file.json");
			GetFileIntegrityLevel(portName);
			jsonFile << ", ";
			find_file_owner_name(portName);
			read_acl(portName, 0);
			jsonFile.close();
			jsonObj2.reset();
		}
		else if (strcmp(argv[1], "addace") == 0)
		{
			size_t size = strlen(argv[2]) + 1;
			wchar_t* portName = new wchar_t[size];
			size_t outSize;
			mbstowcs_s(&outSize, portName, size, argv[2], size - 1);
			size = strlen(argv[3]) + 1;
			wchar_t* name = new wchar_t[size];
			mbstowcs_s(&outSize, name, size, argv[3], size - 1);
			int str = strlen(argv[4]);
			char* right = new char[str+1];
			memset(right, 0, str+1);
			DWORD get = 0;
			for (int i = 0, j=0; i < str+1; i++, j++)
			{
				if (i == str || argv[4][i] == ',')
				{
					if (strcmp(right, "GENERIC_READ") == 0)
						get = get | GENERIC_READ;
					else if (strcmp(right, "GENERIC_WRITE") == 0)
						get = get | GENERIC_WRITE;
					else if (strcmp(right, "GENERIC_EXECUTE") == 0)
						get = get | GENERIC_EXECUTE;
					else if (strcmp(right, "GENERIC_ALL") == 0)
						get = get | GENERIC_ALL;
					else if (strcmp(right, "MAXIMUM_ALLOWED") == 0)
						get = get | MAXIMUM_ALLOWED;
					else if (strcmp(right, "DELETE") == 0)
						get = get | DELETE;
					else if (strcmp(right, "READ_CONTROL") == 0)
						get = get | READ_CONTROL;
					else if (strcmp(right, "WRITE_DAC") == 0)
						get = get | WRITE_DAC;
					else if (strcmp(right, "WRITE_OWNER") == 0)
						get = get | WRITE_OWNER;
					else if (strcmp(right, "SYNCHRONIZE") == 0)
						get = get | SYNCHRONIZE;
					else if (strcmp(right, "STANDARD_RIGHTS_REQUIRED") == 0)
						get = get | STANDARD_RIGHTS_REQUIRED;
					else if (strcmp(right, "STANDARD_RIGHTS_ALL") == 0)
						get = get | STANDARD_RIGHTS_ALL;
					memset(right, 0, str);
					j = 0;
					if (i == str)
						break;
					i++;
				}
				right[j] = argv[4][i];
			}
			ACCESS_MODE access = DENY_ACCESS;
			if (strcmp(argv[5], "set") == 0)
			{
				access = SET_ACCESS;
			}
			DWORD inher =0;
			int len = strlen(argv[6]);
			char* inherit = new char[len+1];
			memset(inherit, 0, len+1);
			for (int i = 0, j = 0; i < len+1; i++, j++)
			{
				if (i == len || argv[6][i] == ',')
				{
					if (strcmp(inherit, "NO_INHERITANCE") == 0)
						inher = inher | NO_INHERITANCE;
					else if (strcmp(inherit, "SUB_OBJECTS_ONLY_INHERIT") == 0)
						inher = inher | SUB_OBJECTS_ONLY_INHERIT;
					else if (strcmp(inherit, "SUB_CONTAINERS_ONLY_INHERIT") == 0)
						inher = inher | SUB_CONTAINERS_ONLY_INHERIT;
					else if (strcmp(inherit, "SUB_CONTAINERS_AND_OBJECTS_INHERIT") == 0)
						inher = inher | SUB_CONTAINERS_AND_OBJECTS_INHERIT;
					else if (strcmp(inherit, "INHERIT_NO_PROPAGATE") == 0)
						inher = inher | INHERIT_NO_PROPAGATE;
					else if (strcmp(inherit, "INHERIT_ONLY") == 0)
						inher = inher | INHERIT_ONLY;
					memset(inherit, 0, len);
					j = 0;
					if (i == len)
						break;
					i++;
				}
				inherit[j] = argv[6][i];
			}
			AddAceToObjectsSecurityDescriptor(portName, name, get, access, inher);
			jsonFile.open("file.json");
			GetFileIntegrityLevel(portName);
			jsonFile << ", ";
			find_file_owner_name(portName);
			read_acl(portName, 0);
			jsonFile.close();
			jsonObj2.reset();
		}
	}
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
		return FALSE;
	SetPrivilege(hToken, L"SeDebugPrivilege", 1);
	SetPrivilege(hToken, L"SeSecurityPrivilege", 1);
	SetPrivilege(hToken, L"SeAssignPrimaryTokenPrivilege", 1);
	SetPrivilege(hToken, L"SeTcbPrivilege", 1);
	ExitProcess(0);
}

