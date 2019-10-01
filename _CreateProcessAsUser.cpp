#include <Windows.h>
#include <tchar.h>
#include <WtsApi32.h>
#include <Userenv.h>

#pragma comment(lib, "WtsApi32.lib")
#pragma comment(lib, "Userenv.lib")

/**
* _CreateProcessAsUser func
* @param path - path to exe
* @param lpCommandLine - command line params to start exe
* @return pid created process
*/
extern "C" int _CreateProcessAsUser(LPWSTR path, LPWSTR lpCommandLine)
{
	DWORD pId = 0;// result

	LUID luid; // local uniq id for process

	HANDLE TokenHandle = NULL;

	TOKEN_PRIVILEGES NewState = { 0 };
	TOKEN_PRIVILEGES PreviousState = { 0 };

	HANDLE phToken = NULL;
	HANDLE phNewToken = NULL;

	STARTUPINFO si = { 0 };
	si.cb = sizeof(STARTUPINFO);
    si.lpDesktop = _T("WinSta0\\Default");// current user desktop

	LPVOID lpEnvironment = NULL;
	PROCESS_INFORMATION pi = { 0 };

	DWORD ReturnLength;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &TokenHandle))// read current process token
	{
		 return -1;
    }

    if (!LookupPrivilegeValue(NULL, _T("SeTcbPrivilege"), &luid)) 
	{
		return -1;
    }

    NewState.PrivilegeCount = 1;
    NewState.Privileges[0].Luid = luid;
    NewState.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if (!AdjustTokenPrivileges(TokenHandle, FALSE, &NewState, sizeof(TOKEN_PRIVILEGES), &PreviousState, &ReturnLength))// change proc privileges to user
	{
		return -1;
    }

    DWORD sessionId = WTSGetActiveConsoleSessionId();

    if (sessionId == 0xFFFFFFFF) 
	{
		return -1;
    }

    if (!WTSQueryUserToken(sessionId, &phToken))
	{
		return -1;
    }

    if (!DuplicateTokenEx(phToken, MAXIMUM_ALLOWED, NULL, SecurityIdentification, TokenPrimary, &phNewToken)) 
	{
		return -1;
    }

    if (!CreateEnvironmentBlock(&lpEnvironment, phNewToken, TRUE)) 
	{
		return -1;
    }

    if (!CreateProcessAsUser(phNewToken, path, lpCommandLine, NULL, NULL, FALSE, CREATE_NO_WINDOW, lpEnvironment, NULL, &si, &pi))// for hollowing CREATE_SUSPENDED | CREATE_NO_WINDOW 
	{
		return -1;
    }

	pId = pi.dwProcessId;

	AdjustTokenPrivileges(TokenHandle, FALSE, &PreviousState, sizeof(TOKEN_PRIVILEGES), NULL, NULL);// return proc privileges to system
	DestroyEnvironmentBlock(lpEnvironment);

	// clear memory
	CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
	CloseHandle(phToken);
	CloseHandle(phNewToken);
	CloseHandle(TokenHandle);

	return pId;
}