#define WINDOWS_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <stdio.h>

struct ProcessEnvironmentBlock
{
	BYTE Reserved1[2];
	BYTE BeingDebugged;
};

typedef NTSTATUS(__stdcall* tNtQueryInformationProcess)(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);

uintptr_t getPEBAddress(HANDLE procHandle)
{
	HMODULE ntdllModHandle = GetModuleHandleW(L"ntdll.dll");
	if (!ntdllModHandle) 
	{
		return 0;
	}
	
	tNtQueryInformationProcess NtQueryInfoProc = (tNtQueryInformationProcess)GetProcAddress(ntdllModHandle, "NtQueryInformationProcess");
	if (!NtQueryInfoProc)
	{
		return 0;
	}

	PROCESS_BASIC_INFORMATION pbi;
	NTSTATUS status = NtQueryInfoProc(procHandle, ProcessBasicInformation, &pbi, sizeof(pbi), 0);
	if (NT_SUCCESS(status))
	{
		return (uintptr_t)pbi.PebBaseAddress;
	}

	return 0;
}

int main()
{
	DWORD procId = 0;
	printf("Enter process id: ");
	if (scanf("%d", &procId) < 1) 
	{
		printf("Error getting proc id from user");
		return 0;
	}

	HANDLE procHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, procId);

	if (procHandle == INVALID_HANDLE_VALUE) 
	{
		printf("Failed to open process");
		return 0;
	}

	BOOL isProcWow64;
	if (!IsWow64Process(procHandle, &isProcWow64))
	{
		printf("Failed to determine if process is WOW64");
		return 0;
	}

#if _WIN64
	if (isProcWow64)
	{
		printf("Run the 32-bit version of this program to attach to a 32-bit process");
		return 0;
	}
#else
	if (!isProcWow64)
	{
		printf("Run the 64-bit version of this program to attach to a 64-bit process");
		return 0;
	}
#endif

	int userInput = 0;
	while (1)
	{
		printf("1 - patch IsDebuggerPresent to return 0\n2 - patch CheckRemoteDebuggerPresent to retunr 0\n3 - set BeingDebugged to 0 in the PEB\n4 - quit\n");
		printf("Input: ");
		if (scanf("%d", &userInput) < 1) 
		{
			printf("Error getting user input");
			break;
		}

		if (userInput == 4) 
		{
			break;
		}

		DWORD oldProtect;
		uintptr_t pebBaseAddress;
		struct ProcessEnvironmentBlock peb;
		switch (userInput)
		{
		case 1:
			VirtualProtectEx(procHandle, IsDebuggerPresent, 6, PAGE_EXECUTE_READWRITE, &oldProtect);
			WriteProcessMemory(procHandle, IsDebuggerPresent, (BYTE*)"\xB8\x0\x0\x0\x0\xC3", 6, 0); // mov eax, 0 and ret
			VirtualProtectEx(procHandle, IsDebuggerPresent, 6, oldProtect, &oldProtect);
			printf("patched IsDebuggerPresent\n");
			break;
		case 2:
			VirtualProtectEx(procHandle, CheckRemoteDebuggerPresent, 6, PAGE_EXECUTE_READWRITE, &oldProtect);
			WriteProcessMemory(procHandle, CheckRemoteDebuggerPresent, (BYTE*)"\xB8\x0\x0\x0\x0\xC3", 6, 0); // mov eax, 0 and ret
			VirtualProtectEx(procHandle, CheckRemoteDebuggerPresent, 6, oldProtect, &oldProtect);
			printf("Patched CheckRemoteDebuggerPresent\n");
			break;
		case 3:
			printf("Setting BeingDebugged in the PEB to 0 every 100 miliseconds\n");

			pebBaseAddress = getPEBAddress(procHandle);
			if (pebBaseAddress == 0) { break; }
			printf("PEB address: %llX\n", pebBaseAddress);

			while (1)
			{
				ReadProcessMemory(procHandle, (void*)pebBaseAddress, &peb, sizeof(peb), 0);
				peb.BeingDebugged = 0;
				WriteProcessMemory(procHandle, (void*)pebBaseAddress, &peb, sizeof(peb), 0);

				Sleep(100);
			}
		default:
			printf("Invalid input\n");
			break;
		}
	}

	return 0;
}