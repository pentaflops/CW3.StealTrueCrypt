#pragma once

#ifdef _M_IX86
#define _M_IX86_X64
#elif defined _M_X64
#define _M_IX86_X64
#endif

BOOL Mhook_SetHook(PVOID *ppSystemFunction, PVOID pHookFunction);
BOOL Mhook_Unhook(PVOID *ppHookedFunction);
