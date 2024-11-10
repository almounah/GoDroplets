#include <windows.h>

extern void OnProcessAttach(HINSTANCE, DWORD, LPVOID);

typedef struct {
    HINSTANCE hinstDLL;  // handle to DLL module
    DWORD fdwReason;     // reason for calling function // reserved
    LPVOID lpReserved;   // reserved
} MyThreadParams;

DWORD WINAPI MyThreadFunction(LPVOID lpParam) {
    MyThreadParams params = *((MyThreadParams*)lpParam);
    OnProcessAttach(params.hinstDLL, params.fdwReason, params.lpReserved);
    free(lpParam);
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved )
{
    switch (fdwReason) {
    case DLL_PROCESS_ATTACH:
		    // Initialize once for each new process.
        // Return FALSE to fail DLL load.
        {
            MyThreadParams* lpThrdParam = (MyThreadParams*)malloc(sizeof(MyThreadParams));
            lpThrdParam->hinstDLL = hinstDLL;
            lpThrdParam->fdwReason = fdwReason;
            lpThrdParam->lpReserved = lpvReserved;
            HANDLE hThread = CreateThread(NULL, 0, MyThreadFunction, lpThrdParam, 0, NULL);
            // CreateThread() because otherwise DllMain() is highly likely to deadlock.
        }
        break;
    case DLL_PROCESS_DETACH:
        // Perform any necessary cleanup.
        break;
    case DLL_THREAD_DETACH:
        // Do thread-specific cleanup.
        break;
    case DLL_THREAD_ATTACH:
		// Do thread-specific initialization.
        break;
    }
    return TRUE; // Successful.
}

