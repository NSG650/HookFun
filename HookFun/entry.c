#include <Windows.h>
#include <Psapi.h>
#include <stdio.h>
#include <winternl.h>
#include "log.h"

typedef NTSTATUS(WINAPI *NT_CREATE_FILE)(
	PHANDLE FileHandle, ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock,
	PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess,
	ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer,
	ULONG EaLength);

NT_CREATE_FILE OrignalNtCreateFile;
NT_CREATE_FILE NtCreateFileAddress;
BYTE OrignalNtCreateFileBytes[23];

NTSTATUS NtCreateFileHook(PHANDLE FileHandle, ACCESS_MASK DesiredAccess,
						  POBJECT_ATTRIBUTES ObjectAttributes,
						  PIO_STATUS_BLOCK IoStatusBlock,
						  PLARGE_INTEGER AllocationSize, ULONG FileAttributes,
						  ULONG ShareAccess, ULONG CreateDisposition,
						  ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength) {
	Logf(2, "Object name: %S", ObjectAttributes->ObjectName->Buffer);
	return OrignalNtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock,
				 AllocationSize, FileAttributes, ShareAccess, CreateDisposition,
				 CreateOptions, EaBuffer, EaLength);
}

VOID DllEntry(VOID) {
	if (AllocConsole()) {
		FILE *fp;
		freopen_s(&fp, "CONOUT$", "w", stdout);
	}

	BYTE Patch[] = {
		0x49, 0xba, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, // mov r10, address
		0x41, 0xff, 0xe2									// jmp r10
	};

	NtCreateFileAddress = (NT_CREATE_FILE)GetProcAddress(
		GetModuleHandle(L"ntdll"), "NtCreateFile");

	if (NtCreateFileAddress) {
		Logf(2, "NtCreateFile located at 0x%p", NtCreateFileAddress);
	}

	ULONG_PTR NtCreateFileHookAddress = (ULONG_PTR)NtCreateFileHook;
	BYTE *NtCreateFileHookBytes = (BYTE *)&NtCreateFileHookAddress;

	RtlCopyMemory(&Patch[2], NtCreateFileHookBytes, sizeof(ULONG_PTR));

	if (ReadProcessMemory(GetCurrentProcess(), NtCreateFileAddress,
						  OrignalNtCreateFileBytes, 23, NULL)) {
		Logf(0, "Sucessfully copied NtCreateFile's orignal bytes");
	} else {
		Logf(1, "Failed to copy");
	}

	OrignalNtCreateFile = (NT_CREATE_FILE)VirtualAlloc(NULL, 23, MEM_COMMIT,
												PAGE_EXECUTE_READWRITE);

	RtlCopyMemory(OrignalNtCreateFile, &OrignalNtCreateFileBytes, 23);

	Logf(2, "Trampoline NtCreateFile located at 0x%p", OrignalNtCreateFile);

	if (WriteProcessMemory(GetCurrentProcess(), (LPVOID)NtCreateFileAddress,
						   Patch, sizeof(Patch), NULL)) {
		Logf(0, "Sucessfully overwrote NtCreateFile");
	} else {
		Logf(1, "Failed to overwrite");
	}

}

BOOL __stdcall DllMain(HINSTANCE hInstance, DWORD dwReason, LPVOID lpReserved) {
    switch (dwReason) {
        case DLL_PROCESS_ATTACH:
			DllEntry();
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
        case DLL_PROCESS_DETACH:
            break;
    }
    return TRUE;
}