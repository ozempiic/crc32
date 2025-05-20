#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <tlhelp32.h>   
#include <psapi.h>       

int main(int argc, char* argv[]) {
    if (argc != 2) {
        printf("Usage: %s <process_name>\n", argv[0]);
        printf("Example: %s section_monitor.exe\n", argv[0]);
        return 1;
    }

    DWORD pid = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        printf("Failed to create process snapshot\n");
        return 1;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    
    if (!Process32First(snapshot, &pe32)) {
        CloseHandle(snapshot);
        printf("Failed to get first process\n");
        return 1;
    }

    do {
        if (_stricmp(pe32.szExeFile, argv[1]) == 0) {
            pid = pe32.th32ProcessID;
            break;
        }
    } while (Process32Next(snapshot, &pe32));

    CloseHandle(snapshot);

    if (pid == 0) {
        printf("Process %s not found\n", argv[1]);
        return 1;
    }

    HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, pid);
    if (!hProcess) {
        printf("Failed to open process\n");
        return 1;
    }

    HMODULE hMod;
    DWORD cbNeeded;
    if (!EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded)) {
        printf("Failed to get module handle\n");
        CloseHandle(hProcess);
        return 1;
    }

    MODULEINFO modInfo;
    if (!GetModuleInformation(hProcess, hMod, &modInfo, sizeof(modInfo))) {
        printf("Failed to get module information\n");
        CloseHandle(hProcess);
        return 1;
    }

    BYTE* targetAddr = (BYTE*)modInfo.lpBaseOfDll + 0x1000;  
    BYTE newByte = 0x90; 
    SIZE_T bytesWritten;
    DWORD oldProtect;

    if (VirtualProtectEx(hProcess, targetAddr, 1, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        if (WriteProcessMemory(hProcess, targetAddr, &newByte, 1, &bytesWritten)) {
            printf("Successfully modified read-only section at %p\n", targetAddr);
            printf("The section monitor should detect this modification!\n");
        }
        
        VirtualProtectEx(hProcess, targetAddr, 1, oldProtect, &oldProtect);
    }

    CloseHandle(hProcess);
    return 0;
}