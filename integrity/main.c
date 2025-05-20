#include "section_monitor.h"
#include <windows.h>

typedef struct {
    HANDLE hProcess;
    Section* sections;
} MonitorContext;

DWORD WINAPI MonitorThread(LPVOID lpParam) {
    MonitorContext* ctx = (MonitorContext*)lpParam;
    size_t count = get_remote_non_writable_sections(ctx->hProcess, ctx->sections, MAX_SECTIONS);
    if (count == 0) {
        printf("No non-writable sections found in target process.\n");
        OutputDebugStringA("No non-writable sections found in target process.\n");
        return 1;
    }

    printf("Monitoring %zu non-writable sections...\n", count);
    for (size_t i = 0; i < count; i++) {
        printf("Section %zu: %s at %p (size: %zu)\n", 
               i, ctx->sections[i].name, ctx->sections[i].base, ctx->sections[i].size);
    }

    for (size_t i = 0; i < count; i++) {
        ctx->sections[i].crc32 = remote_crc32(ctx->hProcess, ctx->sections[i].base, ctx->sections[i].size);
        printf("Initial CRC for section %s: %08X\n", ctx->sections[i].name, ctx->sections[i].crc32);
    }

    printf("\nMonitoring for modifications...\n");
    while (1) {
        for (size_t i = 0; i < count; i++) {
            uint32_t current_crc = remote_crc32(ctx->hProcess, ctx->sections[i].base, ctx->sections[i].size);
            if (current_crc != ctx->sections[i].crc32) {
                char logMessage[256];
                sprintf(logMessage, "[ALERT] Section %s has been modified!\n"
                                  "        Expected CRC: %08X\n"
                                  "        Current CRC:  %08X\n"
                                  "        Address:      %p\n",
                        ctx->sections[i].name, 
                        ctx->sections[i].crc32,
                        current_crc,
                        ctx->sections[i].base);
                OutputDebugStringA(logMessage);
                printf("\n%s\n", logMessage);
                
                ctx->sections[i].crc32 = current_crc;
            }
        }
        Sleep(100); 
    }

    return 0;
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        printf("Usage: %s <target_process_name>\n", argv[0]);
        return EXIT_FAILURE;
    }

    DWORD pid = get_process_id(argv[1]);
    if (pid == 0) {
        printf("Target process '%s' not found\n", argv[1]);
        return EXIT_FAILURE;
    }

    HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProcess) {
        printf("Failed to open target process (error %lu)\n", GetLastError());
        return EXIT_FAILURE;
    }

    Section* sections = (Section*)malloc(sizeof(Section) * MAX_SECTIONS);
    if (!sections) {
        printf("Failed to allocate memory for sections\n");
        CloseHandle(hProcess);
        return EXIT_FAILURE;
    }

    MonitorContext ctx = {
        .hProcess = hProcess,
        .sections = sections
    };

    HANDLE hThread = CreateThread(NULL, 0, MonitorThread, &ctx, 0, NULL);
    if (!hThread) {
        printf("Failed to create monitoring thread\n");
        free(sections);
        CloseHandle(hProcess);
        return EXIT_FAILURE;
    }

    printf("Monitoring process '%s' (PID: %lu). Press Enter to exit...\n", argv[1], pid);
    getchar();

    TerminateThread(hThread, 0);
    CloseHandle(hThread);
    CloseHandle(hProcess);
    free(sections);

    return EXIT_SUCCESS;
}