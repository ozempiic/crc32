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
        
        ctx->sections[i].page_size = 4096;
        ctx->sections[i].merkle_root = build_merkle_tree(ctx->hProcess, 
                                                       ctx->sections[i].base, 
                                                       ctx->sections[i].size, 
                                                       ctx->sections[i].page_size);
        if (ctx->sections[i].merkle_root) {
            ctx->sections[i].crc32 = ctx->sections[i].merkle_root->hash;
            printf("Built Merkle tree for section %s (root hash: %08X)\n", 
                   ctx->sections[i].name, ctx->sections[i].crc32);
        }
    }

    printf("\nMonitoring for modifications with self-healing enabled...\n");
    while (1) {
        for (size_t i = 0; i < count; i++) {
            check_and_heal_section(ctx->hProcess, &ctx->sections[i]);
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

    HANDLE hProcess = OpenProcess(
        PROCESS_VM_READ | 
        PROCESS_VM_WRITE |
        PROCESS_VM_OPERATION |
        PROCESS_QUERY_INFORMATION, 
        FALSE, pid);
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
