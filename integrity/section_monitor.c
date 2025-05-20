#include "section_monitor.h"

size_t get_non_writable_sections(Section* sections, size_t max_sections) {
    HMODULE hModule = GetModuleHandle(NULL);
    if (!hModule) return 0;

    BYTE* base = (BYTE*)hModule;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);

    size_t count = 0;
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections && count < max_sections; i++) {
        DWORD characteristics = sec[i].Characteristics;
        if (!(characteristics & IMAGE_SCN_MEM_WRITE)) {
            Section* s = &sections[count++];
            strncpy(s->name, (char*)sec[i].Name, 8);
            s->name[8] = '\0';
            s->base = base + sec[i].VirtualAddress;
            s->size = sec[i].Misc.VirtualSize;
        }
    }
    return count;
}

static uint32_t crc32_table[256];
static CRITICAL_SECTION tableLock;
static int have_table = 0;

uint32_t crc32(const void* data, size_t length) {
    uint32_t crc = 0xFFFFFFFF;
    const uint8_t* p = (const uint8_t*)data;

    if (!have_table) {
        InitializeCriticalSection(&tableLock);
        EnterCriticalSection(&tableLock);
        if (!have_table) {
            for (int i = 0; i < 256; i++) {
                uint32_t rem = i;
                for (int j = 0; j < 8; j++) {
                    if (rem & 1)
                        rem = (rem >> 1) ^ 0xEDB88320;
                    else
                        rem >>= 1;
                }
                crc32_table[i] = rem;
            }
            have_table = 1;
        }
        LeaveCriticalSection(&tableLock);
    }

    for (size_t i = 0; i < length; i++)
        crc = (crc >> 8) ^ crc32_table[(crc ^ p[i]) & 0xFF];

    return ~crc;
}

MerkleNode* build_merkle_tree(HANDLE hProcess, void* data, size_t size, size_t page_size) {
    MerkleNode* node = (MerkleNode*)malloc(sizeof(MerkleNode));
    if (!node) return NULL;
    
    node->left = node->right = NULL;
    node->data_ptr = data;
    node->data_size = size;
    
    if (size <= page_size) {
        BYTE* buffer = (BYTE*)malloc(size);
        if (!buffer) {
            free(node);
            return NULL;
        }
        
        SIZE_T bytes_read;
        if (!ReadProcessMemory(hProcess, data, buffer, size, &bytes_read) || bytes_read != size) {
            free(buffer);
            free(node);
            return NULL;
        }
        
        node->hash = crc32(buffer, size);
        
        node->original_data = buffer;
        return node;
    }
    
    size_t half_size = size / 2;
    node->left = build_merkle_tree(hProcess, data, half_size, page_size);
    node->right = build_merkle_tree(hProcess, (BYTE*)data + half_size, size - half_size, page_size);
    
    uint32_t combined[2] = {node->left->hash, node->right->hash};
    node->hash = crc32(combined, sizeof(combined));
    node->original_data = NULL;  
    
    return node;
}

void update_merkle_path(MerkleNode* node) {
    if (!node || (!node->left && !node->right)) return;
    
    uint32_t combined[2] = {node->left->hash, node->right->hash};
    node->hash = crc32(combined, sizeof(combined));
}

void check_and_heal_section(HANDLE hProcess, Section* section) {
    if (!section->merkle_root) return;
    
    void check_node(MerkleNode* node) {
        if (!node) return;
        
        if (!node->left && !node->right) {  
            BYTE* current = (BYTE*)malloc(node->data_size);
            if (!current) return;
            
            SIZE_T bytes_read;
            if (ReadProcessMemory(hProcess, node->data_ptr, current, node->data_size, &bytes_read) &&
                bytes_read == node->data_size) {
                
                uint32_t current_hash = crc32(current, node->data_size);
                if (current_hash != node->hash) {
                    SIZE_T bytes_written;
                    DWORD old_protect;
                    
                    char logMessage[512];
                    sprintf(logMessage, "[TAMPER-DETECT] Section: %s, Address: %p, Size: %zu, Original Hash: %08X, Current Hash: %08X\n",
                            section->name, node->data_ptr, node->data_size, node->hash, current_hash);
                    OutputDebugStringA(logMessage);
                    printf("%s", logMessage);
                    
                    if (VirtualProtectEx(hProcess, node->data_ptr, node->data_size, 
                                       PAGE_EXECUTE_READWRITE, &old_protect)) {
                        if (WriteProcessMemory(hProcess, node->data_ptr, node->original_data,
                                            node->data_size, &bytes_written) && 
                            bytes_written == node->data_size) {
                            
                            VirtualProtectEx(hProcess, node->data_ptr, node->data_size, 
                                           old_protect, &old_protect);
                            
                            node->hash = current_hash;
                            
                            sprintf(logMessage, "[AUTO-HEAL] Successfully restored original content for section %s at %p\n",
                                    section->name, node->data_ptr);
                            OutputDebugStringA(logMessage);
                            printf("%s", logMessage);
                            
                            Sleep(1000);
                        }
                    } else {
                        sprintf(logMessage, "[ERROR] Failed to heal section %s at %p (Error: %lu)\n",
                                section->name, node->data_ptr, GetLastError());
                        OutputDebugStringA(logMessage);
                        printf("%s", logMessage);
                    }
                }
            }
            free(current);
        } else {
            check_node(node->left);
            check_node(node->right);
            update_merkle_path(node);
        }
    }
    
    check_node(section->merkle_root);
}

void free_merkle_tree(MerkleNode* root) {
    if (!root) return;
    free_merkle_tree(root->left);
    free_merkle_tree(root->right);
    free(root->original_data);
    free(root);
}

void initialize_checksums(Section* sections, size_t count) {
    const size_t PAGE_SIZE = 4096;  
    for (size_t i = 0; i < count; i++) {
        sections[i].page_size = PAGE_SIZE;
        sections[i].merkle_root = build_merkle_tree(GetCurrentProcess(), 
                                                  sections[i].base, 
                                                  sections[i].size, 
                                                  PAGE_SIZE);
        sections[i].crc32 = sections[i].merkle_root ? sections[i].merkle_root->hash : 0;
    }
}

void check_integrity(const Section* sections, size_t count) {
    for (size_t i = 0; i < count; i++) {
        check_and_heal_section(GetCurrentProcess(), (Section*)&sections[i]);
    }
}

DWORD get_process_id(const char* process_name) {
    DWORD pid = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    
    if (Process32First(snapshot, &pe32)) {
        do {
            if (_stricmp(pe32.szExeFile, process_name) == 0) {
                pid = pe32.th32ProcessID;
                break;
            }
        } while (Process32Next(snapshot, &pe32));
    }

    CloseHandle(snapshot);
    return pid;
}

size_t get_remote_non_writable_sections(HANDLE hProcess, Section* sections, size_t max_sections) {
    HMODULE hMod;
    DWORD cbNeeded;
    if (!EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded)) 
        return 0;

    IMAGE_DOS_HEADER dos;
    if (!ReadProcessMemory(hProcess, hMod, &dos, sizeof(dos), NULL))
        return 0;

    IMAGE_NT_HEADERS nt;
    if (!ReadProcessMemory(hProcess, (BYTE*)hMod + dos.e_lfanew, &nt, sizeof(nt), NULL))
        return 0;

    size_t count = 0;
    IMAGE_SECTION_HEADER sec;
    
    for (WORD i = 0; i < nt.FileHeader.NumberOfSections && count < max_sections; i++) {
        if (!ReadProcessMemory(hProcess, 
            (BYTE*)hMod + dos.e_lfanew + sizeof(IMAGE_NT_HEADERS) + (i * sizeof(IMAGE_SECTION_HEADER)),
            &sec, sizeof(sec), NULL))
            continue;

        if (!(sec.Characteristics & IMAGE_SCN_MEM_WRITE)) {
            Section* s = &sections[count++];
            strncpy(s->name, (char*)sec.Name, 8);
            s->name[8] = '\0';
            s->base = (BYTE*)hMod + sec.VirtualAddress;  
            s->size = sec.Misc.VirtualSize;
        }
    }
    return count;
}

uint32_t remote_crc32(HANDLE hProcess, const void* base, size_t length) {
    static uint8_t buffer[BUFFER_SIZE];
    uint32_t crc = 0xFFFFFFFF;
    size_t remaining = length;
    const uint8_t* current = (const uint8_t*)base;

    if (!have_table) {
        crc32(NULL, 0);  
    }

    while (remaining > 0) {
        size_t to_read = (remaining < BUFFER_SIZE) ? remaining : BUFFER_SIZE;
        SIZE_T bytes_read;
        
        if (!ReadProcessMemory(hProcess, current, buffer, to_read, &bytes_read) || bytes_read == 0)
            break;

        for (size_t i = 0; i < bytes_read; i++)
            crc = (crc >> 8) ^ crc32_table[(crc ^ buffer[i]) & 0xFF];

        current += bytes_read;
        remaining -= bytes_read;
    }

    return ~crc;  
}
