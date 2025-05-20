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

void initialize_checksums(Section* sections, size_t count) {
    for (size_t i = 0; i < count; i++) {
        sections[i].crc32 = crc32(sections[i].base, sections[i].size);
    }
}

void check_integrity(const Section* sections, size_t count) {
    for (size_t i = 0; i < count; i++) {
        uint32_t current_crc = crc32(sections[i].base, sections[i].size);
        if (current_crc != sections[i].crc32) {
            char logMessage[256];
            sprintf(logMessage, "[ALERT] Section %s has been modified! Expected CRC: %08X, Current CRC: %08X\n",
                    sections[i].name, sections[i].crc32, current_crc);
            OutputDebugStringA(logMessage);
        }
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