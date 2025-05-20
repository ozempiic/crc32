#ifndef SECTION_MONITOR_H
#define SECTION_MONITOR_H

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <tlhelp32.h>   
#include <psapi.h>      

#define MAX_SECTIONS 64
#define BUFFER_SIZE 4096 

typedef struct {
    char name[9];      
    void* base;        
    size_t size;       
    uint32_t crc32;   
} Section;

size_t get_non_writable_sections(Section* sections, size_t max_sections);
uint32_t crc32(const void* data, size_t length);
void initialize_checksums(Section* sections, size_t count);
void check_integrity(const Section* sections, size_t count);
DWORD get_process_id(const char* process_name);
size_t get_remote_non_writable_sections(HANDLE hProcess, Section* sections, size_t max_sections);
uint32_t remote_crc32(HANDLE hProcess, const void* base, size_t length);

#endif 