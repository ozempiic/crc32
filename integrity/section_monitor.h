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

// Forward declare MerkleNode for use in Section struct
struct MerkleNode;

typedef struct {
    char name[9];      
    void* base;        
    size_t size;       
    uint32_t crc32;    
    struct MerkleNode* merkle_root;  // Root of the Merkle tree for this section
    size_t page_size;         // Size of each page (typically 4KB)
    BYTE* shadow_copy;        // Shadow copy for self-healing
} Section;

typedef struct MerkleNode {
    uint32_t hash;
    struct MerkleNode* left;
    struct MerkleNode* right;
    void* data_ptr;        // Points to the actual page data
    size_t data_size;      // Size of the data this node represents
    BYTE* original_data;   // For self-healing: stores original content
} MerkleNode;

// Function declarations
MerkleNode* build_merkle_tree(HANDLE hProcess, void* data, size_t size, size_t page_size);
void update_merkle_path(MerkleNode* node);
void check_and_heal_section(HANDLE hProcess, Section* section);
void free_merkle_tree(MerkleNode* root);

size_t get_non_writable_sections(Section* sections, size_t max_sections);
uint32_t crc32(const void* data, size_t length);
void initialize_checksums(Section* sections, size_t count);
void check_integrity(const Section* sections, size_t count);
DWORD get_process_id(const char* process_name);
size_t get_remote_non_writable_sections(HANDLE hProcess, Section* sections, size_t max_sections);
uint32_t remote_crc32(HANDLE hProcess, const void* base, size_t length);

#endif
