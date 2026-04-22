#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>
#include <windows.h>

#pragma comment(lib, "advapi32.lib")

typedef void (WINAPI *GO_PTR)(char*, int);

// --- SAFEMATH & MEMORY HELPERS ---

// Safely adds two size_t values, returning 0 on overflow.
static int safe_add_size_t(size_t a, size_t b, size_t* out) {
    if (SIZE_MAX - a < b) return 0;
    *out = a + b;
    return 1;
}

// Safely multiplies two size_t values, returning 0 on overflow.
static int safe_mul_size_t(size_t a, size_t b, size_t* out) {
    if (a == 0 || b == 0) { *out = 0; return 1; }
    if (SIZE_MAX / a < b) return 0;
    *out = a * b;
    return 1;
}

// Safely aligns a size_t value to the next 4KB page boundary.
static int safe_align_to_page(size_t in, size_t* out) {
    size_t temp;
    if (!safe_add_size_t(in, 0xFFF, &temp)) return 0;
    *out = temp & ~(size_t)0xFFF;
    return 1;
}

// Wrapper around memcpy_s that logs critical memory layout corruption on failure.
static int safe_memcpy(void* dest, size_t dest_sz, const void* src, size_t count) {
    if (memcpy_s(dest, dest_sz, src, count) != 0) {
        printf("    [!] INTERNAL BUG: safe_memcpy failed (Memory layout corruption).\n");
        return 0;
    }
    return 1;
}

// --- BEACON API IMPLEMENTATION ---

// Emulates the BeaconPrintf API for standard output formatting.
static void BeaconPrintf(int type, const char* fmt, ...) {
    (void)type; // Fixes C4100: Variable required by signature but not used
	va_list args;
    va_start(args, fmt);
    printf("[BOF OUTPUT] ");
    vprintf(fmt, args);
    printf("\n");
    va_end(args);
}

// Emulates the BeaconPrintf API specifically for error output formatting.
static void BeaconErrorPrintf(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    printf("[-] BOF Error: ");
    vprintf(fmt, args);
    printf("\n");
    va_end(args);
}

typedef struct {
    char* original;
    char* buffer;
    int   length;
    int   size;
} datap;

// Initializes the data parser structure for reading arguments passed to the BOF.
static void BeaconDataParse(datap* parser, char* buffer, int size) {
    if (!parser) return;
    parser->original = buffer;
    parser->buffer = buffer;
    parser->length = size;
    parser->size = size;
}

// Extracts a 4-byte integer from the parsed argument buffer.
static int BeaconDataInt(datap* parser) {
    if (!parser || !parser->buffer || parser->length < 4) return 0;
    int value = *(int*)parser->buffer;
    parser->buffer += 4;
    parser->length -= 4;
    return value;
}

// Extracts a length-prefixed binary buffer from the parsed argument buffer.
static char* BeaconDataExtract(datap* parser, int* size) {
    if (!parser || !parser->buffer || parser->length < 4) return NULL;
    
    int len = *(int*)parser->buffer;
    parser->buffer += 4;
    parser->length -= 4;

    if (len > parser->length || len < 0) return NULL;

    char* result = parser->buffer;
    if (size) *size = len;

    parser->buffer += len;
    parser->length -= len;

    return result;
}

// Checks if the current process token has local Administrator group membership.
static BOOL BeaconIsAdmin() {
    BOOL isAdmin = FALSE;
    PSID adminGroup = NULL;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;

    if (AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 
                                 0, 0, 0, 0, 0, 0, &adminGroup)) {
        if (!CheckTokenMembership(NULL, adminGroup, &isAdmin)) {
            isAdmin = FALSE;
        }
        FreeSid(adminGroup);
    }
    return isAdmin;
}

// --- UTILITIES ---

// Attempts to enable SeDebugPrivilege on the current process token.
static BOOL EnableDebugPrivilege() {
    HANDLE hToken = NULL;
    LUID luid;
    TOKEN_PRIVILEGES tp;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        printf("    [-] OpenProcessToken error: %lu\n", GetLastError());
        return FALSE;
    }

    if (!LookupPrivilegeValueA(NULL, SE_DEBUG_NAME, &luid)) {
        printf("    [-] LookupPrivilegeValue error: %lu\n", GetLastError());
        CloseHandle(hToken);
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
        printf("    [-] AdjustTokenPrivileges failed: %lu\n", GetLastError());
        CloseHandle(hToken);
        return FALSE;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        printf("    [!] Warning: The token does not have the SeDebugPrivilege.\n");
        printf("    [!] (Did you run the loader as Administrator?)\n");
        CloseHandle(hToken);
        return FALSE;
    }

    CloseHandle(hToken);
    return TRUE; 
}

// --- COFF PARSING CORE ---

typedef struct _COFF_CTX {
    const unsigned char* file;
    size_t file_size;
    const IMAGE_FILE_HEADER* header;
    const IMAGE_SECTION_HEADER* sections;
    const IMAGE_SYMBOL* symbols;
    const char* string_table;
    size_t string_table_size;
} COFF_CTX;

// Converts a COFF machine type identifier into a human-readable string.
static const char* machine_to_string(WORD machine) {
    switch (machine) {
        case IMAGE_FILE_MACHINE_I386:  return "x86";
        case IMAGE_FILE_MACHINE_AMD64: return "x64";
        case IMAGE_FILE_MACHINE_ARM:   return "ARM";
        case IMAGE_FILE_MACHINE_ARM64: return "ARM64";
        default:                       return "Unknown";
    }
}

// Validates that a specified offset and length stay within the bounds of the file size.
static int range_is_valid(size_t file_size, size_t offset, size_t length) {
    if (offset > file_size) return 0;
    if (length > (file_size - offset)) return 0;
    return 1;
}

// --- OPSEC & ROBUSTNESS VALIDATORS ---

// Calculates the logical size of a section, falling back to 4096 if unspecified.
static size_t get_section_logical_size(const IMAGE_SECTION_HEADER* sec) {
    size_t sz = sec->Misc.VirtualSize > 0 ? sec->Misc.VirtualSize : sec->SizeOfRawData;
    return sz == 0 ? 4096 : sz;
}

// Validates that a section's raw data pointer and size reside within the file boundaries.
static int validate_section_raw_range(const COFF_CTX* ctx, const IMAGE_SECTION_HEADER* sec) {
    if (sec->SizeOfRawData == 0) return 1; 
    return range_is_valid(ctx->file_size, sec->PointerToRawData, sec->SizeOfRawData);
}

// Validates that the relocation table for a section resides entirely within the file boundaries.
static int validate_section_reloc_range(const COFF_CTX* ctx, const IMAGE_SECTION_HEADER* sec) {
    if (sec->NumberOfRelocations == 0) return 1;
    size_t reloc_size = 0;
    if (!safe_mul_size_t(sec->NumberOfRelocations, sizeof(IMAGE_RELOCATION), &reloc_size)) return 0;
    return range_is_valid(ctx->file_size, sec->PointerToRelocations, reloc_size);
}

// Ensures a symbol table index is strictly less than the total number of symbols.
static int validate_symbol_index(const COFF_CTX* ctx, DWORD idx) {
    return idx < ctx->header->NumberOfSymbols;
}

// Ensures a section number is greater than zero and within the declared section count.
static int validate_section_number(const COFF_CTX* ctx, SHORT sec_num) {
    return (sec_num > 0 && sec_num <= ctx->header->NumberOfSections);
}

// Confirms that a patch offset and its size fit entirely within the target section's logical size.
static int validate_patch_offset(size_t sec_logical_size, DWORD virtual_address, size_t patch_size) {
    if ((size_t)virtual_address > sec_logical_size) return 0;
    if (patch_size > (sec_logical_size - (size_t)virtual_address)) return 0;
    return 1;
}

// Safely reads the entire contents of a file into a dynamically allocated buffer.
static int read_file_to_buffer(const char* path, unsigned char** out_buf, size_t* out_size) {
    FILE* f = NULL;
    long file_len = 0;
    size_t read_len = 0;
    unsigned char* buf = NULL;

    if (!path || !out_buf || !out_size) return 0;
    *out_buf = NULL;
    *out_size = 0;

    if (fopen_s(&f, path, "rb") != 0 || !f) {
        fprintf(stderr, "[-] ERROR: Failed to open file: %s\n", path);
        return 0;
    }

    if (fseek(f, 0, SEEK_END) != 0) {
        fprintf(stderr, "[-] ERROR: fseek(SEEK_END) failed.\n");
        fclose(f);
        return 0;
    }

    file_len = ftell(f);
    if (file_len <= 0) {
        fprintf(stderr, "[-] ERROR: File is empty or ftell failed (size: %ld).\n", file_len);
        fclose(f);
        return 0;
    }

    if (fseek(f, 0, SEEK_SET) != 0) {
        fprintf(stderr, "[-] ERROR: fseek(SEEK_SET) failed.\n");
        fclose(f);
        return 0;
    }

    buf = (unsigned char*)malloc((size_t)file_len);
    if (!buf) {
        fprintf(stderr, "[-] ERROR: Memory allocation failed for %ld bytes.\n", file_len);
        fclose(f);
        return 0;
    }

    read_len = fread(buf, 1, (size_t)file_len, f);
    fclose(f);

    if (read_len != (size_t)file_len) {
        fprintf(stderr, "[-] ERROR: Incomplete read. Expected %ld bytes, got %zu.\n", file_len, read_len);
        free(buf);
        return 0;
    }

    *out_buf = buf;
    *out_size = (size_t)file_len;
    return 1;
}

// Initializes the COFF context by validating core headers, sections, and symbol tables.
static int coff_init(COFF_CTX* ctx, const unsigned char* file, size_t file_size) {
    if (!ctx || !file) return 0;
    memset(ctx, 0, sizeof(*ctx));
    ctx->file = file;
    ctx->file_size = file_size;

    if (!range_is_valid(file_size, 0, sizeof(IMAGE_FILE_HEADER))) return 0;
    ctx->header = (const IMAGE_FILE_HEADER*)file;

    size_t sections_size = 0;
    if (!safe_mul_size_t(ctx->header->NumberOfSections, sizeof(IMAGE_SECTION_HEADER), &sections_size)) return 0;
    if (!range_is_valid(file_size, sizeof(IMAGE_FILE_HEADER), sections_size)) return 0;
    ctx->sections = (const IMAGE_SECTION_HEADER*)(file + sizeof(IMAGE_FILE_HEADER));

    if (ctx->header->PointerToSymbolTable != 0 && ctx->header->NumberOfSymbols != 0) {
        size_t symbols_offset = (size_t)ctx->header->PointerToSymbolTable;
        size_t symbols_size = 0;
        if (!safe_mul_size_t(ctx->header->NumberOfSymbols, sizeof(IMAGE_SYMBOL), &symbols_size)) return 0;

        if (!range_is_valid(file_size, symbols_offset, symbols_size)) return 0;
        ctx->symbols = (const IMAGE_SYMBOL*)(file + symbols_offset);

        size_t string_offset = 0;
        if (!safe_add_size_t(symbols_offset, symbols_size, &string_offset)) return 0;

        uint32_t string_table_total_size = 0;
        if (range_is_valid(file_size, string_offset, sizeof(uint32_t))) {
            if (safe_memcpy(&string_table_total_size, sizeof(uint32_t), file + string_offset, sizeof(uint32_t))) {
                if (string_table_total_size >= sizeof(uint32_t) && range_is_valid(file_size, string_offset, (size_t)string_table_total_size)) {
                    ctx->string_table = (const char*)(file + string_offset);
                    ctx->string_table_size = (size_t)string_table_total_size;
                }
            }
        }
    }
    return 1;
}

// Resolves a symbol's name, checking the short name array or retrieving it from the string table.
static int get_symbol_name(const COFF_CTX* ctx, const IMAGE_SYMBOL* sym, char* out, size_t out_size) {
    if (!ctx || !sym || !out || out_size == 0) return 0;
    memset(out, 0, out_size);

    if (sym->N.Name.Short != 0) {
        size_t copy_len = (8 >= out_size) ? out_size - 1 : 8;
        if (!safe_memcpy(out, out_size, sym->N.ShortName, copy_len)) return 0;
        out[copy_len] = '\0';
        return 1;
    }

    if (!ctx->string_table || ctx->string_table_size < 4) return 0;
    if ((size_t)sym->N.Name.Long >= ctx->string_table_size) return 0;

    const char* s = ctx->string_table + sym->N.Name.Long;
    size_t max_len = ctx->string_table_size - (size_t)sym->N.Name.Long;
    size_t i = 0;

    while (i + 1 < out_size && i < max_len && s[i] != '\0') {
        out[i] = s[i];
        i++;
    }
    out[i] = '\0';
    return 1;
}

// Fetches a pointer to a specific IMAGE_SYMBOL based on its index.
static const IMAGE_SYMBOL* get_symbol_by_index(const COFF_CTX* ctx, DWORD index) {
    if (!ctx->symbols || index >= ctx->header->NumberOfSymbols) return NULL;
    return &ctx->symbols[index];
}

// Iterates through the symbol table to find the index of a symbol matching the given name.
static int find_symbol(const COFF_CTX* ctx, const char* wanted, DWORD* out_index) {
    if (!ctx || !wanted || !out_index || !ctx->symbols) return 0;
    DWORD i = 0;
    while (i < ctx->header->NumberOfSymbols) {
        char name[256];
        const IMAGE_SYMBOL* sym = &ctx->symbols[i];
        get_symbol_name(ctx, sym, name, sizeof(name));
        if (strcmp(name, wanted) == 0) {
            *out_index = i;
            return 1;
        }
        i += 1u + (DWORD)sym->NumberOfAuxSymbols;
    }
    return 0;
}

// Maps COFF section characteristics to standard Windows VirtualProtect memory protection flags.
static DWORD GetSectionProtection(DWORD characteristics) {
    BOOL r = (characteristics & IMAGE_SCN_MEM_READ) != 0;
    BOOL w = (characteristics & IMAGE_SCN_MEM_WRITE) != 0;
    BOOL x = (characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;

    if (x && r && w) return PAGE_EXECUTE_READWRITE;
    if (x && r)      return PAGE_EXECUTE_READ;
    if (x)           return PAGE_EXECUTE;
    if (r && w)      return PAGE_READWRITE;
    if (r)           return PAGE_READONLY;
    
    return PAGE_NOACCESS;
}

// Converts a Windows memory protection constant into a printable string for logging.
static const char* ProtectionToString(DWORD prot) {
    switch (prot) {
        case PAGE_EXECUTE_READWRITE: return "PAGE_EXECUTE_READWRITE";
        case PAGE_EXECUTE_READ:      return "PAGE_EXECUTE_READ";
        case PAGE_EXECUTE:           return "PAGE_EXECUTE";
        case PAGE_READWRITE:         return "PAGE_READWRITE";
        case PAGE_READONLY:          return "PAGE_READONLY";
        case PAGE_NOACCESS:          return "PAGE_NOACCESS";
        default:                     return "UNKNOWN";
    }
}

// --- RELOCATION STRATEGIES ---

typedef enum {
    RELOC_ERROR = 0,
    RELOC_SUCCESS = 1,
    RELOC_IGNORED = 2
} RELOC_STATUS;

// Handles architecture-specific memory patching for AMD64 (x64) relocations.
static RELOC_STATUS apply_relocation_amd64(uintptr_t patch_addr, void* target_addr, WORD reloc_type) {
    switch (reloc_type) {
        case IMAGE_REL_AMD64_REL32: {
            int32_t rel = (int32_t)((int64_t)target_addr - ((int64_t)patch_addr + 4));
            if (!safe_memcpy((void*)patch_addr, 4, &rel, 4)) return RELOC_ERROR;
            return RELOC_SUCCESS;
        }
        case IMAGE_REL_AMD64_ADDR64: {
            if (!safe_memcpy((void*)patch_addr, 8, &target_addr, 8)) return RELOC_ERROR;
            return RELOC_SUCCESS;
        }
        case IMAGE_REL_AMD64_ADDR32NB: {
            return RELOC_IGNORED; 
        }
        default:
            return RELOC_ERROR;
    }
}

// Handles architecture-specific memory patching for i386 (x86) relocations.
static RELOC_STATUS apply_relocation_i386(uintptr_t patch_addr, void* target_addr, WORD reloc_type) {
    switch (reloc_type) {
        case IMAGE_REL_I386_DIR32: {
            if (!safe_memcpy((void*)patch_addr, 4, &target_addr, 4)) return RELOC_ERROR;
            return RELOC_SUCCESS;
        }
        case IMAGE_REL_I386_REL32: {
            int32_t rel = (int32_t)((int64_t)target_addr - ((int64_t)patch_addr + 4));
            if (!safe_memcpy((void*)patch_addr, 4, &rel, 4)) return RELOC_ERROR;
            return RELOC_SUCCESS;
        }
        default:
            return RELOC_ERROR; 
    }
}

// --- API RESOLVERS ---

typedef struct {
    const char* name;
    void* addr;
} BEACON_API_MAPPING;

static const BEACON_API_MAPPING g_BeaconApiTable[] = {
    {"BeaconPrintf",      (void*)&BeaconPrintf},
    {"BeaconDataParse",   (void*)&BeaconDataParse},
    {"BeaconDataInt",     (void*)&BeaconDataInt},
    {"BeaconDataExtract", (void*)&BeaconDataExtract},
    {"BeaconErrorPrintf", (void*)&BeaconErrorPrintf},
    {"BeaconIsAdmin",     (void*)&BeaconIsAdmin}
};
static const size_t g_BeaconApiCount = sizeof(g_BeaconApiTable) / sizeof(g_BeaconApiTable[0]);

// Looks up internal Beacon APIs mapped within the loader.
static void* ResolveBeaconApi(const char* name) {
    for (size_t i = 0; i < g_BeaconApiCount; i++) {
        if (strcmp(name, g_BeaconApiTable[i].name) == 0) {
            return g_BeaconApiTable[i].addr;
        }
    }
    return NULL; 
}

static const char* const g_SystemApiWhitelist[] = {
    "GetComputerNameA", "GetSystemInfo", "GetVersionExA", "GetTickCount",
    "OpenProcess", "CloseHandle", "CreateFileA", "GetLastError",
    "VirtualAlloc", "VirtualFree", "VirtualProtect"
};
static const size_t g_SystemApiWhitelistCount = sizeof(g_SystemApiWhitelist) / sizeof(g_SystemApiWhitelist[0]);

// Validates if an unqualified symbol name is permitted to be resolved dynamically via kernel32.
static int is_whitelisted_unqualified_symbol(const char* name) {
    for (size_t i = 0; i < g_SystemApiWhitelistCount; i++) {
        if (strcmp(name, g_SystemApiWhitelist[i]) == 0) return 1;
    }
    return 0;
}

// Resolves external system functions using standard GetProcAddress, enforcing DLL$Function format or whitelisting.
static void* ResolveSystemApi(const char* name) {
    char dll_name[MAX_PATH] = "kernel32.dll"; 
    const char* func_name = name;
    const char* dollar = strchr(name, '$');

    if (dollar) {
        size_t len = dollar - name;
        if (len >= MAX_PATH) {
            printf("    [!] ERROR: DLL name too long in symbol '%s'.\n", name);
            return NULL;
        }
        if (!safe_memcpy(dll_name, MAX_PATH, name, len)) return NULL;
        dll_name[len] = '\0';
        strcat_s(dll_name, MAX_PATH, ".dll");
        func_name = dollar + 1;
    } else {
        if (!is_whitelisted_unqualified_symbol(name)) {
            printf("    [!] ERROR: Unqualified external symbol '%s'. Expected format 'DLL$Function'.\n", name);
            return NULL;
        } else {
            printf("    [!] WARNING: Unqualified symbol '%s'. Forcing resolution from kernel32.dll (Whitelist).\n", name);
        }
    }

    HMODULE hMod = GetModuleHandleA(dll_name);
    if (!hMod) hMod = LoadLibraryA(dll_name);
    
    if (!hMod) {
        printf("    [!] ERROR: Could not load required library '%s' for symbol '%s'.\n", dll_name, name);
        return NULL;
    }

    void* target_addr = (void*)GetProcAddress(hMod, func_name);
    if (!target_addr) {
        printf("    [!] ERROR: Could not find function '%s' in '%s'.\n", func_name, dll_name);
    }

    return target_addr;
}

// --- MAIN LOADER LOGIC ---

// Parses arguments, loads the BOF into memory, applies relocations, sets page protections, and executes 'go'.
int main(int argc, char** argv) {
    unsigned char* file_buf = NULL;
    uintptr_t* section_mapping = NULL;
    unsigned char* base_addr = NULL;
    char* final_args = NULL;
    int exit_code = 1; 

    size_t file_size = 0;
    COFF_CTX ctx;
    const char* filename = NULL;
    int target_pid = 0; 
    int explicit_elevation = 0;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <file.obj> [-p PID] [-e]\n", argv[0]);
        fprintf(stderr, "  -p PID : Pass a target PID to the BOF\n");
        fprintf(stderr, "  -e     : Explicitly request SeDebugPrivilege elevation\n");
        goto cleanup;
    }

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            target_pid = atoi(argv[i + 1]);
            explicit_elevation = 1; 
            i++;
        } else if (strcmp(argv[i], "-e") == 0 || strcmp(argv[i], "--elevate") == 0) {
            explicit_elevation = 1; 
        } else if (filename == NULL) {
            filename = argv[i];
        }
    }

    if (!filename) {
        fprintf(stderr, "[-] Error: No BOF file specified.\n");
        goto cleanup;
    }

    if (!read_file_to_buffer(filename, &file_buf, &file_size)) goto cleanup;
    if (!coff_init(&ctx, file_buf, file_size)) goto cleanup;

    printf("[*] Loaded %s | Machine: %s\n", filename, machine_to_string(ctx.header->Machine));

    section_mapping = (uintptr_t*)calloc(ctx.header->NumberOfSections, sizeof(uintptr_t));
    if (!section_mapping) {
        printf("    [!] ERROR: Failed to allocate memory for section mapping.\n");
        goto cleanup;
    }

    // --- PASS 1: Memory size Calculation (Safe Math & Alignment) ---
    size_t current_offset = 0;
    size_t iat_entries_count = 0;

    for (WORD i = 0; i < ctx.header->NumberOfSections; i++) {
        const IMAGE_SECTION_HEADER* sec = &ctx.sections[i];
        
        if (!safe_add_size_t(iat_entries_count, sec->NumberOfRelocations, &iat_entries_count)) {
            printf("    [!] CRITICAL: IAT entries overflow.\n"); goto cleanup;
        }
        
        if (sec->SizeOfRawData == 0 && !(sec->Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA)) continue;

        size_t logical_size = get_section_logical_size(sec);

        if (!safe_align_to_page(current_offset, &current_offset)) goto cleanup;
        if (!safe_add_size_t(current_offset, logical_size, &current_offset)) {
            printf("    [!] CRITICAL: Offset overflow.\n"); goto cleanup;
        }
    }

    if (!safe_align_to_page(current_offset, &current_offset)) goto cleanup;
    size_t iat_offset = current_offset;
    size_t iat_size = 0;
    
    if (!safe_mul_size_t(iat_entries_count, 8, &iat_size)) {
        printf("    [!] CRITICAL: IAT size overflow.\n"); goto cleanup;
    }
    
    size_t aligned_iat_size = 0;
    if (!safe_align_to_page(iat_size, &aligned_iat_size)) goto cleanup;

    if (!safe_add_size_t(current_offset, aligned_iat_size, &current_offset)) {
        printf("    [!] CRITICAL: Total size overflow.\n"); goto cleanup;
    }

    size_t total_size = current_offset;

    base_addr = (unsigned char*)VirtualAlloc(NULL, total_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!base_addr) { 
        printf("    [!] ERROR: VirtualAlloc failed with code %lu\n", GetLastError());
        goto cleanup; 
    }

    // --- PASS 2: Section Mapping ---
    current_offset = 0;
    for (WORD i = 0; i < ctx.header->NumberOfSections; i++) {
        const IMAGE_SECTION_HEADER* sec = &ctx.sections[i];
        if (sec->SizeOfRawData == 0 && !(sec->Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA)) continue;

        if (!validate_section_raw_range(&ctx, sec)) {
            printf("    [!] CRITICAL: Section %d RawData points out of bounds!\n", i);
            goto cleanup;
        }

        if (!safe_align_to_page(current_offset, &current_offset)) goto cleanup;
        section_mapping[i] = (uintptr_t)base_addr + current_offset;

        size_t logical_size = get_section_logical_size(sec);

        if (sec->SizeOfRawData > 0) {
            if (!safe_memcpy((void*)section_mapping[i], logical_size, ctx.file + sec->PointerToRawData, sec->SizeOfRawData)) goto cleanup;
            if (logical_size > sec->SizeOfRawData) {
                memset((void*)(section_mapping[i] + sec->SizeOfRawData), 0, logical_size - sec->SizeOfRawData);
            }
        } else {
            memset((void*)section_mapping[i], 0, logical_size);
        }
        
        if (!safe_add_size_t(current_offset, logical_size, &current_offset)) goto cleanup;
    }

    uintptr_t iat_pool_start = (uintptr_t)base_addr + iat_offset;
    uintptr_t iat_pool_current = iat_pool_start;
    uintptr_t iat_pool_end = iat_pool_start + iat_size;

    // --- PASS 3: Applying Relocations ---
    printf("[*] Applying Relocations...\n");

    for (WORD i = 0; i < ctx.header->NumberOfSections; i++) {
        const IMAGE_SECTION_HEADER* sec = &ctx.sections[i];
        if (sec->NumberOfRelocations == 0) continue;

        if (!validate_section_reloc_range(&ctx, sec)) {
            printf("    [!] CRITICAL: Relocation table for section %d is out of bounds!\n", i);
            goto cleanup;
        }

        const IMAGE_RELOCATION* relocs = (const IMAGE_RELOCATION*)(ctx.file + sec->PointerToRelocations);
        size_t sec_logical_size = get_section_logical_size(sec);
        
        for (WORD j = 0; j < sec->NumberOfRelocations; j++) {
            const IMAGE_RELOCATION* r = &relocs[j];

            if (!validate_symbol_index(&ctx, r->SymbolTableIndex)) {
                printf("    [!] ERROR: Invalid SymbolTableIndex %lu.\n", r->SymbolTableIndex);
                continue;
            }

            const IMAGE_SYMBOL* sym = &ctx.symbols[r->SymbolTableIndex];
            uintptr_t patch_addr = section_mapping[i] + r->VirtualAddress;
            void* target_addr = NULL;

            if (sym->SectionNumber > 0) {
                if (!validate_section_number(&ctx, sym->SectionNumber)) {
                    printf("    [!] ERROR: Invalid SectionNumber %d.\n", sym->SectionNumber);
                    continue;
                }
                
                size_t target_sec_size = get_section_logical_size(&ctx.sections[sym->SectionNumber - 1]);
                if (sym->Value >= target_sec_size) {
                    printf("    [!] ERROR: Symbol value %lu is out of bounds for target section %d.\n", sym->Value, sym->SectionNumber);
                    continue;
                }
                
                target_addr = (void*)(section_mapping[sym->SectionNumber - 1] + sym->Value);
            } 
            else {
                char sym_name[256];
                get_symbol_name(&ctx, sym, sym_name, sizeof(sym_name));
                const char* clean_name = sym_name;
                if (strncmp(sym_name, "__imp_", 6) == 0) clean_name = sym_name + 6;

                if (strncmp(clean_name, "Beacon", 6) == 0) {
                    target_addr = ResolveBeaconApi(clean_name);
                    if (!target_addr) printf("    [!] ERROR: Unsupported Beacon API '%s'\n", clean_name);
                } else {
                    target_addr = ResolveSystemApi(clean_name);
                }

                if (target_addr && ctx.header->Machine == IMAGE_FILE_MACHINE_AMD64 && r->Type == IMAGE_REL_AMD64_REL32) {
                    if (iat_pool_current + 8 > iat_pool_end) {
                        printf("    [!] CRITICAL: IAT pool overflow detected!\n");
                        goto cleanup;
                    }
                    if (!safe_memcpy((void*)iat_pool_current, 8, &target_addr, 8)) goto cleanup;
                    target_addr = (void*)iat_pool_current;
                    iat_pool_current += 8; 
                }
            }

            if (target_addr) {
                size_t expected_patch_size = (r->Type == IMAGE_REL_AMD64_ADDR64) ? 8 : 4; 
                if (!validate_patch_offset(sec_logical_size, r->VirtualAddress, expected_patch_size)) {
                    printf("    [!] ERROR: Patch offset OOB at RVA 0x%08X.\n", r->VirtualAddress);
                    continue;
                }

                RELOC_STATUS status = RELOC_ERROR;
                if (ctx.header->Machine == IMAGE_FILE_MACHINE_AMD64) {
                    status = apply_relocation_amd64(patch_addr, target_addr, r->Type);
                } else if (ctx.header->Machine == IMAGE_FILE_MACHINE_I386) {
                    status = apply_relocation_i386(patch_addr, target_addr, r->Type);
                } else {
                    printf("    [!] ERROR: Unsupported Machine Type.\n");
                    goto cleanup;
                }

                if (status == RELOC_ERROR) {
                    char sym_name[256];
                    get_symbol_name(&ctx, sym, sym_name, sizeof(sym_name));
                    printf("    [!] ERROR: Unsupported relocation type 0x%04X for '%s'\n", r->Type, sym_name);
                } 
            }
        }
    }

    // --- PASS 4: Execution & OPSEC ---
    DWORD go_idx = 0;
    if (find_symbol(&ctx, "go", &go_idx)) {
        const IMAGE_SYMBOL* sym = get_symbol_by_index(&ctx, go_idx);
        
        if (!sym || !validate_section_number(&ctx, sym->SectionNumber) || section_mapping[sym->SectionNumber - 1] == 0) {
            printf("    [!] CRITICAL: Invalid 'go' entrypoint section.\n");
            goto cleanup;
        }

        size_t go_sec_logical_size = get_section_logical_size(&ctx.sections[sym->SectionNumber - 1]);

        if (sym->Value >= go_sec_logical_size) {
            printf("    [!] CRITICAL: 'go' entrypoint offset is out of section bounds.\n");
            goto cleanup;
        }

        GO_PTR pGo = (GO_PTR)(section_mapping[sym->SectionNumber - 1] + sym->Value);
        
        if (explicit_elevation) {
            printf("[*] Elevation requested. Enabling SeDebugPrivilege...\n");
            if (EnableDebugPrivilege()) {
                printf("    [+] Privileges escalated successfully.\n");
            } else {
                printf("    [!] Proceeding without SeDebugPrivilege. Operation may fail.\n");
            }
        }

        int final_len = 0;
        if (target_pid > 0) {
            final_len = 4;
            final_args = (char*)malloc(final_len);
            if (!final_args) {
                printf("    [!] ERROR: Failed to allocate arguments buffer.\n");
                goto cleanup;
            }
            if (!safe_memcpy(final_args, final_len, &target_pid, 4)) goto cleanup;
        }

        printf("[*] Applying granular memory protections...\n");
        DWORD oldProtect;
        current_offset = 0;

        for (WORD i = 0; i < ctx.header->NumberOfSections; i++) {
            const IMAGE_SECTION_HEADER* sec = &ctx.sections[i];
            if (sec->SizeOfRawData == 0 && !(sec->Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA)) continue;

            if (!safe_align_to_page(current_offset, &current_offset)) goto cleanup;
            size_t logical_size = get_section_logical_size(sec);

            size_t protect_size;
            if (!safe_align_to_page(logical_size, &protect_size)) goto cleanup;
            DWORD targetProtection = GetSectionProtection(sec->Characteristics);

            char sec_name[9] = {0};
            if (!safe_memcpy(sec_name, sizeof(sec_name), sec->Name, 8)) goto cleanup;

            if (VirtualProtect((LPVOID)((uintptr_t)base_addr + current_offset), protect_size, targetProtection, &oldProtect)) {
                printf("    [+] Section %-8s : Set to 0x%02X (%s)\n", sec_name, targetProtection, ProtectionToString(targetProtection));
            } else {
                printf("    [!] Failed to protect %-8s. Error: %lu\n", sec_name, GetLastError());
            }
            if (!safe_add_size_t(current_offset, logical_size, &current_offset)) goto cleanup;
        }

        if (iat_size > 0) {
            if (safe_align_to_page(iat_size, &aligned_iat_size)) {
                if (VirtualProtect((LPVOID)(base_addr + iat_offset), aligned_iat_size, PAGE_READONLY, &oldProtect)) {
                    printf("    [+] Section %-8s : Set to 0x%02X (%s)\n", "IAT_POOL", PAGE_READONLY, ProtectionToString(PAGE_READONLY));
                } else {
                    printf("    [!] Failed to protect IAT_POOL. Error: %lu\n", GetLastError());
                }
            }
        }

        printf("\n[*] Jumping to go()...\n");
        printf("--------------------------------------------\n");

        __try {
            pGo(final_args, final_len); 
            printf("--------------------------------------------\n");
            printf("[+] BOF Finished successfully.\n");
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            printf("\n[!] CRITICAL: BOF Exception 0x%08X\n", GetExceptionCode());
        }
        
        exit_code = 0; 

    } else {
        printf("[-] Entrypoint 'go' not found.\n");
    }

cleanup:
    if (final_args)      free(final_args);
    if (section_mapping) free(section_mapping);
    if (base_addr)       VirtualFree(base_addr, 0, MEM_RELEASE);
    if (file_buf)        free(file_buf);
    
    return exit_code;
}