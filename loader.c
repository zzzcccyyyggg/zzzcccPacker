#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>
#include <winnt.h>
void* load_PE(char* PE_data);
void fix_iat(char*, IMAGE_NT_HEADERS64*);
void fix_base_reloc(char* p_image_base, IMAGE_NT_HEADERS64* p_NT_headers64);
int mystrcmp(const char* str1, const char* str2);
void mymemcpy(char* dest, const char* src, size_t length);
unsigned int Time1;
unsigned int Time2;
int _start(void) {
    asm volatile (
        "rdtsc\n"
        "movl %%edx, %0\n"
        : "=r" (Time1) // 输出操作数
        : // 输入操作数
        : "%eax", "%ecx", "%edx" // 受影响的寄存器
    );
    char* unpacker_VA = (char*)GetModuleHandleA(NULL);


    IMAGE_DOS_HEADER* p_DOS_header = (IMAGE_DOS_HEADER*)unpacker_VA;


    IMAGE_NT_HEADERS64* p_NT_headers64 = (IMAGE_NT_HEADERS64*)(((char*)unpacker_VA) + p_DOS_header->e_lfanew);


    IMAGE_SECTION_HEADER* sections = (IMAGE_SECTION_HEADER*)(p_NT_headers64 + 1);


    char* packed = NULL;

    // asm(
    //     "call nextds\n"
    //     "nextds:\n"
    //     "movl $continuedaa,(%esp)\n"
    //     "ret\n"
    //     "continuedaa:\n"    
    // );


    char packed_section_name[] = ".ATOM";
    for (int i = 0; i < p_NT_headers64->FileHeader.NumberOfSections; i++) {
   
        if (mystrcmp((const char*)sections[i].Name, packed_section_name) == 0) {

            packed = unpacker_VA + sections[i].VirtualAddress;
            for(int j = 0;j<sections[i].Misc.VirtualSize;j++){
                packed[j] = packed[j]^0x23;
            }
            break;
        }
    }
    	//花指令3
    // LoadLibraryA("not-exists.dll");
    // asm("test %eax,%eax;\njz next555;\n.byte 0xe8;\nnext555:\n");
    MessageBoxA(NULL, "fighting", "Info", MB_ICONINFORMATION);
    if (packed != NULL) {
        

        void (*entrypoint)(void) = (void (*)(void))load_PE(packed);
        asm volatile (
            "rdtsc\n"
            "movl %%edx, %0\n"
            : "=r" (Time2) // 输出操作数
            : // 输入操作数
            : "%eax", "%ecx", "%edx" // 受影响的寄存器
        );
        if (Time2 - Time1>1){
            return 0;
        }
        entrypoint();
    }


    return 0;
}

void* load_PE(char* PE_data) {
    //   ȡDOSͷ
    //printf("HELLO");
    IMAGE_DOS_HEADER* p_DOS_header = (IMAGE_DOS_HEADER*)PE_data;
    //   ȡNTͷ  ע  Ҫ    DOSͷ  ƫ    
    int temp = p_DOS_header->e_lfanew;
    IMAGE_NT_HEADERS64* p_NT_headers64 = (IMAGE_NT_HEADERS64*)(PE_data + temp);

    //   PEͷ  ȡ  Ϣ
    DWORD size_of_image = p_NT_headers64->OptionalHeader.SizeOfImage;          //      С
    DWORD entry_point_RVA = p_NT_headers64->OptionalHeader.AddressOfEntryPoint; //   ڵ  RVA
    DWORD size_of_headers = p_NT_headers64->OptionalHeader.SizeOfHeaders;       // ͷ    С
    //      ڴ 
    char* p_image_base = (char*)GetModuleHandleA(NULL);
    if (p_image_base == NULL) {
        return NULL;
    }
    DWORD old_protect;
    VirtualProtect(p_image_base, p_NT_headers64->OptionalHeader.SizeOfHeaders, PAGE_READWRITE, &old_protect);
    mymemcpy(p_image_base, PE_data, size_of_headers);


    //   ͷ  IMAGE_NT_HEADERS64 ṹ�?  ʼ               ָ      
    IMAGE_SECTION_HEADER* sections = (IMAGE_SECTION_HEADER*)(p_NT_headers64 + 1);

    for (int i = 0; i < p_NT_headers64->FileHeader.NumberOfSections; i++) {

        char* dest = p_image_base + sections[i].VirtualAddress;
        VirtualProtect(dest, sections[i].SizeOfRawData, PAGE_EXECUTE_READWRITE, &old_protect);
        //     Ƿ   ԭʼ    Ҫ    
        if (sections[i].SizeOfRawData > 0) {
            //     SizeOfRawData ֽڵ ԭʼ   ݣ    ļ  е PointerToRawDataƫ ƴ   ʼ
            mymemcpy(dest, PE_data + sections[i].PointerToRawData, sections[i].SizeOfRawData);
        }else {
            //    û  ԭʼ   ݣ   Ŀ         Ϊ �?  СΪMisc.VirtualSize
            for (size_t i = 0; i < sections[i].Misc.VirtualSize; i++) {
                dest[i] = 0;
            }
        }
    }
    fix_iat(p_image_base, p_NT_headers64);
    fix_base_reloc(p_image_base, p_NT_headers64);
    DWORD oldProtect;
    VirtualProtect(p_image_base, p_NT_headers64->OptionalHeader.SizeOfHeaders, PAGE_READONLY, &oldProtect);

    //     PE ļ  ĸ     
    for (int i = 0; i < p_NT_headers64->FileHeader.NumberOfSections; ++i) {
        //    㵱�?     ڴ  е      ַ
        char* dest = p_image_base + sections[i].VirtualAddress;
        //   ȡ  ǰ ڵ    Ա ־
        DWORD s_perm = sections[i].Characteristics;
        //   ʼ       ڴ Ȩ ޱ ־Ϊ0    Ϊ     ڴ ͽ ͷ ı ־    ȫ  ͬ
        DWORD v_perm = 0;

        //   鵱�?   Ƿ   п ִ      
        if (s_perm & IMAGE_SCN_MEM_EXECUTE) {
            //      ִ У   һ      Ƿ  д
            v_perm = (s_perm & IMAGE_SCN_MEM_WRITE) ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;
        }
        else {
            //        ִ У ͬ    һ      Ƿ  д
            v_perm = (s_perm & IMAGE_SCN_MEM_WRITE) ? PAGE_READWRITE : PAGE_READONLY;
        }

        // ʹ  VirtualProtect       õ ǰ     ڴ  е Ȩ  
        VirtualProtect(dest, sections[i].Misc.VirtualSize, v_perm, &oldProtect);
    }
    if (IsDebuggerPresent()) {
        return 0;
    }else {
        return (void*)(p_image_base + entry_point_RVA);
    }
    
}

void fix_iat(char* p_image_base, IMAGE_NT_HEADERS64* p_NT_headers64) {
    //   ȡPEͷ е     Ŀ¼
    IMAGE_DATA_DIRECTORY* data_directory = p_NT_headers64->OptionalHeader.DataDirectory;

    //    ص             ĵ ַ
    IMAGE_IMPORT_DESCRIPTOR* import_descriptors =
        (IMAGE_IMPORT_DESCRIPTOR*)(p_image_base + data_directory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    //                Կ ֵ  ֹ
    for (int i = 0; import_descriptors[i].OriginalFirstThunk != 0; ++i) {
        //   ȡDLL     Ʋ       
        char* module_name = p_image_base + import_descriptors[i].Name;
        HMODULE import_module = LoadLibraryA(module_name);
        if (import_module == NULL) {
            //printf("    ģ  Ϊ  ");
            //abort();
        }

        //    ұ   Lookup Table  ָ       ƻ           IDT  Import Descriptor Table        һƪ      ˵  INT  
        IMAGE_THUNK_DATA* lookup_table = (IMAGE_THUNK_DATA*)(p_image_base + import_descriptors[i].OriginalFirstThunk);

        //   ַ   ǲ  ұ  ĸ          ǽ    صĺ     ַ       У     IAT  Import Address Table  
        IMAGE_THUNK_DATA* address_table = (IMAGE_THUNK_DATA*)(p_image_base + import_descriptors[i].FirstThunk);

        //  Կ ֵ  ֹ     �? ٴ       ֹѭ  
        for (int j = 0; lookup_table[j].u1.AddressOfData != 0; ++j) {
            void* function_handle = NULL;

            //      ұ  Ի ȡҪ    ĺ      Ƶĵ ַ
            ULONGLONG lookup_addr = lookup_table[j].u1.AddressOfData;

            if ((lookup_addr & IMAGE_ORDINAL_FLAG) == 0) { //      һλ    1
                // ͨ     Ƶ  �?  ȡIMAGE_IMPORT_BY_NAME �?
                IMAGE_IMPORT_BY_NAME* image_import = (IMAGE_IMPORT_BY_NAME*)(p_image_base + lookup_addr);
                //  ýṹ�?  ASCII        
                char* funct_name = (char*)&(image_import->Name);
                //   ģ        л ȡ ú    ĵ ַ
                function_handle = (void*)GetProcAddress(import_module, funct_name);
            }
            else {
                // ͨ      ֱ ӵ   
                function_handle = (void*)GetProcAddress(import_module, (LPSTR)lookup_addr);
            }

            if (function_handle == NULL) {
                //  printf("       Ϊ  ");
                    //abort();
            }

            //  ޸ IAT          ַ        
            address_table[j].u1.Function = (ULONGLONG)function_handle;
        }
    }
}

void fix_base_reloc(char* p_image_base, IMAGE_NT_HEADERS64* p_NT_headers64) {
    //   ȡPE ļ       Ŀ¼
    IMAGE_DATA_DIRECTORY* data_directory = p_NT_headers64->OptionalHeader.DataDirectory;

    //     ImageBase  ƫ    
    ULONGLONG delta_VA_reloc = ((ULONGLONG)p_image_base) - p_NT_headers64->OptionalHeader.ImageBase;

    //         ض λ        ȷʵ ƶ   ImageBase
    if (data_directory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress != 0 && delta_VA_reloc != 0) {

        //      ض λ   ĵ ַ
        IMAGE_BASE_RELOCATION* p_reloc =
            (IMAGE_BASE_RELOCATION*)(p_image_base + data_directory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

        //  ض λ    һ    null  β      
        while (p_reloc->VirtualAddress != 0) {

            //  ÿ  е  ض λ         ܴ С  ȥ"ͷ" Ĵ С   ٳ   2    Щ     ֣ ÿ    2   ֽڣ 
            DWORD size = (p_reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2;
            //  ض λ   е һ   ض λԪ أ λ  ͷ֮  ʹ  ָ     �?
            WORD* fixups = (WORD*)(p_reloc + 1);
            for (unsigned int i = 0; i < size; ++i) {
                //        ض λ ֵ ǰ4λ
                int type = fixups[i] >> 12;
                // ƫ     ض λ ֵĺ 12λ
                int offset = fixups[i] & 0x0fff;
                //        ǽ Ҫ   ĵĵ ַ
                ULONGLONG* change_addr = (ULONGLONG*)(p_image_base + p_reloc->VirtualAddress + offset);

                // ֻ  һ        Ҫ        
                switch (type) {
                case IMAGE_REL_BASED_HIGHLOW:
                    *change_addr += delta_VA_reloc;
                    break;
                default:
                    break;
                }
            }
            //  л     һ   ض λ �?   ڴ С
            p_reloc = (IMAGE_BASE_RELOCATION*)(((ULONGLONG)p_reloc) + p_reloc->SizeOfBlock);
        }
    }
}

int mystrcmp(const char* str1, const char* str2) {
    while (*str1 == *str2 && *str1 != 0) {
        str1++;
        str2++;
    }
    if (*str1 == 0 && *str2 == 0) {
        return 0;
    }
    return -1;
}

void mymemcpy(char* dest, const char* src, size_t length) {
    for (size_t i = 0; i < length; i++) {
        dest[i] = src[i];
    }
}


