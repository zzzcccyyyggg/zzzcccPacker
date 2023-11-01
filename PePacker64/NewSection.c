#include <windows.h>
#include <stdio.h>

#include "Header.h"

//https://github.com/hMihaiDavid/addscn/blob/master/addscn/addscn.cpp

#define P2ALIGNDOWN(x, align) ((x) & -(align))
#define P2ALIGNUP(x, align) (-(-(x) & -(align)))

#ifdef _WIN64
#define MACHINE IMAGE_FILE_MACHINE_AMD64
#else
#define MACHINE IMAGE_FILE_MACHINE_I386
#endif

typedef struct MyStruct
{
	HANDLE hFile;
	HANDLE hFileMapping;
	PBYTE  pView;
};


struct MyStruct NewSection = { 0 };

void mymemcpy(char* dest, const char* src, size_t length) {
    for (size_t i = 0; i < length; i++) {
        dest[i] = src[i];
    }
}

PBYTE MapFileReadOnly() {
    // 创建文件映射对象，将文件映射到内存，以只读方式访问文件内容

    // 创建文件映射对象
    NewSection.hFileMapping = CreateFileMapping(NewSection.hFile, NULL, PAGE_READONLY, 0, 0, NULL);

    if (NewSection.hFileMapping == INVALID_HANDLE_VALUE) {
        // 处理错误：创建文件映射对象失败
    }

    // 将文件映射到内存
    NewSection.pView = (PBYTE)MapViewOfFile(NewSection.hFileMapping, FILE_MAP_READ, 0, 0, 0);

    if (NewSection.pView == NULL){
        // 处理错误：文件映射到内存失败
    }

    // 检查文件映射对象是否有效
    if (NewSection.hFileMapping == INVALID_HANDLE_VALUE) {
        // 如果出现错误，需要关闭文件句柄
        CloseHandle(NewSection.hFile);
    }

    // 返回文件内容的内存映射视图指针
    return NewSection.pView;
}




PBYTE MapFileRWNewSize(DWORD newSize) {

	NewSection.hFileMapping = CreateFileMapping(NewSection.hFile, NULL, PAGE_READWRITE, 0, newSize, NULL);

	if (NewSection.hFileMapping == INVALID_HANDLE_VALUE) {
		// error
	}

	NewSection.pView = (PBYTE)MapViewOfFile(NewSection.hFileMapping, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0);
	if (NewSection.pView == NULL) {
		// error
	}

	if (NewSection.hFileMapping == INVALID_HANDLE_VALUE) {
		CloseHandle(NewSection.hFile);
	}

	return NewSection.pView;

}

BOOL Unmap() {
	return (UnmapViewOfFile((PVOID)NewSection.pView) && CloseHandle(NewSection.hFileMapping));
}


DWORD VAtoRVA(PIMAGE_SECTION_HEADER sectionHeaders, DWORD numberOfSections, DWORD virtualAddress) {
    // 遍历节头部数组，找到包含虚拟地址的节
    for (DWORD i = 0; i < numberOfSections; i++) {
        DWORD sectionVA = sectionHeaders[i].VirtualAddress;
        DWORD sectionSize = sectionHeaders[i].Misc.VirtualSize;

        if (virtualAddress >= sectionVA && virtualAddress < sectionVA + sectionSize) {
            // 计算RVA = 虚拟地址 - 节的虚拟地址 + 节的PointerToRawData
            return virtualAddress - sectionVA + sectionHeaders[i].PointerToRawData;
        }
    }

    // 如果虚拟地址不在任何节内，返回 0 表示未找到
    return 0;
}



BOOL FixImportTable(PBYTE pSectionData,DWORD offset) {
    // 获取导入表描述符
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(pSectionData + ((PIMAGE_DOS_HEADER)pSectionData)->e_lfanew);
    printf("signature is %x\n", ntHeaders->Signature);
    PIMAGE_DATA_DIRECTORY importDirectory = (PIMAGE_DATA_DIRECTORY)(&ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]);

    //PIMAGE_DATA_DIRECTORY importDirectory = (PIMAGE_DATA_DIRECTORY)(pSectionData + 0x110);
    if (importDirectory->VirtualAddress == 0 || importDirectory->Size == 0) {
        // 没有导入表，无需修复
        printf("no importdirectory");
        return 0;
    }
    // 获取可选头部的大小
    WORD sizeOfOptionalHeader = ntHeaders->FileHeader.SizeOfOptionalHeader;

    // 获取文件头部信息
    PIMAGE_FILE_HEADER fileHeader = &(ntHeaders->FileHeader);

    // 获取第一个节头部
    PIMAGE_SECTION_HEADER firstSectionHeader = (PIMAGE_SECTION_HEADER)(((UINT_PTR)fileHeader) + sizeof(IMAGE_FILE_HEADER) + sizeOfOptionalHeader);

    // 获取已存在的节的数量
    WORD numberOfSections = ntHeaders->FileHeader.NumberOfSections;
    // 计算导入表在文件中的偏移
    DWORD importTableOffset = VAtoRVA(firstSectionHeader, numberOfSections,importDirectory->VirtualAddress);

    // 获取导入表的地址
    PIMAGE_IMPORT_DESCRIPTOR importTable = (PIMAGE_IMPORT_DESCRIPTOR)(pSectionData + importTableOffset);
    printf("%p\n", importTable);
    // 遍历导入表，修复每个DLL的导入项
    for (int i = 0; i < 2;i++ ) {
        printf("fix importTable %d\n", i);
        printf("oringin pname is %x\n", importTable->Name);
        importTable->Name += offset;
        printf("oringin pname is %x\n", importTable->Name);
        // 获取DLL的导入表
        long long int* importNameTable = (long long int*)(pSectionData + VAtoRVA(firstSectionHeader, numberOfSections, importTable->FirstThunk));
        long long int* importAddressTable = (long long int*)(pSectionData + VAtoRVA(firstSectionHeader, numberOfSections, importTable->OriginalFirstThunk));
        printf("%p\n", importAddressTable);
        // 遍历导入表中的每个导入项
        int j = 0;
        while(importAddressTable[j++]) {
            printf("%llx\n", importAddressTable[j-1]);
            importAddressTable[j - 1] += offset;
            importNameTable[j - 1] += offset;
        }
        importTable->FirstThunk += offset;
        importTable->OriginalFirstThunk += offset;
        // 移动到下一个DLL的导入表 
        importTable++;
    }
}

void encrypt(PBYTE pSectionData,DWORD sizeofrawdata) {
    for (int i = 0; i < sizeofrawdata; i++) {
        pSectionData[i] ^= 0x23;
    }
}

char really[3000];
BOOL AppendNewSectionHeader(DWORD dwFileSizeLow, PSTR name, DWORD VirtualSize, DWORD Characteristics, PBYTE pSectionData) {

    PIMAGE_NT_HEADERS myexe_ntHeaders = (PIMAGE_NT_HEADERS)(pSectionData + ((PIMAGE_DOS_HEADER)pSectionData)->e_lfanew);

    // 获取Optional Header
    PIMAGE_OPTIONAL_HEADER myexe_optionalHeader = &myexe_ntHeaders->OptionalHeader;
    // 虚拟地址的最大值通常等于图像基址（ImageBase）加上图像的大小（SizeOfImage）
    int myexe_imageSizeMax = ((myexe_optionalHeader->SizeOfImage));
    int offset = myexe_imageSizeMax;
    printf("myexe_imageSizeMax is: 0x%x\n", myexe_imageSizeMax);
    DWORD bytesWritten;
    char my_name[8] = ".zzzccc";
    FixImportTable((PBYTE)NewSection.pView, myexe_imageSizeMax);
    // 获取可执行文件的 DOS 头部
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)NewSection.pView;
    
    // 获取 NT 头部，NT 头部位于 DOS 头部的 e_lfanew 偏移位置处
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((UINT_PTR)NewSection.pView + dosHeader->e_lfanew);
    
    // 获取可选头部的大小
    WORD sizeOfOptionalHeader = ntHeaders->FileHeader.SizeOfOptionalHeader;
    
    // 获取文件头部信息
    PIMAGE_FILE_HEADER fileHeader = &(ntHeaders->FileHeader);
    
    // 获取第一个节头部
    PIMAGE_SECTION_HEADER firstSectionHeader = (PIMAGE_SECTION_HEADER)(((UINT_PTR)fileHeader) + sizeof(IMAGE_FILE_HEADER) + sizeOfOptionalHeader);
    
    // 获取已存在的节的数量
    WORD numberOfSections = ntHeaders->FileHeader.NumberOfSections;
    
    // 获取节的对齐方式和文件对齐方式
    DWORD sectionAlignment = ntHeaders->OptionalHeader.SectionAlignment;
    DWORD fileAlignment = ntHeaders->OptionalHeader.FileAlignment;
    //在第一个节之前加入一个节
    char temp1[41];
    char temp2[3000];
    mymemcpy(temp1, (char*)firstSectionHeader, 40);
    mymemcpy(temp2, (char*)firstSectionHeader, 40 * numberOfSections);
    mymemcpy((char*)(firstSectionHeader + 1), temp2, numberOfSections * 40);
    mymemcpy((char*)firstSectionHeader, temp1, 40);
    mymemcpy(&firstSectionHeader->Name, my_name, 8);
    ntHeaders->FileHeader.NumberOfSections += 1;
    numberOfSections = ntHeaders->FileHeader.NumberOfSections;
    // 创建新的节头部
    for (int i = 1; i < numberOfSections; i++) {
        firstSectionHeader[i].VirtualAddress += myexe_imageSizeMax;
        firstSectionHeader[i].PointerToRawData += 0x1c00;
    }
    ntHeaders->OptionalHeader.AddressOfEntryPoint += myexe_imageSizeMax;
    for (int i = 0; i < 15; i++) {
        if (ntHeaders->OptionalHeader.DataDirectory[i].VirtualAddress > 0) {
            ntHeaders->OptionalHeader.DataDirectory[i].VirtualAddress += myexe_imageSizeMax;
        }
    }
  
    PIMAGE_SECTION_HEADER newSectionHeader = &firstSectionHeader[numberOfSections];
    PIMAGE_SECTION_HEADER lastSectionHeader = &firstSectionHeader[numberOfSections - 1];
  
    // 清空新节头部的内容
    memset(newSectionHeader, 0, sizeof(IMAGE_SECTION_HEADER));
    // 复制节的名字，但最多只能有8个字符
    mymemcpy(&newSectionHeader->Name, name, min(strlen(name), 8));
    printf("success write");
    // 设置新节的虚拟大小
    firstSectionHeader->Misc.VirtualSize = myexe_imageSizeMax;
    firstSectionHeader->SizeOfRawData = 0x1c00;
    firstSectionHeader->Characteristics |= IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE;
    newSectionHeader->Misc.VirtualSize = VirtualSize;
    
    // 设置新节的虚拟地址
    newSectionHeader->VirtualAddress = P2ALIGNUP(lastSectionHeader->VirtualAddress + lastSectionHeader->Misc.VirtualSize, sectionAlignment);
    printf("\nnew virtualaddress is %ld", newSectionHeader->VirtualAddress);
    // 设置新节的原始数据大小
    newSectionHeader->SizeOfRawData = P2ALIGNUP(VirtualSize, fileAlignment);
    printf("%ld", newSectionHeader->SizeOfRawData);
    // 设置新节的数据在文件中的偏移
    newSectionHeader->PointerToRawData = P2ALIGNUP(lastSectionHeader->SizeOfRawData + lastSectionHeader->PointerToRawData,fileAlignment);
    printf("pointertorawdata is %d",dwFileSizeLow);
    // 设置新节的特性
    newSectionHeader->Characteristics = (Characteristics | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE);
    
    // 增加已存在节的数量
    numberOfSections++;
    ntHeaders->FileHeader.NumberOfSections = numberOfSections;
    
    // 更新可执行文件的大小
    ntHeaders->OptionalHeader.SizeOfImage = P2ALIGNUP(newSectionHeader->VirtualAddress + newSectionHeader->Misc.VirtualSize, sectionAlignment);
    printf(" %ld", ntHeaders->OptionalHeader.SizeOfImage);
    printf("success write");
    // 复制新节的数据到文件中
    
    HANDLE newFile = CreateFileA("test_zzzcccpacked.exe", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (newFile == INVALID_HANDLE_VALUE) {
        perror("Segment file creation error");
        printf("success write");
        return 1;
    }

    WriteFile(newFile, NewSection.pView ,firstSectionHeader->PointerToRawData, &bytesWritten, NULL);
    WriteFile(newFile, really, 0x1c00, &bytesWritten, NULL);
    WriteFile(newFile, (PVOID)((UINT_PTR)NewSection.pView + firstSectionHeader->PointerToRawData), firstSectionHeader[numberOfSections-2].PointerToRawData - firstSectionHeader[1].PointerToRawData + firstSectionHeader[numberOfSections - 2].SizeOfRawData, &bytesWritten, NULL);
    encrypt(pSectionData, newSectionHeader->SizeOfRawData);
    WriteFile(newFile, pSectionData, newSectionHeader->SizeOfRawData, &bytesWritten, NULL);
    WriteFile(newFile, (PVOID)((UINT_PTR)NewSection.pView + firstSectionHeader[numberOfSections - 2].PointerToRawData+firstSectionHeader[numberOfSections-2].SizeOfRawData-0x1c00), 0xf80, &bytesWritten, NULL);

    printf("success write");
    CloseHandle(newFile);
    printf("success write");


}




BOOL CreateNewSection(HANDLE hFile, DWORD dwSectionSize, PBYTE pSectionData) {
    DWORD dwFileSizeLow, dwFileSizeHigh;
	//dwFileSizeLow 中的 dw 是一个常见的缩写，通常代表 "double word"
    PBYTE pView = NULL;
    NewSection.hFile = hFile;

    CHAR str_section_name[9] = ".ATOM";

    if (NewSection.hFile == NULL) {
        return FALSE;
    }

    // 获取已存在文件的大小
    dwFileSizeLow = GetFileSize(hFile, &dwFileSizeHigh);
    //高32位部分和低32位部分

    if (dwFileSizeHigh != NULL){
        // 处理错误：文件大小过大
        CloseHandle(hFile);
        return FALSE;
    }

    // 映射文件到内存，获得文件数据的指针
    if ((pView = MapFileReadOnly()) == NULL) {
        CloseHandle(hFile);
        return FALSE;
    }

    // 检查 DOS 头部和 NT 头部的魔数，确保文件是一个有效的可执行文件
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)pView;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        // 处理错误：无效的 DOS 头部
    }
    
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((UINT_PTR)pView + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE || ntHeaders->FileHeader.Machine != MACHINE) {
        // 处理错误：无效的 NT 头部或不匹配的机器类型
    }

    // 获取已存在的节的数量、节的对齐方式和文件对齐方式
    WORD numberOfSections = ntHeaders->FileHeader.NumberOfSections;
    DWORD sectionAlignment = ntHeaders->OptionalHeader.SectionAlignment;
    DWORD fileAlignment = ntHeaders->OptionalHeader.FileAlignment;

    // 获取文件头部信息
    PIMAGE_FILE_HEADER fileHeader = &(ntHeaders->FileHeader);

    // 获取可选头部的大小
    WORD sizeOfOptionalHeader = ntHeaders->FileHeader.SizeOfOptionalHeader;

    // 获取第一个已存在的节头部
    PIMAGE_SECTION_HEADER firstSectionHeader = (PIMAGE_SECTION_HEADER)(((UINT_PTR)fileHeader) + sizeof(IMAGE_FILE_HEADER) + sizeOfOptionalHeader);

    // 获取新节头部
    PIMAGE_SECTION_HEADER newSectionHeader = &firstSectionHeader[numberOfSections];

    // 获取第一个已存在节的数据
    PBYTE firstByteOfSectionData = (PBYTE)(((DWORD)firstSectionHeader->PointerToRawData) + (UINT_PTR)pView);

    // 计算可用的空间，用于放置新的节头部
    SIZE_T available_space = ((UINT_PTR)firstByteOfSectionData) - ((UINT_PTR)newSectionHeader);
    if (available_space < sizeof(IMAGE_SECTION_HEADER)) {
        // 处理错误：可用空间不足
    }

    // 解除映射已存在的文件
    if (!Unmap()) {
        // 处理错误：解除映射失败
    }

    // 计算新的文件大小，并将文件映射到读写权限并设置新的大小
    DWORD newSize = P2ALIGNUP(dwFileSizeLow + dwSectionSize, fileAlignment);
    if ((pView = MapFileRWNewSize(newSize)) == NULL) {
        CloseHandle(hFile);
        return FALSE;
    }

    // 调用函数 AppendNewSectionHeader 来添加新的节头部信息
    if (!AppendNewSectionHeader(dwFileSizeLow, str_section_name, dwSectionSize, IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ, pSectionData)) {
        // 处理错误：添加节头部失败
    }

    // 解除映射文件
    if (!Unmap()) {
        // 处理错误：解除映射失败
    }

    // 关闭文件句柄
    return CloseHandle(hFile);
}

