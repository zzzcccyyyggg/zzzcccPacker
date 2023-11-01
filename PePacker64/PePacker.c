#include <Windows.h>
#include <stdio.h>

#include "Header.h"

#define _64PE	0x064
#define _32PE	0x032
#define DllPE	0xD11
#define NotPE	0x000



BOOL ReportError(const char* ApiName) {
	printf("[!] \"%s\" [ FAILED ] \t%d \n", ApiName, GetLastError());
	return FALSE;
}


BOOL ReadPayloadFile(const char* FileInput, PDWORD sPayloadSize, unsigned char** pPayloadAddress) {

	HANDLE hFile = INVALID_HANDLE_VALUE;
	DWORD FileSize = NULL;
	DWORD lpNumberOfBytesRead = NULL;

	hFile = CreateFileA(FileInput, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_READONLY, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		return ReportError("CreateFileA");
	}

	FileSize = GetFileSize(hFile, NULL);

	unsigned char* Payload = (unsigned char*)malloc(FileSize);

	ZeroMemory(Payload, FileSize);

	if (!ReadFile(hFile, Payload, FileSize, &lpNumberOfBytesRead, NULL)) {
		return ReportError("ReadFile");
	}

	*pPayloadAddress = Payload;
	*sPayloadSize = lpNumberOfBytesRead;

	CloseHandle(hFile);

	if (*pPayloadAddress != NULL && *sPayloadSize != NULL)
		return TRUE;

	return FALSE;
}
void program_start() {
	printf("**************************************************\n\n"
		"* ======    ======= ======= ** ====== zzzzzz cccccc *\n"
		"*     /          /       /  ** ||     c      z      *\n"
		"*    =         =       ||   ** ||     c      z      *\n"
		"*  /         /        /     ** ||     c      z      *\n"
		"* |=====*  z|=====*||=====c ** ====== zzzzzz ccccc  *\n\n"
		"*****************************************************\n\n");
}
INT main(INT argc, CHAR* argv[]) {
	program_start();
	BOOL IsDll = FALSE, IsExe = TRUE;
	BOOL NoConsole = FALSE;
	unsigned char* PeFile;
	DWORD			dwSize;
	char			LoaderStub[MAX_PATH] = "loader.exe";

	printf("[i] Reading \" %s \" ... \n", argv[1]);

	if (!ReadPayloadFile(argv[1], &dwSize, &PeFile)) {
		return -1;
	}

	printf("[i] Reading The Loader \"%s\" ...", LoaderStub);
	HANDLE hFile = CreateFileA(LoaderStub, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		//error
		return -1;
	}
	printf(" [ DONE ] \n");

	// compression:
	printf("[i] Packing ... ");

	if (!CreateNewSection(hFile, dwSize, PeFile)) {
		printf("[!] Failed To Create A New Section \n");
		return -1;
	}

	printf("[+] Section .ATOM is Created Containing The Input Packed Pe \n");


	return 0;
}
