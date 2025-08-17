#include <windows.h>
#include <tchar.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char* argv[])
{
    DWORD bytesRead;
    const char* filePath;
    BOOL fileReadSuccess, filePermChangeSuccess, processCreateSuccess;
    if(argc < 2)
    {
        printf("Shellcode file name is required. Usage: loader.exe <shellcode_file>\n");
        return 0;
    }
    filePath = argv[1];

    printf("Loader started!\n");

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