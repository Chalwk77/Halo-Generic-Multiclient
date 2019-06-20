#include <windows.h>
#include <string>
#include <vector>

std::string GetWorkingDirectory();
BOOL WriteBytes(HANDLE hProcess, DWORD destAddress, LPVOID patch, DWORD numBytes);
BOOL ReadBytes(HANDLE hProcess, DWORD sourceAddress, LPVOID buffer, DWORD numBytes);
std::vector<DWORD> FindSignature(LPBYTE sigBuffer, LPBYTE sigWildCard, DWORD sigSize, LPBYTE pBuffer, DWORD size);