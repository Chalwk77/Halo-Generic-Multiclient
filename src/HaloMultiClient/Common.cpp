#include "Common.h"

// Gets the directory of the process
std::string GetWorkingDirectory()
{
	char szOutput[1024] = {0};
	std::string path = "";

	// Get the plugins directory (GetCurrentDirectory() won't always give what we want)
	GetModuleFileName(GetModuleHandle(0), szOutput, sizeof(szOutput)-1);

	char* szExeDelim = strrchr(szOutput, '\\');

	if (szExeDelim)
	{
		szExeDelim[0] = '\0';
		path = szOutput;
	}

	return path;
}

BOOL WriteBytes(HANDLE hProcess, DWORD destAddress, LPVOID patch, DWORD numBytes)
{
	DWORD oldProtect = 0, dwWritten = 0;
	LPVOID srcAddress = (LPVOID)PtrToUlong(destAddress);
	BOOL result = TRUE;

	result = result && VirtualProtectEx(hProcess, srcAddress, numBytes, PAGE_EXECUTE_READWRITE, &oldProtect);
	result = result && WriteProcessMemory(hProcess, srcAddress, patch, numBytes,  &dwWritten);
	result = result && numBytes == dwWritten;
	result = result && VirtualProtectEx(hProcess, srcAddress, numBytes, oldProtect, &oldProtect);
	result = result && FlushInstructionCache(hProcess, srcAddress, numBytes); 

	return result;
}

// Reads bytes in the current process (Made by Drew_Benton).
BOOL ReadBytes(HANDLE hProcess, DWORD sourceAddress, LPVOID buffer, DWORD numBytes)
{
	DWORD oldProtect = 0, dwRead = 0;
	LPVOID srcAddress = (LPVOID)PtrToUlong(sourceAddress);
	BOOL result = TRUE;

	result = result && VirtualProtectEx(hProcess, srcAddress, numBytes, PAGE_EXECUTE_READWRITE, &oldProtect);
	result = result && ReadProcessMemory(hProcess, srcAddress, buffer, numBytes,  &dwRead);
	result = result && numBytes == dwRead;
	result = result && VirtualProtectEx(hProcess, srcAddress, numBytes, oldProtect, &oldProtect);
	result = result && FlushInstructionCache(hProcess, srcAddress, numBytes); 

	return result;
}

std::vector<DWORD> FindSignature(LPBYTE sigBuffer, LPBYTE sigWildCard, DWORD sigSize, LPBYTE pBuffer, DWORD size)
{
	std::vector<DWORD> results;
	for(DWORD index = 0; index < size; ++index)
	{
		bool found = true;
		for(DWORD sindex = 0; sindex < sigSize; ++sindex)
		{
			// Make sure we don't overrun the buffer!
			if(sindex + index >= size)
			{
				found = false;
				break;
			}

			if(sigWildCard != 0)
			{
				if(pBuffer[index + sindex] != sigBuffer[sindex] && sigWildCard[sindex] == 0)
				{
					found = false;
					break;
				}
			}
			else
			{
				if(pBuffer[index + sindex] != sigBuffer[sindex])
				{
					found = false;
					break;
				}
			}
		}
		if(found)
		{
			results.push_back(index);
		}
	}
	return results;
}