#pragma once

#include <windows.h>

struct ASSEMBLY_BUFFER
{
	LPBYTE pBuffer;
	DWORD dwSize;
};

class asmGenerator
{
private:
	DWORD replaceIndex, replaceValue;
	ASSEMBLY_BUFFER code;
	LPBYTE lpCurrent;

public:
	asmGenerator(void (__fastcall *templateFunc)(ASSEMBLY_BUFFER*), DWORD dwMagic);
	~asmGenerator();

	// Replaces the value of the next place holder with the specified value
	bool replaceNext(DWORD dwValue);

	// Returns the assembly buffer
	ASSEMBLY_BUFFER getAssembly();
};