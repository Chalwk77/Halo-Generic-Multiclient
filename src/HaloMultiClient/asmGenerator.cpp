#include "asmGenerator.h"
#include <string>

asmGenerator::asmGenerator(void (__fastcall *templateFunc)(ASSEMBLY_BUFFER*), DWORD dwMagic)
{
	ASSEMBLY_BUFFER temp = {0};

	// populate the assembly buffer with the passed function
	templateFunc(&temp);

	if (!temp.dwSize)
	{
		std::string err = __FUNCTION__ + std::string(" couldn't locate the base assembly stub.");
		throw std::exception(err.c_str());
	}

	code.pBuffer = new BYTE[temp.dwSize];
	code.dwSize = temp.dwSize;
	memcpy(code.pBuffer, temp.pBuffer, temp.dwSize);

	// set variables
	replaceIndex = 0;
	replaceValue = dwMagic;
	lpCurrent = code.pBuffer;
}

asmGenerator::~asmGenerator()
{
	delete[] code.pBuffer;
}

// Replaces the value of the next place holder with the specified value
bool asmGenerator::replaceNext(DWORD dwValue)
{
	bool found = false;
	// Search through the code for the "magic" value
	// if found replace it with dwValue
	while (!found && replaceIndex < code.dwSize)
	{
		if (*(DWORD*)lpCurrent == replaceValue)
		{
			*(DWORD*)lpCurrent = dwValue;
			replaceIndex += 4;
			lpCurrent += 4;
			found = true;
		}
		else
		{
			replaceIndex++;
			lpCurrent++;
		}
	}

	return found;
}

// Returns the assembly buffer
ASSEMBLY_BUFFER asmGenerator::getAssembly()
{
	return code;
}