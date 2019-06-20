#include <windows.h>
#include "asmGenerator.h"
#include "Common.h"

void __fastcall getRandomHashCodecave(ASSEMBLY_BUFFER*);
void generateString(LPBYTE out);

int main(int argc, char* args[])
{
	printf("Halo Generic Multiclient. By Oxide.\n"
		"Clients generate random CD Key hashes and as such the server you join should have sv_public set to 0.\n");

	if (argc < 2)
	{
		printf("Please pass at least one command line arguments.\n<target> opt:<command line args to pass to halo>\n");
		return 0;
	}

	std::string startPath = GetWorkingDirectory() + std::string("\\") + args[1];
	std::string cmdLine;

	for (int i = 2; i < argc; i++)
	{
		cmdLine += " ";
		cmdLine += args[i];
	}

	PROCESS_INFORMATION pi = {0};
	STARTUPINFO si = {0};
	si.cb = sizeof(STARTUPINFO);

	srand(GetTickCount());
	DWORD port = rand() % 0xFFFF;

	if (port < 800)
		port += 800;

	char portStr[12] = {0};
	sprintf_s(portStr, 12, "%i", port);

	cmdLine += " -cport ";
	cmdLine += portStr;

	printf("Launching: %s\nCommand line: %s\nPort: %i\n", startPath.c_str(), cmdLine.c_str(), port);

	//Create the process suspended.
	if (CreateProcess((LPSTR)startPath.c_str(), (LPSTR)cmdLine.c_str(), NULL, NULL, NULL, CREATE_SUSPENDED, NULL, NULL, &si, &pi))
	{
		DWORD MODULE_BASE = 0x400000, bytesRead = 0;
		BYTE peHeader[0x1000];
		ReadBytes(pi.hProcess, MODULE_BASE, (LPVOID)&peHeader, sizeof(peHeader));

		DWORD offsetToPE = *(DWORD*)(peHeader + 0x3C);
		DWORD codeSize = *(DWORD*)(peHeader + offsetToPE + 0x1C);
		DWORD baseOfCode = *(DWORD*)(peHeader + offsetToPE + 0x2C);

		LPBYTE codeSection = new BYTE[codeSize];
		ReadBytes(pi.hProcess, MODULE_BASE + baseOfCode, (LPVOID)codeSection, codeSize);

		DWORD dwMutexCheck = 0, dwSaveGamePatch = 0, dwCodecaveJump = 0, dwCodecaveAddress = 0;
		
		BYTE mutexCheckSig[] = {0xC7, 0x44, 0x24, 0x40, 0x94, 0x00, 0x00, 0x00};
		std::vector<DWORD> results = FindSignature(mutexCheckSig, NULL, sizeof(mutexCheckSig), codeSection, codeSize);
		
		if (results.size())
			dwMutexCheck = MODULE_BASE + baseOfCode + results[0] - 0x24;

		BYTE saveGameSig[] = {0x6A, 0x00, 0x68, 0x00, 0x00, 0x00, 0x08};
		results = FindSignature(saveGameSig, NULL, sizeof(saveGameSig), codeSection, codeSize);

		if (results.size() >= 2)
			dwSaveGamePatch =  MODULE_BASE + baseOfCode + results[1];
		
		BYTE codecaveJmpSig[] = {0x8B, 0xB4, 0x24, 0x28, 0x02, 0x00, 0x00, 0x2B, 0xC2};
		results = FindSignature(codecaveJmpSig, NULL, sizeof(codecaveJmpSig), codeSection, codeSize);

		if (results.size())
			dwCodecaveJump = MODULE_BASE + baseOfCode + results[0] + 0x11;

		BYTE codecaveSig[0x60] = {0};
		results = FindSignature(codecaveSig, NULL, sizeof(codecaveSig), codeSection, codeSize);

		if (results.size())
			dwCodecaveAddress = MODULE_BASE + baseOfCode + results[0];

		printf("%08X\n%08X\n%08X\n%08X\n", dwMutexCheck, dwSaveGamePatch, dwCodecaveJump, dwCodecaveAddress);	

		// Apply the patches
		BYTE mutexCheck[] = {0xC3, 0x90, 0x90, 0x90, 0x90, 0x90};
		BYTE savegamePatch[] = {0xEB, 0x4A};
		WriteBytes(pi.hProcess, dwMutexCheck, mutexCheck, sizeof(mutexCheck));
		WriteBytes(pi.hProcess, dwSaveGamePatch, savegamePatch, sizeof(savegamePatch));

		BYTE jmpPatch[] = {0xE9, 0x00, 0x00, 0x00, 0x00, 0x90, 0x90};
		*(DWORD*)(jmpPatch + 1) = dwCodecaveAddress - dwCodecaveJump - 5;
		WriteBytes(pi.hProcess, dwCodecaveJump, jmpPatch, sizeof(jmpPatch));

		asmGenerator gen(getRandomHashCodecave, 0xDEADBEEF);
		
		// fill in seed values
		srand(GetTickCount());
		for (int i = 0; i < 0x20/sizeof(DWORD); i++)
		{
			DWORD chars = 0; generateString((LPBYTE)&chars);
			gen.replaceNext(chars);			
		}

		gen.replaceNext(dwCodecaveJump + 5);

		ASSEMBLY_BUFFER assembly = gen.getAssembly();
		WriteBytes(pi.hProcess, dwCodecaveAddress, assembly.pBuffer, assembly.dwSize);

		delete[] codeSection;
		//TerminateProcess(pi.hProcess, 0);

		//Resume process.
		ResumeThread(pi.hThread);

		//Clean up
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
	}
	else
		printf("Can't create process %i\n", GetLastError());

	return 0;
}

void generateString(LPBYTE out)
{
	const char* values = "0123456789abcdef";
	for (int i = 0; i < 4; i++)
		out[i] = values[rand() % strlen(values)];
}


// Populates a buffer with the assembly code for loading a dll
void __fastcall getRandomHashCodecave(ASSEMBLY_BUFFER*)
{
	__asm
	{
		mov eax, offset buffer_begin
		mov [ecx], eax
		mov edx, offset buffer_end
		sub edx, eax
		mov [ecx + 4], edx
	}
	return;

	__asm
	{
buffer_begin:

		PUSHAD
		MOV EDI,DWORD PTR SS:[ESP+028h]
		MOV DWORD PTR DS:[EDI],0xDEADBEEF
		MOV DWORD PTR DS:[EDI+4],0xDEADBEEF
		MOV DWORD PTR DS:[EDI+8],0xDEADBEEF
		MOV DWORD PTR DS:[EDI+0Ch],0xDEADBEEF
		MOV DWORD PTR DS:[EDI+010h],0xDEADBEEF
		MOV DWORD PTR DS:[EDI+014h],0xDEADBEEF
		MOV DWORD PTR DS:[EDI+018h],0xDEADBEEF
		MOV DWORD PTR DS:[EDI+01Ch],0xDEADBEEF
		POPAD
		LEA EAX,DWORD PTR SS:[ESP+018h]
		LEA EDX,DWORD PTR DS:[ESI+020h]
		mov ecx, 0xDEADBEEF
		JMP ecx	

buffer_end:
	}
}
