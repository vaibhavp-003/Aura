#pragma once

#include "pch.h"
#include "MaxPEFile.h"

#include "..\MaxEmulator\x86emu.h"

const int XPAJ_DECRYPT1_BUFF = 0xA900;
const int XPAJ_DECRYPT2_BUFF = 0x10000;

class CEmulate
{
	Process		*m_pProcess;
	CMaxPEFile	*m_pMaxPEFile;

	static System *m_pSystem;
	static EnviromentVariables	*m_pStructEnvVar;
	
public:
	CEmulate(CMaxPEFile *pMaxPEFile);
	~CEmulate(void);

	static int IntializeSystem();
	static void DeIntializeSystem();	

	int IntializeProcess(bool bHandleAPIs = false);
	int SetEip(DWORD dwEip);
	int SetBreakPoint(char *szBreakPoint);
	int ModifiedBreakPoint(char *szBreakPoint, int n);
	int EmulateFile(bool bCheckSecondBP = true);

	void SetNoOfIteration(DWORD dwIteration);
	void ActiveBreakPoint(int index);
	void PauseBreakPoint(int index);
	void GetInstruction(char *szInstruction);
	bool CheckZeroFlag();
	void ModifiedZeroFlag(bool bFlag);
	void FlushCommitMem();
	
	int DumpFile();
	int ReadEmulateBuffer(BYTE *byBuffer, DWORD dwBufferLength, DWORD dwReadStartOff);
	int WriteBuffer(BYTE *byBuffer, DWORD dwBufferLength, DWORD dwReadStartOff, bool bFileEntry = false);
	
	BOOL UpdateSpecifyReg(DWORD dwRegIndex, DWORD dwNewValue);
	DWORD GetEip();
	DWORD GetImmidiateConstant();
	DWORD GetMemoryOprand();
	DWORD GetJumpAddress();
	DWORD GetSrcRegNo();
	DWORD GetInstructionLength();
	DWORD GetSpecifyRegValue(int dwRegIndex);
	DWORD GetDestRegNo();
	DWORD GetDestinationOprand();
	DWORD AddVirtualPointer(MAX_DWORD x, int index, MAX_DWORD dwSize);
	DWORD GetEmulatorFileSize();
	
	DWORD DissassemBuffer(char *byBuff, char *szInstName);
};
