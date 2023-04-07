#pragma once

#include "Emulate.h"

System *CEmulate::m_pSystem = NULL;
EnviromentVariables	*CEmulate::m_pStructEnvVar = NULL;

CEmulate::CEmulate(CMaxPEFile *pMaxPEFile):
m_pProcess(NULL),
m_pMaxPEFile(pMaxPEFile)
{
}

CEmulate::~CEmulate(void)
{
	if(m_pProcess)
	{
		delete m_pProcess;
		m_pProcess = NULL;
	}
}

int CEmulate::IntializeSystem()
{
	int iRetStatus = 0x00;
	m_pStructEnvVar = new EnviromentVariables;
	if(m_pStructEnvVar == NULL)
	{
		return iRetStatus;
	}
	memset( m_pStructEnvVar,0,sizeof(EnviromentVariables)) ;

	TCHAR szSysFolder[MAX_PATH] = {0};
	if(!GetWindowsDirectory(szSysFolder, MAX_PATH))
	{
		return iRetStatus;
	}
 
#ifdef WIN64
	_tcscat_s(szSysFolder, MAX_PATH, L"\\SysWOW64\\");
	m_pStructEnvVar->kernel32	 = (unsigned __int64)GetModuleHandleA("kernel32.dll") ;
	m_pStructEnvVar->ntdll		 = (unsigned __int64)GetModuleHandleA("ntdll.dll") ;
	m_pStructEnvVar->user32		 = (unsigned __int64)LoadLibraryA("user32.dll") ;
#else
	_tcscat_s(szSysFolder, MAX_PATH, L"\\System32\\");
	m_pStructEnvVar->kernel32 = (unsigned __int32)GetModuleHandleA("kernel32.dll") ;
	m_pStructEnvVar->ntdll    =	(unsigned __int32)GetModuleHandleA("ntdll.dll") ;
	m_pStructEnvVar->user32   = (unsigned __int32)LoadLibraryA("user32.dll") ;
#endif
	m_pStructEnvVar->dllspath = szSysFolder;  
	m_pStructEnvVar->MaxIterations = 80000000; 

	m_pSystem = new System(m_pStructEnvVar);
	if(m_pSystem == NULL)
	{
		return iRetStatus;
	}
	return 1;
}

void CEmulate::DeIntializeSystem()
{
	if(m_pStructEnvVar)
	{
		if(m_pStructEnvVar->user32)
		{
			FreeLibrary((HMODULE)m_pStructEnvVar->user32);
			m_pStructEnvVar->user32 = NULL;
		}
		delete m_pStructEnvVar;
		m_pStructEnvVar = NULL;
	}
	if(m_pSystem)
	{
		delete m_pSystem;
		m_pSystem = NULL;
	}
}

int CEmulate::EmulateFile(bool bCheckSecondBP /*= true*/)
{
	return m_pProcess->emulate(bCheckSecondBP);
}

DWORD CEmulate::DissassemBuffer(char *byBuff, char *szInstName)
{
	DWORD dwLen = 0x00;
	memset(szInstName, 0, MAX_PATH);
	ins_disasm	bIns;
	string		strInstName;

	m_pSystem->disasm(&bIns, byBuff, strInstName);
	sprintf_s(szInstName, strInstName.length() + 1, "%s", strInstName.c_str());
	dwLen = bIns.hde.len;

	int i = strlen(szInstName);
	_strupr_s(szInstName, i+1);

	if(szInstName[i-1] == ' ')
	{
		szInstName[i-1] = '\0';
	}
	return dwLen;
}

void WriteEmulatorLog(LPCTSTR szString)
{
	//TCHAR szLogFile[MAX_PATH] = {0};
	//if(GetModuleFileName(NULL, szLogFile, MAX_PATH))
	//{
	//	WCHAR *cExtPtr = wcsrchr(szLogFile, '\\');
	//	*cExtPtr = '\0';
	//	_tcsncat_s(szLogFile, MAX_PATH, L"\\Log\\EmulatorLog.txt", 20);

	//	FILE * fp = 0;
	//	_tfopen_s(&fp, szLogFile, L"a");
	//	if(fp)
	//	{
	//		_fputts(szString, fp);
	//		_fputts(L"\r\n", fp);
	//		fclose(fp);
	//	}
	//}
}

int CEmulate::IntializeProcess(bool bHandleAPIs/* = false*/)
{
	int iRetStatus = 0;

	TCHAR szMsg[1024] = {0};

	_stprintf_s(szMsg, 1024, L"### File entering for emulation having Imagesize = %12ld File path: %s", m_pMaxPEFile->m_stPEHeader.SizeOfImage, m_pMaxPEFile->m_szFilePath);
	WriteEmulatorLog(szMsg);

	WORD wLastSection = m_pMaxPEFile->m_stPEHeader.NumberOfSections - 1;
	DWORD dwLastSecVS = m_pMaxPEFile->m_stSectionHeader[wLastSection].Misc.VirtualSize; 
	DWORD dwLastSecRVA = m_pMaxPEFile->m_stSectionHeader[wLastSection].VirtualAddress; 	
	DWORD dwLastSecPRD = m_pMaxPEFile->m_stSectionHeader[wLastSection].PointerToRawData; 	
	DWORD dwLastSecSRD = m_pMaxPEFile->m_stSectionHeader[wLastSection].SizeOfRawData; 	
	if(dwLastSecPRD + dwLastSecSRD > 1024*13000 || dwLastSecRVA + dwLastSecVS > 1024*13000 || m_pMaxPEFile->m_stPEHeader.SizeOfImage > 1024*13000)
	{		
		_stprintf_s(szMsg, 1024, L"@@@File having VS + RVA > 10MB so skipping. Imagesize = %12ld File path: %s", m_pMaxPEFile->m_stPEHeader.SizeOfImage, m_pMaxPEFile->m_szFilePath);
		WriteEmulatorLog(szMsg);
		return iRetStatus;
	}
	try
	{
		m_pProcess = new Process (m_pSystem, m_pMaxPEFile, bHandleAPIs);
	}
	catch(int i)
	{
		//cout << "File Not Found"<<i;
		return iRetStatus;
	}
	iRetStatus = 1;
	return iRetStatus;
}

int CEmulate::SetBreakPoint(char *szBreakPoint)
{
	m_pProcess->debugger->AddBp(szBreakPoint) ;
	return 1;
}

int CEmulate::ModifiedBreakPoint(char *szBreakPoint, int n)
{
	return m_pProcess->debugger->ModifiedBp(szBreakPoint, n) ;;
}

int CEmulate::DumpFile()
{
	ReconstructImportTable(m_pProcess);	
	TCHAR szOutput[1024] = {0};	
	_stprintf_s(szOutput, MAX_PATH, L"%s.mem", m_pMaxPEFile->m_szFilePath);	
	PEDump(m_pProcess->GetThread(0)->Eip, m_pProcess, szOutput);
	return 1;
}

int CEmulate::ReadEmulateBuffer(BYTE *byBuffer, DWORD dwBufferLength, DWORD dwReadStartOff)
{
	int iRetStatus = 0x00;
	if(byBuffer == NULL || dwBufferLength == 0x00)
	{
		return iRetStatus;
	}
	BYTE *byTemp = NULL;
	byTemp = (BYTE*)m_pProcess->SharedMem->read_virtual_mem(dwReadStartOff);
	if(byTemp == NULL)
	{
		return iRetStatus;
	}
	memcpy(byBuffer, byTemp, dwBufferLength);
	iRetStatus = 0x01;
	return iRetStatus;
}

DWORD CEmulate::GetEip()
{
	return m_pProcess->GetThread(0)->Eip;
}

int CEmulate::SetEip(DWORD dwEip)
{
	m_pProcess->GetThread(0)->Eip = dwEip;
	return dwEip;
}

void CEmulate::SetNoOfIteration(DWORD dwIteration)
{
	m_pProcess->MaxIterations = dwIteration;
}

DWORD CEmulate::GetImmidiateConstant()
{
	if (m_pProcess->ins->flags & SRC_REG)
	{
		return m_pProcess->GetThread(0)->Exx[m_pProcess->ins->nsrc];
	}
	return m_pProcess->ins->nsrc;
}

DWORD CEmulate::GetMemoryOprand()
{
	return modrm_calc(*(m_pProcess->GetThread(0)), m_pProcess->ins);
}

void CEmulate::ActiveBreakPoint(int index)
{
	m_pProcess->debugger->ActivateBp(index);
}

void CEmulate::PauseBreakPoint(int index)
{
	m_pProcess->debugger->PauseBp(index);
}

void CEmulate::GetInstruction(char *szInstruction)
{
	if(szInstruction != NULL)
	{
		memcpy(&szInstruction[0], m_pProcess->strInstName.c_str(), m_pProcess->strInstName.length());
	}
}

DWORD CEmulate::GetJumpAddress()
{
	return (m_pProcess->GetThread(0)->Eip + m_pProcess->ins->ndest + m_pProcess->ins->hde.len);
}

void CEmulate::ModifiedZeroFlag(bool bFlag)
{
	if(bFlag == true)
	{
		m_pProcess->GetThread(0)->EFlags = EFLG_ZF;
	}
	else
	{
		m_pProcess->GetThread(0)->EFlags &= 0xFFFFFFBF;
	}
}


bool CEmulate::CheckZeroFlag()
{
	if((m_pProcess->GetThread(0)->EFlags&EFLG_ZF) == EFLG_ZF)
	{
		return true;
	}

	return false;
}


int CEmulate::WriteBuffer(BYTE *byBuffer, DWORD dwBufferLength, DWORD dwReadStartOff, bool bFileEntry /*= false*/)
{
	int iRetStatus = 0x00;
	if(byBuffer == NULL || dwBufferLength == 0x00)
	{
		return iRetStatus;
	}
	BYTE *byTemp = NULL;
	if(bFileEntry)
	{
		byTemp = (BYTE*)m_pProcess->SharedMem->read_file_mem(dwReadStartOff);
	}
	else
	{
		byTemp = (BYTE*)m_pProcess->SharedMem->read_virtual_mem(dwReadStartOff);
	}
	if(byTemp == NULL)
	{
		return iRetStatus;
	}
	memcpy(byTemp, byBuffer, dwBufferLength);
	iRetStatus = 0x01;
	return iRetStatus;
}

DWORD CEmulate::GetSrcRegNo()
{
	if ((m_pProcess->ins->flags & SRC_REG) && m_pProcess->ins->nsrc < 8)
	{
		return m_pProcess->ins->nsrc;
	}
	return -1;
}

DWORD CEmulate::GetSpecifyRegValue(int dwRegIndex)
{
	if (dwRegIndex < 8)
	{
		return m_pProcess->GetThread(0)->Exx[dwRegIndex];
	}
	return -1;
}

void CEmulate::FlushCommitMem()
{
	for(int i = 0; i < m_pProcess->SharedMem->cmem_length; i++)
	{
		free_emu((void*) m_pProcess->SharedMem->cmem[i]);
	}
	m_pProcess->SharedMem->cmem_length = 0;
}

DWORD	CEmulate::GetDestinationOprand()
{
	if (m_pProcess->ins->flags & DEST_REG )
	{
		if(m_pProcess->ins->ndest < 8)
		{
			return m_pProcess->GetThread(0)->Exx[m_pProcess->ins->ndest];
		}
		return -1;
	}
	if(m_pProcess->ins->flags & DEST_IMM)
	{
		return m_pProcess->ins->ndest;
	}
	return -1;
}

DWORD CEmulate::GetInstructionLength()
{
	return m_pProcess->ins->hde.len;
}

BOOL CEmulate::UpdateSpecifyReg(DWORD dwRegIndex, DWORD dwNewValue)
{
	return m_pProcess->GetThread(0)->UpdateSpecifyRegister(dwRegIndex, dwNewValue);
}

DWORD CEmulate::AddVirtualPointer(MAX_DWORD x, int index, MAX_DWORD dwSize)
{
	DWORD dwAllocAddress = 0x00;
	if(dwSize <= 0x10000)
	{
		dwAllocAddress = m_pProcess->GetThread(0)->mem->vmem[0]->size + m_pProcess->GetThread(0)->mem->vmem[0]->vmem + index * 0x10000;
		m_pProcess->GetThread(0)->mem->add_pointer(x, (DWORD)dwAllocAddress, (DWORD)dwSize, MEM_VIRTUALPROTECT);
	}
	return dwAllocAddress;
}

DWORD CEmulate::GetDestRegNo()
{
	if ((m_pProcess->ins->flags & DEST_REG) && m_pProcess->ins->ndest < 8)
	{
		return m_pProcess->ins->ndest;
	}
	return -1;
}

DWORD CEmulate::GetEmulatorFileSize()
{
	return m_pProcess->m_dwEmulatorFileSize;
}
