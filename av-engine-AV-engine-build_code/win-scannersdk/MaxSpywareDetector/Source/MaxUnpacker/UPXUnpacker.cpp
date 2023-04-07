#include "UPXUnpacker.h"
#include "MaxExceptionFilter.h"
#include "Packers.h"

LPFNUnPackUPXFile CUPXUnpacker::m_lpfnUnPackUPXFile = NULL;
LPFNUnPackUPXFile64 CUPXUnpacker::m_lpfnUnPackUPXFile64 = NULL;
HMODULE	CUPXUnpacker::m_hUPXUnpacker = NULL;
HMODULE	CUPXUnpacker::m_hUPXUnpacker64 = NULL;

bool CUPXUnpacker::LoadUPXDll()
{
	TCHAR	szAppPath[MAX_PATH] = {0x00}, *pTemp = NULL;
	TCHAR	szUpxPath[MAX_PATH] = {0x00},szUpx64Path[MAX_PATH] = {0x00};

	GetModuleFileName(NULL,&szAppPath[0x00],MAX_PATH);

	//_stprintf(szUpxPath,L"CUPXUnpacker::LoadUPXDll : %s",szAppPath);
	//OutputDebugString(szUpxPath);
	
	_tcslwr(szAppPath);
	if (_tcsstr(szAppPath,L"\\auunpackexe.exe") != NULL)
	{

		pTemp = _tcsrchr(szAppPath,L'\\');
		if (pTemp != NULL)
		{
			*pTemp = '\0';
			_tcscat(szAppPath,L"\\UPack32\\");
		}
		else
		{
			_tcscpy(szAppPath,L"UPack32\\");
		}

		_stprintf( szUpxPath,L"%s\\AuUPXUnpacker.dll",szAppPath);
		_stprintf( szUpx64Path,L"%s\\AuUPXUnpacker64.dll",szAppPath);

	}
	else
	{
		_stprintf( szUpxPath,L"AuUPXUnpacker.dll");
		_stprintf( szUpx64Path,L"AuUPXUnpacker64.dll");
	}
	

	m_hUPXUnpacker = LoadLibrary(szUpxPath);
	m_hUPXUnpacker64 = LoadLibrary(szUpx64Path);
	if(m_hUPXUnpacker == NULL || m_hUPXUnpacker64 == NULL)
	{
		DWORD dwError = GetLastError();
		TCHAR szMsg[1024] = {0};
		_stprintf_s(szMsg, MAX_PATH, L"AuUPXUnpacker.dll LoadLibrary failed. GetLastError = %d[%s]", dwError,szMsg);
		OutputDebugString(szMsg);
		return false;
	}

	m_lpfnUnPackUPXFile = (LPFNUnPackUPXFile) GetProcAddress(m_hUPXUnpacker, "UnPackUPXFile");
	m_lpfnUnPackUPXFile64 = (LPFNUnPackUPXFile64) GetProcAddress(m_hUPXUnpacker64, "UnPackUPXFile64");
	if(m_lpfnUnPackUPXFile  == NULL || m_lpfnUnPackUPXFile64  == NULL)
	{	
		return false;
	}
	return true;
}

bool CUPXUnpacker::UnLoadUPXDll()
{
	if(m_hUPXUnpacker)
	{		
		FreeLibrary(m_hUPXUnpacker);
		m_hUPXUnpacker = NULL;
		m_lpfnUnPackUPXFile = NULL;
	}
	/*
	if(m_hUPXUnpacker64)
	{		
		FreeLibrary(m_hUPXUnpacker64);
		m_hUPXUnpacker64 = NULL;
		m_lpfnUnPackUPXFile64 = NULL;
	}
	*/
	
	return true;
}

bool CUPXUnpacker::UnLoadUPXDll64()
{
	
	if(m_hUPXUnpacker64)
	{		
		FreeLibrary(m_hUPXUnpacker64);
		m_hUPXUnpacker64 = NULL;
		m_lpfnUnPackUPXFile64 = NULL;
	}
	
	
	return true;
}

CUPXUnpacker::CUPXUnpacker(CMaxPEFile *pMaxPEFile, int iCurrentLevel): 
CUnpackBase(pMaxPEFile, iCurrentLevel)
{
}

CUPXUnpacker::~CUPXUnpacker(void)
{
	m_objTempFile.CloseFile();
}


bool CUPXUnpacker::IsPacked() 
{
	TCHAR	szLogLine[1024] = {0x00};
	
	if(m_pMaxPEFile->m_stPEHeader.NumberOfSections >= 0x03 && 
		(m_pMaxPEFile->m_stSectionHeader[0].SizeOfRawData <= 0x05 || 
		m_pMaxPEFile->m_stSectionHeader[0].SizeOfRawData == m_pMaxPEFile->m_stSectionHeader[0].Misc.VirtualSize || 
		m_iCurrentLevel > 0) &&
		m_pMaxPEFile->m_stSectionHeader[1].SizeOfRawData > 0 &&
		m_pMaxPEFile->m_stSectionHeader[2].SizeOfRawData > 0)
	{
		const int UPX_BUFF_SIZE = 12;
		BYTE byBuff[UPX_BUFF_SIZE] = {0};

		if(m_pMaxPEFile->ReadBuffer(byBuff, m_pMaxPEFile->m_dwAEPMapped, UPX_BUFF_SIZE, UPX_BUFF_SIZE))
		{			
			if( (byBuff[0] == 0x60 && byBuff[1] == 0xBE && *(WORD*)&byBuff[6] == 0xBE8D) ||
				(byBuff[0]==0xBE && *(WORD*)&byBuff[5] == 0xBE8D) ||
				(*(DWORD*)&byBuff[0] == 0x08247C80 && byBuff[4] == 0x01 && *(WORD*)&byBuff[5] == 0x850F))
			{
				return true;
			}
			if(m_pMaxPEFile->m_b64bit)
			{
				return true;
			}
		}
	}

	return false;
}

bool CUPXUnpacker::Unpack(LPCTSTR m_szTempFilePath)
{
	TCHAR	szLogLine[1024] = {0x00};
	SetFileAttributes(m_pMaxPEFile->m_szFilePath, FILE_ATTRIBUTE_NORMAL);				

	char szFilePath[MAX_PATH] = {0}, szUnpackFilePath[MAX_PATH] = {0};
	sprintf_s(szFilePath, MAX_PATH, "%S", m_pMaxPEFile->m_szFilePath);
	sprintf_s(szUnpackFilePath, MAX_PATH, "%S", m_szTempFilePath);
	if(strlen(szFilePath) == 0)
	{
		return false;
	}

	if(m_hUPXUnpacker == NULL)
	{
		LoadUPXDll();
	}

	DWORD dwtemp = *((DWORD *)m_pMaxPEFile->m_stSectionHeader[0].Name) & 0x00FFFFFF;
	const int BUFF_SIZE = 0x400;
	BYTE *bySrcBuff = new BYTE[BUFF_SIZE];
	if(!m_pMaxPEFile->ReadBuffer(bySrcBuff,m_pMaxPEFile->m_stSectionHeader[1].PointerToRawData-64, BUFF_SIZE, BUFF_SIZE))
	{
		delete []bySrcBuff;
		bySrcBuff = NULL;
		return false;
	}
	bool bCavity = false;
	DWORD dwboff;
	for(dwboff = 0; dwboff <= (BUFF_SIZE - 4); dwboff++)
	{
		if(bySrcBuff[dwboff] == BYTE(dwtemp) && memcmp((DWORD*)&bySrcBuff[dwboff], &dwtemp, sizeof(WORD) + sizeof(BYTE))==0x00)
		{
			if (dwboff <= 0 || dwboff > 0x30 && dwtemp!=0x21585055)
			{
				dwtemp = 0x21585055;
				dwboff = 0;
			}
			else if(dwboff <= 0 || dwboff > 0x30)
			{
				break;
			}
			else
			{
				break;
			}
		}
	}

	DWORD dwOffset = 0x00;
	bool bLZMA = false;
	if(dwboff+0x18 <=BUFF_SIZE)
	{
		if((bySrcBuff[dwboff+0x06]>0x0E || bySrcBuff[dwboff+0x06]==0x00)||
			bySrcBuff[dwboff+0x04]<12 || bySrcBuff[dwboff+0x04]>13 ||
			*(DWORD*)&bySrcBuff[dwboff+0x14]>m_pMaxPEFile->m_dwFileSize ||
			*(DWORD*)&bySrcBuff[dwboff+0x14]>=*(DWORD*)&bySrcBuff[dwboff+0x10] ||
            *(DWORD*)&bySrcBuff[dwboff+0x14]==0x00
			)
		{
			dwboff=0x3FF;
		}
	}
	
	if(dwboff <= 0 || dwboff > 0x30)
	{
		memset(bySrcBuff, 0, BUFF_SIZE);
		if(!m_pMaxPEFile->ReadBuffer(bySrcBuff, m_pMaxPEFile->m_dwAEPMapped, 0x40, 0x40))
		{
			delete []bySrcBuff;
			bySrcBuff = NULL;
			return false;
		}

		DWORD dwLength = 0, dwInstructionCountFound = 0;		
		char szInstruction[BUFF_SIZE] = {0x00};
		CEmulate objEmulate(m_pMaxPEFile);
		while(dwOffset < 0x30)
		{
			dwLength = objEmulate.DissassemBuffer((char*)&bySrcBuff[dwOffset], szInstruction);

			if(strstr(szInstruction, "MOV AL ,BYTE PTR [ESI]") && dwLength == 0x02)
			{
				break;
			}
			else if(strstr(szInstruction, "INC ESI") && dwLength == 0x01 && *(WORD *)&bySrcBuff[dwOffset + 0x01] == 0x5346)
			{
				bLZMA = true;
				break;
			}
			dwOffset+=dwLength;
		}
	}
	if(bySrcBuff)
	{
		delete []bySrcBuff;
		bySrcBuff = NULL;
	}
	
	if(m_pMaxPEFile->m_b64bit)
	{
		if(!m_lpfnUnPackUPXFile64(szFilePath, szUnpackFilePath))
		{
			UnLoadUPXDll64();
		}
	}

	//if(m_pMaxPEFile->m_b64bit)
	//{
		
	else
	{
		if(!m_lpfnUnPackUPXFile(szFilePath, szUnpackFilePath, dwOffset, dwboff, bLZMA))
		{
			UnLoadUPXDll();

			if(!m_lpfnUnPackUPXFile64(szFilePath, szUnpackFilePath))
			{
				UnLoadUPXDll64();
			}
		}
	}

	
	//}

	/*
	else
	{
		if(!m_lpfnUnPackUPXFile(szFilePath, szUnpackFilePath, dwOffset, dwboff, bLZMA))
			//if(!m_lpfnUnPackUPXFile(szFilePath, szUnpackFilePath))
		{
			
		}
	}
	*/

	WIN32_FILE_ATTRIBUTE_DATA FileInfo = {0};
	if(GetFileAttributesEx(m_szTempFilePath, GetFileExInfoStandard, &FileInfo))
	{
		if(MKQWORD(FileInfo.nFileSizeHigh, FileInfo.nFileSizeLow) > 0x100 && 
			MKQWORD(FileInfo.nFileSizeHigh, FileInfo.nFileSizeLow) != (ULONG64(m_pMaxPEFile->m_dwFileSize)))
		{
			SetFileAttributes(m_szTempFilePath, FILE_ATTRIBUTE_NORMAL);				
			return true;
		}
	}
	::DeleteFile(m_szTempFilePath);
	return false;
}



