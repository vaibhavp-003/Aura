#include "pch.h"
#include "MaxIconScanner.h"


#ifndef _free
#define _free(p) {if(p != NULL){ free(p); p = NULL;}}
#endif

CMaxIconScanner::CMaxIconScanner(void):m_IconS2S(false)
{
	TCHAR	szDllPath[512] = {0x00};
	TCHAR	*pszTemp = NULL;
	
	m_pbyBuff = NULL;
	_tcscpy(m_szDBFilePath,L"");

	GetModuleFileName(NULL,szDllPath,512);
	pszTemp = _tcsrchr(szDllPath,L'\\');
	if (pszTemp != NULL)
	{
		*pszTemp = '\0';
		pszTemp = NULL;
		
		_tcscpy(m_szDBFilePath,szDllPath);
		_tcscat(m_szDBFilePath,L"\\");
	}
	_tcscat(m_szDBFilePath,L"IconDB.DB");
	
	m_IconS2S.Load(m_szDBFilePath);
}

CMaxIconScanner::~CMaxIconScanner(void)
{
	m_IconS2S.RemoveAll();
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
}

bool CMaxIconScanner::FileGetInfo(CMaxPEFile *pMaxPEFile)
{
	bool dwRetVal = false;
	m_pMaxPEFile = pMaxPEFile;
	m_pSectionHeader = &m_pMaxPEFile->m_stSectionHeader[0];
	m_wNoOfSections = m_pMaxPEFile->m_stPEHeader.NumberOfSections;	
	return true;
}

bool CMaxIconScanner::ScanFile(CMaxPEFile *pMaxPEFile,LPCTSTR pszDBPath,char *szVirusName)
{
	bool bRetVal = false;
	LPTSTR lpMalwareName = NULL;

	if (_tcslen(pMaxPEFile->m_szResourceMD5) > 30)
	{
		_tcslwr(pMaxPEFile->m_szResourceMD5);
		if (m_IconS2S.SearchItem(pMaxPEFile->m_szResourceMD5, lpMalwareName))
		{
			strcpy_s(szVirusName, MAX_VIRUS_NAME, CStringA(lpMalwareName).GetString());
			bRetVal = true;                 
		}
	}
	else if (_tcscmp(pMaxPEFile->m_szResourceMD5, L"100") == 0)
	{
		return false;
	} 
	else
	{ 
		FileGetInfo(pMaxPEFile);

		DWORD		dwResourceSRD = 0x00;
		DWORD		dwResourcePRD = 0x00;
		char		strMD5Value[33] = { 0x00 };
		CString		csSign;

		for (int i = 0; i <= m_wNoOfSections; i++)
		{
			if ((memcmp(m_pSectionHeader[i].Name, ".rsrc", 5) == 0))
			{
				dwResourceSRD = m_pSectionHeader[i].SizeOfRawData;

				if (m_pbyBuff)
				{
					delete[]m_pbyBuff;
					m_pbyBuff = NULL;
				}

				if (dwResourceSRD > (5 * 1024 * 1024))
				{
					return bRetVal;
				}

				m_pbyBuff = new BYTE[dwResourceSRD];
				if (!m_pbyBuff)
				{
					return bRetVal;
				}

				dwResourcePRD = m_pSectionHeader[i].PointerToRawData;

				if (GetBuffer(dwResourcePRD, dwResourceSRD, dwResourceSRD))
				{
					objmd5.digestString(&m_pbyBuff[0x00], dwResourceSRD);
					strcpy(strMD5Value, objmd5.digestChars);

					CString		csMD5(strMD5Value);
					csMD5.MakeLower();
					
					csMD5.ReleaseBuffer();
					OutputDebugString(csMD5);
					if (m_IconS2S.SearchItem(csMD5, lpMalwareName))
					{
						strcpy_s(szVirusName, MAX_VIRUS_NAME, CStringA(lpMalwareName).GetString());
						bRetVal = true;
					}
				}
				break;
			}
		}
	}

	return bRetVal;
}


bool CMaxIconScanner::GetBuffer(DWORD dwOffset, DWORD dwNumberOfBytesToRead, DWORD dwMinBytesReq)
{
	DWORD m_dwNoOfBytes = 0;
	return m_pMaxPEFile->ReadBuffer(m_pbyBuff, dwOffset, dwNumberOfBytesToRead, dwMinBytesReq, &m_dwNoOfBytes);	
}
