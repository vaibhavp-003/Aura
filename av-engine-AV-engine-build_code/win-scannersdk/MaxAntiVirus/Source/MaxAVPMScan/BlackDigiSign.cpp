#include "BlackDigiSign.h"
#include "S2S.h"

/*
CMaxDigiSign::CMaxDigiSign(CMaxPEFile *pMaxPEFile):CPolyBase(pMaxPEFile)
{
}
*/

CMaxDigiSign::CMaxDigiSign()
{
	m_pbyBuff = NULL;
}

CMaxDigiSign::~CMaxDigiSign()
{
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
	
}

DWORD CMaxDigiSign::LoadDatabase(LPCTSTR szDBPath)
{
	DWORD	dwRetStatus = 0;
	CS2S	objVirusSigDBMap(false);
	TCHAR	szLoadDBPath[MAX_PATH] = {0x00};
	DWORD	dwSigCount = 0x00;

	_stprintf_s(szLoadDBPath, MAX_PATH,_T("%s%s"), szDBPath,VIRUS_DB_DIGI_SIG);

	if(!objVirusSigDBMap.Load(szLoadDBPath))
	{
		AddLogEntry(L"Failed to Load SDV13.db");
		return dwRetStatus;
		//return ERR_INVALID_FILE;
	}
	if(objVirusSigDBMap.GetFirst() != NULL)
	{
		dwRetStatus = 1;
		LPVOID posSigEntry = objVirusSigDBMap.GetFirst();
		while(posSigEntry)
		{
			dwSigCount++;
			objVirusSigDBMap.GetKey(posSigEntry, m_szSignature);
			objVirusSigDBMap.GetData(posSigEntry, m_szVirName);
			posSigEntry = objVirusSigDBMap.GetNext(posSigEntry);
			//Add to SemipolyDB Object
			if (!posSigEntry)
			{
				m_SemiPolyDB.LoadSigDBEx(m_szSignature, m_szVirName,FALSE);
				//Add with FALSE
			}
			else
			{
				m_SemiPolyDB.LoadSigDBEx(m_szSignature, m_szVirName,TRUE);
				//Add with TRUE
			}
		}
	}
	return dwSigCount;
}

/*
DWORD CMaxDigiSign::ScanFile(CMaxPEFile *pMaxPEFile, LPTSTR pszVirusName)
{
	DWORD	dwRetStatus = VIRUS_NOT_FOUND;
	
	
	DWORD	dwReadBuffOffset = pMaxPEFile->m_stPEHeader.DataDirectory[0x4].VirtualAddress;
	m_pbyBuff = NULL;
	if(0x0 == dwReadBuffOffset)
	{
		return dwRetStatus;
	}
	DWORD BUFF_SIZE  = pMaxPEFile->m_stPEHeader.DataDirectory[0x4].Size;
	DWORD dwFileSize = pMaxPEFile->m_dwFileSize;

	if(0x0 == BUFF_SIZE) 
	{
		return dwRetStatus;
	}
	if(BUFF_SIZE > 0x3C00)	// size should be less than 15kb
	{
		BUFF_SIZE = 0x3C00;	// 1st 15kb from start of Certificate
	}
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff =NULL;
	}

	m_pbyBuff = new BYTE[(BUFF_SIZE)];
	if(!m_pbyBuff)
	{
		return dwRetStatus;
	}	

	if(GetBuffer(dwReadBuffOffset, BUFF_SIZE, (BUFF_SIZE/3)))
	{
		char	m_szVirusName[MAX_VIRUS_NAME] = {0};
		if(m_SemiPolyDB.ScanBuffer(&m_pbyBuff[0], BUFF_SIZE, m_szVirName) >= 0)
		{
			if(_tcslen(m_szVirName) > 0)
			{
				if (pszVirusName != NULL)
				{
					_tcscpy(pszVirusName,m_szVirName);
				}

				dwRetStatus = VIRUS_FILE_DELETE;
				if(m_pbyBuff)
				{
					delete []m_pbyBuff;
					m_pbyBuff =NULL;
				}
				return dwRetStatus;
			}
		}
		return dwRetStatus;
	}
	
	return dwRetStatus;
}
*/

DWORD CMaxDigiSign::ScanFile(CMaxPEFile *pMaxPEFile, LPTSTR pszVirusName)
{
	DWORD		dwRetStatus = VIRUS_NOT_FOUND;
	DWORD		dwNoOfBytes = 0x00;
	//CPolyBase	objPolyBase(pMaxPEFile);
	
	DWORD	dwReadBuffOffset = pMaxPEFile->m_stPEHeader.DataDirectory[0x4].VirtualAddress;
	//m_pbyBuff = NULL;
	if(0x0 == dwReadBuffOffset)
	{
		return dwRetStatus;
	}
	DWORD BUFF_SIZE  = pMaxPEFile->m_stPEHeader.DataDirectory[0x4].Size;
	DWORD dwFileSize = pMaxPEFile->m_dwFileSize;

	if(0x0 == BUFF_SIZE) 
	{
		return dwRetStatus;
	}
	if(BUFF_SIZE > 0x3C00)	// size should be less than 15kb
	{
		BUFF_SIZE = 0x3C00;	// 1st 15kb from start of Certificate
	}
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff =NULL;
	}

	m_pbyBuff = new BYTE[(BUFF_SIZE)];
	if(!m_pbyBuff)
	{
		return dwRetStatus;
	}	

	//if(objPolyBase.GetBuffer(dwReadBuffOffset, BUFF_SIZE, (BUFF_SIZE/3)))
	if (pMaxPEFile->ReadBuffer(&m_pbyBuff[0x00], dwReadBuffOffset, BUFF_SIZE, BUFF_SIZE/3, &dwNoOfBytes))	
	{
		char	m_szVirusName[MAX_VIRUS_NAME] = {0};
		if(m_SemiPolyDB.ScanBuffer(&m_pbyBuff[0], BUFF_SIZE, m_szVirName) >= 0)
		{
			if(_tcslen(m_szVirName) > 0)
			{
				if (pszVirusName != NULL)
				{
					_tcscpy(pszVirusName,m_szVirName);
				}

				dwRetStatus = VIRUS_FILE_DELETE;
				if(m_pbyBuff)
				{
					delete []m_pbyBuff;
					m_pbyBuff =NULL;
				}
				return dwRetStatus;
			}
		}
		return dwRetStatus;
	}
	else
	{
		//OutputDebugString(L"BLACK MAMBA ==> Failed Buffer ReadBuffer!");
	}
	
	return dwRetStatus;
}