#include "pch.h"
#include "MaxReportQMGR.h"
//#pragma warning( push )
#pragma warning( disable : 4789 )
// unused code that generates compiler warning C4789`
//#pragma warning( pop )

BOOL CMaxReportQMGR::AllocateHeapMem()
{
	BOOL	bResult = FALSE;

	if (m_hHeapHadle == NULL)
	{
		m_hHeapHadle = HeapCreate(0x00, MAX_DEF_HEAP_SIZE + 32, 0x00);
		if (m_hHeapHadle == NULL)
		{
			return bResult;
		}
		int		iHEAP_LFH = 0x02;
		HeapSetInformation(m_hHeapHadle, HeapCompatibilityInformation, &iHEAP_LFH, sizeof(iHEAP_LFH));
	}

	if (m_pHeapBuffer == NULL)
	{
		m_pHeapBuffer = (unsigned char*)HeapAlloc(m_hHeapHadle, HEAP_ZERO_MEMORY, MAX_DEF_HEAP_SIZE);
		if (NULL == m_pHeapBuffer)
		{
			return bResult;
		}
		bResult = TRUE;
	}
	else
	{
		bResult = TRUE;
	}

	return bResult;
}

BOOL CMaxReportQMGR::ExtendHeapMemory()
{
	BOOL			bResult = TRUE;
	unsigned char* pTempHeapPtr = NULL;
	int				iError = 0x00;

	pTempHeapPtr = m_pHeapBuffer;

	m_dwHeapIncreaseCnt++;

	m_pHeapBuffer = (unsigned char*)HeapReAlloc(m_hHeapHadle, HEAP_ZERO_MEMORY | HEAP_REALLOC_IN_PLACE_ONLY, (LPVOID)m_pHeapBuffer, (m_dwHeapIncreaseCnt * MAX_DEF_HEAP_SIZE));
	iError = GetLastError();

	if (NULL == m_pHeapBuffer)
	{
		m_dwHeapIncreaseCnt--;
		m_pHeapBuffer = pTempHeapPtr;
		bResult = FALSE;
	}

	return bResult;
}

DWORD CMaxReportQMGR::AddRecordtoReportQueue(LPVOID lpBuffer,int iType = 0x00)
{
	DWORD	dwResult = 0x00;
	DWORD	dwReqBuffLen = 0x00;
	DWORD	dwIndex = 0x00;


	if (lpBuffer == NULL)
	{
		return dwResult;
	}

	if (iType == 0x00) //File
	{
		dwReqBuffLen = MAX_FILE_RECORD_SIZE  + sizeof(DWORD);
		dwIndex = MAX_FILE_RECORD_RANGE + m_dwCurRecCnt;
	}
	else
	{
		dwReqBuffLen = MAX_REG_RECORD_SIZE + sizeof(DWORD);
		dwIndex = MAX_REG_RECORD_RANGE + m_dwCurRecCnt;
	}
	
	if (m_dwCurHeapIndex + dwReqBuffLen >= (MAX_DEF_HEAP_SIZE * m_dwHeapIncreaseCnt))
	{
		//if (!ExtendHeapMemory())
		if (!ExtendMapFileMemory())
		{
			return dwResult;
		}
	}
	
	if (iType == 0x00) //File
	{
		FILE_REPORT_DATA	objData = { 0x00 };
		//LPFILE_REPORT_DATA	objData = new FILE_REPORT_DATA;
		//memset(objData, 0, sizeof(FILE_REPORT_DATA));
		objData.dwIndex = dwIndex;
		memcpy(&objData.byReportData[0x00], lpBuffer, MAX_FILE_RECORD_SIZE);
		memcpy(&m_pHeapBuffer[m_dwCurHeapIndex], &objData, sizeof(FILE_REPORT_DATA));
		//delete objData;
	}
	else
	{
		REG_REPORT_DATA		objData = { 0x00 };
		//LPREG_REPORT_DATA objData = new REG_REPORT_DATA;
		//memset(objData,0,sizeof(REG_REPORT_DATA));
		objData.dwIndex = dwIndex;
		memcpy(&objData.byReportData[0x00], lpBuffer, MAX_REG_RECORD_SIZE);
		memcpy(&m_pHeapBuffer[m_dwCurHeapIndex], &objData, sizeof(REG_REPORT_DATA));
		//delete objData;
	}

	m_dwCurRecCnt++;
	m_dwCurHeapIndex += dwReqBuffLen;

	return dwIndex;
}

DWORD CMaxReportQMGR::GetRecordFromReportQueue(DWORD dwIndex, LPVOID lpBuffer)
{
	DWORD	dwResult = 0x00;
	DWORD	dwCurPos = 0x00;

	if (m_pHeapBuffer == NULL || m_dwCurHeapIndex == 0x00 || dwIndex < MAX_FILE_RECORD_RANGE || lpBuffer == NULL)
	{
		return dwResult;
	}

	while (dwCurPos < m_dwCurHeapIndex)
	{
		BYTE	byIndex[sizeof(DWORD)] = { 0x00 };
		DWORD	dwDBIndex = 0x00;
		DWORD	dwtype = 0x00;
		DWORD	dwReqBuffLen = MAX_FILE_RECORD_SIZE + sizeof(DWORD);

		memcpy(&byIndex[0x00], &m_pHeapBuffer[dwCurPos], sizeof(DWORD));
		dwDBIndex = *((DWORD*)&byIndex[0x00]);

		if (dwDBIndex < MAX_FILE_RECORD_RANGE)
		{
			break;
		}
		else if (dwDBIndex >= MAX_REG_RECORD_RANGE)
		{
			dwtype = 0x1;
			dwReqBuffLen = MAX_REG_RECORD_SIZE + sizeof(DWORD);
		}

		if (dwDBIndex == dwIndex)
		{
			if (dwtype == 0x00)
			{
				LPFILE_REPORT_DATA pTemp1 = (LPFILE_REPORT_DATA)&m_pHeapBuffer[dwCurPos];
				memcpy(lpBuffer, pTemp1->byReportData, MAX_FILE_RECORD_SIZE);
				dwResult = MAX_FILE_RECORD_SIZE;
			}
			else
			{
				LPREG_REPORT_DATA pTemp = (LPREG_REPORT_DATA)&m_pHeapBuffer[dwCurPos];
				memcpy(lpBuffer, pTemp->byReportData, MAX_REG_RECORD_SIZE);
				dwResult = MAX_REG_RECORD_SIZE;
			}
			break;
		}

		dwCurPos += dwReqBuffLen;

	}


	return dwResult;
}

BOOL CMaxReportQMGR::AllocateVirtualMem()
{
	BOOL	bResult = FALSE;

	m_pHeapBuffer = (unsigned char*)VirtualAlloc(NULL, MAX_DEF_HEAP_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (m_pHeapBuffer == nullptr)
	{
		return bResult;
	}
	return TRUE;
}

BOOL CMaxReportQMGR::AllocateMemMapFile(TCHAR *szTempFilename)
{
	BOOL	bResult = FALSE;

	m_hHeapHadle = CreateFile(szTempFilename, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
	if (INVALID_HANDLE_VALUE == m_hHeapHadle)
	{
		return bResult;
	}

	int iError = GetLastError();

	m_hMapping = NULL;
	m_hMapping = CreateFileMapping(m_hHeapHadle, 0, PAGE_READWRITE, 0, (m_dwHeapIncreaseCnt * MAX_DEF_HEAP_SIZE), NULL);
	if (!m_hMapping)
	{
		CloseHandle(m_hHeapHadle);
		m_hHeapHadle = NULL;
		return bResult;
	}

	m_pHeapBuffer = (unsigned char*)MapViewOfFile(m_hMapping, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0);
	if (m_pHeapBuffer == NULL)
	{
		CloseHandle(m_hMapping);
		CloseHandle(m_hHeapHadle);
		m_hMapping = NULL;
		m_hHeapHadle = NULL;
		return bResult;
	}

	return TRUE;
}

BOOL CMaxReportQMGR::ExtendMapFileMemory()
{
	BOOL			bResult = TRUE;
	unsigned char* pTempHeapPtr = NULL;
	int				iError = 0x00;

	pTempHeapPtr = m_pHeapBuffer;

	m_dwHeapIncreaseCnt++;

	UnmapViewOfFile(m_pHeapBuffer);
	CloseHandle(m_hMapping);
	m_hMapping = NULL;
	m_hMapping = CreateFileMapping(m_hHeapHadle, 0, PAGE_READWRITE, 0, (m_dwHeapIncreaseCnt * MAX_DEF_HEAP_SIZE), NULL);
	if (!m_hMapping)
	{
		CloseHandle(m_hHeapHadle);
		m_hHeapHadle = NULL;
		return bResult;
	}

	m_pHeapBuffer = (unsigned char*)MapViewOfFile(m_hMapping, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0);
	if (m_pHeapBuffer == NULL)
	{
		CloseHandle(m_hMapping);
		CloseHandle(m_hHeapHadle);
		m_hMapping = NULL;
		m_hHeapHadle = NULL;
		return bResult;
	}

	if (NULL == m_pHeapBuffer)
	{
		m_dwHeapIncreaseCnt--;
		m_pHeapBuffer = pTempHeapPtr;
		bResult = FALSE;
	}

	return bResult;
}
BOOL CMaxReportQMGR::ReleaseMemMapFile()
{
	if (NULL == m_pHeapBuffer)
	{
		UnmapViewOfFile(m_pHeapBuffer);
		m_pHeapBuffer = NULL;
	}
	
	if (NULL == m_hMapping)
	{
		CloseHandle(m_hMapping);
		m_hMapping = NULL;
	}
	
	
	if (m_hHeapHadle )
	{
		CloseHandle(m_hHeapHadle);
		m_hHeapHadle = NULL;
	}
	return TRUE;
}