#include "stdafx.h"
#include "SpyEntry.h"

CSpyEntry::CSpyEntry():CBalBSTOpt(false)
{
}

CSpyEntry::~CSpyEntry()
{
	RemoveAll();
}

void CSpyEntry::FreeKey(SIZE_T nKey)
{
}

void CSpyEntry::FreeData(SIZE_T nData)
{
	if(((LPBYTE)nData < m_pBuffer) ||((LPBYTE)nData >= (m_pBuffer + m_nBufferSize)))
	{
		DeleteData((LPSPY_DATA)nData);
	}
}

COMPARE_RESULT CSpyEntry::Compare(SIZE_T nKey1, SIZE_T nKey2)
{
	if(nKey1 < nKey2)
	{
		return SMALL;
	}
	else if(nKey1 > nKey2)
	{
		return LARGE;
	}
	else
	{
		return EQUAL;
	}
}

void CSpyEntry::DeleteData(LPSPY_DATA lpData)
{
	if(!lpData)
	{
		return;
	}

	if(lpData->szDateTime)
	{
		Release((LPVOID&)lpData->szDateTime);
	}

	if(lpData->szMachineName)
	{
		Release((LPVOID&)lpData->szMachineName);
	}

	if(lpData->szMachineID)
	{
		Release((LPVOID&)lpData->szMachineID);
	}

	if(lpData->szSpyName)
	{
		Release((LPVOID&)lpData->szSpyName);
	}

	if(lpData->szKey)
	{
		Release((LPVOID&)lpData->szKey);
	}

	if(lpData->szValue)
	{
		Release((LPVOID&)lpData->szValue);
	}

	if(lpData->szBackupFileName)
	{
		Release((LPVOID&)lpData->szBackupFileName);
	}

	if(lpData->byData)
	{
		Release((LPVOID&)lpData->byData);
	}

	if(lpData->byReplaceData)
	{
		Release((LPVOID&)lpData->byReplaceData);
	}

	if(lpData)
	{
		Release((LPVOID&)lpData);
		lpData = NULL;
	}
}

LPSPY_DATA CSpyEntry::GetData(LPCTSTR szMachineID, LPCTSTR szMachineName, ULONG64 ulDate,
								DWORD dwTime, DWORD dwIndexDB, LPSPY_ENTRY_INFO lpSpyEntryInfo)
{
	LPSPY_DATA tmp = NULL;
	TCHAR szDateTime[MAX_PATH] = {0};

	if(!lpSpyEntryInfo)
	{
		return NULL;
	}

	DateTimeForUI(lpSpyEntryInfo->ul64DateTime, szDateTime, _countof(szDateTime));
	if(0 == szDateTime[0])
	{
		return NULL;
	}

	tmp = (LPSPY_DATA)Allocate(sizeof(SPY_DATA));
	if(NULL == tmp)
	{
		return NULL;
	}

	tmp->dwIndexDB = dwIndexDB;
	tmp->eTypeOfEntry = lpSpyEntryInfo->eTypeOfEntry;
	tmp->ulHive = lpSpyEntryInfo->ulHive;
	tmp->dwRegDataSize = lpSpyEntryInfo->dwRegDataSize;
	tmp->dwReplaceRegDataSize = lpSpyEntryInfo->dwReplaceRegDataSize;
	tmp->wRegDataType = lpSpyEntryInfo->wRegDataType;
	tmp->dwSpywareID = lpSpyEntryInfo->dwSpywareID;
	tmp->byStatus = lpSpyEntryInfo->byStatus;
	tmp->byChecked = lpSpyEntryInfo->byChecked;
	tmp->byThreatLevel = lpSpyEntryInfo->byThreatLevel;
	tmp->ul64DateTime = lpSpyEntryInfo->ul64DateTime;
	tmp->byFix_Type = lpSpyEntryInfo->byFix_Type;
	tmp->byFix_Action = lpSpyEntryInfo->byFix_Action;
	tmp->ulDate = ulDate;
	tmp->dwTime = dwTime;
	tmp->szDateTime = DuplicateString(szDateTime);
	tmp->szMachineName = DuplicateString(szMachineName);
	tmp->szMachineID = DuplicateString(szMachineID);
	tmp->szSpyName = DuplicateString(lpSpyEntryInfo->szSpyName);
	tmp->szKey = DuplicateString(lpSpyEntryInfo->szKey);
	tmp->szValue = DuplicateString(lpSpyEntryInfo->szValue);
	tmp->szBackupFileName = DuplicateString(lpSpyEntryInfo->szBackupFileName);
	tmp->byData = DuplicateBuffer(lpSpyEntryInfo->byData, lpSpyEntryInfo->dwRegDataSize);
	tmp->byReplaceData = DuplicateBuffer(lpSpyEntryInfo->byReplaceData, lpSpyEntryInfo->dwReplaceRegDataSize);

	if(szDateTime[0] && !tmp->szDateTime)
	{
		goto ERROR_EXIT;
	}

	if(!tmp->szMachineName && szMachineName)
	{
		goto ERROR_EXIT;
	}

	if(!tmp->szMachineID && szMachineID)
	{
		goto ERROR_EXIT;
	}

	if(!tmp->szSpyName && lpSpyEntryInfo->szSpyName)
	{
		goto ERROR_EXIT;
	}

	if(!tmp->szKey && lpSpyEntryInfo->szKey)
	{
		goto ERROR_EXIT;
	}

	if(!tmp->szValue && lpSpyEntryInfo->szValue)
	{
		goto ERROR_EXIT;
	}

	if(!tmp->szBackupFileName && lpSpyEntryInfo->szBackupFileName)
	{
		goto ERROR_EXIT;
	}

	if(!tmp->byData && lpSpyEntryInfo->byData)
	{
		goto ERROR_EXIT;
	}

	if(!tmp->byReplaceData && lpSpyEntryInfo->byReplaceData)
	{
		goto ERROR_EXIT;
	}

	return tmp;

ERROR_EXIT:

	DeleteData(tmp);
	return NULL;
}

bool CSpyEntry::AppendItemAscOrder(DWORD dwKey, LPCTSTR szMachineID, LPCTSTR szMachineName, ULONG64 ulDate,
									DWORD dwTime, DWORD dwIndexDB, LPSPY_ENTRY_INFO lpSpyEntryInfo)
{
	LPSPY_DATA lpSpyData = NULL;

	lpSpyData = GetData(szMachineID, szMachineName, ulDate, dwTime, dwIndexDB, lpSpyEntryInfo);
	if(!lpSpyData)
	{
		return false;
	}

	if(!AddNodeAscOrder(dwKey, (SIZE_T)lpSpyData))
	{
		DeleteData((LPSPY_DATA)lpSpyData);
		return false;
	}

	return true;
}

bool CSpyEntry::AppendItem(DWORD dwKey, LPCTSTR szMachineID, LPCTSTR szMachineName, ULONG64 ulDate,
							DWORD dwTime, DWORD dwIndexDB, LPSPY_ENTRY_INFO lpSpyEntryInfo)
{
	LPSPY_DATA lpSpyData = NULL;

	lpSpyData = GetData(szMachineID, szMachineName, ulDate, dwTime, dwIndexDB, lpSpyEntryInfo);
	if(!lpSpyData)
	{
		return false;
	}

	if(!AddNode(dwKey, (SIZE_T)lpSpyData))
	{
		DeleteData((LPSPY_DATA)lpSpyData);
		return false;
	}

	return true;
}

bool CSpyEntry::SearchItem(DWORD dwKey, LPSPY_DATA& lpSpyDetail)
{
	SIZE_T nData = 0;

	if(!FindNode(dwKey, nData))
	{
		return false;
	}

	lpSpyDetail = (LPSPY_DATA)nData;
	return true;
}

bool CSpyEntry::GetKey(PVOID pVPtr, DWORD& dwKey)
{
	if(!pVPtr)
	{
		return (false);
	}

	dwKey = (DWORD)(((PNODEOPT)pVPtr)->nKey);
	return (true);
}

bool CSpyEntry::GetData(PVOID pVPtr, LPVOID& lpvData)
{
	if(!pVPtr)
	{
		return (false);
	}

	lpvData = (LPVOID&)(((PNODEOPT)pVPtr)->nData);
	return (true);
}

bool CSpyEntry::AppendObject(CBalBSTOpt& objToAdd)
{
	// implemented because this is pure virtual in base
	return true;
}

bool CSpyEntry::DeleteObject(CBalBSTOpt& objToDel)
{
	// implemented because this is pure virtual in base
	return true;
}

bool CSpyEntry::Load(LPCTSTR szFileName, bool bCheckVersion)
{
	// implemented because this is pure virtual in base
	return true;
}

bool CSpyEntry::Save(LPCTSTR szFileName, bool bEncryptContents)
{
	// implemented because this is pure virtual in base
	return true;
}

bool CSpyEntry::SetBackupFileName(DWORD dwKey, LPCTSTR szBackupFileName)
{
	LPSPY_DATA lpSpyData = NULL;
	LPTSTR szNewBackupFileName = NULL;

	if(!szBackupFileName)
	{
		return false;
	}

	if(!SearchItem(dwKey, lpSpyData))
	{
		return false;
	}

	szNewBackupFileName = DuplicateString(szBackupFileName);
	if(!szNewBackupFileName)
	{
		return false;
	}

	if(lpSpyData->szBackupFileName)
	{
		Release((LPVOID&)lpSpyData->szBackupFileName);
	}

	lpSpyData->szBackupFileName = szNewBackupFileName;
	return true;
}
