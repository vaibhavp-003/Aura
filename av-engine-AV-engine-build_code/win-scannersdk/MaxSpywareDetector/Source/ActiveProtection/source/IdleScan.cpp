#include "pch.h"
#include "IdleScan.h"
#include "Registry.h"
#include "SDSystemInfo.h"
#include "ProcessMonitor.h"
#include "ActiveProtection.h"
#include "RegistryHelper.h"
#include "RegPathExpander.h"

const int EXTENSION_FOR_QUICK_SCAN = 14;
WCHAR ValidExtension[EXTENSION_FOR_QUICK_SCAN][5] =
{
	{L".EXE"}, {L".TMP"}, {L".DLL"}, {L".OCX"}, {L".SYS"}, 
	{L".COM"}, {L".DOC"}, {L".XLS"}, {L".XLT"}, {L".PPT"}, 
	{L".MP3"}, {L".WMA"}, {L".CPL"}, {L".SCR"}
};

/*--------------------------------------------------------------------------------------
Function       : CIdleScan::CIdleScan
In Parameters  : void,
Out Parameters :
Description    :
Author & Date  : Siddharam Pujari & 18-Oct-2012.
--------------------------------------------------------------------------------------*/
CIdleScan::CIdleScan():m_bStopScanning(false)
{

}

/*--------------------------------------------------------------------------------------
Function       : ~CIdleScan
In Parameters  : void,
Out Parameters :
Description    :
Author & Date  : Siddharam Pujari & 18-Oct-2012.
--------------------------------------------------------------------------------------*/
CIdleScan::~CIdleScan()
{

}

/*--------------------------------------------------------------------------------------
Function       : IsValidExtension
In Parameters  : WCHAR *cFileName, 
Out Parameters : int nt 
Description    : 
Author         : Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
int IsValidExtension(WCHAR *cFileName)
{
	return 0;
	//WCHAR *ExtPtr;
	//INT i;

	//ExtPtr = wcsrchr(cFileName, '.');
	//if(ExtPtr != NULL)
	//{
	//	for(i = 0; i < EXTENSION_FOR_QUICK_SCAN; i++)
	//	{
	//		if(_wcsicmp(ExtPtr, ValidExtension[i])== 0)
	//			return i;
	//	}
	//}
	//return -1;
}

/*--------------------------------------------------------------------------------------
Function       : AppendString
In Parameters  : LPTSTR szFinal, DWORD cchFinal, LPCTSTR szAppend
Out Parameters : bool
Description    : concatenate strings but return false if dest smaller
Author & Date  : Anand Srivastava & 22 July, 2011.
--------------------------------------------------------------------------------------*/
bool AppendString(LPTSTR szFinal, DWORD cchFinal, LPCTSTR szAppend)
{
	if(_tcslen(szFinal) + _tcslen(szAppend) >= cchFinal)
	{
		return false;
	}

	_tcscat_s(szFinal, cchFinal, szAppend);
	return true;
}

/*--------------------------------------------------------------------------------------
Function       : JoinStrings
In Parameters  : LPTSTR szFinal, DWORD cchFinal, LPCTSTR szFormat, ...
Out Parameters : bool
Description    : join strings but return false if dest smaller
Author & Date  : Anand Srivastava & 22 July, 2011.
--------------------------------------------------------------------------------------*/
bool JoinStrings(LPTSTR szFinal, DWORD cchFinal, LPCTSTR szFormat, ...)
{
	va_list Arguments_List;
	DWORD dwReqLen = 0;

	va_start(Arguments_List, szFormat);
	dwReqLen = _vsctprintf(szFormat, Arguments_List);
	if(dwReqLen >= cchFinal)
	{
		return false;
	}

	memset(szFinal, 0, cchFinal * sizeof(TCHAR));
	_vstprintf_s(szFinal, cchFinal, szFormat, Arguments_List);
	va_end(Arguments_List);
	return true;
}

/*--------------------------------------------------------------------------------------
Function       : CIdleScan::EnumFolder
In Parameters  : const TCHAR *cFolderPath, bool bCheckCookies,
Out Parameters : void
Description    :
Author & Date  : Siddharam Pujari & 18-Oct-2012.
--------------------------------------------------------------------------------------*/
void CIdleScan::EnumFolder(const TCHAR *cFolderPath, bool bEnumSubFolders, bool bSkipFolder)
{
	bool bFile = false;
	bool bSkipFile = bSkipFolder? false : true;
	HANDLE hFindFile = INVALID_HANDLE_VALUE;
	WIN32_FIND_DATA FindFileData = {0};
	TCHAR *cFullPath = NULL;
	if(!bEnumSubFolders)
	{
		bSkipFile = false;
		bSkipFolder = false;
	}

	//if(theApp.m_pMaxScanner)
	//{
	//	if(theApp.m_pMaxScanner->IsExcluded(0, 0, cFolderPath))
	//	{
	//		AddLogEntry(L"Exl folder: %s", cFolderPath);
	//		return;
	//	}
	//}

	cFullPath = new TCHAR[MAX_PATH];
	if(!cFullPath)
	{
		return;
	}

	if(!JoinStrings(cFullPath, MAX_PATH, _T("%s"), cFolderPath, NULL))
	{
		AddLogEntry(L"Skipping long folder: %s", cFolderPath);
		delete [] cFullPath;
		return;
	}

	if(cFullPath[wcslen(cFullPath) - 1] == '\\') // remove \\ 
	{
		cFullPath[wcslen(cFullPath) - 1] = 0;
	}

	hFindFile = FindFirstFile(cFullPath, &FindFileData);
	if(INVALID_HANDLE_VALUE != hFindFile)
	{
		if((FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)!= FILE_ATTRIBUTE_DIRECTORY)
		{
			bFile = true;
		}

		FindClose(hFindFile);
	}

	if(bFile == false)
	{
		/*if(!pdwTotalNoOfFilesToScan)
		{
			MAX_SCANNER_INFO oScannerInfo = {0};
			oScannerInfo.eScannerType = Scanner_Type_Max_SignatureScan;
			_tcscpy_s(oScannerInfo.szFileToScan, cFullPath);
			m_pMaxScanner->ScanAlternateDataStream(&oScannerInfo);
			if((oScannerInfo.ThreatDetected == 1) || (oScannerInfo.ThreatSuspicious == 1))
			{
				SendScanStatusToUI(&oScannerInfo);
			}
		}*/
		if(!AppendString(cFullPath, MAX_PATH, L"\\*.*"))
		{
			delete [] cFullPath;
			return;
		}
	}

	hFindFile = FindFirstFile(cFullPath, &FindFileData);
	if(INVALID_HANDLE_VALUE != hFindFile)
	{
		do
		{
			if((FindFileData.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)== FILE_ATTRIBUTE_REPARSE_POINT)
			{
				continue;
			}

			if(bFile == false)
			{
				if(!JoinStrings(cFullPath, MAX_PATH, _T("%s%s"), cFolderPath, FindFileData.cFileName, NULL))
				{
					AddLogEntry(L"Skipping long file: %s", FindFileData.cFileName);
					AddLogEntry(L"In this folder: %s", cFolderPath);
					continue;
				}
			}

			_wcslwr_s(cFullPath, MAX_PATH);
			if((FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)== FILE_ATTRIBUTE_DIRECTORY && !bSkipFolder)
			{
				if(bEnumSubFolders)
				{
					if(wcscmp(FindFileData.cFileName, L"") == 0)
					{
						AddLogEntry (L"Blank Folder For Scanning So Break");
						break;
					}

					if((wcscmp(FindFileData.cFileName, L".") != 0) && (wcscmp(FindFileData.cFileName, L"..") != 0) &&
					   (_wcsicmp(FindFileData.cFileName, L"System Volume Information") != 0))
					{
						if(AppendString(cFullPath, MAX_PATH, L"\\"))
						{
							bool bIgnoreFolder = false;
							//if(!pdwTotalNoOfFilesToScan)
							{
								//WaitForSingleObject(m_bStatusVariableLock, INFINITE);
								//m_csCurrentFileName = cFullPath;
								//m_csCurrentFileName.MakeLower();
								//if(m_csCurrentFileName.Left(m_csIgnoreFolder.GetLength()) == m_csIgnoreFolder)
								//	bIgnoreFolder = true;
								//SetEvent(m_bStatusVariableLock);
							}
							if(bIgnoreFolder)
							{
								//AddLogEntry(L"Ignored Folder from scan: %s, %s", m_csCurrentFileName, m_csIgnoreFolder);
							}
							else
							{
								//AddLogEntry(L"$$$$$$ SUB Folder: %s", cFullPath);
								EnumFolder(cFullPath);
							}
						}
					}
				}
			}
			else
			{
				if(!bSkipFile)
				{
					ULONGLONG ulFileSize = (FindFileData.nFileSizeHigh * (((ULONGLONG)MAXDWORD) +1)) + FindFileData.nFileSizeLow;
					if(ulFileSize != 0)
					{
						//WaitForSingleObject(m_bStatusVariableLock, INFINITE);
						//m_csCurrentFileName = cFullPath;
						//m_csCurrentFileName.MakeLower();
						//SetEvent(m_bStatusVariableLock);
						int iExecutableType = IsValidExtension(FindFileData.cFileName);
						if(((iExecutableType != -1) && (iExecutableType >= 0)))
						{
							MAX_SCANNER_INFO oScannerInfo = {0};
							if(JoinStrings(oScannerInfo.szFileToScan, _countof(oScannerInfo.szFileToScan), L"%s", cFullPath, NULL))
							{
								//AddLogEntry(L"******** File For Scan: %s", cFullPath);
								oScannerInfo.eScannerType = Scanner_Type_Max_SignatureScan;
								bool bStopEnum = false;
								m_pProcessMonitor->CheckProcess(&oScannerInfo, CALL_TYPE_F_EXECUTE, bStopEnum);
							}
							else
							{
								AddLogEntry(L"Skipped file from scan: %s", cFullPath);
							}
						}	
					}
				}
			}
		}while((!m_bStopScanning) && (FindNextFile(hFindFile, &FindFileData)));
		FindClose(hFindFile);
	}

	delete [] cFullPath;
	if(bSkipFolder)
	{
		EnumFolder(cFolderPath, true, false);
	}

	return;
}

CString CIdleScan::EnumerateAllDrives()
{
	CRegistry oRegistry;
	CString csAllDrives = L"";
	oRegistry.Get(CSystemInfo::m_csProductRegKey, AllDRIVEKEY, csAllDrives, HKEY_LOCAL_MACHINE);
	return csAllDrives;
}

void CIdleScan::StartIdleScan()
{
	CRegistry oRegistry;
	DWORD dwValue = 0;
	oRegistry.Get(CSystemInfo::m_csProductRegKey, L"FullIdleScan", dwValue, HKEY_LOCAL_MACHINE);
	if(dwValue)
	{
		COleDateTime objOleDateTime;
		objOleDateTime = objOleDateTime.GetCurrentTime();
		CString csDate;
		CString csRegistryDate;
		csDate.Format (_T("%d/%d/%d"), objOleDateTime.GetMonth(),objOleDateTime.GetDay(),objOleDateTime.GetYear());
		oRegistry.Get(CSystemInfo::m_csProductRegKey, L"FullIdleScanTime", csRegistryDate, HKEY_LOCAL_MACHINE);

		if(csRegistryDate == csDate)
		{
			return;
		}
		else
		{
			dwValue = 0;
			oRegistry.Set(CSystemInfo::m_csProductRegKey, L"FullIdleScan", dwValue, HKEY_LOCAL_MACHINE);
		}
	}

	//Sleep(900000);
	AddLogEntry(L"Starting Idle Scan");
	//CString csAllDrives = EnumerateAllDrives();
	//if(csAllDrives.GetLength() > 0)
	{
		/*int iPos = 0;
		CString csToken = csAllDrives.Tokenize(L"|", iPos);
		while(csToken.GetLength() > 0)
		{
		csToken += L"\\";
		EnumFolder(csToken);
		csToken = csAllDrives.Tokenize(L"|", iPos);
		}*/

		CDBPathExpander m_oDBPathExpander;
		CRegistryHelper m_objRegHelper;
		CS2S				m_objAvailableUsers(false);

		TCHAR chDriveToScan[3] = {0};
		chDriveToScan[0] = m_oDBPathExpander.GetOSDriveLetter();
		chDriveToScan[1] = ':';

		m_objRegHelper.LoadAvailableUsers(m_objAvailableUsers);

		LPVOID posUserName = m_objAvailableUsers.GetFirst();
		while((!m_bStopScanning) && (posUserName))
		{
			CString csPathToScan;
			LPTSTR strUserName = NULL;
			m_objAvailableUsers.GetData(posUserName, strUserName);

			csPathToScan = m_oDBPathExpander.m_cs512;			//Desktop Recursive Scan
			csPathToScan.Replace(L"<user>", strUserName);
			EnumFolder(csPathToScan, true);

			csPathToScan = m_oDBPathExpander.m_cs503;			//AppData Main Folder Scan
			csPathToScan.Replace(L"<user>", strUserName);
			EnumFolder(csPathToScan, false, false);

			csPathToScan = m_oDBPathExpander.m_cs509;			//Common AppData Main Folder Scan
			csPathToScan.Replace(L"<user>", strUserName);
			EnumFolder(csPathToScan, false, false);
			posUserName = m_objAvailableUsers.GetNext(posUserName);
		}

		if(!m_bStopScanning)
		{
			EnumFolder(m_oDBPathExpander.m_cs543, false, false);	// Root Drive
			EnumFolder(m_oDBPathExpander.m_cs542, false, false);	// Windows
			EnumFolder(m_oDBPathExpander.m_cs531, false, false);	// System32
			EnumFolder(m_oDBPathExpander.m_cs529, false, false);	// Drivers
			EnumFolder(m_oDBPathExpander.m_cs528, false, false);	// Program Files
		}

		if(!m_bStopScanning)
		{
			DWORD dwValue = 1;
			oRegistry.Set(CSystemInfo::m_csProductRegKey, L"FullIdleScan", dwValue, HKEY_LOCAL_MACHINE);

			COleDateTime objOleDateTime;
			objOleDateTime = objOleDateTime.GetCurrentTime();
			CString csDate;
			csDate.Format (_T("%d/%d/%d"), objOleDateTime.GetMonth(),objOleDateTime.GetDay(),objOleDateTime.GetYear());
			oRegistry.Set(CSystemInfo::m_csProductRegKey, L"FullIdleScanTime", csDate, HKEY_LOCAL_MACHINE);
		}
	}
}

void CIdleScan::SetProcessMonitorPointer(LPVOID lpThis)
{
	CProcessMonitor *pThis = (CProcessMonitor*)lpThis;
	if(pThis)
	{
		m_pProcessMonitor = pThis;
	}
}

void CIdleScan::StopIdleScan()
{
	m_bStopScanning = true;
}
