#include "pch.h"
#include "ScanByName.h"
#include "MaxDSrvWrapper.h"
#include "MaxPipes.h"
#include "BKComDll.h"



CScanByName::CScanByName()
{
	m_pFileSig = new CFileSig;
}


CScanByName::~CScanByName()
{

}


void CScanByName::ScanByNameCount(int iScanByNameArrayLen, int* ptrScanByNameCountArray)
{
	m_csINIFileName = CSystemInfo::m_strAppPath + _T("Setting\\InstantScan.ini");
	if (_waccess_s(m_csINIFileName, 0) != 0)
	{
		return;
	}
	UINT ulNoOfFileEntries = GetPrivateProfileIntW(_T("FileList"), _T("NoOfEntries"), 0, m_csINIFileName);
	UINT ulNoOfSigEntries = GetPrivateProfileInt(_T("Signature"), _T("Count"), 0, m_csINIFileName);

	ptrScanByNameCountArray[0] = ulNoOfFileEntries - 17;
	ptrScanByNameCountArray[1] = ulNoOfSigEntries;
}


void CScanByName::GetScanByNameData(ScanByNameFiles* pScnByNameDataArray, int iScanByNameDataSize)
{
	csScanByNameArray.RemoveAll();
	csScanByNameWormArray.RemoveAll();
	UINT ulNoOfEntries = GetPrivateProfileIntW(_T("FileList"), _T("NoOfEntries"), 0, m_csINIFileName);
	WCHAR lpstrFileToScan[MAX_PATH] = { 0 };
	int iCounter = 0;
	for (UINT iCtr = 1; iCtr <= ulNoOfEntries; iCtr++)
	{

		CString csEntry;
		csEntry.Format(_T("%d"), iCtr);
		GetPrivateProfileStringW(_T("FileList"), csEntry, 0, lpstrFileToScan, MAX_PATH, m_csINIFileName);
		_tcslwr_s(lpstrFileToScan);
		if (iCtr <= 17)
		{
			csScanByNameWormArray.Add(lpstrFileToScan);
			continue;
		}
		
		wcscpy_s(pScnByNameDataArray[iCounter].szFilePath, lpstrFileToScan);
		csScanByNameArray.Add(lpstrFileToScan);
		iCounter++;

		//m_lstScanByNameEntries.InsertItem(iCtr, lpstrFileToScan);
	}

	ulNoOfEntries = GetPrivateProfileInt(_T("Signature"), _T("Count"), 0, m_csINIFileName);
	for (UINT iCtr = 1; iCtr <= ulNoOfEntries; iCtr++)
	{
		CString csEntry;

		csEntry.Format(_T("%d"), iCtr);
		wmemset(lpstrFileToScan, 0, MAX_PATH);
		GetPrivateProfileString(_T("Signature"), csEntry, 0, lpstrFileToScan, MAX_PATH, m_csINIFileName);
		_tcslwr_s(lpstrFileToScan);

		wcscpy_s(pScnByNameDataArray[iCounter].szFilePath, lpstrFileToScan);
		csScanByNameArray.Add(lpstrFileToScan);
		iCounter++;
		//m_lstScanByNameEntries.InsertItem(iCtr, lpstrFileToScan);
	}
}

void CScanByName::AddScanByNameData(ScanByNameFiles* pScnByNameDataArray, int iScanByNameDataSize)
{
	TCHAR szSigPlusFilePath[MAX_PATH] = { 0 };
	bool bDuplicate = false;
	UINT iCnt = 0;
	TCHAR strKey[MAX_PATH] = { 0 };
	for (int i = 0; i < iScanByNameDataSize; i++)
	{
		CString csFilePathName = pScnByNameDataArray[i].szFilePath;
		if (PathFileExists(csFilePathName))
		{
			UINT iCount = 0;
			TCHAR szCount[20] = { 0 };
			ULONG64 ulSignature = 0;

			if (m_pFileSig && SIG_STATUS_PE_SUCCESS == m_pFileSig->CreateSignature(csFilePathName, ulSignature))
			{
				if (_tcslen(csFilePathName) + 1 < _countof(szSigPlusFilePath))
				{
					iCount = GetPrivateProfileInt(_T("Signature"), _T("Count"), 0, m_csINIFileName);
					iCount++;
					_stprintf_s(szCount, _countof(szCount), _T("%u"), iCount);
					WritePrivateProfileString(_T("Signature"), _T("Count"), szCount, m_csINIFileName);
					_stprintf_s(szSigPlusFilePath, _countof(szSigPlusFilePath), _T("%016I64X*%s"), ulSignature, csFilePathName);
					WritePrivateProfileString(_T("Signature"), szCount, szSigPlusFilePath, m_csINIFileName);
				}
			}
		}

		for (int iCount = 0; iCount < csScanByNameArray.GetCount(); iCount++)
		{
			CString csFile = csScanByNameArray.GetAt(iCount);
			if (!csFile.CompareNoCase(csFilePathName))
			{
				bDuplicate = true;
			}
		}

		if(bDuplicate == false)
		{
			iCnt = GetPrivateProfileInt(_T("FileList"), _T("NoOfEntries"), 0, m_csINIFileName);
			iCnt++;
			wsprintf(strKey, _T("%d"), iCnt);
			WritePrivateProfileString(_T("FileList"), strKey, csFilePathName, m_csINIFileName);
			WritePrivateProfileString(_T("FileList"), _T("NoOfEntries"), strKey, m_csINIFileName);
			RemoveEntryFromLocalDB(csFilePathName);
		}

		
		
		
	}
}

void CScanByName::RemoveEntryFromLocalDB(LPCTSTR pszFilePath)
{
	MAX_PIPE_DATA_REG sRequest = { 0 };
	sRequest.eMessageInfo = ChangeFilesLocalDBValue;
	wcscpy_s(sRequest.strValue, pszFilePath);
	CMaxCommunicator objMaxCommunicator(_NAMED_PIPE_UI_TO_SERVICE, false);
	objMaxCommunicator.SendData(&sRequest, sizeof(MAX_PIPE_DATA_REG));
}

void CScanByName::OnClickApply()
{
	CRegistry objReg;
	DWORD dwValProcMon = 0;
	DWORD dwValActProc = 0;
	objReg.Get(CSystemInfo::m_csActMonRegKey, L"ProcessMonitor", dwValProcMon, HKEY_LOCAL_MACHINE);
	objReg.Get(CSystemInfo::m_csProductRegKey, L"bActiveProtection", dwValActProc, HKEY_LOCAL_MACHINE);
	Sleep(2000);
	if (dwValProcMon && !dwValActProc)	// reload active monitor
	{
		theApp.m_objPipeCom.PostMessageToProtection(SETPROCESS, OFF);
		Sleep(2000);
		theApp.m_objPipeCom.PostMessageToProtection(SETPROCESS, ON);
	}
}

void CScanByName::CreateWormstoDeleteINI(CString strINIPath)
{
	if (_waccess_s(strINIPath, 0) != 0)
	{
		// UTF16-LE BOM(FFFE)
		WORD wBOM = 0xFEFF;
		DWORD NumberOfBytesWritten;
		HANDLE hFile = ::CreateFile(strINIPath, GENERIC_WRITE, 0, NULL, CREATE_NEW,
			FILE_ATTRIBUTE_NORMAL, NULL);
		::WriteFile(hFile, &wBOM, sizeof(WORD), &NumberOfBytesWritten, NULL);
		::CloseHandle(hFile);
		WritePrivateProfileStringW(L"FileList", L"NoOfEntries", L"0", strINIPath);
		WritePrivateProfileStringW(L"Signature", L"Count", L"0", strINIPath);
	}
}

void CScanByName::OnClickRemove(ScanByNameFiles* pScnByNameDataArray, int iScanByNameDataSize)
{
	CString csReadString;
	UINT iCnt = 0;
	TCHAR strKey[MAX_PATH] = { 0 };
	bool bIsRemoved = false;
	//bool bFoundRemove = false;
	
	for (int i = 0; i < iScanByNameDataSize; i++)
	{
		DeleteFile(m_csINIFileName);
		CreateWormstoDeleteINI(m_csINIFileName);
		bIsRemoved = true;
	}

	int iLen = csScanByNameArray.GetCount();

	if (bIsRemoved)
	{
		for (int iCount = 0; iCount < csScanByNameWormArray.GetCount(); iCount++)
		{
			csReadString = csScanByNameWormArray.GetAt(iCount);
			iCnt = GetPrivateProfileInt(_T("FileList"), _T("NoOfEntries"), 0, m_csINIFileName);
			iCnt++;
			wsprintf(strKey, _T("%d"), iCnt);

			WritePrivateProfileString(_T("FileList"), strKey, csReadString, m_csINIFileName);
			WritePrivateProfileString(_T("FileList"), _T("NoOfEntries"), strKey, m_csINIFileName);
		}
		/*
		for (int iCount = 0; iCount < iLen; iCount++)
		{
			csReadString = csScanByNameArray.GetAt(iCount);

			for (int i = 0; i < iScanByNameDataSize; i++)
			{
				CString csFile = pScnByNameDataArray[i].szFilePath;
				if (!csReadString.CompareNoCase(csFile))
				{
					csScanByNameArray.RemoveAt(i);
					iLen = csScanByNameArray.GetCount();
				}
			}
		}
		*/

		int iCount = 0;
		int iDone = 0;
		int iWCnt = 0;
		bool bMatch = false;
		while (iCount < iLen)
		{
			csReadString = csScanByNameArray.GetAt(iCount);
			iWCnt = 0;
			bMatch = false;
			while (iWCnt < iScanByNameDataSize && iDone < iScanByNameDataSize)
			{
				CString csFile = pScnByNameDataArray[iWCnt].szFilePath;
				if (csReadString.CompareNoCase(csFile) == 0)
				{
					iDone++;
					csScanByNameArray.RemoveAt(iCount);
					iLen--;
					bMatch = true;;
					break;
				}
				iWCnt++;
			}
			if (iDone >= iScanByNameDataSize)
			{
				break;
			}
			if (bMatch == false)
			{
				iCount++;
			}			
		}
		
		

		for (int iCount = 0; iCount < csScanByNameArray.GetCount(); iCount++)
		{
			csReadString = csScanByNameArray.GetAt(iCount);
			if (_tcsrchr(csReadString, _T('*')))
			{
				iCnt = GetPrivateProfileInt(_T("Signature"), _T("Count"), 0, m_csINIFileName);
				iCnt++;
				wsprintf(strKey, _T("%d"), iCnt);

				WritePrivateProfileString(_T("Signature"), strKey, csReadString, m_csINIFileName);
				WritePrivateProfileString(_T("Signature"), _T("Count"), strKey, m_csINIFileName);
			}
			else
			{
				iCnt = GetPrivateProfileInt(_T("FileList"), _T("NoOfEntries"), 0, m_csINIFileName);
				iCnt++;
				wsprintf(strKey, _T("%d"), iCnt);

				WritePrivateProfileString(_T("FileList"), strKey, csReadString, m_csINIFileName);
				WritePrivateProfileString(_T("FileList"), _T("NoOfEntries"), strKey, m_csINIFileName);
			}
		}
	}	
}