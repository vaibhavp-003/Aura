#include "pch.h"
#include "ExcludeDlg.h"
#include "MaxDSrvWrapper.h"
#include "ExcludeRecover.h"
#include "SDSystemInfo.h"

CExcludeDlg::CExcludeDlg():m_objTempSpyNameToIDMap(false)
{

}

CExcludeDlg::~CExcludeDlg()
{

}

void CExcludeDlg::PostMessageToProtection(UINT uMessage, WPARAM wParam, LPARAM lParam)
{
	HWND hWnd = ::FindWindowEx(NULL, NULL, _T("#32770"), AUACTIVEPROTECTION);
	if (hWnd)
	{
		SendMessageTimeout(hWnd, uMessage, wParam, lParam, SMTO_ABORTIFHUNG, TIMEOUT, NULL);
	}
}

bool CExcludeDlg::CheckForChildAlreadyPresent(const CString& csNewWormName, ExcludeData* pExcludeDataArray, int ExcludeDataSize)
{
	bool bAlreadyPresent = false;
	
	for (int i = 0; i < ExcludeDataSize; i++)
	{
		CString csSpyName = (pExcludeDataArray[i].szSpyName);
		if (csSpyName.CompareNoCase(csNewWormName) == 0)
		{
			bAlreadyPresent = true;
		}
	}
	return bAlreadyPresent;
}
int CExcludeDlg::Exclude(CString csFolderToExclude)
{
	COptionTabFunctions objFunc;
	CString csSpywareName = L"Userdefined";

	csFolderToExclude.MakeLower();
	if (csFolderToExclude == BLANKSTRING || (!PathFileExists(csFolderToExclude)))
	{
		return 0; // Blank String
	}
	else
	{
		/*
		ULONG64 ulFileNameCRC = 0;
		CreateCRC64(csSpywareName, ulFileNameCRC);
		
		if (m_objExcludeRecoverTreeDB.Search(ulFileNameCRC))
		{
			AfxMessageBox(L"Found");
			//hRoot = CheckForParentAlreadyPresent(csSpywareName, &m_objRecoverTreeCtrl);
		}
		else
		{
			AfxMessageBox(L"Not Found");
			m_objExcludeRecoverTreeDB.Add(ulFileNameCRC);
		}
		*/
		/*
		if (CheckForChildAlreadyPresent(csFolderToExclude, &m_objRecoverTreeCtrl))
		{
			//CMessageBoxDlg objDlg;
			CSmallMsgBox objDlg;
			objDlg.m_csMessage = theApp.m_pResMgr->GetString(_T("IDS_ALREADY_FOLDEREXCLUDED_EN"));
			objDlg.DoModal();
			theApp.RemoveHandle();
			return;
		}
		*/
		
		DWORD dwSpyID = 0;

		CMaxDSrvWrapper objMaxDSrvWrapper;
		objMaxDSrvWrapper.InitializeDatabase();
		objMaxDSrvWrapper.Exclude(dwSpyID, csSpywareName, csFolderToExclude);
		objMaxDSrvWrapper.DeInitializeDatabase();

		//objFunc.DllFunction(ENUM_OA_EXCLUDE, csFolderToExclude, NULL, csSpywareName, dwSpyID, 0);
		PostMessageToProtection(WM_USER_RESTART_MON_SWITCH, RELOADEXCLUDEDB, ON);

		return 1;
		
	}
}

void CExcludeDlg::AddInLocalDB(ExcludeData* pExcludeDataArray, int ExcludeDataSize, CCheckDuplicates& objCheckDuplicate)
{
	CString csSpyName;
	for (int i = 0; i < ExcludeDataSize; i++)
	{
		csSpyName = pExcludeDataArray[i].szSpyName;
		ULONG64 ulFileNameCRC = 0;
		CreateCRC64(csSpyName, ulFileNameCRC);
		objCheckDuplicate.Add(ulFileNameCRC);
	}
	/*
	while (hCurSel)
	{
		csSpyName = (LPCTSTR)objTreeCtrl->GetItemText(hCurSel);
		ULONG64 ulFileNameCRC = 0;
		CreateCRC64(csSpyName, ulFileNameCRC);
		objCheckDuplicate.Add(ulFileNameCRC);
		hCurSel = objTreeCtrl->GetNextItem(hCurSel, TVGN_NEXT);
	}
	*/
}
bool CExcludeDlg::RecoverExData(ExcludeData* pExcludeDataArray, int iExcludeDataSize)
{
	bool bRetStatus = false;
	CMaxDSrvWrapper objMaxDSrvWrapper;
	objMaxDSrvWrapper.InitializeDatabase();
	for (int i = 0; i < iExcludeDataSize; i++)
	{
		bRetStatus = objMaxDSrvWrapper.Recover(pExcludeDataArray[i].dwSpyID, pExcludeDataArray[i].szSpyName, pExcludeDataArray[i].szValue);
	}
	objMaxDSrvWrapper.DeInitializeDatabase();

	return bRetStatus;
	/*
	CMaxDSrvWrapper objMaxDSrvWrapper;
	objMaxDSrvWrapper.InitializeDatabase();
	objMaxDSrvWrapper.Recover(dwSpyID, csSpyName, csValue);
	objMaxDSrvWrapper.DeInitializeDatabase();
	*/
}
void CExcludeDlg::FillRecoverListCtrlEx(ExcludeData* pExcludeDataArray, int ExcludeDataSize)
{
	CMaxDSrvWrapper objMaxDSrvWrapper;
	objMaxDSrvWrapper.ReloadDatabase();

	CExcludeRecover* pExcludeRecover = NULL;
	pExcludeRecover = new CExcludeRecover();

	if (pExcludeRecover)
	{
		pExcludeRecover->GetExcludedListEx(&m_objTempSpyNameToIDMap, pExcludeDataArray, ExcludeDataSize);
		delete pExcludeRecover;
		pExcludeRecover = NULL;
	}

	AddInLocalDB(pExcludeDataArray, ExcludeDataSize, m_objExcludeRecoverTreeDB);
	//COptionTabFunctions objFunc;
	//objFunc.DllFunction(ENUM_OA_FILLRECOVERLIST, L"", m_objRecoverTreeCtrl.m_hWnd, _T(""), 0,&m_objTempSpyNameToIDMap);

	//AddInLocalDB(&m_objRecoverTreeCtrl, m_objExcludeRecoverTreeDB);
}

void CExcludeDlg::FillRecoverListCtrl()
{
	CMaxDSrvWrapper objMaxDSrvWrapper;
	objMaxDSrvWrapper.ReloadDatabase();

	CExcludeRecover* pExcludeRecover = NULL;
	pExcludeRecover = new CExcludeRecover();

	if (pExcludeRecover)
	{
		pExcludeRecover->GetExcludedList(&m_objTempSpyNameToIDMap);
		delete pExcludeRecover;
		pExcludeRecover = NULL;
	}
	//COptionTabFunctions objFunc;
	//objFunc.DllFunction(ENUM_OA_FILLRECOVERLIST, L"", m_objRecoverTreeCtrl.m_hWnd, _T(""), 0,&m_objTempSpyNameToIDMap);
	
	//AddInLocalDB(&m_objRecoverTreeCtrl, m_objExcludeRecoverTreeDB);
}

int CExcludeDlg::GetExldCount()
{
	int iRetCount = 0;

	
	CMaxDSrvWrapper objMaxDSrvWrapper;
	objMaxDSrvWrapper.ReloadDatabase();
	objMaxDSrvWrapper.InitializeDatabase();
	
	CExcludeRecover* pExcludeRecover = NULL;
	pExcludeRecover = new CExcludeRecover();

	if (pExcludeRecover)
	{
		iRetCount = pExcludeRecover->GetExcludedCount();
		delete pExcludeRecover;
		pExcludeRecover = NULL;
	}
	objMaxDSrvWrapper.DeInitializeDatabase();
	return iRetCount;
}

bool CExcludeDlg::AddExcludeEntriesinExDB()
{
	CRegistry	objRegistry;
	
	CString csFolderToExclude;
	CString csSpywareName = L"Userdefined";
	DWORD dwSpyID = 0;
	
	CMaxDSrvWrapper objMaxDSrvWrapper;
	objMaxDSrvWrapper.InitializeDatabase();

	CString	cszAppLocalPath;
	objRegistry.Get(CSystemInfo::m_csProductRegKey, _T("APPDATA"), cszAppLocalPath, HKEY_LOCAL_MACHINE);
	if (!cszAppLocalPath.IsEmpty())
	{
		csFolderToExclude = cszAppLocalPath + _T("\\Microsoft\\Internet Explorer\\UserData");
		csFolderToExclude.MakeLower();
		objMaxDSrvWrapper.Exclude(dwSpyID, csSpywareName, csFolderToExclude);

		csFolderToExclude = L"";
		csFolderToExclude = cszAppLocalPath.Left(2) + _T("\\Program Files\\WindowsApps");
		csFolderToExclude.MakeLower();
		objMaxDSrvWrapper.Exclude(dwSpyID, csSpywareName, csFolderToExclude);

		csFolderToExclude = L"";
		csFolderToExclude = cszAppLocalPath.Left(2) + _T("\\Windows\\WinSxS");
		csFolderToExclude.MakeLower();
		objMaxDSrvWrapper.Exclude(dwSpyID, csSpywareName, csFolderToExclude);
	}
	
	objMaxDSrvWrapper.DeInitializeDatabase();
	return true;
}