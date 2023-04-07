#pragma once
#include "pch.h"
#include "OptionTabFunctions.h"
#include "CheckDuplicates.h"

typedef struct _ExcludeData
{
	DWORD		dwSpyID;
	wchar_t		szSpyName[MAX_PATH];
	wchar_t		szValue[MAX_PATH];

} ExcludeData;


class CExcludeDlg
{
public:
	CExcludeDlg();
	~CExcludeDlg();

public:
	int Exclude(CString csFolderToExclude);
	void PostMessageToProtection(UINT uMessage, WPARAM wParam, LPARAM lParam);

	void FillRecoverListCtrl();

	void FillRecoverListCtrlEx(ExcludeData* pExcludeDataArray, int iExcludeDataSize);
	bool RecoverExData(ExcludeData* pExcludeDataArray, int iExcludeDataSize);
	int  GetExldCount();
	bool AddExcludeEntriesinExDB();

	void AddInLocalDB(ExcludeData* pExcludeDataArray, int ExcludeDataSize, CCheckDuplicates& objCheckDuplicate);
	bool CExcludeDlg::CheckForChildAlreadyPresent(const CString& csNewWormName, ExcludeData* pExcludeDataArray, int ExcludeDataSize);
private:
	CCheckDuplicates m_objExcludeRecoverTreeDB;
	CS2U m_objTempSpyNameToIDMap;
	
};