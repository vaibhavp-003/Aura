#include "pch.h"
#include "ExtensionList.h"

/*-------------------------------------------------------------------------------------
Function		: CExtensionList
In Parameters	: -
Out Parameters	: -
Purpose			: Constructor for class CExtensionList
Author			: Swapnil Sanghai
--------------------------------------------------------------------------------------*/
CExtensionList::CExtensionList():m_objDBAppExtList(false)
{
	m_objDBAppExtList.RemoveAll();

}

/*-------------------------------------------------------------------------------------
Function		: CExtensionList
In Parameters	: -
Out Parameters	: -
Purpose			: Destructor for class CExtensionList
Author			: Swapnil Sanghai
--------------------------------------------------------------------------------------*/
CExtensionList::~CExtensionList()
{

}

/*-------------------------------------------------------------------------------------
Function		: OnClickedApply
In Parameters	: -
Out Parameters	: -
Purpose			: Add extension to AppExcludeFileExtList.DB
Author			: Swapnil Sanghai
--------------------------------------------------------------------------------------*/
void CExtensionList::OnClickedApply(int iListSize, wchar_t** csExtensionList)
{
	m_objDBAppExtList.RemoveAll();
	for (int iNoofEntries = 0; iNoofEntries < iListSize; iNoofEntries++)
	{
		OutputDebugString(csExtensionList[iNoofEntries]);
		m_objDBAppExtList.AppendItem(CString(csExtensionList[iNoofEntries]), _T("ext"));
	}
	CString csAppPath = CSystemInfo::m_strAppPath;
	CString csApplicationPath = csAppPath + _T("Tools\\");

	m_objDBAppExtList.Save(csApplicationPath + APP_EXCLUDE_FILEEXTLIST_DB);
}

int CExtensionList::GetExtensionCnt()
{
	m_objDBAppExtList.RemoveAll();

	CString csAppPath = CSystemInfo::m_strAppPath;
	CString csApplicationPath = csAppPath + _T("Tools\\");

	int iCount = 0;

	if (m_objDBAppExtList.Load(csApplicationPath + APP_EXCLUDE_FILEEXTLIST_DB) == true)
	{
		LPVOID lpVoid = m_objDBAppExtList.GetFirst();
		while (lpVoid)
		{
			CString csPath;
			LPTSTR strKey = NULL;
			m_objDBAppExtList.GetKey(lpVoid, strKey);
			csPath = strKey; //GetSpyName(ulSpyName);
			lpVoid = m_objDBAppExtList.GetNext(lpVoid);
			iCount++;
		}
	}
	return iCount;
}

int CExtensionList::FillExtensionArray(ExludeExtensions* pExtensionArray, int size)
{
	m_objDBAppExtList.RemoveAll();

	CString csAppPath = CSystemInfo::m_strAppPath;
	CString csApplicationPath = csAppPath + _T("Tools\\");

	int iCount = 0;

	if (m_objDBAppExtList.Load(csApplicationPath + APP_EXCLUDE_FILEEXTLIST_DB) == true)
	{
		LPVOID lpVoid = m_objDBAppExtList.GetFirst();
		while (lpVoid)
		{
			CString csPath;
			LPTSTR strKey = NULL;
			m_objDBAppExtList.GetKey(lpVoid, strKey); 
			_stprintf(pExtensionArray[iCount].extension, strKey);
			csPath = strKey; //GetSpyName(ulSpyName);
			lpVoid = m_objDBAppExtList.GetNext(lpVoid);
			iCount++;
		}
	}
	return iCount;

}