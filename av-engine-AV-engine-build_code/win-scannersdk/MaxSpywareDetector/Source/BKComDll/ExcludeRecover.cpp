#include "pch.h"
#include "ExcludeRecover.h"
#include "ExcludeDb.h"
#include "MaxDSrvWrapper.h"


CExcludeRecover::CExcludeRecover()
{

}

CExcludeRecover::~CExcludeRecover()
{

}

int CExcludeRecover::GetExcludedCount()
{
	CExcludeDb objExcludeDB;
	int iCntExDBByName = 0, iCntExDBByID = 0, iCntExDBByEntryID = 0, iCntExDBByEntryName = 0,iExldCount = 0;

	//iCntExDBByName = objExcludeDB.m_objExDBByName.GetCount();
	//iCntExDBByID = objExcludeDB.m_objExDBByID.GetCount();
	iCntExDBByEntryID = objExcludeDB.m_objExDBByEntryID.GetCount();
	iCntExDBByEntryName = objExcludeDB.m_objExDBByEntryName.GetCount();

	iExldCount = iCntExDBByName + iCntExDBByID + iCntExDBByEntryID + iCntExDBByEntryName;

	return iExldCount;
}

void CExcludeRecover::GetExcludedListEx(CS2U* pobjSpyNameToIDMap, ExcludeData* pExcludeDataArray, int iExcludeDataSize)
{
	try
	{

		CString csSpyWareName;
		CExcludeDb objExcludeDB;
		CMaxDSrvWrapper objMaxDSrvWrapper;
		objMaxDSrvWrapper.InitializeDatabase();

		ULONG ulSpyName = 0;
		
		/*LPVOID lpVoid = objExcludeDB.m_objExDBByName.GetFirst();
		while (lpVoid)
		{
			LPTSTR strKey = NULL;
			objExcludeDB.m_objExDBByName.GetKey(lpVoid, strKey);
			csSpyWareName = strKey;
			lpVoid = objExcludeDB.m_objExDBByName.GetNext(lpVoid);
		}
		lpVoid = objExcludeDB.m_objExDBByID.GetFirst();
		while (lpVoid)
		{
			objExcludeDB.m_objExDBByID.GetKey(lpVoid, ulSpyName);

			BYTE byThreatIndex = 0;
			csSpyWareName = objMaxDSrvWrapper.GetSpyName(ulSpyName, byThreatIndex);
			if (pobjSpyNameToIDMap)
			{
				CString csTempSpyName = csSpyWareName;
				csTempSpyName.MakeLower();
				pobjSpyNameToIDMap->AppendItem(csTempSpyName, ulSpyName);
			}
			lpVoid = objExcludeDB.m_objExDBByID.GetNext(lpVoid);
		}
		*/
		int im_objExDBByEntryIDCnt = 0;
		LPVOID lpVoid = objExcludeDB.m_objExDBByEntryID.GetFirst();
		while (lpVoid)
		{
			LPTSTR strKey = NULL;
			objExcludeDB.m_objExDBByEntryID.GetKey(lpVoid, strKey);
			objExcludeDB.m_objExDBByEntryID.GetData(lpVoid, ulSpyName);

			BYTE byThreatIndex = 0;
			csSpyWareName = objMaxDSrvWrapper.GetSpyName(ulSpyName, byThreatIndex);
			if (pobjSpyNameToIDMap)
			{
				CString csTempSpyName = csSpyWareName;
				csTempSpyName.MakeLower();
				pobjSpyNameToIDMap->AppendItem(csTempSpyName, ulSpyName);
			}

			pExcludeDataArray[im_objExDBByEntryIDCnt].dwSpyID = ulSpyName;
			wcscpy_s(pExcludeDataArray[im_objExDBByEntryIDCnt].szSpyName, csSpyWareName);
			wcscpy_s(pExcludeDataArray[im_objExDBByEntryIDCnt].szValue, strKey);
			im_objExDBByEntryIDCnt++;
			lpVoid = objExcludeDB.m_objExDBByEntryID.GetNext(lpVoid);
		}

		
		
		lpVoid = objExcludeDB.m_objExDBByEntryName.GetFirst();
		while (lpVoid)
		{
			LPTSTR strKey = NULL, szSpyName = NULL;
			objExcludeDB.m_objExDBByEntryName.GetKey(lpVoid, strKey);
			objExcludeDB.m_objExDBByEntryName.GetData(lpVoid, szSpyName);
			csSpyWareName = szSpyName; //GetSpyName(ulSpyName);

			pExcludeDataArray[im_objExDBByEntryIDCnt].dwSpyID = 0;
			wcscpy_s(pExcludeDataArray[im_objExDBByEntryIDCnt].szSpyName, szSpyName);
			wcscpy_s(pExcludeDataArray[im_objExDBByEntryIDCnt].szValue, strKey);
			im_objExDBByEntryIDCnt++;

			lpVoid = objExcludeDB.m_objExDBByEntryName.GetNext(lpVoid);
		}
		
		objMaxDSrvWrapper.DeInitializeDatabase();

	}

	catch (...)
	{
		AddLogEntry(L"Exception cauhght in CExcludeRecover::GetExcludedList");
	}
}
void CExcludeRecover::GetExcludedList(CS2U* pobjSpyNameToIDMap)
{
	try
	{
		CString csSpyWareName;
		CExcludeDb objExcludeDB;
		CMaxDSrvWrapper objMaxDSrvWrapper;
		objMaxDSrvWrapper.InitializeDatabase();

		ULONG ulSpyName = 0;
		LPVOID lpVoid = objExcludeDB.m_objExDBByName.GetFirst();
		while (lpVoid)
		{
			LPTSTR strKey = NULL;
			objExcludeDB.m_objExDBByName.GetKey(lpVoid, strKey);
			csSpyWareName = strKey;
			lpVoid = objExcludeDB.m_objExDBByName.GetNext(lpVoid);
		}
		lpVoid = objExcludeDB.m_objExDBByID.GetFirst();
		while (lpVoid)
		{
			objExcludeDB.m_objExDBByID.GetKey(lpVoid, ulSpyName);

			BYTE byThreatIndex = 0;
			csSpyWareName = objMaxDSrvWrapper.GetSpyName(ulSpyName, byThreatIndex);
			if (pobjSpyNameToIDMap)
			{
				CString csTempSpyName = csSpyWareName;
				csTempSpyName.MakeLower();
				pobjSpyNameToIDMap->AppendItem(csTempSpyName, ulSpyName);
			}
			lpVoid = objExcludeDB.m_objExDBByID.GetNext(lpVoid);
		}
		lpVoid = objExcludeDB.m_objExDBByEntryID.GetFirst();
		while (lpVoid)
		{
			LPTSTR strKey = NULL;
			objExcludeDB.m_objExDBByEntryID.GetKey(lpVoid, strKey);
			objExcludeDB.m_objExDBByEntryID.GetData(lpVoid, ulSpyName);

			BYTE byThreatIndex = 0;
			csSpyWareName = objMaxDSrvWrapper.GetSpyName(ulSpyName, byThreatIndex);
			if (pobjSpyNameToIDMap)
			{
				CString csTempSpyName = csSpyWareName;
				csTempSpyName.MakeLower();
				pobjSpyNameToIDMap->AppendItem(csTempSpyName, ulSpyName);
			}
			lpVoid = objExcludeDB.m_objExDBByEntryID.GetNext(lpVoid);
		}

		lpVoid = objExcludeDB.m_objExDBByEntryName.GetFirst();
		while (lpVoid)
		{
			LPTSTR strKey = NULL, szSpyName = NULL;
			objExcludeDB.m_objExDBByEntryName.GetKey(lpVoid, strKey);
			objExcludeDB.m_objExDBByEntryName.GetData(lpVoid, szSpyName);
			csSpyWareName = szSpyName; //GetSpyName(ulSpyName);
			lpVoid = objExcludeDB.m_objExDBByEntryName.GetNext(lpVoid);
		}

		objMaxDSrvWrapper.DeInitializeDatabase();

	}

	catch (...)
	{
		AddLogEntry(L"Exception cauhght in CExcludeRecover::GetExcludedList");
	}
}