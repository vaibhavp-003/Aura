#include "pch.h"
#include "RecoverRemovedSpywares.h"
#include "MaxExceptionFilter.h"
#include "MaxDSrvWrapper.h"
#include "CPUInfo.h"
#include "BackupOperations.h"

#define 	EXTRACTED_FILENAME			_T("TempExtractFile")
#define 	QUARANTINE_FOLDER			_T("Quarantine")

CRecoverRemovedSpywares::CRecoverRemovedSpywares():m_objQurTempFilesList(true, true)
{
	m_iUIRefreshed = 0;
	m_iAction = 0;
	m_bThreadProcessing = false;
	m_pObjMaxCommunicator = NULL;
}

CRecoverRemovedSpywares::~CRecoverRemovedSpywares()
{
	if (m_pObjMaxCommunicator)
	{
		delete m_pObjMaxCommunicator;
		m_pObjMaxCommunicator = NULL;
	}
}

int CRecoverRemovedSpywares::GetQuarantainDBCount()
{
	int iDBCount = 0;
	CRemoveDB objDBRemove;
	objDBRemove.Load(CSystemInfo::m_strAppPath + SD_DB_REMOVE);

	iDBCount = objDBRemove.GetCount();

	return iDBCount;

}


void CRecoverRemovedSpywares::EnumFolder(CString csFolderPath)
{
	try
	{
		CFileFind objFileFind;
		CString csFileFilePath = csFolderPath + _T("\\*.*");
		BOOL bFind = objFileFind.FindFile(csFileFilePath);

		if (FALSE == bFind)
		{
			return;
		}
		while (bFind)
		{
			bFind = objFileFind.FindNextFileW();
			if (objFileFind.IsDots())
				continue;

			if (!objFileFind.IsDirectory())
			{
				CString csFilePath = objFileFind.GetFilePath();
				CString csFileName = objFileFind.GetFileName();
				if (_tcsstr(csFilePath, L".tmp") != NULL && csFileName.Left(3).CompareNoCase(L"Max") != 0)
				{
					m_objQurTempFilesList.AppendItem(csFilePath, 0);
				}
			}
		}
		objFileFind.Close();
	}
	catch (...)
	{
		AddLogEntry(_T("Exception caught in CRecoverRemovedSpywares::EnumFolder"));
	}
}

bool CRecoverRemovedSpywares::DecryptAndGetFileName(CString csTempFileName, CString& csFileName)
{
	bool bRet = false;
	try
	{
		CString csDecryptFilePath = csTempFileName.Left(csTempFileName.ReverseFind(L'\\') + 1) + EXTRACTED_FILENAME;

		//Decrypt the file at same location with "TempExtractFile" name
		if (CBackupOperations::CopyAndEncryptFile(csTempFileName, csDecryptFilePath))
		{
			CZipFileHeader fh;
			CZipArchive objArchive;
			objArchive.Open(csDecryptFilePath, CZipArchive::openReadOnly, 0);
			objArchive.GetFileInfo(fh, 0);
			objArchive.Close();

			//Delete the File TempExtractFile 
			SetFileAttributes(csDecryptFilePath, FILE_ATTRIBUTE_NORMAL);
			DeleteFile(csDecryptFilePath);

			csFileName = fh.GetFileName();
			if (csFileName.Trim().GetLength() > 0)
			{
				bRet = true;
			}
		}
	}
	catch (...)
	{
		bRet = false;
	}
	return bRet;
}

bool CRecoverRemovedSpywares::ManageRecoverDB()
{
	try
	{
		//Enumerate all the .tmp files in Qurentine folder
		EnumFolder(CSystemInfo::m_strAppPath + QUARANTINE_FOLDER);

		CRemoveDB objDBRemove;
		objDBRemove.Load(CSystemInfo::m_strAppPath + SD_DB_REMOVE);

		//Remove the Entry which are already present in the SD_DB_REMOVE
		SYS_OBJ oRemoveDB = { 0 };
		bool bFound = objDBRemove.GetFirst(oRemoveDB);
		while (bFound)
		{
			DWORD dwData = 0;
			m_objQurTempFilesList.DeleteItem(oRemoveDB.szBackupFileName);
			memset(&oRemoveDB, 0, sizeof(SYS_OBJ));
			bFound = objDBRemove.GetNext(oRemoveDB);
		}

		memset(&oRemoveDB, 0, sizeof(SYS_OBJ));//used same

		CRemoveDB objMailDBRemove;
		objMailDBRemove.Load(CSystemInfo::m_strAppPath + SD_DB_MAIL_REMOVE);

		//Remove the Entry which are already present in the SD_DB_REMOVE
		bFound = false;
		bFound = objMailDBRemove.GetFirst(oRemoveDB);
		while (bFound)
		{
			DWORD dwData = 0;
			m_objQurTempFilesList.DeleteItem(oRemoveDB.szBackupFileName);
			memset(&oRemoveDB, 0, sizeof(SYS_OBJ));
			bFound = objMailDBRemove.GetNext(oRemoveDB);
		}
		memset(&oRemoveDB, 0, sizeof(SYS_OBJ));//used same

		LPVOID bDiffFound = m_objQurTempFilesList.GetFirst();
		if (!bDiffFound)
			return false;//no files to recover or All entries are present in Qurentine DB

		AddLogEntry(L">>>>>>> Start : Showing Entries which are not in Quarentine DB", 0, 0, true, LOG_DEBUG);

		CCPUInfo objCPUInfo;
		CString csRootDrive = objCPUInfo.GetRootDrive();
		while (bDiffFound)
		{
			LPTSTR szEntry = 0;
			m_objQurTempFilesList.GetKey(bDiffFound, szEntry);
			if (_waccess(szEntry, 0) == 0)
			{
				time_t ltime = 0;
				time(&ltime);

				CString csFile;
				if (DecryptAndGetFileName(szEntry, csFile))
				{
					CString csFileName = csRootDrive + L"\\" + csFile;
					oRemoveDB.dwType = SD_Message_Info::File;
					oRemoveDB.dwSpywareID = 7604;	//using trojan.agent
					oRemoveDB.szKey = _tcsdup(csFileName);
					CString csBackupFileName(szEntry);
					oRemoveDB.szBackupFileName = _tcsdup(csBackupFileName);
					oRemoveDB.u64DateTime = ltime;
					if (csFile.Right(4) == _T(".eml"))
					{
						objMailDBRemove.Add(oRemoveDB);
					}
					else
					{
						objDBRemove.Add(oRemoveDB);
					}
				}
			}
			bDiffFound = m_objQurTempFilesList.GetNext(bDiffFound);
		}
		if (!objDBRemove.Save(CSystemInfo::m_strAppPath + SD_DB_REMOVE))
		{
			AddLogEntry(L"##### Failed to Save QurentineRemove.DB in CRecoverRemovedSpywares::ManageRecoverDB");
			return false;
		}
		if (!objMailDBRemove.Save(CSystemInfo::m_strAppPath + SD_DB_MAIL_REMOVE))
		{
			AddLogEntry(L"##### Failed to Save QurentineRemove.DB in CRecoverRemovedSpywares::ManageRecoverDB");
			return false;
		}
		CMaxDSrvWrapper objMaxDSrvWrapper;
		objMaxDSrvWrapper.ReloadRemoveDB();
		AddLogEntry(L">>>>>>> End: Showing Entries which are not in Quarentine DB");
	}
	catch (...)
	{
		AddLogEntry(_T("Exception caught in CRecoverRemovedSpywares::ManageRecoverDB"));
		return false;
	}
	return true;
}

bool CRecoverRemovedSpywares::GetThreatInfo(ULONG ulSpyName, CString& csSpyName, BYTE& bThreatIndex, CString& csHelpInfo, CString csKeyValue, int iTypeId)
{
	if (m_objThreatInfo.IsLoaded() == false)
	{
		CRegistry objReg;
		CString csMaxDBPath;
		objReg.Get(CSystemInfo::m_csProductRegKey, CURRENT_MAX_DB_VAL, csMaxDBPath, HKEY_LOCAL_MACHINE);
		m_objThreatInfo.SetTempPath(csMaxDBPath);
		//m_objThreatInfo.Load(csMaxDBPath + SD_DB_SPYNAME);
	}

	TCHAR strSpyName[MAX_PATH] = { 0 };
	TCHAR strHelpInfo[1024] = { 0 };
	LPCTSTR strCatName = NULL;
	ULONG ulCatID = 0;
	if (m_objThreatInfo.SearchItem(ulSpyName, bThreatIndex, strHelpInfo, 1024, strSpyName, MAX_PATH))
	{
		if (iTypeId == /*Cookie*/ Cookie_New)
		{
			//csSpyName = csKeyValue+CString(strSpyName);
			csSpyName = csKeyValue + L"Tracking.Cookies";
		}
		else
		{
			csSpyName = CString(strSpyName);
		}

		csHelpInfo = CString(strHelpInfo);
		return true;
	}
	return false;
}

CString CRecoverRemovedSpywares::ConvertULONGtoDate(UINT64 u64DateTime)
{
	time_t rawtime = 0;
	struct tm timeinfo = { 0 };
	TCHAR szBuffer[80] = { 0 };

	rawtime = u64DateTime;
	localtime_s(&timeinfo, &rawtime);
	//wcsftime(szBuffer, 80, _T("%d %b, %Y [%H:%M:%S]"), &timeinfo);
	wcsftime(szBuffer, 80, _T("%d %b, %Y "), &timeinfo);// ravindra

	CString csDate;
	csDate.Format(_T("%s"), szBuffer);

	return csDate;
}

CString CRecoverRemovedSpywares::GetThreatType(SD_Message_Info eWormType)
{
	CString csType = L"";
	switch (eWormType)
	{
	case /*Cookie*/ Cookie_New:
	case Cookie_Report:
	{
		csType = COOKIE;
	}
	break;

	case Process:
	case Process_Report:
	case Rootkit_Process:
	case Rootkit_Process_Report:
	case Special_Process:
	case Special_Process_Report:
	case KeyLogger_Process:
	case KeyLogger_Process_Report:
	case Virus_Process:
	case Virus_Process_Report:
	{
		csType = PROCESS;
	}
	break;

	case Folder:
	case Folder_Report:
	case Rootkit_Folder:
	case Rootkit_Folder_Report:
	case Special_Folder:
	case Special_Folder_Report:
	case KeyLogger_Folder:
	case KeyLogger_Folder_Report:
	{
		csType = FOLDER;
	}
	break;

	case File:
	case File_Report:
	case MD5:
	case MD5_Report:
	case ExecPath:
	case ExecPath_Report:
	case GenPEScan:
	case GenPEScan_Report:
	case Virus_File:
	case Virus_File_Report:
	case Virus_File_Repair:
	case Virus_File_Repair_Report:
	case Rootkit_File:
	case Rootkit_File_Report:
	case Special_File:
	case Special_File_Report:
	case KeyLogger_File:
	case KeyLogger_File_Report:
	case System_File_Replace:
	case System_File_Replace_Report:
	case Pattern_File:
	{
		csType = FILEWORM;
	}
	break;

	case Service:
	case Service_Report:
	{
		csType = SERVICES_WORM;
	}
	break;
	case BHO:
	case BHO_Report:
	case ActiveX:
	case ActiveX_Report:
	case MenuExt_Key:
	case MenuExt_Key_Report:
	case RegKey:
	case RegKey_Report:
	case Notify:
	case Notify_Report:
	case Rootkit_RegKey:
	case Rootkit_RegKey_Report:
	case Virus_RegKey:
	case Virus_RegKey_Report:
	case Special_RegKey:
	case Special_RegKey_Report:
	{
		csType = REGISTRYKEY;
	}
	break;

	case MenuExt_Value:
	case MenuExt_Value_Report:
	case Run1:
	case Run1_Report:
	case SSODL:
	case SSODL_Report:
	case Toolbar:
	case Toolbar_Report:
	case SharedTask:
	case SharedTask_Report:
	case SharedDlls:
	case SharedDlls_Report:
	case ShellExecuteHooks:
	case ShellExecuteHooks_Report:
	case RegValue:
	case RegValue_Report:
	case Rootkit_RegVal:
	case Rootkit_RegVal_Report:
	case Virus_RegVal:
	case Virus_RegVal_Report:
	case Special_RegVal:
	case Special_RegVal_Report:
	{
		csType = REGISTRYVALUE;
	}
	break;

	case RegData:
	case RegData_Report:
	{
		csType = REGISTRYDATA;
	}
	break;
	case RegFix:
	case RegFix_Report:
	case Special_RegFix:
	case Special_RegFix_Report:
	{
		csType = REGDATAFIX;
	}
	break;
	case Module:
	case Module_Report:
	{
		csType = MEMORYWORM;
	}
	break;
	case Network:
	case Network_Report:
	{
		csType = NETWORK_CONNECTION;
	}
	break;
	case AppInit:
	case AppInit_Report:
	{
		csType = APPINIT;
	}
	break;
	default:
	{
		csType = SPYWARE;
	}
	}

	return csType;
}

void CRecoverRemovedSpywares::FillQrtnData(MAX_PIPE_DATA_REG& sMaxPipeDataReg, QuarantainData& sQuarantineData)
{
	CString csSpyName;
	BYTE bThreatIndex;
	wcscpy_s(sQuarantineData.szThreatFilePath,sMaxPipeDataReg.strKey);
	bool bUseSpyID = true;
	int iUseSpyID = 1;
	if (((sMaxPipeDataReg.ulSpyNameID == 0) || (_tcslen(sMaxPipeDataReg.strValue) != 0))
		&& ((sMaxPipeDataReg.eMessageInfo == Virus_Process) || (sMaxPipeDataReg.eMessageInfo == Virus_File)
			|| (sMaxPipeDataReg.eMessageInfo == Virus_File_Repair) || (sMaxPipeDataReg.eMessageInfo == Virus_File_Repair_Report)
			|| (sMaxPipeDataReg.eMessageInfo == Virus_Process_Report) || (sMaxPipeDataReg.eMessageInfo == Virus_File_Report)))
	{
		bUseSpyID = false;
		iUseSpyID = 0;
		csSpyName = sMaxPipeDataReg.strValue;
		bThreatIndex = -1;
	}
	else
	{
		CString strKeyValue = sMaxPipeDataReg.strValue;
		if (!strKeyValue.IsEmpty())
		{
			strKeyValue += _T(".");
		}
		if (GetThreatInfo(sMaxPipeDataReg.ulSpyNameID, csSpyName, bThreatIndex, CString(BLANKSTRING), strKeyValue, sMaxPipeDataReg.eMessageInfo) == false)
			bThreatIndex = -1;
	}


	if ((sMaxPipeDataReg.eMessageInfo < SD_Message_Info_TYPE_REG)// Its a File system Message
		|| (sMaxPipeDataReg.eMessageInfo == Virus_Process) || (sMaxPipeDataReg.eMessageInfo == Virus_File)
		|| (sMaxPipeDataReg.eMessageInfo == Virus_Process_Report) || (sMaxPipeDataReg.eMessageInfo == Virus_File_Report))
	{
		wcscpy_s(sQuarantineData.szSpyName, csSpyName);
		

		CString csThreatType = GetThreatType((SD_Message_Info)sMaxPipeDataReg.eMessageInfo);
		//wcscpy_s(sQuarantineData.szThreatType, csThreatType);
		sQuarantineData.iUseSpyID = iUseSpyID;
		return;
	}
	else
	{
		const int SIZEOFBUFFER = 1024 * 4;
		TCHAR strValue[SIZEOFBUFFER] = { 0 };
		PrepareValueForDispaly(sMaxPipeDataReg, strValue, SIZEOFBUFFER);
		CString csThreatType = GetThreatType((SD_Message_Info)sMaxPipeDataReg.eMessageInfo);
		//wcscpy_s(sQuarantineData.szThreatType, csThreatType);
		if (_tcslen(strValue) > 0)
		{
			wcscpy_s(sQuarantineData.szThreatFilePath, strValue);
		}
		wcscpy_s(sQuarantineData.szSpyName, csSpyName);
		
		sQuarantineData.iUseSpyID = iUseSpyID;
		return;
	}
	
}

void CRecoverRemovedSpywares::PrepareValueForDispaly(MAX_PIPE_DATA_REG& sMaxPipeDataReg, WCHAR* strValue, int iSizeOfBuffer)
{
	if ((sMaxPipeDataReg.eMessageInfo == Network) || (sMaxPipeDataReg.eMessageInfo == Network_Report))
	{
		swprintf_s(strValue, iSizeOfBuffer, L"%s : %s", sMaxPipeDataReg.strKey, sMaxPipeDataReg.strValue);
	}
	else if ((sMaxPipeDataReg.eMessageInfo == AppInit) || (sMaxPipeDataReg.eMessageInfo == AppInit_Report))
	{
		LPCTSTR lpstrHive = (sMaxPipeDataReg.Hive_Type == HKEY_LOCAL_MACHINE ? _T("HKEY_LOCAL_MACHINE") : _T("HKEY_USERS"));
		if (sMaxPipeDataReg.strKey)
		{
			size_t iLen = wcslen(sMaxPipeDataReg.strKey);
			if (sMaxPipeDataReg.strKey[iLen - 1] == '\\')
			{
				sMaxPipeDataReg.strKey[iLen - 1] = '\0';
			}
		}
		swprintf_s(strValue, iSizeOfBuffer, L"%s\\%s\\\"%s\"\\\"%s\" : \"%s\"", lpstrHive, sMaxPipeDataReg.strKey, sMaxPipeDataReg.strValue, (LPCTSTR)sMaxPipeDataReg.bData, (LPCTSTR)sMaxPipeDataReg.bReplaceData);
	}
	else if ((sMaxPipeDataReg.eMessageInfo == Module) || (sMaxPipeDataReg.eMessageInfo == Module_Report))
	{
		swprintf_s(strValue, iSizeOfBuffer, L"%s : %s", sMaxPipeDataReg.strKey, sMaxPipeDataReg.strValue);
	}
	else if ((sMaxPipeDataReg.eMessageInfo == Virus_Process) || (sMaxPipeDataReg.eMessageInfo == Virus_File)
		|| (sMaxPipeDataReg.eMessageInfo == Virus_File_Repair) || (sMaxPipeDataReg.eMessageInfo == Virus_File_Repair_Report)
		|| (sMaxPipeDataReg.eMessageInfo == Virus_Process_Report) || (sMaxPipeDataReg.eMessageInfo == Virus_File_Report)
		|| (sMaxPipeDataReg.eMessageInfo == Cookie_New))
	{
		wcscpy_s(strValue, iSizeOfBuffer, sMaxPipeDataReg.strKey);
	}
	else
	{
		LPCTSTR lpstrHive = (sMaxPipeDataReg.Hive_Type == HKEY_LOCAL_MACHINE ? _T("HKEY_LOCAL_MACHINE") : _T("HKEY_USERS"));
		if (sMaxPipeDataReg.strKey)
		{
			size_t iLen = wcslen(sMaxPipeDataReg.strKey);
			if (sMaxPipeDataReg.strKey[iLen - 1] == '\\')
			{
				sMaxPipeDataReg.strKey[iLen - 1] = '\0';
			}
		}
		if (sMaxPipeDataReg.iSizeOfData > 0)
		{
			if (sMaxPipeDataReg.Type_Of_Data == REG_DWORD && sMaxPipeDataReg.iSizeOfData > 0)
			{
				DWORD dwData = 0;
				memcpy(&dwData, sMaxPipeDataReg.bData, sMaxPipeDataReg.iSizeOfData);
				if (sMaxPipeDataReg.eMessageInfo == RegFix)
				{
					DWORD dwReplaceData = 0;
					if (sMaxPipeDataReg.bReplaceData && sMaxPipeDataReg.iSizeOfReplaceData > 0)
					{
						memcpy(&dwReplaceData, sMaxPipeDataReg.bReplaceData, sMaxPipeDataReg.iSizeOfReplaceData);
					}
					swprintf_s(strValue, iSizeOfBuffer, L"%s\\%s\\\"%s\"\\\"%d\" : \"%d\"", lpstrHive, sMaxPipeDataReg.strKey, sMaxPipeDataReg.strValue, dwData, dwReplaceData);
				}
				else
				{
					swprintf_s(strValue, iSizeOfBuffer, L"%s\\%s\\\"%s\"\\\"%d\"", lpstrHive, sMaxPipeDataReg.strKey, sMaxPipeDataReg.strValue, dwData);
				}
			}
			else if (((sMaxPipeDataReg.Type_Of_Data == REG_SZ) || (sMaxPipeDataReg.Type_Of_Data == REG_EXPAND_SZ))
				&& (sMaxPipeDataReg.iSizeOfData > 0))
			{
				if ((sMaxPipeDataReg.eMessageInfo == RegFix) && (sMaxPipeDataReg.bReplaceData && sMaxPipeDataReg.iSizeOfReplaceData > 0))
				{
					swprintf_s(strValue, iSizeOfBuffer, L"%s\\%s\\\"%s\"\\\"%s\" : \"%s\"", lpstrHive, sMaxPipeDataReg.strKey, sMaxPipeDataReg.strValue, (LPCTSTR)sMaxPipeDataReg.bData, (LPCTSTR)sMaxPipeDataReg.bReplaceData);
				}
				else
				{
					swprintf_s(strValue, iSizeOfBuffer, L"%s\\%s\\\"%s\"\\\"%s\"", lpstrHive, sMaxPipeDataReg.strKey, sMaxPipeDataReg.strValue, (LPCTSTR)sMaxPipeDataReg.bData);
				}
			}
			else // Binary || Multi_SZ Data
			{
				swprintf_s(strValue, iSizeOfBuffer, L"%s\\%s\\\"%s\"", lpstrHive, sMaxPipeDataReg.strKey, sMaxPipeDataReg.strValue);
			}
		}
		else if (wcslen(sMaxPipeDataReg.strValue) > 0)
		{
			swprintf_s(strValue, iSizeOfBuffer, L"%s\\%s\\\"%s\"", lpstrHive, sMaxPipeDataReg.strKey, sMaxPipeDataReg.strValue);
		}
		else
		{
			swprintf_s(strValue, iSizeOfBuffer, L"%s\\%s", lpstrHive, sMaxPipeDataReg.strKey);
		}
	}
}

void CRecoverRemovedSpywares::ShowQuarantineData(MAX_PIPE_DATA_REG& sMaxPipeDataReg, UINT64 u64DateTime)
{
	CString csSpyName;
	BYTE bThreatIndex;

	bool bUseSpyID = true;
	if (((sMaxPipeDataReg.ulSpyNameID == 0) || (_tcslen(sMaxPipeDataReg.strValue) != 0))
		&& ((sMaxPipeDataReg.eMessageInfo == Virus_Process) || (sMaxPipeDataReg.eMessageInfo == Virus_File)
			|| (sMaxPipeDataReg.eMessageInfo == Virus_File_Repair) || (sMaxPipeDataReg.eMessageInfo == Virus_File_Repair_Report)
			|| (sMaxPipeDataReg.eMessageInfo == Virus_Process_Report) || (sMaxPipeDataReg.eMessageInfo == Virus_File_Report)))
	{
		bUseSpyID = false;
		csSpyName = sMaxPipeDataReg.strValue;
		bThreatIndex = -1;
	}
	else
	{
		CString strKeyValue = sMaxPipeDataReg.strValue;
		if (!strKeyValue.IsEmpty())
		{
			strKeyValue += _T(".");
		}
		if (GetThreatInfo(sMaxPipeDataReg.ulSpyNameID, csSpyName, bThreatIndex, CString(BLANKSTRING), strKeyValue, sMaxPipeDataReg.eMessageInfo) == false)
			bThreatIndex = -1;
	}
}

void CRecoverRemovedSpywares::ReadQuarantineData(QuarantainData* pQuarantainArray, int size)
{
	m_bThreadProcessing = true;
	ManageRecoverDB();

	CRemoveDB objDBRemove;
	objDBRemove.Load(CSystemInfo::m_strAppPath + SD_DB_REMOVE);

	SYS_OBJ oRemoveDB = { 0 };
	QuarantainData oQuarantineData = { 0 };

	bool bFound = objDBRemove.GetFirst(oRemoveDB);

	int iCnt = 0;

	while (bFound)
	{
		if ((_tcslen(oRemoveDB.szBackupFileName) == 0) || (_waccess(oRemoveDB.szBackupFileName, 0) == 0))
		{

			memset(&oQuarantineData, 0, sizeof(QuarantainData));
			MAX_PIPE_DATA_REG sMaxPipeDataReg = { 0 };
			sMaxPipeDataReg.eMessageInfo = oRemoveDB.dwType;
			sMaxPipeDataReg.ulSpyNameID = oRemoveDB.dwSpywareID;
			sMaxPipeDataReg.Hive_Type = (HKEY)oRemoveDB.ulptrHive;
			if (oRemoveDB.szKey)
			{
				wcscpy_s(sMaxPipeDataReg.strKey, oRemoveDB.szKey);
			}
			if (oRemoveDB.szValue)
			{
				wcscpy_s(sMaxPipeDataReg.strValue, oRemoveDB.szValue);
			}
			if (oRemoveDB.byData)
			{
				memcpy_s(sMaxPipeDataReg.bData, MAX_PATH * 4, oRemoveDB.byData, oRemoveDB.dwRegDataSize);
			}
			sMaxPipeDataReg.iSizeOfData = oRemoveDB.dwRegDataSize;
			if (oRemoveDB.byReplaceData)
			{
				memcpy_s(sMaxPipeDataReg.bReplaceData, MAX_PATH * 4, oRemoveDB.byReplaceData, oRemoveDB.dwReplaceRegDataSize);
			}

			sMaxPipeDataReg.iSizeOfReplaceData = oRemoveDB.dwReplaceRegDataSize;
			sMaxPipeDataReg.Type_Of_Data = oRemoveDB.wRegDataType;
			sMaxPipeDataReg.ulSpyNameID = oRemoveDB.dwSpywareID;

			oQuarantineData.iIndex = oRemoveDB.iIndex;
			oQuarantineData.dwSpyID = oRemoveDB.dwSpywareID;
			//wcscpy_s(oQuarantineData.szThreatFilePath, oRemoveDB.szKey);
			//wcscpy_s(oQuarantineData.szBackupFilePath, oRemoveDB.szBackupFileName);

			//ShowQuarantineData(sMaxPipeDataReg, oRemoveDB.u64DateTime);

			CString csDateTime = ConvertULONGtoDate(oRemoveDB.u64DateTime);
			//wcscpy_s(oQuarantineData.szDateTime, csDateTime);
			
			FillQrtnData(sMaxPipeDataReg, oQuarantineData);

			//wcscpy_s(pQuarantainArray[iCnt].szSpyName, oQuarantineData.szSpyName);

			pQuarantainArray[iCnt].iIndex = oRemoveDB.iIndex;
			wcscpy_s(pQuarantainArray[iCnt].szSpyName, oQuarantineData.szSpyName);
			pQuarantainArray[iCnt].dwSpyID = oRemoveDB.dwSpywareID;
			wcscpy_s(pQuarantainArray[iCnt].szThreatFilePath, oQuarantineData.szThreatFilePath);
			wcscpy_s(pQuarantainArray[iCnt].szBackupFilePath, oRemoveDB.szBackupFileName);
			wcscpy_s(pQuarantainArray[iCnt].szDateTime, csDateTime);
			//wcscpy_s(pQuarantainArray[iCnt].szThreatType, oQuarantineData.szThreatType);
			pQuarantainArray[iCnt].iUseSpyID = oQuarantineData.iUseSpyID;
			//

			
			iCnt++;
		}
		if (iCnt == size)
		{
			break;
		}
		memset(&oRemoveDB, 0, sizeof(SYS_OBJ));
		bFound = objDBRemove.GetNext(oRemoveDB);
	}


	m_bThreadProcessing = false;
}
void CRecoverRemovedSpywares::RefreshUI()
{
	
	if (m_iUIRefreshed == 0)
	{
		m_iUIRefreshed = 1;

		// Send command to the WatchDog to
		// launch an instance of the AUSCANNER for Recover
		MAX_PIPE_DATA_REG sScanRequest = { 0 };
		sScanRequest.sScanOptions.RecoverSpyware = 1;
		// Start the Scanner here via the WatchDog Service
		CMaxCommunicator objMaxCommunicator(_NAMED_PIPE_UI_TO_SERVICE);
		objMaxCommunicator.SendData(&sScanRequest, sizeof(MAX_PIPE_DATA_REG));

		CMaxDSrvWrapper objMaxDSrvWrapper;
		objMaxDSrvWrapper.ReloadDatabase();
		
		//ReadQuarantineData();		
	}
	
}

void CRecoverRemovedSpywares::OnClickedLoadQuarantineDB(QuarantainData* pQuarantainArray, int size)
{
	__try
	{
		RefreshUI();
		//QuarantainData oQuarantineData = { 0 };
		ReadQuarantineData(pQuarantainArray, size);
	}
	__except (CMaxExceptionFilter::Filter(GetExceptionCode(), GetExceptionInformation(), _T("RefreshUI() CRecoverRemovedSpywares")))
	{
	}

	
}

void CRecoverRemovedSpywares::ShutdownRecoveryScanner(void)
{
	if (NULL == m_pObjMaxCommunicator)
	{
		m_pObjMaxCommunicator = new CMaxCommunicator(_NAMED_PIPE_UI_TO_RECOVER_SCANNER);
	}

	MAX_PIPE_DATA_REG sMaxPipeData = { 0 };
	sMaxPipeData.eMessageInfo = Finished_Recovery;
	m_pObjMaxCommunicator->SendData(&sMaxPipeData, sizeof(MAX_PIPE_DATA_REG));
	m_pObjMaxCommunicator->ReadData((LPVOID)&sMaxPipeData, sizeof(MAX_PIPE_DATA_REG));

	m_iUIRefreshed = 0;
	/*
	if (m_bReloadRequired)
	{
		PostMessageToProtection(WM_USER_RESTART_MON_SWITCH, RELOADEXCLUDEDB, ON);
	}
	*/
}

bool CRecoverRemovedSpywares::IsRestoreDrivePresent(LPCTSTR pszRestorePath)
{
	bool				bResult = false;
	TCHAR				szFilePath[1024] = { 0x00 }, * pTemp = NULL;
	//MAX_PIPE_DATA_REG	sMaxPipeDataReg = {0};

	//m_pMaxDSrvWrapper->GetRemoveDBData(ulSpyID, &sMaxPipeDataReg);

	_tcscpy(szFilePath, pszRestorePath);
	pTemp = _tcsstr(szFilePath, _T(":\\"));
	if (pTemp != NULL)
	{
		pTemp += 2;
		*pTemp = '\0';

		if (_waccess_s(szFilePath, 0) == 0)
		{
			return true;
		}
	}
	else
	{
		return true;
	}

	return bResult;
}

void CRecoverRemovedSpywares::PostMessageToProtection(UINT message, WPARAM wParam, LPARAM lParam)
{
	HWND hwnd = ::FindWindowEx(NULL, NULL, _T("#32770"), AUACTIVEPROTECTION);
	if (hwnd)
	{
		SendMessageTimeout(hwnd, message, wParam, lParam, SMTO_ABORTIFHUNG, TIMEOUT, NULL);
	}
}

void CRecoverRemovedSpywares::PauseActiveProtection(bool bStart)
{
	if (bStart)
	{
		PostMessageToProtection(WM_USER_RESTART_MON_SWITCH, PAUSEPROTECTION, ON);
	}
	else
	{
		PostMessageToProtection(WM_USER_RESTART_MON_SWITCH, RELOADEXCLUDEDB, ON);
		PostMessageToProtection(WM_USER_RESTART_MON_SWITCH, PAUSEPROTECTION, OFF);
	}
}

void CRecoverRemovedSpywares::StartRecoveringSpyware(QuarantainData* pQuarantainArray, int QuarantainArraySize, int iRecoverLength, int* ptrRecoveredIndexArray)
{
	if (m_iAction == E_ACTION_EXCLUDE_RECOVER)
	{
		PauseActiveProtection(true);
	}

	m_objRansCriticalSec.Lock();

	CRemoveDB objDBRemove;
	objDBRemove.Load(CSystemInfo::m_strAppPath + SD_DB_REMOVE);

	LPTSTR lpszBackupName = NULL;
	bool bParentExcluded = false;
	CString csSpyWare;

	if (NULL == m_pObjMaxCommunicator)
	{
		m_pObjMaxCommunicator = new CMaxCommunicator(_NAMED_PIPE_UI_TO_RECOVER_SCANNER);
	}

	MAX_PIPE_DATA_REG sMaxPipeData = { 0 };
	sMaxPipeData.eMessageInfo = Quarantine_DB_Entry;

	DWORD dwSizeMaxPipeData = sizeof(MAX_PIPE_DATA_REG);

	CMaxDSrvWrapper objMaxDSrvWrapper;
	objMaxDSrvWrapper.InitializeDatabase();

	CUIntArray objarrIndexes;

	for (int i = 0; i < QuarantainArraySize; i++)
	{
		bParentExcluded = false;
		csSpyWare = pQuarantainArray[i].szSpyName;

		if (pQuarantainArray[i].iSpyNameParent == 1)
		{
			if (E_ACTION_EXCLUDE_RECOVER == m_iAction)
			{
				bParentExcluded = true;

				ULONG ulSpyNameID = (pQuarantainArray[i].iUseSpyID ? pQuarantainArray[i].dwSpyID : 0);
				LPCTSTR szSpyName = ulSpyNameID ? NULL : csSpyWare;
				objMaxDSrvWrapper.Exclude(ulSpyNameID, szSpyName, 0);
			}
		}

		if ((bParentExcluded == false) && (E_ACTION_EXCLUDE_RECOVER == m_iAction))
		{
			CString csThreatFilePath = pQuarantainArray[i].szThreatFilePath;
			ULONG ulSpyNameID = (pQuarantainArray[i].iUseSpyID ? pQuarantainArray[i].dwSpyID : 0);
			LPCTSTR szSpyName = ulSpyNameID ? NULL : csSpyWare;
			objMaxDSrvWrapper.Exclude(ulSpyNameID, szSpyName, csThreatFilePath);
		}

		objarrIndexes.Add((UINT)pQuarantainArray[i].iIndex);

		if (E_ACTION_DELETE == m_iAction)
		{
			lpszBackupName = pQuarantainArray[i].szBackupFilePath;
			if (_tcslen(lpszBackupName) > 0)
				::DeleteFile(lpszBackupName);
			objDBRemove.SetDeleteFlag(pQuarantainArray[i].iIndex, true);

		}
		else
		{
			CString csThreatFilePath = pQuarantainArray[i].szThreatFilePath;
			if ((_tcslen(pQuarantainArray[i].szBackupFilePath) == 0) || IsRestoreDrivePresent(csThreatFilePath))
			{
				objDBRemove.SetDeleteFlag(pQuarantainArray[i].iIndex, true);
				sMaxPipeData.ulSpyNameID = pQuarantainArray[i].iIndex;
				sMaxPipeData.eMessageInfo = Quarantine_DB_Entry;
				m_pObjMaxCommunicator->SendData(&sMaxPipeData, dwSizeMaxPipeData);
				m_pObjMaxCommunicator->ReadData((LPVOID)&sMaxPipeData, sizeof(MAX_PIPE_DATA_REG));
				Sleep(50);
			}
		}

	}

	objDBRemove.Save(CSystemInfo::m_strAppPath + SD_DB_REMOVE);

	objMaxDSrvWrapper.ReloadRemoveDB();
	objMaxDSrvWrapper.DeInitializeDatabase();

	m_objRansCriticalSec.Unlock();

	if (m_iAction == E_ACTION_EXCLUDE_RECOVER)
	{
		PauseActiveProtection(false);
		PostMessageToProtection(WM_USER_RESTART_MON_SWITCH, RELOADEXCLUDEDB, ON);
	}

	int iTotalCount = (int)objarrIndexes.GetCount();
	for (int iCount = 0; iCount < iTotalCount; iCount++)
	{
		ptrRecoveredIndexArray[iCount] = (int)objarrIndexes.GetAt(iCount);
	}
}

void CRecoverRemovedSpywares::OnClickedRecoverFiles(QuarantainData* pQuarantainArray, int QuarantainArraysize, int iRecoverLength, int* ptrRecoveredIndexArray, int iAction)
{
	m_iAction = iAction;
	//m_iAction = E_ACTION_RECOVER;
	//m_iAction = E_ACTION_DELETE;
	//m_iAction = E_ACTION_EXCLUDE_RECOVER;
	StartRecoveringSpyware(pQuarantainArray, QuarantainArraysize, iRecoverLength, ptrRecoveredIndexArray);
}