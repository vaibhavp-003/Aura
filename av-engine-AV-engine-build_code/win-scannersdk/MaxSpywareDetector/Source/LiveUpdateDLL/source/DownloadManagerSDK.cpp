#include "pch.h"
#include "DownloadManagerSDK.h"
#include "DownloadManagerEx.h"
#include "CommonFileIntegrityCheck.h"
#include "HardDiskManager.h"
//#include "SDKSettings.h"
#include "UpdateManager.h"
#include "LiveUpdateDLL.h"
#include "CPUInfo.h"
//#include "MaxSoftwareMgr.h"

#define BUF_SIZE 4096
#define MAX_DELATAS 300
//const INTERNET_PORT  FTP_PORT=21;


UINT __cdecl ThreadUpdateStatus(LPVOID pParam);

DownloadManagerSDK::DownloadManagerSDK(void):m_objIndexOfDownload(false)
{
	m_bUpdateVersion = false;
	m_bUpdateVersionX64 = false;
	m_bDataBasePatch = false;
	m_bDataBasePatchCL = false;
	m_bDataBasePatchX64 = false;
	m_bVirus = false;	
	m_bVirusX64 = false;
	m_bCloudSrv = false;
	m_bCloudControlSrv = false;

	m_bDownLoadFullPatch=false;
	m_bDataBase=false;
	m_bUpdateStatus = FALSE;
	m_bProductX64 = false;
	m_bProduct = false;
	m_bSDK = false;
	m_bSDKX64 = false;
	m_pSendSDKMessageToUI = NULL;
	
	m_pStatusThread = NULL;


	m_iFilecount = 0;
	m_dwTotalDownloadSize = 0;
	m_dwTotalDownloadedSize = 0;
	
	m_iPercent = 0;
	m_dwRemainingTime = 0;
	m_iEnumLabelStatus = 0;
	m_iMaxNoOfDeltaToDownload = MAX_DELATAS;

	m_csDownloadedFiles = _T("");
}

DownloadManagerSDK::~DownloadManagerSDK(void)
{
	if(m_pStatusThread)
	{
		SuspendThread(m_pStatusThread->m_hThread);

		delete m_pStatusThread;
		m_pStatusThread = NULL;
	}
}

void DownloadManagerSDK::SetCtrlItemsSDK(CStatic *pStatus, CStatic *pTotalTimeRemaining, CStatic *pTotalPercentage)
{
	m_pStatus=pStatus;
	m_pTotalTimeRemaining = pTotalTimeRemaining;
	m_pTotalPercentage = pTotalPercentage;
}

bool DownloadManagerSDK::DownLoad(bool &  bExitApplication)
{
	BOOL bIsSVDownloaded = FALSE;
	CString csIPaddress;
	m_csDownloadedFiles = _T("");
	if(!CheckForUpdate(bIsSVDownloaded))
	{
		m_csDownloadedFiles = L"";//L"Product is up to date!"; IDS_SD_UPTODATE
		m_iEnumLabelStatus = UpdateMessages::UPTODATE;
		bool iRetn = true;
		int iSuccessErr = 0;
		if(!bIsSVDownloaded)
		{
			iRetn = false;
			m_csDownloadedFiles = L"";//L"Error occurred while downloading updates"; IDS_DWONLOAD_ERROR
			m_iEnumLabelStatus = UpdateMessages::DWONLOAD_ERR;
			iSuccessErr = 1;
		}
		else
		{
			bExitApplication = true;
		}
		FinishUpdateStatus(iSuccessErr);
	
		return iRetn;
	}

	
	//Add check for free disk Size
	CHardDiskManager objHardDiskManager;
	CString csPath = CSystemInfo::m_strAppPath;
	objHardDiskManager.CheckFreeSpace(csPath.Left(csPath.Find(_T("\\"))));
	if(objHardDiskManager.GetTotalNumberOfFreeGBytes()< (double)0.21)
	{
		m_csDownloadedFiles = L"";// L"There is not enough free disk space."; //IDS_DISKSIZE_ERROR
		m_iEnumLabelStatus = UpdateMessages::DISKSIZE_ERR;
		FinishUpdateStatus(1);
		AddLogEntry(L"AutoLiveupate: There is not enough free disk space.");
		return false;
	}

	
	int iThreadCount =  GetPrivateProfileInt(DOWNLOADTHREADDETAILS, _T("DownloadThreadCount"), 1, m_csVersionINI);
	CDownloadManagerEx objDownloadManagerEx(iThreadCount);

	if(!theApp.m_bLocalServerUpdate)
	{
		m_csLiveUpdatePath1 = objDownloadManagerEx.DownloadURLContent(CString(LIVEUPDATEPATH_URL));
		//AddLogEntry(_T(">>> Getting New Live Update Path URL 1: "));
		while (!m_csLiveUpdatePath1.IsEmpty() && _T('/') != m_csLiveUpdatePath1.GetAt(m_csLiveUpdatePath1.GetLength() - 1))
		{
			m_csLiveUpdatePath1.Delete(m_csLiveUpdatePath1.GetLength() - 1);
		}
		//AddLogEntry(_T(">>> Getting New Live Update Path URL 1: ") + m_csLiveUpdatePath1, LOG_DEBUG);


		m_csLiveUpdatePath2 = objDownloadManagerEx.DownloadURLContent(CString(LIVEUPDATEPATH_URL2));
		//AddLogEntry(_T(">>> Getting New Live Update Path URL 2: "));
		while (!m_csLiveUpdatePath2.IsEmpty() && _T('/') != m_csLiveUpdatePath2.GetAt(m_csLiveUpdatePath2.GetLength() - 1))
		{
			m_csLiveUpdatePath2.Delete(m_csLiveUpdatePath2.GetLength() - 1);
		}
	}
	else
	{
		m_csLiveUpdatePath1 = theApp.m_csLocalServerPath+L"/";
		AddLogEntry(_T(">>> Getting New Live Update Local Path URL: "));
		m_csLiveUpdatePath2 = BLANKSTRING;
	}
	if(!DownloadHTTPFiles())
	{
		AddLogEntry(_T(">>> FAILED DownloadHTTPFiles()"));
		m_csDownloadedFiles = L"";//Error occurred while downloading updates IDS_DWONLOAD_ERROR
		m_iEnumLabelStatus = UpdateMessages::DWONLOAD_ERR;
		FinishUpdateStatus(1);
		return false;
	}
	CString csServerPath;
	{
		if(!theApp.m_bLocalServerUpdate)
		{
			csServerPath = SERVER_PATH;
		}
		else
		{
			csServerPath = theApp.m_csLocalServerPath;//to add local server address
		}
	}

	CString csIniPath;
	csIniPath = theApp.m_csWaitingForMergePath;
	csIniPath = csIniPath + L"\\LiveUdpDate.txt";

	

	COleDateTime objOleDateTime = objOleDateTime.GetCurrentTime();
	CString csDate;
	CCPUInfo objCPUInfo;
	csDate.Format(L"%d-%s-%d", objOleDateTime.GetDay(), objCPUInfo.GetMonthName(objOleDateTime.GetMonth()),objOleDateTime.GetYear());

	WritePrivateProfileString(L"ServerUpdate",L"Date",csDate,csIniPath);

	FinishUpdateStatus(0);
	return true;
}

/*-------------------------------------------------------------------------------------
Function		: CheckForUpdate
In Parameters	: -
Out Parameters	: bool
Purpose			: This function will check updates availability.
Author			: Avinash Shendage.
--------------------------------------------------------------------------------------*/
bool DownloadManagerSDK::CheckForUpdate(BOOL& bIsSVDownloaded)
{
	CString csSDLiveUpdate;
	
	//csSDLiveUpdate = m_csDownLoadPath + _T("\\") + TEMP_LIVEUPDATE;
	csSDLiveUpdate = m_csDownLoadPath + TEMP_LIVEUPDATE;
	CreateDirectory(csSDLiveUpdate, NULL);
	
	CDownloadManagerEx objDownloadManagerEx(1);

	CString csDestFile = csSDLiveUpdate + _T("\\") + INI_FILE_NAME;
	bIsSVDownloaded = FALSE;

	if(!theApp.m_bLocalServerUpdate)
	{
		if (!bIsSVDownloaded)
		{
			AddLogEntry(_T(">>>>> DOWNLOADING: HTTP ServerVersionEx"));
			bIsSVDownloaded = objDownloadManagerEx.DownloadURLUsingHTTP(SERVER_VERSIONFILE_HTTP, csDestFile);
		}
		if (!bIsSVDownloaded)
		{
			AddLogEntry(_T(">>>>> DOWNLOADING: HTTP Default ServerVersionEx"));
			bIsSVDownloaded = objDownloadManagerEx.DownloadURLUsingHTTP(DEFAULT_SVR_VERSIONFILE_HTTP, csDestFile);
		}
		if (!bIsSVDownloaded)
		{
			AddLogEntry(_T(">>>>> DOWNLOADING: FTP ServerVersionEx"));
			bIsSVDownloaded = objDownloadManagerEx.DownloadURLUsingFTP(SERVER_VERSIONFILE, csDestFile);
		}
		if (!bIsSVDownloaded)
		{
			AddLogEntry(_T(">>>>> DOWNLOADING: FTP Default ServerVersionEx"));
			bIsSVDownloaded = objDownloadManagerEx.DownloadURLUsingFTP(DEFAULT_SVR_VERSIONFILE, csDestFile);
		}

	}
	else
	{
		CString csLocalServerVersionFile;
		csLocalServerVersionFile.Format(L"%s/ServerVersionEx.txt",theApp.m_csLocalServerPath);
		if(!bIsSVDownloaded)
		{
			AddLogEntry(_T(">>>>> DOWNLOADING: Local HTTP ServerVersionEx"));
			bIsSVDownloaded = objDownloadManagerEx.DownloadURLUsingHTTP(csLocalServerVersionFile, csDestFile);
		}
	}

	int iUpdateCount = -1;

	//if(bIsSVDownloaded)
	//{
	//	CString csVal;
	//	GetPrivateProfileString(L"NewProductDetails", L"MD5", _T(""), csVal.GetBuffer(MAX_PATH), MAX_PATH, csDestFile);
	//	csVal.ReleaseBuffer();
	//	csVal.Trim();
	//	if(csVal.GetLength() != 32)
	//		bIsSVDownloaded = FALSE;
	//}
	//if(!bIsSVDownloaded)
	//{
	//	//DisplayError(true);
	//	return false;
	//}

	m_csVersionINI = csSDLiveUpdate + _T("\\") + INI_FILE_NAME;
	m_csDeltaVersionINI = csSDLiveUpdate + _T("\\") + INI_DELTASERVER_FILE_NAME;

	
	// how many delta should be downloaded at one time?
	m_iMaxNoOfDeltaToDownload = GetPrivateProfileInt(DELTADETAILS, _T("MaxNoOfDeltaToDownload"), MAX_DELATAS, m_csVersionINI);
	CString csTemp;
	csTemp.Format(_T("MaxNoOfDeltaToDownload: %d, MAX_DELATAS: %d"), m_iMaxNoOfDeltaToDownload, MAX_DELATAS);
	AddLogEntry(csTemp);
	bool bReturn = false;

///// For Product Patch
	if(theApp.m_bProductPatch)
	{
		m_csProductFileName1 =  m_csProductFileName = m_objCommonFunctions.GetFileName(theApp.m_csProductDetails, m_csVersionINI);
		m_csProductFileName2 =  m_csProductFileNameX64 = m_objCommonFunctions.GetFileName(theApp.m_csProductDetailsX64,m_csVersionINI);
		bool bRet = false;
		if(!IsFileAlreadyDownloaded(theApp.m_csProductDetails, L"MD5", m_csProductFileName))
		{
			AddLogEntry(m_csProductFileName,0 , 0, true,LOG_WARNING);
			m_bProduct = true;
			m_objIndexOfDownload.AppendItem(ENUM_DT_PRODUCT, 0);
			UpdateDownloadSize(theApp.m_csProductDetails);
			if(theApp.m_bFullDataProductUpdates)
				bReturn = true;
			else
				bRet = true;
		}
		if(!IsFileAlreadyDownloaded(theApp.m_csProductDetailsX64, L"MD5", m_csProductFileNameX64))
		{
			AddLogEntry(m_csProductFileNameX64,0 , 0, true,LOG_WARNING);
			m_bProductX64 = true;
			m_objIndexOfDownload.AppendItem(ENUM_DT_PRODUCT_X64, 0);
			UpdateDownloadSize(theApp.m_csProductDetailsX64);
			if(theApp.m_bFullDataProductUpdates)
				bReturn = true;
			else
				bRet = true;
		}

		if(bRet)
			return bRet;

		if(!theApp.m_bFullDataProductUpdates)
			return false;
	}
	if(theApp.m_bStandaloneDownload)
	{	
		m_csDBPatchFileName = m_objCommonFunctions.GetFileName(theApp.m_csDatabaseDetails, m_csVersionINI);
		if(!IsFileAlreadyDownloaded(theApp.m_csDatabaseDetails, L"MD5", m_csDBPatchFileName))
		{
			AddLogEntry(m_csDBPatchFileName);
			m_bDataBasePatch = true;
			m_objIndexOfDownload.AppendItem(ENUM_DT_DBPATCH, 0);
			UpdateDownloadSize(theApp.m_csDatabaseDetails);
		}

	}
	else if(theApp.m_bDatabasePatch)
	{
		if(!GetDBFilesFromBackupIfAvailable() || theApp.m_iIsFullSDDatabase == 1)
		{
			m_csDBPatchFileName = m_objCommonFunctions.GetFileName(theApp.m_csDatabaseDetails, m_csVersionINI);
			if(!IsFileAlreadyDownloaded(theApp.m_csDatabaseDetails, L"MD5", m_csDBPatchFileName))
			{
				AddLogEntry(m_csDBPatchFileName);
				m_bDataBasePatch = true;
				m_objIndexOfDownload.AppendItem(ENUM_DT_DBPATCH, 0);
				UpdateDownloadSize(theApp.m_csDatabaseDetails);
				return true;
			}
		}
		return false;
	}


	//CCommonFunctions objCommonFunctions;
	if(!CheckVersionNumber(theApp.m_csDeltaDetails))
	{
		iUpdateCount++;
		m_objIndexOfDownload.AppendItem(ENUM_DT_DATABASE, iUpdateCount);
	}	

	if(!CheckVersionNumber(theApp.m_csUpdtVerDetails))
	{
		iUpdateCount++;
		m_objIndexOfDownload.AppendItem(ENUM_DT_UPDATE_VERSION, iUpdateCount);
	}
	if(!CheckVersionNumber(theApp.m_csUpdtVerDetailsX64))
	{
		iUpdateCount++;
		m_objIndexOfDownload.AppendItem(ENUM_DT_UPDATE_VERSION_X64, iUpdateCount);
	}

	if(!CheckVersionNumber(theApp.m_csVirusDetails))
	{		
		
		iUpdateCount++;
		m_objIndexOfDownload.AppendItem(ENUM_DT_VIRUS, iUpdateCount);
	}
	if(!CheckVersionNumber(theApp.m_csVirusDetailsX64))
	{		
		iUpdateCount++;
		m_objIndexOfDownload.AppendItem(ENUM_DT_VIRUS_X64, iUpdateCount);
	}
	if(!CheckVersionNumber(theApp.m_csProductDetails))
	{
	/*	if(iUpdateCount == -1)
			m_pStatusListCtrl->DeleteAllItems();*/
		iUpdateCount++;
		//csStringToDisPlay = theApp.m_pResMgr->GetString(_T("IDS_PRODUCT_AVAIL"));
		//m_pStatusListCtrl->InsertItem(iUpdateCount, csStringToDisPlay, 0);
		m_objIndexOfDownload.AppendItem(ENUM_DT_PRODUCT, iUpdateCount);
	}

	if(!CheckVersionNumber(theApp.m_csProductDetailsX64))
	{
		/*if(iUpdateCount == -1)
			m_pStatusListCtrl->DeleteAllItems();*/
		iUpdateCount++;
		//csStringToDisPlay = theApp.m_pResMgr->GetString(_T("IDS_PRODUCT_AVAIL"));
		//m_pStatusListCtrl->InsertItem(iUpdateCount, csStringToDisPlay, 0);
		m_objIndexOfDownload.AppendItem(ENUM_DT_PRODUCT_X64, iUpdateCount);
	}	

	if( m_bDataBase || m_bSDK || m_bSDKX64 || m_bUpdateVersion || m_bUpdateVersionX64 || m_bProduct || m_bProductX64
		|| m_bVirus || m_bVirusX64 || m_bDataBasePatch)
	{
		return true;
	}

	return false;
}

TCHAR* DownloadManagerSDK::GetModuleFilePath()
{
	TCHAR *szModulePath = new TCHAR[MAX_PATH];
	DWORD dwSize = MAX_PATH;
	int iErrorCode = GetModuleFileName(NULL,szModulePath,dwSize);
	if(iErrorCode == ERROR_INSUFFICIENT_BUFFER)
	{
		delete szModulePath;
		szModulePath = new TCHAR[dwSize];
		GetModuleFileName(NULL,szModulePath,dwSize);
	}
	CString csModulePath(szModulePath);
	csModulePath = csModulePath.Left(csModulePath.ReverseFind(L'\\'));
	_stprintf_s(szModulePath,dwSize,csModulePath);
	return szModulePath;
}

BOOL DownloadManagerSDK::CheckVersionNumber(CString csSectionName)
{
	CString csLocalVersion = _T("");
	CString csServerVersion = _T("");
	bool bOldDB = false;
	BOOL bRetVal = TRUE;
	CRegistry objReg;
	if(csSectionName.IsEmpty())
	{
		return bRetVal;
	}
	//CSDKSettings objSettings;
	if(csSectionName == theApp.m_csDeltaDetails)
	{
		GetPrivateProfileString(csSectionName, _T("Max_Ver"), _T("0"), csServerVersion.GetBuffer(100), 100, m_csVersionINI);
		csServerVersion.ReleaseBuffer();
		if(csServerVersion == _T("0"))
		{
			AddLogEntry(_T("Invalid Max version no"));
			GetPrivateProfileString(theApp.m_csDatabaseDetails, _T("VersionNo"), _T("0"), csServerVersion.GetBuffer(100), 100, m_csVersionINI);
			csServerVersion.ReleaseBuffer();
			bOldDB = true;
			
		}
	}
	else if(csSectionName == theApp.m_csUpdtVerDetails)
	{
		GetPrivateProfileString(csSectionName, _T("Max_Ver"), _T("0.0.0.0"), csServerVersion.GetBuffer(100), 100, m_csVersionINI);
		csServerVersion.ReleaseBuffer();
		if(csServerVersion == _T("0.0.0.0"))
		{
			AddLogEntry(_T("Invalid max version for update version, no update versions available"));
		}
	}
	else if(csSectionName == theApp.m_csUpdtVerDetailsX64)
	{
		GetPrivateProfileString(csSectionName, _T("Max_Ver"), _T("0.0.0.0"), csServerVersion.GetBuffer(100), 100, m_csVersionINI);
		csServerVersion.ReleaseBuffer();
		if(csServerVersion == _T("0.0.0.0"))
		{
			AddLogEntry(_T("Invalid max version for update version, no update versions available"));
		}
	}
	else
	{
		GetPrivateProfileString(csSectionName, _T("VersionNo"), _T("0"), csServerVersion.GetBuffer(100), 100, m_csVersionINI);
		csServerVersion.ReleaseBuffer();
	}

	CString csKey = _T("");
	if(csSectionName == theApp.m_csProductDetails || csSectionName == theApp.m_csProductDetailsX64)
	{
		csKey = PRODUCTVERREGKEY;
		CString csIsProductPatchAllow = _T("");
		GetPrivateProfileString(csSectionName, _T("ProductAllow"), _T("0"),	csIsProductPatchAllow.GetBuffer(100), 100, m_csVersionINI);
		csIsProductPatchAllow.ReleaseBuffer();
		
	}
	else if(csSectionName == theApp.m_csDatabaseDetails || csSectionName == theApp.m_csDeltaDetails)
	{
		csKey = DATABASEREGKEY;
	}
	else if(csSectionName == theApp.m_csVirusDetails || csSectionName == theApp.m_csVirusDetailsX64)
	{
		csKey = VIRUSREGKEY;
	}
	else if(csSectionName == theApp.m_csUpdtVerDetails || csSectionName == theApp.m_csUpdtVerDetailsX64)
	{
		csKey = UPDATEVERSION;
	}
	
	csLocalVersion = L"";
	objReg.Get(CSystemInfo::m_csProductRegKey, csKey, csLocalVersion, HKEY_LOCAL_MACHINE);
	
	if( csSectionName == theApp.m_csProductDetails || csSectionName == theApp.m_csProductDetailsX64 ||
		csSectionName == theApp.m_csVirusDetails || csSectionName == theApp.m_csVirusDetailsX64 || 
		csSectionName == theApp.m_csSDKDetails || csSectionName == theApp.m_csSDKDetailsX64 || csSectionName == theApp.m_csCloudServDetails || 
		csSectionName == theApp.m_csCloudControlServDetails)
	{
		csLocalVersion.Replace(_T("."), _T(""));
		csServerVersion.Replace(_T("."), _T(""));
		

		DWORD dwLocalVer=_wtoi(csLocalVersion);
		DWORD dwServerVer=_wtoi(csServerVersion);

		
		if((dwLocalVer < dwServerVer))
		{
			CString csFileName = m_objCommonFunctions.GetFileName(csSectionName, m_csVersionINI);
			AddLogEntry(_T("###File Name: %s"),csFileName);
			if(IsFileAlreadyDownloaded(csSectionName, L"MD5", csFileName))
				return TRUE;
			else if(csSectionName == theApp.m_csVirusDetails)
			{
				m_csVirusFileName1 = csFileName;
				m_bVirus=true;
			}
			else if(csSectionName == theApp.m_csVirusDetailsX64)
			{
				m_csVirusFileName2 = csFileName;
				m_bVirusX64=true;
			}
			else if(csSectionName == theApp.m_csProductDetails)
			{
				m_csProductFileName1 = csFileName;
				m_bProduct = true;				
			}
			else if(csSectionName == theApp.m_csProductDetailsX64)
			{
				m_csProductFileName2 = csFileName;
				m_bProductX64 = true;				
			}
			UpdateDownloadSize(csSectionName);
			return FALSE;
		}
		else
		{
			return TRUE;
		}
	}
	else if(csSectionName == theApp.m_csDeltaDetails)
	{
		objReg.Get(CSystemInfo::m_csProductRegKey, csKey, csLocalVersion, HKEY_LOCAL_MACHINE);
		/*
		GetPrivateProfileString(_T("ProductSetting"), _T("DatabaseVersion"), _T("0"), csLocalVersion.GetBuffer(100), 100, m_csSettingIniPath);
		*/
		csLocalVersion.ReleaseBuffer();

		if(!csLocalVersion.Replace(_T("."), _T("")))
		{
			AddLogEntry(_T("Invalid Local version no"));
			return TRUE;
		}
		if(!csServerVersion.Replace(_T("."), _T("")))
		{
			AddLogEntry(_T("Invalid Max version no"));
			return TRUE;
		}
		DWORD dwLocalVer=_wtoi(csLocalVersion);
		DWORD dwServerVer=_wtoi(csServerVersion);

		if((dwLocalVer<dwServerVer))
		{
			CString csBaseVersion = _T("");
			GetPrivateProfileString(csSectionName, _T("Base_Ver"), _T("0"),
								csBaseVersion.GetBuffer(100), 100, m_csVersionINI);
			csBaseVersion.ReleaseBuffer();
			if(!csBaseVersion.Replace(_T("."), _T("")))
			{
				AddLogEntry(_T("Invalid Base version no"));
			}
			DWORD dwBaseVer=_wtoi(csBaseVersion);
			if(dwLocalVer<dwBaseVer || bOldDB)
			{
				CString  csOldServerVersion=_T("");
				GetPrivateProfileString(theApp.m_csDatabaseDetails, _T("VersionNo"), _T("0"),
							csOldServerVersion.GetBuffer(100), 100, m_csVersionINI);
				csOldServerVersion.ReleaseBuffer();
				csOldServerVersion.Replace(_T("."), _T(""));
				DWORD dwOldServerVersion = _wtoi(csOldServerVersion);

				if(dwOldServerVersion<=dwLocalVer)
				{
					return TRUE;
				}

				m_bDownLoadFullPatch=true;
				CString csFullDBFileNme=m_objCommonFunctions.GetFileName(theApp.m_csDatabaseDetails, m_csVersionINI);
				AddLogEntry(_T("###File Name: %s"),csFullDBFileNme);
				if(!IsFileAlreadyDownloaded(theApp.m_csDatabaseDetails, L"MD5", csFullDBFileNme))
				{
					csSectionName = theApp.m_csDatabaseDetails;
					m_csDBFileNames.Add(csFullDBFileNme);
					bRetVal = FALSE;
				}
			}
			else
			{
				//CString csDestFile = m_csDownLoadPath + _T("\\") + TEMP_LIVEUPDATE + L"\\" + INI_DELTASERVER_FILE_NAME;
				CString csDestFile = m_csDownLoadPath + TEMP_LIVEUPDATE + L"\\" + INI_DELTASERVER_FILE_NAME;
				CDownloadManagerEx objDownloadManagerEx(1);
				bool bDownloadDeltaFile = false;
				if(!theApp.m_bLocalServerUpdate)
				{
					if (!bDownloadDeltaFile)
					{
						AddLogEntry(_T(">>>>> DOWNLOADING: HTTP DeltaServerVersion"));
						bDownloadDeltaFile = objDownloadManagerEx.DownloadURLUsingHTTP(SERVER_VERSIONFILE_HTTPDELTA, csDestFile);
					}
					if (!bDownloadDeltaFile)
					{
						AddLogEntry(_T(">>>>> DOWNLOADING: HTTP Default DeltaServerVersion"));
						bDownloadDeltaFile = objDownloadManagerEx.DownloadURLUsingHTTP(DEFAULT_SVR_VERSIONFILE_HTTPDELTA, csDestFile);
					}
					if (!bDownloadDeltaFile)
					{
						AddLogEntry(_T(">>>>> DOWNLOADING: FTP DeltaServerVersion"));
						bDownloadDeltaFile = objDownloadManagerEx.DownloadURLUsingFTP(SERVER_VERSIONFILEDELTA, csDestFile);
					}
					if (!bDownloadDeltaFile)
					{
						AddLogEntry(_T(">>>>> DOWNLOADING: FTP Default DeltaServerVersion"));
						bDownloadDeltaFile = objDownloadManagerEx.DownloadURLUsingFTP(DEFAULT_SVR_VERSIONFILEDELTA, csDestFile);
					}
				}
				else
				{
					AddLogEntry(_T(">>>>> DOWNLOADING: Local IP Server DeltaServerVersion"));
					bDownloadDeltaFile = objDownloadManagerEx.DownloadURLUsingHTTP(theApp.m_csLocalServerPath+L"/DeltaServerVersion.txt", csDestFile);
				}
				if(!bDownloadDeltaFile)
					return false;
				int iVerDiff=dwServerVer-dwLocalVer;
				if(iVerDiff > m_iMaxNoOfDeltaToDownload)
					iVerDiff = m_iMaxNoOfDeltaToDownload;
				for(int i=1;i<=iVerDiff;i++)
				{
					DWORD dwNewVer=dwLocalVer+i;
					CString csNewVerFileName=_T("");
					//csNewVerFileName.Format(_T("SDDatabase%d"), dwNewVer);		12-April-2016 Delta changes: Ravi
					/*if(theApp.m_iUseCloudScanning == 1)
					{
						csNewVerFileName.Format(_T("SDDatabaseCL%d"), dwNewVer);
					}
					else*/
					//{
						csNewVerFileName.Format(_T("SDDatabaseDB%d"), dwNewVer);
					//}
					csNewVerFileName+=_T(".db");

					CString csKeyName = GetDeltaVersion(csNewVerFileName);
					csKeyName += (L"_MD5");

					if(!IsFileAlreadyDownloaded(csSectionName, csKeyName, csNewVerFileName))
					{
						m_csDBFileNames.Add(csNewVerFileName);
						bRetVal = FALSE;
					}
				}
			}
			if(!bRetVal)
			{
				m_bDataBase=true;
				UpdateDownloadSize(csSectionName);
			}
		}
	}	
	else if(csSectionName == theApp.m_csUpdtVerDetailsX64)
	{
		BOOL bRetVal = TRUE;

		if(!csLocalVersion.Replace(_T("."), _T("")))
		{
			AddLogEntry(_T("Invalid Local version no"));
			return TRUE;
		}

		if(!csServerVersion.Replace(_T("."), _T("")))
		{
			AddLogEntry(_T("Invalid Max version no"));
			return TRUE;
		}

		DWORD dwLocalVer=_wtoi(csLocalVersion);
		DWORD dwServerVer=_wtoi(csServerVersion);

		
		if((dwLocalVer < dwServerVer))
		{
			DWORD dwServerProductVersion = 0, dwLocalProductVersion = 0;
			CString csLocalProductVersion = BLANKSTRING, csServerProductVersion = BLANKSTRING;
			
			//csLocalProductVersion = objSettings.GetProductSettingsString(PRODUCT_SETTINGS,PRODUCTVERSION);
			CRegistry objReg;
			objReg.Get(CSystemInfo::m_csProductRegKey, _T("ProductVersionNo"), csLocalProductVersion, HKEY_LOCAL_MACHINE);

			GetPrivateProfileString(theApp.m_csProductDetailsX64, _T("VersionNo"), _T("0.0.0.0"), csServerProductVersion.GetBuffer(100), 100, m_csVersionINI);
			csServerProductVersion.ReleaseBuffer();

			if(!csServerProductVersion.Replace(_T("."), _T("")))
			{
				AddLogEntry(_T("Invalid product version no in ServerVersion"));
			}

			if(!csLocalProductVersion.Replace(_T("."), _T("")))
			{
				AddLogEntry(_T("Invalid local product version"));
			}

			dwServerProductVersion = _wtoi(csServerProductVersion);
			dwLocalProductVersion = _wtoi(csLocalProductVersion);

			if(dwLocalProductVersion >= dwServerProductVersion || theApp.m_bStandaloneDownload)
			{
				int iMaxUpdateVersions = 0, iVerDiff = 0;
				CString csUVSecName, csUVFileName, csUVMD5;

				iMaxUpdateVersions = GetPrivateProfileInt(csSectionName, _T("Max_Updates"), 0, m_csVersionINI);
				if(0 == iMaxUpdateVersions)
				{
					//20 should be a good number for maximum number of exe patches to be executed at one go
					iMaxUpdateVersions = 20;
				}

				iVerDiff = dwServerVer - dwLocalVer;
				iVerDiff = iVerDiff > iMaxUpdateVersions? iMaxUpdateVersions: iVerDiff;

				for(int i = 1; i <= iVerDiff; i++)
				{
					//#ifdef WIN64
					csUVSecName.Format(_T("UPD_%uX64"), dwLocalVer + i);
					csUVSecName.Insert(4 + 1, _T("."));
					csUVSecName.Insert(4 + 3, _T("."));
					csUVSecName.Insert(4 + 5, _T("."));
					csUVFileName.Format(_T("%s.exe"), csUVSecName);

					GetPrivateProfileString(csUVSecName, _T("md5"), _T("00"), csUVMD5.GetBuffer(100), 100, m_csVersionINI);
					csUVMD5.ReleaseBuffer();

					AddLogEntry(_T("###UV File Name: %s"), csUVFileName);
					if(!IsFileAlreadyDownloaded(csUVSecName, _T("MD5"), csUVFileName))
					{
						m_csUpdtVerFileNamesX64.Add(csUVFileName);
						bRetVal = FALSE;
					}
				}
			}

			if(!bRetVal)
			{
				m_bUpdateVersionX64 = true;
				UpdateDownloadSize(csSectionName);
			}
		}

		return bRetVal;
	}
	else if(csSectionName == theApp.m_csUpdtVerDetails)
	{
		BOOL bRetVal = TRUE;

		if(!csLocalVersion.Replace(_T("."), _T("")))
		{
			AddLogEntry(_T("Invalid Local version no"));
			return TRUE;
		}

		if(!csServerVersion.Replace(_T("."), _T("")))
		{
			AddLogEntry(_T("Invalid Max version no"));
			return TRUE;
		}

		DWORD dwLocalVer=_wtoi(csLocalVersion);
		DWORD dwServerVer=_wtoi(csServerVersion);

		if((dwLocalVer < dwServerVer))
		{
			DWORD dwServerProductVersion = 0, dwLocalProductVersion = 0;
			CString csLocalProductVersion = BLANKSTRING, csServerProductVersion = BLANKSTRING;
			
			//csLocalProductVersion = objSettings.GetProductSettingsString(PRODUCT_SETTINGS,PRODUCTVERSION);
			CRegistry objReg;
			objReg.Get(CSystemInfo::m_csProductRegKey, _T("ProductVersionNo"), csLocalProductVersion, HKEY_LOCAL_MACHINE);
			GetPrivateProfileString(theApp.m_csProductDetails, _T("VersionNo"), _T("0.0.0.0"), csServerProductVersion.GetBuffer(100), 100, m_csVersionINI);
			csServerProductVersion.ReleaseBuffer();

			if(!csServerProductVersion.Replace(_T("."), _T("")))
			{
				AddLogEntry(_T("Invalid product version no in ServerVersion"));
			}

			if(!csLocalProductVersion.Replace(_T("."), _T("")))
			{
				AddLogEntry(_T("Invalid local product version "));
			}

			dwServerProductVersion = _wtoi(csServerProductVersion);
			dwLocalProductVersion = _wtoi(csLocalProductVersion);

			if(dwLocalProductVersion >= dwServerProductVersion || theApp.m_bStandaloneDownload)
			{
				int iMaxUpdateVersions = 0, iVerDiff = 0;
				CString csUVSecName, csUVFileName, csUVMD5;

				iMaxUpdateVersions = GetPrivateProfileInt(csSectionName, _T("Max_Updates"), 0, m_csVersionINI);
				if(0 == iMaxUpdateVersions)
				{
					//20 should be a good number for maximum number of exe patches to be executed at one go
					iMaxUpdateVersions = 20;
				}

				iVerDiff = dwServerVer - dwLocalVer;
				iVerDiff = iVerDiff > iMaxUpdateVersions? iMaxUpdateVersions: iVerDiff;

				for(int i = 1; i <= iVerDiff; i++)
				{
					//#ifdef WIN64

					//#else
					csUVSecName.Format(_T("UPD_%u"), dwLocalVer + i);
					csUVSecName.Insert(4 + 1, _T("."));
					csUVSecName.Insert(4 + 3, _T("."));
					csUVSecName.Insert(4 + 5, _T("."));
					csUVFileName.Format(_T("%s.exe"), csUVSecName);
					//#endif

					GetPrivateProfileString(csUVSecName, _T("md5"), _T("00"), csUVMD5.GetBuffer(100), 100, m_csVersionINI);
					csUVMD5.ReleaseBuffer();

					AddLogEntry(_T("###UV File Name: %s"), csUVFileName);
					if(!IsFileAlreadyDownloaded(csUVSecName, _T("MD5"), csUVFileName))
					{
						m_csUpdtVerFileNames.Add(csUVFileName);
						bRetVal = FALSE;
					}
				}
			}

			if(!bRetVal)
			{
				m_bUpdateVersion = true;

				UpdateDownloadSize(csSectionName);
			}
		}

		return bRetVal;
	}
	return bRetVal;
}

DWORD DownloadManagerSDK::UpdateDownloadSize(CString csSectionName)
{
	DWORD dwRetVal = 0;

	//CString csVersionINI;
	//csVersionINI.Format(_T("%s\\%s"), GetModuleFilePath(), INI_FILE_NAME);

	if(csSectionName == theApp.m_csDeltaDetails)
	{
		int iTotalDBs = (int)m_csDBFileNames.GetCount();
		CString csDeltaVersionINI = m_csVersionINI;
		CString csDeltaINI;
		csDeltaINI = INI_DELTASERVER_FILE_NAME;
		csDeltaVersionINI.Replace(INI_FILE_NAME,csDeltaINI);
		for(int iCount=0 ; iCount<iTotalDBs ; iCount++)
		{
			CString csDeltaVerNo = GetDeltaVersion(m_csDBFileNames.GetAt(iCount));
			CString csFileSize;
			GetPrivateProfileString(theApp.m_csDeltaDetails, csDeltaVerNo, L"0", csFileSize.GetBuffer(100), 100, csDeltaVersionINI);
			csFileSize.ReleaseBuffer();
			dwRetVal += (DWORD)_wtol(csFileSize);
		}
	}
	else if(csSectionName == theApp.m_csUpdtVerDetails)
	{
		int iTotalDBs = 0;
		CString csUVSectionName, csFileSize;

		iTotalDBs = (int)m_csUpdtVerFileNames.GetCount();
		for(int iCount = 0; iCount < iTotalDBs; iCount++)
		{
			csUVSectionName = m_csUpdtVerFileNames.GetAt(iCount);
			csUVSectionName.Replace(_T(".exe"), BLANKSTRING);
			GetPrivateProfileString(csUVSectionName, _T("UpdateSize"), _T("0"), csFileSize.GetBuffer(100), 100, m_csVersionINI);
			csFileSize.ReleaseBuffer();
			dwRetVal += (DWORD)_wtol(csFileSize);
		}
	}
	else if(csSectionName == theApp.m_csUpdtVerDetailsX64)
	{
		int iTotalDBs = 0;
		CString csUVSectionName, csFileSize;

		iTotalDBs = (int)m_csUpdtVerFileNamesX64.GetCount();
		for(int iCount = 0; iCount < iTotalDBs; iCount++)
		{
			csUVSectionName = m_csUpdtVerFileNamesX64.GetAt(iCount);
			csUVSectionName.Replace(_T(".exe"), BLANKSTRING);
			GetPrivateProfileString(csUVSectionName, _T("UpdateSize"), _T("0"), csFileSize.GetBuffer(100), 100, m_csVersionINI);
			csFileSize.ReleaseBuffer();
			dwRetVal += (DWORD)_wtol(csFileSize);
		}
	}
	else	//Patches & Misc (SD38.db)
	{
		CString csUpdateSize;
		GetPrivateProfileString(csSectionName, L"UpdateSize", L"", csUpdateSize.GetBuffer(10), 10, m_csVersionINI);
		csUpdateSize.ReleaseBuffer();
		dwRetVal = (DWORD)_wtol(csUpdateSize);
	}


	if(dwRetVal > 0)
	{
		m_dwTotalDownloadSize += dwRetVal;
	}
	return dwRetVal;
}

/*--------------------------------------------------------------------------------------
Function       : IsFileAlreadyDownloaded
In Parameters  : CString
Out Parameters : BOOL 
Description    : 
Author         : Swapnil D. Lokande
--------------------------------------------------------------------------------------*/
BOOL DownloadManagerSDK::IsFileAlreadyDownloaded(CString csSectionName, CString csKeyName, CString csFileName, CString * pcsFilePath)
{
	BOOL bRetVal = FALSE;

	CString csDest = theApp.m_csWaitingForMergePath + L"\\";
	if(csKeyName.CompareNoCase(L"MD5"))
	{
		if((csSectionName == theApp.m_csDeltaDetails))
		{
			csDest += L"Data\\";
		}
	}

	CString csFilePath = csDest + csFileName;
	bool bSplittedDBsFound = false;
	if(csFileName.Find(_T("SD43")) != -1)
	{
		csDest += L"Data\\";
		bSplittedDBsFound = CheckForSplittedDBs(csDest);
		if(bSplittedDBsFound)
		{	
			AddLogEntry(L"%s File Already downloaded, so skipping download!!!", csFileName, 0, true, LOG_WARNING);
			bRetVal = TRUE;
			return bRetVal;
		}
		else
		{
			bRetVal = FALSE;
			return bRetVal;
		}
	}
	else
	{
		if(GetFileAttributes(csFilePath) == 0xFFFFFFFF)
		{
			if(theApp.m_bStandaloneDownload)
			{
				return bRetVal;
			}
			if((csSectionName != theApp.m_csDeltaDetails))
			{
				csFilePath = CSystemInfo::m_strAppPath[0];
				csFilePath += _T(":\\AuLiveUpdate\\");
				csFilePath += csFileName;
				if(GetFileAttributes(csFilePath) == 0xFFFFFFFF)
				{
					return bRetVal;
				}
			}			
			else
			{
			  return bRetVal;
			}
		}
	}
	//This will take care of change in file version as well since change in file will also change MD5
	//AddLogEntry(_T("Pavan 9"));
	CString csMD5;
	GetPrivateProfileString(csSectionName, csKeyName, L"", csMD5.GetBuffer(100), 100, m_csVersionINI);
	csMD5.ReleaseBuffer();
	if(csMD5.IsEmpty())
	{
		GetPrivateProfileString(csSectionName, csKeyName, L"", csMD5.GetBuffer(100), 100, m_csDeltaVersionINI);
		csMD5.ReleaseBuffer();
	}

	TCHAR szMD5[MAX_PATH]={0};
	CCommonFileIntegrityCheck objCreateSignature(_T(""));
	objCreateSignature.GetSignature(csFilePath.GetBuffer(1000), szMD5);
	csFilePath.ReleaseBuffer();
	if(!csMD5.CompareNoCase(szMD5))
	{
		//AddLogEntry(_T("Pavan 10"));
		AddLogEntry(L"%s File Already downloaded, so skipping download!!!", csFileName, 0, true, LOG_WARNING);
		bRetVal = TRUE;
		if(pcsFilePath)
		{
			*pcsFilePath = csFilePath;
		}
	}

	return bRetVal;
}

/*-------------------------------------------------------------------------------------
Function		: GetDeltaVersion
In Parameters	: CString
Out Parameters	: CString
Purpose			: This function get the delta version from the delta file name
Author			: Sandip Sanap
--------------------------------------------------------------------------------------*/
CString DownloadManagerSDK::GetDeltaVersion(const CString & csFileName)
{
	try
	{
		CString csDeltaVerNo = csFileName;
		//csDeltaVerNo.Replace(_T("SDDatabase"), _T(""));			12-April-2016 Delta changes: Ravi
		//csDeltaVerNo.Replace(_T("SDDatabaseCL"), _T(""));
		csDeltaVerNo.Replace(_T("SDDatabaseDB"), _T(""));
		csDeltaVerNo.Replace(_T(".db"), _T(""));
		csDeltaVerNo.Insert(2, _T("."));
		csDeltaVerNo.Insert(4, _T("."));
		csDeltaVerNo.Insert(6, _T("."));
		return csDeltaVerNo;
	}
	catch(...)
	{
		AddLogEntry(L"Error occoured in CDownloadManager::GetDeltaVersion");
	}
	return BLANKSTRING;

}

bool DownloadManagerSDK::CheckForSplittedDBs(CString &csDestPath)
{
	TCHAR	szFileName[MAX_PATH];
	int		iAccessFlag	= 0;
	bool	bFileExist	= true;
	for(int iIndex = 0x00; iIndex <= 0x0F; iIndex++)
	{
		_stprintf_s(szFileName, MAX_PATH, _T("SD43_%0.1X.db"), iIndex);
		iAccessFlag		= _taccess_s(csDestPath + szFileName, 0);
		
		if(iAccessFlag != 0)
		{
			AddLogEntry(_T("CheckForSplittedDBs : File Doesnt exist : %s"), szFileName);
			bFileExist = false;
			break;
		}
		_stprintf_s(szFileName, MAX_PATH, _T("SD43_%0.1XT.db"), iIndex);
		iAccessFlag		= _taccess_s(csDestPath + szFileName, 0);
		
		if(iAccessFlag != 0)
		{
			AddLogEntry(_T("CheckForSplittedDBs : File Doesnt exist : %s"), szFileName);
			bFileExist = false;
			break;
		}
	}
	return bFileExist;
}

bool DownloadManagerSDK::DownloadHTTPFiles()
{
	int iType = -1;
	bool bRet = true, cDeltaFileCopyFlag = false;
	CStringArray  csFileNameArray;
	CString		csSectionName = _T("");
	CString		csTempVerNo;
	CString		csMsg = CSystemInfo::m_csProductName;
	CString		csStringToDisPlay = _T("");
	
	try
	{
		m_objDownloadStartTime = CTime::GetCurrentTime();

		m_bUpdateStatus = TRUE;
		if(m_pStatusThread)
		{
			SuspendThread(m_pStatusThread->m_hThread);

			delete m_pStatusThread;
			m_pStatusThread = NULL;
		}
		m_pStatusThread = AfxBeginThread(ThreadUpdateStatus, (LPVOID)this, 0, 0, CREATE_SUSPENDED);
		if(m_pStatusThread)
		{
			m_pStatusThread->m_bAutoDelete = FALSE;
			m_pStatusThread->ResumeThread();
		}

		for(iType = ENUM_DT_MERGER; iType <= ENUM_DT_PRODUCT_X64; iType++)
		{
			bool bDBMD5 = false, bUpdtVer = false;
			CString type;

			csFileNameArray.RemoveAll();
			csSectionName = L"";
			//Set the initial status of downloading of the particular patch
			SetInitialStatusText(iType, csFileNameArray, csSectionName);

			if(iType == ENUM_DT_PRODUCT)
			{
				if(!m_bProduct)
				{
					break;
				}
			}
			else if(iType == ENUM_DT_PRODUCT_X64)
			{				
				if(!m_bProductX64)
				{
					break;
				}
			}	

			DWORD dwTotalSize=0;
			CString csMD5 = _T("");
			CString csFileSize=_T("");
			CString csFileVersion = _T("");
			DWORD *pdwDBFileSizeArray = new DWORD[m_iMaxNoOfDeltaToDownload];
			CStringArray strDBMD5Array, csArrUpdtVerSize, csArrUpdtVerMD5;
			CStringArray strArrFileVersion;
			CString csIniVerName;

			if(iType == ENUM_DT_DATABASE && !m_bDownLoadFullPatch)
			{
				bDBMD5 = true;
				cDeltaFileCopyFlag = true;
				CString csDeltaVersionINI = m_csVersionINI;
				CString csDeltaINI;
				csDeltaINI = INI_DELTASERVER_FILE_NAME;
				csDeltaVersionINI.Replace(INI_FILE_NAME,csDeltaINI);
				csIniVerName = _T("DatabaseVersion");
				for(int i=0;i<csFileNameArray.GetCount();i++)
				{
					CString csDeltaVerNo = GetDeltaVersion(csFileNameArray.GetAt(i));
					strArrFileVersion.Add(csDeltaVerNo);
					csFileSize=_T("");
					GetPrivateProfileString(csSectionName, csDeltaVerNo, _T("0"),
						csFileSize.GetBuffer(100), 100, csDeltaVersionINI);
					csFileSize.ReleaseBuffer();
					pdwDBFileSizeArray[i] = _wtoi(csFileSize);
					CString csMD5Key = csDeltaVerNo += _T("_md5");
					TCHAR szMD5[100] = {0};
					GetPrivateProfileString(csSectionName, csMD5Key, _T(""),
						szMD5, 100, csDeltaVersionINI);
					szMD5[32] = L'\0';
					strDBMD5Array.Add(szMD5);
					
				}
			}
			else if(iType == ENUM_DT_UPDATE_VERSION)
			{
				CString csUVMD5, csUVSize, csUVSection;
				csIniVerName = _T("UpdateVersion");
				bUpdtVer = true;
				for(int i = 0, iCount = (int)csFileNameArray.GetCount(); i < iCount; i++)
				{
					csUVMD5 = csUVSize = csUVSection = BLANKSTRING;
					csUVSection = csFileNameArray.GetAt(i);
					csUVSection.Replace(_T(".exe"), _T(""));

					GetPrivateProfileString(csUVSection, _T("MD5"), BLANKSTRING, csUVMD5.GetBuffer(100), 100, m_csVersionINI);
					csUVMD5.ReleaseBuffer();
					GetPrivateProfileString(csUVSection, _T("UpdateSize"), BLANKSTRING, csUVSize.GetBuffer(100), 100, m_csVersionINI);
					csUVSize.ReleaseBuffer();
					csArrUpdtVerMD5.Add(csUVMD5);
					csArrUpdtVerSize.Add(csUVSize);
					csUVSection.Replace(_T("UPD_"), _T(""));
					strArrFileVersion.Add(csUVSection);
				}
			}
			else if(iType == ENUM_DT_UPDATE_VERSION_X64)
			{
				CString csUVMD5, csUVSize, csUVSection;
				csIniVerName = _T("UpdateVersion");
				bUpdtVer = true;
				for(int i = 0, iCount = (int)csFileNameArray.GetCount(); i < iCount; i++)
				{
					csUVMD5 = csUVSize = csUVSection = BLANKSTRING;
					csUVSection = csFileNameArray.GetAt(i);
					csUVSection.Replace(_T(".exe"), _T(""));

					GetPrivateProfileString(csUVSection, _T("MD5"), BLANKSTRING, csUVMD5.GetBuffer(100), 100, m_csVersionINI);
					csUVMD5.ReleaseBuffer();
					GetPrivateProfileString(csUVSection, _T("UpdateSize"), BLANKSTRING, csUVSize.GetBuffer(100), 100, m_csVersionINI);
					csUVSize.ReleaseBuffer();
					csArrUpdtVerMD5.Add(csUVMD5);
					csArrUpdtVerSize.Add(csUVSize);
					csUVSection.Replace(_T("UPD_"), _T(""));
					csUVSection.Replace(_T("X64"), _T(""));
					strArrFileVersion.Add(csUVSection);
				}
			}
			else if(iType != ENUM_DT_MISC)
			{
				GetPrivateProfileString(csSectionName, _T("UpdateSize"), _T(""), csFileSize.GetBuffer(100), 100, m_csVersionINI);
				csFileSize.ReleaseBuffer();

				dwTotalSize = _wtoi(csFileSize);
			}
			
			if(iType == ENUM_DT_VIRUS || iType == ENUM_DT_VIRUS_X64)
			{
				csIniVerName = _T("VirusVersionNo");
			}
			else if(iType == ENUM_DT_PRODUCT || iType == ENUM_DT_PRODUCT_X64)
			{
				csIniVerName = _T("ProductVersion");
			}
			
			GetPrivateProfileString(csSectionName, _T("MD5"), _T(""), csMD5.GetBuffer(100), 100, m_csVersionINI);
			csMD5.ReleaseBuffer();
			GetPrivateProfileString(csSectionName, _T("VersionNo"), _T(""), csFileVersion.GetBuffer(100), 100, m_csVersionINI);
			csFileVersion.ReleaseBuffer();			

			bool bsizeError=false;
			DWORD dwLocalFileSize=0;
			DWORD dwTotalFilesize=0;
			//CString csDestPath=m_csDownLoadPath + _T("\\") + TEMP_LIVEUPDATE + _T("\\");
			CString csDestPath=m_csDownLoadPath + TEMP_LIVEUPDATE + _T("\\");
			int iFilecount=(int)csFileNameArray.GetCount();

			
			for(int i = 0; i < iFilecount; i++)
			{
				if(iType == ENUM_DT_DATABASE && !m_bDownLoadFullPatch)
				{
					m_iFilecount = iFilecount;
					/*
					CString strTemp = L"Threat Definition updates are available";//IDS_DB_AVAIL_DEF
					csStringToDisPlay.Format(_T("  %d %s"), iFilecount, static_cast<LPCTSTR>(strTemp));
					*/
					//m_iEnumLabelStatus = UpdateMessages::AVAIL_DEF;
					dwTotalSize = pdwDBFileSizeArray[i];
					//strTemp = L"Downloading";//IDS_DOWNLOADING
					//CString strTemp1 = L"Threat Definition...";//IDS_THREAT_DEFS
					//csStringToDisPlay.Format(_T("  %s %d/%d %s"), static_cast<LPCTSTR>(strTemp), i+1,iFilecount, static_cast<LPCTSTR>(strTemp1));
					csStringToDisPlay.Format(L"%d/%d", i + 1, iFilecount);
					m_iEnumLabelStatus = UpdateMessages::FILECNT;
					DWORD dwInsertItemCount = 0;
					if(m_objIndexOfDownload.SearchItem(iType, dwInsertItemCount) == false)
					{
						dwInsertItemCount = ENUM_DT_DATABASE;
					}
					m_csDownloadedFiles = csStringToDisPlay;
				}
				if(iType == ENUM_DT_UPDATE_VERSION)
				{
					m_iFilecount = iFilecount;
					dwTotalSize = _ttoi(csArrUpdtVerSize.GetAt(i));
					/*
					CString strTemp = L"Product version updates are available";//IDS_UPDT_VER_AVAIL_DEF
					csStringToDisPlay.Format(_T("  %d %s"), iFilecount, static_cast<LPCTSTR>(strTemp));
					strTemp = L"Downloading"; //IDS_DOWNLOADING
					CString strTemp1 = L"Product version...";//IDS_UPDT_VER
					csStringToDisPlay.Format(_T("  %s %d/%d %s"), static_cast<LPCTSTR>(strTemp), i + 1,
												iFilecount, static_cast<LPCTSTR>(strTemp1));
												*/
					csStringToDisPlay.Format(L"%d/%d", i + 1, iFilecount);
					m_iEnumLabelStatus = UpdateMessages::FILECNT_UPDATE;
					DWORD dwInsertItemCount = 0;
					if(m_objIndexOfDownload.SearchItem(iType, dwInsertItemCount) == false)
					{
						dwInsertItemCount = ENUM_DT_UPDATE_VERSION;
					}
					/*m_pStatusListCtrl->SetItemText(dwInsertItemCount, 0, csStringToDisPlay);
					m_pStatusListCtrl->SetItemImage(dwInsertItemCount, 0, 6);*/
					m_csDownloadedFiles = csStringToDisPlay;
				}
				else if(iType == ENUM_DT_UPDATE_VERSION_X64)
				{
					m_iFilecount = iFilecount;
					dwTotalSize = _ttoi(csArrUpdtVerSize.GetAt(i));
					/*
					CString strTemp = L"Product version updates are available"; //IDS_UPDT_VER_AVAIL_DEF
					csStringToDisPlay.Format(_T("  %d %s"), iFilecount, static_cast<LPCTSTR>(strTemp));
					strTemp = L"Downloading";//IDS_DOWNLOADING
					CString strTemp1 = L"Product version...";//IDS_UPDT_VER
					csStringToDisPlay.Format(_T("  %s %d/%d %s"), static_cast<LPCTSTR>(strTemp), i + 1,
												iFilecount, static_cast<LPCTSTR>(strTemp1));
					*/

					csStringToDisPlay.Format(L"%d/%d", i + 1, iFilecount);
					m_iEnumLabelStatus = UpdateMessages::FILECNT_UPDATE;

					DWORD dwInsertItemCount = 0;
					if(m_objIndexOfDownload.SearchItem(iType, dwInsertItemCount) == false)
					{
						dwInsertItemCount = ENUM_DT_UPDATE_VERSION_X64;
					}
					//m_pStatusListCtrl->SetItemText(dwInsertItemCount, 0, csStringToDisPlay);
					//m_pStatusListCtrl->SetItemImage(dwInsertItemCount, 0, 6);
					m_csDownloadedFiles = csStringToDisPlay;
				}
				double fDownloadSizeInMB;
				CString sText;
				CString csSizeToDisplay=_T("");

				/*CString strTemp1 = theApp.m_pResMgr->GetString(_T("IDS_DWNLD_OK_OF"));*/
				if(dwTotalSize < (999*999))
				{
					fDownloadSizeInMB = ((double)dwTotalSize)/(1024);//*1024);
					/*sText.Format(_T("%s %6.2fKB"), static_cast<LPCTSTR>(strTemp1), fDownloadSizeInMB);
					csSizeToDisplay.Format(_T("%6.2f KB"), fDownloadSizeInMB);*/
				}
				else
				{
					fDownloadSizeInMB = ((double)dwTotalSize)/(1024*1024);
					/*sText.Format(_T("%s %6.2fKB"), static_cast<LPCTSTR>(strTemp1), fDownloadSizeInMB);
					csSizeToDisplay.Format(_T("%6.2f MB"), fDownloadSizeInMB);*/
				}
				DWORD dwInsertItemCount = 0;
				if(m_objIndexOfDownload.SearchItem(iType, dwInsertItemCount) == false)
				{
					dwInsertItemCount = iType;
				}
				//m_pStatus->SetWindowText(sText);
				//m_pStatusListCtrl->SetItemText(dwInsertItemCount, 1, csSizeToDisplay);

				CString csDest=csDestPath+csFileNameArray.GetAt(i);
				//AddLogEntry(_T(">>> Start Downloading File:  ") + csFileNameArray.GetAt(i));
				CString csSource=csFileNameArray.GetAt(i);

				CString csRemotePath = m_csLiveUpdatePath1 + csSource;
				//AddLogEntry(csRemotePath);
				CString csRemotePath2 = m_csLiveUpdatePath2 + csSource;
				//AddLogEntry(csRemotePath2);

				/*if(i == 0)
				{
					m_bAnimation = true;
					if(m_pAnimationThread)
					{
						SuspendThread(m_pAnimationThread->m_hThread);

						delete m_pAnimationThread;
						m_pAnimationThread = NULL;
					}
					m_pAnimationThread = AfxBeginThread(StartAnimation, this, THREAD_PRIORITY_NORMAL, NULL, CREATE_SUSPENDED, NULL);
					if(m_pAnimationThread)
					{
						m_pAnimationThread->m_bAutoDelete = FALSE;
						m_pAnimationThread->ResumeThread();
					}
				}*/

				try
				{
					CString strFileMD5;
					CString strFileVersion;
					if(bDBMD5)
					{
						strFileMD5 = strDBMD5Array.GetAt(i);
						strFileVersion = strArrFileVersion.GetAt(i);
					}
					else if(bUpdtVer)
					{
						strFileMD5 = csArrUpdtVerMD5.GetAt(i);
						strFileVersion = strArrFileVersion.GetAt(i);
					}
					else
					{
						strFileMD5 = csMD5;
						strFileVersion = csFileVersion;
					}

					bRet = DownloadRemoteFile(csRemotePath, csRemotePath2, csDest, dwTotalSize, iType, strFileMD5, csFileNameArray.GetAt(i));
				/*	if(m_pStatusThread)
					{
						m_pStatusThread->m_bAutoDelete = FALSE;
						m_pStatusThread->ResumeThread();
					}*/
					if(bRet)
					{
						m_dwTotalDownloadedSize += dwTotalSize;
						CDownloadManagerEx::m_dDownloadedFileSize = 0;

						AddLogEntry(L">>>File Downloaded Successfully: %s", csSource);

						CString csFileName = csDest.Mid(csDest.ReverseFind(L'\\') + 1);
						CString csExtn = csFileName.Right(3);
						if(csExtn.CompareNoCase(L"EXE"))
						{
							if(iType == ENUM_DT_DATABASE)
							{
								CString csMergeTempPath;
								//csMergeTempPath = m_csExtractFolderPath + _T("\\MergeTemp\\Data\\");
								csMergeTempPath = theApp.m_csWaitingForMergePath + L"\\Data\\";
								if(theApp.m_bStandaloneDownload)
								{
									csMergeTempPath = theApp.m_csWaitingForMergePath + L"\\";
								}
								CreateDirectory(csMergeTempPath, NULL);
								CopyFile(csDest,  csMergeTempPath + csFileName, FALSE);
								DeleteFile(csDest);
								if(!strFileVersion.IsEmpty() && theApp.m_bStandaloneDownload)
								{
									/*
									CSDKSettings objSettings;
									objSettings.SetProductSettings(PRODUCT_SETTINGS,csIniVerName,strFileVersion);
									*/
								}
							}
						}
						else
						{
							Sleep(5000);
							BOOL bCopyFlag = FALSE;
							int iError;
							CString csMergeTempPath;
							//csMergeTempPath = m_csExtractFolderPath + _T("\\MergeTemp\\Data\\");
							csMergeTempPath = theApp.m_csWaitingForMergePath + _T("\\");;
							CopyFileEx(csDest, csMergeTempPath + csFileName, NULL, NULL, &bCopyFlag, COPY_FILE_ALLOW_DECRYPTED_DESTINATION);
							iError = GetLastError();
							if(iError == 6)
							{
								Sleep(5000);
								CFile oFileSrc(csDest, CFile::modeRead);
								CFile oFileDst(csMergeTempPath + csFileName, CFile::modeWrite | CFile::modeCreate);
								
								UINT iCount = 1024;
								char *pszBuffer = NULL;
								pszBuffer = (char *)calloc(1024, sizeof(char)); 
								if(pszBuffer != NULL)
								{
									//AddLogEntry (_T("Going to write the file."));
									while((iCount = oFileSrc.Read(pszBuffer, iCount)) > 0)
									{								
										oFileDst.Write(pszBuffer, iCount);									
										memset(pszBuffer, 0x00, 1024 * sizeof(char));
									}
								}

								if(pszBuffer != NULL)
								{
									delete pszBuffer;
									pszBuffer = NULL;
								}
								
								oFileSrc.Close();
								oFileDst.Close();

							}
							if(!strFileVersion.IsEmpty() && theApp.m_bStandaloneDownload)
							{
								
							/*	if(iType == ENUM_DT_CLOUDSRVDETAILS || iType == ENUM_DT_CLOUDCONTSRVDETAILS)
								{
								}
								else*/
								if(iType ==  ENUM_DT_UPDATE_VERSION || iType ==  ENUM_DT_VIRUS || iType ==  ENUM_DT_PRODUCT)
								{
								}
								else if(!csIniVerName.IsEmpty())
								{
									/*
									CSDKSettings objSettings;
									objSettings.SetProductSettings(PRODUCT_SETTINGS,csIniVerName,strFileVersion);
									*/
								}
							}
						}
					}
				}
				catch (...)
				{
					AddLogEntry (_T("Exception occour for DownloadRemoteFile :%s"), csRemotePath);
					bRet = false;
				}

				if(i == iFilecount - 1 ||!bRet)
				{
					//m_bAnimation = false;
					Sleep(500);
				}

				if(!bRet)
				{
					dwLocalFileSize = 0;
					dwTotalFilesize = 0;
				}
				else
				{
					dwLocalFileSize = dwTotalSize;
					dwTotalFilesize = dwTotalSize;
				}

				if(iType == ENUM_DT_DATABASE && !m_bDownLoadFullPatch)
				{
					if(pdwDBFileSizeArray[i] != dwLocalFileSize || bsizeError || !bRet)
					{
						csStringToDisPlay = L"";//IDS_DB_DOWNLOADED_ERROR
						csStringToDisPlay = _T("  ") + csStringToDisPlay;
						m_iEnumLabelStatus = UpdateMessages::DWONLOAD_ERR;
						m_csDownloadedFiles = csStringToDisPlay;
						
						/*m_pStatusListCtrl->SetItemText(0, 0, csStringToDisPlay);
						m_pStatusListCtrl->SetItemImage(0, 0, 1);*/
						
						/*
						CString strTemp = L"Spyware Threat Definition downloaded!";//theApp.m_pResMgr->GetString(_T("IDS_DB_PART_DOWNLOADED"));//IDS_DB_DOWNLOADED
						csStringToDisPlay.Format(_T("  %d/%d %s"), i, iFilecount, static_cast<LPCTSTR>(strTemp));
						*/
						csStringToDisPlay.Format(_T("%d/%d"), i, iFilecount);
						m_iEnumLabelStatus = UpdateMessages::DB_PART_DOWNLOADED;
						m_csDownloadedFiles = csStringToDisPlay;
						
						
						

						/*m_pStatusListCtrl->SetItemText(ENUM_DT_DATABASE, 0, csStringToDisPlay);
						m_pStatusListCtrl->SetItemImage(ENUM_DT_DATABASE, 0, 1);*/
						//Remove this file from the array
						int iTemp = 0;
						for(iTemp=i; iTemp<m_csDBFileNames.GetCount(); iTemp++)
						{
							m_csDBFileNames.RemoveAt(iTemp);
							iTemp--;
							i++;
						}
					}
				}
				if(iType == ENUM_DT_UPDATE_VERSION)
				{
					DWORD dwUVFileSize = _ttoi(csArrUpdtVerSize.GetAt(i));
					if(dwUVFileSize != dwLocalFileSize || bsizeError || !bRet)
					{
						csStringToDisPlay = L"";// theApp.m_pResMgr->GetString(_T("IDS_UPDT_VER_DOWNLOADED_ERROR"));
						csStringToDisPlay = _T("  ") + csStringToDisPlay;
						//m_pStatusListCtrl->SetItemText(0, 0, csStringToDisPlay);
						//m_pStatusListCtrl->SetItemImage(0, 0, 1);
						m_iEnumLabelStatus = UpdateMessages::DWONLOAD_ERR;
						m_csDownloadedFiles = csStringToDisPlay;

						/*
						CString strTemp = L"Product version update downloaded!";// theApp.m_pResMgr->GetString(_T("IDS_UPDT_VER_PART_DOWNLOADED"));
						csStringToDisPlay.Format(_T("  %d/%d %s"), i, iFilecount, static_cast<LPCTSTR>(strTemp));
						*/
						//m_pStatusListCtrl->SetItemText(ENUM_DT_UPDATE_VERSION, 0, csStringToDisPlay);
						//m_pStatusListCtrl->SetItemImage(ENUM_DT_UPDATE_VERSION, 0, 1);

						m_iEnumLabelStatus = UpdateMessages::UPDT_VER_PART_DOWNLOADED;
						csStringToDisPlay.Format(_T("%d/%d"), i, iFilecount);
						m_csDownloadedFiles = csStringToDisPlay;
						//Remove all the files ahead of this file from the array
						for(int iTemp = i, iTotal = (int)m_csUpdtVerFileNames.GetCount(); iTemp < iTotal; iTemp++)
						{
							m_csUpdtVerFileNames.RemoveAt(iTemp);
							iTemp--;
							i++;
						}
					}
				}

				if(iType == ENUM_DT_UPDATE_VERSION_X64)
				{
					DWORD dwUVFileSize = _ttoi(csArrUpdtVerSize.GetAt(i));
					if(dwUVFileSize != dwLocalFileSize || bsizeError || !bRet)
					{
						csStringToDisPlay = L"";// theApp.m_pResMgr->GetString(_T("IDS_UPDT_VER_DOWNLOADED_ERROR"));
						csStringToDisPlay = _T("  ") + csStringToDisPlay;
						//m_pStatusListCtrl->SetItemText(0, 0, csStringToDisPlay);
						//m_pStatusListCtrl->SetItemImage(0, 0, 1);
						m_iEnumLabelStatus = UpdateMessages::DWONLOAD_ERR;
						m_csDownloadedFiles = csStringToDisPlay;

						/*
						CString strTemp = L"Product version update downloaded!";//theApp.m_pResMgr->GetString(_T("IDS_UPDT_VER_PART_DOWNLOADED"));
						csStringToDisPlay.Format(_T("  %d/%d %s"), i, iFilecount, static_cast<LPCTSTR>(strTemp));
						//m_pStatusListCtrl->SetItemText(ENUM_DT_UPDATE_VERSION_X64, 0, csStringToDisPlay);
						//m_pStatusListCtrl->SetItemImage(ENUM_DT_UPDATE_VERSION_X64, 0, 1);
						*/
						m_iEnumLabelStatus = UpdateMessages::UPDT_VER_PART_DOWNLOADED;
						csStringToDisPlay.Format(_T("%d/%d"), i, iFilecount);

						m_csDownloadedFiles = csStringToDisPlay;
						//Remove all the files ahead of this file from the array
						for(int iTemp = i, iTotal = (int)m_csUpdtVerFileNamesX64.GetCount(); iTemp < iTotal; iTemp++)
						{
							m_csUpdtVerFileNamesX64.RemoveAt(iTemp);
							iTemp--;
							i++;
						}
					}
				}

			}
			if((iType != ENUM_DT_DATABASE || m_bDownLoadFullPatch) && iType != ENUM_DT_MISC && iType != ENUM_DT_UPDATE_VERSION && iType != ENUM_DT_UPDATE_VERSION_X64)
			{
				if(dwTotalFilesize != dwTotalSize || bsizeError || !bRet)
				{
					//Set the downloaded Error Message depend on type
					SetDownloadedErrorStatusText(iType);
				}
			}

			//bRet = true;
			SetDownloadedSuccessStatusText(iType);
			if(iType == ENUM_DT_DATABASE && m_bDataBase && (int)m_csDBFileNames.GetCount() == iFilecount)
			{
				DWORD dwInsertItemCount = 0;
				if(m_objIndexOfDownload.SearchItem(iType, dwInsertItemCount) == false)
				{
					dwInsertItemCount = iType;
				}
				csStringToDisPlay = L"";//theApp.m_pResMgr->GetString(_T("IDS_DB_DOWNLOADED"));
				/*m_pStatusListCtrl->SetItemText(dwInsertItemCount, 0, csStringToDisPlay);
				m_pStatusListCtrl->SetItemImage(dwInsertItemCount, 0, 2);*/
				m_iEnumLabelStatus = UpdateMessages::DB_DOWNLOADED;
				m_csDownloadedFiles = csStringToDisPlay;
			}
			else if(iType == ENUM_DT_UPDATE_VERSION && m_bUpdateVersion && (int)m_csUpdtVerFileNames.GetCount() == iFilecount)
			{
				DWORD dwInsertItemCount = 0;
				if(m_objIndexOfDownload.SearchItem(iType, dwInsertItemCount) == false)
				{
					dwInsertItemCount = iType;
				}
				csStringToDisPlay = L"";//theApp.m_pResMgr->GetString(_T("IDS_UPDT_VER_DOWNLOADED"));
				/*m_pStatusListCtrl->SetItemText(dwInsertItemCount, 0, csStringToDisPlay);
				m_pStatusListCtrl->SetItemImage(dwInsertItemCount, 0, 2);*/
				m_iEnumLabelStatus = UpdateMessages::UPDT_VER_DOWNLOADED;
				m_csDownloadedFiles = csStringToDisPlay;
			}
			else if(iType == ENUM_DT_UPDATE_VERSION_X64 && m_bUpdateVersionX64 && (int)m_csUpdtVerFileNamesX64.GetCount() == iFilecount)
			{
				DWORD dwInsertItemCount = 0;
				if(m_objIndexOfDownload.SearchItem(iType, dwInsertItemCount) == false)
				{
					dwInsertItemCount = iType;
				}
				csStringToDisPlay = L"";//theApp.m_pResMgr->GetString(_T("IDS_UPDT_VER_DOWNLOADED"));
				/*m_pStatusListCtrl->SetItemText(dwInsertItemCount, 0, csStringToDisPlay);
				m_pStatusListCtrl->SetItemImage(dwInsertItemCount, 0, 2);*/
				m_iEnumLabelStatus = UpdateMessages::UPDT_VER_DOWNLOADED;
				m_csDownloadedFiles = csStringToDisPlay;
			}
			else if(m_csDBFileNames.GetCount() == 0)
			{
				m_bDataBase = false;
			}
			else if(m_csUpdtVerFileNames.GetCount() == 0)
			{
				m_bUpdateVersion = false;
			}
			else if(m_csUpdtVerFileNamesX64.GetCount() == 0)
			{
				m_bUpdateVersionX64 = false;
			}
			delete [] pdwDBFileSizeArray;
			pdwDBFileSizeArray = NULL;
			
		}
		m_bUpdateStatus = FALSE;

		if((!m_bDataBase && !m_bDataBasePatch && !m_bDataBasePatchCL && !m_bDataBasePatchX64 && !m_bUpdateVersion 
			&& !m_bUpdateVersionX64&& !m_bProduct && !m_bProductX64 &&  !m_bVirus && !m_bVirusX64 && !m_bCloudSrv && !m_bCloudControlSrv) || !bRet)
		{
			//m_pStatusListCtrl->DeleteAllItems();
			csStringToDisPlay = L"";// theApp.m_pResMgr->GetString(_T("IDS_FAILED_TO_UPDATE"));
			//m_pStatus->SetWindowText(csStringToDisPlay+csMsg+_T("!"));
			//DisplayError(true);
			m_iEnumLabelStatus = UpdateMessages::FAILED_TO_UPDATE;
			m_csDownloadedFiles = csStringToDisPlay;
			return false;
		}

	}
	catch (...)
	{
		//AddLogEntry (_T("Exception occour for DownloadRemoteFile :%s"), csRemotePath);
		bRet = false;
	}

	//CString csData;
	//csData.Format(L"%s : 00:00:00", theApp.m_pResMgr->GetString(_T("IDS_REMAINING_TIME")));
	//m_pTotalTimeRemaining->SetWindowText(csData);
	//csData.Format(L"100%% %s", theApp.m_pResMgr->GetString(_T("IDS_DOWNLOAD_PERCENTAGE")));
	//m_pTotalPercentage->SetWindowText(csData);

	csStringToDisPlay = L"";//theApp.m_pResMgr->GetString(_T("IDS_DOWNLOAD_SUCCESS"));
	//m_pStatus->SetWindowText(csStringToDisPlay);
	m_iEnumLabelStatus = UpdateMessages::DOWNLOAD_SUCCESS;
	m_csDownloadedFiles = csStringToDisPlay;
	return bRet;
}

/*--------------------------------------------------------------------------------------
Function       : ThreadUpdateStatus
In Parameters  : 
Out Parameters : void 
Description    : 
Author         :
--------------------------------------------------------------------------------------*/
UINT __cdecl ThreadUpdateStatus(LPVOID pParam)
{
	DownloadManagerSDK* pDownloadManager = (DownloadManagerSDK*)pParam;
	pDownloadManager->UpdateStatus();

	return 0;
}

/*--------------------------------------------------------------------------------------
Function       : UpdateStatus
In Parameters  : 
Out Parameters : void 
Description    : Update Time Remaining & Percentage complete
Author         :
--------------------------------------------------------------------------------------*/
void DownloadManagerSDK::UpdateStatus()
{
	if(theApp.m_iIsUIProduct == 0 || m_pSendSDKMessageToUI == NULL)
	{
		return; 
	}
	HANDLE	hNewStatusMutex = NULL;
	while(m_bUpdateStatus)
	{
		/*if (theApp.m_bExitThread == true)
		{

		}*/
		double dwFileDownloadedSize = CDownloadManagerEx::m_dDownloadedFileSize;
		double dwTotalSize = CDownloadManagerEx::m_dTotalFileSize;

		m_iPercent = (int)((100*(m_dwTotalDownloadedSize+CDownloadManagerEx::m_dDownloadedFileSize))/m_dwTotalDownloadSize);
		int iPercentage = (int)((100*CDownloadManagerEx::m_dDownloadedFileSize)/CDownloadManagerEx::m_dTotalFileSize);

		CTimeSpan tsDifference = CTime::GetCurrentTime() - m_objDownloadStartTime;
		LONGLONG lTotalSecondTaken = tsDifference.GetTotalSeconds();

		if((m_dwTotalDownloadedSize+CDownloadManagerEx::m_dDownloadedFileSize) > 0)
		{
			double dDownloadSize = m_dwTotalDownloadedSize+CDownloadManagerEx::m_dDownloadedFileSize;
			m_dwRemainingTime = (DWORD)((m_dwTotalDownloadSize * lTotalSecondTaken / dDownloadSize) - lTotalSecondTaken);
		}

		int iHrs = m_dwRemainingTime/3600;
		DWORD dwRemainingTime = m_dwRemainingTime % 3600;
		int iMins = dwRemainingTime/60;
		int iSecs = dwRemainingTime % 60;

		CString sText;
		CString csDownloading = L"Downloading";//theApp.m_pResMgr->GetString(_T("IDS_DOWNLOADING"));;

		if(dwFileDownloadedSize < (999 * 999))
		{
			if(m_dwTotalDownloadSize == m_dwTotalDownloadedSize)	//So that status should not get changed after last download
			{
				m_bUpdateStatus = FALSE;
				break;
			}
			else if( dwFileDownloadedSize != dwTotalSize)
			{
				sText.Format(_T("%s %.0fKB of%6.2fMB"), static_cast<LPCTSTR>(csDownloading),
					((double)dwFileDownloadedSize/1024), ((double)dwTotalSize/(1024*1024)));
			}
			else
			{
				sText.Format(_T("%s %6.2fMB of%6.2fMB"), static_cast<LPCTSTR>(csDownloading),
					((double)dwFileDownloadedSize/(1024*1024)), ((double)dwTotalSize/(1024*1024)));
			}
		}
		else
		{
			sText.Format(_T("%s %.2fMB of%6.2fMB"), static_cast<LPCTSTR>(csDownloading),
				((double)dwFileDownloadedSize/(1024*1024)), ((double)dwTotalSize/(1024*1024)));
		}

		CString csTimeRemaining;
		//csTimeRemaining.Format(L"%s : %02d:%02d:%02d", theApp.m_pResMgr->GetString(L"IDS_REMAINING_TIME"), iHrs, iMins, iSecs);
		csTimeRemaining.Format(L"%02d:%02d:%02d", iHrs, iMins, iSecs);

		//CString csTotalPercentage;
		//csTotalPercentage.Format(L"%d%% %s", m_iPercent, theApp.m_pResMgr->GetString(L"IDS_DOWNLOAD_PERCENTAGE"));

		memset(&theApp.m_objUpdateStatus, 0, sizeof(UPDATE_STATUS));
		theApp.m_objUpdateStatus.iUpdateStatus = m_iEnumLabelStatus;
		_tcscpy_s(theApp.m_objUpdateStatus.szFiles,  m_csDownloadedFiles);
		_tcscpy_s(theApp.m_objUpdateStatus.szStatus, sText);
		_tcscpy_s(theApp.m_objUpdateStatus.szTimeRemaining, csTimeRemaining);
		if (iPercentage > 200)
		{
			iPercentage = 0;
		}
		else if (iPercentage < 0)
		{
			iPercentage = 0;
		}
		if (m_iPercent < 0)
		{
			m_iPercent = 0;
		}
		
		theApp.m_objUpdateStatus.iPercentage = iPercentage;
		theApp.m_objUpdateStatus.iTotalPercentage = m_iPercent;
		

		/*if(NULL == hNewStatusMutex)
		{
			hNewStatusMutex = CreateMutex(NULL,FALSE,_T("Global\\UpdateStatusMutex"));
		}

		if (NULL != hNewStatusMutex)
		{
			CString		cszPercentage;

			cszPercentage.Format(L"%d%%",m_iPercent);
			
			CloseHandle(hNewStatusMutex);
			hNewStatusMutex = NULL;
		}*/

		if(m_pSendSDKMessageToUI != NULL)
		{
			m_pSendSDKMessageToUI(theApp.m_objUpdateStatus);
		}
		
		Sleep(500);
	}
	
	return;
}

void DownloadManagerSDK::UpdateStatusEx()
{
	if (theApp.m_iIsUIProduct == 0 || m_pSendSDKMessageToUI == NULL)
	{
		return;
	}
	HANDLE	hNewStatusMutex = NULL;
	while (m_bUpdateStatus)
	{
		double dwFileDownloadedSize = CDownloadManagerEx::m_dDownloadedFileSize;
		double dwTotalSize = CDownloadManagerEx::m_dTotalFileSize;

		m_iPercent = (int)((100 * (m_dwTotalDownloadedSize + CDownloadManagerEx::m_dDownloadedFileSize)) / m_dwTotalDownloadSize);
		int iPercentage = (int)((100 * CDownloadManagerEx::m_dDownloadedFileSize) / CDownloadManagerEx::m_dTotalFileSize);

		CTimeSpan tsDifference = CTime::GetCurrentTime() - m_objDownloadStartTime;
		LONGLONG lTotalSecondTaken = tsDifference.GetTotalSeconds();

		if ((m_dwTotalDownloadedSize + CDownloadManagerEx::m_dDownloadedFileSize) > 0)
		{
			double dDownloadSize = m_dwTotalDownloadedSize + CDownloadManagerEx::m_dDownloadedFileSize;
			m_dwRemainingTime = (DWORD)((m_dwTotalDownloadSize * lTotalSecondTaken / dDownloadSize) - lTotalSecondTaken);
		}

		int iHrs = m_dwRemainingTime / 3600;
		DWORD dwRemainingTime = m_dwRemainingTime % 3600;
		int iMins = dwRemainingTime / 60;
		int iSecs = dwRemainingTime % 60;

		CString sText;
		CString csDownloading = L"Downloading";//theApp.m_pResMgr->GetString(_T("IDS_DOWNLOADING"));;

		if (dwFileDownloadedSize < (999 * 999))
		{
			if (m_dwTotalDownloadSize == m_dwTotalDownloadedSize)	//So that status should not get changed after last download
			{
				m_bUpdateStatus = FALSE;
				break;
			}
			else if (dwFileDownloadedSize != dwTotalSize)
			{
				sText.Format(_T("%s %.0fKB of%6.2fMB"), static_cast<LPCTSTR>(csDownloading),
					((double)dwFileDownloadedSize / 1024), ((double)dwTotalSize / (1024 * 1024)));
			}
			else
			{
				sText.Format(_T("%s %6.2fMB of%6.2fMB"), static_cast<LPCTSTR>(csDownloading),
					((double)dwFileDownloadedSize / (1024 * 1024)), ((double)dwTotalSize / (1024 * 1024)));
			}
		}
		else
		{
			sText.Format(_T("%s %.2fMB of%6.2fMB"), static_cast<LPCTSTR>(csDownloading),
				((double)dwFileDownloadedSize / (1024 * 1024)), ((double)dwTotalSize / (1024 * 1024)));
		}

		CString csTimeRemaining;
		//csTimeRemaining.Format(L"%s : %02d:%02d:%02d", theApp.m_pResMgr->GetString(L"IDS_REMAINING_TIME"), iHrs, iMins, iSecs);
		csTimeRemaining.Format(L"%02d:%02d:%02d", iHrs, iMins, iSecs);

		//CString csTotalPercentage;
		//csTotalPercentage.Format(L"%d%% %s", m_iPercent, theApp.m_pResMgr->GetString(L"IDS_DOWNLOAD_PERCENTAGE"));
		memset(&theApp.m_objUpdateStatus, 0, sizeof(UPDATE_STATUS));
		theApp.m_objUpdateStatus.iUpdateStatus = m_iEnumLabelStatus;
		_tcscpy_s(theApp.m_objUpdateStatus.szFiles, m_csDownloadedFiles);
		_tcscpy_s(theApp.m_objUpdateStatus.szStatus, sText);
		_tcscpy_s(theApp.m_objUpdateStatus.szTimeRemaining, csTimeRemaining);
		theApp.m_objUpdateStatus.iPercentage = iPercentage;
		theApp.m_objUpdateStatus.iTotalPercentage = m_iPercent;


		/*if(NULL == hNewStatusMutex)
		{
			hNewStatusMutex = CreateMutex(NULL,FALSE,_T("Global\\UpdateStatusMutex"));
		}

		if (NULL != hNewStatusMutex)
		{
			CString		cszPercentage;

			cszPercentage.Format(L"%d%%",m_iPercent);

			CloseHandle(hNewStatusMutex);
			hNewStatusMutex = NULL;
		}*/

		if (m_pSendSDKMessageToUI != NULL)
		{
			m_pSendSDKMessageToUI(theApp.m_objUpdateStatus);
		}

		Sleep(500);
	}

	return;
}

/*-------------------------------------------------------------------------------------
Function		: SetInitialStatusText
In Parameters	: int
Out Parameters	: int
Purpose			: This function will set the initial status of given downloading file/type.
Author			: Sandip Sanap
--------------------------------------------------------------------------------------*/
void  DownloadManagerSDK::SetInitialStatusText(int & iType, CStringArray & csFileNameArray, CString & csSectionName)
{
	DWORD dwInsertItemCount = 0;
	CString csStringToDisPlay = _T("");
	if(iType == ENUM_DT_DATABASE)
	{
		if(!m_bDataBase)
		{ 
			iType++;
		}
		else
		{
			if(m_objIndexOfDownload.SearchItem(iType, dwInsertItemCount) == false)
			{
				dwInsertItemCount = iType;
			}
			m_iEnumLabelStatus = UpdateMessages::DB_DOWNLOADING;
			//csStringToDisPlay = _T(" ") + L"IDS_DB_DOWNLOADING";
			csStringToDisPlay = L"";//IDS_DB_DOWNLOADING
			/*m_pStatusListCtrl->SetItemText(dwInsertItemCount, 0, csStringToDisPlay);
			m_pStatusListCtrl->SetItemImage(dwInsertItemCount, 0, 6);*/
			m_csDownloadedFiles = csStringToDisPlay;

			csFileNameArray.Copy(m_csDBFileNames);			
			csSectionName = theApp.m_csDeltaDetails;

			for(int d=0;d<m_csDBFileNames.GetCount();d++)
			{
				deltaFileNameArray.Add(m_csDBFileNames.GetAt(d));
			}
		}
	}

	if(iType == ENUM_DT_DBPATCH)
	{
		if(!m_bDataBasePatch)
		{
			iType++;
		}
		else
		{
			if(m_objIndexOfDownload.SearchItem(iType, dwInsertItemCount) == false)
			{
				dwInsertItemCount = iType;
			}
			
			m_iEnumLabelStatus = UpdateMessages::DB_DOWNLOADING;
			csStringToDisPlay = L"";//IDS_DB_DOWNLOADING
			
			/*m_pStatusListCtrl->SetItemText(dwInsertItemCount, 0, csStringToDisPlay);
			m_pStatusListCtrl->SetItemImage(dwInsertItemCount, 0, 6);*/
			m_csDownloadedFiles = csStringToDisPlay;
			csFileNameArray.Add(m_csDBPatchFileName);
			csSectionName = theApp.m_csDatabaseDetails;	
			fileNameArray.Add(m_csDBPatchFileName);
		}
	}

	if(iType == ENUM_DT_VIRUS)
	{
		if(!m_bVirus)
		{
			iType++;
		}
		else
		{
			if(m_objIndexOfDownload.SearchItem(iType, dwInsertItemCount) == false)
			{
				dwInsertItemCount = iType;
			}
			m_iEnumLabelStatus = UpdateMessages::VP_DOWNLOADING;
			csStringToDisPlay = L"";//IDS_VIRUS_DOWNLOADING
			
			/*m_pStatusListCtrl->SetItemText(dwInsertItemCount, 0, csStringToDisPlay);
			m_pStatusListCtrl->SetItemImage(dwInsertItemCount, 0, 6);*/
			m_csDownloadedFiles = csStringToDisPlay;

			csFileNameArray.Add(m_csVirusFileName1);
			csSectionName = theApp.m_csVirusDetails;	

			fileNameArray.Add(m_csVirusFileName1);
		}
	}

	if(iType == ENUM_DT_VIRUS_X64)
	{
		if(!m_bVirusX64)
		{
			iType++;
		}
		else
		{
			if(m_objIndexOfDownload.SearchItem(iType, dwInsertItemCount) == false)
			{
				dwInsertItemCount = iType;
			}
			m_iEnumLabelStatus = UpdateMessages::VP_DOWNLOADING;
			csStringToDisPlay = L"";//IDS_VIRUS_DOWNLOADING
			
			/*m_pStatusListCtrl->SetItemText(dwInsertItemCount, 0, csStringToDisPlay);
			m_pStatusListCtrl->SetItemImage(dwInsertItemCount, 0, 6);*/
			m_csDownloadedFiles = csStringToDisPlay;
			
			csFileNameArray.Add(m_csVirusFileName2);
			csSectionName = theApp.m_csVirusDetailsX64;

			fileNameArray.Add(m_csVirusFileName2);
		}
	}
	if(iType == ENUM_DT_UPDATE_VERSION)
	{
		if(!m_bUpdateVersion)
		{
			iType++;
		}
		else
		{
			if(m_objIndexOfDownload.SearchItem(iType, dwInsertItemCount) == false)
			{
				dwInsertItemCount = iType;
			}

			//csStringToDisPlay = _T(" ") + L"IDS_UPDT_VER_DOWNLOADING";
			m_csDownloadedFiles = csStringToDisPlay;
			csStringToDisPlay = L"";//IDS_UPDT_VER_DOWNLOADING
			m_iEnumLabelStatus = UpdateMessages::UPDT_VER_DOWNLOADING;
			/*m_pStatusListCtrl->SetItemText(dwInsertItemCount, 0, csStringToDisPlay);
			m_pStatusListCtrl->SetItemImage(dwInsertItemCount, 0, 6);*/
			

			csFileNameArray.Copy(m_csUpdtVerFileNames);
			csSectionName = theApp.m_csUpdtVerDetails;

			for(int d=0;d<m_csUpdtVerFileNames.GetCount();d++)
			{
				fileNameArray.Add(m_csUpdtVerFileNames.GetAt(d));
			}
		}
	}

	if(iType == ENUM_DT_UPDATE_VERSION_X64)
	{
		if(!m_bUpdateVersionX64)
		{
			iType++;
		}
		else
		{
			//AddLogEntry(_T("Check for ENUM_DT_UPDATE_VERSION_X64....."));
			if(m_objIndexOfDownload.SearchItem(iType, dwInsertItemCount) == false)
			{
				dwInsertItemCount = iType;
			}

			m_iEnumLabelStatus = UpdateMessages::UPDT_VER_DOWNLOADING;
			//csStringToDisPlay = _T(" ") + L"IDS_UPDT_VER_DOWNLOADING";
			csStringToDisPlay = L"";//IDS_UPDT_VER_DOWNLOADING
			
			/*m_pStatusListCtrl->SetItemText(dwInsertItemCount, 0, csStringToDisPlay);
			m_pStatusListCtrl->SetItemImage(dwInsertItemCount, 0, 6);*/
			m_csDownloadedFiles = csStringToDisPlay;

			csFileNameArray.Copy(m_csUpdtVerFileNamesX64);
			csSectionName = theApp.m_csUpdtVerDetailsX64;
			
			for(int d=0;d<m_csUpdtVerFileNamesX64.GetCount();d++)
			{
				fileNameArray.Add(m_csUpdtVerFileNamesX64.GetAt(d));
			}
		}
	}
	if(iType == ENUM_DT_PRODUCT)
	{
		if(!m_bProduct)
		{
			iType++;
		}
		else
		{
			if(m_objIndexOfDownload.SearchItem(iType, dwInsertItemCount) == false)
			{
				dwInsertItemCount = iType;
			}
			
			m_iEnumLabelStatus = UpdateMessages::PRODUCT_DOWNLOADING;
			csStringToDisPlay = L"";//IDS_PRODUCT_DOWNLOADING;
			
			/*m_pStatusListCtrl->SetItemText(dwInsertItemCount, 0, csStringToDisPlay);
			m_pStatusListCtrl->SetItemImage(dwInsertItemCount, 0, 6);*/
			m_csDownloadedFiles = csStringToDisPlay;

			csFileNameArray.Add(m_csProductFileName1);
			
			csSectionName = theApp.m_csProductDetails;	
			fileNameArray.Add(m_csProductFileName1);
		}
	}

	if(iType == ENUM_DT_PRODUCT_X64)
	{
		if(m_bProductX64)
		{

			if(m_objIndexOfDownload.SearchItem(iType, dwInsertItemCount) == false)
			{
				dwInsertItemCount = iType;
			}
			
			m_iEnumLabelStatus = UpdateMessages::PRODUCT_DOWNLOADING;
			csStringToDisPlay = L"";//IDS_PRODUCT_DOWNLOADING
			
			/*m_pStatusListCtrl->SetItemText(dwInsertItemCount, 0, csStringToDisPlay);
			m_pStatusListCtrl->SetItemImage(dwInsertItemCount, 0, 6);*/
			m_csDownloadedFiles = csStringToDisPlay;

			csFileNameArray.Add(m_csProductFileName2);
			csSectionName = theApp.m_csProductDetailsX64;
			fileNameArray.Add(m_csProductFileName2);
		}
	}
}

/*-------------------------------------------------------------------------------------
Function		: DownloadRemoteFile
In Parameters	: CString csSource, fully qualified HTTP Url of the file to be downloaded
In Parameters	: CString csLocalFileName, the dowloaded file will be saved as the given name
Out Parameters	: bool, return TRUE if successfull, else FALSE
Purpose			: This function will download the requested file using HTTP Proxy
Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
bool DownloadManagerSDK::DownloadRemoteFile(CString csSource, CString csSource2, CString csLocalFileName,
											DWORD dwTotalSize, int iType, CString csMD5, CString csHeader)
{
	bool bReturn = false;
	bool bContinue = true;
	int nRetryCount = 0;
	int iThreadCount =  GetPrivateProfileInt(DOWNLOADTHREADDETAILS, _T("DownloadThreadCount"), 1, m_csVersionINI);

	do{
		CDownloadManagerEx objDownloadManagerEx(iThreadCount);
		bReturn = (objDownloadManagerEx.DownloadURL(csSource, csSource2, csLocalFileName, dwTotalSize, csMD5)?true:false);
		if(bReturn)
		{
			//AddLogEntry(L"%s file successfully downloaded.", csLocalFileName);
			bContinue = false;
		}
		else
		{
			//AddLogEntry(L"Failed to Download from source: %s ", csSource);
			//AddLogEntry(L"Failed to Download from source: %s ", csSource2);

			if(nRetryCount >= RETRY_COUNT)
			{
				bContinue = false;
			}
			nRetryCount++;	
			Sleep(ONE_RETRY_TIMEOUT);
		}
	}while (bContinue);
	
	return bReturn;
}

void DownloadManagerSDK::SetSDKParams(SENDSDKLVMESSAGEUI pSendSDKMessageToUI)
{
	//CSDKSettings objSettings;

	CProductInfo objPrdInfo;
	m_csDownLoadPath = objPrdInfo.GetInstallPath();

	m_pSendSDKMessageToUI = pSendSDKMessageToUI;
	
	//m_csDownLoadPath = objSettings.GetProductAppPath(); 
	//m_csDownLoadPath = m_csDownLoadPath;// + SDKDOWNLOADFOLDER;
	m_csSettingIniPath = objPrdInfo.GetInstallPath() + SETTING_FOLDER + "SDKSettings.ini";
	//m_csExtractFolderPath = m_csDownLoadPath + SDKEXTRACTPATH;

	CreateDownloadFolders();
}

bool DownloadManagerSDK::CreateDownloadFolders()
{
	CString csMergeTempPath = theApp.m_csWaitingForMergePath + _T("\\MergeTemp\\");

	CreateDirectory(m_csDownLoadPath, NULL);
	CreateDirectory(theApp.m_csWaitingForMergePath, NULL);		
	if(!theApp.m_bStandaloneDownload)
	{
		CreateDirectory(csMergeTempPath, NULL);
	}
	
	return true;
}

bool DownloadManagerSDK::GetDBFilesFromBackupIfAvailable()
{
	bool bFailedLoadingFromBackupAlso = false;
	
	CUpdateManager objUpdtMgr;
	int iContext = 0;
	CString csBackupPath, csProductPath, csFileName, csFailFileNamesInBackup, csToken;
	//CSDKSettings objSettings;
	//make backup path
	csBackupPath = CSystemInfo::m_strAppPath[0];
	csBackupPath += _T(":\\AuLiveUpdate\\Data\\");

	//make product data folder path
	//csProductPath = objSettings.GetProductSettingsString(PRODUCT_SETTINGS,CURRENT_MAX_DB_VAL);
	CRegistry objReg;
	objReg.Get(CSystemInfo::m_csProductRegKey, CURRENT_MAX_DB_VAL, csProductPath, HKEY_LOCAL_MACHINE);
	for(int i = 0; i < MERGING_THREAD_COUNT; i++)
	{
		CString csLogString;

		csLogString.Format(_T("Count: %i"), i);
		AddLogEntry(csLogString, 0, 0, true, LOG_WARNING);

		csFileName = BLANKSTRING;
		/*if(theApp.m_iUseCloudScanning == 1)
		{
			if(i== 5 || i== 6 || i == 12)
			{
				continue;
			}
		}*/
		AddLogEntry(L"Call load from prod", 0, 0, true, LOG_WARNING);
		//try loading db from product folder to check its health
		if(!objUpdtMgr.LoadDBType(csProductPath, i, &csFileName, false))
		{
			objUpdtMgr.ResetAllMembers();
			AddLogEntry(_T("Failed from prod path: %s"), csFileName, 0, true, LOG_WARNING);

			csFailFileNamesInBackup = BLANKSTRING;

			//if loading failed from product folder, try loading from backup folder
			if(!objUpdtMgr.LoadDBType(csBackupPath, i, &csFailFileNamesInBackup, false))
			{
				AddLogEntry(_T("Get patch now, Failed from backup path: %s"), csFailFileNamesInBackup, 0, true, LOG_WARNING);
				//as no copy was loaded successfully, we need a full database patch now
				bFailedLoadingFromBackupAlso = true;
				break;
			}

			AddLogEntry(_T("Reset all"), 0, 0, true, LOG_WARNING);
			objUpdtMgr.ResetAllMembers();

			iContext = 0;
			//traverse the list of files which failed to load from product folder
			csToken = csFileName.Tokenize(_T(";"), iContext);
			while(-1 != iContext)
			{
				AddLogEntry(_T("Filename: %s"), csToken, 0, true, LOG_WARNING);

				if(0 == CopyFile(csBackupPath + csToken, csProductPath + csToken, FALSE))
				{
					AddLogEntry(_T("copy failure: %s -> %s"), csBackupPath + csToken, csProductPath + csToken, true, LOG_WARNING);
					//terminate loop when failed copying, lets us allow database patch
					bFailedLoadingFromBackupAlso = true;
					break;
				}
				else
				{
					AddLogEntry(_T("copy success: %s -> %s"), csBackupPath + csToken, csProductPath + csToken, true, LOG_WARNING);
				}

				csToken = csFileName.Tokenize(_T(";"), iContext);
			}
		}
		else
		{
			AddLogEntry(L"load success", 0, 0, true, LOG_WARNING);
		}

		if(bFailedLoadingFromBackupAlso)
		{
			//terminate loop when flag is set
			break;
		}

		AddLogEntry(_T("ResetAllMembers() last in loop"), 0, 0, true, LOG_WARNING);
		objUpdtMgr.ResetAllMembers();
	}

	AddLogEntry(_T("ResetAllMembers() ret from function"), 0, 0, true, LOG_WARNING);
	objUpdtMgr.ResetAllMembers();

	if(!bFailedLoadingFromBackupAlso)
	{
		//objSettings.SetProductSettings(PRODUCT_SETTINGS,AUTODATABASEPATCH, _T("0"));
		objReg.Set(CSystemInfo::m_csProductRegKey, _T("AUTODATABASEPATCH"), 0, HKEY_LOCAL_MACHINE);
	}

	return !bFailedLoadingFromBackupAlso;
}
/*-------------------------------------------------------------------------------------
Function		: SetDownloadedErrorStatusText
In Parameters	: int
Out Parameters	: void
Purpose			: This function will set the downloaded error status of downloading file/type.
Author			: 
--------------------------------------------------------------------------------------*/
void  DownloadManagerSDK::SetDownloadedErrorStatusText(const int & iType)
{
	CString csStringToDisPlay;
	if(iType == ENUM_DT_DATABASE && m_bDataBase)
	{
		m_bDataBase = false;
		m_iEnumLabelStatus = UpdateMessages::DB_DOWNLOADED_ERROR;
		csStringToDisPlay = L"";//IDS_DB_DOWNLOADED_ERROR
	}
	if(iType == ENUM_DT_PRODUCT && m_bProduct)
	{
		m_bProduct = false;
		m_iEnumLabelStatus = UpdateMessages::PRODUCT_DOWNLOADED_ERROR;
		csStringToDisPlay = L"";// IDS_PRODUCT_DOWNLOADED_ERROR
	}
	
	if(iType == ENUM_DT_VIRUS && m_bVirus)
	{
		m_bVirus = false;
		m_iEnumLabelStatus = UpdateMessages::VIRUS_DOWNLOADED_ERROR;
		csStringToDisPlay = L"";//IDS_VIRUS_DOWNLOADED_ERROR
	}
	if(iType == ENUM_DT_VIRUS_X64 && m_bVirusX64)
	{
		m_bVirusX64 = false;
		m_iEnumLabelStatus = UpdateMessages::VIRUS_DOWNLOADED_ERROR;
		csStringToDisPlay = L"";//IDS_VIRUS_DOWNLOADED_ERROR
	}
	
	if(iType == ENUM_DT_DBPATCH && m_bDataBasePatch)
	{
		m_bDataBasePatch = false;
		m_iEnumLabelStatus = UpdateMessages::DB_DOWNLOADED_ERROR;
		csStringToDisPlay = L"";//IDS_DB_DOWNLOADED_ERROR
	}
	DWORD dwInsertItemCount = 0;
	if(m_objIndexOfDownload.SearchItem(iType, dwInsertItemCount) == false)
	{
		dwInsertItemCount = iType;
	}
	m_csDownloadedFiles = csStringToDisPlay;
	//csStringToDisPlay = _T("  ") + csStringToDisPlay;
	//m_pStatusListCtrl->SetItemText(dwInsertItemCount, 0, csStringToDisPlay);
	//m_pStatusListCtrl->SetItemImage(dwInsertItemCount, 0, 1);
}
/*-------------------------------------------------------------------------------------
Function		: SetDownloadedSuccessStatusText
In Parameters	: int
Out Parameters	: void
Purpose			: This function will set the downloaded success status of downloading file/type.
Author			: Sandip Sanap
--------------------------------------------------------------------------------------*/
void  DownloadManagerSDK::SetDownloadedSuccessStatusText(const int & iType)
{
	CString csStringToDisPlay;
	DWORD dwInsertItemCount = 0;
	if(m_objIndexOfDownload.SearchItem(iType, dwInsertItemCount) == false)
	{
		dwInsertItemCount = iType;
	}
	if(iType == ENUM_DT_PRODUCT && m_bProduct || iType == ENUM_DT_PRODUCT_X64 && m_bProductX64)
	{
		m_iEnumLabelStatus = UpdateMessages::PRODUCT_DOWNLOADED;
		csStringToDisPlay = L"";//IDS_PRODUCT_DOWNLOADED
		//m_pStatusListCtrl->SetItemImage(dwInsertItemCount, 0, 2);
		//m_pStatusListCtrl->SetItemText(dwInsertItemCount, 0, csStringToDisPlay);

	}
	if(iType == ENUM_DT_VIRUS && m_bVirus || iType == ENUM_DT_VIRUS_X64 && m_bVirusX64)
	{
		m_iEnumLabelStatus = UpdateMessages::VIRUS_DOWNLOADED;
		csStringToDisPlay = L"IDS_VIRUS_DOWNLOADED";//IDS_VIRUS_DOWNLOADED
		//m_pStatusListCtrl->SetItemImage(dwInsertItemCount, 0, 2);
		//m_pStatusListCtrl->SetItemText(dwInsertItemCount, 0, csStringToDisPlay);
	}
	if(iType == ENUM_DT_DBPATCH && m_bDataBasePatch)
	{
		m_iEnumLabelStatus = UpdateMessages::DB_DOWNLOADED;
		csStringToDisPlay = L"";//IDS_DB_DOWNLOADED
		//m_pStatusListCtrl->SetItemImage(dwInsertItemCount, 0, 2);
		//m_pStatusListCtrl->SetItemText(dwInsertItemCount, 0, csStringToDisPlay);
	}
	m_csDownloadedFiles = csStringToDisPlay;
}

/*-------------------------------------------------------------------------------------
Function		: FinishUpdateStatus
In Parameters	: int
Out Parameters	: void
Purpose			: This function will set the downloaded success or error status 

--------------------------------------------------------------------------------------*/
void  DownloadManagerSDK::FinishUpdateStatus(int iSuccessErr)
{
		memset(&theApp.m_objUpdateStatus, 0, sizeof(UPDATE_STATUS));
		theApp.m_objUpdateStatus.iUpdateStatus = m_iEnumLabelStatus;
		_tcscpy_s(theApp.m_objUpdateStatus.szFiles, m_csDownloadedFiles);
		theApp.m_objUpdateStatus.iSuccessErr = iSuccessErr;
		if(m_pSendSDKMessageToUI != NULL)
		{
			m_pSendSDKMessageToUI(theApp.m_objUpdateStatus);
		}
}
