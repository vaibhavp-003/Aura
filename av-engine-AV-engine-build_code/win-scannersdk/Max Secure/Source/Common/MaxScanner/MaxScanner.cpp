#include "pch.h"
#include "MaxScanner.h"
#include "Registry.h"
#include "MaxExceptionFilter.h"
#include "ZipArchive.h"
#include "BackupOperations.h"
#include "MaxDigitalSigCheck.h"
#include "ExecuteProcess.h"
#include "Enumprocess.h"
#include "MaxPipes.h"
#ifdef _SDSCANNER
#include "BufferToStructure.h"
#include "NetWorkUserValidation.h"
#include <Lmcons.h>
#include <lm.h>
#pragma comment(lib, "netapi32.lib")
#endif
#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

#include "ScriptSig.h"

typedef struct _COPYINFO
{
	WCHAR wSrcFile[MAX_PATH];
	WCHAR wDstFile[MAX_PATH];
}COPYINFO, *PCOPYINFO;
const static int IOCTL_COPY_FILE = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8008, METHOD_BUFFERED, FILE_ANY_ACCESS);

extern DWORD g_dwLoggingLevel;
bool GetMD5Signature32(const char *filepath, char *cMD5Signature);

const int EXTENSION_OF_COMPRESSED_FILES = 2;
WCHAR CompressedFileExtension[EXTENSION_OF_COMPRESSED_FILES][5] =
{
	{L".ZIP"}, {L".RAR"}
};

const int EXCLUDE_EXTENSION_OF_COMPRESSED_FILES = 21;
WCHAR CompressedFileExcludeExtension[EXCLUDE_EXTENSION_OF_COMPRESSED_FILES][7] =
{
	{L".JAR"},{L".XLSX"},{L".DOCX"},{L".PPTX"},{L".XLF"},{L".SWC"},{L".ACX"},{L".CFG"},{L".PAT"},{L".DATA"},
	{L".CDT"},{L".PBZ"},{L".THMX"},{L".EFTX"},{L".DOTX"},{L".XLAM"},{L".XLTX"},{L".POTX"},{L".ACCDT"},
	{L".WMZ"}
};


int EXCLUDE_EXTENSION_OF_SCANNING_FILES;
//WCHAR ScanFileExcludeExtension[EXCLUDE_EXTENSION_OF_SCANNING_FILES][7];
WCHAR **pScanFileExcludeExtension;
//WCHAR ScanFileExcludeExtension[EXCLUDE_EXTENSION_OF_SCANNING_FILES][7] =
//{
//	{L".JA"},{L".CHM"},{L".LOG"},{L".TXT"},{L".900"},{L".700"},{L".500"}				//4-Jan-2018 Removed L{".DB"} because of Thunb.db issue: Tushar
//};

CMaxScanner::CMaxScanner():m_objDBExcludeExtList(false)
{
	m_hEMLParser = NULL;
	m_lpfnEMLUnPack = NULL;
	m_lpfnEMLRePack = NULL;
	m_lpfnInitMailDB = NULL;
	m_lpfnDeInitMailDB = NULL;
	m_pThreatManager = NULL;
	m_pMaxDSrvWrapper = NULL;
	m_iTotalNoOfFiles = m_iNoofWhiteFileSigSearched = m_iNoofWhiteFileSigMatched = 
	m_iNoofBlackFileSigSearched = m_iNoofBlackFileSigMatched = 
	m_iNoofMaxVirusSearched = m_iNoofMaxVirusMatched = 
	m_iTotalNoOfPackedFiles = m_iTotalNoOfUnPackSuccessFiles = 
	m_iTotalNoOfUnPackFailedFiles = m_iTotalNoOfADSFiles =
	m_iTotalNoOfArchiveFiles = m_iTotalNoOfArchiveSuccessFiles = 
	m_iTotalNoOfArchiveFailedFiles = m_iTotalNoOfFilesSkipped = 
	m_iNoofFullFileSigSearched = m_iNoofFullFileSigMatched = 
	m_iNoofMACFileSigSearched = m_iNoofMACFileSigMatched = 0;
	m_hUnpacker = NULL;
	m_lpfnUnpackFileNew = NULL;
	m_lpfnExtractFile = NULL;
	m_lpfnExtractNonPEFile = NULL;
	pfnNtQueryInformationFile = NULL;
	m_dwSkipCompressfiles = 0;
	m_hEvent = CreateEvent(NULL, FALSE, TRUE, NULL);
	m_hMLThread=NULL;	
	m_hFullFileSigDB = NULL;
	m_dwSD43CurVersion = 0x00;
	m_dwSD47CurVersion = 0x00;
	m_dwPatCurVersion = 0x00;
	m_dwWhiteCurVersion = 0x00;
	m_dwMLVersion = 0x00;
	m_bMachineLearning = false;
	m_bMachineLearningQ = false;
	m_dwMaxMacLearning = 0;

	m_iNoofMLearnSigSearched = 0x00;
	m_iNoofMLearnSigMatched = 0x00;
	m_iNoofHeurSigSearched = 0x00;
	m_iNoofHeurSigMatched = 0x00;

	m_iNoofYrSigSearched = 0x00;
	m_iNoofYrSigMatched = 0x00;

	m_bIsExcludeExtDBLoaded   = false;
	pScanFileExcludeExtension = NULL;
	m_objDBExcludeExtList.RemoveAll();

	m_pMaxMacLearning = NULL;
	m_bValidated = false;
	m_dwActmonScan = 0;
	m_bADSScan = false;	//AlternateDataStream scan
	m_bRefScan = false;		// Restrict reference scan

	m_dwZipRecursionCnt = 0x00;
	m_dwUpackRecursionCnt = 0x00;
	hScanMutex = NULL;
}

CMaxScanner::~CMaxScanner(void)
{
	if(m_hEvent)
	{
		CloseHandle(m_hEvent);
		m_hEvent = NULL;
	}

	for(int iCount = 0; iCount < EXCLUDE_EXTENSION_OF_SCANNING_FILES; iCount++)
	{
		delete pScanFileExcludeExtension[iCount];
	}
	delete []pScanFileExcludeExtension;

}

DWORD WINAPI Unpacker32Thread(LPVOID pParam)
{
	SHARED_UNPACKER_SWITCH_DATA	*pTemp = (SHARED_UNPACKER_SWITCH_DATA *)pParam;	
	TCHAR	szLogLine[1024] = {0x00};
	
	CMaxCommunicator objMaxCommunicator(_NAMED_PIPE_SCANNER_TO_UNPACKER, false);

	objMaxCommunicator.SendData(pTemp,sizeof(SHARED_UNPACKER_SWITCH_DATA));
	objMaxCommunicator.ReadData(pTemp, sizeof(SHARED_UNPACKER_SWITCH_DATA));
	
	return 0x01;
}

/* For Loading Virus DBs*/
DWORD WINAPI  InitializeVirusDBThread(LPVOID pParam)
{
	CMaxScanner	*pTemp = (CMaxScanner *)pParam;	

	if (SetThreadPriority(pTemp->m_hVirusScanSigDB,THREAD_PRIORITY_HIGHEST))
	{
		AddLogEntry(_T("SetThreadPriority for VIRUS Success"),0,0,true,LOG_DEBUG);
	}

	pTemp->InitializeVirusDB();
	return 0x0l;
}

bool CMaxScanner::InitializeVirusDB()
{
	CString csMaxDBPath;
	bool bDeleteFileBLK = true;
	CRegistry oRegistry;
	CSystemInfo oSysInfo;

	oRegistry.Get(CSystemInfo::m_csProductRegKey, CURRENT_MAX_DB_VAL, csMaxDBPath, HKEY_LOCAL_MACHINE);
	
	m_oMaxVirusScanner.InitializeVirusScanner(csMaxDBPath, m_btPolyVirusRevIDS);
	if(!m_pMaxDSrvWrapper)
	{
		m_pMaxDSrvWrapper = new CMaxDSrvWrapper;
	}
	if(m_pMaxDSrvWrapper)
	{
		m_pMaxDSrvWrapper->InitializeVirusScanner();
	}

	return true;
}

//DWORD WINAPI InitializeYARADBThread(LPVOID pParam)
DWORD WINAPI InitializeYARADBThread(LPVOID pParam)
{
	CMaxScanner	*pTemp = (CMaxScanner *)pParam;	

	pTemp->InitializeYARADB();
	return 0x0l;
}

bool CMaxScanner::InitializeYARADB()
{
	CRegistry oRegistry;
	CSystemInfo oSysInfo;

	AddLogEntry(_T("Initializing YARA Database"),0,0,true,LOG_DEBUG);

	m_dwMaxYrScan = 0;
	if(m_dwActmonScan == 1)
	{
		oRegistry.Get(CSystemInfo::m_csProductRegKey , _T("YrScanAct"), m_dwMaxYrScan ,HKEY_LOCAL_MACHINE);
	}
	else
	{
		oRegistry.Get(CSystemInfo::m_csProductRegKey , _T("YrScan"), m_dwMaxYrScan ,HKEY_LOCAL_MACHINE);	
	}
	m_hMaxYrScan = NULL;
	m_lpfnLoadYrScan = NULL;
	m_lpfnUnLoadYrScan = NULL;
	m_lpfnScanFileYrScan = NULL;
	m_bYrScanLoaded = false;
	if(m_dwMaxYrScan)
	{
		m_hMaxYrScan = LoadLibrary(_T("AuYrScanner.dll"));
		if(m_hMaxYrScan != NULL)
		{
			m_lpfnLoadYrScan		= (LPFN_LoadYrScan)GetProcAddress(m_hMaxYrScan,"LoadYrScan");
			m_lpfnScanFileYrScan	= (LPFN_ScanFileYrScan)GetProcAddress(m_hMaxYrScan,"ScanFile");
			m_lpfnUnLoadYrScan		= (LPFN_UnLoadYrScan)GetProcAddress(m_hMaxYrScan,"UnloadYrScan");
			if( m_lpfnLoadYrScan != NULL && m_lpfnScanFileYrScan!= NULL && m_lpfnUnLoadYrScan != NULL)
			{
				m_bYrScanLoaded = true;
			}
			if(m_lpfnLoadYrScan)
			{
				TCHAR	szMaxYrScanDbPath[MAX_PATH] = {0x00};
				char szYrScanDbPath[MAX_PATH] = {0x00};
				_stprintf(szMaxYrScanDbPath,L"%sYrScanDB.yar",CSystemInfo::m_strAppPath);
				GetAnsiString(szMaxYrScanDbPath,szYrScanDbPath);				
				int iReturn = m_lpfnLoadYrScan(szYrScanDbPath);
				if(iReturn == 0)
				{
					m_bYrScanLoaded = false;
				}
			}

		}
	}

	AddLogEntry(_T("FinishedYARA Database Loading"),0,0,true,LOG_DEBUG);

	return true;
}


DWORD WINAPI InitializeFullFileSigandThread(LPVOID pParam)
{
	CMaxScanner	*pTemp = (CMaxScanner *)pParam;	
	pTemp->InitializeFullFileSigand();
	return 0x0l;
}

bool CMaxScanner::InitializeFullFileSigand()
{
	CString csMaxDBPath;
	bool bDeleteFileBLK = true;
	CRegistry oRegistry;
	CSystemInfo oSysInfo;

	AddLogEntry(_T("Initializing FFS Database"),0,0,true,LOG_DEBUG);

	oRegistry.Get(CSystemInfo::m_csProductRegKey, CURRENT_MAX_DB_VAL, csMaxDBPath, HKEY_LOCAL_MACHINE);
	if(!m_objFullFileSigDB.Load(csMaxDBPath, true, true, &bDeleteFileBLK))
	{
		AddLogEntry(_T("Scanning skip for database : %s"), csMaxDBPath + SD_DB_FS_FULLFILE_MD5);
		oRegistry.Set(CSystemInfo::m_csProductRegKey , _T("AutoDatabasePatch"), 1, HKEY_LOCAL_MACHINE);		
	}
	
	m_dwSD47CurVersion = m_objFullFileSigDB.GetHeighestVersion();
	AddLogEntry(_T("Finish Initializing FFS Database"),0,0,true,LOG_DEBUG);

	return true;
}


//DWORD WINAPI InitializeScannerMLThread(LPVOID pParam)
DWORD WINAPI InitializeScannerMLThread(LPVOID pParam)
{
	CMaxScanner	*pTemp = (CMaxScanner *)pParam;	
	pTemp->InitializeScannerML();
	return 0x0l;
}

bool CMaxScanner::InitializeScannerML()
{
	TCHAR	szMLDllPath[MAX_PATH] = {0x00};	
	TCHAR	szClassifierPath[MAX_PATH] = {0x00};
	TCHAR	szFeaturesPath[MAX_PATH] = {0x00};	

	AddLogEntry(_T("Initializing ML Database"),0,0,true,LOG_DEBUG);

	m_pMaxMacLearning = new CMaxMachineLearning();			
	if (m_pMaxMacLearning != NULL)
	{
		_stprintf(szMLDllPath,L"%s",CSystemInfo::m_strAppPath);
		m_pMaxMacLearning->InitializeScanner(szMLDllPath,true);

		AddLogEntry(_T("Finish Initializing ML Database"),0,0,true,LOG_DEBUG);

		return true;
	}
	return false;
}

bool CMaxScanner::InitializeScanner(const CString &csMaxDBPath)
{
	m_dwTotalScanTime = m_dwTotalRepairTime = m_dwPECreationTime = 
	m_dwWPESearchingTime = m_dwBPESearchingTime = m_dwPEQuarantineTime = 
	m_dwTotalUnPackTime = m_dwTotalADSScanTime = m_dwTotalArchiveTime = 0;
	m_dwMLScanTime = m_dwYaraScanTime = 0x00, m_dwMaxPEFileCreationTime = 0x00, m_dwRansScanTime = 0x00;
	m_dwAppDataScanTime = 0x00, m_dwPatScanTime = 0x00, m_dwInstScanTime = 0x00, m_dwCompSafeScanTime = 0x00;

	CRegistry oRegistry;

	memset(m_btPolyVirusRevIDS, 0, sizeof(m_btPolyVirusRevIDS));

	m_oInstantScanner.LoadEntriesFromINI();
	m_oMaxVirusScanner.m_bUSBScan = m_bIsUsbScan; 
	m_oMaxVirusScanner.m_bIsActMon = m_dwActmonScan;

	m_dwMLVersion = 0x00;
	CString		csMLVersion;
	oRegistry.Get(CSystemInfo::m_csProductRegKey , _T("MLearnVersion"), csMLVersion, HKEY_LOCAL_MACHINE);
	csMLVersion.Replace(_T("."),_T(""));
	if (csMLVersion.GetLength() > 0x00)
	{
		m_dwMLVersion = _tstol(csMLVersion);
	}
	else
	{
		m_dwMLVersion = 190000001;
	}

	m_dwYrVersion = 0x00;
	CString		csMaxYrVersion;
	oRegistry.Get(CSystemInfo::m_csProductRegKey , _T("YrScanVersion"), csMaxYrVersion, HKEY_LOCAL_MACHINE);
	csMaxYrVersion.Replace(_T("."),_T(""));
	if (csMaxYrVersion.GetLength() > 0x00)
	{
		m_dwYrVersion = _tstol(csMaxYrVersion);
	}
	else
	{
		m_dwYrVersion = 200000001;
	}

	m_dwPatCurVersion = m_oPatternFileScanner.GetCurrentPatVersion();
	
	/*------------------------------ Virus Thread ------------------------------*/
	AddLogEntry(_T("Initializing Virus database"),0,0,true,LOG_DEBUG);
	AddLogEntryCmd(_T("####Start Scanning"));

	/*
	DWORD	dwVirusDBThreadID = 0x00;
	m_hVirusScanSigDB = NULL;
	m_hVirusScanSigDB = CreateThread(NULL,0,InitializeVirusDBThread,(LPVOID)this,0,&dwVirusDBThreadID);
	if (m_hVirusScanSigDB)
	{
		WaitForSingleObject(m_hVirusScanSigDB,12000);
		if (m_hVirusScanSigDB)
		{
			if (SetThreadPriority(m_hVirusScanSigDB,THREAD_PRIORITY_NORMAL))
			{
				AddLogEntry(_T("SetThreadPriority for VIRUS Success"),0,0,true,LOG_DEBUG);
			}
		}
	}
	*/
	/*
	//m_VirusDBLoadThread = AfxBeginThread(InitializeVirusDBThread, (LPVOID)this, THREAD_PRIORITY_ABOVE_NORMAL, NULL, NULL, NULL);
	//m_VirusDBLoadThread->m_hThread = NULL;
	InitializeVirusDB();
	*/
	m_hVirusScanSigDB = NULL;
	m_oMaxVirusScanner.InitializeVirusScanner(csMaxDBPath, m_btPolyVirusRevIDS);
	if(!m_pMaxDSrvWrapper)
	{
		m_pMaxDSrvWrapper = new CMaxDSrvWrapper;
	}
	if(m_pMaxDSrvWrapper)
	{
		m_pMaxDSrvWrapper->InitializeVirusScanner();
	}
	
	/*------------------------------ Virus Thread END ------------------------------*/
	
	bool bDeleteFileBLK = true;

	//if(!m_objWhiteDB.Load(csMaxDBPath + SD_DB_FS_WHT))
	AddLogEntry(_T("Initializing White database"),0,0,true,LOG_DEBUG);

	if(!m_objWhiteDB.Load(csMaxDBPath))
	{
		AddLogEntry(_T("Scanning skip for database : %s"), csMaxDBPath + SD_DB_FS_WHT);
		oRegistry.Set(CSystemInfo::m_csProductRegKey , _T("AutoDatabasePatch"), 1, HKEY_LOCAL_MACHINE);
	}
	m_dwWhiteCurVersion = m_objWhiteDB.GetHeighestVersion();


	//if(!m_objBlackDB.Load(csMaxDBPath + SD_DB_FS_BLK, true, true, &bDeleteFileBLK))
	//{
	AddLogEntry(_T("Initializing MAC database"),0,0,true,LOG_DEBUG);
	if(!m_objBlackDB.Load(csMaxDBPath + SD_DB_FS_QIK))
	{
		AddLogEntry(_T("Scanning skip for database : %s"), csMaxDBPath + SD_DB_FS_QIK);
		oRegistry.Set(CSystemInfo::m_csProductRegKey , _T("AutoDatabasePatch"), 1, HKEY_LOCAL_MACHINE);
	}
	//}


	/*------------------------------ SD43 Thread Start ------------------------------*/
	//m_objMD5DB
	bDeleteFileBLK = true;
	DWORD	dwTdreadID = 0x00;
	
	//if(!m_objFullFileSigDB.Load(csMaxDBPath + SD_DB_FS_FULLFILE_MD5, true, true, &bDeleteFileBLK))
	/*if(!m_objFullFileSigDB.Load(csMaxDBPath, true, true, &bDeleteFileBLK))
	{
		AddLogEntry(_T("Scanning skip for database : %s"), csMaxDBPath + SD_DB_FS_FULLFILE_MD5);
		oRegistry.Set(CSystemInfo::m_csProductRegKey , _T("AutoDatabasePatch"), 1, HKEY_LOCAL_MACHINE);		
	}
	m_dwSD47CurVersion = m_objFullFileSigDB.GetHeighestVersion();*/
	//MessageBox(NULL, _T("Attach"), _T(""), MB_OK);

	AddLogEntry(_T("Initializing Black database"),0,0,true,LOG_DEBUG);
	if(!m_obBlackDBManager.Load(csMaxDBPath, true, true, &bDeleteFileBLK))
	{
		AddLogEntry(_T("Scanning skip for database : %s"), csMaxDBPath + SD_DB_FS_BLK);
		oRegistry.Set(CSystemInfo::m_csProductRegKey , _T("AutoDatabasePatch"), 1, HKEY_LOCAL_MACHINE);
	}
	m_dwSD43CurVersion = m_obBlackDBManager.GetHeighestVersion();
	if(bDeleteFileBLK)
	{
		AddLogEntry(_T("Scanning skip for database : %s"), csMaxDBPath + SD_DB_FS_BLK);
		oRegistry.Set(CSystemInfo::m_csProductRegKey , _T("EPMD5UPDATETMP"), 1, HKEY_LOCAL_MACHINE);
	}
	/*else
	{
		AddLogEntry(_T("DB Loaded successfully."));
	}*/

	/*------------------------------ SD43 Thread END ------------------------------*/

	
	/*------------------------------ YARA Thread Start ------------------------------*/
	//// Yara Scanner
	m_hYARASigDB = NULL;
	/*
	m_hYARASigDB = CreateThread(NULL,0,InitializeYARADBThread,(LPVOID)this,0,&dwTdreadID);  // MultiThread loading
	if (m_hYARASigDB)
	{
		WaitForSingleObject(m_hYARASigDB,3000);
	}
	*/
	//m_YARADBLoadThread = AfxBeginThread(InitializeYARADBThread, (LPVOID)this, THREAD_PRIORITY_NORMAL, NULL, NULL, NULL);
	InitializeYARADB();
	
	/*------------------------------ YARA Thread END ------------------------------*/
	
	AddLogEntry(_T("Initializing Au DigiCert Database"),0,0,true,LOG_DEBUG);

	//Digital Certificate Check
	m_hMaxDigiScan = NULL;
	m_lpfnScanFileDigiSig = NULL;
	m_lpfnLoadDigiSig = NULL;
	m_lpfnUnLoadDigiSig = NULL;
	DWORD m_dwMaxDigiCat = 0;
	oRegistry.Get(CSystemInfo::m_csProductRegKey , _T("DigiCat"), m_dwMaxDigiCat ,HKEY_LOCAL_MACHINE);
	if(m_dwMaxDigiCat == 1)
	{
		m_hMaxDigiScan = LoadLibrary(_T("AuDigiScan.dll"));
		if(m_hMaxDigiScan != NULL)
		{
			m_lpfnScanFileDigiSig = (LPFN_ScanFileDigiSig)GetProcAddress(m_hMaxDigiScan, "ScanFileDigiSig");
			m_lpfnLoadDigiSig = (LPFN_LoadDigiSig)GetProcAddress(m_hMaxDigiScan, "LoadDigiSig");
			m_lpfnUnLoadDigiSig = (LPFN_UnLoadDigiSig)GetProcAddress(m_hMaxDigiScan, "UnLoadDigiSig");
			if(m_lpfnLoadDigiSig != NULL)
			{
				m_lpfnLoadDigiSig();
			}
		}
	}

	m_hFullFileSigDB = NULL;
	//m_hFullFileSigDB = CreateThread(NULL,0,InitializeFullFileSigandThread,(LPVOID)this,0,&dwTdreadID);	
	InitializeFullFileSigand();
	
	///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

	m_dwSkipCompressfiles = 0;
	oRegistry.Get(CSystemInfo::m_csProductRegKey , _T("SkipCompressedFiles"), m_dwSkipCompressfiles ,HKEY_LOCAL_MACHINE);
	m_pThreatManager = new CThreatManager(NULL);

	_LoadUnpacker();

	_LoadEMLParser();

	///Load 7zipDll
	m_obj7zDLL.LoadMax7zDll();


	m_hWhiteCerScanDll = NULL;
	
	m_hRansomPatternScanDll = NULL;
	m_hRansomPatternScanDll = LoadLibrary(_T("AuRansomPatternScan.dll"));
	if(m_hRansomPatternScanDll != NULL)
	{
		m_lpfnSetAppDataPath = (LPFN_SetAppDataPath)GetProcAddress(m_hRansomPatternScanDll, "SetAppDataPath");
		if(m_lpfnSetAppDataPath != NULL)
		{
			CString csAppDataPath;
			CString csLocalAppDataPath;
			CRegistry oRegistry; 
			oRegistry.Get(CSystemInfo::m_csProductRegKey, _T("APPDATA"), csAppDataPath, HKEY_LOCAL_MACHINE);
			oRegistry.Get(CSystemInfo::m_csProductRegKey, _T("APPDATA_LOCAL"), csLocalAppDataPath, HKEY_LOCAL_MACHINE);
			if(!csAppDataPath.IsEmpty() && !csLocalAppDataPath.IsEmpty())
			{
				csAppDataPath = csAppDataPath.MakeLower();
				csLocalAppDataPath = csLocalAppDataPath.MakeLower();				
				m_lpfnSetAppDataPath((LPCTSTR)csAppDataPath, (LPCTSTR)csLocalAppDataPath);
			}
		}
		m_lpfnCheckBlackFile = (LPFN_CheckBlackFile)GetProcAddress(m_hRansomPatternScanDll, "CheckFileWithPattern");
		m_lpfnCheckFileInAppData = (LPFN_CheckFileInAppData)GetProcAddress(m_hRansomPatternScanDll, "CheckFileInAppData");
	}

	if(m_lpfnInitMailDB)
	{
		//calling Exported function "InitDB" from AuMailScanner.dll
		m_lpfnInitMailDB(csMaxDBPath, CSystemInfo::m_strAppPath);
	}

	(FARPROC&)pfnNtQueryInformationFile = ::GetProcAddress(::GetModuleHandle(_T("ntdll.dll")), "NtQueryInformationFile");

	m_bIsExcludeExtDBLoaded = LoadExcludeExtDB();

	/*------------------------------ ML Thread START ------------------------------*/
	m_hMLThread = NULL;
	m_dwMaxMacLearning = 0;
	m_hThreateComDll = NULL;
	m_lpfnScanFileHeur = NULL;
	//if(m_bMachineLearning)
	{
		//AddLogEntry(L"~~~~~Loading Machine Learning Dbs");
		if(m_dwActmonScan == 1)
		{
			oRegistry.Get(CSystemInfo::m_csProductRegKey , _T("MacLearningAct"), m_dwMaxMacLearning ,HKEY_LOCAL_MACHINE);
		}
		else
		{
			oRegistry.Get(CSystemInfo::m_csProductRegKey , _T("MacLearning"), m_dwMaxMacLearning ,HKEY_LOCAL_MACHINE);
		}
		if(m_dwMaxMacLearning == 1)
		{	
			DWORD	dwMLThreadID = 0x00;
			m_hMLThread = CreateThread(NULL,0,InitializeScannerMLThread,(LPVOID)this,0,&dwMLThreadID);  // MultiThread loading
			//m_MLDBLoadThread = AfxBeginThread(InitializeScannerMLThread, (LPVOID)this, THREAD_PRIORITY_ABOVE_NORMAL, NULL, NULL, NULL);
		}		
	}
	/*------------------------------ ML Thread END ------------------------------*/

	//if( m_VirusDBLoadThread->m_hThread != NULL)
	if (m_hVirusScanSigDB != NULL)
	{
		WaitForSingleObject(m_hVirusScanSigDB,INFINITE);
		m_hVirusScanSigDB = NULL;
	}

	/*
	if (m_hYARASigDB != NULL)
	{
		if (SetThreadPriority(m_hYARASigDB,THREAD_PRIORITY_HIGHEST))
		{
			AddLogEntry(_T("SetThreadPriority for YARA Success"),0,0,true,LOG_DEBUG);
		}
		WaitForSingleObject(m_hYARASigDB,3000);
	}
	*/
	m_iTotalNoOfFiles = m_iNoofWhiteFileSigSearched = m_iNoofWhiteFileSigMatched = 
	m_iNoofBlackFileSigSearched = m_iNoofBlackFileSigMatched = 
	m_iNoofMaxVirusSearched = m_iNoofMaxVirusMatched = 
	m_iTotalNoOfPackedFiles = m_iTotalNoOfUnPackSuccessFiles = 
	m_iTotalNoOfUnPackFailedFiles = m_iTotalNoOfADSFiles =
	m_iTotalNoOfArchiveFiles = m_iTotalNoOfArchiveSuccessFiles = 
	m_iTotalNoOfArchiveFailedFiles = m_iTotalNoOfFilesSkipped = 
	m_iNoofFullFileSigSearched = m_iNoofFullFileSigMatched = 
	m_iNoofMACFileSigSearched = m_iNoofMACFileSigMatched = 
	m_iNoofMLearnSigSearched = m_iNoofMLearnSigMatched = 
	m_iNoofHeurSigSearched = m_iNoofHeurSigMatched = 
	m_iNoofYrSigSearched = m_iNoofYrSigMatched = 0;

	AddLogEntry(_T("All Scanner Init Success!"));
	/****************************************************************************************/
	/* Added By Tushar :  To Handle DB Manager Issue : Pause the detection of ActMOn (For Himmat Sir) */
	m_dwSnoozeActMon = 0x00;
	oRegistry.Get(CSystemInfo::m_csProductRegKey , _T("SnoozeActMon"), m_dwSnoozeActMon ,HKEY_LOCAL_MACHINE);


	return true;
}

void CMaxScanner::DeInitializeScanner()
{
	
	_UnloadEMLParser();
	_UnloadUnpacker();

	///Unload 7zip
	m_obj7zDLL.UnLoadMax7zDll();

	if(m_hWhiteCerScanDll != NULL)
	{
		FreeLibrary(m_hWhiteCerScanDll);
		m_hWhiteCerScanDll = NULL;
	}


	if(m_hRansomPatternScanDll != NULL)
	{
		FreeLibrary(m_hRansomPatternScanDll);
		m_hRansomPatternScanDll = NULL;
	}

	if (m_hMLThread != NULL)
	{
		WaitForSingleObject(m_hMLThread,INFINITE);
		m_hMLThread = NULL;
	}
	
	if (m_hFullFileSigDB != NULL)
	{
		WaitForSingleObject(m_hFullFileSigDB,INFINITE);
		m_hFullFileSigDB = NULL;
	}

	m_oMaxVirusScanner.DeInitializeVirusScanner();

	if(m_pMaxDSrvWrapper)
	{
		m_pMaxDSrvWrapper->DeInitializeVirusScanner();
		delete m_pMaxDSrvWrapper;
		m_pMaxDSrvWrapper = NULL;
	}

	if(m_pThreatManager)
	{
		delete m_pThreatManager;
		m_pThreatManager = NULL;
	}

	if(m_pMaxMacLearning)
	{
		////m_pMaxMacLearning->DeInitializeScanner();
		delete m_pMaxMacLearning;
		m_pMaxMacLearning = NULL;
	}

	if(m_hThreateComDll != NULL)
	{
		FreeLibrary(m_hThreateComDll);
		m_hThreateComDll = NULL;
		m_lpfnScanFileHeur = NULL;
	}

	if(m_hMaxDigiScan != NULL)
	{
		if(m_lpfnUnLoadDigiSig!= NULL)
		{
			m_lpfnUnLoadDigiSig();
		}
		FreeLibrary(m_hMaxDigiScan);
		m_hMaxDigiScan = NULL;
		m_lpfnScanFileDigiSig = NULL;
		m_lpfnLoadDigiSig = NULL;
		m_lpfnUnLoadDigiSig = NULL;
	}

	if(m_hMaxYrScan != NULL)
	{
		if(m_lpfnUnLoadYrScan != NULL)
		{
			m_lpfnUnLoadYrScan();
		}
		m_bYrScanLoaded = false;
		FreeLibrary(m_hMaxYrScan);
		m_hMaxYrScan = NULL;
		m_lpfnLoadYrScan = NULL;
		m_lpfnUnLoadYrScan = NULL;
		m_lpfnScanFileYrScan = NULL;
	}
	
	m_objWhiteDB.RemoveAll();
	m_objBlackDB.RemoveAll();
	m_objFullFileSigDB.RemoveAll();
	m_obBlackDBManager.RemoveAll();
	m_objDBExcludeExtList.RemoveAll();

	WCHAR *wcsTemp = new WCHAR[MAX_PATH*5];
	wmemset(wcsTemp, 0, MAX_PATH*5);
	swprintf_s(wcsTemp, MAX_PATH*5, _T("TFS: %d, WS: %d, WM: %d, BS: %d, BM: %d, FFSS: %d, FFSM: %d, MFSS: %d, MFSM: %d, MVS: %d, MVM: %d, MLS: %d, MLM: %d, YRS: %d, YRM: %d, TPF: %d, UPS: %d, UPF: %d, TADSF: %d, TAF: %d, AUS: %d, AUF: %d, FSKP: %d"),
				m_iTotalNoOfFiles, m_iNoofWhiteFileSigSearched, m_iNoofWhiteFileSigMatched, 
				m_iNoofBlackFileSigSearched, m_iNoofBlackFileSigMatched,
				m_iNoofFullFileSigSearched, m_iNoofFullFileSigMatched,
				m_iNoofMACFileSigSearched, m_iNoofMACFileSigMatched,
				m_iNoofMaxVirusSearched, m_iNoofMaxVirusMatched,
				m_iNoofMLearnSigSearched,m_iNoofMLearnSigMatched,
				m_iNoofYrSigSearched,m_iNoofYrSigMatched,
				m_iTotalNoOfPackedFiles, m_iTotalNoOfUnPackSuccessFiles, 
				m_iTotalNoOfUnPackFailedFiles, m_iTotalNoOfADSFiles,
				m_iTotalNoOfArchiveFiles, m_iTotalNoOfArchiveSuccessFiles,
				m_iTotalNoOfArchiveFailedFiles, m_iTotalNoOfFilesSkipped);
	AddLogEntry(wcsTemp);
	AddLogEntryCmd(wcsTemp);

	//m_iNoofYrSigSearched,m_iNoofYrSigMatched,

	_stprintf(wcsTemp,_T("TFPLM : %d, TFDBM : %d, TFYRM : %d, TFDGM : %d, TFICM : %d"),m_oMaxVirusScanner.m_dwDetectedByPoly,m_oMaxVirusScanner.m_dwDetectedByDB,m_oMaxVirusScanner.m_dwDetectedByYara,m_oMaxVirusScanner.m_dwDetectedByDigi,m_oMaxVirusScanner.m_dwDetectedByIcon);
	AddLogEntry(wcsTemp);
	AddLogEntryCmd(wcsTemp);

	wmemset(wcsTemp, 0, MAX_PATH*5);
	swprintf_s(wcsTemp, MAX_PATH*5, _T("TST: %d, TRT: %d, PEC: %d, PEWS: %d, PEBS: %d, PEQ: %d, VDBS: %d, VDBR: %d, VPOLS: %d, VPOLR: %d, TUPT: %d, TADSST: %d, TAUPT: %d, TMLST: %d, TYST: %d"),
				m_dwTotalScanTime, m_dwTotalRepairTime, m_dwPECreationTime, m_dwWPESearchingTime, m_dwBPESearchingTime, m_dwPEQuarantineTime, 
				m_oMaxVirusScanner.GetVirDBScanTime(), m_oMaxVirusScanner.GetVirDBRepairTime(), 
				m_oMaxVirusScanner.GetVirPolyScanTime(), m_oMaxVirusScanner.GetVirPolyRepairTime(), 
				m_dwTotalUnPackTime, m_dwTotalADSScanTime, m_dwTotalArchiveTime,m_dwMLScanTime,m_dwYaraScanTime);
	AddLogEntry(wcsTemp); //, 0, 0, true, LOG_DEBUG);

	//if (m_bMachineLearning)
	{
		wmemset(wcsTemp, 0, MAX_PATH*5);
		swprintf_s(wcsTemp, MAX_PATH*5, _T("TFS: %d, MLS: %d, MLM: %d, HRS: %d, HRM: %d"),m_iTotalNoOfFiles,m_iNoofMLearnSigSearched,m_iNoofMLearnSigMatched,m_iNoofHeurSigSearched,m_iNoofHeurSigMatched);
		AddMLearningLogEntry(wcsTemp); //, 0, 0, true, LOG_DEBUG);
	}

	CTimeSpan ctTotalScanTime = (m_dwTotalScanTime/1000);
	CTimeSpan ctTotalRepairTime = (m_dwTotalRepairTime/1000);
	CTimeSpan ctPECreationTime = (m_dwPECreationTime/1000);
	CTimeSpan ctPEWhiteSearchTime = (m_dwWPESearchingTime/1000);
	CTimeSpan ctPEBlackSearchTime = (m_dwBPESearchingTime/1000);
	CTimeSpan ctPEQuarantineTime = (m_dwPEQuarantineTime/1000);
	CTimeSpan ctVirDBScanTime = (m_oMaxVirusScanner.GetVirDBScanTime()/1000);
	CTimeSpan ctVirDBRepairTime = (m_oMaxVirusScanner.GetVirDBRepairTime()/1000);
	CTimeSpan ctVirPolyScanTime = (m_oMaxVirusScanner.GetVirPolyScanTime()/1000);
	CTimeSpan ctVirPolyRepairTime = (m_oMaxVirusScanner.GetVirPolyRepairTime()/1000);
	CTimeSpan ctTotalUnPackTime = (m_dwTotalUnPackTime/1000);
	CTimeSpan ctTotalADSScanTime = (m_dwTotalADSScanTime/1000);
	CTimeSpan ctTotalArchiveUnPackTime = (m_dwTotalArchiveTime/1000);

	CTimeSpan ctTotalMLScanTime = (m_dwMLScanTime/1000);
	CTimeSpan ctTotalYaraScanTime = (m_dwYaraScanTime/1000);
	
	wmemset(wcsTemp, 0, MAX_PATH*5);
	swprintf_s(wcsTemp, MAX_PATH*5, _T("Total Scan Time       : Hours: %02d, Minutes: %02d, Seconds: %02d\r\n\t\t\t\t  Total Repair Time     : Hours: %02d, Minutes: %02d, Seconds: %02d\r\n\t\t\t\t  PE Creation Time      : Hours: %02d, Minutes: %02d, Seconds: %02d\r\n\t\t\t\t  PE White Search Time  : Hours: %02d, Minutes: %02d, Seconds: %02d\r\n\t\t\t\t  PE Black Search Time  : Hours: %02d, Minutes: %02d, Seconds: %02d\r\n\t\t\t\t  PE Quarantine Time    : Hours: %02d, Minutes: %02d, Seconds: %02d\r\n\t\t\t\t  Virus DB Scan Time    : Hours: %02d, Minutes: %02d, Seconds: %02d\r\n\t\t\t\t  Virus DB Repair Time  : Hours: %02d, Minutes: %02d, Seconds: %02d\r\n\t\t\t\t  Virus Poly Scan Time  : Hours: %02d, Minutes: %02d, Seconds: %02d\r\n\t\t\t\t  Virus Poly Repair Time: Hours: %02d, Minutes: %02d, Seconds: %02d\r\n\t\t\t\t  Total UnPack Time     : Hours: %02d, Minutes: %02d, Seconds: %02d\r\n\t\t\t\t  Total ADS Scan Time   : Hours: %02d, Minutes: %02d, Seconds: %02d\r\n\t\t\t\t  Total Archive Time    : Hours: %02d, Minutes: %02d, Seconds: %02d\r\n\t\t\t\t  Total ML Scan Time    : Hours: %02d, Minutes: %02d, Seconds: %02d\r\n\t\t\t\t  Total Yara Scan Time    : Hours: %02d, Minutes: %02d, Seconds: %02d"),
				(DWORD)ctTotalScanTime.GetHours(), (DWORD)ctTotalScanTime.GetMinutes(), (DWORD)ctTotalScanTime.GetSeconds(), 
				(DWORD)ctTotalRepairTime.GetHours(), (DWORD)ctTotalRepairTime.GetMinutes(), (DWORD)ctTotalRepairTime.GetSeconds(), 
				(DWORD)ctPECreationTime.GetHours(), (DWORD)ctPECreationTime.GetMinutes(), (DWORD)ctPECreationTime.GetSeconds(), 
				(DWORD)ctPEWhiteSearchTime.GetHours(), (DWORD)ctPEWhiteSearchTime.GetMinutes(), (DWORD)ctPEWhiteSearchTime.GetSeconds(), 
				(DWORD)ctPEBlackSearchTime.GetHours(), (DWORD)ctPEBlackSearchTime.GetMinutes(), (DWORD)ctPEBlackSearchTime.GetSeconds(), 
				(DWORD)ctPEQuarantineTime.GetHours(), (DWORD)ctPEQuarantineTime.GetMinutes(), (DWORD)ctPEQuarantineTime.GetSeconds(), 
				(DWORD)ctVirDBScanTime.GetHours(), (DWORD)ctVirDBScanTime.GetMinutes(), (DWORD)ctVirDBScanTime.GetSeconds(), 
				(DWORD)ctVirDBRepairTime.GetHours(), (DWORD)ctVirDBRepairTime.GetMinutes(), (DWORD)ctVirDBRepairTime.GetSeconds(), 
				(DWORD)ctVirPolyScanTime.GetHours(), (DWORD)ctVirPolyScanTime.GetMinutes(), (DWORD)ctVirPolyScanTime.GetSeconds(), 
				(DWORD)ctVirPolyRepairTime.GetHours(), (DWORD)ctVirPolyRepairTime.GetMinutes(), (DWORD)ctVirPolyRepairTime.GetSeconds(),
				(DWORD)ctTotalUnPackTime.GetHours(), (DWORD)ctTotalUnPackTime.GetMinutes(), (DWORD)ctTotalUnPackTime.GetSeconds(),
				(DWORD)ctTotalADSScanTime.GetHours(), (DWORD)ctTotalADSScanTime.GetMinutes(), (DWORD)ctTotalADSScanTime.GetSeconds(),
				(DWORD)ctTotalArchiveUnPackTime.GetHours(), (DWORD)ctTotalArchiveUnPackTime.GetMinutes(), (DWORD)ctTotalArchiveUnPackTime.GetSeconds(),
				(DWORD)ctTotalMLScanTime.GetHours(), (DWORD)ctTotalMLScanTime.GetMinutes(), (DWORD)ctTotalMLScanTime.GetSeconds(),
				(DWORD)ctTotalYaraScanTime.GetHours(), (DWORD)ctTotalYaraScanTime.GetMinutes(), (DWORD)ctTotalYaraScanTime.GetSeconds());
	AddLogEntry(wcsTemp, 0, 0, true, LOG_DEBUG);

	CTimeSpan ctMaxPEFileCreationTime = (m_dwMaxPEFileCreationTime / 1000);
	CTimeSpan ctRansScanTime = (m_dwRansScanTime / 1000);
	CTimeSpan ctAppDataScanTime = (m_dwAppDataScanTime / 1000);
	CTimeSpan ctPatScanTime = (m_dwPatScanTime / 1000);
	CTimeSpan ctInstScanTime = (m_dwInstScanTime / 1000);
	CTimeSpan ctCompSafeScanTime = (m_dwCompSafeScanTime / 1000);
	wmemset(wcsTemp, 0, MAX_PATH * 5);

	swprintf_s(wcsTemp, MAX_PATH * 5, _T("Total PE File Time       : Hours: %02d, Minutes: %02d, Seconds: %02d\r\n\t\t\t\t  Total RansPat Scan Time     : Hours: %02d, Minutes: %02d, Seconds: %02d\r\n\t\t\t\t  Total AppPat Scan Time     : Hours: %02d, Minutes: %02d, Seconds: %02d\r\n\t\t\t\t  Total Pat Scan Time     : Hours: %02d, Minutes: %02d, Seconds: %02d\r\n\t\t\t\t  Total INST Scan Time     : Hours: %02d, Minutes: %02d, Seconds: %02d\r\n\t\t\t\t  Total ComSafe Scan Time     : Hours: %02d, Minutes: %02d, Seconds: %02d"),
		(DWORD)ctMaxPEFileCreationTime.GetHours(), (DWORD)ctMaxPEFileCreationTime.GetMinutes(), (DWORD)ctMaxPEFileCreationTime.GetSeconds(),
		(DWORD)ctRansScanTime.GetHours(), (DWORD)ctRansScanTime.GetMinutes(), (DWORD)ctRansScanTime.GetSeconds(),
		(DWORD)ctAppDataScanTime.GetHours(), (DWORD)ctAppDataScanTime.GetMinutes(), (DWORD)ctAppDataScanTime.GetSeconds(),
		(DWORD)ctPatScanTime.GetHours(), (DWORD)ctPatScanTime.GetMinutes(), (DWORD)ctPatScanTime.GetSeconds(),
		(DWORD)ctInstScanTime.GetHours(), (DWORD)ctInstScanTime.GetMinutes(), (DWORD)ctInstScanTime.GetSeconds(),
		(DWORD)ctCompSafeScanTime.GetHours(), (DWORD)ctCompSafeScanTime.GetMinutes(), (DWORD)ctCompSafeScanTime.GetSeconds());

	AddLogEntry(wcsTemp, 0, 0, true, LOG_DEBUG);


	CTimeSpan ctDBBufferReadTime = (m_oMaxVirusScanner.GetDBBufferReadTime() / 1000);
	CTimeSpan ctDBBufferScanTime = (m_oMaxVirusScanner.GetDBBufferScanTime() / 1000);
	
	wmemset(wcsTemp, 0, MAX_PATH * 5);

	swprintf_s(wcsTemp, MAX_PATH * 5, _T("Total DB Buffer Read Time       : Hours: %02d, Minutes: %02d, Seconds: %02d\r\n\t\t\t\t  Total DB Buffer Scan Time     : Hours: %02d, Minutes: %02d, Seconds: %02d"),
		(DWORD)ctDBBufferReadTime.GetHours(), (DWORD)ctDBBufferReadTime.GetMinutes(), (DWORD)ctDBBufferReadTime.GetSeconds(),
		(DWORD)ctDBBufferScanTime.GetHours(), (DWORD)ctDBBufferScanTime.GetMinutes(), (DWORD)ctDBBufferScanTime.GetSeconds());

	AddLogEntry(wcsTemp, 0, 0, true, LOG_DEBUG);

	delete [] wcsTemp;
	wcsTemp = NULL;
}

bool CMaxScanner::ScanFile(PMAX_SCANNER_INFO pScanInfo)
{
	//WaitForSingleObject(m_hEvent, INFINITE);
	bool bReturnVal = false;
	DWORD dwStartTime = GetTickCount();

	
	BOOL	bBreak = FALSE;
	TCHAR	szLogLine[1024] = { 0x00 };

	__try
	{
		
		bReturnVal = _ScanFileTimer(pScanInfo);

		if(pScanInfo->AutoQuarantine == false)	// we dont need the extracted files anymore!
		{
			_CloseMaxPEFile(pScanInfo, true);
		}
	}
	__except(CMaxExceptionFilter::Filter(GetExceptionCode(), GetExceptionInformation(), _T("Exception caught CMaxScanner::ScanFile"), (pScanInfo->IsChildFile ? pScanInfo->szContainerFileName : pScanInfo->szFileToScan)))
	{
	}
	m_dwTotalScanTime += (GetTickCount() - dwStartTime);
	//SetEvent(m_hEvent);
	return bReturnVal;
}

bool CMaxScanner::_ScanFileTimer(PMAX_SCANNER_INFO pScanInfo)
{
	bool	bReturnVal = false;
	bool	bValidDigiCertificate = false;
	BOOL	bAllowedExttoScan = TRUE;
	AddLogEntry(L">>>>> BEGIN      : %s", pScanInfo->szFileToScan, 0, true, LOG_DEBUG);

	if (m_dwActmonScan == 1 && m_dwSnoozeActMon == 1)
	{
		AddLogEntry(L"##### SKIP-SNOOZE-ACT : %s\r\n", pScanInfo->szFileToScan, 0, true, LOG_DEBUG);
		return false;
	}

	PESIGCRCLOCALDB oPEFileSigLocal = {0};
	VIRUSLOCALDB oVirusDBLocal = {0};	
	if(pScanInfo->szFileToScan[0]==L'\\')
	{
		ConfigForNetworkScan(pScanInfo->szFileToScan);
	}

	if (_IsExcludeScanExtension(pScanInfo) > -1)
	{
		m_iTotalNoOfFilesSkipped++;
		AddLogEntry(L"##### SKIP-EXLD-EXT : %s\r\n", pScanInfo->szFileToScan, 0, true, LOG_DEBUG);
		AddLogEntryCmd(L"%s	skipped", pScanInfo->szFileToScan,0,true,LOG_DEBUG);
		return false;
	}

	m_oLocalSignature.GetFileSignature(pScanInfo->szFileToScan, oPEFileSigLocal, oVirusDBLocal);

	if((oPEFileSigLocal.iFileSigCreated == true) && (oVirusDBLocal.iVirusFoundStatus == false) && (oVirusDBLocal.iIsArchiveFile == true)
		&& (oVirusDBLocal.iMaxVirusScanDone == true)
		&& memcmp(m_btPolyVirusRevIDS, oPEFileSigLocal.btVirusPolyScanStatus, sizeof(m_btPolyVirusRevIDS)) == 0)
	{
		m_iTotalNoOfFilesSkipped++;
		AddLogEntry(L"##### SKIP-LOCAL : %s\r\n", pScanInfo->szFileToScan, 0, true, LOG_DEBUG);
		AddLogEntryCmd(L"%s	skipped", pScanInfo->szFileToScan,0,true,LOG_DEBUG);
		return false;
	}
	
	if((oPEFileSigLocal.iFileSigCreated == false) || (oVirusDBLocal.iVirusFoundStatus == true) || (oVirusDBLocal.iIsArchiveFile == true)
		|| (oVirusDBLocal.iMaxVirusScanDone == false)
		|| (memcmp(m_btPolyVirusRevIDS, oPEFileSigLocal.btVirusPolyScanStatus, sizeof(m_btPolyVirusRevIDS)) != 0))
	{
		if(!_CreateMaxPEObject(pScanInfo, oPEFileSigLocal, true, false))
		{
			AddLogEntry(L">>>>> PEFAILED: %s", pScanInfo->szFileToScan, 0, true, LOG_DEBUG);
		}
		
		pScanInfo->eVirusFileType = _CheckFileType(pScanInfo); 
		if (pScanInfo->eVirusFileType == 0x00)
		{
			if (_IsExtensiontoScan(pScanInfo) != 0x01)
			{
				bAllowedExttoScan = FALSE;
			}
		}

		if(pScanInfo->eVirusFileType > VIRUS_FILE_TYPE_NSIS || bAllowedExttoScan == FALSE)		//NSIS nullsoft 7zip extrzction 26-July-2018 :Ravi
		{
			oPEFileSigLocal.iFileSigCreated = true;
			oVirusDBLocal.iIsArchiveFile = true;	// using isarchive flag as this will help in second scan!
			m_oLocalSignature.SetFileSignature(pScanInfo->szFileToScan, oPEFileSigLocal, oVirusDBLocal);
			
			m_iTotalNoOfFilesSkipped++;
			_CloseMaxPEFile(pScanInfo, true);	// will close all open handles
			AddLogEntry(L"##### SKIP-TYPE  : %s\r\n", pScanInfo->szFileToScan, 0, true, LOG_DEBUG);
			AddLogEntryCmd(L"%s	skipped", pScanInfo->szFileToScan,0,true,LOG_DEBUG);
			return false;
		}

		if(m_dwSkipCompressfiles == 1)
		{
			if((pScanInfo->eVirusFileType == VIRUS_FILE_TYPE_RAR)|| (pScanInfo->eVirusFileType == VIRUS_FILE_TYPE_ZIP)
				|| (pScanInfo->eVirusFileType == VIRUS_FILE_TYPE_DMG) || (pScanInfo->eVirusFileType == VIRUS_FILE_TYPE_MSCAB)
				|| (pScanInfo->eVirusFileType == VIRUS_FILE_TYPE_MSI) || (pScanInfo->eVirusFileType == VIRUS_FILE_TYPE_GZ)
				|| (pScanInfo->eVirusFileType == VIRUS_FILE_TYPE_7Z))
			{
				if (_IsExtensiontoScan(pScanInfo) != 0x01)
				{
					m_iTotalNoOfFilesSkipped++;
					_CloseMaxPEFile(pScanInfo, true);	// will close all open handles
					AddLogEntry(L"##### SKIP COMPRESS-TYPE  : %s\r\n", pScanInfo->szFileToScan, 0, true, LOG_DEBUG);
					AddLogEntryCmd(L"%s	skipped", pScanInfo->szFileToScan, 0, true, LOG_DEBUG);
					return false;
				}
			}
		}
		else if (m_dwSkipCompressfiles == 0x00 && m_dwActmonScan == 0x01)
		{
			if ((pScanInfo->eVirusFileType == VIRUS_FILE_TYPE_RAR) || (pScanInfo->eVirusFileType == VIRUS_FILE_TYPE_ZIP)
				|| (pScanInfo->eVirusFileType == VIRUS_FILE_TYPE_DMG) || (pScanInfo->eVirusFileType == VIRUS_FILE_TYPE_MSCAB)
				|| (pScanInfo->eVirusFileType == VIRUS_FILE_TYPE_MSI) || (pScanInfo->eVirusFileType == VIRUS_FILE_TYPE_GZ)
				|| (pScanInfo->eVirusFileType == VIRUS_FILE_TYPE_7Z))
			{
				if (_IsExtensiontoScan(pScanInfo) != 0x01 || (pScanInfo->pMaxPEFile->m_dwFileSize > ((1024 * 1024) * 15)))
				{
					m_iTotalNoOfFilesSkipped++;
					_CloseMaxPEFile(pScanInfo, true);	// will close all open handles
					AddLogEntry(L"##### SKIP COMPRESS-TYPE-RTL : %s\r\n", pScanInfo->szFileToScan, 0, true, LOG_DEBUG);
					AddLogEntryCmd(L"%s	skipped", pScanInfo->szFileToScan, 0, true, LOG_DEBUG);
					return false;
				}
			}
		}

		if(pScanInfo->pMaxPEFile && pScanInfo->eVirusFileType > 0)
		{
			oVirusDBLocal.iIsArchiveFile = true;
			m_oLocalSignature.SetFileSignature(pScanInfo->szFileToScan, oPEFileSigLocal, oVirusDBLocal);

			bool bSizeLimitCrossed = false;
			if(pScanInfo->pMaxPEFile->m_dwFileSize > ((1024 * 1024) * 99))
			{
				bSizeLimitCrossed = true;
			}
			
			if((pScanInfo->eVirusFileType == VIRUS_FILE_TYPE_ZIP) || (pScanInfo->eVirusFileType == VIRUS_FILE_TYPE_EML)
				|| (pScanInfo->eVirusFileType == VIRUS_FILE_TYPE_MSCHM) || (pScanInfo->eVirusFileType == VIRUS_FILE_TYPE_MSSZDD)
				|| (pScanInfo->eVirusFileType == VIRUS_FILE_TYPE_CRYPTCFF) || (pScanInfo->eVirusFileType == VIRUS_FILE_TYPE_MSCAB)
				|| (pScanInfo->eVirusFileType == VIRUS_FILE_TYPE_GZ) || (pScanInfo->eVirusFileType == VIRUS_FILE_TYPE_7Z) || (pScanInfo->eVirusFileType == VIRUS_FILE_TYPE_MSI))
			{				
				_CloseMaxPEFile(pScanInfo, true);	// will close all open handles
			}
			if((pScanInfo->eVirusFileType == VIRUS_FILE_TYPE_UB) || (pScanInfo->eVirusFileType == VIRUS_FILE_TYPE_DMG))
			{
				_CloseMaxPEFile(pScanInfo, true);	// will close all open handles
			}

			if((pScanInfo->eVirusFileType == VIRUS_FILE_TYPE_SIS) || (pScanInfo->eVirusFileType == VIRUS_FILE_TYPE_RAR)
				 || (pScanInfo->eVirusFileType == VIRUS_FILE_TYPE_NSIS))
			{
				bReturnVal = _ScanFileNew(pScanInfo);
				if(bReturnVal)
				{
					CString csThreatName;
					csThreatName.Format(_T("%s"),pScanInfo->szThreatName);
					csThreatName.Trim();
					if(csThreatName.IsEmpty())
					{
						csThreatName.Format(_T("Trojan.Malware.%d.susgen"),pScanInfo->ulThreatID);
					}
					CString csLog;
					csLog.Format(L"%s	detected: %s	%s", pScanInfo->szFileToScan, csThreatName, pScanInfo->szFileSig);
					AddLogEntryCmd(csLog);
					if(pScanInfo->ulThreatID == 121218)
					{
						AddYaraLogEntryCmd(csLog);
					}
					
					_CloseMaxPEFile(pScanInfo, !bReturnVal);	// will close all open handles
					AddLogEntry(L">>>>> FINISH     : %s\r\n", pScanInfo->szFileToScan, 0, true, LOG_DEBUG);
					return bReturnVal;
				}
				
				if (pScanInfo->eVirusFileType == VIRUS_FILE_TYPE_NSIS)
				{
					bValidDigiCertificate = IsValidDidCertificate(pScanInfo->szFileToScan);
					if (bValidDigiCertificate == false)
					{
						_CloseMaxPEFile(pScanInfo, true);	// will close all open handles
					}
					else
					{
						m_iTotalNoOfFilesSkipped++;
						_CloseMaxPEFile(pScanInfo, true);				// will close all open handles
						AddLogEntry(L"##### SKIP-NSISDIG   : %s\r\n", pScanInfo->szFileToScan, 0, true, LOG_DEBUG);
						AddLogEntryCmd(L"%s	skipped", pScanInfo->szFileToScan,0,true,LOG_DEBUG);
					}
				}
			}

			if((pScanInfo->eVirusFileType == VIRUS_FILE_TYPE_PNG) || (pScanInfo->eVirusFileType == VIRUS_FILE_TYPE_BMP))
			{
				if (pScanInfo->pMaxPEFile->SearchForPEHdr() == false)
				{
					_CloseMaxPEFile(pScanInfo, true);				// will close all open handles
					AddLogEntry(L"##### SKIP-IMG  : %s\r\n", pScanInfo->szFileToScan, 0, true, LOG_DEBUG);
					AddLogEntryCmd(L"%s	skipped", pScanInfo->szFileToScan,0,true,LOG_DEBUG);
					return false;
				}
			}

			if(bSizeLimitCrossed)
			{
				oPEFileSigLocal.iFileSigCreated = true;
				m_oLocalSignature.SetFileSignature(pScanInfo->szFileToScan, oPEFileSigLocal, oVirusDBLocal);
				m_iTotalNoOfFilesSkipped++;
				_CloseMaxPEFile(pScanInfo, true);				// will close all open handles
				AddLogEntry(L"##### SKIP-BIG   : %s\r\n", pScanInfo->szFileToScan, 0, true, LOG_DEBUG);
				AddLogEntryCmd(L"%s	skipped", pScanInfo->szFileToScan,0,true,LOG_DEBUG);
				return false;
			}
		}
	}

	TCHAR szExtractPath[MAX_PATH] = {0};
	if (bValidDigiCertificate == false)
	{
		if (_tcslen(pScanInfo->szContainerFileName) <= 0x00)
		{
			m_dwZipRecursionCnt = 0x00;
		}
		_ExtractFile(pScanInfo, szExtractPath);
	}

	if(szExtractPath[0])
	{
		m_dwZipRecursionCnt++;
		if (m_dwZipRecursionCnt > MAX_ZIP_RECURSSION_LEVEL)
		{
			AddLogEntry(L"##### SKIP-REC : %s", pScanInfo->szFileToScan, NULL, true, LOG_DEBUG);
			_CloseMaxPEFile(pScanInfo, true);
			m_oDirectoryManager.MaxDeleteDirectory(szExtractPath, true);
			return false;
		}	

		m_iTotalNoOfArchiveSuccessFiles++;
		AddLogEntry(L">>>>> EXTRACTED  : %s -> %s", pScanInfo->szFileToScan, szExtractPath, true, LOG_DEBUG);
		bool bPrevStatus = pScanInfo->AutoQuarantine;
		pScanInfo->AutoQuarantine = (bPrevStatus && pScanInfo->IsEMLFile ? 1 : 0);
		if ((pScanInfo->ThreatDetected == 0 && pScanInfo->ThreatSuspicious == 0))
		{
			_ScanFolder(pScanInfo, szExtractPath);
		}
		bReturnVal = (pScanInfo->ThreatDetected || pScanInfo->ThreatSuspicious);
		pScanInfo->AutoQuarantine = bPrevStatus;
		_CloseMaxPEFile(pScanInfo, !bReturnVal);	// will close all open handles
		if(!SkipExtractPathFile(pScanInfo->szFileToScan))
		{
			if(bReturnVal)
			{
				CString csThreatName;
				csThreatName.Format(_T("%s"),pScanInfo->szThreatName);
				csThreatName.Trim();
				if(csThreatName.IsEmpty())
				{
					csThreatName.Format(_T("Trojan.Malware.%d.susgen"),pScanInfo->ulThreatID);
				}
				CString csLog;
				csLog.Format(L"%s	detected: %s", pScanInfo->szFileToScan, csThreatName);
				AddLogEntryCmd(csLog);
				if(pScanInfo->ulThreatID == 121218)
				{
					AddYaraLogEntryCmd(csLog);
				}
			}
			else
			{
				AddLogEntryCmd(L"%s	ok", pScanInfo->szFileToScan,0,true,LOG_DEBUG);
			}
		}
		if(pScanInfo->eVirusFileType != VIRUS_FILE_TYPE_EML)
		{
			m_oDirectoryManager.MaxDeleteDirectory(szExtractPath, true);
		}
		else if(bReturnVal)
		{
			pScanInfo->eMessageInfo = Virus_File_Repair;
			pScanInfo->eDetectedBY = Detected_BY_MaxVirus_DB;
		}

		m_oLocalSignature.GetFileSignature(pScanInfo->szFileToScan, oPEFileSigLocal, oVirusDBLocal);
		oVirusDBLocal.iMaxVirusScanDone = true;
		oVirusDBLocal.iVirusFoundStatus = bReturnVal;
		oPEFileSigLocal.iFileSigCreated = true;
		memcpy(oPEFileSigLocal.btVirusPolyScanStatus, m_btPolyVirusRevIDS, sizeof(m_btPolyVirusRevIDS));
		m_oLocalSignature.SetFileSignature(pScanInfo->szFileToScan, oPEFileSigLocal, oVirusDBLocal);

		if((!bReturnVal) && (pScanInfo->eVirusFileType == VIRUS_FILE_TYPE_EML))
		{
			_RePackEMLToFolder(pScanInfo, szExtractPath);
		}
		else if((bReturnVal) && (pScanInfo->AutoQuarantine == 1))
		{
			_ScanAndRepairFile(pScanInfo);
			if(pScanInfo->eVirusFileType == VIRUS_FILE_TYPE_EML)
			{
				_RePackEMLToFolder(pScanInfo, szExtractPath);
			}
		}
		else
		{
			m_oDirectoryManager.MaxDeleteDirectory(szExtractPath, true);
		}
		AddLogEntry(L">>>>> FINISH     : %s\r\n", pScanInfo->szFileToScan, 0, true, LOG_DEBUG);
	}
	else
	{
		if((pScanInfo->eVirusFileType == VIRUS_FILE_TYPE_SIS) || 
			(pScanInfo->eVirusFileType == VIRUS_FILE_TYPE_RAR) || 
			(pScanInfo->eVirusFileType == VIRUS_FILE_TYPE_ZIP)||
			(pScanInfo->eVirusFileType == VIRUS_FILE_TYPE_7Z))
		{
			m_iTotalNoOfArchiveFailedFiles++;
		}
		else
		{
			bReturnVal = _ScanFileNew(pScanInfo);
			if(!SkipExtractPathFile(pScanInfo->szFileToScan))
			{
				if(bReturnVal)
				{
					CString csThreatName;
					csThreatName.Format(_T("%s"),pScanInfo->szThreatName);
					csThreatName.Trim();
					if(csThreatName.IsEmpty())
					{
						csThreatName.Format(_T("Trojan.Malware.%d.susgen"),pScanInfo->ulThreatID);
					}
					CString csLog;
					csLog.Format(L"%s	detected: %s	%s", pScanInfo->szFileToScan, csThreatName, pScanInfo->szFileSig);
					AddLogEntryCmd(csLog);
					if(pScanInfo->ulThreatID == 121218)
					{
						AddYaraLogEntryCmd(csLog);
					}

				}
				else
				{
					AddLogEntryCmd(L"%s	ok", pScanInfo->szFileToScan,0,true,LOG_DEBUG);
				}
			}
		}
	}
	_CloseMaxPEFile(pScanInfo, !bReturnVal);	// will close all open handles


	if(!bReturnVal && !pScanInfo->IsChildFile && pScanInfo->IsLockedFile)
	{
		bReturnVal = _CopyFileToTempFolder(pScanInfo);
		if((bReturnVal) && (pScanInfo->AutoQuarantine == 1))
		{
			_ReplaceLockedFile(pScanInfo);
		}
		_CloseMaxPEFile(pScanInfo, !bReturnVal);	// will close all open handles
	}

	return bReturnVal;
}

void CMaxScanner::_ExtractFile(PMAX_SCANNER_INFO pScanInfo, LPTSTR szExtractPath)
{
	DWORD dwStartTime = GetTickCount();
	__try
	{
		switch(pScanInfo->eVirusFileType)
		{
		case VIRUS_FILE_TYPE_GZ:							// 7Zip Extraction
		case VIRUS_FILE_TYPE_RAR:
		case VIRUS_FILE_TYPE_MSCAB:
		case VIRUS_FILE_TYPE_UB:
		case VIRUS_FILE_TYPE_DMG:
		case VIRUS_FILE_TYPE_ZIP:
		case VIRUS_FILE_TYPE_SIS:
		case VIRUS_FILE_TYPE_MSI:
		case VIRUS_FILE_TYPE_NSIS:
		case VIRUS_FILE_TYPE_7ZSFX:
		case VIRUS_FILE_TYPE_7Z:
			{
				m_obj7zDLL.UnMax7zArchiveEx(pScanInfo->szFileToScan, szExtractPath);
			}
			break;
		/*case VIRUS_FILE_TYPE_RAR:
			{
				if(m_lpfnExtractFile)
				{
					m_iTotalNoOfArchiveFiles++;
					m_lpfnExtractFile(pScanInfo->szFileToScan, szExtractPath);
					if(!szExtractPath[0])
					{
						AddLogEntry(L"##### EXTRACFAIL : %s", pScanInfo->szFileToScan, 0, true, LOG_DEBUG);
					}
				}
			}
			break;*/
		case VIRUS_FILE_TYPE_MSCHM:
		case VIRUS_FILE_TYPE_MSSZDD:
		case VIRUS_FILE_TYPE_CRYPTCFF:
		/*case VIRUS_FILE_TYPE_MSCAB:
		case VIRUS_FILE_TYPE_UB:
		case VIRUS_FILE_TYPE_DMG:*/
			{
				if(m_lpfnExtractNonPEFile)
				{
					m_iTotalNoOfArchiveFiles++;
					m_lpfnExtractNonPEFile(pScanInfo->eVirusFileType, pScanInfo->szFileToScan, szExtractPath);
					if(!szExtractPath[0])
					{
						AddLogEntry(L"##### EXTRACFAIL : %s", pScanInfo->szFileToScan, 0, true, LOG_DEBUG);
					}
				}
			}
			break;
		/*case VIRUS_FILE_TYPE_ZIP:
			{
				_UnzipToFolderSEH(pScanInfo->szFileToScan, szExtractPath);
				if(!szExtractPath[0])
				{
					AddLogEntry(L"##### EXTRACFAIL : %s", pScanInfo->szFileToScan, 0, true, LOG_DEBUG);
				}
			}
			break;*/
		/*case VIRUS_FILE_TYPE_SIS:
			{
				_ExtractSISToFolderSEH(pScanInfo->szFileToScan, szExtractPath);
				if(!szExtractPath[0])
				{
					AddLogEntry(L"##### EXTRACFAIL : %s", pScanInfo->szFileToScan, 0, true, LOG_DEBUG);
				}
			}
			break;*/
		case VIRUS_FILE_TYPE_EML:
			{
				pScanInfo->IsEMLFile = true;
				_ExtractEMLToFolderSEH(pScanInfo, szExtractPath);
				if(!szExtractPath[0])
				{
					AddLogEntry(L"##### EXTRACFAIL : %s", pScanInfo->szFileToScan, 0, true, LOG_DEBUG);
				}
			}
			break;
		default:
			break;
		}
	}
	__except(CMaxExceptionFilter::Filter(GetExceptionCode(), GetExceptionInformation(), _T("Exception caught Scanner::_ExtractFile"), (pScanInfo->IsChildFile ? pScanInfo->szContainerFileName : pScanInfo->szFileToScan)))
	{
	}
	m_dwTotalArchiveTime += (GetTickCount() - dwStartTime);
}

bool CMaxScanner::_ScanFileNew(PMAX_SCANNER_INFO pScanInfo)
{
	_wcslwr_s(pScanInfo->szFileToScan);

	bool bReturn = false;
	__try
	{
		AddLogEntry(L">>>>> SCN       1: %s", pScanInfo->szFileToScan, 0, true, LOG_DEBUG);

		ULONG ulStatus = FSS_NEW_FILE;
		if((ulStatus != FSS_SCAN_STARTED) && (ulStatus != FSS_REPAIR_STARTED))
		{
			bool bPrevStatus = pScanInfo->AutoQuarantine;
			pScanInfo->AutoQuarantine = 0;
			if ((pScanInfo->ThreatDetected == 0 && pScanInfo->ThreatSuspicious == 0))
			{
				bReturn = _ScanPackedFile(pScanInfo, 1);
			}
			else if(pScanInfo->pMaxPEFile && (pScanInfo->ThreatDetected == 1 || pScanInfo->ThreatSuspicious == 1))
			{
				bool bReturnVal = true;
				_CloseMaxPEFile(pScanInfo, !bReturnVal);	// will close all open handles
			}
			pScanInfo->AutoQuarantine = bPrevStatus;
			if(pScanInfo->ulProcessIDToScan == SCAN_ACTION_TIMEOUT)
			{
				bReturn = false;
			}
			else if(pScanInfo->ThreatDetected == 1 || pScanInfo->ThreatSuspicious == 1)
			{
				if(IsExcluded(pScanInfo->ulThreatID, pScanInfo->szThreatName, pScanInfo->szFileToScan))
				{
					pScanInfo->IsExcluded = 1;
					pScanInfo->ThreatDetected = 0;
					pScanInfo->ThreatSuspicious = 0;
					memset(pScanInfo->szThreatName, 0, sizeof(pScanInfo->szThreatName));
					AddLogEntry(L">>>>> EXL        : %s, ThreatName: %s\r\n", pScanInfo->szFileToScan, pScanInfo->szThreatName);
					return false;
				}
				if(pScanInfo->AutoQuarantine == 1)
				{
					bReturn = _ScanAndRepairFile(pScanInfo);
					_CloseMaxPEFile(pScanInfo, true);	// will close all open handles
				}
			}
		}
		else
		{
			AddLogEntry(L">>>>> BAD-FILE   : %s", pScanInfo->szFileToScan, 0, true, LOG_DEBUG);
			if(m_pMaxDSrvWrapper)
			{
				m_pMaxDSrvWrapper->AddFileToRescannedDB(pScanInfo->szFileToScan, pScanInfo->szThreatName);
			}
			m_pThreatManager->AddFileToRescannedDB(pScanInfo->szFileToScan, pScanInfo->szThreatName);
		}
		AddLogEntry(L">>>>> FINISH     : %s\r\n", pScanInfo->szFileToScan, 0, true, LOG_DEBUG);
	}
	__except(CMaxExceptionFilter::Filter(GetExceptionCode(), GetExceptionInformation(), _T("Exception caught Scanner::_ScanFileNew"), (pScanInfo->IsChildFile ? pScanInfo->szContainerFileName : pScanInfo->szFileToScan)))
	{
	}
	return bReturn;
}

bool CMaxScanner::_ScanAndRepairFile(PMAX_SCANNER_INFO pScanInfo)
{
	if(pScanInfo->IsEMLFile)		// only backup the main eml file!
	{
		if(!pScanInfo->IsChildFile)		// incase of child of eml file, no back up is required!
		{
			if(!m_pThreatManager->BackupFile(pScanInfo))
			{
				return false;
			}
			return true;
		}
	}
	else
	{
		if(!m_pThreatManager->BackupFile(pScanInfo))
		{
			return false;
		}		
	}

	TCHAR szDummyPath[1024] = {0};
	bool bUsingDummyFile = m_pThreatManager->GetRepairFileName(pScanInfo->szFileToScan, szDummyPath);
	if(bUsingDummyFile)
	{
		AddLogEntry(L">>>>> DMY-NAME   : %s : %s", pScanInfo->szFileToScan, szDummyPath, true, LOG_DEBUG);
		_tcscpy_s(pScanInfo->szFreshFile, _countof(pScanInfo->szFreshFile), pScanInfo->szFileToScan);
		_tcscpy_s(pScanInfo->szFileToScan, _countof(pScanInfo->szFileToScan), szDummyPath);
	}

	if(pScanInfo->IsArchiveFile)
	{
		if(pScanInfo->eVirusFileType != VIRUS_FILE_TYPE_EML)
		{
			if(bUsingDummyFile)
			{
				pScanInfo->ThreatQuarantined = false;
				m_pThreatManager->AddInRestartDeleteList(RD_FILE_DELETE, 0, pScanInfo->szFreshFile);
				AddLogEntry(L"^^^^^ ADD-RST-Q1  : %s", pScanInfo->szFreshFile, 0, true, LOG_DEBUG);
				_tcscpy_s(pScanInfo->szFileToScan, _countof(pScanInfo->szFileToScan), pScanInfo->szFreshFile);
			}
			else
			{
				if(DeleteFile(pScanInfo->szFileToScan))
				{
					pScanInfo->ThreatQuarantined = true;
				}
				else
				{
					m_pThreatManager->AddInRestartDeleteList(RD_FILE_DELETE, 0, pScanInfo->szFileToScan);
					AddLogEntry(L"^^^^^ ADD-RST-Q2  : %s", pScanInfo->szFileToScan, 0, true, LOG_DEBUG);
				}
			}
		}
		return true;
	}

	bool bReturn = false;
	MAX_SCANNER_INFO oScanInfo = {0};

	if(pScanInfo->IsPackedFile && pScanInfo->pNextScanInfo && (pScanInfo->eMessageInfo == Virus_File_Repair))	// work on the unpacked file on which we need to take action!
	{
		memcpy(&oScanInfo, pScanInfo->pNextScanInfo, sizeof(MAX_SCANNER_INFO));
	}
	else
	{
		memcpy(&oScanInfo, pScanInfo, sizeof(MAX_SCANNER_INFO));
	}

	DWORD dwRepairResult = REAPIR_STATUS_FAILURE;
	for(int iCtr = 0; iCtr < 500; iCtr++)
	{
		oScanInfo.ThreatRepaired = 0;
		oScanInfo.ThreatQuarantined = 0;
		oScanInfo.ThreatNonCurable = 0;
		dwRepairResult = _RepairFile(&oScanInfo, (iCtr+1));
		if((dwRepairResult == REAPIR_STATUS_CORRUPT) || (dwRepairResult == REAPIR_STATUS_TIMEOUT))
		{
			bReturn = false;
			break;
		}
		if((oScanInfo.ThreatRepaired == 0) || (oScanInfo.ThreatQuarantined == 1) || (oScanInfo.ThreatNonCurable == 1))
		{
			bReturn = true;
			if(oScanInfo.ThreatNonCurable)
			{
				bReturn = false;
				AddLogEntry(L">>>>> RE-SCN : %s", pScanInfo->szFileToScan, 0, true, LOG_DEBUG);
				if(m_pMaxDSrvWrapper)
				{
					m_pMaxDSrvWrapper->AddFileToRescannedDB(pScanInfo->szFileToScan, pScanInfo->szThreatName);
				}
				m_pThreatManager->AddFileToRescannedDB(pScanInfo->szFileToScan, pScanInfo->szThreatName);
			}
			break;
		}
		oScanInfo.ThreatDetected = 0;
		oScanInfo.ThreatSuspicious = 0;

		bReturn = _ScanPackedFile(&oScanInfo, (iCtr+2));

		if(oScanInfo.ulProcessIDToScan == SCAN_ACTION_TIMEOUT)
		{
			bReturn = false;
			break;
		}
		if(oScanInfo.ThreatDetected == 0 && oScanInfo.ThreatSuspicious == 0)
		{
			bReturn = true;
			break;
		}
	}
	pScanInfo->eMessageInfo = oScanInfo.eMessageInfo;
	pScanInfo->ThreatRepaired = oScanInfo.ThreatRepaired;
	pScanInfo->ThreatQuarantined = oScanInfo.ThreatQuarantined;
	pScanInfo->ThreatNonCurable = oScanInfo.ThreatNonCurable;

	if(dwRepairResult == REAPIR_STATUS_CORRUPT)
	{
		// restore backup file!
		AddLogEntry(L"##### FILECORRUPT: %s, %s", pScanInfo->szFileToScan, oScanInfo.szThreatName, true, LOG_DEBUG);
		_RestoreOriginal(bUsingDummyFile, pScanInfo);
		AddLogEntry(L">>>>> RE-SCN : %s", pScanInfo->szFileToScan, 0, true, LOG_DEBUG);
		if(m_pMaxDSrvWrapper)
		{
			m_pMaxDSrvWrapper->AddFileToRescannedDB(pScanInfo->szFileToScan, pScanInfo->szThreatName);
		}
		m_pThreatManager->AddFileToRescannedDB(pScanInfo->szFileToScan, pScanInfo->szThreatName);

	}
	else if(bUsingDummyFile)
	{
		if(pScanInfo->ThreatQuarantined)
		{
			pScanInfo->ThreatQuarantined = false;
			m_pThreatManager->AddInRestartDeleteList(RD_FILE_DELETE, 0, pScanInfo->szFreshFile);
			AddLogEntry(L"^^^^^ ADD-RST-Q3  : %s", pScanInfo->szFreshFile, 0, true, LOG_DEBUG);
		}
		else if(pScanInfo->ThreatRepaired)
		{
			pScanInfo->ThreatRepaired = false;
			m_pThreatManager->MakeRestartReplaceEntry(pScanInfo->szFreshFile, pScanInfo->szFileToScan);
			AddLogEntry(L"^^^^^ ADD-RST-REP: %s : %s", pScanInfo->szFreshFile, pScanInfo->szFileToScan, true, LOG_DEBUG);
			if(pScanInfo->IsPackedFile && pScanInfo->pNextScanInfo && (pScanInfo->eMessageInfo == Virus_File_Repair))
			{
				DeleteFile(pScanInfo->szFileToScan);
				CopyFile(pScanInfo->pNextScanInfo->szFileToScan, pScanInfo->szFileToScan, FALSE);
				AddLogEntry(L"##### PKD-REP    : %s : %s", pScanInfo->pNextScanInfo->szFileToScan, pScanInfo->szFileToScan, true, LOG_DEBUG);
			}
		}
		else //using dummy repair failed, lets clean up!
		{
			DeleteFile(pScanInfo->szFileToScan);
		}
		_tcscpy_s(pScanInfo->szFileToScan, _countof(pScanInfo->szFileToScan), pScanInfo->szFreshFile);
	}
	else if((pScanInfo->ThreatRepaired) && (pScanInfo->IsPackedFile && pScanInfo->pNextScanInfo && (pScanInfo->eMessageInfo == Virus_File_Repair)))
	{
		DeleteFile(pScanInfo->szFileToScan);
		CopyFile(pScanInfo->pNextScanInfo->szFileToScan, pScanInfo->szFileToScan, FALSE);
		AddLogEntry(L"##### PKD-REP    : %s : %s", pScanInfo->pNextScanInfo->szFileToScan, pScanInfo->szFileToScan, true, LOG_DEBUG);
	}
	else if((pScanInfo->ThreatQuarantined) && (pScanInfo->IsPackedFile && pScanInfo->pNextScanInfo))
	{
		DeleteFile(pScanInfo->szFileToScan);
		AddLogEntry(L"##### PKD-Q      : %s : %s", pScanInfo->pNextScanInfo->szFileToScan, pScanInfo->szFileToScan, true, LOG_DEBUG);
	}

	return bReturn;
}

bool CMaxScanner::_ReplaceLockedFile(PMAX_SCANNER_INFO pScanInfo)
{
	if(pScanInfo->ThreatQuarantined)
	{
		m_pThreatManager->AddInRestartDeleteList(RD_FILE_DELETE, 0, pScanInfo->szFileToScan);
		AddLogEntry(L"^^^^^ ADD-RST-Q4  : %s", pScanInfo->szFileToScan, 0, true, LOG_DEBUG);
	}
	else if(pScanInfo->ThreatRepaired && pScanInfo->pNextScanInfo)
	{
		m_pThreatManager->MakeRestartReplaceEntry(pScanInfo->pNextScanInfo->szFileToScan, pScanInfo->szFileToScan);
		AddLogEntry(L"^^^^^ ADD-RST-REP: %s : %s", pScanInfo->szFreshFile, pScanInfo->szFileToScan, true, LOG_DEBUG);
	}

	return true;
}

bool CMaxScanner::_ScanPackedFile(PMAX_SCANNER_INFO pScanInfo, int iRecursiveCnt)
{
	bool bReturnVal = false;
	__try
	{
		bReturnVal = _ScanFileContent(pScanInfo, iRecursiveCnt);
		
		if(!bReturnVal)	// Check if this is a packed file
		{
			if((pScanInfo->pMaxPEFile) && (!pScanInfo->IsWhiteFile))
			{
				PMAX_SCANNER_INFO pLastScanInfo = pScanInfo;
				while(pLastScanInfo->pNextScanInfo)
				{
					pLastScanInfo = pLastScanInfo->pNextScanInfo;
				}
				PMAX_SCANNER_INFO pScanInfoUnPacked = new MAX_SCANNER_INFO;
				memset(pScanInfoUnPacked, 0, sizeof(MAX_SCANNER_INFO));
				pLastScanInfo->FreeNextScanInfo = true;
				pLastScanInfo->pNextScanInfo = pScanInfoUnPacked;
				pScanInfoUnPacked->AutoQuarantine = pScanInfo->AutoQuarantine;
				_tcscpy_s(pScanInfoUnPacked->szContainerFileName, pScanInfo->szFileToScan);
				PESIGCRCLOCALDB oPEFileSigLocal = {0};
				if (pScanInfo->IsChildFile == false)
				{
					m_dwUpackRecursionCnt = 0x00;
					//_tcscpy_s(pScanInfoUnPacked->szFirstParent, pScanInfo->szFileToScan);
				}
				else
				{
					m_dwUpackRecursionCnt++;
					//_tcscpy_s(pScanInfoUnPacked->szFirstParent, pScanInfo->szFirstParent);
				}

				if(_CreateMaxPEObject(pScanInfoUnPacked, oPEFileSigLocal, false, false))
				{
					if(_UnpackFile(pScanInfo, pScanInfoUnPacked))
					{
						pLastScanInfo->IsPackedFile = true;
						pScanInfoUnPacked->IsChildFile = true;
						pScanInfoUnPacked->SkipPolyMorphicScan = pLastScanInfo->SkipPolyMorphicScan;
						pScanInfoUnPacked->SkipPatternScan = pLastScanInfo->SkipPatternScan;
						pScanInfoUnPacked->IsEMLFile = pScanInfo->IsEMLFile;
						bReturnVal = _ScanFileTimer(pScanInfoUnPacked);			// recursive call to handle zip inside the packed file
						if(bReturnVal)
						{
							pScanInfo->IsArchiveFile = (pScanInfoUnPacked->IsArchiveFile || pScanInfo->IsArchiveFile);
							pLastScanInfo->ThreatDetected = pScanInfoUnPacked->ThreatDetected;
							pLastScanInfo->ThreatSuspicious = pScanInfoUnPacked->ThreatSuspicious;
							pLastScanInfo->eMessageInfo = pScanInfoUnPacked->eMessageInfo;
							pLastScanInfo->eDetectedBY = pScanInfoUnPacked->eDetectedBY;
							pLastScanInfo->ulThreatID = pScanInfoUnPacked->ulThreatID;
							_tcscpy_s(pLastScanInfo->szThreatName, pScanInfoUnPacked->szThreatName);
							_tcscpy_s(pLastScanInfo->szOLEMacroName, pScanInfoUnPacked->szOLEMacroName);

							PESIGCRCLOCALDB oPEFileSigLocal = {0};
							VIRUSLOCALDB oVirusDBLocal = {0};
							// Resetting local db status to zero so that the file will be rescanned!
							m_oLocalSignature.SetFileSignature(pScanInfo->szFileToScan, oPEFileSigLocal, oVirusDBLocal);
						}
					}
				}
			}
			if(!bReturnVal && m_bADSScan)
			{
				bReturnVal = ScanAlternateDataStream(pScanInfo);
			}
		}
		_CloseMaxPEFile(pScanInfo, !bReturnVal);	// will close all open handles
	}
	__except(CMaxExceptionFilter::Filter(GetExceptionCode(), GetExceptionInformation(), _T("Exception caught Scanner::_ScanPackedFile"), (pScanInfo->IsChildFile ? pScanInfo->szContainerFileName : pScanInfo->szFileToScan)))
	{
	}
	return bReturnVal;
}

bool CMaxScanner::_CreateMaxPEObject(PMAX_SCANNER_INFO pScanInfo, PESIGCRCLOCALDB &oPEFileSigLocal, bool bOpenFile, bool bOpenToRepair)
{
	DWORD	dwStartTime = GetTickCount();
	if(!pScanInfo->pMaxPEFile)
	{
		pScanInfo->pMaxPEFile = new CMaxPEFile();
		pScanInfo->pMaxPEFile->m_bPEFile = false;
		if(bOpenFile)
		{
			AddLogEntry(L">>>>> PECREATE: %s", pScanInfo->szFileToScan, 0, true, LOG_DEBUG);
			if(!pScanInfo->pMaxPEFile->OpenFile(pScanInfo->szFileToScan, bOpenToRepair))
			{
				pScanInfo->IsLockedFile = 1;
				return false;
			}
		}
		else
		{
			return true;
		}
	}
	pScanInfo->pMaxPEFile->m_bPacked = pScanInfo->IsPackedFile;
	pScanInfo->pMaxPEFile->m_byVirusRevIDs = oPEFileSigLocal.btVirusPolyScanStatus;

	/*
	TCHAR	szLogLine[1024] = {0x00};
	_stprintf(szLogLine,L"%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X",oPEFileSigLocal.btVirusPolyScanStatus[0x00],oPEFileSigLocal.btVirusPolyScanStatus[0x01],
	oPEFileSigLocal.btVirusPolyScanStatus[0x02],oPEFileSigLocal.btVirusPolyScanStatus[0x03],oPEFileSigLocal.btVirusPolyScanStatus[0x04],oPEFileSigLocal.btVirusPolyScanStatus[0x05],oPEFileSigLocal.btVirusPolyScanStatus[0x06],oPEFileSigLocal.btVirusPolyScanStatus[0x07],oPEFileSigLocal.btVirusPolyScanStatus[0x08],
	oPEFileSigLocal.btVirusPolyScanStatus[0x09],oPEFileSigLocal.btVirusPolyScanStatus[0x0A],oPEFileSigLocal.btVirusPolyScanStatus[0x0B],oPEFileSigLocal.btVirusPolyScanStatus[0x0C],oPEFileSigLocal.btVirusPolyScanStatus[0x0D],oPEFileSigLocal.btVirusPolyScanStatus[0x0E],oPEFileSigLocal.btVirusPolyScanStatus[0x0F]);
	
	
	_tcscpy_s(szLogLine,1024,L"");
	_stprintf(szLogLine,L"%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X",pScanInfo->pMaxPEFile->m_byVirusRevIDs[0x00],pScanInfo->pMaxPEFile->m_byVirusRevIDs[0x01],
	pScanInfo->pMaxPEFile->m_byVirusRevIDs[0x02],pScanInfo->pMaxPEFile->m_byVirusRevIDs[0x03],pScanInfo->pMaxPEFile->m_byVirusRevIDs[0x04],pScanInfo->pMaxPEFile->m_byVirusRevIDs[0x05],pScanInfo->pMaxPEFile->m_byVirusRevIDs[0x06],pScanInfo->pMaxPEFile->m_byVirusRevIDs[0x07],pScanInfo->pMaxPEFile->m_byVirusRevIDs[0x08],
	pScanInfo->pMaxPEFile->m_byVirusRevIDs[0x09],pScanInfo->pMaxPEFile->m_byVirusRevIDs[0x0A],pScanInfo->pMaxPEFile->m_byVirusRevIDs[0x0B],pScanInfo->pMaxPEFile->m_byVirusRevIDs[0x0C],pScanInfo->pMaxPEFile->m_byVirusRevIDs[0x0D],pScanInfo->pMaxPEFile->m_byVirusRevIDs[0x0E],pScanInfo->pMaxPEFile->m_byVirusRevIDs[0x0F]);
	*/
	m_dwMaxPEFileCreationTime += (GetTickCount() - dwStartTime);

	return true;
}

//Tushar ==> Removed FullFile Sig part from _CreatePESignature, to improve speed
bool CMaxScanner::_CreateFullFileSignature(PMAX_SCANNER_INFO pScanInfo, LPPESIGCRCLOCALDB pPEFileSigLocal)
{
	DWORD	dwStartTime = GetTickCount();
	CFileSig objFileSigForMD5;

	if (objFileSigForMD5.CreateMD5Sig(pScanInfo->szFileToScan, pPEFileSigLocal->ulFullFileSignature))
	{
		m_dwPECreationTime += (GetTickCount() - dwStartTime);
		return true;
	}
	m_dwPECreationTime += (GetTickCount() - dwStartTime);
	return false;
}


bool CMaxScanner::_CreatePESignature(PMAX_SCANNER_INFO pScanInfo, LPPESIGCRCLOCALDB pPEFileSigLocal)
{
	CFileSig objFileSig;
	//CFileSig objFileSigForMD5;

	//objFileSigForMD5.CreateMD5Sig(pScanInfo->szFileToScan, pPEFileSigLocal->ulFullFileSignature);
	
	if(pPEFileSigLocal->iFileSigCreated == true || SIG_STATUS_PE_SUCCESS == objFileSig.CreateSignature(pScanInfo->pMaxPEFile, pPEFileSigLocal->ulSignature))
	{
		return true;
	}
	return false;
}

bool CMaxScanner::_SendFileToYaraScanner(PMAX_SCANNER_INFO	pScanInfo)
{
	bool	bThreatFound = false;

	DWORD	dwStartTime = GetTickCount();
	__try
	{
		if (pScanInfo->pMaxPEFile->m_dwFileSize <= ((1024 * 1024) * 35))
		{
			char	szFile2Scan[MAX_PATH]={0};
			char	szVirusName[MAX_PATH] ={0};
			TCHAR	szDummyVirusName[MAX_PATH] = {0x00};
		
			if (pScanInfo->pMaxPEFile || pScanInfo->eVirusFileType == VIRUS_FILE_TYPE_ELF || pScanInfo->eVirusFileType == VIRUS_FILE_TYPE_SCRIPT || pScanInfo->eVirusFileType == VIRUS_FILE_TYPE_OLE)
			{
				if (pScanInfo->pMaxPEFile && pScanInfo->eVirusFileType != VIRUS_FILE_TYPE_ELF && pScanInfo->eVirusFileType != VIRUS_FILE_TYPE_SCRIPT && pScanInfo->eVirusFileType != VIRUS_FILE_TYPE_OLE)
				{
					if (!pScanInfo->pMaxPEFile->m_bPEFile && pScanInfo->eVirusFileType != VIRUS_FILE_TYPE_PE)
					{
						return bThreatFound;
					}
				}
			}

			if (m_hYARASigDB != NULL)
			{
				WaitForSingleObject(m_hYARASigDB,INFINITE);
				m_hYARASigDB = NULL;
			}
			
			GetAnsiString(pScanInfo->szFileToScan,szFile2Scan);
			m_iNoofYrSigSearched++;
			m_lpfnScanFileYrScan(szFile2Scan,szVirusName);

			if(strlen(szVirusName) > 0x00)
			{
				GetUnicodeString(szVirusName,szDummyVirusName);
				_stprintf(pScanInfo->szThreatName,L"%s_YR",szDummyVirusName);
				bThreatFound = true;
			}
		}
		else
		{
			m_iTotalNoOfFilesSkipped++;
			AddLogEntry(L">>>>> MYR-SKIP-BIG: %s", pScanInfo->szFileToScan, 0, true, LOG_DEBUG);
		}
	}
	__except(CMaxExceptionFilter::Filter(GetExceptionCode(), GetExceptionInformation(), _T("##### MYR-EXP    : "), (pScanInfo->szFileToScan)))
	{
		//AddMLearningLogEntry(L"##### MML-EXP    : %s", pszFile2Scan, NULL);
		bThreatFound =  false;
	}
	m_dwYaraScanTime += (GetTickCount() - dwStartTime);
	return bThreatFound;
}

bool CMaxScanner::_SendFileToMLearningScanner(PMAX_SCANNER_INFO	pScanInfo)
{
	bool	bThreatFound = false;

	DWORD	dwStartTime = GetTickCount();
	__try
	{
		if (pScanInfo->pMaxPEFile->m_dwFileSize <= ((1024 * 1024) * 35))
		{
			m_iNoofMLearnSigSearched++;
			if (m_hMLThread != NULL)
			//if (m_MLDBLoadThread->m_hThread != NULL)
			{
				if (m_dwActmonScan == 0x00)
				{
					WaitForSingleObject(m_hMLThread,INFINITE);
					//OutputDebugString(L"MML EXP TEST 2");
					m_hMLThread = NULL;
				}
				else
				{
					DWORD dwTimer = WaitForSingleObject(m_hMLThread,300);
					if (dwTimer != WAIT_OBJECT_0)
					{
						return false; 
					}
					m_hMLThread = NULL;
				}
			}
			//OutputDebugString(L"MML EXP TEST 8");
			//if(!m_pMaxMacLearning->ScanFile(pScanInfo->szFileToScan))
			if(!m_pMaxMacLearning->ScanFileEX(pScanInfo->pMaxPEFile))
			{
				bThreatFound = true;
			}
		}
		else
		{
			m_iTotalNoOfFilesSkipped++;
			AddLogEntry(L">>>>> MML-SKIP-BIG: %s", pScanInfo->szFileToScan, 0, true, LOG_DEBUG);
		}
	}
	__except(CMaxExceptionFilter::Filter(GetExceptionCode(), GetExceptionInformation(), _T("##### MML-EXP    : "), (pScanInfo->szFileToScan)))
	{
		//AddMLearningLogEntry(L"##### MML-EXP    : %s", pszFile2Scan, NULL);
		bThreatFound =  false;
	}
	m_dwMLScanTime += (GetTickCount() - dwStartTime);
	return bThreatFound;
}


/*
bool CMaxScanner::_SendFileToMLearningScanner(LPCTSTR	pszFile2Scan)
{
	bool	bThreatFound = false;

	__try
	{
		if (pScanInfo->pMaxPEFile->m_dwFileSize <= ((1024 * 1024) * 35))
		{
			m_iNoofMLearnSigSearched++;
			if(!m_pMaxMacLearning->ScanFile(pszFile2Scan))
			{
				bThreatFound = true;
			}
		}
		else
		{
			m_iTotalNoOfFilesSkipped++;
			AddLogEntry(L">>>>> MML-SKIP-BIG: %s", pScanInfo->szFileToScan, 0, true, LOG_DEBUG);
		}
	}
	__except(CMaxExceptionFilter::Filter(GetExceptionCode(), GetExceptionInformation(), _T("##### MML-EXP    : "), (pszFile2Scan)))
	{
		//AddMLearningLogEntry(L"##### MML-EXP    : %s", pszFile2Scan, NULL);
		bThreatFound =  false;
	}
	return bThreatFound;
}
*/
bool CMaxScanner::IsValidFile2Scan(LPCTSTR pszFile2Check)
{
	bool		bRetValue = false;

	bool		bPEFile = false;

	if (pszFile2Check == NULL)
	{
		return	bRetValue;
	}

	//TCHAR	*pTemp = NULL;

	//pTemp = (TCHAR *)_tcsrchr(pszFile2Check,L'.');
	//if (pTemp)
	//{
	//	if (_tcslen(pTemp) > 4)
	//	{
	//		return bRetValue;
	//	}
	//	TCHAR	szExt[0x10] = {0x00};
	//	_tcscpy(szExt,pTemp);
	//	_tcslwr(szExt);

	//	if (_tcsstr(szExt,L".dll") != NULL || _tcsstr(szExt,L".exe") != NULL || _tcsstr(szExt,L".sys") != NULL)   //.config
	//	{
	//		bPEFile = true;
	//	}
	//}
	bPEFile = true;
	if (bPEFile == true)
	{
		//CFileVersionInfo	objVerInfo;
		bool				bFound = false;

		if(m_lpfnScanFileDigiSig != NULL)
		{
			bFound = m_lpfnScanFileDigiSig(pszFile2Check);
			/*if (bFound == true) For Backup
			{
				BackupMLDetectFiles((TCHAR *)pszFile2Check, true);
				bRetValue = true;
			}*/
		}
		
	}
	return	bRetValue;
}
bool CMaxScanner::ScanFileCompanyDigitalSign(PMAX_SCANNER_INFO pScanInfo)
{
	__try
	{
		DWORD	dwStartTickCnt = GetTickCount();
		bool bRetValue = false;
		bRetValue = IsValidFile2Scan(pScanInfo->szFileToScan);	

		if (bRetValue == false)
		{
			DWORD	dwRetValue = m_oMaxVirusScanner.IsWhiteDigiCertORCompany(pScanInfo);
			if (dwRetValue == 0x01)
			{
				bRetValue = true;
			}
		}

		m_dwCompSafeScanTime += (GetTickCount() - dwStartTickCnt);
		return	bRetValue;
	}
	__except(CMaxExceptionFilter::Filter(GetExceptionCode(), GetExceptionInformation(), _T("Exception caught Scanner::ScanFileCompanyDigitalSign")))
	{
	}
	return	false;	
}
bool CMaxScanner::_ScanFileContent(PMAX_SCANNER_INFO pScanInfo, int iRecursiveCnt)
{
	__try
	{
		if((iRecursiveCnt > 1) && (g_dwLoggingLevel == LOG_DEBUG))
		{
			TCHAR szTemp[MAX_PATH * 2] = {0};
			wsprintf(szTemp, L">>>>> SCN %7d: %s", iRecursiveCnt, pScanInfo->szFileToScan);
			AddLogEntry(szTemp, 0, 0, true, LOG_DEBUG);
		}
		m_iTotalNoOfFiles++;

		bool	bUpdateLocalDB = false;
		bool	bFoundInLocalDB = false;
		bool	bSmallVerMisMatched = false;
		bool	bFoundDigiCat = false;
		DWORD	dwStartTickCnt = 0x00;

		PESIGCRCLOCALDB oPEFileSigLocal = {0};
		VIRUSLOCALDB oVirusDBLocal = {0};
		bFoundInLocalDB = m_oLocalSignature.GetFileSignature(pScanInfo->szFileToScan, oPEFileSigLocal, oVirusDBLocal);

		if(oPEFileSigLocal.iFileSigCreated == false)
		{
			if(!_CreateMaxPEObject(pScanInfo, oPEFileSigLocal, true, false))
			{
				AddLogEntry(L">>>>> PEFAILED: %s", pScanInfo->szFileToScan, 0, true, LOG_DEBUG);
			}
		}

		//CString		csLogLine;	
		//TCHAR		szLogLine[1024] = {0x00};
		
		DWORD dwPEScanStartTime = GetTickCount();
		if(_CreatePESignature(pScanInfo, &oPEFileSigLocal))
		{	
			if (bFoundInLocalDB)
			{
				if((oPEFileSigLocal.dwSD43Version < m_dwSD43CurVersion) || (oPEFileSigLocal.dwSD47Version < m_dwSD47CurVersion) || (oPEFileSigLocal.dwPatternVersion < m_dwPatCurVersion)
					|| (oPEFileSigLocal.dwMLVersion < m_dwMLVersion)  || (oPEFileSigLocal.dwYrVersion < m_dwYrVersion))
				{
					bSmallVerMisMatched = true;
				}
				

				if(!bSmallVerMisMatched && (oPEFileSigLocal.iFileSigCreated == true) && (oVirusDBLocal.iVirusFoundStatus == false) && (oVirusDBLocal.iMaxVirusScanDone == true)
					&& memcmp(m_btPolyVirusRevIDS, oPEFileSigLocal.btVirusPolyScanStatus, sizeof(m_btPolyVirusRevIDS)) == 0)
				{
					m_iTotalNoOfFilesSkipped++;
					AddLogEntry(L"##### SKIP-LOCAL : %s", pScanInfo->szFileToScan, 0, true, LOG_DEBUG);
					return false;
				}
			}

			m_dwPECreationTime += (GetTickCount() - dwPEScanStartTime);
			DWORD dwWPESearchStartTime = GetTickCount();

			swprintf_s(pScanInfo->szFileSig, _countof(pScanInfo->szFileSig), L"%016I64x", oPEFileSigLocal.ulSignature);
			bUpdateLocalDB = (!oPEFileSigLocal.iFileSigCreated ? true : false);
			oPEFileSigLocal.iFileSigCreated = true;
			m_iNoofWhiteFileSigSearched++;
			ULONG64 ulSignature = oPEFileSigLocal.ulSignature; //SearchItem reverses the value of ulSignature!
			WaitForSingleObject(m_hEvent, INFINITE);
			
			if(m_objWhiteDB.SearchSig(&ulSignature, &pScanInfo->ulThreatID))
			{
				SetEvent(m_hEvent);
				bUpdateLocalDB = (!oPEFileSigLocal.iIsWhiteFile ? true : false);
				oPEFileSigLocal.iIsWhiteFile = true;
				pScanInfo->IsWhiteFile = true;
				m_iNoofWhiteFileSigMatched++;
				if(bUpdateLocalDB)
				{
					m_oLocalSignature.SetFileSignature(pScanInfo->szFileToScan, oPEFileSigLocal, oVirusDBLocal);
				}
				AddLogEntry(L"##### WFS-WHT    : %s : %s", pScanInfo->szFileToScan, pScanInfo->szFileSig, true, LOG_DEBUG);
				m_dwWPESearchingTime += (GetTickCount() - dwWPESearchStartTime);
				return false;
			}
			
			SetEvent(m_hEvent);
			AddLogEntry(L">>>>> WFS-CLN    : %s : %s", pScanInfo->szFileToScan, pScanInfo->szFileSig, true, LOG_DEBUG);
			m_dwWPESearchingTime += (GetTickCount() - dwWPESearchStartTime);
		}

		if(m_bMachineLearning == false || m_bMachineLearningQ == true)
		{

			if (pScanInfo->eVirusFileType == VIRUS_FILE_TYPE_EICAR)
			{
				pScanInfo->eMessageInfo = File;
				//pScanInfo->eDetectedBY = Detected_BY_MaxAVModule;
				pScanInfo->eDetectedBY = Detected_BY_Max_Pattern;
				pScanInfo->ThreatDetected = 1;
				pScanInfo->ulThreatID = 6618;	//using adware.agent
				_tcscpy_s(pScanInfo->szThreatName,MAX_PATH,L"VIRUS.EICAR.TEST");
				oVirusDBLocal.iVirusFoundStatus = true;			// will ask for a rescan everytime we scan this file even with local db
				m_oLocalSignature.SetFileSignature(pScanInfo->szFileToScan, oPEFileSigLocal, oVirusDBLocal);

				//m_oLocalSignature.SetFileSignature(pScanInfo->szFileToScan, oPEFileSigLocal, oVirusDBLocal);
				AddLogEntry(pScanInfo->eMessageInfo, pScanInfo->szFileToScan, pScanInfo->szFileSig, pScanInfo->eDetectedBY, pScanInfo->ulThreatID, pScanInfo->szThreatName);
				AddLogEntry(L"##### EICAR-DET   : %s : %s", pScanInfo->szFileToScan, pScanInfo->szFileSig, true, LOG_DEBUG);

				return true;
			}

			if(m_lpfnCheckBlackFile != NULL && !bFoundDigiCat)
			{
				dwStartTickCnt = GetTickCount();
				if(m_lpfnCheckBlackFile(pScanInfo->szFileToScan) == 1)
				{
					if(ScanFileCompanyDigitalSign(pScanInfo))
					{
						bFoundDigiCat = true;
					}
					else
					{
						pScanInfo->eMessageInfo = File;
						pScanInfo->eDetectedBY = Detected_BY_Max_Pattern;
						pScanInfo->ThreatDetected = 1;
						pScanInfo->ulThreatID = 7604;	//using adware.agent
						oVirusDBLocal.iVirusFoundStatus = true;			// will ask for a rescan everytime we scan this file even with local db
						m_oLocalSignature.SetFileSignature(pScanInfo->szFileToScan, oPEFileSigLocal, oVirusDBLocal);
						AddLogEntry(pScanInfo->eMessageInfo, pScanInfo->szFileToScan, pScanInfo->szFileSig, pScanInfo->eDetectedBY, pScanInfo->ulThreatID, pScanInfo->szThreatName);
						AddLogEntry(L"##### RANSOM-DET   : %s : %s", pScanInfo->szFileToScan, pScanInfo->szFileSig, true, LOG_DEBUG);

						m_dwRansScanTime += (GetTickCount() - dwStartTickCnt);

						return true;
					}
				}
				else
				{
					AddLogEntry(L">>>>> RANSOM-CLN   : %s", pScanInfo->szFileToScan, 0, true, LOG_DEBUG);
				}
				m_dwRansScanTime += (GetTickCount() - dwStartTickCnt);
			}

			if(m_lpfnCheckFileInAppData != NULL && !bFoundDigiCat)
			{
				dwStartTickCnt = GetTickCount();
				if(m_lpfnCheckFileInAppData(pScanInfo->szFileToScan) == 1)
				{
					if(ScanFileCompanyDigitalSign(pScanInfo))
					{
						bFoundDigiCat = true;
					}
					else
					{
						pScanInfo->eMessageInfo = File;
						pScanInfo->eDetectedBY = Detected_BY_Max_Pattern;
						pScanInfo->ThreatDetected = 1;
						pScanInfo->ulThreatID = 7604;	//using adware.agent
						oVirusDBLocal.iVirusFoundStatus = true;			// will ask for a rescan everytime we scan this file even with local db
						m_oLocalSignature.SetFileSignature(pScanInfo->szFileToScan, oPEFileSigLocal, oVirusDBLocal);
						AddLogEntry(pScanInfo->eMessageInfo, pScanInfo->szFileToScan, pScanInfo->szFileSig, pScanInfo->eDetectedBY, pScanInfo->ulThreatID, pScanInfo->szThreatName);
						AddLogEntry(L"##### APPDATA-DET   : %s : %s", pScanInfo->szFileToScan, pScanInfo->szFileSig, true, LOG_DEBUG);
						m_dwAppDataScanTime += (GetTickCount() - dwStartTickCnt);
						return true;
					}
				}
				else
				{
					AddLogEntry(L">>>>> APPDATA-CLN   : %s", pScanInfo->szFileToScan, 0, true, LOG_DEBUG);
				}
				m_dwAppDataScanTime += (GetTickCount() - dwStartTickCnt);
			}

			if(!pScanInfo->SkipPatternScan && !bFoundDigiCat)
			{
				dwStartTickCnt = GetTickCount();
				BYTE byVerTabInfo = oPEFileSigLocal.iVerTabInfo;
				if(m_oPatternFileScanner.ScanFile(pScanInfo->szFileToScan, oPEFileSigLocal.iFileSigCreated, oPEFileSigLocal.ulSignature, byVerTabInfo,oPEFileSigLocal.dwPatternVersion))
				{
					if(ScanFileCompanyDigitalSign(pScanInfo))
					{
						bFoundDigiCat = true;
					}
					else
					{
						oPEFileSigLocal.iVerTabInfo = byVerTabInfo;
						pScanInfo->eMessageInfo = File;
						pScanInfo->eDetectedBY = Detected_BY_Max_Pattern;
						pScanInfo->ThreatDetected = 1;
						pScanInfo->ulThreatID = 7604;	//using trojan.agent
						oVirusDBLocal.iVirusFoundStatus = true;			// will ask for a rescan everytime we scan this file even with local db
						m_oLocalSignature.SetFileSignature(pScanInfo->szFileToScan, oPEFileSigLocal, oVirusDBLocal);
						AddLogEntry(pScanInfo->eMessageInfo, pScanInfo->szFileToScan, pScanInfo->szFileSig, pScanInfo->eDetectedBY, pScanInfo->ulThreatID, pScanInfo->szThreatName);
						AddLogEntry(L"##### PAT-DET     : %s : %s", pScanInfo->szFileToScan, pScanInfo->szFileSig, true, LOG_DEBUG);
						m_dwPatScanTime += (GetTickCount() - dwStartTickCnt);
						return true;
					}

				}
				else
				{
					oPEFileSigLocal.iVerTabInfo = byVerTabInfo;
					AddLogEntry(L">>>>> PAT-CLN    : %s", pScanInfo->szFileToScan, 0, true, LOG_DEBUG);

				}
				m_dwPatScanTime += (GetTickCount() - dwStartTickCnt);
			}
			else
			{
				AddLogEntry(L"##### PAT-SKIP   : %s", pScanInfo->szFileToScan, 0, true, LOG_DEBUG);
			}

			dwStartTickCnt = GetTickCount();
			if(m_oInstantScanner.ScanFile(pScanInfo->szFileToScan, oPEFileSigLocal.iFileSigCreated, oPEFileSigLocal.ulSignature))
			{
				pScanInfo->eMessageInfo = File;
				pScanInfo->eDetectedBY = Detected_BY_Max_Instant;
				pScanInfo->ThreatDetected = 1;
				pScanInfo->ulThreatID = 7604;	//using adware.agent
				oVirusDBLocal.iVirusFoundStatus = true;			// will ask for a rescan everytime we scan this file even with local db
				m_oLocalSignature.SetFileSignature(pScanInfo->szFileToScan, oPEFileSigLocal, oVirusDBLocal);
				AddLogEntry(pScanInfo->eMessageInfo, pScanInfo->szFileToScan, pScanInfo->szFileSig, pScanInfo->eDetectedBY, pScanInfo->ulThreatID, pScanInfo->szThreatName);
				AddLogEntry(L"##### INST-DET   : %s : %s", pScanInfo->szFileToScan, pScanInfo->szFileSig, true, LOG_DEBUG);
				m_dwInstScanTime += (GetTickCount() - dwStartTickCnt);
				return true;
			}
			else
			{
				AddLogEntry(L">>>>> INST-CLN   : %s", pScanInfo->szFileToScan, 0, true, LOG_DEBUG);
			}
			m_dwInstScanTime += (GetTickCount() - dwStartTickCnt);

			if(!bFoundDigiCat)
			{
				if((oVirusDBLocal.iMaxVirusScanDone == false) || (oVirusDBLocal.iVirusFoundStatus == true) || (memcmp(m_btPolyVirusRevIDS, oPEFileSigLocal.btVirusPolyScanStatus, sizeof(m_btPolyVirusRevIDS)) != 0x00))
				{
					m_iNoofMaxVirusSearched++;
					bUpdateLocalDB = true;
					_CreateMaxPEObject(pScanInfo, oPEFileSigLocal, true, false);	// create the pe object if not created already!

					if ((oPEFileSigLocal.dwYrVersion >= m_dwYrVersion) || m_dwMaxYrScan == 0x00)
					{
						m_oMaxVirusScanner.m_bSKipYaraScanner = true;
						/*
						if (m_dwMaxYrScan == 0x00)
						{
							AddLogEntry(L"##### MYR-SKIP   : %s : %s", pScanInfo->szFileToScan, pScanInfo->szFileSig, true, LOG_DEBUG);
						}
						else
						{
							AddLogEntry(L"##### MYR-SKIP LOCAL   : %s : %s", pScanInfo->szFileToScan, pScanInfo->szFileSig, true, LOG_DEBUG);
						}
						*/
					}
					else
					{
						m_oMaxVirusScanner.m_bSKipYaraScanner = false;
					}

					pScanInfo->ulProcessIDToScan = m_oMaxVirusScanner.ScanFile(pScanInfo);
					if((pScanInfo->ThreatDetected == 1) || (pScanInfo->ThreatSuspicious == 1))
					{
						if (pScanInfo->eMessageInfo != SCAN_ACTION_REPAIR)
						{
							if(ScanFileCompanyDigitalSign(pScanInfo))
							{
								pScanInfo->ThreatDetected = false;
								pScanInfo->ThreatSuspicious = false;
								pScanInfo->eMessageInfo = File;
								pScanInfo->eDetectedBY = Detected_BY_NONE;
								bFoundDigiCat = true;
							}
						}
						if (bFoundDigiCat == false)
						{
							m_iNoofMaxVirusMatched++;
							oVirusDBLocal.iVirusFoundStatus = true;			// will ask for a rescan everytime we scan this file even with local db
							m_oLocalSignature.SetFileSignature(pScanInfo->szFileToScan, oPEFileSigLocal, oVirusDBLocal);
							AddLogEntry(pScanInfo->eMessageInfo, pScanInfo->szFileToScan, pScanInfo->szFileSig, pScanInfo->eDetectedBY, pScanInfo->ulThreatID, pScanInfo->szThreatName);
							AddLogEntry(L"##### MVS-DET    : %s", pScanInfo->szFileToScan, 0, true, LOG_DEBUG);
							return true;
						}
						/*
						if(ScanFileCompanyDigitalSign(pScanInfo))
						{
							pScanInfo->ThreatDetected = false;
							pScanInfo->ThreatSuspicious = false;
							pScanInfo->eMessageInfo = File;
							pScanInfo->eDetectedBY = Detected_BY_NONE;
							bFoundDigiCat = true;
						}
						else
						{
							m_iNoofMaxVirusMatched++;
							oVirusDBLocal.iVirusFoundStatus = true;			// will ask for a rescan everytime we scan this file even with local db
							m_oLocalSignature.SetFileSignature(pScanInfo->szFileToScan, oPEFileSigLocal, oVirusDBLocal);
							AddLogEntry(pScanInfo->eMessageInfo, pScanInfo->szFileToScan, pScanInfo->szFileSig, pScanInfo->eDetectedBY, pScanInfo->ulThreatID, pScanInfo->szThreatName);
							AddLogEntry(L"##### MVS-DET    : %s", pScanInfo->szFileToScan, 0, true, LOG_DEBUG);
							return true;
						}
						*/
					}

					oVirusDBLocal.iMaxVirusScanDone = true;

					/*_stprintf(szLogLine,L"%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X",oPEFileSigLocal.btVirusPolyScanStatus[0x00],oPEFileSigLocal.btVirusPolyScanStatus[0x01],
					oPEFileSigLocal.btVirusPolyScanStatus[0x02],oPEFileSigLocal.btVirusPolyScanStatus[0x03],oPEFileSigLocal.btVirusPolyScanStatus[0x04],oPEFileSigLocal.btVirusPolyScanStatus[0x05],oPEFileSigLocal.btVirusPolyScanStatus[0x06],oPEFileSigLocal.btVirusPolyScanStatus[0x07],oPEFileSigLocal.btVirusPolyScanStatus[0x08],
					oPEFileSigLocal.btVirusPolyScanStatus[0x09],oPEFileSigLocal.btVirusPolyScanStatus[0x0A],oPEFileSigLocal.btVirusPolyScanStatus[0x0B],oPEFileSigLocal.btVirusPolyScanStatus[0x0C],oPEFileSigLocal.btVirusPolyScanStatus[0x0D],oPEFileSigLocal.btVirusPolyScanStatus[0x0E],oPEFileSigLocal.btVirusPolyScanStatus[0x0F]);*/
					AddLogEntry(L">>>>> MVS-CLN    : %s", pScanInfo->szFileToScan, 0, true, LOG_DEBUG);
				}
				else
				{
					AddLogEntry(L">>>>> LOC-MVS-CLN: %s", pScanInfo->szFileToScan, 0, true, LOG_DEBUG);
				}
			}
			if(!bFoundDigiCat)
			{
				if(oPEFileSigLocal.iFileSigCreated == true && (oPEFileSigLocal.dwSD43Version < m_dwSD43CurVersion))
				{
					DWORD dwBPESearchStartTime = GetTickCount();
					m_iNoofBlackFileSigSearched++;
					ULONG64 ulSignature = oPEFileSigLocal.ulSignature; //SearchItem reverses the value of ulSignature!
					WaitForSingleObject(m_hEvent, INFINITE);
					if(m_obBlackDBManager.SearchSig(&ulSignature, &pScanInfo->ulThreatID,oPEFileSigLocal.dwSD43Version))
					{
						if(ScanFileCompanyDigitalSign(pScanInfo))
						{
							bFoundDigiCat = true;
						}
						else
						{
							SetEvent(m_hEvent);
							pScanInfo->eMessageInfo = ExecPath;
							pScanInfo->eDetectedBY = Detected_BY_Max_FileSig;
							pScanInfo->ThreatDetected = 1;
							m_iNoofBlackFileSigMatched++;
							oVirusDBLocal.iVirusFoundStatus = true;			// will ask for a rescan everytime we scan this file even with local db
							m_oLocalSignature.SetFileSignature(pScanInfo->szFileToScan, oPEFileSigLocal, oVirusDBLocal);
							AddLogEntry(pScanInfo->eMessageInfo, pScanInfo->szFileToScan, pScanInfo->szFileSig, pScanInfo->eDetectedBY, pScanInfo->ulThreatID, pScanInfo->szThreatName);
							AddLogEntry(L"##### BFS-DET    : %s : %s", pScanInfo->szFileToScan, pScanInfo->szFileSig, true, LOG_DEBUG);
							m_dwBPESearchingTime += (GetTickCount() - dwBPESearchStartTime);
							return true;
						}
					}
					SetEvent(m_hEvent);
					AddLogEntry(L">>>>> BFS-CLN    : %s : %s", pScanInfo->szFileToScan, pScanInfo->szFileSig, true, LOG_DEBUG);

					//bUpdateLocalDB = true;
					m_dwBPESearchingTime += (GetTickCount() - dwBPESearchStartTime);
				}
				else
				{
					if (oPEFileSigLocal.dwSD43Version >= m_dwSD43CurVersion)
					{
						AddLogEntry(L"##### BFS-SKIP LOCAL   : %s : %s", pScanInfo->szFileToScan, pScanInfo->szFileSig, true, LOG_DEBUG);
					}
					else
					{
						pScanInfo->IsLockedFile = 1;
						AddLogEntry(L"##### SKIP-LOCKED: %s : %s", pScanInfo->szFileToScan, pScanInfo->szFileSig, true, LOG_DEBUG);
					}
				}
			}
			//Scan with SD42.db
			if((pScanInfo->eVirusFileType >=VIRUS_FILE_TYPE_MAC) && (pScanInfo->eVirusFileType <=VIRUS_FILE_TYPE_IOS_DEB) && !bFoundDigiCat)
			{
				if(oPEFileSigLocal.iFileSigCreated == true)
				{
					DWORD dwBPESearchStartTime = GetTickCount();
					m_iNoofMACFileSigSearched++;
					ULONG64 ulSignature = oPEFileSigLocal.ulSignature; //SearchItem reverses the value of ulSignature!
					WaitForSingleObject(m_hEvent, INFINITE);
					if(m_objBlackDB.SearchSig(&ulSignature, &pScanInfo->ulThreatID))
					{
						if(ScanFileCompanyDigitalSign(pScanInfo))
						{
							bFoundDigiCat = true;
						}
						else
						{
							SetEvent(m_hEvent);
							pScanInfo->eMessageInfo = ExecPath;
							pScanInfo->eDetectedBY = Detected_BY_Max_FileSig;
							pScanInfo->ThreatDetected = 1;
							m_iNoofMACFileSigMatched++;
							oVirusDBLocal.iVirusFoundStatus = true;			// will ask for a rescan everytime we scan this file even with local db
							m_oLocalSignature.SetFileSignature(pScanInfo->szFileToScan, oPEFileSigLocal, oVirusDBLocal);
							AddLogEntry(pScanInfo->eMessageInfo, pScanInfo->szFileToScan, pScanInfo->szFileSig, pScanInfo->eDetectedBY, pScanInfo->ulThreatID, pScanInfo->szThreatName);
							AddLogEntry(L"##### MFS-DET    : %s : %s", pScanInfo->szFileToScan, pScanInfo->szFileSig, true, LOG_DEBUG);
							m_dwBPESearchingTime += (GetTickCount() - dwBPESearchStartTime);
							return true;
						}
					}
					SetEvent(m_hEvent);
					AddLogEntry(L">>>>> MFS-CLN    : %s : %s", pScanInfo->szFileToScan, pScanInfo->szFileSig, true, LOG_DEBUG);
					m_dwBPESearchingTime += (GetTickCount() - dwBPESearchStartTime);
				}
			}

			//Scan with SD47.db
			if(!bFoundDigiCat)
			{
				if (oPEFileSigLocal.dwSD47Version < m_dwSD47CurVersion)
				{
					TCHAR	szFullFileSig[0x25] = {0x00};

					_CreateFullFileSignature(pScanInfo, &oPEFileSigLocal);

					swprintf_s(szFullFileSig, _countof(szFullFileSig), L"%016I64x", oPEFileSigLocal.ulFullFileSignature);
					//AddLogEntry(L">>>>> FULL FILE Sig   : %s", szFullFileSig);

					DWORD dwBPESearchStartTime = GetTickCount();
					m_iNoofFullFileSigSearched++;

					WaitForSingleObject(m_hEvent, INFINITE);
					if (m_hFullFileSigDB != NULL)
					{
						WaitForSingleObject(m_hFullFileSigDB,INFINITE);
						m_hFullFileSigDB = NULL;
					}
					if(m_objFullFileSigDB.SearchSig(&oPEFileSigLocal.ulFullFileSignature, &pScanInfo->ulThreatID,oPEFileSigLocal.dwSD47Version))
					{
						if(ScanFileCompanyDigitalSign(pScanInfo))
						{
							bFoundDigiCat = true;
						}
						else
						{
							SetEvent(m_hEvent);
							pScanInfo->eMessageInfo = ExecPath;
							pScanInfo->eDetectedBY = Detected_BY_Max_FullFileSig;
							pScanInfo->ThreatDetected = 1;
							m_iNoofFullFileSigMatched++;
							oVirusDBLocal.iVirusFoundStatus = true;			// will ask for a rescan everytime we scan this file even with local db
							//m_oLocalSignature.SetFileSignature(pScanInfo->szFileToScan, oPEFileSigLocal, oVirusDBLocal);
							AddLogEntry(pScanInfo->eMessageInfo, pScanInfo->szFileToScan, pScanInfo->szFileSig, pScanInfo->eDetectedBY, pScanInfo->ulThreatID, pScanInfo->szThreatName);
							AddLogEntry(L"##### FFS-DET    : %s : %s", pScanInfo->szFileToScan, szFullFileSig, true, LOG_DEBUG);
							m_dwBPESearchingTime += (GetTickCount() - dwBPESearchStartTime);
							return true;
						}
					}
					SetEvent(m_hEvent);
					AddLogEntry(L">>>>> FFS-CLN    : %s : %s", pScanInfo->szFileToScan, szFullFileSig, true, LOG_DEBUG);
					m_dwBPESearchingTime += (GetTickCount() - dwBPESearchStartTime);
				}
				else
				{
					AddLogEntry(L"##### FFS-SKIP LOCAL   : %s : %s", pScanInfo->szFileToScan, pScanInfo->szFileSig, true, LOG_DEBUG);
				}
			}

			//Yara Scanner
			if(!bFoundDigiCat)
			{
				if(m_lpfnScanFileYrScan != NULL && m_bYrScanLoaded && m_dwMaxYrScan == 1)
				{
					if (oPEFileSigLocal.dwYrVersion < m_dwYrVersion)
					{
						if(_SendFileToYaraScanner(pScanInfo))
						{
							if(ScanFileCompanyDigitalSign(pScanInfo))
							{
								bFoundDigiCat = true;
							}
							else
							{
								m_iNoofYrSigMatched++;
								pScanInfo->eMessageInfo = File;
								pScanInfo->eDetectedBY = Detected_BY_Max_Yara;//Detected_BY_MaxAVModule;
								pScanInfo->ulThreatID = 121218;
								pScanInfo->ThreatDetected = 1;
								
								oVirusDBLocal.iVirusFoundStatus = true;			// will ask for a rescan everytime we scan this file even with local db
								//m_oLocalSignature.SetFileSignature(pScanInfo->szFileToScan, oPEFileSigLocal, oVirusDBLocal);

								AddLogEntry(pScanInfo->eMessageInfo, pScanInfo->szFileToScan, pScanInfo->szFileSig, pScanInfo->eDetectedBY, pScanInfo->ulThreatID, pScanInfo->szThreatName);
								AddLogEntry(L"##### MYR-DET    : %s", pScanInfo->szFileToScan, 0, true, LOG_DEBUG);
								return true;
							}
						}
						else
						{
							AddLogEntry(L">>>>> MYR-CLN: %s", pScanInfo->szFileToScan, 0, true, LOG_DEBUG);
						}
						
						bSmallVerMisMatched = true;
						oPEFileSigLocal.dwYrVersion = m_dwYrVersion;
						//m_oLocalSignature.SetFileSignature(pScanInfo->szFileToScan, oPEFileSigLocal, oVirusDBLocal);
					}
					else
					{
						AddLogEntry(L"##### MYR-SKIP LOCAL   : %s : %s", pScanInfo->szFileToScan, pScanInfo->szFileSig, true, LOG_DEBUG);
					}
				}
				else
				{
					AddLogEntry(L"##### MYR-SKIP   : %s : %s", pScanInfo->szFileToScan, pScanInfo->szFileSig, true, LOG_DEBUG);
				}
			}
			

			//Machine Learning Scanner
			if(!bFoundDigiCat)
			{
				if(m_dwMaxMacLearning == 0)
				{
					AddLogEntry(L"##### MML-SKIP   : %s : %s", pScanInfo->szFileToScan, pScanInfo->szFileSig, true, LOG_DEBUG);
				}
				else if (oPEFileSigLocal.dwMLVersion < m_dwMLVersion && m_pMaxMacLearning)
				{
					if(_SendFileToMLearningScanner(pScanInfo))
					{
						if(ScanFileCompanyDigitalSign(pScanInfo))
						{
							bFoundDigiCat = true;
						}
						else
						{
							m_iNoofMLearnSigMatched++;
							pScanInfo->eMessageInfo = File;
							pScanInfo->eDetectedBY = Detected_BY_Max_ML;//Detected_BY_MaxAVModule;
							pScanInfo->ThreatDetected = 1;
							pScanInfo->ulThreatID = 300983;	//MacLearning
							oVirusDBLocal.iVirusFoundStatus = true;			// will ask for a rescan everytime we scan this file even with local db
							//m_oLocalSignature.SetFileSignature(pScanInfo->szFileToScan, oPEFileSigLocal, oVirusDBLocal);
							AddLogEntry(pScanInfo->eMessageInfo, pScanInfo->szFileToScan, pScanInfo->szFileSig, pScanInfo->eDetectedBY, pScanInfo->ulThreatID, pScanInfo->szThreatName);
							AddLogEntry(L"##### MML-DET    : %s", pScanInfo->szFileToScan, 0, true, LOG_DEBUG);
							AddMLearningLogEntry(L"##### MML-DET    : %s [%s]", pScanInfo->szFileToScan, pScanInfo->szFileSig);
							//BackupMLDetectFiles(pScanInfo->szFileToScan);
							return true;
						}
					}
					else
					{
						m_iTotalNoOfFilesSkipped++;
						AddLogEntry(L">>>>> MML-CLN: %s", pScanInfo->szFileToScan, 0, true, LOG_DEBUG);
					}
					
					bSmallVerMisMatched = true;
					oPEFileSigLocal.dwMLVersion = m_dwMLVersion;
					//m_oLocalSignature.SetFileSignature(pScanInfo->szFileToScan, oPEFileSigLocal, oVirusDBLocal);
				}
				else
				{
					m_iTotalNoOfFilesSkipped++;
					AddLogEntry(L"##### MML-SKIP LOCAL   : %s : %s", pScanInfo->szFileToScan, pScanInfo->szFileSig, true, LOG_DEBUG);
				}
			}

		}
		if(m_bMachineLearning == true && !bFoundDigiCat)
		{
			if (oPEFileSigLocal.dwMLVersion < m_dwMLVersion && m_pMaxMacLearning)
			{
				//if (pScanInfo->pMaxPEFile->m_dwFileSize <= ((1024 * 1024) * 35))
				//{
					//m_iNoofMLearnSigSearched++;
					//if(!m_pMaxMacLearning->ScanFile(pScanInfo->szFileToScan))
					if(_SendFileToMLearningScanner(pScanInfo))
					{
						if(ScanFileCompanyDigitalSign(pScanInfo))
						{
							bFoundDigiCat = true;
						}
						else
						{
							m_iNoofMLearnSigMatched++;
							pScanInfo->eMessageInfo = File;
							pScanInfo->eDetectedBY = Detected_BY_MaxAVModule;
							pScanInfo->ThreatDetected = 1;
							pScanInfo->ulThreatID = 300983;	//MaxMacLearning
							oVirusDBLocal.iVirusFoundStatus = true;			// will ask for a rescan everytime we scan this file even with local db
							//m_oLocalSignature.SetFileSignature(pScanInfo->szFileToScan, oPEFileSigLocal, oVirusDBLocal);
							AddLogEntry(pScanInfo->eMessageInfo, pScanInfo->szFileToScan, pScanInfo->szFileSig, pScanInfo->eDetectedBY, pScanInfo->ulThreatID, pScanInfo->szThreatName);
							AddLogEntry(L"##### MML-DET    : %s", pScanInfo->szFileToScan, 0, true, LOG_DEBUG);
							AddMLearningLogEntry(L"##### MML-DET    : %s [%s]", pScanInfo->szFileToScan, pScanInfo->szFileSig);
							//BackupMLDetectFiles(pScanInfo->szFileToScan);
							return true;
						}
					}
					else
					{
						m_iTotalNoOfFilesSkipped++;
						AddLogEntry(L">>>>> MML-CLN: %s", pScanInfo->szFileToScan, 0, true, LOG_DEBUG);
					}
				//}
				//else
				//{
				//	m_iTotalNoOfFilesSkipped++;
				//	AddLogEntry(L">>>>> MML-SKIP-BIG: %s", pScanInfo->szFileToScan, 0, true, LOG_DEBUG);			

				//}
				//if (m_lpfnScanFileHeur)
				//{
				//	m_iNoofHeurSigSearched++;
				//	if(m_lpfnScanFileHeur(pScanInfo->szFileToScan) == true)
				//	{
				//		m_iNoofHeurSigMatched++;
				//		pScanInfo->eMessageInfo = File;
				//		pScanInfo->eDetectedBY = Detected_BY_MaxAVModule;
				//		pScanInfo->ThreatDetected = 1;
				//		pScanInfo->ulThreatID = 90594;	//MacLearning
				//		oVirusDBLocal.iVirusFoundStatus = true;			// will ask for a rescan everytime we scan this file even with local db
				//		//m_oLocalSignature.SetFileSignature(pScanInfo->szFileToScan, oPEFileSigLocal, oVirusDBLocal);
				//		AddLogEntry(pScanInfo->eMessageInfo, pScanInfo->szFileToScan, pScanInfo->szFileSig, pScanInfo->eDetectedBY, pScanInfo->ulThreatID, pScanInfo->szThreatName);
				//		AddLogEntry(L"##### HEUR-DET    : %s", pScanInfo->szFileToScan, 0, true, LOG_DEBUG);
				//		AddMLearningLogEntry(L"##### HEUR-DET    : %s [%s]", pScanInfo->szFileToScan, pScanInfo->szFileSig);
				//		BackupMLDetectFiles(pScanInfo->szFileToScan);
				//		return true;
				//	}
				//	else
				//	{
				//		AddLogEntry(L">>>>> HEUR-CLN: %s", pScanInfo->szFileToScan, 0, true, LOG_DEBUG);
				//	}
				//}
				oPEFileSigLocal.dwMLVersion = m_dwMLVersion;
				m_oLocalSignature.SetFileSignature(pScanInfo->szFileToScan, oPEFileSigLocal, oVirusDBLocal);
			}
			else
			{
				m_iTotalNoOfFilesSkipped++;
				AddLogEntry(L"##### MML-SKIP LOCAL   : %s : %s", pScanInfo->szFileToScan, pScanInfo->szFileSig, true, LOG_DEBUG);
			}
		}
		if(bFoundDigiCat)
		{
			AddLogEntry(L"##### WFS-WHTC    : %s : %s", pScanInfo->szFileToScan, pScanInfo->szFileSig, true, LOG_DEBUG);
		}
		if(bSmallVerMisMatched)
		{
			oPEFileSigLocal.dwSD47Version = m_dwSD47CurVersion;
			oPEFileSigLocal.dwSD43Version = m_dwSD43CurVersion;
			oPEFileSigLocal.dwPatternVersion = m_dwPatCurVersion;
			bUpdateLocalDB = true;
		}

		if((bUpdateLocalDB) && (!pScanInfo->SkipPolyMorphicScan))
		{
			memcpy(oPEFileSigLocal.btVirusPolyScanStatus,m_btPolyVirusRevIDS,sizeof(m_btPolyVirusRevIDS));
			m_oLocalSignature.SetFileSignature(pScanInfo->szFileToScan, oPEFileSigLocal, oVirusDBLocal);
		}
		return false;
	}
	__except(CMaxExceptionFilter::Filter(GetExceptionCode(), GetExceptionInformation(), _T("Exception caught Scanner::_ScanFileContent"), (pScanInfo->IsChildFile ? pScanInfo->szContainerFileName : pScanInfo->szFileToScan)))
	{
	}
	return false;
}

DWORD CMaxScanner::_RepairFile(PMAX_SCANNER_INFO pScanInfo, int iRecursiveCnt)
{
	__try
	{
		DWORD dwRepairResult = REAPIR_STATUS_SUCCESS;
		if(g_dwLoggingLevel == LOG_DEBUG)
		{
			TCHAR szTemp[MAX_PATH * 2] = {0};
			wsprintf(szTemp, L">>>>> CLN/REP%4d: %s", iRecursiveCnt, pScanInfo->szFileToScan);
			AddLogEntry(szTemp, 0, 0, true, LOG_DEBUG);
		}
		if(_waccess(pScanInfo->szFileToScan, 0))
		{
			pScanInfo->ThreatQuarantined = true;
			AddLogEntry(L"##### MISSING    : %s", pScanInfo->szFileToScan, 0, true, LOG_DEBUG);
			return dwRepairResult;
		}

		if(pScanInfo->eMessageInfo == Virus_File_Repair)	// call for repair
		{
			DWORD dwStartTime = GetTickCount();
			TCHAR szOldMD5[MAX_PATH]={0};
			TCHAR szNewMD5[MAX_PATH]={0};
		
			GetSignature(pScanInfo->szFileToScan, szOldMD5);
			AddLogEntry(L">>>>> MD5-ORG    : %s : %s", pScanInfo->szFileToScan, szOldMD5, true, LOG_DEBUG);
			
			PESIGCRCLOCALDB oPEFileSigLocal = {0};
			if(!_CreateMaxPEObject(pScanInfo, oPEFileSigLocal, true, true))
			{
				AddLogEntry(L">>>>> PEFAILED: %s", pScanInfo->szFileToScan, 0, true, LOG_DEBUG);
			}

			WaitForSingleObject(m_hEvent, INFINITE);
			dwRepairResult = m_oMaxVirusScanner.RepairFile(pScanInfo);
			SetEvent(m_hEvent);

			_CloseMaxPEFile(pScanInfo, false);	// will close all open handles

			if(_waccess(pScanInfo->szFileToScan, 0))
			{
				pScanInfo->ThreatQuarantined = true;
				AddLogEntry(L"##### MISSING    : %s", pScanInfo->szFileToScan, 0, true, LOG_DEBUG);
				m_dwTotalRepairTime += (GetTickCount() - dwStartTime);
				return dwRepairResult;
			}

			_tcscpy_s(szNewMD5, MAX_PATH, szOldMD5);
			if(pScanInfo->ThreatRepaired == true)
			{
				GetSignature(pScanInfo->szFileToScan, szNewMD5);
				AddLogEntry(L">>>>> MD5-NEW    : %s : %s", pScanInfo->szFileToScan, szNewMD5, true, LOG_DEBUG);
			}
			if((_tcsicmp(szOldMD5, szNewMD5) == 0) || (dwRepairResult != REAPIR_STATUS_SUCCESS))
			{
				pScanInfo->ThreatNonCurable = true;
			}
			m_dwTotalRepairTime += (GetTickCount() - dwStartTime);
		}
		else												// call for quarantine
		{
			_CloseMaxPEFile(pScanInfo, false);	// will close all open handles
			DWORD dwPEQuarantineStartTime = GetTickCount();
			m_pThreatManager->QuarantineFile(pScanInfo);
			m_dwPEQuarantineTime += (GetTickCount() - dwPEQuarantineStartTime);
		}
		return dwRepairResult;
	}
	__except(CMaxExceptionFilter::Filter(GetExceptionCode(), GetExceptionInformation(), _T("Exception caught Scanner::_RepairFile"), (pScanInfo->IsChildFile ? pScanInfo->szContainerFileName : pScanInfo->szFileToScan)))
	{
	}
	return REAPIR_STATUS_FAILURE;
}

bool CMaxScanner::GetSignature(TCHAR * szFilePath, TCHAR *szMd5)
{
	memset(szMd5, 0, MAX_PATH * sizeof(TCHAR));
	if(_tcslen(szFilePath) > 0)
	{
		CStringA csFilePath(szFilePath);
		char cMD5Signature[33] = {0};
		if(GetMD5Signature32((LPCSTR)csFilePath, cMD5Signature))
		{
			CString csSignature(cMD5Signature);
			_tcscpy_s(szMd5, MAX_PATH, (LPCTSTR)csSignature);
			return true;
		}
	}
	return false;
}

int CMaxScanner::_IsCompressedFile(PMAX_SCANNER_INFO pScanInfo)
{
	if(!pScanInfo)
	{
		return -1;
	}

	int i = 0;
	WCHAR *ExtPtr = NULL;

	ExtPtr = wcsrchr(pScanInfo->szFileToScan, '.');
	if(ExtPtr != NULL)
	{
		for(i = 0; i < EXTENSION_OF_COMPRESSED_FILES; i++)
		{
			if(_wcsicmp(ExtPtr, CompressedFileExtension[i])== 0)
				return i;
		}
	}
	return -1;
}

int CMaxScanner::_IsExcludeCompressedExtension(PMAX_SCANNER_INFO pScanInfo)
{
	if(!pScanInfo)
	{
		return -1;
	}

	int i = 0;
	WCHAR *ExtPtr = NULL;

	if(_tcsstr(pScanInfo->szFileToScan, _T("\\thumb.db"))!= NULL)
		return -1;

	ExtPtr = wcsrchr(pScanInfo->szFileToScan, '.');
	if(ExtPtr != NULL)
	{
		for(i = 0; i < EXCLUDE_EXTENSION_OF_COMPRESSED_FILES; i++)
		{
			if(_wcsicmp(ExtPtr, CompressedFileExcludeExtension[i])== 0)
				return i;
		}
	}
	return -1;
}

/*
int CMaxScanner::_IsExcludeScanExtension(PMAX_SCANNER_INFO pScanInfo)
{
	if(!pScanInfo)
	{
		return -1;
	}

	if(!m_bIsExcludeExtDBLoaded)
	{
		return -1;
	}

	int i = 0;
	WCHAR *ExtPtr = NULL;

	ExtPtr = wcsrchr(pScanInfo->szFileToScan, '.');
	CString csExt(ExtPtr);
	if(ExtPtr != NULL)
	{
		for(i = 0; i < EXCLUDE_EXTENSION_OF_SCANNING_FILES; i++)
		{
			CString csLog(pScanFileExcludeExtension[i]);
			if(_wcsicmp(ExtPtr,pScanFileExcludeExtension[i])== 0)
			{
				return i;
			}
		}
	}
	return -1;
}
*/
int CMaxScanner::_IsExcludeScanExtension(PMAX_SCANNER_INFO pScanInfo)
{
	if(!pScanInfo)
	{
		return -1;
	}

	if(!m_bIsExcludeExtDBLoaded)
	{
		return -1;
	}

	int i = 0;
	WCHAR *ExtPtr = NULL;

	TCHAR	szFile2Scan[1024] = {0x00};

	_tcscpy_s(szFile2Scan, 1024,pScanInfo->szFileToScan);

	while(1)
	{
		ExtPtr = NULL;
		ExtPtr = wcsrchr(szFile2Scan, L'.');
		if(ExtPtr != NULL)
		{
			CString csExt(ExtPtr);

			*ExtPtr = L'\0';
			for(i = 0; i < EXCLUDE_EXTENSION_OF_SCANNING_FILES; i++)
			{
				CString csLog(pScanFileExcludeExtension[i]);
				if(_wcsicmp(csExt,pScanFileExcludeExtension[i])== 0)
				{
					return i;
				}
			}
		}
		else
		{
			break;
		}
	}
	return -1;
}

bool CMaxScanner::IsExcluded(ULONG ulThreatID, LPCTSTR szThreatName, LPCTSTR szPath)
{
	return m_pMaxDSrvWrapper && m_pMaxDSrvWrapper->IsExcluded(ulThreatID, szThreatName, szPath);
}

bool CMaxScanner::GetThreatName(ULONG ulThreatID, TCHAR *szThreatName)
{
	if(m_pMaxDSrvWrapper)
	{
		BYTE byThreatLevel = 0;
		CString csThreatName = m_pMaxDSrvWrapper->GetSpyName(ulThreatID, byThreatLevel);
		_tcscpy_s(szThreatName, MAX_PATH, csThreatName);
		return true;
	}
	return false;
}

bool CMaxScanner::_RestoreOriginal(bool bUsingDummyFile, PMAX_SCANNER_INFO pScanInfo)
{
	if(bUsingDummyFile) //incase of dummy file name no need to restore file to original location!
	{
		DeleteFile(pScanInfo->szFileToScan);	// clean up dummy file!
		_tcscpy_s(pScanInfo->szFileToScan, _countof(pScanInfo->szFileToScan), pScanInfo->szFreshFile);
	}
	else
	{
		if(!m_pThreatManager->RestoreFile(pScanInfo))
		{
			return false;
		}
	}
	AddLogEntry(L">>>>> RESTORED   : %s", pScanInfo->szFileToScan, NULL, true, LOG_DEBUG);
	return true;
}

void CMaxScanner::ReloadInstantINI()
{
	m_oInstantScanner.LoadEntriesFromINI();
}

bool CMaxScanner::_LoadUnpacker()
{
	if(m_lpfnUnpackFileNew == NULL)
	{
		m_hUnpacker = LoadLibrary(_T("AuUnpacker.dll"));
		if(m_hUnpacker == NULL)
		{
			return false;
		}

		m_lpfnUnpackFileNew = (LPFNUnpackFileNew) GetProcAddress(m_hUnpacker, "UnPackFileNew");
		if(m_lpfnUnpackFileNew  == NULL)
		{
			return false;
		}
		
		m_lpfnExtractFile = (LPFNExtractFile) GetProcAddress(m_hUnpacker, "ExtractFile");
		if(m_lpfnExtractFile  == NULL)
		{
			return false;
		}

		m_lpfnExtractNonPEFile = (LPFNExtractNonPEFile) GetProcAddress(m_hUnpacker, "ExtractNonPEFile");
		if(m_lpfnExtractNonPEFile  == NULL)
		{
			return false;
		}
	}

	CString csGUID = _T("Global\\{F71D449D-E461-43aa-B51A-4825EEA94A2F}}");
		HANDLE	hMutex = NULL;

		hMutex = OpenMutex(SYNCHRONIZE, FALSE, csGUID);
		if (hMutex == NULL)
		{
			TCHAR	szAppPath[1024] = { 0x00 }, szExeName[1024] = { 0x00 };

			_stprintf(szAppPath, L"%s", CSystemInfo::m_strAppPath);
			_stprintf(szExeName, L"%sAuUnpackExe.exe", szAppPath);

			CExecuteProcess		objExecuteProc;
			objExecuteProc.ExecuteProcess(szExeName, L"", true, 0);

			Sleep(200);
		}
		else
		{
			CloseHandle(hMutex);
			hMutex = NULL;
		}

	return true;
}

bool CMaxScanner::_Unpack32Fileon64Os(PMAX_SCANNER_INFO pScanInfo, PMAX_SCANNER_INFO pUnpakcedScanInfo)
{
	CString		csCmdLine;
	TCHAR		szFileName[1024] = {0x00};
	TCHAR		szOnlyFileName[512] = {0x00};
	TCHAR		*pTemp = nullptr;

	if (pScanInfo->pMaxPEFile->m_szFilePath == nullptr)
	{
		return false;
	}

	CString csGUID = _T("Global\\{F71D449D-E461-43aa-B51A-4825EEA94A2F}}");
	HANDLE	hMutex = NULL;

	hMutex = OpenMutex(SYNCHRONIZE,FALSE,csGUID);
	if (hMutex == NULL)
	{
		TCHAR	szAppPath[1024] = {0x00},szExeName[1024] = {0x00};
		
		_stprintf(szAppPath,L"%s", CSystemInfo::m_strAppPath);
		_stprintf(szExeName,L"%sAuUnpackExe.exe",szAppPath);
		
		CExecuteProcess		objExecuteProc;
		objExecuteProc.ExecuteProcess(szExeName,L"",true,0);
		Sleep(200);
	}
	else
	{
		CloseHandle(hMutex);
		hMutex = NULL;
	}

	TCHAR	szDummyFile[1024] = {0x00};
	SHARED_UNPACKER_SWITCH_DATA	objSendData = {0x00};

	_tcscpy_s(objSendData.szFile2Unpack,520,pScanInfo->pMaxPEFile->m_szFilePath);

	HANDLE	hUnpackerThread = NULL;
	DWORD	dwTdreadID = 0x00;

	hUnpackerThread = CreateThread(nullptr,0,Unpacker32Thread,(LPVOID)&objSendData,0,&dwTdreadID);
	if (hUnpackerThread)
	{
		DWORD dwWaitRet = WaitForSingleObject(hUnpackerThread,15 * 1000);
		TerminateThread(hUnpackerThread,0x01);
		hUnpackerThread = nullptr;

	}
	_tcscpy_s(pUnpakcedScanInfo->pMaxPEFile->m_szFilePath,MAX_PATH,objSendData.szUnpackedFileName);
	
	if (PathFileExists(objSendData.szUnpackedFileName) == TRUE)
	{
		return true;
	}

	
	return false;
}

bool CMaxScanner::_UnpackFile(PMAX_SCANNER_INFO pScanInfo, PMAX_SCANNER_INFO pUnpakcedScanInfo)
{
	DWORD dwStartTime = GetTickCount();
	
	__try
	{
		if((!m_lpfnUnpackFileNew) || (!pScanInfo) || (!pScanInfo->pMaxPEFile))
		{
			m_dwTotalUnPackTime += (GetTickCount() - dwStartTime);
			return false;
		}

		if (m_dwUpackRecursionCnt > MAX_UNPACK_RECURSSION_LEVEL)
		{
			AddLogEntry(L"##### SKIP-UPREC : %s", pScanInfo->szFileToScan, NULL, true, LOG_DEBUG);
			return false;
		}

		int  iStatus = 0x00;
		bool b32BitFile = false;
/*
		iStatus = m_lpfnUnpackFileNew(pScanInfo->pMaxPEFile, pUnpakcedScanInfo->pMaxPEFile);

	
#ifdef WIN64

		if (iStatus == 7 && (pScanInfo->pMaxPEFile->m_b64bit == false || m_dwActmonScan == 0x00))
		{
			OutputDebugString(pScanInfo->pMaxPEFile->m_szFilePath);
			OutputDebugString(L"Inside iStatus == 7 ");
			iStatus = 0;
			if (_Unpack32Fileon64Os(pScanInfo, pUnpakcedScanInfo))
			{
				b32BitFile = true;
				iStatus = 1;
			}
		}

#endif
*/

#ifndef WIN64	
		
		iStatus = m_lpfnUnpackFileNew(pScanInfo->pMaxPEFile, pUnpakcedScanInfo->pMaxPEFile);
#else
		if (pScanInfo->pMaxPEFile->m_b64bit == false || m_dwActmonScan == 0x00)
		{
			iStatus = 0;
			if (_Unpack32Fileon64Os(pScanInfo, pUnpakcedScanInfo))
			{
				b32BitFile = true;
				iStatus = 1;
			}
		}
		else
		{
			iStatus = m_lpfnUnpackFileNew(pScanInfo->pMaxPEFile, pUnpakcedScanInfo->pMaxPEFile);
		}
#endif

		if(iStatus == 0)			// Not Packed
		{
			AddLogEntry(L">>>>> NOTPACKED  : %s", pScanInfo->szFileToScan, 0, true, LOG_DEBUG);
		}
		else if(iStatus == 1)		// Unpack Success
		{
			m_iTotalNoOfPackedFiles++;
			m_iTotalNoOfUnPackSuccessFiles++;
			m_dwTotalUnPackTime += (GetTickCount() - dwStartTime);
			_tcscpy_s(pUnpakcedScanInfo->szFileToScan, pUnpakcedScanInfo->pMaxPEFile->m_szFilePath);
			if (b32BitFile)
			{
				_CloseMaxPEFile(pUnpakcedScanInfo, true);
			}

			AddLogEntry(L"##### UPSUCCESS  : %s -> %s", pScanInfo->szFileToScan, pUnpakcedScanInfo->szFileToScan, true, LOG_DEBUG);
			return true;
		}
		else if(iStatus == 2)		// Unpack Failed
		{
			m_iTotalNoOfPackedFiles++;
			m_iTotalNoOfUnPackFailedFiles++;
			AddLogEntry(L"##### UPFAILED   : %s", pScanInfo->szFileToScan, 0, true, LOG_DEBUG);
		}
	}
	__except(CMaxExceptionFilter::Filter(GetExceptionCode(), GetExceptionInformation(), _T("Exception caught Scanner::_UnpackFile"), (pScanInfo->IsChildFile ? pScanInfo->szContainerFileName : pScanInfo->szFileToScan)))
	{
	}
	m_dwTotalUnPackTime += (GetTickCount() - dwStartTime);

	return false;
}

void CMaxScanner::_UnloadUnpacker()
{
	if(m_hUnpacker)
	{
		LPFNUnloadDlls lpfnUnloadDll = (LPFNUnloadDlls) GetProcAddress(m_hUnpacker, "UnloadDlls");
		if(lpfnUnloadDll)
		{
			lpfnUnloadDll();
		}
		FreeLibrary(m_hUnpacker);
		m_hUnpacker = NULL;
		m_lpfnUnpackFileNew = NULL;
		m_lpfnExtractFile = NULL;
		m_lpfnExtractNonPEFile = NULL;
	}
}

void CMaxScanner::_CloseMaxPEFile(PMAX_SCANNER_INFO pScanInfo, bool bCleanTree)
{
	__try
	{
		PMAX_SCANNER_INFO pHoldScanInfo = pScanInfo;
		while(pHoldScanInfo)
		{
			if(pHoldScanInfo->pMaxPEFile)
			{
				pHoldScanInfo->pMaxPEFile->CloseFile();
				delete pHoldScanInfo->pMaxPEFile;
				pHoldScanInfo->pMaxPEFile = NULL;
			}
			pHoldScanInfo = pHoldScanInfo->pNextScanInfo;
		}
	
		if(bCleanTree)
		{
			pHoldScanInfo = pScanInfo;
			if(pHoldScanInfo->pNextScanInfo && pHoldScanInfo->FreeNextScanInfo)
			{
				pScanInfo = pHoldScanInfo;
				pHoldScanInfo = pHoldScanInfo->pNextScanInfo;
				pScanInfo->pNextScanInfo = NULL;
				pScanInfo->FreeNextScanInfo = false;
				while(pHoldScanInfo)
				{
					pScanInfo = pHoldScanInfo->pNextScanInfo;
					if(pHoldScanInfo->IsChildFile && !pHoldScanInfo->IsEMLFile)
					{
						::DeleteFile(pHoldScanInfo->szFileToScan);
					}
					delete pHoldScanInfo;
					pHoldScanInfo = pScanInfo;
				}
			}
		}
	}
	__except (CMaxExceptionFilter::Filter(GetExceptionCode(), GetExceptionInformation(), _T("Exception caught Scanner::_CloseMaxPEFile"), (pScanInfo->IsChildFile ? pScanInfo->szContainerFileName : pScanInfo->szFileToScan)))
	{
	}
}

/*--------------------------------------------------------------------------------------
Function       : CMaxScanner::_ScanFolder
In Parameters  : PMAX_SCANNER_INFO pScanInfo, LPCTSTR szExtractPath
Out Parameters : void
Description    :
Author & Date  : Darshan Singh Virdi & 11 Jan, 2012.
--------------------------------------------------------------------------------------*/
bool CMaxScanner::_ScanFolder(PMAX_SCANNER_INFO pScanInfo, LPCTSTR szExtractPath)
{
	bool bReturnVal = false;
	HANDLE hFindFile = INVALID_HANDLE_VALUE;
	WIN32_FIND_DATA FindFileData = {0};
	TCHAR *cFullPath = NULL;
	CS2U oScanList(false, true);

	AddLogEntry(L">>>>> SCAN-FOLDER: %s : %s", pScanInfo->szFileToScan, szExtractPath, true, LOG_DEBUG);
	
	cFullPath = new TCHAR[MAX_PATH];
	if(!cFullPath)
	{
		return bReturnVal;
	}

	if(!m_oDirectoryManager.FormatStrings(cFullPath, MAX_PATH, _T("%s"), szExtractPath))
	{
		AddLogEntry(L"Skipping long folder: %s", szExtractPath);
		delete [] cFullPath;
		return bReturnVal;
	}

	if(cFullPath[wcslen(cFullPath) - 1] == '\\') // remove \\ 
	{
		cFullPath[wcslen(cFullPath) - 1] = 0;
	}

	if(!m_oDirectoryManager.AppendString(cFullPath, MAX_PATH, L"\\*.*"))
	{
		delete [] cFullPath;
		return bReturnVal;
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
			
			if(!m_oDirectoryManager.FormatStrings(cFullPath, MAX_PATH, _T("%s\\%s"), szExtractPath, FindFileData.cFileName))
			{
				continue;
			}

			if((FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)== FILE_ATTRIBUTE_DIRECTORY)
			{
				if(wcscmp(FindFileData.cFileName, L"") == 0)
				{
					break;
				}

				if((wcscmp(FindFileData.cFileName, L".") != 0) && (wcscmp(FindFileData.cFileName, L"..") != 0))
				{
					bReturnVal = _ScanFolder(pScanInfo, cFullPath);
					if(bReturnVal)	//stop scanning even if one file infected found!
					{
						break;
					}
				}
			}
			else
			{
				if(pScanInfo->IsEMLFile)
				{
					DWORD ulData = 0;
					if(oScanList.SearchItem(cFullPath, &ulData))
					{
						AddLogEntry(L">>>>> SKIP-RESCAN: %s : %s", pScanInfo->szFileToScan, cFullPath, true, LOG_DEBUG);
						continue;
					}
					oScanList.AppendItem(cFullPath, ulData);
				}
				
				PMAX_SCANNER_INFO pLastScanInfo = pScanInfo;
				while(pLastScanInfo->pNextScanInfo)
				{
					pLastScanInfo = pLastScanInfo->pNextScanInfo;
				}
				PMAX_SCANNER_INFO pScanInfoExtracted = new MAX_SCANNER_INFO;
				memset(pScanInfoExtracted, 0, sizeof(MAX_SCANNER_INFO));
				pLastScanInfo->FreeNextScanInfo = true;
				pLastScanInfo->pNextScanInfo = pScanInfoExtracted;
				_tcscpy_s(pScanInfoExtracted->szFileToScan, cFullPath);
				_tcscpy_s(pScanInfoExtracted->szContainerFileName, pScanInfo->szFileToScan);
				pScanInfo->IsArchiveFile = true;
				pScanInfoExtracted->IsChildFile = true;
				pScanInfoExtracted->AutoQuarantine = pScanInfo->AutoQuarantine;
				pScanInfoExtracted->SkipPolyMorphicScan = pScanInfo->SkipPolyMorphicScan;
				pScanInfoExtracted->SkipPatternScan = pScanInfo->SkipPatternScan;
				pScanInfoExtracted->IsEMLFile = pScanInfo->IsEMLFile;

				AddLogEntry(L">>>>> SCAN-FILE  : %s : %s", pScanInfo->szFileToScan, cFullPath, true, LOG_DEBUG);
				bReturnVal = _ScanFileTimer(pScanInfoExtracted);			// recursive call to handle zip inside a zip
				if(bReturnVal)
				{
					pScanInfo->ThreatDetected = pScanInfoExtracted->ThreatDetected;
					pScanInfo->ThreatSuspicious = pScanInfoExtracted->ThreatSuspicious;
					pScanInfo->eMessageInfo = pScanInfoExtracted->eMessageInfo;
					pScanInfo->eDetectedBY = pScanInfoExtracted->eDetectedBY;
					pScanInfo->ulThreatID = pScanInfoExtracted->ulThreatID;
					_tcscpy_s(pScanInfo->szThreatName, pScanInfoExtracted->szThreatName);
					_tcscpy_s(pScanInfo->szOLEMacroName, pScanInfoExtracted->szOLEMacroName);
					if(pScanInfo->AutoQuarantine == false)	// we dont need the extracted files anymore!
					{
						_CloseMaxPEFile(pScanInfo, true);
						break;
					}
					else if(!pScanInfo->IsEMLFile)
					{
						break;
					}
				}
			}
		}while(FindNextFile(hFindFile, &FindFileData));
		FindClose(hFindFile);
	}

	delete [] cFullPath;
	return bReturnVal;
}

int CMaxScanner::_CheckFileType(PMAX_SCANNER_INFO pScanInfo)
{
	BYTE		bELFSig[]		= {0x7F, 0x45, 0x4C, 0x46};
	BYTE		bRARSig[]		= {0x52, 0x61, 0x72, 0x21};
	BYTE		bZIPSig[]		= {0x50, 0x4B, 0x03, 0x04};
	BYTE		bZIPSig_1[] 	= {0x50, 0x4B, 0x30, 0x30, 0x50, 0x4B, 0x03, 0x04};
	BYTE		bGZipSig[]		= {0x1F, 0x8B};
	BYTE		bBZipSig[]		= {0x42, 0x5A, 0x68};
	BYTE		bARJSig[]		= {0x60, 0xEA};
	BYTE		bMSSZDDSig[]	= {0x53, 0x5A,0x44,0x44};
	BYTE		bMSCABSig[] 	= {0x4D,0x53,0x43,0x46};
	BYTE		bMSCHMSig[] 	= {0x49,0x54,0x53,0x46};
	BYTE		bCryptCFFSig[]	= {0xB6, 0xB9, 0xAC, 0xAE};
	BYTE		bGIFSig[]		= {0x47,0x49,0x46};
	BYTE		bBMPSig[]		= {0x42,0x4D};
	BYTE		bJPEGSig[]		= {0xFF,0xD8,0xFF};
	BYTE		bPNGSig[]		= {0x89,0x50,0x4E,0x47};	
	BYTE		bMaxEMLSig[]	= {0x7b, 0x37, 0x39, 0x39, 0x35, 0x33, 0x39, 0x45, 0x35, 0x2d, 0x45, 0x44, 0x43, 0x45, 0x2d, 0x34, 0x35, 0x36, 0x35, 0x2d, 0x39, 0x41, 0x36, 0x32, 0x2d, 0x31, 0x45, 0x39, 0x35, 0x37, 0x46, 0x30, 0x41, 0x30, 0x46, 0x38, 0x34, 0x7d};	//{799539E5-EDCE-4565-9A62-1E957F0A0F84}

	BYTE		bJPEGSig_1[]	= {0x4A,0x46,0x49,0x46}; //Offset : 0x06
	BYTE		bJPEGSig_2[]	= {0x45,0x78,0x69,0x66}; //Offset : 0x06
	BYTE		bSISSig[]		= {0x19,0x04,0x00,0x10}; //Offset : 0x08

	BYTE		bPDFSig[]		= {0x25, 0x50, 0x44, 0x46};
	BYTE		bMSISig[]		= {0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1};
	BYTE		bCURSig[]		= {0x00, 0x00, 0x02, 0x00, 0x01, 0x00, 0x20, 0x20, 0x00, 0x00};
	BYTE		bICONSig[]		= {0x00, 0x00, 0x01, 0x00};

	BYTE		bDMGCollySig[]	= {0x6B, 0x6F, 0x6C, 0x79};
	BYTE		bUBSig_1[]		= {0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00};
	BYTE		bUBSig_2[]		= {0xBE, 0xBA, 0xFE, 0xCA, 0x00, 0x00};
	//For Mac detection 26-Sept-2015 Ravi
	BYTE		bMAC_MetaSig[] = {0x00, 0x00, 0x01, 0x00}; //Mac Metadata files
	BYTE		bMAC_O_32_LE[] = {0xCE, 0xFA, 0xED, 0xFE}; //Mac 32 Bit Little Endian
	BYTE		bMAC_O_64_LE[] = {0xCF, 0xFA, 0xED, 0xFE}; //Mac 64 Bit Little Endian
	BYTE		bMAC_O_32_BE[] = {0xFE, 0xED, 0xFA, 0xCE}; //Mac 32 Bit Big Endian
	BYTE		bMAC_O_64_BE[] = {0xFE, 0xED, 0xFA, 0xCF}; //Mac 64 Bit Big Endian
	BYTE		bMAC_MetaSig2[] = {0x23, 0x21, 0x2F, 0x62, 0x69, 0x6E};
	BYTE		bMAC_MetaSigLarge[] = {0x00, 0x00, 0x01, 0x00, 0x00, 0x00};

	BYTE		bUBSig_Class_1[]		= {0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x03};
	BYTE		bUBSig_Class_2[]		= {0xBE, 0xBA, 0xFE, 0xCA, 0x00, 0x03};

	BYTE		bIOS_DEB[] = {0x21, 0x3C, 0x61, 0x72, 0x63, 0x68, 0x3E, 0x0A, 0x64, 0x65, 0x62, 0x69, 0x61, 0x6E, 0x2D, 0x62, 0x69, 0x6E, 0x61, 0x72, 0x79}; //IOS deb files
	//Header to Exclude 
	BYTE		bPDBSig_1[]		= {0x4D, 0x69, 0x63, 0x72, 0x6F, 0x73, 0x6F, 0x66, 0x74, 0x20, 0x43, 0x2F, 0x43, 0x2B, 0x2B, 0x20, 0x70, 0x72, 0x6F, 0x67, 0x72, 0x61, 0x6D, 0x20, 0x64, 0x61, 0x74, 0x61, 0x62, 0x61, 0x73, 0x65};		//(Microsoft C/C++ program database)
	BYTE		bPDBSig_2[]		= {0x4D, 0x69, 0x63, 0x72, 0x6F, 0x73, 0x6F, 0x66, 0x74, 0x20, 0x43, 0x2F, 0x43, 0x2B, 0x2B, 0x20, 0x4D, 0x53, 0x46};	//(Microsoft C/C++ MSF)
	BYTE		bFLVSig[]		= {0x46, 0x4C, 0x56};
	BYTE		bOBJSig[]		= {0x00, 0x00, 0xFF, 0xFF, 0x01, 0x00, 0x4C, 0x01};
	BYTE		bDMPSig[]		= {0x4D, 0x44, 0x4D, 0x50};
	BYTE		bMP4_3GPSig[]	= {0x66, 0x74, 0x79, 0x70, 0x33, 0x67}; //0x04
	BYTE		bMP4Sig[]		= {0x66, 0x74, 0x79, 0x70, 0x69, 0x73, 0x6F, 0x6D}; //0x04
	BYTE		bMP3Sig[]		= {0x49, 0x44, 0x33}; 
	BYTE		bMPEGSig[]		= {0x00, 0x00, 0x01, 0xB3};
	BYTE		bVOBSig[]		= {0x00, 0x00, 0x01, 0xBA};
	BYTE		bM4VSig[]		= {0x66, 0x74, 0x79, 0x70, 0x4D, 0x34, 0x56}; //0x04
	BYTE		bM4ASig[]		= {0x66, 0x74, 0x79, 0x70, 0x6D, 0x70, 0x34}; //0x04
	BYTE		bM4A_2Sig[]		= {0x66, 0x74, 0x79, 0x70, 0x4D, 0x34, 0x41}; //0x04
	BYTE		bWEBMSig[]		= {0x1A, 0x45, 0xDF, 0xA3, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1F, 0x42, 0x86, 0x81, 0x01};
	BYTE		bMSUSig[]		= {0x4D, 0x53, 0x43, 0x46};
	BYTE		bLIBSig[]		= {0x21, 0x3C, 0x61, 0x72, 0x63, 0x68, 0x3E};
	BYTE		bWMFSig[]		= {0xD7, 0xCD, 0xC6, 0x9A, 0x00, 0x00};
	BYTE		bAVISig[]		= {0x52, 0x49, 0x46, 0x46};
	BYTE		bPREFETCHSig[]	= {0x11, 0x00, 0x00, 0x00, 0x53, 0x43, 0x43, 0x41, 0x0F};
	BYTE		bPNFSig[]		= {0x01, 0x01, 0x02, 0x00, 0xA3, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00};
	BYTE		bMNGSig[]		= {0x8A, 0x4D, 0x4E, 0x47};
	BYTE		bDCTSig[]		= {0x89, 0x53, 0x44, 0x42};
	BYTE		bSAVSig[]		= {0x72, 0x65, 0x67, 0x66, 0x01};
	BYTE		bTLBSig[]		= {0x4D, 0x53, 0x46, 0x54};
	BYTE		bRMVDSig[]		= {0x2E, 0x52, 0x4D, 0x46};
	BYTE		bAWBSig[]		= {0x23, 0x21, 0x41, 0x4D, 0x52, 0x2D, 0x57, 0x42};
	BYTE		bMDBSig[]		= {0x53, 0x74, 0x61, 0x6E, 0x64, 0x61, 0x72, 0x64, 0x20, 0x4A, 0x65, 0x74, 0x20, 0x44, 0x42};
	BYTE		bMKVSig[]		= {0x6D, 0x61, 0x74, 0x72, 0x6F, 0x73, 0x6B, 0x61}; //0x18
	BYTE		bDWGSig[]		= {0x41, 0x43, 0x31, 0x30};
	BYTE		bPSDSig[]		= {0x38, 0x42, 0x50, 0x53, 0x00, 0x01, 0x00};
	BYTE		bMSTSig[]		= {0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1};
	BYTE		b7zSig[]		= {0x37, 0x7A, 0xBC, 0xAF};

	BYTE		bDexHeader[] = {0x64, 0x65, 0x78, 0x0A, 0x30, 0x33, 0x35, 0x00};
	BYTE		bDexHeader1[] = {0x64, 0x65, 0x78, 0x0A, 0x30, 0x33, 0x36, 0x00};  // dex.036   added by Himanshu

	BYTE		bWMAHeader[]	= {0x30,0x26,0xB2,0x75,0x8E,0x66,0xCF,0x11,0xA6,0xD9,0x00,0xAA,0x00,0x62,0xCE,0x6C};

	BYTE		bSISHeader[] = {0x12, 0x3A, 0x00, 0x10};
	BYTE		bSISDllHeader[] = {0x79, 0x00, 0x00, 0x10};
	BYTE		bSISExeHeader[] = {0x7A, 0x00, 0x00, 0x10};

	BYTE		bJCLASS[] = {0xCA, 0xFE, 0xBA, 0xBE};

	BYTE		bMSOfficeHeader[] = {0xD0,0xCF,0x11,0xE0,0xA1,0xB1,0x1A,0xE1};

	BYTE		bRegSigV4[] = {0x52, 0x45, 0x47, 0x45, 0x44, 0x49, 0x54, 0x34}; 
	BYTE		bRegSig[] = {0x57, 0x00, 0x69, 0x00, 0x6E, 0x00, 0x64, 0x00, 0x6F, 0x00, 0x77, 0x00, 0x73, 
							 0x00, 0x20, 0x00, 0x52, 0x00, 0x65, 0x00, 0x67, 0x00, 0x69, 0x00, 0x73, 0x00, 0x74, 0x00, 
							 0x72, 0x00, 0x79, 0x00, 0x20, 0x00, 0x45, 0x00, 0x64, 0x00, 0x69, 0x00, 0x74, 0x00};

	BYTE		bRTFSig[] = {0x7B, 0x5C, 0x72, 0x74, 0x66};

	BYTE		bANI_RIFF[] = {0x46, 0x49, 0x52, 0x46};
	BYTE		bANI_ACON[] = {0x4F, 0x43, 0x41,0x4E};

	BYTE		bMGHeader[] = {0x3F,0x5F,0x03,0x00};

	BYTE		bMZPE[] = {0x4D,0x5A};
	BYTE		bMxQrtSig[]		= {0xDA, 0xB4, 0xFC, 0xFB, 0xCA, 0xFF};

	BYTE		bLNKSig[]		= {0x4C, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00};
	
	BYTE		bEICARSig[]		= {0x58, 0x35, 0x4F, 0x21, 0x50, 0x25, 0x40, 0x41, 0x50, 0x5B, 0x34, 0x5C, 0x50, 0x5A, 0x58, 0x35, 0x34, 0x28, 0x50, 0x5E, 0x29, 0x37, 0x43, 0x43, 0x29, 0x37, 0x7D, 0x24, 0x45, 0x49, 0x43, 0x41, 0x52, 0x2D, 0x53, 0x54, 0x41, 0x4E, 0x44, 0x41, 0x52, 0x44};

	BYTE		bBPFFile[]		= {0x56, 0x46, 0x41, 0x54, 0x46, 0x49, 0x4C, 0x45};
	BYTE		bAutoITA3X[]	= {0x41, 0x55, 0x33, 0x21, 0x45, 0x41, 0x30, 0x36};

	BYTE		bHeaderBuff[55] = {0};
	
	if(!pScanInfo->pMaxPEFile)
	{
		AddLogEntry(L">>>>> FILE-TYPE  : %s : %s", pScanInfo->szFileToScan, _T("NOT OPEN"), true, LOG_DEBUG);
		return 0x00;
	}

	if(!pScanInfo->pMaxPEFile->ReadBuffer(bHeaderBuff, 0, 50, 50))
	{
		AddLogEntry(L">>>>> FILE-TYPE  : %s : %s", pScanInfo->szFileToScan, _T("READ FAILED"), true, LOG_DEBUG);
		return 0x00;
	}

	/*
	AddLogEntry(L">>>>> FILE-TYPE  : %s : After Read Buffer", pScanInfo->szFileToScan, NULL, true, LOG_DEBUG);

	TCHAR	szDummy[1024] = {0x00};

	_stprintf(szDummy,L"%02X %02X %02X %02X",bHeaderBuff[0x00],bHeaderBuff[0x01],bHeaderBuff[0x02],bHeaderBuff[0x03]);

	AddLogEntry(L">>>>> FILE-TYPE  : %s : %s", pScanInfo->szFileToScan, szDummy, true, LOG_DEBUG);
	*/
	if (memcmp(&bHeaderBuff[0],bMZPE,sizeof(bMZPE)) == 0x00)
	{
		DWORD dwOverlayStart = 0x0;
		dwOverlayStart = pScanInfo->pMaxPEFile->m_stSectionHeader[pScanInfo->pMaxPEFile->m_stPEHeader.NumberOfSections - 1].PointerToRawData + pScanInfo->pMaxPEFile->m_stSectionHeader[pScanInfo->pMaxPEFile->m_stPEHeader.NumberOfSections - 1].SizeOfRawData;

		///NULLSoft
		if(pScanInfo->pMaxPEFile->m_stPEHeader.NumberOfSections > 3)
		{
			if(memcmp(pScanInfo->pMaxPEFile->m_stSectionHeader[0x03].Name, ".ndata", 7) == 0 && (pScanInfo->pMaxPEFile->m_stSectionHeader[0x03].SizeOfRawData == 0x00) && (pScanInfo->pMaxPEFile->m_stSectionHeader[0x03].PointerToRawData == 0))
			{ 
				//EFBEADDE4E756C6C736F6674496E7374B9510000 : ....NullsoftInst
				const BYTE bySign[] = {0xEF,0xBE,0xAD,0xDE,0x4E,0x75,0x6C,0x6C,0x73,0x6F,0x66,0x74,0x49,0x6E,0x73,0x74};
				
				if(dwOverlayStart != 0)
				{			
					BYTE bNSISHeaderBuff[0x300]={0x00};
					if(pScanInfo->pMaxPEFile->ReadBuffer(bNSISHeaderBuff,dwOverlayStart,0x300,0x30))
					{
						for(int iIndex = 0x4; iIndex < 0x2D0; iIndex++)
						{						
							if(memcmp(&bNSISHeaderBuff[iIndex], bySign, sizeof(bySign)) == 0x00)
							{
								AddLogEntry(L">>>>> FILE-TYPE : %s : %s", pScanInfo->szFileToScan, _T("VIRUS_FILE_TYPE_NSIS"), true, LOG_DEBUG);
								return VIRUS_FILE_TYPE_NSIS;
							}
						}

					}
				}	
			}
		}

		if (pScanInfo->pMaxPEFile->m_dwFileSize > (dwOverlayStart + 0x58))
		{
			//EFBEADDE4E756C6C736F6674496E7374B9510000 : ....NullsoftInst
			const BYTE bySFXSign[] = {0x37,0x7A};

			BYTE bSFXHeaderBuff[0x10]={0x00};
			if(pScanInfo->pMaxPEFile->ReadBuffer(bSFXHeaderBuff,(dwOverlayStart + 0x56),0x02,0x02))
			{
				if(memcmp(&bSFXHeaderBuff[0x00], bySFXSign, sizeof(bySFXSign)) == 0x00)
				{
					AddLogEntry(L">>>>> FILE-TYPE : %s : %s", pScanInfo->szFileToScan, _T("VIRUS_FILE_TYPE_7ZSFX"), true, LOG_DEBUG);
					return VIRUS_FILE_TYPE_7ZSFX;
				}
			}
		}

		AddLogEntry(L">>>>> FILE-TYPE  : %s : %s", pScanInfo->szFileToScan, _T("VIRUS_FILE_TYPE_PE"), true, LOG_DEBUG);
		return VIRUS_FILE_TYPE_PE;
	}

	if (memcmp(&bHeaderBuff[0],bEICARSig,sizeof(bEICARSig)) == 0x00)
	{
		AddLogEntry(L">>>>> FILE-TYPE  : %s : %s", pScanInfo->szFileToScan, _T("VIRUS_FILE_TYPE_EICAR"), true, LOG_DEBUG);
		return VIRUS_FILE_TYPE_EICAR;
	}

	if (memcmp(&bHeaderBuff[0],bLNKSig,sizeof(bLNKSig)) == 0x00)
	{
		AddLogEntry(L">>>>> FILE-TYPE  : %s : %s", pScanInfo->szFileToScan, _T("VIRUS_FILE_TYPE_LNK"), true, LOG_DEBUG);
		if (m_dwActmonScan == 0x01)
		{
			return 0x00;
		}
		else
		{
			return VIRUS_FILE_TYPE_LNK;
		}
	}

	if (memcmp(&bHeaderBuff[0],bGZipSig,sizeof(bGZipSig)) == 0x00)
	{
		AddLogEntry(L">>>>> FILE-TYPE  : %s : %s", pScanInfo->szFileToScan, _T("VIRUS_FILE_TYPE_GZ"), true, LOG_DEBUG);
		return VIRUS_FILE_TYPE_GZ;
	}

	if (memcmp(&bHeaderBuff[0],bDexHeader,sizeof(bDexHeader)) == 0x00 || memcmp(&bHeaderBuff[0],bDexHeader1,sizeof(bDexHeader1)) == 0x00)
	{
		AddLogEntry(L">>>>> FILE-TYPE  : %s : %s", pScanInfo->szFileToScan, _T("VIRUS_FILE_TYPE_DEX"), true, LOG_DEBUG);
		return VIRUS_FILE_TYPE_DEX;
	}

	if (   memcmp(&bHeaderBuff[0x04],bSISHeader,sizeof(bSISHeader)) == 0x00 
		|| memcmp(&bHeaderBuff[0],bSISDllHeader,sizeof(bSISDllHeader)) == 0x00
		|| memcmp(&bHeaderBuff[0],bSISExeHeader,sizeof(bSISExeHeader)) == 0x00)
	{
		AddLogEntry(L">>>>> FILE-TYPE  : %s : %s", pScanInfo->szFileToScan, _T("VIRUS_FILE_TYPE_SIS"), true, LOG_DEBUG);
		return VIRUS_FILE_TYPE_SIS;
	}

	if (memcmp(&bHeaderBuff[0x00],bMSOfficeHeader,sizeof(bMSOfficeHeader)) == 0x00)
	{
		AddLogEntry(L">>>>> FILE-TYPE  : %s : %s", pScanInfo->szFileToScan, _T("VIRUS_FILE_TYPE_OLE"), true, LOG_DEBUG);
		return VIRUS_FILE_TYPE_OLE;
	}

	if (memcmp(&bHeaderBuff[0x00],bRTFSig,sizeof(bRTFSig)) == 0x00)
	{
		AddLogEntry(L">>>>> FILE-TYPE  : %s : %s", pScanInfo->szFileToScan, _T("VIRUS_FILE_TYPE_RTF"), true, LOG_DEBUG);
		return VIRUS_FILE_TYPE_RTF;
	}

	for(int i = 0x00; i < 0x04; i++)
	{
		if ((memcmp(&bHeaderBuff[i], &bRegSig[0], sizeof(bRegSig)) == 0) || (memcmp(&bHeaderBuff[i], &bRegSigV4[0], sizeof(bRegSigV4)) == 0))
		{
			AddLogEntry(L">>>>> FILE-TYPE  : %s : %s", pScanInfo->szFileToScan, _T("VIRUS_FILE_TYPE_REG"), true, LOG_DEBUG);
			return VIRUS_FILE_TYPE_REG;
		}
	}

	if (memcmp(&bHeaderBuff[0x00],bANI_RIFF,sizeof(bANI_RIFF)) == 0x00 && memcmp(&bHeaderBuff[0x08],bANI_ACON,sizeof(bANI_ACON)) == 0x00)
	{
		AddLogEntry(L">>>>> FILE-TYPE  : %s : %s", pScanInfo->szFileToScan, _T("VIRUS_FILE_TYPE_CUR"), true, LOG_DEBUG);
		return VIRUS_FILE_TYPE_CUR;
	}

	if (memcmp(&bHeaderBuff[0x00],bMGHeader,sizeof(bMGHeader)) == 0x00)
	{
		AddLogEntry(L">>>>> FILE-TYPE  : %s : %s", pScanInfo->szFileToScan, _T("VIRUS_FILE_TYPE_MSCHM"), true, LOG_DEBUG);
		return VIRUS_FILE_TYPE_MSCHM; //It is Help File
	}

	if (memcmp(&bHeaderBuff[0x10],bAutoITA3X,sizeof(bAutoITA3X)) == 0x00)
	{
		AddLogEntry(L">>>>> FILE-TYPE  : %s : %s", pScanInfo->szFileToScan, _T("VIRUS_FILE_TYPE_A3X"), true, LOG_DEBUG);
		return VIRUS_FILE_TYPE_A3X;
	}
	
//-------------------------- Exclude Extensions
	
	if (memcmp(&bHeaderBuff[0],bBPFFile,sizeof(bBPFFile)) == 0x00)
	{
		AddLogEntry(L">>>>> FILE-TYPE  : %s : %s", pScanInfo->szFileToScan, _T("VIRUS_FILE_TYPE_BPF"), true, LOG_DEBUG);
		return VIRUS_FILE_TYPE_BPF;
	}

	if (memcmp(&bHeaderBuff[0],bARJSig,sizeof(bARJSig)) == 0x00)
	{
		AddLogEntry(L">>>>> FILE-TYPE  : %s : %s", pScanInfo->szFileToScan, _T("VIRUS_FILE_TYPE_ARJ"), true, LOG_DEBUG);
		return VIRUS_FILE_TYPE_ARJ;
	}
	if (memcmp(&bHeaderBuff[0],bPDBSig_1,sizeof(bPDBSig_1)) == 0x00)
	{
		AddLogEntry(L">>>>> FILE-TYPE  : %s : %s", pScanInfo->szFileToScan, _T("VIRUS_FILE_TYPE_PDB"), true, LOG_DEBUG);
		return VIRUS_FILE_TYPE_PDB;
	}
	if (memcmp(&bHeaderBuff[0],bPDBSig_2,sizeof(bPDBSig_2)) == 0x00)
	{
		AddLogEntry(L">>>>> FILE-TYPE  : %s : %s", pScanInfo->szFileToScan, _T("VIRUS_FILE_TYPE_PDB"), true, LOG_DEBUG);
		return VIRUS_FILE_TYPE_PDB;
	}
	if (memcmp(&bHeaderBuff[0],bFLVSig,sizeof(bFLVSig)) == 0x00)
	{
		AddLogEntry(L">>>>> FILE-TYPE  : %s : %s", pScanInfo->szFileToScan, _T("VIRUS_FILE_TYPE_FLV"), true, LOG_DEBUG);
		return VIRUS_FILE_TYPE_FLV;
	}
	if (memcmp(&bHeaderBuff[0],bOBJSig,sizeof(bOBJSig)) == 0x00)
	{
		AddLogEntry(L">>>>> FILE-TYPE  : %s : %s", pScanInfo->szFileToScan, _T("VIRUS_FILE_TYPE_OBJ"), true, LOG_DEBUG);
		return VIRUS_FILE_TYPE_OBJ;
	}
	if (memcmp(&bHeaderBuff[0],bDMPSig,sizeof(bDMPSig)) == 0x00)
	{
		AddLogEntry(L">>>>> FILE-TYPE  : %s : %s", pScanInfo->szFileToScan, _T("VIRUS_FILE_TYPE_DMP"), true, LOG_DEBUG);
		return VIRUS_FILE_TYPE_DMP;
	}
	if (memcmp(&bHeaderBuff[0x04],bMP4_3GPSig,sizeof(bMP4_3GPSig)) == 0x00)
	{
		AddLogEntry(L">>>>> FILE-TYPE  : %s : %s", pScanInfo->szFileToScan, _T("VIRUS_FILE_TYPE_MP4"), true, LOG_DEBUG);
		return VIRUS_FILE_TYPE_MP4;
	}
	if (memcmp(&bHeaderBuff[0x04],bMP4Sig,sizeof(bMP4Sig)) == 0x00)
	{
		AddLogEntry(L">>>>> FILE-TYPE  : %s : %s", pScanInfo->szFileToScan, _T("VIRUS_FILE_TYPE_MP4"), true, LOG_DEBUG);
		return VIRUS_FILE_TYPE_MP4;
	}
	if (memcmp(&bHeaderBuff[0],bMP3Sig,sizeof(bMP3Sig)) == 0x00)
	{
		AddLogEntry(L">>>>> FILE-TYPE  : %s : %s", pScanInfo->szFileToScan, _T("VIRUS_FILE_TYPE_MP3"), true, LOG_DEBUG);
		return VIRUS_FILE_TYPE_MP3;
	}
	if (memcmp(&bHeaderBuff[0],bMPEGSig,sizeof(bMPEGSig)) == 0x00)
	{
		AddLogEntry(L">>>>> FILE-TYPE  : %s : %s", pScanInfo->szFileToScan, _T("VIRUS_FILE_TYPE_MPEG"), true, LOG_DEBUG);
		return VIRUS_FILE_TYPE_MPEG;
	}
	if (memcmp(&bHeaderBuff[0],bVOBSig,sizeof(bVOBSig)) == 0x00)
	{
		AddLogEntry(L">>>>> FILE-TYPE  : %s : %s", pScanInfo->szFileToScan, _T("VIRUS_FILE_TYPE_VOB"), true, LOG_DEBUG);
		return VIRUS_FILE_TYPE_VOB;
	}
	if (memcmp(&bHeaderBuff[0x04],bM4VSig,sizeof(bM4VSig)) == 0x00)
	{
		AddLogEntry(L">>>>> FILE-TYPE  : %s : %s", pScanInfo->szFileToScan, _T("VIRUS_FILE_TYPE_M4V"), true, LOG_DEBUG);
		return VIRUS_FILE_TYPE_M4V;
	}
	if (memcmp(&bHeaderBuff[0x04],bM4ASig,sizeof(bM4ASig)) == 0x00)
	{
		AddLogEntry(L">>>>> FILE-TYPE  : %s : %s", pScanInfo->szFileToScan, _T("VIRUS_FILE_TYPE_M4A"), true, LOG_DEBUG);
		return VIRUS_FILE_TYPE_M4A;
	}
	if (memcmp(&bHeaderBuff[0x04],bM4A_2Sig,sizeof(bM4A_2Sig)) == 0x00)
	{
		AddLogEntry(L">>>>> FILE-TYPE  : %s : %s", pScanInfo->szFileToScan, _T("VIRUS_FILE_TYPE_M4A_2"), true, LOG_DEBUG);
		return VIRUS_FILE_TYPE_M4A_2;
	}
	if (memcmp(&bHeaderBuff[0],bWEBMSig,sizeof(bWEBMSig)) == 0x00)
	{
		AddLogEntry(L">>>>> FILE-TYPE  : %s : %s", pScanInfo->szFileToScan, _T("VIRUS_FILE_TYPE_WEBM"), true, LOG_DEBUG);
		return VIRUS_FILE_TYPE_WEBM;
	}
	if (memcmp(&bHeaderBuff[0],bMSUSig,sizeof(bMSUSig)) == 0x00)
	{
		AddLogEntry(L">>>>> FILE-TYPE  : %s : %s", pScanInfo->szFileToScan, _T("VIRUS_FILE_TYPE_MSU"), true, LOG_DEBUG);
		return VIRUS_FILE_TYPE_MSU;
	}
	if (memcmp(&bHeaderBuff[0],bLIBSig,sizeof(bLIBSig)) == 0x00)
	{
		AddLogEntry(L">>>>> FILE-TYPE  : %s : %s", pScanInfo->szFileToScan, _T("VIRUS_FILE_TYPE_LIB"), true, LOG_DEBUG);
		return VIRUS_FILE_TYPE_LIB;
	}
	if (memcmp(&bHeaderBuff[0],bWMFSig,sizeof(bWMFSig)) == 0x00)
	{
		AddLogEntry(L">>>>> FILE-TYPE  : %s : %s", pScanInfo->szFileToScan, _T("VIRUS_FILE_TYPE_WMF"), true, LOG_DEBUG);
		return VIRUS_FILE_TYPE_WMF;
	}
	if (memcmp(&bHeaderBuff[0],bAVISig,sizeof(bAVISig)) == 0x00)
	{
		AddLogEntry(L">>>>> FILE-TYPE  : %s : %s", pScanInfo->szFileToScan, _T("VIRUS_FILE_TYPE_AVI"), true, LOG_DEBUG);
		return VIRUS_FILE_TYPE_AVI;
	}
	if (memcmp(&bHeaderBuff[0],bPREFETCHSig,sizeof(bPREFETCHSig)) == 0x00)
	{
		AddLogEntry(L">>>>> FILE-TYPE  : %s : %s", pScanInfo->szFileToScan, _T("VIRUS_FILE_TYPE_PREF"), true, LOG_DEBUG);
		return VIRUS_FILE_TYPE_PREF;
	}
	if (memcmp(&bHeaderBuff[0],bPNFSig,sizeof(bPNFSig)) == 0x00)
	{
		AddLogEntry(L">>>>> FILE-TYPE  : %s : %s", pScanInfo->szFileToScan, _T("VIRUS_FILE_TYPE_PNF"), true, LOG_DEBUG);
		return VIRUS_FILE_TYPE_PNF;
	}
	if (memcmp(&bHeaderBuff[0],bMNGSig,sizeof(bMNGSig)) == 0x00)
	{
		AddLogEntry(L">>>>> FILE-TYPE  : %s : %s", pScanInfo->szFileToScan, _T("VIRUS_FILE_TYPE_MNG"), true, LOG_DEBUG);
		return VIRUS_FILE_TYPE_MNG;
	}
	if (memcmp(&bHeaderBuff[0],bDCTSig,sizeof(bDCTSig)) == 0x00)
	{
		AddLogEntry(L">>>>> FILE-TYPE  : %s : %s", pScanInfo->szFileToScan, _T("VIRUS_FILE_TYPE_DCT"), true, LOG_DEBUG);
		return VIRUS_FILE_TYPE_DCT;
	}
	if (memcmp(&bHeaderBuff[0],bSAVSig,sizeof(bSAVSig)) == 0x00)
	{
		AddLogEntry(L">>>>> FILE-TYPE  : %s : %s", pScanInfo->szFileToScan, _T("VIRUS_FILE_TYPE_SAV"), true, LOG_DEBUG);
		return VIRUS_FILE_TYPE_SAV;
	}
	if (memcmp(&bHeaderBuff[0],bTLBSig,sizeof(bTLBSig)) == 0x00)
	{
		AddLogEntry(L">>>>> FILE-TYPE  : %s : %s", pScanInfo->szFileToScan, _T("VIRUS_FILE_TYPE_TLB"), true, LOG_DEBUG);
		return VIRUS_FILE_TYPE_TLB;
	}
	if (memcmp(&bHeaderBuff[0],bRMVDSig,sizeof(bRMVDSig)) == 0x00)
	{
		AddLogEntry(L">>>>> FILE-TYPE  : %s : %s", pScanInfo->szFileToScan, _T("VIRUS_FILE_TYPE_RMVD"), true, LOG_DEBUG);
		return VIRUS_FILE_TYPE_RMVD;
	}
	if (memcmp(&bHeaderBuff[0],bAWBSig,sizeof(bAWBSig)) == 0x00)
	{
		AddLogEntry(L">>>>> FILE-TYPE  : %s : %s", pScanInfo->szFileToScan, _T("VIRUS_FILE_TYPE_AWB"), true, LOG_DEBUG);
		return VIRUS_FILE_TYPE_AWB;
	}
	if (memcmp(&bHeaderBuff[0x04],bMDBSig,sizeof(bMDBSig)) == 0x00)
	{
		AddLogEntry(L">>>>> FILE-TYPE  : %s : %s", pScanInfo->szFileToScan, _T("VIRUS_FILE_TYPE_MDB"), true, LOG_DEBUG);
		return VIRUS_FILE_TYPE_MDB;
	}
	
	if (memcmp(&bHeaderBuff[0x18],bMKVSig,sizeof(bMKVSig)) == 0x00)
	{
		AddLogEntry(L">>>>> FILE-TYPE  : %s : %s", pScanInfo->szFileToScan, _T("VIRUS_FILE_TYPE_MKV"), true, LOG_DEBUG);
		return VIRUS_FILE_TYPE_MKV;
	}
	if (memcmp(&bHeaderBuff[0x00],bDWGSig,sizeof(bDWGSig)) == 0x00)
	{
		AddLogEntry(L">>>>> FILE-TYPE  : %s : %s", pScanInfo->szFileToScan, _T("VIRUS_FILE_TYPE_DWG"), true, LOG_DEBUG);
		return VIRUS_FILE_TYPE_DWG;
	}
	if (memcmp(&bHeaderBuff[0x00],bPSDSig,sizeof(bPSDSig)) == 0x00)
	{
		AddLogEntry(L">>>>> FILE-TYPE  : %s : %s", pScanInfo->szFileToScan, _T("VIRUS_FILE_TYPE_PSD"), true, LOG_DEBUG);
		return VIRUS_FILE_TYPE_PSD;
	}
	if (memcmp(&bHeaderBuff[0x00],bMSTSig,sizeof(bMSTSig)) == 0x00)
	{
		TCHAR	szDumyPath[MAX_PATH] = {0x00};
		_tcscpy_s(szDumyPath,MAX_PATH,pScanInfo->szFileToScan);
		_tcslwr(szDumyPath);
		if (_tcsstr(szDumyPath,_T(".mst")) != nullptr)
		{
			AddLogEntry(L">>>>> FILE-TYPE  : %s : %s", pScanInfo->szFileToScan, _T("VIRUS_FILE_TYPE_MST"), true, LOG_DEBUG);
			return VIRUS_FILE_TYPE_MST;
		}
	}

//-------------------------------------------------------------

	if (memcmp(&bHeaderBuff[0],bELFSig,sizeof(bELFSig)) == 0x00)
	{
		AddLogEntry(L">>>>> FILE-TYPE  : %s : %s", pScanInfo->szFileToScan, _T("VIRUS_FILE_TYPE_ELF"), true, LOG_DEBUG);
		return VIRUS_FILE_TYPE_ELF;
	}
	if (memcmp(&bHeaderBuff[0],bRARSig,sizeof(bRARSig)) == 0x00)
	{
		AddLogEntry(L">>>>> FILE-TYPE  : %s : %s", pScanInfo->szFileToScan, _T("VIRUS_FILE_TYPE_RAR"), true, LOG_DEBUG);
		return VIRUS_FILE_TYPE_RAR;
	}
	if (memcmp(&bHeaderBuff[0],bZIPSig,sizeof(bZIPSig)) == 0x00)
	{
		if (_IsExcludeCompressedExtension(pScanInfo) > -1)
		{
			AddLogEntry(L">>>>> FILE-TYPE : %s : %s", pScanInfo->szFileToScan, _T("VIRUS_FILE_TYPE_ZIP (SKIP)"), true, LOG_DEBUG);
			return 0x00;  //Changes:- To skip files from extracting but they go for scanning 
		}
		AddLogEntry(L">>>>> FILE-TYPE  : %s : %s", pScanInfo->szFileToScan, _T("VIRUS_FILE_TYPE_ZIP"), true, LOG_DEBUG);
		return VIRUS_FILE_TYPE_ZIP;
	}
	if (memcmp(&bHeaderBuff[0],bZIPSig_1,sizeof(bZIPSig_1)) == 0x00)
	{
		AddLogEntry(L">>>>> FILE-TYPE  : %s : %s", pScanInfo->szFileToScan, _T("VIRUS_FILE_TYPE_ZIP"), true, LOG_DEBUG);
		return VIRUS_FILE_TYPE_ZIP;
	}
	
	if (memcmp(&bHeaderBuff[0],bMSSZDDSig,sizeof(bMSSZDDSig)) == 0x00)
	{
		AddLogEntry(L">>>>> FILE-TYPE  : %s : %s", pScanInfo->szFileToScan, _T("VIRUS_FILE_TYPE_MSSZDD"), true, LOG_DEBUG);
		return VIRUS_FILE_TYPE_MSSZDD;
	}
	if (memcmp(&bHeaderBuff[0],bMSCABSig,sizeof(bMSCABSig)) == 0x00)
	{
		AddLogEntry(L">>>>> FILE-TYPE  : %s : %s", pScanInfo->szFileToScan, _T("VIRUS_FILE_TYPE_MSCAB"), true, LOG_DEBUG);
		return VIRUS_FILE_TYPE_MSCAB;
	}
	if (memcmp(&bHeaderBuff[0],bCryptCFFSig,sizeof(bCryptCFFSig)) == 0x00 && bHeaderBuff[0x10] == 0xB2 && bHeaderBuff[0x11] == 0xA5)
	{
		AddLogEntry(L">>>>> FILE-TYPE  : %s : %s", pScanInfo->szFileToScan, _T("VIRUS_FILE_TYPE_CRYPTCFF"), true, LOG_DEBUG);
		return VIRUS_FILE_TYPE_CRYPTCFF;
	}
	if (memcmp(&bHeaderBuff[0],bMSCHMSig,sizeof(bMSCHMSig)) == 0x00)
	{
		AddLogEntry(L">>>>> FILE-TYPE  : %s : %s", pScanInfo->szFileToScan, _T("VIRUS_FILE_TYPE_MSCHM"), true, LOG_DEBUG);
		return VIRUS_FILE_TYPE_MSCHM;
	}
	if (memcmp(&bHeaderBuff[0],bGIFSig,sizeof(bGIFSig)) == 0x00)
	{
		AddLogEntry(L">>>>> FILE-TYPE  : %s : %s", pScanInfo->szFileToScan, _T("VIRUS_FILE_TYPE_GIF"), true, LOG_DEBUG);
		return VIRUS_FILE_TYPE_GIF;
	}
	if (memcmp(&bHeaderBuff[0],bBMPSig,sizeof(bBMPSig)) == 0x00)
	{
		AddLogEntry(L">>>>> FILE-TYPE  : %s : %s", pScanInfo->szFileToScan, _T("VIRUS_FILE_TYPE_BMP"), true, LOG_DEBUG);
		return VIRUS_FILE_TYPE_BMP;
	}
	if (memcmp(&bHeaderBuff[0],bJPEGSig,sizeof(bJPEGSig)) == 0x00)
	{
		AddLogEntry(L">>>>> FILE-TYPE  : %s : %s", pScanInfo->szFileToScan, _T("VIRUS_FILE_TYPE_JPEG"), true, LOG_DEBUG);
		return VIRUS_FILE_TYPE_JPEG;
	}
	if (memcmp(&bHeaderBuff[0],bPNGSig,sizeof(bPNGSig)) == 0x00)
	{
		AddLogEntry(L">>>>> FILE-TYPE  : %s : %s", pScanInfo->szFileToScan, _T("VIRUS_FILE_TYPE_PNG"), true, LOG_DEBUG);
		return VIRUS_FILE_TYPE_PNG;
	}
	if (memcmp(&bHeaderBuff[0],bMaxEMLSig,sizeof(bMaxEMLSig)) == 0x00)
	{
		AddLogEntry(L">>>>> FILE-TYPE  : %s : %s", pScanInfo->szFileToScan, _T("VIRUS_FILE_TYPE_EML"), true, LOG_DEBUG);
		return VIRUS_FILE_TYPE_EML;
	}

	if (memcmp(&bHeaderBuff[6],bJPEGSig_1,sizeof(bJPEGSig_1)) == 0x00)
	{
		AddLogEntry(L">>>>> FILE-TYPE  : %s : %s", pScanInfo->szFileToScan, _T("VIRUS_FILE_TYPE_JPEG"), true, LOG_DEBUG);
		return VIRUS_FILE_TYPE_JPEG;
	}
	if (memcmp(&bHeaderBuff[6],bJPEGSig_2,sizeof(bJPEGSig_2)) == 0x00)
	{
		AddLogEntry(L">>>>> FILE-TYPE  : %s : %s", pScanInfo->szFileToScan, _T("VIRUS_FILE_TYPE_JPEG"), true, LOG_DEBUG);
		return VIRUS_FILE_TYPE_JPEG;
	}
	if (memcmp(&bHeaderBuff[8],bSISSig,sizeof(bSISSig)) == 0x00)
	{
		AddLogEntry(L">>>>> FILE-TYPE  : %s : %s", pScanInfo->szFileToScan, _T("VIRUS_FILE_TYPE_SIS"), true, LOG_DEBUG);
		return VIRUS_FILE_TYPE_SIS;
	}

	if (memcmp(&bHeaderBuff[0],bPDFSig,sizeof(bPDFSig)) == 0x00)
	{
		AddLogEntry(L">>>>> FILE-TYPE  : %s : %s", pScanInfo->szFileToScan, _T("VIRUS_FILE_TYPE_PDF"), true, LOG_DEBUG);
		return VIRUS_FILE_TYPE_PDF;
	}
	if (memcmp(&bHeaderBuff[0],bMSISig,sizeof(bMSISig)) == 0x00)
	{
		AddLogEntry(L">>>>> FILE-TYPE  : %s : %s", pScanInfo->szFileToScan, _T("VIRUS_FILE_TYPE_MSI"), true, LOG_DEBUG);
		return VIRUS_FILE_TYPE_MSI;
	}
	if (memcmp(&bHeaderBuff[0],bCURSig,sizeof(bCURSig)) == 0x00)
	{
		AddLogEntry(L">>>>> FILE-TYPE  : %s : %s", pScanInfo->szFileToScan, _T("VIRUS_FILE_TYPE_CUR"), true, LOG_DEBUG);
		return VIRUS_FILE_TYPE_CUR;
	}
	if (memcmp(&bHeaderBuff[0],bICONSig,sizeof(bICONSig)) == 0x00)
	{
		AddLogEntry(L">>>>> FILE-TYPE  : %s : %s", pScanInfo->szFileToScan, _T("VIRUS_FILE_TYPE_ICON"), true, LOG_DEBUG);
		return VIRUS_FILE_TYPE_ICON;
	}
	
	if (memcmp(&bHeaderBuff[0], bUBSig_1, sizeof(bUBSig_1)) == 0x00 || memcmp(&bHeaderBuff[0], bUBSig_2, sizeof(bUBSig_2)) == 0x00)
	{
		AddLogEntry(L">>>>> FILE-TYPE  : %s : %s", pScanInfo->szFileToScan, _T("VIRUS_FILE_TYPE_UB"), true, LOG_DEBUG);
		return VIRUS_FILE_TYPE_UB;
	}
	//Mac Detection 26-Sept-2015 Ravi
	if (memcmp(&bHeaderBuff[0], bUBSig_Class_1, sizeof(bUBSig_Class_1)) == 0x00 || memcmp(&bHeaderBuff[0], bUBSig_Class_2, sizeof(bUBSig_Class_2)) == 0x00)
	{
		AddLogEntry(L">>>>> FILE-TYPE  : %s : %s", pScanInfo->szFileToScan, _T("VIRUS_FILE_TYPE_UB_CLASS"), true, LOG_DEBUG);
		return VIRUS_FILE_TYPE_UB_CLASS;
	}
	if (memcmp(&bHeaderBuff[0], bJCLASS, sizeof(bJCLASS)) == 0x00)
	{
		AddLogEntry(L">>>>> FILE-TYPE  : %s : %s", pScanInfo->szFileToScan, _T("VIRUS_FILE_TYPE_JCLASS"), true, LOG_DEBUG);
		return VIRUS_FILE_TYPE_JCLASS;
	}
	if (memcmp(&bHeaderBuff[0], bIOS_DEB, sizeof(bIOS_DEB)) == 0x00)
	{
		AddLogEntry(L">>>>> FILE-TYPE  : %s : %s", pScanInfo->szFileToScan, _T("VIRUS_FILE_TYPE_IOS_DEB"), true, LOG_DEBUG);
		return VIRUS_FILE_TYPE_IOS_DEB;
	}
	if (memcmp(&bHeaderBuff[0],bBZipSig,sizeof(bBZipSig)) == 0x00)
	{
		AddLogEntry(L">>>>> FILE-TYPE  : %s : %s", pScanInfo->szFileToScan, _T("VIRUS_FILE_TYPE_BZ"), true, LOG_DEBUG);
		return VIRUS_FILE_TYPE_BZ;
	}
	if (memcmp(&bHeaderBuff[0],b7zSig,sizeof(b7zSig)) == 0x00)
	{
		AddLogEntry(L">>>>> FILE-TYPE  : %s : %s", pScanInfo->szFileToScan, _T("VIRUS_FILE_TYPE_7Z"), true, LOG_DEBUG);
		return VIRUS_FILE_TYPE_7Z;
	}

	if (memcmp(&bHeaderBuff[0],bMxQrtSig,sizeof(bMxQrtSig)) == 0x00)
	{
		AddLogEntry(L">>>>> FILE-TYPE  : %s : %s", pScanInfo->szFileToScan, _T("VIRUS_FILE_TYPE_MXQRT"), true, LOG_DEBUG);
		return VIRUS_FILE_TYPE_MXQRT;
	}

	if (memcmp(&bHeaderBuff[0],bWMAHeader,sizeof(bWMAHeader)) == 0x00)
	{
		AddLogEntry(L">>>>> FILE-TYPE  : %s : %s", pScanInfo->szFileToScan, _T("VIRUS_FILE_TYPE_WMA"), true, LOG_DEBUG);
		return VIRUS_FILE_TYPE_WMA;
	}

	if ( (memcmp(&bHeaderBuff[0], bMAC_O_32_BE, sizeof(bMAC_O_32_BE)) == 0x00)
		|| (memcmp(&bHeaderBuff[0], bMAC_O_32_LE, sizeof(bMAC_O_32_LE)) == 0x00) 
		|| (memcmp(&bHeaderBuff[0], bMAC_O_64_BE, sizeof(bMAC_O_64_BE)) == 0x00)
		|| (memcmp(&bHeaderBuff[0], bMAC_O_64_LE, sizeof(bMAC_O_64_LE)) == 0x00)
		|| (memcmp(&bHeaderBuff[0], bMAC_MetaSig2, sizeof(bMAC_MetaSig2)) == 0x00)
		|| (memcmp(&bHeaderBuff[0], bMAC_MetaSigLarge, sizeof(bMAC_MetaSigLarge)) == 0x00))
	{
		AddLogEntry(L">>>>> FILE-TYPE  : %s : %s", pScanInfo->szFileToScan, _T("VIRUS_FILE_TYPE_MAC"), true, LOG_DEBUG);
		return VIRUS_FILE_TYPE_MAC;
	}
	//Mac

	for(WORD wSec = 0; wSec < pScanInfo->pMaxPEFile->m_stPEHeader.NumberOfSections; wSec++)
	{
		if(memcmp(pScanInfo->pMaxPEFile->m_stSectionHeader[wSec].Name, "_winzip_", 8) == 0)
		{
			AddLogEntry(L">>>>> FILE-TYPE  SFX : %s : %s", pScanInfo->szFileToScan, _T("VIRUS_FILE_TYPE_ZIP"), true, LOG_DEBUG);
			return VIRUS_FILE_TYPE_ZIP;
		}
	}
	
	WORD wNoOfSections = pScanInfo->pMaxPEFile->m_stPEHeader.NumberOfSections;
	DWORD dwStartOfOverlay = pScanInfo->pMaxPEFile->m_stSectionHeader[wNoOfSections - 1].PointerToRawData + pScanInfo->pMaxPEFile->m_stSectionHeader[wNoOfSections - 1].SizeOfRawData;
	
	if(pScanInfo->pMaxPEFile->ReadBuffer(bHeaderBuff, dwStartOfOverlay, 50, 50))
	{
		for(DWORD dwOffset = 0; dwOffset < (50 - sizeof(bRARSig)); dwOffset++)
		{
			if (memcmp(&bHeaderBuff[dwOffset], bRARSig, sizeof(bRARSig)) == 0x00)
			{
				AddLogEntry(L">>>>> FILE-TYPE SFX : %s : %s", pScanInfo->szFileToScan, _T("VIRUS_FILE_TYPE_RAR"), true, LOG_DEBUG);
				return VIRUS_FILE_TYPE_RAR;
			}
		}
	}

	if(pScanInfo->pMaxPEFile->m_dwFileSize > 0x200)
	{
		if(pScanInfo->pMaxPEFile->ReadBuffer(bHeaderBuff, (pScanInfo->pMaxPEFile->m_dwFileSize - 0x200), 0x04, 0x04))
		{
			if(memcmp(&bHeaderBuff[0x00], bDMGCollySig, sizeof(bDMGCollySig)) == 0x00)
			{
				AddLogEntry(L">>>>> FILE-TYPE DMG : %s : %s", pScanInfo->szFileToScan, _T("VIRUS_FILE_TYPE_DMG"), true, LOG_DEBUG);
				return VIRUS_FILE_TYPE_DMG;
			}
		}
	}

	///NULLSoft
	if(pScanInfo->pMaxPEFile->m_stPEHeader.NumberOfSections > 3)
	{
		if(memcmp(pScanInfo->pMaxPEFile->m_stSectionHeader[0x03].Name, ".ndata", 7) == 0 && (pScanInfo->pMaxPEFile->m_stSectionHeader[0x03].SizeOfRawData == 0x00) && (pScanInfo->pMaxPEFile->m_stSectionHeader[0x03].PointerToRawData == 0))
		{ 
			DWORD dwOverlayStart = 0x0;
			//EFBEADDE4E756C6C736F6674496E7374B9510000 : ....NullsoftInst
			const BYTE bySign[] = {0xEF,0xBE,0xAD,0xDE,0x4E,0x75,0x6C,0x6C,0x73,0x6F,0x66,0x74,0x49,0x6E,0x73,0x74};
			dwOverlayStart = pScanInfo->pMaxPEFile->m_stSectionHeader[pScanInfo->pMaxPEFile->m_stPEHeader.NumberOfSections - 1].PointerToRawData + pScanInfo->pMaxPEFile->m_stSectionHeader[pScanInfo->pMaxPEFile->m_stPEHeader.NumberOfSections - 1].SizeOfRawData;
			if(dwOverlayStart != 0)
			{			
				BYTE bNSISHeaderBuff[0x300]={0x00};
				if(pScanInfo->pMaxPEFile->ReadBuffer(bNSISHeaderBuff,dwOverlayStart,0x300,0x30))
				{
					for(int iIndex = 0x4; iIndex < 0x2D0; iIndex++)
					{						
						if(memcmp(&bNSISHeaderBuff[iIndex], bySign, sizeof(bySign)) == 0x00)
						{
							AddLogEntry(L">>>>> FILE-TYPE DMG : %s : %s", pScanInfo->szFileToScan, _T("VIRUS_FILE_TYPE_NSIS"), true, LOG_DEBUG);
							return VIRUS_FILE_TYPE_NSIS;
						}
					}

				}
			}	
		}
	}


	if (m_dwActmonScan == 0x01)
	{
		CString		csFilePath;
		csFilePath.Format(L"%s", pScanInfo->szFileToScan);
		csFilePath.MakeLower();
		csFilePath.Append(L";");
		if (csFilePath.Find(L".") == -1)
		{
			AddLogEntry(L">>>>> FILE-TYPE  : %s : %s", pScanInfo->szFileToScan, _T("EXL_SCRIPT"), true, LOG_DEBUG);
			return 0x00;
		}
		if (csFilePath.Find(L".vbs;") != -1 || csFilePath.Find(L".js;") != -1 || csFilePath.Find(L".php;") != -1 || csFilePath.Find(L".asp;") != -1)
		{
			AddLogEntry(L">>>>> FILE-TYPE : %s : %s", pScanInfo->szFileToScan, _T("VIRUS_FILE_TYPE_SCRIPT"), true, LOG_DEBUG);
			return VIRUS_FILE_TYPE_SCRIPT;
		}
	}
	else
	{
		CScriptSig	objScript;
		if (objScript.IsItValidScript(pScanInfo->pMaxPEFile))
		{
			CString		csFilePath;
			csFilePath.Format(L"%s", pScanInfo->szFileToScan);
			csFilePath.MakeLower();
			if ((csFilePath.Find(L".") == -1 && m_dwActmonScan == 0x01) || csFilePath.Find(L"\\local\\microsoft\\") != -1 || csFilePath.Find(L".txt") != -1)
			{
				AddLogEntry(L">>>>> FILE-TYPE  : %s : %s", pScanInfo->szFileToScan, _T("EXL_SCRIPT"), true, LOG_DEBUG);
				return 0x00;
			}
			AddLogEntry(L">>>>> FILE-TYPE : %s : %s", pScanInfo->szFileToScan, _T("VIRUS_FILE_TYPE_SCRIPT"), true, LOG_DEBUG);
			return VIRUS_FILE_TYPE_SCRIPT;
		}
	}
	
		
	AddLogEntry(L">>>>> FILE-TYPE  : %s : %s", pScanInfo->szFileToScan, _T("0x00"), true, LOG_DEBUG);
	return 0x00;
}

void CMaxScanner::SetAutomationLabStatus(bool bAutomationLab)
{
	if(m_pThreatManager)
	{
		m_pThreatManager->m_bAutomationLab = bAutomationLab;
	}
}

bool CMaxScanner::ScanAlternateDataStream(PMAX_SCANNER_INFO pScanInfo)
{
	if (m_bADSScan == false)
	{
		return false;
	}
	if(!pfnNtQueryInformationFile)
	{
		return false;
	}

	DWORD dwStartTime = GetTickCount();

	bool bReturnVal = false;
	LPBYTE pInfoBlock = NULL;

	__try
	{
		ULONG uInfoBlockSize = 0;
		IO_STATUS_BLOCK ioStatus = {0};
		HANDLE hFile = INVALID_HANDLE_VALUE;
		WCHAR wszStreamName[MAX_PATH] = {0};
		NTSTATUS status = S_FALSE;

		hFile = ::CreateFile(pScanInfo->szFileToScan, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);

		if(hFile == INVALID_HANDLE_VALUE)
		{
			m_dwTotalADSScanTime += (GetTickCount() - dwStartTime);
			return false;
		}

		do 
		{
			uInfoBlockSize += (sizeof(FILE_STREAM_INFORMATION) * 2);		// 2 Blocks (We always need minimum 2 blocks to check if ads entry is present)
			if(pInfoBlock != NULL)
			{
				delete [] pInfoBlock;
			}

			pInfoBlock = NULL;
			pInfoBlock = new BYTE [uInfoBlockSize];

			((PFILE_STREAM_INFORMATION)pInfoBlock)->StreamNameLength = 0;

			status = pfnNtQueryInformationFile(hFile, &ioStatus, (LPVOID)pInfoBlock, uInfoBlockSize, (FILE_INFORMATION_CLASS)FileStreamInformation);

		} while ((status == STATUS_SINGLE_STEP) || (status == STATUS_BUFFER_OVERFLOW));

		if(hFile != INVALID_HANDLE_VALUE)
		{
			::CloseHandle(hFile);
		}

		if(uInfoBlockSize != (sizeof(FILE_STREAM_INFORMATION) * 2))
		{
			TCHAR szTest[MAX_PATH*2] = {0};
			swprintf_s(szTest, MAX_PATH*2, L">>>>> ADS BLOCK SIZE: %d, STATUS: 0x%08X, FileName: %s", uInfoBlockSize, status, pScanInfo->szFileToScan);
			AddLogEntry(szTest, 0, 0, true, LOG_DEBUG);
		}

		PFILE_STREAM_INFORMATION pStreamInfo = (PFILE_STREAM_INFORMATION)(LPVOID)pInfoBlock;
		for(;;) 
		{
			if(pStreamInfo->StreamNameLength == 0) 
			{
				break;
			}

			if(pStreamInfo->StreamSize.QuadPart > 0) 
			{
				memcpy(wszStreamName, pStreamInfo->StreamName, pStreamInfo->StreamNameLength);
				wszStreamName[pStreamInfo->StreamNameLength / sizeof(WCHAR)] = L'\0';

				if(wcscmp(wszStreamName, _T(":")) && wcscmp(wszStreamName, _T("::$DATA"))
					&& wcscmp(wszStreamName, _T(":Zone.Identifier:$DATA"))
					&& wcscmp(wszStreamName, _T(":encryptable:$DATA")))
				{
					*_tcsrchr(wszStreamName, L':') = L'\0';
					m_iTotalNoOfADSFiles++;
					PMAX_SCANNER_INFO pLastScanInfo = pScanInfo;
					while(pLastScanInfo->pNextScanInfo)
					{
						pLastScanInfo = pLastScanInfo->pNextScanInfo;
					}
					PMAX_SCANNER_INFO pScanInfoADSEntry = new MAX_SCANNER_INFO;
					memset(pScanInfoADSEntry, 0, sizeof(MAX_SCANNER_INFO));
					pLastScanInfo->FreeNextScanInfo = true;
					pLastScanInfo->pNextScanInfo = pScanInfoADSEntry;
					pScanInfoADSEntry->AutoQuarantine = pScanInfo->AutoQuarantine;
					_tcscpy_s(pScanInfoADSEntry->szContainerFileName, pScanInfo->szFileToScan);
					_tcscpy_s(pScanInfoADSEntry->szFileToScan, pScanInfo->szFileToScan);
					_tcscat_s(pScanInfoADSEntry->szFileToScan, wszStreamName);

					AddLogEntry(L"##### ADS-ENTRY  : %s", pScanInfoADSEntry->szFileToScan, NULL, true, LOG_DEBUG);

					bReturnVal = _ScanFileContent(pScanInfoADSEntry, 1);

					if(bReturnVal)
					{
						_CloseMaxPEFile(pScanInfo, false);
						PMAX_SCANNER_INFO pNextScanInfo = pScanInfo->pNextScanInfo;
						memcpy_s(pScanInfo, sizeof(MAX_SCANNER_INFO), pScanInfoADSEntry, sizeof(MAX_SCANNER_INFO));
						pScanInfo->pNextScanInfo = pNextScanInfo;
						pScanInfo->FreeNextScanInfo = true;
						_CloseMaxPEFile(pScanInfo, true);
						break;
					}
				}
			}

			if(pStreamInfo->NextEntryOffset == 0)
			{
				break;
			}
			pStreamInfo = (PFILE_STREAM_INFORMATION)((LPBYTE)pStreamInfo + pStreamInfo->NextEntryOffset);
		}
	}
	__except(CMaxExceptionFilter::Filter(GetExceptionCode(), GetExceptionInformation(), _T("Exception caught Scanner::ScanAlternateDataStream(1)"), (pScanInfo->IsChildFile ? pScanInfo->szContainerFileName : pScanInfo->szFileToScan)))
	{
		bReturnVal = false;
	}

	__try
	{
		if(pInfoBlock)
		{
			delete [] pInfoBlock;
			pInfoBlock = NULL;
		}
	}
	__except(CMaxExceptionFilter::Filter(GetExceptionCode(), GetExceptionInformation(), _T("Exception caught Scanner::ScanAlternateDataStream(2)"), (pScanInfo->IsChildFile ? pScanInfo->szContainerFileName : pScanInfo->szFileToScan)))
	{
		bReturnVal = false;
	}

	m_dwTotalADSScanTime += (GetTickCount() - dwStartTime);
	return bReturnVal;
}

void CMaxScanner::_UnzipToFolderSEH(LPCTSTR szFileToScan, LPTSTR szExtractedPath)
{
	__try
	{
		_UnzipToFolder(szFileToScan, szExtractedPath);
	}
	__except(CMaxExceptionFilter::Filter(GetExceptionCode(), GetExceptionInformation(), _T("Exception caught Scanner::_UnzipToFolderSEH()"), szFileToScan))
	{
		AddLogEntry(L"##### UNZIPFAILED: (2) %s, Extract To: %s", szFileToScan, szExtractedPath, true, LOG_DEBUG);
	}
}

void CMaxScanner::_UnzipToFolder(LPCTSTR szFileToScan, LPTSTR szExtractedPath)
{
	try
	{
		CString sz;
		CZipArchive objArchive;
		objArchive.Open(szFileToScan, CZipArchive::openReadOnly, 0);
		int iCount = objArchive.GetNoEntries();

		if(iCount > 0)
		{
			TCHAR szTempFolderPath[MAX_PATH] = {0};
			// Get temp folder path where to extract the files
			GetModuleFileName(NULL, szTempFolderPath, MAX_PATH);
			WCHAR *cExtPtr = wcsrchr(szTempFolderPath, '\\');
			if(cExtPtr) *cExtPtr = '\0';
			swprintf_s(szExtractedPath, MAX_PATH, _T("%s\\TempFolder\\%08x-%05d-%05d\\"), 
									szTempFolderPath, GetTickCount(), GetCurrentThreadId(), 
									GetCurrentProcessId());

			AddLogEntry(L"##### EXTRACT-ZIP: %s - %s", szFileToScan, szExtractedPath, true, LOG_DEBUG);
		}

		for(int i=0; i < iCount; i++)
		{
			CZipFileHeader fh;
			objArchive.GetFileInfo(fh, (WORD)i);
			sz = (LPCTSTR)fh.GetFileName();
			CString csFullPath(szExtractedPath);
			int iPos = sz.ReverseFind('\\');
			if(iPos != -1)
			{
				csFullPath += sz.Left(iPos + 1);
				sz = sz.Mid(iPos + 1);
			}
			if(objArchive.ExtractFile((WORD)i, csFullPath, false, sz))
				AddLogEntry(L">>>>> EXTRACT-SUC: %s%s", csFullPath, sz, true, LOG_DEBUG);
			else
				AddLogEntry(L"##### EXTRACT-FAL: %s%s", csFullPath, sz, true, LOG_DEBUG);
		}
		
		objArchive.Close();
		
		if(iCount > 0)
		{
			WCHAR *cExtPtr = wcsrchr(szExtractedPath, '\\');
			if(cExtPtr) *cExtPtr = '\0';
		}
	}
	catch(...)
	{
		AddLogEntry(L"##### UNZIPFAILED: (1) %s, Extract To: %s", szFileToScan, szExtractedPath, true, LOG_DEBUG);
	}
}

void CMaxScanner::_ExtractSISToFolderSEH(LPCTSTR szFileToScan, LPTSTR szExtractedPath)
{
	__try
	{
		_ExtractSISToFolder(szFileToScan, szExtractedPath);
	}
	__except(CMaxExceptionFilter::Filter(GetExceptionCode(), GetExceptionInformation(), _T("Exception caught Scanner::_ExtractSISToFolderSEH()"), szFileToScan))
	{
		AddLogEntry(L"##### UNZIPSIS-F : (2) %s, Extract To: %s", szFileToScan, szExtractedPath, true, LOG_DEBUG);
	}
}

void CMaxScanner::_ExtractSISToFolder(LPCTSTR szFileToScan, LPTSTR szExtractedPath)
{
	try
	{
		TCHAR szTempFolderPath[MAX_PATH] = {0};
		// Get temp folder path where to extract the files
		GetModuleFileName(NULL, szTempFolderPath, MAX_PATH);
		WCHAR *cExtPtr = wcsrchr(szTempFolderPath, '\\');
		if(cExtPtr) *cExtPtr = '\0';
		swprintf_s(szExtractedPath, MAX_PATH, _T("%s\\TempFolder\\%08x-%05d-%05d\\"), 
								szTempFolderPath, GetTickCount(), GetCurrentThreadId(), 
								GetCurrentProcessId());
		
		_wmkdir(szExtractedPath);

		AddLogEntry(L"##### EXTRACT-SIS: %s - %s", szFileToScan, szExtractedPath, true, LOG_DEBUG);

		CZipArchive objArchive;
		objArchive.ExtractSIS(szFileToScan, szExtractedPath);

		cExtPtr = wcsrchr(szExtractedPath, '\\');
		if(cExtPtr) *cExtPtr = '\0';
	}
	catch(...)
	{
		AddLogEntry(L"##### UNZIPSIS-F : (1) %s, Extract To: %s", szFileToScan, szExtractedPath, true, LOG_DEBUG);
	}
}

bool CMaxScanner::_LoadEMLParser()
{
	if(m_hEMLParser == NULL)
	{
		m_hEMLParser = LoadLibrary(_T("AuMailScanner.dll"));
		if(m_hEMLParser == NULL)
		{
			return false;
		}

		m_lpfnEMLUnPack = (LPFNEMLParser) GetProcAddress(m_hEMLParser, "UnPackFile");
		if(m_lpfnEMLUnPack == NULL)
		{
			return false;
		}

		m_lpfnEMLRePack = (LPFNEMLRePack) GetProcAddress(m_hEMLParser, "RePackFile");
		if(m_lpfnEMLRePack == NULL)
		{
			return false;
		}

		m_lpfnInitMailDB = (LPFNInitMailDB) GetProcAddress(m_hEMLParser, "InitDB");
		if(m_lpfnInitMailDB == NULL)
		{
			return false;
		}

		m_lpfnDeInitMailDB = (LPFNDeInitMailDB) GetProcAddress(m_hEMLParser, "DeInitDB");
		if(m_lpfnDeInitMailDB == NULL)
		{
			return false;
		}
	}

	return true;
}

void CMaxScanner::_ExtractEMLToFolderSEH(PMAX_SCANNER_INFO pScanInfo, LPTSTR szExtractedPath)
{
	__try
	{
		_ExtractEMLToFolder(pScanInfo, szExtractedPath);
	}
	__except(CMaxExceptionFilter::Filter(GetExceptionCode(), GetExceptionInformation(), _T("Exception caught Scanner::_ExtractEMLToFolderSEH()"), pScanInfo->szFileToScan))
	{
		AddLogEntry(L"##### EXT-EML-F  : (2) %s, Extract To: %s", pScanInfo->szFileToScan, szExtractedPath, true, LOG_DEBUG);
	}
}

void CMaxScanner::_ExtractEMLToFolder(PMAX_SCANNER_INFO pScanInfo, LPTSTR szExtractedPath)
{
	try
	{
		if(!m_lpfnEMLUnPack)
		{
			return;
		}

		TCHAR szTempFolderPath[MAX_PATH] = {0};
		// Get temp folder path where to extract the files
		GetModuleFileName(NULL, szTempFolderPath, MAX_PATH);
		WCHAR *cExtPtr = wcsrchr(szTempFolderPath, '\\');
		if(cExtPtr) *cExtPtr = '\0';
		swprintf_s(szExtractedPath, MAX_PATH, _T("%s\\TempFolder\\%08x-%05d-%05d\\"), 
								szTempFolderPath, GetTickCount(), GetCurrentThreadId(), 
								GetCurrentProcessId());
		
		_wmkdir(szExtractedPath);

		AddLogEntry(L"##### EXTRACT-EML: %s - %s", pScanInfo->szFileToScan, szExtractedPath, true, LOG_DEBUG);
		int iStatus = m_lpfnEMLUnPack(pScanInfo->szFileToScan, szExtractedPath, pScanInfo->szFreshFile, pScanInfo->szBackupFileName);
		if(iStatus == 1)	// Success??
		{
			cExtPtr = wcsrchr(szExtractedPath, '\\');
			if(cExtPtr) *cExtPtr = '\0';
		}
		else
		{
			m_oDirectoryManager.MaxDeleteDirectory(szExtractedPath, true);
			szExtractedPath[0] = '\0';
		}
	}
	catch(...)
	{
		AddLogEntry(L"##### EXT-EML-F  : (1) %s, Extract To: %s", pScanInfo->szFileToScan, szExtractedPath, true, LOG_DEBUG);
	}
}

void CMaxScanner::_RePackEMLToFolderSEH(PMAX_SCANNER_INFO pScanInfo, LPTSTR szExtractedPath)
{
	__try
	{
		_RePackEMLToFolder(pScanInfo, szExtractedPath);
	}
	__except(CMaxExceptionFilter::Filter(GetExceptionCode(), GetExceptionInformation(), _T("Exception caught Scanner::_RePackEMLToFolderSEH()"), pScanInfo->szFileToScan))
	{
		AddLogEntry(L"##### PCK-EML-F  : (2) %s, Extract To: %s", pScanInfo->szFileToScan, szExtractedPath, true, LOG_DEBUG);
	}
}

void CMaxScanner::_RePackEMLToFolder(PMAX_SCANNER_INFO pScanInfo, LPTSTR szExtractedPath)
{
	try
	{
		if(!m_lpfnEMLRePack)
		{
			return;
		}

		int iStatus = m_lpfnEMLRePack(pScanInfo->szFileToScan, szExtractedPath);
		if(iStatus == 1)
			AddLogEntry(L">>>>> REPCK-EML-S: %s, Repack: %s", pScanInfo->szFileToScan, szExtractedPath, true, LOG_DEBUG);
		else
			AddLogEntry(L"##### REPCK-EML-F: %s, Repack: %s", pScanInfo->szFileToScan, szExtractedPath, true, LOG_DEBUG);

		if(!pScanInfo->IsChildFile)	// do not clean up this folder!
		{
			m_oDirectoryManager.MaxDeleteDirectory(szExtractedPath, true);
			szExtractedPath[0] = '\0';
		}
	}
	catch(...)
	{
		AddLogEntry(L"##### PCK-EML-F  : (1) %s, Extract To: %s", pScanInfo->szFileToScan, szExtractedPath, true, LOG_DEBUG);
	}
}

void CMaxScanner::_UnloadEMLParser()
{
	if(m_hEMLParser)
	{
		if(m_lpfnDeInitMailDB)
		{
			//calling Exported function "DeInitDB" from AuMailScanner.dll
			m_lpfnDeInitMailDB();
		}
		FreeLibrary(m_hEMLParser);
		m_hEMLParser = NULL;
		m_lpfnEMLUnPack = NULL;
		m_lpfnEMLRePack = NULL;
		m_lpfnInitMailDB = NULL;
		m_lpfnDeInitMailDB = NULL;
	}
}

bool CMaxScanner::ReloadMailScannerDB()
{
	if(m_lpfnDeInitMailDB == NULL || m_lpfnInitMailDB == NULL)
	{
		return false;
	}
	if(m_lpfnDeInitMailDB)
	{
		m_lpfnDeInitMailDB();
	}
	if(m_lpfnInitMailDB)
	{
		CRegistry oReg;
		CString csMaxDBPath;
		oReg.Get(CSystemInfo::m_csProductRegKey, CURRENT_MAX_DB_VAL, csMaxDBPath, HKEY_LOCAL_MACHINE);
		m_lpfnInitMailDB(csMaxDBPath, CSystemInfo::m_strAppPath);		
	}
	return true;
}

bool CMaxScanner::_CopyFileToTempFolder(PMAX_SCANNER_INFO pScanInfo)
{
	PMAX_SCANNER_INFO pScanInfoLockedEntry = new MAX_SCANNER_INFO;
	memset(pScanInfoLockedEntry, 0, sizeof(MAX_SCANNER_INFO));

	TCHAR szTempFilePath[MAX_PATH] = {0};
	GetModuleFileName(NULL, szTempFilePath, MAX_PATH);
	WCHAR *cExtPtr = wcsrchr(szTempFilePath, '\\');
	if(cExtPtr) *cExtPtr = '\0';
	cExtPtr = wcsrchr(pScanInfo->szFileToScan, '\\');
	if(cExtPtr) cExtPtr++; else cExtPtr = pScanInfo->szFileToScan;
	swprintf_s(pScanInfoLockedEntry->szFileToScan, MAX_PATH, _T("%s\\TempData\\%08x-%05d-%05d-%s"), 
							szTempFilePath, GetTickCount(), GetCurrentThreadId(), 
							GetCurrentProcessId(), cExtPtr);

	TCHAR szSrcFilePath[MAX_PATH] = {0};
	TCHAR szDestFilePath[MAX_PATH] = {0};

	if(pScanInfo->szFileToScan[0] != '\\')
		swprintf_s(szSrcFilePath, MAX_PATH, _T("\\??\\%s"), pScanInfo->szFileToScan);
	else
		swprintf_s(szSrcFilePath, MAX_PATH, _T("%s"), pScanInfo->szFileToScan);

	swprintf_s(szDestFilePath, MAX_PATH, _T("\\??\\%s"), pScanInfoLockedEntry->szFileToScan);

	AddLogEntry(L"##### LOCKED-FILE: %s : %s", szSrcFilePath, szDestFilePath, true, LOG_DEBUG);

	DWORD dwReturn = 0;
	HANDLE hFile = CreateFile(ACTMON_DRIVE_SYMBOLIC, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);

	COPYINFO oCopyInfo = {0};
	if(hFile != INVALID_HANDLE_VALUE)
	{
		wcscpy_s(oCopyInfo.wSrcFile, szSrcFilePath);
		wcscpy_s(oCopyInfo.wDstFile, szDestFilePath);
		DeviceIoControl(hFile, IOCTL_COPY_FILE, &oCopyInfo, sizeof(COPYINFO), NULL, NULL, &dwReturn, NULL);
		CloseHandle(hFile);
	}

	if(_waccess(pScanInfoLockedEntry->szFileToScan, 0) == 0)
	{
		PMAX_SCANNER_INFO pLastScanInfo = pScanInfo;
		while(pLastScanInfo->pNextScanInfo)
		{
			pLastScanInfo = pLastScanInfo->pNextScanInfo;
		}

		pLastScanInfo->FreeNextScanInfo = true;
		pLastScanInfo->pNextScanInfo = pScanInfoLockedEntry;
		pScanInfo->IsLockedFile = 1;
		pScanInfoLockedEntry->IsChildFile = 1;
		pScanInfoLockedEntry->AutoQuarantine = pScanInfo->AutoQuarantine;
		_tcscpy_s(pScanInfoLockedEntry->szContainerFileName, pScanInfo->szFileToScan);

		if(_ScanFileTimer(pScanInfoLockedEntry))
		{
			pScanInfo->eVirusFileType = pScanInfoLockedEntry->eVirusFileType;
			pScanInfo->IsArchiveFile = pScanInfoLockedEntry->IsArchiveFile;
			pScanInfo->IsEMLFile = pScanInfoLockedEntry->IsEMLFile;
			pScanInfo->IsExcluded = pScanInfoLockedEntry->IsExcluded;
			pScanInfo->IsPackedFile = pScanInfoLockedEntry->IsPackedFile;
			pScanInfo->IsPasswordProtected = pScanInfoLockedEntry->IsPasswordProtected;
			pScanInfo->IsWhiteFile = pScanInfoLockedEntry->IsWhiteFile;
			pScanInfo->IsPackedFile = pScanInfoLockedEntry->IsPackedFile;
			pScanInfo->ThreatDetected = pScanInfoLockedEntry->ThreatDetected;
			pScanInfo->ThreatSuspicious = pScanInfoLockedEntry->ThreatSuspicious;
			pScanInfo->ThreatQuarantined = pScanInfoLockedEntry->ThreatQuarantined;
			pScanInfo->ThreatRepaired = pScanInfoLockedEntry->ThreatRepaired;
			pScanInfo->eMessageInfo = pScanInfoLockedEntry->eMessageInfo;
			pScanInfo->eDetectedBY = pScanInfoLockedEntry->eDetectedBY;
			pScanInfo->ulThreatID = pScanInfoLockedEntry->ulThreatID;
			_tcscpy_s(pScanInfo->szFileSig, pScanInfoLockedEntry->szFileSig);
			_tcscpy_s(pScanInfo->szThreatName, pScanInfoLockedEntry->szThreatName);
			_tcscpy_s(pScanInfo->szOLEMacroName, pScanInfoLockedEntry->szOLEMacroName);
			return true;
		}
		return false;
	}

	delete pScanInfoLockedEntry;
	pScanInfoLockedEntry = NULL;

	return false;
}

bool CMaxScanner::LoadExcludeExtDB()
{
	
	bool bRetVal = false;
	CString csAppPath =  CSystemInfo::m_strAppPath;
	CString csApplicationPath = csAppPath +_T("Tools\\");
	//AddLogEntry(csApplicationPath);
	int iCount = 0; 
	

	if (m_objDBExcludeExtList.Load(csApplicationPath + APP_EXCLUDE_FILEEXTLIST_DB) == true)
	{
		
		LPVOID lpVoid = m_objDBExcludeExtList.GetFirst();
		EXCLUDE_EXTENSION_OF_SCANNING_FILES = m_objDBExcludeExtList.GetCount();
		pScanFileExcludeExtension = new WCHAR*[EXCLUDE_EXTENSION_OF_SCANNING_FILES];
		while(lpVoid)
		{
			CString csPath;
			LPTSTR strKey = NULL;
			m_objDBExcludeExtList.GetKey(lpVoid, strKey);
			csPath = strKey; //GetSpyName(ulSpyName);
			pScanFileExcludeExtension[iCount] = new WCHAR[50];
			_tcscpy_s(pScanFileExcludeExtension[iCount],50, csPath);
			lpVoid = m_objDBExcludeExtList.GetNext(lpVoid);
			iCount++;
		}
		bRetVal = true;
	}

	return bRetVal;
}
///*-------------------------------------------------------------------------------------
//Function		:	CFileSystemScanner::SetParam
//Description		:	To set different parameters for scanner	 
//--------------------------------------------------------------------------------------*/
//void CMaxScanner::SetParams(bool bMacLearning)
//{
//	m_bMachineLearning = bMacLearning;
//}

bool CMaxScanner::BackupMLDetectFiles(TCHAR *szFileDataPath, bool bDigiCat)
{
	//Threatcommunity removed
	/*CString csFileDataPath(szFileDataPath);
	csFileDataPath.MakeLower();
	CString	csMLFileBackup;
	int iPos = csFileDataPath.ReverseFind('\\');
	if(iPos != -1)
	{
		csMLFileBackup = csFileDataPath.Mid(iPos+1);
		iPos = csMLFileBackup.ReverseFind('.');
		if(iPos!= -1)
		{
			csMLFileBackup = csMLFileBackup.Left(iPos);
		}

		csMLFileBackup.Format(_T("%s%s\\ml_%s.zip"),CSystemInfo::m_strAppPath,THREAT_COMMUNITY_FOLDER,csMLFileBackup);

		m_obj7zDLL.Max7zArchive(csMLFileBackup,csFileDataPath,_T("a@u$ecD!"));
		return true;
	}*/


	return false;
}

bool CMaxScanner::IsValidDidCertificate(LPCTSTR pszFile2Check)
{
	bool					bReturn = false;
	CMaxDigitalSigCheck		objCertCheck;
	
	bReturn = objCertCheck.CheckDigitalSign(pszFile2Check);

	return bReturn;
}


bool CMaxScanner::_CheckForValidDigiCert(LPCTSTR pszFile2Check)
{
	bool	bReturn = false;
	__try
	{
		bReturn = IsValidDidCertificate(pszFile2Check);
	}
	__except(CMaxExceptionFilter::Filter(GetExceptionCode(), GetExceptionInformation(), _T("Exception caught Scanner::CheckForValidDigiCert"), pszFile2Check))
	{
		return false;
	}	
	return bReturn;
}
bool CMaxScanner::SkipExtractPathFile(LPCTSTR pszFile2Check)
{
	CString csSkipTempfolderPath = CSystemInfo::m_strAppPath + _T("tempfolder\\");
	CString csSkipTempdataPath = CSystemInfo::m_strAppPath + _T("tempdata\\");
	CString csFileToCheck(pszFile2Check);
	csSkipTempfolderPath.MakeLower();
	csSkipTempdataPath.MakeLower();
	csFileToCheck.MakeLower();
	if((csFileToCheck.Find(csSkipTempfolderPath) != -1) || (csFileToCheck.Find(csSkipTempdataPath) != -1))
	{
		return true;
	}
	return false;

}
void  CMaxScanner::ConfigForNetworkScan(CString csScanDrive)
{
#ifdef _SDSCANNER
		if(!m_bValidated)
	{
	CString csAppPath =  CSystemInfo::m_strAppPath;
	CString csApplicationPath = csAppPath +_T("Tools\\");
	TCHAR szHostname[MAX_PATH]={0};
	DWORD dwSize = UNLEN + 1;
	CString csMachineName = csScanDrive.Left(csScanDrive.Find(L"\\",csScanDrive.Find(L"\\")+3));
	csMachineName = csMachineName.Mid(2);
	csMachineName.Trim();
	GetComputerName(szHostname,&dwSize);
	CString csHostname(szHostname);
	csHostname.Trim();
	if(csMachineName.CompareNoCase(csHostname) == 0 ) 
	{
		return;
	}			
	if(csScanDrive.GetAt(0)==L'\\')
	{		
		CRegistry objReg;				
		TCHAR  szUsername[MAX_PATH]= {0};
		CString csUsername;
		CString csProductKey = CSystemInfo::m_csProductRegKey;	           
		objReg.Get(csProductKey,L"CurrUser", csUsername,HKEY_LOCAL_MACHINE);
		_tcscpy_s(szUsername,MAX_PATH,csUsername);

		CS2S objUseraccounts(false);
		objUseraccounts.Load(csApplicationPath + CURR_USER_CRED);
		TCHAR *szPassword=NULL;
		objUseraccounts.SearchItem(szUsername,szPassword);

		CNetWorkUserValidation objNetValid;
		objNetValid.ImpersonateLocalUser(szUsername,szPassword);

		CString csMachineName;
		size_t iLen = csScanDrive.GetLength();
		if(iLen > 0)
		{
			CString csTemp(csScanDrive);			
			if(csTemp.Right(1) == L"\\")
			{
				csTemp = csTemp.Left((int)iLen -1);
			}
			if(csTemp.GetAt(0)==L'\\')
			{
				csMachineName = csTemp.Left(csTemp.Find(L"\\",csTemp.Find(L"\\")+3));
				csMachineName = csMachineName.Mid(2);			
			}
		}		
		TCHAR szMachineName[MAX_PATH]={0};
		_tcscpy_s(szMachineName,MAX_PATH,csMachineName);


		CBufferToStructure objNetworkCredentials(false, sizeof(TCHAR)*MAX_PATH, sizeof(NETCREDDATA));
		LPNETCREDDATA lpNetCredentials = NULL;				
		RevertToSelf();
		objNetworkCredentials.Load(csApplicationPath + NETWORK_SCAN_CRED);
	
		_tcslwr(szMachineName);
				if(objNetworkCredentials.SearchItem(szMachineName,(LPVOID&)lpNetCredentials))
				{
					//OutputDebugString(L"Successfully Got the Machine Name");
					objNetValid.ImpersonateLocalUser(szUsername,szPassword);
					objNetValid.NetworkValidation(szMachineName,lpNetCredentials->szUsername,lpNetCredentials->szPassword);					   
					m_bValidated = true;
				}					   
	}
	else
	{
		return;
	}
		}
#endif
}
BOOL CMaxScanner::GetAnsiString(LPCTSTR pszUnicodeIN,LPSTR pszAnsiOUT)
{
	BOOL		bRetValue = FALSE;
	char		szOut[MAX_PATH] = {0x00};		

	if (pszUnicodeIN == NULL || pszAnsiOUT == NULL)
	{
		return bRetValue;
	}

	int iRetLen =  WideCharToMultiByte(CP_ACP,WC_COMPOSITECHECK,pszUnicodeIN,_tcslen(pszUnicodeIN),szOut,MAX_PATH,NULL,NULL);

	if (iRetLen > 0x00)
	{
		strcpy(pszAnsiOUT,szOut);
	}

	return bRetValue;
}
BOOL CMaxScanner::GetUnicodeString(LPCSTR pszAnsiIN, LPTSTR pszUnicodeOUT)
{
	BOOL		bRetValue = FALSE;
	TCHAR		szOut[MAX_PATH] = {0x00};		

	if (pszAnsiIN == NULL || pszUnicodeOUT == NULL)
	{
		return bRetValue;
	}

	int iRetLen =  MultiByteToWideChar(CP_ACP,0,pszAnsiIN,strlen(pszAnsiIN),szOut,MAX_PATH);

	if (iRetLen > 0x00)
	{
		_tcscpy(pszUnicodeOUT,szOut);
	}

	return bRetValue;
}


int CMaxScanner::_IsExtensiontoScan(PMAX_SCANNER_INFO pScanInfo)
{
	if(!pScanInfo)
	{
		return -1;
	}

	/*
	if(!m_bIsExcludeExtDBLoaded)
	{
		return -1;
	}
	*/

	int i = 0;
	WCHAR *ExtPtr = NULL;

	ExtPtr = wcsrchr(pScanInfo->szFileToScan, '.');
	CString csExt(ExtPtr);
	if(ExtPtr != NULL)
	{
		if( _wcsicmp(ExtPtr,L".BAT")== 0
			|| _wcsicmp(ExtPtr,L".REG")== 0
			|| _wcsicmp(ExtPtr,L".INI")== 0
			|| _wcsicmp(ExtPtr, L".7Z") == 0
			|| _wcsicmp(ExtPtr, L".ZIP") == 0
			|| _wcsicmp(ExtPtr, L".RAR") == 0
			|| _wcsicmp(ExtPtr, L".GZ") == 0)
		{
			return 0x01;
		}

		/*
		for(i = 0; i < EXCLUDE_EXTENSION_OF_SCANNING_FILES; i++)
		{
			CString csLog(pScanFileExcludeExtension[i]);
			if(_wcsicmp(ExtPtr,pScanFileExcludeExtension[i])== 0)
			{
				return i;
			}
		}
		*/
	}
	return -1;
}