#pragma once
#include "MaxPEFile.h"
#include "FSDB.h"
#include "ThreatManager.h"
#include "FileSig.h"
#include "InstantScanner.h"
#include "PatternFileScanner.h"
#include "MaxVirusScanner.h"
#include "MaxDSrvWrapper.h"
#include "FileSignatureDb.h"
#include "MaxProcessScanner.h"
#include "DirectoryManager.h"
#include "ADSConstants.h"
#include "BlackDBManager.h"
#include "FullFileSigDBManager.h"
#include "WhiteSigDBManager.h"
#include "MaxMachineLearning.h"
#include "C7zDLL.h"

#define MAX_ZIP_RECURSSION_LEVEL 0x32
#define MAX_UNPACK_RECURSSION_LEVEL 100
const int FileStreamInformation = 22;

typedef int (*LPFNEMLParser)(LPCTSTR szFileToParse, LPTSTR szExtractedPath, LPTSTR szSubject, LPTSTR szFrom);
typedef int (*LPFNEMLRePack)(LPCTSTR szFileToRePack, LPTSTR szExtractedPath);
typedef int (*LPFNInitMailDB)(LPCTSTR szDBPath, LPCTSTR szAppPath);
typedef int (*LPFNDeInitMailDB)();
typedef DWORD	(*LPFN_WhiteCerScan)(LPCTSTR szFilePath);
typedef void	(*LPFN_WhiteCerScanIni)(LPCTSTR szFilePath);
typedef DWORD	(*LPFN_WhiteExpParse)(LPCTSTR szFilePath);
typedef void	(*LPFN_SetAppDataPath) (LPCTSTR szAppDataPath, LPCTSTR szLocalAppDataPath);
typedef DWORD	(*LPFN_CheckBlackFile) (LPCTSTR szFilePath);
typedef DWORD	(*LPFN_CheckFileInAppData)(LPCTSTR szFilePath);

typedef bool	(*LPFN_ScanFileHeur)(LPCTSTR szFilePath);

//Max Learning
typedef DWORD	(*LPFN_InitializeScanner)(LPCTSTR pszClassifierPath,LPCTSTR pszFeaturesPath);
typedef DWORD	(*LPFN_ScanFile)(LPCTSTR pszFile2Scan);

typedef bool	(*LPFN_ScanFileDigiSig)(LPCTSTR pszFile2Scan);
typedef bool	(*LPFN_LoadDigiSig)();
typedef bool	(*LPFN_UnLoadDigiSig)();

typedef bool	(*LPFN_ScanFileYrScan)(const char* pszFile2Scan, char* pszVirusName);
typedef bool	(*LPFN_LoadYrScan)(const char* pszFileDB);
typedef bool	(*LPFN_UnLoadYrScan)();

class CMaxScanner
{
public:
	CMaxScanner();
	virtual ~CMaxScanner(void);

	bool InitializeScanner(const CString &csMaxDBPath);
	void DeInitializeScanner();
	bool InitializeScannerML();	
	bool InitializeFullFileSigand();
	bool InitializeVirusDB();
	bool InitializeYARADB();

	bool _CheckForValidDigiCert(LPCTSTR pszFile2Check);
	bool IsValidDidCertificate(LPCTSTR pszFile2Check);	
	
	CFileSignatureDb	m_oLocalSignature;
	CMaxProcessScanner	m_oMaxProcessScanner;
	CS2S			    m_objDBExcludeExtList;

	void ReloadInstantINI();
	bool ScanFile(PMAX_SCANNER_INFO pScanInfo);
	bool ScanAlternateDataStream(PMAX_SCANNER_INFO pScanInfo);
	bool GetSignature(TCHAR *csFilePath, TCHAR *szMd5);
	bool GetThreatName(ULONG ulThreatID, TCHAR *szThreatName);
	bool IsExcluded(ULONG ulThreatID, LPCTSTR szThreatName, LPCTSTR szPath);
	void SetAutomationLabStatus(bool bAutomationLab);
	bool ReloadMailScannerDB();
	void SetParams(bool bMacLearning = false);
	bool	m_bIsUsbScan;
	bool	m_bMachineLearning;
	bool	m_bMachineLearningQ;
	DWORD	m_dwSkipCompressfiles;
	bool	m_bValidated;
	DWORD	m_dwActmonScan;
	bool	m_bADSScan;
	bool	m_bRefScan;
	DWORD	m_dwSnoozeActMon;
		
	HANDLE						m_hVirusScanSigDB;
	HANDLE						m_hYARASigDB;

private:
	HANDLE						m_hEvent;
	HANDLE						m_hMLThread;	
	HANDLE						m_hFullFileSigDB;
	
	
	CFSDB						m_objBlackDB;
	//CFSDB						m_objFullFileSigDB;
	CFullFileSigDBManager		m_objFullFileSigDB;
	CBlackDBManager				m_obBlackDBManager;
	//CFSDB						m_objWhiteDB;
	CWhiteSigDBManager			m_objWhiteDB;
	CMaxVirusScanner			m_oMaxVirusScanner;
	CInstantScanner				m_oInstantScanner;
	CPatternFileScanner			m_oPatternFileScanner;
	CMaxDSrvWrapper				*m_pMaxDSrvWrapper;
	CThreatManager				*m_pThreatManager;
	CDirectoryManager			m_oDirectoryManager;
	//MaxLearning
	TCHAR						m_szMcLearningDir[MAX_PATH];
	CMaxMachineLearning			*m_pMaxMacLearning;
	C7zDLL						m_obj7zDLL;
	DWORD						m_dwMaxMacLearning;
	DWORD						m_dwMaxYrScan;
	
	BYTE						m_btPolyVirusRevIDS[16];
	DWORD						m_dwSD43CurVersion;
	DWORD						m_dwSD47CurVersion;
	DWORD						m_dwWhiteCurVersion; //For future use, as we are not keeping local db for white entries...
	DWORD						m_dwPatCurVersion;
	DWORD						m_dwMLVersion;//For MAchine learning
	DWORD						m_dwYrVersion;//For Yara scanner

	DWORD	m_dwTotalScanTime;
	DWORD	m_dwTotalRepairTime;
	DWORD	m_dwPECreationTime; //PE Signature Creation Time
	DWORD	m_dwWPESearchingTime;
	DWORD	m_dwBPESearchingTime;
	DWORD	m_dwPEQuarantineTime;
	DWORD	m_dwTotalUnPackTime;
	DWORD	m_dwTotalADSScanTime;
	DWORD	m_dwTotalArchiveTime;
	DWORD	m_dwMLScanTime;
	DWORD	m_dwYaraScanTime; 

	DWORD	m_dwMaxPEFileCreationTime = 0x00; //MaxPEFile Creation Time
	DWORD	m_dwRansScanTime = 0x00; //RANSOM-DET Time
	DWORD	m_dwAppDataScanTime = 0x00; //APPDATA Scan
	DWORD	m_dwPatScanTime = 0x00; //Pattern Scan
	DWORD	m_dwInstScanTime = 0x00; //Instance Scanner
	DWORD	m_dwCompSafeScanTime = 0x00; //ScanFileCompanyDigitalSign Check Time

	int		m_iTotalNoOfFiles;
	int		m_iNoofWhiteFileSigSearched;
	int		m_iNoofWhiteFileSigMatched;
	int		m_iNoofBlackFileSigSearched;
	int		m_iNoofBlackFileSigMatched;
	int		m_iNoofFullFileSigSearched;
	int		m_iNoofFullFileSigMatched;
	int		m_iNoofMACFileSigSearched;
	int		m_iNoofMACFileSigMatched;
	int		m_iNoofMaxVirusSearched;
	int		m_iNoofMaxVirusMatched;
	int		m_iTotalNoOfPackedFiles;
	int		m_iTotalNoOfUnPackSuccessFiles;
	int		m_iTotalNoOfUnPackFailedFiles;
	int		m_iTotalNoOfADSFiles;
	int		m_iTotalNoOfArchiveFiles;
	int		m_iTotalNoOfArchiveSuccessFiles;
	int		m_iTotalNoOfArchiveFailedFiles;
	int		m_iTotalNoOfFilesSkipped;
	bool    m_bIsExcludeExtDBLoaded;

	int		m_iNoofMLearnSigSearched;
	int		m_iNoofMLearnSigMatched;
	int		m_iNoofHeurSigSearched;
	int		m_iNoofHeurSigMatched;
	int		m_iNoofYrSigSearched;
	int		m_iNoofYrSigMatched;

	
	bool	_ScanFileTimer(PMAX_SCANNER_INFO pScanInfo);
	int		_CheckFileType(PMAX_SCANNER_INFO pScanInfo);
	void	_ExtractFile(PMAX_SCANNER_INFO pScanInfo, LPTSTR szExtractPath);
	bool	_ScanFolder(PMAX_SCANNER_INFO pScanInfo, LPCTSTR szExtractPath);
	bool	_ScanFileNew(PMAX_SCANNER_INFO pScanInfo);
	int		_IsCompressedFile(PMAX_SCANNER_INFO pScanInfo);
	int		_IsExcludeCompressedExtension(PMAX_SCANNER_INFO pScanInfo);
	int		_IsExcludeScanExtension(PMAX_SCANNER_INFO pScanInfo);
	bool	_ScanPackedFile(PMAX_SCANNER_INFO pScanInfo, int iRecursiveCnt);
	bool	_ScanFileContent(PMAX_SCANNER_INFO pScanInfo, int iRecursiveCnt);
	//bool	ScanFileCompanyDigitalSign(LPCTSTR pszFile2Check);
	bool	ScanFileCompanyDigitalSign(PMAX_SCANNER_INFO pScanInfo);
	bool	IsValidFile2Scan(LPCTSTR pszFile2Check);
	DWORD	_RepairFile(PMAX_SCANNER_INFO pScanInfo, int iRecursiveCnt);
	bool	_ScanAndRepairFile(PMAX_SCANNER_INFO pScanInfo);
	bool	_RestoreOriginal(bool bUsingDummyFile, PMAX_SCANNER_INFO pScanInfo);
	bool	_CreatePESignature(PMAX_SCANNER_INFO pScanInfo, LPPESIGCRCLOCALDB pPEFileSigLocal);
	bool	_CreateFullFileSignature(PMAX_SCANNER_INFO pScanInfo, LPPESIGCRCLOCALDB pPEFileSigLocal);
	bool	_CreateMaxPEObject(PMAX_SCANNER_INFO pScanInfo, PESIGCRCLOCALDB &oPEFileSigLocal, bool bOpenFile, bool bOpenToRepair);
	void	_CloseMaxPEFile(PMAX_SCANNER_INFO pScanInfo, bool bCleanTree);
	NTQUERYINFORMATIONFILE pfnNtQueryInformationFile;
	
	bool	_CopyFileToTempFolder(PMAX_SCANNER_INFO pScanInfo);
	bool	_ReplaceLockedFile(PMAX_SCANNER_INFO pScanInfo);

	bool	_SendFileToMLearningScanner(PMAX_SCANNER_INFO	pScanInfo);
	bool	_SendFileToYaraScanner(PMAX_SCANNER_INFO	pScanInfo);
	BOOL	GetAnsiString(LPCTSTR pszUnicodeIN,LPSTR pszAnsiOUT);
	BOOL	GetUnicodeString(LPCSTR pszAnsiIN, LPTSTR pszUnicodeOUT);


	int		_IsExtensiontoScan(PMAX_SCANNER_INFO pScanInfo);
	
private:
	HMODULE m_hUnpacker = NULL;
	LPFNUnpackFileNew m_lpfnUnpackFileNew = nullptr;
	LPFNExtractFile m_lpfnExtractFile = nullptr;
	LPFNExtractNonPEFile m_lpfnExtractNonPEFile = nullptr;

	HMODULE m_hWhiteCerScanDll;
	HMODULE m_hRansomPatternScanDll;
	LPFN_WhiteCerScan		m_lpfnWhiteCerScan;
	LPFN_WhiteCerScanIni	m_lpfnWhiteCerScanIni;
	LPFN_WhiteExpParse		m_lpfnWhiteExpParse;
	LPFN_SetAppDataPath		m_lpfnSetAppDataPath;
	LPFN_CheckBlackFile		m_lpfnCheckBlackFile;
	LPFN_CheckFileInAppData	m_lpfnCheckFileInAppData;

	HMODULE m_hMaxDigiScan;
	LPFN_ScanFileDigiSig	m_lpfnScanFileDigiSig;
	LPFN_LoadDigiSig		m_lpfnLoadDigiSig;
	LPFN_UnLoadDigiSig		m_lpfnUnLoadDigiSig;

	HMODULE m_hMaxYrScan;
	LPFN_ScanFileYrScan		m_lpfnScanFileYrScan;
	LPFN_LoadYrScan			m_lpfnLoadYrScan;
	LPFN_UnLoadYrScan		m_lpfnUnLoadYrScan;
	bool					m_bYrScanLoaded;

	HMODULE m_hThreateComDll;
	LPFN_ScanFileHeur	m_lpfnScanFileHeur;

	bool _LoadUnpacker();
	bool _UnpackFile(PMAX_SCANNER_INFO pScanInfo, PMAX_SCANNER_INFO pUnpakcedScanInfo);
	void _UnloadUnpacker();

	void _UnzipToFolderSEH(LPCTSTR szFileToScan, LPTSTR szExtractedPath);
	void _UnzipToFolder(LPCTSTR szFileToScan, LPTSTR szExtractedPath);

	void _ExtractSISToFolderSEH(LPCTSTR szFileToScan, LPTSTR szExtractedPath);
	void _ExtractSISToFolder(LPCTSTR szFileToScan, LPTSTR szExtractedPath);

	HMODULE				m_hEMLParser;
	LPFNEMLParser		m_lpfnEMLUnPack;
	LPFNEMLRePack		m_lpfnEMLRePack;
	LPFNInitMailDB		m_lpfnInitMailDB;
	LPFNDeInitMailDB	m_lpfnDeInitMailDB;

	bool _LoadEMLParser();
	void _ExtractEMLToFolderSEH(PMAX_SCANNER_INFO pScanInfo, LPTSTR szExtractedPath);
	void _ExtractEMLToFolder(PMAX_SCANNER_INFO pScanInfo, LPTSTR szExtractedPath);
	void _RePackEMLToFolderSEH(PMAX_SCANNER_INFO pScanInfo, LPTSTR szExtractedPath);
	void _RePackEMLToFolder(PMAX_SCANNER_INFO pScanInfo, LPTSTR szExtractedPath);
	void _UnloadEMLParser();

	bool LoadExcludeExtDB();
	bool BackupMLDetectFiles(TCHAR *szBackupMLDetectPath, bool bDigiCat = false);
	bool SkipExtractPathFile(LPCTSTR pszFile2Check);
	void ConfigForNetworkScan(CString csScanDrive);

	bool _Unpack32Fileon64Os(PMAX_SCANNER_INFO pScanInfo, PMAX_SCANNER_INFO pUnpakcedScanInfo);

	DWORD		m_dwZipRecursionCnt;
	DWORD		m_dwUpackRecursionCnt;

	CWinThread	*m_VirusDBLoadThread;
	CWinThread	*m_YARADBLoadThread;
	CWinThread	*m_MLDBLoadThread;

	HANDLE		hScanMutex;

};
