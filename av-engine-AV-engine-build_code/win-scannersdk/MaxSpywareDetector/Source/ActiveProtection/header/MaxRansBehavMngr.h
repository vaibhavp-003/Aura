#pragma once
#include "afxmt.h"

#ifndef MAX_REQSTRUCT
	#include "ReqStruct.h"
#endif

#ifndef _MAX_RANS_BEHAV_MGR
	#define _MAX_RANS_BEHAV_MGR
#endif

#define WATCH_LIST_NOT_FOUND	0x00
#define WATCH_LIST_PRESENT		0x01
#define	WATCH_LIST_IGNORE		0x02

#define MAX_FILE_ACCESSED_CNT	10
typedef DWORD (*LPFN_LoadDigiSigDBByPath)(LPCTSTR szDBPath);
typedef DWORD  (*LPFN_SendFile4DigiScan)(LPCTSTR szFilePath);

/*----------------------------------------------------------------------------------------*/
#define MAX_UNICODE_PATH	32767L

typedef ULONG smPPS_POST_PROCESS_INIT_ROUTINE;

const TCHAR SuspeciousDroppFiles[][50] =
{
	L"\\penta_readme.txt",
	L"\\readme!!!!!!.txt",
	L"\\krab-decrypt.txt",
	L"\\@readme@.txt",
	L"entschluesselungs_anleitung.html",
	L"get_your_files_back.txt",
	L"how to restore your files.txt",
	L"RECOVERY INSTRUCTIONS 0 .txt"
};


const TCHAR Process2IgnoreDigiCert[][50] =
{
	L"\\msbuild.exe",
	L"\\svhost.exe",
	L"\\regasm.exe",
	L"\\msmpeng.exe"
};

const TCHAR MaliciousProcessList[][50] =
{
	L"\\fantom.exe",
	L"\\windowsupdate.exe",
	L"\\microsoft edge.exe",
	L".tmp\\aescrypt.exe"
};


// Used in PEB struct
typedef struct _smPEB_LDR_DATA {
	BYTE Reserved1[8];
	PVOID Reserved2[3];
	LIST_ENTRY InMemoryOrderModuleList;
} smPEB_LDR_DATA, *smPPEB_LDR_DATA;

// Used in PEB struct
typedef struct _smRTL_USER_PROCESS_PARAMETERS {
	BYTE Reserved1[16];
	PVOID Reserved2[10];
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;
} smRTL_USER_PROCESS_PARAMETERS, *smPRTL_USER_PROCESS_PARAMETERS;

// Used in PROCESS_BASIC_INFORMATION struct
typedef struct _smPEB {
BYTE Reserved1[2];
	BYTE BeingDebugged;
	BYTE Reserved2[1];
	PVOID Reserved3[2];
	smPPEB_LDR_DATA Ldr;
	smPRTL_USER_PROCESS_PARAMETERS ProcessParameters;
	BYTE Reserved4[104];
	PVOID Reserved5[52];
	smPPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
	BYTE Reserved6[128];
	PVOID Reserved7[1];
	ULONG SessionId;
} smPEB, *smPPEB;

// Used with NtQueryInformationProcess
typedef struct _smPROCESS_BASIC_INFORMATION {
    LONG ExitStatus;
    smPPEB PebBaseAddress;
    ULONG_PTR AffinityMask;
    LONG BasePriority;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR InheritedFromUniqueProcessId;
} smPROCESS_BASIC_INFORMATION, *smPPROCESS_BASIC_INFORMATION;

typedef struct _smPROCESSINFO
{
	DWORD	dwPID;
	DWORD	dwPEBBaseAddress;
	TCHAR	szImgPath[MAX_UNICODE_PATH];
	TCHAR	szCmdLine[MAX_UNICODE_PATH];
} smPROCESSINFO;

/*----------------------------------------------------------------------------------------*/

typedef struct _PROCESS_BEHAV_WATCH_ARRAY
{
	TCHAR	szProcName[512];
	TCHAR	szFileLastAccessed[MAX_FILE_ACCESSED_CNT][512];
	DWORD	dwCurAccessedCount;
	DWORD	dwCurRepeatCount;
	DWORD	dwDiffFilesCnt;
	BOOL	bIsIgnored;		
	CTime	ctFirstWriteTime;
	TCHAR	szOrgProcName[512];
}PROCESS_BEHAV_WATCH_ARRAY,*LPPROCESS_BEHAV_WATCH_ARRAY;

class CMaxRansBehavMngr
{
	LPPROCESS_BEHAV_WATCH_ARRAY		*m_pProcWatchLst;
	DWORD							m_dwWatchLstCnt;
	TCHAR							m_szProcessPah[512];
	TCHAR							m_szOrgProcPath[512];
	TCHAR							m_szFileAccessed[512];
	TCHAR							m_szFileAccessedOld[512];

	bool							IsFileInIgnoreDir(LPCTSTR	pszFilePath);
	bool							IsProcInIgnoreDir(LPCTSTR	pszProcPath);
	int								IsPresentInWatchArray(int &iIndex);
	bool							Check4Directory(LPCTSTR pszFile2Check);
	bool							Check4EncryptedFile(LPCTSTR pszFile2Check, int iArrayPos);
	bool							Check4RootEncryptedFile(LPCTSTR pszFile2Check);
	bool							Check4PersonalIDFile(LPCTSTR pszFile2Check);
	bool							IsFileAlreadyPresentInArray(LPCTSTR pszFile2Check, int iArrayPos);
	int								Check4EncryptedFile(int	iIndex);

	bool							PrintLog(LPCTSTR pszLogLine);
	int								ManageFileAccessed(int iIRecIndex);
	int								FileExists(int iIRecIndex);
	int								IsSameFileAccessed(int iIRecIndex);
	int								GetCmdLineFilePath(LPCTSTR pszProcPath,CString &csProcCmdLine);
	BOOL							CheckProcessCmdLine(DWORD dwProcID,LPCTSTR pszExePath,CString &csCmdLine);
	int								SetDebugPrivileges(void);

	int								Check4FileSize(LPCTSTR pszFile2Check);

	HMODULE							m_hNTDll;
	NTQUERYINFORMATIONPROCESS		NtQueryInformationProcess;

	bool							Check4DateModified(LPCTSTR pszFile2Check);//Added 21-12-2020
	int								GetFileDateTime(LPCTSTR szFilePath, FILETIME &ftCreated, FILETIME &ftModified, FILETIME &ftAccessed);//Added 21-12-2020


public:
	CMaxRansBehavMngr(void);
	~CMaxRansBehavMngr(void);

	int		IsSuspeciousBehavior(LPCTSTR pszFilePath, LPCTSTR pszFileAccess);
	int		ManageProcessBehavior(int iIRecIndex);

	HMODULE								m_hDBScan;
	LPFN_LoadDigiSigDBByPath			m_lpfnLoadDBByPath;
	LPFN_SendFile4DigiScan				m_lpfnScanFile;
	bool								m_bDigiSigDBLoaded;

	bool	IsBadDigiCertFound(LPCTSTR pszProcPath);
	bool	TerminateSusProcess(LPCTSTR pszProcPath);
	bool	IsLegitimateWindowsProcess(LPCTSTR pszProcPath);
	bool	CheckFileSizeMisMatch(DWORD	dwFileSize, const CString csFilePath);
	bool	CheckValidDigiSig(CString csFilePath);
	bool	IsSuspeciousDropper(LPCTSTR pszFilePath);
	bool	IsMaliciousProcess(LPCTSTR pszFilePath);

	bool	IsChapakRansomware();

	int		DropperRansomPattern(LPCTSTR pszFilePath, LPCTSTR pszFileAccess);
	int		Check4SameExtFiles(int iIRecIndex);
	bool	Check4MultiExt(LPCTSTR	pszFile2Check, LPTSTR pszLastExt);

	BOOL		m_bIsWin7;

	CCriticalSection	m_objCriticalSec;
};
