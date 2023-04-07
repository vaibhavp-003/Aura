#pragma once
#include "S2U.h"

//////////////////////////// Registry Key Paths ///////////////////////////////

const TCHAR KEY_PARAMETERS[]				=	_T ( "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters" ) ;
const TCHAR KEY_NETWORK_CARDS[]				=	_T ( "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkCards" ) ;
const TCHAR KEY_INTERFACES[]				=	_T ( "SYSTEM\\CurrentControlSet\\Services\\TcpIp\\Parameters\\Interfaces" ) ;
const TCHAR KEY_PROFILE_LIST[]				=	_T ( "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList" ) ;

//////////////////////////// EVENT NAMES ///////////////////////////////

//const TCHAR EVENT_NOTIFY_AUTOMATION[]		=	_T("Global\\_EVENT_NOTIFY_AUTOMATION_");
#define _EVENT_NOTIFY_AUTOMATION_			_T("Global\\_EVENT_NOTIFY_AUTOMATION_")
//////////////////////////// EVENT NAMES ///////////////////////////////

class CGeneralServices
{
	static SECURITY_ATTRIBUTES m_sa ;
	static PSID m_pEveryoneSID ;
	static PSID m_pAdminSID ;
	static PACL m_pACL ;
	static PSECURITY_DESCRIPTOR m_pSD ;

public:

	CGeneralServices() ;
	~CGeneralServices() ;

	static bool InitSecurityAttribute() ;
	static bool WaitForNetworkActivity ( DWORD dwMaxTimeToWait ) ;
	static bool SetTokenPrivilege ( LPCTSTR szPrivilegeName ) ;
	static bool LoadOtherUsersHive(LPVOID lpParam);
	static bool FormatString ( LPTSTR szOutput , DWORD dwOutputElementsCount , LPCTSTR szFormat , ... ) ;
	static bool SetRegistryValue ( HKEY hHive , LPCTSTR szFullKeyName , LPCTSTR szValueName , LPCTSTR szData ) ;
	static bool GetRegistryValue ( HKEY hHive , LPCTSTR szFullKeyName , LPCTSTR szValueName , LPTSTR szData , DWORD dwDataElementsCount ) ;

	static bool ExecuteApplication ( LPCTSTR szFullAppName , LPTSTR szCmdLineParam , bool bHideWindow = true , DWORD dwWaitForAppMS = MAXDWORD , LPDWORD pdwThreaID = NULL , LPDWORD pdwProcessID = NULL ) ;
	static void GetCurrDateTime(TCHAR *szDateTime, int iBuffSize);
	static bool ChangePCName ( LPCTSTR szFullAppName ) ;
	static bool ChangePCIPAddress ( LPCTSTR szFullAppName ) ;
	static bool ChangePCTime ( LPSYSTEMTIME lpNewSystemTime ) ;
	static bool RebootSystem ( DWORD dwType = 0 ) ;
    static bool UnzipToFolder(const CString csFileToUnzip,TCHAR *csDestination,CString csPassword ,bool bDeleteAfterUncompressed);
    static bool CompressFolder( CString csFolderName ,CString csZipName ,bool bDeleteAfterCompress ,bool bFinalZip );
    static bool GetAllFileNamesInPath ( CString csFolderName , CStringArray& csArrFilePath );
	static bool CopyDirectory( LPCTSTR szExistingFolder , LPCTSTR szDestinationFolder );
	static bool CleanDirectory( LPCTSTR szDirectoryPath);
	static bool DeleteDirectory( LPCTSTR szDirectoryPath);
	static bool KillProcessByID(DWORD ProcessID);
	static bool GetIPAddress(TCHAR * pIPAddress);
	static bool ReadAndExecuteFilesFromDB();
	static bool CopyAllFilesToBinaryCollection();
	static void CreateAllDirectory(CString csOrginalPath);
	/*static bool GetAndExecuteNewExe (CS2U &objFilesAdded, CString csInputFolderPath );
	static int RegisterComponent ( CString csFileName , bool bRegister ) ;
	static int ExecuteSpyFile(const CString& strFileToExecute) ;*/

	static bool StartProcessWithToken(CString csProcessPath, CString csCommandLineParam ,CString csAccessProcessName , bool bWait = false);
	static HANDLE GetExplorerProcessHandle(CString csAccessProcessName);

	// read SZ_DWORD
	bool	GetRegDWORD( LPCTSTR strKeyPath, LPCTSTR strValueName, DWORD &dwValue, HKEY HiveRoot ) const;
	// Write SZ_DWORD
	bool	SetRegDWORD( LPCTSTR strKeyPath, LPCTSTR strValueName, DWORD &dwValue, HKEY HiveRoot ) const;
};
