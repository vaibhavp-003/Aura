/*====================================================================================
   FILE				: SplSpyScan.h
   ABSTRACT			: This class contains commonly used functions among the spcecial spyware classes
   DOCUMENTS		: SpecialSpyHandler_DesignDoc.doc
   AUTHOR			: Anand Srivastava
   COMPANY			: Aura 
   COPYRIGHT NOTICE : (C) Aura
      				  Created as an unpublished copyright work.  All rights reserved.
     				  This document and the information it contains is confidential and
      				  proprietary to Aura.  Hence, it may not be 
      				  used, copied, reproduced, transmitted, or stored in any form or by any 
      				  means, electronic, recording, photocopying, mechanical or otherwise, 
      				  without the prior written permission of Aura
   CREATION DATE	: 25/12/2003
   NOTE				:
   VERSION HISTORY	:
					version: 2.5.0.23
					Resource : Anand
					Description: Ported to VS2005 with Unicode and X64 bit Compatability
========================================================================================*/

#pragma once
#include <aclapi.h>
//#include <shfolder.h>
#include <winsvc.h>

#include "verinfo.h"
#include "Registry.h"
#include "EnumProcess.h"
#include "SDSystemInfo.h"
#include "QuarantineFile.h"
#include "FileOperation.h"
#include "FileSignatureDb.h"
#include "S2S.h"
#include "DBPathExpander.h"
#include "GenericFileScanner.h"
#include <vector>

using namespace std;
#ifdef _DEBUG
#define CRTDBG_MAP_ALLOC
#include <stdlib.h>
#include <crtdbg.h>
#endif

const int KEY_ID_NOTIFY = 1 ;
const int KEY_ID_APPINIT = 2 ;
const int KEY_ID_SSODL = 4 ;

// function pointer type for calling LSP fnctions in Options.dll
typedef bool (*GETACTIVEXPROC) (int,CString,HWND,CString , bool);

typedef bool ( __cdecl * LPFN_QUARANTINEFILEEX ) ( CString csFileName , CString csBackupFileName ) ;

typedef struct tagSearchFolderList
{
	CString csPath;				//  path to search for the files
	CString csWildCard;			// Wildcard for files to be searched
}SEARCH_FOLDER_LIST ;

#pragma pack(1)
//created copies of the structure definitions to pack them for file reading
typedef struct _IMAGE_DOS_HEADER_MSS
{
    WORD   e_magic;                     // Magic number
    WORD   e_cblp;                      // Bytes on last page of file
    WORD   e_cp;                        // Pages in file
    WORD   e_crlc;                      // Relocations
    WORD   e_cparhdr;                   // Size of header in paragraphs
    WORD   e_minalloc;                  // Minimum extra paragraphs needed
    WORD   e_maxalloc;                  // Maximum extra paragraphs needed
    WORD   e_ss;                        // Initial (relative) SS value
    WORD   e_sp;                        // Initial SP value
    WORD   e_csum;                      // Checksum
    WORD   e_ip;                        // Initial IP value
    WORD   e_cs;                        // Initial (relative) CS value
    WORD   e_lfarlc;                    // File address of relocation table
    WORD   e_ovno;                      // Overlay number
    WORD   e_res[4];                    // Reserved words
    WORD   e_oemid;                     // OEM identifier (for e_oeminfo)
    WORD   e_oeminfo;                   // OEM information; e_oemid specific
    WORD   e_res2[10];                  // Reserved words
    LONG   e_lfanew;                    // File address of new exe header
}IMAGE_DOS_HEADER_MSS, *PIMAGE_DOS_HEADER_MSS;

typedef struct _IMAGE_FILE_HEADER_MSS
{
    WORD    Machine;
    WORD    NumberOfSections;
    DWORD   TimeDateStamp;
    DWORD   PointerToSymbolTable;
    DWORD   NumberOfSymbols;
    WORD    SizeOfOptionalHeader;
    WORD    Characteristics;
}IMAGE_FILE_HEADER_MSS, *PIMAGE_FILE_HEADER_MSS;

typedef struct _IMAGE_DATA_DIRECTORY_MSS
{
    DWORD   VirtualAddress;
    DWORD   Size;
}IMAGE_DATA_DIRECTORY_MSS, *PIMAGE_DATA_DIRECTORY_MSS;

typedef struct _IMAGE_OPTIONAL_HEADER_MSS
{
    //
    // Standard fields.
    //

    WORD    Magic;
    BYTE    MajorLinkerVersion;
    BYTE    MinorLinkerVersion;
    DWORD   SizeOfCode;
    DWORD   SizeOfInitializedData;
    DWORD   SizeOfUninitializedData;
    DWORD   AddressOfEntryPoint;
    DWORD   BaseOfCode;
    DWORD   BaseOfData;

    //
    // NT additional fields.
    //

    DWORD   ImageBase;
    DWORD   SectionAlignment;
    DWORD   FileAlignment;
    WORD    MajorOperatingSystemVersion;
    WORD    MinorOperatingSystemVersion;
    WORD    MajorImageVersion;
    WORD    MinorImageVersion;
    WORD    MajorSubsystemVersion;
    WORD    MinorSubsystemVersion;
    DWORD   Win32VersionValue;
    DWORD   SizeOfImage;
    DWORD   SizeOfHeaders;
    DWORD   CheckSum;
    WORD    Subsystem;
    WORD    DllCharacteristics;
    DWORD   SizeOfStackReserve;
    DWORD   SizeOfStackCommit;
    DWORD   SizeOfHeapReserve;
    DWORD   SizeOfHeapCommit;
    DWORD   LoaderFlags;
    DWORD   NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY_MSS DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
}IMAGE_OPTIONAL_HEADER_MSS, *PIMAGE_OPTIONAL_HEADER_MSS;

typedef struct _IMAGE_NT_HEADERS_MSS
{
    DWORD Signature;
    IMAGE_FILE_HEADER_MSS FileHeader;
    IMAGE_OPTIONAL_HEADER_MSS OptionalHeader;
}IMAGE_NT_HEADERS_MSS, *PIMAGE_NT_HEADERS_MSS;

typedef struct _IMAGE_SECTION_HEADER_MSS
{
    BYTE    Name[IMAGE_SIZEOF_SHORT_NAME];
    union
	{
            DWORD   PhysicalAddress;
            DWORD   VirtualSize;
    } Misc;
    DWORD   VirtualAddress;
    DWORD   SizeOfRawData;
    DWORD   PointerToRawData;
    DWORD   PointerToRelocations;
    DWORD   PointerToLinenumbers;
    WORD    NumberOfRelocations;
    WORD    NumberOfLinenumbers;
    DWORD   Characteristics;
}IMAGE_SECTION_HEADER_MSS, *PIMAGE_SECTION_HEADER_MSS;
#pragma pack()

//enum RESTART_DELETE_TYPE
//{
//	RD_INVALID = 0,
//	RD_FILE_DELETE,
//	RD_FILE_BACKUP,
//	RD_PROCESS,
//	RD_FOLDER,
//	RD_KEY,
//	RD_VALUE,
//	RD_DATA,
//	RD_FILE_RENAME
//};

class CSplSpyScan
{
	LPFN_QUARANTINEFILEEX m_lpfnQuarantineFileEx ;
	void CreateWormstoDeleteINI(CString strINIPath);
	
protected:
	bool QueryRegData(LPCWSTR strKeyPath, LPCWSTR strValueName, DWORD &dwDataType, LPBYTE lpbData, DWORD &dwBuffSize, HKEY HiveRoot);

	static CS2S	m_objAvailableUsers;
	static CDBPathExpander	m_oDBPathExpander;
	static CRegistry		m_oRegistry;
	

public:
	BOOL AddInRestartDeleteList(RESTART_DELETE_TYPE eRD_Type, ULONG ulSpyNameID, LPCTSTR szValue);
	void LoadAvailableUsers();
	CSplSpyWrapper* m_pSplSpyWrapper;
	CEnumProcess m_objEnumProcess;
	CRegistry	 m_objReg;
	CSystemInfo  m_objSysInfo;
	CGenericFileScanner 	m_objGenFileScan;
	CString		m_csSysDir;
	CString		m_csWinDir;
	
	CMapStringToString m_objAppInitWhiteList ;
	CMapStringToString m_objNotifyWhiteList ;
	CMapStringToString m_objSSODLWhiteList ;
	CMapStringToString m_objAExtMap;
	
	//const CString	m_csSpywareName ;
	ULONG m_ulSpyName;
	//const CString GetSpywareName(){ return m_ulSpyName ; }
	//CSplSpyScan(CSplSpyWrapper *pSplSpyWrapper,const CString csSpywareName = _T("") );
	CSplSpyScan(CSplSpyWrapper *pSplSpyWrapper, ULONG ulSpyName);
	virtual ~CSplSpyScan(void);

	virtual bool ScanSplSpy(bool bIsDelete = false, CFileSignatureDb *m_pFileSigMan = NULL) = 0;

    void SendScanStatusToUI(SD_Message_Info eTypeOfScanner);
    void SendScanStatusToUI(SD_Message_Info eTypeOfScanner, const ULONG ulSpyName, const WCHAR *strValue);
    void SendScanStatusToUI(SD_Message_Info eTypeOfScanner, const ULONG ulSpyName, HKEY Hive_Type, const WCHAR *strKey, const WCHAR *strValue, int Type_Of_Data, LPBYTE lpbData, int iSizeOfData);
	void SendScanStatusToUI(SD_Message_Info eTypeOfScanner, const ULONG ulSpyName, HKEY Hive_Type, const TCHAR *strKey, const TCHAR *strValue, int Type_Of_Data, LPBYTE lpbData, int iSizeOfData, REG_FIX_OPTIONS *psReg_Fix_Options, LPBYTE lpbReplaceData, int iSizeOfReplaceData);

	bool EnumFolder ( const CString &csFolder , CStringArray &csArrFolder , ULONG ulSpywareName, int iDepth = 1, bool bReprtToUI = false );
	bool CheckIfValidExtension ( const CString &csFileName , const CString &csExt ) ;
	bool CheckVersionInfo ( const CString &csFileName , int iVersionOption , const CString &csActualVersionInforequired );
	bool AddToCompulsoryDeleteOnRestartList(int iVal, ULONG m_ulSpyName, const CString& csEntry);
	
protected:
	CStringArray m_arrAllUsers; // Stores the list of users keys under HKEY_USERS 
	CFileSignatureDb *m_pFileSigMan;
	
	// new structure variables
	bool IsStopScanningSignaled() ;
	// new structure variables

	bool SearchStringsInFileU(LPCTSTR szFilePath, const CStringArray& csArrStrList);
	bool SearchStringsInFile ( LPCTSTR szFileName , CArray<CStringA,CStringA> &csArrList);
	bool GetServiceFileName ( SC_HANDLE hService , CString& csServiceFileName ,	CString& csServiceFolder );

	bool KillProcess ( CString csFolder , CString csFile );
	void HandleUninstaller( ULONG ulSpywareName );
	bool CheckUnInstaller(ULONG ulSpyName,LPCTSTR sFolderName, LPCTSTR sExeName, bool bRunSetup);
	bool CheckAndRunUnInstallerWithParam ( CString csFullFolderName, CString csFileName, CString csParameters, bool bToDelete, ULONG ulSpywareName);
	
	bool LocateNTDLLEntryPoints ( void );
	bool DelKey ( WCHAR * wDelKeyName , ULONG NameLength );
	bool DelKeyLocalMachine ( LPCTSTR FullRegKey );
	
	bool RemoveFolders(CString csFolderPath, ULONG ulSpyName, bool bDeleteEntries, bool bAddRestartDel = false);
	bool RemoveBHOWithKey(CString sClasssID, bool bToDelete, ULONG ulSpywareName);
	
	bool CheckAndRemoveDriver ( ULONG ulSpyware , CString csDriverName , CString csDriverFullPath , CStringArray &csaTodeleteKeys , bool bToDelete );
	bool FindAndAddDriverKey( ULONG ulSpyware, CString csDriverName, CString csRegMainKey, CStringArray &csArrInfectedKeys, bool &bDriverKeyFound, bool isdelete);
	BOOL EnableTokenPrivilege ( HANDLE hToken , LPCTSTR lpszPrivilege , BOOL bEnablePrivilege ) ;
	bool DeleteAllTheValues ( HKEY hParent , CString csRegKey );
	void RemoveRegistryKey(CString csMainKey, HKEY hMainHive, ULONG ulSpyName);
	void EnumerateValuesAndData(CString csParentKey, HKEY hHiveKey, ULONG ulSpyName, bool bCheckForFile);

	bool CheckAndRemoveSSODLEntries ( ULONG ulSpywareName ,CStringArray & csArrSSODLRegEntries ,
									  CStringArray & csArrSSODLFileEntries , bool bToDelete );
	bool IsFilePresentInSystem ( TCHAR * szFile , DWORD cbszFile );
	bool LookUpWhiteList ( LPCTSTR szFileName , DWORD dwRegistryEntryID );
	bool InitWhiteListDB ( void ) ;
	bool DeInitWhiteListDB ( void ) ;
	bool SearchStringInRunKeyData ( ULONG ulSpywareName , CString csSearchString , CString& csRegValue = CString ( _T("") ) , CString& csRegData = CString ( _T("") ) , HKEY hHive = HKEY_LOCAL_MACHINE ) ;
	bool CheckIfCodecFolder ( CString csFolderName );
	bool SearchPathInCLSID ( CString csClassID , CString csPath , ULONG ulSpywareName );
	bool ChangePermission(CString csRegKey, HKEY hKey);
	bool FixLSP ( void );
	bool CheckSubFoldersForVariant ( ULONG ulSpywareName, CString csMainFolder, CArray<CStringA,CStringA>& csArrKeywordsList );

	bool IsRandomSpywareFolder ( const CString& csFolderName , const CString& csSearchString , ULONG ulSpywareName );
	bool CheckForUninstallKey ( const CString& csRandomNumber , ULONG  ulSpywareName , const CString& csMainFolder);
	bool RandomVersion (const CString& csFolderName , CString & csRandomVersion , CString & csSubFolderName , CString & csRandomVersionWithDot , const CString& csKeyName);
	
	bool IsEntryInMultiStringReg(HKEY hHive, CString csKey, CString csValue, CString csCompareWith, bool bRemoveIt);

	void TempLog(CString csFileWorm);
	bool ListFolders ( WCHAR * wSearchPath , bool bToDelete );
	bool CheckAndDeleteWideCharFilenames ( WCHAR * wSearchPath, bool bToDelete, ULONG ulSpywareName );
	bool GetIllegitimateFileNames ( TCHAR * RegData , CStringArray& csFileNames );

	void EnumKeynSubKey ( CString csKeyToEnumerate , ULONG ulSpywareName , bool bAddInRestart = false );
	bool FixINIFile ( LPCTSTR sIniFile , LPCTSTR sAppName , LPCTSTR sValue , LPCTSTR sInfectedStr );
	bool FindExeAndRemove(ULONG ulSpyName, CString csPath, CString csWildcard, bool bRemoveit);
	bool FindExeAndRemove(ULONG ulSpyName, CString csPath, CString csWildcard, bool bRemoveit, CStringArray & sIgnoreList);// 2.5.0.49
	
	bool CheckReportDeleteRegKey( HKEY hive, CString csKeyPath, CString csSubKey, ULONG ulSpyDBName, bool isDelete);
	bool FindKillReportProcess(CString csFileName, ULONG ulSpywareName, bool isDelete,  bool bDeleteFile = false );
	bool FindKillReportDll(CString csFileName, ULONG ulSpywareName,CString csProcessName, bool isDelete );
	bool FindKillReportService(CString csFullFileName, CString csServiceName, ULONG ulSpywareName, bool isDelete );
	bool FindReportRegKey(CString csKeyPath, ULONG ulSpyName,  HKEY hive, bool isDelete, bool enumFullKey = false );
	bool FindReportRegValue(CString csKeyPath, CString csValue, ULONG ulSpyName,  HKEY hive, bool isDelete,  bool reportData = false);
	bool FindReportKillServiceOnRestart(CString csServiceName,ULONG ulSpywareName, CString &csServiceFileName, 
										CString &csServiceFolderName, bool isDelete );
	bool FindReportKillOnRestart( CString csFullFilePath, ULONG ulSpyName, bool isDelete, bool isDeleteOnRestart = true);
	bool CheckCompanyName ( CString csFullFileName , CString csCompanyName );
	bool CheckReportKeyValueData( ULONG ulSpywareName, CString csMainKey, HKEY hive );

	bool GetGenuineFile(LPCTSTR sFileName, LPTSTR sGenuineFileName,DWORD cbGenuineFileName );
	bool CheckSystemFolder(LPCTSTR sFolderName, LPCTSTR sFileName, LPTSTR sGenuineFileName);
	bool CheckWindowsFolder(LPCTSTR sFolderName, LPCTSTR sFileName, LPTSTR sGenuineFileName,DWORD cbGenuineFileName);
	bool CheckRegKey ( CString csMainKey, CString csCompare, HKEY hHiveKey, CString &strSubKey);
	bool IsCodecFolder ( CString csFolderName ) ;
	void EnumAndReportCOMKeys ( ULONG ulSpywareName, const CString& csKey, HKEY hKeyHive , const bool bCheckFiles = true) ;
	bool CheckToScanOtherLocations() ;
	bool QuarantineFile ( ULONG ulSpywareName, const CString& csSpyValue ) ;
	bool CheckForKeyLoggerFiles ( const CString & csRandomNumber , ULONG ulSpywareName , const CString & csSubFolderName ,const CString & csRandomVersion , const CString & csSpy) ;
	bool CheckForKeyLoggerKeys ( CString csRandomNumber , CString csFileName , ULONG ulSpywareName , CString csSpyToSearch ) ;
	bool CheckRandomEntry ( CString csSpyentry , CString csRandomNumber , CString csRandomVersion , ULONG ulSpywareName, CStringArray &csArrServiceKeys , CString csSubFolderName );
	bool CheckForFileMD5 ( HKEY hHive, CString & csRegKey , CStringArray & csArrRegValue ,CStringArray & csArrBlackMD5, CString & csBlackFilePath, CString  & csBlackFilename, bool bReportFullKey, bool bReportValue, CFileSignatureDb *pFileSigMan, bool bToDelete);
	bool RegfixData ( HKEY hHive, const CString& csKey, const CString& csValue, CString csData, const CString& csNewData, ULONG ulSpywareName );
    void GetDrivesToScan ( CString & csDrivesToScan );
	bool GetFilePathFromRegData(LPCTSTR szRegData, CString& csFilePath);
	bool GetCurUserStartupPath(CString& csStartupPath, bool bAllUser = false);
	bool GetCurUserStartMenuProgs(CString& csStartMenuProgsPath, bool bAllUser = false);
	bool GetCurUserDesktopPath(CString& csCurUserDesktopPath, bool bAllUser = false);
	bool CheckIfSectionsPresent(LPCTSTR szFilePath, LPBYTE bySections, DWORD cbSections, PIMAGE_DOS_HEADER_MSS pDosHeader = NULL, PIMAGE_NT_HEADERS_MSS pNtHeader = NULL, PIMAGE_SECTION_HEADER_MSS pSecHdr = NULL, DWORD* pdwCount = NULL);
	void SetRestartFlag(bool bSet);

public:
	bool			m_bSplSpyFound;
	bool			m_bStatusbar;
	bool			m_bScanOtherLocations ;
	CString			m_csOtherSysDir ;
	CString			m_csOtherPFDir ;

	void PrepareMD5String(CString &csSignature, LPBYTE MD5Signature);
	BOOL EnablePrivilegesToHandleReg(void);
	void CallToStatusBarFucn();
	void DoEvents();
};
