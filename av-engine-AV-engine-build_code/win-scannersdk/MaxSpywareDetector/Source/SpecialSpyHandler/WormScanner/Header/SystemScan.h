/*====================================================================================
   FILE				: SystemScan.h
   ABSTRACT			: Class definition of system scan object
   DOCUMENTS		: 
   COMPANY			: Aura 
   CREATION DATE	: 
   NOTES			: 
   VERSION HISTORY	: 
					Version: 2.5.0.7
					Resource : Vikram
					Description: added functions for trojan delf scanning

					Version: 2.5.0.14
					Resource : Shweta
					Description: added CheckDelfExe and GetiniFileName
====================================================================================*/

#pragma once
#include "splspyscan.h"
#include "MaxDSrvWrapper.h"

// maximum file size for searching random entries in sysdir folder
#define MAXIMUM_FILE_SIZE   500 * 1024
const int iSPYID_WormKolab = 3497;

class CSystemScan :	public CSplSpyScan
{
	CFileFind	m_objFile;
	CString		m_csAdmokeServiceName;
	CStringArray m_csArrCommonInfectedFiles;
	CMaxDSrvWrapper *m_pMaxDSrvWrapper;
	
	CMapStringToString		m_objAExtMap;
	unsigned char * m_cFileBuff ;

	bool EnumerateFiles ( SEARCH_FOLDER_LIST SFLVariable ,CFileSignatureDb *pFileSigMan );
	bool CheckForAdmokeFiles ( const CString& csFileName );
	bool CheckStringsinAdmokeFiles(CString csFileName , UCHAR * cFileBuff , DWORD dwBytes);
	bool FindServiceName ( UCHAR * cFileBuff , DWORD dwBytesRead );
	bool ChecknDelforAdmokeBHO( void );

	bool CheckExtension( CString csFileName);
	bool Check180FileCompany ( CString csFullFileName );
	bool IsApherFile( CString csFileName, UCHAR * FileBuffer, DWORD cbFileBuffer);
	bool CheckIfHSAFile(CString csFileName,UCHAR * FileBuffer, DWORD cbFileBuffer);
	bool EnumKeysForHSA ( CString csMainKey , HKEY hHiveKey , bool bRemove , CString csExePath , CString& csDllClassID );
	bool CheckIfRandomSpyware( CString csFullFileName, BYTE* cFileBuff, DWORD cbFileBuff );
	bool CheckIfVSToolbarFile( CString csFileName, BYTE *cFileBuff, DWORD cbFileBuff );
	bool CheckIfISearchFile ( CString csFullFileName, BYTE *cFileBuff, DWORD dwBytesRead );
	bool CheckIfSpyLockedFile( const CString& csFullFileName, UCHAR * cFileBuff,
							   DWORD dwBytesRead, ULONGLONG iFileLength);
	bool IsFilePresentInSharedTaskKey ( const CString& csFullFileName );
	bool CheckIfTrojanDelfFile( const CString& csFullFileName , UCHAR * cFileBuff , DWORD dwBytesRead , ULONGLONG iFileLength ) ;
	bool CheckDelfExe( const CString& csFullFileName , UCHAR * cFileBuff , DWORD dwBytesRead  );
	bool GetiniFileName ( CString csFullFileName , UCHAR * cFileBuff ,DWORD dwBytesRead );
	bool CheckforAboutBlank  ( const CString& csFullFileName , UCHAR * cFileBuff , DWORD dwBytesRead , ULONGLONG iFileLength  );
	bool CheckWinBlueSoft ( const CString& csFullFileName ,BYTE * m_cFileBuff , DWORD dwFileSize);
	bool CheckforMonder( const CString& csFullFileName ,BYTE * m_cFileBuff, CString csFileName, ULONGLONG iFileLength );
    bool CheckRegEntryForRun(const CString& csFullFilePath, const CString& csFileName);	
	bool CheckForDreamy( const CString& csFilePath, ULONGLONG iFileLength );
	bool CheckSignatureOfDreamyFile ( const CString csFilePath ) ;	
	bool CheckforMalwareAgent ( const CString& csFullFileName , CString& csFileName ,CFileSignatureDb *pFileSigMan , ULONGLONG iFileLength);
	bool CheckForStuh ( const CString& csFullFileName , ULONGLONG iFileLength );
	bool checkSecondStuhSig ( const CString& csFilePath );
	bool CheckFirstStuhSig ( const CString& csFilePath );
	bool IsRecentlyModified(const CString& csFilePath, FILETIME* stLastModTime, DWORD dwModWithinDays);
	bool CheckForWormKolab(const CString& csFilePath, FILETIME* stLastModTime, const CString& csFileLoc);

public:

	//CSystemScan(CSplSpyWrapper *pSplSpyWrapper):CSplSpyScan(pSplSpyWrapper,_T("SystemScan"))
	CSystemScan(CSplSpyWrapper *pSplSpyWrapper):CSplSpyScan(pSplSpyWrapper,295)//_T("Trojan.Agent"))
	{
		m_bSplSpyFound = false;
		m_cFileBuff = new unsigned char [ MAXIMUM_FILE_SIZE ] ;
				
		m_objAExtMap.SetAt( _T(".dat") , _T(".dat") ) ;
		m_objAExtMap.SetAt( _T(".dll") , _T(".dll")  ) ;
		m_objAExtMap.SetAt( _T(".txt") , _T(".txt") ) ;
		m_objAExtMap.SetAt( _T(".exe") , _T(".exe") ) ;
		m_objAExtMap.SetAt( _T(".log") , _T(".log") ) ;
		m_objAExtMap.SetAt( _T(".ocx") , _T(".ocx") ) ;
		m_objAExtMap.SetAt( _T(".bin") , _T(".bin") ) ;
		m_objAExtMap.SetAt( _T(".cpl") , _T(".cpl") ) ;		
		m_objAExtMap.SetAt( _T(".syz") , _T(".syz") ) ;
	}
	
	virtual ~CSystemScan(void)
	{
		m_objAExtMap.RemoveAll();
		delete []m_cFileBuff ;
		m_cFileBuff = NULL ;
	}
	bool ScanSplSpy ( bool bIsDelete = false, CFileSignatureDb *pFileSigMan = NULL);
};
