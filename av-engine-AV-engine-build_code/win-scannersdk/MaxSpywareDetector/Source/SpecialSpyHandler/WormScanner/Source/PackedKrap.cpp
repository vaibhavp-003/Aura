/*======================================================================================
   FILE				: PackedKrap.cpp
   ABSTRACT			: This class is used for scanning and qurantining Spyware Packed Krap
   DOCUMENTS		: SpecialSpyHandler_DesignDoc.doc
   AUTHOR			: Yuvraj 
   COMPANY			: Aura 
   COPYRIGHT NOTICE : (C) Aura
      				  Created as an unpublished copyright work.  All rights reserved.
     				  This document and the information it contains is confidential and
      				  proprietary to Aura.  Hence, it may not be 
      				  used, copied, reproduced, transmitted, or stored in any form or by any 
      				  means, electronic, recording, photocopying, mechanical or otherwise, 
      				  without the prior written permission of Aura
   CREATION DATE	: 13-4-2010
   NOTE				:
   VERSION HISTORY	:
					
========================================================================================*/

#include "pch.h"
#include "PackedKrap.h"
#include "ExecuteProcess.h"
#include <io.h>

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*-------------------------------------------------------------------------------------
	Function		: ScanSplSpy
	In Parameters	: bool bToDelete , CFileSignatureDb *pFileSigMan
	Out Parameters	: 
	Purpose			: 
	Author			: Yuvraj
	Description		: main entry point of this class for spyware scanning
--------------------------------------------------------------------------------------*/
bool CPackedKrap::ScanSplSpy(bool bToDelete, CFileSignatureDb *pFileSigMan)
{
 	try
	{
		CExecuteProcess objExeProc;
		CString csSid = objExeProc.GetCurrentUserSid();
		
		if(IsStopScanningSignaled())
		{
			return(m_bSplSpyFound);
		}
		if(bToDelete)
		{
			CString csReplaceString, csRenameFile;
			int iRestart;
			for(INT_PTR i = 0, iTotal = m_csInfecFiles.GetCount() ; i < iTotal ; i++)
			{
				csRenameFile = m_csInfecFiles[i];
				csRenameFile.Insert(csRenameFile.GetLength() - 4, _T(' '));
				csReplaceString = csRenameFile + RENAME_FILE_SEPARATOR + m_csInfecFiles[i];
				
				if(!_taccess(m_csInfecFiles[i],0))
				{
					_tremove(m_csInfecFiles[i] + _T(".sd"));

					iRestart = _trename(m_csInfecFiles[i], m_csInfecFiles[i] + _T(".sd"));
					if( iRestart != 0 ) //Could not rename 
					{
						AddInRestartDeleteList(RD_FILE_RENAME, m_ulSpyName, csReplaceString);		
					}
					iRestart = _trename(csRenameFile, m_csInfecFiles[i]);
					if( iRestart != 0 ) //Could not rename 
					{
						AddInRestartDeleteList(RD_FILE_RENAME, m_ulSpyName, csReplaceString);			
					}
				}
				else if(!_taccess(csRenameFile, 0))
				{
					AddInRestartDeleteList(RD_FILE_RENAME, m_ulSpyName, csReplaceString);
				}
			}
			return true;
		}

		ScanEnrtyInRun(HKEY_LOCAL_MACHINE, RUN_REG_PATH);
		ScanEnrtyInRun(HKEY_USERS, csSid + BACK_SLASH + RUN_REG_PATH);
		if(!_taccess(CSystemInfo::m_strProgramFilesDir+_T("\\Internet Explorer\\wmpscfgs.exe"),0))
		{
			SendScanStatusToUI(Special_File, m_ulSpyName, CSystemInfo::m_strProgramFilesDir+_T("\\Internet Explorer\\wmpscfgs.exe"));
		}

		if(m_bScanOtherLocations)
		{
			CString csWowPath = CString(WOW6432NODE_REG_PATH) + UNDERWOW_RUN_REG_PATH;
			ScanEnrtyInRun(HKEY_LOCAL_MACHINE, csWowPath);
			ScanEnrtyInRun(HKEY_USERS, csSid + BACK_SLASH + csWowPath);

			if(!_taccess(CSystemInfo::m_strProgramFilesDirX64+_T("\\Internet Explorer\\wmpscfgs.exe"),0))
			{
				SendScanStatusToUI(Special_File, m_ulSpyName, CSystemInfo::m_strProgramFilesDirX64+_T("\\Internet Explorer\\wmpscfgs.exe"));
			}
		}
		
		m_bSplSpyFound = bToDelete ? false : m_bSplSpyFound;
		return m_bSplSpyFound;
	}
	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CPackedKrap::ScanSplSpy, Error : %d"), GetLastError());
		AddLogEntry( csErr, 0, 0 );
	}
	return( false );
}

/*-------------------------------------------------------------------------------------
	Function		: ScanEnrtyInRun
	In Parameters	: HKEY, CString
	Out Parameters	: bool
	Purpose			: Enumerate Run entries and check for spyware 
	Author			: Yuvraj
	Description		: Enumerate Run Registry entries, get file path and check file for 
					  spyware
--------------------------------------------------------------------------------------*/
bool CPackedKrap::ScanEnrtyInRun(HKEY hHive, CString csLocation)
{
	CString csData, csFilePath;
	CStringArray csArrValues, csArrData;
	bool bSuccess = false;

	m_objReg.QueryDataValue(csLocation, csArrValues, csArrData, hHive);

	for(INT_PTR i = 0, iTotal = csArrData.GetCount() ; i < iTotal ; i++)
	{
		if(IsStopScanningSignaled())
		{
			break;
		}
		csData = csArrData.GetAt(i);
		csData.MakeLower();
		
		bSuccess = GetFilePathFromRegData(csData, csFilePath);
		bSuccess = CheckFileIsSpyware(csFilePath);
	}
	return m_bSplSpyFound;
}
/*-------------------------------------------------------------------------------------
	Function		: CheckFileIsSpyware
	In Parameters	: CString 
	Out Parameters	: bool
	Purpose			: Check the given file for spyware
	Author			: Yuvraj
	Description		: Check the file if infected and send msg to ui
--------------------------------------------------------------------------------------*/
bool CPackedKrap::CheckFileIsSpyware(CString csFilePath)
{
	CString csOriFile = csFilePath;
	
	if(csOriFile.Right(4) != _T(".exe"))
	{
		return false;
	}
	else
	{
		bool bSuccess = ScanFile(csOriFile);
		if(!bSuccess)
		{
			return false;
		}
	}
	m_bSplSpyFound = true;		
	
	csOriFile.Insert(csOriFile.GetLength() - 4, _T(' '));
	if(!_taccess(csOriFile, 0)) //file with space exists
	{
		m_csInfecFiles.Add(csFilePath);
		SendScanStatusToUI(Special_File_Report, m_ulSpyName, csOriFile);//report space file coz of refernce scanner
	}
	else
	{
		SendScanStatusToUI(Special_File, m_ulSpyName, csFilePath);
	}
	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: ScanFile
	In Parameters	: const CString csFullFileName
	Out Parameters	: bool
	Purpose			: Scan file for PE
	Author			: Yuvraj
	Description		: Check signature and PE checks of file  
--------------------------------------------------------------------------------------*/
bool CPackedKrap::ScanFile(const CString csFullFileName)
{
	HANDLE hFile ;
	DWORD dwBytesRead = 0 ;
	IMAGE_DOS_HEADER ImageDosHeader = { 0 } ;
	IMAGE_NT_HEADERS ImageNTHeader = { 0 } ;
	IMAGE_SECTION_HEADER ImageSectionHeader [ 5 ] = { 0 } ;

	hFile = CreateFile( csFullFileName , GENERIC_READ , FILE_SHARE_READ , 0 , OPEN_EXISTING ,
						FILE_ATTRIBUTE_NORMAL , 0 ) ;
	if(hFile == INVALID_HANDLE_VALUE)
	{
		return false;
	}

	ReadFile ( hFile , &ImageDosHeader , sizeof ( ImageDosHeader ) , &dwBytesRead , 0 ) ;
	if(dwBytesRead != sizeof(ImageDosHeader))
	{
		CloseHandle ( hFile ) ;
		return false;
	}

	SetFilePointer ( hFile , ImageDosHeader.e_lfanew , 0 , FILE_BEGIN );
	ReadFile ( hFile , &ImageNTHeader , sizeof ( ImageNTHeader ) , &dwBytesRead , 0 ) ;
	if ( dwBytesRead != sizeof ( ImageNTHeader ) )
	{
		CloseHandle ( hFile ) ;
		return ( false ) ;
	}

	ReadFile ( hFile , &ImageSectionHeader , sizeof ( ImageSectionHeader ) , &dwBytesRead , 0 ) ;
	if ( dwBytesRead != sizeof ( ImageSectionHeader ) )
	{
		CloseHandle ( hFile ) ;
		return ( false ) ;
	}

	if(ImageNTHeader.FileHeader.NumberOfSections != 0x0003)
	{
		CloseHandle ( hFile ) ;
		return ( false ) ;
	}
	if(ImageNTHeader.OptionalHeader.AddressOfEntryPoint != 0x34AF0)
	{
		CloseHandle ( hFile ) ;
		return ( false ) ;
	}
	if(ImageNTHeader.OptionalHeader.SizeOfImage != 0x36000)
	{
		CloseHandle ( hFile ) ;
		return ( false ) ;
	}
	if(ImageSectionHeader[0].SizeOfRawData != 0)
	{
		CloseHandle ( hFile ) ;
		return ( false ) ;
	}

	BYTE byReadBuffer [ 0x10 ] = { 0 } ;
	BYTE byRsrcSignature1 [ 0x0F ] = { 0x54, 0x00, 0x57, 0x00, 0x58, 0x00, 0x20, 
									   0x00, 0x43, 0x00, 0x6F, 0x00, 0x72, 0x00, 0x70};

	SetFilePointer( hFile, 0xA5A8, 0, FILE_BEGIN ) ;
	ReadFile ( hFile, &byReadBuffer, 0x0F, &dwBytesRead, 0 ) ;
	if ( dwBytesRead != 0x0F )
	{
		CloseHandle ( hFile ) ;
		return ( false ) ;
	}
	if ( _memicmp ( byRsrcSignature1, byReadBuffer, 0x0F ) != 0 )
	{
		CloseHandle ( hFile ) ;
		return ( false ) ;
	}

	CloseHandle ( hFile ) ;
	return true;
}
