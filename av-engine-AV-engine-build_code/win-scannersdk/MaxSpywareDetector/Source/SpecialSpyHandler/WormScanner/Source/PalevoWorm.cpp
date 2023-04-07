/*======================================================================================
   FILE				: PalevoWorm.cpp
   ABSTRACT			: This class is used for scanning and qurantining Spyware PalevoWorm
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
   CREATION DATE	: 2-2-2010
   NOTE				:
   VERSION HISTORY	:
					
========================================================================================*/

#include "pch.h"
#include "PalevoWorm.h"
#include <io.h>

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*-------------------------------------------------------------------------------------
	Function		: ScanSplSpy
	In Parameters	: bool bToDelete , CFileSignatureDb *pFileSigMan
	Out Parameters	: bool
	Purpose			: 
	Author			: Yuvraj
	Description		: scan random files created by palevo spyware
--------------------------------------------------------------------------------------*/
bool CPalevoWorm  :: ScanSplSpy ( bool bToDelete , CFileSignatureDb *pFileSigMan )
{
 	try
	{
		TCHAR szTempPath[MAX_PATH] = {0};

		GetTempPath(MAX_PATH, szTempPath);
		if(0 != szTempPath[0])
		{
			ScanPathForExes(szTempPath);
			szTempPath[3] = 0;
			_tcscat_s(szTempPath, _countof(szTempPath), _T("Recycler"));
			ScanPathForExes(szTempPath);
		}

		m_bSplSpyFound = bToDelete ? false : m_bSplSpyFound ;
		return ( m_bSplSpyFound ) ;
	}

	catch ( ... )
	{
		CString csErr ;
		csErr . Format ( _T("Exception caught in CPalevoWorm::ScanSplSpy, Error : %d") ,GetLastError() ) ;
		AddLogEntry ( csErr , 0 , 0 ) ;
	}
	
	return ( false ) ;
}

/*-------------------------------------------------------------------------------------
	Function		: ScanPathForExes
	In Parameters	: bool bToDelete , CFileSignatureDb *pFileSigMan
	Out Parameters	: bool
	Purpose			: 
	Author			: Yuvraj
	Description		: scan random files created by palevo spyware
--------------------------------------------------------------------------------------*/
void CPalevoWorm::ScanPathForExes(const CString csPath)
{
	CFileFind objFinder;
	CString csFilePath = csPath + _T("\\*");
	BOOL bMoreFiles = FALSE;
	CString csFile;

	bMoreFiles = objFinder.FindFile(csFilePath);
	if (!bMoreFiles)
	{
		return;
	}

	while(bMoreFiles)
	{
		bMoreFiles = objFinder.FindNextFile();

		if(objFinder.IsDots())
		{
			continue;
		}

		if(objFinder.IsDirectory())
		{
			ScanPathForExes(objFinder.GetFilePath());
		}
		else
		{
			csFile = objFinder.GetFilePath();
			csFile.MakeLower();

			if(csFile.Right(4) == _T(".exe"))
			{
				ScanFile(csFile);
			}
		}
	}

	objFinder.Close();
	return;
}

/*-------------------------------------------------------------------------------------
	Function		: ScanFile
	In Parameters	: const CString csFullFileName
	Out Parameters	: bool
	Purpose			: 
	Author			: Yuvraj
	Description		: scan random files created by palevo spyware by signatures
--------------------------------------------------------------------------------------*/
bool CPalevoWorm::ScanFile(const CString csFullFileName)
{
	HANDLE hFile ;
	DWORD dwBytesRead = 0 ;
	DWORD dwRsrcPointRW;
	BYTE byReadBuffer [ 0x20 ] = { 0 } ;
	IMAGE_DOS_HEADER ImageDosHeader = { 0 } ;
	IMAGE_NT_HEADERS ImageNTHeader = { 0 } ;
	IMAGE_SECTION_HEADER ImageSectionHeader [ 5 ] = { 0 } ;

	hFile = CreateFile ( csFullFileName , GENERIC_READ , FILE_SHARE_READ , 0 , OPEN_EXISTING ,
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

	if(ImageNTHeader.OptionalHeader.SizeOfImage != 0x43000)
	{
		CloseHandle ( hFile ) ;
		return ( false ) ;
	}

	BYTE byRsrcSignature1 [ 0x09 ] = { 0x40, 0x40, 0x40, 0x00, 0x60, 0x40, 0x40, 0x00, 0x7F};
	BYTE byRsrcSignature2 [ 0x20 ] = { 0x01, 0x00, 0x20, 0x00, 0xA8, 0x10, 0x00, 0x00, 
										0x35, 0x00, 0x30, 0x30, 0x00, 0x00, 0x01, 0x00,
										0x20, 0x00, 0xA8, 0x25, 0x00, 0x00, 0x36, 0x00, 
										0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

	dwRsrcPointRW = ImageSectionHeader[3].PointerToRawData;
	SetFilePointer ( hFile , dwRsrcPointRW + 0x1F0 , 0 , FILE_BEGIN ) ;
	ReadFile ( hFile , &byReadBuffer , 9 , &dwBytesRead , 0 ) ;
	if ( dwBytesRead != 9 )
	{
		CloseHandle ( hFile ) ;
		return ( false ) ;
	}

	if ( _memicmp ( byRsrcSignature1 , byReadBuffer , 9 ) != 0 )
	{
		CloseHandle ( hFile ) ;
		return ( false ) ;
	}

	SetFilePointer ( hFile , dwRsrcPointRW + 0x53A0 , 0 , FILE_BEGIN ) ;
	ReadFile ( hFile , &byReadBuffer , 32 , &dwBytesRead , 0 ) ;
	if ( dwBytesRead != 32 )
	{
		CloseHandle ( hFile ) ;
		return ( false ) ;
	}

	if ( _memicmp ( byRsrcSignature2 , byReadBuffer , 32 ) != 0 )
	{
		CloseHandle ( hFile ) ;
		return ( false ) ;
	}

	SendScanStatusToUI ( Special_File , m_ulSpyName , csFullFileName ) ;
	CloseHandle ( hFile ) ;
	return true;
}
