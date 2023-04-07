/*=============================================================================
   FILE			: ExportLog.cpp
   ABSTRACT		: 
   DOCUMENTS	: CommonSystem DesignDoc.doc
   AUTHOR		: Sandip Sanap
   COMPANY		: Aura 
COPYRIGHT NOTICE:
				(C) Aura
				Created as an unpublished copyright work.  All rights reserved.
				This document and the information it contains is confidential and
				proprietary to Aura.  Hence, it may not be 
				used, copied, reproduced, transmitted, or stored in any form or by any 
				means, electronic, recording, photocopying, mechanical or otherwise, 
				with out the prior written permission of Aura
CREATION DATE   : 20/09/2006
   NOTES		:
VERSION HISTORY	:24 Aug 2007, Avinash B : Unicode Supported
				 12 Sept 2007, Avinash B : removed CArchive usage
				 17 Oct. 2007 Avinash B: changed the handling of scan log writing to export mail.htm
                 23-Oct-2009 Sandip S: Call the GetOSVerTagFromRegistry() to get os version
============================================================================*/
#include "pch.h"
#include "time.h"
#include "CPUInfo.h"
#include "ProductInfo.h"
#include "Exportlog.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

CStdioFile CExportLog::m_objExportFile;
/*-------------------------------------------------------------------------------------
Function		: CExportLog
In Parameters	: -
Out Parameters	: -
Purpose			: Constructor
Author			: Sandip Sanap
Created Date	: 20-09-2006
--------------------------------------------------------------------------------------*/
CExportLog::CExportLog(void)
{
	m_objExportFile.m_hFile = INVALID_HANDLE_VALUE;
}
/*-------------------------------------------------------------------------------------
Function		: ~CExportLog
In Parameters	: -
Out Parameters	: -
Purpose			: Destructor
Author			: Sandip Sanap
Created Date	: 20-09-2006
--------------------------------------------------------------------------------------*/
CExportLog::~CExportLog(void)
{
}

/*-------------------------------------------------------------------------------------
	Function		: AddHijackLogEntry
	In Parameters	: -
	Out Parameters	: void
	Purpose			: to add Hijack log entry
	Author			: Sandip Sanap
	Created Date	: 20-09-2006
--------------------------------------------------------------------------------------*/
void CExportLog::AddHijackLogEntry()
{
	try
	{
		CProductInfo objSystem;
		CString csExeInstallPath = objSystem.GetAppInstallPath();
		CString csHijackLogName = REGISTRY_LOG_FILE;
		CString csHijackLogFullPath = csExeInstallPath + csHijackLogName;
		
		FILE* pOutFile;
		pOutFile = _wfsopen( csHijackLogFullPath, _T("w"), 0x40);
		if(pOutFile != NULL)
		{
			CCPUInfo cSystemInfo;
			CProductInfo objPrdInfo ;
			CString    csLine;
			csLine  = _T("\n----------------------------------------------------------------------------\n");
			CString csProdVersion;
			csProdVersion = _T("\nProduct Version: ") ;
			csProdVersion += objPrdInfo.GetProductVersion();
			csProdVersion += _T("\n");
	
			fputws( (LPCTSTR) cSystemInfo.GetDate(),pOutFile);
			fputws((LPCTSTR)csLine, pOutFile);
			fputws((LPCTSTR)_T("\n Registry Information"), pOutFile);
			fputws((LPCTSTR)csLine, pOutFile);
			fputws(( LPCTSTR)csProdVersion, pOutFile);
			fflush(pOutFile);
			fclose(pOutFile);
		}
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in  CExportLog::AddHijackLogEntry"));
	}
}

/*-------------------------------------------------------------------------------------
Function		: AddSystemLogEntry
In Parameters	: -
Out Parameters	: void
Purpose			: to add the log entry
Author			: Sandip Sanap
Created Date	: 20-09-2006
--------------------------------------------------------------------------------------*/
void CExportLog::AddSystemLogEntry(bool bSd)
{
	try
	{
		CProductInfo objSystem;
		CString csExeInstallPath = objSystem.GetAppInstallPath();
		CString csSystemName = SYSTEM_LOG_FILE;
		CString csSysLogFullPath = csExeInstallPath + csSystemName;

		FILE* pOutFile;
		pOutFile = _wfsopen(csSysLogFullPath, _T("w"), 0x40);
		if(pOutFile != NULL)
		{
			CCPUInfo cSystemInfo;
			CProductInfo objPrdInfo;
			CString csHeader;
			CString csHardWareInfo;
			CString csMemoryInfo;
			CString csDiskspaceInfo;
			CString csFileSystemInfo;
			CString csOtherInfo;
			CString csLine;
			csLine  = _T("\n----------------------------------------------------------------------------\n");

			csDiskspaceInfo = csLine;
			csDiskspaceInfo += _T("\t\tHardDrives Configuration : ");
			csDiskspaceInfo += csLine;
			csDiskspaceInfo +=  cSystemInfo.GetHardDiskStatus();
			csDiskspaceInfo += _T("\n");

			csMemoryInfo  = csLine;
			csMemoryInfo += _T("\t\tRAM Configuration : ");
			csMemoryInfo += csLine;
			csMemoryInfo += cSystemInfo.GetRAMStatus();
			csMemoryInfo+= _T("\n");

			csFileSystemInfo = csLine;
			csFileSystemInfo += _T("\t\tFile System Information:");
			csFileSystemInfo += csLine;
			csFileSystemInfo += _T("\nWindows Directory : \t");
			csFileSystemInfo += cSystemInfo.GetWindowsDir();
			csFileSystemInfo += _T("\nSystem Path : \t");
			csFileSystemInfo += cSystemInfo.GetSystemDir();
			csFileSystemInfo += _T("\nProgram Files Directory: \t");
			csFileSystemInfo += cSystemInfo.GetProgramFilesDir();
			csFileSystemInfo += _T("\nApplication Install Path : \t");
			csFileSystemInfo += objPrdInfo.GetAppInstallPath();

			if(bSd)
			{
				csFileSystemInfo += _T("\nOperating System Version: \t");
				csFileSystemInfo += cSystemInfo.GetOSVerTag();
				csFileSystemInfo += _T("\nOperating System Version From Registry: \t");
				csFileSystemInfo += cSystemInfo.GetOSVerTagFromRegistry();
				csFileSystemInfo += _T("\nOperating System Service Pack: \t");
				csFileSystemInfo += cSystemInfo.GetServicePack();
				csFileSystemInfo += _T("\n Registration No.: \t");
				csFileSystemInfo +=  objPrdInfo.GetVoucherNo();
				csFileSystemInfo +=_T("\n");

				fputws((LPCTSTR)cSystemInfo.GetDate(),pOutFile);
				fputws((LPCTSTR)csMemoryInfo, pOutFile);
				fputws((LPCTSTR)csDiskspaceInfo, pOutFile);
				fputws((LPCTSTR)csFileSystemInfo, pOutFile);
			}
			else
			{
				csHeader = csLine;
				csHeader += _T("\t\tHardware Configuration : ");
				csHeader += csLine;
				csHardWareInfo = _T("\nVendor ID: \t");
				csHardWareInfo += cSystemInfo.GetVendorID();
				csHardWareInfo += _T("\nProcessor Name: \t");
				csHardWareInfo += cSystemInfo.GetProcessorName();
				csHardWareInfo += _T("\nProcessor Identifier: \t");
				csHardWareInfo += cSystemInfo.GetProcessorIdentifier();
				csHardWareInfo += _T("\nNumber of Processors: \t");
				csHardWareInfo += cSystemInfo.GetProcessorsCount();
				csHardWareInfo += _T("\n\nOperating System Version: \t");
				csHardWareInfo += cSystemInfo.GetOSVerTag();
				if(cSystemInfo.isOS64bit())
					csHardWareInfo += _T("\t X64 bit");
				csHardWareInfo += _T("\n\nOperating System Service Pack: \t");
				csHardWareInfo += cSystemInfo.GetServicePack();

				csHardWareInfo += _T("\n\nLocale Information: \t");
				csHardWareInfo += cSystemInfo.GetUserLocaleInfo();
				csHardWareInfo += _T("\n");


				csFileSystemInfo +=_T("\n");

				csOtherInfo = csLine;
				csOtherInfo += _T("\n Computer Name: \t");
				csOtherInfo += cSystemInfo.GetPCName();
				csOtherInfo += _T("\n IP Address : \t");
				csOtherInfo += cSystemInfo.GetIPAddress();
				csOtherInfo += _T("\n Admin Rights available : \t");
				if(cSystemInfo.CheckForAdminRights() == TRUE)
					csOtherInfo += _T(" Rights Available");
				else
					csOtherInfo += _T("Rights Not Available");


				csOtherInfo += _T("\n Registration No.: \t");
				csOtherInfo +=  objPrdInfo.GetVoucherNo();

				csOtherInfo += _T("\n Disk No.: \t");    //Not working for Win 98 - Nupur
				csOtherInfo += cSystemInfo.GetDiskSerialNo();
				csOtherInfo += _T("\n");


				fputws((LPCTSTR)cSystemInfo.GetDate(),pOutFile);
				fputws((LPCTSTR)csHeader, pOutFile);
				fputws((LPCTSTR)csHardWareInfo, pOutFile);
				fputws((LPCTSTR)csMemoryInfo, pOutFile);
				fputws((LPCTSTR)csDiskspaceInfo, pOutFile);
				fputws((LPCTSTR)csFileSystemInfo, pOutFile);
				fputws((LPCTSTR)csOtherInfo, pOutFile);
			}

			fflush(pOutFile);
			fclose(pOutFile);
		}
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CExportLog::AddSystemLogEntry "));
	}
}

/*-------------------------------------------------------------------------------------
Function		: OpenLogFile
In Parameters	: CString csFileName :Log File Name
Out Parameters	: bool:Check for LogFile Open,Create or Not available
Purpose			: This function open the log file,if not already exist then create log file
Author			: Sandip Sanap
Created Date	: 20-09-2006
--------------------------------------------------------------------------------------*/
bool CExportLog::OpenLogFile(CString csFileName)
{
	BOOL bRet = FALSE;

	try
	{
		CFileException excpFile;
		bRet = m_objExportFile.Open(static_cast < LPCTSTR >(csFileName), 
								CFile::modeCreate|CFile::modeNoTruncate|CFile::modeWrite, &excpFile);
		if(bRet)
		{
			m_objExportFile.SeekToEnd();
		}
		else
		{
			TCHAR tchErrMsg[MAX_PATH];
			excpFile.GetErrorMessage(tchErrMsg, MAX_PATH);
			AddLogEntry(_T("CExportLog::OpenLogFile(...) - CFileException - Message: %s"), tchErrMsg);
		}

		return bRet ? true : false;
	}

	catch(...)
	{
		AddLogEntry(_T("Unknown Exception caught in CExportLog::OpenLogFile(...)"));
	}

	return bRet ? true : false;
}

/*-------------------------------------------------------------------------------------
Function		: CloseLogFile
In Parameters	: -
Out Parameters	: bool:Check Log File close or not
Purpose			: When all operation end's then this function close the log file
Author			: Sandip Sanap
Created Date	: 20-09-2006
--------------------------------------------------------------------------------------*/
bool CExportLog::CloseLogFile()
{
	try
	{
		if(m_objExportFile.m_hFile != INVALID_HANDLE_VALUE)
		{
			m_objExportFile.Close();
			m_objExportFile.m_hFile = INVALID_HANDLE_VALUE;
		}
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CExportLog::CloseLogFile"));
		return false;
	}
	return true; //Return true if Log File closes Successfully
}

/*-------------------------------------------------------------------------------------
Function		: WriteLog
In Parameters	: CString csWriteStr:take value which write in log file
Out Parameters	: -
Purpose			: Write the value of the parameter into the log file
Author			: Sandip Sanap
Created Date	: 21-09-2006
--------------------------------------------------------------------------------------*/
void CExportLog::WriteLog(CString csWriteStr)
{
	try
	{
		if(m_objExportFile.m_hFile != INVALID_HANDLE_VALUE)
		{
			m_objExportFile.SeekToEnd();
			m_objExportFile.WriteString(csWriteStr); //write given string value into log file
		}
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CExportLog::WriteLog"));
	}
}


/*-------------------------------------------------------------------------------------
Function		: WriteScanStatus
In Parameters	: int status :status id of the scan type
CSstring csStatus: Entry of the file
Out Parameters	: -
Purpose			: To write the scan type and related entry of this scan in log file
Author			: Sandip Sanap
Date			:20-09-2006
--------------------------------------------------------------------------------------*/
void CExportLog::WriteScanStatus(int iStatus,CString csPathEntry)
{
#ifndef MAX_RCL
	try
	{
		CString csStatus; //take the scan Type name corresponding to the enum
		switch(iStatus)//iStatus take value of scan type id from enum
		{
		case ENUM_STATUS_SCANNED: //when iStatus value is 0
			csStatus=CONST_SCANNED_STATUS;
			break;
		case ENUM_STATUS_QSUCCESS: //when iStatus value is 1
			csStatus=CONST_QSUCCESS_STATUS;
			break;
		case ENUM_STATUS_QFAILED: //when iStatus value is 2
			csStatus=CONST_QFAILED_STATUS;
			break;
		case ENUM_STATUS_QCHILD: //when iStatus value is 3
			csStatus=CONST_QCHILD_STATUS;
			break;
		case ENUM_STATUS_DSUCCESS: //when iStatus value is 4
			csStatus=CONST_DSUCCESS_STATUS;
			break;
		case ENUM_STATUS_DFAILED: //when iStatus value is 5
			csStatus=CONST_DFAILED_STATUS;
			break;
		case ENUM_STATUS_RQSUCCESS: //when iStatus value is 6
			csStatus=CONST_RQSUCCESS_STATUS;
			break;
		case ENUM_STATUS_RQFAILED: //when iStatus value is 7
			csStatus=CONST_RQFAILED_STATUS;
			break;
		case ENUM_STATUS_QSCAN: //when iStatus value is 8
			csStatus=CONST_QSCAN;
			break;
		case ENUM_STATUS_FSCAN: //when iStatus value is 9
			csStatus=CONST_FSCAN;
			break;
		case ENUM_STATUS_SSCAN: //when iStatus value is 10
			csStatus=CONST_SSCAN;
			break;
		case ENUM_STATUS_DEFAULT: //WHEN istatus value is NULL
			csStatus = "";
			break;
		}
		if(iStatus != ENUM_STATUS_DEFAULT)//check the istatus value is NULL or not
		{
			csStatus = csStatus + _T(" ->> ");
		}
		csStatus += csPathEntry;
		WriteLog(_T("\n"));
		WriteLog(csStatus); //write the value of status and file path in log file
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CExportLog::WriteScanStatus"));
	}
#endif
}

/*-------------------------------------------------------------------------------------
Function		: GetLine
In Parameters	: -
Out Parameters	: CString:return string which which hold line
Purpose			: Get the line into string
Author			: Sandip Sanap
Created Date    : 20/09/2006
-------------------------------------------------------------------------------------*/
CString CExportLog::GetLine (void)
{
	CString csWriteLine; //hold the line
	csWriteLine=_T("\n----------------------------------------------------------------------------\n");
	return csWriteLine; //return line to the various function's
}

/*-------------------------------------------------------------------------------------
Function		: WriteLine
In Parameters	: -
Out Parameters	: -
Purpose			: Write  the line
Author			: Sandip Sanap
Created Date    : 13/10/2006
-------------------------------------------------------------------------------------*/
void  CExportLog::WriteLine (void)
{
	CString csWriteLine; //hold the line
	csWriteLine="----------------------------------------------------------------------------\n";
	WriteLog(csWriteLine);
}