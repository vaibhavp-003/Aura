/*=============================================================================
   FILE			: FileRW.cpp
   ABSTRACT		: Implementation of the CFileRW class.
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
VERSION HISTORY	: 21 Aug 2007, Avinash B
				  Unicode Supported
				  12 Sept 2007, Avinash B : removed CArchive usage
				  17 Oct. 2007 Avinash B: added a method to write scan log since scan log contains local language characters
============================================================================*/

#include "stdafx.h"
#include "FileRW.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*-------------------------------------------------------------------------------------
Function		: OpenLogFile
In Parameters	: CString csFileName :Log File Name
Out Parameters	: bool: Check for LogFile Open,Create or Not available
Purpose			: This function open the log file,if not already exist then create log file
Author			: Sandip Sanap
Created Date	: 20-09-2006
--------------------------------------------------------------------------------------*/
bool CExportFileOperations::OpenLogFile(CString csFileName)
{
	try
	{
		if(!m_objExportFile.Open(csFileName.GetBuffer(),CFile::modeCreate |CFile::modeNoTruncate | CFile::modeWrite))
		{
			csFileName.ReleaseBuffer();
			return false;				//If error occur in opening the Log file then return False
		}
		csFileName.ReleaseBuffer();
		m_objExportFile.SeekToEnd();
		return true;
		//If LogFile open successfully then return true
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CExportFileOperations::OpenLogFile"));
	}
	return false;
}

/*-------------------------------------------------------------------------------------
Function		: CloseLogFile
In Parameters	: -
Out Parameters	: bool:Check Log File close or not
Purpose			: When all operation end's then this function close the log file
Author			: Sandip Sanap
Created Date	: 20-09-2006
--------------------------------------------------------------------------------------*/
bool CExportFileOperations::CloseLogFile()
{
	try
	{
		if(m_objExportFile)
			m_objExportFile.Close();
		return true; //Return true if Log File closes Successfully
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CExportFileOperations::CloseLogFile"));
	}
	return false;
}

/*-------------------------------------------------------------------------------------
Function		: WriteLog
In Parameters	: CString csWriteStr:take value which write in log file
Out Parameters	: -
Purpose			: Write the value of the parameter into the log file
Author			: Sandip Sanap
Created Date	: 21-09-2006
--------------------------------------------------------------------------------------*/
void CExportFileOperations::WriteLog(CString csWriteStr)
{
	try
	{
		if(m_objExportFile)
			m_objExportFile.WriteString(csWriteStr); //write given string value into log file
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CExportFileOperations::WriteLog"));
	}
}

/*-------------------------------------------------------------------------------------
Function		: WriteLog
In Parameters	: CFile& - file
CString - file path
Out Parameters	: void
Purpose			: Write log to file
Author			: Sandip Sanap
Created Date	: 21-09-2006
--------------------------------------------------------------------------------------*/
void CExportFileOperations::WriteLog(CStdioFile& pTempLog, CString csFilePath)
{
	try
	{
		CFileException e;
		CString csReturnStr;
		CStdioFile pExportLog;
		if(!pExportLog.Open(csFilePath, CFile::modeRead, &e))//Reading
			return;
		else
		{
			csReturnStr = _T("");
			while(pExportLog.ReadString(csReturnStr))
			{ 
				csReturnStr = _T("\n") + csReturnStr; //For all lines of the file
				pTempLog.SeekToEnd();
				pTempLog.WriteString((LPCTSTR)csReturnStr);
			}
			pExportLog.Close();
		}
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CExportFileOperations::WriteLog"));
	}
}

/*-------------------------------------------------------------------------------------
Function		: GetLine
In Parameters	: -
Out Parameters	: CString:return string which which hold line
Purpose			: Get the line into string
Author			: Sandip Sanap
Created Date    : 20/09/2006
-------------------------------------------------------------------------------------*/
CString CExportFileOperations::GetLine (void)
{
	try
	{
		CString csWriteLine; //hold the line
		csWriteLine=_T("----------------------------------------------------------------------------\n");
		return csWriteLine; //return line to the various function's
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CExportFileOperations::GetLine"));
	}
	return _T("");
}

/*-------------------------------------------------------------------------------------
Function		: WriteLine
In Parameters	: -
Out Parameters	: -
Purpose			: Write  the line
Author			: Sandip Sanap
Created Date    : 13/10/2006
-------------------------------------------------------------------------------------*/

void  CExportFileOperations::WriteLine (void)
{
	try
	{
		CString csWriteLine; //hold the line
		csWriteLine=_T("----------------------------------------------------------------------------\n");
		WriteLog(csWriteLine);
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CExportFileOperations::WriteLine"));
	}
}

/*-------------------------------------------------------------------------------------
Function		: WriteToFile
In Parameters	: HANDLE fileHandle: handle to open file
CString csDataToWrite: data to write
Out Parameters	: none
Purpose			: writes unicode characters to opened file.
Author			: Avinash Bhardwaj
--------------------------------------------------------------------------------------*/
void CExportFileOperations::WriteToFile(HANDLE fileHandle, CString csDataToWrite)
{
	try
	{
		if(fileHandle)
		{
			DWORD nBytesWritten = 0;
			//getting the size of the file in bytes.
			DWORD dwFileSize = 0,dwFile;
			dwFileSize = GetFileSize(fileHandle,&dwFile);
			//setting the file pointer to the end of the file.
			SetFilePointer(fileHandle,dwFileSize,NULL,FILE_BEGIN);
			WriteFile(fileHandle,csDataToWrite.GetBuffer(),(csDataToWrite.GetLength())*2,&nBytesWritten,NULL);
			csDataToWrite.ReleaseBuffer();
		}
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CExportFileOperations::WriteToFile"));
	}
}

/*-------------------------------------------------------------------------------------
Function		: WriteScanLog
In Parameters	: HANDLE fileHandle: handle to open file
CString csFilePath: path of the scan log
Out Parameters	: none
Purpose			: writes unicode characters to opened file.
Author			: Avinash Bhardwaj
--------------------------------------------------------------------------------------*/
void CExportFileOperations::WriteScanLog(HANDLE hFileHandle,CString csFilePath)
{
	try
	{
		CFileException e;
		CString csReturnStr;
		CStdioFile pExportLog;

		if(!pExportLog.Open(csFilePath, CFile::modeRead, &e))//Reading
			return;
		else
		{
			CArchive ArForWrmExp(&pExportLog, CArchive::load);
			csReturnStr = _T("");
			while(ArForWrmExp.ReadString(csReturnStr))
			{ 
				csReturnStr = _T("\r\n") + csReturnStr; //For all lines of the file
				WriteToFile(hFileHandle,csReturnStr);
			}
			ArForWrmExp.Flush();
			ArForWrmExp.Close();
			pExportLog.Close();
		}
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CExportFileOperations::WriteScanLog"));
	}
}