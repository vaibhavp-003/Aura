/*=============================================================================
   FILE			: InternetOperation.cpp
   DESCRIPTION	: This class provides the functionality related with the Internet http operations
   DOCUMENTS	: 
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
CREATION DATE   : 22-12-2007
   NOTES		:
VERSION HISTORY	:
============================================================================*/
#include <afxinet.h>
#include "StdAfx.h"
#include "InternetOperation.h"
#include "SDSystemInfo.h"

const INTERNET_PORT  FTP_PORT = 21;

/*-------------------------------------------------------------------------------------
Function		: CInternetOperation
In Parameters	: void
Out Parameters	: void
Purpose			: CInternetOperation constructor
Author			: sandip sanap
--------------------------------------------------------------------------------------*/
CInternetOperation::CInternetOperation(void)
{
}

/*-------------------------------------------------------------------------------------
Function		: ~CInternetOperation
In Parameters	: void
Out Parameters	: void
Purpose			: COperationOnRestart destructor
Author			: sandip sanap
--------------------------------------------------------------------------------------*/
CInternetOperation::~CInternetOperation(void)
{
}

/*-------------------------------------------------------------------------------------
Function		: CheckInternetConnection
In Parameters	: -
Out Parameters	: BOOL	 - TRUE / FALSE
Purpose			: Check for internet connection
Author			:  Dipali
--------------------------------------------------------------------------------------*/
BOOL CInternetOperation::CheckInternetConnection()
{
	CStringArray csPingSiteArr;
	csPingSiteArr.Add(MAX_CHECK_INTERNET_CONNECTION_1);
	csPingSiteArr.Add(MAX_CHECK_INTERNET_CONNECTION_2);
	
	for(int i = 0; i < csPingSiteArr.GetCount(); i++)
	{
		if(InternetCheckConnection(csPingSiteArr.GetAt(i), FLAG_ICC_FORCE_CONNECTION, 0))
		{
			return TRUE;
		}
	}
	return FALSE;
}

/*-------------------------------------------------------------------------------------
Function		: DownloadFile
In Parameters	: const TCHAR *url - URL
const TCHAR *filename - Destination Filename
Out Parameters	: BOOL
Purpose			: Download file from given url to destination
Author			: Dipali Pawar
--------------------------------------------------------------------------------------*/
bool CInternetOperation::DownloadFile(const TCHAR *url, const TCHAR *filename)
{
	CString csServerName;
	CString csCurrentDirectory = FTP_DIR_NAME;

	CString csObject;
	DWORD dwServiceType;
	INTERNET_PORT nPort;

	if(!AfxParseURL(url, dwServiceType, csServerName, csObject, nPort))
		return false;

	int nPos = csObject.ReverseFind('/');
	if(nPos != -1)
		csCurrentDirectory = csObject.Left(nPos+1);

	CFtpConnection* pConn = NULL;
	try
	{
		CInternetSession Session(_T("ServerVersion.txt Session"));
		// when reducing the timeout connection, the internet connection speed is faster.
		int nConnectionTimeout = 60000;
		Session.SetOption(INTERNET_OPTION_CONNECT_TIMEOUT, nConnectionTimeout);
		Session.SetOption(INTERNET_OPTION_RECEIVE_TIMEOUT, nConnectionTimeout);
		Session.SetOption(INTERNET_OPTION_SEND_TIMEOUT, nConnectionTimeout);

		int x=0;
		do
		{
			pConn = Session.GetFtpConnection(csServerName,FTP_USER_NAME,FTP_PASSWORD,FTP_PORT,TRUE);
			x++;
		}
		while(pConn == NULL && x<2); //Reatempt to connect
		if(!pConn)
		{
			return false;
		}
		pConn->SetCurrentDirectory(csCurrentDirectory);

		if(pConn->GetFile(INI_FILE_NAME, filename,false) == FALSE)
		{
			Session.Close();
			if(pConn  != NULL)
				pConn ->Close();
			delete pConn;
			pConn = NULL;
			return false;
		}
		Session.Close();
		if(pConn  != NULL)
			pConn ->Close();
		delete pConn;
		pConn = NULL;
	}
	catch (CInternetException* pEx)
	{
		TCHAR szStatus[MAX_PATH] = {0};
		pConn = NULL;
		pEx->GetErrorMessage(szStatus, _countof(szStatus));
		pEx->Delete();
		AddLogEntry(szStatus);
		return false;
	}
	return true;
}