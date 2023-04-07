
/*======================================================================================
FILE             : DownloadManagerApp.cpp
ABSTRACT         :
DOCUMENTS	     : 
AUTHOR		     : Sandip Sanap
COMPANY		     : Aura 
COPYRIGHT(NOTICE): 
				  (C) Aura
				  Created as an unpublished copyright work.  All rights reserved.
				  This document and the information it contains is confidential and
				  proprietary to Aura.  Hence, it may not be 
				  used, copied, reproduced, transmitted, or stored in any form or by any 
				  means, electronic, recording, photocopying, mechanical or otherwise, 
				  without the prior written permission of Aura.	
CREATION DATE    : 12/28/2009
NOTES		     : Defines the class behaviors for the application
VERSION HISTORY  : 
======================================================================================*/

#include "StdAfx.h"
#include "DownloadManagerApp.h"
#include "Logger.h"
#include "DownloadController.h"
#ifdef _DEBUG

#define new DEBUG_NEW

#undef THIS_FILE

static char THIS_FILE[] = __FILE__;

#endif

CDownloadManagerApp theDownloadManagerApp;
/*--------------------------------------------------------------------------------------
Function       : CDownloadManagerApp
In Parameters  : void, 
Out Parameters :
Description    :constructor
Author         : Sandip Sanap
--------------------------------------------------------------------------------------*/
CDownloadManagerApp::CDownloadManagerApp(void)
{
	m_pIController = NULL;
}

/*--------------------------------------------------------------------------------------
Function       : ~CDownloadManagerApp
In Parameters  : void, 
Out Parameters :
Description    :destructor
Author         : Sandip Sanap
--------------------------------------------------------------------------------------*/
CDownloadManagerApp::~CDownloadManagerApp(void)
{
}

/*--------------------------------------------------------------------------------------
Function       : StartController
In Parameters  : LPVOID pThis, 
Out Parameters : bool
Description    :start controller
Author         : Sandip Sanap
--------------------------------------------------------------------------------------*/
bool CDownloadManagerApp::StartController(LPVOID pThis)
{
	bool bRet = false;
	g_objLogApp.AddLog1(_T("Starting Controller"));
	m_pIController = new CDownloadController();
	if(m_pIController)
	{
		bRet = m_pIController->StartController(pThis);
	}
	return bRet;
}

/*--------------------------------------------------------------------------------------
Function       : StartScanner
In Parameters  : LPVOID pThis, 
Out Parameters : bool
Description    :start the downloader
Author         : Sandip Sanap
--------------------------------------------------------------------------------------*/
bool CDownloadManagerApp::StartScanner(LPVOID pThis)
{
	g_objLogApp.AddLog1(_T("Starting Scanner..."));
	bool bRet = StartController(pThis);
	return bRet;
}

/*--------------------------------------------------------------------------------------
Function       : InitDownloadManagerApp
In Parameters  : void, 
Out Parameters : bool
Description    :
Author         : Sandip Sanap
--------------------------------------------------------------------------------------*/
bool CDownloadManagerApp::InitDownloadManagerApp(void)
{
	return false;
}

/*--------------------------------------------------------------------------------------
Function       : ExitScanner
In Parameters  : void, 
Out Parameters : bool
Description    : exit the controller
Author         : Sandip Sanap
--------------------------------------------------------------------------------------*/
bool CDownloadManagerApp::ExitScanner(void)
{
	if(m_pIController)
	{
		m_pIController->StopController();
	}
	if(m_pIController)
	{
		delete (CDownloadController*)m_pIController;
		m_pIController = NULL;
	}
	return false;
}
