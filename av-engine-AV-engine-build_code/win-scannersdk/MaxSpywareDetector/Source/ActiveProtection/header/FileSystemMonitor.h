/*======================================================================================
   FILE				: FileSystemMonitor.h
   ABSTRACT			: Module for monitoring the file system changes
   DOCUMENTS		: 
   AUTHOR			: Darshan Singh Virdi
   COMPANY			: Aura 
   COPYRIGHT NOTICE	: (C) Aura
      				  Created as an unpublished copyright work.  All rights reserved.
     				  This document and the information it contains is confidential and
      				  proprietary to Aura.  Hence, it may not be 
      				  used, copied, reproduced, transmitted, or stored in any form or by any 
      				  means, electronic, recording, photocopying, mechanical or otherwise, 
      				  without the prior written permission of Aura
   CREATION DATE	: 25 Sep 2009
   NOTES			: 
   VERSION HISTORY	: 
=====================================================================================*/

#pragma once
#include "ActiveMonitor.h"
#include "S2U.h"

class CFileSystemMonitor : public CActiveMonitor
{
public:
	CFileSystemMonitor(void);
	virtual ~CFileSystemMonitor(void);

	bool StartMonitor();
	bool StopMonitor();
	bool HandleExisting();
	void SetHandler(LPVOID pMessageHandler, LPVOID lpThis);
	bool CheckFileEntry(CString &csFileEntry, CString &csParentProcessName, int iTypeOfCall);

private:
	CString m_csSunBeltSetup;
	CString m_csWindowsInstaller;
	CString m_csOurMainUI;
	HANDLE	m_hEvent;
	ACTMON_MESSAGEPROCHANDLER m_pMsgHandler;
	LPVOID m_pThis;

	void CleanUp();
};
