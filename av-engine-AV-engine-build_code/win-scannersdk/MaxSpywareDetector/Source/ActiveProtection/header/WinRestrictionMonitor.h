/*======================================================================================
   FILE				: WinRestrictionMonitor.h
   ABSTRACT			: Module for active monitoring of Windows Restriction registry value
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
   CREATION DATE	: 05 Feb 2008
   NOTES			: 
   VERSION HISTORY	: 
=====================================================================================*/
#pragma once
#include "ActiveMonitor.h"

class CWinRestrictionMonitor : public CActiveMonitor
{
public:
	CWinRestrictionMonitor(void);
	virtual ~CWinRestrictionMonitor(void);

	bool StartMonitor();
	bool StopMonitor();
	bool HandleExisting();
	void SetHandler(LPVOID pMessageHandler, LPVOID lpThis);
	bool CheckRegistryEntry(CString &csRegistryEntry, CString &csParentProcessName);

private:
	HANDLE	m_hEvent;

	DWORD m_ulSpyID;
	LPCTSTR m_WRMKey ;
	LPVOID m_pThis;
	ACTMON_MESSAGEPROCHANDLER m_pMsgHandler;
	CMapStringToString  m_objMapStrToStr;

	void CleanUp();
	bool CheckForOldEntry(CString csFullPath, CString &csMainPath, CString csData, CString csUserSID,
							CString csValue,  bool & bAddNewEntry);
};
