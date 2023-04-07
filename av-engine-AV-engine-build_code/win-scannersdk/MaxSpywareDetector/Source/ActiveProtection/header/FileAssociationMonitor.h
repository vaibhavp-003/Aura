/*======================================================================================
   FILE				: FileAssociationMonitor.h
   ABSTRACT			: Module for active monitoring of File Association registry value(s)
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
   CREATION DATE	: 01 Oct 2009
   NOTES			: 
   VERSION HISTORY	: 
=====================================================================================*/
#pragma once
#include "ActiveMonitor.h"

class CFileAssociationMonitor : public CActiveMonitor
{
public:
	CFileAssociationMonitor(void);
	virtual ~CFileAssociationMonitor(void);

	bool StartMonitor();
	bool StopMonitor();
	bool HandleExisting();
	void SetHandler(LPVOID pMessageHandler, LPVOID lpThis);
	bool CheckRegistryEntry(CString &csRegistryEntry, CString &csParentProcessName);

private:
	HANDLE	m_hEvent;

	CTime m_ctLastCallTime;
	bool m_bLastAction;
	CString m_csLastEntry;
	CString m_csLastParentProcessName;
	CString m_csSpyName;
	ACTMON_MESSAGEPROCHANDLER m_pMsgHandler;
	LPVOID m_pThis;

	void CleanUp();
};
