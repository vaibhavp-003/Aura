/*======================================================================================
FILE             : FolderScan.h
ABSTRACT         : declares a class to scan folders using a files scanned list
DOCUMENTS	     : 
AUTHOR		     : Anand Srivastava
COMPANY		     : Aura 
COPYRIGHT(NOTICE): 
				  (C) Aura
				  Created as an unpublished copyright work.  All rights reserved.
				  This document and the information it contains is confidential and
				  This document and the information it contains is confidential and
				  proprietary to Aura.  Hence, it may not be 
				  used, copied, reproduced, transmitted, or stored in any form or by any 
				  means, electronic, recording, photocopying, mechanical or otherwise, 
				  without the prior written permission of Aura.	
				  
CREATION DATE    : 4/March/2010 9:57 P
NOTES		     : Defines the class behaviors for the application
VERSION HISTORY  : 
======================================================================================*/
#pragma once

#include "MaxConstant.h"
#include "S2U.h"
#include "U2OS2U.h"
#include "U2OU2O.h"
#include "DBPathExpander.h"
#include "Registry.h"

class CFolderScan
{
public:

	CFolderScan();
	~CFolderScan();

	bool AddToScannedList(LPCTSTR szScannedFilePath, DWORD dwSpyID);
	bool StartFolderScan(SENDMESSAGETOUIMS lpSendMessageToUI, const CString &csMaxDBPath);
	void SetReporter(SENDMESSAGETOUIMS lpSendMessageToUI);

private:

	CS2U				m_objScannedList;
	CU2OU2O				m_objFolderDBMap;
	CRegistry			m_objRegistry;
	CDBPathExpander		m_objDBPathExpander;
	SENDMESSAGETOUIMS		m_lpSendMessageToUI;
	bool				m_bScanStarted;

	bool EnumerateAndReportFolder(LPCTSTR szPath, DWORD dwSpyID);
};
