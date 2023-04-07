/*======================================================================================
   FILE			: RegistryHelper.h
   ABSTRACT		: This class provides add-on functionality to registry functions
   DOCUMENTS	: 
   AUTHOR		: Anand Srivastava
   COMPANY		: Aura 
COPYRIGHT NOTICE:
				(C) Aura
				Created as an unpublished copyright work.  All rights reserved.
				This document and the information it contains is confidential and
				proprietary to Aura.  Hence, it may not be 
				used, copied, reproduced, transmitted, or stored in any form or by any 
				means, electronic, recording, photocopying, mechanical or otherwise, 
				with out the prior written permission of Aura
   CREATION DATE: 03/03/2010
   NOTES		: Implements registry enumeration and reporting to UI functions
======================================================================================*/
#pragma once
#include "Registry.h"
#include "S2S.h"
#include "DBPathExpander.h"

class CRegistryHelper
{
public:
	CRegistryHelper();
	virtual ~CRegistryHelper();

	void GetAllComEntries(const CString csCLSID, ULONG ulSpyNameID);
	void EnumKeyNReportToUI(HKEY hHiveKey, LPCWSTR wcsMainKey, ULONG ulSpyNameID);
	void SetReporter(SENDMESSAGETOUIMS lpSendMessaegToUI);
	void LoadAvailableUsers(CS2S& objAvailableUsers);
	void GetAlreadyLoadedProfilePath(CS2S& objLoadedUsers);

private:

	CRegistry		m_objReg;
	SENDMESSAGETOUIMS m_lpSendMessaegToUI;
	CS2S			m_objAvailableUsers;
	CDBPathExpander	m_objDBPathExpander;

	void SendScanStatusToUI(SD_Message_Info eTypeOfScanner, const ULONG ulSpyName,
							HKEY Hive_Type, const TCHAR *strKey, const TCHAR *strValue,
							int Type_Of_Data, LPBYTE lpbData, int iSizeOfData,
							REG_FIX_OPTIONS *psReg_Fix_Options, LPBYTE lpbReplaceData,
							int iSizeOfReplaceData);
};

