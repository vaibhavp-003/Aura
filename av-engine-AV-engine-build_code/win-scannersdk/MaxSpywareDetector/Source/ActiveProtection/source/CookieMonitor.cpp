/*======================================================================================
   FILE				: CookieMonitor.h
   ABSTRACT			: Module for active Protection of Cookie's
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
   CREATION DATE	: 30 Apr 2008
   NOTES			: 
   VERSION HISTORY	:	Resource : sandip
						Description : Handle End Now Conditon on ShutDown
						Version:1.0.0.8
=====================================================================================*/

#include "pch.h"
#include "CookieMonitor.h"
#include "RegistryHelper.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*-------------------------------------------------------------------------------------
	Function		: CCookieMonitor
	In Parameters	: -
	Out Parameters	: -
	Purpose			: CCookieMonitor initialization
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
CCookieMonitor::CCookieMonitor():m_objCookieDB(false),m_objAvailableUsers(false)
{	
}

/*-------------------------------------------------------------------------------------
	Function		: ~CCookieMonitor
	In Parameters	: -
	Out Parameters	: -
	Purpose			: Destructor
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
CCookieMonitor::~CCookieMonitor()
{
	CleanUp();
}

/*-------------------------------------------------------------------------------------
	Function		: StartMonitor
	In Parameters	: -
	Out Parameters	: bool
	Purpose			: Start Cookie Key Monitoring
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
bool CCookieMonitor::StartMonitor()
{
	if(!SetPrivacyAdvancedOn())
	{
		return false;
	}

	m_bIsMonitoring = true;
	return true;
}

bool CCookieMonitor::HandleExisting()
{
	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: StopMonitor
	In Parameters	: -
	Out Parameters	: -
	Purpose			: Stop Cookie Key monitoring
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
bool CCookieMonitor::StopMonitor()
{
	m_bIsMonitoring = false;
	CleanUp();
	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanUp
	In Parameters	: -
	Out Parameters	: -
	Purpose			: frees memory
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
void CCookieMonitor::CleanUp()
{
	if(m_bPCShutDownStatus == false)
	{
		LPVOID pos = m_objCookieDB.GetFirst();
		while(pos)
		{
			LPTSTR szCookie = NULL;
			if(m_objCookieDB.GetKey(pos, szCookie))
			{
				m_objRegistry.DeleteKey(ACTMON_COOKIE_KEY, szCookie, HKEY_LOCAL_MACHINE);
			}
			pos = m_objCookieDB.GetNext(pos);
		}
	}
	m_objCookieDB.RemoveAll();

	DWORD dwData = 0;
	m_objRegistry.Set(ACTMON_INET_SETTING_KEY, ACTMON_PRIVACY_ADV_VAL, dwData, HKEY_LOCAL_MACHINE);

	//VERSION HISTORY	:	Resource: Sid
	//		Description	: ??
	//		Version		: ??
	CStringA csData;
	csData.Format("%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c",
					26, 55, 97, 89, 35, 82, 53, 12, 122, 95, 32, 23, 47, 30,
					26, 25, 14, 43, 1, 115, 19, 55, 19, 18, 20, 26, 21, 42);

	CRegistryHelper objRegHelp;
	LPVOID posUserName = m_objAvailableUsers.GetFirst();
	if( posUserName == NULL )
	{
		objRegHelp.LoadAvailableUsers (m_objAvailableUsers);
	}
	while(posUserName)
	{
		LPTSTR strUserSID = NULL;
		m_objAvailableUsers.GetKey(posUserName, strUserSID);

		CString csKey = (CString)strUserSID + _T("\\") + ACTMON_ZONES_3_KEY;
		if(m_objRegistry.KeyExists(csKey, HKEY_USERS))
		{
			m_objRegistry.Set(csKey, ACTMON_THIRD_PARTY_KEY, (BYTE*)(const char*)csData, 
								(DWORD)csData.GetLength(), REG_BINARY, HKEY_USERS);
		}
		posUserName = m_objAvailableUsers.GetNext(posUserName);
	}
}

/*-------------------------------------------------------------------------------------
	Function		: SetPrivacyAdvancedOn
	In Parameters	: -
	Out Parameters	: true if success else false
	Purpose			: Set the Privacy Indication setting to ON for Internet Explorer for
					  internet zone browsing i.e. Zone 3
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
bool CCookieMonitor::SetPrivacyAdvancedOn()
{
	DWORD dwData = 1;
	if(!m_objRegistry.Set(ACTMON_INET_SETTING_KEY, ACTMON_PRIVACY_ADV_VAL, dwData,
						HKEY_LOCAL_MACHINE))
	{
		return false;
	}

	CStringA csData;
	csData.Format("%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c",
					26, 55, 97, 89, 35, 82, 53, 12, 122, 95, 32, 23, 47, 30,
					26, 25, 14, 43, 1, 115, 19, 55, 19, 18, 20, 26, 21, 57);
	
	if(!m_objRegistry.Set(ACTMON_ZONES_3_KEY, ACTMON_THIRD_PARTY_KEY, (BYTE*)(const char*)csData, 
						(DWORD)csData.GetLength(), REG_BINARY, HKEY_LOCAL_MACHINE))
	{
		return false;
	}

	//VERSION HISTORY	:	Resource: Sid
	//					Description	: ??
	//					Version		: ??
	CRegistryHelper objRegHelp;
	LPVOID posUserName = m_objAvailableUsers.GetFirst();
	if( posUserName == NULL )
	{
		objRegHelp.LoadAvailableUsers (m_objAvailableUsers);
	}
	while(posUserName)
	{
		LPTSTR strUserSID = NULL;
		m_objAvailableUsers.GetKey(posUserName, strUserSID);

		CString csKey = (CString)strUserSID + _T("\\") + ACTMON_ZONES_3_KEY;
		if(m_objRegistry.KeyExists(csKey, HKEY_USERS))
		{
			m_objRegistry.Set(csKey, ACTMON_THIRD_PARTY_KEY, (BYTE*)(const char*)csData, 
							(DWORD)csData.GetLength(), REG_BINARY, HKEY_USERS);
		}
		posUserName = m_objAvailableUsers.GetNext(posUserName);
	}
	return true;
}
