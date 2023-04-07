
/*======================================================================================
FILE             : USBNotify.cpp
ABSTRACT         : 
DOCUMENTS	     : 
AUTHOR		     : Dipali Pawar
COMPANY		     : Aura 
COPYRIGHT(NOTICE): 
				  (C) Aura
				  Created as an unpublished copyright work.  All rights reserved.
				  This document and the information it contains is confidential and
				  proprietary to Aura.  Hence, it may not be 
				  used, copied, reproduced, transmitted, or stored in any form or by any 
				  means, electronic, recording, photocopying, mechanical or otherwise, 
				  without the prior written permission of Aura.	
CREATION DATE    : 2 Feb, 2010.
NOTES		     : Defines the class behaviors for the application
VERSION HISTORY  : 
======================================================================================*/
#include "pch.h"
#include "USBNotify.h"


/*--------------------------------------------------------------------------------------
Function       : CUSBNotify
In Parameters  : 
Out Parameters : 
Description    : Constrcutor
Author         : Dipali Pawar
--------------------------------------------------------------------------------------*/
CUSBNotify::CUSBNotify()
{
	m_bIsUSBDevice = false;
	wmemset(m_strDriverLetter, 0, 10);
	::ZeroMemory(&m_hDevNotify, sizeof(HDEVNOTIFY) * 10);
}

/*--------------------------------------------------------------------------------------
Function       : ~CUSBNotify
In Parameters  : void, 
Out Parameters : 
Description    : Destructor
Author         : Dipali Pawar
--------------------------------------------------------------------------------------*/
CUSBNotify::~CUSBNotify(void)
{
	UnRegisterNotification();
}

/*--------------------------------------------------------------------------------------
Function       : RegisterNotification
In Parameters  : HWND hWnd, 
Out Parameters : bool 
Description    : Register Device notification, to get USB mount notification.
Author         : Dipali Pawar
--------------------------------------------------------------------------------------*/
bool CUSBNotify::RegisterNotification(HWND hWnd)
{
	m_hParentHwnd = hWnd;
	DEV_BROADCAST_DEVICEINTERFACE NotificationFilter;
	ZeroMemory(&NotificationFilter, sizeof(NotificationFilter));
	NotificationFilter.dbcc_size = sizeof(DEV_BROADCAST_DEVICEINTERFACE);
	NotificationFilter.dbcc_devicetype = DBT_DEVTYP_DEVICEINTERFACE;
	for(int i = 0; i<sizeof(GUID_DEVINTERFACE_LIST)/sizeof(GUID); i++)
	{
		NotificationFilter.dbcc_classguid = GUID_DEVINTERFACE_LIST[i];
		m_hDevNotify[i] = RegisterDeviceNotification(m_hParentHwnd, &NotificationFilter, DEVICE_NOTIFY_WINDOW_HANDLE);
		if(!m_hDevNotify[i])
		{
			AddLogEntry(_T("Can't register device notification: "));
			return false;
		}
	}
	return true;
}

/*--------------------------------------------------------------------------------------
Function       : UnRegisterNotification
In Parameters  : 
Out Parameters : bool 
Description    : Unregister notification.
Author         : Dipali Pawar
--------------------------------------------------------------------------------------*/
bool CUSBNotify::UnRegisterNotification()
{
	bool bRet = false;
	for(int i = 0; i<sizeof(GUID_DEVINTERFACE_LIST)/sizeof(GUID); i++)
	{
		if(m_hDevNotify[i])
		{
			if(UnregisterDeviceNotification(m_hDevNotify[i]))
			{
				bRet = true;
			}
		}
	}
	return bRet;
}

/*--------------------------------------------------------------------------------------
Function       : ChangeDeviceNotification
In Parameters  : PDEV_BROADCAST_DEVICEINTERFACE pDevInf, WPARAM wParam, 
Out Parameters : void 
Description    : This funciotn will call on Device mount. Check type of device.
				 If it is USB, we have to scan it.
Author         : Dipali Pawar
--------------------------------------------------------------------------------------*/
void CUSBNotify::ChangeDeviceNotification(PDEV_BROADCAST_DEVICEINTERFACE pDevInf, WPARAM wParam)
{
	// pDevInf->dbcc_name:
	// \\?\USB#Vid_04e8&Pid_503b#0002F9A9828E0F06#{a5dcbf10-6530-11d2-901f-00c04fb951ed}
	// szDevId: USB\Vid_04e8&Pid_503b\0002F9A9828E0F06
	// szClass: USB
	ASSERT(lstrlen(pDevInf->dbcc_name) > 4);
	CString szDevId = pDevInf->dbcc_name+4;
	int idx = szDevId.ReverseFind(_T('#'));
	ASSERT(-1 != idx);
	szDevId.Truncate(idx);
	szDevId.Replace(_T('#'), _T('\\'));
	szDevId.MakeUpper();

	CString szClass;
	idx = szDevId.Find(_T('\\'));
	ASSERT(-1 != idx);
	szClass = szDevId.Left(idx);
	CString szLog;

	CString szTmp;
	if(DBT_DEVICEARRIVAL == wParam)
	{
		szTmp.Format(_T("Adding %s\r\n"), szDevId.GetBuffer());
	}
	else
	{
		m_bIsUSBDevice = false;
		szTmp.Format(_T("Removing %s\r\n"), szDevId.GetBuffer());
		return;
	}

	// seems we should ignore "ROOT" type....
	if(_T("ROOT") == szClass)
	{
		return;
	}
	if(_T("USB") == szClass)
	{
		m_bIsUSBDevice = true;
	}
}

/*--------------------------------------------------------------------------------------
Function       : GetDriveLetter
In Parameters  : int iMask, 
Out Parameters : TCHAR* 
Description    : Get driver letter for USB drive for scanning
Author         : Dipali Pawar
--------------------------------------------------------------------------------------*/
TCHAR* CUSBNotify::GetDriveLetter(int iMask)
{
	TCHAR chLetter;
	TCHAR strDrives[] = _T("ABCDEFGHIJKLMNOPQRSTUVWXYZ");

	UINT iCnt = 0;
	int iPos = iMask / 2;
	while (iPos != 0)
	{
		// while there is any bit set in the mask
		// shift it to the righ...
		iPos = iPos / 2;
		iCnt++;
	}

	if(iCnt < _tcslen(strDrives))
	{
		chLetter = strDrives[iCnt];
	}
	else
	{
		chLetter = '?';
	}

	if(chLetter != '?')
	{
		swprintf_s(m_strDriverLetter, 10, _T("%c:"), chLetter);
	}
	return m_strDriverLetter;
}
