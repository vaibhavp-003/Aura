// USBMonitor.cpp : implementation file
//
#include "pch.h"
#include "USBMonitor.h"
#include "CPUInfo.h"
#include "EnumProcess.h"
#include "S2S.h"
#include "WatchDogServiceApp.h"
#include "BufferToStructure.h"
#include "SDSystemInfo.h"

CUSBMonitor::CUSBMonitor(CWnd* pParent /*=NULL*/) : CDialog(CUSBMonitor::IDD, pParent)
{
}

CUSBMonitor::~CUSBMonitor()
{
}

void CUSBMonitor::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CUSBMonitor, CDialog)
	ON_MESSAGE(WM_DEVICECHANGE, OnDeviceChange)
END_MESSAGE_MAP()

BOOL CUSBMonitor::OnInitDialog()
{
	CDialog::OnInitDialog();

	ModifyStyleEx(WS_EX_APPWINDOW, WS_EX_TOOLWINDOW);
	SetWindowPos(NULL, 0, 0, 0, 0, SWP_FRAMECHANGED|SWP_NOZORDER|SWP_NOMOVE|SWP_NOSIZE);
	this->MoveWindow(0, 0, 0, 0);

	m_objUsbNotify.RegisterNotification(m_hWnd);

	return TRUE;  // return TRUE unless you set the focus to a control
}

// CUSBMonitor message handlers
LRESULT CUSBMonitor::OnDeviceChange(WPARAM wParam, LPARAM lParam)
{
	if(DBT_DEVICEARRIVAL == wParam)
	{
		PDEV_BROADCAST_HDR pHdr = (PDEV_BROADCAST_HDR)lParam;
		PDEV_BROADCAST_DEVICEINTERFACE pDevInf;
		PDEV_BROADCAST_VOLUME pDevVolume;
		switch(pHdr->dbch_devicetype)
		{
		case DBT_DEVTYP_DEVICEINTERFACE:
			pDevInf = (PDEV_BROADCAST_DEVICEINTERFACE)pHdr;
			m_objUsbNotify.ChangeDeviceNotification(pDevInf, wParam);
			break;

		case DBT_DEVTYP_VOLUME:
			pDevVolume = (PDEV_BROADCAST_VOLUME)pHdr;
			if(m_objUsbNotify.IsUSBDevice())
			{
				CString csDrv = m_objUsbNotify.GetDriveLetter(pDevVolume->dbcv_unitmask);
				ULONG uDriveType = GetDriveType(csDrv);
				if(uDriveType == DRIVE_REMOVABLE || uDriveType == DRIVE_FIXED)
				{
					CString csDBPass = _T("");
					CS2S objSPass(false);
					LPVOID lpDBPass = 0;
					CString csFilePath = theApp.m_strAppPath;
					csFilePath += _T("\\");
					csFilePath +=FWDATA_USERPASSDB;
					/*bool bRet = objSPass.Load(csFilePath);
					if(bRet)
					{
						LPTSTR szData;
						lpDBPass = objSPass.GetFirst();
						if(lpDBPass)
						{
							if(objSPass.GetData(lpDBPass, szData))
							{
								csDBPass = szData;
							}
						}
					}*/
					//DWORD dwVal = 0;
					//CRegistry objReg;
					//objReg.Get(CSystemInfo::m_csProductRegKey, PASSWORD_USB, dwVal, HKEY_LOCAL_MACHINE);
					//LPUSER_INFO lpUserInfo = NULL;
					//CBufferToStructure objBuffToStruct(false, 20 * 2, sizeof(USER_INFO));
					//if(objBuffToStruct.Load(csFilePath))
					//{
					//	TCHAR szKey[20] = {0};
					//	szKey[0] = L'1';
					//	szKey[1] = L'\0';
					//	if(objBuffToStruct.SearchItem(szKey, (LPVOID&)lpUserInfo))
					//	{
					//		if(lpUserInfo)
					//		{
					//			csDBPass.Format(L"%s",lpUserInfo->szPassword);
					//		}
					//	}
					//	//return (false);
					//}
					//if(csDBPass.Trim().GetLength() == 0 || dwVal == 0)
					//{
					//	return 0;
					//}
					CEnumProcess oEnumProc;
					if(!oEnumProc.IsProcessRunning(_T("AuTray.exe"), false, false, false))
					{
						m_oMaxProtectionMgr.BlockDriverLetter(csDrv);
					}
				}
			}
			break;
		}
	}
	else if(DBT_DEVICEREMOVECOMPLETE == wParam)
	{
		PDEV_BROADCAST_HDR pHdr = (PDEV_BROADCAST_HDR)lParam;
		PDEV_BROADCAST_VOLUME pDevVolume;
		switch(pHdr->dbch_devicetype)
		{
		case DBT_DEVTYP_VOLUME:
			{
				pDevVolume = (PDEV_BROADCAST_VOLUME)pHdr;
				CString csDrv = m_objUsbNotify.GetDriveLetter(pDevVolume->dbcv_unitmask);
				m_oMaxProtectionMgr.DisconnectDriverLetter(csDrv);
			}
			break;
		}
	}
	return 0;
}
