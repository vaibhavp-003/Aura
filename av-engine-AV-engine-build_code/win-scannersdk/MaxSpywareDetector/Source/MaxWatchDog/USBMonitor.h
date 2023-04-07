#pragma once
#include "resource.h"
#include "USBNotify.h"
#include "MaxProtectionMgr.h"

// CUSBMonitor dialog

typedef struct _UserInfo
{
	TCHAR szPassword[50];
	bool  bActivated;
}USER_INFO, *LPUSER_INFO;

class CUSBMonitor : public CDialog
{
	CMaxProtectionMgr m_oMaxProtectionMgr;
	CUSBNotify m_objUsbNotify;
	CString m_csDriverSymbolicPath;

public:
	CUSBMonitor(CWnd* pParent = NULL);   // standard constructor
	virtual ~CUSBMonitor();

// Dialog Data
	enum { IDD = IDD_USB_MONITOR };

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support

	DECLARE_MESSAGE_MAP()
public:
	afx_msg LRESULT OnDeviceChange(WPARAM wParam, LPARAM lParam);

	virtual BOOL OnInitDialog();
};
