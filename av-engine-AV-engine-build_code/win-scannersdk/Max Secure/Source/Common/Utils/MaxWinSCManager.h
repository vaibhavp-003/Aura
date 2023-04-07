#pragma once
#include "wscisvapi.h"

class CMaxWinSCManager
{
public:
	CMaxWinSCManager();
	~CMaxWinSCManager();
	BOOL	RegisterAVwithWSC(LPCTSTR pszProductName, LPCTSTR pszRemediationPath);
	BOOL	RegisterAVStatuswithWSC(_WSC_SECURITY_PRODUCT_STATE iProductStaus, BOOL bIsUptoDate);
	BOOL	RegisterAVSUBStatuswithWSC(int iUpdateSet, WSC_SECURITY_PRODUCT_SUBSTATUS eProductStaus);
	BOOL	UnRegisterAVwithWSC();
	BOOL	ReRegisterWSC(_WSC_SECURITY_PRODUCT_STATE eProductStaus, BOOL bIsUptoDate);
	BOOL	NotifyExpire(DWORD dwDays =0);
	CString	m_csProductName;
	CString m_RemediationPath;
	int		m_iRegister;
	
};

