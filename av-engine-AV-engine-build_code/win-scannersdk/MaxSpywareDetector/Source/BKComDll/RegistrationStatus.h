#pragma once
#include "pch.h"
#include "SDSystemInfo.h"

#define EVALUATION_PERIOD		_T("30")
#define EVALUATION_PERIOD_INT	30
#define VERSION					_T("25")

class CRegistrationStatus
{
public:
	CRegistrationStatus();
	~CRegistrationStatus();

public:
	CString csBuyNowPage;
	int m_iRegDaysLeft;
	bool ChkRegStatus();
	REGISTRATION_STATUS GetRegisrationStatus();
	CString RegGetBuyURL();
	CString GetDomainName(CString csRegVal = _T("DomainName"));
};