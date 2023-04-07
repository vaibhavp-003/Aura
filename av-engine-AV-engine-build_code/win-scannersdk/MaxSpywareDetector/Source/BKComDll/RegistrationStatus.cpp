#include "pch.h"
#include "RegistrationStatus.h"

CRegistrationStatus::CRegistrationStatus()
{

}

CRegistrationStatus::~CRegistrationStatus()
{

}

bool CRegistrationStatus::ChkRegStatus()
{
	bool bRetStatus = false;

	REGISTRATION_STATUS eStatus = GetRegisrationStatus();
	if (eStatus == STATUS_REGISTERED_COPY)
	{
		bRetStatus = true;
	}
	return bRetStatus;
}

CString CRegistrationStatus::GetDomainName(CString csRegVal)
{
	CString csDomainName;
	CRegistry objReg;
	objReg.Get(CSystemInfo::m_csProductRegKey, csRegVal, csDomainName, HKEY_LOCAL_MACHINE);

	return csDomainName;
}


REGISTRATION_STATUS CRegistrationStatus::GetRegisrationStatus()
{
	
	/*
	CString csBuyNow = RegGetBuyURL();
	if (csBuyNow.IsEmpty())
		csBuyNowPage = GetDomainName(BUYNOWPAGE);
	else
		csBuyNowPage = csBuyNow;

	//subscription expired or 15 days left
	if ((m_iRegDaysLeft <= EVALUATION_PERIOD_INT && m_iRegDaysLeft > 0)
		|| (m_iRegDaysLeft == IS_SUBSCRIPTION_EXPIRED))
	{
		CString csVoucher, csLink;
		CRegistry objReg;
		objReg.Get(CSystemInfo::m_csVoucherKey, _T("VoucherNo"), csVoucher, HKEY_LOCAL_MACHINE);
		CString csRenewNow = RegGetBuyURL();
		if (csRenewNow.IsEmpty())
		{
			csRenewNow = RENEW_URL;
			csLink += csRenewNow;
			csLink += csVoucher;
			objReg.Get(CSystemInfo::m_csProductRegKey, _T("VendorName"), csVoucher, HKEY_LOCAL_MACHINE);
			csLink = csLink + _T("&P2=") + csVoucher;
		}
		else
		{
			csLink = csRenewNow;
		}

		csBuyNowPage = csLink;
	}

	if (CSDUINew::m_iControlFlag == IS_REGISTERED_COPY)
	{
		// subscription expired or 30 days left
		if ((m_iRegDaysLeft <= EVALUATION_PERIOD_INT && m_iRegDaysLeft > 0)
			|| (m_iRegDaysLeft == IS_SUBSCRIPTION_EXPIRED))
		{
			// 30 days left
			if (m_iRegDaysLeft <= EVALUATION_PERIOD_INT && m_iRegDaysLeft > 0)
			{
				return STATUS_30_DAYS_REMAINING;
			}
			else	// subscription expired
			{
				return STATUS_SUBSCRIPTION_EXPIRED;
			}
		}
		else //register copy, hide all ads
		{
			return STATUS_REGISTERED_COPY;
		}
	}
	else
	{
		// subscription expired or 30 days left
		if ((m_iRegDaysLeft <= EVALUATION_PERIOD_INT && m_iRegDaysLeft > 0)
			|| (m_iRegDaysLeft == IS_SUBSCRIPTION_EXPIRED))
		{
			// 30 days left
			if (m_iRegDaysLeft <= EVALUATION_PERIOD_INT && m_iRegDaysLeft > 0)
			{
				return STATUS_30_DAYS_REMAINING;
			}
			else	// subscription expired
			{
				return STATUS_SUBSCRIPTION_EXPIRED;
			}
		}

		// Trial period
		if (CSystemInfo::m_iVirusScanFlag)
		{
			if (m_iNoofDays > IS_EVALUATION_EXPIRED)
			{
				if (m_iNoofDays <= EVALUATION_PERIOD_INT)
				{
					return STATUS_TRIAL_COPY;
				}
			}
		}
	}
	return STATUS_UNREGISTERED_COPY;

	*/
	bool bStatus = false;
	if (bStatus == true)
	{
		return STATUS_REGISTERED_COPY;
	}
	else
	{
		return STATUS_UNREGISTERED_COPY;
	}
}

CString CRegistrationStatus::RegGetBuyURL()
{
	CString csBuyURL = _T("");
	
	return csBuyURL;
}