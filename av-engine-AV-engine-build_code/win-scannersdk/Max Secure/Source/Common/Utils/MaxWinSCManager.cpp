#include "pch.h"
#include "MaxWinSCManager.h"
#include "WatchDogServiceApp.h"

CMaxWinSCManager::CMaxWinSCManager()
{
	m_iRegister = 0;
}


CMaxWinSCManager::~CMaxWinSCManager()
{
}

BOOL CMaxWinSCManager::RegisterAVwithWSC(LPCTSTR pszProductName, LPCTSTR pszRemediationPath)
{
	BOOL bRetValue = FALSE;

	if (pszProductName == NULL || pszRemediationPath == NULL)
	{
		return bRetValue;
	}

	CComPtr<IUnknown>	spUnknown;
	HRESULT				hr;

	hr = CoInitializeEx(0, COINIT_APARTMENTTHREADED);
	
	hr = CoCreateInstance(CLSID_WscIsv,NULL,CLSCTX_INPROC_SERVER,IID_IUnknown,reinterpret_cast<LPVOID*> (&spUnknown));
	if (SUCCEEDED(hr))
	{
		CComPtr<IWscAVStatus> spAvStatus;

		hr = spUnknown->QueryInterface(IID_IWscAVStatus, reinterpret_cast<void**> (&spAvStatus));
		if (SUCCEEDED(hr))
		{
			CComBSTR bstrProductExe(pszRemediationPath);
			CComBSTR bstrDispName(pszProductName);
			
			hr = spAvStatus->Register(bstrProductExe,bstrDispName,FALSE,FALSE);
			if (SUCCEEDED(hr))
			{
				bRetValue = TRUE;
			}
		}
	}
	return bRetValue;
}

BOOL CMaxWinSCManager::UnRegisterAVwithWSC()
{
	BOOL bRetValue = FALSE;

	CComPtr<IUnknown>	spUnknown;
	HRESULT				hr;

	hr = CoInitializeEx(0, COINIT_APARTMENTTHREADED);
	
	hr = CoCreateInstance(CLSID_WscIsv,NULL,CLSCTX_INPROC_SERVER,IID_IUnknown,reinterpret_cast<LPVOID*> (&spUnknown));
	if (SUCCEEDED(hr))
	{
		CComPtr<IWscAVStatus> spAvStatus;
		hr = spUnknown->QueryInterface(IID_IWscAVStatus, reinterpret_cast<void**> (&spAvStatus));
		if (SUCCEEDED(hr))
		{
			hr = spAvStatus->Unregister();
			if (SUCCEEDED(hr))
			{
				bRetValue = TRUE;
			}
		}
	}
	
	return bRetValue;
}

BOOL CMaxWinSCManager::RegisterAVStatuswithWSC(_WSC_SECURITY_PRODUCT_STATE eProductStaus, BOOL bIsUptoDate)
{
	BOOL				bRetValue = FALSE;
	CComPtr<IUnknown>	spUnknown;
	HRESULT				hr;

	hr = CoInitializeEx(0, COINIT_APARTMENTTHREADED);
	
	hr = CoCreateInstance(CLSID_WscIsv,NULL,CLSCTX_INPROC_SERVER,IID_IUnknown,reinterpret_cast<LPVOID*> (&spUnknown));
	if (SUCCEEDED(hr))
	{
		CComPtr<IWscAVStatus> spAvStatus;
		hr = spUnknown->QueryInterface(IID_IWscAVStatus,reinterpret_cast<void**> (&spAvStatus));
		if (SUCCEEDED(hr))
		{
			hr = spAvStatus->UpdateStatus(eProductStaus,bIsUptoDate);
			if (S_OK == hr)
			{
				bRetValue = TRUE;
			}
			else //if (S_OK == E_file_)
			{
				//CoUninitialize();
				bRetValue = ReRegisterWSC(eProductStaus,bIsUptoDate);
				return bRetValue;
			}
		}
	}
	return bRetValue;
}

BOOL CMaxWinSCManager::RegisterAVSUBStatuswithWSC(int iUpdateSet ,WSC_SECURITY_PRODUCT_SUBSTATUS eProductStaus)
{
	BOOL				bRetValue = FALSE;
	CComPtr<IUnknown>	spUnknown;
	HRESULT				hr;

	hr = CoInitializeEx(0, COINIT_APARTMENTTHREADED);

	hr = CoCreateInstance(CLSID_WscIsv,NULL,CLSCTX_INPROC_SERVER,IID_IUnknown,reinterpret_cast<LPVOID*> (&spUnknown));
	if (SUCCEEDED(hr))
	{
		CComPtr<IWscAVStatus4> spAvStatus;

		hr = spUnknown->QueryInterface(IID_IWscAVStatus4,reinterpret_cast<void**> (&spAvStatus));
		if (SUCCEEDED(hr))
		{
			switch(iUpdateSet)
			{
			case 1:
				hr = spAvStatus->UpdateScanSubstatus(eProductStaus);
				break;

			case 2:
				hr = spAvStatus->UpdateSettingsSubstatus(eProductStaus);
				break;

			case 3:
				hr = spAvStatus->UpdateProtectionUpdateSubstatus(eProductStaus);
				break;
			}
			if (S_OK == hr)
			{
				bRetValue = TRUE;
			}
		}
	}
	return bRetValue;
}

BOOL CMaxWinSCManager::ReRegisterWSC(_WSC_SECURITY_PRODUCT_STATE eProductStaus, BOOL bIsUptoDate)
{
	if(m_iRegister < 1)
	{
		++m_iRegister;
		RegisterAVwithWSC(theApp.m_csProductName,theApp.m_RemediationPath);
		RegisterAVStatuswithWSC(eProductStaus,bIsUptoDate);
		return 1;
	}

	return 0;
}

BOOL CMaxWinSCManager::NotifyExpire(DWORD dwDays)
{
	CComPtr<IUnknown> spUnknown;

	HRESULT				hr;
	BOOL bRetValue = FALSE;

	CoInitializeEx(0, COINIT_APARTMENTTHREADED );
	
	hr = CoCreateInstance(CLSID_WscIsv, NULL, CLSCTX_INPROC_SERVER, IID_IUnknown, reinterpret_cast<LPVOID*> (&spUnknown));
	if(SUCCEEDED(hr))
	{
		CComPtr<IWscAVStatus2> spAvStatus;
		hr = spUnknown->QueryInterface(IID_IWscAVStatus2, reinterpret_cast<void**> (&spAvStatus));
		if(SUCCEEDED(hr))
		{
			hr = spAvStatus->NotifyUserForNearExpiration(dwDays); 
		}
	}
	return bRetValue;
}