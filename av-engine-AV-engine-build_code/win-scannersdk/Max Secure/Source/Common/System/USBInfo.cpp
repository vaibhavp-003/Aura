#include "pch.h"
#include "USBInfo.h"
#include "MaxExceptionFilter.h"
CUSBInfo::CUSBInfo(void)
{
	pSvc = NULL;
	pLoc = NULL;
	InitializeCOM();
}

CUSBInfo::~CUSBInfo(void)
{
	DeinitializeCOM();
}
BOOL CUSBInfo::InitializeCOM()
{

	m_hres =  CoInitializeEx(0,COINIT_MULTITHREADED);

	if(m_hres != RPC_E_CHANGED_MODE)
	{

	// Step 2: --------------------------------------------------
	// Set general COM security levels --------------------------

	m_hres =  CoInitializeSecurity(
		NULL, 
		-1,                          // COM authentication
		NULL,                        // Authentication services
		NULL,                        // Reserved
		RPC_C_AUTHN_LEVEL_DEFAULT,   // Default authentication 
		RPC_C_IMP_LEVEL_IMPERSONATE, // Default Impersonation  
		NULL,                        // Authentication info
		EOAC_NONE,                   // Additional capabilities 
		NULL                         // Reserved
		);


				if (FAILED(m_hres))
				{     
					CoUninitialize();
				}
	

	}
	// Step 3: ---------------------------------------------------
	// Obtain the initial locator to WMI -------------------------


	m_hres = CoCreateInstance(
		CLSID_WbemLocator,             
		0, 
		CLSCTX_INPROC_SERVER, 
		IID_IWbemLocator, (LPVOID *) &pLoc);

	if (FAILED(m_hres))
	{        
		CoUninitialize();
		return false;                 // Program has failed.
	}
	// Step 4: -----------------------------------------------------
	// Connect to WMI through the IWbemLocator::ConnectServer method


	// Connect to the root\cimv2 namespace with
	// the current user and obtain pointer pSvc
	// to make IWbemServices calls.
	m_hres = pLoc->ConnectServer(
		_bstr_t(L"ROOT\\CIMV2"), // Object path of WMI namespace
		NULL,                    // User name. NULL = current user
		NULL,                    // User password. NULL = current
		0,                       // Locale. NULL indicates current
		NULL,                    // Security flags.
		0,                       // Authority (for example, Kerberos)
		0,                       // Context object 
		&pSvc                    // pointer to IWbemServices proxy
		);

	if (FAILED(m_hres))
	{       
		if(pSvc)
		{
			pSvc->Release();
			pSvc = NULL;
		}

		CoUninitialize();
		return false;                // Program has failed.
	}



	// Step 5: --------------------------------------------------
	// Set security levels on the proxy -------------------------

	m_hres = CoSetProxyBlanket(
		pSvc,                        // Indicates the proxy to set
		RPC_C_AUTHN_WINNT,           // RPC_C_AUTHN_xxx
		RPC_C_AUTHZ_NONE,            // RPC_C_AUTHZ_xxx
		NULL,                        // Server principal name 
		RPC_C_AUTHN_LEVEL_CALL,      // RPC_C_AUTHN_LEVEL_xxx 
		RPC_C_IMP_LEVEL_IMPERSONATE, // RPC_C_IMP_LEVEL_xxx
		NULL,                        // client identity
		EOAC_NONE                    // proxy capabilities 
		);
	if (FAILED(m_hres))
	{       
		if(pSvc)
		{
			pSvc->Release();
			pSvc = NULL;
		}

		if(pLoc)
		{
			pLoc->Release();
			pLoc = NULL;
		}	   
		CoUninitialize();
		return false;               
	}

}
void CUSBInfo::DeinitializeCOM()
{	
	if(pSvc)
	pSvc->Release();
	if(pLoc)
	pLoc->Release();   	
	CoUninitialize();
}
CString CUSBInfo::ExtractRemovableDrivesInfo(CString csCaption)
{
	try
	{
		char czQuery[MAX_PATH] = {0};
		char czCaption[3]={0};
		wchar_t tmp[1024];
		char query[1024];
		wcstombs(czCaption,csCaption,MAX_PATH);
		CString csSerialNumber(L"");
		sprintf(czQuery,"SELECT * FROM Win32_LogicalDisk where Caption='%s'",czCaption);
		IEnumWbemClassObject* pEnumerator = NULL;
		IEnumWbemClassObject* pEnumerator1 = NULL;
		IEnumWbemClassObject* pEnumerator2 = NULL;
		m_hres = pSvc->ExecQuery(
			bstr_t("WQL"), 
			bstr_t(czQuery),
			WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, 
			NULL,
			&pEnumerator);

		if (FAILED(m_hres))
		{	
			if(pSvc)
			{
				pSvc->Release();
				pSvc = NULL;
			}

			if(pLoc)
			{
				pLoc->Release();
				pLoc = NULL;
			}			

			return csSerialNumber;              
		}
		IWbemClassObject *pclsObj = NULL;
		ULONG uReturn = 0;	
		int count=0;	
		if (pEnumerator)
		{		

			HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);				
			VARIANT vtProp;		
			
			if(pclsObj)
			{
				pclsObj->Get(L"DeviceID", 0, &vtProp, 0, 0);
			}
			else
			{
                if(pSvc)
				{
					pSvc->Release();
					pSvc = NULL;
				}

                if(pLoc)
				{
					pLoc->Release();
					pLoc = NULL;
				}

                if(pclsObj)
				{
					pclsObj->Release();
					pclsObj = NULL;
				}

				CoUninitialize();
				return csSerialNumber;
			}
			char szTmp[MAX_PATH] = {0};
			wcscpy(tmp, vtProp.bstrVal);
			wcstombs(szTmp,tmp,MAX_PATH);
			// "join" Win32_LogicalDisk to Win32_DiskPartition
			sprintf(query, 
				"ASSOCIATORS OF {Win32_LogicalDisk.DeviceID='%s'} WHERE ResultClass=Win32_DiskPartition",
				szTmp);
			m_hres = pSvc->ExecQuery(
				bstr_t("WQL"),
				bstr_t(query),
				WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, 
				NULL,
				&pEnumerator1);
			if (FAILED(m_hres))
			{	
				 if(pSvc)
				{
					pSvc->Release();
					pSvc = NULL;
				}

                if(pLoc)
				{
					pLoc->Release();
					pLoc = NULL;
				}

                if(pclsObj)
				{
					pclsObj->Release();
					pclsObj = NULL;
				}

				CoUninitialize();
				return csSerialNumber;              
			}
			if(SUCCEEDED(m_hres) && pEnumerator1)
			{               
				HRESULT hr = pEnumerator1->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);

				if(SUCCEEDED(hr) && 0 != uReturn)
				{                   
					hr = pclsObj->Get(L"DeviceID", 0, &vtProp, 0, 0);
					if(SUCCEEDED(hr))
					{
						if(vtProp.vt == VT_BSTR)
						{
							wcscpy(tmp, vtProp.bstrVal);
						}
						VariantClear(&vtProp);

						char sztmp[MAX_PATH]={0};
						wcstombs(sztmp,tmp,MAX_PATH);
						// "join" Win32_DiskPartition to Win32_DiskDrive
						sprintf(query,
							"ASSOCIATORS OF {Win32_DiskPartition.DeviceID='%s'} WHERE ResultClass=Win32_DiskDrive",
							sztmp);

						m_hres = pSvc->ExecQuery(
							bstr_t("WQL"),
							bstr_t(query),
							WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, 
							NULL,
							&pEnumerator2);
						if(SUCCEEDED(m_hres) && pEnumerator2)
						{

							hr = pEnumerator2->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);				
							hr = pclsObj->Get(L"SerialNumber", 0, &vtProp, 0, 0);
							if (FAILED(m_hres))
							{	           
								if(pSvc)
								{
									pSvc->Release();
									pSvc = NULL;
								}

								if(pLoc)
								{
									pLoc->Release();
									pLoc = NULL;
								}

								if(pclsObj)
								{
									pclsObj->Release();
									pclsObj = NULL;
								}

								CoUninitialize();
								return csSerialNumber;              
							}
							if(SUCCEEDED(hr))
							{
								if(vtProp.vt == VT_BSTR)
								{
									wcscpy(tmp, vtProp.bstrVal);									
									csSerialNumber.Format(_T("%s"),tmp);
								}

								VariantClear(&vtProp);
							}
							if(csSerialNumber.GetLength() < 2)
							{
								hr = pclsObj->Get(L"PNPDeviceID", 0, &vtProp, 0, 0);
								if (FAILED(m_hres))
								{	           
									if(pSvc)
									{
										pSvc->Release();
										pSvc = NULL;
									}

									if(pLoc)
									{
										pLoc->Release();
										pLoc = NULL;
									}

									if(pclsObj)
									{
										pclsObj->Release();
										pclsObj = NULL;
									}
									CoUninitialize();
									return csSerialNumber;              
								}
								if(SUCCEEDED(hr))
								{
									if(vtProp.vt == VT_BSTR)
									{
										wcscpy(tmp, vtProp.bstrVal);									
										csSerialNumber.Format(_T("%s"),tmp);
										int ipos = 0;
										CString csToken = csSerialNumber.Tokenize(L"\\",ipos);
										int count = 1;
										while(!csToken.IsEmpty())
										{
											if(count==3)
											{
												csSerialNumber.Format(L"%s",csToken);
												break;
											}
											csToken = csSerialNumber.Tokenize(L"\\",ipos);
											count++;
											
										}
										if(csSerialNumber.Find(L"&") != -1)
										{
											csSerialNumber = csSerialNumber.Mid(0,csSerialNumber.ReverseFind(_T('&')));
										}										
									}

									VariantClear(&vtProp);
								}
							}
						}
					}
				}
			}
			VariantClear(&vtProp);		

				if(pclsObj)
				{
					pclsObj->Release();
					pclsObj = NULL;
				}
			
		}		
		csSerialNumber.Trim();
		return csSerialNumber;
	}
	catch(...)
	{
		return _T("");
	}
}
