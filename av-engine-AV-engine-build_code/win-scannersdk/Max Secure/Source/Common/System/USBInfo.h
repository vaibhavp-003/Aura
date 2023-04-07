#pragma once
#define _WIN32_DCOM
#include <comdef.h>
#include <Wbemidl.h>
#pragma comment(lib, "wbemuuid.lib")

class CUSBInfo
{
public:
	CUSBInfo(void);
	~CUSBInfo(void);
	BOOL InitializeCOM();
	void DeinitializeCOM();
	HRESULT m_hres;
	IWbemLocator *pLoc;
	IWbemServices *pSvc;	
	CString ExtractRemovableDrivesInfo(CString caption);	
};
