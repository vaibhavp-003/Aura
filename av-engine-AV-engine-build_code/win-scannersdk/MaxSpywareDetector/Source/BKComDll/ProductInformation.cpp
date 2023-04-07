#include "pch.h"
#include "ProductInformation.h"
#include "SDSystemInfo.h"

CProductInformation::CProductInformation()
{

}

CProductInformation::~CProductInformation()
{

}

void CProductInformation::GetCurrentVersions(ProductInfo* sProductInfo)
{
	CString csCoreScanEngineVer, csVirusScanVer, csThreatDefinationVer, csUpdateVersion, csLastLiveUpdate, csFirstPriorityVer;
	csCoreScanEngineVer = GetProductVersion();
	csVirusScanVer = GetVirusScanEngineVersion();
	csThreatDefinationVer = GetDatabaseVersion();
	csUpdateVersion = GetUpdateVersion();
	csLastLiveUpdate = GetLiveupdateDate();
	csFirstPriorityVer = GetFirstPriorityVersion();

	wcscpy_s(sProductInfo->szCoreScanEngineVer, csCoreScanEngineVer);
	wcscpy_s(sProductInfo->szVirusScanEngineVer, csVirusScanVer);
	wcscpy_s(sProductInfo->szThreatDefinationVer, csThreatDefinationVer);
	wcscpy_s(sProductInfo->szUpdateVer, csUpdateVersion);
	wcscpy_s(sProductInfo->szLastLiveUpdate, csLastLiveUpdate);
	wcscpy_s(sProductInfo->szFirstPriorityVer, csFirstPriorityVer);
}

CString CProductInformation::GetProductVersion(void)
{
	CString csVer = _T("5.0");
	try
	{
		CRegistry objReg;
		objReg.Get(CSystemInfo::m_csProductRegKey, _T("ProductVersionNo"), csVer, HKEY_LOCAL_MACHINE);
	}
	catch (...)
	{
		//Exception occured
		return _T("5.0");
	}
	return csVer;
}


CString CProductInformation::GetVirusScanEngineVersion(void)
{
	CString csVer = _T("1.2");
	try
	{
		CRegistry objReg;
		objReg.Get(CSystemInfo::m_csProductRegKey, _T("VirusVersionNo"), csVer, HKEY_LOCAL_MACHINE);
	}
	catch (...)
	{
		//Exception occured
		return _T("1.2");
	}
	return csVer;
}


CString CProductInformation::GetDatabaseVersion(void)
{
	CString csVer = _T("3.0");
	try
	{
		CRegistry objReg;
		objReg.Get(CSystemInfo::m_csProductRegKey, _T("DatabaseVersionNo"), csVer, HKEY_LOCAL_MACHINE);
	}
	catch (...)
	{
		//Exception occured
		return _T("3.0");
	}
	return csVer;

}

CString CProductInformation::GetUpdateVersion(void)
{
	CString csVer = _T("1.0");
	try
	{
		CRegistry objReg;
		objReg.Get(CSystemInfo::m_csProductRegKey, _T("UpdateVersion"), csVer, HKEY_LOCAL_MACHINE);
	}
	catch (...)
	{
		//Exception occured
		return _T("1.0");
	}
	return csVer;
}

CString CProductInformation::GetLiveupdateDate(void)
{
	CString csDate = _T("");
	try
	{
		CRegistry objReg;
		objReg.Get(CSystemInfo::m_csProductRegKey, _T("LastLiveUpdate"), csDate, HKEY_LOCAL_MACHINE);
	}
	catch (...)
	{
		//Exception occured
		return _T("");
	}
	csDate.Replace(_T("200"), _T("0"));
	return csDate;
}

CString CProductInformation::GetFirstPriorityVersion(void)
{
	CString csVer = _T("1.0");
	try
	{
		CRegistry objReg;
		objReg.Get(CSystemInfo::m_csProductRegKey, _T("FirstPriorityVersionNo"), csVer, HKEY_LOCAL_MACHINE);
	}
	catch (...)
	{
		//Exception occured
		return _T("1.0");
	}
	return csVer;
}