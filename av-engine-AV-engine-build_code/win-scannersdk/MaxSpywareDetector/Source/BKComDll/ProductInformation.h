#pragma once
#include "pch.h"

typedef struct _ProductInfo
{
	wchar_t szCoreScanEngineVer[MAX_PATH];
	wchar_t szVirusScanEngineVer[MAX_PATH];
	wchar_t szThreatDefinationVer[MAX_PATH];
	wchar_t szUpdateVer[MAX_PATH];
	wchar_t szLastLiveUpdate[MAX_PATH];
	wchar_t szFirstPriorityVer[MAX_PATH];
} ProductInfo;

class CProductInformation
{
public:
	CProductInformation();
	~CProductInformation();

public:
	void GetCurrentVersions(ProductInfo * sProductInfo);

	CString GetProductVersion(void);//Core Scan Engine
	CString GetVirusScanEngineVersion(void);//Virus Scan Engine
	CString GetDatabaseVersion(void);//Threat Defination
	CString GetUpdateVersion(void);//Update Version
	CString GetLiveupdateDate(void);//Last Live Update
	CString GetFirstPriorityVersion(void);//First Priority
};
