#pragma once
#include "pch.h"
//#include "ResourceManager.h"
#include "LiveUpdate.h"

class CLiveUpdateDLL: public CWinApp
{

public:
	CLiveUpdateDLL(void);
	~CLiveUpdateDLL(void);

	virtual BOOL InitInstance();
	//BOOL InitDLLCode(bool bCheckRights = true);
	//DECLARE_MESSAGE_MAP()

	virtual int ExitInstance();
	void ReadAllSectionNameFromIniX64();
	void ReadAllSectionNameFromIni();	
	bool InitLiveUpdate();
	bool InstallSetup(CString csFilePath, CString csMD5);

	bool m_bAutoUpdate;
	bool m_bManualUpdate;
	bool m_bLocalServerUpdate;
	bool m_bIsLocalServer;
	bool m_bFullUpdate;
	bool m_bProductPatch;
	bool m_bDatabasePatch;
	bool m_bFullDataProductUpdates;
	int m_iCurrentLunguage;
	bool m_bAutoRollBack;

	BOOL m_bLiveUpdateUpToDate;
	UPDATE_STATUS m_objUpdateStatus;

	CString m_csUpdtVerDetails;//UPDATEVERSIONDETAILS
	CString m_csDeltaDetails;//DELTADETAILS
	CString m_csDatabaseDetails;//DATABASEKEY.
	CString m_csDatabaseDetailsCL;//DATABASEKEY.
	CString m_csVirusDetails;//VIRUSKEY
	CString m_csProductDetails;//PRODUCTKEY
	CString m_csSDKDetails;
	CString m_csSDKDetailsX64;
	
	/********For X64 Variable Declaration************/
	CString m_csUpdtVerDetailsX64;
	CString m_csDeltaDetailsX64;//DELTADETAILS
	CString m_csVirusDetailsX64;//VIRUSKEY
	CString m_csProductDetailsX64;//PRODUCTKEY
	/********For X64 Variable Declaration************/
	
	/********For Cloud Server Patch************/
	CString m_csCloudServDetails;
	/********For Cloud Server Patch************/
	/********For Cloud Control Server Patch************/
	CString m_csCloudControlServDetails;
	/********For Cloud Control Server Patch************/

	CString m_csDownLoadPath;
	CString m_csIniPath;
	CString m_csLocalServerPath;
	CString m_csLocalServerLivePath;
	CString m_csLocalServerMainPath;
	CString m_csWaitingForMergePath;
	
	bool	m_bExitApplication;
	bool m_bUpdateCheck;
	bool m_bNewDBFileDownloaded;
	int m_iIsUIProduct;
	int m_iUseCloudScanning;
	int m_iIsFullSDDatabase;
	bool m_bStandaloneDownload;
	bool m_bControlServerDownload;
	bool m_bOtherProductDownload;
	bool m_bServerUpdateLaunch;

	bool m_bExitThread;
	CLiveUpdate m_objLiveUpdtate;

	bool m_bSoftwareUpdate; //Added
};

extern CLiveUpdateDLL theApp;


