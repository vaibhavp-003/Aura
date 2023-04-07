#pragma once
#include "maxinstallproduct.h"

class CUltraAVInstaller :
	public CMaxInstallProduct
{
public:
	CUltraAVInstaller(void);
	~CUltraAVInstaller(void);
private:
	WCHAR	m_szAppPath[MAX_PATH];
	CString m_szProductName;
	CString m_szRegistryKey;
	CString m_szStartMenuFolder;
	CString m_szDesktopFolder;
	CString m_szPFx86Path;
	CString m_szFolderInAppPath;
	WCHAR	m_szSystemPath[MAX_PATH];
	WCHAR	m_szFirewallPath[MAX_PATH];

	void Init();
	void AddProcessesInArray(CStringArray &arrProcesses);

public:
	BOOL m_bCompUninstall;
	ENUM_PRODUCT_TYPE m_eProductType;
	void StartCleanUp();
	void UninstalltionStart();

};
