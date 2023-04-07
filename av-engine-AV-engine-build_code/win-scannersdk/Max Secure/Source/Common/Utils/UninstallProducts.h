#pragma once
#include "Registry.h"

const LPCTSTR g_szTitle			= _T("Uninstall Other Products");

//KASPERSKY
const LPCTSTR g_szKaspIS2010	= _T("Kaspersky Internet Security 2010");
const LPCTSTR g_szKaspAV2010	= _T("Kaspersky Anti-Virus 2010");
const LPCTSTR g_szKaspIS2011	= _T("Kaspersky Internet Security 2011");
const LPCTSTR g_szKaspAV2011	= _T("Kaspersky Anti-Virus 2011");
const LPCTSTR g_szKaspIS2012	= _T("Kaspersky Internet Security 2012");
const LPCTSTR g_szKaspAV2012	= _T("Kaspersky Anti-Virus 2012");

//NET-PROTECTOR
const LPCTSTR g_szNP2010		= _T("Net Protector 2010M");
const LPCTSTR g_szNP2011		= _T("Net Protector 2011");
const LPCTSTR g_szNPManual		= _T("Net Protector 2011M");
const LPCTSTR g_szNPManual2012	= _T("Net Protector 2012M");
const LPCTSTR g_szNP2012		= _T("Net Protector 2012");
const LPCTSTR g_szNPManualKey	= _T("NPManual");

//QUICK-HEAL
const LPCTSTR g_szQHAV			= _T("Quick Heal AntiVirus");
const LPCTSTR g_szQHFWPro		= _T("Quick Heal Firewall Pro");
const LPCTSTR g_szQHIS			= _T("Quick Heal Internet Security");
const LPCTSTR g_szQHTS			= _T("Quick Heal Total Security");
const LPCTSTR g_szQHAVPro		= _T("Quick Heal AntiVirus Pro");

//E-SCAN
const LPCTSTR g_szEScanAV		= _T("eScan Anti-Virus (AV) Edition for Windows");

//TREND-MICRO
const LPCTSTR g_szTMISPro		= _T("Trend Micro Internet Security Pro");
const LPCTSTR g_szTMTitanIS		= _T("Trend Micro Titanium Internet Security");

//AVIRA
const LPCTSTR g_szAviraPSS		= _T("Avira Premium Security Suite");
const LPCTSTR g_szAviraAVP		= _T("Avira AntiVir Premium");

//SUNBELT-VIPRE
const LPCTSTR g_szSunPFW		= _T("Sunbelt Personal Firewall");
const LPCTSTR g_szVipre			= _T("VIPRE Antivirus + Antispyware");
const LPCTSTR g_szVipreAV2012	= _T("VIPRE Antivirus");

//AVAST
const LPCTSTR g_szAvastAV		= _T("avast! Antivirus");

//WINDOWS-DEFENDER
const LPCTSTR g_szWF			= _T("Windows Firewall        Action: Disable");
const LPCTSTR g_szWD			= _T("Windows Defender        Action: Disable");

const LPCTSTR g_szMcAfeeIS		= _T("McAfee Internet Security");
const LPCTSTR g_szKaspIS2013	= _T("Kaspersky Internet Security 2013");
const LPCTSTR g_szAVG2013		= _T("AVG 2013");
const LPCTSTR g_szNortonIS		= _T("Norton Internet Security");
const LPCTSTR g_szNortonAV		= _T("Norton Antivirus");
const LPCTSTR g_szNorton360		= _T("Norton 360");
const LPCTSTR g_szMcAfeeTP		= _T("McAfee Total Protection");
const LPCTSTR g_szMcAfeeAVPlus	= _T("McAfee AntiVirus Plus");
const LPCTSTR g_szMcAfeeFP		= _T("McAfee Family Protection");

const int	ID_CMD_BTN			=	0;
const int	ID_CHK_BOX			=	1;
const int	ID_LST_BOX			=	2;
const int	ID_RDO_BTN			=	3;

typedef struct _tagWndInfo
{
	LPCTSTR szWndTitle;
	LPCTSTR szWndText;
	DWORD	dwTimeOut;
	int		iCtrlID;
	int		iPos;
}WNDINFO, *LPWNDINFO;

class CUninstallProducts
{
public:

	CUninstallProducts();
	~CUninstallProducts();

	bool CheckForIncompatProds(CStringArray& csArrProdList);
	bool CheckForIncompatProdsX64(CStringArray& csArrProdList);

	bool UninsQHAV(const CString& csUninstallString);
	bool UninsQHFWPro(const CString& csUninstallString);
	bool UninsQHIS(const CString& csUninstallString);
	bool UninsQHTS(const CString& csUninstallString);
	bool UninsNP2010M(const CString& csUninstallString);
	bool UninsNP2011(const CString& csUninstallString);
	bool UninsKIS2010(const CString& csUninstallString);
	bool UninsKAV2010(const CString& csUninstallString);
	bool UninsMaxAV(const CString& csUninstallString);
	bool UninsMaxSD(const CString& csUninstallString);
	bool UninsEScanAV(const CString& csUninstallString);
	bool UninsTMISPro(const CString& csUninstallString);
	bool UninsAviraPSS(const CString& csUninstallString);
	bool UninsSunPFW(const CString& csUninstallString);
	bool UninsAvastAV(const CString& csUninstallString);
	bool UninsVipre(const CString& csUninstallString);
	bool UninsKAV2011(const CString& csUninstallString);
	bool UninsKIS2011(const CString& csUninstallString);
	bool ExecuteUninstaller(const CString& csDisplayName, const CString& csUninstallString);

	bool	m_bFoundChild;
	int		m_iChildPos;
	int		m_iCurChildPos;

protected:

	DWORD		m_dwTimeOut;
	bool		m_bKIS2010Done;
	bool		m_bKAV2010Done;
	bool		m_bKAV2011Done;
	bool		m_bKIS2011Done;
	HANDLE		m_hProcess;

	void CloseProcessHandle();
	void InsertQuotesToFilePath(CString& csUninsString);
	void FindAndClick(LPCTSTR szWndTitle, LPCTSTR szWndText, DWORD dwTimeOut = 0, int iCtrlID = ID_CMD_BTN, int iPos = 0);
	bool ExecuteProcess(LPCTSTR szCommand, LPCTSTR szArguments, DWORD dwWaitSeconds);
};

