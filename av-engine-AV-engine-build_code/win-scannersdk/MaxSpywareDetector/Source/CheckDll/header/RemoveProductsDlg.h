#pragma once
#include "afxcmn.h"
#include "SetDialogBitmaps.h"
#include "afxwin.h"
#include "ColorStatic.h"
#include "ProductInfo.h"
#include "Netfw.h"
#include <crtdbg.h>
#include <objbase.h>
#include <oleauto.h>
#include <stdio.h>
#include "MaxFont.h"

#pragma comment( lib, "ole32.lib" )
#pragma comment( lib, "oleaut32.lib" )


#define PROD_ID_UAV			(21)

UINT AFX_CDECL CheckAndRemoveOtherProductsThread(LPVOID lpThis);

// CRemoveProductsDlg dialog

class CRemoveProductsDlg : public CDialog
{
	DECLARE_DYNAMIC(CRemoveProductsDlg)

public:
	CRemoveProductsDlg(CWnd* pParent = NULL);   // standard constructor
	virtual ~CRemoveProductsDlg();

// Dialog Data
	enum { IDD = IDD_DLG_REM_OTH_PROD };

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support

	DECLARE_MESSAGE_MAP()
public:

	int				m_iKeyCount;
	bool			m_bStartChecking;
	bool			m_bAbortChecking;
	bool			m_bCheckingDone;
	CRegistry		m_objRegistry;
	CStringArray	m_csArrKeysListCheck;
	CStringArray	m_csArrDispName;
	CStringArray	m_csArrUninsStr;
	CStringArray	m_csArrKnownProd;
	CProgressCtrl	m_PrgrsCtrl;
	int				m_iProdID;
	bool			m_bCheckSD;
	bool			m_bCheckAV;
	DWORD			m_dwLanguage;
	bool			m_bIncompatProdPresent;
	CWinThread*		m_pRemoveOtherProductsThread;
	
	CString m_csProdName;
	HMODULE	m_hResDLL;
	CBrush objBrush;

	virtual BOOL OnInitDialog();
	afx_msg void OnBnClickedCancel();

	void Init();
	void DeInit();
	void Process();
	void DoEvents();
	bool RemoveOtherProducts();
	bool CheckAndRemoveOtherProducts();
	void DisableFirewall();
	bool CheckForWindowsFirewallAndDefender();
	void CheckForFirewallSettingAndConfigure(int iType);
	HRESULT WindowsFirewallIsOn(IN INetFwProfile* fwProfile, OUT BOOL* fwOn);
	HRESULT WindowsFirewallInitialize(OUT INetFwProfile** fwProfile);
	HRESULT WFCOMInitializeWin7(INetFwPolicy2** ppNetFwPolicy2);
	void DisbaleFirewallOnWindows7(BOOL bEnable);
	void ConfigureFWDuringUninstallation();

	void LoadImages();
	void AdjustControls(CDC *pDC);
	CRegistry	m_objRegistryX64;
	bool m_bIs64Bit;
	bool m_bIsFirewallRunning;
	bool m_bIsWindowsDefenderRunning;
	
public:
	CSpyDetectDlgBitmaps * m_SpyDetectDlgBitmaps;
	afx_msg void OnPaint();

private:
	COLORREF TITLE_COLOR_RGB;	
	bool CheckForDuplicateAndAdd(const CString& csDispName, const CString& csUninsString);
	bool IsConflictingProductPresent();
	bool RemoveOtherThanConflictingProducts();

public:
	/*CStatic m_Title_Image;
	CStatic m_Title_Extend;
	CStatic m_Title_Right_Corner;
	CStatic m_BottomLeft;
	CStatic m_BottomRight;*/
	afx_msg HBRUSH OnCtlColor(CDC* pDC, CWnd* pWnd, UINT nCtlColor);
	/*CStatic m_YN_Top_Left;
	CStatic m_YN_Top_Right;
	CStatic m_YN_Bottom_Left;
	CStatic m_YN_Bottom_Right;*/
	CColorStatic m_stTilte;
	CColorStatic m_stCheckOtherInstpro;
	COLORREF MAINUIDLG_HEADING_TEXT_RGB;
	COLORREF MAINUIDLG_CONTENT_TEXT_RGB;
	CMaxFont *m_pTitleFont,*m_pMsgFont;
	HICON m_hIcon;
};
