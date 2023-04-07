// RemoveProductsDlg.cpp : implementation file
//

#include "pch.h"
#include "RemoveProductsDlg.h"
#include "UninstallProducts.h"
#include "YesNoMsgBoxDlg.h"
#include "MessageBoxNormal.h"
#include "SDSystemInfo.h"
#include "YesNoMsgProdDlg.h"
#include "CPUInfo.h"
#include "RemoteService.h"
#include "MaxConstant.h"
#include "MessageBoxNormal.h"

// CRemoveProductsDlg dialog

IMPLEMENT_DYNAMIC(CRemoveProductsDlg, CDialog)

CRemoveProductsDlg::CRemoveProductsDlg(CWnd* pParent /*=NULL*/)
	: CDialog(CRemoveProductsDlg::IDD, pParent)	
{
	m_iProdID = 0;
	m_bCheckSD = false;
	m_bCheckAV = false;
	m_bIsFirewallRunning = false;
	m_bIsWindowsDefenderRunning = false;
	m_pRemoveOtherProductsThread = NULL;
	m_bIncompatProdPresent = false;

	m_SpyDetectDlgBitmaps = new CSpyDetectDlgBitmaps(this, NULL, 
		NULL, 
		NULL, 
		NULL, 
		NULL, 
		NULL, 
		NULL, 
		NULL);

	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
	m_bIs64Bit = false;
	m_pTitleFont	= NULL;
	m_pMsgFont	= NULL;
}

CRemoveProductsDlg::~CRemoveProductsDlg()
{
	if(m_pRemoveOtherProductsThread)
	{
		WaitForSingleObject(m_pRemoveOtherProductsThread->m_hThread, INFINITE);
		delete m_pRemoveOtherProductsThread;
		m_pRemoveOtherProductsThread = NULL;
	}
	if(m_SpyDetectDlgBitmaps)
	{
		delete m_SpyDetectDlgBitmaps;
		m_SpyDetectDlgBitmaps = NULL;
	}
	if(m_hResDLL != NULL)
	{
		FreeLibrary(m_hResDLL);
	}
	if(m_pTitleFont)
	{
		delete m_pTitleFont;
		m_pTitleFont	= NULL;
	}
	if(m_pMsgFont)
	{
		delete m_pMsgFont;
		m_pMsgFont	= NULL;
	}
}

void CRemoveProductsDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_PROGRESS1, m_PrgrsCtrl);
	/*DDX_Control(pDX, IDC_STATIC_TITLEBAR_LEFT, m_Title_Image);
	DDX_Control(pDX, IDC_STATIC_TITLEBAR_MIDDLE, m_Title_Extend);
	DDX_Control(pDX, IDC_STATIC_TITLEBAR_RIGHT, m_Title_Right_Corner);
	DDX_Control(pDX, IDC_STATIC_LEFT_BOTTOM, m_BottomLeft);
	DDX_Control(pDX, IDC_STATIC_RIGHT_BOTTOM, m_BottomRight);
	DDX_Control(pDX, IDC_STATIC_LEFT_BOTTOM4, m_YN_Top_Left);
	DDX_Control(pDX, IDC_STATIC_LEFT_BOTTOM5, m_YN_Top_Right);
	DDX_Control(pDX, IDC_STATIC_LEFT_BOTTOM6, m_YN_Bottom_Left);
	DDX_Control(pDX, IDC_STATIC_LEFT_BOTTOM7, m_YN_Bottom_Right);*/
	DDX_Control(pDX, IDC_STATIC_TITLE, m_stTilte);
	DDX_Control(pDX, IDC_STATIC_INSTALLED_PRODUCT, m_stCheckOtherInstpro);
}


BEGIN_MESSAGE_MAP(CRemoveProductsDlg, CDialog)
	ON_BN_CLICKED(IDCANCEL, &CRemoveProductsDlg::OnBnClickedCancel)	
	ON_WM_PAINT()
	ON_WM_CTLCOLOR()
END_MESSAGE_MAP()


BOOL CRemoveProductsDlg::OnInitDialog()
{
	CString csUninsString;
	CDialog::OnInitDialog();
	//CSystemInfo oSysInfo;
	//CRect rect1;
	//CRgn rgn;
	//this->GetClientRect(rect1);
	//CProductInfo oProdInfo;
	//if(oProdInfo.SquareCorners())
	//	rgn.CreateRectRgn(rect1.left, rect1.top, rect1.right - 3,rect1.bottom -3);
	//else
	//	rgn.CreateRoundRectRgn(rect1.left, rect1.top, rect1.right - 2,rect1.bottom -2, 11, 11);
	//this->SetWindowRgn(rgn, TRUE );

	csUninsString.LoadString(IDS_UNINSTALL_OTHER_PRD_EN);
	this->SetWindowText(csUninsString);
	objBrush.CreateSolidBrush(RGB(255,255,255));
	CSystemInfo obj;

	m_hResDLL = NULL;
	m_hResDLL = LoadLibraryEx(CSystemInfo::m_strModulePath + _T("AuGuiRes.dll"), nullptr, LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE);//LOAD_LIBRARY_AS_IMAGE_RESOURCE//LOAD_LIBRARY_AS_DATAFILE
	if(m_hResDLL == NULL)
	{
		DWORD dw = GetLastError();
		CString csStr;
		csStr.Format(_T("%d"), dw);
	}

	if(m_hResDLL == NULL)
	{
		m_hResDLL = AfxGetResourceHandle();
	}

	m_hIcon = LoadIcon(m_hResDLL,  MAKEINTRESOURCE(IDI_PRODUCT_ICON));

	SetIcon(m_hIcon, FALSE);
	SetIcon(m_hIcon, TRUE);
	CString csIniPath = CSystemInfo::m_strModulePath + SETTING_FOLDER + CURRENT_SETTINGS_INI;
	MAINUIDLG_HEADING_TEXT_RGB =		GetPrivateProfileInt(_T("colorcode"), _T("MAINUIDLG_HEADING_TEXT"),16777215, csIniPath);
	MAINUIDLG_CONTENT_TEXT_RGB =		GetPrivateProfileInt(_T("colorcode"), _T("MAINUIDLG_CONTENT_TEXT"),16777215, csIniPath);
	m_pTitleFont = CMaxFont::GetBoldSize21Font();
	m_pMsgFont = CMaxFont::GetNormalSize18Font();
	m_stTilte.SetFont(m_pTitleFont);
	
	m_stTilte.SetTextColor(MAINUIDLG_HEADING_TEXT_RGB);
	csUninsString = _T("");
	csUninsString.LoadString(IDS_UNINSTALL_OTHER_PRD_EN);
	m_stTilte.SetWindowText(csUninsString);

	csUninsString = _T("");
	csUninsString.LoadString(IDS_UNINTALL_CHECK_OTHER_EN);
	m_stCheckOtherInstpro.SetWindowText(csUninsString);
	m_stCheckOtherInstpro.SetFont(m_pMsgFont);
	m_stCheckOtherInstpro.SetTextColor(MAINUIDLG_CONTENT_TEXT_RGB);

	m_bIncompatProdPresent = false;
	//LoadImages();
	CCPUInfo objCpu;
	CString strOS = objCpu.GetSystemWow64Dir();
	
	if(strOS.GetLength())
	{
		m_bIs64Bit = true;
	}
	
	m_pRemoveOtherProductsThread = AfxBeginThread(CheckAndRemoveOtherProductsThread, this, 0, 0, CREATE_SUSPENDED);
	if(m_pRemoveOtherProductsThread)
	{
		m_pRemoveOtherProductsThread->m_bAutoDelete = FALSE;
		m_pRemoveOtherProductsThread->ResumeThread();
	}

	return TRUE;  // return TRUE unless you set the focus to a control
	// EXCEPTION: OCX Property Pages should return FALSE
}


///////////////////////////////////////////////////////////////////////////////////////////////////
void CRemoveProductsDlg::LoadImages()
{
	/*HBITMAP hBitmap = NULL;
	hBitmap = LoadBitmap(m_hResDLL, MAKEINTRESOURCE(IDB_BITMAP_TASKDLG_TITLEBAR)); 
	m_Title_Image.SetBitmap(hBitmap);

	hBitmap = NULL;
	hBitmap = LoadBitmap(m_hResDLL, MAKEINTRESOURCE(IDB_BITMAP_CORNER_LEFT_BOTTOM));
	m_BottomLeft.SetBitmap(hBitmap);
	
	hBitmap = NULL;
	hBitmap = LoadBitmap(m_hResDLL, MAKEINTRESOURCE(IDB_BITMAP_CORNER_RIGHT_BOTTOM));
	m_BottomRight.SetBitmap(hBitmap);

	hBitmap = NULL;
	hBitmap = LoadBitmap(m_hResDLL, MAKEINTRESOURCE(IDB_BITMAP_TASKDLG_TITLE_EXTEND));
	m_Title_Extend.SetBitmap(hBitmap);

	hBitmap = NULL;
	hBitmap = LoadBitmap(m_hResDLL, MAKEINTRESOURCE(IDB_BITMAP_TITLEBAR_RIGHT_CORNER));
	m_Title_Right_Corner.SetBitmap(hBitmap);

	hBitmap = NULL;
	hBitmap = LoadBitmap(m_hResDLL, MAKEINTRESOURCE(IDB_BITMAP_LEFT_BOTTOM_CORNER));
	m_YN_Bottom_Left.SetBitmap(hBitmap);

	hBitmap = NULL;
	hBitmap = LoadBitmap(m_hResDLL, MAKEINTRESOURCE(IDB_BITMAP_RIGHT_BOTTOM_CORNER));
	m_YN_Bottom_Right.SetBitmap(hBitmap);

	hBitmap = NULL;
	hBitmap = LoadBitmap(m_hResDLL, MAKEINTRESOURCE(IDB_BITMAP_TOP_LEFT_CORNER));
	m_YN_Top_Left.SetBitmap(hBitmap);

	hBitmap = NULL;
	hBitmap = LoadBitmap(m_hResDLL, MAKEINTRESOURCE(IDB_BITMAP_TOP_RIGHT_CORNER));
	m_YN_Top_Right.SetBitmap(hBitmap);*/
}
///////////////////////////////////////////////////////////////////////////////////////////////////

// CRemoveProductsDlg message handlers

void CRemoveProductsDlg::DoEvents()
{
	MSG Message = {0};

	while(PeekMessage(&Message, m_hWnd, 0, MSG_PEEK, PM_REMOVE))
	{
		TranslateMessage(&Message);
		DispatchMessage(&Message);
	}
}

void CRemoveProductsDlg::OnBnClickedCancel()
{
	if(m_bStartChecking)
	{
		m_bAbortChecking = true;
		while(m_bStartChecking)
		{
			Sleep(5);
			DoEvents();
		}
	}

	OnCancel();
}

UINT AFX_CDECL CheckAndRemoveOtherProductsThread(LPVOID lpThis)
{
	CRemoveProductsDlg* pRemoveProductsDlg = (CRemoveProductsDlg*)lpThis;
	if(pRemoveProductsDlg)
	{
		pRemoveProductsDlg->Init();
		pRemoveProductsDlg->Process();
		pRemoveProductsDlg->DeInit();
		pRemoveProductsDlg->OnBnClickedCancel();
	}
	return 0;
}

void CRemoveProductsDlg::Init()
{
	m_csArrKnownProd.RemoveAll();
	m_csArrDispName.RemoveAll();
	m_csArrUninsStr.RemoveAll();
	m_csArrKeysListCheck.RemoveAll();


	/*Read product name from ini file*/
	
	CString csFilePath = CSystemInfo::m_strModulePath + _T("ProdCompatibility.ini");
	char szFilterFile[MAX_PATH];
	CString csRegistryName;
	sprintf(szFilterFile, "%S", csFilePath);


	int iPathLength = 1024*2,iRegistryCount;
	iRegistryCount = GetPrivateProfileIntA("UnistallProduct","Count",0,szFilterFile);
	for(int nCount = 1; nCount <= iRegistryCount; nCount++ )
	{
		csRegistryName.Format(_T("%d"),nCount);
		GetPrivateProfileString(_T("UnistallProduct"), csRegistryName, _T("0"), csRegistryName.GetBuffer(iPathLength), iPathLength, csFilePath);
		if(!csRegistryName.IsEmpty())
		{
			m_csArrKnownProd.Add(csRegistryName);
			CString csLog;
			csLog.Format(_T("Uninstaller Key From ini: %s"),csRegistryName);
			OutputDebugString(csLog);
		}
	}
	/*************End*****************/


	if(m_bCheckAV)
	{
		
	}


	m_objRegistry.EnumSubKeys(_T("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall"), m_csArrKeysListCheck, HKEY_LOCAL_MACHINE);
	if(m_bIs64Bit)
	{
		m_objRegistryX64.SetWow64Key(true);
		m_objRegistryX64.EnumSubKeys(_T("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall"), m_csArrKeysListCheck, HKEY_LOCAL_MACHINE);
	}
	m_bCheckingDone = false;
	m_bStartChecking = true;
	m_bAbortChecking = false;
	m_iKeyCount = 0;

	m_iKeyCount = (int)m_csArrKeysListCheck.GetCount();

	m_PrgrsCtrl.SetRange32(0, m_iKeyCount);
	m_PrgrsCtrl.SetStep(1);
}

void CRemoveProductsDlg::DeInit()
{
	m_PrgrsCtrl.SetPos(m_iKeyCount);
	m_bCheckingDone = true;
	m_bAbortChecking = true;
	m_bStartChecking = false;
}

void CRemoveProductsDlg::Process()
{
	CheckAndRemoveOtherProducts();
}

bool CRemoveProductsDlg::CheckForDuplicateAndAdd(const CString& csDispName, const CString& csUninsString)
{
	bool bFound = false;
	int iToBeRemoved = -1;

	for(int i = 0, iTotal = (int)m_csArrDispName.GetCount(); i < iTotal; i++)
	{
		if(m_csArrDispName.GetAt(i) == csDispName)
		{
			bFound = true;
			if(0 == _tcsnicmp(csDispName, _T("Quick Heal"), 10))
			{
				if(0 == _tcsnicmp(m_csArrUninsStr.GetAt(i), _T("MsiExec.exe"), 11))
				{
					bFound = false;
					iToBeRemoved = i;
				}
			}

			break;
		}
	}

	if(-1 != iToBeRemoved)
	{
		m_csArrDispName.RemoveAt(iToBeRemoved);
		m_csArrUninsStr.RemoveAt(iToBeRemoved);
	}

	if(!bFound)
	{
		m_csArrDispName.Add(csDispName);
		m_csArrUninsStr.Add(csUninsString);
	}

	return true;
}

bool CRemoveProductsDlg::CheckAndRemoveOtherProducts()
{
	
	bool bMatched = false, bOtherProductFound = false;
	HKEY hHive = HKEY_LOCAL_MACHINE;
	CString csMessage, csHoldString;
	CYesNoMsgProdDlg objYesNoProdDlg;
	CString csKey, csData, csHold, csMainKey = _T("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall");

	csMessage.LoadString(IDS_OTH_PROD_FOUND_MSG_EN);
	for(int i = 0, iTotalCount = (int)m_csArrKeysListCheck.GetCount(); i < iTotalCount; i++)
	{
		bool b64KeyFound = false;
		if(m_bAbortChecking)
		{
			break;
		}

		bMatched = false;
		csData = _T("");
		m_PrgrsCtrl.StepIt(); Sleep(20);

		csKey = csMainKey + _T("\\") + m_csArrKeysListCheck.GetAt(i);
		m_objRegistry.Get(csKey, _T("DisplayName"), csData, hHive);
		if(_T("") == csData)
		{
			if(m_bIs64Bit)
			{
				m_objRegistryX64.Get(csKey, _T("DisplayName"), csData, hHive);
				if(csData.GetLength() > 0)
				{
					b64KeyFound = true;
				}
				else
				{
					csKey = _T("SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\") + m_csArrKeysListCheck.GetAt(i);
					m_objRegistryX64.Get(csKey, _T("DisplayName"), csData, hHive);
					if(csData.GetLength() > 0)
					{
						b64KeyFound = true;
					}
				}
			}
		}
		if(_T("") == csData)
		{
			continue;
		}

		for(int j = 0, iProdCount = (int)m_csArrKnownProd.GetCount(); j < iProdCount; j++)
		{
			if(0 == csData.CompareNoCase(m_csArrKnownProd.GetAt(j)))
			{
				CString cs;
				cs.Format(_T("######Ravidnra In CheckAndRemoveOtherProducts: unistaller string matched for : %s"),csData);
				//OutputDebugString(cs);
				bMatched = true;
				break;
			}
			if(0 == m_csArrKeysListCheck.GetAt(i).CompareNoCase(m_csArrKnownProd.GetAt(j)))
			{
				CString cs;
				cs.Format(_T("######Ravidnra In CheckAndRemoveOtherProducts: unistaller string matched for : %s"),m_csArrKeysListCheck.GetAt(i));
				//OutputDebugString(cs);
				bMatched = true;
				break;
			}
		}

		if(bMatched)
		{
			bOtherProductFound = true;
			csHold = _T("");

			if(csData == g_szVipre)
			{
				CheckForDuplicateAndAdd(csData, _T("MsiExec.exe /I") + m_csArrKeysListCheck.GetAt(i));
			}
			else
			{
				if(b64KeyFound)
				{
					m_objRegistryX64.Get(csKey, _T("QuietUninstallString"), csHold, hHive);
				}
				else
				{
					m_objRegistry.Get(csKey, _T("QuietUninstallString"), csHold, hHive);
				}
				if(_T("") == csHold)
				{
					if(b64KeyFound)
					{
						m_objRegistryX64.Get(csKey, _T("UninstallString"), csHold, hHive);
					}
					else
					{
						m_objRegistry.Get(csKey, _T("UninstallString"), csHold, hHive);
					}
				}

				if((_T("") != csHold) && (_T("") != csData))
				{
					CheckForDuplicateAndAdd(csData, csHold);
				}
			}
		}
	}

	
	/*bool bRunning = CheckForWindowsFirewallAndDefender();
	if(bRunning)
		bOtherProductFound = true;*/

	if(!bOtherProductFound)
	{
		return false;
	}

	for(int i = 0, iTotal = (int)m_csArrDispName.GetCount(); i < iTotal; i++)
	{
		csHoldString = m_csArrDispName.GetAt(i);
		if(-1 == csMessage.Find(csHoldString))
		{
			csMessage += csHoldString + _T("\n");
		}
	}

	csHoldString.LoadString(IDS_OTH_PROD_RMND_UN_EN);
	csMessage += csHoldString;
	objYesNoProdDlg.m_csMessage = csMessage;
	if(IDCANCEL == objYesNoProdDlg.DoModal())
	{	
		m_bIncompatProdPresent = false;
		//OutputDebugString(_T("Call second yes no dialog"));
		CYesNoMsgBoxDlg objYesNoMsgDlg;
		objYesNoMsgDlg.m_csMessage.LoadString(IDS_CONFIRM_INCOMPAT_PROD_EN);
		if(IDCANCEL == objYesNoMsgDlg.DoModal())
		{
			//OutputDebugString(_T("Returning false unistall other prodct 2"));
			m_bIncompatProdPresent = false;
			return false;
			////DisableFirewall();
			//if(!IsConflictingProductPresent())
			//{
			//	return false;
			//}

			//RemoveOtherThanConflictingProducts();
		}
	}

	RemoveOtherProducts();
	return false;
}

bool CRemoveProductsDlg::RemoveOtherProducts()
{
	CString csDisplayName, csUninsString;
	CRegistry objReg;
	CUninstallProducts objUninsProds;
	bool bShowRestartMsg = true;

	if(m_bIs64Bit)
	{
		OutputDebugString(L"This 64 bit OS");
		objReg.SetWow64Key(true);
	}
	else
	{
		OutputDebugString(L"This 32 bit OS");
	}

	try
	{
		DWORD dwLangCode = 0; // dont know how to get this
		CMessageBoxNormal objInformToFollowUninsSteps;
		objInformToFollowUninsSteps.m_csMessage.LoadString(IDS_FOLLOW_UNINS_STEPS_EN + (dwLangCode * 1000));
		objInformToFollowUninsSteps.DoModal();

		for(int i = 0, iTotal = (int)m_csArrDispName.GetCount(); i < iTotal; i++)
		{
			csDisplayName = m_csArrDispName.GetAt(i);
			csUninsString = m_csArrUninsStr.GetAt(i);

			if(csDisplayName == g_szWD)
			{
				bShowRestartMsg = false;
				ShellExecute( NULL,  L"open", CSystemInfo::m_strModulePath + _T("WindefendDisbale.bat"),_T(""),0,SW_NORMAL | SW_HIDE);				
				
				if(objReg.ValueExists(RUN_KEY_PATH, _T("Windows Defender"), HKEY_LOCAL_MACHINE))
				{
					objReg.DeleteValue(RUN_KEY_PATH, _T("Windows Defender"), HKEY_LOCAL_MACHINE);
				}
				objReg.Set (CSystemInfo::m_csProductRegKey, _T("Windows Defender"), 1, HKEY_LOCAL_MACHINE);
				OutputDebugString(CSystemInfo::m_csProductRegKey);
			}
			else if(csDisplayName == g_szWF)
			{
				bShowRestartMsg = false;
				//Off Windows Firewall	
				OutputDebugString(_T("Checking for OS") + CSystemInfo ::m_strOS);
				if(CSystemInfo ::m_strOS.Find(WVISTA) != -1 || CSystemInfo ::m_strOS.Find( WWIN7) != -1
				   || CSystemInfo ::m_strOS.Find( WWIN8) != -1)
				{
					OutputDebugString(_T("This Win7 or Vista OS So Case 3"));
					DisbaleFirewallOnWindows7(FALSE);
		
				}
				else
				{
					OutputDebugString(_T("This is other than Win7 or Vista OS So Case 2"));
					CheckForFirewallSettingAndConfigure(2);
				}
				objReg.Set (CSystemInfo::m_csProductRegKey, _T("Windows Firewall"), 1, HKEY_LOCAL_MACHINE);
				OutputDebugString(CSystemInfo::m_csProductRegKey);
			}
			else
			{
				//OutputDebugString(_T(" Calling Execute unistaller fn"));
				objUninsProds.ExecuteUninstaller(csDisplayName, csUninsString);
			}
		}
	}

	catch(...)
	{
		OutputDebugString(L"exception ocured");
	}
	if(bShowRestartMsg)
	{
		CMessageBoxNormal objMsgBox;
		objMsgBox.m_csMessage = _T("");
		m_bIncompatProdPresent = true;
		//objMsgBox.m_csMessage.LoadString(IDS_OTH_PROD_RES_MSG_EN);
		//objMsgBox.DoModal();
	}
	return true;
}

void CRemoveProductsDlg::OnPaint()
{
	//DEBUG_MACRO(L"OnPaint");

	CPaintDC dc(this); // device context for painting	
	m_SpyDetectDlgBitmaps->DoGradientFillNew(&dc);	
	AdjustControls(&dc);
}

HBRUSH CRemoveProductsDlg::OnCtlColor(CDC* pDC, CWnd* pWnd, UINT nCtlColor)
{
	//DEBUG_MACRO(L"OnCtlColor");

	HBRUSH hbr = CDialog::OnCtlColor(pDC, pWnd, nCtlColor);	
	int	ctrlID;
	ctrlID = pWnd->GetDlgCtrlID();	
	if(ctrlID == IDC_STATIC_INSTALLED_PRODUCT || ctrlID ==  IDC_STATIC_TITLE)
	{
		pDC->SetBkMode(TRANSPARENT);
		hbr = (HBRUSH)GetStockObject(NULL_BRUSH);
	}		
	return hbr;
}

void CRemoveProductsDlg::AdjustControls(CDC *pDC)
{
	//DEBUG_MACRO(L"AdjustControls");

	/*HDWP hdwp = BeginDeferWindowPos(1);	
	CRect oRcTitleLeftRect;
	m_Title_Image.GetClientRect(&oRcTitleLeftRect);		
	CRect oRcDlgRect;
	GetClientRect(&oRcDlgRect);		
	DeferWindowPos(hdwp, m_Title_Extend, NULL, oRcTitleLeftRect.right , oRcTitleLeftRect.top ,oRcDlgRect.right, oRcTitleLeftRect.bottom , SWP_NOZORDER);	
	EndDeferWindowPos(hdwp);	*/
	
	//m_SpyDetectDlgBitmaps->DrawRectangle(pDC, oRcDlgRect, IDC_STATIC_LEFT_BOTTOM4, IDC_STATIC_LEFT_BOTTOM5, IDC_STATIC_LEFT_BOTTOM6, IDC_STATIC_LEFT_BOTTOM7);

}

void CRemoveProductsDlg::DisableFirewall()
{
	HKEY hKey = NULL;
	CRegistry objReg;

	objReg.CreateKey(_T("SYSTEM\\CurrentControlSet\\Services\\SBFW"), hKey, HKEY_LOCAL_MACHINE);
	if(hKey == NULL)
	{
		return;
	}

	objReg.Set(_T("SYSTEM\\CurrentControlSet\\Services\\SBFW"), _T("Start"), 4, HKEY_LOCAL_MACHINE);
	objReg.CloseKey(hKey);
	return;
}

bool CRemoveProductsDlg::CheckForWindowsFirewallAndDefender()
{
	CRemoteService objRemote;
	bool bRet = false;
	
	//bIsFirewallRunning = objRemote.IsRmoteServiceRunning();
	CheckForFirewallSettingAndConfigure(1);
	m_bIsWindowsDefenderRunning = objRemote.IsRmoteServiceRunning(_T("WinDefend"));
	
	if(m_bIsFirewallRunning)
	{
		m_csArrDispName.Add(g_szWF);
		m_csArrUninsStr.Add(L"dummy, unused");
		bRet = true;
	}

	if(m_bIsWindowsDefenderRunning)
	{
		m_csArrDispName.Add(g_szWD);
		m_csArrUninsStr.Add(L"dummy, unused");
		bRet = true;
	}	
	return bRet;
}

void CRemoveProductsDlg::CheckForFirewallSettingAndConfigure(int iType)
{
	HRESULT hr = S_OK;
	HRESULT comInit = E_FAIL;
	INetFwProfile* fwProfile = NULL;

	// Initialize COM.
	comInit = CoInitializeEx(0, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
	COINITIALIZE_OUTPUTDEBUGSTRING(comInit);
	// Ignore RPC_E_CHANGED_MODE; this just means that COM has already been
	// initialized with a different mode. Since we don't care what the mode is,
	// we'll just use the existing mode.
	if (comInit != RPC_E_CHANGED_MODE)
	{
		hr = comInit;
		if (FAILED(hr))
		{
			OutputDebugString(L"CoInitializeEx failed: CheckForFirewallSettingAndConfigure\n");
			goto error;
		}
	}

	// Retrieve the firewall profile currently in effect.
	hr = WindowsFirewallInitialize(&fwProfile);
	if (FAILED(hr))
	{
		OutputDebugString(L"WindowsFirewallInitialize failed: \n");
		goto error;
	}
	
	switch(iType)
	{
	case 1:
		{
			hr = S_OK;
			BOOL fwOn;

			_ASSERT(fwProfile != NULL);

			// Check to see if the firewall is on.
			hr = WindowsFirewallIsOn(fwProfile, &fwOn);
			if (FAILED(hr))
			{
				OutputDebugString(L"WindowsFirewallIsOn failed:\n");
				goto error;
			}
			if(fwOn)
			{
				// Release the firewall profile.
				m_bIsFirewallRunning = true;
				goto error;
			}
		}
		break;
	case 2:
		{
			_ASSERT(fwProfile != NULL);
			// Turn the firewall off.
			hr = fwProfile->put_FirewallEnabled(VARIANT_FALSE);
			if (FAILED(hr))
			{
				OutputDebugString(L"put_FirewallEnabled failed:\n");
			}
			OutputDebugString(L"The firewall is now off.\n");
			goto error;
		}
		break;
	case 3:
		{
			_ASSERT(fwProfile != NULL);
			hr = fwProfile->put_FirewallEnabled(VARIANT_TRUE);
			if (FAILED(hr))
			{
				OutputDebugString(L"put_FirewallEnabled failed:\n");
			}
			OutputDebugString(L"The firewall is now on.\n");
			goto error;
   		}
		break;
	}

error:
    // Release the firewall profile.
    if (fwProfile != NULL)
    {
        fwProfile->Release();
    }
    // Uninitialize COM.
	CoUninitialize();
}

HRESULT CRemoveProductsDlg::WindowsFirewallIsOn(IN INetFwProfile* fwProfile, OUT BOOL* fwOn)
{
    HRESULT hr = S_OK;
    VARIANT_BOOL fwEnabled;

    _ASSERT(fwProfile != NULL);
    _ASSERT(fwOn != NULL);

    *fwOn = FALSE;

    // Get the current state of the firewall.
    hr = fwProfile->get_FirewallEnabled(&fwEnabled);
    if (FAILED(hr))
    {
        OutputDebugString(L"get_FirewallEnabled failed: WindowsFirewallIsOn \n");
        goto error;
    }

    // Check to see if the firewall is on.
    if (fwEnabled != VARIANT_FALSE)
    {
        *fwOn = TRUE;
        OutputDebugString(L"The firewall is on.\n");
    }
    else
    {
        OutputDebugString(L"The firewall is off.\n");
    }

error:

    return hr;
}

HRESULT CRemoveProductsDlg::WindowsFirewallInitialize(OUT INetFwProfile** fwProfile)
{
    HRESULT hr = S_OK;
    INetFwMgr* fwMgr = NULL;
    INetFwPolicy* fwPolicy = NULL;

    _ASSERT(fwProfile != NULL);

    *fwProfile = NULL;

    // Create an instance of the firewall settings manager.
    hr = CoCreateInstance(__uuidof(NetFwMgr), NULL, CLSCTX_INPROC_SERVER, __uuidof(INetFwMgr), (void**)&fwMgr);
	COCREATE_OUTPUTDEBUGSTRING(hr);
    if (FAILED(hr))
    {
        OutputDebugString(L"CoCreateInstance failed: WindowsFirewallInitialize\n");
        goto error;
    }

    // Retrieve the local firewall policy.
    hr = fwMgr->get_LocalPolicy(&fwPolicy);
    if (FAILED(hr))
    {
        OutputDebugString(L"get_LocalPolicy failed: WindowsFirewallInitialize\n");
        goto error;
    }

    // Retrieve the firewall profile currently in effect.
    hr = fwPolicy->get_CurrentProfile(fwProfile);
    if (FAILED(hr))
    {
        OutputDebugString(L"get_CurrentProfile failed: WindowsFirewallInitialize\n");
        goto error;
    }

error:

    // Release the local firewall policy.
    if (fwPolicy != NULL)
    {
        fwPolicy->Release();
    }

    // Release the firewall settings manager.
    if (fwMgr != NULL)
    {
        fwMgr->Release();
    }

    return hr;
}

void CRemoveProductsDlg::DisbaleFirewallOnWindows7(BOOL bEnable)
{
    HRESULT hrComInit = S_OK;
    HRESULT hr = S_OK;

    INetFwPolicy2 *pNetFwPolicy2 = NULL;

    // Initialize COM.
    hrComInit = CoInitializeEx(0, COINIT_APARTMENTTHREADED);
	COINITIALIZE_OUTPUTDEBUGSTRING(hrComInit);

    // Ignore RPC_E_CHANGED_MODE; this just means that COM has already been
    // initialized with a different mode. Since we don't care what the mode is,
    // we'll just use the existing mode.
    if (hrComInit != RPC_E_CHANGED_MODE)
    {
        if (FAILED(hrComInit))
        {
            OutputDebugString(L"CoInitializeEx failed: \n");
            goto Cleanup;
        }
    }

    // Retrieve INetFwPolicy2
    hr = WFCOMInitializeWin7(&pNetFwPolicy2);
    if (FAILED(hr))
    {
        goto Cleanup;
    }

    // Disable Windows Firewall for the Domain profile
    hr = pNetFwPolicy2->put_FirewallEnabled(NET_FW_PROFILE2_DOMAIN, bEnable);
    if (FAILED(hr))
    {
        OutputDebugString(L"put_FirewallEnabled failed for Domain: \n");
        goto Cleanup;
    }

    // Disable Windows Firewall for the Private profile
    hr = pNetFwPolicy2->put_FirewallEnabled(NET_FW_PROFILE2_PRIVATE, bEnable);
    if (FAILED(hr))
    {
        OutputDebugString(L"put_FirewallEnabled failed for Private: \n");
        goto Cleanup;
    }

    // Disable Windows Firewall for the Public profile
    hr = pNetFwPolicy2->put_FirewallEnabled(NET_FW_PROFILE2_PUBLIC, bEnable);
    if (FAILED(hr))
    {
        OutputDebugString(L"put_FirewallEnabled failed for Public:\n");
        goto Cleanup;
    }

Cleanup:

    // Release INetFwPolicy2
    if (pNetFwPolicy2 != NULL)
    {
        pNetFwPolicy2->Release();
    }

    // Uninitialize COM.
	CoUninitialize();

    return;
}


// Instantiate INetFwPolicy2
HRESULT CRemoveProductsDlg::WFCOMInitializeWin7(INetFwPolicy2** ppNetFwPolicy2)
{
    HRESULT hr = S_OK;

    hr = CoCreateInstance(__uuidof(NetFwPolicy2), NULL, CLSCTX_INPROC_SERVER, __uuidof(INetFwPolicy2), (void**)ppNetFwPolicy2);
	COCREATE_OUTPUTDEBUGSTRING(hr);
    if (FAILED(hr))
    {
        OutputDebugString(L"CoCreateInstance for INetFwPolicy2 failed:\n");
        goto Cleanup;        
    }

Cleanup:
    return hr;
}

void CRemoveProductsDlg::ConfigureFWDuringUninstallation()
{
	OutputDebugString(_T("In ConfigureFWDuringUninstallation"));
	CRemoteService objRemote;
	CRegistry objReg;
	CSystemInfo obj;
	bool bWF = false, bWD = false, bRet = false;
	CCPUInfo objCpu;
	CString strOS = objCpu.GetSystemWow64Dir();
	
	if(strOS.GetLength())
	{
		m_bIs64Bit = true;
	}
	
	if(m_bIs64Bit)
	{
		objReg.SetWow64Key(true);
	}
	//bIsFirewallRunning = objRemote.IsRmoteServiceRunning();

	OutputDebugString(CSystemInfo::m_csProductRegKey);
	DWORD dwWD = 0;
	DWORD dwWF = 0;

	if(objReg.ValueExists(CSystemInfo::m_csProductRegKey, _T("Windows Defender"),HKEY_LOCAL_MACHINE))
	{
		objReg.Get (CSystemInfo::m_csProductRegKey, _T("Windows Defender"), dwWD, HKEY_LOCAL_MACHINE);
	}
	if(objReg.ValueExists(CSystemInfo::m_csProductRegKey, _T("Windows Firewall"),HKEY_LOCAL_MACHINE))
	{
		objReg.Get (CSystemInfo::m_csProductRegKey, _T("Windows Firewall"), dwWF, HKEY_LOCAL_MACHINE);
	}

	if(!dwWF && !dwWD)
		return;

	if(dwWF)
	{
		CheckForFirewallSettingAndConfigure(1);
	}

	if(dwWD)
	{
		m_bIsWindowsDefenderRunning = objRemote.IsRmoteServiceRunning(_T("WinDefend"));
	}

	if(m_bIsFirewallRunning && m_bIsWindowsDefenderRunning)
	{
		return;
	}
	CYesNoMsgBoxDlg objYesNoMsgDlg;
	if (dwWD && dwWF && !m_bIsFirewallRunning && !m_bIsWindowsDefenderRunning)
	{
		OutputDebugString(_T("Both are ON"));
		objYesNoMsgDlg.m_csMessage = _T("Windows Firewall and Defender Has been Disabled Previosly! Do You want to Enable them?");		
	}
	else if (dwWD && !m_bIsWindowsDefenderRunning)
	{
		OutputDebugString(_T("WD is ON"));
		objYesNoMsgDlg.m_csMessage = _T("Windows Defender Has been Disabled Previosly! Do You want to Enable them?");		
	}
	else if (dwWF && !m_bIsFirewallRunning)
	{
		OutputDebugString(_T("WF is ON"));
		objYesNoMsgDlg.m_csMessage = _T("Windows Firewall Has been Disabled Previosly! Do You want to Enable them?");		
	}
	else
	{
		OutputDebugString(_T("Returning"));
		return;
	}
	
	if(!m_bIsFirewallRunning || !m_bIsWindowsDefenderRunning)
	{
		if(IDCANCEL == objYesNoMsgDlg.DoModal())
		{
			return;
		}
		else if (dwWD && !m_bIsWindowsDefenderRunning)
		{
			ShellExecute( NULL,  L"open", CSystemInfo::m_strAppPath + _T("WindefendEnable.bat"),_T(""),0,SW_NORMAL | SW_HIDE);				 
			if(!objReg.ValueExists(RUN_KEY_PATH, _T("Windows Defender"), HKEY_LOCAL_MACHINE))
			{
				if(m_bIs64Bit)
				{
					CString csProgramPath = objCpu.GetRootDrive() + _T("\\Program Files");
					objReg.Set(RUN_KEY_PATH, _T("Windows Defender"), csProgramPath + _T("\\Windows Defender\\MSASCui.exe -hide") ,HKEY_LOCAL_MACHINE); 
				}
				else
				{
					objReg.Set(RUN_KEY_PATH, _T("Windows Defender"), CSystemInfo::m_strProgramFilesDir + _T("\\Windows Defender\\MSASCui.exe -hide") ,HKEY_LOCAL_MACHINE); 
				}				
			}
		}
		if (dwWF && !m_bIsFirewallRunning)
		{
			OutputDebugString(_T("Checking for OS") + CSystemInfo ::m_strOS);
			if(CSystemInfo ::m_strOS.Find(WVISTA) != -1 || CSystemInfo ::m_strOS.Find( WWIN7) != -1)
			{
				DisbaleFirewallOnWindows7(TRUE);
			}
			else
			{
				CheckForFirewallSettingAndConfigure(3);
			}
		}
	}	
}

bool CRemoveProductsDlg::IsConflictingProductPresent()
{
	CString csDispName;
	bool bConfProdPresent = false;

	for(INT_PTR i = 0, iTotal = m_csArrDispName.GetCount(); i < iTotal; i++)
	{
		csDispName = m_csArrDispName.GetAt(i);
		if(0 == _tcsnicmp(csDispName, _T("Net Protector"), 13))
		{
			bConfProdPresent = true;
			break;
		}
	}

	return bConfProdPresent;
}

bool CRemoveProductsDlg::RemoveOtherThanConflictingProducts()
{
	CString csDispName;
	bool bConfProdPresent = false, bProdFound = false;

	do
	{
		bProdFound = false;
		for(INT_PTR i = 0, iTotal = m_csArrDispName.GetCount(); i < iTotal; i++)
		{
			csDispName = m_csArrDispName.GetAt(i);
			if(0 == _tcsnicmp(csDispName, _T("Net Protector"), 13))
			{
				m_csArrDispName.RemoveAt(i);
				m_csArrUninsStr.RemoveAt(i);

				bProdFound = true;
				bConfProdPresent = true;
				break;
			}
		}
	}while(bProdFound);

	return bConfProdPresent;
}