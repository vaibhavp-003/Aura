// YesNoMsgProdDlg.cpp : implementation file
//

#include "pch.h"
#include "MaxFont.h"
#include "YesNoMsgProdDlg.h"
#include "SDSystemInfo.h"
#include "ProductInfo.h"

// CYesNoMsgProdDlg dialog

IMPLEMENT_DYNAMIC(CYesNoMsgProdDlg, CDialog)

CYesNoMsgProdDlg::CYesNoMsgProdDlg(CWnd* pParent /*=NULL*/)
	: CDialog(CYesNoMsgProdDlg::IDD, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);

	m_bAllowCancel = false;
	m_csTitle = _T("");
	m_iProdID = 0;
	m_SpyDetectDlgBitmaps = NULL;
	m_SpyDetectDlgBitmaps = new CSpyDetectDlgBitmaps(this, NULL, 
		NULL, 
		NULL, 
		NULL, 
		NULL, 
		NULL, 
		NULL, 
		NULL);
	m_pbtnFont	= NULL;
	m_pTitleFont	= NULL;
	m_pMsgFont	= NULL;
}

CYesNoMsgProdDlg::~CYesNoMsgProdDlg()
{
	if(m_SpyDetectDlgBitmaps)
	{
		delete m_SpyDetectDlgBitmaps;
		m_SpyDetectDlgBitmaps = NULL;
	}
	if(m_hResDLL != NULL)
	{
		FreeLibrary(m_hResDLL);
	}
	if(m_pbtnFont)
	{
		delete m_pbtnFont;
		m_pbtnFont = NULL;
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

void CYesNoMsgProdDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	/*DDX_Control(pDX, IDC_STATIC_TITLEBAR_LEFT, m_Title_Image);
	DDX_Control(pDX, IDC_STATIC_TITLEBAR_MIDDLE, m_Title_Extend);
	DDX_Control(pDX, IDC_STATIC_TITLEBAR_RIGHT, m_Title_Right_Corner);
	DDX_Control(pDX, IDC_STATIC_LEFT_BOTTOM, m_BottomLeft);
	DDX_Control(pDX, IDC_STATIC_RIGHT_BOTTOM, m_BottomRight);
	DDX_Control(pDX, IDC_STATIC_LEFT_BOTTOM3, m_YN_Top_Left);
	DDX_Control(pDX, IDC_STATIC_LEFT_BOTTOM4, m_YN_Top_Right);
	DDX_Control(pDX, IDC_STATIC_LEFT_BOTTOM5, m_YN_Bottom_Left);
	DDX_Control(pDX, IDC_STATIC_LEFT_BOTTOM6, m_YN_Bottom_Right);*/
	DDX_Control(pDX, IDC_STATIC_TITLE, m_stTilte);
	DDX_Control(pDX, IDC_BTN_PROD_ONE, m_BtnNoLeft);
	DDX_Control(pDX, IDC_BTN_PROD_TWO, m_BtnNo);
	DDX_Control(pDX, IDC_BTN_PROD_THR, m_BtnNoRight);
	DDX_Control(pDX, IDC_BTN_PROD_FOR, m_BtnYes);
	DDX_Control(pDX, IDC_STATIC_MSG3, m_StMainText);
}


BEGIN_MESSAGE_MAP(CYesNoMsgProdDlg, CDialog)
	ON_WM_PAINT()
	ON_WM_CTLCOLOR()
	ON_WM_NCHITTEST()
	ON_BN_CLICKED(IDC_BTN_PROD_TWO, &CYesNoMsgProdDlg::OnBnClickedBtnProdTwo_No)
	ON_BN_CLICKED(IDC_BTN_PROD_FOR, &CYesNoMsgProdDlg::OnBnClickedBtnProdFor_Yes)
END_MESSAGE_MAP()


// CYesNoMsgProdDlg message handlers

BOOL CYesNoMsgProdDlg::OnInitDialog()
{
	CDialog::OnInitDialog();

	CSystemInfo oSysInfo;
	CString csTitleString;
	/*CRect rect1;
	CRgn rgn;
	this->GetClientRect(rect1);
	CProductInfo oProdInfo;
	if(oProdInfo.SquareCorners())
		rgn.CreateRectRgn(rect1.left, rect1.top, rect1.right - 3, rect1.bottom -3);
	else
		rgn.CreateRoundRectRgn(rect1.left, rect1.top, rect1.right - 2, rect1.bottom -2, 11, 11);
	this->SetWindowRgn(rgn, TRUE );
	*/
	CString csUninsString;
	csUninsString.LoadString(IDS_UNINSTALL_OTHER_PRD_EN);
	this->SetWindowTextW(csUninsString);
	
	if(_T("") == m_csTitle)
	{
		m_csTitle.LoadStringW(IDS_UNINSTALL_OTHER_PRD_EN);
	}

	m_StMainText.SetWindowText(m_csMessage);
	m_stTilte.SetWindowText(m_csTitle);

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

	//m_stTilte.SetFont(&m_SpyDetectDlgBitmaps->m_fontWindowTitle);
	if(m_iProdID == 0) //PROD_ID_AV)
	{
		m_stTilte.SetTextColor(RGB(255, 255, 255));
	}
	else
	{
		m_stTilte.SetTextColor(RGB(0, 0, 0));
	}
	CString csIniPath = CSystemInfo::m_strModulePath + SETTING_FOLDER + CURRENT_SETTINGS_INI;
	MAINUIDLG_HEADING_TEXT_RGB =		GetPrivateProfileInt(_T("colorcode"), _T("MAINUIDLG_HEADING_TEXT"),16777215, csIniPath);
	MAINUIDLG_CONTENT_TEXT_RGB =		GetPrivateProfileInt(_T("colorcode"), _T("MAINUIDLG_CONTENT_TEXT"),16777215, csIniPath);
	INNER_UI_BUTTON_TEXT_RGB		= GetPrivateProfileInt(_T("colorcode"), _T("INNER_UI_BUTTON_TEXT"), 7434354, csIniPath);
	INNER_UI_BUTTON_OVER_TEXT_RGB	= GetPrivateProfileInt(_T("colorcode"), _T("INNER_UI_BUTTON_OVER_TEXT"), 7434354, csIniPath);
	MAINUIDLG_BUTTON_TEXT_RGB =			GetPrivateProfileInt(_T("colorcode"), _T("MAINUIDLG_BUTTON_TEXT"),16777215, csIniPath);
	MAIN_UI_BUTTON_OVER_TEXT_RGB	= GetPrivateProfileInt(_T("colorcode"), _T("MAIN_UI_BUTTON_OVER_TEXT"), 7434354, csIniPath);

	m_pTitleFont = CMaxFont::GetBoldSize21Font();
	m_pMsgFont = CMaxFont::GetNormalSize16Font();
	m_pbtnFont = CMaxFont::GetNormalSize20Font();

	m_BtnNoLeft.SetSkin(m_hResDLL, IDB_BTN_NO_LEFT, IDB_BTN_NO_LEFT, IDB_BTN_NO_LEFT, IDB_BTN_NO_LEFT, 0, 0, 0, 0);
	m_BtnNo.SetSkin(m_hResDLL,IDB_BITMAP_NEWDELETE, IDB_BITMAP_NEWDELETE_OVER , IDB_BITMAP_NEWDELETE_OVER , IDB_BITMAP_NEWDELETE_OVER , IDB_BITMAP_NEWDELETE_OVER , IDB_BITMAP_NEWEDIT_MASK, 0, 0, 0);
	m_BtnNoRight.SetSkin(m_hResDLL, IDB_BTN_NO_RIGHT, IDB_BTN_NO_RIGHT, IDB_BTN_NO_RIGHT, IDB_BTN_NO_RIGHT, 0, 0, 0, 0);
	m_BtnYes.SetSkin(m_hResDLL,IDB_BITMAP_NEWSAVE_NORMAL, IDB_BITMAP_NEWSAVE_OVER, IDB_BITMAP_NEWSAVE_OVER, IDB_BITMAP_NEWSAVE_NORMAL, IDB_BITMAP_NEWSAVE_OVER, IDB_BITMAP_NEWEDIT_MASK, 0, 0, 0);

	csTitleString = _T("");
	csTitleString.LoadString(IDS_YES_EN);
	m_BtnYes.SetWindowText(csTitleString);

	csTitleString = _T("");
	csTitleString.LoadString(IDS_NO_EN);
	m_BtnNo.SetWindowText(csTitleString);
	
	m_BtnYes.SetTextColorA(INNER_UI_BUTTON_TEXT_RGB, INNER_UI_BUTTON_OVER_TEXT_RGB, INNER_UI_BUTTON_OVER_TEXT_RGB);
	m_BtnNo.SetTextColorA(MAINUIDLG_BUTTON_TEXT_RGB,MAIN_UI_BUTTON_OVER_TEXT_RGB, MAIN_UI_BUTTON_OVER_TEXT_RGB);

		m_stTilte.SetFont(m_pTitleFont);
		m_StMainText.SetFont(m_pMsgFont);
		m_StMainText.SetTextColor(MAINUIDLG_CONTENT_TEXT_RGB);
		//m_stTilte.SetTextColor(RGB (51,51,51));
		m_stTilte.SetTextColor(MAINUIDLG_HEADING_TEXT_RGB);

	//CMaxFont *pbtnFont = CMaxFont::GetMaxFont(MICROSOFT_SANS_SERIF, MAXSIZE_14, Bold);
	if(m_pbtnFont)
	{
		m_BtnYes.SetFont(m_pbtnFont);
		m_BtnNo.SetFont(m_pbtnFont);

	
	}
	/*m_BtnYes.SetTextColorA(RGB (255, 255, 255), RGB (255, 255, 255), RGB (255, 255, 255));
	m_BtnNo.SetTextColorA(RGB (139, 139, 139), RGB (139, 139, 139), RGB (55, 55, 55));*/

	SetForegroundWindow();

	// TODO:  Add extra initialization here
	LoadImages();

	return TRUE;  // return TRUE unless you set the focus to a control
	// EXCEPTION: OCX Property Pages should return FALSE
}

void CYesNoMsgProdDlg::OnCancel()
{
	if(m_bAllowCancel)
	{
		CDialog::OnCancel();
	}
}

void CYesNoMsgProdDlg::OnPaint()
{
	CPaintDC dc(this); // device context for painting
	// TODO: Add your message handler code here
	// Do not call CDialog::OnPaint() for painting messages
	m_SpyDetectDlgBitmaps->DoGradientFillNew(&dc);	
	AdjustControls(&dc);
}

void CYesNoMsgProdDlg::AdjustControls(CDC *pDC)
{
	/*HDWP hdwp = BeginDeferWindowPos(1);
	CRect oRcTitleLeftRect;
	m_Title_Image.GetClientRect(&oRcTitleLeftRect);
	CRect oRcDlgRect;
	GetClientRect(&oRcDlgRect);
	DeferWindowPos(hdwp, m_Title_Extend, NULL, oRcTitleLeftRect.right , oRcTitleLeftRect.top ,oRcDlgRect.right, oRcTitleLeftRect.bottom , SWP_NOZORDER);
	EndDeferWindowPos(hdwp);*/
	
//	m_SpyDetectDlgBitmaps->DrawRectangle(pDC, oRcDlgRect, IDC_STATIC_LEFT_BOTTOM3, IDC_STATIC_LEFT_BOTTOM4, IDC_STATIC_LEFT_BOTTOM5, IDC_STATIC_LEFT_BOTTOM6);
}

void CYesNoMsgProdDlg::LoadImages()
{
	//HBITMAP hBitmap = NULL;
	//hBitmap = LoadBitmap(m_hResDLL, MAKEINTRESOURCE(IDB_BITMAP_TASKDLG_TITLEBAR)); 
	//m_Title_Image.SetBitmap(hBitmap);

	//hBitmap = NULL;
	//hBitmap = LoadBitmap(m_hResDLL, MAKEINTRESOURCE(IDB_BITMAP_CORNER_LEFT_BOTTOM));
	//m_BottomLeft.SetBitmap(hBitmap);
	//
	//hBitmap = NULL;
	//hBitmap = LoadBitmap(m_hResDLL, MAKEINTRESOURCE(IDB_BITMAP_CORNER_RIGHT_BOTTOM));
	//m_BottomRight.SetBitmap(hBitmap);

	//hBitmap = NULL;
	//hBitmap = LoadBitmap(m_hResDLL, MAKEINTRESOURCE(IDB_BITMAP_TASKDLG_TITLE_EXTEND));
	//m_Title_Extend.SetBitmap(hBitmap);

	//hBitmap = NULL;
	//hBitmap = LoadBitmap(m_hResDLL, MAKEINTRESOURCE(IDB_BITMAP_TITLEBAR_RIGHT_CORNER));
	//m_Title_Right_Corner.SetBitmap(hBitmap);

	//hBitmap = NULL;
	//hBitmap = LoadBitmap(m_hResDLL, MAKEINTRESOURCE(IDB_BITMAP_LEFT_BOTTOM_CORNER));
	//m_YN_Bottom_Left.SetBitmap(hBitmap);

	//hBitmap = NULL;
	//hBitmap = LoadBitmap(m_hResDLL, MAKEINTRESOURCE(IDB_BITMAP_RIGHT_BOTTOM_CORNER));
	//m_YN_Bottom_Right.SetBitmap(hBitmap);

	//hBitmap = NULL;
	//hBitmap = LoadBitmap(m_hResDLL, MAKEINTRESOURCE(IDB_BITMAP_TOP_LEFT_CORNER));
	//m_YN_Top_Left.SetBitmap(hBitmap);

	//hBitmap = NULL;
	//hBitmap = LoadBitmap(m_hResDLL, MAKEINTRESOURCE(IDB_BITMAP_TOP_RIGHT_CORNER));
	//m_YN_Top_Right.SetBitmap(hBitmap);
}

HBRUSH CYesNoMsgProdDlg::OnCtlColor(CDC* pDC, CWnd* pWnd, UINT nCtlColor)
{
	HBRUSH hbr = CDialog::OnCtlColor(pDC, pWnd, nCtlColor);	
	int	ctrlID;
	ctrlID = pWnd->GetDlgCtrlID();	
	if(ctrlID == IDC_STATIC_MSG3 || ctrlID == IDC_STATIC_TITLE)
	{
		pDC->SetBkMode(TRANSPARENT);
		hbr = (HBRUSH)GetStockObject(NULL_BRUSH);
	}
	return hbr;
}

LRESULT CYesNoMsgProdDlg::OnNcHitTest(CPoint point)
{
	if(!IsZoomed())
	{
		return HTCAPTION;
	}
	else
	{
		return CDialog::OnNcHitTest(point);
	}
}

void CYesNoMsgProdDlg::OnBnClickedBtnProdTwo_No()
{
	m_bAllowCancel = true;
	CDialog::OnCancel();
}

void CYesNoMsgProdDlg::OnBnClickedBtnProdFor_Yes()
{
	m_bAllowCancel = true;
	CDialog::OnOK();
}
