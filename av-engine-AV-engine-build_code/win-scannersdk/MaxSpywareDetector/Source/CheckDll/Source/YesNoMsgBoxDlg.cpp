/*=============================================================================
FILE			: YesNoMsgBoxDlg.cpp
ABSTRACT		: Message box Dialog
DOCUMENTS	: 
AUTHOR		: 
COMPANY		: Aura 
COPYRIGHT NOTICE:
			(C) Aura
			Created as an unpublished copyright work.  All rights reserved.
			This document and the information it contains is confidential and
			proprietary to Aura.  Hence, it may not be 
			used, copied, reproduced, transmitted, or stored in any form or by any 
			means, electronic, recording, photocopying, mechanical or otherwise, 
			with out the prior written permission of Aura
CREATION DATE   : 
NOTES		:
VERSION HISTORY	:15 Jan 2008 : Milind Shete
Unicode Supported.

============================================================================*/
#include "pch.h"
#include "YesNoMsgBoxDlg.h"
#include <atlbase.h>
#include <winuser.h>
#include <windows.h>
#include "MaxRes.h"
#include "SDSystemInfo.h"
#include "ProductInfo.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

IMPLEMENT_DYNAMIC(CYesNoMsgBoxDlg, CDialog)
/*-------------------------------------------------------------------------------------
Function		: CYesNoMsgBoxDlg(Constructor)
In Parameters	: -
Out Parameters	: -
Purpose			: This Function  Initilaize CYesNoMsgBoxDlg class
Author			:
--------------------------------------------------------------------------------------*/
CYesNoMsgBoxDlg::CYesNoMsgBoxDlg(CWnd* pParent):CDialog(CYesNoMsgBoxDlg::IDD, pParent)
{
	m_Icon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);

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


/*-------------------------------------------------------------------------------------
Function		: ~CYesNoMsgBoxDlg (Destructor)
In Parameters	: -
Out Parameters	: -
Purpose			: This Function Destruct CYesNoMsgBoxDlg class.
Author			:
--------------------------------------------------------------------------------------*/
CYesNoMsgBoxDlg::~CYesNoMsgBoxDlg()
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

void CYesNoMsgBoxDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	DDX_Control(pDX, IDOK, m_btnOk);
	DDX_Text(pDX, IDC_STATIC_MSG, m_csMessage);
	DDX_Control(pDX, IDC_STATIC_MSG, m_stMessage);
	DDX_Control(pDX, IDCANCEL, m_btnClose);
	DDX_Control(pDX, IDC_STATIC_TITLE, m_stTilte);
	
}


BEGIN_MESSAGE_MAP(CYesNoMsgBoxDlg, CDialog)
	ON_BN_CLICKED(IDOK, OnBnClickedOk)
	ON_BN_CLICKED(IDCANCEL, OnBnClickedCancel)
	ON_WM_PAINT()
	ON_WM_CTLCOLOR()
	ON_WM_NCHITTEST()
	ON_WM_ERASEBKGND()
END_MESSAGE_MAP()

/*-------------------------------------------------------------------------------------
Function		: OnBnClickedOk
In Parameters	: -
Out Parameters	: void
Purpose			: This Function calls OnOK()
Author			:
--------------------------------------------------------------------------------------*/
void CYesNoMsgBoxDlg::OnBnClickedOk()
{
	OnOK();
}

/*-------------------------------------------------------------------------------------
Function		: OnBnClickedCancel
In Parameters	: -
Out Parameters	: void
Purpose			: This Function ends the dialog
Author			:
--------------------------------------------------------------------------------------*/
void CYesNoMsgBoxDlg::OnBnClickedCancel()
{
	OnCancel();
}

/*-------------------------------------------------------------------------------------
Function		: OnInitDialog
In Parameters	: -
Out Parameters	: BOOL
Purpose			: This Function initializes the dialog
Author			:
--------------------------------------------------------------------------------------*/
BOOL CYesNoMsgBoxDlg::OnInitDialog()
{
	try
	{
		CDialog::OnInitDialog();
		GetRGBFromIni();
		
		CSystemInfo obj;

		m_hResDLL = NULL;
		m_hResDLL = LoadLibraryEx(CSystemInfo::m_strModulePath + _T("AuGuiRes.dll"), nullptr, LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE);
		if(m_hResDLL == NULL)
		{
			DWORD dw = GetLastError();
			CString csStr;
			csStr.Format(_T("%d"), dw);
			//AfxMessageBox(csStr);
		}

		if(m_hResDLL == NULL)
			m_hResDLL = AfxGetResourceHandle();

		m_Icon = LoadIcon(m_hResDLL,  MAKEINTRESOURCE(IDI_PRODUCT_ICON));

		SetIcon(m_Icon, FALSE);
		SetIcon(m_Icon, TRUE);
		m_pTitleFont = CMaxFont::GetBoldSize21Font();
		m_pMsgFont = CMaxFont::GetNormalSize16Font();
		m_pbtnFont = CMaxFont::GetNormalSize20Font();
		m_stTilte.SetFont(m_pTitleFont);
		m_stMessage.SetFont(m_pMsgFont);
		m_stMessage.SetTextColor(MAINUIDLG_CONTENT_TEXT_RGB);
		//m_stTilte.SetTextColor(RGB (51,51,51));
		m_stTilte.SetTextColor(MAINUIDLG_HEADING_TEXT_RGB);
		m_stTilte.SetWindowText(m_csProdName);

		this->SetWindowTextW(m_csProdName);

		//CSystemInfo oSysInfo;
		//CRect rect1;
		//this->GetClientRect(rect1);
		////rgn.CreateRectRgn(rect1.left, rect1.top, rect1.right-3, rect1.bottom-2);
		//CProductInfo oProdInfo;
		//if(oProdInfo.SquareCorners())
		//	rgn.CreateRectRgn(rect1.left, rect1.top, rect1.right-3, rect1.bottom-3);
		//else
		//	rgn.CreateRoundRectRgn(rect1.left, rect1.top, rect1.right-2, rect1.bottom-2, 11, 11);
		//this->SetWindowRgn(rgn, TRUE);

		m_btnOk.SetWindowText(_T("Yes"));
		m_btnClose.SetWindowText(_T("No"));

		
		{
			m_btnOk.SetSkin(m_hResDLL, IDB_BITMAP_SMALL, IDB_BITMAP_SMALL_OVER, IDB_BITMAP_SMALL_OVER, IDB_BITMAP_SMALL_DISABLE, IDB_BITMAP_SMALL_FOCUS, IDB_BTN_SMALL_MASK, 0, 0, 0);
			m_btnClose.SetSkin(m_hResDLL, IDB_BITMAP_SMALL, IDB_BITMAP_SMALL_OVER, IDB_BITMAP_SMALL_OVER, IDB_BITMAP_SMALL_DISABLE, IDB_BITMAP_SMALL_FOCUS, IDB_BTN_SMALL_MASK, 0, 0, 0);
		}
		m_btnOk.SetSkin(m_hResDLL,IDB_BITMAP_NEWSAVE_NORMAL, IDB_BITMAP_NEWSAVE_OVER, IDB_BITMAP_NEWSAVE_OVER, IDB_BITMAP_NEWSAVE_NORMAL, IDB_BITMAP_NEWSAVE_OVER, IDB_BITMAP_NEWEDIT_MASK, 0, 0, 0);
		m_btnOk.SetTextColorA(INNER_UI_BUTTON_TEXT_RGB, INNER_UI_BUTTON_OVER_TEXT_RGB, INNER_UI_BUTTON_OVER_TEXT_RGB);
		
		//m_btnOk.SetTextColorA (RGB (51,51,51),RGB (51,51,51),RGB (51,51,51));
		m_btnClose.SetSkin(m_hResDLL,IDB_BITMAP_NEWDELETE, IDB_BITMAP_NEWDELETE_OVER , IDB_BITMAP_NEWDELETE_OVER , IDB_BITMAP_NEWDELETE_OVER , IDB_BITMAP_NEWDELETE_OVER , IDB_BITMAP_NEWEDIT_MASK, 0, 0, 0);
		m_btnClose.SetTextColorA(MAINUIDLG_BUTTON_TEXT_RGB,MAIN_UI_BUTTON_OVER_TEXT_RGB, MAIN_UI_BUTTON_OVER_TEXT_RGB);
		//m_pbtnFont = CMaxFont::GetMaxFont(MICROSOFT_SANS_SERIF, MAXSIZE_14, Bold);
		if(m_pbtnFont)
		{
			m_btnOk.SetFont(m_pbtnFont);
			m_btnClose.SetFont(m_pbtnFont);
		}

		CPoint   Point;
		CRect    oWndRect;
		CRect    oDesktopRect;
		int      nWidth;
		int      nHeight;

		// Get the size of the MainWindow and the Desktop.
		this->GetWindowRect(&oWndRect);
		GetDesktopWindow()->GetWindowRect(oDesktopRect);

		// Calculate the height and width for MoveWindow().
		nWidth = oWndRect.Width();
		nHeight = oWndRect.Height();

		// Find the center point and convert to screen coordinates.
		Point.x = oDesktopRect.Width()/ 2;
		Point.y = oDesktopRect.Height()/ 2;
		GetDesktopWindow()->ClientToScreen(&Point);

		// Calculate the new X, Y starting point.
		Point.x -= nWidth / 2;
		Point.y -= nHeight / 2;
		Point.y -= 20;
		// Move the window.
		this->MoveWindow(Point.x, Point.y, nWidth, nHeight, FALSE);
		
		//LoadImages();
		return TRUE;  // return TRUE unless you set the focus to a control
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CYesNoMsgBoxDlg::OnInitDialog"));
		return FALSE;
	}
}

/*-------------------------------------------------------------------------------------
Function		: OnPaint
In Parameters	: -
Out Parameters	: void
Purpose			: This Function is used for painting
Author			:
--------------------------------------------------------------------------------------*/
void CYesNoMsgBoxDlg::OnPaint()
{
	try
	{
		CPaintDC dc(this); // device context for painting

		m_SpyDetectDlgBitmaps->DoGradientFillNew(&dc);
	//	CRect rcDlgRect;
	//	this->GetClientRect(&rcDlgRect);
	//	dc.FillSolidRect( &rcDlgRect, RGB(159, 182, 250) );

		AdjustControls(&dc);
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CYesNoMsgBoxDlg::OnPaint"));
	}
}

/*-------------------------------------------------------------------------------------
Function		: AdjustControls
In Parameters	: CDC
Out Parameters	: void
Purpose			: This Function adjust the cotrols on dialog
Author			:
--------------------------------------------------------------------------------------*/
void CYesNoMsgBoxDlg::AdjustControls(CDC * pDC)
{
	try
	{
		CRect rcDlgRect;
		GetClientRect(&rcDlgRect);

		m_SpyDetectDlgBitmaps ->OnSize();

		HDWP hdwp = BeginDeferWindowPos(10);

		//Adjust dialog's Title
		CRect rcTitleRect;
		m_stTilte.GetClientRect(&rcTitleRect);
		ScreenToClient(&rcTitleRect);
		DeferWindowPos(hdwp, m_stTilte, NULL, rcDlgRect.left + 35, rcDlgRect.top + 7, rcTitleRect.Width(), rcTitleRect.Height(), SWP_NOZORDER);

		//Adjust dialog's No button
		CRect rcNoRect;
		m_btnClose.GetClientRect(&rcNoRect);
		ScreenToClient(&rcNoRect);
		DeferWindowPos(hdwp, m_btnClose, NULL, rcDlgRect.right - rcNoRect.Width() - 28, rcDlgRect.bottom - 46, rcNoRect.Width(), rcNoRect.Height(), SWP_NOZORDER);

		//Adjust dialog's Ok button
		CRect rcOkRect;
		m_btnOk.GetClientRect(&rcOkRect);
		ScreenToClient(&rcOkRect);
		DeferWindowPos(hdwp, m_btnOk, NULL, rcDlgRect.right - (rcNoRect.Width()*2) - 38, rcDlgRect.bottom - 46, rcOkRect.Width(), rcOkRect.Height(), SWP_NOZORDER);

		//m_SpyDetectDlgBitmaps->DrawRectangle(pDC, rcDlgRect, IDC_STATIC_LEFT_BOTTOM3, IDC_STATIC_LEFT_BOTTOM4, IDC_STATIC_LEFT_BOTTOM5, IDC_STATIC_LEFT_BOTTOM6);
	
		EndDeferWindowPos(hdwp);
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CYesNoMsgBoxDlg::AdjustControls"));
	}
}

/*-------------------------------------------------------------------------------------
Function		: OnCtlColor
In Parameters	: CDC, CWnd, UINT
Out Parameters	: HBRUSH
Purpose			: This Function adjust the cotrols on dialog
Author			:
--------------------------------------------------------------------------------------*/
HBRUSH CYesNoMsgBoxDlg::OnCtlColor(CDC* pDC, CWnd* pWnd, UINT nCtlColor)
{
	try
	{
		HBRUSH hbr = CDialog::OnCtlColor(pDC, pWnd, nCtlColor);

		int	ctrlID;
		ctrlID = pWnd->GetDlgCtrlID();
		if(ctrlID == IDC_STATIC_TITLE || ctrlID == IDC_STATIC_MSG)
		{

			pDC->SetBkMode(TRANSPARENT);
			hbr = (HBRUSH)GetStockObject(NULL_BRUSH);
		}

		return hbr;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CYesNoMsgBoxDlg::OnCtlColor"));
		return NULL;
	}
}

/*--------------------------------------------------------------------------------------
Function       : OnNcHitTest
In Parameters  : CPoint point, 
Out Parameters : LRESULT
Description    :
Author         : Sandip Sanap
--------------------------------------------------------------------------------------*/
LRESULT CYesNoMsgBoxDlg::OnNcHitTest(CPoint point)
{
	// TODO: Add your message handler code here and/or call default
	if(!IsZoomed())
	{
		return HTCAPTION;
	}
	return CDialog::OnNcHitTest(point);
}

/*--------------------------------------------------------------------------------------
Function       : OnEraseBkgnd
In Parameters  : CDC* pDC 
Out Parameters : BOOL
Description    : 
Author         : Sid
--------------------------------------------------------------------------------------*/
BOOL CYesNoMsgBoxDlg::OnEraseBkgnd(CDC* pDC)
{
	m_SpyDetectDlgBitmaps->DoGradientFillNew(pDC);
	//pDC->FillSolidRect( &rcDlgRect, RGB (220,219,219) );
	//DrawBorder(pDC);
	return false;
	//return CDialog::OnEraseBkgnd(pDC);
}

/*--------------------------------------------------------------------------------------
Function       : DrawBorder
In Parameters  : CDC* pDC 
Out Parameters : void
Description    : Draws the Border
Author         : Sid
--------------------------------------------------------------------------------------*/
void CYesNoMsgBoxDlg::DrawBorder(CDC * pDC)
{
	CRect rcDlgRect;
	this->GetClientRect(&rcDlgRect);

	CPoint oPt1, oPt2;
//First Point
	oPt1.x = rcDlgRect.left;
	oPt1.y = rcDlgRect.top + 28;

	oPt2.x = oPt1.x;
	oPt2.y = rcDlgRect.bottom;

	DrawLine(pDC,oPt1,oPt2);

//Second Point	
	oPt1.x = rcDlgRect.right - 4;
	oPt1.y = rcDlgRect.top + 28;

	oPt2.x = oPt1.x;
	oPt2.y = rcDlgRect.bottom - 3;

	DrawLine(pDC,oPt1,oPt2);

//Third Point
	oPt1.x = rcDlgRect.left;
	oPt1.y = rcDlgRect.bottom - 3;

	oPt2.x = rcDlgRect.right - 3;
	oPt2.y = rcDlgRect.bottom - 3;
	
	DrawLine(pDC,oPt1,oPt2);
}

/*--------------------------------------------------------------------------------------
Function       : DrawLine
In Parameters  : CDC* pDC 
Out Parameters : void
Description    : DrawLine
Author         : Sid
--------------------------------------------------------------------------------------*/
void CYesNoMsgBoxDlg::DrawLine(CDC * pDC,CPoint oPt1,CPoint oPt2)
{
	LOGBRUSH oLogBrush = {0};
	oLogBrush.lbStyle = BS_SOLID;
	oLogBrush.lbColor = RGB (90,90,90);

	CPen pen2(PS_SOLID, 1, &oLogBrush);
	CPen * oldPen = pDC->SelectObject(&pen2);

	pDC->MoveTo(oPt1);
	pDC->LineTo(oPt2);

	pDC->SelectObject(oldPen);
}

/*-------------------------------------------------------------------------------------
Function		: LoadImages.
In Parameters	: 
Out Parameters	: void
Purpose			: To Load backgrounding Image
Author			: Tejas Kurhade
--------------------------------------------------------------------------------------*/
void CYesNoMsgBoxDlg::LoadImages()
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

/*-------------------------------------------------------------------------------------
Function		: GetRGBFromIni
In Parameters	: void
Out Parameters	: void
Purpose			: Get RGb value from ini
Author			: Dipali PAwar
--------------------------------------------------------------------------------------*/
void CYesNoMsgBoxDlg::GetRGBFromIni()
{
	CString csIniPath = CSystemInfo::m_strModulePath + SETTING_FOLDER + CURRENT_SETTINGS_INI;
	BACKGROUND_RBG			= GetPrivateProfileInt(_T("colorcode"), _T("BACKGROUND"), 0, csIniPath);
	BANNER_TEXT_COLOR_RGB	= GetPrivateProfileInt(_T("colorcode"), _T("BANNER_TEXT_COLOR"), 0, csIniPath);
	BLACK_RBG				= GetPrivateProfileInt(_T("colorcode"), _T("BLACK"), 0, csIniPath);
	TABINFORMATIONLABLE_RGB = GetPrivateProfileInt(_T("colorcode"), _T("TABINFORMATIONLABLE"), 0, csIniPath);
	BANNER_TEXT_COLOR_RGB	= GetPrivateProfileInt(_T("colorcode"), _T("BANNER_TEXT_COLOR"), 0, csIniPath);;
	TABBACKGROUND_RGB		= GetPrivateProfileInt(_T("colorcode"), _T("TABBACKGROUND"), 0, csIniPath);
	TAB_TEXT_COLOR_RGB		= GetPrivateProfileInt(_T("colorcode"), _T("TAB_TEXT_COLOR"), 0, csIniPath);
	TITLE_COLOR_RGB			= GetPrivateProfileInt(_T("colorcode"), _T("TITLE_COLOR"), 0, csIniPath);
	MAIN_UI_BUTTON_TEXT_RGB = GetPrivateProfileInt(_T("colorcode"), _T("MAIN_UI_BUTTON_TEXT"), 7434354, csIniPath);
	MAIN_UI_BUTTON_OVER_TEXT_RGB	= GetPrivateProfileInt(_T("colorcode"), _T("MAIN_UI_BUTTON_OVER_TEXT"), 7434354, csIniPath);
	MAIN_UI_BUTTON_FOCUS_TEXT_RGB	= GetPrivateProfileInt(_T("colorcode"), _T("MAIN_UI_BUTTON_FOCUS_TEXT"), 7434354, csIniPath);
	INNER_UI_BUTTON_TEXT_RGB		= GetPrivateProfileInt(_T("colorcode"), _T("INNER_UI_BUTTON_TEXT"), 7434354, csIniPath);
	INNER_UI_BUTTON_OVER_TEXT_RGB	= GetPrivateProfileInt(_T("colorcode"), _T("INNER_UI_BUTTON_OVER_TEXT"), 7434354, csIniPath);
	INNER_UI_BUTTON_FOCUS_TEXT_RGB	= GetPrivateProfileInt(_T("colorcode"), _T("INNER_UI_BUTTON_FOCUS_TEXT"), 7434354, csIniPath);
	BLUEBACKGROUND_RGB		= GetPrivateProfileInt(_T("colorcode"), _T("BLUEBACKGROUND"), 0, csIniPath);
	UI_BORDER_RGB			= GetPrivateProfileInt(_T("colorcode"), _T("UI_BORDER"), 0, csIniPath);
	INNER_UI_BORDER_RGB		= GetPrivateProfileInt(_T("colorcode"), _T("INNER_UI_BORDER"), 0, csIniPath);
	MAIN_UI_MIDDLE_BG_RGB	= GetPrivateProfileInt(_T("colorcode"), _T("MAIN_UI_MIDDLE_BG"), 0, csIniPath);
	INFO_COLOR_RGB			= GetPrivateProfileInt(_T("colorcode"), _T("INFO_COLOR"), 0, csIniPath);
	INFO_TEXT_COLOR_RGB		= GetPrivateProfileInt(_T("colorcode"), _T("INFO_TEXT_COLOR"), 0, csIniPath);
	TAB_INFO_LABEL_RGB		= GetPrivateProfileInt(_T("colorcode"), _T("TAB_INFO_LABEL"), WHITE, csIniPath);	
	TAB_INFO_LABEL_SIDE_BAR_RGB		= GetPrivateProfileInt(_T("colorcode"), _T("TAB_INFO_LABEL_SIDE_BAR"), WHITE, csIniPath);	
	UI_MIDDLE_BG_RGB				= GetPrivateProfileInt(_T("colorcode"), _T("UI_MIDDLE_BG"), WHITE, csIniPath);
	SHOW_TIPS_TOP_COLOR_RGB			= GetPrivateProfileInt(_T("colorcode"), _T("SHOW_TIPS_TOP_COLOR"), WHITE, csIniPath);
	BUYNOW_LINK_TEXT_COLOR_RGB		= GetPrivateProfileInt(_T("colorcode"), _T("BUYNOW_LINK_TEXT_COLOR"), WHITE, csIniPath);
	SELECTDRIVE_LU_TEXT_COLOR_RGB	= GetPrivateProfileInt(_T("colorcode"), _T("SELECTDRIVE_LU_TEXT_COLOR"), 16777215, csIniPath);
	INNER_UI_TAB_TEXT_COLOR_RGB		= GetPrivateProfileInt(_T("colorcode"), _T("INNER_UI_TAB_TEXT_COLOR"), 16777215, csIniPath);
	BTN_TEXT_COLOR_RGB				= GetPrivateProfileInt(_T("colorcode"), _T("BTN_TEXT_COLOR"), 16777215, csIniPath);
	MAINUIDLG_HEADING_TEXT_RGB =		GetPrivateProfileInt(_T("colorcode"), _T("MAINUIDLG_HEADING_TEXT"),16777215, csIniPath);
	MAINUIDLG_CONTENT_TEXT_RGB =		GetPrivateProfileInt(_T("colorcode"), _T("MAINUIDLG_CONTENT_TEXT"),16777215, csIniPath);
	MAINUIDLG_BUTTON_TEXT_RGB =			GetPrivateProfileInt(_T("colorcode"), _T("MAINUIDLG_BUTTON_TEXT"),16777215, csIniPath);
	GetPrivateProfileString(_T("Settings"), _T("PRODUCTNAME"), _T(""), m_csProdName.GetBuffer(MAX_PATH), MAX_PATH, csIniPath);
	m_csProdName.ReleaseBuffer();
}

