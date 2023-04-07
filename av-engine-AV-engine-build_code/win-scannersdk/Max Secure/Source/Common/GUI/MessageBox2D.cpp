/*=============================================================================
   FILE		           : MessageBox2D.cpp
   ABSTRACT		       : 
   DOCUMENTS	       : 
   AUTHOR		       : 
   COMPANY		       : Aura 
   COPYRIGHT NOTICE    :
						(C) Aura
						 Created as an unpublished copyright work.  All rights reserved.
						 This document and the information it contains is confidential and
						 proprietary to Aura.  Hence, it may not be 
						 used, copied, reproduced, transmitted, or stored in any form or by any 
						 means, electronic, recording, photocopying, mechanical or otherwise, 
						 without the prior written permission of Aura.	
   CREATION DATE      : 
   NOTES		      : implementation file
   VERSION HISTORY    : 
						
						
=============================================================================*/

#include "stdafx.h"
#include "ResourceManager.h"
#include "MessageBox2D.h"
#include "Registry.h"
#include "SDSystemInfo.h"
#include "Messagebox2D.h"
#include "SDSAconstants.h"
#include "resource.h"
#include "DownloadConst.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

IMPLEMENT_DYNAMIC(CMessageBox2D, CDialog)

/*-------------------------------------------------------------------------------------
	Function		: CMessageBox2D
	In Parameters	: CWnd* pParent
	Out Parameters	: -
	Purpose			: Constructor for class CMessageBox2D
	Author			: Nitin Shekokar
--------------------------------------------------------------------------------------*/
CMessageBox2D::CMessageBox2D(CWnd* pParent, HMODULE hResDLL)
	: CDialog(CMessageBox2D::IDD, pParent)
	,m_StaticLink(hResDLL)
{
	m_IsErrorCall = false;
	m_IsCancel = false;
	//calling the constructor to adjust the titlebar corner logo and Titlebar : Mrudula
	m_SpyDetectDlgBitmaps = NULL;

	m_SpyDetectDlgBitmaps = new CSpyDetectDlgBitmaps( this, 
		NULL, 
		NULL, 
		NULL, 
		NULL, 
		NULL, 
		NULL, 
		NULL, 
		NULL,
		100000);
	m_nColor = DOWNLOADMGR_COLOR;
}

/*-------------------------------------------------------------------------------------
	Function		: ~CMessageBox2D
	In Parameters	: -
	Out Parameters	: -
	Purpose			: Destructor for class CMessageBox2D
	Author			: Nitin Shekokar
--------------------------------------------------------------------------------------*/
CMessageBox2D::~CMessageBox2D()
{
	if( m_SpyDetectDlgBitmaps )
	{
		delete m_SpyDetectDlgBitmaps;
		m_SpyDetectDlgBitmaps = NULL;
	}
}

/*-------------------------------------------------------------------------------------
	Function		: DoDataExchange
	In Parameters	: CDataExchange* pDX
	Out Parameters	: void
	Purpose			: Called by the framework to exchange and validate dialog data.
	Author			: Nitin Shekokar
--------------------------------------------------------------------------------------*/
void CMessageBox2D::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	DDX_Control(pDX,IDOK, m_btnOk);
	DDX_Control(pDX,IDYES, m_btYes);
	DDX_Control(pDX, IDC_STATIC_TITLE, m_stTitle);
	//DDX_Control( pDX, IDC_STATIC_MSG, m_Message );
	DDX_Control( pDX, IDC_STATIC_MSG, m_lblMessageBox );
	DDX_Text( pDX, IDC_STATIC_MSG, m_csMessage );
	DDX_Control(pDX, IDC_STATIC_LINK, m_StaticLink);	
}

BEGIN_MESSAGE_MAP(CMessageBox2D, CDialog)
	ON_BN_CLICKED(IDOK, OnBnClickedOk)
	ON_BN_CLICKED(IDYES, OnBnClickedYes)
	ON_WM_PAINT()
	ON_WM_CTLCOLOR()
	ON_WM_NCHITTEST()
END_MESSAGE_MAP()

/*-------------------------------------------------------------------------------------
	Function		: OnBnClickedOk
	In Parameters	: -
	Out Parameters	: void
	Purpose			: Function to handle ok button click
	Author			: Nitin Shekokar
--------------------------------------------------------------------------------------*/
void CMessageBox2D::OnBnClickedOk()
{
	
	if(m_IsError == false)
	{
		m_IsCancel = false;
	}
	else
	{
		m_IsCancel = true;
	}
	OnOK();
}

void CMessageBox2D::OnBnClickedYes()
{
	if(m_IsError == true)
	{
		m_IsCancel = false;
	}
	else
	{
		m_IsCancel = true;
	}
	
	OnOK();
}

/*-------------------------------------------------------------------------------------
	Function		: OnInitDialog
	In Parameters	: -
	Out Parameters	: BOOL
	Purpose			: This member function is called in response to the WM_INITDIALOG message.
	Author			: Nitin Shekokar
--------------------------------------------------------------------------------------*/
BOOL CMessageBox2D::OnInitDialog()
{
	CDialog::OnInitDialog();

	this->SetIcon(m_Icon, TRUE);
	this->SetIcon(m_Icon, FALSE);
	m_stTitle.SetFont(&m_SpyDetectDlgBitmaps->m_fontWindowTitle);
	if(m_nColor == RED_COLOUR)
	{
		m_stTitle.SetTextColor(RGB (255, 255, 255));
	}
	else if(m_nColor == BLUE_COLOUR)
	{
		m_stTitle.SetTextColor(RGB(255, 255, 255));
	}
	else if(m_nColor == GE_BLUE_COLOR)
	{
		m_stTitle.SetTextColor(RGB(255, 255, 255));
	}
	m_stTitle.SetWindowText (DOWNLOADMGR_UI_TITLE);
	this->SetWindowText(DOWNLOADMGR_UI_TITLE);

	//////////////////////Button UI/////////////////////////////
	m_btYes.SetSkin(IDB_BUTTON_NORMAL, IDB_BUTTON_OVER, IDB_BUTTON_OVER, 0,
		IDB_BUTTON_FOCUS, IDB_BUTTON_MASK, 0, 0, 0);//set skin
	m_btYes.SetFont(&m_SpyDetectDlgBitmaps->m_fontButton);
	m_btnOk.SetSkin(IDB_BUTTON_NORMAL, IDB_BUTTON_OVER, IDB_BUTTON_OVER, 0,
		IDB_BUTTON_FOCUS, IDB_BUTTON_MASK, 0, 0, 0);//set skin
	m_btnOk.SetFont(&m_SpyDetectDlgBitmaps->m_fontButton);
	/////////////////////End button UI//////////////////////////
	if ( m_IsErrorCall )
	{
		m_IsError = false; 
		m_btnOk.SetWindowText(csNoMsg1);
		//m_btnOk.SetWindowText(csOKMsg);
		m_btYes.ShowWindow (SW_SHOW);
	}
	else if( m_IsErrorCall == false)
	{
		m_IsError = true;
		m_btYes.SetWindowText(csRetryMsg1);
		m_btnOk.SetWindowText(csCancelMsg1);
	}
	if(m_strTitle.GetLength() > 0)
	{
		m_StaticLink.SetWindowText(m_strTitle);
		m_StaticLink.SetURL(m_strLink);
	}
	else
	{
		m_StaticLink.ShowWindow(SW_HIDE);
	}
#ifdef RELEASE_BLUE_PRO
	if(m_nColor == RED_COLOUR)
	{
		/*m_btnOk.SetTextColorA(RGB (140, 8, 3), 0 ,RGB (73, 72, 72));
		m_btYes.SetTextColorA(RGB (140, 8, 3), 0 ,RGB (73, 72, 72));*/
		m_btnOk.SetTextColorA(RGB (0, 0, 0), 0 ,RGB (0, 0, 0));
		m_btYes.SetTextColorA(RGB (0, 0, 0), 0 ,RGB (0, 0, 0));
	}
	if(m_nColor == BLUE_COLOUR)
	{
		/*m_btnOk.SetTextColorA(RGB (140, 8, 3), 0 ,RGB (73, 72, 72));
		m_btYes.SetTextColorA(RGB (140, 8, 3), 0 ,RGB (73, 72, 72));*/
		m_btnOk.SetTextColorA(RGB (0, 0, 0), 0 ,RGB (0, 0, 0));
		m_btYes.SetTextColorA(RGB (0, 0, 0), 0 ,RGB (0, 0, 0));
	}
	/*else if(m_nColor == GE_BLUE_COLOR)
	{
		m_btnOk.SetTextColorA(RGB (255, 255, 255));
		m_btYes.SetTextColorA(RGB (255, 255, 255));
	}
	*/
#elif  RELEASE_RED_PRO
	if(m_nColor == RED_COLOUR)
	{
		m_btnOk.SetTextColorA(RGB (140, 8, 3), 0 ,RGB (73, 72, 72));
		m_btYes.SetTextColorA(RGB (140, 8, 3), 0 ,RGB (73, 72, 72));
	}
	if(m_nColor == BLUE_COLOUR)
	{
		m_btnOk.SetTextColorA(RGB (140, 8, 3), 0 ,RGB (73, 72, 72));
		m_btYes.SetTextColorA(RGB (140, 8, 3), 0 ,RGB (73, 72, 72));
	
	}
#else
	if(m_nColor == RED_COLOUR)
	{
		m_btnOk.SetTextColorA(RGB (140, 8, 3), 0 ,RGB (73, 72, 72));
		m_btYes.SetTextColorA(RGB (140, 8, 3), 0 ,RGB (73, 72, 72));
	}
	else if(m_nColor == GE_BLUE_COLOR)
	{
		m_btnOk.SetTextColorA(RGB (255, 255, 255));
		m_btYes.SetTextColorA(RGB (255, 255, 255));
	}
	
#endif
	UpdateData(FALSE);
	return TRUE;  // return TRUE unless you set the focus to a control
	// EXCEPTION: OCX Property Pages should return FALSE
}

/*-------------------------------------------------------------------------------------
	Function		: OnPaint
	In Parameters	: -
	Out Parameters	: void
	Purpose			: Function to handle paint event
	Author			: Nitin Shekokar
--------------------------------------------------------------------------------------*/
void CMessageBox2D::OnPaint()
{
	CPaintDC dc(this); // device context for painting	
	AdjustControls(&dc);
#ifdef RELEASE_BLUE_PRO
	m_SpyDetectDlgBitmaps->DoGradientFillDM(&dc);	//painting the dialog and also the titlebar
#elif RELEASE_RED_PRO
	m_SpyDetectDlgBitmaps->DoGradientFillDM(&dc);
#else
	m_SpyDetectDlgBitmaps->DoGradientFill(&dc);	//painting the dialog and also the titlebar
#endif
	AdjustControls(&dc);
	//m_SpyDetectDlgBitmaps ->OnSize( );	//to adjust the title bar and icon on the dialog
}

void CMessageBox2D::AdjustControls(CDC * pDC)
{
	CRect rcDlgRect, rcList, rcEdit;
	GetClientRect(&rcDlgRect);
	//m_SpyDetectDlgBitmaps ->OnSize();
	HDWP hdwp = BeginDeferWindowPos(20);

	int nLeft = rcDlgRect.left;
	int nTop = rcDlgRect.top;
	int nRight = rcDlgRect.right;
	int nBottom = rcDlgRect.bottom;
	
	CRect rcTitleRect;
	m_stTitle.GetClientRect(&rcTitleRect);
	ScreenToClient(&rcTitleRect);
	DeferWindowPos(hdwp, m_stTitle, NULL, rcDlgRect.left + 20, rcDlgRect.top + 15,
		rcTitleRect.Width(), rcTitleRect.Height(), SWP_NOZORDER);

	//DrawRectangle(pDC, nLeft-1, nTop-1, nRight, nBottom , m_nColor);
	
	nLeft = rcDlgRect.left + 15;
	nTop = rcDlgRect.top + 43;
	nRight = rcDlgRect.right - 15;
	nBottom = rcDlgRect.bottom -15;

	//DrawRectangle(pDC, nLeft, nTop, nRight, nBottom, WHITE_COLOUR);
	
	EndDeferWindowPos(hdwp);
}
/*-------------------------------------------------------------------------------------
	Function		: OnCtlColor
	In Parameters	: CDC* pDC, CWnd* pWnd, UINT nCtlColor
	Out Parameters	: HBRUSH
	Purpose			: The framework calls this member function when a child control is about to be drawn.
	Author			: Nitin Shekokar
--------------------------------------------------------------------------------------*/
HBRUSH CMessageBox2D::OnCtlColor(CDC* pDC, CWnd* pWnd, UINT nCtlColor)
{
	HBRUSH hbr = CDialog::OnCtlColor(pDC, pWnd, nCtlColor);

	int	ctrlID;
	ctrlID = pWnd->GetDlgCtrlID();
	if(ctrlID==IDC_STATIC_TITLE)
	{
	
		pDC->SetBkMode(TRANSPARENT);
		hbr = (HBRUSH)GetStockObject(NULL_BRUSH);
	}
	

	// TODO:  Return a different brush if the default is not desired
	return hbr;
}

/*-------------------------------------------------------------------------------------
	Function		: OnNcHitTest
	In Parameters	: CPoint point
	Out Parameters	: UINT
	Purpose			: The framework calls this member function for the CWnd object that 
	                  contains the cursor (or the CWnd object that used the SetCapture
					  member function to capture the mouse input) every time the mouse is moved.
	Author			: Nitin Shekokar
--------------------------------------------------------------------------------------*/
LRESULT CMessageBox2D::OnNcHitTest(CPoint point)
{
	// TODO: Add your message handler code here and/or call default
	if( ! IsZoomed( ) )
	{		
		return HTCAPTION;
	}
	return CDialog::OnNcHitTest(point);
}


/*-------------------------------------------------------------------------------------
Function		: DrawRectangle
In Parameters	: -
Out	Parameters	: void
Purpose			: to draw the white oRcRectangle on dialog both upper and lower
Author			: Nitin Shekokar
--------------------------------------------------------------------------------------*/
void CMessageBox2D::DrawRectangle(CDC * pDC, int left, int top, int right, int bottom ,int ColourFlg)
{
	CRect oRcRectangle;
	int i = 0;

	for(i = left; i <= right; ++i)// Fill in strip
	{
		oRcRectangle.SetRect(i, top, i + 1, bottom );

		if(i <= (left+1))
		{
			oRcRectangle.SetRect(i, top, i + 1, bottom);
			if ( ColourFlg == BLUE_COLOUR )
			{
				pDC ->FillSolidRect(&oRcRectangle, RGB(62, 93, 189));
			}
			else if ( ColourFlg == RED_COLOUR )
			{
				pDC ->FillSolidRect(&oRcRectangle, RGB (104, 2, 1));
			}
			else if(ColourFlg == GE_BLUE_COLOR)
			{
				pDC ->FillSolidRect(&oRcRectangle, RGB (2, 24, 41));
			}
			
		}
		else if(i >= (right-1) && i <= right)
		{
			oRcRectangle.SetRect(i, top, i + 1, bottom);
			if ( ColourFlg == BLUE_COLOUR )
			{
				pDC ->FillSolidRect(&oRcRectangle, RGB(62, 93, 189));
			}
			else if ( ColourFlg == RED_COLOUR )
			{
				pDC ->FillSolidRect(&oRcRectangle, RGB (104, 2, 1));
			}
			else if(ColourFlg == GE_BLUE_COLOR)
			{
				pDC ->FillSolidRect(&oRcRectangle, RGB (2, 24, 41));
			}
			
		}
		else
		{
			if ( ColourFlg == BLUE_COLOUR )
				pDC ->FillSolidRect(&oRcRectangle, RGB(159, 182, 250));
			else if ( ColourFlg == RED_COLOUR )
				pDC ->FillSolidRect(&oRcRectangle, RGB (170,1,4));
			else if( ColourFlg == WHITE_COLOUR ) 
				pDC ->FillSolidRect(&oRcRectangle, RGB(255, 255, 255));
			else if(ColourFlg == GE_BLUE_COLOR)
				pDC ->FillSolidRect(&oRcRectangle, RGB (2, 24, 41));
			
		}
	}

	//bottom horizontal line
	oRcRectangle.SetRect(left, bottom - 1, right, bottom + 1);
	if ( ColourFlg == BLUE_COLOUR )
	{
		pDC ->FillSolidRect(&oRcRectangle, RGB(62, 93, 189));
	}
	else if ( ColourFlg == RED_COLOUR )
	{
		pDC ->FillSolidRect(&oRcRectangle, RGB (104, 2, 1));
	}
	else if(ColourFlg == GE_BLUE_COLOR)
	{
		pDC ->FillSolidRect(&oRcRectangle, RGB (2, 24, 41));
	}
	


	//top horizontal line
	oRcRectangle.SetRect(left, top, right, top+2);
	if ( ColourFlg == BLUE_COLOUR )
	{
		pDC ->FillSolidRect(&oRcRectangle, RGB(62, 93, 189));
	}
	else if ( ColourFlg == RED_COLOUR )
	{
		pDC ->FillSolidRect(&oRcRectangle, RGB (104, 2, 1));
	}
	else if(ColourFlg == GE_BLUE_COLOR)
	{
		pDC ->FillSolidRect(&oRcRectangle, RGB (2, 24, 41));
	}
	
}

/*-------------------------------------------------------------------------------------
Function		: SetURL
In Parameters	: CString &strTitle, CString &strLink
Out	Parameters	: void
Purpose			: Assigns title and Link
Author			: Darshit Kasliwal
--------------------------------------------------------------------------------------*/
void CMessageBox2D::SetURL(CString strTitle, CString strLink)
{
	m_strTitle = strTitle;
	m_strLink = strLink;
}