/*======================================================================================
FILE			: MessageBox.cpp
ABSTRACT		: 
DOCUMENTS	: CheckDll DesignDoc.doc
COMPANY		 : Aura 
COPYRIGHT NOTICE:
			(C) Aura
			Created as an unpublished copyright work.  All rights reserved.
			This document and the information it contains is confidential and
			proprietary to Aura.  Hence, it may not be 
			used, copied, reproduced, transmitted, or stored in any form or by any 
			means, electronic, recording, photocopying, mechanical or otherwise, 
			with out the prior written permission of Aura
CREATION DATE: 18/01/2008
NOTES		:
VERSION HISTORY : 
======================================================================================*/

#include "pch.h"
#include "MessageBox.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

#define BITSET(dw, bit)		(((dw)& (bit)) != 0L)


IMPLEMENT_DYNAMIC(CMessageBox, CDialog)

/*-----------------------------------------------------------------------------
Function		: CMessageBox (CONSTRUCTOR)
In Parameters	: CWnd* : Handle to CWnd class
Out Parameters	:
Purpose			: initialize CMessageBox class
Author			:
-----------------------------------------------------------------------------*/
CMessageBox::CMessageBox(CWnd* pParent /*=NULL*/): CJpegDialog(CMessageBox::IDD, pParent)
{
}

/*-----------------------------------------------------------------------------
Function		: ~CMessageBox (DISTRUCTOR)
In Parameters	:
Out Parameters	:
Purpose		: delete member object
Author		:
-----------------------------------------------------------------------------*/
CMessageBox::~CMessageBox()
{
}


/*-----------------------------------------------------------------------------
Function		: DoDataExchange
In Parameters	: CDataExchange* : A pointer to a CDataExchange object.
Out Parameters	:
Purpose		: Called by the framework to exchange and validate dialog data
Author		:
-----------------------------------------------------------------------------*/
void CMessageBox::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_STATIC_MSG2, m_st_Message);
	DDX_Control(pDX, IDC_STATIC_LINK, m_st_link);
}

/*-----------------------------------------------------------------------------
Function		: OnInitDialog
In Parameters	:
Out Parameters	: BOOL : return TRUE  unless you set the focus to a control
Purpose		:This function is called to perform special processing
when the dialog box is initialized
Author		:
-----------------------------------------------------------------------------*/
BOOL CMessageBox::OnInitDialog()
{
	CJpegDialog::OnInitDialog();
	m_brBlue.CreateSolidBrush(BLUEBACKGROUND);
	m_st_Message.SetWindowText(m_Text);
	m_st_link.SetWindowText(m_Link);
	this->SetWindowText(m_Title);
	m_st_link.SetTextColor(RGB(0, 0, 255));
 
	return true;
}

/*-----------------------------------------------------------------------------
Function		: OnCtlColor
In Parameters	: CDC* :  device-context  pointer
				: CWnd* :Contains a pointer to the control asking for the color
				: UINT : specifying the type of control:
Out Parameters	:HBRUSH : return a handle to the brush that is to be used for
				painting the control background.
Purpose			:The framework calls this member function when a child control is
				about to be drawn.This function is used to prepare pDc for
				drawing the controll or setting other attribute of controll
Author			:
-----------------------------------------------------------------------------*/
HBRUSH CMessageBox::OnCtlColor(CDC* pDC, CWnd* pWnd, UINT nCtlColor)
{
	HBRUSH hbr = CJpegDialog::OnCtlColor(pDC, pWnd, nCtlColor);

	int	iCtrlID;
	iCtrlID = pWnd->GetDlgCtrlID();
	if(iCtrlID == IDC_STATIC_MSG2 || iCtrlID == IDC_STATIC_LINK)
	{
		pDC->SetBkMode(TRANSPARENT);
		hbr = (HBRUSH)GetStockObject(NULL_BRUSH);
	}
	return hbr;
}


BEGIN_MESSAGE_MAP(CMessageBox, CDialog)
	ON_WM_CTLCOLOR()
	ON_WM_LBUTTONDOWN()
END_MESSAGE_MAP()


/*-----------------------------------------------------------------------------
Function		: OnLButtonDown
In Parameters	: UINT :  Indicates whether various virtual keys are down
				: CPoint : Specifies the x- and y-coordinate of the cursor
Out Parameters	:
Purpose		:The framework calls this member function when the user presses the
			left mouse button.
Author		: Nupur
-----------------------------------------------------------------------------*/
void CMessageBox::OnLButtonDown(UINT nFlags, CPoint point)
{
	//CRect oRect;
	//m_st_link.GetClientRect(&oRect);
	
	if(!m_Link.IsEmpty())
	{
		ShellExecute(NULL, _T("open"), m_Link, NULL, NULL, SW_SHOW);
	}
	CJpegDialog::OnLButtonDown(nFlags, point);
}
