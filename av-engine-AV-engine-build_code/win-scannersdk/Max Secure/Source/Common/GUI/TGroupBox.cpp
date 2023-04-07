/*=============================================================================
   FILE			: TGroupBox.h
   ABSTRACT		: This class will be used for drawing the transparent group box. This
				  class will avoid the drawing of rectangle over the caption of group
				  box when using a bitmap image as background. This class will inherit
				  from CButton class.
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
CREATION DATE   : 2/24/06
   NOTES		:
VERSION HISTORY	:
				
============================================================================*/
#include "pch.h"
#include "TGroupBox.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*-------------------------------------------------------------------------------------
Function		: CTGroupBox
In Parameters	: -
Out	Parameters	: -
Purpose			: standard constructor
Author			:
--------------------------------------------------------------------------------------*/
CTGroupBox::CTGroupBox(void)
{
}

/*-------------------------------------------------------------------------------------
Function		: ~CTGroupBox
In Parameters	: -
Out	Parameters	: -
Purpose			: destructor to free memory
Author			:
--------------------------------------------------------------------------------------*/
CTGroupBox::~CTGroupBox(void)
{
	m_NormalFont.DeleteObject();
}


BEGIN_MESSAGE_MAP(CTGroupBox, CButton)
	//{{AFX_MSG_MAP(CTGroupBox)
	ON_WM_PAINT()
	ON_WM_LBUTTONDOWN()
	ON_WM_LBUTTONUP()
	ON_WM_LBUTTONDBLCLK()
	ON_WM_MBUTTONDBLCLK()
	ON_WM_MBUTTONDOWN()
	ON_WM_MBUTTONUP()
	ON_WM_NCLBUTTONDOWN()
	ON_WM_NCLBUTTONUP()
	ON_WM_NCMBUTTONDBLCLK()
	ON_WM_NCMBUTTONDOWN()
	ON_WM_NCMBUTTONUP()
	ON_WM_NCRBUTTONDBLCLK()
	ON_WM_NCRBUTTONDOWN()
	ON_WM_NCRBUTTONUP()
	ON_WM_RBUTTONUP()
	ON_WM_RBUTTONDOWN()
	ON_WM_RBUTTONDBLCLK()
	ON_CONTROL_REFLECT(BN_CLICKED, OnClicked)
	ON_CONTROL_REFLECT(BN_DOUBLECLICKED, OnDoubleclicked)
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()

/*-------------------------------------------------------------------------------------
Function		: PreSubclassWindow
In Parameters	: void
Out	Parameters	: void
Purpose			: to allow other necessary subclassing to occur before the window is
subclassed
Author			:
--------------------------------------------------------------------------------------*/
void CTGroupBox::PreSubclassWindow(void)
{
	try
	{
		ModifyStyle(0, BS_OWNERDRAW|BS_GROUPBOX);

		CFont*		pFont = GetFont();
		LOGFONT		lf;
		pFont->GetLogFont(&lf);

		m_NormalFont.DeleteObject();
		m_NormalFont.CreateFontIndirect(&lf);
		SetFont(&m_NormalFont);
		CButton::PreSubclassWindow();
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CTGroupBox::PreSubclassWindow"));
	}
}

/*-----------------------------------------------------------------------------
Function		: OnPaint
In Parameters	:
Out Parameters	:
Purpose		: The framework calls this member function when Windows or
an application makes a request to repaint a portion of an
application's window.User can put check here for any necessary
internal repainting
Author		:
-----------------------------------------------------------------------------*/
void CTGroupBox::OnPaint(void)
{
	try
	{
		CRect	 rc;
		CPoint	 ptStart, ptEnd;
		CSize	 seText;
		CString	 sText, sTemp;
		CPen	 pnFrmDark, pnFrmLight, *ppnOldPen;
		int		 iUpDist, nSavedDC;
		DWORD	 dwStyle, dwExStyle;


		CPaintDC dc(this); // device context for painting

		// save dc state
		nSavedDC = dc.SaveDC();

		dc.SelectObject(&m_NormalFont);

		// window rect
		GetWindowRect(&rc);
		ScreenToClient(&rc);

		// determine text length
		GetWindowText(sTemp);
		sText.Format(_T(" %s "), static_cast<LPCTSTR>(sTemp)); // looks better with a blank on each side
		seText = dc.GetTextExtent(sText);

		// distance from window top to group rect
		iUpDist =(seText.cy / 2);

		// calc rect and start/end points
		dwStyle = GetStyle();
		dwExStyle = GetExStyle();

		// handle text alignment (Caution: BS_CENTER == BS_LEFT|BS_RIGHT!!!)
		ptStart.y = ptEnd.y = rc.top + iUpDist;
		if((dwStyle & BS_CENTER) == BS_RIGHT)// right aligned
		{
			ptEnd.x = rc.right - OFS_X;
			ptStart.x = ptEnd.x - seText.cx;
		}
		else if((!(dwStyle & BS_CENTER)) ||((dwStyle & BS_CENTER) == BS_LEFT))// left aligned	/ default
		{
			ptStart.x = rc.left + OFS_X;
			ptEnd.x = ptStart.x + seText.cx;
		}
		else if((dwStyle & BS_CENTER) == BS_CENTER)// text centered
		{
			ptStart.x = (rc.Width() - seText.cx)/ 2;
			ptEnd.x = ptStart.x + seText.cx;
		}


		if(dwStyle & BS_FLAT)// "flat" frame
		{
			VERIFY(pnFrmDark.CreatePen(PS_SOLID, 1, RGB(0, 0, 0)));
			VERIFY(pnFrmLight.CreatePen(PS_SOLID, 1, ::GetSysColor(COLOR_3DHILIGHT)));

			ppnOldPen = dc.SelectObject(&pnFrmDark);

			dc.MoveTo(ptStart);
			dc.LineTo(rc.left, ptStart.y);
			dc.LineTo(rc.left, rc.bottom);
			dc.LineTo(rc.right, rc.bottom);
			dc.LineTo(rc.right, ptEnd.y);
			dc.LineTo(ptEnd);

			dc.SelectObject(&pnFrmLight);

			dc.MoveTo(ptStart.x, ptStart.y+1);
			dc.LineTo(rc.left+1, ptStart.y+1);
			dc.LineTo(rc.left+1, rc.bottom-1);
			dc.LineTo(rc.right-1, rc.bottom-1);
			dc.LineTo(rc.right-1, ptEnd.y+1);
			dc.LineTo(ptEnd.x, ptEnd.y+1);

		}
		else // 3D frame
		{
			VERIFY(pnFrmDark.CreatePen(PS_SOLID, 1, ::GetSysColor(COLOR_3DSHADOW)));
			VERIFY(pnFrmLight.CreatePen(PS_SOLID, 1, ::GetSysColor(COLOR_3DHILIGHT)));

			ppnOldPen = dc.SelectObject(&pnFrmDark);

			dc.MoveTo(ptStart);
			dc.LineTo(rc.left, ptStart.y);
			dc.LineTo(rc.left, rc.bottom-1);
			dc.LineTo(rc.right-1, rc.bottom-1);
			dc.LineTo(rc.right-1, ptEnd.y);
			dc.LineTo(ptEnd);

			dc.SelectObject(&pnFrmLight);

			dc.MoveTo(ptStart.x, ptStart.y+1);
			dc.LineTo(rc.left+1, ptStart.y+1);
			dc.LineTo(rc.left+1, rc.bottom-1);
			dc.MoveTo(rc.left, rc.bottom);
			dc.LineTo(rc.right, rc.bottom);
			dc.LineTo(rc.right, ptEnd.y-1);
			dc.MoveTo(rc.right-2, ptEnd.y+1);
			dc.LineTo(ptEnd.x, ptEnd.y+1);
		}

		// draw text (if any)
		if(!sText.IsEmpty() && !(dwExStyle &(BS_ICON|BS_BITMAP)))
		{
			if(!IsWindowEnabled())
			{
				ptStart.y -= iUpDist;
				dc.DrawState(ptStart, seText, sText, DSS_DISABLED, TRUE, 0, (HBRUSH)NULL);
			}
			else
			{
				dc.SetBkMode(TRANSPARENT);
				dc.DrawText(sText, CRect(ptStart, ptEnd), DT_VCENTER|DT_LEFT|DT_SINGLELINE|DT_NOCLIP);
			}
		}

		// cleanup
		dc.SelectObject(ppnOldPen);
		dc.RestoreDC(nSavedDC);
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CTGroupBox::OnPaint"));
	}
}