/*=============================================================================
   FILE			: CBitmapButtonXP.cpp
   ABSTRACT		: 
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
NOTES		    : Custom Bitmap Creation
VERSION HISTORY	:
				
============================================================================*/
#include "pch.h"
#include "BitmapButtonXP.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif


/*-----------------------------------------------------------------------------
Function		: CBitmapButtonXP(Constructor)
In Parameters	:
Out Parameters	:
Purpose		:This Function initialize CBitmapButtonXP class
Author		:
-----------------------------------------------------------------------------*/
CBitmapButtonXP::CBitmapButtonXP()
{
	try
	{
		m_bOverControl      = FALSE;                // Cursor not yet over control
		m_nTimerID = 1002;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CBitmapButtonXP::CBitmapButtonXP"));
	}
}

/*-----------------------------------------------------------------------------
Function		: ~CBitmapButtonXP (Destructor)
In Parameters	:
Out Parameters	:
Purpose		:This Function destruct the CBitmapButtonXP class
Author		:
-----------------------------------------------------------------------------*/
CBitmapButtonXP::~CBitmapButtonXP()
{
}


BEGIN_MESSAGE_MAP(CBitmapButtonXP, CButton)
	ON_WM_MOUSEMOVE()
	ON_WM_TIMER()
	ON_WM_LBUTTONDOWN()
	ON_WM_LBUTTONUP()
END_MESSAGE_MAP()

/*-----------------------------------------------------------------------------
Function		: OnMouseMove
In Parameters	: UINT : Indicates whether various virtual keys are down.
: CPoint :Specifies the x- and y-coordinate of the cursor.
Out Parameters	:
Purpose		:The framework calls this member function when the mouse cursor moves.
Author		:
-----------------------------------------------------------------------------*/
void CBitmapButtonXP::OnMouseMove(UINT nFlags, CPoint point)
{
	try
	{
		if(!m_bOverControl)      // Cursor has just moved over control
		{
			m_bOverControl = TRUE;
			SetTimer(m_nTimerID, 100, NULL);
			Invalidate();
		}
		CButton::OnMouseMove(nFlags, point);
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CBitmapButtonXP::OnMouseMove"));
	}
}

/*-----------------------------------------------------------------------------
Function		: OnTimer
In Parameters	: UINT_PTR : Specifies the identifier of the timer.
Out Parameters	:
Purpose		:The framework calls this member function after each interval
specified in the SetTimer member function used to install a timer.
Author		:
-----------------------------------------------------------------------------*/
void CBitmapButtonXP::OnTimer(UINT_PTR nIDEvent)
{
	try
	{
		CPoint p(GetMessagePos());
		ScreenToClient(&p);

		CRect rect;
		GetClientRect(rect);
		if(!rect.PtInRect(p))
		{
			m_bOverControl = FALSE;
			KillTimer(m_nTimerID);
			Invalidate();
		}
		CButton::OnTimer(nIDEvent);
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CBitmapButtonXP::OnTimer"));
	}
}

/*-----------------------------------------------------------------------------
Function		: DestroyWindow
In Parameters	:
:
Out Parameters	:
Purpose		:Destroys the Windows window attached to the CButton object.

Author		:
-----------------------------------------------------------------------------*/
BOOL CBitmapButtonXP::DestroyWindow()
{
	try
	{
		KillTimer(m_nTimerID);
		return CButton::DestroyWindow();
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CBitmapButtonXP::DestroyWindow"));
	}
	return FALSE;
}

/*-----------------------------------------------------------------------------
Function		: PreSubclassWindow
In Parameters	:
Out Parameters	:
Purpose		:This member function is called by the framework to allow other
necessary subclassing to occur before the window is subclassed.
Author		:
-----------------------------------------------------------------------------*/
void CBitmapButtonXP::PreSubclassWindow()
{
	try
	{
		CButton::PreSubclassWindow();
		ModifyStyle(0, BS_OWNERDRAW);
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CBitmapButtonXP::PreSubclassWindow"));
	}
}

/*-----------------------------------------------------------------------------
Function		: DrawItem
In Parameters	: LPDRAWITEMSTRUCT : A long pointer to a DRAWITEMSTRUCT structure.
The structure contains information about the item to
be drawn and the type of drawing required.
Out Parameters	:
Purpose		:Called by the framework when a visual aspect of an
owner-drawn button has changed.
Author		:
-----------------------------------------------------------------------------*/
void CBitmapButtonXP::DrawItem(LPDRAWITEMSTRUCT lpDrawItemStruct)
{
	try
	{
		ASSERT (lpDrawItemStruct);
		if(m_bOverControl == FALSE)
			CBitmapButton::DrawItem(lpDrawItemStruct);
		else
		{
			if(m_bOver.m_hObject != NULL)
			{
				CDC *pDC = CDC::FromHandle(lpDrawItemStruct->hDC);	// get device context
				RECT r=lpDrawItemStruct->rcItem;					// context rectangle
				pDC->SetBkMode(TRANSPARENT);
				DrawBitmap(pDC, (HBITMAP)m_bOver, r);
			}
			else
			{
				CBitmapButton::DrawItem(lpDrawItemStruct);
			}
		}
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CBitmapButtonXP::DrawItem"));
	}
}

/*-----------------------------------------------------------------------------
Function		: DrawBitmap
In Parameters	: CDC* :
: HBITMAP :
: RECT :
Out Parameters	:
Purpose		:This Function draw Bitmap
Author		:
-----------------------------------------------------------------------------*/
void CBitmapButtonXP::DrawBitmap(CDC* dc, HBITMAP hbmp, RECT r)
{
	try
	{
		if(!hbmp)return;	//safe check
		int cx=r.right  - r.left;
		int cy=r.bottom - r.top;

		CDC dcBmp;
		dcBmp.CreateCompatibleDC(dc);
		dcBmp.SelectObject(hbmp);
		dc->BitBlt(r.left,r.top,cx,cy,&dcBmp,0,0,SRCCOPY);
		DeleteDC(dcBmp);
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CBitmapButtonXP::DrawBitmap"));
	}
}

/*-----------------------------------------------------------------------------
Function		: SetMouseOverBitmap
In Parameters	: CString :
Out Parameters	:
Purpose		:This Function set mouse over bitmap
Author		:
-----------------------------------------------------------------------------*/
void CBitmapButtonXP::SetMouseOverBitmap(CString sMouseOverID)
{
	try
	{
		m_bOver.DeleteObject();
		m_bOver.LoadBitmap(sMouseOverID);

	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CBitmapButtonXP::SetMouseOverBitmap"));
	}
}

/*-----------------------------------------------------------------------------
Function		: OnLButtonDown
In Parameters	: UINT : Indicates whether various virtual keys are down.
: CPoint :Specifies the x- and y-coordinate of the cursor.
Out Parameters	:
Purpose		:This Funcion is called when when the user presses the left mouse button
Author		:
-----------------------------------------------------------------------------*/
void CBitmapButtonXP::OnLButtonDown(UINT nFlags, CPoint point)
{
	try
	{
		m_bOverControl = FALSE;
		CButton::OnLButtonDown(nFlags, point);
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CBitmapButtonXP::OnLButtonDown"));
	}
}

/*-----------------------------------------------------------------------------
Function		: OnLButtonUp
In Parameters	: UINT : Indicates whether various virtual keys are down.
: CPoint :Specifies the x- and y-coordinate of the cursor.
Out Parameters	:
Purpose		:This Funcion is called when when the user releases the left mouse button
Author		:
-----------------------------------------------------------------------------*/
void CBitmapButtonXP::OnLButtonUp(UINT nFlags, CPoint point)
{
	try
	{
		m_bOverControl = FALSE;
		CButton::OnLButtonUp(nFlags, point);
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CBitmapButtonXP::OnLButtonUp"));
	}
}

BOOL CBitmapButtonXP::LoadBitmapImage(HMODULE hinstDLL, UINT iBitmap,UINT iBitmapSel,UINT iBitmapFocus,UINT iBitmapDisabled)
{
	HANDLE hBmp = LoadBitmap(hinstDLL, MAKEINTRESOURCE(iBitmap)); 
	if (hBmp == NULL)
	{
		return FALSE;
	}

	m_bitmap.Detach();
	m_bitmap.Attach(hBmp);

	BOOL AllLoaded = TRUE;
	if (iBitmapSel != 0)
	{
		hBmp = LoadBitmap(hinstDLL, MAKEINTRESOURCE(iBitmapSel)); 
		if (hBmp != NULL)
		{
			m_bitmapSel.Detach();
			m_bitmapSel.Attach(hBmp);
		}
		else
		{
			AllLoaded = FALSE;
		}
	}
	if (iBitmapDisabled != 0)
	{
		hBmp = LoadBitmap(hinstDLL, MAKEINTRESOURCE(iBitmapDisabled)); 
		if (hBmp != NULL)
		{
			m_bitmapDisabled.Detach();
			m_bitmapDisabled.Attach(hBmp);
		}
		else
		{
			AllLoaded = FALSE;
		}
	}
	if (iBitmapFocus != 0)
	{
		hBmp = LoadBitmap(hinstDLL, MAKEINTRESOURCE(iBitmapFocus)); 
		if (hBmp != NULL)
		{
			m_bitmapFocus.Detach();
			m_bitmapFocus.Attach(hBmp);
		}
		else
		{
			AllLoaded = FALSE;
		}
	}
	return AllLoaded;
}