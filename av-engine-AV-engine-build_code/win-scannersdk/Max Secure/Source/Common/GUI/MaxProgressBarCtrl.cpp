/*=============================================================================
   FILE		           : MaxProgressBarCtrl.cpp
   ABSTRACT		       : This control is Inherited From CProgressCtrl to change its look from 
						 Normal to 3D.
   DOCUMENTS	       : Refer The GUI Design.doc, GUI Requirement Document.doc
   AUTHOR		       : Ramkrushna Shelke 
   COMPANY		       : Aura 
   COPYRIGHT NOTICE    :
						(C)Aura:
      					Created as an unpublished copyright work.  All rights reserved.
     					This document and the information it contains is confidential and
      					proprietary to Aura.  Hence, it may not be 
      					used, copied, reproduced, transmitted, or stored in any form or by any 
      					means, electronic, recording, photocopying, mechanical or otherwise, 
      					without the prior written permission of Aura
   CREATION DATE      : 19/10/2011
   NOTES		      : header file for class inplementing header control
   VERSION HISTORY    : 
				
=============================================================================*/
#include "stdafx.h"
#include "MaxProgressBarCtrl.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

#define	IDT_INDETERMINATE		100
#define	IND_BAND_WIDTH			20

// Funtion prototypes.
COLORREF LightenColor(const COLORREF crColor, BYTE byIncreaseVal);
COLORREF DarkenColor(const COLORREF crColor, BYTE byReduceVal);

/*-----------------------------------------------------------------------------
Function		: LightenColor
In Parameters	: const COLORREF crColor, BYTE byIncreaseVal
Out Parameters	: COLORREF
Purpose			: Lightens a color by increasing the RGB values by the given number.
Author			: Ramkrushna Shelke
-----------------------------------------------------------------------------*/
COLORREF LightenColor(const COLORREF crColor, BYTE byIncreaseVal)
{
	BYTE byRed = GetRValue(crColor);
	BYTE byGreen = GetGValue(crColor);
	BYTE byBlue = GetBValue(crColor);

	if ((byRed + byIncreaseVal) <= 255)
		byRed = BYTE(byRed + byIncreaseVal);
	if ((byGreen + byIncreaseVal)	<= 255)
		byGreen = BYTE(byGreen + byIncreaseVal);
	if ((byBlue + byIncreaseVal) <= 255)
		byBlue = BYTE(byBlue + byIncreaseVal);

	return RGB(byRed, byGreen, byBlue);
}

/*-----------------------------------------------------------------------------
Function		: CHyperLink (Connstructor)
In Parameters	: const COLORREF crColor, BYTE byIncreaseVal
Out Parameters	: COLORREF
Purpose			: Darkens a color by reducing the RGB values by the given number.
Author			: Ramkrushna Shelke
-----------------------------------------------------------------------------*/
COLORREF DarkenColor(const COLORREF crColor, BYTE byReduceVal)
{
	BYTE byRed = GetRValue(crColor);
	BYTE byGreen = GetGValue(crColor);
	BYTE byBlue = GetBValue(crColor);

	if (byRed >= byReduceVal)
		byRed = BYTE(byRed - byReduceVal);
	if (byGreen >= byReduceVal)
		byGreen = BYTE(byGreen - byReduceVal);
	if (byBlue >= byReduceVal)
		byBlue = BYTE(byBlue - byReduceVal);

	return RGB(byRed, byGreen, byBlue);
}

/*-----------------------------------------------------------------------------
Function		: CMaxProgressBarCtrl
In Parameters	: void
Out Parameters	: int
Purpose			: Standard constructor
Author			: Ramkrushna Shelke
-----------------------------------------------------------------------------*/
CMaxProgressBarCtrl::CMaxProgressBarCtrl()
{
	m_bIndeterminate = FALSE;
	m_nIndOffset = 0;
	m_crColorTop = ::GetSysColor(COLOR_HIGHLIGHT);
	m_crColorBottom = ::GetSysColor(COLOR_HIGHLIGHT);
	GetColors();
	CreatePens();
}

/*-----------------------------------------------------------------------------
Function		: ~CMaxProgressBarCtrl
In Parameters	: void
Out Parameters	: int
Purpose			: Standard Destructor
Author			: Ramkrushna Shelke
-----------------------------------------------------------------------------*/
CMaxProgressBarCtrl::~CMaxProgressBarCtrl()
{
	DeletePens();
}

BEGIN_MESSAGE_MAP(CMaxProgressBarCtrl, CProgressCtrl)
	//{{AFX_MSG_MAP(CMaxProgressBarCtrl)
	ON_WM_PAINT()
	ON_WM_TIMER()
	ON_WM_ERASEBKGND()
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()

/*-----------------------------------------------------------------------------
Function		: OnPaint
In Parameters	: void
Out Parameters	: void
Purpose			: The framework calls this member function when Windows or an
				  application makes a request to repaint a portion of an application's 
				  window.
Author			: Ramkrushna Shelke
-----------------------------------------------------------------------------*/
void CMaxProgressBarCtrl::OnPaint() 
{
	CPaintDC dcPaint(this); // device context for painting
	CRect rect, rectClient;
	GetClientRect(rectClient);
	rect = rectClient;
	BOOL bVertical = GetStyle() & PBS_VERTICAL;

	// Create a memory DC for drawing.
	CDC dc;
	dc.CreateCompatibleDC(&dcPaint);
 	int nSavedDC = dc.SaveDC();
	CBitmap bmp;
	bmp.CreateCompatibleBitmap(&dcPaint, rect.Width(), rect.Height());
	CBitmap *pOldBmp = dc.SelectObject(&bmp);
	
	CBrush br1(m_crColorLightest);
	CBrush br2(m_bkColor1);
	CBrush br3(m_crColorBottom);
	dc.FillRect(rect, &br2);

	int nLower, nUpper;
	GetRange(nLower, nUpper);

	// Determine the size of the bar and draw it.
	if (bVertical)
	{
		if (!m_bIndeterminate)
			rect.top = rect.bottom - int(((float)rect.Height() * float(GetPos() - nLower)) / float(nUpper - nLower));
		dc.FillRect(rect, &br1);
		DrawVerticalBar(&dc, rect);
	}
	else
  	{
		if (!m_bIndeterminate)
			rect.right = int(((float)rect.Width() * float(GetPos() - nLower)) / float(nUpper - nLower));

		CBrush br3(m_crColorTop);
		CBrush br4(m_crColorBottom);

		CRect oRcTemp;
		oRcTemp = rect;
		oRcTemp.bottom = oRcTemp.bottom / 2;
		dc.FillRect(oRcTemp, &br3);

		oRcTemp.top = oRcTemp.bottom / 2;
		oRcTemp.top = rect.bottom;

		dc.FillRect(oRcTemp, &br4);


		//DrawHorizontalBar(&dc, rect);
	}

	dcPaint.BitBlt(rectClient.left, rectClient.top, rectClient.Width(), rectClient.Height(), 
						&dc, rectClient.left, rectClient.top, SRCCOPY);

	dc.SelectObject(pOldBmp);
	dc.RestoreDC(nSavedDC);
	dc.DeleteDC();
}

/*-----------------------------------------------------------------------------
Function		: DrawHorizontalBar
In Parameters	: CDC *pDC, const CRect rect
Out Parameters	: void
Purpose			: Draws a horizontal progress bar.
Author			: Ramkrushna Shelke
-----------------------------------------------------------------------------*/
void CMaxProgressBarCtrl::DrawHorizontalBar(CDC *pDC, const CRect rect)
{
	if (!rect.Width())
		return;

	int nLeft = rect.left;
	int nTop = rect.top;
	int nBottom = rect.bottom;

	// Assume we're not drawing the indeterminate state.
	CPen *pOldPen = pDC->SelectObject(&m_penColorLight);

	if (m_bIndeterminate)
	{
		pOldPen = pDC->SelectObject(&m_penColor);
		int nNumBands = (rect.Width() / IND_BAND_WIDTH) + 2;
		int nHeight = rect.Height() + 1;

		int nAdjust = nLeft - IND_BAND_WIDTH + m_nIndOffset;
		int nXpos = 0;
		int nYpos1 = nTop + 1;
		int nYpos2 = nBottom - 2;

		for (int i = 0; i < nNumBands; i++)
		{
			nXpos = nAdjust + (i * IND_BAND_WIDTH);

			pDC->SelectObject(&m_penColorDarker);
			pDC->MoveTo(nXpos + 1, nTop);
			pDC->LineTo(nXpos + nHeight, nBottom);

			pDC->SelectObject(&m_penColorDark);
			pDC->MoveTo(nXpos + 2, nTop);
			pDC->LineTo(nXpos + nHeight + 1, nBottom);
			pDC->MoveTo(nXpos + 10, nTop);
			pDC->LineTo(nXpos + nHeight + 9, nBottom);

			pDC->SelectObject(&m_penColor);
			pDC->MoveTo(nXpos + 3, nTop);
			pDC->LineTo(nXpos + nHeight + 2, nBottom);
			pDC->MoveTo(nXpos + 9, nTop);
			pDC->LineTo(nXpos + nHeight + 8, nBottom);

			pDC->SelectObject(&m_penColorLight);
			pDC->MoveTo(nXpos + 4, nTop);
			pDC->LineTo(nXpos + nHeight + 3, nBottom);
			pDC->MoveTo(nXpos + 8, nTop);
			pDC->LineTo(nXpos + nHeight + 7, nBottom);

			pDC->SelectObject(&m_penColorLighter);
			pDC->MoveTo(nXpos + 5, nTop);
			pDC->LineTo(nXpos + nHeight + 4, nBottom);
			pDC->MoveTo(nXpos + 7, nTop);
			pDC->LineTo(nXpos + nHeight + 6, nBottom);
		}	// for the number of bands
	}	// if indeterminate
	else
	{
		int nRight = rect.right;
	
		pDC->MoveTo(nLeft + 2, nBottom - 4);
		pDC->LineTo(nRight - 2, nBottom - 4);
		pDC->MoveTo(nLeft + 2, nTop + 2);
		pDC->LineTo(nRight - 2, nTop + 2);
		pDC->SetPixel(nLeft + 1, nBottom - 3, m_crColorLight);
		pDC->SetPixel(nLeft + 1, nTop + 1, m_crColorLight);

		pDC->SelectObject(&m_penColorLighter);
		pDC->MoveTo(nLeft + 2, nBottom - 5);
		pDC->LineTo(nRight - 3, nBottom - 5);
		pDC->LineTo(nRight - 3, nTop + 3);
		pDC->LineTo(nLeft + 1, nTop + 3);
		pDC->SetPixel(nLeft + 1, nBottom - 4, m_crColorLighter);
		pDC->SetPixel(nLeft + 1, nTop + 2, m_crColorLighter);

		pDC->SelectObject(&m_penColor);
		pDC->MoveTo(nLeft, nBottom - 1);
		pDC->LineTo(nLeft, nTop);
		pDC->LineTo(nLeft + 2, nTop);
		pDC->SetPixel(nLeft + 1, nBottom - 2, m_crColorTop);
		pDC->MoveTo(nLeft + 2, nBottom - 3);
		pDC->LineTo(nRight - 2, nBottom - 3);
		pDC->MoveTo(nLeft + 2, nTop + 1);
		pDC->LineTo(nRight - 1, nTop + 1);
		
		pDC->SelectObject(&m_penColorDark);
		pDC->MoveTo(nLeft + 2, nBottom - 2);
		pDC->LineTo(nRight - 2, nBottom - 2);
		pDC->LineTo(nRight - 2, nTop + 1);
		pDC->MoveTo(nLeft + 2, nTop);
		pDC->LineTo(nRight, nTop);
		pDC->SetPixel(nLeft + 1, nBottom - 1, m_crColorDark);

		pDC->SelectObject(&m_penColorDarker);
		pDC->MoveTo(nLeft + 2, nBottom - 1);
		pDC->LineTo(nRight - 1, nBottom - 1);
		pDC->LineTo(nRight - 1, nTop);

		pDC->SelectObject(&m_penShadow);
		pDC->MoveTo(nRight, nTop);
 		pDC->LineTo(nRight, nBottom);

		pDC->SelectObject(&m_penLiteShadow);
 		pDC->MoveTo(nRight + 1, nTop);
		pDC->LineTo(nRight + 1, nBottom);
	}	// if not indeterminate

	pDC->SelectObject(pOldPen);
}

/*-----------------------------------------------------------------------------
Function		: DrawVerticalBar
In Parameters	: CDC *pDC, const CRect rect
Out Parameters	: void
Purpose			: Draws a Vertical progress bar.
Author			: Ramkrushna Shelke
-----------------------------------------------------------------------------*/
void CMaxProgressBarCtrl::DrawVerticalBar(CDC *pDC, const CRect rect)
{
	int nHeight = rect.Height();
	if (!nHeight)
		return;

	int nLeft = rect.left;
	int nTop = rect.top;
	int nRight = rect.right;
	int nBottom = rect.bottom;

	CPen *pOldPen = pDC->SelectObject(&m_penColor);

	if (m_bIndeterminate)
	{
		int nNumBands = (nHeight / IND_BAND_WIDTH) + 2;
		int nHeight = rect.Width() + 1;

		int nAdjust = nBottom - m_nIndOffset;
		int nXpos1 = nLeft;
		int nXpos2 = nRight + 1;
		int nYpos = nTop + 1;

		for (int i = 0; i < nNumBands; i++)
		{
			nYpos = nAdjust - (i * IND_BAND_WIDTH);

			pDC->SelectObject(&m_penColorDarker);
			pDC->MoveTo(nXpos1, nYpos);
			pDC->LineTo(nXpos2, nYpos + nHeight);

			pDC->SelectObject(&m_penColorDark);
			pDC->MoveTo(nXpos1, nYpos + 1);
			pDC->LineTo(nXpos2, nYpos + nHeight + 1);
			pDC->MoveTo(nXpos1, nYpos + 9);
			pDC->LineTo(nXpos2, nYpos + nHeight + 9);

			pDC->SelectObject(&m_penColor);
			pDC->MoveTo(nXpos1, nYpos + 2);
			pDC->LineTo(nXpos2, nYpos + nHeight + 2);
			pDC->MoveTo(nXpos1, nYpos + 8);
			pDC->LineTo(nXpos2, nYpos + nHeight + 8);

			pDC->SelectObject(&m_penColorLight);
			pDC->MoveTo(nXpos1, nYpos + 3);
			pDC->LineTo(nXpos2, nYpos + nHeight + 3);
			pDC->MoveTo(nXpos1, nYpos + 7);
			pDC->LineTo(nXpos2, nYpos + nHeight + 7);

			pDC->SelectObject(&m_penColorLighter);
			pDC->MoveTo(nXpos1, nYpos + 4);
			pDC->LineTo(nXpos2, nYpos + nHeight + 4);
			pDC->MoveTo(nXpos1, nYpos + 6);
			pDC->LineTo(nXpos2, nYpos + nHeight + 6);
		}	// for the number of bands
	}	// if indeterminate
	else
	{
		if (nHeight > 3)
		{
			pDC->MoveTo(nLeft, nTop + 1);
			pDC->LineTo(nLeft, nTop);
			pDC->LineTo(nRight, nTop);
			pDC->MoveTo(nLeft + 1, nBottom - 2);
			pDC->LineTo(nLeft + 1, nTop + 1);
			pDC->MoveTo(nRight - 3, nBottom - 3);
			pDC->LineTo(nRight - 3, nTop + 1);
			pDC->SetPixel(nRight - 2, nTop + 1, m_crColorTop);

			pDC->SelectObject(&m_penColorLight);
			pDC->MoveTo(nLeft + 2, nBottom - 3);
			pDC->LineTo(nLeft + 2, nTop + 1);
			pDC->MoveTo(nRight - 4, nBottom - 3);
			pDC->LineTo(nRight - 4, nTop + 1);
			pDC->SetPixel(nLeft + 1, nTop + 1, m_crColorLight);
			pDC->SetPixel(nRight - 3, nTop + 1, m_crColorLight);
			
			pDC->SelectObject(&m_penColorLighter);
			pDC->MoveTo(nLeft + 3, nBottom - 3);
			pDC->LineTo(nLeft + 3, nTop + 1);
			pDC->MoveTo(nRight - 5, nBottom - 3);
			pDC->LineTo(nRight - 5, nTop + 1);
			pDC->SetPixel(nLeft + 2, nTop + 1, m_crColorLighter);
			pDC->SetPixel(nRight - 4, nTop + 1, m_crColorLighter);

			pDC->SelectObject(&m_penColorDark);
			pDC->MoveTo(nLeft, nBottom - 1);
			pDC->LineTo(nLeft, nTop + 1);
			pDC->MoveTo(nLeft + 2, nBottom - 2);
			pDC->LineTo(nRight - 2, nBottom - 2);
			pDC->LineTo(nRight - 2, nTop + 1);
			pDC->SetPixel(nRight - 1, nTop + 1, m_crColorDark);

			pDC->SelectObject(&m_penColorDarker);
			pDC->MoveTo(nLeft + 1, nBottom - 1);
			pDC->LineTo(nRight - 1, nBottom - 1);
			pDC->LineTo(nRight - 1, nTop + 1);
		}
		else
		{
			CBrush br(m_crColorTop);
			CBrush *pOldBrush = pDC->SelectObject(&br);
			pDC->SelectObject(&m_penColorDark);
			pDC->Rectangle(rect);
			pDC->SelectObject(pOldBrush);
		}
	}	// if not indeterminate

	pDC->SelectObject(pOldPen);
}

/*-----------------------------------------------------------------------------
Function		: OnEraseBkgnd
In Parameters	: CDC *pDC
Out Parameters	: BOOL
Purpose			: The framework calls this member function when the 
			   	  CWnd object background needs erasing (for example, 
				  when resized). It is called to prepare an invalidated 
				  region for painting.
Author			: Ramkrushna Shelke
-----------------------------------------------------------------------------*/
BOOL CMaxProgressBarCtrl::OnEraseBkgnd(CDC* pDC) 
{
		return TRUE;
}

/*-----------------------------------------------------------------------------
Function		: GetColors
In Parameters	: void 
Out Parameters	: void
Purpose			: Calculates the lighter and darker colors, as well as the shadow colors.
Author			: Ramkrushna Shelke
-----------------------------------------------------------------------------*/
void CMaxProgressBarCtrl::GetColors()
{
	m_crColorLight = LightenColor(m_crColorTop, 51);
	m_crColorLighter = LightenColor(m_crColorLight, 51);
	m_crColorLightest = LightenColor(m_crColorLighter, 51);
	m_crColorDark = DarkenColor(m_crColorTop, 51);
	m_crColorDarker = DarkenColor(m_crColorDark, 51);
	m_crDkShadow = ::GetSysColor(COLOR_3DDKSHADOW);
	m_crLiteShadow = ::GetSysColor(COLOR_3DSHADOW);

	// Get a color halfway between COLOR_3DDKSHADOW and COLOR_3DSHADOW
	BYTE byRed3DDkShadow = GetRValue(m_crDkShadow);
	BYTE byRed3DLiteShadow = GetRValue(m_crLiteShadow);
	BYTE byGreen3DDkShadow = GetGValue(m_crDkShadow);
	BYTE byGreen3DLiteShadow = GetGValue(m_crLiteShadow);
	BYTE byBlue3DDkShadow = GetBValue(m_crDkShadow);
	BYTE byBlue3DLiteShadow = GetBValue(m_crLiteShadow);

	m_crShadow = RGB(byRed3DLiteShadow + ((byRed3DDkShadow - byRed3DLiteShadow) >> 1),
						  byGreen3DLiteShadow + ((byGreen3DDkShadow - byGreen3DLiteShadow) >> 1),
						  byBlue3DLiteShadow + ((byBlue3DDkShadow - byBlue3DLiteShadow) >> 1));
}

/*-----------------------------------------------------------------------------
Function		: SetColor
In Parameters	: COLORREF crColor
Out Parameters	: void
Purpose			: Sets the progress	bar control's color. The lighter darker colors are recalculated, 
				  and the pens recreated.
Author			: Ramkrushna Shelke
-----------------------------------------------------------------------------*/
void CMaxProgressBarCtrl::SetColor(COLORREF crColorTop, COLORREF crColorBottom)
{
	m_crColorTop = crColorTop;
	m_crColorBottom = crColorBottom;
	GetColors();
	CreatePens();
	RedrawWindow();
}

/*-----------------------------------------------------------------------------
Function		: GetColor
In Parameters	: void
Out Parameters	: COLORREF
Purpose			: Returns the progress bar control's current color.
Author			: Ramkrushna Shelke
-----------------------------------------------------------------------------*/
COLORREF CMaxProgressBarCtrl::GetColor()
{
	return m_crColorTop;
}

/*-----------------------------------------------------------------------------
Function		: CreatePens
In Parameters	: void
Out Parameters	: void
Purpose			: Deletes the pen objects, if necessary, and creates them.
Author			: Ramkrushna Shelke
-----------------------------------------------------------------------------*/
void CMaxProgressBarCtrl::CreatePens()
{
	DeletePens();
	m_penColorLight.CreatePen(PS_SOLID, 1, m_crColorLight);
	m_penColorLighter.CreatePen(PS_SOLID, 1, m_crColorLighter);
	m_penColor.CreatePen(PS_SOLID, 1, m_crColorTop);
	m_penColorDark.CreatePen(PS_SOLID, 1, m_crColorDark);
	m_penColorDarker.CreatePen(PS_SOLID, 1, m_crColorDarker);
	m_penDkShadow.CreatePen(PS_SOLID, 1, m_crDkShadow);
	m_penShadow.CreatePen(PS_SOLID, 1, m_crShadow);
	m_penLiteShadow.CreatePen(PS_SOLID, 1, m_crLiteShadow);
}

/*-----------------------------------------------------------------------------
Function		: DeletePens
In Parameters	: void
Out Parameters	: void
Purpose			: Deletes the pen objects.
Author			: Ramkrushna Shelke
-----------------------------------------------------------------------------*/
void CMaxProgressBarCtrl::DeletePens()
{
	if (m_penColorLight.m_hObject)
		m_penColorLight.DeleteObject();
	if (m_penColorLighter.m_hObject)
		m_penColorLighter.DeleteObject();
	if (m_penColor.m_hObject)
		m_penColor.DeleteObject();
	if (m_penColorDark.m_hObject)
		m_penColorDark.DeleteObject();
	if (m_penColorDarker.m_hObject)
		m_penColorDarker.DeleteObject();
	if (m_penDkShadow.m_hObject)
		m_penDkShadow.DeleteObject();
	if (m_penShadow.m_hObject)
		m_penShadow.DeleteObject();
	if (m_penLiteShadow.m_hObject)
		m_penLiteShadow.DeleteObject();
}

/*-----------------------------------------------------------------------------
Function		: SetIndeterminate
In Parameters	: BOOL bIndeterminate
Out Parameters	: void
Purpose			: Sets the indeterminate flag.
Author			: Ramkrushna Shelke
-----------------------------------------------------------------------------*/
void CMaxProgressBarCtrl::SetIndeterminate(BOOL bIndeterminate)
{
	m_bIndeterminate = bIndeterminate;

	if (m_bIndeterminate)
	{
		CRect rect;
		GetClientRect(rect);
		m_nIndOffset = 0;

		RedrawWindow();
		SetTimer(IDT_INDETERMINATE, 25, NULL);
	}
	else
	{
		KillTimer(IDT_INDETERMINATE);
		RedrawWindow();
	}
}

/*-----------------------------------------------------------------------------
Function		: GetIndeterminate
In Parameters	: void
Out Parameters	: BOOL
Purpose			: Returns m_bIndeterminate.
Author			: Ramkrushna Shelke
-----------------------------------------------------------------------------*/
BOOL CMaxProgressBarCtrl::GetIndeterminate()
{
	return m_bIndeterminate;
}

/*-----------------------------------------------------------------------------
Function		: OnTimer
In Parameters	: UINT nIDEvent
Out Parameters	: void
Purpose			: The framework calls this member function after each 
				  interval specified in the SetTimer member function used 
				  to install a timer.
Author			: Ramkrushna Shelke
-----------------------------------------------------------------------------*/
void CMaxProgressBarCtrl::OnTimer(UINT_PTR nIDEvent) 
{
	// Increment the indeterminate bar offset and redraw the window.
	if (nIDEvent == IDT_INDETERMINATE)
	{
		KillTimer(nIDEvent);

		if (++m_nIndOffset > IND_BAND_WIDTH - 1)
			m_nIndOffset = 0;
		RedrawWindow();

		SetTimer(IDT_INDETERMINATE, 25, NULL);
	}
}	// OnTimer

void CMaxProgressBarCtrl::SetBkColor(COLORREF cleNew)
{
	m_bkColor1 = cleNew;
}

