/*======================================================================================
   FILE				: StaticEx.cpp
   ABSTRACT			: This class is Inheritage version of CStatic class.
					  By using this class we draw the Html text on any static button.
   DOCUMENTS		: 
   AUTHOR			: Sandip Sanap
   COMPANY			: Aura 
   COPYRIGHT NOTICE	: (C) Aura
      				  Created as an unpublished copyright work.  All rights reserved.
     				  This document and the information it contains is confidential and
      				  proprietary to Aura.  Hence, it may not be 
      				  used, copied, reproduced, transmitted, or stored in any form or by any 
      				  means, electronic, recording, photocopying, mechanical or otherwise, 
      				  without the prior written permission of Aura
   CREATION DATE	: 03-November-2008
   NOTE				:
   VERSION HISTORY	:                     
=======================================================================================*/
#include "StdAfx.h"
#include "StaticEx.h"
#include "DrawHtml.h"
#include "MemDC.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

//Constructor
CStaticEx::CStaticEx(void)
{
	
}

//Destructor
CStaticEx::~CStaticEx(void)
{
	// Done with the font.Delete the font object.
	m_objFont.DeleteObject();
}

BEGIN_MESSAGE_MAP(CStaticEx, CStatic)
	ON_WM_DRAWITEM()
	ON_WM_PAINT()
	ON_WM_CTLCOLOR()
END_MESSAGE_MAP()

/*-------------------------------------------------------------------------------------
Function		: OnPaint
In Parameters	: -
Out Parameters	:
Purpose			: Handling of writing html text on paint of static control.
Author			: Sandip Sanap
-------------------------------------------------------------------------------------*/
void CStaticEx::OnPaint()
{
	CPaintDC dc(this); // device context for painting
	CDC *pDC = &dc;

	CString csWndTxt;
	GetWindowText(csWndTxt);

	CRect rcWnd;
	GetClientRect(&rcWnd);

	CFont *pObjFont = pDC->SelectObject(&m_objFont);

	CRect rcItem = rcWnd;
	rcItem.bottom = 0;

	int nScrollPos = GetScrollPos(SB_VERT);
	rcItem.OffsetRect(0, -nScrollPos);

	// Set transparent background
	if(m_bTransparent)
		pDC->SetBkMode(TRANSPARENT);
	else
		pDC ->FillSolidRect(&rcWnd, m_clrBack);

	pDC->SetTextColor(m_clrText);

	DrawHTML(pDC->GetSafeHdc(), csWndTxt, csWndTxt.GetLength(), &rcItem, DT_LEFT|DT_WORDBREAK);
	//Release GDI stuff
	pDC->SelectObject(pObjFont);
}

/*-------------------------------------------------------------------------------------
Function		: OnCtlColor
In Parameters	: CDC* pDC, CWnd* pWnd, UINT nCtlColor
Out Parameters	: HBRUSH
Purpose			:
Author			: Sandip Sanap
-------------------------------------------------------------------------------------*/
HBRUSH CStaticEx::OnCtlColor(CDC* pDC, CWnd* pWnd, UINT nCtlColor)
{
	HBRUSH hbr = CStatic::OnCtlColor(pDC, pWnd, nCtlColor);
	pDC->SetTextColor(m_clrText);
	pDC->SetBkMode(TRANSPARENT);
	hbr = (HBRUSH)GetStockObject(NULL_BRUSH);
	return hbr;
}

/*-----------------------------------------------------------------------------
Function		: SetBkColor
In Parameters	: COLORREF : object of COLORREF which contains background color
Out Parameters	:
Purpose		:This Function set the background Color
Author		: Sandip Sanap
-----------------------------------------------------------------------------*/
void CStaticEx::SetBkColorEx(COLORREF clrBack, bool bTransparent)
{
	m_clrBack = clrBack;
	m_bTransparent = bTransparent;
}

/*-----------------------------------------------------------------------------
Function		: SetTextColor
In Parameters	: COLORREF : object of COLORREF which contains text color
Out Parameters	:
Purpose		:This fucntion set the Text color
Author		: Sandip Sanap
-----------------------------------------------------------------------------*/
void CStaticEx::SetTextColorEx(COLORREF clrText)
{
	m_clrText = clrText;
}

/*-----------------------------------------------------------------------------
Function		: SetFontEx
In Parameters	: CString : contains name of font
: int : contains height of font
: int : contains width of font
: int : contains flag fro under line
Out Parameters	:
Purpose		:This Function draws set Text Drawing property
Author		: Sandip Sanap
-----------------------------------------------------------------------------*/
void CStaticEx::SetFontEx(const CString& csFontName, int iFontHeight, int iFontWidth,int iFontUnderline, int iFontWeight)
{
	try
	{
		LOGFONT lf;                        // Used to create the CFont.
		SecureZeroMemory(&lf, sizeof(LOGFONT));   // Clear out structure.
		lf.lfHeight = iFontHeight;
		lf.lfWidth  = iFontWidth;
		lf.lfUnderline = iFontUnderline;
		lf.lfWeight    = iFontWeight;
		_tcscpy_s(lf.lfFaceName, LF_FACESIZE, csFontName);    //    with face name "Arial".
		m_objFont.CreateFontIndirect(&lf);    // Create the font.
		SetFont(&m_objFont);
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CStaticEx::SetFontEx"));
	}
}

void CStaticEx::SetDefaultFont()
{
	SetFontEx(_T("MS Sans Dlg"), -11, 0);
	SetBkColorEx(::GetSysColor(COLOR_3DFACE), true);
	SetTextColorEx(RGB(0, 0, 0));
}