/*=============================================================================
   FILE			: ColorStatic.cpp
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
   NOTES		:
VERSION HISTORY	:
				
============================================================================*/

#include "pch.h"
#include "ColorStatic.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*-----------------------------------------------------------------------------
Function		: CColorStatic(Constructor)
In Parameters	:
Out Parameters	:
Purpose		:This Function initialize CColorStatic class
Author		:
-----------------------------------------------------------------------------*/

CColorStatic::CColorStatic()
{
	try
	{
		m_SetTransparent = false;
		m_clrText = RGB (0, 0, 0);
		m_clrBack = ::GetSysColor (COLOR_3DFACE);
		m_brBkgnd.CreateSolidBrush (m_clrBack);
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CColorStatic::CColorStatic"));
	}
}

/*-----------------------------------------------------------------------------
Function		: ~CColorStatic(Destructor)
In Parameters	:
Out Parameters	:
Purpose		:This Function destruct CColorStatic  class
Author		:
-----------------------------------------------------------------------------*/
CColorStatic::~CColorStatic()
{
	try
	{
		m_brBkgnd.DeleteObject();
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CColorStatic::~CColorStatic"));
	}
}


BEGIN_MESSAGE_MAP(CColorStatic, CStatic)
	//{{AFX_MSG_MAP(CColorStatic)
	ON_WM_CTLCOLOR_REFLECT()
	//}}AFX_MSG_MAP
	//ON_WM_PAINT()
END_MESSAGE_MAP()


/*-----------------------------------------------------------------------------
Function		: SetTextColor
In Parameters	: COLORREF : object of COLORREF which contains text color
Out Parameters	:
Purpose		:This fucntion set the Text color
Author		:
-----------------------------------------------------------------------------*/
void CColorStatic::SetTextColor (COLORREF clrText)
{
	try
	{
		m_clrText = clrText;
		Invalidate ();
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CColorStatic::SetTextColor"));
	}
}

/*-----------------------------------------------------------------------------
Function		: SetBkColor
In Parameters	: COLORREF : object of COLORREF which contains background color
Out Parameters	:
Purpose		:This Function set the background Color
Author		:
-----------------------------------------------------------------------------*/
void CColorStatic::SetBkColor (COLORREF clrBack)
{
	try
	{
		m_clrBack = clrBack;
		m_brBkgnd.DeleteObject ();
		m_brBkgnd.CreateSolidBrush (clrBack);
		Invalidate ();
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CColorStatic::SetBkColor"));
	}
}

/*-----------------------------------------------------------------------------
Function		: SetTransparent
In Parameters	: bool :
Out Parameters	:
Purpose		:
Author		:
-----------------------------------------------------------------------------*/
void CColorStatic::SetTransparent(bool bSetState)
{
	m_SetTransparent = bSetState;
}

/*-----------------------------------------------------------------------------
Function		: setUnderline
In Parameters	: int : Flag to indicate if text would be underlined
Out Parameters	:
Purpose		:This Fucntion set the underline property of text
Author		:
-----------------------------------------------------------------------------*/
void CColorStatic::setUnderline( int iFontUnderline)
{
	try
	{
		CFont m_font;
		// Get window font
		CFont* pFont = GetFont();

		// Create LOGFONT structure
		LOGFONT lfLogFont;

		// Get LOGFONT structure of current font
		pFont->GetLogFont(&lfLogFont);

		// Set font to be bold
		lfLogFont.lfWeight = FW_NORMAL;

		// Create normal font that is bold (when not hovered)
		m_font.CreateFontIndirect(&lfLogFont);

		// Set underline attribute
		lfLogFont.lfUnderline = TRUE;

		// Create current font with underline attribute (when hovered)
		m_font.CreateFontIndirect(&lfLogFont);

		SetFont(&m_font);
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CColorStatic::setUnderline"));
	}
}
/*-----------------------------------------------------------------------------
Function		: CColorStatic
In Parameters	: CDD* : pointer to CDC
: UINT :
Out Parameters	:
Purpose		:
Author		:
-----------------------------------------------------------------------------*/
HBRUSH CColorStatic::CtlColor(CDC* pDC, UINT nCtlColor)
{
	try
	{
		UNREFERENCED_PARAMETER(nCtlColor);
		pDC->SetTextColor (m_clrText);
		pDC->SetBkMode(m_clrBack);
		return m_brBkgnd;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CColorStatic::CtlColor"));
	}
	return m_brBkgnd;
}
