/*=============================================================================
   FILE		           : TransparentStatic.cpp
   ABSTRACT		       : Class implements transparent labels
   DOCUMENTS	       : Refer The GUI Design.doc, GUI Requirement Document.doc
   AUTHOR		       : 
   COMPANY		       : Aura 
   COPYRIGHT NOTICE    :
						(C)Aura:
      					Created as an unpublished copyright work.  All rights reserved.
     					This document and the information it contains is confidential and
      					proprietary to Aura.  Hence, it may not be 
      					used, copied, reproduced, transmitted, or stored in any form or by any 
      					means, electronic, recording, photocopying, mechanical or otherwise, 
      					without the prior written permission of Aura
   CREATION DATE      : 2/24/06
   NOTES		      : Implementation file for Class To Make The Label Transprent.
   VERSION HISTORY    : 
				
=============================================================================*/
#include "pch.h"
#include "TransparentStatic.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

IMPLEMENT_DYNAMIC(CTransparentStatic, CStatic)

/*-------------------------------------------------------------------------------------
Function		: CTransparentStatic
In Parameters	: -
Out Parameters	: -
Purpose			: Constructor for the class CTransparentStatic
Author			:
--------------------------------------------------------------------------------------*/
CTransparentStatic::CTransparentStatic()
{
}

/*-------------------------------------------------------------------------------------
Function		: ~CTransparentStatic
In Parameters	: -
Out Parameters	: -
Purpose			: Destructor for the class CTransparentStatic
Author			:
--------------------------------------------------------------------------------------*/
CTransparentStatic::~CTransparentStatic()
{
}

BEGIN_MESSAGE_MAP(CTransparentStatic, CStatic)
	ON_WM_PAINT()
END_MESSAGE_MAP()

/*-------------------------------------------------------------------------------------
Function		: OnPaint
In Parameters	: void
Out Parameters	: void
Purpose			: Handles the paint event
Author			:
--------------------------------------------------------------------------------------*/
void CTransparentStatic::OnPaint(void)
{
	CPaintDC	 dc(this); // device context for painting

	CRect		 client_rect;
	GetClientRect(client_rect);

	CString		 szText;
	GetWindowText(szText);

	// Get the font
	CFont	*pFont, *pOldFont;
	pFont = GetFont();
	pOldFont = dc.SelectObject(pFont);

	// Map "Static Styles" to "Text Styles"
#define MAP_STYLE(src, dest)if(dwStyle & (src))dwText |= (dest)
#define NMAP_STYLE(src, dest)if(!(dwStyle & (src)))dwText |= (dest)

	DWORD	dwStyle = GetStyle(), dwText = 0;

	MAP_STYLE(	SS_RIGHT,			DT_RIGHT					);
	MAP_STYLE(	SS_CENTER,			DT_CENTER					);
	MAP_STYLE(	SS_CENTERIMAGE,		DT_VCENTER | DT_SINGLELINE	);
	MAP_STYLE(	SS_NOPREFIX,		DT_NOPREFIX					);
	MAP_STYLE(	SS_WORDELLIPSIS,	DT_WORD_ELLIPSIS			);
	MAP_STYLE(	SS_ENDELLIPSIS,		DT_END_ELLIPSIS				);
	MAP_STYLE(	SS_PATHELLIPSIS,	DT_PATH_ELLIPSIS			);

	NMAP_STYLE(	SS_LEFTNOWORDWRAP |
		SS_CENTERIMAGE |
		SS_WORDELLIPSIS |
		SS_ENDELLIPSIS |
		SS_PATHELLIPSIS,	DT_WORDBREAK				);

	// Set transparent background
	dc.SetBkMode(TRANSPARENT);

	// Draw the text
	dc.DrawText(szText, client_rect, dwText);

	// Select old font
	dc.SelectObject(pOldFont);
}
