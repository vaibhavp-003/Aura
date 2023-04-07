/*======================================================================================
   FILE				: ColorEdit.cpp
   ABSTRACT			: This class is used to change the color and background property of edit control
   DOCUMENTS		: 
   AUTHOR			: 
   COMPANY			: Aura 
   COPYRIGHT NOTICE	: (C) Aura
      				  Created as an unpublished copyright work.  All rights reserved.
     				  This document and the information it contains is confidential and
      				  proprietary to Aura.  Hence, it may not be 
      				  used, copied, reproduced, transmitted, or stored in any form or by any 
      				  means, electronic, recording, photocopying, mechanical or otherwise, 
      				  without the prior written permission of Aura
   CREATION DATE	: 22/02/2007
   NOTE				:
   VERSION HISTORY	: 1/03/2008 : Avinash Bhardwaj : Ported to VS2005 with Unicode and X64 bit Compatability,string resources taken from ini.
				
=======================================================================================*/


#include "stdafx.h"
#include "ColorEdit.h"


#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

CColorEdit::CColorEdit()
{
	m_crBkColor = ::GetSysColor(COLOR_3DFACE); // Initializing background color to the system face color.
	m_crTextColor =RGB(0,0,0); // Initializing text color to black
	m_brBkgnd.CreateSolidBrush(m_crBkColor); // Creating the Brush Color For the Edit Box Background
}

CColorEdit::~CColorEdit()
{
}


BEGIN_MESSAGE_MAP(CColorEdit, CEdit)
	//{{AFX_MSG_MAP(CColorEdit)
	ON_WM_CTLCOLOR_REFLECT()
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()

/*-------------------------------------------------------------------------------------
Function		: SetTextColor
In Parameters	: COLORREF crColor : color value.
Out Parameters	:
Purpose			: sets the color of the text in edit control.
Author			:
--------------------------------------------------------------------------------------*/
void CColorEdit::SetTextColor(COLORREF crColor)
{
	m_crTextColor = crColor; // Passing the value passed by the dialog to the member varaible for Text Color
	RedrawWindow();
}
/*-------------------------------------------------------------------------------------
Function		: SetBkColor
In Parameters	: COLORREF crColor : color value.
Out Parameters	:
Purpose			: sets the background color
Author			:
--------------------------------------------------------------------------------------*/
void CColorEdit::SetBkColor(COLORREF crColor)
{
	m_crBkColor = crColor; // Passing the value passed by the dialog to the member varaible for Backgound Color
	m_brBkgnd.DeleteObject(); // Deleting any Previous Brush Colors if any existed.
	m_brBkgnd.CreateSolidBrush(crColor); // Creating the Brush Color For the Edit Box Background
	RedrawWindow();
}

/*-------------------------------------------------------------------------------------
Function		: CtlColor
In Parameters	:
Out Parameters	:
Purpose			: to change the background colors
Author			:
--------------------------------------------------------------------------------------*/
HBRUSH CColorEdit::CtlColor(CDC* pDC, UINT nCtlColor)
{
	HBRUSH hbr;
	hbr = (HBRUSH)m_brBkgnd; // Passing a Handle to the Brush
	pDC->SetBkColor(m_crBkColor); // Setting the Color of the Text Background to the one passed by the Dialog
	pDC->SetTextColor(m_crTextColor); // Setting the Text Color to the one Passed by the Dialog

	if(nCtlColor)      // To get rid of compiler warning
		nCtlColor += 0;

	return hbr;
}

/*-------------------------------------------------------------------------------------
Function		: SetReadOnly
In Parameters	: bool flag: true for making the edit control read only else false.
Out Parameters	:
Purpose			: to set the dialog box read only.
Author			:
--------------------------------------------------------------------------------------*/
BOOL CColorEdit::SetReadOnly(BOOL flag)
{
	if(flag == TRUE)
		SetBkColor(m_crBkColor);
	else
		SetBkColor(RGB(255,255,255));

	return CEdit::SetReadOnly(flag);
}

