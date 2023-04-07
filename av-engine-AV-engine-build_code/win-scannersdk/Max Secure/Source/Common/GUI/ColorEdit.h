/*=============================================================================
   FILE			: ColorEdit.h
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
CREATION DATE   : 22/02/2007
   NOTES		:GUI Custom Draw classes
VERSION HISTORY	:
				
============================================================================*/
#if !defined(AFX_ColorEdit_H__E889B47D_AF6B_4066_B055_967508314A88__INCLUDED_)
#define AFX_ColorEdit_H__E889B47D_AF6B_4066_B055_967508314A88__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000
// ColorEdit.h : header file
//


/////////////////////////////////////////////////////////////////////////////
// CColorEdit window

class CColorEdit : public CEdit
{
// Construction
public:
	CColorEdit();
	void SetBkColor(COLORREF crColor); // This Function is to set the BackGround Color for the Text and the Edit Box.
	void SetTextColor(COLORREF crColor); // This Function is to set the Color for the Text.
	BOOL SetReadOnly(BOOL flag = TRUE);
	virtual ~CColorEdit();

	// Generated message map functions
protected:
	CBrush m_brBkgnd; // Holds Brush Color for the Edit Box
	COLORREF m_crBkColor; // Holds the Background Color for the Text
	COLORREF m_crTextColor; // Holds the Color for the Text
	afx_msg HBRUSH CtlColor(CDC* pDC, UINT nCtlColor); // This Function Gets Called Every Time Your Window Gets Redrawn.
	DECLARE_MESSAGE_MAP()
};

#endif // !defined(AFX_ColorEdit_H__E889B47D_AF6B_4066_B055_967508314A88__INCLUDED_)
