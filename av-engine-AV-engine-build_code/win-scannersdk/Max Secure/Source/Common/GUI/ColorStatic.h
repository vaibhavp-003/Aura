/*=============================================================================
   FILE			: ColorStatic.h 
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
CREATION DATE   :2/24/06 
   NOTES		:
VERSION HISTORY	:
				
============================================================================*/
#if !defined(AFX_COLORSTATIC_H__F35D88B3_A7BA_46D1_8FFF_AA0E973D9CC7__INCLUDED_)
#define AFX_COLORSTATIC_H__F35D88B3_A7BA_46D1_8FFF_AA0E973D9CC7__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

class CColorStatic : public CStatic
{
	bool m_SetTransparent;
// Construction
public:
	CColorStatic();

// Attributes
public:
    COLORREF m_clrText;
    COLORREF m_clrBack;
    CBrush m_brBkgnd;

// Operations
public:
    void SetTextColor (COLORREF clrText);
    void SetBkColor (COLORREF clrBack);
	void SetTransparent(bool bSetState);
	void setUnderline(  int iFontUnderline );

// Implementation
public:
	virtual ~CColorStatic();

	// Generated message map functions
protected:
	//{{AFX_MSG(CColorStatic)
	afx_msg HBRUSH CtlColor(CDC* pDC, UINT nCtlColor);
	//}}AFX_MSG

	DECLARE_MESSAGE_MAP()

};

#endif // !defined(AFX_COLORSTATIC_H__F35D88B3_A7BA_46D1_8FFF_AA0E973D9CC7__INCLUDED_)
