/*======================================================================================
   FILE				: StaticEx.h
   ABSTRACT			: This class is used as advance version of CStatic class
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
#pragma once
#include "afxwin.h"

class CStaticEx :
	public CStatic
{
public:
	CStaticEx(void);
	~CStaticEx(void);

	afx_msg void OnPaint();
	afx_msg HBRUSH OnCtlColor(CDC* pDC, CWnd* pWnd, UINT nCtlColor);

	void SetDefaultFont();
	void SetBkColorEx(COLORREF clrBack, bool bTransparent = false);
	void SetTextColorEx(COLORREF clrText);
	void SetFontEx(const CString& csFontName, int iFontHeight, int iFontWidth, int iFontUnderline = 0, int iFontWeight = FW_NORMAL);

	DECLARE_MESSAGE_MAP()
private:
	CFont m_objFont;
	COLORREF m_clrBack;
	COLORREF m_clrText;
	bool m_bTransparent;
};
