/*=============================================================================
   FILE			: TGroupBox.h
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
CREATION DATE   : 
   NOTES		:2/24/06
VERSION HISTORY	:
				
============================================================================*/
#if !defined(AFX_TGROUPBOX_H__FC985894_7DBF_11D3_AE2E_000000000000__INCLUDED_)
#define AFX_TGROUPBOX_H__FC985894_7DBF_11D3_AE2E_000000000000__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#define OFS_X	10 // distance from left/right side to beginning/end of text
// Includes

class CTGroupBox : public CButton
{
public:
	CTGroupBox(void);
	virtual ~CTGroupBox(void);
protected:
	virtual void PreSubclassWindow();
protected:
	//{{AFX_MSG(CTGroupBox)
	afx_msg void OnPaint();
	afx_msg void OnLButtonDown(UINT nFlags, CPoint point){}
	afx_msg void OnLButtonUp(UINT nFlags, CPoint point){}
	afx_msg void OnLButtonDblClk(UINT nFlags, CPoint point){}
	afx_msg void OnMButtonDblClk(UINT nFlags, CPoint point){}
	afx_msg void OnMButtonDown(UINT nFlags, CPoint point){}
	afx_msg void OnMButtonUp(UINT nFlags, CPoint point){}
	afx_msg void OnNcLButtonDown(UINT nHitTest, CPoint point){}
	afx_msg void OnNcLButtonUp(UINT nHitTest, CPoint point){}
	afx_msg void OnNcMButtonDblClk(UINT nHitTest, CPoint point){}
	afx_msg void OnNcMButtonDown(UINT nHitTest, CPoint point){}
	afx_msg void OnNcMButtonUp(UINT nHitTest, CPoint point){}
	afx_msg void OnNcRButtonDblClk(UINT nHitTest, CPoint point){}
	afx_msg void OnNcRButtonDown(UINT nHitTest, CPoint point){}
	afx_msg void OnNcRButtonUp(UINT nHitTest, CPoint point){}
	afx_msg void OnRButtonUp(UINT nFlags, CPoint point){}
	afx_msg void OnRButtonDown(UINT nFlags, CPoint point){}
	afx_msg void OnRButtonDblClk(UINT nFlags, CPoint point){}
	afx_msg void OnClicked(){}
	afx_msg void OnDoubleclicked(){}
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()
private:
	CFont    m_NormalFont;			// Font for Normal BOLD display
};
#endif // !defined(AFX_TGROUPBOX_H__FC985894_7DBF_11D3_AE2E_000000000000__INCLUDED_)
