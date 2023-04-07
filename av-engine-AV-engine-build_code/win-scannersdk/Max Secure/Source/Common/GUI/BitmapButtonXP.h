/*=============================================================================
   FILE			: CBitmapButtonXP.h
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
   NOTES		:Custom Bitmap Creation
VERSION HISTORY	:
				
============================================================================*/
#if !defined(AFX_BITMAPBUTTONXP_H__B24E34A6_A3E0_426E_8822_F3FA9881FF3F__INCLUDED_)
#define AFX_BITMAPBUTTONXP_H__B24E34A6_A3E0_426E_8822_F3FA9881FF3F__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

class CBitmapButtonXP : public CBitmapButton
{
public:
	CBitmapButtonXP();
	void SetMouseOverBitmap(CString sMouseOverID);
	virtual BOOL DestroyWindow();
	virtual void DrawItem(LPDRAWITEMSTRUCT lpDrawItemStruct);
	virtual void PreSubclassWindow();
	virtual ~CBitmapButtonXP();
	BOOL LoadBitmapImage(HMODULE hinstDLL, UINT iBitmap,UINT iBitmapSel = 0,UINT iBitmapFocus = 0,UINT iBitmapDisabled = 0);

protected:
	//{{AFX_MSG(CBitmapButtonXP)
	afx_msg void OnMouseMove(UINT nFlags, CPoint point);
	afx_msg void OnTimer(UINT_PTR nIDEvent);
	afx_msg void OnLButtonDown(UINT nFlags, CPoint point);
	afx_msg void OnLButtonUp(UINT nFlags, CPoint point);
	//}}AFX_MSG

	DECLARE_MESSAGE_MAP()
private:
	BOOL	m_bOverControl;
	UINT_PTR m_nTimerID;
	CBitmap m_bOver; // Mouse Over bitmap
	void DrawBitmap(CDC* dc, HBITMAP hbmp, RECT r);
};
#endif // !defined(AFX_BITMAPBUTTONXP_H__B24E34A6_A3E0_426E_8822_F3FA9881FF3F__INCLUDED_)
