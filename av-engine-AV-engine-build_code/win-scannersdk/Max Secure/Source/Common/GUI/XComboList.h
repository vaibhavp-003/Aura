/*=============================================================================
   FILE			 : XComboList.h
   ABSTRACT		 : 
   DOCUMENTS	 : 
   AUTHOR		 :
   COMPANY		 : Aura 
   COPYRIGHT NOTICE:
			(C) Aura
      		Created as an unpublished copyright work.  All rights reserved.
     		 This document and the information it contains is confidential and
      		proprietary to Aura.  Hence, it may not be 
      		used, copied, reproduced, transmitted, or stored in any form or by any 
      		means, electronic, recording, photocopying, mechanical or otherwise, 
      		with out the prior written permission of Aura
   CREATION DATE : 2/24/06
   NOTES		 :
   VERSION HISTORY :
				
============================================================================*/
#pragma once
#include "StdAfx.h"

extern UINT NEAR WM_XCOMBOLIST_VK_RETURN;
extern UINT NEAR WM_XCOMBOLIST_VK_ESCAPE;
extern UINT NEAR WM_XCOMBOLIST_KEYDOWN;
extern UINT NEAR WM_XCOMBOLIST_LBUTTONUP;

class CXComboList : public CWnd
{
public:
	CXComboList(CWnd *pParent);
	virtual ~CXComboList();
	void SetActive(int nScrollBarWidth);

	int AddString(LPCTSTR lpszItem)
	{
		return m_ListBox.AddString(lpszItem);
	}
	int GetCount()
	{
		return m_ListBox.GetCount();
	}
	void GetText(int nIndex, CString& rString)
	{
		m_ListBox.GetText(nIndex, rString);
	}
	int FindStringExact(int nIndexStart, LPCTSTR lpszFind)
	{
		return m_ListBox.FindStringExact(nIndexStart, lpszFind);
	}
	int SetCurSel(int nSelect)
	{
		return m_ListBox.SetCurSel(nSelect);
	}
	int GetCurSel()
	{
		return m_ListBox.GetCurSel();
	}
	void SetFont(CFont* pFont, BOOL bRedraw = TRUE)
	{
		m_ListBox.SetFont(pFont, bRedraw);
	}
	virtual BOOL PreTranslateMessage(MSG* pMsg);
	virtual CScrollBar* GetScrollBarCtrl(int nBar);

protected:
	CListBox	m_ListBox;
	CScrollBar	m_wndSBVert;
	CWnd *		m_pParent;
	int			m_nCount;
	BOOL		m_bFirstTime;
	void SendRegisteredMessage(UINT nMsg, WPARAM wParam, LPARAM lParam);
	afx_msg void OnLButtonDown(UINT nFlags, CPoint point);
	afx_msg void OnKillFocus(CWnd* pNewWnd);
	afx_msg int OnCreate(LPCREATESTRUCT lpCreateStruct);
	afx_msg void OnVScroll(UINT nSBCode, UINT nPos, CScrollBar* pScrollBar);
	afx_msg void OnDestroy();
	afx_msg void OnTimer(UINT_PTR nIDEvent);
	DECLARE_MESSAGE_MAP()
};