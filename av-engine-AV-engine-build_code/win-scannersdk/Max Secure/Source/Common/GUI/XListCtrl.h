/*=============================================================================
   FILE			 : XListCtrl.h
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
   CREATION DATE   : 2/24/06
   NOTES		 :
   VERSION HISTORY :
				
============================================================================*/
#pragma once
#include "StdAfx.h"
#include "XHeaderCtrl.h"

#ifndef DO_NOT_INCLUDE_XCOMBOLIST
#include "XComboList.h"
#endif

extern UINT NEAR WM_XLISTCTRL_COMBO_SELECTION;
extern UINT NEAR WM_XLISTCTRL_CHECKBOX_CLICKED;

struct XLISTCTRLDATA
{
	XLISTCTRLDATA()
	{
		bEnabled             = TRUE;
		crText               = ::GetSysColor(COLOR_WINDOWTEXT);
		crBackground         = ::GetSysColor(COLOR_WINDOW);
		bShowProgress        = FALSE;
		nProgressPercent     = 0;
		strProgressMessage   = _T("");
		bShowProgressMessage = TRUE;
		nCheckedState        = -1;
		bBold                = FALSE;
		bLink				 = FALSE;
		nImage               = -1;
#ifndef NO_XLISTCTRL_TOOL_TIPS
		strToolTip           = _T("");
#endif
		bCombo               = FALSE;
		bComboIsClicked      = FALSE;
		nComboListHeight     = 10;
		nInitialComboSel     = 0;
		psa                  = NULL;
		dwItemData           = 0;
	}

	BOOL			bEnabled;				// TRUE = enabled, FALSE = disabled (gray text)
	BOOL			bBold;					// TRUE = display bold text
	BOOL			bLink;					//TRUE = disply hyperlink
	int				nImage;					// index in image list, else -1
#ifndef NO_XLISTCTRL_TOOL_TIPS
	CString			strToolTip;				// tool tip text for cell
#endif

	BOOL			bCombo;					// TRUE = display combobox
	BOOL			bComboIsClicked;		// TRUE = downarrow is clicked
	CStringArray *	psa;					// pointer to string array for combo listbox
	int				nComboListHeight;		// combo listbox height (in rows)
	int				nInitialComboSel;		// initial combo listbox selection (0 = first)

	COLORREF	crText;
	COLORREF	crBackground;

	BOOL		bShowProgress;				// true = show progress control
	int			nProgressPercent;			// 0 - 100
	CString		strProgressMessage;			// custom message for progress indicator -
	// MUST INCLUDE %d
	BOOL		bShowProgressMessage;		// TRUE = display % message, or custom message
	// if one is supplied
	// for checkbox
	int			nCheckedState;				// -1 = don't show, 0 = unchecked, 1 = checked

	DWORD		dwItemData;					// pointer to app's data
};


class CXListCtrl : public CListCtrl
{

public:
	CXListCtrl();
	virtual ~CXListCtrl();

	int		CountCheckedItems(int nSubItem);
	BOOL	DeleteAllItems();
	BOOL	DeleteItem(int nItem);
	void	DeleteProgress(int nItem, int nSubItem);
	BOOL	GetBold(int nItem, int nSubItem);
	int		GetCheckbox(int nItem, int nSubItem);
	int		GetColumns();
	CString	GetComboText(int iItem, int iSubItem);
	int		GetCurSel();
	BOOL	GetEnabled(int nItem);
	DWORD	GetExtendedStyleX(){ return m_dwExtendedStyleX; }
	int		GetHeaderCheckedState(int nSubItem);
	DWORD	GetItemData(int nItem);
	BOOL	GetSubItemRect(int iItem, int iSubItem, int nArea, CRect& rect);
	int		InsertItem(int nItem, LPCTSTR lpszItem,  int iImage = -1);
	int		InsertItem(int nItem, LPCTSTR lpszItem, COLORREF crText, COLORREF crBackground,  int iImage = -1);
	int		InsertItem(const LVITEM* pItem);
	BOOL	SetBold(int nItem, int nSubItem, BOOL bBold);
	BOOL	SetHyperLink(int nItem, int nSubItem, BOOL bLink);
	BOOL	SetComboBox(int nItem, int nSubItem, BOOL bEnableCombo, CStringArray *psa,
		int nComboListHeight, int nInitialComboSel);
	BOOL	SetCheckbox(int nItem, int nSubItem, int nCheckedState);
	BOOL	SetCurSel(int nItem);
	BOOL	SetEnabled(int nItem, BOOL bEnable);
	HANDLE	m_hListCtrlMgr;
	DWORD	SetExtendedStyleX(DWORD dwNewStyle)
	{
		DWORD dwOldStyle = m_dwExtendedStyleX;
		m_dwExtendedStyleX = dwNewStyle;
		return dwOldStyle;
	}

	BOOL	SetHeaderCheckedState(int nSubItem, int nCheckedState);
	int		SetItem(const LVITEM* pItem);
	BOOL	SetItemData(int nItem, DWORD dwData);
	BOOL	SetItemImage(int nItem, int nSubItem, int nImage);
	BOOL	SetItemText(int nItem, int nSubItem, LPCTSTR lpszText);
	BOOL	SetItemText(int nItem, int nSubItem, LPCTSTR lpszText, COLORREF crText, COLORREF crBackground);
	BOOL	SetProgress(int nItem, int nSubItem, BOOL bShowProgressText = TRUE, LPCTSTR lpszProgressText = NULL);
	void	UpdateProgress(int nItem, int nSubItem, int nPercent, CString strMessage=_T(""));
	void	UpdateSubItem(int nItem, int nSubItem);
	HCURSOR		m_hCursorHotSpot;

#ifndef NO_XLISTCTRL_TOOL_TIPS
	void DeleteAllToolTips();
	BOOL SetItemToolTipText(int nItem, int nSubItem, LPCTSTR lpszToolTipText);
	CString GetItemToolTipText(int nItem, int nSubItem);
	virtual INT_PTR OnToolHitTest(CPoint point, TOOLINFO * pTI)const;
#endif

	virtual void PreSubclassWindow();
	CXHeaderCtrl	m_HeaderCtrl;
	CImageList		m_cImageList;	// Image list for the header control

protected:
	void DrawCheckbox(int nItem,
		int nSubItem,
		CDC *pDC,
		COLORREF crText,
		COLORREF crBkgnd,
		CRect& rect,
		XLISTCTRLDATA *pCLD);
#ifndef DO_NOT_INCLUDE_XCOMBOLIST
	void DrawComboBox(int nItem,
		int nSubItem,
		CDC *pDC,
		COLORREF crText,
		COLORREF crBkgnd,
		CRect& rect,
		XLISTCTRLDATA *pCLD);
	void UnpressComboButton();
#endif
	int DrawImage(int nItem,
		int nSubItem,
		CDC* pDC,
		COLORREF crText,
		COLORREF crBkgnd,
		CRect rect,
		XLISTCTRLDATA *pXLCD);
	void DrawProgress(int nItem,
		int nSubItem,
		CDC *pDC,
		COLORREF crText,
		COLORREF crBkgnd,
		CRect& rect,
		XLISTCTRLDATA *pCLD);
	void DrawText(int nItem,
		int nSubItem,
		CDC *pDC,
		COLORREF crText,
		COLORREF crBkgnd,
		CRect& rect,
		XLISTCTRLDATA *pCLD);
	void GetDrawColors(int nItem,
		int nSubItem,
		COLORREF& colorText,
		COLORREF& colorBkgnd);
	void SubclassHeaderControl();

	BOOL			m_bHeaderIsSubclassed;
	DWORD			m_dwExtendedStyleX;

	COLORREF		m_cr3DFace;
	COLORREF		m_cr3DHighLight;
	COLORREF		m_cr3DShadow;
	COLORREF		m_crBtnFace;
	COLORREF		m_crBtnShadow;
	COLORREF		m_crBtnText;
	COLORREF		m_crGrayText;
	COLORREF		m_crHighLight;
	COLORREF		m_crHighLightText;
	COLORREF		m_crWindow;
	COLORREF		m_crWindowText;

#ifndef DO_NOT_INCLUDE_XCOMBOLIST
	BOOL			m_bComboIsClicked;
	int				m_nComboItem;
	int				m_nComboSubItem;
	CRect			m_rectComboButton;
	CRect			m_rectComboList;
	CXComboList *	m_pListBox;
	CFont			m_ListboxFont;
	BOOL			m_bFontIsCreated;
	CString			m_strInitialComboString;
#endif

	// Generated message map functions
	//{{AFX_MSG(CXListCtrl)
	afx_msg BOOL OnClick(NMHDR* pNMHDR, LRESULT* pResult);
	afx_msg BOOL OnColumnClick(NMHDR* pNMHDR, LRESULT* pResult);
	afx_msg int OnCreate(LPCREATESTRUCT lpCreateStruct);
	afx_msg void OnCustomDraw(NMHDR* pNMHDR, LRESULT* pResult);
	afx_msg void OnDestroy();
	afx_msg void OnLButtonDown(UINT nFlags, CPoint point);
	afx_msg void OnPaint();
	afx_msg void OnSysColorChange();
	//}}AFX_MSG
#ifndef DO_NOT_INCLUDE_XCOMBOLIST
	afx_msg void OnTimer(UINT_PTR nIDEvent);
	afx_msg LRESULT OnComboEscape(WPARAM, LPARAM);
	afx_msg LRESULT OnComboReturn (WPARAM, LPARAM);
	afx_msg LRESULT OnComboKeydown(WPARAM, LPARAM);
	afx_msg LRESULT OnComboLButtonUp(WPARAM, LPARAM);
#endif

#ifndef NO_XLISTCTRL_TOOL_TIPS
	virtual afx_msg BOOL OnToolTipText(UINT id, NMHDR * pNMHDR, LRESULT * pResult);
#endif

	DECLARE_MESSAGE_MAP()
};
