/*======================================================================================
FILE             : MaxListControl.h
ABSTRACT         :
DOCUMENTS	     : 
AUTHOR		     : Ramkrushna Shelke
COMPANY		     : Aura 
COPYRIGHT(NOTICE): 
				  (C) Aura
				  Created as an unpublished copyright work.  All rights reserved.
				  This document and the information it contains is confidential and
				  This document and the information it contains is confidential and
				  proprietary to Aura.  Hence, it may not be 
				  used, copied, reproduced, transmitted, or stored in any form or by any 
				  means, electronic, recording, photocopying, mechanical or otherwise, 
				  without the prior written permission of Aura.	

CREATION DATE    : 17 April, 2012.
NOTES		     : Defines the class behaviors for the application
VERSION HISTORY  : 
======================================================================================*/
#pragma once
#include <AfxTempl.h>
#include "DrawHTML.h"
#include "MaxFont.h"

#define DEFAULT_STYLES				WS_BORDER|WS_CHILD|WS_VISIBLE|WS_VSCROLL|WS_TABSTOP
#define HTMLLIST_STYLE_CHECKBOX		1
#define HTMLLIST_STYLE_GRIDLINES	2
#define HTMLLIST_STYLE_IMAGES		4
#define HTMLLIST_STYLE_BUTTONS		5
#define INVALID_ITEM	-1
//Item Types
#define HTML_TEXT			1
#define NORMAL_TEXT			2
#define SINGLE_LINE_TEXT	3
#define SINGLE_BUTTON		4
//Calculate Item height Automatically
#define AUTO	0
//Padding between items
#define ITEM_PADDING_TOP			7
#define ITEM_PADDING_BOTTOM			20
#define ITEM_PADDING_LEFT			5	//if check box then after checkbox padding
#define ITEM_PADDING_CHECKBOX_LEFT	3
#define ITEM_IMAGE_PADDING_LEFT		5
#define ITEM_IMAGE_PADDING_RIGHT	10
#define ITEM_CHECKBOX_WIDTH			26
//for selection
#define NONE_SELECTED		-1
//Events
#define HTMLLIST_SELECTIONCHANGED	1
#define HTMLLIST_LBUTTONDOWN		2
#define HTMLLIST_RBUTTONDOWN		3
#define HTMLLIST_LBUTTONDBLCLICK	4
#define HTMLLIST_ITEMCHECKED		5
#define HTMLLIST_ITEMONOFF			6

struct NM_HTMLLISTCTRL
{
	NMHDR hdr;
	int nItemNo;
	CString sItemText;
	LPARAM lItemData;
	BOOL bChecked;
	BOOLEAN bStatus;
};
struct HTMLLIST_ITEM
{
	HTMLLIST_ITEM()
	{
		nItemNo = INVALID_ITEM;
		lItemData = 0;
		nHeight = 0;
		nStyle = NORMAL_TEXT;
		rcItem.SetRectEmpty();
		bChecked = FALSE;
		bHeightSpecified = FALSE;
	}

	int			nItemNo;
	int			nHeight;
	int			nStyle;
	CString		sItemText;
	LPARAM		lItemData;
	CRect		rcItem;
	BOOL		bChecked;
	BOOL		bHeightSpecified;
	UINT		uiImage;
	BOOLEAN		bStatus;
};

class CMaxListControl : public CWnd
{
	// Construction
public:
	CMaxListControl();
	virtual ~CMaxListControl();

	bool m_bRegister;

	void SetInternalData(int nPos, HTMLLIST_ITEM *pData);
	BOOL IsRectVisible(CRect rcClipBox, CRect rcItem);
	void SendCheckStateChangedNotification(int nPos);
	void SendSelectionChangeNotification(int nPos);
	virtual void DrawItem(CDC *pDC, CRect rcItem, HTMLLIST_ITEM *pItem, BOOL bSelected);
	void SetImage(int nPos, UINT uiImage);
	UINT GetImage(int nPos);
	void ReArrangeWholeLayout();
	void ReArrangeItems();
	BOOL DeleteItem(int nPos);
	void SetItemText(int nPos, CString sItemText, BOOL bCalculateHeight = FALSE);
	BOOL GetItemCheck(int nPos);
	BOOL GetItemStatus(int nPos);
	void SetItemCheck(int nPos, BOOL bChecked = TRUE);
	void EnsureVisible(int nPos);
	DWORD GetExtendedStyle();
	void SetExtendedStyle(DWORD dwExStyle);
	CString GetItemText(int nPos);
	int GetSelectedItem();
	void SetItemData(int nPos, LPARAM lItemData);
	LPARAM GetItemData(int nPos);
	void DeleteAllItems();
	int InsertItem(CString sText, UINT uiImage, int nStyle = HTML_TEXT, int nHeight = AUTO);
	BOOL Create(CWnd *pParent, CRect oRc, UINT nID, DWORD dwStyle = DEFAULT_STYLES);
	void SetItemStatus(int iItemNo, BOOLEAN bStatus);

	int	GetItemCount()
	{
		return static_cast<int>(m_oListItems.GetCount());
	}
	void SetImageList(CImageList *pImageList)
	{
		m_pImageList = pImageList;
	}
	CImageList* GetImageList()
	{
		return m_pImageList;
	}

private:
	CList<HTMLLIST_ITEM*, HTMLLIST_ITEM*> m_oListItems;
	CMap<int, int, HTMLLIST_ITEM*, HTMLLIST_ITEM*> m_oMapItems;
	int		m_nTotalItems;
	int		m_nListHeight;			//List Height (Not the actual window height)
	int		m_nWndWidth;			//Actual window width
	int		m_nWndHeight;
	int		m_nSelectedItem;		//selected item
	UINT	m_nControlID;		//Controls id
	BOOL	m_bHasFocus;
	DWORD	m_dwExtendedStyles;

	//GDI stuff
	CMaxFont	*m_pFont;
	CPen		 m_oPenLight;
	COLORREF	 m_clrBkSelectedItem;

	CImageList	m_ImageList;
	CImageList	m_ButtonImageList;
	CImageList *m_pImageList;

	HTMLLIST_ITEM * GetInternalData(int nPos);
	CRect GetItemRect(int nPos);
	int CalculateItemHeight(CString sText, int nStyle, UINT uiImage, int nWidth);
protected:
	afx_msg void OnPaint();
	afx_msg BOOL OnEraseBkgnd(CDC* pDC);
	afx_msg void OnLButtonDown(UINT nFlags, CPoint point);
	afx_msg void OnVScroll(UINT nSBCode, UINT nPos, CScrollBar* pScrollBar);
	afx_msg void OnSize(UINT nType, int cx, int cy);
	afx_msg void OnSetFocus(CWnd* pOldWnd);
	afx_msg void OnKillFocus(CWnd* pNewWnd);
	afx_msg UINT OnGetDlgCode();
	afx_msg void OnKeyDown(UINT nChar, UINT nRepCnt, UINT nFlags);
	afx_msg void OnRButtonDown(UINT nFlags, CPoint point);
	afx_msg void OnLButtonDblClk(UINT nFlags, CPoint point);
	afx_msg void OnDestroy();
	afx_msg BOOL OnSetCursor(CWnd* pWnd, UINT nHitTest, UINT message);
	afx_msg BOOL OnMouseWheel(UINT nFlags, short zDelta, CPoint pt);
	DECLARE_MESSAGE_MAP()
};

