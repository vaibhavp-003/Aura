/*======================================================================================
   FILE			: NewTreeListCtrl.h
   ABSTRACT		: Class to manage the tree control of the tree view.
   DOCUMENTS	: 
   AUTHOR		: Zuber
   COMPANY		: Aura 
   COPYRIGHT NOTICE    :
						(C)Aura:
      					Created as an unpublished copyright work.  All rights reserved.
     					This document and the information it contains is confidential and
      					proprietary to Aura.  Hence, it may not be 
      					used, copied, reproduced, transmitted, or stored in any form or by any 
      					means, electronic, recording, photocopying, mechanical or otherwise, 
      					without the prior written permission of Aura
   CREATION DATE: 22/01/2007
   NOTE			: This is a third party code
   VERSION HISTORY	:
=======================================================================================*/

#if !defined(AFX_NEWTREELISTCTRL_H__B2E827F7_4D4B_11D1_980A_004095E0DEFA__INCLUDED_)
#define AFX_NEWTREELISTCTRL_H__B2E827F7_4D4B_11D1_980A_004095E0DEFA__INCLUDED_

#if _MSC_VER >= 1000
#pragma once
#endif

#include "NewHeaderCtrl.h"
#include "MaxConstant.h"

struct SSortType
{
	int nCol;
	BOOL bAscending;
	BOOL m_ParentsOnTop;
};

enum {ALIGN_LEFT, ALIGN_RIGHT, ALIGN_CENTER, NO_ALIGN};

class CTLItem
{
public:
	CTLItem();						//Constructor for class CTLItem
	CTLItem(CTLItem &copyItem);		//Copy Constructor for class CTLItem
	~CTLItem();

	//below m_nSub is zero-based
	//Returns the text associated with the item
	CString GetItemString(){ return m_itemString; };
	//Returns the text associated with the column
	CString GetSubstring(int m_nSub);
	//Returns the text in column 0
	CString GetItemText(){ return GetSubstring(0); };
	//Sets the text for a particular column in the tree
	void SetSubstring(int m_nSub, CString m_sText);
	//Sets text for column 0
	void InsertItem(CString m_sText){ SetSubstring(0, m_sText); };

	void SetStructure(MAX_PIPE_DATA sPipeData)
	{
		m_PipeDataReg.eMessageInfo = sPipeData.eMessageInfo;
		m_PipeDataReg.sScanOptions = sPipeData.sScanOptions;
		m_PipeDataReg.ulSpyNameID = sPipeData.ulSpyNameID;
		_tcscpy_s(m_PipeDataReg.strKey, sPipeData.strValue);
		_tcscpy_s(m_PipeDataReg.strValue, sPipeData.strFreshFile);
	}
	void SetStructure(MAX_PIPE_DATA_REG sPipeDataReg)
	{
		memcpy_s(&m_PipeDataReg, sizeof(MAX_PIPE_DATA_REG), &sPipeDataReg, sizeof(MAX_PIPE_DATA_REG));
	}

	void SetStructure(LPSPY_ENTRY_DETAIL pSpyEntryDetails)
	{
		memcpy_s(&m_SpyEntryDetails, SIZE_OF_SPY_ENTRY_DETAIL, pSpyEntryDetails, SIZE_OF_SPY_ENTRY_DETAIL);
	}

	DWORD m_itemData;
	WCHAR m_cEnding;
	CString m_itemString;
	DWORD m_dwSpyID;
	bool m_bUseSpyID;

	// visual attributes
	BOOL m_Bold;					//Indicates bold font for the item text
	COLORREF m_Color;				//Indicates color for the item text
	BOOL m_HasChildren;				//Indicates that the item has children
	int m_nPriority;				//Indicates the priority of the item

	BOOL m_Group;					//
	BOOL m_Destructed;

	SPY_ENTRY_DETAIL		m_SpyEntryDetails;
	MAX_PIPE_DATA_REG		m_PipeDataReg;
	TCHAR					m_tchBackupFileName[MAX_PATH];
	UINT64					m_u64DateTime;
	long					m_lIndex;
	int						m_iRemoveDBType;
};

// CNewTreeListCtrl window
class CNewTreeListCtrl : public CTreeCtrl
{
public:
	CNewTreeListCtrl(HMODULE hResDLL);			//Constructor for class CNewTreeListCtrl
	virtual ~CNewTreeListCtrl();	//Destructor for class CNewTreeListCtrl

	//Performance Fix
	void ResetPaintParams();
	void SetRedrawOnInsert(BOOL bRedraw, BOOL bCheckPrevious = FALSE);
	BOOL m_bRedrawOnInsert;
	void SetInsertItemState(bool bEnablePaint);
	//Creates a rect object with co-ordinates within the tree control
	CRect CRectGet(int left, int top, int right, int bottom);

	//Calculates and sets the header of the tree control
	void RecalcHeaderPosition();

	//Gets the number of columns in the tree view
	int GetColumnsNum(){ return m_nColumns; };

	//Gets the total width of the columns
	int GetColumnsWidth();

	//Gets the total item count
	int GetItemCount(){ return m_nItems; };

	//Gets the total width of the columns
	int GetSelectedItemCount(){ return m_nSelectedItems; };

	//Get all entries
	void GetAllEntries();

	//Calculates the total width of all the columns
	void RecalcColumnsWidth();

	//Reset the vertical scroll bar of the tree control.
	void ResetVertScrollBar();

	//Returns the handle of the item for a particular index in the tree
	HTREEITEM GetTreeItem(int nItem);

	//Retrieves the index of a item 'hItem' from the tree control
	int GetListItem(HTREEITEM hItem);

	//Inserts a new column in the header of tree control
	int InsertColumn(int nCol, LPCTSTR lpszColumnHeading, int nFormat = LVCFMT_LEFT, int nWidth = -1, int nSubItem = -1);

	//Retrieves the column width
	int GetColumnWidth(int nCol);

	//Retrieves the column alligment (LVCFMT_LEFT, LVCFMT_RIGHT
	int GetColumnAlign(int nCol);

	//Sets application-specific value associated with the specified item
	BOOL SetItemData(HTREEITEM hItem, DWORD dwData);
	//Retrieves the application-specific value associated with the item
	DWORD GetItemData(HTREEITEM hItem)const;

	//Retrieves the text from the column of an item
	CString GetItemText(HTREEITEM hItem, int nSubItem = 0);
	//Retrieves the text from the column of an item
	CString GetItemText(int nItem, int nSubItem);

	//Inserts new item in the tree control
	HTREEITEM InsertItem(LPCTSTR lpszItem, int nImage, int nSelectedImage, HTREEITEM hParent = TVI_ROOT, HTREEITEM hInsertAfter = TVI_LAST);
	//Inserts new item in the tree control
	HTREEITEM InsertItem(LPCTSTR lpszItem, HTREEITEM hParent = TVI_ROOT, HTREEITEM hInsertAfter = TVI_LAST);
	//Inserts new item in the tree control
	HTREEITEM InsertItem(UINT nMask, LPCTSTR lpszItem, int nImage, int nSelectedImage, UINT nState, UINT nStateMask, LPARAM lParam, HTREEITEM hParent, HTREEITEM hInsertAfter);

	//Finds an item which has m_title at the nCol column.Searches only the parent items
	HTREEITEM FindParentItem(CString m_title, int nCol = 0, HTREEITEM hItem = NULL, LPARAM itemData = 0);

	//Copies and pastes the item in the tree control
	HTREEITEM CopyItem(HTREEITEM hItem, HTREEITEM hParent=TVI_ROOT, HTREEITEM hInsertAfter=TVI_LAST);
	//Moves the item to a new location in the tree
	HTREEITEM MoveItem(HTREEITEM hItem, HTREEITEM hParent=TVI_ROOT, HTREEITEM hInsertAfter=TVI_LAST);

	//Deletes the item
	BOOL DeleteItem(HTREEITEM hItem);
	//Deletes the item at the index
	BOOL DeleteItem(int nItem);

	//Deletes the application-specific data of the item and its children, if any
	void MemDeleteAllItems(HTREEITEM hParent);
	//Deletes all the items in the tree view
	BOOL DeleteAllItems();

	//Sets the text in a particular column for the tree item
	BOOL SetItemText(HTREEITEM hItem, int nCol,LPCTSTR lpszItem);

	//Sets the color for the item
	BOOL SetItemColor(HTREEITEM hItem, COLORREF m_newColor, BOOL m_bInvalidate = TRUE);
	//Sets bold font for the text of the item
	BOOL SetItemBold(HTREEITEM hItem, BOOL m_Bold = TRUE, BOOL m_bInvalidate = TRUE);
	//
	BOOL SetItemGroup(HTREEITEM hItem, BOOL m_Group = TRUE, BOOL m_bInvalidate = TRUE);
	//
	BOOL SetItemFrame(HTREEITEM hItem, int nFrame, BOOL bInvalidate = TRUE);
	//
	BOOL GetItemFrame(HTREEITEM hItem);

	//Retrieves whether the font is bold for the item
	BOOL IsBold(HTREEITEM hItem);
	//
	BOOL IsGroup(HTREEITEM hItem);

	//Sets the priority for the item, required for sorting
	BOOL SetItemPriority(HTREEITEM hItem, int m_nPriority);
	//Retrieves the priority of the item
	int GetItemPriority(HTREEITEM hItem);

	//Application defined callback function that compares the items required for sorting
	static int CALLBACK CompareFunc(LPARAM lParam1, LPARAM lParam2, LPARAM lParamSort);
	//Sorts the tree view using application defined callback function
	BOOL SortItems(int nCol = 0, BOOL bAscending = TRUE, HTREEITEM low = NULL);

	//Draws the text for an item
	void DrawItemText (CDC* pDC, CString text, CRect rect, int nWidth, int nFormat);

	//Expands or collapses the item
	BOOL Expand(HTREEITEM hItem, UINT nCode);

	//Returns the number of children for the hItem if it is not NULL,
	//otherwise the total number of children in the tree view
	int GetChildCount(HTREEITEM hItem = NULL);

	//Modifies the check state of the item and its children, if item is not NULL otherwise changes
	//the state of all the items in the tree view
	bool SetCheckAll(bool fCheck = true, HTREEITEM hItem = NULL);
	//Modifies the check state of the item
	bool SetCheck(HTREEITEM hItem, bool fCheck = true);
	//Retrieves the check state of the item
	bool GetCheck(HTREEITEM hItem);

	bool Expand(CString csParentItem);

	BOOL SetItemStructure(HTREEITEM, MAX_PIPE_DATA&);
	BOOL SetItemStructure(HTREEITEM, MAX_PIPE_DATA_REG&);
	BOOL SetItemStructure(HTREEITEM hItem, LPSPY_ENTRY_DETAIL pSpyEntryDetails);

	MAX_PIPE_DATA_REG* GetItemStructure(HTREEITEM hItem);
	bool GetItemStructure(HTREEITEM hItem, LPSPY_ENTRY_DETAIL &lpSpyEntry);

	BOOL SetItemBackupFileName(HTREEITEM hItem, LPTSTR lpszBackup);
	BOOL SetItemDateTime(HTREEITEM hItem, UINT64 u64DateTime);

	LPTSTR GetItemBackupFileName(HTREEITEM hItem);
	UINT64 GetItemDateTime(HTREEITEM hItem);

	BOOL SetItemIndex(HTREEITEM hItem, long lIndex, int iRemoveDBType);
	long GetItemIndex(HTREEITEM hItem, int &iRemoveDBType);

	CTLItem* GetTLItem(HTREEITEM hItem);
	void SetTLItem(HTREEITEM hItem, CTLItem* pTLItem);

	HMODULE	m_hResDLL;
	CNewHeaderCtrl m_wndHeader;		//Obect of the tree header
	CFont m_headerFont;				//Font for the header
	int m_nOffset;					//
	CScrollBar m_horScrollBar;		//Object of the horizontal scroll bar
	BOOL m_ParentsOnTop;			// Specifies whether all the items that have children should go first
	BOOL m_RTL;						//Right to left
	bool m_bPaint;
	// drag & drop
	CImageList* m_pDragImage;
	HTREEITEM m_htiDrag, m_htiDrop, m_htiOldDrop;
	BOOL m_bLDragging, m_toDrag;
	UINT m_idTimer, m_scrollTimer;
	UINT m_timerticks;
	HCURSOR m_hCursor;
	bool m_bShowLink;
	CString m_csLinkText;
	bool m_bShowHelp; //this variable will be true if help is to be shown for a list control.: Avinash Bhardwaj
	// Generated message map functions
protected:
	//{{AFX_MSG(CNewTreeListCtrl)
	afx_msg void OnPaint();
	afx_msg int OnCreate(LPCREATESTRUCT lpCreateStruct);
	afx_msg void OnLButtonDown(UINT nFlags, CPoint point);
	afx_msg void OnLButtonDblClk(UINT nFlags, CPoint point);
	afx_msg void OnTimer(UINT_PTR nIDEvent);
	afx_msg void OnDestroy();
	afx_msg void OnMouseMove(UINT nFlags, CPoint point);
	afx_msg void OnVScroll(UINT nSBCode, UINT nPos, CScrollBar* pScrollBar);
	afx_msg void OnSize(UINT nType, int cx, int cy);
	afx_msg void OnNMCustomdraw(NMHDR *pNMHDR, LRESULT *pResult);
	afx_msg void OnKeyDown(UINT nChar, UINT nRepCnt, UINT nFlags);
	virtual BOOL PreTranslateMessage(MSG* pMsg);
	afx_msg BOOL OnSetCursor(CWnd* pWnd, UINT nHitTest, UINT message);

	//}}AFX_MSG

	DECLARE_MESSAGE_MAP()

private:
	bool m_bVisibleItemDraw;
	bool m_bEnableInsPaint;
	int m_nColumns;					//Number of columns in the tree view
	int m_nColumnsWidth;			//Total columns width
	int m_nItems;					//Total items in the tree view
	int m_nSelectedItems;
	CImageList m_ImageList;
	HTREEITEM m_prevSelectedItem;
	CMapStringToOb m_ParentMap;
	int m_iChildCnt;
};
#endif // !defined(AFX_NEWTREELISTCTRL_H__B2E827F7_4D4B_11D1_980A_004095E0DEFA__INCLUDED_)
