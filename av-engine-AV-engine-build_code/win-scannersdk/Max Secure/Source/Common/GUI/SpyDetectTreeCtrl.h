/*=============================================================================
FILE		           : SpyDetectTreeCtrl.h
ABSTRACT		       : 
DOCUMENTS	       : Refer The GUI Design.doc, GUI Requirement Document.doc
AUTHOR		       : Zuber
COMPANY		       : Aura 
COPYRIGHT NOTICE    :
					(C)Aura:
					Created as an unpublished copyright work.  All rights reserved.
					This document and the information it contains is confidential and
					proprietary to Aura.  Hence, it may not be 
					used, copied, reproduced, transmitted, or stored in any form or by any 
					means, electronic, recording, photocopying, mechanical or otherwise, 
					without the prior written permission of Aura
CREATION DATE       : 22/01/2007
NOTE			       : Class to manage the tree view on the main dialog.
VERSION HISTORY	   :
Version 1.0
Resource: Zuber
Description: New class to manage the tree control of the tree view.
=============================================================================*/
#ifndef SPY_DETECT_TREE_CTRL_H
#define SPY_DETECT_TREE_CTRL_H

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#include "afxwin.h"
#include <Afxcmn.h>

#include "NewTreeListCtrl.h"
#include "NewHeaderCtrl.h"

#include "MaxConstant.h"

#define ID_TREE_LIST_HEADER		6000
#define ID_TREE_LIST_CTRL		6001
#define ID_TREE_LIST_SCROLLBAR	6003
/*-------------------------------------------------------------------------------------
Class          : CSpyDetectTreeCtrl
Purpose		   : Class to manage the tree view on the main dialog.
Author		   :
-------------------------------------------------------------------------------------*/
const int INSERT_ITEM_PAINT_COUNT = 500;
const int DELETE_ITEM_PAINT_COUNT = 50;
class CSpyDetectTreeCtrl
{
public:
	int m_nDiff;
	CSpyDetectTreeCtrl(CStatic * treeView, HMODULE hResDLL);		//Constructor for class CSpyDetectTreeCtrl
	~CSpyDetectTreeCtrl();							//Destructor for class CSpyDetectTreeCtrl

	//Sets the tree control handle
	void SetTreeView(CStatic * treeView);

	int GetHeaderColumnNo(POINT pt);
	void ExpandColumntoFullLength(int iColumn);

	//Initializes the tree view, creates columns, header, tree control and sets the image list.
	void InitializeTreeCtrl();

	//Inserts the parent in the tree control
	HTREEITEM InsertParent(const CString& text, int threatIndex, const CString &csInfoHelp = _T(""), DWORD dwSpyID = 0, bool bUseSpyID = true);

	//Inserts an child item under the parent in the tree control
	HTREEITEM InsertChild(HTREEITEM hRoot, const CString& threatType, const CString& threatValue,
		const CString& signature, int image,CString csActMonDB =L"");

	//Inserts an child item under the parent in the tree control
	HTREEITEM InsertChild(HTREEITEM hRoot, const CString& threatType, const CString& threatValue,const CString csDate,
		const CString& csKey,const CString& csData,const CString& csNewFileName, int image = -1);


	//Invoked from main OnNotify handler.Manages sorting and movement of header
	void OnNotify(WPARAM wParam, LPARAM lParam, LRESULT * pResult);

	//Invoked from main OnHScroll handler.Handles the scrolling of horizontal scroll bar
	void OnHScroll(UINT nSBCode, UINT nPos, CScrollBar * pScrollBar);

	//Invoked from main OnSize handler.Resizes the controls of the tree view
	void OnSize();

	//Sets the horizontal scroll bar to correct position
	void ResetScrollBar();

	//Checks if the spyware name is already present in the tree view
	HTREEITEM FindParentItem(const CString& spyName);

	//Returns the number of children for the hItem if it is not NULL,
	//otherwise the total number of children in the tree view
	int GetChildCount(HTREEITEM hItem = NULL);

	//Inserts a new column in the header of tree view
	int InsertColumn(int nCol, LPCTSTR lpszColumnHeading, int nFormat = LVCFMT_LEFT,
		int nWidth = -1, int nSubItem = -1);

	//Deletes all items in the tree view
	bool DeleteAllItems();

	//Returns the total number nodes in the tree view
	int GetItemCount();

	//Returns the total number selected items in the tree view
	int GetSelectedItemCount();
	//Returns the item for the given index
	HTREEITEM GetTreeItem(int nItem);

	//Retrieves an item's check state
	bool GetCheck(HTREEITEM hItem);
	//Sets the item's check state
	bool SetCheck(HTREEITEM hItem, bool fCheck = true);

	//Sets the item's check state
	bool SetCheckAll(bool fCheck = true, HTREEITEM hItem = NULL);

	//Returns the text from the given column for the respective hItem
	CString GetItemText(HTREEITEM hItem, int nSubItem = 0);
	//Returns the text from the column for the item at the given index
	CString GetItemText(int nItem, int nSubItem);
	//Sets the text in the column for the given item
	bool SetItemText(HTREEITEM hItem, int nCol, LPCTSTR lpszItem);

	//Sets link
	void SetLink(bool bFlag = true);
	void SetLinkCaption(const CString &csCaption);
	//Deletes an item from the tree view
	bool DeleteItem(HTREEITEM hItem);
	//Deletes an item from the tree view
	bool DeleteItem(int nItem);

	//Sets the state of the item specified by hItem
	bool SetItemState(HTREEITEM hItem, UINT nState, UINT nStateMask);
	//Retrieves the state of the item specified by hItem
	UINT GetItemState(HTREEITEM hItem, UINT nStateMask)const;
	//Sets the color for the item
	BOOL SetItemColor(HTREEITEM hItem, COLORREF m_newColor, BOOL m_bInvalidate = TRUE);

	HTREEITEM GetRootItem();
	HTREEITEM GetChildItem(HTREEITEM hItem);
	HTREEITEM GetNextItem(HTREEITEM hItem,UINT nCode);

	bool Expand(CString csParentItem);

	//Ensures that a tree view item is visible
	bool EnsureVisible(HTREEITEM hItem);

	//Retrieves the coordinates of a window's client area
	void GetClientRect(LPRECT lpRect)const;

	//Retrieves the handle of the parent window
	CWnd * GetParent()const;

	//Show/Hide the window
	void ShowWindow(int nCmdShow);

	//return the visible state of the window
	BOOL IsWindowVisible();

	//Check if item has children
	bool ItemHasChildren(HTREEITEM hItem);

	//Returns the parent of the item
	HTREEITEM GetParentItem(HTREEITEM hItem)const;

	//Sorts the list
	void SortItems(int nCol);
	void EnableHelp(bool bEnable);
	//Sets the redraw flag
	void SetRedraw(bool redraw, bool bUpdate = false);

	void SetHeaderColumnText(int iColumn,CString csText);

	void AddStructure(HTREEITEM, MAX_PIPE_DATA&);
	void AddStructure(HTREEITEM, MAX_PIPE_DATA_REG&);
	void AddStructure(HTREEITEM hItem, LPSPY_ENTRY_DETAIL pSpyEntryDetails);
	MAX_PIPE_DATA_REG* GetStructure(HTREEITEM);
	bool GetStructure(HTREEITEM hItem, LPSPY_ENTRY_DETAIL &lpSpyEntry);

	void AddBackupFileName(HTREEITEM hItem, LPTSTR lpszBackup);
	void AddDateTime(HTREEITEM hItem, UINT64 u64DateTime);
	void AddIndex(HTREEITEM hItem, long lIndex, int iRemoveDBType);
	LPTSTR GetBackupFileName(HTREEITEM);
	UINT64 GetDateTime(HTREEITEM);
	long GetIndex(HTREEITEM, int&);

	CTLItem* GetTLItem(HTREEITEM hRoot)
	{
		return m_treeCtrl.GetTLItem(hRoot);
	}
	void UpdatePaintTree(bool bPaint)
	{
		m_treeCtrl.m_bPaint = bPaint;
	}
	void SetInsertItemState(bool bEnablePaint)
	{
		m_treeCtrl.SetInsertItemState(bEnablePaint);
	}
	friend class CNewHeaderCtrl;

private:
	CStatic * m_treeView;							//Tree view handle
	CImageList m_ThreatImgList;						//Image list for threat level
	CImageList m_WormImgList;						//Image list for worm type
	CImageList m_TestImgList;						//Image list for worm type
	CImageList m_CheckboxImgList;					//Image list for check boxes in the treeview
	bool m_ctrlInit;								//Indicates that tree control is initialized
	CNewTreeListCtrl m_treeCtrl;					//Object of the tree control
	bool m_Destructed;

	//Checks if the vertical scroll bar is visible
	BOOL VerticalScrollVisible();
};

#endif //SPY_DETECT_TREE_CTRL_H