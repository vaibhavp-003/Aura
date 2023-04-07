/*=============================================================================
   FILE			: SpyDetecttreeCtrl.h
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
   NOTES		:
VERSION HISTORY	:
				
============================================================================*/
#ifndef SPY_DETECT_TREE_CTRL_H
#define SPY_DETECT_TREE_CTRL_H

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#include "afxwin.h"
#include <Afxcmn.h>
#include "RCTreeListCtrl.h"
#include "RCHeaderCtrl.h"

#define ID_TREE_LIST_HEADER		6000
#define ID_TREE_LIST_CTRL		6001
#define ID_TREE_LIST_SCROLLBAR	6003

class CRCSpyDetectTreeCtrl
{
	private:
		CStatic * m_treeView;							//Tree view handle
		CRCNewTreeListCtrl m_treeCtrl;					//Object of the tree control
		bool m_Destructed;

	public:
		bool m_ctrlInit;								//Indicates that tree control is initialized
		CImageList m_ThreatImgList;						//Image list for threat level
		CImageList m_WormImgList;						//Image list for worm type
		CImageList m_TestImgList;						//Image list for worm type
		CImageList m_CheckboxImgList;					//Image list for check boxes in the treeview
	
	private:
		//Checks if the vertical scroll bar is visible
		BOOL VerticalScrollVisible( );

	public:
		CRCSpyDetectTreeCtrl( CStatic * treeView );		//Constructor for class CRCSpyDetectTreeCtrl
		~CRCSpyDetectTreeCtrl( );							//Destructor for class CRCSpyDetectTreeCtrl

		//Sets the tree control handle
		void SetTreeView( CStatic * treeView );

		//Initializes the tree view, creates columns, header, tree control and sets the image list.
		void InitializeTreeCtrl( );

		//Inserts the parent in the tree control
		HTREEITEM InsertParent( const CString& text , int threatIndex, const CString &csInfoHelp = _T(""));

		//Inserts an child item under the parent in the tree control
		HTREEITEM InsertChild( HTREEITEM hRoot , const CString& csWormType , const CString &csKey, 
							   const CString &csValue, const CString &csData, const CString &csDisplayName,
							   const bool bIsChild , const bool bIsAdminEntry, int image );

		//Inserts an child item under the parent in the tree control
		HTREEITEM InsertChild( HTREEITEM hRoot , const CString& threatType , 
							   const CString& threatValue , const CString& csKey ,
							   const CString& csData,const CString& csNewFileName,
							   const CString& csRegDataType, int image = -1);

		//Invoked from main OnNotify handler. Manages sorting and movement of header
		void OnNotify( WPARAM wParam , LPARAM lParam , LRESULT * pResult );

		//Invoked from main OnHScroll handler. Handles the scrolling of horizontal scroll bar
		void OnHScroll( UINT nSBCode , UINT nPos , CScrollBar * pScrollBar );

		//Invoked from main OnSize handler. Resizes the controls of the tree view
		void OnSize( );

		//Sets the horizontal scroll bar to correct position
		void ResetScrollBar( );

		//Checks if the spyware name is already present in the tree view
		HTREEITEM FindParentItem( const CString& spyName );

		//Returns the number of children for the hItem if it is not NULL,
		//otherwise the total number of children in the tree view
		int GetChildCount( HTREEITEM hItem = NULL );

		//Inserts a new column in the header of tree view
		int InsertColumn( int nCol , LPCTSTR lpszColumnHeading , int nFormat = LVCFMT_LEFT ,
						  int nWidth = -1 , int nSubItem = -1 );

		//Deletes all items in the tree view
		bool DeleteAllItems( );

		//Returns the total number nodes in the tree view
		int GetItemCount( );
		
		//Returns the total number selected items in the tree view
		int GetSelectedItemCount();
		//Returns the item for the given index
		HTREEITEM GetTreeItem( int nItem );

		//Retrieves an item's check state
		bool GetCheck( HTREEITEM hItem );
		//Sets the item's check state
		bool SetCheck( HTREEITEM hItem , bool fCheck = true );

		//Sets the item's check state
		bool SetCheckAll( bool fCheck = true , HTREEITEM hItem = NULL );

		//Returns the text from the given column for the respective hItem
		CString GetItemText( HTREEITEM hItem , int nSubItem = 0 );
		//Returns the text from the column for the item at the given index
		CString GetItemText( int nItem , int nSubItem );
		//Sets the text in the column for the given item
		bool SetItemText( HTREEITEM hItem , int nCol , LPCTSTR lpszItem );

		//Sets link
		void SetLink( bool bFlag = true );
		void SetLinkCaption(const CString &csCaption);
		//Deletes an item from the tree view
		bool DeleteItem( HTREEITEM hItem );
		//Deletes an item from the tree view
		bool DeleteItem( int nItem );

		//Sets the state of the item specified by hItem
		bool SetItemState( HTREEITEM hItem , UINT nState , UINT nStateMask );
		//Retrieves the state of the item specified by hItem
		UINT GetItemState( HTREEITEM hItem , UINT nStateMask ) const;

		void GetAllEntries();
		HTREEITEM GetRootItem();
		HTREEITEM GetChildItem(HTREEITEM hItem);
		HTREEITEM GetNextItem(HTREEITEM hItem,UINT nCode);

		bool Expand(CString csParentItem);

		//Ensures that a tree view item is visible
		bool EnsureVisible( HTREEITEM hItem );

		//Retrieves the coordinates of a window's client area
		void GetClientRect( LPRECT lpRect ) const;

		//Retrieves the handle of the parent window
		CWnd * GetParent( ) const;

		//Show/Hide the window
		void ShowWindow( int nCmdShow );

		//Check if item has children
		bool ItemHasChildren( HTREEITEM hItem );

		//Returns the parent of the item
		HTREEITEM CRCSpyDetectTreeCtrl::GetParentItem( HTREEITEM hItem ) const;

		//Sorts the list
		void SortItems( int nCol );

		//Sets the redraw flag
		void SetRedraw( bool redraw );

		//Gets the tree control
		CRCNewTreeListCtrl* GetTreeControl();
		friend class CRCNewHeaderCtrl;
		void SetHeaderColumnText(int iColumn,CString csText);

		bool IsValid()
		{
			if(m_treeView && m_treeView->m_hWnd && m_treeCtrl.m_hWnd)
			{
				return true;
			}
			return false;
		}
};

#endif //SPY_DETECT_TREE_CTRL_H
