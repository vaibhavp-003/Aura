/*=============================================================================
   FILE		           : SpyDetectTreeCtrl.cpp
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


#include "stdafx.h"
#include "SpyDetectTreeCtrl.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*-------------------------------------------------------------------------------------
Function		: CSpyDetectTreeCtrl
In Parameters	: treeView	- Handle of the tree view control
Out Parameters	: -
Purpose			: Constructor for class CSpyDetectTreeCtrl
Author			: Zuber
--------------------------------------------------------------------------------------*/
CSpyDetectTreeCtrl::CSpyDetectTreeCtrl(CStatic * treeView, HMODULE hResDLL)
: m_treeCtrl(hResDLL), m_treeView(treeView), m_ctrlInit(false), m_Destructed(false)
{
	m_nDiff = 0;
}//CSpyDetectTreeCtrl

/*-------------------------------------------------------------------------------------
Function		: ~CSpyDetectTreeCtrl
In Parameters	: -
Out Parameters	: -
Purpose			: Destructor for class CSpyDetectTreeCtrl
Author			: Zuber
--------------------------------------------------------------------------------------*/
CSpyDetectTreeCtrl::~CSpyDetectTreeCtrl()
{
	m_Destructed = true;
}//~CSpyDetectTreeCtrl

/*-------------------------------------------------------------------------------------
Function		: InitializeTreeCtrl
In Parameters	: -
Out Parameters	: -
Purpose			: Initializes the tree view, creates columns, header, tree control
and sets the image list.
Author			: Zuber
--------------------------------------------------------------------------------------*/
void CSpyDetectTreeCtrl::InitializeTreeCtrl()
{
	CWnd * pWnd = m_treeView ->GetParent();

	CRect m_wndRect;
	m_treeView ->GetWindowRect(&m_wndRect);
	CRect m_headerRect;

	{
		m_headerRect.left = m_headerRect.top = -1;
		m_headerRect.right = m_wndRect.Width();

		//create header
		m_treeCtrl.m_wndHeader.Create(/*WS_CHILD | WS_VISIBLE | */HDS_BUTTONS |HDS_HORZ, m_headerRect, m_treeView, ID_TREE_LIST_HEADER);
	}

	CSize textSize;
	{
		//set header's pos, dimensions and image list
		LOGFONT logfont;

		CFont * pFont = m_treeView->GetFont();
		pFont ->GetLogFont(&logfont);

		m_treeCtrl.m_headerFont.CreateFontIndirect(&logfont);
		m_treeCtrl.m_wndHeader.SetFont(&m_treeCtrl.m_headerFont);

		CDC * pDC = m_treeCtrl.m_wndHeader.GetDC();
		pDC ->SelectObject(&m_treeCtrl.m_headerFont);
		textSize = pDC ->GetTextExtent(_T("A"));

		m_treeView ->GetParent() ->ScreenToClient(&m_wndRect);

		m_treeCtrl.m_wndHeader.SetWindowPos(&m_treeView->wndTop, 0, 0, m_headerRect.Width(), textSize.cy + 4, SWP_SHOWWINDOW);
		m_treeCtrl.m_wndHeader.ModifyStyleEx(0,WS_BORDER | WS_EX_TOPMOST);

		m_treeCtrl.m_wndHeader.UpdateWindow();
	}

	CRect m_treeRect;
	{
		//create tree control
		m_treeRect.left = 0;
		m_treeRect.top = textSize.cy + 4;
		m_treeRect.right = m_headerRect.Width() - 7;
		m_treeRect.bottom = m_wndRect.Height() - GetSystemMetrics(SM_CYHSCROLL) - 5;

		m_treeCtrl.Create(WS_CHILD | WS_VISIBLE | TVS_LINESATROOT | TVS_HASBUTTONS | TVS_TRACKSELECT, m_treeRect, m_treeView, ID_TREE_LIST_CTRL);

		//use our own bitmaps for checkboxes
		m_CheckboxImgList.Create(IDB_BITMAP_TREE_CHECKBOX, 16, 1, RGB(255, 255, 255));
		m_treeCtrl.SetImageList(&m_CheckboxImgList, TVSIL_STATE);

		m_WormImgList.Create(16, 16, ILC_COLOR16 | ILC_MASK, 8, 8);
		m_WormImgList.Add(LoadIcon(m_treeCtrl.m_hResDLL, MAKEINTRESOURCE(IDI_LIST_REGISTRY_ICON)));
		m_WormImgList.Add(LoadIcon(m_treeCtrl.m_hResDLL, MAKEINTRESOURCE(IDI_LIST_INTERNET_ICON)));
		m_WormImgList.Add(LoadIcon(m_treeCtrl.m_hResDLL, MAKEINTRESOURCE(IDI_LIST_FILE_ICON)));
		m_WormImgList.Add(LoadIcon(m_treeCtrl.m_hResDLL, MAKEINTRESOURCE(IDI_LIST_FOLDER_ICON)));
		m_WormImgList.Add(LoadIcon(m_treeCtrl.m_hResDLL, MAKEINTRESOURCE(IDI_LIST_PROCESS_ICON)));
		m_WormImgList.Add(LoadIcon(m_treeCtrl.m_hResDLL, MAKEINTRESOURCE(IDI_LIST_ROOTKIT_ICON)));
		m_WormImgList.Add(LoadIcon(m_treeCtrl.m_hResDLL, MAKEINTRESOURCE(IDI_LIST_MEMORY_ICON)));

		m_treeCtrl.SetImageList(&m_WormImgList, TVSIL_NORMAL);
	}

	// finally, create the horizontal scroll bar
	{
		CRect m_scrollRect, treeRect;
		m_treeCtrl.GetClientRect(&m_treeRect);
		m_treeView ->GetWindowRect(&treeRect);
		pWnd ->ScreenToClient(&treeRect);

		m_scrollRect.left = treeRect.left + 2;
		m_scrollRect.top = treeRect.bottom - 17;
		m_scrollRect.right = m_treeRect.Width();//- GetSystemMetrics(SM_CXVSCROLL);
		m_scrollRect.bottom = treeRect.bottom;

		m_treeCtrl.m_horScrollBar.Create(WS_CHILD | WS_VISIBLE | WS_DISABLED | SBS_HORZ | SBS_TOPALIGN, m_scrollRect, pWnd, ID_TREE_LIST_SCROLLBAR);

		SCROLLINFO si;
		si.fMask = SIF_PAGE;
		si.nPage = m_treeRect.Width();
		m_treeCtrl.m_horScrollBar.SetScrollInfo(&si, TRUE);

	}
	m_ctrlInit = true;
}//InitializeTreeCtrl

/*-------------------------------------------------------------------------------------
Function		: SetTreeView
In Parameters	: treeCtrl	- Handle of the tree control
Out Parameters	: -
Purpose			: Sets the tree view control
Author			: Zuber
--------------------------------------------------------------------------------------*/
void CSpyDetectTreeCtrl::SetTreeView(CStatic * treeView)
{
	m_treeView = treeView;
}//SetTreeView

/*-------------------------------------------------------------------------------------
Function		: InsertParent
In Parameters	: text		  - Text to insert
: threatIndex - Index of the image in the image list
Out Parameters	: Handle of the new inserted item
Purpose			: Creates a new row with text in the tree control
Author			: Zuber
--------------------------------------------------------------------------------------*/
HTREEITEM CSpyDetectTreeCtrl::InsertParent(const CString& text, int threatIndex,
										   const CString &csInfoHelp, DWORD dwSpyID, bool bUseSpyID)
{
	HTREEITEM hRoot = NULL;
	#ifndef DATABACKUP 
	  hRoot = m_treeCtrl.InsertItem(text, 10, 10, 0, 0);
	#else
		hRoot = m_treeCtrl.InsertItem(text, threatIndex, 10, 0, 0);
	#endif

	CTLItem* pTLItem = m_treeCtrl.GetTLItem(hRoot);

	pTLItem->m_Bold = 1;

	m_treeCtrl.SetItemState(hRoot, INDEXTOSTATEIMAGEMASK(2), TVIS_STATEIMAGEMASK);
	m_treeCtrl.SetItemHeight(20);
	//Rest columns are blank
	pTLItem->SetSubstring(1, _T(""));
	pTLItem->SetSubstring(2, _T(""));
	pTLItem->SetSubstring(3, _T(""));
	pTLItem->SetSubstring(COLUMN_3, csInfoHelp);

	#ifndef DATABACKUP 
	  CString threat;
	 threat.Format(_T("%d"), threatIndex);
	 pTLItem->SetSubstring(5, threat);
	#endif

//	SetScrollPos(m_treeCtrl.m_hWnd,SB_VERT,0,1);
	m_treeCtrl.SetTLItem(hRoot, pTLItem);
	pTLItem->m_dwSpyID = dwSpyID;
	pTLItem->m_bUseSpyID = bUseSpyID;
	return hRoot;
}//InsertParent

/*-------------------------------------------------------------------------------------
Function		: InsertChild
In Parameters	: parentIndex	- Index of the parent item
: threatType	- String for threat type
: threatValue	- String for threat value
: signature		- String for signature
: image			- Image index in the image list
Out Parameters	: Handle of the item inserted
Purpose			: Creates a new row after the parent with the given information
Author			: Zuber
--------------------------------------------------------------------------------------*/
HTREEITEM CSpyDetectTreeCtrl::InsertChild(HTREEITEM hRoot, const CString& threatType, const CString& threatValue,
										  const CString& signature, int image,CString csActMonDB)
{
	HTREEITEM hTmp = NULL;
	CTLItem* pTLItem = NULL;
	#ifndef DATABACKUP
	   hTmp = m_treeCtrl.InsertItem(_T(""), image, image, hRoot);
	   pTLItem = m_treeCtrl.GetTLItem(hTmp);
	   pTLItem->SetSubstring(1, threatType);
		pTLItem->SetSubstring(2, threatValue);
		pTLItem->SetSubstring(3, signature);
	#else
		hTmp = m_treeCtrl.InsertItem(threatType, image, image, hRoot);
		pTLItem = m_treeCtrl.GetTLItem(hTmp);
		pTLItem->SetSubstring(1, threatValue);
		pTLItem->SetSubstring(2, signature);
		//pTLItem->SetSubstring(3, signature);
	#endif

	
	if(csActMonDB != BLANKSTRING)
		pTLItem->SetSubstring(4, csActMonDB);

	m_treeCtrl.SetItemState(hTmp, INDEXTOSTATEIMAGEMASK(2), TVIS_STATEIMAGEMASK);

//	SetScrollPos(m_treeCtrl.m_hWnd,SB_VERT,0,1);

	m_treeCtrl.SetTLItem(hTmp, pTLItem);

	return hTmp;
}//InsertChild

/*-------------------------------------------------------------------------------------
Function		: InsertChild
In Parameters	: parentIndex	- Index of the parent item
: threatType	- String for threat type
: threatValue	- String for threat value
: signature		- String for signature
: image			- Image index in the image list
: csKey			- Registry Key
: csData		- Registry Value
: csNewFileName - New file name
Out Parameters	: Handle of the item inserted
Purpose			: Creates a new row after the parent with the given information
Author			:
--------------------------------------------------------------------------------------*/
HTREEITEM CSpyDetectTreeCtrl::InsertChild(HTREEITEM hRoot, const CString& threatType, const CString& threatValue,const CString csDate,
										  const CString& csKey,const CString& csData,const CString& csNewFileName, int image)
{
	HTREEITEM hTmp = m_treeCtrl.InsertItem(_T(""), image, image, hRoot);
	m_treeCtrl.SetItemText(hTmp, 1, threatType);
	m_treeCtrl.SetItemText(hTmp, 2, threatValue);
	m_treeCtrl.SetItemText(hTmp, 3, csDate);
	m_treeCtrl.SetItemText(hTmp, 4, csKey);
	m_treeCtrl.SetItemText(hTmp, 5, csData);
	m_treeCtrl.SetItemText(hTmp, 6, csNewFileName);
	m_treeCtrl.SetItemState(hTmp, INDEXTOSTATEIMAGEMASK(2), TVIS_STATEIMAGEMASK);
	return hTmp;
}//InsertChild

/*-------------------------------------------------------------------------------------
Function		: OnNotify
In Parameters	: wParam	- Identifies the control
: lParam	- Pointer to a notification message (NMHDR)structure
: pResult	- Not used
Out Parameters	: -
Purpose			: Invoked from main OnNotify handler.Manages sorting and movement
of header
Author			: Zuber
--------------------------------------------------------------------------------------*/
void CSpyDetectTreeCtrl::OnNotify(WPARAM wParam, LPARAM lParam, LRESULT * pResult)
{
	if(m_Destructed)
	{
		return;
	}

	HD_NOTIFY * pHDN =(HD_NOTIFY *)lParam;

	if((wParam == ID_TREE_LIST_HEADER) &&(pHDN ->hdr.code == HDN_ITEMCLICK))
	{
		int nCol = pHDN ->iItem;
		if(nCol != 0)
		{
			m_treeCtrl.GetParent() ->SendMessage(WM_NOTIFY, wParam, lParam);
		}

		BOOL bAscending = FALSE;

		if(m_treeCtrl.m_wndHeader.GetItemImage(nCol) == -1)
		{
			bAscending = TRUE;
		}
		else
			if(m_treeCtrl.m_wndHeader.GetItemImage(nCol) == 1)
			{
				bAscending = TRUE;
			}

			for(int i = 0; i < m_treeCtrl.GetColumnsNum(); i++)
			{
				m_treeCtrl.m_wndHeader.SetItemImage(i, -1);
			}

			if(bAscending)
			{
				m_treeCtrl.m_wndHeader.SetItemImage(nCol, 0);
			}
			else
			{
				m_treeCtrl.m_wndHeader.SetItemImage(nCol, 1);
			}

			m_treeCtrl.SortItems(nCol, bAscending, NULL);

			m_treeCtrl.UpdateWindow();
	}
	else
		if((wParam == ID_TREE_LIST_HEADER) &&(pHDN ->hdr.code == HDN_ITEMCHANGED))
		{
			int m_nPrevColumnsWidth = m_treeCtrl.GetColumnsWidth();
			m_treeCtrl.RecalcColumnsWidth();
			ResetScrollBar();

			// in case we were at the scroll bar's end,
			// and some column's width was reduced,
			// update header's position (move to the right).
			CRect m_treeRect;
			m_treeCtrl.GetClientRect(&m_treeRect);

			CRect m_headerRect;
			m_treeCtrl.m_wndHeader.GetClientRect(&m_headerRect);

			if((m_nPrevColumnsWidth > m_treeCtrl.GetColumnsWidth()) &&
				(m_treeRect.Width()< m_treeCtrl.GetColumnsWidth()))
			{
				m_treeCtrl.m_nOffset = -m_treeCtrl.GetColumnsWidth() + m_treeRect.Width();
			}

			m_treeCtrl.Invalidate();
		}
		else
		{
			m_treeCtrl.GetParent() ->SendMessage(WM_NOTIFY, wParam, lParam);
		}
}//OnNotify

/*-------------------------------------------------------------------------------------
Function		: OnHScroll
In Parameters	: nSBCode	- Indicates the scrolling request of the user
: nPos		- Specifies the scroll-box position
: pScrollBar- Pointer to the scroll bar control
Out Parameters	: -
Purpose			: Invoked from main OnHScroll handler.Handles the scrolling of
horizontal scroll bar
Author			: Zuber
--------------------------------------------------------------------------------------*/
void CSpyDetectTreeCtrl::OnHScroll(UINT nSBCode, UINT nPos, CScrollBar * pScrollBar)
{
	CRect m_treeRect;
	m_treeCtrl.GetClientRect(&m_treeRect);

	if(pScrollBar == &m_treeCtrl.m_horScrollBar)
	{
		int m_nCurPos = m_treeCtrl.m_horScrollBar.GetScrollPos();
		int m_nPrevPos = m_nCurPos;
		switch(nSBCode)
		{
		case SB_LEFT:
			m_nCurPos = 0;
			break;

		case SB_RIGHT:
			m_nCurPos = m_treeCtrl.m_horScrollBar.GetScrollLimit() - 1;
			break;

		case SB_LINELEFT:
			m_nCurPos = max(m_nCurPos - 6, 0);
			break;

		case SB_LINERIGHT:
			m_nCurPos = min(m_nCurPos + 6, m_treeCtrl.m_horScrollBar.GetScrollLimit() - 1);
			break;

		case SB_PAGELEFT:
			m_nCurPos = max(m_nCurPos - m_treeRect.Width(), 0);
			break;

		case SB_PAGERIGHT:
			m_nCurPos = min(m_nCurPos + m_treeRect.Width(), m_treeCtrl.m_horScrollBar.GetScrollLimit() - 1);
			break;

		case SB_THUMBTRACK:
		case SB_THUMBPOSITION:
			if(nPos == 0)
			{
				m_nCurPos = 0;
			}
			else
			{
				int width =((nPos / 6) + 1)* 6;
				m_nCurPos = min(width, m_treeCtrl.m_horScrollBar.GetScrollLimit() - 1);
				break;
			}
		}

		m_treeCtrl.m_horScrollBar.SetScrollPos(m_nCurPos);
		m_treeCtrl.m_nOffset = -m_nCurPos;

		// smoothly scroll the tree control
		{
			CRect m_scrollRect;
			m_treeCtrl.GetClientRect(&m_scrollRect);
			m_treeCtrl.ScrollWindow(m_nPrevPos - m_nCurPos, 0, &m_scrollRect, &m_scrollRect);
		}

		CRect m_headerRect, m_wndRect;
		m_treeCtrl.m_wndHeader.GetWindowRect(&m_headerRect);
		m_treeView ->GetWindowRect(&m_wndRect);
		m_treeView ->GetParent() ->ScreenToClient(&m_wndRect);
		int width =((m_treeCtrl.GetColumnsWidth()/ m_treeRect.Width()) + 1)* m_treeRect.Width();
		m_treeCtrl.m_wndHeader.SetWindowPos(&CWnd::wndTop, m_treeCtrl.m_nOffset, 0, max(width, m_wndRect.Width()), m_headerRect.Height(), SWP_SHOWWINDOW);
		SetRedraw(true,true);
	}
}//OnHScroll

/*-------------------------------------------------------------------------------------
Function		: ResetScrollBar
In Parameters	: -
Out Parameters	: -
Purpose			: Sets the horizontal scroll bar to correct position
Author			: Zuber
--------------------------------------------------------------------------------------*/
void CSpyDetectTreeCtrl::ResetScrollBar()
{
	// resetting the horizontal scroll bar

	int m_nTotalWidth = 0, m_nPageWidth;

	CRect m_treeRect;
	m_treeCtrl.GetClientRect(&m_treeRect);
	CRect rect;
	m_treeCtrl.GetWindowRect(&rect);
	CRect m_wndRect;
	m_treeView ->GetWindowRect(&m_wndRect);
	m_treeView ->GetParent() ->ScreenToClient(&m_wndRect);

	CRect m_headerRect;
	m_treeCtrl.m_wndHeader.GetClientRect(&m_headerRect);

	CRect m_barRect;
	m_treeCtrl.m_horScrollBar.GetClientRect(&m_barRect);

	m_nPageWidth = rect.Width(); // m_treeRect.Width();

	m_nTotalWidth = m_treeCtrl.GetColumnsWidth();

	if(m_nTotalWidth > m_nPageWidth)
	{
		// show the scroll bar and adjust it's size
		{
			if(m_treeCtrl.IsWindowVisible())
			{
				m_treeCtrl.m_horScrollBar.EnableWindow(TRUE);

				m_treeCtrl.m_horScrollBar.ShowWindow(SW_SHOW);
			}

			// the tree becomes smaller
			CRect TreeRect;
			m_treeCtrl.GetWindowRect(&TreeRect);
			m_treeView ->ScreenToClient(&TreeRect);
			if(TreeRect.Width() != m_wndRect.Width() || TreeRect.Height() != m_wndRect.Height() - m_barRect.Height() - m_headerRect.Height())
			{
				m_treeCtrl.MoveWindow(0, m_headerRect.bottom, m_wndRect.Width() - 6, m_wndRect.Height() - m_headerRect.Height() - GetSystemMetrics(SM_CYHSCROLL) - 3);
			}

			m_treeCtrl.GetWindowRect(&TreeRect);
			m_treeView ->ScreenToClient(&TreeRect);
			// check if vertical scroll bar isn't visible
			if(!VerticalScrollVisible())
			{
				m_treeCtrl.m_horScrollBar.MoveWindow(m_wndRect.left + 2, m_wndRect.top + m_wndRect.Height() -  GetSystemMetrics(SM_CYHSCROLL)/*+ m_nDiff*/, m_treeRect.Width() - 4, 17);
			}
			else
			{
				m_treeCtrl.m_horScrollBar.MoveWindow(m_wndRect.left + 2,m_wndRect.top + m_wndRect.Height() - GetSystemMetrics(SM_CYHSCROLL)/*+ m_nDiff*/, m_treeRect.Width() - 4, 17);
			}
		}

		SCROLLINFO si;
		si.fMask = SIF_PAGE | SIF_RANGE;
		si.nPage = m_treeRect.Width();
		si.nMin = 0;
		si.nMax = m_nTotalWidth;
		m_treeCtrl.m_horScrollBar.SetScrollInfo(&si, FALSE);

		// recalculate the offset
		{
			CRect m_wndHeaderRect;
			m_treeCtrl.m_wndHeader.GetWindowRect(&m_wndHeaderRect);
			m_treeView ->ScreenToClient(&m_wndHeaderRect);

			m_treeCtrl.m_nOffset = m_wndHeaderRect.left;
			m_treeCtrl.m_horScrollBar.SetScrollPos(- m_treeCtrl.m_nOffset);
		}
	}
	else
	{
		m_treeCtrl.m_horScrollBar.EnableWindow(FALSE);

		// we no longer need it, so hide it!
		{
			// the tree takes scroll's place
			CRect TreeRect;
			m_treeCtrl.GetClientRect(&TreeRect);
			m_treeCtrl.m_horScrollBar.ShowWindow(SW_HIDE);
		}

		m_treeCtrl.m_horScrollBar.SetScrollRange(0, 0);

		// set scroll offset to zero
		{
			m_treeCtrl.m_nOffset = 0;
			m_treeCtrl.m_wndHeader.GetWindowRect(&m_headerRect);
			m_treeView ->GetWindowRect(&m_wndRect);
			m_treeView ->GetParent() ->ScreenToClient(&m_wndRect);
			int width =((m_treeCtrl.GetColumnsWidth()/ m_wndRect.Width()) + 1)* m_wndRect.Width();
			m_treeCtrl.m_wndHeader.SetWindowPos(&CWnd::wndTop, m_treeCtrl.m_nOffset, 0, max(width, m_wndRect.Width()), m_headerRect.Height(), SWP_SHOWWINDOW);
		}
	}
}//ResetScrollBar

/*-------------------------------------------------------------------------------------
Function		: VerticalScrollVisible
In Parameters	: -
Out Parameters	: TRUE, if vertical scroll bar visible
Purpose			: Checks if the vertical scroll bar is visible
Author			: Zuber
--------------------------------------------------------------------------------------*/
BOOL CSpyDetectTreeCtrl::VerticalScrollVisible()
{
	int sMin, sMax;
	m_treeCtrl.GetScrollRange(SB_VERT, &sMin, &sMax);

	return sMax != 0;
}//VerticalScrollVisible

/*-------------------------------------------------------------------------------------
Function		: OnSize
In Parameters	: -
Out Parameters	: -
Purpose			: Invoked from main OnSize handler.Resizes the controls of the
tree view
Author			: Zuber
--------------------------------------------------------------------------------------*/
void CSpyDetectTreeCtrl::OnSize()
{
	if(!m_ctrlInit)
	{
		return;
	}
	// resize all the controls
	{
		CRect m_wndRect;
		m_treeView ->GetWindowRect(&m_wndRect);
		m_treeView ->GetParent() ->ScreenToClient(&m_wndRect);

		CRect m_headerRect;
		m_treeCtrl.m_wndHeader.GetWindowRect(&m_headerRect);
		m_treeView ->ScreenToClient(&m_headerRect);

		int sMin, sMax;
		m_treeCtrl.m_horScrollBar.GetScrollRange(&sMin, &sMax);

		if(m_treeView ->GetParent() ->IsZoomed() || sMax == 0)
		{
			m_treeCtrl.MoveWindow(0, m_headerRect.Height(), m_wndRect.Width() - 4, m_wndRect.Height() - GetSystemMetrics(SM_CYHSCROLL) - 5);
		}
		else
		{
			m_treeCtrl.MoveWindow(0, m_headerRect.Height(), m_wndRect.Width() - 4, m_wndRect.Height() - GetSystemMetrics(SM_CYHSCROLL));
		}
		ResetScrollBar();
		m_treeCtrl.m_horScrollBar.Invalidate(FALSE);
	}
}//OnSize

/*-------------------------------------------------------------------------------------
Function		: FindParentItem
In Parameters	: spyName - Spyware name to check, if its already present
Out Parameters	: Handle of the item, if found
Purpose			: Checks if the spyware name is already present in the tree view
Author			: Zuber
--------------------------------------------------------------------------------------*/
HTREEITEM CSpyDetectTreeCtrl::FindParentItem(const CString& spyName)
{
	return m_treeCtrl.FindParentItem(spyName);
}//FindParentItem

/*-------------------------------------------------------------------------------------
Function		: GetChildCount
In Parameters	: hItem - Item whose children count is required
Out Parameters	: Total number of children
Purpose			: Returns the number of children for the hItem if it is not NULL,
otherwise the total number of children in the tree view
Author			: Zuber
--------------------------------------------------------------------------------------*/
int CSpyDetectTreeCtrl::GetChildCount(HTREEITEM hItem)
{
	return m_treeCtrl.GetChildCount(hItem);
}//GetChildCount

/*-------------------------------------------------------------------------------------
Function		: InsertColumn
In Parameters	: nCol				- Column number
: lpszColumnHeading	- Text for the column
: nFormat			- Format for the column (LVCFMT_LEFT,
LVCFMT_CENTER, LVCFMT_RIGHT)
: nWidth			- Width for column
: nSubItem			- Not used
Out Parameters	: Index of new column if successful
Purpose			: Inserts a new column in the header of tree view
Author			: Zuber
--------------------------------------------------------------------------------------*/
int CSpyDetectTreeCtrl::InsertColumn(int nCol, LPCTSTR lpszColumnHeading, int nFormat,
									 int nWidth, int nSubItem)
{
	return m_treeCtrl.InsertColumn(nCol, lpszColumnHeading, nFormat, nWidth, nSubItem);
}//InsertColumn

/*-------------------------------------------------------------------------------------
Function		: DeleteAllItems
In Parameters	: -
Out Parameters	: Nonzero if successful
Purpose			: Deletes all items in the tree view
Author			: Zuber
--------------------------------------------------------------------------------------*/
bool CSpyDetectTreeCtrl::DeleteAllItems()
{
	UpdatePaintTree(false);
	bool bRet = (FALSE == m_treeCtrl.DeleteAllItems())? false:true;
	UpdatePaintTree(true);
	return bRet;
}//DeleteAllItems

/*-------------------------------------------------------------------------------------
Function		: GetItemCount
In Parameters	: -
Out Parameters	: Total number nodes in the tree view
Purpose			: Returns the total number nodes in the tree view
Author			: Zuber
--------------------------------------------------------------------------------------*/
int CSpyDetectTreeCtrl::GetItemCount()
{
	return m_treeCtrl.GetItemCount();
}//GetItemCount

/*-------------------------------------------------------------------------------------
Function		: GetTreeItem
In Parameters	: nItem - Index of the item in tree view
Out Parameters	: Handle of the item in the tree view
Purpose			: Returns the item for the given index
Author			: Zuber
--------------------------------------------------------------------------------------*/
HTREEITEM CSpyDetectTreeCtrl::GetTreeItem(int nItem)
{
	return m_treeCtrl.GetTreeItem(nItem);
}//GetTreeItem

/*--------------------------------------------------------------------------------------
Function       : GetSelectedItemCount
In Parameters  :
Out Parameters : int
Description    : Gets the selected Item count from the TreeCtrl
Author         : Zuber
--------------------------------------------------------------------------------------*/
int CSpyDetectTreeCtrl::GetSelectedItemCount()
{
	return m_treeCtrl.GetSelectedItemCount();
}
/*-------------------------------------------------------------------------------------
Function		: GetCheck
In Parameters	: item - Specifies the handle of the item in the tree view
Out Parameters	: True if checked
Purpose			: Retrieves an item's check state
Author			: Zuber
--------------------------------------------------------------------------------------*/
bool CSpyDetectTreeCtrl::GetCheck(HTREEITEM hItem)
{
	return m_treeCtrl.GetCheck(hItem);
}//GetCheck

/*--------------------------------------------------------------------------------------
Function       : GetRootItem
In Parameters  :
Out Parameters : HTREEITEM
Description    : Return the handle to the Root
Author         :
--------------------------------------------------------------------------------------*/
HTREEITEM CSpyDetectTreeCtrl::GetRootItem()
{
	return m_treeCtrl.GetRootItem();
}

/*--------------------------------------------------------------------------------------
Function       : GetChildItem
In Parameters  : HTREEITEM hItem,
Out Parameters : HTREEITEM
Description    : Returns the handle to the child Tree Item handle
Author         : Darshit Kasliwal
--------------------------------------------------------------------------------------*/
HTREEITEM CSpyDetectTreeCtrl::GetChildItem(HTREEITEM hItem)
{
	return m_treeCtrl.GetChildItem(hItem);
}

/*--------------------------------------------------------------------------------------
Function       : GetNextItem
In Parameters  : HTREEITEM hItem, UINT nCode,
Out Parameters : HTREEITEM
Description    : Wrapper over the TreeCtrl GetNextItem
Author         :
--------------------------------------------------------------------------------------*/
HTREEITEM CSpyDetectTreeCtrl::GetNextItem(HTREEITEM hItem,UINT nCode)
{
	return m_treeCtrl.GetNextItem(hItem, nCode);
}

/*--------------------------------------------------------------------------------------
Function       : GetStructure
In Parameters  : HTREEITEM hItem,
Out Parameters : MAX_PIPE_DATA_REG*
Description    : Wrapper over the TreeCtrl GetItemData and returns the pointer to the
MAX_PIPE_DATA_REG structure which is stored in the Tree Ctrl Item
Author         :
--------------------------------------------------------------------------------------*/
MAX_PIPE_DATA_REG* CSpyDetectTreeCtrl::GetStructure(HTREEITEM hItem)
{
	return m_treeCtrl.GetItemStructure(hItem);
}

bool CSpyDetectTreeCtrl::GetStructure(HTREEITEM hItem, LPSPY_ENTRY_DETAIL &lpSpyEntry)
{
	return m_treeCtrl.GetItemStructure(hItem, lpSpyEntry);
}

/*--------------------------------------------------------------------------------------
Function       : AddStructure
In Parameters  : HTREEITEM hItem, MAX_PIPE_DATA& sMaxPipeData,
Out Parameters : void
Description    : Adds the structure at the List Index in the CTLItem object
Author         :
--------------------------------------------------------------------------------------*/
void CSpyDetectTreeCtrl::AddStructure(HTREEITEM hItem, MAX_PIPE_DATA& sMaxPipeData)
{
	m_treeCtrl.SetItemStructure(hItem, sMaxPipeData);
}

/*--------------------------------------------------------------------------------------
Function       : AddStructure
In Parameters  : HTREEITEM hItem, MAX_PIPE_DATA_REG& sMaxPipeDataReg,
Out Parameters : void
Description    : Adds the structure at the List Index in the CTLItem object
Author         :
--------------------------------------------------------------------------------------*/
void CSpyDetectTreeCtrl::AddStructure(HTREEITEM hItem, MAX_PIPE_DATA_REG& sMaxPipeDataReg)
{
	m_treeCtrl.SetItemStructure(hItem, sMaxPipeDataReg);
}

/*--------------------------------------------------------------------------------------
Function       : AddStructure
In Parameters  : HTREEITEM hItem, MAX_PIPE_DATA_REG& sMaxPipeDataReg,
Out Parameters : void
Description    : Adds the structure at the List Index in the CTLItem object
Author         :
--------------------------------------------------------------------------------------*/
void CSpyDetectTreeCtrl::AddStructure(HTREEITEM hItem, LPSPY_ENTRY_DETAIL pSpyEntryDetails)
{
	m_treeCtrl.SetItemStructure(hItem, pSpyEntryDetails);
}

/*--------------------------------------------------------------------------------------
Function       : AddBackupFileName
In Parameters  : HTREEITEM hItem, LPTSTR lpszBackup,
Out Parameters : void
Description    : Adds the backup file name to the CTLItem object
Author         :
--------------------------------------------------------------------------------------*/
void CSpyDetectTreeCtrl::AddBackupFileName(HTREEITEM hItem, LPTSTR lpszBackup)
{
	m_treeCtrl.SetItemBackupFileName(hItem, lpszBackup);
}

/*--------------------------------------------------------------------------------------
Function       : AddDateTime
In Parameters  : HTREEITEM hItem, UINT64 u64DateTime,
Out Parameters : void
Description    : Wrapper over SetItemData function
Author         :
--------------------------------------------------------------------------------------*/
void CSpyDetectTreeCtrl::AddDateTime(HTREEITEM hItem, UINT64 u64DateTime)
{
	m_treeCtrl.SetItemDateTime(hItem, u64DateTime);
}

/*--------------------------------------------------------------------------------------
Function       : AddIndex
In Parameters  : HTREEITEM hItem, long lIndex,
Out Parameters : void
Description    : Wrapper over SetItemData for  adding Index
Author         :
--------------------------------------------------------------------------------------*/
void CSpyDetectTreeCtrl::AddIndex(HTREEITEM hItem, long lIndex, int iRemoveDBType)
{
	m_treeCtrl.SetItemIndex(hItem, lIndex, iRemoveDBType);
}

/*--------------------------------------------------------------------------------------
Function       : GetIndex
In Parameters  : HTREEITEM hItem,
Out Parameters : long
Description    : Wrapper over GetItemData for getting index from Handle
Author         :
--------------------------------------------------------------------------------------*/
long CSpyDetectTreeCtrl::GetIndex(HTREEITEM hItem, int &iRemoveDBType)
{
	return m_treeCtrl.GetItemIndex(hItem, iRemoveDBType);
}

/*--------------------------------------------------------------------------------------
Function       : GetBackupFileName
In Parameters  : HTREEITEM hItem,
Out Parameters : LPTSTR
Description    : Retrieves the backupfile name
Author         :
--------------------------------------------------------------------------------------*/
LPTSTR CSpyDetectTreeCtrl::GetBackupFileName(HTREEITEM hItem)
{
	return m_treeCtrl.GetItemBackupFileName(hItem);
}

/*--------------------------------------------------------------------------------------
Function       : GetDateTime
In Parameters  : HTREEITEM hItem,
Out Parameters : UINT64
Description    : Retrieves Date Time
Author         :
--------------------------------------------------------------------------------------*/
UINT64 CSpyDetectTreeCtrl::GetDateTime(HTREEITEM hItem)
{
	return m_treeCtrl.GetItemDateTime(hItem);
}

/*-------------------------------------------------------------------------------------
Function		: SetCheck
In Parameters	: hItem		- Specifies the handle of the item to receive the check
state change
: fCheck	- Indicates whether the item is to be checked or unchecked
Out Parameters	: Nonzero if successful
Purpose			: Sets the item's check state
Author			: Zuber
--------------------------------------------------------------------------------------*/
bool CSpyDetectTreeCtrl::SetCheck(HTREEITEM hItem, bool fCheck)
{
	return m_treeCtrl.SetCheck(hItem, fCheck);
}//SetCheck

/*-------------------------------------------------------------------------------------
Function		: SetCheckAll
In Parameters	: fCheck - Indicates whether the item is to be checked or unchecked
: hItem  - Handle of the item to receive the check state change.
If item is NULL (un)checks all the tree view items.If
item is not NULL, (un)checks the item and its children
if any.
Out Parameters	: true
Purpose			: Sets the item's check state
Author			: Zuber
--------------------------------------------------------------------------------------*/
bool CSpyDetectTreeCtrl::SetCheckAll(bool fCheck, HTREEITEM hItem)
{
	return m_treeCtrl.SetCheckAll(fCheck, hItem);
}//SetCheckAll

/*-------------------------------------------------------------------------------------
Function		: GetItemText
In Parameters	: hItem		- Specifies the handle of the item in the tree
: nSubItem	- Column number
Out Parameters	: Respective item text
Purpose			: Returns the text from the given column for the respective hItem
Author			: Zuber
--------------------------------------------------------------------------------------*/
CString CSpyDetectTreeCtrl::GetItemText(HTREEITEM hItem, int nSubItem)
{
	return m_treeCtrl.GetItemText(hItem, nSubItem);
}//GetItemText

/*-------------------------------------------------------------------------------------
Function		: GetItemText
In Parameters	: nItem		- Index of the item in the tree
: nSubItem	- Column number
Out Parameters	: Respective item text
Purpose			: Returns the text from the column for the item at the given index
Author			: Zuber
--------------------------------------------------------------------------------------*/
CString CSpyDetectTreeCtrl::GetItemText(int nItem, int nSubItem)
{
	return m_treeCtrl.GetItemText(nItem, nSubItem);
}//GetItemText

/*-------------------------------------------------------------------------------------
Function		: SetItemText
In Parameters	: hItem		- Specifies the handle of the item in the tree
: nCol		- Column number
: lpszItem	- Text to set for the item
Out Parameters	: Nonzero if it is successful
Purpose			: Sets the text in the column for the given item
Author			: Zuber
--------------------------------------------------------------------------------------*/
bool CSpyDetectTreeCtrl::SetItemText(HTREEITEM hItem, int nCol, LPCTSTR lpszItem)
{
	bool bRet = (FALSE == m_treeCtrl.SetItemText(hItem, nCol, lpszItem))? false:true;
	return bRet;
}//SetItemText

/*-------------------------------------------------------------------------------------
Function		: DeleteItem
In Parameters	: hItem	- Specifies the handle of the item in the tree to delete
Out Parameters	: Nonzero if it is successful
Purpose			: Deletes an item from the tree view
Author			: Zuber
--------------------------------------------------------------------------------------*/
bool CSpyDetectTreeCtrl::DeleteItem(HTREEITEM hItem)
{
	bool bRet = (FALSE == m_treeCtrl.DeleteItem(hItem))? false:true;
	return bRet;
}//DeleteItem

/*-------------------------------------------------------------------------------------
Function		: DeleteItem
In Parameters	: nItem	- Index of the item in the tree to delete
Out Parameters	: Nonzero if it is successful
Purpose			: Deletes an item from the tree view
Author			: Zuber
--------------------------------------------------------------------------------------*/
bool CSpyDetectTreeCtrl::DeleteItem(int nItem)
{
	bool bRet = (FALSE == m_treeCtrl.DeleteItem(nItem))? false:true;
	return bRet;
}//DeleteItem

/*-------------------------------------------------------------------------------------
Function		: SetItemState
In Parameters	: hItem		- Specifies the handle of the item whose state is to be set
: nState	- Specifies new states for the item
: nStateMask- Specifies which states are to be changed
Out Parameters	: Nonzero if it is successful
Purpose			: Sets the state of the item specified by hItem
Author			: Zuber
--------------------------------------------------------------------------------------*/
bool CSpyDetectTreeCtrl::SetItemState(HTREEITEM hItem, UINT nState, UINT nStateMask)
{
	bool bRet = (FALSE == m_treeCtrl.SetItemState(hItem, nState, nStateMask))? false:true;
	return bRet;
}//SetItemState

/*-------------------------------------------------------------------------------------
Function		: GetItemState
In Parameters	: hItem		- Specifies the handle of the item whose state is required
: nStateMask- Indicates which states are to be retrieved
Out Parameters	: State of the item
Purpose			: Retrieves the state of the item specified by hItem
Author			: Zuber
--------------------------------------------------------------------------------------*/
UINT CSpyDetectTreeCtrl::GetItemState(HTREEITEM hItem, UINT nStateMask)const
{
	return m_treeCtrl.GetItemState(hItem, nStateMask);
}//GetItemState

/*-------------------------------------------------------------------------------------
Function		: EnsureVisible
In Parameters	: hItem	- Specifies the handle of the tree item being made visible
Out Parameters	: Returns true if the system scrolled the items in the tree-view
control to ensure that the specified item is visible, else false
Purpose			: Ensures that a tree view item is visible
Author			: Zuber
--------------------------------------------------------------------------------------*/
bool CSpyDetectTreeCtrl::EnsureVisible(HTREEITEM hItem)
{
	bool bRet = (FALSE == m_treeCtrl.EnsureVisible(hItem))? false:true;
	return bRet;
}//EnsureVisible

/*-------------------------------------------------------------------------------------
Function		: GetClientRect
In Parameters	: lpRect - CRect object to receive the co-ordinates
Out Parameters	: -
Purpose			: Retrieves the coordinates of a window's client area
Author			: Zuber
--------------------------------------------------------------------------------------*/
void CSpyDetectTreeCtrl::GetClientRect(LPRECT lpRect)const
{
	m_treeCtrl.GetClientRect(lpRect);
}//GetClientRect

/*-------------------------------------------------------------------------------------
Function		: GetParent
In Parameters	: -
Out Parameters	: Handle of the parent window
Purpose			: Retrieves the handle of the parent window
Author			: Zuber
--------------------------------------------------------------------------------------*/
CWnd * CSpyDetectTreeCtrl::GetParent()const
{
	return m_treeCtrl.GetParent();
}//GetParent

/*-------------------------------------------------------------------------------------
Function		: ShowWindow
In Parameters	: nCmdShow - Specifies how the window is to be shown
Out Parameters	: -
Purpose			: Show/Hide the window
Author			: Zuber
--------------------------------------------------------------------------------------*/
void CSpyDetectTreeCtrl::ShowWindow(int nCmdShow)
{
	if(nCmdShow)
	{
		m_treeCtrl.SetWindowPos(0, 0, 0, 0, 0, SWP_NOSIZE | SWP_NOMOVE | SWP_NOZORDER | SWP_SHOWWINDOW);
		m_treeCtrl.m_horScrollBar.SetWindowPos(0, 0, 0, 0, 0, SWP_NOSIZE | SWP_NOMOVE | SWP_NOZORDER | SWP_SHOWWINDOW);
	}
	else
	{
		m_treeCtrl.SetWindowPos(0, 0, 0, 0, 0, SWP_NOSIZE | SWP_NOMOVE | SWP_NOZORDER | SWP_HIDEWINDOW);
		m_treeCtrl.m_horScrollBar.SetWindowPos(0, 0, 0, 0, 0, SWP_NOSIZE | SWP_NOMOVE | SWP_NOZORDER | SWP_HIDEWINDOW);
	}
}//ShowWindow

/*-------------------------------------------------------------------------------------
Function		: IsWindowVisible
In Parameters	: -
Out Parameters	: - true if visible else false
Purpose			: return the visible state of the window
Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
BOOL CSpyDetectTreeCtrl::IsWindowVisible()
{
	return m_treeCtrl.IsWindowVisible();
}

/*-------------------------------------------------------------------------------------
Function		: ItemHasChildren
In Parameters	: hItem - Specifies the handle of the item which is to be checked
Out Parameters	: true, if item has children
Purpose			: Checks if the item has children
Author			: Zuber
--------------------------------------------------------------------------------------*/
bool CSpyDetectTreeCtrl::ItemHasChildren(HTREEITEM hItem)
{
	if(hItem == NULL)
	{
		return false;
	}
	bool bRet = (FALSE == m_treeCtrl.ItemHasChildren(hItem))? false:true;
	return bRet;
}//ItemHasChildren

/*-------------------------------------------------------------------------------------
Function		: GetParentItem
In Parameters	: Handle of the item whose parent is required
Out Parameters	: Parent item
Purpose			: Returns the parent of the item
Author			: Zuber
--------------------------------------------------------------------------------------*/
HTREEITEM CSpyDetectTreeCtrl::GetParentItem(HTREEITEM hItem)const
{
	if(hItem == NULL)
	{
		return NULL;
	}

	return m_treeCtrl.GetParentItem(hItem);
}//GetParentCount

/*-------------------------------------------------------------------------------------
Function		: SortItems
In Parameters	: int nCol
Out Parameters	: void
Purpose			: Sorts the list
Author			: Zuber
--------------------------------------------------------------------------------------*/
void CSpyDetectTreeCtrl::SortItems(int nCol)
{
	m_treeCtrl.SortItems(nCol);
}//SortItems

/*-------------------------------------------------------------------------------------
Function		: SetRedraw
In Parameters	: bool redraw
Out Parameters	: void
Purpose			: Returns the parent of the item
Author			: Zuber
--------------------------------------------------------------------------------------*/
void CSpyDetectTreeCtrl::SetRedraw(bool redraw, bool bUpdate)
{
	m_treeCtrl.SetRedraw(redraw);
	if(bUpdate)
	{
		if(false == redraw)
		{
			m_treeCtrl.m_bRedrawOnInsert = false;
		}
		else
		{
			m_treeCtrl.Invalidate();
			m_treeCtrl.UpdateWindow();
			m_treeCtrl.SetRedrawOnInsert(FALSE);
		}
	}
}//SetRedraw

/*-------------------------------------------------------------------------------------
Function		: Expand
In Parameters	: CString csParentItem
Out Parameters	: bool
Purpose			: Sets the redraw flag
Author			: Zuber
--------------------------------------------------------------------------------------*/
bool CSpyDetectTreeCtrl::Expand(CString csParentItem)
{
	return m_treeCtrl.Expand(csParentItem);
}

/*-------------------------------------------------------------------------------------
Function		: SetLink
In Parameters	: bool bFlag
Out Parameters	: void
Purpose			: To Set link
Author			: Zuber
--------------------------------------------------------------------------------------*/
void CSpyDetectTreeCtrl::SetLink(bool bFlag)
{
	m_treeCtrl.m_bShowLink = bFlag;
}

/*-------------------------------------------------------------------------------------
Function		: SetLinkCaption
In Parameters	: const CString &csCaption
Out Parameters	: void
Purpose			: To Set link
Author			: Dipali
--------------------------------------------------------------------------------------*/
void CSpyDetectTreeCtrl::SetLinkCaption(const CString &csCaption)
{
	m_treeCtrl.m_csLinkText = csCaption;
}
/*-------------------------------------------------------------------------------------
Function		: SetItemColor
In Parameters	: HTREEITEM hItem - item
COLORREF m_newColor - color
BOOL m_bInvalidate - invalidate (default true)
Out Parameters	: BOOL
Purpose			: Set color to item
Author			: Dipali
--------------------------------------------------------------------------------------*/
BOOL CSpyDetectTreeCtrl::SetItemColor(HTREEITEM hItem, COLORREF m_newColor, BOOL m_bInvalidate)
{
	return m_treeCtrl.SetItemColor(hItem,m_newColor,m_bInvalidate);
}

/*-------------------------------------------------------------------------------------
Function		: EnableHelp
In Parameters	: bool bEnable: enable or disable help
Out Parameters	:
Purpose			: Sets the tree control help enable or disable.
Author			: Avinash Bhardwaj
--------------------------------------------------------------------------------------*/
void CSpyDetectTreeCtrl::EnableHelp(bool bEnable)
{
	m_treeCtrl.m_bShowHelp = bEnable;
}

/*-------------------------------------------------------------------------------------
Function		: SetHeaderColumnText
In Parameters	: iColumn : Specifies the column number whose text is to be changed.
: CString : text which will be set
Out Parameters	: bool : true if function is successful
Purpose			: changes the text of the column header.
Author			: Ashwinee Jagtap
--------------------------------------------------------------------------------------*/
void CSpyDetectTreeCtrl::SetHeaderColumnText(int iColumn,CString csText)
{
	try
	{
		CHeaderCtrl *pHeaderCtrl = (CHeaderCtrl*)&(m_treeCtrl.m_wndHeader);
		if(pHeaderCtrl)
		{
			HDITEM hdi;
			hdi.mask = HDI_TEXT;
			hdi.pszText = (LPTSTR)(LPCTSTR)csText;
			pHeaderCtrl->SetItem(iColumn, &hdi);
		}
	}
	catch(...)
	{
	}
}

int CSpyDetectTreeCtrl::GetHeaderColumnNo(POINT pt)
{
	int iColumn = -1;
	CRect rc;
	m_treeCtrl.m_wndHeader.GetWindowRect(rc);

	if( (pt.x >= rc.left) && (pt.x <= rc.right) && 
		(pt.y >= rc.top) && (pt.y <= rc.bottom) )
	{
		int iTotalColumns = m_treeCtrl.m_wndHeader.GetItemCount();
		int iColWidth = rc.left;
		for(int iCount=0 ; iCount<iTotalColumns ; iCount++)
		{
			iColWidth += m_treeCtrl.GetColumnWidth(iCount);
			if(iColWidth >= pt.x)
			{
				iColumn = iCount;
				break;
			}
		}
	}
	
	return iColumn;
}

void CSpyDetectTreeCtrl::ExpandColumntoFullLength(int iColumn)
{
	CHeaderCtrl &objHeaderCtrl = m_treeCtrl.m_wndHeader;
	int iTotalColumns = objHeaderCtrl.GetItemCount();
	if( (iColumn < 0) || (iColumn >= iTotalColumns) )
		return;

	CWnd* pWnd = &m_treeCtrl;
	CDC* pDC = pWnd->GetDC();
	if(!pDC)
	{
		pWnd = CWnd::GetDesktopWindow();
		pDC = pWnd->GetDC();
	}

	if(pDC)
	{
		int iColWidth = 0;
		HTREEITEM hCurSel = m_treeCtrl.GetRootItem();
		while(hCurSel)
		{
			HTREEITEM hChildItem = m_treeCtrl.GetChildItem(hCurSel);
			while(hChildItem != NULL)
			{
				CString csData = m_treeCtrl.GetItemText(hChildItem, iColumn);
				CSize size = pDC->GetTextExtent(csData);
				if(size.cx > iColWidth)
					iColWidth = size.cx;

				hChildItem = m_treeCtrl.GetNextItem(hChildItem, TVGN_NEXT);
			}
			hCurSel = m_treeCtrl.GetNextItem(hCurSel, TVGN_NEXT);
		}

		if(iColWidth > m_treeCtrl.GetColumnWidth(iColumn))
		{
			HD_ITEM hItem;
			hItem.mask = HDI_WIDTH;
			hItem.cxy = iColWidth;
			objHeaderCtrl.SetItem(iColumn, &hItem);
		}

		pWnd->ReleaseDC(pDC);
	}
}