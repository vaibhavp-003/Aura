/*======================================================================================
   FILE			: SpyDetectTreeCtrl.cpp
   ABSTRACT		: Class to manage the tree view on the main dialog.
   DOCUMENTS	: 
   AUTHOR		: Zuber
   COMPANY		: Aura 
COPYRIGHT NOTICE:
				(C) Aura
				Created as an unpublished copyright work.  All rights reserved.
				This document and the information it contains is confidential and
				proprietary to Aura.  Hence, it may not be 
				used, copied, reproduced, transmitted, or stored in any form or by any 
				means, electronic, recording, photocopying, mechanical or otherwise, 
				with out the prior written permission of Aura
   CREATION DATE: 22/01/2007
   NOTE			:
   VERSION HISTORY	:
					Version 1.0
					Resource: Zuber
					Description: New class to manage the tree view on the main dialog.
=======================================================================================*/

#include "stdafx.h"
#include "Resource.h"
#include "RCTreeCtrl.h"

/*-------------------------------------------------------------------------------------
	Function		: CRCSpyDetectTreeCtrl
	In Parameters	: treeView	- Handle of the tree view control
	Out Parameters	: -
	Purpose			: Constructor for class CRCSpyDetectTreeCtrl
	Author			: Zuber
--------------------------------------------------------------------------------------*/
CRCSpyDetectTreeCtrl::CRCSpyDetectTreeCtrl(CStatic * treeView)
				   : m_treeView(treeView), m_ctrlInit(false), m_Destructed(false)
{
}//CRCSpyDetectTreeCtrl

/*-------------------------------------------------------------------------------------
	Function		: ~CRCSpyDetectTreeCtrl
	In Parameters	: -
	Out Parameters	: -
	Purpose			: Destructor for class CRCSpyDetectTreeCtrl
	Author			: Zuber
--------------------------------------------------------------------------------------*/
CRCSpyDetectTreeCtrl::~CRCSpyDetectTreeCtrl()
{
	m_Destructed = true;
}//~CRCSpyDetectTreeCtrl

/*-------------------------------------------------------------------------------------
	Function		: InitializeTreeCtrl
	In Parameters	: -
	Out Parameters	: -
	Purpose			: Initializes the tree view, creates columns, header, tree control
					  and sets the image list.
	Author			: Zuber
--------------------------------------------------------------------------------------*/
void CRCSpyDetectTreeCtrl::InitializeTreeCtrl()
{	
	try
	{
		CWnd *pWnd = m_treeView->GetParent();

		CRect m_wndRect;
		m_treeView->GetWindowRect(&m_wndRect);
		CRect m_headerRect;

		{
			m_headerRect.left = m_headerRect.top = -1;
			m_headerRect.right = m_wndRect.Width();
			m_headerRect.bottom = m_headerRect.top + 12;
			//create header
			m_treeCtrl.m_wndHeader.Create( /*WS_CHILD |WS_VISIBLE | */HDS_BUTTONS |HDS_HORZ, m_headerRect, m_treeView, ID_TREE_LIST_HEADER);
		}

		CSize textSize;
		{
			//set header's pos, dimensions and image list
			LOGFONT logfont;
			m_treeView->GetParent()->GetFont()->GetLogFont(&logfont);
			m_treeCtrl.m_headerFont.CreateFontIndirect(&logfont);
			m_treeCtrl.m_wndHeader.SetFont(&m_treeCtrl.m_headerFont);

			CDC *pDC = m_treeCtrl.m_wndHeader.GetDC();
			pDC->SelectObject(&m_treeCtrl.m_headerFont );
			textSize = pDC->GetTextExtent(_T("A"));

			m_treeView->GetParent()->ScreenToClient(&m_wndRect);

			m_treeCtrl.m_wndHeader.SetWindowPos(&m_treeView->wndTop,0, 0, m_headerRect.Width(), textSize.cy + 4, SWP_SHOWWINDOW);
			m_treeCtrl.m_wndHeader.ModifyStyleEx(0,WS_BORDER | WS_EX_TOPMOST);

			m_treeCtrl.m_wndHeader.UpdateWindow();
		}

		CRect m_treeRect;
		{
			m_treeCtrl.m_wndHeader.GetClientRect(&m_headerRect);
			m_treeView->GetWindowRect(&m_wndRect); 
			//create tree control
			m_treeRect.left = 0;
			m_treeRect.top = m_headerRect.bottom;
			m_treeRect.right = m_headerRect.Width() - 7;
			m_treeRect.bottom = m_wndRect.bottom;

			m_treeCtrl.Create( WS_CHILD | WS_VISIBLE | TVS_LINESATROOT | TVS_HASBUTTONS | TVS_TRACKSELECT, m_treeRect, m_treeView, ID_TREE_LIST_CTRL);
			
			//use our own bitmaps for checkboxes
			m_CheckboxImgList.Create(IDB_BITMAP_TREE_CHECKBOX, 16, 1, RGB(255,255,255));
			m_treeCtrl.SetImageList(&m_CheckboxImgList, TVSIL_STATE);
			
			if(m_WormImgList.Create(16,16,ILC_COLOR16 | ILC_MASK, 8, 8))
			{
	

				m_WormImgList.Add(AfxGetApp()->LoadIcon(IDI_APPLICATION_INFO));
				#ifndef _PCBOOSTER
					m_WormImgList.Add(AfxGetApp()->LoadIcon(IDI_APPLICATION_LOG));
					m_WormImgList.Add(AfxGetApp()->LoadIcon(IDI_CLIPBOARD_MEMORY));
				#endif
				m_WormImgList.Add(AfxGetApp()->LoadIcon(IDI_COM_ACTIVEX));
				#ifndef _PCBOOSTER
					m_WormImgList.Add(AfxGetApp()->LoadIcon(IDI_COOKIES));
				#endif
				m_WormImgList.Add(AfxGetApp()->LoadIcon(IDI_DEEP_SCAN));
				
				m_WormImgList.Add(AfxGetApp()->LoadIcon(IDI_EMPTY_REGISTRY_KEY));
				m_WormImgList.Add(AfxGetApp()->LoadIcon(IDI_FILE_EXTENSION));
				m_WormImgList.Add(AfxGetApp()->LoadIcon(IDI_FONTS));
				m_WormImgList.Add(AfxGetApp()->LoadIcon(IDI_HELP_FILE));
				m_WormImgList.Add(AfxGetApp()->LoadIcon(IDI_LOGGEDIN_USER));
				m_WormImgList.Add(AfxGetApp()->LoadIcon(IDI_MRU_FILES ));

				#ifndef _PCBOOSTER
					m_WormImgList.Add(AfxGetApp()->LoadIcon(IDI_RECYCLE_BIN));
				#endif
				m_WormImgList.Add(AfxGetApp()->LoadIcon(IDI_SHARED_DLL));
				m_WormImgList.Add(AfxGetApp()->LoadIcon(IDI_SHARED_FOLDER));
				m_WormImgList.Add(AfxGetApp()->LoadIcon(IDI_SOUND_APP_EVENTS));
				m_WormImgList.Add(AfxGetApp()->LoadIcon(IDI_START_MENU_ITEM));
				m_WormImgList.Add(AfxGetApp()->LoadIcon(IDI_STARTUP_PROGRAM));

				#ifndef _PCBOOSTER
					m_WormImgList.Add(AfxGetApp()->LoadIcon(IDI_TEMP_FILE_SCAN));
					m_WormImgList.Add(AfxGetApp()->LoadIcon(IDI_TEMP_INTERNET_FILE));
					m_WormImgList.Add(AfxGetApp()->LoadIcon(IDI_VISITED_URL_LIST));
				#endif
				m_WormImgList.Add(AfxGetApp()->LoadIcon(IDI_WIN_MSDOS_SHORTCUTS));
				

				m_treeCtrl.SetImageList(&m_WormImgList, TVSIL_NORMAL);
			}
			SHORT cyHeight = m_treeCtrl.GetItemHeight();  
			m_treeCtrl.SetItemHeight(cyHeight + 2); 
		}

		// finally, create the horizontal scroll bar
		{
			CRect m_scrollRect, m_treeRect, treeRect;
			m_treeCtrl.GetWindowRect(&m_treeRect);
			pWnd->ScreenToClient(&m_treeRect);  
			m_treeView->GetWindowRect(&treeRect);
			pWnd->ScreenToClient(&treeRect);

			m_scrollRect.left = treeRect.left + 2;
			m_scrollRect.top = treeRect.bottom - GetSystemMetrics(SM_CYHSCROLL);
			m_scrollRect.right = m_headerRect.right - GetSystemMetrics(SM_CXVSCROLL);
			m_scrollRect.bottom = treeRect.bottom;

			m_treeCtrl.m_horScrollBar.Create( WS_CHILD /*| WS_VISIBLE*/ | WS_DISABLED | SBS_HORZ | SBS_TOPALIGN, m_scrollRect, pWnd, ID_TREE_LIST_SCROLLBAR);
		
			SCROLLINFO si;
			si.fMask = SIF_PAGE;
			si.nPage = m_treeRect.Width();
			m_treeCtrl.m_horScrollBar.SetScrollInfo(&si,TRUE);
		}

		if(pWnd)
		{
			pWnd = NULL;
		}
		m_ctrlInit = true;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CRCSpyDetectTreeCtrl::InitializeTreeCtrl("));
	}
}//InitializeTreeCtrl

/*-------------------------------------------------------------------------------------
	Function		: SetTreeView
	In Parameters	: treeCtrl	- Handle of the tree control
	Out Parameters	: -
	Purpose			: Sets the tree view control
	Author			: Zuber
--------------------------------------------------------------------------------------*/
void CRCSpyDetectTreeCtrl::SetTreeView( CStatic *treeView )
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
HTREEITEM CRCSpyDetectTreeCtrl::InsertParent(const CString& text, int threatIndex, const CString &csInfoHelp )
{
	try
	{
		HTREEITEM hRoot = m_treeCtrl.InsertItem(text, threatIndex, threatIndex, TVI_ROOT, TVI_LAST);
		m_treeCtrl.SetItemBold(hRoot);
		m_treeCtrl.SetItemState(hRoot, INDEXTOSTATEIMAGEMASK(2), TVIS_STATEIMAGEMASK);

		//Rest columns are blank 
		m_treeCtrl.SetItemText(hRoot, COLUMN_OPTIONTYPE, _T( ""));
		m_treeCtrl.SetItemText(hRoot, COLUMN_THREAT, _T( ""));
		m_treeCtrl.SetItemText(hRoot, COLUMN_VALUENAME, _T("" ));
		m_treeCtrl.SetItemText(hRoot, COLUMN_INVALIDVALUE, _T( ""));
		m_treeCtrl.SetItemText(hRoot, COLUMN_TYPE_CT, _T( ""));
		m_treeCtrl.SetItemText(hRoot, COLUMN_IS_CHILD, _T(""));
		m_treeCtrl.SetItemText(hRoot, COLUMN_IS_ADMINENTRY, _T("" ));

		CString threat;
		threat.Format(_T("%d"), threatIndex);
		m_treeCtrl.SetItemText(hRoot, COLUMN_THREAT_ICON, threat);
		
		return hRoot;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CRCSpyDetectTreeCtrl::InsertParent"));
	}
	return NULL;
}//InsertParent

/*------------------------------------------------------------------------------------------
	Function		: InsertChild
	In Parameters	: parentIndex	- Index of the parent item
					: threatType	- String for threat type
					: threatValue	- String for threat value
					: signature		- String for signature
					: image			- Image index in the image list
	Return Value	: Handle of the item inserted
	Purpose			: Creates a new row after the parent with the given information
	Author			: Zuber
						Modified By : Mrudula
						In Parameters : hRoot			- Handle to Parent Tree Item
										csWormType		- Worm Type
										csKey			- Key 
										csValue			- Value of the Key
										csData			- Data of the Value
										csDisplayName	- Display Name of the Key
										bIsChild		- true, if the item is a child
									    bIsAdminEntry	- true, if the item is admin entry
										image			- index of the image
---------------------------------------------------------------------------------------------*/
HTREEITEM CRCSpyDetectTreeCtrl::InsertChild( HTREEITEM hRoot, const CString& csWormType,
										   const CString &csKey, const CString &csValue,
										   const CString &csData, const CString &csDisplayName,
										   const bool bIsChild, const bool bIsAdminEntry,
										   int image )
{
	try
	{
		HTREEITEM hTmp = m_treeCtrl.InsertItem(_T( ""), image, image, hRoot);
		m_treeCtrl.SetItemText(hTmp, COLUMN_OPTIONTYPE, csWormType);
		m_treeCtrl.SetItemText(hTmp, COLUMN_THREAT, csKey);
		m_treeCtrl.SetItemText(hTmp, COLUMN_VALUENAME, csValue );
		m_treeCtrl.SetItemText(hTmp, COLUMN_INVALIDVALUE, csData );
		m_treeCtrl.SetItemText(hTmp, COLUMN_TYPE_CT, csDisplayName );
		CString csBool;
		csBool.Format(_T("%d"), bIsChild); 
		m_treeCtrl.SetItemText(hTmp, COLUMN_IS_CHILD, csBool);
		csBool.Format(_T("%d"), bIsAdminEntry); 
		m_treeCtrl.SetItemText(hTmp,COLUMN_IS_ADMINENTRY, csBool);
		m_treeCtrl.SetItemState(hTmp, INDEXTOSTATEIMAGEMASK(2), TVIS_STATEIMAGEMASK);

		m_treeCtrl.Expand(hRoot, TVE_EXPAND);

		//ResetScrollBar();

		return hTmp;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CRCSpyDetectTreeCtrl::InsertChild"));
	}
	return NULL;
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
HTREEITEM CRCSpyDetectTreeCtrl::InsertChild( HTREEITEM hRoot, const CString& threatType,const CString& csKey,
										  const CString& threatValue, const CString& csData,const CString& csNewFileName,const CString& csRegDataType, int image )
{
	try
	{
		HTREEITEM hTmp = m_treeCtrl.InsertItem(_T(""), image, image, hRoot);
		m_treeCtrl.SetItemText(hTmp, COLUMN_RECOVER_TYPE, threatType);
		m_treeCtrl.SetItemText(hTmp, COLUMN_RECOVER_KEY, csKey);
		m_treeCtrl.SetItemText(hTmp, COLUMN_RECOVER_VALUE, threatValue);
		m_treeCtrl.SetItemText(hTmp, COLUMN_RECOVER_DATA, csData);
		m_treeCtrl.SetItemText(hTmp, COLUMN_RECOVER_FILENAME, csNewFileName);
		m_treeCtrl.SetItemText(hTmp, COLUMN_RECOVER_REGDATATYPE, csRegDataType);
		m_treeCtrl.SetItemState(hTmp, INDEXTOSTATEIMAGEMASK(2), TVIS_STATEIMAGEMASK);

		return hTmp;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CRCSpyDetectTreeCtrl::InsertChild("));
	}
	return NULL;
		
}//InsertChild
/*-------------------------------------------------------------------------------------
	Function		: OnNotify
	In Parameters	: wParam	- Identifies the control
					: lParam	- Pointer to a notification message (NMHDR) structure
					: pResult	- Not used
	Out Parameters	: -
	Purpose			: Invoked from main OnNotify handler. Manages sorting and movement
					  of header
	Author			: Zuber
--------------------------------------------------------------------------------------*/
void CRCSpyDetectTreeCtrl::OnNotify(WPARAM wParam, LPARAM lParam, LRESULT *pResult)
{
	try
	{
		if(m_Destructed)
		{
			return;
		}

		HD_NOTIFY *pHDN = (HD_NOTIFY *)lParam;
		int nCol = pHDN->iItem;
		if((wParam == ID_TREE_LIST_HEADER) && (pHDN->hdr.code == HDN_ITEMCLICK))
		{
			if(nCol != 0)
			{
				m_treeCtrl.GetParent()->SendMessage(WM_NOTIFY, wParam, lParam);
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
		if((wParam == ID_TREE_LIST_HEADER) && (pHDN->hdr.code == HDN_ITEMCHANGED))
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

			if((m_nPrevColumnsWidth > m_treeCtrl.GetColumnsWidth())&&
				(m_treeRect.Width() < m_treeCtrl.GetColumnsWidth()))
			{
				m_treeCtrl.m_nOffset = -m_treeCtrl.GetColumnsWidth() + m_treeRect.Width();
			}

			m_treeCtrl.Invalidate();
		}
		else
		if((wParam == ID_TREE_LIST_HEADER) && (pHDN->hdr.code == HDN_TRACK || pHDN->hdr.code == HDN_TRACKA || pHDN->hdr.code == HDN_TRACKW ) )
		{
			if(nCol == 0)
			{
				pHDN->iButton = 0;
				//pHDN->iItem = 0;
				pHDN->pitem->mask = HDI_WIDTH;
				if(pHDN->pitem->cxy < MIN_COLUMN_WIDTH) 
					pHDN->pitem->cxy = MIN_COLUMN_WIDTH;  
			}
		}
		else
		{
			m_treeCtrl.GetParent()->SendMessage(WM_NOTIFY, wParam, lParam);
		}
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CRCSpyDetectTreeCtrl::OnNotify"));
	}
}//OnNotify

/*-------------------------------------------------------------------------------------
	Function		: OnHScroll
	In Parameters	: nSBCode	- Indicates the scrolling request of the user
					: nPos		- Specifies the scroll-box position
					: pScrollBar- Pointer to the scroll bar control
	Out Parameters	: -
	Purpose			: Invoked from main OnHScroll handler. Handles the scrolling of 
					  horizontal scroll bar
	Author			: Zuber
--------------------------------------------------------------------------------------*/
void CRCSpyDetectTreeCtrl::OnHScroll(UINT nSBCode, UINT nPos, CScrollBar *pScrollBar)
{
	try
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
					if( nPos == 0 )
					{
						m_nCurPos = 0;
					}
					else
					{
						int width = ((nPos / 6 ) + 1) * 6;
						m_nCurPos = min(width,m_treeCtrl.m_horScrollBar.GetScrollLimit() - 1);
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
			m_treeView->GetWindowRect(&m_wndRect);
			m_treeView->GetParent()->ScreenToClient(&m_wndRect);
			int width = ((m_treeCtrl.GetColumnsWidth() / m_treeRect.Width()) + 1) * m_treeRect.Width();
			m_treeCtrl.m_wndHeader.SetWindowPos(&CWnd::wndTop, m_treeCtrl.m_nOffset, 0, max(width, m_wndRect.Width()), m_headerRect.Height(), SWP_SHOWWINDOW);
		}
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CRCSpyDetectTreeCtrl::OnHScroll"));
	}
}//OnHScroll

/*-------------------------------------------------------------------------------------
	Function		: ResetScrollBar
	In Parameters	: -
	Out Parameters	: -
	Purpose			: Sets the horizontal scroll bar to correct position
	Author			: Zuber
--------------------------------------------------------------------------------------*/
void CRCSpyDetectTreeCtrl::ResetScrollBar()
{
	try
	{
		// resetting the horizontal scroll bar

		int m_nTotalWidth = 0, m_nPageWidth;

		CRect m_treeRect;
		m_treeCtrl.GetWindowRect(&m_treeRect);
		m_treeView->GetParent()->ScreenToClient(&m_treeRect);

		CRect m_wndRect;
		m_treeView->GetWindowRect(&m_wndRect);
		m_treeView->GetParent()->ScreenToClient(&m_wndRect);

		CRect m_headerRect;
		m_treeCtrl.m_wndHeader.GetWindowRect(&m_headerRect);
		m_treeView->GetParent()->ScreenToClient(&m_headerRect);

		CRect m_barRect;
		m_treeCtrl.m_horScrollBar.GetClientRect(&m_barRect);
		m_treeView->GetParent()->ScreenToClient(&m_barRect);

		m_nPageWidth = m_treeRect.Width();		
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
				else
				{
					m_treeCtrl.m_horScrollBar.ShowWindow(SW_HIDE);
				}

				// the tree becomes smaller
				CRect TreeRect;
				m_treeCtrl.GetWindowRect(&TreeRect);
				m_treeView->ScreenToClient(&TreeRect);
				if(TreeRect.Width() != m_wndRect.Width() || TreeRect.Height() != m_wndRect.Height() - m_barRect.Height() - m_headerRect.Height())
				{
					m_treeCtrl.MoveWindow(0, m_headerRect.Height(), m_wndRect.Width() - 6, m_wndRect.Height() - m_headerRect.Height() - GetSystemMetrics( SM_CYHSCROLL ) - 3 );
				}

				// check if vertical scroll bar isn't visible
				if( ! VerticalScrollVisible() )
				{
					m_treeCtrl.m_horScrollBar.MoveWindow( m_wndRect.left + 2, m_wndRect.bottom - GetSystemMetrics( SM_CYHSCROLL ), m_treeRect.Width()/* - 4 */, GetSystemMetrics( SM_CYHSCROLL ) );
				}
				else
				{
					m_treeCtrl.m_horScrollBar.MoveWindow( m_wndRect.left + 2, m_wndRect.bottom - GetSystemMetrics( SM_CYHSCROLL ), m_treeRect.Width() - GetSystemMetrics( SM_CXVSCROLL ), GetSystemMetrics( SM_CYHSCROLL ) );
				}
			}

			SCROLLINFO si;
			si.fMask = SIF_PAGE | SIF_RANGE;
			si.nPage = m_treeRect.Width();
			si.nMin = 0;
			si.nMax = m_nTotalWidth;
			m_treeCtrl.m_horScrollBar.SetScrollInfo( &si, FALSE );

			// recalculate the offset
			{
				CRect m_wndHeaderRect;
				m_treeCtrl.m_wndHeader.GetWindowRect( &m_wndHeaderRect );
				m_treeView->ScreenToClient( &m_wndHeaderRect );

				m_treeCtrl.m_nOffset = m_wndHeaderRect.left;
				m_treeCtrl.m_horScrollBar.SetScrollPos( - m_treeCtrl.m_nOffset );
			}
			m_treeCtrl.m_horScrollBar.EnableWindow(TRUE); 
		}
		else
		{
			m_treeCtrl.m_horScrollBar.EnableWindow( FALSE );

			// we no longer need it, so hide it!
			{
				// the tree takes scroll's place
				CRect TreeRect;
				m_treeCtrl.GetClientRect( &TreeRect );
				m_treeCtrl.m_horScrollBar.ShowWindow( SW_HIDE );
			}

			m_treeCtrl.m_horScrollBar.SetScrollRange( 0, 0 );

			// set scroll offset to zero
			{
				m_treeCtrl.m_nOffset = 0;
				//check
				//////m_treeCtrl.Invalidate();
				CRect m_headerRect, m_wndRect;
				m_treeCtrl.m_wndHeader.GetWindowRect( &m_headerRect );
				m_treeView->GetWindowRect( &m_wndRect );
				m_treeView->GetParent()->ScreenToClient( &m_wndRect );
				int width = ( ( m_treeCtrl.GetColumnsWidth() / m_wndRect.Width() ) + 1 ) * m_wndRect.Width();
				m_treeCtrl.m_wndHeader.SetWindowPos( &CWnd::wndTop, m_treeCtrl.m_nOffset, 0, max( width, m_wndRect.Width() ), m_headerRect.Height(), SWP_SHOWWINDOW );
				m_treeCtrl.MoveWindow( 0, m_headerRect.Height(), m_wndRect.Width() - 6, m_wndRect.Height() - m_headerRect.Height()- 3 );
			}
		}
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CRCSpyDetectTreeCtrl::ResetScrollBar"));
	}
}//ResetScrollBar

/*-------------------------------------------------------------------------------------
	Function		: VerticalScrollVisible
	In Parameters	: -
	Out Parameters	: TRUE, if vertical scroll bar visible
	Purpose			: Checks if the vertical scroll bar is visible
	Author			: Zuber
--------------------------------------------------------------------------------------*/
BOOL CRCSpyDetectTreeCtrl::VerticalScrollVisible()
{
	try
	{
		int sMin, sMax;
		m_treeCtrl.GetScrollRange( SB_VERT, &sMin, &sMax );

		return sMax != 0;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CRCSpyDetectTreeCtrl::VerticalScrollVisibl"));
	}
	return FALSE;
}//VerticalScrollVisible

/*-------------------------------------------------------------------------------------
	Function		: OnSize
	In Parameters	: -
	Out Parameters	: -
	Purpose			: Invoked from main OnSize handler. Resizes the controls of the
					  tree view
	Author			: Zuber
--------------------------------------------------------------------------------------*/
void CRCSpyDetectTreeCtrl::OnSize()
{
	try
	{
		if( !m_ctrlInit )
		{
			return;
		}

		// resize all the controls
		{
			CRect m_wndRect;
			m_treeView->GetWindowRect( &m_wndRect );
			m_treeView->GetParent()->ScreenToClient( &m_wndRect );

			CRect m_headerRect;
			m_treeCtrl.m_wndHeader.GetWindowRect( &m_headerRect );
			m_treeView->ScreenToClient( &m_headerRect );
			//m_treeCtrl.m_wndHeader.MoveWindow( 0, 0, -m_headerRect.left + m_wndRect.Width(), m_headerRect.Height() );

			int sMin, sMax;
			m_treeCtrl.m_horScrollBar.GetScrollRange( &sMin, &sMax );

			if( m_treeView->GetParent()->IsZoomed() || sMax == 0 )
			{
				m_treeCtrl.MoveWindow( 0, m_headerRect.Height(), m_wndRect.Width() - 4, m_wndRect.Height() - GetSystemMetrics( SM_CYHSCROLL ) - 5 );
			}
			else
			{
				m_treeCtrl.MoveWindow( 0, m_headerRect.Height(), m_wndRect.Width() - 4, m_wndRect.Height() - GetSystemMetrics( SM_CYHSCROLL ) );
			}
			ResetScrollBar();
			m_treeCtrl.ResetVertScrollBar();
			m_treeCtrl.m_horScrollBar.Invalidate( FALSE );
		}
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CRCSpyDetectTreeCtrl::OnSize"));
	}
}//OnSize

/*-------------------------------------------------------------------------------------
	Function		: FindParentItem
	In Parameters	: spyName - Spyware name to check, if its already present
	Out Parameters	: Handle of the item, if found
	Purpose			: Checks if the spyware name is already present in the tree view
	Author			: Zuber
--------------------------------------------------------------------------------------*/
HTREEITEM CRCSpyDetectTreeCtrl::FindParentItem( const CString& spyName )
{
	return m_treeCtrl.FindParentItem( spyName );
}//FindParentItem

/*-------------------------------------------------------------------------------------
	Function		: GetChildCount
	In Parameters	: hItem - Item whose children count is required
	Out Parameters	: Total number of children
	Purpose			: Returns the number of children for the hItem if it is not NULL,
					  otherwise the total number of children in the tree view
	Author			: Zuber
--------------------------------------------------------------------------------------*/
int CRCSpyDetectTreeCtrl::GetChildCount( HTREEITEM hItem )
{
	try
	{
		return m_treeCtrl.GetChildCount( hItem );
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CRCSpyDetectTreeCtrl::GetChildCount()"));
	}
	return 0;
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
int CRCSpyDetectTreeCtrl::InsertColumn( int nCol, LPCTSTR lpszColumnHeading, int nFormat,
									  int nWidth, int nSubItem )
{
	try
	{
		return m_treeCtrl.InsertColumn( nCol, lpszColumnHeading, nFormat, nWidth, nSubItem );
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CRCSpyDetectTreeCtrl::InsertColumn"));
	}
	return 0;
}//InsertColumn

/*-------------------------------------------------------------------------------------
	Function		: DeleteAllItems
	In Parameters	: -
	Out Parameters	: Nonzero if successful
	Purpose			: Deletes all items in the tree view
	Author			: Zuber
--------------------------------------------------------------------------------------*/
bool CRCSpyDetectTreeCtrl::DeleteAllItems()
{
	try
	{
		return (m_treeCtrl.DeleteAllItems() == FALSE ? false : true);
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CRCSpyDetectTreeCtrl::DeleteAllItems("));
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: GetItemCount
	In Parameters	: -
	Out Parameters	: Total number nodes in the tree view
	Purpose			: Returns the total number nodes in the tree view
	Author			: Zuber
--------------------------------------------------------------------------------------*/
int CRCSpyDetectTreeCtrl::GetItemCount()
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
HTREEITEM CRCSpyDetectTreeCtrl::GetTreeItem( int nItem )
{
	return m_treeCtrl.GetTreeItem( nItem );

}//GetTreeItem

int CRCSpyDetectTreeCtrl::GetSelectedItemCount()
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
bool CRCSpyDetectTreeCtrl::GetCheck( HTREEITEM hItem )
{
	try
	{
		return m_treeCtrl.GetCheck( hItem );
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CRCSpyDetectTreeCtrl::GetCheck"));
	}
	return false;
}//GetCheck

void CRCSpyDetectTreeCtrl::GetAllEntries()
{
	return m_treeCtrl.GetAllEntries();
}

HTREEITEM CRCSpyDetectTreeCtrl::GetRootItem()
{
	return m_treeCtrl.GetRootItem();
}

HTREEITEM CRCSpyDetectTreeCtrl::GetChildItem(HTREEITEM hItem)
{
	return m_treeCtrl.GetChildItem(hItem);
}

HTREEITEM CRCSpyDetectTreeCtrl::GetNextItem(HTREEITEM hItem,UINT nCode)
{
	return m_treeCtrl.GetNextItem(hItem, nCode);
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
bool CRCSpyDetectTreeCtrl::SetCheck( HTREEITEM hItem, bool fCheck )
{
	try
	{
		return m_treeCtrl.SetCheck( hItem, fCheck );
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CRCSpyDetectTreeCtrl::SetCheck"));
	}
	return false;
}//SetCheck

/*-------------------------------------------------------------------------------------
	Function		: SetCheckAll
	In Parameters	: fCheck - Indicates whether the item is to be checked or unchecked
					: hItem  - Handle of the item to receive the check state change.
							   If item is NULL (un)checks all the tree view items. If
							   item is not NULL, (un)checks the item and its children
							   if any.
	Out Parameters	: true
	Purpose			: Sets the item's check state
	Author			: Zuber
--------------------------------------------------------------------------------------*/
bool CRCSpyDetectTreeCtrl::SetCheckAll( bool fCheck, HTREEITEM hItem )
{
	try
	{
		return m_treeCtrl.SetCheckAll( fCheck, hItem );
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CRCSpyDetectTreeCtrl::SetCheckAll"));
	}
	return false;
}//SetCheckAll

/*-------------------------------------------------------------------------------------
	Function		: GetItemText
	In Parameters	: hItem		- Specifies the handle of the item in the tree
					: nSubItem	- Column number
	Out Parameters	: Respective item text
	Purpose			: Returns the text from the given column for the respective hItem
	Author			: Zuber
--------------------------------------------------------------------------------------*/
CString CRCSpyDetectTreeCtrl::GetItemText( HTREEITEM hItem, int nSubItem )
{

	return m_treeCtrl.GetItemText( hItem, nSubItem );
}//GetItemText

/*-------------------------------------------------------------------------------------
	Function		: GetItemText
	In Parameters	: nItem		- Index of the item in the tree
					: nSubItem	- Column number
	Out Parameters	: Respective item text
	Purpose			: Returns the text from the column for the item at the given index
	Author			: Zuber
--------------------------------------------------------------------------------------*/
CString CRCSpyDetectTreeCtrl::GetItemText( int nItem, int nSubItem )
{
	return m_treeCtrl.GetItemText( nItem, nSubItem );

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
bool CRCSpyDetectTreeCtrl::SetItemText( HTREEITEM hItem, int nCol, LPCTSTR lpszItem )
{
	return (m_treeCtrl.SetItemText(hItem, nCol, lpszItem) == FALSE ? false : true);
}

/*-------------------------------------------------------------------------------------
	Function		: DeleteItem
	In Parameters	: hItem	- Specifies the handle of the item in the tree to delete
	Out Parameters	: Nonzero if it is successful
	Purpose			: Deletes an item from the tree view
	Author			: Zuber
--------------------------------------------------------------------------------------*/
bool CRCSpyDetectTreeCtrl::DeleteItem( HTREEITEM hItem )
{
	return (m_treeCtrl.DeleteItem(hItem) == FALSE ? false : true);
}	

/*-------------------------------------------------------------------------------------
	Function		: DeleteItem
	In Parameters	: nItem	- Index of the item in the tree to delete
	Out Parameters	: Nonzero if it is successful
	Purpose			: Deletes an item from the tree view
	Author			: Zuber
--------------------------------------------------------------------------------------*/
bool CRCSpyDetectTreeCtrl::DeleteItem(int nItem)
{
	return (m_treeCtrl.DeleteItem(nItem) == FALSE ? false : true);
}

/*-------------------------------------------------------------------------------------
	Function		: SetItemState
	In Parameters	: hItem		- Specifies the handle of the item whose state is to be set
					: nState	- Specifies new states for the item
					: nStateMask- Specifies which states are to be changed
	Out Parameters	: Nonzero if it is successful
	Purpose			: Sets the state of the item specified by hItem
	Author			: Zuber
--------------------------------------------------------------------------------------*/
bool CRCSpyDetectTreeCtrl::SetItemState(HTREEITEM hItem, UINT nState, UINT nStateMask)
{
	return (m_treeCtrl.SetItemState(hItem, nState, nStateMask) == FALSE ? false : true);
}

/*-------------------------------------------------------------------------------------
	Function		: GetItemState
	In Parameters	: hItem		- Specifies the handle of the item whose state is required
					: nStateMask- Indicates which states are to be retrieved
	Out Parameters	: State of the item
	Purpose			: Retrieves the state of the item specified by hItem
	Author			: Zuber
--------------------------------------------------------------------------------------*/
UINT CRCSpyDetectTreeCtrl::GetItemState(HTREEITEM hItem, UINT nStateMask) const
{
	return m_treeCtrl.GetItemState(hItem, nStateMask);
}

/*-------------------------------------------------------------------------------------
	Function		: EnsureVisible
	In Parameters	: hItem	- Specifies the handle of the tree item being made visible
	Out Parameters	: Returns true if the system scrolled the items in the tree-view
					  control to ensure that the specified item is visible, else false
	Purpose			: Ensures that a tree view item is visible
	Author			: Zuber
--------------------------------------------------------------------------------------*/
bool CRCSpyDetectTreeCtrl::EnsureVisible(HTREEITEM hItem)
{
	return (m_treeCtrl.EnsureVisible(hItem) == FALSE ? false : true);
}

/*-------------------------------------------------------------------------------------
	Function		: GetClientRect
	In Parameters	: lpRect - CRect object to receive the co-ordinates
	Out Parameters	: -
	Purpose			: Retrieves the coordinates of a window's client area
	Author			: Zuber
--------------------------------------------------------------------------------------*/
void CRCSpyDetectTreeCtrl::GetClientRect( LPRECT lpRect ) const
{
	m_treeCtrl.GetClientRect( lpRect );

}//GetClientRect

/*-------------------------------------------------------------------------------------
	Function		: GetParent
	In Parameters	: -
	Out Parameters	: Handle of the parent window
	Purpose			: Retrieves the handle of the parent window
	Author			: Zuber
--------------------------------------------------------------------------------------*/
CWnd * CRCSpyDetectTreeCtrl::GetParent() const
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
void CRCSpyDetectTreeCtrl::ShowWindow( int nCmdShow )
{
	try
	{
		if( nCmdShow )
		{
			m_treeCtrl.SetWindowPos( 0, 0, 0, 0, 0, SWP_NOSIZE | SWP_NOMOVE | SWP_NOZORDER | SWP_SHOWWINDOW );
			m_treeCtrl.m_horScrollBar.SetWindowPos( 0, 0, 0, 0, 0, SWP_NOSIZE | SWP_NOMOVE | SWP_NOZORDER | SWP_SHOWWINDOW );
		}
		else
		{
			m_treeCtrl.SetWindowPos( 0, 0, 0, 0, 0, SWP_NOSIZE | SWP_NOMOVE | SWP_NOZORDER | SWP_HIDEWINDOW );
			m_treeCtrl.m_horScrollBar.SetWindowPos( 0, 0, 0, 0, 0, SWP_NOSIZE | SWP_NOMOVE | SWP_NOZORDER | SWP_HIDEWINDOW );
		}
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CRCSpyDetectTreeCtrl::ShowWindow"));
	}
}

/*-------------------------------------------------------------------------------------
	Function		: ItemHasChildren
	In Parameters	: hItem - Specifies the handle of the item which is to be checked
	Out Parameters	: true, if item has children
	Purpose			: Checks if the item has children
	Author			: Zuber
--------------------------------------------------------------------------------------*/
bool CRCSpyDetectTreeCtrl::ItemHasChildren(HTREEITEM hItem)
{
	try
	{
		if( hItem == NULL )
		{
			return false;
		}

		return (m_treeCtrl.ItemHasChildren(hItem) == FALSE ? false : true);
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CRCSpyDetectTreeCtrl::ItemHasChildren"));
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: GetParentItem
	In Parameters	: Handle of the item whose parent is required
	Out Parameters	: Parent item
	Purpose			: Returns the parent of the item
	Author			: Zuber
--------------------------------------------------------------------------------------*/
HTREEITEM CRCSpyDetectTreeCtrl::GetParentItem( HTREEITEM hItem ) const
{
	try
	{
		if( hItem == NULL )
		{
			return NULL;
		}

		return m_treeCtrl.GetParentItem( hItem );
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CRCSpyDetectTreeCtrl::GetParentItem"));
	}
	return NULL;
}

/*-------------------------------------------------------------------------------------
	Function		: SortItems
	In Parameters	: int - column
	Out Parameters	: void
	Purpose			: to sort the items
	Author			: Zuber
--------------------------------------------------------------------------------------*/
void CRCSpyDetectTreeCtrl::SortItems( int nCol )
{
	try
	{
		m_treeCtrl.SortItems( nCol );
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CRCSpyDetectTreeCtrl::SortItems"));
	}
}//SortItems

/*-------------------------------------------------------------------------------------
	Function		: SetRedraw
	In Parameters	: bool
	Out Parameters	: void
	Purpose			: to set redraw
	Author			: Zuber
--------------------------------------------------------------------------------------*/
void CRCSpyDetectTreeCtrl::SetRedraw( bool redraw )
{
	try
	{
		m_treeCtrl.SetRedraw( redraw );
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CRCSpyDetectTreeCtrl::SetRedraw"));
	}
}//SetRedraw

/*-------------------------------------------------------------------------------------
	Function		: Expand
	In Parameters	: CString - parent item
	Out Parameters	: void
	Purpose			: to expand the tree item
	Author			: Zuber
--------------------------------------------------------------------------------------*/
bool CRCSpyDetectTreeCtrl::Expand(CString csParentItem)
{
	try
	{
		return m_treeCtrl.Expand(csParentItem);
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CRCSpyDetectTreeCtrl::Expand"));
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: SetLink
	In Parameters	: bool - flag
	Out Parameters	: void
	Purpose			: to set the link to tree
	Author			: Zuber
--------------------------------------------------------------------------------------*/
void CRCSpyDetectTreeCtrl::SetLink(bool bFlag)
{
	m_treeCtrl.m_bShowLink = bFlag;
}

/*-------------------------------------------------------------------------------------
	Function		: SetLinkCaption
	In Parameters	: CString& - caption
	Out Parameters	: void
	Purpose			: to set the link caption
	Author			: Zuber
--------------------------------------------------------------------------------------*/
void CRCSpyDetectTreeCtrl::SetLinkCaption(const CString &csCaption)
{
	m_treeCtrl.m_csLinkText = csCaption;
}

/*-------------------------------------------------------------------------------------
	Function		: GetTreeControl
	In Parameters	: -
	Out Parameters	: CNewTreeListCtrl * - ptr to tree control
	Purpose			: to get tree control pointer
	Author			: Zuber
--------------------------------------------------------------------------------------*/
CRCNewTreeListCtrl * CRCSpyDetectTreeCtrl::GetTreeControl()
{
	return &m_treeCtrl;
}

/*-------------------------------------------------------------------------------------
	Function		: SetHeaderColumnText
	In Parameters	: iColumn : Specifies the column number whose text is to be changed.
					: CString : text which will be set
	Out Parameters	: bool : true if function is successful
	Purpose			: changes the text of the column header.
	Author			: Avinash Bhardwaj
--------------------------------------------------------------------------------------*/
void CRCSpyDetectTreeCtrl::SetHeaderColumnText(int iColumn,CString csText)
{
	try
	{
		CHeaderCtrl *pHeaderCtrl = (CHeaderCtrl*) &(m_treeCtrl.m_wndHeader);
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