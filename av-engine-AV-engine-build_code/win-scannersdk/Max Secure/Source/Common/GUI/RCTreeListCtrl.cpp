/*======================================================================================
   FILE			: NewTreeListCtrl.cpp
   ABSTRACT		: Class to manage the tree control of the tree view.
   DOCUMENTS	: 
   AUTHOR		: Zuber
   COMPANY		: Aura 
COPYRIGHT NOTICE:
				(C) Aura
				Created as an unpublished copyright work. All rights reserved.
				This document and the information it contains is confidential and
				proprietary to Aura. Hence, it may not be 
				used, copied, reproduced, transmitted, or stored in any form or by any 
				means, electronic, recording, photocopying, mechanical or otherwise, 
				with out the prior written permission of Aura
   CREATION DATE: 22/01/2007
   NOTE			: This is a third party code
   VERSION HISTORY	:
					Version 1.0
					Resource: Zuber
					Description: New class to manage the tree control of the tree view.
=======================================================================================*/

#include "stdafx.h"
#include "RCTreeListCtrl.h"
#include "RCTreeCtrl.h"
#include "Resource.h"
#include "RegistryCleaner.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*-------------------------------------------------------------------------------------
	Function		: CRCTLItem
	In Parameters	: -
	Out Parameters	: -
	Purpose			: Constructor for class CRCTLItem
	Author			: Zuber
--------------------------------------------------------------------------------------*/
CRCTLItem::CRCTLItem()
{
	try
	{
		m_cEnding = _T('Γ');//'¶';
		m_itemString = _T("");
		m_Bold = FALSE;
		m_Color = ::GetSysColor(COLOR_WINDOWTEXT);
		m_HasChildren = FALSE;
		m_nPriority = 1000;
		m_Group = FALSE;
		m_Destructed = FALSE;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in  CRCTLItem::CRCTLItem"));
	}
}//CRCTLItem

/*-------------------------------------------------------------------------------------
	Function		: CRCTLItem
	In Parameters	: -
	Out Parameters	: -
	Purpose			: Copy Constructor for class CRCTLItem
	Author			: Zuber
--------------------------------------------------------------------------------------*/
CRCTLItem::CRCTLItem(CRCTLItem &copyItem)
{
	try
	{
		m_cEnding = copyItem .m_cEnding;
		m_itemString = copyItem .GetItemString();
		m_Bold = copyItem .m_Bold;
		m_Color = copyItem .m_Color;
		itemData = copyItem .itemData;
		m_HasChildren = copyItem .m_HasChildren;
		m_nPriority = copyItem .m_nPriority;
		m_Group = copyItem .m_Group;
		m_Destructed = copyItem.m_Destructed;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in  CRCTLItem::CRCTLItem"));
	}
}//CRCTLItem

CRCTLItem::~CRCTLItem()
{
	m_Destructed = TRUE;
}//~CRCTLItem

/*-------------------------------------------------------------------------------------
	Function		: GetSubstring
	In Parameters	: m_nSub - Column number
	Out Parameters	: Text for a particular column
	Purpose			: Retrieves the text for a particular column from tree view
	Author			: Zuber
--------------------------------------------------------------------------------------*/
CString CRCTLItem::GetSubstring(int m_nSub)
{
	try
	{
		if(m_Destructed)
		{
			return _T("");
		}

		CString m_tmpStr(_T(""));
		int i=0, nHits=0;

		int length = m_itemString .GetLength();

		while((i<length) && (nHits<=m_nSub))
		{
			if(m_itemString[i]==m_cEnding)
			{
				nHits++;
			}
			else
			if(nHits==m_nSub)
			{
				m_tmpStr+=m_itemString[i];
			}

			i++;
		}

		if((i>=length) && (nHits<m_nSub))
		{
			return _T("");
		}
		else
		{
			return m_tmpStr;
		}
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in  CRCTLItem::GetSubstring"));
	}
	return _T("");
}//GetSubstring

/*-------------------------------------------------------------------------------------
	Function		: SetSubstring
	In Parameters	: m_nSub  - Column number
					: m_sText - Text for the column
	Out Parameters	: -
	Purpose			: Sets the text for a particular column in the tree view
	Author			: Zuber
--------------------------------------------------------------------------------------*/
void CRCTLItem::SetSubstring(int m_nSub, CString m_sText)
{
	try
	{
	
		if(m_itemString != _T(""))
		{
			if(m_itemString != m_cEnding)
				m_itemString += m_cEnding;
			m_itemString += m_sText;
		}
		else 
		{
			m_itemString = m_sText;
			if(m_itemString == _T(""))
				m_itemString += m_cEnding;
		}
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in  CRCTLItem::SetSubstring"));
	}
}//SetSubstring

// CRCNewTreeListCtrl
/*-------------------------------------------------------------------------------------
	Function		: CRCNewTreeListCtrl
	In Parameters	: -
					: -
	Out Parameters	: -
	Purpose			: Constructor for class CRCNewTreeListCtrl
	Author			: Zuber
--------------------------------------------------------------------------------------*/
CRCNewTreeListCtrl::CRCNewTreeListCtrl()
{
	try
	{
		m_bDeletingAllMembers = false;
		m_prevSelectedItem = NULL;
		m_nColumns = m_nColumnsWidth = 0;
		m_nSelectedItems = 0;
		m_nOffset = 0;
		m_ParentsOnTop = TRUE;

		m_bLDragging = FALSE;
		m_htiOldDrop = m_htiDrop = m_htiDrag = NULL;
		m_scrollTimer = m_idTimer = 0;
		m_timerticks = 0;
		m_toDrag = FALSE;

		m_nItems = 0;
		m_iChildCnt = 0;
		m_RTL = FALSE;

		m_bShowLink = false;
		m_csLinkText = _T("Info");

		CBitmap bitmap;
		BITMAP bm;

		bitmap.LoadBitmap(IDB_BITMAP_THREAT_HIGH);
		bitmap.GetBitmap(&bm);

		m_ImageList.Create(bm.bmWidth, bm.bmHeight, ILC_COLOR24, 3, 3);
		m_ImageList.Add(&bitmap, (COLORREF) 0x000000);
		bitmap.DeleteObject();

		bitmap.LoadBitmap(IDB_BITMAP_THREAT_MEDIUM);
		m_ImageList.Add(&bitmap, (COLORREF) 0x000000);
		bitmap.DeleteObject();
		bitmap.LoadBitmap(IDB_BITMAP_THREAT_LOW);
		m_ImageList.Add(&bitmap, (COLORREF) 0x000000);
		bitmap.DeleteObject();
		bitmap.LoadBitmap(IDB_BITMAP_THREAT_LOW);
		m_ImageList.Add(&bitmap, (COLORREF) 0x000000);
		bitmap.DeleteObject();
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in  CRCNewTreeListCtrl::CRCNewTreeListCtrl"));
	}
	
}//CRCNewTreeListCtrl

/*-------------------------------------------------------------------------------------
	Function		: ~CRCNewTreeListCtrl
	In Parameters	: -
					: -
	Out Parameters	: -
	Purpose			: Destructor for class CRCNewTreeListCtrl
	Author			: Zuber
--------------------------------------------------------------------------------------*/
CRCNewTreeListCtrl::~CRCNewTreeListCtrl()
{
	
}

BEGIN_MESSAGE_MAP(CRCNewTreeListCtrl, CTreeCtrl)
	//{{AFX_MSG_MAP(CRCNewTreeListCtrl)
	ON_WM_PAINT()
	ON_WM_CREATE()
	ON_WM_LBUTTONDOWN()
	ON_WM_LBUTTONDBLCLK()
	ON_WM_TIMER()
	ON_WM_MOUSEMOVE()
	ON_WM_DESTROY()
	ON_NOTIFY_REFLECT(NM_CUSTOMDRAW, OnNMCustomdraw)
	ON_WM_KEYDOWN()
	//}}AFX_MSG_MAP
	ON_WM_SETCURSOR()
END_MESSAGE_MAP()

/*-------------------------------------------------------------------------------------
	Function		: OnCreate
	In Parameters	: lpCreateStruct - Contains information about the CWnd object being created
	Out Parameters	: -
	Purpose			: Called by framework when the tree list control is created
	Author			: Zuber
--------------------------------------------------------------------------------------*/
int CRCNewTreeListCtrl::OnCreate(LPCREATESTRUCT lpCreateStruct) 
{
	try
	{
		if (CTreeCtrl::OnCreate(lpCreateStruct) == -1)
		{
			return -1;
		}
		return 0;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in  CRCNewTreeListCtrl::OnCreate"));
	}
	return -1;
}//OnCreate

/*-------------------------------------------------------------------------------------
	Function		: GetTreeItem
	In Parameters	: nItem	- Index of the item
	Out Parameters	: Item on the particular index
	Purpose			: Returns the handle of the item for a particular index in the tree
	                  control
	Author			: Zuber
--------------------------------------------------------------------------------------*/
HTREEITEM CRCNewTreeListCtrl::GetTreeItem(int nItem)
{
	try
	{
		HTREEITEM m_ParentItem = GetRootItem();
		int m_nCount = 0;

		while((m_ParentItem != NULL) && (m_nCount < nItem))
		{
			m_nCount ++ ;
			if(ItemHasChildren(m_ParentItem))
			{
				HTREEITEM childItem = GetChildItem(m_ParentItem);
				while((childItem != NULL) && (m_nCount < nItem))
				{
					m_nCount ++;
					childItem = GetNextSiblingItem(childItem);
				}
				if(childItem != NULL)
				{
					m_ParentItem = childItem;
					break ;
				}
			}
			m_ParentItem = GetNextSiblingItem(m_ParentItem);
		}

		return m_ParentItem;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in  CRCNewTreeListCtrl::GetTreeItem"));
	}
	return GetRootItem();

}//GetTreeItem
/*-------------------------------------------------------------------------------------
	Function		: GetAllEntries
	In Parameters	: 
					: 
	Out Parameters	: 
	Purpose			: This Function will retrive All Entry
	Author			: 
--------------------------------------------------------------------------------------*/
void CRCNewTreeListCtrl::GetAllEntries()
{
	try
	{
		HTREEITEM hCurSel = GetRootItem();
		while(hCurSel)
		{
			
			CString str;
			str = (LPCTSTR) GetItemText(hCurSel);
			HTREEITEM hChildItem = GetChildItem(hCurSel);		
			while(hChildItem != NULL)
			{
				str = (LPCTSTR) GetItemText (hChildItem,2);
				hChildItem = GetNextItem(hChildItem , TVGN_NEXT);
			}
			hCurSel = GetNextItem(hCurSel, TVGN_NEXT);
			
		}
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in  CRCNewTreeListCtrl::GetAllEntries"));
	}
}
/*-------------------------------------------------------------------------------------
	Function		: GetListItem
	In Parameters	: hItem - Handle of the item in the tree control
	Out Parameters	: Index of the item in the tree control
	Purpose			: Retrieves the index of a item 'hItem' from the tree control
	Author			: Zuber
--------------------------------------------------------------------------------------*/
int CRCNewTreeListCtrl::GetListItem(HTREEITEM hItem)
{
	try
	{
		HTREEITEM m_ParentItem = GetRootItem();
		int m_nCount = 0;

		while((m_ParentItem!=NULL) && (m_ParentItem!=hItem))
		{
			m_nCount ++ ;
			GetNextSiblingItem(m_ParentItem);
		}

		return m_nCount;

	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in  CRCNewTreeListCtrl::GetListItem"));
	}
	return -1;

}//GetListItem

/*-------------------------------------------------------------------------------------
	Function		: RecalcHeaderPosition
	In Parameters	: -
	Out Parameters	: -
	Purpose			: Calculates and sets the header of the tree control
	Author			: Zuber
--------------------------------------------------------------------------------------*/
void CRCNewTreeListCtrl::RecalcHeaderPosition()
{
	try
	{
		if(m_RTL)
		{
			CRect m_clientRect;
			GetClientRect(&m_clientRect);

			if(GetColumnsWidth() > m_clientRect .Width())
			{
				int m_nOffset = m_clientRect.Width() - GetColumnsWidth();

				CStatic * st = (CStatic *) GetParent();

				int width = ((GetColumnsWidth()/m_clientRect.Width())+1)*m_clientRect.Width();

				CRect m_wndRect;
				st->GetClientRect(&m_wndRect);
				CRect m_headerRect;
				m_wndHeader.GetClientRect(&m_headerRect);

				m_wndHeader.SetWindowPos(&wndTop, m_nOffset, 0, max(width,m_wndRect.Width()), m_headerRect.Height(), SWP_SHOWWINDOW);
			}
		}
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in  CRCNewTreeListCtrl::RecalcHeaderPosition"));
	}
}//RecalcHeaderPosition

/*-------------------------------------------------------------------------------------
	Function		: InsertColumn
	In Parameters	: nCol				- Column number
					: lpszColumnHeading - Text for the column
					: nFormat			- Format for the column (LVCFMT_LEFT,
										  LVCFMT_CENTER, LVCFMT_RIGHT)
					: nWidth			- Width for column
					: nSubItem			- Not used
	Out Parameters	: Index of new column if successful
	Purpose			: Inserts a new column in the header of tree control
	Author			: Zuber
--------------------------------------------------------------------------------------*/
int CRCNewTreeListCtrl::InsertColumn(int nCol, LPCTSTR lpszColumnHeading, int nFormat, int nWidth, int nSubItem)
{
	try
	{
		HD_ITEM hdi;
		hdi.mask = HDI_TEXT | HDI_FORMAT;
		if(nWidth!=-1)
		{
			hdi.mask |= HDI_WIDTH;
			hdi.cxy = nWidth;
		}
		
		hdi.pszText = (LPTSTR)lpszColumnHeading;
		hdi.fmt = HDF_OWNERDRAW;

		if(nFormat == LVCFMT_RIGHT)
		{
			hdi.fmt |= HDF_RIGHT;
		}
		else
		if(nFormat == LVCFMT_CENTER)
		{
			hdi.fmt |= HDF_CENTER;
		}
		else
		{
			hdi.fmt |= HDF_LEFT;
		}

		m_nColumns ++ ;

		int m_nReturn = m_wndHeader.InsertItem(nCol, &hdi);

		if(m_nColumns==1)
		{
			m_wndHeader.SetItemImage(m_nReturn, 0);
		}

		RecalcColumnsWidth();

		if(m_RTL)
		{
			RecalcHeaderPosition();
		}

		UpdateWindow();

		return m_nReturn;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in  CRCNewTreeListCtrl::InsertColumn"));
	}
	return -1;
}//InsertColumn

/*-------------------------------------------------------------------------------------
	Function		: GetColumnWidth
	In Parameters	: nCol  - Column number
	Out Parameters	: Column width
	Purpose			: Retrieves the column width
	Author			: Zuber
--------------------------------------------------------------------------------------*/
int CRCNewTreeListCtrl::GetColumnWidth(int nCol)
{	
	try
	{
		if(m_RTL)
		{
			nCol = GetColumnsNum() - nCol - 1;
		}

		HD_ITEM hItem;
		hItem.mask = HDI_WIDTH;
		if(!m_wndHeader.GetItem(nCol, &hItem))
		{
			return 0;
		}

		return hItem.cxy;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in  CRCNewTreeListCtrl::GetColumnWidth"));
	}
	return 0;
}//GetColumnWidth

/*-------------------------------------------------------------------------------------
	Function		: GetColumnAlign
	In Parameters	: nCol  - Column number
	Out Parameters	: Column allignment
	Purpose			: Retrieves the column alligment (LVCFMT_LEFT, LVCFMT_RIGHT
	                  or LVCFMT_CENTER)
	Author			: Zuber
--------------------------------------------------------------------------------------*/
int CRCNewTreeListCtrl::GetColumnAlign(int nCol)
{
	try
	{
		HD_ITEM hItem;
		hItem.mask = HDI_FORMAT;
		if(!m_wndHeader.GetItem(nCol, &hItem))
		{
			return LVCFMT_LEFT;
		}

		if(hItem.fmt & HDF_RIGHT)
		{
			return LVCFMT_RIGHT;
		}
		else
		if(hItem.fmt & HDF_CENTER)
		{
			return LVCFMT_CENTER;
		}
		else
		{
			return LVCFMT_LEFT;
		}
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in  CRCNewTreeListCtrl::GetColumnAlign"));
	}
	return LVCFMT_LEFT;
}//GetColumnAlign

/*-------------------------------------------------------------------------------------
	Function		: RecalcColumnsWidth
	In Parameters	: -
	Out Parameters	: -
	Purpose			: Calculates the total width of all the columns
	Author			: Zuber
--------------------------------------------------------------------------------------*/
void CRCNewTreeListCtrl::RecalcColumnsWidth()
{
	try
	{
		m_nColumnsWidth = 0;
		for(int i=0;i<m_nColumns;i++)
		{
			m_nColumnsWidth += GetColumnWidth(i);
		}
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in  CRCNewTreeListCtrl::RecalcColumnsWidth"));
	}
}//RecalcColumnsWidth

/*-------------------------------------------------------------------------------------
	Function		: DrawItemText
	In Parameters	: pDC		- CDC pointer
					: text		- Text for the item
					: rect		- Prescribed rectangle for the text
					: nWidth	- Max.width for the text
					: nFormat	- Allignment for the text
	Out Parameters	: -
	Purpose			: Draws the text for an item
	Author			: Zuber
--------------------------------------------------------------------------------------*/
void CRCNewTreeListCtrl::DrawItemText(CDC* pDC, CString text, CRect rect, int nWidth, int nFormat)
{
    // Make sure the text will fit in the prescribed rectangle, and truncate
    // it if it won't.
    try
	{
		BOOL bNeedDots = FALSE;
		int nMaxWidth = nWidth - 4;

		while ((text.GetLength()>0) && (pDC->GetTextExtent((LPCTSTR) text).cx > (nMaxWidth - 4)))
		{
			text = text.Left (text.GetLength () - 1);
			bNeedDots = TRUE;
		}

		if (bNeedDots)
		{
			if (text.GetLength () >= 1)
			{
				text = text.Left (text.GetLength () - 1);
			}
			if(!m_RTL)
			{
				text += _T("...");
			}
			else
			{
				text = _T("...")+ text;
			}
		}

		//
		// Draw the text into the rectangle using MFC's handy CDC::DrawText
		// function.
		//
		rect.right = rect.left + nMaxWidth;
		if(m_RTL)
		{
			rect.right += 4;
			rect.left += 4;
		}

		UINT nStyle = DT_VCENTER | DT_SINGLELINE;
		if (nFormat == LVCFMT_LEFT)
		{
			nStyle |= DT_LEFT;
		}
		else
		if (nFormat == LVCFMT_CENTER)
		{
			nStyle |= DT_CENTER;
		}
		else // nFormat == LVCFMT_RIGHT
		{
			nStyle |= DT_RIGHT;
		}

		if((text.GetLength()>0) && (rect.right>rect.left))
		{
			pDC->DrawText (text, rect, nStyle);

			CRect clientRect;
			GetClientRect(&clientRect);
			rect.left = 0;
			rect.right = clientRect.Width();
			if(rect.right < GetColumnsWidth())
			{
				rect.right = GetColumnsWidth();
			}

			pDC->DrawEdge(&rect, BDR_SUNKENINNER, BF_BOTTOM);
		}
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in  CRCNewTreeListCtrl::DrawItemText"));
	}
}//DrawItemText

/*-------------------------------------------------------------------------------------
	Function		: CRectGet
	In Parameters	: left	- Left co-ordinate
					: top	- Top co-ordinate
					: right	- Right co-ordinate
					: bottom- Bottom co-ordinate
	Out Parameters	: CRect object
	Purpose			: Creates a rect object with co-ordinates within the tree control
	Author			: Zuber
--------------------------------------------------------------------------------------*/
CRect CRCNewTreeListCtrl::CRectGet(int left, int top, int right, int bottom)
{
	try
	{
		if(m_RTL)
		{
			CRect m_clientRect;
			GetClientRect(&m_clientRect);

			return CRect(m_clientRect.Width() - right, top, m_clientRect.Width() - left, bottom);
		}
		else
		{
			return CRect(left, top, right, bottom);
		}
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in  CRCNewTreeListCtrl::CRectGet"));
	}
	return CRect(0,0,0,0);
}//CRectGet

/*-------------------------------------------------------------------------------------
	Function		: OnPaint
	In Parameters	: -
					: -
	Out Parameters	: -
	Purpose			: Handles the paint of the tree control
	Author			: Zuber
--------------------------------------------------------------------------------------*/
void CRCNewTreeListCtrl::OnPaint() 
{
	try
	{
		if(m_bDeletingAllMembers)
			return;

		CPaintDC dc(this); // device context for painting

		CRect rcClip;
		dc.GetClipBox(&rcClip);

		// Set clip region to be same as that in paint DC
		CRgn rgn;
		rgn.CreateRectRgnIndirect(&rcClip);
		dc.SelectClipRgn(&rgn);
		rgn.DeleteObject();
		
		COLORREF m_wndColor = GetSysColor(COLOR_WINDOW);

		dc.SetViewportOrg(m_nOffset, 0);

		dc.SetTextColor(m_wndColor);

		// First let the control do its default drawing.

		CRect m_clientRect;
		GetClientRect(&m_clientRect);
		if(m_RTL)
		{
			dc.SetViewportOrg(m_clientRect.Width(), 0);
			CSize ext = dc.GetViewportExt();
			ext.cx = ext.cx > 0 ? -ext.cx : ext.cx;

			dc.SetMapMode(MM_ANISOTROPIC);
			dc.SetViewportExt(ext);
		}

		CTreeCtrl::DefWindowProc(WM_PAINT, (WPARAM)dc.m_hDC, 0);

		if(m_RTL)
		{
			dc.SetViewportOrg(0, 0);
			dc.SetMapMode(MM_TEXT);
		}

		HTREEITEM hItem = GetFirstVisibleItem();

		int n = GetVisibleCount(), m_nWidth;

		CRCTLItem *pItem;

		// create the font
		CFont *pFontDC;
		CFont fontDC, boldFontDC,ulFontDC;
		LOGFONT logfont;

		GetFont()->GetLogFont(&logfont);

		fontDC.CreateFontIndirect(&logfont);
		pFontDC = dc.SelectObject(&fontDC);

		logfont.lfUnderline = 1;
		ulFontDC.CreateFontIndirect(&logfont);

		logfont.lfUnderline = 0;
		logfont.lfWeight = 700;
		boldFontDC.CreateFontIndirect(&logfont);

		// and now let's get to the painting itself
		hItem = GetFirstVisibleItem();
		n = GetVisibleCount();
		while(hItem!=NULL && n>=0)
		{
			
			IMAGEINFO imageInfo;

			m_ImageList.GetImageInfo(0, &imageInfo);
			int width = imageInfo.rcImage.right;

			CRect rect;

			UINT selflag = TVIS_SELECTED;

			pItem = (CRCTLItem *)CTreeCtrl::GetItemData(hItem);
			if(pItem)
			{

				HTREEITEM hParent = GetParentItem(hItem);
				if(hParent != NULL)
				{
					CRCTLItem *pParent = (CRCTLItem *)CTreeCtrl::GetItemData(hParent);
					if(pParent->m_Group)
					{
						pItem->m_Group = TRUE;
					}
				}

				if (!(GetItemState(hItem, selflag) & selflag))
				{
					dc.SetBkMode(TRANSPARENT);

					CString sItem = pItem->GetItemText();

					CRect m_labelRect;
					GetItemRect(hItem, &m_labelRect, TRUE);
					GetItemRect(hItem, &rect, FALSE);
					if(GetColumnsNum()>1)
					{
						rect.left = min(m_labelRect.left, GetColumnWidth(0));
					}
					else
					{
						rect.left = m_labelRect.left;
					}
					rect.right = m_nColumnsWidth;

					if(pItem->m_Group)
					{
						if(hParent != NULL)
						{
							GetItemRect(hParent, &m_labelRect, TRUE);
						}
						rect.left = m_labelRect.left;
						CBrush bkBrush(m_wndColor);
						dc.FillRect(rect, &bkBrush);
					}

					dc.SetBkColor(m_wndColor);

					dc.SetTextColor(pItem->m_Color);

					if(pItem->m_Bold)
					{
						dc.SelectObject(&boldFontDC);
					}

					if(!pItem->m_Group)
					{
						DrawItemText(&dc, sItem, CRectGet(rect.left+2, rect.top, m_nColumnsWidth, rect.bottom), m_nColumnsWidth, GetColumnAlign(0));
						//DrawItemText(&dc, sItem, CRectGet(rect.left+2, rect.top, GetColumnWidth(0), rect.bottom), GetColumnWidth(0)-rect.left-2, GetColumnAlign(0));
						//DrawItemText(&dc, sItem, CRectGet(rect.left + width, rect.top, m_nColumnsWidth, rect.bottom), m_nColumnsWidth-rect.left-2, GetColumnAlign(0));
					}
					else
					{
						DrawItemText(&dc, sItem, CRectGet(rect.left+2, rect.top, m_nColumnsWidth, rect.bottom), m_nColumnsWidth, LVCFMT_RIGHT);
						//DrawItemText(&dc, sItem, CRectGet(rect.left+2, rect.top, GetColumnWidth(0), rect.bottom), GetColumnWidth(0)-rect.left-2, LVCFMT_RIGHT);
						//DrawItemText(&dc, sItem, CRectGet(rect.left + width, rect.top, m_nColumnsWidth, rect.bottom), m_nColumnsWidth-rect.left-2, LVCFMT_RIGHT);
					}

					m_nWidth = 0;
					for(int i=1;i<m_nColumns;i++)
					{
						m_nWidth += GetColumnWidth(i-1);
						DrawItemText(&dc, pItem->GetSubstring(i), CRectGet(m_nWidth, rect.top, m_nWidth+GetColumnWidth(i), rect.bottom), GetColumnWidth(i), GetColumnAlign(i));
					}

					if(pItem->m_Bold)
					{
						dc.SelectObject(&fontDC);
					}
					//Draw more info link which point to url
					if(pItem->m_Bold && m_bShowLink)
					{
						// Mrudula: Displaying count for each option
						dc.SelectObject(&boldFontDC);	
						dc.SetTextColor(COUNT_COLOR);
						
						DWORD dwData = pItem->itemData;
						CString csData;
						csData.Format(_T("%lu"),dwData);
						DrawItemText(&dc, csData, CRectGet(rect.left + width + 220, rect.top, m_nColumnsWidth, rect.bottom), m_nColumnsWidth-rect.left-2, GetColumnAlign(0));

						dc.SelectObject(&fontDC);
					}
					dc.SetTextColor(::GetSysColor (COLOR_WINDOWTEXT));
				}
				else
				{
					CRect m_labelRect;
					GetItemRect(hItem, &m_labelRect, TRUE);
					GetItemRect(hItem, &rect, FALSE);
					if(GetColumnsNum()>1)
					{
						rect.left = min(m_labelRect.left, GetColumnWidth(0));
					}
					else
					{
						rect.left = m_labelRect.left;
					}
					rect.right = m_nColumnsWidth;

					if(pItem->m_Group)
					{
						if(hParent != NULL)
						{
							GetItemRect(hParent, &m_labelRect, TRUE);
						}
						rect.left = m_labelRect.left;
					}

					// If the item is selected, paint the rectangle with the system color
					// COLOR_HIGHLIGHT

					COLORREF m_highlightColor = ::GetSysColor (COLOR_HIGHLIGHT);

					CBrush brush(m_highlightColor);

					CRect imgRect = rect;
					IMAGEINFO imageInfo;
					m_ImageList.GetImageInfo(0, &imageInfo);
					imgRect.right = imageInfo.rcImage.right;

					if(!m_RTL)
					{
						CRect m_Rrect = rect;
						if(ItemHasChildren(hItem))
						{
							m_Rrect.left += imgRect.right;
						}
						dc.FillRect (m_Rrect, &brush);
						// draw a dotted focus rectangle
						dc.DrawFocusRect (m_Rrect);
						//dc.FillRect(rect, &brush);
						//dc.DrawFocusRect(rect);
					}
					else
					{
						CRect m_Rrect = rect;
						m_Rrect.right = m_clientRect.Width() - rect.left;
						m_Rrect.left = m_clientRect.Width() - rect.right;

						dc.FillRect (m_Rrect, &brush);
						// draw a dotted focus rectangle
						dc.DrawFocusRect (m_Rrect);
					}

					pItem = (CRCTLItem *)CTreeCtrl::GetItemData(hItem);
					if(pItem)
					{
						CString sItem = pItem->GetItemText();

						dc.SetBkColor(m_highlightColor);

						dc.SetTextColor(::GetSysColor (COLOR_HIGHLIGHTTEXT));

						if(pItem->m_Bold)
						{
							dc.SelectObject(&boldFontDC);
						}

						if(!pItem->m_Group)
						{
							DrawItemText(&dc, sItem, CRectGet(rect.left+2, rect.top, m_nColumnsWidth, rect.bottom), m_nColumnsWidth, GetColumnAlign(0));
							//DrawItemText(&dc, sItem, CRectGet(rect.left+2, rect.top, GetColumnWidth(0), rect.bottom), GetColumnWidth(0)-rect.left-2, GetColumnAlign(0));
							//DrawItemText(&dc, sItem, CRectGet(rect.left+ width, rect.top, m_nColumnsWidth, rect.bottom), m_nColumnsWidth-rect.left-2, GetColumnAlign(0));
						}
						else
						{
							DrawItemText(&dc, sItem, CRectGet(rect.left+2, rect.top, m_nColumnsWidth, rect.bottom), m_nColumnsWidth, LVCFMT_RIGHT);
							//DrawItemText(&dc, sItem, CRectGet(rect.left+2, rect.top, GetColumnWidth(0), rect.bottom), GetColumnWidth(0)-rect.left-2, LVCFMT_RIGHT);
							//DrawItemText(&dc, sItem, CRectGet(rect.left+ width, rect.top, m_nColumnsWidth, rect.bottom), m_nColumnsWidth-rect.left-2, LVCFMT_RIGHT);
						}

						m_nWidth = 0;
						for(int i=1;i<m_nColumns;i++)
						{
							m_nWidth += GetColumnWidth(i-1);
						//	if(i == 1)
								DrawItemText(&dc, pItem->GetSubstring(i), CRectGet(m_nWidth, rect.top, m_nWidth+GetColumnWidth(i), rect.bottom), GetColumnWidth(i), GetColumnAlign(i));
						}

						if(pItem->m_Bold)
						{
							dc.SelectObject(&fontDC);
						}
						//Draw more info link which point to url
						if(pItem->m_Bold && m_bShowLink)
						{
							// Mrudula: Displaying count for each option
							dc.SelectObject(&boldFontDC);   
							dc.SetTextColor(COUNT_COLOR);
							
							DWORD dwData = pItem->itemData;
							CString csData;
							csData.Format(_T("%lu"),dwData);
							DrawItemText(&dc, csData, CRectGet(rect.left+width + 220, rect.top, m_nColumnsWidth, rect.bottom), m_nColumnsWidth-rect.left-2, GetColumnAlign(0));
							dc.SelectObject(&fontDC);
						}
					}
				}
			}

			hItem = GetNextVisibleItem(hItem);
			n--;
		}

		dc.SelectObject(pFontDC);
	}//try
	catch(...)
	{
		AddLogEntry(_T("Exception caught in  CRCNewTreeListCtrl::OnPaint"));
	}
}//OnPaint

/*-------------------------------------------------------------------------------------
	Function		: ResetVertScrollBar
	In Parameters	: -
					: -
	Out Parameters	: -
	Purpose			: Reset the vertical scroll bar of the tree control.
	Author			: Zuber
--------------------------------------------------------------------------------------*/
void CRCNewTreeListCtrl::ResetVertScrollBar()
{
	//Currently not used.
	return;

	CStatic * st = (CStatic *) GetParent();
	
	CRect m_treeRect;
	GetClientRect(&m_treeRect);

	CRect m_wndRect;
	st->GetClientRect(&m_wndRect);

	CRect m_headerRect;
	m_wndHeader.GetClientRect(&m_headerRect);

	CRect m_barRect;

	m_horScrollBar.GetClientRect(&m_barRect);

	int hmin, hmax;
	m_horScrollBar.GetScrollRange(&hmin, &hmax);

	int vmin, vmax;
	GetScrollRange(SB_VERT, &vmin, &vmax);

	if(! (hmax != 0))
	{ 
		SetWindowPos(&wndTop, 0, 0, m_wndRect.Width(), m_wndRect.Height()-m_headerRect.Height(), SWP_NOMOVE);
	}
	else
	{
		SetWindowPos(&wndTop, 0, 0, m_wndRect.Width(), m_wndRect.Height()-m_barRect.Height()-m_headerRect.Height(), SWP_NOMOVE);
	}

	if((hmax != 0))
	{
		if(! (vmax != 0))
		{
			m_horScrollBar.SetWindowPos(&wndTop, 0, 0, m_wndRect.Width(), m_barRect.Height(), SWP_NOMOVE);

			int nMin, nMax;
			m_horScrollBar.GetScrollRange(&nMin, &nMax);
			if((nMax-nMin) == (GetColumnsWidth()-m_treeRect.Width()+GetSystemMetrics(SM_CXVSCROLL)))
				// i.e.it disappeared because of calling
				// SetWindowPos
			{
				if(nMax - GetSystemMetrics(SM_CXVSCROLL) > 0)
				{
					m_horScrollBar.SetScrollRange(nMin, nMax - GetSystemMetrics(SM_CXVSCROLL));
				}
				else
					// hide the horz scroll bar and update the tree
				{
					m_horScrollBar.EnableWindow(FALSE);

					// we no longer need it, so hide it!
					{
						m_horScrollBar.ShowWindow(SW_HIDE);

						SetWindowPos(&wndTop, 0, 0, m_wndRect.Width(), m_wndRect.Height() - m_headerRect.Height(), SWP_NOMOVE);
						// the tree takes scroll's place
					}

					m_horScrollBar.SetScrollRange(0, 0);

					// set scroll offset to zero
					{
						m_nOffset = 0;
						Invalidate();
						m_wndHeader.GetWindowRect(&m_headerRect);
						int width = ((GetColumnsWidth() / m_wndRect.Width()) + 1) * m_wndRect.Width();
						m_wndHeader.SetWindowPos(&wndTop, m_nOffset, 0, max(width, m_wndRect.Width()), m_headerRect.Height(), SWP_SHOWWINDOW);
					}
				}
			}
		}
		else
		{
			m_horScrollBar.SetWindowPos(&wndTop, 0, 0, m_wndRect.Width() - GetSystemMetrics(SM_CXVSCROLL), m_barRect.Height(), SWP_NOMOVE);

			int nMin, nMax;
			m_horScrollBar.GetScrollRange(&nMin, &nMax);
			if((nMax-nMin) == (GetColumnsWidth()-m_treeRect.Width()-GetSystemMetrics(SM_CXVSCROLL)))
				// i.e.it appeared because of calling
				// SetWindowPos
			{
				m_horScrollBar.SetScrollRange(nMin, nMax + GetSystemMetrics(SM_CXVSCROLL));
			}
		}
	}
	else
	if(vmax != 0)
	{
		if(GetColumnsWidth()>m_treeRect.Width())
			// the vertical scroll bar takes some place
			// and the columns are a bit bigger than the client
			// area but smaller than (client area + vertical scroll width)
		{
			// show the horz scroll bar
			{
				m_horScrollBar.EnableWindow(TRUE);

				m_horScrollBar.ShowWindow(SW_SHOW);

				// the tree becomes smaller
				SetWindowPos(&wndTop, 0, 0, m_wndRect.Width(), m_wndRect.Height()-m_barRect.Height()-m_headerRect.Height(), SWP_NOMOVE);

				m_horScrollBar.SetWindowPos(&wndTop, 0, 0, m_wndRect.Width() - GetSystemMetrics(SM_CXVSCROLL), m_barRect.Height(), SWP_NOMOVE);
			}

			m_horScrollBar.SetScrollRange(0, GetColumnsWidth()-m_treeRect.Width());
		}
	}
}//ResetVertScrollBar

/*-------------------------------------------------------------------------------------
	Function		: OnLButtonDown
	In Parameters	: nFlags	- Indicates whether various virtual keys are down
					: point		- Specifies the x- and y-coordinate of the cursor
	Out Parameters	: -
	Purpose			: Called by the framework when the user presses the left mouse button
	Author			: Zuber
--------------------------------------------------------------------------------------*/
void CRCNewTreeListCtrl::OnLButtonDown(UINT nFlags, CPoint point) 
{
	try
	{
		UINT flags;
		HTREEITEM m_selectedItem = HitTest(point, &flags);
		OutputDebugString(_T("In OnLButtonDown"));
		// Darshan
		// 09-Feb-2009
		// To save application crash when clicked withen tree control but not on a valid row
		if(!m_selectedItem)
			return;

		if((flags & TVHT_ONITEMRIGHT) || (flags & TVHT_ONITEMINDENT) ||
		   (flags & TVHT_ONITEM))
		{
			SelectItem(m_selectedItem);
		}
		if(flags & TVHT_ONITEMSTATEICON)
		{
			int iImage = GetItemState(m_selectedItem, TVIS_STATEIMAGEMASK) >> 12;
			int image = iImage == 1 ? 2 : 1;

			HTREEITEM childItem;
			if(ItemHasChildren(m_selectedItem))
			{
				//change children check states according to parent check state
				bool bCheck = image == 2 ? true : false;
				SetCheckAll(bCheck, m_selectedItem);
			}
			else
			{
				SetItemState(m_selectedItem, INDEXTOSTATEIMAGEMASK(image), TVIS_STATEIMAGEMASK);

				if(image == 2)
					m_nSelectedItems++;
				else
					m_nSelectedItems--;

				HTREEITEM parentItem = GetParentItem(m_selectedItem);
				int parentImage = GetItemState(parentItem, TVIS_STATEIMAGEMASK) >> 12;
				if(parentItem != NULL)
				{
					if(image == 1 && parentImage == 2)
					{
						//uncheck parent even if one child is unchecked
						SetItemState(parentItem, INDEXTOSTATEIMAGEMASK(image), TVIS_STATEIMAGEMASK);
						m_nSelectedItems--;
					}
					else if(image == 2)
					{
						//check for all the child item images and set proper image to parent
						bool allItem = true;
						childItem = GetChildItem(parentItem);
						while(childItem != NULL)
						{
							int img = GetItemState(childItem, TVIS_STATEIMAGEMASK) >> 12;
							if(img == 1)
							{
								allItem = false;
								break;
							}
						//	m_nSelectedItems++;
							childItem = GetNextSiblingItem(childItem);
						}

						if(allItem)
						{
							//set parent checked if all children are checked
							SetItemState(parentItem, INDEXTOSTATEIMAGEMASK(image), TVIS_STATEIMAGEMASK);
							m_nSelectedItems++;
			
						}
					}
				}
			}
		}
		else
		{
			if(m_bShowLink)
			{
				if((GetItemState(m_selectedItem, TVIS_SELECTED) & TVIS_SELECTED))
				{
					if(ItemHasChildren(m_selectedItem))
					{
						CRect rect;
						GetItemRect(m_selectedItem, &rect, FALSE);
						rect.left += 120;//imageInfo.rcImage.right;

					}
				}
			}

		}
		if(!m_RTL)
		{
			if((GetColumnsNum()==0) || (point.x<GetColumnWidth(0)))
			{
				point.x -= m_nOffset;
				m_selectedItem = HitTest(point, &flags);
				if(flags & TVHT_ONITEMBUTTON)
				{
					GetParent()->SendMessage(WM_LBUTTONDOWN);
				}
			}
		}
		else
		{
			CRect m_clientRect;
			GetClientRect(&m_clientRect);

			if((GetColumnsNum()==0) || (point.x>(m_clientRect.Width() - GetColumnWidth(0))))
			{
				point.x = m_clientRect.Width() - point.x;
				point.x -= m_nOffset;
				m_selectedItem = HitTest(point, &flags);
				if(flags & TVHT_ONITEMBUTTON)
				{
					GetParent()->SendMessage(WM_LBUTTONDOWN);
				}
			}
		}

		SetFocus();

		ResetVertScrollBar();

		m_toDrag = FALSE;
		m_idTimer = static_cast<UINT>(SetTimer(1000, 70, NULL));
		OutputDebugString(_T("Out OnLButtonDown"));
		CTreeCtrl::OnLButtonDown(nFlags, point);
	}//try
	catch(...)
	{
		AddLogEntry(_T("Exception caught in  CRCNewTreeListCtrl::OnLButtonDown"));
	}

}//OnLButtonDown

/*-------------------------------------------------------------------------------------
	Function		: OnLButtonDblClk
	In Parameters	: nFlags	- Indicates whether various virtual keys are down
					: point		- Specifies the x- and y-coordinate of the cursor
	Out Parameters	: -
	Purpose			: Called by the framework when the user double-clicks the left
					  mouse button
	Author			: Zuber
--------------------------------------------------------------------------------------*/
void CRCNewTreeListCtrl::OnLButtonDblClk(UINT nFlags, CPoint point) 
{
	try
	{ 
		if((GetColumnsNum()==0) || (point.x<GetColumnWidth(0)))
		{
			CTreeCtrl::OnLButtonDblClk(nFlags, point);
			ResetVertScrollBar();
		}

		SetFocus();

		GetParent()->SendMessage(WM_LBUTTONDBLCLK);
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in  CRCNewTreeListCtrl::OnLButtonDblClk"));
	}

}//OnLButtonDblClk

/*-------------------------------------------------------------------------------------
	Function		: SetItemData
	In Parameters	: hItem  - Specifies the handle of the item whose data is to be set
					: dwData - Application-specific value associated with the item
	Out Parameters	: Nonzero if it is successful
	Purpose			: Sets application-specific value associated with the specified item
	Author			: Zuber
--------------------------------------------------------------------------------------*/
BOOL CRCNewTreeListCtrl::SetItemData(HTREEITEM hItem, DWORD dwData)
{
	try
	{
		if(hItem == NULL)
		{
			return FALSE;
		}

		CRCTLItem *pItem = (CRCTLItem *)CTreeCtrl::GetItemData(hItem);
		if(!pItem)
		{
			return FALSE;
		}
		pItem->itemData = dwData;
		return CTreeCtrl::SetItemData(hItem, (LPARAM)pItem);
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in  CRCNewTreeListCtrl::SetItemData"));
	}
	return FALSE;

}//SetItemData

/*-------------------------------------------------------------------------------------
	Function		: GetItemData
	In Parameters	: hItem - Specifies the handle of the item whose data is to be retrieved
	Out Parameters	: Application-specific value associated with the item
	Purpose			: Retrieves the application-specific value associated with the item
	Author			: Zuber
--------------------------------------------------------------------------------------*/
DWORD CRCNewTreeListCtrl::GetItemData(HTREEITEM hItem) const
{
	try
	{
		if(hItem == NULL)
		{
			return NULL;
		}

		CRCTLItem *pItem = (CRCTLItem *)CTreeCtrl::GetItemData(hItem);
		if(!pItem)
		{
			return NULL;
		}
		return pItem->itemData;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in  CRCNewTreeListCtrl::GetItemData"));
	}
	return 0;
}//GetItemData

/*-------------------------------------------------------------------------------------
	Function		: InsertItem
	In Parameters	: lpszItem		- String containing the text of the item
					: hParent		- Specifies the handle of the parent item
					: hInsertAfter	- Specifies the handle of the item after which
									  the new item is to be inserted
	Out Parameters	: Handle of the new item
	Purpose			: Inserts new item in the tree control
	Author			: Zuber
--------------------------------------------------------------------------------------*/
HTREEITEM CRCNewTreeListCtrl::InsertItem(LPCTSTR lpszItem, HTREEITEM hParent, HTREEITEM hInsertAfter)
{
	try
	{
		CRCTLItem *pItem = new CRCTLItem;
		pItem->InsertItem(lpszItem);
		m_nItems++;

		if((hParent!=NULL) && (hParent!=TVI_ROOT))
		{
			CRCTLItem *pParent = (CRCTLItem *)CTreeCtrl::GetItemData(hParent);
			pParent->m_HasChildren = TRUE;
		}

		HTREEITEM hReturn = CTreeCtrl::InsertItem(TVIF_PARAM|TVIF_TEXT,_T(""), 0, 0, 0, 0, (LPARAM)pItem, hParent, hInsertAfter);

		if(m_RTL)
		{
			RecalcHeaderPosition();
		}

		SetScrollPos(SB_VERT, 0);
		SetItemState(hReturn, INDEXTOSTATEIMAGEMASK(2), TVIS_STATEIMAGEMASK);
		m_nSelectedItems++;
		return hReturn;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in  CRCNewTreeListCtrl::GetItemData"));
	}
	return NULL;

}//InsertItem

/*-------------------------------------------------------------------------------------
	Function		: InsertItem
	In Parameters	: lpszItem		- String containing the text of the item
					: nImage		- Index of the image for the item in the image list
					: nSelectedImage- Index of the item’s selected image in the image list
					: hParent		- Specifies the handle of the parent item
					: hInsertAfter	- Specifies the handle of the item after which
									  the new item is to be inserted
	Out Parameters	: Handle of the new item
	Purpose			: Inserts new item in the tree control
	Author			: Zuber
--------------------------------------------------------------------------------------*/
HTREEITEM CRCNewTreeListCtrl::InsertItem(LPCTSTR lpszItem, int nImage, int nSelectedImage, HTREEITEM hParent, HTREEITEM hInsertAfter)
{
	try
	{
		CRCTLItem *pItem = new CRCTLItem;
		pItem->InsertItem(lpszItem);
		m_nItems++;

		if((hParent!=NULL) && (hParent!=TVI_ROOT))
		{
			CRCTLItem *pParent = (CRCTLItem *)CTreeCtrl::GetItemData(hParent);
			pParent->m_HasChildren = TRUE;
		}

		HTREEITEM hReturn = CTreeCtrl::InsertItem(TVIF_PARAM|TVIF_TEXT|TVIF_IMAGE|TVIF_SELECTEDIMAGE, _T(""), nImage, nSelectedImage, 0, 0, (LPARAM)pItem, hParent, hInsertAfter);
		if(m_RTL)
		{
			RecalcHeaderPosition();
		}
		SetScrollPos(SB_VERT, 0);

		if((CString)lpszItem != _T(""))
		{
			CString csParentItem(lpszItem);
			csParentItem.MakeLower();
			//m_ParentMap.SetAt(csParentItem,(CObject*)hReturn);
		}
		else
			m_iChildCnt++;
		SetItemState(hReturn, INDEXTOSTATEIMAGEMASK(2), TVIS_STATEIMAGEMASK);
		m_nSelectedItems++;
		
		return hReturn;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in  CRCNewTreeListCtrl::SetSubstring"));
	}
	return NULL;

}//SetSubstring

/*-------------------------------------------------------------------------------------
	Function		: InsertItem
	In Parameters	: nMask			- Specifies which attributes to set
					: lpszItem		- String containing the text of the item
					: nImage		- Index of the image for the item in the image list
					: nSelectedImage- Index of the item’s selected image in the image list
					: nState		- Values for the states of the item
					: nStateMask	- States that are to be set
					: lParam		- Application-specific value associated with the item
					: hParent		- Specifies the handle of the parent item
					: hInsertAfter	- Specifies the handle of the item after which
									  the new item is to be inserted
	Out Parameters	: Handle of the new item
	Purpose			: Inserts new item in the tree control
	Author			: Zuber
--------------------------------------------------------------------------------------*/
HTREEITEM CRCNewTreeListCtrl::InsertItem(UINT nMask, LPCTSTR lpszItem, int nImage, int nSelectedImage, UINT nState, UINT nStateMask, LPARAM lParam, HTREEITEM hParent, HTREEITEM hInsertAfter)
{
	try
	{
		CRCTLItem *pItem = new CRCTLItem;
		pItem->InsertItem(lpszItem);
		pItem->itemData = static_cast<DWORD>(lParam);
		m_nItems++;

		if((hParent!=NULL) && (hParent!=TVI_ROOT))
		{
			CRCTLItem *pParent = (CRCTLItem *)CTreeCtrl::GetItemData(hParent);
			pParent->m_HasChildren = TRUE;
		}

		HTREEITEM hReturn = CTreeCtrl::InsertItem(nMask, _T(""), nImage, nSelectedImage, nState, nStateMask, (LPARAM)pItem, hParent, hInsertAfter);
		if(m_RTL)
		{
			RecalcHeaderPosition();
		}

		SetScrollPos(SB_VERT, 0);
		SetItemState(hReturn, INDEXTOSTATEIMAGEMASK(2), TVIS_STATEIMAGEMASK);
		m_nSelectedItems++;
		return hReturn;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in  CRCNewTreeListCtrl::InsertItem"));
	}
	return NULL;
}//InsertItem

/*-------------------------------------------------------------------------------------
	Function		: CopyItem
	In Parameters	: hItem			- Specifies the handle of the item to be copied
					: hParent		- Handle of the item under which the item is to be
									  pasted
					: hInsertAfter	- Handle of the item after which the item is to be
									  pasted
	Out Parameters	: Handle of the pasted item
	Purpose			: Copies and pastes the item in the tree control
	Author			: Zuber
--------------------------------------------------------------------------------------*/
HTREEITEM CRCNewTreeListCtrl::CopyItem(HTREEITEM hItem, HTREEITEM hParent, HTREEITEM hInsertAfter)
{
	try
	{
		if(ItemHasChildren(hItem))
		{
			return NULL;
		}

		TV_ITEM item;
		item.mask = TVIF_IMAGE | TVIF_PARAM | TVIF_SELECTEDIMAGE | TVIF_STATE | TVIF_TEXT;
		item.hItem = hItem;
		GetItem(&item);
		CRCTLItem *pItem = (CRCTLItem *)CTreeCtrl::GetItemData(hItem);
		CRCTLItem *pNewItem = new CRCTLItem(*pItem);

		item.lParam = (LPARAM)pNewItem;

		TV_INSERTSTRUCT insStruct;
		insStruct.item = item;
		insStruct.hParent = hParent;
		insStruct.hInsertAfter = hInsertAfter;

		if((hParent!=NULL) && (hParent!=TVI_ROOT))
		{
			CRCTLItem *pParent = (CRCTLItem *)CTreeCtrl::GetItemData(hParent);
			pParent->m_HasChildren = TRUE;
		}
		
		return CTreeCtrl::InsertItem(&insStruct);
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in  CRCNewTreeListCtrl::CopyItem"));
	}
	return NULL;

}//CopyItem

/*-------------------------------------------------------------------------------------
	Function		: MoveItem
	In Parameters	: hItem			- Handle of the item that is to be moved
					: hParent		- Handle of the item under which the item is to be
									  pasted
					: hInsertAfter	- Handle of the item after which the item is to be
									  pasted
	Out Parameters	: Handle of the pasted item
	Purpose			: Moves the item to a new location in the tree
	Author			: Zuber
--------------------------------------------------------------------------------------*/
HTREEITEM CRCNewTreeListCtrl::MoveItem(HTREEITEM hItem, HTREEITEM hParent, HTREEITEM hInsertAfter)
{
	try
	{
		if(ItemHasChildren(hItem))
		{
			return NULL;
		}

		TV_ITEM item;
		item.mask = TVIF_IMAGE | TVIF_SELECTEDIMAGE | TVIF_STATE;
		item.hItem = hItem;
		GetItem(&item);
		CRCTLItem *pItem = (CRCTLItem *)CTreeCtrl::GetItemData(hItem);
		CRCTLItem *pNewItem = new CRCTLItem(*pItem);

		item.pszText = _T("");
		item.lParam = (LPARAM)pNewItem;
		item.hItem = NULL;

		item.mask |= TVIF_TEXT | TVIF_PARAM;

		TV_INSERTSTRUCT insStruct;
		insStruct.item = item;
		insStruct.hParent = hParent;
		insStruct.hInsertAfter = hInsertAfter;

		if((hParent!=NULL) && (hParent!=TVI_ROOT))
		{
			CRCTLItem *pParent = (CRCTLItem *)CTreeCtrl::GetItemData(hParent);
			pParent->m_HasChildren = TRUE;
		}

		DeleteItem(hItem);
		
		return CTreeCtrl::InsertItem(&insStruct);
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in  CRCNewTreeListCtrl::MoveItem"));
	}
	return NULL;

}//MoveItem

/*-------------------------------------------------------------------------------------
	Function		: SetItemText
	In Parameters	: hItem		- Handle of the item whose text is to be modified
					: nCol		- Column number
					: lpszItem	- New text
	Out Parameters	: Nonzero if it is successful
	Purpose			: Sets the text in a particular column for the tree item
	Author			: Zuber
--------------------------------------------------------------------------------------*/
BOOL CRCNewTreeListCtrl::SetItemText(HTREEITEM hItem, int nCol,LPCTSTR lpszItem)
{
	try
	{
		if(hItem == NULL)
		{
			return FALSE;
		}
		CRCTLItem *pItem = (CRCTLItem *)CTreeCtrl::GetItemData(hItem);
		if(!pItem)
			return FALSE;
		pItem->SetSubstring(nCol, lpszItem);
		return CTreeCtrl::SetItemData(hItem, (LPARAM)pItem);
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in  CRCNewTreeListCtrl::SetItemText"));
	}
	return FALSE;

}//SetItemText

/*-------------------------------------------------------------------------------------
	Function		: SetItemColor
	In Parameters	: hItem			- Handle of the item whose color is to be changed
					: m_newColor	- New color for the item
					: m_bInvalidate	- Specifies whether to invoke paint
	Out Parameters	: TRUE, if successful
	Purpose			: Sets the color for the item
	Author			: Zuber
--------------------------------------------------------------------------------------*/
BOOL CRCNewTreeListCtrl::SetItemColor(HTREEITEM hItem, COLORREF m_newColor, BOOL m_bInvalidate)
{
	try
	{
		if(hItem == NULL)
		{
			return FALSE;
		}

		CRCTLItem *pItem = (CRCTLItem *)CTreeCtrl::GetItemData(hItem);
		if(!pItem)
		{
			return FALSE;
		}
		pItem->m_Color = m_newColor;
		if(!CTreeCtrl::SetItemData(hItem, (LPARAM)pItem))
		{
			return FALSE;
		}
		if(m_bInvalidate)
		{
			Invalidate();
		}
		return TRUE;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in  CRCNewTreeListCtrl::SetItemColor"));
	}
	return FALSE;
}//SetItemColor

/*-------------------------------------------------------------------------------------
	Function		: SetItemPriority
	In Parameters	: hItem			- Handle of the item whose priority is to be changed
					: m_nPriority	- Priority for the item
	Out Parameters	: TRUE, if successful
	Purpose			: Sets the priority for the item, required for sorting
	Author			: Zuber
--------------------------------------------------------------------------------------*/
BOOL CRCNewTreeListCtrl::SetItemPriority(HTREEITEM hItem, int m_nPriority)
{
	try
	{
		if(hItem == NULL)
		{
			return FALSE;
		}

		CRCTLItem *pItem = (CRCTLItem *)CTreeCtrl::GetItemData(hItem);
		if(!pItem)
		{
			return FALSE;
		}
		pItem->m_nPriority = m_nPriority;
		if(!CTreeCtrl::SetItemData(hItem, (LPARAM)pItem))
		{
			return FALSE;
		}
		return TRUE;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in  CRCNewTreeListCtrl::SetItemPriority"));
	}

	return FALSE;
}//SetItemPriority

/*-------------------------------------------------------------------------------------
	Function		: GetItemPriority
	In Parameters	: hItem  - Handle of the item whose priority is required
	Out Parameters	: Priority of the item
	Purpose			: Retrieves the priority of the item
	Author			: Zuber
--------------------------------------------------------------------------------------*/
int CRCNewTreeListCtrl::GetItemPriority(HTREEITEM hItem)
{
	try
	{
		if(hItem == NULL)
		{
			return -1;
		}

		CRCTLItem *pItem = (CRCTLItem *)CTreeCtrl::GetItemData(hItem);
		if(!pItem)
		{
			return -1;
		}
		return pItem->m_nPriority;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in  CRCNewTreeListCtrl::GetItemPriority"));
	}
	return FALSE;
}//GetItemPriority

/*-------------------------------------------------------------------------------------
	Function		: SetItemGroup
	In Parameters	: hItem			- 
					: m_Group		- 
					: m_bInvalidate	- 
	Out Parameters	: -
	Purpose			: -
	Author			: Zuber
--------------------------------------------------------------------------------------*/
BOOL CRCNewTreeListCtrl::SetItemGroup(HTREEITEM hItem, BOOL m_Group, BOOL m_bInvalidate)
{
	try
	{
		if(hItem == NULL)
		{
			return FALSE;
		}

		CRCTLItem *pItem = (CRCTLItem *)CTreeCtrl::GetItemData(hItem);
		if(!pItem)
		{
			return FALSE;
		}
		pItem->m_Group = m_Group;
		Expand(hItem, TVE_EXPAND);
		if(m_bInvalidate)
		{
			Invalidate();
		}
		return TRUE;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in  CRCNewTreeListCtrl::SetItemGroup"));
	}
	return FALSE;
}//SetItemGroup

/*-------------------------------------------------------------------------------------
	Function		: SetItemBold
	In Parameters	: hItem			- Handle of the item whose text is to be shown bold
					: m_Bold		- Specifies if the item is to be bold
					: m_bInvalidate	- Specifies if paint is to be called
	Out Parameters	: TRUE, if successful
	Purpose			: Sets bold font for the text of the item
	Author			: Zuber
--------------------------------------------------------------------------------------*/
BOOL CRCNewTreeListCtrl::SetItemBold(HTREEITEM hItem, BOOL m_Bold, BOOL m_bInvalidate)
{
	try
	{
		if(hItem == NULL)
		{
			return FALSE;
		}

		CRCTLItem *pItem = (CRCTLItem *)CTreeCtrl::GetItemData(hItem);
		if(!pItem)
		{
			return FALSE;
		}
		pItem->m_Bold = m_Bold;
		if(!CTreeCtrl::SetItemData(hItem, (LPARAM)pItem))
		{
			return FALSE;
		}
		if(m_bInvalidate)
		{
			//Invalidate();
		}
		//SetCursor(m_hCursor);
		return TRUE;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in  CRCNewTreeListCtrl::SetItemBold"));
	}
	return FALSE;
}//SetItemBold

/*-------------------------------------------------------------------------------------
	Function		: IsBold
	In Parameters	: hItem - Handle of the item whose font is to be checked
	Out Parameters	: TRUE, if the item font is bold
	Purpose			: Retrieves whether the font is bold for the item
	Author			: Zuber
--------------------------------------------------------------------------------------*/
BOOL CRCNewTreeListCtrl::IsBold(HTREEITEM hItem)
{
	try
	{
		if(hItem == NULL)
		{
			return FALSE;
		}

		CRCTLItem *pItem = (CRCTLItem *)CTreeCtrl::GetItemData(hItem);
		if(!pItem)
		{
			return FALSE;
		}
		return pItem->m_Bold;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in  CRCNewTreeListCtrl::IsBold"));
	}
	return FALSE;
}//IsBold

/*-------------------------------------------------------------------------------------
	Function		: IsGroup
	In Parameters	: hItem -
	Out Parameters	: -
	Purpose			: -
	Author			: Zuber
--------------------------------------------------------------------------------------*/
BOOL CRCNewTreeListCtrl::IsGroup(HTREEITEM hItem)
{
	try
	{
		if(hItem == NULL)
		{
			return FALSE;
		}

		CRCTLItem *pItem = (CRCTLItem *)CTreeCtrl::GetItemData(hItem);
		if(!pItem)
		{
			return FALSE;
		}
		return pItem->m_Group;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in  CRCNewTreeListCtrl::IsBold"));
	}
	return FALSE;
}//IsGroup

/*-------------------------------------------------------------------------------------
	Function		: GetItemText
	In Parameters	: hItem - Handle of the item whose text is required
					: nSubItem - Column number from which the text is required
	Out Parameters	: Text in the column
	Purpose			: Retrieves the text from the column of an item
	Author			: Zuber
--------------------------------------------------------------------------------------*/
CString CRCNewTreeListCtrl::GetItemText(HTREEITEM hItem, int nSubItem)
{
	try
	{
		if(hItem == NULL)
		{
			return _T("");
		}

		CRCTLItem *pItem = (CRCTLItem *)CTreeCtrl::GetItemData(hItem);
		if(!pItem)
		{
			return _T("");
		}

		if(pItem->m_Destructed)
		{
			return _T("");
		}

		return pItem->GetSubstring(nSubItem);
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in  CRCNewTreeListCtrl::GetItemText"));
	}
	return _T("");
}//GetItemText

/*-------------------------------------------------------------------------------------
	Function		: GetItemText
	In Parameters	: nItem		- Index of the item in the tree control
					: nSubItem	- Column number from which the text is required
	Out Parameters	: Text in the column
	Purpose			: Retrieves the text from the column of an item at given index
	Author			: Zuber
--------------------------------------------------------------------------------------*/
CString CRCNewTreeListCtrl::GetItemText(int nItem, int nSubItem)
{
	try
	{
		return GetItemText(GetTreeItem(nItem), nSubItem);
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in  CRCNewTreeListCtrl::GetItemText"));
	}
	return _T("");
}//GetItemText

/*-------------------------------------------------------------------------------------
	Function		: DeleteItem
	In Parameters	: hItem  - Handle of the item which is to be deleted
	Out Parameters	: Nonzero if it is successful
	Purpose			: Deletes the item
	Author			: Zuber
--------------------------------------------------------------------------------------*/
BOOL CRCNewTreeListCtrl::DeleteItem(HTREEITEM hItem)
{
	try
	{
		if(hItem == NULL)
		{
			return FALSE;
		}

		HTREEITEM hOldParent = GetParentItem(hItem);

		CRCTLItem *pItem = (CRCTLItem *)CTreeCtrl::GetItemData(hItem);
		if(!pItem)
		{
			return FALSE;
		}

		

		BOOL bReturn = CTreeCtrl::DeleteItem(hItem);

		if(bReturn)
		{
			if((hOldParent!=TVI_ROOT) && (hOldParent!=NULL))
			{
				CRCTLItem *pOldParent = (CRCTLItem *)CTreeCtrl::GetItemData(hOldParent);
				pOldParent->m_HasChildren = ItemHasChildren(hOldParent);
			}
		}

		--m_nItems;
		m_nSelectedItems--;
		
		delete pItem;
		pItem = NULL;
		
		return bReturn;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in  CRCNewTreeListCtrl::DeleteItem"));
	}
	return FALSE;
}//DeleteItem

/*-------------------------------------------------------------------------------------
	Function		: DeleteItem
	In Parameters	: nItem  - Index of the item to delete
	Out Parameters	: Nonzero if it is successful
	Purpose			: Deletes the item at the index
	Author			: Zuber
--------------------------------------------------------------------------------------*/
BOOL CRCNewTreeListCtrl::DeleteItem(int nItem)
{
	try
	{
		return DeleteItem(GetTreeItem(nItem));
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in  CRCNewTreeListCtrl::DeleteItem"));
	}
	return FALSE;
}//DeleteItem

/*-------------------------------------------------------------------------------------
	Function		: FindParentItem
	In Parameters	: m_title	- Text in the column
					: nCol		- Column number
					: hItem		- Handle of the item
					: itemData	- Application-specific data
	Out Parameters	: Handle of the item
	Purpose			: Finds an item which has m_title at the nCol column.Searches only
					  the parent items
	Author			: Zuber
--------------------------------------------------------------------------------------*/
HTREEITEM CRCNewTreeListCtrl::FindParentItem(CString m_title, int nCol, HTREEITEM hItem, LPARAM itemData)
{
	try
	{
		hItem = NULL;
		/*if(m_ParentMap.GetCount() != 0)
		{
			m_title.MakeLower();
			m_ParentMap.Lookup(m_title,(CObject*&)hItem);
		}
		return hItem;*/

	// Return from 
		if(hItem == NULL)
		{
			hItem = GetRootItem();
		}
		if(itemData==0)
		{
			while((hItem!=NULL) && (GetItemText(hItem, nCol)!=m_title))
			{
				hItem = GetNextSiblingItem(hItem);
			}
		}
		else
		{
			while(hItem!=NULL)
			{ 
				if((GetItemText(hItem, nCol)==m_title) && ((LPARAM)GetItemData(hItem)==itemData))
				{
					break;
				}
				hItem = GetNextSiblingItem(hItem);
			}
		}

		return hItem;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in  CRCNewTreeListCtrl::FindParentItem"));
	}
	return NULL;
}//FindParentItem

/*-------------------------------------------------------------------------------------
	Function		: MemDeleteAllItems
	In Parameters	: hParent  - Handle of the item whose data is to be deleted
	Out Parameters	: -
	Purpose			: Deletes the application-specific data of the item and its children,
					  if any
	Author			: Zuber
--------------------------------------------------------------------------------------*/
void CRCNewTreeListCtrl::MemDeleteAllItems(HTREEITEM hParent)
{
	try
	{
		HTREEITEM hItem = hParent;
		CRCTLItem *pItem;


		while(hItem!=NULL)
		{
			pItem = (CRCTLItem *)CTreeCtrl::GetItemData(hItem);

			if(ItemHasChildren(hItem))
				MemDeleteAllItems(GetChildItem(hItem));

			if(hItem)
				hItem = CTreeCtrl::GetNextSiblingItem(hItem);

			//we should delete the item data only when we are finished with using it 
			//else it will cause disasterous crash to program.: Avinash Bhardwaj

			// Darshan
			// 09-Feb-2009
			// Fixed Memory Leak Generated by Tree Item.
			if(pItem)
			{
				delete pItem;
				pItem = NULL;
			}
		}
		return;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CRCNewTreeListCtrl::MemDeleteAllItems"));
	}
}//MemDeleteAllItems

/*-------------------------------------------------------------------------------------
	Function		: DeleteAllItems
	In Parameters	: -
	Out Parameters	: Nonzero if successful
	Purpose			: Deletes all the items in the tree view
	Author			: Zuber
--------------------------------------------------------------------------------------*/
BOOL CRCNewTreeListCtrl::DeleteAllItems()
{
	BOOL bReturn = FALSE;
	try
	{
		m_bDeletingAllMembers = true;

		//m_ParentMap.RemoveAll();
		m_nSelectedItems = 0;
		m_nItems = 0;
		m_iChildCnt = 0;
		SetRedraw(FALSE);
		BeginWaitCursor();

		MemDeleteAllItems(GetRootItem());
	
		bReturn = CTreeCtrl::DeleteAllItems();

		m_bDeletingAllMembers = false;

		EndWaitCursor();
		SetRedraw(TRUE);
		Invalidate();
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CRCNewTreeListCtrl::DeleteAllItems"));
	}
	return bReturn;
}

/*-------------------------------------------------------------------------------------
	Function		: CompareFunc
	In Parameters	: lParam1	 -
					: lParam2	 -
					: lParamSort -
	Out Parameters	: -
	Purpose			: Application defined callback function that compares the items
					  required for sorting
	Author			: Zuber
--------------------------------------------------------------------------------------*/
int CALLBACK CRCNewTreeListCtrl::CompareFunc(LPARAM lParam1, LPARAM lParam2, LPARAM lParamSort)
{
	try
	{
		int comp;
		CRCTLItem * pItem1 = (CRCTLItem *) lParam1;
		CRCTLItem * pItem2 = (CRCTLItem *) lParam2;

		SSortType * pSortType = (SSortType *) lParamSort;

		if(pSortType->nCol == 0)
		{
			CString strThreat1 = pItem1->GetSubstring(5);
			CString strThreat2 = pItem2->GetSubstring(5);
			int threat1 = strThreat1[ 0 ] - '0';
			int threat2 = strThreat2[ 0 ] - '0';

			comp = 0;
			if(threat1 > threat2)
			{
				comp = 1;
			}
			else
			if(threat1 < threat2)
			{
				comp = -1;
			}
		}
		else
		{
			if(pSortType->m_ParentsOnTop)
			{
				if((pItem1->m_HasChildren) && (! pItem2->m_HasChildren))
				{
					return -1;
				}
				else
				if((pItem2->m_HasChildren) && (! pItem1->m_HasChildren))
				{
					return 1;
				}
			}

			if(pItem1->m_nPriority > pItem2->m_nPriority)
			{
				return -1;
			}
			else
			if(pItem1->m_nPriority < pItem2->m_nPriority)
			{
				return 1;
			}

			CString str1 = pItem1->GetSubstring(pSortType->nCol);
			CString str2 = pItem2->GetSubstring(pSortType->nCol);

			// compare the two strings, but
			// notice:
			// in this case, "xxxx10" comes after "xxxx2"
			{
				CString tmpStr1, tmpStr2;
				int index = str1.FindOneOf(_T("0123456789"));
				if(index != -1)
				{
					tmpStr1 = str1.Right(str1.GetLength() - index);
				}
				index = str2.FindOneOf(_T("0123456789"));
				if(index != -1)
				{
					tmpStr2 = str2.Right(str2.GetLength() - index);
				}

				tmpStr1 = tmpStr1.SpanIncluding(_T("0123456789"));
				tmpStr2 = tmpStr2.SpanIncluding(_T("0123456789"));

				if((tmpStr1 == _T("")) && (tmpStr2 == _T("")))
				{
					comp = str1.CompareNoCase(str2);
				}
				else
				{
					int num1 = _wtoi(tmpStr1);
					int num2 = _wtoi(tmpStr2);

					tmpStr1 = str1.SpanExcluding(_T("0123456789"));
					tmpStr2 = str2.SpanExcluding(_T("0123456789"));

					if(tmpStr1 == tmpStr2)
					{
						if(num1 > num2)
						{
							comp = 1;
						}
						else
						if(num1 < num2)
						{
							comp = -1;
						}
						else
						{
							comp = str1.CompareNoCase(str2);
						}
					}
					else
					{
						comp = str1.CompareNoCase(str2);
					}
				}
			}
		}

		if(! pSortType->bAscending)
		{
			if(comp == 1)
			{
				comp = -1;
			}
			else
			if(comp == -1)
			{
				comp = 1;
			}
		}

		return comp;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CRCNewTreeListCtrl::CompareFunc"));
	}
	return -1;
}//CompareFunc

/*-------------------------------------------------------------------------------------
	Function		: SortItems
	In Parameters	: nCol		 - Column number which is to be sorted
					: bAscending - Ascending/Descending
					: low		 - Handle of the parent item
	Out Parameters	: Nonzero if it is successful
	Purpose			: Sorts the tree view using application defined callback function
	Author			: Zuber
--------------------------------------------------------------------------------------*/
BOOL CRCNewTreeListCtrl::SortItems(int nCol, BOOL bAscending, HTREEITEM low)
{
	try
	{
		TV_SORTCB tSort;
		BOOL m_bReturn = FALSE;

		SSortType *pSortType = new SSortType;
		tSort.lpfnCompare = CompareFunc;
		pSortType->nCol = nCol;
		pSortType->bAscending = bAscending;
		pSortType->m_ParentsOnTop = m_ParentsOnTop;
		tSort.lParam = (LPARAM)pSortType;

		if(nCol > 0)
		{
			HTREEITEM m_ParentItem = GetRootItem();
			while(m_ParentItem != NULL)
			{
				if(ItemHasChildren(m_ParentItem))
				{
					tSort.hParent = m_ParentItem;
					m_bReturn = SortChildrenCB(&tSort);
				}

				m_ParentItem = GetNextSiblingItem(m_ParentItem);
			}
		}
		else
		{
			tSort.hParent = NULL;
			m_bReturn = SortChildrenCB(&tSort);
		}

		delete pSortType;

		return m_bReturn;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CRCNewTreeListCtrl::SortItems"));
	}
	return false;
}//SortItems

/*-------------------------------------------------------------------------------------
	Function		: OnTimer
	In Parameters	: nIDEvent - Specifies the identifier of the timer
	Out Parameters	: -
	Purpose			: Called by framework after each interval specified in the SetTimer
					  method used to install a timer
	Author			: Zuber
--------------------------------------------------------------------------------------*/
void CRCNewTreeListCtrl::OnTimer(UINT_PTR nIDEvent) 
{
	try
	{
		if(nIDEvent == m_idTimer)
		{
			m_toDrag = TRUE;
			KillTimer(m_idTimer);
		}

		CTreeCtrl::OnTimer(nIDEvent);
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CRCNewTreeListCtrl::OnTimer"));
	}
}//OnTimer

/*-------------------------------------------------------------------------------------
	Function		: OnDestroy
	In Parameters	: -
	Out Parameters	: -
	Purpose			: Called by the framework to inform the CWnd object that
					  it is being destroyed
	Author			: Zuber
--------------------------------------------------------------------------------------*/
void CRCNewTreeListCtrl::OnDestroy()
{
	// Darshan
	// 09-Feb-2009
	// Fixed Memory Leak Generated by Tree Item.
	try
	{
		MemDeleteAllItems(GetRootItem());
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CRCNewTreeListCtrl::OnDestroy - MemDeleteAllItems"));
	}

	try
	{
		CTreeCtrl::OnDestroy();
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CRCNewTreeListCtrl::OnDestroy"));
	}
}//OnDestroy

/*-------------------------------------------------------------------------------------
	Function		: Expand
	In Parameters	: hItem - Handle of the item to expand
					: nCode - Type of action to be taken (TVE_COLLAPSE, TVE_COLLAPSERESET,
							  TVE_EXPAND or TVE_TOGGLE)
	Out Parameters	: Nonzero if successful
	Purpose			: Expands or collapses the item
	Author			: Zuber
--------------------------------------------------------------------------------------*/
BOOL CRCNewTreeListCtrl::Expand(HTREEITEM hItem, UINT nCode)
{
	try
	{
		BOOL bReturn = CTreeCtrl::Expand(hItem, nCode);
		return bReturn;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CRCNewTreeListCtrl::Expand"));
	}
	return false;
}//Expand

/*-------------------------------------------------------------------------------------
	Function		: GetChildCount
	In Parameters	: hItem - Item whose child count is required
	Out Parameters	: Total number of children
	Purpose			: Returns the number of children for the hItem if it is not NULL,
					  otherwise the total number of children in the tree view
	Author			: Zuber
--------------------------------------------------------------------------------------*/
int CRCNewTreeListCtrl::GetChildCount(HTREEITEM hItem)
{
	return m_iChildCnt;
}//GetChildCount

/*-------------------------------------------------------------------------------------
	Function		: OnMouseMove
	In Parameters	: nFlags - Indicates whether various virtual keys are down
					: point	 - Specifies the x- and y-coordinate of the cursor
	Out Parameters	: -
	Purpose			: Called by the framework when the mouse cursor or stylus moves.
					  Calls 'ShowHelp' for a spyware
	Author			: Zuber
--------------------------------------------------------------------------------------*/
void CRCNewTreeListCtrl::OnMouseMove(UINT nFlags, CPoint point)
{
	try
	{
		UINT flags;
		HTREEITEM selectedItem = HitTest(point, &flags);

		int count = GetItemCount();
		HTREEITEM ht = GetTreeItem(count - 1);
		if(ht == selectedItem)
		{
			return;
		}

		if(selectedItem != NULL || m_prevSelectedItem != selectedItem)
		{
			m_prevSelectedItem = selectedItem;

			if(! ItemHasChildren(selectedItem))
			{
				selectedItem = GetParentItem(selectedItem);
			}

			int sMin, sMax;
			int pos = GetScrollPos(SB_VERT);
			GetScrollRange(SB_VERT, &sMin, &sMax);

			SetScrollPos(SB_VERT, pos);
		}
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CRCNewTreeListCtrl::OnMouseMove"));
	}
}//OnMouseMove

/*-------------------------------------------------------------------------------------
	Function		: SetCheck
	In Parameters	: hItem  - Handle of the item whose check state is to be changed
					: fCheck - Check state
	Out Parameters	: true if successful
	Purpose			: Modifies the check state of the item
	Author			: Zuber
--------------------------------------------------------------------------------------*/
bool CRCNewTreeListCtrl::SetCheck(HTREEITEM hItem, bool fCheck)
{
	try
	{
		if(hItem == NULL)
		{
			return false;
		}

		int iImage = GetItemState(hItem, TVIS_STATEIMAGEMASK) >> 12;
		int image = fCheck ? 2 :1;

		if(image != iImage)
		{
			SetItemState(hItem, INDEXTOSTATEIMAGEMASK(image), TVIS_STATEIMAGEMASK);
			if(image == 2)
				m_nSelectedItems++;
			else
				m_nSelectedItems--;
		}

		
		return true;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CRCNewTreeListCtrl::SetCheck"));
	}
	return false;
}//SetCheck

/*-------------------------------------------------------------------------------------
	Function		: GetCheck
	In Parameters	: hItem - Handle of the item whose check state is to be retrieved
	Out Parameters	: Check state
	Purpose			: Retrieves the check state of the item
	Author			: Zuber
--------------------------------------------------------------------------------------*/
bool CRCNewTreeListCtrl::GetCheck(HTREEITEM hItem)
{
	try
	{
		if(hItem == NULL)
		{
			return false;
		}

		int iImage = GetItemState(hItem, TVIS_STATEIMAGEMASK) >> 12;
		return iImage == 1 ? false : true;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CRCNewTreeListCtrl::SetCheck"));
	}
	return false;
}//SetCheck

/*-------------------------------------------------------------------------------------
	Function		: SetCheckAll
	In Parameters	: fCheck - Check state
					: hItem  - Handle of the item whose check state is to be modified
	Out Parameters	: true
	Purpose			: Modifies the check state of the item and its children, if item 
					  is not NULL otherwise changes the state of all the items in the
					  tree view
	Author			: Zuber
--------------------------------------------------------------------------------------*/
bool CRCNewTreeListCtrl::SetCheckAll(bool fCheck, HTREEITEM hItem)
{
	try
	{
		int image = fCheck ? 2 : 1;

		if(hItem != NULL)
		{
			//change check states only for the item and its child, if any
			HTREEITEM childItem;
			
			SetItemState(hItem, INDEXTOSTATEIMAGEMASK(image), TVIS_STATEIMAGEMASK);
			if(ItemHasChildren(hItem))
			{
				childItem = GetChildItem(hItem);
				while(childItem != NULL)
				{
					int iImage = GetItemState(childItem, TVIS_STATEIMAGEMASK) >> 12;
					SetItemState(childItem, INDEXTOSTATEIMAGEMASK(image), TVIS_STATEIMAGEMASK);
					childItem = GetNextSiblingItem(childItem);
					if(iImage != image)
					{
						//for child
						if(image == 2)
							m_nSelectedItems++;
						else
							m_nSelectedItems--;
					}
				}
			
			}
			//for parent
			int iImage = GetItemState(hItem, TVIS_STATEIMAGEMASK) >> 12;
			if(iImage != image)
			{
				if(image == 2)
					m_nSelectedItems++;
				else
					m_nSelectedItems--;
			}
		}
		else
		{
			//change check states for all the items in the tree
			HTREEITEM hItem = GetRootItem();
			while(hItem != NULL)
			{
				SetCheckAll(fCheck, hItem);
				hItem = GetNextSiblingItem(hItem);
			}
		}

		return true;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CRCNewTreeListCtrl::SetCheckAll"));
	}
	return false;
}//SetCheckAll

/*-------------------------------------------------------------------------------------
	Function		: OnNMCustomdraw
	In Parameters	: 
					: 
	Out Parameters	: 
	Purpose			: 
	Author			: 
--------------------------------------------------------------------------------------*/
void CRCNewTreeListCtrl::OnNMCustomdraw(NMHDR *pNMHDR, LRESULT *pResult)
{
	try
	{
		NMCUSTOMDRAW * pTVCD = reinterpret_cast<LPNMCUSTOMDRAW>(pNMHDR);

		if (CDDS_PREPAINT == pTVCD->dwDrawStage)
		{
			*pResult = CDRF_NOTIFYITEMDRAW;
		}
		else
		if (CDDS_ITEMPREPAINT == pTVCD->dwDrawStage)
		{
			*pResult = CDRF_NOTIFYPOSTPAINT;
		}
		else
		if(CDDS_ITEMPOSTPAINT == pTVCD->dwDrawStage)
		{
			CRCTLItem * item = (CRCTLItem *) pTVCD->lItemlParam;
			if(item->m_Destructed)
			{
				return;
			}

			if(item)
			{
				HTREEITEM hItem = FindParentItem(item->GetItemText());
				if(hItem)
				{
					CRect imgRect, stImgRect;
					COLORREF rgb;
					IMAGEINFO imageInfo;

					CImageList * stImgList = GetImageList(TVSIL_STATE);
					stImgList->GetImageInfo(0, &imageInfo);
					stImgRect = imageInfo.rcImage;

					CDC * pDC = CDC::FromHandle(pTVCD->hdc);

					GetItemRect(hItem, &imgRect, FALSE);

					CString strThreat = GetItemText(hItem, COLUMN_THREAT_ICON);
					int threat = strThreat[ 0 ] - '0';

					m_ImageList.GetImageInfo(threat, &imageInfo);
					imgRect.right = imageInfo.rcImage.right - imageInfo.rcImage.left;
					int width = imgRect.Width();
					imgRect.left += stImgRect.right + 19 ;
					imgRect.right = imgRect.left + width;

					rgb = m_ImageList.GetBkColor();
					m_ImageList.DrawIndirect(pDC,
											threat,				//the ID of the image you actully want to paint
											imgRect.TopLeft(),
											imgRect.Size(),
											CPoint(0, 0));

					m_ImageList.SetBkColor(rgb);
					*pResult = CDRF_SKIPDEFAULT;	// We've painted everything.
				}
				else
				{
					*pResult = CDRF_NOTIFYITEMDRAW;
				}
			}
		}
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CRCNewTreeListCtrl::OnNMCustomdraw"));
	}
}

/*-------------------------------------------------------------------------------------
	Function		: OnKeyDown
	In Parameters	: nChar		- Specifies the virtual key code of the given key
					: nRepCnt	- Specifies the repeat count
					: nFlags	- Specifies the scan code, key-transition code,
								  previous key state, and context code
	Out Parameters	: -
	Purpose			: Called by the framework when a nonsystem key is pressed
	Author			: Zuber
--------------------------------------------------------------------------------------*/
void CRCNewTreeListCtrl::OnKeyDown(UINT nChar, UINT nRepCnt, UINT nFlags)
{
	
	try
	{
		if(nChar == VK_DOWN || nChar == VK_UP || nChar == VK_NEXT || nChar == VK_PRIOR)
			ResetVertScrollBar();
		CTreeCtrl::OnKeyDown(nChar, nRepCnt, nFlags);
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CRCNewTreeListCtrl::OnKeyDown"));
	}
}

/*-----------------------------------------------------------------------------
	Function		: PreTranslateMessage
	In Parameters	: MSG* : Points to a MSG structure that contains the 
						     message to process.
	Out Parameters	: BOOL :Nonzero if the message was translated and should not be 
							dispatched; 0 if the message was not translated and should 
							be dispatched.
	Purpose		: Used by class CWinApp to translate window messages before they are 
					dispatched to the TranslateMessage and DispatchMessage Windows 
					functions.
	Author		: 
-----------------------------------------------------------------------------*/
BOOL CRCNewTreeListCtrl::PreTranslateMessage(MSG* pMsg)
{
	// TODO: Add your specialized code here and/or call the base class
	try
	{
		return CTreeCtrl::PreTranslateMessage(pMsg);
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CRCNewTreeListCtrl::PreTranslateMessage"));
	}
	return FALSE;
}
/*-------------------------------------------------------------------------------------
	Function		: Expand
	In Parameters	: 
	Out Parameters	: 
	Purpose			: This Functio will expand string
	Author			: 
--------------------------------------------------------------------------------------*/
bool CRCNewTreeListCtrl::Expand(CString csParentItem)
{
	try
	{
		HTREEITEM hParent = NULL;
		hParent = FindParentItem(csParentItem);
		if(hParent != NULL)
		{
			CTreeCtrl::Expand(hParent,TVE_EXPAND);
		}
		return true;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CRCNewTreeListCtrl::Expand"));
	}
	return FALSE;
}
/*-------------------------------------------------------------------------------------
	Function		: OnSetCursor
	In Parameters	: CWnd* : Specifies a pointer to the window that contains the cursor
					: UINT : Specifies the hit-test area code.The hit test determines 
							 the cursor's location.
					: UINT : Specifies the mouse message number.
	Out Parameters	: 
	Purpose			: This Functio will Set Cursor
	Author			: 
--------------------------------------------------------------------------------------*/
BOOL CRCNewTreeListCtrl::OnSetCursor(CWnd* pWnd, UINT nHitTest, UINT message)
{
	try
	{
		return CTreeCtrl::OnSetCursor(pWnd, nHitTest, message);
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CRCNewTreeListCtrl::OnSetCursor"));
	}
	return FALSE;
}

int CRCNewTreeListCtrl::GetColumnsWidth()
{	
	int iOldWidth = m_nColumnsWidth;
	RecalcColumnsWidth();
	int iNewWidth = m_nColumnsWidth;
	if(iNewWidth != iOldWidth)
	{
		m_horScrollBar.Invalidate(FALSE);
		Invalidate();
	}	

	return m_nColumnsWidth;
}