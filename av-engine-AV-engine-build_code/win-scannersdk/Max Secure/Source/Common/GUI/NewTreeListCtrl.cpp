/*======================================================================================
   FILE			: NewTreeListCtrl.cpp
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

#include "stdafx.h"
#include "NewTreeListCtrl.h"
#include "SpyDetectTreeCtrl.h"
#include "ExecuteProcess.h"
#include "SDSystemInfo.h"

#ifdef FIREWALL
#include "RecoverMail.h"
#else
#ifndef DATABACKUP
#include "ScanProgressDlg.h"
#endif
#endif

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*-------------------------------------------------------------------------------------
Function		: CTLItem
In Parameters	: -
Out Parameters	: -
Purpose			: Constructor for class CTLItem
Author			: Zuber
--------------------------------------------------------------------------------------*/
CTLItem::CTLItem()
{
	m_cEnding = _T('Γ');
	m_itemString = _T("");
	m_Bold = FALSE;
	m_Color = ::GetSysColor(COLOR_WINDOWTEXT);
	m_HasChildren = FALSE;
	m_nPriority = 1000;
	m_Group = FALSE;
	m_Destructed = FALSE;

	m_u64DateTime = 0;
	m_lIndex = 0;
	m_itemData = 0; 
	ZeroMemory(&m_PipeDataReg, sizeof(MAX_PIPE_DATA_REG));
	ZeroMemory(m_tchBackupFileName, MAX_PATH*sizeof(TCHAR));
}

/*-------------------------------------------------------------------------------------
Function		: CTLItem
In Parameters	: -
Out Parameters	: -
Purpose			: Copy Constructor for class CTLItem
Author			: Zuber
--------------------------------------------------------------------------------------*/
CTLItem::CTLItem(CTLItem &copyItem)
{
	m_cEnding = copyItem.m_cEnding;
	m_itemString = copyItem.GetItemString();
	m_Bold = copyItem.m_Bold;
	m_Color = copyItem.m_Color;
	m_itemData = copyItem.m_itemData;
	m_HasChildren = copyItem.m_HasChildren;
	m_nPriority = copyItem.m_nPriority;
	m_Group = copyItem.m_Group;
	m_Destructed = copyItem.m_Destructed;
}//CTLItem

CTLItem::~CTLItem()
{
	m_Destructed = TRUE;
}//~CTLItem

/*-------------------------------------------------------------------------------------
Function		: GetSubstring
In Parameters	: m_nSub - Column number
Out Parameters	: Text for a particular column
Purpose			: Retrieves the text for a particular column from tree view
Author			: Zuber
--------------------------------------------------------------------------------------*/
CString CTLItem::GetSubstring(int m_nSub)
{
	if(m_Destructed)
	{
		return _T("");
	}

	CString m_tmpStr(_T(""));
	int i=0, nHits=0;

	int length = m_itemString.GetLength();

	while((i<length) && (nHits<=m_nSub))
	{
		if(m_itemString[i] == m_cEnding)
		{
			nHits++;
		}
		else
			if(nHits == m_nSub)
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
}//GetSubstring

/*-------------------------------------------------------------------------------------
Function		: SetSubstring
In Parameters	: m_nSub  - Column number
: m_sText - Text for the column
Out Parameters	: -
Purpose			: Sets the text for a particular column in the tree view
Author			: Zuber
--------------------------------------------------------------------------------------*/
void CTLItem::SetSubstring(int m_nSub, CString m_sText)
{

	CString m_newStr = _T("");
	if(m_itemString != _T(""))
	{
		if(m_itemString != m_cEnding)
			m_itemString += m_cEnding;
		m_itemString += m_sText;
	}
	else
	{
		m_itemString += m_sText;
		if(m_itemString == _T(""))
		{
			m_newStr = m_itemString;
			m_newStr = m_newStr +  m_cEnding;
			m_itemString = m_newStr;
		}
	}
}//SetSubstring

// CNewTreeListCtrl
/*-------------------------------------------------------------------------------------
Function		: CNewTreeListCtrl
In Parameters	: -
: -
Out Parameters	: -
Purpose			: Constructor for class CNewTreeListCtrl
Author			: Zuber
--------------------------------------------------------------------------------------*/
CNewTreeListCtrl::CNewTreeListCtrl(HMODULE hResDLL): m_hResDLL(hResDLL)
{
	m_bPaint = true;
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
	m_bShowHelp = false;//the default value of this variable is false.: Avinash Bhardwaj
//#ifndef DATABACKUP 
	CBitmap *bitmap;
	BITMAP bm;
	HBITMAP hBitmap = NULL;
	hBitmap = LoadBitmap(m_hResDLL, MAKEINTRESOURCE(IDB_BITMAP_THREAT_CRITICAL));
	
	bitmap = CBitmap::FromHandle(hBitmap);
	bitmap->GetBitmap(&bm);

	m_ImageList.Create(bm.bmWidth, bm.bmHeight, ILC_COLOR24, 3, 3);
	m_ImageList.Add(bitmap,(COLORREF)0x000000);
	bitmap->DeleteObject();

	hBitmap = NULL;
	hBitmap = LoadBitmap(m_hResDLL, MAKEINTRESOURCE(IDB_BITMAP_THREAT_HIGH));
	bitmap = CBitmap::FromHandle(hBitmap);
	m_ImageList.Add(bitmap,(COLORREF)0x000000);
	bitmap->DeleteObject();
	
	hBitmap = NULL;
	hBitmap = LoadBitmap(m_hResDLL, MAKEINTRESOURCE(IDB_BITMAP_THREAT_MEDIUM));
	bitmap = CBitmap::FromHandle(hBitmap);
	m_ImageList.Add(bitmap,(COLORREF)0x000000);
	bitmap->DeleteObject();
	
	hBitmap = NULL;
	hBitmap = LoadBitmap(m_hResDLL, MAKEINTRESOURCE(IDB_BITMAP_THREAT_LOW));
	bitmap = CBitmap::FromHandle(hBitmap);
	m_ImageList.Add(bitmap,(COLORREF)0x000000);
	bitmap->DeleteObject();
	
	#ifndef DATABACKUP 
	hBitmap = NULL;
	hBitmap = LoadBitmap(m_hResDLL, MAKEINTRESOURCE(IDB_BITMAP_THREAT_LOW));
	bitmap = CBitmap::FromHandle(hBitmap);
	m_ImageList.Add(bitmap,(COLORREF)0x000000);
	bitmap->DeleteObject();
	m_hCursor = LoadCursor(m_hResDLL, MAKEINTRESOURCE(IDC_HAND_CURSOR));
	m_bEnableInsPaint = true;
//#else
//	CBitmap *bitmap;
//	BITMAP bm;
//	HBITMAP hBitmap = NULL;
//	hBitmap = LoadBitmap(m_hResDLL, MAKEINTRESOURCE(IDB_BITMAP_FOLDER));
//	
//	bitmap = CBitmap::FromHandle(hBitmap);
//	bitmap->GetBitmap(&bm);
//
//	m_ImageList.Create(bm.bmWidth, bm.bmHeight, ILC_COLOR24, 3, 3);
//	m_ImageList.Add(bitmap,(COLORREF)0x000000);
//	bitmap->DeleteObject();
	#endif
	ResetPaintParams();
}//CNewTreeListCtrl

/*--------------------------------------------------------------------------------------
Function       : SetInsertItemState
In Parameters  : bool bEnablePaint,
Out Parameters : void
Description    : Performance enhancement.To Enable Repaint at the time of insert
Author         : Darshit Kasliwal
--------------------------------------------------------------------------------------*/
void CNewTreeListCtrl::SetInsertItemState(bool bEnablePaint)
{
	m_bEnableInsPaint = bEnablePaint;
}

/*--------------------------------------------------------------------------------------
Function       : ResetPaintParams
In Parameters  :
Out Parameters : void
Description    : Reset the Repainting related params
Author         : Darshit Kasliwal
--------------------------------------------------------------------------------------*/
void CNewTreeListCtrl::ResetPaintParams()
{
	m_bVisibleItemDraw = true;
	m_bRedrawOnInsert = TRUE;
}

/*--------------------------------------------------------------------------------------
Function       : SetRedrawOnInsert
In Parameters  : BOOL bRedraw, BOOL bCheckPrevious,
Out Parameters : void
Description    : Redraws by checking the previoud state
Author         : Darshit Kasliwal
--------------------------------------------------------------------------------------*/
void CNewTreeListCtrl::SetRedrawOnInsert(BOOL bRedraw, BOOL bCheckPrevious)
{
	if(!m_bEnableInsPaint)
	{
		if(bCheckPrevious)
		{
			if(m_bRedrawOnInsert != bRedraw)
			{
				m_bRedrawOnInsert = bRedraw;
				SetRedraw(bRedraw);
				Invalidate(FALSE);
				UpdateWindow();
			}
		}
		else
		{
			m_bRedrawOnInsert = bRedraw;
			SetRedraw(bRedraw);
		}
	}
}

/*-------------------------------------------------------------------------------------
Function		: ~CNewTreeListCtrl
In Parameters	: -
: -
Out Parameters	: -
Purpose			: Destructor for class CNewTreeListCtrl
Author			: Zuber
--------------------------------------------------------------------------------------*/
CNewTreeListCtrl::~CNewTreeListCtrl()
{
}//~CNewTreeListCtrl

BEGIN_MESSAGE_MAP(CNewTreeListCtrl, CTreeCtrl)
	//{{AFX_MSG_MAP(CNewTreeListCtrl)
	ON_WM_PAINT()
	ON_WM_CREATE()
	ON_WM_LBUTTONDOWN()
	ON_WM_LBUTTONDBLCLK()
	ON_WM_TIMER()
	ON_WM_MOUSEMOVE()
	ON_WM_DESTROY()
	ON_NOTIFY_REFLECT(NM_CUSTOMDRAW, OnNMCustomdraw)
	ON_WM_KEYDOWN()
	ON_WM_VSCROLL()
	//}}AFX_MSG_MAP
	ON_WM_SETCURSOR()
	ON_WM_SIZE()
END_MESSAGE_MAP()

// CNewTreeListCtrl message handlers
/*-------------------------------------------------------------------------------------
Function		: OnCreate
In Parameters	: lpCreateStruct - Contains information about the CWnd object being created
Out Parameters	: -
Purpose			: Called by framework when the tree list control is created
Author			: Zuber
--------------------------------------------------------------------------------------*/
int CNewTreeListCtrl::OnCreate(LPCREATESTRUCT lpCreateStruct)
{
	if(CTreeCtrl::OnCreate(lpCreateStruct) == -1)
	{
		return -1;
	}
	return 0;
}

/*-------------------------------------------------------------------------------------
Function		: GetTreeItem
In Parameters	: nItem	- Index of the item
Out Parameters	: Item on the particular index
Purpose			: Returns the handle of the item for a particular index in the tree
control
Author			: Zuber
--------------------------------------------------------------------------------------*/
HTREEITEM CNewTreeListCtrl::GetTreeItem(int nItem)
{
	HTREEITEM m_ParentItem = GetRootItem();
	int m_nCount = 0;

	while((m_ParentItem != NULL) &&(m_nCount < nItem))
	{
		m_nCount ++;
		if(ItemHasChildren(m_ParentItem))
		{
			HTREEITEM childItem = GetChildItem(m_ParentItem);
			while((childItem != NULL) &&(m_nCount < nItem))
			{
				m_nCount ++;
				childItem = GetNextSiblingItem(childItem);
			}
			if(childItem != NULL)
			{
				m_ParentItem = childItem;
				break;
			}
		}
		m_ParentItem = GetNextSiblingItem(m_ParentItem);
	}

	return m_ParentItem;
}//GetTreeItem

/*-------------------------------------------------------------------------------------
Function		: GetAllEntries
In Parameters	: -
Out Parameters	: -
Purpose			: Iterates the tree control from the root
Author			: Zuber
--------------------------------------------------------------------------------------*/
void CNewTreeListCtrl::GetAllEntries()
{
	HTREEITEM hCurSel = GetRootItem();
	while(hCurSel)
	{

		CString str;
		str = (LPCTSTR)GetItemText(hCurSel);
		HTREEITEM hChildItem = GetChildItem(hCurSel);
		while(hChildItem != NULL)
		{
			str = (LPCTSTR)GetItemText (hChildItem,2);
			hChildItem = GetNextItem(hChildItem, TVGN_NEXT);
		}
		hCurSel = GetNextItem(hCurSel, TVGN_NEXT);

	}
}

/*-------------------------------------------------------------------------------------
Function		: GetListItem
In Parameters	: hItem - Handle of the item in the tree control
Out Parameters	: Index of the item in the tree control
Purpose			: Retrieves the index of a item 'hItem' from the tree control
Author			: Zuber
--------------------------------------------------------------------------------------*/
int CNewTreeListCtrl::GetListItem(HTREEITEM hItem)
{
	HTREEITEM m_ParentItem = GetRootItem();
	int m_nCount = 0;

	while((m_ParentItem!=NULL) && (m_ParentItem!=hItem))
	{
		m_nCount ++;
		GetNextSiblingItem(m_ParentItem);
	}

	return m_nCount;
}

/*-------------------------------------------------------------------------------------
Function		: RecalcHeaderPosition
In Parameters	: -
Out Parameters	: -
Purpose			: Calculates and sets the header of the tree control
Author			: Zuber
--------------------------------------------------------------------------------------*/
void CNewTreeListCtrl::RecalcHeaderPosition()
{
	if(m_RTL)
	{
		CRect m_clientRect;
		GetClientRect(&m_clientRect);

		if(GetColumnsWidth() > m_clientRect.Width())
		{
			int m_nOffset = m_clientRect.Width() - GetColumnsWidth();

			CStatic * st =(CStatic *)GetParent();

			int width = ((GetColumnsWidth()/m_clientRect.Width()) +1)*m_clientRect.Width();

			CRect m_wndRect;
			st ->GetClientRect(&m_wndRect);
			CRect m_headerRect;
			m_wndHeader.GetClientRect(&m_headerRect);

			m_wndHeader.SetWindowPos(&wndTop, m_nOffset, 0, max(width,m_wndRect.Width()), m_headerRect.Height(), SWP_SHOWWINDOW);
		}
	}
}

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
int CNewTreeListCtrl::InsertColumn(int nCol, LPCTSTR lpszColumnHeading, int nFormat, int nWidth, int nSubItem)
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

		m_nColumns ++;

		int m_nReturn = m_wndHeader.InsertItem(nCol, &hdi);

		if(m_nColumns == 1)
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

/*-------------------------------------------------------------------------------------
Function		: GetColumnWidth
In Parameters	: nCol  - Column number
Out Parameters	: Column width
Purpose			: Retrieves the column width
Author			: Zuber
--------------------------------------------------------------------------------------*/
int CNewTreeListCtrl::GetColumnWidth(int nCol)
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
		if(nCol == 0 && hItem.cxy < 75)
		{
			hItem.cxy = 75;
		}
		return hItem.cxy;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CNewTreeListCtrl::GetColumnWidth"));
		return 0;
	}
}

/*-------------------------------------------------------------------------------------
Function		: GetColumnAlign
In Parameters	: nCol  - Column number
Out Parameters	: Column allignment
Purpose			: Retrieves the column alligment (LVCFMT_LEFT, LVCFMT_RIGHT
or LVCFMT_CENTER)
Author			: Zuber
--------------------------------------------------------------------------------------*/
int CNewTreeListCtrl::GetColumnAlign(int nCol)
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

/*-------------------------------------------------------------------------------------
Function		: RecalcColumnsWidth
In Parameters	: -
Out Parameters	: -
Purpose			: Calculates the total width of all the columns
Author			: Zuber
--------------------------------------------------------------------------------------*/
void CNewTreeListCtrl::RecalcColumnsWidth()
{
	m_nColumnsWidth = 0;
	for(int i=0;i<m_nColumns;i++)
	{
		m_nColumnsWidth += GetColumnWidth(i);
	}
}

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
void CNewTreeListCtrl::DrawItemText(CDC* pDC, CString text, CRect rect, int nWidth, int nFormat)
{
	// Make sure the text will fit in the prescribed rectangle, and truncate
	// it if it won't.
	BOOL bNeedDots = FALSE;
	int nMaxWidth = nWidth - 4;

	while ((text.GetLength() >0) && (pDC ->GetTextExtent((LPCTSTR)text).cx > (nMaxWidth - 4)))
	{
		text = text.Left (text.GetLength () - 1);
		bNeedDots = TRUE;
	}

	if(bNeedDots)
	{
		if(text.GetLength () >= 1)
		{
			text = text.Left (text.GetLength () - 1);
		}
		if(!m_RTL)
		{
			text += _T("...");
		}
		else
		{
			text = _T("...") + text;
		}
	}

	// Draw the text into the rectangle using MFC's handy CDC::DrawText
	// function.
	rect.right = rect.left + nMaxWidth;
	if(m_RTL)
	{
		rect.right += 4;
		rect.left += 4;
	}

	UINT nStyle = DT_VCENTER | DT_SINGLELINE;
	if(nFormat == LVCFMT_LEFT)
	{
		nStyle |= DT_LEFT;
	}
	else
		if(nFormat == LVCFMT_CENTER)
		{
			nStyle |= DT_CENTER;
		}
		else // nFormat == LVCFMT_RIGHT
		{
			nStyle |= DT_RIGHT;
		}

		if((text.GetLength() >0) && (rect.right>rect.left))
		{
			pDC ->DrawText (text, rect, nStyle);

			CRect clientRect;
			GetClientRect(&clientRect);
			rect.left = 0;
			rect.right = clientRect.Width();
			if(rect.right < GetColumnsWidth())
			{
				rect.right = GetColumnsWidth();
			}

			pDC ->DrawEdge(&rect, BDR_SUNKENINNER, BF_BOTTOM);
		}
}

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
CRect CNewTreeListCtrl::CRectGet(int left, int top, int right, int bottom)
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

/*-------------------------------------------------------------------------------------
Function		: OnPaint
In Parameters	: -
: -
Out Parameters	: -
Purpose			: Handles the paint of the tree control
Author			: Zuber
--------------------------------------------------------------------------------------*/
void CNewTreeListCtrl::OnPaint()
{
	if(m_bPaint == false)
		return;

	CPaintDC dc(this); // device context for painting
	IMAGEINFO imageInfo;
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

	CTLItem *pItem;

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
		//IMAGEINFO imageInfo;

		m_ImageList.GetImageInfo(0, &imageInfo);
		int width = imageInfo.rcImage.right;

		CRect rect;

		UINT selflag = TVIS_SELECTED;

		pItem = (CTLItem *)CTreeCtrl::GetItemData(hItem);

		HTREEITEM hParent = GetParentItem(hItem);
		if(hParent != NULL)
		{
			CTLItem *pParent = (CTLItem *)CTreeCtrl::GetItemData(hParent);
			if(pParent ->m_Group)
			{
				pItem ->m_Group = TRUE;
			}
		}

		if(!(GetItemState(hItem, selflag)& selflag))
		{
			dc.SetBkMode(TRANSPARENT);

			CString sItem = pItem ->GetItemText();

			CRect m_labelRect;
			GetItemRect(hItem, &m_labelRect, TRUE);
			GetItemRect(hItem, &rect, FALSE);
			if(GetColumnsNum() >1)
			{
				rect.left = min(m_labelRect.left, GetColumnWidth(0));
			}
			else
			{
				rect.left = m_labelRect.left;
			}
			rect.right = m_nColumnsWidth;

			if(pItem ->m_Group)
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

			dc.SetTextColor(pItem ->m_Color);

			if(pItem ->m_Bold)
			{
				dc.SelectObject(&boldFontDC);
			}

			if(!pItem ->m_Group)
			{
				//DrawItemText(&dc, sItem, CRectGet(rect.left+2, rect.top, GetColumnWidth(0), rect.bottom), GetColumnWidth(0) -rect.left-2, GetColumnAlign(0));
				DrawItemText(&dc, sItem, CRectGet(rect.left+width, rect.top, m_nColumnsWidth, rect.bottom), m_nColumnsWidth-rect.left-2, GetColumnAlign(0));
			}
			else
			{
				//DrawItemText(&dc, sItem, CRectGet(rect.left+2, rect.top, GetColumnWidth(0), rect.bottom), GetColumnWidth(0) -rect.left-2, LVCFMT_RIGHT);
				DrawItemText(&dc, sItem, CRectGet(rect.left+width, rect.top, m_nColumnsWidth, rect.bottom), m_nColumnsWidth-rect.left-2, LVCFMT_RIGHT);
			}

			m_nWidth = 0;
			for(int i=1;i<m_nColumns;i++)
			{
				//This commneted code is to stop overlapping of 1st column imgs
				//and 2nd column text
				m_nWidth += GetColumnWidth(i-1);
				/*if(i == 1 && m_nWidth < 75)
				{
				m_nWidth = 75;
				}*/
				DrawItemText(&dc, pItem ->GetSubstring(i), CRectGet(m_nWidth, rect.top, m_nWidth+GetColumnWidth(i), rect.bottom), GetColumnWidth(i), GetColumnAlign(i));
			}

			if(pItem ->m_Bold)
			{
				dc.SelectObject(&fontDC);
			}
			//Draw more info link which point to url
			if(pItem ->m_Bold && m_bShowLink)
			{
				dc.SelectObject(&ulFontDC);
				dc.SetTextColor(RGB(0,0,255));
				DrawItemText(&dc, m_csLinkText, CRectGet(rect.left+width + 340, rect.top, m_nColumnsWidth, rect.bottom), m_nColumnsWidth-rect.left-2, GetColumnAlign(0));

				dc.SelectObject(&fontDC);
			}
			dc.SetTextColor(::GetSysColor (COLOR_WINDOWTEXT));
		}
		else
		{
			CRect m_labelRect;
			GetItemRect(hItem, &m_labelRect, TRUE);
			GetItemRect(hItem, &rect, FALSE);
			if(GetColumnsNum() >1)
			{
				rect.left = min(m_labelRect.left, GetColumnWidth(0));
			}
			else
			{
				rect.left = m_labelRect.left;
			}
			rect.right = m_nColumnsWidth;

			if(pItem ->m_Group)
			{
				if(hParent != NULL)
				{
					GetItemRect(hParent, &m_labelRect, TRUE);
				}
				rect.left = m_labelRect.left;
			}

			// If the item is selected, paint the rectangle with the system color
			// COLOR_HIGHLIGHT
			
			COLORREF m_highlightColor = RGB(0,191,255);//::GetSysColor (COLOR_HIGHLIGHT);

			CBrush brush(m_highlightColor);

			CRect imgRect = rect;
			//IMAGEINFO imageInfo;
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

			pItem = (CTLItem *)CTreeCtrl::GetItemData(hItem);
			CString sItem = pItem ->GetItemText();

			dc.SetBkColor(m_highlightColor);

			dc.SetTextColor(::GetSysColor (COLOR_HIGHLIGHTTEXT));

			if(pItem ->m_Bold)
			{
				dc.SelectObject(&boldFontDC);
			}

			if(!pItem ->m_Group)
			{
				DrawItemText(&dc, sItem, CRectGet(rect.left+width, rect.top, m_nColumnsWidth, rect.bottom), m_nColumnsWidth-rect.left-2, GetColumnAlign(0));
			}
			else
			{
				DrawItemText(&dc, sItem, CRectGet(rect.left+width, rect.top, m_nColumnsWidth, rect.bottom), m_nColumnsWidth-rect.left-2, LVCFMT_RIGHT);
			}

			m_nWidth = 0;
			for(int i=1;i<m_nColumns;i++)
			{
				m_nWidth += GetColumnWidth(i-1);
				DrawItemText(&dc, pItem ->GetSubstring(i), CRectGet(m_nWidth, rect.top, m_nWidth+GetColumnWidth(i), rect.bottom), GetColumnWidth(i), GetColumnAlign(i));
			}

			if(pItem ->m_Bold)
			{
				dc.SelectObject(&fontDC);
			}
			//Draw more info link which point to url
			if(pItem ->m_Bold && m_bShowLink )
			{
				dc.SelectObject(&ulFontDC);
				DrawItemText(&dc, m_csLinkText, CRectGet(rect.left+width + 340, rect.top, m_nColumnsWidth, rect.bottom), m_nColumnsWidth-rect.left-2, GetColumnAlign(0));

				dc.SelectObject(&fontDC);
			}
		}

		hItem = GetNextVisibleItem(hItem);
		n--;
	}

	dc.SelectObject(pFontDC);
}

/*-------------------------------------------------------------------------------------
Function		: ResetVertScrollBar
In Parameters	: -
: -
Out Parameters	: -
Purpose			: Reset the vertical scroll bar of the tree control.
Author			: Zuber
--------------------------------------------------------------------------------------*/
void CNewTreeListCtrl::ResetVertScrollBar()
{
	//Currently not used.
	return;

	CStatic * st =(CStatic *)GetParent();
	CRect m_treeRect;
	GetClientRect(&m_treeRect);

	CRect m_wndRect;
	st ->GetClientRect(&m_wndRect);

	CRect m_headerRect;
	m_wndHeader.GetClientRect(&m_headerRect);

	CRect m_barRect;

	m_horScrollBar.GetClientRect(&m_barRect);

	int hmin, hmax;
	m_horScrollBar.GetScrollRange(&hmin, &hmax);

	int vmin, vmax;
	GetScrollRange(SB_VERT, &vmin, &vmax);

	if(!(hmax != 0))
	{
		SetWindowPos(&wndTop, 0, 0, m_wndRect.Width(), m_wndRect.Height() -m_headerRect.Height(), SWP_NOMOVE);
	}
	else
	{
		SetWindowPos(&wndTop, 0, 0, m_wndRect.Width(), m_wndRect.Height() -m_barRect.Height() -m_headerRect.Height(), SWP_NOMOVE);
	}

	if((hmax != 0))
	{
		if(!(vmax != 0))
		{
			m_horScrollBar.SetWindowPos(&wndTop, 0, 0, m_wndRect.Width(), m_barRect.Height(), SWP_NOMOVE);

			int nMin, nMax;
			m_horScrollBar.GetScrollRange(&nMin, &nMax);
			if((nMax-nMin) == (GetColumnsWidth() -m_treeRect.Width() +GetSystemMetrics(SM_CXVSCROLL)))
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
						int width =((GetColumnsWidth()/ m_wndRect.Width()) + 1)* m_wndRect.Width();
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
			if((nMax-nMin) == (GetColumnsWidth() -m_treeRect.Width() -GetSystemMetrics(SM_CXVSCROLL)))
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
			if(GetColumnsWidth() >m_treeRect.Width())
				// the vertical scroll bar takes some place
				// and the columns are a bit bigger than the client
				// area but smaller than (client area + vertical scroll width)
			{
				// show the horz scroll bar
				{
					m_horScrollBar.EnableWindow(TRUE);

					m_horScrollBar.ShowWindow(SW_SHOW);

					// the tree becomes smaller
					SetWindowPos(&wndTop, 0, 0, m_wndRect.Width(), m_wndRect.Height() -m_barRect.Height() -m_headerRect.Height(), SWP_NOMOVE);

					m_horScrollBar.SetWindowPos(&wndTop, 0, 0, m_wndRect.Width() - GetSystemMetrics(SM_CXVSCROLL), m_barRect.Height(), SWP_NOMOVE);
				}

				m_horScrollBar.SetScrollRange(0, GetColumnsWidth() -m_treeRect.Width());
			}
		}
}

/*-------------------------------------------------------------------------------------
Function		: OnLButtonDown
In Parameters	: nFlags	- Indicates whether various virtual keys are down
: point		- Specifies the x- and y-coordinate of the cursor
Out Parameters	: -
Purpose			: Called by the framework when the user presses the left mouse button
Author			: Zuber
--------------------------------------------------------------------------------------*/
void CNewTreeListCtrl::OnLButtonDown(UINT nFlags, CPoint point)
{
	UINT flags = 0;
	HTREEITEM m_selectedItem = HitTest(point, &flags);

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
				else
					if(image == 2)
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
#ifndef DATABACKUP
		if(m_bShowLink)
		{
			if(m_selectedItem)
			{
				if((GetItemState(m_selectedItem, TVIS_SELECTED)& TVIS_SELECTED))
				{
					if(ItemHasChildren(m_selectedItem))
					{
						CRect rect;
						GetItemRect(m_selectedItem, &rect, FALSE);
						IMAGEINFO imageInfo;
						m_ImageList.GetImageInfo(0, &imageInfo);
						rect.left += 120;//imageInfo.rcImage.right;

						if(rect.PtInRect(point))
						{
							CString csURL = GetItemText(m_selectedItem,0);
							if(csURL.Find(_T("GenKeylogger.")) != -1)
							{
								csURL = _T("Keylogger.Generic");
							}
							else if(csURL.Find(_T("GenSSODL")) != -1)
							{
								csURL = _T("GenSSODL");
							}
							else if(csURL.Find(_T("GenBHO.")) != -1)
							{
								csURL = _T("GenBHO");
							}
							else if(csURL.Find(_T("GenSTS.")) != -1)
							{
								csURL = _T("GenSTS");
							}
							else if(csURL.Find(_T("GenToolbar.")) != -1)
							{
								csURL = _T("GenToolbar");
							}
							else if(csURL.Find(_T("GenMenuExt.")) != -1)
							{
								csURL = _T("GenMenuExt");
							}
							else if(csURL.Find(_T("GenSEH.")) != -1)
							{
								csURL = _T("GenSEH");
							}
							else if(csURL.Left(3) == (_T("IP.")))
							{
								csURL = _T("NetworkConnection");
							}

							/*CString csCatName;
							int iFind = csURL.Find(_T("."));
							if(iFind != -1)
							{
								csCatName = csURL.Left(iFind);
								csCatName += _T("/");
							}*/

							
							if (csURL.Find(L"Trojan.Malware.") != -1 && csURL.Find(L".susgen") != -1)
							{
								DWORD	dwSpyID = 0x00;
								CString	csSpyID =  csURL.Trim();
								csSpyID.Replace(L"Trojan.Malware.",L"");
								csSpyID.Replace(L".susgen",L"");
								csSpyID.Trim();

								dwSpyID = _wtol(csSpyID);

								csURL.Format(_T("https://www.thespywaredetector.com/spywareinfo.aspx?ID=%d") ,dwSpyID);
							}
							else
							{
								csURL = _T("https://www.thespywaredetector.com/showspyinfobyname.aspx?query=") + csURL.Trim();
							}
							

							CExecuteProcess objExecuteproc;
							objExecuteproc.LaunchURLInBrowser(csURL);
							
						}
					}
				}
			}
		}
#endif
	}
	if(!m_RTL)
	{
		if((GetColumnsNum() == 0) || (point.x<GetColumnWidth(0)))
		{
			point.x -= m_nOffset;
			m_selectedItem = HitTest(point, &flags);
			if(flags & TVHT_ONITEMBUTTON)
			{
				GetParent() ->SendMessage(WM_LBUTTONDOWN);
			}
		}
	}
	else
	{
		CRect m_clientRect;
		GetClientRect(&m_clientRect);

		if((GetColumnsNum() == 0) || (point.x>(m_clientRect.Width() - GetColumnWidth(0))))
		{
			point.x = m_clientRect.Width() - point.x;
			point.x -= m_nOffset;
			m_selectedItem = HitTest(point, &flags);
			if(flags & TVHT_ONITEMBUTTON)
			{
				GetParent() ->SendMessage(WM_LBUTTONDOWN);
			}
		}
	}

	SetFocus();

	ResetVertScrollBar();

	m_toDrag = FALSE;
	m_idTimer = static_cast<UINT>(SetTimer(1000, 70, NULL));
	SetRedraw(TRUE);
	CTreeCtrl::OnLButtonDown(nFlags, point);
}

/*-------------------------------------------------------------------------------------
Function		: OnLButtonDblClk
In Parameters	: nFlags	- Indicates whether various virtual keys are down
: point		- Specifies the x- and y-coordinate of the cursor
Out Parameters	: -
Purpose			: Called by the framework when the user double-clicks the left
mouse button
Author			: Zuber
--------------------------------------------------------------------------------------*/
void CNewTreeListCtrl::OnLButtonDblClk(UINT nFlags, CPoint point)
{
	if((GetColumnsNum() == 0) || (point.x<GetColumnWidth(0)))
	{
		CTreeCtrl::OnLButtonDblClk(nFlags, point);
		ResetVertScrollBar();
	}
	SetFocus();

	GetParent() ->SendMessage(WM_LBUTTONDBLCLK);
}

/*-------------------------------------------------------------------------------------
Function		: SetItemData
In Parameters	: hItem  - Specifies the handle of the item whose data is to be set
: dwData - Application-specific value associated with the item
Out Parameters	: Nonzero if it is successful
Purpose			: Sets application-specific value associated with the specified item
Author			: Zuber
--------------------------------------------------------------------------------------*/
BOOL CNewTreeListCtrl::SetItemData(HTREEITEM hItem, DWORD dwData)
{
	if(hItem == NULL)
	{
		return FALSE;
	}

	CTLItem *pItem = (CTLItem *)CTreeCtrl::GetItemData(hItem);
	if(!pItem)
	{
		return FALSE;
	}
	pItem ->m_itemData = dwData;
	return CTreeCtrl::SetItemData(hItem, (LPARAM)pItem);
}

/*-------------------------------------------------------------------------------------
Function		: GetItemData
In Parameters	: hItem - Specifies the handle of the item whose data is to be retrieved
Out Parameters	: Application-specific value associated with the item
Purpose			: Retrieves the application-specific value associated with the item
Author			: Zuber
--------------------------------------------------------------------------------------*/
DWORD CNewTreeListCtrl::GetItemData(HTREEITEM hItem)const
{
	if(hItem == NULL)
	{
		return NULL;
	}

	CTLItem *pItem = (CTLItem *)CTreeCtrl::GetItemData(hItem);
	if(!pItem)
	{
		return NULL;
	}
	return pItem ->m_itemData;
}

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
HTREEITEM CNewTreeListCtrl::InsertItem(LPCTSTR lpszItem, HTREEITEM hParent, HTREEITEM hInsertAfter)
{
	CTLItem *pItem = new CTLItem;
	pItem ->InsertItem(lpszItem);
	m_nItems++;

	if((hParent!=NULL) && (hParent!=TVI_ROOT))
	{
		CTLItem *pParent = (CTLItem *)CTreeCtrl::GetItemData(hParent);
		pParent ->m_HasChildren = TRUE;
	}


	HTREEITEM hReturn = CTreeCtrl::InsertItem(TVIF_PARAM|TVIF_TEXT, _T(""), 0, 0, 0, 0, (LPARAM)pItem, hParent, hInsertAfter);

	if(m_RTL)
	{
		RecalcHeaderPosition();
	}

//	SetScrollPos(SB_VERT, 0);
	SetItemState(hReturn, INDEXTOSTATEIMAGEMASK(2), TVIS_STATEIMAGEMASK);
	m_nSelectedItems++;
	return hReturn;
}

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
HTREEITEM CNewTreeListCtrl::InsertItem(LPCTSTR lpszItem, int nImage, int nSelectedImage, HTREEITEM hParent, HTREEITEM hInsertAfter)
{
	CTLItem *pItem = new CTLItem;
	pItem ->InsertItem(lpszItem);
	m_nItems++;
	bool bRedrawFirstChild = false;
	if((hParent!=NULL) && (hParent!=TVI_ROOT))
	{
		CTLItem *pParent = (CTLItem *)CTreeCtrl::GetItemData(hParent);
		if(!pParent ->m_HasChildren)
		{
			bRedrawFirstChild = true;
		}
		pParent ->m_HasChildren = TRUE;
	}
	if(!m_bEnableInsPaint)
	{
		if(m_bVisibleItemDraw)
		{
			int iItemCount = GetItemCount();
			if(iItemCount >= 0)
			{
				if((UINT)iItemCount > (GetVisibleCount() +50))
				{
					m_bVisibleItemDraw = false;
				}
			}
		}
		else
		{
			if(GetItemCount()% INSERT_ITEM_PAINT_COUNT == 0)
			{
				SetRedrawOnInsert(TRUE,true);
			}
			SetRedrawOnInsert(FALSE,true);
		}
	}
	HTREEITEM hReturn = CTreeCtrl::InsertItem(TVIF_PARAM|TVIF_TEXT|TVIF_IMAGE|TVIF_SELECTEDIMAGE, _T(""), nImage, nSelectedImage, 0, 0, (LPARAM)pItem, hParent, hInsertAfter);
	if(m_RTL)
	{
		RecalcHeaderPosition();
	}
//	SetScrollPos(SB_VERT, 0);

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
	if(bRedrawFirstChild)
	{
		SetRedraw();
	}
	return hReturn;
}

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
HTREEITEM CNewTreeListCtrl::InsertItem(UINT nMask, LPCTSTR lpszItem, int nImage, int nSelectedImage, UINT nState, UINT nStateMask, LPARAM lParam, HTREEITEM hParent, HTREEITEM hInsertAfter)
{
	CTLItem *pItem = new CTLItem;
	pItem ->InsertItem(lpszItem);
	pItem ->m_itemData = static_cast<DWORD>(lParam);
	m_nItems++;

	if((hParent!=NULL) && (hParent!=TVI_ROOT))
	{
		CTLItem *pParent = (CTLItem *)CTreeCtrl::GetItemData(hParent);
		pParent ->m_HasChildren = TRUE;
	}

	HTREEITEM hReturn = CTreeCtrl::InsertItem(nMask, _T(""), nImage, nSelectedImage, nState, nStateMask, (LPARAM)pItem, hParent, hInsertAfter);
	if(m_RTL)
	{
		RecalcHeaderPosition();
	}

//	SetScrollPos(SB_VERT, 0);
	SetItemState(hReturn, INDEXTOSTATEIMAGEMASK(2), TVIS_STATEIMAGEMASK);
	m_nSelectedItems++;
	return hReturn;
}

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
HTREEITEM CNewTreeListCtrl::CopyItem(HTREEITEM hItem, HTREEITEM hParent, HTREEITEM hInsertAfter)
{
	if(ItemHasChildren(hItem))
	{
		return NULL;
	}

	TV_ITEM item;
	item.mask = TVIF_IMAGE | TVIF_PARAM | TVIF_SELECTEDIMAGE | TVIF_STATE | TVIF_TEXT;
	item.hItem = hItem;
	GetItem(&item);
	CTLItem *pItem = (CTLItem *)CTreeCtrl::GetItemData(hItem);
	CTLItem *pNewItem = new CTLItem(*pItem);

	item.lParam = (LPARAM)pNewItem;

	TV_INSERTSTRUCT insStruct;
	insStruct.item = item;
	insStruct.hParent = hParent;
	insStruct.hInsertAfter = hInsertAfter;

	if((hParent!=NULL) && (hParent!=TVI_ROOT))
	{
		CTLItem *pParent = (CTLItem *)CTreeCtrl::GetItemData(hParent);
		pParent ->m_HasChildren = TRUE;
	}

	return CTreeCtrl::InsertItem(&insStruct);
}

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
HTREEITEM CNewTreeListCtrl::MoveItem(HTREEITEM hItem, HTREEITEM hParent, HTREEITEM hInsertAfter)
{
	if(ItemHasChildren(hItem))
	{
		return NULL;
	}

	TV_ITEM item;
	item.mask = TVIF_IMAGE | TVIF_SELECTEDIMAGE | TVIF_STATE;
	item.hItem = hItem;
	GetItem(&item);
	CTLItem *pItem = (CTLItem *)CTreeCtrl::GetItemData(hItem);
	CTLItem *pNewItem = new CTLItem(*pItem);

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
		CTLItem *pParent = (CTLItem *)CTreeCtrl::GetItemData(hParent);
		pParent ->m_HasChildren = TRUE;
	}

	DeleteItem(hItem);

	return CTreeCtrl::InsertItem(&insStruct);
}

/*--------------------------------------------------------------------------------------
Function       : GetTLItem
In Parameters  : HTREEITEM hItem,
Out Parameters : CTLItem*
Description    : Wrapper over CTreeCtrl::GetItemData
Author         : Darshit Kasliwal
--------------------------------------------------------------------------------------*/
CTLItem* CNewTreeListCtrl::GetTLItem(HTREEITEM hItem)
{
	return (CTLItem *)CTreeCtrl::GetItemData(hItem);
}

/*--------------------------------------------------------------------------------------
Function       : GetTLItem
In Parameters  : HTREEITEM hItem,
Out Parameters : CTLItem*
Description    : Wrapper over CTreeCtrl::SetItemData
Author         : Darshit Kasliwal
--------------------------------------------------------------------------------------*/
void CNewTreeListCtrl::SetTLItem(HTREEITEM hItem, CTLItem* pTLItem)
{
	CTreeCtrl::SetItemData(hItem, (LPARAM)pTLItem);
}

/*--------------------------------------------------------------------------------------
Function       : GetItemStructure
In Parameters  : HTREEITEM hItem,
Out Parameters : MAX_PIPE_DATA_REG*
Description    : Returns the pointer to the structure associated with the TreeItem
Author         : Darshit Kasliwal
--------------------------------------------------------------------------------------*/
MAX_PIPE_DATA_REG* CNewTreeListCtrl::GetItemStructure(HTREEITEM hItem)
{
	if(hItem == NULL)
		return NULL;

	CTLItem *pItem = (CTLItem *)CTreeCtrl::GetItemData(hItem);

	if(NULL == pItem)
		return FALSE;

	return &pItem->m_PipeDataReg;
}

bool CNewTreeListCtrl::GetItemStructure(HTREEITEM hItem, LPSPY_ENTRY_DETAIL &lpSpyEntry)
{
	if(hItem == NULL)
		return false;

	CTLItem *pItem = (CTLItem *)CTreeCtrl::GetItemData(hItem);

	if(NULL == pItem)
		return false;

	lpSpyEntry = &pItem->m_SpyEntryDetails;
	return true;
}


/*--------------------------------------------------------------------------------------
Function       : SetItemStructure
In Parameters  : HTREEITEM hItem, MAX_PIPE_DATA& sMaxPipeData,
Out Parameters : BOOL
Description    : Assigns the structure pointer to using SetItemData
Author         : Darshit Kasliwal
--------------------------------------------------------------------------------------*/
BOOL CNewTreeListCtrl::SetItemStructure(HTREEITEM hItem, MAX_PIPE_DATA& sMaxPipeData)
{
	if(hItem == NULL)
	{
		return FALSE;
	}

	CTLItem *pItem = (CTLItem *)CTreeCtrl::GetItemData(hItem);

	if(NULL == pItem)
		return FALSE;

	pItem->SetStructure(sMaxPipeData);

	return CTreeCtrl::SetItemData(hItem, (LPARAM)pItem);
}

/*--------------------------------------------------------------------------------------
Function       : SetItemStructure
In Parameters  : HTREEITEM hItem, MAX_PIPE_DATA_REG& sMaxPipeDataReg,
Out Parameters : BOOL
Description    : Assigns the structure pointer to using SetItemData
Author         : Darshit Kasliwal
--------------------------------------------------------------------------------------*/
BOOL CNewTreeListCtrl::SetItemStructure(HTREEITEM hItem, MAX_PIPE_DATA_REG& sMaxPipeDataReg)
{
	if(hItem == NULL)
	{
		return FALSE;
	}

	CTLItem *pItem = (CTLItem *)CTreeCtrl::GetItemData(hItem);

	if(NULL == pItem)
		return FALSE;

	pItem->SetStructure(sMaxPipeDataReg);

	return CTreeCtrl::SetItemData(hItem, (LPARAM)pItem);
}

BOOL CNewTreeListCtrl::SetItemStructure(HTREEITEM hItem, LPSPY_ENTRY_DETAIL pSpyEntryDetails)
{
	if(hItem == NULL)
	{
		return FALSE;
	}

	CTLItem *pItem = (CTLItem *)CTreeCtrl::GetItemData(hItem);

	if(NULL == pItem)
		return FALSE;

	pItem->SetStructure(pSpyEntryDetails);

	return CTreeCtrl::SetItemData(hItem, (LPARAM)pItem);
}

/*--------------------------------------------------------------------------------------
Function       : SetItemBackupFileName
In Parameters  : HTREEITEM hItem, LPTSTR lpszBackup,
Out Parameters : BOOL
Description    : Assigns the Backup file name in the TLItem object
Author         : Darshit Kasliwal
--------------------------------------------------------------------------------------*/
BOOL CNewTreeListCtrl::SetItemBackupFileName(HTREEITEM hItem, LPTSTR lpszBackup)
{
	if(hItem == NULL)
	{
		return FALSE;
	}

	CTLItem *pItem = (CTLItem *)CTreeCtrl::GetItemData(hItem);

	if(NULL == pItem)
		return FALSE;

	_tcscpy_s(pItem->m_tchBackupFileName, lpszBackup);

	return CTreeCtrl::SetItemData(hItem, (LPARAM)pItem);
}

/*--------------------------------------------------------------------------------------
Function       : SetItemDateTime
In Parameters  : HTREEITEM hItem, UINT64 u64DateTime,
Out Parameters : BOOL
Description    : Assigns the Date Time in the TLItem object
Author         : Darshit Kasliwal
--------------------------------------------------------------------------------------*/
BOOL CNewTreeListCtrl::SetItemDateTime(HTREEITEM hItem, UINT64 u64DateTime)
{
	if(hItem == NULL)
	{
		return FALSE;
	}

	CTLItem *pItem = (CTLItem *)CTreeCtrl::GetItemData(hItem);

	if(NULL == pItem)
		return FALSE;

	pItem->m_u64DateTime = u64DateTime;

	return CTreeCtrl::SetItemData(hItem, (LPARAM)pItem);
}

/*--------------------------------------------------------------------------------------
Function       : SetItemIndex
In Parameters  : HTREEITEM hItem, long lIndex,
Out Parameters : BOOL
Description    : Saves the Index in the CTLItem object associated with the TreeCtrl
Author         : Darshit Kasliwal
--------------------------------------------------------------------------------------*/
BOOL CNewTreeListCtrl::SetItemIndex(HTREEITEM hItem, long lIndex, int iRemoveDBType)
{
	if(hItem == NULL)
	{
		return FALSE;
	}

	CTLItem *pItem = (CTLItem *)CTreeCtrl::GetItemData(hItem);

	if(NULL == pItem)
		return FALSE;

	pItem->m_lIndex = lIndex;
	pItem->m_iRemoveDBType = iRemoveDBType;

	return CTreeCtrl::SetItemData(hItem, (LPARAM)pItem);
}

/*--------------------------------------------------------------------------------------
Function       : GetItemBackupFileName
In Parameters  : HTREEITEM hItem,
Out Parameters : LPTSTR
Description    : Assigns the Backupfile name
Author         : Darshit Kasliwal
--------------------------------------------------------------------------------------*/
LPTSTR CNewTreeListCtrl::GetItemBackupFileName(HTREEITEM hItem)
{
	if(hItem == NULL)
		return NULL;

	CTLItem *pItem = (CTLItem *)CTreeCtrl::GetItemData(hItem);

	if(NULL == pItem)
		return NULL;

	return pItem->m_tchBackupFileName;
}

/*--------------------------------------------------------------------------------------
Function       : GetItemDateTime
In Parameters  : HTREEITEM hItem,
Out Parameters : UINT64
Description    : Retrives the Date Time from the CTLItem object using the TreeItem Handle
Author         : Darshit Kasliwal
--------------------------------------------------------------------------------------*/
UINT64 CNewTreeListCtrl::GetItemDateTime(HTREEITEM hItem)
{
	if(hItem == NULL)
		return NULL;

	CTLItem *pItem = (CTLItem *)CTreeCtrl::GetItemData(hItem);

	if(NULL == pItem)
		return NULL;

	return pItem->m_u64DateTime;
}

/*--------------------------------------------------------------------------------------
Function       : GetItemIndex
In Parameters  : HTREEITEM hItem,
Out Parameters : long
Description    : Gets the index of CTLItem object from the TreeCtrl handle
Author         : Darshit Kasliwal
--------------------------------------------------------------------------------------*/
long CNewTreeListCtrl::GetItemIndex(HTREEITEM hItem, int &iRemoveDBType)
{
	if(hItem == NULL)
		return NULL;

	CTLItem *pItem = (CTLItem *)CTreeCtrl::GetItemData(hItem);

	if(NULL == pItem)
		return NULL;

	iRemoveDBType = pItem->m_iRemoveDBType;
	return pItem->m_lIndex;
}


/*-------------------------------------------------------------------------------------
Function		: SetItemText
In Parameters	: hItem		- Handle of the item whose text is to be modified
: nCol		- Column number
: lpszItem	- New text
Out Parameters	: Nonzero if it is successful
Purpose			: Sets the text in a particular column for the tree item
Author			: Zuber
--------------------------------------------------------------------------------------*/
BOOL CNewTreeListCtrl::SetItemText(HTREEITEM hItem, int nCol,LPCTSTR lpszItem)
{
	if(hItem == NULL)
	{
		return FALSE;
	}
	CTLItem *pItem = (CTLItem *)CTreeCtrl::GetItemData(hItem);
	if(!pItem)
		return FALSE;
	pItem->SetSubstring(nCol, lpszItem);
	return CTreeCtrl::SetItemData(hItem, (LPARAM)pItem);
}

/*-------------------------------------------------------------------------------------
Function		: SetItemColor
In Parameters	: hItem			- Handle of the item whose color is to be changed
: m_newColor	- New color for the item
: m_bInvalidate	- Specifies whether to invoke paint
Out Parameters	: TRUE, if successful
Purpose			: Sets the color for the item
Author			: Zuber
--------------------------------------------------------------------------------------*/
BOOL CNewTreeListCtrl::SetItemColor(HTREEITEM hItem, COLORREF m_newColor, BOOL m_bInvalidate)
{
	if(hItem == NULL)
	{
		return FALSE;
	}

	CTLItem *pItem = (CTLItem *)CTreeCtrl::GetItemData(hItem);
	if(!pItem)
	{
		return FALSE;
	}
	pItem ->m_Color = m_newColor;
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

/*-------------------------------------------------------------------------------------
Function		: SetItemPriority
In Parameters	: hItem			- Handle of the item whose priority is to be changed
: m_nPriority	- Priority for the item
Out Parameters	: TRUE, if successful
Purpose			: Sets the priority for the item, required for sorting
Author			: Zuber
--------------------------------------------------------------------------------------*/
BOOL CNewTreeListCtrl::SetItemPriority(HTREEITEM hItem, int m_nPriority)
{
	if(hItem == NULL)
	{
		return FALSE;
	}

	CTLItem *pItem = (CTLItem *)CTreeCtrl::GetItemData(hItem);
	if(!pItem)
	{
		return FALSE;
	}
	pItem ->m_nPriority = m_nPriority;
	if(!CTreeCtrl::SetItemData(hItem, (LPARAM)pItem))
	{
		return FALSE;
	}
	return TRUE;
}

/*-------------------------------------------------------------------------------------
Function		: GetItemPriority
In Parameters	: hItem  - Handle of the item whose priority is required
Out Parameters	: Priority of the item
Purpose			: Retrieves the priority of the item
Author			: Zuber
--------------------------------------------------------------------------------------*/
int CNewTreeListCtrl::GetItemPriority(HTREEITEM hItem)
{
	if(hItem == NULL)
	{
		return -1;
	}

	CTLItem *pItem = (CTLItem *)CTreeCtrl::GetItemData(hItem);
	if(!pItem)
	{
		return -1;
	}
	return pItem ->m_nPriority;
}

/*-------------------------------------------------------------------------------------
Function		: SetItemGroup
In Parameters	: hItem			-
: m_Group		-
: m_bInvalidate	-
Out Parameters	: -
Purpose			: -
Author			: Zuber
--------------------------------------------------------------------------------------*/
BOOL CNewTreeListCtrl::SetItemGroup(HTREEITEM hItem, BOOL m_Group, BOOL m_bInvalidate)
{
	if(hItem == NULL)
	{
		return FALSE;
	}

	CTLItem *pItem = (CTLItem *)CTreeCtrl::GetItemData(hItem);
	if(!pItem)
	{
		return FALSE;
	}
	pItem ->m_Group = m_Group;
	Expand(hItem, TVE_EXPAND);
	if(m_bInvalidate)
	{
		Invalidate();
	}
	return TRUE;
}

/*-------------------------------------------------------------------------------------
Function		: SetItemBold
In Parameters	: hItem			- Handle of the item whose text is to be shown bold
: m_Bold		- Specifies if the item is to be bold
: m_bInvalidate	- Specifies if paint is to be called
Out Parameters	: TRUE, if successful
Purpose			: Sets bold font for the text of the item
Author			: Zuber
--------------------------------------------------------------------------------------*/
BOOL CNewTreeListCtrl::SetItemBold(HTREEITEM hItem, BOOL m_Bold, BOOL m_bInvalidate)
{
	if(hItem == NULL)
	{
		return FALSE;
	}

	CTLItem *pItem = (CTLItem *)CTreeCtrl::GetItemData(hItem);
	if(!pItem)
	{
		return FALSE;
	}
	pItem ->m_Bold = m_Bold;
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

/*-------------------------------------------------------------------------------------
Function		: IsBold
In Parameters	: hItem - Handle of the item whose font is to be checked
Out Parameters	: TRUE, if the item font is bold
Purpose			: Retrieves whether the font is bold for the item
Author			: Zuber
--------------------------------------------------------------------------------------*/
BOOL CNewTreeListCtrl::IsBold(HTREEITEM hItem)
{
	if(hItem == NULL)
	{
		return FALSE;
	}

	CTLItem *pItem = (CTLItem *)CTreeCtrl::GetItemData(hItem);
	if(!pItem)
	{
		return FALSE;
	}
	return pItem ->m_Bold;
}

/*-------------------------------------------------------------------------------------
Function		: IsGroup
In Parameters	: hItem -
Out Parameters	: -
Purpose			: -
Author			: Zuber
--------------------------------------------------------------------------------------*/
BOOL CNewTreeListCtrl::IsGroup(HTREEITEM hItem)
{
	if(hItem == NULL)
	{
		return FALSE;
	}

	CTLItem *pItem = (CTLItem *)CTreeCtrl::GetItemData(hItem);
	if(!pItem)
	{
		return FALSE;
	}
	return pItem ->m_Group;
}

/*-------------------------------------------------------------------------------------
Function		: GetItemText
In Parameters	: hItem - Handle of the item whose text is required
: nSubItem - Column number from which the text is required
Out Parameters	: Text in the column
Purpose			: Retrieves the text from the column of an item
Author			: Zuber
--------------------------------------------------------------------------------------*/
CString CNewTreeListCtrl::GetItemText(HTREEITEM hItem, int nSubItem)
{
	if(hItem == NULL)
	{
		return _T("");
	}

	CTLItem *pItem = (CTLItem *)CTreeCtrl::GetItemData(hItem);
	if(!pItem)
	{
		return _T("");
	}
	return pItem ->GetSubstring(nSubItem);
}

/*-------------------------------------------------------------------------------------
Function		: GetItemText
In Parameters	: nItem		- Index of the item in the tree control
: nSubItem	- Column number from which the text is required
Out Parameters	: Text in the column
Purpose			: Retrieves the text from the column of an item at given index
Author			: Zuber
--------------------------------------------------------------------------------------*/
CString CNewTreeListCtrl::GetItemText(int nItem, int nSubItem)
{
	return GetItemText(GetTreeItem(nItem), nSubItem);
}

/*-------------------------------------------------------------------------------------
Function		: DeleteItem
In Parameters	: hItem  - Handle of the item which is to be deleted
Out Parameters	: Nonzero if it is successful
Purpose			: Deletes the item
Author			: Zuber
--------------------------------------------------------------------------------------*/
BOOL CNewTreeListCtrl::DeleteItem(HTREEITEM hItem)
{
	if(hItem == NULL)
	{
		return FALSE;
	}

	HTREEITEM hOldParent = GetParentItem(hItem);

	CTLItem *pItem = (CTLItem *)CTreeCtrl::GetItemData(hItem);
	if(!pItem)
	{
		return FALSE;
	}


	int m_bReturn = CTreeCtrl::DeleteItem(hItem);

	if(m_bReturn)
	{
		if((hOldParent!=TVI_ROOT) && (hOldParent!=NULL))
		{
			CTLItem *pOldParent = (CTLItem *)CTreeCtrl::GetItemData(hOldParent);
			if(pOldParent)
			{
				pOldParent ->m_HasChildren = ItemHasChildren(hOldParent);
			}
		}
	}

	--m_nItems;
	m_nSelectedItems--;
	//relocated to avoid the crash whil calling CTreeCtrl::DeleteItem
	if(pItem)
	{
		delete pItem;
		pItem = NULL;
	}
	return m_bReturn;
}

/*-------------------------------------------------------------------------------------
Function		: DeleteItem
In Parameters	: nItem  - Index of the item to delete
Out Parameters	: Nonzero if it is successful
Purpose			: Deletes the item at the index
Author			: Zuber
--------------------------------------------------------------------------------------*/
BOOL CNewTreeListCtrl::DeleteItem(int nItem)
{
	return DeleteItem(GetTreeItem(nItem));
}

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
HTREEITEM CNewTreeListCtrl::FindParentItem(CString m_title, int nCol, HTREEITEM hItem, LPARAM itemData)
{

	hItem = NULL;
	//if(m_ParentMap.GetCount() != 0)
	//{
	//	m_title.MakeLower();
	//	m_ParentMap.Lookup(m_title,(CObject*&)hItem);
	//}
	//return hItem;

	// Return from
	if(hItem == NULL)
	{
		hItem = GetRootItem();
	}
	if(itemData == 0)
	{
		while((hItem!=NULL) && (GetItemText(hItem, nCol) !=m_title))
		{
			hItem = GetNextSiblingItem(hItem);
		}
	}
	else
	{
		while(hItem!=NULL)
		{
			if((GetItemText(hItem, nCol) == m_title) && ((LPARAM)GetItemData(hItem) == itemData))
			{
				break;
			}
			hItem = GetNextSiblingItem(hItem);
		}
	}

	return hItem;
}

/*-------------------------------------------------------------------------------------
Function		: MemDeleteAllItems
In Parameters	: hParent  - Handle of the item whose data is to be deleted
Out Parameters	: -
Purpose			: Deletes the application-specific data of the item and its children,
if any
Author			: Zuber
--------------------------------------------------------------------------------------*/
void CNewTreeListCtrl::MemDeleteAllItems(HTREEITEM hParent)
{
	try
	{
		HTREEITEM hItem = hParent;
		CTLItem *pItem;

		while(hItem!=NULL)
		{
			pItem = (CTLItem *)CTreeCtrl::GetItemData(hItem);

			if(ItemHasChildren(hItem))
				MemDeleteAllItems(GetChildItem(hItem));

			if(hItem)
				hItem = CTreeCtrl::GetNextSiblingItem(hItem);

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
		AddLogEntry(_T("Exception caught in  CNewTreeListCtrl::MemDeleteAllItems"));
	}
}

/*-------------------------------------------------------------------------------------
Function		: DeleteAllItems
In Parameters	: -
Out Parameters	: Nonzero if successful
Purpose			: Deletes all the items in the tree view
Author			: Zuber
--------------------------------------------------------------------------------------*/
BOOL CNewTreeListCtrl::DeleteAllItems()
{
	try
	{
		//m_ParentMap.RemoveAll();
		m_nSelectedItems = 0;
		m_nItems = 0;
		m_iChildCnt = 0;
		BOOL m_bReturn = FALSE;
		if(m_hWnd)
		{
			SetRedraw(FALSE);
			BeginWaitCursor();
			MemDeleteAllItems(GetRootItem());
			m_bReturn = CTreeCtrl::DeleteAllItems();
			EndWaitCursor();
			ResetPaintParams();
			SetRedraw(TRUE);
			Invalidate();
		}
		return m_bReturn;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in  CNewTreeListCtrl::DeleteAllItems"));
		return FALSE;
	}
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
int CALLBACK CNewTreeListCtrl::CompareFunc(LPARAM lParam1, LPARAM lParam2, LPARAM lParamSort)
{
	int comp;
	CTLItem * pItem1 =(CTLItem *)lParam1;
	CTLItem * pItem2 =(CTLItem *)lParam2;

	SSortType * pSortType =(SSortType *)lParamSort;

	if(pSortType ->nCol == 0)
	{
		CString strThreat1 = pItem1 ->GetSubstring(5);
		CString strThreat2 = pItem2 ->GetSubstring(5);
		int threat1 = strThreat1[ 0]- '0';
		int threat2 = strThreat2[ 0]- '0';

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
		if(pSortType ->m_ParentsOnTop)
		{
			if((pItem1 ->m_HasChildren) &&(!pItem2 ->m_HasChildren))
			{
				return -1;
			}
			else
				if((pItem2 ->m_HasChildren) &&(!pItem1 ->m_HasChildren))
				{
					return 1;
				}
		}

		if(pItem1 ->m_nPriority > pItem2 ->m_nPriority)
		{
			return -1;
		}
		else
			if(pItem1 ->m_nPriority < pItem2 ->m_nPriority)
			{
				return 1;
			}

			CString str1 = pItem1 ->GetSubstring(pSortType ->nCol);
			CString str2 = pItem2 ->GetSubstring(pSortType ->nCol);

			// compare the two strings, but
			// notice:
			// in this case, _T("xxxx10")comes after _T("xxxx2")
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

				if((tmpStr1 == _T("")) &&(tmpStr2 == _T("")))
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

	if(!pSortType ->bAscending)
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
BOOL CNewTreeListCtrl::SortItems(int nCol, BOOL bAscending, HTREEITEM low)
{
	TV_SORTCB tSort;
	BOOL m_bReturn = FALSE;

	SSortType *pSortType = new SSortType;
	tSort.lpfnCompare = CompareFunc;
	pSortType ->nCol = nCol;
	pSortType ->bAscending = bAscending;
	pSortType ->m_ParentsOnTop = m_ParentsOnTop;
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

/*-------------------------------------------------------------------------------------
Function		: OnTimer
In Parameters	: nIDEvent - Specifies the identifier of the timer
Out Parameters	: -
Purpose			: Called by framework after each interval specified in the SetTimer
method used to install a timer
Author			: Zuber
--------------------------------------------------------------------------------------*/
void CNewTreeListCtrl::OnTimer(UINT_PTR nIDEvent)
{
	if(nIDEvent == m_idTimer)
	{
		m_toDrag = TRUE;
		KillTimer(m_idTimer);
	}

	CTreeCtrl::OnTimer(nIDEvent);
}

/*-------------------------------------------------------------------------------------
Function		: OnDestroy
In Parameters	: -
Out Parameters	: -
Purpose			: Called by the framework to inform the CWnd object that
it is being destroyed
Author			: Zuber
--------------------------------------------------------------------------------------*/
void CNewTreeListCtrl::OnDestroy()
{
	MemDeleteAllItems(GetRootItem());

	CTreeCtrl::OnDestroy();
}

/*-------------------------------------------------------------------------------------
Function		: Expand
In Parameters	: hItem - Handle of the item to expand
: nCode - Type of action to be taken (TVE_COLLAPSE, TVE_COLLAPSERESET,
TVE_EXPAND or TVE_TOGGLE)
Out Parameters	: Nonzero if successful
Purpose			: Expands or collapses the item
Author			: Zuber
--------------------------------------------------------------------------------------*/
BOOL CNewTreeListCtrl::Expand(HTREEITEM hItem, UINT nCode)
{
	BOOL bReturn = CTreeCtrl::Expand(hItem, nCode);
	return bReturn;
}

/*-------------------------------------------------------------------------------------
Function		: GetChildCount
In Parameters	: hItem - Item whose child count is required
Out Parameters	: Total number of children
Purpose			: Returns the number of children for the hItem if it is not NULL,
otherwise the total number of children in the tree view
Author			: Zuber
--------------------------------------------------------------------------------------*/
int CNewTreeListCtrl::GetChildCount(HTREEITEM hItem)
{
	return m_iChildCnt;
}

/*-------------------------------------------------------------------------------------
Function		: OnMouseMove
In Parameters	: nFlags - Indicates whether various virtual keys are down
: point	 - Specifies the x- and y-coordinate of the cursor
Out Parameters	: -
Purpose			: Called by the framework when the mouse cursor or stylus moves.
Calls 'ShowHelp' for a spyware
Author			: Zuber
--------------------------------------------------------------------------------------*/
void CNewTreeListCtrl::OnMouseMove(UINT nFlags, CPoint point)
{
	UINT flags = 0;
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

		if(!ItemHasChildren(selectedItem))
		{
			selectedItem = GetParentItem(selectedItem);
		}

		int sMin, sMax;
		int pos = GetScrollPos(SB_VERT);
		GetScrollRange(SB_VERT, &sMin, &sMax);

		SetScrollPos(SB_VERT, pos);
	}
}

/*-------------------------------------------------------------------------------------
Function		: SetCheck
In Parameters	: hItem  - Handle of the item whose check state is to be changed
: fCheck - Check state
Out Parameters	: true if successful
Purpose			: Modifies the check state of the item
Author			: Zuber
--------------------------------------------------------------------------------------*/
bool CNewTreeListCtrl::SetCheck(HTREEITEM hItem, bool fCheck)
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

/*-------------------------------------------------------------------------------------
Function		: GetCheck
In Parameters	: hItem - Handle of the item whose check state is to be retrieved
Out Parameters	: Check state
Purpose			: Retrieves the check state of the item
Author			: Zuber
--------------------------------------------------------------------------------------*/
bool CNewTreeListCtrl::GetCheck(HTREEITEM hItem)
{
	if(hItem == NULL)
	{
		return false;
	}
	int iImage = GetItemState(hItem, TVIS_STATEIMAGEMASK) >> 12;
	return iImage == 1 ? false : true;
}

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
bool CNewTreeListCtrl::SetCheckAll(bool fCheck, HTREEITEM hItem)
{
	int image = fCheck ? 2 : 1;

	if(hItem != NULL)
	{
		//change check states only for the item and its child, if any
		HTREEITEM childItem;

		int iImageParent = GetItemState(hItem, TVIS_STATEIMAGEMASK) >> 12;
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
		if(iImageParent != image)
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
		HTREEITEM hTreeItem = GetRootItem();
		while(hTreeItem != NULL)
		{
			SetCheckAll(fCheck, hTreeItem);
			hTreeItem = GetNextSiblingItem(hTreeItem);
		}
	}

	return true;
}

void CNewTreeListCtrl::OnNMCustomdraw(NMHDR *pNMHDR, LRESULT *pResult)
{
	NMCUSTOMDRAW * pTVCD = reinterpret_cast<LPNMCUSTOMDRAW>(pNMHDR);

	if(CDDS_PREPAINT == pTVCD ->dwDrawStage)
	{
		*pResult = CDRF_NOTIFYITEMDRAW;
	}
	else
		if(CDDS_ITEMPREPAINT == pTVCD ->dwDrawStage)
		{
			*pResult = CDRF_NOTIFYPOSTPAINT;
		}
		else
			if(CDDS_ITEMPOSTPAINT == pTVCD ->dwDrawStage)
			{
				CTLItem * item = (CTLItem *)pTVCD ->lItemlParam;
				if(item ->m_Destructed)
				{
					return;
				}

				if(item)
				{
					HTREEITEM hItem = FindParentItem(item ->GetItemText());
					if(hItem)
					{
						CRect imgRect, stImgRect;
						COLORREF rgb;
						IMAGEINFO imageInfo;

						CImageList * stImgList = GetImageList(TVSIL_STATE);
						stImgList ->GetImageInfo(0, &imageInfo);
						stImgRect = imageInfo.rcImage;

						CDC * pDC = CDC::FromHandle(pTVCD ->hdc);

						GetItemRect(hItem, &imgRect, FALSE);

						CString strThreat = GetItemText(hItem, 5);
						int threat = strThreat[ 0]- '0';
						int nCount = m_ImageList.GetImageCount();
						m_ImageList.GetImageInfo(threat, &imageInfo);
						imgRect.right = imageInfo.rcImage.right - imageInfo.rcImage.left;
						int width = imgRect.Width();
						imgRect.left += stImgRect.right + 30;
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
void CNewTreeListCtrl::OnKeyDown(UINT nChar, UINT nRepCnt, UINT nFlags)
{
	if(nChar == VK_DOWN || nChar == VK_UP || nChar == VK_NEXT || nChar == VK_PRIOR)
	{
		ResetVertScrollBar();
	}

	CTreeCtrl::OnKeyDown(nChar, nRepCnt, nFlags);
}

/*--------------------------------------------------------------------------------------
Function       : PreTranslateMessage
In Parameters  : MSG* pMsg,
Out Parameters : BOOL
Description    :
Author         :
--------------------------------------------------------------------------------------*/
BOOL CNewTreeListCtrl::PreTranslateMessage(MSG* pMsg)
{
	return CTreeCtrl::PreTranslateMessage(pMsg);
}

/*--------------------------------------------------------------------------------------
Function       : Expand
In Parameters  : CString csParentItem,
Out Parameters : bool
Description    : Wrapper over the CTreeCtrl Expand function
Author         :
--------------------------------------------------------------------------------------*/
bool CNewTreeListCtrl::Expand(CString csParentItem)
{
	HTREEITEM hParent = NULL;
	hParent = FindParentItem(csParentItem);
	if(hParent != NULL)
	{
		CTreeCtrl::Expand(hParent,TVE_EXPAND);
	}
	return true;
}

/*--------------------------------------------------------------------------------------
Function       : OnSetCursor
In Parameters  : CWnd* pWnd, UINT nHitTest, UINT message,
Out Parameters : BOOL
Description    : Override function
Author         :
--------------------------------------------------------------------------------------*/
BOOL CNewTreeListCtrl::OnSetCursor(CWnd* pWnd, UINT nHitTest, UINT message)
{
	return CTreeCtrl::OnSetCursor(pWnd, nHitTest, message);
}

/*--------------------------------------------------------------------------------------
Function       : OnVScroll
In Parameters  : UINT nSBCode, UINT nPos, CScrollBar* pScrollBar,
Out Parameters : void
Description    : Override function for Vertical Scroll.Handling Repaint whenever user scrolls
Author         : Darshit Kasliwal
--------------------------------------------------------------------------------------*/
void CNewTreeListCtrl::OnVScroll(UINT nSBCode, UINT nPos, CScrollBar* pScrollBar)
{
	SetRedrawOnInsert(TRUE,TRUE);
	CTreeCtrl::OnVScroll(nSBCode, nPos, pScrollBar);
}

/*--------------------------------------------------------------------------------------
Function       : OnSize
In Parameters  : UINT nType, int cx, int cy,
Out Parameters : void
Description    : Handling Repaint whenever user resizes
Author         : Darshit Kasliwal
--------------------------------------------------------------------------------------*/
void CNewTreeListCtrl::OnSize(UINT nType, int cx, int cy)
{
	CTreeCtrl::OnSize(nType, cx, cy);
	SetRedrawOnInsert(TRUE,TRUE);
}

/*--------------------------------------------------------------------------------------
Function       : GetColumnsWidth
In Parameters  : -
Out Parameters : int
Description    : Gets the total width of the columns
Author         : Swapnil Lokhande
--------------------------------------------------------------------------------------*/
int CNewTreeListCtrl::GetColumnsWidth()					  
{
	int iOldWidth = m_nColumnsWidth;
	RecalcColumnsWidth();
	int iNewWidth = m_nColumnsWidth;
	if(iNewWidth != iOldWidth)
	{
		Invalidate();
	}
	return m_nColumnsWidth;
};