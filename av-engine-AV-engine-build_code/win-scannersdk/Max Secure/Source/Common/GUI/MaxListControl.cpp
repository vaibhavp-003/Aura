/*======================================================================================
FILE             : MaxListControl.cpp
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
#include "stdafx.h"
#include <shlwapi.h>
#include "MaxListControl.h"
#include "MaxFirewall.h"
#include "memdc.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*-------------------------------------------------------------------------------------
Function		: CMaxListControl
In Parameters	: -
Out Parameters	: -
Purpose			: constructor To initialize the member variables
Author			: Ramkrushna Shelke
--------------------------------------------------------------------------------------*/
CMaxListControl::CMaxListControl()
{
	m_nTotalItems = 0;
	m_nListHeight = 0;
	m_nWndHeight = 0;
	m_nWndWidth = 0;

	m_nSelectedItem = NONE_SELECTED;
	//Create a light pen for border
	m_oPenLight.CreatePen(PS_SOLID, 1, RGB(200, 200, 200));

	m_pFont = CMaxFont::GetMaxFont(TAHOMA, MAXSIZE_NEG11, Normal);
	m_clrBkSelectedItem = RGB(220, 220, 220);
	m_dwExtendedStyles = 0;
	m_bHasFocus = FALSE;
	m_ImageList.Create(16, 16, ILC_COLOR24|ILC_MASK, 4, 4);
	m_ButtonImageList.Create(90, 45, ILC_COLOR24|ILC_MASK, 4, 4);

	CBitmap oBitmap;
	HBITMAP hBitmap = LoadBitmap(AfxGetResourceHandle(), MAKEINTRESOURCE(IDB_BITMAP_USER_OPTION));
	oBitmap.Attach(hBitmap);	
	m_ImageList.Add(&oBitmap, RGB(255, 0, 255));
	oBitmap.Detach();

	hBitmap = LoadBitmap(AfxGetResourceHandle(), MAKEINTRESOURCE(IDB_BITMAP_USEROPTION_OVER));
	oBitmap.Attach(hBitmap);
	m_ImageList.Add(&oBitmap, RGB(255, 0, 255));
	oBitmap.Detach();
	
	/*hBitmap = LoadBitmap(AfxGetResourceHandle(), MAKEINTRESOURCE(IDB_BITMAP_STATUS_OFF));
	oBitmap.Attach(hBitmap);
	m_ButtonImageList.Add(&oBitmap, RGB(255, 0, 255));
	oBitmap.Detach();

	hBitmap = LoadBitmap(AfxGetResourceHandle(), MAKEINTRESOURCE(IDB_BITMAP_STATUS_ON));
	oBitmap.Attach(hBitmap);
	m_ButtonImageList.Add(&oBitmap, RGB(255, 0, 255));
	oBitmap.Detach();*/
	hBitmap = LoadBitmap(AfxGetResourceHandle(), MAKEINTRESOURCE(IDB_BITMAP_NEWOFF_BTN));
	oBitmap.Attach(hBitmap);
	m_ButtonImageList.Add(&oBitmap, RGB(0, 0, 0));
	oBitmap.Detach();

	hBitmap = LoadBitmap(AfxGetResourceHandle(), MAKEINTRESOURCE(IDB_BITMAP_NEWON_BTN));
	oBitmap.Attach(hBitmap);
	m_ButtonImageList.Add(&oBitmap, RGB(0, 0, 0));
	oBitmap.Detach();

	m_pImageList = NULL;
	m_nControlID = 0;
}

/*-------------------------------------------------------------------------------------
Function		: ~CMaxListControl
In Parameters	: -
Out Parameters	: -
Purpose			: destructor To free the memory
Author			: Ramkrushna Shelke
--------------------------------------------------------------------------------------*/
CMaxListControl::~CMaxListControl()
{
	DeleteAllItems();
	if(m_pFont)
	{
		delete m_pFont;
		m_pFont = NULL;
	}
}


BEGIN_MESSAGE_MAP(CMaxListControl, CWnd)
	//{{AFX_MSG_MAP(CMaxListControl)
	ON_WM_PAINT()
	ON_WM_ERASEBKGND()
	ON_WM_LBUTTONDOWN()
	ON_WM_VSCROLL()
	ON_WM_SIZE()
	ON_WM_SETFOCUS()
	ON_WM_KILLFOCUS()
	ON_WM_GETDLGCODE()
	ON_WM_KEYDOWN()
	ON_WM_RBUTTONDOWN()
	ON_WM_LBUTTONDBLCLK()
	ON_WM_DESTROY()
	ON_WM_SETCURSOR()
	//}}AFX_MSG_MAP
	ON_WM_MOUSEWHEEL()
END_MESSAGE_MAP()


/*-------------------------------------------------------------------------------------
Function		: Create
In Parameters	: CWnd * - pointer To parent window
				  CRect - area To draw
				  DWORD - style
Out Parameters	: bool
Purpose			: To create the HTML ListCtrl
Author			: Ramkrushna Shelke
--------------------------------------------------------------------------------------*/
BOOL CMaxListControl::Create(CWnd *pParent, CRect oRc, UINT nID, DWORD dwStyle)
{
	//Get a New Class Name
	CString sWindowClassName = ::AfxRegisterWndClass(CS_DBLCLKS);

	//Try To create it with default styles
	if(!CWnd::Create(sWindowClassName, _T("HTMLListCtrl"), dwStyle, oRc, pParent, nID))
	{
		return FALSE;
	}

	m_nControlID = nID;
	m_nWndWidth = oRc.Width();
	m_nWndHeight = oRc.Height();
	m_nListHeight = 0;

	//Set the scrolling oScrollInfo
	SCROLLINFO oScrollInfo;
	oScrollInfo.cbSize = sizeof(oScrollInfo);

	oScrollInfo.fMask = SIF_PAGE|SIF_RANGE;
	oScrollInfo.nMax = 0;
	oScrollInfo.nMin = 0;
	oScrollInfo.nPage = 0;
	oScrollInfo.nPos = 0;
	SetScrollInfo(SB_VERT, &oScrollInfo);

	return TRUE;
}

/*-------------------------------------------------------------------------------------
Function		: InsertItem
In Parameters	: CString - text
				  UINT - image
				  int - style
				  int - height
Out Parameters	: int
Purpose			: To insert item in the HTML ListCtrl
Author			: Ramkrushna Shelke
--------------------------------------------------------------------------------------*/
int CMaxListControl::InsertItem(CString sText, UINT uiImage, int nStyle, int nHeight)
{
	//Allocate memory
	HTMLLIST_ITEM *pItem = new HTMLLIST_ITEM;
	pItem->sItemText = sText;
	pItem->nStyle = nStyle;
	pItem->nItemNo = m_nTotalItems;
	pItem->uiImage = uiImage;
	pItem->bStatus = 0;

	if(nHeight == AUTO)
	{
		//Calculate items height
		pItem->nHeight = CalculateItemHeight(sText, nStyle, uiImage, m_nWndWidth);
		pItem->bHeightSpecified = FALSE;
	}
	else
	{
		pItem->nHeight = nHeight;
		pItem->bHeightSpecified = TRUE;
	}
	
	m_oListItems.AddTail(pItem);
	m_nTotalItems ++;
	m_nListHeight += pItem->nHeight;

	SCROLLINFO oScrollInfo;
	oScrollInfo.cbSize = sizeof(oScrollInfo);
	oScrollInfo.fMask = SIF_PAGE|SIF_RANGE;
	oScrollInfo.nMax = m_nListHeight;
	oScrollInfo.nMin = 0;
	oScrollInfo.nPage = m_nWndHeight;
	oScrollInfo.nPos = 0;
	SetScrollInfo(SB_VERT, &oScrollInfo);

	m_oMapItems.SetAt(pItem->nItemNo, pItem);

	return (m_nTotalItems - 1);
}

/*-------------------------------------------------------------------------------------
Function		: CalculateItemHeight
In Parameters	: CString - text
				  UINT - image
				  int - style
				  int - width of item
Out Parameters	: int
Purpose			: To calculate item height
Author			: Ramkrushna Shelke
--------------------------------------------------------------------------------------*/
int CMaxListControl::CalculateItemHeight(CString sText, int nStyle, UINT uiImage, int nItemWidth)
{
	int nImageWidth = 0, nImageHeight = 0;
	int nPadding = ITEM_PADDING_LEFT; //default space

	if(m_dwExtendedStyles & HTMLLIST_STYLE_IMAGES)
	{
		if(m_pImageList)
		{
			if(m_pImageList->GetImageCount())
			{
				IMAGEINFO Info = {0};
				if(m_pImageList->GetImageInfo(uiImage, &Info))
				{
					nImageHeight = Info.rcImage.bottom - Info.rcImage.top;
					nImageWidth = Info.rcImage.right - Info.rcImage.left;
					nImageWidth += (ITEM_IMAGE_PADDING_LEFT + ITEM_IMAGE_PADDING_RIGHT);
					return nImageHeight + 15;
				}
			}
		}
	}

	if(m_dwExtendedStyles & HTMLLIST_STYLE_CHECKBOX)
	{
		nPadding += ITEM_PADDING_CHECKBOX_LEFT + ITEM_CHECKBOX_WIDTH;
	}

	CFont *pOldFont = NULL;
	if(nStyle == NORMAL_TEXT)
	{
		CDC *pDC = GetDC();

		if(m_pFont)
			pOldFont = pDC->SelectObject(m_pFont);
		CRect oRc;
		oRc.SetRectEmpty();
		oRc.left = 0;
		oRc.right = nItemWidth - nPadding;
		oRc.right -= nImageWidth;
		pDC->DrawText(sText, &oRc, DT_WORDBREAK|DT_CALCRECT|DT_EXTERNALLEADING);
		if(pOldFont)
			pDC->SelectObject(pOldFont);
		ReleaseDC(pDC);
		return oRc.Height() + ITEM_PADDING_BOTTOM + ITEM_PADDING_TOP;
	}
	else if(nStyle == HTML_TEXT)
	{
		CDC *pDC = GetDC();
		CDC oMemDC;
		oMemDC.CreateCompatibleDC(pDC);
		if(m_pFont)
			pOldFont = oMemDC.SelectObject(m_pFont);
		int nWidth = 0;
		nWidth = nItemWidth - nPadding;
		nWidth -= nImageWidth;

		CRect oRc(0, 0, nWidth, m_nWndHeight);

		DrawHTML(oMemDC.GetSafeHdc(), sText, sText.GetLength(), &oRc, DT_LEFT|DT_CALCRECT|DT_WORDBREAK|DT_EXTERNALLEADING);
		if(pOldFont)
			oMemDC.SelectObject(pOldFont);
		ReleaseDC(pDC);
		return oRc.Height() + ITEM_PADDING_BOTTOM + ITEM_PADDING_TOP;
	}
	else if(nStyle == SINGLE_LINE_TEXT)
	{
		CDC *pDC = GetDC();
		if(m_pFont)
			pOldFont = pDC->SelectObject(m_pFont);
		CRect oRc;
		oRc.SetRectEmpty();
		oRc.left = 0;
		oRc.right = nItemWidth - nPadding;
		oRc.right -= nImageWidth;

		pDC->DrawText(sText, &oRc, DT_VCENTER|DT_CALCRECT|DT_SINGLELINE);

		if(pOldFont)
			pDC->SelectObject(pOldFont);
		ReleaseDC(pDC);
		return oRc.Height() + ITEM_PADDING_BOTTOM + ITEM_PADDING_TOP;
	}
	return 0;
}

/*-------------------------------------------------------------------------------------
Function		: DeleteAllItems
In Parameters	: void
Out Parameters	: void
Purpose			: To delete all items from list control
Author			: Ramkrushna Shelke
--------------------------------------------------------------------------------------*/
void CMaxListControl::DeleteAllItems()
{
	m_nListHeight = 0;
	m_nTotalItems = 0;

	POSITION pos = m_oListItems.GetHeadPosition();
	for(int i = 0;i < m_oListItems.GetCount();i++)
	{
		HTMLLIST_ITEM *pItem = m_oListItems.GetNext(pos);
		delete pItem;
	}
	m_oListItems.RemoveAll();
	m_oMapItems.RemoveAll();
}

/*-------------------------------------------------------------------------------------
Function		: GetItemData
In Parameters	: int - position
Out Parameters	: LPARAM - item data
Purpose			: To get the item data
Author			: Ramkrushna Shelke
--------------------------------------------------------------------------------------*/
LPARAM CMaxListControl::GetItemData(int nPos)
{
	HTMLLIST_ITEM* pItem = GetInternalData(nPos);
	if(pItem)
	{
		return pItem->lItemData;
	}
	else
	{
		return NULL;
	}
}

/*-------------------------------------------------------------------------------------
Function		: SetItemData
In Parameters	: int - position, LPARAM - item data
Out Parameters	: void
Purpose			: To get the item data
Author			: Ramkrushna Shelke
--------------------------------------------------------------------------------------*/
void CMaxListControl::SetItemData(int nPos, LPARAM lItemData)
{
	HTMLLIST_ITEM* pItem = GetInternalData(nPos);
	if(pItem)
	{
		pItem->lItemData = lItemData;
	}
}

/*-------------------------------------------------------------------------------------
Function		: OnPaint
In Parameters	: void
Out Parameters	: void
Purpose			: To paint the list
Author			: Ramkrushna Shelke
--------------------------------------------------------------------------------------*/
void CMaxListControl::OnPaint()
{
	CPaintDC dc(this); // device context for painting

	CMaxMemDC pDC(&dc);
	CFont *pOldFont = NULL;
	if(m_pFont)
//		pOldFont = pDC->SelectObject(m_pFont);
//	pOldFont = pDC->SelectObject(theApp.m_pSize20NormalFont);
pOldFont = pDC->SelectObject(theApp.m_pSize18NormalFont);


	CRect oRcWnd;
	GetClientRect(&oRcWnd);
	CRect rcItem = oRcWnd;
	rcItem.bottom = 0;
	int nScrollPos = GetScrollPos(SB_VERT);
	rcItem.OffsetRect(0, -nScrollPos);

	POSITION pos = m_oListItems.GetHeadPosition();
	for(int i = 0;i < m_oListItems.GetCount();i++)
	{
		HTMLLIST_ITEM *pItem = m_oListItems.GetNext(pos);
		//Create the bounding rect for item
		rcItem.bottom = rcItem.top + pItem->nHeight;
		if(i == m_nSelectedItem)
		{
			//Call the virtual function for drawing the item
			DrawItem(pDC, rcItem, pItem, TRUE);
		}
		else
		{
			DrawItem(pDC, rcItem, pItem, FALSE);
		}

		pItem->rcItem = rcItem;
		//Move rcItem To next item
		rcItem.OffsetRect(0, pItem->nHeight);
	}

	//Release GDI stuff
	if(pOldFont)
		pDC->SelectObject(pOldFont);
}

/*-------------------------------------------------------------------------------------
Function		: OnEraseBkgnd
In Parameters	: CDC* - pointer To device context
Out Parameters	: bool
Purpose			: Erase background msg handler
Author			: Ramkrushna Shelke
--------------------------------------------------------------------------------------*/
BOOL CMaxListControl::OnEraseBkgnd(CDC* pDC)
{
	return TRUE;
}

/*-------------------------------------------------------------------------------------
Function		: OnLButtonDown
In Parameters	: UINT - flags, CPoint - point
Out Parameters	: void
Purpose			: To handle the LButton down msg
Author			: Ramkrushna Shelke
--------------------------------------------------------------------------------------*/
void CMaxListControl::OnLButtonDown(UINT nFlags, CPoint point)
{
	SetFocus();

	NM_HTMLLISTCTRL *pNMHDR = new NM_HTMLLISTCTRL;
	pNMHDR->hdr.code = HTMLLIST_LBUTTONDOWN;
	pNMHDR->hdr.hwndFrom = GetSafeHwnd();
	pNMHDR->hdr.idFrom = m_nControlID;
	pNMHDR->lItemData = 0;
	pNMHDR->nItemNo = -1;
	pNMHDR->sItemText = _T("");
	pNMHDR->bChecked = 1;
	//Send LButton down event first
	GetParent() ->SendMessage(WM_NOTIFY, m_nControlID, (LPARAM)pNMHDR);

	delete pNMHDR;
	pNMHDR = NULL;

	BOOL bItemSelected = FALSE;
	m_nSelectedItem = NONE_SELECTED;

	POSITION pos = m_oListItems.GetHeadPosition();
	for(int i = 0;i < m_oListItems.GetCount();i++)
	{
		HTMLLIST_ITEM *pItem = m_oListItems.GetNext(pos);
		if(pItem->rcItem.PtInRect(point))
		{
			if(m_dwExtendedStyles & HTMLLIST_STYLE_CHECKBOX)
			{
				//see if we clicked in the box
				CPoint pt = pItem->rcItem.BottomRight();
				pt.x -= 60;// click area :RPS
				pt.y -= 35; //vishal

				CRect rcBox(pt, CPoint(pt.x + 15, pt.y + 15));
				if(rcBox.PtInRect(point))
				{
					pNMHDR = new NM_HTMLLISTCTRL;
					pNMHDR->hdr.code = HTMLLIST_ITEMCHECKED;
					pNMHDR->hdr.hwndFrom = GetSafeHwnd();
					pNMHDR->hdr.idFrom = m_nControlID;
					pNMHDR->lItemData = pItem->lItemData;
					pNMHDR->nItemNo = pItem->nItemNo;
					pNMHDR->sItemText = pItem->sItemText;
					pNMHDR->bChecked = pItem->bChecked;

					//Send check changed Event
					GetParent() ->SendMessage(WM_NOTIFY, m_nControlID, (LPARAM)pNMHDR);
					delete pNMHDR;
					pNMHDR = NULL;
				}

				//see if we clicked in the box
				pt = pItem->rcItem.BottomRight();
				pt.x -= 240;
				pt.y -= 45; //vishal

				CRect rcBox1(pt, CPoint(pt.x + 65, pt.y + 30));
				if(rcBox1.PtInRect(point))
				{
					pNMHDR = new NM_HTMLLISTCTRL;
					pNMHDR->hdr.code = HTMLLIST_ITEMONOFF;
					pNMHDR->hdr.hwndFrom = GetSafeHwnd();
					pNMHDR->hdr.idFrom = m_nControlID;
					pNMHDR->lItemData = pItem->lItemData;
					pNMHDR->nItemNo = pItem->nItemNo;
					pNMHDR->sItemText = pItem->sItemText;
					pNMHDR->bChecked = pItem->bChecked;
					pNMHDR->bStatus = pItem->bStatus;

					//Send check changed Event
					GetParent() ->SendMessage(WM_NOTIFY, m_nControlID, (LPARAM)pNMHDR);
					delete pNMHDR;
					pNMHDR = NULL;
				}
			}
			//Send WM_NOTIFY msg To parent
			pNMHDR = new NM_HTMLLISTCTRL;
			pNMHDR->hdr.code = HTMLLIST_SELECTIONCHANGED;
			pNMHDR->hdr.hwndFrom = GetSafeHwnd();
			pNMHDR->hdr.idFrom = m_nControlID;
			pNMHDR->lItemData = pItem->lItemData;
			pNMHDR->nItemNo = pItem->nItemNo;
			pNMHDR->sItemText = pItem->sItemText;
			pNMHDR->bChecked = pItem->bChecked;

			//Send Selection changed Event
			GetParent() ->SendMessage(WM_NOTIFY, m_nControlID, (LPARAM)pNMHDR);
			delete pNMHDR;
			pNMHDR = NULL;

			m_nSelectedItem = i;
			Invalidate(FALSE);
			bItemSelected = TRUE;
			break;
		}
	}
	CWnd::OnLButtonDown(nFlags, point);
}

/*-------------------------------------------------------------------------------------
Function		: OnVScroll
In Parameters	: UINT - ScrollBar code
				  UINT - pos
				  CScrollBar * - pointer To scroll bar
Out Parameters	: void
Purpose			: To handle vertical scrolling of list
Author			: Ramkrushna Shelke
--------------------------------------------------------------------------------------*/
void CMaxListControl::OnVScroll(UINT nSBCode, UINT nPos, CScrollBar* pScrollBar)
{
	//nPos is not valid in case of THUMB type msgs see below url
	//http://support.microsoft.com/kb/q152252/

	int nScrollPos = GetScrollPos(SB_VERT);
	int nLimit = GetScrollLimit(SB_VERT);
	int nScroll = nLimit;
	int SCROLL_AMT_Y = 50;

	switch(nSBCode)
	{
		case SB_LINEUP:      // Scroll up.
		case SB_PAGEUP:
			{
				if(nScrollPos <= 0)
				{
					return;
				}
				nScroll = min(nScrollPos, SCROLL_AMT_Y);
				SetScrollPos(SB_VERT, nScrollPos - nScroll);
			}
			break;
		case SB_LINEDOWN:   // Scroll down.
		case SB_PAGEDOWN:
			{
				if(nScrollPos >= nLimit)
				{
					return;
				}
				nScroll = min(nScroll-nScrollPos, SCROLL_AMT_Y);
				SetScrollPos(SB_VERT, nScrollPos + nScroll);
			}
			break;
		case SB_THUMBPOSITION:
			{
				HWND hWndScroll = NULL;
				if(pScrollBar == NULL)
				{
					hWndScroll = m_hWnd;
				}
				else
				{
					hWndScroll = pScrollBar->m_hWnd;
				}

				SCROLLINFO oScrollInfo = {0};
				oScrollInfo.cbSize = sizeof(SCROLLINFO);
				oScrollInfo.fMask = SIF_TRACKPOS;
				::GetScrollInfo(hWndScroll, SB_VERT, &oScrollInfo);
				nPos = oScrollInfo.nTrackPos;
				SetScrollPos(SB_VERT, nPos);
			}
			break;
		case SB_THUMBTRACK:
			{
				HWND hWndScroll = NULL;
				if(pScrollBar == NULL)
				{
					hWndScroll = m_hWnd;
				}
				else
				{
					hWndScroll = pScrollBar->m_hWnd;
				}

				SCROLLINFO oScrollInfo;
				oScrollInfo.cbSize = sizeof(SCROLLINFO);
				oScrollInfo.fMask = SIF_TRACKPOS;
				::GetScrollInfo(hWndScroll, SB_VERT, &oScrollInfo);
				nPos = oScrollInfo.nTrackPos;
				SetScrollPos(SB_VERT, nPos, FALSE);
			}
			break;
	}

	Invalidate();
	UpdateWindow();
	CWnd::OnVScroll(nSBCode, nPos, pScrollBar);
}

/*-------------------------------------------------------------------------------------
Function		: OnSize
In Parameters	: UINT - type, int - cx, int - cy
Out Parameters	: void
Purpose			: To handle ONSize message
Author			: Ramkrushna Shelke
--------------------------------------------------------------------------------------*/
void CMaxListControl::OnSize(UINT nType, int cx, int cy)
{
	CWnd::OnSize(nType, cx, cy);

	CRect oRc;
	GetClientRect(&oRc);
	m_nWndHeight = oRc.Height();
	m_nWndWidth = oRc.Width();

	ReArrangeWholeLayout();

	SCROLLINFO oScrollInfo;
	oScrollInfo.cbSize = sizeof(oScrollInfo);
	oScrollInfo.fMask = SIF_PAGE|SIF_RANGE;
	oScrollInfo.nMax = m_nListHeight;
	oScrollInfo.nMin = 0;
	oScrollInfo.nPage = m_nWndHeight;
	oScrollInfo.nPos = 0;
	SetScrollInfo(SB_VERT, &oScrollInfo);
	Invalidate(FALSE);
}

/*-------------------------------------------------------------------------------------
Function		: GetItemRect
In Parameters	: int - pos
Out Parameters	: CRect
Purpose			: To get the item rect
Author			: Ramkrushna Shelke
--------------------------------------------------------------------------------------*/
CRect CMaxListControl::GetItemRect(int nPos)
{
	HTMLLIST_ITEM* pItem = GetInternalData(nPos);
	if(pItem)
	{
		return pItem->rcItem;
	}
	else
	{
		return NULL;
	}
}

/*-------------------------------------------------------------------------------------
Function		: OnMouseWheel
In Parameters	: UINT - flags, short - delta, CPoint - point
Out Parameters	: bool
Purpose			: To handle on mouse wheel msg
Author			: Ramkrushna Shelke
--------------------------------------------------------------------------------------*/
BOOL CMaxListControl::OnMouseWheel(UINT nFlags, short zDelta, CPoint pt)
{
	int nVertScroll = GetScrollPos(SB_VERT);
	int maxpos = GetScrollLimit(SB_VERT);
	if(zDelta < 0)
	{
		int nNewPos = min(nVertScroll + 40, maxpos);
		SetScrollPos(SB_VERT, nNewPos);
		UpdateWindow();
	}
	else
	{
		int nNewPos = max((nVertScroll - 40), 0);
		SetScrollPos(SB_VERT, nNewPos);
		UpdateWindow();
	}
	Invalidate();
	return CWnd::OnMouseWheel(nFlags, zDelta, pt);
}

/*-------------------------------------------------------------------------------------
Function		: GetSelectedItem
In Parameters	: -
Out Parameters	: int
Purpose			: To get the selected item number
Author			: Ramkrushna Shelke
--------------------------------------------------------------------------------------*/
int CMaxListControl::GetSelectedItem()
{
	return m_nSelectedItem;
}

/*-------------------------------------------------------------------------------------
Function		: GetItemText
In Parameters	: int - pos
Out Parameters	: CStrring - text
Purpose			: To get the text of the item
Author			: Ramkrushna Shelke
--------------------------------------------------------------------------------------*/
CString CMaxListControl::GetItemText(int nPos)
{
	HTMLLIST_ITEM* pItem = GetInternalData(nPos);
	if(pItem)
	{
		return pItem->sItemText;
	}
	else
	{
		return _T("");
	}
}

/*-------------------------------------------------------------------------------------
Function		: SetExtendedStyle
In Parameters	: DWORD - style
Out Parameters	: void
Purpose			: To set the style of ListCtrl
Author			: Ramkrushna Shelke
--------------------------------------------------------------------------------------*/
void CMaxListControl::SetExtendedStyle(DWORD dwExStyle)
{
	m_dwExtendedStyles = dwExStyle;

	ReArrangeWholeLayout();
	SCROLLINFO oScrollInfo;
	oScrollInfo.cbSize = sizeof(oScrollInfo);
	oScrollInfo.fMask = SIF_PAGE|SIF_RANGE;
	oScrollInfo.nMax = m_nListHeight;
	oScrollInfo.nMin = 0;
	oScrollInfo.nPage = m_nWndHeight;
	oScrollInfo.nPos = 0;
	SetScrollInfo(SB_VERT, &oScrollInfo);

	Invalidate(FALSE);
}

/*-------------------------------------------------------------------------------------
Function		: GetExtendedStyle
In Parameters	: DWORD - style
Out Parameters	: void
Purpose			: To get the style of ListCtrl
Author			: Ramkrushna Shelke
--------------------------------------------------------------------------------------*/
DWORD CMaxListControl::GetExtendedStyle()
{
	return m_dwExtendedStyles;
}

/*-------------------------------------------------------------------------------------
Function		: OnSetFocus
In Parameters	: CWnd* - pointer To window
Out Parameters	: void
Purpose			: To handle set focus msg
Author			: Ramkrushna Shelke
--------------------------------------------------------------------------------------*/
void CMaxListControl::OnSetFocus(CWnd* pOldWnd)
{
	CWnd::OnSetFocus(pOldWnd);
	m_bHasFocus = TRUE;
	if(m_nSelectedItem != NONE_SELECTED)
	{
		InvalidateRect(GetItemRect(m_nSelectedItem));
	}
}

/*-------------------------------------------------------------------------------------
Function		: OnKillFocus
In Parameters	: CWnd* - pointer To window
Out Parameters	: void
Purpose			: To handle kill focus msg
Author			: Ramkrushna Shelke
--------------------------------------------------------------------------------------*/
void CMaxListControl::OnKillFocus(CWnd* pNewWnd)
{
	CWnd::OnKillFocus(pNewWnd);
	m_bHasFocus = FALSE;
	if(m_nSelectedItem != NONE_SELECTED)
	{
		InvalidateRect(GetItemRect(m_nSelectedItem));
	}
}

/*-------------------------------------------------------------------------------------
Function		: OnGetDlgCode
In Parameters	: -
Out Parameters	: UINT
Purpose			: To handle getDlgCode msg
Author			: Ramkrushna Shelke
--------------------------------------------------------------------------------------*/
UINT CMaxListControl::OnGetDlgCode()
{
	return DLGC_WANTARROWS|DLGC_WANTCHARS;
}

/*-------------------------------------------------------------------------------------
Function		: OnKeyDown
In Parameters	: UINT - char
UINT - repcnt
UINT - flags
Out Parameters	: void
Purpose			: To handle key press event
Author			: Ramkrushna Shelke
--------------------------------------------------------------------------------------*/
void CMaxListControl::OnKeyDown(UINT nChar, UINT nRepCnt, UINT nFlags)
{
	if(nChar == VK_UP)
	{
		if(m_nSelectedItem == NONE_SELECTED)
		{
			m_nSelectedItem = 0;
		}
		else
		{
			if(m_nSelectedItem > 0)
			{
				m_nSelectedItem --;
			}
		}
		EnsureVisible(m_nSelectedItem);
		Invalidate(FALSE);
		SendSelectionChangeNotification(m_nSelectedItem);
	}
	else if(nChar == VK_DOWN)
	{
		if(m_nSelectedItem == NONE_SELECTED)
		{
			m_nSelectedItem = m_nTotalItems - 1;
		}
		else
		{
			if(m_nSelectedItem < (m_nTotalItems - 1))
			{
				m_nSelectedItem ++;
			}
		}
		EnsureVisible(m_nSelectedItem);
		Invalidate(FALSE);
		SendSelectionChangeNotification(m_nSelectedItem);
	}
	CWnd::OnKeyDown(nChar, nRepCnt, nFlags);
}

/*-------------------------------------------------------------------------------------
Function		: EnsureVisible
In Parameters	: int - pos
Out Parameters	: void
Purpose			: To ensure that list control is visible
Author			: Ramkrushna Shelke
--------------------------------------------------------------------------------------*/
void CMaxListControl::EnsureVisible(int nPos)
{
	int nScrollPos = GetScrollPos(SB_VERT);
	int nItemPos = 0;
	int nScrollAmount = 0;

	POSITION pos = m_oListItems.GetHeadPosition();
	for(int i = 0;i < m_oListItems.GetCount();i++)
	{
		HTMLLIST_ITEM *pItem = m_oListItems.GetNext(pos);
		if(pItem->nItemNo == nPos)
		{
			if(nItemPos < nScrollPos)
			{
				//Item is above
				nScrollAmount = nScrollPos - nItemPos;
			}
			else if((nItemPos + pItem->nHeight) > (nScrollPos + m_nWndHeight))
			{
				//Item is below
				nScrollAmount = (nScrollPos + m_nWndHeight) - nItemPos - pItem->nHeight;
			}
			break;
		}
		nItemPos += pItem->nHeight;
	}

	if(nScrollAmount)
	{
		SetScrollPos(SB_VERT, nScrollPos - nScrollAmount);
		Invalidate(FALSE);
	}
}

/*-------------------------------------------------------------------------------------
Function		: SetItemCheck
In Parameters	: int - pos
bool - check
Out Parameters	: void
Purpose			: To set the item check / uncheck
Author			: Ramkrushna Shelke
--------------------------------------------------------------------------------------*/
void CMaxListControl::SetItemCheck(int nPos, BOOL bCheck)
{
	HTMLLIST_ITEM* pItem = GetInternalData(nPos);
	if(pItem)
	{
		pItem->bChecked = bCheck;
		InvalidateRect(pItem->rcItem, FALSE);
	}
}

/*-------------------------------------------------------------------------------------
Function		: GetItemCheck
In Parameters	: int - pos
Out Parameters	: bool - check
Purpose			: To get the item check status
Author			: Ramkrushna Shelke
--------------------------------------------------------------------------------------*/
BOOL CMaxListControl::GetItemCheck(int nPos)
{
	HTMLLIST_ITEM* pItem = GetInternalData(nPos);
	if(pItem)
	{
		return pItem->bChecked;
	}
	else
	{
		return FALSE;
	}
}

/*-------------------------------------------------------------------------------------
Function		: GetItemStatus
In Parameters	: int - pos
Out Parameters	: bool - check
Purpose			: To get the item check status
Author			: Ravi Bisht
--------------------------------------------------------------------------------------*/
BOOL CMaxListControl::GetItemStatus(int nPos)
{
	HTMLLIST_ITEM* pItem = GetInternalData(nPos);
	if(pItem)
	{
		return pItem->bStatus;
	}
	else
	{
		return FALSE;
	}
}
/*-------------------------------------------------------------------------------------
Function		: OnRButtonDown
In Parameters	: UINT - flags, CPoint - point
Out Parameters	: void
Purpose			: To handle the RButton down msg
Author			: Ramkrushna Shelke
--------------------------------------------------------------------------------------*/
void CMaxListControl::OnRButtonDown(UINT nFlags, CPoint point)
{
	NM_HTMLLISTCTRL *pNMHDR = new NM_HTMLLISTCTRL;
	pNMHDR->hdr.code = HTMLLIST_RBUTTONDOWN;
	pNMHDR->hdr.hwndFrom = GetSafeHwnd();
	pNMHDR->hdr.idFrom = m_nControlID;
	pNMHDR->lItemData = 0;
	pNMHDR->nItemNo = -1;
	pNMHDR->sItemText = _T("");
	pNMHDR->bChecked = 1;

	GetParent() ->SendMessage(WM_NOTIFY, m_nControlID, (LPARAM)pNMHDR);

	delete pNMHDR;
	pNMHDR = NULL;
	CWnd::OnRButtonDown(nFlags, point);
}

/*-------------------------------------------------------------------------------------
Function		: SetItemText
In Parameters	: int - pos
				  CString - item text
				  bool - calculate height
Out Parameters	: void
Purpose			: To set the text of item
Author			: Ramkrushna Shelke
--------------------------------------------------------------------------------------*/
void CMaxListControl::SetItemText(int nPos, CString sItemText, BOOL bCalculateHeight)
{
	HTMLLIST_ITEM* pItem = GetInternalData(nPos);
	if(pItem)
	{
		pItem->sItemText = sItemText;
		if(bCalculateHeight)
		{
			pItem->bHeightSpecified = FALSE;
			ReArrangeWholeLayout();
			Invalidate(FALSE);
		}
		else
		{
			InvalidateRect(pItem->rcItem, FALSE);
		}
	}
}

/*-------------------------------------------------------------------------------------
Function		: DeleteItem
In Parameters	: int - pos
Out Parameters	: bool
Purpose			: To delete the item from list ctrl
Author			: Ramkrushna Shelke
--------------------------------------------------------------------------------------*/
BOOL CMaxListControl::DeleteItem(int nPos)
{
	POSITION pos = m_oListItems.GetHeadPosition();
	for(int i = 0; i < m_oListItems.GetCount(); i++)
	{
		HTMLLIST_ITEM *pItem = m_oListItems.GetNext(pos);
		if(pItem->nItemNo == nPos)
		{
			//Is this the last item
			if(pos != NULL)
			{
				//pos is now pointing To the next row, so go back
				m_oListItems.GetPrev(pos);
				m_oListItems.RemoveAt(pos);
			}
			else
			{
				m_oListItems.RemoveAt(m_oListItems.GetTailPosition());
			}

			if(m_nSelectedItem == pItem->nItemNo)
			{
				m_nSelectedItem = NONE_SELECTED;
			}

			//Adjust scrollbar
			m_nListHeight -= pItem->nHeight;
			SCROLLINFO oScrollInfo;
			oScrollInfo.cbSize = sizeof(oScrollInfo);

			oScrollInfo.fMask = SIF_PAGE|SIF_RANGE;
			oScrollInfo.nMax = m_nListHeight;
			oScrollInfo.nMin = 0;
			oScrollInfo.nPage = m_nWndHeight;
			oScrollInfo.nPos = 0;
			SetScrollInfo(SB_VERT, &oScrollInfo);

			//delete pItem;
			m_nTotalItems --;

			ReArrangeItems();
			Invalidate(FALSE);
			return TRUE;
		}
	}
	return FALSE;
}

/*-------------------------------------------------------------------------------------
Function		: ReArrangeItems
In Parameters	: -
Out Parameters	: void
Purpose			: To reaarrange all the items
Author			: Ramkrushna Shelke
--------------------------------------------------------------------------------------*/
void CMaxListControl::ReArrangeItems()
{
	m_oMapItems.RemoveAll();
	POSITION pos = m_oListItems.GetHeadPosition();
	for(int i = 0;i < m_oListItems.GetCount();i++)
	{
		HTMLLIST_ITEM *pItem = m_oListItems.GetNext(pos);
		pItem->nItemNo = i;
		SetInternalData(i, pItem);
	}
}

/*-------------------------------------------------------------------------------------
Function		: ReArrangeWholeLayout
In Parameters	: -
Out Parameters	: void
Purpose			: To reaarrange whole layout
Author			: Ramkrushna Shelke
--------------------------------------------------------------------------------------*/
void CMaxListControl::ReArrangeWholeLayout()
{
	m_nTotalItems = 0;
	m_nListHeight = 0;
	m_oMapItems.RemoveAll();

	POSITION pos = m_oListItems.GetHeadPosition();
	for(int i = 0;i < m_oListItems.GetCount();i++)
	{
		HTMLLIST_ITEM *pItem = m_oListItems.GetNext(pos);
		pItem->nItemNo = i;

		if(!pItem->bHeightSpecified)
		{
			//Calculate items height
			pItem->nHeight = CalculateItemHeight(pItem->sItemText, pItem->nStyle, pItem->uiImage, m_nWndWidth);
		}

		m_nTotalItems ++;

		m_nListHeight += pItem->nHeight;
		SetInternalData(i, pItem);
	}
}

/*-------------------------------------------------------------------------------------
Function		: GetImage
In Parameters	: int - pos
Out Parameters	: UINT - image ID
Purpose			: To get the image ID
Author			: Ramkrushna Shelke
--------------------------------------------------------------------------------------*/
UINT CMaxListControl::GetImage(int nPos)
{
	HTMLLIST_ITEM *pItem = GetInternalData(nPos);
	if(pItem)
	{
		return pItem->uiImage;
	}
	return 0;
}

/*-------------------------------------------------------------------------------------
Function		: SetImage
In Parameters	: int - pos, UINT - image ID
Out Parameters	: void
Purpose			: To set the image To item
Author			: Ramkrushna Shelke
--------------------------------------------------------------------------------------*/
void CMaxListControl::SetImage(int nPos, UINT uiImage)
{
	HTMLLIST_ITEM *pItem = GetInternalData(nPos);
	if(pItem)
	{
		pItem->uiImage = uiImage;
		InvalidateRect(pItem->rcItem, FALSE);
	}
}

/*-------------------------------------------------------------------------------------
Function		: OnLButtonDblClk
In Parameters	: UINT - flags, CPoint - point
Out Parameters	: void
Purpose			: To handle the double click message
Author			: Ramkrushna Shelke
--------------------------------------------------------------------------------------*/
void CMaxListControl::OnLButtonDblClk(UINT nFlags, CPoint point)
{
	NM_HTMLLISTCTRL *pNMHDR = new NM_HTMLLISTCTRL;
	pNMHDR->hdr.code = HTMLLIST_LBUTTONDBLCLICK;
	pNMHDR->hdr.hwndFrom = GetSafeHwnd();
	pNMHDR->hdr.idFrom = m_nControlID;
	pNMHDR->lItemData = 0;
	pNMHDR->nItemNo = -1;
	pNMHDR->sItemText = _T("");
	pNMHDR->bChecked = 1;

	GetParent() ->SendMessage(WM_NOTIFY, m_nControlID, (LPARAM)pNMHDR);

	delete pNMHDR;
	CWnd::OnLButtonDblClk(nFlags, point);
}

/*-------------------------------------------------------------------------------------
Function		: DrawItem
In Parameters	: CDC* - pointer To device context
CRect - rect
HTMLLIST_ITEM * - list item pointer
bool - selected flag
Out Parameters	: void
Purpose			: To draw the HTML ListCtrl
Author			: Ramkrushna Shelke
--------------------------------------------------------------------------------------*/
void CMaxListControl::DrawItem(CDC *pDC, CRect rcItem, HTMLLIST_ITEM *pItem, BOOL bSelected)
{
	int iParentItems = GetItemCount();
	int iRegistryMonitorChild = 10;
	CRect oRcClipBox;
	pDC->GetClipBox(&oRcClipBox);

	if(!IsRectVisible(oRcClipBox, rcItem))
	{
		return;
	}

	COLORREF clrText = RGB(0, 0, 0);
	COLORREF clrOld = RGB(0, 0, 0);
	CRect rcImage(0, 0, 0, 0);

	if(bSelected)
	{
		//clrText = RGB(255, 255, 255);
		pDC->FillSolidRect(&rcItem, RGB(255, 255, 255));
	}
	else
	{
		pDC->FillSolidRect(&rcItem, RGB(255, 255, 255));
	}
	if(m_dwExtendedStyles & HTMLLIST_STYLE_GRIDLINES)
	{
		CRect rect = rcItem;
		//rect.right = 190;
		//rect.right = 297;
		//pDC->DrawEdge(&rect, BDR_SUNKENINNER, BF_BOTTOM|BF_LEFT |BF_RIGHT | BF_FLAT);
		pDC->DrawEdge(&rcItem, BDR_SUNKENINNER, BF_BOTTOM|BF_LEFT |BF_FLAT);
	}

	CPoint ptCheckBox = rcItem.TopLeft();

	if(m_dwExtendedStyles & HTMLLIST_STYLE_CHECKBOX && pItem->nItemNo < iParentItems)
	{
		CPoint ptButton = rcItem.BottomRight();
		ptButton.x -= 60;
		ptButton.y = ptCheckBox.y + 15;
		if(bSelected)
			m_ImageList.Draw(pDC, 1, ptButton, ILD_TRANSPARENT);
		else
			m_ImageList.Draw(pDC, 0, ptButton, ILD_TRANSPARENT);

		ptButton.x -= 200;
		ptButton.y = ptCheckBox.y;
		if(pItem->bStatus)
			m_ButtonImageList.Draw(pDC, 1, ptButton, ILD_TRANSPARENT);
		else
			m_ButtonImageList.Draw(pDC, 0, ptButton, ILD_TRANSPARENT);
	}

	//Draw image if an imagelist is attached
	if(m_dwExtendedStyles & HTMLLIST_STYLE_IMAGES && pItem->nItemNo < iParentItems + iRegistryMonitorChild)
	{
		if(m_pImageList)
		{
			IMAGEINFO imgInfo = {0};
			m_pImageList->GetImageInfo(0, &imgInfo);
			rcImage = imgInfo.rcImage;

			CPoint pt = ptCheckBox;
			if(pItem->nItemNo < iParentItems)
			{
				pt.x += ITEM_IMAGE_PADDING_LEFT;
			}
			else
			{
				pt.x += ITEM_IMAGE_PADDING_LEFT + ITEM_CHECKBOX_WIDTH;
			}
			pt.y = rcItem.top + 4;			
			m_pImageList->Draw(pDC, pItem->uiImage, pt, ILD_TRANSPARENT);
		}
	}

	else if(m_dwExtendedStyles & HTMLLIST_STYLE_IMAGES && pItem->nItemNo >= iParentItems + iRegistryMonitorChild)
	{
		if(m_pImageList)
		{
			IMAGEINFO imgInfo = {0};
			m_pImageList->GetImageInfo(0, &imgInfo);
			rcImage = imgInfo.rcImage;

			CPoint pt = ptCheckBox;
			if(pItem->nItemNo < iParentItems)
			{
				pt.x += ITEM_IMAGE_PADDING_LEFT;
			}
			else
			{
				pt.x += ITEM_IMAGE_PADDING_LEFT + ITEM_CHECKBOX_WIDTH;
			}
			pt.y = rcItem.top;
			pt.y += rcItem.Height()/ 2 - rcImage.Height()/2;
		}
	}

	if(pItem->nStyle == NORMAL_TEXT)
	{
		clrOld = pDC->SetTextColor(clrText);
		CRect oRc = rcItem;
		if(rcImage.Width())
		{
			//make space for the Image already drawn
			oRc.DeflateRect(rcImage.Width() + ITEM_IMAGE_PADDING_LEFT + ITEM_IMAGE_PADDING_RIGHT, 0, 0, 0);
		}

		if(m_dwExtendedStyles & HTMLLIST_STYLE_CHECKBOX)
		{
			oRc.left += ITEM_PADDING_LEFT + ITEM_CHECKBOX_WIDTH;
		}
		else
		{
			oRc.left += ITEM_PADDING_LEFT + ITEM_CHECKBOX_WIDTH;
		}

		if(!pItem->bHeightSpecified)
			oRc.top += ITEM_PADDING_TOP;

		pDC->DrawText(pItem->sItemText, pItem->sItemText.GetLength(), &oRc,
					 DT_LEFT|DT_WORDBREAK);
	}
	else if(pItem->nStyle == HTML_TEXT)
	{
		//Draw HTML
		clrOld = pDC->SetTextColor(clrText);
		CRect oRc = rcItem;
		if(rcImage.Width())
		{
			//make space for the Image already drawn
			oRc.DeflateRect(rcImage.Width() + ITEM_IMAGE_PADDING_LEFT + ITEM_IMAGE_PADDING_RIGHT, 12, 0, 0);
		}
		if(m_dwExtendedStyles & HTMLLIST_STYLE_CHECKBOX)
		{
			oRc.left += ITEM_PADDING_LEFT + ITEM_CHECKBOX_WIDTH;
		}
		else
		{
			oRc.left += ITEM_PADDING_LEFT + ITEM_CHECKBOX_WIDTH;
		}

		if(!pItem->bHeightSpecified)
		{
			oRc.top += ITEM_PADDING_TOP;
		}

		DrawHTML(pDC->GetSafeHdc(), pItem->sItemText, pItem->sItemText.GetLength(),
				&oRc, DT_LEFT|DT_WORDBREAK);
	}
	else if(pItem->nStyle == SINGLE_LINE_TEXT)
	{
		clrOld = pDC->SetTextColor(clrText);

		CRect oRc = rcItem;
		if(rcImage.Width())
		{
			//make space for the Image already drawn
			oRc.DeflateRect(rcImage.Width() + ITEM_IMAGE_PADDING_LEFT + ITEM_IMAGE_PADDING_RIGHT, 0, 0, 0);
		}
		if(m_dwExtendedStyles & HTMLLIST_STYLE_CHECKBOX)
		{
			oRc.left += ITEM_PADDING_LEFT + ITEM_CHECKBOX_WIDTH;
		}
		else
		{
			oRc.left += ITEM_PADDING_LEFT + ITEM_CHECKBOX_WIDTH;
		}

		if(!pItem->bHeightSpecified)
		{
			oRc.top += ITEM_PADDING_TOP;
		}

		//See if we can fit the text in one line
		WCHAR szBuffer[_MAX_PATH] = {0};
		wcscpy_s(szBuffer, _MAX_PATH, pItem->sItemText);

		if(PathCompactPath(pDC->GetSafeHdc(), szBuffer, oRc.Width()))
		{
			pDC->DrawText(szBuffer, (int)_tcslen(szBuffer), &oRc,
						DT_LEFT|DT_SINGLELINE|DT_VCENTER);
		}
		else
		{
			pDC->DrawText(pItem->sItemText, pItem->sItemText.GetLength(), &oRc,
						DT_LEFT|DT_SINGLELINE|DT_VCENTER);
		}
	}

	pDC->SetTextColor(clrOld);
	//Draw the focus rect if focused
	if(m_bHasFocus && (bSelected))
	{
		pDC->DrawFocusRect(&rcItem);
	}
}

/*-------------------------------------------------------------------------------------
Function		: SendSelectionChangeNotification
In Parameters	: int - pos
Out Parameters	: void
Purpose			: To send the selection changed notification To parent
Author			: Ramkrushna Shelke
--------------------------------------------------------------------------------------*/
void CMaxListControl::SendSelectionChangeNotification(int nPos)
{
	//Send WM_NOTIFY msg To parent
	HTMLLIST_ITEM *pItem = GetInternalData(nPos);
	if(pItem)
	{
		NM_HTMLLISTCTRL *pNMHDR = new NM_HTMLLISTCTRL;
		pNMHDR->hdr.code = HTMLLIST_SELECTIONCHANGED;
		pNMHDR->hdr.hwndFrom = GetSafeHwnd();
		pNMHDR->hdr.idFrom = m_nControlID;
		pNMHDR->lItemData = pItem->lItemData;
		pNMHDR->nItemNo = pItem->nItemNo;
		pNMHDR->sItemText = pItem->sItemText;
		pNMHDR->bChecked = pItem->bChecked;

		//Send Selection changed Event
		GetParent() ->SendMessage(WM_NOTIFY, m_nControlID, (LPARAM)pNMHDR);
		delete pNMHDR;
		return;
	}
}

/*-------------------------------------------------------------------------------------
Function		: SendCheckStateChangedNotification
In Parameters	: int - pos
Out Parameters	: void
Purpose			: To send the check state changed notification To parent
Author			: Ramkrushna Shelke
--------------------------------------------------------------------------------------*/
void CMaxListControl::SendCheckStateChangedNotification(int nPos)
{
	//Send WM_NOTIFY msg To parent
	HTMLLIST_ITEM *pItem = GetInternalData(nPos);
	if(pItem)
	{
		NM_HTMLLISTCTRL *pNMHDR = new NM_HTMLLISTCTRL;

		pNMHDR->hdr.code = HTMLLIST_ITEMCHECKED;
		pNMHDR->hdr.hwndFrom = GetSafeHwnd();
		pNMHDR->hdr.idFrom = m_nControlID;
		pNMHDR->lItemData = pItem->lItemData;
		pNMHDR->nItemNo = pItem->nItemNo;
		pNMHDR->sItemText = pItem->sItemText;
		pNMHDR->bChecked = pItem->bChecked;

		//Send Selection changed Event
		GetParent() ->SendMessage(WM_NOTIFY, m_nControlID, (LPARAM)pNMHDR);
		delete pNMHDR;
		return;
	}
}

/*-------------------------------------------------------------------------------------
Function		: IsRectVisible
In Parameters	: CRect - clip rect, CRect - item rect
Out Parameters	: bool
Purpose			: To check that rect is visible or not
Author			: Ramkrushna Shelke
--------------------------------------------------------------------------------------*/
BOOL CMaxListControl::IsRectVisible(CRect oRcClipBox, CRect rcItem)
{
	if(oRcClipBox.top > rcItem.bottom)
	{
		//Item is above the clip box
		return FALSE;
	}
	else if(oRcClipBox.bottom < rcItem.top)
	{
		return FALSE;
	}
	return TRUE;
}

/*-------------------------------------------------------------------------------------
Function		: GetInternalData
In Parameters	: int  - pos
Out Parameters	: HTMLLIST_ITEM * - pointer To list item
Purpose			: To get the internal data
Author			: Ramkrushna Shelke
--------------------------------------------------------------------------------------*/
HTMLLIST_ITEM * CMaxListControl::GetInternalData(int nPos)
{
	HTMLLIST_ITEM *pData = NULL;
	m_oMapItems.Lookup(nPos, pData);
	return pData;
}

/*-------------------------------------------------------------------------------------
Function		: SetInternalData
In Parameters	: int  - pos
HTMLLIST_ITEM * - pointer To list item
Out Parameters	: void
Purpose			: To set the internal data
Author			: Ramkrushna Shelke
--------------------------------------------------------------------------------------*/
void CMaxListControl::SetInternalData(int nPos, HTMLLIST_ITEM *pData)
{
	m_oMapItems.SetAt(nPos, pData);
}

/*-------------------------------------------------------------------------------------
Function		: OnDestroy
In Parameters	: -
Out Parameters	: void
Purpose			: on exit free the memory
Author			: Ramkrushna Shelke
--------------------------------------------------------------------------------------*/
void CMaxListControl::OnDestroy()
{
	CWnd::OnDestroy();
	if(m_pFont)
	{
		delete m_pFont;
		m_pFont = NULL;
	}
}

/*-------------------------------------------------------------------------------------
Function		: OnSetCursor
In Parameters	: -
Out Parameters	: bool
Purpose			: To handle the set cursor msg
Author			: Ramkrushna Shelke
--------------------------------------------------------------------------------------*/
BOOL CMaxListControl::OnSetCursor(CWnd* pWnd, UINT nHitTest, UINT message)
{
	SetCursor(::LoadCursor(NULL, IDC_ARROW));
	return TRUE;//CWnd::OnSetCursor(pWnd, nHitTest, message);
}

void CMaxListControl::SetItemStatus(int iItemNo, BOOLEAN bStatus)
{
	POSITION pos = m_oListItems.GetHeadPosition();
	for(int i = 0;i < m_oListItems.GetCount();i++)
	{
		HTMLLIST_ITEM *pItem = m_oListItems.GetNext(pos);
		if(iItemNo == i)		
		{
			pItem->bStatus = bStatus;
		}		
	}	
}