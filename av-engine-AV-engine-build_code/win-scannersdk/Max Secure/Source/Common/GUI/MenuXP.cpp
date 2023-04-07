/*======================================================================================
   FILE			: MenuXP.cpp
   ABSTRACT		: this class will be used for custom menu bar
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
   CREATION DATE: 22/01/2007
   NOTE			: 
VERSION HISTORY	:
=======================================================================================*/

#include "pch.h"
#include "MenuXP.h"
#define OBM_CHECK           32760

#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[]=__FILE__;
#define new DEBUG_NEW
#endif

// constants used for drawing
const int CXGAP = 0;				// num pixels between button and text
const int CXTEXTMARGIN = 2;		// num pixels after hilite to start text
const int CXBUTTONMARGIN = 2;	// num pixels wider button is than bitmap
const int CYBUTTONMARGIN = 2;	// ditto for height

// DrawText flags
const int DT_MYSTANDARD = DT_SINGLELINE|DT_LEFT|DT_VCENTER;


IMPLEMENT_DYNAMIC(CMenuXP, CMenu)

/*-----------------------------------------------------------------------------
Function		: CMenuXP
In Parameters	: -
Out Parameters	: -
Purpose			: constructor to initialize member variables
Author			:
-----------------------------------------------------------------------------*/
CMenuXP::CMenuXP()
{
	try
	{
		//initialize menu font with the default
		NONCLIENTMETRICS info;
		info.cbSize = sizeof(info);
		SystemParametersInfo(SPI_GETNONCLIENTMETRICS, sizeof(info), &info, 0);
		VERIFY(m_fontMenu.CreateFontIndirect(&info.lfMenuFont));

		//initialize colors with system default
		m_clrBackGround = ::GetSysColor(COLOR_MENU);
		m_clrSelectedBar = ::GetSysColor(COLOR_HIGHLIGHT);
		m_clrSelectedText = ::GetSysColor(COLOR_HIGHLIGHTTEXT);
		m_clrText = ::GetSysColor(COLOR_MENUTEXT);
		m_clrDisabledText = ::GetSysColor(COLOR_GRAYTEXT);
		m_clrIconArea = m_clrBackGround;

		//initialize sidebar colors
		m_clrSideBarStart = RGB(0, 0, 192);
		m_clrSideBarEnd = RGB(0, 0, 0);

		//the default sytle is office style
		m_Style = STYLE_STARTMENU;

		m_bBreak = false;
		m_bBreakBar = false;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CMenuXP::CMenuXP"));
	}
}

/*-----------------------------------------------------------------------------
Function		: ~CMenuXP
In Parameters	: -
Out Parameters	: -
Purpose			: destructor to free the memory used
Author			:
-----------------------------------------------------------------------------*/
CMenuXP::~CMenuXP()
{
	try
	{
		m_fontMenu.DeleteObject();
		Clear();
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CMenuXP::~CMenuXP"));
	}
}

/*-----------------------------------------------------------------------------
Function		: MeasureItem
In Parameters	: LPMEASUREITEMSTRUCT - structure
Out Parameters	: void
Purpose			: to measure the item height and width
Author			:
-----------------------------------------------------------------------------*/
void CMenuXP::MeasureItem(LPMEASUREITEMSTRUCT lpms)
{
	try
	{
		if(lpms->CtlType != ODT_MENU)
			return;

		CMenuXPItem	*pItem = (CMenuXPItem *)lpms->itemData;

		if(!pItem || !pItem->IsMyData())
			return;

		if(pItem->m_bSideBar)
		{
			lpms->itemWidth = pItem->m_nSize;
			lpms->itemHeight = 0;
		}
		else if(pItem->m_bSeparator)
		{
			// separator: use half system height and zero width
			lpms->itemHeight = ::GetSystemMetrics(SM_CYMENUCHECK) >>1;
			lpms->itemWidth  = 0;
		}
		else
		{
			//calculate the size needed to draw the text: use DrawText with DT_CALCRECT

			CWindowDC dc(NULL);	// screen DC--I won't actually draw on it
			CRect rcText(0,0,0,0);
			CFont* pOldFont = dc.SelectObject(&m_fontMenu);
			dc.DrawText(pItem->m_strText, rcText, DT_MYSTANDARD|DT_CALCRECT);
			dc.SelectObject(pOldFont);

			// the height of the item should be the maximun of the text and the button
			lpms->itemHeight = max(rcText.Height(), pItem->m_nSize + (CYBUTTONMARGIN<<1));

			if(pItem->m_bButtonOnly)
			{	//for button only style, we set the item's width to be the same as its height
				lpms->itemWidth = lpms->itemHeight;
			}
			else
			{
				// width is width of text plus a bunch of stuff
				int cx = rcText.Width();	// text width
				cx += CXTEXTMARGIN<<1;		// L/R margin for readability
				cx += CXGAP;					// space between button and menu text
				cx += (pItem->m_nSize + CYBUTTONMARGIN * 2)<<1;		// button width (L=button; R=empty margin)

				lpms->itemWidth = cx;		// done deal
			}
		}

		// whatever value I return in lpms->itemWidth, Windows will add the
		// width of a menu checkmark, so I must subtract to defeat Windows.Argh.
		//
		lpms->itemWidth -= GetSystemMetrics(SM_CXMENUCHECK) -1;

		TRACE(_T("MeasureItem: ID(%d), Width(%d), Height(%d)\n"),
			lpms->itemID,
			lpms->itemWidth, lpms->itemHeight);
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in  CMenuXP::MeasureItem"));
	}
}

/*-----------------------------------------------------------------------------
Function		: DrawItem
In Parameters	: LPDRAWITEMSTRUCT - item draw structure
Out Parameters	: void
Purpose			: to draw the individual items one by one
Author			:
-----------------------------------------------------------------------------*/
void CMenuXP::DrawItem(LPDRAWITEMSTRUCT lpds)
{
	try
	{
		ASSERT(lpds);
		if(NULL == lpds)
			return;

		if(lpds->CtlType != ODT_MENU)
			return; // not handled by me
		CMenuXPItem * pItem = (CMenuXPItem *)lpds->itemData;
		if(!pItem)
			return;

		ASSERT(lpds->itemAction != ODA_FOCUS);
		ASSERT(lpds->hDC);
		CDC dc;
		dc.Attach(lpds->hDC);

		//get the drawing area
		CRect rcItem = lpds->rcItem;


		if(pItem->m_bSideBar)
		{
			CRect rcClipBox;
			dc.GetClipBox(rcClipBox);

			//draw the side bar
			CRect rc = rcItem;
			rc.top = rcClipBox.top;
			rc.bottom = rcClipBox.bottom;
			DrawSideBar(&dc, rc, pItem->m_hIcon, pItem->m_strText);
		}
		else if(pItem->m_bSeparator)
		{
			//draw background first
			DrawBackGround(&dc, rcItem, FALSE, FALSE);
			// draw the background
			CRect rc = rcItem;								// copy rect
			rc.top += rc.Height() >>1;						// vertical center
			dc.DrawEdge(&rc, EDGE_ETCHED, BF_TOP);		// draw separator line

			// in XP mode, fill the icon area with the iconarea color
			if(m_Style == STYLE_XP)
			{
				CRect rcArea(rcItem.TopLeft(),
					CSize(pItem->m_nSize + (CYBUTTONMARGIN<<1),
					pItem->m_nSize + (CYBUTTONMARGIN<<1)));
				DrawIconArea(&dc, rcArea, FALSE, FALSE, FALSE);
			}
		}
		else
		{
			BOOL bDisabled = lpds->itemState & ODS_GRAYED;
			BOOL bSelected = lpds->itemState & ODS_SELECTED;
			BOOL bChecked  = lpds->itemState & ODS_CHECKED;

			//draw the background first
			DrawBackGround(&dc, rcItem, bSelected, bDisabled);

			//Draw the icon area for XP style
			if(m_Style == STYLE_XP)
			{
				CRect rcArea(rcItem.TopLeft(), CSize(rcItem.Height(), rcItem.Height()));
				DrawIconArea(&dc, rcArea, bSelected, bDisabled, bChecked);
			}

			//draw the button, not the icon
			CRect rcButton(rcItem.TopLeft(), CSize(rcItem.Height(), rcItem.Height()));
			if(pItem->m_bButtonOnly)
				rcButton = rcItem;
			if(pItem->m_hIcon || bChecked)
			{
				DrawButton(&dc, rcButton, bSelected, bDisabled, bChecked);
			}
			//draw the icon actually
			if(pItem->m_hIcon)
			{
				CRect	rcIcon = rcButton;
				rcIcon.DeflateRect(2, 2);
				DrawIcon(&dc, rcIcon, pItem->m_hIcon, bSelected, bDisabled);
			}
			else if(bChecked)
			{
				//draw the check mark
				CRect	rcCheck = rcButton;
				rcCheck.DeflateRect(2, 2);
				DrawCheckMark(&dc, rcCheck, bSelected);


			}

			//draw text finally
			if(!pItem->m_bButtonOnly)
			{
				CRect rcText = rcItem;				 // start w/whole item
				rcText.left += rcButton.Width() + CXGAP + CXTEXTMARGIN; // left margin
				rcText.right -= pItem->m_nSize;				 // right margin
				DrawText(&dc, rcText, pItem->m_strText, bSelected, bDisabled, lpds->itemState&ODS_DEFAULT ? 1 : 0);
			}
		}
		dc.Detach();
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in  CMenuXP::DrawItem"));
	}
}

/*-----------------------------------------------------------------------------
Function		: DrawBackGround
In Parameters	: CDC * - pointer to Device context
CRect - area
BOOL - select flag
BOOL - enable / disable flag
Out Parameters	: void
Purpose			: to draw the background
Author			:
-----------------------------------------------------------------------------*/
void CMenuXP::DrawBackGround(CDC *pDC, CRect rect, BOOL bSelected, BOOL bDisabled)
{
	try
	{
		if(bSelected)
		{
			FillRect(pDC, rect, bDisabled? ((m_Style == STYLE_XP)?m_clrBackGround:m_clrSelectedBar): m_clrSelectedBar);
		}
		else
		{
			FillRect(pDC, rect, m_clrBackGround);
		}

		//in XP mode, draw a line rectangle around
		if(m_Style == STYLE_XP && bSelected && !bDisabled)
		{
			CGdiObject *pOldBrush = pDC->SelectStockObject(HOLLOW_BRUSH);
			CGdiObject	*pOldPen = pDC->SelectStockObject(BLACK_PEN);
			pDC->Rectangle(rect);
			pDC->SelectObject(pOldBrush);
			pDC->SelectObject(pOldPen);
		}
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CMenuXP::DrawBackGround"));
	}
}

/*-----------------------------------------------------------------------------
Function		: DrawButton
In Parameters	: CDC * - pointer to Device context
CRect - area
BOOL - select flag
BOOL - enable / disable flag
BOOL - check flag
Out Parameters	: void
Purpose			: to draw the individual icon buttons
Author			:
-----------------------------------------------------------------------------*/
void CMenuXP::DrawButton(CDC *pDC, CRect rect, BOOL bSelected, BOOL bDisabled, BOOL bChecked)
{
	try
	{
		if(m_Style == STYLE_OFFICE)
		{
			// normal: fill BG depending on state
			FillRect(pDC, rect, (bChecked && !bSelected)? m_clrBackGround+RGB(2, 2, 2): m_clrBackGround);

			// draw pushed-in or popped-out edge
			if(!bDisabled && (bSelected || bChecked))
			{
				pDC->DrawEdge(rect, bChecked ? BDR_SUNKENOUTER : BDR_RAISEDINNER,
					BF_RECT);
			}
		}
		else if(m_Style == STYLE_XP && !bSelected)
		{
			if(bChecked && !bDisabled)
			{
				DrawBackGround(pDC, rect, TRUE, FALSE);
			}
		}
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CMenuXP::DrawButton"));
	}
}

/*-----------------------------------------------------------------------------
Function		: DrawIconArea
In Parameters	: CDC * - pointer to Device context
CRect - area
BOOL - select flag
BOOL - enable / disable flag
BOOL - check flag
Out Parameters	: void
Purpose			: to draw the icon area, the icon is not included, only in XP style
Author			:
-----------------------------------------------------------------------------*/
void CMenuXP::DrawIconArea(CDC *pDC, CRect rect, BOOL bSelected, BOOL bDisabled, BOOL bChecked)
{
	try
	{
		if(m_Style != STYLE_XP)
			return;

		// normal: fill BG depending on state
		if(!bSelected || bDisabled)
		{
			FillRect(pDC, rect, m_clrIconArea);
		}
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CMenuXP::DrawIconArea"));
	}
}

/*-----------------------------------------------------------------------------
Function		: DrawIcon
In Parameters	: CDC * - pointer to Device context
CRect - area
BOOL - select flag
BOOL - enable / disable flag
Out Parameters	: void
Purpose			: to draw the icon
Author			:
-----------------------------------------------------------------------------*/
void CMenuXP::DrawIcon(CDC *pDC, CRect rect, HICON hIcon, BOOL bSelected, BOOL bDisabled)
{
	try
	{
		if(bDisabled)
		{
			DrawEmbossed(pDC, hIcon, rect);
		}
		else
		{
			::DrawIconEx(pDC->m_hDC, rect.left, rect.top, hIcon,
				rect.Width(), rect.Height(), 0, NULL,
				DI_NORMAL);
		}
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CMenuXP::DrawIcon"));
	}
}

/*-----------------------------------------------------------------------------
Function		: DrawSideBar
In Parameters	: CDC * - pointer to Device context
CRect - area
HICON - handle to icon
CString - text
Out Parameters	: void
Purpose			: to draw the sidebar
Author			:
-----------------------------------------------------------------------------*/
void CMenuXP::DrawSideBar(CDC *pDC, CRect rect, HICON hIcon, CString strText)
{
	try
	{
		rect.right += 3;	//fill the gap produced by the menubreak

		HBITMAP	bmpBar = CreateGradientBMP(
			pDC->m_hDC, m_clrSideBarStart, m_clrSideBarEnd,
			rect.Width(), rect.Height(),
			0, 256);
		if(bmpBar)
		{
			CDC memDC;
			memDC.CreateCompatibleDC(pDC);
			HBITMAP hOldBmp = (HBITMAP)::SelectObject(memDC.m_hDC, bmpBar);
			pDC->BitBlt(rect.left, rect.top,
				rect.Width(), rect.Height(),
				&memDC, 0, 0, SRCCOPY);
			::SelectObject(memDC, hOldBmp);
			::DeleteObject(bmpBar);
		}
		//Draw Sidebar text
		CFont	vertFont;
		vertFont.CreateFont(16, 0, 900, 900, FW_BOLD,
			0, 0, 0, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
			CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY,
			DEFAULT_PITCH, _T("Arial"));
		CFont *pOldFont = pDC->SelectObject(&vertFont);
		COLORREF oldColor = pDC->GetTextColor();
		pDC->SetTextColor(RGB(255, 255, 255));
		pDC->SetBkMode(TRANSPARENT);
		pDC->TextOut(rect.left+2, rect.bottom-4, strText);
		pDC->SetTextColor(oldColor);
		pDC->SelectObject(pOldFont);
		vertFont.DeleteObject();
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CMenuXP::DrawSideBar"));
	}
}

/*-----------------------------------------------------------------------------
Function		: DrawCheckMark
In Parameters	: CDC * - pointer to Device context
CRect - area
BOOL - select flag
Out Parameters	: void
Purpose			: to draw the check mark
Author			:
-----------------------------------------------------------------------------*/
void CMenuXP::DrawCheckMark(CDC *pDC, CRect rect, BOOL bSelected)
{

	try
	{
		CBitmap bmp;	//Check mark bitmap
		//"#define OEMRESOURCE" must be in the begining of your stdafx.h
		//for the LoadOEMBitmap to work
		VERIFY(bmp.LoadOEMBitmap(OBM_CHECK));


		// center bitmap in caller's rectangle
		BITMAP bm;
		bmp.GetBitmap(&bm);
		int cx = bm.bmWidth;
		int cy = bm.bmHeight;
		CRect rcDest = rect;
		CPoint p(0,0);
		CSize delta(CPoint((rect.Width() - cx)/2, (rect.Height() - cy)/2));
		if(rect.Width() > cx)
			rcDest = CRect(rect.TopLeft() + delta, CSize(cx, cy));
		else
			p -= delta;

		// select checkmark into memory DC
		CDC memdc;
		memdc.CreateCompatibleDC(pDC);
		CBitmap *pOldBmp = memdc.SelectObject(&bmp);

		COLORREF colorOld =
			pDC->SetBkColor(GetSysColor(bSelected ? COLOR_MENU : COLOR_3DLIGHT));

		pDC->BitBlt(rcDest.left, rcDest.top, rcDest.Width(), rcDest.Height(),
			&memdc, p.x, p.y, SRCCOPY);
		pDC->SetBkColor(colorOld);

		memdc.SelectObject(pOldBmp);
		bmp.DeleteObject();

		/*CRect	rcDest = rect;
		pDC->DrawFrameControl(rcDest, DFC_MENU, DFCS_MENUCHECK);*/
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in C CMenuXP::DrawCheckMark"));
	}
}

/*-----------------------------------------------------------------------------
Function		: DrawText
In Parameters	: CDC * - pointer to Device context
CRect - area
CString - text
BOOL - select flag
BOOL - enable/disable flag
BOOL - bold flag
Out Parameters	: void
Purpose			: to draw menu text
Author			:
-----------------------------------------------------------------------------*/
void CMenuXP::DrawText(CDC *pDC, CRect rect, CString strText, BOOL bSelected, BOOL bDisabled, BOOL bBold)
{
	try
	{
		CFont*	pOldFont;
		CFont	fontBold;

		if(bBold)
		{
			LOGFONT	logFont;
			m_fontMenu.GetLogFont(&logFont);
			logFont.lfWeight = FW_BOLD;
			fontBold.CreateFontIndirect(&logFont);

			pOldFont = pDC->SelectObject(&fontBold);
		}
		else
		{
			pOldFont = pDC->SelectObject(&m_fontMenu);
		}

		pDC->SetBkMode(TRANSPARENT);
		if(bDisabled && (!bSelected || m_Style == STYLE_XP))
		{
			DrawMenuText(*pDC, rect + CPoint(1, 1), strText, m_clrSelectedText);
		}
		if(bDisabled)
		{
			DrawMenuText(*pDC, rect, strText, m_clrDisabledText);
		}
		else
		{
			DrawMenuText(*pDC, rect, strText, bSelected? m_clrSelectedText : m_clrText);
		}

		pDC->SelectObject(pOldFont);

		if(bBold)
			fontBold.DeleteObject();
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in  CMenuXP::DrawText"));
	}
}

/*-----------------------------------------------------------------------------
Function		: SetMenuFont
In Parameters	: LOGFONT - font struct
Out Parameters	: void
Purpose			: to set menu font
Author			:
-----------------------------------------------------------------------------*/
BOOL CMenuXP::SetMenuFont(LOGFONT	lgfont)
{
	try
	{
		m_fontMenu.DeleteObject();
		return m_fontMenu.CreateFontIndirect(&lgfont);
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CMenuXP::SetMenuFont"));
	}
	return false;
}

/*-----------------------------------------------------------------------------
Function		: Clear
In Parameters	: void
Out Parameters	: void
Purpose			: to clear all memory and handles
Author			:
-----------------------------------------------------------------------------*/
void CMenuXP::Clear(void)
{
	try
	{
		UINT	nCount = GetMenuItemCount();
		for (UINT i=0; i<nCount; i++)
		{
			MENUITEMINFO	info = {0};
			info.cbSize = sizeof(MENUITEMINFO);
			info.fMask = MIIM_DATA | MIIM_TYPE;
			GetMenuItemInfo(i, &info, TRUE);

			CMenuXPItem *pData = (CMenuXPItem *)info.dwItemData;
			if((info.fType & MFT_OWNERDRAW) && pData && pData->IsMyData())
			{
				delete pData;
			}

			CMenu	*pSubMenu = GetSubMenu(i);
			if(pSubMenu && pSubMenu->IsKindOf(RUNTIME_CLASS(CMenuXP)))
				delete pSubMenu;
		}
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CMenuXP::Clear"));
	}
}

/*-----------------------------------------------------------------------------
Function		: DrawEmbossed
In Parameters	: CDC * - pointer to Device context
HICON - handle to icon
CRect - area
BOOL - color flag
Out Parameters	: void
Purpose			: to draw embossed icon for the disabled item
Author			:
-----------------------------------------------------------------------------*/
const DWORD		MAGICROP		= 0xb8074a;
const COLORREF CWHITE  = RGB(255,255,255);

void CMenuXP::DrawEmbossed(CDC *pDC, HICON hIcon, CRect rect, BOOL bColor)
{
	try
	{
		CDC	memdc;
		memdc.CreateCompatibleDC(pDC);
		int cx = rect.Width();
		int cy = rect.Height();


		// create mono or color bitmap
		CBitmap bm;
		if(bColor)
			bm.CreateCompatibleBitmap(pDC, cx, cy);
		else
			bm.CreateBitmap(cx, cy, 1, 1, NULL);

		// draw image into memory DC--fill BG white first
		CBitmap* pOldBitmap = memdc.SelectObject(&bm);
		//FillRect(&memdc, CRect(0, 0, cx, cy), m_clrBackGround);
		memdc.PatBlt(0, 0, cx, cy, WHITENESS);
		::DrawIconEx(memdc.m_hDC, 0, 0, hIcon, cx, cy, 1, NULL, DI_NORMAL);

		// This seems to be required.Why, I don't know.???
		COLORREF colorOldBG = pDC->SetBkColor(CWHITE);

		// Draw using hilite offset by (1,1), then shadow
		CBrush brShadow(GetSysColor(COLOR_3DSHADOW));
		CBrush brHilite(GetSysColor(COLOR_3DHIGHLIGHT));
		CBrush* pOldBrush = pDC->SelectObject(&brHilite);
		pDC->BitBlt(rect.left+1, rect.top+1, cx, cy, &memdc, 0, 0, MAGICROP);
		pDC->SelectObject(&brShadow);
		pDC->BitBlt(rect.left, rect.top, cx, cy, &memdc, 0, 0, MAGICROP);
		pDC->SelectObject(pOldBrush);
		pDC->SetBkColor(colorOldBG);				 // restore
		memdc.SelectObject(pOldBitmap);		 //...
		bm.DeleteObject();
		brShadow.DeleteObject();
		brHilite.DeleteObject();
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CMenuXP::DrawEmbossed"));
	}
}

/*-----------------------------------------------------------------------------
Function		: FillRect
In Parameters	: CDC * - pointer to Device context
CRect - area
COLORREF - color
Out Parameters	: void
Purpose			: to fill a rectangle with a solid color
Author			:
-----------------------------------------------------------------------------*/
void CMenuXP::FillRect(CDC *pDC, const CRect& rc, COLORREF color)
{
	try
	{
		CBrush brush(color);
		CBrush* pOldBrush = pDC->SelectObject(&brush);
		pDC->PatBlt(rc.left, rc.top, rc.Width(), rc.Height(), PATCOPY);
		pDC->SelectObject(pOldBrush);
		brush.DeleteObject();
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught inCMenuXP::FillRect"));
	}
}

/*-----------------------------------------------------------------------------
Function		: CreateGradientBMP
In Parameters	: HDC - Device context handle
COLORREF - color1
COLORREF - color2
int - width
int - height
int - dir
int - num colors
Out Parameters	: void
Purpose			: to create gradient bitmap
Author			:
-----------------------------------------------------------------------------*/
HBITMAP CMenuXP::CreateGradientBMP(HDC hDC,COLORREF cl1,COLORREF cl2,int nWidth,int nHeight,int nDir,int nNumColors)
{
	try
	{
		if(nNumColors > 256)
			nNumColors = 256;

		COLORREF PalVal[256] = {0};

		int nIndex;
		BYTE peRed=0,peGreen=0,peBlue=0;

		int r1=GetRValue(cl1);
		int r2=GetRValue(cl2);
		int g1=GetGValue(cl1);
		int g2=GetGValue(cl2);
		int b1=GetBValue(cl1);
		int b2=GetBValue(cl2);

		for (nIndex = 0; nIndex < nNumColors; nIndex++)
		{
			peRed = (BYTE)(r1 + MulDiv((r2-r1),nIndex,nNumColors-1));
			peGreen = (BYTE)(g1 + MulDiv((g2-g1),nIndex,nNumColors-1));
			peBlue = (BYTE)(b1 + MulDiv((b2-b1),nIndex,nNumColors-1));

			PalVal[nIndex]=(peRed << 16)| (peGreen << 8)| (peBlue);
		}

		int x,y,w,h;
		w=nWidth;
		h=nHeight;

		DWORD*			pGradBits = new DWORD[w*h*sizeof(DWORD)];
		BITMAPINFO		GradBitInfo = {0};
		GradBitInfo.bmiHeader.biSize=sizeof(BITMAPINFOHEADER);
		GradBitInfo.bmiHeader.biWidth=w;
		GradBitInfo.bmiHeader.biHeight=h;
		GradBitInfo.bmiHeader.biPlanes=1;
		GradBitInfo.bmiHeader.biBitCount=32;
		GradBitInfo.bmiHeader.biCompression=BI_RGB;

		if(nDir == 0)
		{
			for(y=0;y<h;y++)
			{
				for(x=0;x<w;x++)
				{
					*(pGradBits+(y*w) +x)=PalVal[MulDiv(nNumColors,y,h)];
				}
			}
		}
		else if(nDir == 1)
		{
			for(y=0;y<h;y++)
			{
				int l,r;
				l=MulDiv((nNumColors/2),y,h);
				r=l+(nNumColors/2) -1;
				for(x=0;x<w;x++)
				{
					*(pGradBits+(y*w) +x)=PalVal[l+MulDiv((r-l),x,w)];
				}
			}
		}
		else if(nDir == 2)
		{
			for(x=0;x<w;x++)
			{
				for(y=0;y<h;y++)
				{
					*(pGradBits+(y*w) +x)=PalVal[MulDiv(nNumColors,x,w)];
				}
			}
		}
		else if(nDir == 3)
		{
			for(y=0;y<h;y++)
			{
				int l,r;
				r=MulDiv((nNumColors/2),y,h);
				l=r+(nNumColors/2) -1;
				for(x=0;x<w;x++)
				{
					*(pGradBits+(y*w) +x)=PalVal[l+MulDiv((r-l),x,w)];
				}
			}
		}

		HBITMAP hBmp = CreateDIBitmap(hDC,&GradBitInfo.bmiHeader,CBM_INIT,
			pGradBits,&GradBitInfo,DIB_RGB_COLORS);

		delete [] pGradBits;

		return hBmp;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in  CMenuXP::CreateGradientBMP"));
	}
	return NULL;
}

/*-----------------------------------------------------------------------------
Function		: OnMenuChar
In Parameters	: UINT - char
UINT - flags
CMenu * - pointer to current object
Out Parameters	: LRESULT -
Purpose			: static member for keyboard operation, you can used it in
you parent window it work with shortcut key
Author			:
-----------------------------------------------------------------------------*/
LRESULT CMenuXP::OnMenuChar(UINT nChar, UINT nFlags, CMenu* pMenu)
{
	try
	{
		UINT iCurrentItem = (UINT) -1; // guaranteed higher than any command ID
		CUIntArray arItemsMatched;		// items that match the character typed

		UINT nItem = pMenu->GetMenuItemCount();
		UINT i;
		for (i=0; i< nItem; i++)
		{
			MENUITEMINFO	info = {0};
			info.cbSize = sizeof(info);
			info.fMask = MIIM_DATA | MIIM_TYPE | MIIM_STATE;
			::GetMenuItemInfo(*pMenu, i, TRUE, &info);

			CMenuXPItem	*pData = (CMenuXPItem *)info.dwItemData;
			if((info.fType & MFT_OWNERDRAW) && pData && pData->IsMyData())
			{
				CString	text = pData->m_strText;
				int iAmpersand = text.Find('&');
				if(iAmpersand >=0 && toupper(nChar) == toupper(text[iAmpersand+1]))
					arItemsMatched.Add(i);
			}
			if(info.fState & MFS_HILITE)
				iCurrentItem = i; // note index of current item
		}


		// arItemsMatched now contains indexes of items that match the char typed.
		//
		//   * if none: beep
		//   * if one:  execute it
		//   * if more than one: hilite next
		//
		UINT nFound = static_cast<UINT>(arItemsMatched.GetSize());

		if(nFound == 0)
			return 0;

		else if(nFound == 1)
			return MAKELONG(arItemsMatched[0], MNC_EXECUTE);

		// more than one found--return 1st one past current selected item;
		UINT iSelect = 0;
		for (i=0; i < nFound; i++){
			if(arItemsMatched[i] > iCurrentItem){
				iSelect = i;
				break;
			}
		}
		return MAKELONG(arItemsMatched[iSelect], MNC_SELECT);
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in  CMenuXP::OnMenuChar"));
	}
	return 0;
}

/*-----------------------------------------------------------------------------
Function		: DrawMenuText
In Parameters	: CDC&  - reference to Device context
CRect - area
CString - text
COLORREF - color
Out Parameters	: LRESULT -
Purpose			: to draw menu text
Author			:
-----------------------------------------------------------------------------*/
void CMenuXP::DrawMenuText(CDC& dc, CRect rc, CString text,	COLORREF color)
{
	try
	{
		CString left = text;
		CString right;
		int iTabPos = left.Find(_T('\t'));
		if(iTabPos >= 0){
			right = left.Right(left.GetLength() - iTabPos - 1);
			left  = left.Left(iTabPos);
		}
		dc.SetTextColor(color);
		dc.DrawText(left, &rc, DT_MYSTANDARD);
		if(iTabPos > 0)
			dc.DrawText(right, &rc, DT_MYSTANDARD|DT_RIGHT);
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CMenuXP::DrawMenuText"));
	}
}

/*-----------------------------------------------------------------------------
Function		: FindSubMenuFromID
In Parameters	: DWORD - ID
Out Parameters	: CMenuXP * - pinter to object
Purpose			: to find a popupmenu from a menuitem id
Author			:
-----------------------------------------------------------------------------*/
CMenuXP *CMenuXP::FindSubMenuFromID(DWORD dwID)
{
	try
	{
		CMenuXP	*pSubMenu;
		CMenuXP	*pResult;
		UINT i;
		for (i=0; i<GetMenuItemCount(); i++)
		{
			if(GetMenuItemID(i) == dwID)
				return this;
		}

		for (i=0; i<GetMenuItemCount(); i++)
		{
			pSubMenu = (CMenuXP *)GetSubMenu(i);
			if(pSubMenu)
			{
				pResult = pSubMenu->FindSubMenuFromID(dwID);
				if(pResult)
					return pResult;
			}
		}

		return NULL;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CMenuXP::FindSubMenuFromID"));
	}
	return NULL;
}

/*-----------------------------------------------------------------------------
Function		: AddSideBar
In Parameters	: CMenuXPSideBar * - CMenuXPSideBar object pointer
Out Parameters	: BOOL -
Purpose			: to Add a gradient sidebar, it must be the first item in a popupmenu
Author			:
-----------------------------------------------------------------------------*/
BOOL CMenuXP::AddSideBar(CMenuXPSideBar *pItem)
{
	try
	{
		ASSERT(pItem);
		if(NULL == pItem)
		{
			return FALSE;
		}
		m_bBreak = TRUE;
		m_bBreakBar = FALSE;

		return AppendMenu(MF_OWNERDRAW, pItem->m_dwID, (LPCTSTR)pItem);

	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CMenuXP::AddSideBar"));
	}
	return false;
}

/*-----------------------------------------------------------------------------
Function		: AppendODMenu
In Parameters	: UINT - flags
CMenuXPItem * - menu item pointer
ACCEL * - key ptr
Out Parameters	: BOOL -
Purpose			: to add a normal menuitem, an accelerator key could be specified,
and the accel text will be added automatically
Author			:
-----------------------------------------------------------------------------*/
BOOL CMenuXP::AppendODMenu(UINT nFlags, CMenuXPItem *pItem)
{
	try
	{
		ASSERT(pItem);
		if(NULL == pItem)
		{
			return FALSE;
		}

		nFlags |= MF_OWNERDRAW;
		if(m_bBreak)
			nFlags |= MF_MENUBREAK;
		if(m_bBreakBar)
			nFlags |= MF_MENUBARBREAK;
		m_bBreak = m_bBreakBar = FALSE;

		return AppendMenu(nFlags, pItem->m_dwID, (LPCTSTR)pItem);
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CMenuXP::AppendODMenu"));
	}
	return false;
}

/*-----------------------------------------------------------------------------
Function		: AppendSeparator
In Parameters	: void
Out Parameters	: BOOL -
Purpose			: to Add a separator line
Author			:
-----------------------------------------------------------------------------*/
BOOL CMenuXP::AppendSeparator(void)
{
	try
	{
		m_bBreak = m_bBreakBar = FALSE;

		CMenuXPSeparator *pItem = new CMenuXPSeparator;

		return AppendMenu(MF_OWNERDRAW | MF_SEPARATOR, 0, (LPCTSTR)pItem);
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CMenuXP::AppendSeparator"));
	}
	return false;
}

/*-----------------------------------------------------------------------------
Function		: AppendODPopup
In Parameters	: UINT  - Flags
CMenuXP * - menu ptr
CMenuXPItem * - menu item ptr
Out Parameters	: BOOL -
Purpose			: to add a popup menu
Author			:
-----------------------------------------------------------------------------*/
BOOL CMenuXP::AppendODPopup(UINT nFlags, CMenuXP *pPopup, CMenuXPItem *pItem)
{
	try
	{
		ASSERT(pPopup);
		ASSERT(pItem);

		nFlags |= MF_OWNERDRAW;
		nFlags |= MF_POPUP;
		if(m_bBreak)
			nFlags |= MF_MENUBREAK;
		if(m_bBreakBar)
			nFlags |= MF_MENUBARBREAK;
		m_bBreak = m_bBreakBar = FALSE;

		return AppendMenu(nFlags, reinterpret_cast<UINT_PTR>(pPopup->m_hMenu), (LPCTSTR)pItem);
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CMenuXP::AppendODPopup"));
	}
	return FALSE;
}

/*-----------------------------------------------------------------------------
Function		: Break
In Parameters	: void
Out Parameters	: void
Purpose			: to Change column, the next item added will be in the next column
Author			:
-----------------------------------------------------------------------------*/
void CMenuXP::Break(void)
{
	m_bBreak = TRUE;
}

/*-----------------------------------------------------------------------------
Function		: BreakBar
In Parameters	: void
Out Parameters	: void
Purpose			: same as Break(), except that a break line will appear between the two columns
Author			:
-----------------------------------------------------------------------------*/
void CMenuXP::BreakBar(void)
{
	m_bBreakBar = TRUE;
}

