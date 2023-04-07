/*=============================================================================
   FILE			 : XHeaderCtrl.cpp
   ABSTRACT		 : 
   DOCUMENTS	 : LiveUpdate DesignDoc.doc 
   AUTHOR		 :
   COMPANY		 : Aura 
   COPYRIGHT NOTICE:
			(C) Aura
      		Created as an unpublished copyright work.  All rights reserved.
     		This document and the information it contains is confidential and
      		proprietary to Aura.  Hence, it may not be 
      		used, copied, reproduced, transmitted, or stored in any form or by any 
      		means, electronic, recording, photocopying, mechanical or otherwise, 
      		with out the prior written permission of Aura
   CREATION DATE   : 2/3/2005
   NOTES		 :
   VERSION HISTORY :17 Aug 2007 : Avinash B
					Unicode Supported.
				
============================================================================*/

#include "stdafx.h"
#include "XHeaderCtrl.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

IMPLEMENT_DYNCREATE(CXHeaderCtrl, CHeaderCtrl)

BEGIN_MESSAGE_MAP(CXHeaderCtrl, CHeaderCtrl)
	ON_MESSAGE(HDM_INSERTITEMA, OnInsertItem)
	ON_MESSAGE(HDM_INSERTITEMW, OnInsertItem)
	ON_MESSAGE(HDM_DELETEITEM, OnDeleteItem)
	ON_MESSAGE(HDM_SETIMAGELIST, OnSetImageList)
	ON_MESSAGE(HDM_LAYOUT, OnLayout)
	ON_WM_PAINT()
	ON_WM_SYSCOLORCHANGE()
	ON_WM_ERASEBKGND()
END_MESSAGE_MAP()

/*-----------------------------------------------------------------------------
Function		: CXHeaderCtrl(CONSTRUCTOR)
In Parameters	:
Out Parameters	:
Purpose		:Initialze CXHeaderCtrl class
Author		:
-----------------------------------------------------------------------------*/
CXHeaderCtrl::CXHeaderCtrl()
{
	try
	{
		m_bDoubleBuffer = TRUE;
		m_iSpacing = 6;
		m_sizeArrow.cx = 8;
		m_sizeArrow.cy = 8;
		m_sizeImage.cx = 0;
		m_sizeImage.cy = 0;
		m_bStaticBorder = FALSE;
		m_nDontDropCursor = 0;
		m_bResizing = FALSE;
		m_nClickFlags = 0;

		m_cr3DHighLight = ::GetSysColor(COLOR_3DHIGHLIGHT);
		m_cr3DShadow    = ::GetSysColor(COLOR_3DSHADOW);
		m_cr3DFace      = ::GetSysColor(COLOR_3DFACE);
		m_crBtnText     = ::GetSysColor(COLOR_BTNTEXT);
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CXHeaderCtrl::CXHeaderCtrl"));
	}
}

/*-----------------------------------------------------------------------------
Function		: ~CXHeaderCtrl
In Parameters	:
Out Parameters	:
Purpose		:Detruct CXHeaderCtrl class
Author		:
-----------------------------------------------------------------------------*/
CXHeaderCtrl::~CXHeaderCtrl()
{
}

/*-----------------------------------------------------------------------------
Function		:ModifyProperty
In Parameters	: WPARAM : additional information regarding Controlls
: LPARAM : additional information regarding Controlls
Out Parameters	:true if modifes any controll otherwise false
Purpose		:This function modifies header controlls
Author		:
-----------------------------------------------------------------------------*/
BOOL CXHeaderCtrl::ModifyProperty(WPARAM wParam, LPARAM lParam)
{
	try
	{
		switch(wParam)
		{
		case FH_PROPERTY_SPACING:
			m_iSpacing = (int)lParam;
			break;

		case FH_PROPERTY_ARROW:
			m_sizeArrow.cx = LOWORD(lParam);
			m_sizeArrow.cy = HIWORD(lParam);
			break;

		case FH_PROPERTY_STATICBORDER:
			m_bStaticBorder = (BOOL)lParam;
			break;

		case FH_PROPERTY_DONTDROPCURSOR:
			m_nDontDropCursor = (UINT)lParam;
			break;

		default:
			return FALSE;
		}

		Invalidate();
		return TRUE;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CXHeaderCtrl::ModifyProperty"));
	}
	return FALSE;
}

/*-----------------------------------------------------------------------------
Function		: DrawCtrl
In Parameters	: CDC* : pointer to CDC
Out Parameters	:
Purpose		:This function draw all the controlls
Author		:
-----------------------------------------------------------------------------*/
void CXHeaderCtrl::DrawCtrl(CDC* pDC)
{
	try
	{
		CRect rectClip;
		if(pDC->GetClipBox(&rectClip) == ERROR)
			return;

		CRect rectClient, rectItem;
		GetClientRect(&rectClient);

		pDC->FillSolidRect(rectClip, m_cr3DFace);

		int iItems = GetItemCount();
		ASSERT(iItems >= 0);

		CPen penHighLight(PS_SOLID, 1, m_cr3DHighLight);
		CPen penShadow(PS_SOLID, 1, m_cr3DShadow);
		CPen* pPen = pDC->GetCurrentPen();

		CFont* pFont = pDC->SelectObject(GetFont());

		pDC->SetBkColor(m_cr3DFace);
		pDC->SetTextColor(m_crBtnText);

		int iWidth = 0;

		for (int i = 0; i < iItems; i++)
		{
			int iItem = OrderToIndex(i);

			TCHAR szText[FLATHEADER_TEXT_MAX];

			HDITEM hditem;
			hditem.mask = HDI_WIDTH|HDI_FORMAT|HDI_TEXT|HDI_IMAGE|HDI_BITMAP;
			hditem.pszText = szText;
			hditem.cchTextMax = _countof(szText);
			VERIFY(GetItem(iItem, &hditem));

			VERIFY(GetItemRect(iItem, rectItem));

			if(rectItem.right >= rectClip.left || rectItem.left <= rectClip.right)
			{
				if(hditem.fmt & HDF_OWNERDRAW)
				{
					DRAWITEMSTRUCT disItem;
					disItem.CtlType = ODT_BUTTON;
					disItem.CtlID = GetDlgCtrlID();
					disItem.itemID = iItem;
					disItem.itemAction = ODA_DRAWENTIRE;
					disItem.itemState = 0;
					disItem.hwndItem = m_hWnd;
					disItem.hDC = pDC->m_hDC;
					disItem.rcItem = rectItem;
					disItem.itemData = 0;

					DrawItem(&disItem);
				}
				else
				{
					rectItem.DeflateRect(m_iSpacing, 0);
					DrawItem(pDC, rectItem, &hditem);
					rectItem.InflateRect(m_iSpacing, 0);
				}

				if(i < iItems-1)
				{
					pDC->SelectObject(&penShadow);
					pDC->MoveTo(rectItem.right-1, rectItem.top+2);
					pDC->LineTo(rectItem.right-1, rectItem.bottom-2);

					pDC->SelectObject(&penHighLight);
					pDC->MoveTo(rectItem.right, rectItem.top+2);
					pDC->LineTo(rectItem.right, rectItem.bottom-2);
				}
			}

			iWidth += hditem.cxy;
		}

		if(iWidth > 0)
		{
			rectClient.right = rectClient.left + iWidth;
			pDC->Draw3dRect(rectClient, m_cr3DHighLight, m_cr3DShadow);
		}

		pDC->SelectObject(pFont);
		pDC->SelectObject(pPen);

		penHighLight.DeleteObject();
		penShadow.DeleteObject();
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CXHeaderCtrl::DrawCtrl"));
	}
}

/*-----------------------------------------------------------------------------
Function		: DrawItem
In Parameters	:  LPDRAWITEMSTRUCT :
Out Parameters	:
Purpose		:This Function is overridden for self draw header controls
Author		:
-----------------------------------------------------------------------------*/
void CXHeaderCtrl::DrawItem(LPDRAWITEMSTRUCT)
{
	ASSERT(FALSE);  // must override for self draw header controls
}

/*-----------------------------------------------------------------------------
Function		: DrawItem
In Parameters	: CDC* :pointer to CDC class
: CRect : object of CRect
: LPHDITEM : pointer to structure _HDITEM
Out Parameters	:
Purpose		:This function draw bitmap,text and image
Author		:
-----------------------------------------------------------------------------*/
void CXHeaderCtrl::DrawItem(CDC* pDC, CRect rect, LPHDITEM lphdi)
{
	try
	{
		ASSERT(lphdi->mask & HDI_FORMAT);

		int iWidth = 0;

		CBitmap* pBitmap = NULL;
		BITMAP BitmapInfo;

		if(lphdi->fmt & HDF_BITMAP)
		{
			ASSERT(lphdi->mask & HDI_BITMAP);
			ASSERT(lphdi->hbm);

			pBitmap = CBitmap::FromHandle(lphdi->hbm);
			if(pBitmap)
				VERIFY(pBitmap->GetObject(sizeof(BITMAP), &BitmapInfo));
		}

		rect.left += ((iWidth = DrawImage(pDC, rect, lphdi, FALSE)) != 0)? iWidth + m_iSpacing : 0;
		rect.right -= ((iWidth = DrawBitmap(pDC, rect, lphdi, pBitmap, &BitmapInfo, TRUE)) != 0)?
			iWidth + m_iSpacing : 0;
		DrawText(pDC, rect, lphdi);
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CXHeaderCtrl::DrawItem"));
	}
}

/*-----------------------------------------------------------------------------
Function		: DrawImage
In Parameters	: CDC* :pointer to CDC class
: CRect : object of CRect
: LPHDITEM : pointer to structure _HDITEM
: BOOL :
Out Parameters	: int : returns width of image
Purpose		: is member function to draw an image from an image list.
Author		:
-----------------------------------------------------------------------------*/
int CXHeaderCtrl::DrawImage(CDC* pDC, CRect rect, LPHDITEM lphdi, BOOL bRight)
{
	try
	{
		CImageList* pImageList = GetImageList();
		int iWidth = 0;

		if(lphdi->iImage != XHEADERCTRL_NO_IMAGE)
		{
			if(pImageList)
			{
				if(rect.Width() > 0)
				{
					POINT point;

					point.y = rect.CenterPoint().y - (m_sizeImage.cy >> 1);

					if(bRight)
						point.x = rect.right - m_sizeImage.cx;
					else
						point.x = rect.left;

					SIZE size;
					size.cx = rect.Width()<m_sizeImage.cx ? rect.Width():m_sizeImage.cx;
					size.cy = m_sizeImage.cy;

					// save image list background color
					COLORREF rgb = pImageList->GetBkColor();

					// set image list background color to same as header control
					pImageList->SetBkColor(pDC->GetBkColor());
					pImageList->DrawIndirect(pDC, lphdi->iImage, point, size, CPoint(0, 0));
					pImageList->SetBkColor(rgb);

					iWidth = m_sizeImage.cx;
				}
			}
		}

		return iWidth;

	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CXHeaderCtrl::DrawImage"));
	}
	return 0;
}

/*-----------------------------------------------------------------------------
Function		: DrawBitmap
In Parameters	: CDC* :pointer to CDC class
: CRect : object of CRect
: LPHDITEM : pointer to structure _HDITEM
: CBitmap* : pointer to CBITMAP
: BITMAP* : pointer to BITMAP
: BOOL :
Out Parameters	: int :returns width of bitmap
Purpose		: Copies a bitmap from the source device context to this current
device context
Author		:
-----------------------------------------------------------------------------*/
int CXHeaderCtrl::DrawBitmap(CDC* pDC, CRect rect, LPHDITEM lphdi, CBitmap* pBitmap,
							 BITMAP* pBitmapInfo, BOOL bRight)
{
	try
	{
		UNUSED_ALWAYS(lphdi);

		int iWidth = 0;

		if(pBitmap)
		{
			iWidth = pBitmapInfo->bmWidth;
			if(iWidth <= rect.Width() && rect.Width() > 0)
			{
				POINT point;

				point.y = rect.CenterPoint().y - (pBitmapInfo->bmHeight >> 1);

				if(bRight)
					point.x = rect.right - iWidth;
				else
					point.x = rect.left;

				CDC dc;
				if(dc.CreateCompatibleDC(pDC) == TRUE)
				{
					VERIFY(dc.SelectObject(pBitmap));
					iWidth = pDC->BitBlt(
						point.x, point.y,
						pBitmapInfo->bmWidth, pBitmapInfo->bmHeight,
						&dc,
						0, 0,
						SRCCOPY
						)? iWidth:0;
				}
				else
					iWidth = 0;
			}
			else
				iWidth = 0;
		}

		return iWidth;

	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CXHeaderCtrl::DrawBitmap"));
	}
	return 0;
}

/*-----------------------------------------------------------------------------
Function		: DrawText
In Parameters	: CDC* :pointer to CDC
: CRect : object to CRect structure
: LPHDITEM : pointer to structure _HDITEM
Out Parameters	: int : return x cordinate of CSIZE object if it is greater then 0
Purpose		:  format text in the given rectangle
Author		:
-----------------------------------------------------------------------------*//////////////////////////////////////////////////////////////////
int CXHeaderCtrl::DrawText(CDC* pDC, CRect rect, LPHDITEM lphdi)
{
	try
	{
		CSize size;

		//dipali
		CFont *pOldFont = NULL;
		CFont boldfont;
		CFont *font = pDC->GetCurrentFont();
		if(font)
		{
			LOGFONT lf;
			font->GetLogFont(&lf);
			lf.lfWeight = FW_BOLD;
			boldfont.CreateFontIndirect(&lf);
			pOldFont = pDC->SelectObject(&boldfont);
		}
		//dipali
		pDC->SetTextColor(RGB(0,0,0));

		if(rect.Width() > 0 && lphdi->mask & HDI_TEXT && lphdi->fmt & HDF_STRING)
		{
			size = pDC->GetTextExtent(lphdi->pszText);

			// always center column headers
			pDC->DrawText(lphdi->pszText, -1, rect,
				DT_LEFT|DT_END_ELLIPSIS|DT_SINGLELINE|DT_VCENTER);
			if(pOldFont)
				pDC->SelectObject(pOldFont);
		}

		size.cx = rect.Width() >size.cx ? size.cx:rect.Width();
		return size.cx>0 ? size.cx:0;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CXHeaderCtrl::DrawText"));
	}
	return 0;
}

/*-----------------------------------------------------------------------------
Function		: OnInsertItem
In Parameters	: WPARAM :additional information
: LPARAM :additional information
Out Parameters	: LRESULT : LRESULT : return value,return by default Window procedure
Purpose		:calls default Window procedure
Author		:
-----------------------------------------------------------------------------*/
LRESULT CXHeaderCtrl::OnInsertItem(WPARAM, LPARAM)
{
	return Default();
}

/*-----------------------------------------------------------------------------
Function		: OnDeleteItem
In Parameters	: WPARAM :additional information
: LPARAM :additional information
Out Parameters	: LRESULT : LRESULT : return value,return by default Window procedure
Purpose		:calls default Window procedure
Author		:
-----------------------------------------------------------------------------*/
LRESULT CXHeaderCtrl::OnDeleteItem(WPARAM, LPARAM)
{
	return Default();
}

/*-----------------------------------------------------------------------------
Function		: OnSetImageList
In Parameters	: WPARAM : additional information
: LPARAM :contains information regarding CImageList
Out Parameters	: LRESULT : return value,return by default Window procedure
Purpose		: This function is used to retrieve information about an image.
Author		:
-----------------------------------------------------------------------------*/
LRESULT CXHeaderCtrl::OnSetImageList(WPARAM, LPARAM lParam)
{
	try
	{
		CImageList* pImageList;
		pImageList = CImageList::FromHandle((HIMAGELIST)lParam);

		IMAGEINFO info;
		if(pImageList->GetImageInfo(0, &info))
		{
			m_sizeImage.cx = info.rcImage.right - info.rcImage.left;
			m_sizeImage.cy = info.rcImage.bottom - info.rcImage.top;
		}

		return Default();
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CXHeaderCtrl::OnSetImageList"));
	}
	return 0;
}

/*-----------------------------------------------------------------------------
Function		: OnLayout
In Parameters	: WPARAM : additional information related to the message
: LPARAM :contains information regarding LPHDLAYOUT structure
Out Parameters	: LRESULT : Returns TRUE if successful, or FALSE otherwise.
Purpose		:this function retrives the headerLayout
Author		:
-----------------------------------------------------------------------------*/
LRESULT CXHeaderCtrl::OnLayout(WPARAM, LPARAM lParam)
{
	try
	{
		LPHDLAYOUT lphdlayout = (LPHDLAYOUT)lParam;

		if(m_bStaticBorder)
			lphdlayout->prc->right += GetSystemMetrics(SM_CXBORDER)*2;

		return CHeaderCtrl::DefWindowProc(HDM_LAYOUT, 0, lParam);
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CXHeaderCtrl::OnLayout"));
	}
	return 0;
}

/*-----------------------------------------------------------------------------
Function		:OnSysColorChange
In Parameters	:
Out Parameters	:
Purpose		: The framework calls this member function for all top-level windows
when a change is made in the system color setting
Author		:
-----------------------------------------------------------------------------*/
void CXHeaderCtrl::OnSysColorChange()
{
	try
	{
		TRACE(_T("in CXHeaderCtrl::OnSysColorChange\n"));

		CHeaderCtrl::OnSysColorChange();

		m_cr3DHighLight = ::GetSysColor(COLOR_3DHIGHLIGHT);
		m_cr3DShadow    = ::GetSysColor(COLOR_3DSHADOW);
		m_cr3DFace      = ::GetSysColor(COLOR_3DFACE);
		m_crBtnText     = ::GetSysColor(COLOR_BTNTEXT);
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CXHeaderCtrl::OnSysColorChange"));
	}
}

/*-----------------------------------------------------------------------------
Function		: OnEraseBkgnd
In Parameters	: CDC* :  device-context  pointer
Out Parameters	:BOOL : it always return false
Purpose		:The framework calls this member function when the CWnd object
background needs erasing.
Author		:
-----------------------------------------------------------------------------*/
BOOL CXHeaderCtrl::OnEraseBkgnd(CDC* pDC)
{
	try
	{
		UNUSED_ALWAYS(pDC);
		return TRUE;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CXHeaderCtrl::OnEraseBkgnd"));
	}
	return FALSE;
}

/*-----------------------------------------------------------------------------
Function		: OnPaint
In Parameters	:
Out Parameters	:
Purpose		: The framework calls this member function when Windows or
an application makes a request to repaint a portion of an
application's window.User can put check here for any necessary
internal repainting
Author		:
-----------------------------------------------------------------------------*/
void CXHeaderCtrl::OnPaint()
{
	try
	{
		CPaintDC dc(this);

		if(m_bDoubleBuffer)
		{
			CMemDCEx MemDC(&dc);
			DrawCtrl(&MemDC);
		}
		else
			DrawCtrl(&dc);
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CXHeaderCtrl::OnPaint"));
	}
}
