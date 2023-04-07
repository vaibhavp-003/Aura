// MyListCtrl.cpp : implementation file
//

#include "stdafx.h"
#include "Resource.h"
#include "MyListCtrl.h"

// CMyListCtrl
//#define IDB_THREAT_BMP                  426

IMPLEMENT_DYNAMIC(CMyListCtrl, CListCtrl)
CMyListCtrl::CMyListCtrl()
{
	bPaintImage = false;
	m_ImageList.Create(87, 13, ILC_COLOR24, 3, 3);
#ifdef MAX_PRIVACY
	CBitmap oBMP;
	oBMP.LoadBitmap(IDB_NEW_THREAT_BMP);
	m_ImageList.Add(&oBMP, COLORREF(0x000000));
#else
	CBitmap bitmap;
	bitmap.LoadBitmap(IDB_BITMAP_THREAT_CRITICAL);
	m_ImageList.Add(&bitmap, (COLORREF)0x000000);
	bitmap.DeleteObject();
	bitmap.LoadBitmap(IDB_BITMAP_THREAT_HIGH);
	m_ImageList.Add(&bitmap, (COLORREF)0x000000);
	bitmap.DeleteObject();
	bitmap.LoadBitmap(IDB_BITMAP_THREAT_MEDIUM);
	m_ImageList.Add(&bitmap, (COLORREF)0x000000);
	bitmap.DeleteObject();
	bitmap.LoadBitmap(IDB_BITMAP_THREAT_LOW);
	m_ImageList.Add(&bitmap, (COLORREF)0x000000);
	bitmap.DeleteObject();

	iImageColumn = 1;
#endif
}

CMyListCtrl::~CMyListCtrl()
{
}


BEGIN_MESSAGE_MAP(CMyListCtrl, CListCtrl)
	ON_WM_VSCROLL()
	ON_WM_VSCROLLCLIPBOARD()
	ON_NOTIFY_REFLECT(NM_CUSTOMDRAW, OnNMCustomdraw)
END_MESSAGE_MAP()



// CMyListCtrl message handlers


void CMyListCtrl::OnVScroll(UINT nSBCode, UINT nPos, CScrollBar* pScrollBar)
{
	Invalidate();
	CListCtrl::OnVScroll(nSBCode, nPos, pScrollBar);
}

void CMyListCtrl::OnVScrollClipboard(CWnd* pClipAppWnd, UINT nSBCode, UINT nPos)
{
	CListCtrl::OnVScrollClipboard(pClipAppWnd, nSBCode, nPos);
}


void CMyListCtrl::OnNMCustomdraw(NMHDR *pNMHDR, LRESULT *pResult)
{
	NMLVCUSTOMDRAW* pLVCD = reinterpret_cast<NMLVCUSTOMDRAW*>( pNMHDR );

	//*pResult = CDRF_NOTIFYSUBITEMDRAW;
	//return;

	// If this is the beginning of the control's paint cycle, request
    // notifications for each item.
    if ( CDDS_PREPAINT == pLVCD->nmcd.dwDrawStage )
	{
        *pResult = CDRF_NOTIFYITEMDRAW;
	}
    else if ( CDDS_ITEMPREPAINT == pLVCD->nmcd.dwDrawStage )
	{
        // This is the pre-paint stage for an item.  We need to make another
        // request to be notified during the post-paint stage.
        *pResult = CDRF_NOTIFYSUBITEMDRAW;
	}
    else if ( (CDDS_ITEMPREPAINT| CDDS_SUBITEM) == pLVCD->nmcd.dwDrawStage )
	{
#ifdef MAX_PRIVACY
		if(pLVCD->iSubItem == 1 && bPaintImage == true)// (csVal == L"0" || csVal == L"1" || csVal == L"2" ) )
#else
		if(pLVCD->iSubItem == iImageColumn && bPaintImage == true)// (csVal == L"0" || csVal == L"1" || csVal == L"2" ) )
#endif
		{
			CDC* pDC = CDC::FromHandle(pLVCD->nmcd.hdc);
			DrawImage(static_cast<int> (pLVCD->nmcd.dwItemSpec), pLVCD->iSubItem, pDC);
			*pResult = CDRF_SKIPDEFAULT;	// We've painted everything.
		}
		else
		{	// Let windows handle the other columns for painting
			*pResult = CDRF_NOTIFYSUBITEMDRAW;
		}
	}
}

void CMyListCtrl::DrawImage(int item, int subitem, CDC* pDC)
{
	CRect imgRect;
	if(GetImageRect(item, subitem, imgRect, false))
	{
		// save image list background color
		COLORREF rgb = m_ImageList.GetBkColor();

		//Fill background
		//FillSolidRect(pDC, imgRect, RGB(255,255,255));

		GetImageRect(item, subitem, imgRect, true);

		CString sImageID = GetItemText(item, subitem);

		int iImageID = _ttoi(sImageID.GetBuffer(5));

		m_ImageList.DrawIndirect(pDC, 
								iImageID, // the ID of the image you actully want to paint
								imgRect.TopLeft(), 
								imgRect.Size(), 
								CPoint(0, 0));
		m_ImageList.SetBkColor(rgb);
	}
	return;
}

bool CMyListCtrl::GetImageRect(int item, int subitem, CRect& rect, bool imageOnly)
{
	GetSubItemRect(item, subitem, LVIR_BOUNDS, rect);
	//Draw image?
	//if (id.m_image.m_imageList)
	{
		int nImage = 0; //id.m_image.m_imageID;

		if (nImage < 0)
			return false;

		SIZE sizeImage;
		sizeImage.cx = sizeImage.cy = 0;
		IMAGEINFO info;

		if (rect.Width() > 0 && m_ImageList.GetImageInfo(nImage, &info))
		{
			//if imageOnly we only return the rect of the image.
			//otherwise we also include area under and below image.
			sizeImage.cx = info.rcImage.right - info.rcImage.left;
			sizeImage.cy = info.rcImage.bottom - info.rcImage.top;

			//Real size
			SIZE size;
			size.cx = rect.Width() < sizeImage.cx ? rect.Width() : sizeImage.cx;
			size.cy = 1+rect.Height() < sizeImage.cy ? rect.Height() : sizeImage.cy;

			int leftMarging = 1;
			POINT point;
			point.y = rect.CenterPoint().y - (sizeImage.cy/2);
			point.x = rect.left;
			point.x += leftMarging;

			//Out of area?
			if(point.y<rect.top)
				point.y = rect.top;
			//
			if( !imageOnly )
			{
				rect.right = point.x+sizeImage.cx;				
			}
			else
				//Make rect of point and size, and return this
				rect = CRect(point, size);

			return true;
		}
	}
	return false;
}
