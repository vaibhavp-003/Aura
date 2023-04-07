/*======================================================================================
   FILE				: NewHeaderCtrl.cpp
   ABSTRACT			: Class to manage the header of the tree view.
   DOCUMENTS		: 
   AUTHOR			:  Zuber
   COMPANY			: Aura 
   COPYRIGHT NOTICE :
						(C)Aura
						Created as an unpublished copyright work.  All rights reserved.
						This document and the information it contains is confidential and
						proprietary to Aura.  Hence, it may not be 
						used, copied, reproduced, transmitted, or stored in any form or by any 
						means, electronic, recording, photocopying, mechanical or otherwise, 
						without the prior written permission of Aura
   CREATION DATE	: 2/20/07
   NOTE				:class inplementing header control
   VERSION HISTORY  :  5/01/2008 : Avinash Bhardwaj : Ported to VS2005 with Unicode and X64 bit Compatability,string resources taken from ini.
=======================================================================================*/
#include "stdafx.h"
#include "NewTreeListCtrl.h"
#include "SpyDetectTreeCtrl.h"
#include "NewHeaderCtrl.h"
#include "SDSystemInfo.h"

#ifdef FIREWALL
#include "RecoverMail.h"
#elif DATABACKUP
#include "OptionTabFunctions.h"
//..//#include "OptionTab.h"
//..//#include "RecoverRemovedSpywares.h"
#else
#include "OptionTabFunctions.h"
#include "SDOptionsPaint.h"
#include "ScanProgressDlg.h"
#include "ExcludeDlg.h"
#include "OptionTab.h"
#include "RecoverRemovedSpywares.h"
#endif


#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*-------------------------------------------------------------------------------------
Function		: CNewHeaderCtrl
In Parameters	: -
Out Parameters	: -
Purpose			: Constructor for class CNewHeaderCtrl
Author			: Zuber
--------------------------------------------------------------------------------------*/
CNewHeaderCtrl::CNewHeaderCtrl()
:m_pImageList(NULL), m_RTL(FALSE), m_Ascending(TRUE)
{
	m_bIsSort = false;
}//CNewHeaderCtrl

/*-------------------------------------------------------------------------------------
Function		: ~CNewHeaderCtrl
In Parameters	: -
Out Parameters	: -
Purpose			: Destructor for class CNewHeaderCtrl
Author			: Zuber
--------------------------------------------------------------------------------------*/
CNewHeaderCtrl::~CNewHeaderCtrl()
{
}//~CNewHeaderCtrl


BEGIN_MESSAGE_MAP(CNewHeaderCtrl, CHeaderCtrl)
	//{{AFX_MSG_MAP(CNewHeaderCtrl)
	ON_WM_PAINT()
	//}}AFX_MSG_MAP
	ON_WM_LBUTTONDOWN()
	ON_WM_LBUTTONUP()
END_MESSAGE_MAP()

/*-------------------------------------------------------------------------------------
Function		: DrawItem
In Parameters	: lpDrawItemStruct - Pointer to DRAWITEMSTRUCT structure describing
the item to be painted
Out Parameters	: -
Purpose			: Called by framework when a visual aspect changes
Author			: Zuber
--------------------------------------------------------------------------------------*/
void CNewHeaderCtrl::DrawItem(LPDRAWITEMSTRUCT lpDrawItemStruct)
{
	CDC dc;
	int nPrevColumnsWidth = 0;
	dc.Attach(lpDrawItemStruct->hDC);

	// Save DC
	int nSavedDC = dc.SaveDC();

	// Get the column rect
	CRect rcLabel(lpDrawItemStruct->rcItem);
	dc.DrawEdge(&rcLabel,EDGE_RAISED,BF_RECT);
	// Set clipping region to limit drawing within column
	CRgn rgn;
	rgn.CreateRectRgnIndirect(&rcLabel);
	dc.SelectObject(&rgn);
	rgn.DeleteObject();

	// Labels are offset by a certain amount
	// This offset is related to the width of a space character
	int offset = dc.GetTextExtent(_T(" "), 1).cx*2;


	// Draw image from image list

	// Get the column text and format
	TCHAR buf[256];
	HD_ITEM hditem;

	hditem.mask = HDI_TEXT | HDI_FORMAT;
	hditem.pszText = buf;
	hditem.cchTextMax = 255;

	GetItem(lpDrawItemStruct->itemID, &hditem);

	// Determine format for drawing column label
	UINT uFormat = DT_SINGLELINE | DT_NOPREFIX | DT_NOCLIP | DT_VCENTER | DT_END_ELLIPSIS;

	if(hditem.fmt & HDF_CENTER)
	{
		uFormat |= DT_CENTER;
	}
	else
		if(hditem.fmt & HDF_RIGHT)
		{
			uFormat |= DT_RIGHT;
		}
		else
		{
			uFormat |= DT_LEFT;
		}

		if(!(uFormat & DT_RIGHT))
		{
			// Adjust the rect if the mouse button is pressed on it
			if(lpDrawItemStruct->itemState == ODS_SELECTED)
			{
				rcLabel.left++;
				rcLabel.top += 2;
				rcLabel.right++;
			}

			rcLabel.left += offset;
			rcLabel.right -= offset;

			// Draw column label
			if(rcLabel.left < rcLabel.right)
			{
				dc.DrawText(buf,-1,rcLabel, uFormat);
			}
		}

		int imageIndex;
		if(m_pImageList &&
			m_mapImageIndex.Lookup(lpDrawItemStruct->itemID, imageIndex))
		{
			if(imageIndex != -1)
			{
				if(uFormat & DT_RIGHT)
				{
					// draw to the left of the label
					m_pImageList->Draw(&dc, imageIndex, CPoint(rcLabel.left + offset,offset/3), ILD_TRANSPARENT);
				}
				else
				{
					// draw to the right
					m_pImageList->Draw(&dc, imageIndex, CPoint(rcLabel.right - dc.GetTextExtent(buf, 1).cx*2,offset/3),
						ILD_TRANSPARENT);
				}

				// Now adjust the label rectangle
				IMAGEINFO imageinfo;
				if(m_pImageList->GetImageInfo(imageIndex, &imageinfo))
				{
					rcLabel.left += offset/2 + imageinfo.rcImage.right - imageinfo.rcImage.left;
				}
			}
		}

		if(uFormat & DT_RIGHT)
		{
			// Adjust the rect if the mouse button is pressed on it
			if(lpDrawItemStruct->itemState == ODS_SELECTED)
			{
				rcLabel.left++;
				rcLabel.top += 2;
				rcLabel.right++;
			}

			rcLabel.left += offset;
			rcLabel.right -= offset;

			// Draw column label
			if(rcLabel.left < rcLabel.right)
			{
				dc.DrawText(buf,-1,rcLabel, uFormat);

			}
		}

		// Restore dc
		dc.RestoreDC(nSavedDC);

		// Detach the dc before returning
		dc.Detach();

		//taking the name of the window.
		CWnd * pWnd = GetParent() ->GetParent();
		CString csWndName;
		pWnd->GetWindowText(csWndName);

#ifndef FIREWALL
#ifndef DATABACKUP
		//since every window has its unique class so we need to check the window's title and get the parent accordingly : Avinash Bhardwaj
		if(csWndName.CompareNoCase(_T("Exclude")) == 0)
		{
			CExcludeDlg *parent = (CExcludeDlg*)GetParent() ->GetParent();
			int nItemCount = GetItemCount();
			nPrevColumnsWidth = parent ->m_lstWormsList.m_treeCtrl.GetColumnsWidth();
			int nTotalWidthOfColumns = 0;
			HD_ITEM hi;

			// Get total width of all columns
			for(int nItem = 0; nItem < nItemCount; nItem++)
			{
				hi.mask = HDI_WIDTH;
				GetItem(nItem, &hi);

				nTotalWidthOfColumns += hi.cxy;
			}

			if(nTotalWidthOfColumns != nPrevColumnsWidth)
			{
				nPrevColumnsWidth = parent ->m_lstWormsList.m_treeCtrl.GetColumnsWidth();
				parent ->m_lstWormsList.m_treeCtrl.RecalcColumnsWidth();
				parent ->m_lstWormsList.ResetScrollBar();
				parent ->m_lstWormsList.m_treeCtrl.Invalidate();
			}
		}
		else if(csWndName.CompareNoCase(_T("Recover")) == 0)
		{
			CRecoverRemovedSpywares *parent = (CRecoverRemovedSpywares *)GetParent() ->GetParent();
			int nItemCount = GetItemCount();
			nPrevColumnsWidth = parent ->m_treeList ->m_treeCtrl.GetColumnsWidth();
			int nTotalWidthOfColumns = 0;
			HD_ITEM hi;

			// Get total width of all columns
			for(int nItem = 0; nItem < nItemCount; nItem++)
			{
				hi.mask = HDI_WIDTH;
				GetItem(nItem, &hi);

				nTotalWidthOfColumns += hi.cxy;
			}

			if(nTotalWidthOfColumns != nPrevColumnsWidth)
			{
				nPrevColumnsWidth = parent ->m_treeList ->m_treeCtrl.GetColumnsWidth();
				parent ->m_treeList ->m_treeCtrl.RecalcColumnsWidth();
				parent ->m_treeList ->ResetScrollBar();
				parent ->m_treeList ->m_treeCtrl.Invalidate();
			}
		}
#endif
#endif



#ifndef DATABACKUP 
#ifdef FIREWALL
		if(csWndName.CompareNoCase(CSystemInfo::m_csProductName) == 0)
		{
			CRecoverMail *parent = (CRecoverMail *)GetParent() ->GetParent();

#else 
		if(csWndName.CompareNoCase(CSystemInfo::m_csProductName) == 0)
		{
			CScanProgressDlg *parent = (CScanProgressDlg *)GetParent() ->GetParent();

#endif
			int nItemCount = GetItemCount();
			nPrevColumnsWidth = parent ->GetTreeList()->m_treeCtrl.GetColumnsWidth();
			int nTotalWidthOfColumns = 0;
			HD_ITEM hi;

			// Get total width of all columns
			for(int nItem = 0; nItem < nItemCount; nItem++)
			{
				hi.mask = HDI_WIDTH;
				GetItem(nItem, &hi);

				nTotalWidthOfColumns += hi.cxy;
			}

			if(nTotalWidthOfColumns != nPrevColumnsWidth)
			{
				nPrevColumnsWidth = parent ->m_treeList ->m_treeCtrl.GetColumnsWidth();
				parent ->GetTreeList() ->m_treeCtrl.RecalcColumnsWidth();
				parent ->GetTreeList() ->ResetScrollBar();
				parent ->GetTreeList() ->m_treeCtrl.Invalidate();
			}
		}
 #endif
}


/*-------------------------------------------------------------------------------------
Function		: SetImageList
In Parameters	: pImageList - Image list for the header control
Out Parameters	: Previous image list associated with the header control
Purpose			: Associates a image list with the header control
Author			: Zuber
--------------------------------------------------------------------------------------*/
CImageList* CNewHeaderCtrl::SetImageList(CImageList* pImageList)
{
	CImageList *pPrevList = m_pImageList;
	m_pImageList = pImageList;
	return pPrevList;
}

/*-------------------------------------------------------------------------------------
Function		: GetItemImage
In Parameters	: nItem
Out Parameters	: Image index associated with the item
Purpose			: Retrieves the image associated with the item
Author			: Zuber
--------------------------------------------------------------------------------------*/
int CNewHeaderCtrl::GetItemImage(int nItem)
{
	int imageIndex;
	if(m_mapImageIndex.Lookup(nItem, imageIndex))
	{
		return imageIndex;
	}
	return -1;
}

/*-------------------------------------------------------------------------------------
Function		: SetItemImage
In Parameters	: nItem - Item whose image is to be changed
: nImage- Index of the image which is to be associated with the item
Out Parameters	: -
Purpose			: Associates an image with an item
Author			: Zuber
--------------------------------------------------------------------------------------*/
void CNewHeaderCtrl::SetItemImage(int nItem, int nImage)
{
	// Save the image index
	m_mapImageIndex[nItem] = nImage;

	// Change the item to ownder drawn
	HD_ITEM hditem;

	hditem.mask = HDI_FORMAT;
	GetItem(nItem, &hditem);
	hditem.fmt |= HDF_OWNERDRAW;
	SetItem(nItem, &hditem);

	// Invalidate header control so that it gets redrawn
	Invalidate();
}

/*-------------------------------------------------------------------------------------
Function		: Autofit
In Parameters	: nOverrideItemData - Item which is to be auto fitted
: nOverrideWidth	- Item width
Out Parameters	: -
Purpose			: Autofit the header in the tree view
Author			: Zuber
--------------------------------------------------------------------------------------*/
void CNewHeaderCtrl::Autofit(int nOverrideItemData /*= -1*/, int nOverrideWidth /*= 0*/)
{
	int nItemCount = GetItemCount();
	int nTotalWidthOfColumns = 0;
	int nDifferenceInWidht;
	int nItem;
	HD_ITEM hi;
	CRect rClient;

	if(!m_bAutofit)
	{
		return;
	}

	SetRedraw(FALSE);

	GetParent() ->GetClientRect(&rClient);
	if(-1 != nOverrideItemData)
	{
		rClient.right -= nOverrideWidth;
	}

	// Get total width of all columns
	for (nItem = 0; nItem < nItemCount; nItem++)
	{
		if(nItem == nOverrideItemData)	// Don't mess with the item being resized by the user
		{
			continue;
		}

		hi.mask = HDI_WIDTH;
		GetItem(nItem, &hi);

		nTotalWidthOfColumns += hi.cxy;
	}

	if(nTotalWidthOfColumns != rClient.Width())
	{
		nDifferenceInWidht = abs(nTotalWidthOfColumns-rClient.Width());	// We need to shrink/expand all columns!

		// Shrink/expand all columns proportionally based on their current size
		for (nItem = 0; nItem < nItemCount; nItem++)
		{
			if(nItem == nOverrideItemData)	// Skip the overrride column if there is one!
			{
				continue;
			}

			hi.mask = HDI_WIDTH;
			GetItem(nItem, &hi);

			hi.mask = HDI_WIDTH;
			hi.cxy = (hi.cxy * rClient.Width())/ nTotalWidthOfColumns;

			SetItem(nItem, &hi);
		}
	}

	SetRedraw(TRUE);
	Invalidate();
}

/*-------------------------------------------------------------------------------------
Function		: OnPaint
In Parameters	: -
Out Parameters	: -
Purpose			: Paints the items
Author			: Zuber
--------------------------------------------------------------------------------------*/
void CNewHeaderCtrl::OnPaint()
{
	CPaintDC dc(this); // device context for painting

	CWnd::DefWindowProc(WM_PAINT, (WPARAM)dc.m_hDC, 0);
}

/*-------------------------------------------------------------------------------------
Function		: OnLButtonDown
In Parameters	: UINT nFlags - flag
, CPoint point - point of click.
Out Parameters	: -
Purpose			: Paints the items
Author			: Zuber
--------------------------------------------------------------------------------------*/
void CNewHeaderCtrl::OnLButtonDown(UINT nFlags, CPoint point)
{
	HD_ITEM hi;

	hi.mask = HDI_WIDTH;
	GetItem(0, &hi);

	if(point.x < hi.cxy)
	{
		CNewTreeListCtrl * parent =(CNewTreeListCtrl *)GetParent();
		if(parent)
			parent ->SortItems(0, !m_Ascending);
		m_Ascending = !m_Ascending;
	}

	CHeaderCtrl::OnLButtonDown(nFlags, point);
}
