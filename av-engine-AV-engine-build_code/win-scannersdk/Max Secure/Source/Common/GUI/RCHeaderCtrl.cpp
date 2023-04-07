/*======================================================================================
   FILE			: NewHeaderCtrl.cpp
   ABSTRACT		: Class to manage the header of the tree view.
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
#include "stdafx.h"
#include "RCHeaderCtrl.h"

#include "Resource.h"
#include "RegistryCleaner.h"


#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif


/*-------------------------------------------------------------------------------------
	Function		: CRCNewHeaderCtrl
	In Parameters	: -
	Out Parameters	: -
	Purpose			: Constructor for class CRCNewHeaderCtrl
	Author			: Zuber
--------------------------------------------------------------------------------------*/
CRCNewHeaderCtrl::CRCNewHeaderCtrl()
			   :m_pImageList( NULL ) , m_RTL( FALSE ) , m_Ascending( TRUE )
{
	m_bIsSort = false;
}//CRCNewHeaderCtrl

/*-------------------------------------------------------------------------------------
	Function		: ~CRCNewHeaderCtrl
	In Parameters	: -
	Out Parameters	: -
	Purpose			: Destructor for class CRCNewHeaderCtrl
	Author			: Zuber
--------------------------------------------------------------------------------------*/
CRCNewHeaderCtrl::~CRCNewHeaderCtrl()
{
}//~CRCNewHeaderCtrl


BEGIN_MESSAGE_MAP(CRCNewHeaderCtrl, CHeaderCtrl)
	//{{AFX_MSG_MAP(CRCNewHeaderCtrl)
	ON_WM_PAINT()
	//}}AFX_MSG_MAP
	ON_WM_LBUTTONDOWN()
	ON_WM_LBUTTONUP()
	ON_NOTIFY(HDN_TRACKA, 0, &CRCNewHeaderCtrl::OnHdnTrack)
	ON_NOTIFY(HDN_TRACKW, 0, &CRCNewHeaderCtrl::OnHdnTrack)
END_MESSAGE_MAP()


/*-------------------------------------------------------------------------------------
	Function		: DrawItem
	In Parameters	: lpDrawItemStruct - Pointer to DRAWITEMSTRUCT structure describing
										 the item to be painted
	Out Parameters	: -
	Purpose			: Called by framework when a visual aspect changes
	Author			: Zuber
--------------------------------------------------------------------------------------*/
void CRCNewHeaderCtrl::DrawItem( LPDRAWITEMSTRUCT lpDrawItemStruct )
{
	
	try
	{
		CDC dc;
		dc.Attach( lpDrawItemStruct->hDC );

		// Save DC
		int nSavedDC = dc.SaveDC();

		// Get the column rect
		CRect rcLabel( lpDrawItemStruct->rcItem );
		dc.DrawEdge(&rcLabel,EDGE_RAISED,BF_RECT);
		// Set clipping region to limit drawing within column
		CRgn rgn;
		rgn.CreateRectRgnIndirect( &rcLabel );
		dc.SelectObject( &rgn );
		rgn.DeleteObject();

		// Labels are offset by a certain amount  
		// This offset is related to the width of a space character
		int offset = dc.GetTextExtent(_T(" "), 1 ).cx*2;


		// Draw image from image list

		// Get the column text and format
		TCHAR buf[256];
		HD_ITEM hditem;
		
		hditem.mask = HDI_TEXT | HDI_FORMAT;
		hditem.pszText = buf;
		hditem.cchTextMax = 255;

		GetItem( lpDrawItemStruct->itemID, &hditem );

		// Determine format for drawing column label
		UINT uFormat = DT_SINGLELINE | DT_NOPREFIX | DT_NOCLIP | DT_VCENTER | DT_END_ELLIPSIS ;

		if( hditem.fmt & HDF_CENTER)
		{
			uFormat |= DT_CENTER;
		}
		else
		if( hditem.fmt & HDF_RIGHT)
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
			if( lpDrawItemStruct->itemState == ODS_SELECTED )
			{
				rcLabel.left++;
				rcLabel.top += 2;
				rcLabel.right++;
			}

			rcLabel.left += offset;
			rcLabel.right -= offset;

			// Draw column label
			if( rcLabel.left < rcLabel.right )
			{
				dc.DrawText(buf,-1,rcLabel, uFormat);
			}
		}

		int imageIndex;
		if (m_pImageList && 
			m_mapImageIndex.Lookup( lpDrawItemStruct->itemID, imageIndex ) )
		{
			if( imageIndex != -1 )
			{
				if(uFormat & DT_RIGHT)
				{
					// draw to the left of the label
					m_pImageList->Draw(&dc, imageIndex, CPoint( rcLabel.left + offset,offset/3 ), ILD_TRANSPARENT );
				}
				else
				{
					// draw to the right
					m_pImageList->Draw(&dc, imageIndex, CPoint( rcLabel.right - dc.GetTextExtent(buf, 1 ).cx*2,offset/3 ),
									   ILD_TRANSPARENT );
				}

				// Now adjust the label rectangle
				IMAGEINFO imageinfo;
				if( m_pImageList->GetImageInfo( imageIndex, &imageinfo ) )
				{
					rcLabel.left += offset/2 + imageinfo.rcImage.right - imageinfo.rcImage.left;
				}
			}
		}

		if(uFormat & DT_RIGHT)
		{
			// Adjust the rect if the mouse button is pressed on it
			if( lpDrawItemStruct->itemState == ODS_SELECTED )
			{
				rcLabel.left++;
				rcLabel.top += 2;
				rcLabel.right++;
			}

			rcLabel.left += offset;
			rcLabel.right -= offset;

			// Draw column label
			if( rcLabel.left < rcLabel.right )
			{
				dc.DrawText(buf,-1,rcLabel, uFormat);
				
			}
		}

		// Restore dc
		dc.RestoreDC( nSavedDC );

		// Detach the dc before returning
		dc.Detach();
		CWnd * pWnd = GetParent()->GetParent();
		CString csWndName;
		pWnd->GetWindowText(csWndName);  //GetWindowTextA
		
		if(csWndName.CompareNoCase(_T("RecoverIgnoreList")) == 0 )
		{
			//CRecoverIgnoreList
			CRegistryCleaner * parent = (CRegistryCleaner *)GetParent( ) ->GetParent( );
			int nItemCount = GetItemCount( );

			int m_nPrevColumnsWidth = parent ->m_treeList ->m_treeCtrl .GetColumnsWidth( );
			int nTotalWidthOfColumns = 0;
			HD_ITEM hi;

			// Get total width of all columns
			for( int nItem = 0 ; nItem < nItemCount ; nItem++ )
			{
				hi .mask = HDI_WIDTH;
				GetItem( nItem , &hi );

				nTotalWidthOfColumns += hi .cxy;
			}

			if( nTotalWidthOfColumns != m_nPrevColumnsWidth )
			{
				parent ->m_treeList ->m_treeCtrl.GetColumnsWidth( );
				parent ->m_treeList ->m_treeCtrl .RecalcColumnsWidth( );
				parent ->m_treeList ->ResetScrollBar( );
				parent ->m_treeList ->m_treeCtrl .Invalidate( );
			}
		}
		else if(csWndName.CompareNoCase(_T("Recover")) == 0 )
		{
			//CRecover
			CRegistryCleaner * parent = (CRegistryCleaner *)GetParent( ) ->GetParent( );
			int nItemCount = GetItemCount( );

			int m_nPrevColumnsWidth = parent ->m_treeList ->m_treeCtrl .GetColumnsWidth( );
			int nTotalWidthOfColumns = 0;
			HD_ITEM hi;

			// Get total width of all columns
			for( int nItem = 0 ; nItem < nItemCount ; nItem++ )
			{
				hi .mask = HDI_WIDTH;
				GetItem( nItem , &hi );

				nTotalWidthOfColumns += hi .cxy;
			}

			if( nTotalWidthOfColumns != m_nPrevColumnsWidth )
			{
				parent ->m_treeList ->m_treeCtrl.GetColumnsWidth( );
				parent ->m_treeList ->m_treeCtrl .RecalcColumnsWidth( );
				parent ->m_treeList ->ResetScrollBar( );
				parent ->m_treeList ->m_treeCtrl .Invalidate( );
			}
		}
		else if(csWndName.CompareNoCase(_T("RecoverBKPopUp")) == 0 )
		{
			//RecoverBKPopUp
			CRegistryCleaner * parent = (CRegistryCleaner *)GetParent( ) ->GetParent( );
			int nItemCount = GetItemCount( );

			int m_nPrevColumnsWidth = parent ->m_treeList ->m_treeCtrl .GetColumnsWidth( );
			int nTotalWidthOfColumns = 0;
			HD_ITEM hi;

			// Get total width of all columns
			for( int nItem = 0 ; nItem < nItemCount ; nItem++ )
			{
				hi .mask = HDI_WIDTH;
				GetItem( nItem , &hi );

				nTotalWidthOfColumns += hi .cxy;
			}

			if( nTotalWidthOfColumns != m_nPrevColumnsWidth )
			{
				parent ->m_treeList ->m_treeCtrl.GetColumnsWidth( );
				parent ->m_treeList ->m_treeCtrl .RecalcColumnsWidth( );
				parent ->m_treeList ->ResetScrollBar( );
				parent ->m_treeList ->m_treeCtrl .Invalidate( );
			}
		}
		else
		{
			return;
		}
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in  CRCNewHeaderCtrl::DrawItem"));
	}
}//DrawItem

/*-------------------------------------------------------------------------------------
	Function		: SetImageList
	In Parameters	: pImageList - Image list for the header control
	Out Parameters	: Previous image list associated with the header control
	Purpose			: Associates a image list with the header control
	Author			: Zuber
--------------------------------------------------------------------------------------*/
CImageList* CRCNewHeaderCtrl::SetImageList( CImageList* pImageList )
{
	try
	{
		CImageList *pPrevList = m_pImageList;
		m_pImageList = pImageList;
		return pPrevList;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CRCNewHeaderCtrl::SetImageList"));
	}
	return NULL;
}//SetImageList

/*-------------------------------------------------------------------------------------
	Function		: GetItemImage
	In Parameters	: nItem
	Out Parameters	: Image index associated with the item
	Purpose			: Retrieves the image associated with the item
	Author			: Zuber
--------------------------------------------------------------------------------------*/
int CRCNewHeaderCtrl::GetItemImage( int nItem )
{
	try
	{
		int imageIndex;
		if( m_mapImageIndex.Lookup( nItem, imageIndex ) )
		{
			return imageIndex;
		}
		return -1;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in  CRCNewHeaderCtrl::GetItemImage"));
	}
	return -1;
}//GetItemImage

/*-------------------------------------------------------------------------------------
	Function		: SetItemImage
	In Parameters	: nItem - Item whose image is to be changed
					: nImage- Index of the image which is to be associated with the item
	Out Parameters	: -
	Purpose			: Associates an image with an item
	Author			: Zuber
--------------------------------------------------------------------------------------*/
void CRCNewHeaderCtrl::SetItemImage( int nItem, int nImage )
{
	try
	{
		// Save the image index
		m_mapImageIndex[nItem] = nImage;

		// Change the item to ownder drawn
		HD_ITEM hditem;

		hditem.mask = HDI_FORMAT;
		GetItem( nItem, &hditem );
		hditem.fmt |= HDF_OWNERDRAW;
		SetItem( nItem, &hditem );

		// Invalidate header control so that it gets redrawn
		Invalidate();
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CRCNewHeaderCtrl::SetItemImage"));
	}
}//SetItemImage

/*-------------------------------------------------------------------------------------
	Function		: Autofit
	In Parameters	: nOverrideItemData - Item which is to be auto fitted
					: nOverrideWidth	- Item width
	Out Parameters	: -
	Purpose			: Autofit the header in the tree view
	Author			: Zuber
--------------------------------------------------------------------------------------*/
void CRCNewHeaderCtrl::Autofit(int nOverrideItemData /*= -1*/, int nOverrideWidth /*= 0*/)
{
	try
	{
		int nItemCount = GetItemCount();
		int nTotalWidthOfColumns = 0;
		int nDifferenceInWidht;
		int nItem;
		HD_ITEM hi;
		CRect rClient;

		if (!m_bAutofit)
		{
			return;
		}

		SetRedraw(FALSE);

		GetParent()->GetClientRect(&rClient);
		if (-1 != nOverrideItemData)
		{
			rClient.right -= nOverrideWidth;
		}

		// Get total width of all columns
		for (nItem = 0; nItem < nItemCount; nItem++)
		{
			if (nItem == nOverrideItemData)	// Don't mess with the item being resized by the user
			{
				continue;
			}

			hi.mask = HDI_WIDTH;
			GetItem(nItem, &hi);

			nTotalWidthOfColumns += hi.cxy;
		}

		if (nTotalWidthOfColumns != rClient.Width())
		{
			nDifferenceInWidht = abs(nTotalWidthOfColumns-rClient.Width());	// We need to shrink/expand all columns!
			
			// Shrink/expand all columns proportionally based on their current size
			for (nItem = 0; nItem < nItemCount; nItem++)
			{
				if (nItem == nOverrideItemData)	// Skip the overrride column if there is one!
				{
					continue;
				}
				
				hi.mask = HDI_WIDTH;
				GetItem(nItem, &hi);

				hi.mask = HDI_WIDTH;
				hi.cxy = (hi.cxy * rClient.Width()) / nTotalWidthOfColumns;

				SetItem(nItem, &hi);
			}
		}

		SetRedraw(TRUE);
		Invalidate();
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CRCNewHeaderCtrl::Autofit"));
	}
}//Autofit

/*-------------------------------------------------------------------------------------
	Function		: OnPaint
	In Parameters	: -
	Out Parameters	: -
	Purpose			: Paints the items
	Author			: Zuber
--------------------------------------------------------------------------------------*/
void CRCNewHeaderCtrl::OnPaint() 
{
	try
	{
		CPaintDC dc(this); // device context for painting

		CWnd::DefWindowProc( WM_PAINT, (WPARAM)dc.m_hDC, 0 );
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CRCNewHeaderCtrl::OnPaint"));
	}
}//OnPaint

/*-------------------------------------------------------------------------------------
	Function		: OnLButtonDown
	In Parameters	: UINT :Indicates whether various virtual keys are down
					: CPoint :Specifies the x- and y-coordinate of the cursor
	Out Parameters	: 
	Purpose			: The framework calls this member function when the user presses the 
						left mouse button.
	Author			: Zuber
--------------------------------------------------------------------------------------*/
void CRCNewHeaderCtrl::OnLButtonDown(UINT nFlags, CPoint point)
{
	try
	{
		HD_ITEM hi;

		hi .mask = HDI_WIDTH | HDI_ORDER;
		GetItem( 0 , &hi );
		
		if( point .x < hi .cxy )
		{
			CWnd * pWnd = GetParent()->GetParent();
			CString csWndName;
			pWnd->GetWindowText(csWndName);  //GetWindowTextA
			
		
				if(csWndName.CompareNoCase(_T("RecoverIgnoreList")) == 0 )
			{
				//CRecoverIgnoreList
				CRegistryCleaner * parent = (CRegistryCleaner *)GetParent( ) ->GetParent( );
				int iCountItems = GetItemCount();
				if( iCountItems > 1 )
				{ 
					parent->m_treeList->m_treeCtrl.SortItems( 0 , ! m_Ascending );
					m_Ascending = ! m_Ascending;
				}
			}
			else if(csWndName.CompareNoCase(_T("Recover")) == 0 )
			{
				//CRecover
				CRegistryCleaner * parent = (CRegistryCleaner *)GetParent( ) ->GetParent( );
				int iCountItems = GetItemCount();
				if( iCountItems > 1 )
				{ 
					parent->m_treeList->m_treeCtrl.SortItems( 0 , ! m_Ascending );
					m_Ascending = ! m_Ascending;
				}
			}
			else
			{
				return;
			}
		}

		CHeaderCtrl::OnLButtonDown(nFlags, point);
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CRCNewHeaderCtrl::OnPaint"));
	}
}

/*-------------------------------------------------------------------------------------
	Function		: OnNotify
	In Parameters	: WPARAM :Identifies the control that sends the message if 
								the message is from a control
					: LPARAM :Pointer to a notification message (NMHDR) structure 
							  that contains the notification code and additional information
					: LRESULT * :Pointer to an LRESULT variable in which to store the 
									result code if the message is handled
	Out Parameters	: BOOL :An application returns nonzero if it processes this message;
							otherwise 0.
	Purpose			: The framework calls this member function to inform the 
					  parent window of a control that an event has occurred in 
					  the control or that the control requires some kind of information.
	Author			: Zuber
--------------------------------------------------------------------------------------*/
BOOL CRCNewHeaderCtrl::OnNotify(WPARAM wParam, LPARAM lParam, LRESULT* pResult)
{
	try
	{
		return CHeaderCtrl::OnNotify(wParam, lParam, pResult);
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CRCNewHeaderCtrl::OnNotify"));
	}
	return FALSE;
}

/*-------------------------------------------------------------------------------------
	Function		: OnHdnTrack
	In Parameters	: -
	Out Parameters	: -
	Purpose			: 
	Author			: 
--------------------------------------------------------------------------------------*/
void CRCNewHeaderCtrl::OnHdnTrack(NMHDR *pNMHDR, LRESULT *pResult)
{
	try
	{
		LPNMHEADER phdr = reinterpret_cast<LPNMHEADER>(pNMHDR);
		if(phdr->iButton == 0)
		{
			phdr->pitem->mask = HDI_WIDTH;
			if(phdr->pitem->cxy < MIN_COLUMN_WIDTH) 
				phdr->pitem->cxy = MIN_COLUMN_WIDTH;  
		}
		*pResult = 0;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught inCRCNewHeaderCtrl::OnHdnTrack"));
	}
}
