///////////////////////////////////////////////////////////////////////////////
// 
// CSortClass Class Implementation
//
// ABSTRACT		:  Sorting of list control column
//
///////////////////////////////////////////////////////////////////////////////

// Includes

#include "StdAfx.h"
#include "sortclass.h"

CSortClass::CSortClass( CListCtrl * _pWnd, const int _iCol )
{
	pWnd = _pWnd;
	iSortCol = _iCol;

	ASSERT(pWnd);
}

CSortClass::~CSortClass()
{
}

void CSortClass::Sort( bool _bAsc, EDataType _dtype )
{
	long	lParamSort = _dtype;
	// if lParamSort positive - ascending sort order, negative - descending
	if( !_bAsc )
		lParamSort *= -1; 
	
	pWnd->SetRedraw(FALSE);
	int iLast = pWnd->GetItemCount();
	for(int iIndex = 0; iIndex < iLast; iIndex++)
	{
		// skip the last record check
		if(iIndex+1 == iLast)
			continue;

		//Check the header first
		CString csText1 = pWnd->GetItemText(iIndex, 0);
		CString csText2 = pWnd->GetItemText(iIndex + 1, 0);

		// Skip this record as one of them contains the header entry
		// so we dont need any swapping here!
		//if(csText1.GetLength() != 0 || csText2.GetLength() != 0)
		//	continue;

		//okay now check the text contents!
		csText1 = pWnd->GetItemText(iIndex, iSortCol);
		csText2 = pWnd->GetItemText(iIndex + 1, iSortCol);

		int iRetVal = 0;
		if(_bAsc)
			iRetVal = Compare(csText1, csText2, lParamSort);
		else
			iRetVal = Compare(csText2, csText1, lParamSort);

		if(iRetVal > 0)
		{
			if(_bAsc)
			{
				ReplaceEntries(iIndex, iIndex+1);
				iIndex = -1; //start from stratch
			}
		}
		else if(iRetVal < 0)
		{
			if(!_bAsc)
			{
				ReplaceEntries(iIndex, iIndex+1);
				iIndex = -1; //start from stratch
			}
		}
	}
	pWnd->SetRedraw(TRUE);
	//ListViewSetArrow(pWnd, iSortCol, _bAsc );
}

void CSortClass::ReplaceEntries(int Index1, int Index2)
{
	CStringArray csTempArray;
	for(int iColumnNo=0; iColumnNo < pWnd->GetHeaderCtrl()->GetItemCount(); iColumnNo++)
		csTempArray.Add(pWnd->GetItemText(Index1, iColumnNo));
	for(int iColumnNo=0; iColumnNo < pWnd->GetHeaderCtrl()->GetItemCount(); iColumnNo++)
		pWnd->SetItemText(Index1, iColumnNo, pWnd->GetItemText(Index2, iColumnNo));
	for(int iColumnNo=0; iColumnNo < pWnd->GetHeaderCtrl()->GetItemCount(); iColumnNo++)
		pWnd->SetItemText(Index2, iColumnNo, csTempArray.GetAt(iColumnNo));
	return;
}

int CSortClass::Compare(CString csText1, CString csText2, long lParamSort)
{
	// restore data type and sort order from lParamSort
	// if lParamSort positive - ascending sort order, negative - descending
	short		sOrder = lParamSort < 0 ? -1 : 1; 
	EDataType dType  = ( EDataType ) ( lParamSort * sOrder ); // get rid of sign
	
	// declare typed buffers
	COleDateTime	objOleDateTime1, objOleDateTime2;
	
	switch( dType )
	{
	case  dtINT:
		return (_wtol(csText1) - _wtol(csText2))*sOrder;

	case  dtDEC:
		return (_wtof(csText1) < _wtof(csText2) ? -1 : 1)*sOrder;

	case  dtDATETIME:
		if (objOleDateTime1.ParseDateTime(csText1) && objOleDateTime2.ParseDateTime(csText2))
		{
			if(objOleDateTime1 == objOleDateTime2)
				return 0;
			else
				return (objOleDateTime1 < objOleDateTime2 ? -1 : 1 )*sOrder;
		}
		else
		{
			if(csText1.GetLength() == 0)
				return -1*sOrder;
			else if(csText2.GetLength() == 0)
				return 1*sOrder;
			else
				return 0;
		}

	case  dtSTRING:
		return csText1.CompareNoCase(csText2)*sOrder;
		
	default:
		ASSERT("Error: attempt to sort a column without type.");
		return 0;
	}
}

void CSortClass::ListViewSetArrow(CListCtrl * pList, int nColumn, BOOL bReverse)
{
    ASSERT_VALID( pList ) ;
    //
    // Find header
    //
    CWnd * pChild = pList->GetWindow( GW_CHILD ) ;
    if ( pChild == NULL ) return ;
    ASSERT_VALID( pChild ) ;
 
	WCHAR	szChar[256] = {0} ;
    GetClassName( pChild->m_hWnd, szChar, 256 ) ;
    if ( 0 != _wcsicmp( szChar, L"SysHeader32" ) )
    {
        return ;
    }
    
    // Get width and height of selected item
     HD_ITEM hdi ;
    memset( &hdi, 0, sizeof hdi ) ;
    hdi.mask = HDI_WIDTH ;
    pChild->SendMessage( HDM_GETITEM, nColumn, (LPARAM)&hdi );
 
    int iCoordinates = hdi.cxy ;
    CRect rectClient ;
	::GetClientRect( pChild->m_hWnd, &rectClient ) ;
    int iHeight = rectClient.Height() ;
    ASSERT( iCoordinates > 0 ) ;
    ASSERT( iHeight > 0 ) ;
      
    // Get Text
    WCHAR	szText[256] ;
    memset( &hdi, 0, sizeof hdi ) ;
    hdi.mask = HDI_TEXT ;
    hdi.pszText = szText ;
    hdi.cchTextMax = sizeof szText ;
    pChild->SendMessage( HDM_GETITEM, nColumn, (LPARAM)&hdi );
     
    // Create bitmap
	HDC hdcHeader = ::GetDC( pChild->m_hWnd ) ;
    HBITMAP hbitmap = CreateCompatibleBitmap( hdcHeader, iCoordinates, iHeight ) ;
    HDC hbitmapDC = CreateCompatibleDC( hdcHeader ) ;
    SelectObject( hbitmapDC, hbitmap ) ;
 
    HBRUSH hBrush = GetSysColorBrush( COLOR_BTNFACE ) ;
    HBRUSH hOldBrush = (HBRUSH)SelectObject( hbitmapDC, hBrush ) ;
    HFONT hOldFont = (HFONT)SelectObject( hbitmapDC, GetStockObject(DEFAULT_GUI_FONT) ) ;
 
    CRect rectBack(0,0,iCoordinates,iHeight) ;
    FillRect( hbitmapDC, &rectBack, hBrush ) ;
    if ( iCoordinates > 32 )
    {
        CRect rectText(0,0,iCoordinates-32,iHeight) ;
        SetBkMode( hbitmapDC, TRANSPARENT ) ;
        DrawTextEx( hbitmapDC, szText, -1, rectText, DT_LEFT | DT_TOP | DT_SINGLELINE | DT_NOPREFIX | DT_END_ELLIPSIS, NULL ) ;
    }
 
    HPEN hWhitePen = (HPEN)GetStockObject( WHITE_PEN ) ;
    HPEN hBlackPen = (HPEN)GetStockObject( BLACK_PEN ) ;
    HPEN hOldPen = (HPEN)SelectObject( hbitmapDC, hWhitePen ) ;
    if ( bReverse )
    {
        MoveToEx( hbitmapDC, iCoordinates-24, 4, NULL ) ;
        LineTo( hbitmapDC, iCoordinates-28, 12 ) ;
        SelectObject( hbitmapDC, hBlackPen ) ;
        LineTo( hbitmapDC, iCoordinates-20, 12 ) ;
        LineTo( hbitmapDC, iCoordinates-24, 4 ) ;
    } else
    {
        MoveToEx( hbitmapDC, iCoordinates-20, 4, NULL ) ;
        LineTo( hbitmapDC, iCoordinates-28, 4 ) ;
        LineTo( hbitmapDC, iCoordinates-24, 12 ) ;
        SelectObject( hbitmapDC, hBlackPen ) ;
        LineTo( hbitmapDC, iCoordinates-20, 4 ) ;
    }
    SelectObject( hbitmapDC, hOldPen ) ;
    SelectObject( hbitmapDC, hOldFont ) ;
    SelectObject( hbitmapDC, hOldBrush ) ;
    DeleteDC( hbitmapDC ) ;
	::ReleaseDC( pChild->m_hWnd, hdcHeader ) ;
	//DeleteObject(hbitmap);

    //
    // set header of selected item
    //
    memset( &hdi, 0, sizeof hdi ) ;
    hdi.mask = HDI_BITMAP | HDI_FORMAT ;
    hdi.fmt = HDF_LEFT | HDF_BITMAP ;
    hdi.hbm = hbitmap ;
    pChild->SendMessage( HDM_SETITEM, nColumn, (LPARAM)&hdi ) ;
 
    //
    // reset all others
    //
    int nCount = (int)pChild->SendMessage( HDM_GETITEMCOUNT, 0, 0L);
    if ( nCount > 0 )
    {
        for ( int ii = 0 ; ii < nCount ; ii++ )
        {
            if (nColumn != ii )
            {
                HD_ITEM hdi2 ;
                memset( &hdi2, 0, sizeof hdi2 ) ;
                hdi2.mask = HDI_FORMAT ;
                hdi2.fmt = HDF_LEFT | HDF_STRING ;
                pChild->SendMessage( HDM_SETITEM, ii, (LPARAM)&hdi2 ) ;
            }
        } // for
    } // if
}