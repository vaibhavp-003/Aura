#ifndef CSORTCLASS_H
#define CSORTCLASS_H

///////////////////////////////////////////////////////////////////////////////
//
// $Header:  $
//
// NAME:			CSortClass
//
// BASE  CLASSES:	none
//
// PURPOSE:			Sorting of list control column
//
// REVISION HISTORY:
// $Log:      $
///////////////////////////////////////////////////////////////////////////////

// Includes

#pragma once

class CSortClass
{
public:
	enum EDataType{ dtNULL, dtINT, dtSTRING, dtDATETIME, dtDEC };
	CSortClass( CListCtrl * _pWnd, const int _iCol );
	virtual			~CSortClass();
	void			Sort( bool bAsc, EDataType _dtype );

private:
	void			ListViewSetArrow( CListCtrl * pList, int nColumn, BOOL bReverse );
	int				Compare(CString csText1, CString csText2, long lParamSort );

	void			ReplaceEntries(int Index1, int Index2);

	CListCtrl*		pWnd;
	int				iSortCol;
};

#endif // CSORTCLASS_H