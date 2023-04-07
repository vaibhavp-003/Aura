/*=============================================================================
   FILE			: NewHeaderCtrl.h
   ABSTRACT		: 
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
CREATION DATE   : 
   NOTES		:
VERSION HISTORY	:
				
============================================================================*/
#if !defined(AFX_NEWHEADERCTRL_H__99EB0481_4FA1_11D1_980A_004095E0DEFA__INCLUDED_)
#define AFX_NEWHEADERCTRL_H__99EB0481_4FA1_11D1_980A_004095E0DEFA__INCLUDED_

#if _MSC_VER >= 1000
#pragma once
#endif // _MSC_VER >= 1000
// NewHeaderCtrl.h : header file
//

#include <afxtempl.h>

/////////////////////////////////////////////////////////////////////////////
// CRCNewHeaderCtrl window

class CRCNewHeaderCtrl : public CHeaderCtrl
{
// Construction
public:
	CRCNewHeaderCtrl();

// Attributes
protected:
	CImageList *m_pImageList;
	CMap< int, int, int, int> m_mapImageIndex;

private:
	bool m_bIsSort;
	BOOL m_bAutofit;
	BOOL m_Ascending;
	void Autofit(int nOverrideItemData = -1, int nOverrideWidth = 0);

// Operations
public:
	BOOL m_RTL;

	virtual void DrawItem( LPDRAWITEMSTRUCT lpDrawItemStruct );
	CImageList* SetImageList( CImageList* pImageList );
	int GetItemImage( int nItem );
	void SetItemImage( int nItem, int nImage );
	void SetAutofit(bool bAutofit = true) { m_bAutofit = bAutofit; Autofit(); }

// Overrides
	// ClassWizard generated virtual function overrides
	//{{AFX_VIRTUAL(CRCNewHeaderCtrl)
	//}}AFX_VIRTUAL

// Implementation
public:
	virtual ~CRCNewHeaderCtrl();

	// Generated message map functions
protected:
	//{{AFX_MSG(CRCNewHeaderCtrl)
	afx_msg void OnPaint();
	//}}AFX_MSG

	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnLButtonDown(UINT nFlags, CPoint point);
protected:
	virtual BOOL OnNotify(WPARAM wParam, LPARAM lParam, LRESULT* pResult);
public:
	afx_msg void OnHdnTrack(NMHDR *pNMHDR, LRESULT *pResult);
};

/////////////////////////////////////////////////////////////////////////////

//{{AFX_INSERT_LOCATION}}
// Microsoft Developer Studio will insert additional declarations immediately before the previous line.

#endif // !defined(AFX_NEWHEADERCTRL_H__99EB0481_4FA1_11D1_980A_004095E0DEFA__INCLUDED_)
