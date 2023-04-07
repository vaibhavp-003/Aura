/*=============================================================================
   FILE			 : XHeaderCtrl.h
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
   VERSION HISTORY :
				
============================================================================*/
#pragma once
#include <tchar.h>
#include "MemDC.h"

#define FLATHEADER_TEXT_MAX	80

#define XHEADERCTRL_NO_IMAGE		0
#define XHEADERCTRL_UNCHECKED_IMAGE	1
#define XHEADERCTRL_CHECKED_IMAGE	2


#define FH_PROPERTY_SPACING			1
#define FH_PROPERTY_ARROW			2
#define FH_PROPERTY_STATICBORDER	3
#define FH_PROPERTY_DONTDROPCURSOR	4
#define FH_PROPERTY_DROPTARGET		5


class CXHeaderCtrl : public CHeaderCtrl
{
	DECLARE_DYNCREATE(CXHeaderCtrl)
public:
	CXHeaderCtrl();
	virtual ~CXHeaderCtrl();
	BOOL ModifyProperty(WPARAM wParam, LPARAM lParam);
	int GetSpacing(){ return m_iSpacing; }
	void SetSpacing(int nSpacing){ m_iSpacing = nSpacing; }
	virtual void DrawItem(LPDRAWITEMSTRUCT);
	virtual void DrawItem(CDC* pDC, CRect rect, LPHDITEM lphdi);
protected:
	BOOL m_bDoubleBuffer;
	int m_iSpacing;
	SIZE m_sizeImage;
	SIZE m_sizeArrow;
	BOOL m_bStaticBorder;
	UINT m_nDontDropCursor;
	BOOL m_bResizing;
	UINT m_nClickFlags;
	CPoint m_ptClickPoint;

	COLORREF m_cr3DHighLight;
	COLORREF m_cr3DShadow;
	COLORREF m_cr3DFace;
	COLORREF m_crBtnText;

	void DrawCtrl(CDC* pDC);
	int DrawImage(CDC* pDC, CRect rect, LPHDITEM hdi, BOOL bRight);
	int DrawBitmap(CDC* pDC, CRect rect, LPHDITEM hdi, CBitmap* pBitmap,
		BITMAP* pBitmapInfo, BOOL bRight);
	int DrawText (CDC* pDC, CRect rect, LPHDITEM lphdi);

	afx_msg LRESULT OnDeleteItem(WPARAM wparam, LPARAM lparam);
	afx_msg LRESULT OnInsertItem(WPARAM wparam, LPARAM lparam);
	afx_msg LRESULT OnLayout(WPARAM wparam, LPARAM lparam);
	afx_msg LRESULT OnSetImageList(WPARAM wparam, LPARAM lparam);
	afx_msg BOOL OnEraseBkgnd(CDC* pDC);
	afx_msg void OnPaint();
	afx_msg void OnSysColorChange();

	DECLARE_MESSAGE_MAP()
};
