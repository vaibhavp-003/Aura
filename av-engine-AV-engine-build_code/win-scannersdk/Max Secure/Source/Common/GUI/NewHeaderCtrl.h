/*=============================================================================
   FILE		           : CNewHeaderCtrl.h
   ABSTRACT		       : A "header control" is a window usually positioned above columns of text or numbers. 
	                 It contains a title for each column, and it can be divided into parts. The user can 
					 drag the dividers that separate the parts to set the width of each column. 
   DOCUMENTS	       : Refer The GUI Design.doc, GUI Requirement Document.doc
   AUTHOR		       : 
   COMPANY		       : Aura 
   COPYRIGHT NOTICE    :
						(C)Aura:
      					Created as an unpublished copyright work.  All rights reserved.
     					This document and the information it contains is confidential and
      					proprietary to Aura.  Hence, it may not be 
      					used, copied, reproduced, transmitted, or stored in any form or by any 
      					means, electronic, recording, photocopying, mechanical or otherwise, 
      					without the prior written permission of Aura
   CREATION DATE      : 2/20/07
   NOTES		      : header file for class inplementing header control
   VERSION HISTORY    : 
				
=============================================================================*/
#if !defined(AFX_NEWHEADERCTRL_H__99EB0481_4FA1_11D1_980A_004095E0DEFA__INCLUDED_)
#define AFX_NEWHEADERCTRL_H__99EB0481_4FA1_11D1_980A_004095E0DEFA__INCLUDED_

#if _MSC_VER >= 1000
#pragma once
#endif

#include <afxtempl.h>

class CNewHeaderCtrl : public CHeaderCtrl
{
public:
	CNewHeaderCtrl();
	void DrawItem(LPDRAWITEMSTRUCT lpDrawItemStruct);
	CImageList* SetImageList(CImageList* pImageList);
	int GetItemImage(int nItem);
	void SetItemImage(int nItem, int nImage);
	void SetAutofit(bool bAutofit = true){ m_bAutofit = bAutofit; Autofit(); }
	virtual ~CNewHeaderCtrl();

protected:
	//{{AFX_MSG(CNewHeaderCtrl)
	afx_msg void OnPaint();
	afx_msg void OnLButtonDown(UINT nFlags, CPoint point);
	//}}AFX_MSG
	CImageList *m_pImageList;
	CMap< int, int, int, int> m_mapImageIndex;

	DECLARE_MESSAGE_MAP()

private:
	void Autofit(int nOverrideItemData = -1, int nOverrideWidth = 0);
	bool m_bIsSort;
	BOOL m_bAutofit;
	BOOL m_Ascending;
	BOOL m_RTL;
};

#endif // !defined(AFX_NEWHEADERCTRL_H__99EB0481_4FA1_11D1_980A_004095E0DEFA__INCLUDED_)
