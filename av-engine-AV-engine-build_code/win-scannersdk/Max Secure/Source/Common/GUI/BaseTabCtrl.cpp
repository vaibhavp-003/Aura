/*=============================================================================
   FILE			: CBaseTabCtrl.cpp
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
#include "stdafx.h"
#include "BaseTabCtrl.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

BEGIN_MESSAGE_MAP(CBaseTabCtrl, CTabCtrl)
	ON_WM_ERASEBKGND()
END_MESSAGE_MAP()

/*-----------------------------------------------------------------------------
	Function		: OnEraseBkgnd 
	In Parameters	: CDC* :  device-context  pointer
	Out Parameters	:BOOL : it always return false
	Purpose		:The framework calls this member function when the CWnd object
				background needs erasing. 
	Author		: 
-----------------------------------------------------------------------------*/
BOOL CBaseTabCtrl::OnEraseBkgnd(CDC* pDC) 
{
	try
	{
		CRect rClient, rTab, rTotalTab, rBkgnd, rEdge;
		COLORREF crBack;
		int nTab, nTabHeight = 0;
		
		CTabCtrl::OnEraseBkgnd(pDC);

		// calc total tab width
		GetClientRect(rClient);
		nTab = GetItemCount();
		rTotalTab.SetRectEmpty();

		while (nTab--)
		{
			GetItemRect(nTab, rTab);
			rTotalTab.UnionRect(rTab, rTotalTab);
		}

		nTabHeight = rTotalTab.Height();

		// add a bit
		rTotalTab.InflateRect(2, 3);
		rEdge = rTotalTab;

		// then if background color is set, paint the visible background
		// area of the tabs in the bkgnd color
		// note: the mfc code for drawing the tabs makes all sorts of assumptions
		// about the background color of the tab control being the same as the page
		// color - in some places the background color shows thru' the pages!!
		// so we must only paint the background color where we need to, which is that
		// portion of the tab area not excluded by the tabs themselves
		//crBack = (m_crBack == -1) ? ::GetSysColor(COLOR_3DFACE) : m_crBack;
		crBack = RGB(202,202,255);
		
		// full width of tab ctrl above top of tabs
		rBkgnd = rClient;
		rBkgnd.bottom = rTotalTab.top + 3;
		pDC->SetBkColor(crBack);
		pDC->ExtTextOut(rBkgnd.left, rBkgnd.top, ETO_CLIPPED | ETO_OPAQUE, rBkgnd, _T(""), NULL);
		
		// width of tab ctrl visible bkgnd including bottom pixel of tabs to left of tabs
		rBkgnd = rClient;
		rBkgnd.right = 2;
		rBkgnd.bottom = rBkgnd.top + (nTabHeight + 2);
		pDC->ExtTextOut(rBkgnd.left, rBkgnd.top, ETO_CLIPPED | ETO_OPAQUE, rBkgnd, _T(""), NULL);
		
		// to right of tabs
		rBkgnd = rClient;
		rBkgnd.left += rTotalTab.Width() - 2;
		rBkgnd.bottom = rBkgnd.top + (nTabHeight + 2);
		pDC->ExtTextOut(rBkgnd.left, rBkgnd.top, ETO_CLIPPED | ETO_OPAQUE, rBkgnd, _T(""), NULL);

		return TRUE;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CBaseTabCtrl::OnEraseBkgnd"));
	}
	return FALSE;
}

