/*=============================================================================
   FILE			: FlatToolTipCtrl.h
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
CREATION DATE   : 2/24/06
   NOTES		:Arrow drawing is ported from the FLATGUI version in Delphi.
				You are free to use and modify this as long as you don`t claim it.
				Copyright : Tomkat(.ro)2004
VERSION HISTORY	:
				
============================================================================*/
#pragma once

class CToolTipCtrlEx : public CToolTipCtrl
{
public:
	CToolTipCtrlEx();
	virtual ~CToolTipCtrlEx();
protected:
	DECLARE_MESSAGE_MAP()
	virtual void PreSubclassWindow();
private:
	DECLARE_DYNAMIC(CToolTipCtrlEx)
	enum	Orientations
	{
		NW=1,
		NE,
		SW,
		SE,
	};
	afx_msg void OnPaint();
	afx_msg BOOL OnEraseBkgnd(CDC* pDC);
	COLORREF	m_bkColor;//=RGB(255,255,255);
	COLORREF	m_leftColor;//=RGB(255, 210, 83);
	COLORREF	m_frameColor;//=RGB(155, 110, 53);
	COLORREF	m_textColor;//=RGB(0,0,0);
	COLORREF	m_arrowColor;//=RGB(0,0,0);
};