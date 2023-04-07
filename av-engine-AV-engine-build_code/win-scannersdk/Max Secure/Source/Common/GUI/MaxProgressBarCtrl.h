/*=============================================================================
   FILE		           : MaxProgressBarCtrl.h
   ABSTRACT		       : This control is used for Progrss Bar should be 3D Look. 
   DOCUMENTS	       : Refer The GUI Design.doc, GUI Requirement Document.doc
   AUTHOR		       : Ramkrushna Shelke 
   COMPANY		       : Aura 
   COPYRIGHT NOTICE    :
						(C)Aura:
      					Created as an unpublished copyright work.  All rights reserved.
     					This document and the information it contains is confidential and
      					proprietary to Aura.  Hence, it may not be 
      					used, copied, reproduced, transmitted, or stored in any form or by any 
      					means, electronic, recording, photocopying, mechanical or otherwise, 
      					without the prior written permission of Aura
   CREATION DATE      : 19/10/2011
   NOTES		      : header file for class inplementing header control
   VERSION HISTORY    : 
				
=============================================================================*/
#if !defined(AFX_MAXPROGRESSBARCTRL_H__603BBF44_B19C_11D3_90FA_0020AFBC499D__INCLUDED_)
#define AFX_MAXPROGRESSBARCTRL_H__603BBF44_B19C_11D3_90FA_0020AFBC499D__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

class CMaxProgressBarCtrl : public CProgressCtrl
{
// Construction
public:
	CMaxProgressBarCtrl();

// Attributes
public:

// Operations
public:
// Implementation
public:
	BOOL GetIndeterminate();
	void SetIndeterminate(BOOL bIndeterminate = TRUE);
	COLORREF GetColor();
	void SetColor(COLORREF crColorTop, COLORREF crColorBottom);
	virtual void SetBkColor(COLORREF cleNew);
	virtual ~CMaxProgressBarCtrl();

	// Generated message map functions
protected:
	//{{AFX_MSG(CMaxProgressBarCtrl)
	afx_msg void OnPaint();
	afx_msg void OnTimer(UINT_PTR nIDEvent);
	afx_msg BOOL OnEraseBkgnd(CDC* pDC);
	//}}AFX_MSG

	DECLARE_MESSAGE_MAP()
private:
	int m_nIndOffset;
	BOOL m_bIndeterminate;
	void DrawVerticalBar(CDC *pDC, const CRect rect);
	void DrawHorizontalBar(CDC *pDC, const CRect rect);
	void DeletePens();
	void CreatePens();
	CPen m_penColor;
	CPen m_penColorLight;
	CPen m_penColorLighter;
	CPen m_penColorDark;
	CPen m_penColorDarker;
	CPen m_penDkShadow;
	CPen m_penShadow;
	CPen m_penLiteShadow;
	void GetColors();
	COLORREF m_crColorTop;
	COLORREF m_crColorBottom;	
	COLORREF m_crColorLight;
	COLORREF m_crColorLighter;
	COLORREF m_crColorLightest;
	COLORREF m_crColorDark;
	COLORREF m_crColorDarker;
	COLORREF m_crDkShadow;
	COLORREF m_crShadow;
	COLORREF m_crLiteShadow;
	COLORREF m_bkColor1;		
	COLORREF m_bkColor2;		
};
#endif // !defined(AFX_MACPROGRESSCTRL_H__603BBF44_B19C_11D3_90FA_0020AFBC499D__INCLUDED_)
