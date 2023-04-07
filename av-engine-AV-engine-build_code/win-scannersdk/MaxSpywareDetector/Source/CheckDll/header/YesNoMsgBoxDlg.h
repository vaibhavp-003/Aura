/*=============================================================================
   FILE			: YesNoMsgBoxDlg.h
   ABSTRACT		: This class provides methods to make dialog
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
VERSION HISTORY	: 15 Jan 2008 : Milind Shete
				 Unicode Supported.
				
============================================================================*/
#pragma once
#include "resource.h"
#include "xSkinButton.h"
#include "afxext.h"
#include "ColorStatic.h"
#include "SetDialogBitmaps.h"
#include "ResourceManager.h"
#include "afxwin.h"
#include "MaxFont.h"

// CYesNoMsgBoxDlg dialog
class CYesNoMsgBoxDlg : public CDialog
{
public:
	CYesNoMsgBoxDlg(CWnd* pParent = NULL);   // standard constructor
	virtual ~CYesNoMsgBoxDlg();
	enum{IDD = IDD_YESNOMEG_DLG };
	CString		m_csMessage;
	afx_msg void OnBnClickedOk();
	afx_msg void OnBnClickedCancel();
	virtual BOOL OnInitDialog();
	afx_msg void OnPaint();
	afx_msg HBRUSH OnCtlColor(CDC* pDC, CWnd* pWnd, UINT nCtlColor);
	afx_msg LRESULT OnNcHitTest(CPoint point);

protected:
	DECLARE_DYNAMIC(CYesNoMsgBoxDlg)
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support
	DECLARE_MESSAGE_MAP()
	CxSkinButton		m_btnOk;

private:
	COLORREF BACKGROUND_RBG;
	COLORREF BANNER_TEXT_COLOR_RGB;
	COLORREF BLACK_RBG;
	COLORREF TABINFORMATIONLABLE_RGB;
	COLORREF TABBACKGROUND_RGB;
	COLORREF TAB_TEXT_COLOR_RGB;
	COLORREF TITLE_COLOR_RGB;
	COLORREF MAIN_UI_BUTTON_TEXT_RGB;
	COLORREF MAIN_UI_BUTTON_OVER_TEXT_RGB;
	COLORREF MAIN_UI_BUTTON_FOCUS_TEXT_RGB;
	COLORREF INNER_UI_BUTTON_TEXT_RGB;
	COLORREF INNER_UI_BUTTON_OVER_TEXT_RGB;
	COLORREF INNER_UI_BUTTON_FOCUS_TEXT_RGB;
	COLORREF BLUEBACKGROUND_RGB;
	COLORREF UI_BORDER_RGB;
	COLORREF INNER_UI_BORDER_RGB;
	COLORREF MAIN_UI_MIDDLE_BG_RGB;
	COLORREF INFO_COLOR_RGB;
	COLORREF INFO_TEXT_COLOR_RGB;
	COLORREF TAB_INFO_LABEL_RGB;
	COLORREF TAB_INFO_LABEL_SIDE_BAR_RGB;
	COLORREF UI_MIDDLE_BG_RGB;
	COLORREF SHOW_TIPS_TOP_COLOR_RGB;
	COLORREF BUYNOW_LINK_TEXT_COLOR_RGB;
	COLORREF SELECTDRIVE_LU_TEXT_COLOR_RGB;
	COLORREF INNER_UI_TAB_TEXT_COLOR_RGB;
	COLORREF BTN_TEXT_COLOR_RGB;
	COLORREF MAINUIDLG_HEADING_TEXT_RGB;
	COLORREF MAINUIDLG_CONTENT_TEXT_RGB;
	COLORREF MAINUIDLG_BUTTON_TEXT_RGB;
	CxSkinButton m_btnClose;
	CString m_csProdName;
	HMODULE	m_hResDLL;
	CRgn rgn;
	CColorStatic m_stTilte;
	CColorStatic m_stMessage;
	HICON m_Icon;
	CMaxFont *m_pbtnFont, *m_pTitleFont,*m_pMsgFont;
	CSpyDetectDlgBitmaps * m_SpyDetectDlgBitmaps;
	CResourceManager m_ResMgr;
	DWORD GetDpiValue();
	void AdjustControls(CDC * pDC);
	void LoadImages();
	void GetRGBFromIni();

public:
	afx_msg BOOL OnEraseBkgnd(CDC* pDC);
	void DrawBorder(CDC * pDC);	
	void DrawLine (CDC * pDC,CPoint oPt1,CPoint oPt2);
	
};
