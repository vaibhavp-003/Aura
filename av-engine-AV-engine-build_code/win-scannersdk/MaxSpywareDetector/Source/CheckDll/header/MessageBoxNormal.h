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

// CMessageBoxNormal dialog

class CMessageBoxNormal : public CDialog
{

public:
	CString				m_csMessage;
	CMessageBoxNormal(CWnd* pParent = NULL);   // standard constructor
	virtual ~CMessageBoxNormal();
	enum{IDD = IDD_MESSAGEBOX };

protected:
	DECLARE_DYNAMIC(CMessageBoxNormal)
	DECLARE_MESSAGE_MAP()
	CxSkinButton		m_btnOk;
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support

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
	CString m_csProdName;
	CRgn rgn;
	CColorStatic m_stTilte;
	CColorStatic m_stMsg;
	HICON m_Icon;
	HMODULE	m_hResDLL;
	CMaxFont *m_pbtnFont, *m_pTitleFont,*m_pMsgFont;
	CSpyDetectDlgBitmaps * m_SpyDetectDlgBitmaps;
	CResourceManager m_ResMgr;
	void AdjustControls(CDC * pDC);
	void LoadImages();
	afx_msg LRESULT OnNcHitTest(CPoint point);
	afx_msg void OnBnClickedOk();
	afx_msg void OnBnClickedCancel();
	virtual BOOL OnInitDialog();
	void GetRGBFromIni();
	afx_msg void OnPaint();
	afx_msg HBRUSH OnCtlColor(CDC* pDC, CWnd* pWnd, UINT nCtlColor);
	DWORD GetDpiValue();
public:
	/*CStatic m_stBottomLeft;
	CStatic m_stBottomRight;
	CStatic m_Title_Image;
	CStatic m_Title_Extend;
	CStatic m_Title_Right_Corner;
	CStatic m_MSG_Bottom_Left;
	CStatic m_MSG_Bottom_Right;
	CStatic m_MSG_Top_Left;
	CStatic m_Msg_Top_Right;*/
};
