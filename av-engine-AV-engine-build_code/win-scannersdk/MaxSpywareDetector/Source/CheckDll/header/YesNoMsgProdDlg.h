#pragma once
#include "SetDialogBitmaps.h"
#include "ColorStatic.h"
#include "afxwin.h"
#include "xSkinButton.h"
#include "MaxFont.h"


// CYesNoMsgProdDlg dialog

class CYesNoMsgProdDlg : public CDialog
{
	DECLARE_DYNAMIC(CYesNoMsgProdDlg)

public:
	CYesNoMsgProdDlg(CWnd* pParent = NULL);   // standard constructor
	virtual ~CYesNoMsgProdDlg();

// Dialog Data
	enum { IDD = IDD_DLG_PROD_YESNO };

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support

	DECLARE_MESSAGE_MAP()

public:
	int m_iProdID;
	HMODULE	m_hResDLL;
	CSpyDetectDlgBitmaps * m_SpyDetectDlgBitmaps;
	/*CStatic m_Title_Image;
	CStatic m_Title_Extend;
	CStatic m_Title_Right_Corner;
	CStatic m_BottomLeft;
	CStatic m_BottomRight;
	CStatic m_YN_Top_Left;
	CStatic m_YN_Top_Right;
	CStatic m_YN_Bottom_Left;
	CStatic m_YN_Bottom_Right;*/
	CColorStatic m_stTilte;
	CColorStatic m_stMessage;
	CBrush objBrush;
	CString		m_csTitle;
	CString		m_csMessage;
	bool		m_bAllowCancel;
	CMaxFont *m_pbtnFont, *m_pTitleFont,*m_pMsgFont;
	COLORREF MAINUIDLG_HEADING_TEXT_RGB;
	COLORREF MAINUIDLG_CONTENT_TEXT_RGB;
	COLORREF MAINUIDLG_BUTTON_TEXT_RGB;
	COLORREF INNER_UI_BUTTON_TEXT_RGB;
	COLORREF INNER_UI_BUTTON_OVER_TEXT_RGB;
	COLORREF MAIN_UI_BUTTON_OVER_TEXT_RGB;

	void AdjustControls(CDC *pDC);
	virtual BOOL OnInitDialog();
protected:
	virtual void OnCancel();
public:
	afx_msg void OnPaint();
	void LoadImages();
	afx_msg HBRUSH OnCtlColor(CDC* pDC, CWnd* pWnd, UINT nCtlColor);
	CxSkinButton m_BtnNoLeft;
	CxSkinButton m_BtnNo;
	CxSkinButton m_BtnNoRight;
	CxSkinButton m_BtnYes;
	afx_msg LRESULT OnNcHitTest(CPoint point);
	afx_msg void OnBnClickedBtnProdTwo_No();
	afx_msg void OnBnClickedBtnProdFor_Yes();
	CColorStatic m_StMainText;
	HICON m_hIcon;
};
