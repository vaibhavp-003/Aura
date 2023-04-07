#pragma once
#include "afxcmn.h"
#include "afxwin.h"
#include "SetDialogBitmaps.h"
#include "xSkinButton.h"
#include "ColorStatic.h"
#include "PictureExLogo.h"
#include "HyperLink.h"
#include "MaxFont.h"

// CSrvOptDlg dialog
class CSrvOptDlg : public CDialog
{
public:
	// Construction
	CSrvOptDlg(CWnd* pParent = NULL);	// standard constructor
	~CSrvOptDlg();

	afx_msg void OnTimer(UINT_PTR nIDEvent);
	CProgressCtrl m_ctrlMigrateProgress;
	afx_msg void OnClose();
	afx_msg BOOL OnEraseBkgnd(CDC* pDC);
	afx_msg HBRUSH OnCtlColor(CDC* pDC, CWnd* pWnd, UINT nCtlColor);
	afx_msg void OnWindowPosChanging(WINDOWPOS* lpwndpos);
	CxSkinButton m_btnContinue;
	CColorStatic m_stTitle;
	CColorStatic m_stMsg_Title;
	CColorStatic m_stMsg_Sub_Title;
	CButton m_ctrlThreat_Yes;
	CStatic m_stTopLeftCorner;
	CStatic m_stBottomLeftCorner;
	CStatic m_stTopRightCorner;
	CStatic m_stBottomRightCorner;
	afx_msg void OnBnClickedContinueButton();
	CPictureExLogo m_MigrateAnim;
	CHyperLink m_ctrlPrivacyPolicy;
	afx_msg LRESULT OnNcHitTest(CPoint point);
	CPictureExLogo m_ctrlMigrateStatic;
	afx_msg void OnBnClickedCancel();

	// Dialog Data
	enum {IDD = IDD_MIGRATESD_DIALOG};

protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV support

	// Implementation
	HICON m_hIcon;
	// Generated message map functions
	virtual BOOL OnInitDialog();
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()

private:
	CSpyDetectDlgBitmaps *m_SpyDetectDlgBitmaps;
	CRgn rgn;
	void AdjustControls(CDC * pDC);
	CMaxFont *m_pMsg_Title_Font, *m_pMsg_Sub_Title_Font;
	BOOL m_bShowWindow;
};
