/*=============================================================================
   FILE		           : MessageBox2D.h
   ABSTRACT		       : This class implements message box functionality
   DOCUMENTS	       : 
   AUTHOR		       : Nitin Shekokar
   COMPANY		       : Aura 
   COPYRIGHT NOTICE    :
						(C) Aura
						 Created as an unpublished copyright work.  All rights reserved.
						 This document and the information it contains is confidential and
						 proprietary to Aura.  Hence, it may not be 
						 used, copied, reproduced, transmitted, or stored in any form or by any 
						 means, electronic, recording, photocopying, mechanical or otherwise, 
						 without the prior written permission of Aura.	
   CREATION DATE      :
   NOTES		      : Header file
   VERSION HISTORY    :				
=============================================================================*/
#pragma once
#include "TransparentStatic.h"
#include "xSkinButton.h"
#include "afxext.h"
#include "ColorStatic.h"
#include "SetDialogBitmaps.h"
#include "afxwin.h"
#include "resource.h"
#include "hyperlink.h"

const CString csOKMsg =	_T("OK");
const CString csRetryMsg1 =	_T("Retry");
const CString csCancelMsg1 =	_T("Cancel");
const CString csYesMsg1 =	_T("Yes");
const CString csNoMsg1 =	_T("No");

class CMessageBox2D : public CDialog
{
public:
	CMessageBox2D(CWnd* pParent, HMODULE hResDLL);   // standard constructor
	virtual ~CMessageBox2D();
	// Dialog Data
	enum{IDD = IDD_MESSAGEBOX };
	CxSkinButton m_btnOk;
	CColorStatic m_stTitle;
	CTransparentStatic	m_lblMessageBox;
	CString				m_csMessage;
	CColorStatic		m_Message;
	CRgn rgn;
	HICON				m_Icon;
	CSpyDetectDlgBitmaps *m_SpyDetectDlgBitmaps;
	
	CxSkinButton m_btnCancel;
	bool m_IsErrorCall;
	bool m_IsCancel; 
	bool m_IsError;

	CxSkinButton m_btYes;
	CxSkinButton m_btNo;
	
	virtual BOOL OnInitDialog();
	afx_msg void OnPaint();
	afx_msg HBRUSH OnCtlColor(CDC* pDC, CWnd* pWnd, UINT nCtlColor);
	afx_msg LRESULT OnNcHitTest(CPoint point);
	afx_msg void OnBnClickedOk();
	afx_msg void OnBnClickedYes();
	void AdjustControls(CDC * pDC);
	static void DrawRectangle(CDC * pDC, int left, int top, int right, int bottom , int ColourFlg);
	void SetURL(CString strTitle, CString strLink);
protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support
	DECLARE_DYNAMIC(CMessageBox2D)
	DECLARE_MESSAGE_MAP()
private:
	CHyperLink m_StaticLink;
	CString m_strTitle;
	CString m_strLink;
	int m_nColor;
};
