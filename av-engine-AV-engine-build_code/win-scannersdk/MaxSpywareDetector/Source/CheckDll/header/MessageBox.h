/*======================================================================================
   FILE			: MessageBox.h
   ABSTRACT		: Defines the class behaviors for the application.
   DOCUMENTS	: Refer The Design Folder 
    COMPANY		: Aura 
COPYRIGHT NOTICE:
				(C) Aura
      		Created as an unpublished copyright work.  All rights reserved.
     		This document and the information it contains is confidential and
      		proprietary to Aura.  Hence, it may not be 
      		used, copied, reproduced, transmitted, or stored in any form or by any 
      		means, electronic, recording, photocopying, mechanical or otherwise, 
      		with out the prior written permission of Aura
   CREATION DATE: 18/01/2008
   NOTES		:
 VERSION HISTORY: 
======================================================================================*/

#pragma once
#include "afxwin.h"
#include "resource.h"
#include "ColorStatic.h"
#include "JpegDialog.h"

// CMessageBox dialog

class CMessageBox : public CJpegDialog
{
public:
	CMessageBox(CWnd* pParent = NULL);// standard constructor
	virtual ~CMessageBox();
	enum{IDD = IDD_DIALOG_MSG };

	CString m_Text;
	CString m_Link;
	CString m_Title;
	CBrush  m_brBlue;

	BOOL OnInitDialog();
	afx_msg HBRUSH	OnCtlColor(CDC* pDC, CWnd* pWnd, UINT nCtlColor);
	afx_msg void OnLButtonDblClk(UINT nFlags, CPoint point);
	afx_msg void OnLButtonDown(UINT nFlags, CPoint point);

protected:
	virtual void DoDataExchange(CDataExchange* pDX);// DDX/DDV support
	DECLARE_MESSAGE_MAP()

private:
	DECLARE_DYNAMIC(CMessageBox)

	CColorStatic m_st_link;
	CColorStatic m_st_Message;
};
