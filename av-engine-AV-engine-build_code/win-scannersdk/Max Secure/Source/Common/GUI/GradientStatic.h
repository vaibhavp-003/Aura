/*======================================================================================
   FILE				: GradientStatic.h 
   ABSTRACT			: 
   DOCUMENTS		: 
   AUTHOR			: 
   COMPANY			: Aura 
   COPYRIGHT NOTICE :
						(C)Aura
						Created as an unpublished copyright work.  All rights reserved.
						This document and the information it contains is confidential and
						proprietary to Aura.  Hence, it may not be 
						used, copied, reproduced, transmitted, or stored in any form or by any 
						means, electronic, recording, photocopying, mechanical or otherwise, 
						without the prior written permission of Aura
   CREATION DATE	: 2/24/06
   NOTE				:
   VERSION HISTORY	: 29.01.2008 : Avinash Bhardwaj : added function and file header
=======================================================================================*/
#if !defined(AFX_GRADIENTSTATIC_H__0709E3A1_C8B6_11D6_B74E_004033A0FB96__INCLUDED_)
#define AFX_GRADIENTSTATIC_H__0709E3A1_C8B6_11D6_B74E_004033A0FB96__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif

// CGradientStatic window
typedef UINT (CALLBACK* LPFNDLLFUNC1)(HDC,CONST PTRIVERTEX,DWORD,CONST PVOID,DWORD,DWORD);

class CGradientStatic : public CStatic
{
public:
	CGradientStatic();
	virtual ~CGradientStatic();
	void SetWindowText(LPCTSTR a_lpstr);
	void SetColor(long cl){clLeft=cl;};
	void SetGradientColor(long cl){clRight=cl;};
	void SetTextColor(long cl){clText=cl;};
	void SetReverseGradient();
	void SetLeftSpacing(int iNoOfPixels){ m_iLeftSpacing = iNoOfPixels; };
	void SetTextAlign(int iAlign){ m_iAlign = iAlign; }; //0 - left, 1 - center, 2 -right
	void SetVerticalGradient(BOOL a_bVertical = TRUE){ m_bVertical = a_bVertical; };

	static void DrawGradRect(CDC *pDC, CRect r, COLORREF cLeft, COLORREF cRight, BOOL a_bVertical);

protected:
	CString m_sTEXT;
	int m_iLeftSpacing;
	long clLeft;
	long clRight;
	long clText;
	int m_iAlign;
	HINSTANCE hinst_msimg32;
	BOOL m_bCanDoGradientFill;
	BOOL m_bVertical;
	LPFNDLLFUNC1 dllfunc_GradientFill;

	//{{AFX_MSG(CGradientStatic)
	afx_msg void OnPaint();
	//}}AFX_MSG

	DECLARE_MESSAGE_MAP()
};

#endif // !defined(AFX_GRADIENTSTATIC_H__0709E3A1_C8B6_11D6_B74E_004033A0FB96__INCLUDED_)
