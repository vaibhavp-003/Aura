/*=============================================================================
   FILE			: HyperLink.h
   ABSTRACT		: 
   DOCUMENTS	: Refer The ---- document
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
   NOTES		:Common GUI Custom Draw Class
VERSION HISTORY	:
				
============================================================================*/

#if !defined(AFX_HYPERLINK_H_04ET323B01_023500_0204251998_ENG_INCLUDED_)
#define AFX_HYPERLINK_H_04ET323B01_023500_0204251998_ENG_INCLUDED_

#if _MSC_VER >= 1000
#pragma once
#endif // _MSC_VER >= 1000

// Structure used to get/set hyperlink colors
typedef struct tagHYPERLINKCOLORS {
	COLORREF	crLink;
	COLORREF	crActive;
	COLORREF	crVisited;
	COLORREF	crHover;
} HYPERLINKCOLORS;


class CHyperLink : public CStatic
{
	DECLARE_DYNAMIC(CHyperLink)

public:
// Link styles
	static const DWORD StyleUnderline;
	static const DWORD StyleUseHover;
	static const DWORD StyleAutoSize;
	static const DWORD StyleDownClick;
	static const DWORD StyleGetFocusOnClick;
	static const DWORD StyleNoHandCursor;
	static const DWORD StyleNoActiveColor;

// Construction/destruction
	CHyperLink(HMODULE hResDLL);
	virtual ~CHyperLink();

	static void SetDefaultCursor();
	static void GetColors(HYPERLINKCOLORS& linkColors);

	static COLORREF g_crLinkColor;		// Link normal color
	static COLORREF g_crActiveColor;	// Link active color
	static COLORREF g_crVisitedColor;	// Link visited color
	static COLORREF g_crHoverColor;		// Hover color
	static HCURSOR  g_hLinkCursor;		// Hyperlink mouse cursor

	bool	 m_bShowWindow;				// show/hide window

	static HCURSOR GetLinkCursor();
	static void SetLinkCursor(HCURSOR hCursor);
    
    static void SetColors(COLORREF crLinkColor, COLORREF crActiveColor, 
				   COLORREF crVisitedColor, COLORREF crHoverColor = -1);
    static void SetColors(HYPERLINKCOLORS& colors);

	void SetURL(CString strURL);
    CString GetURL() const;

	DWORD GetLinkStyle() const;
	BOOL ModifyLinkStyle(DWORD dwRemove, DWORD dwAdd, BOOL bApply=TRUE);	
    
	void SetWindowText(LPCTSTR lpszText);
	void SetFont(CFont *pFont);
	
	BOOL IsVisited() const;
	void SetVisited(BOOL bVisited = TRUE);
	
	// Use this if you want to subclass and also set different URL
	BOOL SubclassDlgItem(UINT nID, CWnd* pParent, LPCTSTR lpszURL=NULL) {
		m_strURL = lpszURL;
		return CStatic::SubclassDlgItem(nID, pParent);
	}

// Overrides
	// ClassWizard generated virtual function overrides
	//{{AFX_VIRTUAL(CHyperLink)
	virtual BOOL PreTranslateMessage(MSG* pMsg);	
protected:
	virtual void PreSubclassWindow();	
	//}}AFX_VIRTUAL
// Implementation
	static LONG GetRegKey(HKEY key, LPCTSTR subkey, LPTSTR retdata,DWORD dwLength);
	static void ReportError(int nError);	
	static HINSTANCE GotoURL(LPCTSTR url, int showcmd);
	static BOOL GotoURLSEH(LPCTSTR url, int showcmd);

	void AdjustWindow();	
	void FollowLink();
	inline void SwitchUnderline();
	
	static HMODULE m_hResDLL;

// Protected attributes
	BOOL	 m_bLinkActive;				// Is the link active?
	BOOL     m_bOverControl;			// Is cursor over control?
	BOOL	 m_bVisited;				// Has link been visited?
	DWORD	 m_dwStyle;					// Link styles
	CString  m_strURL;					// Hyperlink URL string
	CFont    m_Font;					// Underlined font (if required)	
	CToolTipCtrl m_ToolTip;				// The link tooltip	

	// Generated message map functions
	//{{AFX_MSG(CHyperLink)
	afx_msg HBRUSH CtlColor(CDC* pDC, UINT nCtlColor);
	afx_msg BOOL OnSetCursor(CWnd* pWnd, UINT nHitTest, UINT message);
	afx_msg void OnMouseMove(UINT nFlags, CPoint point);
	afx_msg void OnLButtonUp(UINT nFlags, CPoint point);
	afx_msg void OnSetFocus(CWnd* pOldWnd);
	afx_msg void OnKillFocus(CWnd* pNewWnd);
	afx_msg void OnKeyDown(UINT nChar, UINT nRepCnt, UINT nFlags);
	afx_msg LRESULT OnNcHitTest(CPoint point);
	afx_msg void OnLButtonDown(UINT nFlags, CPoint point);
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()
};
#endif // !defined(AFX_HYPERLINK_H_04ET323B01_023500_0204251998_ENG_INCLUDED_)
