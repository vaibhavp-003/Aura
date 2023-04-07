/*=============================================================================
   FILE			: HyperLink.cpp
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
   NOTES		:Common GUI Custom Draw Classes
VERSION HISTORY	: 29.01.2008 : Avinash Bhardwaj : removed the code to close the parent window after clicking the hyperlink
				
============================================================================*/

#include "pch.h"
#include "resource.h"
#include "HyperLink.h"
#include "ExecuteProcess.h"
#include "MaxRes.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

#define TOOLTIP_ID 1

#define SETBITS(dw, bits)	(dw |= bits)
#define CLEARBITS(dw, bits)	(dw &= ~(bits))
#define BITSET(dw, bit)		(((dw)& (bit)) != 0L)

const DWORD CHyperLink::StyleUnderline		 = 0x00000000;		// Underline bit
const DWORD CHyperLink::StyleUseHover		 = 0x00000002;		// Hand over coloring bit
const DWORD CHyperLink::StyleAutoSize	  	 = 0x00000004;		// Auto size bit
const DWORD CHyperLink::StyleDownClick		 = 0x00000008;		// Down click mode bit
const DWORD CHyperLink::StyleGetFocusOnClick = 0x00000010;		// Get focus on click bit
const DWORD CHyperLink::StyleNoHandCursor	 = 0x00000020;		// No hand cursor bit
const DWORD CHyperLink::StyleNoActiveColor	 = 0x00000040;		// No active color bit

COLORREF CHyperLink::g_crLinkColor		= RGB(0, 0, 255);	// Blue
COLORREF CHyperLink::g_crActiveColor	= RGB(0, 128, 128);	// Dark cyan
COLORREF CHyperLink::g_crVisitedColor	= RGB(128, 0, 128);	// Purple
COLORREF CHyperLink::g_crHoverColor		= RGB(255, 0, 0	);	// Red
HCURSOR	 CHyperLink::g_hLinkCursor		= NULL;				// No cursor
HMODULE  CHyperLink::m_hResDLL			= NULL;
/*-----------------------------------------------------------------------------
Function		: CHyperLink (Connstructor)
In Parameters	:
Out Parameters	:
Purpose			:This Fucntion initialize CHyperLink class
Author			:
-----------------------------------------------------------------------------*/
CHyperLink::CHyperLink(HMODULE hResDLL)
{
	try
	{
		m_hResDLL			= hResDLL;
		m_bOverControl		= FALSE;	// Cursor not yet over control
		m_bVisited			= FALSE;	// Link has not been visited yet
		m_bLinkActive		= FALSE;	// Control doesn't own the focus yet
		m_strURL.Empty();				// Set URL to an empty string
		m_bShowWindow		= true;
		// Set default styles
		m_dwStyle = StyleUnderline|StyleAutoSize|StyleGetFocusOnClick;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CHyperLink::CHyperLink"));
	}
}

/*-----------------------------------------------------------------------------
Function		: ~CHyperLink (Destructor)
In Parameters	:
Out Parameters	:
Purpose			:This Function destruct CHyperLink class
Author			:
-----------------------------------------------------------------------------*/
CHyperLink::~CHyperLink()
{
	try
	{
		m_Font.DeleteObject();
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CHyperLink::~CHyperLink"));
	}
}

IMPLEMENT_DYNAMIC(CHyperLink, CStatic)

BEGIN_MESSAGE_MAP(CHyperLink, CStatic)
	//{{AFX_MSG_MAP(CHyperLink)
	ON_WM_CTLCOLOR_REFLECT()
	ON_WM_SETCURSOR()
	ON_WM_MOUSEMOVE()
	ON_WM_LBUTTONUP()
	ON_WM_SETFOCUS()
	ON_WM_KILLFOCUS()
	ON_WM_KEYDOWN()
	ON_WM_NCHITTEST()
	ON_WM_LBUTTONDOWN()
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()

/*-----------------------------------------------------------------------------
Function		: PreTranslateMessage
In Parameters	: MSG* : Points to a MSG structure that contains the
message to process.
Out Parameters	: BOOL :Nonzero if the message was translated and should not be
dispatched; 0 if the message was not translated and should
be dispatched.
Purpose		: Used by class CWinApp to translate window messages before they are
dispatched to the TranslateMessage and DispatchMessage Windows
functions.
Author		:
-----------------------------------------------------------------------------*/
BOOL CHyperLink::PreTranslateMessage(MSG* pMsg)
{
	try
	{
		m_ToolTip.RelayEvent(pMsg);
		return CStatic::PreTranslateMessage(pMsg);
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CHyperLink::PreTranslateMessage"));
	}
	return FALSE;
}

/*-----------------------------------------------------------------------------
Function		: PreSubclassWindow
In Parameters	:
Out Parameters	:
Purpose		:This member function is called by the framework to allow other
necessary subclassing to occur before the window is subclassed.
Author		:
-----------------------------------------------------------------------------*/
void CHyperLink::PreSubclassWindow()
{
	try
	{
		// If the URL string is empty try to set it to the window text
		if(m_strURL.IsEmpty())
			GetWindowText(m_strURL);

		// Check that the window text isn't empty.If it is, set it as URL string.
		CString strWndText;
		GetWindowText(strWndText);
		if(strWndText.IsEmpty()){
			// Set the URL string as the window text
			ASSERT(!m_strURL.IsEmpty());    // window text and URL both NULL!
			CStatic::SetWindowText(m_strURL);
		}

		// Get the current window font
		CFont* pFont = GetFont();

		if(pFont != NULL){
			LOGFONT lf;
			pFont->GetLogFont(&lf);
			lf.lfUnderline = 1/*BITSET(m_dwStyle, StyleUnderline)*/;
			if(m_Font.CreateFontIndirect(&lf))
				CStatic::SetFont(&m_Font);
			// Adjust window size to fit URL if necessary
			AdjustWindow();
		}
		else {
			// if GetFont()returns NULL then probably the static
			// control is not of a text type: it's better to set
			// auto-resizing off
			CLEARBITS(m_dwStyle,StyleAutoSize);
		}

		if(!BITSET(m_dwStyle,StyleNoHandCursor))
			SetDefaultCursor();      // Try to load an "hand" cursor

		// Create the tooltip
		CRect rect;
		GetClientRect(rect);
		m_ToolTip.Create(this);

		m_ToolTip.AddTool(this, m_strURL, rect, TOOLTIP_ID);

		CStatic::PreSubclassWindow();
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CHyperLink::PreSubclassWindow"));
	}
}

/*-----------------------------------------------------------------------------
Function		: CtlColor
In Parameters	: CDD* : pointer to CDC
: UINT :
Out Parameters	:
Purpose		:
Author		:
-----------------------------------------------------------------------------*/
HBRUSH CHyperLink::CtlColor(CDC* pDC, UINT nCtlColor)
{
	try
	{
		ASSERT(nCtlColor == CTLCOLOR_STATIC);

		if(m_bOverControl && BITSET(m_dwStyle,StyleUseHover))
			pDC->SetTextColor(g_crHoverColor);
		else if(!BITSET(m_dwStyle,StyleNoActiveColor) && m_bLinkActive)
			pDC->SetTextColor(g_crActiveColor);
		else if(m_bVisited)
			pDC->SetTextColor(g_crVisitedColor);
		else
			pDC->SetTextColor(g_crLinkColor);

		// Set transparent drawing mode
		pDC->SetBkMode(TRANSPARENT);
		return (HBRUSH)GetStockObject(NULL_BRUSH);
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CHyperLink::CtlColor"));
	}
	return NULL;
}

/*-----------------------------------------------------------------------------
Function		: OnMouseMove
In Parameters	: UINT :Indicates whether various virtual keys are down
:  CPoint :Specifies the x- and y-coordinate of the cursor.
Out Parameters	:
Purpose		:This Function is called on mouse move
Author		:
-----------------------------------------------------------------------------*/
void CHyperLink::OnMouseMove(UINT nFlags, CPoint point)
{
	try
	{
		if(m_bOverControl)       // Cursor currently over control
		{
			CRect rect;
			GetClientRect(rect);

			if(!rect.PtInRect(point))
			{
				m_bOverControl = FALSE;
				ReleaseCapture();
				Invalidate();
				return;
			}
		}
		else                      // Cursor has left control area
		{
			m_bOverControl = TRUE;
			Invalidate();
			SetCapture();
		}
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CHyperLink::OnMouseMove"));
	}
}

// "Normally, a static control does not get mouse events unless it has
// SS_NOTIFY.This achieves the same effect as SS_NOTIFY, but it's fewer
// lines of code and more reliable than turning on SS_NOTIFY in OnCtlColor
// because Windows doesn't send WM_CTLCOLOR to bitmap static controls."
// (Paul DiLascia)

/*-----------------------------------------------------------------------------
Function		: OnNcHitTest
In Parameters	: CPoint : object to CPoint structure
Out Parameters	:LRESULT : HTCAPTION
Purpose		: The framework calls this member function for the CWnd object
that contains the cursor,every time the mouse is moved
Author		:
-----------------------------------------------------------------------------*/
LRESULT CHyperLink::OnNcHitTest(CPoint /*point*/)
{
	return HTCLIENT;
}

/*-----------------------------------------------------------------------------
Function		: OnLButtonDown
In Parameters	: UINT :Indicates whether various virtual keys are down
: CPoint :Specifies the x- and y-coordinate of the cursor.
Out Parameters	:
Purpose		:This Function is called user presses the left mouse button.
Author		:
-----------------------------------------------------------------------------*/
void CHyperLink::OnLButtonDown(UINT /*nFlags*/, CPoint /*point*/)
{
	try
	{
		if(BITSET(m_dwStyle,StyleGetFocusOnClick))
			SetFocus();				// Set the focus and make the link active
		if(BITSET(m_dwStyle,StyleDownClick))
			FollowLink();
		m_bLinkActive = TRUE;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CHyperLink::OnLButtonDown"));
	}
}

/*-----------------------------------------------------------------------------
Function		: OnLButtonUp
In Parameters	: UINT :Indicates whether various virtual keys are down
: CPoint :Specifies the x- and y-coordinate of the cursor.
Out Parameters	:
Purpose		:This Function  is called  when the user releases the left mouse button.
Author		:
-----------------------------------------------------------------------------*/
void CHyperLink::OnLButtonUp(UINT /*nFlags*/, CPoint /*point*/)
{
	try
	{
		if(m_bLinkActive && !BITSET(m_dwStyle,StyleDownClick))
			FollowLink();
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CHyperLink::OnLButtonUp"));
	}
}

/*-----------------------------------------------------------------------------
Function		: OnSetCursor
In Parameters	: CWnd* : Specifies a pointer to the window that contains the cursor.
: UINT : Specifies the hit-test area code.The hit test determines
the cursor's location.
: UINT :Specifies the mouse message number.
Out Parameters	: BOOL :true if successfully associated else false.
Purpose		: associate a new cursor with the button.
Author		:
-----------------------------------------------------------------------------*/
BOOL CHyperLink::OnSetCursor(CWnd* /*pWnd*/, UINT /*nHitTest*/, UINT /*message*/)
{
	try
	{
		if(g_hLinkCursor)
		{
			::SetCursor(g_hLinkCursor);
			return TRUE;
		}
		return FALSE;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CHyperLink::OnSetCursor"));
	}
}

/*-----------------------------------------------------------------------------
Function		: OnSetFocus
In Parameters	:  CWnd* : Contains the CWnd object that loses the input focus
Out Parameters	:
Purpose		:This method is called by the framework after gaining the input focus
Author		:
-----------------------------------------------------------------------------*/
void CHyperLink::OnSetFocus(CWnd* /*pOldWnd*/)
{
	try
	{
		m_bLinkActive = TRUE;
		Invalidate();
		// Repaint to set the focus
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CHyperLink::OnSetFocus"));
	}
}

/*-----------------------------------------------------------------------------
Function		: OnKillFocus
In Parameters	: CWnd* :Specifies a pointer to the window that receives the input focus.
Out Parameters	:
Purpose		:This method is called by the framework immediately before losing the
input focus
Author		:
-----------------------------------------------------------------------------*/
void CHyperLink::OnKillFocus(CWnd* /*pNewWnd*/)
{
	try
	{
		// Assume that control lost focus = mouse out
		// this avoid troubles with the Hover color
		m_bOverControl = FALSE;
		m_bLinkActive = FALSE;
		Invalidate();							// Repaint to unset the focus
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CHyperLink::OnKillFocus"));
	}
}

/*-----------------------------------------------------------------------------
Function		: OnKeyDown
: UINT :Specifies the virtual key code of the given key
: UINT :Specifies the repeat count
: UINT :Specifies the scan code
In Parameters	:
Out Parameters	:
Purpose		:This method is called by the framework when a nonsystem key is pressed
Author		:
-----------------------------------------------------------------------------*/
void CHyperLink::OnKeyDown(UINT nChar, UINT nRepCnt, UINT nFlags)
{
	try
	{
		if(nChar == VK_SPACE)
			FollowLink();
		else
			CStatic::OnKeyDown(nChar, nRepCnt, nFlags);
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CHyperLink::OnKeyDown"));
	}
}

/*-----------------------------------------------------------------------------
Function		: SetColors :
In Parameters	: COLORREF :
: COLORREF :
: COLORREF :
: COLORREF :
Out Parameters	:
Purpose		:This Function sets the color
Author		:
-----------------------------------------------------------------------------*/
void CHyperLink::SetColors(	COLORREF crLinkColor,
						   COLORREF crActiveColor,
						   COLORREF crVisitedColor,
						   COLORREF crHoverColor /* = -1 */)
{
	try
	{
		g_crLinkColor    = crLinkColor;
		g_crActiveColor	 = crActiveColor;
		g_crVisitedColor = crVisitedColor;

		if(crHoverColor == -1)
			g_crHoverColor = ::GetSysColor(COLOR_HIGHLIGHT);
		else
			g_crHoverColor = crHoverColor;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CHyperLink::SetColors"));
	}
}

/*-----------------------------------------------------------------------------
Function		: SetColors
In Parameters	: HYPERLINKCOLORS :
Out Parameters	:
Purpose		:This Function set hiperlink color
Author		:
-----------------------------------------------------------------------------*/
void CHyperLink::SetColors(HYPERLINKCOLORS& linkColors){
	try
	{
		g_crLinkColor	 = linkColors.crLink;
		g_crActiveColor	 = linkColors.crActive;
		g_crVisitedColor = linkColors.crVisited;
		g_crHoverColor	 = linkColors.crHover;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CHyperLink::SetColors"));
	}
}

/*-----------------------------------------------------------------------------
Function		: GetColors
In Parameters	: HYPERLINKCOLORS :
Out Parameters	:
Purpose		:This Function retrives HYPERLINKCOLORS color
Author		:
-----------------------------------------------------------------------------*/
void CHyperLink::GetColors(HYPERLINKCOLORS& linkColors){
	try
	{
		linkColors.crLink = g_crLinkColor;
		linkColors.crActive = g_crActiveColor;
		linkColors.crVisited = g_crVisitedColor;
		linkColors.crHover = g_crHoverColor;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CHyperLink::GetColors"));
	}
}

/*-----------------------------------------------------------------------------
Function		: SetLinkCursor
In Parameters	: HCURSOR :
Out Parameters	:
Purpose		:Set the link cursor
Author		:
-----------------------------------------------------------------------------*/
void CHyperLink::SetLinkCursor(HCURSOR hCursor){
	try
	{
		ASSERT(hCursor != NULL);

		g_hLinkCursor = hCursor;
		if(g_hLinkCursor == NULL)
			SetDefaultCursor();
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CHyperLink::SetLinkCursor"));
	}
}

/*-----------------------------------------------------------------------------
Function		: GetLinkCursor
In Parameters	:
Out Parameters	:
Purpose		:This Function retrives link cursor
Author		:
-----------------------------------------------------------------------------*/
HCURSOR CHyperLink::GetLinkCursor()
{
	return g_hLinkCursor;
}

/*-----------------------------------------------------------------------------
Function		: ModifyLinkStyle
In Parameters	: DWORD :
: DWORD :
: BOOL :
Out Parameters	: BOOL : true if successfully modified else false.
Purpose		:This Function modify link style
Author		:
-----------------------------------------------------------------------------*/
BOOL CHyperLink:: ModifyLinkStyle(DWORD dwRemove, DWORD dwAdd,
								  BOOL bApply /* =TRUE */)
{
	try
	{
		// Check if we are adding and removing the same style
		if((dwRemove & dwAdd) != 0L)
			return FALSE;

		// Remove old styles and set the new ones
		CLEARBITS(m_dwStyle, dwRemove);
		SETBITS(m_dwStyle, dwAdd);

		if(bApply && ::IsWindow(GetSafeHwnd())){
			// If possible, APPLY the new styles on the fly
			if(BITSET(dwAdd,StyleUnderline) || BITSET(dwRemove,StyleUnderline))
				SwitchUnderline();
			if(BITSET(dwAdd,StyleAutoSize))
				AdjustWindow();
			if(BITSET(dwRemove,StyleUseHover))
				Invalidate();
		}
		return TRUE;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CHyperLink::ModifyLinkStyle"));
	}
	return FALSE;
}

/*-----------------------------------------------------------------------------
Function		: GetLinkStyle
In Parameters	:
Out Parameters	:
Purpose		:This Function retrives link Style
Author		:
-----------------------------------------------------------------------------*/
DWORD CHyperLink::GetLinkStyle()const {
	return m_dwStyle;
}

/*-----------------------------------------------------------------------------
Function		: SetURL
In Parameters	: CString : string containg URL
Out Parameters	:
Purpose		:This functin set URL.
Author		:
-----------------------------------------------------------------------------*/
void CHyperLink::SetURL(CString strURL)
{
	try
	{
		m_strURL = strURL;

		if(::IsWindow(GetSafeHwnd())){
			ShowWindow(SW_HIDE);
			AdjustWindow();
			m_ToolTip.UpdateTipText(strURL, this, TOOLTIP_ID);
			if(m_bShowWindow)
				ShowWindow(SW_SHOW);
		}
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CHyperLink::SetURL"));
	}
}

/*-----------------------------------------------------------------------------
Function		: GetURL
In Parameters	:
Out Parameters	:
Purpose		:This Function retrive URL
Author		:
-----------------------------------------------------------------------------*/
CString CHyperLink::GetURL()const{
	return m_strURL;
}

/*-----------------------------------------------------------------------------
Function		: SetWindowText
In Parameters	: LPCTSTR : pointer to string containg text
Out Parameters	:
Purpose		: This Function sets the Window title.
Author		:
-----------------------------------------------------------------------------*/
void CHyperLink::SetWindowText(LPCTSTR lpszText)
{
	try
	{
		ASSERT(lpszText != NULL);

		if(::IsWindow(GetSafeHwnd())){
			// Set the window text and adjust its size while the window
			// is kept hidden in order to allow dynamic modification
			ShowWindow(SW_HIDE);				// Hide window
			// Call the base class SetWindowText()
			CStatic::SetWindowText(lpszText);
			// Resize the control if necessary
			AdjustWindow();
			if(m_bShowWindow)
				ShowWindow(SW_SHOW);				// Show window
		}

	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CHyperLink::SetWindowText"));
	}
}

/*-----------------------------------------------------------------------------
Function		: SetFont
In Parameters	: CFont :contains font
Out Parameters	:
Purpose		:This Function sets the Fonts
Author		:
-----------------------------------------------------------------------------*/
void CHyperLink::SetFont(CFont* pFont)
{
	try
	{
		ASSERT(::IsWindow(GetSafeHwnd()));
		ASSERT(pFont != NULL);

		// Set the window font and adjust its size while the window
		// is kept hidden in order to allow dynamic modification
		ShowWindow(SW_HIDE);				// Hide window
		LOGFONT lf;
		// Create the new font
		pFont->GetLogFont(&lf);
		m_Font.DeleteObject();
		m_Font.CreateFontIndirect(&lf);
		// Call the base class SetFont()
		CStatic::SetFont(&m_Font);
		// Resize the control if necessary
		AdjustWindow();
		if(m_bShowWindow)
			ShowWindow(SW_SHOW);				// Show window
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CHyperLink::SetFont"));
	}
}

/*-----------------------------------------------------------------------------
Function		: SwitchUnderline
In Parameters	:
Out Parameters	:
Purpose		:This Function switches the undrline property
Author		:
-----------------------------------------------------------------------------*/
void CHyperLink::SwitchUnderline()
{
	try
	{
		LOGFONT lf;
		CFont* pFont = GetFont();
		if(pFont != NULL){
			pFont->GetLogFont(&lf);
			lf.lfUnderline = BITSET(m_dwStyle,StyleUnderline);
			m_Font.DeleteObject();
			m_Font.CreateFontIndirect(&lf);
			SetFont(&m_Font);
		}
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CHyperLink::SwitchUnderline"));
	}
}

/*-----------------------------------------------------------------------------
Function		: AdjustWindow
In Parameters	:
Out Parameters	:
Purpose		:Move and resize the window so that its client area has the same size
as the hyperlink text.This prevents the hyperlink cursor being active
when it is not over the text.
Author		:
-----------------------------------------------------------------------------*/
void CHyperLink::AdjustWindow()
{
	try
	{
		ASSERT(::IsWindow(GetSafeHwnd()));

		if(!BITSET(m_dwStyle,StyleAutoSize))
			return;

		// Get the current window rect
		CRect rcWnd;
		GetWindowRect(rcWnd);

		// For a child CWnd object, window rect is relative to the
		// upper-left corner of the parent window’s client area.
		CWnd* pParent = GetParent();
		if(pParent)
			pParent->ScreenToClient(rcWnd);

		// Get the current client rect
		CRect rcClient;
		GetClientRect(rcClient);

		// Calc border size based on window and client rects
		int borderWidth = rcWnd.Width() - rcClient.Width();
		int borderHeight = rcWnd.Height() - rcClient.Height();

		// Get the extent of window text
		CString strWndText;
		GetWindowText(strWndText);

		CDC* pDC = GetDC();
		CFont* pOldFont = pDC->SelectObject(&m_Font);
		CSize Extent = pDC->GetTextExtent(strWndText);
		pDC->SelectObject(pOldFont);
		ReleaseDC(pDC);

		// Get the text justification style
		DWORD dwStyle = GetStyle();

		// Recalc window size and position based on text justification
		if(BITSET(dwStyle, SS_CENTERIMAGE))
			rcWnd.DeflateRect(0, (rcWnd.Height() - Extent.cy)/ 2);
		else
			rcWnd.bottom = rcWnd.top + Extent.cy;

		if(BITSET(dwStyle, SS_CENTER))
			rcWnd.DeflateRect((rcWnd.Width() - Extent.cx)/ 2, 0);
		else if(BITSET(dwStyle,SS_RIGHT))
			rcWnd.left  = rcWnd.right - Extent.cx;
		else // SS_LEFT
			rcWnd.right = rcWnd.left + Extent.cx;

		// Move and resize the window
		MoveWindow(rcWnd.left, rcWnd.top, rcWnd.Width() + borderWidth,
			rcWnd.Height() + borderHeight);
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CHyperLink::AdjustWindow"));
	}
}

/*-----------------------------------------------------------------------------
Function		: SetVisited
In Parameters	: BOOL :
Out Parameters	:
Purpose		:
Author		:
-----------------------------------------------------------------------------*/
void CHyperLink::SetVisited(BOOL bVisited /* = TRUE */)
{
	m_bVisited = bVisited;
}

/*-----------------------------------------------------------------------------
Function		: IsVisited
In Parameters	:
Out Parameters	:
Purpose		:This function tells visited state.
Author		:
-----------------------------------------------------------------------------*/
BOOL CHyperLink::IsVisited()const
{
	return m_bVisited;
}

/*-----------------------------------------------------------------------------
Function		: SetDefaultCursor
In Parameters	:
Out Parameters	:
Purpose		:This Fucntion set the default cursor
Author		:
-----------------------------------------------------------------------------*/
// The following function appeared in Paul DiLascia's Jan 1998
// MSJ articles.It loads a "hand" cursor from "winhlp32.exe"
// resources
void CHyperLink::SetDefaultCursor()
{
	try
	{
		if(g_hLinkCursor == NULL)		// No cursor handle - load our own
		{
			HCURSOR hHandCursor = ::LoadCursor(m_hResDLL, MAKEINTRESOURCE(IDC_HAND_CURSOR));
			if(hHandCursor)
				g_hLinkCursor = CopyCursor(hHandCursor);
		}
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CHyperLink::SetDefaultCursor"));
	}
}
/*-----------------------------------------------------------------------------
Function		: GetRegKey
In Parameters	: HKEY :
: LPCTSTR :
: LPCTSTR :
Out Parameters	:
Purpose		:This Function retrives the registry key
Author		:
-----------------------------------------------------------------------------*/
LONG CHyperLink::GetRegKey(HKEY key, LPCTSTR subkey, LPTSTR retdata,DWORD dwLength)
{
	try
	{
		HKEY hkey;
		LONG retval = RegOpenKeyEx(key, subkey, 0, KEY_QUERY_VALUE, &hkey);

		if(retval == ERROR_SUCCESS){
			long datasize = MAX_PATH*sizeof(TCHAR);
			TCHAR data[MAX_PATH]={0};
			RegQueryValue(hkey, NULL, data, &datasize);
			_tcscpy_s(retdata,dwLength,data);
			RegCloseKey(hkey);
		}

		return retval;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CHyperLink::GetRegKey"));
	}
}
/*-----------------------------------------------------------------------------
Function		: ReportError
In Parameters	:  int : error no
Out Parameters	:
Purpose		:This Function will report any error occured
Author		:
-----------------------------------------------------------------------------*/
// Error report function
void CHyperLink::ReportError(int nError)
{
	try
	{
		CString str;

		switch (nError){
			case 0:                       str = _T("The operating system is out\nof memory or resources."); break;
			case ERROR_FILE_NOT_FOUND:    str = _T("The specified file was not found."); break;
			case ERROR_PATH_NOT_FOUND:	  str = _T("The specified path was not found."); break;
			case ERROR_BAD_FORMAT:        str = _T("The.EXE file is invalid\n(non-Win32.EXE or error in.EXE image)."); break;
			case SE_ERR_ACCESSDENIED:     str = _T("The operating system denied\naccess to the specified file."); break;
			case SE_ERR_ASSOCINCOMPLETE:  str = _T("The filename association is\nincomplete or invalid."); break;
			case SE_ERR_DDEBUSY:          str = _T("The DDE transaction could not\nbe completed because other DDE transactions\nwere being processed."); break;
			case SE_ERR_DDEFAIL:          str = _T("The DDE transaction failed."); break;
			case SE_ERR_DDETIMEOUT:       str = _T("The DDE transaction could not\nbe completed because the request timed out."); break;
			case SE_ERR_DLLNOTFOUND:      str = _T("The specified dynamic-link library was not found."); break;
				//case SE_ERR_FNF:			  str = _T("Windows 95 only: The specified file was not found."); break;
			case SE_ERR_NOASSOC:          str = _T("There is no application associated\nwith the given filename extension."); break;
			case SE_ERR_OOM:              str = _T("There was not enough memory to complete the operation."); break;
				//case SE_ERR_PNF:              str = _T("The specified path was not found."); break;
			case SE_ERR_SHARE:            str = _T("A sharing violation occurred."); break;
			default:                      str.Format(_T("Unknown Error (%d)occurred."), nError); break;
		}

		//str = _T("Can't open link:\n\n") + str;
		AfxMessageBox(str, MB_ICONEXCLAMATION | MB_OK);
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CHyperLink::ReportError"));
	}
}
/*-----------------------------------------------------------------------------
Function		: GotoURL
In Parameters	: LPCTSTR : contains URL
: int :
Out Parameters	:
Purpose		:This Function will open given URL
Author		:
-----------------------------------------------------------------------------*/
// "GotoURL" function by Stuart Patterson
// As seen in the August, 1997 Windows Developer's Journal.
HINSTANCE CHyperLink::GotoURL(LPCTSTR url, int showcmd)
{
	__try
	{
		GotoURLSEH(url,showcmd);
		HINSTANCE result = HINSTANCE_ERROR + (HINSTANCE)1;
		return result ;
		//TCHAR key[MAX_PATH + MAX_PATH]={0};
		// First try ShellExecute()
		//CExecuteProcess objExecute;
		//objExecute.ShellExecuteEx(url,L"", false, L"runas");
		//HINSTANCE result = ShellExecute(NULL, _T("open"), url, NULL,NULL, showcmd);

		// If it failed, get the.htm regkey and lookup the program
//#pragma warning (disable: 4311)
//		if(reinterpret_cast<UINT>(result)<= HINSTANCE_ERROR)
//		{
//#pragma warning (default: 4311)
//			AddLogEntry(_T("CHyperLink::GotoURL: ShellExecute failed!"));
//
//			if(GetRegKey(HKEY_CLASSES_ROOT, _T(".htm"), key,MAX_PATH + MAX_PATH) == ERROR_SUCCESS)
//			{
//				lstrcat(key, _T("\\shell\\open\\command"));
//				if(GetRegKey(HKEY_CLASSES_ROOT,key,key,MAX_PATH + MAX_PATH) == ERROR_SUCCESS)
//				{
//					TCHAR *pos;
//					pos = _tcsstr(key, _T("\"%1\""));
//					if(pos == NULL){                     // No quotes found
//						pos = wcsstr(key, _T("%1"));       // Check for %1, without quotes
//						if(pos == NULL)                  // No parameter at all...
//							pos = key+lstrlen(key) -1;
//						else
//							*pos = _T('\0');                   // Remove the parameter
//					}
//					else
//						*pos = _T('\0');                       // Remove the parameter
//
//					lstrcat(pos, _T(" "));
//					lstrcat(pos, url);
//					STARTUPINFO si;
//					si.dwFlags =STARTF_USESHOWWINDOW;
//					si.wShowWindow = showcmd;
//					PROCESS_INFORMATION pi;
//
//					AddLogEntry(_T("CHyperLink::GotoURL: Trying: ") + CString(key));
//
//#pragma warning (disable: 4312)
//					result = (HINSTANCE)CreateProcess(key, NULL, NULL, NULL, FALSE, 0,
//						NULL, NULL, &si, &pi);
//					if(!result)
//					{
//						if(pi.hProcess != INVALID_HANDLE_VALUE)
//							CloseHandle(pi.hProcess);
//
//						if(pi.hThread != INVALID_HANDLE_VALUE)
//							CloseHandle(pi.hThread);
//					}
//
//
//#pragma warning (default: 4312)
//				}
//			}
//		}
//		return result;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{

	}
	/*catch(...)
	{
		AddLogEntry(_T("Exception caught in CHyperLink::GotoURL"));
		return NULL;
	}*/
	return NULL;
}

/*-----------------------------------------------------------------------------
Function		: FollowLink
In Parameters	:
Out Parameters	:
Purpose		: Activate the link
Author		:
-----------------------------------------------------------------------------*/
void CHyperLink::FollowLink()
{
	try
	{
		HINSTANCE hResult = GotoURL(m_strURL, SW_SHOW);

#pragma warning (disable: 4311)
		if(reinterpret_cast<UINT>(hResult) > HINSTANCE_ERROR)
#pragma warning (default: 4311)
		{
			// Mark link as visited and repaint window
			m_bVisited = TRUE;
			Invalidate();
		}
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CHyperLink::FollowLink"));
	}
}

BOOL CHyperLink::GotoURLSEH(LPCTSTR url, int showcmd)
{
	BOOL bRet = FALSE; 
	CExecuteProcess objExecute;
	
	BOOL bShow = TRUE;
	if( _tcsstr(url, _T("mailto"))!= NULL)
		bShow = FALSE;
	
	bRet = objExecute.LaunchURLInBrowser(url, bShow);

	return bRet;
}