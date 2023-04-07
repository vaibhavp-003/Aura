// SkinDialog.cpp : implementation file
//
#include "stdafx.h"
#include "SkinDialog.h"

typedef BOOL (WINAPI *FN_SETLAYEREDWINDOWATTRIBUTES)(HWND hWnd, COLORREF cr, BYTE bAlpha, DWORD dwFlags);
FN_SETLAYEREDWINDOWATTRIBUTES g_pSetLayeredWindowAttributes;

typedef BOOL (WINAPI* FN_ANIMATEWINDOW)(HWND,DWORD,DWORD);
FN_ANIMATEWINDOW g_fnAnimateWindow;

// CSkinDialog dialog
CSkinDialog::CSkinDialog(CWnd* pParent /*=NULL*/)
{
	Init();
}

CSkinDialog::CSkinDialog(UINT uResourceID, CWnd* pParent)
						: CDialog(uResourceID, pParent)
{
	Init();
}


CSkinDialog::CSkinDialog(LPCTSTR pszResourceID, CWnd* pParent)
						: CDialog(pszResourceID, pParent)
{
	Init();
}

CSkinDialog::~CSkinDialog()
{
	FreeResources();
}

void CSkinDialog::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CSkinDialog, CDialog)
	ON_WM_LBUTTONDOWN()
	ON_WM_SIZE()
	ON_WM_ERASEBKGND()
END_MESSAGE_MAP()

// CSkinDialog message handlers

BOOL CSkinDialog::OnInitDialog()
{
	CDialog::OnInitDialog();

	return TRUE;  // return TRUE unless you set the focus to a control
}

void CSkinDialog::OnLButtonDown(UINT nFlags, CPoint point)
{
	if(m_bEasyMove)
	{
		PostMessage(WM_NCLBUTTONDOWN, HTCAPTION, MAKELPARAM(point.x, point.y));	
	}
	CDialog::OnLButtonDown(nFlags, point);
}

void CSkinDialog::OnSize(UINT nType, int cx, int cy)
{
	CDialog::OnSize(nType, cx, cy);
	if(m_hBitmap != NULL)
	{
		Invalidate();
	}	
}

BOOL CSkinDialog::SetTransparent(BYTE bAlpha)
{
	if(g_pSetLayeredWindowAttributes == NULL)
	{
		return FALSE;
	}

	if(bAlpha < 255)
	{
		//  set layered style for the dialog
		SetWindowLong(m_hWnd, GWL_EXSTYLE, GetWindowLong(m_hWnd, GWL_EXSTYLE) | WS_EX_LAYERED);
		//  call it with 255 as alpha - opacity
		g_pSetLayeredWindowAttributes(m_hWnd, 0, bAlpha, LWA_ALPHA);
	}
	else
	{
		SetWindowLong(m_hWnd, GWL_EXSTYLE, GetWindowLong(m_hWnd, GWL_EXSTYLE) & ~WS_EX_LAYERED);
		// Ask the window and its children to repaint
		::RedrawWindow(m_hWnd, NULL, NULL, RDW_ERASE | RDW_INVALIDATE | RDW_FRAME | RDW_ALLCHILDREN);
	}
	return TRUE;
}

BOOL CSkinDialog::SetTransparentColor(COLORREF col, BOOL bTrans)
{
	if(g_pSetLayeredWindowAttributes == NULL)
	{
		return FALSE;
	}

	if(bTrans)
	{
		//  set layered style for the dialog
		SetWindowLong(m_hWnd, GWL_EXSTYLE, GetWindowLong(m_hWnd, GWL_EXSTYLE) | WS_EX_LAYERED);
		//  call it with 0 alpha for the given color
		g_pSetLayeredWindowAttributes(m_hWnd, col, 0, LWA_COLORKEY);
	}
	else
	{
		SetWindowLong(m_hWnd, GWL_EXSTYLE, GetWindowLong(m_hWnd, GWL_EXSTYLE) & ~WS_EX_LAYERED);
		// Ask the window and its children to repaint
		::RedrawWindow(m_hWnd, NULL, NULL, RDW_ERASE | RDW_INVALIDATE | RDW_FRAME | RDW_ALLCHILDREN);
	}
	return TRUE;
}

void CSkinDialog::Init()
{
	m_hBitmap = NULL;
	m_bEasyMove = TRUE;
	m_loStyle = LOS_DEFAULT;

	//  get the function from the user32.dll 
	HMODULE hUser32 = GetModuleHandle(_T("USER32.DLL"));
	g_pSetLayeredWindowAttributes = (FN_SETLAYEREDWINDOWATTRIBUTES) GetProcAddress(hUser32, "SetLayeredWindowAttributes");
	g_fnAnimateWindow = (FN_ANIMATEWINDOW)GetProcAddress(hUser32, "AnimateWindow");
}

void CSkinDialog::FreeResources()
{
	if(m_hBitmap)
	{
		::DeleteObject(m_hBitmap);
	}
	m_hBitmap = NULL;
}

DWORD CSkinDialog::SetBitmap(UINT uBitmapResourceID)
{
	HBITMAP	hBitmap	   = NULL;
	HINSTANCE  hInstResource = NULL;
	
	// Find correct resource handle
	hInstResource = AfxFindResourceHandle(MAKEINTRESOURCE(uBitmapResourceID), RT_BITMAP);

	// Load bitmap In
	hBitmap = (HBITMAP)::LoadImage(hInstResource, MAKEINTRESOURCE(uBitmapResourceID), IMAGE_BITMAP, 0, 0, 0);
	
	return SetBitmap(hBitmap);
}

DWORD CSkinDialog::SetBitmap(HBITMAP hBitmap)
{
	int nRetValue;
	BITMAP  csBitmapSize;

	// Free any loaded resource
	FreeResources();

	if(hBitmap)
	{
		m_hBitmap = hBitmap;

		// Get bitmap size
		nRetValue = ::GetObject(hBitmap, sizeof(csBitmapSize), &csBitmapSize);
		if(nRetValue == 0)
		{
			FreeResources();
			return 0;
		}

		m_dwWidth = (DWORD)csBitmapSize.bmWidth;
		m_dwHeight = (DWORD)csBitmapSize.bmHeight;
	}

	if(IsWindow(this->GetSafeHwnd()))
	{
		Invalidate();
	}

	return 1;
}

DWORD CSkinDialog::SetBitmap(LPCTSTR lpszFileName)
{
	HBITMAP hBitmap = NULL;
	hBitmap = (HBITMAP)::LoadImage(0, lpszFileName, IMAGE_BITMAP, 0, 0, LR_LOADFROMFILE);
	return SetBitmap(hBitmap);
}

BOOL CSkinDialog::OnEraseBkgnd(CDC* pDC)
{
	BOOL bRetValue = CDialog::OnEraseBkgnd(pDC);
	if(!m_hBitmap)
	{
		return bRetValue;
	}

	CRect rect;
	GetClientRect(rect);
	
	CDC dc;
	dc.CreateCompatibleDC(pDC);

	HBITMAP pbmpOldBmp = NULL;
	pbmpOldBmp = (HBITMAP)::SelectObject(dc.m_hDC, m_hBitmap);
	
	if(m_loStyle == LOS_DEFAULT || m_loStyle == LOS_RESIZE)
	{
		pDC->BitBlt(0, 0, rect.Width(), rect.Height(), &dc, 0, 0, SRCCOPY);
	}
	else if(m_loStyle == LOS_TILE)
	{
		int ixOrg, iyOrg;
		for(iyOrg = 0; iyOrg < rect.Height(); iyOrg += m_dwHeight)
		{
			for(ixOrg = 0; ixOrg < rect.Width(); ixOrg += m_dwWidth)
			{
				pDC->BitBlt(ixOrg, iyOrg, rect.Width(), rect.Height(), &dc, 0, 0, SRCCOPY);
			}
		}
	}
	else if(m_loStyle == LOS_CENTER)
	{
		int ixOrg = (rect.Width() - m_dwWidth) / 2;
		int iyOrg = (rect.Height() - m_dwHeight) / 2;
		pDC->BitBlt(ixOrg, iyOrg, rect.Width(), rect.Height(), &dc, 0, 0, SRCCOPY);
	}
	else if ( m_loStyle == LOS_STRETCH)
	{
		pDC->StretchBlt(0, 0, rect.Width(), rect.Height(), &dc, 0, 0, m_dwWidth, m_dwHeight, SRCCOPY);
	}

	::SelectObject(dc.m_hDC, m_hBitmap);

	return bRetValue;
}

void CSkinDialog::EnableEasyMove(BOOL pEnable)
{
	m_bEasyMove = pEnable;
}

void CSkinDialog::SetStyle(LayOutStyle style)
{
	m_loStyle = style;
	if(m_loStyle == LOS_RESIZE && m_hBitmap)
	{
		SetWindowPos(0, 0, 0, m_dwWidth, m_dwHeight, SWP_NOMOVE | SWP_NOREPOSITION);
	}
}
