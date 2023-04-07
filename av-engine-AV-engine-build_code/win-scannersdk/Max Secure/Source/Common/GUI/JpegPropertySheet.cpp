#include "stdafx.h"
#include "PictureExLogo.h"
#include "JpegPropertySheet.h"

CJpegPropertySheet::CJpegPropertySheet(LPCTSTR szCaption, CWnd* pParentWnd, UINT iSelectPage)
	: CPropertySheet(szCaption, pParentWnd, iSelectPage)
{
	m_pPicture		   = NULL;
	m_bIsInitialized   = FALSE;
	m_hBitmap          = NULL;
	m_hOldBitmap	   = NULL;
	m_hMemDC		   = NULL;
	m_nDataSize		   = 0;
	m_PictureSize.cx = m_PictureSize.cy = 0;
	SetRect(&m_PaintRect,0,0,0,0);
	m_clrBackground    = RGB(255,255,255); // white by default
}

CJpegPropertySheet::~CJpegPropertySheet()
{
	if (m_pPicture)
	{
		m_pPicture->Release();
		m_pPicture = NULL;
	}
	if (m_hMemDC)
	{
		SelectObject(m_hMemDC,m_hOldBitmap);
		::DeleteDC(m_hMemDC);
		::DeleteObject(m_hBitmap);
		m_hMemDC  = NULL;
		m_hBitmap = NULL;
	}
}

BEGIN_MESSAGE_MAP(CJpegPropertySheet, CPropertySheet)
	ON_WM_ERASEBKGND()
#ifndef SDENTERPRISE
	ON_WM_NCHITTEST()
#endif
END_MESSAGE_MAP()

BOOL CJpegPropertySheet::OnEraseBkgnd(CDC *pDC)
{
#ifndef SDENTERPRISE
	return FALSE;
#else
	LONG nPaintWidth = m_PaintRect.right-m_PaintRect.left;
	if (nPaintWidth > 0)
	{
		LONG nPaintHeight = m_PaintRect.bottom - m_PaintRect.top;
		::BitBlt(pDC->m_hDC, 0, 0, nPaintWidth, nPaintHeight, m_hMemDC, m_PaintRect.left,				m_PaintRect.top, SRCCOPY);
	}
	else
	{
		::BitBlt(pDC->m_hDC, 0, 0, m_PictureSize.cx, m_PictureSize.cy, m_hMemDC, 0, 0, SRCCOPY);
	}
	return TRUE;
#endif
}

BOOL CJpegPropertySheet::Load(LPCTSTR szResourceName, LPCTSTR szResourceType)
{
	ASSERT(szResourceName);
	ASSERT(szResourceType);

	HRSRC hPicture = FindResource(AfxGetResourceHandle(),szResourceName,szResourceType);
	HGLOBAL hResData;
	if (!hPicture || !(hResData = LoadResource(AfxGetResourceHandle(),hPicture)))
	{
		TRACE(_T("Load (resource): Error loading resource %s\n"),szResourceName);
		return FALSE;
	};
	DWORD dwSize = SizeofResource(AfxGetResourceHandle(),hPicture);

	// hResData is not the real HGLOBAL (we can't lock it)
	// let's make it real
	HGLOBAL hGlobal = GlobalAlloc(GMEM_MOVEABLE | GMEM_NODISCARD,dwSize);
	if (!hGlobal)
	{
		TRACE(_T("Load (resource): Error allocating memory\n"));
		FreeResource(hResData);
		return FALSE;
	};
	
	char *pDest = reinterpret_cast<char *> (GlobalLock(hGlobal));
	char *pSrc = reinterpret_cast<char *> (LockResource(hResData));
	if (!pSrc || !pDest)
	{
		TRACE(_T("Load (resource): Error locking memory\n"));
		GlobalFree(hGlobal);
		FreeResource(hResData);
		return FALSE;
	};
	CopyMemory(pDest,pSrc,dwSize);
	FreeResource(hResData);
	GlobalUnlock(hGlobal);

	BOOL bRetValue = Load(hGlobal,dwSize);
	GlobalFree(hGlobal);
	return bRetValue;
}

BOOL CJpegPropertySheet::Load(HGLOBAL hGlobal, DWORD dwSize)
{
	IStream *pStream = NULL;
	m_nDataSize = dwSize;
	GlobalUnlock(hGlobal);

	// don't delete memory on object's release
	if (CreateStreamOnHGlobal(hGlobal,FALSE,&pStream) != S_OK)
		return FALSE;

	if (OleLoadPicture(pStream,dwSize,FALSE,IID_IPicture,
		reinterpret_cast<LPVOID *>(&m_pPicture)) != S_OK)
	{
		pStream->Release();
		return FALSE;
	};
	pStream->Release();

	// store picture's size
	long hmWidth;
	long hmHeight;

	m_pPicture->get_Width(&hmWidth);
	m_pPicture->get_Height(&hmHeight);

	HDC hDC = ::GetDC(m_hWnd);
	m_PictureSize.cx = MulDiv(hmWidth, GetDeviceCaps(hDC,LOGPIXELSX), 2540);
	m_PictureSize.cy = MulDiv(hmHeight, GetDeviceCaps(hDC,LOGPIXELSY), 2540);
	::ReleaseDC(m_hWnd,hDC);

	return PrepareDC(m_PictureSize.cx,m_PictureSize.cy);
}

BOOL CJpegPropertySheet::PrepareDC(int nWidth, int nHeight)
{
	#ifdef MASTRSCAN
		SetWindowPos(NULL, 0, 0, nWidth+10, nHeight+27, SWP_NOMOVE | SWP_NOZORDER);
	#else
		SetWindowPos(NULL, 0, 0, nWidth+10, nHeight+23, SWP_NOMOVE | SWP_NOZORDER);
	#endif
	HDC hWinDC = ::GetDC(m_hWnd);
	if (!hWinDC) return FALSE;
	
	m_hMemDC = CreateCompatibleDC(hWinDC);
	if (!m_hMemDC) 
	{
		::ReleaseDC(m_hWnd,hWinDC);
		return FALSE;
	};

	m_hBitmap  = CreateCompatibleBitmap(hWinDC,nWidth,nHeight);
	if (!m_hBitmap) 
	{
		::ReleaseDC(m_hWnd,hWinDC);
		::DeleteDC(m_hMemDC);
		return FALSE;
	};

	m_hOldBitmap = reinterpret_cast<HBITMAP> (SelectObject(m_hMemDC,m_hBitmap));
	
	// fill the background
	m_clrBackground = GetSysColor(COLOR_3DFACE);
	RECT rect = {0,0,nWidth,nHeight};
	FillRect(m_hMemDC,&rect,(HBRUSH)(COLOR_WINDOW));

	::ReleaseDC(m_hWnd,hWinDC);
	m_bIsInitialized = TRUE;
	return TRUE;
}

BOOL CJpegPropertySheet::Draw()
{
	if (!m_bIsInitialized)
	{
		TRACE(_T("Call one of the CPictureExLogo::Load() member functions before calling Draw()\n"));
		return FALSE;
	};
	if (m_pPicture)
	{
		long hmWidth;
		long hmHeight;
		m_pPicture->get_Width(&hmWidth);
		m_pPicture->get_Height(&hmHeight);
		if (m_pPicture->Render(m_hMemDC, 0, 0, m_PictureSize.cx, m_PictureSize.cy, 
			0, hmHeight, hmWidth, -hmHeight, NULL) == S_OK)
		{
			Invalidate(FALSE);
			return TRUE;
		};
	};
	return FALSE;	
}

// Darshan
// 18-Aug-2006
// This function is required in SD StandAlone and NOT required in SD Enterprise
#ifndef SDENTERPRISE
UINT CJpegPropertySheet::OnNcHitTest(CPoint point)
{
	return HTCAPTION;
}
#endif

