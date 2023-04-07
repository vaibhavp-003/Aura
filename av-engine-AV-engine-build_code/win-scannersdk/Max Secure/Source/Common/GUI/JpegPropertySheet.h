// JpegPropertySheet.h : header file

#pragma once

class CJpegPropertySheet : public CPropertySheet
{
	RECT		m_PaintRect;
	HDC			m_hMemDC;
	SIZE		m_PictureSize;
	UINT		m_nDataSize;
	HBITMAP		m_hBitmap;
	HBITMAP		m_hOldBitmap;
	IPicture	*m_pPicture;
	COLORREF	m_clrBackground;
	BOOL		m_bIsInitialized;

private:
	BOOL PrepareDC(int nWidth, int nHeight);

public:
	CJpegPropertySheet(LPCTSTR szCaption, CWnd* pParentWnd = NULL, UINT iSelectPage = NULL); // standard constructor
	~CJpegPropertySheet();

	BOOL Load(LPCTSTR szResourceName, LPCTSTR szResourceType);
	BOOL Load(HGLOBAL hGlobal, DWORD dwSize);
	BOOL Draw();

public:
	afx_msg BOOL OnEraseBkgnd(CDC* pDC);

#ifndef SDENTERPRISE
	afx_msg UINT OnNcHitTest(CPoint point);
#endif

protected:
	DECLARE_MESSAGE_MAP()
};