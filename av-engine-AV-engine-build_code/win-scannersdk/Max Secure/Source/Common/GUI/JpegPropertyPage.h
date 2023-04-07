// JpegDialog.h : header file

#pragma once

class CJpegPropertyPage : public CPropertyPage
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
	CJpegPropertyPage(UINT nTemplateID);	// standard constructor
	~CJpegPropertyPage();

	BOOL Load(LPCTSTR szResourceName, LPCTSTR szResourceType);
	BOOL Load(HGLOBAL hGlobal, DWORD dwSize);
	BOOL Draw();

public:
	afx_msg BOOL OnEraseBkgnd(CDC* pDC);

protected:
	DECLARE_MESSAGE_MAP()
};