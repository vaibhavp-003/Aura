// JpegFormView.h : header file

#pragma once

class CJpegFormView : public CFormView
{
	DECLARE_DYNAMIC(CJpegFormView)
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
	CJpegFormView();
	CJpegFormView(UINT nTemplateID);	// standard constructor
	~CJpegFormView();

	BOOL Load(LPCTSTR szFileName);
	BOOL Load(LPCTSTR szResourceName, LPCTSTR szResourceType);
	BOOL Load(HGLOBAL hGlobal, DWORD dwSize);
	BOOL Draw();
	void UnLoad();

public:
	afx_msg BOOL OnEraseBkgnd(CDC* pDC);

protected:
	DECLARE_MESSAGE_MAP()
};