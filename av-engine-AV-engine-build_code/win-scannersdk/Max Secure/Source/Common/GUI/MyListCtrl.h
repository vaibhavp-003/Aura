#pragma once


// CMyListCtrl

class CMyListCtrl : public CListCtrl
{
	DECLARE_DYNAMIC(CMyListCtrl)

	CImageList m_ImageList;
	void DrawImage(int item, int subitem, CDC* pDC);
	bool GetImageRect(int item, int subitem, CRect& rect, bool imageOnly);

	int iImageColumn;

public:
	CMyListCtrl();
	virtual ~CMyListCtrl();

protected:
	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnVScroll(UINT nSBCode, UINT nPos, CScrollBar* pScrollBar);
	afx_msg void OnVScrollClipboard(CWnd* pClipAppWnd, UINT nSBCode, UINT nPos);
	afx_msg void OnNMCustomdraw(NMHDR *pNMHDR, LRESULT *pResult);
	bool bPaintImage;
};


 