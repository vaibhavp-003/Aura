#pragma once

enum LayOutStyle
{
	LOS_DEFAULT,
	LOS_TILE,		// Tile the background picture
	LOS_CENTER,		// Center the background picture
	LOS_STRETCH,	// Stretch the background picture to the dialog window size
	LOS_RESIZE		// Resize the dialog so that it just fits the background 
};

class CSkinDialog : public CDialog
{
public:
	CSkinDialog(CWnd* pParent = NULL);		// standard constructor
	CSkinDialog(UINT uResourceID, CWnd* pParent = NULL);
	CSkinDialog(LPCTSTR pszResourceID, CWnd* pParent = NULL);
	virtual ~CSkinDialog();

	DWORD SetBitmap(HBITMAP hBitmap);
	DWORD SetBitmap(UINT uBitmapResourceID);
	DWORD SetBitmap(LPCTSTR lpszFileName);
	void SetStyle(LayOutStyle style);
	void EnableEasyMove(BOOL pEnable = TRUE);
	BOOL SetTransparent(BYTE bAlpha);
	BOOL SetTransparentColor(COLORREF col, BOOL bTrans = TRUE);

protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV support

	DECLARE_MESSAGE_MAP()

private:
	BOOL m_bEasyMove;
	void FreeResources();
	void Init();
	HBITMAP		m_hBitmap;
	DWORD		m_dwWidth;		// Width of bitmap
	DWORD		m_dwHeight;		// Height of bitmap
	LayOutStyle	m_loStyle;		// LayOutStyle style
public:
	virtual BOOL OnInitDialog();
	afx_msg void OnLButtonDown(UINT nFlags, CPoint point);
	afx_msg void OnSize(UINT nType, int cx, int cy);
	afx_msg BOOL OnEraseBkgnd(CDC* pDC);
};
