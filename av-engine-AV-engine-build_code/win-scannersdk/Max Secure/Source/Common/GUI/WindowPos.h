#pragma once

class CWindowPos
{
	static CString m_csProductNumber;
	static int m_iCurrentLanguage;
	static int GetTitleLeft();
	static int GetTitleHeight();
	static int GetTitleTop();

public:
	CWindowPos(void);
	virtual ~CWindowPos(void);

	static void SetCurrentLanguage(int iLanguageID);
	static void SetProductNumber(CString csProductNumber);

	static void PositionTitle(CWnd &oTitleWnd);
	static void ResizeButton(CWnd *pParentDlg, CWnd *pChildWnd, int iWidth, int iHeight, int iNewTop, int iNewLeft);
	static int PositionCloseRight();
	static int PositionCloseTop();
	static int PositionCloseLeft();
};
