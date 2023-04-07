#include "pch.h"
#include "WindowPos.h"

int CWindowPos::m_iCurrentLanguage = 0;				// default language is english!
CString CWindowPos::m_csProductNumber = _T("");		// default product number is none!

CWindowPos::CWindowPos(void)
{
}

CWindowPos::~CWindowPos(void)
{
}

void CWindowPos::SetCurrentLanguage(int iLanguageID)
{
	m_iCurrentLanguage = iLanguageID;
}

void CWindowPos::SetProductNumber(CString csProductNumber)
{
	m_csProductNumber = csProductNumber;
}

int CWindowPos::GetTitleLeft()
{
	return 10;
}

int CWindowPos::GetTitleHeight()
{
	int iTop = 7;
	if(m_iCurrentLanguage == 6 || m_iCurrentLanguage == 7)
		iTop = 3;
	else if(m_iCurrentLanguage == 9 || m_iCurrentLanguage == 11)
		iTop = 4;
	return 35 - iTop;
}

int CWindowPos::GetTitleTop()
{
	int iTop = 7;
	if(m_iCurrentLanguage == 6 || m_iCurrentLanguage == 7)
		iTop = 3;
	else if(m_iCurrentLanguage == 9 || m_iCurrentLanguage == 11)
		iTop = 4;
	return iTop;
}

void CWindowPos::PositionTitle(CWnd &oTitleWnd)
{
	CRect oRect;
	oTitleWnd.GetClientRect(&oRect);
	oTitleWnd.MoveWindow(GetTitleLeft(), GetTitleTop(), oRect.Width(), GetTitleHeight());
}

void CWindowPos::ResizeButton(CWnd *pParentDlg, CWnd *pChildWnd, int iWidth, int iHeight, int iNewTop, int iNewLeft)
{
	CRect oRect;
	pChildWnd->GetWindowRect(&oRect);
	pParentDlg->ScreenToClient(&oRect);
	if(iNewTop != -1) 
	{
		oRect.top = iNewTop;
	}
	if(iNewLeft != -1) 
	{
		oRect.left = iNewLeft;
	}
	if(iWidth != -1) 
	{
		oRect.right = oRect.left + iWidth;
	}
	if(iHeight != -1) 
	{
		oRect.bottom = oRect.top + iHeight;  
	}
	pChildWnd->MoveWindow(&oRect);
}

int CWindowPos::PositionCloseRight()
{
	int iFromRight = 9;
	return iFromRight;
}

int CWindowPos::PositionCloseTop()
{
	int iFromTop = 5;
	return iFromTop;
}

int CWindowPos::PositionCloseLeft()
{
	int iFromLeft = 2;
	
	return iFromLeft;
}