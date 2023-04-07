/*======================================================================================
   FILE			: SetDialogBitmaps.cpp
   ABSTRACT		: Class to manage the common bitmaps of a dialog.
   DOCUMENTS	: 
   AUTHOR		: Zuber
   COMPANY		: Aura 
COPYRIGHT NOTICE:
				(C) Aura
				Created as an unpublished copyright work.  All rights reserved.
				This document and the information it contains is confidential and
				proprietary to Aura.  Hence, it may not be 
				used, copied, reproduced, transmitted, or stored in any form or by any 
				means, electronic, recording, photocopying, mechanical or otherwise, 
				with out the prior written permission of Aura
   CREATION DATE: 12/01/2007
   NOTE			:
VERSION HISTORY	:
					Version 1.0
					Resource: Zuber
					Description: New class to manage the common bitmaps of a dialog.

					Date: 27 March 2008
					Resource: Avinash Bhardwaj
					Description: Added extra handling for tray popup exe.

					Version: 19.0.0.73
					Date: 4-Feb-2009
					Resource: Ashwinee Jagtap
					Description: Modification in code for MultiLanguage Support.
=======================================================================================*/

#include "pch.h"
#include "SetDialogBitmaps.h"
#include "CPUInfo.h"
#include "shellapi.h"
#include "Constants.h"
#include "ProductInfo.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

DWORD CSpyDetectDlgBitmaps::m_dwDPIValue = 96;
/*-------------------------------------------------------------------------------------
Function		: CSpyDetectDlgBitmaps
In Parameters	: pWnd				- Handle of the dialog
: titleImageID		- Image ID of the title 
: titlebarImageID	- Image ID of the title bar
: monogramImageID	- Image ID of the monogram
: whiteImageID		- Image ID of the white patch
: bitsImageID		- Image ID of the bits (image below the "help" button)
Out Parameters	: -
Purpose			: Constructor for class CSpyDetectDlgBitmaps
Author			: Zuber
--------------------------------------------------------------------------------------*/
CSpyDetectDlgBitmaps::CSpyDetectDlgBitmaps(CWnd * pWnd,
										   int titleImageID,
										   int titlebarImageID,
										   int monogramImageID,
										   int whiteImageID,
										   int bitsImageID,
										   int titlebarRightCornerID,
										   int leftBottomCornerID,
										   int rightBottomCornerID,
										   int leftStripID,
										   int rightStripID,
										   int bottomMiddleStripID)
										   : m_parentWnd(pWnd), //dialog's window handle
										   m_titleImageID(titleImageID), // titlebar left
										   m_titlebarImageID(titlebarImageID), // titlebar middle
										   m_monogramImageID(monogramImageID), // banner left
										   m_whiteImageID(whiteImageID), // banner middle
										   m_bitsImageID(bitsImageID), // banner right
										   m_titlebarRightCornerID(titlebarRightCornerID), // titlebar right
										   m_leftBottomCornerID(leftBottomCornerID), //dialog's left bottom corner
										   m_rightBottomCornerID(rightBottomCornerID), //dialog's right bottom corner
										   m_leftStripID(leftStripID),
										   m_rightStripID(rightStripID), //dialog's right bottom corner
										   m_bottomMiddleStripID(bottomMiddleStripID)
{
	try
	{

		CWnd * cWnd = m_parentWnd ->GetDesktopWindow();
		cWnd ->GetWindowRect(&m_DesktopRect);

		CCPUInfo objCPUInfo;
		m_dwDPIValue = objCPUInfo.GetDpiValue();

		LOGFONT	lf;						   // Used to create the CFont.
		SecureZeroMemory(&lf, sizeof(LOGFONT));   // Clear	out	structure.
		//lf.lfWidth = 8;
		lf.lfWidth = 6;				// changed for MultiLanguage support

		lf.lfWeight = FW_BOLD;
		if(m_dwDPIValue > 96)
		{
			//lf.lfHeight	=8;
			lf.lfHeight	=-14;		// changed for MultiLanguage support
		}
		else
		{
			//lf.lfHeight	=12;
			lf.lfHeight	=-14;		// changed for MultiLanguage support.
		}
		wcscpy_s(lf.lfFaceName, LF_FACESIZE, _T("Microsoft Sans Serif"));	 //	   with	face name "Verdana".
		m_fontWindowTitle.CreateFontIndirect(&lf);	   // Create the font.

		LOGFONT	lfBtn;						   // Used to create the CFont.
		SecureZeroMemory(&lfBtn, sizeof(LOGFONT));   // Clear	out	structure.
		if(m_dwDPIValue > 96)
			lfBtn.lfHeight	= 14;
		else
			lfBtn.lfHeight	= 14;
		lfBtn.lfWeight = FW_BOLD;
		wcscpy_s(lf.lfFaceName, LF_FACESIZE, _T("Microsoft Sans Serif"));	 //	   with	face name "Verdana".
		m_fontButton.CreateFontIndirect(&lfBtn);

		SecureZeroMemory(&lf, sizeof(LOGFONT));
		lf.lfHeight	=14;
		lf.lfWidth = 0;
		lf.lfWeight = FW_NORMAL;
		wcscpy_s(lf.lfFaceName, LF_FACESIZE, _T("Microsoft Sans Serif"));
		m_fontInfoText.CreateFontIndirect(&lf);	   // Create the font.

		CProductInfo oProductInfo;
		ENUM_PRODUCT_TYPE eProductType = oProductInfo.GetProductType();
		CString csIniPath =  oProductInfo.GetProductAppFolderPath(eProductType) + SETTING_FOLDER + CURRENT_SETTINGS_INI;
		if(_waccess(csIniPath, 0) == -1)
		{
			CCPUInfo objCpuInfo;
			csIniPath = objCpuInfo.GetProdInstallPath() + SETTING_FOLDER + CURRENT_SETTINGS_INI;
		}

		UINT iBigUIBorder	= GetPrivateProfileInt(_T("Settings"), _T("BIGUIBORDER"), 0, csIniPath);
		m_iBigUIBorder = iBigUIBorder;
		
		DefaultStripColor[0] = RGB(148, 171, 241);
		DefaultStripColor[1] = RGB(136, 159, 232);
		DefaultStripColor[2] = RGB(130, 154, 227);
		DefaultStripColor[3] = RGB(123, 147, 222);
		DefaultStripColor[4] = RGB(118, 142, 218);
		DefaultStripColor[5] = RGB(114, 138, 215);
		DefaultStripColor[6] = RGB(110, 134, 212);
		DefaultStripColor[7] = RGB(106, 130, 208);

		CString csVal;
		int i;
		for(i = 0; i < 8; i++)
		{
			csVal.Format(_T("StripColor[%d]"), i);
			StripColor[i] = GetPrivateProfileInt(_T("colorcode"), csVal, DefaultStripColor[i], csIniPath);
		}
		
		TITLE_COLOR_RGB		= GetPrivateProfileInt(_T("colorcode"), _T("UI_BORDER"), 8991770, csIniPath);
		BLUEBACKGROUND_RGB	= GetPrivateProfileInt(_T("colorcode"), _T("BLUEBACKGROUND"), BLUEBACKGROUND, csIniPath);
		INNER_UI_BORDER_RGB	= GetPrivateProfileInt(_T("colorcode"), _T("INNER_UI_BORDER"), 0, csIniPath);
		UI_MIDDLE_BG_RGB	= GetPrivateProfileInt(_T("colorcode"), _T("UI_MIDDLE_BG"), 16777215, csIniPath);
			
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CSpyDetectDlgBitmaps::CSpyDetectDlgBitmaps"));
	}
}

/*-------------------------------------------------------------------------------------
Function		: ~CSpyDetectDlgBitmaps
In Parameters	: -
Out Parameters	: -
Purpose			: Destructor for class CSpyDetectDlgBitmaps
Author			: Zuber
--------------------------------------------------------------------------------------*/
CSpyDetectDlgBitmaps::~CSpyDetectDlgBitmaps()
{
}

/*-------------------------------------------------------------------------------------
Function		: SetParentWnd
In Parameters	: pWnd	- Handle of the dialog
Out Parameters	: -
Purpose			: Sets the dialog handle
Author			: Zuber
--------------------------------------------------------------------------------------*/
void CSpyDetectDlgBitmaps::SetParentWnd(CWnd * pWnd)
{
	m_parentWnd = pWnd;
}//SetParentWnd

/*-------------------------------------------------------------------------------------
Function		: OnSize
In Parameters	: -
Out Parameters	: -
Purpose			: Resizes the bitmaps according to the dialog size if necessary
Author			: Zuber
--------------------------------------------------------------------------------------*/
void CSpyDetectDlgBitmaps::OnSize()
{
	try
	{
		CWnd * pWnd;
		CRect parentRect;
		CRect titleRect, monogramRect, bitsRect, whiteRect, titleBarRect, titlebarRightCornerRect;
		CRect leftBottomCornerRect, rightBottomCornerRect, leftStripRect, rightStripRect, bottomMiddleStripRect;
		int iFromRight,iDiff;

		if(m_leftStripID > 0)
		{
			iFromRight = titlebarRightCornerRect.Width() - 3;
			iDiff = 0;//for traypop the difference should be 3
		}
		else
		{
			iFromRight = titlebarRightCornerRect.Width() - 6;
			iDiff = 3;//for traypop the difference should be 7
		}

		//Get the parent dialog rect.
		m_parentWnd ->GetClientRect(parentRect);

		//Title of dialog
		pWnd = m_parentWnd ->GetDlgItem(m_titleImageID);
		if(pWnd)
		{
			pWnd ->GetClientRect(&titleRect);
			m_parentWnd ->ScreenToClient(&titleRect);
			pWnd ->MoveWindow(0, 0, titleRect.Width(), titleRect.Height());
		}

		//Titlebar's right corner
		pWnd = m_parentWnd ->GetDlgItem(m_titlebarRightCornerID);
		if(pWnd)
		{
			pWnd ->GetWindowRect(&titlebarRightCornerRect);
			m_parentWnd ->ScreenToClient(&titlebarRightCornerRect);
			pWnd ->MoveWindow(parentRect.right - titlebarRightCornerRect.Width() - iDiff, parentRect.top, titlebarRightCornerRect.Width(), titlebarRightCornerRect.Height());
		}

		//Portion after title
		pWnd = m_parentWnd ->GetDlgItem(m_titlebarImageID);
		if(pWnd)
		{
			pWnd ->GetClientRect(&titleBarRect);
			m_parentWnd ->ScreenToClient(&titleBarRect);
			//pWnd ->MoveWindow(titleRect.Width() - 1, 0, parentRect.right-100, titleRect.Height());
			pWnd ->MoveWindow(titleRect.Width(), 0, parentRect.right - titleRect.Width() - titlebarRightCornerRect.Width() - iDiff + 2, titleRect.Height());
		}

		//monogram of the dialog
		pWnd = m_parentWnd ->GetDlgItem(m_monogramImageID);
		if(pWnd)
		{
			pWnd ->GetClientRect(&monogramRect);
			m_parentWnd ->ScreenToClient(&monogramRect);
			if(m_titleImageID > 0)
				pWnd ->MoveWindow(0, titleRect.Height(), monogramRect.Width(), monogramRect.Height());
			else
				pWnd ->MoveWindow(0, 35, monogramRect.Width(), monogramRect.Height());
		}

		//Extreme right portion below the title bar
		pWnd = m_parentWnd ->GetDlgItem(m_bitsImageID);
		if(pWnd)
		{
			pWnd ->GetClientRect(&bitsRect);
			m_parentWnd ->ScreenToClient(&bitsRect);
			if(m_titleImageID > 0)
				pWnd ->MoveWindow(parentRect.right - bitsRect.Width() -3, titleRect.Height(), bitsRect.Width(), monogramRect.Height());
			else
				pWnd ->MoveWindow(parentRect.right - bitsRect.Width() -3, 35, bitsRect.Width(), monogramRect.Height());
		}

		//Portion between the the above two
		pWnd = m_parentWnd ->GetDlgItem(m_whiteImageID);
		if(pWnd)
		{
			pWnd ->GetClientRect(&whiteRect);
			m_parentWnd ->ScreenToClient(&whiteRect);
			if(m_titleImageID > 0)
				pWnd ->MoveWindow(monogramRect.Width() - 1, titleRect.Height(), parentRect.right - bitsRect.Width() - monogramRect.Width() -2, monogramRect.Height());
			else
				pWnd ->MoveWindow(monogramRect.Width() - 1, 35, parentRect.right - bitsRect.Width() - monogramRect.Width() + 1, monogramRect.Height());
		}

		//vishal
		//dialog's left bottom corner
		pWnd = m_parentWnd ->GetDlgItem(m_leftBottomCornerID);
		if(pWnd)
		{
			pWnd ->GetClientRect(&leftBottomCornerRect);
			m_parentWnd ->ScreenToClient(&leftBottomCornerRect);
			pWnd ->MoveWindow(parentRect.left, parentRect.bottom - 15, leftBottomCornerRect.Width(), leftBottomCornerRect.Height());
		}

		//vishal
		//dialog's left bottom corner
		pWnd = m_parentWnd ->GetDlgItem(m_rightBottomCornerID);
		if(pWnd)
		{
			pWnd ->GetClientRect(&rightBottomCornerRect);
			m_parentWnd ->ScreenToClient(&rightBottomCornerRect);
			pWnd ->MoveWindow(parentRect.right - rightBottomCornerRect.Width() - 3, parentRect.bottom - 15, rightBottomCornerRect.Width(), rightBottomCornerRect.Height());
		}

		//vishal
		//dialog's middle bottom strip to be strected
		pWnd = m_parentWnd ->GetDlgItem(m_bottomMiddleStripID);
		if(pWnd)
		{
			pWnd ->GetClientRect(&bottomMiddleStripRect);
			m_parentWnd ->ScreenToClient(&bottomMiddleStripRect);
			bottomMiddleStripRect.left = parentRect.left + leftBottomCornerRect.Width();
			bottomMiddleStripRect.top = parentRect.bottom - 15;
			bottomMiddleStripRect.right = parentRect.Width() - rightBottomCornerRect.Width();
			bottomMiddleStripRect.bottom = parentRect.bottom - 3;
			pWnd ->MoveWindow(bottomMiddleStripRect.left, bottomMiddleStripRect.top, bottomMiddleStripRect.Width(), bottomMiddleStripRect.Height());
		}

		//traypopup dialog's left strip
		pWnd = m_parentWnd ->GetDlgItem(m_leftStripID);
		if(pWnd)
		{
			pWnd ->GetClientRect(&leftStripRect);
			m_parentWnd ->ScreenToClient(&leftStripRect);
			pWnd ->MoveWindow(parentRect.left, parentRect.top + titleRect.Height(), leftStripRect.Width(), parentRect.bottom);
		}

		//vishal
		//traypopup dialog's right strip
		pWnd = m_parentWnd ->GetDlgItem(m_rightStripID);
		if(pWnd)
		{
			pWnd ->GetClientRect(&rightStripRect);
			m_parentWnd ->ScreenToClient(&rightStripRect);
			pWnd ->MoveWindow(parentRect.right - rightStripRect.Width() - 3, parentRect.top + titleRect.Height(), rightStripRect.Width(), parentRect.bottom);
		}
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CSpyDetectDlgBitmaps::OnSize"));
	}

}//OnSize

/*-------------------------------------------------------------------------------------
Function		: DoGradientFill
In Parameters	: pDC	- CDC required for drqwing
Out Parameters	: -
Purpose			: Paints the dialog background
Author			: Zuber
: changed by vishal
--------------------------------------------------------------------------------------*/
void CSpyDetectDlgBitmaps::DoGradientFill(CDC * pDC, BOOL bEraseCenter)
{
	try
	{
		CString csVal;

		CProductInfo oProductInfo;
		ENUM_PRODUCT_TYPE eProductType = oProductInfo.GetProductType();
		CString csIniPath =  oProductInfo.GetProductAppFolderPath(eProductType) + SETTING_FOLDER + CURRENT_SETTINGS_INI;
		TITLE_COLOR_RGB = GetPrivateProfileInt(_T("colorcode"), _T("UI_BORDER"), 8991770, csIniPath);
		BLUEBACKGROUND_RGB = GetPrivateProfileInt(_T("colorcode"), _T("BLUEBACKGROUND"), BLUEBACKGROUND, csIniPath);
		INNER_UI_BORDER_RGB = GetPrivateProfileInt(_T("colorcode"), _T("INNER_UI_BORDER"), 0, csIniPath);
		UI_MIDDLE_BG_RGB = GetPrivateProfileInt(_T("colorcode"), _T("UI_MIDDLE_BG"), 16777215, csIniPath);
		int i;
		for (i = 0; i < 8; i++)
		{
			csVal.Format(_T("StripColor[%d]"), i);

			StripColor[i] = GetPrivateProfileInt(_T("colorcode"), csVal, DefaultStripColor[i], csIniPath);
		}
		// Use the provided border images to draw the border
		if(m_leftStripID > 0 && m_rightStripID > 0 && m_leftBottomCornerID > 0 && m_bottomMiddleStripID > 0 && m_rightBottomCornerID > 0)
		{
			// using images to draw the border! noting to do here!
		}
		else
		{
			CRect parentRect;
			//Get the parent dialog rect.
			m_parentWnd->GetClientRect(&parentRect);

			if(TRUE == bEraseCenter)	// Paints the whole dialog with the given background color
			{
				pDC->FillSolidRect(&parentRect, BLUEBACKGROUND_RGB);
			}
			else	// Draw 15 PIXEL border with the background color around the Dialog
			{
				CRect rcTemp = parentRect;
				//	Left Strip
				rcTemp.left = 0;
				rcTemp.right = 15;
				pDC ->FillSolidRect(&rcTemp, BLUEBACKGROUND_RGB);

				//	Right Strip
				rcTemp = parentRect;
				rcTemp.left = rcTemp.right - 16;
				pDC ->FillSolidRect(&rcTemp, BLUEBACKGROUND_RGB);

				//	Bottom Strip
				rcTemp = parentRect;
				rcTemp.top = parentRect.bottom - 15;
				pDC ->FillSolidRect(&rcTemp, BLUEBACKGROUND_RGB);
			}

			int nWidth = parentRect.Width();
			int nHeight = parentRect.Height();


			//draw top strip
			drawHorizontalStrip(pDC, 0, 1, nWidth, 8, true);

			//draw left strip
			drawVerticalStrip(pDC, 1, 0, 8, nHeight, false);

			//draw right strip
			drawVerticalStrip(pDC, nWidth - 12, 0, nWidth - 5, nHeight, true);

			//draw bottom strip
			drawHorizontalStrip(pDC, 0, nHeight - 12, nWidth, nHeight - 4, false);


			// Finally Draw ONE Pixel Dark Border around the Dialog!

			CRect rectangle;
			//top line
			rectangle.SetRect(0, 0, nWidth, 1);
			pDC->FillSolidRect(&rectangle, TITLE_COLOR_RGB);

			//left line
			rectangle.SetRect(0, 0, 1, nHeight);
			pDC->FillSolidRect(&rectangle, TITLE_COLOR_RGB);

			//right line
			rectangle.SetRect(nWidth - 3, 0, nWidth - 4, nHeight);
			pDC->FillSolidRect(&rectangle, TITLE_COLOR_RGB);

			//bottom line
			rectangle.SetRect(0, nHeight - 4, nWidth, nHeight - 3);
			pDC->FillSolidRect(&rectangle, TITLE_COLOR_RGB);

		}
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CSpyDetectDlgBitmaps::DoGradientFill"));
	}
}//DoGradientFill

void CSpyDetectDlgBitmaps::DrawInnerBorder(CDC * pDC, BOOL bEraseCenter)
{
    // top border line
	CRect oRcDlgRect,oRcDlgRect1;
	m_parentWnd->GetClientRect(&oRcDlgRect1);
	oRcDlgRect.left = oRcDlgRect1.left + 5 ;
	oRcDlgRect.right = oRcDlgRect1.right - 5;
	oRcDlgRect.top = oRcDlgRect1.top;
	oRcDlgRect.bottom = oRcDlgRect1.top + 1;
	pDC->FillSolidRect(&oRcDlgRect, TITLE_COLOR_RGB);

	//bottom border line
	oRcDlgRect.top = oRcDlgRect1.bottom;
	oRcDlgRect.bottom = oRcDlgRect1.bottom - 1;
	pDC->FillSolidRect(&oRcDlgRect, TITLE_COLOR_RGB);

	//left border line
	oRcDlgRect.left = oRcDlgRect1.left + 5 ;
	oRcDlgRect.right = oRcDlgRect1.left + 6;
	oRcDlgRect.top = oRcDlgRect1.top;
	oRcDlgRect.bottom = oRcDlgRect1.bottom ;
	pDC->FillSolidRect(&oRcDlgRect, TITLE_COLOR_RGB);

	// right border line
	oRcDlgRect.left = oRcDlgRect1.right - 5 ;
	oRcDlgRect.right = oRcDlgRect1.right - 6;
	pDC->FillSolidRect(&oRcDlgRect, TITLE_COLOR_RGB);
}


void CSpyDetectDlgBitmaps::DoGradientFillNew(CDC * pDC, BOOL bEraseCenter, BOOL bTray)
{
	try
	{
		// Use the provided border images to draw the border
		if(m_leftStripID > 0 && m_rightStripID > 0 && m_leftBottomCornerID > 0 && m_bottomMiddleStripID > 0 && m_rightBottomCornerID > 0)
		{
			// using images to draw the border! noting to do here!
		}
		else
		{
			CRect parentRect;
			//Get the parent dialog rect.
			m_parentWnd->GetClientRect(&parentRect);

			if(TRUE == bEraseCenter)	// Paints the whole dialog with the given background color
			{
				pDC->FillSolidRect(&parentRect, BLUEBACKGROUND_RGB);
			}
			else	// Draw 15 PIXEL border with the background color around the Dialog
			{
				CRect rcTemp = parentRect;
				//	Left Strip
				rcTemp.left = 0;
				rcTemp.right = 15;
				pDC ->FillSolidRect(&rcTemp, BLUEBACKGROUND_RGB);

				//	Right Strip
				rcTemp = parentRect;
				rcTemp.left = rcTemp.right - 16;
				pDC ->FillSolidRect(&rcTemp, BLUEBACKGROUND_RGB);

				//	Bottom Strip
				rcTemp = parentRect;
				rcTemp.top = parentRect.bottom - 15;
				pDC ->FillSolidRect(&rcTemp, BLUEBACKGROUND_RGB);
			}

			int nWidth = parentRect.Width();
			int nHeight = parentRect.Height();
			if(m_iBigUIBorder != 1)
			{
				// NOW Gradient Fill 8 lines of border around the dialog for a 3D Look!
				{
					//draw top strip
					drawHorizontalStrip(pDC, 0, 1, nWidth, 8, true);

					//draw left strip
					drawVerticalStrip(pDC, 1, 0, 8, nHeight, false);

					//draw right strip
					drawVerticalStrip(pDC, nWidth-12, 0, nWidth-5, nHeight, true);

					//draw bottom strip
					drawHorizontalStrip(pDC, 0, nHeight - 12, nWidth, nHeight-4, false);
				}

				// Finally Draw ONE Pixel Dark Border around the Dialog!
				if(bTray)
				{
					CRect rectangle;
					//top line
					rectangle.SetRect(0, 0, nWidth, 1);
					pDC ->FillSolidRect(&rectangle, BLUEBACKGROUND_RGB);

					//left line
					rectangle.SetRect(0, 0, 1, nHeight);
					pDC ->FillSolidRect(&rectangle, BLUEBACKGROUND_RGB);

					//right line
					rectangle.SetRect(nWidth - 3, 0, nWidth - 4, nHeight);
					pDC ->FillSolidRect(&rectangle, BLUEBACKGROUND_RGB);

					//bottom line
					rectangle.SetRect(0, nHeight-4, nWidth, nHeight-3);
					pDC ->FillSolidRect(&rectangle, BLUEBACKGROUND_RGB);
				}
				else
				{
					CRect rectangle;
					//top line
					rectangle.SetRect(0, 0, nWidth, 3);
					pDC ->FillSolidRect(&rectangle, BLUEBACKGROUND_RGB);

					//left line
					rectangle.SetRect(0, 0, 3, nHeight);
					pDC ->FillSolidRect(&rectangle, BLUEBACKGROUND_RGB);

					//right line
					rectangle.SetRect(nWidth - 3, 0, nWidth, nHeight);
					pDC ->FillSolidRect(&rectangle, BLUEBACKGROUND_RGB);

					//bottom line
					rectangle.SetRect(0, nHeight- 4, nWidth, nHeight);
					pDC ->FillSolidRect(&rectangle, BLUEBACKGROUND_RGB);
				}
			}
			else
			{
				if(bTray)
				{
					CRect rectangle;
					//top line
					rectangle.SetRect(0, 0, nWidth, 1);
					pDC ->FillSolidRect(&rectangle, BLUEBACKGROUND_RGB);

					//left line
					rectangle.SetRect(0, 0, 1, nHeight);
					pDC ->FillSolidRect(&rectangle, BLUEBACKGROUND_RGB);

					//right line
					rectangle.SetRect(nWidth - 3, 0, nWidth - 4, nHeight);
					pDC ->FillSolidRect(&rectangle, BLUEBACKGROUND_RGB);

					//bottom line
					rectangle.SetRect(0, nHeight-4, nWidth, nHeight-3);
					pDC ->FillSolidRect(&rectangle, BLUEBACKGROUND_RGB);
				}
				else
				{
					CRect rectangle;
					//top line
					rectangle.SetRect(0, 0, nWidth, 1);
					pDC ->FillSolidRect(&rectangle, BLUEBACKGROUND_RGB);

					//left line
					rectangle.SetRect(0, 0, 1, nHeight);
					pDC ->FillSolidRect(&rectangle, BLUEBACKGROUND_RGB);

					//right line
					rectangle.SetRect(nWidth - 1, 0, nWidth, nHeight);
					pDC ->FillSolidRect(&rectangle, BLUEBACKGROUND_RGB);

					//bottom line
					rectangle.SetRect(0, nHeight- 1, nWidth, nHeight);
					pDC ->FillSolidRect(&rectangle, BLUEBACKGROUND_RGB);
				}
			}
		}
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CSpyDetectDlgBitmaps::DoGradientFill"));
	}
}//DoGradientFill


/*-------------------------------------------------------------------------------------
Function		: ManageDialogSize
In Parameters	: -
Out Parameters	: -
Purpose			: Fits the dialog in the desktop on maximize.
If the dialog does not have a title bar of its own, it covers the
full desktop (along with the taskbar).This function displays the
dialog excluding the taskbar size.
Even if the taskbar is hidden the dialog does not cover the desktop.
It leaves the taskbar size.
Author			: Zuber
--------------------------------------------------------------------------------------*/
void CSpyDetectDlgBitmaps::ManageDialogSize()
{
	try
	{
		CWnd * cWnd = m_parentWnd ->GetDesktopWindow();
		cWnd ->GetWindowRect(&m_DesktopRect);

		if(m_parentWnd ->IsZoomed())
		{
			APPBARDATA abd ={0 };
			abd.hWnd = ::FindWindow(_T("Shell_TrayWnd"), NULL);
			if(!abd.hWnd)
			{
				return;
			}

			CRect DesktopRect;
			::SystemParametersInfo(SPI_GETWORKAREA, 0, &DesktopRect, 0);
			if(DesktopRect.Height() !=::GetSystemMetrics(SM_CYSCREEN))
			{
				if(DesktopRect.top)//Taskbar is at Top
				{
					abd.uEdge = ABE_TOP;

				}
				else//Taskbar is at Bottom
				{
					abd.uEdge = ABE_BOTTOM;
				}
			}
			else//Taskbar is vertical
			{
				if(DesktopRect.left)//Taskbar is on the Left
				{
					abd.uEdge = ABE_LEFT;
				}
				else//Taskbar is on the Right
				{
					abd.uEdge = ABE_RIGHT;
				}
			}

			abd.cbSize = sizeof(APPBARDATA);
			SHAppBarMessage(ABM_GETTASKBARPOS, &abd);

			CRect systrayRect;
			systrayRect = abd.rc;

			int x = m_DesktopRect.left;
			int y = m_DesktopRect.top;
			int cx = m_DesktopRect.right;
			int cy = m_DesktopRect.bottom;
			switch(abd.uEdge)
			{
			case ABE_LEFT:
				x += (m_DesktopRect.Width() - DesktopRect.Width())/*systrayRect.Width()*/;
				cx -= (m_DesktopRect.Width() - DesktopRect.Width());
				break;

			case ABE_TOP:
				y += (m_DesktopRect.Height() - DesktopRect.Height());
				cy -= (m_DesktopRect.Height() - DesktopRect.Height());
				break;

			case ABE_RIGHT:
				cx -= (m_DesktopRect.Width() - DesktopRect.Width());
				break;

			case ABE_BOTTOM:
				cy -= (m_DesktopRect.Height() - DesktopRect.Height());
				break;
			}

			m_parentWnd ->MoveWindow(x, y, cx + 4, cy);
			CPoint ptTopLeft,ptRightBottom;
			ptTopLeft.SetPoint(x,y);
			ptRightBottom.SetPoint(x + cx + 4,y + cy);
			m_rcAfterManagingDialog.SetRect(ptTopLeft,ptRightBottom);
		}
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CSpyDetectDlgBitmaps::ManageDialogSize"));
	}
}//ManageDialogSize

/*-------------------------------------------------------------------------------------
Function		: OnPropertySheetSize
In Parameters	: pDC	- CDC pointer for drawing.
: titleImg	  - Object for the title image on the property sheet.
: titlebarImg - Pointer for the titlebar image on the property sheet.
: monogramImg - Pointer for the monogram image on the property sheet.
: whiteImg	  - Pointer for the white image on the property sheet.
: bitsImg	  - Pointer for the bits image on the property sheet.
Out Parameters	: -
Purpose			: Resizes the bitmaps according to the property sheet size if necessary
Author			: Zuber
--------------------------------------------------------------------------------------*/
void CSpyDetectDlgBitmaps::OnPropertySheetSize(CDC * pDC,
											   CPictureHolder* titleImg,
											   CPictureHolder* titlebarImg,
											   CPictureHolder* monogramImg,
											   CPictureHolder* whiteImg,
											   CPictureHolder* bitsImg,
											   CPictureHolder* titlebarRightCornerImg,
											   CPictureHolder* cornerLeftBottomImg,
											   CPictureHolder* cornerRightBottomImg)
{
	try
	{
		if((titleImg == NULL) ||(titlebarImg == NULL) ||(monogramImg == NULL) ||
			(whiteImg == NULL) ||(bitsImg == NULL) ||(titlebarRightCornerImg == NULL) ||
			(cornerLeftBottomImg == NULL) ||(cornerRightBottomImg == NULL))
		{
			return;
		}

		CRect rcSheetRect;
		CRect rcRender, rcWBounds;
		CBitmap bitmap;
		BITMAP bm;
		int titleRight, titleBottom, monogramBottom, monogramRight, bitsLeft, bitsRight;

		m_parentWnd ->GetClientRect(&rcSheetRect);

		//draw title image
		bitmap.LoadBitmap(m_titleImageID);
		bitmap.GetBitmap(&bm);
		bitmap.DeleteObject();
		rcWBounds.left = rcRender.left = 0;
		rcWBounds.top = rcRender.top = 0;
		titleRight = rcWBounds.right = rcRender.right = bm.bmWidth;
		titleBottom = rcWBounds.bottom = rcRender.bottom = bm.bmHeight;
		titleImg ->Render(pDC, rcRender, rcWBounds);

		//draw titlebar image
		bitmap.LoadBitmap(m_titlebarImageID);
		bitmap.GetBitmap(&bm);
		bitmap.DeleteObject();
		rcWBounds.left = rcRender.left = titleRight;
		rcWBounds.top = rcRender.top = 0;
		rcWBounds.right = rcRender.right = titleRight + rcSheetRect.Width();
		rcWBounds.bottom = rcRender.bottom = titleBottom;
		titlebarImg ->Render(pDC, rcRender, rcWBounds);

		//draw monogram image
		bitmap.LoadBitmap(m_monogramImageID);
		bitmap.GetBitmap(&bm);
		bitmap.DeleteObject();
		rcWBounds.left = rcRender.left = 0;
		rcWBounds.top = rcRender.top = titleBottom;
		monogramRight = rcWBounds.right = rcRender.right = bm.bmWidth;
		monogramBottom = rcWBounds.bottom = rcRender.bottom = titleBottom + bm.bmHeight;
		monogramImg ->Render(pDC, rcRender, rcWBounds);

		//draw bits image
		bitmap.LoadBitmap(m_bitsImageID);
		bitmap.GetBitmap(&bm);
		bitmap.DeleteObject();
		bitsLeft = rcWBounds.left = rcRender.left = rcSheetRect.Width() - bm.bmWidth;
		rcWBounds.top = rcRender.top = titleBottom;
		bitsRight = rcWBounds.right = rcRender.right = rcSheetRect.Width() -3;
		rcWBounds.bottom = rcRender.bottom = monogramBottom;
		bitsImg ->Render(pDC, rcRender, rcWBounds);

		//draw white image
		bitmap.LoadBitmap(m_whiteImageID);
		bitmap.GetBitmap(&bm);
		bitmap.DeleteObject();
		rcWBounds.left = rcRender.left = monogramRight;
		rcWBounds.top = rcRender.top = titleBottom;
		rcWBounds.right = rcRender.right = bitsLeft;
		rcWBounds.bottom = rcRender.bottom = monogramBottom;
		whiteImg ->Render(pDC, rcRender, rcWBounds);

		//draw titlebar right corner image
		bitmap.LoadBitmap(m_titlebarRightCornerID);
		bitmap.GetBitmap(&bm);
		bitmap.DeleteObject();
		rcWBounds.left = rcRender.left = bitsRight - 6;
		rcWBounds.top = rcRender.top = 0;
		rcWBounds.right = rcRender.right = (bitsRight - 6) + bm.bmWidth;
		rcWBounds.bottom = rcRender.bottom = bm.bmHeight;
		titlebarRightCornerImg ->Render(pDC, rcRender, rcWBounds);

		//draw dialogs left bottom corner image
		bitmap.LoadBitmap(m_leftBottomCornerID);
		bitmap.GetBitmap(&bm);
		bitmap.DeleteObject();
		rcWBounds.left = rcRender.left = rcSheetRect.left;
		rcWBounds.top = rcRender.top = rcSheetRect.bottom - 15;
		rcWBounds.right = rcRender.right = bm.bmWidth;
		rcWBounds.bottom = rcRender.bottom = (rcSheetRect.bottom - 15) + bm.bmHeight;
		cornerLeftBottomImg ->Render(pDC, rcRender, rcWBounds);

		//draw dialogs right bottom corner image
		bitmap.LoadBitmap(m_rightBottomCornerID);
		bitmap.GetBitmap(&bm);
		bitmap.DeleteObject();
		rcWBounds.left = rcRender.left = bitsRight - 12;
		rcWBounds.top = rcRender.top = rcSheetRect.bottom - 15;
		rcWBounds.right = rcRender.right = (bitsRight - 12) + bm.bmWidth;
		rcWBounds.bottom = rcRender.bottom = (rcSheetRect.bottom - 15) + bm.bmHeight;
		cornerRightBottomImg ->Render(pDC, rcRender, rcWBounds);
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CSpyDetectDlgBitmaps::OnPropertySheetSize"));
	}

}//OnPropertySheetSize


/*-------------------------------------------------------------------------------------
Function		: drawHorizontalStrip
In Parameters	: pDC	- CDC pointer for drawing.
left - x coords
top - y coords
right - x1 coords
bottom - y1 coords
Out Parameters	: -
Purpose			: to draw the bottom as well as top strip
Author			: Vishal Bochkari
--------------------------------------------------------------------------------------*/
void CSpyDetectDlgBitmaps::drawHorizontalStrip(CDC *pDC, int left, int top, int right, int bottom,bool flag)
{
	try
	{
		int i, UpCnt = 0,DownCnt = 7;
		CRect rectangle;

		for(i = top; i <= bottom; ++i)
		{
			rectangle.SetRect(left, i, right, i + 1);
			if(flag)
				pDC ->FillSolidRect(&rectangle, StripColor[DownCnt--]);
			else
				pDC ->FillSolidRect(&rectangle, StripColor[UpCnt++]);
		}

	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CSpyDetectDlgBitmaps::drawHorizontalStrip"));
	}
}

/*-------------------------------------------------------------------------------------
Function		: drawVerticalStrip
In Parameters	: pDC	- CDC pointer for drawing.
left - x coords
top - y coords
right - x1 coords
bottom - y1 coords
Out Parameters	: -
Purpose			: to draw the left as well as right strip
Author			: Vishal Bochkari
--------------------------------------------------------------------------------------*/
void CSpyDetectDlgBitmaps::drawVerticalStrip(CDC *pDC, int left, int top, int right, int bottom, bool flag)
{
	try
	{
		int i, UpCnt = 0,DownCnt = 7;
		CRect rectangle;

		for(i = left; i <= right; i++)
		{
			rectangle.SetRect(i, top, i+1, bottom);
			if(flag)
				pDC ->FillSolidRect(&rectangle, StripColor[UpCnt++]);
			else
				pDC ->FillSolidRect(&rectangle, StripColor[DownCnt--]);
		}
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CSpyDetectDlgBitmaps::drawVerticalStrip"));
	}
}

bool CSpyDetectDlgBitmaps::LoadStringFromTable(HINSTANCE hInstance,int iCurrentLunguage,UINT IDS,CString * csBuffer)
{
	try
	{
		int uID;
		uID = iCurrentLunguage + IDS;
		int iRet = LoadString(hInstance,uID,csBuffer->GetBuffer(1024),1024);
		csBuffer->ReleaseBuffer ();
		if(iRet > 0)
			return true;
		else
			return false;

	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CSpyDetectDlgBitmaps::LoadStringFromTable"));
	}
	return false;
}

CRect CSpyDetectDlgBitmaps::GetSizeAfterManagingDialog()
{
	return m_rcAfterManagingDialog;
}
/*-------------------------------------------------------------------------------------
Function		: DrawRectangle.
In Parameters	: 
Out Parameters	: CDC * pDC, int left, int top, int right, int bottom
Purpose			: To draw the rectangle with white background in main dialog
Author			: Tejas Kurhade
--------------------------------------------------------------------------------------*/
void CSpyDetectDlgBitmaps::DrawRectangle(CDC * pDC, CRect oRcDlgRect, int LeftTopImageID, int RightTopImageID, int LeftBottomImageID, int RightBottomImageID)
{
	int left = oRcDlgRect.left + 15;
	int top = oRcDlgRect.top + 41;
	int right = oRcDlgRect.right - 18;
	int bottom = oRcDlgRect.bottom - 18;

	CRect oRcRectangle;
	CRect LeftTopRect, RightTopRect, LeftBottomRect, RightBottomRect;
	int i = 0;
	CWnd * pWnd;

	pWnd = m_parentWnd ->GetDlgItem(LeftTopImageID);
	if(pWnd)
	{
		pWnd ->GetClientRect(&LeftTopRect);
		m_parentWnd ->ScreenToClient(&LeftTopRect);
		pWnd ->MoveWindow(left, top, LeftTopRect.Width(), LeftTopRect.Height());
	}

	pWnd = m_parentWnd ->GetDlgItem(RightTopImageID);
	if(pWnd)
	{
		pWnd ->GetClientRect(&RightTopRect);
		m_parentWnd ->ScreenToClient(&RightTopRect);
		pWnd ->MoveWindow(right - RightTopRect.Width(), top, RightTopRect.Width(), RightTopRect.Height());
	}

	pWnd = m_parentWnd ->GetDlgItem(LeftBottomImageID);
	if(pWnd)
	{
		pWnd ->GetClientRect(&LeftBottomRect);
		m_parentWnd ->ScreenToClient(&LeftBottomRect);
		pWnd ->MoveWindow(left, bottom - LeftBottomRect.Height() + 1, LeftBottomRect.Width(), LeftBottomRect.Height());
	}

	pWnd = m_parentWnd ->GetDlgItem(RightBottomImageID);
	if(pWnd)
	{
		pWnd ->GetClientRect(&RightBottomRect);
		m_parentWnd ->ScreenToClient(&RightBottomRect);
		pWnd ->MoveWindow(right - RightBottomRect.Width(), bottom - RightBottomRect.Height() + 1, RightBottomRect.Width(), RightBottomRect.Height());
	}

	
	// Fill inner background with signle color
	CRect rectangle;
	rectangle.SetRect(left + 1, top + 1, right - 1, bottom);
	pDC->FillSolidRect(&rectangle, UI_MIDDLE_BG_RGB);


	// Draw one pixel inner border
	
	// Top line
	rectangle.SetRect(left, top, right, top + 1);
	pDC->FillSolidRect(&rectangle, INNER_UI_BORDER_RGB);

	// Left Line
	rectangle.SetRect(left, top, left + 1, bottom);
	pDC->FillSolidRect(&rectangle, INNER_UI_BORDER_RGB);

	// Right Line
	rectangle.SetRect(right - 1, top, right, bottom);
	pDC->FillSolidRect(&rectangle, INNER_UI_BORDER_RGB);

	// Bottom Line
	rectangle.SetRect(left, bottom, right, bottom + 1);
	pDC->FillSolidRect(&rectangle, INNER_UI_BORDER_RGB);

}
void CSpyDetectDlgBitmaps::DoGradientFillDM(CDC *pDC, BOOL bEraseCenter)
{
	try
	{
		// Use the provided border images to draw the border
		if(m_leftStripID > 0 && m_rightStripID > 0 && m_leftBottomCornerID > 0 && m_bottomMiddleStripID > 0 && m_rightBottomCornerID > 0)
		{
			// using images to draw the border! noting to do here!
		}
		else
		{
			CRect parentRect;
			//Get the parent dialog rect.
			m_parentWnd->GetClientRect(&parentRect);

			if(TRUE == bEraseCenter)	// Paints the whole dialog with the given background color
			{
				pDC->FillSolidRect(&parentRect, RGB(255,255,255));
			}
			else	// Draw 15 PIXEL border with the background color around the Dialog
			{
				CRect rcTemp = parentRect;
				//	Left Strip
				rcTemp.left = 0;
				rcTemp.right = 15;
			//	pDC ->FillSolidRect(&rcTemp, RGB(148,171,241));

				//	Right Strip
				rcTemp = parentRect;
				rcTemp.left = rcTemp.right - 16;
			//	pDC ->FillSolidRect(&rcTemp, RGB(148,171,241));

				//	Bottom Strip
				rcTemp = parentRect;
				rcTemp.top = parentRect.bottom - 15;
			//	pDC ->FillSolidRect(&rcTemp, RGB(148,171,241));
			}

			int nWidth = parentRect.Width();
			int nHeight = parentRect.Height();

			// NOW Gradient Fill 8 lines of border around the dialog for a 3D Look!
			{
				//draw top strip
			//	drawHorizontalStrip(pDC, 0, 1, nWidth, 8, true);

				//draw left strip
			//	drawVerticalStrip(pDC, 1, 0, 8, nHeight, false);

				//draw right strip
			//	drawVerticalStrip(pDC, nWidth-12, 0, nWidth-5, nHeight, true);

				//draw bottom strip
			//	drawHorizontalStrip(pDC, 0, nHeight - 12, nWidth, nHeight-4, false);
			}

			// Finally Draw ONE Pixel Dark Border around the Dialog!
			{
				CRect rectangle;
				//top line
				
				rectangle.SetRect(0, 0, nWidth, 50);
				pDC ->FillSolidRect(&rectangle, RGB(156, 7, 7));

				//left line
				rectangle.SetRect(0, 0, 2, nHeight);
				pDC ->FillSolidRect(&rectangle, RGB(156, 7, 7));

				//right line
				rectangle.SetRect(nWidth - 2, 0, nWidth, nHeight);
				pDC ->FillSolidRect(&rectangle, RGB(156, 7, 7));

				//bottom line
				rectangle.SetRect(0, nHeight- 2, nWidth, nHeight);
				pDC ->FillSolidRect(&rectangle, RGB(156, 7, 7));
			
			}
		}
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CSpyDetectDlgBitmaps::DoGradientFillNew"));
	}
}
