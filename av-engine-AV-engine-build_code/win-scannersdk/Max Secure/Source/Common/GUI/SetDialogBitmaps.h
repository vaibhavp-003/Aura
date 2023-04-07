/*=============================================================================
   FILE			: SetDialogBitmaps.h
   ABSTRACT		: 
   DOCUMENTS	: 
   AUTHOR		:
   COMPANY		: Aura 
COPYRIGHT NOTICE:
				(C) Aura
				Created as an unpublished copyright work.  All rights reserved.
				This document and the information it contains is confidential and
				proprietary to Aura.  Hence, it may not be 
				used, copied, reproduced, transmitted, or stored in any form or by any 
				means, electronic, recording, photocopying, mechanical or otherwise, 
				with out the prior written permission of Aura
CREATION DATE   : 12/01/2007
   NOTES		:
VERSION HISTORY	:
				
============================================================================*/

#ifndef SPY_DETECT_DIALOG_BITMAPS_H
#define SPY_DETECT_DIALOG_BITMAPS_H

#if _MSC_VER > 1000
#pragma once
#endif //_MSC_VER > 1000

#include <afxctl.h>

class CSpyDetectDlgBitmaps
{
public:
	CSpyDetectDlgBitmaps(CWnd * pWnd,
		int titleImageID = -1,
		int titlebarImageID = -1,
		int monogramImageID = -1,
		int whiteImageID = -1,
		int bitsImageID =-1,
		int titlebarRightCornerID = -1,
		int leftBottomCornerID = -1,
		int rightBottomCornerID = -1,
		int leftStripID = -1,
		int rightStripID = -1,
		int bottomMiddleStripID = -1);
	~CSpyDetectDlgBitmaps();

	void SetParentWnd(CWnd * pWnd);	//Sets the dialog handle
	void OnSize();						//Resizes the bitmaps according to the dialog size if necessary
	void DoGradientFill(CDC * pDC,BOOL bEraseCenter = TRUE);	//Paints the dialog background
	//void DoGradientFillNew(CDC * pDC,BOOL bEraseCenter = TRUE);	//Paints the dialog background
	void DoGradientFillNew(CDC * pDC,BOOL bEraseCenter = TRUE, BOOL bTray = FALSE);	//Paints the dialog background
	void DoGradientFillDM(CDC * pDC,BOOL bEraseCenter = TRUE);	//Paints the dialog background 
	void DrawInnerBorder(CDC * pDC,BOOL bEraseCenter = TRUE);	//Paints the dialog background
	void ManageDialogSize();			//Resizes the dialog based on taskbar size.
	

	//Resizes the bitmaps according to the Property sheet size if necessary
	void OnPropertySheetSize(CDC * pDC,
		CPictureHolder* titleImg,
		CPictureHolder* titlebarImg,
		CPictureHolder* monogramImg,
		CPictureHolder* whiteImg,
		CPictureHolder* bitsImg,
		CPictureHolder* titlebarRightCornerImg,
		CPictureHolder* cornerLeftBottomImg,
		CPictureHolder* cornerRightBottomImg);

	void drawHorizontalStrip(CDC *pDC, int left, int top, int right, int bottom,bool flag);
	void drawVerticalStrip(CDC *pDC, int left, int top, int right, int bottom, bool flag);
	void DrawRectangle(CDC * pDC, CRect oRcDlgRect, int LeftTopImageID, int RightTopImageID, int LeftBottomImageID, int RightBottomImageID);

	CFont m_fontWindowTitle,m_fontButton;
	CFont m_fontInfoText;
	static DWORD m_dwDPIValue;
	COLORREF StripColor[8];
	COLORREF DefaultStripColor[8];
	COLORREF TITLE_COLOR_RGB;
	COLORREF BLUEBACKGROUND_RGB;
	COLORREF INNER_UI_BORDER_RGB;
	COLORREF UI_MIDDLE_BG_RGB;
	bool LoadStringFromTable(HINSTANCE hInstance,int iCurrentLunguage,UINT IDS,CString * csBuffer);
	CRect GetSizeAfterManagingDialog();
	CRect m_rcAfterManagingDialog;
private:
	CWnd * m_parentWnd;				//Handle of the dialog
	int m_titleImageID;				//Image ID of the title 
	int m_titlebarImageID;			//Image ID of the title bar
	int m_monogramImageID;			//Image ID of the monogram
	int m_whiteImageID;				//Image ID of the white patch
	int m_bitsImageID;				//Image ID of the bits (under the "help" button)
	int m_titlebarRightCornerID;	//Image ID of the right corner of titlebar
	int m_leftBottomCornerID;		//Image ID of left bottom corner of dialog
	int m_rightBottomCornerID;		//Image ID of right bottom corner of dialog
	int m_leftStripID;				//Image ID of left strip
	int m_rightStripID;				//Image ID of right strip
	int m_bottomMiddleStripID;		//Image ID of bottom middle strip which will be strected
	CRect m_DesktopRect;			//Co-ordinates of desktop

	int m_iBigUIBorder;

	
};

#endif //SPY_DETECT_DIALOG_BITMAPS_H
