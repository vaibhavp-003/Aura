// SpyDetectDlgBitmaps.h: header file of the CSpyDetectDlgBitmaps class.
//
//////////////////////////////////////////////////////////////////////

#ifndef SPY_DETECT_DIALOG_BITMAPS_H
#define SPY_DETECT_DIALOG_BITMAPS_H

#if _MSC_VER > 1000
#pragma once
#endif //_MSC_VER > 1000

#include <afxctl.h>

class CSpyDetectDlgBitmaps
{
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
		CRect m_DesktopRect;			//Co-ordinates of desktop
		void drawHorizontalStrip( CDC *pDC, int left, int top, int right, int bottom,bool flag );
		void drawVerticalStrip( CDC *pDC, int left, int top, int right, int bottom, bool flag );


	public:
		CSpyDetectDlgBitmaps( CWnd * pWnd , 
								int titleImageID = -1,
								int titlebarImageID = -1,
								int monogramImageID = -1,
                                int whiteImageID = -1,
								int bitsImageID =-1,
								int titlebarRightCornerID = -1,
								int leftBottomCornerID = -1,
								int rightBottomCornerID = -1,
								int leftStripID = -1,
								int rightStripID = -1); // last 2 param used only for tray popup

		~CSpyDetectDlgBitmaps( );

		void SetParentWnd( CWnd * pWnd );	//Sets the dialog handle
		void OnSize( );						//Resizes the bitmaps according to the dialog size if necessary
		void DoGradientFill( CDC * pDC, BOOL bEraseCenter = TRUE );	//Paints the dialog background
		void ManageDialogSize( );			//Resizes the dialog based on taskbar size.

		//Resizes the bitmaps according to the Property sheet size if necessary
		void OnPropertySheetSize( CDC * pDC,
								CPictureHolder* titleImg,
								CPictureHolder* titlebarImg,
								CPictureHolder* monogramImg,
								CPictureHolder* whiteImg,
								CPictureHolder* bitsImg,
								CPictureHolder* titlebarRightCornerImg,
								CPictureHolder* cornerLeftBottomImg,
								CPictureHolder* cornerRightBottomImg);
		CFont m_fontButton;
		CFont m_fontWindowTitle;
		CFont m_fontInfoText;

		COLORREF StripColor[8];
		COLORREF TITLE_COLOR_RGB;
		COLORREF BLUEBACKGROUND_RGB;
		COLORREF INNER_UI_BORDER_RGB;
		COLORREF UI_MIDDLE_BG_RGB;
		COLORREF BACKGROUND_RGB;
		bool LoadStringFromTable(HINSTANCE hInstance,int iCurrentLunguage,UINT IDS,CString * csBuffer);
		void DrawRectangle(CDC * pDC, CRect oRcDlgRect, int LeftTopImageID, int RightTopImageID, int LeftBottomImageID, int RightBottomImageID);
};

#endif //SPY_DETECT_DIALOG_BITMAPS_H
