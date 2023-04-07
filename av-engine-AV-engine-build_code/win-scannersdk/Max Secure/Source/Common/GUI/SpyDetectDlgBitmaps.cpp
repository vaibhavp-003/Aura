/*======================================================================================
   FILE			: SpyDetectDlgBitmaps.cpp
   ABSTRACT		: Class to manage the common bitmaps of a dialog.
   DOCUMENTS	: 
   AUTHOR		: Zuber
   COMPANY		: Aura 
   CREATION DATE: 12/01/2007
   NOTE			:
   VERSION HISTORY	:
					Version 1.0
					Resource: Zuber
					Description: New class to manage the common bitmaps of a dialog.
=======================================================================================*/

#include "stdafx.h"
#include "SpyDetectDlgBitmaps.h"
#include "Constants.h"
#include "CPUInfo.h"

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
CSpyDetectDlgBitmaps::CSpyDetectDlgBitmaps( CWnd * pWnd , 
											int titleImageID ,
										    int titlebarImageID , 
											int monogramImageID ,
											int whiteImageID , 
											int bitsImageID, 
											int titlebarRightCornerID,
											int leftBottomCornerID,
											int rightBottomCornerID,
											int leftStripID,
											int rightStripID)
											: m_parentWnd( pWnd ), //dialog's window handle
											  m_titleImageID( titleImageID ), // titlebar left
											  m_titlebarImageID( titlebarImageID ), // titlebar middle 
											  m_monogramImageID( monogramImageID ), // banner left
											  m_whiteImageID( whiteImageID ), // banner middle
											  m_bitsImageID( bitsImageID ), // banner right
											  m_titlebarRightCornerID(titlebarRightCornerID), // titlebar right
											  m_leftBottomCornerID(leftBottomCornerID), //dialog's left bottom corner
											  m_rightBottomCornerID(rightBottomCornerID), //dialog's right bottom corner
											  m_leftStripID(leftStripID),
											  m_rightStripID(rightStripID)
{
	//OutputDebugString("In CSpyDetectDlgBitmaps");
	CWnd * cWnd = m_parentWnd ->GetDesktopWindow( );
	cWnd ->GetWindowRect( &m_DesktopRect );

	LOGFONT	lf;						   // Used to create the CFont.
	memset(&lf,	0, sizeof(LOGFONT));   // Clear	out	structure.
	lf.lfHeight	=12;
	lf.lfWidth = 8;
	lf.lfWeight = FW_BOLD;
	_tcscpy_s(lf.lfFaceName, L"Ms Sans Serif");	 //	   with	face name "Verdana".
	m_fontWindowTitle.CreateFontIndirect(&lf);	   // Create the font.

	LOGFONT	lfInfoText;						   // Used to create the CFont.
	memset(&lfInfoText,	0, sizeof(LOGFONT));   // Clear	out	structure.
	lfInfoText.lfHeight	=8;
	lfInfoText.lfWidth = 6;
	lfInfoText.lfWeight = FW_NORMAL;
	_tcscpy_s(lfInfoText.lfFaceName, L"Ms Sans Serif");	 //	   with	face name "Verdana".
	m_fontInfoText.CreateFontIndirect(&lfInfoText);	   // Create the font.
	
	LOGFONT	lfBtn;						   // Used to create the CFont.
	memset(&lfBtn,	0, sizeof(LOGFONT));   // Clear	out	structure.
	lfBtn.lfHeight	= 8;
	//lfBtn.lfWidth = 10;
	lfBtn.lfWeight = FW_BOLD;
	_tcscpy_s(lfBtn.lfFaceName, L"Ms Sans Serif");	 //	   with	face name "Verdana".
	m_fontButton.CreateFontIndirect(&lfBtn);	   // Create the font.

	StripColor[0] = RGB( 148,171,241);
	StripColor[1] = RGB( 136,159,232);
	StripColor[2] = RGB( 130,154,227);
	StripColor[3] = RGB( 123,147,222);
	StripColor[4] = RGB( 118,142,218);
	StripColor[5] = RGB( 114,138,215);
	StripColor[6] = RGB( 110,134,212);
	StripColor[7] = RGB( 106,130,208);

	CCPUInfo objCpuInfo;
	CString csIniPath = objCpuInfo.GetProdInstallPath() + SETTING_FOLDER + CURRENT_SETTINGS_INI;

	CString csVal;
	int i;
	for(i = 0; i < 8; i++)
	{
		csVal.Format(_T("StripColor[%d]"), i);
		StripColor[i] = GetPrivateProfileInt(_T("colorcode"), csVal, StripColor[i], csIniPath);
	}

	BACKGROUND_RGB	= GetPrivateProfileInt(_T("colorcode"), _T("BACKGROUND"), BACKGROUND, csIniPath);
	TITLE_COLOR_RGB		= GetPrivateProfileInt(_T("colorcode"), _T("UI_BORDER"), 8991770, csIniPath);
	BLUEBACKGROUND_RGB	= GetPrivateProfileInt(_T("colorcode"), _T("BLUEBACKGROUND"), BLUEBACKGROUND, csIniPath);
	INNER_UI_BORDER_RGB	= GetPrivateProfileInt(_T("colorcode"), _T("INNER_UI_BORDER"), 0, csIniPath);
	UI_MIDDLE_BG_RGB	= GetPrivateProfileInt(_T("colorcode"), _T("UI_MIDDLE_BG"), 16777215, csIniPath);

}//CSpyDetectDlgBitmaps

/*-------------------------------------------------------------------------------------
	Function		: ~CSpyDetectDlgBitmaps
	In Parameters	: -
	Out Parameters	: -
	Purpose			: Destructor for class CSpyDetectDlgBitmaps
	Author			: Zuber
--------------------------------------------------------------------------------------*/
CSpyDetectDlgBitmaps::~CSpyDetectDlgBitmaps( )
{
}//~CSpyDetectDlgBitmaps

/*-------------------------------------------------------------------------------------
	Function		: SetParentWnd
	In Parameters	: pWnd	- Handle of the dialog
	Out Parameters	: -
	Purpose			: Sets the dialog handle
	Author			: Zuber
--------------------------------------------------------------------------------------*/
void CSpyDetectDlgBitmaps::SetParentWnd( CWnd * pWnd )
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
void CSpyDetectDlgBitmaps::OnSize( )
{
//	OutputDebugString("In CSpyDetectDlgBitmaps::OnSize( )");
	CWnd * pWnd;
	CRect parentRect;
	CRect titleRect , monogramRect , bitsRect , whiteRect , titleBarRect, titlebarRightCornerRect;
	CRect leftBottomCornerRect, rightBottomCornerRect,leftStripRect,rightStripRect ;
	int iFromRight;

	if(m_leftStripID > 0 )
		iFromRight = 6;
	else
		iFromRight = 9;

#ifdef OUTPUT_DEBUG
	char str[2048] = {0};
//	OutputDebugString( "In CSpyDetectDlgBitmaps::OnSize" );
#endif

	//Get the parent dialog rect.
	m_parentWnd ->GetClientRect( parentRect );

	//Title of dialog
	pWnd = m_parentWnd ->GetDlgItem( m_titleImageID );
	if( pWnd )
	{
		pWnd ->GetClientRect( &titleRect );
		m_parentWnd ->ScreenToClient( &titleRect );
		pWnd ->MoveWindow( 0 , 0 , titleRect .Width( ) , titleRect .Height( ) );
#ifdef OUTPUT_DEBUG
		memset( str , 0 , sizeof( str ) ) ;
		sprintf( str , "TITLE => Left: %d    Top: %d    Right: %d    Bottom: %d" , -1 , -1 , titleRect .Width( ) , titleRect.Height() );
//		OutputDebugString( str );
#endif
	}

	//Portion after title
	pWnd = m_parentWnd ->GetDlgItem( m_titlebarImageID );
	if( pWnd )
	{
		pWnd ->GetClientRect( &titleBarRect );
		m_parentWnd ->ScreenToClient( &titleBarRect );
		//pWnd ->MoveWindow( titleRect .Width ( ) - 1 , 0 , parentRect .right-100, titleRect .Height( ) );
		pWnd ->MoveWindow( titleRect .Width ( ) - 1 , 0 , parentRect .right - titleRect .Width( ) - 3, titleRect .Height( ) );
#ifdef OUTPUT_DEBUG
		memset( str , 0 , sizeof( str ) ) ;
		sprintf( str , "TITLEBAR => Left: %d    Top: %d    Right: %d    Bottom: %d" , titleRect .Width ( ) - 1 , -1 , parentRect .right , titleRect .Height( ) );
//		OutputDebugString( str );
#endif
	}

	//monogram of the dialog
	pWnd = m_parentWnd ->GetDlgItem( m_monogramImageID );
	if( pWnd )
	{
		pWnd ->GetClientRect( &monogramRect );
		m_parentWnd ->ScreenToClient( &monogramRect );
		if(m_titleImageID > 0)
			pWnd ->MoveWindow( 0 , titleRect .Height( ) , monogramRect .Width( ) , monogramRect .Height( ) );
		else
			pWnd ->MoveWindow( 0 , 35 , monogramRect .Width( ) , monogramRect .Height( ) );
#ifdef OUTPUT_DEBUG
		memset( str , 0 , sizeof( str ) ) ;
		sprintf( str , "MONOGRAM => Left: %d    Top: %d    Right: %d    Bottom: %d" , -1 , titleRect .Height( ) , monogramRect .Width( ) , monogramRect .Height( ) );
//		OutputDebugString( str );
#endif
	}

	//Extreme right portion below the title bar
	pWnd = m_parentWnd ->GetDlgItem( m_bitsImageID );
	if( pWnd )
	{
		pWnd ->GetClientRect( &bitsRect );
		m_parentWnd ->ScreenToClient( &bitsRect );
		if(m_titleImageID > 0)
			pWnd ->MoveWindow( parentRect .right - bitsRect .Width( )-3 , titleRect .Height( ) , bitsRect .Width( ) , monogramRect .Height( ) );
		else
			pWnd ->MoveWindow( parentRect .right - bitsRect .Width( )-3 , 35 , bitsRect .Width( ) , monogramRect .Height( ) );
#ifdef OUTPUT_DEBUG
		memset( str , 0 , sizeof( str ) ) ;
		sprintf( str , "BITS => Left: %d    Top: %d    Right: %d    Bottom: %d" ,  parentRect .right - bitsRect .Width( ) , titleRect .Height( ) , bitsRect .Width( ) , monogramRect .Height( ) );
//		OutputDebugString( str );
#endif
	}

	//Portion between the the above two
	pWnd = m_parentWnd ->GetDlgItem( m_whiteImageID );
	if( pWnd )
	{
		pWnd ->GetClientRect( &whiteRect );
		m_parentWnd ->ScreenToClient( &whiteRect );
		if(m_titleImageID > 0)
			pWnd ->MoveWindow( monogramRect .Width( ) - 1 , titleRect .Height( ), parentRect .right - bitsRect .Width( ) - monogramRect .Width( ) -2 , monogramRect .Height( ) );
		else
			pWnd ->MoveWindow( monogramRect .Width( ) - 1 , 35, parentRect .right - bitsRect .Width( ) - monogramRect .Width( ) + 1 , monogramRect .Height( ) );
#ifdef OUTPUT_DEBUG
		memset( str , 0 , sizeof( str ) ) ;
		sprintf( str , "WHITE => Left: %d    Top: %d    Right: %d    Bottom: %d" , monogramRect .Width( ) - 1 , titleRect .Height( ) , parentRect .right - bitsRect .Width( ) - monogramRect .Width( ) + 1 , monogramRect .Height( ) );
//		OutputDebugString( str );
#endif
	}

	//vishal
	//Titlebar's right corner
	pWnd = m_parentWnd ->GetDlgItem( m_titlebarRightCornerID );
	if( pWnd )
	{
		pWnd ->GetClientRect( &titlebarRightCornerRect );
		m_parentWnd ->ScreenToClient( &titlebarRightCornerRect );
		pWnd ->MoveWindow( parentRect.right - iFromRight , parentRect.top, titlebarRightCornerRect .Width( )  , titlebarRightCornerRect .Height( ) );
	}

	//vishal
	//dialog's left bottom corner
	pWnd = m_parentWnd ->GetDlgItem( m_leftBottomCornerID );
	if( pWnd )
	{
		pWnd ->GetClientRect( &leftBottomCornerRect );
		m_parentWnd ->ScreenToClient( &leftBottomCornerRect );
		pWnd ->MoveWindow( parentRect.left , parentRect.bottom - 15, leftBottomCornerRect .Width( )  , leftBottomCornerRect .Height( ) );
	}

	//vishal
	//dialog's left bottom corner
	pWnd = m_parentWnd ->GetDlgItem( m_rightBottomCornerID );
	if( pWnd )
	{
		pWnd ->GetClientRect( &rightBottomCornerRect );
		m_parentWnd ->ScreenToClient( &rightBottomCornerRect );
		pWnd ->MoveWindow( parentRect.right - rightBottomCornerRect .Width( ) - 3 , parentRect.bottom - 15, rightBottomCornerRect .Width( )  , rightBottomCornerRect .Height( ) );
	}
	
	//traypopup dialog's left strip
	pWnd = m_parentWnd ->GetDlgItem( m_leftStripID );
	if( pWnd )
	{
		pWnd ->GetClientRect( &leftStripRect );
		m_parentWnd ->ScreenToClient( &leftStripRect );
		pWnd ->MoveWindow( parentRect.left , parentRect.top + titleRect.Height(), leftStripRect .Width( )  , parentRect.bottom );
	}

	
	//vishal
	//traypopup dialog's right strip
	pWnd = m_parentWnd ->GetDlgItem( m_rightStripID );
	if( pWnd )
	{
		pWnd ->GetClientRect( &rightStripRect );
		m_parentWnd ->ScreenToClient( &rightStripRect );
		pWnd ->MoveWindow( parentRect.right - rightStripRect .Width( )  , parentRect.top + titleRect.Height(), rightStripRect .Width( )  , parentRect.bottom );
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
		// Use the provided border images to draw the border
		if(m_leftStripID > 0 && m_rightStripID > 0 && m_leftBottomCornerID > 0 && m_rightBottomCornerID > 0)
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
				rcTemp.left = rcTemp.right - 15;
				pDC ->FillSolidRect(&rcTemp, BLUEBACKGROUND_RGB);

				//	Bottom Strip
				rcTemp = parentRect;
				rcTemp.top = parentRect.bottom - 15;
				pDC ->FillSolidRect(&rcTemp, BLUEBACKGROUND_RGB);
			}

			int nWidth = parentRect.Width();
			int nHeight = parentRect.Height();

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
			{
				CRect rectangle;
				//top line
				rectangle.SetRect(0, 0, nWidth, 1);
				pDC ->FillSolidRect(&rectangle, TITLE_COLOR_RGB);

				//left line
				rectangle.SetRect(0, 0, 1, nHeight);
				pDC ->FillSolidRect(&rectangle, TITLE_COLOR_RGB);

				//right line
				rectangle.SetRect(nWidth - 3, 0, nWidth - 4, nHeight);
				pDC ->FillSolidRect(&rectangle, TITLE_COLOR_RGB);

				//bottom line
				rectangle.SetRect(0, nHeight-4, nWidth, nHeight-3);
				pDC ->FillSolidRect(&rectangle, TITLE_COLOR_RGB);
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
					  full desktop (along with the taskbar). This function displays the
					  dialog excluding the taskbar size.
					  Even if the taskbar is hidden the dialog does not cover the desktop.
					  It leaves the taskbar size.
	Author			: Zuber
--------------------------------------------------------------------------------------*/
void CSpyDetectDlgBitmaps::ManageDialogSize( )
{
	CWnd * cWnd = m_parentWnd ->GetDesktopWindow( );
	cWnd ->GetWindowRect( &m_DesktopRect );

	if( m_parentWnd ->IsZoomed( ) )
	{
		APPBARDATA abd = { 0 };
		abd .hWnd = ::FindWindow( _T("Shell_TrayWnd") , NULL );
		if( ! abd .hWnd )
		{
			return;
		}

		abd .cbSize = sizeof( APPBARDATA );
		SHAppBarMessage( ABM_GETTASKBARPOS , &abd );

		CRect systrayRect;
		systrayRect = abd .rc;

		int x = m_DesktopRect .left;
		int y = m_DesktopRect .top;
		int cx = m_DesktopRect .right;
		int cy = m_DesktopRect .bottom;
		switch( abd .uEdge )
		{
			case ABE_LEFT:
				x += systrayRect .Width( );
				cx -= systrayRect .Width( );
				break;

			case ABE_TOP:
				y += systrayRect .Height( );
				cy -= systrayRect .Height( );
				break;

			case ABE_RIGHT:
				cx -= systrayRect .Width( );
				break;

			case ABE_BOTTOM:
				cy -= systrayRect .Height( );
				break;
		}
		m_parentWnd ->MoveWindow( x , y , cx + 4 , cy );
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
void CSpyDetectDlgBitmaps::OnPropertySheetSize( CDC * pDC ,
											   CPictureHolder* titleImg,
											   CPictureHolder* titlebarImg,
                                               CPictureHolder* monogramImg,
											   CPictureHolder* whiteImg,
											   CPictureHolder* bitsImg,
											   CPictureHolder* titlebarRightCornerImg,
											   CPictureHolder* cornerLeftBottomImg,
											   CPictureHolder* cornerRightBottomImg)
{
	if( ( titleImg == NULL ) || ( titlebarImg == NULL ) || ( monogramImg == NULL ) ||
		( whiteImg == NULL ) || ( bitsImg == NULL ) || ( titlebarRightCornerImg == NULL ) ||
		  ( cornerLeftBottomImg == NULL )|| ( cornerRightBottomImg == NULL ) )
	{
		return;
	}

	CRect rcSheetRect;
	CRect rcRender , rcWBounds;
	CBitmap bitmap;
	BITMAP bm;
	int titleRight , titleBottom  , monogramBottom , monogramRight , bitsLeft, bitsRight;

	m_parentWnd ->GetClientRect( &rcSheetRect );

	//draw title image
	bitmap .LoadBitmap( m_titleImageID );
	bitmap .GetBitmap( &bm );
	bitmap.DeleteObject();
	rcWBounds .left = rcRender .left = 0;
	rcWBounds .top = rcRender .top = 0;
	titleRight = rcWBounds .right = rcRender .right = bm .bmWidth;
	titleBottom = rcWBounds .bottom = rcRender .bottom = bm .bmHeight;
	titleImg ->Render( pDC , rcRender , rcWBounds );

	//draw titlebar image
	bitmap .LoadBitmap( m_titlebarImageID );
	bitmap .GetBitmap( &bm );
	bitmap.DeleteObject();
	rcWBounds .left = rcRender .left = titleRight;
	rcWBounds .top = rcRender .top = 0;
	rcWBounds .right = rcRender .right = titleRight + rcSheetRect .Width( );
	rcWBounds .bottom = rcRender .bottom = titleBottom;
	titlebarImg ->Render( pDC , rcRender , rcWBounds );

	//draw monogram image
	bitmap .LoadBitmap( m_monogramImageID );
	bitmap .GetBitmap( &bm );
	bitmap.DeleteObject();
	rcWBounds .left = rcRender .left = 0;
	rcWBounds .top = rcRender .top = titleBottom;
	monogramRight = rcWBounds .right = rcRender .right = bm .bmWidth;
	monogramBottom = rcWBounds .bottom = rcRender .bottom = titleBottom + bm .bmHeight;
	monogramImg ->Render( pDC , rcRender , rcWBounds );

	//draw bits image
	bitmap .LoadBitmap( m_bitsImageID );
	bitmap .GetBitmap( &bm );
	bitmap.DeleteObject();
	bitsLeft = rcWBounds .left = rcRender .left = rcSheetRect .Width( ) - bm .bmWidth;
	rcWBounds .top = rcRender .top = titleBottom;
	bitsRight = rcWBounds .right = rcRender .right = rcSheetRect .Width( )-3;
	rcWBounds .bottom = rcRender .bottom = monogramBottom;
	bitsImg ->Render( pDC , rcRender , rcWBounds );

	//draw white image
	bitmap .LoadBitmap( m_whiteImageID );
	bitmap .GetBitmap( &bm );
	bitmap.DeleteObject();
	rcWBounds .left = rcRender .left = monogramRight;
	rcWBounds .top = rcRender .top = titleBottom;
	rcWBounds .right = rcRender .right = bitsLeft;
	rcWBounds .bottom = rcRender .bottom = monogramBottom;
	whiteImg ->Render( pDC , rcRender , rcWBounds );

	//draw titlebar right corner image
	bitmap .LoadBitmap( m_titlebarRightCornerID);
	bitmap .GetBitmap( &bm );
	bitmap.DeleteObject();
	rcWBounds .left = rcRender .left = bitsRight - 6 ;
	rcWBounds .top = rcRender .top = 0;
	rcWBounds .right = rcRender .right = (bitsRight - 6) + bm .bmWidth;
	rcWBounds .bottom = rcRender .bottom = bm .bmHeight;
	titlebarRightCornerImg ->Render( pDC , rcRender , rcWBounds );

	//draw dialogs left bottom corner image
	bitmap .LoadBitmap( m_leftBottomCornerID);
	bitmap .GetBitmap( &bm );
	bitmap.DeleteObject();
	rcWBounds .left = rcRender .left = rcSheetRect.left ;
	rcWBounds .top = rcRender .top = rcSheetRect.bottom - 15;
	rcWBounds .right = rcRender .right = bm .bmWidth;
	rcWBounds .bottom = rcRender .bottom = (rcSheetRect.bottom - 15) + bm .bmHeight;
	cornerLeftBottomImg ->Render( pDC , rcRender , rcWBounds );

	//draw dialogs right bottom corner image
	bitmap .LoadBitmap( m_rightBottomCornerID);
	bitmap .GetBitmap( &bm );
	bitmap.DeleteObject();
	rcWBounds .left = rcRender .left = bitsRight - 12 ;
	rcWBounds .top = rcRender .top = rcSheetRect.bottom - 15;
	rcWBounds .right = rcRender .right = (bitsRight - 12) + bm .bmWidth;
	rcWBounds .bottom = rcRender .bottom = (rcSheetRect.bottom - 15) + bm .bmHeight;
	cornerRightBottomImg ->Render( pDC , rcRender , rcWBounds );

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

void CSpyDetectDlgBitmaps::drawHorizontalStrip( CDC *pDC, int left, int top, int right, int bottom,bool flag )
{
	int i, UpCnt = 0,DownCnt = 7;
	CRect rectangle;

	for( i = top ; i <= bottom ; ++i )
	{
		rectangle .SetRect( left , i , right , i + 1 );
		if(flag)
			pDC ->FillSolidRect( &rectangle , StripColor[DownCnt--]);
		else
			pDC ->FillSolidRect( &rectangle , StripColor[UpCnt++]);
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
void CSpyDetectDlgBitmaps::drawVerticalStrip( CDC *pDC, int left, int top, int right, int bottom, bool flag )
{
	int i, UpCnt = 0,DownCnt = 7;
	CRect rectangle;

	for( i = left ; i <= right ; i++  )
	{
		rectangle .SetRect( i, top, i+1, bottom );
		if(flag)
			pDC ->FillSolidRect( &rectangle , StripColor[UpCnt++]);
		else
			pDC ->FillSolidRect( &rectangle , StripColor[DownCnt--]);
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
bool CSpyDetectDlgBitmaps::LoadStringFromTable(HINSTANCE hInstance,int iCurrentLunguage,UINT IDS,CString * csBuffer)
{
	int uID;
	uID = iCurrentLunguage + IDS;
	//csBuffer = new CString();
	int iRet = LoadString(hInstance,uID,csBuffer->GetBuffer(1024),1024);
	csBuffer->ReleaseBuffer ();
	if(iRet > 0)
		return true;
	else
		return false;
}

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

	{
		// Fill inner background with signle color
		CRect rectangle;
		rectangle.SetRect(left+1, top+1, right-1, bottom);
		pDC ->FillSolidRect(&rectangle, UI_MIDDLE_BG_RGB);
	}

	{
		// Draw one pixel inner border
		CRect rectangle;
		// Top line
		rectangle.SetRect(left, top, right, top+1);
		pDC ->FillSolidRect(&rectangle, INNER_UI_BORDER_RGB);

		// Left Line
		rectangle.SetRect(left, top, left + 1, bottom);
		pDC ->FillSolidRect(&rectangle, INNER_UI_BORDER_RGB);

		// Right Line
		rectangle.SetRect(right-1, top, right, bottom);
		pDC ->FillSolidRect(&rectangle, INNER_UI_BORDER_RGB);

		// Bottom Line
		rectangle.SetRect(left, bottom, right, bottom+1);
		pDC ->FillSolidRect(&rectangle, INNER_UI_BORDER_RGB);
	}
}