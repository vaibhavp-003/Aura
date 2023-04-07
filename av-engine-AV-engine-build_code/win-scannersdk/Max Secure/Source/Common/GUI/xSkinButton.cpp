/*=============================================================================
   FILE			: xSkinButton.cpp
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
CREATION DATE   : 2/24/06
   NOTES		:
VERSION HISTORY	:
				
============================================================================*/
#include "pch.h"
#include "xSkinButton.h"
#include "MaxWarnings.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif


/*-------------------------------------------------------------------------------------
Function		: CxSkinButton
In Parameters	: -
Out	Parameters	: -
Purpose			: constructor to initialize member variables
Author			:
--------------------------------------------------------------------------------------*/
CxSkinButton::CxSkinButton()
{
	try
	{
		m_DrawMode				=	1;			// normal drawing mode
		m_FocusRectMargin		=	0;	// disable focus dotted rect
		hClipRgn				=	NULL;			// no clipping region
		m_TextColor				=	RGB(17, 31, 118);
		m_DownTextColor			=	RGB(255, 255, 255);
		m_OverTextColor			=	RGB(255, 255, 255);
		m_FocusTextColor		=   0;
		m_button_down			=	m_tracking = m_Checked = false;
		m_AlignStyle			=	DT_VCENTER|DT_CENTER;
		m_bShowText				=	true;
		m_bShiftClickText		=	true;
		m_bShowMultiline		=	false;
		m_bShowTopline			=	false; //Displays text center + 3 pixels (Nupur)
		m_pstBoost				=	NULL;
		m_bBottom				=	false;
	}
	catch(...)
	{
		//AddLogEntry(_T("Exception caught in CxSkinButton::CxSkinButton"));
	}
}

/*-------------------------------------------------------------------------------------
Function		: ~CxSkinButton
In Parameters	: -
Out	Parameters	: -
Purpose			: destructor to free memory
Author			:
--------------------------------------------------------------------------------------*/
CxSkinButton::~CxSkinButton()
{
	try
	{
		if(hClipRgn)
			DeleteObject(hClipRgn);	// free clip region
	}
	catch(...)
	{
		//AddLogEntry(_T("Exception caught in CxSkinButton::~CxSkinButton"));
	}
}

BEGIN_MESSAGE_MAP(CxSkinButton, CButton)
	//{{AFX_MSG_MAP(CxSkinButton)
	ON_WM_ERASEBKGND()
	ON_WM_LBUTTONDOWN()
	ON_WM_LBUTTONUP()
	ON_WM_MOUSEMOVE()
	ON_WM_LBUTTONDBLCLK()
	ON_WM_KILLFOCUS()
	ON_WM_SETFOCUS()
	ON_WM_KEYDOWN()
	//}}AFX_MSG_MAP
	ON_MESSAGE(WM_MOUSELEAVE, OnMouseLeave)
	ON_MESSAGE(WM_CXSHADE_RADIO, OnRadioInfo)
	ON_MESSAGE(BM_SETCHECK, OnBMSetCheck)
	ON_MESSAGE(BM_GETCHECK, OnBMGetCheck)
END_MESSAGE_MAP()

/*-------------------------------------------------------------------------------------
Function		: PreSubclassWindow
In Parameters	: -
Out	Parameters	: void
Purpose			: to allow other necessary subclassing to occur before the window is
subclassed
Author			:
--------------------------------------------------------------------------------------*/
void CxSkinButton::PreSubclassWindow()
{
	try
	{
		m_Style=GetButtonStyle();	///get specific BS_ styles

		if((m_Style & BS_AUTOCHECKBOX) == BS_AUTOCHECKBOX)
			m_Style=BS_CHECKBOX;
		else if((m_Style & BS_AUTORADIOBUTTON) == BS_AUTORADIOBUTTON)
			m_Style=BS_RADIOBUTTON;
		else
			m_Style=BS_PUSHBUTTON;


		CButton::PreSubclassWindow();
		ModifyStyle(0, BS_OWNERDRAW);

	}
	catch(...)
	{
		//AddLogEntry(_T("Exception caught in CxSkinButton::PreSubclassWindow"));
	}
}
void CxSkinButton::SetResourceHandle(HANDLE hResHandle, HWND hWnd)
{
	AfxSetResourceHandle((HINSTANCE)hResHandle);
	this->m_hWnd = hWnd;

}
/*-----------------------------------------------------------------------------
Function		: OnEraseBkgnd
In Parameters	: CDC* :  device-context  pointer
Out Parameters	:BOOL : it always return false
Purpose		:The framework calls this member function when the CWnd object
background needs erasing.
Author		:
-----------------------------------------------------------------------------*/
BOOL CxSkinButton::OnEraseBkgnd(CDC* pDC)
{
	return 1; // doesn't erase the button background
}

/*-------------------------------------------------------------------------------------
Function		: DrawItem
In Parameters	: lpDrawItemStruct - Pointer to DRAWITEMSTRUCT structure describing
the item to be painted
Out Parameters	: -
Purpose			: Called by framework when a visual aspect changes
Author			:
--------------------------------------------------------------------------------------*/
void CxSkinButton::DrawItem(LPDRAWITEMSTRUCT lpDrawItemStruct)
{
	try
	{
		ASSERT (lpDrawItemStruct);

		//Check if the button state in not in inconsistent mode...
		POINT mouse_position;
		if((m_button_down) && (::GetCapture() == m_hWnd) && (::GetCursorPos(&mouse_position)))
		{
			if(::WindowFromPoint(mouse_position) == m_hWnd)
			{
				if((GetState()& BST_PUSHED) != BST_PUSHED)
				{
					SetState(TRUE);
					return;
				}
			}
			else
			{
				if((GetState()& BST_PUSHED) == BST_PUSHED)
				{
					SetState(FALSE);
					return;
				}
			}
		}

		CString sCaption;
		CDC *pDC = CDC::FromHandle(lpDrawItemStruct->hDC);	// get device context
		RECT r=lpDrawItemStruct->rcItem;					// context rectangle
		
		// get text box position
		RECT tr={r.left + m_FocusRectMargin + 2, r.top, r.right - m_FocusRectMargin - 2, r.bottom};

		GetWindowText(sCaption);							// get button text

		pDC->SetBkMode(TRANSPARENT);

		// Select the correct skin
		if(lpDrawItemStruct->itemState & ODS_DISABLED)
		{
			// DISABLED BUTTON
			if(m_bDisabled.m_hObject == NULL)
				// no skin selected for disabled state->standard button
				pDC->FillSolidRect(&r,GetSysColor(COLOR_BTNFACE));
			else // paint the skin
				DrawBitmap(pDC,(HBITMAP)m_bDisabled,r,m_DrawMode);
			// if needed, draw the standard 3D rectangular border
			if(m_Border)pDC->DrawEdge(&r,EDGE_RAISED,BF_RECT);
			// paint the etched button text
			pDC->SetTextColor(GetSysColor(COLOR_3DHILIGHT));
			if(m_AlignStyle == DT_BOTTOM)
			{
				if(m_bBottom == false)
				{
					tr.top = tr.top - 2;
					tr.bottom = tr.bottom - 5;
				}
				else
				{
					tr.top = tr.top - 10;
					tr.bottom = tr.bottom - 13;
				}
			}
			
			if(m_bShowText && !m_bShowMultiline)
				pDC->DrawText(sCaption,&tr,DT_SINGLELINE|m_AlignStyle|DT_CENTER);
			pDC->SetTextColor(GetSysColor(COLOR_GRAYTEXT));
			if(m_bShowText && !m_bShowMultiline)
				pDC->DrawText(sCaption,&tr,DT_SINGLELINE|m_AlignStyle|DT_CENTER);

			if(m_bShowMultiline)	
			{
				tr = r;
				if(m_bBottom)
					tr.top = (tr.bottom - tr.top) - ((tr.bottom - tr.top) * 35/100);
				else
					tr.top = (tr.bottom - tr.top) - ((tr.bottom - tr.top) * 45/100);
								
				if(sCaption.Find(_T("/")) == -1)
					ModifyStyleEx(lpDrawItemStruct->hwndItem,0,BS_MULTILINE,0);
				pDC->DrawText(sCaption,&tr,DT_WORDBREAK|DT_CENTER);
			}
			//Nupur: Shifting text 3 pixels above the center for Max PC Boost
			else if(m_AlignStyle == DT_VCENTER && m_bShowTopline)
			{
				tr.top = tr.top - 3;
			}
		}
		else
		{										// SELECTED (DOWN)BUTTON
			if((lpDrawItemStruct->itemState & ODS_SELECTED) ||m_Checked)
			{
				if(m_bDown.m_hObject == NULL)
					// no skin selected for selected state->standard button
					pDC->FillSolidRect(&r,GetSysColor(COLOR_BTNFACE));
				else
				{ // paint the skin
					DrawBitmap(pDC,(HBITMAP)m_bDown,r,m_DrawMode);
				}
				if(m_bShiftClickText)
					OffsetRect(&tr,1,1);  //shift text
				// if needed, draw the standard 3D rectangular border
				if(m_Border)pDC->DrawEdge(&r,EDGE_SUNKEN,BF_RECT);
				// paint the enabled button text
				pDC->SetTextColor(m_DownTextColor);
			}
			else
			{											// DEFAULT BUTTON
				if(m_bNormal.m_hObject == NULL)
					// no skin selected for normal state->standard button
					pDC->FillSolidRect(&r,GetSysColor(COLOR_BTNFACE));
				else if((m_tracking) &&(m_bOver.m_hObject!=NULL))// paint the skin
				{
					DrawBitmap(pDC,(HBITMAP)m_bOver,r,m_DrawMode);
					if(m_FocusTextColor != 0)
						pDC->SetTextColor(m_FocusTextColor);
					else
						// paint the enabled button text
						pDC->SetTextColor(m_OverTextColor);
				}
				else
				{
					// paint the enabled button text
					pDC->SetTextColor(m_TextColor);
					if((lpDrawItemStruct->itemState & ODS_FOCUS) &&(m_bFocus.m_hObject!=NULL))
					{
						if(m_FocusTextColor != 0)
							pDC->SetTextColor(m_FocusTextColor);
						DrawBitmap(pDC,(HBITMAP)m_bFocus,r,m_DrawMode);
					}
					else
					{
						DrawBitmap(pDC,(HBITMAP)m_bNormal,r,m_DrawMode);
					}
				}
				// if needed, draw the standard 3D rectangular border
				if(m_Border)pDC->DrawEdge(&r,EDGE_RAISED,BF_RECT);

			}
			// paint the focus rect
			if((lpDrawItemStruct->itemState & ODS_FOCUS) &&(m_FocusRectMargin>0))
			{
				r.left   += m_FocusRectMargin;
				r.top    += m_FocusRectMargin;
				r.right  -= m_FocusRectMargin;
				r.bottom -= m_FocusRectMargin;
				DrawFocusRect (lpDrawItemStruct->hDC, &r);
			}

			if(m_AlignStyle == DT_BOTTOM)
			{
				if(m_bBottom == false)
				{
					tr.top = tr.top - 2;
					tr.bottom = tr.bottom - 5;
				}
				else
				{
					tr.top = tr.top - 10;
					tr.bottom = tr.bottom - 13;
				}
				if(m_bShowText && !m_bShowMultiline)
					pDC->DrawText(sCaption,&tr,DT_SINGLELINE|m_AlignStyle|DT_CENTER);
			}
			
			
			//Nupur: Shifting text 3 pixels above the center for Max PC Boost
			else if(m_AlignStyle == DT_VCENTER && m_bShowTopline)
			{
				tr.top = tr.top - 3;
				if(m_bShowText && !m_bShowMultiline)
					pDC->DrawText(sCaption,&tr,DT_SINGLELINE|m_AlignStyle|DT_CENTER);
			}
			else
			{
				if(m_bShowText && !m_bShowMultiline)
					pDC->DrawText(sCaption,&tr,DT_SINGLELINE|m_AlignStyle);
			}
			if(m_bShowMultiline)	
			{
				tr = r;
				if(m_bBottom)
					tr.top = (tr.bottom - tr.top) - ((tr.bottom - tr.top) * 35/100);
				else
					tr.top = (tr.bottom - tr.top) - ((tr.bottom - tr.top) * 45/100);

				if(sCaption.Find(_T("/")) == -1)
					ModifyStyleEx(lpDrawItemStruct->hwndItem,0,BS_MULTILINE,0);
				pDC->DrawText(sCaption,&tr,DT_WORDBREAK|DT_CENTER);
			}

		}
	}
	catch(...)
	{
		//AddLogEntry(_T("Exception caught in CxSkinButton::DrawItem"));
	}
}

/*-------------------------------------------------------------------------------------
Function		: GetBitmapWidth
In Parameters	: HBITMAP - bitmap handle
Out	Parameters	: int
Purpose			: to retrieve Bitmap width
Author			:
--------------------------------------------------------------------------------------*/
int CxSkinButton::GetBitmapWidth (HBITMAP hBitmap)
{
	try
	{
		BITMAP bm; GetObject(hBitmap,sizeof(BITMAP),(PSTR)&bm);
		return bm.bmWidth;
	}
	catch(...)
	{
		//AddLogEntry(_T("Exception caught in CxSkinButton::DrawItem"));
	}
	return 0;
}

/*-------------------------------------------------------------------------------------
Function		: GetBitmapHeight
In Parameters	: HBITMAP - bitmap handle
Out	Parameters	: int
Purpose			: to retrieve Bitmap height
Author			:
--------------------------------------------------------------------------------------*/
int CxSkinButton::GetBitmapHeight (HBITMAP hBitmap)
{
	try
	{
		BITMAP bm; GetObject(hBitmap,sizeof(BITMAP),(PSTR)&bm);
		return bm.bmHeight;
	}
	catch(...)
	{
		//AddLogEntry(_T("Exception caught in CxSkinButton::GetBitmapHeight"));
	}
	return 0;
}

/*-------------------------------------------------------------------------------------
Function		: DrawBitmap
In Parameters	: CDC* - pointer to DC
HBITMAP - bitmap handle
RECT - rect
int  -draw mode
Out	Parameters	: void
Purpose			: to draw the bitmap image
Author			:
--------------------------------------------------------------------------------------*/
void CxSkinButton::DrawBitmap(CDC* dc, HBITMAP hbmp, RECT r, int DrawMode)
{
	//	DrawMode: 0=Normal; 1=stretch; 2=tiled fill
	try
	{
		if(DrawMode == 2)
		{
			FillWithBitmap(dc,hbmp,r);
			return;
		}
		if(!hbmp)
			return;	//safe check

		int cx=r.right  - r.left;
		int cy=r.bottom - r.top;
		CDC dcBmp,dcMask;
		dcBmp.CreateCompatibleDC(dc);
		dcBmp.SelectObject(hbmp);

		if(m_bMask.m_hObject!=NULL)
		{
			dcMask.CreateCompatibleDC(dc);
			dcMask.SelectObject(m_bMask);

			CDC hdcMem;
			hdcMem.CreateCompatibleDC(dc);
			CBitmap hBitmap;
			hBitmap.CreateCompatibleBitmap(dc,cx,cy);
			hdcMem.SelectObject(hBitmap);

			hdcMem.BitBlt(r.left,r.top,cx,cy,dc,0,0,SRCCOPY);
			if(!DrawMode)
			{
				hdcMem.BitBlt(r.left,r.top,cx,cy,&dcBmp,0,0,SRCINVERT);
				hdcMem.BitBlt(r.left,r.top,cx,cy,&dcMask,0,0,SRCAND);
				hdcMem.BitBlt(r.left,r.top,cx,cy,&dcBmp,0,0,SRCINVERT);
			}
			else
			{
				int bx=GetBitmapWidth(hbmp);
				int by=GetBitmapHeight(hbmp);
				hdcMem.StretchBlt(r.left,r.top,cx,cy,&dcBmp,0,0,bx,by,SRCINVERT);
				hdcMem.StretchBlt(r.left,r.top,cx,cy,&dcMask,0,0,bx,by,SRCAND);
				hdcMem.StretchBlt(r.left,r.top,cx,cy,&dcBmp,0,0,bx,by,SRCINVERT);
			}
			dc->BitBlt(r.left,r.top,cx,cy,&hdcMem,0,0,SRCCOPY);

			hdcMem.DeleteDC();
			hBitmap.DeleteObject();

			DeleteDC(dcMask);
		}
		else
		{
			if(!DrawMode)
			{
				dc->BitBlt(r.left,r.top,cx,cy,&dcBmp,0,0,SRCCOPY);
			}
			else
			{
				int bx=GetBitmapWidth(hbmp);
				int by=GetBitmapHeight(hbmp);
				dc->StretchBlt(r.left,r.top,cx,cy,&dcBmp,0,0,bx,by,SRCCOPY);
			}
		}
		DeleteDC(dcBmp);
	}
	catch(...)
	{
		//AddLogEntry(_T("Exception caught in CxSkinButton::DrawBitmap"));
	}
}

/*-------------------------------------------------------------------------------------
Function		: DrawBitmap
In Parameters	: CDC* - pointer to DC
HBITMAP - bitmap handle
RECT - rect
Out	Parameters	: void
Purpose			: to draw the bitmap image
Author			:
--------------------------------------------------------------------------------------*/
void CxSkinButton::FillWithBitmap(CDC* dc, HBITMAP hbmp, RECT r)
{
	try
	{
		if(!hbmp)return;
		CDC memdc;
		memdc.CreateCompatibleDC(dc);
		memdc.SelectObject(hbmp);
		int w = r.right - r.left;
		int	h = r.bottom - r.top;
		int x,y,z;
		int	bx=GetBitmapWidth(hbmp);
		int	by=GetBitmapHeight(hbmp);
		for (y = r.top; y < h; y += by)
		{
			if((y+by) >h)by=h-y;
			z=bx;
			for (x = r.left; x < w; x += z)
			{
				if((x+z) >w)z=w-x;
				dc->BitBlt(x, y, z, by, &memdc, 0, 0, SRCCOPY);
			}
		}
		DeleteDC(memdc);
	}
	catch(...)
	{
		//AddLogEntry(_T("Exception caught in CxSkinButton::FillWithBitmap"));
	}
}

/*-------------------------------------------------------------------------------------
Function		: SetSkin
In Parameters	: UINT - normal image ID
UINT - down image ID
UINT - over image ID
UINT - disable image ID
UINT - focus image ID
UINT - mask image ID
short - draw mode
short - border
short - margin
Out	Parameters	: void
Purpose			: to set sking to button
Author			:
--------------------------------------------------------------------------------------*/
void CxSkinButton::SetSkin(UINT normal,UINT down,UINT over,UINT disabled, UINT focus,UINT mask,
						   short drawmode, short border, short margin)
{
	try
	{
		m_bNormal.DeleteObject();	//free previous allocated bitmap
		m_bDown.DeleteObject();
		m_bOver.DeleteObject();
		m_bDisabled.DeleteObject();
		m_bMask.DeleteObject();
		m_bFocus.DeleteObject();

		if(normal>0)m_bNormal.LoadBitmap(normal);
		if(down>0)	  m_bDown.LoadBitmap(down);
		if(over>0)	  m_bOver.LoadBitmap(over);
		if(focus>0) m_bFocus.LoadBitmap(focus);

		if(disabled>0)m_bDisabled.LoadBitmap(disabled);
		else if(normal>0)m_bDisabled.LoadBitmap(normal);

		m_DrawMode=max(0,min(drawmode,2));
		m_Border=border;
		m_FocusRectMargin=max(0,margin);

		if(mask>0)
		{
			m_bMask.LoadBitmap(mask);
			if(hClipRgn)DeleteObject(hClipRgn);
			hClipRgn = CreateRgnFromBitmap(m_bMask,RGB(255,255,255));
			if(hClipRgn)
			{
				SetWindowRgn(hClipRgn, TRUE);
				SelectClipRgn((HDC)GetDC(),hClipRgn);
			}
			if(m_DrawMode == 0)
			{
				SetWindowPos(NULL,0,0,GetBitmapWidth(m_bMask),
					GetBitmapHeight(m_bMask),SWP_NOZORDER|SWP_NOMOVE);
			}
		}
	}
	catch(...)
	{
		//AddLogEntry(_T("Exception caught in CxSkinButton::SetSkin"));
	}
}
/*-------------------------------------------------------------------------------------
Function		: SetSkin
In Parameters	: HMODULE hinstDLL, UINT normal,UINT down,UINT over,UINT disabled, UINT focus,UINT mask,
						   short drawmode, short border, short margin
Out	Parameters	: void
Purpose			: Load button image from dll
Author			: Dipali Pawar
--------------------------------------------------------------------------------------*/
void CxSkinButton::SetSkin(HMODULE hinstDLL, UINT normal,UINT down,UINT over,UINT disabled, UINT focus,UINT mask,
						   short drawmode, short border, short margin)
{
	try
	{
		m_bNormal.DeleteObject();	//free previous allocated bitmap
		m_bDown.DeleteObject();
		m_bOver.DeleteObject();
		m_bDisabled.DeleteObject();
		m_bMask.DeleteObject();
		m_bFocus.DeleteObject();


		if(normal>0)
		{
			HANDLE hBmp = LoadBitmap(hinstDLL, MAKEINTRESOURCE(normal)); 
			if (hBmp == NULL)
			{
			  return ;
			}

			m_bNormal.Attach(hBmp);
		}
		if(down>0)	  
		{
			HANDLE hBmp = LoadBitmap(hinstDLL, MAKEINTRESOURCE(down)); 
			if (hBmp == NULL)
			{
			  return ;
			}

			m_bDown.Attach(hBmp);
			//m_bDown.LoadBitmap(down);
		}
		if(over>0)
		{
			HANDLE hBmp = LoadBitmap(hinstDLL, MAKEINTRESOURCE(over)); 
			
			if (hBmp == NULL)
			{
			  return ;
			}

			m_bOver.Attach(hBmp);
			//m_bOver.LoadBitmap(over);
		}
		if(focus>0) 
		{
			//HANDLE hBmp = LoadImage(hinstDLL,focus,IMAGE_BITMAP,0,0,LR_DEFAULTSIZE);
			HANDLE hBmp = LoadBitmap(hinstDLL, MAKEINTRESOURCE(focus)); 
			if (hBmp == NULL)
			{
			  return ;
			}

			m_bFocus.Attach(hBmp);
			//m_bFocus.LoadBitmap(focus);
		}

		if(disabled>0)
		{
			//HANDLE hBmp = LoadImage(hinstDLL,disabled,IMAGE_BITMAP,0,0,LR_DEFAULTSIZE);
			HANDLE hBmp = LoadBitmap(hinstDLL, MAKEINTRESOURCE(disabled));
			if (hBmp == NULL)
			{
			  return ;
			}

			m_bDisabled.Attach(hBmp);
			//m_bDisabled.LoadBitmap(disabled);
		}
		else if(normal>0)
		{
			//HANDLE hBmp = LoadImage(hinstDLL,normal,IMAGE_BITMAP,0,0,LR_DEFAULTSIZE);
			HANDLE hBmp = LoadBitmap(hinstDLL, MAKEINTRESOURCE(normal));
			if (hBmp == NULL)
			{
			  return ;
			}

			m_bDisabled.Attach(hBmp);
			//m_bDisabled.LoadBitmap(normal);
		}

		m_DrawMode=max(0,min(drawmode,2));
		m_Border=border;
		m_FocusRectMargin=max(0,margin);

		if(mask>0)
		{
			HANDLE hBmp = LoadBitmap(hinstDLL, MAKEINTRESOURCE(mask)); 
			if (hBmp == NULL)
			{
			  return ;
			}

			m_bMask.Attach(hBmp);

			//m_bMask.LoadBitmap(mask);
			if(hClipRgn)DeleteObject(hClipRgn);
			hClipRgn = CreateRgnFromBitmap(m_bMask,RGB(255,255,255));
			if(hClipRgn)
			{
				SetWindowRgn(hClipRgn, TRUE);
				SelectClipRgn((HDC)GetDC(),hClipRgn);
			}
			if(m_DrawMode == 0)
			{
				SetWindowPos(NULL,0,0,GetBitmapWidth(m_bMask),
					GetBitmapHeight(m_bMask),SWP_NOZORDER|SWP_NOMOVE);
			}
		}
	}
	catch(...)
	{
		//AddLogEntry(_T("Exception caught in CxSkinButton::SetSkin"));
	}
}
/*-------------------------------------------------------------------------------------
Function		: SetSkin
In Parameters	: LPCTSTR normal,LPCTSTR down,LPCTSTR over,LPCTSTR disabled, LPCTSTR focus,LPCTSTR mask,
						   short drawmode, short border, short margin
Out	Parameters	: void
Purpose			: Load button image from disk image file
Author			: Dipali Pawar
--------------------------------------------------------------------------------------*/
void CxSkinButton::SetSkin(LPCTSTR normal,LPCTSTR down,LPCTSTR over,LPCTSTR disabled, LPCTSTR focus,LPCTSTR mask,
						   short drawmode, short border, short margin)
{
	try
	{
		m_bNormal.DeleteObject();	//free previous allocated bitmap
		m_bDown.DeleteObject();
		m_bOver.DeleteObject();
		m_bDisabled.DeleteObject();
		m_bMask.DeleteObject();
		m_bFocus.DeleteObject();


		if(normal>0)
		{
			HANDLE hBmp = LoadImage(NULL,normal,IMAGE_BITMAP,0,0,LR_DEFAULTSIZE|LR_LOADFROMFILE);
			if (hBmp == NULL)
			{
			  return ;
			}

			m_bNormal.Attach(hBmp);
		}
		if(down>0)	  
		{
			HANDLE hBmp = LoadImage(NULL,down,IMAGE_BITMAP,0,0,LR_DEFAULTSIZE|LR_LOADFROMFILE);
			if (hBmp == NULL)
			{
			  return ;
			}

			m_bDown.Attach(hBmp);
			//m_bDown.LoadBitmap(down);
		}
		if(over>0)
		{
			HANDLE hBmp = LoadImage(NULL,over,IMAGE_BITMAP,0,0,LR_DEFAULTSIZE|LR_LOADFROMFILE);
			if (hBmp == NULL)
			{
			  return ;
			}

			m_bOver.Attach(hBmp);
			//m_bOver.LoadBitmap(over);
		}
		if(focus>0) 
		{
			HANDLE hBmp = LoadImage(NULL,focus,IMAGE_BITMAP,0,0,LR_DEFAULTSIZE|LR_LOADFROMFILE);
			if (hBmp == NULL)
			{
			  return ;
			}

			m_bFocus.Attach(hBmp);
			//m_bFocus.LoadBitmap(focus);
		}

		if(disabled>0)
		{
			HANDLE hBmp = LoadImage(NULL,disabled,IMAGE_BITMAP,0,0,LR_DEFAULTSIZE|LR_LOADFROMFILE);
			if (hBmp == NULL)
			{
			  return ;
			}

			m_bDisabled.Attach(hBmp);
			//m_bDisabled.LoadBitmap(disabled);
		}
		else if(normal>0)
		{
			HANDLE hBmp = LoadImage(NULL,normal,IMAGE_BITMAP,0,0,LR_DEFAULTSIZE|LR_LOADFROMFILE);
			if (hBmp == NULL)
			{
			  return ;
			}

			m_bDisabled.Attach(hBmp);
			//m_bDisabled.LoadBitmap(normal);
		}

		m_DrawMode=max(0,min(drawmode,2));
		m_Border=border;
		m_FocusRectMargin=max(0,margin);

		if(mask>0)
		{
			HANDLE hBmp = LoadImage(NULL,mask,IMAGE_BITMAP,0,0,LR_DEFAULTSIZE|LR_LOADFROMFILE);
			if (hBmp == NULL)
			{
			  return ;
			}

			m_bMask.Attach(hBmp);

			//m_bMask.LoadBitmap(mask);
			if(hClipRgn)DeleteObject(hClipRgn);
			hClipRgn = CreateRgnFromBitmap(m_bMask,RGB(255,255,255));
			if(hClipRgn)
			{
				SetWindowRgn(hClipRgn, TRUE);
				SelectClipRgn((HDC)GetDC(),hClipRgn);
			}
			if(m_DrawMode == 0)
			{
				SetWindowPos(NULL,0,0,GetBitmapWidth(m_bMask),
					GetBitmapHeight(m_bMask),SWP_NOZORDER|SWP_NOMOVE);
			}
		}
	}
	catch(...)
	{
		//AddLogEntry(_T("Exception caught in CxSkinButton::SetSkin"));
	}
}
/*-------------------------------------------------------------------------------------
Function		: SetSkin
In Parameters	: HBITMAP - bitmap handle
COLORREF - color
Out	Parameters	: HRGN - nadle to rgn
Purpose			: to get rgn from bitmap image
Author			:
--------------------------------------------------------------------------------------*/
HRGN CxSkinButton::CreateRgnFromBitmap(HBITMAP hBmp, COLORREF color)
{
	try
	{
		if(!hBmp)
			return NULL;

		BITMAP bm;
		GetObject(hBmp, sizeof(BITMAP), &bm);	// get bitmap attributes

		CDC dcBmp;
		dcBmp.CreateCompatibleDC(GetDC());	//Creates a memory device context for the bitmap
		dcBmp.SelectObject(hBmp);			//selects the bitmap in the device context

		const DWORD RDHDR = sizeof(RGNDATAHEADER);
		const DWORD MAXBUF = 40;		// size of one block in RECTs
		// (i.e.MAXBUF*sizeof(RECT)in bytes)
		LPRECT	pRects;
		DWORD	cBlocks = 0;			// number of allocated blocks

		INT		i, j;					// current position in mask image
		INT		first = 0;				// left position of current scan line
		// where mask was found
		bool	wasfirst = false;		// set when if mask was found in current scan line
		bool	ismask;					// set when current color is mask color

		// allocate memory for region data
		RGNDATAHEADER* pRgnData = (RGNDATAHEADER*)new BYTE[ RDHDR + ++cBlocks * MAXBUF * sizeof(RECT)];
		memset(pRgnData, 0, RDHDR + cBlocks * MAXBUF * sizeof(RECT));
		// fill it by default
		pRgnData->dwSize	= RDHDR;
		pRgnData->iType		= RDH_RECTANGLES;
		pRgnData->nCount	= 0;
		for(i = 0; i < bm.bmHeight; i++)
			for(j = 0; j < bm.bmWidth; j++)
			{
				// get color
				ismask=(dcBmp.GetPixel(j,bm.bmHeight-i-1) !=color);
				// place part of scan line as RECT region if transparent color found after mask color or
				// mask color found at the end of mask image
				if(wasfirst && ((ismask && (j == (bm.bmWidth-1))) ||(ismask ^ (j<bm.bmWidth))))
				{
					// get offset to RECT array if RGNDATA buffer
					pRects = (LPRECT)((LPBYTE)pRgnData + RDHDR);
					// save current RECT
					pRects[ pRgnData->nCount++]= CRect(first, bm.bmHeight - i - 1, j+(j == (bm.bmWidth-1)), bm.bmHeight - i);
					// if buffer full reallocate it
					if(pRgnData->nCount >= cBlocks * MAXBUF)
					{
						LPBYTE pRgnDataNew = new BYTE[ RDHDR + ++cBlocks * MAXBUF * sizeof(RECT)];
						memcpy(pRgnDataNew, pRgnData, RDHDR + (cBlocks - 1)* MAXBUF * sizeof(RECT));

						if(pRgnData)
						{
							delete[] pRgnData;
							pRgnData = NULL;
						}
						pRgnData = (RGNDATAHEADER*)pRgnDataNew;
					}
					wasfirst = false;
				}
				else if(!wasfirst && ismask)
				{		// set wasfirst when mask is found
					first = j;
					wasfirst = true;
				}
			}
			dcBmp.DeleteDC();	//release the bitmap

			// create region
			HRGN hRgn= CreateRectRgn(0, 0, 0, 0);
			ASSERT(hRgn!=NULL);
			pRects = (LPRECT)((LPBYTE)pRgnData + RDHDR);
			for(i=0;i<(int)pRgnData->nCount;i++)
			{
				HRGN hr=CreateRectRgn(pRects[i].left, pRects[i].top, pRects[i].right, pRects[i].bottom);
				VERIFY(CombineRgn(hRgn, hRgn, hr, RGN_OR) !=ERROR);
				if(hr)DeleteObject(hr);
			}
			ASSERT(hRgn!=NULL);

			if(pRgnData)
			{
				delete[] pRgnData;
				pRgnData = NULL;
			}
			return hRgn;
	}
	catch(...)
	{
		//AddLogEntry(_T("Exception caught in CxSkinButton::CreateRgnFromBitmap"));
	}
	return CreateRectRgn(0, 0, 0, 0);
}

/*-------------------------------------------------------------------------------------
Function		: SetTextColor
In Parameters	: COLORREF - color
Out	Parameters	: COLORREF - color
Purpose			: to set button text color
Author			:
--------------------------------------------------------------------------------------*/
COLORREF CxSkinButton::SetTextColor(COLORREF new_color)
{
	try
	{
		COLORREF tmp_color = m_TextColor;
		m_TextColor = new_color;
		return tmp_color;			//returns the previous color
	}
	catch(...)
	{
		//AddLogEntry(_T("Exception caught in CxSkinButton::SetTextColor"));
	}
	return m_TextColor;
}

/*-------------------------------------------------------------------------------------
Function		: SetTextColor
In Parameters	: COLORREF - color
Out	Parameters	: COLORREF - color
Purpose			: to set button text color
Author			: Sandip Sanap
--------------------------------------------------------------------------------------*/
COLORREF CxSkinButton::SetFocusTextColor(COLORREF new_color)
{
	try
	{
		COLORREF tmp_color = m_FocusTextColor;
		m_FocusTextColor = new_color;
		return tmp_color;			//returns the previous color
	}
	catch(...)
	{
		//AddLogEntry(_T("Exception caught in CxSkinButton::SetFocusTextColor"));
	}
	return m_FocusTextColor;
}

/*-------------------------------------------------------------------------------------
Function		: SetTextColorA
In Parameters	: COLORREF - normal color
COLORREF - down color
COLORREF - over color
Out	Parameters	: COLORREF - previous color
Purpose			: to set button text color for each event
Author			:
--------------------------------------------------------------------------------------*/
COLORREF CxSkinButton::SetTextColorA(COLORREF normal_color,COLORREF down_color,COLORREF over_color)
{
	try
	{
		COLORREF tmp_color = m_TextColor;
		m_TextColor = normal_color;
		m_DownTextColor = down_color;
		m_OverTextColor = over_color;
		return tmp_color;			//returns the previous color
	}
	catch(...)
	{
		//AddLogEntry(_T("Exception caught in CxSkinButton::SetTextColorA"));
	}
	return m_TextColor;
}

/*-------------------------------------------------------------------------------------
Function		: SetToolTipText
In Parameters	: CString - tip
Out	Parameters	: void
Purpose			: to set tool tip text
Author			:
--------------------------------------------------------------------------------------*/
void CxSkinButton::SetToolTipText(CString s)
{
	try
	{
		if(m_tooltip.m_hWnd == NULL)
		{
			if(m_tooltip.Create(this))	//first assignment
				if(m_tooltip.AddTool(this, (LPCTSTR)s))
					m_tooltip.Activate(1);
		}
		else
		{
			m_tooltip.UpdateTipText((LPCTSTR)s,this);
		}
	}
	catch(...)
	{
		//AddLogEntry(_T("Exception caught in CxSkinButton::SetToolTipText"));
	}
}

/*-------------------------------------------------------------------------------------
Function		: RelayEvent
In Parameters	: UINT - msg
WPARAM -
LPARAM -
Out	Parameters	: void
Purpose			: RelayEvent
Author			:
--------------------------------------------------------------------------------------*/
void CxSkinButton::RelayEvent(UINT message, WPARAM wParam, LPARAM lParam)
{
	// This function will create a MSG structure, fill it in a pass it to
	// the ToolTip control, m_ttip. Note that we ensure the point is in window
	// coordinates (relative to the control's window).
	try
	{
		if(NULL != m_tooltip.m_hWnd)
		{
			MSG msg;
			msg.hwnd = m_hWnd;
			msg.message = message;
			msg.wParam = wParam;
			msg.lParam = lParam;
			msg.time = 0;
			msg.pt.x = LOWORD(lParam);
			msg.pt.y = HIWORD(lParam);

			m_tooltip.RelayEvent(&msg);
		}

	}
	catch(...)
	{
		//AddLogEntry(_T("Exception caught in CxSkinButton::RelayEvent"));
	}
}

/*-------------------------------------------------------------------------------------
Function		: OnLButtonDblClk
In Parameters	: nFlags: not used
point: coordinates of the mouse pointer when this event was spawned
Out	Parameters	: void
Purpose			: This event is handled like an ordinary left-button-down event
Author			:
--------------------------------------------------------------------------------------*/

void CxSkinButton::OnLButtonDblClk(UINT flags, CPoint point)
{
	try
	{
		SendMessage(WM_LBUTTONDOWN, flags, MAKELPARAM(point.x, point.y));
	}
	catch(...)
	{
		//AddLogEntry(_T("Exception caught in CxSkinButton::OnLButtonDblClk"));
	}
}

/*-------------------------------------------------------------------------------------
Function		: OnLButtonDown
In Parameters	: nFlags: not used
point: coordinates of the mouse pointer when this event was spawned
Out	Parameters	: void
Purpose			: Handle event when left button is pressed down
Author			:
--------------------------------------------------------------------------------------*/
void CxSkinButton::OnLButtonDown(UINT nFlags, CPoint point)
{
	try
	{
		//Pass this message to the ToolTip control
		RelayEvent(WM_LBUTTONDOWN,(WPARAM)nFlags,MAKELPARAM(LOWORD(point.x),LOWORD(point.y)));

		//If we are tracking this button, cancel it
		if(m_tracking){
			TRACKMOUSEEVENT t = {
				sizeof(TRACKMOUSEEVENT),
				TME_CANCEL | TME_LEAVE,
				m_hWnd,
				0
			};
			if(::_TrackMouseEvent(&t)){
				m_tracking = false;
			}
		}

		//Default-process the message
		CButton::OnLButtonDown(nFlags, point);
		if(m_pstBoost)
			m_pstBoost->Invalidate();

		m_button_down = true;
	}
	catch(...)
	{
		//AddLogEntry(_T("Exception caught in CxSkinButton::OnLButtonDown"));
	}
}

/*-------------------------------------------------------------------------------------
Function		: OnLButtonUp
In Parameters	: nFlags: not used
point: coordinates of the mouse pointer when this event was spawned
Out	Parameters	: void
Purpose			: Handle event when left button is released (goes up)
Author			:
--------------------------------------------------------------------------------------*/
void CxSkinButton::OnLButtonUp(UINT nFlags, CPoint point)
{
	try
	{
		if(m_Style)
		{ //track mouse for radio & check buttons
			POINT p2 = point;
			::ClientToScreen(m_hWnd, &p2);
			HWND mouse_wnd = ::WindowFromPoint(p2);
			if(mouse_wnd == m_hWnd)
			{ // mouse is in button
				if(m_Style == BS_CHECKBOX)SetCheck(m_Checked ? 0 : 1);
				if(m_Style == BS_RADIOBUTTON)SetCheck(1);
			}
		}
		//Pass this message to the ToolTip control
		RelayEvent(WM_LBUTTONUP,(WPARAM)nFlags,MAKELPARAM(LOWORD(point.x),LOWORD(point.y)));

		//Default-process the message
		m_button_down = false;
		CButton::OnLButtonUp(nFlags, point);
	}
	catch(...)
	{
		//AddLogEntry(_T("Exception caught in CxSkinButton::OnLButtonUp"));
	}
}

/*-------------------------------------------------------------------------------------
Function		: OnMouseMove
In Parameters	: nFlags: not used
point: coordinates of the mouse pointer when this event was spawned
Out	Parameters	: void
Purpose			: Handle change of mouse position: see the comments in the
method for further info.
Author			:
--------------------------------------------------------------------------------------*/
void CxSkinButton::OnMouseMove(UINT nFlags, CPoint point)
{
	try
	{
		//TRACE("* %08X: Mouse\n", ::GetTickCount());

		//Pass this message to the ToolTip control
		RelayEvent(WM_MOUSEMOVE,(WPARAM)nFlags,MAKELPARAM(LOWORD(point.x),LOWORD(point.y)));

		//If we are in capture mode, button has been pressed down
		//recently and not yet released - therefore check is we are
		//actually over the button or somewhere else.If the mouse
		//position changed considerably (e.g.we moved mouse pointer
		//from the button to some other place outside button area)
		//force the control to redraw
		//
		if((m_button_down) && (::GetCapture() == m_hWnd))
		{
			POINT p2 = point;
			::ClientToScreen(m_hWnd, &p2);
			HWND mouse_wnd = ::WindowFromPoint(p2);

			bool pressed = ((GetState()& BST_PUSHED) == BST_PUSHED);
			bool need_pressed = (mouse_wnd == m_hWnd);
			if(pressed != need_pressed)
			{
				SetState(need_pressed ? TRUE : FALSE);
				Invalidate();
				if(m_pstBoost)
					m_pstBoost->Invalidate();
			}
		} else {

			//Otherwise the button is released.That means we should
			//know when we leave its area - and so if we are not tracking
			//this mouse leave event yet, start now!
			//
			if(!m_tracking)
			{
				TRACKMOUSEEVENT t =
				{
					sizeof(TRACKMOUSEEVENT),
					TME_LEAVE,
					m_hWnd,
					0
				};
				if(::_TrackMouseEvent(&t))
				{
					m_tracking = true;
					Invalidate();
					if(m_pstBoost)
						m_pstBoost->Invalidate();

				}
			}
		}


		//Forward this event to superclass
		CButton::OnMouseMove(nFlags, point);
	}
	catch(...)
	{
		//AddLogEntry(_T("Exception caught in CxSkinButton::OnMouseMove"));
	}
}

/*-------------------------------------------------------------------------------------
Function		: OnMouseLeave
In Parameters	:
Out	Parameters	: void
Purpose			: Handle situation when mouse cursor leaves area of this
window (button).This event might be generated ONLY
if we explicitely call 'TrackMouseEvent'.This is
signalled by setting the m_tracking flag (see the assert
precondition) - in 'OnMouseMove' method

When a mouse pointer leaves area of this button (i.e.
when this method is invoked), presumably the look of
the button changes (e.g.when hover/non-hover images are set)
and therefore we force the control to redraw.
Author			:
--------------------------------------------------------------------------------------*/

LRESULT CxSkinButton::OnMouseLeave(WPARAM, LPARAM)
{
	try
	{
		//ASSERT (m_tracking);
		m_tracking = false;
		Invalidate();
		if(m_pstBoost)
			m_pstBoost->Invalidate();


		return 0;
	}
	catch(...)
	{
		//AddLogEntry(_T("Exception caught in CxSkinButton::OnMouseLeave"));
	}
	return 0;
}

/*-------------------------------------------------------------------------------------
Function		: OnKillFocus
In Parameters	:
Out	Parameters	: void
Purpose			: If focus is killed during capture, we may no longer
have the exclusive access to user input and therefore
release it.
Such a situation might happens when the user left-clicks
this button, keeps the button down and simultaneously
presses TAB key.
Author			:
--------------------------------------------------------------------------------------*/
void CxSkinButton::OnKillFocus(CWnd *new_wnd)
{

	try
	{
		if(::GetCapture() == m_hWnd){
			::ReleaseCapture();
			ASSERT (!m_tracking);
			m_button_down = false;
		}
		CButton::OnKillFocus(new_wnd);
		if(m_pstBoost)
			m_pstBoost->Invalidate();

	}
	catch(...)
	{
		//AddLogEntry(_T("Exception caught in CxSkinButton::OnKillFocus"));
	}
}
/*-------------------------------------------------------------------------------------
Function		: OnSetFocus
In Parameters	: CWnd *old_wnd
Out	Parameters	: void
Purpose			: To Invalidate static button
Author			: Sunil Apte
--------------------------------------------------------------------------------------*/
void CxSkinButton::OnSetFocus(CWnd *new_wnd)
{

	try
	{
		CButton::OnSetFocus(new_wnd);
		if(m_pstBoost)
			m_pstBoost->Invalidate();

	}
	catch(...)
	{
		//AddLogEntry(_T("Exception caught in CxSkinButton::OnSetFocus"));
	}
}

/*-------------------------------------------------------------------------------------
Function		: OnClicked
In Parameters	:
Out	Parameters	: FALSE (do not stop in this handler - forward to parent)
Purpose			: Keep consistency of attributes of this instance before
submitting click event to the parent.

Currently NOT used.To use, umcomment line
"ON_CONTROL_REFLECT_EX(BN_CLICKED, OnClicked)" in message map
at the beginning of this file.
Author			:
--------------------------------------------------------------------------------------*/
BOOL CxSkinButton::OnClicked()
{
	try
	{
		if(::GetCapture() == m_hWnd)
		{
			::ReleaseCapture();
			ASSERT (!m_tracking);
		}
		m_button_down = false;
		return FALSE;
	}
	catch(...)
	{
		//AddLogEntry(_T("Exception caught in CxSkinButton::OnClicked"));
	}
	return FALSE;
}

/*-------------------------------------------------------------------------------------
Function		: OnRadioInfo
In Parameters	:
Out	Parameters	: WPARAM and LPARAM (LPARAM not used)
Purpose			: Handle notification, that a Button in the same group was pushed
Author			:
--------------------------------------------------------------------------------------*/
LRESULT CxSkinButton::OnRadioInfo(WPARAM wparam, LPARAM)
{
	try
	{
		if(m_Checked){	//only checked buttons need to be unchecked
			m_Checked = false;
			Invalidate();
			if(m_pstBoost)
				m_pstBoost->Invalidate();

		}
		return 0;
	}
	catch(...)
	{
		//AddLogEntry(_T("Exception caught in CxSkinButton::OnRadioInfo"));
	}
	return 0;
}

void CxSkinButton::OnKeyDown(UINT nChar, UINT nRepCnt, UINT nFlags)
{
	try
	{
		if((m_Style) &&(nChar == ' ')){ //needed stuff for check & radio buttons
			if(m_Style == BS_CHECKBOX)SetCheck(m_Checked ? 0 : 1);
			if(m_Style == BS_RADIOBUTTON)SetCheck(1);
		}

		CButton::OnKeyDown(nChar, nRepCnt, nFlags);
	}
	catch(...)
	{
		//AddLogEntry(_T("Exception caught in CxSkinButton::OnKeyDown"));
	}
}

/*-------------------------------------------------------------------------------------
Function		: SetCheck
In Parameters	:
Out	Parameters	: bool
Purpose			: Set the state of this button (pushed or not).
Works for both, Radio and CheckBox - Buttons
Author			:
--------------------------------------------------------------------------------------*/
LRESULT CxSkinButton::OnBMSetCheck(WPARAM wparam, LPARAM)
{
	try
	{
		m_Checked=wparam!=0;
		switch (m_Style)
		{
		case BS_RADIOBUTTON:
			if(m_Checked){ //uncheck the other radio buttons (in the same group)
				HWND hthis,hwnd2,hpwnd;
				hpwnd=GetParent() ->GetSafeHwnd();	//get button parent handle
				hwnd2=hthis=GetSafeHwnd();			//get this button handle
				if(hthis && hpwnd){				//consistency check
					for(;;){	//scan the buttons within the group
						hwnd2=::GetNextDlgGroupItem(hpwnd,hwnd2,0);
						//until we reach again this button
						if((hwnd2 == hthis) ||(hwnd2 == NULL))break;
						//post the uncheck message
						::PostMessage(hwnd2, WM_CXSHADE_RADIO, 0, 0);
					}
				}
			}
			break;
		case BS_PUSHBUTTON:
			m_Checked=false;
			ASSERT(false); // Must be a Check or Radio button to use this function
		}

		Invalidate();
		if(m_pstBoost)
			m_pstBoost->Invalidate();

		return 0;
	}
	catch(...)
	{
		//AddLogEntry(_T("Exception caught in CxSkinButton::OnBMSetCheck"));
	}
	return 0;
}

/*-------------------------------------------------------------------------------------
Function		: OnBMGetCheck
In Parameters	: WPARAM -
LPARAM -
Out	Parameters	: LRESULT
Purpose			: to get check status
Author			:
--------------------------------------------------------------------------------------*/
LRESULT CxSkinButton::OnBMGetCheck(WPARAM wparam, LPARAM)
{
	return m_Checked; //returns the state for check & radio buttons
}

/*-------------------------------------------------------------------------------------
Function		: OnKeyDown
In Parameters	: DWORD - alignment
Out	Parameters	: void
Purpose			: to set button text alignment
Author			:
--------------------------------------------------------------------------------------*/
void CxSkinButton::SetTextAlignment(DWORD dwAlignment, bool bBottom)
{
	m_AlignStyle = dwAlignment;
	m_bBottom = bBottom;
}
/*-------------------------------------------------------------------------------------
Function		: ShowMultilineText
In Parameters	: bool bMultiline - true, if multiline text to be displayed on button
false, otherwise.
Out	Parameters	: void
Purpose			: to set multiline text on the button
Author			: Mrudula Deshpande.
--------------------------------------------------------------------------------------*/
void CxSkinButton::ShowMultilineText(bool bMultiline)
{
	m_bShowMultiline = bMultiline;
}

/*-------------------------------------------------------------------------------------
Function		: ShowToplineText
In Parameters	: bool bTopline - true, Shifts text 3 pixels above the center.

false, otherwise.
Out	Parameters	: void
Purpose			: to set Topline text on the button
Author			: Nupur Aggarwal.
--------------------------------------------------------------------------------------*/
void CxSkinButton::ShowToplineText(bool bTopline)
{
	m_bShowTopline = bTopline;
}