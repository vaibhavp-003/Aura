/*=============================================================================
   FILE			 : XListCtrl.cpp
   ABSTRACT		 : 
   DOCUMENTS	 : 
   AUTHOR		 :
   COMPANY		 : Aura 
      COPYRIGHT NOTICE:
(C) Aura
      		Created as an unpublished copyright work.  All rights reserved.
     		 This document and the information it contains is confidential and
      		proprietary to Aura.  Hence, it may not be 
      		used, copied, reproduced, transmitted, or stored in any form or by any 
      		means, electronic, recording, photocopying, mechanical or otherwise, 
      		with out the prior written permission of Aura
   CREATION DATE   : 2/24/06
   NOTES		 :
   VERSION HISTORY : 
					Date: 18 March 2008
					Resource: Avinash Bhardwaj
					Description : changed hardcoded link to the link set in the text.
============================================================================*/

#include "stdafx.h"
#include "XListCtrl.h"

#ifndef INCLUDE_VSTS_WARNINGS
#pragma warning(disable: 6011)//Warnings mainly for CDC Pointers
#endif

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

UINT NEAR WM_XLISTCTRL_COMBO_SELECTION  = ::RegisterWindowMessage(_T("WM_XLISTCTRL_COMBO_SELECTION"));
UINT NEAR WM_XLISTCTRL_CHECKBOX_CLICKED = ::RegisterWindowMessage(_T("WM_XLISTCTRL_CHECKBOX_CLICKED"));
#ifndef IDC_HAND
#define IDC_HAND            MAKEINTRESOURCE(32649)
#endif

BEGIN_MESSAGE_MAP(CXListCtrl, CListCtrl)
	ON_NOTIFY_REFLECT_EX(NM_CLICK, OnClick)
	ON_NOTIFY_REFLECT_EX(LVN_COLUMNCLICK, OnColumnClick)
	ON_WM_CREATE()
	ON_NOTIFY_REFLECT(NM_CUSTOMDRAW, OnCustomDraw)
	ON_WM_DESTROY()
	ON_WM_LBUTTONDOWN()
	ON_WM_PAINT()
	ON_WM_SYSCOLORCHANGE()
#ifndef DO_NOT_INCLUDE_XCOMBOLIST
	ON_WM_TIMER()
	ON_REGISTERED_MESSAGE(WM_XCOMBOLIST_VK_ESCAPE, OnComboEscape)
	ON_REGISTERED_MESSAGE(WM_XCOMBOLIST_VK_RETURN, OnComboReturn)
	ON_REGISTERED_MESSAGE(WM_XCOMBOLIST_KEYDOWN, OnComboKeydown)
	ON_REGISTERED_MESSAGE(WM_XCOMBOLIST_LBUTTONUP, OnComboLButtonUp)
#endif
#ifndef NO_XLISTCTRL_TOOL_TIPS
	ON_NOTIFY_EX_RANGE(TTN_NEEDTEXTW, 0, 0xFFFF, OnToolTipText)
	ON_NOTIFY_EX_RANGE(TTN_NEEDTEXTA, 0, 0xFFFF, OnToolTipText)
#endif

END_MESSAGE_MAP()


/*-----------------------------------------------------------------------------
Function		: CXListCtrl
In Parameters	:
Out Parameters	:
Purpose		:Initialze CXListCtrl class
Author		:
-----------------------------------------------------------------------------*/
CXListCtrl::CXListCtrl()
{
	try
	{
		m_hListCtrlMgr = CreateEvent(NULL, FALSE, TRUE, NULL);

#ifndef DO_NOT_INCLUDE_XCOMBOLIST
		m_bComboIsClicked       = FALSE;
		m_nComboItem            = 0;
		m_nComboSubItem         = 0;
		m_pListBox              = NULL;
		m_bFontIsCreated        = FALSE;
		m_strInitialComboString = _T("");
#endif

		m_dwExtendedStyleX      = 0;
		m_bHeaderIsSubclassed   = FALSE;

		m_cr3DFace              = ::GetSysColor(COLOR_3DFACE);
		m_cr3DHighLight         = ::GetSysColor(COLOR_3DHIGHLIGHT);
		m_cr3DShadow            = ::GetSysColor(COLOR_3DSHADOW);
		m_crBtnFace             = ::GetSysColor(COLOR_BTNFACE);
		m_crBtnShadow           = ::GetSysColor(COLOR_BTNSHADOW);
		m_crBtnText             = ::GetSysColor(COLOR_BTNTEXT);
		m_crGrayText            = ::GetSysColor(COLOR_GRAYTEXT);
		m_crHighLight           = ::GetSysColor(COLOR_HIGHLIGHT);
		m_crHighLightText       = ::GetSysColor(COLOR_HIGHLIGHTTEXT);
		m_crWindow              = ::GetSysColor(COLOR_WINDOW);
		m_crWindowText          = ::GetSysColor(COLOR_WINDOWTEXT);
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CXListCtrl::CXListCtrl"));
	}
}

/*-----------------------------------------------------------------------------
Function		: ~CXListCtrl
In Parameters	:
Out Parameters	:
Purpose		:destruct CXListCtrl class
Author		:
-----------------------------------------------------------------------------*/
CXListCtrl::~CXListCtrl()
{
	try
	{
#ifndef DO_NOT_INCLUDE_XCOMBOLIST
		if(m_pListBox)
		{
			delete m_pListBox;
			m_pListBox = NULL;
		}
#endif
		if(m_hListCtrlMgr)
		{
			CloseHandle(m_hListCtrlMgr);
			m_hListCtrlMgr = NULL;
		}
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CXListCtrl::~CXListCtrl"));
	}
}

/*-----------------------------------------------------------------------------
Function		: PreSubclassWindow
In Parameters	:
Out Parameters	:
Purpose		:This member function is called by the framework to allow other
necessary subclassing to occur before the window is subclassed.
Author		:
-----------------------------------------------------------------------------*/
void CXListCtrl::PreSubclassWindow()
{
	try
	{
		CListCtrl::PreSubclassWindow();

		// for Dialog based applications, this is a good place
		// to subclass the header control because the OnCreate()
		// function does not get called.

		SubclassHeaderControl();
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CXListCtrl::PreSubclassWindow"));
	}
}

/*-----------------------------------------------------------------------------
Function		: OnCreate
In Parameters	: LPCREATESTRUCT :Points to a CREATESTRUCT structure that contains
information about the CWnd object being created.
Out Parameters	:int : return 0 to continue the creation of the CWnd object.
If the application returns –1, the window will be destroyed.
Purpose			:The framework calls this member function when an application requests
that the Windows window be created
Author			:
-----------------------------------------------------------------------------*/
int CXListCtrl::OnCreate(LPCREATESTRUCT lpCreateStruct)
{
	try
	{
		if(CListCtrl::OnCreate(lpCreateStruct) == -1)
		{
			ASSERT(FALSE);
			return -1;
		}

		// When the CXListCtrl object is created via a call to Create(), instead
		// of via a dialog box template, we must subclass the header control
		// window here because it does not exist when the PreSubclassWindow()
		// function is called.

		SubclassHeaderControl();

		return 0;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CXListCtrl::OnCreate"));
	}
	return 0;
}

/*-----------------------------------------------------------------------------
Function		: SubclassHeaderControl
In Parameters	:
Out Parameters	:
Purpose		: This function  subclass  header controll window
Author		:
-----------------------------------------------------------------------------*/
void CXListCtrl::SubclassHeaderControl()
{
	try
	{
		if(m_bHeaderIsSubclassed)
			return;

		// if the list control has a header control window, then
		// subclass it

		// Thanks to Alberto Gattegno and Alon Peleg  and their article
		// "A Multiline Header Control Inside a CListCtrl" for easy way
		// to determine if the header control exists.

		CHeaderCtrl* pHeader = GetHeaderCtrl();
		if(pHeader)
		{
			VERIFY(m_HeaderCtrl.SubclassWindow(pHeader->m_hWnd));
			m_bHeaderIsSubclassed = TRUE;
		}
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CXListCtrl::SubclassHeaderControl"));
	}
}

/*-----------------------------------------------------------------------------
Function		: OnClick
In Parameters	: NMHDR* : pointer to NHMDR structure
: LRESULT* :always set to 0
Out Parameters	: BOOL :always return false
Purpose		:This function handles NM_CLICK notification  message
Author		:
-----------------------------------------------------------------------------*/
BOOL CXListCtrl::OnClick(NMHDR* pNMHDR, LRESULT* pResult)
{
	try
	{
		NMLISTVIEW* pnmlv = (NMLISTVIEW*)pNMHDR;

		int nSubItem = pnmlv->iSubItem;
		int nItem = pnmlv->iItem;
		XLISTCTRLDATA *pXLCD = (XLISTCTRLDATA *)CListCtrl::GetItemData(nItem);
		if(pXLCD && pXLCD[nSubItem].bLink == TRUE)
		{
			CString csURL = GetItemText(nItem,nSubItem);
			csURL.Trim();
			ShellExecute(0, 0, csURL, 0, 0, SW_SHOWNORMAL);
		}

#ifndef DO_NOT_INCLUDE_XCOMBOLIST
		UnpressComboButton();
#endif
		*pResult = 0;
		return FALSE;		// return FALSE to send message to parent also -
		// NOTE:  MSDN documentation is incorrect
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CXListCtrl::OnClick"));
	}
	return FALSE;
}

/*-----------------------------------------------------------------------------
Function		: OnCustomDraw
In Parameters	: NMHDR* : pointer to NHMDR structure
: LRESULT* : its value depend on message
Out Parameters	:
Purpose		:This function handles NM_CUSTOMDRAW notification message.
Author		:
-----------------------------------------------------------------------------*/
void CXListCtrl::OnCustomDraw(NMHDR* pNMHDR, LRESULT* pResult)
{

	try
	{
		NMLVCUSTOMDRAW* pLVCD = reinterpret_cast<NMLVCUSTOMDRAW*>(pNMHDR);

		// Take the default processing unless we set this to something else below.
		*pResult = CDRF_DODEFAULT;

		// First thing - check the draw stage.If it's the control's prepaint
		// stage, then tell Windows we want messages for every item.

		if(pLVCD->nmcd.dwDrawStage == CDDS_PREPAINT)
		{
			*pResult = CDRF_NOTIFYITEMDRAW;
		}
		else if(pLVCD->nmcd.dwDrawStage == CDDS_ITEMPREPAINT)
		{
			// This is the notification message for an item. We'll request
			// notifications before each subitem's prepaint stage.

			*pResult = CDRF_NOTIFYSUBITEMDRAW;
		}
		else if(pLVCD->nmcd.dwDrawStage == (CDDS_ITEMPREPAINT | CDDS_SUBITEM))
		{
			// This is the prepaint stage for a subitem.Here's where we set the
			// item's text and background colors.Our return value will tell
			// Windows to draw the subitem itself, but it will use the new colors
			// we set here.

			int nItem = static_cast<int> (pLVCD->nmcd.dwItemSpec);
			int nSubItem = pLVCD->iSubItem;

			XLISTCTRLDATA *pXLCD = (XLISTCTRLDATA *)pLVCD->nmcd.lItemlParam;
			//ASSERT(pXLCD);

			COLORREF crText  = m_crWindowText;
			COLORREF crBkgnd = m_crWindow;

			if(pXLCD)
			{
				crText  = pXLCD[nSubItem].crText;
				crBkgnd = pXLCD[nSubItem].crBackground;

				if(!pXLCD[0].bEnabled)
					crText = m_crGrayText;
			}


			// store the colors back in the NMLVCUSTOMDRAW struct
			pLVCD->clrText = crText;
			pLVCD->clrTextBk = crBkgnd;

			CDC* pDC = CDC::FromHandle(pLVCD->nmcd.hdc);
			CRect rect;
			GetSubItemRect(nItem, nSubItem, LVIR_BOUNDS, rect);

			rect.bottom = rect.bottom - 2;
			rect.top = rect.top + 2;
			if(pXLCD && (pXLCD[nSubItem].bShowProgress))
			{
				DrawProgress(nItem, nSubItem, pDC, crText, crBkgnd, rect, pXLCD);

				*pResult = CDRF_SKIPDEFAULT;	// We've painted everything.
			}
#ifndef DO_NOT_INCLUDE_XCOMBOLIST
			else if(pXLCD && (pXLCD[nSubItem].bCombo))
			{
				if(GetItemState(nItem, LVIS_SELECTED))
					DrawComboBox(nItem, nSubItem, pDC, crText, crBkgnd, rect, pXLCD);
				else
				{
					DrawText(nItem, nSubItem, pDC, crText, crBkgnd, rect, pXLCD);
				}

				*pResult = CDRF_SKIPDEFAULT;	// We've painted everything.
			}
#endif
			else if(pXLCD && (pXLCD[nSubItem].nCheckedState != -1))
			{
				DrawCheckbox(nItem, nSubItem, pDC, crText, crBkgnd, rect, pXLCD);

				*pResult = CDRF_SKIPDEFAULT;	// We've painted everything.
			}
			else
			{
				rect.left += DrawImage(nItem, nSubItem, pDC, crText, crBkgnd, rect, pXLCD);

				DrawText(nItem, nSubItem, pDC, crText, crBkgnd, rect, pXLCD);

				*pResult = CDRF_SKIPDEFAULT;	// We've painted everything.
			}
		}
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CXListCtrl::OnCustomDraw"));
	}
}

/*-----------------------------------------------------------------------------
Function		: DrawProgress
In Parameters	: int : Index of the subitem's parent item.
: int :  index of the subitem.
: CDC* : pointer to CDC class
: COLORREF : color for text
: COLORREF: color for background
: CRect& :Reference to a CRect object that contains the
coordinates of the subitem's bounding rectangle.
: XLISTCTRLDATA* : ponter to XLISTCTRLDATA structure
Out Parameters	:
Purpose		: this fuction draws progress bar
Author		:
-----------------------------------------------------------------------------*/
void CXListCtrl::DrawProgress(int nItem, int nSubItem, CDC *pDC, COLORREF crText,
							  COLORREF crBkgnd, CRect& rect, XLISTCTRLDATA *pXLCD)
{
	try
	{
		UNUSED_ALWAYS(nItem);

		ASSERT(pDC);
		//		ASSERT(pXLCD);

		rect.bottom -= 1;
		rect.left += 1;		// leave margin in case row is highlighted
		rect.right -= 2;

		// draw border
		CPen graypen(PS_SOLID, 1, m_crBtnShadow);
		CPen *pOldPen = pDC->SelectObject(&graypen);

		pDC->MoveTo(rect.left, rect.bottom);
		pDC->LineTo(rect.right+1, rect.bottom);

		pDC->MoveTo(rect.left, rect.top);
		pDC->LineTo(rect.right, rect.top);

		pDC->MoveTo(rect.left, rect.top);
		pDC->LineTo(rect.left, rect.bottom);

		pDC->MoveTo(rect.right, rect.top);
		pDC->LineTo(rect.right, rect.bottom);

		// fill interior with light gray
		CRect InteriorRect;
		InteriorRect = rect;
		InteriorRect.left += 1;
		InteriorRect.top += 1;
		pDC->FillSolidRect(InteriorRect, RGB(244,240,231));

		// finish drawing border
		CPen blackpen(PS_SOLID, 1, RGB(0,0,0));
		pDC->SelectObject(&blackpen);

		pDC->MoveTo(rect.left+1, rect.top+1);
		pDC->LineTo(rect.right, rect.top+1);

		pDC->MoveTo(rect.left+1, rect.top+1);
		pDC->LineTo(rect.left+1, rect.bottom);

		pDC->SelectObject(pOldPen);

		if(pXLCD[nSubItem].nProgressPercent > 0)
		{
			// draw progress bar and text

			CRect LeftRect, RightRect;
			LeftRect = rect;
			LeftRect.left += 2;
			LeftRect.top += 2;
			RightRect = LeftRect;
			int w = (LeftRect.Width()* pXLCD[nSubItem].nProgressPercent)/ 100;
			LeftRect.right = LeftRect.left + w;
			RightRect.left = LeftRect.right + 1;
			pDC->FillSolidRect(LeftRect, RGB(82,218,85));

			if(pXLCD[nSubItem].bShowProgressMessage)
			{
				CString str, format;
				format = pXLCD[nSubItem].strProgressMessage;
				if(format.IsEmpty())
					str.Format(_T("%d%%"), pXLCD[nSubItem].nProgressPercent);
				else
					str.Format(format, pXLCD[nSubItem].nProgressPercent);

				pDC->SetBkMode(TRANSPARENT);

				CRect TextRect;
				TextRect = rect;
				TextRect.DeflateRect(1, 1);
				TextRect.top += 1;

				CRgn rgn;
				rgn.CreateRectRgn(LeftRect.left, LeftRect.top, LeftRect.right, LeftRect.bottom);
				pDC->SelectClipRgn(&rgn);
				pDC->SetTextColor(crBkgnd);
				TextRect.top -=2;
				pDC->DrawText(str, &TextRect, DT_CENTER | DT_VCENTER | DT_SINGLELINE);

				rgn.DeleteObject();
				rgn.CreateRectRgn(RightRect.left, RightRect.top, RightRect.right, RightRect.bottom);
				pDC->SelectClipRgn(&rgn);
				pDC->SetTextColor(crText);
				pDC->DrawText(str, &TextRect, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
				rgn.DeleteObject();
				pDC->SelectClipRgn(NULL);
			}
		}
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CXListCtrl::DrawProgress"));
	}
}

#ifndef DO_NOT_INCLUDE_XCOMBOLIST

/*-----------------------------------------------------------------------------
Function		: DrawComboBox
In Parameters	: int : Index of the subitem's parent item.
: int :  index of the subitem.
: CDC* : pointer to CDC class
: COLORREF : color for text
: COLORREF: color for background
: CRect& :Reference to a CRect object that contains the
coordinates of the subitem's bounding rectangle.
: XLISTCTRLDATA* : ponter to XLISTCTRLDATA structure
Out Parameters	:
Purpose			:This function draws Combo box
Author			:
-----------------------------------------------------------------------------*/
void CXListCtrl::DrawComboBox(int nItem, int nSubItem, CDC *pDC, COLORREF crText,
							  COLORREF crBkgnd, CRect& rect, XLISTCTRLDATA *pXLCD)
{
	try
	{
		UNUSED_ALWAYS(crText);
		UNUSED_ALWAYS(crBkgnd);

		ASSERT(pDC);
		ASSERT(pXLCD);

#ifdef _DEBUG
		DWORD dwExStyle = GetExtendedStyle();
		if((dwExStyle & LVS_EX_FULLROWSELECT) == 0)
		{
			TRACE(_T("XListCtrl: combo boxes require LVS_EX_FULLROWSELECT style\n"));
			ASSERT(FALSE);
		}
#endif

		rect.bottom += 1;	// bottom edge is white, so this doesn't matter
		rect.left += 1;		// leave margin in case row is highlighted
		rect.right -= 2;

		// draw border

		CPen pen(PS_SOLID, 1, m_crBtnShadow);
		CPen *pOldPen = pDC->SelectObject(&pen);

		pDC->MoveTo(rect.left, rect.bottom-2);
		pDC->LineTo(rect.right, rect.bottom-2);

		pDC->MoveTo(rect.left, rect.top);
		pDC->LineTo(rect.right, rect.top);

		pDC->MoveTo(rect.left, rect.top);
		pDC->LineTo(rect.left, rect.bottom-2);

		pDC->MoveTo(rect.right, rect.top);
		pDC->LineTo(rect.right, rect.bottom-1);

		CPen blackpen(PS_SOLID, 1, RGB(0,0,0));
		pDC->SelectObject(&blackpen);

		// fill interior with white
		CRect InteriorRect;
		InteriorRect = rect;
		InteriorRect.DeflateRect(2, 2);
		pDC->FillSolidRect(InteriorRect, RGB(255,255,255));

		// set arrow rect
		CRect ArrowRect;
		ArrowRect = rect;
		ArrowRect.right += 1;
		ArrowRect.left = ArrowRect.right - ArrowRect.Height();
		ArrowRect.DeflateRect(2, 2);

		CString str;
		str = GetItemText(nItem, nSubItem);

		if(str.IsEmpty())
		{
			// subitem text is empty, try to get from listbox strings
			if(pXLCD[nSubItem].psa)
			{
				int index = 0;
				if((pXLCD[nSubItem].nInitialComboSel >= 0) &&
					(pXLCD[nSubItem].psa->GetSize() > pXLCD[nSubItem].nInitialComboSel))
				{
					index = pXLCD[nSubItem].nInitialComboSel;
					str = pXLCD[nSubItem].psa->GetAt(index);
					SetItemText(nItem, nSubItem, str);
				}
			}
		}

		if(!str.IsEmpty())
		{
			// draw text
			CRect TextRect;
			TextRect = rect;
			TextRect.top -= 1;
			TextRect.left += 2;
			TextRect.right = ArrowRect.left - 1;

			pDC->SetBkMode(TRANSPARENT);
			COLORREF cr = m_crWindowText;
			if(!pXLCD[0].bEnabled)
				cr = m_crGrayText;
			pDC->SetTextColor(cr);
			pDC->SetBkColor(m_crWindow);
			UINT nFormat = DT_LEFT | DT_VCENTER | DT_SINGLELINE;
			pDC->DrawText(str, &TextRect, nFormat);
		}

		if(!pXLCD[nSubItem].bComboIsClicked)
		{
			// draw depressed combobox
			pDC->DrawEdge(&ArrowRect, EDGE_RAISED, BF_RECT);
			ArrowRect.DeflateRect(2, 2);
			pDC->FillSolidRect(ArrowRect, m_crBtnFace);

			// draw the downarrow using blackpen
			int x = ArrowRect.left + 1;
			int y = ArrowRect.top + 2;
			int k = 5;
			for (int i = 0; i < 3; i++)
			{
				pDC->MoveTo(x, y);
				pDC->LineTo(x+k, y);
				x++;
				y++;
				k -= 2;
			}
		}
		else
		{
			// draw normal combobox
			m_rectComboButton = ArrowRect;
			CBrush brush(m_cr3DShadow);
			pDC->FrameRect(&ArrowRect, &brush);
			ArrowRect.DeflateRect(1, 1);
			pDC->FillSolidRect(ArrowRect, m_crBtnFace);

			// draw the downarrow using blackpen
			int x = ArrowRect.left + 3;
			int y = ArrowRect.top + 4;
			int k = 5;
			for (int i = 0; i < 3; i++)
			{
				pDC->MoveTo(x, y);
				pDC->LineTo(x+k, y);
				x++;
				y++;
				k -= 2;
			}

			// show listbox if not already shown
			if(!m_pListBox)
			{
				// create and populate the combo's listbox
				m_pListBox = new CXComboList(this);
				ASSERT(m_pListBox);

				if(m_pListBox)
				{
					m_nComboItem = nItem;
					m_nComboSubItem = nSubItem;

					m_rectComboList = rect;
					m_rectComboList.right -= 1;
					m_rectComboList.top += rect.Height() - 1;

					m_rectComboList.bottom = m_rectComboList.top +
						(pXLCD[nSubItem].nComboListHeight)* (rect.Height() - 2);
					ClientToScreen(&m_rectComboList);

					CString szClassName = AfxRegisterWndClass(CS_CLASSDC|CS_SAVEBITS,
						LoadCursor(NULL, IDC_ARROW));

					BOOL bSuccess = m_pListBox->CreateEx(0, szClassName, _T(""),
						WS_POPUP | WS_VISIBLE | WS_BORDER,
						m_rectComboList, this, 0, NULL);

					if(bSuccess)
					{
						m_strInitialComboString = _T("");

						if(!m_bFontIsCreated)
						{
							// use font from list control
							CFont *font = pDC->GetCurrentFont();
							if(font)
							{
								LOGFONT lf;
								font->GetLogFont(&lf);
								m_ListboxFont.CreateFontIndirect(&lf);
								m_bFontIsCreated = TRUE;
							}
						}

						if(m_bFontIsCreated)
							m_pListBox->SetFont(&m_ListboxFont, FALSE);

						if(pXLCD[nSubItem].psa)
						{
							CString s;
							for (int i = 0; i < pXLCD[nSubItem].psa->GetSize(); i++)
							{
								s = pXLCD[nSubItem].psa->GetAt(i);
								if(!s.IsEmpty())
									m_pListBox->AddString(s);
							}
						}

						int index = 0;
						if(str.IsEmpty())
						{
							// str is empty, try to get from first listbox string
							if(m_pListBox->GetCount() > 0)
								m_pListBox->GetText(0, str);

							SetItemText(nItem, nSubItem, str);
						}
						else
						{
							// set listbox selection from subitem text
							index = m_pListBox->FindStringExact(-1, str);
							if(index == LB_ERR)
								index = 0;
						}
						m_pListBox->SetCurSel(index);
						m_pListBox->GetText(index, m_strInitialComboString);
						m_pListBox->SetActive(11);
					}
				}
			}
		}
		pDC->SelectObject(pOldPen);
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CXListCtrl::DrawComboBox"));
	}
}

#endif

/*-----------------------------------------------------------------------------
Function		: DrawCheckbox
In Parameters	: int : Index of the subitem's parent item.
: int :  index of the subitem.
: CDC* : pointer to CDC class
: COLORREF : color for text
: COLORREF: color for background
: CRect& :Reference to a CRect object that contains the
coordinates of the subitem's bounding rectangle.
: XLISTCTRLDATA* : ponter to XLISTCTRLDATA structure
Out Parameters	:
Purpose			: This function draw chwckbox for given subitem
Author			:
-----------------------------------------------------------------------------*/
void CXListCtrl::DrawCheckbox(int nItem, int nSubItem, CDC *pDC, COLORREF crText,
							  COLORREF crBkgnd, CRect& rect, XLISTCTRLDATA *pXLCD)
{
	try
	{
		ASSERT(pDC);
		ASSERT(pXLCD);

		GetDrawColors(nItem, nSubItem, crText, crBkgnd);

		pDC->FillSolidRect(&rect, crBkgnd);

		CRect chkboxrect;
		chkboxrect = rect;
		chkboxrect.bottom -= 1;
		chkboxrect.left += 9;		// line up checkbox with header checkbox
		chkboxrect.right = chkboxrect.left + chkboxrect.Height();	// width = height

		CString str;
		str = GetItemText(nItem, nSubItem);

		if(str.IsEmpty())
		{
			// center the checkbox
			chkboxrect.left = rect.left + rect.Width()/2 - chkboxrect.Height()/2 - 1;
			chkboxrect.right = chkboxrect.left + chkboxrect.Height();
		}

		// fill rect around checkbox with white
		pDC->FillSolidRect(&chkboxrect, m_crWindow);

		chkboxrect.left += 1;

		// draw border
		pDC->DrawEdge(&chkboxrect, EDGE_SUNKEN, BF_RECT);

		if(pXLCD[nSubItem].nCheckedState == 1)
		{
			CPen *pOldPen = NULL;

			CPen graypen(PS_SOLID, 1, m_crGrayText);
			CPen blackpen(PS_SOLID, 1, RGB(0,0,0));

			if(pXLCD[0].bEnabled)
				pOldPen = pDC->SelectObject(&blackpen);
			else
				pOldPen = pDC->SelectObject(&graypen);

			// draw the checkmark
			int x = chkboxrect.left + 9;
			ASSERT(x < chkboxrect.right);
			int y = chkboxrect.top + 3;
			int i;
			for (i = 0; i < 4; i++)
			{
				pDC->MoveTo(x, y);
				pDC->LineTo(x, y+3);
				x--;
				y++;
			}
			for (i = 0; i < 3; i++)
			{
				pDC->MoveTo(x, y);
				pDC->LineTo(x, y+3);
				x--;
				y--;
			}

			if(pOldPen)
				pDC->SelectObject(pOldPen);
		}

		if(!str.IsEmpty())
		{
			pDC->SetBkMode(TRANSPARENT);
			pDC->SetTextColor(crText);
			pDC->SetBkColor(crBkgnd);
			CRect textrect;
			textrect = rect;
			textrect.left = chkboxrect.right + 4;

			pDC->DrawText(str, &textrect, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
		}
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CXListCtrl::DrawCheckbox"));
	}
}

/*-----------------------------------------------------------------------------
Function		: GetDrawColors
In Parameters	: int : Index of the subitem's parent item.
: int :  index of the subitem.
: COLORREF : color for text
: COLORREF: color for background
Out Parameters	:
Purpose		:This function retrives the text and backgroun color for given subitem
Author		:
-----------------------------------------------------------------------------*/
void CXListCtrl::GetDrawColors(int nItem, int nSubItem, COLORREF& colorText, COLORREF& colorBkgnd)
{
	try
	{
		DWORD dwStyle    = GetStyle();
		DWORD dwExStyle  = GetExtendedStyle();

		COLORREF crText  = colorText;
		COLORREF crBkgnd = colorBkgnd;

		if(GetItemState(nItem, LVIS_SELECTED))
		{
			if(dwExStyle & LVS_EX_FULLROWSELECT)
			{
				// selected?  if so, draw highlight background
				crText  = m_crHighLightText;
				crBkgnd = m_crHighLight;

				// has focus?  if not, draw gray background
				if(m_hWnd != ::GetFocus())
				{
					if(dwStyle & LVS_SHOWSELALWAYS)
					{
						crText  = m_crWindowText;
						crBkgnd = m_crBtnFace;
					}
					else
					{
						crText  = colorText;
						crBkgnd = colorBkgnd;
					}
				}
			}
			else	// not full row select
			{
				if(nSubItem == 0)
				{
					// selected?  if so, draw highlight background
					crText  = m_crHighLightText;
					crBkgnd = m_crHighLight;

					// has focus?  if not, draw gray background
					if(m_hWnd != ::GetFocus())
					{
						if(dwStyle & LVS_SHOWSELALWAYS)
						{
							crText  = m_crWindowText;
							crBkgnd = m_crBtnFace;
						}
						else
						{
							crText  = colorText;
							crBkgnd = colorBkgnd;
						}
					}
				}
			}
		}

		colorText = crText;
		colorBkgnd = crBkgnd;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CXListCtrl::GetDrawColors"));
	}
}

/*-----------------------------------------------------------------------------
Function		: DrawImage
In Parameters	: int : Index of the subitem's parent item.
: int :  index of the subitem.
: CDC* : pointer to CDC class
: COLORREF : color for text
: COLORREF: color for background
: CRect& :Reference to a CRect object that contains the
coordinates of the subitem's bounding rectangle.
: XLISTCTRLDATA* : ponter to XLISTCTRLDATA structure
Out Parameters	: int : width of image if successfully drawn else 0
Purpose			: This function will draw image for subitem
Author			:
-----------------------------------------------------------------------------*/
int CXListCtrl::DrawImage(int nItem, int nSubItem, CDC* pDC, COLORREF crText, COLORREF crBkgnd,
						  CRect rect,XLISTCTRLDATA *pXLCD)
{
	try
	{
		GetDrawColors(nItem, nSubItem, crText, crBkgnd);

		pDC->FillSolidRect(&rect, crBkgnd);

		int nWidth = 0;
		rect.left += m_HeaderCtrl.GetSpacing();

		CImageList* pImageList = GetImageList(LVSIL_SMALL);
		if(pImageList)
		{
			SIZE sizeImage;
			sizeImage.cx = sizeImage.cy = 0;
			IMAGEINFO info;

			int nImage = -1;
			if(pXLCD)
				nImage = pXLCD[nSubItem].nImage;

			if(nImage == -1)
				return 0;

			if(pImageList->GetImageInfo(nImage, &info))
			{
				sizeImage.cx = info.rcImage.right - info.rcImage.left;
				sizeImage.cy = info.rcImage.bottom - info.rcImage.top;
			}

			if(nImage >= 0)
			{
				if(rect.Width() > 0)
				{
					POINT point;

					point.y = rect.CenterPoint().y - (sizeImage.cy >> 1);
					point.x = rect.left;

					SIZE size;
					size.cx = rect.Width()< sizeImage.cx ? rect.Width(): sizeImage.cx;
					size.cy = rect.Height()< sizeImage.cy ? rect.Height(): sizeImage.cy;

					// save image list background color
					COLORREF rgb = pImageList->GetBkColor();

					// set image list background color
					pImageList->SetBkColor(crBkgnd);
					pImageList->DrawIndirect(pDC, nImage, point, size, CPoint(0, 0));
					pImageList->SetBkColor(rgb);

					nWidth = sizeImage.cx + m_HeaderCtrl.GetSpacing();
				}
			}
		}

		return nWidth;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CXListCtrl::DrawImage"));
	}
	return 0;
}

/*-----------------------------------------------------------------------------
Function		: DrawText
In Parameters	: int : Index of the subitem's parent item.
: int :  index of the subitem.
: CDC* : pointer to CDC class
: COLORREF : color for text
: COLORREF: color for background
: CRect& :Reference to a CRect object that contains the
coordinates of the subitem's bounding rectangle.
: XLISTCTRLDATA* : ponter to XLISTCTRLDATA structure
Out Parameters	:
Purpose		:This Function Draw the label of subItem
Author		:
-----------------------------------------------------------------------------*/
void CXListCtrl::DrawText(int nItem, int nSubItem, CDC *pDC, COLORREF crText,
						  COLORREF crBkgnd, CRect& rect, XLISTCTRLDATA *pXLCD)
{
	try
	{
		ASSERT(pDC);
		GetDrawColors(nItem, nSubItem, crText, crBkgnd);

		pDC->FillSolidRect(&rect, crBkgnd);

		CString str;
		str = GetItemText(nItem, nSubItem);

		if(!str.IsEmpty())
		{
			// get text justification
			HDITEM hditem;
			hditem.mask = HDI_FORMAT;
			m_HeaderCtrl.GetItem(nSubItem, &hditem);
			int nFmt = hditem.fmt & HDF_JUSTIFYMASK;
			UINT nFormat = DT_VCENTER | DT_SINGLELINE;
			if(nFmt == HDF_CENTER)
				nFormat |= DT_CENTER;
			else if(nFmt == HDF_LEFT)
				nFormat |= DT_LEFT;
			else
				nFormat |= DT_RIGHT;

			CFont *pOldFont = NULL;
			CFont boldfont;

			// check if bold specified for subitem
			if(pXLCD && pXLCD[nSubItem].bBold)
			{
				CFont *font = pDC->GetCurrentFont();
				if(font)
				{
					LOGFONT lf;
					font->GetLogFont(&lf);
					lf.lfWeight = FW_BOLD;
					boldfont.CreateFontIndirect(&lf);
					pOldFont = pDC->SelectObject(&boldfont);
				}
			}
			//Check if hyperlink specified for item
			if(pXLCD && pXLCD[nSubItem].bLink)
			{
				CFont *font = pDC->GetCurrentFont();
				if(font)
				{
					LOGFONT lf;
					font->GetLogFont(&lf);
					lf.lfUnderline = TRUE;
					boldfont.CreateFontIndirect(&lf);
					pOldFont = pDC->SelectObject(&boldfont);
				}
				m_hCursorHotSpot	= AfxGetApp() ->LoadStandardCursor(IDC_HAND); //Icon hand
				SetCursor(m_hCursorHotSpot);

			}

			pDC->SetBkMode(TRANSPARENT);
			pDC->SetTextColor(crText);
			pDC->SetBkColor(crBkgnd);
			rect.top -=4;
			pDC->DrawText(str, &rect, nFormat);
			if(pOldFont)
				pDC->SelectObject(pOldFont);
		}
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CXListCtrl::DrawText"));
	}
}

/*-----------------------------------------------------------------------------
Function		: GetSubItemRect
In Parameters	: int : Index of the subitem's parent item.
: int :  index of the subitem.
: int : Determines the portion of the bounding rectangle
to be retrieved
: CRect : Reference to a CRect object that contains the
coordinates of the subitem's bounding rectangle.
Out Parameters	:BOOL : return true if successfull otherwise false
Purpose			:Retrieves the bounding rectangle of an item in a list view control.
Author			:
-----------------------------------------------------------------------------*/
BOOL CXListCtrl::GetSubItemRect(int nItem, int nSubItem, int nArea, CRect& rect)
{
	try
	{
		ASSERT(nItem >= 0);
		ASSERT(nItem < GetItemCount());
		if((nItem < 0) || nItem >= GetItemCount())
			return FALSE;
		ASSERT(nSubItem >= 0);
		ASSERT(nSubItem < GetColumns());
		if((nSubItem < 0) || nSubItem >= GetColumns())
			return FALSE;

		BOOL bRC = CListCtrl::GetSubItemRect(nItem, nSubItem, nArea, rect);

		// if nSubItem == 0, the rect returned by CListCtrl::GetSubItemRect
		// is the entire row, so use left edge of second subitem

		if(nSubItem == 0)
		{
			if(GetColumns() > 1)
			{
				CRect rect1;
				bRC = GetSubItemRect(nItem, 1, LVIR_BOUNDS, rect1);
				rect.right = rect1.left;
			}
		}
		return bRC;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CXListCtrl::GetSubItemRect"));
	}
	return FALSE;
}

/*-----------------------------------------------------------------------------
Function		: OnLButtonDown
In Parameters	: UINT : Indicates whether various virtual keys are down
: CPoint : Specifies the x- and y-coordinate of the cursor.
Out Parameters:
Purpose			:This function is called when  the user presses the left mouse button.
Author			:
-----------------------------------------------------------------------------*/
void CXListCtrl::OnLButtonDown(UINT nFlags, CPoint point)
{
	try
	{
		TRACE(_T("in CXListCtrl::OnLButtonDown\n"));

		int nItem = -1;
		CRect rect;

		int i;
		for (i = 0; i < GetItemCount(); i++)
		{
			if(CListCtrl::GetItemRect(i, &rect, LVIR_BOUNDS))
			{
				if(rect.PtInRect(point))
				{
					nItem = i;
					break;
				}
			}
		}

		if(nItem == -1)
		{
#ifndef DO_NOT_INCLUDE_XCOMBOLIST
			if(m_pListBox)
				OnComboEscape(0, 0);
#endif
		}
		else
		{
			XLISTCTRLDATA *pXLCD = (XLISTCTRLDATA *)CListCtrl::GetItemData(nItem);
			if(!pXLCD)
			{
				return;
			}

			if(!pXLCD[0].bEnabled)
				return;

			// CRect rect; // Not required, already declared

			int nSubItem = -1;

			// check if a subitem checkbox was clicked
			for (i = 0; i < GetColumns(); i++)
			{
				GetSubItemRect(nItem, i, LVIR_BOUNDS, rect);
				if(rect.PtInRect(point))
				{
					nSubItem = i;
					break;
				}
			}

			if(nSubItem == -1)
			{
				// -1 = no checkbox for this subitem

#ifndef DO_NOT_INCLUDE_XCOMBOLIST
				if(m_pListBox)
				{
					OnComboEscape(0, 0);
				}
#endif
			}
			else
			{
				if(pXLCD[nSubItem].nCheckedState >= 0)
				{
					int nChecked = pXLCD[nSubItem].nCheckedState;

					nChecked = (nChecked == 0)? 1 : 0;

					pXLCD[nSubItem].nCheckedState = nChecked;

					UpdateSubItem(nItem, nSubItem);

					CWnd *pWnd = GetParent();
					if(!pWnd)
						pWnd = GetOwner();
					if(pWnd && ::IsWindow(pWnd->m_hWnd))
						pWnd->SendMessage(WM_XLISTCTRL_CHECKBOX_CLICKED,
						nItem, nSubItem);

					// now update checkbox in header

					// -1 = no checkbox in column header
					if(GetHeaderCheckedState(nSubItem) != XHEADERCTRL_NO_IMAGE)
					{
						int nCheckedCount = CountCheckedItems(nSubItem);

						if(nCheckedCount == GetItemCount())
							SetHeaderCheckedState(nSubItem, XHEADERCTRL_CHECKED_IMAGE);
						else
							SetHeaderCheckedState(nSubItem, XHEADERCTRL_UNCHECKED_IMAGE);
					}
				}
#ifndef DO_NOT_INCLUDE_XCOMBOLIST
				else if(pXLCD[nSubItem].bCombo)
				{
					if(m_pListBox)
					{
						m_pListBox->DestroyWindow();
						delete m_pListBox;
						m_pListBox = NULL;
					}

					rect.left = rect.right - rect.Height();
					if(point.x >= rect.left && point.y <= rect.right)
					{
						pXLCD[nSubItem].bComboIsClicked = TRUE;
						m_bComboIsClicked = TRUE;
						m_nComboItem = nItem;
						m_nComboSubItem = nSubItem;
						UpdateSubItem(nItem, nSubItem);
						SetTimer(1, 100, NULL);
					}
				}
				else if(m_pListBox)
				{
					OnComboEscape(0, 0);
				}
#endif
			}
		}

		CListCtrl::OnLButtonDown(nFlags, point);
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CXListCtrl::OnLButtonDown"));
	}
}

/*-----------------------------------------------------------------------------
Function		: OnPaint
In Parameters	:
Out Parameters	:
Purpose			: The framework calls this member function when Windows or
an application makes a request to repaint a portion of an
application's window.User can put check here for any necessary
internal repainting
Author		:
-----------------------------------------------------------------------------*/
void CXListCtrl::OnPaint()
{
	try
	{
		Default();
		if(GetItemCount()<= 0)
		{
			CDC* pDC = GetDC();
			int nSavedDC = pDC->SaveDC();

			CRect rc;
			GetWindowRect(&rc);
			ScreenToClient(&rc);
			CHeaderCtrl* pHC = GetHeaderCtrl();
			if(pHC != NULL)
			{
				CRect rcH;
				pHC->GetItemRect(0, &rcH);
				rc.top += rcH.bottom;
			}
			rc.top += 10;
			CString strText;
			strText = _T("There are no items to show in this view.");

			COLORREF crText = m_crWindowText;
			COLORREF crBkgnd = m_crWindow;

			CBrush brush(crBkgnd);
			pDC->FillRect(rc, &brush);

			pDC->SetTextColor(crText);
			pDC->SetBkColor(crBkgnd);
			pDC->SelectStockObject(ANSI_VAR_FONT);
			pDC->DrawText(strText, -1, rc, DT_CENTER | DT_WORDBREAK | DT_NOPREFIX | DT_NOCLIP);
			pDC->RestoreDC(nSavedDC);
			ReleaseDC(pDC);
		}
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CXListCtrl::OnPaint"));
	}
}

/*-----------------------------------------------------------------------------
Function		: InsertItem
In Parameters	: LVITEM : pointer to LVITEM
Out Parameters	: int : index if item is successfully inserted otherwise -1
Purpose		:This function insert a item as well as create XLISTCTRLDATA structure
for that item.
Author		:
-----------------------------------------------------------------------------*/
int CXListCtrl::InsertItem(const LVITEM* pItem)
{
	try
	{
		WaitForSingleObject(m_hListCtrlMgr, INFINITE);
		ASSERT(pItem->iItem >= 0);
		if(pItem->iItem < 0)
		{
			SetEvent(m_hListCtrlMgr);
			return -1;
		}

		int index = CListCtrl::InsertItem(pItem);

		if(index < 0)
		{
			SetEvent(m_hListCtrlMgr);
			return index;
		}

		XLISTCTRLDATA *pXLCD = new XLISTCTRLDATA [GetColumns()];
		if(!pXLCD)
		{
			SetEvent(m_hListCtrlMgr);
			return -1;
		}

		pXLCD[0].crText       = m_crWindowText;
		pXLCD[0].crBackground = m_crWindow;
		pXLCD[0].nImage       = pItem->iImage;

		CListCtrl::SetItemData(index, reinterpret_cast<DWORD_PTR>(pXLCD));

		SetEvent(m_hListCtrlMgr);
		return index;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CXListCtrl::InsertItem"));
	}
	SetEvent(m_hListCtrlMgr);
	return -1;
}

/*-----------------------------------------------------------------------------
Function		: InsertItem
In Parameters	: int : index of item to be inserted in list view control
: LPCTSTR :ddress of a string containing the item's label
Out Parameters	: int : index if item is successfully inserted otherwise -1
Purpose		: This function insert a Item in list View control
Author		:
-----------------------------------------------------------------------------*/
int CXListCtrl::InsertItem(int nItem, LPCTSTR lpszItem,  int iImage)
{
	try
	{
		ASSERT(nItem >= 0);
		if(nItem < 0)
			return -1;

		return InsertItem(nItem, lpszItem, m_crWindowText, m_crWindow, iImage);
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CXListCtrl::InsertItem"));
	}
	return -1;
}

/*-----------------------------------------------------------------------------
Function		: InsertItem
In Parameters	: int : Index of Item to be inserted
: LPCTSTR : Address of a string containing the item's label
: COLORREF : text color of Item
: COLORREF : background Color for item
Out Parameters	: int : index if successfully inserted otherwise -1.
Purpose			: This Function Insert the new item in ListView Control
Author			:
-----------------------------------------------------------------------------*/
int CXListCtrl::InsertItem(int nItem, LPCTSTR lpszItem, COLORREF crText, COLORREF crBackground, int iImage)
{
	try
	{
		ASSERT(nItem >= 0);
		if(nItem < 0)
			return -1;

		int index = CListCtrl::InsertItem(nItem, lpszItem);

		if(index < 0)
			return index;

		XLISTCTRLDATA *pXLCD = new XLISTCTRLDATA [GetColumns()];
		if(!pXLCD)
			return -1;

		pXLCD[0].crText       = crText;
		pXLCD[0].crBackground = crBackground;
		pXLCD[0].nImage       = iImage;

		CListCtrl::SetItemData(index, reinterpret_cast<DWORD_PTR>(pXLCD));

		return index;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CXListCtrl::InsertItem"));
	}
	return -1;
}

/*-----------------------------------------------------------------------------
Function		: SetItem
In Parameters	: LVITEM * :pointer to LVITEM structure
Out Parameters	: int : TRUE if successfully set the attribute for an item else
false
Purpose			:This function set the  attributes of a list-view item.
Author			:
-----------------------------------------------------------------------------*/
int CXListCtrl::SetItem(const LVITEM* pItem)
{
	try
	{
		ASSERT(pItem->iItem >= 0);
		if(pItem->iItem < 0)
		{
			return -1;
		}

		BOOL rc = CListCtrl::SetItem(pItem);

		if(!rc)
		{
			return FALSE;
		}

		XLISTCTRLDATA *pXLCD = (XLISTCTRLDATA *)CListCtrl::GetItemData(pItem->iItem);
		if(pXLCD)
		{
			pXLCD[pItem->iSubItem].nImage = pItem->iImage;
			UpdateSubItem(pItem->iItem, pItem->iSubItem);
			rc = TRUE;
		}
		else
		{
			rc = FALSE;
		}

		return rc;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CXListCtrl::SetItem"));
	}
	return -1;
}

/*-----------------------------------------------------------------------------
Function		: SetItemImage
In Parameters	: int : Index of the subitem's parent item.
: int :  index of the subitem.
: nImage : vlaue of image to be set fro subitem
Out Parameters	: BOOL : true if successfully set the Image for subItem
Purpose		:set the image for subItem
Author		:
-----------------------------------------------------------------------------*/
BOOL CXListCtrl::SetItemImage(int nItem, int nSubItem, int nImage)
{
	try
	{
		WaitForSingleObject(m_hListCtrlMgr, INFINITE);
		ASSERT(nItem >= 0);
		ASSERT(nItem < GetItemCount());
		if((nItem < 0) || nItem >= GetItemCount())
		{
			SetEvent(m_hListCtrlMgr);
			return FALSE;
		}
		ASSERT(nSubItem >= 0);
		ASSERT(nSubItem < GetColumns());
		if((nSubItem < 0) || nSubItem >= GetColumns())
		{
			SetEvent(m_hListCtrlMgr);
			return FALSE;
		}

		BOOL rc = TRUE;

		if(nItem < 0)
		{
			SetEvent(m_hListCtrlMgr);
			return FALSE;
		}

		XLISTCTRLDATA *pXLCD = (XLISTCTRLDATA *)CListCtrl::GetItemData(nItem);
		if(pXLCD)
		{
			pXLCD[nSubItem].nImage = nImage;
		}

		UpdateSubItem(nItem, nSubItem);

		SetEvent(m_hListCtrlMgr);
		return rc;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CXListCtrl::SetItemImage"));
	}
	SetEvent(m_hListCtrlMgr);
	return FALSE;
}

/*-----------------------------------------------------------------------------
Function		: SetItemText
In Parameters	: int : Index of the subitem's parent item.
: int :  index of the subitem.
: LPCTSTR : string  to be set for subitem
Out Parameters	: BOOL : true if successfully set the text for subItem
Purpose			:This function set the text for subItem
Author			:
-----------------------------------------------------------------------------*/
BOOL CXListCtrl::SetItemText(int nItem, int nSubItem, LPCTSTR lpszText)
{
	try
	{
		WaitForSingleObject(m_hListCtrlMgr, INFINITE);
		ASSERT(nItem >= 0);
		ASSERT(nItem < GetItemCount());
		if((nItem < 0) || nItem >= GetItemCount())
		{
			SetEvent(m_hListCtrlMgr);
			return FALSE;
		}
		ASSERT(nSubItem >= 0);
		ASSERT(nSubItem < GetColumns());
		if((nSubItem < 0) || nSubItem >= GetColumns())
		{
			SetEvent(m_hListCtrlMgr);
			return FALSE;
		}

		BOOL rc = CListCtrl::SetItemText(nItem, nSubItem, lpszText);

		UpdateSubItem(nItem, nSubItem);

		SetEvent(m_hListCtrlMgr);
		return rc;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CXListCtrl::SetItemText"));
	}
	SetEvent(m_hListCtrlMgr);
	return FALSE;
}

/*-----------------------------------------------------------------------------
Function		: SetItemText
In Parameters	: int : Index of the subitem's parent item.
: int :  index of the subitem.
: LPCTSTR : string  to be set for subitem
: COLORREF : color to be set for subitem string
: COLORREF : color to be set for subitem background
Out Parameters	: BOOL : True if sucessfully set the textand color for subitem
else false.
Purpose		:This function will set the text and colors for a subitem.
If lpszText is NULL, only the colors will be set. If a color value is -1,
the display color will be set to the default Windows color.
Author		:
-----------------------------------------------------------------------------*/
BOOL CXListCtrl::SetItemText(int nItem, int nSubItem, LPCTSTR lpszText,
							 COLORREF crText, COLORREF crBackground)
{
	try
	{
		WaitForSingleObject(m_hListCtrlMgr, INFINITE);
		ASSERT(nItem >= 0);
		ASSERT(nItem < GetItemCount());
		if((nItem < 0) || nItem >= GetItemCount())
		{
			SetEvent(m_hListCtrlMgr);
			return FALSE;
		}
		ASSERT(nSubItem >= 0);
		ASSERT(nSubItem < GetColumns());
		if((nSubItem < 0) || nSubItem >= GetColumns())
		{
			SetEvent(m_hListCtrlMgr);
			return FALSE;
		}

		BOOL rc = TRUE;

		if(nItem < 0)
		{
			SetEvent(m_hListCtrlMgr);
			return FALSE;
		}

		if(lpszText)
			rc = CListCtrl::SetItemText(nItem, nSubItem, lpszText);

		XLISTCTRLDATA *pXLCD = (XLISTCTRLDATA *)CListCtrl::GetItemData(nItem);
		if(pXLCD)
		{
			pXLCD[nSubItem].crText       = (crText == -1)? m_crWindowText : crText;
			pXLCD[nSubItem].crBackground = (crBackground == -1)? m_crWindow : crBackground;
		}

		UpdateSubItem(nItem, nSubItem);

		SetEvent(m_hListCtrlMgr);
		return rc;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CXListCtrl::SetItemText"));
	}
	SetEvent(m_hListCtrlMgr);
	return FALSE;
}

/*-----------------------------------------------------------------------------
Function		: DeleteItem
In Parameters	: int : Index to item in list view controll
Out Parameters	: BOOL :Nonzero if successful; otherwise zero.
Purpose		: It delete the XLISTCTRLDATAstructure
for selected item from List view controll
Author		:
-----------------------------------------------------------------------------*/
BOOL CXListCtrl::DeleteItem(int nItem)
{
	try
	{
		WaitForSingleObject(m_hListCtrlMgr, INFINITE);
		ASSERT(nItem >= 0);
		ASSERT(nItem < GetItemCount());
		if((nItem < 0) || nItem >= GetItemCount())
		{
			SetEvent(m_hListCtrlMgr);
			return FALSE;
		}

		XLISTCTRLDATA *pXLCD = (XLISTCTRLDATA *)CListCtrl::GetItemData(nItem);
		if(pXLCD)
		{
			delete [] pXLCD;
		}

		CListCtrl::SetItemData(nItem, 0);
		SetEvent(m_hListCtrlMgr);
		return CListCtrl::DeleteItem(nItem);
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CXListCtrl::DeleteItem"));
	}
	SetEvent(m_hListCtrlMgr);
	return FALSE;
}

/*-----------------------------------------------------------------------------
Function		: DeleteAllItems
In Parameters	:
Out Parameters	:BOOL :Nonzero if successful; otherwise zero.
Purpose		: It delete the XLISTCTRLDATAstructure
for every item in List view controll
Author		:
-----------------------------------------------------------------------------*/
BOOL CXListCtrl::DeleteAllItems()
{
	try
	{
		WaitForSingleObject(m_hListCtrlMgr, INFINITE);
		int n = GetItemCount();
		for (int i = 0; i < n; i++)
		{
			XLISTCTRLDATA *pXLCD = (XLISTCTRLDATA *)CListCtrl::GetItemData(i);
			if(pXLCD)
			{
				delete [] pXLCD;
			}
			CListCtrl::SetItemData(i, 0);
		}

		SetEvent(m_hListCtrlMgr);
		return CListCtrl::DeleteAllItems();
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CXListCtrl::DeleteAllItems"));
	}
	SetEvent(m_hListCtrlMgr);
	return FALSE;
}

/*-----------------------------------------------------------------------------
Function		: OnDestroy
In Parameters	:
Out Parameters	:
Purpose			:The framework calls this member function to inform the
CWnd object that it is being destroyed.It delete the XLISTCTRLDATA
for every item in List view controll
Author			:
-----------------------------------------------------------------------------*/
void CXListCtrl::OnDestroy()
{
	try
	{
		int n = GetItemCount();
		for (int i = 0; i < n; i++)
		{
			XLISTCTRLDATA *pXLCD = (XLISTCTRLDATA *)CListCtrl::GetItemData(i);
			if(pXLCD)
				delete [] pXLCD;
			CListCtrl::SetItemData(i, 0);
		}

		CListCtrl::OnDestroy();
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CXListCtrl::OnDestroy"));
	}
}


/*-----------------------------------------------------------------------------
Function		: SetProgress
In Parameters	: int : Index of the subitem's parent item.
: int :  index of the subitem.
: BOOL : if true ProgressTextis shown else no
string is shown
: LPCTSTR : Progress text
Out Parameters	: BOOL : true if successfully set text else false
Purpose			:set the progress text and its visibility
Author			:
-----------------------------------------------------------------------------*/
// This function creates a progress bar in the specified subitem. The
// UpdateProgress function may then be called to update the progress
// percent. If bShowProgressText is TRUE, either the default text
// of "n%" or the custom percent text (lpszProgressText)will be
// displayed. If bShowProgressText is FALSE, only the progress bar
// will be displayed, with no text.
// Note that the lpszProgressText string should include the format
// specifier "%d":  e.g., "Pct %d%%"

BOOL CXListCtrl::SetProgress(int nItem, int nSubItem, BOOL bShowProgressText /*= TRUE*/,
							 LPCTSTR lpszProgressText /*= NULL*/)
{
	try
	{
		ASSERT(nItem >= 0);
		ASSERT(nItem < GetItemCount());
		if((nItem < 0) || nItem >= GetItemCount())
			return FALSE;
		ASSERT(nSubItem >= 0);
		ASSERT(nSubItem < GetColumns());
		if((nSubItem < 0) || nSubItem >= GetColumns())
			return FALSE;

		XLISTCTRLDATA *pXLCD = (XLISTCTRLDATA *)CListCtrl::GetItemData(nItem);
		if(!pXLCD)
		{
			return FALSE;
		}

		pXLCD[nSubItem].bShowProgress        = TRUE;
		pXLCD[nSubItem].nProgressPercent     = 0;
		pXLCD[nSubItem].bShowProgressMessage = bShowProgressText;
		pXLCD[nSubItem].strProgressMessage   = lpszProgressText;

		UpdateSubItem(nItem, nSubItem);

		return TRUE;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CXListCtrl::SetProgress"));
	}
	return FALSE;
}

/*-----------------------------------------------------------------------------
Function		: DeleteProgress
In Parameters	:: int : Index of the subitem's parent item.
: int :  index of the subitem.
Out Parameters	:
Purpose			:Reset progress of selected item in XLISTCTRLDATA structure
Author			:
-----------------------------------------------------------------------------*/
void CXListCtrl::DeleteProgress(int nItem, int nSubItem)
{
	try
	{
		WaitForSingleObject(m_hListCtrlMgr, INFINITE);
		ASSERT(nItem >= 0);
		ASSERT(nItem < GetItemCount());
		if((nItem < 0) || nItem >= GetItemCount())
		{
			SetEvent(m_hListCtrlMgr);
			return;
		}
		ASSERT(nSubItem >= 0);
		ASSERT(nSubItem < GetColumns());
		if((nSubItem < 0) || nSubItem >= GetColumns())
		{
			SetEvent(m_hListCtrlMgr);
			return;
		}

		XLISTCTRLDATA *pXLCD = (XLISTCTRLDATA *)CListCtrl::GetItemData(nItem);
		if(!pXLCD)
		{
			SetEvent(m_hListCtrlMgr);
			return;
		}

		pXLCD[nSubItem].bShowProgress = FALSE;
		pXLCD[nSubItem].nProgressPercent = 0;

		UpdateSubItem(nItem, nSubItem);
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CXListCtrl::DeleteProgress"));
	}
	SetEvent(m_hListCtrlMgr);
}

/*-----------------------------------------------------------------------------
Function		: UpdateProgress
In Parameters	: int : Index of the subitem's parent item.
: int :  index of the subitem.
: int : progress percent
: CString : progress message
Out Parameters	:
Purpose			:update the progress percent and progress message for selected item
in XLISTCTRLDATA structure.
Author		:
-----------------------------------------------------------------------------*/
void CXListCtrl::UpdateProgress(int nItem, int nSubItem, int nPercent, CString strMessage)
{
	try
	{
		ASSERT(nItem >= 0);
		ASSERT(nItem < GetItemCount());
		if((nItem < 0) || nItem >= GetItemCount())
			return;
		ASSERT(nSubItem >= 0);
		ASSERT(nSubItem < GetColumns());
		if((nSubItem < 0) || nSubItem >= GetColumns())
			return;

		ASSERT(nPercent >= 0 && nPercent <= 100);

		XLISTCTRLDATA *pXLCD = (XLISTCTRLDATA *)CListCtrl::GetItemData(nItem);
		if(!pXLCD)
		{
			return;
		}


		pXLCD[nSubItem].nProgressPercent = nPercent;
		pXLCD[nSubItem].strProgressMessage = strMessage;

		UpdateSubItem(nItem, nSubItem);
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CXListCtrl::UpdateProgress"));
	}
}

/*-----------------------------------------------------------------------------
Function		: SetCheckbox
In Parameters	: int : Index of the subitem's parent item.
: int :  index of the subitem.
: int : value for checked state
Out Parameters	:BOOL : true if successfully updated the state
Purpose		: set the flag of checked state in XLISTCTRLDATA structure
Author		:
-----------------------------------------------------------------------------*/
BOOL CXListCtrl::SetCheckbox(int nItem, int nSubItem, int nCheckedState)
{
	try
	{
		ASSERT(nItem >= 0);
		ASSERT(nItem < GetItemCount());
		if((nItem < 0) || nItem >= GetItemCount())
			return FALSE;
		ASSERT(nSubItem >= 0);
		ASSERT(nSubItem < GetColumns());
		if((nSubItem < 0) || nSubItem >= GetColumns())
			return FALSE;
		ASSERT(nCheckedState == 0 || nCheckedState == 1 || nCheckedState == -1);

		XLISTCTRLDATA *pXLCD = (XLISTCTRLDATA *)CListCtrl::GetItemData(nItem);
		if(!pXLCD)
		{
			return FALSE;
		}

		// update checkbox in subitem
		pXLCD[nSubItem].nCheckedState = nCheckedState;

		UpdateSubItem(nItem, nSubItem);

		// now update checkbox in column header
		// -1 = no checkbox in column header
		if(GetHeaderCheckedState(nSubItem) != XHEADERCTRL_NO_IMAGE)
		{
			int nCheckedCount = CountCheckedItems(nSubItem);

			if(nCheckedCount == GetItemCount())
				SetHeaderCheckedState(nSubItem, XHEADERCTRL_CHECKED_IMAGE);
			else
				SetHeaderCheckedState(nSubItem, XHEADERCTRL_UNCHECKED_IMAGE);
		}

		return TRUE;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CXListCtrl::SetCheckbox"));
	}
	return FALSE;
}

/*-----------------------------------------------------------------------------
Function		: GetCheckbox
In Parameters	: int : Index of the subitem's parent item.
: int :  index of the subitem.
Out Parameters	:int :return check state of given item
Purpose		: retrive the check state of given item
Author		:
-----------------------------------------------------------------------------*/
int CXListCtrl::GetCheckbox(int nItem, int nSubItem)
{
	try
	{
		ASSERT(nItem >= 0);
		ASSERT(nItem < GetItemCount());
		if((nItem < 0) || nItem >= GetItemCount())
			return -1;
		ASSERT(nSubItem >= 0);
		ASSERT(nSubItem < GetColumns());
		if((nSubItem < 0) || nSubItem >= GetColumns())
			return -1;

		XLISTCTRLDATA *pXLCD = (XLISTCTRLDATA *)CListCtrl::GetItemData(nItem);
		if(!pXLCD)
		{
			return -1;
		}

		return pXLCD[nSubItem].nCheckedState;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CXListCtrl::GetCheckbox"));
	}
	return -1;
}
/*-----------------------------------------------------------------------------
Function		: GetEnabled
In Parameters	int : Index to item in list view controll
Out Parameters	: BOOL : contains the flag value
Purpose		:retrive the flag value for given item from XLISTCTRLDATA  structure
Author		:
-----------------------------------------------------------------------------*/
// Note that GetEnabled and SetEnabled only Get/Set the enabled flag from
// subitem 0, since this is a per-row flag.

BOOL CXListCtrl::GetEnabled(int nItem)
{
	try
	{
		ASSERT(nItem >= 0);
		ASSERT(nItem < GetItemCount());
		if((nItem < 0) || nItem >= GetItemCount())
			return FALSE;

		XLISTCTRLDATA *pXLCD = (XLISTCTRLDATA *)CListCtrl::GetItemData(nItem);
		if(!pXLCD)
		{
			return FALSE;
		}

		return pXLCD[0].bEnabled;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CXListCtrl::GetEnabled"));
	}
	return FALSE;
}

/*-----------------------------------------------------------------------------
Function		: SetEnabled
In Parameters	: int : Index to item in list view controll
Out Parameters	: BOOL : true if sucessfully updated XLISTCTRLDATA structure
Purpose		: set the bEnabled flag for seleted item in XLISTCTRLDATA structure
Author		:
-----------------------------------------------------------------------------*/
BOOL CXListCtrl::SetEnabled(int nItem, BOOL bEnable)
{
	try
	{
		ASSERT(nItem >= 0);
		ASSERT(nItem < GetItemCount());
		if((nItem < 0) || nItem >= GetItemCount())
			return FALSE;

		XLISTCTRLDATA *pXLCD = (XLISTCTRLDATA *)CListCtrl::GetItemData(nItem);
		if(!pXLCD)
		{
			return FALSE;
		}

		pXLCD[0].bEnabled = bEnable;

		CRect rect;
		GetItemRect(nItem, &rect, LVIR_BOUNDS);
		InvalidateRect(&rect);
		UpdateWindow();

		return TRUE;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CXListCtrl::SetEnabled"));
	}
	return FALSE;
}

/*-----------------------------------------------------------------------------
Function		: SetBold
In Parameters	: int : Index of the subitem's parent item.
: int :  index of the subitem.
: BOOL : bBold value user want to set
Out Parameters	: BOOL : true if user successfully set the value otherwisw false
Purpose		:set bBold value in XLISTCTRLDATA structure  for given item
Author		:
-----------------------------------------------------------------------------*/
BOOL CXListCtrl::SetBold(int nItem, int nSubItem, BOOL bBold)
{
	try
	{
		ASSERT(nItem >= 0);
		ASSERT(nItem < GetItemCount());
		if((nItem < 0) || nItem >= GetItemCount())
			return FALSE;
		ASSERT(nSubItem >= 0);
		ASSERT(nSubItem < GetColumns());
		if((nSubItem < 0) || nSubItem >= GetColumns())
			return FALSE;

		XLISTCTRLDATA *pXLCD = (XLISTCTRLDATA *)CListCtrl::GetItemData(nItem);
		if(!pXLCD)
		{
			return FALSE;
		}

		// update bold flag
		pXLCD[nSubItem].bBold = bBold;

		UpdateSubItem(nItem, nSubItem);

		return TRUE;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CXListCtrl::SetBold"));
	}
	return FALSE;
}

/*-----------------------------------------------------------------------------
Function		: GetBold
In Parameters	: int : Index of the subitem's parent item.
: int :  index of the subitem.
Out Parameters	:BOOL : returns bBOLd value of given item if present in list view
controll
Purpose		:retrive bBold value of given Item.
Author		:
-----------------------------------------------------------------------------*/
BOOL CXListCtrl::GetBold(int nItem, int nSubItem)
{
	try
	{
		ASSERT(nItem >= 0);
		ASSERT(nItem < GetItemCount());
		if((nItem < 0) || nItem >= GetItemCount())
			return FALSE;
		ASSERT(nSubItem >= 0);
		ASSERT(nSubItem < GetColumns());
		if((nSubItem < 0) || nSubItem >= GetColumns())
			return FALSE;

		XLISTCTRLDATA *pXLCD = (XLISTCTRLDATA *)CListCtrl::GetItemData(nItem);
		if(!pXLCD)
		{
			return FALSE;
		}

		// update bold flag
		return pXLCD[nSubItem].bBold;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CXListCtrl::GetBold"));
	}
	return FALSE;
}
/*-----------------------------------------------------------------------------
Function		: SetHyperLink
In Parameters	: int : Index of the subitem's parent item.
: int :  index of the subitem.
: BOOL :
Out Parameters	:BOOL : true if HyperLink is set otherwise false.
Purpose			:This function set hyperlink for given item
Author			:
-----------------------------------------------------------------------------*/
BOOL CXListCtrl::SetHyperLink(int nItem, int nSubItem, BOOL bLink)
{
	try
	{
		ASSERT(nItem >= 0);
		ASSERT(nItem < GetItemCount());
		if((nItem < 0) || nItem >= GetItemCount())
			return FALSE;
		ASSERT(nSubItem >= 0);
		ASSERT(nSubItem < GetColumns());
		if((nSubItem < 0) || nSubItem >= GetColumns())
			return FALSE;

		XLISTCTRLDATA *pXLCD = (XLISTCTRLDATA *)CListCtrl::GetItemData(nItem);
		if(!pXLCD)
		{
			return FALSE;
		}

		// update bold flag
		pXLCD[nSubItem].bLink = bLink;

		UpdateSubItem(nItem, nSubItem);

		return TRUE;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CXListCtrl::SetHyperLink"));
	}
	return FALSE;
}
/*-----------------------------------------------------------------------------
Function		: SetComboBox
In Parameters	: int : Index of the subitem's parent item.
: int :  index of the subitem.
: BOOL : if true then XLISTCTRLDATA is upadted
: CString :pointer CString Array
: int : height of ComboList
: int :Index to initial combobox selection
Out Parameters	: BOOL : returns true  if XLISTCTRLDATA is updated otherwise false
Purpose			: Set the combo box
Author			:
-----------------------------------------------------------------------------*/
// Note:  SetItemText may also be used to set the initial combo selection.
BOOL CXListCtrl::SetComboBox(int nItem, int nSubItem, BOOL bEnableCombo, CStringArray *psa,
							 int nComboListHeight, int nInitialComboSel)
{
	try
	{
		ASSERT(nItem >= 0);
		ASSERT(nItem < GetItemCount());
		if((nItem < 0) || nItem >= GetItemCount())
			return FALSE;
		ASSERT(nSubItem >= 0);
		ASSERT(nSubItem < GetColumns());
		if((nSubItem < 0) || nSubItem >= GetColumns())
			return FALSE;
		ASSERT(psa);
		if(!psa)
			return FALSE;
		ASSERT(nComboListHeight > 0);
		ASSERT(nInitialComboSel >= 0 && nInitialComboSel < psa->GetSize());
		if((nInitialComboSel < 0) || (nInitialComboSel >= psa->GetSize()))
			nInitialComboSel = 0;

		XLISTCTRLDATA *pXLCD = (XLISTCTRLDATA *)CListCtrl::GetItemData(nItem);
		if(!pXLCD)
		{
			return FALSE;
		}

		// update flag
		pXLCD[nSubItem].bCombo = bEnableCombo;

		if(bEnableCombo)
		{
			pXLCD[nSubItem].psa = psa;
			pXLCD[nSubItem].nComboListHeight = nComboListHeight;
			pXLCD[nSubItem].nInitialComboSel = nInitialComboSel;

			if(pXLCD[nSubItem].psa)
			{
				int index = 0;
				if((pXLCD[nSubItem].nInitialComboSel >= 0) &&
					(pXLCD[nSubItem].psa->GetSize() > pXLCD[nSubItem].nInitialComboSel))
				{
					index = pXLCD[nSubItem].nInitialComboSel;
					CString str;
					str = pXLCD[nSubItem].psa->GetAt(index);
					SetItemText(nItem, nSubItem, str);
				}
			}
		}

		UpdateSubItem(nItem, nSubItem);

		return TRUE;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CXListCtrl::SetComboBox"));
	}
	return FALSE;
}

/*-----------------------------------------------------------------------------
Function		: GetComboText
In Parameters	: int : Index of the subitem's parent item.
: int :  index of the subitem.
Out Parameters	: CSTring : contains combo text
Purpose			:retrive combo text
Author			:
-----------------------------------------------------------------------------*/
CString	CXListCtrl::GetComboText(int nItem, int nSubItem)
{
	try
	{
		ASSERT(nItem >= 0);
		ASSERT(nItem < GetItemCount());
		if((nItem < 0) || nItem >= GetItemCount())
			return _T("");
		ASSERT(nSubItem >= 0);
		ASSERT(nSubItem < GetColumns());
		if((nSubItem < 0) || nSubItem >= GetColumns())
			return _T("");

		CString str;
		str = _T("");

		str = GetItemText(nItem, nSubItem);

		return str;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CXListCtrl::GetComboText"));
	}
	return _T("");
}

/*-----------------------------------------------------------------------------
Function		: SetCurSel
In Parameters	: int :index of item to be selected
Out Parameters	:BOOL :
Purpose		:set item to be Selected
Author		:
-----------------------------------------------------------------------------*/
BOOL CXListCtrl::SetCurSel(int nItem)
{
	try
	{
		return SetItemState(nItem, LVIS_FOCUSED | LVIS_SELECTED, LVIS_FOCUSED | LVIS_SELECTED);
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CXListCtrl::SetCurSel"));
	}
	return FALSE;
}
/*-----------------------------------------------------------------------------
Function		: GetCurSel
In Parameters	:
Out Parameters	:int :returns Index of item number, or -1 if no item is present
int List View Control
Purpose		:retrive Index of Item
Author		:
-----------------------------------------------------------------------------*/
// Note:  for single-selection lists only

int CXListCtrl::GetCurSel()
{
	try
	{
		POSITION pos = GetFirstSelectedItemPosition();
		int nSelectedItem = -1;
		if(pos != NULL)
			nSelectedItem = GetNextSelectedItem(pos);
		return nSelectedItem;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CXListCtrl::GetCurSel"));
	}
	return -1;
}

/*-----------------------------------------------------------------------------
Function		: UpdateSubItem
In Parameters	: int : Index of the subitem's parent item.
: int :  index of the subitem.
Out Parameters	:
Purpose			:update subitem
Author			:
-----------------------------------------------------------------------------*/
void CXListCtrl::UpdateSubItem(int nItem, int nSubItem)
{
	try
	{
		ASSERT(nItem >= 0);
		ASSERT(nItem < GetItemCount());
		if((nItem < 0) || nItem >= GetItemCount())
			return;
		ASSERT(nSubItem >= 0);
		ASSERT(nSubItem < GetColumns());
		if((nSubItem < 0) || nSubItem >= GetColumns())
			return;

		CRect rect;
		if(nSubItem == -1)
		{
			GetItemRect(nItem, &rect, LVIR_BOUNDS);
		}
		else
		{
			GetSubItemRect(nItem, nSubItem, LVIR_BOUNDS, rect);
		}

		InvalidateRect(&rect);
		UpdateWindow();
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CXListCtrl::UpdateSubItem"));
	}
}

/*-----------------------------------------------------------------------------
Function		: GetColumns
In Parameters	:
Out Parameters	: int : returns no of coloumn
Purpose		 : Retrives The no of coloumn
Author		:
-----------------------------------------------------------------------------*/
int CXListCtrl::GetColumns()
{
	try
	{
		return GetHeaderCtrl() ->GetItemCount();
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CXListCtrl::GetColumns"));
	}
	return -1;
}
/*-----------------------------------------------------------------------------
Function		: GetItemData
In Parameters	: Index of application specific data.
Out Parameters	: DWORD : returnd data if found otherwise return false;
Purpose			:retrive the given data from specfic index from XLISTCTRLDATA
struct if present.
Author		:
-----------------------------------------------------------------------------*/
// The GetItemData and SetItemData functions allow for app-specific data
// to be stored, by using an extra field in the XLISTCTRLDATA struct.
DWORD CXListCtrl::GetItemData(int nItem)
{
	try
	{
		ASSERT(nItem >= 0);
		ASSERT(nItem < GetItemCount());
		if((nItem < 0) || nItem >= GetItemCount())
			return 0;

		XLISTCTRLDATA *pXLCD = (XLISTCTRLDATA *)CListCtrl::GetItemData(nItem);
		if(!pXLCD)
		{
			return 0;
		}

		return pXLCD->dwItemData;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CXListCtrl::GetItemData"));
	}
	return 0;
}

/*-----------------------------------------------------------------------------
Function		: SetItemData
In Parameters	: int :Index of Item
Out Parameters	: BOOL : true if data is successfully set otherwisw false
Purpose		: set the given data at given index in XLISTCTRLDATA
struct
Author		:
-----------------------------------------------------------------------------*/
BOOL CXListCtrl::SetItemData(int nItem, DWORD dwData)
{
	try
	{
		ASSERT(nItem >= 0);
		ASSERT(nItem < GetItemCount());
		if((nItem < 0) || nItem >= GetItemCount())
			return FALSE;

		XLISTCTRLDATA *pXLCD = (XLISTCTRLDATA *)CListCtrl::GetItemData(nItem);
		if(!pXLCD)
		{
			return FALSE;
		}

		pXLCD->dwItemData = dwData;

		return TRUE;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CXListCtrl::SetItemData"));
	}
	return FALSE;
}
/*-----------------------------------------------------------------------------
Function		: GetHeaderCheckedState
In Parameters	: int : index of checked subitem
Out Parameters	: int :return state of checked box
Purpose			:The GetHeaderCheckedState and SetHeaderCheckedState may be used
to toggle the checkbox in a column header.
0 = no checkbox
1 = unchecked
2 = checked
Author			:
-----------------------------------------------------------------------------*/
int CXListCtrl::GetHeaderCheckedState(int nSubItem)
{
	try
	{
		ASSERT(nSubItem >= 0);
		ASSERT(nSubItem < GetColumns());
		if((nSubItem < 0) || nSubItem >= GetColumns())
			return -1;

		HDITEM hditem;

		// use the image index (0 or 1)to indicate the checked status
		hditem.mask = HDI_IMAGE;
		m_HeaderCtrl.GetItem(nSubItem, &hditem);
		return hditem.iImage;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CXListCtrl::GetHeaderCheckedState"));
	}
	return -1;
}

/*-----------------------------------------------------------------------------
Function		: SetHeaderCheckedState
In Parameters	: int : Index of subitem checkbox clicked
: int :state of Checkbox
Out Parameters	: BOOL :returnd true if item is present else false
Purpose		:set the checkbox to checked state
Author		:
-----------------------------------------------------------------------------*/
BOOL CXListCtrl::SetHeaderCheckedState(int nSubItem, int nCheckedState)
{
	try
	{
		ASSERT(nSubItem >= 0);
		ASSERT(nSubItem < GetColumns());
		if((nSubItem < 0) || nSubItem >= GetColumns())
			return FALSE;
		ASSERT(nCheckedState == 0 || nCheckedState == 1 || nCheckedState == 2);

		HDITEM hditem;

		hditem.mask = HDI_IMAGE;
		hditem.iImage = nCheckedState;
		m_HeaderCtrl.SetItem(nSubItem, &hditem);

		return TRUE;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CXListCtrl::SetHeaderCheckedState"));
	}
	return FALSE;
}

/*-----------------------------------------------------------------------------
Function		: OnColumnClick
In Parameters	: NMHDR : pointer to MNHDR structure
: LRESULT : is always set to 0
Out Parameters	: BOOL : always return false
Purpose			: handles LVN_COLUMNCLICK message
Author			:
-----------------------------------------------------------------------------*/
BOOL CXListCtrl::OnColumnClick(NMHDR* pNMHDR, LRESULT* pResult)
{
	try
	{
		NMLISTVIEW* pnmlv = (NMLISTVIEW*)pNMHDR;

		int nSubItem = pnmlv->iSubItem;

		int nCheckedState = GetHeaderCheckedState(nSubItem);

		// 0 = no checkbox
		if(nCheckedState != XHEADERCTRL_NO_IMAGE)
		{
			nCheckedState = (nCheckedState == 1)? 2 : 1;
			SetHeaderCheckedState(nSubItem, nCheckedState);

			m_HeaderCtrl.UpdateWindow();

			for (int nItem = 0; nItem < GetItemCount(); nItem++)
			{
				XLISTCTRLDATA *pXLCD = (XLISTCTRLDATA *)CListCtrl::GetItemData(nItem);
				if(!pXLCD)
				{
					continue;
				}

				if(pXLCD[nSubItem].nCheckedState != -1)
				{
					pXLCD[nSubItem].nCheckedState = nCheckedState - 1;
					UpdateSubItem(nItem, nSubItem);
				}

			}
		}

		*pResult = 0;
		return FALSE;		// return FALSE to send message to parent also -
		// NOTE:  MSDN documentation is incorrect
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CXListCtrl::OnColumnClick"));
	}
	return FALSE;
}

/*-----------------------------------------------------------------------------
Function		: CountCheckedItems
In Parameters	: int :  Index of subitem checkbox clicked
Out Parameters	:int  :returns the number of list item checked.
Purpose		:Retrives the number of list item checked.
Author		:
-----------------------------------------------------------------------------*/
int CXListCtrl::CountCheckedItems(int nSubItem)
{
	try
	{
		ASSERT(nSubItem >= 0);
		ASSERT(nSubItem < GetColumns());
		if((nSubItem < 0) || nSubItem >= GetColumns())
			return 0;

		int nCount = 0;

		for (int nItem = 0; nItem < GetItemCount(); nItem++)
		{
			XLISTCTRLDATA *pXLCD = (XLISTCTRLDATA *)CListCtrl::GetItemData(nItem);
			if(!pXLCD)
			{
				continue;
			}

			if(pXLCD[nSubItem].nCheckedState == 1)
				nCount++;
		}

		return nCount;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CXListCtrl::CountCheckedItems"));
	}
	return 0;
}

/*-----------------------------------------------------------------------------
Function		: OnSysColorChange
In Parameters	:
Out Parameters	:
Purpose		:The framework calls this member function for all top-level windows
when a change is made in the system color setting.
Author		:
-----------------------------------------------------------------------------*/
void CXListCtrl::OnSysColorChange()
{
	try
	{
		TRACE(_T("in CXListCtrl::OnSysColorChange\n"));

		CListCtrl::OnSysColorChange();

		m_cr3DFace        = ::GetSysColor(COLOR_3DFACE);
		m_cr3DHighLight   = ::GetSysColor(COLOR_3DHIGHLIGHT);
		m_cr3DShadow      = ::GetSysColor(COLOR_3DSHADOW);
		m_crBtnFace       = ::GetSysColor(COLOR_BTNFACE);
		m_crBtnShadow     = ::GetSysColor(COLOR_BTNSHADOW);
		m_crBtnText       = ::GetSysColor(COLOR_BTNTEXT);
		m_crGrayText      = ::GetSysColor(COLOR_GRAYTEXT);
		m_crHighLight     = ::GetSysColor(COLOR_HIGHLIGHT);
		m_crHighLightText = ::GetSysColor(COLOR_HIGHLIGHTTEXT);
		m_crWindow        = ::GetSysColor(COLOR_WINDOW);
		m_crWindowText    = ::GetSysColor(COLOR_WINDOWTEXT);
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CXListCtrl::OnSysColorChange"));
	}
}


#ifndef DO_NOT_INCLUDE_XCOMBOLIST

/*-----------------------------------------------------------------------------
Function		: UnpressComboButton
In Parameters	:
Out Parameters	:
Purpose		: This function is called combo button to be unpressed
Author		:
-----------------------------------------------------------------------------*/
void CXListCtrl::UnpressComboButton()
{
	try
	{
		static BOOL bFlag = FALSE;
		if(bFlag)
			return;
		bFlag = TRUE;

		if(m_bComboIsClicked)
		{
			if(m_nComboItem >= 0 && m_nComboItem < GetItemCount())
			{
				XLISTCTRLDATA *pXLCD = (XLISTCTRLDATA *)CListCtrl::GetItemData(m_nComboItem);

				if(pXLCD)
				{
					if(m_nComboSubItem >= 0 && m_nComboSubItem < GetColumns())
					{
						pXLCD[m_nComboSubItem].bComboIsClicked = FALSE;

						UpdateSubItem(m_nComboItem, m_nComboSubItem);
					}
				}
			}
		}
		m_bComboIsClicked = FALSE;
		bFlag = FALSE;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CXListCtrl::UnpressComboButton"));
	}
}
/*-----------------------------------------------------------------------------
Function		: OnTimer
In Parameters	: UINT_PTR : EventId
Out Parameters	:
Purpose		: Timer usage:
1 - used to check if combo button needs to be unpressed,set in
OnLButtonDown (when combo button is clicked)
2 - used to close combo listbox, set in OnComboEscape (user hits Escape
or listbox loses focus)
3 - used to get combo listbox selection, then close combo listbox,
set in OnComboReturn and OnComboLButtonUp (user hits Enter
or clicks on item in listbox)
4 - used to get combo listbox selection, set in OnComboKeydown (for
example, user hits arrow key in listbox)
Author		:
-----------------------------------------------------------------------------*/
void CXListCtrl::OnTimer(UINT_PTR nIDEvent)
{
	try
	{
		if(nIDEvent == 1)			// timer set when combo button is clicked
		{
			if(m_bComboIsClicked)
			{
				POINT point;
				::GetCursorPos(&point);
				ScreenToClient(&point);

				if(!m_rectComboButton.PtInRect(point))
				{
					UnpressComboButton();
				}
			}
			else if(m_pListBox)
			{
				m_pListBox->SetActive(11);
			}
			else
			{
				KillTimer(nIDEvent);
			}
		}
		else if(nIDEvent == 2)		// close combo listbox
		{
			KillTimer(nIDEvent);

			if(m_pListBox)
			{
				m_pListBox->DestroyWindow();
				delete m_pListBox;
			}
			m_pListBox = NULL;
		}
		else if(nIDEvent == 3)		// get combo listbox selection, then close combo listbox
		{
			KillTimer(nIDEvent);

			if(m_pListBox)
			{
				CString str;
				int i = m_pListBox->GetCurSel();
				if(i != LB_ERR)
				{
					m_pListBox->GetText(i, str);

					if((m_nComboItem >= 0 && m_nComboItem < GetItemCount()) &&
						(m_nComboSubItem >= 0 && m_nComboSubItem < GetColumns()))
					{
						SetItemText(m_nComboItem, m_nComboSubItem, str);

						UpdateSubItem(m_nComboItem, m_nComboSubItem);

						CWnd *pWnd = GetParent();
						if(!pWnd)
							pWnd = GetOwner();
						if(pWnd && ::IsWindow(pWnd->m_hWnd))
							pWnd->SendMessage(WM_XLISTCTRL_COMBO_SELECTION,
							m_nComboItem, m_nComboSubItem);
					}
				}

				m_pListBox->DestroyWindow();
				if(m_pListBox)
					delete m_pListBox;
			}
			m_pListBox = NULL;
		}
		else if(nIDEvent == 4)		// get combo listbox selection
		{
			KillTimer(nIDEvent);

			if(m_pListBox)
			{
				CString str;
				int i = m_pListBox->GetCurSel();
				if(i != LB_ERR)
				{
					m_pListBox->GetText(i, str);

					if((m_nComboItem >= 0 && m_nComboItem < GetItemCount()) &&
						(m_nComboSubItem >= 0 && m_nComboSubItem < GetColumns()))
					{
						SetItemText(m_nComboItem, m_nComboSubItem, str);

						UpdateSubItem(m_nComboItem, m_nComboSubItem);
					}
				}
			}
		}
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CXListCtrl::OnTimer"));
	}
}

/*-----------------------------------------------------------------------------
Function		: OnComboEscape
In Parameters	: WPARAM :Additional message Information
: LPARAM :Additional message Information
Out Parameters	: LRESULT : always returned 0.
Purpose		:This Function Handles WM_XCOMBOLIST_VK_ESCAPE message
Author		:
-----------------------------------------------------------------------------*/
LRESULT CXListCtrl::OnComboEscape(WPARAM, LPARAM)
{
	try
	{
		KillTimer(1);
		SetTimer(2, 50, NULL);

		// restore original string
		SetItemText(m_nComboItem, m_nComboSubItem, m_strInitialComboString);

		UpdateSubItem(m_nComboItem, m_nComboSubItem);

		return 0;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CXListCtrl::OnComboEscape"));
	}
	return 0;
}

/*-----------------------------------------------------------------------------
Function		: OnComboReturn
In Parameters	: WPARAM :Additional message Information
: LPARAM :Additional message Information
Out Parameters	: LRESULT : always returned 0.
Purpose		:This Function Handles WM_XCOMBOLIST_VK_RETURN message
Author		:
-----------------------------------------------------------------------------*/
LRESULT CXListCtrl::OnComboReturn (WPARAM, LPARAM)
{
	try
	{
		TRACE(_T("in CXListCtrl::OnComboReturn\n"));
		KillTimer(1);
		SetTimer(3, 50, NULL);
		return 0;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CXListCtrl::OnComboReturn"));
	}
	return 0;
}

/*-----------------------------------------------------------------------------
Function		: OnComboLButtonUp
In Parameters	: WPARAM :Additional message Information
: LPARAM :Additional message Information
Out Parameters	: LRESULT : always returned 0.
Purpose		:This Function Handles WM_XCOMBOLIST_LBUTTONUP message
Author		:
-----------------------------------------------------------------------------*/
LRESULT CXListCtrl::OnComboLButtonUp(WPARAM, LPARAM)
{
	try
	{
		TRACE(_T("in CXListCtrl::OnComboLButtonUp\n"));
		KillTimer(1);
		SetTimer(3, 50, NULL);
		return 0;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CXListCtrl::OnComboLButtonUp"));
	}
	return 0;
}

/*-----------------------------------------------------------------------------
Function		: OnComboKeydown
In Parameters	: WPARAM :Additional message Information
: LPARAM :Additional message Information
Out Parameters	: LRESULT : always returned 0.
Purpose		:This Function Handles WM_XCOMBOLIST_KEYDOWN message
Author		:
-----------------------------------------------------------------------------*/
LRESULT CXListCtrl::OnComboKeydown(WPARAM, LPARAM)
{
	try
	{
		SetTimer(4, 50, NULL);
		return 0;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CXListCtrl::OnComboKeydown"));
	}
	return 0;
}

#endif

#ifndef NO_XLISTCTRL_TOOL_TIPS

/*-----------------------------------------------------------------------------
Function		: OnToolHitTest
In Parameters	: CPoint :a object of CPoint
: TOOLINFO : a pointer to TOOLINFO structure which conatins
retirve data.
Out Parameters	: INT_PTR : return unique id if
Purpose		: This function locate a list item and retrive TOOLINFO structure value
from it.
Author		:
-----------------------------------------------------------------------------*/
INT_PTR CXListCtrl::OnToolHitTest(CPoint point, TOOLINFO * pTI)const
{
	try
	{
		LVHITTESTINFO lvhitTestInfo;

		lvhitTestInfo.pt = point;

		int nItem = ListView_SubItemHitTest(this->m_hWnd, &lvhitTestInfo);
		int nSubItem = lvhitTestInfo.iSubItem;
		TRACE(_T("in CToolTipListCtrl::OnToolHitTest: %d,%d\n"), nItem, nSubItem);

		UINT nFlags = lvhitTestInfo.flags;

		// nFlags is 0 if the SubItemHitTest fails
		// Therefore, 0 & <anything> will equal false
		if(nFlags & LVHT_ONITEMLABEL)
		{
			// If it did fall on a list item, and it was also hit one of the
			// item specific subitems we wish to show tool tips for

			// get the client (area occupied by this control
			RECT rcClient;
			GetClientRect(&rcClient);

			// fill in the TOOLINFO structure
			pTI->hwnd = m_hWnd;
			pTI->uId = (UINT)(nItem * 1000 + nSubItem + 1);
			pTI->lpszText = LPSTR_TEXTCALLBACK;
			pTI->rect = rcClient;

			return pTI->uId;	// By returning a unique value per listItem,
			// we ensure that when the mouse moves over another
			// list item, the tooltip will change
		}
		else
		{
			//Otherwise, we aren't interested, so let the message propagate
			return -1;
		}
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CXListCtrl::OnToolHitTest"));
	}
	return -1;
}

/*-----------------------------------------------------------------------------
Function		: OnToolTipText
In Parameters	: UINT :
: NMHDR :
: LRESULT :

Out Parameters	:
Purpose		: Handles  TTN_NEEDTEXTW message
Author		:
-----------------------------------------------------------------------------*/
BOOL CXListCtrl::OnToolTipText(UINT /*id*/, NMHDR * pNMHDR, LRESULT * pResult)
{
	try
	{
		UINT nID = static_cast<UINT>(pNMHDR->idFrom);
		TRACE(_T("in CXListCtrl::OnToolTipText: id=%d\n"), nID);

		// check if this is the automatic tooltip of the control
		if(nID == 0)
			return TRUE;	// do not allow display of automatic tooltip,
		// or our tooltip will disappear

		// handle both ANSI and UNICODE versions of the message
		TOOLTIPTEXTA* pTTTA = (TOOLTIPTEXTA*)pNMHDR;
		TOOLTIPTEXTW* pTTTW = (TOOLTIPTEXTW*)pNMHDR;

		*pResult = 0;

		// get the mouse position
		const MSG* pMessage;
		pMessage = GetCurrentMessage();
		ASSERT(pMessage);
		CPoint pt;
		pt = pMessage->pt;		// get the point from the message
		ScreenToClient(&pt);	// convert the point's coords to be relative to this control

		// see if the point falls onto a list item

		LVHITTESTINFO lvhitTestInfo;

		lvhitTestInfo.pt = pt;

		int nItem = SubItemHitTest(&lvhitTestInfo);
		int nSubItem = lvhitTestInfo.iSubItem;

		UINT nFlags = lvhitTestInfo.flags;

		// nFlags is 0 if the SubItemHitTest fails
		// Therefore, 0 & <anything> will equal false
		if(nFlags & LVHT_ONITEMLABEL)
		{
			// If it did fall on a list item,
			// and it was also hit one of the
			// item specific subitems we wish to show tooltips for

			CString strToolTip;
			strToolTip = _T("");

			XLISTCTRLDATA *pXLCD = (XLISTCTRLDATA *)CListCtrl::GetItemData(nItem);
			if(pXLCD)
			{
				strToolTip = pXLCD[nSubItem].strToolTip;
			}

			if(!strToolTip.IsEmpty())
			{
				// If there was a CString associated with the list item,
				// copy it's text (up to 80 characters worth, limitation
				// of the TOOLTIPTEXT structure)into the TOOLTIPTEXT
				// structure's szText member

#ifndef _UNICODE
				if(pNMHDR->code == TTN_NEEDTEXTA)
					lstrcpyn(pTTTA->szText, strToolTip, 80);
				else
					_mbstowcsz(pTTTW->szText, strToolTip, 80);
#else
				if(pNMHDR->code == TTN_NEEDTEXTA)
					_wcstombsz(pTTTA->szText, strToolTip, 80);
				else
					lstrcpyn(pTTTW->szText, strToolTip, 80);
#endif
				return FALSE;	 // we found a tool tip,
			}
		}

		return FALSE;	// we didn't handle the message, let the
		// framework continue propagating the message
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CXListCtrl::OnToolTipText"));
	}
	return FALSE;
}

/*-----------------------------------------------------------------------------
Function		: SetItemToolTipText
In Parameters	: int : Index of the list item whose data is to be retrieved
: int :  Index of subItem in XLISTCTRLDATA structure
: LPCTSTR : pointer to string of ToolTipText
Out Parameters	: BOOl : true if successfuly set the value otherwise false
Purpose			:This Fumction set strToolTipin value in XLISTCTRLDATA structure.
Author			:
-----------------------------------------------------------------------------*/
BOOL CXListCtrl::SetItemToolTipText(int nItem, int nSubItem, LPCTSTR lpszToolTipText)
{
	try
	{
		ASSERT(nItem >= 0);
		ASSERT(nItem < GetItemCount());
		if((nItem < 0) || nItem >= GetItemCount())
			return FALSE;
		ASSERT(nSubItem >= 0);
		ASSERT(nSubItem < GetColumns());
		if((nSubItem < 0) || nSubItem >= GetColumns())
			return FALSE;

		XLISTCTRLDATA *pXLCD = (XLISTCTRLDATA *)CListCtrl::GetItemData(nItem);
		if(!pXLCD)
		{
			return FALSE;
		}

		pXLCD[nSubItem].strToolTip = lpszToolTipText;

		return TRUE;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CXListCtrl::SetItemToolTipText"));
	}
	return FALSE;
}

/*-----------------------------------------------------------------------------
Function		: GetItemToolTipText
In Parameters	: int : Index of the list item whose data is to be retrieved
: int : Index of subItem in XLISTCTRLDATA structure
Out Parameters	: CString : returns strToolTip
Purpose		:This function retrives strToolTip at given index from XLISTCTRLDATA
structure
Author		:
-----------------------------------------------------------------------------*/
CString CXListCtrl::GetItemToolTipText(int nItem, int nSubItem)
{
	try
	{
		CString strToolTip;
		strToolTip = _T("");

		ASSERT(nItem >= 0);
		ASSERT(nItem < GetItemCount());
		if((nItem < 0) || nItem >= GetItemCount())
			return strToolTip;
		ASSERT(nSubItem >= 0);
		ASSERT(nSubItem < GetColumns());
		if((nSubItem < 0) || nSubItem >= GetColumns())
			return strToolTip;

		XLISTCTRLDATA *pXLCD = (XLISTCTRLDATA *)CListCtrl::GetItemData(nItem);
		if(pXLCD)
		{
			strToolTip = pXLCD[nSubItem].strToolTip;
		}

		return strToolTip;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CXListCtrl::GetItemToolTipText"));
	}
	return _T("");
}

/*-----------------------------------------------------------------------------
Function		: DeleteAllToolTips
In Parameters	:
Out Parameters	:
Purpose		:This Function Reset  XLISTCTRLDATA structure
Author		:
-----------------------------------------------------------------------------*/
void CXListCtrl::DeleteAllToolTips()
{
	try
	{
		int nRow = GetItemCount();
		int nCol = GetColumns();

		for (int nItem = 0; nItem < nRow; nItem++)
		{
			XLISTCTRLDATA *pXLCD = (XLISTCTRLDATA *)CListCtrl::GetItemData(nItem);
			if(pXLCD)
				for (int nSubItem = 0; nSubItem < nCol; nSubItem++)
					pXLCD[nSubItem].strToolTip = _T("");
		}
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CXListCtrl::DeleteAllToolTips"));
	}
}

#endif

#ifndef INCLUDE_VSTS_WARNINGS
#pragma warning (default:6011)
#endif