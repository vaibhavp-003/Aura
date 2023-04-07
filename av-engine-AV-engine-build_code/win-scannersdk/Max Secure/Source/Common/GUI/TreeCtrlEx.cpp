/*======================================================================================
   FILE			: TreeCtrlEx.cpp
   ABSTRACT		: Class to manage the simple tree control of the tree view.
   DOCUMENTS	: 
   AUTHOR		: Dipali
   COMPANY		: Aura 
   COPYRIGHT NOTICE    :
						(C)Aura:
      					Created as an unpublished copyright work.  All rights reserved.
     					This document and the information it contains is confidential and
      					proprietary to Aura.  Hence, it may not be 
      					used, copied, reproduced, transmitted, or stored in any form or by any 
      					means, electronic, recording, photocopying, mechanical or otherwise, 
      					without the prior written permission of Aura
   CREATION DATE: 13/05/2008
   NOTE			: 
   VERSION HISTORY	:19.0.0.063
=======================================================================================*/
#include "StdAfx.h"
#include "TreeCtrlEx.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*-------------------------------------------------------------------------------------
Function		: CTreeCtrlEx
In Parameters	: -
Out Parameters	: -
Purpose			: Constructor for class CTreeCtrlEx
Author			: Dipali
--------------------------------------------------------------------------------------*/
CTreeCtrlEx::CTreeCtrlEx(bool bUseItemDataStruct)
{
	m_bUseItemDataStruct = bUseItemDataStruct;
}

/*-------------------------------------------------------------------------------------
Function		: ~CTreeCtrlEx
In Parameters	: -
Out Parameters	: -
Purpose			: Destructor for class CTreeCtrlEx
Author			: Dipali
--------------------------------------------------------------------------------------*/
CTreeCtrlEx::~CTreeCtrlEx(void)
{
}


BEGIN_MESSAGE_MAP(CTreeCtrlEx, CTreeCtrl)
	ON_WM_LBUTTONDOWN()
	ON_WM_DESTROY()
END_MESSAGE_MAP()

/*-------------------------------------------------------------------------------------
Function		: OnLButtonDown
In Parameters	: nFlags	- Indicates whether various virtual keys are down
: point		- Specifies the x- and y-coordinate of the cursor
Out Parameters	: -
Purpose			: Called by the framework when the user presses the left mouse button
Author			: Dipali
--------------------------------------------------------------------------------------*/
void CTreeCtrlEx::OnLButtonDown(UINT nFlags, CPoint point)
{
	m_iX = point.x;
	m_iY = point.y;

	CPoint pt;
	pt.x = m_iX;
	pt.y = m_iY;
	if((m_iX < 17 || (m_iX > 34 && m_iX < 41) || m_iX > 53))
	{
		CTreeCtrl::OnLButtonDown(nFlags, point);
		return;
	}
	HTREEITEM hTreeItem = HitTest(pt);
	if(hTreeItem)
	{
		CString csName;
		DWORD_PTR dwItemData = 0;

		if(m_bUseItemDataStruct)
		{
			LPITEMDATA lpItemData = (LPITEMDATA)GetItemData(hTreeItem);
			dwItemData = lpItemData ? lpItemData->bIsParent : 0;
		}
		else
		{
			dwItemData = (DWORD_PTR)GetItemData(hTreeItem);
		}

		csName = GetItemText(hTreeItem);

		BOOL bCheck = FALSE;
		if(GetCheck(hTreeItem))
		{
			bCheck = FALSE;
		}
		else
		{
			bCheck = TRUE;
		}

		if((dwItemData == 1) && m_iX < 34)
		{
			SetAllChildren(hTreeItem,bCheck);
		}
		else
		{
			//HTREEITEM hParent =  GetParentItem(hTreeItem);
			//CheckAllChildCheck(hParent, hTreeItem, bCheck);

		}
	}
	CTreeCtrl::OnLButtonDown(nFlags, point);
}

/*-------------------------------------------------------------------------------------
Function		: CheckAllChildCheck
In Parameters	: HTREEITEM  - Handle of the parent
HTREEITEM - handle of child
BOOL - checked or unchecked
Out Parameters	: void
Purpose			: If all children are checked, check parent.if not uncheck parent
Author			: Dipali
--------------------------------------------------------------------------------------*/
void CTreeCtrlEx::CheckAllChildCheck(HTREEITEM hTreeItem, HTREEITEM hChildExclude,  BOOL bCheck)
{
	int iChild = 0;
	int iChecked = 0;
	if(ItemHasChildren(hTreeItem))
	{
		HTREEITEM hChildItem = GetChildItem(hTreeItem);
		while(hChildItem != NULL)
		{
			iChild++;
			if(GetCheck(hChildItem) == TRUE)
				iChecked++;
			hChildItem = GetNextItem(hChildItem, TVGN_NEXT);
		}
	}
	if(bCheck)
		iChecked++;
	else
		iChecked--;
	if(iChild == iChecked)
		SetCheck(hTreeItem,TRUE);
	else
		SetCheck(hTreeItem,FALSE);

}

/*-------------------------------------------------------------------------------------
Function		: SetAllChildren
In Parameters	: BOOL - Check state
: HTREEITEM  - Handle of the item whose check state is to be modified
Out Parameters	: void
Purpose			: Modifies the check state of item children
Author			: Dipali
--------------------------------------------------------------------------------------*/
void CTreeCtrlEx::SetAllChildren(HTREEITEM hTreeItem,BOOL bCheck)
{
	if(ItemHasChildren(hTreeItem))
	{
		HTREEITEM hChildItem = GetChildItem(hTreeItem);
		while(hChildItem != NULL)
		{
			SetCheck(hChildItem,bCheck);
			hChildItem = GetNextItem(hChildItem, TVGN_NEXT);
		}
	}
}

/*-------------------------------------------------------------------------------------
Function		: OnDestroy
In Parameters	: 
Out Parameters	: void
Purpose			: on control destroy
Author			: Anand Srivastava
--------------------------------------------------------------------------------------*/
void CTreeCtrlEx::OnDestroy(void)
{
	DeleteItemData(GetRootItem());
	CTreeCtrl::OnDestroy();
}

/*-------------------------------------------------------------------------------------
Function		: DeleteItemData
In Parameters	: HTREEITEM hTreeItem
Out Parameters	: void
Purpose			: recursively delete all item data
Author			: Anand Srivastava
--------------------------------------------------------------------------------------*/
void CTreeCtrlEx::DeleteItemData(HTREEITEM hTreeItem)
{
	while(m_bUseItemDataStruct && hTreeItem)
	{
		DeleteItemData(GetChildItem(hTreeItem));
		LPITEMDATA lpItemData = (LPITEMDATA)GetItemData(hTreeItem);
		if(lpItemData) delete lpItemData;
		hTreeItem = GetNextItem(hTreeItem, TVGN_NEXT);
	}
}
