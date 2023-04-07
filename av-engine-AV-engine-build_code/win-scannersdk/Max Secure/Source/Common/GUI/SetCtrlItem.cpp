/*======================================================================================
   FILE				: SetCtrlItem.cpp 
   ABSTRACT			: This class will be used for the common function that most of the 
					  OptionDll classes are using. This class is used to add data into UI
					  list or tree.
   DOCUMENTS		: OptionDll Design.doc
   AUTHOR			: Dipali Pawar
   COMPANY			: Aura 
   COPYRIGHT NOTICE	: (C) Aura
      				  Created as an unpublished copyright work.  All rights reserved.
     				  This document and the information it contains is confidential and
      				  proprietary to Aura.  Hence, it may not be 
      				  used, copied, reproduced, transmitted, or stored in any form or by any 
      				  means, electronic, recording, photocopying, mechanical or otherwise, 
      				  without the prior written permission of Aura
   CREATION DATE	: 
   NOTE				:
   VERSION HISTORY	: 
						Version : 11-08-07
						Resource : Dipali
						Description : Added unicode and 64 support
======================================================================================*/

#include "stdafx.h"
#include "SetCtrlItem.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif
// CSetCtrlItem

IMPLEMENT_DYNAMIC(CSetCtrlItem, CWnd)

/*-------------------------------------------------------------------------------------
	Function		: CSetCtrlItem
	In Parameters	: -
	Out Parameters	: -
	Purpose			: standard constructor
	Author			: Dipali Pawar
--------------------------------------------------------------------------------------*/
CSetCtrlItem::CSetCtrlItem()
{
}

/*-------------------------------------------------------------------------------------
	Function		: CSetCtrlItem
	In Parameters	: -
	Out Parameters	: -
	Purpose			: standard desstructor
	Author			: Dipali Pawar
--------------------------------------------------------------------------------------*/
CSetCtrlItem::~CSetCtrlItem()
{
}


BEGIN_MESSAGE_MAP(CSetCtrlItem, CWnd)
END_MESSAGE_MAP()

/*-------------------------------------------------------------------------------------
	Function		: SetItem
	In Parameters	: HWND - window handle
					  CString - value
					  int - row
					  int - col
					  int - image ID
					  int - data
	Out Parameters	: void
	Purpose			: to insert the item in UI list control
	Author			: Dipali Pawar
--------------------------------------------------------------------------------------*/
void CSetCtrlItem::SetItem(HWND hWnd,CString csValue, int iRow, int iCol,int iImage,int iData)
{
    //Fill the LVITEM structure with the 
    //values given as parameters.
	LVITEM lvItem = {0};
    lvItem.mask = LVIF_TEXT ;
    lvItem.iItem = iRow;
	lvItem.pszText = csValue.GetBuffer();
	csValue.ReleaseBuffer();
    lvItem.iSubItem = iCol;
	if(iData != -1)
	{
		lvItem.lParam = iData;
	}
    if(iCol >0)
	{
		//set the value of listItem
		ListView_SetItem(hWnd,&lvItem);
	}
    else
	{
		lvItem.mask += LVIF_PARAM | LVIF_IMAGE;
		lvItem.iImage = iImage;
        //Insert the value into List
        ListView_InsertItem(hWnd,&lvItem);
	}
}

/*-------------------------------------------------------------------------------------
	Function		: SetTreeItem
	In Parameters	: HWND - window handle
					  CString - value
					  int - image ID
					  HTREEITEM - item structure
					  int - data
	Out Parameters	: HTREEITEM - 
	Purpose			: to insert the item in UI list control
	Author			: Dipali Pawar
--------------------------------------------------------------------------------------*/
HTREEITEM CSetCtrlItem::SetTreeItem(HWND hWnd,CString csValue,int iImage,HTREEITEM htree,int iData)
{
	TVINSERTSTRUCT tvInsert = {0};
	tvInsert.hParent = htree;
	tvInsert.hInsertAfter = NULL;
	tvInsert.item.mask = TVIF_TEXT|TVIF_PARAM|LVIF_IMAGE|TVIF_SELECTEDIMAGE;
	tvInsert.item.pszText = csValue.GetBuffer();
	tvInsert.item.iImage=iImage;
	tvInsert.item.iSelectedImage=iImage;
	
	if(iData!=-1)
	{
		tvInsert.item.lParam = iData;
	}

	csValue.ReleaseBuffer();
	
	htree = (HTREEITEM)::SendMessage(hWnd,TVM_INSERTITEM,(WPARAM)0,(LPARAM)&tvInsert);	
	return htree;
}
