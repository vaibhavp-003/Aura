/*======================================================================================
   FILE			: TreeCtrlEx.h
   ABSTRACT		: header file of CTreeCtrlEx
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
#pragma once
#include "afxcmn.h"

typedef struct _tagItemData
{
	DWORD	dwID;
	BYTE	byType;
	bool	bIsParent;
}ITEMDATA, *PITEMDATA, *LPITEMDATA;

class CTreeCtrlEx : public CTreeCtrl
{
public:
	bool	m_bUseItemDataStruct;
	CTreeCtrlEx(bool bUseItemDataStruct = false);
	~CTreeCtrlEx(void);
	afx_msg void OnDestroy(void);
	void DeleteItemData(HTREEITEM hTreeItem);
	DECLARE_MESSAGE_MAP()
	int m_iX, m_iY;
	afx_msg void OnLButtonDown(UINT nFlags, CPoint point);
	void SetAllChildren(HTREEITEM hTreeItem,BOOL bCheck);
	void CheckAllChildCheck(HTREEITEM hTreeItem, HTREEITEM hChildExclude, BOOL bCheck);
};
