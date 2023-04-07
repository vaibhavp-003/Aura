/*======================================================================================
   FILE				: SetCtrlItem.h 
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
#pragma once

class CSetCtrlItem : public CWnd
{
	DECLARE_DYNAMIC(CSetCtrlItem)

public:
	CSetCtrlItem();
	virtual ~CSetCtrlItem();
	void SetItem(HWND hWnd,CString value, int iRow, int iCol,int iImage = 0,int iData = -1);
	HTREEITEM SetTreeItem(HWND hWnd,CString csValue,int iImage,HTREEITEM htree=NULL,int iData=-1);

protected:
	DECLARE_MESSAGE_MAP()
};


