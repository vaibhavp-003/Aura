/*======================================================================================
   FILE				: OptionTabFunctions.h
   ABSTRACT			: 
   DOCUMENTS		: 
   AUTHOR			: 
   COMPANY			: Aura 
   COPYRIGHT NOTICE :
						(C)Aura
						Created as an unpublished copyright work.  All rights reserved.
						This document and the information it contains is confidential and
						proprietary to Aura.  Hence, it may not be 
						used, copied, reproduced, transmitted, or stored in any form or by any 
						means, electronic, recording, photocopying, mechanical or otherwise, 
						without the prior written permission of Aura
   CREATION DATE	:	2/24/06
   NOTE				:
     VERSION HISTORY  :  Avinash Bhardwaj : Ported to VS2005 with Unicode and X64 bit Compatability,string resources taken from ini.
=======================================================================================*/
#pragma once
#include "S2U.h"

class COptionTabFunctions
{
public:
	
	COptionTabFunctions();
	virtual ~COptionTabFunctions();
	bool DllFunction(int iOperation,CString csValue, HWND hWnd ,CString csSpyName = L"",
						DWORD dwSpyID = 0, CS2U* pobjSpyNameToIDMap = NULL);

private:
	HINSTANCE hinstDLL;
	typedef bool (*GETACTIVEXPROC)(int, CString, HWND ,CString , DWORD, CS2U*);
	GETACTIVEXPROC OptionTabAction;
	void LoadOptionDLL();
	void FreeOptionDLL();
};


