/*======================================================================================
   FILE				: OptionTabFunctions.cpp
   ABSTRACT			: implementation file
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
   CREATION DATE	:   2/24/06 
   NOTE				:
   VERSION HISTORY	:  5/01/2008 : Avinash Bhardwaj : Ported to VS2005 with Unicode and X64 bit Compatability,string resources taken from ini.
=======================================================================================*/
#pragma once
#include "pch.h"
#include "OptionTabFunctions.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

// COptionTabFunctions
/*--------------------------------------------------------------------------------------
Function       : COptionTabFunctions
In Parameters  :
Out Parameters :
Description    : Loads the Option Dll
Author         :
--------------------------------------------------------------------------------------*/
COptionTabFunctions::COptionTabFunctions(): hinstDLL(NULL), OptionTabAction(NULL)
{
	LoadOptionDLL();
}

/*--------------------------------------------------------------------------------------
Function       : ~COptionTabFunctions
In Parameters  :
Out Parameters :
Description    : Unloads the Option dll in d'tor
Author         : Darshit Kasliwal
--------------------------------------------------------------------------------------*/
COptionTabFunctions::~COptionTabFunctions()
{
	FreeOptionDLL();
}

/*-------------------------------------------------------------------------------------
Function		: DllFunction
In Parameters	: int
CString
HWND
Out Parameters	: bool - return the status of Optiontabfunction
Purpose			: calls DLL Functions
Author			:
--------------------------------------------------------------------------------------*/
bool COptionTabFunctions::DllFunction(int iOperation, CString csValue, HWND hWnd, CString csSpyName,
									  DWORD dwSpyID, CS2U* pobjSpyNameToIDMap)
{
	if(OptionTabAction)
	{
		return OptionTabAction(iOperation, csValue, hWnd, csSpyName, dwSpyID, pobjSpyNameToIDMap);
	}
	return false; //SMA
}

/*-------------------------------------------------------------------------------------
Function		: LoadOptionDLL
In Parameters	: -
Out Parameters	: void
Purpose			: Loads Option.dll
Author			:
--------------------------------------------------------------------------------------*/
void COptionTabFunctions::LoadOptionDLL()
{
	hinstDLL = ::LoadLibrary((LPCTSTR)_T("Option.dll"));
	if(hinstDLL)
		OptionTabAction = (GETACTIVEXPROC)GetProcAddress(hinstDLL, "OptionTabAction");
}

/*-------------------------------------------------------------------------------------
Function		: FreeOptionDLL
In Parameters	: -
Out Parameters	: void
Purpose			: Frees Option.dll
Author			:
--------------------------------------------------------------------------------------*/
void COptionTabFunctions::FreeOptionDLL()
{
	if(hinstDLL)
	{
		::FreeLibrary(hinstDLL);
		hinstDLL = NULL;		// Ashwinee.
	}
}

