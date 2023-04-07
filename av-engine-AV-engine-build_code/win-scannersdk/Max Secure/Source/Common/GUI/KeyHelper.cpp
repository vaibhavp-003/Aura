/*=============================================================================
   FILE			: KeyHelper.cpp
   ABSTRACT		: 
   DOCUMENTS	: Refer The GUI design document
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
CREATION DATE   : 11/29/07
   NOTES		:
VERSION HISTORY	:
				
============================================================================*/

// KeyHelper.cpp: implementation of the CBCGKeyHelper class.

#include "stdafx.h"
#include "KeyHelper.h"

#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[]=__FILE__;
#define new DEBUG_NEW
#endif


/*-----------------------------------------------------------------------------
Function		: CBCGKeyHelper (parametric Constructor)
In Parameters	: LPACCEL :
Out Parameters	:
Purpose		:This Function initialise  CBCGKeyHelper class
Author		:
-----------------------------------------------------------------------------*/
CBCGKeyHelper::CBCGKeyHelper(LPACCEL lpAccel):
m_lpAccel (lpAccel)
{
}
/*-----------------------------------------------------------------------------
Function		: CBCGKeyHelper (Default Constructor)
In Parameters	: LPACCEL :
Out Parameters	:
Purpose		:This Function initialise  CBCGKeyHelper class
Author		:
-----------------------------------------------------------------------------*/

CBCGKeyHelper::CBCGKeyHelper():
m_lpAccel (NULL)
{
}
/*-----------------------------------------------------------------------------
Function		: ~CBCGKeyHelper(Destructor)
In Parameters	:
Out Parameters	:
Purpose		:This Function destruct CBCGKeyHelper  class
Author		:
-----------------------------------------------------------------------------*/
CBCGKeyHelper::~CBCGKeyHelper()
{
}
/*-----------------------------------------------------------------------------
Function		: Format
In Parameters	:  CString :contains name of a key
Out Parameters	:
Purpose		:Retrieves a string that represents the name of a key.
Author		:
-----------------------------------------------------------------------------*/
void CBCGKeyHelper::Format (CString& str)const
{
	try
	{
		str.Empty ();

		if(m_lpAccel == NULL)
		{
			ASSERT (FALSE);
			return;
		}

		if(m_lpAccel->fVirt & FCONTROL)
		{
			str += _T("Ctrl+");
		}

		if(m_lpAccel->fVirt & FSHIFT)
		{
			str += _T("Shift+");
		}

		if(m_lpAccel->fVirt & FALT)
		{
			str += _T("Alt+");
		}

		if(m_lpAccel->fVirt & FVIRTKEY)
		{
			TCHAR keyname[64];
			UINT vkey = MapVirtualKey(m_lpAccel->key, 0)<<16;
			GetKeyNameText(vkey, keyname, _countof(keyname));
			str += keyname;
		}
		else if(m_lpAccel->key != 27)	// Don't print esc
		{
			str += (char)m_lpAccel->key;
		}
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CBCGKeyHelper::Format"));
	}
}
/*-----------------------------------------------------------------------------
Function		: AddVirtKeyStr
In Parameters	: CString :
: UINT :
: BOOL :
Out Parameters	: This Function add a virtual key stroke
Purpose		:
Author		:
-----------------------------------------------------------------------------*/
void CBCGKeyHelper::AddVirtKeyStr (CString& str, UINT uiVirtKey, BOOL bLast)const
{
	try
	{
#define BUFFER_LEN 50
		TCHAR szBuffer [BUFFER_LEN + 1];

		TRACE(_T("KeyboardLayout: 0x%x\n"), ::GetKeyboardLayout (0));

		UINT nScanCode = ::MapVirtualKeyEx (uiVirtKey, 0,
			::GetKeyboardLayout (0))<<16 | 0x1;

		if(uiVirtKey >= VK_PRIOR && uiVirtKey <= VK_HELP)
		{
			nScanCode |= 0x01000000;
		}

		::GetKeyNameText (nScanCode, szBuffer, BUFFER_LEN);

		CString strKey(szBuffer);
		strKey.MakeLower();

		//--------------------------------------
		// The first letter should be uppercase:
		//--------------------------------------
		for (int nCount = 0; nCount < strKey.GetLength(); nCount++)
		{
			TCHAR c = strKey[nCount];
			if(IsCharLower (c))
			{
				c = (TCHAR)toupper (c); // Convert single character JY 4-Dec-99
				strKey.SetAt (nCount, c);
				break;
			}
		}

		str += strKey;

		if(!bLast)
		{
			str += _T('+');
		}
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CBCGKeyHelper::AddVirtKeyStr"));
	}
}

