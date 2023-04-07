/*=============================================================================
   FILE			: KeyHelper.h
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

// KeyHelper.h: interface for the CBCGKeyHelper class.


#if !defined(AFX_KEYHELPER_H__283E6045_54C6_11D2_B110_D085EB8D1B3C__INCLUDED_)
#define AFX_KEYHELPER_H__283E6045_54C6_11D2_B110_D085EB8D1B3C__INCLUDED_

#if _MSC_VER >= 1000
#pragma once
#endif // _MSC_VER >= 1000

#include "MaxWarnings.h"

class DLLEXPORT CBCGKeyHelper : public CObject
{
public:
	CBCGKeyHelper();
	CBCGKeyHelper(LPACCEL lpAccel);
	virtual ~CBCGKeyHelper();

	// Atttributes:
	void SetAccelerator (LPACCEL lpAccel)
	{
		m_lpAccel = lpAccel;
	}

	// Operations:
	void Format (CString& str)const;

protected:
	void AddVirtKeyStr (CString& str, UINT uiVirtKey, BOOL bLast = FALSE)const;

	LPACCEL m_lpAccel;
};

#endif // !defined(AFX_KEYHELPER_H__283E6045_54C6_11D2_B110_D085EB8D1B3C__INCLUDED_)
