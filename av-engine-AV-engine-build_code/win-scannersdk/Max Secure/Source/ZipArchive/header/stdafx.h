/*=============================================================================
   FILE		           : stdafx.h
   ABSTRACT		       :  include file for standard system include files, or project specific include files that are used frequently, but
						  are changed infrequently
   DOCUMENTS	       : 
   AUTHOR		       : 
   COMPANY		       : Aura 
   COPYRIGHT NOTICE    :
						(C)Aura:
      					Created as an unpublished copyright work.  All rights reserved.
     					This document and the information it contains is confidential and
      					proprietary to Aura.  Hence, it may not be 
      					used, copied, reproduced, transmitted, or stored in any form or by any 
      					means, electronic, recording, photocopying, mechanical or otherwise, 
      					without the prior written permission of Aura
   CREATION DATE      : 
   NOTES		      : 
   VERSION HISTORY    :
				
=============================================================================*/
#if !defined(AFX_STDAFX_H__926F70F4_1B34_49AA_9532_498E8D2F3495__INCLUDED_)
#define AFX_STDAFX_H__926F70F4_1B34_49AA_9532_498E8D2F3495__INCLUDED_
// #include "UseMSPrivateAssemblies.h"
#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#define VC_EXTRALEAN		// Exclude rarely-used stuff from Windows headers

#ifndef WINVER				// Allow use of features specific to Windows XP or later.
#define WINVER 0x0501		// Change this to the appropriate value to target other versions of Windows.
#endif

//3rd Party Library Skipping the changes. To be done later
#ifndef INCLUDE_VSTS_WARNINGS
#pragma warning(disable: 4996)
#pragma warning(disable: 6011)
#pragma warning(disable: 6031)
#pragma warning(disable: 6202)
#pragma warning(disable: 6246)
#pragma warning(disable: 6385)
#pragma warning(disable: 6387)
#endif



#include <afx.h>
#include <afxwin.h>


#ifdef _DEBUG
#define CRTDBG_MAP_ALLOC
#include <stdlib.h>
#include <crtdbg.h>
#endif

#endif // !defined(AFX_STDAFX_H__926F70F4_1B34_49AA_9532_498E8D2F3495__INCLUDED_)
