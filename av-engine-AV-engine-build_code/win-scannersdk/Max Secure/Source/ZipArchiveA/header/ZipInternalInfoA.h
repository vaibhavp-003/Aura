/*=============================================================================
   FILE		           : ZipInternalInfoA.h
   ABSTRACT		       : interface for the CZipInternalInfoA class.
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

#if !defined(AFX_ZIPINTERNALINFOA_H__C6749101_590C_4F74_8121_B82E3BE9FA44__INCLUDED_)
#define AFX_ZIPINTERNALINFOA_H__C6749101_590C_4F74_8121_B82E3BE9FA44__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000
#include "ZipAutoBufferA.h"
#include "zlib.h"

class CZipInternalInfoA  
{
public:
	DWORD m_iBufferSize;
	z_stream m_stream;
	DWORD m_uUncomprLeft;
	DWORD m_uComprLeft;
	DWORD m_uCrc32;
	void Init();
	CZipAutoBufferA m_pBuffer;
	CZipInternalInfoA();
	virtual ~CZipInternalInfoA();
};

#endif // !defined(AFX_ZIPINTERNALINFOA_H__C6749101_590C_4F74_8121_B82E3BE9FA44__INCLUDED_)
