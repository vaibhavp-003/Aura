/*=============================================================================
   FILE		           : ZipAutoBuffer.h
   ABSTRACT		       : Interface for the CZipAutoBuffer class.
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
#if !defined(AFX_ZIPAUTOBUFFER_H__DEC28C20_83FE_11D3_B7C3_EDEC47A8A86C__INCLUDED_)
#define AFX_ZIPAUTOBUFFER_H__DEC28C20_83FE_11D3_B7C3_EDEC47A8A86C__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

class CZipAutoBuffer  
{
public:
	operator char*()
	{
		return m_pBuffer;
	}

	const char* GetBuffer() const {return m_pBuffer;}
	char* Allocate(DWORD iSize, bool bZeroMemory = false);
	void Release();
	DWORD GetSize() const 
	{
		return m_iSize;
	}	
	bool IsAllocated() const
	{
		return (m_pBuffer != NULL);
	}
	CZipAutoBuffer(DWORD iSize, bool bZeroMemory = false);
	CZipAutoBuffer();
	CZipAutoBuffer(const CZipAutoBuffer& buffer);
	virtual ~CZipAutoBuffer();
	CZipAutoBuffer& operator=(const CZipAutoBuffer& buffer);

protected:
	char* m_pBuffer;
	DWORD m_iSize;
};

#endif // !defined(AFX_ZIPAUTOBUFFER_H__DEC28C20_83FE_11D3_B7C3_EDEC47A8A86C__INCLUDED_)
