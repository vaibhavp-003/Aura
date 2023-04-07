/*=============================================================================
   FILE		           : ZipBigFile.h
   ABSTRACT		       : Interface for the CZipBigFile class.
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

#if !defined(AFX_ZipBigFile_H__79E0E6BD_25D6_4B82_85C5_AB397D9EC368__INCLUDED_)
#define AFX_ZipBigFile_H__79E0E6BD_25D6_4B82_85C5_AB397D9EC368__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

class CZipBigFile : public CFile  
{
	DECLARE_DYNAMIC(CZipBigFile)
public:
	ULONGLONG Seek(_int64 dOff, UINT nFrom);
	CZipBigFile();
	virtual ~CZipBigFile();

};

#endif // !defined(AFX_ZipBigFile_H__79E0E6BD_25D6_4B82_85C5_AB397D9EC368__INCLUDED_)
