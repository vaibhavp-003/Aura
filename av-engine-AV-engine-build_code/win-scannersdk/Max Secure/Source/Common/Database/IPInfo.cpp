/*======================================================================================
   FILE				: IPInfo.cpp
   ABSTRACT			: Information of spyware IP entry. Spyware name and spyware ID of thet IP
   DOCUMENTS		: Network Connection scanner-Design Document.doc
   AUTHOR			: Anand Srivastava
   COMPANY			: Aura 
   COPYRIGHT NOTICE	: (C) Aura
      				  Created as an unpublished copyright work.  All rights reserved.
     				  This document and the information it contains is confidential and
      				  proprietary to Aura.  Hence, it may not be 
      				  used, copied, reproduced, transmitted, or stored in any form or by any 
      				  means, electronic, recording, photocopying, mechanical or otherwise, 
      				  without the prior written permission of Aura
   CREATION DATE	: 10/june/2008
   NOTES			: 
   VERSION HISTORY	: 	
======================================================================================*/

#include "stdafx.h"
#include "IPInfo.h"

IMPLEMENT_SERIAL(CIPInfo, CObject, 1)

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*-------------------------------------------------------------------------------------
Function		: Serialize
In Parameters	: CArchive &archive - archive object
Out Parameters	: void
Purpose			: Serialize member
Author			: Anand Srivastava
--------------------------------------------------------------------------------------*/
void CIPInfo::Serialize(CArchive &archive)
{
	CObject::Serialize(archive);
	if(archive.IsStoring())
		archive << 	csSpywareID << csSpywareName;
	else
		archive >> 	csSpywareID >> csSpywareName;
}
