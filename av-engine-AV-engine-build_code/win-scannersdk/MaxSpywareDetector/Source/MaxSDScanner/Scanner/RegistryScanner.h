/*======================================================================================
FILE             : RegistryScanner.h
ABSTRACT         :
DOCUMENTS	     : 
AUTHOR		     : Darshan Singh Virdi
COMPANY		     : Aura 
COPYRIGHT(NOTICE): 
				  (C) Aura
				  Created as an unpublished copyright work.  All rights reserved.
				  This document and the information it contains is confidential and
				  This document and the information it contains is confidential and
				  proprietary to Aura.  Hence, it may not be 
				  used, copied, reproduced, transmitted, or stored in any form or by any 
				  means, electronic, recording, photocopying, mechanical or otherwise, 
				  without the prior written permission of Aura.	
				  
CREATION DATE    : 8/1/2009 7:47:37 PM
NOTES		     : Defines the class behaviors for the application
VERSION HISTORY  : 
======================================================================================*/
#pragma once
#include "RegistryBase.h"

class CRegistryScanner : public CRegistryBase
{
public:
	CRegistryScanner(void);
	~CRegistryScanner(void);

	void ScanRegistry(CS2U* objFilesList, CS2U* objFoldersList, bool bScanReferences);
	void ScanRegFixEntry(bool bRegFixForOptionTab);
};
