/*======================================================================================
FILE             : NetworkScanner.h
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
				  
CREATION DATE    : 8/1/2009 6:59:48 PM
NOTES		     : Defines the class behaviors for the application
VERSION HISTORY  : 
======================================================================================*/
#pragma once
#include "ScannerBase.h"
#include "S2U.h"

class CNetworkScanner : public CScannerBase
{
public:
	CNetworkScanner(void);
	virtual ~CNetworkScanner(void);

	void ScanNetworkConnectionSEH();

private:
	void ScanNetworkConnection();
	void ScanNetworkConnections();
	CS2U m_objNetworkDBMap;
};
