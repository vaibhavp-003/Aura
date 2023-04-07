/*======================================================================================
   FILE				: VirusScannerBase.cpp
   ABSTRACT			: This abstract base class, as of today supports scanning for Virus 
						using Virus Scanner
   DOCUMENTS		: 
   AUTHOR			: Darshan Singh Virdi
   COMPANY			: Aura 
   COPYRIGHT NOTICE	: (C) Aura
      				  Created in 2008 as an unpublished copyright work.  All rights reserved.
     				  This document and the information it contains is confidential and
      				  proprietary to Aura.  Hence, it may not be 
      				  used, copied, reproduced, transmitted, or stored in any form or by any 
      				  means, electronic, recording, photocopying, mechanical or otherwise, 
      				  without the prior written permission of Aura
   CREATION DATE	: 20-Apr-2010
   NOTES			: 
   VERSION HISTORY	: 
=====================================================================================*/
#include "pch.h"
#include "VirusScannerBase.h"

#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*-------------------------------------------------------------------------------------
Function		: Constructor
In Parameters	: None
Out Parameters	: None
Purpose			: Init class objects
Author			: Darshan Singh Virdi
Description		: init class variables
--------------------------------------------------------------------------------------*/
CVirusScannerBase::CVirusScannerBase(): m_bStopScanning(false),m_bUSBScan(false),m_bIsActMon(false)
{
}

/*-------------------------------------------------------------------------------------
Function		: Destructor
In Parameters	:
Out Parameters	:
Purpose			: Deinitialize the dll
Author			: Darshan Singh Virdi
Description		: 
--------------------------------------------------------------------------------------*/
CVirusScannerBase::~CVirusScannerBase()
{
}
