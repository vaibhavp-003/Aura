
/*======================================================================================
FILE             : DownloadManagerApp.h
ABSTRACT         :
DOCUMENTS	     : 
AUTHOR		     : Sandip Sanap
COMPANY		     : Aura 
COPYRIGHT(NOTICE): 
				  (C) Aura
				  Created as an unpublished copyright work.  All rights reserved.
				  This document and the information it contains is confidential and
				  proprietary to Aura.  Hence, it may not be 
				  used, copied, reproduced, transmitted, or stored in any form or by any 
				  means, electronic, recording, photocopying, mechanical or otherwise, 
				  without the prior written permission of Aura.	
CREATION DATE    : 12/28/2009
NOTES		     : Defines the class behaviors for the application
VERSION HISTORY  : 
======================================================================================*/

#pragma once
#include "IController.h"
class CDownloadManagerApp
{
public:
	CDownloadManagerApp(void);
	~CDownloadManagerApp(void);
	bool StartController(LPVOID pThis);
	bool StartScanner(LPVOID pThis);
	bool InitDownloadManagerApp(void);
	bool ExitScanner(void);
	IController *m_pIController;
};

extern CDownloadManagerApp theDownloadManagerApp;