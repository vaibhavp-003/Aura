/*=============================================================================
   FILE			: InternetOperation.h
   DESCRIPTION	: Header file of CInternetOperation class
   DOCUMENTS	: 
   AUTHOR		: Sandip Sanap
   COMPANY		: Aura 
COPYRIGHT NOTICE:
				(C) Aura
				Created as an unpublished copyright work.  All rights reserved.
				This document and the information it contains is confidential and
				proprietary to Aura.  Hence, it may not be 
				used, copied, reproduced, transmitted, or stored in any form or by any 
				means, electronic, recording, photocopying, mechanical or otherwise, 
				with out the prior written permission of Aura
CREATION DATE   : 21-12-2007
   NOTES		:
VERSION HISTORY	:
============================================================================*/
#pragma once
#include "pch.h"
class CInternetOperation
{

public:
	CInternetOperation(void);
	~CInternetOperation(void);
	bool DownloadFile(const TCHAR *url, const TCHAR *filename);
	BOOL CheckInternetConnection();
};
