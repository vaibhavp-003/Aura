/*======================================================================================
FILE				: SecSigDb.h
ABSTRACT			: Manages list of Secondary Signature matching
DOCUMENTS			: 
AUTHOR				: Tushar Kadam
COMPANY				: Aura 
COPYRIGHT NOTICE	: (C) Aura
					Created as an unpublished copyright work.  All rights reserved.
					This document and the information it contains is confidential and
					proprietary to Aura.  Hence, it may not be 
					used, copied, reproduced, transmitted, or stored in any form or by any 
					means, electronic, recording, photocopying, mechanical or otherwise, 
					without the prior written permission of Aura
CREATION DATE		: 22-Apr-2010
NOTES				: Manages list of Secondary Signature matching
VERSION HISTORY		: 
				Version: 1.0.1.1
				Date:22-Apr-2010
				Description :Check in code changed by Tushar
=====================================================================================*/
#pragma once
#include <windows.h>
#ifndef SIGMATCHLINK
	#define SIGMATCHLINK
#endif

class CSigMatchLink
{
public:
	CSigMatchLink(void);
	~CSigMatchLink(void);
	unsigned int m_FinalSigsCnt;
	unsigned int **m_FinalSigs;
};
