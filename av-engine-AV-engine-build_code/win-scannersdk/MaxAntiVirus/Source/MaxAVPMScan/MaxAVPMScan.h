/*======================================================================================
FILE				: MaxAVPMScan.h
ABSTRACT			: AuAVPMScan.dll module.
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
CREATION DATE		: 25 Jun 2010
NOTES				: This is main polymorphic scanning engine of Antivirus.
VERSION HISTORY		: 
=====================================================================================*/
#pragma once
#include <pch.h>

//#include <afx.h>
#include <stdlib.h>
#include <crtdbg.h>
#include <stdio.h>
#include <io.h>
#include <fcntl.h>
#include <tchar.h>
#include <sys/stat.h>
#include <share.h>
#include "CRTCheck.h"

#define DLL_EXPORT		extern "C" __declspec(dllexport)
extern CCRTCheck objCheck;