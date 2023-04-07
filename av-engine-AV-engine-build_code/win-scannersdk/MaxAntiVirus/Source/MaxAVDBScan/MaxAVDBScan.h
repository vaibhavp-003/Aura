/*======================================================================================
FILE				: MaxAVDBScan.h
ABSTRACT			: Dll export header for AuAVDBScan.dll
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
NOTES				: This class module keeps the information of virus names identifiers of signature loaded in memory.
VERSION HISTORY		: 
				Version: 1.0.1.1
				Date:22-Apr-2010
				Description :Check in code changed by Tushar
=====================================================================================*/
#pragma once
#include "pch.h"

extern "C" DWORD LoadSigDBEx(SENDMESSAGETOUI lpSendMessaegToUI);
extern "C" int SendFile4ScanningEx(LPCTSTR sz_FilePath);
extern "C" int UnLoadSigDBEx();
#define DLL_EXPORT	extern "C" __declspec(dllexport)

