/*======================================================================================
FILE				: PDFSig.h
ABSTRACT			: Return value's constant
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
NOTES				: Return value's constant.
VERSION HISTORY		: 
				Version: 1.0.1.1
				Date:22-Apr-2010
				Description :Check in code changed by Tushar
=====================================================================================*/
#pragma once

#ifndef RETURN_VALUES
	#define	RETURN_VALUES
#endif

// GLOBAL VALUES
#define		MAX_SZ_LEN				9500//1024
#define		MAX_SEC_SIG_LEN			9500//800
#define		SCAN_BUFFER_LEN			40960 //35840//20480//10240
#define		SECTION_HEADER_LEN		100
#define     SCAN_SCRIPT_BUFFER_LEN   65536

#define		ERR_SUCCESS				 0

#define		ERR_ZERO_LEN_INPUT		-1
#define		ERR_IN_OPENING_FILE		-2
#define		ERR_IN_READING_FILE		-3
#define		ERR_INVALID_INPUT		-4
#define		ERR_NEW_ALLOC_FAIL		-5
#define		ERR_INVALID_POINTER		-6
#define		ERR_FILE_NOT_FOUND		-7
#define		ERR_ZERO_LEN_FILE		-8
#define		ERR_INVALID_FILE		-9
#define		ERR_REACH_FILE_END		-10
#define		ERR_BUFF_END			-11
