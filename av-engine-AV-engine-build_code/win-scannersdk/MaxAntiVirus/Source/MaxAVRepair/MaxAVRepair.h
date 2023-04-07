/*======================================================================================
FILE             : MaxAVRepair.h
ABSTRACT         : This module repaires virus files deteted by AuAVDBScan.dll
DOCUMENTS	     : 
AUTHOR		     : Tushar Kadam + Virus Team
COMPANY		     : Aura 
COPYRIGHT(NOTICE): 
				  (C) Aura
				  Created as an unpublished copyright work.  All rights reserved.
				  This document and the information it contains is confidential and
				  proprietary to Aura.  Hence, it may not be 
				  used, copied, reproduced, transmitted, or stored in any form or by any 
				  means, electronic, recording, photocopying, mechanical or otherwise, 
				  without the prior written permission of Aura.	
				  
CREATION DATE    : June 2010
NOTES		     : This module repaires virus files deteted by AuAVDBScan.dll
				   Contains set of predefine Constants and Repaire routines that can be released in DSVRepaire.db	
VERSION HISTORY  : 
======================================================================================*/

#pragma once
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <tchar.h>

#define DLL_EXPORT		extern "C" __declspec(dllexport)
