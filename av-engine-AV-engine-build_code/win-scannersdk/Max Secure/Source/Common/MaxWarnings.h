/*======================================================================================
FILE             : MaxWarnings.h
ABSTRACT         :
DOCUMENTS	     :
AUTHOR		     : Darshit Kasliwal
COMPANY		     : Aura 
COPYRIGHT(NOTICE):
				  (C) Aura
				  Created as an unpublished copyright work.  All rights reserved.
				  This document and the information it contains is confidential and
				  proprietary to Aura.  Hence, it may not be
				  used, copied, reproduced, transmitted, or stored in any form or by any
				  means, electronic, recording, photocopying, mechanical or otherwise,
				  without the prior written permission of Aura.

CREATION DATE    : 6/16/2009.
NOTES		     : Enabling/Disabling of warnings for code compilation/static code analysis
				   It includes VSTS warnings also
VERSION HISTORY  :
======================================================================================*/
#pragma once
#pragma warning(disable: 4005)     
#pragma warning(disable: 4251)
#pragma warning(disable: 4275)
#pragma warning(disable: 4103)
#pragma warning(disable: 4482)

#ifdef ENABLE_FULL_WARNINGS
#pragma warning( disable : 4267 )
#pragma warning (disable:4244 4018 4701)
#pragma warning(disable: 4312)
#pragma warning(disable: 4311)
#endif

#pragma warning(disable: 6011)     
#pragma warning(disable: 6031)   
#pragma warning(disable: 6246)             
#pragma warning(disable: 6248)      
#pragma warning(disable: 6255)         
#pragma warning(disable: 6284)         
#pragma warning(disable: 6305)  
#pragma warning(disable: 6309)  
#pragma warning(disable: 6385)
#ifdef ENABLE_FULL_WARNINGS
#pragma warning(disable: 6386)   
#endif
#pragma warning(disable: 6387)
