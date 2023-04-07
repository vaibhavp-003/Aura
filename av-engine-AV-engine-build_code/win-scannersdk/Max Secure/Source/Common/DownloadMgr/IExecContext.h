
/*======================================================================================
FILE             : IExecContext.h
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
				  
CREATION DATE    : 12/28/2009
NOTES		     : Declares the standard interface for running any methods under a thread pool
                   All the classes that needs to be executed in a Thread Pool should implement 
				   the IExecution interface
VERSION HISTORY  : 
======================================================================================*/
#pragma once

interface IExecContext
{
	virtual bool Initialize(HANDLE hQueueEvent) = 0;
    virtual bool Run(bool bLastOperation = false) = 0;
	virtual void DeleteContext() = 0;
	virtual void NotifyQueueEvent() = 0;
};