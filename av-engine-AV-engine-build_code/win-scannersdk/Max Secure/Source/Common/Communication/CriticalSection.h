/*======================================================================================
FILE             : CriticalSection.h
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
				  
CREATION DATE    : 5/14/2009.
NOTES		     : Declares 3 Wrapper classes for using Critical section and
				   Semaphores automatically. Primary purpose is to avoid deadlock condition
				   which generally happens due to programming errors or due to unhandled
				   exceptions and the lock is not released
				   The CAutoCriticalSection class automatically releases the assigned synch object
				   during stack cleanup even if the function returns inbetween
VERSION HISTORY  : 
======================================================================================*/
#pragma once
const int MAX_SEM_COUNT = 1;
const int MAX_WAIT_COUNT = 60000*2;
class CMaxSemaphore;
class CAutoCriticalSection;
class CAutoSemaphore;

class CMaxCriticalSection
{
public:
	CMaxCriticalSection();
	virtual ~CMaxCriticalSection();

	void Lock();
	void Unlock();

private:
	CRITICAL_SECTION m_CritSect;
};

class CMaxSemaphore
{
public:
	CMaxSemaphore(int nMaxCount = MAX_SEM_COUNT);
	virtual ~CMaxSemaphore();

	void Lock();
	void Unlock();

private:
	HANDLE m_hSemaphore;;
	int m_nMaxCount;
};

class CAutoCriticalSection
{
public:
	CAutoCriticalSection(CMaxCriticalSection& rCritSect);
	virtual ~CAutoCriticalSection();

private:
	CMaxCriticalSection& m_rCritSect;
};

class CAutoSemaphore
{
public:
	CAutoSemaphore(CMaxSemaphore& rSemaphore);
	virtual ~CAutoSemaphore();

private:
	CMaxSemaphore& m_rSemaphore;
};