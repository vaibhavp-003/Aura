/*======================================================================================
FILE             : Singleinstance.h
ABSTRACT         : 
DOCUMENTS        : 
AUTHOR           : Darshan Singh Virdi
COMPANY          : Aura 
COPYRIGHT(NOTICE): (C) Aura
                   Created as an unpublished copyright work.  All rights reserved.
                   This document and the information it contains is confidential and
                   proprietary to Aura.  Hence, it may not be
                   used, copied, reproduced, transmitted, or stored in any form or by any
                   means, electronic, recording, photocopying, mechanical or otherwise,
                   without the prior written permission of Aura.
CREATION DATE   : 24-Feb-2006
NOTES           : Defines the class behaviors for the application
VERSION HISTORY : 
======================================================================================*/
#include "pch.h"
#include <afxmt.h>
#include "singleinstance.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif // _DEBUG

// Manages shared data between applications, could be anything,
// but for this case it is the "command line arguments"
class CSingleInstanceData
{
public :
	CSingleInstanceData(CString & aName);
	virtual ~CSingleInstanceData ();

	CString GetValue ()const;

private :
	enum{MAX_DATA = 256};
	// Data pointer
	LPTSTR  mData;
	// File handle
	HANDLE  mMap;
	// Acces mutex
	CMutex* mMutex;
};

#ifndef INCLUDE_VSTS_WARNINGS
#pragma warning(disable: 6386)
#endif

/*--------------------------------------------------------------------------------------
Function       : CSingleInstanceData
In Parameters  : CString & aName, 
Out Parameters : 
Description    :  Create shared memory mapped file or create view of it
Author         : Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
CSingleInstanceData::CSingleInstanceData(CString & aName)
{
	try
	{
		// Build names
		CString lFileName = aName;
		lFileName += _T("-Data-Mapping-File");

		CString lMutexName = aName;
		lMutexName += _T("-Data-Mapping-Mutex");

		// Create mutex, global scope
		mMutex = new CMutex(FALSE, lMutexName);

		// Create file mapping
		mMap = CreateFileMapping(NULL, NULL, PAGE_READWRITE, 0, sizeof(TCHAR)* MAX_DATA, lFileName);

		if(GetLastError ()== ERROR_ALREADY_EXISTS)
		{
			// Close handle
			if(NULL != mMap)
			{
				CloseHandle(mMap);
			}
			// Open existing file mapping
			mMap = OpenFileMapping(FILE_MAP_WRITE, FALSE, lFileName);
		}

		// Set up data mapping
		mData = (LPTSTR)MapViewOfFile(mMap, FILE_MAP_WRITE, 0, 0, sizeof(TCHAR)* MAX_DATA);

		// Lock file
		CSingleLock lLock(mMutex, TRUE);
		if(lLock.IsLocked ())
		{
			// Clear data
			ZeroMemory(mData, sizeof(TCHAR)* MAX_DATA);
		}
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CSingleInstanceData::CSingleInstanceData"));
	}
}
#ifndef INCLUDE_VSTS_WARNINGS
#pragma warning (default:6386)
#endif

/*--------------------------------------------------------------------------------------
Function       : ~CSingleInstanceData 
In Parameters  : 
Out Parameters : 
Description    : Close memory mapped file
Author         : Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
CSingleInstanceData::~CSingleInstanceData ()
{
	try
	{
		if(mMap)
		{
			// Unmap data from file
			UnmapViewOfFile(mData);

			// Close file
			CloseHandle(mMap);
		}

		// Clean up mutex
		if(mMutex)
		{
			delete mMutex;
		}
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CSingleInstanceData::~CSingleInstanceData"));
	}
}

/*--------------------------------------------------------------------------------------
Function       : GetValue
In Parameters  : 
Out Parameters : CString 
Description    : Get value from memory mapped file
Author         : Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
CString CSingleInstanceData::GetValue() const
{
	try
	{
		// Lock file
		CSingleLock lLock(mMutex, TRUE);
		if(lLock.IsLocked())
		{
			// Return the data
			return mData;
		}
		// Not locked to return empty data
		return _T("");
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CSingleInstanceData::GetValue"));
	}
	return _T("");
}

// Implementation to manage single instance activation
class CSingleInstanceImpl
{
public :
	// Constructor/Destructor
	CSingleInstanceImpl(const CSingleInstance* aOwner);
	virtual ~CSingleInstanceImpl ();

	// Creates the instance handler
	BOOL Create(CString & aName);
	// Sleeping thread waiting for activation
	static UINT Sleeper(LPVOID aObject);

	// Events to singal new instance, and kill thread
	CEvent* mEvent;
	CEvent* mSignal;
	CSingleInstanceData* mData;

	// Owner, so we can get at virtual callbacks
	const CSingleInstance* mOwner;

private:
	//For storing command line.
	CString m_strCommandLine;
};

/*--------------------------------------------------------------------------------------
Function       : CSingleInstanceImpl
In Parameters  : const CSingleInstance *aOwner, 
Out Parameters : 
Description    : Initialise member attributes
Author         : Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
CSingleInstanceImpl::CSingleInstanceImpl(const CSingleInstance *aOwner) 
							: mOwner(aOwner), mEvent(NULL), mSignal(NULL), mData(NULL)
{
}

/*--------------------------------------------------------------------------------------
Function       : ~CSingleInstanceImpl
In Parameters  : 
Out Parameters : 
Description    : Signal event to end thread, wait for thread to signal back, cleanup
Author         : Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
CSingleInstanceImpl::~CSingleInstanceImpl()
{
	try
	{
		// If event and signal exist
		if(mEvent && mSignal)
		{
			// Set signal event to allow thread to exit
			if(mSignal->PulseEvent ())
			{
				// Wait for thread to start exiting
				CSingleLock lWaitForEvent(mEvent, TRUE);
			}
			// Close all open handles
			delete mEvent;
			delete mSignal;
		}
		if(mData)
		{
			delete mData;
		}
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CSingleInstanceImpl::~CSingleInstanceImpl"));
	}
}

/*--------------------------------------------------------------------------------------
Function       : Sleeper
In Parameters  : LPVOID aObject, 
Out Parameters : UINT 
Description    : Sleep on events, wake and activate application or wake and quit
Author         : Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
UINT CSingleInstanceImpl::Sleeper(LPVOID aObject)
{
	try
	{
		// Get single instance pointer
		CSingleInstanceImpl* lSingleInstanceImpl = (CSingleInstanceImpl*)aObject;

		// Build event handle array
		CSyncObject* lEvents [] =
		{
			lSingleInstanceImpl->mEvent,
			lSingleInstanceImpl->mSignal
		};

		// Forever
		BOOL lForever = TRUE;
		while(lForever)
		{
			CMultiLock lWaitForEvents(lEvents, sizeof(lEvents)/ sizeof(CSyncObject*));

			// Goto sleep until one of the events signals, zero CPU overhead
			DWORD lResult = lWaitForEvents.Lock(INFINITE, FALSE);

			// What signaled, 0 = event, another instance started
			if(lResult == WAIT_OBJECT_0 + 0)
			{
				if(lSingleInstanceImpl->mOwner)
				{
					// Wake up the owner with the data (last command line)
					lSingleInstanceImpl->mOwner->WakeUp(lSingleInstanceImpl->mData->GetValue());
				}
			}
			// 1 = signal, time to exit the thread
			else if(lResult == WAIT_OBJECT_0 + 1)
			{
				// Break the forever loop
				lForever = FALSE;
			}
			lWaitForEvents.Unlock();
		}
		// Set event to say thread is exiting
		lSingleInstanceImpl->mEvent->SetEvent();
		return 0;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CSingleInstanceImpl::Sleeper"));
	}
	return 0;
}

/*--------------------------------------------------------------------------------------
Function       : Create
In Parameters  : CString &csGUID, 
Out Parameters : BOOL 
Description    : this Fucntion create Mutex object
Author         : Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
BOOL CSingleInstanceImpl::Create(CString &csGUID)
{
	try
	{
		//just create mutex with valid name in InitInstance ()method of MFC application
		HANDLE hmutex = CreateMutex(NULL,FALSE,csGUID);
		DWORD dwLastErrorCode = GetLastError();
		if(!hmutex)
		{
			return false;
		}
		// then check for that name whether it already exists or not by following code,
		// if exists release mutex and return false otherwise just release the mutex
		{
			if(hmutex && dwLastErrorCode == ERROR_ALREADY_EXISTS)
			{
				ReleaseMutex (hmutex);
				return false;
			}
		}
		ReleaseMutex (hmutex);
		return true;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CSingleInstanceImpl::Create"));
	}
	return false;
}

/*--------------------------------------------------------------------------------------
Function       : CSingleInstance
In Parameters  : 
Out Parameters : 
Description    : Initialize CSingleInstance class, Create implementor
Author         : Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
CSingleInstance::CSingleInstance()
{
	// Create the implementor class
	try
	{
		mImplementor = new CSingleInstanceImpl(this);
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CSingleInstance::CSingleInstance"));
	}
}

/*--------------------------------------------------------------------------------------
Function       : ~CSingleInstance
In Parameters  : 
Out Parameters : 
Description    : Delete implementor
Author         : Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
CSingleInstance::~CSingleInstance()
{
	// If implementor exists delete it
	try
	{
		if(mImplementor)
		{
			delete mImplementor;
		}
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CSingleInstance::~CSingleInstance"));
	}
}

/*--------------------------------------------------------------------------------------
Function       : Create
In Parameters  : CString & aName, 
Out Parameters : BOOL 
Description    : Pass message to implementor
Author         : Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
BOOL CSingleInstance::Create(CString & aName)
{
	try
	{
		if(mImplementor)
		{
			return mImplementor->Create(aName);
		}
		return FALSE;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CSingleInstance::Create"));
	}
	return FALSE;
}

/*--------------------------------------------------------------------------------------
Function       : WakeUp
In Parameters  : LPCTSTR aCommandLine, 
Out Parameters : void 
Description    : Default action, find main application window and make foreground
Author         : Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
void CSingleInstance::WakeUp(LPCTSTR aCommandLine) const
{
	// Find application and main window
	try
	{
		CWinApp* lApplication = AfxGetApp();
		if(lApplication && lApplication->m_pMainWnd)
		{
			// Get window handle
			HWND lWnd = lApplication->m_pMainWnd->GetSafeHwnd();

			if(lWnd)
			{
				// Make main window foreground, flashy, flashy time
				SetForegroundWindow(lWnd);
			}
		}
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CSingleInstance::WakeUp"));
	}
}

/*-------------------------------------------------------------------------------------
Function		: SingleInstance
In Parameters	: void
Out Parameters	: BOOL
Purpose			: Added the session id to the unique guid
				  This helps in running a single instance of anny application in multiple sessions.
				  Every session has its own single instance of this application!
Author			: Darshan - 16-Aug-2012
--------------------------------------------------------------------------------------*/
BOOL CSingleInstance::SingleInstancePerSession(LPCTSTR szUniqueGUID)
{
	DWORD dwProcessSessionID = 0;
	ProcessIdToSessionId(GetCurrentProcessId(), &dwProcessSessionID);
	CString	strGUID;
	strGUID.Format(L"Global\\%s-%d", szUniqueGUID, dwProcessSessionID);
	CSingleInstance objInstance;
	if(objInstance.Create(strGUID) == FALSE)
	{
		return FALSE;
	}
	return TRUE;
}
