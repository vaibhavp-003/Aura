// LiveUpdate.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "pch.h"
#include "framework.h"
#include "LiveUpdate.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

UINT	LiveUpdateThread(LPVOID lpParam);


UINT LiveUpdateThread(LPVOID lpParam)
{
    bool bException = false;

    CLiveUpdate* pLiveUpdate = (CLiveUpdate*)lpParam;
    if (!pLiveUpdate)
    {
        return 0;
    }
    pLiveUpdate->m_bLiveUpdateThread = true;
    __try
    {
        pLiveUpdate->CheckForLiveUpdate();
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        bException = true;
    }
    pLiveUpdate->m_bLiveUpdateThread = false;
    /*if (bException)
    {
        pLiveUpdate->EndDialog(0);
    }*/
    return 0;
}


// The one and only application object

//CWinApp theApp;
CLiveUpdate theApp;

using namespace std;

int main()
{
    int nRetCode = 0;

    HMODULE hModule = ::GetModuleHandle(nullptr);

    if (hModule != nullptr)
    {
        // initialize MFC and print and error on failure
        if (!AfxWinInit(hModule, nullptr, ::GetCommandLine(), 0))
        {
            // TODO: code your application's behavior here.
            wprintf(L"Fatal Error: MFC initialization failed\n");
            nRetCode = 1;
        }
        else
        {
            CLiveUpdate objLiveUpdate;
            objLiveUpdate.DoLiveUpdate();
            // TODO: code your application's behavior here.
        }
    }
    else
    {
        // TODO: change error code to suit your needs
        wprintf(L"Fatal Error: GetModuleHandle failed\n");
        nRetCode = 1;
    }

    return nRetCode;
}

CLiveUpdate::CLiveUpdate()
{
    m_bAutoUpdate = false;
    m_bLiveUpdateStart = false;
    m_hLiveUpdateThread = NULL;
    m_hLiveUpdateDll = NULL;
    m_lpLiveUpdate = NULL;
    m_lpLiveUpdateStop = NULL;
    m_bLiveUpdateThread = false;
}

CLiveUpdate::~CLiveUpdate()
{
    /*
    if (m_hLiveUpdateThread != NULL)
    {
        if (m_hLiveUpdateThread->m_hThread != NULL)
        {
            ::SuspendThread(m_hLiveUpdateThread->m_hThread);
            TerminateThread(m_hLiveUpdateThread->m_hThread, 0);
        }
    }

    if (m_hLiveUpdateDll != NULL)
    {
        FreeLibrary(m_hLiveUpdateDll);
        m_hLiveUpdateDll = NULL;
        m_lpLiveUpdate = NULL;
        m_lpLiveUpdateStop = NULL;
    }
    */

}

void CLiveUpdate::DoLiveUpdate()
{
	CString csCommandLine = GetCommandLine();
	csCommandLine.Delete(0, csCommandLine.Find('-') + 1);
	csCommandLine.Trim();

	if (csCommandLine.CompareNoCase(_T("AUTO")) == 0)
	{
		m_bAutoUpdate = true;
	}

	else if (csCommandLine.CompareNoCase(_T("AUTOPRODUCTPATCH")) == 0)
	{
        m_bAutoUpdate = true;
	}

	else if (csCommandLine.CompareNoCase(_T("AUTODATABASEPATCH")) == 0)
	{
        m_bAutoUpdate = true;
	}

	else if (csCommandLine.CompareNoCase(_T("DATABASEPATCH")) == 0)
	{
        m_bAutoUpdate = true;
	}

    if (m_bAutoUpdate)
    {
        OnBnClickedButtonLiveupStartStop();
    }
}

void CLiveUpdate::OnBnClickedButtonLiveupStartStop()
{
    int iStop = 0;
    if (m_bLiveUpdateStart == false)
    {
        m_bLiveUpdateStart = true;
        iStop = CheckForLiveUpdate();
        //m_hLiveUpdateThread = AfxBeginThread(LiveUpdateThread, this, THREAD_PRIORITY_NORMAL, NULL, NULL, NULL);
       // WaitForSingleObject(m_hLiveUpdateThread, INFINITE);

    }
    
    if(iStop==0 || iStop == 2)
    {
        if (m_hLiveUpdateDll != NULL)
        {
            if (m_lpLiveUpdateStop != NULL)
            {
                m_lpLiveUpdateStop();
            }
            if (m_hLiveUpdateDll != NULL)
            {
                FreeLibrary(m_hLiveUpdateDll);
            }
            m_hLiveUpdateDll = NULL;
            m_lpLiveUpdate = NULL;
            m_lpLiveUpdateStop = NULL;
           /* if (m_hLiveUpdateThread && m_hLiveUpdateThread->m_hThread)
            {
                if (m_bLiveUpdateThread)
                {
                    ::TerminateThread(m_hLiveUpdateThread->m_hThread, 0);
                }
                ::CloseHandle(m_hLiveUpdateThread->m_hThread);
            }*/
        }
    }
}

int CLiveUpdate::CheckForLiveUpdate()
{
    int bRet = 0;

    LoadLiveUpdate();
    if (m_hLiveUpdateDll != NULL && m_lpLiveUpdate != NULL)
    {
        SENDSDKLVMESSAGEUI pSendSDKMessageToUI = NULL;
        pSendSDKMessageToUI = NULL;//&SendMessageToUI;
        bRet = m_lpLiveUpdate(pSendSDKMessageToUI, 2);
    }

    return bRet;
}

bool CLiveUpdate::LoadLiveUpdate()
{
    bool bRet = false;
    if (m_hLiveUpdateDll == NULL)
    {
        m_hLiveUpdateDll = LoadLibrary(_T("AuLiveUpdateDLL.dll"));
        if (m_hLiveUpdateDll == NULL)
        {
            AddLogEntry(_T("\nUnable to load AuLiveUpdate dll ..... \r\n"));
        }
        else
        {
            m_lpLiveUpdate = (LPUPDATE)GetProcAddress(m_hLiveUpdateDll, "StartLiveUpdate");
            m_lpLiveUpdateStop = (LPSTOPUPDATE)GetProcAddress(m_hLiveUpdateDll, "StopLiveUpdate");
            if (m_lpLiveUpdate == NULL || m_lpLiveUpdateStop == NULL)
            {
                FreeLibrary(m_hLiveUpdateDll);
                m_hLiveUpdateDll = NULL;
                m_lpLiveUpdate = NULL;
                m_lpLiveUpdateStop = NULL;

                AddLogEntry(_T("\nUnable to load AuLiveUpdate dll ..... \r\n"));
            }
            else
            {
                bRet = true;
            }
        }
    }
    return bRet;
}