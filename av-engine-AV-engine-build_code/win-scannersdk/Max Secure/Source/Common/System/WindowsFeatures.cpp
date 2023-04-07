#include "stdafx.h"
#include "WindowsFeatures.h"
#include "MaxConstant.h"

CWindowsFeatures::CWindowsFeatures()
{

}

CWindowsFeatures::~CWindowsFeatures()
{

}

bool CWindowsFeatures::CheckForFirewallSettingAndConfigure(int iType)
{
	HRESULT hr = S_OK;
	HRESULT comInit = E_FAIL;
	INetFwProfile* fwProfile = NULL;
	bool bRet = false;

	// Initialize COM.
	comInit = CoInitializeEx(0, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
	COINITIALIZE_OUTPUTDEBUGSTRING(comInit);
	// Ignore RPC_E_CHANGED_MODE; this just means that COM has already been
	// initialized with a different mode. Since we don't care what the mode is,
	// we'll just use the existing mode.
	if (comInit != RPC_E_CHANGED_MODE)
	{
		hr = comInit;
		if (FAILED(hr))
		{
			OutputDebugString(L"CoInitializeEx failed: CheckForFirewallSettingAndConfigure\n");
			goto error;
		}
	}

	// Retrieve the firewall profile currently in effect.
	hr = WindowsFirewallInitialize(&fwProfile);
	if (FAILED(hr))
	{
		OutputDebugString(L"WindowsFirewallInitialize failed: \n");
		goto error;
	}
	
	switch(iType)
	{
	case 1:
		{
			hr = S_OK;
			BOOL fwOn;

			_ASSERT(fwProfile != NULL);

			// Check to see if the firewall is on.
			hr = WindowsFirewallIsOn(fwProfile, &fwOn);
			if (FAILED(hr))
			{
				OutputDebugString(L"WindowsFirewallIsOn failed:\n");
				goto error;
			}
			if(fwOn)
			{
				// Release the firewall profile.
				bRet = true;
				goto error;
			}
		}
		break;
	case 2:
		{
			_ASSERT(fwProfile != NULL);
			// Turn the firewall off.
			hr = fwProfile->put_FirewallEnabled(VARIANT_FALSE);
			if (FAILED(hr))
			{
				OutputDebugString(L"put_FirewallEnabled failed:\n");
			}
			OutputDebugString(L"The firewall is now off.\n");
			goto error;
		}
		break;
	case 3:
		{
			_ASSERT(fwProfile != NULL);
			hr = fwProfile->put_FirewallEnabled(VARIANT_TRUE);
			if (FAILED(hr))
			{
				OutputDebugString(L"put_FirewallEnabled failed:\n");
			}
			OutputDebugString(L"The firewall is now on.\n");
			goto error;
   		}
		break;
	}

error:
    // Release the firewall profile.
    if (fwProfile != NULL)
    {
        fwProfile->Release();
    }
    // Uninitialize COM.
	CoUninitialize();
	return bRet;
}

HRESULT CWindowsFeatures::WindowsFirewallIsOn(IN INetFwProfile* fwProfile, OUT BOOL* fwOn)
{
    HRESULT hr = S_OK;
    VARIANT_BOOL fwEnabled;

    _ASSERT(fwProfile != NULL);
    _ASSERT(fwOn != NULL);

    *fwOn = FALSE;

    // Get the current state of the firewall.
    hr = fwProfile->get_FirewallEnabled(&fwEnabled);
    if (FAILED(hr))
    {
        OutputDebugString(L"get_FirewallEnabled failed: WindowsFirewallIsOn \n");
        goto error;
    }

    // Check to see if the firewall is on.
    if (fwEnabled != VARIANT_FALSE)
    {
        *fwOn = TRUE;
        OutputDebugString(L"The firewall is on.\n");
    }
    else
    {
        OutputDebugString(L"The firewall is off.\n");
    }

error:

    return hr;
}

HRESULT CWindowsFeatures::WindowsFirewallInitialize(OUT INetFwProfile** fwProfile)
{
    HRESULT hr = S_OK;
    INetFwMgr* fwMgr = NULL;
    INetFwPolicy* fwPolicy = NULL;

    _ASSERT(fwProfile != NULL);

    *fwProfile = NULL;

    // Create an instance of the firewall settings manager.
    hr = CoCreateInstance(__uuidof(NetFwMgr), NULL, CLSCTX_INPROC_SERVER, __uuidof(INetFwMgr), (void**)&fwMgr);
	COCREATE_OUTPUTDEBUGSTRING(hr);
    if (FAILED(hr))
    {
        OutputDebugString(L"CoCreateInstance failed: WindowsFirewallInitialize\n");
        goto error;
    }

    // Retrieve the local firewall policy.
    hr = fwMgr->get_LocalPolicy(&fwPolicy);
    if (FAILED(hr))
    {
        OutputDebugString(L"get_LocalPolicy failed: WindowsFirewallInitialize\n");
        goto error;
    }

    // Retrieve the firewall profile currently in effect.
    hr = fwPolicy->get_CurrentProfile(fwProfile);
    if (FAILED(hr))
    {
        OutputDebugString(L"get_CurrentProfile failed: WindowsFirewallInitialize\n");
        goto error;
    }

error:

    // Release the local firewall policy.
    if (fwPolicy != NULL)
    {
        fwPolicy->Release();
    }

    // Release the firewall settings manager.
    if (fwMgr != NULL)
    {
        fwMgr->Release();
    }

    return hr;
}

void CWindowsFeatures::DisbaleFirewallOnWindows7(BOOL bEnable)
{
    HRESULT hrComInit = S_OK;
    HRESULT hr = S_OK;

    INetFwPolicy2 *pNetFwPolicy2 = NULL;

    // Initialize COM.
    hrComInit = CoInitializeEx(0, COINIT_APARTMENTTHREADED);
	COINITIALIZE_OUTPUTDEBUGSTRING(hrComInit);

    // Ignore RPC_E_CHANGED_MODE; this just means that COM has already been
    // initialized with a different mode. Since we don't care what the mode is,
    // we'll just use the existing mode.
    if (hrComInit != RPC_E_CHANGED_MODE)
    {
        if (FAILED(hrComInit))
        {
            OutputDebugString(L"CoInitializeEx failed: \n");
            goto Cleanup;
        }
    }

    // Retrieve INetFwPolicy2
    hr = WFCOMInitializeWin7(&pNetFwPolicy2);
    if (FAILED(hr))
    {
        goto Cleanup;
    }

    // Disable Windows Firewall for the Domain profile
    hr = pNetFwPolicy2->put_FirewallEnabled(NET_FW_PROFILE2_DOMAIN, bEnable);
    if (FAILED(hr))
    {
        OutputDebugString(L"put_FirewallEnabled failed for Domain: \n");
        goto Cleanup;
    }

    // Disable Windows Firewall for the Private profile
    hr = pNetFwPolicy2->put_FirewallEnabled(NET_FW_PROFILE2_PRIVATE, bEnable);
    if (FAILED(hr))
    {
        OutputDebugString(L"put_FirewallEnabled failed for Private: \n");
        goto Cleanup;
    }

    // Disable Windows Firewall for the Public profile
    hr = pNetFwPolicy2->put_FirewallEnabled(NET_FW_PROFILE2_PUBLIC, bEnable);
    if (FAILED(hr))
    {
        OutputDebugString(L"put_FirewallEnabled failed for Public:\n");
        goto Cleanup;
    }

Cleanup:

    // Release INetFwPolicy2
    if (pNetFwPolicy2 != NULL)
    {
        pNetFwPolicy2->Release();
    }

    // Uninitialize COM.
	CoUninitialize();

    return;
}


// Instantiate INetFwPolicy2
HRESULT CWindowsFeatures::WFCOMInitializeWin7(INetFwPolicy2** ppNetFwPolicy2)
{
    HRESULT hr = S_OK;

    hr = CoCreateInstance(__uuidof(NetFwPolicy2), NULL, CLSCTX_INPROC_SERVER, __uuidof(INetFwPolicy2), (void**)ppNetFwPolicy2);
	COCREATE_OUTPUTDEBUGSTRING(hr);
    if (FAILED(hr))
    {
        OutputDebugString(L"CoCreateInstance for INetFwPolicy2 failed:\n");
        goto Cleanup;        
    }

Cleanup:
    return hr;
}