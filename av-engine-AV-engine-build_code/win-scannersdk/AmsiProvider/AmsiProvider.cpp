#include "stdafx.h"

using namespace Microsoft::WRL;

// Define a trace logging provider: 00604c86-2d25-46d6-b814-cd149bfdf0b3
TRACELOGGING_DEFINE_PROVIDER(g_traceLoggingProvider, "AuAmsiProvider",
    (0x00604c86, 0x2d25, 0x46d6, 0xb8, 0x14, 0xcd, 0x14, 0x9b, 0xfd, 0xf0, 0xb3));

HMODULE g_currentModule;
DWORD	g_dwAMSIOn = 0x00;

DWORD IsMaxAMSIOn()
{
	DWORD	dwRetValue = 0x00;
	HKEY	hMaxKey = NULL;

	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\AMSI\\Providers\\{992DACE9-4CBB-4208-889A-A42431FE4827}", 0x00, KEY_QUERY_VALUE | KEY_READ, &hMaxKey) == ERROR_SUCCESS)
	{
		if (hMaxKey != NULL)
		{
			TCHAR	szData[512] = { 0x00 };
			TCHAR	dwData = 0x00;
			DWORD	dwDataLen = 0x04;
			if (RegQueryValueEx(hMaxKey, L"AuFileless", NULL, NULL, (LPBYTE)&dwData, &dwDataLen) == ERROR_SUCCESS)
			{
				dwRetValue = dwData;
			}
			RegCloseKey(hMaxKey);
			hMaxKey = NULL;
		}
	}
	

	return dwRetValue;
}

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID reserved)
{
	
    switch (reason)
    {
    case DLL_PROCESS_ATTACH:
		OutputDebugString(L"AU AMSI Provider : DLL_PROCESS_ATTACH");
		g_dwAMSIOn = IsMaxAMSIOn();
        g_currentModule = module;
        DisableThreadLibraryCalls(module);
        TraceLoggingRegister(g_traceLoggingProvider);
        TraceLoggingWrite(g_traceLoggingProvider, "Loaded");
        Module<InProc>::GetModule().Create();
        break;

    case DLL_PROCESS_DETACH:
		OutputDebugString(L"AU AMSI Provider : DLL_PROCESS_DETACH");
        Module<InProc>::GetModule().Terminate();
        TraceLoggingWrite(g_traceLoggingProvider, "Unloaded");
        TraceLoggingUnregister(g_traceLoggingProvider);
        break;
    }
    return TRUE;
}

#pragma region COM server boilerplate
HRESULT WINAPI DllCanUnloadNow()
{
    return Module<InProc>::GetModule().Terminate() ? S_OK : S_FALSE;
}

STDAPI DllGetClassObject(_In_ REFCLSID rclsid, _In_ REFIID riid, _Outptr_ LPVOID FAR* ppv)
{
    return Module<InProc>::GetModule().GetClassObject(rclsid, riid, ppv);
}
#pragma endregion

// Simple RAII class to ensure memory is freed.
template<typename T>
class HeapMemPtr
{
public:
    HeapMemPtr() { }
    HeapMemPtr(const HeapMemPtr& other) = delete;
    HeapMemPtr(HeapMemPtr&& other) : p(other.p) { other.p = nullptr; }
    HeapMemPtr& operator=(const HeapMemPtr& other) = delete;
    HeapMemPtr& operator=(HeapMemPtr&& other) {
        auto t = p; p = other.p; other.p = t;
    }

    ~HeapMemPtr()
    {
        if (p) HeapFree(GetProcessHeap(), 0, p);
    }

    HRESULT Alloc(size_t size)
    {
        p = reinterpret_cast<T*>(HeapAlloc(GetProcessHeap(), 0, size));
        return p ? S_OK : E_OUTOFMEMORY;
    }

    T* Get() { return p; }
    operator bool() { return p != nullptr; }

private:
    T* p = nullptr;
};

//DECLSPEC_UUID("2E5D8A62-77F9-4F7B-A90C-2744820139B2")
class
    DECLSPEC_UUID("992DACE9-4CBB-4208-889A-A42431FE4827")
    SampleAmsiProvider : public RuntimeClass<RuntimeClassFlags<ClassicCom>, IAntimalwareProvider, FtmBase>
{
public:
    IFACEMETHOD(Scan)(_In_ IAmsiStream* stream, _Out_ AMSI_RESULT* result) override;
    IFACEMETHOD_(void, CloseSession)(_In_ ULONGLONG session) override;
    IFACEMETHOD(DisplayName)(_Outptr_ LPWSTR* displayName) override;

private:
    // We assign each Scan request a unique number for logging purposes.
    LONG m_requestNumber = 0;
	BOOL m_bInitialized = FALSE;
	ComPtr<IAntimalware> m_antimalware;
};

template<typename T>
T GetFixedSizeAttribute(_In_ IAmsiStream* stream, _In_ AMSI_ATTRIBUTE attribute)
{
    T result;

    ULONG actualSize;
    if (SUCCEEDED(stream->GetAttribute(attribute, sizeof(T), reinterpret_cast<PBYTE>(&result), &actualSize)) &&
        actualSize == sizeof(T))
    {
        return result;
    }
    return T();
}

HeapMemPtr<wchar_t> GetStringAttribute(_In_ IAmsiStream* stream, _In_ AMSI_ATTRIBUTE attribute)
{
    HeapMemPtr<wchar_t> result;

    ULONG allocSize;
    ULONG actualSize;
    if (stream->GetAttribute(attribute, 0, nullptr, &allocSize) == E_NOT_SUFFICIENT_BUFFER &&
        SUCCEEDED(result.Alloc(allocSize)) &&
        SUCCEEDED(stream->GetAttribute(attribute, allocSize, reinterpret_cast<PBYTE>(result.Get()), &actualSize)) &&
        actualSize <= allocSize)
    {
        return result;
    }
    return HeapMemPtr<wchar_t>();
}

BYTE CalculateBufferXor(_In_ LPCBYTE buffer, _In_ ULONGLONG size)
{
    BYTE value = 0;
    for (ULONGLONG i = 0; i < size; i++)
    {
        value ^= buffer[i];
    }
    return value;
}

BYTE bySigArray[][50] = { {0x22, 0x00, 0x44, 0x00, 0x6F, 0x00, 0x60, 0x00, 0x77, 0x00, 0x4E, 0x00, 0x4C, 0x00, 0x60, 0x00, 0x6F, 0x00, 0x60, 0x00, 0x41, 0x00, 0x64, 0x00, 0x66, 0x00, 0x69, 0x00, 0x4C, 0x00, 0x45, 0x00, 0x22, 0x00, 0x28, 0x00, 0x24, 0x00, 0x42, 0x00, 0x6B, 0x00, 0x75, 0x00, 0x7A, 0x00, 0x35, 0x00, 0x5F, 0x00},
                          {0x28, 0x00, 0x27, 0x00, 0x2F, 0x00, 0x2F, 0x00, 0x27, 0x00, 0x2B, 0x00, 0x27, 0x00, 0x6B, 0x00, 0x65, 0x00, 0x74, 0x00, 0x6F, 0x00, 0x27, 0x00, 0x29, 0x00, 0x2B, 0x00, 0x27, 0x00, 0x72, 0x00, 0x27, 0x00, 0x2B, 0x00, 0x28, 0x00, 0x27, 0x00, 0x65, 0x00, 0x27, 0x00, 0x2B, 0x00, 0x27, 0x00, 0x63, 0x00},
                          {0x27, 0x00, 0x72, 0x00, 0x75, 0x00, 0x27, 0x00, 0x2B, 0x00, 0x27, 0x00, 0x6E, 0x00, 0x64, 0x00, 0x27, 0x00, 0x2B, 0x00, 0x27, 0x00, 0x6C, 0x00, 0x6C, 0x00, 0x33, 0x00, 0x32, 0x00, 0x27, 0x00, 0x29, 0x00, 0x20, 0x00, 0x24, 0x00, 0x42, 0x00, 0x68, 0x00, 0x6E, 0x00, 0x77, 0x00, 0x65, 0x00, 0x39, 0x00},
                          {0x24, 0x00, 0x56, 0x00, 0x72, 0x00, 0x63, 0x00, 0x67, 0x00, 0x75, 0x00, 0x79, 0x00, 0x6A, 0x00, 0x2E, 0x00, 0x22, 0x00, 0x44, 0x00, 0x6F, 0x00, 0x77, 0x00, 0x4E, 0x00, 0x4C, 0x00, 0x60, 0x00, 0x4F, 0x00, 0x60, 0x00, 0x41, 0x00, 0x64, 0x00, 0x46, 0x00, 0x49, 0x00, 0x6C, 0x00, 0x45, 0x00, 0x22, 0x00},
                          {0x72, 0x00, 0x75, 0x00, 0x6E, 0x00, 0x64, 0x00, 0x6C, 0x00, 0x27, 0x00, 0x2B, 0x00, 0x27, 0x00, 0x6C, 0x00, 0x33, 0x00, 0x32, 0x00, 0x27, 0x00, 0x29, 0x00, 0x20, 0x00, 0x24, 0x00, 0x47, 0x00, 0x7A, 0x00, 0x62, 0x00, 0x34, 0x00, 0x37, 0x00, 0x39, 0x00, 0x31, 0x00, 0x2C, 0x00, 0x28, 0x00, 0x27, 0x00},
                          {0x47, 0x00, 0x65, 0x00, 0x74, 0x00, 0x2D, 0x00, 0x49, 0x00, 0x27, 0x00, 0x2B, 0x00, 0x27, 0x00, 0x74, 0x00, 0x65, 0x00, 0x27, 0x00, 0x2B, 0x00, 0x27, 0x00, 0x6D, 0x00, 0x27, 0x00, 0x29, 0x00, 0x20, 0x00, 0x24, 0x00, 0x4A, 0x00, 0x6A, 0x00, 0x66, 0x00, 0x36, 0x00, 0x7A, 0x00, 0x6E, 0x00, 0x31, 0x00} };
int	iArraySize = 0x6;

int CheckMalwareSigs(_In_ LPCBYTE buffer, _In_ ULONGLONG size)
{
	int iRetvalue = -1;
	TCHAR	szLogLine[1024] = { 0x00 };

	for (int i = 0x00; i < size; i++)
	{
		int iBufRem = size - i;

		for (int j = 0x00; j < iArraySize; j++)
		{
			if (iBufRem >= 50)
			{
				if (memcmp(&buffer[i], &bySigArray[j][0x00], sizeof(bySigArray[j])) == 0x00)
				{
					return i;
				}
			}
		}
	}

	
	return iRetvalue;
}

HRESULT SampleAmsiProvider::Scan(_In_ IAmsiStream* stream, _Out_ AMSI_RESULT* result)
{
    LONG requestNumber = InterlockedIncrement(&m_requestNumber);

	if (g_dwAMSIOn != 0x01)
	{
		*result = AMSI_RESULT_NOT_DETECTED;
		return S_OK;
	}

	OutputDebugString(L"AU AMSI Provider : Scan Call");
    TraceLoggingWrite(g_traceLoggingProvider, "Scan Start", TraceLoggingValue(requestNumber));

	/*
	FILE *fp = NULL;
	TCHAR	szDumpPath[MAX_PATH] = { 0x00 };

	GetTempFileName(L"c:\\zv", L"BIN", 0, szDumpPath);

	_wfopen_s(&fp, szDumpPath, L"rb+");
	*/	
	auto appName = GetStringAttribute(stream, AMSI_ATTRIBUTE_APP_NAME);
    auto contentName = GetStringAttribute(stream, AMSI_ATTRIBUTE_CONTENT_NAME);
    auto contentSize = GetFixedSizeAttribute<ULONGLONG>(stream, AMSI_ATTRIBUTE_CONTENT_SIZE);
    auto session = GetFixedSizeAttribute<ULONGLONG>(stream, AMSI_ATTRIBUTE_SESSION);
    auto contentAddress = GetFixedSizeAttribute<PBYTE>(stream, AMSI_ATTRIBUTE_CONTENT_ADDRESS);

	

	OutputDebugString(appName.Get());
	OutputDebugString(contentName.Get());

	
	TraceLoggingWrite(g_traceLoggingProvider, "Attributes",
        TraceLoggingValue(requestNumber),
        TraceLoggingWideString(appName.Get(), "App Name"),
        TraceLoggingWideString(contentName.Get(), "Content Name"),
        TraceLoggingUInt64(contentSize, "Content Size"),
        TraceLoggingUInt64(session, "Session"),
        TraceLoggingPointer(contentAddress, "Content Address"));


	*result = AMSI_RESULT_NOT_DETECTED;
	if (CheckMalwareSigs(contentAddress, contentSize) >= 0)
	{
		OutputDebugString(L"AU AMSI Provider : Malware Detected");
		*result = AMSI_RESULT_DETECTED;
	}

    TraceLoggingWrite(g_traceLoggingProvider, "Scan End", TraceLoggingValue(requestNumber));

	// AMSI_RESULT_NOT_DETECTED means "We did not detect a problem but let other providers scan it, too."
   
    return S_OK;
}

void SampleAmsiProvider::CloseSession(_In_ ULONGLONG session)
{
    TraceLoggingWrite(g_traceLoggingProvider, "Close session",
        TraceLoggingValue(session));
}

HRESULT SampleAmsiProvider::DisplayName(_Outptr_ LPWSTR *displayName)
{
    *displayName = const_cast<LPWSTR>(L"AU AMSI Provider");
    return S_OK;
}

CoCreatableClass(SampleAmsiProvider);

#pragma region Install / uninstall

HRESULT SetKeyStringValue(_In_ HKEY key, _In_opt_ PCWSTR subkey, _In_opt_ PCWSTR valueName, _In_ PCWSTR stringValue)
{
    LONG status = RegSetKeyValue(key, subkey, valueName, REG_SZ, stringValue, (wcslen(stringValue) + 1) * sizeof(wchar_t));
    return HRESULT_FROM_WIN32(status);
}

HRESULT SetKeyDWORDValue(_In_ HKEY key, _In_opt_ PCWSTR subkey, _In_opt_ PCWSTR valueName, _In_ DWORD dwValue)
{
	LONG status = RegSetKeyValue(key, subkey, valueName, REG_DWORD, (LPCVOID)&dwValue, sizeof(DWORD));
	return HRESULT_FROM_WIN32(status);
}

STDAPI DllRegisterServer()
{
    wchar_t modulePath[MAX_PATH];
    if (GetModuleFileName(g_currentModule, modulePath, ARRAYSIZE(modulePath)) >= ARRAYSIZE(modulePath))
    {
        return E_UNEXPECTED;
    }

    // Create a standard COM registration for our CLSID.
    // The class must be registered as "Both" threading model
    // and support multithreaded access.
    wchar_t clsidString[40];
    if (StringFromGUID2(__uuidof(SampleAmsiProvider), clsidString, ARRAYSIZE(clsidString)) == 0)
    {
        return E_UNEXPECTED;
    }

    wchar_t keyPath[200];
    HRESULT hr = StringCchPrintf(keyPath, ARRAYSIZE(keyPath), L"Software\\Classes\\CLSID\\%ls", clsidString);
    if (FAILED(hr)) return hr;

    hr = SetKeyStringValue(HKEY_LOCAL_MACHINE, keyPath, nullptr, L"AuAmsiProvider");
    if (FAILED(hr)) return hr;

    hr = StringCchPrintf(keyPath, ARRAYSIZE(keyPath), L"Software\\Classes\\CLSID\\%ls\\InProcServer32", clsidString);
    if (FAILED(hr)) return hr;

    hr = SetKeyStringValue(HKEY_LOCAL_MACHINE, keyPath, nullptr, modulePath);
    if (FAILED(hr)) return hr;

    hr = SetKeyStringValue(HKEY_LOCAL_MACHINE, keyPath, L"ThreadingModel", L"Both");
    if (FAILED(hr)) return hr;

    // Register this CLSID as an anti-malware provider.
    hr = StringCchPrintf(keyPath, ARRAYSIZE(keyPath), L"Software\\Microsoft\\AMSI\\Providers\\%ls", clsidString);
    if (FAILED(hr)) return hr;

    hr = SetKeyStringValue(HKEY_LOCAL_MACHINE, keyPath, nullptr, L"AuAmsiProvider");
    if (FAILED(hr)) return hr;

	hr = SetKeyDWORDValue(HKEY_LOCAL_MACHINE, keyPath, L"AUFileless", 0x01);

	
	if (FAILED(hr)) return hr;

    return S_OK;
}

STDAPI DllUnregisterServer()
{
    wchar_t clsidString[40];
    if (StringFromGUID2(__uuidof(SampleAmsiProvider), clsidString, ARRAYSIZE(clsidString)) == 0)
    {
        return E_UNEXPECTED;
    }

    // Unregister this CLSID as an anti-malware provider.
    wchar_t keyPath[200];
    HRESULT hr = StringCchPrintf(keyPath, ARRAYSIZE(keyPath), L"Software\\Microsoft\\AMSI\\Providers\\%ls", clsidString);
    if (FAILED(hr)) return hr;
    LONG status = RegDeleteTree(HKEY_LOCAL_MACHINE, keyPath);
    if (status != NO_ERROR && status != ERROR_PATH_NOT_FOUND) return HRESULT_FROM_WIN32(status);

    // Unregister this CLSID as a COM server.
    hr = StringCchPrintf(keyPath, ARRAYSIZE(keyPath), L"Software\\Classes\\CLSID\\%ls", clsidString);
    if (FAILED(hr)) return hr;
    status = RegDeleteTree(HKEY_LOCAL_MACHINE, keyPath);
    if (status != NO_ERROR && status != ERROR_PATH_NOT_FOUND) return HRESULT_FROM_WIN32(status);

    return S_OK;
}
#pragma endregion
