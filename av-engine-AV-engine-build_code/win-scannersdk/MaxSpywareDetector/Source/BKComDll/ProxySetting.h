#pragma once
#include "pch.h"

typedef struct _ProxySetting
{
	wchar_t szProxyUserName[260];
	wchar_t szProxyPassword[260];
	wchar_t szProxyServer[260];
	wchar_t szProxyPort[260];
} ProxySetting;

class CProxySetting
{
public:
	CProxySetting();
	~CProxySetting();

public:
	void GetProxySetting(ProxySetting* pProxySettingArray);
	void SetProxySettings(ProxySetting* pProxySettingArray);
};