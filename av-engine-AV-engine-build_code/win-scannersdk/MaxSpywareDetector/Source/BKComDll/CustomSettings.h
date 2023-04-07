#pragma once
#include "pch.h"
#include "Registry.h"
#include "SDSystemInfo.h"

class CCustomSettings
{
public:
	CCustomSettings();
	~CCustomSettings();

public:
	void GetCustomSetting(int CustomSettingLength, int* CustomSetting);

	void SetCustomSetting(int iSetting, int iValue);

};