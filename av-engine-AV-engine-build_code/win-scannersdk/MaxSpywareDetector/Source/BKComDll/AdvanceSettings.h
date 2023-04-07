#pragma once
class CAdvanceSettings
{
public:
	void GetAdvanceSettingsData(int iAdvanceSettingLength, int* ptrAdvanceSetting);
	void SetAdvanceSettingsData(int iSetOption, int iSetVal);

	bool SetGamingMode(bool bStatus);
};

