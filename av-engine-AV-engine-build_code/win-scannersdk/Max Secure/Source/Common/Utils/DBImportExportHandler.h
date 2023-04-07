#pragma once
#include "S2S.h"

class CDBImportExportHandler
{
public:
	CDBImportExportHandler(void);
	~CDBImportExportHandler(void);
	void			ImportSettings();
	void			ExportSettings();
	void			DefaultSettings();
	void			SetValues(bool bCustomSettings, bool bScanByName, bool bUsbManager, bool bFirewall, bool bAppWhiteList);
	
private:
	bool			m_bCustomSettings;
	bool			m_bScanByName;
	bool			m_bUsbManager;
	bool			m_bFirewall;
	bool			m_bAppWhiteList;
	CS2S			m_objUserSettingsDB;
	CS2S			m_objUserSettingsUSBDB;
	CS2S			m_objUserSettingsFirewallDB;
	CS2S			m_objUserSettingsPassDB;
	CString			m_csDBsPath;
	CString			m_csAppPath;
	bool			m_bWriteButton;
	bool			m_bExecuteButton;
	bool			m_bReadButton;
	bool			m_bActivityLogButton;
	bool			m_bBlockAutorun;
	bool			m_bTotalBlock;
	bool			m_bSysFileProtection;
	void			ExportDB();
	void			ImportDB();
	int				ReadUsbRegistrySettings(ULONG ulTypeOfKey);
	void			WriteUSBSettings();
	void			USBManagerSettings();
	void			WriteUsbRegistrySettings(int iType, ULONG ulUsbSettings);
	void			SendMessageToTray(UINT uMessage, WPARAM wParam, LPARAM lParam);
	void			SendDataToDriver(ULONG ulIoCode,ULONG data);
	void			SystemFileProtection();
	bool			SetGamingMode(bool bStatus);
	void			GamingModeSetting(DWORD dwSettingVal);
	void			EnableCopyPasteSetting(DWORD dwSettingVal);
	void			EnableReplicatingSetting(DWORD dwSettingVal);
	//void			CheckRunNativeScanner(bool bSettingVal);
	//void			SendSockProductSettingsMsg(bool bStatus);
	//void			SendSockProductSettingsMsg(DWORD dw);
	void			SetProcessMonitor();
	void			ShowGadget(DWORD dw);
	void			DoEvents();
	bool			PostMessageToProtection(WPARAM wParam, LPARAM lParam);

};
