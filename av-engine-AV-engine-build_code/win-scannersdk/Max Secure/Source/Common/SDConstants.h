/*======================================================================================
FILE             : SDConstants.h
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

CREATION DATE    : 2/24/06
NOTES		     : Declaring SD contants
VERSION HISTORY  :
======================================================================================*/
#pragma once
#ifndef NON_MFC
#include "Constants.h"
#endif
#include <winioctl.h>
#define ON					1
#define OFF					0

#define WIN98_SIZE			32000
#define WIN2K_SIZE			90000

const DWORD COOKIE_ALLOW		= 1;
const DWORD COOKIE_BLOCK		= 5;

const DWORD BLOCK_ACTIVEX		=	1024;
const DWORD RESTRICT_SITE_VAL	=	4;
const int HTTPBUFLEN			=	1024;     
const int TIMEOUT				=	1000 * 60 * 5;

const int COLUMN_0				= 0;
const int COLUMN_1				= 2;
const int COLUMN_2				= 3;
const int COLUMN_3				= 4;
const int COLUMN_4				= 1;
const int COLUMN_5				= 5;
const int COLUMN_SPY_INFO_6		= 6;
const int COLUMN_QUARANTINE_7	= 7;
const int COLUMN_SCAN_TYPE		= 8;  


const int ENGLISH		= 0;
const int FRENCH		= 10000;
const int JAPANESE		= 20000;

#define CSIDL_APPDATA_CONST				26
#define CSIDL_INTERNET_CACHE_CONST		32
#define CSIDL_COMMON_STARTUP_CONST		24
#define CSIDL_STARTUP_CONST				7


#define LIVEUPADTE_STATUS_STARTED		1			
#define LIVEUPADTE_STATUS_SUCCESFULL	2
#define LIVEUPADTE_STATUS_FAILED		3
#define LIVEUPADTE_STATUS_FINISHED		4

#define REGISTRATION_SUCCESSFUL			1
#define EVALUATION_SUCCESSFUL			2

#define MERGING_THREAD_COUNT			13

#define MAXSHIELD_ACTIVEX_CHANGE		1
#define MAXSHIELD_COOKIE_CHANGE			2
#define MAXSHIELD_HOST_CHANGE			3
#define MAXSHIELD_RESTRICTED_CHANGE		4

#define  REMOVE_SPYDB_FILE_NAME_NEW		_T("SDRemoveDB.db")
#define  REMOVE_VIRUSDB_FILE_NAME_NEW		_T("SDVirRemoveDB.db")
#define  EXCLUDE_SPYDB_FILE_NAME			_T("ExcludeDB.db")
#define  EXCLUDE_DB_FILE_NAME			_T("Exclude.db")
#define FWPNPDATA_FOLDER				_T("PnPFolder")
#define FWDATA_PNPUSERDB				_T("PnpUserDB.DB")
#define FWDATA_PNPFIREWALLDB			_T("PnpFirewall.DB")
#define FWDATA_USERPASSDB				_T("ManageUserPass.DB")

enum ENUM_THREAT_IMAGES
{
	ENUM_TI_CRITICAL,
	ENUM_TI_HIGH,
	ENUM_TI_MEDIUM,
	ENUM_TI_LOW
};

enum ENUM_STATUS
{
	ENUM_STATUS_SCANNED,
	ENUM_STATUS_QSUCCESS,
	ENUM_STATUS_QFAILED,
	ENUM_STATUS_QCHILD,
	ENUM_STATUS_DSUCCESS,
	ENUM_STATUS_DFAILED,
	ENUM_STATUS_RQSUCCESS,
	ENUM_STATUS_RQFAILED,
	ENUM_STATUS_QSCAN,
	ENUM_STATUS_FSCAN,
	ENUM_STATUS_SSCAN,
	ENUM_STATUS_DEFAULT,
};
enum ENUM_MAXSHIELD_POS
{
	ENUM_MS_HOMEPAGE,
	ENUM_MS_COOKIE,
	ENUM_MS_PROCESS,
	ENUM_MS_FILEASSOC_REG,
	ENUM_MS_WIN_RESTRICTION_MON,
	ENUM_MS_IERESTRCTION_MON
};

enum ENUM_MAXTOOLS_POS
{
	ENUM_MS_APP_WHITELIST,
	ENUM_MS_APP_CRYPTO,
	ENUM_MS_PASSWORD_MANAGER,
	ENUM_MS_USB_MANAGER,
	ENUM_MS_BROWSER_RESET,
	ENUM_MS_BACKUP_UTIL,
	ENUM_MS_ADWARE_CLEANER,
	ENUM_MS_LU_FIX,
	ENUM_MS_IEXPLORER_FIX,
	ENUM_MS_REG_BACKUP,
	ENUM_MS_REG_FIX,
	ENUM_MS_ROOTKIT,
	ENUM_MS_SERVICE_LIST,
	ENUM_MS_SYS_SCANNER,
	ENUM_MS_UNHIDE_FOLDER,
	ENUM_MS_SUBMIT_SAMPLE,
	ENUM_MS_PC_DIAGNOSTICS,
	ENUM_MS_VUL_SCAN,
	ENUM_MS_SECURE_FOLDER,
	ENUM_MS_MAXPASSWORD_MGR,
	ENUM_MS_SAFE_BROWSER,
	ENUM_MS_VIRTUAL_KEYBOARD,
	ENUM_MS_NETWORK_PREVENTION
};


enum operation
{
	STARTPROTECTION = 1,
	STOPPROTECTION,
	RESTARTPROTECTION,
	PAUSEPROTECTION,
	RELOADEXCLUDEDB,
	SETPROCESS,
	SETHOMEPAGE,
	SETCOOKIE,
	SETNOTIFICATION,
	SETHOSTMONITOR, 
	SETNETWORKMONITOR,
	CHANGELANGUAGE,
	SETFILESYSTEMMONITOR,
	TRUSTPID,
    SCANNINGANIMATION,
	SETWINRESTRICTIONMONITOR,
	SETIERESTRICTIONMONITOR,
    SETFILEASSOCIATION,
	SETFILESYSTEMPROTECTION,
	SETINFECTEDSYSTEMFILE,
	SETGAMINGMODE,
	SETFIREWALL,
	SETEMAILSCAN,
	SETFIREWALLOPTIONS,
	
	PROTECTION_LAST_MESSAGE
};

enum DownloadType
{
	ENUM_DT_MERGER=1,
	ENUM_DT_MERGER_X64,
	ENUM_DT_DATABASE,
	ENUM_DT_DBPATCH,
	ENUM_DT_INFOCHM,
	ENUM_DT_INFOCHM_X64,
	ENUM_DT_REMOVESPYWARE,
	ENUM_DT_REMOVESPYWARE_X64,
	ENUM_DT_KEYLOGGER,
	ENUM_DT_KEYLOGGER_X64,
	ENUM_DT_ROOTKIT,
	ENUM_DT_ROOTKIT_X64,
    ENUM_DT_MISC,
	ENUM_DT_ADVSCAN,
	ENUM_DT_ADVSCAN_X64,
	ENUM_DT_VIRUS,
	ENUM_DT_VIRUS_X64,
	ENUM_DT_FIREWALL,
	ENUM_DT_FIREWALL_X64,
	ENUM_DT_UPDATE_VERSION,
	ENUM_DT_UPDATE_VERSION_X64,
	ENUM_DT_DATABASE_MONTHLY,
	ENUM_DT_DATABASE_WEEKLY,
	ENUM_DT_MINI_DATABASE,
	ENUM_DT_MINI_DATABASE_X64,
	ENUM_DT_PRODUCT,
	ENUM_DT_PRODUCT_X64
	
};

enum SCAN_PROCESS_STATUS
{
	SCAN_PS_START_PROCESS = 1,
	SCAN_PS_STOP_PROCESS,
	SCAN_PS_START_COOKIE,
	SCAN_PS_STOP_COOKIES,
	SCAN_PS_START_FILE,
	SCAN_PS_STOP_FILE,
	SCAN_PS_START_FOLDER,
	SCAN_PS_STOP_FOLDER,
	SCAN_PS_START_REGKEY,
	SCAN_PS_STOP_REGKEY,
	SCAN_PS_START_REGVAL,
	SCAN_PS_STOP_REGVAL,
	SCAN_PS_START_FULL_SCAN,
	SCAN_PS_STOP_FULL_SCAN,
	SCAN_PS_START_REGDATA,
	SCAN_PS_STOP_REGDATA,
	SCAN_PS_START_SPECIAL_SCAN,
	SCAN_PS_STOP_SPECIAL_SCAN,
	SCAN_PS_START_BHO,
	SCAN_PS_STOP_BHO,
	SCAN_PS_START_TOOLBAR,
	SCAN_PS_STOP_TOOLBAR,
	SCAN_PS_START_MENUEXTENSION,
	SCAN_PS_STOP_MENUEXTENSION,
	SCAN_PS_START_ACTIVEX,
	SCAN_PS_STOP_ACTIVEX,
	SCAN_PS_START_SSODL,
	SCAN_PS_STOP_SSODL,
	SCAN_PS_START_SHAREDTASKSCHEDULER,
	SCAN_PS_STOP_SHAREDTASKSCHEDULER,
	SCAN_PS_START_APPINIT,
	SCAN_PS_STOP_APPINIT,
	SCAN_PS_START_REGFIX,
	SCAN_PS_STOP_REGFIX,
	SCAN_PS_START_SERVICES,
	SCAN_PS_STOP_SERVICES,
	SCAN_PS_START_NOTIFY,
	SCAN_PS_STOP_NOTIFY,
	SCAN_PS_START_KEYLOGGER,
	SCAN_PS_STOP_KEYLOGGER,
	SCAN_PS_START_SHELLEXECHOOK,
	SCAN_PS_STOP_SHELLEXECHOOK,
	SCAN_PS_START_STARTUP,
	SCAN_PS_STOP_STARTUP,
	SCAN_PS_START_NETWORKCONNECTIONS,
	SCAN_PS_STOP_NETWORKCONNECTIONS,
	SCAN_PS_START_VIRUS,
	SCAN_PS_FINISH_VIRUS
};



enum OptionAction
{
	ENUM_OA_DELCOOKIE=1,
	ENUM_OA_FILLCOOKIELIST,
	ENUM_OA_BLOCKBHO,
	ENUM_OA_UNBLOCKBHO,
	ENUM_OA_FILLBHOTREE,
	ENUM_OA_SNAPIT,
	ENUM_OA_COMPARE,
	ENUM_OA_RESTORE,
	ENUM_OA_FILLLSP,
	ENUM_OA_FIXLSP,
	ENUM_OA_FILLPROCESS,
	ENUM_OA_TERMNATEPROC,
	ENUM_OA_FILLSTARTUP,
	ENUM_OA_INSERTSTARTUP,
	ENUM_OA_DELSTARTUP,
	ENUM_OA_CHANGESTARTUP,
	ENUM_OA_FILLACTIVEX,
	ENUM_OA_BLOCKACTIVEX,
	ENUM_OA_UNBLOCKACTIVEX,
	ENUM_OA_FILLSITES,
	ENUM_OA_ADDSITES,
	ENUM_OA_REMOVESITES,
	ENUM_OA_INSERTSITE,
	ENUM_OA_FILLTRACKINGCOOKIE,
	ENUM_OA_ADDTRACKINGCOOKIE,
	ENUM_OA_REMOVETRACKINGCOOKIE,
	ENUM_OA_INSERTTRACKINGCOOKIE,
	ENUM_OA_FILLHOSTLIST,
	ENUM_OA_ADDHOSTS,
	ENUM_OA_REMOVEHOSTS,
	ENUM_OA_INSERTHOST,
	ENUM_OA_OPENHOST,
	ENUM_OA_CLOSEHOST,
	ENUM_OA_FILLRECOVERLIST,
	ENUM_OA_FILLEXCLUDELIST,
	ENUM_OA_EXCLUDE,
	ENUM_OA_RECOVER,
	ENUM_OA_FILLIPLIST,
	ENUM_OA_INSERTIP,
	ENUM_OA_DELETEIP,
	ENUM_OA_FILLTCPVIEW,
	ENUM_OA_FILLBANNERLIST,
	ENUM_OA_INSERTBANNERIP,
	ENUM_OA_DELETEBANNERIP,
	ENUM_OA_TOTALBLOK,
	ENUM_OA_WRITE_ACCESS,
	ENUM_OA_BLOCKAUTORUN,
	ENUM_OA_PROTECTSYSREG
 };

enum StartupType
{
	HK_CU_RUN=1,
	HK_CU_RUNSVC,
	HK_LM_RUN,
	HK_LM_RUNSVC,
	USERSTARTUP,
	GLOBALSTARTUP
};

enum ENUM_WORMTYPE
{
	ENUM_WT_FILEWORM,						 
	ENUM_WT_FOLDER,							 
	ENUM_WT_PROCESSES,						 
	ENUM_WT_COOKIE,							 
	ENUM_WT_REGVAL,							  
	ENUM_WT_REGDATA,						  
	ENUM_WT_REGKEY,							  
	ENUM_WT_MOZILLACOOKIE,					  
	ENUM_WT_APPINIT,						 
	ENUM_WT_SERVICES,						 
	ENUM_WT_NOTIFY,							 
	ENUM_WT_REGDATAFIX,						   	
	ENUM_WT_REGVALFIX,						   
	ENUM_WT_ROOTKIT,						 
	ENUM_WT_NOTHING,
	ENUM_WT_SPECIALSPYWARE,					  
	ENUM_WT_NETWORK_CONNECTION,				  
	ENUM_WT_MEMORY,							  
	ENUM_WT_VIRUS							  
};


enum ENUM_LIVEUPDATE_ACTIOB
{
	ENUM_LA_ADD = 1,
	ENUM_LA_MODIFY,
	ENUM_LA_DELETE
};
enum ENUM_SCAN_CONDITION
{
	ENUM_SC_DO_NOT_RUN_SCAN,				       
	ENUM_SC_AUTOSCAN,						    
	ENUM_SC_SCHEDULED,						    
	ENUM_SC_USERCLICKED,					     
	ENUM_SC_FORCEFULLSCAN,					      
    ENUM_SC_CMDCONTINUESCAN,
	ENUM_SC_CUSTOMSCAN,						 
	ENUM_SC_SETTINGSDLG,					  
	ENUM_SC_REGISTERNOW						    
};

enum ENUM_REGFIX_TYPE
{
	ENUM_RT_SPYPRESENT = 1,
	ENUM_RT_ALWAYS,
	ENUM_RT_DEFAULT
};

enum ENUM_REGFIX_OS
{
	ENUM_RO_All,
	ENUM_RO_2K,
	ENUM_RO_XP,
	ENUM_RO_VISTA
};

enum TYPE_OF_SCAN
{
	ENUM_SCAN_QUICK = 0,
	ENUM_SCAN_CUSTOM,
	ENUM_SCAN_FULL
};

const int IOCTL_SD_TRAY_EXE_PROCESS_ID	= CTL_CODE (FILE_DEVICE_UNKNOWN,0x8001,METHOD_BUFFERED, FILE_ANY_ACCESS );
const int IOCTL_SETUP_EXE_PROCESS_ID	= CTL_CODE (FILE_DEVICE_UNKNOWN,0x8002,METHOD_BUFFERED, FILE_ANY_ACCESS );
const int IOCTL_PAUSE_SELFPROTECTION	= CTL_CODE (FILE_DEVICE_UNKNOWN,0x8003,METHOD_BUFFERED, FILE_ANY_ACCESS );
const int IOCTL_CONTINUE_SELFPROTECTION	= CTL_CODE (FILE_DEVICE_UNKNOWN,0x8004,METHOD_BUFFERED, FILE_ANY_ACCESS );;

#define ID_PROCESS_TIMER    7000

#define EXPLORE_EXE				_T("Explorer.exe")

#define FIREWAL_KEY				_T("FireWallEnable")
#define GAMINGMODE_KEY			_T("GamingMode")
#define REGISTRYSCAN_KEY		_T("RegistryScan")
#define TRACKING_COOKIE			_T("TrackingCookie")
#define HOME_PAGE_KEY			_T("HomePage")
#define PROCESS_KEY				_T("ProcessMonitor")
#define HOST_MONITOR_KEY		_T("HostMonitor")
#define START_PAGE_VAL			_T("Start Page")
#define ACTIVEX_VALUE		    _T("Compatibility Flags")
#define SCANPROGRESS_KEY		_T("ScanProgress")	
#define NETWORK_MONITOR_KEY		_T("NetworkMonitor")
#define FILEASSOC_MONITOR_KEY	_T("FileAssocMonitor")
#define WIN_RESTRICTION_MONITOR_KEY	_T("WinRestrictionMonitor")
#define IERESTRUCTION_MONITOR_KEY	_T("IERestrictionMonitor")
#define SHOW_GADGET_KEY			L"ShowGadget"
#define BLOCKPOPUP				L"BlockPopup"         
#define TOOLBARCLEANER			L"Toolbar Cleaner"
#define PASSWORD_USB            _T("PasswordUsb")     
#define PASSWORD_WHITELIST      _T("PasswordWhiteList")     
#define PASSWORD_PARENTAL       _T("PasswordParental")     
#define PASSWORD_UNINSTALL		_T("PasswordUnInstall")     

#define APP_EXEPATH_KEY			_T("AppPath")
#define QUARANTINEFOLDER		_T("Quarantine")
#define  QUARENTINE_FOLDER_NAME		 _T("\\Quarantine")
#define LOGFOLDER				_T("Log")
#define SETTINGFOLDER			_T("Setting")
#define DATABASEFOLDER			_T("Data")


#define WINNT_LAYAR_KEY     _T("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Layers")

#define  SHELL					_T("Shell")
#define  USERINIT				_T("Userinit")
#define  REGISTRYKEY			_T("Registry Key")
#define  REGISTRYVALUE			_T("Registry Value")
#define  REGISTRYDATA			_T("Registry Data")
#define  COOKIE				_T("Cookie")
#define  MOZILLACOOKIE			_T("MozillaCookie")
#define  FILEWORM				_T("File")
#define  FOLDER				_T("Folder")
#define  PROCESS				_T("Process")
#define  REGISTRY				_T("Registry")
#define  APPINIT				_T("AppInit Dlls")
#define  APP_INIT_DLLS			_T("appinit_dlls")
#define  REGDATAFIX			_T("Fix: Registry Data")
#define  REGVALFIX				_T("Fix: Registry Value")
#define  SERVICES_WORM			_T("Services")
#define  NOTIFY				_T("Notify")
#define  ROOTKIT				_T("RootKit")
#define  HOSTS					_T("Hosts")
#define  NETWORK_CONNECTION 	_T("Network Connection")
#define  AUACTIVEPROTECTION 	_T("AuActiveMonitor")
#define  MEMORYWORM			_T("Memory")
#define SENDLOG				_T("SendLog") 
#define SENDLOGFLAG          _T("Flag")
#define ACTIVEX					_T("ActiveX")
#define MENU					_T("Menu")
#define STARTUP					_T("StartUp")
#define TOOLBAR					_T("Toolbar")
#define VIRUS					_T("Virus")
#define SPYWARE					_T("Spyware")

#define SUMMARY						_T("summary")
#define SPYCOUNTS					_T("SpyCounts")
#define	WORMCOUNTS					_T("WormCounts")
#define WORMCNT						_T("WormCnt")
#define LASTLIVEUPDATE				_T("LastLiveUpdate")
#define	WORMS						_T("Worms")
#define	SWITCHES					_T("switches")
#define TRACKINGCOOKIESWITCH		_T("TrackingCookie")
#define	PROCESSMONITORSWITCH		_T("ProcessMonitor")
#define	HOMEPAGESWITCH				_T("HomePage")
#define	LOADINGSTATUS				_T("LoadingStatus")
#define	SPYLOADED					_T("SpyLoaded")
#define	WORMSLOADED					_T("WormsLoaded")
#define UNKNOWN						_T("UNKNOWN")
#define PROTECT						_T("Protect")

	#define  TRACK_COOKIE_PATH_X64			 _T("software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\P3P\\History")
	#define  START_PAGE_KEY_X64			 _T("software\\Wow6432Node\\Microsoft\\Internet Explorer\\Main")
	#define  CLSID_KEY_X64					 _T("software\\Wow6432Node\\classes\\clsid\\")
	#define  CLASS_ROOT_KEY_X64			 _T("software\\wow6432node\\classes\\")
	#define  INTERFACE_PATH_X64			 _T("software\\Wow6432Node\\classes\\interface\\")
	#define  TYPELIB_PATH_X64				 _T("software\\Wow6432Node\\classes\\typelib\\")
	#define  SHELLEX_KEY_X64				 _T("software\\Wow6432Node\\classes\\folder\\shellex\\")
	#define  APPID_PATH_X64				 _T("software\\Wow6432Node\\classes\\appid\\")
	#define  EXT_STATS_PATH_X64			 _T("software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Ext\\Stats\\")
	#define  CMDMAPPING_PATH_X64			 _T("software\\Wow6432Node\\Microsoft\\Internet Explorer\\Extensions\\CmdMapping\\")
	#define  CURRENTVERSION_PATH_X64		 _T("software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\")
	#define  CV_SHELL_EXT_PATH_X64			 _T("software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Shell Extensions\\Approved") 
	#define  REG_NOTIFY_ENTRY_X64			 _T("software\\Wow6432Node\\microsoft\\windows nt\\currentversion\\winlogon\\notify\\")
	#define  TOOLBAR_LOCAL_PATH_X64		 _T("hkey_local_machine\\software\\Wow6432Node\\microsoft\\internet explorer\\toolbar\\")	
	#define  SSODL_PATH_X64				 _T("software\\Wow6432Node\\microsoft\\windows\\currentversion\\shellserviceobjectdelayload")
	#define  STS_PATH_X64					 _T("software\\Wow6432Node\\microsoft\\windows\\currentversion\\explorer\\sharedtaskscheduler")
	#define  WINLOGON_REG_KEY_X64			 _T("software\\Wow6432Node\\microsoft\\windows nt\\currentversion\\winlogon")
	#define  ACTIVEX_KEY_X64				 _T("Software\\Wow6432Node\\Microsoft\\Internet Explorer\\ActiveX Compatibility\\")
	#define  WNT_WINDOWS_PATH_X64			 _T("software\\Wow6432Node\\microsoft\\windows NT\\currentversion\\Windows")
	#define  IE_RESTRICTION_KEY_X64		 _T("Software\\Wow6432Node\\Policies\\Microsoft\\Internet Explorer\\Restrictions")
	#define  NOTIFY_MAIN_KEY_X64			 _T("software\\Wow6432Node\\microsoft\\windows nt\\currentversion\\winlogon\\notify")
	#define  RESTRICTED_SITE_KEY_X64		 _T("Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\ZoneMap\\Domains\\")
	#define  SATARTUPKEY_PATH_X64		 _T("Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\")
	#define  SHELL_EXEC_HOOKS_X64		 _T("SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellExecuteHooks") 


#define  RUN_KEY_PATH			_T("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run")
#define  TRACK_COOKIE_PATH		_T("Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\P3P\\History")
#define  START_PAGE_KEY			_T("software\\microsoft\\internet explorer\\main")
#define  CLSID_KEY				_T("software\\classes\\clsid\\")
#define  CLASS_ROOT_KEY			_T("software\\classes\\")
#define  INTERFACE_PATH			_T("software\\classes\\interface\\")
#define  TYPELIB_PATH			_T("software\\classes\\typelib\\")
#define  STATS_PATH				_T("\\software\\microsoft\\windows\\currentversion\\ext\\stats\\")
#define  SHELLEX_KEY			_T("software\\classes\\folder\\shellex\\")
#define  APPID_PATH				_T("software\\classes\\appid\\")
#define  EXT_STATS_PATH			_T("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Ext\\Stats\\")
#define  CMDMAPPING_PATH		_T("Software\\Microsoft\\Internet Explorer\\Extensions\\CmdMapping\\")
#define  CURRENTVERSION_PATH	_T("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\")
#define  CV_SHELL_EXT_PATH		_T("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Shell Extensions\\Approved") 
#define  TOOLBAR_LOCAL_PATH		_T("hkey_local_machine\\software\\microsoft\\internet explorer\\toolbar\\")
#define  TOOLBAR_WEB_PATH		_T("hkey_current_user\\software\\microsoft\\internet explorer\\toolbar\\webbrowser\\")
#define  TOOLBAR_SHELL_PATH		_T("hkey_current_user\\software\\microsoft\\internet explorer\\toolbar\\shellbrowser\\")
#define  STS_PATH				_T("software\\microsoft\\windows\\currentversion\\explorer\\sharedtaskscheduler")
#define  POL_EXPL_RUN_PATH		_T("software\\microsoft\\windows\\currentversion\\policies\\explorer\\run") 
#define  WNT_WINDOWS_PATH		_T("software\\microsoft\\windows NT\\currentversion\\Windows")
#define  IE_REGISTRY_KEY		_T("software\\Microsoft\\Windows\\CurrentVersion\\App Paths\\IEXPLORE.EXE")
#define  SOFTWARE_PATH			_T("hkey_local_machine\\software")
#define  SERVICES_MAIN_KEY		_T("SYSTEM\\CurrentControlSet\\Services\\")

#define  SERVICES_ENUM_KEY		_T("SYSTEM\\CurrentControlSet\\Enum\\") 
#define  SERVICES_LEGACY_KEY	_T("SYSTEM\\CurrentControlSet\\Enum\\Root\\LEGACY_")
#define  DRIVER_MINIMAL_KEY		_T("SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Minimal\\")
#define  DRIVER_NETWORK_KEY		_T("SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\NetWork\\")
#define  IE_RESTRICTION_KEY		_T("Software\\Policies\\Microsoft\\Internet Explorer\\Restrictions")
#define  SERVICES_MONITOR_KEY	_T("system\\currentcontrolset\\services")
#define  SATARTUPKEY_PATH		_T("Software\\Microsoft\\Windows\\CurrentVersion\\")
#define  SHELL_EXEC_HOOKS		_T("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellExecuteHooks") 
#define  SYSTEM_WINIK			_T("SYSTEM\\CurrentControlSet\\Services\\WinIK")
#define  ACTIVEX_KEY			_T("Software\\Microsoft\\Internet Explorer\\ActiveX Compatibility\\")
#define  TESTKEY				_T("SOFTWARE\\SDTest")
#define  APP_PATH				_T("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths") 
#define  UNINSTALL_PATH			_T("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall")
#define  POLICIES_RUN_PATH		_T("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\policies\\explorer\\run")
#define  IMG_FILE_EXE_OPTS_PATH	_T("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options")

#define  WIN_RESTRICTION_SYSTEM_KEY	 _T("Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System")
#define  WIN_RESTRICTION_EXPLORER_KEY   _T("Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer")
#define  RESTRICTED_SITE_KEY			 _T("Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\ZoneMap\\Domains\\")
#define  RESTRICTED_RANGES_KEY			 _T("Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\ZoneMap\\Ranges\\")

#define  RUN_KEY_PATH_X64					_T("SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run")
#define  BHO_REGISTRY_PATH_X64				_T("software\\Wow6432Node\\microsoft\\windows\\currentversion\\explorer\\browser helper objects")
#define  TOOLBAR_REGISTRY_PATH_X64			_T("software\\Wow6432Node\\Microsoft\\Internet Explorer\\Toolbar")
#define  BHO_REGISTRY_INFO_X64				_T("software\\Wow6432Node\\Classes\\CLSID")
#define  MENUEXTENSION_REGISTRY_INFO_X64	_T("software\\Wow6432Node\\microsoft\\internet explorer\\extensions")
#define  ACTIVEX_REGISTRY_PATH_X64			_T("software\\Wow6432Node\\microsoft\\code store database\\distribution units")
#define  ACTIVEX_REGISTRY_INFO_X64			_T("software\\Wow6432Node\\Classes\\CLSID\\")
#define  IE_URLSEARCH_HOOKS_X64				_T("software\\Wow6432Node\\Microsoft\\Internet Explorer\\URLSearchHooks")
#define  PRODUCTS_PATH_X64					_T("SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Installer\\UserData\\S-1-5-18\\Products") 
#define  UNINSTALL_PATH_X64					_T("SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall")
#define  POL_EXPL_RUN_PATH_X64				_T("software\\wow6432node\\microsoft\\windows\\currentversion\\policies\\explorer\\run")
#define  IMG_FILE_EXE_OPTS_PATH_X64			_T("software\\wow6432node\\microsoft\\windows nt\\currentversion\\image file execution options")
#define  SHARED_DLLS_KEY_PATH_X64			_T("software\\wow6432node\\microsoft\\windows\\currentversion\\shareddlls")
#define  MEXT_CMD_KEY_PATH_X64				_T("software\\wow6432node\\microsoft\\internet explorer\\extensions\\cmdmapping")
#define  ACTIVESETUP_INSTALLCOMPONENTS_X64 	_T("Software\\Wow6432Node\\Microsoft\\Active Setup\\Installed")

#define  BHO_REGISTRY_PATH				_T("software\\microsoft\\windows\\currentversion\\explorer\\browser helper objects")
#define  TOOLBAR_REGISTRY_PATH			_T("SOFTWARE\\Microsoft\\Internet Explorer\\Toolbar")
#define  BHO_REGISTRY_INFO				_T("SOFTWARE\\Classes\\CLSID")
#define  MENUEXTENSION_REGISTRY_INFO	_T("software\\microsoft\\internet explorer\\extensions")
#define  ACTIVEX_REGISTRY_PATH			_T("software\\microsoft\\code store database\\distribution units")
#define  ACTIVEX_REGISTRY_INFO			_T("SOFTWARE\\Classes\\CLSID")
#define  IE_URLSEARCH_HOOKS				_T("SOFTWARE\\Microsoft\\Internet Explorer\\URLSearchHooks")
#define  SHARED_DLLS_KEY_PATH			_T("software\\microsoft\\windows\\currentversion\\shareddlls")
#define  MEXT_CMD_KEY_PATH				_T("software\\microsoft\\internet explorer\\extensions\\cmdmapping")

#define  TOOLBAR_REGISTRY_PATH_IE		 _T("software\\microsoft\\internet explorer\\toolbar")
#define  TOOLBAR_REGISTRY_PATH_IE_WB	 _T("software\\microsoft\\internet explorer\\toolbar\\webbrowser")
#define  TOOLBAR_REGISTRY_PATH_IE_SB	 _T("software\\microsoft\\internet explorer\\toolbar\\shellbrowser")
#define  TOOLBAR_REGISTRY_PATH_IE_EX	 _T("software\\microsoft\\internet explorer\\toolbar\\explorer")


#define  TOOLBAR_REGISTRY_PATH_IE_X64		 _T("software\\Wow6432Node\\microsoft\\internet explorer\\toolbar")
#define  TOOLBAR_REGISTRY_PATH_IE_WB_X64	 _T("software\\Wow6432Node\\microsoft\\internet explorer\\toolbar\\webbrowser")
#define  TOOLBAR_REGISTRY_PATH_IE_SB_X64	 _T("software\\Wow6432Node\\microsoft\\internet explorer\\toolbar\\shellbrowser")
#define  TOOLBAR_REGISTRY_PATH_IE_EX_X64	 _T("software\\Wow6432Node\\microsoft\\internet explorer\\toolbar\\explorer")


#define  RUNONCE_REG_PATH				 _T("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce") 
#define  DESKTOP_COMPONENTS_PATH		 _T("Software\\Microsoft\\Internet Explorer\\Desktop\\Components")
#define  PRODUCTS_PATH					 _T("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Installer\\UserData\\S-1-5-18\\Products") 
#define  MOUNTPOINTS_PATH_XP			 _T("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2")
#define  MOUNTPOINTS_PATH_2K			 _T("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints")
#define  DESKTOP_GENERAL_PATH			 _T("Software\\Microsoft\\Internet Explorer\\Desktop\\General")
#define	 ACTIVESETUP_INSTALLCOMPONENTS   _T("SOFTWARE\\Microsoft\\Active Setup\\Installed Components")
#define  WIN_RESTRICTION_POLICIES_KEY	 _T("Software\\Policies\\Microsoft\\Windows\\System")
#define  DISABLE_CDROM_POLICIES_KEY		 _T("SYSTEM\\CurrentControlSet\\Services\\CDRom")
#define  DISABLE_ALLDRIVES_INF_KEY		 _T("Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer")

#define  EXE_ASSOC_COMMAND					_T("software\\classes\\.exe\\shell\\open\\command")
#define  EXEFILE_ASSOC_COMMAND				_T("software\\classes\\exefile\\shell\\open\\command")
#define  EXE_ASSOC_COMMAND_X64				_T("software\\Wow6432Node\\classes\\.exe\\shell\\open\\command")
#define  EXEFILE_ASSOC_COMMAND_X64			_T("software\\Wow6432Node\\classes\\exefile\\shell\\open\\command")


#define  HKCR	 _T("HKEY_CLASSES_ROOT")
#define  HKCU	 _T("HKEY_CURRENT_USER")
#define  HKLM	 _T("HKEY_LOCAL_MACHINE")
#define  HKU	 _T("HKEY_USERS")
#define  HKCC	 _T("HKEY_CURRENT_CONFIG")

#define REG_SW_MS_PATH  _T("software\\")
#define REG_SW_MS_PATH_X86  _T("software\\wow6432node\\")

enum ENUM_REG_HIVE_TYPE
{
	ENUM_RHT_LM = 1,
	ENUM_RHT_CU,
	ENUM_RHT_BOTH,
	ENUM_RHT_CR
};

#define  SOFTWARE_SUB_KEY  _T("software")
#define  SYSTEM_SUB_KEY  _T("system")
#define  DOT_DEFAULT_SUB_KEY  _T(".default")


#define	SHOWPROCPOPUP				_T("ShowKillPopup")
#define	LIVE_MONITOR_LOG_FOLDER		_T("\\LiveMonitorLogFolder\\")

#define	TRACKING_COOKIE_INI			_T("setting\\SDActualTrackingCookies.ini")
#define RESTRICTEDSITESINI			_T("setting\\SDRestrictedSites.ini")
#define RESTRICTEDSITES_INSERT_INI  _T("setting\\RSitesInsert.ini");
#define TRACKINGCOOKIESINI			_T("setting\\SDActualTrackingCookies.ini")
#define	WORMSCOUNTINI				_T("setting\\wormcounts.ini")   
#define WORMS_COUNT_INI				_T("Worms.ini")
#define BLOCKACTIVEXINI				_T("setting\\BlockActivexSD.ini")
#define SVCQUARANTINEINI			_T("setting\\SDWormsToDelete.ini")
#define SDHOOKINI					_T("SDHook.ini")
#define	SYSVERSIONINI				_T("sysversionSD.ini")
#define BLOCK_COOKIESINI_FILE_NAME	_T("setting\\BlockCookiesSD.ini")


#define  HOST_INSERT_INI	   _T("setting\\HostInsert.ini")
#define  WININI				_T("win.ini")
#define  HOSTLIST_INI			_T("setting\\HostListSD.ini")
#define ROOTKITDB_INI_FILE      _T("setting\\AntiRootkit.ini")

#define WORMFOUNDLOGFILE			_T("WormFoundLogFile.txt")
#define SPYINSPECTEDCNTFILE			_T("SpyInspectedCntFile.txt")

#ifdef WIN64
#define LOG_FILE					_T("Log\\ScLog64.txt")
#define EXPORT_LOG_FILE				_T("Log\\Export64.txt")
#define GENPE_LOG_FILE				_T("Log\\GenPELog64.txt")
#define ROOTKIT_LOG_FILE			_T("Log\\RootKitLog64.txt")
#define HEUR_LOG_FILE				_T("Log\\HeurLog64.txt")
#define EXEC_LOG_FILE				_T("Log\\ExecLog64.txt")
#define PESIG_LOG_FILE				_T("Log\\PESigLog64.txt")
#define MD5_LOG_FILE				_T("Log\\MD5Log64.txt")
#define LIVEUPDATE_LOG_FILE			_T("Log\\LiveupdateLog64.txt")
#define VOUCHER_LOG_FILE			_T("Log\\VoucherLog64.txt")
#define VIRUS_LOG_FILE				_T("Log\\VirusLog64.txt")
#define SPLSPY_LOG_FILE				_T("Log\\SplSpyLog64.txt")
#define LIVEUPDATE_LOG				_T("LiveupdateLog64.txt")
#else
#define LOG_FILE					_T("Log\\ScLog32.txt")
#define EXPORT_LOG_FILE				_T("Log\\Export32.txt")
#define GENPE_LOG_FILE				_T("Log\\GenPELog32.txt")
#define ROOTKIT_LOG_FILE			_T("Log\\RootKitLog32.txt")
#define HEUR_LOG_FILE				_T("Log\\HeurLog32.txt")
#define EXEC_LOG_FILE				_T("Log\\ExecLog32.txt")
#define PESIG_LOG_FILE				_T("Log\\PESigLog32.txt")
#define MD5_LOG_FILE				_T("Log\\MD5Log32.txt")
#define LIVEUPDATE_LOG_FILE			_T("Log\\LiveupdateLog32.txt")
#define VOUCHER_LOG_FILE			_T("Log\\VoucherLog32.txt")
#define VIRUS_LOG_FILE				_T("Log\\VirusLog32.txt")
#define SPLSPY_LOG_FILE				_T("Log\\SplSpyLog32.txt")
#define LIVEUPDATE_LOG				_T("LiveupdateLog32.txt")
#endif

#define LOG_SCAN_RESULT_CMD				_T("Log\\ScanLog.txt")



#define LIVEUPDATE_WAIT_FOR_MERGE	_T("WaitingForMerge")
#define TEMP_LIVEUPDATE				_T("AuLiveupdate")
#define TEMP_LIVEUPDATE_DATA		_T("AuLiveupdate\\Data")

#define  FTP_USER_NAME			 _T("anonymous")
#define  FTP_PASSWORD			 _T("")
#define  FTP_DIR_NAME			 _T("uploadstandalone")

#define   LASTSCANDATE		_T("LastScanDate")

#define   SCHEDULAR_PARAM	_T("-SCHEDULAR")
#define   AUAUTOSCAN    	_T("AutoScan")
#define	  QUARANTINECNT     _T("QuarantinedCnt")
#define   VERSIONNO			_T("VersionNo")

#define	  DRIVEKEY			_T("SelectedDrive")	
#define	  AllDRIVEKEY		_T("AllDrives")	
#define   ACCOUNTKEY		_T("Account")
#define   APPUSERKEY		_T("AppUser")
#define   EXPIREDKEY		_T("Expired")
#define	  SPLALLLOCKEY		_T("SplAllLocations")	
#define   BUYNOWPAGE					_T("BuyNowPage")
#define   SCHEDULESCAN					_T("ScheduleScan")
#define	  CLEANTEMPKEY					_T("CleanTemp")
#define	  CLEANTEMPIEKEY				_T("CleanTempIE")
#define	  KEYLOGGERSCANKEY				_T("KeyLoggerScan")
#define	  ROOTKITSCANKEY				_T("RootKitScan")
#define	  ADVSCANKEY					_T("AdvancedScan")
#define	  VIRUSSCANKEY					_T("VirusScan")
#define   ROOTKITQUARANTINEKEY          _T("RootkitQuarantine") 
#define   ROOTKITQUARANTINEALWAYKEY     _T("RootkitQuarantineAlway") 
#define   ROOTKITFOUND                  _T("RootkitFound")
#define   RESCANDATAPRESENT             _T("RescanDataPresent")
#define   RESCANNED_ENTRIES             _T("RescannedEntries")

#define WINSOCKXP					_T("WinsockBkp-WinXP.reg")
#define WINSOCK2K					_T("WinsockBkp-Win2K.reg")
#define WINSOCK98					_T("WinsockBkp-Win98.reg")
#define WINSOCKME					_T("WinsockBkp-WinME.reg")
#define WINSOCKXPHE					_T("WinsockBkp-WinXPHE.reg")
#define WINSOCKVISTA				_T("WinsockBkp-WinVista.reg")

#define WIN_BACKUP		_T("Windows_Backup.reg")
#define IE_BACKUP		_T("IE_Backup.reg")
#define WIN_INI			_T("savewin.ini")
#define SYS_INI			_T("savesys.ini")
#define KEYS_BACKUP		_T("startupBackup.reg")

#define HOST_FILE_PATH			_T("\\drivers\\etc\\hosts")
#define HOSTBACKUP_FILE_PATH	_T("\\drivers\\etc\\hosts.backup")

#define  SERVER_PATH				 _T("https://updateultraav.s3.amazonaws.com/update")
#define  SERVER_PATH2				 _T("https://updateultraav.s3.amazonaws.com")
#define  SERVER_UPDATE_FOLDER_PATH    _T("https://updateultraav.s3.amazonaws.com/update/")
#define  INI_FILE_NAME				 _T("ServerVersionEx.txt")
#define  INI_DELTASERVER_FILE_NAME				 _T("DeltaServerVersion.txt")
#define  INI_CHEKC_UPDATE				 _T("CheckUpdate.txt")



#define  LIVEUPDATEPATH_URL		   _T("https://updateultraav.s3.amazonaws.com/update/getliveupdatepath.txt")
#define  LIVEUPDATEPATH_URL2		   _T("https://updateultraav.s3.amazonaws.com/update/getliveupdatepath.txt")


#define  SERVER_VERSIONFILE		 _T("https://updateultraav.s3.amazonaws.com/update/ServerversionEx.txt")   

#define  DEFAULT_SERVERPATH		 _T("https://updateultraav.s3.amazonaws.com/update/")
#define  DEFAULT_SVR_VERSIONFILE	   _T("https://updateultraav.s3.amazonaws.com/update/ServerversionEx.txt")

#define  SERVER_VERSIONFILE_HTTP			_T("https://updateultraav.s3.amazonaws.com/update/ServerversionEx.txt")   
#define  DEFAULT_SVR_VERSIONFILE_HTTP	_T("https://updateultraav.s3.amazonaws.com/update/ServerversionEx.txt")

#define  SERVER_VERSIONFILE_HTTPDELTA			_T("https://updateultraav.s3.amazonaws.com/update/deltaServerversion.txt")    

#define  DEFAULT_SVR_VERSIONFILE_HTTPDELTA	_T("https://updateultraav.s3.amazonaws.com/update/deltaServerversion.txt")

#define  SERVER_VERSIONFILEDELTA		 _T("https://updateultraav.s3.amazonaws.com/update/deltaServerversion.txt")    

#define  DEFAULT_SVR_VERSIONFILEDELTA	    _T("https://updateultraav.s3.amazonaws.com/update/deltaServerversion.txt")

#define	 MAX_CHECK_INTERNET_CONNECTION_1	_T("https://updateultraav.s3.amazonaws.com/update/checkinternet.txt")
#define	 MAX_CHECK_INTERNET_CONNECTION_2	_T("https://updateultraav.s3.amazonaws.com/update/checkinternet.txt")

#ifdef WIN64
#define  DATABASEKEY				 _T("DataBaseDetailsx64")
#else
#define  DATABASEKEY				 _T("DataBaseDetails")
#endif
#define  DATABASEKEYM				 _T("DataBaseDetailsMonthly")
#define  DATABASEKEYW				 _T("DataBaseDetailsWeekly")
#define  DELTADETAILS		 _T("NewDeltaDBDetails")		    
#define  EPREGKEY			 _T("EPVersionNo")
#define  MD5REGKEY			 _T("MD5VersionNo")
#define  EPDetails           _T("EPLiveUpdateDetails")
#define  MD5Details          _T("MD5LiveUpdateDetails")

#define  UPDATEVERSION					_T("UpdateVersion")
#define  FIRSTPRIOTYREGKEY				_T("FirstPriorityVersionNo")
#define  PRODUCTVERREGKEY				_T("ProductVersionNo")
#define  DATABASEREGKEY					_T("DatabaseVersionNo")
#define  VIRUSDBUPDATECOUNT				_T("VirusDBUpdateCount")
#define  BASEVERSIONREGKEY				_T("BaseVersionNo")
#define  MERGERREGKEY					_T("MergerVersionNo")
#define  INFOREGKEY						_T("InformationVersionNo")
#define  REMOVESPYREGKEY				_T("ComplexSpyVersionNo")
#define  KEYLOGGERREGKEY				_T("KeyLoggerVersionNo")
#define  ROOTKITREGKEY					_T("RootKitVersionNo")
#define  ADVANCEREGKEY					_T("AdvanceScanVersionNo")
#define  VIRUSREGKEY					_T("VirusVersionNo")
#define  FIREWALLREGKEY					_T("FirewallVersionNo")
#define  PATTERNREGKEY					_T("PatternVersionNo")
#define  PATTERNDETAILS					_T("PatternDetails")
#define  ADVANCEDETAILS					_T("AdvanceScanDetails")
#define  MINIDBREGKEY					_T("DatabaseMiniVersionNo")
#define  PRODUCTVERSION				_T("ProductVersionNo")

#define  BASEREGKEY				 _T("BaseVersionNo")
#define  INCRDBKEY					 _T("IncrDBVersionNo")
#define  FULL_DBPATCH_NAME			 _T("AUFDB.exe")
#define  INCR_DBPATCH_NAME			 _T("IncrSDDatabase.db")
#define  CLIENT_LIST_DB_FILE		 _T("IConfSDC_ClientsDB_2.cdb")
#define  SENDREPORT_EXE				_T("\\SendReport.exe")
#define  TEAMVIEWER_EXE				_T("TeamViewerQS.exe")



#define  CONST_PF_DIR					 _T("%pfdir%")
#define  CONST_SYSTEM_DIR				 _T("%sysdir%")

#define  CONST_ADMINTOOLS_DIR			 _T("%admintools%")
#define  CONST_COMMON_ADMINTOOLS_DIR	 _T("%common_admintools%")
#define  CONST_APPDATA_DIR				 _T("%appdata%")
#define  CONST_COMMON_APPDATA_DIR		 _T("%common_appdata%")
#define  CONST_COMMON_DOCUMENTS_DIR	 _T("%common_documents%")
#define  CONST_COOKIES_DIR				 _T("%cookies%")
#define  CONST_FLAG_CREATE_DIR			 _T("%flag_create%")
#define  CONST_HISTORY_DIR				 _T("%history%")
#define  CONST_INTERNET_CACHE_DIR		 _T("%internet_cache%")
#define  CONST_MYPICTURES_DIR			 _T("%mypictures%")
#define  CONST_PERSONAL_DIR			 _T("%personal%")
#define  CONST_COMMON_PROGRAMS_DIR		 _T("%common_programs%")
#define  CONST_FAVORITES_DIR			 _T("%favorites%")
#define  CONST_COMMON_DESKTOP_DIR		 _T("%common_desktop%")
#define  CONST_ROOT_DIR				 _T("%root%")
#define  CONST_PROFILES_DIR			 _T("%profiles%")
#define  CONST_COMMON_FAVORITES_DIR	 _T("%common_favorites%")

#define  CONST_AU_LS_TEMP_IE	 _T("%das.au.ls.temp-inet-files%")
#define  CONST_AU_LS_HISTORY	 _T("%das.au.ls.history%")
#define  CONST_AU_LS_APPDATA	 _T("%das.au.ls.app-data%")
#define  CONST_AU_LS			 _T("%das.au.ls%")
#define  CONST_AU_MD_MYVIDEOS	 _T("%das.au.md.myvideos%")
#define  CONST_AU_MD_MYMUSIC	 _T("%das.au.md.mymusic%")
#define  CONST_AU_MD_MYPIC		 _T("%das.au.md.mypictures%")
#define  CONST_AU_MYDOC		 _T("%das.au.md%")
#define  CONST_AU_APPDATA		 _T("%das.au.app data%")
#define  CONST_AU_TEMPLATES	 _T("%das.au.templates%")
#define  CONST_AU_COOKIES		 _T("%das.au.cookies%")
#define  CONST_AU_DESKTOP		 _T("%das.au.desktop%")
#define  CONST_AU_D_MYVIDEOS	 _T("%das.au.doc.myvideos%")
#define  CONST_AU_D_MYMUSIC	 _T("%das.au.doc.mymusic%")
#define  CONST_AU_D_MYPIC		 _T("%das.au.doc.mypictures%")
#define  CONST_AU_DOC			 _T("%das.au.doc%")
#define  CONST_AU_PRN_HOOD		 _T("%das.au.prn-hood%")
#define  CONST_AU_NET_HOOD		 _T("%das.au.net-hood%")
#define  CONST_AU_FAVORITES 	 _T("%das.au.fav-hood%")
#define  CONST_AU_SM_P_STARTUP  _T("%das.au.sm.p-startup%")
#define  CONST_AU_SM_PROG		 _T("%das.au.sm.p%")
#define  CONST_AU_SM			 _T("%das.au.sm%")
#define  CONST_AU_MY_RECENT_DOC  _T("%das.au.recent%")
#define  CONST_AU_SENDTO		 _T("%das.au.sendto%")
#define  CONST_AU				 _T("%das.au%")
#define  CONST_DAS				 _T("%das%")
#define  CONST_PF_COMMON		 _T("%pf.common%")
#define  CONST_PF				 _T("%pf%")
#define  CONST_WIN_SYS32_DRIVERS	 _T("%win.sys32.drivers%")
#define  CONST_WIN_SYS32_DLLCACHE	 _T("%win.sys32.dllcache%")
#define  CONST_WIN_SYS32			 _T("%win.sys32%")
#define  CONST_WIN_SYS				 _T("%win.sys%")
#define  CONST_WIN_APP_DATA		 _T("%win.app-data%")
#define  CONST_WIN_SPFILES			 _T("%win.sp-files%")
#define  CONST_WIN_MS_NET_FRM		 _T("%win.ms.net.frm%")
#define  CONST_WIN_MS_NET			 _T("%win.ms.net%")
#define  CONST_WIN_FONT			 _T("%win.fonts%")
#define  CONST_WIN_HELP			 _T("%win.help%")
#define  CONST_WIN_DWN_PF			 _T("%win.dwn-pf%")
#define  CONST_WIN_INSTALLER		 _T("%win.installer%")
#define  CONST_WIN_RESOURCE		 _T("%win.resource%")
#define  CONST_WIN					 _T("%win%")
#define  CONST_ROOT				 _T("%root%")


#define  SS_REGISTRY_SNAP  _T("RegistryBackup")
#define  SS_STARTUP_SNAP  _T("StartUpAll")


#define  ACTION_ADD  _T("1")
#define  ACTION_RESTORE  _T("2")

typedef BOOL (CALLBACK *SENDSCANMESSAGE)(int iScanMsgID, WPARAM wParam, LPARAM lParam, ENUM_WORMTYPE eWormType, LPVOID pThis);
typedef BOOL (CALLBACK *REGISTRYFIXMESSAGE)(int iScanMsgID, LPCTSTR sSpyName, LPCTSTR sWorm, LPCTSTR sAction, ENUM_WORMTYPE eWormType, LPVOID pThis);
typedef BOOL (CALLBACK *SENDSPLSCANMESSAGE)(CString csSpyName,CString csWorm,  ENUM_WORMTYPE eWormType, LPVOID pThis,bool bCheckStop);
typedef void (CALLBACK *SENDKLSCANMESSAGE)(int iMsgID,CString sSpyName, CString sWorm, int iWormType,int iQuarantine,LPVOID pThis);
typedef BOOL (CALLBACK *SENDSIGNATURESCANMESSAGE)(int iScanMsgID, WPARAM wParam, LPARAM lParam, LPVOID pThis);

#define  BLOCKBHO_SPYDB_FILE_NAME		 _T("BlockBHO.db")
#define  REMOVE_SPYDB_FILE_NAME		 _T("RemoveDB.db")
#define  DELETE_SPYDB_FILE_NAME		 _T("DeleteDB.db")


const int FILE_DATA_LEN						= 2048;
const int LOOKIN_TEXT_NOT_FOUND_IN_FILE		= 0;
const int LOOKIN_TEXT_FOUND_IN_FILE			= 1;
const int LOOKIN_FILE_IN_USE				= 2;
const int LOOKIN_FILE_DOES_NOT_EXISIT		= 3;
const int LOOKIN_FILE_READ_FAILED			= 4;
const int LOOKIN_UNHANDLED_EXCEPTION		= 5;

#define	SDMONITOREXE					_T("\\SDMonitor.exe")
#define  REMOTE_ADMIN_CORP_SERVICE_EXE	_T("SDClient.exe")
#define  SDCESPYLIST_DATABASE			_T("SDCESpylist.db")
#define  REMOTE_HSITORY_SCAN_INI		_T("ScanHistory.ini")	
#define  PROCESS_MONITOR_DLL			_T("ProcessMonitorDll.dll")
#define  PROCESSSPY_DATABASE			_T("ProcessSpy.db")
#define  TRACKINGCOOKIES_INI			_T("setting\\SDTrackingCookies.ini")
#define  RECOVERSPY_EXE					_T("SDRecoverSpy.exe")
#define  MFC71_DLL						_T("MFC71.dll")
#define  MSVCP71_DLL					_T("msvcp71.dll")
#define  MSVCR71_DLL					_T("msvcr71.dll")
#define  PSAPI_DLL						_T("psapi.dll")
#define  EXCLUDE_SPYDB			  		_T("ExcludeDB.db")
#define  SCHEDULEINFO_INI				_T("Schedule_Info.ini")
#define  SDNOTIFY_DLL					_T("SDNotify.dll")
#define  SDHOOK_DLL						_T("SDHook.dll")
#define  UNREGISTER_REG					_T("UnReg.reg")
#define  FILE1_DLL						_T("file1.dll")
#define  CLK_EXE						_T("clk.exe")
#define  SCANHISTORYFILE				_T("\\ScanHistory.ini")
#define  SCANNER_EXTENSION				_T("ScannerExtension.exe")
#define SPYDB_FILE_NAME					_T("FixScanlist.db")
#define WHITESLLLIST_DB				    _T("WhiteDllList.db")
#define	SIGNATUREMD5_DB					_T("SignatureMD5.db")
#define LIVEUPDATEPOPUP				_T("UpdatePopUp.exe")

#define UI_EXENAME					_T("AuMainUI.exe")
#define UI_TRAYNAME					_T("AuTray.exe")
#define UI_PPLSRVNAME				_T("AuPSrvOpt.dll")
#define UNINSTALL_PROCESS			_T("AuUninstall.dll")

#define  SPY_QUARANTINE_DELETE        	_T("QDELETE")
#define  SPY_DETECTED_DELETE			_T("DDELETE")	
#define  SPY_RECOVER					_T("RECOVER")
#define	 SPY_QUARANTINE                 _T("QUARANTINE")
#define  PARENT_LOG_FOLDER			    _T("LogFolder\\")
#define  PARENT_ACTIVE_MON_LOG_FOLDER	_T("LiveMonitorLogFolder\\")

#define NOOFSCANS			"noofscans"
#define FOUND				"Detected"
#define DELETED				"Deleted"
#define QUARANTINED			"Quarantined"
#define SPECIALSPYCNT		"SpecialSpyCount"

	
#define  CONST_SCANNED_STATUS		 _T("SCANNED   ")
#define  CONST_QSUCCESS_STATUS		 _T("Q-SUCCESS ")
#define  CONST_QFAILED_STATUS		 _T("Q-FAILED  ")
#define  CONST_QCHILD_STATUS		 _T("Q-CHILD   ")
#define  CONST_DSUCCESS_STATUS		 _T("D-SUCCESS ")
#define  CONST_DFAILED_STATUS		 _T("D-FAILED  ")
#define  CONST_RQSUCCESS_STATUS	 _T("RQ-SUCCESS")
#define  CONST_RQFAILED_STATUS		 _T("RQ-FAILED ")
#define  CONST_QSCAN				 _T("Quick Scan ")
#define  CONST_FSCAN				 _T("Full Scan ")
#define  CONST_SSCAN				 _T("Signature Scan ")
#define  CONST_NOTIFY_SPYNAME		 _T("Vundo")

#define  SYSTEM_LOG_FILE			_T("Log\\SystemLog.txt")
#define  REGISTRY_LOG_FILE			_T("Log\\RegistryInfo.txt")


#define OBJ_CASE_INSENSITIVE 0x40

#define NT_SUCCESS(Status) ((NTSTATUS)(Status) == 0)



#define InitializeObjectAttributes( p, n, a, r, s ) { \
    (p)->Length = sizeof( OBJECT_ATTRIBUTES );          \
    (p)->RootDirectory = r;                             \
    (p)->Attributes = a;                                \
    (p)->ObjectName = n;                                \
    (p)->SecurityDescriptor = s;                        \
    (p)->SecurityQualityOfService = NULL;               \
    }


const int iLow = 20;
const int iMedium = 40;
const int iHigh = 60;
const int iCritical = 100;


const int WORM_TYPE_COOKIE			= 1;
const int WORM_TYPE_FILE			= 2;
const int WORM_TYPE_FOLDER			= 3;
const int WORM_TYPE_PROCESS			= 4;
const int WORM_TYPE_REGKEY			= 5;
const int WORM_TYPE_REGVAL			= 6;
const int WORM_TYPE_REGDATA			= 7;
const int WORM_TYPE_MOZILLACOOKIE	= 8;
const int WORM_TYPE_WHITELIST		= 9;
const int WORM_TYPE_SIGNATURE		= 10;
const int WORM_TYPE_BHO				= 11;
const int WORM_TYPE_TOOLBAR			= 12;
const int WORM_TYPE_MENUEXTENSION   = 13; 
const int WORM_TYPE_ACTIVEX         = 14;
const int WORM_TYPE_COM		        = 15;
const int WORM_TYPE_SSODL			= 16;
const int WORM_TYPE_SHAREDTASKSCH	= 17;
const int WORM_TYPE_APPINIT			= 18;
const int WORM_TYPE_SERVICES		= 19;
const int WORM_TYPE_NOTIFY			= 20;
const int WORM_TYPE_WHITE_SSODL		= 21;
const int WORM_TYPE_WHITE_APPINIT	= 22;
const int WORM_TYPE_WHITE_NOTIFY	= 23;
const int WORM_TYPE_INFO_HELP		= 24;
const int WORM_TYPE_REGFIX			= 25;
const int WORM_TYPE_MON_SSODL		= 26;      
const int WORM_TYPE_MON_SHARED		= 27;       
const int WORM_TYPE_KEYLOGGER		= 28;
const int WORM_TYPE_COUNT			= 30;
const int WORM_TYPE_PATTERN			= 29;
const int WORM_TYPE_EPSIGNATURE		= 30;
const int WORM_TYPE_STARTUP			= 31;      
const int WORM_TYPE_SHELLEXECHOOK	= 32;
const int WORM_TYPE_NETCONMONITOR	= 33;
const int WORM_TYPE_VALUETYPE		= 34;
const int WORM_TYPE_SPYNAME			= 35;
const int WORM_TYPE_REGFIX_FT1		= 36;
const int WORM_TYPE_REGFIX_FT2		= 37;
const int WORM_TYPE_REGFIX_FT3		= 38;
const int WORM_TYPE_WORMCOUNT       = 39;
const int WORM_TYPE_HOST			= 40;      

#define  SPYDB_FILE_NAME_COOKIE				_T("SD1.DB")
#define  SPYDB_FILE_NAME_PROCESS				_T("SD2.DB")
#define  SPYDB_FILE_NAME_FILE					_T("SD3.DB")
#define  SPYDB_FILE_NAME_FOLDER				_T("SD4.DB")
#define  SPYDB_FILE_NAME_REGKEY				_T("SD5.DB")
#define  SPYDB_FILE_NAME_REGVAL				_T("SD6.DB")
#define  SPYDB_FILE_NAME_REGDATA				_T("SD7.DB")
#define  SPYDB_FILE_NAME_REGFIX				_T("SD8.DB")
#define  SPYDB_FILE_NAME_WHITELIST				_T("SD9.DB")
#define  SPYDB_FILE_NAME_SIGNATURE				_T("SD10.DB")
#define  SPYDB_FILE_NAME_BHO					_T("SD11.DB")
#define  SPYDB_FILE_NAME_MAIN_INFO_HELP		_T("SD12.DB")
#define  SPYDB_FILE_NAME_TOOLBAR				_T("SD13.DB")
#define  SPYDB_FILE_NAME_MENUEXTENSION     	_T("SD14.DB")
#define  SPYDB_FILE_NAME_ACTIVEX              _T("SD15.DB")
#define  SPYDB_FILE_NAME_COM		           _T("SD16.DB")
#define  SPYDB_FILE_NAME_IGNORE_ZIP           _T("SD17.DB")
#define  SPYDB_FILE_NAME_SSODL		           _T("SD18.DB")
#define  SPYDB_FILE_NAME_SHAREDTASKSCH		   _T("SD19.DB")
#define  SPYDB_FILE_NAME_WHITE_SSODL		   _T("SDWS.DB")
#define  SPYDB_FILE_NAME_APPINIT			   _T("SD21.DB")
#define  SPYDB_FILE_NAME_WHITE_APPINIT		   _T("SDWA.DB")
#define  SPYDB_FILE_NAME_SERVICES			   _T("SD23.DB")
#define  SPYDB_FILE_NAME_NOTIFY			   _T("SD24.DB")
#define  SPYDB_FILE_NAME_WHITE_NOTIFY		   _T("SDWN.DB")
#define  SPYDB_FILE_NAME_WHITE_KEYLOGGER	   _T("SDWK.DB")
#define  SPYDB_FILE_NAME_PATTERN			   _T("SD27.DB")
#define  SPYDB_FILE_NAME_MD5SIGNATURE			_T("SD28.DB")
#define  SPYDB_FILE_NAME_WHITE_HEURISTIC	   _T("HeurWhiteDb.db") 
#define  SPYDB_FILE_NAME_EPINFO			   _T("SD30.DB")
#define  SPYDB_FILE_NAME_NET_CONNECTIONS	   _T("SD31.DB")  
#define  SPYDB_FILE_NAME_KEYLOGGER_WHITE	   _T("SDWK.DB")
#define  SPYDB_FILE_NAME_APPINIT_WHITE		   _T("SDWA.DB")
#define  SPYDB_FILE_NAME_HOST_FILE			   _T("SDH.DB")

#define  VIRDB_FILE_NAME_INI_SCAN			   _T("SDVS01.DB") 
#define  VIRDB_FILE_NAME_INI_REPAIR		   _T("SDVS02.DB") 
#define  VIRDB_FILE_NAME_PE_SCAN			   _T("SDVS03.DB") 
#define  VIRDB_FILE_NAME_PE_EX_SCAN		   _T("SDVS04.DB") 
#define  VIRDB_FILE_NAME_PE_REPAIR			   _T("SDVS05.DB") 
#define  VIRDB_FILE_NAME_PE_EX_REPAIR		   _T("SDVS06.DB") 
#define  VIRDB_FILE_NAME_PE_MODULES		   _T("SDVS07.DB") 
#define  VIRDB_FILE_NAME_SCRIPT_SCAN		   _T("SDVS08.DB") 
#define  VIRDB_FILE_NAME_OLE_SCAN				_T("SDVS09.DB") 
#define  VIRDB_FILE_NAME_OLE_MACRO_SCAN		_T("SDVS10.DB") 
#define  VIRDB_FILE_NAME_OLE_EMBEDDED_SCAN		_T("SDVS11.DB") 
#define  VIRDB_FILE_NAME_BINARY_SCAN			_T("SDVS12.DB") 
#define  VIRDB_FILE_NAME_PROCESS_SCAN			_T("SDVS13.DB") 

#define  SPYDB_FILE_NAME_MON_SSODL			   _T("SM1.DB")
#define  SPYDB_FILE_NAME_MON_SHARED		   _T("SM2.DB")

#define  SPYDB_FILE_NAME_HOST				   _T("host.DB")
#define  SPYDB_FILE_NAME_RESTRICTED		   _T("RSite.DB")

#define  USERDB_FILE_NAME_NET_CONNECTIONS	   _T("UserNetCon.DB")   

#define  SPYDB_COUNT_WORM_ID				 _T("c0")

#define  SCANNER_DB_FILE_NAME_PROCESS			_T("SE2.DB")
#define  SCANNER_DB_FILE_NAME_FILE				_T("SE3.DB")
#define  SCANNER_DB_FILE_NAME_FOLDER			_T("SE4.DB")
#define  SCANNER_DB_FILE_NAME_REGKEY			_T("SE5.DB")
#define  SCANNER_DB_FILE_NAME_REGVAL			_T("SE6.DB")
#define  SCANNER_DB_FILE_NAME_REGDATA			_T("SE7.DB")
#define  SCANNER_DB_FILE_NAME_SIGNATURE		_T("SE10.DB")

#define  EX_DB_BY_ID			  		L"ExByID.DB"
#define  EX_DB_BY_NAME			  		L"ExByName.DB"
#define  EX_DB_BY_IDENTRY			  	L"ExByIDEntry.DB"
#define  EX_DB_BY_NAMEENTRY				L"ExByNameEntry.DB"
#define  EX_DB_BY_AUTO_RTKT				L"AutoExRtkt.DB"

#define WHITELIST_MGR_DB			 _T("WhiteListMgr.DB")
#define APPBLOCKLIST_MGR_DB			 _T("AppBlockListMgr.DB")

#define APPEXTLIST_MGR_DB			 _T("AppExtListMgr.DB")
#define APP_EXCLUDE_FILEEXTLIST_DB   _T("AppExcludeFileExtList.DB")


#define USERSETTINGS_IMEX_DB			 _T("UserSettingsImEx.DB")
#define USERSETTINGS_FIREWALL_IMEX_DB	 _T("UserSettingsFirewallImEx.DB")
#define USERSETTINGS_USB_IMEX_DB		 _T("UserSettingsUSBImEx.DB")
#define USERSETTINGS_PASSWORDIMEX_DB	 _T("UserSettingsPASSImEx.DB")
#define NETWORK_SCAN_CRED				 _T("NetworkCredImxEX.DB")
#define CURR_USER_CRED				     _T("UserCredImxEX.DB")
#define  csFILE_DB				_T("spl1.db") 
#define  csEXT_DB				_T("spl2.db") 
#define  csLOC_DB				_T("spl3.db") 
#define  csSTRING_DB			_T("spl4.db") 
#define  csDELETE_DB			_T("spl5.db") 
#define  csFILEGROUP_DB		_T("spl6.db")

#define  UNDERWOW_RUN_REG_PATH			  _T("Microsoft\\Windows\\CurrentVersion\\Run")
#define  WOW6432NODE_REG_PATH			  _T("SOFTWARE\\Wow6432Node\\")
#define  UNDERWOW_WINLOGON_REG_KEY		  _T("microsoft\\windows nt\\currentversion\\winlogon")
#define  UNDERWOW_RUNSVC_REG_PATH		  _T("Microsoft\\Windows\\CurrentVersion\\RunServices")
#define  UNDERWOW_REG_NOTIFY_ENTRY		  _T("microsoft\\windows nt\\currentversion\\winlogon\\notify\\")
#define  UNDERWOW_STS_PATH				  _T("microsoft\\windows\\currentversion\\explorer\\sharedtaskscheduler")
#define  UNDERWOW_SHELL_EXEC_HOOKS		  _T("Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellExecuteHooks") 
#define  UNDERWOW_RUNONCE_REG_PATH		  _T("Microsoft\\Windows\\CurrentVersion\\RunOnce") 
#define  UNDERWOW_CV_SHELL_EXT_PATH	  _T("Microsoft\\Windows\\CurrentVersion\\Shell Extensions\\Approved") 
#define  UNDERWOW_BHO_REGISTRY_PATH	  _T("Microsoft\\windows\\currentversion\\explorer\\browser helper objects")
#define  UNDERWOW_WNT_WINDOWS_PATH		  _T("Microsoft\\windows NT\\currentversion\\Windows")
#define  UNDERWOW_POL_EXPL_RUN_PATH	  _T("Microsoft\\windows\\currentversion\\policies\\explorer\\run") 
#define  UNDERWOW_SSODL_PATH			  _T("Microsoft\\windows\\currentversion\\shellserviceobjectdelayload")
#define  UNDERWOW_SVCHOST_MAIN_KEY		  _T("Microsoft\\Windows NT\\CurrentVersion\\SvcHost")


#define WM_USER_LOAD_DATABSE_COMPLATE		(WM_APP + 100)
#define WM_USER_SCAN_FINISH					(WM_APP + 101)
#define WM_USER_SCANING_STATUS				(WM_APP + 102)
#define WM_USER_LOADING_STATUS				(WM_APP + 103)
#define WM_USER_SCAN_STATUS					(WM_APP + 104)
#define WM_USER_FULL_SCAN_STATUS			(WM_APP + 105)
#define	WM_USER_START_SCHEDULE_SCAN			(WM_APP + 106)
#define	WM_USER_PROTECTION_SWITCH			(WM_APP + 107)
#define	WM_USER_TRACKINGCOOKIE_SWITCH		(WM_APP + 108)
#define	WM_USER_HOMEPAGE_SWITCH				(WM_APP + 109)
#define	WM_USER_LIVEUPADTE_STATUS			(WM_APP + 110)
#define WM_USER_RESTART_MON_SWITCH			(WM_APP + 111)
#define WM_USER_WORM_FOUND					(WM_APP + 112)
#define WM_USER_FAIL_QUARANTINE				(WM_APP + 113)
#define WM_USER_SCAN_FINISH_POST_MSG		(WM_APP + 114)
#define WM_USER_SHOW_LOG_POST_MSG			(WM_APP + 115)
#define WM_USER_SCAN_IN_PROGRESS_STATUS		(WM_APP + 116)
#define WM_USER_FINISHED_SPECIAL_REMOVAL	(WM_APP + 117)
#define	WM_USER_START_LIVEUPADTE			(WM_APP + 118)
#define	WM_USER_FILE_RECEIVED				(WM_APP + 119)
#define WM_USER_SCHEDULE_INFO				(WM_APP + 120)
#define	WM_USER_ALL_LOG_FILES_RECEIVED		(WM_APP + 121)
#define WM_SCHEDULE_INFO					(WM_APP + 122)
#define WM_ADDTOOUTPUT						(WM_APP + 123)
#define WM_USER_SCANSTOPPED					(WM_APP + 124)
#define WM_USER_SPECWORM_FOUND				(WM_APP + 125)
#define WM_USER_ACTIVEX_LOAD				(WM_APP + 126)
#define WM_USER_SITES_LOAD					(WM_APP + 127)
#define WM_USER_COOKIE_LOAD					(WM_APP + 128)
#define WM_USER_HOST_MON_SWITCH				(WM_APP + 129)
#define WM_USER_SPL_SCAN_FINISH				(WM_APP + 130)
#define WM_USER_SPL_SCAN_START              (WM_APP + 131)
#define WM_SCANSTART						(WM_APP + 132)
#define WM_SCANSTOP							(WM_APP + 133)
#define WM_USER_KEYLOGGER_SCAN_START		(WM_APP + 134)
#define WM_USER_KEYLOGGER_SCAN_FINISH		(WM_APP + 135)
#define WM_USER_ROOTKIT_SCAN_FINISH			(WM_APP + 136)
#define WM_USER_ROOTKIT_SCAN_START			(WM_APP + 137)
#define WM_USER_EXEC_SIGNATURE_SCAN_FINISH	(WM_APP + 138) 
#define WM_USER_EXEC_SIGNATURE_SCAN_START	(WM_APP + 139) 
#define WM_USER_HEURISTIC_SCAN_FINISH		(WM_APP + 140) 
#define WM_USER_HEURISTIC_SCAN_START		(WM_APP + 141) 
#define WM_USER_REGFIX_WORM_FOUND			(WM_APP + 142)
#define WM_USER_VIRUS_SCAN_FINISH			(WM_APP + 143)
#define WM_USER_VIRUS_SCAN_START            (WM_APP + 144)
#define WM_USER_ALL_SCAN_END				(WM_APP + 145)
#define WM_USER_ID_MAXSHIELD_LIST			(WM_APP + 146)
#define WM_USER_ID_MAXSHIELD_TIMER			(WM_APP + 147)
#define WM_USER_START_FULL_SCAN             (WM_APP + 148)
#define WM_USER_START_CUSTOM_SCAN           (WM_APP + 149)
#define WM_SHOWOUTPUTWINDOW					(WM_APP + 150)
#define WM_REFRESH_GRAPH					(WM_APP + 151)
#define WM_SCAN_PROGRESS					(WM_APP + 152)
#define UM_LogLevelChanged					(WM_APP + 153)
#define UM_NotifyPages						(WM_APP + 154)	
#define UM_FwPublishingCB					(WM_APP + 155)	 			 	    
#define UM_FwReportingCB					(WM_APP + 156)	 			 	    
#define UM_WfPublishingCB					(WM_APP + 157)	 			 	    
#define UM_WfReportingCB					(WM_APP + 158)	 			 	    
#define UM_HipsPublishingCB				(WM_APP + 159)	 			 	    
#define UM_HipsReportingCB					(WM_APP + 160)	 			 	    	
#define WM_USER_RELOAD_MAXSHEILD			(WM_APP + 161)
#define WM_PAUSE_ACTIVE_MONITOR				(WM_APP + 162)
#define WM_USER_RELOAD_MAIN_MTS_UI			(WM_APP + 163)
#define WM_USER_INTERNET_OPT_LIST			(WM_APP + 164)
#define WM_USER_LANGUAGE_CHANGED			(WM_APP + 164)
#define WM_USER_ENABLE_PROTECTION			(WM_APP + 165)
#define WM_USER_CHANGED_FIREWALL			(WM_APP + 166)
#define WM_USER_RELOAD_FW_RULES				(WM_APP + 167)
#define WM_USER_PROTECTION_CHANGE			(WM_APP + 168)
#define WM_USER_PARENTAL_CONTROL			(WM_APP + 169)
#define WM_USER_CHANGED_EMAIL_PROTECTION	(WM_APP + 170)
#define WM_USER_ENABLE_GAMING_MODE			(WM_APP + 171)
#define WM_USER_UI_GAMING_MODE				(WM_APP + 172)
#define WM_USER_HIDE_NOTIFICATION			(WM_APP + 173)
#define WM_USER_SHOW_TRIAL_MESSAGE			(WM_APP + 174)
#define WM_USER_HIDE_TRIAL_MESSAGE			(WM_APP + 175)
#define WM_USER_OPTION_TAB_BUTTON_CLICK		(WM_APP + 176)
#define WM_USER_FEATURE_LOCKED_REGISTER		(WM_APP + 177)
#define WM_USER_SHOW_FIREWALL_TAB			(WM_APP + 178)
#define WM_USER_SHOW_EVALUATION_DIALOG		(WM_APP + 179)
#define WM_USER_REFRESH_MAINUI				(WM_APP + 180)
#define WM_USER_SHOW_LICENSE_OPTIONS		(WM_APP + 181)
#define WM_USER_ID_TOOLS_LIST				(WM_APP + 182)
#define WM_USER_ID_FW_PNP_RESTART			(WM_APP + 183)
#define WM_USER_ID_FW_PNP_STOP				(WM_APP + 184)
#define	WM_USER_START_SCHEDULE_BACKUP		(WM_APP + 185)
#define	WM_USER_TRAY_FIREWALL_RESTART		(WM_APP + 186)
#define WM_USER_ID_FW_MON_RESTART			(WM_APP + 187)
#define WM_USER_ID_FW_MON_STOP				(WM_APP + 188)
#define WM_USER_CONTENT_STATUS				(WM_APP + 189)
#define WM_USER_CONTENT_IN_PROGRESS_STATUS	(WM_APP + 190)
#define WM_USER_BACKUP_IN_PROGRESS_STATUS	(WM_APP + 191)
#define WM_USER_ID_NODESERVER_STARTSTOP		(WM_APP + 192)
#define WM_USER_LAUNCH_SDUI_FROMTRAY		(WM_APP + 193)

//#ifndef _SDACTMON_CONSTANT
//#define _SDACTMON_CONSTANT
const LPCTSTR ACTMON_DRIVE_FILENAME	= _T("AuActMonDrv.sys");
const LPCTSTR ACTMON_DRIVE_SYMBOLIC		= _T("\\\\.\\AuActMonDrv");
const LPCTSTR ACTMON_DRIVE_TITLE	    = _T("AuActMonDrv");
const LPCTSTR ACTMON_REG_KEY = _T("System\\Currentcontrolset\\services\\AuActMonDrv");



const LPCTSTR ELAM_DRIVE_TITLE = _T("AuSecPPLElm");
const LPCTSTR ELAM_DRIVE_FILENAME = _T("AuSecPPLElm.sys");
const LPCTSTR ELAM_DRIVE_PATH = _T("system\\currentcontrolset\\services\\AuSecPPLElm");

const LPCTSTR MAX_PROTECTOR_REG_KEY = _T("System\\Currentcontrolset\\services\\AuFSProcDrv");
const LPCTSTR MAXPROTECTOR_DRIVE_ALTITUDEID = _T("328610");
const LPCTSTR MAXPROTECTOR_DRIVE_SYMBOLIC = _T("\\\\.\\AuFSProcDrv");
const LPCTSTR MAXPROTECTOR_DRIVE_FILENAME = _T("AuFSProcDrv.sys");
const LPCTSTR MAXPROTECTOR_DRIVE_TITLE = _T("AuFSProcDrv");


const LPCTSTR MAXMGR_DRIVE_TITLE = _T("AuFsMgrDrv");
const LPCTSTR MAXMGR_DRIVE_SYMBOLIC = _T("\\\\.\\AuFsMgrDrv");
const LPCTSTR MAXMGR_DRIVE_FILENAME = _T("AuFsMgrDrv.sys");
const LPCTSTR MAXMGR_DRIVE_REG_KEY = _T("System\\Currentcontrolset\\services\\AuFsMgrDrv");
#define  MAXMGR_KEY	            MAXMGR_DRIVE_REG_KEY

const LPCTSTR FW_SERVICE_PATH = _T("system\\currentcontrolset\\services\\AuFirewallSrv");
const LPCTSTR FW_SERVICE_NAME = _T("AuFirewallSrv");
const LPCTSTR FW_SERVICE_EXE = _T("AuFirewallSrv.exe");

const LPCTSTR FW_DRIVER_PATH = _T("system\\currentcontrolset\\services\\netfilter2");
const LPCTSTR FW_DRIVER_NAME = _T("netfilter2");
const LPCTSTR FW_DRIVER_SYS = _T("netfilter2.sys");

const LPCTSTR MAXWATCHDOG_SVC_PATH = _T("system\\currentcontrolset\\services\\AuWatchDogService");

#define MAXWATCHDOG_SVC_NAME _T("AuWatchDogService")
#define MAXWATCHDOG_SVC_EXE _T("AuWatchDogService.exe")

#define	ACTMON_SERVICE_NAME	_T("AuActMon")
#define ACTMON_SVC_NAME		_T("AuActMon.exe")
#define MAXMERGER_SVC_NAME  _T("AuMerger")
#define MAXMERGER_SVC_EXE   _T("AuMerger.exe")
#define	MAX_SCANNER			_T("AuScanner.exe")
#define	MAX_DSRV			_T("AuDSrv.exe")
#define BKComDll			_T("AuBKComDll.dll")


#define FSMON_KEY				_T("CryptMonitor")     

const LPCTSTR ACTMON_SERVICE_PATH		= _T("system\\currentcontrolset\\services\\AuActMondrv");
const LPCTSTR ACTMON_INSTANCE_PATH		= _T("system\\currentcontrolset\\services\\AuActMondrv\\instances");

const LPCTSTR ACTMON_NTDLL_FILENAME	= _T("ntdll.dll");
const LPCSTR ACTMON_FN_CREATESEC	= "NtCreateSection";
const LPCSTR ACTMON_FN_CREATEKEY	= "NtCreateKey";
const LPCSTR ACTMON_FN_SETVALUE		= "NtSetValueKey";

const LPCTSTR ACTMON_DATA_SEPERATOR		= _T("#@#");
const LPCTSTR ACTMON_DATA_SEPERATOR2	= _T(" - ");
const LPCTSTR ACTMON_DATA_SEPERATOR3	= _T(" ");
const LPCTSTR ACTMON_DATA_SEPERATOR4	= _T(" ^ ");
const LPCTSTR ACTMON_APPINIT_SEPERATOR	= _T(",");

const LPCTSTR REG_SEPERATOR		= _T(" :: ");

const unsigned int SIZE_5MB					= 5242880;

const int	  ACTMON_HKLM_LEN			= 18;
const int	  ACTMON_USER_LEN			= 15;
const int	  ACTMON_SOFT_LEN			= 9;
const int	  ACTMON_CTRL_LEN			= 14;
const int	  ACTMON_SYS_LEN			= 7;
const LPCTSTR ACTMON_HKLM_KEY			= _T("\\registry\\machine\\");
const LPCTSTR ACTMON_USER_KEY			= _T("\\registry\\user\\");
const LPCTSTR ACTMON_CTRL_KEY			= _T("control panel\\");
const LPCTSTR ACTMON_SOFT_KEY			= _T("software\\");
const LPCTSTR ACTMON_SYS_KEY			= _T("system\\");
const LPCTSTR ACTMON_APPINITDLL_KEY		= _T("software\\microsoft\\windows nt\\currentversion\\windows\\appinit_dlls#@#");
const LPCTSTR ACTMON_APPINITDLL_KEY_X64	= _T("software\\wow6432node\\microsoft\\windows nt\\currentversion\\windows\\appinit_dlls#@#");
const LPCTSTR ACTMON_BHO_KEY			= _T("software\\microsoft\\windows\\currentversion\\explorer\\browser helper objects\\");
const LPCTSTR ACTMON_BHO_KEY_X64		= _T("software\\wow6432node\\microsoft\\windows\\currentversion\\explorer\\browser helper objects\\");
const LPCTSTR ACTMON_EXTENSIONS_KEY		= _T("software\\microsoft\\internet explorer\\extensions\\");
const LPCTSTR ACTMON_EXTENSIONS_KEY_X64	= _T("software\\wow6432node\\microsoft\\internet explorer\\extensions\\");
const LPCTSTR ACTMON_STARTPAGE_KEY		= _T("software\\microsoft\\internet explorer\\main\\start page#@#");
const LPCTSTR ACTMON_STARTPAGE_KEY_X64	= _T("software\\wow6432node\\microsoft\\internet explorer\\main\\start page#@#");
const LPCTSTR ACTMON_COMPONENT_KEY		= _T("software\\microsoft\\internet explorer\\desktop\\components\\");
const LPCTSTR ACTMON_COMPONENT_KEY_X64	= _T("software\\wow6432node\\microsoft\\internet explorer\\desktop\\components\\");
const LPCTSTR ACTMON_IERESTRICT_KEY		= _T("software\\policies\\microsoft\\internet explorer\\restrictions\\");
const LPCTSTR ACTMON_IERESTRICT_KEY_X64	= _T("software\\wow6432node\\policies\\microsoft\\internet explorer\\restrictions\\");
const LPCTSTR ACTMON_SERVICES_KEY1		= _T("system\\currentcontrolset\\services\\");
const LPCTSTR ACTMON_SERVICES_KEY2		= _T("system\\controlset001\\services\\");
const LPCTSTR ACTMON_SERVICES_KEY3		= _T("system\\controlset002\\services\\");
const LPCTSTR ACTMON_SERVICES_KEY4		= _T("system\\controlset003\\services\\");
const LPCTSTR ACTMON_SERVICES_KEY5		= _T("system\\controlset004\\services\\");
const LPCTSTR ACTMON_SERVICES_KEY6		= _T("system\\controlset005\\services\\");
const LPCTSTR ACTMON_SHAREDTASK_KEY		= _T("software\\microsoft\\windows\\currentversion\\explorer\\sharedtaskscheduler\\");
const LPCTSTR ACTMON_SHAREDTASK_KEY_X64	= _T("software\\wow6432node\\microsoft\\windows\\currentversion\\explorer\\sharedtaskscheduler\\");
const LPCTSTR ACTMON_SHELL_KEY			= _T("software\\microsoft\\windows nt\\currentversion\\winlogon\\shell#@#");
const LPCTSTR ACTMON_SHELL_KEY_X64		= _T("software\\wow6432node\\microsoft\\windows nt\\currentversion\\winlogon\\shell#@#");
const LPCTSTR ACTMON_SSODL_KEY			= _T("software\\microsoft\\windows\\currentversion\\shellserviceobjectdelayload\\");
const LPCTSTR ACTMON_SSODL_KEY_X64		= _T("software\\wow6432node\\microsoft\\windows\\currentversion\\shellserviceobjectdelayload\\");
const LPCTSTR ACTMON_RUN_KEY1			= _T("software\\microsoft\\windows\\currentversion\\run\\");
const LPCTSTR ACTMON_RUN_KEY1_X64		= _T("software\\wow6432node\\microsoft\\windows\\currentversion\\run\\");
const LPCTSTR ACTMON_RUN_KEY2			= _T("software\\microsoft\\windows\\currentversion\\runonce\\");
const LPCTSTR ACTMON_RUN_KEY2_X64		= _T("software\\wow6432node\\microsoft\\windows\\currentversion\\runonce\\");
const LPCTSTR ACTMON_RUN_KEY3			= _T("software\\microsoft\\windows\\currentversion\\runonceex\\");
const LPCTSTR ACTMON_RUN_KEY3_X64		= _T("software\\wow6432node\\microsoft\\windows\\currentversion\\runonceex\\");
const LPCTSTR ACTMON_RUN_KEY4			= _T("software\\microsoft\\windows\\currentversion\\runservices\\");
const LPCTSTR ACTMON_RUN_KEY4_X64		= _T("software\\wow6432node\\microsoft\\windows\\currentversion\\runservices\\");
const LPCTSTR ACTMON_RUN_KEY5			= _T("software\\microsoft\\windows\\currentversion\\runservicesonce\\");
const LPCTSTR ACTMON_RUN_KEY5_X64		= _T("software\\wow6432node\\microsoft\\windows\\currentversion\\runservicesonce\\");
const LPCTSTR ACTMON_TOOLBAR_KEY1		= _T("software\\microsoft\\internet explorer\\toolbar\\");
const LPCTSTR ACTMON_TOOLBAR_KEY1_X64	= _T("software\\wow6432node\\microsoft\\internet explorer\\toolbar\\");
const LPCTSTR ACTMON_TOOLBAR_KEY2		= _T("software\\microsoft\\internet explorer\\toolbar\\webbrowser\\");
const LPCTSTR ACTMON_TOOLBAR_KEY2_X64	= _T("software\\wow6432node\\microsoft\\internet explorer\\toolbar\\webbrowser\\");
const LPCTSTR ACTMON_TOOLBAR_KEY3		= _T("software\\microsoft\\internet explorer\\toolbar\\shellbrowser\\");
const LPCTSTR ACTMON_TOOLBAR_KEY3_X64	= _T("software\\wow6432node\\microsoft\\internet explorer\\toolbar\\shellbrowser\\");
const LPCTSTR ACTMON_TOOLBAR_KEY4		= _T("software\\microsoft\\internet explorer\\toolbar\\explorer\\");
const LPCTSTR ACTMON_TOOLBAR_KEY4_X64	= _T("software\\wow6432node\\microsoft\\internet explorer\\toolbar\\explorer\\");
const LPCTSTR ACTMON_USERINIT_KEY		= _T("software\\microsoft\\windows nt\\currentversion\\winlogon\\userinit#@#");
const LPCTSTR ACTMON_USERINIT_KEY_X64	= _T("software\\wow6432node\\microsoft\\windows nt\\currentversion\\winlogon\\userinit#@#");
const LPCTSTR ACTMON_WINLOGON_KEY		= _T("software\\microsoft\\windows nt\\currentversion\\winlogon\\notify\\");
const LPCTSTR ACTMON_WINLOGON_KEY_X64	= _T("software\\wow6432node\\microsoft\\windows nt\\currentversion\\winlogon\\notify\\");
const LPCTSTR ACTMON_WIN_POL_SYS_KEY	= _T("software\\microsoft\\windows\\currentversion\\policies\\system\\");
const LPCTSTR ACTMON_WIN_POL_SYS_KEY_X64= _T("software\\wow6432node\\microsoft\\windows\\currentversion\\policies\\system\\");
const LPCTSTR ACTMON_WIN_POL_EXP_KEY	= _T("software\\microsoft\\windows\\currentversion\\policies\\explorer\\");
const LPCTSTR ACTMON_WIN_POL_EXP_KEY_X64= _T("software\\wow6432node\\microsoft\\windows\\currentversion\\policies\\explorer\\");
const LPCTSTR ACTMON_COOKIE_KEY			= _T("software\\microsoft\\windows\\currentversion\\internet settings\\p3p\\history\\");
const LPCTSTR ACTMON_COOKIE_KEY_X64		= _T("software\\wow6432node\\microsoft\\windows\\currentversion\\internet settings\\p3p\\history\\");
const LPCTSTR ACTMON_INET_SETTING_KEY	= _T("software\\microsoft\\windows\\currentversion\\internet settings");
const LPCTSTR ACTMON_INET_SETTING_KEY_X64	= _T("software\\wow6432node\\microsoft\\windows\\currentversion\\internet settings");
const LPCTSTR ACTMON_PRIVACY_ADV_VAL	= _T("PrivacyAdvanced");
const LPCTSTR ACTMON_ZONES_3_KEY		= _T("software\\microsoft\\windows\\currentversion\\internet settings\\zones\\3");
const LPCTSTR ACTMON_THIRD_PARTY_KEY	= _T("{A8A88C49-5EB2-4990-A1A2-0876022C854F}");
const LPCTSTR ACTMON_ACTIVEX_KEY		= _T("software\\microsoft\\internet explorer\\activex compatibility\\");
const LPCTSTR ACTMON_ACTIVEX_KEY_X64	= _T("software\\wow6432node\\microsoft\\internet explorer\\activex compatibility\\");
const LPCTSTR ACTMON_COMP_FLAG_VAL		= _T("Compatibility Flags");
const LPCTSTR ACTMON_RESTRICTED_SITE_KEY= _T("software\\microsoft\\windows\\currentversion\\internet settings\\zonemap\\domains\\");
const LPCTSTR ACTMON_RESTRICTED_SITE_VAL= _T("*");
const LPCTSTR ACTMON_APPINITDLL_KEY_ONLY= _T("software\\microsoft\\windows nt\\currentversion\\windows");
const LPCTSTR ACTMON_APPINITDLL_KEY_ONLY_X64 = _T("software\\wow6432node\\microsoft\\windows nt\\currentversion\\windows");
const LPCTSTR ACTMON_USERINIT_KEY_ONLY	= _T("software\\microsoft\\windows nt\\currentversion\\winlogon");
const LPCTSTR ACTMON_USERINIT_KEY_ONLY_X64= _T("software\\wow6432node\\microsoft\\windows nt\\currentversion\\winlogon");
const LPCTSTR ACTMON_SHELL_KEY_ONLY		= _T("software\\microsoft\\windows nt\\currentversion\\winlogon\\shell");
const LPCTSTR ACTMON_SHELL_KEY_ONLY_X64	= _T("software\\wow6432node\\microsoft\\windows nt\\currentversion\\winlogon\\shell");
const LPCTSTR ACTMON_STARTPAGE_KEY_ONLY	= _T("software\\microsoft\\internet explorer\\main");
const LPCTSTR ACTMON_HOST_FILE_XP		= _T("\\windows\\system32\\drivers\\etc\\hosts");
const LPCTSTR ACTMON_HOST_FILE_2K		= _T("\\winnt\\system32\\drivers\\etc\\hosts");
const LPCTSTR ACTMON_DESKTOP_BG_KEY		= _T("control panel\\desktop\\wallpaper#@#");
const LPCTSTR ACTMON_DESKTOP_BG_FILE_VISTA	= _T("\\appdata\\local\\microsoft\\wallpaper1.bmp");
const LPCTSTR ACTMON_DESKTOP_BG_FILE_XP		= _T("\\local settings\\application data\\microsoft\\wallpaper1.bmp");
const LPCTSTR ACTMON_FILE_ASSOCIATION_KEY1	= _T("software\\classes\\exe");
const LPCTSTR ACTMON_FILE_ASSOCIATION_KEY2	= _T("software\\classes\\.exe");
const LPCTSTR ACTMON_FILE_ASSOCIATION_KEY3	= _T("software\\wow6432node\\classes\\exe");
const LPCTSTR ACTMON_FILE_ASSOCIATION_KEY4	= _T("software\\wow6432node\\classes\\.exe");

const LPCTSTR ACTMON_SEARCHPAGE_KEY		= _T("software\\microsoft\\internet explorer\\main\\search page#@#");
const LPCTSTR ACTMON_SEARCHPAGE_KEY_X64	= _T("software\\wow6432node\\microsoft\\internet explorer\\main\\search page#@#");
const LPCTSTR ACTMON_REDIRECTCACHE_KEY		= _T("software\\microsoft\\internet explorer\\main\\start page redirect cache#@#");
const LPCTSTR ACTMON_REDIRECTCACHE_KEY_X64	= _T("software\\wow6432node\\microsoft\\internet explorer\\main\\start page redirect cache#@#");
const LPCTSTR ACTMON_DEFAULTPAGEURL_KEY		= _T("software\\microsoft\\internet explorer\\main\\default_page_url#@#");
const LPCTSTR ACTMON_DEFAULTPAGEURL_KEY_X64	= _T("software\\wow6432node\\microsoft\\internet explorer\\main\\default_page_url#@#");
const LPCTSTR ACTMON_DEFAULTSEARCHURL_KEY		= _T("software\\microsoft\\internet explorer\\main\\default_search_url#@#");
const LPCTSTR ACTMON_DEFAULTSEARCHURL_KEY_X64	= _T("software\\wow6432node\\microsoft\\internet explorer\\main\\default_search_url#@#");

const LPCTSTR ACTMON_STARTMENU_KEY		= _T("software\\clients\\startmenuinternet\\");
const LPCTSTR ACTMON_STARTMENU_KEY_X64		= _T("software\\wow6432node\\clients\\startmenuinternet\\");


typedef BOOL (CALLBACK *ACTMON_MESSAGEPROCHANDLER)(int, LPCTSTR, LPCTSTR,LPCTSTR, LPVOID);

#define MAX_KEEPALIVE_TIMEOUT		30000   

static const int Add_Entry = 1;
static const int Delete_Entry = 2;
enum EnumLiveUpdateEntryType
{
    Entry_Type_Cookie = 1,
    Entry_Type_File,
    Entry_Type_BinaryFile,
    Entry_Type_ExecutableFile,
    Entry_Type_Folder,
    Entry_Type_BHO,
    Entry_Type_Toolbar,
    Entry_Type_STS,
    Entry_Type_SSODL,
    Entry_Type_StartUp,
    Entry_Type_AppInit_DLLs,
    Entry_Type_Notify,
    Entry_Type_Services,
    Entry_Type_RegKey,
    Entry_Type_RegValue,
    Entry_Type_ActiveX,
    Entry_Type_MenuExt,
    Entry_Type_EPSignature,
    Entry_Type_MD5Signature,
    Entry_Type_SpyName,
    Entry_Type_SharedDll,
    Entry_Type_ShellExecHook,
	Entry_Type_SystemFiles

};

typedef enum _tagRegistryRestrictions
{
	eRES_TaskMgr,
	eRES_Property,
	eRES_Password,
	eRES_LockComp,
	eRES_RegEdit,
	eRES_Search,
	eRES_Shutdown,
	eRES_TaskBarClk,
	eRES_Run,
	eRES_CtrlPnl,
	eRES_Cmd,
	eRES_ExeAssoc,
	eRES_LnkAssoc,
	eRES_RegAssoc,
	eRES_TotalCount			           
}REG_RES_OPT;
typedef struct NETCRED
{
	TCHAR szUsername[260];
	TCHAR szPassword[260];
}NETCREDDATA,*LPNETCREDDATA;

const int REG_RES_GET_OPT = 1001;
const int REG_RES_SET_OPT = 1002;

#define	PASSWORD_THREAT_COMM			_T("mAx5#Cu8$")


enum CustomSettings
{
	ShowActMonNotification,
	CleanTempRecycleFiles,
	CleanTempInternetFiles,
	AutoLiveUpdate,
	LiveUpdateReminder,
	DontQuarantineBackup
};

enum AdvanceSettings
{
	WindowStartScan,
	SkipCompressFile,
	ProtectSysRegistry,
	CopyProtection,
	BlockReplicatingPattern,
	AutoQuarantine,
	CleanBroswer,
	HeuristicScanML,
	CookiesScan,
	EnableGamingMode,
	ActiveMonitor
};


enum ScanActionStatus
{
	None,
	Cleaned,
	Repaired
};

enum PasswordManagerSettings
{
	Password_USBManager,
	Password_WhiteList,
	Password_Uninstall
};

typedef struct ScanStatusData
{
	int iMessageId;
	int iPercentage;
	DWORD dwFilesCount;
	DWORD dwThreatCount;
	WCHAR szData[1024];
}UScanStatusData;

typedef struct ScanStartInfo
{
	int iMessageId;								//Launch Condition of scanner Scheduler, autoscan(quick scan) or user click
	int iScanType;								//Quick scan, full scan, custom scan
	int iDeepScan;								//Deep scan is ON/OFF
	int iCriticalScan;							//Critical scan is ON/OFF
	int iShutdownFinish;						//Shutdown system after scan is complete
	WCHAR szPath[MAX_PATH];						//Scan path
}UScanStartInfo, * LPUScanStartInfo;

typedef struct ScanUIReport
{
	DWORD dwIndex;								//Index of report structure in memory
	int iMessageId;								//Scan Message type (File, Process, Virus, Registry)
	int iActionStatus;							//Action on detected files(Detected, Cleaned etc) 
	WCHAR szSpyName[MAX_PATH];					//Spyware Name
	WCHAR szPath[MAX_PATH];						// File or registry path
}UScanUIReport;

typedef void(CALLBACK* SENDTDSSMESSAGETOULTRAUI)(UScanStatusData objData);
typedef void(CALLBACK* SENDDETECTIONTOULTRAUI)(UScanUIReport objUScannerUIReport);

typedef struct ScanSchedulerData
{
	int iScanSchStatus;						//If scan scheduler is set or not
	int iScanOption;						//Scan option quick or full
	int iDeepScan;							//Deep scan option
	int iScanFreq;							//Scan frequency daily, weekly, hourly or minutes
	int iDay;								//Day of the week or daily
	int iHrMins;								//Hours and minutes of scheduler
	int iAction;								//Action on detected files(Log only, Cleaned) 
	int iShutdownAction;						//Action after scan is done(0= None, 1= shutdown, 2= logoff) 
	WCHAR szSchTime[9];							//Scheduler Time
	WCHAR szPath[MAX_PATH];						// Scan path
}UScanSchedulerData, *LPUScanSchedulerData;

typedef struct ScanGraphInfo
{
	DWORD dwThreatCount;										//Threat counts
	WCHAR szDate[100];										//Date 
}UScanGraphInfo, * LPUScanGraphInfo;

enum enScheduleType { DAILYSCAN = 8, HOURLYSCAN, MINUTESSCAN };

typedef struct FullScanReport
{
	int iScannerType;								//Scan type: 0: On Demand, 1: Actmon
	int iActionStatus;								//Scan Action Status: Detected, Quarantine, Repaired etc.
	DWORD dwSpyID;									//Spyware id from DB
	int iTypeOfEntry;								//Entry type of detected file
	WCHAR szSpyName[MAX_PATH];						//Spyware Name
	WCHAR szDateTime[100];							//Scan Time
	WCHAR szPath[MAX_PATH];							//Detected path
}UFullScanReport, * LPUFullScanReport;

typedef struct FullScanReportLink
{
	UFullScanReport objFullScanReport;								//FullScanReport 
	FullScanReportLink* pLinkNode;									//Path of Next linklist
}UFullScanReportLink, * LPUFullScanReportLink;

enum ScanFullReportType 
{	OnDemand=0,										//Detected by Scanner
	Actmon											//Detected by Actmon
};
enum ScanCurrentStatus
{
	Stop = 0,										//Scanner is stop
	Scanning,										//Scanner is running
	Pause,											//Scanner is paused
	NoScanner,										//No scanner found in memory
	Quarantine,										//Quarantine is going on
	Nothing											//Initial status when nothing is going on
};

enum REGISTRATION_STATUS
{
	STATUS_UNREGISTERED_COPY = 0,	// 0 = unregistered copy
	STATUS_REGISTERED_COPY = 1,	// 1 = registered copy
	STATUS_SUBSCRIPTION_EXPIRED = 2		// 2 = subscription expired
};

