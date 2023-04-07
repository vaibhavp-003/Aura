#pragma once


class CChromePreference
{

	public:
			bool RemoveUrl(void);
			CChromePreference(void);
			~CChromePreference(void);
			void ResetMozillaUsingPrefJS();
			bool EnumrateAndRenameFolder(CString csFolderPath,bool bRenameFile,bool bDeleteFile = false);
			bool	RemoveToolbarFromMozilla();
			bool	RemoveToolbarFromChrome();
			bool	EnumrateAndRenameRegKey(CString csToolPath,HKEY HiveRoot);
			void	RemoveExtensionFromChrome();
			void	RemoveCommandLine();
			bool	RenameSecurePreference();
			
			bool RenamePrefsJS();
			bool EnumrateRegKey(CString csKey,HKEY HiveRoot);
			bool SetToDefaultIE(CString csUsers,HKEY HiveRoot);
			void CleanBrowsers();
			int GetIEVersion();
			void CleanOpera();
			void RenameOperaPrefsJS();
			void CheckInstalledBrowsers();

			CString m_csFilePath;
			int		m_nRegistryValueCount;
			bool m_bCleanIE;
			bool m_bCleanChrome;
			bool m_bCleanFireFox;
			bool m_bCleanOpera;
};