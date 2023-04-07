#pragma once

enum MaxTypeofFont
{
	NormalFont,
	PointFont
};

enum MaxFonts
{
	OSFONT,
	ARIAL,
	MICROSOFT_SANS_SERIF,
	VERDANA,
	TAHOMA,
	CRYSTAL,
	NEW_TIMES_ROMAN,
	COURIER_NEW,
	ENGLISH_FONT,
	GERMAN,
	FRENCH_FONT,
	SPANISH,
	RUSSIAN,
	JAPANESE_FONT,
	HINDI,
	MARATHI,
	GUJRATI,
	TELGU,
	TAMIL,
	KANNADA,
	BENGALA,
	CHINISE_S,
	CHINISE_T,
	GREEK
};

enum MaxSizes
{
	MAXSIZE_NEG18 = -18,
	MAXSIZE_NEG17 = -17,
	MAXSIZE_NEG16 = -16,
	MAXSIZE_NEG15 = -15,
	MAXSIZE_NEG14 = -14,
	MAXSIZE_NEG12 = -12,
	MAXSIZE_NEG11 = -11,
	MAXSIZE_01 = 1,
	MAXSIZE_02 = 2,
	MAXSIZE_04 = 4,
	MAXSIZE_06 = 6,
	MAXSIZE_08 = 8,
	MAXSIZE_11 = 11,
	MAXSIZE_12 = 12,
	MAXSIZE_13 = 13,
	MAXSIZE_14 = 14,
	MAXSIZE_15 = 15,
	MAXSIZE_16 = 16,
	MAXSIZE_17 = 17,
	MAXSIZE_18 = 18,
	MAXSIZE_20 = 20,
	MAXSIZE_21 = 21,
	MAXSIZE_22 = 22,
	MAXSIZE_24 = 24,
	MAXSIZE_28 = 28,
	MAXSIZE_34 = 34,
	MAXSIZE_40 = 40,
	MAXSIZE_80 = 80,
	MAXSIZE_100 = 100,
	MAXSIZE_110 = 110,
	MAXSIZE_120 = 120,
	MAXSIZE_130 = 130,
	MAXSIZE_140 = 140,
	MAXSIZE_150 = 150,
	MAXSIZE_DONTCARE = 0
};

enum MaxWeight
{
	Normal,
	Bold,
	Italic
};

class CMaxFont : public CFont
{
	CMaxFont(MaxFonts eMaxFont);

	MaxFonts m_eMaxFont;

	LONG GetWeight(MaxWeight eMaxWeight);
	CString GetFontName(MaxFonts eMaxFont);
	BOOL CreateMaxFont(MaxFonts eMaxFont, MaxSizes eMaxSize, MaxWeight eMaxWeight, MaxTypeofFont eMaxTypeofFont, BOOL bUnderline);
	BOOL IsFontInstalled(CString csFontName, MaxWeight eMaxWeight=Normal);
	MaxFonts GetAlternativeFont();
	static MaxSizes GetNormalSize(MaxFonts eMaxFont);
	static MaxSizes GetBigControlSize(MaxFonts eMaxFont);
	static MaxSizes GetBigButtonSize(MaxFonts eMaxFont);
	static MaxSizes GetInnerBoldSize(MaxFonts eMaxFont);
	static MaxSizes GetTitleSize(MaxFonts eMaxFont);
	static int m_iCurrentLanguage;
	static DWORD m_dwDPI;
	static CString m_csOS;
public:
	~CMaxFont();
	
	static CMaxFont* GetMaxFont(MaxFonts eMaxFont, MaxSizes eMaxSize, MaxWeight eMaxWeight = Normal, MaxTypeofFont eMaxTypeofFont=NormalFont, BOOL bUnderline=FALSE);
	static MaxFonts GetLanguageEnum(DWORD dwLangCode);
	static void SetCurrentLanguage(int iLanguageID);
	static CMaxFont* GetControlsFont();
	static CMaxFont* GetBigControlsFont();
	static CMaxFont* GetBigControlsBoldFont();
	static CMaxFont* GetTitleFont();
	static CMaxFont* GetButtonFont();
	static CMaxFont* GetBigButtonFont();
	static CMaxFont* GetNumbersNormalFont();
	static CMaxFont* GetNumbersBoldFont();
	static CMaxFont* GetOptionTabBtnFont();
	static CMaxFont* GetInnerBoldFont();
	static void GetNewsParams(CString &csFontName, int &iHeight);
	static void GetFixIssuesFontParams(CString &csFontName, int &iHeight);
	static CMaxFont* GetWebLinkFont();
	static CMaxFont* GetEnglishOnlyFont();
	static CMaxFont* GetItalicBoldUnderlineFont();
	static CMaxFont* GetBoldFont();
	static CMaxFont* GetUnderlineFont();
	static CMaxFont* GetFeatureLockedTitleFont();
	static CMaxFont* GetFeatureLockedSubTitleFont();
	static CMaxFont* GetControlsSmallFont();
	static CMaxFont* GetButtonUnderlineFont();
	static CMaxFont* GetNormalWarningFont();
	static CMaxFont* GetBigWarningFont();

};
