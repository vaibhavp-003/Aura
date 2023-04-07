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
	MAXSIZE_03 = 3,
	MAXSIZE_04 = 4,
	MAXSIZE_05 = 5,
	MAXSIZE_06 = 6,
	MAXSIZE_07 = 7,
	MAXSIZE_08 = 8,
	MAXSIZE_09 = 9,
	MAXSIZE_10 = 10,
	MAXSIZE_11 = 11,
	MAXSIZE_12 = 12,
	MAXSIZE_13 = 13,
	MAXSIZE_14 = 14,
	MAXSIZE_15 = 15,
	MAXSIZE_16 = 16,
	MAXSIZE_17 = 17,
	MAXSIZE_18 = 18,
	MAXSIZE_19 = 19,
	MAXSIZE_20 = 20,
	MAXSIZE_21 = 21,
	MAXSIZE_22 = 22,
	MAXSIZE_23 = 23,
	MAXSIZE_24 = 24,
	MAXSIZE_25 = 25,
	MAXSIZE_26 = 26,
	MAXSIZE_27 = 27,
	MAXSIZE_28 = 28,
	MAXSIZE_29 = 29,
	MAXSIZE_30 = 30,
	MAXSIZE_31 = 31,
	MAXSIZE_32 = 32,
	MAXSIZE_33 = 33,
	MAXSIZE_34 = 34,
	MAXSIZE_35 = 35,
	MAXSIZE_36 = 36,
	MAXSIZE_37 = 37,
	MAXSIZE_38 = 38,
	MAXSIZE_39 = 39,
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
	static MaxSizes Get15Size(MaxFonts eMaxFont);
	static MaxSizes Get16Size(MaxFonts eMaxFont);
	static MaxSizes Get17Size(MaxFonts eMaxFont);
	static MaxSizes Get18Size(MaxFonts eMaxFont);
	static MaxSizes Get19Size(MaxFonts eMaxFont);
	static MaxSizes Get20Size(MaxFonts eMaxFont);
	static MaxSizes Get21Size(MaxFonts eMaxFont);
	static MaxSizes Get22Size(MaxFonts eMaxFont);
	static MaxSizes Get23Size(MaxFonts eMaxFont);
	static MaxSizes Get24Size(MaxFonts eMaxFont);
	static MaxSizes Get25Size(MaxFonts eMaxFont);
	static MaxSizes Get26Size(MaxFonts eMaxFont);
	static MaxSizes Get27Size(MaxFonts eMaxFont);
	static MaxSizes Get28Size(MaxFonts eMaxFont);
	static MaxSizes Get29Size(MaxFonts eMaxFont);
	static MaxSizes Get30Size(MaxFonts eMaxFont);
	static MaxSizes Get31Size(MaxFonts eMaxFont);
	static MaxSizes Get32Size(MaxFonts eMaxFont);
	static MaxSizes Get33Size(MaxFonts eMaxFont);
	static MaxSizes Get34Size(MaxFonts eMaxFont);
	static MaxSizes Get12Size(MaxFonts eMaxFont);
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
	static CMaxFont* GetBoldSize15Font();
	static CMaxFont* GetNormalSize15Font();
	static CMaxFont* GetBoldSize16Font();
	static CMaxFont* GetNormalSize16Font();
	static CMaxFont* GetBoldSize17Font();
	static CMaxFont* GetNormalSize17Font();
	static CMaxFont* GetBoldSize18Font();
	static CMaxFont* GetNormalSize18Font();
	static CMaxFont* GetBoldSize19Font();
	static CMaxFont* GetNormalSize19Font();
	static CMaxFont* GetBoldSize20Font();
	static CMaxFont* GetNormalSize20Font();
	static CMaxFont* GetBoldSize21Font();
	static CMaxFont* GetNormalSize21Font();
	static CMaxFont* GetBoldSize22Font();
	static CMaxFont* GetNormalSize22Font();
	static CMaxFont* GetBoldSize23Font();
	static CMaxFont* GetNormalSize23Font();
	static CMaxFont* GetBoldSize24Font();
	static CMaxFont* GetNormalSize24Font();
	static CMaxFont* GetBoldSize25Font();
	static CMaxFont* GetNormalSize25Font();
	static CMaxFont* GetBoldSize26Font();
	static CMaxFont* GetNormalSize26Font();
	static CMaxFont* GetBoldSize27Font();
	static CMaxFont* GetNormalSize27Font();
	static CMaxFont* GetBoldSize28Font();
	static CMaxFont* GetNormalSize28Font();
	static CMaxFont* GetBoldSize29Font();
	static CMaxFont* GetNormalSize29Font();
	static CMaxFont* GetBoldSize30Font();
	static CMaxFont* GetNormalSize30Font();

	static CMaxFont* GetBoldSize15UnderLineFont();
	static CMaxFont* GetNormalSize15UnderLineFont();

	static CMaxFont* GetBoldSize18UnderLineFont();
	static CMaxFont* GetNormalSize18UnderLineFont();

	static CMaxFont* GetBoldSize31Font();
	static CMaxFont* GetNormalSize31Font();
	static CMaxFont* GetBoldSize32Font();
	static CMaxFont* GetNormalSize32Font();
	static CMaxFont* GetBoldSize33Font();
	static CMaxFont* GetNormalSize33Font();
	static CMaxFont* GetBoldSize34Font();
	static CMaxFont* GetNormalSize34Font();

	static CMaxFont* GetNormalSize12Font();


};
