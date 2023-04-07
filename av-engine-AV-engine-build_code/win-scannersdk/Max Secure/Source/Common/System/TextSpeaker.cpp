/*======================================================================================
FILE             : TextSpeaker.cpp
ABSTRACT         : defines a class to speak some text
DOCUMENTS	     : 
AUTHOR		     : Siddharam Pujari
COMPANY		     : Aura 
COPYRIGHT(NOTICE): 
				  (C) Aura
				  Created as an unpublished copyright work.  All rights reserved.
				  This document and the information it contains is confidential and
				  proprietary to Aura.  Hence, it may not be 
				  used, copied, reproduced, transmitted, or stored in any form or by any 
				  means, electronic, recording, photocopying, mechanical or otherwise, 
				  without the prior written permission of Aura.	
				  
CREATION DATE    : 25/4/2012
NOTES		     : 
VERSION HISTORY  : 
======================================================================================*/
#include "stdafx.h"
#include "TextSpeaker.h"

using namespace gds;
CTextSpeaker::CTextSpeaker()
{
	
}

CTextSpeaker::~CTextSpeaker()
{
	// Nothing to do here.
	// Automatic cleanup thanks to C++ RAII is fine :-)
}


void CTextSpeaker::Speak(const CString &csTextToSpeak)
{
	if(!InitializeCOM())
	{
		AddLogEntry(L"InitializeCOM Failed");
		::CoUninitialize();
		//ATLTRACE(TEXT("Empty text passed to CTextSpeaker::Speak().\n"));
		//AtlThrow(E_INVALIDARG);
		return;
	}
	//
	// Input text must not be empty
	//
	if (csTextToSpeak.IsEmpty())
	{
		AddLogEntry(L"Empty text passed to CTextSpeaker::Speak()");
		::CoUninitialize();
		//ATLTRACE(TEXT("Empty text passed to CTextSpeaker::Speak().\n"));
		//AtlThrow(E_INVALIDARG);
		return;
	}

	//
	// Speak input text
	//
	ULONG ulstreamNumber;
	HRESULT hr = m_tts->Speak(
		csTextToSpeak, 
		SPF_IS_NOT_XML | SPF_DEFAULT | SPF_PURGEBEFORESPEAK, 
		&ulstreamNumber);
	
	if (FAILED(hr))
	{
		AddLogEntry(L"CTextSpeaker::Speak() failed");
		//ATLTRACE(TEXT("Speak failed.\n"));
		//AtlThrow(hr);
	}
	//::CoUninitialize();
}

bool CTextSpeaker::InitializeCOM()
{
	HRESULT hr = ::CoInitialize(NULL);
	if (FAILED(hr))
	{
		AddLogEntry(L"CoInitialize() failed in CComAutoInit constructor");
		//ATLTRACE(TEXT("CoInitialize() failed in CComAutoInit constructor (hr=0x%08X).\n"), hr);
		//AtlThrow(hr);
		return false;
	}
	//
	// Create text to speech engine
	//
	hr = m_tts.CoCreateInstance(CLSID_SpVoice);
	if (FAILED(hr))
	{
		AddLogEntry(L"Text-to-speech creation failed");
		//ATLTRACE(TEXT("Text-to-speech creation failed.\n"));
		//AtlThrow(hr);
		return false;
	}

	//
	// Get token corresponding to default voice 
	//
	hr = SpGetDefaultTokenFromCategoryId(SPCAT_VOICES, &m_voiceToken, FALSE);
	if (FAILED(hr))
	{
		AddLogEntry(L"Can't get default voice token");
		//ATLTRACE(TEXT("Can't get default voice token.\n"));
		//AtlThrow(hr);
		return false;
	}

	//
	// Set default voice
	//
	hr = m_tts->SetVoice(m_voiceToken);
	if (FAILED(hr))
	{
		AddLogEntry(L"Can't set default voice");
		//ATLTRACE(TEXT("Can't set default voice.\n"));
		//AtlThrow(hr);
		return false;
	}
	return true;
}

void CTextSpeaker::DeInitializeCOM()
{
	
}