/*======================================================================================
FILE             : TextSpeaker.h
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
#pragma once
#pragma warning(disable : 4995)

#ifndef GDS_TEXTSPEAKER_H_INCLUDED
#define GDS_TEXTSPEAKER_H_INCLUDED

#include <sapi.h>               // SAPI
#include <sphelper.h>           // SAPI Helper

//#include "ComAutoInit.h"        // COM auto initializer
#include "atlstr.h"


namespace gds {

class CTextSpeaker
{

public:

	CTextSpeaker();
	~CTextSpeaker();
	bool InitializeCOM();
	void Speak(const CString  &csTextToSpeak); 
	void DeInitializeCOM();

private:

    CTextSpeaker(const CTextSpeaker &);
    CTextSpeaker & operator=(const CTextSpeaker &);


private:

	// COM initialization and cleanup (must precede other COM related data members)
	//gds::CComAutoInit m_comInit;

	// Text to speech engine
	CComPtr<ISpVoice> m_tts;

	// Default voice token
	CComPtr<ISpObjectToken> m_voiceToken;

};


} // namespace gds

#endif // GDS_TEXTSPEAKER_H_INCLUDED
