/*======================================================================================
   FILE			: zlib.h 
   ABSTRACT		: zlib file
   DOCUMENTS	: Refer The Design Folder (FastMap Design.Doc)
   AUTHOR		: Dipali Pawar
   COMPANY		: Aura 
   COPYRIGHT NOTICE    :
						(C)Aura:
      					Created as an unpublished copyright work.  All rights reserved.
     					This document and the information it contains is confidential and
      					proprietary to Aura.  Hence, it may not be 
      					used, copied, reproduced, transmitted, or stored in any form or by any 
      					means, electronic, recording, photocopying, mechanical or otherwise, 
      					without the prior written permission of Aura
   CREATION DATE: 1/sep/2007
   NOTES		:
   VERSION HISTORY	:
					Version: 19-jan-08
					Resourec:Darshan
					Description: Added unicode and X64 support
======================================================================================*/
#ifndef _zlib_h
#define _zlib_h


// Configuration symbols that define operation

//SMA : for VS 2005
#define USE_TEMPLATED_STREAMS   // define/undefine to match application
#define HAVE_TEMPLATES            // define if non-MS compiler supports templates

// Diagnostics

// See if this version of compiler supports templates.
#if !defined(HAVE_TEMPLATES) && defined(_WIN32) && defined(_MSC_VER) && _MSC_VER > 1000
    #define HAVE_TEMPLATES
#endif

// Issue message if option conflict.
#if !defined(HAVE_TEMPLATES) && defined(USE_TEMPLATED_STREAMS)
    #error This version of the compiler does not support USE_TEMPLATED_STREAMS
#endif


// Includes

// If using MFC, ensure afx.h included.
#if !defined(NO_MFC) && !defined(__AFX_H__)
    #include "afx.h"
#endif

#ifndef _INC_STDLIB
#include "stdlib.h"
#endif

#ifndef _INC_MALLOC
#include "malloc.h"
#endif

// Standard iostreams were moved from the global namespace to the "std"
// namespace in V5.0.  Define a namespace qualifier as needed.
#if (defined(_MSC_VER) && _MSC_VER >= 1100 && defined(USE_TEMPLATED_STREAMS))
	#define NQ std::			// 5.0 or later, define namespace qualifier
#else
	#define NQ					// prior to 5.0 or non-templated streams
#endif

// VC++ includes two incompatible versions of iostreams.  Templated
// classes require the templated version.
#if defined(USE_TEMPLATED_STREAMS) && defined(HAVE_TEMPLATES)
    #pragma warning(disable:4786)   // complaints about excess name length
    #include "string"
    #include "fstream"
    #include "iostream"
#else
    #ifndef _INC_STRING
    #include "string.h"
    #endif

    #ifndef _INC_IOSTREAM
    #include "iostream.h"
    #endif

    #ifndef _INC_FSTREAM
    #include "fstream.h"
    #endif
#endif

#ifndef _INC_LIMITS
#include "limits.h"
#endif

#ifndef _INC_CTYPE
#include "ctype.h"
#endif

#ifndef _INC_STDIO
#include "stdio.h"
#endif

// Other definitions

// Ensure that POSITION is defined (normally defined in afx.h)
#if !defined(POSITION) && !defined(__AFX_H__)
    typedef void* POSITION;
#endif

// if not using MFC, nullify ASSERT() and TRACE() unless defined by user
#ifndef __AFX_H__
    #ifndef CDECL
        #ifdef WIN32
            #define CDECL
        #else
            #define CDECL _cdecl
        #endif
    #endif
    inline void CDECL nullNULLnUlL(...) { }
    #ifndef ASSERT
        #define ASSERT 1 ? (void)0 : ::nullNULLnUlL
    #endif
    #ifndef TRACE
        #define TRACE 1 ? (void)0 : ::nullNULLnUlL
    #endif
#endif

// define class-export symbols used if built as a library
#ifndef EXT_CLASS
    #ifdef _AFXEXT
        #ifdef AFX_EXT_CLASS
            #define EXT_CLASS   AFX_EXT_CLASS
            #define EXT_API     AFX_EXT_API
            #define EXT_DATA    AFX_EXT_DATA
            #define EXT_DATADEF AFX_EXT_DATADEF
        #else
            #define EXT_CLASS
            #define EXT_API
            #define EXT_DATA
            #define EXT_DATADEF
        #endif
    #else
            #define EXT_CLASS __declspec(dllexport)
            #define EXT_API
            #define EXT_DATA
            #define EXT_DATADEF
    #endif
#endif

// define other symbols used for 16/32 bit compatability
#ifndef _WIN32
    #define HIBIT   0x8000
#else
    #define HIBIT   0x80000000L
#endif

// ONLY FOR TESTING UNDER 16-BIT MFC, DO NOT UNCOMMENT!
// Use MFC storage checking to validate malloc/free/_strdup
/*
#ifdef __AFX_H__
    #ifdef _DEBUG
        #undef malloc
        #undef free
        #undef _strdup
        #undef strdup
        #define malloc(a)   new char [a]
        #define free(a)     delete [] a
        #define _strdup(a)  strcpy(malloc(strlen(a)),a)
        #define strdup(a)  strcpy(malloc(strlen(a)),a)
    #endif
#endif
*/

#endif  // _zlib_h