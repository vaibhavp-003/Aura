/*
 * aPLib compression library  -  the smaller the better :)
 *
 * C safe depacker, header file
 *
 * Copyright (c) 1998-2009 by Joergen Ibsen / Jibz
 * All Rights Reserved
 *
 * http://www.ibsensoftware.com/
 */

#ifndef DEPACKS_H_INCLUDED
#define DEPACKS_H_INCLUDED

#ifdef __cplusplus
extern "C" {
#endif

#ifndef APLIB_ERROR
# define APLIB_ERROR (-1)
#endif

#if (!defined(__cplusplus)) 
  typedef enum { false, true } bool;
#endif

/* function prototype */
unsigned int aP_depack_safe(const void *source,
                            unsigned int srclen,
                            void *destination,
                            unsigned int dstlen,
							int iCType,
							unsigned int *ActualSrclen);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* DEPACKS_H_INCLUDED */
