/*======================================================================================
FILE				: MaxDisassem.cpp
ABSTRACT			: Part of AuAVPMScan.dll module. It is build using Open Source code
DOCUMENTS			: 
AUTHOR				: Tushar Kadam + Vilas Suvarnakar
COMPANY				: Aura 
COPYRIGHT NOTICE	: (C) Aura
					Created as an unpublished copyright work.  All rights reserved.
					This document and the information it contains is confidential and
					proprietary to Aura.  Hence, it may not be 
					used, copied, reproduced, transmitted, or stored in any form or by any 
					means, electronic, recording, photocopying, mechanical or otherwise, 
					without the prior written permission of Aura
CREATION DATE		: 12 Jul 2010
NOTES				: This module disasembles the binary code for scanning based on CPU Instruction without executing.
VERSION HISTORY		: 
=====================================================================================*/
#include "MaxDisassem.h"
#include <ctype.h>
//#include <dir.h>
#include <math.h>
#include <float.h>
#include <stdio.h>
#pragma hdrstop

/*-------------------------------------------------------------------------------------
	Function		: CMaxDisassem
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam + Vilas Suvarnakar
	Description		: Constructor of Class
--------------------------------------------------------------------------------------*/
CMaxDisassem::CMaxDisassem()
{
	InitializeData();
}

/*-------------------------------------------------------------------------------------
	Function		: Scanasm
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam + Vilas Suvarnakar
	Description		: Simple and slightly recursive scanner shared by Assemble(). The scanner is
					 straightforward and ineffective, but high speed is not a must here. As
					 input, it uses global pointer to source line asmcmd. On exit, it fills in
					 global variables scan, prio, sdata, idata and/or fdata. If some error is
					 detected, asmerror points to error message, otherwise asmerror remains
					 unchanged.
--------------------------------------------------------------------------------------*/
void CMaxDisassem::Scanasm(int mode) 
{
  int i,j,base,maxdigit;
  long decimal,hex;
  long double floating,divisor;
  char s[TEXTLEN] = {0},*pcmd;
  
  pcmd = NULL ;
  i = j = base = maxdigit = 0x00 ;
  decimal = hex = 0x00 ;
  floating = divisor = 0 ;
  sdata[0]='\0';
  idata=0;
  if (asmcmd==NULL) {
    asmerror="NULL input line"; scan=SCAN_ERR; return; };
  while (*asmcmd==' ' || *asmcmd=='\t')
    asmcmd++;                          // Skip leading spaces
  if (*asmcmd=='\0' || *asmcmd==';') {
    scan=SCAN_EOL; return; };          // Empty line
  if (isalpha(*asmcmd) || *asmcmd=='_' || *asmcmd=='@') {
    sdata[0]=*asmcmd++; i=1;           // Some keyword or identifier
    while ((isalnum(*asmcmd) || *asmcmd=='_' || *asmcmd=='@') &&
      i<sizeof(sdata))
      sdata[i++]=*asmcmd++;
    if (i>=sizeof(sdata)) {
      asmerror="Too long identifier"; scan=SCAN_ERR; return; };
    sdata[i]='\0';
    while (*asmcmd==' ' || *asmcmd=='\t')
      asmcmd++;                        // Skip trailing spaces
    strcpy_s(s, 256, sdata); _strupr_s(s,256);
    for (j=0; j<=8; j++) {             // j==8 means "any register"
      if (strcmp(s,regname[0][j])!=0) continue;
      idata=j; scan=SCAN_REG8;         // 8-bit register
      return; };
    for (j=0; j<=8; j++) {
      if (strcmp(s,regname[1][j])!=0) continue;
      idata=j; scan=SCAN_REG16;        // 16-bit register
      return; };
    for (j=0; j<=8; j++) {
      if (strcmp(s,regname[2][j])!=0) continue;
      idata=j; scan=SCAN_REG32;        // 32-bit register
      return; };
    for (j=0; j<6; j++) {
      if (strcmp(s,segname[j])!=0) continue;
      idata=j; scan=SCAN_SEG;          // Segment register
      while (*asmcmd==' ' || *asmcmd=='\t')
        asmcmd++;                      // Skip trailing spaces
      return; };
    if (strcmp(s,"ST")==0) {
      pcmd=asmcmd; Scanasm(SA_NAME);   // FPU register
      if (scan!=SCAN_SYMB || idata!='(') {
        asmcmd=pcmd;                   // Undo last scan
        idata=0; scan=SCAN_FPU; return; };
      Scanasm(SA_NAME); j=idata;
      if ((scan!=SCAN_ICONST && scan!=SCAN_DCONST) || idata<0 || idata>7) {
        asmerror="FPU registers have indexes 0 to 7";
        scan=SCAN_ERR; return; };
      Scanasm(SA_NAME);
      if (scan!=SCAN_SYMB || idata!=')') {
        asmerror="Closing parenthesis expected";
        scan=SCAN_ERR; return; };
      idata=j; scan=SCAN_FPU; return; };
    for (j=0; j<=8; j++) {
      if (strcmp(s,fpuname[j])!=0) continue;
      idata=j; scan=SCAN_FPU;          // FPU register (alternative coding)
      return; };
    for (j=0; j<=8; j++) {
      if (strcmp(s,mmxname[j])!=0) continue;
      idata=j; scan=SCAN_MMX;          // MMX register
      return; };
    for (j=0; j<=8; j++) {
      if (strcmp(s,crname[j])!=0) continue;
      idata=j; scan=SCAN_CR;           // Control register
      return; };
    for (j=0; j<=8; j++) {
      if (strcmp(s,drname[j])!=0) continue;
      idata=j; scan=SCAN_DR;           // Debug register
      return; };
    for (j=0; j<sizeof(sizename)/sizeof(sizename[0]); j++) {
      if (strcmp(s,sizename[j])!=0) continue;
      pcmd=asmcmd; Scanasm(SA_NAME);
      if (scan!=SCAN_PTR)              // Fetch non-functional "PTR"
        asmcmd=pcmd;
      idata=j; scan=SCAN_OPSIZE;       // Operand (data) size in bytes
      return; };
    if (strcmp(s,"EIP")==0) {          // Register EIP
      scan=SCAN_EIP; idata=0; return; };
    if (strcmp(s,"SHORT")==0) {        // Relative jump has 1-byte offset
      scan=SCAN_JMPSIZE; idata=1; return; };
    if (strcmp(s,"LONG")==0) {         // Relative jump has 4-byte offset
      scan=SCAN_JMPSIZE; idata=2; return; };
    if (strcmp(s,"NEAR")==0) {         // Jump within same code segment
      scan=SCAN_JMPSIZE; idata=4; return; };
    if (strcmp(s,"FAR")==0) {          // Jump to different code segment
      scan=SCAN_JMPSIZE; idata=8; return; };
    if (strcmp(s,"LOCAL")==0 && *asmcmd=='.') {
      asmcmd++;
      while (*asmcmd==' ' || *asmcmd=='\t')
        asmcmd++;                      // Skip trailing spaces
      if (!isdigit(*asmcmd)) {
        asmerror="Integer number expected";
        scan=SCAN_ERR; return; };
      while (isdigit(*asmcmd))         // LOCAL index is decimal number!
        idata=idata*10+(*asmcmd++)-'0';
      scan=SCAN_LOCAL; return; };
    if (strcmp(s,"ARG")==0 && *asmcmd=='.') {
      asmcmd++;
      while (*asmcmd==' ' || *asmcmd=='\t')
        asmcmd++;                      // Skip trailing spaces
      if (!isdigit(*asmcmd)) {
        asmerror="Integer number expected";
        scan=SCAN_ERR; return; };
      while (isdigit(*asmcmd))         // ARG index is decimal number!
        idata=idata*10+(*asmcmd++)-'0';
      scan=SCAN_ARG; return; };
    if (strcmp(s,"REP")==0) {
      scan=SCAN_REP; return; };        // REP prefix
    if (strcmp(s,"REPE")==0 || strcmp(s,"REPZ")==0) {
      scan=SCAN_REPE; return; };       // REPE prefix
    if (strcmp(s,"REPNE")==0 || strcmp(s,"REPNZ")==0) {
      scan=SCAN_REPNE; return; };      // REPNE prefix
    if (strcmp(s,"LOCK")==0) {
      scan=SCAN_LOCK; return; };       // LOCK prefix
    if (strcmp(s,"PTR")==0) {
      scan=SCAN_PTR; return; };        // PTR in MASM addressing statements
    if (strcmp(s,"CONST")==0 || strcmp(s,"OFFSET")==0) {
      scan=SCAN_OFS; return; };        // Present but undefined offset/constant
    if (strcmp(s,"SIGNED")==0) {
      scan=SCAN_SIGNED; return; };     // Keyword "SIGNED" (in expressions)
    if (strcmp(s,"UNSIGNED")==0) {
      scan=SCAN_UNSIGNED; return; };   // Keyword "UNSIGNED" (in expressions)
    if (strcmp(s,"CHAR")==0) {
      scan=SCAN_CHAR; return; };       // Keyword "CHAR" (in expressions)
    if (strcmp(s,"FLOAT")==0) {
      scan=SCAN_FLOAT; return; };      // Keyword "FLOAT" (in expressions)
    if (strcmp(s,"DOUBLE")==0) {
      scan=SCAN_DOUBLE; return; };     // Keyword "DOUBLE" (in expressions)
    if (strcmp(s,"FLOAT10")==0) {
      scan=SCAN_FLOAT10; return; };    // Keyword "FLOAT10" (in expressions)
    if (strcmp(s,"STRING")==0) {
      scan=SCAN_STRING; return; };     // Keyword "STRING" (in expressions)
    if (strcmp(s,"UNICODE")==0) {
      scan=SCAN_UNICODE; return; };    // Keyword "UNICODE" (in expressions)
    if (strcmp(s,"MSG")==0) {
      scan=SCAN_MSG; return; };        // Pseudovariable MSG (in expressions)
    if (mode & SA_NAME) {
      idata=i; scan=SCAN_NAME;         // Don't try to decode symbolic label
      return; }
    asmerror="Unknown identifier";
    scan=SCAN_ERR; return; }
  else if (isdigit(*asmcmd)) {         // Constant
    base=0; maxdigit=0; decimal=hex=0L; floating=0.0;
    if (asmcmd[0]=='0' && toupper(asmcmd[1])=='X') {
      base=16; asmcmd+=2; };           // Force hexadecimal number
    while (1) {
      if (isdigit(*asmcmd)) {
        decimal=decimal*10+(*asmcmd)-'0';
        floating=floating*10.0+(*asmcmd)-'0';
        hex=hex*16+(*asmcmd)-'0';
        if (maxdigit==0) maxdigit=9;
        asmcmd++; }
      else if (isxdigit(*asmcmd)) {
        hex=hex*16+toupper(*asmcmd++)-'A'+10;
        maxdigit=15; }
      else break; };
    if (maxdigit==0) {
      asmerror="Hexadecimal digits after 0x... expected";
      scan=SCAN_ERR; return; };
    if (toupper(*asmcmd)=='H') {       // Force hexadecimal number
      if (base==16) {
        asmerror="Please don't mix 0xXXXX and XXXXh forms";
        scan=SCAN_ERR; return; };
      asmcmd++;
      idata=hex; scan=SCAN_ICONST;
      while (*asmcmd==' ' || *asmcmd=='\t') asmcmd++;
      return; };
    if (*asmcmd=='.') {                // Force decimal number
      if (base==16 || maxdigit>9) {
        asmerror="Not a decimal number"; scan=SCAN_ERR; return; };
      asmcmd++;
      if (isdigit(*asmcmd) || toupper(*asmcmd)=='E') {
        divisor=1.0;
        while (isdigit(*asmcmd)) {     // Floating-point number
          divisor/=10.0;
          floating+=divisor*(*asmcmd-'0');
          asmcmd++; };
        if (toupper(*asmcmd)=='E') {
          asmcmd++;
          if (*asmcmd=='-') { base=-1; asmcmd++; }
          else base=1;
          if (!isdigit(*asmcmd)) {
            asmerror="Invalid exponent"; scan=SCAN_ERR; return; };
          decimal=0;
          while (isdigit(*asmcmd)) {
            if (decimal<65536L) decimal=decimal*10+(*asmcmd++)-'0'; };
          floating*=floating*10.0+(decimal*base); };
        fdata=floating;
        scan=SCAN_FCONST; return; }
      else {
        idata=decimal; scan=SCAN_DCONST;
        while (*asmcmd==' ' || *asmcmd=='\t') asmcmd++;
        return;
      };
    };
    idata=hex; scan=SCAN_ICONST;       // Default is hexadecimal
    while (*asmcmd==' ' || *asmcmd=='\t') asmcmd++;
    return; }
  else if (*asmcmd=='\'') {            // Character constant
    asmcmd++;
    if (*asmcmd=='\0' || (*asmcmd=='\\' && asmcmd[1]=='\0'))  {
      asmerror="Unterminated character constant"; scan=SCAN_ERR; return; };
    if (*asmcmd=='\'') {
      asmerror="Empty character constant"; scan=SCAN_ERR; return; };
    if (*asmcmd=='\\') asmcmd++;
    idata=*asmcmd++; 
    if (*asmcmd!='\'')  {
      asmerror="Unterminated character constant"; scan=SCAN_ERR; return; };
    asmcmd++;
    while (*asmcmd==' ' || *asmcmd=='\t') asmcmd++;
    scan=SCAN_ICONST; return; }
  else {                               // Any other character or combination
    idata=sdata[0]=*asmcmd++; sdata[1]=sdata[2]='\0';
    if (idata=='|' && *asmcmd=='|') {
      idata='||'; prio=10;             // '||'
      sdata[1]=*asmcmd++; }
    else if (idata=='&' && *asmcmd=='&') {
      idata='&&'; prio=9;              // '&&'
      sdata[1]=*asmcmd++; }
    else if (idata=='=' && *asmcmd=='=') {
      idata='=='; prio=5;              // '=='
      sdata[1]=*asmcmd++; }
    else if (idata=='!' && *asmcmd=='=') {
      idata='!='; prio=5;              // '!='
      sdata[1]=*asmcmd++; }
    else if (idata=='<' && *asmcmd=='=') {
      idata='<='; prio=4;              // '<='
      sdata[1]=*asmcmd++; }
    else if (idata=='>' && *asmcmd=='=') {
      idata='>='; prio=4;              // '>='
      sdata[1]=*asmcmd++; }
    else if (idata=='<' && *asmcmd=='<') {
      idata='<<'; prio=3;              // '<<'
      sdata[1]=*asmcmd++; }
    else if (idata=='>' && *asmcmd=='>') {
      idata='>>'; prio=3;              // '>>'
      sdata[1]=*asmcmd++; }
    else if (idata=='|') prio=8;       // '|'
    else if (idata=='^') prio=7;       // '^'
    else if (idata=='&') prio=6;       // '&'
    else if (idata=='<') {
      if (*asmcmd=='&') {              // Import pseudolabel (for internal use)
        if ((mode & SA_IMPORT)==0) {
          asmerror="Syntax error"; scan=SCAN_ERR; return; };
        asmcmd++; i=0;
        while (*asmcmd!='\0' && *asmcmd!='>') {
          sdata[i++]=*asmcmd++;
          if (i>=sizeof(sdata)) {
            asmerror="Too long import name"; scan=SCAN_ERR; return;
          };
        };
        if (*asmcmd!='>') {
          asmerror="Unterminated import name"; scan=SCAN_ERR; return; };
        asmcmd++; sdata[i]='\0';
        scan=SCAN_IMPORT; return; }
      else prio=4; }                   // '<'
    else if (idata=='>') prio=4;       // '>'
    else if (idata=='+') prio=2;       // '+'
    else if (idata=='-') prio=2;       // '-'
    else if (idata=='*') prio=1;       // '*'
    else if (idata=='/') prio=1;       // '/'
    else if (idata=='%') prio=1;       // '%'
    else if (idata==']') {
      pcmd=asmcmd; Scanasm(SA_NAME);
      if (scan!=SCAN_SYMB || idata!='[') {
        idata=']'; asmcmd=pcmd; prio=0; }
      else {
        idata='+'; prio=2;             // Translate '][' to '+'
      };
    }
    else prio=0;                       // Any other character
    scan=SCAN_SYMB;
    return;
  };
};


/*-------------------------------------------------------------------------------------
	Function		: Parseasmoperand
	In Parameters	: Operand
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Fetches one complete operand from the input line and fills in structure op
					  with operand's data. Expects that first token of the operand is already
					  scanned. Supports operands in generalized form (for example, R32 means any
					  of general-purpose 32-bit integer registers).
--------------------------------------------------------------------------------------*/
void CMaxDisassem::Parseasmoperand(t_asmoperand *op) 
{
  int i,j,bracket,sign,xlataddr;
  int reg,r[9] = {0} ;
  long offset = 0x00 ;

  i = j = bracket = sign = xlataddr = reg = 0x00 ;
  if (scan==SCAN_EOL || scan==SCAN_ERR)
    return;                            // No or bad operand
  // Jump or call address may begin with address size modifier(s) SHORT, LONG,
  // NEAR and/or FAR. Not all combinations are allowed. After operand is
  // completely parsed, this function roughly checks whether modifier is
  // allowed. Exact check is done in Assemble().
  if (scan==SCAN_JMPSIZE) {
    j=0;
    while (scan==SCAN_JMPSIZE) {
      j|=idata;                        // Fetch all size modifiers
      Scanasm(0); };
    if (
      ((j & 0x03)==0x03) ||            // Mixed SHORT and LONG
      ((j & 0x0C)==0x0C) ||            // Mixed NEAR and FAR
      ((j & 0x09)==0x09)               // Mixed FAR and SHORT
    ) {
      asmerror="Invalid combination of jump address modifiers";
      scan=SCAN_ERR; return; };
    if ((j & 0x08)==0) j|=0x04;        // Force NEAR if not FAR
    op->jmpmode=j; };
  // Simple operands are either register or constant, their processing is
  // obvious and straightforward.
  if (scan==SCAN_REG8 || scan==SCAN_REG16 || scan==SCAN_REG32) {
    op->type=REG; op->index=idata;     // Integer general-purpose register
    if (scan==SCAN_REG8) op->size=1;
    else if (scan==SCAN_REG16) op->size=2;
    else op->size=4; }
  else if (scan==SCAN_FPU) {           // FPU register
    op->type=RST; op->index=idata; }
  else if (scan==SCAN_MMX) {           // MMX or 3DNow! register
    op->type=RMX; op->index=idata; }
  else if (scan==SCAN_CR) {            // Control register
    op->type=CRX; op->index=idata; }
  else if (scan==SCAN_DR) {            // Debug register
    op->type=DRX; op->index=idata; }
  else if (scan==SCAN_SYMB && idata=='-') {
    Scanasm(0);                        // Negative constant
    if (scan!=SCAN_ICONST && scan!=SCAN_DCONST && scan!=SCAN_OFS) {
      asmerror="Integer number expected";
      scan=SCAN_ERR; return; };
    op->type=IMM; op->offset=-idata;
    if (scan==SCAN_OFS) op->anyoffset=1; }
  else if (scan==SCAN_SYMB && idata=='+') {
    Scanasm(0);                        // Positive constant
    if (scan!=SCAN_ICONST && scan!=SCAN_DCONST && scan!=SCAN_OFS) {
      asmerror="Integer number expected";
      scan=SCAN_ERR; return; };
    op->type=IMM; op->offset=idata;
    if (scan==SCAN_OFS) op->anyoffset=1; }
  else if (scan==SCAN_ICONST || scan==SCAN_DCONST || scan==SCAN_OFS) {
    j=idata;
    if (scan==SCAN_OFS) op->anyoffset=1;
    Scanasm(0);
    if (scan==SCAN_SYMB && idata==':') {
      Scanasm(0);                      // Absolute long address (seg:offset)
      if (scan!=SCAN_ICONST && scan!=SCAN_DCONST && scan!=SCAN_OFS) {
        asmerror="Integer address expected";
        scan=SCAN_ERR; return; };
      op->type=JMF; op->offset=idata; op->segment=j;
      if (scan==SCAN_OFS) op->anyoffset=1; }
    else {
      op->type=IMM; op->offset=j;      // Constant without sign
      return;                          // Next token already scanned
    }; }
  else if (scan==SCAN_FCONST) {
    asmerror="Floating-point numbers are not allowed in command";
    scan=SCAN_ERR; return; }
  // Segment register or address.
  else if (scan==SCAN_SEG || scan==SCAN_OPSIZE ||
    (scan==SCAN_SYMB && idata=='[')
  ) {                                  // Segment register or address
    bracket=0;
    if (scan==SCAN_SEG) {
      j=idata; Scanasm(0);
      if (scan!=SCAN_SYMB || idata!=':') {
        op->type=SGM; op->index=j;     // Segment register as operand
        return; };                     // Next token already scanned
      op->segment=j; Scanasm(0); };
    // Scan 32-bit address. This parser does not support 16-bit addresses.
    // First of all, get size of operand (optional), segment register (optional)
    // and opening bracket (required).
    while (1) {
      if (scan==SCAN_SYMB && idata=='[') {
        if (bracket) {                 // Bracket
          asmerror="Only one opening bracket allowed";
          scan=SCAN_ERR; return; };
        bracket=1; }
      else if (scan==SCAN_OPSIZE) {
        if (op->size!=0) {             // Size of operand
          asmerror="Duplicated size modifier";
          scan=SCAN_ERR; return; };
        op->size=idata; }
      else if (scan==SCAN_SEG) {
        if (op->segment!=SEG_UNDEF) {  // Segment register
          asmerror="Duplicated segment register";
          scan=SCAN_ERR; return; };
        op->segment=idata; Scanasm(0);
        if (scan!=SCAN_SYMB || idata!=':') {
          asmerror="Semicolon expected";
          scan=SCAN_ERR; return;
        }; }
      else if (scan==SCAN_ERR)
        return;
      else break;                      // None of expected address elements
      Scanasm(0); };
    if (bracket==0) {
      asmerror="Address expression requires brackets";
      scan=SCAN_ERR; return; };
    // Assembling a 32-bit address may be a kind of nigthmare, due to a large
    // number of allowed forms. Parser collects immediate offset in op->offset
    // and count for each register in array r[]. Then it decides whether this
    // combination is valid and determines scale, index and base. Assemble()
    // will use these numbers to select address form (with or without SIB byte,
    // 8- or 32-bit offset, use segment prefix or not). As a useful side effect
    // of this technique, one may specify, for example, [EAX*5] which will
    // correctly assemble to [EAX*4+EAX].
    for (i=0; i<=8; i++) r[i]=0;
    sign='+';                          // Default sign for the first operand
    xlataddr=0;
    while (1) {                        // Get SIB and offset
      if (scan==SCAN_SYMB && (idata=='+' || idata=='-')) {
        sign=idata; Scanasm(0); };
      if (scan==SCAN_ERR) return;
      if (sign=='?') {
        asmerror="Syntax error"; scan=SCAN_ERR; return; };
      // Register AL appears as part of operand of (seldom used) command XLAT.
      if (scan==SCAN_REG8 && idata==REG_EAX) {
        if (sign=='-') {
          asmerror="Unable to subtract register"; scan=SCAN_ERR; return; };
        if (xlataddr!=0) {
          asmerror="Too many registers"; scan=SCAN_ERR; return; };
        xlataddr=1;
        Scanasm(0); }
      else if (scan==SCAN_REG16) {
        asmerror="Sorry, 16-bit addressing is not supported";
        scan=SCAN_ERR; return; }
      else if (scan==SCAN_REG32) {
        if (sign=='-') {
          asmerror="Unable to subtract register"; scan=SCAN_ERR; return; };
        reg=idata; Scanasm(0);
        if (scan==SCAN_SYMB && idata=='*') {
          Scanasm(0);                  // Try index*scale
          if (scan==SCAN_ERR) return;
          if (scan==SCAN_OFS) {
            asmerror="Undefined scale is not allowed"; scan=SCAN_ERR; return; };
          if (scan!=SCAN_ICONST && scan!=SCAN_DCONST) {
            asmerror="Syntax error"; scan=SCAN_ERR; return; };
          if (idata==6 || idata==7 || idata>9) {
            asmerror="Invalid scale"; scan=SCAN_ERR; return; };
          r[reg]+=idata;
          Scanasm(0); }
        else r[reg]++; }               // Simple register
      else if (scan==SCAN_LOCAL) {
        r[REG_EBP]++;
        op->offset-=idata*4;
        Scanasm(0); }
      else if (scan==SCAN_ARG) {
        r[REG_EBP]++;
        op->offset+=(idata+1)*4;
        Scanasm(0); }
      else if (scan==SCAN_ICONST || scan==SCAN_DCONST) {
        offset=idata; Scanasm(0);
        if (scan==SCAN_SYMB && idata=='*') {
          Scanasm(0);                  // Try scale*index
          if (scan==SCAN_ERR) return;
          if (sign=='-') {
            asmerror="Unable to subtract register"; scan=SCAN_ERR; return; };
          if (scan==SCAN_REG16) {
            asmerror="Sorry, 16-bit addressing is not supported";
            scan=SCAN_ERR; return; };
          if (scan!=SCAN_REG32) {
            asmerror="Syntax error"; scan=SCAN_ERR; return; };
          if (offset==6 || offset==7 || offset>9) {
            asmerror="Invalid scale"; scan=SCAN_ERR; return; };
          r[idata]+=offset;
          Scanasm(0); }
        else {
          if (sign=='-') op->offset-=offset;
          else op->offset+=offset;
        }; }
      else if (scan==SCAN_OFS) {
        Scanasm(0);
        if (scan==SCAN_SYMB && idata=='*') {
          asmerror="Undefined scale is not allowed"; scan=SCAN_ERR; return; }
        else {
          op->anyoffset=1;
        }; }
      else break;                      // None of expected address elements
      if (scan==SCAN_SYMB && idata==']') break;
      sign='?';
    };
    if (scan==SCAN_ERR) return;
    if (scan!=SCAN_SYMB || idata!=']') {
      asmerror="Syntax error";
      scan=SCAN_ERR; return; };
    // Process XLAT address separately.
    if (xlataddr!=0) {                 // XLAT address in form [EBX+AX]
      for (i=0; i<=8; i++) {           // Check which registers used
        if (i==REG_EBX) continue;
        if (r[i]!=0) break; };
      if (i<=8 || r[REG_EBX]!=1 || op->offset!=0 || op->anyoffset!=0) {
        asmerror="Invalid address"; scan=SCAN_ERR; return; };
      op->type=MXL; }
    // Determine scale, index and base.
    else {
      j=0;                             // Number of used registers
      for (i=0; i<=8; i++) {
        if (r[i]==0)
          continue;                    // Unused register
        if (r[i]==3 || r[i]==5 || r[i]==9) {
          if (op->index>=0 || op->base>=0) {
            if (j==0) asmerror="Invalid scale";
            else asmerror="Too many registers";
            scan=SCAN_ERR; return; };
          op->index=op->base=i;
          op->scale=r[i]-1; }
        else if (r[i]==2 || r[i]==4 || r[i]==8) {
          if (op->index>=0) {
            if (j<=1) asmerror="Only one register may be scaled";
            else asmerror="Too many registers";
            scan=SCAN_ERR; return; };
          op->index=i; op->scale=r[i]; }
        else if (r[i]==1) {
          if (op->base<0)
            op->base=i;
          else if (op->index<0) {
            op->index=i; op->scale=1; }
          else {
            asmerror="Too many registers";
            scan=SCAN_ERR; return;
          }; }
        else {
          asmerror="Invalid scale"; scan=SCAN_ERR; return; };
        j++;
      };
      op->type=MRG;
    }; }
  else {
    asmerror="Unrecognized operand"; scan=SCAN_ERR; return; };
  // In general, address modifier is allowed only with address expression which
  // is a constant, a far address or a memory expression. More precise check
  // will be done later in Assemble().
  if (op->jmpmode!=0 && op->type!=IMM && op->type!=JMF && op->type!=MRG) {
    asmerror="Jump address modifier is not allowed";
    scan=SCAN_ERR; return; };
  Scanasm(0);                          // Fetch next token from input line

};

// Function assembles text into 32-bit 80x86 machine code. It supports imprecise
// operands (for example, R32 stays for any general-purpose 32-bit register).
// This allows to search for incomplete commands. Command is precise when all
// significant bytes in model.mask are 0xFF. Some commands have more than one
// decoding. By calling Assemble() with attempt=0,1... and constsize=0,1,2,3 one
// gets also alternative variants (bit 0x1 of constsize is responsible for size
// of address constant and bit 0x2 - for immediate data). However, only one
// address form is generated ([EAX*2], but not [EAX+EAX]; [EBX+EAX] but not
// [EAX+EBX]; [EAX] will not use SIB byte; no DS: prefix and so on). Returns
// number of bytes in assembled code or non-positive number in case of detected
// error. This number is the negation of the offset in the input text where the
// error encountered. Unfortunately, BC 4.52 is unable to compile the switch
// (arg) in this code when any common subexpression optimization is on. The
// next #pragma statement disables all optimizations.

//#pragma option -Od                     // No optimizations, or BC 4.52 crashes

#ifdef USE_ASSEMBLE
int CMaxDisassem::Assemble(char *cmd,ulong ip,t_asmmodel *model,int attempt, int constsize,char *errtext)
{
  int i,j,k,namelen,nameok,arg,match,datasize,addrsize,bytesize,minop,maxop;
  int rep,lock,segment,jmpsize,jmpmode,longjump;
  int hasrm,hassib,dispsize,immsize;
  int anydisp,anyimm,anyjmp;
  long l,displacement,immediate,jmpoffset;
  char name[32],*nameend;
  char tcode[MAXCMDSIZE],tmask[MAXCMDSIZE];
  t_asmoperand aop[3],*op;             // Up to 3 operands allowed
  const t_cmddata *pd;
  if (model!=NULL) model->length=0;
  if (cmd==NULL || model==NULL || errtext==NULL) {
    if (errtext!=NULL) strcpy(errtext,"Internal OLLYDBG error");
    return 0; };                       // Error in parameters
  asmcmd=cmd;
  rep=lock=0; errtext[0]='\0';
  Scanasm(SA_NAME);
  if (scan==SCAN_EOL)                  // End of line, nothing to assemble
    return 0;
  while (1) {                          // Fetch all REPxx and LOCK prefixes
    if (scan==SCAN_REP || scan==SCAN_REPE || scan==SCAN_REPNE) {
      if (rep!=0) {
        strcpy(errtext,"Duplicated REP prefix"); goto error; };
      rep=scan; }
    else if (scan==SCAN_LOCK) {
      if (lock!=0) {
        strcpy(errtext,"Duplicated LOCK prefix"); goto error; };
      lock=scan; }
    else break;                        // No more prefixes
    Scanasm(SA_NAME); };
  if (scan!=SCAN_NAME || idata>16) {
    strcpy(errtext,"Command mnemonic expected"); goto error; };
  nameend=asmcmd;
  strupr(sdata);
  // Prepare full mnemonic (including repeat prefix, if any).
  if (rep==SCAN_REP) sprintf_s(name,32,"REP %s",sdata);
  else if (rep==SCAN_REPE) sprintf_s(name,32,"REPE %s",sdata);
  else if (rep==SCAN_REPNE) sprintf_s(name,32,"REPNE %s",sdata);
  else strcpy_s(name,32,sdata);
  Scanasm(0);
  // Parse command operands (up to 3). Note: jump address is always the first
  // (and only) operand in actual command set.
  for (i=0; i<3; i++) {
    aop[i].type=NNN;                   // No operand
    aop[i].size=0;                     // Undefined size
    aop[i].index=-1;                   // No index
    aop[i].scale=0;                    // No scale
    aop[i].base=-1;                    // No base
    aop[i].offset=0;                   // No offset
    aop[i].anyoffset=0;                // No offset
    aop[i].segment=SEG_UNDEF;          // No segment
    aop[i].jmpmode=0; };               // No jump size modifier
  Parseasmoperand(aop+0);
  jmpmode=aop[0].jmpmode;
  if (jmpmode!=0) jmpmode|=0x80;
  if (scan==SCAN_SYMB && idata==',') {
    Scanasm(0);
    Parseasmoperand(aop+1);
    if (scan==SCAN_SYMB && idata==',') {
      Scanasm(0);
      Parseasmoperand(aop+2);
    };
  };
  if (scan==SCAN_ERR) {
    strcpy(errtext,asmerror); goto error; };
  if (scan!=SCAN_EOL) {
    strcpy(errtext,"Extra input after operand"); goto error; };
  // If jump size is not specified, function tries to use short jump. If
  // attempt fails, it retries with long form.
  longjump=0;                          // Try short jump on the first pass
retrylongjump:
  nameok=0;
  // Some commands allow different number of operands. Variables minop and
  // maxop accumulate their minimal and maximal counts. The numbers are not
  // used in assembly process but allow for better error diagnostics.
  minop=3; maxop=0;
  // Main assembly loop: try to find the command which matches all operands,
  // but do not process operands yet.
  namelen=strlen(name);
  for (pd=cmddata; pd->mask!=0; pd++) {
    if (pd->name[0]=='&') {            // Mnemonic depends on operand size
      j=1;
      datasize=2;
      addrsize=4;
      while (1) {                      // Try all mnemonics (separated by ':')
        for (i=0; pd->name[j]!='\0' && pd->name[j]!=':'; j++) {
          if (pd->name[j]=='*') {
            if (name[i]=='W') { datasize=2; i++; }
            else if (name[i]=='D') { datasize=4; i++; }
            else if (sizesens==0) datasize=2;
            else datasize=4; }
          else if (pd->name[j]==name[i]) i++;
          else break;
        };
        if (name[i]=='\0' && (pd->name[j]=='\0' || pd->name[j]==':'))
          break;                       // Bingo!
        while (pd->name[j]!='\0' && pd->name[j]!=':')
          j++;
        if (pd->name[j]==':') {
          j++; datasize=4; }           // Retry with 32-bit mnenonic
        else {
          i=0; break;                  // Comparison failed
        };
      };
      if (i==0) continue; }
    else if (pd->name[0]=='$') {       // Mnemonic depends on address size
      j=1;
      datasize=0;
      addrsize=2;
      while (1) {                      // Try all mnemonics (separated by ':')
        for (i=0; pd->name[j]!='\0' && pd->name[j]!=':'; j++) {
          if (pd->name[j]=='*') {
            if (name[i]=='W') { addrsize=2; i++; }
            else if (name[i]=='D') { addrsize=4; i++; }
            else if (sizesens==0) addrsize=2;
            else addrsize=4; }
          else if (pd->name[j]==name[i]) i++;
          else break;
        };
        if (name[i]=='\0' && (pd->name[j]=='\0' || pd->name[j]==':'))
          break;                       // Bingo!
        while (pd->name[j]!='\0' && pd->name[j]!=':')
          j++;
        if (pd->name[j]==':') {
          j++; addrsize=4; }           // Retry with 32-bit mnenonic
        else {
          i=0; break;                  // Comparison failed
        };
      };
      if (i==0) continue; }
    else {                             // Compare with all synonimes
      j=k=0;
      datasize=0;                      // Default settings
      addrsize=4;
      while (1) {
        while (pd->name[j]!=',' && pd->name[j]!='\0') j++;
        if (j-k==namelen && strnicmp(name,pd->name+k,namelen)==0) break;
        k=j+1; if (pd->name[j]=='\0') break;
        j=k; };
      if (k>j) continue;
    };
    // For error diagnostics it is important to know whether mnemonic exists.
    nameok++;
    if (pd->arg1==NNN || pd->arg1>=PSEUDOOP)
       minop=0;
    else if (pd->arg2==NNN || pd->arg2>=PSEUDOOP) {
       if (minop>1) minop=1;
       if (maxop<1) maxop=1; }
    else if (pd->arg3==NNN || pd->arg3>=PSEUDOOP) {
       if (minop>2) minop=2;
       if (maxop<2) maxop=2; }
    else
      maxop=3;
    // Determine default and allowed operand size(s).
    if (pd->bits==FF) datasize=2;      // Forced 16-bit size
    if (pd->bits==WW || pd->bits==WS || pd->bits==W3 || pd->bits==WP)
      bytesize=1;                      // 1-byte size allowed
    else
      bytesize=0;                      // Word/dword size only
    // Check whether command operands match specified. If so, variable match
    // remains zero, otherwise it contains kind of mismatch. This allows for
    // better error diagnostics.
    match=0;
    for (j=0; j<3; j++) {              // Up to 3 operands
      op=aop+j;
      if (j==0) arg=pd->arg1;
      else if (j==1) arg=pd->arg2;
      else arg=pd->arg3;
      if (arg==NNN || arg>=PSEUDOOP) {
        if (op->type!=NNN)             // No more arguments
          match|=MA_NOP;
        break; };
      if (op->type==NNN) {
        match|=MA_NOP; break; };       // No corresponding operand
      switch (arg) {
        case REG:                      // Integer register in Reg field
        case RCM:                      // Integer register in command byte
        case RAC:                      // Accumulator (AL/AX/EAX, implicit)
          if (op->type!=REG) match|=MA_TYP;
          if (arg==RAC && op->index!=REG_EAX && op->index!=8) match|=MA_TYP;
          if (bytesize==0 && op->size==1) match|=MA_SIZ;
          if (datasize==0) datasize=op->size;
          if (datasize!=op->size) match|=MA_DIF;
          break;
        case RG4:                      // Integer 4-byte register in Reg field
          if (op->type!=REG) match|=MA_TYP;
          if (op->size!=4) match|=MA_SIZ;
          if (datasize==0) datasize=op->size;
          if (datasize!=op->size) match|=MA_DIF;
          break;
        case RAX:                      // AX (2-byte, implicit)
          if (op->type!=REG || (op->index!=REG_EAX && op->index!=8))
            match|=MA_TYP;
          if (op->size!=2) match|=MA_SIZ;
          if (datasize==0) datasize=op->size;
          if (datasize!=op->size) match|=MA_DIF;
          break;
        case RDX:                      // DX (16-bit implicit port address)
          if (op->type!=REG || (op->index!=REG_EDX && op->index!=8))
            match|=MA_TYP;
          if (op->size!=2) match|=MA_SIZ; break;
        case RCL:                      // Implicit CL register (for shifts)
          if (op->type!=REG || (op->index!=REG_ECX && op->index!=8))
            match|=MA_TYP;
          if (op->size!=1) match|=MA_SIZ;
          break;
        case RS0:                      // Top of FPU stack (ST(0))
          if (op->type!=RST || (op->index!=0 && op->index!=8))
            match|=MA_TYP;
          break;
        case RST:                      // FPU register (ST(i)) in command byte
          if (op->type!=RST) match|=MA_TYP; break;
        case RMX:                      // MMX register MMx
        case R3D:                      // 3DNow! register MMx
          if (op->type!=RMX) match|=MA_TYP; break;
        case MRG:                      // Memory/register in ModRM byte
          if (op->type!=MRG && op->type!=REG) match|=MA_TYP;
          if (bytesize==0 && op->size==1) match|=MA_SIZ;
          if (datasize==0) datasize=op->size;
          if (op->size!=0 && op->size!=datasize) match|=MA_DIF;
          break;
        case MR1:                      // 1-byte memory/register in ModRM byte
          if (op->type!=MRG && op->type!=REG) match|=MA_TYP;
          if (op->size!=0 && op->size!=1) match|=MA_SIZ;
          break;
        case MR2:                      // 2-byte memory/register in ModRM byte
          if (op->type!=MRG && op->type!=REG) match|=MA_TYP;
          if (op->size!=0 && op->size!=2) match|=MA_SIZ;
          break;
        case MR4:                      // 4-byte memory/register in ModRM byte
          if (op->type!=MRG && op->type!=REG) match|=MA_TYP;
          if (op->size!=0 && op->size!=4) match|=MA_SIZ;
          break;
        case RR4:                      // 4-byte memory/register (register only)
          if (op->type!=REG) match|=MA_TYP;
          if (op->size!=0 && op->size!=4) match|=MA_SIZ;
          break;
        case MRJ:                      // Memory/reg in ModRM as JUMP target
          if (op->type!=MRG && op->type!=REG) match|=MA_TYP;
          if (op->size!=0 && op->size!=4) match|=MA_SIZ;
          if ((jmpmode & 0x09)!=0) match|=MA_JMP;
          jmpmode&=0x7F; break;
        case MR8:                      // 8-byte memory/MMX register in ModRM
        case MRD:                      // 8-byte memory/3DNow! register in ModRM
          if (op->type!=MRG && op->type!=RMX) match|=MA_TYP;
          if (op->size!=0 && op->size!=8) match|=MA_SIZ;
          break;
        case RR8:                      // 8-byte MMX register only in ModRM
        case RRD:                      // 8-byte memory/3DNow! (register only)
          if (op->type!=RMX) match|=MA_TYP;
          if (op->size!=0 && op->size!=8) match|=MA_SIZ;
          break;
        case MMA:                      // Memory address in ModRM byte for LEA
          if (op->type!=MRG) match|=MA_TYP; break;
        case MML:                      // Memory in ModRM byte (for LES)
          if (op->type!=MRG) match|=MA_TYP;
          if (op->size!=0 && op->size!=6) match|=MA_SIZ;
          if (datasize==0) datasize=4; else if (datasize!=4) match|=MA_DIF;
          break;
        case MMS:                      // Memory in ModRM byte (as SEG:OFFS)
          if (op->type!=MRG) match|=MA_TYP;
          if (op->size!=0 && op->size!=6) match|=MA_SIZ;
          if ((jmpmode & 0x07)!=0) match|=MA_JMP;
          jmpmode&=0x7F; break;
        case MM6:                      // Memory in ModRm (6-byte descriptor)
          if (op->type!=MRG) match|=MA_TYP;
          if (op->size!=0 && op->size!=6) match|=MA_SIZ;
          break;
        case MMB:                      // Two adjacent memory locations (BOUND)
          if (op->type!=MRG) match|=MA_TYP;
          k=op->size; if (ideal==0 && k>1) k/=2;
          if (k!=0 && k!=datasize) match|=MA_DIF;
          break;
        case MD2:                      // Memory in ModRM byte (16-bit integer)
        case MB2:                      // Memory in ModRM byte (16-bit binary)
          if (op->type!=MRG) match|=MA_TYP;
          if (op->size!=0 && op->size!=2) match|=MA_SIZ;
          break;
        case MD4:                      // Memory in ModRM byte (32-bit integer)
        case MF4:                      // Memory in ModRM byte (32-bit float)
          if (op->type!=MRG) match|=MA_TYP;
          if (op->size!=0 && op->size!=4) match|=MA_SIZ;
          break;
        case MD8:                      // Memory in ModRM byte (64-bit integer)
        case MF8:                      // Memory in ModRM byte (64-bit float)
          if (op->type!=MRG) match|=MA_TYP;
          if (op->size!=0 && op->size!=8) match|=MA_SIZ;
          break;
        case MDA:                      // Memory in ModRM byte (80-bit BCD)
        case MFA:                      // Memory in ModRM byte (80-bit float)
          if (op->type!=MRG) match|=MA_TYP;
          if (op->size!=0 && op->size!=10) match|=MA_SIZ;
          break;
        case MFE:                      // Memory in ModRM byte (FPU environment)
        case MFS:                      // Memory in ModRM byte (FPU state)
        case MFX:                      // Memory in ModRM byte (ext. FPU state)
          if (op->type!=MRG) match|=MA_TYP;
          if (op->size!=0) match|=MA_SIZ;
          break;
        case MSO:                      // Source in string operands ([ESI])
          if (op->type!=MRG || op->base!=REG_ESI ||
            op->index!=-1 || op->offset!=0 || op->anyoffset!=0) match|=MA_TYP;
          if (datasize==0) datasize=op->size;
          if (op->size!=0 && op->size!=datasize) match|=MA_DIF;
          break;
        case MDE:                      // Destination in string operands ([EDI])
          if (op->type!=MRG || op->base!=REG_EDI ||
            op->index!=-1 || op->offset!=0 || op->anyoffset!=0) match|=MA_TYP;
          if (op->segment!=SEG_UNDEF && op->segment!=SEG_ES) match|=MA_SEG;
          if (datasize==0) datasize=op->size;
          if (op->size!=0 && op->size!=datasize) match|=MA_DIF;
          break;
        case MXL:                      // XLAT operand ([EBX+AL])
          if (op->type!=MXL) match|=MA_TYP; break;
        case IMM:                      // Immediate data (8 or 16/32)
        case IMU:                      // Immediate unsigned data (8 or 16/32)
          if (op->type!=IMM) match|=MA_TYP;
          break;
        case VXD:                      // VxD service (32-bit only)
          if (op->type!=IMM) match|=MA_TYP;
          if (datasize==0) datasize=4;
          if (datasize!=4) match|=MA_SIZ;
          break;
        case JMF:                      // Immediate absolute far jump/call addr
          if (op->type!=JMF) match|=MA_TYP;
          if ((jmpmode & 0x05)!=0) match|=MA_JMP;
          jmpmode&=0x7F; break;
        case JOB:                      // Immediate byte offset (for jumps)
          if (op->type!=IMM || longjump) match|=MA_TYP;
          if ((jmpmode & 0x0A)!=0) match|=MA_JMP;
          jmpmode&=0x7F; break;
        case JOW:                      // Immediate full offset (for jumps)
          if (op->type!=IMM) match|=MA_TYP;
          if ((jmpmode & 0x09)!=0) match|=MA_JMP;
          jmpmode&=0x7F; break;
        case IMA:                      // Immediate absolute near data address
          if (op->type!=MRG || op->base>=0 || op->index>=0) match|=MA_TYP;
          break;
        case IMX:                      // Immediate sign-extendable byte
          if (op->type!=IMM) match|=MA_TYP;
          if (op->offset<-128 || op->offset>127) match|=MA_RNG;
          break;
        case C01:                      // Implicit constant 1 (for shifts)
          if (op->type!=IMM || (op->offset!=1 && op->anyoffset==0))
            match|=MA_TYP;
          break;
        case IMS:                      // Immediate byte (for shifts)
        case IM1:                      // Immediate byte
          if (op->type!=IMM) match|=MA_TYP;
          if (op->offset<-128 || op->offset>255) match|=MA_RNG;
          break;
        case IM2:                      // Immediate word (ENTER/RET)
          if (op->type!=IMM) match|=MA_TYP;
          if (op->offset<0 || op->offset>65535) match|=MA_RNG;
          break;
        case SGM:                      // Segment register in ModRM byte
          if (op->type!=SGM) match|=MA_TYP;
          if (datasize==0) datasize=2;
          if (datasize!=2) match|=MA_DIF;
          break;
        case SCM:                      // Segment register in command byte
          if (op->type!=SGM) match|=MA_TYP;
          break;
        case CRX:                      // Control register CRx
        case DRX:                      // Debug register DRx
          if (op->type!=arg) match|=MA_TYP;
          if (datasize==0) datasize=4;
          if (datasize!=4) match|=MA_DIF;
          break;
        case PRN:                      // Near return address (pseudooperand)
        case PRF:                      // Far return address (pseudooperand)
        case PAC:                      // Accumulator (AL/AX/EAX, pseudooperand)
        case PAH:                      // AH (in LAHF/SAHF, pseudooperand)
        case PFL:                      // Lower byte of flags (pseudooperand)
        case PS0:                      // Top of FPU stack (pseudooperand)
        case PS1:                      // ST(1) (pseudooperand)
        case PCX:                      // CX/ECX (pseudooperand)
        case PDI:                      // EDI (pseudooperand in MMX extentions)
          break;
        default:                       // Undefined type of operand
          strcpy(errtext,"Internal Assembler error");
        goto error;
      };                               // End of switch (arg)
      if ((jmpmode & 0x80)!=0) match|=MA_JMP;
      if (match!=0) break;             // Some of the operands doesn't match
    };                                 // End of operand matching loop
    if (match==0) {                    // Exact match found
      if (attempt>0) {
        --attempt; nameok=0; }         // Well, try to find yet another match
      else break;
    };
  };                                   // End of command search loop
  // Check whether some error was detected. If several errors were found
  // similtaneously, report one (roughly in order of significance).
  if (nameok==0) {                     // Mnemonic unavailable
    strcpy(errtext,"Unrecognized command");
    asmcmd=nameend; goto error; };
  if (match!=0) {                      // Command not found
    if (minop>0 && aop[minop-1].type==NNN)
      strcpy(errtext,"Too few operands");
    else if (maxop<3 && aop[maxop].type!=NNN)
      strcpy(errtext,"Too many operands");
    else if (nameok>1)                 // More that 1 command
      strcpy(errtext,"Command does not support given operands");
    else if (match & MA_JMP)
      strcpy(errtext,"Invalid jump size modifier");
    else if (match & MA_NOP)
      strcpy(errtext,"Wrong number of operands");
    else if (match & MA_TYP)
      strcpy(errtext,"Command does not support given operands");
    else if (match & MA_NOS)
      strcpy(errtext,"Please specify operand size");
    else if (match & MA_SIZ)
      strcpy(errtext,"Bad operand size");
    else if (match & MA_DIF)
      strcpy(errtext,"Different size of operands");
    else if (match & MA_SEG)
      strcpy(errtext,"Invalid segment register");
    else if (match & MA_RNG)
      strcpy(errtext,"Constant out of expected range");
    else
      strcpy(errtext,"Erroneous command");
    goto error;
  };
  // Exact match found. Now construct the code.
  hasrm=0;                             // Whether command has ModR/M byte
  hassib=0;                            // Whether command has SIB byte
  dispsize=0;                          // Size of displacement (if any)
  immsize=0;                           // Size of immediate data (if any)
  segment=SEG_UNDEF;                   // Necessary segment prefix
  jmpsize=0;                           // No relative jumps
  memset(tcode,0,sizeof(tcode));
  *(ulong *)tcode=pd->code & pd->mask;
  memset(tmask,0,sizeof(tmask));
  *(ulong *)tmask=pd->mask;
  i=pd->len-1;                         // Last byte of command itself
  if (rep) i++;                        // REPxx prefixes count as extra byte
  // In some cases at least one operand must have explicit size declaration (as
  // in MOV [EAX],1). This preliminary check does not include all cases.
  if (pd->bits==WW || pd->bits==WS || pd->bits==WP) {
    if (datasize==0) {
      strcpy(errtext,"Please specify operand size"); goto error; }
    else if (datasize>1)
      tcode[i]|=0x01;                  // WORD or DWORD size of operands
    tmask[i]|=0x01; }
  else if (pd->bits==W3) {
    if (datasize==0) {
      strcpy(errtext,"Please specify operand size"); goto error; }
    else if (datasize>1)
      tcode[i]|=0x08;                  // WORD or DWORD size of operands
    tmask[i]|=0x08; };
  // Present suffix of 3DNow! command as immediate byte operand.
  if ((pd->type & C_TYPEMASK)==C_NOW) {
    immsize=1;
    immediate=(pd->code>>16) & 0xFF; };
  // Process operands again, this time constructing the code.
  anydisp=anyimm=anyjmp=0;
  for (j=0; j<3; j++) {                // Up to 3 operands
    op=aop+j;
    if (j==0) arg=pd->arg1;
    else if (j==1) arg=pd->arg2;
    else arg=pd->arg3;
    if (arg==NNN) break;               // All operands processed
    switch (arg) {
      case REG:                        // Integer register in Reg field
      case RG4:                        // Integer 4-byte register in Reg field
      case RMX:                        // MMX register MMx
      case R3D:                        // 3DNow! register MMx
      case CRX:                        // Control register CRx
      case DRX:                        // Debug register DRx
        hasrm=1;
        if (op->index<8) {
          tcode[i+1]|=(char)(op->index<<3); tmask[i+1]|=0x38; };
        break;
      case RCM:                        // Integer register in command byte
      case RST:                        // FPU register (ST(i)) in command byte
        if (op->index<8) {
          tcode[i]|=(char)op->index; tmask[i]|=0x07; };
        break;
      case RAC:                        // Accumulator (AL/AX/EAX, implicit)
      case RAX:                        // AX (2-byte, implicit)
      case RDX:                        // DX (16-bit implicit port address)
      case RCL:                        // Implicit CL register (for shifts)
      case RS0:                        // Top of FPU stack (ST(0))
      case MDE:                        // Destination in string op's ([EDI])
      case C01:                        // Implicit constant 1 (for shifts)
        break;                         // Simply skip implicit operands
      case MSO:                        // Source in string op's ([ESI])
      case MXL:                        // XLAT operand ([EBX+AL])
        if (op->segment!=SEG_UNDEF && op->segment!=SEG_DS)
          segment=op->segment;
        break;
      case MRG:                        // Memory/register in ModRM byte
      case MRJ:                        // Memory/reg in ModRM as JUMP target
      case MR1:                        // 1-byte memory/register in ModRM byte
      case MR2:                        // 2-byte memory/register in ModRM byte
      case MR4:                        // 4-byte memory/register in ModRM byte
      case RR4:                        // 4-byte memory/register (register only)
      case MR8:                        // 8-byte memory/MMX register in ModRM
      case RR8:                        // 8-byte MMX register only in ModRM
      case MRD:                        // 8-byte memory/3DNow! register in ModRM
      case RRD:                        // 8-byte memory/3DNow! (register only)
        hasrm=1;
        if (op->type!=MRG) {           // Register in ModRM byte
          tcode[i+1]|=0xC0; tmask[i+1]|=0xC0;
          if (op->index<8) {
            tcode[i+1]|=(char)op->index; tmask[i+1]|=0x07; };
          break;
        };                             // Note: NO BREAK, continue with address
      case MMA:                        // Memory address in ModRM byte for LEA
      case MML:                        // Memory in ModRM byte (for LES)
      case MMS:                        // Memory in ModRM byte (as SEG:OFFS)
      case MM6:                        // Memory in ModRm (6-byte descriptor)
      case MMB:                        // Two adjacent memory locations (BOUND)
      case MD2:                        // Memory in ModRM byte (16-bit integer)
      case MB2:                        // Memory in ModRM byte (16-bit binary)
      case MD4:                        // Memory in ModRM byte (32-bit integer)
      case MD8:                        // Memory in ModRM byte (64-bit integer)
      case MDA:                        // Memory in ModRM byte (80-bit BCD)
      case MF4:                        // Memory in ModRM byte (32-bit float)
      case MF8:                        // Memory in ModRM byte (64-bit float)
      case MFA:                        // Memory in ModRM byte (80-bit float)
      case MFE:                        // Memory in ModRM byte (FPU environment)
      case MFS:                        // Memory in ModRM byte (FPU state)
      case MFX:                        // Memory in ModRM byte (ext. FPU state)
        hasrm=1; displacement=op->offset; anydisp=op->anyoffset;
        if (op->base<0 && op->index<0) {
          dispsize=4;                  // Special case of immediate address
          if (op->segment!=SEG_UNDEF && op->segment!=SEG_DS)
            segment=op->segment;
          tcode[i+1]|=0x05;
          tmask[i+1]|=0xC7; }
        else if (op->index<0 && op->base!=REG_ESP) {
          tmask[i+1]|=0xC0;            // SIB byte unnecessary
          if (op->offset==0 && op->anyoffset==0 && op->base!=REG_EBP)
            ;                          // [EBP] always requires offset
          else if ((constsize & 1)!=0 &&
            ((op->offset>=-128 && op->offset<128) || op->anyoffset!=0)
          ) {
            tcode[i+1]|=0x40;          // Disp8
            dispsize=1; }
          else {
            tcode[i+1]|=0x80;          // Disp32
            dispsize=4; };
          if (op->base<8) {
            if (op->segment!=SEG_UNDEF && op->segment!=addr32[op->base].defseg)
              segment=op->segment;
            tcode[i+1]|=
              (char)op->base;          // Note that case [ESP] has base<0.
            tmask[i+1]|=0x07; }
          else segment=op->segment; }
        else {                         // SIB byte necessary
          hassib=1;
          if (op->base==REG_EBP &&     // EBP as base requires offset, optimize
            op->index>=0 && op->scale==1 && op->offset==0 && op->anyoffset==0) {
            op->base=op->index; op->index=REG_EBP; };
          if (op->index==REG_ESP &&    // ESP cannot be an index, reorder
            op->scale<=1) {
            op->index=op->base; op->base=REG_ESP; op->scale=1; };
          if (op->base<0 &&            // No base means 4-byte offset, optimize
            op->index>=0 && op->scale==2 &&
            op->offset>=-128 && op->offset<128 && op->anyoffset==0) {
            op->base=op->index; op->scale=1; };
          if (op->index==REG_ESP) {    // Reordering was unsuccessfull
            strcpy(errtext,"Invalid indexing mode");
            goto error; };
          if (op->base<0) {
            tcode[i+1]|=0x04;
            dispsize=4; }
          else if (op->offset==0 && op->anyoffset==0 && op->base!=REG_EBP)
            tcode[i+1]|=0x04;          // No displacement
          else if ((constsize & 1)!=0 &&
            ((op->offset>=-128 && op->offset<128) || op->anyoffset!=0)
          ) {
            tcode[i+1]|=0x44;          // Disp8
            dispsize=1; }
          else {
            tcode[i+1]|=0x84;          // Disp32
            dispsize=4; };
          tmask[i+1]|=0xC7;            // ModRM completed, proceed with SIB
          if (op->scale==2) tcode[i+2]|=0x40;
          else if (op->scale==4) tcode[i+2]|=0x80;
          else if (op->scale==8) tcode[i+2]|=0xC0;
          tmask[i+2]|=0xC0;
          if (op->index<8) {
            if (op->index<0) op->index=0x04;
            tcode[i+2]|=(char)(op->index<<3);
            tmask[i+2]|=0x38; };
          if (op->base<8) {
            if (op->base<0) op->base=0x05;
            if (op->segment!=SEG_UNDEF && op->segment!=addr32[op->base].defseg)
              segment=op->segment;
            tcode[i+2]|=(char)op->base;
            tmask[i+2]|=0x07; }
          else segment=op->segment; };
        break;
      case IMM:                        // Immediate data (8 or 16/32)
      case IMU:                        // Immediate unsigned data (8 or 16/32)
      case VXD:                        // VxD service (32-bit only)
        if (datasize==0 && pd->arg2==NNN && (pd->bits==SS || pd->bits==WS))
          datasize=4;
        if (datasize==0) {
          strcpy(errtext,"Please specify operand size");
          goto error; };
        immediate=op->offset; anyimm=op->anyoffset;
        if (pd->bits==SS || pd->bits==WS) {
          if (datasize>1 && (constsize & 2)!=0 &&
            ((immediate>=-128 && immediate<128) || op->anyoffset!=0)) {
            immsize=1; tcode[i]|=0x02; }
          else immsize=datasize;
          tmask[i]|=0x02; }
        else immsize=datasize;
        break;
      case IMX:                        // Immediate sign-extendable byte
      case IMS:                        // Immediate byte (for shifts)
      case IM1:                        // Immediate byte
        if (immsize==2)                // To accomodate ENTER instruction
          immediate=(immediate & 0xFFFF) | (op->offset<<16);
        else immediate=op->offset;
        anyimm|=op->anyoffset;
        immsize++; break;
      case IM2:                        // Immediate word (ENTER/RET)
        immediate=op->offset; anyimm=op->anyoffset;
        immsize=2; break;
      case IMA:                        // Immediate absolute near data address
        if (op->segment!=SEG_UNDEF && op->segment!=SEG_DS)
          segment=op->segment;
        displacement=op->offset; anydisp=op->anyoffset;
        dispsize=4; break;
      case JOB:                        // Immediate byte offset (for jumps)
        jmpoffset=op->offset; anyjmp=op->anyoffset;
        jmpsize=1; break;
      case JOW:                        // Immediate full offset (for jumps)
        jmpoffset=op->offset; anyjmp=op->anyoffset;
        jmpsize=4; break;
      case JMF:                        // Immediate absolute far jump/call addr
        displacement=op->offset; anydisp=op->anyoffset; dispsize=4;
        immediate=op->segment; anyimm=op->anyoffset; immsize=2;
        break;
      case SGM:                        // Segment register in ModRM byte
        hasrm=1;
        if (op->index<6) {
          tcode[i+1]|=(char)(op->index<<3); tmask[i+1]|=0x38; };
        break;
      case SCM:                        // Segment register in command byte
        if (op->index==SEG_FS || op->index==SEG_GS) {
          tcode[0]=(char)0x0F; tmask[0]=(char)0xFF;
          i=1;
          if (strcmp(name,"PUSH")==0)
            tcode[i]=(char)((op->index<<3) | 0x80);
          else
            tcode[i]=(char)((op->index<<3) | 0x81);
          tmask[i]=(char)0xFF; }
        else if (op->index<6) {
          if (op->index==SEG_CS && strcmp(name,"POP")==0) {
            strcpy(errtext,"Unable to POP CS");
            goto error; };
          tcode[i]=(char)((tcode[i] & 0xC7) | (op->index<<3)); }
        else {
          tcode[i]&=0xC7;
          tmask[i]&=0xC7; };
        break;
      case PRN:                        // Near return address (pseudooperand)
      case PRF:                        // Far return address (pseudooperand)
      case PAC:                        // Accumulator (AL/AX/EAX, pseudooperand)
      case PAH:                        // AH (in LAHF/SAHF, pseudooperand)
      case PFL:                        // Lower byte of flags (pseudooperand)
      case PS0:                        // Top of FPU stack (pseudooperand)
      case PS1:                        // ST(1) (pseudooperand)
      case PCX:                        // CX/ECX (pseudooperand)
      case PDI:                        // EDI (pseudooperand in MMX extentions)
        break;                         // Simply skip preudooperands
      default:                         // Undefined type of operand
        strcpy(errtext,"Internal Assembler error");
      goto error;
    };
  };
  // Gather parts of command together in the complete command.
  j=0;
  if (lock!=0) {                       // Lock prefix specified
    model->code[j]=(char)0xF0;
    model->mask[j]=(char)0xFF; j++; };
  if (datasize==2 && pd->bits!=FF) {   // Data size prefix necessary
    model->code[j]=0x66;
    model->mask[j]=(char)0xFF; j++; };
  if (addrsize==2) {                   // Address size prefix necessary
    model->code[j]=0x67;
    model->mask[j]=(char)0xFF; j++; };
  if (segment!=SEG_UNDEF) {            // Segment prefix necessary
    if (segment==SEG_ES) model->code[j]=0x26;
    else if (segment==SEG_CS) model->code[j]=0x2E;
    else if (segment==SEG_SS) model->code[j]=0x36;
    else if (segment==SEG_DS) model->code[j]=0x3E;
    else if (segment==SEG_FS) model->code[j]=0x64;
    else if (segment==SEG_GS) model->code[j]=0x65;
    else { strcpy(errtext,"Internal Assembler error"); goto error; };
    model->mask[j]=(char)0xFF; j++; };
  if (dispsize>0) {
    memcpy(tcode+i+1+hasrm+hassib,&displacement,dispsize);
    if (anydisp==0) memset(tmask+i+1+hasrm+hassib,0xFF,dispsize); };
  if (immsize>0) {
    if (immsize==1) l=0xFFFFFF00L;
    else if (immsize==2) l=0xFFFF0000L;
    else l=0L;
    if ((immediate & l)!=0 && (immediate & l)!=l) {
      strcpy(errtext,"Constant does not fit into operand");
      goto error; };
    memcpy(tcode+i+1+hasrm+hassib+dispsize,&immediate,immsize);
    if (anyimm==0) memset(tmask+i+1+hasrm+hassib+dispsize,0xFF,immsize); };
  i=i+1+hasrm+hassib+dispsize+immsize;
  jmpoffset=jmpoffset-(i+j+jmpsize);
  model->jmpsize=jmpsize;
  model->jmpoffset=jmpoffset;
  model->jmppos=i+j;
  if (jmpsize!=0) {
    if (ip!=0) {
      jmpoffset=jmpoffset-ip;
      if (jmpsize==1 && anyjmp==0 && (jmpoffset<-128 || jmpoffset>=128)) {
        if (longjump==0 && (jmpmode & 0x03)==0) {
          longjump=1;
          goto retrylongjump; };
        sprintf(errtext,
          "Relative jump out of range, use %s LONG form",name);
        goto error; };
      memcpy(tcode+i,&jmpoffset,jmpsize);
    };
    if (anyjmp==0) memset(tmask+i,0xFF,jmpsize);
    i+=jmpsize; };
  memcpy(model->code+j,tcode,i);
  memcpy(model->mask+j,tmask,i);
  i+=j;
  model->length=i;
  return i;                            // Positive value: length of code
error:
  model->length=0;
  return cmd-asmcmd;                   // Negative value: position of error
};
#endif
//#pragma option -O.                     // Restore old optimization options

////////////////////////////////////////////////////////////////////////////////
//////////////////////////// DISASSEMBLER FUNCTIONS ////////////////////////////


/*-------------------------------------------------------------------------------------
	Function		: DecodeRG
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Disassemble name of 1, 2 or 4-byte general-purpose integer register and, if
					  requested and available, dump its contents. Parameter type changes decoding
					  of contents for some operand types
--------------------------------------------------------------------------------------*/
void CMaxDisassem::DecodeRG(int index,int datasize,int type) {
  int sizeindex;
  char name[9] = {0} ;

  if (mode<DISASM_DATA) return;        // No need to decode
  index&=0x07;
  if (datasize==1)
    sizeindex=0;
  else if (datasize==2)
    sizeindex=1;
  else if (datasize==4)
    sizeindex=2;
  else {
    da->error=DAE_INTERN; return; };
  if (mode>=DISASM_FILE) {
    strcpy_s(name,9,regname[sizeindex][index]);
    if (lowercase) _strlwr_s(name);
    if (type<PSEUDOOP)                 // Not a pseudooperand
      nresult+=sprintf_s(da->result+nresult,256-nresult,"%s",name);
    ;
  };
};


/*-------------------------------------------------------------------------------------
	Function		: DecodeST
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Disassemble name of 80-bit floating-point register and, if available, dump
					  its contents.
--------------------------------------------------------------------------------------*/
void CMaxDisassem::DecodeST(int index,int pseudoop) {
  int i = 0x00 ;
  char s[32]={0};
  if (mode<DISASM_FILE) return;        // No need to decode
  index&=0x07;
  i=sprintf_s(s,32,"%s(%i)",(lowercase?"st":"ST"),index);
  if (pseudoop==0) {
    strcpy_s(da->result+nresult,256-nresult,s);
    nresult+=i;
  };
};

/*-------------------------------------------------------------------------------------
	Function		: DecodeMX
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam + Vilas Suvarnakar
	Description		: Disassemble name of 64-bit MMX register.
--------------------------------------------------------------------------------------*/
void CMaxDisassem::DecodeMX(int index) {
  char *pr = NULL;
  if (mode<DISASM_FILE) return;        // No need to decode
  index&=0x07;
  pr=da->result+nresult;
  if(pr)
  {
	nresult+=sprintf_s(pr,256-nresult,"%s%i",(lowercase?"mm":"MM"),index);
  }
};

// Disassemble name of 64-bit 3DNow! register and, if available, dump its
// contents.
void CMaxDisassem::DecodeNR(int index) {
  char *pr = NULL ;

  if (mode<DISASM_FILE) return;        // No need to decode
  index&=0x07;
  pr=da->result+nresult;
  nresult+=sprintf_s(pr,256-nresult,"%s%i",(lowercase?"mm":"MM"),index);
};


/*-------------------------------------------------------------------------------------
	Function		: Memadr
	In Parameters	: 
	Out Parameters	: 
	Purpose			: Get Memory Address
	Author			: Tushar Kadam
	Description		: Service function, adds valid memory adress in MASM or Ideal format to
					  disassembled string. Parameters: defseg - default segment for given
					 register combination, descr - fully decoded register part of address,
					 offset - constant part of address, dsize - data size in bytes. If global
					 flag 'symbolic' is set, function also tries to decode offset as name of
					 some label.
--------------------------------------------------------------------------------------*/
void CMaxDisassem::Memadr(int defseg,const char *descr,long offset,int dsize) {
  int i,n,seg;
  char *pr = NULL ;
  char s[TEXTLEN] = {0};
  
  i = n = seg = 0x00 ;
  if (mode<DISASM_FILE || descr==NULL)
    return;                            // No need or possibility to decode
  pr=da->result+nresult; n=0;
  if (segprefix!=SEG_UNDEF) seg=segprefix; else seg=defseg;
  if (ideal!=0) pr[n++]='[';
  // In some cases Disassembler may omit size of memory operand. Namely, flag
  // showmemsize must be 0, type bit C_EXPL must be 0 (this bit namely means
  // that explicit operand size is necessary) and type of command must not be
  // C_MMX or C_NOW (because bit C_EXPL has in these cases different meaning).
  // Otherwise, exact size must be supplied.
  if (showmemsize!=0 || (da->cmdtype & C_TYPEMASK)==C_MMX ||
    (da->cmdtype & C_TYPEMASK)==C_NOW || (da->cmdtype & C_EXPL)!=0
  ) {
    if (dsize<sizeof(sizename)/sizeof(sizename[0]))
      n+=sprintf_s(pr+n,256-nresult-n,"%s %s",sizename[dsize],(ideal==0?"PTR ":""));
    else
      n+=sprintf_s(pr+n,256-nresult-n,"(%i-BYTE) %s",dsize,(ideal==0?"PTR ":""));
    ;
  };
  if ((putdefseg!=0 || seg!=defseg) && seg!=SEG_UNDEF)
    n+=sprintf_s(pr+n,256-nresult-n,"%s:",segname[seg]);
  if (ideal==0) pr[n++]='[';
  n+=sprintf_s(pr+n,256-nresult-n,"%s",descr);
  if (lowercase) _strlwr_s(pr,256-nresult);
  if (offset==0L) {
    if (*descr=='\0') pr[n++]='0'; }
  else {
    if (symbolic && mode>=DISASM_CODE)
      i=Decodeaddress(offset,s,TEXTLEN-n-24,NULL);
    else i=0;
    if (i>0) {                         // Offset decoded in symbolic form
      if (*descr!='\0') pr[n++]='+';
      strcpy_s(pr+n,256-nresult-n,s); n+=i; }
    else if (offset<0 && offset>-16384 && *descr!='\0')
      n+=sprintf_s(pr+n,256-nresult-n,"-%lX",-offset);
    else {
      if (*descr!='\0') pr[n++]='+';
      n+=sprintf_s(pr+n,256-nresult-n,"%lX",offset);
    };
  };
  pr[n++]=']'; pr[n]='\0';
  nresult+=n;
};


/*-------------------------------------------------------------------------------------
	Function		: DecodeMR
	In Parameters	: 
	Out Parameters	: 
	Purpose			: Get Memory Address
	Author			: Tushar Kadam
	Description		: Disassemble memory/register from the ModRM/SIB bytes and, if available, dump
					  address and contents of memory.
--------------------------------------------------------------------------------------*/
void CMaxDisassem::DecodeMR(int type) {
  int j,memonly,inmemory,seg;
  int c,sib;
  ulong dsize,regsize,addr;
  char s[TEXTLEN] = {0};

  j = memonly = inmemory = seg = 0x00 ;
  c = sib = 0x00 ;
  dsize = regsize = addr = 0x00 ;

  if (size<2) {
    da->error=DAE_CROSS; return; };    // ModR/M byte outside the memory block
  hasrm=1;
  dsize=regsize=datasize;              // Default size of addressed reg/memory
  memonly=0;                           // Register in ModM field is allowed
  // Size and kind of addressed memory or register in ModM has no influence on
  // the command size, and exact calculations are omitted if only command size
  // is requested. If register is used, optype will be incorrect and we need
  // to correct it later.
  c=cmd[1] & 0xC7;                     // Leave only Mod and M fields
  if (mode>=DISASM_DATA) {
    if ((c & 0xC0)==0xC0)              // Register operand
      inmemory=0;
    else                               // Memory operand
      inmemory=1;
    switch (type) {
      case MRG:                        // Memory/register in ModRM byte
        if (inmemory) {
          if (datasize==1) da->memtype=DEC_BYTE;
          else if (datasize==2) da->memtype=DEC_WORD;
          else da->memtype=DEC_DWORD; };
        break;
      case MRJ:                        // Memory/reg in ModRM as JUMP target
        if (datasize!=2 && inmemory)
          da->memtype=DEC_DWORD; 
        if (mode>=DISASM_FILE && shownear!=0)
          nresult+=sprintf_s(da->result+nresult,256-nresult,"%s ",(lowercase?"near":"NEAR"));
        break;
      case MR1:                        // 1-byte memory/register in ModRM byte
        dsize=regsize=1;
        if (inmemory) da->memtype=DEC_BYTE; break;
      case MR2:                        // 2-byte memory/register in ModRM byte
        dsize=regsize=2;
        if (inmemory) da->memtype=DEC_WORD; break;
      case MR4:                        // 4-byte memory/register in ModRM byte
      case RR4:                        // 4-byte memory/register (register only)
        dsize=regsize=4;
        if (inmemory) da->memtype=DEC_DWORD; break;
      case MR8:                        // 8-byte memory/MMX register in ModRM
      case RR8:                        // 8-byte MMX register only in ModRM
        dsize=8;
        if (inmemory) da->memtype=DEC_QWORD; break;
      case MRD:                        // 8-byte memory/3DNow! register in ModRM
      case RRD:                        // 8-byte memory/3DNow! (register only)
        dsize=8;
        if (inmemory) da->memtype=DEC_3DNOW; break;
      case MMA:                        // Memory address in ModRM byte for LEA
        memonly=1; break;
      case MML:                        // Memory in ModRM byte (for LES)
        dsize=datasize+2; memonly=1;
        if (datasize==4 && inmemory)
          da->memtype=DEC_FWORD;
        da->warnings|=DAW_SEGMENT;
        break;
      case MMS:                        // Memory in ModRM byte (as SEG:OFFS)
        dsize=datasize+2; memonly=1;
        if (datasize==4 && inmemory)
          da->memtype=DEC_FWORD;
        if (mode>=DISASM_FILE)
          nresult+=sprintf_s(da->result+nresult,256-nresult,"%s ",(lowercase?"far":"FAR"));
        break;
      case MM6:                        // Memory in ModRM (6-byte descriptor)
        dsize=6; memonly=1;
        if (inmemory) da->memtype=DEC_FWORD; break;
      case MMB:                        // Two adjacent memory locations (BOUND)
        dsize=(ideal?datasize:datasize*2); memonly=1; break;
      case MD2:                        // Memory in ModRM byte (16-bit integer)
      case MB2:                        // Memory in ModRM byte (16-bit binary)
        dsize=2; memonly=1;
        if (inmemory) da->memtype=DEC_WORD; break;
      case MD4:                        // Memory in ModRM byte (32-bit integer)
        dsize=4; memonly=1;
        if (inmemory) da->memtype=DEC_DWORD; break;
      case MD8:                        // Memory in ModRM byte (64-bit integer)
        dsize=8; memonly=1;
        if (inmemory) da->memtype=DEC_QWORD; break;
      case MDA:                        // Memory in ModRM byte (80-bit BCD)
        dsize=10; memonly=1;
        if (inmemory) da->memtype=DEC_TBYTE; break;
      case MF4:                        // Memory in ModRM byte (32-bit float)
        dsize=4; memonly=1;
        if (inmemory) da->memtype=DEC_FLOAT4; break;
      case MF8:                        // Memory in ModRM byte (64-bit float)
        dsize=8; memonly=1;
        if (inmemory) da->memtype=DEC_FLOAT8; break;
      case MFA:                        // Memory in ModRM byte (80-bit float)
        dsize=10; memonly=1;
        if (inmemory) da->memtype=DEC_FLOAT10; break;
      case MFE:                        // Memory in ModRM byte (FPU environment)
        dsize=28; memonly=1; break;
      case MFS:                        // Memory in ModRM byte (FPU state)
        dsize=108; memonly=1; break;
      case MFX:                        // Memory in ModRM byte (ext. FPU state)
        dsize=512; memonly=1; break;
      default:                         // Operand is not in ModM!
        da->error=DAE_INTERN;
      break;
    };
  };
  addr=0;
  // There are many possibilities to decode ModM/SIB address. The first
  // possibility is register in ModM - general-purpose, MMX or 3DNow!
  if ((c & 0xC0)==0xC0) {              // Decode register operand
    if (type==MR8 || type==RR8)
      DecodeMX(c);                     // MMX register
    else if (type==MRD || type==RRD)
      DecodeNR(c);                     // 3DNow! register
    else  
      DecodeRG(c,regsize,type);        // General-purpose register
    if (memonly!=0)
      softerror=DAE_MEMORY;            // Register where only memory allowed
    return; };
  // Next possibility: 16-bit addressing mode, very seldom in 32-bit flat model
  // but still supported by processor. SIB byte is never used here.
  if (addrsize==2) {
    if (c==0x06) {                     // Special case of immediate address
      dispsize=2;
      if (size<4)
        da->error=DAE_CROSS;           // Disp16 outside the memory block
      else if (mode>=DISASM_DATA) {
        da->adrconst=addr=*(ushort *)(cmd+2);
        if (addr==0) da->zeroconst=1;
        seg=SEG_DS;
        Memadr(seg,"",addr,dsize);
      }; }
    else {
      da->indexed=1;
      if ((c & 0xC0)==0x40) {          // 8-bit signed displacement
        if (size<3) da->error=DAE_CROSS;
        else addr=(signed char)cmd[2] & 0xFFFF;
        dispsize=1; }
      else if ((c & 0xC0)==0x80) {     // 16-bit unsigned displacement
        if (size<4) da->error=DAE_CROSS;
        else addr=*(ushort *)(cmd+2);
        dispsize=2; };
      if (mode>=DISASM_DATA && da->error==DAE_NOERR) {
        da->adrconst=addr;
        if (addr==0) da->zeroconst=1;
        seg=addr16[c & 0x07].defseg;
        Memadr(seg,addr16[c & 0x07].descr,addr,dsize);
      };
    };
  }
  // Next possibility: immediate 32-bit address.
  else if (c==0x05) {                  // Special case of immediate address
    dispsize=4;
    if (size<6)
      da->error=DAE_CROSS;             // Disp32 outside the memory block
    else if (mode>=DISASM_DATA) {
      da->adrconst=addr=*(ulong *)(cmd+2);
      if (pfixup==NULL) pfixup=cmd+2;
      da->fixupsize+=4;
      if (addr==0) da->zeroconst=1;
      seg=SEG_DS;
      Memadr(seg,"",addr,dsize);
    }; }
  // Next possibility: 32-bit address with SIB byte.
  else if ((c & 0x07)==0x04) {         // SIB addresation
    sib=cmd[2]; hassib=1;
    *s='\0';
    if (c==0x04 && (sib & 0x07)==0x05) {
      dispsize=4;                      // Immediate address without base
      if (size<7)
        da->error=DAE_CROSS;           // Disp32 outside the memory block
      else {
        da->adrconst=addr=*(ulong *)(cmd+3);
        if (pfixup==NULL) pfixup=cmd+3;
        da->fixupsize+=4;
        if (addr==0) da->zeroconst=1;
        if ((sib & 0x38)!=0x20) {      // Index register present
          da->indexed=1;
          if (type==MRJ) da->jmptable=addr; };
        seg=SEG_DS;
      }; }
    else {                             // Base and, eventually, displacement
      if ((c & 0xC0)==0x40) {          // 8-bit displacement
        dispsize=1;
        if (size<4) da->error=DAE_CROSS;
        else {
          da->adrconst=addr=(signed char)cmd[3];
          if (addr==0) da->zeroconst=1;
        }; }
      else if ((c & 0xC0)==0x80) {     // 32-bit displacement
        dispsize=4;
        if (size<7)
          da->error=DAE_CROSS;         // Disp32 outside the memory block
        else {
          da->adrconst=addr=*(ulong *)(cmd+3);
          if (pfixup==NULL) pfixup=cmd+3;
          da->fixupsize+=4;
          if (addr==0) da->zeroconst=1;
          // Most compilers use address of type [index*4+displacement] to
          // address jump table (switch). But, for completeness, I allow all
          // cases which include index with scale 1 or 4, base or both.
          if (type==MRJ) da->jmptable=addr;
        }; };
      da->indexed=1;
      j=sib & 0x07;
      if (mode>=DISASM_FILE) {
        strcpy_s(s,256,regname[2][j]);
        seg=addr32[j].defseg;
      };
    };
    if ((sib & 0x38)!=0x20) {          // Scaled index present
      if ((sib & 0xC0)==0x40) da->indexed=2;
      else if ((sib & 0xC0)==0x80) da->indexed=4;
      else if ((sib & 0xC0)==0xC0) da->indexed=8;
      else da->indexed=1;
    };
    if (mode>=DISASM_FILE && da->error==DAE_NOERR) {
      if ((sib & 0x38)!=0x20) {        // Scaled index present
        if (*s!='\0') strcat_s(s,256,"+");
        strcat_s(s,256,addr32[(sib>>3) & 0x07].descr);
        if ((sib & 0xC0)==0x40) {
          da->jmptable=0;              // Hardly a switch!
          strcat_s(s,256,"*2"); }
        else if ((sib & 0xC0)==0x80)
          strcat_s(s,256,"*4");
        else if ((sib & 0xC0)==0xC0) {
          da->jmptable=0;              // Hardly a switch!
          strcat_s(s,256,"*8");
        };
      };
      Memadr(seg,s,addr,dsize);
    };
  }
  // Last possibility: 32-bit address without SIB byte.
  else {                               // No SIB
    if ((c & 0xC0)==0x40) {
      dispsize=1;
      if (size<3) da->error=DAE_CROSS; // Disp8 outside the memory block
      else {
        da->adrconst=addr=(signed char)cmd[2];
        if (addr==0) da->zeroconst=1;
      }; }
    else if ((c & 0xC0)==0x80) {
      dispsize=4;
      if (size<6)
        da->error=DAE_CROSS;           // Disp32 outside the memory block
      else {
        da->adrconst=addr=*(ulong *)(cmd+2);
        if (pfixup==NULL) pfixup=cmd+2;
        da->fixupsize+=4;
        if (addr==0) da->zeroconst=1;
        if (type==MRJ) da->jmptable=addr;
      };
    };
    da->indexed=1;
    if (mode>=DISASM_FILE && da->error==DAE_NOERR) {
      seg=addr32[c & 0x07].defseg;
      Memadr(seg,addr32[c & 0x07].descr,addr,dsize);
    };
  };
};


/*-------------------------------------------------------------------------------------
	Function		: DecodeSO
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam + Vilas Suvarnakar
	Description		: Disassemble implicit source of string operations and, if available, dump
					  address and contents.
--------------------------------------------------------------------------------------*/
void CMaxDisassem::DecodeSO(void) {
  if (mode<DISASM_FILE) return;        // No need to decode
  if (datasize==1) da->memtype=DEC_BYTE;
  else if (datasize==2) da->memtype=DEC_WORD;
  else if (datasize==4) da->memtype=DEC_DWORD;
  da->indexed=1;
  Memadr(SEG_DS,regname[addrsize==2?1:2][REG_ESI],0L,datasize);
};


/*-------------------------------------------------------------------------------------
	Function		: DecodeDE
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam + Vilas Suvarnakar
	Description		: Disassemble implicit destination of string operations and, if available,
					  dump address and contents. Destination always uses segment ES, and this
					  setting cannot be overridden.
--------------------------------------------------------------------------------------*/
void CMaxDisassem::DecodeDE(void) {
  int seg = 0x00 ;

  if (mode<DISASM_FILE) return;        // No need to decode
  if (datasize==1) da->memtype=DEC_BYTE;
  else if (datasize==2) da->memtype=DEC_WORD;
  else if (datasize==4) da->memtype=DEC_DWORD;
  da->indexed=1;
  seg=segprefix; segprefix=SEG_ES;     // Fake Memadr by changing segment prefix
  Memadr(SEG_DS,regname[addrsize==2?1:2][REG_EDI],0L,datasize);
  segprefix=seg;                       // Restore segment prefix
};


/*-------------------------------------------------------------------------------------
	Function		: DecodeXL
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam + Vilas Suvarnakar
	Description		: Decode XLAT operand and, if available, dump address and contents.
--------------------------------------------------------------------------------------*/
void CMaxDisassem::DecodeXL(void) {
  if (mode<DISASM_FILE) return;        // No need to decode
  da->memtype=DEC_BYTE;
  da->indexed=1;
  Memadr(SEG_DS,(addrsize==2?"BX+AL":"EBX+AL"),0L,1);
};


/*-------------------------------------------------------------------------------------
	Function		: DecodeIM
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam + Vilas Suvarnakar
	Description		: Decode immediate operand of size constsize. If sxt is non-zero, byte operand
					 should be sign-extended to sxt bytes. If type of immediate constant assumes
					 this, small negative operands may be displayed as signed negative numbers.
					 Note that in most cases immediate operands are not shown in comment window.
--------------------------------------------------------------------------------------*/
void CMaxDisassem::DecodeIM(int constsize,int sxt,int type) {
  int i = 0x00 ;
  signed long data = 0x00 ;
  ulong l = 0x00 ;
  char name[TEXTLEN] = {0}, comment[TEXTLEN] = {0} ;

  immsize+=constsize;                    // Allows several immediate operands
  if (mode<DISASM_DATA) return;
  l=1+hasrm+hassib+dispsize+(immsize-constsize);
  data=0;
  if (size<l+constsize)
    da->error=DAE_CROSS;
  else if (constsize==1) {
    if (sxt==0) data=(uchar)cmd[l];
    else data=(signed char)cmd[l];
    if (type==IMS && ((data & 0xE0)!=0 || data==0)) {
      da->warnings|=DAW_SHIFT;
      da->cmdtype|=C_RARE;
    }; }
  else if (constsize==2) {
    if (sxt==0) data=*(ushort *)(cmd+l);
    else data=*(short *)(cmd+l); }
  else {
    data=*(long *)(cmd+l);
    if (pfixup==NULL) pfixup=cmd+l;
    da->fixupsize+=4; };
  if (sxt==2) data&=0x0000FFFF;
  if (data==0 && da->error==0) da->zeroconst=1;
  // Command ENTER, as an exception from Intel's rules, has two immediate
  // constants. As the second constant is rarely used, I exclude it from
  // search if the first constant is non-zero (which is usually the case).
  if (da->immconst==0)
    da->immconst=data;
  if (mode>=DISASM_FILE && da->error==DAE_NOERR) {
    if (mode>=DISASM_CODE && type!=IMU)
      i=Decodeaddress(data,name,TEXTLEN-nresult-24,comment);
    else {
      i=0; comment[0]='\0'; };
    if (i!=0 && symbolic!=0) {
      strcpy_s(da->result+nresult,256-nresult,name); nresult+=i; }
    else if (type==IMU || type==IMS || type==IM2 || data>=0 || data<NEGLIMIT)
      nresult+=sprintf_s(da->result+nresult,256-nresult,"%lX",data);
    else
      nresult+=sprintf_s(da->result+nresult,256-nresult,"-%lX",-data);
    if (addcomment && comment[0]!='\0') strcpy_s(da->comment,256,comment);
  };
};

/*-------------------------------------------------------------------------------------
	Function		: DecodeVX
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam + Vilas Suvarnakar
	Description		: Decode VxD service name (always 4-byte).
--------------------------------------------------------------------------------------*/
void CMaxDisassem::DecodeVX(void) {
  ulong l = 0x00,data = 0x00 ;
  
  immsize+=4;                          // Allows several immediate operands
  if (mode<DISASM_DATA) return;
  l=1+hasrm+hassib+dispsize+(immsize-4);
  if (size<l+4) {
    da->error=DAE_CROSS;
    return; };
  data=*(long *)(cmd+l);
  if (data==0 && da->error==0) da->zeroconst=1;
  if (da->immconst==0)
    da->immconst=data;
  if (mode>=DISASM_FILE && da->error==DAE_NOERR) {
    if ((data & 0x00008000)!=0 && _memicmp("VxDCall",da->result,7)==0)
      memcpy(da->result,lowercase?"vxdjump":"VxDJump",7);
    nresult+=sprintf_s(da->result+nresult,256-nresult,"%lX",data);
  };
};


/*-------------------------------------------------------------------------------------
	Function		: DecodeC1
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam + Vilas Suvarnakar
	Description		: Decode implicit constant 1 (used in shift commands). This operand is so
					  insignificant that it is never shown in comment window.
--------------------------------------------------------------------------------------*/
void CMaxDisassem::DecodeC1(void) {
  if (mode<DISASM_DATA) return;
  da->immconst=1;
  if (mode>=DISASM_FILE) nresult+=sprintf_s(da->result+nresult,256-nresult,"1");
};

/*-------------------------------------------------------------------------------------
	Function		: DecodeIA
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam + Vilas Suvarnakar
	Description		: Decode immediate absolute data address. This operand is used in 8080-
					  compatible commands which allow to move data from memory to accumulator and
					  back. Note that bytes ModRM and SIB never appear in commands with IA operand.
--------------------------------------------------------------------------------------*/
void CMaxDisassem::DecodeIA(void) {
  ulong addr = 0x00 ;

  if (size<1+addrsize) {
    da->error=DAE_CROSS; return; };
  dispsize=addrsize;
  if (mode<DISASM_DATA) return;
  if (datasize==1) da->memtype=DEC_BYTE;
  else if (datasize==2) da->memtype=DEC_WORD;
  else if (datasize==4) da->memtype=DEC_DWORD;
  if (addrsize==2)
    addr=*(ushort *)(cmd+1);
  else {
    addr=*(ulong *)(cmd+1);
    if (pfixup==NULL) pfixup=cmd+1;
    da->fixupsize+=4; };
  da->adrconst=addr;
  if (addr==0) da->zeroconst=1;
  if (mode>=DISASM_FILE) {
    Memadr(SEG_DS,"",addr,datasize);
  };
};


/*-------------------------------------------------------------------------------------
	Function		: DecodeRJ
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam + Vilas Suvarnakar
	Description		: Decodes jump relative to nextip of size offsize.
--------------------------------------------------------------------------------------*/
void CMaxDisassem::DecodeRJ(ulong offsize,ulong nextip) {
  int i = 0x00 ;
  ulong addr = 0x00 ;
  char s[TEXTLEN] = {0} ;
  
  if (size<offsize+1) {
    da->error=DAE_CROSS; return; };
  dispsize=offsize;                    // Interpret offset as displacement
  if (mode<DISASM_DATA) return;
  if (offsize==1)
    addr=(signed char)cmd[1]+nextip;
  else if (offsize==2)
    addr=*(signed short *)(cmd+1)+nextip;
  else
    addr=*(ulong *)(cmd+1)+nextip;
  if (datasize==2)
    addr&=0xFFFF;
  da->jmpconst=addr;
  if (addr==0) da->zeroconst=1;
  if (mode>=DISASM_FILE) {
    if (offsize==1) nresult+=sprintf_s(da->result+nresult,256-nresult,
      "%s ",(lowercase==0?"SHORT":"short"));
    if (mode>=DISASM_CODE)
      i=Decodeaddress(addr,s,TEXTLEN,da->comment);
    else
      i=0;
    if (symbolic==0 || i==0)
      nresult+=sprintf_s(da->result+nresult,256-nresult,"%08lX",addr);
    else
      nresult+=sprintf_s(da->result+nresult,256-nresult,"%.*s",TEXTLEN-nresult,s);
    if (symbolic==0 && i!=0 && da->comment[0]=='\0')
      strcpy_s(da->comment,256,s);
    ;
  };
};

/*-------------------------------------------------------------------------------------
	Function		: DecodeJF
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam + Vilas Suvarnakar
	Description		: Decode immediate absolute far jump address. In flat model, such addresses
					 are not used (mostly because selector is specified directly in the command),
					 so I neither decode as symbol nor comment it. To allow search for selector
					 by value, I interprete it as an immediate constant.
--------------------------------------------------------------------------------------*/
void CMaxDisassem::DecodeJF(void) {
  ulong addr = 0x00 ,seg = 0x00 ;

  if (size<1+addrsize+2) {
    da->error=DAE_CROSS; return; };
  dispsize=addrsize; immsize=2;        // Non-trivial but allowed interpretation
  if (mode<DISASM_DATA) return;
  if (addrsize==2) {
    addr=*(ushort *)(cmd+1);
    seg=*(ushort *)(cmd+3); }
  else {
    addr=*(ulong *)(cmd+1);
    seg=*(ushort *)(cmd+5); };
  da->jmpconst=addr;
  da->immconst=seg;
  if (addr==0 || seg==0) da->zeroconst=1;
  if (mode>=DISASM_FILE) {
    nresult+=sprintf_s(da->result+nresult,256-nresult,"%s %04X:%08X",
    (lowercase==0?"FAR":"far"),seg,addr);
  };
};


/*-------------------------------------------------------------------------------------
	Function		: DecodeSG
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam + Vilas Suvarnakar
	Description		: Decode segment register. In flat model, operands of this type are seldom.
--------------------------------------------------------------------------------------*/
void CMaxDisassem::DecodeSG(int index) {
  int i = 0x00 ;

  if (mode<DISASM_DATA) return;
  index&=0x07;
  if (index>=6) softerror=DAE_BADSEG;  // Undefined segment register
  if (mode>=DISASM_FILE) {
    i=sprintf_s(da->result+nresult,256-nresult,"%s",segname[index]);
    if (lowercase) _strlwr_s(da->result+nresult,256-nresult);
    nresult+=i;
  };
};


/*-------------------------------------------------------------------------------------
	Function		: DecodeCR
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam + Vilas Suvarnakar
	Description		: Decode control register addressed in R part of ModRM byte. Operands of
					 this type are extremely rare. Contents of control registers are accessible
					 only from privilege level 0, so I cannot dump them here.
--------------------------------------------------------------------------------------*/
void CMaxDisassem::DecodeCR(int index) {
  hasrm=1;
  if (mode>=DISASM_FILE) {
    index=(index>>3) & 0x07;
    nresult+=sprintf_s(da->result+nresult,256-nresult,"%s",crname[index]);
    if (lowercase) _strlwr_s(da->result+nresult,256-nresult);
  };
};


/*-------------------------------------------------------------------------------------
	Function		: DecodeDR
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam + Vilas Suvarnakar
	Description		: Decode debug register addressed in R part of ModRM byte. Operands of
					 this type are extremely rare. I can dump only those debug registers
					 available in CONTEXT structure..
--------------------------------------------------------------------------------------*/
void CMaxDisassem::DecodeDR(int index) {
  int i = 0x00 ;

  hasrm=1;
  if (mode>=DISASM_FILE) {
    index=(index>>3) & 0x07;
    i=sprintf_s(da->result+nresult,256-nresult,"%s",drname[index]);
    if (lowercase) _strlwr_s(da->result+nresult,256-nresult);
    nresult+=i;
  };
};


/*-------------------------------------------------------------------------------------
	Function		: Get3dnowsuffix
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam + Vilas Suvarnakar
	Description		: Skips 3DNow! operands and extracts command suffix. Returns suffix or -1 if
					 suffix lies outside the memory block. This subroutine assumes that cmd still
					 points to the beginning of 3DNow! command (i.e. to the sequence of two bytes
					 0F, 0F).
--------------------------------------------------------------------------------------*/
int CMaxDisassem::Get3dnowsuffix(void) {
  int c = 0x00, sib = 0x00 ;
  ulong offset = 0x00 ;

  if (size<3) return -1;               // Suffix outside the memory block
  offset=3;
  c=cmd[2] & 0xC7;                     // Leave only Mod and M fields
  // Register in ModM - general-purpose, MMX or 3DNow!
  if ((c & 0xC0)==0xC0)
    ;
  // 16-bit addressing mode, SIB byte is never used here.
  else if (addrsize==2) {
    if (c==0x06)                       // Special case of immediate address
      offset+=2;
    else if ((c & 0xC0)==0x40)         // 8-bit signed displacement
      offset++;
    else if ((c & 0xC0)==0x80)         // 16-bit unsigned displacement
      offset+=2;
    ; }
  // Immediate 32-bit address.
  else if (c==0x05)                    // Special case of immediate address
    offset+=4;
  // 32-bit address with SIB byte.
  else if ((c & 0x07)==0x04) {         // SIB addresation
    if (size<4) return -1;             // Suffix outside the memory block
    sib=cmd[3]; offset++;
    if (c==0x04 && (sib & 0x07)==0x05)
      offset+=4;                       // Immediate address without base
    else if ((c & 0xC0)==0x40)         // 8-bit displacement
      offset+=1;
    else if ((c & 0xC0)==0x80)         // 32-bit dislacement
      offset+=4;
    ; }
  // 32-bit address without SIB byte
  else if ((c & 0xC0)==0x40)
    offset+=1;
  else if ((c & 0xC0)==0x80)
    offset+=4;
  if (offset>=size) return -1;         // Suffix outside the memory block
  return cmd[offset];
};


/*-------------------------------------------------------------------------------------
	Function		: Checkcondition
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam + Vilas Suvarnakar
	Description		: Function checks whether 80x86 flags meet condition set in the command.
					 Returns 1 if condition is met, 0 if not and -1 in case of error (which is
					 not possible).
--------------------------------------------------------------------------------------*/
int	CMaxDisassem::Checkcondition(int code,ulong flags)
{
  ulong cond = 0x00,temp = 0x00 ;

  switch (code & 0x0E) {
    case 0:                            // If overflow
      cond=flags & 0x0800; break;
    case 2:                            // If below
      cond=flags & 0x0001; break;
    case 4:                            // If equal
      cond=flags & 0x0040; break;
    case 6:                            // If below or equal
      cond=flags & 0x0041; break;
    case 8:                            // If sign
      cond=flags & 0x0080; break;
    case 10:                           // If parity
      cond=flags & 0x0004; break;
    case 12:                           // If less
      temp=flags & 0x0880;
      cond=(temp==0x0800 || temp==0x0080); break;
    case 14:                           // If less or equal
      temp=flags & 0x0880;
      cond=(temp==0x0800 || temp==0x0080 || (flags & 0x0040)!=0); break;
    default: return -1;                // Internal error, not possible!
  };
  if ((code & 0x01)==0) return (cond!=0);
  else return (cond==0);               // Invert condition
};

/*-------------------------------------------------------------------------------------
	Function		: Disasm
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam + Vilas Suvarnakar
	Description		: This functions gives the CPU instruction in form of Mnumonics - Opcode format.
--------------------------------------------------------------------------------------*/
ulong CMaxDisassem::Disasm(char *src,ulong srcsize,ulong srcip, t_disasm *disasm,int disasmmode)
{
	int i = 0,j = 0,isprefix = 0,is3dnow = 0,repeated = 0,operand = 0,mnemosize = 0,arg = 0;
	int temp=0 ;
	ulong u = 0,code = 0;
	int lockprefix = 0;                      // Non-zero if lock prefix present
	int repprefix = 0;                       // REPxxx prefix or 0
	int cxsize = 0;
	char name[TEXTLEN] = {0},*pname = NULL;
	const t_cmddata *pd = {0},*pdan = {0};
	// Prepare disassembler variables and initialize structure disasm.
	datasize=addrsize=4;                 // 32-bit code and data segments only!
	segprefix=SEG_UNDEF;
	hasrm=hassib=0; dispsize=immsize=0;
	lockprefix=0; repprefix=0;
	ndump=0; nresult=0;

	cmd = NULL ;

	cmd=src; size=srcsize; pfixup=NULL;
	softerror=0; is3dnow=0;
	da=disasm;
	da->ip=srcip;
	da->comment[0]='\0';
	da->cmdtype=C_BAD; da->nprefix=0;
	da->memtype=DEC_UNKNOWN; da->indexed=0;
	da->jmpconst=0; da->jmptable=0;
	da->adrconst=0; da->immconst=0;
	da->zeroconst=0;
	da->fixupoffset=0; da->fixupsize=0;
	da->warnings=0;
	da->error=DAE_NOERR;
	memset(da->result,0,sizeof(da->result));

	mode=disasmmode;                     // No need to use register contents
	// Correct 80x86 command may theoretically contain up to 4 prefixes belonging
	// to different prefix groups. This limits maximal possible size of the
	// command to MAXCMDSIZE=16 bytes. In order to maintain this limit, if
	// Disasm() detects second prefix from the same group, it flushes first
	// prefix in the sequence as a pseudocommand.
	u=0; repeated=0;
	while (size>0) {
		isprefix=1;                        // Assume that there is some prefix
		switch (*cmd) {
	  case 0x26: if (segprefix==SEG_UNDEF) segprefix=SEG_ES;
				 else repeated=1; break;
	  case 0x2E: if (segprefix==SEG_UNDEF) segprefix=SEG_CS;
				 else repeated=1; break;
	  case 0x36: if (segprefix==SEG_UNDEF) segprefix=SEG_SS;
				 else repeated=1; break;
	  case 0x3E: if (segprefix==SEG_UNDEF) segprefix=SEG_DS;
				 else repeated=1; break;
	  case 0x64: if (segprefix==SEG_UNDEF) segprefix=SEG_FS;
				 else repeated=1; break;
	  case 0x65: if (segprefix==SEG_UNDEF) segprefix=SEG_GS;
				 else repeated=1; break;
	  case 0x66: if (datasize==4) datasize=2;
				 else repeated=1; break;
	  case 0x67: if (addrsize==4) addrsize=2;
				 else repeated=1; break;
	  case 0xF0: if (lockprefix==0) lockprefix=0xF0;
				 else repeated=1; break;
	  case 0xF2: if (repprefix==0) repprefix=0xF2;
				 else repeated=1; break;
	  case 0xF3: if (repprefix==0) repprefix=0xF3;
				 else repeated=1; break;
	  default: isprefix=0; break; };
		  if (isprefix==0 || repeated!=0)
			  break;                           // No more prefixes or duplicated prefix
		  if (mode>=DISASM_FILE)
			  ndump+=sprintf_s(da->dump+ndump,256-ndump,"%02X:",*cmd);
		  da->nprefix++;
		  cmd++; srcip++; size--; u++; };
		  // We do have repeated prefix. Flush first prefix from the sequence.
		  if (repeated) {
			  if (mode>=DISASM_FILE) {
				  da->dump[3]='\0';                // Leave only first dumped prefix
				  da->nprefix=1;
				  switch (cmd[-(long)u]) {
	  case 0x26: pname=(char *)(segname[SEG_ES]); break;
	  case 0x2E: pname=(char *)(segname[SEG_CS]); break;
	  case 0x36: pname=(char *)(segname[SEG_SS]); break;
	  case 0x3E: pname=(char *)(segname[SEG_DS]); break;
	  case 0x64: pname=(char *)(segname[SEG_FS]); break;
	  case 0x65: pname=(char *)(segname[SEG_GS]); break;
	  case 0x66: pname="DATASIZE"; break;
	  case 0x67: pname="ADDRSIZE"; break;
	  case 0xF0: pname="LOCK"; break;
	  case 0xF2: pname="REPNE"; break;
	  case 0xF3: pname="REPE"; break;
	  default: pname="?"; break; };
		  nresult+=sprintf_s(da->result+nresult,256-nresult,"PREFIX %s:",pname);
		  if (lowercase) _strlwr_s(da->result,256);
		  if (extraprefix==0) strcpy_s(da->comment,256,"Superfluous prefix"); };
		  da->warnings|=DAW_PREFIX;
		  if (lockprefix) da->warnings|=DAW_LOCK;
		  da->cmdtype=C_RARE;
		  return 1;                          // Any prefix is 1 byte long
		  };
		  // If lock prefix available, display it and forget, because it has no
		  // influence on decoding of rest of the command.
		  if (lockprefix!=0) {
			  if (mode>=DISASM_FILE) nresult+=sprintf_s(da->result+nresult,256-nresult,"LOCK ");
			  da->warnings|=DAW_LOCK; };
			  // Fetch (if available) first 3 bytes of the command, add repeat prefix and
			  // find command in the command table.
			  code=0;
			  if (size>0) *(((char *)&code)+0)=cmd[0];
			  if (size>1) *(((char *)&code)+1)=cmd[1];
			  if (size>2) *(((char *)&code)+2)=cmd[2];
			  if (repprefix!=0)                    // RER/REPE/REPNE is considered to be
				  code=(code<<8) | repprefix;        // part of command.
			  if (decodevxd && (code & 0xFFFF)==0x20CD)
				  pd=&vxdcmd;                        // Decode VxD call (Win95/98)
			  else {
				  for (pd=cmddata; pd->mask!=0; pd++) {
					  if (((code^pd->code) & pd->mask)!=0) continue;
					  if (mode>=DISASM_FILE && shortstringcmds &&
						  (pd->arg1==MSO || pd->arg1==MDE || pd->arg2==MSO || pd->arg2==MDE))
						  continue;                      // Search short form of string command
					  break;
				  };
			  };
			  if ((pd->type & C_TYPEMASK)==C_NOW) {
				  // 3DNow! commands require additional search.
				  is3dnow=1;
				  j=Get3dnowsuffix();
				  if (j<0)
					  da->error=DAE_CROSS;
				  else {
					  for ( ; pd->mask!=0; pd++) {
						  if (((code^pd->code) & pd->mask)!=0) continue;
						  if (((uchar *)&(pd->code))[2]==j) break;
					  };
				  };
			  };
			  if (pd->mask==0) {                   // Command not found
				  da->cmdtype=C_BAD;
				  if (size<2) da->error=DAE_CROSS;
				  else da->error=DAE_BADCMD; }
			  else {                               // Command recognized, decode it
				  da->cmdtype=pd->type;
				  cxsize=datasize;                   // Default size of ECX used as counter
				  if (segprefix==SEG_FS || segprefix==SEG_GS || lockprefix!=0)
					  da->cmdtype|=C_RARE;             // These prefixes are rare
				  if (pd->bits==PR)
					  da->warnings|=DAW_PRIV;          // Privileged command (ring 0)
				  else if (pd->bits==WP)
					  da->warnings|=DAW_IO;            // I/O command
				  // Win32 programs usually try to keep stack dword-aligned, so INC ESP
				  // (44) and DEC ESP (4C) usually don't appear in real code. Also check for
				  // ADD ESP,imm and SUB ESP,imm (81,C4,imm32; 83,C4,imm8; 81,EC,imm32;
				  // 83,EC,imm8).
				  if (cmd[0]==0x44 || cmd[0]==0x4C ||
					  (size>=3 && (cmd[0]==0x81 || cmd[0]==0x83) &&
					  (cmd[1]==0xC4 || cmd[1]==0xEC) && (cmd[2] & 0x03)!=0)
					  ) {
						  da->warnings|=DAW_STACK;
						  da->cmdtype|=C_RARE; };
						  // Warn also on MOV SEG,... (8E...). Win32 works in flat mode.
						  if (cmd[0]==0x8E)
							  da->warnings|=DAW_SEGMENT;
						  // If opcode is 2-byte, adjust command.
						  if (pd->len==2) {
							  if (size==0) da->error=DAE_CROSS;
							  else {
								  if (mode>=DISASM_FILE)
									  ndump+=sprintf_s(da->dump+ndump,256-ndump,"%02X",*cmd);
								  cmd++; srcip++; size--;
							  }; };
							  if (size==0) da->error=DAE_CROSS;
							  // Some commands either feature non-standard data size or have bit which
							  // allowes to select data size.
							  if ((pd->bits & WW)!=0 && (*cmd & WW)==0)
								  datasize=1;                      // Bit W in command set to 0
							  else if ((pd->bits & W3)!=0 && (*cmd & W3)==0)
								  datasize=1;                      // Another position of bit W
							  else if ((pd->bits & FF)!=0)
								  datasize=2;                      // Forced word (2-byte) size
							  // Some commands either have mnemonics which depend on data size (8/16 bits
							  // or 32 bits, like CWD/CDQ), or have several different mnemonics (like
							  // JNZ/JNE). First case is marked by either '&' (mnemonic depends on
							  // operand size) or '$' (depends on address size). In the second case,
							  // there is no special marker and disassembler selects main mnemonic.
							  if (mode>=DISASM_FILE) {
								  if (pd->name[0]=='&') mnemosize=datasize;
								  else if (pd->name[0]=='$') mnemosize=addrsize;
								  else mnemosize=0;
								  if (mnemosize!=0) {
									  for (i=0,j=1; pd->name[j]!='\0'; j++) {
										  if (pd->name[j]==':') {      // Separator between 16/32 mnemonics
											  if (mnemosize==4) i=0;
											  else break; }
										  else if (pd->name[j]=='*') { // Substitute by 'W', 'D' or none
											  if (mnemosize==4 && sizesens!=2) name[i++]='D';
											  else if (mnemosize!=4 && sizesens!=0) name[i++]='W'; }
										  else name[i++]=pd->name[j];
									  };
									  name[i]='\0'; }
								  else {
									  strcpy_s(name,256,pd->name);
									  for (i=0; name[i]!='\0'; i++) {
										  if (name[i]==',') {          // Use main mnemonic
											  name[i]='\0'; break;
										  };
									  };
								  };
								  if (repprefix!=0 && tabarguments) {
									  for (i=0; name[i]!='\0' && name[i]!=' '; i++)
										  da->result[nresult++]=name[i];
									  if (name[i]==' ') {
										  da->result[nresult++]=' '; i++; };
										  while (nresult<8) da->result[nresult++]=' ';
										  for ( ; name[i]!='\0'; i++)
											  da->result[nresult++]=name[i];
										  ; }
								  else
									  nresult+=sprintf_s(da->result+nresult,256-nresult,"%s",name);
								  if (lowercase) _strlwr_s(da->result,256);
							  };
							  // Decode operands (explicit - encoded in command, implicit - present in
							  // mmemonic or assumed - used or modified by command). Assumed operands
							  // must stay after all explicit and implicit operands. Up to 3 operands
							  // are allowed.
							  for (operand=0; operand<3; operand++) {
								  if (da->error) break;            // Error - no sense to continue
								  // If command contains both source and destination, one usually must not
								  // decode destination to comment because it will be overwritten on the
								  // next step. Global addcomment takes care of this. Decoding routines,
								  // however, may ignore this flag.
								  if (operand==0 && pd->arg2!=NNN && pd->arg2<PSEUDOOP)
									  addcomment=0;
								  else
									  addcomment=1;
								  // Get type of next argument.
								  if (operand==0) arg=pd->arg1;
								  else if (operand==1) arg=pd->arg2;
								  else arg=pd->arg3;
								  if (arg==NNN) break;             // No more operands
								  // Arguments with arg>=PSEUDOOP are assumed operands and are not
								  // displayed in disassembled result, so they require no delimiter.
								  if ((mode>=DISASM_FILE) && arg<PSEUDOOP) {
									  if (operand==0) {
										  da->result[nresult++]=' ';
										  if (tabarguments) {
											  while (nresult<8) da->result[nresult++]=' ';
										  }; }
									  else {
										  da->result[nresult++]=',';
										  if (extraspace) da->result[nresult++]=' ';
									  };
								  };
								  // Decode, analyse and comment next operand of the command.
								  switch (arg) {
	  case REG:                      // Integer register in Reg field
		  if (size<2)
			  da->error=DAE_CROSS;
		  else 
		  {
			  temp = cmd[1] ;
			  temp = temp & 0x000000FF ;
			  temp = temp>>3 ;
			  DecodeRG(temp, datasize, REG );
			  //DecodeRG(cmd[1]>>3, datasize, REG );
		  }
		  hasrm=1; 
		  break;
	  case RCM:                      // Integer register in command byte
		  DecodeRG(cmd[0],datasize,RCM); break;
	  case RG4:                      // Integer 4-byte register in Reg field
		  if (size<2) da->error=DAE_CROSS;
		  else DecodeRG(cmd[1]>>3,4,RG4);
		  hasrm=1; break;
	  case RAC:                      // Accumulator (AL/AX/EAX, implicit)
		  DecodeRG(REG_EAX,datasize,RAC); break;
	  case RAX:                      // AX (2-byte, implicit)
		  DecodeRG(REG_EAX,2,RAX); break;
	  case RDX:                      // DX (16-bit implicit port address)
		  DecodeRG(REG_EDX,2,RDX); break;
	  case RCL:                      // Implicit CL register (for shifts)
		  DecodeRG(REG_ECX,1,RCL); break;
	  case RS0:                      // Top of FPU stack (ST(0))
		  DecodeST(0,0); break;
	  case RST:                      // FPU register (ST(i)) in command byte
		  DecodeST(cmd[0],0); break;
	  case RMX:                      // MMX register MMx
		  if (size<2) da->error=DAE_CROSS;
		  else DecodeMX(cmd[1]>>3);
		  hasrm=1; break;
	  case R3D:                      // 3DNow! register MMx
		  if (size<2) da->error=DAE_CROSS;
		  else DecodeNR(cmd[1]>>3);
		  hasrm=1; break;
	  case MRG:                      // Memory/register in ModRM byte
	  case MRJ:                      // Memory/reg in ModRM as JUMP target
	  case MR1:                      // 1-byte memory/register in ModRM byte
	  case MR2:                      // 2-byte memory/register in ModRM byte
	  case MR4:                      // 4-byte memory/register in ModRM byte
	  case MR8:                      // 8-byte memory/MMX register in ModRM
	  case MRD:                      // 8-byte memory/3DNow! register in ModRM
	  case MMA:                      // Memory address in ModRM byte for LEA
	  case MML:                      // Memory in ModRM byte (for LES)
	  case MM6:                      // Memory in ModRm (6-byte descriptor)
	  case MMB:                      // Two adjacent memory locations (BOUND)
	  case MD2:                      // Memory in ModRM byte (16-bit integer)
	  case MB2:                      // Memory in ModRM byte (16-bit binary)
	  case MD4:                      // Memory in ModRM byte (32-bit integer)
	  case MD8:                      // Memory in ModRM byte (64-bit integer)
	  case MDA:                      // Memory in ModRM byte (80-bit BCD)
	  case MF4:                      // Memory in ModRM byte (32-bit float)
	  case MF8:                      // Memory in ModRM byte (64-bit float)
	  case MFA:                      // Memory in ModRM byte (80-bit float)
	  case MFE:                      // Memory in ModRM byte (FPU environment)
	  case MFS:                      // Memory in ModRM byte (FPU state)
	  case MFX:                      // Memory in ModRM byte (ext. FPU state)
		  DecodeMR(arg); break;
	  case MMS:                      // Memory in ModRM byte (as SEG:OFFS)
		  DecodeMR(arg);
		  da->warnings|=DAW_FARADDR; break;
	  case RR4:                      // 4-byte memory/register (register only)
	  case RR8:                      // 8-byte MMX register only in ModRM
	  case RRD:                      // 8-byte memory/3DNow! (register only)
		  if ((cmd[1] & 0xC0)!=0xC0) softerror=DAE_REGISTER;
		  DecodeMR(arg); break;
	  case MSO:                      // Source in string op's ([ESI])
		  DecodeSO(); break;
	  case MDE:                      // Destination in string op's ([EDI])
		  DecodeDE(); break;
	  case MXL:                      // XLAT operand ([EBX+AL])
		  DecodeXL(); break;
	  case IMM:                      // Immediate data (8 or 16/32)
	  case IMU:                      // Immediate unsigned data (8 or 16/32)
		  if ((pd->bits & SS)!=0 && (*cmd & 0x02)!=0)
			  DecodeIM(1,datasize,arg);
		  else
			  DecodeIM(datasize,0,arg);
		  break;
	  case VXD:                      // VxD service (32-bit only)
		  DecodeVX(); break;
	  case IMX:                      // Immediate sign-extendable byte
		  DecodeIM(1,datasize,arg); break;
	  case C01:                      // Implicit constant 1 (for shifts)
		  DecodeC1(); break;
	  case IMS:                      // Immediate byte (for shifts)
	  case IM1:                      // Immediate byte
		  DecodeIM(1,0,arg); break;
	  case IM2:                      // Immediate word (ENTER/RET)
		  DecodeIM(2,0,arg);
		  if ((da->immconst & 0x03)!=0) da->warnings|=DAW_STACK;
		  break;
	  case IMA:                      // Immediate absolute near data address
		  DecodeIA(); break;
	  case JOB:                      // Immediate byte offset (for jumps)
		  DecodeRJ(1,srcip+2); break;
	  case JOW:                      // Immediate full offset (for jumps)
		  DecodeRJ(datasize,srcip+datasize+1); break;
	  case JMF:                      // Immediate absolute far jump/call addr
		  DecodeJF();
		  da->warnings|=DAW_FARADDR; break;
	  case SGM:                      // Segment register in ModRM byte
		  if (size<2) da->error=DAE_CROSS;
		  DecodeSG(cmd[1]>>3); hasrm=1; break;
	  case SCM:                      // Segment register in command byte
		  DecodeSG(cmd[0]>>3);
		  if ((da->cmdtype & C_TYPEMASK)==C_POP) da->warnings|=DAW_SEGMENT;
		  break;
	  case CRX:                      // Control register CRx
		  if ((cmd[1] & 0xC0)!=0xC0) da->error=DAE_REGISTER;
		  DecodeCR(cmd[1]); break;
	  case DRX:                      // Debug register DRx
		  if ((cmd[1] & 0xC0)!=0xC0) da->error=DAE_REGISTER;
		  DecodeDR(cmd[1]); break;
	  case PRN:                      // Near return address (pseudooperand)
		  break;
	  case PRF:                      // Far return address (pseudooperand)
		  da->warnings|=DAW_FARADDR; break;
	  case PAC:                      // Accumulator (AL/AX/EAX, pseudooperand)
		  DecodeRG(REG_EAX,datasize,PAC); break;
	  case PAH:                      // AH (in LAHF/SAHF, pseudooperand)
	  case PFL:                      // Lower byte of flags (pseudooperand)
		  break;
	  case PS0:                      // Top of FPU stack (pseudooperand)
		  DecodeST(0,1); break;
	  case PS1:                      // ST(1) (pseudooperand)
		  DecodeST(1,1); break;
	  case PCX:                      // CX/ECX (pseudooperand)
		  DecodeRG(REG_ECX,cxsize,PCX); break;
	  case PDI:                      // EDI (pseudooperand in MMX extentions)
		  DecodeRG(REG_EDI,4,PDI); break;
	  default:
		  da->error=DAE_INTERN;        // Unknown argument type
		  break;
								  };
							  };
							  // Check whether command may possibly contain fixups.
							  if (pfixup!=NULL && da->fixupsize>0)
								  da->fixupoffset=pfixup-src;
							  // Segment prefix and address size prefix are superfluous for command which
							  // does not access memory. If this the case, mark command as rare to help
							  // in analysis.
							  if (da->memtype==DEC_UNKNOWN &&
								  (segprefix!=SEG_UNDEF || (addrsize!=4 && pd->name[0]!='$'))
								  ) {
									  da->warnings|=DAW_PREFIX;
									  da->cmdtype|=C_RARE; };
									  // 16-bit addressing is rare in 32-bit programs. If this is the case,
									  // mark command as rare to help in analysis.
									  if (addrsize!=4) da->cmdtype|=C_RARE;
			  };
			  // Suffix of 3DNow! command is accounted best by assuming it immediate byte
			  // constant.
			  if (is3dnow) {
				  if (immsize!=0) da->error=DAE_BADCMD;
				  else immsize=1; };
				  // Right or wrong, command decoded. Now dump it.
				  if (da->error!=0) {                  // Hard error in command detected
					  if (mode>=DISASM_FILE)
						  nresult=sprintf_s(da->result,256,"???");
					  if (da->error==DAE_BADCMD &&
						  (*cmd==0x0F || *cmd==0xFF) && size>0
						  ) {
							  if (mode>=DISASM_FILE) ndump+=sprintf_s(da->dump+ndump,256-ndump,"%02X",*cmd);
							  cmd++; size--; };
							  if (size>0) {
								  if (mode>=DISASM_FILE) ndump+=sprintf_s(da->dump+ndump,256-ndump,"%02X",*cmd);
								  cmd++; size--;
							  }; }
				  else {                               // No hard error, dump command
					  if (mode>=DISASM_FILE) {
						  ndump+=sprintf_s(da->dump+ndump,256-ndump,"%02X",*cmd++);
						  if (hasrm) ndump+=sprintf_s(da->dump+ndump,256-ndump,"%02X",*cmd++);
						  if (hassib) ndump+=sprintf_s(da->dump+ndump,256-ndump,"%02X",*cmd++);
						  if (dispsize!=0) {
							  da->dump[ndump++]=' ';
							  for (i=0; i<dispsize; i++) {
								  ndump+=sprintf_s(da->dump+ndump,256-ndump,"%02X",*cmd++);
							  };
						  };
						  if (immsize!=0) {
							  da->dump[ndump++]=' ';
							  for (i=0; i<immsize; i++) {
								  ndump+=sprintf_s(da->dump+ndump,256-ndump,"%02X",*cmd++);
							  };
						  };
					  }
					  else
						  cmd+=1+hasrm+hassib+dispsize+immsize;
					  size-=1+hasrm+hassib+dispsize+immsize;
				  };
				  // Check that command is not a dangerous one.
				  if (mode>=DISASM_DATA) {
					  for (pdan=dangerous; pdan->mask!=0; pdan++) {
						  if (((code^pdan->code) & pdan->mask)!=0)
							  continue;
						  if (pdan->type==C_DANGERLOCK && lockprefix==0)
							  break;                         // Command harmless without LOCK prefix
						  if (iswindowsnt && pdan->type==C_DANGER95)
							  break;                         // Command harmless under Windows NT
						  // Dangerous command!
						  if (pdan->type==C_DANGER95) da->warnings|=DAW_DANGER95;
						  else da->warnings|=DAW_DANGEROUS;
						  break;
					  };
				  };
				  if (da->error==0 && softerror!=0)
					  da->error=softerror;               // Error, but still display command
				  if (mode>=DISASM_FILE) {
					  if (da->error!=DAE_NOERR) switch (da->error) {
	  case DAE_CROSS:
		  strcpy_s(da->comment,256,"Command crosses end of memory block"); break;
	  case DAE_BADCMD:
		  strcpy_s(da->comment,256,"Unknown command"); break;
	  case DAE_BADSEG:
		  strcpy_s(da->comment,256,"Undefined segment register"); break;
	  case DAE_MEMORY:
		  strcpy_s(da->comment,256,"Illegal use of register"); break;
	  case DAE_REGISTER:
		  strcpy_s(da->comment,256,"Memory address not allowed"); break;
	  case DAE_INTERN:
		  strcpy_s(da->comment,256,"Internal OLLYDBG error"); break;
	  default:
		  strcpy_s(da->comment,256,"Unknown error");
		  break; }
					  else if ((da->warnings & DAW_PRIV)!=0 && privileged==0)
						  strcpy_s(da->comment,256,"Privileged command");
					  else if ((da->warnings & DAW_IO)!=0 && iocommand==0)
						  strcpy_s(da->comment,256,"I/O command");
					  else if ((da->warnings & DAW_FARADDR)!=0 && farcalls==0) {
						  if ((da->cmdtype & C_TYPEMASK)==C_JMP)
							  strcpy_s(da->comment,256,"Far jump");
						  else if ((da->cmdtype & C_TYPEMASK)==C_CAL)
							  strcpy_s(da->comment,256,"Far call");
						  else if ((da->cmdtype & C_TYPEMASK)==C_RET)
							  strcpy_s(da->comment,256,"Far return");
						  ; }
					  else if ((da->warnings & DAW_SEGMENT)!=0 && farcalls==0)
						  strcpy_s(da->comment,256,"Modification of segment register");
					  else if ((da->warnings & DAW_SHIFT)!=0 && badshift==0)
						  strcpy_s(da->comment,256,"Shift constant out of range 1..31");
					  else if ((da->warnings & DAW_PREFIX)!=0 && extraprefix==0)
						  strcpy_s(da->comment,256,"Superfluous prefix");
					  else if ((da->warnings & DAW_LOCK)!=0 && lockedbus==0)
						  strcpy_s(da->comment,256,"LOCK prefix");
					  else if ((da->warnings & DAW_STACK)!=0 && stackalign==0)
						  strcpy_s(da->comment,256,"Unaligned stack operation");
					  ;
				  };
				  return (srcsize-size);               // Returns number of recognized bytes
};

/*-------------------------------------------------------------------------------------
	Function		: InitializeData
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam + Vilas Suvarnakar
	Description		: Initializes all the neccesary data required for disassembly.
--------------------------------------------------------------------------------------*/
void	CMaxDisassem::InitializeData()
{
	ideal=0;                // Force IDEAL decoding mode
	lowercase=0;            // Force lowercase display
	tabarguments=0;         // Tab between mnemonic and arguments
	extraspace=0;           // Extra space between arguments
	putdefseg=0;            // Display default segments in listing
	showmemsize=0;          // Always show memory size
	shownear=0;             // Show NEAR modifiers
	shortstringcmds=0;      // Use short form of string commands
	sizesens=0;             // How to decode size-sensitive mnemonics
	symbolic=0;             // Show symbolic addresses in disasm
	farcalls=0;             // Accept far calls, returns & addresses
	decodevxd=0;            // Decode VxD calls (Win95/98)
	privileged=0;           // Accept privileged commands
	iocommand=0;            // Accept I/O commands
	badshift=0;             // Accept shift out of range 1..31
	extraprefix=0;          // Accept superfluous prefixes
	lockedbus=0;            // Accept LOCK prefixes
	stackalign=0;           // Accept unaligned stack operations
	iswindowsnt=0;          // When checking for dangers, assume NT

	asmcmd = NULL;              // Pointer to 0-terminated source line
	scan = 0;                 // Type of last scanned element
	prio = 0;                 // Priority of operation (0: highest)
	ZeroMemory(sdata,sizeof(sdata));       // Last scanned name (depends on type)
	idata = 0;                // Last scanned value
	fdata = 0;         // Floating-point number
	asmerror = NULL;        // Explanation of last error, or NULL

	datasize=0;             // Size of data (1,2,4 bytes)
	addrsize=0;             // Size of address (2 or 4 bytes)
	segprefix=0;            // Segment override prefix or SEG_UNDEF
	hasrm=0;                // Command has ModR/M byte
	hassib=0;               // Command has SIB byte
	dispsize=0;             // Size of displacement (if any)
	immsize=0;              // Size of immediate data (if any)
	softerror=0;            // Noncritical disassembler error
	ndump=0;                // Current length of command dump
	nresult=0;              // Current length of disassembly
	addcomment=0;           // Comment value of operand

	// Copy of input parameters of function Disasm()
	cmd = NULL;                 // Pointer to binary data
	pfixup = NULL;              // Pointer to possible fixups or NULL
	size=0;                 // Remaining size of the command buffer
	da = NULL;                  // Pointer to disassembly results
	mode=0;                 // Disassembly mode (DISASM_xxx)
}
