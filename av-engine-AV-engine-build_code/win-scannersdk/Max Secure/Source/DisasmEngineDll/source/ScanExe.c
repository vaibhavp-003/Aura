#include <windows.h>

#include <io.h>
#include <stdio.h>
#include <stdlib.h>
#include "ctype.h"
#include "string.h"
#include <math.h>
#include <conio.h>

#include <dos.h>
#include <fcntl.h>

#include "peformat.h"

#define UNKNOWN		-1
#define VI_COM		5
#define VI_EXE		6
#define VI_NE		7
#define VI_LE		8
#define	VI_PE		9
#define VI_DOC		10
#define VI_XLS		11
#define VI_DOC97	12
#define VI_XLS97	13
#define VI_PPT97	14
#define VI_EMBEDDED 15
#define VI_ELF		16

#define		VIRUSNAMELENGTH 		128
#define		EXECUTIONPATHLENGTH		2048

#include "scan.h"

// Link list structure 
#pragma pack  ( 1 )
typedef struct node
{
	char			* Ptr ;
	struct node*	Zero ; // Left 
	struct node*	One ;  // Right 
} BinaryTreeNode ;
#pragma pack  ( )

extern BinaryTreeNode Header ;

#define MIN_INSTRUCTION		32
#define MAX_INSTRUCTION		128

//===============================================================================
/*		Tokens used :
		A	sreg2
		B	Branch bit,this is already used for branch instruction
		C	reg1
		D	reg2
		E	reg
		F	eee
		G	ST(i)
		H	tttn
		I	type
		J	port number
		K	fulld
		L	unsigned full offset, selector
		M	mod
		N	r/m
		O	idata
		P	imm8 and imm8 data
		Q	8-bit displ and 8 bit
		R	R
		s	s
		T	16-bit displ
		w	w
		Z	sreg3
		d	d

*/

unsigned char * BootPtr = NULL ;
static long int Count = 0 ;

/*
Name		: BootRead
Description : Reads data from a memory.
Parameters	:
1. Buffer	: ( OUT ) Data read from memory pointer.
2. Bytes	: ( IN )  Number of bytes to read.
3. BytesRead: ( OUT ) Number of bytes read.
4. MemPtrLength	: ( IN )  Size of memory pointer.

Return Value : TRUE
*/

unsigned long int BootRead ( unsigned char * Buffer , DWORD Bytes , DWORD * BytesRead , unsigned long int MemPtrLength )
{
	unsigned long int RetVal = 0 ;
	DWORD	i ;

	* BytesRead = 0 ;

	for ( i = 0 ; i < Bytes ; i ++ )
	{
		if ( Count <= ( signed long int ) MemPtrLength )
		{
			Buffer [ i ] = * BootPtr ;
			( * BytesRead ) ++ ;
			Count ++ ;
			BootPtr ++ ;
		}
		else
			break ;
	}
	Buffer [ i ] = '\0' ;

	return ( RetVal ) ;

}//BootRead

/*
Name		: Lseek
Description : Seeks to desired position in a file or memory buffer.
			  If memory buffer is NULL then operation is performed on file.
Parameters	:
	1. handle		: ( IN ) File handle.
	2. FileOffset	: ( IN ) Number of bytes from initial position.
	3. FromWhere	: ( IN ) Initial position.
	4. FilePos		: ( OUT ) New position from beginning of the file or memory buffer.
	5. MemPtr		: ( IN ) Memory buffer.
	6. MemPtrLength	: ( IN ) Memory buffer length.
Return Value : TRUE
*/

unsigned long int Lseek ( HANDLE handle , LARGE_INTEGER FileOffset , DWORD dwMoveMethod ,
				LARGE_INTEGER * FilePos , char * MemPtr , unsigned long int MemPtrLength )
{
	LARGE_INTEGER CurrentFileOffset ;

	CurrentFileOffset . QuadPart = 0 ;

	if ( MemPtr == NULL )
	{
		SetFilePointerEx ( handle , FileOffset , FilePos , dwMoveMethod ) ;
	}
	else
	{
		FilePos -> QuadPart = CurrentFileOffset . QuadPart + FileOffset . QuadPart ;
		if ( FilePos -> QuadPart < MemPtrLength )
		{
			BootPtr = ( unsigned char * ) MemPtr;
			BootPtr += FilePos -> QuadPart ;
			Count = ( long ) FilePos -> QuadPart ;
		}
		else
		{
			return ( 1 ) ;
		}
	}

	return ( 0 ) ;

}//Lseek


/*------------------------------------------------

	Name		: Read
	Description : Reads from file or a memory buffer.
				  if memory buffer is NULL then reads from file.
	Parameters	:
		1. FileHandle	: ( IN ) File handle.
		2. Buffer		: ( IN ) Holds data read from file or memory buffer.
		3. Bytes		: ( IN ) Bytes to read.
		4. BytesRead	: ( OUT ) Actual bytes read.
		5. MemPtr		: ( IN ) Memory buffer.
		6. MemPtrLength	: ( IN ) Memory buffer length.
	Return Value : TRUE

--------------------------------------------------*/

unsigned long int Read ( HANDLE FileHandle , unsigned char * Buffer , DWORD Bytes , 
				DWORD * BytesRead , void * MemPtr , unsigned long int MemPtrLength )
{
	if ( MemPtr == NULL )
	{
		ReadFile ( FileHandle , Buffer , Bytes , BytesRead , NULL ) ;
	}
	else
	{
		BootRead ( Buffer , Bytes , BytesRead , MemPtrLength ) ;
		if ( Buffer [ 0 ] == '\0' )
		{
		}
	}

	return ( 0 ) ;

}//Read

/*------------------------------------------------

	Name		: atoh
	Description : Converts character from Decimal to Hexadecimal.
	Parameters	:
		1. Output	: ( OUT ) Hexadecimal number.
		2. c		: ( IN ) Decimal number.
	Return Value : None

--------------------------------------------------*/

void atoh ( char * OutPut , unsigned char c )
{
	unsigned char		quo , rem ;
	signed short int	i , j ;
	char	temp[ 4 ] ;

	memset ( temp , 0 , sizeof ( temp ) ) ;

	quo = c ;
	i = 0 ;

	while ( quo >= 16 )
	{
		rem = quo % 16 ;
		if ( rem == 0 )
			rem = '0' ;

		quo = quo / 16 ;
		OutPut [ i ] = rem ;
		i++ ;
	}

	if ( quo == 0 )
		quo = '0' ;

	OutPut [ i ] = quo ;
	i++ ;
	OutPut [ i ] =  '\0' ;

	j = 0 ;

	for ( i = ( (short)strlen ( OutPut ) - 1 ) ; i >= 0 ; i -- )
	{
		 temp [ j ] = OutPut [ i ] ;
		 j++ ;
	}

	strcpy ( OutPut , temp ) ;

	for ( i = 0 ; i < strlen ( OutPut ) ; i++ )
	{
		if ( ( OutPut [ i ] >= 10 ) && ( OutPut [ i ] <= 15 ) )
		{
			OutPut [ i ] += 55 ; //For 10 to 15
		}

		if ( ( OutPut [ i ] >= 1 ) && ( OutPut [ i ] <= 9 ) ) 
		{
			OutPut [ i ] += 48 ; //For 1 to 9
		}
		
	}

}//atoh

/*------------------------------------------------

	Name		: FieldOperation
	Description : If any field is found ( eg. mod,reg1,sreg2.... )
				  increment appropriate position in the input for compare
				  eg. if sreg2 is found , then as sreg2 is of 2 bits , increment by 2
	Parameters	:
		1. Source		: ( IN ).
		2. i			: ( IN ).
		3. j			: ( IN ).
		4. wBit			: ( OUT ).
		5. sBit			: ( OUT ).
		6. Input		: ( IN ).
		7. ModBuffer	: ( OUT ).
		8. RmBuffer		: ( OUT ).
		9. Mode			: ( OUT ).
		10. Sreg2Flag	: ( OUT ).
		11. ModBit		: ( OUT ).
	Return Value : None

--------------------------------------------------*/

void FieldOperation ( char * Source , signed short int * i , signed short int * j , signed short int * wBit ,
					  signed short int * sBit , unsigned char * Input , char ModBuffer [ 3 ] ,
					  char * RmBuffer , signed short int Mode , signed short int * Sreg2Flag ,
					  signed short int * ModBit , unsigned char AddressSize , unsigned char OperandSize )
{
	signed short int Value = 0 ;
	char SregBuf [ 3 ] , OpCode ;

	/////////02/04/2002
	if ( OperandSize == TRUE )
	{
		if ( Mode == 16 )
			Mode = 32 ;
		else
			Mode = 16 ;
	}
	/////////

	OpCode = Source [ * j ] ;

	switch ( OpCode )
	{
		case 'w' :
				//if source contains w field , get appropriate value from input
				if ( Input [ * i ] == '0' )
					* wBit = 0 ;
				else
					* wBit = 1 ;

				( * i ) ++ ;
				* j = * j + 2 ;
				return ;

		case 's' :
				//if source contains only s field & not sreg3 field
				if ( Input [ * i ] == '0' )
					* sBit = 0 ;
				else
					* sBit = 1 ;

				( * i ) ++ ;
				( * j ) ++ ;
				return ;

		case 'd' :
				//if source contains only d field & not data field
				( * i ) ++ ;
				( * j ) ++ ;
				return ;

		case 'R' :
				//if source contains R field
				( * i ) ++ ;
				( * j ) ++ ;
				return ;

		case 'A' :
				//if sreg2
				SregBuf [ 0 ] = Input [ ( * i ) ++ ] ;
				SregBuf [ 1 ] = Input [ ( * i ) ++ ] ;
				SregBuf [ 2 ] = '\0' ;

				if ( * ( ( unsigned short int * ) SregBuf ) == 0x3130 )	//if SregBuf = 01
					* Sreg2Flag = 0xFF ;

				* j = * j + 2 ;
				return ;

		case 'Z' :
		case 'C' :
		case 'D' :
		case 'E' :
		case 'F' :
		case 'G' :
				//if reg2 or reg1 or sreg3 or reg or eee or ST(i)
				* i = *  i + 3 ;
				* j = * j + 2 ;
				return ;

		case 'H' :
				//if tttn
				* i = * i + 4 ;
				* j = * j + 2 ;
				return ;

		case 'I' :
		case 'J' :
				//if type or port number
				* i = * i+ 8 ;
				* j = * j + 2 ;
				return ;

		case 'T' :
				//if 16-bit displacement
				* i = * i + 16 ;	// 16 added b'caz of 16-bit displacement
				* j = * j + 2 ;
				return ;

		case 'Q' :
				//if 8-bit displacement
				* i = * i + 8 ;		//8 added b'caz of 8-bit displacement
				* j = * j + 2 ;
				return ;

		case 'K' :
				//if fulld
				* i = * i + Mode ;	//for 16-bit data mode=16, for 32-bit mode=32
				* j = * j + 2 ;
				return ;

		case 'L' :
				//if unsigned full offset, selector
				//for 16-bit, offset = 16 bits, selector = 16 bits
				//for 32-bit, offset = 32 bits, selector = 16 bits

				* i = * i + Mode + 16 ;
				* j = * j + 2 ;
				return ;

		case 'M' :
				//if mod,
				//get consecutive 2 bits of input from current position in modbuffer
				* ModBit = 1 ;
				ModBuffer [ 0 ] = Input [ ( * i ) ++ ] ;
				ModBuffer [ 1 ] = Input [ ( * i ) ++ ] ;
				ModBuffer [ 2 ] = '\0' ;

				* j = * j + 2 ;
				return ;

		case 'N' :
				//if r/m,
				//get consecutive 3 bits of input from current position in rmbuffer
				RmBuffer [ 0 ] = Input [ ( * i ) ++ ] ;
				RmBuffer [ 1 ] = Input [ ( * i ) ++ ] ;
				RmBuffer [ 2 ] = Input [ ( * i ) ++ ] ;
				RmBuffer [ 3 ] = '\0' ;

				//For look up table refer to TABAK page no 217 and 218
				if ( 16 == Mode )
				{
					if ( * ( ( unsigned short int * ) ModBuffer ) == 0x3030 )	//If ModBuffer = 00
					{
						//if mod = 00 & r/m = 110 then 2 bytes are added  
						if ( RmBuffer [ 0 ] == '1' && RmBuffer [ 1 ] == '1' &&
							 RmBuffer [ 2 ] == '0' )
						{
							Value = 2 ;
						}
					}

					//if mod = 01 , 1 byte is added irrespective of r/m
					if ( * ( ( unsigned short int * ) ModBuffer ) == 0x3130 )
						Value = 1 ;

					//if mod = 10 , 2 byte is added irrespective of r/m
					if ( * ( ( unsigned short int * ) ModBuffer ) == 0x3031 )
						Value = 2 ;
				}

				//for 32 bit, s-i-b byte is also present in some cases 
				//lookup table of s-i-b is given in the TABAK page no 218
				if ( 32 == Mode )
				{
					//if mod = 11 then no byte is added
					if ( * ( ( unsigned short int * ) ModBuffer ) != 0x3131 )
					{
						if ( * ( ( unsigned short int * ) ModBuffer ) == 0x3030 )	//mod = 00
						{
							//if mod = 00 & r/m = 101, 4 bytes are added
							if ( RmBuffer [ 0 ] == '1' && RmBuffer [ 1 ] == '0' &&
								 RmBuffer [ 2 ] == '1' )
							{
								Value = 4 ;
							}
							else
							{
								if ( RmBuffer [ 0 ] == '1' && RmBuffer [ 1 ] == '0' &&
									 RmBuffer [ 2 ] == '0')
								{
									//if mod = 00 & r/m = 100 ,s-i-b byte present
									//take 3 bits from input . This is 'base'
									//refer to TABAK page no 214 figure 2.A.1 for base
									//if base = 101, 5 bytes are added
									//1 byte for sib byte & 4 bytes for d32
									if ( Input [ * i + 5 ] == '1' &&
										 Input [ * i + 6 ] == '0' &&
										 Input [ * i + 7 ] == '1' )
									{
											Value = 5 ;
									}
									else
										Value = 1 ;//1 byte for sib byte

								}
							}
						}//if 

						if ( * ( ( unsigned short int * ) ModBuffer ) == 0x3130 )//mod = 01
						{
							//if mod = 01 & r/m = 100, s-i-b byte present
							if ( RmBuffer [ 0 ] == '1' && RmBuffer [ 1 ] == '0' &&
								 RmBuffer [ 2 ] == '0' )
							{
								//s-i-b byte present
								Value = 2 ;//1 byte for sib byte
										   //1 byte for d8
							}
							else
								Value = 1 ;
						}

						if ( * ( ( unsigned short int * ) ModBuffer ) == 0x3031 )//mod = 10
						{
							//if mod = 10 & r/m = 100, s-i-b byte present						
							if ( RmBuffer [ 0 ] == '1' && RmBuffer [ 1 ] == '0' &&
								 RmBuffer [ 2 ] == '0' )
							{
								//s-i-b byte present
								Value = 5 ;//1 byte for sib byte
										   //4 byte for d32
							}
							else
								Value = 4 ;
						}
					}//if ModBuffer != 0x3131 
				}//if ( 32 == Mode )

				* i = * i  + ( 8 * Value ) ;
				* j = * j + 2 ;

				return ;

		case 'O' :
				//if idata ,
				//for lookup table, refer to README.TXT ( i:\yogesh\asm) 
				//when bit w = 0 , 1 byte is added for both 16 bit and 32 bit
				//					independent of s bit
				//when bit w = 1 , s = 1, 1 byte is added for both 16 bit and 32 bit
				//				   s = 0, 2 bytes for 16 bit & 4 bytes for 32 bit 	
				if ( * wBit == 0 )
					* i = * i + 8 ;
				//This if else is coded b'caz only 3 instructions format
				//is having idata but only s bit is present ( w bit is absent )
				//Instructions are :
				//PUSH		0110 10s0 : idata
				//IMUL		0110 10s1 : 11 reg1 reg2 : idata
				//IMUL		0110 10s1 : mod reg r/m : idata
				else
				{	
					if ( * sBit == 1 )
						* i = * i + 8 ;
					else
						* i = * i + Mode ;
				}

				* j = * j + 2 ;
				return ;

		case 'P' :
				//if imm8 ,
				* i = * i + 8 ;//8 are added b'caz of immediate 8 bit data
				* j = * j + 2 ;
				return ;

		case 'B' :
				//if Branch instruction ,
				* j = * j + 2 ;
				return ;
	}//end switch(OpCode)

}//FieldOperation

/*------------------------------------------------

	Name		: CheckEachEntry
	Description : Compare single entry in the SourceData array with the input
	Parameters	:
		1. Source		: ( IN ).
		2. Input		: ( IN ).
		3. Start		: ( IN ).
		4. Count		: ( OUT ).
		5. Mode			: ( OUT ).
		6. Width		: ( OUT ) Width of instruction if entry matches, 0 if entry does not match
		7. Buffer		: ( OUT ).
		8. Branch		: ( OUT ).
		9. rc			: ( OUT ).
	Return Value : TRUE.

--------------------------------------------------*/

unsigned long int CheckEachEntry ( char * Source , unsigned char * Input , signed long int Start , signed long int Count ,
						  signed short int Mode , signed short int * Width , unsigned char * Buffer ,
						  signed short int * Branch , signed long int * rc , unsigned char AddressSize , unsigned char OperandSize )
{
	signed short int	i , j = 0 , wBit = 0xFF , sBit = 0xFF ;
	signed short int	BranchBit , Sreg2Flag = 0 , ModBit = 0 ;
	char	ModBuffer [ 3 ] , RmBuffer [ 4 ] , OffsetBuff [ 5 ] , Buf [ 3 ] ;
	signed long int		Value = 0 ;
	unsigned long int IPCurrent = 0, IPNext = 0 ;	//IPCurrent points to the byte in the Buffer

	IPCurrent = Start / 8 ;
	i = Start + ( Count - Start + 1 ) ;

	while ( 1 )
	{
		Sreg2Flag = 0 ;
		if ( Source [ j ] == ' ' )
		{
			j ++ ;
			continue ;
		}

		//if any field (eg. w,s,mod,sreg2,reg1..... ) is found
		//get appropriate value
		while ( 0 != isalpha ( Source [ j ] ) )
		{
			FieldOperation ( Source , & i , & j , & wBit , & sBit , Input , ModBuffer ,
							 RmBuffer , Mode , & Sreg2Flag , & ModBit , AddressSize , OperandSize ) ;
		}

		if ( Source [ j ] == '\0' )
			break ;

		//if sreg2 field is present and having a value "01"(ie . if Sreg2Flag == 0xFF )
		//then check for the next 3 characters ( ie. Buf string )
		//if Buf == "111" , then the instruction format is 000 01 111
		//and instruction is pop cs which is never executed
		//therefore if u get 000 sreg2 111 & sreg2 =="01", skip it.
		//this is requried b'caz another instrucions satisfying this pattern
		//for eg. 0000 1111 : 0010 0011 : 11 eee reg

		if ( Sreg2Flag == 0xFF )
		{
			Buf [ 0 ] = Input [ i + 1 ] ;
			Buf [ 1 ] = Input [ i + 2 ] ;
			Buf [ 2 ] = '\0' ;

			if ( * ( ( unsigned short int * ) Buf ) == 0x3131 )
				Sreg2Flag = 1 ;
		}

		//comparision is bit by bit
		//if match does not occur, return 0
		if ( ( Source [ j ] != Input [ i ] ) || Sreg2Flag == 1 )
		{
			return ( 1 ) ;			
		}

		i ++ ;
		j ++ ;
	}//end of while (1)

    //when ("idata" is not present) && (mod r/m present) && (also 's' bit is present)
	//only 1 instrucion satisfies this condition
	//1000 00sw : mod 111 r/m  => CMP immediate with memory

	if ( NULL == strchr ( Source , 'O' ) && ModBit == 1 && sBit != 0xFF )
	{
		//for lookup table, refer to README.TXT ( i:\yogesh\asm) 
		//when bit w = 0 , 1 byte is added for both 16 bit and 32 bit
		//					independent of s bit
		//when bit w = 1 , s = 1, 1 byte is added for both 16 bit and 32 bit
		//				   s = 0, 2 bytes for 16 bit & 4 bytes for 32 bit 	
		if ( wBit == 1 )
		{
			if ( sBit == 1 )
				i = i + 8 ; 
			else
			{
				////////02/04/2002
				if ( OperandSize == TRUE )
				{
					if ( Mode == 16 )
						i = i + 32 ;
					else
						i = i + 16 ;
				}
				else
				////////
					i = i + Mode ;
			}
		}

		if ( wBit == 0 )
			i = i + 8 ;
	}

	* Width = ( i - Start ) / 8 ;

	//if jump instrucion, then calculate offset
	if ( strrchr ( Source , 'B' ) )
	{
		*Branch = 1 ;

		//BranchBit decides from which point offset is started
		//ie if BranchBit == 1 then starting from 2nd byte upto total width
		//if it is 2 then starting from 3nd byte upto total width

		BranchBit = Source [ strlen ( Source ) - 1 ] - 0x30 ;
		if ( BranchBit == 1 )
		{
			for ( i = ( signed short int ) ( IPCurrent + 1 ) , j = 0 ;
			    i < ( signed short int ) ( IPCurrent + * Width ) ; i ++ , j ++ )
			{
				OffsetBuff [ j ] = Buffer [ i ] ;
			}
		}
		else
		if ( BranchBit == 2 )
		{
			for ( i = ( signed short int ) ( IPCurrent + 2 ) , j = 0 ;
				  i < ( signed short int ) ( IPCurrent + * Width ) ; i ++ , j ++ )
			{
				OffsetBuff [ j ] = Buffer [ i ] ;
			}
		}
		OffsetBuff [ j ] = '\0' ;
		switch ( j )
		{
			//for offset is 8 bits
			case 1 :
				Value =  * ( char * ) ( OffsetBuff ) ;
				break ;

			//for 16 bit offset
			case 2 :
				Value =  * ( signed short int * ) ( OffsetBuff ) ;
				break ;

			//for 32 bit offset
			case 4 :
				Value =  * ( signed long int * ) ( OffsetBuff ) ;
				break ;
		}
	}

	IPNext = ( unsigned long int ) ( * Width ) + Value ;

	* rc = 8L * IPNext ;

	return ( 0 ) ;

}//CheckEachEntry

/*------------------------------------------------

	Name		: GetString
	Description : All strings are length preceded, So according to that get each string
	Parameters	:
		1. Block	: ( IN ) Input buffer.
		2. Source	: ( OUT ) Extracted string.
		3. Number	: ( IN ) Initial position from where string is to be extracted.
		4. Length	: ( IN ) Length of string to be extracted.
	Return Value : None

--------------------------------------------------*/

void GetString ( char * Block , char * Source , signed short int * Number , signed short int * Length )
{
	signed short int k , i ;

	* Length = Block [ * Number ] ;

	for ( k= ( * Number + 1 ) , i = 0 ; k <= ( * Number + * Length ) ; k ++ , i ++ )
	{
		Source [ i ] = Block [ k ] ;
	}

	Source [ i ] = '\0' ;

}//GetString


/*------------------------------------------------

	Name		: CheckAllEntriesForMatch
	Description : Compare all entries with the input
	Parameters	:
		1. Source		: ( IN ).
		2. Input		: ( IN ).
		3. Start		: ( IN ).
		4. Count		: ( OUT ).
		5. Mode			: ( OUT ).
		6. Width		: ( OUT ) Width of instruction if entry matches, 0 if entry does not match
		7. Buffer		: ( OUT ).
		8. Branch		: ( OUT ).
		9. rc			: ( OUT ).
	Return Value : TRUE.

--------------------------------------------------*/

unsigned long int CheckAllEntriesForMatch (  char * Block , unsigned char * Input , signed long int Start , signed long int Count ,
									signed short int Mode , signed short int * Width , unsigned char * Buffer , signed short int *Branch ,
									signed long int * rc , unsigned char AddressSize , unsigned char OperandSize )
{
	unsigned long int	RetValue = 0 ;
	signed short int	Number = 0 , Length = 0 ;
	char	Source [ 64 ] ;

	while ( Block [ Number ] != '\0' )
	{
 		memset ( Source , 0 , sizeof ( Source ) ) ;
		//Get each string from Block which contains chunk of strings
		GetString ( Block , Source , & Number , & Length ) ;
		//compare each entry with the input
		RetValue = CheckEachEntry ( Source , Input , Start , Count , Mode , Width , Buffer , Branch, rc , AddressSize , OperandSize ) ;
		if ( 0 == RetValue )
		{
			return ( 0 ) ;
		}

		Number += Length + 1 ;
	}

	return ( 1 ) ;

}//CheckAllEntriesForMatch

/*------------------------------------------------

	Name		: ConvertAsciiToBinary
	Description : This function converts ascii byte into binary string.
	Parameters	:
		1. value		: ( IN ) Ascii character.
		2. String		: ( IN ) Binary string.
	Return Value : None.

--------------------------------------------------*/

void ConvertAsciiToBinary ( signed short int value , unsigned char * String )
{
	String [ 0 ] = value & 0x80 ? '1' : '0' ;
	value <<= 1 ;

	String [ 1 ] = value & 0x80 ? '1' : '0' ;
	value <<= 1 ;

	String [ 2 ] = value & 0x80 ? '1' : '0' ;
	value <<= 1 ;

	String [ 3 ] = value & 0x80 ? '1' : '0' ;
	value <<= 1 ;
	
	String [ 4 ] = value & 0x80 ? '1' : '0' ;
	value <<= 1 ;

	String [ 5 ] = value & 0x80 ? '1' : '0' ;
	value <<= 1 ;

	String [ 6 ] = value & 0x80 ? '1' : '0' ;
	value <<= 1 ;

	String [ 7 ] = value & 0x80 ? '1' : '0' ;

}//ConvertAsciiToBinary

/*------------------------------------------------

	Name		: TraverseTree
	Description : Traverse tree according to the binary input string
				  & finally find out width of the instruction
	Parameters	:
		1. Buffer				: ( IN ) Ascii character.
		2. InstructionNo		: ( IN ) Binary string.
		3. Mode					: ( IN ) 16-bit or 32-bit
		4. ExecutionPathPtr		: ( OUT ) Holds the execution path.
		5. BytesOperated		: ( OUT ) Actual number of bytes operated on.
		6. CallVar				: ( IN ).
		7. InternalFileType		: ( IN ) File type
		8. ExecutionPathWidth	: ( OUT ) Holds the instruction's wodth.
	Return Value : TRUE

--------------------------------------------------*/

unsigned long int TraverseTree ( unsigned int Flag , unsigned char * Buffer , signed short int * InstructionNo , signed short int Mode ,
						char * ExecutionPathPtr , signed long int * BytesOperated ,
						signed short int * CallVar , signed short int InternalFileType ,
						char * ExecutionPathWidth , unsigned char * AddressSize , unsigned char * OperandSize )
{
	BinaryTreeNode	  * TempNode ;
	signed long int		rc , Start = 0 , Count = 0 ;
	unsigned char 		Input [ 513 ] ;
	signed short int 	Width = 0 , i = 0 , Position = 0 , Branch ;
	signed short int 	j = 0 ;
	char Output [ 8 ] , Temp [ 25 ] ;
	char FinalOutput [ 4 ] ;
	signed short int 	AddInstructionBytes ;
	unsigned char String [ 2 ] ;

	// check added

	if ( * Buffer == 0x0F )
	{
		( * InstructionNo ) ++ ;
		strcat ( ExecutionPathPtr , "0F" ) ;
		strcat ( ExecutionPathWidth , "1" ) ;
		* BytesOperated = 1 ;
		* CallVar = 0 ;
		* OperandSize = FALSE ;
		* AddressSize = FALSE ;

		return ( 0 ) ;
	}

	// check for floating point inst.
	if ( * Buffer == 0xD8 )
	{
		( * InstructionNo ) += 2 ;
		sprintf ( Output , "%02X%02X" , * Buffer , * ( Buffer + 1 ) ) ;

		if ( Flag & FEATURE_ONLY_OP_CODE )
			strncat ( ExecutionPathPtr , Output , 2 ) ;
		else
			strcat ( ExecutionPathPtr , Output ) ;

		strcat ( ExecutionPathWidth , "2" ) ;
		* BytesOperated = 2 ;
		* CallVar = 0 ;
		* OperandSize = FALSE ;
		* AddressSize = FALSE ;

		return ( 0 ) ;
	}

	memset ( Input , 0 , sizeof ( Input ) ) ;
	memset ( String , 0 , sizeof ( String ) ) ;

	//Convert all ascii bytes into binary format.

	if ( 16 == Mode )
	{
		// for 16 bit convert first 8 byte
		for( j = 0 ; j < 8 ; j ++ )
			ConvertAsciiToBinary ( Buffer [ j ] , ( Input + j * 8 ) ) ;
	}
	else
	{
		//for 32 bit convert first 16 byte
		for( j = 0 ; j < 16 ; j ++ )
			ConvertAsciiToBinary ( Buffer [ j ] , ( Input + j * 8 ) ) ;
	}

	TempNode = & Header ;
	while ( Input [ Count ] != '\0' ) // travel according to the token bit
	{
		rc = Branch = 0 ;
		AddInstructionBytes = TRUE ;

		if ( Input [ Count ] == '0' )
			TempNode = TempNode -> Zero ;

		if ( Input [ Count ] == '1' )
			TempNode = TempNode -> One ;

		//code added on 17/4/2k
		if ( TempNode == NULL )
		{
			return ( 1 ) ;
		}

		//if index has valid value (ie. Ptr != NULL )
		//compare all entries with the input
		if ( TempNode -> Ptr != NULL )
		{
			CheckAllEntriesForMatch ( TempNode -> Ptr , Input , Start , Count , Mode , & Width ,
									  Buffer , & Branch , & rc , * AddressSize , * OperandSize ) ;
		}

		//rc contains location from where next instruction
		//should start.
		if ( rc != 0 )
		{
			( * InstructionNo ) ++ ;
			//if for EXE File first instruction is branch instruction,
			//dont add it to the array pointed by ExecutionPathPtr
			if ( InternalFileType != VI_COM )
			{
				if ( ( * InstructionNo == 1 ) &&
					 ( Buffer [ 0 ] == 0x9A || Buffer [ 0 ] == 0xEB || Buffer [ 0 ] ==  0xE9 ) )
				{
					* CallVar = 1 ;
					AddInstructionBytes = FALSE ;
				}
			}

			if ( AddInstructionBytes == TRUE )
			{
				//Get total instruction in the Temp buffer
				Position = Start / 8 ;
				memset ( Temp , 0 , sizeof ( Temp ) ) ;

				for ( i = Position ; i < Position + Width ; i++ )
				{
					memset ( Output , 0 , sizeof ( Output ) ) ;
					memset ( FinalOutput , 0 , sizeof ( FinalOutput ) ) ;
					FinalOutput [ 0 ] = '0' ;
					atoh ( Output , Buffer [ i ] ) ;
					if ( 1 == strlen ( Output ) )
					{
						strcat ( FinalOutput , Output ) ;
						strcat ( Temp , FinalOutput ) ;
					}
					else
						strcat ( Temp , Output ) ;
				}

				if ( Width == 1 )
				{
					if ( Temp [ 0 ] == '6' )
					{
						if ( Temp [ 1 ] == '6' )
							* OperandSize = TRUE ;
						else
						if ( Temp [ 1 ] == '7' )
							* AddressSize = TRUE ;
						else
						{
							* OperandSize = FALSE ;
							* AddressSize = FALSE ;
						}
					}
					else
					{
						* OperandSize = FALSE ;
						* AddressSize = FALSE ;
					}
				}
				else
				{
					* OperandSize = FALSE ;
					* AddressSize = FALSE ;
				}

				if ( EXECUTIONPATHLENGTH <= strlen ( ExecutionPathPtr ) + strlen ( Temp ) )
				{
#ifdef VAXINE_DEBUG
	#ifdef DYNAMIC_LINK
					OutputDebugString ( "\nEXECUTIONPATHLENGTH is small" ) ;
	#endif
#endif
//					OS_GlobalUnLock ( ExecutionPathPtr ) ;
					return ( 3 ) ;
				}

				if ( Flag & FEATURE_ONLY_OP_CODE )
					strncat ( ExecutionPathPtr , Temp , 2 ) ;
				else
					strcat ( ExecutionPathPtr , Temp ) ;

				memset ( String , 0 , sizeof ( String ) ) ;
				if ( Width > 9 )
					String [ 0 ] = Width + - 10 + 'A' ;
				else
					String [ 0 ] = Width + '0' ;

				strcat ( ExecutionPathWidth , String ) ;
//				OS_GlobalUnLock ( ExecutionPathWidth ) ;
			}

			//this is done for special type of viruses
			//if upto 32 instructions you dont get a call instruction
			//then continue upto 128 instructions
			if ( * InstructionNo < MIN_INSTRUCTION )
			{
				if ( ( Temp [ 0 ] == 'E' && Temp [ 1 ] == '8' ) ||
					 ( Temp [ 0 ] == 'F' && Temp [ 1 ] == 'F' && Temp [ 2 ] == 'D' ) )
				{
					* CallVar = 1 ;
				}
			}

			Start = Start + rc ;

			//This is true only for branch instructions.
			if ( j <= Start / 8 )
			{
				j = Start / 8 ;

				/////////02/04/2002
				if ( * AddressSize == TRUE )
				{
					if ( Mode == 16 )
						Width = 32 / 2 ;
					else
						Width = 16 / 2 ;
				}
				else
				/////////
					Width = Mode / 2 ;
			}

			//breaking condition
			if ( 1 == * CallVar )
			{
				if ( Start >= 160 || Start < 0 || * InstructionNo == MIN_INSTRUCTION || j >= 16 )
					break ;
			}
			else
			{
				if ( Start >= 160 || Start < 0 || * InstructionNo == MAX_INSTRUCTION || j >= 16 )
					break ;
			}

			//this for loop is added to convert n bytes from Buffer
			//into binary and concatenated to the input buffer
			//n = width of instruction.
			//Buffer is actually of 64 bytes read from file
			//Firstly we converted bytes from Buffer into binary string according to
			//mode. Now according to width of instruction, Convert next bytes from
			//Buffer into binary string
			//eg. for 16 bit, first we have converted first 8 byte from Buffer and resulted
			//binary string was in Input array. now if we recognize AAD instruction
			//its width is 2 bytes, so take next 2 bytes (byte 9 and byte 10) from
			//Buffer and convert it

			Position = j ;

			for(  ; j < Position + Width ; j ++ )
				ConvertAsciiToBinary ( Buffer [ j ] , ( Input + j * 8 ) ) ;

			Count = Start ; // b'coz to start again leaving 'start' bits
			TempNode = & Header ; //again start traverse from the header
			continue ;
		}

		Count ++ ;
	}

	* BytesOperated = Start / 8 ;

	return ( 0 ) ;

}//TraverseTree


/*------------------------------------------------

	Name		: MakeDeassembly
	Description : Main unassembly of file starts here.
	Parameters	:
		1. RHandle				: ( IN ) File handle.
		2. EntryPoint			: ( IN ) Offset.
		3. Mode					: ( IN ) 16-bit or 32-bit
		4. ExecutionPathPtr		: ( OUT ) Holds the execution path.
		5. InternalFileType		: ( OUT ) File type.
		6. MemoryPtr			: ( IN ) Memory buffer.
		7. MemPtrLength			: ( IN ) Size of memory buffer.
		8. ExecutionPathWidth	: ( OUT ) Holds the instruction's width.
	Return Value : TRUE

--------------------------------------------------*/

unsigned long int GetActualOffset ( SEGMENTS * Segments , unsigned long int ImageBase , unsigned long int BaseOfCode , signed long int * BytesOperated , LARGE_INTEGER FilePtr , int * NewSegment )
{
	signed short int	i , j ;
	unsigned long int	SegmentStart = 0 , SegmentEnd = 0 ;
	unsigned long int	OffsetInSegment = 0 ;
	unsigned long int	ActualIP = 0xFFFFFFFF ;
//	signed long int	PrevOffsetInSegment ;

	long Var ;

	Var = * BytesOperated ;
	Var = Var ;

//	PrevOffsetInSegment = FilePtr . QuadPart + Var ; //* BytesOperated ;
	for ( i = 0 ; i < 32 ; i ++ )
	{
		if ( Segments [ i ] . SegmentSize > 0 )
		{
			if ( ( FilePtr . QuadPart >= Segments [ i ] . FileOffset ) && ( FilePtr . QuadPart <= ( Segments [ i ] . FileOffset + Segments [ i ] . SegmentSize ) ) )
			{
				// located FilePtr Segment

				OffsetInSegment = FilePtr . QuadPart - Segments [ i ] . FileOffset ;

				if ( ( OffsetInSegment + * BytesOperated ) < Segments [ i ] . SegmentSize )
				{
					OffsetInSegment = FilePtr . QuadPart + * BytesOperated ;
					* NewSegment = i ;
					return ( OffsetInSegment ) ;
				}

				//calculate current IP
				ActualIP = ImageBase ; //Segments [ i ] . BaseAddress * 0x1000 ;
				ActualIP += Segments [ i ] . Offset ;
				ActualIP += OffsetInSegment ;

				//add jump offset
				ActualIP += * BytesOperated ;

				//locate new EIP in all segments
				for ( j = 0 ; j < 32 ; j ++ )
				{
					SegmentStart = ImageBase ; //Segments [ j ] . BaseAddress * 0x1000 ;
					SegmentStart += Segments [ j ] . Offset ;
					SegmentEnd = SegmentStart + Segments [ j ] . SegmentSize ;

					if ( ActualIP >= SegmentStart && ActualIP <= SegmentEnd )
					{
						// located Segment to which jump points, OffsetInSegment is new offset

						OffsetInSegment = ActualIP - SegmentStart ;
						OffsetInSegment += Segments [ j ] . FileOffset ;
						* NewSegment = j ;
						return ( OffsetInSegment ) ;
					}
				}

				// is in PE header
			}
		}
	}

	if ( ActualIP == 0xFFFFFFFF )
	{
		OffsetInSegment = FilePtr . QuadPart ;
		ActualIP = ImageBase + BaseOfCode ;
		ActualIP += OffsetInSegment ;
		ActualIP += * BytesOperated ;

		//locate new EIP in all segments
		for ( j = 0 ; j < 32 ; j ++ )
		{
			SegmentStart = ImageBase ; //Segments [ j ] . BaseAddress * 0x1000 ;
			SegmentStart += Segments [ j ] . Offset ;
			SegmentEnd = SegmentStart + Segments [ j ] . SegmentSize ;

			if ( ActualIP >= SegmentStart && ActualIP <= SegmentEnd )
			{
				// located Segment to which jump points, OffsetInSegment is new offset

				OffsetInSegment = ActualIP - SegmentStart ;
				OffsetInSegment += Segments [ j ] . FileOffset ;
				* NewSegment = j ;
				return ( OffsetInSegment ) ;
			}
		}
	}

	OffsetInSegment = ActualIP - ImageBase ;
	return ( OffsetInSegment ) ;
}//GetActualOffset

unsigned long int MakeDeassembly ( HANDLE RHandle , unsigned int Flag , LARGE_INTEGER EntryPoint , signed short int Mode ,
						  void * ExecutionPathPtr , signed short int InternalFileType ,
						  unsigned char * MemoryPtr , unsigned long int MemPtrLength ,
						  void * ExecutionPathWidth , SEGMENTS * Segments , unsigned long int ImageBase ,
						  unsigned long int BaseOfCode , LARGE_INTEGER * CurrentEntryPoint , int * NewEntryPointSectionNumber )
{
	int	RetValue = 0 , RetVal , NewSegment ;
	signed short int	InstructionNo = 0 ;
	unsigned char		Buffer [32] ;
	signed long int		BytesOperated = 0 ;
	LARGE_INTEGER FilePtr ;
	signed short int	CallVar = 0 ;
	DWORD BytesRead ;
	LARGE_INTEGER FilePos ;

//////02/04/2002
	//
	// Mode changes from 32-bit to 16-bit and vice-versa if first byte found in an instruction
	// is 66 or 67. For this reason AddressSize and OperandSize have been defined whose values are
	// manipulated accordingly so as to determine the address or operand size of next instruction.
	//
	unsigned char		AddressSize , OperandSize ;

	AddressSize = OperandSize = FALSE ;
//////

	// At start FilePtr is an offset value ( entrypoint in file )
	//
	FilePtr . QuadPart = EntryPoint . QuadPart ;

	// From binary input traverse in the tree
	// & compare entries from SourceData array with input
	while ( 1 )
	{
		memset ( Buffer , 0 , sizeof ( Buffer ) ) ;

		//move file pointer at position specified by FilePtr .
		//
		Lseek ( RHandle , FilePtr , SEEK_SET , & FilePos , MemoryPtr , MemPtrLength ) ;

		RetValue = Read ( RHandle , Buffer , sizeof ( Buffer ) , & BytesRead , MemoryPtr , MemPtrLength ) ;
		if ( 0 != RetValue )
		{
			return ( 1 ) ;
		}

		//now for 64 bytes traverse tree according to the bits
		//
		RetVal = TraverseTree ( Flag , Buffer , & InstructionNo , Mode , ExecutionPathPtr ,
										 & BytesOperated , & CallVar , InternalFileType ,
										 ExecutionPathWidth , & AddressSize , & OperandSize ) ;

		if ( 0 != RetVal )
		{
			return ( RetVal ) ;
		}

		//checking RetValue condition
		//
		if ( 0 != RetVal )
		{
			return ( RetVal ) ;
		}

		//stop deassembling when 32 instructions are over
		if ( 1 == CallVar )
		{
			if ( InstructionNo == MIN_INSTRUCTION )
			{
				break ;
			}
		}
		else
		{
			if ( InstructionNo == MAX_INSTRUCTION )
			{
				break ;
			}
		}

		//additional check
		if ( Flag & FEATURE_32_BYTES_LENGTH )
		{
			if ( InstructionNo == 32 )
				break ;
		}
		if ( Flag & FEATURE_64_BYTES_LENGTH )
		{
			if ( InstructionNo == 64 )
				break ;
		}

		if ( 1 == CallVar )
		{
			FilePtr . QuadPart = GetActualOffset ( Segments , ImageBase , BaseOfCode , & BytesOperated , FilePtr , & NewSegment ) ;
		}
		else
		{
			FilePtr . QuadPart += BytesOperated ;
		}

		if ( InstructionNo == 1 )
		{
			CurrentEntryPoint -> QuadPart = FilePtr . QuadPart ;
			if ( 1 == CallVar )
			{
				if ( NewEntryPointSectionNumber != NULL )
					* NewEntryPointSectionNumber = NewSegment ;
			}
			else
			{
				if ( NewEntryPointSectionNumber != NULL )
					* NewEntryPointSectionNumber = -1 ;
			}
		}

		CallVar = 0 ;
	}

	return ( RetVal ) ;

}//MakeDeassembly
