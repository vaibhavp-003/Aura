#pragma pack ( 1 )

#ifdef _DEBUG
#define CRTDBG_MAP_ALLOC
#include <stdlib.h>
#include <crtdbg.h>
#endif

typedef struct tagSegments
{
	unsigned long int	BaseAddress ;
	unsigned long int	Offset ;
	unsigned long int	FileOffset ;
	unsigned long int	SegmentSize ;
} SEGMENTS ;
#pragma pack  ( )

#pragma pack  ( 1 )
typedef struct _Init_Pointers
{
	unsigned long int	( * InitialiseFunctionPointers ) ( OSGLOBALMEM ) ;

}INITPOINTERS ;
#pragma pack  ( )