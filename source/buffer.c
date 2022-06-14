/*-
 *
 * extc2: open source dns over http(s)
 * transport for cs. does not use the
 * smb beacon.
 *
-*/

#include "common.h"

/*-
 *
 * BufferCreate
 *
 * Purpose:
 *
 * Allocates a buffer on the heap
 *
-*/
DEFINESEC(B) PVOID BufferCreate( PBEACON_INSTANCE Ins, ULONG Length )
{
	return Ins->api.LocalAlloc(
		LMEM_MOVEABLE | LMEM_ZEROINIT,
		Length
		);
};

/*-
 *
 * BufferExtend
 *
 * Purpose:
 *
 * Extends a buffer on the heap
 *
-*/
DEFINESEC(B) PVOID BufferExtend( PBEACON_INSTANCE Ins, PVOID Buffer, ULONG Length )
{
	return Ins->api.LocalReAlloc(
			Buffer,
			Ins->api.LocalSize ( Buffer ) + Length,
			LMEM_MOVEABLE | LMEM_ZEROINIT
			);
};

/*-
 *
 * BufferAddRaw
 *
 * Purpose:
 *
 * Appends a value of the specified length
 * onto a buffer.
 *
-*/
DEFINESEC(B) PVOID BufferAddRaw( PBEACON_INSTANCE Ins, PVOID Buffer, PVOID Value, ULONG Length )
{
	PVOID Heap;
	PVOID Addr;

	if ( Buffer )
		Heap = BufferExtend( Ins, Buffer, Length );
	else
		Heap = BufferCreate( Ins, Length );

	if ( Heap != NULL )
	{
		if ((Addr = Ins->api.LocalLock( Heap )) != NULL)
		{
			RtlCopyMemory(
				CPTR( UPTR( Addr ) + Ins->api.LocalSize( Heap ) - Length ),
				CPTR( Value ),
				Length
				);
			Ins->api.LocalUnlock( Heap );
		};
	};
	return Heap ? Heap : Buffer ;
};

/*-
 *
 * BufferAddUI1
 *
 * Purpose:
 *
 * Appends a 1-byte int onto a buffer
 *
-*/
DEFINESEC(B) PVOID BufferAddUI1( PBEACON_INSTANCE Ins, PVOID Buffer, BYTE Value )
{
	return BufferAddRaw( Ins, Buffer, &Value, 1 );
};

/*-
 *
 * BufferAddUI2
 *
 * Purpose:
 *
 * Appends a 2-byte int onto a buffer
 *
-*/
DEFINESEC(B) PVOID BufferAddUI2( PBEACON_INSTANCE Ins, PVOID Buffer, USHORT Value )
{
	return BufferAddRaw( Ins, Buffer, &Value, 2 );
};

/*-
 *
 * BufferAddUI4
 *
 * Purpose:
 *
 * Appends a 4-byte int onto a buffer
 *
-*/
DEFINESEC(B) PVOID BufferAddUI4( PBEACON_INSTANCE Ins, PVOID Buffer, ULONG Value )
{
	return BufferAddRaw( Ins, Buffer, &Value, 4 );
};
