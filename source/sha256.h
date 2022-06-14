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
 * Sha256Sum
 *
 * Purpose:
 *
 * Calculates the SHA-256 sum of an input
 * string.
 *
-*/
DEFINESEC(B) PVOID Sha256Sum( PBEACON_INSTANCE Ins, PVOID Buf, ULONG Len );
