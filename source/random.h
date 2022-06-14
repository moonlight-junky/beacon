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
 * RandomNumber32
 *
 * Purpose:
 *
 * Returns a random unsigned long integer.
 *
-*/
DEFINESEC(B) LONG RandomNumber32( PBEACON_INSTANCE Ins );
