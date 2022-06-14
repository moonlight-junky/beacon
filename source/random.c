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
 * RandomNumber32
 *
 * Purpose:
 *
 * Returns a random long integer from
 * a range of 2 to LONG_MAX
 *
-*/
DEFINESEC(B) LONG RandomNumber32( PBEACON_INSTANCE Ins )
{
	ULONG Seed = 0;

	Seed = Ins->api.GetTickCount();
	Seed = Ins->api.RtlRandomEx( &Seed );
	Seed = Ins->api.RtlRandomEx( &Seed );
	Seed = ( Seed % ( LONG_MAX - 2 + 1 ) ) + 2;

	return Seed % 2 == 0 ? Seed : Seed + 1;
};
