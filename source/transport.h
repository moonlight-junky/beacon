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
 * TransportInit
 *
 * Purpose:
 *
 * Creates the transport routines, and 
 * connects to the server.
 *
-*/
DEFINESEC(B) BOOL TransportInit( PBEACON_INSTANCE Ins );

/*-
 *
 * TransportFree
 *
 * Purpose:
 *
 * Frees the transport routines, and
 * disconnects from the server.
 *
-*/
DEFINESEC(B) VOID TransportFree( PBEACON_INSTANCE Ins );

/*-
 *
 * TransportSend
 *
 * Purpose:
 *
 * Send's data over the connected socket
 * of the specified length.
 *
-*/
DEFINESEC(B) BOOL TransportSend( PBEACON_INSTANCE Ins, PVOID Data, ULONG Size );

/*-
 *
 * TransportRecv
 *
 * Purpose:
 *
 * Recv's data over the connected socket.
 * Sets the length recieved in the buffer
 *
-*/
DEFINESEC(B) BOOL TransportRecv( PBEACON_INSTANCE Ins, PVOID* Data, ULONG* Size );
