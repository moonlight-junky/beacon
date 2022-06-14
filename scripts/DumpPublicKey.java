import java.io.*;
import java.util.Base64;
import common.CommonUtils;
import java.security.KeyPair;

class DumpPublicKey
{
	public static void main( String[] args )
	{
		try 
		{
			File file = new File(".cobaltstrike.beacon_keys");

			if ( file.exists() )
			{
				KeyPair Pair = ( KeyPair ) CommonUtils.readObject( file, null );

				OutputStream keys = new FileOutputStream("publickey.bin");
				keys.write( Pair.getPublic().getEncoded() );
				keys.close();
			} else
			{
				System.out.println("Could not find beacon keys.\n");
			};
		}
		catch( Exception exception )
		{
			System.out.println("Could not read keys file.");
		}
	}
}
