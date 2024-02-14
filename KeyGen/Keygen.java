import java.io.FileOutputStream;
import java.util.Scanner;

public class Keygen{
    private static int KEY_SIZE = 1024;

    public static void main(String[] args) throws Exception {
		RSA_Custom keyPairX, keyPairY;
	
		//generate key-pair X
		keyPairX = new RSA_Custom(KEY_SIZE);
		keyPairX.genKeyPair();
		exportKeys("X", keyPairX);

		//generate key-pair y
		keyPairY = new RSA_Custom(KEY_SIZE);
		keyPairY.genKeyPair();
		exportKeys("Y", keyPairY);

		//prompt user for symmetric key
		System.out.print("Enter 16-characters to be used as the symmetric key: ");
		Scanner userIn = new Scanner(System.in);
		String symKey = userIn.nextLine();
		userIn.close();
		byte[] keyBytes = symKey.getBytes("UTF-8");
		bytesToFile("symmetric.key", new byte[][]{keyBytes});
    }
	
	public static void exportKeys (String userID, RSA_Custom keyPair) throws Exception {
		byte[] truncMod = RSA_Custom.removeLeadingNull(keyPair.getMod().toByteArray());
		byte[][] pubKey = new byte[][]{truncMod, keyPair.getPubExp().toByteArray()};
		byte[][] privKey = new byte[][]{truncMod, keyPair.getPrivExp().toByteArray()};

		bytesToFile(userID + "Public.key", pubKey);
		bytesToFile(userID + "Private.key", privKey);
    }

	public static void bytesToFile (String fileName, byte[][] inArr) throws Exception {
		FileOutputStream fWriter;

		fWriter = new FileOutputStream(fileName);
		for (byte[] bArr : inArr) fWriter.write(bArr);
		fWriter.close();
	}
}
