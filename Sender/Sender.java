import java.util.Scanner;
import java.io.FileInputStream;
import java.io.BufferedInputStream;
import java.io.FileOutputStream;
import java.io.BufferedOutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;

public class Sender{
    private static int KEY_SIZE = 1024, MAX_CHUNK = 512*1024;
    
    public static void main(String[] args) throws Exception {
		//Kx-
		RSA_Custom xPriv;
		//Kxy
		AES128_Sym symKey;

		//read the private key
		xPriv = new RSA_Custom(KEY_SIZE);
		xPriv.readKeyFile("XPrivate.key");

		//read the symmetric key and run the key expansion/schedule method
		symKey = new AES128_Sym();
		symKey.readKeyFile("symmetric.key");
		symKey.expandKey();

		//prompt user for message file name
		System.out.print("Input name of the message file: ");
		Scanner userIn = new Scanner(System.in);
		String messageFile = userIn.nextLine();
		userIn.close();

		//calculate the hash, print, and save to file
		SHA256_Sum fileSum = new SHA256_Sum();
		fileSum.hashFile(messageFile);
		System.out.format("'%s' Hash:\t%s\n", messageFile, fileSum);
		bytesToFile("message.dd", new byte[][]{fileSum.toBytes()});

		//generate the RSA signature, print, and save to a file
		byte[] signature = xPriv.genSig(fileSum.toBytes());
		System.out.format("Signature:\t%s\n", byteArr2String(signature));
		bytesToFile("message.ds-msg", new byte[][]{signature});
		appendMessage("message.ds-msg", messageFile);

		symKey.encrypt("message.ds-msg", "message.aescipher");
    }

	public static String byteArr2String (byte[] inBytes) {
		String strOut = "";
		for (byte h : inBytes) strOut += String.format("%02x", h);
		return strOut;
	}
	
	public static void bytesToFile (String fileName, byte[][] inArr) throws Exception {
		FileOutputStream fWriter;

		fWriter = new FileOutputStream(fileName);
		for (byte[] bArr : inArr) fWriter.write(bArr);
		fWriter.close();
	}

	public static void appendMessage (String appendFile, String messageFile) throws Exception {
		//prepare files
		BufferedInputStream inFile = new BufferedInputStream(new FileInputStream(messageFile));
		BufferedOutputStream outFile = new BufferedOutputStream(new FileOutputStream(appendFile, true));
		//read input file length in bytes
		long inByteN = Files.size(Paths.get(messageFile));
	
		//loop until end of input file is reached
		for (long i = 0; i < inByteN; i+=MAX_CHUNK) {
			//decide how long next read chunk will be
			int chunkLen = (i+MAX_CHUNK < inByteN) ? MAX_CHUNK : (int)(inByteN-i);
			outFile.write(file2ByteArr(inFile, chunkLen));
		}
		
		inFile.close();
		outFile.close();
	}

	public static byte[] file2ByteArr (BufferedInputStream inFile, int byteLen) throws Exception {
		byte[] inBytes = new byte[byteLen];
		//read input file to byte array
		inFile.read(inBytes, 0, byteLen);

		return inBytes;
	}
}
