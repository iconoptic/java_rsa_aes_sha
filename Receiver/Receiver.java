import java.util.Scanner;
import java.util.Arrays;
import java.io.FileInputStream;
import java.io.BufferedInputStream;
import java.io.FileOutputStream;
import java.io.BufferedOutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;

public class Receiver{
    private static int KEY_SIZE = 1024, MAX_CHUNK = 512*1024;
    
    public static void main(String[] args) throws Exception {
		//Kx-
		RSA_Custom xPub;
		//Kxy
		AES128_Sym symKey;

		//read the private key
		xPub = new RSA_Custom(KEY_SIZE);
		xPub.readKeyFile("XPublic.key");

		//read the symmetric key and run the key expansion/schedule method
		symKey = new AES128_Sym();
		symKey.readKeyFile("symmetric.key");
		symKey.expandKey();

		//prompt user for message file name
		System.out.print("Input name of the message file: ");
		Scanner userIn = new Scanner(System.in);
		String messageFile = userIn.nextLine();
		userIn.close();

		//decrypt with shared key and save to file: message.ds-message
		symKey.decrypt("message.aescipher", "message.ds-msg");

		//recover and print digital digest
		byte[] signature = recoverMessage("message.ds-msg", messageFile);
		byte[] ddSender = xPub.decSig(signature);
		System.out.format("Sender Hash:\t%s\n", byteArr2String(ddSender));
		bytesToFile("message.dd", new byte[][]{ddSender});

		SHA256_Sum fileSum = new SHA256_Sum();
		fileSum.hashFile(messageFile);
		System.out.format("Receiver Hash:\t%s\n", fileSum);

		if (Arrays.equals(fileSum.toBytes(), ddSender))
			System.out.println("Verification passed.");
		else
			System.out.println("Verification failed.");
    }

	public static byte[] recoverMessage (String concatFile, String messageFile) throws Exception{
		BufferedInputStream inFile = new BufferedInputStream(new FileInputStream(concatFile));
		BufferedOutputStream outFile = new BufferedOutputStream(new FileOutputStream(messageFile));
		int sigLen = KEY_SIZE/8;
		long inByteN = Files.size(Paths.get(concatFile));
		int byteLen;

		//read signature to byte arr
		byte[] signature = new byte[sigLen];
		inFile.read(signature, 0, sigLen);

		//read remaining bytes to file
		for (long i = sigLen; i < inByteN; i+=MAX_CHUNK) {
			byteLen = (i+MAX_CHUNK < inByteN) ? MAX_CHUNK : (int)(inByteN-i);
			outFile.write(file2ByteArr(inFile, byteLen));
		}
		inFile.close();
		outFile.close();

		return signature;
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
	
	public static byte[] file2ByteArr (BufferedInputStream inFile, int byteLen) throws Exception {
		byte[] inBytes = new byte[byteLen];
		//read input file to byte array
		inFile.read(inBytes, 0, byteLen);

		return inBytes;
	}
}
