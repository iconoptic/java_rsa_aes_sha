import java.math.BigInteger;
import java.util.Random;
import java.util.Arrays;
import java.io.BufferedInputStream;
import java.io.FileInputStream;

public class RSA_Custom {
    private static int KEY_SIZE, PRIME_SIZE, N_SIZE, KEY_BYTES;		//key params; measured in bits
    private static BigInteger[] KEY_PAIR;               			//array to store n, e, & d
    
	/* Constructor takes key size in bits (e.g. 1024) as argument. */
    public RSA_Custom (int keySize) {
        KEY_SIZE = keySize;
        PRIME_SIZE = KEY_SIZE/2;
        N_SIZE = (KEY_SIZE/8);
		KEY_BYTES = (KEY_SIZE/4) + 1;
		
		KEY_PAIR = new BigInteger[3];
    }

	/* Interface Functions */

    public void genKeyPair() {
		KEY_PAIR = rsaGen();
    }

    public BigInteger getMod () {
        return KEY_PAIR[0];         //return n
    }

    public BigInteger getPubExp () {
        return KEY_PAIR[1];         //return e
    }

    public BigInteger getPrivExp() {
        return KEY_PAIR[2];         //return d
    }

	/* Handle leading null bytes (useful for storing in file) */

	public static byte[] removeLeadingNull (byte[] bigInt) {
		if ( bigInt[0] != 0x0 ) return bigInt;
		//remove leading zero so file can be imported to bigint on correct boundary
		else { 
			byte[] writeBytes = new byte[bigInt.length-1];
			System.arraycopy(bigInt, 1, writeBytes, 0, writeBytes.length);
			return writeBytes;
		}
	}

	public static byte[] addLeadingNull (byte[] readBytes) {
		if ( (int)(readBytes[0] & 0x80) == 0x00 ) return readBytes;
		//add leading zero to prevent import as negative bigint
		else {
			byte[] bigInt = new byte[readBytes.length+1];
			bigInt[0] = 0x0;
			System.arraycopy(readBytes, 0, bigInt, 1, readBytes.length);
			return bigInt;
		}
	}

	/* Read key file; handle nulls for modulus */

	public void readKeyFile (String fileN) throws Exception {
		BufferedInputStream keyFile = new BufferedInputStream(new FileInputStream(fileN));
		byte[] inBytes = new byte[KEY_BYTES];
		int i, whichExp;
		
		for (i = 0; keyFile.available() > 0; i++) 
			inBytes[i] = (byte)keyFile.read();
		keyFile.close();
	
		//import modulus
		KEY_PAIR[0] = new BigInteger(addLeadingNull(Arrays.copyOfRange(inBytes, 0, N_SIZE)));

		//import exponent
		whichExp = ((i-N_SIZE) < 4) ? 1 : 2; 
		KEY_PAIR[whichExp] = new BigInteger(Arrays.copyOfRange(inBytes, N_SIZE, i));
		
		//derive pubKey and save to instance if import was privKey
		if (whichExp == 2) derivePubExp();
    }

	/* Create padded signature from byte array */
	public byte[] genSig (byte[] plainText) {
		BigInteger cipherText, message;
		byte[] cipherBytes;

		do {
			//create padded message
			byte[] paddedBytes = oaEncode(plainText);
			message = new BigInteger(paddedBytes);

			//encrypt using private key
			cipherText = message.modPow(KEY_PAIR[2], KEY_PAIR[0]);

			//test decode 
			cipherBytes = cipherText.toByteArray();
		} while ( decSig(cipherBytes).length == 0 || removeLeadingNull(cipherBytes).length == 127 );

		//remove leading 0x0 so array is fixed size (128-bytes for 1024-bit key); return result
		return removeLeadingNull(cipherBytes);
	}

	/* Decode signature and padding */
	public byte[] decSig (byte[] cipherBytes) {
		BigInteger plainText, cipherMessage;

		//import from byte array after check for leading null
		cipherMessage = new BigInteger(addLeadingNull(cipherBytes));
		
		//decrypt using public key
		plainText = cipherMessage.modPow(KEY_PAIR[1], KEY_PAIR[0]);

		//remove padding
		byte[] ptBytes = oaDecode(plainText.toByteArray());

		return ptBytes;
	}

	/* OAE Padding Functions */

	private byte[] oaEncode (byte[] ptMessage) {
		int mLen = ptMessage.length;
		int k = getMod().toByteArray().length;
		int hLen = SHA256_Sum.ddByteN(); //256/8 = 32

		//hash the empty string and save in byte array
		SHA256_Sum lHash = new SHA256_Sum();
		lHash.hashEmptyStr();
		byte[] lBytes = lHash.toBytes();

		//init padding string with zeros
		int padStrLen = k - mLen - 2*hLen - 2;
		byte[] padStr = new byte[padStrLen];
		for (int i = 0; i < padStrLen; i++) padStr[i] = 0x0;

		//concatentate values -> db
		int dbLen = k - hLen - 1; 
		byte[] dataBlocks = new byte[dbLen];
		System.arraycopy(lBytes, 0, dataBlocks, 0, lBytes.length);
		System.arraycopy(padStr, 0, dataBlocks, lBytes.length, padStrLen);
		dataBlocks[lBytes.length+padStrLen] = (byte) 0x01;
		System.arraycopy(ptMessage, 0, dataBlocks, lBytes.length+padStrLen+1, ptMessage.length);

		//generate random seed
		byte[] seed = new byte[hLen];
		Random rng = new Random();
		rng.nextBytes(seed);

		//mask dataBlocks
		byte[] randMask = maskGenFunc(seed, dbLen);
		byte[] maskedDB = maskBytes(dataBlocks, randMask);

		//mask seed
		byte[] seedMask = maskGenFunc(maskedDB, hLen);
		byte[] maskedSeed = maskBytes(seed, seedMask);

		//concatenate results -> output
		byte[] paddedMessage = new byte[1+hLen+dbLen];
		paddedMessage[0] = 0x0;
		System.arraycopy(maskedSeed, 0, paddedMessage, 1, hLen);
		System.arraycopy(maskedDB, 0, paddedMessage, 1+hLen, dbLen);

		return paddedMessage;
	}
	
	private byte[] oaDecode (byte[] paddedMessage) {
		int k = getMod().toByteArray().length;
		int hLen = SHA256_Sum.ddByteN(); //256/8 = 32

		//prevent index out of bounds exception
		if ((k - paddedMessage.length) > 1) return new byte[]{};

		//hash the empty string and save to byte array
		SHA256_Sum lHash = new SHA256_Sum();
		lHash.hashEmptyStr();
		byte[] lBytes = lHash.toBytes();

		//determine whether BigInteger constructor removed leading 0x0
		int arrStart = (paddedMessage.length == 129) ? 1 : 0;
		
		//retrieve masked seed and masked db
		int dbLen = k - hLen - 1;
		byte[] maskedSeed = new byte[hLen];
		byte[] maskedDB = new byte[dbLen];
		System.arraycopy(paddedMessage, arrStart, maskedSeed, 0, hLen);
		System.arraycopy(paddedMessage, arrStart+hLen, maskedDB, 0, dbLen);

		//generate seed mask and recover seed
		byte[] seedMask = maskGenFunc(maskedDB, hLen);
		byte[] seed = maskBytes(maskedSeed, seedMask);

		//generate dbMask and recover db
		byte[] dbMask = maskGenFunc(seed, dbLen);
		byte[] dataBlocks = maskBytes(maskedDB, dbMask);

		//try again if unmasked does not match empty string
		for (int i = 0; i < lBytes.length; i++)
			if (dataBlocks[i] != lBytes[i]) return new byte[]{};

		//find start of plaintext; copy to output array
		int ptMI;
		for (ptMI = lBytes.length; dataBlocks[ptMI] != 0x01; ptMI++);
		ptMI++;
		byte[] ptMessage = new byte[dataBlocks.length-ptMI];
		System.arraycopy(dataBlocks, ptMI, ptMessage, 0, ptMessage.length);
		
		return ptMessage;
	}

	/* Apply mask to byte array (xor data w/mask) */
	private static byte[] maskBytes (byte[] dBytes, byte[] mBytes) {
		byte[] maskedBytes = new byte[dBytes.length];
		for (int i = 0; i < maskedBytes.length; i++) maskedBytes[i] = (byte)(dBytes[i] ^ mBytes[i]);
		return maskedBytes;
	}

	/* Create mask bytes using random seed */
	private static byte[] maskGenFunc (byte[] seed, int maskLen) {
		//byte[] mask = new byte[maskLen/SHA256_Sum.ddByteN()];
		SHA256_Sum concatSum;
		int maskI = 0;
		byte[] mask = new byte[maskLen];
		byte[] concatStr = new byte[seed.length+4];
		System.arraycopy(seed, 0, concatStr, 0, seed.length);
		for (int i = 0; maskI < maskLen; i++) {
			concatSum = new SHA256_Sum();
			System.arraycopy(int2ByteStrPrim(i), 0, concatStr, seed.length, 4);
			concatSum.hashBytes(concatStr);
			int stopI = ((maskI+SHA256_Sum.ddByteN()) > maskLen) ? SHA256_Sum.ddByteN()-1 : SHA256_Sum.ddByteN();
			System.arraycopy(concatSum.toBytes(), 0, mask, maskI, stopI);
			maskI += SHA256_Sum.ddByteN();
		}
		return mask;
	}

	private static byte[] int2ByteStrPrim (int iBytes) {
		byte[] outBytes = new byte[4];
		for (int i = 0; i < outBytes.length; i++) outBytes[i] = (byte)((iBytes >> ((3-i)*8)) & 0xff);
		return outBytes;
	}
	
	private static void derivePubExp () {
		BigInteger privEnc = BigInteger.valueOf(2).modPow(KEY_PAIR[2], KEY_PAIR[0]);
		BigInteger testPubDec = privEnc.modPow(BigInteger.valueOf(2), KEY_PAIR[0]);
		
		//loop until a key works for decryption
		BigInteger e = BigInteger.ONE;
		do {
			e = e.add(BigInteger.valueOf(2));
			privEnc = privEnc.multiply(testPubDec).mod(KEY_PAIR[0]);
		} while ( privEnc.compareTo(BigInteger.valueOf(2)) != 0 );

		//save to this instance
		KEY_PAIR[1] = e;
	}

	/* Key generation method */
    private static BigInteger[] rsaGen() {
		BigInteger p, q, n, lambdaN, e, d;
		Random rng = new Random();

		//Generate n-bit pseudo-random prime BigInteger
		p = BigInteger.probablePrime(PRIME_SIZE, rng);
		q = BigInteger.probablePrime(PRIME_SIZE, rng);
		
		//Find n
		n = p.multiply(q);
		//Find lamda(n) <=> z
		lambdaN = eucLCM(p.subtract(BigInteger.ONE), q.subtract(BigInteger.ONE));

		//Find e (result is 2^16+1)
		e = BigInteger.valueOf(65536);
		do {
			e = e.add(BigInteger.ONE);
		} while ( !e.gcd(lambdaN).equals(BigInteger.ONE) );
		
		//Find d
		//e*d % z = 1
		//d = 1/e % lambdaN
		d = e.modInverse(lambdaN);

		return new BigInteger[]{n, e, d};
    }

	/* Euclid's LCM function for BigIntegers a & b */
	private static BigInteger eucLCM (BigInteger a, BigInteger b) {
		BigInteger lcm = a.multiply(b).abs();
		return lcm.divide(a.gcd(b));
	}
}
