import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.BufferedOutputStream;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;

public class AES128_Sym {
	private static int[] KEY_W, R_CONST;
    private static int KEY_SIZE, NUM_WORD, NUM_ROUND;
	private static byte[] MIX_A, INV_MIX_A, SYM_KEY;
	private static byte CONST_C, INV_CONST_C;

    public AES128_Sym () {
		//128-bit key params
		KEY_SIZE = 16;			//16-byte key
		NUM_WORD = KEY_SIZE/4;
		NUM_ROUND = 10;

		//Matrices for mix columns (defined as the vector form of row[0]-transpose)
		MIX_A = int2ByteArr(0x02030101);
		INV_MIX_A = int2ByteArr(0x0e0b0d09);

		//Round constant for key expansion
		R_CONST = new int[]{0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000, 0x20000000, 0x40000000, 0x80000000, 0x1b000000, 0x36000000};

		//Constant c for subBytes function
		CONST_C = (byte)0x63;
		//Constant c for the invSubBytes function
		INV_CONST_C = (byte)0x05;
   }

   /* Interface Functions */
	
	public void readKeyFile (String fileN) throws Exception {
		BufferedInputStream keyFile = new BufferedInputStream(new FileInputStream(fileN));
		SYM_KEY = new byte[KEY_SIZE];
		int i;
		
		for (i = 0; keyFile.available() > 0; i++) 
			SYM_KEY[i] = (byte)keyFile.read();
		keyFile.close();
    }

	public String toString() {
		String strOut = "";
		for (byte c : SYM_KEY) strOut += String.format("%c",c);
		return strOut;
	}

	public String toByteString () {
		String strOut = "";
		for (byte b : SYM_KEY) strOut += String.format("%02x", b);
		return strOut;
	}

	public void decrypt (String ctFile, String ptFile) throws Exception {
		BufferedInputStream ctFStream = new BufferedInputStream(new FileInputStream(ctFile));
		BufferedOutputStream ptFStream = new BufferedOutputStream(new FileOutputStream(ptFile));
		long ctByteN = Files.size(Paths.get(ctFile));
		int buffSize = 1024*KEY_SIZE;
		byte[] ctBytes = new byte[buffSize];
		byte[] ptBytes = new byte[buffSize];
		byte[] padBytes;
		int i, padBound;

		for (i = 0; i < ctByteN-buffSize; i += buffSize) {
			ctFStream.read(ctBytes, 0, buffSize);
			ptBytes = arrToCipher(ctBytes, buffSize, true);
			ptFStream.write(ptBytes, 0, buffSize);
		}
		
		//decrypt last block
		buffSize = (int)(ctByteN-i);
		ctFStream.read(ctBytes, 0, buffSize);
		padBytes = new byte[buffSize];
		padBytes = arrToCipher(ctBytes, buffSize, true);

		//remove padding and save to file
		for (padBound = buffSize - 1; padBytes[padBound] == 0x0; padBound--);
		if (padBytes[padBound] == (byte)0x80) {
			buffSize = padBound;
			ptBytes = new byte[buffSize];
			System.arraycopy(padBytes, 0, ptBytes, 0, buffSize);
		}
		
		ptFStream.write(ptBytes, 0, buffSize);

		ptFStream.close();
		ctFStream.close();
	}

	public void encrypt (String ptFile, String ctFile) throws Exception {
		BufferedInputStream ptFStream = new BufferedInputStream(new FileInputStream(ptFile));
		BufferedOutputStream ctFStream = new BufferedOutputStream(new FileOutputStream(ctFile));
		long ptByteN = Files.size(Paths.get(ptFile));
		int buffSize = 1024*KEY_SIZE;
		byte[] ptBytes = new byte[buffSize];
		byte[] ctBytes = new byte[buffSize];
		int i, padStart;

		for (i = 0; i < ptByteN-buffSize; i += buffSize) {
			ptFStream.read(ptBytes, 0, buffSize);
			ctBytes = arrToCipher(ptBytes, buffSize, false);
			ctFStream.write(ctBytes, 0, buffSize);
		}

		//add padding
		padStart = (int)(ptByteN-i);
		buffSize = padStart;
		buffSize += (padStart % 16 != 0) ? (16-(padStart%16)) : 16;
		ptBytes = new byte[buffSize];
		ptBytes[padStart] = (byte)0x80;
		for (int j = padStart+1; j < KEY_SIZE; j++)
			ptBytes[j] = (byte)0x0;

		//encrypt last block
		ptFStream.read(ptBytes, 0, padStart);
		ctBytes = arrToCipher(ptBytes, buffSize, false);
		ctFStream.write(ctBytes, 0, buffSize);

		ptFStream.close();
		ctFStream.close();
	}

	private static byte[] arrToCipher (byte[] inBytes, int buffSize, boolean inv) {
		byte[] outBytes = new byte[buffSize];
		byte[] stateBytes = new byte[KEY_SIZE];
		for (int i = 0; i < buffSize; i += KEY_SIZE) {
			System.arraycopy(inBytes, i, stateBytes, 0, KEY_SIZE);
			if (inv) System.arraycopy(invCipher(stateBytes), 0, outBytes, i, KEY_SIZE);
			else System.arraycopy(cipher(stateBytes), 0, outBytes, i, KEY_SIZE);
		}
		return outBytes;
	}

	/* Cipher Functions */

	private static byte[] cipher (byte[] plainText) {
		byte[][] state = byteArr2Nested(plainText);
		byte[][] wSched = new byte[state.length][];
		
		for (int j = 0; j < wSched.length; j++) 
			wSched[j] = int2ByteArr(KEY_W[j]);
		
		state = addRoundKey(state, wSched);
		
		//iterate through key schedule and message
		for (int i = 1; i < NUM_ROUND; i++) {
			state = subArrBytes(state);
			state = shiftRows(state);
			state = mixColumns(state);
			for (int j = 0; j < wSched.length; j++)
				wSched[j] = int2ByteArr(KEY_W[4*i+j]);
			state = addRoundKey(state, wSched);
		}

		//final iteration (w/o mixColumns)
		state = subArrBytes(state);
		state = shiftRows(state);
		for (int j = 0; j < wSched.length; j++)
			wSched[j] = int2ByteArr(KEY_W[4*NUM_ROUND+j]);
		state = addRoundKey(state, wSched);

		return nested2ByteArr(state); //byteArr2IntArr(state);
	}

	private static byte[][] mixColumns (byte[][] state) {
		for (int i = 0; i < state.length; i++) 
			state[i] = gf8MultVector(state[i], false);
		return state;
	}


	private static byte[][] shiftRows (byte[][] state) {
		byte[][] shifted = new byte[state.length][state[0].length];
		//copy first row
		for (int c = 0; c < state.length; c++)
			shifted[c][0] = state[c][0];
		
		//shift remaining rows by r
		for (int r = 1; r < state[0].length; r++)
			for (int c = 0; c < state.length; c++)
				shifted[c][r] = state[(c+r)%state.length][r];
		
		return shifted;
	}

	private static byte[][] subArrBytes (byte[][] state) {
		for (int i = 0; i < state.length; i++)
			state[i] = int2ByteArr(subBytes(byteArr2IntArr(state[i])[0]));
		return state;
	}

	private static byte[][] addRoundKey (byte[][] state, byte[][] wSched) {
		for (int i = 0; i < state.length; i++) 
			for (int j = 0; j < state[i].length; j++) 
				state[i][j] = gf8Add(state[i][j], wSched[i][j]);
		return state;
	}
	
	/* Inverse Cipher Functions */

	private static byte[] invCipher (byte[] cipherText) {
		byte[][] state = byteArr2Nested(cipherText);
		byte[][] wSched = new byte[state.length][];

		for (int j = 0; j < wSched.length; j++)
			wSched[j] = int2ByteArr(KEY_W[4*NUM_ROUND+j]);
		
		state = addRoundKey(state, wSched);
		
		//iterate through key schedule and message
		for (int i = NUM_ROUND-1; i > 0; i--) {
			//printState(state);
			state = invShiftRows(state);
			state = invSubArrBytes(state);
			for (int j = 0; j < wSched.length; j++)
				wSched[j] = int2ByteArr(KEY_W[4*i+j]);
			state = addRoundKey(state, wSched);
			state = invMixColumns(state);
		}

		//final iteration (w/o mixColumns)
		state = invShiftRows(state);
		state = invSubArrBytes(state);
		for (int j = 0; j < wSched.length; j++) 
			wSched[j] = int2ByteArr(KEY_W[j]);
		state = addRoundKey(state, wSched);

		return nested2ByteArr(state); 
	}

	private static byte[][] invMixColumns (byte[][] state) {
		for (int i = 0; i < state.length; i++) 
			state[i] = gf8MultVector(state[i], true);
		return state;
	}

	private static byte[][] invShiftRows (byte[][] state) {
		byte[][] shifted = new byte[state.length][state[0].length];
		//copy first row
		for (int c = 0; c < state.length; c++)
			shifted[c][0] = state[c][0];
		
		//shift remaining rows by r
		for (int r = 1; r < state[0].length; r++)
			for (int c = 0; c < state.length; c++) 
				shifted[c][r] = state[((c-r)+state.length)%state.length][r];
		
		return shifted;
	}

	private static byte[][] invSubArrBytes (byte[][] state) {
		for (int i = 0; i < state.length; i++)
			state[i] = int2ByteArr(invSubBytes(byteArr2IntArr(state[i])[0]));
		return state;
	}

	private static int invSubBytes (int sBytes) {
		byte[] inBytes = int2ByteArr(sBytes);
		byte[] tfBytes = new byte[inBytes.length];
		byte[] invBytes = {(byte)0x0, (byte)0x0, (byte)0x0, (byte)0x0};
		int[] rotN = {1, 3, 6};

		for (int i = 0; i < inBytes.length; i++) {
			tfBytes[i] = 0x0;
			for (int j = 0; j < 3; j++) 
				tfBytes[i] = gf8Add(tfBytes[i], lRotByte(inBytes[i], (byte)rotN[j]));
			tfBytes[i] = gf8Add(tfBytes[i], INV_CONST_C);
		}
		
		//invert bytes != 0
		for (int i = 0; i < invBytes.length; i++)
			if (tfBytes[i] != (byte)0x0) invBytes[i] = gf8Inv(tfBytes[i]);

		return byteArr2IntArr(invBytes)[0];
	}

	/* Key Expansion Functions */

	public void expandKey () {
		int loopTerm = 4 * NUM_ROUND + 4;
		KEY_W = new int[loopTerm];
		System.arraycopy(byteArr2IntArr(SYM_KEY), 0, KEY_W, 0, NUM_WORD);
		
		int temp;
		for (int i = NUM_WORD; i < loopTerm; i++) {
			temp = KEY_W[i-1];
			if (i % NUM_WORD == 0) temp = subBytes(Integer.rotateLeft(temp, 8)) ^ R_CONST[i/NUM_WORD - 1];
			KEY_W[i] = KEY_W[i-NUM_WORD] ^ temp;
		}
	}

	private static int subBytes (int sBytes) {
		byte[] inBytes = int2ByteArr(sBytes);
		byte[] invBytes = {(byte)0, (byte)0, (byte)0, (byte)0};
		byte[] outBytes = new byte[inBytes.length];

		//invert bytes != 0
		for (int i = 0; i < invBytes.length; i++)
			if (inBytes[i] != (byte)0x00) invBytes[i] = gf8Inv(inBytes[i]);

		//affine transformation
		for (int i = 0; i < outBytes.length; i++) {
			outBytes[i] = invBytes[i];
			for (int j = 1; j <= 4; j++)
				outBytes[i] = gf8Add(outBytes[i], lRotByte(invBytes[i], (byte)j));
			outBytes[i] = gf8Add(outBytes[i], CONST_C);
		}

		return byteArr2IntArr(outBytes)[0];
	}

	private static byte lRotByte (byte in, byte shift) {
		return (byte)((in << shift) | ((in & 0xff) >>> (8-shift)));
	}

	/* Galois Field Functions */
	
	private static byte gf8Add (byte a, byte b) {
		return (byte)(a ^ b);
	}
	
	/* Peasant's algorithm */
	private static byte gf8Mult (byte a, byte b) {
		byte prod = 0x0;
		byte irrPoly = 0x1b;
		byte carry;
		for (int i = 7; i >= 0; i--) {
			if ((b & 0x01) == 1) prod = gf8Add(prod, a);
			b = (byte)((b&0xff) >> 1);
			carry = (byte)(a&0x80);
			a = (byte)((a << 1)&0xff);
			if (carry == (byte)0x80) a = gf8Add(a, irrPoly);
		}
		return prod;
	}

	/* Brute-force approach to find GF8 inverse */
	private static byte gf8Inv (byte in) {
		byte i = 0, inv = 0;
		for (; inv != (byte)0x1; i++) inv = gf8Mult(in, i);
		return --i;
	}
	
	private static byte[] gf8MultVector (byte[] stateVect, boolean invA) {
		byte[] outVect = new byte[stateVect.length];
		byte[] matA = (invA) ? INV_MIX_A : MIX_A;
		
		for (int i = 0; i < stateVect.length; i++) {
			outVect[i] = 0x0;
			for (int j = 0; j < matA.length; j++)
				outVect[i] = gf8Add(outVect[i], gf8Mult(matA[j], stateVect[j]));
			//rotated vector <=> next row in matrix
			matA = int2ByteArr(Integer.rotateRight(byteArr2IntArr(matA)[0], 8));
		}

		return outVect;
	}

	/* Byte Conversion Functions
		For conversions between byte arrays and integers/integer arrays. */

	private static byte[] int2ByteArr (int iBytes) {
		byte[] outBytes = new byte[4];
		for (int i = 0; i < outBytes.length; i++) outBytes[i] = (byte)((iBytes >> ((3-i)*8)) & 0xff);
		return outBytes;
	}

	private static int[] byteArr2IntArr (byte[] byteArr) {
		int[] intArr = new int[byteArr.length/4];
		for (int i = 0; i < byteArr.length; i++) intArr[i/4] |= (byteArr[i] & 0xff) << ((3-i%4)*8);
		return intArr;
	}

	private static byte[][] byteArr2Nested (byte[] byteArr) {
		byte[][] nested = new byte[byteArr.length/4][4];
		for (int i = 0; i < byteArr.length; i++)
			nested[i/4][i%4] = byteArr[i];
		return nested;
	}

	private static byte[] nested2ByteArr (byte[][] nested) {
		byte[] byteArr = new byte[nested.length*nested[0].length];
		for (int i = 0; i < byteArr.length; i++)
			byteArr[i] = nested[i/4][i%4];
		return byteArr;
	}

	/* For displaying state and comparing to examples in FIPS-197 */
	private static void printState (byte[][] state) {
		for (int c = 0; c < state[0].length; c++) {
			for (int r = 0; r < state.length; r++)
				System.out.format("%02x ", state[r][c]);
			System.out.println();
		}
		System.out.println();
	}
}
