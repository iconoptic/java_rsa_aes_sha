import java.util.Arrays;
import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Paths;

public class SHA256_Sum {
    private static int BLOCK_BYTES = 0x40;
	private static int M_COUNT, MAX_CHUNK;
	private static int[] CONST_K, HASH_VAL, SEED;
	private static long FILE_I, byteCount;
    
    public SHA256_Sum () {
		M_COUNT = BLOCK_BYTES/4;
		SEED = new int[]{0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
		MAX_CHUNK = 512*1024;
		CONST_K = new int[]{0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
		FILE_I = 0;
	}

	public static int ddByteN () {
		//return length of digest in bytes (for RSA padding)
		return BLOCK_BYTES/2;
	}

	public String toString () {
		String strOut = "";
		for (int h : HASH_VAL) strOut += String.format("%08x", h);
		return strOut;
	}

	public byte[] toBytes () {
		byte[] sumBytes = new byte[HASH_VAL.length*4];
		for (int i = 0; i < sumBytes.length; i++)
			sumBytes[i] = (byte)((HASH_VAL[i/4] >> ((3-i)*8)) & 0xff);
		return sumBytes;
	}

	/* These three functions could be one */
	public void hashEmptyStr () {
		//seed value for hash
		HASH_VAL = Arrays.copyOf(SEED, SEED.length);
		
		int[][] messageBlocks = new int[1][M_COUNT]; // bytes2Blocks(inBytes);

		//input is one block of padding; ends with byte count of 0
		byte[] padded = new byte[BLOCK_BYTES];
		padded[0] = (byte) 0x80;
		for (int i = 1; i < padded.length; i++) 
			padded[i] = 0x0;
		
		//complete hash
		messageBlocks = bytes2Blocks(padded);
		iterHash(messageBlocks);
	}

	public void hashBytes (byte[] byteStr) {
		byteCount = byteStr.length;
		byte[] inBytes;

		//seed value for hash
		HASH_VAL = Arrays.copyOf(SEED, SEED.length);

		int[][] messageBlocks;
		int tailArrSize = blocksPlusPad();
		inBytes = Arrays.copyOf(byteStr, tailArrSize);

		//add padding to last block
		int startPos;
		if (byteCount <= 56) startPos = 0; 
		else startPos = tailArrSize - (BLOCK_BYTES * 2);
		//pad the end of the array
		byte[] padded = pad(Arrays.copyOfRange(inBytes,startPos,tailArrSize));
		//copy padded blocks back to inBytes array
		System.arraycopy(padded, 0, inBytes, startPos, padded.length);
		
		//complete hash
		messageBlocks = bytes2Blocks(inBytes);
		iterHash(messageBlocks);
	}
	
    public void hashFile (String fileN) throws Exception {
		//message file to byte array
		byteCount = Files.size(Paths.get(fileN));

		//prevents error if given file is empty
		if (byteCount == 0) hashEmptyStr();
		else {
			FileInputStream fInStream = new FileInputStream(fileN);
			BufferedInputStream inFile = new BufferedInputStream(fInStream);
			byte[] inBytes;

			//seed value for hash
			HASH_VAL = Arrays.copyOf(SEED, SEED.length);

			int[][] messageBlocks;

			//iterate hash for files larger than MAX_CHUNK
			while (byteCount > (long)MAX_CHUNK + FILE_I) {
				inBytes = file2ByteArr(inFile, MAX_CHUNK);
				messageBlocks = bytes2Blocks(inBytes);
				iterHash(messageBlocks);
			}

			int tailArrSize = blocksPlusPad();

			inBytes = file2ByteArr(inFile, tailArrSize);
			inFile.close();

			//add padding to last block
			int startPos;
			if (byteCount <= 56) startPos = 0; 
			else startPos = tailArrSize - (BLOCK_BYTES * 2);
			//pad the end of the array
			byte[] padded = pad(Arrays.copyOfRange(inBytes,startPos,tailArrSize));
			//copy padded blocks back to inBytes array
			System.arraycopy(padded, 0, inBytes, startPos, padded.length);
			
			//complete hash
			messageBlocks = bytes2Blocks(inBytes);
			iterHash(messageBlocks);
		}
    }

	private static void iterHash (int[][] messageBlocks) {
		//convert imported bytes to array of blocks
		int[] messageSchedule;
		//array to store working variables
		int[] working = new int[HASH_VAL.length];
		for (int i = 0; i < messageBlocks.length; i++) {
			//prep message schedule
			messageSchedule = calcSchedule(messageBlocks[i]);

			//init working vars
			System.arraycopy(HASH_VAL, 0, working, 0, HASH_VAL.length);

			//transform working vars
			working = iterWorking(working, messageSchedule);

			//calculate intermediate hash
			for (int j = 0; j < HASH_VAL.length; j++) 
				HASH_VAL[j] += working[j];
		}
	}

	private static int[] iterWorking (int[] working, int[] messageSchedule) {
		int t1, t2;
		for (int t = 0; t < 64; t++) {
			t1 = working[7] + uSigmaOne(working[4]) + funcCh(working[4], working[5], working[6]) + CONST_K[t] + messageSchedule[t];
			t2 = uSigmaZero(working[0]) + funcMaj(working[0], working[1], working[2]);
			
			for (int j = 7; j > 4; j--) working[j] = working[j-1];
			working[4] = working[3] + t1;
			
			for (int j = 3; j > 0; j--) working[j] = working[j-1];
			working[0] = t1 + t2;
		}
		return working;
	}
	
	private static int[] calcSchedule (int[] curBlock) {
		int[] messageSchedule = new int[BLOCK_BYTES];
		int i;
		
		//for first 16 blocks: mSched == m
		for (i = 0; i < curBlock.length; i++) messageSchedule[i] = curBlock[i];

		for (; i < messageSchedule.length; i++ ) {
			messageSchedule[i] = lSigmaOne(messageSchedule[i-2]);
			messageSchedule[i] += messageSchedule[i-7];
			messageSchedule[i] += lSigmaZero(messageSchedule[i-15]);
			messageSchedule[i] += messageSchedule[i-16];
		}

		return messageSchedule;
	}

	
	private static byte[] file2ByteArr (BufferedInputStream inFile, int byteLen) throws Exception {
		byte[] inBytes = new byte[byteLen];

		//read input file to byte array
		inFile.read(inBytes, 0, byteLen);
		FILE_I += byteLen;
		
		return inBytes;
	}

	private static int blocksPlusPad () {
		int remainder = (int)(byteCount % BLOCK_BYTES);
		int arrSize = (int)(byteCount - FILE_I + BLOCK_BYTES - remainder);
		if ( remainder >= 56)
			return arrSize + BLOCK_BYTES;
		else
			return arrSize;
	}

    private static byte[] pad (byte[] tail) {
		int tailLen = (int)(byteCount % BLOCK_BYTES);
		//start index to append padding
		int i;
		if ( tail[tailLen] != 0 || tailLen % BLOCK_BYTES == 0) i = tailLen + BLOCK_BYTES;
		else  i = tailLen;
		if (tailLen == 0) tailLen += BLOCK_BYTES;
		
		//bits of message in final block
		long tailBits = 0; // (long)(byteCount * 8);
		for (int j = 0; j < 8; j++) tailBits += byteCount;

		//Add padding: 0b100...
		tail[i++] = (byte)0x80;
		for (; i < tail.length - 8; i++ ) //- 8; i++)
			tail[i] = (byte)0x00;

		for (; i < tail.length; i++)
			tail[i] = (byte)(tailBits>>(tail.length-i-1)*8);
		
		return tail;
    }

	private static int[][] bytes2Blocks (byte[] inArr) {
		int blockCount = inArr.length/(M_COUNT*4);
		int wordSize = M_COUNT/4;
		int[][] messageBlocks = new int[blockCount][M_COUNT];
		ByteBuffer wordBuffer = ByteBuffer.wrap(inArr);

 		for (int i = 0; i < blockCount; i++) 
			for (int j = 0; j < BLOCK_BYTES; j+=wordSize) 
				messageBlocks[i][j/wordSize] = wordBuffer.getInt(i*BLOCK_BYTES+j);
		
		return messageBlocks;
	}

	/* Functions for iterating working variables. */

	private static int funcMaj (int x, int y, int z) {
		return (x & y) ^ (x & z) ^ (y & z);
	}
	private static int funcCh (int x, int y, int z) {
		return (x & y) ^ (~x & z);
	}
	
	private static int uSigmaZero (int word) {
		int rotr2 = Integer.rotateRight(word, 2);
		int rotr13 = Integer.rotateRight(word, 13);
		int rotr22 = Integer.rotateRight(word, 22);
		return rotr2 ^ rotr13 ^ rotr22;
	}
	
	private static int uSigmaOne (int word) {
		int rotr6 = Integer.rotateRight(word, 6);
		int rotr11 = Integer.rotateRight(word, 11);
		int rotr25 = Integer.rotateRight(word, 25);
		return rotr6 ^ rotr11 ^ rotr25;
	}
	
	/* Functions for iterating message schedule. */

	private static int lSigmaZero (int word) {
		int rotr7 = Integer.rotateRight(word, 7);
		int rotr18 = Integer.rotateRight(word, 18);
		int shr3 = word >>> 3;
		return rotr7 ^ rotr18 ^ shr3;
	}
	
	private static int lSigmaOne (int word) {
		int rotr17 = Integer.rotateRight(word, 17);
		int rotr19 = Integer.rotateRight(word, 19);
		int shr10 = word >>> 10;
		return rotr17 ^ rotr19 ^ shr10;
	}
}
