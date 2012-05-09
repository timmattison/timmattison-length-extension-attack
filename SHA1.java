import java.security.NoSuchAlgorithmException;

/*
 * A Java implementation of the Secure Hash Algorithm, SHA-1, as defined
 * in FIPS PUB 180-1
 * Copyright (C) Sam Ruby 2004
 * All rights reserved
 *
 * Based on code Copyright (C) Paul Johnston 2000 - 2002.
 * See http://pajhome.org.uk/site/legal.html for details.
 *
 * Converted to Java by Russell Beattie 2004
 * Base64 logic and inlining by Sam Ruby 2004
 * Bug fix correcting single bit error in base64 code by John Wilson
 *
 *                                BSD License
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer. Redistributions in binary
 * form must reproduce the above copyright notice, this list of conditions and
 * the following disclaimer in the documentation and/or other materials
 * provided with the distribution.
 *
 * Neither the name of the author nor the names of its contributors may be
 * used to endorse or promote products derived from this software without
 * specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

public class SHA1 {
	public static void main(String[] args) throws NoSuchAlgorithmException {
		int secretKeyLength = Integer.parseInt(args[0]);
		String originalMessage = args[1];
		String originalHash = args[2];
		String hackedSuffix = args[3];
		byte[] hackedSuffixBytes = hackedSuffix.getBytes();

		// The length of the message with the secret key
		int originalMessageLengthWithKey = secretKeyLength
				+ originalMessage.length();

		// The length of the padding on the original message
		int originalMessagePaddingLength = generatePadding(originalMessageLengthWithKey).length;

		// The length of the message with the secret key and padding
		int totalOriginalMessageLength = originalMessageLengthWithKey
				+ originalMessagePaddingLength;

		// The length of the hacked message
		int hackedMessageLength = totalOriginalMessageLength
				+ hackedSuffix.length();

		// The padding for the hacked message
		byte[] hackedMessagePadding = generatePadding(hackedSuffixBytes.length,
				hackedMessageLength);

		// The hacked message with the hacked padding
		byte[] hackedMessageBytes = SHA1.concat(hackedSuffix.getBytes(),
				hackedMessagePadding);

		// Print out the new hash from the hacked message
		System.out.println("New hash: "
				+ encode(toShorts(hackedMessageBytes),
						extractState(originalHash), false));
	}

	/**
	 * Concatenate several byte arrays together
	 * 
	 * @param arrays
	 * @return
	 */
	public static byte[] concat(byte[]... arrays) {
		// Calculate the length of the output array
		int length = 0;

		for (byte[] array : arrays) {
			length += array.length;
		}

		// Allocate the output array
		byte[] output = new byte[length];

		// Copy all of the data into the output array
		int lastPosition = 0;

		for (byte[] array : arrays) {
			System.arraycopy(array, 0, output, lastPosition, array.length);
			lastPosition += array.length;
		}

		return output;
	}

	private static byte[] generatePadding(byte[] bytes) {
		return generatePadding(bytes.length, bytes.length);
	}

	private static byte[] generatePadding(int count) {
		return generatePadding(count, count);
	}

	private static byte[] generatePadding(int count, int desiredByteCount) {
		int currentBlockLength = count % 64;
		int paddingLength = (64 - currentBlockLength);

		// We need 17 bytes for the padding
		if ((currentBlockLength + 17) > 64) {
			// We need to generate another block
			paddingLength += 64;
		}

		// Create an array to hold the padding data
		byte[] padding = new byte[paddingLength];

		// The first padding byte is always 0x80
		padding[0] = (byte) 0x80;

		// Fill in all of the padding with zeroes
		for (int loop = 1; loop < (paddingLength - 8); loop++) {
			padding[loop] = 0;
		}

		// Determine the bit count
		int bitCount = desiredByteCount * 8;

		/**
		 * Convert the bit count to a quadword (this will only work for bit
		 * counts < 2^32
		 */
		byte[] bitCountQuadWord = convertToQuadword(bitCount);

		// Copy the bit count to the end of the padding
		padding[paddingLength - 8] = bitCountQuadWord[0];
		padding[paddingLength - 7] = bitCountQuadWord[1];
		padding[paddingLength - 6] = bitCountQuadWord[2];
		padding[paddingLength - 5] = bitCountQuadWord[3];
		padding[paddingLength - 4] = bitCountQuadWord[4];
		padding[paddingLength - 3] = bitCountQuadWord[5];
		padding[paddingLength - 2] = bitCountQuadWord[6];
		padding[paddingLength - 1] = bitCountQuadWord[7];

		return padding;
	}

	/**
	 * Convert an integer to a byte array representing its value as a quad word.
	 * Used for the final 64 bits of the padding that represents the message
	 * length.
	 * 
	 * @param count
	 * @return
	 */
	private static byte[] convertToQuadword(int count) {
		byte[] output = new byte[8];

		output[0] = (byte) ((count & 0xFF00000000000000L) >> 56);
		output[1] = (byte) ((count & 0x00FF000000000000L) >> 48);
		output[2] = (byte) ((count & 0x0000FF0000000000L) >> 40);
		output[3] = (byte) ((count & 0x000000FF00000000L) >> 32);
		output[4] = (byte) ((count & 0x00000000FF000000L) >> 24);
		output[5] = (byte) ((count & 0x0000000000FF0000L) >> 16);
		output[6] = (byte) ((count & 0x000000000000FF00L) >> 8);
		output[7] = (byte) ((count & 0x00000000000000FFL));

		return output;
	}

	/**
	 * HACK - Throws an exception if assertedValue is false
	 * 
	 * @param assertedValue
	 */
	private static void checkAssertion(boolean assertedValue) {
		if (assertedValue != true) {
			// Assertion failed
			throw new AssertionError();
		}
	}

	/**
	 * Bitwise rotate a 32-bit number to the left
	 */
	private static int rol(int num, int cnt) {
		return (num << cnt) | (num >>> (32 - cnt));
	}

	/**
	 * Converts a byte array to a short array
	 * 
	 * @param bytes
	 * @return
	 */
	public static short[] toShorts(byte[] bytes) {
		// Allocate space for the new array
		short[] temp = new short[bytes.length];

		/**
		 * Loop through and copy all of the byte values (can't use
		 * System.arrayCopy since they are different types)
		 */
		for (int loop = 0; loop < bytes.length; loop++) {
			temp[loop] = bytes[loop];
		}

		// Convert all negative values to their correct byte values
		fixNegatives(temp);

		return temp;
	}

	/**
	 * Extracts the state of a SHA-1 hash from a hex string containing 5 32-bit
	 * words
	 * 
	 * @param state
	 * @return
	 */
	private static int[] extractState(String state) {
		// Make sure the state isn't NULL
		checkAssertion(state != null);

		// Make sure the state is the correct length (40 characters)
		checkAssertion(state.length() == 40);

		// Extract the 5 32-bit words
		int H0 = (int) Long.parseLong(state.substring(0, 8), 16);
		int H1 = (int) Long.parseLong(state.substring(8, 16), 16);
		int H2 = (int) Long.parseLong(state.substring(16, 24), 16);
		int H3 = (int) Long.parseLong(state.substring(24, 32), 16);
		int H4 = (int) Long.parseLong(state.substring(32, 40), 16);

		// Put the 5 32-bit words into an array
		int[] stateValues = new int[5];
		stateValues[0] = H0;
		stateValues[1] = H1;
		stateValues[2] = H2;
		stateValues[3] = H3;
		stateValues[4] = H4;

		return stateValues;
	}

	/**
	 * Converts values that were converted from signed bytes to their unsigned
	 * byte equivalents in a short array
	 * 
	 * @param shorts
	 */
	private static void fixNegatives(short[] shorts) {
		for (int loop = 0; loop < shorts.length; loop++) {
			if (shorts[loop] < 0) {
				short temp = shorts[loop];
				temp = (short) (256 + temp);
				shorts[loop] = temp;
			}
		}
	}

	/**
	 * Calculates the SHA-1 hash of a string
	 * 
	 * @param string
	 * @return
	 */
	public static String encode(String string, boolean calculatePadding) {
		return encode(string.getBytes(), calculatePadding);
	}

	/**
	 * Calculates the SHA-1 hash of a byte array
	 * 
	 * @param bytes
	 * @return
	 */
	public static String encode(byte[] bytes, boolean calculatePadding) {
		return encode(toShorts(bytes), calculatePadding);
	}

	/**
	 * Take a byte array and return the hex representation of its SHA-1 using
	 * the standard state values
	 */
	public static String encode(short[] shorts, boolean calculatePadding) {
		// These are the default values
		int[] stateValues = extractState("67452301EFCDAB8998BADCFE10325476C3D2E1F0");

		checkAssertion(stateValues[0] == 1732584193);
		checkAssertion(stateValues[1] == -271733879);
		checkAssertion(stateValues[2] == -1732584194);
		checkAssertion(stateValues[3] == 271733878);
		checkAssertion(stateValues[4] == -1009589776);

		return encode(shorts, stateValues, calculatePadding);
	}

	/**
	 * Take a short array and return the hex representation of its SHA-1 using
	 * some given state values
	 * 
	 * @param shorts
	 * @param stateValues
	 * @return
	 */
	private static String encode(short[] shorts, int[] stateValues,
			boolean calculatePadding) {
		return encode(shorts, stateValues[0], stateValues[1], stateValues[2],
				stateValues[3], stateValues[4], calculatePadding);
	}

	/**
	 * Take a byte array and return the hex representation of its SHA-1 using
	 * some given state values
	 */
	private static String encode(short[] shorts, int H0, int H1, int H2,
			int H3, int H4, boolean calculatePadding) {
		// Convert a string to a sequence of 16-word blocks, stored as an array.
		// Append padding bits and the length, as described in the SHA1 standard

		int[] blocks;

		if (calculatePadding) {
			// Calculate padding

			// Example 1:
			// Bytes: 0x00 x 2
			//
			// Step 1: 2 + 8 = 10 bytes
			// Step 2: 10 >> 6 = 0 full blocks
			// Step 3: 0 + 1 = 1 full block
			// Step 4: 1 * 16 = 16 words
			//
			// Example 2:
			// Bytes: 0x00 x 64
			// Length: 64
			//
			// Step 1: 64 + 8 = 72 bytes
			// Step 2: 72 >> 6 = 1 full block
			// Step 3: 1 + 1 = 2 full blocks
			// Step 4: 2 * 16 = 32 words

			/**
			 * Step 1: Add 8 bytes to the length of the data for the initial
			 * padding byte (0x80)
			 */
			int step1 = shorts.length + 8;

			/**
			 * Step 2: Shift right by 6/divide by 64 calculate the number of
			 * full 512-bit blocks (one 64-byte block is one 512-bit block)
			 */
			int step2 = step1 >> 6;

			// Step 3: Add 1 so there is at least one full 512-bit block
			int step3 = step2 + 1;

			/**
			 * Step 4: Multiply by 16 to get back to the number of 16-byte
			 * sub-blocks
			 */
			int numberOfBlocks = step3 * 16;

			// Allocate space for the blocks
			blocks = new int[numberOfBlocks];

			// SHA-1 padding
			// Step 1: Place the trailing 1 bit where it belongs
			blocks[shorts.length >> 2] |= 0x80 << (24 - (shorts.length % 4) * 8);

			// Step 2: End the data with the number of bits in the message
			blocks[blocks.length - 1] = shorts.length * 8;
		} else {
			// No padding to calculate

			// Calculate the number of blocks
			int numberOfBlocks = shorts.length >> 2;

			// Allocate space for the blocks
			blocks = new int[numberOfBlocks];

			// Do we have data that falls exactly on a 512-bit boundary?
			if ((shorts.length % 64) != 0) {
				// No, quit
				throw new AssertionError("Length must be a multiple of 64 ["
						+ shorts.length + "]");
			}
		}

		// Set up the blocks
		for (int loop = 0; loop < shorts.length; loop++) {
			blocks[loop >> 2] |= shorts[loop] << (24 - (loop % 4) * 8);
		}

		// Calculate 160 bit SHA1 hash of the sequence of blocks
		int[] w = new int[80];

		for (int loop = 0; loop < blocks.length; loop += 16) {
			int oldH0 = H0;
			int oldH1 = H1;
			int oldH2 = H2;
			int oldH3 = H3;
			int oldH4 = H4;

			for (int innerLoop = 0; innerLoop < 80; innerLoop++) {
				w[innerLoop] = (innerLoop < 16) ? blocks[loop + innerLoop]
						: (rol(w[innerLoop - 3] ^ w[innerLoop - 8]
								^ w[innerLoop - 14] ^ w[innerLoop - 16], 1));

				int t = rol(H0, 5)
						+ H4
						+ w[innerLoop]
						+ ((innerLoop < 20) ? 1518500249 + ((H1 & H2) | ((~H1) & H3))
								: (innerLoop < 40) ? 1859775393 + (H1 ^ H2 ^ H3)
										: (innerLoop < 60) ? -1894007588
												+ ((H1 & H2) | (H1 & H3) | (H2 & H3))
												: -899497514 + (H1 ^ H2 ^ H3));
				H4 = H3;
				H3 = H2;
				H2 = rol(H1, 30);
				H1 = H0;
				H0 = t;
			}

			H0 = H0 + oldH0;
			H1 = H1 + oldH1;
			H2 = H2 + oldH2;
			H3 = H3 + oldH3;
			H4 = H4 + oldH4;
		}

		StringBuilder stringBuilder = new StringBuilder();
		stringBuilder.append(String.format("%08x", H0));
		stringBuilder.append(String.format("%08x", H1));
		stringBuilder.append(String.format("%08x", H2));
		stringBuilder.append(String.format("%08x", H3));
		stringBuilder.append(String.format("%08x", H4));

		return stringBuilder.toString();
	}
}
