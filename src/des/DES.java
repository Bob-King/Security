package des;

/*
 * Leave it now
 */

public class DES {

	/*
	public DES(final long key) {
		mKey = key;
	}
	
	public long[] encrypt(long[] plaintext) {
		final long[] TURN_KEYS = generateTurnKeys();
		return plaintext;
	}
	
	public long[] decrypt(long[] ciphertext) {
		return ciphertext;
	}
	
	private long[] generateTurnKeys() {
		long[] keys = new long[16];
		
		keys[0] = p(mKey, PC1);
		keys[0] = shiftKey(keys[0], TURN_SHIFT_TABLE[0]);
		
		for (int i = 1; i != keys.length; ++i) {
			keys[i] = shiftKey(keys[i - 1], TURN_SHIFT_TABLE[i]);
		}
		
		for (int i = 0; i != keys.length; ++i) {
			keys[i] = p(mKey, PC2);
		}
		
		return keys;
	}
	
	private long shiftKey(long key, int shift) {
		int left = ((int) (key >> HALF_KEY_BITS_PC1)) & HALF_KEY_MASK_PC1;
		int right = ((int) key) & HALF_KEY_MASK_PC1;
		
		left = circularLShift(left, HALF_KEY_BITS_PC1, shift);
		right = circularLShift(right, HALF_KEY_BITS_PC1, shift);
		
		long r = left;
		r <<= HALF_KEY_BITS_PC1;
		r |= right;
		
		return r;
	}
	
	private static int circularLShift(int value, int range, int shift) {
		if (range < 1 || range > 32) {
			throw new IllegalArgumentException("Invalid range");
		}
		
		shift %= range;
		
		if (shift == 0) {
			return value;
		}
		
		final int tmp = range - shift;
		
		value = (value << shift) | ((value >> tmp) & ((1 << shift) - 1));
		
		if (range < 32) {
			value &= (1 << range) - 1;
		}
		
		return value;
	}

	private long ip(long value) {
		return p(value, IP);
	}
	
	private long rip(long value) {
		return p(value, RIP);
	}
	
	private long p(long value, int[] bitOrder) {
		long v = 0;
		for (int i = 0; i != bitOrder.length; ++i) {
			v = setBit(v, i, getBit(value, bitOrder[i] - 1));
		}
		
		return v;
	}
	
	private static boolean getBit(long value, int index) {
		if (index < 0 || index > 63) {
			throw new IllegalArgumentException("Bit index out of range");
		}
		
		long v = value >> index;
		return (v & 1) != 0;
	}
	
	private static long setBit(long value, int index, boolean bit) {
		if (index < 0 || index > 63) {
			throw new IllegalArgumentException("Bit index out of range");
		}
		
		return bit ? value | (1 << index) : value & ~(1 << index);
	}
	
	private final long mKey;
	
	private static final int IP[] = {
		58, 50, 42, 34, 26, 18, 10, 2,
		60, 52, 44, 36, 28, 20, 12, 4,
		62, 54, 46, 38, 30, 22, 14, 6,
		64, 56, 48, 40, 32, 24, 16, 8,
		57, 49, 41, 33, 25, 17,  9, 1,
		59, 51, 43, 35, 27, 19, 11, 3,
		61, 53, 45, 37, 29, 21, 13, 5,
		63, 55, 47, 39, 31, 23, 15, 7
	};
	
	private static final int[] RIP = {
		40, 8, 48, 16, 56, 24, 64, 32,
		39, 7, 47, 15, 55, 23, 63, 31,
		38, 6, 46, 14, 54, 22, 62, 30,
		37, 5, 45, 13, 53, 21, 61, 29,
		36, 4, 44, 12, 52, 20, 60, 28,
		35, 3, 43, 11, 51, 19, 59, 27,
		34, 2, 42, 10, 50, 18, 58, 26,
		33, 1, 41,  9, 49, 17, 57, 25
	};
	
	private static final int[] TURN_SHIFT_TABLE = {
		1, 1, 2, 2,
		2, 2, 2, 2,
		1, 2, 2, 2,
		2, 2, 2, 1
	};
	
	// 57, 49, 41, 33, 25, 17,  9 -> 1
	//  1, 58, 50, 42, 34, 26, 18 -> 2
	// 10,  2, 59, 51, 43, 35, 27 -> 3 
	// 19, 11,  3, 60, 52, 44, 36 -> 4
	// 63, 55, 47, 39, 31, 23, 15 -> 7
	//  7, 62, 54, 46, 38, 30, 22 -> 6
	// 14,  6, 61, 53, 45, 37, 29 -> 5
	// 21, 13,  5, 28, 20, 12,  4 -> 4
	private static final int[] PC1 = {
		61, 53, 45, 37, 60, 52, 44, // 5 
		36, 28, 20, 12,  4, 59, 51, // 4
		43, 35, 27, 19, 11,  3, 58, // 3
		50, 42, 34, 26, 18, 10,  2, // 2 
		29, 21, 13,  5, 62, 54, 46, // 5
		38, 20, 22, 14,  6, 63, 55, // 6
		47, 39, 31, 23, 15,  7, 64, // 7 
		56, 48, 40, 32, 24, 16,  8  // 0
	};
	
	private static final int[] PC2 = {
		25, 28, 21,  7, 15, 11, 14, 23,
		 1, 18,  8, 13,  9, 24, 12,  6,
		17, 27,  2, 10, 20, 26,  5, 16,
		55, 44, 37, 30, 50, 41, 49, 31,
		53, 45, 38, 37, 47, 36, 51, 42,
		29, 54, 52, 56, 33, 45, 40, 43
	};
	
	private static final int HALF_KEY_BITS_PC1 = 28;
	private static final int HALF_KEY_MASK_PC1 = (1 << HALF_KEY_BITS_PC1) - 1;
	
	private static final int TURN_KEY_BITS = 48;
	private static final long TURN_KEY_MASK = (((long)1) << TURN_KEY_BITS) - 1;
	*/ 

}
