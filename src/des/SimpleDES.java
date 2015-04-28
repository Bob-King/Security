package des;

public class SimpleDES {
	
	
	public SimpleDES(final int key) {
		mKey = key;
	}
	
	public byte[] encrypt(final byte[] plaintext) {
		if (plaintext == null) {
			return null;
		}

		final int[] turnKeys = { generateTurnKey(0), generateTurnKey(1) };
		
		byte[] ciphertext = new byte[plaintext.length];
		
		for (int i = 0; i != plaintext.length; ++i) {
			byte tmp = ip(plaintext[i]);
			
			byte ap4 = p4(s((byte) (ep(tmp) ^ turnKeys[0])));
			byte left = (byte) ((ap4 ^ (tmp >> 4)) & 0xf);
			tmp = (byte) ((left << 4) | (tmp & 0xf));
			
			tmp = sw(tmp);
			
			ap4 = p4(s((byte) (ep(tmp) ^ turnKeys[1])));
			left = (byte) ((ap4 ^ (tmp >> 4)) & 0xf);
			tmp = (byte) ((left << 4) | (tmp & 0xf));
			
			ciphertext[i] = rip(tmp);
		}
		
		return ciphertext;
	}
	
	
	public byte[] decrypt(byte[] ciphertext) {
		if (ciphertext == null) {
			return null;
		}

		final int[] turnKeys = { generateTurnKey(0), generateTurnKey(1) };
		
		byte[] plaintext = new byte[ciphertext.length];
		
		for (int i = 0; i != ciphertext.length; ++i) {
			byte tmp = ip(ciphertext[i]);
			
			byte ap4 = (byte) p4(s((byte) (ep(tmp) ^ turnKeys[1])));
			ap4 = (byte) ((ap4 ^ (tmp >> 4)) & 0xf);
			tmp = (byte) ((ap4 << 4) | (tmp & 0xf)); 
			
			tmp = sw(tmp);
			
			ap4 = (byte) p4(s((byte) (ep(tmp) ^ turnKeys[0])));
			ap4 = (byte) ((ap4 ^ (tmp >> 4)) & 0xf);
			tmp = (byte) ((ap4 << 4) | (tmp & 0xf));
			
			plaintext[i] = rip(tmp);
		}
		
		return plaintext;
	}
	
	
	private byte ip(byte message) {
		return (byte) p(byte2Integer(message), IP);
	}
	
	private byte rip(byte message) {
		return (byte) p(byte2Integer(message), RIP);
	}
	
	private byte ep(byte message) {
		return (byte) p(byte2Integer(message), EP);
	}
	
	private byte s(byte message) {
		int s0r = p(message, new int[] { 5, 8 });
		int s0w = p(message, new int[] { 6, 7 });
		int s1r = p(message, new int[] { 1, 4 });
		int s1w = p(message, new int[] { 2, 3 });
		
		return (byte) ((SBOX[0][s0r][s0w] << 2) | SBOX[1][s1r][s1w]);
	}
	
	private byte p4(byte message) {
		return (byte) p(byte2Integer(message), P4);
	}
	
	
	private byte sw(byte message) {
		return (byte) (((message >> 4) & 0xf) | (message << 4));
	}
	
	private int byte2Integer(byte b) {
		return b & 0xff;
	}
	
	private int p(int message, int[] bitOrder) {
		int r = 0;
		
		for (int i = 0; i != bitOrder.length; ++i) {
			r = setBit(r, i, getBit(message, bitOrder[i] - 1));
		}
		
		return r;
	}
	
	private int generateTurnKey(final int turn) {
		if (turn < 0 || turn > 1) {
			throw new IllegalArgumentException("Invalid turn");
		}
		
		final int tmp = p(mKey, TURNS[turn]);
		
		return p(tmp, P8);
	}
	
	private static boolean getBit(int value, int index) {
		if (index < 0 || index > 31) {
			throw new IllegalArgumentException("Invalid index");
		}
		int v = value >> index;
		return (v & 1) != 0;
	}
	
	private static int setBit(int value, int index, boolean bit) {
		if (index < 0 || index > 31) {
			throw new IllegalArgumentException("Invalid index");
		}
		
		return bit ? value | (1 << index) : value & ~(1 << index);
	}
	
	private final int mKey;
	
	private static final int[][][] SBOX = {
		{
			{ 1, 0, 3, 2 },
			{ 3, 2, 1, 0 },
			{ 0, 2, 1, 3 },
			{ 3, 1, 3, 2 }
		},
		
		{
			{ 0, 1, 2, 3 },
			{ 2, 0, 1, 3 },
			{ 3, 0, 1, 0 },
			{ 2, 1, 0, 3 }
		},
	};
	
	// Course
	// IP:	2 6 3 1 4 8 5 7
	// RIP:	4 1 3 5 7 2 8 6
	// EIP:	4 1 2 3 2 3 4 1

	private static final int[] IP = {
		2, 4, 1, 5, 8, 6, 3, 7
	};
	
	private static final int[] RIP = {
		3, 1, 7, 2, 4, 6, 8, 5
	};
	
	private static final int[] EP = {
		4, 1, 2, 3, 2, 3, 4, 1
	};	

	// Course
	// KEY:	1 2 3 4 5 6 7 8 9 10
	// P10:	3 5 2 7 4 10 1 9 8 6
	// P8:	6 3 7 4 8 5 10 9
	
	@SuppressWarnings("unused")
	private static final int[] P10 = {
		5, 3, 2, 10, 1, 7, 4, 9, 6, 8
	};
	
	private static final int[] P8 = {
		2, 1, 6, 3, 7, 4, 8, 5
	};
	
	private static final int[][] TURNS = {
		{ 1, 5, 3, 2, 10, 8, 7, 4, 9, 6 },
		{ 2, 10, 1, 5, 3, 9, 6, 8, 7, 7 },
	};
	
	// Course
	// P4:	2 4 3 1
	
	private static final int[] P4 = {
		4, 2, 1, 3
	};
}
