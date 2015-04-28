package des;

import static org.junit.Assert.*;

import org.junit.Test;

public class DesTest {
	
	@Test
	public void testCase1() {
		byte[] plaintext = new byte[] { 0x3 };
		
		testDes(plaintext);
	}
	
	@Test
	public void testCase2() {
		byte[] plaintext = new byte[0x100];
		for (int i = 0; i != plaintext.length; ++i) {
			plaintext[i] = (byte) i;
		}
		
		testDes(plaintext);
	}
	
	private void testDes(byte[] plaintext) {
		
		SimpleDES sd = new SimpleDES(0x282);
		
		// byte[] plaintext = new byte[] { (byte) 0xf3 };
		
		byte[] ciphertext = sd.encrypt(plaintext);

				
		byte[] table = new byte[0x100];

		for (int i = 0; i != plaintext.length; ++i) {
			assertEquals(Integer.toHexString(plaintext[i] & 0xff) + " -> " + Integer.toHexString(ciphertext[i] & 0xff)
					, table[ciphertext[i] & 0xff], 0);
			table[ciphertext[i] & 0xff] = 1;
		}
		
		byte[] plaintext1 = sd.decrypt(ciphertext);
		
		for (int i = 0; i != plaintext.length; ++i) {
			System.out.println(Integer.toHexString(plaintext[i] & 0xff)
					+ " -> "
					+ Integer.toHexString(ciphertext[i] & 0xff)
					+ " -> "
					+ Integer.toHexString(plaintext1[i] & 0xff));
		}
		
		assertEquals("Opps", plaintext.length, plaintext1.length);
		
		for (int i = 0; i != plaintext.length; ++i) {
			assertEquals(Integer.toHexString(plaintext[i] & 0xff) + " <>" + Integer.toHexString(plaintext1[i] & 0xff)
					, plaintext[i], plaintext1[i]);
		}
	}

}
