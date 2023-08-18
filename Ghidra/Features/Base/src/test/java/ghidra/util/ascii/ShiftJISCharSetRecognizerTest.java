package ghidra.util.ascii;

import static org.junit.Assert.assertEquals;

import java.io.UnsupportedEncodingException;

import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.TestAddress;
import ghidra.program.model.mem.ByteMemBufferImpl;
import ghidra.program.model.mem.MemBuffer;

public class ShiftJISCharSetRecognizerTest extends AbstractGenericTest {
	private ShiftJISCharSetRecognizer recognizer;

	@Test
	public void testWhitespace() {
		int ret = matchCharacter(' ');
		assertEquals(ShiftJISCharSetRecognizer.ONE_BYTE, ret);
	}
	
	@Test
	public void testAscii() {
		int ret = matchCharacter('0');
		assertEquals(ShiftJISCharSetRecognizer.ONE_BYTE, ret);

		ret = matchCharacter('A');
		assertEquals(ShiftJISCharSetRecognizer.ONE_BYTE, ret);

		ret = matchCharacter('a');
		assertEquals(ShiftJISCharSetRecognizer.ONE_BYTE, ret);
	}
	
	@Test
	public void testHalfWidthKatakana() {
		int ret = matchCharacter('ﾈ');
		assertEquals(ShiftJISCharSetRecognizer.ONE_BYTE, ret);
	}
	
	@Test
	public void testInvalidSingleByte() {
		int ret = matchBytes(new byte[] { (byte) 0xf1, 0 });
		assertEquals(ShiftJISCharSetRecognizer.NOT_PRINTABLE_SHIFT_JIS, ret);
	}
	
	@Test
	public void testDoubleByteHiragana() {
		int ret = matchCharacter('ね');
		assertEquals(ShiftJISCharSetRecognizer.TWO_BYTES, ret);
	}

	@Test
	public void testDoubleByteKanji() {
		int ret = matchCharacter('水');
		assertEquals(ShiftJISCharSetRecognizer.TWO_BYTES, ret);
	}
	
	@Test
	public void testInvalidDoubleByte() {
		// first byte valid, second byte invalid for all first bytes
		int ret = matchBytes(new byte[] { (byte) 0x81, 0x0d });
		assertEquals(ShiftJISCharSetRecognizer.NOT_PRINTABLE_SHIFT_JIS, ret);

		// first byte valid, second byte invalid for odd first bytes
		ret = matchBytes(new byte[] { (byte) 0x81, (byte) 0xa0 });
		assertEquals(ShiftJISCharSetRecognizer.NOT_PRINTABLE_SHIFT_JIS, ret);

		// first byte valid, second byte invalid for even first bytes
		ret = matchBytes(new byte[] { (byte) 0x82, 0x40 });
		assertEquals(ShiftJISCharSetRecognizer.NOT_PRINTABLE_SHIFT_JIS, ret);
	}
	
	private int matchCharacter(char ch) {
		byte[] testBytes;
		try {
			testBytes = new String(new char[] { ch }).getBytes("Shift_JIS");
		} catch (UnsupportedEncodingException e) {
			throw new RuntimeException(e);
		}
		return matchBytes(testBytes);
	}
	
	private int matchBytes(byte[] bytes) {
		Address addr = new TestAddress(0);
		MemBuffer memBuffer = new ByteMemBufferImpl(addr, bytes, false);
		recognizer = new ShiftJISCharSetRecognizer();
		return recognizer.matchCharacter(memBuffer, 0);
	}
}
