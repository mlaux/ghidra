package ghidra.util.ascii;

import ghidra.program.model.mem.MemBuffer;

/**
 * A recognizer for printable Shift-JIS as defined in JIS X 0208:1997. Matches whitespace,
 * printable 7-bit ASCII, half-width katakana, and two-byte characters.
 */
public class ShiftJISCharSetRecognizer implements VariableLengthCharSetMatcher {
	static final int NOT_PRINTABLE_SHIFT_JIS = 0;
	static final int ONE_BYTE = 1;
	static final int TWO_BYTES = 2;

	@Override
	public int matchCharacter(MemBuffer buf, int baseIdx) {
		byte[] bytes = new byte[2];
		int read = buf.getBytes(bytes, 2);
		if (read != 2) {
			return NOT_PRINTABLE_SHIFT_JIS;
		}

		// whitespace
		int first = bytes[0] & 0xff;
		if (first == '\r' || first == '\n' || first == '\t') {
			return ONE_BYTE;
		}

		// easy ascii
		if (first >= ' ' && first <= '~') {
			return ONE_BYTE;
		}

		// single-byte half-width katakana
		if (first >= 0xa1 && first <= 0xdf) {
			return ONE_BYTE;
		}

		// first byte of a two byte sequence
		if ((first >= 0x81 && first <= 0x9f) || (first >= 0xe0 && first <= 0xef)) {
			// check validity of second byte
			int second = (bytes[1] >> 8) & 0xff;
			if ((first & 1) == 1 && (second >= 0x40 && second <= 0x9e)
					|| (second >= 0x9f && second <= 0xfc)) {
				return TWO_BYTES;
			}
			
		}
		return NOT_PRINTABLE_SHIFT_JIS;
	}
}
