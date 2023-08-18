package ghidra.util.ascii;

import ghidra.program.model.mem.MemBuffer;

public interface VariableLengthCharSetMatcher {
	/**
	 * @return the number of bytes to advance to get to the next char,  or 0 if buf[baseIdx] 
	 *         isn't the beginning of a valid char in this encoding
	 */
	int matchCharacter(MemBuffer buf, int baseIdx);
}
