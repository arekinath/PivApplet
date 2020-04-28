/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2017, Alex Wilson <alex@cooperi.net>
 */

package net.cooperi.pivapplet;

import javacard.framework.JCSystem;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;

public class TlvReader {
/*#if APPLET_LOW_TRANSIENT
	private static final short STACK_SIZE = (short)5;
#else*/
	private static final short STACK_SIZE = (short)8;
//#endif

	private static final byte OFFSET = 0;
	private static final byte PTR = 1;
	private static final byte LEN = 2;
	private static final byte END = 3;

	private Object[] target = null;
	private short[] s = null;
	private short[] stack = null;

	public
	TlvReader()
	{
		target = JCSystem.makeTransientObjectArray((short)1,
		    JCSystem.CLEAR_ON_DESELECT);
		stack = JCSystem.makeTransientShortArray(STACK_SIZE,
		    JCSystem.CLEAR_ON_DESELECT);
		s = JCSystem.makeTransientShortArray((short)(END + 1),
		    JCSystem.CLEAR_ON_DESELECT);
	}

	public void
	start(Readable newTarget)
	{
		target[0] = (Object)newTarget;
		s[OFFSET] = (short)0;
		s[PTR] = (short)0;
		s[LEN] = newTarget.available();
		s[END] = s[LEN];
	}

	public void
	rewind()
	{
		final Readable src = (Readable)target[0];
		src.rewind();
		s[OFFSET] = (short)0;
		s[PTR] = (short)0;
		s[LEN] = src.available();
		s[END] = s[LEN];
	}

	public boolean
	atEnd()
	{
		if (s[OFFSET] >= s[END])
			return (true);
		return (false);
	}

	public byte
	readTag()
	{
		stack[s[PTR]++] = s[END];

		final Readable src = (Readable)target[0];
		final byte tag = src.readByte();
		s[OFFSET]++;
		final byte firstLen = src.readByte();
		final short firstLenOff = s[OFFSET]++;
		switch (firstLen) {
		case (byte)0x81:
			s[OFFSET] += 1;
			s[LEN] = (short)(
			    (short)src.readByte() & (short)0x00FF);
			break;
		case (byte)0x82:
			s[OFFSET] += 2;
			s[LEN] = src.readShort();
			break;
		default:
			if (firstLen > (byte)0x7f) {
				ISOException.throwIt(ISO7816.SW_DATA_INVALID);
				return (0);
			}
			s[LEN] = (short)firstLen;
			break;
		}
		final short end = (short)(s[OFFSET] + s[LEN]);
		if (end > s[END]) {
			ISOException.throwIt(ISO7816.SW_DATA_INVALID);
			return (0);
		}
		return (tag);
	}

	public void
	end()
	{
		if (s[LEN] > 0) {
			ISOException.throwIt(PivApplet.SW_TAG_END_ASSERT);
			return;
		}
		final short oldEnd = stack[--s[PTR]];
		s[END] = oldEnd;
		s[LEN] = (short)(oldEnd - s[OFFSET]);
	}

	public void
	abort()
	{
		final short oldEnd = stack[0];
		s[END] = oldEnd;
		s[LEN] = (short)(oldEnd - s[OFFSET]);
		s[PTR] = 1;
		skip();
	}

	public void
	finish()
	{
		if (s[LEN] > 0) {
			ISOException.throwIt(PivApplet.SW_TAG_END_ASSERT);
			return;
		}
		if (s[PTR] != 0) {
			ISOException.throwIt(PivApplet.SW_DATA_END_ASSERT);
			return;
		}
	}

	public short
	tagLength()
	{
		return (s[LEN]);
	}

	public byte
	readByte()
	{
		final Readable src = (Readable)target[0];
		s[OFFSET]++;
		s[LEN]--;
		if (s[LEN] < 0) {
			ISOException.throwIt(ISO7816.SW_DATA_INVALID);
			return ((byte)0);
		}
		return (src.readByte());
	}

	public short
	readShort()
	{
		final Readable src = (Readable)target[0];
		s[OFFSET] += 2;
		s[LEN] -= 2;
		if (s[LEN] < 0) {
			ISOException.throwIt(ISO7816.SW_DATA_INVALID);
			return ((byte)0);
		}
		return (src.readShort());
	}

	public void
	skip()
	{
		final Readable src = (Readable)target[0];
		src.skip(s[LEN]);
		s[OFFSET] += s[LEN];
		s[LEN] = (short)0;
		end();
	}

	public short
	read(byte[] dest, short offset, short maxLen)
	{
		final Readable src = (Readable)target[0];
		final short toCopy = (s[LEN] > maxLen) ? maxLen : s[LEN];
		final short done = src.read(dest, offset, toCopy);
		s[LEN] -= done;
		s[OFFSET] += done;
		return (done);
	}

	public short
	read(TransientBuffer into, short maxLen)
	{
		final Readable src = (Readable)target[0];
		final short toCopy = (s[LEN] > maxLen) ? maxLen : s[LEN];
		final short done = src.read(into, toCopy);
		s[LEN] -= done;
		s[OFFSET] += done;
		return (done);
	}

	public short
	readPartial(TransientBuffer into, short maxLen)
	{
		final Readable src = (Readable)target[0];
		final short toCopy = (s[LEN] > maxLen) ? maxLen : s[LEN];
		final short done = src.readPartial(into, toCopy);
		s[LEN] -= done;
		s[OFFSET] += done;
		return (done);
	}
}
