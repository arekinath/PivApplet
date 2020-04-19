/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2017, Alex Wilson <alex@cooperi.net>
 */

package net.cooperi.pivapplet;

import javacard.framework.APDU;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;

public class APDUStream implements Readable {
	private static final byte OFFSET = 0;
	private static final byte LEN = 1;

	private short[] s = null;

	public
	APDUStream()
	{
		s = JCSystem.makeTransientShortArray((short)2,
			JCSystem.CLEAR_ON_DESELECT);
	}

	public void
	reset(short offset, short len)
	{
		s[OFFSET] = offset;
		s[LEN] = (short)(len + offset);
	}

	public void
	rewind()
	{
		s[OFFSET] = (short)0;
	}

	public byte
	readByte()
	{
		final byte[] buf = APDU.getCurrentAPDUBuffer();
		if ((short)(s[OFFSET] + 1) > s[LEN]) {
			ISOException.throwIt(ISO7816.SW_DATA_INVALID);
			return ((byte)0);
		}
		return (buf[s[OFFSET]++]);
	}

	public short
	readShort()
	{
		final byte[] buf = APDU.getCurrentAPDUBuffer();
		if ((short)(s[OFFSET] + 2) > s[LEN]) {
			ISOException.throwIt(ISO7816.SW_DATA_INVALID);
			return ((short)0);
		}
		final short val = Util.getShort(buf, s[OFFSET]);
		s[OFFSET] += 2;
		return (val);
	}

	public boolean
	atEnd()
	{
		return (s[OFFSET] >= s[LEN]);
	}

	public short
	available()
	{
		return ((short)(s[LEN] - s[OFFSET]));
	}

	public short
	read(byte[] dest, short offset, short maxLen)
	{
		final byte[] buf = APDU.getCurrentAPDUBuffer();
		final short rem = (short)(s[LEN] - s[OFFSET]);
		final short take = (rem < maxLen) ? rem : maxLen;
		Util.arrayCopyNonAtomic(buf, s[OFFSET], dest, offset, take);
		s[OFFSET] += take;
		return (take);
	}

	public short
	read(Buffer into, short maxLen)
	{
		return (0);
	}

	public short
	readPartial(Buffer into, short maxLen)
	{
		return (0);
	}

	public void
	skip(short len)
	{
		if ((short)(s[OFFSET] + len) > s[LEN]) {
			ISOException.throwIt(ISO7816.SW_DATA_INVALID);
			return;
		}
		s[OFFSET] += len;
	}
}
