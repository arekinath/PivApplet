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
	private static final byte ST_BEGIN = 0;
	private static final byte ST_RPTR = 1;
	private static final byte ST_END = 2;

	private short[] s = null;

	public
	APDUStream()
	{
		s = JCSystem.makeTransientShortArray((short)3,
			JCSystem.CLEAR_ON_DESELECT);
	}

	public void
	reset(final short offset, final short len)
	{
		s[ST_RPTR] = offset;
		s[ST_BEGIN] = offset;
		s[ST_END] = (short)(len + offset);
	}

	public void
	rewind()
	{
		s[ST_RPTR] = s[ST_BEGIN];
	}

	public byte
	readByte()
	{
		final byte[] buf = APDU.getCurrentAPDUBuffer();
		if ((short)(s[ST_RPTR] + 1) > s[ST_END]) {
			ISOException.throwIt(ISO7816.SW_DATA_INVALID);
			return ((byte)0);
		}
		return (buf[s[ST_RPTR]++]);
	}

	public short
	readShort()
	{
		final byte[] buf = APDU.getCurrentAPDUBuffer();
		if ((short)(s[ST_RPTR] + 2) > s[ST_END]) {
			ISOException.throwIt(ISO7816.SW_DATA_INVALID);
			return ((short)0);
		}
		final short val = Util.getShort(buf, s[ST_RPTR]);
		s[ST_RPTR] += 2;
		return (val);
	}

	public boolean
	atEnd()
	{
		return (s[ST_RPTR] >= s[ST_END]);
	}

	public short
	available()
	{
		return ((short)(s[ST_END] - s[ST_RPTR]));
	}

	public short
	read(final byte[] dest, final short offset, final short maxLen)
	{
		final byte[] buf = APDU.getCurrentAPDUBuffer();
		final short rem = (short)(s[ST_END] - s[ST_RPTR]);
		final short take = (rem < maxLen) ? rem : maxLen;
		Util.arrayCopyNonAtomic(buf, s[ST_RPTR], dest, offset, take);
		s[ST_RPTR] += take;
		return (take);
	}

	public short
	read(final TransientBuffer into, final short maxLen)
	{
		final short rem = (short)(s[ST_END] - s[ST_RPTR]);
		final short take = (rem < maxLen) ? rem : maxLen;
		into.setApdu(s[ST_RPTR], take);
		s[ST_RPTR] += take;
		return (take);
	}

	public short
	readPartial(final TransientBuffer into, final short maxLen)
	{
		return (read(into, maxLen));
	}

	public void
	skip(final short len)
	{
		if ((short)(s[ST_RPTR] + len) > s[ST_END]) {
			ISOException.throwIt(ISO7816.SW_DATA_INVALID);
			return;
		}
		s[ST_RPTR] += len;
	}
}
