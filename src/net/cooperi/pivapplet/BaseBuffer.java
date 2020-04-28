/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2018, Alex Wilson <alex@cooperi.net>
 */

package net.cooperi.pivapplet;

import javacard.framework.JCSystem;
import javacard.framework.SystemException;

public class BaseBuffer implements Buffer {
//#if PIV_SUPPORT_RSA
	public static final short RAM_ALLOC_SIZE = 512;
	public static final short RAM_ALLOC_SIZE_2 = 256;
/*#else
	public static final short RAM_ALLOC_SIZE = 256;
	public static final short RAM_ALLOC_SIZE_2 = 128;
#endif*/

/*#if APPLET_LOW_TRANSIENT
	public static final short RAM_ALLOC_MAX_INDEX = 2;
	public static final short EEPROM_ALLOC_SIZE = 2048;
#else*/
	public static final short RAM_ALLOC_MAX_INDEX = 7;
	public static final short EEPROM_ALLOC_SIZE = 1024;
//#endif

	private static final short ST_RPOS = 0;
	private static final short ST_WPOS = 1;
	private static final short ST_AMASK = 2;

	private byte[] data;
	public boolean isTransient;
	public final short index;
	private short[] state;
	public final BufferManager manager;
	public short offsetStep;

	public
	BaseBuffer(BufferManager mgr, short idx)
	{
		index = idx;
		manager = mgr;
		data = null;
		offsetStep = 0;
		state = JCSystem.makeTransientShortArray((short)(ST_AMASK + 1),
		    JCSystem.CLEAR_ON_DESELECT);
		isTransient = false;
	}

	public boolean
	maskAvailable(final short mask)
	{
		return ((short)(mask & state[ST_AMASK]) == 0);
	}

	public short
	maskAnd(final short mask)
	{
		return ((short)(mask & state[ST_AMASK]));
	}

	public boolean
	maskFull()
	{
		return (state[ST_AMASK] == (short)0xffff);
	}

	public void
	setMask(final short mask)
	{
		state[ST_AMASK] |= mask;
	}

	public void
	clearMask(final short mask)
	{
		final short invMask = (short)~mask;
		state[ST_AMASK] &= invMask;
	}

	public boolean
	setMaskIfAvailable(final short mask)
	{
		if ((short)(mask & state[ST_AMASK]) == 0) {
			state[ST_AMASK] |= mask;
			return (true);
		}
		return (false);
	}

	public short
	rpos()
	{
		return (state[ST_RPOS]);
	}

	public void
	read(short bytes)
	{
		state[ST_RPOS] += bytes;
	}

	public short
	wpos()
	{
		return (state[ST_WPOS]);
	}

	public void
	write(short bytes)
	{
		state[ST_WPOS] += bytes;
	}

	public void
	jumpWpos(short newpos)
	{
		state[ST_WPOS] = newpos;
	}

	public void
	reset()
	{
		state[ST_RPOS] = 0;
		state[ST_WPOS] = 0;
	}

	public void
	rewind()
	{
		state[ST_RPOS] = 0;
	}

	public short
	remaining()
	{
		return ((short)(state[ST_WPOS] - state[ST_RPOS]));
	}

	public short
	available()
	{
		return ((short)((short)data.length - state[ST_WPOS]));
	}

	public short
	offset()
	{
		return (0);
	}

	public short
	len()
	{
		return ((short)data.length);
	}

	public byte[]
	data()
	{
		return (data);
	}

	public void
	free()
	{
		data = null;
		isTransient = false;
		offsetStep = 0;
	}

	public void
	alloc()
	{
		if (data != null)
			return;

		if (index > RAM_ALLOC_MAX_INDEX) {
			isTransient = false;
			data = new byte[EEPROM_ALLOC_SIZE];
			offsetStep = (short)((short)data.length >> 4);
			return;
		}

		try {
			data = JCSystem.makeTransientByteArray(RAM_ALLOC_SIZE,
			    JCSystem.CLEAR_ON_DESELECT);
			isTransient = true;
			offsetStep = (short)((short)data.length >> 4);
			return;
		} catch (SystemException ex) {
			if (ex.getReason() != SystemException.NO_TRANSIENT_SPACE) {
				throw (ex);
			}
		}

		try {
			data = JCSystem.makeTransientByteArray(RAM_ALLOC_SIZE_2,
			    JCSystem.CLEAR_ON_DESELECT);
			isTransient = true;
			offsetStep = (short)((short)data.length >> 4);
			return;
		} catch (SystemException ex) {
			if (ex.getReason() != SystemException.NO_TRANSIENT_SPACE) {
				throw (ex);
			}
		}

		isTransient = false;
		data = new byte[EEPROM_ALLOC_SIZE];
		offsetStep = (short)((short)data.length >> 4);
	}
}
