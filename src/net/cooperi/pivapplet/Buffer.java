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

public class Buffer {
//#if PIV_SUPPORT_RSA
	public static final short RAM_ALLOC_SIZE = 512;
	public static final short RAM_ALLOC_SIZE_2 = 256;
/*#else
	public static final short RAM_ALLOC_SIZE = 256;
	public static final short RAM_ALLOC_SIZE_2 = 128;
#endif*/
	public static final short EEPROM_ALLOC_SIZE = 1024;

/*#if APPLET_SIMULATOR
	public static final short RAM_ALLOC_MAX_INDEX = 2;
#else*/
	public static final short RAM_ALLOC_MAX_INDEX = 8;
//#endif

	public static final byte OFFSET = 0;
	public static final byte LEN = 1;

	public byte[] data;
	public boolean isDynamic;
	public boolean isTransient;
	public short[] state;
	public final short index;

	public
	Buffer(short idx)
	{
		index = idx;
		state = JCSystem.makeTransientShortArray((short)(LEN + 1),
		    JCSystem.CLEAR_ON_DESELECT);
		isDynamic = false;
		isTransient = false;
		state[OFFSET] = (short)0;
		state[LEN] = (short)0;
	}

	public
	Buffer()
	{
		this((short)0);
	}

	public short
	offset()
	{
		return (state[OFFSET]);
	}

	public short
	available()
	{
		return (state[LEN]);
	}

	public void
	allocTransient()
	{
		if (isDynamic && data != null) {
			state[OFFSET] = (short)0;
			state[LEN] = (short)data.length;
			return;
		} else if (data != null) {
			return;
		}

		isDynamic = true;

		if (index > RAM_ALLOC_MAX_INDEX) {
			isTransient = false;
			data = new byte[EEPROM_ALLOC_SIZE];
			state[OFFSET] = (short)0;
			state[LEN] = (short)EEPROM_ALLOC_SIZE;
			return;
		}

		try {
			data = JCSystem.makeTransientByteArray(RAM_ALLOC_SIZE,
			    JCSystem.CLEAR_ON_RESET);
			state[OFFSET] = (short)0;
			state[LEN] = (short)RAM_ALLOC_SIZE;
			isTransient = true;
			return;
		} catch (SystemException ex) {
			if (ex.getReason() != SystemException.NO_TRANSIENT_SPACE) {
				throw (ex);
			}
		}

		try {
			data = JCSystem.makeTransientByteArray(RAM_ALLOC_SIZE_2,
			    JCSystem.CLEAR_ON_RESET);
			state[OFFSET] = (short)0;
			state[LEN] = (short)RAM_ALLOC_SIZE_2;
			isTransient = true;
			return;
		} catch (SystemException ex) {
			if (ex.getReason() != SystemException.NO_TRANSIENT_SPACE) {
				throw (ex);
			}
		}

		isTransient = false;
		data = new byte[EEPROM_ALLOC_SIZE];
		state[OFFSET] = (short)0;
		state[LEN] = (short)EEPROM_ALLOC_SIZE;
	}
}
