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
	public static final short RAM_ALLOC_SIZE = 512;
	public static final short RAM_ALLOC_SIZE_2 = 256;
	public static final short EEPROM_ALLOC_SIZE = 1024;

	public static final byte OFFSET = 0;
	public static final byte LEN = 1;

	public byte[] data;
	public boolean isTransient;
	public short[] state;

	public
	Buffer()
	{
		state = JCSystem.makeTransientShortArray((short)(LEN + 1),
		    JCSystem.CLEAR_ON_DESELECT);
		isTransient = false;
		state[OFFSET] = (short)0;
		state[LEN] = (short)0;
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
		if (isTransient && data != null) {
			state[OFFSET] = (short)0;
			state[LEN] = (short)data.length;
			return;
		} else if (data != null) {
			return;
		}

		isTransient = true;

		try {
			data = JCSystem.makeTransientByteArray(RAM_ALLOC_SIZE,
			    JCSystem.CLEAR_ON_RESET);
			state[OFFSET] = (short)0;
			state[LEN] = (short)RAM_ALLOC_SIZE;
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
			return;
		} catch (SystemException ex) {
			if (ex.getReason() != SystemException.NO_TRANSIENT_SPACE) {
				throw (ex);
			}
		}

		data = new byte[EEPROM_ALLOC_SIZE];
		state[OFFSET] = (short)0;
		state[LEN] = (short)EEPROM_ALLOC_SIZE;
	}
}
