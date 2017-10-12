/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2017, Alex Wilson <alex@cooperi.net>
 */

package net.cooperi.pivapplet;

import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.framework.OwnerPIN;

import javacard.security.KeyPair;
import javacard.security.SecretKey;

public class PivSlot {
	public static final byte F_UNLOCKED = (byte)0;
	public static final byte F_PIN_USED = (byte)1;
	public static final byte MAX_FLAGS = (byte)(F_PIN_USED + 1);

	public static final byte P_DEFAULT = (byte)0x00;
	public static final byte P_NEVER = (byte)0x01;
	public static final byte P_ONCE = (byte)0x02;
	public static final byte P_ALWAYS = (byte)0x03;

	public byte[] cert = null;
	public short certLen = 0;
	public boolean certGzip = false;
	public boolean imported = false;

	public byte pinPolicy = P_NEVER;

	public KeyPair asym = null;
	public byte asymAlg = -1;
	public SecretKey sym = null;
	public byte symAlg = -1;

	public boolean[] flags = null;

	public
	PivSlot()
	{
		flags = JCSystem.makeTransientBooleanArray((short)MAX_FLAGS,
		    JCSystem.CLEAR_ON_DESELECT);
	}

	public boolean
	checkPin(OwnerPIN pin)
	{
		switch (pinPolicy) {
		case P_NEVER:
			return (true);
		case P_ONCE:
			return (pin.isValidated());
		case P_ALWAYS:
			if (!pin.isValidated())
				return (false);

			if (flags[F_PIN_USED]) {
				return (false);
			} else {
				flags[F_PIN_USED] = true;
				return (true);
			}
		default:
			return (false);
		}
	}
}
