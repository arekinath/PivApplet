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
	public static final byte F_AFTER_VERIFY = (byte)1;
	public static final byte MAX_FLAGS = (byte)(F_AFTER_VERIFY + 1);

	public static final byte P_DEFAULT = (byte)0x00;
	public static final byte P_NEVER = (byte)0x01;
	public static final byte P_ONCE = (byte)0x02;
	public static final byte P_ALWAYS = (byte)0x03;

	public boolean imported = false;
	public File cert = null;

	public byte pinPolicy = P_ONCE;

	public KeyPair asym = null;
	public byte asymAlg = -1;
	public SecretKey sym = null;
	public byte symAlg = -1;
	public byte id = (byte)0;

	public boolean[] flags = null;

	public
	PivSlot(byte id)
	{
		flags = JCSystem.makeTransientBooleanArray((short)MAX_FLAGS,
		    JCSystem.CLEAR_ON_DESELECT);
		this.id = id;
	}
}
