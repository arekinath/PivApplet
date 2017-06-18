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
	public static final byte MAX_FLAGS = (byte)(F_UNLOCKED + 1);

	public byte[] cert = null;
	public short certLen = 0;
	public boolean certGzip = false;

	public boolean needsPin = false;
	public OwnerPIN pin = null;

	public KeyPair asym = null;
	public byte asymAlg = -1;
	public SecretKey sym = null;
	public byte symAlg = -1;

	public boolean[] flags = null;

	public PivSlot() {
		flags = JCSystem.makeTransientBooleanArray((short)MAX_FLAGS,
		    JCSystem.CLEAR_ON_DESELECT);
	}
}
