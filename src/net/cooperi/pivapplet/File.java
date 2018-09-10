/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2018, Alex Wilson <alex@cooperi.net>
 */

package net.cooperi.pivapplet;

public class File {
	public static final byte P_ALWAYS = (byte)0;
	public static final byte P_PIN = (byte)1;
	public static final byte P_NEVER = (byte)2;

	public byte[] data;
	public short len;

	public byte contact = P_ALWAYS;
	public byte contactless = P_ALWAYS;
}
