/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2018, Alex Wilson <alex@cooperi.net>
 */

package net.cooperi.pivapplet;

public interface Buffer {
	public short offset();
	public short len();
	public byte[] data();

	public short rpos();
	public void read(short bytes);
	public short wpos();
	public void jumpWpos(short newpos);
	public void write(short bytes);
	public short remaining();
	public short available();
	public void reset();
	public void rewind();

	public void free();
}
