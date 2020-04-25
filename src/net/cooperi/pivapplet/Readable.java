/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2018, Alex Wilson <alex@cooperi.net>
 */

package net.cooperi.pivapplet;

public interface Readable {
	public boolean atEnd();
	public short available();
	public byte readByte();
	public short readShort();
	public short read(byte[] dest, short offset, short maxLen);
	public short read(TransientBuffer into, short maxLen);
	public short readPartial(TransientBuffer into, short maxLen);
	public void skip(short len);
	public void rewind();
}
