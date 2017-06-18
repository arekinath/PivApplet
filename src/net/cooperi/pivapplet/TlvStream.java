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

public class TlvStream {
	private static final short STACK_SIZE = (short)8;

	private Object[] target = null;
	private short[] offPtrLenEnd = null;
	private short[] stack = null;

	public
	TlvStream()
	{
		target = JCSystem.makeTransientObjectArray((short)1,
		    JCSystem.CLEAR_ON_DESELECT);
		stack = JCSystem.makeTransientShortArray(STACK_SIZE,
		    JCSystem.CLEAR_ON_DESELECT);
		offPtrLenEnd = JCSystem.makeTransientShortArray((short)4,
		    JCSystem.CLEAR_ON_DESELECT);
	}

	public void
	setTarget(byte[] newTarget)
	{
		target[0] = (Object)newTarget;
		offPtrLenEnd[0] = (short)0;
		offPtrLenEnd[1] = (short)0;
		offPtrLenEnd[2] = (short)0;
		offPtrLenEnd[3] = (short)0;
	}

	public void
	setTarget(byte[] newTarget, short offset, short len)
	{
		target[0] = (Object)newTarget;
		offPtrLenEnd[0] = offset;
		offPtrLenEnd[1] = (short)0;
		offPtrLenEnd[2] = (short)0;
		offPtrLenEnd[3] = (short)(offset + len);
	}

	public boolean
	atEnd()
	{
		if (offPtrLenEnd[0] >= offPtrLenEnd[3])
			return (true);
		return (false);
	}

	public byte
	readTag()
	{
		final byte[] buf = target[0] == null ?
		    APDU.getCurrentAPDUBuffer() : (byte[])target[0];
		final byte tag = buf[offPtrLenEnd[0]++];
		final short firstLenOff = offPtrLenEnd[0]++;
		switch (buf[firstLenOff]) {
		case (byte)0x81:
			offPtrLenEnd[2] = (short)(
			    (short)buf[offPtrLenEnd[0]++] & (short)0x00FF);
			break;
		case (byte)0x82:
			offPtrLenEnd[2] = Util.getShort(buf, offPtrLenEnd[0]);
			offPtrLenEnd[0] += 2;
			break;
		default:
			if (buf[firstLenOff] > (byte)0x7f) {
				ISOException.throwIt(ISO7816.SW_DATA_INVALID);
				return (0);
			}
			offPtrLenEnd[2] = (short)buf[firstLenOff];
			break;
		}
		final short end = (short)(offPtrLenEnd[0] + offPtrLenEnd[2]);
		if (end > offPtrLenEnd[3]) {
			ISOException.throwIt(ISO7816.SW_DATA_INVALID);
			return (0);
		}
		return (tag);
	}

	public short
	tagLength()
	{
		return (offPtrLenEnd[2]);
	}

	public short
	offset()
	{
		return (offPtrLenEnd[0]);
	}

	public byte
	readByte()
	{
		final byte[] buf = target[0] == null ?
		    APDU.getCurrentAPDUBuffer() : (byte[])target[0];
		--offPtrLenEnd[2];
		return (buf[offPtrLenEnd[0]++]);
	}

	public short
	readShort()
	{
		final byte[] buf = target[0] == null ?
		    APDU.getCurrentAPDUBuffer() : (byte[])target[0];
		final short val = Util.getShort(buf, offPtrLenEnd[0]);
		offPtrLenEnd[0] += (short)2;
		offPtrLenEnd[2] -= (short)2;
		return (val);
	}

	public void
	skip()
	{
		offPtrLenEnd[0] += offPtrLenEnd[2];
		offPtrLenEnd[2] = (short)0;
	}

	public short
	read(byte[] dest, short offset, short maxLen)
	{
		final byte[] buf = target[0] == null ?
		    APDU.getCurrentAPDUBuffer() : (byte[])target[0];
		final short toCopy =
		    offPtrLenEnd[2] > maxLen ? maxLen : offPtrLenEnd[2];
		Util.arrayCopyNonAtomic(buf, offPtrLenEnd[0],
		    dest, offset, toCopy);
		offPtrLenEnd[2] -= toCopy;
		offPtrLenEnd[0] += toCopy;
		return (toCopy);
	}

	public void
	push(byte tag)
	{
		final byte[] buf = target[0] == null ?
		    APDU.getCurrentAPDUBuffer() : (byte[])target[0];
		buf[offPtrLenEnd[0]++] = tag;
		stack[offPtrLenEnd[1]++] = offPtrLenEnd[0];
		buf[offPtrLenEnd[0]++] = (short)0;
	}

	public void
	push(short tag)
	{
		final byte[] buf = target[0] == null ?
		    APDU.getCurrentAPDUBuffer() : (byte[])target[0];
		offPtrLenEnd[0] = Util.setShort(buf, offPtrLenEnd[0], tag);
		stack[offPtrLenEnd[1]++] = offPtrLenEnd[0];
		buf[offPtrLenEnd[0]++] = (short)0;
	}

	public void
	push(byte tag, short expLen)
	{
		if (expLen > (short)250) {
			push64k(tag);
		} else if (expLen > (short)124) {
			push256(tag);
		} else {
			push(tag);
		}
	}

	public void
	push256(byte tag)
	{
		final byte[] buf = target[0] == null ?
		    APDU.getCurrentAPDUBuffer() : (byte[])target[0];
		buf[offPtrLenEnd[0]++] = tag;
		stack[offPtrLenEnd[1]++] = offPtrLenEnd[0];
		buf[offPtrLenEnd[0]++] = (byte)0x81;
		buf[offPtrLenEnd[0]++] = (byte)0;
	}

	public void
	push256(short tag)
	{
		final byte[] buf = target[0] == null ?
		    APDU.getCurrentAPDUBuffer() : (byte[])target[0];
		offPtrLenEnd[0] = Util.setShort(buf, offPtrLenEnd[0], tag);
		stack[offPtrLenEnd[1]++] = offPtrLenEnd[0];
		buf[offPtrLenEnd[0]++] = (byte)0x81;
		buf[offPtrLenEnd[0]++] = (byte)0;
	}

	public void
	push64k(byte tag)
	{
		final byte[] buf = target[0] == null ?
		    APDU.getCurrentAPDUBuffer() : (byte[])target[0];
		buf[offPtrLenEnd[0]++] = tag;
		stack[offPtrLenEnd[1]++] = offPtrLenEnd[0];
		buf[offPtrLenEnd[0]++] = (byte)0x82;
		buf[offPtrLenEnd[0]++] = (byte)0;
		buf[offPtrLenEnd[0]++] = (byte)0;
	}

	public void
	push64k(short tag)
	{
		final byte[] buf = target[0] == null ?
		    APDU.getCurrentAPDUBuffer() : (byte[])target[0];
		offPtrLenEnd[0] = Util.setShort(buf, offPtrLenEnd[0], tag);
		stack[offPtrLenEnd[1]++] = offPtrLenEnd[0];
		buf[offPtrLenEnd[0]++] = (byte)0x82;
		buf[offPtrLenEnd[0]++] = (byte)0;
		buf[offPtrLenEnd[0]++] = (byte)0;
	}

	public short
	write(short len)
	{
		final short off = offPtrLenEnd[0];
		offPtrLenEnd[0] += len;
		return (off);
	}

	public short
	write(byte[] data, short off, short len)
	{
		final byte[] buf = target[0] == null ?
		    APDU.getCurrentAPDUBuffer() : (byte[])target[0];
		offPtrLenEnd[0] = Util.arrayCopy(
		    data, off, buf, offPtrLenEnd[0], len);
		return (offPtrLenEnd[0]);
	}

	public short
	writeByte(byte data)
	{
		final byte[] buf = target[0] == null ?
		    APDU.getCurrentAPDUBuffer() : (byte[])target[0];
		buf[offPtrLenEnd[0]++] = data;
		return (offPtrLenEnd[0]);
	}

	public short
	writeShort(short data)
	{
		final byte[] buf = target[0] == null ?
		    APDU.getCurrentAPDUBuffer() : (byte[])target[0];
		offPtrLenEnd[0] = Util.setShort(buf, offPtrLenEnd[0], data);
		return (offPtrLenEnd[0]);
	}

	public short
	pop()
	{
		final byte[] buf = target[0] == null ?
		    APDU.getCurrentAPDUBuffer() : (byte[])target[0];
		final short off = stack[--offPtrLenEnd[1]];
		final short len;
		switch (buf[off]) {
		case (byte)0x00:
			len = (short)(offPtrLenEnd[0] - off - 1);
			buf[off] = (byte)len;
			break;
		case (byte)0x81:
			len = (short)(offPtrLenEnd[0] - off - 2);
			buf[(short)(off + 1)] = (byte)len;
			break;
		case (byte)0x82:
			len = (short)(offPtrLenEnd[0] - off - 3);
			Util.setShort(buf, (short)(off + 1), len);
			break;
		}
		return (offPtrLenEnd[0]);
	}
}
