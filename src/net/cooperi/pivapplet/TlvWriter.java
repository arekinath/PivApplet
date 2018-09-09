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

public class TlvWriter {
	private static final short STACK_SIZE = (short)8;

	private static final byte PTR = 0;

	private Object[] target = null;
	private short[] s = null;
	private short[] stackBuf = null;
	private short[] stackOff = null;
	private short[] stackWPtr = null;

	private SGList scratch = null;

	public
	TlvWriter(SGList scratch)
	{
		target = JCSystem.makeTransientObjectArray((short)1,
		    JCSystem.CLEAR_ON_DESELECT);
		stackBuf = JCSystem.makeTransientShortArray(STACK_SIZE,
		    JCSystem.CLEAR_ON_DESELECT);
		stackOff = JCSystem.makeTransientShortArray(STACK_SIZE,
		    JCSystem.CLEAR_ON_DESELECT);
		stackWPtr = JCSystem.makeTransientShortArray(STACK_SIZE,
		    JCSystem.CLEAR_ON_DESELECT);
		s = JCSystem.makeTransientShortArray((short)(PTR + 1),
		    JCSystem.CLEAR_ON_DESELECT);
		this.scratch = scratch;
	}

	public void
	start(SGList newTarget)
	{
		target[0] = (Object)newTarget;
		s[PTR] = (short)0;
		scratch.reset();
	}

	private void
	saveStackFrame()
	{
		stackBuf[s[PTR]] = scratch.wPtrBuf();
		stackOff[s[PTR]] = scratch.wPtrOff();
		final SGList dest = (SGList)target[0];
		stackWPtr[s[PTR]] = (short)(dest.wPtr() + scratch.available());
		s[PTR]++;
	}

	public void
	startReserve(short len, Buffer into)
	{
		scratch.startReserve(len, into);
	}

	public void
	endReserve(short used)
	{
		scratch.endReserve(used);
	}

	public void
	push(byte tag)
	{
		scratch.writeByte(tag);
		saveStackFrame();
		scratch.writeByte((byte)0);
	}

	public void
	push(short tag)
	{
		scratch.writeShort(tag);
		saveStackFrame();
		scratch.writeByte((byte)0);
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
		scratch.writeByte(tag);
		saveStackFrame();
		scratch.writeByte((byte)0x81);
		scratch.writeByte((byte)0);
	}

	public void
	push256(short tag)
	{
		scratch.writeShort(tag);
		saveStackFrame();
		scratch.writeByte((byte)0x81);
		scratch.writeByte((byte)0);
	}

	public void
	push64k(byte tag)
	{
		scratch.writeByte(tag);
		saveStackFrame();
		scratch.writeByte((byte)0x82);
		scratch.writeByte((byte)0);
		scratch.writeByte((byte)0);
	}

	public void
	push64k(short tag)
	{
		scratch.writeShort(tag);
		saveStackFrame();
		scratch.writeByte((byte)0x82);
		scratch.writeByte((byte)0);
		scratch.writeByte((byte)0);
	}

	public void
	write(byte[] data, short off, short len)
	{
		if (len <= 16) {
			scratch.write(data, off, len);
			return;
		}
		final SGList dest = (SGList)target[0];
		scratch.readInto(dest, scratch.available());
		dest.append(data, off, len);
	}

	public void
	writeByte(byte data)
	{
		scratch.writeByte(data);
	}

	public void
	writeShort(short data)
	{
		scratch.writeShort(data);
	}

	public void
	pop()
	{
		final SGList dest = (SGList)target[0];

		s[PTR]--;
		final short curOff = (short)(dest.wPtr() + scratch.available());
		final short off = stackWPtr[s[PTR]];

		scratch.rewriteAt(stackBuf[s[PTR]], stackOff[s[PTR]]);

		final short len;
		switch (scratch.peekByteW()) {
		case (byte)0x00:
			len = (short)(curOff - (short)(off + 1));
			scratch.writeByte((byte)len);
			break;
		case (byte)0x81:
			len = (short)(curOff - (short)(off + 2));
			scratch.writeByte((byte)0x81);
			scratch.writeByte((byte)len);
			break;
		case (byte)0x82:
			len = (short)(curOff - (short)(off + 3));
			scratch.writeByte((byte)0x82);
			scratch.writeShort(len);
			break;
		}

		scratch.endRewrite();
	}

	public void
	end()
	{
		final SGList dest = (SGList)target[0];
		scratch.readInto(dest, scratch.available());
	}
}
