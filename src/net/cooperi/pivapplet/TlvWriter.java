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

public class TlvWriter {
/*#if APPLET_LOW_TRANSIENT
	private static final short STACK_SIZE = (short)5;
#else*/
	private static final short STACK_SIZE = (short)8;
//#endif

	private static final byte PTR = 0;

	private Object[] target = null;
	private short[] s = null;
	private short[] stackBuf = null;
	private short[] stackOff = null;
	private short[] stackWPtr = null;
	private byte[] tmp = null;

	private SGList scratch = null;

	public
	TlvWriter(BufferManager bufmgr)
	{
		target = JCSystem.makeTransientObjectArray((short)1,
		    JCSystem.CLEAR_ON_DESELECT);
		stackBuf = JCSystem.makeTransientShortArray(STACK_SIZE,
		    JCSystem.CLEAR_ON_DESELECT);
		stackOff = JCSystem.makeTransientShortArray(STACK_SIZE,
		    JCSystem.CLEAR_ON_DESELECT);
		stackWPtr = JCSystem.makeTransientShortArray(STACK_SIZE,
		    JCSystem.CLEAR_ON_DESELECT);
		tmp = JCSystem.makeTransientByteArray((short)5,
		    JCSystem.CLEAR_ON_DESELECT);
		s = JCSystem.makeTransientShortArray((short)(PTR + 1),
		    JCSystem.CLEAR_ON_DESELECT);
		this.scratch = new SGList(bufmgr, (short)4);
	}

	public void
	start(SGList newTarget)
	{
		target[0] = (Object)newTarget;
		s[PTR] = (short)0;
		scratch.reset();
	}

	/*
	 * Set our scratch SGList to use the APDU buffer space first -- so
	 * if everything we write fits into the APDU buffer, we don't have to
	 * double-copy it.
	 */
	public void
	useApdu(final short offset, final short len)
	{
		scratch.useApdu(offset, len);
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
	startReserve(short len, TransientBuffer into)
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
	push(short tag, short expLen)
	{
		if (expLen > (short)250) {
			push64k(tag);
		} else if (expLen > (short)124) {
			push256(tag);
		} else {
			push(tag);
		}
	}

	public static short
	sizeWithByteTag(final short len)
	{
		if (len > (short)250) {
			return ((short)(len + 4));
		} else if (len > (short)124) {
			return ((short)(len + 3));
		} else {
			return ((short)(len + 2));
		}
	}

	public static short
	sizeWithShortTag(final short len)
	{
		if (len > (short)250) {
			return ((short)(len + 5));
		} else if (len > (short)124) {
			return ((short)(len + 4));
		} else {
			return ((short)(len + 3));
		}
	}

	/*
	 * Optimised tag writing for when we have a known length in advance
	 * for the tag.
	 */
	public void
	writeTagRealLen(final byte tag, final short len)
	{
		tmp[0] = tag;
		if (len > (short)250) {
			tmp[1] = (byte)0x82;
			Util.setShort(tmp, (short)2, len);
			scratch.write(tmp, (short)0, (short)4);
		} else if (len > (short)124) {
			tmp[1] = (byte)0x81;
			tmp[2] = (byte)len;
			scratch.write(tmp, (short)0, (short)3);
		} else {
			tmp[1] = (byte)len;
			scratch.write(tmp, (short)0, (short)2);
		}
	}

	public void
	writeTagRealLen(short tag, short len)
	{
		Util.setShort(tmp, (short)0, tag);
		if (len > (short)250) {
			tmp[2] = (byte)0x82;
			Util.setShort(tmp, (short)3, len);
			scratch.write(tmp, (short)0, (short)5);
		} else if (len > (short)124) {
			tmp[2] = (byte)0x81;
			tmp[3] = (byte)len;
			scratch.write(tmp, (short)0, (short)4);
		} else {
			tmp[2] = (byte)len;
			scratch.write(tmp, (short)0, (short)3);
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
		/* For short strings, just write directly into scratch. */
		if (len <= 32) {
			scratch.write(data, off, len);
			return;
		}
		final SGList dest = (SGList)target[0];
		scratch.readInto(dest, scratch.available());
		dest.append(data, off, len);
	}

	public void
	write(Buffer buf)
	{
		write(buf.data(), buf.rpos(), buf.remaining());
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
