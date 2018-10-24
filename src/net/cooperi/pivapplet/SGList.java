/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2018, Alex Wilson <alex@cooperi.net>
 */

package net.cooperi.pivapplet;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.APDU;
import javacard.framework.Util;

public class SGList implements Readable {
	public static final byte MAX_BUFS = 16;

	public static final byte WPTR_BUF = 0;
	public static final byte WPTR_OFF = 1;
	public static final byte WPTR_TOTOFF = 2;
	public static final byte RPTR_BUF = 3;
	public static final byte RPTR_OFF = 4;
	public static final byte RPTR_TOTOFF = 5;
	public static final byte OWPTR_BUF = 6;
	public static final byte OWPTR_OFF = 7;
	public static final byte STATE_MAX = OWPTR_OFF;

	public Buffer[] buffers;
	public short[] state;
	public boolean gcBlewUp = false;

	public
	SGList()
	{
		buffers = new Buffer[MAX_BUFS];
		for (short i = 0; i < MAX_BUFS; ++i)
			buffers[i] = new Buffer();
		state = JCSystem.makeTransientShortArray((short)(STATE_MAX + 1),
		    JCSystem.CLEAR_ON_DESELECT);
		this.reset();
	}

	public void
	reset()
	{
		state[WPTR_BUF] = (short)0;
		state[WPTR_OFF] = (short)0;
		state[RPTR_BUF] = (short)0;
		state[RPTR_OFF] = (short)0;
		state[RPTR_TOTOFF] = (short)0;
		state[WPTR_TOTOFF] = (short)0;
		state[OWPTR_BUF] = (short)0;
		state[OWPTR_BUF] = (short)0;

		for (short i = 0; i < MAX_BUFS; ++i) {
			final Buffer buf = buffers[i];
			if (buf.isDynamic && buf.data != null) {
				buf.state[Buffer.OFFSET] = (short)0;
				buf.state[Buffer.LEN] = (short)buf.data.length;
			}
		}
	}

	public void
	cullNonTransient()
	{
		if (!JCSystem.isObjectDeletionSupported() || gcBlewUp)
			return;
		boolean dogc = false;
		for (short i = 0; i < MAX_BUFS; ++i) {
			final Buffer buf = buffers[i];
			if (buf.isDynamic && !buf.isTransient &&
			    buf.data != null) {
				buf.data = null;
				buf.isDynamic = false;
				buf.isTransient = false;
				buf.state[Buffer.LEN] = (short)0;
				dogc = true;
			}
		}
		if (dogc) {
			try {
				JCSystem.requestObjectDeletion();
			} catch (Exception e) {
				gcBlewUp = true;
			}
		}
	}

	public void
	rewind()
	{
		state[RPTR_BUF] = (short)0;
		state[RPTR_OFF] = (short)0;
		state[RPTR_TOTOFF] = (short)0;
	}

	public short
	wPtrBuf()
	{
		return (state[WPTR_BUF]);
	}

	public short
	wPtrOff()
	{
		return (state[WPTR_OFF]);
	}

	public short
	wPtr()
	{
		return (state[WPTR_TOTOFF]);
	}

	public void
	rewriteAt(short buf, short off)
	{
		if (state[OWPTR_BUF] != 0 || state[OWPTR_OFF] != 0) {
			ISOException.throwIt(PivApplet.SW_BAD_REWRITE);
			return;
		}
		state[OWPTR_BUF] = state[WPTR_BUF];
		state[OWPTR_OFF] = state[WPTR_OFF];
		state[WPTR_BUF] = buf;
		state[WPTR_OFF] = off;
	}

	public void
	endRewrite()
	{
		if (state[OWPTR_BUF] == 0 && state[OWPTR_OFF] == 0) {
			ISOException.throwIt(PivApplet.SW_BAD_REWRITE);
			return;
		}
		state[WPTR_BUF] = state[OWPTR_BUF];
		state[WPTR_OFF] = state[OWPTR_OFF];
		state[OWPTR_BUF] = (short)0;
		state[OWPTR_OFF] = (short)0;
	}

	private short
	takeForRead(short len)
	{
		final Buffer buf = buffers[state[RPTR_BUF]];
		if (buf.data == null || buf.state[Buffer.LEN] == (short)0) {
			/* Cut off by steal() */
			if (buf.state[Buffer.OFFSET] > 0 && buf.data != null) {
				state[RPTR_BUF]++;
				state[RPTR_OFF] = (short)0;
				return (takeForRead(len));
			}
			return ((short)0);
		}
		short take = (short)(buf.state[Buffer.LEN] - state[RPTR_OFF]);
		if (take > len)
			take = len;
		if (state[RPTR_BUF] == state[WPTR_BUF] &&
		    (short)(state[RPTR_OFF] + take) > state[WPTR_OFF]) {
			take = (short)(state[WPTR_OFF] - state[RPTR_OFF]);
		}
		return (take);
	}

	private void
	incRPtr(short take)
	{
		final Buffer buf = buffers[state[RPTR_BUF]];
		state[RPTR_OFF] += take;
		state[RPTR_TOTOFF] += take;
		if (state[RPTR_OFF] >= buf.state[Buffer.LEN]) {
			state[RPTR_BUF]++;
			state[RPTR_OFF] = (short)0;
		}
	}

	private short
	takeForWrite(short len)
	{
		final Buffer buf = buffers[state[WPTR_BUF]];
		if (buf.data == null || buf.state[Buffer.LEN] == 0)
			buf.allocTransient();
		short take = (short)(buf.state[Buffer.LEN] - state[WPTR_OFF]);
		if (take > len)
			take = len;
		if (take == (short)0)
			ISOException.throwIt(PivApplet.SW_RESERVE_FAILURE);
		return (take);
	}

	private void
	incWPtr(short take)
	{
		final Buffer buf = buffers[state[WPTR_BUF]];
		state[WPTR_OFF] += take;
		if (state[OWPTR_BUF] == 0 && state[OWPTR_OFF] == 0)
			state[WPTR_TOTOFF] += take;
		if (state[WPTR_OFF] >= buf.state[Buffer.LEN]) {
			state[WPTR_BUF]++;
			state[WPTR_OFF] = (short)0;
		}
	}

	public void
	write(byte[] source, short offset, short len)
	{
		while (len > 0) {
			final short take = takeForWrite(len);
			final Buffer buf = buffers[state[WPTR_BUF]];
			Util.arrayCopyNonAtomic(source, offset,
			    buf.data, (short)(state[WPTR_OFF] +
			    buf.state[Buffer.OFFSET]), take);
			offset += take;
			len -= take;
			incWPtr(take);
		}
	}

	public void
	startReserve(short len, Buffer into)
	{
		final Buffer curBuf = buffers[state[WPTR_BUF]];
		final short rem = (short)(curBuf.state[Buffer.LEN] - state[WPTR_OFF]);
		if (rem >= len) {
			into.data = curBuf.data;
			into.state[Buffer.LEN] = len;
			into.state[Buffer.OFFSET] = state[WPTR_OFF];
			into.isDynamic = false;
			into.isTransient = curBuf.isTransient;
			return;
		}
		curBuf.state[Buffer.LEN] = state[WPTR_OFF];

		while (true && state[WPTR_BUF] < MAX_BUFS) {
			state[WPTR_BUF]++;
			state[WPTR_OFF] = (short)0;

			final Buffer buf = buffers[state[WPTR_BUF]];
			if (buf.data == null || buf.state[Buffer.LEN] == 0)
				buf.allocTransient();
			if (buf.state[Buffer.LEN] < len) {
				continue;
			}
			into.data = buf.data;
			into.state[Buffer.LEN] = len;
			into.state[Buffer.OFFSET] = (short)0;
			into.isDynamic = false;
			into.isTransient = buf.isTransient;
			return;
		}

		ISOException.throwIt(PivApplet.SW_RESERVE_FAILURE);
	}

	public void
	steal(short len, Buffer into)
	{
		final Buffer curBuf = buffers[state[WPTR_BUF]];
		final short rem = (short)(curBuf.state[Buffer.LEN] - state[WPTR_OFF]);
		if (rem >= len) {
			into.data = curBuf.data;
			into.state[Buffer.LEN] = len;
			into.state[Buffer.OFFSET] = state[WPTR_OFF];
			into.isDynamic = false;
			into.isTransient = curBuf.isTransient;
			curBuf.state[Buffer.LEN] = state[WPTR_OFF];
			state[WPTR_BUF]++;
			state[WPTR_OFF] = (short)0;
			return;
		}
		curBuf.state[Buffer.LEN] = state[WPTR_OFF];

		while (true && state[WPTR_BUF] < MAX_BUFS) {
			state[WPTR_BUF]++;
			state[WPTR_OFF] = (short)0;

			final Buffer buf = buffers[state[WPTR_BUF]];
			if (buf.data == null || buf.state[Buffer.LEN] == 0)
				buf.allocTransient();
			if (buf.state[Buffer.LEN] < len) {
				continue;
			}
			into.data = buf.data;
			into.state[Buffer.LEN] = len;
			into.state[Buffer.OFFSET] = (short)0;
			into.isDynamic = false;
			into.isTransient = buf.isTransient;
			buf.state[Buffer.OFFSET] += len;
			buf.state[Buffer.LEN] -= len;
			if (state[WPTR_OFF] >= buf.state[Buffer.LEN]) {
				state[WPTR_BUF]++;
				state[WPTR_OFF] = (short)0;
			}
			return;
		}

		ISOException.throwIt(PivApplet.SW_RESERVE_FAILURE);
	}

	public void
	endReserve(short used)
	{
		incWPtr(used);
	}

	public short
	read(Buffer into, short len)
	{
		final short rem = takeForRead(len);
		final Buffer buf = buffers[state[RPTR_BUF]];
		if (rem >= len) {
			return (readPartial(into, len));
		}
		steal(len, into);
		return (read(into.data, into.state[Buffer.OFFSET], len));
	}

	public short
	readPartial(Buffer into, short maxLen)
	{
		final short take = takeForRead(maxLen);
		final Buffer buf = buffers[state[RPTR_BUF]];
		if (take == (short)0)
			return (0);
		into.data = buf.data;
		into.state[Buffer.LEN] = take;
		into.state[Buffer.OFFSET] = (short)(state[RPTR_OFF] +
		    buf.state[Buffer.OFFSET]);
		into.isDynamic = false;
		into.isTransient = buf.isTransient;
		incRPtr(take);
		return (take);
	}

	public void
	writeByte(byte val)
	{
		final short rem = takeForWrite((short)1);
		final Buffer buf = buffers[state[WPTR_BUF]];
		buf.data[state[WPTR_OFF]] = val;
		incWPtr((short)1);
	}

	public void
	writeShort(short val)
	{
		final short rem = takeForWrite((short)2);
		final Buffer buf = buffers[state[WPTR_BUF]];
		if (rem < 2) {
			final short upper = (short)(
			    (short)((val & (short)0xFF00) >> 8) & (short)0xFF);
			final short lower = (short)(val & (short)0xFF);
			writeByte((byte)upper);
			writeByte((byte)lower);
			return;
		}
		final short off = (short)(buf.state[Buffer.OFFSET] +
		    state[WPTR_OFF]);
		incWPtr((short)2);
		Util.setShort(buf.data, off, val);
	}

	public short
	readInto(SGList dest, short len)
	{
		short done = (short)0;
		while (len > 0) {
			final short take = takeForRead(len);
			final Buffer buf = buffers[state[RPTR_BUF]];
			if (take == (short)0)
				break;
			dest.append(buf.data, (short)(state[RPTR_OFF] +
			    buf.state[Buffer.OFFSET]), take);
			len -= take;
			done += take;
			incRPtr(take);
		}
		return (done);
	}

	public boolean
	atEnd()
	{
		if (state[RPTR_BUF] < state[WPTR_BUF])
			return (false);
		if (state[RPTR_OFF] < state[WPTR_OFF])
			return (false);
		return (true);
	}

	public short
	available()
	{
		return ((short)(state[WPTR_TOTOFF] - state[RPTR_TOTOFF]));
	}

	public byte
	peekByte()
	{
		final short take = takeForRead((short)1);
		final Buffer buf = buffers[state[RPTR_BUF]];
		if (take == (short)0) {
			ISOException.throwIt(ISO7816.SW_DATA_INVALID);
			return (0);
		}
		final short off = (short)(buf.state[Buffer.OFFSET] +
		    state[RPTR_OFF]);
		return (buf.data[off]);
	}

	public byte
	peekByteW()
	{
		final Buffer buf = buffers[state[WPTR_BUF]];
		final short off = (short)(buf.state[Buffer.OFFSET] +
		    state[WPTR_OFF]);
		return (buf.data[off]);
	}

	public byte
	readByte()
	{
		final short take = takeForRead((short)1);
		final Buffer buf = buffers[state[RPTR_BUF]];
		if (take == (short)0) {
			ISOException.throwIt(ISO7816.SW_DATA_INVALID);
			return (0);
		}
		final short off = (short)(buf.state[Buffer.OFFSET] +
		    state[RPTR_OFF]);
		incRPtr((short)1);
		return (buf.data[off]);
	}

	public short
	readShort()
	{
		final short rem = takeForRead((short)2);
		final Buffer buf = buffers[state[RPTR_BUF]];
		if (rem < 2) {
			short val = (short)((short)readByte() & 0xFF);
			val <<= 8;
			val |= (short)((short)readByte() & 0xFF);
			return (val);
		}
		final short off = (short)(buf.state[Buffer.OFFSET] +
		    state[RPTR_OFF]);
		incRPtr((short)2);
		return (Util.getShort(buf.data, off));
	}

	public void
	skip(short len)
	{
		while (len > 0) {
			final short take = takeForRead(len);
			final Buffer buf = buffers[state[RPTR_BUF]];
			if (take == (short)0) {
				ISOException.throwIt(
				    PivApplet.SW_SKIPPED_OVER_WPTR);
				return;
			}
			len -= take;
			incRPtr(take);
		}
	}

	public void
	append(byte[] data, short offset, short len)
	{
		final Buffer buf = buffers[state[WPTR_BUF]];
		if (state[WPTR_OFF] > 0) {
			buf.state[Buffer.LEN] = state[WPTR_OFF];
			state[WPTR_BUF]++;
		}
		final Buffer nbuf = buffers[state[WPTR_BUF]++];
		state[WPTR_OFF] = (short)0;

		nbuf.data = data;
		nbuf.state[Buffer.OFFSET] = offset;
		nbuf.state[Buffer.LEN] = len;
		nbuf.isDynamic = false;
		nbuf.isTransient = false;

		state[WPTR_TOTOFF] += len;
	}

	public short
	read(byte[] dest, short offset, short maxLen)
	{
		short done = (short)0;
		while (done < maxLen) {
			final short take = takeForRead((short)(maxLen - done));
			final Buffer buf = buffers[state[RPTR_BUF]];
			Util.arrayCopyNonAtomic(buf.data,
			    (short)(state[RPTR_OFF] + buf.state[Buffer.OFFSET]),
			    dest, offset, take);
			offset += take;
			done += take;
			incRPtr(take);
		}
		return (done);
	}
}
