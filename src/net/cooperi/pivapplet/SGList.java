/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2018, Alex Wilson <alex@cooperi.net>
 */

package net.cooperi.pivapplet;

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;

public class SGList implements Readable {
/*#if APPLET_LOW_TRANSIENT
	public static final short DEFAULT_MAX_BUFS = 4;
#else*/
	public static final short DEFAULT_MAX_BUFS = 10;
//#endif

	/*
	 * Minimum number of bytes we will ask our BufferManager for if
	 * allocating for a small request.
	 * */
	public static final short MIN_ALLOC_LEN = 16;

	private static final byte WPTR_BUF = 0;
	private static final byte WPTR_TOTOFF = 1;
	private static final byte RPTR_BUF = 2;
	private static final byte RPTR_TOTOFF = 3;
	private static final byte OWPTR_BUF = 4;
	private static final byte OWPTR_WPOS = 5;
	private static final byte STATE_MAX = OWPTR_WPOS;

	private final BufferManager mgr;
	private final short maxBufs;
	private final TransientBuffer[] buffers;
	private final short[] state;

	public
	SGList(final BufferManager srcmgr)
	{
		this(srcmgr, DEFAULT_MAX_BUFS);
	}

	public
	SGList(final BufferManager srcmgr, short maxBufs)
	{
		mgr = srcmgr;
		this.maxBufs = maxBufs;
		buffers = new TransientBuffer[maxBufs];
		for (short i = 0; i < maxBufs; ++i)
			buffers[i] = new TransientBuffer();
		state = JCSystem.makeTransientShortArray((short)(STATE_MAX + 1),
		    JCSystem.CLEAR_ON_DESELECT);
		this.reset();
	}

	public short
	writeDebugInfo(final byte[] buf, short off)
	{
		off = Util.setShort(buf, off, state[WPTR_BUF]);
		off = Util.setShort(buf, off, buffers[state[WPTR_BUF]].wpos());
		for (short i = 0; i < maxBufs; ++i) {
			final BaseBuffer parent = buffers[i].parent();
			if (buffers[i].data() == null)
				break;
			buf[off++] = (byte)i;
			byte status = (byte)0;
			if (parent != null && parent.isTransient)
				status |= (byte)0x02;
			buf[off++] = status;
			off = Util.setShort(buf, off,
			    (short)buffers[i].data().length);
			off = Util.setShort(buf, off, buffers[i].offset());
			off = Util.setShort(buf, off, buffers[i].len());
		}
		return (off);
	}

	public void
	reset()
	{
		for (short i = 0; i <= state[WPTR_BUF]; ++i) {
			final Buffer buf = buffers[i];
			buf.reset();
		}
		state[WPTR_BUF] = (short)0;
		state[RPTR_BUF] = (short)0;
		state[RPTR_TOTOFF] = (short)0;
		state[WPTR_TOTOFF] = (short)0;
	}

	public void
	resetAndFree()
	{
		for (short i = 0; i <= state[WPTR_BUF]; ++i) {
			final Buffer buf = buffers[i];
			buf.free();
		}
		state[WPTR_BUF] = (short)0;
		state[RPTR_BUF] = (short)0;
		state[RPTR_TOTOFF] = (short)0;
		state[WPTR_TOTOFF] = (short)0;
	}

	/*
	 * Use the APDU buffer as the first element in the SGList -- this way
	 * whatever data is written there can be directly sent without any
	 * copying.
	 */
	public void
	useApdu(final short offset, final short len)
	{
		final TransientBuffer buf = buffers[0];
		if (len > 0) {
			buf.free();
			buf.setApdu(offset, len);
		}
	}


	public void
	rewind()
	{
		for (short i = 0; i <= state[RPTR_BUF]; ++i) {
			final Buffer buf = buffers[i];
			buf.rewind();
		}
		state[RPTR_BUF] = (short)0;
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
		return (buffers[state[WPTR_BUF]].wpos());
	}

	public short
	wPtr()
	{
		return (state[WPTR_TOTOFF]);
	}

	public void
	rewriteAt(final short buf, final short wpos)
	{
		if (state[OWPTR_BUF] != 0 || state[OWPTR_WPOS] != 0) {
			ISOException.throwIt(PivApplet.SW_BAD_REWRITE);
			return;
		}
		state[OWPTR_BUF] = state[WPTR_BUF];
		state[OWPTR_WPOS] = buffers[buf].wpos();
		state[WPTR_BUF] = buf;
		buffers[buf].jumpWpos(wpos);
	}

	public void
	endRewrite()
	{
		if (state[OWPTR_BUF] == 0 && state[OWPTR_WPOS] == 0) {
			ISOException.throwIt(PivApplet.SW_BAD_REWRITE);
			return;
		}
		buffers[state[WPTR_BUF]].jumpWpos(state[OWPTR_WPOS]);
		state[WPTR_BUF] = state[OWPTR_BUF];
		state[OWPTR_BUF] = (short)0;
		state[OWPTR_WPOS] = (short)0;
	}

	private short
	takeForRead(final short len)
	{
		final Buffer buf = buffers[state[RPTR_BUF]];
		short take = buf.remaining();
		if (take > len)
			take = len;
		return (take);
	}

	private void
	incRPtr(final short take)
	{
		final Buffer buf = buffers[state[RPTR_BUF]];
		buf.read(take);
		state[RPTR_TOTOFF] += take;
		if (buf.remaining() == 0 &&
		    state[RPTR_BUF] != state[WPTR_BUF]) {
			state[RPTR_BUF]++;
		}
	}

	private short
	takeForWrite(final short len)
	{
		if (state[WPTR_BUF] >= maxBufs) {
			ISOException.throwIt(PivApplet.SW_RESERVE_FAILURE);
			return ((short)0);
		}
		final TransientBuffer buf = buffers[state[WPTR_BUF]];
		if (!buf.isAllocated()) {
			final short allocLen =
			    (len < MIN_ALLOC_LEN) ? MIN_ALLOC_LEN : len;
			mgr.alloc(allocLen, buf);
		}
		short take = buf.available();
		if (take > len) {
			take = len;
		} else if (take < len) {
			buf.expand((short)(len - take));
			take = buf.available();
			if (take > len)
				take = len;
		}
		if (take == (short)0)
			ISOException.throwIt(PivApplet.SW_RESERVE_FAILURE);
		return (take);
	}

	private void
	incWPtr(final short take)
	{
		final TransientBuffer buf = buffers[state[WPTR_BUF]];
		buf.write(take);
		if (state[OWPTR_BUF] == 0 && state[OWPTR_WPOS] == 0)
			state[WPTR_TOTOFF] += take;
		if (buf.available() == 0) {
			buf.expand(MIN_ALLOC_LEN);
			if (buf.available() == 0 &&
			    state[WPTR_BUF] < maxBufs) {
				state[WPTR_BUF]++;
				final TransientBuffer nbuf;
				nbuf = buffers[state[WPTR_BUF]];
				if (nbuf.data() == null)
					mgr.alloc(MIN_ALLOC_LEN, nbuf);
			}
		}
	}

	public void
	write(final byte[] source, short offset, short len)
	{
		while (len > 0) {
			final short take = takeForWrite(len);
			final Buffer buf = buffers[state[WPTR_BUF]];
			Util.arrayCopyNonAtomic(source, offset,
			    buf.data(), buf.wpos(), take);
			offset += take;
			len -= take;
			incWPtr(take);
		}
	}

	public void
	startReserve(final short len, final TransientBuffer into)
	{
		final TransientBuffer curBuf = buffers[state[WPTR_BUF]];
		short rem = curBuf.available();
		if (rem >= len) {
			into.setWriteSlice(curBuf, len);
			return;
		}
		curBuf.expand((short)(curBuf.len() + len));
		rem = curBuf.available();
		if (rem >= len) {
			into.setWriteSlice(curBuf, len);
			return;
		}

		state[WPTR_BUF]++;
		for (; state[WPTR_BUF] < maxBufs; state[WPTR_BUF]++) {
			final TransientBuffer buf = buffers[state[WPTR_BUF]];
			if (buf.data() == null)
				mgr.alloc(len, buf);
			if (buf.available() < len)
				buf.expand(len);
			if (buf.available() < len)
				continue;
			into.setWriteSlice(buf, len);
			return;
		}

		ISOException.throwIt(PivApplet.SW_RESERVE_FAILURE);
	}

	public void
	endReserve(final short used)
	{
		incWPtr(used);
	}

	public short
	read(final TransientBuffer into, final short len)
	{
		final short rem = takeForRead(len);
		if (rem >= len) {
			return (readPartial(into, len));
		}
		if (!mgr.alloc(len, into))
			return (0);
		final short wrote = read(into.data(), into.wpos(), len);
		into.write(wrote);
		return (wrote);
	}

	public short
	readPartial(final TransientBuffer into, final short maxLen)
	{
		final short take = takeForRead(maxLen);
		final TransientBuffer buf = buffers[state[RPTR_BUF]];
		if (take == (short)0)
			return (0);
		into.setReadSlice(buf, take);
		incRPtr(take);
		return (take);
	}

	public void
	writeByte(final byte val)
	{
		final short rem = takeForWrite((short)1);
		if (rem < 1) {
			ISOException.throwIt(PivApplet.SW_WRITE_OVER_END);
			return;
		}
		final Buffer buf = buffers[state[WPTR_BUF]];
		buf.data()[buf.wpos()] = val;
		incWPtr((short)1);
	}

	public void
	writeShort(final short val)
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
		Util.setShort(buf.data(), buf.wpos(), val);
		incWPtr((short)2);
	}

	public short
	readInto(final SGList dest, short len)
	{
		short done = (short)0;
		while (len > 0) {
			final short take = takeForRead(len);
			final TransientBuffer buf = buffers[state[RPTR_BUF]];
			if (take == (short)0 && state[RPTR_BUF] == state[WPTR_BUF])
				break;
			dest.append(buf, take);
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
		if (buffers[state[RPTR_BUF]].remaining() > 0)
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
		return (buf.data()[buf.rpos()]);
	}

	public byte
	peekByteW()
	{
		final Buffer buf = buffers[state[WPTR_BUF]];
		return (buf.data()[buf.wpos()]);
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
		final byte v = buf.data()[buf.rpos()];
		incRPtr((short)1);
		return (v);
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
		final short v = Util.getShort(buf.data(), buf.rpos());
		incRPtr((short)2);
		return (v);
	}


	public void
	skip(short len)
	{
		while (len > 0) {
			final short take = takeForRead(len);
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
	append(final byte[] data, final short offset, final short len)
	{
		if (buffers[state[WPTR_BUF]].remaining() > 0)
			state[WPTR_BUF]++;
		final TransientBuffer buf = buffers[state[WPTR_BUF]];
		buf.free();
		buf.setBuffer(data, offset, len);
		buf.write(len);
		state[WPTR_TOTOFF] += len;
	}

	public void
	append(final TransientBuffer obuf, final short len)
	{
		if (buffers[state[WPTR_BUF]].remaining() > 0)
			state[WPTR_BUF]++;
		final TransientBuffer buf = buffers[state[WPTR_BUF]];
		buf.free();
		buf.setReadSlice(obuf, len);
		buf.write(len);
		state[WPTR_TOTOFF] += len;
	}


	public short
	read(final byte[] dest, short offset, final short maxLen)
	{
		short done = (short)0;
		while (done < maxLen) {
			final short take = takeForRead((short)(maxLen - done));
			if (take == 0)
				return (done);
			final Buffer buf = buffers[state[RPTR_BUF]];
			Util.arrayCopyNonAtomic(buf.data(), buf.rpos(),
			    dest, offset, take);
			offset += take;
			done += take;
			incRPtr(take);
		}
		return (done);
	}

	public short
	readToApdu(short offset, short maxLen)
	{
		final byte[] buf = APDU.getCurrentAPDUBuffer();
		final TransientBuffer buffer = buffers[state[RPTR_BUF]];
		if (buffer.isApdu() && buffer.rpos() == offset) {
			final short alreadyDone = buffer.remaining();
			offset += alreadyDone;
			maxLen -= alreadyDone;
			incRPtr(alreadyDone);
		}
		return (read(buf, offset, maxLen));
	}
}
