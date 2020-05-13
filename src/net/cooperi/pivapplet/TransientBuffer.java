/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2018, Alex Wilson <alex@cooperi.net>
 */

package net.cooperi.pivapplet;

import javacard.framework.APDU;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;

public class TransientBuffer implements Buffer {
	private static final short PTR_PARENT = 0;
	private static final short PTR_BUF = 1;

	private static final short ST_MASK = 0;
	private static final short ST_FLAGS = 1;
	private static final short ST_BEGIN = 2;
	private static final short ST_END = 3;
	private static final short ST_RPOS = 4;
	private static final short ST_WPOS = 5;

	private static final short FL_APDU = 1;
	private static final short FL_BUF = 2;
	private static final short FL_ALLOC = 4;
	private static final short FL_EXPANDED = 8;

	private Object[] ptrs;
	private short[] state;

	public
	TransientBuffer()
	{
/*#if APPLET_LOW_TRANSIENT
		ptrs = new Object[PTR_BUF + 1];
#else*/
		ptrs = JCSystem.makeTransientObjectArray((short)(PTR_BUF + 1),
		    JCSystem.CLEAR_ON_DESELECT);
//#endif
		state = JCSystem.makeTransientShortArray((short)(ST_WPOS + 1),
		    JCSystem.CLEAR_ON_DESELECT);
	}

	public boolean
	isAllocated()
	{
		return (state[ST_FLAGS] != (short)0);
	}

	public BaseBuffer
	parent()
	{
		if (ptrs[PTR_PARENT] == null)
			return (null);
		if ((short)(state[ST_FLAGS] & FL_ALLOC) == 0)
			return (null);
		return ((BaseBuffer)ptrs[PTR_PARENT]);
	}

	public short
	mask()
	{
		return (state[ST_MASK]);
	}

	public void
	setApdu(final short offset, final short len)
	{
		ptrs[PTR_PARENT] = null;
		ptrs[PTR_BUF] = null;
		state[ST_BEGIN] = offset;
		state[ST_END] = (short)(offset + len);
		state[ST_FLAGS] = FL_APDU;
		reset();
	}

	public void
	setWriteSlice(final TransientBuffer other, final short len)
	{
		if (other.isApdu())
			setApdu(other.wpos(), len);
		else
			setBuffer(other.data(), other.wpos(), len);
	}

	public void
	setReadSlice(final TransientBuffer other, final short len)
	{
		if (other.isApdu())
			setApdu(other.rpos(), len);
		else
			setBuffer(other.data(), other.rpos(), len);
	}

	public void
	setBuffer(final byte[] buffer, final short offset, final short len)
	{
		ptrs[PTR_PARENT] = null;
		ptrs[PTR_BUF] = buffer;
		state[ST_BEGIN] = offset;
		state[ST_END] = (short)(offset + len);
		state[ST_FLAGS] = FL_BUF;
		reset();
	}

	public void
	allocFromBase(final BaseBuffer parent, final short offset,
	    final short mask, final short size)
	{
		ptrs[PTR_PARENT] = parent;
		ptrs[PTR_BUF] = parent.data();
		state[ST_BEGIN] = offset;
		state[ST_END] = (short)(offset + size);
		state[ST_MASK] = mask;
		state[ST_FLAGS] = FL_ALLOC;
		reset();
	}

	public void
	expandFromBase(final short newMask, final short newSize)
	{
		state[ST_END] = (short)(state[ST_BEGIN] + newSize);
		state[ST_MASK] = newMask;
		state[ST_FLAGS] |= FL_EXPANDED;
	}

	public void
	expand(final short sizeIncr)
	{
		final BaseBuffer parent = (BaseBuffer)ptrs[PTR_PARENT];
		if (parent != null) {
			final short size = (short)(
			    state[ST_END] - state[ST_BEGIN]);
			final short newSize = (short)(size + sizeIncr);
			parent.manager.realloc(newSize, this);
		}
	}

	public void
	free()
	{
		final BaseBuffer parent = (BaseBuffer)ptrs[PTR_PARENT];
		if (parent != null)
			parent.clearMask(state[ST_MASK]);

		ptrs[PTR_PARENT] = null;
		ptrs[PTR_BUF] = null;
		state[ST_BEGIN] = 0;
		state[ST_END] = 0;
		state[ST_RPOS] = 0;
		state[ST_WPOS] = 0;
		state[ST_FLAGS] = 0;
	}

	public short
	offset()
	{
		return (state[ST_BEGIN]);
	}

	public short
	len()
	{
		return ((short)(state[ST_END] - state[ST_BEGIN]));
	}

	public byte[]
	data()
	{
		final short flags = state[ST_FLAGS];
		if ((short)(flags & FL_APDU) != 0)
			return (APDU.getCurrentAPDUBuffer());
		if (flags == 0)
			return (null);
		return ((byte[])ptrs[PTR_BUF]);
	}

	public boolean
	isApdu()
	{
		return ((short)(state[ST_FLAGS] & FL_APDU) != 0);
	}

	public short
	rpos()
	{
		return (state[ST_RPOS]);
	}

	public short
	wpos()
	{
		return (state[ST_WPOS]);
	}

	public void
	jumpWpos(final short newpos)
	{
		if (newpos < state[ST_BEGIN] || newpos > state[ST_END]) {
			ISOException.throwIt(PivApplet.SW_BAD_REWRITE);
			return;
		}
		state[ST_WPOS] = newpos;
	}

	public void
	read(short bytes)
	{
		state[ST_RPOS] += bytes;
	}

	public void
	write(short bytes)
	{
		state[ST_WPOS] += bytes;
		if (state[ST_WPOS] < state[ST_BEGIN] ||
		    state[ST_WPOS] > state[ST_END]) {
			ISOException.throwIt(PivApplet.SW_WRITE_OVER_END);
			return;
		}
	}

	public short
	remaining()
	{
		return ((short)(state[ST_WPOS] - state[ST_RPOS]));
	}

	public short
	available()
	{
		return ((short)(state[ST_END] - state[ST_WPOS]));
	}

	public void
	reset()
	{
		state[ST_RPOS] = state[ST_BEGIN];
		state[ST_WPOS] = state[ST_BEGIN];
	}

	public void
	rewind()
	{
		state[ST_RPOS] = state[ST_BEGIN];
	}
}
