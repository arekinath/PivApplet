/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2018, Alex Wilson <alex@cooperi.net>
 */

package net.cooperi.pivapplet;

import javacard.framework.JCSystem;

/*
 * BufferManager represents a simple first-fit memory allocator. It keeps an
 * array of BaseBuffer instances which each represent a memory chunk (preferably
 * transient memory, but falling back to regular), and splits each into 16
 * pieces. Each BaseBuffer has a bitmap of the 16 pieces as a short.
 *
 * When someone requests a chunk of memory, we round it up to the nearest 1/16th
 * chunk and use a bitwise AND against the bitmap to test if the space is
 * available. If it is, we use it; otherwise we slide the mask to the left and
 * try again (searching for a higher offset).
 *
 * Note that the whole allocation state is all kept in DESELECT transient memory
 * -- so the worst "memory leak" we can have lasts until the applet is
 * de-selected.
 *
 * The reason why this is done dynamically is to enable the TlvWriter, crypto
 * etc to grab small chunks of memory for "scratch" space for constructing
 * tags or decrypting data while re-using the precious transient memory we used
 * for spooling in chained packets. It also enables easy re-use between rx and
 * tx, even when we allocate something in between that has to be kept (e.g. we
 * rx some data, then encrypt part of it, put the encrypted data in a temp
 * buffer, then release all the rx state to start txing, but we need to keep
 * that ciphertext to put it into the tx payload).
 */
public class BufferManager {
/*#if APPLET_LOW_TRANSIENT
	public static final byte MAX_BUFS = 6;
#else*/
	public static final byte MAX_BUFS = 10;
//#endif

	private final BaseBuffer[] buffers;
	public boolean gcBlewUp = false;

	public
	BufferManager()
	{
		buffers = new BaseBuffer[MAX_BUFS];
		for (short i = 0; i < MAX_BUFS; ++i)
			buffers[i] = new BaseBuffer(this, i);
	}

	public void
	cullNonTransient()
	{
		if (!JCSystem.isObjectDeletionSupported() || gcBlewUp)
			return;
		boolean dogc = false;
		for (short i = 0; i < MAX_BUFS; ++i) {
			final BaseBuffer buf = buffers[i];
			if (!buf.isTransient && buf.data() != null) {
				buf.free();
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

	public boolean
	alloc(final short size, final TransientBuffer buf)
	{
		/*
		 * Lots of the backing buffers are the same size, so we can
		 * re-use these calculations.
		 */
		short lastBaseMask = 0;
		short lastBufSize = 0;
		short lastBits = 0;

		/*
		 * If we already allocated this buffer and can re-use it, just
		 * do that.
		 */
		if (buf.isAllocated()) {
			final short curLen = buf.len();
			if (curLen < size)
				buf.expand((short)(size - curLen));
			if (buf.len() >= size) {
				buf.reset();
				return (true);
			}
		}

		buf.free();

		for (short idx = 0; idx < MAX_BUFS; ++idx) {
			final BaseBuffer buffer = buffers[idx];

			if (buffer.maskFull())
				continue;

			/*
			 * We've never used this buffer before? Try to allocate
			 * some space to it.
			 */
			if (buffer.data() == null)
				buffer.alloc();

			final byte[] data = buffer.data();
			if (data == null)
				continue;

			final short bufSize = (short)data.length;

			/*
			 * offsetStep is the size of one of the 1/16th chunks
			 * which are represented by 1 bit in the bitmap.
			 */
			final short offsetStep = buffer.offsetStep;

			/*
			 * baseMask will contain the number of set bits that
			 * we're trying to allocate, starting at bit 0 (e.g.
			 * if we need to alloc 4 bits worth, it will be 0b1111
			 * or 0x0f).
			 */
			final short baseMask;
			/* Number of set bits */
			short bits;

			if (bufSize == lastBufSize) {
				baseMask = lastBaseMask;
				bits = lastBits;
			} else {
				short baseSize = offsetStep;
				bits = 1;
				while (baseSize < size) {
					++bits;
					baseSize += offsetStep;
				}
				baseMask = (short)(
				    (short)((short)1 << bits) - 1);
				lastBaseMask = baseMask;
				lastBufSize = bufSize;
				lastBits = bits;
			}

			/*
			 * Now shift the mask left until we've got free space
			 * or we run out of bits to check.
			 */
			short mask = baseMask;
			short offset = 0;
			bits = (short)(16 - bits);
			while (!buffer.maskAvailable(mask) && bits >= 0) {
				--bits;
				offset += offsetStep;
				mask = (short)(mask << 1);
			}

			if ((short)(offset + size) > bufSize)
				continue;

			if (buffer.setMaskIfAvailable(mask)) {
				buf.allocFromBase(buffer, offset, mask, size);
				return (true);
			}
		}
		return (false);
	}

	/* Called by TransientBuffer#expand */
	public boolean
	realloc(final short size, final TransientBuffer buf)
	{
		final BaseBuffer buffer = buf.parent();
		final short bufSize = buffer.len();
		final short offset = buf.offset();

		/*
		 * We can't possibly fit this in the buffer, even if the
		 * bitmap is empty.
		 */
		if ((short)(offset + size) > bufSize)
			return (false);

		/*
		 * mask = our current mask (before realloc)
		 * nmask = our desired mask
		 */
		final short mask = buf.mask();
		final short offsetStep = (short)(bufSize >> 4);
		short baseSize = offsetStep;
		short nmask = mask;
		while (baseSize < buf.len())
			baseSize += offsetStep;
		while (baseSize < size) {
			nmask |= (short)(nmask << 1);
			baseSize += offsetStep;
		}

		/*
		 * If all of the new bits that we want to add are zero, then
		 * buffer's bitmap AND nmask will be just mask (only our old
		 * existing used bits are set)
		 */
		if (buffer.maskAnd(nmask) != mask)
			return (false);

		buffer.setMask(nmask);
		buf.expandFromBase(nmask, size);
		return (true);
	}
}
