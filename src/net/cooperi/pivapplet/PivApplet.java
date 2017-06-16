/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2017, Alex Wilson <alex@cooperi.net>
 */

package net.cooperi.pivapplet;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.OwnerPIN;
import javacard.framework.Util;
import javacard.security.CryptoException;
import javacard.security.ECKey;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.Key;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.RandomData;
import javacard.security.RSAPrivateCrtKey;
import javacard.security.RSAPublicKey;
import javacard.security.Signature;
import javacardx.crypto.Cipher;

public class PivApplet extends Applet
{
	private static final byte PIV_AID_LEN = (byte)11;
	private static final byte[] PIV_AID = {
	    (byte)0xa0, (byte)0x00, (byte)0x00, (byte)0x03, (byte)0x08,
	    (byte)0x00, (byte)0x00, (byte)0x10, (byte)0x00, (byte)0x01,
	    (byte)0x00
	};

	private static final byte[] TAG_CHUID =
	    { (byte)0x5F, (byte)0xC1, (byte)0x02 };

	private static final byte INS_GET_DATA = (byte)0xCB;
	private static final short P1P2_USE_TLV = (short)0x3FFF;

	private static final short RAM_BUF_SIZE = (short)100;
	private byte[] ramBuf = null;
	private byte[] guid = null;

	private RandomData randData = null;

	public static void
	install(byte[] bArray, short bOffset, byte bLength)
	{
		new PivApplet().register();
	}

	protected
	PivApplet()
	{
		randData = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);

		ramBuf = JCSystem.makeTransientByteArray(RAM_BUF_SIZE,
		    JCSystem.CLEAR_ON_DESELECT);
		guid = new byte[16];
		randData.generateData(guid, (short)0, (short)16);
	}

	@Override
	public void
	process(APDU apdu)
	{
		byte[] buffer = apdu.getBuffer();
		byte ins = buffer[ISO7816.OFFSET_INS];
		short lc = buffer[ISO7816.OFFSET_LC];

		if (buffer[ISO7816.OFFSET_CLA] != 0x00) {
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		}

		if (selectingApplet()) {
			short le = apdu.setOutgoing();
			lc = 0;

			buffer[lc++] = 0x61;
			buffer[lc++] = 0;

			/* {4F, LL, ...} = application identifier */
			buffer[lc++] = 0x4F;
			buffer[lc++] = PIV_AID_LEN;
			Util.arrayCopy(PIV_AID, (short)0, buffer, lc,
			    PIV_AID_LEN);
			lc += PIV_AID_LEN;

			/* {79, XX, {4F, LL, ... } } = tag allocation auth */
			buffer[lc++] = 0x79;
			buffer[lc++] = (byte)(2 + PIV_AID_LEN);
			buffer[lc++] = 0x4F;
			buffer[lc++] = PIV_AID_LEN;
			Util.arrayCopy(PIV_AID, (short)0, buffer, lc,
			    PIV_AID_LEN);
			lc += PIV_AID_LEN;

			buffer[1] = (byte)(lc - 2);

			if (le < lc)
				ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

			apdu.setOutgoingLength(lc);
			apdu.sendBytes((short)0, lc);

			return;
		}

		switch (ins) {
		case INS_GET_DATA:
			processGetData(apdu);
			break;
		default:
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
	}

	private void
	processGetData(APDU apdu)
	{
		byte[] buffer = apdu.getBuffer();
		short lc, le, tagOff;

		short p1p2 = Util.makeShort(buffer[ISO7816.OFFSET_P1],
		    buffer[ISO7816.OFFSET_P2]);

		if (p1p2 != P1P2_USE_TLV)
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);

		lc = apdu.setIncomingAndReceive();
		if (lc != apdu.getIncomingLength()) {
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		}
		tagOff = apdu.getOffsetCdata();
		if (lc < 3 || buffer[tagOff++] != 0x5C)
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);
		if (buffer[tagOff++] != (byte)(lc - 2))
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);

		/* CHUID file */
		if (lc == 5 && Util.arrayCompare(buffer, tagOff, TAG_CHUID,
		    (short)0, (short)3) == 0) {
			le = apdu.setOutgoing();
			lc = 0;

			buffer[lc++] = 0x53;
			buffer[lc++] = 0;

			/* {30, LL, ...} = FASC-N */
			buffer[lc++] = 0x30;
			buffer[lc++] = 1;
			buffer[lc++] = 0x00;

			/* {34, LL, ... } = GUID */
			buffer[lc++] = 0x34;
			buffer[lc++] = 16;
			Util.arrayCopy(guid, (short)0, buffer, lc, (short)16);
			lc += 16;

			buffer[1] = (byte)(lc - 2);

			apdu.setOutgoingLength(le);
			apdu.sendBytes((short)0, le);
			return;
		} else {
			ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
		}
	}
}
