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
import javacard.framework.APDUException;
import javacard.security.CryptoException;
import javacard.security.ECKey;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.DESKey;
import javacard.security.Key;
import javacard.security.KeyBuilder;
import javacard.security.KeyAgreement;
import javacard.security.KeyPair;
import javacard.security.PrivateKey;
import javacard.security.PublicKey;
import javacard.security.RandomData;
import javacard.security.RSAPrivateCrtKey;
import javacard.security.RSAPublicKey;
import javacard.security.Signature;
import javacard.security.SecretKey;
import javacard.security.MessageDigest;
import javacardx.crypto.Cipher;
import javacardx.apdu.ExtendedLength;

public class PivApplet extends Applet implements ExtendedLength
{
	private static final byte[] PIV_AID = {
	    (byte)0xa0, (byte)0x00, (byte)0x00, (byte)0x03, (byte)0x08,
	    (byte)0x00, (byte)0x00, (byte)0x10, (byte)0x00, (byte)0x01,
	    (byte)0x00
	};

	private static final byte[] APP_NAME = {
	    'P', 'i', 'v', 'A', 'p', 'p', 'l', 'e', 't'
	};

	private static final byte[] DEFAULT_ADMIN_KEY = {
	    (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04,
	    (byte)0x05, (byte)0x06, (byte)0x07, (byte)0x08,
	    (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04,
	    (byte)0x05, (byte)0x06, (byte)0x07, (byte)0x08,
	    (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04,
	    (byte)0x05, (byte)0x06, (byte)0x07, (byte)0x08
	};

	private static final byte[] DEFAULT_PIN = {
	    '1', '2', '3', '4', '5', '6', (byte)0xFF, (byte)0xFF
	};
	private static final byte[] DEFAULT_PUK = {
	    '1', '2', '3', '4', '5', '6', '7', '8'
	};

	private static final byte[] CARD_ID_FIXED = {
	    /* GSC-RID: GSC-IS data model */
	    (byte)0xa0, (byte)0x00, (byte)0x00, (byte)0x01, (byte)0x16,
	    /* Manufacturer: ff (unknown) */
	    (byte)0xff,
	    /* Card type: JavaCard */
	    (byte)0x02
	};

	private static final byte INS_VERIFY = (byte)0x20;
	private static final byte INS_CHANGE_PIN = (byte)0x24;
	private static final byte INS_RESET_PIN = (byte)0x2C;
	private static final byte INS_GEN_AUTH = (byte)0x87;
	private static final byte INS_GET_DATA = (byte)0xCB;
	private static final byte INS_PUT_DATA = (byte)0xDB;
	private static final byte INS_GEN_ASYM = (byte)0x47;
	private static final byte INS_GET_RESPONSE = (byte)0xC0;

	private static final byte INS_SET_MGMT = (byte)0xff;
	private static final byte INS_IMPORT_ASYM = (byte)0xfe;
	private static final byte INS_GET_VER = (byte)0xfd;

	private static final byte INS_SG_DEBUG = (byte)0xe0;

	/* ASSERT: tag.end() was called but tag has bytes left. */
	protected static final short SW_TAG_END_ASSERT = (short)0x6F60;
	protected static final short SW_DATA_END_ASSERT = (short)0x6F63;
	/* ASSERT: SGList#startReserve() ran out of Buffers. */
	protected static final short SW_RESERVE_FAILURE = (short)0x6F61;
	/* ASSERT: SGList#skip */
	protected static final short SW_SKIPPED_OVER_WPTR = (short)0x6F62;
	protected static final short SW_BAD_REWRITE = (short)0x6F64;

	private static final boolean USE_EXT_LEN = false;

	private SGList incoming = null;
	private SGList outgoing = null;
	private APDUStream apduStream = null;
	private Buffer tempBuf = null;
	private Buffer outBuf = null;

	private byte[] challenge = null;
	private byte[] iv = null;

	private byte[] guid = null;
	private byte[] cardId = null;
	private byte[] fascn = null;
	private byte[] expiry = null;

	private TlvReader tlv = null;
	private TlvWriter wtlv = null;

	private OwnerPIN pivPin = null;
	private OwnerPIN pukPin = null;

	private RandomData randData = null;
	private Cipher tripleDes = null;
	private Cipher rsaPkcs1 = null;
	private Signature ecdsaP256Sha = null;
	private Signature ecdsaP256Sha256 = null;
	private KeyAgreement ecdh = null;
	private KeyAgreement ecdhSha = null;

	private PivSlot slot9a = null, slot9b = null, slot9c = null,
	    slot9d = null, slot9e = null;

	private static final byte PIV_ALG_DEFAULT = (byte)0x00;
	private static final byte PIV_ALG_3DES = (byte)0x03;
	private static final byte PIV_ALG_RSA1024 = (byte)0x06;
	private static final byte PIV_ALG_RSA2048 = (byte)0x07;
	private static final byte PIV_ALG_AES128 = (byte)0x08;
	private static final byte PIV_ALG_AES192 = (byte)0x0A;
	private static final byte PIV_ALG_AES256 = (byte)0x0C;
	private static final byte PIV_ALG_ECCP256 = (byte)0x11;
	private static final byte PIV_ALG_ECCP384 = (byte)0x14;

	private static final byte PIV_ALG_ECCP256_SHA1 = (byte)0xf0;
	private static final byte PIV_ALG_ECCP256_SHA256 = (byte)0xf1;

	private static final byte GA_TAG_WITNESS = (byte)0x80;
	private static final byte GA_TAG_CHALLENGE = (byte)0x81;
	private static final byte GA_TAG_RESPONSE = (byte)0x82;
	private static final byte GA_TAG_EXP = (byte)0x85;

	private static final byte TAG_CARDCAP = (byte)0x07;
	private static final byte TAG_CHUID = (byte)0x02;
	private static final byte TAG_SECOBJ = (byte)0x06;
	private static final byte TAG_KEYHIST = (byte)0x0C;

	private static final byte TAG_FINGERPRINTS = (byte)0x03;
	private static final byte TAG_FACE = (byte)0x08;

	private static final byte TAG_CERT_9A = (byte)0x05;
	private static final byte TAG_CERT_9C = (byte)0x0A;
	private static final byte TAG_CERT_9D = (byte)0x0B;
	private static final byte TAG_CERT_9E = (byte)0x01;

	private static final byte ALG_EC_SVDP_DH_PLAIN = (byte)3;
	private static final byte ALG_EC_SVDP_DHC_PLAIN = (byte)4;

	public static void
	install(byte[] info, short off, byte len)
	{
		final PivApplet applet = new PivApplet();
		applet.register();
	}

	protected
	PivApplet()
	{
		randData = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
		tripleDes = Cipher.getInstance(Cipher.ALG_DES_CBC_NOPAD, false);
		rsaPkcs1 = Cipher.getInstance(Cipher.ALG_RSA_NOPAD, false);

		try {
			ecdsaP256Sha = Signature.getInstance(
			    Signature.ALG_ECDSA_SHA, false);
		} catch (CryptoException ex) {
			if (ex.getReason() != CryptoException.NO_SUCH_ALGORITHM)
				throw (ex);
		}
		try {
			ecdsaP256Sha256 = Signature.getInstance(
			    ECParams.ALG_ECDSA_SHA_256, false);
		} catch (CryptoException ex) {
			if (ex.getReason() != CryptoException.NO_SUCH_ALGORITHM)
				throw (ex);
		}

		try {
			ecdh = KeyAgreement.getInstance(ALG_EC_SVDP_DH_PLAIN,
			    false);
		} catch (CryptoException ex) {
			if (ex.getReason() != CryptoException.NO_SUCH_ALGORITHM)
				throw (ex);
		}

		if (ecdh == null) {
			try {
				ecdh = KeyAgreement.getInstance(
				    ALG_EC_SVDP_DHC_PLAIN, false);
			} catch (CryptoException ex) {
				if (ex.getReason() !=
				    CryptoException.NO_SUCH_ALGORITHM)
					throw (ex);
			}
		}

		try {
			ecdhSha = KeyAgreement.getInstance(
			    KeyAgreement.ALG_EC_SVDP_DH, false);
		} catch (CryptoException ex) {
			if (ex.getReason() != CryptoException.NO_SUCH_ALGORITHM)
				throw (ex);
		}

		challenge = JCSystem.makeTransientByteArray((short)16,
		    JCSystem.CLEAR_ON_DESELECT);
		iv = JCSystem.makeTransientByteArray((short)16,
		    JCSystem.CLEAR_ON_DESELECT);

		guid = new byte[16];
		randData.generateData(guid, (short)0, (short)16);
		cardId = new byte[21];
		Util.arrayCopy(CARD_ID_FIXED, (short)0, cardId, (short)0,
		    (short)CARD_ID_FIXED.length);
		randData.generateData(cardId, (short)CARD_ID_FIXED.length,
		    (short)(21 - (short)CARD_ID_FIXED.length));

		fascn = new byte[25];
		expiry = new byte[] { '2', '0', '5', '0', '0', '1', '0', '1' };

		slot9a = new PivSlot();
		slot9b = new PivSlot();
		slot9c = new PivSlot();
		slot9d = new PivSlot();
		slot9e = new PivSlot();

		incoming = new SGList();
		outgoing = new SGList();
		apduStream = new APDUStream();

		tempBuf = new Buffer();
		outBuf = new Buffer();

		tlv = new TlvReader();
		wtlv = new TlvWriter(incoming);

		/* Initialize the admin key */
		DESKey dk = (DESKey)KeyBuilder.buildKey(KeyBuilder.TYPE_DES,
		    KeyBuilder.LENGTH_DES3_3KEY, false);
		slot9b.sym = dk;
		dk.setKey(DEFAULT_ADMIN_KEY, (short)0);
		slot9b.symAlg = PIV_ALG_3DES;

		pivPin = new OwnerPIN((byte)5, (byte)8);
		pivPin.update(DEFAULT_PIN, (short)0, (byte)8);
		pukPin = new OwnerPIN((byte)3, (byte)8);
		pukPin.update(DEFAULT_PUK, (short)0, (byte)8);

		slot9a.pinPolicy = PivSlot.P_ONCE;
		slot9c.pinPolicy = PivSlot.P_ALWAYS;
		slot9d.pinPolicy = PivSlot.P_ONCE;
	}

	public void
	process(APDU apdu)
	{
		final byte[] buffer = apdu.getBuffer();
		final byte ins = buffer[ISO7816.OFFSET_INS];

		if (!apdu.isISOInterindustryCLA()) {
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
			return;
		}

		if (selectingApplet()) {
			sendSelectResponse(apdu);
			return;
		}

		switch (ins) {
		case INS_GET_DATA:
			processGetData(apdu);
			break;
		case INS_GEN_AUTH:
			processGeneralAuth(apdu);
			break;
		case INS_PUT_DATA:
			processPutData(apdu);
			break;
		case INS_CHANGE_PIN:
			processChangePin(apdu);
			break;
		case INS_VERIFY:
			processVerify(apdu);
			break;
		case INS_GEN_ASYM:
			processGenAsym(apdu);
			break;
		case INS_RESET_PIN:
			processResetPin(apdu);
			break;
		case INS_GET_VER:
			processGetVersion(apdu);
			break;
		case INS_IMPORT_ASYM:
			processImportAsym(apdu);
			break;
		case INS_SET_MGMT:
			processSetMgmtKey(apdu);
			break;
		case INS_SG_DEBUG:
			processSGDebug(apdu);
			break;
		case INS_GET_RESPONSE:
			continueResponse(apdu);
			break;
		default:
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
	}

	private void
	processGetVersion(APDU apdu)
	{
		short len = 0;
		final short le;
		final byte[] buffer = apdu.getBuffer();

		le = apdu.setOutgoing();
		buffer[len++] = (byte)0x04;
		buffer[len++] = (byte)0x00;
		buffer[len++] = (byte)0x00;

		len = le > 0 ? (le > len ? len : le) : len;
		apdu.setOutgoingLength(len);
		apdu.sendBytes((short)0, len);
	}

	private void
	processSGDebug(APDU apdu)
	{
		short len = (short)0;
		short i = (short)0;
		final short le;
		final byte[] buffer = apdu.getBuffer();

		le = apdu.setOutgoing();
		len = Util.setShort(buffer, len, incoming.state[SGList.WPTR_BUF]);
		len = Util.setShort(buffer, len, incoming.state[SGList.WPTR_OFF]);
		for (i = 0; i < SGList.MAX_BUFS; ++i) {
			if (incoming.buffers[i].data == null)
				break;
			buffer[len++] = (byte)i;
			if (incoming.buffers[i].isTransient)
				buffer[len++] = (byte)1;
			else
				buffer[len++] = (byte)0;
			len = Util.setShort(buffer, len,
			    (short)incoming.buffers[0].data.length);
			len = Util.setShort(buffer, len,
			    incoming.buffers[0].state[Buffer.OFFSET]);
			len = Util.setShort(buffer, len,
			    incoming.buffers[0].state[Buffer.LEN]);
		}

		len = le > 0 ? (le > len ? len : le) : len;
		apdu.setOutgoingLength(len);
		apdu.sendBytes((short)0, len);
	}

	private void
	sendSelectResponse(APDU apdu)
	{
		outgoing.reset();
		wtlv.start(outgoing);

		wtlv.push((byte)0x61);

		wtlv.push((byte)0x4F);
		wtlv.write(PIV_AID, (short)0, (short)PIV_AID.length);
		wtlv.pop();

		wtlv.push((byte)0x79);
		wtlv.push((byte)0x4F);
		wtlv.write(PIV_AID, (short)0, (short)PIV_AID.length);
		wtlv.pop();
		wtlv.pop();

		wtlv.push((byte)0x50);
		wtlv.write(APP_NAME, (short)0, (short)APP_NAME.length);
		wtlv.pop();

		wtlv.push((byte)0xAC);
		wtlv.push((byte)0x80);
		wtlv.writeByte(PIV_ALG_3DES);
		wtlv.pop();
		wtlv.push((byte)0x80);
		wtlv.writeByte(PIV_ALG_RSA1024);
		wtlv.pop();
		wtlv.push((byte)0x80);
		wtlv.writeByte(PIV_ALG_RSA2048);
		wtlv.pop();
		if (ecdsaP256Sha != null || ecdsaP256Sha256 != null) {
			wtlv.push((byte)0x80);
			wtlv.writeByte(PIV_ALG_ECCP256);
			wtlv.pop();
		}
		if (ecdsaP256Sha != null) {
			wtlv.push((byte)0x80);
			wtlv.writeByte(PIV_ALG_ECCP256_SHA1);
			wtlv.pop();
		}
		if (ecdsaP256Sha256 != null) {
			wtlv.push((byte)0x80);
			wtlv.writeByte(PIV_ALG_ECCP256_SHA256);
			wtlv.pop();
		}
		wtlv.push((byte)0x06);
		wtlv.pop();
		wtlv.pop();

		wtlv.pop();
		wtlv.end();

		sendOutgoing(apdu);
	}

	private void
	sendOutgoing(APDU apdu)
	{
		final short len = outgoing.available();
		if (len < 1) {
			ISOException.throwIt(
			    ISO7816.SW_CONDITIONS_NOT_SATISFIED);
			return;
		}

		final short le = apdu.setOutgoing();
		final byte[] buf = apdu.getBuffer();

		short toSend = len;
		if (le > 0 && toSend > le)
			toSend = le;
		if (toSend > (short)0xFF)
			toSend = (short)0xFF;

		final short rem = (short)(len - toSend);
		final byte wantNext =
		    rem > (short)0xFF ? (byte)0xFF : (byte)rem;

		apdu.setOutgoingLength(toSend);
		outgoing.read(buf, (short)0, toSend);
		apdu.sendBytes((short)0, toSend);

		if (rem > 0) {
			ISOException.throwIt(
			    (short)(ISO7816.SW_BYTES_REMAINING_00 |
			    ((short)wantNext & (short)0x00ff)));
		} else {
			ISOException.throwIt(ISO7816.SW_NO_ERROR);
		}
	}

	private void
	continueResponse(APDU apdu)
	{
		sendOutgoing(apdu);
	}

	private boolean
	receiveChain(APDU apdu)
	{
		final byte[] buf = apdu.getBuffer();
		final byte chainBit =
		    (byte)(buf[ISO7816.OFFSET_CLA] & (byte)0x10);

		if (incoming.atEnd())
			incoming.reset();

		short recvLen = apdu.setIncomingAndReceive();
		final short cdata = apdu.getOffsetCdata();

		while (recvLen > 0) {
			incoming.write(buf, cdata, recvLen);
			recvLen = apdu.receiveBytes(cdata);
		}

		if (chainBit != 0) {
			ISOException.throwIt(ISO7816.SW_NO_ERROR);
			return (false);
		}

		return (true);
	}

	private void
	processGenAsym(APDU apdu)
	{
		final byte[] buffer = apdu.getBuffer();
		short lc, len, cLen;
		byte tag, alg = (byte)0xFF;
		final byte key;
		final PivSlot slot;

		if (buffer[ISO7816.OFFSET_P1] != (byte)0x00) {
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
			return;
		}

		key = buffer[ISO7816.OFFSET_P2];

		switch (key) {
		case (byte)0x9A:
			slot = slot9a;
			break;
		case (byte)0x9C:
			slot = slot9c;
			break;
		case (byte)0x9D:
			slot = slot9d;
			break;
		case (byte)0x9E:
			slot = slot9e;
			break;
		default:
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
			return;
		}

		lc = apdu.setIncomingAndReceive();
		if (lc != apdu.getIncomingLength()) {
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
			return;
		}

		if (!slot9b.flags[PivSlot.F_UNLOCKED]) {
			ISOException.throwIt(
			    ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
			return;
		}

		apduStream.reset(apdu.getOffsetCdata(), lc);
		tlv.start(apduStream);

		if (tlv.readTag() != (byte)0xAC) {
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);
			return;
		}

		while (!tlv.atEnd()) {
			tag = tlv.readTag();
			switch (tag) {
			case (byte)0x80:
				if (tlv.tagLength() != 1) {
					ISOException.throwIt(
					    ISO7816.SW_WRONG_DATA);
					return;
				}
				alg = tlv.readByte();
				tlv.end();
				break;
			case (byte)0x81:
				tlv.skip();
				break;
			case (byte)0xab:
				if (tlv.tagLength() != 1) {
					ISOException.throwIt(
					    ISO7816.SW_WRONG_DATA);
					return;
				}
				tag = tlv.readByte();
				if (tag != (byte)0x00 && tag != (byte)0x01) {
					ISOException.throwIt(
					    ISO7816.SW_FUNC_NOT_SUPPORTED);
					return;
				}
				tlv.end();
				break;
			case (byte)0xaa:
				if (tlv.tagLength() != 1) {
					ISOException.throwIt(
					    ISO7816.SW_WRONG_DATA);
					return;
				}
				tag = tlv.readByte();
				switch (tag) {
				case PivSlot.P_DEFAULT:
					if (key == (byte)0x9e) {
						slot.pinPolicy =
						    PivSlot.P_NEVER;
					} else if (key == (byte)0x9c) {
						slot.pinPolicy =
						    PivSlot.P_ALWAYS;
					} else {
						slot.pinPolicy =
						    PivSlot.P_ONCE;
					}
					break;
				case PivSlot.P_NEVER:
				case PivSlot.P_ONCE:
				case PivSlot.P_ALWAYS:
					slot.pinPolicy = tag;
					break;
				default:
					ISOException.throwIt(
					    ISO7816.SW_FUNC_NOT_SUPPORTED);
					return;
				}
				tlv.end();
				break;
			}
		}

		tlv.end();

		if (alg == (byte)0xFF) {
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);
			return;
		}

		switch (alg) {
		case PIV_ALG_RSA1024:
			if (slot.asym == null || slot.asymAlg != alg) {
				slot.asym = new KeyPair(KeyPair.ALG_RSA_CRT,
				    (short)1024);
			}
			slot.asymAlg = alg;
			break;
		case PIV_ALG_RSA2048:
			if (slot.asym == null || slot.asymAlg != alg) {
				slot.asym = new KeyPair(KeyPair.ALG_RSA_CRT,
				    (short)2048);
			}
			slot.asymAlg = alg;
			break;
		case PIV_ALG_ECCP256:
			if (ecdsaP256Sha == null && ecdsaP256Sha256 == null) {
				ISOException.throwIt(ISO7816.SW_WRONG_DATA);
				return;
			}
			ECPrivateKey ecPriv;
			ECPublicKey ecPub;
			if (slot.asym == null || slot.asymAlg != alg) {
				ecPriv = (ECPrivateKey)KeyBuilder.buildKey(
				    KeyBuilder.TYPE_EC_FP_PRIVATE,
				    (short)256, false);
				ecPub = (ECPublicKey)KeyBuilder.buildKey(
				    KeyBuilder.TYPE_EC_FP_PUBLIC,
				    (short)256, false);
				slot.asym = new KeyPair(
				    (PublicKey)ecPub, (PrivateKey)ecPriv);
				ECParams.setCurveParameters(ecPriv);
				ECParams.setCurveParameters(ecPub);
			}
			slot.asymAlg = alg;
			break;
		default:
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);
			return;
		}

		slot.asym.genKeyPair();
		slot.imported = false;

		outgoing.reset();
		wtlv.start(outgoing);

		switch (alg) {
		case PIV_ALG_RSA1024:
		case PIV_ALG_RSA2048:
			RSAPublicKey rpubk =
			    (RSAPublicKey)slot.asym.getPublic();

			wtlv.push64k((short)0x7F49);

			wtlv.push64k((byte)0x81);
			wtlv.startReserve((short)257, tempBuf);
			cLen = rpubk.getModulus(tempBuf.data, tempBuf.offset());
			wtlv.endReserve(cLen);
			wtlv.pop();

			wtlv.push((byte)0x82);
			wtlv.startReserve((short)9, tempBuf);
			cLen = rpubk.getExponent(tempBuf.data, tempBuf.offset());
			wtlv.endReserve(cLen);
			wtlv.pop();
			break;
		case PIV_ALG_ECCP256:
			ECPublicKey epubk =
			    (ECPublicKey)slot.asym.getPublic();

			wtlv.push((short)0x7F49);

			wtlv.push((byte)0x86);
			wtlv.startReserve((short)33, tempBuf);
			cLen = epubk.getW(tempBuf.data, tempBuf.offset());
			wtlv.endReserve(cLen);
			wtlv.pop();
			break;
		default:
			return;
		}

		wtlv.pop();
		wtlv.end();

		sendOutgoing(apdu);
	}

	private void
	processImportAsym(APDU apdu)
	{
		final byte[] buffer = apdu.getBuffer();
		final byte key, alg;
		short lc, len;
		byte tag;
		final PivSlot slot;

		alg = buffer[ISO7816.OFFSET_P1];
		key = buffer[ISO7816.OFFSET_P2];

		if (!slot9b.flags[PivSlot.F_UNLOCKED]) {
			ISOException.throwIt(
			    ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
			return;
		}

		if (!receiveChain(apdu))
			return;

		tlv.start(incoming);

		switch (key) {
		case (byte)0x9a:
			slot = slot9a;
			break;
		case (byte)0x9b:
			slot = slot9b;
			break;
		case (byte)0x9c:
			slot = slot9c;
			break;
		case (byte)0x9d:
			slot = slot9d;
			break;
		case (byte)0x9e:
			slot = slot9e;
			break;
		default:
			tlv.abort();
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
			return;
		}

		switch (alg) {
		case PIV_ALG_RSA1024:
			if (slot.asym == null || slot.asymAlg != alg) {
				slot.asym = new KeyPair(KeyPair.ALG_RSA_CRT,
				    (short)1024);
			}
			slot.asymAlg = alg;
			break;
		case PIV_ALG_RSA2048:
			if (slot.asym == null || slot.asymAlg != alg) {
				slot.asym = new KeyPair(KeyPair.ALG_RSA_CRT,
				    (short)2048);
			}
			slot.asymAlg = alg;
			break;
		case PIV_ALG_ECCP256:
			if (ecdsaP256Sha == null && ecdsaP256Sha256 == null) {
				tlv.abort();
				ISOException.throwIt(ISO7816.SW_WRONG_DATA);
				return;
			}
			ECPrivateKey ecPriv;
			ECPublicKey ecPub;
			if (slot.asym == null || slot.asymAlg != alg) {
				ecPriv = (ECPrivateKey)KeyBuilder.buildKey(
				    KeyBuilder.TYPE_EC_FP_PRIVATE,
				    (short)256, false);
				ecPub = (ECPublicKey)KeyBuilder.buildKey(
				    KeyBuilder.TYPE_EC_FP_PUBLIC,
				    (short)256, false);
				slot.asym = new KeyPair(
				    (PublicKey)ecPub, (PrivateKey)ecPriv);
				ECParams.setCurveParameters(ecPriv);
				ECParams.setCurveParameters(ecPub);
			}
			slot.asymAlg = alg;
			break;
		default:
			tlv.abort();
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
			return;
		}

		slot.imported = true;

		switch (alg) {
		case PIV_ALG_RSA1024:
		case PIV_ALG_RSA2048:
			final RSAPublicKey rpubk =
			    (RSAPublicKey)slot.asym.getPublic();
			final RSAPrivateCrtKey rprivk =
			    (RSAPrivateCrtKey)slot.asym.getPrivate();
			rpubk.clearKey();

			while (!tlv.atEnd()) {
				tag = tlv.readTag();
				switch (tag) {
				case (byte)0x01:
					tlv.read(tempBuf, tlv.tagLength());
					rprivk.setP(tempBuf.data,
					    tempBuf.offset(), tlv.tagLength());
					tlv.end();
					break;
				case (byte)0x02:
					tlv.read(tempBuf, tlv.tagLength());
					rprivk.setQ(tempBuf.data,
					    tempBuf.offset(), tlv.tagLength());
					tlv.end();
					break;
				case (byte)0x03:
					tlv.read(tempBuf, tlv.tagLength());
					rprivk.setDP1(tempBuf.data,
					    tempBuf.offset(), tlv.tagLength());
					tlv.end();
					break;
				case (byte)0x04:
					tlv.read(tempBuf, tlv.tagLength());
					rprivk.setDQ1(tempBuf.data,
					    tempBuf.offset(), tlv.tagLength());
					tlv.end();
					break;
				case (byte)0x05:
					tlv.read(tempBuf, tlv.tagLength());
					rprivk.setPQ(tempBuf.data,
					    tempBuf.offset(), tlv.tagLength());
					tlv.end();
					break;
				case (byte)0xaa:
					if (tlv.tagLength() != 1) {
						tlv.abort();
						ISOException.throwIt(
						    ISO7816.SW_WRONG_DATA);
						return;
					}
					tag = tlv.readByte();
					tlv.end();
					switch (tag) {
					case PivSlot.P_DEFAULT:
						if (key == (byte)0x9e) {
							slot.pinPolicy =
							    PivSlot.P_NEVER;
						} else if (key == (byte)0x9c) {
							slot.pinPolicy =
							    PivSlot.P_ALWAYS;
						} else {
							slot.pinPolicy =
							    PivSlot.P_ONCE;
						}
						break;
					case PivSlot.P_NEVER:
					case PivSlot.P_ONCE:
					case PivSlot.P_ALWAYS:
						slot.pinPolicy = tag;
						break;
					default:
						tlv.abort();
						ISOException.throwIt(
						    ISO7816.
						    SW_FUNC_NOT_SUPPORTED);
						return;
					}
					break;
				case (byte)0xab:
					if (tlv.tagLength() != 1) {
						tlv.abort();
						ISOException.throwIt(
						    ISO7816.SW_WRONG_DATA);
						return;
					}
					final byte touchPolicy = tlv.readByte();
					tlv.end();
					if (touchPolicy != (byte)0x00 &&
					    touchPolicy != (byte)0x01) {
						tlv.abort();
						ISOException.throwIt(
						    ISO7816.
						    SW_FUNC_NOT_SUPPORTED);
						return;
					}
					break;
				default:
					tlv.abort();
					ISOException.throwIt(
					    ISO7816.SW_WRONG_DATA);
					return;
				}
			}
			break;
		case PIV_ALG_ECCP256:
			final ECPublicKey epubk =
			    (ECPublicKey)slot.asym.getPublic();
			final ECPrivateKey eprivk =
			    (ECPrivateKey)slot.asym.getPrivate();
			epubk.clearKey();

			while (!tlv.atEnd()) {
				tag = tlv.readTag();
				switch (tag) {
				case (byte)0x06:
					tlv.read(tempBuf, tlv.tagLength());
					eprivk.setS(tempBuf.data,
					    tempBuf.offset(), tlv.tagLength());
					tlv.end();
					break;
				case (byte)0xaa:
					if (tlv.tagLength() != 1) {
						tlv.abort();
						ISOException.throwIt(
						    ISO7816.SW_WRONG_DATA);
						return;
					}
					tag = tlv.readByte();
					tlv.end();
					switch (tag) {
					case PivSlot.P_DEFAULT:
						if (key == (byte)0x9e) {
							slot.pinPolicy =
							    PivSlot.P_NEVER;
						} else if (key == (byte)0x9c) {
							slot.pinPolicy =
							    PivSlot.P_ALWAYS;
						} else {
							slot.pinPolicy =
							    PivSlot.P_ONCE;
						}
						break;
					case PivSlot.P_NEVER:
					case PivSlot.P_ONCE:
					case PivSlot.P_ALWAYS:
						slot.pinPolicy = tag;
						break;
					default:
						tlv.abort();
						ISOException.throwIt(
						    ISO7816.
						    SW_FUNC_NOT_SUPPORTED);
						return;
					}
					break;
				case (byte)0xab:
					if (tlv.tagLength() != 1) {
						tlv.abort();
						ISOException.throwIt(
						    ISO7816.SW_WRONG_DATA);
						return;
					}
					final byte touchPolicy = tlv.readByte();
					tlv.end();
					if (touchPolicy != (byte)0x00 &&
					    touchPolicy != (byte)0x01) {
						tlv.abort();
						ISOException.throwIt(
						    ISO7816.
						    SW_FUNC_NOT_SUPPORTED);
						return;
					}
					break;
				default:
					tlv.abort();
					ISOException.throwIt(
					    ISO7816.SW_WRONG_DATA);
					return;
				}
			}
			break;
		default:
			tlv.abort();
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
			return;
		}

		tlv.finish();
	}

	private void
	processSetMgmtKey(APDU apdu)
	{
		final byte[] buffer = apdu.getBuffer();
		short lc, len, off;

		if (buffer[ISO7816.OFFSET_P1] != (byte)0xFF ||
		    buffer[ISO7816.OFFSET_P2] != (byte)0xFF) {
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
			return;
		}

		if (!slot9b.flags[PivSlot.F_UNLOCKED]) {
			ISOException.throwIt(
			    ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
			return;
		}

		lc = apdu.setIncomingAndReceive();
		if (lc != apdu.getIncomingLength()) {
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
			return;
		}
		if (lc != 27) {
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);
			return;
		}

		off = apdu.getOffsetCdata();
		final byte alg = buffer[off++];
		final byte key = buffer[off++];
		final byte keyLen = buffer[off++];

		if (alg != PIV_ALG_3DES || key != (byte)0x9b ||
		    keyLen != (byte)24) {
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);
			return;
		}

		final DESKey dk = (DESKey)slot9b.sym;
		dk.setKey(buffer, off);
	}

	private void
	processGeneralAuth(APDU apdu)
	{
		final byte[] buffer = apdu.getBuffer();
		final byte key;
		byte alg, tag, wanted = 0;
		short lc, le, len, cLen;
		final PivSlot slot;
		final Cipher ci;
		final Signature si;

		alg = buffer[ISO7816.OFFSET_P1];
		key = buffer[ISO7816.OFFSET_P2];

		if (!receiveChain(apdu))
			return;

		tlv.start(incoming);

		if (tlv.readTag() != (byte)0x7C) {
			tlv.abort();
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);
			return;
		}

		switch (key) {
		case (byte)0x9a:
			slot = slot9a;
			break;
		case (byte)0x9b:
			slot = slot9b;
			break;
		case (byte)0x9c:
			slot = slot9c;
			break;
		case (byte)0x9d:
			slot = slot9d;
			break;
		case (byte)0x9e:
			slot = slot9e;
			break;
		default:
			tlv.abort();
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
			return;
		}

		switch (alg) {
		case PIV_ALG_DEFAULT:
		case PIV_ALG_3DES:
			alg = PIV_ALG_3DES;
			if (slot.symAlg != alg || slot.sym == null) {
				tlv.abort();
				ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
				return;
			}
			len = (short)8;
			break;
		case PIV_ALG_AES128:
			if (slot.symAlg != alg || slot.sym == null) {
				tlv.abort();
				ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
				return;
			}
			len = (short)16;
			break;
		case PIV_ALG_RSA1024:
		case PIV_ALG_RSA2048:
		case PIV_ALG_ECCP256:
			if (slot.asymAlg != alg || slot.asym == null) {
				tlv.abort();
				ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
				return;
			}
			len = (short)0;
			break;
		case PIV_ALG_ECCP256_SHA1:
		case PIV_ALG_ECCP256_SHA256:
			if (slot.asymAlg != PIV_ALG_ECCP256 ||
			    slot.asym == null) {
				tlv.abort();
				ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
				return;
			}
			len = (short)0;
			break;
		default:
			tlv.abort();
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
			return;
		}

		switch (alg) {
		case PIV_ALG_3DES:
			ci = tripleDes;
			break;
		case PIV_ALG_RSA1024:
		case PIV_ALG_RSA2048:
			ci = rsaPkcs1;
			break;
		default:
			ci = null;
			break;
		}

		/*
		 * First, scan through the TLVs to figure out what the host
		 * actually wants from us.
		 */
		while (!tlv.atEnd()) {
			tag = tlv.readTag();
			if (tlv.tagLength() == 0) {
				wanted = tag;
				break;
			}
			tlv.skip();
		}

		/* Now rewind, let's figure out what to do */
		tlv.rewind();
		tlv.readTag(); /* The 0x7C outer tag */

		tag = tlv.readTag();
		if (tag == wanted) {
			tlv.skip();
			if (!tlv.atEnd())
				tag = tlv.readTag();
		}

		if (wanted == (byte)0) {
			if (key != (byte)0x9b) {
				tlv.abort();
				ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
				return;
			}

			byte comp = -1;
			if (tag == GA_TAG_RESPONSE) {
				ci.init(slot.sym, Cipher.MODE_DECRYPT, iv,
				    (short)0, len);
				tlv.read(tempBuf, len);
				incoming.startReserve(len, outBuf);
				cLen = ci.doFinal(tempBuf.data, tempBuf.offset(),
				    len, outBuf.data, outBuf.offset());

				if (tlv.tagLength() == 0) {
					comp = Util.arrayCompare(outBuf.data,
					    outBuf.offset(), challenge,
					    (short)0, cLen);
					tlv.end();
				}

			} else if (tag == GA_TAG_WITNESS) {
				if (tlv.tagLength() == len) {
					tlv.read(tempBuf, len);
					comp = Util.arrayCompare(tempBuf.data,
					    tempBuf.offset(), challenge,
					    (short)0, len);
					tlv.end();
				}

			} else {
				tlv.abort();
				ISOException.throwIt(ISO7816.SW_WRONG_DATA);
				return;
			}

			if (comp == 0) {
				slot.flags[PivSlot.F_UNLOCKED] = true;
			} else {
				tlv.abort();
				ISOException.throwIt(ISO7816.SW_WRONG_DATA);
				return;
			}

			if (tlv.atEnd()) {
				tlv.end();
				tlv.finish();
				ISOException.throwIt(ISO7816.SW_NO_ERROR);
				return;
			}
			tag = tlv.readTag();
			if (tag == GA_TAG_CHALLENGE)
				wanted = GA_TAG_RESPONSE;
		}

		switch (wanted) {
		case GA_TAG_CHALLENGE:
			if (key != (byte)0x9b) {
				tlv.abort();
				ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
				return;
			}
			/*
			 * The host is asking us for a challenge value
			 * for them to encrypt and return in a RESPONSE
			 */
			outgoing.reset();
			wtlv.start(outgoing);

			randData.generateData(challenge, (short)0, len);
			/*for (byte i = 0; i < (byte)len; ++i)
				challenge[i] = (byte)(i + 1);*/

			wtlv.push((byte)0x7C);

			wtlv.push(GA_TAG_CHALLENGE);
			wtlv.write(challenge, (short)0, len);
			wtlv.pop();

			wtlv.pop();

			wtlv.end();
			sendOutgoing(apdu);
			break;

		case GA_TAG_WITNESS:
			if (key != (byte)0x9b) {
				tlv.abort();
				ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
				return;
			}

			outgoing.reset();
			wtlv.start(outgoing);

			randData.generateData(challenge, (short)0, len);
			/*for (byte i = 0; i < (byte)len; ++i)
				challenge[i] = (byte)(i + 1);*/

			wtlv.push((byte)0x7C);

			wtlv.push(GA_TAG_WITNESS);
			ci.init(slot.sym, Cipher.MODE_ENCRYPT, iv,
			    (short)0, len);
			wtlv.startReserve(len, tempBuf);
			cLen = ci.doFinal(challenge, (short)0, len,
			    tempBuf.data, tempBuf.offset());
			wtlv.endReserve(cLen);
			wtlv.pop();

			wtlv.pop();
			wtlv.end();
			sendOutgoing(apdu);
			break;

		case GA_TAG_RESPONSE:
			if (tag == GA_TAG_EXP) {
				KeyAgreement ag;

				if (alg == PIV_ALG_ECCP256_SHA1) {
					ag = ecdhSha;
				} else if (alg == PIV_ALG_ECCP256) {
					ag = ecdh;
				} else {
					tlv.abort();
					ISOException.throwIt(
					    ISO7816.SW_WRONG_DATA);
					return;
				}
				if (ag == null) {
					tlv.abort();
					ISOException.throwIt(
					    ISO7816.SW_FUNC_NOT_SUPPORTED);
					return;
				}
				if ((key == (byte)0x9b &&
				    !slot9b.flags[PivSlot.F_UNLOCKED]) ||
				    !slot.checkPin(pivPin)) {
					tlv.abort();
					ISOException.throwIt(
					    ISO7816.
					    SW_SECURITY_STATUS_NOT_SATISFIED);
					return;
				}
				incoming.steal((short)257, outBuf);

				cLen = tlv.read(tempBuf, tlv.tagLength());
				tlv.end();

				ag.init(slot.asym.getPrivate());
				cLen = ag.generateSecret(tempBuf.data,
				    tempBuf.offset(), cLen,
				    outBuf.data, outBuf.offset());

				outgoing.reset();
				wtlv.start(outgoing);

				wtlv.push((byte)0x7C, (short)(cLen + 4));
				wtlv.push(GA_TAG_RESPONSE, cLen);
				wtlv.write(outBuf.data, outBuf.offset(), cLen);
				wtlv.pop();

				wtlv.pop();
				wtlv.end();
				sendOutgoing(apdu);
				break;
			}
			if (tag != GA_TAG_CHALLENGE) {
				tlv.abort();
				ISOException.throwIt(ISO7816.SW_WRONG_DATA);
				return;
			}
			final short sLen = tlv.tagLength();
			cLen = tlv.tagLength();
			switch (alg) {
			case PIV_ALG_RSA1024:
				cLen = (short)256;
				break;
			case PIV_ALG_RSA2048:
				cLen = (short)512;
				break;
			case PIV_ALG_ECCP256:
			case PIV_ALG_ECCP256_SHA1:
			case PIV_ALG_ECCP256_SHA256:
				cLen = (short)256;
				break;
			}
			incoming.steal(cLen, outBuf);

			if ((key == (byte)0x9b &&
			    !slot9b.flags[PivSlot.F_UNLOCKED]) ||
			    !slot.checkPin(pivPin)) {
				tlv.abort();
				ISOException.throwIt(
				    ISO7816.
				    SW_SECURITY_STATUS_NOT_SATISFIED);
				return;
			}

			if (slot.symAlg == alg) {
				tlv.read(tempBuf, sLen);
				tlv.end();
				ci.init(slot.sym, Cipher.MODE_ENCRYPT,
				    iv, (short)0, len);
				cLen = ci.doFinal(tempBuf.data,
				    tempBuf.offset(), sLen,
				    outBuf.data, outBuf.offset());

			} else if (slot.asymAlg == alg && (
			    alg == PIV_ALG_RSA1024 || alg == PIV_ALG_RSA2048)) {
				tlv.read(tempBuf, sLen);
				tlv.end();
				ci.init(slot.asym.getPrivate(),
				    Cipher.MODE_ENCRYPT);
				cLen = ci.doFinal(tempBuf.data,
				    tempBuf.offset(), sLen,
				    outBuf.data, outBuf.offset());

			} else if (slot.asymAlg == PIV_ALG_ECCP256) {
				switch (alg) {
				case PIV_ALG_ECCP256_SHA256:
					si = ecdsaP256Sha256;
					break;
				case PIV_ALG_ECCP256_SHA1:
					si = ecdsaP256Sha;
					break;
				default:
					tlv.abort();
					ISOException.throwIt(
					    ISO7816.SW_WRONG_DATA);
					return;
				}

				si.init(slot.asym.getPrivate(),
				    Signature.MODE_SIGN);
				short done = (short)0;
				while (done < sLen) {
					final short read =
					    tlv.readPartial(tempBuf, sLen);
					si.update(tempBuf.data, tempBuf.offset(),
					    read);
					done += read;
				}
				tlv.end();
				cLen = si.sign(null, (short)0, (short)0,
				    outBuf.data, outBuf.offset());
			} else {
				tlv.abort();
				ISOException.throwIt(ISO7816.SW_WRONG_DATA);
				return;
			}

			outgoing.reset();
			wtlv.start(outgoing);

			wtlv.push((byte)0x7C, (short)(cLen + 4));
			wtlv.push(GA_TAG_RESPONSE, cLen);
			wtlv.write(outBuf.data, outBuf.offset(), cLen);
			wtlv.pop();

			wtlv.pop();
			wtlv.end();
			sendOutgoing(apdu);
			break;

		default:
			tlv.abort();
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);
			return;
		}

		tlv.end();
		tlv.finish();
	}

	private void
	processPutData(APDU apdu)
	{
		final byte[] buffer = apdu.getBuffer();
		short lc;
		byte tag;
		PivSlot slot;

		if (buffer[ISO7816.OFFSET_P1] != (byte)0x3F ||
		    buffer[ISO7816.OFFSET_P2] != (byte)0xFF) {
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
			return;
		}

		if (!receiveChain(apdu))
			return;
		tlv.start(incoming);

		if (tlv.readTag() != (byte)0x5C) {
			tlv.abort();
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);
			return;
		}

		if (!slot9b.flags[PivSlot.F_UNLOCKED]) {
			tlv.abort();
			ISOException.throwIt(
			    ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
			return;
		}

		if (tlv.tagLength() == (short)3 &&
		    tlv.readByte() == (byte)0x5F &&
		    tlv.readByte() == (byte)0xC1) {
			/* A regular PIV object, so let's go find the data. */
			tag = tlv.readByte();
			tlv.end();
			switch (tag) {
			case TAG_CHUID:
				ISOException.throwIt(
				    ISO7816.SW_FUNC_NOT_SUPPORTED);
				return;
			case TAG_CERT_9A:
				slot = slot9a;
				break;
			case TAG_CERT_9C:
				slot = slot9c;
				break;
			case TAG_CERT_9D:
				slot = slot9d;
				break;
			case TAG_CERT_9E:
				slot = slot9e;
				break;
			default:
				tlv.abort();
				ISOException.throwIt(
				    ISO7816.SW_FUNC_NOT_SUPPORTED);
				return;
			}

			if (tlv.readTag() != (byte)0x53) {
				tlv.abort();
				ISOException.throwIt(ISO7816.SW_WRONG_DATA);
				return;
			}

			slot.certGzip = false;

			while (!tlv.atEnd()) {
				tag = tlv.readTag();
				if (tag == (byte)0x70) {
					final short len = tlv.tagLength();
					if (slot.cert == null)
						slot.cert = new byte[len];
					if (slot.cert.length < len) {
						slot.cert = new byte[len];
						JCSystem.requestObjectDeletion();
					}
					slot.certLen = tlv.read(slot.cert,
					    (short)0, len);
					tlv.end();
				} else if (tag == (byte)0x71) {
					if (tlv.readByte() == (byte)0x01)
						slot.certGzip = true;
					tlv.end();
				} else {
					tlv.skip();
				}
			}

			tlv.end();
			tlv.finish();

		} else {
			tlv.abort();
			ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
		}
	}

	private void
	processVerify(APDU apdu)
	{
		final byte[] buffer = apdu.getBuffer();
		short lc, pinOff;
		OwnerPIN pin;

		if (buffer[ISO7816.OFFSET_P1] != (byte)0x00 &&
		    buffer[ISO7816.OFFSET_P1] != (byte)0xFF) {
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
			return;
		}

		switch (buffer[ISO7816.OFFSET_P2]) {
		case (byte)0x80:
			pin = pivPin;
			break;
		case (byte)0x81:
			pin = pukPin;
			break;
		default:
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
			return;
		}

		lc = apdu.setIncomingAndReceive();
		if (lc != apdu.getIncomingLength()) {
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
			return;
		}
		pinOff = apdu.getOffsetCdata();

		if (lc == 0) {
			ISOException.throwIt((short)(
			    (short)0x63C0 | pin.getTriesRemaining()));
			return;
		}

		if (lc != 8) {
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);
			return;
		}

		if (!pin.check(buffer, pinOff, (byte)8)) {
			if (pukPin.getTriesRemaining() == 0) {
				if (slot9a.asym != null)
					slot9a.asym.getPrivate().clearKey();
				if (slot9c.asym != null)
					slot9c.asym.getPrivate().clearKey();
				if (slot9d.asym != null)
					slot9d.asym.getPrivate().clearKey();
				if (slot9e.asym != null)
					slot9e.asym.getPrivate().clearKey();
			}
			ISOException.throwIt((short)(
			    (short)0x63C0 | pin.getTriesRemaining()));
			return;
		}

		slot9a.flags[PivSlot.F_PIN_USED] = false;
		slot9c.flags[PivSlot.F_PIN_USED] = false;
		slot9d.flags[PivSlot.F_PIN_USED] = false;
		slot9e.flags[PivSlot.F_PIN_USED] = false;
	}

	private void
	processChangePin(APDU apdu)
	{
		final byte[] buffer = apdu.getBuffer();
		short lc, oldPinOff, newPinOff, idx;
		OwnerPIN pin;

		if (buffer[ISO7816.OFFSET_P1] != (byte)0x00) {
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
			return;
		}

		switch (buffer[ISO7816.OFFSET_P2]) {
		case (byte)0x80:
			pin = pivPin;
			break;
		case (byte)0x81:
			pin = pukPin;
			break;
		default:
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
			return;
		}

		lc = apdu.setIncomingAndReceive();
		if (lc != apdu.getIncomingLength()) {
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
			return;
		}

		oldPinOff = apdu.getOffsetCdata();
		if (lc != 16) {
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);
			return;
		}

		if (!pin.isValidated() &&
		    !pin.check(buffer, oldPinOff, (byte)8)) {
			ISOException.throwIt((short)(
			    (short)0x63C0 | pin.getTriesRemaining()));
			return;
		}

		newPinOff = (short)(oldPinOff + 8);
		for (idx = newPinOff; idx < (short)(newPinOff + 6); ++idx) {
			if (buffer[idx] < (byte)0x30 ||
			    buffer[idx] > (byte)0x39) {
				ISOException.throwIt(ISO7816.SW_WRONG_DATA);
				return;
			}
		}
		for (; idx < (short)(newPinOff + 8); ++idx) {
			if (buffer[idx] != (byte)0xFF && (
			    buffer[idx] < (byte)0x30 ||
			    buffer[idx] > (byte)0x39)) {
				ISOException.throwIt(ISO7816.SW_WRONG_DATA);
				return;
			}
		}
		pin.update(buffer, newPinOff, (byte)8);
	}

	private void
	processResetPin(APDU apdu)
	{
		final byte[] buffer = apdu.getBuffer();
		short lc, pukOff, newPinOff, idx;
		OwnerPIN pin;

		if (buffer[ISO7816.OFFSET_P1] != (byte)0x00) {
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
			return;
		}

		switch (buffer[ISO7816.OFFSET_P2]) {
		case (byte)0x80:
			pin = pivPin;
			break;
		default:
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
			return;
		}

		lc = apdu.setIncomingAndReceive();
		if (lc != apdu.getIncomingLength()) {
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
			return;
		}

		pukOff = apdu.getOffsetCdata();
		if (lc != 16) {
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);
			return;
		}

		if (!pukPin.isValidated() &&
		    !pukPin.check(buffer, pukOff, (byte)8)) {
			ISOException.throwIt((short)(
			    (short)0x63C0 | pin.getTriesRemaining()));
			return;
		}

		newPinOff = (short)(pukOff + 8);
		for (idx = newPinOff; idx < (short)(newPinOff + 6); ++idx) {
			if (buffer[idx] < (byte)0x30 ||
			    buffer[idx] > (byte)0x39) {
				ISOException.throwIt(ISO7816.SW_WRONG_DATA);
				return;
			}
		}
		for (; idx < (short)(newPinOff + 8); ++idx) {
			if (buffer[idx] != (byte)0xFF && (
			    buffer[idx] < (byte)0x30 ||
			    buffer[idx] > (byte)0x39)) {
				ISOException.throwIt(ISO7816.SW_WRONG_DATA);
				return;
			}
		}
		pin.update(buffer, newPinOff, (byte)8);
		pin.resetAndUnblock();
	}

	private void
	processGetData(APDU apdu)
	{
		final byte[] buffer = apdu.getBuffer();
		short lc;
		byte tag;

		if (buffer[ISO7816.OFFSET_P1] != (byte)0x3F ||
		    buffer[ISO7816.OFFSET_P2] != (byte)0xFF) {
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
			return;
		}

		lc = apdu.setIncomingAndReceive();
		if (lc != apdu.getIncomingLength()) {
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
			return;
		}

		apduStream.reset(apdu.getOffsetCdata(), lc);
		tlv.start(apduStream);

		tag = tlv.readTag();
		if (tag != (byte)0x5C) {
			tlv.abort();
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);
			return;
		}

		if (tlv.tagLength() == (short)3 &&
		    tlv.readByte() == (byte)0x5F &&
		    tlv.readByte() == (byte)0xC1) {
			/* A regular PIV object, so let's go find the data. */
			tag = tlv.readByte();
			tlv.end();
			sendPIVObject(apdu, tag);

		} else if (tlv.tagLength() == 1 &&
		    tlv.readByte() == (byte)0x7E) {
			tlv.end();
			/* The special discovery object */
			sendDiscoveryObject(apdu);

		} else {
			tlv.abort();
			ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
		}

		tlv.finish();
	}

	private void
	sendPIVObject(APDU apdu, byte tag)
	{
		PivSlot slot;

		switch (tag) {
		case TAG_CARDCAP:
			outgoing.reset();
			wtlv.start(outgoing);

			wtlv.push((byte)0x53);

			/* Card Identifier */
			wtlv.push((byte)0xF0);
			wtlv.write(cardId, (short)0, (short)cardId.length);
			wtlv.pop();

			/* Container version number */
			wtlv.push((byte)0xF1);
			wtlv.writeByte((byte)0x21);
			wtlv.pop();
			wtlv.push((byte)0xF2);
			wtlv.writeByte((byte)0x21);
			wtlv.pop();

			wtlv.push((byte)0xF3);
			wtlv.pop();

			wtlv.push((byte)0xF4);
			wtlv.pop();

			/* Data Model Number */
			wtlv.push((byte)0xF5);
			wtlv.writeByte((byte)0x10);
			wtlv.pop();

			wtlv.push((byte)0xF6);
			wtlv.pop();

			wtlv.push((byte)0xF7);
			wtlv.pop();

			wtlv.push((byte)0xFA);
			wtlv.pop();

			wtlv.push((byte)0xFB);
			wtlv.pop();

			wtlv.push((byte)0xFC);
			wtlv.pop();

			wtlv.push((byte)0xFD);
			wtlv.pop();

			wtlv.push((byte)0xFE);
			wtlv.pop();

			wtlv.pop();
			wtlv.end();
			sendOutgoing(apdu);
			return;
		case TAG_CHUID:
			outgoing.reset();
			wtlv.start(outgoing);

			wtlv.push((byte)0x53);

			/* FASC-N identifier */
			wtlv.push((byte)0x30);
			wtlv.write(fascn, (short)0, (short)fascn.length);
			wtlv.pop();

			/* Card GUID */
			wtlv.push((byte)0x34);
			wtlv.write(guid, (short)0, (short)guid.length);
			wtlv.pop();

			/* Expiry date */
			wtlv.push((byte)0x35);
			wtlv.write(expiry, (short)0, (short)expiry.length);
			wtlv.pop();

			/* Issuer signature */
			wtlv.push((byte)0x3E);
			wtlv.pop();

			wtlv.push((byte)0xFE);
			wtlv.pop();

			wtlv.pop();
			wtlv.end();
			sendOutgoing(apdu);
			return;
		case TAG_KEYHIST:
			outgoing.reset();
			wtlv.start(outgoing);

			wtlv.push((byte)0x53);

			wtlv.push((byte)0xC1);
			wtlv.writeByte((byte)0);
			wtlv.pop();

			wtlv.push((byte)0xC2);
			wtlv.writeByte((byte)0);
			wtlv.pop();

			wtlv.push((byte)0xFE);
			wtlv.pop();

			wtlv.pop();
			wtlv.end();
			sendOutgoing(apdu);
			return;
		case TAG_CERT_9A:
			slot = slot9a;
			break;
		case TAG_CERT_9C:
			slot = slot9c;
			break;
		case TAG_CERT_9D:
			slot = slot9d;
			break;
		case TAG_CERT_9E:
			slot = slot9e;
			break;
		default:
			ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
			return;
		}

		if (slot.cert == null || slot.certLen == 0) {
			ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
			return;
		}

		outgoing.reset();
		wtlv.start(outgoing);

		wtlv.push((byte)0x53, (short)(slot.certLen + 10));

		wtlv.push((byte)0x70, slot.certLen);
		wtlv.write(slot.cert, (short)0, slot.certLen);
		wtlv.pop();

		wtlv.push((byte)0x71);
		if (slot9a.certGzip)
			wtlv.writeByte((byte)0x01);
		else
			wtlv.writeByte((byte)0x00);
		wtlv.pop();

		wtlv.pop();
		wtlv.end();
		sendOutgoing(apdu);
	}

	private void
	sendDiscoveryObject(APDU apdu)
	{
		outgoing.reset();
		wtlv.start(outgoing);

		wtlv.push((byte)0x7E);

		/* AID */
		wtlv.push((byte)0x4F);
		wtlv.write(PIV_AID, (short)0, (short)PIV_AID.length);
		wtlv.pop();

		/* PIN policy */
		wtlv.push((short)0x5F2F);
		wtlv.writeByte((byte)0x40);	/* PIV pin only, no others */
		wtlv.writeByte((byte)0x00);	/* RFU, since no global PIN */
		wtlv.pop();

		wtlv.pop();
		wtlv.end();
		sendOutgoing(apdu);
	}
}
