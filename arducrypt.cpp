/*
 * Copyright (C) 2017 A. Koller - akandroid75@gmail.com
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */


#include <arducrypt.h>
#include <CRC32.h>
#include <Curve25519.h>
#include <Ed25519.h>
#include <HardwareSerial.h>
#include <cstring>
#include "esp8266_peri.h"

/**
 * \class arducrypt arducrypt.h <arducrypt.h>
 * \brief helper class for crypto session creation
 *
 * session is created via a ECDH (elliptic curve diffie-hellman) key exchange.
 *
 * crypto lib uses:
 * https://github.com/rweather/arduinolibs/
 *
 */


void generateInitVector(uint8_t* sessionIv);



/**
 * \brief validates signature of message with given signkey
 */
boolean arducrypt::validateSignature(arducryptsignature* signature,
		uint8_t* message, int length, arducryptkey* key) {
	bool verified = Ed25519::verify(
			(const unsigned char*) &signature->signaturebytes,
			(const unsigned char*) &key->keybytes,
			(const unsigned char*) message, length);
	return verified;
}

/**
 * \brief generates a random iv (or nounce)
 */
void generateInitVector(uint8_t* sessionIv) {
	for(unsigned int i = 0 ; i < IVSIZE; i++) {
		sessionIv[i] = (uint8_t)RANDOM_REG32;
	}
	ARDUCRYPTDEBUG_PRINT(F("generateInitVector:"));
	ARDUCRYPTDEBUG_HEXPRINT(sessionIv, IVSIZE);
}

/**
 * \brief
 * generates a Ed25519 key pair
 * privateKey[32] & publicKey[32]
 */
void arducrypt::generateSigKeyPair(uint8_t* privateKey, uint8_t* publicKey) {
	Ed25519::generatePrivateKey(privateKey);
	Ed25519::derivePublicKey(publicKey, privateKey);
}

/**
 * \brief initializes arducryptsession
 */
boolean arducrypt::generateSession(arducryptsession* session, arducryptkey* partnerkey) {
	ARDUCRYPTDEBUG_PRINT(F("generateSessionKey"));
	uint8_t privKey[KEYSIZE];
	uint8_t secretShared[KEYSIZE];
	memcpy(secretShared,partnerkey,KEYSIZE);
	ESP.wdtFeed();
	Curve25519::dh1(session->publicKey, privKey);
	ESP.wdtFeed();
	ARDUCRYPTDEBUG_PRINT(F("sessionServerPrivKey:"));
	ARDUCRYPTDEBUG_HEXPRINT((uint8_t* )&privKey, KEYSIZE);
	ARDUCRYPTDEBUG_PRINT(F("sessionServerPubKey:"));
	ARDUCRYPTDEBUG_HEXPRINT(
			(uint8_t* )&session->publicKey,
			KEYSIZE);
	ARDUCRYPTDEBUG_PRINT(F("partnerKey:"));
	ARDUCRYPTDEBUG_HEXPRINT(
			(uint8_t* )&partnerkey->keybytes,
			KEYSIZE);
	if (Curve25519::dh2(secretShared, privKey) == true) {
		ESP.wdtFeed();
		ARDUCRYPTDEBUG_PRINT(F("secret:"));
		ARDUCRYPTDEBUG_HEXPRINT((uint8_t* )&secretShared, KEYSIZE);
		// generate IV
		generateInitVector((uint8_t*)&session->iv);
		ESP.wdtFeed();
		// copy to buffer out
		ARDUCRYPTDEBUG_PRINT(F("generateIV:"));
		ARDUCRYPTDEBUG_HEXPRINT((uint8_t* )&session->iv, IVSIZE);
		session->encrypt.setKey(secretShared, KEYSIZE);
		session->encrypt.setIV(session->iv, IVSIZE);
		session->decrypt.setKey(secretShared, KEYSIZE);
		session->decrypt.setIV(session->iv, IVSIZE);
		ESP.wdtFeed();
		// delete
		memset(secretShared ,0,KEYSIZE);
		return true;
	}
	return false;
}

/**
 * \brief signs message with given sign key
 */
void arducrypt::sign(arducryptkeypair* signKey, uint8_t* message, arducryptsignature* signature,int length) {

		Ed25519::sign(signature->signaturebytes,
				signKey->privateKey.keybytes, signKey->publicKey.keybytes,
				message,
				length);
		ARDUCRYPTDEBUG_PRINT(F("signature:"));
		ARDUCRYPTDEBUG_HEXPRINT(
				(uint8_t* )&signature->signaturebytes,
				SIGNATURESIZE);
}

/**
 * \brief decrypt encryptedmessage with given arducryptsession
 * output: plainmessage
 */
void arducrypt::decrypt(uint8_t* plainmessage,
		uint8_t* encryptedmessage, arducryptsession* session) {
	ARDUCRYPTDEBUG_PRINT(F("decrypt_data: "));
	ARDUCRYPTDEBUG_HEXPRINT((uint8_t* )encryptedmessage,  messagesize);

		session->decrypt.decrypt((uint8_t*) plainmessage,
				(const uint8_t*) encryptedmessage,
				(size_t)  messagesize);
		ARDUCRYPTDEBUG_PRINT(F("decrypted: "));
		ARDUCRYPTDEBUG_HEXPRINT((uint8_t* )plainmessage,  messagesize);
}

/**
 * \brief encrypt plainmessage with given arducryptsession
 */
void arducrypt::encrypt(uint8_t* plainmessage,
		uint8_t* encryptedmessage, arducryptsession* session) {
	ARDUCRYPTDEBUG_PRINT(F("encrypt_data: "));
	ARDUCRYPTDEBUG_HEXPRINT((uint8_t* )plainmessage, messagesize);

		session->encrypt.encrypt((uint8_t*) encryptedmessage,
				(const uint8_t*) plainmessage, (size_t) messagesize);
		ARDUCRYPTDEBUG_PRINT(F("encrypted: "));
		ARDUCRYPTDEBUG_HEXPRINT((uint8_t* )encryptedmessage,  messagesize);

}

/**
 * \brief calculate CRC32 checksum for given message
 */
uint32_t arducrypt::calcChecksum(uint8_t* message, int length) {
	uint32_t chksum = CRC32::calculate(message, length);
	return chksum;
}

/**
 * \brief helper method: print hexstring
 */
void arducrypt::printHex(uint8_t *data, int length)
		{
	char hexstring[length * 2 + 1];
	byte left;
	byte right;
	for (int i = 0; i < length; i++) {
		left = (data[i] >> 4) & 0x0f;
		right = data[i] & 0x0f;
		hexstring[i * 2] = left + 48;
		hexstring[i * 2 + 1] = right + 48;
		if (left > 9)
			hexstring[i * 2] += 39;
		if (right > 9)
			hexstring[i * 2 + 1] += 39;
	}
	hexstring[length * 2] = '\0';
	Serial.println(hexstring);
}

