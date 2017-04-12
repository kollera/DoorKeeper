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


#ifndef ARDUCRYPT_H_
#define ARDUCRYPT_H_

#include <Arduino.h>
#include <ChaCha.h>
#include <stdint.h>

#define SIGNATURESIZE 64
#define KEYSIZE 32
#define IVSIZE 8
#define CHECKSUMSIZE 4
#define INVALIDINDEX -1

#define ARDUCRYPTDEBUG 1

#ifdef ARDUCRYPTDEBUG
#define ARDUCRYPTDEBUG_HEXPRINT(x,y) arducrypt::printHex(x,y)
#define ARDUCRYPTDEBUG_HEXPRINTBYTE(x) arducrypt::printHex(&x,1)
#define ARDUCRYPTDEBUG_WRITE(x,y)  Serial.write (x,y)
#define ARDUCRYPTDEBUG_PRINT(z)  Serial.print (z)
#define ARDUCRYPTDEBUG_PRINTLN(z)  Serial.println (z)
#else
#define ARDUCRYPTDEBUG_HEXPRINT(x,y)
#define ARDUCRYPTDEBUG_HEXPRINTBYTE(x)
#define ARDUCRYPTDEBUG_WRITE(x,y)
#define ARDUCRYPTDEBUG_PRINT(x)
#define ARDUCRYPTDEBUG_PRINTLN(z)
#endif

#define ARDUCRYPTMESSAGESIZE 128

struct arducryptsignature {
	uint8_t signaturebytes[SIGNATURESIZE];
};

struct arducryptkey {
	byte keybytes[KEYSIZE];
};

struct arducryptkeypair {
	arducryptkey publicKey;
	arducryptkey privateKey;
};

struct arducryptsession {
	uint8_t publicKey[KEYSIZE];
	uint8_t iv[IVSIZE];
	ChaCha encrypt;
	ChaCha decrypt;
};

class arducrypt {

public:
	static void printHex(uint8_t *data, int length);

public:


	arducrypt(int framesize) {
		messagesize = framesize;
	}

	boolean generateSession(arducryptsession* session,
			arducryptkey* partnerkey);

	void sign(arducryptkeypair* signKey, uint8_t* message,
			arducryptsignature* signature, int length);
	boolean validateSignature(arducryptsignature* signature, uint8_t* message,
			int length, arducryptkey* key);

	void decrypt(uint8_t* plainmessage, uint8_t* encryptedmessage,
			arducryptsession* session);
	void encrypt(uint8_t* plainmessage, uint8_t* encryptedmessage,
			arducryptsession* session);

	uint32_t calcChecksum(uint8_t* message, int len);

	void static generateSigKeyPair(uint8_t* privateKey, uint8_t* publicKey);

private:
	int messagesize;
};

#endif /* ARDUCRYPT_H_ */
