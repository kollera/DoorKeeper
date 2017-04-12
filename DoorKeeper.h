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

#ifndef doorkeeper_h
#define doorkeeper_h

#include <arducrypt.h>
#include <Arduino.h>
#include <stdint.h>
#include <sys/types.h>

#define DOORKEEPERDEBUG 1

#ifdef DOORKEEPERDEBUG
#define DOORKEEPERDEBUG_HEXPRINT(x,y) arducrypt::printHex(x,y)
#define DOORKEEPERDEBUG_HEXPRINTBYTE(x) arducrypt::printHex(&x,1)
#define DOORKEEPERDEBUG_WRITE(x,y)  Serial.write (x,y)
#define DOORKEEPERDEBUG_PRINT(z)  Serial.print (z)
#define DOORKEEPERDEBUG_PRINTLN(z)  Serial.println (z)
#else
#define DOORKEEPERDEBUG_HEXPRINT(x,y)
#define DOORKEEPERDEBUG_HEXPRINTBYTE(x)
#define DOORKEEPERDEBUG_WRITE(x,y)
#define DOORKEEPERDEBUG_PRINT(x)
#define DOORKEEPERDEBUG_PRINTLN(z)
#endif

struct timestruct {
	int tm_sec; /* seconds,          range 0 to 59  */
	int tm_min; /* minutes,          range 0 to 59  */
	int tm_hour; /* hours,            range 0 to 23  */
	int tm_mday; /* day of the month, range 1 to 31  */
	int tm_mon; /* month,            range 0 to 11  */
	int tm_year; /* number of years   since 1900     */
	int tm_wday; /* day of the week,  range 0 to 6   */ //sunday = 0
	int tm_yday; /* day in the year,  range 0 to 365 */
	int tm_isdst;/* daylight saving time             */ //no=0, yes>0
};

enum RelaisStatus
	: uint8_t {
		OPEN = 0x01, CLOSE = 0x02
};

enum MesType
	:uint8_t
	{
		STARTSESSIONREQUEST = 0x10,
	STARTSESSIONRESPONSE = 0x20,
	FIRMWAREREQUEST = 0x01,
	FIRMWARERESPONSE = 0x02,
	STATUSREQUEST = 0x03,
	STATUSRESPONSE = 0x04,
	RELAISREQUEST = 0x05,
	ADDKEYREQUEST = 0x06,
	ADDKEYRESPONSE = 0x07,
	REMOVEKEYREQUEST = 0x08,
	REMOVEKEYRESPONSE = 0x09

};
typedef uint8_t MessageType;

struct StartSessionRequest {
	uint8_t sessionClientPubKey[KEYSIZE];
	uint8_t signature[SIGNATURESIZE];
	uint8_t clientPubKey[KEYSIZE];

};

struct StartSessionResponse {
	uint8_t sessionServerPubKey[KEYSIZE];
	uint8_t sessionIV[IVSIZE];
	uint8_t signature[SIGNATURESIZE];
};

struct FirmwareResponse {
	uint8_t major;
	uint8_t minor;
	uint8_t build;
};

struct StatusRequest {
	uint8_t relaisnr;
};

struct StatusResponse {
	uint8_t relaisnr;
	uint8_t relaisstate;
};

struct RelaisRequest {
	uint8_t relaisnumber;
	uint8_t relaisstate;
	uint8_t duration_s;
};

struct AddKeyRequest {
	uint8_t clientPubKey[KEYSIZE];
	uint8_t validFromYear;
	uint8_t validFromMonth;
	uint8_t validFromDay;
	uint8_t validtoYear;
	uint8_t validtoMonth;
	uint8_t validtoDay;
};

struct AddKeyResponse {
	uint8_t status_;
};

struct RemoveKeyRequest {
	uint8_t clientPubKey[KEYSIZE];
};

struct RemoveKeyResponse {
	uint8_t status_;
};

struct CustomRequest {
	uint8_t data[];
};

union MessageData {
	StartSessionRequest startSessionRequest;
	StartSessionResponse startSessionResponse;
	FirmwareResponse firmwareResponse;
	StatusRequest statusRequest;
	StatusResponse statusResponse;
	RelaisRequest relaisRequest;
	AddKeyRequest addKeyRequest;
	AddKeyResponse addKeyResponse;
	RemoveKeyRequest removeKeyRequest;
	RemoveKeyResponse removeKeyResponse;
	CustomRequest custom;
};

struct MessagePayload {
	MessageData data;
	uint32_t checksum;
};

struct __attribute__((packed)) DoorKeeperMessage {
	uint8_t headerbyte1;
	uint8_t headerbyte2;
	uint8_t messagetype;
	uint8_t reserved;
	MessagePayload message;
};

const uint32_t DoorKeeperMessageSize = sizeof(DoorKeeperMessage);

#define MAXUSERS 10
struct User {
	uint8_t userPubKey[KEYSIZE];
	uint8_t validFromYear;
	uint8_t validFromMonth;
	uint8_t validFromDay;
	uint8_t validToYear;
	uint8_t validToMonth;
	uint8_t validToDay;
};
struct Users {
	User users[MAXUSERS];
	int modified;
};

struct DoorKeeperSession {
	char name[32];
	arducryptsession cryptSession;
	int userindex = -1;
};

struct DKPin {
 byte portpin = 0xff;
 byte initstate;
 byte ON;
 byte OFF;
};

#define MAXRELAISNR 4


struct DoorKeeperConfig {
	arducryptkeypair* serverkeys;
	boolean saveDB = false;
	DKPin pins[MAXRELAISNR];
};

class DoorKeeper {

public:
	void initKeeper(DoorKeeperConfig* config);
	void initTime(timestruct* time);

	boolean handleMessage(DoorKeeperMessage* doorkeeperBufferIn,
			DoorKeeperMessage* doorkeeperBufferOut, DoorKeeperSession* session);

	void addDefaultHandler(
			boolean (*usercallback)(uint8_t, uint8_t, MessagePayload*,
					DoorKeeperMessage*));

	void addUser(User* u);
	User* getUser(int index);

// called from a cyclic timer
	void CB1000ms(ulong time);
// called from loop
	void checkTimer();
// called from loop
	void doorkeeperLoop();

private:

	boolean isStarted(DoorKeeperSession* session);
	void endSession(DoorKeeperSession* session);
	void addChecksum(uint8_t* message, uint32_t* chksum);
	boolean verifyChecksum(uint8_t* message, uint32_t chksum);
	boolean decrypt_data(MessagePayload* doorkeeperplain,
			MessagePayload* doorkeepercrypted, DoorKeeperSession* session);
	boolean encrypt_data(MessagePayload* doorkeeperplain,
			MessagePayload* doorkeepercrypted, DoorKeeperSession* session);
	boolean isMessageEncrypted(DoorKeeperMessage* doorkeeperBufferIn);
	void clearBuffer(MessagePayload* body, int size);
	boolean defaultCallback(uint8_t messagetype, uint8_t reservedbyte,
			MessagePayload* databuffer, DoorKeeperMessage* doorkeeperBufferOut);
	int getFreeUser();
	boolean handleRemoveKeyRequest(RemoveKeyRequest keyrequest);
	boolean handleStatusRequest(MessagePayload* statusRequest);
	boolean handleAddKeyRequest(AddKeyRequest keyrequest);
	void getFirmware(MessagePayload* body);
	void switchRelais(RelaisRequest relaisRequest);
	uint8_t getRelaisState(byte nr);
	void setRelais(byte nr, boolean on);
	void setMessageType(DoorKeeperMessage* bufferOut, MesType type);
	boolean isAuthenticated(StartSessionRequest request,
			DoorKeeperSession* session);
	int findUser(uint8_t* userkey);
	boolean fromDateValid(int userindex, uint8_t actYear, uint8_t actMonth,
			uint8_t actDay);
	boolean toDateValid(int userindex, uint8_t actYear, uint8_t actMonth,
			uint8_t actDay);
	boolean checkValidation(int userindex);
	boolean isValidUser(StartSessionRequest request, DoorKeeperSession* session);
	boolean isAdminSession(DoorKeeperSession* session);
	boolean isAdminUser(int index);
	boolean isSignatureValid(StartSessionRequest request);
	void setHeader(DoorKeeperMessage* doorkeeperBuffer);
	void loadUser(User* user, int userIndex);
	void storeUser(User* user, int userIndex);
	void storeUserIndex(int index);
	void loadUserDb();
	void initUserDb();
	void dumpUserDb();
	void eraseDB();
	struct TimerObj {
		uint8_t duration;
		byte relaisNr;
		boolean state;
		void (DoorKeeper::*timercallback)(byte, boolean) = NULL;
	};
	TimerObj timeObj;

	DoorKeeperConfig* config;
	Users userDb;
	ulong act_ms = 0;

};
#endif
