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


#include <DoorKeeper.h>
#include <pins_arduino.h>
#include <stddef.h>
#include <cstring>
#include <EEPROM.h>


boolean isAuthenticated(StartSessionRequest request,
		DoorKeeperSession* session);

void setMessageType(DoorKeeperMessage* bufferOut, MesType type);
boolean isValidUser(StartSessionRequest request, DoorKeeperSession* session);
boolean isSignatureValid(StartSessionRequest request);
boolean isAdminUser(int userindex);
boolean isAdminSession(DoorKeeperSession* session);
void switchRelais(RelaisRequest relaisRequest);

void setHeader(DoorKeeperMessage* doorkeeperBuffer);

void getFirmware(MessagePayload* body);
void setRelais(byte nr, boolean on);
uint8_t getRelaisState(byte nr);
boolean handleAddKeyRequest(AddKeyRequest keyrequest);
boolean handleRemoveKeyRequest(RemoveKeyRequest keyrequest);
boolean handleStatusRequest(MessagePayload* statusRequest);

boolean defaultCallback(uint8_t messagetype, uint8_t reserved, MessagePayload* databuffer, DoorKeeperMessage* doorkeeperBufferOut);

int findUser(uint8_t* userkey);
boolean checkValidation(int userindex);

void initUserDb();
void dumpUserDb();

const int PAYLOADLENGTH = sizeof(MessagePayload);
const int DATALENGTH = sizeof(MessageData);
const int HEADERLEN = sizeof(DoorKeeperMessage) - PAYLOADLENGTH;

const uint8_t MAJOR = 0x01;
const uint8_t MINOR = 0x02;
const uint8_t BUILD = 0x03;

struct TimerObj {
	uint8_t duration;
	byte relaisNr;
	boolean state;
	void (*timercallback)(byte, boolean) = NULL;
};

boolean (*defaultcallback)(uint8_t,uint8_t,MessagePayload*,DoorKeeperMessage*) = NULL;

TimerObj timeObj;

Users userDb;

timestruct* t;

ulong act_ms = 0;

arducryptkeypair* serverkeypair;

arducrypt acrypt(sizeof(MessagePayload));

boolean dbsave = false;

/**
 * \brief init with server key pair (public / private)
 * needed for signing
 */
void DoorKeeper::initKeeper(arducryptkeypair* serverkeys) {
	serverkeypair = serverkeys;
	digitalWrite(RELAIS1PIN, RELAISPININIT);
	pinMode(RELAIS1PIN, OUTPUT);
	digitalWrite(RELAIS2PIN, RELAISPININIT);
	pinMode(RELAIS2PIN, OUTPUT);

	digitalWrite(RCOPENPIN, RCPININIT);
	pinMode(RCOPENPIN, OUTPUT);
	digitalWrite(RCCLOSEPIN, RCPININIT);
	pinMode(RCCLOSEPIN, OUTPUT);
	initUserDb();
}

void DoorKeeper::initTime(timestruct* time) {
	t = time;
	DOORKEEPERDEBUG_PRINT(F("date: "));
	DOORKEEPERDEBUG_PRINT(t->tm_mday);
	DOORKEEPERDEBUG_PRINT(F("."));
	DOORKEEPERDEBUG_PRINT((t->tm_mon + 1));
	DOORKEEPERDEBUG_PRINT(F("."));DOORKEEPERDEBUG_PRINTLN(t->tm_year);
}
void setDBSave(boolean save) {
	dbsave = save;
}

void DoorKeeper::CB1000ms(ulong time) {
	act_ms = time;

	if (timeObj.timercallback != NULL) {
		timeObj.duration -= 0x01;
	}
}

void DoorKeeper::checkTimer() {
	if (timeObj.timercallback != NULL && timeObj.duration == 0x00) {
		(*timeObj.timercallback)(timeObj.relaisNr, timeObj.state);
		timeObj.timercallback = NULL;
	}
}


/**
 * \brief add a default handler (will be called when a 'non standard' message was received.
 * callback is responsible for setting correct 'type' in output buffer.
 * if response should be send, the fuction has to return 'true' - 'false' otherwise.
 */
void DoorKeeper::addDefaultHandler(boolean (*defaulthandler)(uint8_t,uint8_t,MessagePayload*,DoorKeeperMessage*)) {
	defaultcallback = defaulthandler;
}

boolean isStarted(DoorKeeperSession* session) {
	return (session->userindex != INVALIDINDEX);
}

void endSession(DoorKeeperSession* session) {
	session->userindex = INVALIDINDEX;
	session->cryptSession.decrypt.clear();
	session->cryptSession.encrypt.clear();
}

void addChecksum(uint8_t* message, uint32_t* chksum) {
	*chksum = acrypt.calcChecksum((uint8_t *) message,
			DATALENGTH);
}

boolean verifyChecksum(uint8_t* message, uint32_t chksum) {
	DOORKEEPERDEBUG_PRINT(F("checksum: "));
	DOORKEEPERDEBUG_HEXPRINT((uint8_t* )message, CHECKSUMSIZE);
	DOORKEEPERDEBUG_PRINTLN();

	uint32_t chk = acrypt.calcChecksum((uint8_t *) message,
			DATALENGTH);
	DOORKEEPERDEBUG_PRINT(F("calculated checksum: "));
	DOORKEEPERDEBUG_HEXPRINT((uint8_t* )&chk, CHECKSUMSIZE);
	DOORKEEPERDEBUG_PRINTLN();
	if (chk == chksum) {
		return true;
	}
	return false;
}

boolean decrypt_data(MessagePayload* doorkeeperplain,
		MessagePayload* doorkeepercrypted, DoorKeeperSession* session) {
	DOORKEEPERDEBUG_PRINT(F("crypted: "));
	DOORKEEPERDEBUG_HEXPRINT((uint8_t* )doorkeepercrypted, PAYLOADLENGTH);
	// decrypt if session is started ;)
	if (isStarted(session) == true) {
		acrypt.decrypt((uint8_t*)doorkeeperplain, (uint8_t*)doorkeepercrypted,&session->cryptSession);
		return verifyChecksum((uint8_t*)doorkeeperplain, doorkeeperplain->checksum);
	} else {
		DOORKEEPERDEBUG_PRINT(F("session not started"));
		return false;
	}
}

boolean encrypt_data(MessagePayload* doorkeeperplain,
		MessagePayload* doorkeepercrypted, DoorKeeperSession* session) {
	DOORKEEPERDEBUG_PRINT(F("plain: "));
	DOORKEEPERDEBUG_HEXPRINT((uint8_t* )doorkeeperplain, PAYLOADLENGTH);
	// decrypt if session is started ;)
	if (isStarted(session) == true) {
		addChecksum((uint8_t*)doorkeeperplain, &doorkeeperplain->checksum);
		acrypt.encrypt((uint8_t*)doorkeeperplain, (uint8_t*)doorkeepercrypted,&session->cryptSession);
		return true;
	} else {
		DOORKEEPERDEBUG_PRINT(F("session not started"));
		return false;
	}
}

boolean isMessageEncrypted(DoorKeeperMessage* doorkeeperBufferIn) {

	if (doorkeeperBufferIn->messagetype!=MesType::STARTSESSIONREQUEST) {
		return true;
	}
	return false;
}

void clearBuffer(MessagePayload* body, int size) {
	memset(body, 0, size);
}

boolean DoorKeeper::handleMessage(DoorKeeperMessage* doorkeeperBufferIn,
		DoorKeeperMessage* doorkeeperBufferOut, DoorKeeperSession* session) {
	DOORKEEPERDEBUG_PRINT(F("handleMessage:"));
	DOORKEEPERDEBUG_HEXPRINT((uint8_t* )doorkeeperBufferIn, sizeof(DoorKeeperMessage));
	MessagePayload databuffer;

	// if encyrpted ... decrypt
	if (isMessageEncrypted(doorkeeperBufferIn) == true) {
		DOORKEEPERDEBUG_PRINT(F("encrypted data: "));
		DOORKEEPERDEBUG_HEXPRINT((uint8_t* )&(doorkeeperBufferIn->message),
				PAYLOADLENGTH);
		if(decrypt_data(&databuffer, &(doorkeeperBufferIn->message), session)==true) {
		DOORKEEPERDEBUG_PRINT(F("unencrypted data: "));
		DOORKEEPERDEBUG_HEXPRINT((uint8_t* )&databuffer, PAYLOADLENGTH);
		} else {
			DOORKEEPERDEBUG_PRINT(F("unencrypted data: checksum error!"));
			return false;
		}

	} else {
		// copy to buffer
		memcpy(&databuffer, &doorkeeperBufferIn->message, PAYLOADLENGTH);
		DOORKEEPERDEBUG_PRINT(F("copied data: "));
		DOORKEEPERDEBUG_HEXPRINT((uint8_t* )&databuffer, PAYLOADLENGTH);
		// chsum
		if (verifyChecksum((uint8_t*)&databuffer,databuffer.checksum) == false) {
			DOORKEEPERDEBUG_PRINTLN(F("checksum error!"));
			return false;
		}
	}

	switch (doorkeeperBufferIn->messagetype) {

	case MesType::STARTSESSIONREQUEST:

		//
		DOORKEEPERDEBUG_PRINT(F("STARTSESSIONREQUEST:"));
		DOORKEEPERDEBUG_HEXPRINT((uint8_t* )&databuffer.data,
				sizeof(StartSessionRequest));
		DOORKEEPERDEBUG_PRINT(F("userpublickey:"));
		DOORKEEPERDEBUG_HEXPRINT(
				(uint8_t* )databuffer.data.startSessionRequest.clientPubKey,
				KEYSIZE);
		DOORKEEPERDEBUG_PRINT(F("sessionpublickey:"));
		DOORKEEPERDEBUG_HEXPRINT(
				(uint8_t* )databuffer.data.startSessionRequest.sessionClientPubKey,
				KEYSIZE);
		DOORKEEPERDEBUG_PRINT(F("signature:"));
		DOORKEEPERDEBUG_HEXPRINT((uint8_t* )databuffer.data.startSessionRequest.signature,
				SIGNATURESIZE);

		if (isAuthenticated(databuffer.data.startSessionRequest,
				session) == true) {
			if(acrypt.generateSession(&session->cryptSession,
			(arducryptkey*) databuffer.data.startSessionRequest.sessionClientPubKey)==true) {
				memcpy(
						doorkeeperBufferOut->message.data.startSessionResponse.sessionServerPubKey,
						session->cryptSession.publicKey, KEYSIZE);
				memcpy(
						doorkeeperBufferOut->message.data.startSessionResponse.sessionIV,
						session->cryptSession.iv, IVSIZE);
				acrypt.sign((arducryptkeypair*)serverkeypair,(uint8_t*)&doorkeeperBufferOut->message.data.startSessionResponse.sessionServerPubKey, (arducryptsignature*)&doorkeeperBufferOut->message.data.startSessionResponse.signature, KEYSIZE+IVSIZE);

// checksum
				addChecksum((uint8_t*)&doorkeeperBufferOut->message, &doorkeeperBufferOut->message.checksum);
				setMessageType(doorkeeperBufferOut,
						MesType::STARTSESSIONRESPONSE);
				return true;
			}

		} else {

		}
		break;

	case MesType::RELAISREQUEST:
		switchRelais(databuffer.data.relaisRequest);
		// do a encryption to keep counter sync!
//		encrypt_data(&databuffer, &doorkeeperBufferOut->message, session);
		return false;
		break;
	case MesType::FIRMWAREREQUEST:
		clearBuffer(&databuffer, PAYLOADLENGTH);
		getFirmware(&databuffer);
//		addChecksum(&databuffer);
		encrypt_data(&databuffer, &doorkeeperBufferOut->message, session);
		setMessageType(doorkeeperBufferOut, MesType::FIRMWARERESPONSE);
		return true;
		break;
	case MesType::ADDKEYREQUEST:
		if (isAdminSession(session) != true) {
			return false;
		}
		if (handleAddKeyRequest(databuffer.data.addKeyRequest) == true) {
			clearBuffer(&databuffer, PAYLOADLENGTH);
			databuffer.data.addKeyResponse.status_ = 0x01;
//			addChecksum(&databuffer);
			encrypt_data(&databuffer, &doorkeeperBufferOut->message, session);
			setMessageType(doorkeeperBufferOut, MesType::ADDKEYRESPONSE);

			return true;
		}
		return false;
		break;
	case MesType::REMOVEKEYREQUEST:
		if (isAdminSession(session) != true) {
			return false;
		}
		if (handleRemoveKeyRequest(databuffer.data.removeKeyRequest) == true) {
			clearBuffer(&databuffer, PAYLOADLENGTH);
			databuffer.data.removeKeyResponse.status_ = 0x01;
//			addChecksum(&databuffer);
			encrypt_data(&databuffer, &doorkeeperBufferOut->message, session);
			setMessageType(doorkeeperBufferOut, MesType::REMOVEKEYRESPONSE);
			return true;
		}
		return false;
		break;
	case MesType::STATUSREQUEST:
		if (handleStatusRequest(&databuffer) == true) {
//			addChecksum(&databuffer);
			encrypt_data(&databuffer, &doorkeeperBufferOut->message, session);
			setMessageType(doorkeeperBufferOut, MesType::STATUSRESPONSE);
			return true;
		}
		return false;
		break;
	default:
		DOORKEEPERDEBUG_PRINTLN(F("unknown messagetype!"));
		// callback
		if(defaultCallback(doorkeeperBufferIn->messagetype,doorkeeperBufferIn->reserved,&databuffer,doorkeeperBufferOut) == true) {
			encrypt_data(&databuffer, &doorkeeperBufferOut->message, session);
			// message type has to be set by callback
			return true;
		}
		break;
	}

	// defaultaddKeyTest
	return false;
}

boolean defaultCallback(uint8_t messagetype, uint8_t reservedbyte, MessagePayload* databuffer, DoorKeeperMessage* doorkeeperBufferOut){
	if(defaultcallback==NULL) {
		return false;
	}
	// callback
	return (*defaultcallback)(messagetype,reservedbyte,databuffer,doorkeeperBufferOut);
}

int getFreeUser() {
	for (int index = 0; index < MAXUSERS; index++) {
		if (userDb.users[index].validToDay == 0xff
				&& userDb.users[index].validToDay == 0xff
				&& userDb.users[index].validToDay == 0xff) {
			DOORKEEPERDEBUG_PRINT(F("free user entry found: "));
			DOORKEEPERDEBUG_PRINTLN(index);
			return index;
		}
	}
	return INVALIDINDEX;
}

boolean handleRemoveKeyRequest(RemoveKeyRequest keyrequest) {
	DOORKEEPERDEBUG_PRINTLN(F("handle remove key"));
	int userindex = findUser(keyrequest.clientPubKey);
	if (userindex == INVALIDINDEX) {
		return false;
	}
	memset(&userDb.users[userindex], 0xff, KEYSIZE);
	userDb.users[userindex].validFromDay = 0xff;
	userDb.users[userindex].validFromMonth = 0xff;
	userDb.users[userindex].validFromYear = 0xff;
	userDb.users[userindex].validToDay = 0xff;
	userDb.users[userindex].validToMonth = 0xff;
	userDb.users[userindex].validToYear = 0xff;
	userDb.modified = userindex;
	return true;
}

boolean handleStatusRequest(MessagePayload* statusRequest) {
	DOORKEEPERDEBUG_PRINTLN(F("handleStatusRequest"));
	uint8_t relais = statusRequest->data.statusRequest.relaisnr;
	//check status
	statusRequest->data.statusResponse.relaisstate = getRelaisState(relais);
	return true;
}

boolean handleAddKeyRequest(AddKeyRequest keyrequest) {
	DOORKEEPERDEBUG_PRINTLN(F("handle add key"));

	int userindex = findUser(keyrequest.clientPubKey);
	if (userindex == INVALIDINDEX) {
		// add new key
		userindex = getFreeUser();
		if (userindex == INVALIDINDEX) {
			// no free space!
			return false;
		}
		DOORKEEPERDEBUG_PRINT(F("add new user "));
		DOORKEEPERDEBUG_PRINTLN(userindex);
		memcpy(&userDb.users[userindex], keyrequest.clientPubKey, KEYSIZE);
		userDb.users[userindex].validFromDay = keyrequest.validFromDay;
		userDb.users[userindex].validFromMonth = keyrequest.validFromMonth;
		userDb.users[userindex].validFromYear = keyrequest.validFromYear;
		userDb.users[userindex].validToDay = keyrequest.validtoDay;
		userDb.users[userindex].validToMonth = keyrequest.validtoMonth;
		userDb.users[userindex].validToYear = keyrequest.validtoYear;
		userDb.modified = userindex;
		return true;
	} else {
		// update existing
		DOORKEEPERDEBUG_PRINT(F("updating user "));
		DOORKEEPERDEBUG_PRINTLN(userindex);
		userDb.users[userindex].validFromDay = keyrequest.validFromDay;
		userDb.users[userindex].validFromMonth = keyrequest.validFromMonth;
		userDb.users[userindex].validFromYear = keyrequest.validFromYear;
		userDb.users[userindex].validToDay = keyrequest.validtoDay;
		userDb.users[userindex].validToMonth = keyrequest.validtoMonth;
		userDb.users[userindex].validToYear = keyrequest.validtoYear;
		userDb.modified = userindex;
		return true;
	}
	return false;
}

void getFirmware(MessagePayload* body) {
	body->data.firmwareResponse.major = MAJOR;
	body->data.firmwareResponse.minor = MINOR;
	body->data.firmwareResponse.build = BUILD;
}

void switchRelais(RelaisRequest relaisRequest) {
	DOORKEEPERDEBUG_PRINT(F("switchRelais: nr="));
	DOORKEEPERDEBUG_HEXPRINTBYTE(relaisRequest.relaisnumber);
	DOORKEEPERDEBUG_PRINT(F(" , state="));
	DOORKEEPERDEBUG_HEXPRINTBYTE(relaisRequest.relaisstate);
	DOORKEEPERDEBUG_PRINT(F(" , duration="));
	DOORKEEPERDEBUG_HEXPRINTBYTE(relaisRequest.duration_s);
	DOORKEEPERDEBUG_PRINTLN();
	if (timeObj.timercallback != NULL) {
		DOORKEEPERDEBUG_PRINTLN(F("timer active!"));
		return;
	}
	// switch ...
	if (relaisRequest.relaisstate == RelaisStatus::OPEN
			|| relaisRequest.relaisstate == RelaisStatus::CLOSE) {
		boolean on = false;
		if (relaisRequest.relaisstate == RelaisStatus::CLOSE) {
			on = true;
		}
		setRelais(relaisRequest.relaisnumber, on);
		if (relaisRequest.duration_s != 0x00) {
			DOORKEEPERDEBUG_PRINTLN(F("activating timer"));
			// set timer
			timeObj.duration = relaisRequest.duration_s;
			timeObj.relaisNr = relaisRequest.relaisnumber;
			timeObj.state = !on;
			timeObj.timercallback = &setRelais;
		}
	}

}

uint8_t getRelaisState(byte nr) {
	DOORKEEPERDEBUG_PRINT(F("getRelais "));
	DOORKEEPERDEBUG_PRINT(nr);
	byte relstatus = 0x00;
	switch (nr) {

	case 0x01:
		//D6
		if (digitalRead(RELAIS1PIN) == LOW) {
			relstatus =  CLOSE;
		} else {
			relstatus =  OPEN;
		}
		break;
	case 0x02:
		// D7
		if (digitalRead(RELAIS2PIN) == LOW) {
			relstatus =  CLOSE;
		} else {
			relstatus =  OPEN;
		}
		break;
	case 0x03:
		// D5
		if (digitalRead(RCCLOSEPIN) == HIGH) {
			relstatus =  CLOSE;
		} else {
			relstatus =  OPEN;
		}
		break;
	case 0x04:
		// D4
		if (digitalRead(RCOPENPIN) == HIGH) {
			relstatus =  CLOSE;
		} else {
			relstatus =  OPEN;
		}
		break;
	default:
		DOORKEEPERDEBUG_PRINTLN(F("unknown relais nr"));
		break;
	}

	if(relstatus==CLOSE) {
		DOORKEEPERDEBUG_PRINTLN(F(" on"));
	} else {
		DOORKEEPERDEBUG_PRINTLN(F(" off"));
	}
	return relstatus;
}

void setRelais(byte nr, boolean on) {
	DOORKEEPERDEBUG_PRINT(F("setRelais "));
	DOORKEEPERDEBUG_PRINT(nr);
	if(on) {
		DOORKEEPERDEBUG_PRINTLN(F(" on"));
	} else {
		DOORKEEPERDEBUG_PRINTLN(F(" off"));
	}
	switch (nr) {

	case 0x01:
		//D6
		digitalWrite(RELAIS1PIN, on == true ? LOW : HIGH);
		break;
	case 0x02:
		// D7
		digitalWrite(RELAIS2PIN, on == true ? LOW : HIGH);

		break;
	case 0x03:
		// D5
		digitalWrite(RCCLOSEPIN, on == true ? HIGH : LOW);

		break;
	case 0x04:
		// D4
		digitalWrite(RCOPENPIN, on == true ? HIGH : LOW);

		break;
	default:
		DOORKEEPERDEBUG_PRINTLN(F("unknown relais nr"));
		break;
	}
}

void setMessageType(DoorKeeperMessage* bufferOut, MesType type) {
	bufferOut->messagetype = type;
}

boolean isAuthenticated(StartSessionRequest request,
		DoorKeeperSession* session) {
	if (isValidUser(request, session) == true) {
		DOORKEEPERDEBUG_PRINTLN(F("user valid!"));
		if (isSignatureValid(request) == true) {
			DOORKEEPERDEBUG_PRINTLN(F("signature valid!"));
			return true;
		} else {
			DOORKEEPERDEBUG_PRINT(F("signature invalid!"));
		}
	} else {
		DOORKEEPERDEBUG_PRINT(F("no valid user!"));
	}
	return false;
}

int findUser(uint8_t* userkey) {
	for (int index = 0; index < MAXUSERS; index++) {
		if (memcmp(userDb.users[index].userPubKey, userkey,
		KEYSIZE) == 0) {
			return index;
		}
	}
	return INVALIDINDEX;
}

boolean fromDateValid(int userindex, uint8_t actYear, uint8_t actMonth,
		uint8_t actDay) {
	DOORKEEPERDEBUG_PRINT(F("valid from y/m/d "));
	DOORKEEPERDEBUG_PRINT(userDb.users[userindex].validFromYear);
	DOORKEEPERDEBUG_PRINT(F("/"));
	DOORKEEPERDEBUG_PRINT(userDb.users[userindex].validFromMonth);
	DOORKEEPERDEBUG_PRINT(F("/"));
	DOORKEEPERDEBUG_PRINTLN(userDb.users[userindex].validFromDay);
	if ((userDb.users[userindex].validFromYear == 0xff)
			&& (userDb.users[userindex].validFromMonth == 0xff)
			&& (userDb.users[userindex].validFromDay == 0xff)) {
		// valid from now ;)
		return true;
	} else if ((userDb.users[userindex].validFromYear < actYear)
			|| ((userDb.users[userindex].validFromYear == actYear)
					&& (userDb.users[userindex].validFromMonth < actMonth))
			|| ((userDb.users[userindex].validFromYear == actYear)
					&& (userDb.users[userindex].validFromMonth == actMonth)
					&& (userDb.users[userindex].validFromDay <= actDay))) {
		return true;
	}
	return false;
}

boolean toDateValid(int userindex, uint8_t actYear, uint8_t actMonth,
		uint8_t actDay) {
	DOORKEEPERDEBUG_PRINT(F("valid till y/m/d "));
	DOORKEEPERDEBUG_PRINT(userDb.users[userindex].validToYear);
	DOORKEEPERDEBUG_PRINT(F("/"));
	DOORKEEPERDEBUG_PRINT(userDb.users[userindex].validToMonth);
	DOORKEEPERDEBUG_PRINT(F("/"));
	DOORKEEPERDEBUG_PRINTLN(userDb.users[userindex].validToDay);
	if ((userDb.users[userindex].validToYear > actYear)
			|| ((userDb.users[userindex].validToYear == actYear)
					&& (userDb.users[userindex].validToMonth > actMonth))
			|| ((userDb.users[userindex].validToYear == actYear)
					&& (userDb.users[userindex].validToMonth == actMonth)
					&& (userDb.users[userindex].validToDay >= actDay))) {
		return true;
	}
	return false;
}

boolean checkValidation(int userindex) {
	// is this true ??
	uint8_t year = t->tm_year - 2000;
	// is 0 .. 11
	uint8_t month = t->tm_mon + 1;
	uint8_t day = t->tm_mday;
	DOORKEEPERDEBUG_PRINT(F("act date y/m/d "));
	DOORKEEPERDEBUG_PRINT(year);
	DOORKEEPERDEBUG_PRINT(F("/"));
	DOORKEEPERDEBUG_PRINT(month);
	DOORKEEPERDEBUG_PRINT(F("/"));
	DOORKEEPERDEBUG_PRINTLN(day);

	if ((fromDateValid(userindex, year, month, day) == true)
			&& (toDateValid(userindex, year, month, day))) {
		return true;
	}
	return false;
}

boolean isValidUser(StartSessionRequest request, DoorKeeperSession* session) {
	int userindex = findUser(request.clientPubKey);
	if (userindex == INVALIDINDEX) {
		return false;
	}
	if (checkValidation(userindex) == true) {
		session->userindex = userindex;
		return true;
	} else {
		DOORKEEPERDEBUG_PRINTLN(F("Userkey expired!"));
		session->userindex = INVALIDINDEX;
	}
	return false;
}

boolean isAdminSession(DoorKeeperSession* session) {
	return isAdminUser(session->userindex);
}

boolean isAdminUser(int index) {
	if ((userDb.users[index].validToYear == 0xee)
			&& (userDb.users[index].validToMonth == 0xee)
			&& (userDb.users[index].validToDay == 0xee)) {
		DOORKEEPERDEBUG_PRINTLN(F("user is admin!"));
		return true;
	}
	DOORKEEPERDEBUG_PRINTLN(F("user is NO admin!"));
	return false;
}

boolean isSignatureValid(StartSessionRequest request) {
	bool verified = acrypt.validateSignature((arducryptsignature*) &request.signature,
			(uint8_t*)&request.sessionClientPubKey, KEYSIZE,
			(arducryptkey*) &request.clientPubKey);

	return verified;
}


void setHeader(DoorKeeperMessage* doorkeeperBuffer) {
	doorkeeperBuffer->headerbyte1 = 0x23;
	doorkeeperBuffer->headerbyte2 = 0x42;
}

void loadUser(User* user, int userIndex) {
	if (userIndex < 0 || userIndex >= MAXUSERS) {
		return;
	}
	int address = sizeof(User);
	address *= userIndex;
	uint8_t* userPtr = (uint8_t*) user;
	for (unsigned int i = 0; i < sizeof(User); i++) {
		*userPtr = EEPROM.read(address + i);
		userPtr++;
	}
	DOORKEEPERDEBUG_PRINT(F("load user: "));
	DOORKEEPERDEBUG_HEXPRINT((uint8_t* )user, sizeof(User));
}

void storeUser(User* user, int userIndex) {
	if (userIndex < 0 || userIndex >= MAXUSERS) {
		DOORKEEPERDEBUG_PRINT(F("invalid index: "));
		DOORKEEPERDEBUG_PRINTLN(userIndex);
		return;
	}
	EEPROM.begin(DBSIZE);
	int address = sizeof(User);
	address *= userIndex;
	uint8_t* userPtr = (uint8_t*) user;
	for (unsigned int i = 0; i < sizeof(User); i++) {
		EEPROM.write(address + i, *userPtr);
		userPtr++;
	}
	EEPROM.end();
	DOORKEEPERDEBUG_PRINT(F("store user: "));
	DOORKEEPERDEBUG_HEXPRINT((uint8_t* )user, sizeof(User));
}

void storeUserIndex(int index) {
	storeUser(&userDb.users[index], index);
}

void loadUserDb() {
	for (int i = 0; i < MAXUSERS; i++) {
		loadUser(&userDb.users[i], i);
	}
	userDb.modified = INVALIDINDEX;
}

void initUserDb() {
	EEPROM.begin(DBSIZE);
	loadUserDb();
	EEPROM.end();
}

void dumpUserDb() {
	DOORKEEPERDEBUG_PRINT(F("userdb: "));
	int x = sizeof(User) * MAXUSERS;
	DOORKEEPERDEBUG_HEXPRINT((uint8_t * )&userDb, x);

}

void eraseDB() {
	DOORKEEPERDEBUG_PRINTLN(F("eraseDB!!!!!!!"));
	for (int i = 0; i < MAXUSERS; i++) {
		memset(&userDb.users[i], 0xff, sizeof(User));
		storeUser(&userDb.users[i], i);
	}
}

void DoorKeeper::doorkeeperLoop() {

	int modifiedIndex = userDb.modified;
	if (modifiedIndex != INVALIDINDEX) {
		if(dbsave==false) {
			DOORKEEPERDEBUG_PRINTLN(F("dbsave is set to false! do not store to eeprom!"));
		} else {
		DOORKEEPERDEBUG_PRINT(F("db was modified ... updating entry "));
		DOORKEEPERDEBUG_PRINTLN(modifiedIndex);
		storeUserIndex(modifiedIndex);
		}
		userDb.modified = INVALIDINDEX;
	}
}

User* DoorKeeper::getUser(int index) {
	if(index<0||index>MAXUSERS) {
		return NULL;
	}
	return &userDb.users[index];
}

void DoorKeeper::addUser(User* user) {
	DOORKEEPERDEBUG_PRINTLN(F("add user to db"));

	int index = getFreeUser();
	if(index!=INVALIDINDEX) {
		for (int i = 0; i < KEYSIZE; i++) {
			userDb.users[index].userPubKey[i] = user->userPubKey[i];
		}
		userDb.users[index].validToDay = user->validToDay;
		userDb.users[index].validToMonth = user->validToMonth;
		userDb.users[index].validToYear = user->validToYear;
	} else {
		DOORKEEPERDEBUG_PRINTLN(F("no free entry available!"));
	}

}

