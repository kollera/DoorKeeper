# Protocol

## Message

```
  +------------------------------------------------------------------------------------+
  |  header1 | header2 |  type  | reserved |                 data         |  checksum  |
  |------------------------------------------------------------------------------------|
  |  1 byte  | 1 byte  | 1 byte |   1byte  |               128 byte       |    4 byte  |
  |------------------------------------------------------------------------------------|
  |                    header              |                   Payload                 |
  +------------------------------------------------------------------------------------+
```
### Header

```
  +----------------------------------------+
  |                 header                 |
  |----------------------------------------|
  |  0x23  |  0x42  |  typebyte  |   0x00  |
  +----------------------------------------+
```

#### Type


   |  typebyte   |   message     |
   |-----------|-------------------------------|
   |  0x10   |  StartSessionRequest   |
   |  0x20   |   StartSessionResponse   |
   |  0x01   |   FirmwareRequest   |
   |  0x02   |   FirmwareResponse   |
   |  0x03   |   StatusRequest   |
   |  0x04   |  StatusResponse   |
   |  0x05   |   RelaisRequest   |
   |  0x06   |   AddKeyRequest   |
   |  0x07   |   AddKeyResponse    |
   |  0x08   |   RemoveKeyRequest   |
   |  0x09   |   RemoveKeyResponse    |
   
   


### Session



#### Precondition

```
+---------------------+                   +---------------------+
|        client       |                   |   server (esp8266)  |
+---------------------+                   +---------------------+
+---------+ +---------+                   +---------+ +---------+
|  public | | private |                   |  public | | private |
|   key   | |   key   |                   |   key   | |   key   |
|  client | |  client |                   |  server | |  server |
+---------+ +---------+                   +---------+ +---------+
+---------+                               +---------+
|  public |                               |  public |
|   key   |                               |   key   |
|  server |                               |  client |
+---------+                               +---------+


```



#### Sequence


Client generates a session key pair (dh1) and sends a StartSessionRequest.
To ensure data integrity a signature (with client private key) is generated for the session public key.

Server verifies signature (with client public key) and also generates a session key pair and a IV ( or nounce).
Signature is generated for session public key and IV and a StartSessionResponse is sent to the client.

Both parties generate a shared secret (dh2) and initialize a stream cipher (ChaCha20).


```
+---------------------+                   +---------------------+
|        client       |                   |   server (esp8266)  |
+---------------------+                   +---------------------+


                        startSessionRequest                          
                ----------------------------------->
       session public key, signature, user public key
                
                                           - search user in db
                                           - if existing user
                                             - verify signature with user public key
                                             - if signature valid
                                               - generate session key pair
                                               - sign session public key  & iv
                                               - generate symmetric session key


                        StartSessionResponse                          
                <-----------------------------------
             session public key, IV, signature
            
 - verify signature with server public key
 - if signature valid
   - generate symmetric session key
                      

+---------------------+                   +---------------------+
|  symmetric key      |                   |  symmetric key      |
+---------------------+                   +---------------------+

                      encrypted messages  
                <----------------------------------->                     

```


#### StartSessionRequest

```
+----------------------------------------------------------------------------------------------------------+
|0x23|0x42|0x10|0x00|session_public_key (32 byte) |signature (64 byte) |user_public_key (32 byte) |checksum|
+----------------------------------------------------------------------------------------------------------+
```
#### StartSessionResponse

```
+----------------------------------------------------------------------------------------------------------+
|0x23|0x42|0x20|0x00|session_public_key (32 byte) | iv (nounce) (8 byte) |  signature (64 byte)   |checksum|
+----------------------------------------------------------------------------------------------------------+
```


### Firmware

#### FirmwareRequest

```
+----------------------------------------------------------------------------------------------------------+
|0x23|0x42|0x01|0x00|                                                                             |checksum|
+----------------------------------------------------------------------------------------------------------+
```
#### FirmwareResponse

```
+----------------------------------------------------------------------------------------------------------+
|0x23|0x42|0x02|0x00| major (1 byte) | minor (8 byte) |  build (1 byte)                           |checksum|
+----------------------------------------------------------------------------------------------------------+
```

### Status

#### StatusRequest

```
+----------------------------------------------------------------------------------------------------------+
|0x23|0x42|0x03|0x00| relaisnr (1 byte) |                                                         |checksum|
+----------------------------------------------------------------------------------------------------------+
```
#### StatusResponse

```
+----------------------------------------------------------------------------------------------------------+
|0x23|0x42|0x04|0x00| relaisnr (1 byte) | state (1 byte) |                                       |checksum|
+----------------------------------------------------------------------------------------------------------+
```
   |  state byte   |   state     |
   |-----------|-------------------------------|
   | 0x01  | open |
   | 0x02  | closed |

### Relais

#### RelaisRequest

```
+----------------------------------------------------------------------------------------------------------+
|0x23|0x42|0x05|0x00| relaisnr (1 byte) | state (1 byte) | duration sec (1 byte)                  |checksum|
+----------------------------------------------------------------------------------------------------------+
```
   | state byte   |   state     |
   |-----------|-------------------------------|
   | 0x01  | open |
   | 0x02  | closed |

### Keys

#### AddKeyRequest

```
+----------------------------------------------------------------------------------------------------------+
|    |    |    |    |   client  |   valid  |   valid  |  valid  |   valid  |  valid   |valid      |        |
|0x23|0x42|0x06|0x00|    key    | FromYear | FromMonth| FromDay |  toYear  | toMonth  |  toDay    |checksum|
|    |    |    |    | (byte 32) | (1 byte) | (1 byte) |(1 byte) | (1 byte) | (1 byte) | (1 byte)  |        |
+----------------------------------------------------------------------------------------------------------+
```
#### AddKeyResponse

```
+----------------------------------------------------------------------------------------------------------+
|0x23|0x42|0x07|0x00| state (1 byte) |                                                           |checksum|
+----------------------------------------------------------------------------------------------------------+
```

   |  state byte   |   state     |
   |-----------|-------------------------------|
   | 0x00  | OK |
   | 0x01  | ERROR |

#### RemoveKeyRequest

```
+----------------------------------------------------------------------------------------------------------+
|0x23|0x42|0x08|0x00| client key (byte 32) |                                                      |checksum|
+----------------------------------------------------------------------------------------------------------+
```
#### RemoveKeyResponse

```
+----------------------------------------------------------------------------------------------------------+
|0x23|0x42|0x09|0x00| state (1 byte) |                                                           |checksum|
+----------------------------------------------------------------------------------------------------------+
```

   |  state byte   |   state     |
   |-----------|-------------------------------|
   | 0x00  | OK |
   | 0x01  | ERROR |

