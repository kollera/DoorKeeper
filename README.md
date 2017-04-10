# DoorKeeper

## Warning

 May contain traces of software.

## Hardware
<https://www.wemos.cc/product/d1.html><br/>
<https://en.wikipedia.org/wiki/ESP8266>

## Software
<https://github.com/esp8266/Arduino>


## Dependencies (Arduino Libraries)

### CRC32
<https://github.com/bakercp/CRC32/>

### Crypto
<https://github.com/rweather/arduinolibs/tree/master/libraries/Crypto><br/>

#### Sign & verify
Ed25519 <https://en.wikipedia.org/wiki/Ed25519><br/>
  
#### Session key
Curve25519 <https://en.wikipedia.org/wiki/Curve25519><br/>

#### Stream Cipher
ChaCha20 <https://en.wikipedia.org/wiki/ChaCha20><br/>

#### ESP8266 hacked version of Crypto libs
use internal esp8266 hardware random generator<br/>
<http://esp8266-re.foogod.com/wiki/Random_Number_Generator><br/>
<https://github.com/kollera/arduinolibs><br/>

### NTP
<https://github.com/Juppit/esp8266-SNTPClock>

## Project

### What is it all about?

An attempt to enable secure communication, authentication & authorization for my ESP8266 project.


### Some details

Take a look [here](./protocol.md)


### FAQ

#### Why dont use SSL/TLS?

When i started my project, TLS for Arduino was not available  (to be precise, it was, but not in a stable version).

#### Whats the advantage of your solution?
No idea. It's  this public - private - elliptic - curve - stream - cipher ... thing.
For details, ask the NSA!
  
#### Do you know how ECDH works?
No. But Wikipedia does.<br/>
<https://en.wikipedia.org/wiki/Elliptic_curve_Diffie%E2%80%93Hellman>
  
#### Do you know how StreamCipher works?
No. But Wikipedia does.<br/>
<https://en.wikipedia.org/wiki/Stream_cipher>

#### Your code looks kind of messy.
Yes, thats right!<br/>

#### I found a bug / I know how to improve your code.
Excellent! Please write a [mail](akandroid75@gmail.com) or use the [bugtracker]()





