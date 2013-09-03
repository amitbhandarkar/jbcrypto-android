jbcrypto-android
================

Encryption on Android

Performs Rijndael-256 encryption/decryption and AES-128 compatible with OpenSSL for Ruby

AES-128 compatible with OpenSSL for Ruby
----------------------------------------
Outputs base64 for encryption and takes in base64 string for decryption

To use in your own project:
1. Copy SPRubyCrypto

Usage:

For encryption:
String encrypt(String seed, String cleartext)

For decryption:
String decrypt(String seed, String encrypted)

Rijndael-256 encryption/decryption (SPRijndaelCrypto)
---------------------------------------
Outputs hex for encryption and takes in hex string for decryption

To use in your own project:
0. Copy and setup the ff. libraries to your project: sc-light-jdk15on-1.47.0.2.jar, scprov-jdk15on-1.47.0.2.jar.
1. Copy SPRijndaelCrypto to your project

Usage:

For encryption:
String encrypt(String seed, String cleartext)

For decryption:
String decrypt(String seed, String encrypted)
