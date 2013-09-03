jbcrypto-android
================

Encryption on Android

To use in your own project:
0. Copy and setup the ff. libraries to your project: sc-light-jdk15on-1.47.0.2.jar, scprov-jdk15on-1.47.0.2.jar.
1. Copy SPCrypto.java to your project

Usage:

For encryption:
public static String encrypt(String seed, String cleartext) throws Exception

For decryption:
public static String decrypt(String seed, String encrypted) throws Exception