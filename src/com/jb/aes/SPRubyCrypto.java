/**
 * Encrypt/Decrypt strings using AES-128
 * Uses an iv on a string of zeroes, CBC, PCKS7Padding
 * 
 * Compatible with AES-256-CBC mode with 0 padding using
 * OpenSSL on Ruby
 * 
 * @author John Bennedict Lorenzo
 */

package com.jb.aes;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.http.util.ByteArrayBuffer;

public class SPRubyCrypto {
	
	private static int AES128KeySizeInBytes = 16; 
	
	static byte[] makeKey(String seed) {
		try {
			MessageDigest md = MessageDigest.getInstance("PKCS5");
			byte[] key = md.digest(seed.getBytes("UTF-8"));
			return key;
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}

		return null;
	}

	
	public static String encrypt(String seed, String cleartext) throws Exception {
        byte[] rawKey = seed.getBytes("utf-8"); 
        
        byte[] rawText = cleartext.getBytes("utf-8");
        
        byte[] result = encrypt(rawKey, rawText);
        
        return toHex(result);
	}
	
	public static String decrypt(String seed, String encrypted) throws Exception {
	        byte[] enc = toByte(encrypted);
	        byte[] result = decrypt(getPaddedRawKey(seed), enc);
	        return new String(result);
	}
	
	/** Returns the bytes for the input keyString, makes sure it is AES128KeySizeInBytes bytes long */
	private static byte[] getPaddedRawKey(String keyString) {
		ByteArrayBuffer keyBuffer = new ByteArrayBuffer(0);
		
		int initialBufferLength = Math.min(AES128KeySizeInBytes, keyString.length());
		
		try {
			keyBuffer.append(keyString.getBytes("utf-8"), 0, initialBufferLength);
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		int paddingLength = (initialBufferLength % AES128KeySizeInBytes);
		if (paddingLength != 0)
			paddingLength = AES128KeySizeInBytes - paddingLength;
		
		if (paddingLength > 0) {
			byte[] padding = new byte[paddingLength];
			
			keyBuffer.append(padding, 0, paddingLength);			
		}
		
		return keyBuffer.toByteArray();
	}
	
	static String ivString = "0000000000000000";
	static byte[] ivBytes  = ivString.getBytes();
	private static IvParameterSpec iv = new IvParameterSpec(ivBytes);
	
	private static byte[] encrypt(byte[] raw, byte[] clear) throws Exception {
	    SecretKeySpec skeySpec = new SecretKeySpec(raw, "AES");
	    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding");
	    cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);
	    byte[] encrypted = cipher.doFinal(clear);
	    
	    return encrypted;
	}
	
	private static byte[] decrypt(byte[] raw, byte[] encrypted) throws Exception {
	    SecretKeySpec skeySpec = new SecretKeySpec(raw, "AES");
	    Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
	    cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);
	    byte[] decrypted = cipher.doFinal(encrypted);
	    
	    return decrypted;
	}
	
	public static String toHex(String txt) {
	        return toHex(txt.getBytes());
	}
	public static String fromHex(String hex) {
	        return new String(toByte(hex));
	}
	
	public static byte[] toByte(String hexString) {
	        int len = hexString.length()/2;
	        byte[] result = new byte[len];
	        for (int i = 0; i < len; i++)
	                result[i] = Integer.valueOf(hexString.substring(2*i, 2*i+2), 16).byteValue();
	        return result;
	}
	
	public static String toHex(byte[] buf) {
	        if (buf == null)
	                return "";
	        StringBuffer result = new StringBuffer(2*buf.length);
	        for (int i = 0; i < buf.length; i++) {
	                appendHex(result, buf[i]);
	        }
	        return result.toString();
	}
	private final static String HEX = "0123456789abcdef";
	private static void appendHex(StringBuffer sb, byte b) {
	        sb.append(HEX.charAt((b>>4)&0x0f)).append(HEX.charAt(b&0x0f));
	}
}
