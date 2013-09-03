/**
 * Encrypt/Decrypt strings using AES-256
 * Uses an iv of all zeros, CBC, Zero Byte padding
 * 
 * @author John Bennedict Lorenzo
 * 
 */

package com.jb.aes;

import java.security.Security;

import org.spongycastle.crypto.CipherParameters;
import org.spongycastle.crypto.engines.RijndaelEngine;
import org.spongycastle.crypto.modes.CBCBlockCipher;
import org.spongycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.spongycastle.crypto.paddings.ZeroBytePadding;
import org.spongycastle.crypto.params.KeyParameter;
import org.spongycastle.crypto.params.ParametersWithIV;

public class SPRijndaelCrypto {
	
	private static int AES256KeySizeInBytes = 32; 
	
	static {
	    Security.insertProviderAt(new org.spongycastle.jce.provider.BouncyCastleProvider(), 1);
	}
	
	public static String encrypt(String seed, String cleartext) throws Exception {
        byte[] rawKey = toByte(seed); 
        byte[] rawText = cleartext.getBytes("utf-8");
        byte[] result = encrypt(rawKey, rawText);
        
        return toHex(result);
	}
	
	public static String decrypt(String seed, String encrypted) throws Exception {
	        byte[] enc = toByte(encrypted);
	        byte[] result = decrypt(toByte(seed), enc);
	        return new String(result);
	}
	
	static byte[] ivBytes  = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
		                      0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
	
	private static byte[] encrypt(byte[] raw, byte[] clear) throws Exception {
	    PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(
	    	    new CBCBlockCipher(new RijndaelEngine(256)), new ZeroBytePadding());

	    int keySize = AES256KeySizeInBytes;

	    CipherParameters ivAndKey = new ParametersWithIV(new KeyParameter(raw, 0, keySize), ivBytes, 0, keySize);
	    cipher.init(true, ivAndKey);
	    byte[] encrypted  = new byte[cipher.getOutputSize(clear.length)];
	    int oLen = cipher.processBytes(clear, 0, clear.length, encrypted, 0);
	    cipher.doFinal(encrypted, oLen);
	    
	    return encrypted;
	}
	
	private static byte[] decrypt(byte[] raw, byte[] encrypted) throws Exception {
	    PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(
	    	    new CBCBlockCipher(new RijndaelEngine(256)), new ZeroBytePadding());

	    int keySize = AES256KeySizeInBytes;

	    CipherParameters ivAndKey = new ParametersWithIV(new KeyParameter(raw, 0, keySize), ivBytes, 0, keySize);
	    cipher.init(false, ivAndKey);
	    byte[] decrypted  = new byte[cipher.getOutputSize(encrypted.length)];
	    int oLen = cipher.processBytes(encrypted, 0, encrypted.length, decrypted, 0);
	    cipher.doFinal(decrypted, oLen);
	    
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
