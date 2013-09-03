/**
 * Encrypt/Decrypt strings using AES-256
 * Uses an iv of all zeros, CBC, Zero Byte padding
 * 
 * Depends on the SpongyCastle libraries
 * 
 * Copyright (c) 2013, John Bennedict Lorenzo
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 * 
 * Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 * 
 * Redistributions in binary form must reproduce the above copyright notice, this
 * list of conditions and the following disclaimer in the documentation and/or
 * other materials provided with the distribution.
 * 
 * Neither the name of the {organization} nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGE
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 * ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package com.jb.aes;

import java.io.UnsupportedEncodingException;
import java.security.Security;

import org.apache.http.util.ByteArrayBuffer;
import org.spongycastle.crypto.CipherParameters;
import org.spongycastle.crypto.engines.RijndaelEngine;
import org.spongycastle.crypto.modes.CBCBlockCipher;
import org.spongycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.spongycastle.crypto.paddings.ZeroBytePadding;
import org.spongycastle.crypto.params.KeyParameter;
import org.spongycastle.crypto.params.ParametersWithIV;

public class SPCrypto {
	
	private static int AES256KeySizeInBytes = 32; 
	
	static {
		// Starts the spongy castle encryption provider
	    Security.insertProviderAt(new org.spongycastle.jce.provider.BouncyCastleProvider(), 1);
	}
	
	public static String encrypt(String seed, String cleartext) throws Exception {
        byte[] rawKey = getPaddedRawKey(seed); 
                
        byte[] rawText = cleartext.getBytes("utf-8");
        
        byte[] result = encrypt(rawKey, rawText);
        
        return toHex(result);
	}
	
	public static String decrypt(String seed, String encrypted) throws Exception {
	        byte[] enc = toByte(encrypted);
	        byte[] result = decrypt(getPaddedRawKey(seed), enc);
	        return new String(result);
	}
	
	/** Returns the bytes for the input keyString, makes sure it is AES256KeySizeInBytes bytes long */
	private static byte[] getPaddedRawKey(String keyString) {
		ByteArrayBuffer keyBuffer = new ByteArrayBuffer(0);
		
		int initialBufferLength = Math.min(AES256KeySizeInBytes, keyString.length());
		
		try {
			keyBuffer.append(keyString.getBytes("utf-8"), 0, initialBufferLength);
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
		
		int paddingLength = AES256KeySizeInBytes - initialBufferLength;
		
		if (paddingLength > 0) {
			byte[] padding = new byte[paddingLength];
			
			keyBuffer.append(padding, initialBufferLength, paddingLength);			
		}
		
		return keyBuffer.buffer();
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
