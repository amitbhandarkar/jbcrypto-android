package com.jb.aes;

import com.example.aes.R;

import android.os.Bundle;
import android.app.Activity;
import android.util.Log;
import android.view.Menu;

public class MainActivity extends Activity {

	String TAG = "tag"; 
	
    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
    
        String encrypted;
        String key="1234567890ABCDEF1234567890ABCDEF";
		try {
			encrypted = SPCrypto.encrypt(key, "sometext");
			Log.d(TAG,encrypted);
			
			String decrypted = SPCrypto.decrypt(key,encrypted);
			Log.d(TAG,decrypted);			
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        getMenuInflater().inflate(R.menu.activity_main, menu);
        return true;
    }

    
}
