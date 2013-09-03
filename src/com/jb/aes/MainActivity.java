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
        String key="U2FsdGVkX1ABsfH59fG2OIDYPZSjY9wL";
		try {
			encrypted = SPRubyCrypto.encrypt(key, "0.betasecurity");
			Log.d(TAG,encrypted);
			
//			String decrypted = LO2Crypto.decrypt(key,encrypted);
//			Log.d(TAG,decrypted);
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
