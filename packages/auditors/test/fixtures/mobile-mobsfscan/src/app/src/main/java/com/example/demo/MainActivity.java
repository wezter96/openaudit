package com.example.demo;

import android.app.Activity;
import android.content.Context;
import android.os.Bundle;
import android.util.Log;
import android.webkit.WebView;
import javax.crypto.Cipher;

public class MainActivity extends Activity {
    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        WebView w = new WebView(this);
        w.getSettings().setJavaScriptEnabled(true);
        w.addJavascriptInterface(new Object(), "bridge");
        Log.d("auth", "password=hunter2");
        getSharedPreferences("p", Context.MODE_WORLD_READABLE);
        try { Cipher.getInstance("DES/ECB/PKCS5Padding"); } catch (Exception e) {}
    }
}
