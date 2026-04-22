package com.skydata.app;

import android.os.Bundle;
import android.webkit.WebChromeClient; // استدعاء أداة الكروم
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import androidx.appcompat.app.AppCompatActivity;
import com.onesignal.OneSignal;

public class MainActivity extends AppCompatActivity {

    // المعرف الخاص بك من OneSignal
    private static final String ONESIGNAL_APP_ID = "48370ee9-5129-4aa7-994a-d3dd8368c5f7";
    private WebView myWebView;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        // ==========================================
        // 1. إعداد وتفعيل الإشعارات
        // ==========================================
        OneSignal.setLogLevel(OneSignal.LOG_LEVEL.VERBOSE, OneSignal.LOG_LEVEL.NONE);
        OneSignal.initWithContext(this);
        OneSignal.setAppId(ONESIGNAL_APP_ID);
        
        // هذا السطر هو الذي سيظهر رسالة طلب الإذن للمستخدم ويربط جهازه بخادم الإشعارات
        OneSignal.promptForPushNotifications();

        // ==========================================
        // 2. إعداد المتصفح الخفي (WebView)
        // ==========================================
        myWebView = findViewById(R.id.webview);
        WebSettings webSettings = myWebView.getSettings();
        
        // تفعيل الجافاسكريبت
        webSettings.setJavaScriptEnabled(true);
        
        // تفعيل التخزين المحلي (هذا هو السر الذي سيجعل الأزرار والموقع يعمل بشكل كامل!)
        webSettings.setDomStorageEnabled(true);
        
        // دعم ميزات المتصفح المتقدمة (مثل النوافذ المنبثقة وتحميل الصفحات بشكل صحيح)
        myWebView.setWebChromeClient(new WebChromeClient());
        myWebView.setWebViewClient(new WebViewClient());
        
        // تحميل موقعك
        myWebView.loadUrl("https://skydata.bond");
    }

    // برمجة زر الرجوع في الهاتف
    @Override
    public void onBackPressed() {
        if (myWebView.canGoBack()) {
            myWebView.goBack();
        } else {
            super.onBackPressed();
        }
    }
}
