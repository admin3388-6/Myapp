require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cookieParser = require('cookie-parser');
const CryptoJS = require('crypto-js');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const axios = require('axios');
const crypto = require('crypto');
const { createClient } = require('@supabase/supabase-js');

const app = express();

// الاتصال بقاعدة بيانات Supabase باستخدام المفاتيح التي ستضعها في Render
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY);

// إعدادات الحماية
app.use(helmet());
app.use(express.json());
app.use(cookieParser());

// حصر الطلبات لتكون فقط من الدومين الخاص بك
const allowedOrigins = ['https://skydata.bond', 'https://www.skydata.bond'];
app.use(cors({
    origin: (origin, callback) => {
        if (!origin || allowedOrigins.includes(origin)) {
            callback(null, true);
        } else {
            callback(new Error('CORS Error: Not allowed'));
        }
    },
    credentials: true,
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'Cookie']
}));

// حماية من الهجمات (DDoS / Spam)
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, 
    max: 50, 
    message: { error: 'تم تجاوز الحد المسموح من الطلبات.' }
});
app.use('/api/', limiter);

// إعداد الإيميل (Nodemailer)
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: { user: process.env.GMAIL_USER, pass: process.env.GMAIL_APP_PASSWORD }
});

// دوال مساعدة لفك التشفير وفحص البيانات
const decryptPayload = (encryptedText) => {
    try {
        const bytes = CryptoJS.AES.decrypt(encryptedText, process.env.ENCRYPTION_SECRET);
        return JSON.parse(bytes.toString(CryptoJS.enc.Utf8));
    } catch (e) { return null; }
};

const getGeoIP = async (ip) => {
    try {
        const res = await axios.get(`http://ip-api.com/json/${ip}`);
        return res.data.country || 'Unknown';
    } catch (e) { return 'Unknown'; }
};

// --- مسار التسجيل والدخول ---
app.post('/api/auth/process', async (req, res) => {
    const { payload } = req.body;
    
    // فك التشفير
    const decrypted = decryptPayload(payload);
    if (!decrypted) return res.status(403).json({ error: 'تم التلاعب بالبيانات أو فشل فك التشفير.' });

    const { action, email, password, username, fingerprint, recaptchaToken } = decrypted;
    
    // جلب IP المستخدم والدولة
    const clientIP = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    const country = await getGeoIP(clientIP);

    try {
        if (action === 'register') {
            // التحقق من قوة واسم المستخدم
            if (!/^[a-zA-Z0-9]{3,20}$/.test(username)) return res.status(400).json({ error: 'اسم المستخدم يجب أن يكون من 3 إلى 20 حرف ورقم إنجليزي فقط.' });
            if (password.length < 6) return res.status(400).json({ error: 'كلمة المرور يجب أن تكون 6 أحرف على الأقل.' });

            // التحقق من عدم وجود الإيميل أو اسم المستخدم مسبقاً
            const { data: existUser } = await supabase.from('users').select('id').or(`email.eq.${email},username.eq.${username}`).single();
            if (existUser) return res.status(400).json({ error: 'البريد الإلكتروني أو اسم المستخدم مستخدم بالفعل.' });

            // إنشاء الحساب في Supabase Auth
            const { data: authData, error: authError } = await supabase.auth.admin.createUser({
                email, password, email_confirm: true
            });
            if (authError) throw authError;

            // إدخال تفاصيل الحساب في جدول users
            await supabase.from('users').insert([{
                id: authData.user.id, username, email, auth_provider: 'email', last_ip: clientIP, last_country: country, last_device_fingerprint: fingerprint
            }]);
            
            return res.status(200).json({ success: true, message: 'تم إنشاء الحساب بأمان تام.' });
        }

        if (action === 'login') {
            const { data: user } = await supabase.from('users').select('*').eq('email', email).single();
            if (!user) return res.status(401).json({ error: 'بيانات الدخول خاطئة.' });
            if (user.auth_provider !== 'email') return res.status(400).json({ error: 'هذا الحساب مربوط بجوجل، الرجاء الدخول عبر زر جوجل.' });

            // التحقق من كلمة المرور
            const { error: signInError } = await supabase.auth.signInWithPassword({ email, password });
            if (signInError) return res.status(401).json({ error: 'بيانات الدخول خاطئة.' });

            // نظام الحماية: التحقق من بصمة الجهاز والموقع
            if (user.last_device_fingerprint !== fingerprint || user.last_country !== country) {
                await transporter.sendMail({
                    from: `"Slime.io Security" <${process.env.GMAIL_USER}>`,
                    to: email,
                    subject: '⚠️ تنبيه أمني: تسجيل دخول جديد',
                    html: `<h3 style="color:red;">تم رصد تسجيل دخول جديد لحسابك</h3><p>IP: ${clientIP}</p><p>الدولة: ${country}</p><p>إذا لم تكن أنت، قم بتأمين حسابك فوراً.</p>`
                });
            }

            // تحديث سجلات الدخول
            await supabase.from('users').update({ last_ip: clientIP, last_country: country, last_device_fingerprint: fingerprint, last_login: new Date() }).eq('id', user.id);
            await supabase.from('security_logs').insert([{ user_id: user.id, action: 'LOGIN_SUCCESS', ip_address: clientIP, country, device_fingerprint: fingerprint }]);

            // إصدار كوكيز آمنة (JWT)
            const token = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '7d' });
            res.cookie('auth_session', token, { httpOnly: true, secure: true, sameSite: 'strict', maxAge: 7 * 24 * 60 * 60 * 1000 });

            return res.status(200).json({ success: true, message: 'تم تسجيل الدخول المشفر بنجاح.' });
        }
    } catch (err) {
        console.error(err);
        return res.status(500).json({ error: 'خطأ داخلي في الخادم.' });
    }
});

// --- مسار نسيت كلمة المرور (إرسال OTP) ---
app.post('/api/auth/forgot', async (req, res) => {
    const { payload } = req.body;
    const decrypted = decryptPayload(payload);
    if (!decrypted) return res.status(403).json({ error: 'البيانات غير صالحة.' });

    const { email } = decrypted;
    const otp = Math.floor(100000 + Math.random() * 900000).toString(); // 6 أرقام
    const tokenHash = crypto.randomBytes(32).toString('hex'); // توكن لقتل الجلسة

    await supabase.from('password_resets').insert([{ email, otp_code: otp, token_hash: tokenHash, expires_at: new Date(Date.now() + 5 * 60000) }]);

    await transporter.sendMail({
        from: `"Slime.io Security" <${process.env.GMAIL_USER}>`,
        to: email,
        subject: 'استعادة كلمة المرور',
        html: `<h2>استعادة كلمة المرور الخاصة بك</h2>
               <p>لقد طلبت استعادة كلمة المرور. الرمز الخاص بك هو:</p>
               <h1 style="background:#eee;padding:15px;text-align:center;letter-spacing:10px;">${otp}</h1>
               <p>ينتهي هذا الرمز خلال 5 دقائق.</p>
               <hr>
               <p style="color:red;font-weight:bold;">تنبيه أمني: إذا لم تكن أنت من طلب هذا، اضغط على الرابط التالي فوراً لإيقاف العملية وتأمين الحساب:</p>
               <a href="https://api.skydata.bond/api/auth/kill-session?token=${tokenHash}">إلغاء العملية (Kill Session)</a>`
    });
    res.json({ success: true });
});

// --- مسار التحقق من OTP وتغيير كلمة السر ---
app.post('/api/auth/verify-otp', async (req, res) => {
    const { payload } = req.body;
    const decrypted = decryptPayload(payload);
    const { email, otp, newPassword } = decrypted;

    const { data: record } = await supabase.from('password_resets').select('*').eq('email', email).eq('otp_code', otp).eq('is_used', false).single();

    if (!record || new Date() > new Date(record.expires_at)) {
        return res.status(400).json({ error: 'الرمز غير صحيح أو منتهي الصلاحية.' });
    }

    // تحديث كلمة السر
    const userResult = await supabase.from('users').select('id').eq('email', email).single();
    if(userResult.data) {
        await supabase.auth.admin.updateUserById(userResult.data.id, { password: newPassword });
    }
    
    // إبطال الرمز
    await supabase.from('password_resets').update({ is_used: true }).eq('id', record.id);
    
    res.json({ success: true });
});

// --- مسار قتل الجلسة (الرابط في الإيميل) ---
app.get('/api/auth/kill-session', async (req, res) => {
    const { token } = req.query;
    await supabase.from('password_resets').update({ is_used: true }).eq('token_hash', token);
    res.send('<div style="text-align:center;margin-top:50px;font-family:sans-serif;"><h1 style="color:green;">تم إلغاء العملية وقتل الجلسة بنجاح</h1><p>حسابك الآن في أمان تام.</p></div>');
});

// تشغيل الخادم
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Slime.io Secure Server running on port ${PORT}`));
