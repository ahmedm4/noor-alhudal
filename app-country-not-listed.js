/**
 * Noor Al-Huda Web Application v9 - Vercel Edition
 * تطبيق ويب للنشر على Vercel
 * 
 * ⚠️ مهم: كل مستخدم يستخدم توكنه الخاص فقط - لا تداخل بين المستخدمين
 */

require('dotenv').config();
const express = require('express');
const session = require('express-session');
const axios = require('axios');
const { DynamoDBClient, PutItemCommand, GetItemCommand, UpdateItemCommand, DeleteItemCommand, ScanCommand } = require('@aws-sdk/client-dynamodb');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// ====== الإعدادات ======
const config = {
    lwaClientId: process.env.LWA_CLIENT_ID,
    lwaClientSecret: process.env.LWA_CLIENT_SECRET,
    alexaClientId: process.env.ALEXA_CLIENT_ID,
    alexaClientSecret: process.env.ALEXA_CLIENT_SECRET,
    redirectUri: process.env.REDIRECT_URI || 'https://noor-alhudal.vercel.app/auth/callback',
    baseUrl: process.env.BASE_URL || 'https://noor-alhudal.vercel.app',
    awsRegion: process.env.AWS_REGION || 'us-east-1',
    dynamoTable: process.env.DYNAMODB_TABLE || 'doorbell-users',
    scheduleTable: process.env.SCHEDULE_TABLE || 'doorbell-schedule',
    soundsJsonUrl: process.env.SOUNDS_JSON_URL || 'https://alexaalhuda.s3.eu-north-1.amazonaws.com/sounds2.json'
};

// DynamoDB Client
const dynamoClient = new DynamoDBClient({ region: config.awsRegion });

// ====== تحميل ملف JSON محلي ======
let localSoundsData = null;
try {
    const localPath = path.join(__dirname, 'sounds2.json');
    if (fs.existsSync(localPath)) {
        localSoundsData = JSON.parse(fs.readFileSync(localPath, 'utf8'));
        console.log('✅ Loaded local sounds2.json with', Object.keys(localSoundsData).length, 'items');
    }
} catch (e) {
    console.log('ℹ️ No local sounds2.json found');
}

// ====== Cache ======
let soundsCache = null;
let cacheTimestamp = 0;
const CACHE_DURATION = 5 * 60 * 1000;

// ====== جلب الأصوات ======
async function fetchSoundsFromJSON() {
    if (localSoundsData) return localSoundsData;
    if (soundsCache && (Date.now() - cacheTimestamp) < CACHE_DURATION) return soundsCache;
    
    try {
        const response = await axios.get(config.soundsJsonUrl, { timeout: 10000 });
        soundsCache = response.data;
        cacheTimestamp = Date.now();
        return soundsCache;
    } catch (error) {
        console.error('Error fetching sounds:', error.message);
        return soundsCache || {};
    }
}

// ====== Middleware ======
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.set('trust proxy', 1);

// إعدادات الجلسة - 30 يوم
const sessionConfig = {
    secret: process.env.SESSION_SECRET || 'noor-alhuda-secret-2024',
    resave: false,
    saveUninitialized: false,
    cookie: { 
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true, 
        maxAge: 30 * 24 * 60 * 60 * 1000,  // 30 يوم
        sameSite: 'lax'
    }
};

// في Vercel، استخدم cookie-based session
if (process.env.VERCEL) {
    sessionConfig.cookie.secure = true;
}

app.use(session(sessionConfig));

// ====== الصفحة الرئيسية ======
app.get('/', async (req, res) => {
    let user = req.session.user;
    
    // محاولة استعادة الجلسة من الكوكي إذا لم تكن موجودة
    if (!user) {
        const cookieHeader = req.headers.cookie || '';
        const userIdMatch = cookieHeader.match(/userId=([^;]+)/);
        if (userIdMatch) {
            const userId = decodeURIComponent(userIdMatch[1]);
            try {
                const userData = await getUserData(userId);
                if (userData && userData.userName) {
                    user = {
                        id: userId,
                        name: userData.userName,
                        email: userData.userEmail
                    };
                    req.session.user = user;
                    console.log('✅ Session restored from cookie for:', userId.slice(-10));
                }
            } catch (e) {
                console.log('Could not restore session:', e.message);
            }
        }
    }
    
    const soundsData = await fetchSoundsFromJSON();
    
    let doorbells = [{ id: 'default-trigger-001', name: 'المنبه الرئيسي' }];
    if (user) {
        const userData = await getUserData(user.id);
        if (userData && userData.doorbells && userData.doorbells.length > 0) {
            doorbells = userData.doorbells;
        }
    }
    
    res.send(generateHTML(user, soundsData, doorbells));
});

// ====== Login ======
app.get('/login', (req, res) => {
    const state = Math.random().toString(36).substring(7);
    req.session.oauthState = state;
    
    const authUrl = 'https://www.amazon.com/ap/oa?' +
        'client_id=' + encodeURIComponent(config.lwaClientId) +
        '&scope=profile' +
        '&response_type=code' +
        '&redirect_uri=' + encodeURIComponent(config.redirectUri) +
        '&state=' + state;
    
    res.redirect(authUrl);
});

// ====== Callback ======
async function handleCallback(req, res) {
    const { code, error } = req.query;
    
    if (error || !code) {
        return res.redirect('/?error=' + (error || 'no_code'));
    }
    
    try {
        // Get LWA token
        const tokenResponse = await axios.post('https://api.amazon.com/auth/o2/token', 
            new URLSearchParams({
                grant_type: 'authorization_code',
                code: code,
                redirect_uri: config.redirectUri,
                client_id: config.lwaClientId,
                client_secret: config.lwaClientSecret
            }), {
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
            }
        );
        
        const { access_token, refresh_token } = tokenResponse.data;
        
        // Get user profile
        const profileResponse = await axios.get('https://api.amazon.com/user/profile', {
            headers: { 'Authorization': 'Bearer ' + access_token }
        });
        
        const profile = profileResponse.data;
        
        // Save to session
        req.session.user = {
            id: profile.user_id,
            name: profile.name,
            email: profile.email,
            accessToken: access_token,
            refreshToken: refresh_token
        };
        
        // Check if user already has Alexa token from Smart Home Authorization
        const existingUser = await getUserData(profile.user_id);
        
        const defaultDoorbells = [{ id: 'default-trigger-001', name: 'المنبه الرئيسي', nameEn: 'Main Trigger' }];
        
        if (existingUser && existingUser.accessToken) {
            // User already has tokens from Alexa - just update profile info
            console.log('✅ User has existing Alexa tokens - preserving them');
            await updateUserProfile(profile.user_id, {
                userName: profile.name || '',
                userEmail: profile.email || '',
                lwaAccessToken: access_token,
                lwaRefreshToken: refresh_token
            });
        } else {
            // New user - save LWA tokens (will be replaced by Alexa tokens later)
            console.log('ℹ️ New user - saving LWA tokens');
            await saveUserData(profile.user_id, {
                accessToken: access_token,
                refreshToken: refresh_token,
                userName: profile.name || '',
                userEmail: profile.email || '',
                doorbells: defaultDoorbells
            });
        }
        
        // حفظ cookie للمستخدم (30 يوم)
        res.cookie('userId', profile.user_id, {
            maxAge: 30 * 24 * 60 * 60 * 1000,
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'lax'
        });
        
        req.session.save(() => res.redirect('/'));
        
    } catch (err) {
        console.error('Callback Error:', err.response?.data || err.message);
        res.redirect('/?error=auth_failed');
    }
}

app.get('/callback', handleCallback);
app.get('/auth/callback', handleCallback);

// ====== Logout ======
app.get('/logout', (req, res) => {
    res.clearCookie('userId');
    req.session.destroy();
    res.redirect('/');
});

// ====== API: Schedule Audio ======
app.post('/api/schedule', async (req, res) => {
    const user = req.session.user;
    if (!user) return res.status(401).json({ error: 'Not authenticated' });
    
    const { audioUrl, audioName, doorbellId, spokenTitle, spokenReader } = req.body;
    if (!audioUrl) return res.status(400).json({ error: 'Audio URL required' });
    
    try {
        console.log('📝 Scheduling audio for user:', user.id);
        console.log('📝 Audio:', audioName, '| Spoken:', spokenTitle, '-', spokenReader);
        
        // Save scheduled audio FIRST with spoken names
        await scheduleAudio(user.id, { 
            audioUrl, 
            audioName, 
            doorbellId,
            spokenTitle: spokenTitle || audioName?.split(' - ')[0],
            spokenReader: spokenReader || audioName?.split(' - ')[1]
        });
        console.log('✅ Audio scheduled successfully');
        
        // Small delay to ensure DynamoDB write is complete
        await new Promise(resolve => setTimeout(resolve, 500));
        
        // Send doorbell event - استخدام توكن المستخدم الحالي فقط!
        console.log('🔔 Sending doorbell event...');
        const sent = await sendDoorbellEvent(user.id, doorbellId || 'default-trigger-001');
        
        if (!sent) {
            return res.json({ 
                success: false, 
                doorbellSent: false,
                error: 'skill_not_linked',
                message: 'يجب تفعيل المهارة في تطبيق Alexa أولاً. افتح Alexa App → Skills → ابحث عن المهارة → Enable → ثم قل "Alexa, discover my devices"'
            });
        }
        
        console.log('✅ Doorbell event sent successfully');
        res.json({ success: true, doorbellSent: sent });
    } catch (error) {
        console.error('Schedule Error:', error);
        res.status(500).json({ error: 'Failed to schedule' });
    }
});

// ====== API: Doorbells ======
app.get('/api/doorbells', async (req, res) => {
    const user = req.session.user;
    if (!user) return res.status(401).json({ error: 'Not authenticated' });
    
    const userData = await getUserData(user.id);
    const doorbells = userData?.doorbells || [{ id: 'default-trigger-001', name: 'المنبه الرئيسي' }];
    res.json(doorbells);
});

app.post('/api/doorbells', async (req, res) => {
    const user = req.session.user;
    if (!user) return res.status(401).json({ error: 'Not authenticated' });
    
    const { name, nameEn } = req.body;
    if (!name && !nameEn) return res.status(400).json({ error: 'Name required' });
    
    const userData = await getUserData(user.id);
    const doorbells = userData?.doorbells || [];
    
    const newDoorbell = {
        id: 'doorbell-' + Date.now().toString(36),
        name: name || nameEn,      // الاسم العربي (أو الإنجليزي إذا لم يوجد)
        nameEn: nameEn || name     // الاسم الإنجليزي (أو العربي إذا لم يوجد)
    };
    
    doorbells.push(newDoorbell);
    await updateUserDoorbells(user.id, doorbells);
    
    res.json({ success: true, doorbell: newDoorbell, doorbells });
});

app.delete('/api/doorbells/:id', async (req, res) => {
    const user = req.session.user;
    if (!user) return res.status(401).json({ error: 'Not authenticated' });
    
    const userData = await getUserData(user.id);
    let doorbells = userData?.doorbells || [];
    
    doorbells = doorbells.filter(d => d.id !== req.params.id);
    if (doorbells.length === 0) {
        doorbells = [{ id: 'default-trigger-001', name: 'المنبه الرئيسي' }];
    }
    
    await updateUserDoorbells(user.id, doorbells);
    res.json({ success: true, doorbells });
});

// ====== API: Schedules ======
app.get('/api/schedules', async (req, res) => {
    const user = req.session.user;
    if (!user) return res.status(401).json({ error: 'Not authenticated' });
    
    const userData = await getUserData(user.id);
    const schedules = userData?.schedules || [];
    res.json({ schedules });
});

app.post('/api/schedules', async (req, res) => {
    const user = req.session.user;
    if (!user) return res.status(401).json({ error: 'Not authenticated' });
    
    const schedule = req.body;
    
    console.log('📅 Adding schedule for user:', user.id);
    console.log('📅 Schedule:', schedule.duaaName, 'at', schedule.time);
    
    const userData = await getUserData(user.id);
    const schedules = userData?.schedules || [];
    
    schedules.push(schedule);
    await updateUserSchedules(user.id, schedules);
    
    console.log('✅ Schedule saved. Total schedules:', schedules.length);
    
    res.json({ success: true, schedules });
});

app.delete('/api/schedules/:id', async (req, res) => {
    const user = req.session.user;
    if (!user) return res.status(401).json({ error: 'Not authenticated' });
    
    const userData = await getUserData(user.id);
    let schedules = userData?.schedules || [];
    
    schedules = schedules.filter(s => s.id !== req.params.id);
    await updateUserSchedules(user.id, schedules);
    
    res.json({ success: true, schedules });
});

app.post('/api/schedules/:id/toggle', async (req, res) => {
    const user = req.session.user;
    if (!user) return res.status(401).json({ error: 'Not authenticated' });
    
    const userData = await getUserData(user.id);
    let schedules = userData?.schedules || [];
    
    schedules = schedules.map(s => {
        if (s.id === req.params.id) {
            s.enabled = !s.enabled;
        }
        return s;
    });
    
    await updateUserSchedules(user.id, schedules);
    res.json({ success: true, schedules });
});

// ====== Send Doorbell Event ======
// ⚠️ مهم: كل مستخدم يستخدم توكنه الخاص فقط - لا نستخدم توكن مستخدم آخر أبداً!
async function sendDoorbellEvent(visitorId, doorbellId) {
    try {
        // جلب بيانات المستخدم الحالي فقط
        let userData = await getUserData(visitorId);
        
        if (!userData?.accessToken) {
            console.log('❌ No access token for user:', visitorId);
            console.log('ℹ️ User needs to enable skill in Alexa App first');
            return false;
        }
        
        // محاولة إرسال الحدث
        let sent = await tryDoorbellEvent(userData.accessToken, doorbellId);
        
        // إذا فشل، حاول تجديد التوكن الخاص بهذا المستخدم فقط
        if (!sent && userData.refreshToken) {
            console.log('🔄 Token expired for user, refreshing...');
            const newToken = await refreshAccessToken(userData.refreshToken);
            
            if (newToken) {
                // حفظ التوكن الجديد لهذا المستخدم
                await updateUserToken(visitorId, newToken.access_token, newToken.refresh_token);
                
                // إعادة المحاولة
                sent = await tryDoorbellEvent(newToken.access_token, doorbellId);
            }
        }
        
        if (!sent) {
            console.log('❌ Failed to send doorbell event for user:', visitorId);
            console.log('ℹ️ User may need to re-enable skill: Alexa App → Skills → Disable → Enable → Discover devices');
        }
        
        return sent;
    } catch (error) {
        console.error('Doorbell Error:', error.response?.data || error.message);
        return false;
    }
}

// محاولة إرسال حدث الجرس
async function tryDoorbellEvent(accessToken, doorbellId) {
    try {
        const event = {
            event: {
                header: {
                    namespace: 'Alexa.DoorbellEventSource',
                    name: 'DoorbellPress',
                    messageId: 'msg-' + Date.now(),
                    payloadVersion: '3'
                },
                endpoint: {
                    scope: {
                        type: 'BearerToken',
                        token: accessToken
                    },
                    endpointId: doorbellId
                },
                payload: {
                    cause: { type: 'PHYSICAL_INTERACTION' },
                    timestamp: new Date().toISOString()
                }
            }
        };
        
        await axios.post('https://api.amazonalexa.com/v3/events', event, {
            headers: {
                'Authorization': 'Bearer ' + accessToken,
                'Content-Type': 'application/json'
            },
            timeout: 10000
        });
        
        console.log('✅ Doorbell event sent');
        return true;
    } catch (error) {
        const errorData = error.response?.data;
        console.error('Doorbell attempt failed:', errorData?.payload?.code || error.message);
        return false;
    }
}

// تجديد التوكن - نجرب Alexa credentials أولاً ثم LWA
async function refreshAccessToken(refreshToken) {
    // أولاً: جرب Alexa credentials (للتوكن من Smart Home)
    const alexaResult = await tryRefreshToken(refreshToken, config.alexaClientId, config.alexaClientSecret);
    if (alexaResult) {
        console.log('✅ Token refreshed with Alexa credentials');
        return alexaResult;
    }
    
    // ثانياً: جرب LWA credentials (للتوكن من Login with Amazon)
    const lwaResult = await tryRefreshToken(refreshToken, config.lwaClientId, config.lwaClientSecret);
    if (lwaResult) {
        console.log('✅ Token refreshed with LWA credentials');
        return lwaResult;
    }
    
    console.error('❌ Token refresh failed with both credentials');
    return null;
}

async function tryRefreshToken(refreshToken, clientId, clientSecret) {
    try {
        console.log('🔄 Trying to refresh token...');
        
        const response = await axios.post('https://api.amazon.com/auth/o2/token',
            new URLSearchParams({
                grant_type: 'refresh_token',
                refresh_token: refreshToken,
                client_id: clientId,
                client_secret: clientSecret
            }), {
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
            }
        );
        
        return response.data;
    } catch (error) {
        console.log('Refresh attempt failed:', error.response?.data?.error || error.message);
        return null;
    }
}

// تحديث التوكن في قاعدة البيانات
async function updateUserToken(visitorId, accessToken, refreshToken) {
    try {
        await dynamoClient.send(new UpdateItemCommand({
            TableName: config.dynamoTable,
            Key: { visitorId: { S: visitorId } },
            UpdateExpression: 'SET accessToken = :a, refreshToken = :r, updatedAt = :u',
            ExpressionAttributeValues: {
                ':a': { S: accessToken },
                ':r': { S: refreshToken || '' },
                ':u': { S: new Date().toISOString() }
            }
        }));
        console.log('✅ Token updated in database');
    } catch (error) {
        console.error('❌ Failed to update token:', error);
    }
}

// ====== DynamoDB ======
async function saveUserData(visitorId, data) {
    await dynamoClient.send(new PutItemCommand({
        TableName: config.dynamoTable,
        Item: {
            visitorId: { S: visitorId },
            accessToken: { S: data.accessToken || '' },
            refreshToken: { S: data.refreshToken || '' },
            userName: { S: data.userName || '' },
            userEmail: { S: data.userEmail || '' },
            doorbells: { S: JSON.stringify(data.doorbells || []) },
            updatedAt: { S: new Date().toISOString() }
        }
    }));
}

async function getUserData(visitorId) {
    try {
        const result = await dynamoClient.send(new GetItemCommand({
            TableName: config.dynamoTable,
            Key: { visitorId: { S: visitorId } }
        }));
        
        if (!result.Item) return null;
        
        return {
            visitorId: result.Item.visitorId?.S,
            accessToken: result.Item.accessToken?.S,
            refreshToken: result.Item.refreshToken?.S,
            doorbells: result.Item.doorbells ? JSON.parse(result.Item.doorbells.S) : [],
            schedules: result.Item.schedules ? JSON.parse(result.Item.schedules.S) : []
        };
    } catch (error) {
        console.error('getUserData Error:', error);
        return null;
    }
}

async function updateUserSchedules(visitorId, schedules) {
    await dynamoClient.send(new UpdateItemCommand({
        TableName: config.dynamoTable,
        Key: { visitorId: { S: visitorId } },
        UpdateExpression: 'SET schedules = :s, updatedAt = :u',
        ExpressionAttributeValues: {
            ':s': { S: JSON.stringify(schedules) },
            ':u': { S: new Date().toISOString() }
        }
    }));
}

async function updateUserProfile(visitorId, data) {
    await dynamoClient.send(new UpdateItemCommand({
        TableName: config.dynamoTable,
        Key: { visitorId: { S: visitorId } },
        UpdateExpression: 'SET userName = :n, userEmail = :e, lwaAccessToken = :la, lwaRefreshToken = :lr, updatedAt = :u',
        ExpressionAttributeValues: {
            ':n': { S: data.userName || '' },
            ':e': { S: data.userEmail || '' },
            ':la': { S: data.lwaAccessToken || '' },
            ':lr': { S: data.lwaRefreshToken || '' },
            ':u': { S: new Date().toISOString() }
        }
    }));
}

async function updateUserDoorbells(visitorId, doorbells) {
    await dynamoClient.send(new UpdateItemCommand({
        TableName: config.dynamoTable,
        Key: { visitorId: { S: visitorId } },
        UpdateExpression: 'SET doorbells = :d, updatedAt = :u',
        ExpressionAttributeValues: {
            ':d': { S: JSON.stringify(doorbells) },
            ':u': { S: new Date().toISOString() }
        }
    }));
}

async function scheduleAudio(visitorId, data) {
    const item = {
        visitorId: { S: visitorId },
        audioUrl: { S: data.audioUrl },
        audioName: { S: data.audioName || 'Unknown' },
        doorbellId: { S: data.doorbellId || 'default-trigger-001' },
        updatedAt: { S: new Date().toISOString() }
    };
    
    // إضافة الأسماء المنطوقة إذا كانت متاحة
    if (data.spokenTitle) {
        item.spokenTitle = { S: data.spokenTitle };
    }
    if (data.spokenReader) {
        item.spokenReader = { S: data.spokenReader };
    }
    
    await dynamoClient.send(new PutItemCommand({
        TableName: config.scheduleTable,
        Item: item
    }));
}

// ====== HTML ======
function generateHTML(user, soundsData, doorbells) {
    const soundsJSON = JSON.stringify(soundsData || {});
    const doorbellsJSON = JSON.stringify(doorbells || []);
    
    return `<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>نور الهدى - Noor Al-Huda</title>
    <link href="https://fonts.googleapis.com/css2?family=Tajawal:wght@400;500;700&display=swap" rel="stylesheet">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Tajawal', sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
            min-height: 100vh;
            color: #fff;
        }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        
        header {
            text-align: center;
            padding: 30px 0;
            border-bottom: 1px solid rgba(255,255,255,0.1);
            margin-bottom: 30px;
        }
        header h1 { font-size: 2.5em; color: #e0a346; margin-bottom: 10px; }
        header p { color: rgba(255,255,255,0.7); }
        
        .user-section {
            background: rgba(255,255,255,0.05);
            border-radius: 15px;
            padding: 20px;
            margin-bottom: 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 15px;
        }
        .user-info { display: flex; align-items: center; gap: 15px; }
        .user-avatar {
            width: 50px; height: 50px;
            border-radius: 50%;
            background: linear-gradient(135deg, #e0a346, #c7922c);
            display: flex; align-items: center; justify-content: center;
            font-size: 1.5em;
        }
        
        .btn {
            padding: 12px 25px;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            font-family: inherit;
            font-size: 1em;
            transition: all 0.3s;
        }
        .btn-primary {
            background: linear-gradient(135deg, #e0a346, #c7922c);
            color: #1a1a2e;
            font-weight: 700;
        }
        .btn-primary:hover { transform: translateY(-2px); box-shadow: 0 5px 20px rgba(224,163,70,0.4); }
        .btn-secondary { background: rgba(255,255,255,0.1); color: #fff; }
        .btn-secondary:hover { background: rgba(255,255,255,0.2); }
        .btn-play {
            background: linear-gradient(135deg, #4CAF50, #45a049);
            color: white;
            padding: 10px 20px;
        }
        .btn-play:hover { background: linear-gradient(135deg, #45a049, #3d8b40); }
        .btn-danger { background: #e74c3c; color: white; padding: 8px 15px; }
        
        /* Prayer Times Styles */
        .prayer-times-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-top: 20px;
        }
        .prayer-card {
            background: linear-gradient(135deg, rgba(255,255,255,0.08), rgba(255,255,255,0.03));
            border-radius: 15px;
            padding: 20px;
            text-align: center;
            transition: all 0.3s;
            border: 1px solid rgba(255,255,255,0.1);
        }
        .prayer-card:hover {
            transform: translateY(-3px);
            box-shadow: 0 10px 30px rgba(0,0,0,0.3);
            border-color: rgba(224,163,70,0.3);
        }
        .prayer-card .prayer-icon {
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        .prayer-card .prayer-name {
            color: #e0a346;
            font-size: 1.2em;
            margin-bottom: 10px;
        }
        .prayer-card .prayer-time {
            font-size: 2em;
            font-weight: bold;
            color: #fff;
            margin-bottom: 15px;
            font-family: 'Courier New', monospace;
        }
        .prayer-card .calibration-controls {
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 10px;
            margin-top: 10px;
        }
        .prayer-card .calibration-btn {
            width: 32px;
            height: 32px;
            border-radius: 50%;
            border: none;
            background: rgba(224,163,70,0.2);
            color: #e0a346;
            font-size: 1.2em;
            cursor: pointer;
            transition: all 0.2s;
        }
        .prayer-card .calibration-btn:hover {
            background: rgba(224,163,70,0.4);
            transform: scale(1.1);
        }
        .prayer-card .calibration-value {
            min-width: 50px;
            color: rgba(255,255,255,0.7);
            font-size: 0.9em;
        }
        
        .tabs {
            display: flex;
            gap: 10px;
            margin-bottom: 20px;
            flex-wrap: wrap;
        }
        .tab {
            padding: 12px 25px;
            background: rgba(255,255,255,0.1);
            border: none;
            border-radius: 8px;
            color: #fff;
            cursor: pointer;
            font-family: inherit;
            font-size: 1em;
            transition: all 0.3s;
        }
        .tab.active { background: linear-gradient(135deg, #e0a346, #c7922c); color: #1a1a2e; }
        .tab-content { display: none; }
        .tab-content.active { display: block; }
        
        .doorbells-section {
            background: rgba(255,255,255,0.05);
            border-radius: 15px;
            padding: 20px;
            margin-bottom: 20px;
        }
        .doorbells-section h3 { color: #e0a346; margin-bottom: 15px; }
        .doorbell-list { display: flex; flex-wrap: wrap; gap: 10px; margin-bottom: 15px; }
        .doorbell-item {
            background: rgba(255,255,255,0.1);
            padding: 10px 15px;
            border-radius: 8px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .doorbell-item.selected { background: rgba(224,163,70,0.3); border: 1px solid #e0a346; }
        .add-doorbell { display: flex; gap: 10px; }
        .add-doorbell input {
            flex: 1;
            padding: 10px 15px;
            border: none;
            border-radius: 8px;
            background: rgba(255,255,255,0.1);
            color: #fff;
            font-family: inherit;
        }
        
        .sounds-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
            gap: 20px;
        }
        .sound-card {
            background: rgba(255,255,255,0.05);
            border-radius: 15px;
            overflow: hidden;
            transition: all 0.3s;
        }
        .sound-card:hover { transform: translateY(-5px); box-shadow: 0 10px 30px rgba(0,0,0,0.3); }
        .sound-header {
            background: linear-gradient(135deg, rgba(224,163,70,0.2), rgba(224,163,70,0.1));
            padding: 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .sound-header h3 { color: #e0a346; font-size: 1.2em; }
        .sound-body { padding: 15px 20px; }
        
        .reader-select {
            width: 100%;
            padding: 10px 15px;
            border: none;
            border-radius: 8px;
            background: rgba(255,255,255,0.1);
            color: #fff;
            font-family: inherit;
            font-size: 1em;
            margin-bottom: 15px;
            cursor: pointer;
        }
        .reader-select option { background: #1a1a2e; color: #fff; }
        
        .search-box {
            width: 100%;
            padding: 15px 20px;
            border: none;
            border-radius: 10px;
            background: rgba(255,255,255,0.1);
            color: #fff;
            font-size: 1.1em;
            font-family: inherit;
            margin-bottom: 20px;
        }
        .search-box::placeholder { color: rgba(255,255,255,0.5); }
        
        .login-section {
            text-align: center;
            padding: 60px 20px;
            background: rgba(255,255,255,0.05);
            border-radius: 20px;
        }
        .login-section h2 { color: #e0a346; margin-bottom: 20px; }
        .login-section p { color: rgba(255,255,255,0.7); margin-bottom: 30px; }
        
        .toast {
            position: fixed;
            bottom: 30px;
            left: 50%;
            transform: translateX(-50%);
            padding: 15px 30px;
            border-radius: 10px;
            color: #fff;
            font-weight: 500;
            z-index: 1000;
            display: none;
        }
        .toast.success { background: linear-gradient(135deg, #4CAF50, #45a049); }
        .toast.error { background: linear-gradient(135deg, #f44336, #d32f2f); }
        .toast.show { display: block; animation: slideUp 0.3s ease; }
        
        .schedule-form {
            background: rgba(255,255,255,0.05);
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 20px;
        }
        .form-row { margin-bottom: 15px; }
        .form-row label { display: block; margin-bottom: 8px; color: rgba(255,255,255,0.8); }
        .time-input {
            width: 100%;
            padding: 12px 15px;
            border: none;
            border-radius: 8px;
            background: rgba(255,255,255,0.1);
            color: #fff;
            font-family: inherit;
            font-size: 1em;
        }
        .time-input::-webkit-calendar-picker-indicator { filter: invert(1); }
        .days-selector { display: flex; flex-wrap: wrap; gap: 10px; }
        .day-checkbox {
            background: rgba(255,255,255,0.1);
            padding: 8px 12px;
            border-radius: 8px;
            cursor: pointer;
            display: flex;
            align-items: center;
            gap: 5px;
            transition: all 0.3s;
        }
        .day-checkbox:has(input:checked) { background: rgba(224,163,70,0.3); border: 1px solid #e0a346; }
        .day-checkbox input { accent-color: #e0a346; }
        
        .schedules-list { display: flex; flex-direction: column; gap: 10px; }
        .schedule-item {
            background: rgba(255,255,255,0.05);
            padding: 15px 20px;
            border-radius: 10px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 10px;
        }
        .schedule-info { flex: 1; }
        .schedule-info h4 { color: #e0a346; margin-bottom: 5px; }
        .schedule-info p { color: rgba(255,255,255,0.6); font-size: 0.9em; }
        .schedule-time {
            background: rgba(224,163,70,0.2);
            padding: 8px 15px;
            border-radius: 8px;
            color: #e0a346;
            font-weight: 700;
            font-size: 1.2em;
        }
        .schedule-actions { display: flex; gap: 10px; }
        .no-schedules { text-align: center; padding: 30px; color: rgba(255,255,255,0.5); }
        
        @keyframes slideUp {
            from { opacity: 0; transform: translateX(-50%) translateY(20px); }
            to { opacity: 1; transform: translateX(-50%) translateY(0); }
        }
        
        @media (max-width: 768px) {
            .sounds-grid { grid-template-columns: 1fr; }
            header h1 { font-size: 1.8em; }
            .user-section { flex-direction: column; text-align: center; }
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🌙 نور الهدى</h1>
            <p>منصة الأدعية والأذكار لأجهزة Alexa</p>
        </header>
        
        ${user ? `
        <div class="user-section">
            <div class="user-info">
                <div class="user-avatar">👤</div>
                <div>
                    <strong>${user.name || 'مستخدم'}</strong>
                    <p style="color: rgba(255,255,255,0.6); font-size: 0.9em;">${user.email || ''}</p>
                </div>
            </div>
            <a href="/logout" class="btn btn-secondary">تسجيل الخروج</a>
        </div>
        
        <div class="tabs">
            <button class="tab active" onclick="showTab('sounds')">🎵 الأصوات</button>
            <button class="tab" onclick="showTab('doorbells')">🔔 الأجراس</button>
            <button class="tab" onclick="showTab('schedule')">📅 الجدولة</button>
            <button class="tab" onclick="showTab('prayer')">🕌 أوقات الصلاة</button>
        </div>
        
        <div id="sounds-tab" class="tab-content active">
            <div class="doorbells-section">
                <h3>🔔 الجرس المحدد للتشغيل</h3>
                <div class="doorbell-list" id="doorbell-select"></div>
            </div>
            <input type="text" class="search-box" id="search" placeholder="🔍 ابحث عن دعاء...">
            <div class="sounds-grid" id="sounds-container"></div>
        </div>
        
        <div id="doorbells-tab" class="tab-content">
            <div class="doorbells-section">
                <h3>🔔 إدارة الأجراس</h3>
                <p style="color: rgba(255,255,255,0.6); margin-bottom: 15px;">أضف أجراس متعددة لغرف مختلفة.</p>
                <div class="doorbell-list" id="doorbells-list"></div>
                <div class="add-doorbell" style="flex-direction: column; gap: 10px;">
                    <div style="display: flex; gap: 10px; width: 100%;">
                        <input type="text" id="new-doorbell-name" placeholder="الاسم بالعربي (مثال: المجلس)" style="flex: 1;">
                        <input type="text" id="new-doorbell-name-en" placeholder="الاسم بالإنجليزي (مثال: Majlis)" style="flex: 1;">
                    </div>
                    <button class="btn btn-primary" onclick="addDoorbell()" style="width: 100%;">➕ إضافة جرس</button>
                </div>
            </div>
        </div>
        
        <div id="schedule-tab" class="tab-content">
            <div class="doorbells-section">
                <h3>📅 جدولة الأصوات</h3>
                <p style="color: rgba(255,255,255,0.6); margin-bottom: 20px;">جدولة تشغيل الأدعية في أوقات محددة يومياً.</p>
                
                <div class="schedule-form">
                    <div class="form-row">
                        <label>🎵 الدعاء:</label>
                        <select id="schedule-duaa" class="reader-select"><option value="">-- اختر الدعاء --</option></select>
                    </div>
                    <div class="form-row">
                        <label>🎙️ القارئ:</label>
                        <select id="schedule-reader" class="reader-select"><option value="">-- اختر القارئ --</option></select>
                    </div>
                    <div class="form-row">
                        <label>🔔 الجرس:</label>
                        <select id="schedule-doorbell" class="reader-select"></select>
                    </div>
                    <div class="form-row">
                        <label>⏰ نوع الوقت:</label>
                        <select id="schedule-time-type" class="reader-select" onchange="toggleTimeInput()">
                            <option value="manual">وقت محدد يدوياً</option>
                            <option value="fajr">🌅 وقت صلاة الفجر</option>
                            <option value="dhuhr">☀️ وقت صلاة الظهر</option>
                            <option value="maghrib">🌆 وقت صلاة المغرب</option>
                        </select>
                    </div>
                    <div class="form-row" id="manual-time-row">
                        <label>⏰ الوقت:</label>
                        <input type="time" id="schedule-time" class="time-input">
                    </div>
                    <div class="form-row" id="prayer-time-note" style="display: none;">
                        <div style="background: rgba(224,163,70,0.1); padding: 10px 15px; border-radius: 8px; border-right: 3px solid #e0a346;">
                            <span style="color: rgba(255,255,255,0.8); font-size: 0.9em;">
                                ⚡ سيتم تشغيل الصوت تلقائياً في وقت الصلاة المحدد حسب موقعك.
                                <br><small style="color: rgba(255,255,255,0.5);">تأكد من تحديد موقعك في تبويب "أوقات الصلاة"</small>
                            </span>
                        </div>
                    </div>
                    <div class="form-row">
                        <label>📆 الأيام:</label>
                        <div class="days-selector">
                            <label class="day-checkbox"><input type="checkbox" value="0" checked> الأحد</label>
                            <label class="day-checkbox"><input type="checkbox" value="1" checked> الإثنين</label>
                            <label class="day-checkbox"><input type="checkbox" value="2" checked> الثلاثاء</label>
                            <label class="day-checkbox"><input type="checkbox" value="3" checked> الأربعاء</label>
                            <label class="day-checkbox"><input type="checkbox" value="4" checked> الخميس</label>
                            <label class="day-checkbox"><input type="checkbox" value="5" checked> الجمعة</label>
                            <label class="day-checkbox"><input type="checkbox" value="6" checked> السبت</label>
                        </div>
                    </div>
                    <button class="btn btn-primary" onclick="addSchedule()" style="margin-top: 15px;">➕ إضافة جدولة</button>
                </div>
                
                <h4 style="color: #e0a346; margin-top: 30px; margin-bottom: 15px;">📋 الجدولات الحالية</h4>
                <div id="schedules-list" class="schedules-list"></div>
            </div>
        </div>
        
        <div id="prayer-tab" class="tab-content">
            <div class="doorbells-section">
                <h3>🕌 أوقات الصلاة</h3>
                <p style="color: rgba(255,255,255,0.6); margin-bottom: 20px;">حدد موقعك لمعرفة أوقات الصلاة وجدولة الأذان تلقائياً.</p>
                
                <div class="prayer-location-form">
                    <div class="form-row">
                        <label>🌍 الدولة:</label>
                        <select id="prayer-country" class="reader-select">
                            <option value="">-- اختر الدولة --</option>
                        </select>
                    </div>
                    <div class="form-row">
                        <label>🏙️ المدينة:</label>
                        <select id="prayer-city" class="reader-select" disabled>
                            <option value="">-- اختر المدينة --</option>
                        </select>
                    </div>
                    <button class="btn btn-primary" onclick="fetchPrayerTimes()" style="margin-top: 10px;">🔄 جلب أوقات الصلاة</button>
                </div>
                
                <div id="prayer-times-container" style="margin-top: 25px;">
                    <div class="prayer-times-grid" id="prayer-times-grid"></div>
                </div>
                
                <div id="prayer-calibration-note" style="display: none; margin-top: 15px; padding: 15px; background: rgba(224,163,70,0.1); border-radius: 10px; border-right: 3px solid #e0a346;">
                    <p style="color: rgba(255,255,255,0.8); font-size: 0.9em;">
                        💡 <strong>ملاحظة:</strong> يمكنك معايرة أوقات الصلاة بالضغط على + أو - لكل صلاة. سيتم حفظ المعايرة واستخدامها في الجدولة التلقائية.
                    </p>
                </div>
            </div>
        </div>
        ` : `
        <div class="login-section">
            <h2>مرحباً بك في نور الهدى</h2>
            <p>سجّل دخولك باستخدام حساب Amazon لتشغيل الأدعية على أجهزة Alexa</p>
            <a href="/login" class="btn btn-primary">تسجيل الدخول بحساب Amazon</a>
        </div>
        `}
    </div>
    
    <div class="toast" id="toast"></div>
    
    <script>
        const soundsData = ${soundsJSON};
        const isLoggedIn = ${user ? 'true' : 'false'};
        let doorbells = ${doorbellsJSON};
        let selectedDoorbellId = doorbells[0]?.id || 'default-trigger-001';
        let schedules = [];
        
        function showTab(tabName) {
            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
            event.target.classList.add('active');
            document.getElementById(tabName + '-tab').classList.add('active');
        }
        
        function renderDoorbellSelector() {
            const container = document.getElementById('doorbell-select');
            if (!container) return;
            container.innerHTML = doorbells.map(d => 
                '<div class="doorbell-item ' + (d.id === selectedDoorbellId ? 'selected' : '') + '" onclick="selectDoorbell(\\'' + d.id + '\\')">' +
                '🔔 ' + d.name + '</div>'
            ).join('');
        }
        
        function selectDoorbell(id) {
            selectedDoorbellId = id;
            renderDoorbellSelector();
            showToast('تم تحديد الجرس', 'success');
        }
        
        function renderDoorbellsList() {
            const container = document.getElementById('doorbells-list');
            if (!container) return;
            container.innerHTML = doorbells.map(d => 
                '<div class="doorbell-item">🔔 ' + d.name +
                (doorbells.length > 1 ? ' <button class="btn btn-danger" onclick="deleteDoorbell(\\'' + d.id + '\\')">🗑️</button>' : '') +
                '</div>'
            ).join('');
        }
        
        async function addDoorbell() {
            const inputAr = document.getElementById('new-doorbell-name');
            const inputEn = document.getElementById('new-doorbell-name-en');
            const nameAr = inputAr.value.trim();
            const nameEn = inputEn.value.trim();
            
            if (!nameAr && !nameEn) return showToast('أدخل اسم الجرس بالعربي أو الإنجليزي', 'error');
            
            try {
                const res = await fetch('/api/doorbells', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ 
                        name: nameAr || nameEn,
                        nameEn: nameEn || nameAr
                    })
                });
                const data = await res.json();
                if (data.success) {
                    doorbells = data.doorbells;
                    inputAr.value = '';
                    inputEn.value = '';
                    renderDoorbellsList();
                    renderDoorbellSelector();
                    showToast('تمت إضافة الجرس', 'success');
                }
            } catch (e) { showToast('حدث خطأ', 'error'); }
        }
        
        async function deleteDoorbell(id) {
            if (!confirm('هل تريد حذف هذا الجرس؟')) return;
            try {
                const res = await fetch('/api/doorbells/' + id, { method: 'DELETE' });
                const data = await res.json();
                if (data.success) {
                    doorbells = data.doorbells;
                    if (selectedDoorbellId === id) selectedDoorbellId = doorbells[0]?.id;
                    renderDoorbellsList();
                    renderDoorbellSelector();
                    showToast('تم حذف الجرس', 'success');
                }
            } catch (e) { showToast('حدث خطأ', 'error'); }
        }
        
        function renderSounds(filter = '') {
            const container = document.getElementById('sounds-container');
            if (!container) return;
            container.innerHTML = '';
            for (const key in soundsData) {
                const sound = soundsData[key];
                if (!sound.sounds || sound.sounds.length === 0) continue;
                if (filter && !sound.name.toLowerCase().includes(filter.toLowerCase())) continue;
                const card = document.createElement('div');
                card.className = 'sound-card';
                // إضافة خيار "عشوائي" في البداية
                const randomOption = '<option value="-1">🎲 عشوائي</option>';
                const options = sound.sounds.map((s, i) => '<option value="' + i + '">' + s.reader + '</option>').join('');
                card.innerHTML = 
                    '<div class="sound-header"><h3>' + sound.name + '</h3><span style="color: rgba(255,255,255,0.6);">' + sound.sounds.length + ' قارئ</span></div>' +
                    '<div class="sound-body"><select class="reader-select" id="reader-' + key + '">' + randomOption + options + '</select>' +
                    '<button class="btn btn-play" onclick="playSound(\\'' + key + '\\')">▶️ تشغيل</button></div>';
                container.appendChild(card);
            }
        }
        
        async function playSound(key) {
            const select = document.getElementById('reader-' + key);
            const sound = soundsData[key];
            
            // إذا لم يتم اختيار قارئ محدد، اختر عشوائياً
            let readerIndex;
            if (select && select.value !== '' && select.value !== '-1') {
                readerIndex = parseInt(select.value);
            } else {
                // اختيار عشوائي
                readerIndex = Math.floor(Math.random() * sound.sounds.length);
            }
            
            const reader = sound.sounds[readerIndex];
            if (!reader) return showToast('خطأ في تحميل الصوت', 'error');
            showToast('جاري الإرسال...', 'success');
            try {
                const res = await fetch('/api/schedule', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ 
                        audioUrl: reader.url, 
                        audioName: sound.name + ' - ' + reader.reader, 
                        doorbellId: selectedDoorbellId,
                        spokenTitle: sound.spokentitle || sound.name,
                        spokenReader: reader.spokenreader || reader.reader
                    })
                });
                const data = await res.json();
                if (data.success) {
                    showToast('تم إرسال ' + sound.name + ' بصوت ' + reader.reader, 'success');
                } else if (data.error === 'skill_not_linked') {
                    showToast('⚠️ يجب تفعيل المهارة في Alexa App أولاً', 'error');
                    alert(data.message);
                } else {
                    showToast('حدث خطأ', 'error');
                }
            } catch (e) { showToast('حدث خطأ في الاتصال', 'error'); }
        }
        
        function showToast(msg, type) {
            const toast = document.getElementById('toast');
            toast.textContent = msg;
            toast.className = 'toast ' + type + ' show';
            setTimeout(() => toast.className = 'toast', 3000);
        }
        
        const searchInput = document.getElementById('search');
        if (searchInput) searchInput.addEventListener('input', e => renderSounds(e.target.value));
        
        function initScheduleForm() {
            const duaaSelect = document.getElementById('schedule-duaa');
            if (!duaaSelect) return;
            for (const key in soundsData) {
                const opt = document.createElement('option');
                opt.value = key;
                opt.textContent = soundsData[key].name;
                duaaSelect.appendChild(opt);
            }
            const doorbellSelect = document.getElementById('schedule-doorbell');
            doorbells.forEach(d => {
                const opt = document.createElement('option');
                opt.value = d.id;
                opt.textContent = d.name;
                doorbellSelect.appendChild(opt);
            });
            duaaSelect.addEventListener('change', updateReaderOptions);
        }
        
        function updateReaderOptions() {
            const duaaKey = document.getElementById('schedule-duaa').value;
            const readerSelect = document.getElementById('schedule-reader');
            readerSelect.innerHTML = '<option value="">-- اختر القارئ --</option>';
            if (!duaaKey || !soundsData[duaaKey]) return;
            
            // إضافة خيار "عشوائي"
            const randomOpt = document.createElement('option');
            randomOpt.value = '-1';
            randomOpt.textContent = '🎲 عشوائي (كل يوم قارئ مختلف)';
            readerSelect.appendChild(randomOpt);
            
            // إضافة القراء
            soundsData[duaaKey].sounds.forEach((s, i) => {
                const opt = document.createElement('option');
                opt.value = i;
                opt.textContent = s.reader;
                readerSelect.appendChild(opt);
            });
        }
        
        async function addSchedule() {
            const duaaKey = document.getElementById('schedule-duaa').value;
            const readerIndex = document.getElementById('schedule-reader').value;
            const doorbellId = document.getElementById('schedule-doorbell').value;
            const timeType = document.getElementById('schedule-time-type').value;
            let time = document.getElementById('schedule-time').value;
            
            // إذا كان وقت صلاة، جلب الوقت
            if (timeType !== 'manual') {
                const prayerKey = timeType.charAt(0).toUpperCase() + timeType.slice(1);
                time = getPrayerTime(prayerKey);
                if (!time) {
                    showToast('يرجى تحديد موقعك في تبويب أوقات الصلاة أولاً', 'error');
                    return;
                }
            }
            
            if (!duaaKey || readerIndex === '' || !time) return showToast('يرجى ملء جميع الحقول', 'error');
            
            const duaa = soundsData[duaaKey];
            const isRandom = readerIndex === '-1';
            
            // إذا كان عشوائي، نحفظ -1 كـ readerIndex
            const reader = isRandom ? null : duaa.sounds[parseInt(readerIndex)];
            
            const days = [];
            document.querySelectorAll('.days-selector input:checked').forEach(cb => days.push(parseInt(cb.value)));
            if (days.length === 0) return showToast('يرجى اختيار يوم واحد على الأقل', 'error');
            
            const prayerNames = { fajr: 'الفجر', dhuhr: 'الظهر', maghrib: 'المغرب' };
            
            const schedule = {
                id: 'sch-' + Date.now(),
                duaaKey, 
                duaaName: duaa.name,
                spokenTitle: duaa.spokentitle || duaa.name,
                readerIndex: isRandom ? -1 : parseInt(readerIndex), 
                readerName: isRandom ? '🎲 عشوائي' : reader.reader,
                isRandom: isRandom,
                audioUrl: isRandom ? '' : reader.url, 
                doorbellId,
                doorbellName: doorbells.find(d => d.id === doorbellId)?.name || 'غير معروف',
                time, 
                timeType: timeType,
                prayerName: timeType !== 'manual' ? prayerNames[timeType] : null,
                days, 
                enabled: true
            };
            
            try {
                const res = await fetch('/api/schedules', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(schedule)
                });
                const data = await res.json();
                if (data.success) {
                    schedules = data.schedules;
                    renderSchedulesList();
                    showToast('تمت إضافة الجدولة', 'success');
                    document.getElementById('schedule-duaa').value = '';
                    document.getElementById('schedule-reader').innerHTML = '<option value="">-- اختر القارئ --</option>';
                    document.getElementById('schedule-time').value = '';
                }
            } catch (e) { showToast('حدث خطأ', 'error'); }
        }
        
        async function loadSchedules() {
            try {
                const res = await fetch('/api/schedules');
                const data = await res.json();
                schedules = data.schedules || [];
                renderSchedulesList();
            } catch (e) { console.error('Error loading schedules:', e); }
        }
        
        async function deleteSchedule(id) {
            if (!confirm('هل تريد حذف هذه الجدولة؟')) return;
            try {
                const res = await fetch('/api/schedules/' + id, { method: 'DELETE' });
                const data = await res.json();
                if (data.success) {
                    schedules = data.schedules;
                    renderSchedulesList();
                    showToast('تم حذف الجدولة', 'success');
                }
            } catch (e) { showToast('حدث خطأ', 'error'); }
        }
        
        async function toggleSchedule(id) {
            try {
                const res = await fetch('/api/schedules/' + id + '/toggle', { method: 'POST' });
                const data = await res.json();
                if (data.success) { schedules = data.schedules; renderSchedulesList(); }
            } catch (e) { showToast('حدث خطأ', 'error'); }
        }
        
        function renderSchedulesList() {
            const container = document.getElementById('schedules-list');
            if (!container) return;
            if (schedules.length === 0) {
                container.innerHTML = '<div class="no-schedules">لا توجد جدولات حالياً</div>';
                return;
            }
            const dayNames = ['الأحد', 'الإثنين', 'الثلاثاء', 'الأربعاء', 'الخميس', 'الجمعة', 'السبت'];
            container.innerHTML = schedules.map(s => {
                const daysText = s.days.length === 7 ? 'كل يوم' : s.days.map(d => dayNames[d]).join(', ');
                const timeDisplay = s.prayerName ? '🕌 ' + s.prayerName + ' (' + s.time + ')' : '⏰ ' + s.time;
                return '<div class="schedule-item" style="opacity: ' + (s.enabled ? '1' : '0.5') + '">' +
                    '<div class="schedule-info"><h4>' + s.duaaName + '</h4>' +
                    '<p>🎙️ ' + s.readerName + ' | 🔔 ' + s.doorbellName + '</p><p>📆 ' + daysText + '</p></div>' +
                    '<div class="schedule-time">' + timeDisplay + '</div>' +
                    '<div class="schedule-actions">' +
                    '<button class="btn btn-secondary" onclick="toggleSchedule(\\'' + s.id + '\\')">' + (s.enabled ? '⏸️' : '▶️') + '</button>' +
                    '<button class="btn btn-danger" onclick="deleteSchedule(\\'' + s.id + '\\')">🗑️</button></div></div>';
            }).join('');
        }
        
        if (isLoggedIn) {
            renderSounds();
            renderDoorbellSelector();
            renderDoorbellsList();
            initScheduleForm();
            loadSchedules();
            initPrayerTimes();
        }
        
        // ===== Prayer Times =====
        const COUNTRIES_CITIES = {
            'السعودية': ['الرياض', 'جدة', 'مكة المكرمة', 'المدينة المنورة', 'الدمام', 'الخبر', 'الأحساء', 'الظهران', 'القطيف', 'الجبيل', 'أبها', 'تبوك', 'بريدة', 'خميس مشيط', 'حائل', 'نجران', 'جازان', 'ينبع', 'الطائف', 'عنيزة', 'الخرج', 'سكاكا', 'عرعر', 'الباحة', 'حفر الباطن'],
            'مصر': ['القاهرة', 'الإسكندرية', 'الجيزة', 'بورسعيد', 'السويس', 'الأقصر', 'أسوان', 'المنصورة', 'طنطا', 'أسيوط', 'الإسماعيلية', 'الفيوم', 'الزقازيق', 'دمياط', 'المنيا', 'سوهاج'],
            'العراق': ['بغداد', 'البصرة', 'الموصل', 'أربيل', 'كركوك', 'النجف', 'كربلاء', 'السليمانية', 'الناصرية', 'العمارة', 'الديوانية', 'الكوت', 'الحلة', 'الرمادي', 'الفلوجة', 'سامراء', 'تكريت', 'دهوك'],
            'الأردن': ['عمان', 'الزرقاء', 'إربد', 'العقبة', 'مادبا', 'جرش', 'السلط', 'عجلون', 'الكرك', 'المفرق', 'الطفيلة', 'معان'],
            'الكويت': ['مدينة الكويت', 'حولي', 'السالمية', 'الجابرية', 'الفروانية', 'الأحمدي', 'الفحيحيل', 'المنقف', 'صباح السالم'],
            'لبنان': ['بيروت', 'طرابلس', 'صيدا', 'صور', 'زحلة', 'جونية', 'بعلبك', 'النبطية', 'جبيل', 'عاليه'],
            'فلسطين': ['القدس', 'غزة', 'رام الله', 'نابلس', 'الخليل', 'بيت لحم', 'خان يونس', 'رفح', 'جنين', 'طولكرم', 'قلقيلية', 'أريحا'],
            'سوريا': ['دمشق', 'حلب', 'حمص', 'اللاذقية', 'حماة', 'الرقة', 'دير الزور', 'الحسكة', 'القامشلي', 'طرطوس', 'درعا', 'إدلب'],
            'الإمارات': ['دبي', 'أبوظبي', 'الشارقة', 'عجمان', 'رأس الخيمة', 'الفجيرة', 'أم القيوين', 'العين', 'خورفكان'],
            'قطر': ['الدوحة', 'الوكرة', 'الريان', 'أم صلال', 'الخور', 'دخان', 'مسيعيد'],
            'البحرين': ['المنامة', 'المحرق', 'الرفاع', 'مدينة حمد', 'مدينة عيسى', 'سترة', 'البديع'],
            'عمان': ['مسقط', 'صلالة', 'صحار', 'نزوى', 'صور', 'عبري', 'السيب', 'البريمي', 'الرستاق', 'خصب'],
            'اليمن': ['صنعاء', 'عدن', 'تعز', 'الحديدة', 'المكلا', 'إب', 'ذمار', 'زنجبار', 'صعدة', 'مأرب'],
            'الجزائر': ['الجزائر', 'وهران', 'قسنطينة', 'عنابة', 'البليدة', 'باتنة', 'سطيف', 'الجلفة', 'سيدي بلعباس', 'تلمسان', 'بسكرة', 'تبسة'],
            'المغرب': ['الدار البيضاء', 'الرباط', 'فاس', 'مراكش', 'طنجة', 'أكادير', 'مكناس', 'وجدة', 'القنيطرة', 'تطوان', 'آسفي', 'الناظور'],
            'تونس': ['تونس', 'صفاقس', 'سوسة', 'القيروان', 'بنزرت', 'قابس', 'أريانة', 'قفصة', 'المنستير', 'بن عروس'],
            'ليبيا': ['طرابلس', 'بنغازي', 'مصراتة', 'البيضاء', 'الزاوية', 'طبرق', 'سبها', 'أجدابيا', 'درنة'],
            'السودان': ['الخرطوم', 'أم درمان', 'بورتسودان', 'كسلا', 'نيالا', 'الأبيض', 'القضارف', 'ود مدني', 'عطبرة'],
            'إيران': ['طهران', 'مشهد', 'أصفهان', 'كرج', 'شيراز', 'تبريز', 'قم', 'الأهواز', 'كرمانشاه', 'أرومية', 'رشت', 'زاهدان', 'همدان', 'يزد'],
            'تركيا': ['إسطنبول', 'أنقرة', 'إزمير', 'بورصة', 'أنطاليا', 'أضنة', 'قونية', 'غازي عنتاب', 'مرسين', 'قيصري', 'ديار بكر', 'سامسون'],
            'باكستان': ['كراتشي', 'لاهور', 'فيصل آباد', 'راولبندي', 'ملتان', 'إسلام آباد', 'بيشاور', 'كويتا', 'سيالكوت', 'غوجرانوالا', 'حيدر آباد', 'سكر'],
            'أفغانستان': ['كابل', 'قندهار', 'هرات', 'مزار شريف', 'جلال آباد', 'قندوز', 'غزني', 'لشكركاه'],
            'بنغلاديش': ['دكا', 'شيتاغونغ', 'خولنا', 'راجشاهي', 'سيلهت', 'باريسال', 'رانجبور', 'مايمنسينغ', 'كوميلا'],
            'ماليزيا': ['كوالالمبور', 'جورج تاون', 'إيبوه', 'جوهور باهرو', 'ملقا', 'شاه علم', 'بيتالينج جايا', 'كوتشينج', 'كوتا كينابالو', 'سرمبان'],
            'إندونيسيا': ['جاكرتا', 'سورابايا', 'باندونج', 'ميدان', 'سيمارانج', 'ماكاسار', 'باليمبانج', 'تانجيرانج', 'ديبوك', 'بيكاسي', 'بوجور', 'يوجياكارتا'],
            'الهند': ['دلهي', 'مومباي', 'كلكتا', 'بنغالور', 'حيدر آباد', 'تشيناي', 'أحمد آباد', 'بونه', 'سورات', 'جايبور', 'لكناو', 'كانبور']
        };
        
        // English names for API
        const CITY_EN_NAMES = {
            'الرياض': 'Riyadh', 'جدة': 'Jeddah', 'مكة المكرمة': 'Mecca', 'المدينة المنورة': 'Medina',
            'الدمام': 'Dammam', 'الخبر': 'Khobar', 'الأحساء': 'Al-Ahsa', 'الظهران': 'Dhahran',
            'القطيف': 'Qatif', 'الجبيل': 'Jubail', 'أبها': 'Abha', 'تبوك': 'Tabuk',
            'القاهرة': 'Cairo', 'الإسكندرية': 'Alexandria', 'بغداد': 'Baghdad', 'البصرة': 'Basra',
            'النجف': 'Najaf', 'كربلاء': 'Karbala', 'عمان': 'Amman', 'بيروت': 'Beirut',
            'دمشق': 'Damascus', 'دبي': 'Dubai', 'أبوظبي': 'Abu Dhabi', 'الدوحة': 'Doha',
            'المنامة': 'Manama', 'مسقط': 'Muscat', 'صنعاء': 'Sanaa', 'الجزائر': 'Algiers',
            'الرباط': 'Rabat', 'تونس': 'Tunis', 'طرابلس': 'Tripoli', 'الخرطوم': 'Khartoum',
            'طهران': 'Tehran', 'إسطنبول': 'Istanbul', 'كراتشي': 'Karachi', 'كابل': 'Kabul',
            'دكا': 'Dhaka', 'كوالالمبور': 'Kuala Lumpur', 'جاكرتا': 'Jakarta', 'دلهي': 'Delhi'
        };
        
        const COUNTRY_EN_NAMES = {
            'السعودية': 'Saudi Arabia', 'مصر': 'Egypt', 'العراق': 'Iraq', 'الأردن': 'Jordan',
            'الكويت': 'Kuwait', 'لبنان': 'Lebanon', 'فلسطين': 'Palestine', 'سوريا': 'Syria',
            'الإمارات': 'UAE', 'قطر': 'Qatar', 'البحرين': 'Bahrain', 'عمان': 'Oman',
            'اليمن': 'Yemen', 'الجزائر': 'Algeria', 'المغرب': 'Morocco', 'تونس': 'Tunisia',
            'ليبيا': 'Libya', 'السودان': 'Sudan', 'إيران': 'Iran', 'تركيا': 'Turkey',
            'باكستان': 'Pakistan', 'أفغانستان': 'Afghanistan', 'بنغلاديش': 'Bangladesh',
            'ماليزيا': 'Malaysia', 'إندونيسيا': 'Indonesia', 'الهند': 'India'
        };
        
        let prayerState = {
            country: localStorage.getItem('prayerCountry') || '',
            city: localStorage.getItem('prayerCity') || '',
            times: null,
            calibration: JSON.parse(localStorage.getItem('prayerCalibration') || '{"Fajr":0,"Dhuhr":0,"Maghrib":0}')
        };
        
        function initPrayerTimes() {
            const countrySelect = document.getElementById('prayer-country');
            const citySelect = document.getElementById('prayer-city');
            if (!countrySelect) return;
            
            // Populate countries
            Object.keys(COUNTRIES_CITIES).forEach(country => {
                const opt = document.createElement('option');
                opt.value = country;
                opt.textContent = country;
                if (country === prayerState.country) opt.selected = true;
                countrySelect.appendChild(opt);
            });
            
            countrySelect.addEventListener('change', (e) => {
                prayerState.country = e.target.value;
                prayerState.city = '';
                localStorage.setItem('prayerCountry', prayerState.country);
                populatePrayerCities();
            });
            
            citySelect.addEventListener('change', (e) => {
                prayerState.city = e.target.value;
                localStorage.setItem('prayerCity', prayerState.city);
            });
            
            if (prayerState.country) {
                populatePrayerCities();
                if (prayerState.city) {
                    fetchPrayerTimes();
                }
            }
        }
        
        function populatePrayerCities() {
            const citySelect = document.getElementById('prayer-city');
            citySelect.innerHTML = '<option value="">-- اختر المدينة --</option>';
            citySelect.disabled = false;
            
            if (prayerState.country && COUNTRIES_CITIES[prayerState.country]) {
                COUNTRIES_CITIES[prayerState.country].forEach(city => {
                    const opt = document.createElement('option');
                    opt.value = city;
                    opt.textContent = city;
                    if (city === prayerState.city) opt.selected = true;
                    citySelect.appendChild(opt);
                });
            }
        }
        
        async function fetchPrayerTimes() {
            const city = prayerState.city || document.getElementById('prayer-city').value;
            const country = prayerState.country || document.getElementById('prayer-country').value;
            
            if (!city || !country) {
                showToast('يرجى اختيار الدولة والمدينة', 'error');
                return;
            }
            
            prayerState.city = city;
            prayerState.country = country;
            localStorage.setItem('prayerCity', city);
            localStorage.setItem('prayerCountry', country);
            
            const cityEn = CITY_EN_NAMES[city] || city;
            const countryEn = COUNTRY_EN_NAMES[country] || country;
            
            showToast('جاري جلب أوقات الصلاة...', 'success');
            
            try {
                const url = 'https://api.aladhan.com/v1/timingsByCity?city=' + encodeURIComponent(cityEn) + '&country=' + encodeURIComponent(countryEn) + '&method=0';
                const response = await fetch(url);
                const data = await response.json();
                
                if (data.code === 200 && data.data && data.data.timings) {
                    prayerState.times = data.data.timings;
                    displayPrayerTimes();
                    showToast('تم جلب أوقات الصلاة بنجاح', 'success');
                } else {
                    throw new Error('بيانات غير صحيحة');
                }
            } catch (error) {
                console.error('Error fetching prayer times:', error);
                showToast('حدث خطأ في جلب أوقات الصلاة', 'error');
            }
        }
        
        function displayPrayerTimes() {
            const container = document.getElementById('prayer-times-grid');
            const note = document.getElementById('prayer-calibration-note');
            if (!container || !prayerState.times) return;
            
            note.style.display = 'block';
            
            const prayers = [
                { key: 'Fajr', name: 'الفجر', icon: '🌅' },
                { key: 'Dhuhr', name: 'الظهر', icon: '☀️' },
                { key: 'Maghrib', name: 'المغرب', icon: '🌆' }
            ];
            
            container.innerHTML = prayers.map(prayer => {
                const time = prayerState.times[prayer.key];
                const offset = prayerState.calibration[prayer.key] || 0;
                const adjustedTime = adjustPrayerTime(time, offset);
                
                return '<div class="prayer-card">' +
                    '<div class="prayer-icon">' + prayer.icon + '</div>' +
                    '<div class="prayer-name">' + prayer.name + '</div>' +
                    '<div class="prayer-time">' + adjustedTime + '</div>' +
                    '<div class="calibration-controls">' +
                        '<button class="calibration-btn" onclick="adjustCalibration(\\'' + prayer.key + '\\', -1)">−</button>' +
                        '<span class="calibration-value">' + (offset > 0 ? '+' : '') + offset + ' د</span>' +
                        '<button class="calibration-btn" onclick="adjustCalibration(\\'' + prayer.key + '\\', 1)">+</button>' +
                    '</div>' +
                '</div>';
            }).join('');
        }
        
        function adjustPrayerTime(timeStr, offsetMinutes) {
            const [hours, minutes] = timeStr.split(':').map(Number);
            const totalMinutes = hours * 60 + minutes + offsetMinutes;
            const adjustedHours = Math.floor((totalMinutes + 1440) % 1440 / 60);
            const adjustedMinutes = ((totalMinutes + 1440) % 1440) % 60;
            return String(adjustedHours).padStart(2, '0') + ':' + String(adjustedMinutes).padStart(2, '0');
        }
        
        function adjustCalibration(prayerKey, delta) {
            prayerState.calibration[prayerKey] = (prayerState.calibration[prayerKey] || 0) + delta;
            localStorage.setItem('prayerCalibration', JSON.stringify(prayerState.calibration));
            displayPrayerTimes();
        }
        
        function getPrayerTime(prayerKey) {
            if (!prayerState.times || !prayerState.times[prayerKey]) return null;
            const offset = prayerState.calibration[prayerKey] || 0;
            return adjustPrayerTime(prayerState.times[prayerKey], offset);
        }
        
        function toggleTimeInput() {
            const timeType = document.getElementById('schedule-time-type').value;
            const manualRow = document.getElementById('manual-time-row');
            const prayerNote = document.getElementById('prayer-time-note');
            const timeInput = document.getElementById('schedule-time');
            
            if (timeType === 'manual') {
                manualRow.style.display = 'flex';
                prayerNote.style.display = 'none';
                timeInput.value = '';
            } else {
                manualRow.style.display = 'none';
                prayerNote.style.display = 'block';
                
                // Get prayer time
                const prayerKey = timeType.charAt(0).toUpperCase() + timeType.slice(1);
                const prayerTime = getPrayerTime(prayerKey);
                if (prayerTime) {
                    timeInput.value = prayerTime;
                } else {
                    showToast('يرجى تحديد موقعك في تبويب أوقات الصلاة أولاً', 'error');
                }
            }
        }
    </script>
</body>
</html>`;
}

// Vercel handler
if (process.env.NODE_ENV !== 'production') {
    app.listen(PORT, () => {
        console.log('Server running on port ' + PORT);
    });
}

module.exports = app;
