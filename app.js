/**
 * Noor Al-Huda Web Application v9
 * تطبيق ويب محسّن لإدارة مهارة نور الهدى
 * 
 * الميزات:
 * - جلب الأصوات من JSON محلي أو خارجي
 * - قوائم منسدلة للقراء
 * - إدارة الأجراس
 * - جدولة الأصوات
 * - تشغيل فوري عبر Alexa
 */

require('dotenv').config();
const express = require('express');
const session = require('express-session');
const axios = require('axios');
const { DynamoDBClient, PutItemCommand, GetItemCommand, UpdateItemCommand, DeleteItemCommand, ScanCommand } = require('@aws-sdk/client-dynamodb');
const fs = require('fs');
const path = require('path');

const app = express();
//const PORT = process.env.PORT || 3000;
if (process.env.NODE_ENV !== 'production') {
    app.listen(PORT, () => {
        console.log(`Server is running on port ${PORT}`);
    });
}


// ====== الإعدادات ======
const config = {
    lwaClientId: process.env.LWA_CLIENT_ID,
    lwaClientSecret: process.env.LWA_CLIENT_SECRET,
    alexaClientId: process.env.ALEXA_CLIENT_ID,
    alexaClientSecret: process.env.ALEXA_CLIENT_SECRET,
    redirectUri: process.env.REDIRECT_URI || 'http://localhost:3000/auth/callback',
    baseUrl: process.env.BASE_URL || 'http://localhost:3000',
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
app.use(session({
    secret: process.env.SESSION_SECRET || 'noor-alhuda-secret-2024',
    resave: true,
    saveUninitialized: true,
    cookie: { secure: false, httpOnly: true, maxAge: 7 * 24 * 60 * 60 * 1000 }
}));

// ====== الصفحة الرئيسية ======
app.get('/', async (req, res) => {
    const user = req.session.user;
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
        
        // Get Alexa token for sending events
        let alexaToken = null;
        try {
            const alexaTokenResponse = await axios.post('https://api.amazon.com/auth/o2/token',
                new URLSearchParams({
                    grant_type: 'client_credentials',
                    client_id: config.alexaClientId,
                    client_secret: config.alexaClientSecret,
                    scope: 'alexa::proactive_events'
                }), {
                    headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
                }
            );
            alexaToken = alexaTokenResponse.data.access_token;
            console.log('✅ Got Alexa token');
        } catch (e) {
            console.log('⚠️ Could not get Alexa token:', e.message);
        }
        
        // Save to session
        req.session.user = {
            id: profile.user_id,
            name: profile.name,
            email: profile.email,
            accessToken: access_token,
            refreshToken: refresh_token,
            alexaToken: alexaToken
        };
        
        // Check if user already has Alexa token from Smart Home Authorization
        const existingUser = await getUserData(profile.user_id);
        
        // Save to DynamoDB - but DON'T overwrite Alexa tokens!
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
                alexaToken: alexaToken || '',
                userName: profile.name || '',
                userEmail: profile.email || '',
                doorbells: defaultDoorbells
            });
        }
        
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
    req.session.destroy();
    res.redirect('/');
});

// ====== API: Schedule Audio ======
app.post('/api/schedule', async (req, res) => {
    const user = req.session.user;
    if (!user) return res.status(401).json({ error: 'Not authenticated' });
    
    const { audioUrl, audioName, doorbellId } = req.body;
    if (!audioUrl) return res.status(400).json({ error: 'Audio URL required' });
    
    try {
        // Save scheduled audio
        await scheduleAudio(user.id, { audioUrl, audioName, doorbellId });
        
        // Send doorbell event
        const sent = await sendDoorbellEvent(user.id, doorbellId || 'default-trigger-001');
        
        if (!sent) {
            return res.json({ 
                success: false, 
                doorbellSent: false,
                error: 'skill_not_linked',
                message: 'يجب تفعيل المهارة في تطبيق Alexa أولاً. افتح Alexa App → Skills → ابحث عن المهارة → Enable → ثم قل "Alexa, discover my devices"'
            });
        }
        
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
    
    const { name } = req.body;
    if (!name) return res.status(400).json({ error: 'Name required' });
    
    const userData = await getUserData(user.id);
    const doorbells = userData?.doorbells || [];
    
    const newDoorbell = {
        id: 'doorbell-' + Date.now().toString(36),
        name: name,
        nameEn: name
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
    
    const userData = await getUserData(user.id);
    const schedules = userData?.schedules || [];
    
    schedules.push(schedule);
    await updateUserSchedules(user.id, schedules);
    
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
async function sendDoorbellEvent(visitorId, doorbellId) {
    try {
        // أولاً: جرب التوكن الخاص بالمستخدم
        let userData = await getUserData(visitorId);
        
        // ثانياً: إذا لم يعمل، ابحث عن أي توكن صالح في قاعدة البيانات
        // (التوكن الصحيح يأتي من Lambda عند Authorization)
        if (!userData?.accessToken) {
            console.log('No token for user, searching for valid token...');
            userData = await findValidToken();
        }
        
        if (!userData?.accessToken) {
            console.log('❌ No access token found');
            return false;
        }
        
        // محاولة إرسال الحدث
        let success = await tryDoorbellEvent(userData.accessToken, doorbellId);
        
        // إذا فشل، حاول تجديد التوكن
        if (!success && userData.refreshToken) {
            console.log('🔄 Token expired, refreshing...');
            const newToken = await refreshAccessToken(userData.refreshToken);
            
            if (newToken) {
                // حفظ التوكن الجديد
                await updateUserToken(userData.visitorId || visitorId, newToken.access_token, newToken.refresh_token);
                
                // إعادة المحاولة
                success = await tryDoorbellEvent(newToken.access_token, doorbellId);
            }
        }
        
        // إذا لا يزال لا يعمل، جرب البحث عن توكن آخر
        if (!success) {
            console.log('🔍 Searching for another valid token...');
            const otherUser = await findValidToken(userData.visitorId);
            if (otherUser?.accessToken) {
                success = await tryDoorbellEvent(otherUser.accessToken, doorbellId);
                
                if (!success && otherUser.refreshToken) {
                    const newToken = await refreshAccessToken(otherUser.refreshToken);
                    if (newToken) {
                        await updateUserToken(otherUser.visitorId, newToken.access_token, newToken.refresh_token);
                        success = await tryDoorbellEvent(newToken.access_token, doorbellId);
                    }
                }
            }
        }
        
        return success;
    } catch (error) {
        console.error('Doorbell Error:', error.response?.data || error.message);
        return false;
    }
}

// البحث عن توكن صالح في قاعدة البيانات
async function findValidToken(excludeVisitorId = null) {
    try {
        const result = await dynamoClient.send(new ScanCommand({
            TableName: config.dynamoTable
        }));
        
        if (!result.Items) return null;
        
        // ابحث عن أول مستخدم لديه توكن
        for (const item of result.Items) {
            const vid = item.visitorId?.S;
            if (excludeVisitorId && vid === excludeVisitorId) continue;
            
            if (item.accessToken?.S) {
                console.log('Found token for:', vid);
                return {
                    visitorId: vid,
                    accessToken: item.accessToken.S,
                    refreshToken: item.refreshToken?.S
                };
            }
        }
        
        return null;
    } catch (error) {
        console.error('findValidToken Error:', error);
        return null;
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
        
        // إذا كان الخطأ بسبب التوكن، نرجع false للتجديد
        if (errorData?.payload?.code === 'INVALID_ACCESS_TOKEN_EXCEPTION') {
            return false;
        }
        
        // أخطاء أخرى
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
            alexaToken: { S: data.alexaToken || '' },
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
            alexaToken: result.Item.alexaToken?.S,
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

// تحديث معلومات المستخدم فقط (بدون التوكنات)
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
    await dynamoClient.send(new PutItemCommand({
        TableName: config.scheduleTable,
        Item: {
            visitorId: { S: visitorId },
            audioUrl: { S: data.audioUrl },
            audioName: { S: data.audioName || 'Unknown' },
            doorbellId: { S: data.doorbellId || 'default-trigger-001' },
            updatedAt: { S: new Date().toISOString() }
        }
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
        
        /* Tabs */
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
        
        /* Doorbells */
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
        
        /* Sounds Grid */
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
        
        /* Dropdown */
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
        
        /* Search */
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
        
        /* Login */
        .login-section {
            text-align: center;
            padding: 60px 20px;
            background: rgba(255,255,255,0.05);
            border-radius: 20px;
        }
        .login-section h2 { color: #e0a346; margin-bottom: 20px; }
        .login-section p { color: rgba(255,255,255,0.7); margin-bottom: 30px; }
        
        /* Toast */
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
        
        /* Schedule Form */
        .schedule-form {
            background: rgba(255,255,255,0.05);
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 20px;
        }
        .form-row {
            margin-bottom: 15px;
        }
        .form-row label {
            display: block;
            margin-bottom: 8px;
            color: rgba(255,255,255,0.8);
        }
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
        .time-input::-webkit-calendar-picker-indicator {
            filter: invert(1);
        }
        .days-selector {
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
        }
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
        .day-checkbox:has(input:checked) {
            background: rgba(224,163,70,0.3);
            border: 1px solid #e0a346;
        }
        .day-checkbox input {
            accent-color: #e0a346;
        }
        
        /* Schedules List */
        .schedules-list {
            display: flex;
            flex-direction: column;
            gap: 10px;
        }
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
        .schedule-info {
            flex: 1;
        }
        .schedule-info h4 {
            color: #e0a346;
            margin-bottom: 5px;
        }
        .schedule-info p {
            color: rgba(255,255,255,0.6);
            font-size: 0.9em;
        }
        .schedule-time {
            background: rgba(224,163,70,0.2);
            padding: 8px 15px;
            border-radius: 8px;
            color: #e0a346;
            font-weight: 700;
            font-size: 1.2em;
        }
        .schedule-actions {
            display: flex;
            gap: 10px;
        }
        .no-schedules {
            text-align: center;
            padding: 30px;
            color: rgba(255,255,255,0.5);
        }
        .toast.show { display: block; animation: slideUp 0.3s ease; }
        
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
        
        <!-- Tabs -->
        <div class="tabs">
            <button class="tab active" onclick="showTab('sounds')">🎵 الأصوات</button>
            <button class="tab" onclick="showTab('doorbells')">🔔 الأجراس</button>
            <button class="tab" onclick="showTab('schedule')">📅 الجدولة</button>
        </div>
        
        <!-- Sounds Tab -->
        <div id="sounds-tab" class="tab-content active">
            <!-- Current Doorbell -->
            <div class="doorbells-section">
                <h3>🔔 الجرس المحدد للتشغيل</h3>
                <div class="doorbell-list" id="doorbell-select">
                    <!-- Filled by JS -->
                </div>
            </div>
            
            <input type="text" class="search-box" id="search" placeholder="🔍 ابحث عن دعاء...">
            
            <div class="sounds-grid" id="sounds-container">
                <!-- Filled by JS -->
            </div>
        </div>
        
        <!-- Doorbells Tab -->
        <div id="doorbells-tab" class="tab-content">
            <div class="doorbells-section">
                <h3>🔔 إدارة الأجراس</h3>
                <p style="color: rgba(255,255,255,0.6); margin-bottom: 15px;">
                    أضف أجراس متعددة لغرف مختلفة. عند تشغيل صوت، سيعمل على الجرس المحدد.
                </p>
                <div class="doorbell-list" id="doorbells-list">
                    <!-- Filled by JS -->
                </div>
                <div class="add-doorbell">
                    <input type="text" id="new-doorbell-name" placeholder="اسم الجرس الجديد...">
                    <button class="btn btn-primary" onclick="addDoorbell()">➕ إضافة</button>
                </div>
            </div>
        </div>
        
        <!-- Schedule Tab -->
        <div id="schedule-tab" class="tab-content">
            <div class="doorbells-section">
                <h3>📅 جدولة الأصوات</h3>
                <p style="color: rgba(255,255,255,0.6); margin-bottom: 20px;">
                    جدولة تشغيل الأدعية في أوقات محددة يومياً.
                </p>
                
                <!-- Add Schedule Form -->
                <div class="schedule-form">
                    <div class="form-row">
                        <label>🎵 الدعاء:</label>
                        <select id="schedule-duaa" class="reader-select">
                            <option value="">-- اختر الدعاء --</option>
                        </select>
                    </div>
                    <div class="form-row">
                        <label>🎙️ القارئ:</label>
                        <select id="schedule-reader" class="reader-select">
                            <option value="">-- اختر القارئ --</option>
                        </select>
                    </div>
                    <div class="form-row">
                        <label>🔔 الجرس:</label>
                        <select id="schedule-doorbell" class="reader-select">
                        </select>
                    </div>
                    <div class="form-row">
                        <label>⏰ الوقت:</label>
                        <input type="time" id="schedule-time" class="time-input">
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
                
                <!-- Scheduled Items List -->
                <h4 style="color: #e0a346; margin-top: 30px; margin-bottom: 15px;">📋 الجدولات الحالية</h4>
                <div id="schedules-list" class="schedules-list">
                    <!-- Filled by JS -->
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
        
        // Tabs
        function showTab(tabName) {
            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
            
            event.target.classList.add('active');
            document.getElementById(tabName + '-tab').classList.add('active');
        }
        
        // Render doorbell selector
        function renderDoorbellSelector() {
            const container = document.getElementById('doorbell-select');
            if (!container) return;
            
            container.innerHTML = doorbells.map(d => 
                '<div class="doorbell-item ' + (d.id === selectedDoorbellId ? 'selected' : '') + '" onclick="selectDoorbell(\\'' + d.id + '\\')">' +
                '🔔 ' + d.name +
                '</div>'
            ).join('');
        }
        
        function selectDoorbell(id) {
            selectedDoorbellId = id;
            renderDoorbellSelector();
            showToast('تم تحديد الجرس', 'success');
        }
        
        // Render doorbells management
        function renderDoorbellsList() {
            const container = document.getElementById('doorbells-list');
            if (!container) return;
            
            container.innerHTML = doorbells.map(d => 
                '<div class="doorbell-item">' +
                '🔔 ' + d.name +
                (doorbells.length > 1 ? ' <button class="btn btn-danger" onclick="deleteDoorbell(\\'' + d.id + '\\')">🗑️</button>' : '') +
                '</div>'
            ).join('');
        }
        
        // Add doorbell
        async function addDoorbell() {
            const input = document.getElementById('new-doorbell-name');
            const name = input.value.trim();
            if (!name) return showToast('أدخل اسم الجرس', 'error');
            
            try {
                const res = await fetch('/api/doorbells', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ name })
                });
                const data = await res.json();
                if (data.success) {
                    doorbells = data.doorbells;
                    input.value = '';
                    renderDoorbellsList();
                    renderDoorbellSelector();
                    showToast('تمت إضافة الجرس', 'success');
                }
            } catch (e) {
                showToast('حدث خطأ', 'error');
            }
        }
        
        // Delete doorbell
        async function deleteDoorbell(id) {
            if (!confirm('هل تريد حذف هذا الجرس؟')) return;
            
            try {
                const res = await fetch('/api/doorbells/' + id, { method: 'DELETE' });
                const data = await res.json();
                if (data.success) {
                    doorbells = data.doorbells;
                    if (selectedDoorbellId === id) {
                        selectedDoorbellId = doorbells[0]?.id;
                    }
                    renderDoorbellsList();
                    renderDoorbellSelector();
                    showToast('تم حذف الجرس', 'success');
                }
            } catch (e) {
                showToast('حدث خطأ', 'error');
            }
        }
        
        // Render sounds
        function renderSounds(filter = '') {
            const container = document.getElementById('sounds-container');
            if (!container) return;
            
            container.innerHTML = '';
            
            for (const key in soundsData) {
                const sound = soundsData[key];
                if (!sound.sounds || sound.sounds.length === 0) continue;
                
                // Filter
                if (filter && !sound.name.toLowerCase().includes(filter.toLowerCase())) continue;
                
                const card = document.createElement('div');
                card.className = 'sound-card';
                
                // Build reader options
                const options = sound.sounds.map((s, i) => 
                    '<option value="' + i + '">' + s.reader + '</option>'
                ).join('');
                
                card.innerHTML = 
                    '<div class="sound-header">' +
                        '<h3>' + sound.name + '</h3>' +
                        '<span style="color: rgba(255,255,255,0.6);">' + sound.sounds.length + ' قارئ</span>' +
                    '</div>' +
                    '<div class="sound-body">' +
                        '<select class="reader-select" id="reader-' + key + '">' + options + '</select>' +
                        '<button class="btn btn-play" onclick="playSound(\\'' + key + '\\')">▶️ تشغيل</button>' +
                    '</div>';
                
                container.appendChild(card);
            }
        }
        
        // Play sound
        async function playSound(key) {
            const select = document.getElementById('reader-' + key);
            const sound = soundsData[key];
            const readerIndex = select ? parseInt(select.value) : 0;
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
                        doorbellId: selectedDoorbellId
                    })
                });
                
                const data = await res.json();
                if (data.success) {
                    showToast('تم إرسال ' + sound.name + ' إلى Alexa', 'success');
                } else if (data.error === 'skill_not_linked') {
                    showToast('⚠️ يجب تفعيل المهارة في Alexa App أولاً', 'error');
                    alert(data.message);
                } else {
                    showToast('حدث خطأ', 'error');
                }
            } catch (e) {
                showToast('حدث خطأ في الاتصال', 'error');
            }
        }
        
        // Toast
        function showToast(msg, type) {
            const toast = document.getElementById('toast');
            toast.textContent = msg;
            toast.className = 'toast ' + type + ' show';
            setTimeout(() => toast.className = 'toast', 3000);
        }
        
        // Search
        const searchInput = document.getElementById('search');
        if (searchInput) {
            searchInput.addEventListener('input', e => renderSounds(e.target.value));
        }
        
        // Init
        if (isLoggedIn) {
            renderSounds();
            renderDoorbellSelector();
            renderDoorbellsList();
            initScheduleForm();
            loadSchedules();
        }
        
        // ====== Schedule Functions ======
        let schedules = [];
        
        function initScheduleForm() {
            // Fill duaa dropdown
            const duaaSelect = document.getElementById('schedule-duaa');
            if (!duaaSelect) return;
            
            for (const key in soundsData) {
                const opt = document.createElement('option');
                opt.value = key;
                opt.textContent = soundsData[key].name;
                duaaSelect.appendChild(opt);
            }
            
            // Fill doorbell dropdown
            const doorbellSelect = document.getElementById('schedule-doorbell');
            doorbells.forEach(d => {
                const opt = document.createElement('option');
                opt.value = d.id;
                opt.textContent = d.name;
                doorbellSelect.appendChild(opt);
            });
            
            // Update readers when duaa changes
            duaaSelect.addEventListener('change', updateReaderOptions);
        }
        
        function updateReaderOptions() {
            const duaaKey = document.getElementById('schedule-duaa').value;
            const readerSelect = document.getElementById('schedule-reader');
            readerSelect.innerHTML = '<option value="">-- اختر القارئ --</option>';
            
            if (!duaaKey || !soundsData[duaaKey]) return;
            
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
            const time = document.getElementById('schedule-time').value;
            
            if (!duaaKey || readerIndex === '' || !time) {
                return showToast('يرجى ملء جميع الحقول', 'error');
            }
            
            const duaa = soundsData[duaaKey];
            const reader = duaa.sounds[parseInt(readerIndex)];
            
            // Get selected days
            const days = [];
            document.querySelectorAll('.days-selector input:checked').forEach(cb => {
                days.push(parseInt(cb.value));
            });
            
            if (days.length === 0) {
                return showToast('يرجى اختيار يوم واحد على الأقل', 'error');
            }
            
            const schedule = {
                id: 'sch-' + Date.now(),
                duaaKey,
                duaaName: duaa.name,
                readerIndex: parseInt(readerIndex),
                readerName: reader.reader,
                audioUrl: reader.url,
                doorbellId,
                doorbellName: doorbells.find(d => d.id === doorbellId)?.name || 'غير معروف',
                time,
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
                    
                    // Reset form
                    document.getElementById('schedule-duaa').value = '';
                    document.getElementById('schedule-reader').innerHTML = '<option value="">-- اختر القارئ --</option>';
                    document.getElementById('schedule-time').value = '';
                }
            } catch (e) {
                showToast('حدث خطأ', 'error');
            }
        }
        
        async function loadSchedules() {
            try {
                const res = await fetch('/api/schedules');
                const data = await res.json();
                schedules = data.schedules || [];
                renderSchedulesList();
            } catch (e) {
                console.error('Error loading schedules:', e);
            }
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
            } catch (e) {
                showToast('حدث خطأ', 'error');
            }
        }
        
        async function toggleSchedule(id) {
            try {
                const res = await fetch('/api/schedules/' + id + '/toggle', { method: 'POST' });
                const data = await res.json();
                if (data.success) {
                    schedules = data.schedules;
                    renderSchedulesList();
                }
            } catch (e) {
                showToast('حدث خطأ', 'error');
            }
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
                return '<div class="schedule-item" style="opacity: ' + (s.enabled ? '1' : '0.5') + '">' +
                    '<div class="schedule-info">' +
                        '<h4>' + s.duaaName + '</h4>' +
                        '<p>🎙️ ' + s.readerName + ' | 🔔 ' + s.doorbellName + '</p>' +
                        '<p>📆 ' + daysText + '</p>' +
                    '</div>' +
                    '<div class="schedule-time">⏰ ' + s.time + '</div>' +
                    '<div class="schedule-actions">' +
                        '<button class="btn btn-secondary" onclick="toggleSchedule(\\'' + s.id + '\\')">' + (s.enabled ? '⏸️' : '▶️') + '</button>' +
                        '<button class="btn btn-danger" onclick="deleteSchedule(\\'' + s.id + '\\')">🗑️</button>' +
                    '</div>' +
                '</div>';
            }).join('');
        }
    </script>
</body>
</html>`;
}

// ====== Start Server ======
app.listen(PORT, () => {
    console.log('='.repeat(50));
    console.log('   نور الهدى - Noor Al-Huda v9');
    console.log('='.repeat(50));
    console.log('   Server: http://localhost:' + PORT);
    console.log('   Sounds: ' + (localSoundsData ? 'Local file' : config.soundsJsonUrl));
    console.log('   Scheduler: AWS CloudWatch + Lambda');
    console.log('='.repeat(50));
});
module.exports = app;
