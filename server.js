const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const axios = require('axios');
const path = require('path');
require('dotenv').config();

// ==================== EXPRESS APP ====================
const app = express();
const PORT = process.env.PORT || 3000;

// ==================== MONGOOSE SCHEMAS ====================
// SYNC NOTE: This schema is kept aligned with bot.js's User schema so both services
// (the Telegram bot and this verification API) read/write the same fields consistently
// on the same MongoDB collection. Added `verificationBypassed` and `bypassReason`
// (present in bot.js, missing here before) so an admin bypass granted from the bot's
// Admin Panel -> Device Verification -> "Remove Restrictions" flow is respected here too.

const botConfigSchema = new mongoose.Schema({
    key: { type: String, required: true, unique: true, default: 'main_config' },
    isMaintenanceMode: { type: Boolean, default: false },
    referPoints: { type: Number, default: 10 },
    referredBonusPoints: { type: Number, default: 5 },
    subCost: { type: Number, default: 50 },
    subDurationHours: { type: Number, default: 24 },
    contactAdmin: { type: String, default: '@DevilAdmin' },
    admins: { type: [String], default: [] },
    isDepositEnabled: { type: Boolean, default: true },
    minDepositAmount: { type: Number, default: 100 },
    qrImageUrl: { type: String, default: 'https://placehold.co/400x400?text=Scan+to+Pay' },
    paymentVerifyApiUrl: { type: String, default: 'https://api.yoursite.com/verify?orderid={orderid}' },
    miniAppUrl: { type: String, default: 'https://your-api-domain.com/verify-mini-app.html' },
    numberPanelUrl: { type: String, default: 'https://your-number-panel.com' },
    requireDeviceVerification: { type: Boolean, default: true }
});
const BotConfig = mongoose.model('BotConfig', botConfigSchema);

const userSchema = new mongoose.Schema({
    userId: { type: String, required: true, unique: true, index: true },
    username: { type: String, default: '' },
    firstName: { type: String, default: '' },
    lastName: { type: String, default: '' },
    points: { type: Number, default: 0 },
    totalReferrals: { type: Number, default: 0 },
    subscriptionExpires: { type: Date, default: null },
    referredBy: { type: String, default: null },
    isReferralVerified: { type: Boolean, default: false },
    joinedAt: { type: Date, default: Date.now },
    lastActive: { type: Date, default: Date.now },
    isBanned: { type: Boolean, default: false },
    deviceFingerprint: { type: String, default: null },
    deviceIP: { type: String, default: null },
    isDeviceVerified: { type: Boolean, default: false },
    deviceVerifiedAt: { type: Date, default: null },
    deviceUserAgent: { type: String, default: null },
    devicePlatform: { type: String, default: null },
    deviceScreen: { type: String, default: null },
    deviceTimezone: { type: String, default: null },
    // SYNC FIX: added — these exist in bot.js's schema (used by the Admin Panel's
    // Device Verification bypass flow) but were missing here, so a bypass granted
    // in the bot was invisible to this API.
    verificationBypassed: { type: Boolean, default: false },
    bypassReason: { type: String, default: null },
    isPromoRestricted: { type: Boolean, default: false }
});
const User = mongoose.model('User', userSchema);

const referralSchema = new mongoose.Schema({
    referrerId: { type: String, required: true, index: true },
    referredId: { type: String, required: true, unique: true },
    pointsEarned: { type: Number, default: 0 },
    friendPointsEarned: { type: Number, default: 0 },
    status: { type: String, enum: ['pending', 'verified', 'blocked_multi_device'], default: 'pending' },
    createdAt: { type: Date, default: Date.now }
});
const Referral = mongoose.model('Referral', referralSchema);

const transactionSchema = new mongoose.Schema({
    txnId: { type: String, required: true, unique: true, index: true },
    userId: { type: String, required: true, index: true },
    type: { type: String, enum: ['Deposit', 'Referral', 'PromoCode', 'SubscriptionBuy', 'AdminCredit', 'AdminDebit'], required: true },
    amount: { type: Number, default: 0 },
    pointsMeta: { type: Number, required: true },
    status: { type: String, enum: ['Success', 'Failed', 'Pending', 'Cancelled'], default: 'Success' },
    description: { type: String, default: '' },
    createdAt: { type: Date, default: Date.now }
});
const Transaction = mongoose.model('Transaction', transactionSchema);

const deviceFingerprintSchema = new mongoose.Schema({
    fingerprint: { type: String, required: true, index: true },
    userId: { type: String, required: true, index: true },
    ipAddress: { type: String, default: null },
    userAgent: { type: String, default: null },
    platform: { type: String, default: null },
    screenResolution: { type: String, default: null },
    timezone: { type: String, default: null },
    isActive: { type: Boolean, default: true },
    blocked: { type: Boolean, default: false },
    createdAt: { type: Date, default: Date.now },
    lastUsed: { type: Date, default: Date.now }
});
deviceFingerprintSchema.index({ fingerprint: 1, userId: 1 }, { unique: true });
const DeviceFingerprint = mongoose.model('DeviceFingerprint', deviceFingerprintSchema);

// ==================== CONFIG ====================
const MONGODB_URI = process.env.MONGODB_URI || 'YOUR_MONGODB_URI';
const BOT_TOKEN = process.env.BOT_TOKEN || 'YOUR_BOT_TOKEN';
// SYNC FIX: bot.js always guarantees the root owner is included in every admin alert
// (deduped with the configured admins list) so alerts never depend solely on the
// `admins` array in BotConfig. Mirrored here for the security alert below.
const ROOT_OWNER_ID = '1807697106';

// ==================== MIDDLEWARE ====================
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'", 'https://telegram.org', 'https://*.telegram.org'],
            connectSrc: ["'self'", 'https://api.ipify.org', 'https://*.telegram.org'],
            styleSrc: ["'self'", "'unsafe-inline'"],
            imgSrc: ["'self'", 'data:', 'https:'],
            fontSrc: ["'self'", 'data:', 'https:'],
            frameSrc: ["'self'", 'https://telegram.org', 'https://*.telegram.org'],
            objectSrc: ["'none'"],
            baseUri: ["'self'"]
        }
    }
}));
app.use(cors({
    origin: '*',
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));

const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: { success: false, message: 'Too many requests, please try again later.' }
});
app.use('/api/', limiter);

// ==================== DATABASE CONNECTION ====================
async function connectDB() {
    try {
        await mongoose.connect(MONGODB_URI, {
            serverSelectionTimeoutMS: 5000,
            socketTimeoutMS: 45000,
        });
        console.log('✅ MongoDB Connected Successfully');
        await initDefaultConfig();
    } catch (err) {
        console.error('MongoDB Connection Error:', err.message);
        process.exit(1);
    }
}

async function initDefaultConfig() {
    try {
        const exists = await BotConfig.findOne({ key: 'main_config' }).lean();
        if (!exists) {
            await new BotConfig({ key: 'main_config' }).save();
            console.log('✅ Default BotConfig created');
        }
    } catch (err) {
        console.error('Init Config Error:', err.message);
    }
}

// ==================== HELPERS ====================
function generateTxnId() {
    return 'TXN' + Date.now() + Math.floor(1000 + Math.random() * 9000);
}

async function sendTelegramMessage(chatId, text, showKeyboard) {
    try {
        const payload = {
            chat_id: chatId.toString(),
            text: text,
            parse_mode: 'HTML'
        };
        if (showKeyboard) {
            payload.reply_markup = {
                keyboard: [
                    ['🚀 Open Panel'],
                    ['💎 My Points', '🔗 Refer & Earn'],
                    ['🎁 Claim Promo Code', '🛒 Buy Subscription'],
                    ['💳 Deposit Funds', '📊 Transaction Ledger'],
                    ['🏆 Leaderboard', '👨‍💻 Contact Admin']
                ],
                resize_keyboard: true
            };
        }
        await axios.post(`https://api.telegram.org/bot${BOT_TOKEN}/sendMessage`, payload, { timeout: 5000 });
    } catch (err) {
        console.error(`[Bot Error Logger] Message delivery skipped for ${chatId}:`, err.message);
    }
}

// NEW (sync fix): bot.js's original /api/verify-device sent a Telegram security alert
// to admins whenever a multi-account conflict was detected. That alerting was lost when
// this standalone service dropped the old fingerprint-based check and switched to
// IP-only detection — admins had no way to know an IP conflict occurred except by
// polling /api/admin/flagged-users. Restored here, using the same root-owner + admins
// dedupe pattern used in bot.js.
async function alertAdminsOfConflict(uidStr, conflictOwnerUserId, realIP, platform, reasons) {
    try {
        const cfg = await BotConfig.findOne({ key: 'main_config' }).lean();
        const targetAdmins = Array.from(new Set([ROOT_OWNER_ID, ...((cfg && cfg.admins) || [])]));
        const alertMsg = `⚠️ <b>[SECURITY ALERT - MULTI ACCOUNT DETECTED]</b>\n\n` +
            `👤 <b>Suspect Attacker User ID:</b> <code>${uidStr}</code>\n` +
            `🔗 <b>Existing Owner Profile ID:</b> <code>${conflictOwnerUserId}</code>\n` +
            `🌐 <b>IP Address Node:</b> <code>${realIP || 'N/A'}</code>\n` +
            `📱 <b>Device OS Platform:</b> <code>${platform || 'N/A'}</code>\n` +
            `📝 <b>Reason:</b> <code>${reasons.join(', ')}</code>\n\n` +
            `❌ <b>Action:</b> Promo features restricted automatically.`;
        for (const adminId of targetAdmins) {
            try { await sendTelegramMessage(adminId, alertMsg, false); } catch (e) {}
        }
    } catch (e) {
        console.error('alertAdminsOfConflict error:', e.message);
    }
}

async function saveDeviceFingerprint(userId, fingerprintData) {
    const { fingerprint, ipAddress, userAgent, platform, screenResolution, timezone } = fingerprintData;
    await User.updateOne(
        { userId: userId.toString() },
        {
            $set: {
                deviceFingerprint: fingerprint,
                deviceIP: ipAddress,
                isDeviceVerified: true,
                deviceVerifiedAt: new Date(),
                deviceUserAgent: userAgent,
                devicePlatform: platform,
                deviceScreen: screenResolution,
                deviceTimezone: timezone,
                // SYNC FIX: once a device is actually verified through this API,
                // clear any earlier admin bypass flag so the profile reflects real
                // verification rather than a manual override (mirrors bot.js's
                // "Verify Device Now" admin action which also clears bypass state).
                verificationBypassed: false,
                bypassReason: null
            }
        }
    );
    await DeviceFingerprint.findOneAndUpdate(
        { fingerprint: fingerprint, userId: userId.toString() },
        {
            $set: {
                fingerprint: fingerprint,
                userId: userId.toString(),
                ipAddress: ipAddress,
                userAgent: userAgent,
                platform: platform,
                screenResolution: screenResolution,
                timezone: timezone,
                isActive: true,
                lastUsed: new Date()
            }
        },
        { upsert: true }
    );
}

// ==================== TELEGRAM INITDATA VALIDATION ====================
function validateTelegramInitData(initData) {
    try {
        if (!initData || typeof initData !== 'string') {
            return { valid: false, user: null, reason: 'initData missing' };
        }

        // Parse initData query string
        const params = new URLSearchParams(initData);
        const hash = params.get('hash');
        if (!hash) {
            return { valid: false, user: null, reason: 'hash missing' };
        }

        // Build data-check-string: all fields except hash, sorted alphabetically
        const pairs = [];
        for (const [key, value] of params.entries()) {
            if (key !== 'hash') {
                pairs.push(`${key}=${value}`);
            }
        }
        pairs.sort();
        const dataCheckString = pairs.join('\n');

        // Secret key = HMAC-SHA256("WebAppData", bot_token)
        const secretKey = crypto.createHmac('sha256', 'WebAppData').update(BOT_TOKEN).digest();

        // Verify hash = HMAC-SHA256(secret_key, data_check_string)
        const computedHash = crypto.createHmac('sha256', secretKey).update(dataCheckString).digest('hex');

        if (computedHash !== hash) {
            return { valid: false, user: null, reason: 'hash mismatch' };
        }

        // Extract user object
        const userJson = params.get('user');
        if (!userJson) {
            return { valid: false, user: null, reason: 'user missing' };
        }

        const user = JSON.parse(userJson);
        if (!user.id) {
            return { valid: false, user: null, reason: 'user.id missing' };
        }

        // Optional: check auth_date is not too old (max 24 hours)
        const authDate = parseInt(params.get('auth_date'), 10);
        const now = Math.floor(Date.now() / 1000);
        if (authDate && (now - authDate) > 86400) {
            return { valid: false, user: null, reason: 'initData expired' };
        }

        return { valid: true, user: user };
    } catch (err) {
        console.error('[InitData Validation Error]', err.message);
        return { valid: false, user: null, reason: 'validation error' };
    }
}

// ==================== ROUTES ====================

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/health', (req, res) => {
    res.json({ status: 'ok', service: 'DevilBot Device Verification API' });
});

// ==================== DEVICE VERIFICATION API ====================
app.post('/api/verify-device', async (req, res) => {
    try {
        const { userId, fingerprint, ipAddress, userAgent, platform, screenResolution, timezone, initData } = req.body;

        // FIX: Properly parse x-forwarded-for which can contain multiple IPs
        const forwarded = req.headers['x-forwarded-for'];
        const clientIP = forwarded 
            ? forwarded.toString().split(',')[0].trim() 
            : req.socket.remoteAddress;
        const realIP = ipAddress || clientIP;

        if (!userId || !fingerprint) {
            return res.status(400).json({ success: false, message: 'Missing required fields: userId and fingerprint are required' });
        }

        const uidStr = userId.toString().trim();
        if (!uidStr) {
            return res.status(400).json({ success: false, message: 'Invalid userId' });
        }

        // ==================== INITDATA VALIDATION ====================
        const tgAuth = validateTelegramInitData(initData);
        if (!tgAuth.valid) {
            console.log(`[Auth Block] userId=${uidStr} reason=${tgAuth.reason}`);
            return res.status(403).json({ success: false, message: 'Telegram authentication failed: ' + tgAuth.reason });
        }

        // Ensure userId from body matches initData user.id
        if (tgAuth.user.id.toString() !== uidStr) {
            console.log(`[Auth Block] userId mismatch: body=${uidStr} initData=${tgAuth.user.id}`);
            return res.status(403).json({ success: false, message: 'User ID mismatch with Telegram auth data.' });
        }

        let freshUserObj = await User.findOne({ userId: uidStr });

        // Auto-create user if not exists (with Telegram profile data)
        if (!freshUserObj) {
            freshUserObj = await new User({
                userId: uidStr,
                username: tgAuth.user.username || '',
                firstName: tgAuth.user.first_name || '',
                lastName: tgAuth.user.last_name || ''
            }).save();
        }

        // Block banned users
        if (freshUserObj.isBanned) {
            await sendTelegramMessage(uidStr, '❌ <b>Access Denied</b>\n\nYour account has been banned. Contact admin for support.', false);
            return res.status(403).json({ success: false, message: 'Account is banned.' });
        }

        // SYNC FIX: bot.js's requireDeviceVerification toggle (Admin Panel -> Bot
        // Settings -> Device Verify ON/OFF) was not respected here at all — this
        // endpoint always ran full verification logic even when the admin had
        // switched device verification off globally. Now, if it's off, we short
        // circuit and report success without enforcing IP/fingerprint checks, so
        // the mini app doesn't error out while the feature is disabled bot-wide.
        const cfgCheck = await BotConfig.findOne({ key: 'main_config' }).lean();
        if (cfgCheck && cfgCheck.requireDeviceVerification === false) {
            await User.updateOne({ userId: uidStr }, { $set: { lastActive: new Date() } });
            await sendTelegramMessage(uidStr, '✅ <b>Verification Complete</b>\nYour device has been verified successfully.', true);
            return res.json({ success: true, message: 'Your device has been verified successfully.', isPromoRestricted: freshUserObj.isPromoRestricted });
        }

        // RULE: Same Telegram User - Already verified with same or different fingerprint
        if (freshUserObj.isDeviceVerified) {
            if (freshUserObj.deviceFingerprint === fingerprint) {
                await User.updateOne(
                    { userId: uidStr },
                    { $set: { lastActive: new Date(), deviceIP: realIP || freshUserObj.deviceIP } }
                );
                await sendTelegramMessage(uidStr, '✅ <b>Verification Complete</b>\nYour device has been verified successfully.', true);
                return res.json({ success: true, message: 'Your device has been verified successfully.', isPromoRestricted: freshUserObj.isPromoRestricted });
            } else {
                await sendTelegramMessage(uidStr, '❌ <b>Verification Failed</b>\n\nDifferent hardware profile detected on this account. You cannot verify from a new device.', false);
                return res.json({ success: false, message: 'Different hardware profile detected on this account.', code: 'DEVICE_MISMATCH' });
            }
        }

        let isMultipleMarked = false;
        let conflictReason = [];
        let conflictOwnerUserId = null;

        // ==================== MULTI-ACCOUNT DETECTION (IP ONLY) ====================
        // STRICT: 1 IP = 1 Account (no family/office exceptions)
        // SYNC FIX: skip this block entirely if an admin has manually bypassed
        // restrictions for this user via the bot's Admin Panel (verificationBypassed),
        // otherwise an admin-approved user could still get auto-flagged here.
        if (realIP && !freshUserObj.verificationBypassed) {
            const activeConflictIP = await User.findOne({
                deviceIP: realIP,
                userId: { $ne: uidStr },
                isDeviceVerified: true
            }).lean();

            if (activeConflictIP) {
                isMultipleMarked = true;
                conflictOwnerUserId = activeConflictIP.userId;
                conflictReason.push('Multple Acc Detect');
                console.log(`[Multi-Detect] IP ${realIP} conflict: ${uidStr} vs ${activeConflictIP.userId}`);
            }
        }

        // NOTE: Fingerprint conflict check REMOVED as per request.
        // Only IP-based detection is used to enforce strict 1 user = 1 account policy.

        // If multiple account activity is detected, restrict the referred account only.
        // The referrer must not be punished for a suspicious referred account. The
        // referred user receives the explicit invalid-referral/fake-referral alert.
        if (isMultipleMarked) {
            await User.updateOne(
                { userId: uidStr },
                { $set: { isPromoRestricted: true, lastActive: new Date(), isReferralVerified: false } }
            );

            if (freshUserObj.referredBy) {
                await Referral.findOneAndUpdate(
                    { referredId: uidStr },
                    {
                        $set: {
                            referrerId: freshUserObj.referredBy.toString(),
                            referredId: uidStr,
                            status: 'blocked_multi_device',
                            pointsEarned: 0,
                            friendPointsEarned: 0
                        }
                    },
                    { upsert: true }
                );
            }

            await sendTelegramMessage(
                uidStr,
                `❌ <b>Referral Not Valid</b>\n\nThis referral could not be verified because multiple accounts were detected.\n<b>Fake referrals are not allowed.</b>\n\nYour referred account has been restricted. Please contact admin if this is a mistake.`,
                false
            );

            // Notify admins, but never send a punishment notice to the referrer.
            await alertAdminsOfConflict(uidStr, conflictOwnerUserId, realIP, platform, conflictReason);
        }

        // Save device fingerprint
        await saveDeviceFingerprint(uidStr, {
            fingerprint,
            ipAddress: realIP,
            userAgent,
            platform,
            screenResolution,
            timezone
        });

        // ==================== REFERRAL PROCESSING ====================
        let referralResult = false;
        const updatedUserObj = await User.findOne({ userId: uidStr }).lean();

        if (!isMultipleMarked && updatedUserObj && updatedUserObj.referredBy && !updatedUserObj.isReferralVerified) {
            const referrerId = updatedUserObj.referredBy.toString().trim();
            const referrer = await User.findOne({ userId: referrerId }).lean();

            // A referral is valid only when its owner exists, is not self-referral,
            // and is not banned/restricted. This prevents fake/non-existent IDs from
            // creating rewards and clearly reports the error to the referred user.
            if (!referrer || referrerId === uidStr || referrer.isBanned || referrer.isPromoRestricted) {
                await User.updateOne(
                    { userId: uidStr },
                    { $set: { isPromoRestricted: true, isReferralVerified: false, lastActive: new Date() } }
                );
                await Referral.findOneAndUpdate(
                    { referredId: uidStr },
                    { $set: { referrerId, referredId: uidStr, status: 'blocked_multi_device', pointsEarned: 0, friendPointsEarned: 0 } },
                    { upsert: true }
                );
                await sendTelegramMessage(
                    uidStr,
                    '❌ <b>Referral Not Valid</b>\n\nThe referral user ID does not exist or is not eligible. <b>Fake referrals are not allowed.</b>\nYour referred account has been restricted. Please contact admin.',
                    false
                );
            } else {
                await User.updateOne({ userId: uidStr }, { $set: { isReferralVerified: true } });

            const config = await BotConfig.findOne({ key: 'main_config' }).lean();
            if (config) {
                const pointsReward = config.referPoints || 10;
                const friendReward = config.referredBonusPoints || 5;

                // Atomic upsert to prevent race conditions
                const referralDoc = await Referral.findOneAndUpdate(
                    { referredId: uidStr, status: { $in: ['pending', 'blocked_multi_device'] } },
                    {
                        $set: {
                            referrerId: updatedUserObj.referredBy.toString(),
                            referredId: uidStr,
                            pointsEarned: pointsReward,
                            friendPointsEarned: friendReward,
                            status: 'verified'
                        }
                    },
                    { upsert: true, new: true }
                );

                if (referralDoc) {
                    await User.updateOne(
                        { userId: updatedUserObj.referredBy.toString() },
                        { $inc: { points: pointsReward, totalReferrals: 1 } }
                    );
                    await new Transaction({
                        txnId: generateTxnId(),
                        userId: updatedUserObj.referredBy.toString(),
                        type: 'Referral',
                        pointsMeta: pointsReward,
                        description: 'Referral reward for joining User ID: ' + uidStr
                    }).save();

                    if (friendReward > 0) {
                        await User.updateOne({ userId: uidStr }, { $inc: { points: friendReward } });
                        await new Transaction({
                            txnId: generateTxnId(),
                            userId: uidStr,
                            type: 'Referral',
                            pointsMeta: friendReward,
                            description: 'Received Referral join bonus from User ID: ' + updatedUserObj.referredBy
                        }).save();

                        await sendTelegramMessage(uidStr, `🎁 <b>Welcome Bonus!</b>\n\n💰 You received <code>${friendReward} Points</code> for joining via referral link.`, false);
                    }

                    await sendTelegramMessage(
                        updatedUserObj.referredBy.toString(),
                        `✅ <b>Referral Success!</b>\n\n🆔 <b>User ID:</b> <code>${uidStr}</code>\n💰 <b>Balance Added:</b> <code>${pointsReward} Points</code>`,
                        false
                    );
                    referralResult = true;
                }
            }
            }
        }

        await sendTelegramMessage(uidStr, isMultipleMarked ? '⚠️ <b>Verification Complete with Restrictions</b>\n\nYour account remains restricted because the referral was not valid.' : '✅ <b>Verification Complete</b>\n\nYour device has been verified successfully.', true);

        return res.json({
            success: true,
            message: 'Your device has been verified successfully.',
            code: 'VERIFIED',
            referralProcessed: referralResult,
            isPromoRestricted: isMultipleMarked,
            conflictReason: conflictReason.length > 0 ? conflictReason : undefined
        });

    } catch (err) {
        console.error('[/api/verify-device] Global Exception Catch:', err.message);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
});

// ==================== ADMIN API ROUTES ====================

app.get('/api/admin/user-device/:userId', async (req, res) => {
    try {
        const { userId } = req.params;
        const adminKey = req.headers['x-admin-key'];

        if (!adminKey || adminKey !== process.env.ADMIN_API_KEY) {
            return res.status(401).json({ success: false, message: 'Unauthorized' });
        }

        const user = await User.findOne({ userId: userId.toString() }).lean();
        if (!user) return res.status(404).json({ success: false, message: 'User not found' });

        const fingerprints = await DeviceFingerprint.find({ userId: userId.toString() }).lean();
        res.json({ success: true, user, fingerprints });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

app.get('/api/admin/flagged-users', async (req, res) => {
    try {
        const adminKey = req.headers['x-admin-key'];
        if (!adminKey || adminKey !== process.env.ADMIN_API_KEY) {
            return res.status(401).json({ success: false, message: 'Unauthorized' });
        }

        const flagged = await User.find({ isPromoRestricted: true }).lean();
        res.json({ success: true, count: flagged.length, users: flagged });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

app.post('/api/admin/ban-user', async (req, res) => {
    try {
        const adminKey = req.headers['x-admin-key'];
        if (!adminKey || adminKey !== process.env.ADMIN_API_KEY) {
            return res.status(401).json({ success: false, message: 'Unauthorized' });
        }

        const { userId, ban } = req.body;
        if (!userId) return res.status(400).json({ success: false, message: 'userId required' });

        await User.updateOne({ userId: userId.toString() }, { $set: { isBanned: ban === true } });
        res.json({ success: true, message: `User ${ban ? 'banned' : 'unbanned'} successfully` });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// ==================== GLOBAL ANTI-CRASH HOOKS ====================
process.on('unhandledRejection', (reason, promise) => {
    console.error('⚠️ [Anti-Crash] Unhandled Rejection at:', promise, 'reason:', reason);
});
process.on('uncaughtException', (err) => {
    console.error('⚠️ [Anti-Crash] Uncaught Exception thrown:', err);
});

// ==================== START SERVER ====================
connectDB().then(() => {
    app.listen(PORT, () => {
        console.log('🚀 DevilBot Device Verification API running on port ' + PORT);
    });
});
