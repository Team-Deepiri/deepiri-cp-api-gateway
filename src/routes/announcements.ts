import { Router, Request, Response } from 'express';
import { userAuthMiddleware } from '../middleware/userAuth.middleware';
import { createLogger } from '@team-deepiri/shared-utils';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import axios from 'axios';

const router = Router();
const logger = createLogger('announcements');

// Shared secret with Norozo's PLATFORM_ANNOUNCEMENTS_WEBHOOK_SECRET / ANNOUNCEMENTS_INBOUND_SECRET.
const ANNOUNCEMENTS_WEBHOOK_SECRET =
  process.env.PLATFORM_ANNOUNCEMENTS_WEBHOOK_SECRET || process.env.NOROZO_WEBHOOK_SECRET || '';
// Norozo's inbound webhook, e.g. https://<norozo>.onrender.com/announcements/webhook
const NOROZO_ANNOUNCEMENTS_WEBHOOK_URL = process.env.NOROZO_ANNOUNCEMENTS_WEBHOOK_URL || '';

function signBody(rawBody: Buffer | string): string {
  const buf = Buffer.isBuffer(rawBody) ? rawBody : Buffer.from(rawBody, 'utf-8');
  return `sha256=${crypto.createHmac('sha256', ANNOUNCEMENTS_WEBHOOK_SECRET).update(buf).digest('hex')}`;
}

function verifySignature(rawBody: Buffer, signatureHeader: string): boolean {
  if (!ANNOUNCEMENTS_WEBHOOK_SECRET || !signatureHeader) return false;
  const expected = signBody(rawBody);
  const a = Buffer.from(expected);
  const b = Buffer.from(signatureHeader);
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

async function forwardAnnouncementToDiscord(ann: {
  title: string;
  body: string;
  authorName?: string;
  url?: string;
}): Promise<void> {
  if (!NOROZO_ANNOUNCEMENTS_WEBHOOK_URL || !ANNOUNCEMENTS_WEBHOOK_SECRET) {
    logger.warn('Skipping forward to Discord: NOROZO_ANNOUNCEMENTS_WEBHOOK_URL or shared secret not configured');
    return;
  }
  const payload = {
    title: ann.title,
    body: ann.body,
    author: ann.authorName || 'Platform',
    url: ann.url || '',
  };
  const raw = Buffer.from(JSON.stringify(payload), 'utf-8');
  const signature = signBody(raw);
  try {
    await axios.post(NOROZO_ANNOUNCEMENTS_WEBHOOK_URL, raw, {
      headers: { 'Content-Type': 'application/json', 'X-Norozo-Signature': signature },
      timeout: 10_000,
    });
    logger.info('Forwarded web announcement to Discord via Norozo');
  } catch (e: any) {
    logger.error('Failed to forward announcement to Discord', { error: e.message });
  }
}

interface Announcement {
  id: string;
  title: string;
  body: string;
  authorName?: string;
  authorId?: string;
  createdAt: string;
  source: 'web' | 'norozo';
  discordChannelId?: string;
}

const STORE_PATH = process.env.ANNOUNCEMENTS_STORE_PATH || '/tmp/announcements.json';

// In-memory store
let announcements: Announcement[] = [];

function loadStore() {
  try {
    if (fs.existsSync(STORE_PATH)) {
      const raw = fs.readFileSync(STORE_PATH, 'utf-8');
      const data = JSON.parse(raw);
      if (Array.isArray(data)) announcements = data;
    }
  } catch (e: any) {
    logger.warn('Failed to load announcements store', { error: e.message });
  }
}

function saveStore() {
  try {
    const dir = path.dirname(STORE_PATH);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(STORE_PATH, JSON.stringify(announcements, null, 2));
  } catch (e: any) {
    logger.warn('Failed to save announcements store', { error: e.message });
  }
}

// Seed with a welcome announcement if empty (so dashboard not blank)
function ensureSeed() {
  if (announcements.length === 0) {
    announcements.push({
      id: 'seed-1',
      title: 'Welcome to the new Deepiri Platform',
      body: 'This is the new internal hub. Check Team Meetings on your Dashboard (role-filtered), and explore Tools for Registry, Jobs, Documents, and more. Norozo will now auto-forward every post from Discord #announcements here.',
      authorName: 'Deepiri Team',
      createdAt: new Date().toISOString(),
      source: 'web',
    });
    saveStore();
  }
}

loadStore();
ensureSeed();

// GET /api/announcements — list
router.get('/announcements', (req: Request, res: Response) => {
  const sorted = [...announcements].sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());
  res.json({ announcements: sorted });
});

// POST /api/announcements — create from web (requires auth)
router.post('/announcements', userAuthMiddleware as any, (req: Request, res: Response) => {
  const { title, body } = req.body || {};
  if (!title || !String(title).trim() || !body || !String(body).trim()) {
    return res.status(400).json({ error: 'Title and body are required' });
  }
  if (String(title).length > 200) return res.status(400).json({ error: 'Title too long (200 max)' });
  if (String(body).length > 4000) return res.status(400).json({ error: 'Body too long (4000 max)' });

  const user: any = (req as any).user;
  const ann: Announcement = {
    id: `ann-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
    title: String(title).trim(),
    body: String(body).trim(),
    authorName: user?.name || user?.email || 'Unknown',
    authorId: user?.userId || user?.id,
    createdAt: new Date().toISOString(),
    source: 'web',
  };
  announcements.unshift(ann);
  // keep last 200
  if (announcements.length > 200) announcements = announcements.slice(0, 200);
  saveStore();
  logger.info('Announcement created via web', { id: ann.id, title: ann.title });
  res.status(201).json({ success: true, announcement: ann });

  // Bidirectional bridge: mirror web-created announcements to Discord #announcements.
  // Fire-and-forget — don't block the API response on Discord being reachable.
  void forwardAnnouncementToDiscord({ title: ann.title, body: ann.body, authorName: ann.authorName });
});

// POST /api/webhooks/norozo/announcements — Norozo Discord bot forwards #announcements
// Auth: HMAC-SHA256 over the raw request body, header X-Norozo-Signature: sha256=<hex>,
// keyed with the secret shared via PLATFORM_ANNOUNCEMENTS_WEBHOOK_SECRET — matches
// Norozo's own _forward_announcement_to_platform() and inbound platform_announcement_handler(),
// so both directions of the bridge use the same scheme.
router.post('/webhooks/norozo/announcements', (req: Request, res: Response) => {
  const sigHeader = String(req.headers['x-norozo-signature'] || req.headers['x-platform-signature'] || '').trim();
  const rawBody: Buffer | undefined = (req as any).rawBody;
  if (!rawBody || !verifySignature(rawBody, sigHeader)) {
    logger.warn('Norozo webhook unauthorized', { hasSignature: !!sigHeader });
    return res.status(401).json({ error: 'Missing or invalid signature' });
  }

  const { title, body, content, author, author_id: authorId, discord_channel_id: discordChannelId } = req.body || {};
  const finalTitle = String(title || content?.slice(0, 80) || 'Discord Announcement').trim().slice(0, 200);
  const finalBody = String(body || content || '').trim();
  if (!finalBody) return res.status(400).json({ error: 'Body/content is required' });
  if (finalBody.length > 4000) return res.status(400).json({ error: 'Body too long' });

  const ann: Announcement = {
    id: `norozo-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
    title: finalTitle,
    body: finalBody,
    authorName: String(author || 'Norozo (Discord #announcements)'),
    authorId: authorId ? String(authorId) : undefined,
    createdAt: new Date().toISOString(),
    source: 'norozo',
    discordChannelId: String(discordChannelId || process.env.ANNOUNCEMENTS_CHANNEL_ID || '1436509524818395156'),
  };
  announcements.unshift(ann);
  if (announcements.length > 200) announcements = announcements.slice(0, 200);
  saveStore();
  logger.info('Announcement created via Norozo webhook', { id: ann.id, channelId: ann.discordChannelId });
  res.status(201).json({ success: true, announcement: ann });
});

export default router;
