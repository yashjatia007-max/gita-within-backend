// ═══════════════════════════════════════════════════════════

// GITA WITHIN — Backend Server

// Handles: user creation, login, conversation storage, memory

// ═══════════════════════════════════════════════════════════

require('dotenv').config();

const express    = require('express');

const cors       = require('cors');

const bcrypt     = require('bcryptjs');

const jwt        = require('jsonwebtoken');

const nodemailer = require('nodemailer');

const rateLimit  = require('express-rate-limit');

const { createClient } = require('@supabase/supabase-js');

const crypto     = require('crypto');

const app = express();

// ── Supabase (service role — bypasses RLS for backend operations) ──

const supabase = createClient(

  process.env.SUPABASE_URL,

  process.env.SUPABASE_SERVICE_KEY

);

// ── Email transporter ──

const mailer = nodemailer.createTransporter({

  host:   process.env.EMAIL_HOST,

  port:   parseInt(process.env.EMAIL_PORT),

  secure: process.env.EMAIL_PORT === '465',

  auth: {

    user: process.env.EMAIL_USER,

    pass: process.env.EMAIL_PASS,

  },

});

// ── Middleware ──

app.use(cors({ origin: process.env.FRONTEND_URL, credentials: true }));

app.use(express.json());

// Rate limiting

const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10, message: { error: 'Too many attempts. Please wait.' } });

const apiLimiter  = rateLimit({ windowMs: 60 * 1000, max: 60 });

app.use('/api/auth', authLimiter);

app.use('/api', apiLimiter);

// ── Auth middleware ──

function requireAuth(req, res, next) {

  const auth = req.headers.authorization;

  if (!auth?.startsWith('Bearer ')) return res.status(401).json({ error: 'Not authenticated' });

  try {

    req.user = jwt.verify(auth.slice(7), process.env.JWT_SECRET);

    next();

  } catch {

    res.status(401).json({ error: 'Invalid or expired session' });

  }

}

// ── Generate a memorable but secure password ──

function generatePassword() {

  const adjectives = ['Sacred','Ancient','Golden','Eternal','Serene','Lotus','Divine','Peaceful','Radiant','Noble'];

  const nouns      = ['River','Light','Flame','Path','Wisdom','Journey','Soul','Truth','Dawn','Star'];

  const adj  = adjectives[Math.floor(Math.random() * adjectives.length)];

  const noun = nouns[Math.floor(Math.random() * nouns.length)];

  const num  = Math.floor(Math.random() * 900) + 100;

  return `${adj}${noun}${num}`;

}

// ═══════════════════════════════════════════════════════════

// ROUTE: Create user from Google Form submission

// Called by Google Apps Script when form is submitted

// ═══════════════════════════════════════════════════════════

app.post('/api/users/create', async (req, res) => {

  // Verify this is coming from your Apps Script

  const secret = req.headers['x-apps-script-secret'];

  if (secret !== process.env.APPS_SCRIPT_SECRET) {

    return res.status(403).json({ error: 'Forbidden' });

  }

  const { name, email, why_seeking } = req.body;

  if (!name || !email) return res.status(400).json({ error: 'Name and email required' });

  try {

    // Check if user already exists

    const { data: existing } = await supabase

      .from('users')

      .select('id')

      .eq('email', email.toLowerCase())

      .single();

    if (existing) return res.json({ message: 'User already exists', existing: true });

    // Generate password

    const password     = generatePassword();

    const passwordHash = await bcrypt.hash(password, 12);

    // Create user in Supabase

    const { data: user, error } = await supabase

      .from('users')

      .insert({

        name:          name.trim(),

        email:         email.toLowerCase().trim(),

        password_hash: passwordHash,

        why_seeking:   why_seeking || '',

        known_context: why_seeking

          ? `This seeker shared when joining: "${why_seeking}"`

          : '',

      })

      .select()

      .single();

    if (error) throw error;

    // Send welcome email

    await sendWelcomeEmail(user, password);

    res.json({ success: true, userId: user.id });

  } catch (err) {

    console.error('Create user error:', err);

    res.status(500).json({ error: 'Failed to create user' });

  }

});

// ═══════════════════════════════════════════════════════════

// ROUTE: Login

// ═══════════════════════════════════════════════════════════

app.post('/api/auth/login', async (req, res) => {

  const { email, password } = req.body;

  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

  try {

    const { data: user, error } = await supabase

      .from('users')

      .select('*')

      .eq('email', email.toLowerCase().trim())

      .single();

    if (error || !user) return res.status(401).json({ error: 'No account found with that email' });

    const valid = await bcrypt.compare(password, user.password_hash);

    if (!valid) return res.status(401).json({ error: 'Incorrect password' });

    // Update last login

    await supabase.from('users').update({ last_login: new Date().toISOString() }).eq('id', user.id);

    // JWT token — 7 day expiry

    const token = jwt.sign(

      { userId: user.id, email: user.email, name: user.name },

      process.env.JWT_SECRET,

      { expiresIn: '7d' }

    );

    // Return user profile (no password hash)

    const { password_hash, ...profile } = user;

    res.json({ token, user: profile });

  } catch (err) {

    console.error('Login error:', err);

    res.status(500).json({ error: 'Login failed' });

  }

});

// ═══════════════════════════════════════════════════════════

// ROUTE: Get current user profile + memory context

// ═══════════════════════════════════════════════════════════

app.get('/api/auth/me', requireAuth, async (req, res) => {

  const { data: user, error } = await supabase

    .from('users')

    .select('id, name, email, why_seeking, created_at, total_sessions, total_messages, known_themes, known_context, last_summary')

    .eq('id', req.user.userId)

    .single();

  if (error) return res.status(404).json({ error: 'User not found' });

  res.json(user);

});

// ═══════════════════════════════════════════════════════════

// ROUTE: Start a new conversation

// ═══════════════════════════════════════════════════════════

app.post('/api/conversations', requireAuth, async (req, res) => {

  const { data: conv, error } = await supabase

    .from('conversations')

    .insert({ user_id: req.user.userId })

    .select()

    .single();

  if (error) return res.status(500).json({ error: 'Failed to start conversation' });

  // Increment user session count

  await supabase.rpc('increment_sessions', { user_id: req.user.userId });

  res.json(conv);

});

// ═══════════════════════════════════════════════════════════

// ROUTE: Save a message

// ═══════════════════════════════════════════════════════════

app.post('/api/conversations/:convId/messages', requireAuth, async (req, res) => {

  const { role, content } = req.body;

  const { convId }        = req.params;

  if (!['user','assistant'].includes(role)) return res.status(400).json({ error: 'Invalid role' });

  try {

    const { data: msg, error } = await supabase

      .from('messages')

      .insert({

        conversation_id: convId,

        user_id:         req.user.userId,

        role,

        content,

      })

      .select()

      .single();

    if (error) throw error;

    // Update message counts

    await supabase.from('conversations').update({

      message_count: supabase.raw('message_count + 1'),

      ended_at: new Date().toISOString(),

    }).eq('id', convId);

    await supabase.from('users').update({

      total_messages: supabase.raw('total_messages + 1'),

    }).eq('id', req.user.userId);

    res.json(msg);

  } catch (err) {

    console.error('Save message error:', err);

    res.status(500).json({ error: 'Failed to save message' });

  }

});

// ═══════════════════════════════════════════════════════════

// ROUTE: Get conversation history (last N conversations)

// ═══════════════════════════════════════════════════════════

app.get('/api/conversations', requireAuth, async (req, res) => {

  const { data, error } = await supabase

    .from('conversations')

    .select('id, started_at, ended_at, message_count, themes, title, summary')

    .eq('user_id', req.user.userId)

    .order('started_at', { ascending: false })

    .limit(20);

  if (error) return res.status(500).json({ error: 'Failed to fetch conversations' });

  res.json(data);

});

// ═══════════════════════════════════════════════════════════

// ROUTE: Get messages for a specific conversation

// ═══════════════════════════════════════════════════════════

app.get('/api/conversations/:convId/messages', requireAuth, async (req, res) => {

  const { data, error } = await supabase

    .from('messages')

    .select('id, role, content, created_at, feedback, saved')

    .eq('conversation_id', req.params.convId)

    .eq('user_id', req.user.userId)

    .order('created_at', { ascending: true });

  if (error) return res.status(500).json({ error: 'Failed to fetch messages' });

  res.json(data);

});

// ═══════════════════════════════════════════════════════════

// ROUTE: Update feedback on a message

// ═══════════════════════════════════════════════════════════

app.patch('/api/messages/:msgId/feedback', requireAuth, async (req, res) => {

  const { feedback, saved } = req.body;

  const updates = {};

  if (feedback !== undefined) updates.feedback = feedback;

  if (saved    !== undefined) updates.saved    = saved;

  const { error } = await supabase

    .from('messages')

    .update(updates)

    .eq('id', req.params.msgId)

    .eq('user_id', req.user.userId);

  if (error) return res.status(500).json({ error: 'Failed to update feedback' });

  res.json({ success: true });

});

// ═══════════════════════════════════════════════════════════

// ROUTE: Update user memory context

// Called after each conversation to build Krishna's memory

// ═══════════════════════════════════════════════════════════

app.patch('/api/users/memory', requireAuth, async (req, res) => {

  const { known_themes, known_context, last_summary, conv_id, conv_title, conv_themes } = req.body;

  try {

    // Update user memory

    if (known_context || known_themes || last_summary) {

      await supabase.from('users').update({

        ...(known_themes  && { known_themes }),

        ...(known_context && { known_context }),

        ...(last_summary  && { last_summary }),

      }).eq('id', req.user.userId);

    }

    // Update conversation title and themes

    if (conv_id && (conv_title || conv_themes)) {

      await supabase.from('conversations').update({

        ...(conv_title  && { title: conv_title }),

        ...(conv_themes && { themes: conv_themes }),

      }).eq('id', conv_id).eq('user_id', req.user.userId);

    }

    res.json({ success: true });

  } catch (err) {

    res.status(500).json({ error: 'Failed to update memory' });

  }

});

// ═══════════════════════════════════════════════════════════

// ROUTE: Change password

// ═══════════════════════════════════════════════════════════

app.post('/api/auth/change-password', requireAuth, async (req, res) => {

  const { current_password, new_password } = req.body;

  if (!current_password || !new_password) return res.status(400).json({ error: 'Both passwords required' });

  if (new_password.length < 6) return res.status(400).json({ error: 'New password must be at least 6 characters' });

  const { data: user } = await supabase.from('users').select('password_hash').eq('id', req.user.userId).single();

  const valid = await bcrypt.compare(current_password, user.password_hash);

  if (!valid) return res.status(401).json({ error: 'Current password incorrect' });

  const hash = await bcrypt.hash(new_password, 12);

  await supabase.from('users').update({ password_hash: hash }).eq('id', req.user.userId);

  res.json({ success: true });

});

// ═══════════════════════════════════════════════════════════

// WELCOME EMAIL

// ═══════════════════════════════════════════════════════════

async function sendWelcomeEmail(user, password) {

  const html = `

<!DOCTYPE html>

<html>

<head>

  <style>

    body { font-family: Georgia, serif; background: #faf6f0; margin: 0; padding: 0; }

    .container { max-width: 560px; margin: 40px auto; background: #fff; border: 1px solid rgba(201,147,58,0.2); }

    .header { background: #1a1410; padding: 40px 40px 30px; text-align: center; }

    .om { font-size: 2.5rem; color: #c9933a; display: block; margin-bottom: 8px; }

    .title { color: #faf6f0; font-size: 1.5rem; font-weight: 300; letter-spacing: 0.05em; }

    .body { padding: 40px; }

    .greeting { font-size: 1.2rem; color: #1a1410; margin-bottom: 1.2rem; font-style: italic; }

    .verse { border-left: 3px solid #c9933a; padding: 12px 16px; background: rgba(201,147,58,0.05); margin: 20px 0; font-style: italic; color: #4a3f35; font-size: 0.95rem; line-height: 1.7; }

    .creds { background: #f2ebe0; padding: 20px 24px; margin: 24px 0; }

    .creds-title { font-size: 0.72rem; letter-spacing: 0.15em; text-transform: uppercase; color: #8a7a6a; margin-bottom: 12px; }

    .cred-row { display: flex; margin-bottom: 8px; font-size: 0.9rem; }

    .cred-label { color: #8a7a6a; min-width: 90px; }

    .cred-value { color: #1a1410; font-weight: 500; font-family: monospace; }

    .btn { display: block; text-align: center; background: #c9933a; color: #fff; text-decoration: none; padding: 14px 28px; font-size: 0.85rem; letter-spacing: 0.1em; text-transform: uppercase; margin: 28px 0; }

    .note { font-size: 0.82rem; color: #8a7a6a; line-height: 1.7; }

    .footer { background: #f2ebe0; padding: 20px 40px; text-align: center; font-size: 0.75rem; color: #8a7a6a; }

  </style>

</head>

<body>

  <div class="container">

    <div class="header">

      <span class="om">ॐ</span>

      <div class="title">Gita Within</div>

    </div>

    <div class="body">

      <p class="greeting">Dear ${user.name},</p>

      <p style="color:#4a3f35;line-height:1.8;font-size:0.95rem;">You have been accepted as a seeker. Your journey with Krishna begins now.</p>

      <div class="verse">

        "I am the self seated in the hearts of all creatures. I am the beginning, the middle, and the end of all beings."

        <br><span style="font-style:normal;font-size:0.8rem;color:#c9933a;letter-spacing:0.1em;">BHAGAVAD GITA · 10.20</span>

      </div>

      <div class="creds">

        <div class="creds-title">Your Login Credentials</div>

        <div class="cred-row"><span class="cred-label">Username</span><span class="cred-value">${user.email}</span></div>

        <div class="cred-row"><span class="cred-label">Password</span><span class="cred-value">${password}</span></div>

      </div>

      <a href="${process.env.FRONTEND_URL}" class="btn">Begin Your Journey →</a>

      <p class="note">

        You can change your password after logging in. Krishna will remember your conversations and grow to know you over time — each session builds on the last.<br><br>

        ${user.why_seeking ? `You shared that you seek guidance because: <em>"${user.why_seeking}"</em> — Krishna has heard this and will carry it with him.` : ''}

      </p>

    </div>

    <div class="footer">

      Gita Within · Ancient wisdom for modern life · For seekers of all paths

    </div>

  </div>

</body>

</html>`;

  await mailer.sendMail({

    from:    process.env.EMAIL_FROM,

    to:      user.email,

    subject: `ॐ Welcome to Gita Within, ${user.name} — Your login details inside`,

    html,

    text: `Welcome to Gita Within, ${user.name}.\n\nYour login:\nUsername: ${user.email}\nPassword: ${password}\n\nVisit: ${process.env.FRONTEND_URL}\n\nॐ`,

  });

}

// ── Health check ──

app.get('/health', (_, res) => res.json({ status: 'ok', service: 'gita-within-backend' }));

// ── Start ──

const PORT = process.env.PORT || 3001;

app.listen(PORT, () => console.log(`🪔 Gita Within backend running on port ${PORT}`));