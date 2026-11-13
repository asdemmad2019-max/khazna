// الخزنة — سيرفر حقيقي
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { db, getSetting, setSetting, log } = require('./db.js');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');
const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || 'admin@khazna.com').toLowerCase();
const ADMIN_PASS = process.env.ADMIN_PASS || 'Khazna@2026-Change-Me';
const ADMIN_NAME = process.env.ADMIN_NAME || 'المدير العام';

app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: '100kb' }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.static(__dirname));

const authLimiter = rateLimit({ windowMs: 15*60*1000, max: 60, message: { error: 'محاولات كثيرة — حاول بعد 15 دقيقة' } });
const apiLimiter = rateLimit({ windowMs: 60*1000, max: 120 });
app.use('/api/', apiLimiter);

(function seed(){
  const count = db.prepare('SELECT COUNT(*) c FROM plans').get().c;
  if(count===0){
    const plans=[['p1','البرونزية','🥉','بداية هادئة للمبتدئين','',1,1,25],['p2','الفضية','🥈','توازن بين الأمان والعائد','',2,1,45],['p3','الذهبية','🥇','الأكثر طلباً','الأكثر طلباً',3,1,70],['p4','البلاتينية','💎','خدمة خاصة ومدير محفظة','خاصة',4,1,90]];
    const ins=db.prepare('INSERT INTO plans(id,name,icon,desc,tag,ord,active,level) VALUES(?,?,?,?,?,?,?,?)');
    plans.forEach(p=>ins.run(...p));
  }
  if(!getSetting('site', null)) setSetting('site', { siteName:'الخزنة', allowReg:true, topText:'الخزنة • منصة استثمار الذهب • أمان • شفافية • متابعة مباشرة' });
  const admin = db.prepare('SELECT * FROM users WHERE email=?').get(ADMIN_EMAIL);
  if(!admin){
    const hash = bcrypt.hashSync(ADMIN_PASS, 12);
    db.prepare('INSERT INTO users(id,name,email,pass_hash,role,created_at) VALUES(?,?,?,?,?,?)').run(crypto.randomUUID(), ADMIN_NAME, ADMIN_EMAIL, hash, 'مدير عام', new Date().toISOString());
  }
})();

function sign(user){ return jwt.sign({ id:user.id, email:user.email, role:user.role }, JWT_SECRET, { expiresIn:'7d' }); }
function auth(req,res,next){
  const h=req.headers.authorization||''; const tok=h.replace('Bearer ','');
  if(!tok) return res.status(401).json({ error:'غير مسجل دخول' });
  try{ req.user = jwt.verify(tok, JWT_SECRET); next(); }catch(e){ return res.status(401).json({ error:'انتهت الجلسة — سجل دخول مرة أخرى' }); }
}
function isAdmin(req,res,next){ if(req.user.role==='مدير عام') return next(); return res.status(403).json({ error:'للإدارة فقط' }); }
function validEmail(e){ return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e||''); }

app.get('/api/health', (req,res)=>res.json({ ok:true, time:new Date().toISOString() }));
app.get('/api/plans', (req,res)=>{ const rows=db.prepare('SELECT * FROM plans WHERE active=1 ORDER BY ord ASC').all(); res.json(rows.map(r=>({ id:r.id, name:r.name, icon:r.icon, desc:r.desc, tag:r.tag, order:r.ord, active:!!r.active, level:r.level }))); });
app.get('/api/ads', (req,res)=>res.json(db.prepare('SELECT * FROM ads ORDER BY created_at DESC').all()));
app.get('/api/sections', (req,res)=>res.json(db.prepare('SELECT * FROM sections').all()));
app.get('/api/settings', (req,res)=>{ const s=getSetting('site',{ allowReg:true, topText:'' }); res.json({ allowReg:s.allowReg, topText:s.topText }); });

app.post('/api/register', authLimiter, (req,res)=>{
  const { name, email, pass } = req.body||{};
  const site=getSetting('site',{ allowReg:true });
  if(!site.allowReg) return res.status(403).json({ error:'التسجيل متوقف حالياً' });
  if(!name||!validEmail(email)||!pass) return res.status(400).json({ error:'املأ كل الحقول بشكل صحيح' });
  if(pass.length<8) return res.status(400).json({ error:'كلمة السر قصيرة — 8 أحرف على الأقل' });
  const em=email.toLowerCase().trim();
  if(db.prepare('SELECT id FROM users WHERE email=?').get(em)) return res.status(400).json({ error:'الإيميل مسجل مسبقاً' });
  const id=crypto.randomUUID(); const hash=bcrypt.hashSync(pass,12);
  db.prepare('INSERT INTO users(id,name,email,pass_hash,role,created_at) VALUES(?,?,?,?,?,?)').run(id, name.trim(), em, hash, 'مستثمر', new Date().toISOString());
  log('إنشاء حساب جديد: '+em, em);
  const user={ id, email:em, role:'مستثمر' };
  res.json({ token: sign(user), user:{ name:name.trim(), email:em, role:'مستثمر' } });
});
app.post('/api/login', authLimiter, (req,res)=>{
  const { email, pass } = req.body||{};
  const u=db.prepare('SELECT * FROM users WHERE email=?').get((email||'').toLowerCase().trim());
  if(!u || !bcrypt.compareSync(pass||'', u.pass_hash)) return res.status(400).json({ error:'بيانات خاطئة' });
  db.prepare('UPDATE users SET last_login=? WHERE id=?').run(new Date().toISOString(), u.id);
  res.json({ token: sign(u), user:{ name:u.name, email:u.email, role:u.role } });
});
app.get('/api/me', auth, (req,res)=>{ const u=db.prepare('SELECT name,email,role FROM users WHERE id=?').get(req.user.id); res.json(u); });
app.post('/api/orders', auth, (req,res)=>{
  const { plan, amount, type } = req.body||{};
  if(!plan) return res.status(400).json({ error:'اختر الخطة' });
  const id=crypto.randomUUID();
  db.prepare('INSERT INTO orders(id,user_id,email,plan,amount,type,status,created_at) VALUES(?,?,?,?,?,?,?,?)').run(id, req.user.id, req.user.email, plan, String(amount||''), type||'plan', 'قيد المراجعة', new Date().toISOString());
  log('طلب جديد: '+plan+' من '+req.user.email, req.user.email);
  res.json({ id, status:'قيد المراجعة' });
});
app.get('/api/my-orders', auth, (req,res)=>res.json(db.prepare('SELECT * FROM orders WHERE user_id=? ORDER BY created_at DESC').all(req.user.id)));
app.post('/api/messages', (req,res)=>{
  const { name, email, text, category } = req.body||{};
  if(!name||!text) return res.status(400).json({ error:'املأ الاسم والرسالة' });
  db.prepare('INSERT INTO messages(id,name,email,text,category,created_at) VALUES(?,?,?,?,?,?)').run(crypto.randomUUID(), name, email||'', text, category||'استفسار عام', new Date().toISOString());
  res.json({ ok:true });
});
app.post('/api/admin/login', authLimiter, (req,res)=>{
  const { email, pass } = req.body||{};
  const u=db.prepare('SELECT * FROM users WHERE email=? AND role=?').get((email||'').toLowerCase().trim(), 'مدير عام');
  if(!u || !bcrypt.compareSync(pass||'', u.pass_hash)) return res.status(400).json({ error:'بيانات المدير خاطئة' });
  res.json({ token: sign(u), user:{ name:u.name, email:u.email, role:'مدير عام' } });
});
app.get('/api/admin/overview', auth, isAdmin, (req,res)=>res.json({
  users: db.prepare('SELECT COUNT(*) c FROM users').get().c,
  orders: db.prepare('SELECT COUNT(*) c FROM orders').get().c,
  msgs: db.prepare('SELECT COUNT(*) c FROM messages').get().c,
  plans: db.prepare('SELECT COUNT(*) c FROM plans').get().c,
  pending: db.prepare("SELECT COUNT(*) c FROM orders WHERE status='قيد المراجعة'").get().c
}));
app.get('/api/admin/orders', auth, isAdmin, (req,res)=>res.json(db.prepare('SELECT * FROM orders ORDER BY created_at DESC LIMIT 500').all()));
app.post('/api/admin/orders/:id/status', auth, isAdmin, (req,res)=>{
  const o=db.prepare('SELECT * FROM orders WHERE id=?').get(req.params.id);
  if(!o) return res.status(404).json({ error:'الطلب غير موجود' });
  if(!['مقبول','مرفوض','قيد المراجعة'].includes(req.body.status)) return res.status(400).json({ error:'حالة غير صالحة' });
  db.prepare('UPDATE orders SET status=? WHERE id=?').run(req.body.status, req.params.id);
  log('تغيير حالة الطلب '+req.params.id+' إلى '+req.body.status, req.user.email);
  res.json({ ok:true });
});
app.get('/api/admin/users', auth, isAdmin, (req,res)=>res.json(db.prepare('SELECT id,name,email,role,created_at,last_login FROM users ORDER BY created_at DESC').all()));
app.post('/api/admin/users/role', auth, isAdmin, (req,res)=>{
  db.prepare('UPDATE users SET role=? WHERE email=?').run(req.body.role, req.body.email);
  log('تغيير دور '+req.body.email+' إلى '+req.body.role, req.user.email); res.json({ ok:true });
});
app.post('/api/admin/plans', auth, isAdmin, (req,res)=>{
  const id=crypto.randomUUID(); db.prepare('INSERT INTO plans(id,name,icon,desc,tag,ord,active,level) VALUES(?,?,?,?,?,?,?,?)').run(id, req.body.name, req.body.icon||'💎', req.body.desc||'', req.body.tag||'', 99, 1, 50);
  log('إضافة خطة '+req.body.name, req.user.email); res.json({ id });
});
app.delete('/api/admin/plans/:id', auth, isAdmin, (req,res)=>{ db.prepare('DELETE FROM plans WHERE id=?').run(req.params.id); res.json({ ok:true }); });
app.post('/api/admin/ads', auth, isAdmin, (req,res)=>{ const id=crypto.randomUUID(); db.prepare('INSERT INTO ads(id,title,text,created_at) VALUES(?,?,?,?)').run(id, req.body.title, req.body.text||'', new Date().toISOString()); res.json({ id }); });
app.delete('/api/admin/ads/:id', auth, isAdmin, (req,res)=>{ db.prepare('DELETE FROM ads WHERE id=?').run(req.params.id); res.json({ ok:true }); });
app.get('/api/admin/msgs', auth, isAdmin, (req,res)=>res.json(db.prepare('SELECT * FROM messages ORDER BY created_at DESC').all()));
app.get('/api/admin/logs', auth, isAdmin, (req,res)=>res.json(db.prepare('SELECT * FROM logs ORDER BY id DESC LIMIT 200').all()));
app.post('/api/admin/settings', auth, isAdmin, (req,res)=>{ const cur=getSetting('site',{}); setSetting('site', { ...cur, ...req.body }); res.json({ ok:true }); });

app.get('*', (req,res)=>res.sendFile(fs.existsSync(path.join(__dirname,'public','index.html')) ? path.join(__dirname,'public','index.html') : path.join(__dirname,'index.html')));
app.use((err,req,res,next)=>{ console.error(err); res.status(500).json({ error:'خطأ بالسيرفر' }); });
app.listen(PORT, ()=>console.log('✅ KHAZNA real server on http://localhost:'+PORT));
