const express = require('express');
const { Pool, types } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');

types.setTypeParser(20, Number); // bigint -> number (amounts are whole FRW)

const SECRET = process.env.JWT_SECRET;
if (!SECRET || !process.env.DATABASE_URL) {
  console.error('Shyiraho DATABASE_URL na JWT_SECRET muri Environment Variables');
  process.exit(1);
}
const db = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });
const app = express();
app.use(express.json());

const fail = (status, msg) => Object.assign(new Error(msg), { status });
const wrap = f => (req, res) => f(req, res).catch(e => {
  if (!e.status) console.error(e);
  res.status(e.status || 500).json({ error: e.status ? e.message : 'Ikosa muri server' });
});
const tx = async f => {
  const c = await db.connect();
  try { await c.query('begin'); const r = await f(c); await c.query('commit'); return r; }
  catch (e) { await c.query('rollback'); throw e; }
  finally { c.release(); }
};
const int = (v, min = 1) => { const n = Number(v); if (!Number.isInteger(n) || n < min) throw fail(400, 'Umubare si wo'); return n; };
const wh = w => { if (!['A', 'B'].includes(w)) throw fail(400, 'Ububiko si bwo'); return w; };

// Uruhare rufatwa muri database buri gihe, ntabwo rwizerwa mu busabe
const auth = (...roles) => async (req, res, next) => {
  try {
    const { id } = jwt.verify((req.headers.authorization || '').replace('Bearer ', ''), SECRET);
    const u = (await db.query('select id,name,role,balance from users where id=$1', [id])).rows[0];
    if (!u) throw new Error('no user');
    if (roles.length && !roles.includes(u.role)) return res.status(403).json({ error: 'Nta burenganzira ufite' });
    req.user = u; next();
  } catch { res.status(401).json({ error: 'Ongera winjire (login)' }); }
};

async function init() {
  await db.query(`
    create table if not exists users(id serial primary key, name text not null, email text unique not null,
      password text not null, role text not null default 'STAFF', balance bigint not null default 0);
    create table if not exists products(id serial primary key, name text unique not null, unit_price bigint not null default 0);
    create table if not exists stock(product_id int references products(id), warehouse text,
      qty int not null default 0 check (qty >= 0), primary key(product_id, warehouse));
    create table if not exists sales(id serial primary key, user_id int references users(id), product_id int references products(id),
      warehouse text, qty int, total bigint, created_at timestamptz default now());
    create table if not exists withdrawals(id serial primary key, user_id int references users(id), amount bigint not null,
      bank_name text, account_no text, status text not null default 'PENDING', approved_by int, created_at timestamptz default now());
    create table if not exists transactions(id serial primary key, user_id int references users(id), amount bigint,
      type text, description text, created_at timestamptz default now());
    insert into products(name) values ('Isukari ya Lugazi'),('Isukari ya Hoima'),('Umunyu wa Neel'),
      ('Umuceri wa Bugarama'),('Ifarini ya Ibanga') on conflict do nothing;`);
}

// ---- Auth ----
app.post('/api/setup', wrap(async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password || password.length < 8) throw fail(400, 'Uzuza byose; password nibura inyuguti 8');
  if ((await db.query('select 1 from users limit 1')).rowCount) throw fail(403, 'Setup yarangiye');
  await db.query('insert into users(name,email,password,role) values($1,$2,$3,$4)',
    [name, email.toLowerCase(), await bcrypt.hash(password, 10), 'CEO']);
  res.json({ ok: true });
}));

app.post('/api/login', wrap(async (req, res) => {
  const { email = '', password = '' } = req.body;
  const u = (await db.query('select * from users where email=$1', [email.toLowerCase()])).rows[0];
  if (!u || !(await bcrypt.compare(password, u.password))) throw fail(401, 'Email cyangwa password si byo');
  res.json({ token: jwt.sign({ id: u.id }, SECRET, { expiresIn: '12h' }) });
}));

app.get('/api/me', auth(), (req, res) => res.json(req.user));

app.get('/api/users', auth('CEO'), wrap(async (req, res) =>
  res.json((await db.query('select id,name,role,balance from users order by name')).rows)));

app.post('/api/users', auth('CEO'), wrap(async (req, res) => {
  const { name, email, password, role } = req.body;
  if (!name || !email || !password || password.length < 8 || !['ADMIN', 'STAFF'].includes(role)) throw fail(400, 'Amakuru ntabwo yuzuye');
  try {
    await db.query('insert into users(name,email,password,role) values($1,$2,$3,$4)',
      [name, email.toLowerCase(), await bcrypt.hash(password, 10), role]);
  } catch (e) { if (e.code === '23505') throw fail(400, 'Iyi email irakoreshwa'); throw e; }
  res.json({ ok: true });
}));

// ---- Inventory ----
app.get('/api/inventory', auth(), wrap(async (req, res) => res.json((await db.query(
  `select p.id,p.name,p.unit_price,w.warehouse,coalesce(s.qty,0) qty
   from products p cross join (values ('A'),('B')) w(warehouse)
   left join stock s on s.product_id=p.id and s.warehouse=w.warehouse order by p.name,w.warehouse`)).rows)));

app.post('/api/inventory/add', auth('CEO', 'ADMIN'), wrap(async (req, res) => {
  const qty = int(req.body.qty);
  await db.query(`insert into stock(product_id,warehouse,qty) values($1,$2,$3)
    on conflict(product_id,warehouse) do update set qty=stock.qty+$3`, [int(req.body.productId), wh(req.body.warehouse), qty]);
  res.json({ ok: true });
}));

app.patch('/api/products/:id', auth('CEO', 'ADMIN'), wrap(async (req, res) => {
  await db.query('update products set unit_price=$1 where id=$2', [int(req.body.unitPrice, 0), int(req.params.id)]);
  res.json({ ok: true });
}));

// ---- Sales (stock igabanuka muri transaction imwe) ----
app.post('/api/sales', auth(), wrap(async (req, res) => {
  const qty = int(req.body.qty), pid = int(req.body.productId), w = wh(req.body.warehouse);
  const total = await tx(async c => {
    const p = (await c.query('select unit_price from products where id=$1', [pid])).rows[0];
    if (!p) throw fail(404, 'Igicuruzwa nticyabonetse');
    const u = await c.query('update stock set qty=qty-$1 where product_id=$2 and warehouse=$3 and qty>=$1', [qty, pid, w]);
    if (!u.rowCount) throw fail(400, 'Stock ntihagije muri ubu bubiko');
    const t = qty * p.unit_price;
    await c.query('insert into sales(user_id,product_id,warehouse,qty,total) values($1,$2,$3,$4,$5)', [req.user.id, pid, w, qty, t]);
    return t;
  });
  res.json({ total });
}));

app.get('/api/sales/report', auth('CEO', 'ADMIN'), wrap(async (req, res) => res.json((await db.query(
  `select count(*) filter (where created_at::date = (now() at time zone 'Africa/Kigali')::date) today_count,
          coalesce(sum(total) filter (where created_at::date = (now() at time zone 'Africa/Kigali')::date),0) today_total,
          count(*) all_count, coalesce(sum(total),0) all_total from sales`)).rows[0])));

// ---- Amafaranga ----
app.post('/api/deposit', auth('CEO'), wrap(async (req, res) => {
  const amount = int(req.body.amount), uid = int(req.body.userId);
  await tx(async c => {
    if (!(await c.query('update users set balance=balance+$1 where id=$2', [amount, uid])).rowCount) throw fail(404, 'Umukozi ntabonetse');
    await c.query('insert into transactions(user_id,amount,type,description) values($1,$2,$3,$4)', [uid, amount, 'DEPOSIT', 'Yongewe na CEO']);
  });
  res.json({ ok: true });
}));

app.post('/api/withdrawals', auth(), wrap(async (req, res) => {
  const amount = int(req.body.amount), { bankName, accountNo } = req.body;
  if (!bankName || !accountNo) throw fail(400, 'Andika banki/MoMo na nimero');
  const pend = (await db.query(`select coalesce(sum(amount),0) s from withdrawals where user_id=$1 and status='PENDING'`, [req.user.id])).rows[0].s;
  if (amount > req.user.balance - pend) throw fail(400, 'Balance yawe ntihagije');
  await db.query('insert into withdrawals(user_id,amount,bank_name,account_no) values($1,$2,$3,$4)', [req.user.id, amount, bankName, accountNo]);
  res.json({ ok: true });
}));

app.get('/api/withdrawals/mine', auth(), wrap(async (req, res) => res.json((await db.query(
  'select id,amount,status,created_at from withdrawals where user_id=$1 order by id desc limit 20', [req.user.id])).rows)));

app.get('/api/withdrawals/pending', auth('CEO'), wrap(async (req, res) => res.json((await db.query(
  `select w.id,w.amount,w.bank_name,w.account_no,u.name from withdrawals w join users u on u.id=w.user_id
   where w.status='PENDING' order by w.id`)).rows)));

app.patch('/api/withdrawals/:id', auth('CEO'), wrap(async (req, res) => {
  const { status } = req.body;
  if (!['APPROVED', 'REJECTED'].includes(status)) throw fail(400, 'Status si yo');
  await tx(async c => {
    const w = (await c.query('select * from withdrawals where id=$1 for update', [int(req.params.id)])).rows[0];
    if (!w || w.status !== 'PENDING') throw fail(400, 'Ubu busabe ntibukiri PENDING');
    if (status === 'APPROVED') {
      const u = await c.query('update users set balance=balance-$1 where id=$2 and balance>=$1', [w.amount, w.user_id]);
      if (!u.rowCount) throw fail(400, 'Balance y\'umukozi ntihagije');
      await c.query('insert into transactions(user_id,amount,type,description) values($1,$2,$3,$4)',
        [w.user_id, w.amount, 'WITHDRAWAL', 'Withdrawal yemejwe na ' + req.user.name]);
    }
    await c.query('update withdrawals set status=$1, approved_by=$2 where id=$3', [status, req.user.id, w.id]);
  });
  res.json({ ok: true });
}));

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

init().then(() => app.listen(process.env.PORT || 3000, () => console.log('Server iri gukora')))
  .catch(e => { console.error('Database ntiyakoze:', e.message); process.exit(1); });
