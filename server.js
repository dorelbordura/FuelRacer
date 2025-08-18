import 'dotenv/config'
import express from 'express'
import cors from 'cors'
import jwt from 'jsonwebtoken'
import { JsonRpcProvider, verifyMessage, Contract, parseUnits } from 'ethers'
import admin from 'firebase-admin'
import { nanoid } from 'nanoid'
import cron from "node-cron";

const {
  PORT,
  JWT_SECRET,
  FUEL_TOKEN_ADDRESS,
  CHAIN_RPC_URL,
  PAYMENT_ADDRESS,
  PRICE_PER_FUEL,
  FIREBASE_TYPE,
  FIREBASE_PROJECT_ID,
  FIREBASE_PRV_KEY_ID,
  FIREBASE_PRIVATE_KEY,
  FIREBASE_CLIENT_EMAIL,
  FIREBASE_CLIENT_ID,
  AUTH_URI,
  TOKEN_URI,
  AUTH_PROVIDER_CERT,
  CLIENT_CERT_URL,
  UNIVERSE_DOMAIN
} = process.env;

if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert({
      type: FIREBASE_TYPE,
      project_id: FIREBASE_PROJECT_ID,
      private_key_id: FIREBASE_PRV_KEY_ID,
      private_key: FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n'),
      client_email: FIREBASE_CLIENT_EMAIL,
      client_id: FIREBASE_CLIENT_ID,
      auth_uri: AUTH_URI,
      token_uri: TOKEN_URI,
      auth_provider_x509_cert_url: AUTH_PROVIDER_CERT,
      client_x509_cert_url: CLIENT_CERT_URL,
      universe_domain: UNIVERSE_DOMAIN
    })
  })
}
const db = admin.firestore()

const provider = new JsonRpcProvider(CHAIN_RPC_URL)
const tokenAbi = [
  { inputs:[{internalType:'address',name:'account',type:'address'}],
    name:'balanceOf', outputs:[{internalType:'uint256',name:'',type:'uint256'}],
    stateMutability:'view', type:'function' }
]

const app = express()
app.use(cors())
app.use(express.json())

const nonces = new Map()

function auth(req, res, next){
  const header = req.headers.authorization || ''
  const token = header.startsWith('Bearer ') ? header.slice(7) : null
  if (!token) return res.status(401).json({ error: 'No token' })
  try {
    const payload = jwt.verify(token, JWT_SECRET)
    req.user = payload
    next()
  } catch (e) {
    return res.status(401).json({ error: 'Invalid token' })
  }
}

// Helper: verify ERC20 transfer to PAYMENT_ADDRESS for minimum amount
async function verifyPaymentTx(txHash, buyerAddress, minAmount) {
  if (!txHash) return false
  try {
    const receipt = await provider.getTransactionReceipt(txHash)
    if (!receipt || !receipt.logs) return false
    const transferTopic = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a0e5d1e5c"
    for (const log of receipt.logs) {
      if (log.address.toLowerCase() === (FUEL_TOKEN_ADDRESS || '').toLowerCase() && log.topics && log.topics[0] === transferTopic) {
        const from = '0x' + log.topics[1].slice(26)
        const to = '0x' + log.topics[2].slice(26)
        const amount = BigInt(log.data)
        if (to.toLowerCase() === (PAYMENT_ADDRESS || '').toLowerCase() && from.toLowerCase() === buyerAddress.toLowerCase()) {
          if (amount >= BigInt(minAmount)) return true
        }
      }
    }
  } catch (e) {
    console.error('verifyPaymentTx error', e)
  }
  return false
}

function getRaceTimesUTC() {
  const now = new Date();
  const y = now.getUTCFullYear();
  const m = now.getUTCMonth();
  const d = now.getUTCDate();

  // 13:00–13:30 UTC
  const race1Start = new Date(Date.UTC(y, m, d, 13, 0, 0));
  const race1End = new Date(Date.UTC(y, m, d, 14, 0, 0));

  // 21:00–21:30 UTC
  const race2Start = new Date(Date.UTC(y, m, d, 21, 0, 0));
  const race2End = new Date(Date.UTC(y, m, d, 22, 0, 0));

  return [
    { startAt: race1Start, endAt: race1End },
    { startAt: race2Start, endAt: race2End }
  ];
}

async function createDailyRaces() {
  const races = getRaceTimesUTC();

  for (const race of races) {
    const raceId = `${race.startAt.toISOString().slice(0, 10)}_${race.startAt.getUTCHours()}`;
    const ref = db.collection("raceEvents").doc(raceId);
    const snap = await ref.get();
    if (!snap.exists) {
      await ref.set({
        startAt: admin.firestore.Timestamp.fromDate(race.startAt),
        endAt: admin.firestore.Timestamp.fromDate(race.endAt),
        state: "upcoming",
        createdAt: admin.firestore.Timestamp.now()
      });
      console.log(`Created race ${raceId}`);
    }
  }
}

async function updateRaceStates() {
  const now = new Date();
  const snap = await db.collection("raceEvents")
    .where("endAt", ">=", admin.firestore.Timestamp.fromDate(new Date(now.getTime() - 3600*1000)))
    .get();

  for (const doc of snap.docs) {
    const race = doc.data();
    const startAt = race.startAt.toDate();
    const endAt = race.endAt.toDate();

    let newState = "upcoming";
    if (now >= startAt && now <= endAt) {
      newState = "active";
    } else if (now > endAt) {
      newState = "finished";
    }

    if (race.state !== newState) {
      await doc.ref.update({ state: newState });
      console.log(`Race ${doc.id} → ${newState}`);
    }
  }
}

// Cron: check every minute
cron.schedule("* * * * *", async () => {
  await createDailyRaces();
  await updateRaceStates();
});

app.get('/auth/nonce', (req, res) => {
  const { address } = req.query
  if (!address) return res.status(400).json({ error: 'address required' })
  const nonce = nanoid()
  nonces.set(address.toLowerCase(), nonce)
  res.json({ nonce })
})

app.post('/auth/verify', async (req, res) => {
  const { address, signature } = req.body;
  const nonce = nonces.get((address||'').toLowerCase())
  if (!nonce) return res.status(400).json({ error: 'nonce missing' })

  const msg = `FuelRacer login ${nonce}`
  let recovered
  try { recovered = verifyMessage(msg, signature) }
  catch { return res.status(400).json({ error: 'bad signature' }) }

  if (recovered.toLowerCase() !== address.toLowerCase()) {
    return res.status(400).json({ error: 'address/signature mismatch' })
  }
  nonces.delete(address.toLowerCase())

  const token = new Contract(FUEL_TOKEN_ADDRESS, tokenAbi, provider)
  const bal = await token.balanceOf(address)
  const min = parseUnits('10000000', 18)
  const hasAccess = bal >= min

  const ref = db.collection('players').doc(address.toLowerCase())
  const snap = await ref.get()
  if (!snap.exists) {
    await ref.set({ fuel: 0, lastClaim: null, createdAt: admin.firestore.FieldValue.serverTimestamp() })
  }

  const jwtToken = jwt.sign({ address, hasAccess }, JWT_SECRET, { expiresIn: '7d' })
  res.json({ token: jwtToken, hasAccess })
})

app.get('/player/me', auth, async (req, res) => {
  const addr = req.user.address.toLowerCase()
  const doc = await db.collection('players').doc(addr).get()
  res.json(doc.data() || {})
})

app.post('/fuel/claimDaily', auth, async (req, res) => {
  const addr = req.user.address.toLowerCase()
  const ref = db.collection('players').doc(addr)
  const snap = await ref.get()
  const data = snap.data() || { fuel: 0 }
  const now = Date.now()
  const last = data.lastClaim?.toMillis?.() || 0
  const oneDay = 24 * 60 * 60 * 1000
  if (now - last < oneDay) {
    return res.json({ message: 'Daily already claimed', fuel: data.fuel })
  }
  await ref.update({ fuel: (data.fuel||0)+1, lastClaim: admin.firestore.FieldValue.serverTimestamp() })
  const updated = await ref.get()
  res.json({ message: 'Daily +1 Fuel', fuel: updated.data().fuel })
})

app.post('/fuel/purchase', auth, async (req, res) => {
  const { amount = 1, txHash } = req.body
  const addr = req.user.address.toLowerCase()
  const ref = db.collection('players').doc(addr)
  const snap = await ref.get()
  const data = snap.data() || { fuel: 0 }

  const units = Math.max(1, Math.min(100, amount))
  const pricePerFuel = PRICE_PER_FUEL ? parseUnits(PRICE_PER_FUEL, 18) : parseUnits('1', 18)
  const totalPrice = pricePerFuel * BigInt(units)

  if (!PAYMENT_ADDRESS) return res.status(500).json({ error: 'PAYMENT_ADDRESS not configured' })
  const ok = await verifyPaymentTx(txHash, addr, totalPrice)
  if (!ok) return res.status(400).json({ error: 'Payment verification failed. Provide txHash of a valid transfer.' })

  const newFuel = (data.fuel||0) + units
  await ref.set({ ...data, fuel: newFuel }, { merge: true })
  res.json({ fuel: newFuel })
})

// Public: get summary (active + next upcoming)
app.get('/races/summary', async (req, res) => {
  const activeSnap = await db.collection('raceEvents').where('state','==','active').orderBy('startAt','asc').limit(1).get()
  const active = activeSnap.docs[0]?.data() ? ({ id: activeSnap.docs[0].id, ...activeSnap.docs[0].data() }) : null

  const upcomingSnap = await db.collection('raceEvents').where('state','==','upcoming').orderBy('startAt','asc').limit(2).get()
  const upcoming = upcomingSnap.docs.map(d => ({ id: d.id, ...d.data() }))
  res.json({ active, upcoming })
})

// Public: list past (finished) events
app.get('/races/past', async (req, res) => {
  const n = Math.min(100, Math.max(1, Number(req.query.limit||20)))
  const snap = await db.collection('raceEvents').where('state','==','finished').orderBy('endAt','desc').limit(n).get()
  const items = snap.docs.map(d => ({ id: d.id, ...d.data() }))
  res.json({ items })
})

// Public: leaderboard top N (default 10)
app.get('/races/:id/leaderboard', async (req, res) => {
  const top = Math.min(50, Math.max(1, Number(req.query.top||10)))
  const q = await db.collection('raceEvents').doc(req.params.id).collection('results').orderBy('bestTime','asc').limit(top).get()
  const rows = q.docs.map((d, i) => ({ rank: i+1, id: d.id, ...d.data() }))
  res.json({ rows })
})

// ======================== RUNS (server-timed) ======================
// Start a run: consume 1 fuel, validate race active, record server start
app.post('/runs/start', auth, async (req, res) => {
  const { raceId } = req.body || {}
  const addr = req.user.address.toLowerCase()
  if (!raceId) return res.status(400).json({ error: 'raceId required' })

  const raceRef = db.collection('raceEvents').doc(raceId)
  const playerRef = db.collection('players').doc(addr)
  try {
    const result = await db.runTransaction(async (tx) => {
      const [raceSnap, playerSnap] = await Promise.all([ tx.get(raceRef), tx.get(playerRef) ])
      if (!raceSnap.exists) throw new Error('Race not found')
      const race = raceSnap.data()
      if (race.state !== 'active') throw new Error('Race not active')

      const player = playerSnap.data() || { fuel: 0 }
      const fuel = player.fuel || 0
      if (fuel < 1) throw new Error('Not enough Fuel')

      const runRef = raceRef.collection('runs').doc()
      tx.set(runRef, { playerAddress: addr, startedAt: admin.firestore.FieldValue.serverTimestamp() })
      tx.update(playerRef, { fuel: fuel - 1 })

      return { runId: runRef.id, fuel: fuel - 1 }
    })
    res.json({ ok: true, ...result })
  } catch (e) {
    res.status(400).json({ ok: false, error: e.message })
  }
})

// Finish a run: compute elapsed on server, update best result
app.post('/runs/finish', auth, async (req, res) => {
  const { raceId, runId } = req.body || {}
  const dateNow = Date.now();
  const addr = req.user.address.toLowerCase()
  if (!raceId || !runId) return res.status(400).json({ error: 'raceId and runId required' })

  const raceRef = db.collection('raceEvents').doc(raceId)
  const runRef = raceRef.collection('runs').doc(runId)
  const resultRef = raceRef.collection('results').doc(addr)

  try {
    let elapsedMsOut = 0
    await db.runTransaction(async (tx) => {
      const [raceSnap, runSnap, resultSnap] = await Promise.all([
        tx.get(raceRef), tx.get(runRef), tx.get(resultRef)
      ])
      if (!runSnap.exists) throw new Error('Run not found')
      const run = runSnap.data()
      if (run.finishedAt) throw new Error('Run already finished')

      const race = raceSnap.data()
      const now = admin.firestore.Timestamp.now()
      const startedAt = run.startedAt?.toDate?.()
      if (!startedAt) throw new Error('Run missing start time')

      // Allow finish while active or within 15s after end
      const endMs = race.endAt?.toMillis?.() || 0
      const nowMs = now.toMillis()
      if (race.state === 'finished' && nowMs > endMs + 15000) throw new Error('Race finished')

      const elapsedMs = dateNow - startedAt.getTime()
      if (elapsedMs < 2000 || elapsedMs > 5*60*1000) throw new Error('Invalid elapsed time')

      tx.update(runRef, { finishedAt: now, elapsedMs })
      elapsedMsOut = elapsedMs

      if (!resultSnap.exists) {
        tx.set(resultRef, { playerAddress: addr, bestTime: elapsedMs, attempts: 1, updatedAt: now })
      } else {
        const r = resultSnap.data()
        const best = Math.min(r.bestTime || Number.MAX_SAFE_INTEGER, elapsedMs)
        tx.update(resultRef, { bestTime: best, attempts: (r.attempts||0)+1, updatedAt: now })
      }
    })
    res.json({ ok: true, elapsedMs: elapsedMsOut })
  } catch (e) {
    res.status(400).json({ ok: false, error: e.message })
  }
})


app.listen(PORT, () => console.log(`Fuel Racer backend listening on :_|_`));


