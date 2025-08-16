import 'dotenv/config'
import express from 'express'
import cors from 'cors'
import jwt from 'jsonwebtoken'
import { JsonRpcProvider, verifyMessage, Contract, parseUnits } from 'ethers'
import admin from 'firebase-admin'
import { nanoid } from 'nanoid'

const {
  PORT,
  JWT_SECRET,
  FUEL_TOKEN_ADDRESS,
  CHAIN_RPC_URL,
  PAYMENT_ADDRESS,
  PRICE_PER_FUEL
} = process.env

if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert('./cert.json')
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

app.get('/auth/nonce', (req, res) => {
  const { address } = req.query
  if (!address) return res.status(400).json({ error: 'address required' })
  const nonce = nanoid()
  nonces.set(address.toLowerCase(), nonce)
  res.json({ nonce })
})

app.post('/auth/verify', async (req, res) => {
  const { address, signature } = req.body;
  console.log({address, signature});
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

app.post('/race/start', auth, async (req, res) => {
  const addr = req.user.address.toLowerCase()
  const ref = db.collection('players').doc(addr)
  const snap = await ref.get()
  const data = snap.data() || { fuel: 0 }
  if ((data.fuel||0) < 1) return res.json({ ok: false, message: 'Not enough Fuel', fuel: data.fuel||0 })

  const raceId = nanoid()
  await ref.update({ fuel: data.fuel - 1, activeRace: { id: raceId, start: admin.firestore.FieldValue.serverTimestamp() } })
  await db.collection('races').doc(raceId).set({
    address: addr,
    startAt: admin.firestore.FieldValue.serverTimestamp(),
    state: 'running'
  })
  res.json({ ok: true, raceId, fuel: data.fuel - 1 })
})

app.post('/race/complete', auth, async (req, res) => {
  const { timeMs = 999999, crashed = false } = req.body
  const addr = req.user.address.toLowerCase()
  const pref = db.collection('players').doc(addr)
  const psnap = await pref.get()
  const pdata = psnap.data() || {}
  const active = pdata.activeRace

  if (!active) return res.status(400).json({ message: 'No active race' })

  if (crashed) {
    await pref.update({ activeRace: admin.firestore.FieldValue.delete() })
    return res.json({ message: 'Crashed. Better luck next time!', fuel: pdata.fuel||0 })
  }
  if (timeMs < 2000 || timeMs > 60000) {
    await pref.update({ activeRace: admin.firestore.FieldValue.delete() })
    return res.json({ message: 'Invalid time reported', fuel: pdata.fuel||0 })
  }

  await db.collection('races').doc(active.id).set({ state: 'finished', timeMs }, { merge: true })
  await pref.update({ activeRace: admin.firestore.FieldValue.delete() })

  const newFuel = (pdata.fuel||0) + 1
  await pref.update({ fuel: newFuel })

  res.json({ message: 'Finished! +1 Fuel reward', fuel: newFuel, win: true, timeMs })
})

app.listen(PORT, () => console.log(`Fuel Racer backend listening on :${PORT}`))
