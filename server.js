const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const dotenv = require('dotenv');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const twilio = require('twilio');

dotenv.config();

const app = express();
app.disable('x-powered-by');
const PORT = Number(process.env.PORT) || 3000;
const NUMEROS_FILE = path.join(__dirname, 'numeros-vendidos.json');
const OWNER_CODE = String(process.env.OWNER_CODE || 'Ken_1.8.1.6').trim();
const SELLER_WHATSAPP_NUMBER = String(process.env.SELLER_WHATSAPP_NUMBER || '').trim();
const TWILIO_ACCOUNT_SID = process.env.TWILIO_ACCOUNT_SID || '';
const TWILIO_AUTH_TOKEN = process.env.TWILIO_AUTH_TOKEN || '';
const TWILIO_WHATSAPP_NUMBER = process.env.TWILIO_WHATSAPP_NUMBER || '';
const OWNER_SESSION_TTL_MS = 15 * 60 * 1000;
const ownerSessions = new Map();

const limpiarSesionesExpiradas = () => {
  const ahora = Date.now();
  for (const [token, session] of ownerSessions) {
    if (ahora > session.expiresAt) ownerSessions.delete(token);
  }
};

const leerNumerosVendidos = () => {
  try {
    const contenido = fs.readFileSync(NUMEROS_FILE, 'utf8');
    const numeros = JSON.parse(contenido);
    return Array.isArray(numeros) ? numeros.filter((n) => /^\d{4}$/.test(String(n))) : [];
  } catch (error) {
    if (error.code !== 'ENOENT') {
      console.error('No se pudo leer los números vendidos:', error);
    }
    return [];
  }
};

const guardarNumerosVendidos = (numeros) => {
  const listaFinal = [...new Set(numeros.filter((n) => /^\d{4}$/.test(String(n))))].sort();
  const temporal = `${NUMEROS_FILE}.${process.pid}.tmp`;
  fs.writeFileSync(temporal, JSON.stringify(listaFinal), 'utf8');
  fs.renameSync(temporal, NUMEROS_FILE);
};

const normalizarNumero = (valor) => String(valor ?? '').replace(/\D/g, '').slice(0, 4).padStart(4, '0');
const normalizarTelefono = (valor) => String(valor ?? '').replace(/\D/g, '').slice(0, 20);
const sanitizarTexto = (valor) => String(valor ?? '').replace(/[<>]/g, '').trim().slice(0, 80);

const limitarTasa = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
  message: { ok: false, message: 'Demasiadas solicitudes. Intenta de nuevo más tarde.' }
});

const autenticarDueño = (req, res, next) => {
  const authHeader = String(req.headers.authorization || '');
  const match = authHeader.match(/^Bearer\s+(.+)$/i);

  if (!match) {
    return res.status(401).json({ ok: false, message: 'Token de propietario requerido.' });
  }

  const token = match[1];
  const session = ownerSessions.get(token);

  if (!session || Date.now() > session.expiresAt) {
    ownerSessions.delete(token);
    return res.status(401).json({ ok: false, message: 'Sesión de propietario expirada o inválida.' });
  }

  req.ownerToken = token;
  return next();
};

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", 'data:'],
      connectSrc: ["'self'"],
      objectSrc: ["'none'"],
      baseUri: ["'self'"],
      formAction: ["'self'"],
      frameAncestors: ["'none'"]
    }
  },
  crossOriginResourcePolicy: { policy: 'same-origin' }
}));
app.use(express.json({ limit: '1mb' }));
app.use('/api', limitarTasa);
app.use(express.static(__dirname));

app.get('/api/config', (req, res) => {
  res.json({
    ok: true,
    precioNumero: 200,
    sellerWhatsapp: SELLER_WHATSAPP_NUMBER,
    maxNumerosPorPedido: 10
  });
});

app.get('/api/numeros-vendidos', (req, res) => {
  res.json({ ok: true, numeros: leerNumerosVendidos() });
});

app.post('/api/owner/validate', (req, res) => {
  limpiarSesionesExpiradas();
  const codigo = String(req.body?.codigo || '').trim();

  if (!OWNER_CODE) { 
    return res.status(503).json({ ok: false, message: 'No se ha configurado el código del dueño en el servidor.' });
  }

  const codigoBuffer = Buffer.from(codigo);
  const ownerCodeBuffer = Buffer.from(OWNER_CODE);
  if (codigoBuffer.length !== ownerCodeBuffer.length || !crypto.timingSafeEqual(codigoBuffer, ownerCodeBuffer)) {
    return res.status(401).json({ ok: false, message: 'Código incorrecto.' });
  }

  const token = crypto.randomBytes(24).toString('hex');
  ownerSessions.set(token, { expiresAt: Date.now() + OWNER_SESSION_TTL_MS });

  return res.json({ ok: true, token });
});

app.post('/api/owner/toggle-numero', autenticarDueño, (req, res) => {
  const numero = normalizarNumero(req.body?.numero);

  if (!/^\d{4}$/.test(numero)) {
    return res.status(400).json({ ok: false, message: 'Número inválido.' });
  }

  const vendidos = new Set(leerNumerosVendidos());

  if (vendidos.has(numero)) {
    vendidos.delete(numero);
  } else {
    vendidos.add(numero);
  }

  guardarNumerosVendidos([...vendidos]);
  return res.json({ ok: true, numeros: [...vendidos].sort() });
});

app.post('/api/confirmar-compra', async (req, res) => {
  const nombre = sanitizarTexto(req.body?.nombre);
  const telefono = normalizarTelefono(req.body?.telefono ?? req.body?.numero ?? '');
  const numerosSeleccionados = Array.isArray(req.body?.numeros) ? req.body.numeros : [];

  if (!nombre || nombre.length < 2) {
    return res.status(400).json({ ok: false, message: 'Escribe un nombre válido.' });
  }

  if (telefono && telefono.length < 8) {
    return res.status(400).json({ ok: false, message: 'Si agregas teléfono, debe ser válido.' });
  }

  if (!numerosSeleccionados.length || numerosSeleccionados.length > 10) {
    return res.status(400).json({ ok: false, message: 'Debes elegir entre 1 y 10 números.' });
  }

  const numeros = [];
  const vistos = new Set();

  for (const item of numerosSeleccionados) {
    const numero = normalizarNumero(item);
    if (!/^\d{4}$/.test(numero) || vistos.has(numero)) continue;
    vistos.add(numero);
    numeros.push(numero);
  }

  if (!numeros.length || numeros.length > 10) {
    return res.status(400).json({ ok: false, message: 'El pedido incluye números inválidos o repetidos.' });
  }

  const vendidos = new Set(leerNumerosVendidos());
  const yaVendidos = numeros.filter((numero) => vendidos.has(numero));

  if (yaVendidos.length) {
    return res.status(409).json({
      ok: false,
      message: `Los números ${yaVendidos.join(', ')} ya están vendidos.`
    });
  }

  const listaActualizada = [...new Set([...vendidos, ...numeros])].sort();
  guardarNumerosVendidos(listaActualizada);

  const formatted = numeros.map((n) => `*${n}*`).join(', ');
  const infoTelefono = telefono ? `\n\n📱 WhatsApp del cliente: ${telefono}` : '';
  const message = `¡Buenas buenas ${nombre}! 👋\n\n✅ Recibimos tu compra de sticker(s) con el/los número(s):\n${formatted}\n\n📸 Recuerda que para recibir tus stickers debes enviar la imagen de transferencia que confirma el pago${infoTelefono}`;

  if (!SELLER_WHATSAPP_NUMBER) {
    console.log('--- WhatsApp message preview ---');
    console.log(message);
    return res.json({
      ok: true,
      message: 'Pedido recibido. Configura SELLER_WHATSAPP_NUMBER para enviar el mensaje automáticamente.',
      preview: message,
      whatsapp: `https://wa.me/?text=${encodeURIComponent(message)}`
    });
  }

  if (!TWILIO_ACCOUNT_SID || !TWILIO_AUTH_TOKEN || !TWILIO_WHATSAPP_NUMBER) {
    console.log('--- WhatsApp message preview ---');
    console.log(message);
    return res.json({
      ok: true,
      message: 'Pedido recibido. Configura Twilio para enviar el mensaje automáticamente.',
      preview: message,
      whatsapp: `https://wa.me/${SELLER_WHATSAPP_NUMBER}?text=${encodeURIComponent(message)}`
    });
  }

  try {
    const client = twilio(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN);
    await client.messages.create({
      from: TWILIO_WHATSAPP_NUMBER,
      to: SELLER_WHATSAPP_NUMBER,
      body: message
    });

    return res.json({
      ok: true,
      message: 'Pedido enviado correctamente.',
      whatsapp: `https://wa.me/${SELLER_WHATSAPP_NUMBER}?text=${encodeURIComponent(message)}`
    });
  } catch (error) {
    console.error('Twilio error:', error);
    return res.status(500).json({ ok: false, message: 'No se pudo enviar el WhatsApp.' });
  }
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, () => {
  console.log(`Servidor listo en http://localhost:${PORT}`);
});
