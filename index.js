const express = require('express');
const mongoose = require('mongoose');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcryptjs');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

const MONGODB_URI = 'mongodb+srv://gallery:gallery@cluster0.9zkt0hl.mongodb.net/gallery?retryWrites=true&w=majority&appName=Cluster0';
const SESSION_SECRET = 'super_secret_key_change_this_in_production';

app.set('trust proxy', 1);

app.use(helmet({
  contentSecurityPolicy: false,
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: { success: false, message: 'Terlalu banyak percobaan login, coba lagi 15 menit kemudian.' }
});

const sessionConfig = {
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({ mongoUrl: MONGODB_URI }),
  cookie: {
    httpOnly: true,
    sameSite: 'none',
    secure: true,
    maxAge: 1000 * 60 * 60 * 24
  }
};

if (process.env.NODE_ENV !== 'production') {
  sessionConfig.cookie.sameSite = 'lax';
  sessionConfig.cookie.secure = false;
}

app.use(session(sessionConfig));

mongoose.connect(MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
}).then(() => console.log('✅ MongoDB Connected')).catch(err => console.log(err));

const AdminSchema = new mongoose.Schema({
  username: { type: String, unique: true, required: true },
  password: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
});

const GallerySchema = new mongoose.Schema({
  title: { type: String, unique: true, required: true },
  images: [{
    _id: { type: mongoose.Schema.Types.ObjectId, auto: true },
    url: { type: String, required: true }
  }],
  createdAt: { type: Date, default: Date.now }
});

const Admin = mongoose.model('Admin', AdminSchema);
const Gallery = mongoose.model('Gallery', GallerySchema);

async function autoCreateAdmin() {
  const adminExists = await Admin.findOne({ username: 'kila' });
  if (!adminExists) {
    const hashedPass = await bcrypt.hash('imut', 10);
    await Admin.create({ username: 'kila', password: hashedPass });
    console.log('✅ Admin default dibuat: username=kila, password=imut');
  }
}

function isAuthenticated(req, res, next) {
  if (req.session.userId) return next();
  res.redirect('/login');
}

function isAuthenticatedApi(req, res, next) {
  if (req.session.userId) return next();
  res.status(401).json({ success: false, message: 'Unauthorized' });
}

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/login', (req, res) => {
  if (req.session.userId) return res.redirect('/admin');
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/admin', isAuthenticated, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

app.get('/api/gallery', async (req, res) => {
  try {
    const albums = await Gallery.find().sort({ createdAt: -1 });
    res.json({ success: true, data: albums });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

app.get('/api/gallery/:id', async (req, res) => {
  try {
    const album = await Gallery.findById(req.params.id);
    if (!album) return res.status(404).json({ success: false, message: 'Album tidak ditemukan' });
    res.json({ success: true, data: album });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

app.get('/api/admin/albums', isAuthenticatedApi, async (req, res) => {
  try {
    const albums = await Gallery.find().sort({ createdAt: -1 });
    res.json({ success: true, data: albums });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

app.post('/api/admin/add-album', isAuthenticatedApi, async (req, res) => {
  try {
    const { title } = req.body;
    if (!title || title.trim() === '') {
      return res.status(400).json({ success: false, message: 'Judul album tidak boleh kosong' });
    }
    const existing = await Gallery.findOne({ title: title.trim() });
    if (existing) {
      return res.status(400).json({ success: false, message: 'Judul album sudah ada' });
    }
    const album = new Gallery({ title: title.trim(), images: [] });
    await album.save();
    res.json({ success: true, message: 'Album berhasil ditambahkan', data: album });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

app.delete('/api/admin/delete-album/:id', isAuthenticatedApi, async (req, res) => {
  try {
    const album = await Gallery.findByIdAndDelete(req.params.id);
    if (!album) return res.status(404).json({ success: false, message: 'Album tidak ditemukan' });
    res.json({ success: true, message: 'Album berhasil dihapus' });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

app.post('/api/admin/add-image', isAuthenticatedApi, async (req, res) => {
  try {
    const { albumId, imageUrl } = req.body;
    if (!albumId || !imageUrl || imageUrl.trim() === '') {
      return res.status(400).json({ success: false, message: 'Album ID dan URL gambar wajib diisi' });
    }
    try {
      new URL(imageUrl);
    } catch (_) {
      return res.status(400).json({ success: false, message: 'URL gambar tidak valid' });
    }
    const album = await Gallery.findById(albumId);
    if (!album) return res.status(404).json({ success: false, message: 'Album tidak ditemukan' });
    album.images.push({ url: imageUrl.trim() });
    await album.save();
    res.json({ success: true, message: 'Gambar berhasil ditambahkan', data: album });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

app.delete('/api/admin/delete-image', isAuthenticatedApi, async (req, res) => {
  try {
    const { albumId, imageId } = req.body;
    if (!albumId || !imageId) {
      return res.status(400).json({ success: false, message: 'Parameter tidak lengkap' });
    }
    const album = await Gallery.findById(albumId);
    if (!album) return res.status(404).json({ success: false, message: 'Album tidak ditemukan' });
    album.images = album.images.filter(img => img._id.toString() !== imageId);
    await album.save();
    res.json({ success: true, message: 'Gambar berhasil dihapus', data: album });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

app.post('/login', loginLimiter, async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ success: false, message: 'Username dan password harus diisi' });
    }
    const admin = await Admin.findOne({ username });
    if (!admin) {
      return res.status(401).json({ success: false, message: 'Username atau password salah' });
    }
    const match = await bcrypt.compare(password, admin.password);
    if (!match) {
      return res.status(401).json({ success: false, message: 'Username atau password salah' });
    }
    req.session.userId = admin._id;
    await new Promise((resolve, reject) => {
      req.session.save((err) => {
        if (err) reject(err);
        else resolve();
      });
    });
    res.json({ success: true, message: 'Login berhasil', redirect: '/admin' });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

app.post('/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) return res.status(500).json({ success: false, message: err.message });
    res.json({ success: true, message: 'Logout berhasil', redirect: '/login' });
  });
});

app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ success: false, message: 'Terjadi kesalahan server' });
});

mongoose.connection.once('open', async () => {
  await autoCreateAdmin();
  app.listen(PORT, () => console.log(`🚀 Server berjalan di http://localhost:${PORT}`));
});
