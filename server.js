// server.js
import express from "express";
import mongoose from "mongoose";
import dotenv from "dotenv";
import cors from "cors";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import OpenAI from "openai";

dotenv.config();
const app = express();
app.use(cors());
app.use(express.json());

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
const JWT_SECRET = process.env.JWT_SECRET || "segredo";
const MONGODB_URI = process.env.MONGODB_URI;

// Conexão com banco (MongoDB Atlas)
mongoose.connect(MONGODB_URI, { dbName: "ebookmaker" })
  .then(() => console.log("✅ Banco conectado"))
  .catch(err => console.error("Erro MongoDB:", err));

// Schema do usuário
const userSchema = new mongoose.Schema({
  email: String,
  passwordHash: String,
  plan: { type: String, default: "free" },
  usage: { date: String, ebooksToday: { type: Number, default: 0 } }
});
userSchema.methods.setPassword = async function (pwd) {
  this.passwordHash = await bcrypt.hash(pwd, 10);
};
userSchema.methods.validatePassword = async function (pwd) {
  return bcrypt.compare(pwd, this.passwordHash);
};
const User = mongoose.model("User", userSchema);

// Schema do eBook
const ebookSchema = new mongoose.Schema({
  userId: String,
  theme: String,
  title: String,
  pages: Number,
  chapters: Array,
  summary: String
}, { timestamps: true });
const Ebook = mongoose.model("Ebook", ebookSchema);

// Middleware de autenticação
async function auth(req, res, next) {
  try {
    const token = (req.headers.authorization || "").replace("Bearer ", "");
    if (!token) return res.status(401).json({ error: "Token ausente" });
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = await User.findById(decoded.id);
    if (!req.user) throw new Error();
    next();
  } catch {
    res.status(401).json({ error: "Não autorizado" });
  }
}

// --- Rotas ---
app.get("/api/health", (_, res) => res.json({ ok: true }));

// Registro
app.post("/api/register", async (req, res) => {
  const { email, password } = req.body;
  const exists = await User.findOne({ email });
  if (exists) return res.status(409).json({ error: "Email já cadastrado" });
  const user = new User({ email });
  await user.setPassword(password);
  await user.save();
  const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: "7d" });
  res.json({ token });
});

// Login
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (!user || !(await user.validatePassword(password))) {
    return res.status(401).json({ error: "Credenciais inválidas" });
  }
  const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: "7d" });
  res.json({ token });
});

// Gerar eBook
app.post("/api/generate", auth, async (req, res) => {
  const { theme, pages = 10 } = req.body;
  if (!theme) return res.status(400).json({ error: "Tema obrigatório" });

  // Limite plano Free: 1 por dia
  const today = new Date().toISOString().split("T")[0];
  if (req.user.plan === "free") {
    if (req.user.usage.date !== today) req.user.usage = { date: today, ebooksToday: 0 };
    if (req.user.usage.ebooksToday >= 1)
      return res.status(402).json({ error: "Limite diário atingido" });
  }

  const prompt = `
  Gere um e-book de ${pages} páginas sobre "${theme}".
  Retorne em JSON:
  { "title": "Título", "chapters": [{"title":"Capítulo 1","content":"..." }], "summary":"..." }
  `;
  const resp = await openai.chat.completions.create({
    model: "gpt-4-turbo",
    messages: [{ role: "user", content: prompt }],
  });

  let content = resp.choices[0].message.content.trim();
  if (content.startsWith("```")) content = content.replace(/```json|```/g, "").trim();
  const data = JSON.parse(content);

  const ebook = await Ebook.create({
    userId: req.user._id,
    theme,
    pages,
    title: data.title,
    chapters: data.chapters,
    summary: data.summary
  });

  req.user.usage.ebooksToday++;
  await req.user.save();

  res.json(ebook);
});

// Listar eBooks
app.get("/api/ebooks", auth, async (req, res) => {
  const ebooks = await Ebook.find({ userId: req.user._id }).sort({ createdAt: -1 });
  res.json(ebooks);
});

// Iniciar servidor local ou exportar pra Vercel
if (process.env.VERCEL) {
  export default app;
} else {
  app.listen(3000, () => console.log("🚀 Rodando em http://localhost:3000"));
}
