// chat/server.js
const express = require("express");
const admin = require("firebase-admin");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const { PrismaClient } = require("@prisma/client");
require("dotenv").config();

const app = express();
const prisma = new PrismaClient();

// ===================== FIREBASE INIT =====================
const serviceAccount = {
  type: "service_account",
  project_id: process.env.FIREBASE_PROJECT_ID,
  private_key_id: process.env.FIREBASE_PRIVATE_KEY_ID,
  private_key: process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, "\n"),
  client_email: process.env.FIREBASE_CLIENT_EMAIL,
  client_id: process.env.FIREBASE_CLIENT_ID,
  auth_uri: "https://accounts.google.com/o/oauth2/auth",
  token_uri: "https://oauth2.googleapis.com/token",
  auth_provider_x509_cert_url: "https://www.googleapis.com/oauth2/v1/certs",
  client_x509_cert_url: process.env.FIREBASE_CLIENT_EMAIL
    ? `https://www.googleapis.com/robot/v1/metadata/x509/${process.env.FIREBASE_CLIENT_EMAIL}`
    : undefined,
};

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  projectId: process.env.FIREBASE_PROJECT_ID,
});

// ===================== MIDDLEWARE =====================
app.use(
  cors({
    origin: process.env.FRONTEND_URL || "http://localhost:3000",
    credentials: true,
  })
);
app.use(express.json({ limit: "10mb" }));

// Rate limiting
const limiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: 100, // limit each IP to 100 requests per window
});
app.use("/api/", limiter);

// Chat-specific limiter
const chatLimiter = rateLimit({
  windowMs: 1 * 60 * 1000,
  max: 30,
});

// Auth middleware
const authenticateToken = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    const token = authHeader && authHeader.split(" ")[1];
    if (!token) return res.status(401).json({ error: "Access token required" });

    const decodedToken = await admin.auth().verifyIdToken(token);
    req.user = decodedToken;
    next();
  } catch (error) {
    console.error("Token verification error:", error);
    res.status(403).json({ error: "Invalid token" });
  }
};

// ===================== AUTH ROUTES =====================
app.get("/api/health", (req, res) => {
  res.json({ status: "OK", message: "Chat Backend is running" });
});

app.get("/api/user/profile", authenticateToken, async (req, res) => {
  try {
    const userRecord = await admin.auth().getUser(req.user.uid);
    res.json({ user: userRecord });
  } catch (error) {
    console.error("Error getting user profile:", error);
    res.status(500).json({ error: "Failed to get user profile" });
  }
});

app.put("/api/user/profile", authenticateToken, async (req, res) => {
  try {
    const { displayName, photoURL } = req.body;
    const updateData = {};
    if (displayName) updateData.displayName = displayName;
    if (photoURL) updateData.photoURL = photoURL;

    await admin.auth().updateUser(req.user.uid, updateData);
    res.json({ message: "Profile updated successfully" });
  } catch (error) {
    console.error("Error updating profile:", error);
    res.status(500).json({ error: "Failed to update profile" });
  }
});

app.delete("/api/user/account", authenticateToken, async (req, res) => {
  try {
    await prisma.message.deleteMany({ where: { userId: req.user.uid } });
    await prisma.conversation.deleteMany({ where: { userId: req.user.uid } });
    await admin.auth().deleteUser(req.user.uid);

    res.json({ message: "Account and chat data deleted successfully" });
  } catch (error) {
    console.error("Error deleting account:", error);
    res.status(500).json({ error: "Failed to delete account" });
  }
});

// ===================== CHAT ROUTES =====================
app.get("/api/chat/conversations", authenticateToken, async (req, res) => {
  try {
    const conversations = await prisma.conversation.findMany({
      where: { userId: req.user.uid },
      include: {
        messages: { take: 1, orderBy: { createdAt: "desc" } },
      },
      orderBy: { updatedAt: "desc" },
    });
    res.json({ conversations });
  } catch (error) {
    console.error("Error fetching conversations:", error);
    res.status(500).json({ error: "Failed to fetch conversations" });
  }
});

app.post("/api/chat/conversations", authenticateToken, async (req, res) => {
  try {
    const { title } = req.body;
    const conversation = await prisma.conversation.create({
      data: { title: title || "New Chat", userId: req.user.uid },
    });
    res.json({ conversation });
  } catch (error) {
    console.error("Error creating conversation:", error);
    res.status(500).json({ error: "Failed to create conversation" });
  }
});

// Public shared chat
app.get("/api/public/conversations/:conversationId", async (req, res) => {
  try {
    const { conversationId } = req.params;
    const conversation = await prisma.conversation.findUnique({
      where: { id: conversationId },
      select: {
        id: true,
        title: true,
        createdAt: true,
        updatedAt: true,
        messages: {
          orderBy: { createdAt: "asc" },
          select: {
            id: true,
            content: true,
            role: true,
            createdAt: true,
            metadata: true,
          },
        },
      },
    });

    if (!conversation) return res.status(404).json({ error: "Conversation not found" });
    res.json({ conversation });
  } catch (error) {
    console.error("Error fetching public conversation:", error);
    res.status(500).json({ error: "Failed to fetch conversation" });
  }
});

// Private chat
app.get("/api/chat/conversations/:conversationId", authenticateToken, async (req, res) => {
  try {
    const { conversationId } = req.params;
    const { page = 1, limit = 50 } = req.query;

    const conversation = await prisma.conversation.findFirst({
      where: { id: conversationId, userId: req.user.uid },
      include: {
        messages: {
          orderBy: { createdAt: "asc" },
          skip: (page - 1) * limit,
          take: parseInt(limit),
        },
      },
    });

    if (!conversation) return res.status(404).json({ error: "Conversation not found" });
    res.json({ conversation });
  } catch (error) {
    console.error("Error fetching conversation:", error);
    res.status(500).json({ error: "Failed to fetch conversation" });
  }
});

app.post("/api/chat/conversations/:conversationId/messages", authenticateToken, chatLimiter, async (req, res) => {
  try {
    const { conversationId } = req.params;
    const { content, role = "user", metadata } = req.body;

    if (!content?.trim()) return res.status(400).json({ error: "Message content is required" });

    const conversation = await prisma.conversation.findFirst({
      where: { id: conversationId, userId: req.user.uid },
    });
    if (!conversation) return res.status(404).json({ error: "Conversation not found" });

    const message = await prisma.message.create({
      data: {
        content: content.trim(),
        role,
        conversationId,
        userId: req.user.uid,
        metadata: metadata ? JSON.stringify(metadata) : null,
      },
    });

    await prisma.conversation.update({
      where: { id: conversationId },
      data: { updatedAt: new Date() },
    });

    res.json({ message });
  } catch (error) {
    console.error("Error sending message:", error);
    res.status(500).json({ error: "Failed to send message" });
  }
});

// Update, delete, search routes
app.put("/api/chat/conversations/:conversationId", authenticateToken, async (req, res) => {
  try {
    const { conversationId } = req.params;
    const { title } = req.body;

    if (!title?.trim()) return res.status(400).json({ error: "Title is required" });

    const updated = await prisma.conversation.updateMany({
      where: { id: conversationId, userId: req.user.uid },
      data: { title: title.trim() },
    });

    if (updated.count === 0) return res.status(404).json({ error: "Conversation not found" });
    res.json({ message: "Conversation title updated successfully" });
  } catch (error) {
    console.error("Error updating conversation:", error);
    res.status(500).json({ error: "Failed to update conversation" });
  }
});

app.delete("/api/chat/conversations/:conversationId", authenticateToken, async (req, res) => {
  try {
    const { conversationId } = req.params;
    await prisma.message.deleteMany({ where: { conversationId, userId: req.user.uid } });
    const deleted = await prisma.conversation.deleteMany({
      where: { id: conversationId, userId: req.user.uid },
    });

    if (deleted.count === 0) return res.status(404).json({ error: "Conversation not found" });
    res.json({ message: "Conversation deleted successfully" });
  } catch (error) {
    console.error("Error deleting conversation:", error);
    res.status(500).json({ error: "Failed to delete conversation" });
  }
});

app.delete("/api/chat/conversations", authenticateToken, async (req, res) => {
  try {
    await prisma.message.deleteMany({ where: { userId: req.user.uid } });
    await prisma.conversation.deleteMany({ where: { userId: req.user.uid } });
    res.json({ message: "All conversations deleted successfully" });
  } catch (error) {
    console.error("Error deleting all conversations:", error);
    res.status(500).json({ error: "Failed to delete conversations" });
  }
});

app.get("/api/chat/stats", authenticateToken, async (req, res) => {
  try {
    const [conversationCount, messageCount] = await Promise.all([
      prisma.conversation.count({ where: { userId: req.user.uid } }),
      prisma.message.count({ where: { userId: req.user.uid } }),
    ]);
    res.json({ totalConversations: conversationCount, totalMessages: messageCount });
  } catch (error) {
    console.error("Error fetching stats:", error);
    res.status(500).json({ error: "Failed to fetch statistics" });
  }
});

app.get("/api/chat/search", authenticateToken, async (req, res) => {
  try {
    const { q, limit = 20 } = req.query;
    if (!q?.trim() || q.trim().length < 2)
      return res.status(400).json({ error: "Search query must be at least 2 characters" });

    const messages = await prisma.message.findMany({
      where: {
        userId: req.user.uid,
        content: { contains: q.trim(), mode: "insensitive" },
      },
      include: { conversation: { select: { id: true, title: true } } },
      orderBy: { createdAt: "desc" },
      take: parseInt(limit),
    });

    res.json({ messages });
  } catch (error) {
    console.error("Error searching messages:", error);
    res.status(500).json({ error: "Failed to search messages" });
  }
});

// ===================== ADMIN ROUTES =====================
app.post("/api/auth/custom-token", async (req, res) => {
  try {
    const { uid, additionalClaims } = req.body;
    if (!uid) return res.status(400).json({ error: "UID is required" });

    const customToken = await admin.auth().createCustomToken(uid, additionalClaims);
    res.json({ customToken });
  } catch (error) {
    console.error("Error creating custom token:", error);
    res.status(500).json({ error: "Failed to create custom token" });
  }
});

// ===================== ERROR HANDLING =====================
app.use((req, res) => {
  res.status(404).json({ error: "Route not found" });
});

app.use((error, req, res, next) => {
  console.error("Unhandled error:", error);
  res.status(500).json({ error: "Internal server error" });
});

// ===================== SERVER =====================
const PORT = process.env.PORT || 8000;
app.listen(PORT, () => {
  console.log(`🚀 Chat Server running on port ${PORT}`);
  console.log(`📱 Backend ready with Firebase Auth + Chat functionality`);
  console.log(`🗄️ Database connected via Prisma + PostgreSQL`);
});

// Graceful shutdown
process.on("SIGINT", async () => {
  console.log("Shutting down gracefully...");
  await prisma.$disconnect();
  process.exit(0);
});
process.on("SIGTERM", async () => {
  console.log("Shutting down gracefully...");
  await prisma.$disconnect();
  process.exit(0);
});
