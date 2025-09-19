// chat/server.js
const express = require('express');
const admin = require('firebase-admin');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const { PrismaClient } = require('@prisma/client');
require('dotenv').config();

const app = express();
const prisma = new PrismaClient();

// Initialize Firebase Admin SDK
const serviceAccount = {
  type: "service_account",
  project_id: process.env.FIREBASE_PROJECT_ID,
  private_key_id: process.env.FIREBASE_PRIVATE_KEY_ID,
  private_key: process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, '\n'),
  client_email: process.env.FIREBASE_CLIENT_EMAIL,
  client_id: process.env.FIREBASE_CLIENT_ID,
  auth_uri: "https://accounts.google.com/o/oauth2/auth",
  token_uri: "https://oauth2.googleapis.com/token",
  auth_provider_x509_cert_url: "https://www.googleapis.com/oauth2/v1/certs",
  client_x509_cert_url: `https://www.googleapis.com/robot/v1/metadata/x509/${process.env.FIREBASE_CLIENT_EMAIL}`
};

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  projectId: process.env.FIREBASE_PROJECT_ID
});

// Middleware
app.use(cors({
  origin: 'http://localhost:9002',
  credentials: true
}));
app.use(express.json({ limit: '10mb' }));

// Rate limiting
const limiter = rateLimit({
  // windowMs: 15 * 60 * 1000, // 15 minutes
  windowMs: 1 * 30 * 1000, // 1 minute
  max: 100 // limit each IP to 100 requests per windowMs
});
app.use('/api/', limiter);

// Chat specific rate limiting
const chatLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: 30 // 30 messages per minute
});

// Auth middleware
const authenticateToken = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
      return res.status(401).json({ error: 'Access token required' });
    }

    const decodedToken = await admin.auth().verifyIdToken(token);
    req.user = decodedToken;
    next();
  } catch (error) {
    console.error('Token verification error:', error);
    return res.status(403).json({ error: 'Invalid token' });
  }
};

// ===================== AUTH ROUTES =====================

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'OK', message: 'Chat Backend with Auth is running' });
});

// Get user profile
app.get('/api/user/profile', authenticateToken, async (req, res) => {
  try {
    const userRecord = await admin.auth().getUser(req.user.uid);
    
    const userProfile = {
      uid: userRecord.uid,
      email: userRecord.email,
      displayName: userRecord.displayName,
      photoURL: userRecord.photoURL,
      emailVerified: userRecord.emailVerified,
      disabled: userRecord.disabled,
      metadata: {
        creationTime: userRecord.metadata.creationTime,
        lastSignInTime: userRecord.metadata.lastSignInTime
      },
      providerData: userRecord.providerData
    };

    res.json({ user: userProfile });
  } catch (error) {
    console.error('Error getting user profile:', error);
    res.status(500).json({ error: 'Failed to get user profile' });
  }
});

// Update user profile
app.put('/api/user/profile', authenticateToken, async (req, res) => {
  try {
    const { displayName, photoURL } = req.body;
    
    const updateData = {};
    if (displayName) updateData.displayName = displayName;
    if (photoURL) updateData.photoURL = photoURL;

    await admin.auth().updateUser(req.user.uid, updateData);
    
    res.json({ message: 'Profile updated successfully' });
  } catch (error) {
    console.error('Error updating profile:', error);
    res.status(500).json({ error: 'Failed to update profile' });
  }
});

// Delete user account
app.delete('/api/user/account', authenticateToken, async (req, res) => {
  try {
    // First delete all chat data
    await prisma.message.deleteMany({
      where: { userId: req.user.uid }
    });
    
    await prisma.conversation.deleteMany({
      where: { userId: req.user.uid }
    });
    
    // Then delete Firebase user
    await admin.auth().deleteUser(req.user.uid);
    
    res.json({ message: 'Account and all chat data deleted successfully' });
  } catch (error) {
    console.error('Error deleting account:', error);
    res.status(500).json({ error: 'Failed to delete account' });
  }
});

// ===================== CHAT ROUTES =====================
app.use((req, res, next) => {
  console.log(`Received request for: ${req.method} ${req.originalUrl}`);
  next();
});
// Get all conversations for a user
app.get('/api/chat/conversations', authenticateToken, async (req, res) => {
  try {
    const conversations = await prisma.conversation.findMany({
      where: {
        userId: req.user.uid
      },
      include: {
        messages: {
          take: 1,
          orderBy: {
            createdAt: 'desc'
          }
        }
      },
      orderBy: {
        updatedAt: 'desc'
      }
    });

    res.json({ conversations });
  } catch (error) {
    console.error('Error fetching conversations:', error);
    res.status(500).json({ error: 'Failed to fetch conversations' });
  }
});

// Create new conversation
app.post('/api/chat/conversations', authenticateToken, async (req, res) => {
  try {
    const { title } = req.body;
    
    const conversation = await prisma.conversation.create({
      data: {
        title: title || 'New Chat',
        userId: req.user.uid
      }
    });

    res.json({ conversation });
  } catch (error) {
    console.error('Error creating conversation:', error);
    res.status(500).json({ error: 'Failed to create conversation' });
  }
});

// Get a specific conversation for public viewing (UPDATED)
app.get('/api/public/conversations/:conversationId', async (req, res) => {
  try {
    const { conversationId } = req.params;

    console.log(`Fetching public conversation: ${conversationId}`);

    const conversation = await prisma.conversation.findUnique({
      where: {
        id: conversationId,
      },
      select: {
        id: true,
        title: true,
        createdAt: true,
        updatedAt: true,
        messages: {
          orderBy: {
            createdAt: 'asc'
          },
          select: {
            id: true,
            content: true,
            role: true,
            createdAt: true,
            metadata: true,
          }
        }
      }
    });

    if (!conversation) {
      console.log(`Conversation ${conversationId} not found`);
      return res.status(404).json({ error: 'Conversation not found' });
    }

    console.log(`Found conversation with ${conversation.messages.length} messages`);

    res.json({ conversation });
  } catch (error) {
    console.error('Error fetching public conversation:', error);
    res.status(500).json({ error: 'Failed to fetch conversation' });
  }
});

// Get specific conversation with messages
app.get('/api/chat/conversations/:conversationId', authenticateToken, async (req, res) => {
  try {
    const { conversationId } = req.params;
    const { page = 1, limit = 50 } = req.query;

    const conversation = await prisma.conversation.findFirst({
      where: {
        id: conversationId,
        userId: req.user.uid
      },
      include: {
        messages: {
          orderBy: {
            createdAt: 'asc'
          },
          skip: (page - 1) * limit,
          take: parseInt(limit)
        }
      }
    });

    if (!conversation) {
      return res.status(404).json({ error: 'Conversation not found' });
    }

    res.json({ conversation });
  } catch (error) {
    console.error('Error fetching conversation:', error);
    res.status(500).json({ error: 'Failed to fetch conversation' });
  }
});

// Send message
app.post('/api/chat/conversations/:conversationId/messages', authenticateToken, chatLimiter, async (req, res) => {
  try {
    const { conversationId } = req.params;
    const { content, role = 'user', metadata } = req.body;

    if (!content || content.trim().length === 0) {
      return res.status(400).json({ error: 'Message content is required' });
    }

    // Verify conversation belongs to user
    const conversation = await prisma.conversation.findFirst({
      where: {
        id: conversationId,
        userId: req.user.uid
      }
    });

    if (!conversation) {
      return res.status(404).json({ error: 'Conversation not found' });
    }

    // Create message
    const message = await prisma.message.create({
      data: {
        content: content.trim(),
        role,
        conversationId,
        userId: req.user.uid,
        metadata: metadata ? JSON.stringify(metadata) : null
      }
    });

    // Update conversation's updatedAt
    await prisma.conversation.update({
      where: { id: conversationId },
      data: { updatedAt: new Date() }
    });

    res.json({ message });
  } catch (error) {
    console.error('Error sending message:', error);
    res.status(500).json({ error: 'Failed to send message' });
  }
});

// Update conversation title
app.put('/api/chat/conversations/:conversationId', authenticateToken, async (req, res) => {
  try {
    const { conversationId } = req.params;
    const { title } = req.body;

    if (!title || title.trim().length === 0) {
      return res.status(400).json({ error: 'Title is required' });
    }

    const conversation = await prisma.conversation.updateMany({
      where: {
        id: conversationId,
        userId: req.user.uid
      },
      data: {
        title: title.trim()
      }
    });

    if (conversation.count === 0) {
      return res.status(404).json({ error: 'Conversation not found' });
    }

    res.json({ message: 'Conversation title updated successfully' });
  } catch (error) {
    console.error('Error updating conversation:', error);
    res.status(500).json({ error: 'Failed to update conversation' });
  }
});

// Delete conversation
app.delete('/api/chat/conversations/:conversationId', authenticateToken, async (req, res) => {
  try {
    const { conversationId } = req.params;

    // Delete all messages first
    await prisma.message.deleteMany({
      where: {
        conversationId,
        userId: req.user.uid
      }
    });

    // Delete conversation
    const deletedConversation = await prisma.conversation.deleteMany({
      where: {
        id: conversationId,
        userId: req.user.uid
      }
    });

    if (deletedConversation.count === 0) {
      return res.status(404).json({ error: 'Conversation not found' });
    }

    res.json({ message: 'Conversation deleted successfully' });
  } catch (error) {
    console.error('Error deleting conversation:', error);
    res.status(500).json({ error: 'Failed to delete conversation' });
  }
});

// Delete all conversations for user
app.delete('/api/chat/conversations', authenticateToken, async (req, res) => {
  try {
    // Delete all messages
    await prisma.message.deleteMany({
      where: { userId: req.user.uid }
    });

    // Delete all conversations
    await prisma.conversation.deleteMany({
      where: { userId: req.user.uid }
    });

    res.json({ message: 'All conversations deleted successfully' });
  } catch (error) {
    console.error('Error deleting all conversations:', error);
    res.status(500).json({ error: 'Failed to delete conversations' });
  }
});

// Get chat statistics
// app.get('/api/chat/stats', authenticateToken, async (req, res) => {
//   try {
//     const [conversationCount, messageCount] = await Promise.all([
//       prisma.conversation.count({
//         where: { userId: req.user.uid }
//       }),
//       prisma.message.count({
//         where: { userId: req.user.uid }
//       })
//     ]);
// d
//     res.json({
//       totalConversations: conversationCount,
//       totalMessages: messageCount
//     });
//   } catch (error) {
//     console.error('Error fetching stats:', error);
//     res.status(500).json({ error: 'Failed to fetch statistics' });
//   }
// });

// Get chat statistics
app.get('/api/chat/stats', authenticateToken, async (req, res) => {
  try {
    const [conversationCount, messageCount] = await Promise.all([
      prisma.conversation.count({
        where: { userId: req.user.uid }
      }),
      prisma.message.count({
        where: { userId: req.user.uid }
      })
    ]);

    res.json({
      totalConversations: conversationCount,
      totalMessages: messageCount
    });
  } catch (error) {
    console.error('Error fetching stats:', error);
    res.status(500).json({ error: 'Failed to fetch statistics' });
  }
});


// Search messages
app.get('/api/chat/search', authenticateToken, async (req, res) => {
  try {
    const { q, limit = 20 } = req.query;

    if (!q || q.trim().length < 2) {
      return res.status(400).json({ error: 'Search query must be at least 2 characters' });
    }

    const messages = await prisma.message.findMany({
      where: {
        userId: req.user.uid,
        content: {
          contains: q.trim(),
          mode: 'insensitive'
        }
      },
      include: {
        conversation: {
          select: {
            id: true,
            title: true
          }
        }
      },
      orderBy: {
        createdAt: 'desc'
      },
      take: parseInt(limit)
    });

    res.json({ messages });
  } catch (error) {
    console.error('Error searching messages:', error);
    res.status(500).json({ error: 'Failed to search messages' });
  }
});

// ===================== ADMIN ROUTES =====================

// Generate custom token
app.post('/api/auth/custom-token', async (req, res) => {
  try {
    const { uid, additionalClaims } = req.body;
    
    if (!uid) {
      return res.status(400).json({ error: 'UID is required' });
    }

    const customToken = await admin.auth().createCustomToken(uid, additionalClaims);
    res.json({ customToken });
  } catch (error) {
    console.error('Error creating custom token:', error);
    res.status(500).json({ error: 'Failed to create custom token' });
  }
});

// Error handling middleware
app.use((error, req, res, next) => {
  console.error('Unhandled error:', error);
  res.status(500).json({ error: 'Internal server error' });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

// Graceful shutdown
process.on('SIGINT', async () => {
  console.log('Shutting down gracefully...');
  await prisma.$disconnect();
  process.exit(0);
});

process.on('SIGTERM', async () => {
  console.log('Shutting down gracefully...');
  await prisma.$disconnect();
  process.exit(0);
});

const PORT = process.env.PORT || 8000;

app.listen(PORT, () => {
  console.log(`🚀 Chat Server running on port ${PORT}`);
  console.log(`📱 Backend ready with Firebase Auth + Chat functionality`);
  console.log(`🗄️  Database connected via Prisma + PostgreSQL`);
});