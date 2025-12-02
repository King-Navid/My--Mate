const express = require("express");
const fs = require("fs/promises");
const path = require("path");
const bcrypt = require("bcrypt");
const session = require("express-session");
const rateLimit = require("express-rate-limit");

const app = express();

// Security: Limit request body size to prevent DoS
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Trust proxy (important for Render.com and other hosting services)
app.set('trust proxy', 1);

// Rate limiting to prevent brute force attacks
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Limit each IP to 5 requests per windowMs
  message: { error: "تعداد تلاش‌های ورود بیش از حد مجاز است. لطفاً 15 دقیقه صبر کنید." },
  standardHeaders: true,
  legacyHeaders: false,
});

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: { error: "تعداد درخواست‌ها بیش از حد مجاز است. لطفاً کمی صبر کنید." },
  standardHeaders: true,
  legacyHeaders: false,
});

// Apply general API rate limiting
app.use("/api/", apiLimiter);

// Session configuration
app.use(
  session({
    secret: process.env.SESSION_SECRET || "your-secret-key-change-in-production",
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: process.env.NODE_ENV === "production", // true on Render.com (HTTPS)
      httpOnly: true,
      maxAge: 24 * 60 * 60 * 1000, // 24 hours
      sameSite: "lax", // Better security and compatibility
    },
  })
);

const usersFile = path.resolve("./users.json");
const messagesFile = path.resolve("./messages.json");
const commentsFile = path.resolve("./comment.json");
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || "navidadmin";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "asdfghjkl;'";

async function readJSON(file) {
  try {
    const data = await fs.readFile(file, "utf-8");
    const parsed = JSON.parse(data);
    // Ensure we return an array
    return Array.isArray(parsed) ? parsed : [];
  } catch (error) {
    // If file doesn't exist, create it with empty array
    if (error.code === 'ENOENT') {
      try {
        await writeJSON(file, []);
        return [];
      } catch (writeError) {
        console.error(`Error creating ${file}:`, writeError);
        return [];
      }
    }
    console.error(`Error reading ${file}:`, error);
    return [];
  }
}

async function writeJSON(file, data) {
  try {
    // Ensure directory exists (in case of nested paths)
    const dir = path.dirname(file);
    try {
      await fs.mkdir(dir, { recursive: true });
    } catch (mkdirError) {
      // Directory might already exist, ignore error
    }
    
    // Write file with proper error handling
    await fs.writeFile(file, JSON.stringify(data, null, 2), "utf-8");
    // Removed console.log for production (keep only errors)
  } catch (error) {
    console.error(`Error writing to ${file}:`, error);
    throw error;
  }
}

async function ensureAdminUser() {
  try {
    const users = await readJSON(usersFile);
    let adminUser = users.find(u => u.username === ADMIN_USERNAME);
    let requiresWrite = false;

    if (!adminUser) {
      const hashed = await bcrypt.hash(ADMIN_PASSWORD, 10);
      adminUser = {
        id: Date.now(),
        username: ADMIN_USERNAME,
        password: hashed,
        isAdmin: true,
      };
      users.push(adminUser);
      requiresWrite = true;
    } else {
      if (!adminUser.isAdmin) {
        adminUser.isAdmin = true;
        requiresWrite = true;
      }
      const matches = await bcrypt.compare(ADMIN_PASSWORD, adminUser.password).catch(() => false);
      if (!matches) {
        adminUser.password = await bcrypt.hash(ADMIN_PASSWORD, 10);
        requiresWrite = true;
      }
    }

    if (requiresWrite) {
      await writeJSON(usersFile, users);
    }
  } catch (error) {
    console.error("Error ensuring admin user:", error);
  }
}

ensureAdminUser();

// Authentication middleware
function requireAuth(req, res, next) {
  if (req.session && req.session.userId) {
    return next();
  }
  return res.status(401).json({ error: "لطفاً ابتدا وارد شوید." });
}

function requireAdmin(req, res, next) {
  if (req.session && req.session.isAdmin) {
    return next();
  }
  return res.status(403).json({ error: "دسترسی غیرمجاز." });
}

// ثبت‌نام
app.post("/api/register", async (req, res) => {
  const { username, password } = req.body;

  if (typeof username !== "string" || username.trim() === "") {
    return res.status(400).json({ error: "نام کاربری معتبر نیست." });
  }
  
  // Security: Limit username length
  if (username.trim().length > 50) {
    return res.status(400).json({ error: "نام کاربری نمی‌تواند بیشتر از 50 کاراکتر باشد." });
  }
  
  if (typeof password !== "string" || password.length < 8) {
    return res.status(400).json({ error: "رمز عبور باید حداقل 8 کاراکتر باشد." });
  }
  
  // Security: Limit password length
  if (password.length > 200) {
    return res.status(400).json({ error: "رمز عبور نمی‌تواند بیشتر از 200 کاراکتر باشد." });
  }

  const users = await readJSON(usersFile);
  if (users.find(u => u.username === username)) {
    return res.status(409).json({ error: "این نام کاربری قبلاً ثبت شده است." });
  }

  try {
    const hashed = await bcrypt.hash(password, 10);
    const userId = Date.now();
    users.push({ id: userId, username, password: hashed, isAdmin: false });
    await writeJSON(usersFile, users);

    res.json({ message: "ثبت‌نام با موفقیت انجام شد." });
  } catch (error) {
    console.error("Registration error:", error);
    return res.status(500).json({ error: "خطا در ثبت‌نام. لطفاً دوباره تلاش کنید." });
  }
});

// ورود (with rate limiting to prevent brute force)
app.post("/api/login", loginLimiter, async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: "نام کاربری و رمز عبور باید وارد شود." });
  }

  const users = await readJSON(usersFile);
  const user = users.find(u => u.username === username);

  if (!user) {
    return res.status(401).json({ error: "نام کاربری یا رمز عبور اشتباه است." });
  }

  const match = await bcrypt.compare(password, user.password);
  if (!match) {
    return res.status(401).json({ error: "نام کاربری یا رمز عبور اشتباه است." });
  }

  // Create session
  req.session.userId = user.id;
  req.session.username = user.username;
  req.session.isAdmin = !!user.isAdmin;

  res.json({
    message: "ورود با موفقیت انجام شد.",
    user: { id: user.id, username: user.username, isAdmin: !!user.isAdmin },
  });
});

// Admin-only login endpoint (secret page)
app.post("/api/admin/login", loginLimiter, async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: "نام کاربری و رمز عبور باید وارد شود." });
  }

  const users = await readJSON(usersFile);
  const user = users.find(u => u.username === ADMIN_USERNAME);

  if (!user || user.username !== username) {
    return res.status(401).json({ error: "نام کاربری یا رمز عبور اشتباه است." });
  }

  const match = await bcrypt.compare(password, user.password);
  if (!match) {
    return res.status(401).json({ error: "نام کاربری یا رمز عبور اشتباه است." });
  }

  req.session.userId = user.id;
  req.session.username = user.username;
  req.session.isAdmin = true;

  res.json({
    message: "ورود مدیر با موفقیت انجام شد.",
    user: { id: user.id, username: user.username, isAdmin: true },
  });
});

// Logout endpoint
app.post("/api/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({ error: "خطا در خروج از سیستم." });
    }
    res.clearCookie("connect.sid");
    res.json({ message: "خروج با موفقیت انجام شد." });
  });
});

// Get current user
app.get("/api/user", (req, res) => {
  if (req.session && req.session.userId) {
    return res.json({
      authenticated: true,
      user: {
        id: req.session.userId,
        username: req.session.username,
        isAdmin: !!req.session.isAdmin,
      },
    });
  }
  return res.json({ authenticated: false });
});

// دریافت پیام‌ها
app.get("/api/messages", requireAuth, async (req, res) => {
  const messages = await readJSON(messagesFile);
  
  // If user is logged in, return only their messages
  // If not logged in (admin viewing all), return all messages
  if (req.session && req.session.userId) {
    if (req.session.isAdmin) {
      return res.json(messages);
    }
    const userMessages = messages.filter(m => m.userId === req.session.userId);
    return res.json(userMessages);
  }
  
  // For admin or unauthenticated requests, return all messages
  res.json(messages);
});

// ارسال پیام کاربر
app.post("/api/messages", requireAuth, async (req, res) => {
  try {
    const { userMessage } = req.body;
    if (typeof userMessage !== "string" || userMessage.trim() === "") {
      return res.status(400).json({ error: "متن پیام نامعتبر است." });
    }
    
    // Security: Limit message length
    if (userMessage.trim().length > 5000) {
      return res.status(400).json({ error: "پیام نمی‌تواند بیشتر از 5000 کاراکتر باشد." });
    }
    
    // User must be logged in (requireAuth ensures this)
    const userId = req.session.userId;
    const username = req.session.username;
    
    if (!userId || !username) {
      return res.status(401).json({ error: "لطفاً ابتدا وارد شوید." });
    }
    
    const messages = await readJSON(messagesFile);
    messages.push({
      id: Date.now(),
      userId: userId,
      username: username,
      userMessage: userMessage.trim(),
      adminReply: null,
    });
    await writeJSON(messagesFile, messages);
    res.status(201).json({ message: "پیام با موفقیت ارسال شد." });
  } catch (error) {
    console.error("Error sending message:", error);
    res.status(500).json({ error: "خطا در ارسال پیام." });
  }
});

// پاسخ ادمین (نیاز به احراز هویت مدیر دارد)
app.post("/api/messages/reply", requireAdmin, async (req, res) => {
  try {
    const { id, reply } = req.body;
    if (typeof id !== "number" && typeof id !== "string") {
      return res.status(400).json({ error: "شناسه پیام نامعتبر است." });
    }
    if (typeof reply !== "string" || reply.trim() === "") {
      return res.status(400).json({ error: "پاسخ نمی‌تواند خالی باشد." });
    }
    
    // Security: Limit reply length
    if (reply.trim().length > 5000) {
      return res.status(400).json({ error: "پاسخ نمی‌تواند بیشتر از 5000 کاراکتر باشد." });
    }
    
    const messages = await readJSON(messagesFile);
    const msg = messages.find(m => m.id == id);
    if (!msg) {
      return res.status(404).json({ error: "پیام مورد نظر پیدا نشد." });
    }
    
    msg.adminReply = reply.trim();
    await writeJSON(messagesFile, messages);
    res.json({ message: "پاسخ با موفقیت ثبت شد." });
  } catch (error) {
    console.error("Error replying to message:", error);
    res.status(500).json({ error: "خطا در ثبت پاسخ." });
  }
});

// دریافت نظرات برای عموم - فقط نظرات تأیید شده
app.get("/api/comments", async (req, res) => {
  try {
    const comments = await readJSON(commentsFile);

    if (!Array.isArray(comments)) {
      console.error("Comments file is not an array, returning empty array");
      return res.json([]);
    }

    // Only approved comments and replies are visible publicly
    const approved = comments.filter(c => c.approved);

    if (approved.length > 0) {
      // Sort by creation time (newest first)
      const sortedComments = [...approved].sort((a, b) => {
        const aTime = a.createdAt ? new Date(a.createdAt).getTime() : 0;
        const bTime = b.createdAt ? new Date(b.createdAt).getTime() : 0;
        return bTime - aTime;
      });
      return res.json(sortedComments);
    }

    res.json([]);
  } catch (error) {
    console.error("Error loading comments:", error);
    res.json([]);
  }
});

// مدیریت نظرات برای ادمین (همه نظرات، شامل تأیید نشده)
app.get("/api/admin/comments", requireAdmin, async (req, res) => {
  try {
    const comments = await readJSON(commentsFile);

    if (!Array.isArray(comments)) {
      console.error("Comments file is not an array, returning empty array");
      return res.json([]);
    }

    const sortedComments = [...comments].sort((a, b) => {
      const aTime = a.createdAt ? new Date(a.createdAt).getTime() : 0;
      const bTime = b.createdAt ? new Date(b.createdAt).getTime() : 0;
      return bTime - aTime;
    });

    res.json(sortedComments);
  } catch (error) {
    console.error("Error loading admin comments:", error);
    res.status(500).json({ error: "خطا در بارگذاری نظرات." });
  }
});

// تأیید نظر توسط ادمین
app.post("/api/admin/comments/:id/approve", requireAdmin, async (req, res) => {
  try {
    const commentId = parseInt(req.params.id, 10);
    if (isNaN(commentId)) {
      return res.status(400).json({ error: "شناسه نظر نامعتبر است." });
    }

    const comments = await readJSON(commentsFile);
    if (!Array.isArray(comments)) {
      return res.status(500).json({ error: "خطا در ساختار فایل نظرات." });
    }

    const comment = comments.find(c => c.id === commentId);
    if (!comment) {
      return res.status(404).json({ error: "نظر مورد نظر پیدا نشد." });
    }

    if (comment.approved) {
      return res.json({ message: "این نظر قبلاً تأیید شده است." });
    }

    comment.approved = true;
    await writeJSON(commentsFile, comments);
    res.json({ message: "نظر با موفقیت تأیید شد." });
  } catch (error) {
    console.error("Error approving comment:", error);
    res.status(500).json({ error: "خطا در تأیید نظر." });
  }
});

// حذف نظر (نیاز به احراز هویت مدیر دارد)
app.delete("/api/comments/:id", requireAdmin, async (req, res) => {
  try {
    const commentId = parseInt(req.params.id);
    
    if (isNaN(commentId)) {
      return res.status(400).json({ error: "شناسه نظر نامعتبر است." });
    }
    
    const comments = await readJSON(commentsFile);
    
    // Find and remove the comment and its replies
    const initialLength = comments.length;
    const filteredComments = comments.filter(
      c => c.id !== commentId && c.parentId !== commentId
    );
    
    if (filteredComments.length === initialLength) {
      return res.status(404).json({ error: "نظر مورد نظر پیدا نشد." });
    }
    
    await writeJSON(commentsFile, filteredComments);
    // Removed console.log for production
    res.json({ message: "نظر با موفقیت حذف شد." });
  } catch (error) {
    console.error("Error deleting comment:", error);
    res.status(500).json({ error: `خطا در حذف نظر: ${error.message}` });
  }
});

// ارسال نظر
app.post("/api/comments", requireAuth, async (req, res) => {
  try {
    const { comment, parentId } = req.body;
    
    if (typeof comment !== "string" || comment.trim() === "") {
      return res.status(400).json({ error: "متن نظر نمی‌تواند خالی باشد." });
    }
    
    // Security: Limit comment length
    if (comment.trim().length > 2000) {
      return res.status(400).json({ error: "نظر نمی‌تواند بیشتر از 2000 کاراکتر باشد." });
    }
    
    // User must be logged in (requireAuth ensures this)
    const userId = req.session.userId;
    const username = req.session.username;
    
    if (!userId || !username) {
      return res.status(401).json({ error: "لطفاً ابتدا وارد شوید." });
    }

    // Optional parentId for replies
    let parentIdValue = null;
    if (typeof parentId === "number") {
      parentIdValue = parentId;
    } else if (typeof parentId === "string" && parentId.trim() !== "") {
      const parsed = parseInt(parentId, 10);
      if (!isNaN(parsed)) {
        parentIdValue = parsed;
      }
    }

    let comments = await readJSON(commentsFile);
    
    // Ensure comments is an array
    if (!Array.isArray(comments)) {
      console.error("Comments file is not an array, initializing...");
      await writeJSON(commentsFile, []);
      comments = [];
    }
    
    const newComment = {
      id: Date.now(),
      userId: userId,
      username: username,
      comment: comment.trim(),
      createdAt: new Date().toISOString(),
      parentId: parentIdValue,
      approved: false,
      authorRole: req.session.isAdmin ? "admin" : "user",
    };
    
    comments.push(newComment);
    
    // Save comments to file - ensure it's saved properly
    try {
      await writeJSON(commentsFile, comments);
      // Removed console.log for production
    } catch (writeError) {
      console.error("Error writing comment to file:", writeError);
      // Still return success to user, but log the error
      // In production, you might want to use a database instead
    }
    
    res.status(201).json({ message: "نظر با موفقیت ثبت شد.", comment: newComment });
  } catch (error) {
    console.error("Error saving comment:", error);
    res.status(500).json({ error: `خطا در ثبت نظر: ${error.message}` });
  }
});

// سرو فایل‌های ایستا مثل HTML/CSS/JS
app.use(express.static("public"));

// اجرای سرور
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
