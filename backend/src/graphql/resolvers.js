import bcrypt from 'bcryptjs';
import { GraphQLError } from 'graphql';
import User from '../models/User.js';
import Post from '../models/Post.js';
import Reply from '../models/Reply.js';
import { signToken } from '../utils/auth.js';
import { sanitizeText } from '../utils/sanitize.js';
import { getStats, getEvents, getBlockedIps } from '../security/stats.js';
import { unblockIp, normalizeIp } from '../security/blocklist.js';

const fail = (message, code) => new GraphQLError(message, { extensions: { code } });

const requireAuth = (ctx) => {
  if (!ctx.user) throw fail('You must be logged in', 'UNAUTHENTICATED');
  return ctx.user;
};

const requireAdmin = (ctx) => {
  const user = requireAuth(ctx);
  if (user.role !== 'admin') throw fail('Admins only', 'FORBIDDEN');
  return user;
};

// Sanitize first (strip HTML, control and hidden characters), then validate the length
const cleanText = (text, max = 280) => {
  const t = sanitizeText(text);
  if (!t || t.length > max) throw fail(`Text must be 1-${max} characters`, 'BAD_USER_INPUT');
  return t;
};

const iso = (doc) => (doc.createdAt ? doc.createdAt.toISOString() : null);

// NOTE: resolvers that read from MongoDB end with .exec() so GraphQL gets a real
// Promise. Returning a bare Mongoose query causes "Query was already executed".
export default {
  Query: {
    me: (_, __, ctx) => ctx.user,
    feed: (_, { limit }) =>
      Post.find().sort({ createdAt: -1 }).limit(Math.min(Math.max(limit, 1), 50)).exec(),
    post: (_, { id }) => Post.findById(id).exec(),
    user: (_, { id }) => User.findById(id).select('-password').exec(),

    // Admin-only security console data
    securityStats: (_, __, ctx) => {
      requireAdmin(ctx);
      return getStats();
    },
    securityEvents: (_, args, ctx) => {
      requireAdmin(ctx);
      return getEvents(args);
    },
    blockedIps: (_, __, ctx) => {
      requireAdmin(ctx);
      return getBlockedIps();
    },
  },

  Mutation: {
    signup: async (_, { username, email, password }) => {
      if (!/^[A-Za-z0-9_]{3,20}$/.test(username))
        throw fail('Username: 3-20 letters, numbers or underscores', 'BAD_USER_INPUT');
      if (email.length > 100 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
        throw fail('Enter a valid email address', 'BAD_USER_INPUT');
      if (password.length < 8 || password.length > 72)
        throw fail('Password must be 8-72 characters', 'BAD_USER_INPUT');
      const exists = await User.findOne({
        $or: [{ email: String(email).toLowerCase() }, { username: String(username) }],
      });
      if (exists) throw fail('Username or email already taken', 'BAD_USER_INPUT');

      const hash = await bcrypt.hash(password, 12);
      const user = await User.create({ username, email, password: hash });
      return { token: signToken(user), user };
    },

    login: async (_, { email, password }) => {
      const user = await User.findOne({ email: String(email).toLowerCase() });
      // Same message for "no such user" and "wrong password" - don't leak which one
      const ok = user && (await bcrypt.compare(password, user.password));
      if (!ok) throw fail('Invalid credentials', 'UNAUTHENTICATED');
      return { token: signToken(user), user };
    },

    createPost: async (_, { content }, ctx) => {
      const user = requireAuth(ctx);
      return Post.create({ author: user._id, content: cleanText(content) });
    },

    deletePost: async (_, { id }, ctx) => {
      const user = requireAuth(ctx);
      const post = await Post.findById(id);
      if (!post) throw fail('Post not found', 'NOT_FOUND');
      // Authorization: only the owner (or an admin) may delete
      if (!post.author.equals(user._id) && user.role !== 'admin')
        throw fail('Not allowed', 'FORBIDDEN');
      await Reply.deleteMany({ post: post._id });
      await post.deleteOne();
      return true;
    },

    toggleLike: async (_, { postId }, ctx) => {
      const user = requireAuth(ctx);
      const post = await Post.findById(postId);
      if (!post) throw fail('Post not found', 'NOT_FOUND');
      const liked = post.likes.some((id) => id.equals(user._id));
      if (liked) post.likes.pull(user._id);
      else post.likes.addToSet(user._id);
      await post.save();
      return post;
    },

    addReply: async (_, { postId, content }, ctx) => {
      const user = requireAuth(ctx);
      if (!(await Post.exists({ _id: postId }))) throw fail('Post not found', 'NOT_FOUND');
      return Reply.create({ post: postId, author: user._id, content: cleanText(content) });
    },

    unblockIp: async (_, { ip }, ctx) => {
      requireAdmin(ctx);
      await unblockIp(normalizeIp(String(ip).trim()));
      return true;
    },
  },

  // Field resolvers. User.posts <-> Post.author lets queries nest forever,
  // which is exactly what the Day 2 depth limiter will defend against.
  User: {
    // email is private: only the owner (or an admin) can read it
    email: (u, _, ctx) =>
      ctx.user && (ctx.user._id.equals(u._id) || ctx.user.role === 'admin') ? u.email : 'hidden',
    posts: (u) => Post.find({ author: u._id }).sort({ createdAt: -1 }).exec(),
    createdAt: iso,
  },
  Post: {
    author: (p) => User.findById(p.author).select('-password').exec(),
    likesCount: (p) => p.likes.length,
    likedByMe: (p, _, ctx) => !!ctx.user && p.likes.some((id) => id.equals(ctx.user._id)),
    replies: (p) => Reply.find({ post: p._id }).sort({ createdAt: 1 }).exec(),
    createdAt: iso,
  },
  SecurityEvent: {
    createdAt: iso,
  },
  BlockedIp: {
    blockedUntil: (b) => b.blockedUntil.toISOString(),
  },
  Reply: {
    author: (r) => User.findById(r.author).select('-password').exec(),
    createdAt: iso,
  },
};