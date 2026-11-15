import bcrypt from 'bcryptjs';
import { GraphQLError } from 'graphql';
import User from '../models/User.js';
import Post from '../models/Post.js';
import Reply from '../models/Reply.js';
import { signToken } from '../utils/auth.js';

const fail = (message, code) => new GraphQLError(message, { extensions: { code } });

const requireAuth = (ctx) => {
  if (!ctx.user) throw fail('You must be logged in', 'UNAUTHENTICATED');
  return ctx.user;
};

const cleanText = (text, max = 280) => {
  const t = String(text).trim();
  if (!t || t.length > max) throw fail(`Text must be 1-${max} characters`, 'BAD_USER_INPUT');
  return t;
};

const iso = (doc) => (doc.createdAt ? doc.createdAt.toISOString() : null);

export default {
  Query: {
    me: (_, __, ctx) => ctx.user,
    feed: (_, { limit }) =>
      Post.find().sort({ createdAt: -1 }).limit(Math.min(Math.max(limit, 1), 50)),
    post: (_, { id }) => Post.findById(id),
    user: (_, { id }) => User.findById(id).select('-password'),
  },

  Mutation: {
    signup: async (_, { username, email, password }) => {
      if (password.length < 8) throw fail('Password must be at least 8 characters', 'BAD_USER_INPUT');
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
  },

  // Field resolvers. User.posts <-> Post.author lets queries nest forever,
  // which is exactly what the Day 2 depth limiter will defend against.
  User: {
    // email is private: only the owner (or an admin) can read it
    email: (u, _, ctx) =>
      ctx.user && (ctx.user._id.equals(u._id) || ctx.user.role === 'admin') ? u.email : 'hidden',
    posts: (u) => Post.find({ author: u._id }).sort({ createdAt: -1 }),
    createdAt: iso,
  },
  Post: {
    author: (p) => User.findById(p.author).select('-password'),
    likesCount: (p) => p.likes.length,
    likedByMe: (p, _, ctx) => !!ctx.user && p.likes.some((id) => id.equals(ctx.user._id)),
    replies: (p) => Reply.find({ post: p._id }).sort({ createdAt: 1 }),
    createdAt: iso,
  },
  Reply: {
    author: (r) => User.findById(r.author).select('-password'),
    createdAt: iso,
  },
};
