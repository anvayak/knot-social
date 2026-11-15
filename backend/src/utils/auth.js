import jwt from 'jsonwebtoken';
import User from '../models/User.js';

export function signToken(user) {
  return jwt.sign({ id: user.id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '2h' });
}

// Returns the logged-in User document, or null (never throws)
export async function getUserFromReq(req) {
  try {
    const header = req.headers.authorization || '';
    if (!header.startsWith('Bearer ')) return null;
    const decoded = jwt.verify(header.slice(7), process.env.JWT_SECRET);
    return await User.findById(decoded.id).select('-password');
  } catch {
    return null;
  }
}
