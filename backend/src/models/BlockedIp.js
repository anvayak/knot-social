import mongoose from 'mongoose';

const blockedIpSchema = new mongoose.Schema(
  {
    ip: { type: String, required: true, unique: true },
    reason: { type: String },
    strikes: { type: Number, default: 0 },
    blockedUntil: { type: Date, default: null },
  },
  { timestamps: true }
);

export default mongoose.model('BlockedIp', blockedIpSchema);
