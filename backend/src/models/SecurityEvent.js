import mongoose from 'mongoose';

// Used from Day 2/3 - created now so the schema is ready
const securityEventSchema = new mongoose.Schema(
  {
    ip: { type: String, required: true },
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
    attackType: { type: String, default: 'none' }, // depth, complexity, sqli, xss, ssrf, cmdi, rate_limit...
    riskScore: { type: Number, default: 0 },
    decision: { type: String, enum: ['ALLOW', 'FLAG', 'BLOCK'], required: true },
    snippet: { type: String, maxlength: 500 },
  },
  { timestamps: true }
);

export default mongoose.model('SecurityEvent', securityEventSchema);
