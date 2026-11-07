import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';

const BCRYPT_ROUNDS = 12;

// Instructor Portal account.
//
// Security notes:
//  - `password` is stored only as a bcrypt hash and is `select: false`, so it
//    is never loaded by default. The login controller opts in with
//    .select('+password') to compare the hash.
//  - `apiKey` is `select: false` for the same reason: it can't leak through
//    a find() that forgets a projection.
//  - privateEmail / privatePhone are NOT select:false because the controller
//    returns them to the owner after login, but list/search endpoints use an
//    explicit projection (name department role) and never include them.
const instructorSchema = new mongoose.Schema(
  {
    name: { type: String, required: true, trim: true },
    username: { type: String, required: true, unique: true, trim: true },
    password: { type: String, required: true, select: false },
    department: { type: String, trim: true },
    role: { type: String, default: 'instructor' }, // 'instructor' | 'superadmin'

    apiKey: { type: String, select: false },
    privateEmail: { type: String },
    privatePhone: { type: String }
  },
  { timestamps: true }
);

const isBcryptHash = (s) => typeof s === 'string' && /^\$2[aby]\$\d{2}\$/.test(s);

// Hash on create / save whenever the password changed.
instructorSchema.pre('save', async function () {
  if (!this.isModified('password')) return;
  this.password = await bcrypt.hash(this.password, BCRYPT_ROUNDS);
});

// Also hash for Instructor.insertMany([...]) (e.g. seed scripts), which skips
// the 'save' hook. Already-hashed values are left alone.
instructorSchema.pre('insertMany', async function (next, docs) {
  const list = Array.isArray(docs) ? docs : [docs];
  for (const doc of list) {
    if (doc && doc.password && !isBcryptHash(doc.password)) {
      doc.password = await bcrypt.hash(doc.password, BCRYPT_ROUNDS);
    }
  }
});

// Never serialise secrets, even if some future code selects them by accident.
instructorSchema.set('toJSON', {
  transform: (_doc, ret) => {
    delete ret.password;
    delete ret.apiKey;
    return ret;
  }
});

export const Instructor = mongoose.model('Instructor', instructorSchema);