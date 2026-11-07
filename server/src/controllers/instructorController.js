import Joi from 'joi';
import bcrypt from 'bcryptjs';
import { Instructor } from '../models/Instructor.js';

// =============================================================================
//  INSTRUCTOR PORTAL CONTROLLER  —  hardened against NoSQL injection
// =============================================================================
//
//  Layer 1 (app.js): express-mongo-sanitize strips/neutralises any key that
//                    starts with "$" or contains "." in body/query/params.
//                    It is a blanket, schema-agnostic safety net.
//  Layer 2 (here):   Joi enforces the *shape and type* of every input: strings
//                    only, known keys only, bounded length. An object like
//                    {"$ne": null} is rejected as "must be a string" even if
//                    the sanitizer were ever misconfigured or bypassed.
//  Layer 3 (here):   Filters are built by hand from validated values; user
//                    input is never passed to Mongoose as a query object.
//  Layer 4 (here):   Passwords are bcrypt hashes, secrets are never returned.
// =============================================================================

const JOI_OPTIONS = { abortEarly: true, allowUnknown: false, stripUnknown: false };

const loginSchema = Joi.object({
  username: Joi.string().trim().min(1).max(64).required(),
  password: Joi.string().min(1).max(128).required()
});

// Only PUBLIC fields can be searched on. username/password/apiKey/private*
// are deliberately absent so they can't be probed (e.g. ?privateEmail=...).
const searchSchema = Joi.object({
  name: Joi.string().trim().min(1).max(64),
  department: Joi.string().trim().min(1).max(64),
  role: Joi.string().trim().min(1).max(32)
});

// Fields that may ever leave the server through list/search endpoints.
const PUBLIC_FIELDS = 'name department role';

// A real bcrypt hash of a random string, used so that "user not found" takes
// about as long as "wrong password" (prevents username enumeration by timing).
const DUMMY_HASH = bcrypt.hashSync('not-a-real-password', 12);

function escapeRegExp(str) {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// What the logged-in instructor gets about THEMSELVES. Never includes the
// password hash or the apiKey.
function ownProfile(doc) {
  return {
    id: doc._id.toString(),
    name: doc.name,
    username: doc.username,
    department: doc.department,
    role: doc.role,
    privateEmail: doc.privateEmail,
    privatePhone: doc.privatePhone
  };
}

// POST /api/instructors/login
export async function loginInstructor(req, res, next) {
  try {
    const { error, value } = loginSchema.validate(req.body, JOI_OPTIONS);
    if (error) {
      // Same generic message for every malformed input: don't help attackers.
      return res.status(400).json({ message: 'Invalid username or password format' });
    }
    const { username, password } = value;

    // `username` is guaranteed to be a plain string here, so this is an
    // equality match and can't carry an operator. Password is NOT part of the
    // query anymore: it is compared against the stored hash below, which kills
    // the $regex / $ne oracle completely.
    const instructor = await Instructor.findOne({ username }).select('+password');

    const hash = instructor ? instructor.password : DUMMY_HASH;
    const ok = await bcrypt.compare(password, hash);

    if (!instructor || !ok) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }
    return res.json({ instructor: ownProfile(instructor) });
  } catch (err) {
    next(err);
  }
}

// GET /api/instructors
export async function getDirectory(req, res, next) {
  try {
    const instructors = await Instructor.find()
      .select(PUBLIC_FIELDS)
      .sort({ name: 1 })
      .lean();
    res.json({ instructors });
  } catch (err) {
    next(err);
  }
}

// GET /api/instructors/search
export async function searchInstructors(req, res, next) {
  try {
    // Only plain strings in whitelisted keys are ever considered. Anything else
    // (unknown keys like username/$where, or objects such as {$ne:...} that the
    // sanitizer has already emptied) is silently ignored, so an injection
    // attempt degrades to the harmless public directory instead of an error.
    const input = {};
    for (const key of ['name', 'department', 'role']) {
      if (typeof req.query[key] === 'string') input[key] = req.query[key];
    }

    const { error, value } = searchSchema.validate(input, JOI_OPTIONS);
    if (error) {
      return res.status(400).json({ message: 'Invalid search parameters' });
    }

    // Build the filter ourselves from validated strings. Nothing from the
    // request is used as a key, and every value is a string or an escaped regex.
    const filter = {};
    if (value.name) filter.name = { $regex: escapeRegExp(value.name), $options: 'i' };
    if (value.department) filter.department = value.department;
    if (value.role) filter.role = value.role;

    const instructors = await Instructor.find(filter)
      .select(PUBLIC_FIELDS)
      .sort({ name: 1 })
      .limit(50)
      .lean();

    res.json({ count: instructors.length, instructors });
  } catch (err) {
    next(err);
  }
}