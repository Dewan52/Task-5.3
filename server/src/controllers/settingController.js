import Joi from 'joi';
import { Setting } from '../models/Setting.js';

const recoveryEmailSchema = Joi.object({
  recoveryEmail: Joi.string().email().required()
});

function publicSettings(doc) {
  return {
    recoveryEmail: doc?.recoveryEmail || '',
    notifications: doc?.notifications ?? true
  };
}

// GET /api/settings — the logged-in user's settings (created lazily on first write).
export async function getSettings(req, res, next) {
  try {
    const doc = await Setting.findOne({ user: req.user.id }).lean();
    res.json({ settings: publicSettings(doc) });
  } catch (err) { next(err); }
}

// POST /api/settings/recovery-email — change the recovery email.
//
// State-changing: requests only reach this handler with a valid CSRF token
// (checked by `doubleCsrfProtection` in app.js), so forged cross-site requests get a 403.
export async function updateRecoveryEmail(req, res, next) {
  try {
    const { value, error } = recoveryEmailSchema.validate({ recoveryEmail: req.body.recoveryEmail });
    if (error) return res.status(400).json({ message: error.message });

    const doc = await Setting.findOneAndUpdate(
      { user: req.user.id },
      { $set: { recoveryEmail: value.recoveryEmail } },
      { new: true, upsert: true, runValidators: true, setDefaultsOnInsert: true }
    );
    res.json({ settings: publicSettings(doc) });
  } catch (err) { next(err); }
}
