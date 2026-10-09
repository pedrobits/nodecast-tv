const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const passport = require('passport');
const { Strategy: JwtStrategy, ExtractJwt } = require('passport-jwt');
const { Strategy: LocalStrategy } = require('passport-local');
const { createHash, timingSafeEqual } = require('node:crypto');

/**
 * Authentication and Authorization Module
 * Handles user authentication, session management, and role-based access control
 * Using Passport.js with JWT tokens
 */

// JWT Secret - In production, use environment variable
const JWT_SECRET = process.env.JWT_SECRET || 'nodecast-tv-secret-key-change-in-production';
const JWT_EXPIRY = '24h';
const SENTRA_HUB_TOKEN = process.env.SENTRA_HUB_TOKEN || '';
const SENTRA_HUB_USERNAME = process.env.SENTRA_HUB_USERNAME || 'sentra-hub';

if (SENTRA_HUB_TOKEN && SENTRA_HUB_TOKEN.length < 32) {
    throw new Error('SENTRA_HUB_TOKEN must contain at least 32 characters');
}

const sentraTokenDigest = SENTRA_HUB_TOKEN
    ? createHash('sha256').update(SENTRA_HUB_TOKEN).digest()
    : null;

/**
 * Hash password using bcrypt
 */
async function hashPassword(password) {
    const salt = await bcrypt.genSalt(10);
    return bcrypt.hash(password, salt);
}

/**
 * Verify password against hash
 */
async function verifyPassword(password, hash) {
    return bcrypt.compare(password, hash);
}

/**
 * Generate JWT token
 */
function generateToken(user) {
    // The dedicated account uses the same credential in every captured session.
    if (SENTRA_HUB_TOKEN && user.username === SENTRA_HUB_USERNAME) {
        return SENTRA_HUB_TOKEN;
    }

    return jwt.sign(
        {
            id: user.id,
            username: user.username,
            role: user.role
        },
        JWT_SECRET,
        { expiresIn: JWT_EXPIRY }
    );
}

/**
 * Verify JWT token
 */
function verifyToken(token) {
    try {
        return jwt.verify(token, JWT_SECRET);
    } catch (err) {
        return null;
    }
}

/**
 * Configure Passport Local Strategy for username/password authentication
 */
function configureLocalStrategy(getUserByUsername, verifyUserPassword) {
    passport.use(new LocalStrategy(
        async (username, password, done) => {
            try {
                const user = await getUserByUsername(username);

                if (!user) {
                    return done(null, false, { message: 'Invalid credentials' });
                }

                const isValid = await verifyUserPassword(password, user.passwordHash);

                if (!isValid) {
                    return done(null, false, { message: 'Invalid credentials' });
                }

                return done(null, user);
            } catch (err) {
                return done(err);
            }
        }
    ));
}

/**
 * Configure Passport JWT Strategy for token-based authentication
 */
function configureJwtStrategy(getUserById) {
    const options = {
        jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
        secretOrKey: JWT_SECRET
    };

    passport.use(new JwtStrategy(options, async (payload, done) => {
        try {
            const user = await getUserById(payload.id);

            if (!user) {
                return done(null, false);
            }

            return done(null, {
                id: user.id,
                username: user.username,
                role: user.role
            });
        } catch (err) {
            return done(err, false);
        }
    }));
}

/**
 * Configure Passport session serialization
 * Required for OIDC flow which uses sessions
 */
function configureSessionSerialization(getUserById) {
    passport.serializeUser((user, done) => {
        done(null, user.id);
    });

    passport.deserializeUser(async (id, done) => {
        try {
            const user = await getUserById(id);
            done(null, user);
        } catch (err) {
            done(err, null);
        }
    });
}

/**
 * Configure Passport OpenID Connect Strategy
 */
function configureOidcStrategy(findUserByOidcId, findUserByEmail, createUser) {
    if (!process.env.OIDC_ISSUER_URL || !process.env.OIDC_CLIENT_ID || !process.env.OIDC_CLIENT_SECRET) {
        console.warn('OIDC configuration missing - SSO disabled');
        return;
    }

    const { Strategy: OpenIDConnectStrategy } = require('passport-openidconnect');

    passport.use(new OpenIDConnectStrategy({
        issuer: process.env.OIDC_ISSUER_URL || 'https://mock-issuer.com', // Dummy default for mock
        authorizationURL: process.env.OIDC_AUTH_URL || `${process.env.OIDC_ISSUER_URL}/protocol/openid-connect/auth`,
        tokenURL: process.env.OIDC_TOKEN_URL || `${process.env.OIDC_ISSUER_URL}/protocol/openid-connect/token`,
        userInfoURL: process.env.OIDC_USERINFO_URL || `${process.env.OIDC_ISSUER_URL}/protocol/openid-connect/userinfo`,
        clientID: process.env.OIDC_CLIENT_ID || 'mock-client-id',
        clientSecret: process.env.OIDC_CLIENT_SECRET || 'mock-secret',
        callbackURL: process.env.OIDC_CALLBACK_URL || '/api/auth/oidc/callback',
        scope: ['openid', 'profile', 'email']
    },
        async (...args) => {
            // The done callback is always the last argument
            const done = args[args.length - 1];

            // Map known arguments
            // Standard: issuer, sub, profile, accessToken, refreshToken, done
            // Some versions: issuer, sub, profile, accessToken, refreshToken, params, done

            let issuer, sub, profile;

            if (args.length === 3) {
                // Scenario: (issuer, profile, done)
                const arg0 = args[0];
                const arg1 = args[1];

                if (typeof arg1 === 'object' && arg1.id) {
                    issuer = arg0;
                    profile = arg1;
                    sub = profile.id;
                } else if (typeof arg0 === 'string' && typeof arg1 === 'string') {
                    issuer = arg0;
                    sub = arg1;
                    profile = { id: sub, displayName: 'Unknown' };
                }
            } else if (args.length >= 4) {
                // Assume standard: iss, sub, profile...
                issuer = args[0];
                sub = args[1];
                profile = args[2];
            }

            if (!sub && profile && profile.id) sub = profile.id;

            if (!sub) {
                return done(new Error('Could not identify OIDC Subject (sub) from arguments'));
            }

            try {
                // 1. Try to find by OIDC ID (sub)
                let user = await findUserByOidcId(sub);

                // 2. If not found, try to match by email
                // Extract email - handle both profile.emails[] (Google) and profile.email (others)
                const email = profile.emails?.[0]?.value || profile.email || profile._json?.email;

                if (!user && email) {
                    user = await findUserByEmail(email);

                    // If found by email but no OIDC ID, link them
                    if (user && !user.oidcId) {
                        // We don't have a direct update method for specific fields without full user object in this context
                        // Ideally we'd update the user here. For now, we'll just log in.
                        // Future: Update user with oidcId
                    }
                }

                // 3. If still not found, create new user (JIT Provisioning)
                if (!user) {
                    const username = profile.username || profile.displayName || (email ? email.split('@')[0] : `user_${sub.substring(0, 8)}`);

                    user = await createUser({
                        username: username,
                        role: 'viewer', // Default role for SSO users
                        oidcId: sub,
                        email: email || null
                    });
                }

                return done(null, user);
            } catch (err) {
                return done(err);
            }
        }));
}

/**
 * Middleware: Accept the Sentra integration token or a normal Passport JWT.
 */
const requireJwt = passport.authenticate('jwt', { session: false });

async function requireAuth(req, res, next) {
    const token = ExtractJwt.fromAuthHeaderAsBearerToken()(req);
    if (sentraTokenDigest && token) {
        const digest = createHash('sha256').update(token).digest();
        if (timingSafeEqual(digest, sentraTokenDigest)) {
            try {
                // Resolve the account on each request so deletion and role changes apply.
                const user = await require('./db').users.getByUsername(SENTRA_HUB_USERNAME);
                if (!user) {
                    return res.status(401).json({ error: 'Sentra Hub account is not configured' });
                }
                req.user = { id: user.id, username: user.username, role: user.role };
                return next();
            } catch (err) {
                return next(err);
            }
        }
    }
    return requireJwt(req, res, next);
}

/**
 * Middleware: Require admin role
 */
function requireAdmin(req, res, next) {
    if (!req.user || req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Forbidden - Admin access required' });
    }
    next();
}

/**
 * Middleware: Check for specific role
 */
function requireRole(role) {
    return (req, res, next) => {
        if (!req.user || req.user.role !== role) {
            return res.status(403).json({ error: `Forbidden - ${role} access required` });
        }
        next();
    };
}

module.exports = {
    passport,
    hashPassword,
    verifyPassword,
    generateToken,
    verifyToken,
    configureLocalStrategy,
    configureJwtStrategy,
    configureSessionSerialization,
    configureOidcStrategy,
    requireAuth,
    requireAdmin,
    requireRole
};
