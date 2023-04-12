const jwt = require('jsonwebtoken');
const User = require('../models/user');
require('dotenv').config();

/**
 * Middleware function for authentication.
 * Verifies the token and checks if the user exists in the database.
 */
const auth = async (req, res, next) => {
    try {
        const token = extractTokenFromHeader(req);
        const decoded = verifyToken(token);
        const user = await findUserByToken(decoded._id, token);

        if (!user) {
            throw new Error();
        }

        attachUserDataToRequest(req, user, token);
        next();
    } catch (e) {
        console.error(e);
        sendUnauthorizedResponse(res, 'Please authenticate');
    }
};


/**
 * Middleware function for verifying email.
 * Verifies the token, checks if the user exists, and ensures the user's email is confirmed.
 */
const isVerified = async (req, res, next) => {
    try {
        const token = extractTokenFromHeader(req);
        const decoded = verifyToken(token);
        const user = await findUserByToken(decoded._id, token);

        if (!user) {
            throw new Error();
        } else if (!user.isEmailConfirmed) {
            return res.status(400).send({ error: 'You need to verify your email' });
        }

        attachUserDataToRequest(req, user, token);
        next();
    } catch (e) {
        console.error(e);
        sendUnauthorizedResponse(res, 'Please authenticate');
    }
};

/**
 * Extracts the token from the Authorization header.
 */
const extractTokenFromHeader = (req) => {
    return req.header('Authorization').replace('Bearer ', '');
};

/**
 * Verifies the token using the JWT_SECRET_KEY and decodes its payload.
 */
const verifyToken = (token) => {
    return jwt.verify(token, process.env.JWT_SECRET_KEY);
};

/**
 * Searches for a user in the database with the given userId and token.
 */
const findUserByToken = async (userId, token) => {
    return await User.findOne({ _id: userId, 'tokens.token': token });
};

/**
 * Sends a 401 Unauthorized response with the provided error message.
 */
const sendUnauthorizedResponse = (res, message) => {
    return res.status(401).send({ error: message });
};

/**
 * Attaches the user object and token to the request object.
 */
const attachUserDataToRequest = (req, user, token) => {
    req.token = token;
    req.user = user;
};

module.exports = {
    auth,
    isVerified,
};
