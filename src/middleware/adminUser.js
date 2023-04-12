const jwt = require('jsonwebtoken');
const User = require('../models/user');
require('dotenv').config();


/**
 * Middleware function to ensure the user is authenticated and an admin.
 * Verifies the token, checks if the user exists, and ensures the user is an admin.
 */
const adminUser = async (req, res, next) => {
    try {
        const token = extractTokenFromHeader(req);
        const decoded = verifyToken(token);
        const user = await findUserByToken(decoded._id, token);

    if (!user || !user.isAdmin) {
        throw new Error();
    }

    attachUserDataToRequest(req, user, token);
    next();
    } catch (e) {
        res.status(401).send({ error: 'you need to authenticate or be an admin user to do this' });
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
 * Attaches the user object and token to the request object.
 */
const attachUserDataToRequest = (req, user, token) => {
    req.token = token;
    req.user = user;
};


module.exports = adminUser;
