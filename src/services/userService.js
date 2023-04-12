const User = require('../models/user');


/**
 * Create a new user.
 * @param {Object} userData - The data for the new user.
 * @returns {Promise<User>} - The created user.
 * @throws {Error} - If the user with the given email already exists.
 */
async function createUser(userData) {
    const user = new User(userData);
    const userExists = await User.findOne({ email: userData.email });

    if (userExists) {
        throw new Error('User already exists');
    }

    await user.save();
    return user;
}


/**
 * Find a user by ID.
 * @param {string} userId - The user ID to search for.
 * @returns {Promise<User|null>} - The user found or null if not found.
 */
async function findUserById(userId) {
    return await User.findById(userId);
}


/**
 * Find a user by email and password.
 * 
 * @param {String} email - The email of the user.
 * @param {String} password - The password of the user.
 * @returns {Promise<Object>} The found user object.
 * @throws {Error} If no user is found or the password is incorrect.
 */
async function findByCredentials(email, password) {
    const user = await User.findOne({ email }).select('+password');

    if (!user) {
        throw new Error('Invalid email or password');
    }

    const isMatch = await user.comparePassword(password);

    if (!isMatch) {
        throw new Error('Invalid email or password');
    }

    return user;
}


/**
 * Find a user by email.
 * @param {string} email - The email address to search for.
 * @returns {Promise<User|null>} - The user found or null if not found.
 */
async function getUserByEmail(email) {
    return await User.findOne({ email });
}


/**
 * Update an existing user.
 * @param {User} user - The user to update.
 * @param {Object} updates - The updates to apply to the user.
 * @returns {Promise<void>} - Resolves when the user is updated.
 */
async function updateUser(user, updates) {
    Object.assign(user, updates);
    await user.save();
}


/**
 * Save the password reset token to the user's document.
 * @param {Object} user - The user object.
 * @param {String} token - The password reset token.
 * @returns {Promise<Object>} - A promise that resolves to the updated user document.
 * @throws {Error} - If an error occurs while saving the token.
 */
const savePasswordResetToken = async (user, token) => {
    try {
        // Set the passwordResetToken field in the user document
        user.passwordResetToken = token;
        // Save the updated user document to the database
        await user.save();
        // Return the updated user document
        return user;
    } catch (error) {
        // If an error occurs, throw the error
        throw error;
    }
};


/**
 * Update the user's password.
 *
 * @param {Object} user - The user object.
 * @param {string} newPassword - The new password to be set.
 * @returns {Promise} - A promise that resolves when the password is updated successfully.
 */
async function updateUserPassword(user, newPassword) {
    user.password = newPassword;
    await user.save();
}


module.exports = {
    createUser,
    findUserById,
    findByCredentials,
    getUserByEmail,
    updateUser,
    savePasswordResetToken,
    updateUserPassword
};
