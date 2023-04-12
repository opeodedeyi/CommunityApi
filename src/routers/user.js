// Import required modules
const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { OAuth2Client } = require('google-auth-library');
const { s3 } = require('../middleware/aws');

// Import services
const userService = require('../services/userService');
const authService = require('../services/authService');
const emailService = require('../services/emailService');

// Create a router
const router = new express.Router();


// Lookaam API homepage -- (Tested)
router.get('', async (req, res) => {
    try {
        res.status(201).send({"message": "Welcome to community api"})
    } catch (e) {
        res.status(400).send({ "message": "Email failed to verify" })
    }
})


// Signup a normal user
router.post('/signup', async (req, res) => {
    // Use the userService to create a new user
    try {
        const newUser = await userService.createUser(req.body);
        // Send a confirmation email using the emailService
        emailService.sendConfirmationEmail(newUser);
        // Generate an authentication token using authService
        const token = await authService.generateAuthToken(newUser);
        res.status(201).send({ newUser, token, message: 'User created' });
    } catch (e) {
        res.status(401).send({ message: 'Something went wrong' });
    }
});


// Route for Google OAuth
router.post('/google-auth', async (req, res) => {
    try {
        // Verify the Google token
        const payload = await verifyGoogleToken(req.body.idToken);

        // Extract user information from the payload
        const { email, given_name, family_name, picture } = payload;

        // Check if the user already exists in the database
        let user = await userService.getUserByEmail(email);

        if (!user) {
            // If the user doesn't exist, create a new user with the information from the payload
            const newUser = {
                email,
                    fullName: `${given_name} ${family_name}`,
                    password: bcrypt.hashSync(process.env.GOOGLE_USER_DEFAULT_PASSWORD, 8),
                    profilePhoto: {
                        photoKey: '',
                        photoURL: picture,
                    },
                    isEmailConfirmed: true,
            };

            // Save the new user
            user = await userService.createUser(newUser);
        }

        // Generate an authentication token using authService
        const token = await authService.generateAuthToken(user);
        res.status(200).send({ user, token, message: 'User logged in with Google' });
    } catch (e) {
        res.status(401).send({ message: 'Something went wrong with Google authentication' });
    }
});


// Request a new verification email
router.post('/request-verification-email', async (req, res) => {
    try {
        // Find the user by their email address
        const user = await userService.getUserByEmail(req.body.email);

        if (!user) {
            // If the user doesn't exist, return an error
            return res.status(404).send({ message: 'User not found' });
        }

        if (user.isEmailConfirmed) {
            // If the user's email is already confirmed, return a message
            return res.status(200).send({ message: 'Email is already confirmed' });
        }

        // Send a confirmation email using the emailService
        emailService.sendConfirmationEmail(user);
        res.status(200).send({ message: 'Verification email sent' });
    } catch (e) {
        res.status(500).send({ message: 'Something went wrong' });
    }
});


// Request new verification email for logged-in user
router.post('/request-verification-email-logged-in', auth, async (req, res) => {
    try {
        // Contains the logged-in user information (populated by 'auth' middleware)
        const user = req.user;

        // Check if the user's email is already confirmed
        if (user.isEmailConfirmed) {
            return res.status(400).send({ message: 'Email is already confirmed' });
        }

        // Send a new confirmation email using the emailService
        emailService.sendConfirmationEmail(user);
        res.status(200).send({ message: 'Verification email sent' });

    } catch (e) {
        res.status(500).send({ message: 'Something went wrong' });
    }
});


// Confirming an email
router.get('/confirm-email/:token', async (req, res) => {
    try {
        const token = req.params.token;

        // Verify the email confirmation token
        const decoded = jwt.verify(token, process.env.EMAIL_CONFIRM_SECRET_KEY)
        const user = await User.findOne({ _id: decoded._id, emailConfirmToken: token });

        if (!user) {
            return res.status(404).send({ message: 'Token not found or expired' });
        }

        // Update the user's email confirmation status
        user.isEmailConfirmed = true;
        user.emailConfirmToken = null;
        await user.save();
        
        res.status(200).send({ message: 'Email confirmed successfully' });
    } catch (e) {
        res.status(400).send({ "message": "Email failed to verify" })
    }
})


// Request password reset email
router.post('/password-reset', async (req, res) => {
    try {
        const email = req.body.email;
        const user = await userService.getUserByEmail(email);

        if (!user) {
            return res.status(404).send({ message: 'User not found' });
        }

        const resetToken = authService.generatePasswordResetToken(user);
        await userService.savePasswordResetToken(user, resetToken);

        emailService.sendPasswordResetEmail(user, resetToken);
        res.status(200).send({ message: 'Password reset email sent' });
    } catch (e) {
        res.status(500).send({ message: 'Something went wrong' });
    }
})


// Reset password
router.post('/reset-password/:resetToken', async (req, res) => {
    try {
        const resetToken = req.params.resetToken;
        const newPassword = req.body.newPassword;
        
        const decoded = authService.verifyPasswordResetToken(resetToken);
        const user = await userService.findUserById(decoded._id);

        if (!user) {
            return res.status(404).send({ message: 'User not found' });
        }

        await userService.updateUserPassword(user, newPassword);
        res.status(200).send({ message: 'Password updated successfully' });
    } catch (e) {
        res.status(500).send({ message: 'Something went wrong' });
    }
})


// Login a user
router.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await userService.findByCredentials(email, password);
        
        if (!user) {
            return res.status(401).send({ message: 'Invalid email or password' });
        }
        
        const token = await authService.generateAuthToken(user);
        res.status(200).send({ user, token, message: 'User logged in successfully' });
    } catch (e) {
        res.status(500).send({ message: 'Something went wrong' });
    }
})


// Log out a user by removing the current authentication token.
router.post('/logout', auth, async (req, res) => {
    try {
        req.user.tokens = req.user.tokens.filter((token) => {
            return token.token !== req.token;
        });
        await req.user.save();
        res.status(200).send({ message: 'User logged out' });
    } catch (e) {
        res.status(500).send({ message: 'Something went wrong' })
    }
})


// Log out a user from all devices by removing all authentication tokens
router.post('/logout-all', auth, async (req, res) => {
    try {
        req.user.tokens = []
        await req.user.save()
        res.status(200).send({ message: 'User logged out from all devices' });
    } catch (e) {
        res.status(500).send({ message: 'Something went wrong' });
    }
})


// Get the profile of the currently logged-in user
router.get('/me', auth, async (req, res) => {
    try {
        res.status(200).send(req.user);
    } catch (error) {
        res.status(500).send({ message: 'Something went wrong' });
    }
})


// Change users password -- (Tested)
router.patch('/me/password', auth, async (req, res) => {
    const user = req.user
    const oldPassword = req.body.oldPassword
    const newPassword = req.body.password
    try {
        const isMatch = await bcrypt.compare(oldPassword, user.password)
        if (!isMatch) {
            return res.status(400).send({ "message": "Wrong old password" })
        }
        req.user.password = newPassword
        req.user.tokens = []
        await req.user.save()
        const token = await user.generateAuthToken()
        res.status(200).send({ user, token, "message": "password has been changed" })
    } catch (e) {
        res.status(400).send({ "message": "The password failed to change" })
    }
})


// set a display picture of the user -- (Tested)
router.patch('/me/avatar', auth, async (req, res) => {
    try {
        const key = req.user.profilePhoto.key
        const providedphoto = req.body.location
        const providedkey = req.body.key
        
        var params = {
            Bucket: process.env.AWS_BUCKET_NAME,
            Key: key
        };
        
        if (key) {
            await s3.deleteObject(params).promise()
        }
        
        if (!providedphoto || !providedkey) {
            return res.status(400).send({ "message": "something went wrong", "developer": "you need to provide a key and location" })
        }
        
        req.user.profilePhoto.location = providedphoto
        req.user.profilePhoto.key = providedkey
        await req.user.save()
        res.status(200).send({ "message": "Successfully updated" })
    } catch(error) {
        return res.status(400).send({ error, "message": "Something went wrong" })
    }
})


// Getting a specific user details -- (Tested)
router.get('/users/:id', async (req, res) => {
    const _id = req.params.id

    try {
        const user = await User.findById(_id)
        if (!user) {
            return res.status(404).send()
        }
        res.status(200).send(user)
    } catch (e) {
        res.status(400).send({ "message": "failed to get user, please try again" })
    }
})




// Initialize Google OAuth2 client
const CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const client = new OAuth2Client(CLIENT_ID);

// Define an async function to verify the Google token
const verifyGoogleToken = async (idToken) => {
  const ticket = await client.verifyIdToken({
    idToken,
    audience: CLIENT_ID,
  });
  return ticket.getPayload();
};

// Export the router
module.exports = router
