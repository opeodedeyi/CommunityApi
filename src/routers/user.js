const express = require('express')
const User = require('../models/user')
const { auth } = require('../middleware/auth')
const router = new express.Router()
const jwt = require('jsonwebtoken')
require('dotenv').config()

const {OAuth2Client} = require('google-auth-library')
const { sendConfirmationEmail, sendPasswordResetEmail } = require('../services/sendmail')
const { s3 } = require('../middleware/aws')
const bcrypt = require('bcryptjs')

const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID)


// Lookaam API homepage -- (Tested)
router.get('', async (req, res) => {
    try {
        res.status(201).send({"message": "Welcome to community api"})
    } catch (e) {
        res.status(400).send({ "message": "Email failed to verify" })
    }
})


// Signup a normal user -- (Tested)(mail)
router.post('/signup', async (req, res) => {
    const user = new User(req.body)
    const userExists = await User.findOne({ email: req.body.email })

    if (userExists) { // checks if user already exists
        return res.status(400).send({ "message": "user already exists" })
    }

    try {
        await user.save()
        sendConfirmationEmail(user) // send verification email to the user
        const token = await user.generateAuthToken() // sends a token to the user
        res.status(201).send({ user, token, "message": "user created" })
    } catch (e) {
        res.status(401).send({ "message": "Something went wrong" })
    }
})


// Login or Signup a user using Google -- (Tested)
router.post('/googlelogin', async (req, res) => {
    try {
        const { tokenId } = req.body
        client.verifyIdToken({ idToken: tokenId, audience: process.env.GOOGLE_CLIENT_ID })
        .then( async (response) => {
            const {email_verified, name, email, picture} = response.payload;
            if (email_verified) { // Check if user on google is verified
                const user = await User.findOne({email}) 
                if (user) { // Check if user exists on our platform
                    if (user.isEmailConfirmed==false) {
                        user.isEmailConfirmed=true // Set email as confirmed
                        await user.save()
                    }
                    const token = await user.generateAuthToken() // Generate token that is sent in next line
                    res.status(200).send({ user, token })
                } else {
                    let password = email+process.env.ADMIN_SECRET_KEY // Generate random password for the google user
                    let newUser = new User({ email, fullname: name, password, profilePhoto: {location: picture}, isEmailConfirmed: true }) // Create user
                    await newUser.save()
                    const token = await newUser.generateAuthToken() // Generate token that is sent in next line
                    res.status(201).send({ "user": newUser , token })
                }
            }
        }).catch(e => { // you need to catch the error for promise 
            res.status(400).send({ "message": "Something went wrong" })
        })
    } catch (e) {
        res.status(400).send({ "message": "Something went wrong" })
    }
})


// Request new verification email -- (Tested)(mail)
router.post('/requestverification', async (req, res) => {
    const user = await User.findOne({ email: req.body.email })

    if (!user) {
        return res.status(401).send({ "message": "there is no such user, please signup" })
    } if (user.isEmailConfirmed) {
        return res.status(401).send({ "message": "Email is already verified" })
    }

    try {
        sendConfirmationEmail(user)
        res.status(201).send({ user, "message": "verification email has been sent" })
    } catch (e) {
        res.status(400).send({"message": "Email failed to send"})
    }
})


// Request new verification email loggedin user -- (Tested)(mail)
router.post('/requestverificationloggedin', auth, async (req, res) => {
    const user = req.user

    if (!user) {
        return res.status(404).send({ "message": "there is no such user, please signup" })
    } if (user.isEmailConfirmed) {
        return res.status(400).send({ "message": "Email is already verified" })
    }

    try {
        sendConfirmationEmail(user)
        res.status(201).send({ user, "message": "verification email has been sent" })
    } catch (e) {
        res.status(401).send({"message": "Email failed to send"})
    }
})


// Confirming an email -- (Tested)
router.get('/confirmation/:token', async (req, res) => {
    try {
        token = req.params.token

        const verifyToken = jwt.verify(token, process.env.JWT_SECRET_KEY)
        const user = await User.findById(verifyToken._id)

        if (user.isEmailConfirmed==true) {
            return res.status(200).send({"message": "Email has been verified"})
        }

        user.isEmailConfirmed=true
        await user.save()
        res.status(201).send({"message": "Email has been verified"})
    } catch (e) {
        res.status(400).send({ "message": "Email failed to verify" })
    }
})


// Reset password in case you forget a password -- (Tested) (mail)
router.post('/resetpassword', async (req, res) => {
    const user = await User.findOne({ email: req.body.email })

    if (!user) {
        return res.status(401).send({ "message": "email doesnt exist, please signup" })
    }

    try {
        sendPasswordResetEmail(user)
        res.status(201).send({ user, "message": "password reset email sent" })
    } catch (e) {
        res.status(400).send({ "message": "failed to send reset email, please try again" })
    }
})


// Reset password change -- (Tested)
router.post('/resetpassword/:token', async (req, res) => {
    try {
        const oldtoken = req.params.token
        newpassword = req.body.password
        const verifyToken = jwt.verify(oldtoken, process.env.JWT_SECRET_KEY)
        const user = await User.findById(verifyToken._id)

        if (!user) {
            return res.status(401).send({"message": "The token may have expired, please reapply for password reset"})
        }

        user.password=newpassword
        user.tokens = []
        await user.save()
        const token = await user.generateAuthToken()
        res.status(201).send({ user, token, "message": "Password successfully reset" })
    } catch (e) {
        res.status(400).send({ "message": "Failed to reset password" })
    }
})


// Login a user -- (Tested)
router.post('/login', async (req, res) => {
    try {
        const user = await User.findByCredentials(req.body.email, req.body.password)
        if (!user.isActive) {
            return res.status(400).send({"message": "Your account has been deativated, please contact us if you have an issue"})
        }
        const token = await user.generateAuthToken()
        res.status(200).send({ user, token })
    } catch (e) {
        res.status(401).send({ "message": "Failed to log in" })
    }
})


// Log out a user -- (Tested)
router.post('/logout', auth, async (req, res) => {
    try {
        req.user.tokens = req.user.tokens.filter((token) => {
            return token.token !== req.token
        })
        await req.user.save()

        res.status(204).send({ "message": "Successfully logged out" })
    } catch (e) {
        res.status(401).send({ "message": "Failed to log out" })
    }
})


// Logged Out of all of a user's devices -- (Tested)
router.post('/logoutall', auth, async (req, res) => {
    try {
        req.user.tokens = []
        await req.user.save()

        res.status(200).send({ "message": "Successfully logged out" })
    } catch (e) {
        res.status(400).send({ "message": "Failed to log out" })
    }
})


// Get logged in users profile -- (Tested)
router.get('/me', auth, async (req, res) => {
    try {
        res.status(200).send(req.user)
    } catch (error) {
        res.status(400).send({ "message": "Please log in or try again" })
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


module.exports = router
