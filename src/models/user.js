// Import required packages
const mongoose = require('mongoose')
const validator = require('validator')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')

// Load environment variables
require('dotenv').config()

// Define the User schema
const userSchema = new mongoose.Schema({
    fullname: {
        type: String, 
        required: true,
        trim: true,
        lowercase: true
    },
    email: {
        type: String,
        unique: true,
        required: true,
        trim: true,
        lowercase: true,
        validate(value) {
            if (!validator.isEmail(value)) {
                throw new Error('Email is invalid')
            }
        }
    },
    password: {
        type: String,
        required: true,
        minlength: 7,
        trim: true,
        validate(value) {
            if (value.toLowerCase().includes('password')) {
                throw new Error('Password cannot contain "password"');
            }
        },
        select: false // Exclude the password field when querying users
    },
    gender: {
      type: String,
      enum: ['Male', 'Female', 'Non-binary', 'Prefer not to say'],
      required: false
    },
    interests: {
      type: [String],
      default: [],
      required: false
    },
    profilePhoto: {
        key: {
            type: String,
            required: false
        },
        location: {
            type: String,
            required: false
        },
    },
    isEmailConfirmed: {
        type: Boolean,
        required: false,
        default: false
    },
    isVerified: {
        type: Boolean,
        required: false,
        default: false
    },
    isAdmin: {
        type: Boolean,
        required: false,
        default: false
    },
    isActive: {
        type: Boolean,
        required: false,
        default: true
    },
    emailConfirmToken: {
        type: String,
        required: false
    },
    passwordResetToken: {
        type: String,
        required: false
    },
    tokens: [{
        token: {
            type: String,
            required: true
        }
    }]
}, {
    timestamps: true
})

// Create a text index for the fullname field
userSchema.index({ fullname: 'text' });

// Method to generate a new authentication token
// userSchema.methods.generateAuthToken = async function () {
//     const user = this
//     const token = jwt.sign({ _id: user._id.toString() }, process.env.JWT_SECRET_KEY)

//     user.tokens = user.tokens.concat({ token })
//     await user.save()

//     return token
// }

// Custom toJSON method to remove sensitive fields from the output
userSchema.methods.toJSON = function () {
    const user = this
    const userObject = user.toObject()

    delete userObject.password
    delete userObject.tokens

    return userObject
}

// Static method to find a user by email and password
// userSchema.statics.findByCredentials = async (email, password) => {
//     const user = await User.findOne({ email })

//     if (!user) {
//         throw new Error('Unable to login')
//     }

//     const isMatch = await bcrypt.compare(password, user.password)

//     if (!isMatch) {
//         throw new Error('Unable to login')
//     }

//     return user
// }

// Middleware to hash the password before saving the user
userSchema.pre('save', async function (next) {
    const user = this

    if (user.isModified('password')) {
        user.password = await bcrypt.hash(user.password, 8)
    }

    next()
})

// Transformation function to remove sensitive fields
const userTransformation = function (doc, ret, options) {
    delete ret.password;
    delete ret.tokens;
    return ret;
}

userSchema.set('toObject', { transform: userTransformation });
userSchema.set('toJSON', { transform: userTransformation });

const User = mongoose.model('User', userSchema);

module.exports = User;
