const mongoose = require('mongoose')

const groupSchema = new mongoose.Schema({
    owner: {
        type: mongoose.Schema.Types.ObjectId,
        required: true,
        ref: 'User'
    },
    name: {
        type: String,
        required: false,
        maxlength: 50,
        trim: true
    },
    description: {
        type: String,
        required: false,
        maxlength: 500,
        trim: true
    },
    rules: {
        type: String,
        required: false,
        maxlength: 500,
        trim: true
    },
    banner: {
        type: Boolean,
        required: false,
        default: false
    },
    location: {
        address: {
            type: String,
            required: false
        },
        street: {
            type: String,
            required: false
        },
        city: {
            type: String,
            required: false
        },
        zip: {
            type: String,
            required: false
        }
    },
    category: {
        type: String,
        required: false,
        enum: ["studio", "house", "field", "room",
                "restaurant", "school", "church", 
                "beach", "warehouse", "others", 
                "road", "rooftop"
            ]
    },
    members: [{
        type: mongoose.Schema.Types.ObjectId,
        required: false,
        ref: 'User'
    }],
    moderators: [{
        type: mongoose.Schema.Types.ObjectId,
        required: false,
        ref: 'User'
    }],
    requests: [{
        type: mongoose.Schema.Types.ObjectId,
        required: false,
        ref: 'User'
    }],
    permissionRequired: {
        type: Boolean,
        required: false,
        default: false
    },
    deactivated: {
        type: Boolean,
        required: false,
        default: false
    },
}, {
    timestamps: true
})

// groupSchema.index( { "location.country": "text", "location.street": "text", "location.city": "text", "location.state": "text", "location.zip": "text" } )

const Group = mongoose.model('Group', groupSchema)

module.exports = Group
