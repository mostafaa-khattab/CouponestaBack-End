import mongoose, { Schema, Types, model } from "mongoose";


const userSchema = new Schema({

    fullName: {
        type: String,
        required: [true, 'full name is required'],
        min: [2, 'minimum length 2 char'],
        max: [50, 'max length 50 char'],
        trim: true,
    },
    email: {
        type: String,
        trim: true,
        lower: true
    },

    password: {
        type: String,
        required: [true, 'password is required'],
    },

    changePasswordTime: Date,

    phoneNumber: {
        type: String,
        trim: true,
        lower: true
    },


    countryCode: {
        type: String,
    },

    role: {
        type: String,
        default: 'User',
        enum: ['User', 'Admin', 'Employee']
    },

    confirmAccount: {
        type: Boolean,
        default: true,
    },

    
    status: {
        type: String,
        default: "offline",
        enum: ['offline', 'online', 'blocked'],
    },

    favorite: [
        {
            type: Types.ObjectId,
            ref: 'Coupon',
        }
    ],

    follow: [
        {
            type: Types.ObjectId,
            ref: 'Brand',
        }
    ],

    notification: [
        {
            type: Types.ObjectId,
            ref: 'Notification'
        }
    ],

    isDeleted: {
        type: Boolean,
        default: false
    },

    createdBy: {
        type: Types.ObjectId,
        ref: 'User',
    },

    updatedBy: {
        type: Types.ObjectId,
        ref: 'User',
    },

    image: String,
    DOB: Date,
    joined: Date,

    gender: {
        type: String,
        enum: ['male', 'female'],
    },

    provider: {
        type: String,
        default: 'system',
        enum: ['system', 'facebook', 'GOOGLE'],
    },

}, {
    timestamps: true
})

const userModel = mongoose.model.User || model('User', userSchema)
export default userModel