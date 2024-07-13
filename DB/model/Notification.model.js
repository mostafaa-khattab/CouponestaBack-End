import mongoose, { Schema, Types, model } from "mongoose";


const notificationSchema = new Schema({

    header: {
        en: {
            type: String,
            required: [true, 'English header is required'],
            trim: true,
            lowercase: true
        },
        ar: {
            type: String,
            required: [true, 'Arabic header is required'],
            trim: true,
            lowercase: true
        }
    },
    body: {
        en: {
            type: String,
            required: [true, 'English body is required'],
            trim: true,
            lowercase: true
        },
        ar: {
            type: String,
            required: [true, 'Arabic body is required'],
            trim: true,
            lowercase: true
        }
    },

    user: [
        {
            type: Types.ObjectId,
            ref: 'User',
            required: true
        }
    ],

    createdBy: {
        type: Types.ObjectId,
        ref: 'User',
        required: true
    },

    updatedBy: {
        type: Types.ObjectId,
        ref: 'User',
    },

    isDeleted: {
        type: Boolean,
        default: false
    },

    isWatched: {
        type: Boolean,
        default: false
    },


}, {
    timestamps: true,
})

notificationSchema.pre(/^find/, function () {

    this.populate('createdBy', 'fullName')
        .populate('updatedBy', 'fullName')
        .populate('user' , 'fullName email phone status')

})

const notificationModel = mongoose.models.Notification || model("Notification", notificationSchema)
export default notificationModel