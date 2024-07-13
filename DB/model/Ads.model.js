import mongoose, { Schema, Types, model } from "mongoose";


const adsSchema = new Schema({

    name: {
        type: String,
        required: [true, 'name is required'],
        unique: [true, 'name is unique'],
        trim: true,
        lower: true
    },

    link: {
        type: String,
        required: [true, 'Ads link is required'],
        trim: true
    },

    image: String,

    createdBy: {
        type: Types.ObjectId,
        ref: 'User',
        required: true
    },

    updatedBy: {
        type: Types.ObjectId,
        ref: 'User',
    },

    location: [
        {
            type: Types.ObjectId,
            ref: 'Location',
        }
    ],

    isDeleted: {
        type: Boolean,
        default: false
    },

}, {
    timestamps: true,
})

adsSchema.pre(/^find/, function () {

    this.populate('createdBy', 'fullName')
        .populate('updatedBy', 'fullName')
        .populate('location' , 'name locationCode')
})

const adsModel = mongoose.models.Ads || model("Ads", adsSchema)
export default adsModel