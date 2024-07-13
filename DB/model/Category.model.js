import mongoose, { Schema, Types, model } from "mongoose";


const categorySchema = new Schema({

    name: {
        en: {
            type: String,
            // required: [true, 'English name is required'],
            // unique: [true, 'English name must be unique'],
            trim: true
        },
        ar: {
            type: String,
            // required: [true, 'Arabic name is required'],
            // unique: [true, 'Arabic name must be unique'],
            trim: true
        }
    },

    slug: {
        en: {
            type: String,
            // required: [true, 'English slug is required'],
            // unique: [true, 'English slug must be unique'],
            trim: true
        },
        ar: {
            type: String,
            // required: [true, 'Arabic slug is required'],
            // unique: [true, 'Arabic slug must be unique'],
            trim: true
        }
    },

    description: {
        type: {
            en: String,
            ar: String
        },
        trim: true
    },

    image: String,

    icon: String,

    color: String,

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
            required: true
        }
    ],


    isDeleted: {
        type: Boolean,
        default: false
    },

}, {
    timestamps: true,
})

categorySchema.pre(/^find/, function () {

    this.populate('createdBy', 'fullName')
        .populate('updatedBy', 'fullName')
        .populate('location')
})

const categoryModel = mongoose.models.Category || model("Category", categorySchema)
export default categoryModel