import joi from "joi";
import { generalFields } from "../../middleware/validation.js";

// Function to validate URL
const validateURL = (value, helper) => {
    try {
        new URL(value);
        return true;
    } catch (error) {
        return helper.message('Invalid URL');
    }
};

export const createAdsValidation = joi.object({

    name: joi.string().min(1).max(50).required(),
    link: joi.string().min(1).max(200).required().custom(validateURL),
    image: generalFields.file,
    location: joi.alternatives().try(
        generalFields.id.required(), // Single ID
        generalFields.idArray.required() // Array of IDs
    )
}).required()

export const updateAdsValidation = joi.object({

    adsId: generalFields.id,
    name: joi.string().min(1).max(50).allow(''),
    link: joi.string().min(1).max(200).custom(validateURL),
    image: generalFields.file,
    location: joi.alternatives().try(
        generalFields.idUpdate, // Single ID
        generalFields.idArrayUpdate // Array of IDs
    ),
    isDeleted: joi.boolean(),

}).required()

export const deleteAdsValidation = joi.object({

    adsId: generalFields.id,

}).required()

export const getAllAdsValidation = joi.object({

    location: generalFields.idUpdate
}).required()

export const getOneAdsValidation = joi.object({

    adsId: generalFields.id,
    location: generalFields.idUpdate
}).required()