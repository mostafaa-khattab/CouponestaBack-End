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

export const createBrandValidation = joi.object({

    en_name: joi.string().trim().min(1).max(255).required(),
    ar_name: joi.string().trim().min(1).max(255).required(),
    en_description: joi.string().trim().allow('').max(1000), // Optional
    ar_description: joi.string().trim().allow('').max(1000),
    link: joi.string().min(1).max(200).required().custom(validateURL),
    image: generalFields.file,
    category: joi.alternatives().try(
        generalFields.id.required(), // Single ID
        generalFields.idArray.required() // Array of IDs
    ).required(),
    location: joi.alternatives().try(
        generalFields.id.required(), // Single ID
        generalFields.idArray.required() // Array of IDs
    ).required(),
}).required()

export const updateBrandValidation = joi.object({

    brandId: generalFields.id,
    en_name: joi.string().trim().allow('').min(1).max(255),
    ar_name: joi.string().trim().allow('').min(1).max(255),
    en_description: joi.string().trim().allow('').max(1000), // Optional
    ar_description: joi.string().trim().allow('').max(1000),
    link: joi.string().min(1).max(200).allow('').custom(validateURL),
    image: generalFields.file,
    category: joi.alternatives().try(
        generalFields.idUpdate, // Single ID
        generalFields.idArrayUpdate // Array of IDs
    ),
    location: joi.alternatives().try(
        generalFields.idUpdate, // Single ID
        generalFields.idArrayUpdate // Array of IDs
    ),
    isDeleted: joi.boolean(),

}).required()


export const deleteBrandsValidation = joi.object({

    brandId: generalFields.id,

}).required()


export const getAllBrandValidation = joi.object({

    location: generalFields.idUpdate,
    locale: joi.string().valid('en', 'ar').default('en'),

}).required()

export const getOneBrandValidation = joi.object({

    brandId: generalFields.id,
    location: generalFields.idUpdate,
    locale: joi.string().valid('en', 'ar').default('en')

}).required()

export const followValidation = joi.object({

    brandId: joi.string().hex().length(24).required().trim(),
}).required()