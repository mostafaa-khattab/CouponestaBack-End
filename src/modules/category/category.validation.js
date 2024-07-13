import joi from "joi";
import { generalFields } from "../../middleware/validation.js";

export const createCategoryValidation = joi.object({
    en_name: joi.string().trim().min(1).max(255).required(),
    ar_name: joi.string().trim().min(1).max(255).required(),
    en_description: joi.string().trim().allow('').max(1000), // Optional
    ar_description: joi.string().trim().allow('').max(1000),
    image: generalFields.file,
    location: joi.alternatives().try(
        generalFields.id.required(), // Single ID
        generalFields.idArray.required() // Array of IDs
    ).required(),
    icon: joi.string().required().allow(''),
    color: joi.string().allow('').required(),
}).required()

export const updateCategoryValidation = joi.object({

    categoryId: generalFields.id,
    en_name: joi.string().trim().allow('').min(1).max(255),
    ar_name: joi.string().trim().allow('').min(1).max(255),
    en_description: joi.string().trim().allow('').max(1000), // Optional
    ar_description: joi.string().trim().allow('').max(1000),
    image: generalFields.file,
    location: joi.alternatives().try(
        generalFields.idUpdate, // Single ID
        generalFields.idArrayUpdate // Array of IDs
    ),
    icon: joi.string().allow(''),
    color: joi.string().allow(''),
    isDeleted: joi.boolean(),

}).required()


export const deleteCategoryValidation = joi.object({

    categoryId: generalFields.id,

}).required()

export const getAllCategoryValidation = joi.object({

    location: generalFields.idUpdate,
    locale: joi.string().valid('en', 'ar')

}).required()
