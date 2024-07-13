import joi from 'joi'
import { generalFields } from '../../middleware/validation.js'

// export const getLoggedUserValidation = joi.object({

//     userId: generalFields.id
    
// }).required()

export const createUserValidation = joi.object({
    fullName: joi.string(),
    email: joi.string().email().allow(''),
    password: joi.string(),
    role: joi.string().valid('User', 'Admin', 'Employee').default('User'),
    phoneNumber: joi.string().allow(''),
    countryCode: joi.string().allow('')

}).required()

export const AdminUpdateUserValidation = joi.object({

    userId: generalFields.id,
    fullName: joi.string().allow(''),
    email: joi.string().email().allow(''),
    password: joi.string().allow(''),
    role: joi.string().valid('User', 'Admin', 'Employee').default('User'),
    phoneNumber: joi.string().allow(''),
    countryCode: joi.string().allow(''),
    confirmAccount: joi.boolean(),
    isDeleted: joi.boolean()

}).required()

export const updateUserValidation = joi.object({

    userId: generalFields.id,
    fullName: joi.string(),
    email: joi.string().email(),
    password: joi.string(),
    phoneNumber: joi.string(),
    countryCode: joi.string(),
    isDeleted: joi.boolean(),

}).required()

export const softDeleteUserValidation = joi.object({

    userId: generalFields.id,
}).required()

export const deleteUserValidation = joi.object({

    userId: generalFields.id,
}).required()