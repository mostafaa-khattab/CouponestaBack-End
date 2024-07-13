import joi from 'joi'
import { generalFields } from '../../middleware/validation.js'


export const signUpValidationEmail = joi.object({
    fullName: joi.string(),
    email: generalFields.email,
    password: generalFields.password,
}).required()

export const signUpValidationPhone = joi.object({
    fullName: joi.string(),
    password: generalFields.password,
    phoneNumber: joi.string(),
    countryCode: joi.string(),
}).required()

export const loginEmailValidation = joi.object({
    email: generalFields.email,
    password: generalFields.password,
}).required()

export const loginPhoneValidation = joi.object({
    phoneNumber: joi.string(),
    countryCode: joi.string(),
    password: generalFields.password,
}).required()

export const confirmAccountValidation = joi.object({

    token: generalFields.token,
}).required()

export const sendEmailToChangePasswordValidation = joi.object({
    email: generalFields.email,
}).required()

export const forgetPasswordEmailValidation = joi.object({
    email: generalFields.email,
    password: generalFields.password,
    cPassword: joi.string().valid(joi.ref('password')).messages({
        'any.only': 'Repeat confirm password must match new password',
    }),
}).required()

export const forgetPasswordPhoneValidation = joi.object({
    phoneNumber: joi.string(),
    countryCode: joi.string(),
    password: generalFields.password,
    cPassword: joi.string().valid(joi.ref('password')).messages({
        'any.only': 'Repeat confirm password must match new password',
    }),
}).required()