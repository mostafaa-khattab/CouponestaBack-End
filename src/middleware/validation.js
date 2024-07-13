import joi from 'joi'
import { Types } from 'mongoose'

const validateObjectId = (value, helper) => {

    return Types.ObjectId.isValid(value) ? true : helper.message('In-valid objectId')
}

export const generalFields = {

    email: joi.string().email().required(),
    password: joi.string().required(),
    cPassword: joi.string().required(),
    id: joi.string().custom(validateObjectId).required(),
    idUpdate: joi.string().custom(validateObjectId),
    idArray: joi.array().items(joi.string().custom(validateObjectId).required()).min(1).required(),
    idArrayUpdate: joi.array().items(joi.string().custom(validateObjectId).required()).min(1),
    token: joi.string().pattern(/^[A-Za-z0-9-_]*\.[A-Za-z0-9-_]*\.[A-Za-z0-9-_]*$/).required(),
    file: joi.any().allow(' ')
    
}

export const validation = (schema) => {
    return (req, res, next) => {

        let inputsData = { ...req.body, ...req.params, ...req.query }

        const validationResult = schema.validate(inputsData, { abortEarly: false })

        if (validationResult.error) {
            return res.json({ message: `validation error:`, validationResult: validationResult.error.details })
        }

        return next()
    }
}