import joi from "joi";
import { generalFields } from "../../middleware/validation.js";

export const createNotificationValidation = joi.object({

    en_header: joi.string().trim().min(1).max(50000).required(),
    ar_header: joi.string().trim().min(1).max(50000).required(),
    en_body: joi.string().trim().min(1).max(1000000).required(),
    ar_body: joi.string().trim().min(1).max(1000000).required(),
    user: joi.alternatives().try(
        generalFields.id.required(), // Single ID
        generalFields.idArray.required() // Array of IDs
    ).required(),
}).required()


export const updateNotificationValidation = joi.object({

    notificationId: generalFields.id,
    en_header: joi.string().trim().min(1).max(50000),
    ar_header: joi.string().trim().min(1).max(50000),
    en_body: joi.string().trim().min(1).max(1000000),
    ar_body: joi.string().trim().min(1).max(1000000),
    user: joi.array().min(0).items(joi.string().min(5).label("item").optional()),
    isDeleted: joi.boolean(),

}).required()

export const deleteNotificationValidation = joi.object({

    notificationId: generalFields.id,

}).required()
