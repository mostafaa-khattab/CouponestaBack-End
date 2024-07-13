import joi from "joi";
import { generalFields } from "../../middleware/validation.js";

export const createLocationValidation = joi.object({

    name: joi.string().min(1).max(25).required(),
    locationCode: joi.string().min(0).max(25).required(),
    image: generalFields.file
}).required()

export const updateLocationValidation = joi.object({

    locationId: generalFields.id,
    name: joi.string().min(1).max(25),
    locationCode: joi.string().min(0).max(25),
    image: generalFields.file,
    isDeleted: joi.boolean(),
}).required()

export const deleteLocationValidation = joi.object({

    locationId: generalFields.id,

}).required()

export const getOneLocationValidation = joi.object({

    locationId: generalFields.id,
}).required()