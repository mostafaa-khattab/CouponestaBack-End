import { validation } from '../../middleware/validation.js';
import { fileUpload, fileValidation } from '../../utils/multer.js';
import * as validators from './location.validation.js';
import * as locationController from './controller/Location.js';
import { Router } from "express";
import { auth, roles } from '../../middleware/auth.js';
const router = Router()


router.get('/',
    locationController.getLocations)


router.post('/',
    auth([roles.Admin]),
    fileUpload('location', fileValidation.image).single('image'),
    validation(validators.createLocationValidation),
    locationController.createLocation)

router.put('/:locationId',
    auth([roles.Admin]),
    fileUpload('location', fileValidation.image).single('image'),
    validation(validators.updateLocationValidation),
    locationController.updateLocation)

router.put('/trash/:locale?',
    auth([roles.Admin]),
    locationController.getLocationsDeleted)

router.delete('/:locationId',
    auth([roles.Admin]),
    validation(validators.deleteLocationValidation),
    locationController.deleteLocation)


export default router