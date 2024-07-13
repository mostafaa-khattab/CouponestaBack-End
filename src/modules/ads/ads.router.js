import { auth, roles } from '../../middleware/auth.js';
import { validation } from '../../middleware/validation.js';
import { fileUpload, fileValidation } from '../../utils/multer.js';
import * as validators from './ads.validation.js';
import * as adsController from './controller/ads.js';
import { Router } from "express";
const router = Router()

router.get('/',
    adsController.getAds)


router.post('/',
    auth([roles.Admin]),
    fileUpload('ads', fileValidation.image).single('image'),
    validation(validators.createAdsValidation),
    adsController.createAds)

router.put('/:adsId',
    auth([roles.Admin]),
    fileUpload('ads', fileValidation.image).single('image'),
    validation(validators.updateAdsValidation),
    adsController.updateAds)

router.put('/trash/softDelete',
    auth([roles.Admin]),
    adsController.getAdsDeleted)

router.delete('/:adsId',
    auth([roles.Admin]),
    validation(validators.deleteAdsValidation),
    adsController.deleteAds)


export default router