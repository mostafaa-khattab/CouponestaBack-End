import { auth, roles } from '../../middleware/auth.js';
import { validation } from '../../middleware/validation.js';
import { fileUpload, fileValidation } from '../../utils/multer.js';
import * as validators from './brand.validation.js';
import * as brandController from './controller/brand.js';
import { Router } from "express";
const router = Router()

router.get('/toDashboard',
    brandController.getAllBrandsToDashboard)

router.get('/:locale?',
    brandController.getBrands)

router.get('/all/favorite/data/:locale?',
    brandController.getFovouriteBrands)


router.post('/',
    auth([roles.Admin]),
    fileUpload('brand', fileValidation.image).single('image'),
    validation(validators.createBrandValidation),
    brandController.createBrand)

router.put('/:brandId',
    auth([roles.Admin]),
    fileUpload('brand', fileValidation.image).single('image'),
    validation(validators.updateBrandValidation),
    brandController.updateBrand)

router.put('/most/:brandId',
    brandController.updateBrandMost)


router.put('/trash/:locale?',
    auth([roles.Admin]),
    brandController.getBrandsDeleted)

router.delete('/:brandId',
    auth([roles.Admin]),
    validation(validators.deleteBrandsValidation),
    brandController.deleteBrand)


router.patch('/:brandId/follow/add',
    auth([roles.User, roles.Admin, roles.Employee]),
    validation(validators.followValidation),
    brandController.addFollow)

router.patch('/:brandId/follow/remove',
    auth([roles.User, roles.Admin]),
    validation(validators.followValidation),
    brandController.deleteFromFollow)

export default router