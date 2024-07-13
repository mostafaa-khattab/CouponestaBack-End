import { auth, roles } from '../../middleware/auth.js';
import { validation } from '../../middleware/validation.js';
import { fileUpload, fileValidation } from '../../utils/multer.js';
import * as validators from './category.validation.js';
import * as categoryController from './controller/Category.js';
import { Router } from "express";
const router = Router()

// get all categories
router.get('/toDashboard',
    categoryController.getAllCategoriesToDashboard)

// get all categories
router.get('/:locale?',
    // validation(validators.getAllCategoryValidation),
    categoryController.getCategories)


router.post('/',
    auth([roles.Admin]),
    fileUpload('category', fileValidation.image).single('image'),
    validation(validators.createCategoryValidation),
    categoryController.createCategory)


router.put('/:categoryId',
    auth([roles.Admin]),
    fileUpload('category', fileValidation.image).single('image'),
    validation(validators.updateCategoryValidation),
    categoryController.updateCategory)


router.put('/trash/:locale?',
    auth([roles.Admin]),
    categoryController.getCategoriesDeleted)

router.delete('/:categoryId',
    auth([roles.Admin]),
    validation(validators.deleteCategoryValidation),
    categoryController.deleteCategory)

// router.get('/:locale?/:categoryId',
//     validation(validators.getOneCategoryValidation),
//     categoryController.getOneCategory)

export default router