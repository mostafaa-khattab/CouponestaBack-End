import { Router } from "express";
import * as userController from "./controller/user.js";
import { auth, roles } from "../../middleware/auth.js";
import { validation } from "../../middleware/validation.js";
import * as validators from "./user.validation.js";
import { fileUpload, fileValidation } from "../../utils/multer.js";
const router = Router()


router.get('/favorite/toDashboard',
    auth([roles.User, roles.Admin]),
    userController.getAllUserFavoriteToDashboard)

router.get('/follow/toDashboard',
    auth([roles.User, roles.Admin]),
    userController.getAllUserFollowToDashboard)

router.get('/favorite/:locale?',
    auth([roles.User, roles.Admin]),
    userController.getAllUserFavorite)


router.get('/follow/:locale?',
    auth([roles.User, roles.Admin]),
    userController.getAllUserFollow)

router.get('/',
    auth([roles.Admin]),
    userController.getAllUsers)

router.get('/loggedUser/data',
    auth([roles.Admin, roles.User, roles.Employee]),
    // validation(validators.getLoggedUserValidation),
    userController.getLoggedUser)

router.post('/',
    auth([roles.Admin]),
    fileUpload('user', fileValidation.image).single('image'),
    validation(validators.createUserValidation),
    userController.addUser)

router.put('/admin/:userId',
    auth([roles.Admin]),
    fileUpload('user', fileValidation.image).single('image'),
    validation(validators.AdminUpdateUserValidation),
    userController.updateUser)

router.put('/:userId',
    auth([roles.Admin, roles.User]),
    fileUpload('user', fileValidation.image).single('image'),
    validation(validators.updateUserValidation),
    userController.updateUser)

router.delete('/softDelete/:userId',
    auth([roles.Admin, roles.User]),
    validation(validators.softDeleteUserValidation),
    userController.softDeleteUser)

router.delete('/logout/:userId',
    auth([roles.Admin, roles.User]),
    validation(validators.softDeleteUserValidation),
    userController.logoutUser)

router.delete('/:userId',
    auth([roles.Admin, roles.User, roles.Employee]),
    validation(validators.deleteUserValidation),
    userController.deleteUser)

router.put('/trash/:locale?',
    auth([roles.Admin]),
    userController.getUsersDeleted)


export default router