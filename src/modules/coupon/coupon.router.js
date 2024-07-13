import { validation } from '../../middleware/validation.js';
import * as validators from './coupon.validation.js';
import * as couponController from './controller/coupon.js';
import { Router } from "express";
import { auth, roles } from '../../middleware/auth.js';
const router = Router()

// get all coupons
router.get('/toDashboard',
    couponController.getAllCouponsToDashboard)

router.get('/:locale?',
    // validation(validators.getAllCouponValidation),
    couponController.getCoupons)

router.get('/all/favorite/data/:locale?',
    // validation(validators.getAllCouponValidation),
    couponController.getFavoriteCoupons)


router.post('/',
    auth([roles.Admin]),
    validation(validators.createCouponValidation),
    couponController.createCoupon)

router.put('/:couponId',
    auth([roles.Admin]),
    validation(validators.updateCouponValidation),
    couponController.updateCoupon)

router.put('/like/:couponId',
    auth([roles.User, roles.Admin]),
    validation(validators.updateCouponLikeValidation),
    couponController.updateCouponLike)


router.put('/trash/:locale?',
    auth([roles.Admin]),
    couponController.getCouponsDeleted)

router.delete('/:couponId',
    auth([roles.Admin]),
    validation(validators.deleteCouponValidation),
    couponController.deleteCoupon)

router.patch('/:couponId/favorite/add',
    auth([roles.User, roles.Admin]),
    validation(validators.favoriteValidation),
    couponController.addFavorite)

router.patch('/:couponId/favorite/remove',
    auth([roles.User, roles.Admin]),
    validation(validators.favoriteValidation),
    couponController.deleteFromFavorite)

router.patch('/:couponId/like/add',
    auth([roles.User, roles.Admin]),
    validation(validators.favoriteValidation),
    couponController.addLike)

router.patch('/:couponId/like/remove',
    auth([roles.User, roles.Admin]),
    validation(validators.favoriteValidation),
    couponController.removeLike)

router.patch('/:couponId/addUseCount',
    couponController.addUseCount)

// get all coupons
router.get('/allCount/database',
    couponController.getAllData)


export default router