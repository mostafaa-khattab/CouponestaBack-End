import { Router } from "express";
import { validation } from "../../middleware/validation.js";
import * as validators from './notification.validation.js';
import { auth, roles } from "../../middleware/auth.js";
import * as notificationController from "./controller/notification.js";

const router = Router()


router.get('/all/toDashboard',
    auth([roles.Admin]),
    notificationController.getNotificationsToDashboard)

router.get('/toDashboard',
    auth([roles.Admin, roles.User]),
    notificationController.getSpacialNotificationToDashboard)

router.get('/all/:locale?',
    auth([roles.Admin]),
    notificationController.getNotifications)

router.get('/:locale?',
    auth([roles.Admin, roles.User]),
    notificationController.getSpacialNotification)

router.post('/',
    auth([roles.Admin]),
    validation(validators.createNotificationValidation),
    notificationController.createNotification)


router.put('/:notificationId',
    auth([roles.Admin]),
    validation(validators.updateNotificationValidation),
    notificationController.updateNotification)

router.put('/trash/:locale?',
    auth([roles.Admin]),
    notificationController.getNotificationsDeleted)

router.delete('/:notificationId',
    auth([roles.Admin, roles.User]),
    validation(validators.deleteNotificationValidation),
    notificationController.deleteNotification)

export default router