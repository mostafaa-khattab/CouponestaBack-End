import notificationModel from "../../../../DB/model/Notification.model.js";
import userModel from "../../../../DB/model/User.model.js";
import ApiFeatures from "../../../utils/apiFeature.js";
import { asyncHandler } from "../../../utils/errorHandling.js";
import cron from 'node-cron'

export const getNotificationsToDashboard = asyncHandler(async (req, res, next) => {

    const apiFeature = new ApiFeatures(notificationModel.find({
        isDeleted: false,
        // user: req.user._id
    }), req.query)
        .paginate()
        .filter()
        .sort()
        .search()
        .select()


    const notification = await apiFeature.mongooseQuery

    return res.status(200).json({ message: 'success', notification })

})

export const getSpacialNotificationToDashboard = asyncHandler(async (req, res, next) => {

    const apiFeature = new ApiFeatures(notificationModel.find({
        isDeleted: false,
        user: req.user._id
    }), req.query)
        .paginate()
        .filter()
        .sort()
        .search()
        .select()


    const notification = await apiFeature.mongooseQuery

    return res.status(200).json({ message: 'success', notification })

})

export const getNotifications = asyncHandler(async (req, res, next) => {

    const locale = req.params.locale || 'en' // Get locale from request parameters (e.g., 'en' or 'ar')

    const apiFeature = new ApiFeatures(notificationModel.find({
        isDeleted: false,
        // user: req.user._id
    }).lean(), req.query)
        .paginate()
        .filter()
        .sort()
        .search()
        .select()


    const notification = await apiFeature.mongooseQuery

    notification?.forEach((elm, index) => {

        // Set header and body based on locale
        const header = elm.header ? elm.header[locale] : undefined;
        const body = elm.body ? elm.body[locale] : undefined;

        // Update header and body
        notification[index].header = header;
        notification[index].body = body;
    });

    return res.status(200).json({ message: 'success', notification })

})

export const getSpacialNotification = asyncHandler(async (req, res, next) => {

    const locale = req.params.locale || 'en' // Get locale from request parameters (e.g., 'en' or 'ar')

    const apiFeature = new ApiFeatures(notificationModel.find({
        isDeleted: false,
        user: req.user._id
    }).lean(), req.query)
        .paginate()
        .filter()
        .sort()
        .search()
        .select()


    const notification = await apiFeature.mongooseQuery

    notification?.forEach((elm, index) => {

        // Set header and body based on locale
        const header = elm.header ? elm.header[locale] : undefined;
        const body = elm.body ? elm.body[locale] : undefined;

        // Update header and body
        notification[index].header = header;
        notification[index].body = body;
    });

    return res.status(200).json({ message: 'success', notification })

})


export const createNotification = asyncHandler(async (req, res, next) => {
    // Extract English and Arabic headers and body from request body
    const { en_header, ar_header, en_body, ar_body, user } = req.body;

    // Convert headers to lowercase
    const enHeader = en_header.toLowerCase();
    const arHeader = ar_header.toLowerCase();

    // Ensure user is an array
    let users = Array.isArray(user) ? user : [user];

    // Check each user ID in the array
    for (const userId of users) {
        // Check if the ID exists in the database
        const checkUser = await userModel.findById(userId);
        if (!checkUser) {
            return next(new Error(`Not found this user ID ${userId}`, { status: 404 }));
        }
    }

    // Create notification with both English and Arabic headers and body
    const notification = await notificationModel.create({
        header: {
            en: enHeader,
            ar: arHeader
        },
        body: {
            en: en_body,
            ar: ar_body
        },
        user: users,
        createdBy: req.user._id
    });

    // Update each user with the new notification ID
    for (const userId of users) {
        await userModel.updateOne(
            { _id: userId },
            { $addToSet: { notification: notification._id } },
            { new: true }
        );
    }

    return res.status(201).json({ message: 'success', notification });
});



export const updateNotification = asyncHandler(async (req, res, next) => {
    const { notificationId } = req.params;

    let notification = await notificationModel.findOne({ _id: notificationId });
    if (!notification) {
        return next(new Error(`Invalid notification ID`, { cause: 400 }));
    }

    const { en_header, ar_header, en_body, ar_body, user } = req.body;

    if (en_header || ar_header) {
        let newEnHead = en_header ? en_header.toLowerCase() : notification.header.en;
        let newArHead = ar_header ? ar_header.toLowerCase() : notification.header.ar;

        notification.header.en = newEnHead;
        notification.header.ar = newArHead;
    }

    if (en_body || ar_body) {
        let newEnBody = en_body ? en_body.toLowerCase() : notification.body.en;
        let newArBody = ar_body ? ar_body.toLowerCase() : notification.body.ar;

        notification.body.en = newEnBody;
        notification.body.ar = newArBody;
    }

    // Update user if provided
    if (user) {
        const newUsers = Array.isArray(user) ? user : [user];

        for (const userId of newUsers) {
            const checkUser = await userModel.findById(userId);
            if (!checkUser) {
                return res.status(404).json({ error: `Not found this user ID ${userId}` });
            }
        }

        // Check for existing users
        const existingUsers = await userModel.find({ _id: { $in: newUsers } }, '_id').lean();

        if (existingUsers.length !== newUsers.length) {
            const existingIds = existingUsers.map(user => user._id);
            const nonExistingUsers = newUsers.filter(userId => !existingIds.includes(userId));

            return res.status(404).json({ error: `Not found these user IDs: ${nonExistingUsers.join(', ')}` });
        }

        // Update the notification's user field
        await notificationModel.findByIdAndUpdate(notificationId, { $addToSet: { user: { $each: newUsers } } });

        // Update each user with the notification ID if not already present
        for (const userId of newUsers) {
            await userModel.updateOne(
                { _id: userId },
                { $addToSet: { notification: notificationId } },
                { new: true }
            );
        }

        // Update req.body.user with the new user IDs
        req.body.user = newUsers;
    }

    req.body.updatedBy = req.user._id;

    // Perform the update without modifying the user field
    const updatedNotification = await notificationModel.findByIdAndUpdate(notificationId, req.body, { new: true });

    return res.status(201).json({ message: 'Success', notification: updatedNotification });
});


export const deleteNotification = asyncHandler(async (req, res, next) => {
    const { notificationId } = req.params;

    const notification = await notificationModel.findByIdAndDelete(notificationId)

    !notification && next(new Error(`notification not found`, { status: 404 }));
    notification && res.status(202).json({ message: "success", notification })
})

export const getNotificationsDeleted = asyncHandler(async (req, res, next) => {

    const locale = req.params.locale || 'en' // Get locale from request parameters (e.g., 'en' or 'ar')

    let { isDeleted, notificationId } = req.body;

    if (isDeleted && notificationId) {
        // Save updated notification
        let isDel = await notificationModel.findByIdAndUpdate(notificationId, { isDeleted }, { new: true });
    }

    // Find brand matching the selected location or the default location
    const apiFeature = new ApiFeatures(notificationModel.find({
        isDeleted: true,
    }).lean(), req.query)
        .paginate()
        .filter()
        .sort()
        .search()
        .select()


    const notification = await apiFeature.mongooseQuery

    notification?.forEach((elm, index) => {

        // Set header and body based on locale
        const header = elm.header ? elm.header[locale] : undefined;
        const body = elm.body ? elm.body[locale] : undefined;

        // Update header and body
        notification[index].header = header;
        notification[index].body = body;
    });


    return res.status(200).json({ message: 'success', notification })
})

// Schedule a job to delete notificationModel older than 60 days
cron.schedule('0 0 0 1 */2 *', async () => {
    try {

        const sixtyDaysAgo = new Date(Date.now() - 60 * 24 * 60 * 60 * 1000);

        let del = await notificationModel.deleteMany({ isDeleted: true, updatedAt: { $lt: sixtyDaysAgo } });// Schedule a job to delete categories older than 60 days

    } catch (error) {
        // new Error('Error deleting');
    }

});

