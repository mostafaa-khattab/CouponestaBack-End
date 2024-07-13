import { asyncHandler } from "../../../utils/errorHandling.js";
import couponModel from "../../../../DB/model/Coupon.model.js";
import locationModel from "../../../../DB/model/Location.model.js";
import categoryModel from "../../../../DB/model/Category.model.js";
import brandModel from "../../../../DB/model/Brand.model.js";
import QRCode from "qrcode"
import userModel from "../../../../DB/model/User.model.js";
import ApiFeatures from "../../../utils/apiFeature.js";
import notificationModel from "../../../../DB/model/Notification.model.js";
import cron from 'node-cron'
import adsModel from "../../../../DB/model/Ads.model.js";


export const getAllCouponsToDashboard = asyncHandler(async (req, res, next) => {

    // Find coupon matching the selected location or the default location
    const apiFeature = new ApiFeatures(couponModel.find({
        isDeleted: false,
    }), req.query)
        .paginate()
        .filter()
        .sort()
        .search()
        .select()


    const coupon = await apiFeature.mongooseQuery

    return res.status(200).json({ message: 'success', coupon })
})


export const getCoupons = asyncHandler(async (req, res, next) => {
    try {
        const locale = req.params.locale || 'en'; // Get locale from request parameters (e.g., 'en' or 'ar')

        // Find coupons matching the selected location or the default location
        const apiFeature = new ApiFeatures(couponModel.find({
            isDeleted: false,
        }).lean(), req.query)
            .paginate()
            .filter()
            .sort()
            .search()
            .select();

        const coupons = await apiFeature.mongooseQuery;

        coupons.forEach((elm, index) => {
            // Set status and description based on locale
            const status = elm.status ? elm.status[locale] : undefined;
            const description = elm.description ? elm.description[locale] : undefined;

            // Update status and description
            coupons[index].status = status;
            coupons[index].description = description;
        });

        const couponCount = coupons.length; // Get count of coupons from the array length

        return res.status(200).json({ message: 'success', couponCount, coupons });

    } catch (error) {
        return res.status(500).json({ message: 'Internal server error' });
    }
});


export const getFavoriteCoupons = asyncHandler(async (req, res, next) => {
    try {
        const locale = req.params.locale || 'en'; // Get locale from request parameters (e.g., 'en' or 'ar')

        // Find all users and populate their favorite brands
        const users = await userModel.find({}).populate('favorite');

        // Get favorite brands from the first user, assuming it's the same for all users
        const favoriteCoupons = users[0]?.favorite || [];

        // Populate favorite brands with localized name and description
        const localizedCoupons = favoriteCoupons.map(coupon => ({
            ...coupon.toObject(), // Convert Mongoose object to plain object
            description: coupon.description[locale] || coupon.description['en'],
            status: coupon.status[locale] || coupon.status['en'],
        }));

        // Update image URLs if available
        const updatedCoupons = localizedCoupons.map(coupon => {
            if (coupon.image) {
                coupon.image = "https://saraha-seej.onrender.com/" + coupon.image;
            }
            return coupon;
        });

        // Count the number of coupons
        const couponCount = updatedCoupons.length;

        return res.status(200).json({ message: 'success', couponCount, coupons: updatedCoupons });

    } catch (error) {
        console.error("Error:", error);
        return res.status(500).json({ message: 'Internal server error' });
    }
});






export const createCoupon = asyncHandler(async (req, res, next) => {
    if ((new Date(req.body.expire)) < (new Date())) return res.status(400).json({ message: "Invalid Date" });

    // Extract English and Arabic descriptions and statuses from request body
    let { brand, category, location, en_description, ar_description, en_status, ar_status } = req.body;

    if (req.body.code) {
        req.body.code = req.body.code.toLowerCase();
        req.body.qrCode = await QRCode.toDataURL(req.body.code);

        const checkCoupon = await couponModel.findOne({ code: req.body.code, isDeleted: false });
        if (checkCoupon) {
            return next(new Error(`Duplicate coupon code ${req.body.code}`, { cause: 409 }));
        }
    }

    // Check each category ID in the array
    if (!Array.isArray(category)) {
        category = [category];
    }

    for (const categoryId of category) {
        const checkCategory = await categoryModel.findById(categoryId);
        if (!checkCategory) {
            return next(new Error(`Not found this category ID ${categoryId}`, { status: 404 }));
        }
    }

    // Check each location ID in the array
    if (!Array.isArray(location)) {
        location = [location];
    }

    for (const locationId of location) {
        const checkLocation = await locationModel.findById(locationId);
        if (!checkLocation) {
            return next(new Error(`Not found this location ID ${locationId}`, { status: 404 }));
        }
    }

    // Check each brand ID in the array
    if (!Array.isArray(brand)) {
        brand = [brand];
    }

    for (const brandId of brand) {
        const checkBrand = await brandModel.findById(brandId);
        if (!checkBrand) {
            return next(new Error(`Not found this brand ID ${brandId}`, { status: 404 }));
        }
    }

    let link = req.body.link || "";

    const coupon = await couponModel.create({
        ...req.body,
        description: {
            en: en_description,
            ar: ar_description
        },
        status: {
            en: en_status,
            ar: ar_status
        },
        link,
        createdBy: req.user._id,
    });

    const usersFollowingBrand = await userModel.find({ follow: { $in: brand } });

    // Send notifications to users who follow the brand
    for (const user of usersFollowingBrand) {
        const notification = await notificationModel.create({
            header: {
                en: req.body.code || "use discount",
                ar: req.body.code || "استخدم الخصم"
            },
            body: {
                en: coupon.description.en || "Includes all products",
                ar: coupon.description.ar || "يشمل جميع المنتجات"
            },
            user: [user._id],
            createdBy: req.user._id
        });

        // Add notification to the user's notification list
        await userModel.updateOne(
            { _id: user._id },
            { $addToSet: { notification: notification._id } },
            { new: true }
        );
    }

    return res.status(201).json({ message: 'success', coupon });
});

export const updateCoupon = asyncHandler(async (req, res, next) => {
    const { couponId } = req.params;
    let coupon = await couponModel.findOne({ _id: couponId });
    if (!coupon) {
        return next(new Error(`In-valid coupon ID`, { cause: 400 }));
    }

    if ((new Date(req.body.expire)) < (new Date())) return res.status(400).json({ message: "In-valid Date" });


    // Create a new object to hold non-empty values
    let updatedData = {};

    // Loop through each key in req.body
    for (const key of Object.keys(req.body)) {
        // Check if the value is not an empty string
        if (req.body[key] !== "") {
            // If it's not empty, add it to the updatedData object
            updatedData[key] = req.body[key];
        }
    }


    // Check code existence and manipulate it if necessary
    if (updatedData.code && updatedData.code !== "") {
        updatedData.code = updatedData.code.toLowerCase();
        updatedData.qrCode = await QRCode.toDataURL(updatedData.code);

        if (updatedData.code == coupon.code) {
            return next(new Error(`Cannot update coupon with the same old code`, { cause: 409 }));
        }

        if (await couponModel.findOne({ code: updatedData.code })) {
            return next(new Error(`Duplicate coupon code ${updatedData.code}`, { cause: 409 }));
        }
    }

    // Update description if provided
    if (updatedData.ar_description || updatedData.en_description) {
        let newEnDesc = updatedData.en_description ? updatedData.en_description.toLowerCase() : coupon.description.en;
        let newArDesc = updatedData.ar_description ? updatedData.ar_description.toLowerCase() : coupon.description.ar;

        updatedData.description = {
            en: newEnDesc,
            ar: newArDesc
        };
    }

    // Update status if provided
    if (updatedData.ar_status || updatedData.en_status) {
        let newEnDesc = updatedData.en_status ? updatedData.en_status.toLowerCase() : coupon.status.en;
        let newArDesc = updatedData.ar_status ? updatedData.ar_status.toLowerCase() : coupon.status.ar;

        updatedData.status = {
            en: newEnDesc,
            ar: newArDesc
        };
    }

    // Update category if provided
    if (updatedData.category) {
        const newCategory = Array.isArray(updatedData.category) ? updatedData.category : [updatedData.category];

        // Check and validate category IDs
        for (const categoryId of newCategory) {
            const checkCategory = await categoryModel.findById(categoryId);
            if (!checkCategory) {
                return res.status(404).json({ error: `Not found this category ID ${categoryId}` });
            }
        }

        // Add new category IDs to the coupon
        updatedData.category = newCategory;
    }

    // Update brand if provided
    if (updatedData.brand) {
        const newBrand = Array.isArray(updatedData.brand) ? updatedData.brand : [updatedData.brand];

        // Check and validate brand IDs
        for (const brandId of newBrand) {
            const checkBrand = await brandModel.findById(brandId);
            if (!checkBrand) {
                return res.status(404).json({ error: `Not found this brand ID ${brandId}` });
            }
        }

        // Add new brand IDs to the coupon
        updatedData.brand = newBrand;
    }

    // Update location if provided
    if (updatedData.location) {
        const newLocation = Array.isArray(updatedData.location) ? updatedData.location : [updatedData.location];

        // Check and validate location IDs
        for (const locationId of newLocation) {
            const checkLocation = await locationModel.findById(locationId);
            if (!checkLocation) {
                return res.status(404).json({ error: `Not found this location ID ${locationId}` });
            }
        }

        // Add new location IDs to the coupon
        updatedData.location = newLocation;
    }

    // Set the updatedBy field
    updatedData.updatedBy = req.user._id;

    // Update coupon with updatedData and return the updated coupon
    coupon = await couponModel.findByIdAndUpdate(couponId, updatedData, { new: true });


    return res.status(201).json({ message: 'success', coupon });
});


export const updateCouponLike = asyncHandler(async (req, res, next) => {

    const { couponId } = req.params;
    let coupon = await couponModel.findOne({ _id: couponId, isDeleted: false })
    if (!coupon) {
        return next(new Error(`In-valid coupon ID`, { cause: 400 }))
    }

    let { usedCount, likeCount, dislikeCount } = req.body;

    req.body.updatedBy = req.user._id

    coupon = await coupon.save();

    coupon = await couponModel.findByIdAndUpdate(couponId,
        {
            usedCount,
            likeCount,
            dislikeCount
        },
        { new: true })

    return res.status(201).json({
        message: 'success', coupon: {
            usedCount,
            likeCount,
            dislikeCount,
            updatedBy: req.user._id
        }
    })
})

export const deleteCoupon = asyncHandler(async (req, res, next) => {
    const { couponId } = req.params;

    const coupon = await couponModel.findByIdAndDelete(couponId)

    !coupon && next(new Error(`coupon not found`, { status: 404 }));
    coupon && res.status(202).json({ message: " success", coupon })
})

export const getCouponsDeleted = asyncHandler(async (req, res, next) => {

    const locale = req.params.locale || 'en' // Get locale from request parameters (e.g., 'en' or 'ar')

    let { isDeleted, couponId } = req.body;

    if (isDeleted && couponId) {
        // Save updated coupon
        let isDel = await couponModel.findByIdAndUpdate(couponId, { isDeleted }, { new: true });
    }

    // Find brand matching the selected location or the default location
    const apiFeature = new ApiFeatures(couponModel.find({
        isDeleted: true,
    }).lean(), req.query)
        .paginate()
        .filter()
        .sort()
        .search()
        .select()


    const coupon = await apiFeature.mongooseQuery

    coupon?.forEach((elm, index) => {

        // Set status and description based on locale
        const status = elm.status ? elm.status[locale] : undefined;
        const description = elm.description ? elm.description[locale] : undefined;

        // Update status and description
        coupon[index].status = status;
        coupon[index].description = description;
    });

    return res.status(200).json({ message: 'success', coupon })
})

// Schedule a job to delete couponModel older than 60 days
cron.schedule('0 0 0 1 */2 *', async () => {
    try {

        const sixtyDaysAgo = new Date(Date.now() - 60 * 24 * 60 * 60 * 1000);

        let del = await couponModel.deleteMany({ isDeleted: true, updatedAt: { $lt: sixtyDaysAgo } });// Schedule a job to delete categories older than 60 days

    } catch (error) {
        // new Error('Error deleting');
    }

});




// // is all Date from Database
// export const getAllData = asyncHandler(async (req, res, next) => {
//     // Get the count of all coupons

//     const couponCount = await couponModel.countDocuments();
//     const categoryCount = await categoryModel.countDocuments();
//     const brandCount = await brandModel.countDocuments();
//     const userCount = await userModel.countDocuments();
//     const adsCount = await adsModel.countDocuments();
//     const locationCount = await locationModel.countDocuments();
//     const notificationCount = await notificationModel.countDocuments();

//     return res.status(200).json({
//         message: 'success',
//         couponCount,
//         categoryCount,
//         brandCount,
//         userCount,
//         adsCount,
//         locationCount,
//         notificationCount
//     });
// });




export let addFavorite = asyncHandler(async (req, res, next) => {
    let { couponId } = req.params;

    // Check if the coupon exists and is not deleted
    let coupon = await couponModel.findOne({ _id: couponId, isDeleted: false });
    if (!coupon) {
        return next(new Error('Invalid coupon ID', { cause: 400 }));
    }

    // Update the user's favorite list
    await userModel.updateOne({ _id: req.user._id }, { $addToSet: { favorite: couponId } }, { new: true });

    // // Update the coupon's isFavorite field
    // coupon.isFavorite = true;
    // await coupon.save();

    // Update the user's favorite list
    coupon = await couponModel.findByIdAndUpdate(couponId, { $addToSet: { userFavorite: req.user._id } }, { new: true });

    return res.status(201).json({ message: 'success', coupon });
});

export let deleteFromFavorite = asyncHandler(async (req, res, next) => {
    let { couponId } = req.params;

    // Check if the coupon exists and is not deleted
    let coupon = await couponModel.findOne({ _id: couponId, isDeleted: false });
    if (!coupon) {
        return next(new Error('Invalid coupon ID', { cause: 400 }));
    }

    // Update the user's favorite list
    await userModel.updateOne({ _id: req.user._id }, { $pull: { favorite: couponId } });

    // // Check if the coupon is still a favorite for any user
    // let isFavoriteForAnyUser = await userModel.exists({ favorite: couponId });
    // if (!isFavoriteForAnyUser) {
    //     coupon.isFavorite = false;
    //     await coupon.save();
    // }

    coupon = await couponModel.findByIdAndUpdate(couponId, { $pull: { userFavorite: req.user._id } }, { new: true });

    return res.status(201).json({ message: 'success', coupon });
});


export const getAllData = asyncHandler(async (req, res, next) => {
    // Get the count of all coupons
    const couponCount = await couponModel.countDocuments();
    const categoryCount = await categoryModel.countDocuments();
    const brandCount = await brandModel.countDocuments();
    const userCount = await userModel.countDocuments();
    const adsCount = await adsModel.countDocuments();
    const locationCount = await locationModel.countDocuments();
    const notificationCount = await notificationModel.countDocuments();

    const dataArray = [
        { name: 'couponCount', count: couponCount },
        { name: 'categoryCount', count: categoryCount },
        { name: 'brandCount', count: brandCount },
        { name: 'userCount', count: userCount },
        { name: 'adsCount', count: adsCount },
        { name: 'locationCount', count: locationCount },
        { name: 'notificationCount', count: notificationCount }
    ];

    return res.status(200).json({
        message: 'success',
        data: dataArray
    });
});

export let addLike = asyncHandler(async (req, res, next) => {
    let { couponId } = req.params;

    // Check if the coupon exists and is not deleted
    let coupon = await couponModel.findOne({ _id: couponId, isDeleted: false });
    if (!coupon) {
        return next(new Error('Invalid coupon ID', { cause: 400 }));
    }

    // Check if the user has already liked the coupon
    const userHasLiked = coupon.userLiked.includes(req.user._id);

    if (!userHasLiked) {

        const userHasDisliked = coupon.userDisLiked.includes(req.user._id);

        // Update the coupon's userLiked list and increment the likeCount
        coupon = await couponModel.findByIdAndUpdate(
            couponId,
            {
                $addToSet: { userLiked: req.user._id },
                $pull: { userDisLiked: req.user._id },
                $inc: {
                    likeCount: 1,
                    dislikeCount: userHasDisliked ? -1 : 0
                }
            },
            { new: true }
        );
    }

    return res.status(201).json({ message: 'success', coupon });
});


export let removeLike = asyncHandler(async (req, res, next) => {
    let { couponId } = req.params;

    // Check if the coupon exists and is not deleted
    let coupon = await couponModel.findOne({ _id: couponId, isDeleted: false });
    if (!coupon) {
        return next(new Error('Invalid coupon ID', { cause: 400 }));
    }

    // Check if the user has already disliked the coupon
    const userHasDisliked = coupon.userDisLiked.includes(req.user._id);

    if (!userHasDisliked) {

        const userHasLiked = coupon.userLiked.includes(req.user._id);


        // Update the coupon's userLiked list and increment the likeCount
        coupon = await couponModel.findByIdAndUpdate(
            couponId,
            {
                $pull: { userLiked: req.user._id },
                $addToSet: { userDisLiked: req.user._id },
                $inc: {
                    dislikeCount: 1,
                    likeCount: userHasLiked ? -1 : 0
                }
            },
            { new: true }
        );
    }

    return res.status(201).json({ message: 'success', coupon });
});




export let addUseCount = asyncHandler(async (req, res, next) => {
    let { couponId } = req.params;

    // Check if the coupon exists and is not deleted
    let coupon = await couponModel.findOne({ _id: couponId, isDeleted: false });
    if (!coupon) {
        return next(new Error('Invalid coupon ID', { cause: 400 }));
    }

    // Update the coupon's userLiked list and increment the likeCount
    coupon = await couponModel.findByIdAndUpdate(
        couponId,
        {
            $inc: { usedCount: 1 }
        },
        { new: true }
    );

    return res.status(201).json({ message: 'success', coupon });
});