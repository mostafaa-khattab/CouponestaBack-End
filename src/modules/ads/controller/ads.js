import adsModel from "../../../../DB/model/Ads.model.js";
import fs from 'fs'
import { asyncHandler } from "../../../utils/errorHandling.js";
import locationModel from "../../../../DB/model/Location.model.js";
import ApiFeatures from "../../../utils/apiFeature.js";
import cron from 'node-cron'


export const getAds = asyncHandler(async (req, res, next) => {

    // Find brand matching the selected location or the default location
    const apiFeature = new ApiFeatures(adsModel.find({
        isDeleted: false,
    }).lean(), req.query)
        .paginate()
        .filter()
        .sort()
        .search()
        .select()


    const ads = await apiFeature.mongooseQuery

    ads?.forEach((elm, index) => {
        // Check if image exists and update its URL
        if (elm.image) {
            ads[index].image = "https://saraha-seej.onrender.com/" + elm.image;
        }

    });


    return res.status(200).json({ message: 'success', ads })
})


export const createAds = asyncHandler(async (req, res, next) => {

    const name = req.body.name.toLowerCase();
    const link = req.body.link
    const image = req?.file?.dest
    let location = req.body.location

    const checkAds = await adsModel.findOne({ name })
    if (checkAds) {
        return next(new Error(`Duplicate Ads name ${name}`, { cause: 409 }))
    }

    // Check each location ID in the array
    if (!Array.isArray(location)) {
        // Convert to array if it's not already
        location = [location];
    }

    for (const locationId of location) {

        // Check if the ID exists in the database
        const checkLocation = await locationModel.findById(locationId);
        if (!checkLocation) {
            return next(new Error(`Not found this location ID ${locationId}`, { status: 404 }));
        }

    }

    const ads = await adsModel.create({
        name,
        image,
        link,
        location,
        createdBy: req.user._id,
    })

    // Append BASE_URL to the image field
    if (ads.image) {
        ads.image = "https://saraha-seej.onrender.com/" + ads.image;
    }

    return res.status(201).json({ message: 'success', ads })

})


export const updateAds = asyncHandler(async (req, res, next) => {

    const { adsId } = req.params;
    let ads = await adsModel.findById(adsId)
    if (!ads) {
        return next(new Error(`In-valid ads ID`, { cause: 400 }))
    }

    // check if ads name is already existing or not
    if (req.body.name) {

        req.body.name = req.body.name.toLowerCase();

        if (req.body.name == ads.name) {
            return next(new Error(`Cannot update ads with the same old name`, { cause: 409 }))
        }

        if (await adsModel.findOne({ name: req.body.name })) {
            return next(new Error(`Duplicate ads name ${req.body.name}`, { cause: 409 }))
        }

        ads.name = req.body.name

    }


    if (ads?.image && req?.file) {
        // Delete the previous image
        // fs.unlinkSync(ads.image, (err) => {
        //     if (err) {
        //         // console.error("Error deleting previous image:", err);
        //     }
        // });

        // Now update ads.image with the new file destination
        req.body.image = req.file.dest;
    }


    let location = req.body.location

    // Update location if provided
    if (location) {
        const newLocations = Array.isArray(location) ? location : [location];

        for (const locationId of newLocations) {
            const checkLocation = await locationModel.findById(locationId);
            if (!checkLocation) {
                return res.status(404).json({ error: `Not found this location ID ${locationId}` });
            }
        }

        // Use $addToSet to add locations without duplication
        await adsModel.findByIdAndUpdate(adsId, { $addToSet: { location: { $each: newLocations } } });

        // Fetch the updated brand
        ads = await adsModel.findById(adsId);
        req.body.location = ads.location;
    }


    req.body.updatedBy = req.user._id

    ads = await adsModel.findByIdAndUpdate(adsId, req.body, { new: true });

    // Append BASE_URL to the image field
    if (ads.image) {
        ads.image = "https://saraha-seej.onrender.com/" + ads.image;
    }

    return res.status(201).json({ message: 'success', ads });

})

export const deleteAds = asyncHandler(async (req, res, next) => {
    const { adsId } = req.params;

    const ads = await adsModel.findByIdAndDelete(adsId)

    !ads && next(new Error(`ads not found`, { status: 404 }));

    if (ads?.image) {
        try {
            fs.unlinkSync(ads?.image);
            // console.log("Image deleted:", document.image);
        } catch (err) {
            // console.error("Error deleting image:", err);
        }
    }

    ads && res.status(202).json({ message: " success", ads })
})


export const getAdsDeleted = asyncHandler(async (req, res, next) => {

    let { isDeleted, adsId } = req.body;

    if (isDeleted && adsId) {
        // Save updated ads
        let isDel = await adsModel.findByIdAndUpdate(adsId, { isDeleted }, { new: true });
    }

    // Find brand matching the selected location or the default location
    const apiFeature = new ApiFeatures(adsModel.find({
        isDeleted: true,
    }).lean(), req.query)
        .paginate()
        .filter()
        .sort()
        .search()
        .select()

    const ads = await apiFeature.mongooseQuery

    ads?.forEach((elm, index) => {
        // Check if image exists and update its URL
        if (elm?.image) {
            ads[index].image = "https://saraha-seej.onrender.com/" + elm.image;
        }

    });

    return res.status(200).json({ message: 'success', ads })
})


// Schedule a job to delete adsModel older than 60 days
cron.schedule('0 0 0 1 */2 *', async () => {
    try {

        const sixtyDaysAgo = new Date(Date.now() - 60 * 24 * 60 * 60 * 1000);

        let adsToDelete = await adsModel.find({ isDeleted: true, updatedAt: { $lt: sixtyDaysAgo } });

        adsToDelete?.forEach(async (document) => {
            // Delete associated image from file system
            if (document?.image) {
                try {
                    fs.unlinkSync(document.image);
                    // console.log("Image deleted:", document.image);
                } catch (err) {
                    // console.error("Error deleting image:", err);
                }
            }
        });

        let del = await adsModel.deleteMany({ isDeleted: true, updatedAt: { $lt: sixtyDaysAgo } });// Schedule a job to delete categories older than 60 days

    } catch (error) {
        // new Error('Error deleting');
    }

});

