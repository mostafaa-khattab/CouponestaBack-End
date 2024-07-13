import locationModel from "../../../../DB/model/Location.model.js";
import fs from 'fs'
import { asyncHandler } from "../../../utils/errorHandling.js";
import ApiFeatures from "../../../utils/apiFeature.js";
import cron from 'node-cron'


export const getLocations = asyncHandler(async (req, res, next) => {

    // Find brand matching the selected location or the default location
    const apiFeature = new ApiFeatures(locationModel.find({
        isDeleted: false,
    }).lean(), req.query)
        .paginate()
        .filter()
        .sort()
        .search()
        .select()


    const location = await apiFeature.mongooseQuery

    location?.forEach((elm, index) => {
        // Check if image exists and update its URL
        if (elm.image) {
            location[index].image = "https://saraha-seej.onrender.com/" + elm.image;
        }
        
    });


    return res.status(200).json({ message: 'success', location })
})


export const createLocation = asyncHandler(async (req, res, next) => {

    const name = req.body.name.toLowerCase();
    const locationCode = req.body.locationCode
    const image = req?.file?.dest
    const checkLocationName = await locationModel.findOne({ name })
    if (checkLocationName) {
        return next(new Error(`Duplicate location name ${name}`, { cause: 409 }))
    }
    

    const checkLocationCode = await locationModel.findOne({ locationCode })
    if (checkLocationCode) {
        return next(new Error(`Duplicate location code ${locationCode}`, { cause: 409 }))
    }

    const location = await locationModel.create({
        name,
        locationCode,
        image,
        createdBy: req.user._id
    })

    // console.log(image);
    // console.log(location);

    return res.status(201).json({ message: 'success', location })

})


export const updateLocation = asyncHandler(async (req, res, next) => {

    const { locationId } = req.params;
    let location = await locationModel.findById(locationId)
    if (!location) {
        return next(new Error(`In-valid location ID`, { cause: 400 }))
    }

    if (req.body.name) {

        req.body.name = req.body.name.toLowerCase();

        if (req.body.name == location.name) {
            return next(new Error(`Cannot update location with the same old name`, { cause: 409 }))
        }

        if (await locationModel.findOne({ name: req.body.name })) {
            return next(new Error(`Duplicate location name ${req.body.name}`, { cause: 409 }))
        }

        location.name = req.body.name

    }

    if (req.body.locationCode) {

        req.body.locationCode = req.body.locationCode.toLowerCase();

        if (req.body.locationCode == location.locationCode) {
            return next(new Error(`Cannot update location with the same old location Code`, { cause: 409 }))
        }

        if (await locationModel.findOne({ locationCode: req.body.locationCode })) {
            return next(new Error(`Duplicate location locationCode ${req.body.locationCode}`, { cause: 409 }))
        }

        location.locationCode = req.body.locationCode

    }


    if (location?.image && req?.file) {
        // Delete the previous image
        // fs?.unlinkSync(location?.image, (err) => {
        //     if (err) {
        //         console.log("Error deleting previous image:", err);
        //     }
        // });

        // Now update location.image with the new file destination
        req.body.image = req.file.dest;
    }

    req.body.updatedBy = req.user._id

    location = await locationModel.findByIdAndUpdate(locationId, req.body, { new: true });

    // Append BASE_URL to the image field
    if (location.image) {
        location.image = "https://saraha-seej.onrender.com/" + location.image;
    }

    return res.status(201).json({ message: 'success', location })

})


export const deleteLocation = asyncHandler(async (req, res, next) => {
    const { locationId } = req.params;

    const location = await locationModel.findByIdAndDelete(locationId)

    !location && next(new Error(`location not found`, { status: 404 }));

    if (location?.image) {
        try {
            fs.unlinkSync(location?.image);
            // console.log("Image deleted:", document.image);
        } catch (err) {
            // console.error("Error deleting image:", err);
        }
    }

    location && res.status(202).json({ message: " success", location })
})


export const getLocationsDeleted = asyncHandler(async (req, res, next) => {

    const locale = req.params.locale || 'en' // Get locale from request parameters (e.g., 'en' or 'ar')

    let { isDeleted, locationId } = req.body;

    if (isDeleted && locationId) {
        // Save updated location
        let isDel = await locationModel.findByIdAndUpdate(locationId, { isDeleted }, { new: true });
    }

    // Find brand matching the selected location or the default location
    const apiFeature = new ApiFeatures(locationModel.find({
        isDeleted: true,
    }).lean(), req.query)
        .paginate()
        .filter()
        .sort()
        .search()
        .select()


    const location = await apiFeature.mongooseQuery

    location?.forEach((elm, index) => {
        // Check if image exists and update its URL
        if (elm.image) {
            location[index].image = "https://saraha-seej.onrender.com/" + elm.image;
        }

    });

    return res.status(200).json({ message: 'success', location })
})


// Schedule a job to delete locationModel older than 60 days
cron.schedule('0 0 0 1 */2 *', async () => {
    try {

        const sixtyDaysAgo = new Date(Date.now() - 60 * 24 * 60 * 60 * 1000);

        let locationToDelete = await locationModel.find({ isDeleted: true, updatedAt: { $lt: sixtyDaysAgo } });

        locationToDelete?.forEach(async (document) => {
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

        let del = await locationModel.deleteMany({ isDeleted: true, updatedAt: { $lt: sixtyDaysAgo } });// Schedule a job to delete categories older than 60 days

    } catch (error) {
        // new Error('Error deleting');
    }

});
