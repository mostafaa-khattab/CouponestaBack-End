import userModel from "../../../../DB/model/User.model.js"
import { generateToken } from "../../../utils/GenerateAndVerifyToken.js";
import { hash } from "../../../utils/HashAndCompare.js";
import ApiFeatures from "../../../utils/apiFeature.js";
import sendEmail from "../../../utils/email.js";
import { asyncHandler } from "../../../utils/errorHandling.js";
import { validatePhoneNumber } from "../../../utils/validatePhone.js";
import bcrypt from 'bcrypt'
import cron from 'node-cron'


export const getAllUserFavoriteToDashboard = asyncHandler(async (req, res, next) => {

    const userFavorite = await userModel.findOne(req.user._id).populate('favorite').lean()

    !userFavorite && next(new AppError(`user favorite not found`, 404))
    userFavorite && res.status(202).json({ message: "success", userFavorite: userFavorite.favorite })
})

export const getAllUserFollowToDashboard = asyncHandler(async (req, res, next) => {

    const userFollow = await userModel.findOne(req.user._id).populate('follow').lean()

    userFollow.follow?.forEach((coup, index) => {

        userFollow.follow[index].image = "https://saraha-seej.onrender.com/" + coup.image
    })

    !userFollow && next(new AppError(`user follow not found`, 404))
    userFollow && res.status(202).json({ message: "success", userFollow: userFollow.follow })
})

export const getAllUserFavorite = asyncHandler(async (req, res, next) => {

    const locale = req.params.locale || 'en' // Get locale from request parameters (e.g., 'en' or 'ar')

    const userFavorite = await userModel.findOne(req.user._id).populate('favorite').lean()

    userFavorite.favorite?.forEach((coup, index) => {

        coup.status = coup.status[`${locale}`] || `coupons- ${locale}`
        coup.description = coup.description[`${locale}`] || `coupons- ${locale}`
    })

    !userFavorite && next(new AppError(`user favorite not found`, 404))
    userFavorite && res.status(202).json({ message: "success", userFavorite: userFavorite.favorite })
})

export const getAllUserFollow = asyncHandler(async (req, res, next) => {

    const locale = req.params.locale || 'en' // Get locale from request parameters (e.g., 'en' or 'ar')

    const userFollow = await userModel.findOne(req.user._id).populate('follow').lean()

    userFollow.follow?.forEach((coup, index) => {

        userFollow.follow[index].image = "https://saraha-seej.onrender.com/" + coup.image
        coup.name = coup.name[`${locale}`] || `coupons- ${locale}`
        coup.description = coup.description[`${locale}`] || `coupons- ${locale}`
    })



    !userFollow && next(new AppError(`user follow not found`, 404))
    userFollow && res.status(202).json({ message: "success", userFollow: userFollow.follow })
})

export const getAllUsers = asyncHandler(async (req, res, next) => {

    // Find brand matching the selected location or the default location
    const apiFeature = new ApiFeatures(userModel.find({
        isDeleted: false,
    }).lean()
        .populate('follow')
        .populate('createdBy', 'fullName')
        .populate('updatedBy', 'fullName')
        .populate('favorite')
        .populate('notification'), req.query)
        .paginate()
        .filter()
        .sort()
        .search()
        .select()

    const users = await apiFeature.mongooseQuery

    users?.forEach((elm, index) => {
        // Check if image exists and update its URL
        if (elm.image) {
            users[index].image = "https://saraha-seej.onrender.com/" + elm.image;
        }
    });

    return res.status(200).json({ message: 'success', users })
})

export const getLoggedUser = asyncHandler(async (req, res, next) => {

    // let { userId } = req.params;

    // Find brand matching the selected location or the default location
    const apiFeature = new ApiFeatures(userModel.findById(req.user._id, {
        isDeleted: false,
    }).lean()
        .populate('follow')
        .populate('createdBy', 'fullName')
        .populate('updatedBy', 'fullName')
        .populate('favorite')
        .populate('notification'), req.query)
        .paginate()
        .filter()
        .sort()
        .search()
        .select()

    let user = await apiFeature.mongooseQuery

    user?.forEach((elm, index) => {
        // Check if image exists and update its URL
        if (elm.image) {
            user[index].image = "https://saraha-seej.onrender.com/" + elm.image;
        }
    });

    return res.status(200).json({ message: 'success', user })
})


export const addUser = asyncHandler(async (req, res, next) => {

    const { phoneNumber, countryCode, email, password } = req.body

    const image = req?.file?.dest;

    // check email exist
    if (email) {
        if (await userModel.findOne({ email: email.toLowerCase() })) {
            return next(new Error("Email exist", { cause: 409 }));
        }

        // send email
        const token = generateToken({ payload: { email }, signature: "saving-coupons-signature by khattab@gmail.com", expiresIn: 60 * 5 })
        const refreshToken = generateToken({ payload: { email }, signature: "saving-coupons-signature by khattab@gmail.com", expiresIn: 60 * 60 * 24 })

        const link = `${req.protocol}://${req.headers.host}/auth/confirmAccount/${token}`
        const rfLink = `${req.protocol}://${req.headers.host}/auth/NewconfirmAccount/${refreshToken}`

        const html = `<!DOCTYPE html>

        <head>
            <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/font-awesome/4.7.0/css/font-awesome.min.css">
        </head>
        <style type="text/css">
            body {
                background-color: #88BDBF;
                margin: 0px;
            }
        </style>
        
        <body style="margin:0px;">
            <table border="0" width="70%" style="margin:auto;padding:30px;background-color: #F3F3F3;border:1px solid teal;">
                <tr>
                    <td>
                        <table border="0" width="100%">
                            <tr>
                                <td>
                                    <h1>
                                        <img width="100px"
                                            src="https://res.cloudinary.com/dlbm6rfwr/image/upload/v1710635049/logo6_df2svv.jpg" />
                                    </h1>
                                </td>
                                <td>
                                    <p style="text-align: right;"><a href="${"https://saraha-seej.onrender.com/"}" target="_blank"
                                            style="text-decoration: none;">View In Website</a></p>
                                </td>
                            </tr>
                        </table>
                    </td>
                </tr>
                <tr>
                    <td>
                        <table border="0" cellpadding="0" cellspacing="0"
                            style="text-align:center;width:100%;padding-bottom: 20px;background-color: #fff;">
                            <tr>
                                <td style="background-color:#66A7A1;height:60px;font-size:50px;color:#fff;">
                                    <img width="50px" height="50px" style="padding-top: 10px;"
                                        src="https://i.pinimg.com/originals/5b/16/1b/5b161b77a352ae26b52b56499601c1c0.jpg">
                                </td>
                            </tr>
                            <tr>
                                <td>
                                    <h1 style="padding-top:20px; color: teal">Email Confirmation</h1>
                                </td>
                            </tr>
                            <tr>
                                <td>
                                    <p style="padding:0px 100px;">
                                    </p>
                                </td>
                            </tr>
                            <tr>
                                <td>
                                    <p><a href="${link}" target="_blank"
                                            style="cursor: pointer;text-decoration: none;font-weight: 900;margin:10px 0px 30px 0px;border-radius:4px;padding:10px 20px;border: 0;color:#fff;background-color:teal; ">
                                            Verify Email address</a></p>
                                </td>
                            </tr>
                            <tr>
                                <td>
                                    <p style="padding:0px 150px;margin-top: 30px;">
                                    </p>
                                </td>
                            </tr>
                            <tr>
                                <td>
                                    <p><a href="${rfLink}" target="_blank"
                                            style="cursor: pointer;text-decoration: none;font-weight: 900;margin:10px 0px 30px 0px;border-radius:4px;padding:10px 20px;border: 0;color:#fff;background-color:darkgoldenrod; ">
                                            Request new Email</a></p>
                                </td>
                            </tr>
                        </table>
                    </td>
                </tr>
                <tr>
                    <td>
                        <table border="0" width="100%" style="border-radius: 5px;text-align: center;">
                            <tr>
                                <td>
                                    <h3 style="margin-top:20px; color:#000">Stay in touch</h3>
                                </td>
                            </tr>
                            <tr>
                                <td>
                                    <div style="margin-top:15px;">
        
                                        <a href="${process.env.facebookLink}" style="text-decoration: none;"><span class="twit"
                                                style="padding:10px 9px;color:#fff;border-radius:50%;">
                                                <img src="https://res.cloudinary.com/ddajommsw/image/upload/v1670703402/Group35062_erj5dx.png"
                                                    width="50px" hight="50px"></span></a>
        
                                        <a href="${process.env.instegram}" style="text-decoration: none;"><span class="twit"
                                                style="padding:10px 9px;color:#fff;border-radius:50%;">
                                                <img src="https://res.cloudinary.com/ddajommsw/image/upload/v1670703402/Group35063_zottpo.png"
                                                    width="50px" hight="50px"></span>
                                        </a>
        
                                        <a href="${process.env.twitterLink}" style="text-decoration: none;"><span class="twit"
                                                style="padding:10px 9px;;color:#fff;border-radius:50%;">
                                                <img src="https://res.cloudinary.com/ddajommsw/image/upload/v1670703402/Group_35064_i8qtfd.png"
                                                    width="50px" hight="50px"></span>
                                        </a>
        
                                    </div>
                                </td>
                            </tr>
                        </table>
                    </td>
                </tr>
            </table>
        </body>
        
        </html>`

        if (!await sendEmail({ to: email, subject: 'Confirmation Email 👋', html })) {
            return res.status(400).json({ message: "Email Rejected" })
        }
    }


    // Validate phone number
    if (phoneNumber && countryCode) {
        const isValidPhoneNumber = validatePhoneNumber(phoneNumber, countryCode);
        if (!isValidPhoneNumber) {
            return next(new Error("Invalid phone number", { cause: 400 }));
        }
    }

    // hash password
    const hashPassword = hash({ plaintext: password })

    // save
    const user = await userModel.create({
        ...req.body,
        password: hashPassword,
        joined: Date.now(),
        image,
        createdBy: req.user._id
    })

    // Append BASE_URL to the image field
    if (user.image) {
        user.image = "https://saraha-seej.onrender.com/" + user.image;
    }

    return res.status(201).json({ message: "success", user })
});

export const updateUser = asyncHandler(async (req, res, next) => {

    let { userId } = req.params;

    // Find user by ID
    let user = await userModel.findById(userId);
    if (!user) {
        return res.status(400).json({ error: 'Invalid user ID' });
    }

    let { phoneNumber, countryCode, email, password } = req.body;
    let image = req?.file?.dest;

    // check email exist
    if (email) {
        if (await userModel.findOne({ email: email.toLowerCase() })) {
            return next(new Error("Email exist", { cause: 409 }));
        }

        // send email
        const token = generateToken({ payload: { email }, signature: "saving-coupons-signature by khattab@gmail.com", expiresIn: 60 * 5 })
        const refreshToken = generateToken({ payload: { email }, signature: "saving-coupons-signature by khattab@gmail.com", expiresIn: 60 * 60 * 24 })

        const link = `${req.protocol}://${req.headers.host}/auth/confirmAccount/${token}`
        const rfLink = `${req.protocol}://${req.headers.host}/auth/NewconfirmAccount/${refreshToken}`

        const html = `<!DOCTYPE html>

        <head>
            <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/font-awesome/4.7.0/css/font-awesome.min.css">
        </head>
        <style type="text/css">
            body {
                background-color: #88BDBF;
                margin: 0px;
            }
        </style>

        <body style="margin:0px;">
            <table border="0" width="70%" style="margin:auto;padding:30px;background-color: #F3F3F3;border:1px solid teal;">
                <tr>
                    <td>
                        <table border="0" width="100%">
                            <tr>
                                <td>
                                    <h1>
                                        <img width="100px"
                                            src="https://res.cloudinary.com/dlbm6rfwr/image/upload/v1710635049/logo6_df2svv.jpg" />
                                    </h1>
                                </td>
                                <td>
                                    <p style="text-align: right;"><a href="${"https://saraha-seej.onrender.com/"}" target="_blank"
                                            style="text-decoration: none;">View In Website</a></p>
                                </td>
                            </tr>
                        </table>
                    </td>
                </tr>
                <tr>
                    <td>
                        <table border="0" cellpadding="0" cellspacing="0"
                            style="text-align:center;width:100%;padding-bottom: 20px;background-color: #fff;">
                            <tr>
                                <td style="background-color:#66A7A1;height:60px;font-size:50px;color:#fff;">
                                    <img width="50px" height="50px" style="padding-top: 10px;"
                                        src="https://i.pinimg.com/originals/5b/16/1b/5b161b77a352ae26b52b56499601c1c0.jpg">
                                </td>
                            </tr>
                            <tr>
                                <td>
                                    <h1 style="padding-top:20px; color: teal">Email Confirmation</h1>
                                </td>
                            </tr>
                            <tr>
                                <td>
                                    <p style="padding:0px 100px;">
                                    </p>
                                </td>
                            </tr>
                            <tr>
                                <td>
                                    <p><a href="${link}" target="_blank"
                                            style="cursor: pointer;text-decoration: none;font-weight: 900;margin:10px 0px 30px 0px;border-radius:4px;padding:10px 20px;border: 0;color:#fff;background-color:teal; ">
                                            Verify Email address</a></p>
                                </td>
                            </tr>
                            <tr>
                                <td>
                                    <p style="padding:0px 150px;margin-top: 30px;">
                                    </p>
                                </td>
                            </tr>
                            <tr>
                                <td>
                                    <p><a href="${rfLink}" target="_blank"
                                            style="cursor: pointer;text-decoration: none;font-weight: 900;margin:10px 0px 30px 0px;border-radius:4px;padding:10px 20px;border: 0;color:#fff;background-color:darkgoldenrod; ">
                                            Request new Email</a></p>
                                </td>
                            </tr>
                        </table>
                    </td>
                </tr>
                <tr>
                    <td>
                        <table border="0" width="100%" style="border-radius: 5px;text-align: center;">
                            <tr>
                                <td>
                                    <h3 style="margin-top:20px; color:#000">Stay in touch</h3>
                                </td>
                            </tr>
                            <tr>
                                <td>
                                    <div style="margin-top:15px;">

                                        <a href="${process.env.facebookLink}" style="text-decoration: none;"><span class="twit"
                                                style="padding:10px 9px;color:#fff;border-radius:50%;">
                                                <img src="https://res.cloudinary.com/ddajommsw/image/upload/v1670703402/Group35062_erj5dx.png"
                                                    width="50px" hight="50px"></span></a>

                                        <a href="${process.env.instegram}" style="text-decoration: none;"><span class="twit"
                                                style="padding:10px 9px;color:#fff;border-radius:50%;">
                                                <img src="https://res.cloudinary.com/ddajommsw/image/upload/v1670703402/Group35063_zottpo.png"
                                                    width="50px" hight="50px"></span>
                                        </a>

                                        <a href="${process.env.twitterLink}" style="text-decoration: none;"><span class="twit"
                                                style="padding:10px 9px;;color:#fff;border-radius:50%;">
                                                <img src="https://res.cloudinary.com/ddajommsw/image/upload/v1670703402/Group_35064_i8qtfd.png"
                                                    width="50px" hight="50px"></span>
                                        </a>

                                    </div>
                                </td>
                            </tr>
                        </table>
                    </td>
                </tr>
            </table>
            </body>

            </html>`

        if (!await sendEmail({ to: email, subject: 'Confirmation Email 👋', html })) {
            return res.status(400).json({ message: "Email Rejected" })
        }
    }

    // Validate phone number if provided
    if (phoneNumber && countryCode) {
        const isValidPhoneNumber = validatePhoneNumber(phoneNumber, countryCode);
        if (!isValidPhoneNumber) {
            return next(new Error("Invalid phone number", { status: 400 }));
        }
    }

    let hashPassword;
    if (password) {
        if (bcrypt.compareSync(password, user.password)) {
            return next(new Error("Please ensure that your new password is different from your old password for security reasons", { cause: 404 }))
        }

        hashPassword = hash({ plaintext: password })

    }

    // Update image if provided
    if (image && req.file) {
        image = req.file.dest;
    }

    // // Update user with hashed password and other fields
    // let updatedUser = await userModel.findByIdAndUpdate(
    //     userId,
    //     {
    //         ...req.body,
    //         password: hashPassword,
    //         changePasswordTime: Date.now(),
    //         image,
    //         updatedBy: req.user._id
    //     },
    //     { new: true }
    // );


    // Update user with hashed password and other fields
    let updatedUser;

    // console.log("hashPassword", hashPassword);

    // console.log("bodyyyyyyyy", req.body);

    if (hashPassword) {

        updatedUser = await userModel.findByIdAndUpdate(
            userId,
            {
                password: hashPassword,
                changePasswordTime: Date.now(),
                updatedBy: req.user._id
            },
            { new: true }
        );

        // console.log("update wirh passsss", updatedUser);

    } else {

        updatedUser = await userModel.findByIdAndUpdate(
            userId,
            {
                ...req.body,
                image,
                updatedBy: req.user._id
            },
            { new: true }
        );

        // console.log("update anotherrrrrr", updatedUser);

    }

    if (!updatedUser) {
        return next(new Error("User not found", { status: 404 }));
    }


    // Append BASE_URL to the image field
    if (updatedUser.image) {
        updatedUser.image = "https://saraha-seej.onrender.com/" + updatedUser.image;
    }


    return res.status(200).json({ message: "success", user: updatedUser });
});



export const softDeleteUser = asyncHandler(async (req, res, next) => {
    const { userId } = req.params;

    const user = await userModel.findByIdAndUpdate(userId, { isDeleted: true, status: "offline" })

    !user && next(new Error(`user not found`, { status: 404 }));

    user && res.status(202).json({ message: "success", user })
})

export const logoutUser = asyncHandler(async (req, res, next) => {
    const { userId } = req.params;

    const user = await userModel.findByIdAndUpdate(userId, { status: "offline" })

    !user && next(new Error(`user not found`, { status: 404 }));

    user && res.status(202).json({ message: "success", user })
})

export const deleteUser = asyncHandler(async (req, res, next) => {
    const { userId } = req.params;

    const user = await userModel.findByIdAndDelete(userId)

    !user && next(new Error(`user not found`, { status: 404 }));

    if (user?.image) {
        try {
            fs.unlinkSync(user?.image);
            // console.log("Image deleted:", document.image);
        } catch (err) {
            // console.error("Error deleting image:", err);
        }
    }

    user && res.status(202).json({ message: "success", user })
})


export const getUsersDeleted = asyncHandler(async (req, res, next) => {

    let { isDeleted, userId } = req.body;

    if (isDeleted && userId) {
        // Save updated user
        let isDel = await userModel.findByIdAndUpdate(userId, { isDeleted }, { new: true });
    }

    // Find brand matching the selected location or the default location
    const apiFeature = new ApiFeatures(userModel.find({
        isDeleted: true,
    }).lean(), req.query)
        .paginate()
        .filter()
        .sort()
        .search()
        .select()


    const user = await apiFeature.mongooseQuery

    user?.forEach((elm, index) => {
        // Check if image exists and update its URL
        if (elm.image) {
            user[index].image = "https://saraha-seej.onrender.com/" + elm.image;
        }
    });

    return res.status(200).json({ message: 'success', user })
})


// Schedule a job to delete userModel older than 60 days
cron.schedule('0 0 0 1 */2 *', async () => {
    try {

        const sixtyDaysAgo = new Date(Date.now() - 60 * 24 * 60 * 60 * 1000);

        let userToDelete = await userModel.find({ isDeleted: true, updatedAt: { $lt: sixtyDaysAgo } });

        userToDelete?.forEach(async (document) => {
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

        let del = await userModel.deleteMany({ isDeleted: true, updatedAt: { $lt: sixtyDaysAgo } });// Schedule a job to delete categories older than 60 days

    } catch (error) {
        // new Error('Error deleting');
    }

});
