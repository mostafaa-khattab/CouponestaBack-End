import userModel from "../../../../DB/model/User.model.js"
import { generateToken, verifyToken } from "../../../utils/GenerateAndVerifyToken.js";
import { comparePassword, hash } from "../../../utils/HashAndCompare.js";
import sendEmail from "../../../utils/email.js";
import { asyncHandler } from "../../../utils/errorHandling.js";
import { sendCodeStyle } from "../../../utils/message.style.js";
import bcrypt from 'bcrypt'
import { validatePhoneNumber } from "../../../utils/validatePhone.js";

export const signupEmail = asyncHandler(async (req, res, next) => {

    const { fullName, email, password } = req.body

    // check email exist
    if (await userModel.findOne({ email: email.toLowerCase() })) {
        return next(new Error("Email exist", { cause: 409 }));
    }

    // send email
    const token = generateToken({ payload: { email }, signature: "saving-coupons-signature by khattab@gmail.com" })
    const refreshToken = generateToken({ payload: { email }, signature: "saving-coupons-signature by khattab@gmail.com" })

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
                                        Request new Confirmation Email</a></p>
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

    // hash password
    const hashPassword = hash({ plaintext: password })

    // save
    const user = await userModel.create({ fullName, email, password: hashPassword, joined: Date.now() })

    const access_token = generateToken({ payload: { id: user._id, role: user.role, fullName: user.fullName } }) // 30 minutes
    const refresh_token = generateToken({ payload: { id: user._id, role: user.role, fullName: user.fullName } }) // 1 year

    user.status = "online"
    await user.save()

    return res.status(201).json({ message: "success", user, access_token, refresh_token })

})


export const signupPhone = asyncHandler(async (req, res, next) => {

    const { fullName, phoneNumber, countryCode, password } = req.body

    // check phoneNumber exist
    if (await userModel.findOne({ phoneNumber: phoneNumber.toLowerCase() })) {
        return next(new Error("phone number exist", { cause: 409 }));
    }

    const isValidPhoneNumber = validatePhoneNumber(phoneNumber, countryCode);
    if (!isValidPhoneNumber) {
        return next(new Error("Invalid phone number", { cause: 400 }));
    }

    // hash password
    const hashPassword = hash({ plaintext: password })

    // save
    const user = await userModel.create({
        fullName,
        phoneNumber,
        countryCode,
        password: hashPassword,
        joined: Date.now(),
        confirmAccount: true
    })

    const access_token = generateToken({ payload: { id: user._id, role: user.role, fullName: user.fullName } }) // 30 minutes
    const refresh_token = generateToken({ payload: { id: user._id, role: user.role, fullName: user.fullName } }) // 1 year

    user.status = "online"
    await user.save()

    return res.status(201).json({ message: "success", user, access_token, refresh_token })

})


export const confirmAccount = asyncHandler(async (req, res, next) => {

    const { token } = req.params
    const { email } = verifyToken({ token, signature: "saving-coupons-signature by khattab@gmail.com" })
    if (!email) {
        return next(new Error(`In-valid token payload`, { cause: 400 }))
    }
    const user = await userModel.updateOne({ email: email.toLowerCase() }, { confirmAccount: true })
    if (!user.matchedCount) {
        // return res.status(404).redirect(`${process.env.FE_URL}/#/invalidEmail`)
        return res.status(404).send(`<h1>Not register account.</h1>`)
    } else {
        return res.status(404).redirect(`https://couponesta.surge.sh/`)
    }
})


export const RequestNewconfirmAccount = asyncHandler(async (req, res, next) => {

    const { token } = req.params
    const { email } = verifyToken({ token, signature: "saving-coupons-signature by khattab@gmail.com" })
    if (!email) {
        return next(new Error(`In-valid token payload`, { cause: 400 }))
    }
    const user = await userModel.findOne({ email: email.toLowerCase() })
    if (!user) {
        // return res.status(404).redirect(`${process.env.FE_URL}/#/invalidEmail`)
        return res.status(404).send(`<h1>Not register account.</h1>`)
    }

    if (user.confirmAccount) {
        return res.status(200).redirect(`https://couponesta.surge.sh/`)

    }

    const newToken = generateToken({ payload: { email }, signature: "saving-coupons-signature by khattab@gmail.com" })

    const link = `${req.protocol}://${req.headers.host}/auth/confirmAccount/${newToken}`
    const rfLink = `${req.protocol}://${req.headers.host}/auth/NewconfirmAccount/${token}`


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


    // return res.status(200).redirect(`${process.env.FE_URL}/#/login`)
    return res.status(200).send(`<h1>New confirmation email send to your inbox plz check it As soon As.</h1>`)


})

export const loginEmail = asyncHandler(async (req, res, next) => {

    const { email, password } = req.body

    // check email exist
    const user = await userModel.findOne({ email: email.toLowerCase() })
    if (!user) {
        return next(new Error("Email not exist", { cause: 404 }));
    }

    if (!user.confirmAccount) {
        return next(new Error("Please confirm your email", { cause: 400 }));
    }

    if (!comparePassword({ plaintext: password, hashValue: user.password })) {
        return next(new Error("In-valid Email or Password", { cause: 400 }));
    }

    const access_token = generateToken({ payload: { id: user._id, email: user.email, role: user.role, fullName: user.fullName } }) // 30 minutes
    const refresh_token = generateToken({ payload: { id: user._id, email: user.email, role: user.role, fullName: user.fullName } }) // 1 year

    user.status = "online"
    await user.save()

    return res.status(201).json({ message: "success", user, access_token, refresh_token })

})

export const loginPhone = asyncHandler(async (req, res, next) => {

    const { phoneNumber, countryCode, password } = req.body

    // check phoneNumber exist
    let user = await userModel.findOne({ phoneNumber: phoneNumber.toLowerCase() })
    if (!user) {
        return next(new Error("phone number not exist", { cause: 404 }));
    }

    const isValidPhoneNumber = validatePhoneNumber(phoneNumber, countryCode);
    if (!isValidPhoneNumber) {
        return next(new Error("Invalid phone number", { cause: 400 }));
    }

    if (!comparePassword({ plaintext: password, hashValue: user.password })) {
        return next(new Error("In-valid Phone Number or Password", { cause: 400 }));
    }

    const access_token = generateToken({ payload: { id: user._id, email: user.email, role: user.role, fullName: user.fullName } }) // 30 minutes
    const refresh_token = generateToken({ payload: { id: user._id, email: user.email, role: user.role, fullName: user.fullName } }) // 1 year

    user.status = "online"
    await user.save()

    return res.status(201).json({ message: "success", user, access_token, refresh_token })

})

// send Email
export const sendEmailToChangePassword = asyncHandler(async (req, res, next) => {

    let { email } = req.body
    // const user = await userModel.findOne({ email: req.user.email }, { email: 1, deleted: 1, emailConfirm: 1, code: 1, userName: 1 })
    let user = await userModel.findOne({ email: email.toLowerCase() })
    if (!user) {
        return next(new Error(`Not register account`, { cause: 404 }))
    }


    // if (user.status == "blocked") return next(new Error("user doesn't exist cause it blocked account", { cause: 409 }))
    // if (user.confirmAccount == false) return next(new Error("Plz confirm your email first", { cause: 409 }))

    const link = `https://couponesta.surge.sh/#/newPassword/${user.email}`

    // let message = sendCodeStyle(code.toString().match(/.{1,3}/g).join("-"), user.fullName)
    let message = sendCodeStyle(link, user.fullName)

    let subject = 'forget password ✍️'

    sendEmail({ to: user.email, subject, html: message })

    // // expire code after 2 minutes
    // setTimeout(async () => {

    //     await userModel.updateOne({ email: user.email }, { code: null })

    // }, 2 * 60000)

    user && res.status(202).json({ message: "success" })
})

// forgot password Email
export const forgetPasswordEmail = asyncHandler(async (req, res, next) => {

    const { email, password } = req.body

    let user = await userModel.findOne({ email: email.toLowerCase() })
    if (!user) {
        return next(new Error(`Not register account`, { cause: 404 }))
    }


    if (bcrypt.compareSync(password, user.password)) {
        return next(new Error("Please ensure that your new password is different from your old password for security reasons", { cause: 404 }))
    }

    const hashPassword = hash({ plaintext: password })

    user = await userModel.findOneAndUpdate({ email: email.toLowerCase() }, { password: hashPassword, changePasswordTime: Date.now() }, { new: true })

    user && res.status(202).json({ message: "success", user })

})

// forgot password phone
export const forgetPasswordPhone = asyncHandler(async (req, res, next) => {

    const { phoneNumber, countryCode, password } = req.body

    let user = await userModel.findOne({ phoneNumber: phoneNumber.toLowerCase() })
    if (!user) {
        return next(new Error(`Not register account`, { cause: 404 }))
    }

    const isValidPhoneNumber = validatePhoneNumber(phoneNumber, countryCode);
    if (!isValidPhoneNumber) {
        return next(new Error("Invalid phone number", { cause: 400 }));
    }

    if (bcrypt.compareSync(password, user.password)) {
        return next(new Error("Please ensure that your new password is different from your old password for security reasons", { cause: 404 }))
    }

    const hashPassword = hash({ plaintext: password })

    user = await userModel.findOneAndUpdate({ phoneNumber: phoneNumber.toLowerCase() }, { password: hashPassword, changePasswordTime: Date.now() }, { new: true })

    user && res.status(202).json({ message: "success", user })

})
