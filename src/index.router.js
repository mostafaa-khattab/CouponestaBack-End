import connectDB from '../DB/connection.js'
import authRouter from './modules/auth/auth.router.js'
import branRouter from './modules/brand/brand.router.js'
import categoryRouter from './modules/category/category.router.js'
import couponRouter from './modules/coupon/coupon.router.js'
import notificationRouter from './modules/notification/notification.router.js'
import adsRouter from './modules/ads/ads.router.js'
import userRouter from './modules/user/user.router.js'
import locationRouter from './modules/location/location.router.js'
import { asyncHandler, globalErrorHandler } from './utils/errorHandling.js'
import passport from './utils/Passport.js'
import session from 'express-session'
import userModel from '../DB/model/User.model.js'
import { generateToken } from './utils/GenerateAndVerifyToken.js'
import { customAlphabet } from 'nanoid'
import bcrypt from 'bcrypt';


const initApp = (app, express) => {
    //convert Buffer Data
    app.use(express.json({}))
    // appear image path
    app.use('/uploads', express.static('uploads'))
    // app.use(express.static('uploads'))

    //Setup API Routing 
    app.use(`/auth`, authRouter)
    app.use(`/user`, userRouter)
    app.use(`/location`, locationRouter)
    app.use(`/category`, categoryRouter)
    app.use(`/brand`, branRouter)
    app.use(`/coupon`, couponRouter)
    app.use(`/ads`, adsRouter)
    app.use(`/notification`, notificationRouter)

    // Set up session management
    app.use(session({
        secret: 'your-secret-key', // Replace with your secret key
        resave: false,
        saveUninitialized: true,
        cookie: { secure: false } // Set secure: true if you are using HTTPS
    }));

    // Initialize Passport
    app.use(passport.initialize());
    app.use(passport.session());

    app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

    app.get('/auth/google/callback',
        passport.authenticate('google', { failureRedirect: 'https://couponesta.surge.sh/#/Login' }),
        asyncHandler(async (req, res, next) => {

            if (req.user._json) {
                const googleUser = req.user._json;

                const user = await userModel.findOne({ email: googleUser.email.toLowerCase() });
                if (user) {
                    // login user
                    if (user.provider != "GOOGLE") {
                        return next(new Error("Invalid provider", { cause: 400 }));
                    }


                    const refresh_token = generateToken({ payload: { id: user._id, role: user.role, fullName: user.fullName } }) // 1 year

                    user.status = "online";
                    await user.save();

                    return res.redirect(`https://couponesta.surge.sh/#/?refresh_token=${refresh_token}`);
                }

                // sign up user
                const customPassword = customAlphabet("dffdsfsdfsgfdgfdvfdvdfgvsdvsdfsd1234567810000", 5)();
                const saltRounds = 10;
                const hashPassword = await bcrypt.hash(customPassword, saltRounds);

                const newUser = await userModel.create({
                    fullName: googleUser.name,
                    image: googleUser.picture,
                    email: googleUser.email,
                    password: hashPassword,
                    joined: Date.now(),
                    provider: "GOOGLE",
                    status: "online",
                    confirmAccount: true
                });

                const refresh_token = generateToken({ payload: { id: newUser._id, email: newUser.email, role: newUser.role, fullName: newUser.fullName } }) // 1 year

                return res.redirect(`https://couponesta.surge.sh/#/?refresh_token=${refresh_token}`);
            } else {
                return res.redirect("https://couponesta.surge.sh/#/Login");
            }
        })
    );



    app.get('/', (req, res, next) => {
        return res.json({ message: "welcome to coponesta" })
    })

    app.all('*', (req, res, next) => {
        return next(new Error(`invalid url can't access this endPoint Plz check url  or  method ${req.originalUrl}`, { cause: 404 }))

    })

    app.use(globalErrorHandler)
    connectDB()

}


export default initApp