import userModel from "../../DB/model/User.model.js";
import { verifyToken } from "../utils/GenerateAndVerifyToken.js";
import { asyncHandler } from "../utils/errorHandling.js";

export const roles = {
    Admin: "Admin",
    Employee: "Employee",
    User: "User",
}

export const auth = (accessRoles = []) => {

    return asyncHandler(async (req, res, next) => {

        const { authorization } = req.headers;

        if (!authorization) {
            return next(new Error(`authorization dose't exist`, { cause: 400 }))
        }

        if (!authorization?.startsWith("Khattab__")) {
            return next(new Error(`In-valid bearer key`, { cause: 400 }))
        }
        const token = authorization.split("Khattab__")[1]

        if (!token) {
            return next(new Error(`In-valid token`, { cause: 400 }))
        }

        const decoded = verifyToken({ token })

        if (!decoded?.id) {
            return next(new Error(`In-valid token payload`, { cause: 400 }))
        }

        const user = await userModel.findById(decoded.id).select('fullName email role status phone image changePasswordTime')
        if (!user) {
            return next(new Error(`Not register account`, { cause: 401 }))
        }

        if (user.status == "blocked") return next(new Error("user doesn't exist cause it blocked account", { cause: 403 }))
        // if (user.confirmAccount == false) return next(new Error("Plz confirm your email first", { cause: 409 }))

        // if (parseInt(user?.changePasswordTime?.getTime() / 1000) > decoded.iat) {

        //     return next(new Error(`Expire token`, { cause: 401 }))
        // }

        if (!accessRoles.includes(user.role)) {
            return next(new Error(`Not authorized account U are ${user.role}`, { cause: 403 }))
        }

        req.user = user;
        return next()

    })
}