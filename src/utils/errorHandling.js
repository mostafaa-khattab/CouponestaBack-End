
export const asyncHandler = (fn) => {
    return (req, res, next) => {
        fn(req, res, next).catch(err => {

            return next(new Error(err, { cause: 500 }))
        })
    }
}

export const globalErrorHandler = (err, req, res, next) => {

    if (err) {
        if (process.env.MOOD == 'DEV') {
            return res.status(err.cause || 500).json({ message: err.message, error: err, stack: err.stack })
        }
        
        return res.status(err.cause || 500).json({ message: err.message })

    }
}