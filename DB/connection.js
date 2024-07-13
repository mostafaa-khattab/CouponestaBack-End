import mongoose from 'mongoose'

const connectDB = async () => {

    return await mongoose.connect(process.env.DB_LOCAL || "mongodb+srv://couponesta:2002246810@cluster0.wvr9xfk.mongodb.net/CouponestaDB")
        .then(res => console.log(`DB Connected successfully on .........`))
        .catch(err => console.log(` Fail to connect  DB.........${err} `))
}



export default connectDB;