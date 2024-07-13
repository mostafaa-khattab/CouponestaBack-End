import nodemailer from "nodemailer";

async function sendEmail({ to, cc, bcc, subject, html, attachments = [] } = {}) {
    let transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
            user: process.env.gmail || "workteach83@gmail.com", // generated ethereal user
            pass: process.env.gmailPass || "mwpz tgqj gkte qxoe", // generated ethereal password
        },
    });

    // send mail with defined transport object
    let info = await transporter.sendMail({
        from: `"Couponesta" <${process.env.gmail}>`, // sender address
        to,
        cc,
        bcc,
        subject,
        html,
        attachments
    });

    return info.rejected.length ? false : true
}



export default sendEmail