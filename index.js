import path from 'path'
import { fileURLToPath } from 'url'
import dotenv from 'dotenv'
import i18n from 'i18n';
import cors from 'cors'
import cron from 'node-cron'
import express from 'express'
import initApp from './src/index.router.js'
import https from 'https'

const app = express()
app.use(cors())

//set directory dirname 
const __dirname = path.dirname(fileURLToPath(import.meta.url))
dotenv.config({ path: path.join(__dirname, './config/.env') })


// i18n configuration
i18n.configure({
    locales: ['en', 'ar'], // Supported locales
    directory: `${__dirname}/locales`, // Directory where your localization files reside
    defaultLocale: 'en', // Default locale
    objectNotation: true, // Use object notation for translation strings
});

// Initialize i18n
app.use(i18n.init);

// Set the default locale for the app
app.use((req, res, next) => {
    const locale = req.params.locale || req?.i18n?.options?.defaultLocale;
    req.i18n?.setLocale(locale);
    next();
});
 

//  to walkUp sever
// Define the URL to call
const url = 'https://saraha-seej.onrender.com/' || process.env.BASE_URL

// Define options for the HTTP request
const options = {
    method: 'GET',
    headers: {
        'Content-Type': 'application/json',
    }
};

// Define a function to call the URL
function callURL() {
    const req = https.request(url, options, (res) => {
        let data = '';
        res.on('data', (chunk) => {
            data += chunk;
        });
        res.on('end', () => {
            console.log('Response from URL:', data);
        });
    });

    req.on('error', (error) => {
        console.error('Error calling URL:', error);
    });

    req.end();
}


// Schedule a job to delete userModel older than 60 days
cron.schedule('*/10 * * * *', async () => {
    try {
        // Call the function to execute the request
        callURL();

    } catch (error) {
        // new Error('Error deleting');
    }

});

// setup port and the baseUrl
const port = process.env.PORT || 5000
initApp(app, express)
app.listen(port, () => console.log(`Example app listening on port ${port}!`))