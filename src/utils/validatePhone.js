import pka from 'google-libphonenumber'; // importing PhoneNumberUtil from google-libphonenumber

const { PhoneNumberUtil } = pka

// Function to validate phone number using libphonenumber
export const validatePhoneNumber = (phoneNumber, countryCode) => {

    const phoneUtil = PhoneNumberUtil.getInstance();

    try {
        const number = phoneUtil.parseAndKeepRawInput(phoneNumber, countryCode);
        return phoneUtil.isValidNumber(number);
    } catch (error) {
        // console.error('Error validating phone number:', error);
        return false;
    }
};

// // Example usage
// const phoneNumber = '01024332335'; // Phone number to validate
// const countryCode = 'EG'; // Country code (e.g., US for United States)
// const isValid = validatePhoneNumber(phoneNumber, countryCode);
// console.log('Is phone number valid?', isValid);