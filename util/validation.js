function isEmpty(value) {
    return !value || value.trim() === '';
}

function userCredentialsAreValid(email, password) {
    return email &&
    email.includes('@') &&
    password &&
    password.trim().length >= 6
}

function userDetailsAreValid(email, password, name, phonenumber, street, postal, city) {
    return (
        userCredentialsAreValid(email, password) &&
        !isEmpty(name) &&
        !isEmpty(phonenumber) &&
        !isEmpty(street) &&
        !isEmpty(postal) &&
        !isEmpty(city)
    );
}

function emailIsConfirmed(email, confirmEmail) {
    return email === confirmEmail;
}

module.exports = {
    userDetailsAreValid: userDetailsAreValid, 
    emailIsConfirmed: emailIsConfirmed
};