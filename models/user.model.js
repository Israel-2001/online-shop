const bcrypt = require('bcryptjs');
const mongodb = require('mongodb');

const db = require('../data/database');

class User {
    constructor(email, password, fullname, phonenumber, street, postal, city) {
        this.email = email;
        this.password = password;
        this.name = fullname;
        this.address = {
            phonenumber: phonenumber,
            street: street,
            postalCode: postal,
            city: city
        };
    }

    static findById(userId) {
        const uid = new mongodb.ObjectId(userId);

        return db
            .getDb()
            .collection('users')
            .findOne({_id: uid}, { projection: { password: 0 } });
    }

    getUserWithSameEmail() {
        return db.getDb().collection('users').findOne({ email: this.email});
    }

    async exitsAlready() {
        const exitingUser = await this.getUserWithSameEmail();
        if (exitingUser) {
            return true;
        }
        return false;
    }

    async signup() {
        const hashedPassword = await bcrypt.hash(this.password, 12);

        await db.getDb().collection('users').insertOne({
            email: this.email,
            password: hashedPassword,
            name: this.name,
            address: this.address
        });
    }

    hasMatchingPassword(hashedPassword) {
        return bcrypt.compare(this.password, hashedPassword);
    }
}

module.exports = User;