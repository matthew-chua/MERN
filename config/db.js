const mongoose = require('mongoose');

const config = require("config");

const db = config.get("mongoURI");

const connectDB = async () => {
    try{
        await mongoose.connect(db, {
            useNewUrlParser: true,
            useUnifiedTopology: true,
            useCreateIndex: true
        });

        console.log("connected to mongo");
    }catch(err) {
        console.log(error);
        
        //exit process 
        process.exit(1);
    }
}

module.exports = connectDB;