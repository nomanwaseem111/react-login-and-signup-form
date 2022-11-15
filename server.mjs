import express from 'express'
import cors from 'cors'
import mongoose from 'mongoose'
import {
    stringToHash,
    varifyHash,
} from "bcrypt-inzi"
import jwt from 'jsonwebtoken';
import cookieParser from 'cookie-parser';



const SECRET = process.env.SECRET || "topsecret";





const app = express()
app.use(express.json())
app.use(cookieParser());

app.use(cors({
    origin: ['http://localhost:3000', "*"],
    credentials: true
}));
const port = process.env.PORT || 5001


const userScheme = new mongoose.Schema({
    firstName: { type: String, required: true },
    lastName: { type: String, required: true },
    email: { type: String, required: true },
    password: { type: String, required: true },
    createdOn: { type: Date, default: Date.now() }
});

const userModel = mongoose.model('user', userScheme);



app.post('/signup', async (req, res) => {

    let body = req.body

    if (!body.firstName || !body.lastName || !body.email || !body.password) {
        res.status(401).send("Please Fill all Required Fields")
        return;
    }

    userModel.findOne({ email: body.email }, (err, data) => {

        if (!err) {

            console.log("data ", data);

            if (data) {
                console.log("User Already Register");
                res.status(200).send({ message: "User Already Register" })
                return;
            } else {

                stringToHash(body.password).then(hashString => {

                    let newUser = new userModel({
                        firstName: body.firstName,
                        lastName: body.lastName,
                        email: body.email.toLowerCase(),
                        password: hashString
                    })
                    newUser.save((err, result) => {

                        if (!err) {

                            console.log("User is Created", result);
                            res.status(200).send({ message: "User is Created" })
                        } else {
                            console.log("db error", err);
                            res.status(500).send({ message: "db error" })
                            return;
                        }
                    })


                })
            }

        } else {
            console.log("db error in query ", err);
            res.status(500).send({ message: "db error in query" })
            return;
        }
    })


})

app.post('/login', async (req, res) => {

    let body = req.body

    if (!body.email || !body.password) {
        res.status(401).send("Please Fill all Required Fields")
        return;
    }

    userModel.findOne({ email: body.email }, "email firstName lastName password", (err, data) => {

        if (!err) {

            console.log("data ", data);

            if (data) {


                varifyHash(body.password, data.password).then(isMatched => {

                    if (isMatched) {


                        var token = jwt.sign({
                            email: data.email,
                            _id: data._id,
                            iat: Math.floor(Date.now() / 1000) - 30,
                            exp: Math.floor(Date.now() / 1000) + (60 * 60 * 24),
                        }, SECRET);

                        console.log("token ", token);

                        res.cookie('token', token, {
                            maxAge: 86_400_000,
                            httpOnly: true
                        });

                        console.log("User Login", data);
                        res.status(200).send({
                            message: "User Login", profile: {
                                email: data.email,
                                firstName: data.firstName,
                                lastName: data.lastName,
                                _id: data._id
                            }
                        })
                        return;


                    } else {
                        console.log("Incorrect Email or Password");
                        res.status(404).send({ message: "Incorrect Email or Password" })
                        return;
                    }

                })

            } else {

                console.log("User not Found");
                res.status(404).send({ message: " User not Found " })
                return;
            }

        } else {
            console.log("db error in query ", err);
            res.status(500).send({ message: "db error in query" })
            return;
        }
    })


})


app.post('/logout', async (req, res) => {


    res.cookie('token', '' , {
        maxAge: 0,
        httpOnly: true
    });

    console.log("User Logout");
    res.status(200).send({ message: "User Logout" })



})


app.use(function (req, res, next) {
    console.log("req.cookies: ", req.cookies);
    if (!req.cookies.token) {
        res.status(401).send({ message: "include http-only credentials with every request" })
        return;
    }
    jwt.verify(req.cookies.token, SECRET, function (err, decodedData) {
        if (!err) {


            console.log("decodedData: ", decodedData);



            const nowDate = new Date().getTime() / 1000;

            if (decodedData.exp < nowDate) { // expire after 5 min (in milis)
                res.status(401).send("token expired")
            } else { // issue new token

                req.body.token = decodedData
                next();
            }
        } else {
            res.status(401).send("invalid token")
        }
    });
})




app.get('/profile', async (req, res) => {


    try {


        let user = await userModel.findOne({ _id: req.body.token._id }).exec()

        res.status(200).send(user);


    } catch (error) {

        console.log("error ", error);

    }


})


app.get('/users', async (req, res) => {


    try {


        let response = await userModel.find({}).exec()

        res.status(200).send(response);


    } catch (error) {

        console.log("error ", error);

    }


})

app.listen(port, () => {
    console.log(`Example app listening on port ${port}`)
})

let dbURI = process.env.MONGODBURI || "mongodb+srv://abc:abc@cluster0.bql8mte.mongodb.net/newUser?retryWrites=true&w=majority";
// let dbURI = 'mongodb://localhost/mydatabase';
mongoose.connect(dbURI);


////////////////mongodb connected disconnected events///////////////////////////////////////////////
mongoose.connection.on('connected', function () {//connected
    console.log("Mongoose is connected");
    // process.exit(1);
});

mongoose.connection.on('disconnected', function () {//disconnected
    console.log("Mongoose is disconnected");
    process.exit(1);
});

mongoose.connection.on('error', function (err) {//any error
    console.log('Mongoose connection error: ', err);
    process.exit(1);
});

process.on('SIGINT', function () {/////this function will run jst before app is closing
    console.log("app is terminating");
    mongoose.connection.close(function () {
        console.log('Mongoose default connection closed');
        process.exit(0);
    });
});