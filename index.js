const fs = require('fs');
const https = require('https');
const express = require('express');


const certificate = fs.readFileSync('path/to/your/certificate.pem');
const ca = fs.readFileSync('path/to/your/ca.pem');
const Redis = require('ioredis');
const uuid=require('uuidv4')
const bcrypt = require('bcrypt');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const rateLimit = require('express-rate-limiter')
const cors = require('cors');
const multer = require('multer')
const recipeRoutes = require('./routes/recipeRoutes');
const { combine, timestamp, label, printf } = winston.format;
const winston = require('winston');
const { Storage } = require("google-cloud/storage")
const upload = multer({ dest: '/uploads' })
const ffmpeg = require('ffmpeg')
const { check, validationResult } = require('express-validator');
const { v4: uuidv4 } = require('uuid')
const nodemailer = require('nodemailer');

const { Client } = require('@elastic/elasticsearch')

const app = express();
const transporter = nodemailer.createTransport({
    service: 'Gmail',
    auth: {
        user: process.env['user'],
        pass: process.env['pass']
    }
})
app.use(cors(
    {
        origin: '*',
        optionsSuccessStatus: 200
    }
));


require('dotenv').config();
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
});
const client = new Client({
  node: process.env['node'],
  auth: {
    user: process.env['user'],
    password: process.env['password'],
  },
});
app.use(limiter)
app.use(express.json());
app.use(cookieParser());
app.use(express.urlencoded({ extended: true }));

const apiKeySchema = new mongoose.Schema({
    key: String,
    createdAt: Date
})
const apiKeyModel = mongoose.model('ApiKey', apiKeySchema);
async function checkApiKey(req, res, next) {
    const apiKey = req.headers['x-api-key'] || req.query.apiKey;
    if (!apiKey) {
        return res.status(401).json({ error: 'API key is missing' });
    }
    try {
        mongoose.connect(process.env[url], { useNewUrlParser: true, useUnifiedTopology: true })
        const result = await apiKeyModel.findOne({ key: apiKey });
        if (!result) {
            return res.status(401).json({ error: 'Invalid API key' });
        }
    } catch (error) {


        res.status(500).send("Internal Server Error");
        logger.error(error, Datetime.now());
    } finally {
        mongoose.connection.close();
    }
    next();
}



const myFormat = printf(({ level, message, label, timestamp }) => {
    return `${timestamp} [${label}] ${level}: ${message}`;
});


const logger = winston.createLogger({
    format: combine(
        label({ label: 'my-app' }),
        timestamp(),
        myFormat
    ),
    transports: [
        new winston.transports.File({ filename: 'logfile.log' })
    ]
});
async function compress() {
    try {
        const process = new ffmpeg('./uploads/video.mp4');
        process.then(function (video) {
            video
                .setVideoSize('640x480', true, true, '#fff')
                .save('./uploads/video_compressed.mp4', function (error, file) {
                    if (!error)
                        console.log('Video file: ' + file);
                });
        }, function (err) {
            console.log('Error: ' + err);
        });
    } catch (e) {
        console.log(e.code);
        console.log(e.msg);
    }
}



const userSchema = new mongoose.Schema({
    id: Number,
    profile_picture_id: Number,
    profile_picture_url: String,
    username: String,
    password: String,
    email: String,
    salt: String,
    createdAt: Date
});

const User = mongoose.model('User', userSchema);


const redisClient = new Redis({
  host: process.env['host'],
  port: 6379,
  password:process.env['password'],
  tls: {
    key: fs.readFileSync(__dirname + '/ssl/client.pem'),
    cert: fs.readFileSync(__dirname + '/ssl/client.pem'),
    ca: fs.readFileSync(__dirname + '/ssl/ca.pem'),
    rejectUnauthorized: false,

  },
});


const options = {
  key: privateKey,
  cert: certificate,
  ca: ca,
};

const taskSchema = new mongoose.Schema({
    post_id:String,
    id:String,
    title:String,
    dueDate:Date,
    createdAt:{type:String,default:Date.now}
});

const Task = mongoose.model('User', taskSchema);
app.get('/',(req,res)=>{
    res.status(200).json("Hello World!")
});

const privateKey = fs.readFileSync('./private.pem', 'utf-8');
const publicKey = fs.readFileSync('./public.pem', 'utf-8');
const storage = new Storage({
    keyFilename: process.env[name],
    projectId: process.env[id]
})

const requireAuth = (req, res, next) => {
    const token = req.cookies.token;
    if (token) {
      jwt.verify(token, publicKey, (err, decodedToken) => {
        if (err) {
          res.status(401).json({ message: 'Unauthorized' });
        } else {
          req.cookies.token = decodedToken;
          next();
        }
      });
    } else {
      res.status(401).json({ message: 'Unauthorized' });
    }
  };
app.use('/recipes', recipeRoutes,requireAuth);

app.get('/user',validateApiKey,async(req,res)=>{
    const task_id=req.body.task_id;
    const jwt=req.cookies.jwt;
    const decoded=jwt.decode();
    const userId=decoded.id;
    try {
        
    } catch (error) {
        res.status(500).send("Internal Server Error");
    }finally{
        mongoose.client.close();
    }
});

app.post('/login', checkApiKey, async (req, res) => {
    const token = req.cookies.jwt;
    const username = req.body.username;
    const password = req.body.password;
    const sanitizedPassword = sanitize(password);
    const sanitizedUsername = sanitize(username);
    if (token) {
        res.send('You are already logged in');
        logger.info('User is already logged in', Date.now());
    } else {

        try {

            mongoose.connect(process.env[url], {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  ssl: true,
  sslValidate: true,
  sslCA: ca}, { useNewUrlParser: true, useUnifiedTopology: true });
            const user = await mongoose.model('User').findOne({ username: sanitizedUsername });
            if (!user) {
                res.status(500).send('User not found');
                logger.error('User not found', Datetime.now());
            } else {
                const salt = user.salt;
                const hashedPassword = await bcrypt.hash(sanitizedPassword, salt);

                mongoose.connect(process.env[url], {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  ssl: true,
  sslValidate: true,
  sslCA: ca}, { useNewUrlParser: true, useUnifiedTopology: true });
                const user = await mongoose.model('User').findOne({ username: sanitizedUsername, password: hashedPassword });
                if (!user) {
                    res.status(401).send('Username or password is incorrect');
                    logger.error('Username or password is incorrect', Datetime.now());
                } else {


                    res.cookie("jwt", token, { httpOnly: true });
                    res.status(200).send('User logged in successfully')
                    logger.info('User logged in successfully', Datetime.now());

                }
            }
        } catch (error) {
            res.status(500).send("Internal Server Error");
            logger.error(error, Datetime.now());
        } finally {
            mongoose.disconnnect();
        }
    }
});


app.post('/logout', checkApiKey, (req, res) => {
    try {
        res.clearCookie("jwt");
        res.send("Cookie cleared");
        logger.info('User logged out successfully', Datetime.now());
    } catch (error) {
        res.status(500).send("Internal Server Error");
        logger.error(error, Datetime.now());
    }
});

app.delete('/delete', checkApiKey, async (req, res) => {
    const token = req.cookies.jwt;
    const username = req.body.username;
    const password = req.body.password;
    const sanitizedPassword = sanitize(password);
    const sanitizedUsername = sanitize(username);
    const profile_picture_id = req.body.profile_picture_id;
    if (token) {

        try {
            await deleteFileFromBucketById(profile_picture_id)


     mongoose.connect(process.env[url], {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  ssl: true,
  sslValidate: true,
  sslCA: ca}, { useNewUrlParser: true, useUnifiedTopology: true });
            if (!user) {
                res.status(404).send('User not found');
                logger.error('User not found', Datetime.now());
            } else {
                res.status(200).send('User deleted successfully')
                logger.info('User deleted successfully', Datetime.now());
            }
        } catch (error) {
            res.status(500).send("Internal Server Error");
        } finally {
            mongoose.connection.close();
        }
    }
    else {
        res.status(401).send('You are not logged in');
        logger.error('User not logged in', Datetime.now());
    }
});

app.put('/user', checkApiKey, upload.single('image'), async (req, res) => {
    const token = req.cookies.jwt;
    const username = req.body.username;
    const password = req.body.password;
    
    const profile_picture_idd = req.body.profile_picture_id;

    const sanitizedPassword = sanitize(password);
    const sanitizedUsername = sanitize(username);

    if (token) {

        try {
            await deleteFileFromBucketById(profile_picture_idd)
            const profile_picture_id = uuidv4();
            const bucket = storage.bucket(process.env[bucket]);
            const file = bucket.file(profile_picture_id);
            const imageFile = req.file;


            const options = {
                resumable: false,
                metadata: {
                    contentType: imageFile.mimetype,
                },
            }


            await file.save(imageFile.buffer, options);
            const publicUrl = `https://storage.googleapis.com/${bucket.name}/${file.name}`;

            mongoose.connect(process.env[url], {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  ssl: true,
  sslValidate: true,
  sslCA: ca}, { useNewUrlParser: true, useUnifiedTopology: true });
            const user = await mongoose.model('User').update({ username: sanitizedUsername }, {
                profile_picture_id: profile
            }, { profile_picture_url: profile_picture_url });
            if (!user) {
                res.status(404).send('User not found');
                logger.error('User not found', Datetime.now());
            } else {
                res.status(200).send('User updated successfully')
                logger.info('User updated successfully', Datetime.now());
            }
        } catch (error) {
            res.status(500).send("Internal Server Error");
            logger.error(error, Datetime.now());
        } finally {
            mongoose.connection.close();
        }
    } else {
        res.status(401).send('You are not logged in');
        logger.error('User not logged in', Datetime.now());
    }

});
app.get('/user', checkApiKey, async (req, res) => {
    const token = req.cookies.jwt;
    const username = req.body.username;
    const sanitizedUsername = sanitize(username);
    if (token) {

        redisClient(username, async (err, result) => {
            if (result) {
                res.status(200).send(result);
                logger.info('User found in cache', Datetime.now());
            } else {
                try {
                    mongoose.connect(process.env[url], {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  ssl: true,
  sslValidate: true,
  sslCA: ca}, { useNewUrlParser: true, useUnifiedTopology: true });
                    const result = await mongoose.model('User').findOne({ username: sanitizedUsername }, { username: 1, email: 1, profile_picture_url: 1,profile_picture_id:1,fastatus: 1 });


                    if (!result) {
                        res.status(404).send('User not found');
                        logger.error('User not found', Datetime.now());
                    } else {

                        redisClient.setex(username, 3600, JSON.stringify(result));
                        res.status(200).send(result)
                    }
                } catch (error) {
                    res.status(500).send("Internal Server Error");
                    logger.error(error, Datetime.now());
                } finally {
                    mongoose.connection.close();
                    redisClient.quit();
                }
            }
        })
    } else {
        res.status(401).send('You are not logged in');
        logger.error('User not logged in', Datetime.now());
    }




});
app.post('/register', upload.single('image'), checkApiKey, [
    check('username', 'Username is too short').isLength({ min: 4 }),
    check('password', 'Password is too short').isLength({ min: 4 }),
    check('email', 'Email is not valid').isEmail(),
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(422).json({ errors: errors.array() });
    }

    const { username, password, emails} = req.body;
    const label = ['Male', 'Female', null];

    if (label.includes(gender)) {
        res.send('Invalid gender');
        logger.error('Invalid gender was given', Datetime.now());
    } else {
        const sanitizedUsername = sanitize(username);
        const sanitizedPassword = sanitize(password);
        const sanitizedEmail = sanitize(email);
       

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(sanitizedPassword, salt);

        const id = uuidv4();
        const profile_picture_id = uuidv4();
        const bucket = storage.bucket(process.env[bucket]);
        const file = bucket.file(profile_picture_id);
        const imageFile = req.file;

        try {
            const options = {
                resumable: false,
                metadata: {
                    contentType: imageFile.mimetype,
                },
            };

            await file.save(imageFile.buffer, options);
            const publicUrl = `https://storage.googleapis.com/${bucket.name}/${file.name}`;

            const user = new User({
                id: id,
                profile_picture_id: profile_picture_id,
                profile_picture_url: publicUrl,
                username: sanitizedUsername,
                password: hashedPassword,
                email: sanitizedEmail,
                salt: salt,
                createdAt: Date.now(),
            });

            mongoose.connect(process.env[url], {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  ssl: true,
  sslValidate: true,
  sslCA: ca}, { useNewUrlParser: true, useUnifiedTopology: true });
            await user.save();

            // Index a user
            elasticClient.index({
                index: 'users',
                body: {
                    username: sanitizedUsername
                }
            }, (err, resp) => {
                if (err) {
                    logger.error(err, Date.now());
                } else {
                    res.status(200).send('User registered successfully');
                    logger.info('Index created succesfully', Date.now());
                }
            });

            const token = jwt.sign({ userId: id }, privateKey, { algorithm: "RS256" }, function (err, token) {
                if (err) {
                    res.status(500).send("Internal server error");
                    logger.error(err, Date.now());
                } else {
                    res.cookie("jwt", token, { httpOnly: true });
                    res.send("Cookie set successfully");
                    logger.info('User registered successfully');
                }
            });

        } catch (error) {
            res.status(500).send("Internal Server Error");
            logger.error(error, Datetime.now());
        } finally {
            if (req.file && req.file.path) {
                fs.unlink(req.file.path, (err) => {
                    if (err) {
                        logger.error(error, Datetime.now());
                    }
                });
            }
            mongoose.connection.close();
        }
    }
});
app.post('/reset-password', validateApiKey, async (req, res) => {
    const email = req.body.email;
    const jwt = req.cookies.jwt;
    const decoded = jwt.decode(jwt)
    const userId = decoded.id
    const emails = process.env[user]
    try {
        mongoose.connect(process.env[url], {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  ssl: true,
  sslValidate: true,
  sslCA: ca}, { useNewUrlParser: true, useUnifiedTopology: true });
        const user = await mongoose.model('User').find({ email: email });
        const code = uuidv4();
        const subjectt = 'Email Verification Code'
        const textt = `Your code is ${code}`
        if (!user) {
            res.status(404).send('User not found');
            logger.error(' User  was not found', Datetime.now())
        } else {

            const mailOptions = {
                from: emails,
                to: email,
                subject: subjectt,
                text: textt
            }
            transporter.sendMail(mailOptions, async (err, data) => {
                if (err) {
                    res.status(500).send("Internal Server Error");
                    logger.error(err, Datetime.now());
                } else {

                    await redisClient.set(userId, code, (err, reply) => {
                        if (err) {
                            res.status(500).send("Internal Server Error");
                        }
                        else {
                            res.status(200).send("Ok");
                        }
                    })
                }
            })

            logger.info('Code sent successfully', Datetime.now())
        }
    } catch (error) {
        res.status(500).send("Internal Server Error");
        logger.error(error, Datetime.now());
        logger.error(error, Datetime.now());
    } finally {
        mongoose.connection.close();
        redisClient.quit();
    }

});
app.post('/verify-password:/id', validateApiKey, async (req, res) => {
    const { id } = req.params;
    const jwt = req.cookies.jwt;
    const decoded = jwt.decode(jwt)
    const userId = decoded.id

    try {
        const retriveOTP = await redisClient.get(userId);
        if (retriveOTP === id) {

            const code = uuidv4();

            await redisClient.setex(userId, 3600, code);
            res.status(200).send(code);
            logger.info('Code verified successfully', Datetime.now())
        } else {
            res.status(401).send("Unauthorized");
            logger.error('Code verification failed', Datetime.now())
        }

    } catch (error) {
        res.status(500).send("Internal Server Error")
        logger.error(error, Datetime.now());
    } finally {
        redisClient.quit();
    }
})



app.put('/reset-password-update', validateApiKey, async (req, res) => {
    const jwt = req.cookies.jwt;
    const decoded = jwt.decode(jwt)
    const userId = decoded.id
    const code = req.body.code;
    const password = req.body.password;
    try {
        redisClient(userId, async (err, reply) => {
            if (err) {
                console.log(err)
            } else {

                if (reply === code) {
                    const salt = await bcrypt.genSalt();
                    const hashedPassword = await bcrypt.hash(password, salt);
                    mongoose.connect(process.env[url], {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  ssl: true,
  sslValidate: true,
  sslCA: ca}, { useNewUrlParser: true, useUnifiedTopology: true });
                    const result = await mongoose.model('User').updateOne({ id: userId }, { $set: { password: hashedPassword } });
                    res.status(200).send("Ok");
                    logger.info('Password updated successfully', Datetime.now())
                } else {
                    res.status(401).send("Unauthorized");
                    logger.error('Password update failed', Datetime.now())
                }
            }

        })
    } catch (error) {
        res.status(500).send("Internal Server Error")
        logger.error(error, Datetime.now());
    } finally {
        redisClient.quit();
        mongoose.connection.close();
    }
});


app.put('/password', validateApiKey, async (req, res) => {
    const jwt = req.cookies.jwt;
    const decoded = jwt.decode(jwt)
    const userId = decoded.id
    const username = req.body.username
    const currentpassword = req.body.password;
    const newpassword = req.body.password;

    try {
        mongoose.connect(process.env[url], {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  ssl: true,
  sslValidate: true,
  sslCA: ca}, { useNewUrlParser: true, useUnifiedTopology: true });
        const salt = await mongoose.model('User').find({ username: username }, { salt: 1 });
        const hashedPassword = await bcrypt.hash(currentpassword, salt);
        const result = await mongoose.model('User').find({ id: userId, password: hashedPassword });
        if (!result) {
            res.status(401).send("Unauthorized");
            logger.error('Password update failed', Datetime.now())
        } else {
            const newsalt = await bcrypt.genSalt();
            const newhashedPassword = await bcrypt.hash(newpassword, newsalt);
            const result = await mongoose.model('User').updateOne({ id: userId }, { $set: { password: newhashedPassword } });
            res.status(200).send("Ok");
            logger.info('Password updated successfully', Datetime.now())
        }
    } catch (error) {
        res.status(500).send("Internal Server Error")
    } finally {
        mongoose.connection.close();
    }


});

app.post('/2fa-enable', validateApiKey, async (req, res) => {
    const jwt = req.cookies.jwt;
    const decoded = jwt.decode(jwt)
    const userId = decoded.id
    const code = uuidv4();
    const email = req.body.email;
    try {

        const subjectt = '2FA Code'
        const textt = `Your code is ${code}`
        const mailOptions = {
            from: process.env[email],
            to: email,
            subject: subjectt,
            text: textt
        }
        transporter.sendMail(mailOptions, (err, data) => {
            if (err) {
                res.status(500).send("Internal Server Error");
                logger.error(err, Datetime.now());
            } else {
                res.status(200).send("Ok");
                logger.info('2fa code sent', Datetime.now())
            }
        })
        redisClient.set(userId, code, 'EX', 300)

        res.status(200).send("Ok");
        logger.info('2fa code sent', Datetime.now())
    } catch (error) {
        res.status(500).send("Internal Server Error")
        logger.error(error, Datetime.now());
    } finally {
        redisClient.quit();
        mongoose.connection.close();
    }
});

app.put('/2fa-enable-update', validateApiKey, async (req, res) => {
    const jwt = req.cookies.jwt;
    const decoded = jwt.decode(jwt)
    const userId = decoded.id
    const code = req.body.code;

    try {
        redisClient(userId, async (err, reply) => {
            if (err) {
                res.status(500).send("Internal Server Error")
                logger.error(err, Datetime.now());

            }
            if (reply === code) {
                const result = await mongoose.model('User').updateOne({ id: userId }, { $set: { twofactor: true } });
                res.status(200).send("Ok");
                logger.info('2fa enabled successfully', Datetime.now())
            } else {
                res.status(401).send("Unauthorized");
                logger.error('2fa enable failed', Datetime.now())
            }
        })
    } catch (error) {
        res.status(500).send("Internal Server Error")
        logger.error(error, Datetime.now());
    } finally {
        redisClient.quit();
        mongoose.connection.close();
    }
}
);

app.post('/2fa-disable', validateApiKey, async (req, res) => {
    const jwt = req.cookies.jwt;
    const decoded = jwt.decode(jwt)
    const userId = decoded.id
    const code = uuidv4();
    const email = req.body.email;
    try {

        const subjectt = '2FA Code'
        const textt = `Your code is ${code}`
        const mailOptions = {
            from: process.env[email],
            to: email,
            subject: subjectt,
            text: textt
        }
        transporter.sendMail(mailOptions, (err, data) => {
            if (err) {
                res.status(500).send("Internal Server Error");
                logger.error(err, Datetime.now());
            } else {
                console.log('Email sent')
            }
        })
        redisClient.set(userId, code, 'EX', 300)

        res.status(200).send("Ok");
        logger.info('2fa code sent', Datetime.now())
    } catch (error) {
        res.status(500).send("Internal Server Error")
        logger.error(error, Datetime.now());
    } finally {
        redisClient.quit();
        mongoose.connection.close();
    }
}
);
app.put('/2fa-disable-update', validateApiKey, async (req, res) => {
    const jwt = req.cookies.jwt;
    const decoded = jwt.decode(jwt)
    const userId = decoded.id
    const code = req.body.code;
    try {
        redisClient(userId, async (err, reply) => {
            if (err) {
                res.status(500).send("Internal Server Error")
                logger.error(err, Datetime.now());

            }
            if (reply === code) {
                const result = await mongoose.model('User').updateOne({ id: userId }, { $set: { twofactor: false } });
                res.status(200).send("Ok");
                logger.info('2fa disabled successfully', Datetime.now())
            } else {
                res.status(401).send("Unauthorized");
                logger.error('2fa disable failed', Datetime.now())
            }
        })
    } catch (error) {
        res.status(500).send("Internal Server Error")
        logger.error(error, Datetime.now());
    } finally {
        redisClient.quit();
        mongoose.connection.close();
    }
}
);

app.post('/verify-email', async (req, res) => {
    const userId = req.query.id;
    try {
        const result = await mongoose.model('User').updateOne({ id: userId }, { $set: { emailVerified: true } });
        res.status(200).send("Ok");
        logger.info('Email verified successfully', Datetime.now())
    } catch (error) {
        res.status(500).send("Internal Server Error")
        logger.error(error, Datetime.now());
    } finally {
        mongoose.connection.close();
    }
}
);





const server = https.createServer(options, app);

server.listen(3000, () => {
  console.log('Server listening on port 3000 with SSL');
});
