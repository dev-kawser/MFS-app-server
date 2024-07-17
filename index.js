const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 5000;

// Middleware
app.use(cors({
    origin: [
        'http://localhost:5173',
    ]
}));
app.use(express.json());

const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.euq4zn2.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
    }
});

async function run() {
    try {
        // Connect the client to the server
        await client.connect();

        const userCollection = client.db("scicTask").collection("users");

        // Middleware for JWT verification
        const verifyToken = (req, res, next) => {
            const token = req.headers.authorization?.split(' ')[1]; // Authorization: 'Bearer TOKEN'
            if (!token) return res.status(401).send('Access Denied');

            try {
                const verified = jwt.verify(token, process.env.JWT_SECRET);
                req.user = verified;
                next();
            } catch (err) {
                res.status(400).send('Invalid Token');
            }
        };

        // User registration
        app.post('/register', async (req, res) => {
            const { name, mobileNumber, email, pin, role } = req.body;
            const hashedPin = await bcrypt.hash(pin, 10);

            const newUser = {
                name,
                mobileNumber,
                email,
                pin: hashedPin,
                role,
                status: 'pending',
                balance: role === 'user' ? 0 : 10000,
            };

            const result = await userCollection.insertOne(newUser);
            res.send(result);
        });

        // User login
        app.post('/login', async (req, res) => {
            const { mobileOrEmail, pin } = req.body;

            const user = await userCollection.findOne({
                $or: [{ mobileNumber: mobileOrEmail }, { email: mobileOrEmail }]
            });

            if (!user) {
                return res.status(400).send('User not found');
            }

            const isPinValid = await bcrypt.compare(pin, user.pin);
            if (!isPinValid) {
                return res.status(400).send('Invalid PIN');
            }

            const token = jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1h' });

            res.send({ token, user });
        });

        // Protected route example (requires JWT verification)
        app.get('/protected', verifyToken, (req, res) => {
            res.json(req.user);
        });

        // Send a ping to confirm a successful connection
        await client.db("admin").command({ ping: 1 });
        console.log("Pinged your deployment. You successfully connected to MongoDB!");
    } finally {
        // Ensures that the client will close when you finish/error
        // await client.close();
    }
}
run().catch(console.dir);

app.get('/', (req, res) => {
    res.send('server is running');
});

app.listen(port, () => {
    console.log(`server is running on port: ${port}`);
});
