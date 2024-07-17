const express = require('express');
const cors = require('cors');
const jwt = require("jsonwebtoken");
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

// JWT middleware
const verifyJWT = (req, res, next) => {
    const token = req.headers['authorization'];
    if (!token) {
        return res.status(403).send('A token is required for authentication');
    }
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;
    } catch (err) {
        return res.status(401).send('Invalid Token');
    }
    return next();
};

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

        // Get all users
        app.get('/users', verifyJWT, async (req, res) => {
            const users = await userCollection.find().toArray();
            res.send(users);
        });

        // Search for a specific user by name
        app.get('/users/search', verifyJWT, async (req, res) => {
            const { name } = req.query;
            const users = await userCollection.find({ name: { $regex: name, $options: "i" } }).toArray();
            res.send(users);
        });

        // Activate or block a user
        app.patch('/users/:id', verifyJWT, async (req, res) => {
            const { id } = req.params;
            const { status } = req.body; // 'active' or 'blocked'
            const result = await userCollection.updateOne({ _id: new ObjectId(id) }, { $set: { status } });
            res.send(result);
        });

        // Update a user status
        app.patch('/users/status/:id', verifyJWT, async (req, res) => {
            const { id } = req.params;
            const { status } = req.body; //
            const result = await userCollection.updateOne({ _id: new ObjectId(id) }, { $set: { status } });
            res.send(result);
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
