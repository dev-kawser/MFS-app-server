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

// MongoDB connection
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.euq4zn2.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;
const client = new MongoClient(uri, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
    }
});

// Middleware for JWT verification
const verifyJWT = async (req, res, next) => {
    const authHeader = req.headers['authorization'];
    if (!authHeader) {
        return res.status(403).send('A token is required for authentication');
    }

    const token = authHeader.split(' ')[1];
    if (!token) {
        return res.status(403).send('A token is required for authentication');
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;
        next();
    } catch (err) {
        return res.status(401).send('Invalid Token');
    }
};

// Middleware for PIN verification
const verifyPin = async (req, res, next) => {
    const { pin } = req.body;

    // Ensure `userCollection` is defined inside this function
    const userCollection = client.db("scicTask").collection("users");

    const user = await userCollection.findOne({ _id: new ObjectId(req.user.id) });

    if (!user) {
        return res.status(400).send('User not found');
    }

    const isPinValid = await bcrypt.compare(pin, user.pin);
    if (!isPinValid) {
        return res.status(400).send('Invalid PIN');
    }

    next();
};

// Middleware for Agent Validation
const verifyAgent = async (req, res, next) => {
    const userId = req.user.id;
    const userCollection = client.db("scicTask").collection("users");

    const user = await userCollection.findOne({ _id: new ObjectId(userId) });

    if (!user || user.role !== 'agent') {
        return res.status(403).send('Access denied. Not an agent.');
    }

    next();
};


async function run() {
    try {
        // Connect the client to the server
        await client.connect();

        const userCollection = client.db("scicTask").collection("users");
        const transactionsCollection = client.db("scicTask").collection("transactions");

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
                action: 'active',
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

            if (user.status !== 'approved') {
                return res.status(403).send('User not approved');
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

        // Update user action (activate or block)
        app.patch('/users/action/:id', verifyJWT, async (req, res) => {
            const { id } = req.params;
            const { action } = req.body;
            const result = await userCollection.updateOne({ _id: new ObjectId(id) }, { $set: { action } });
            res.send(result);
        });

        // Update user status and add balance if approved
        app.patch('/users/status/:id', verifyJWT, async (req, res) => {
            const { id } = req.params;
            const { status } = req.body;

            try {
                // Find the user by ID
                const user = await userCollection.findOne({ _id: new ObjectId(id) });

                if (!user) {
                    return res.status(404).send({ message: 'User not found' });
                }

                const updateFields = { status };

                // Check if the status is approved
                if (user.role === 'user' && status === 'approved') {
                    updateFields.balance = (user.balance || 0) + 40; // Add 40 Taka to balance

                    // If the user is an agent and has not received the 10,000 Taka bonus
                    if (user.role === 'agent' && user.balance === 0) {
                        updateFields.balance += 10000; // Add 10,000 Taka to balance
                    }
                }

                // Update the user's status and balance
                const result = await userCollection.updateOne({ _id: new ObjectId(id) }, { $set: updateFields });

                res.send(result);
            } catch (error) {
                console.error('Error updating user status:', error);
                res.status(500).send({ message: 'Internal server error' });
            }
        });


        // Send money api
        app.post('/send-money', verifyJWT, verifyPin, async (req, res) => {
            const { recipient, amount } = req.body;
            const { id } = req.user;

            if (amount < 50) {
                return res.status(400).send({ message: 'Minimum transaction amount is 50 Taka.' });
            }

            const userCollection = client.db("scicTask").collection("users");

            const sender = await userCollection.findOne({ _id: new ObjectId(id) });
            const recipientUser = await userCollection.findOne({ mobileNumber: recipient });

            if (!recipientUser) {
                return res.status(400).send({ message: 'Recipient not found.' });
            }

            let fee = 0;
            if (amount > 100) {
                fee = 5;
            }

            const totalAmount = parseFloat(amount) + fee;

            if (sender.balance < totalAmount) {
                return res.status(400).send({ message: 'Insufficient balance.' });
            }

            const session = client.startSession();
            session.startTransaction();

            try {
                await userCollection.updateOne(
                    { _id: new ObjectId(id) },
                    { $inc: { balance: -totalAmount } },
                    { session }
                );
                await userCollection.updateOne(
                    { _id: new ObjectId(recipientUser._id) },
                    { $inc: { balance: parseFloat(amount) } },
                    { session }
                );

                const transaction = {
                    senderId: id,
                    recipientId: recipientUser._id,
                    amount: parseFloat(amount),
                    fee,
                    date: new Date()
                };

                await transactionsCollection.insertOne(transaction, { session });

                await session.commitTransaction();
                res.send({ message: 'Transaction successful.' });
            } catch (error) {
                await session.abortTransaction();
                res.status(500).send({ message: 'Transaction failed.' });
            } finally {
                session.endSession();
            }
        });

        // Transactions api
        app.get('/transactions', verifyJWT, async (req, res) => {
            const { id } = req.user;
            const transactions = await transactionsCollection.find({
                $or: [
                    { senderId: id },
                    { recipientId: id }
                ]
            }).sort({ date: -1 }).limit(10).toArray();
            res.send(transactions);
        });

        app.get('/agent-transactions', verifyJWT, verifyAgent, async (req, res) => {
            const { id: agentId } = req.user;
            const transactions = await transactionsCollection.find({
                $or: [
                    { agentId: agentId },
                ]
            }).sort({ date: -1 }).limit(20).toArray();
            res.send(transactions);
        });


        app.get('/allTransactions', verifyJWT, async (req, res) => {
            const transactions = await transactionsCollection.find().toArray();
            res.send(transactions);
        });

        // Cash-In api
        app.post('/cash-in', verifyJWT, verifyPin, async (req, res) => {
            const { agentId, amount } = req.body;
            const { id: userId } = req.user;

            try {
                const agent = await userCollection.findOne({ _id: new ObjectId(agentId) });
                if (!agent) {
                    return res.status(400).send({ message: 'Agent not found.' });
                }

                if (agent.balance < amount) {
                    return res.status(400).send({ message: 'Agent has insufficient balance.' });
                }

                const pendingTransaction = {
                    userId,
                    agentId,
                    amount: parseFloat(amount),
                    type: 'cash-in',
                    status: 'pending',
                    date: new Date()
                };

                await transactionsCollection.insertOne(pendingTransaction);
                res.send({ message: 'Cash-In request submitted and is pending approval.' });
            } catch (error) {
                res.status(500).send({ message: 'Cash-In failed.', error });
            }
        });


        // Cash-Out api
        app.post('/cash-out', verifyJWT, verifyPin, async (req, res) => {
            const { agentId, amount } = req.body;
            const { id: userId } = req.user;

            try {
                const user = await userCollection.findOne({ _id: new ObjectId(userId) });
                if (!user) {
                    return res.status(400).send({ message: 'User not found.' });
                }

                const agent = await userCollection.findOne({ _id: new ObjectId(agentId) });
                if (!agent) {
                    return res.status(400).send({ message: 'Agent not found.' });
                }

                const fee = amount * 0.015;
                const totalDeduction = parseFloat(amount) + fee;

                if (user.balance < totalDeduction) {
                    return res.status(400).send({ message: 'User has insufficient balance.' });
                }

                const pendingTransaction = {
                    userId,
                    agentId,
                    amount: parseFloat(amount),
                    fee,
                    type: 'cash-out',
                    status: 'pending',
                    date: new Date()
                };

                await transactionsCollection.insertOne(pendingTransaction);
                res.send({ message: 'Cash-Out request submitted and is pending approval.' });
            } catch (error) {
                res.status(500).send({ message: 'Cash-Out failed.', error });
            }
        });



        // Get all agents
        app.get('/agents', verifyJWT, async (req, res) => {
            const userCollection = client.db("scicTask").collection("users");
            const agents = await userCollection.find({ role: 'agent' }).toArray();
            res.send(agents);
        });

        app.get('/agent-transactions', verifyJWT, async (req, res) => {
            const { id } = req.user;
            try {
                const transactions = await transactionsCollection.find({
                    $or: [
                        { userId: id },
                        { agentId: id }
                    ]
                }).sort({ date: -1 }).limit(20).toArray();
                res.send(transactions);
            } catch (error) {
                console.error('Error fetching agent transactions:', error);
                res.status(500).send({ message: 'Failed to fetch transactions.' });
            }
        });


        // Approve or Reject a transaction
        app.patch('/approve-transaction/:id', verifyJWT, verifyAgent, async (req, res) => {


            const { id } = req.params;
            const { approve } = req.body;


            if (typeof approve !== 'boolean') {
                return res.status(400).send({ message: 'Invalid approve value.' });
            }

            const session = client.startSession();
            session.startTransaction();

            try {
                const transaction = await transactionsCollection.findOne({ _id: new ObjectId(id) });


                if (!transaction || transaction.status !== 'pending') {
                    return res.status(400).send({ message: 'Transaction not found or already processed.' });
                }

                if (approve) {
                    if (transaction.type === 'cash-in') {
                        await userCollection.updateOne(
                            { _id: new ObjectId(transaction.userId) },
                            { $inc: { balance: transaction.amount } },
                            { session }
                        );
                        await userCollection.updateOne(
                            { _id: new ObjectId(transaction.agentId) },
                            { $inc: { balance: -transaction.amount } },
                            { session }
                        );
                    } else if (transaction.type === 'cash-out') {
                        const fee = transaction.fee;
                        const totalDeduction = transaction.amount + fee;

                        await userCollection.updateOne(
                            { _id: new ObjectId(transaction.userId) },
                            { $inc: { balance: -totalDeduction } },
                            { session }
                        );
                        await userCollection.updateOne(
                            { _id: new ObjectId(transaction.agentId) },
                            { $inc: { balance: transaction.amount } },
                            { session }
                        );
                    }
                }

                await transactionsCollection.updateOne(
                    { _id: new ObjectId(id) },
                    { $set: { status: approve ? 'approved' : 'rejected' } },
                    { session }
                );

                await session.commitTransaction();
                res.send({ message: `Transaction ${approve ? 'approved' : 'rejected'} successfully.` });
            } catch (error) {
                await session.abortTransaction();
                res.status(500).send({ message: 'Transaction processing failed.', error });
            } finally {
                session.endSession();
            }
        });









        // Get pending transactions for an agent
        app.get('/pending-transactions', verifyJWT, verifyAgent, async (req, res) => {
            const { id: agentId } = req.user;
            try {
                
                const transactions = await transactionsCollection.find({
                    agentId: agentId,
                    status: 'pending' // Ensure that only pending transactions are fetched
                }).sort({ date: -1 }).toArray(); // Log the fetched transactions
                res.send(transactions);
            } catch (error) {
                console.error('Error fetching pending transactions:', error);
                res.status(500).send({ message: 'Failed to fetch pending transactions.' });
            }
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
