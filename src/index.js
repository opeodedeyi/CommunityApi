// Import required packages
const express = require('express')
require('./db/mongoose')
require('dotenv').config()
var cors = require('cors')
const app = express()


// Initialize the Express app
const userRouter = require('./routers/user')
const categoryRouter = require('./routers/category');
const groupRouter = require('./routers/group')
const commentRouter = require('./routers/comment')


// Set the port for the server, either from the environment variable or default to 4000
const port = process.env.PORT || 4000


// Middleware for handling CORS (Cross-Origin Resource Sharing) headers
app.use(cors())

// Middleware to parse incoming JSON data in request body
app.use(express.json())

// Register routers with the app
app.use(userRouter)
app.use(categoryRouter);
app.use(groupRouter);
app.use(commentRouter);

// Start the server on the specified port
app.listen(port, () => {
    console.log(`Server is up on port ${port}`);
})
