const express = require('express')
require('./db/mongoose')
require('dotenv').config()
var cors = require('cors')
const app = express()

const userRouter = require('./routers/user')

const port = process.env.PORT || 4000

app.use(cors())
app.use(express.json())
app.use(userRouter)

app.listen(port, () => {
    console.log(`Server is up on port ${port}`);
})
