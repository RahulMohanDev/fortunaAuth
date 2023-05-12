import dotenv from 'dotenv'
import express from 'express'
import mongoose from 'mongoose'
import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'

dotenv.config()

// setting up the app
const app = express()
// adding basic middleware
app.use(express.json())

// connecting to db
mongoose.connect(process.env.MONGO_URL)

mongoose.connection.once('open', () => {
  console.log('Connected to Database')
})

// creating a user schema
const userSchema = new mongoose.Schema({
  userName: { type: String, required: true, unique: true },
  password: { type: String, required: true },
})

// creating a user model
const User = mongoose.model('User', userSchema)

//middleware
const auth = async (req, res, next) => {
  const token = req.header('Authorization')
  console.log(token);
  if (!token) {
    res.status(401).send('please login in')
    return;
  }

  try {
    jwt.verify(token, process.env.JWT_SECRET)
    next()
  } catch {
    res.status(401).send('please login in')
  }
}

// registering a user
app.post('/register', async (req, res) => {
  const { userName, password } = req.body
  try {
    const hashedPassword = await bcrypt.hash(
      password + process.env.SALT_STRING,
      Number(process.env.SALT_ROUNDS),
    )
    console.log(hashedPassword)
    const user = new User({ userName, password: hashedPassword })
    await user.validate()
    await user.save()
    res.status(201).send('User Registered')
  } catch (err) {
    res.status(400).send(err.message)
  }
})

// logging in a user
app.post('/login', async (req, res) => {
  const { userName, password } = req.body
  try {
    User.findOne({ userName })
      .then(async (user) => {
        const idValid = await bcrypt.compare(
          password + process.env.SALT_STRING,
          user.password,
        )
        if (idValid) {
          const token = jwt.sign(
            { _id: user.id, userName: user.userName },
            process.env.JWT_SECRET,
          )
          res.setHeader('Authorization', token).status(200).send('logged in')
        } else {
          res.status(400).send('Invalid Username or Password')
        }
      })
      .catch((err) => {
        res.status(400).send('Invalid Username or Password')
      })
  } catch (err) {
    res.status(400).send(err.message)
  }
})

app.get('/superSafe', auth, (req, res) => {
  res.send('you are logged in yo !')
})

app.listen(process.env.PORT, () => {
  console.log(`Server is listening on port ${process.env.PORT}`)
})
