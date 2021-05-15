const Router = require('express')
const User = require('../models/User')
const bcrypt = require('bcrypt')
const {check, validationResult} = require('express-validator')
const jwt = require('jsonwebtoken')
const config = require('config')

const router = new Router()

router.post('/registration',
  [
    check('email', 'Некорректный email').isEmail(),
    check('password', `Пароль должен быть от 6 до 13 символов`).isLength({min: 6, max: 13}),
  ],
  async (req, res) => {

    try {
      const errors = validationResult(req)
      if (!errors.isEmpty()) {
        return res.status(400).json({message: "Ошибка при регистрации!", errors})
      }

      const {email, password} = req.body

      const candidate = await User.findOne({email})
      if (candidate) {
        return res.status(400).json({message: "Пользователь с таким email уже существует!"})
      }
      const hashPassword = await bcrypt.hash(password, 6)
      const user = new User({email, password: hashPassword})
      await user.save()

      return res.json({message: 'Пользователь успешно зарегистрирован'}).status(201)

    } catch (e) {
      console.log(e)
      res.send({message: 'Ошибка сервера'}).status(500)
    }
  })

router.post('/login',
  async (req, res) => {

    try {
      const {email, password} = req.body
      let user = await User.findOne({email})
      if (!user) {
        return res.status(404).json({message: 'Пользователь не найден'})
      }
      const isPasswordValid = bcrypt.compareSync(password, user.password)
      if (!isPasswordValid) {
        return res.status(404).json({message: 'Неверный пароль'})
      }

      const token = jwt.sign({id: user.id}, config.get("secretKey"), {expiresIn: '1h'})
      return res.json({
        token, user: {
          id: user.id,
          email: user.email,
          diskSpace: user.diskSpace,
          usedSpace: user.usedSpace,
          avatar: user.avatar
        }
      })
    } catch (e) {
      console.log(e)
      res.send({message: 'Ошибка сервера'}).status(500)
    }
  })

module.exports = router