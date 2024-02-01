//[✅]Config inicial
require('dotenv').config()
const express = require('express')
const mongoose = require('mongoose')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')

const app = express()

//[✅]Config JSON
app.use(express.json())

//[✅]Models
const User = require('./models/User')

//[✅]Rota pública
app.get('/', (req, res) => {
    res.status(200).json({ msg: "Bem vindo a API"})
})

//[✅]Rota privada
app.get('/users/:id', checkToken, async (req, res) => {
    const id = req.params.id

    //[✅]Checkar se usuário existe
    const user = await User.findById(id, '-password')

    if(!user) {
        return res.status(404).json({ msg: "Usuário não encontrado."})
    }

    res.status(200).json({ user })
})

//[✅]Checkar token
function checkToken(req, res, next){
    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(' ')[1]

    if(!token) {
        return res.status(401).json({ msg: "Acesso negado!" })
    }

    try {

        const secret = process.env.SECRET
        jwt.verify(token, secret)
        next()
        
    } catch (error) {

        res.status(400).json({ msg: "Token inválido!" })

    }
}

//[✅]Registrar usuário
app.post('/auth/register', async(req, res) => {

    const {name, email, password, confirmpassword} = req.body

    //[✅]Validação
    if(!name) {
        return res
        .status(422)
        .json({ msg: "Nome é obrigatório!" })
    }

    if(!email) {
        return res
        .status(422)
        .json({ msg: "Email é obrigatório!" })
    }

    if(!password) {
        return res
        .status(422)
        .json({ msg: "Senha é obrigatório!" })
    }

    if(password != confirmpassword){
        return res
        .status(422)
        .json({ msg: "As senhas não conferem." })
    }

    //[✅]Check de usuário existente
    const userExists = await User.findOne({ email:email })

    if(userExists) {
        return res
        .status(422)
        .json({ msg: "Email já cadastrado" })
    }

    //[✅]Criar senha
    const salt = await bcrypt.genSalt(12)
    const passwordHash = await bcrypt.hash(password, salt)

    //[✅]Criar usuário
    const user = new User({
        name, 
        email,
        password: passwordHash,
    })

    try {
        
        await user.save()
        res.status(201).json({ msg:"Usuário criado com sucesso!"})

    } catch (error) {

        console.log(error)
        res.status(500).json({ msg: "Houve um erro, tente novamente mais tarde" })

    }
})

//[✅]Login usuário
app.post('/auth/login', async (req, res) => {
    const {email, password} = req.body

    //[✅]Validações
    if(!email) {
        return res
        .status(422)
        .json({ msg: "Email é obrigatório!" })
    }

    if(!password) {
        return res
        .status(422)
        .json({ msg: "Senha é obrigatório!" })
    }

    //[✅]Checkar se o usuário existe
    const user = await User.findOne({ email:email })

    if(!user) {
        return res
        .status(404)
        .json({ msg: "Usuário não encontrado" })
    }
 
    //[✅]Checkar senha
    const checkPassword = bcrypt.compare(password, user.password)

    if(!checkPassword) {
        return res
        .status(422)
        .json({ msg: "Senha inválida" })
    }

    //[✅]Envio de autenticação
    try {

        const secret = process.env.secret
        const token = jwt.sign(
            {
                id: user._id
            },
            secret
        )

        res.status(200).json({ msg: "Autenticação enviada com sucesso", token})

    } catch (error) {
        
        console.log(error)
        res.status(422).json({ msg: "Ocorreu um erro, tente novamente mais tarde"})

    }
})

//[✅]Conexão banco de dados
mongoose
    .connect(`mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASSWORD}@authapi.8aw58se.mongodb.net/authTest?retryWrites=true&w=majority`)
    .then(() => {
        console.log("Conectado ao banco")
    })
    .catch((err) => console.log(err))

app.listen(3000)