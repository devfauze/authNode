//[✅]User para collection com mongoose 
const mongoose = require('mongoose')

const User = mongoose.model('User', {
    //Dados do model User
    name: String,
    email: String,
    password: String
})

module.exports = User