const _ = require('lodash')
const jwt = require('jsonwebtoken')
const bcrypt = require('bcrypt')
const User = require('./user')
const env = require('../../config/.env')

const emailRegex = /\S+@\S+\.\S+/
const passwordRegex = /((?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%]).{6,20})/


const sendErros = (res, dbErros) => {
    const errors = []    

    if(dbErros.errors){
        _.forIn(dbErros.errors, error => errors.push(error.message))
    } else if (dbErros.length > 0){
       errors.push(dbErros)
    }
    console.log('erros:', errors)
    return res.status(400).json({errors})
}

const generateJwtToken = user => {
    return jwt.sign(user, env.authSecret, {
        expiresIn: "1h"
    })
}

const validateSignup = (email, password, confirmPassword, passwordHash) => {
    const errors = []
    if(!email.match(emailRegex)){
        errors.push('O e-mail informado é inválido!')
    }

    if(!password.match(passwordRegex)){        
            errors.push(
                "Senha precisar ter: uma letra maiúscula, uma letra minúscula, um número, uma caractere especial(@#$%) e tamanho entre 6-20."
            )        
    }
    
    if(!bcrypt.compareSync(confirmPassword, passwordHash)){
        errors.push('Senhas não conferem.')
    }

    return errors.length > 0 ? errors : null
}

const login = (req, res, next) => {
    const email = req.body.email || ''
    const password = req.body.password || ''
        
    User.findOne({email}, (err, user) => {
        if(err){
            return sendErros(res, err)
        } else if (user && bcrypt.compareSync(password, user.password)){
            const token = generateJwtToken(user)
            const {name, email} = user
            res.json({ name, email, token })
        } else {
            return res.status(400).send({erros: ['Usuário/Senha inválidos!']})
        }
    })
}

const validateToken = (req, res, next) => {
    const token = req.body.token || ''
    jwt.verify(token, env.authSecret, function(err, decoded){
        return res.status(200).send({valid: !err})
    })
}

const signup = (req, res, next) => {
    const email = req.body.email || ''
    const name = req.body.name || ''
    const password = req.body.password || ''
    const confirmPassword = req.body.confirm_password || ''
    const salt = bcrypt.genSaltSync()
    const passwordHash = bcrypt.hashSync(password, salt)
    const errors = validateSignup(email, password, confirmPassword, passwordHash)
    
    if(errors)
    {
        return sendErros(res, errors)
    }

    User.findOne({email}, (err, user) =>{
        if(err){
            return sendErros(res, err)
        } else if (user) {
            return res.status(400).send({errors: ['Usuário já cadastrado.']})
        } else {
            const newUser = new User({name, email, password: passwordHash})
            newUser.save(err => {
                if (err) {
                    return sendErros(res, err)
                } else {
                    login(req, res, next)
                }
            })
        }
    })
}

module.exports = {login, signup, validateToken}