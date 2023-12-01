'use strict'

const _USER = require('../resources/usuario');
const storage = require('localtoken');
const auth = require('../middlewares/auth');
const cript = require('bcryptjs');
const { check, validationResult } = require('express-validator');

// GET - página para registro de usuário
exports.getRegistro = async (req, res, next) => {
    try {
        return res.render('forms/usuario/registro');
    } catch(err) {
        next(err);
    }
}

// POST - registro de usuário
exports.postRegistro = [
    check('nome').isString(),
    check('email').isEmail(),
    check('senha').isLength({min: 5})
], async (req, res, next) => {
    const body = req.body;
    try {
        let errors = validationResult(req);
        if(errors.isLength() > 0) {
            return res.status(422).json({ errors: errors.array() });
        } else {
            const result = await _USER.verificarRegistro(body);
            if(!result) {
                await _USER.registrar(body);
                return res.redirect('/usuario/login');
            } else {
                console.log('Usuário já existe!');
                return res.render('forms/usuario/registro');
            } 
        }
    } catch(err) {
        next(err);
    }
}


// GET - página de login
exports.getLogin = (req, res, next) => {
    try {
        return res.render('forms/usuario/login');
    } catch (err) {
        next(err);
    }
}


// POST - autenticação e armazenamento do token
exports.postLogin = async (req, res, next) => {
    try {
        const result = await _USER.veriricarLogin(req.body);
        if(!result) {
            console.log('POST LOGIN: { Usuário não existe. }');
            res.render('forms/usuario/login');
        } else if (!await cript.compare(req.body.senha, result.senha)) {
            console.log('POST LOGIN: { Senha inválida. }');
            res.render('forms/usuario/login');
        } else {
            const token = await auth.generateToken({result});  
            storage.setInLocal('token', token);
            console.log('POST LOGIN: { Logado com sucesso. }');
            return res.redirect('home/_home');
        }
    } catch (err) {
        next(err);
    }
}


// GET - procedimento de logout
exports.logout = async (req, res, next) => {
    try {
        await storage.removeLocal('token');
        console.log('POST LOGOUT: { Deslogado com sucesso. }');
        return res.redirect('/');
    } catch (err) {
        next(err);
    }
}

exports.getAll = async (req, res, next) => {
    try {
        const result = await _USER.buscarTodos();
        return res.json(result);
    } catch (err) {
        next(err);
    }
}

