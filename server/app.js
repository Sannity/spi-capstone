const express = require('express')
const app = express()
const cookieParser = require('cookie-parser')
app.use(cookieParser())

const WebSocket = require('ws')
const mysql = require('mysql')
const url = require('url')
const wss = new WebSocket.Server({ port: 8080 })
const config = require('config')
const crypto = require('crypto')
const uuidv4 = require('uuid/v4')

const db = mysql.createConnection(config.get('db'))
db.connect((err) => {
    if (err) throw err;
    console.info("[Server] Database Connection Established")
});

/*
    HTTP Webserver
*/
function validate_token(sessionID) {
    if (sessionID > 0)
        return true
    else
        return true
}
function require_valid_session(req, res, next) {
    if (!validate_token(req.cookies['token']))
        res.redirect('/login')
    else
        return next();
}
app.get('/', require_valid_session, (req, res) => {
    res.cookie('session', '1')
    res.send("Done.")
})
app.get('/login', (req, res) => {
    res.sendFile('./html/login.html', { root: __dirname })
})
app.get('/register', (req, res) => {
    query = req.query
    if(!query['username'] || !query['password'] || !query['email'])
        res.sendFile('./html/register.html', { root: __dirname })
    else{
        var username = query['username']

        var user_sqs = "SELECT * FROM auth_user WHERE username = ?"
        db.query(user_sqs, [username], (err, resu) => {
            if(resu.length > 0){
                res.redirect('/register?error=Username%20Taken')   
                return
            }
            var password = query['password']
            var email = query['email']
    
            var password_salt = crypto.randomBytes(32).toString('base64')
            var password_hash = crypto.createHmac('sha512', password_salt).update(password).digest('base64')
    
            var pass_iqs = "INSERT INTO auth_secret(password_salt, password_hash) VALUES (?,?)"
            db.query(pass_iqs, [ password_salt, password_hash], (err, res1) => {
                var secret_id = res1.insertId;
                var user_iqs = "INSERT INTO auth_user(username, email_address, secret_id) VALUES(?,?,?)"
                db.query(user_iqs, [username, password, secret_id], (err, res2) => {
                    var user_id = res2.insertId
                    var token = uuidv4()
                    var token_iqs = "INSERT INTO auth_token(token, user_id) VALUES (?,?)"
                    db.query(token_iqs, [token, user_id], (err, res3) => {
                        res.cookie('token', token, {
                            maxAge: 24 * 60 * 60 * 1000 // 1 Day login
                        })
                        res.redirect('/login')
                        return
                    })
                })
            })
        })
    }
})
app.use('/css', express.static(__dirname + '/html/css'))

app.listen('8000', () => console.log('[Server] Web Server Started'))

/*
    Websocket Server
*/
wss.on('connection', (ws, req) => {
    //Parse URL and get query element
    var url_parts = url.parse(req.url, true)
    var query = url_parts.query

    //Check for API Key in query
    if (query['api_key'] !== config.get('api_key'))
        ws.close(4000, "Bad API key") //Drop any connection with the wrong API KEY

    /*
        Auth Process Begin
    */
    var authenticated = false

    //Check for token in query, this will indicate they are already logged in
    if (query['token'] && !authenticated)
        authenticated = validateToken(query['token'])
    //If that didnt work check for login credentials
    if (query['username'] && query['password'] && !authenticated)
        authenticated = validateUser()
    if (!authenticated)
        ws.close(4001, "Not Authorized")

})

/**
 * Checks if token is valid
 * @param {string} token 
 */
function validateToken(token) {
    return false;
}

/**
 * Check if username/password combination is okay
 * @param {string} username 
 * @param {string} password 
 */
function validateUser(username, password) {
    return false;
}