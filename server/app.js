const express = require('express')
const app = express()
const cookieParser = require('cookie-parser')
app.use(cookieParser())

const path = require('path');
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
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, '/html'));
//Express middleware requiring token for page.
function require_token(req, res, next) {
    if(req.params['token'])
        token = req.params['token']
    else
        token = req.cookies['token']
    if(token === undefined){
        res.redirect('/login')
        return
    }
    var token_sqs = "SELECT * FROM auth_token WHERE CURRENT_TIMESTAMP < date + INTERVAL 24 HOUR AND active = 1 AND token = ?"
    var result = db.query(token_sqs, token, (err, result) =>{
        if (result.length <= 0){
            res.cookie('token', "", {
                maxAge: -1// Remove Cookie
            })
            res.redirect('/login')
        }
        else
            next();
    })
}
app.get('/', require_token, (req, res) => {
    var username_sqs = "SELECT * FROM auth_user A LEFT JOIN auth_token B ON B.ref_id = A.user_id WHERE token = ?"
    db.query(username_sqs, [req.cookies['token']], (err, username_result) => {
        res.render('index', 
            {
                username: username_result[0]['username']
            })
    })
})
app.get('/login', (req, res) => {
    query = req.query
    if(req.cookies['token']){
        var token_sqs = "SELECT * FROM auth_token WHERE CURRENT_TIMESTAMP < date + INTERVAL 24 HOUR AND active = 1 AND token = ?"
        var result = db.query(token_sqs, req.cookies['token'], (err, result) =>{
            if (result.length > 0){
                res.redirect('/')
                return;
            }else{
                res.cookie('token', "", {
                    maxAge: -1 // unset cookie
                })
                res.redirect('/login');
                return;
            }
        })
    } else{
        if(!query['username'] || !query['password']){
            res.sendFile('./html/login.html', { root: __dirname })
        }
        else{
            var username = query['username']
            var password = query['password']
            
            //Check if username even exists
            var username_sqs = "SELECT * FROM auth_user WHERE username = ?"
            db.query(username_sqs, [username], (err, username_result) => {
                if(username_result.length <= 0){
                    res.redirect('/login?error=Invalid%20Credentials')
                    return;
                }
                var user_id = username_result[0]['user_id']
                var secret_sqs = "SELECT * FROM auth_secret WHERE secret_id = ?"
                db.query(secret_sqs, [username_result[0]['secret_id']], (err, secret_result) => {
                    var user_password = secret_result[0]['password_hash']
                    var password_hash = crypto.createHmac('sha512', secret_result[0]['password_salt']).update(password).digest('base64')
                    if(user_password === password_hash){
                        var token = uuidv4()
                        var token_iqs = "INSERT INTO auth_token(token, user_id) VALUES (?,?)"
                        db.query(token_iqs, [token, user_id], (err, res3) => {
                            res.cookie('token', token, {
                                maxAge: 24 * 60 * 60 * 1000 // 1 Day login
                            })
                            res.redirect('/')
                            return
                        })
                    }
                })
            })
        }
    }

})
app.get('/logout', (req,res) => {
    if(req.cookies['token']){
        var disable_token = "UPDATE auth_token SET active=false WHERE token=?"
        db.query(disable_token, [req.cookies['token']], (err, result) => {
            res.cookie('token', "", {
                maxAge: -1 // unset cookie
            })
            res.redirect('/')
            return
        })
    }else{
        res.redirect('/')
        return
    }
});
app.get('/register', (req, res) => {
    query = req.query
    if(req.cookies['token']){
        var token_sqs = "SELECT * FROM auth_token WHERE CURRENT_TIMESTAMP < date + INTERVAL 24 HOUR AND active = 1 AND token = ?"
        var result = db.query(token_sqs, req.cookies['token'], (err, result) =>{
            if (result.length > 0){
                res.redirect('/')
                return;
            }else{
                res.cookie('token', "", {
                    maxAge: -1 // unset cookie
                })
                res.redirect('/register')
                return;
            }
        })
    } else{
        if(!query['username'] || !query['password'] || !query['email'])
        res.sendFile('./html/register.html', { root: __dirname })
        else{
            console.log(query)
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
                    db.query(user_iqs, [username, email, secret_id], (err, res2) => {
                        var user_id = res2.insertId
                        //User is registered, log them in
                        var token = uuidv4()
                        var token_iqs = "INSERT INTO auth_token(token, ref_id, token_type) VALUES (?,?, (SELECT token_type_id FROM lut_token_types WHERE token_type_desc = 'user'))"
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
    }
})
app.post('/ajax/getAddDeviceForm', (req, res) => {
    res.sendFile('./html/form/')
})
app.post('/ajax/generateDevice', (req, res) => {
    
    res.send('Hello?')
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