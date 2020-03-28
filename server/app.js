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

app.use(express.json());       // to support JSON-encoded bodies
app.use(express.urlencoded()); // to support URL-encoded bodies

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
                        var token_iqs = "INSERT INTO auth_token(token, ref_id, token_type) VALUES (?,?, (SELECT token_type_id FROM lut_token_types WHERE token_type_desc = 'user'))"
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
app.post('/ajax/getAddDeviceForm', require_token, (req, res) => {
    res.sendFile('./html/pieces/addDevice.ejs', { root: __dirname })
})
app.post('/ajax/getDevices', require_token, (req, res) => {
    var token =  req.cookies['token']
    var userId_sqs = "SELECT user_id FROM auth_token LEFT JOIN auth_user ON auth_user.user_id = auth_token.ref_id WHERE token_type = (SELECT token_type_id FROM lut_token_types WHERE token_type_desc = 'user' AND active = true AND token = ?)"
    db.query(userId_sqs, [token], (err, result) => {
        var owner_id = result[0].user_id
        var devices_sqs = "SELECT device_id FROM device WHERE owner_id = ?"
        db.query(devices_sqs, [owner_id], (err, result) => {
            res.send(result)
        })
    })
})
app.post('/ajax/getDeviceDisplay', require_token, (req, res) => {
    var device_id = req.body.device_id
    var device_info_sqs = "SELECT * FROM device WHERE device_id = ?"
    db.query(device_info_sqs, [device_id], (err, result) => {
        res.render('pieces/device', {
            device_id: result[0].device_id,
            device_name: result[0].device_name, 
            device_status : "Online"
        })
    })
});

app.post('/ajax/addDevice', require_token, (req, res) => {
    var device_name = req.body.device_name
    var token =  req.cookies['token']
    var userId_sqs = "SELECT user_id FROM auth_token LEFT JOIN auth_user ON auth_user.user_id = auth_token.ref_id WHERE token_type = (SELECT token_type_id FROM lut_token_types WHERE token_type_desc = 'user' AND active = true AND token = ?)"
    db.query(userId_sqs, [token], (err, result) => {
        var owner_id = result[0].user_id
        var device_iqs = "INSERT INTO device(device_name, owner_id) VALUES (?,?)"
        db.query(device_iqs, [device_name, owner_id], (err, result) => {
            res.send(result.affectedRows > 0)
        })
    })
})

app.post('/ajax/getDeviceDetail', require_token, (req, res) => {
    var device_id = req.body.device_id
    var token =  req.cookies['token']
    var userId_sqs = "SELECT user_id FROM auth_token LEFT JOIN auth_user ON auth_user.user_id = auth_token.ref_id WHERE token_type = (SELECT token_type_id FROM lut_token_types WHERE token_type_desc = 'user' AND active = true AND token = ?)"
    db.query(userId_sqs, [token], (err, result) => {
        var user_id = result[0].user_id
        var link_query_sqs = "SELECT link_id FROM device_link A WHERE A.user_id = ? AND A.device_id = ? AND linked = true"
        db.query(link_query_sqs, [user_id, device_id], (err, result) => {
            var linked = false
            //If Device IS LINKED
            if(result && result.length > 0){
                linked = true
                link_code = result[0].link_code
                res.render('pieces/deviceDetail', {
                    linked: linked,
                    link_code: link_code
                })
                return
            //If Device IS NOT LINKED
            } else {
                linked = false
                link_code = Math.floor(100000 + Math.random() * 900000)
                var link_query_iqs = "INSERT INTO device_link(device_id, user_id, link_code) VALUES (?,?,?)"
                db.query(link_query_iqs, [device_id, user_id, link_code], (err, result) => {
                    res.render('pieces/deviceDetail', {
                        linked: linked,
                        link_code: link_code
                    })
                    return
                })
            }
        })
    })
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