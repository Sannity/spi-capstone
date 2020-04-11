const express = require('express')
const partials = require('express-partials');
const http = require('http')
const app = express()
const cookieParser = require('cookie-parser')
app.use(cookieParser())
app.use(partials())

const path = require('path');
const WebSocket = require('ws')
const mysql = require('mysql')
const url = require('url')
const wss = new WebSocket.Server({ noServer: true })
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

const server_name = "[Server] "
server_error = (message) => {
    console.error(server_name + message)
    process.exit(-1)
}
server_warn = (message) => {
    console.log(server_name + message)
}
server_msg = (message) => {
    console.log(server_name + message)
}
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
        var token =  req.cookies['token']
        var userId_sqs = "SELECT user_id FROM auth_token LEFT JOIN auth_user ON auth_user.user_id = auth_token.ref_id WHERE token_type = (SELECT token_type_id FROM lut_token_types WHERE token_type_desc = 'user' AND active = true AND token = ?)"
        db.query(userId_sqs, [token], (err, result) => {
            var owner_id = result[0].user_id
            var devices_sqs = "SELECT device_id FROM device WHERE owner_id = ?"
            db.query(devices_sqs, [owner_id], (err, result) => {
                res.render('index', 
                {
                    username: username_result[0]['username'],
                    ws_remote: config.get("self_server.address")+":"+config.get("self_server.ws_port"),
                    api_key: config.get('api_key'),
                    token: token
                })
            })
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
            res.render('login')
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
app.get('/api/nwSpeed', (req,res) => {
    res.send(crypto.randomBytes(10000000))
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
    var link_query_sqs = "SELECT * FROM auth_token WHERE token_type=(SELECT token_type_id FROM lut_token_types WHERE token_type_desc = 'device') AND active = true AND ref_id = ?"
    db.query(link_query_sqs, [device_id], (err, result) => {
        var linked = false
        //If Device IS LINKED
        if(result && result.length > 0){
            var user_id = result[0].device_id
            linked = true
            res.render('pieces/deviceDetail', {
                linked: linked,
                link_code: ""
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

app.use('/css', express.static(__dirname + '/html/css'))

var webserver = http.createServer(app).listen('8000', () => server_msg('Web Server Started'))

webserver.on('upgrade', function upgrade(request, socket, head) {
    wss.handleUpgrade(request, socket, head, function done(ws) {
        wss.emit('connection', ws, request);
    });
});

/*
    Websocket Server
*/
device_update_buffer = {}
class DataUpdate{
    constructor(source_id, data){
        this.data_source = source_id
        this.connection_speed = data.connection_speed
        this.updates = data.updates
    }
    buffer(){
        if(!device_update_buffer[this.data_source])
            device_update_buffer[this.data_source] = []
        device_update_buffer[this.data_source].push(this)
    }
}

class ClientMessage{
    constructor(message){
        this.message = JSON.parse(message)    
    }
    process(calling_ws){
        var query_result = { meta: {}, data:{} }
        if(this.message['meta']['type'] == 'link'){
            var link_code =  this.message['data']['code']
            var link_code_sqs = "SELECT * FROM device_link WHERE link_code = ? AND linked = false"
            db.query(link_code_sqs, [link_code], (err, link_code_sresult) =>{
                if(err || link_code_sresult.length <= 0){
                    query_result['meta']['type'] = "link_result"
                    query_result['data']['success'] = false
                    query_result['data']['message'] = "Problem Finding Link Code"
                    calling_ws.send(JSON.stringify(query_result))
                    return
                }
                var device_id = link_code_sresult[0]['device_id']
                var token = uuidv4()
                var device_link_dqs = "DELETE FROM device_link WHERE link_code = ?"
                db.query(device_link_dqs, [link_code], (err, link_delete_result) => {
                    var token_iqs = "INSERT INTO auth_token(token, ref_id, token_type) VALUES (?,?, (SELECT token_type_id FROM lut_token_types WHERE token_type_desc = 'device'))"
                    db.query(token_iqs, [token, device_id], (err, token_result) => {
                        query_result['meta']['type'] = "link_result"
                        query_result['data']['success'] = false
                        if(err){
                            query_result['data']['message'] = "Problem Getting Token"
                            calling_ws.send(JSON.stringify(query_result))
                        }   
                        else if (token_result.affectedRows <= 0){
                            query_result['data']['message'] = "Problem Getting Token"
                            calling_ws.send(JSON.stringify(query_result))
                        }   
                        else {
                            var device_sqs = "SELECT * FROM device WHERE device_id = ?"
                            db.query(device_sqs, [device_id], (err, device_result) => {
                                calling_ws.device_id = device_id;
                                server_msg("Device "+query_result['data']['device_name']+" has joined")
                                query_result['data']['success'] = true
                                query_result['data']['token'] = token
                                query_result['data']['device_name'] = device_result[0]['device_name']
                                calling_ws.send(JSON.stringify(query_result))
                            })
                        }
                    })
                })
            })
        } else{
            var response = {
                meta:{
                    type: "error"
                },
                data: {

                }
            }
            var token_valid_sqs = "SELECT * FROM auth_token WHERE token = ? AND active = true"
            var token = this.message['meta']['token']
            db.query(token_valid_sqs, [token], (err, token_result) => {
                if(err || !token_result || token_result.length <= 0){
                    server_warn("Problem w/ Token")
                    response.meta.type = "error"
                    response.data['message'] = "Problem w/ Token"
                    calling_ws.send(JSON.stringify(response))
                    calling_ws.terminate()
                    return
                }else{
                    var device_id = token_result[0]['ref_id']
                    calling_ws.device_id = device_id
                    calling_ws.isAuthed = true
                    switch (this.message.meta.type) {
                        case 'data_update':
                            (new DataUpdate(calling_ws.device_id, this.message.data)).buffer();
                            break;
                        default:
                            break;
                    }
                    return
                }
            })
        }
        return
    }
}

function heartbeat(){
    this.isAlive = true
}


wss.on('connection', (ws, req) => {
    //Parse URL and get query element
    var url_parts = url.parse(req.url, true)
    var query = url_parts.query
    
    //Check for API Key in query
    if (query['api_key'] !== config.get('api_key'))
        ws.close(4000, "Bad API key") //Drop any connection with the wrong API KEY

    if(query['is_webclient'] && query['token']){
        server_msg("Web Client Connecting")
        var clients_sqs = "SELECT device_id FROM device WHERE owner_id = (SELECT ref_id FROM auth_token WHERE token= ?)"
        db.query(clients_sqs, [query['token']], (err, clients_result) => {
            var clients = clients_result.map(el => el.device_id)
            ws.isWebServer = true;
            ws.clients = clients
            ws.isAlive = true;
            ws.on('pong', heartbeat)
        })
        return
    } else {
        ws.on('message', function(message){
            (new ClientMessage(message)).process(this)
            return
        })
    }
    //KeepAlive set for client
    ws.isAlive = true;
    ws.on('pong', heartbeat)
})

//Set Keepalive heartbeat
const keepAlive = setInterval(function ping() {
    wss.clients.forEach(function each(ws){
        if(ws.isAlive === false) {
            return ws.terminate();
        }

        ws.isAlive = false;
        ws.ping()
    })
}, 30000)

//Set Webserver update
const webserverUpdate = setInterval(function ping(){
    wss.clients.forEach(function each(ws){
        if(ws.isWebServer){
            var update = {
                meta:{
                    type:"update"
                },
                data:{
                    devices: [

                    ]
                }
            }
            ws.clients.forEach((i) => {
                update['data']['devices'][i] = {}
                update['data']['devices'][i]['status'] = 'Offline'
            })
            wss.clients.forEach((ws2)=>{
                if(ws.clients.includes(ws2.device_id)){
                    update['data']['devices'][ws2.device_id]['device_id'] = ws2.device_id
                    update['data']['devices'][ws2.device_id]['update_buffer'] = device_update_buffer[ws2.device_id]
                    device_update_buffer[ws2.device_id] = []
                    if(ws2.isAlive)
                        update['data']['devices'][ws2.device_id]['status'] = 'Online'
                }
            })
            ws.send(JSON.stringify(update))
        }
    })
}, 3000)