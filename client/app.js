const WebSocket = require('ws')
var config = require('config')
const fs = require('fs')
const commandLineArgs = require('command-line-args')
const NetworkSpeed = require('network-speed');
const testNetworkSpeed = new NetworkSpeed();

const client_name = "["+(config.has('device_name') ? config.get('device_name') : 'Unknown Device')+"] "

const optionDefinitions = [
    { name: 'link', alias: 'l', type: String, multiple: false},
    { name: 'remote_ip', alias: 'a', type: String, multiple: false}, //, defaultOption: '127.0.0.1', defaultValue: '127.0.0.1'
    { name: 'remote_port', alias: 'p', type: String, multiple: false} //, defaultOption: '8080', defaultValue: '8080'
]
const options = commandLineArgs(optionDefinitions)

console_error = (message) => {
    console.error(client_name + message)
    process.exit(-1)
}

console_msg = (message) => {
    console.log(client_name + message)
}

class ServerMessage{
    constructor(message){
        this.message = JSON.parse(message)
    }
    process(calling_ws){
        if(this.message['meta']['type'] == 'error')
            console_error(this.message['data']['message'])
        else if(this.message['meta']['type'] == 'link_result'){
            if(this.message['data']['success']){
                console.log(this.message)
                var config_edit = config.util.toObject()
                config_edit['token'] = this.message['data']['token']
                config_edit['device_name']= this.message['data']['device_name'] ? this.message['data']['device_name'] : 'Unknown Device'
                fs.writeFileSync(config.util.getConfigSources()[0]['name'], JSON.stringify(config_edit))
                config = require('config')
                console_msg("Device Linked")
                return
            }
        }
    }
}

var connection_speed = undefined;

function connect(){
    console_msg("Connecting to server on "+options['remote_ip']+':'+options['remote_port'])
    ws = new WebSocket('ws://'+options['remote_ip']+':'+options['remote_port']+'?api_key='+config.get('api_key'))
    ws.on('error', connect)
    ws.on('close', connect)

    ws.on('open', () => {
        console_msg("Connection Complete")
        if(options['link']){
            console_msg('Atttempting Link')
            var link_query = {
                meta: {
                    type: "link"
                },
                data: {
                    code: options['link']
                }
            }
            ws.send(JSON.stringify(link_query))
        }
        if(config.get('token')){
            ws.dataUpdate = setInterval(function(){
                var dataUpdate = {
                    meta: {
                        type: 'data_update',
                        token: config.get('token')
                    },
                    data: {
                        
                    }
                }
                if(connection_speed != undefined){
                    dataUpdate.data['connection_speed'] = connection_speed;
                    connection_speed = undefined;
                }
                ws.send(JSON.stringify(dataUpdate))
            }, 3000)
        }
        ws.clientNetworkSpeed = setInterval(function(){
            //TODO: MAKE SURE THIS ISNT CAUSING ISSUES
            testNetworkSpeed.checkDownloadSpeed('http://'+options['remote_ip']+':'+options['remote_port']+'/api/nwSpeed', 10000000).then(function(speed){
                connection_speed = speed.mbps;
            });
        }, 1000 * 10)
    })
    ws.on('ping', heartbeat)
    ws.on('open', heartbeat)
    ws.on('close', (code, reason) => {
        clearTimeout(this.pingTimeout)
        console_error("Connection Lost ("+code+") "+ reason)
    })
    ws.on('message', function(message){
        (new ServerMessage(message)).process(this)
    })
}

function heartbeat(){
    clearTimeout(this.pingTimeout)
    this.pingTimeout = setTimeout(() => {
        this.terminate();
    }, 30000 + 1000)
}

//Die if there is no remote server provided.
if(!options['remote_port'] || !options['remote_ip'])
    console_error("Please provide server port(-p) and ip(-a)")

connect()