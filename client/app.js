const WebSocket = require('ws')
var config = require('config')
const fs = require('fs')
const dns = require('dns');
const commandLineArgs = require('command-line-args')
const NetworkSpeed = require('network-speed');
const testNetworkSpeed = new NetworkSpeed();

var protocols = require('./resources/protocols.json')
var tcp_ports = require('./resources/tcp_ports.json')
var udp_ports = require('./resources/udp_ports.json')

var dns_resolves = []

const client_name = "["+(config.has('device_name') ? config.get('device_name') : 'Unknown Device')+"] "

const optionDefinitions = [
    { name: 'link', alias: 'l', type: String, multiple: false},
    { name: 'interface', alias: 'i', type: String, multiple: false},
    { name: 'remote_ip', alias: 'a', type: String, multiple: false},
    { name: 'remote_port', alias: 'p', type: String, multiple: false}
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
        console.log(this.message)
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
Number.prototype.pad = function(size) {
    var s = String(this);
    while (s.length < (size || 2)) {s = "0" + s;}
    return s;
}

var updates = []

class ServerPacket{
    constructor(packet){
        this.packet = packet
        this.info = {}
    }
    async process(){
        this.update = {}
        this.update['Parsed_Protocol'] = "Other";
        
        //Layer 2 Protocol Switch
        switch (this.packet.link_type) {
            case 'LINKTYPE_ETHERNET':
                var eth_packet = this.packet.payload;
                //MAC Destination
                var eth_daddr = eth_packet.dhost.addr.map((e) => {
                    var hex = e.toString(16)
                    if(hex.length == 1)
                        hex = '0'+hex
                    return hex
                }).join(':')
                this.update['eth_daddr'] = eth_daddr

                //MAC Source
                var eth_saddr = eth_packet.shost.addr.map((e) => {
                    var hex = e.toString(16)
                    if(hex.length == 1)
                        hex = '0'+hex
                    return hex
                }).join(':')
                this.update['eth_saddr'] = eth_saddr

                //Layer 3 Protocol Switch
                var l3_Packet = eth_packet.payload
                switch (l3_Packet.constructor.name) {
                    case 'IPv4':
                        this.update['l3_saddr'] = l3_Packet.saddr.addr.join('.')
                        this.update['l3_daddr'] = l3_Packet.daddr.addr.join('.')

                        //Layer 4 Protocol Switch
                        var l4_Packet = l3_Packet.payload
                        switch (l4_Packet.constructor.name) {
                            case 'TCP':
                                this.update['Parsed_Protocol'] = "TCP"
                                this.update['table'] = {}
                                this.update.table['SrcIP'] = this.update['l3_saddr']
                                this.update.table['SrcPort'] = l4_Packet.sport
                                this.update.table['SrcPort_Desc'] = (tcp_ports.findIndex((el) => el.port == l4_Packet.sport) == -1 ? "" : tcp_ports[tcp_ports.findIndex((el) => el.port == l4_Packet.sport)].description)
                                this.update.table['DestIP'] = this.update['l3_daddr']
                                this.update.table['DestPort'] = l4_Packet.dport
                                this.update.table['DestPort_Desc'] = (tcp_ports.findIndex((el) => el.port == l4_Packet.dport) == -1 ? "" : tcp_ports[tcp_ports.findIndex((el) => el.port == l4_Packet.dport)].description)
                                break;
                            case 'UDP':
                                this.update['Parsed_Protocol'] = "UDP"
                                this.update['table'] = {}
                                this.update.table['SrcIP'] = this.update['l3_saddr']
                                this.update.table['SrcPort'] = l4_Packet.sport
                                this.update.table['SrcPort_Desc'] = (udp_ports.findIndex((el) => el.port == l4_Packet.sport) == -1 ? "" : udp_ports[udp_ports.findIndex((el) => el.port == l4_Packet.sport)].description)
                                this.update.table['DestIP'] = this.update['l3_daddr']
                                this.update.table['DestPort'] = l4_Packet.dport
                                this.update.table['DestPort_Desc'] = (udp_ports.findIndex((el) => el.port == l4_Packet.dport) == -1 ? "" : udp_ports[udp_ports.findIndex((el) => el.port == l4_Packet.dport)].description)
                                break;
                            case 'ICMP':
                                this.update['Parsed_Protocol'] = "ICMP"
                                console.log(l4_Packet)
                                this.update['table'] = {}
                                this.update.table['SrcIP'] = this.update['l3_saddr']
                                this.update.table['SrcPort'] = ""
                                this.update.table['SrcPort_Desc'] = ""
                                this.update.table['DestIP'] = this.update['l3_daddr']
                                this.update.table['DestPort'] = ""
                                this.update.table['DestPort_Desc'] = ""
                                break;
                            default:
                                console.log(l4_Packet.constructor.name)
                                break;
                        }
                        break
                    case 'Arp':
                        this.update['Parsed_Protocol'] = "Arp"
                        this.update['l3_saddr'] = l3_Packet.sender_pa.addr.join('.')
                        this.update['l3_daddr'] = l3_Packet.target_pa.addr.join('.')
                        this.update['table'] = {}
                        this.update.table['SrcIP'] = l3_Packet.sender_pa.addr.join('.')
                        this.update.table['SrcPort'] = ""
                        this.update.table['SrcPort_Desc'] = ""
                        this.update.table['DestIP'] = l3_Packet.target_pa.addr.join('.')
                        this.update.table['DestPort'] = ""
                        this.update.table['DestPort_Desc'] = ""
                        break
                    default:
                        break
                }
                break;
            default:
                break;
        }
        if(!((this.update['l3_saddr'] == options['remote_ip'] || this.update['l3_daddr'] == options['remote_ip']) && (this.update.table['SrcPort'] == options['remote_port'] || this.update.table['DestPort'] == options['remote_port'] ))){
            if(this.update['l3_saddr'] && this.update['l3_daddr']){
                if(dns_resolves[this.update['l3_saddr']]){
                    this.update['l3_saddr_resolved'] = dns_resolves[this.update['l3_saddr']]
                    if(dns_resolves[this.update['l3_daddr']]){
                        this.update['l3_daddr_resolved'] = dns_resolves[this.update['l3_daddr']]
                        updates.push(this.update)
                    }
                    else{
                        dns.reverse(this.update['l3_daddr'], (err, response) => {
                            this.update['l3_daddr_resolved'] = response
                            dns_resolves[this.update['l3_daddr']] = response
                            updates.push(this.update)
                        })
                    }
                }
                else{
                    dns.reverse(this.update['l3_saddr'], (err, response) => {
                        this.update['l3_saddr_resolved'] = response
                        dns_resolves[this.update['l3_saddr']] = response
                        if(dns_resolves[this.update['l3_daddr']]){
                            this.update['l3_daddr_resolved'] = dns_resolves[this.update['l3_daddr']]
                            updates.push(this.update)
                        }
                        else{
                            dns.reverse(this.update['l3_daddr'], (err, response) => {
                                this.update['l3_daddr_resolved'] = response
                                dns_resolves[this.update['l3_daddr']] = response
                                updates.push(this.update)
                            })
                        }
                    })
                }
            }
            else
                updates.push(this.update)
        }
        return
    }
}

var connection_speed = undefined;

function connect(){
    console_msg("Connecting to server on "+options['remote_ip']+':'+options['remote_port'])
    ws = new WebSocket('ws://'+options['remote_ip']+':'+options['remote_port']+'?api_key='+config.get('api_key'))
    ws.on('error', connect)
    ws.on('close', connect)

    ws.on('open', () => {
        ws.on('message', function(message){
            (new ServerMessage(message)).process(this)
        })
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
        if(config.has('token')){
            var pcap = require('pcap'),
                pcap_session = pcap.createSession(options['interface']);
            pcap_session.on('packet', function (raw_packet) {
                (new ServerPacket(pcap.decode.packet(raw_packet))).process();
            });

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
                dataUpdate.data['updates'] = updates
                updates = []
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
if(!options['interface'])
    console_error("Please prive an interface(-i)")
connect()