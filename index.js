var express = require('express');
var app = express();
var { expressjwt: jwt } = require("express-jwt");
var jwks = require('jwks-rsa');
var cors = require('cors')

var port = process.env.PORT || 8081;

var jwtCheck = jwt({
    secret: jwks.expressJwtSecret({
        cache: true,
        rateLimit: true,
        jwksRequestsPerMinute: 5,
        jwksUri: 'https://dev-ub-vnov4.us.auth0.com/.well-known/jwks.json'
  }),
  audience: 'https://customer-mgmt-api',
  issuer: 'https://dev-ub-vnov4.us.auth0.com/',
  algorithms: ['RS256']
});


var ManagementClient = require('auth0').ManagementClient;
var auth0 = new ManagementClient({
  domain: 'dev-ub-vnov4.us.auth0.com',
  clientId: 'U0lhX9YzGrJqMHUfoTpdSaocpXoeDFrN',
  clientSecret: '******',
  scope: 'read:users',
});


const customerIdRequired = (req, res, next) => {
    if (!req.auth.customerId) res.status(403).send('customerId missing in token')
    next()
}

app.use(cors({origin: 'http://localhost:3000'}));


app.use(jwtCheck);

app.use(customerIdRequired);

const fixName = r => ({ ...r, name: r.name.split('_')[1]})

const getUserRoles = async id => {
    var params = { id };
    const roles = await auth0.getUserRoles(params)
    return roles.map(fixName)
}


// app.use((req, _, next) => {
//     req.auth = {}
//     req.auth.customerId = 1023
//     next()
// })


app.get('/roles', async function (req, res, next) {
    try {
        const roles = await auth0.getRoles()
        res.json(roles
            .filter(r => r.name.startsWith(req.auth.customerId))
            .map(fixName))
    } catch (e) {
        next(e)
    }
});


app.get('/roles/:id/scopes', async function (req, res, next) {
    try {
        res.json(await auth0.getPermissionsInRole({ id: req.params.id }))
    } catch (e) {
        next(e)
    }
});


app.get('/scopes', async function (req, res, next) {
    try {
        const rs = await auth0.getResourceServer({id: '6336c5395c108be960e12c22'})
        res.json(rs.scopes)
    } catch (e) {
        next(e)
    }
});


app.post('/roles/:roleid/scopes/:scopename', async function (req, res, next) {
    try {
        var params = { id: req.params.roleid};
        var data = { "permissions" : [{"permission_name": req.params.scopename , "resource_server_identifier" : "https://customer-api" }]};
        await auth0.addPermissionsInRole(params, data)
        res.json(await auth0.getPermissionsInRole({ id: req.params.roleid }))
    } catch (e) {
        next(e)
    }
});


app.delete('/roles/:roleid/scopes/:scopename', async function (req, res, next) {
    try {
        var params = { id: req.params.roleid};
        var data = { "permissions" : [{"permission_name": req.params.scopename , "resource_server_identifier" : "https://customer-api" }]};
        await auth0.removePermissionsFromRole(params, data)
        res.json(await auth0.getPermissionsInRole({ id: req.params.roleid }))
    } catch (er) {
        next(e)
    }

});


app.get('/users', async function (req, res, next) {
    try {
        res.json(await auth0.getUsers({ q: `app_metadata.customerId:${req.auth.customerId}`}))
    } catch (e) {
        next(e)
    }

});


app.get('/users/:id/roles', async function (req, res, next) {
    try {
        res.json(await getUserRoles(req.params.id))
    } catch (e) {
        next(e)
    }
});


app.post('/users/:userid/roles/:roleid', async function (req, res, next) {
    try {
        var params =  { id : req.params.userid};
        var data = { "roles" :[req.params.roleid]};
        await auth0.assignRolestoUser(params, data)
        res.json(await getUserRoles(req.params.userid))
    } catch (e) {
        next(e)
    }
});


app.delete('/users/:userid/roles/:roleid', async function (req, res, next) {
    try {
        var params =  { id : req.params.userid};
        var data = { "roles" :[req.params.roleid]};
        await auth0.removeRolesFromUser(params, data)
        res.json(await getUserRoles(req.params.userid))
    } catch (e) {
        next(e)
    }
});


app.listen(port);