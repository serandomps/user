var serand = require('serand');
var utils = require('utils');

var perms = require('./permissions');

var REFRESH_BEFORE = 10 * 1000;

var user;

var clientId;

var ready = false;

var send = XMLHttpRequest.prototype.send;

var ajax = $.ajax;

var fresh = false;

var pending = false;

var queue = [];

//anon permissions
var permissions = {};

var loginUri = function (clientId, uri) {
    return 'https://accounts.serandives.com/signin?client_id=' + clientId + '&redirect_uri=' + uri
};

var sayReady = function () {
    if (!ready) {
        ready = true;
        return;
    }
    serand.emit('user', 'ready', user);
};

$.ajax = function (options) {
    var success = options.success;
    var error = options.error;
    options.success = function (data, status, xhr) {
        if (xhr.status === 401) {
            if (!fresh) {
                console.log('transparently retrying unauthorized request');
                pending = true;
                refresh(user, function (err, usr) {
                    user = usr;
                    fresh = true;
                    pending = false;
                    options.success = success;
                    options.error = error;
                    $.ajax(options);
                });
                return;
            }
            if (pending) {
                queue.push({
                    options: options,
                    success: success,
                    error: error
                });
                return;
            }
        }
        if (!success) {
            return;
        }
        success.apply(null, Array.prototype.slice.call(arguments));
    };
    options.error = function (xhr, status, err) {
        if (!error) {
            return;
        }
        error.apply(null, Array.prototype.slice.call(arguments));
    };
    return ajax.call($, options);
};

XMLHttpRequest.prototype.send = function () {
    if (user) {
        this.setRequestHeader('Authorization', 'Bearer ' + user.access);
    }
    send.apply(this, Array.prototype.slice.call(arguments));
};

utils.boot(function (err, config) {
    clientId = config.clientId;
    if (!pending) {
        return;
    }
    pending.done(false, loginUri(clientId, pending.uri));
    pending = null;
});

var expires = function (expin) {
    return new Date().getTime() + expin - REFRESH_BEFORE;
};

var next = function (expires) {
    var exp = expires - new Date().getTime();
    return exp > 0 ? exp : null;
};

var initialize = function () {
    if (!localStorage.user) {
        return sayReady();
    }
    var usr = JSON.parse(localStorage.user);
    console.log(usr);
    var nxt = next(usr.expires);
    if (!nxt) {
        localStorage.removeItem('user');
        return sayReady();
    }
    refresh(usr, function (err, usr) {
        user = usr;
        sayReady();
    });
};

var refresh = function (usr, done) {
    $.ajax({
        method: 'POST',
        url: '/apis/v/tokens',
        headers: {
            'x-host': 'accounts.serandives.com'
        },
        data: {
            grant_type: 'refresh_token',
            refresh_token: usr.refresh
        },
        contentType: 'application/x-www-form-urlencoded',
        dataType: 'json',
        success: function (data) {
            usr = {
                username: usr.username,
                access: data.access_token,
                refresh: data.refresh_token,
                expires: expires(data.expires_in)
            };
            localStorage.user = JSON.stringify(usr);
            console.log('token refresh successful');
            var nxt = next(usr.expires);
            console.log('next refresh in : ' + Math.floor(nxt / 1000));
            setTimeout(function () {
                refresh(usr, function (err, usr) {
                    user = usr;
                });
            }, nxt);
            done(false, usr);
        },
        error: function (xhr) {
            console.log('token refresh error');
            localStorage.removeItem('user');
            done(xhr);
        }
    });
};

module.exports.can = function (permission, action) {
    var tree = user.permissions || permissions;
    return perms.can(tree, permission, action);
};

serand.on('user', 'logout', function (usr) {
    $.ajax({
        method: 'DELETE',
        url: '/apis/v/tokens/' + user.access,
        headers: {
            'x-host': 'accounts.serandives.com'
        },
        dataType: 'json',
        success: function (data) {
            console.log('logout successful');
            user = null;
            localStorage.removeItem('user');
            serand.emit('user', 'logged out');
        },
        error: function () {
            console.log('logout error');
            serand.emit('user', 'logout error');
        }
    });
});

serand.on('serand', 'ready', function () {
    sayReady();
});

serand.on('user', 'logged in', function (usr) {
    user = usr;
    localStorage.user = JSON.stringify(user);
    var nxt = next(user.expires);
    console.log('next refresh in : ' + Math.floor(nxt / 1000));
    setTimeout(function () {
        refresh(usr, function (err, usr) {
            user = usr;
        });
    }, nxt);
});

serand.on('user', 'authenticator', function (uri, done) {
    if (clientId) {
        return done(false, loginUri(clientId, uri));
    }
    pending = {
        uri: uri,
        done: done
    };
});

initialize();