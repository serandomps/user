var serand = require('serand');
var utils = require('utils');

var perms = require('./permissions');

var REFRESH_BEFORE = 10 * 1000;

var uzer;

var clientId;

var ready = false;

var send = XMLHttpRequest.prototype.send;

var ajax = $.ajax;

var queue = [];

var token = false;

var pending;

//anon permissions
var permissions = {};

var loginUri = function (clientId, uri) {
    return 'https://accounts.serandives.com/signin?client_id=' + clientId + (uri ? '&redirect_uri=' + uri : '');
};

var sayReady = function () {
    if (!ready) {
        ready = true;
        return;
    }
    serand.emit('user', 'ready', user());
};

var user = function (usr) {
    if (usr) {
        uzer = usr;
        localStorage.user = JSON.stringify(usr);
        return usr;
    }
    if (usr === undefined) {
        return uzer || (localStorage.user ? (uzer = JSON.parse(localStorage.user)) : null);
    }
    uzer = null;
    localStorage.removeItem('user');
};

var none = function () {

};

$.ajax = function (options) {
    if (token && !options.token) {
        queue.push(options);
        return;
    }
    var success = options.success || none;
    var error = options.error || none;
    options.success = function (data, status, xhr) {
        success.apply(null, Array.prototype.slice.call(arguments));
    };
    options.error = function (xhr, status, err) {
        var usr = user();
        if (xhr.status === 401) {
            if (options.token) {
                error.apply(null, Array.prototype.slice.call(arguments));
                return;
            }
            console.log('transparently retrying unauthorized request');
            token = true;
            refresh(usr, function (err, usr) {
                token = false;
                user(usr);
                options.success = success;
                options.error = error;
                $.ajax(options);
                queue.forEach(function (options) {
                    $.ajax(options);
                });
                queue = [];
                if (err) {
                    serand.emit('user', 'login');
                }
            });
            return;
        }
        error.apply(null, Array.prototype.slice.call(arguments));
    };
    return ajax.call($, options);
};

XMLHttpRequest.prototype.send = function () {
    var usr = user();
    if (usr) {
        this.setRequestHeader('Authorization', 'Bearer ' + usr.access);
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
    var usr = user();
    if (!usr) {
        return sayReady();
    }
    console.log(usr);
    var nxt = next(usr.expires);
    if (!nxt) {
        user(null);
        return sayReady();
    }
    refresh(usr, function (err, usr) {
        user(usr);
        sayReady();
    });
};

var refresh = function (usr, done) {
    $.ajax({
        token: true,
        method: 'POST',
        url: '/apis/v/tokens',
        headers: {
            'X-Host': 'accounts.serandives.com'
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
            user(usr);
            console.log('token refresh successful');
            var nxt = next(usr.expires);
            console.log('next refresh in : ' + Math.floor(nxt / 1000));
            setTimeout(function () {
                refresh(usr, function (err, usr) {
                    user(usr);
                });
            }, nxt);
            done(false, usr);
        },
        error: function (xhr) {
            console.log('token refresh error');
            user(null);
            done(xhr);
        }
    });
};

module.exports.can = function (permission, action) {
    var usr = user();
    var tree = usr.permissions || permissions;
    return perms.can(tree, permission, action);
};

serand.on('user', 'logout', function () {
    var usr = user();
    $.ajax({
        method: 'DELETE',
        url: '/apis/v/tokens/' + usr.access,
        headers: {
            'X-Host': 'accounts.serandives.com'
        },
        dataType: 'json',
        success: function (data) {
            console.log('logout successful');
            user(null);
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
    user(usr);
    var nxt = next(usr.expires);
    console.log('next refresh in : ' + Math.floor(nxt / 1000));
    setTimeout(function () {
        refresh(usr, function (err, usr) {
            user(usr);
        });
    }, nxt);
});

serand.on('user', 'authenticator', function (uri, done) {
    if (!done) {
        done = uri;
        uri = null;
    }
    if (clientId) {
        return done(false, loginUri(clientId, uri));
    }
    pending = {
        uri: uri,
        done: done
    };
});

initialize();