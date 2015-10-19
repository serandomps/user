var serand = require('serand');

var perms = require('./permissions');

var REFRESH_BEFORE = 10 * 1000;

var user;

var refresher;

var send = XMLHttpRequest.prototype.send;

var ajax = $.ajax;

var fresh = false;

var pending = false;

var queue = [];

$.ajax = function (options) {
    var success = options.success;
    var error = options.error;
    options.success = function (data, status, xhr) {
        if (xhr.status === 401) {
            if (!fresh) {
                console.log('transparently retrying unauthorized request');
                pending = true;
                refresh(function (err) {
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

var expires = function (expin) {
    return new Date().getTime() + expin - REFRESH_BEFORE;
};

var next = function (expires) {
    var exp = expires - new Date().getTime();
    return exp > 0 ? exp : null;
};

var permissions = function (user) {
    $.ajax({
        method: 'GET',
        url: '/apis/v/tokens/' + user.tid,
        headers: {
            'x-host': 'accounts.serandives.com'
        },
        dataType: 'json',
        success: function (token) {
            user.has = token.has;
            localStorage.user = JSON.stringify(user);
            console.log('login successful');
            console.log('next refresh in : ' + Math.floor(next(user.expires) / 1000));
            setTimeout(refresh, next(user.expires));
            serand.emit('user', 'logged in', user);
        },
        error: function () {
            serand.emit('user', 'login error');
        }
    });
};

var refresh = function (done) {
    $.ajax({
        method: 'POST',
        url: '/apis/v/tokens',
        headers: {
            'x-host': 'accounts.serandives.com'
        },
        data: {
            grant_type: 'refresh_token',
            refresh_token: user.refresh
        },
        contentType: 'application/x-www-form-urlencoded',
        dataType: 'json',
        success: function (data) {
            user = {
                username: user.username,
                access: data.access_token,
                refresh: data.refresh_token,
                expires: expires(data.expires_in)
            };
            localStorage.user = JSON.stringify(user);
            console.log('token refresh successful');
            console.log('next refresh in : ' + Math.floor(next(user.expires) / 1000));
            setTimeout(refresh, next(user.expires));
            if (done) {
                done();
            }
        },
        error: function (xhr) {
            console.log('token refresh error');
            if (done) {
                done(xhr);
            }
        }
    });
};

serand.on('user', 'authenticate', function (username, password) {
    $.ajax({
        method: 'POST',
        url: '/apis/v/tokens',
        headers: {
            'x-host': 'accounts.serandives.com'
        },
        data: {
            grant_type: 'password',
            username: username,
            password: password
        },
        contentType: 'application/x-www-form-urlencoded',
        dataType: 'json',
        success: function (token) {
            user = {
                tid: token.id,
                username: username,
                access: token.access_token,
                refresh: token.refresh_token,
                expires: expires(token.expires_in)
            };
            permissions(user);
        },
        error: function () {
            serand.emit('user', 'login error');
        }
    });
});

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

var usr;
var nxt;

if (localStorage.user) {
    usr = JSON.parse(localStorage.user);
    console.log(usr);
    nxt = next(usr.expires);
    if (!nxt) {
        localStorage.removeItem('user');
        return;
    }
    user = usr;
    console.log('next refresh in : ' + Math.floor(nxt / 1000));
    setTimeout(refresh, nxt);
    console.log('local storage user');
}

serand.on('serand', 'ready', function () {
    serand.emit('user', 'ready', user);
});

module.exports.can = function (permission, action) {
    var tree = user.permissions || permissions;
    return perms.can(tree, permission, action);
};