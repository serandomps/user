var serand = require('serand');
var utils = require('utils');

var perms = require('./permissions');

var REFRESH_BEFORE = 10 * 1000;

//TODO: move these facebook etc. configs to account-signin, since this relates only to accounts.com
var context = {
    serandives: {
        login: 'https://accounts.serandives.com/signin'
    },
    facebook: {
        login: 'https://www.facebook.com/dialog/oauth',
        location: 'https://accounts.serandives.com/auth/oauth',
        scopes: ['email', 'public_profile']
    }
};

var user;

var refresher;

var ready = false;

var ajax = $.ajax;

var queue = [];

var token = false;

var boot = false;

//anon permissions
var permissions = {};

var loginUri = function (type, location) {
    var o = context[type];
    location = location || o.location;
    var url = o.login + '?client_id=' + o.clientId
        + (location ? '&redirect_uri=' + location : '')
        + (o.scopes ? '&scope=' + o.scopes.join(',') : '');
    console.log(url);
    return url;
};

var emit = function (usr) {
    if (!ready) {
        ready = true;
        serand.emit('user', 'ready', usr);
        return usr;
    }
    if (usr) {
        user ? serand.emit('user', 'refreshed', usr) : serand.emit('user', 'logged in', usr);
        return usr;
    }
    if (user) {
        serand.emit('user', 'logged out', null);
    }
};

var update = function (usr) {
    user = usr;
    serand.store('user', usr);
    if (!usr) {
        clearTimeout(refresher);
    }
    return usr;
};

var emitup = function (usr) {
    emit(usr);
    update(usr);
};

var later = function (task, after) {
    if (refresher) {
        clearTimeout(refresher);
    }
    refresher = setTimeout(task, after);
};

$.ajax = function (options) {
    if (token && !options.token) {
        queue.push(options);
        return;
    }
    var success = options.success || serand.none;
    var error = options.error || serand.none;
    options.success = function (data, status, xhr) {
        success.apply(null, Array.prototype.slice.call(arguments));
    };
    options.error = function (xhr, status, err) {
        if (xhr.status !== 401) {
            error.apply(null, Array.prototype.slice.call(arguments));
            return;
        }
        if (options.token) {
            error.apply(null, Array.prototype.slice.call(arguments));
            return;
        }
        console.log('transparently retrying unauthorized request');
        token = true;
        refresh(user, function (err) {
            token = false;
            if (err) {
                error({status: 401});
                queue.forEach(function (options) {
                    if (!options.error) {
                        return;
                    }
                    options.error({status: 401});
                });
                queue = [];
                serand.emit('user', 'login');
                return;
            }
            options.success = success;
            options.error = error;
            $.ajax(options);
            queue.forEach(function (options) {
                $.ajax(options);
            });
            queue = [];
        });
    };
    var headers;
    if (user) {
        headers = options.headers || (options.headers = {});
        headers['Authorization'] = headers['Authorization'] || ('Bearer ' + user.access);
    }
    console.log(options);
    return ajax.call($, options);
};

utils.configs('boot', function (err, config) {
    var name;
    var clients = config.clients;
    console.log(clients);
    for (name in clients) {
        if (!clients.hasOwnProperty(name)) {
            continue;
        }
        var o = context[name];
        o.clientId = clients[name];
        var pending = o.pending;
        if (!pending) {
            continue;
        }
        var options = pending.options;
        pending.done(false, loginUri(name, options.location));
        delete o.pending;
    }
    boot = true;
});

var expires = function (expin) {
    return new Date().getTime() + expin - REFRESH_BEFORE;
};

var next = function (expires) {
    var exp = expires - new Date().getTime();
    return exp > 0 ? exp : null;
};

var initialize = function () {
    var usr = serand.store('user');
    if (!usr) {
        return emitup(null);
    }
    console.log(usr);
    var nxt = next(usr.expires);
    if (!nxt) {
        return emitup(null);
    }
    refresh(usr, function (err, usr) {
        emitup(usr);
    });
};

var refresh = function (usr, done) {
    done = done || serand.none;
    if (!usr) {
        return done('!user');
    }
    $.ajax({
        token: true,
        method: 'POST',
        url: 'https://accounts.serandives.com/apis/v/tokens',
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
            emitup(usr);
            console.log('token refresh successful');
            var nxt = next(usr.expires);
            console.log('next refresh in : ' + Math.floor(nxt / 1000));
            later(function () {
                refresh(user);
            }, nxt);
            done(null, usr);
        },
        error: function (xhr) {
            console.log('token refresh error');
            emitup(null);
            done(xhr);
        }
    });
};

var authenticator = function (options, done) {
    var type = options.type || 'serandives';
    if (boot) {
        done(false, loginUri(type, options.location));
        return;
    }
    var o = context[type];
    o.pending = {
        options: options,
        done: done
    };
};

module.exports.can = function (permission, action) {
    var tree = user.permissions || permissions;
    return perms.can(tree, permission, action);
};

serand.on('user', 'logout', function () {
    if (!user) {
        return;
    }
    $.ajax({
        method: 'DELETE',
        url: 'https://accounts.serandives.com/apis/v/tokens/' + user.access,
        dataType: 'json',
        success: function (data) {
            console.log('logout successful');
            emitup(null);
        },
        error: function () {
            console.log('logout error');
            serand.emit('user', 'logout error');
        }
    });
});

serand.on('serand', 'ready', function () {
    initialize();
});

serand.on('stored', 'user', function (usr) {
    emit(usr);
    user = usr;
});

serand.on('user', 'logged in', function (usr) {
    update(usr);
    var nxt = next(usr.expires);
    console.log('next refresh in : ' + Math.floor(nxt / 1000));
    later(function () {
        refresh(user);
    }, nxt);
});

serand.on('user', 'authenticator', function (options, done) {
    if (!done) {
        done = options;
        options = {};
    }
    authenticator(options, done);
});

serand.on('user', 'info', function (id, token, done) {
    if (!done) {
        done = token;
        token = null;
    }
    var options = {
        method: 'GET',
        url: 'https://accounts.serandives.com/apis/v/users/' + id,
        dataType: 'json',
        success: function (user) {
            done(false, user);
        },
        error: function () {
            done('permissions error');
        }
    };
    if (token) {
        options.headers = options.headers || {};
        options.headers['Authorization'] = 'Bearer ' + token;
    }
    $.ajax(options);
});

//TODO: token needs to return user id etc. so, later that user id is used to retrieve user info
