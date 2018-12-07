var serand = require('serand');
var utils = require('utils');
var token = require('token');

var perms = require('./permissions');

var REFRESH_BEFORE = 10 * 1000;

var MAX_TIMEOUT_DELAY = 2147483647;

//TODO: move these facebook etc. configs to account-signin, since this relates only to accounts.com
var context = {
    serandives: {
        login: utils.resolve('accounts:///signin')
    },
    facebook: {
        login: 'https://www.facebook.com/dialog/oauth',
        location: utils.resolve('accounts:///auth/oauth'),
        scopes: ['email', 'public_profile']
    }
};

var user;

var refresher;

var ready = false;

var ajax = $.ajax;

var queue = [];

var tokenPending = false;

var boot = false;

//anon permissions
var permissions = {};

var loginUri = function (type, location) {
    var o = context[type];
    location = location || o.location;
    var url = o.login + '?client_id=' + o.clientId
        + (location ? '&redirect_uri=' + location : '')
        + (o.scopes ? '&scope=' + o.scopes.join(',') : '');
    return url;
};

var findUserInfo = function (user, done) {
    if (!user) {
        return done(new Error('!user'));
    }
    token.findOne(user.tid, user.access, function (err, token) {
        if (err) {
            return done(err);
        }
        module.exports.findOne(token.user, user.access, function (err, usr) {
            if (err) {
                return done(err);
            }
            user.id = usr.id;
            user.username = usr.email;
            done(null, user);
        });
    });
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
    refresher = setTimeout(task, after < MAX_TIMEOUT_DELAY ? after : MAX_TIMEOUT_DELAY);
};

$.ajax = function (options) {
    if (tokenPending && !options.token) {
        queue.push(options);
        return;
    }
    options.count = options.count || 0;
    var success = options.success || serand.none;
    var error = options.error || serand.none;
    options.success = function (data, status, xhr) {
        success.apply(null, Array.prototype.slice.call(arguments));
    };
    options.error = function (xhr, status, err) {
        if (!user || xhr.status !== 401 || options.token || options.count > 0 || options.primary) {
            error.apply(null, Array.prototype.slice.call(arguments));
            return;
        }
        console.log('transparently retrying unauthorized request');
        tokenPending = true;
        refresh(user, function (err) {
            tokenPending = false;
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
            options.count++;
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
    if (err) {
        return console.error(err);
    }
    var name;
    var clients = config.clients;
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
        pending.done(null, loginUri(name, options.location));
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
        if (err) {
            return console.error(err);
        }
        if (!usr) {
            return emitup(null);
        }
        findUserInfo(usr, function (err, usr) {
            if (err) {
                console.error(err)
                return
            }
            emitup(usr);
        });
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
        url: utils.resolve('accounts:///apis/v/tokens'),
        data: {
            grant_type: 'refresh_token',
            refresh_token: usr.refresh
        },
        contentType: 'application/x-www-form-urlencoded',
        dataType: 'json',
        success: function (data) {
            usr.access = data.access_token;
            usr.refresh = data.refresh_token;
            usr.expires = expires(data.expires_in);
            emitup(usr);
            console.log('token refresh successful');
            var nxt = next(usr.expires);
            console.log('next refresh in : ' + Math.floor(nxt / 1000));
            later(function () {
                refresh(user);
            }, nxt);
            done(null, usr);
        },
        error: function (xhr, one, two) {
            console.log('token refresh error');
            emitup(null);
            done(xhr);
        }
    });
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
        url: utils.resolve('accounts:///apis/v/tokens/' + user.tid),
        dataType: 'json',
        success: function (data) {
            emitup(null);
        },
        error: function (xhr, status, err) {
            serand.emit('user', 'logout error', err || status || xhr);
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
    findUserInfo(usr, function (err, usr) {
        if (err) {
            console.error(err)
            return
        }
        update(usr);
        var nxt = next(usr.expires);
        console.log('next refresh in : ' + Math.floor(nxt / 1000));
        later(function () {
            refresh(user);
        }, nxt);
    });
});

var userInfo = null;

module.exports.findOne = function (id, token, done) {
    if (!done) {
        done = token;
        token = null;
    }
    utils.sync('user-findone-' + id, function (did) {
        if (userInfo) {
            return did(null, userInfo);
        }
        var options = {
            method: 'GET',
            url: utils.resolve('accounts:///apis/v/users/' + id),
            dataType: 'json',
            success: function (user) {
                if (!user.avatar) {
                    userInfo = user;
                    return did(null, user);
                }
                utils.cdn('images', '/images/288x162/' + user.avatar, function (err, url) {
                    if (err) {
                        return did(err);
                    }
                    user._ = user._ || (user._ = {});
                    user._.avatar = url;
                    userInfo = user;
                    did(null, user);
                });
            },
            error: function (xhr, status, err) {
                did(err || status || xhr);
            }
        };
        if (token) {
            options.headers = options.headers || {};
            options.headers['Authorization'] = 'Bearer ' + token;
        }
        $.ajax(options);
    }, done);
};


exports.update = function (user, data, done) {
    var otp = data.otp;
    delete data.otp;
    _.merge(user, data);
    var clone = _.cloneDeep(user);
    delete clone._;

    var headers = {};
    otp = otp ? otp.value : null;
    if (otp) {
        headers['X-OTP'] = otp;
    }
    $.ajax({
        method: 'PUT',
        url: utils.resolve('accounts:///apis/v/users/' + user.id),
        dataType: 'json',
        contentType: 'application/json',
        data: JSON.stringify(clone),
        headers: headers,
        success: function (data) {
            done(null, data);
        },
        error: function (xhr, status, err) {
            if (xhr.status === 401) {
                return done(null, 'Old password you entered is incorrect');
            }
            done(err);
        }
    });
};

//TODO: token needs to return user id etc. so, later that user id is used to retrieve user info
