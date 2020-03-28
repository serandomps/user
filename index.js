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

var currentToken;

var refresher;

var ready = false;

var ajax = $.ajax;

var queue = [];

var tokenPending = false;

var boot = false;

//anon permissions
var permissions = {};

sera.is = function (name) {
    var user = sera.user;
    if (!user) {
        return false;
    }
    var groups = utils.groups();
    var group = groups[name];
    if (!group) {
        return false;
    }
    return user.groups.indexOf(group.id) !== -1;
};

var loginUri = function (type, location) {
    var o = context[type];
    location = location || o.location;
    var url = o.login + '?client_id=' + o.client
        + (location ? '&redirect_uri=' + location : '')
        + (o.scopes ? '&scope=' + o.scopes.join(',') : '');
    return url;
};

var findUserInfo = function (id, access, done) {
    module.exports.findOne(id, access, function (err, usr) {
        if (err) {
            return done(err);
        }
        done(null, usr);
    });
};

var emit = function (tk) {
    if (!ready) {
        ready = true;
        utils.emit('user', 'ready', tk);
        return tk;
    }
    if (tk) {
        currentToken ? utils.emit('user', 'refreshed', tk) : utils.emit('user', 'logged in', tk);
        return tk;
    }
    if (currentToken) {
        utils.emit('user', 'logged out', null);
    }
};

var update = function (tk) {
    currentToken = tk;
    serand.store('token', tk);
    if (!tk) {
        clearTimeout(refresher);
    }
    return tk;
};

var emitup = function (tk) {
    emit(tk);
    update(tk);
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
        if (!currentToken || xhr.status !== 401 || options.token || options.count > 0 || options.primary) {
            error.apply(null, Array.prototype.slice.call(arguments));
            return;
        }
        console.log('transparently retrying unauthorized request');
        tokenPending = true;
        refresh(currentToken, function (err, tk) {
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
                utils.emit('user', 'login');
                return;
            }
            emitup(tk);
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
    if (currentToken) {
        headers = options.headers || (options.headers = {});
        headers['Authorization'] = headers['Authorization'] || ('Bearer ' + currentToken.access);
    }
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
        o.client = clients[name];
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
    var tk = serand.store('token');
    if (!tk) {
        return emitup(null);
    }
    console.log('initialize', tk);
    var nxt = next(tk.expires);
    if (!nxt) {
        return emitup(null);
    }
    refresh(tk, function (err, tk) {
        if (err) {
            console.error(err);
        }
        if (!tk) {
            return emitup(null);
        }
        if (tk.user.id) {
            return emitup(tk);
        }
        findUserInfo(tk.user.id, tk.access, function (err, usr) {
            if (err) {
                console.error(err);
                return
            }
            tk.user = usr;
            emitup(tk);
        });
    });
};

var refresh = function (tk, done) {
    done = done || serand.none;
    if (!tk) {
        return done('!token');
    }
    $.ajax({
        token: true,
        method: 'POST',
        url: utils.resolve('accounts:///apis/v/tokens'),
        data: {
            grant_type: 'refresh_token',
            refresh_token: tk.refresh
        },
        contentType: 'application/x-www-form-urlencoded',
        dataType: 'json',
        success: function (data) {
            tk.access = data.access_token;
            tk.refresh = data.refresh_token;
            tk.expires = expires(data.expires_in);
            console.log('token refresh successful');
            var nxt = next(tk.expires);
            console.log('next refresh in : ' + Math.floor(nxt / 1000));
            later(function () {
                refresh(currentToken, function (err, tk) {
                    if (err) {
                        console.error(err);
                    }
                    emitup(tk);
                });
            }, nxt);
            done(null, tk);
        },
        error: function (xhr, one, two) {
            console.log('token refresh error');
            done(xhr);
        }
    });
};

module.exports.can = function (permission, action) {
    var tree = currentToken.permissions || permissions;
    return perms.can(tree, permission, action);
};

utils.on('user', 'logout', function () {
    if (!currentToken) {
        return;
    }
    $.ajax({
        method: 'DELETE',
        url: utils.resolve('accounts:///apis/v/tokens/' + currentToken.id),
        dataType: 'json',
        success: function (data) {
            emitup(null);
        },
        error: function (xhr, status, err) {
            utils.emit('user', 'logout error', err || status || xhr);
        }
    });
});

utils.on('serand', 'ready', function () {
    initialize();
});

utils.on('stored', 'token', function (tk) {
    emit(tk);
    currentToken = tk;
});

utils.on('user', 'initialize', function (o, options) {
    token.findOne(o.tid, o.access, function (err, tk) {
        if (err) {
            return console.error(err);
        }
        findUserInfo(tk.user, o.access, function (err, usr) {
            if (err) {
                console.error(err)
                return
            }
            tk.user = usr;
            update(tk);
            var nxt = next(tk.expires);
            console.log('next refresh in : ' + Math.floor(nxt / 1000));
            later(function () {
                refresh(currentToken, function (err, tk) {
                    if (err) {
                        console.error(err);
                    }
                    emitup(tk);
                });
            }, nxt);
            utils.emit('user', 'logged in', tk, options);
        });
    });
});

utils.on('user', 'token', function (tk, options) {
    update(tk);
    var nxt = next(tk.expires);
    console.log('next refresh in : ' + Math.floor(nxt / 1000));
    later(function () {
        refresh(currentToken, function (err, tk) {
            if (err) {
                console.error(err);
            }
            emitup(tk);
        });
    }, nxt);
    utils.emit('user', 'logged in', tk, options);
});

var users = {};

var updated = function (user, done) {
    user._ = user._ || (user._ = {});
    user._.initials = utils.initials(user.alias);
    if (!user.avatar) {
        users[user.id] = user;
        return done(null, user);
    }
    utils.cdn('images', '/images/160x160/' + user.avatar, function (err, url) {
        if (err) {
            return done(err);
        }
        user._.avatar = url;
        users[user.id] = user;
        done(null, user);
    });
};

module.exports.findOne = function (id, access, done) {
    if (!done) {
        done = access;
        access = null;
    }
    utils.sync('user-findone-' + id, function (did) {
        if (users[id]) {
            return did(null, users[id]);
        }
        var options = {
            method: 'GET',
            url: utils.resolve('accounts:///apis/v/users/' + id),
            dataType: 'json',
            success: function (user) {
                updated(user, did);
            },
            error: function (xhr, status, err) {
                did(err || status || xhr);
            }
        };
        if (access) {
            options.headers = options.headers || {};
            options.headers['Authorization'] = 'Bearer ' + access;
        }
        $.ajax(options);
    }, done);
};


exports.update = function (user, data, done) {
    var otp = data.otp;
    delete data.otp;
    _.mergeWith(user, data, function (dest, src) {
        return src || null;
    });
    var clone = _.cloneDeep(user);
    delete clone._;

    var headers = {};
    otp = otp ? otp.strong : null;
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
            updated(data, done);
        },
        error: function (xhr, status, err) {
            if (xhr.status === 401) {
                return done(null, 'Old password you entered is incorrect');
            }
            done(err);
        }
    });
};

exports.find = function (options, done) {
    $.ajax({
        method: 'GET',
        url: utils.resolve('accounts:///apis/v/users' + utils.toData(options.query)),
        dataType: 'json',
        success: function (data, status, xhr) {
            done(null, data);
        },
        error: function (xhr, status, err) {
            done(err || status || xhr);
        }
    });
};
