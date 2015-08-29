var tree = {
    autos: {
        '123456': {
            '': ['read', 'write'],
            'comments': {
                '': ['read'],
                '*': {
                    '': []
                },
                '0001': {
                    '': ['read', 'update'],
                    '*': ['read'],
                    'abcdef': {
                        '': ['update']
                    }
                }
            }
        },
        '*': {
            '': ['read']
        }
    }
};

var has = function (tree, perms, action) {
    var allowed;
    if (!perms.length) {
        allowed = tree[''] || [];
        return allowed.indexOf('*') !== -1 || allowed.indexOf(action) !== -1;
    }
    var all = tree['*'];
    allowed = all ? all[''] || [] : [];
    if (allowed.indexOf('*') !== -1 || allowed.indexOf(action) !== -1) {
        return true;
    }
    tree = tree[perms.shift()];
    if (!tree) {
        return false;
    }
    return has(tree, perms, action);
};

var add = function (tree, perms, actions) {
    var allowed;
    var perm = perms.shift();

    if (perms.length) {
        tree = tree[perm] || (tree[perm] = {});
        return add(tree, perms, actions);
    }

    tree = tree[perm] || (tree[perm] = {});
    allowed = tree[''] || [];
    tree[''] = allowed.concat(actions);
};

var can = function (tree, permission, action) {
    return has(tree, permission.split(':'), action);
};

var permit = function (tree, permission, actions) {
    actions = actions instanceof Array ? actions : [actions];
    return add(tree, permission.split(':'), actions);
};

module.exports.can = can;

module.exports.permit = permit;

// autos:1234
// autos:1234:*
// autos:*
// autos
// autos:*:comments
// autos:*:comments:*
// autos:*:comments:1234

/*
 console.log(can(tree, 'autos', 'read'));
 console.log(can(tree, 'autos', 'write'));
 console.log(can(tree, 'autos:123456', 'read'));
 console.log(can(tree, 'autos:123456:comments:0001:abcdef', 'update1'));
 console.log(can(tree, 'autos:0', 'read'));
 console.log(can(tree, 'autos:*', 'read'));
 console.log(can(tree, 'autos:0:comments', 'read'));

 var perms = {};
 allow(perms, 'autos', 'read');
 allow(perms, 'autos', 'write');
 allow(perms, 'autos:123456', 'read');
 allow(perms, 'autos:123456:comments:0001:abcdef', 'update1');
 allow(perms, 'autos:0', 'read');
 allow(perms, 'autos:*', 'read');
 allow(perms, 'autos:0:comments', 'read');

 console.log(can(perms, 'autos', 'read'));
 console.log(can(perms, 'autos', 'write'));
 console.log(can(perms, 'autos:123456', 'read'));
 console.log(can(perms, 'autos:123456:comments:0001:abcdef', 'update1'));
 console.log(can(perms, 'autos:0', 'read'));
 console.log(can(perms, 'autos:*', 'read'));
 console.log(can(perms, 'autos:0:comments', 'read'));
 */
