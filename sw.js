let sw_version = "02";
let cache_version_number = "01";
(function() {
    var cache_version = 'bitnote_' + cache_version_number;
    var pre_cache_files = ['/', 'sw.js', 'pages/js/zxcvbn.js', 'pages/js/ww.js', 'manifest.json', 'pages/js/new_wl.js', 'pages/fonts/bitnote_box_font.woff2', 'pages/fonts/inter_variable.ttf', ];
    var pre_load_files = ['/', 'sw.js', 'pages/js/ww.js', 'manifest.json', 'pages/js/new_wl.js', 'pages/fonts/bitnote_box_font.woff2', 'pages/fonts/inter_variable.ttf', ];
    var non_static_files = ['/', 'sw.js', 'pages/js/ww.js', 'manifest.json', ];
    function checkVersion(cb) {
        fetch("/pages/live_version.txt?_=" + Date.now()).then(function(response) {
            const reader = response.body.getReader();
            reader.read().then(function processText({done, value}) {
                var version = new TextDecoder().decode(value).split('\n')[0];
                cb(version);
            });
        });
    }
    self.addEventListener('install', function(event) {
        event.waitUntil(caches.open(cache_version).then(function(cache) {
            cache.keys().then(function(keys) {
                if (keys.length === 0)
                    return cache.addAll(pre_cache_files);
            });
        }));
        console.log("skipping install wait");
        self.skipWaiting();
    });
    self.addEventListener('activate', function(event) {
        console.log("waiting on activate claim");
        event.waitUntil(self.clients.claim());
    });
    function updateVersion(full_clear=false, cb) {
        (function clearCache() {
            caches.keys().then(function(keys) {
                if (full_clear) {
                    Promise.all(keys.map(function(cacheName) {
                        return caches.delete(cacheName);
                    }));
                } else {
                    return Promise.all(keys.map(function(key) {
                        return caches.open(key).then(function(cache) {
                            return Promise.all(non_static_files.map(function(filename) {
                                return cache.delete(filename);
                            }));
                        });
                    }));
                }
            }).then(updateCache);
        }
        )();
        function updateCache() {
            caches.open(cache_version).then(function(cache) {
                if (full_clear)
                    hardRefresh(pre_cache_files, cache);
                else
                    hardRefresh(non_static_files, cache);
            });
            function hardRefresh(array_list, cache) {
                var date = Date.now();
                var file_list = array_list.map(function(filename) {
                    return filename + "?_" + date
                });
                var first = file_list.shift();
                fetch(first).then(function(response) {
                    cacheResponse(response);
                    var promises = file_list.map(function(file) {
                        return fetch(file).then(cacheResponse);
                    });
                    Promise.all(promises).then(cb);
                });
                function cacheResponse(response) {
                    if (response.status === 200)
                        return cache.put(response.url.split('?')[0], response);
                }
            }
        }
    }
    self.addEventListener('fetch', standardFetch);
    function standardFetch(e) {
        if (e.request.method === 'GET') {
            e.respondWith(caches.open(cache_version).then(function(cache) {
                var match_url = stripUsername(e.request);
                return cache.match(match_url, {
                    ignoreSearch: true
                }).then(function(response) {
                    return response || fetch(e.request).then(function(response) {
                        if (response.status === 200) {
                            if (e.request.url.includes(self.location.hostname)) {
                                var temp_url = e.request.url.replace(self.location.hostname, "");
                                if (pre_cache_files.includes(temp_url))
                                    cache.put(e.request, response.clone());
                            }
                        }
                        return response;
                    });
                });
            }));
        }
    }
    function stripUsername(request) {
        var url = new URL(request.url);
        if (url.pathname != "/" && url.origin === self.location.origin) {
            var username = url.pathname.match(/\/.*?\//);
            if (checkForProperty(username)) {
                username = username[0].replaceAll("/", "");
                if (username != "pages")
                    return url.origin;
            }
        }
        return request;
    }
    self.addEventListener('message', messageReceiver);
    function messageReceiver(msg) {
        if (msg.ports) {
            switch (msg.data.type) {
            case "init":
                checkVersion(function(ret) {
                    console.log(ret);
                    msg.ports[0].postMessage({
                        type: "version_check",
                        sw_version: sw_version,
                        live_version: ret
                    });
                });
                break;
            case "update_version":
                updateVersion(false, function(ret) {
                    msg.ports[0].postMessage({
                        type: "update_result",
                        response: ret
                    });
                });
                break;
            case "clear_cache":
                updateVersion(true, function(ret) {
                    msg.ports[0].postMessage({
                        type: "clear_cache",
                        response: ret
                    });
                });
                break;
            }
        }
    }
    function checkForProperty(prop) {
        return (prop === "" || prop === null || prop === undefined) ? false : true;
    }
}
)();
